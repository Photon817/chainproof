<?php

declare(strict_types=1);

namespace App\Agent;

use App\Domain\Enum\Severity;
use App\Domain\Enum\VulnType;
use App\Domain\Model\AttackPlan;
use App\Domain\Model\Finding;
use App\Domain\Model\FunctionInfo;
use App\Domain\Model\RiskMarker;
use App\Domain\Model\SoliditySurface;

/**
 * Deterministic attacker used by the demo-safe mock mode. It turns the
 * pre-scan markers into concrete claims and typed PoC plans, so the full
 * Attacker → Reviewer → Foundry loop works with zero API keys.
 */
final class MockAttacker
{
    /**
     * @return list<Finding>
     */
    public function hunt(SoliditySurface $surface, string $skill): array
    {
        $findings = [];

        foreach ($surface->markers as $marker) {
            if ('reentrancy' === $skill && 'reentrancy' === $marker->type) {
                $finding = $this->reentrancyFinding($surface, $marker);
                if (null !== $finding) {
                    $findings[] = $finding;
                }
            }

            if ('access_control' === $skill && 'access_control' === $marker->type) {
                $finding = $this->accessControlFinding($surface, $marker);
                if (null !== $finding) {
                    $findings[] = $finding;
                }
            }
        }

        return $findings;
    }

    private function reentrancyFinding(SoliditySurface $surface, RiskMarker $marker): ?Finding
    {
        $function = $surface->function($marker->contract, $marker->function);
        if (null === $function) {
            return null;
        }

        $deposit = $this->findDepositFunction($surface, $marker->contract);
        $params = [];
        if (null !== $deposit) {
            $params['deposit_function'] = $deposit->name;
        }
        $params['withdraw_function'] = $function->name;

        $plan = null !== $deposit && $this->isZeroArg($function) && $this->isZeroArg($deposit)
            ? new AttackPlan(
                'reentrancy_v1',
                'reentrancy',
                $marker->contract,
                [
                    'Deploy an attacker contract with a receive() hook and 1 ETH of seed capital.',
                    sprintf('Call %s.deposit() to credit the attacker.', $marker->contract),
                    sprintf('Call %s.%s() so the target sends ETH before zeroing the balance.', $marker->contract, $function->name),
                    'Re-enter from receive() until the target balance is below one unit.',
                    'Unwind and keep the drained ETH in the attacker contract.',
                ],
                'Drain the target contract balance into the attacker contract.',
                $params,
            )
            : null;

        $guarded = (bool) ($marker->meta['guarded'] ?? false);
        $guardNote = $guarded
            ? sprintf(' The function is gated by [%s], so the Reviewer may reject the path.', implode(', ', $marker->meta['modifiers'] ?? []))
            : '';

        return (new Finding(
            $this->id('reentrancy', $marker->contract, $function->name, $marker->line),
            VulnType::Reentrancy,
            $guarded ? Severity::Medium : Severity::High,
            $marker->contract,
            $function->name,
            sprintf('Reentrancy in %s.%s()', $marker->contract, $function->name),
            sprintf(
                'The external call at line %d transfers control before the state write at line %d. %s%s',
                (int) ($marker->meta['call_line'] ?? $marker->line),
                (int) ($marker->meta['write_line'] ?? $marker->line),
                $marker->evidence,
                $guardNote,
            ),
            $surface->path,
            $function->startLine,
            $function->endLine,
            $surface->excerpt($function->startLine, $function->endLine),
            sprintf(
                "1. Deploy an attacker contract whose receive() calls %s.%s() again.\n2. Deposit 1 ETH through %s so the target credits the attacker.\n3. Call %s() and let the external call hand control back to receive().\n4. Repeat until the target cannot pay another unit, then unwind.\n5. Withdraw the accumulated ETH from the attacker contract.",
                $marker->contract,
                $function->name,
                null !== $deposit ? $deposit->name.'()' : 'the payable entry point',
                $function->name,
            ),
            'Apply checks-effects-interactions: zero the balance before the external call, and add a nonReentrant mutex. Prefer pull-payment withdrawals over inline ETH transfers.',
            $guarded ? 0.55 : 0.88,
            'reentrancy',
            ['source' => 'mock-static-pre-scan', 'marker' => $marker->toArray()],
        ))->withPlan($plan);
    }

    private function accessControlFinding(SoliditySurface $surface, RiskMarker $marker): ?Finding
    {
        $function = $surface->function($marker->contract, $marker->function);
        if (null === $function) {
            return null;
        }

        $sinkName = $marker->meta['sink_function'] ?? null;
        $sink = is_string($sinkName) ? $surface->function($marker->contract, $sinkName) : null;
        $plan = null;
        if ($this->isSingleAddressArg($function) && null !== $sink && $this->isSingleAddressArg($sink)) {
            $plan = new AttackPlan(
                'access_control_v1',
                'access_control',
                $marker->contract,
                [
                    sprintf('Call %s.%s(attacker) from an unprivileged EOA.', $marker->contract, $function->name),
                    'The contract stores the attacker as the privileged operator.',
                    null !== $sink
                        ? sprintf('Call %s.%s(payable(attacker)) to move the contract balance.', $marker->contract, $sink->name)
                        : 'Invoke the privileged value sink that trusts the overwritten variable.',
                    'Confirm the attacker balance increased by the contract balance.',
                ],
                'Escalate to the privileged role and drain the contract balance.',
                [
                    'privilege_function' => $function->name,
                    'sink_function' => null !== $sink ? $sink->name : '',
                ],
            );
        }

        return (new Finding(
            $this->id('access_control', $marker->contract, $function->name, $marker->line),
            VulnType::AccessControl,
            Severity::Critical,
            $marker->contract,
            $function->name,
            sprintf('Missing authorization on %s.%s()', $marker->contract, $function->name),
            sprintf(
                '%s An unprivileged caller can overwrite "%s"%s.',
                $marker->message,
                (string) ($marker->meta['authority_var'] ?? 'privilege state'),
                null !== $sink ? sprintf(' and reach the value sink %s()', $sink->name) : '',
            ),
            $surface->path,
            $function->startLine,
            $function->endLine,
            $surface->excerpt($function->startLine, $function->endLine),
            sprintf(
                "1. From an attacker EOA, call %s.%s(attacker).\n2. The contract writes the attacker-controlled value into its privilege variable.\n3. %s\n4. The attacker keeps the drained ETH.",
                $marker->contract,
                $function->name,
                null !== $sink
                    ? sprintf('Call %s.%s(payable(attacker)); the function trusts the overwritten variable.', $marker->contract, $sink->name)
                    : 'Invoke any function that trusts the overwritten variable.',
            ),
            'Gate every privilege mutation with onlyOwner / AccessControl, validate the new role, and use a two-step ownership transfer. Never derive authorization from mutable state without a guard.',
            0.95,
            'access_control',
            ['source' => 'mock-static-pre-scan', 'marker' => $marker->toArray()],
        ))->withPlan($plan);
    }

    private function findDepositFunction(SoliditySurface $surface, string $contract): ?FunctionInfo
    {
        foreach ($surface->functions as $function) {
            if (strtolower($function->contract) === strtolower($contract)
                && 'deposit' === strtolower($function->name)
                && 'payable' === $function->mutability) {
                return $function;
            }
        }

        return null;
    }

    private function isZeroArg(FunctionInfo $function): bool
    {
        return '' === trim($function->params);
    }

    private function isSingleAddressArg(FunctionInfo $function): bool
    {
        $params = array_values(array_filter(array_map('trim', explode(',', trim($function->params)))));

        return 1 === count($params) && str_contains(strtolower($params[0]), 'address');
    }

    private function id(string $type, string $contract, string $function, int $line): string
    {
        return 'f-'.substr(hash('sha256', implode('|', [$type, $contract, $function, $line])), 0, 8);
    }
}
