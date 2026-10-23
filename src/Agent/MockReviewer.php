<?php

declare(strict_types=1);

namespace App\Agent;

use App\Domain\Enum\VulnType;
use App\Domain\Model\Finding;
use App\Domain\Model\SoliditySurface;
use App\Domain\Model\Verdict;

/**
 * Deterministic, deliberately skeptical reviewer. Its job in mock mode is to
 * demonstrate that the Reviewer is not a rubber stamp: privileged paths and
 * nonReentrant-guarded paths are culled before Foundry is ever invoked.
 */
final class MockReviewer
{
    public function review(Finding $finding, SoliditySurface $surface, ?string $executionFeedback = null): Verdict
    {
        if (null !== $executionFeedback && '' !== trim($executionFeedback)) {
            return new Verdict(
                'reject',
                0.9,
                'Foundry execution did not prove the claimed path. A reverted or uncompilable PoC is not evidence; the Reviewer withdraws its acceptance until a new plan is supplied. Trace: '.substr(trim($executionFeedback), 0, 500),
                ['A successful PoC must execute against a freshly seeded target and leave the attacker with a positive value delta.'],
                true,
            );
        }

        $marker = $surface->markerFor($finding->type->value, $finding->contract, $finding->function);
        if (null === $marker) {
            return new Verdict(
                'reject',
                0.25,
                'The deterministic pre-scan cannot corroborate this claim: no corresponding evidence marker exists for the cited function. Rejecting as unsupported.',
                ['Re-submit with a concrete line-level evidence marker.'],
            );
        }

        return match ($finding->type) {
            VulnType::Reentrancy => $this->reviewReentrancy($finding, $marker->meta, $marker->message),
            VulnType::AccessControl => $this->reviewAccessControl($finding, $marker->meta, $marker->message),
            default => new Verdict(
                'reject',
                0.3,
                'Mock mode only validates reentrancy and access-control findings. This finding needs a human reviewer or live mode.',
            ),
        };
    }

    /**
     * @param array<string, mixed> $meta
     */
    private function reviewReentrancy(Finding $finding, array $meta, string $message): Verdict
    {
        if ((bool) ($meta['reentrancy_guard'] ?? false)) {
            return new Verdict(
                'reject',
                0.96,
                sprintf('The entry point carries a reentrancy guard (%s), so the nested call cannot reach the state-changing path. %s', implode(', ', $meta['modifiers'] ?? []), $message),
                ['Remove or bypass the mutex to make the path reachable.'],
            );
        }

        $modifiers = $meta['modifiers'] ?? [];
        if (is_array($modifiers) && [] !== $modifiers) {
            return new Verdict(
                'reject',
                0.92,
                sprintf(
                    'The function is gated by [%s]. The Attacker has not demonstrated how an unprivileged account obtains that privilege, so the path is not externally reachable. %s',
                    implode(', ', $modifiers),
                    $message,
                ),
                ['Provide a privilege-escalation step or reclassify the finding as privileged-only.'],
            );
        }

        if (null === $finding->plan) {
            return new Verdict(
                'needs_poc',
                0.7,
                sprintf('The state-ordering evidence is credible, but the target shape does not fit reentrancy_v1 (payable deposit + zero-argument withdraw). Marked for manual PoC. %s', $message),
                ['A custom attacker contract must be written for this function signature.'],
            );
        }

        return new Verdict(
            'accept',
            0.93,
            sprintf(
                'Checks-effects-interactions is violated: the external call at line %d transfers control before the write at line %d, and no mutex or privilege modifier blocks an unprivileged caller. The plan matches the verified zero-argument withdraw and payable deposit.',
                (int) ($meta['call_line'] ?? 0),
                (int) ($meta['write_line'] ?? 0),
            ),
            [
                'The attacker contract must expose receive() and be funded with 1 ETH.',
                'The target must hold at least 1 ETH of victim deposits at exploit time.',
                'The unwind must not underflow the attacker balance.',
            ],
        );
    }

    /**
     * @param array<string, mixed> $meta
     */
    private function reviewAccessControl(Finding $finding, array $meta, string $message): Verdict
    {
        if (null === ($meta['sink_function'] ?? null) || '' === (string) $meta['sink_function']) {
            return new Verdict(
                'needs_poc',
                0.72,
                sprintf('The privilege write is unguarded, but no value sink could be statically linked to the overwritten variable. Impact needs manual confirmation. %s', $message),
                ['Identify a function that transfers ETH or tokens using the overwritten privilege variable.'],
            );
        }

        return new Verdict(
            'accept',
            0.95,
            sprintf(
                'An unprivileged caller can write "%s" through %s() with no modifier or msg.sender check, and the value sink %s() trusts that variable. Privilege escalation maps directly to a balance drain.',
                (string) ($meta['authority_var'] ?? 'state'),
                $finding->function,
                (string) $meta['sink_function'],
            ),
            [
                'The attacker EOA must call the setter directly (not through a contract that alters msg.sender).',
                'The sink must pay an attacker-controlled address.',
            ],
        );
    }
}
