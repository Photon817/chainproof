<?php

declare(strict_types=1);

namespace App\Agent;

use App\Domain\Model\AttackPlan;
use App\Domain\Model\Finding;
use App\Domain\Model\FunctionInfo;
use App\Domain\Model\SoliditySurface;

/**
 * A plan is only executable if it maps cleanly onto a deterministic Foundry
 * template. This validator is deliberately strict: an unprovable plan is
 * reported as manual review, never silently "verified".
 */
final class AttackPlanValidator
{
    public const TEMPLATES = ['reentrancy_v1', 'access_control_v1'];

    /**
     * @return array{0: bool, 1: string}
     */
    public function validate(Finding $finding, ?AttackPlan $plan, SoliditySurface $surface): array
    {
        if (null === $plan) {
            return [false, 'No typed PoC plan was supplied (manual PoC required).'];
        }

        if (!in_array($plan->template, self::TEMPLATES, true)) {
            return [false, sprintf('Unsupported PoC template "%s".', $plan->template)];
        }

        if ('' === $plan->targetContract || !$surface->hasContract($plan->targetContract)) {
            return [false, sprintf('Target contract "%s" does not exist in the source.', $plan->targetContract)];
        }

        return match ($plan->template) {
            'reentrancy_v1' => $this->validateReentrancy($finding, $plan, $surface),
            'access_control_v1' => $this->validateAccessControl($plan, $surface),
            default => [false, 'Unsupported PoC template.'],
        };
    }

    /**
     * @return array{0: bool, 1: string}
     */
    private function validateReentrancy(Finding $finding, AttackPlan $plan, SoliditySurface $surface): array
    {
        $withdrawName = $plan->param('withdraw_function') ?? $finding->function;
        $withdraw = $surface->function($plan->targetContract, $withdrawName);
        if (null === $withdraw) {
            return [false, sprintf('Withdraw function %s() does not exist.', $withdrawName)];
        }
        if (!$withdraw->isExternallyCallable()) {
            return [false, sprintf('%s() is not externally callable.', $withdrawName)];
        }
        if ('' !== trim($withdraw->params)) {
            return [false, sprintf('%s() takes arguments; reentrancy_v1 only supports a zero-argument withdraw.', $withdrawName)];
        }
        if ($withdraw->hasModifier('nonReentrant')) {
            return [false, sprintf('%s() is protected by nonReentrant.', $withdrawName)];
        }

        $depositName = $plan->param('deposit_function');
        if (null === $depositName) {
            return [false, 'reentrancy_v1 requires a payable deposit_function.'];
        }
        $deposit = $surface->function($plan->targetContract, $depositName);
        if (null === $deposit) {
            return [false, sprintf('Deposit function %s() does not exist.', $depositName)];
        }
        if ('payable' !== $deposit->mutability || '' !== trim($deposit->params)) {
            return [false, sprintf('%s() must be a zero-argument payable function.', $depositName)];
        }

        return [true, ''];
    }

    /**
     * @return array{0: bool, 1: string}
     */
    private function validateAccessControl(AttackPlan $plan, SoliditySurface $surface): array
    {
        $privilegeName = $plan->param('privilege_function');
        $sinkName = $plan->param('sink_function');
        if (null === $privilegeName || null === $sinkName) {
            return [false, 'access_control_v1 requires privilege_function and sink_function.'];
        }

        $privilege = $surface->function($plan->targetContract, $privilegeName);
        $sink = $surface->function($plan->targetContract, $sinkName);
        if (null === $privilege) {
            return [false, sprintf('Privilege function %s() does not exist.', $privilegeName)];
        }
        if (null === $sink) {
            return [false, sprintf('Sink function %s() does not exist.', $sinkName)];
        }
        if (!$this->isSingleAddressArg($privilege)) {
            return [false, sprintf('%s() is not a single-address setter.', $privilegeName)];
        }
        if (!$this->isSingleAddressArg($sink)) {
            return [false, sprintf('%s() is not a single-address value sink.', $sinkName)];
        }
        if ($privilege->isGuarded()) {
            return [false, sprintf('%s() carries an authorization modifier.', $privilegeName)];
        }
        if (!$sink->isExternallyCallable()) {
            return [false, sprintf('%s() is not externally callable.', $sinkName)];
        }

        return [true, ''];
    }

    private function isSingleAddressArg(FunctionInfo $function): bool
    {
        $params = array_values(array_filter(array_map('trim', explode(',', trim($function->params)))));

        return 1 === count($params) && str_contains(strtolower($params[0]), 'address');
    }
}
