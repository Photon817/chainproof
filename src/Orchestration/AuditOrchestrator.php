<?php

declare(strict_types=1);

namespace App\Orchestration;

use App\Agent\AttackPlanValidator;
use App\Agent\AttackerAgent;
use App\Agent\ReviewerAgent;
use App\Analysis\StaticPreScanner;
use App\Analysis\SurfaceExtractor;
use App\Bounty\BountyClient;
use App\Config\PlatformConfig;
use App\Domain\Model\AuditRequest;
use App\Domain\Model\Finding;
use App\Domain\Model\SoliditySurface;
use App\Execution\FoundryRunner;
use App\Execution\Wei;
use App\Report\ReportBuilder;
use RuntimeException;
use Throwable;

/**
 * The adversarial loop from symfony-security-auditor, ported to Solidity:
 *
 *   surface map -> Attacker claims -> Reviewer challenges -> Foundry executes
 *                                     ^                         |
 *                                     +---- chain feedback -----+
 *
 * The chain is the only source of truth. A finding cannot reach "proven"
 * without a broadcast transaction receipt that shows a positive value delta.
 */
final class AuditOrchestrator
{
    private const SKILLS = ['reentrancy', 'access_control'];

    public function __construct(
        private readonly PlatformConfig $config,
        private readonly RunStore $store,
        private readonly EventBus $events,
        private readonly SurfaceExtractor $extractor,
        private readonly StaticPreScanner $preScanner,
        private readonly AttackerAgent $attacker,
        private readonly ReviewerAgent $reviewer,
        private readonly AttackPlanValidator $validator,
        private readonly FoundryRunner $foundry,
        private readonly BountyClient $bounty,
        private readonly ReportBuilder $report,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function run(AuditRequest $request): array
    {
        $targetPath = $this->config->targetPath($request->target);
        $targetLabel = 'src/'.basename($targetPath);
        $runId = $request->runId ?? $this->store->newId();

        $this->store->initialize($runId, [
            'target' => basename($targetPath),
            'target_path' => $targetLabel,
            'mode' => strtolower($request->mode),
            'bounty_enabled' => $request->bounty,
        ]);
        $this->store->update($runId, [
            'status' => 'running',
            'started_at' => gmdate('c'),
            'finished_at' => null,
            'error' => null,
        ]);

        $this->events->emit($runId, 'run.started', sprintf(
            'Audit started for %s in %s mode.',
            $targetLabel,
            $request->mode,
        ), [
            'target' => $targetLabel,
            'mode' => $request->mode,
            'bounty' => $request->bounty,
            'poc' => $request->poc,
        ]);

        try {
            $surface = $this->extractor->extractFile($targetPath, $targetLabel);
            $surface->markers = $this->preScanner->scan($surface);

            $this->store->writeText($runId, 'source.sol', $surface->source);
            $this->store->writeJson($runId, 'surface.json', $surface->toArray());

            $this->events->emit($runId, 'surface.ready', sprintf(
                'Surface mapped: %d contract(s), %d function(s), %d state variable(s), %d risk marker(s).',
                count($surface->contracts),
                count($surface->functions),
                count($surface->stateVars),
                count($surface->markers),
            ), [
                'contracts' => $surface->contractNames(),
                'functions' => count($surface->functions),
                'markers' => count($surface->markers),
                'sha256' => $surface->sha256,
            ], 'success');

            $manifest = $this->config->targetManifest($targetPath);
            $contractName = (string) ($manifest['contract'] ?? $surface->primaryContract());
            if (!$surface->hasContract($contractName)) {
                throw new RuntimeException(sprintf(
                    'Target manifest points at contract "%s", which is not present in %s.',
                    $contractName,
                    $targetLabel,
                ));
            }

            foreach (self::SKILLS as $skill) {
                $this->events->emit($runId, 'attacker.skill', sprintf('Attacker switched to the %s surface.', $skill), [
                    'skill' => $skill,
                ]);

                $findings = $this->attacker->hunt(
                    $runId,
                    $surface,
                    $skill,
                    strtolower($request->mode),
                    $this->store,
                    $this->events,
                );

                foreach ($findings as $finding) {
                    $this->resolveFinding($runId, $request, $targetPath, $contractName, $surface, $finding);
                }
            }

            $this->settleBounty($runId, $request);

            $report = $this->report->build($runId);
            $stats = $this->store->stats($runId);
            $this->store->update($runId, [
                'status' => 'completed',
                'finished_at' => gmdate('c'),
                'stats' => $stats,
            ]);

            $this->events->emit($runId, 'report.ready', sprintf(
                'Report ready: %s. Artifacts: %s, %s, %s.',
                (string) $report['headline'],
                $report['markdown'],
                $report['json'],
                $report['html'],
            ), $report, 'success');
            $this->events->emit($runId, 'run.completed', sprintf(
                'Audit completed: %d proven, %s ETH extracted, %s ETH bounty.',
                (int) $stats['proven'],
                (string) $stats['extracted_eth'],
                (string) $stats['bounty_eth'],
            ), $stats, 'success');

            return [
                'run' => $this->store->read($runId),
                'stats' => $stats,
                'report' => $report,
                'bounty' => $this->store->readJson($runId, 'bounty.json'),
            ];
        } catch (Throwable $exception) {
            $this->store->update($runId, [
                'status' => 'failed',
                'error' => $exception->getMessage(),
                'finished_at' => gmdate('c'),
            ]);
            $this->events->emit($runId, 'run.failed', $exception->getMessage(), [
                'exception' => $exception::class,
            ], 'error');

            throw $exception;
        }
    }

    private function resolveFinding(
        string $runId,
        AuditRequest $request,
        string $targetPath,
        string $contractName,
        SoliditySurface $surface,
        Finding $finding,
    ): void {
        $finding->status = 'candidate';
        $this->store->saveFinding($runId, $finding);
        $this->events->emit($runId, 'attacker.finding', sprintf(
            'Attacker claimed [%s] %s',
            strtoupper($finding->severity->value),
            $finding->title,
        ), [
            'finding' => $finding->id,
            'type' => $finding->type->value,
            'contract' => $finding->contract,
            'function' => $finding->function,
            'line_start' => $finding->lineStart,
            'confidence' => $finding->confidence,
            'has_plan' => null !== $finding->plan,
        ], 'warn');

        $verdict = $this->reviewer->review(
            $runId,
            $finding,
            $surface,
            strtolower($request->mode),
            $this->store,
            $this->events,
        );

        $finding->verdict = $verdict;
        $finding->status = match ($verdict->decision) {
            'reject' => 'rejected',
            'needs_poc' => 'needs_manual_poc',
            default => 'accepted',
        };
        $this->store->saveFinding($runId, $finding);

        if (!$verdict->accepted()) {
            $this->events->emit($runId, 'finding.rejected', sprintf(
                'Reviewer stopped %s before any chain interaction: %s',
                $finding->id,
                $verdict->reasoning,
            ), ['finding' => $finding->id, 'decision' => $verdict->decision]);

            return;
        }

        if (!$request->poc) {
            $this->events->emit($runId, 'poc.disabled', 'PoC execution disabled by --no-poc; the finding stays at review stage.', [
                'finding' => $finding->id,
            ], 'warn');

            return;
        }

        [$executable, $blockReason] = $this->validator->validate($finding, $finding->plan, $surface);
        if (!$executable || null === $finding->plan) {
            $finding->status = 'needs_manual_poc';
            $finding->meta['poc_blocked_reason'] = $blockReason;
            $this->store->saveFinding($runId, $finding);
            $this->events->emit($runId, 'poc.skipped', $blockReason, [
                'finding' => $finding->id,
                'template' => $finding->plan?->template,
            ], 'warn');

            return;
        }

        $plan = $finding->plan;

        $this->events->emit($runId, 'poc.started', sprintf(
            'Foundry is executing %s against a fresh %s instance.',
            $plan->template,
            $contractName,
        ), [
            'finding' => $finding->id,
            'template' => $plan->template,
        ]);

        $proof = $this->foundry->prove(
            $runId,
            $targetPath,
            $contractName,
            $finding,
            $plan,
            $surface,
        );

        $finding->proof = $proof;
        $finding->status = 'proven' === $proof['verdict'] ? 'proven' : 'poc_failed';
        $this->store->saveFinding($runId, $finding);

        if ('proven' === $proof['verdict']) {
            return;
        }

        $failureKind = (string) ($proof['failure_kind'] ?? 'unknown');
        if (!in_array($failureKind, ['exploit_reverted', 'no_extraction'], true)) {
            $this->events->emit($runId, 'poc.inconclusive', sprintf(
                'Foundry could not produce a verdict (%s); the finding is kept for manual review.',
                $failureKind,
            ), ['finding' => $finding->id, 'failure_kind' => $failureKind], 'warn');

            return;
        }

        $feedback = sprintf(
            "Foundry verdict: %s\nfailure_kind: %s\nmessage: %s\nstate: target_before=%s wei, target_after=%s wei",
            (string) $proof['verdict'],
            $failureKind,
            (string) ($proof['message'] ?? ''),
            (string) ($proof['target_before_wei'] ?? '0'),
            (string) ($proof['target_after_wei'] ?? '0'),
        );

        $verdict = $this->reviewer->review(
            $runId,
            $finding,
            $surface,
            strtolower($request->mode),
            $this->store,
            $this->events,
            $feedback,
        );

        $finding->verdict = $verdict;
        if ('reject' === $verdict->decision) {
            $finding->status = 'rejected';
            $finding->meta['chain_falsified'] = true;
            $this->store->saveFinding($runId, $finding);

            $this->events->emit($runId, 'finding.chain_falsified', sprintf(
                'Chain feedback overruled %s: %s',
                $finding->id,
                $verdict->reasoning,
            ), ['finding' => $finding->id, 'decision' => $verdict->decision], 'warn');

            return;
        }

        $this->store->saveFinding($runId, $finding);
        $this->events->emit($runId, 'poc.failed', sprintf(
            'PoC did not extract value (%s); the Reviewer kept the claim for manual review.',
            $failureKind,
        ), ['finding' => $finding->id, 'failure_kind' => $failureKind], 'warn');
    }

    private function settleBounty(string $runId, AuditRequest $request): void
    {
        if (!$request->bounty) {
            $this->store->writeJson($runId, 'bounty.json', [
                'enabled' => false,
                'status' => 'disabled',
            ]);

            return;
        }

        $best = null;
        foreach ($this->store->findings($runId) as $finding) {
            if ('proven' !== $finding->status || !$finding->severity->isBountyEligible()) {
                continue;
            }
            if (null === $best || $this->outranks($finding, $best)) {
                $best = $finding;
            }
        }

        if (null === $best) {
            $this->store->writeJson($runId, 'bounty.json', [
                'enabled' => true,
                'status' => 'skipped',
                'reason' => 'No proven finding reached the high/critical bounty threshold.',
                'checked_at' => gmdate('c'),
            ]);
            $this->events->emit($runId, 'bounty.skipped', 'No proven high/critical finding; the bounty stays unclaimed.', [], 'warn');

            return;
        }

        $markdown = $this->report->markdown($runId);
        $this->bounty->settle($runId, $best, $best->proof ?? [], $markdown);
    }

    private function outranks(Finding $candidate, Finding $current): bool
    {
        if ($candidate->severity->weight() !== $current->severity->weight()) {
            return $candidate->severity->weight() > $current->severity->weight();
        }

        $candidateExtracted = (string) ($candidate->proof['extracted_wei'] ?? '0');
        $currentExtracted = (string) ($current->proof['extracted_wei'] ?? '0');

        return Wei::cmp($candidateExtracted, $currentExtracted) > 0;
    }
}
