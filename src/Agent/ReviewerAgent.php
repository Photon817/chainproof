<?php

declare(strict_types=1);

namespace App\Agent;

use App\Config\PlatformConfig;
use App\Domain\Model\AttackPlan;
use App\Domain\Model\Finding;
use App\Domain\Model\SoliditySurface;
use App\Domain\Model\Verdict;
use App\Orchestration\EventBus;
use App\Orchestration\RunStore;
use Throwable;

/**
 * Reviewer pass. It is explicitly allowed to say no, and the orchestrator
 * feeds Foundry failures back into it so the chain can overrule the model.
 */
final class ReviewerAgent
{
    public function __construct(
        private readonly PlatformConfig $config,
        private readonly LlmGateway $llm,
        private readonly PromptLibrary $prompts,
        private readonly MockReviewer $mock,
    ) {
    }

    public function review(
        string $runId,
        Finding $finding,
        SoliditySurface $surface,
        string $mode,
        RunStore $store,
        EventBus $events,
        ?string $executionFeedback = null,
    ): Verdict {
        if ('mock' === strtolower($mode)) {
            $verdict = $this->mock->review($finding, $surface, $executionFeedback);
            $this->emit($events, $runId, $finding, $verdict, 'deterministic');

            return $verdict;
        }

        $events->emit($runId, 'agent.reviewer', sprintf('Reviewer is challenging %s', $finding->id), [
            'finding' => $finding->id,
            'model' => $this->config->llmModel,
            'has_chain_feedback' => null !== $executionFeedback,
        ]);

        try {
            $raw = $this->llm->chat(
                $this->prompts->system('reviewer'),
                $this->prompts->reviewerUser($finding, $surface, $executionFeedback),
            );
        } catch (Throwable $exception) {
            $verdict = new Verdict('reject', 0.1, 'Reviewer LLM call failed: '.$exception->getMessage());
            $this->emit($events, $runId, $finding, $verdict, 'error');

            return $verdict;
        }

        $store->writeText($runId, sprintf('llm/reviewer-%s.json', $finding->id), $raw);

        try {
            $data = LlmJson::decode($raw);
        } catch (LlmException $exception) {
            $verdict = new Verdict('reject', 0.1, 'Reviewer returned malformed JSON: '.$exception->getMessage());
            $this->emit($events, $runId, $finding, $verdict, 'error');

            return $verdict;
        }

        $decision = strtolower(trim((string) ($data['decision'] ?? 'reject')));
        if (!in_array($decision, ['accept', 'reject', 'needs_poc'], true)) {
            $decision = 'reject';
        }
        $data['decision'] = $decision;
        $verdict = Verdict::fromArray($data);

        if ($verdict->accepted() && is_array($data['plan'] ?? null)) {
            $finding->plan = AttackPlan::fromArray($data['plan']);
        }

        $this->emit($events, $runId, $finding, $verdict, 'llm');

        return $verdict;
    }

    private function emit(EventBus $events, string $runId, Finding $finding, Verdict $verdict, string $engine): void
    {
        $events->emit(
            $runId,
            'reviewer.verdict',
            sprintf('Reviewer %s %s (confidence %.2f)', $verdict->label(), $finding->id, $verdict->confidence),
            [
                'finding' => $finding->id,
                'decision' => $verdict->decision,
                'confidence' => $verdict->confidence,
                'reasoning' => $verdict->reasoning,
                'chain_falsified' => $verdict->chainFalsified,
                'engine' => $engine,
            ],
            $verdict->accepted() ? 'success' : 'warn',
        );
    }
}
