<?php

declare(strict_types=1);

namespace App\Agent;

use App\Config\PlatformConfig;
use App\Domain\Enum\VulnType;
use App\Domain\Model\AttackPlan;
use App\Domain\Model\Finding;
use App\Domain\Model\SoliditySurface;
use App\Orchestration\EventBus;
use App\Orchestration\RunStore;
use Throwable;

/**
 * Attacker pass. In live mode the LLM receives the deterministic surface map
 * and risk markers, then returns structured findings. In mock mode a
 * deterministic scenario generator produces the same shape so the demo works
 * without an API key.
 */
final class AttackerAgent
{
    public function __construct(
        private readonly PlatformConfig $config,
        private readonly LlmGateway $llm,
        private readonly PromptLibrary $prompts,
        private readonly MockAttacker $mock,
    ) {
    }

    /**
     * @return list<Finding>
     */
    public function hunt(
        string $runId,
        SoliditySurface $surface,
        string $skill,
        string $mode,
        RunStore $store,
        EventBus $events,
    ): array {
        if ('mock' === strtolower($mode)) {
            $findings = $this->mock->hunt($surface, $skill);
            $events->emit($runId, 'agent.attacker', sprintf('Attacker (%s) produced %d candidate(s)', $skill, count($findings)), [
                'skill' => $skill,
                'count' => count($findings),
                'engine' => 'deterministic',
            ]);

            return $findings;
        }

        $events->emit($runId, 'agent.attacker', sprintf('Attacker (%s) is reasoning over %s', $skill, $surface->path), [
            'skill' => $skill,
            'model' => $this->config->llmModel,
        ]);

        try {
            $raw = $this->llm->chat($this->prompts->system('attacker'), $this->prompts->attackerUser($surface, $skill));
        } catch (Throwable $exception) {
            $events->emit($runId, 'agent.attacker.error', 'Attacker LLM call failed: '.$exception->getMessage(), [
                'skill' => $skill,
            ], 'error');

            return [];
        }

        $store->writeText($runId, sprintf('llm/attacker-%s.json', $skill), $raw);
        $events->emit($runId, 'llm.response', sprintf('Attacker (%s) returned %d bytes', $skill, strlen($raw)), [
            'skill' => $skill,
            'artifact' => sprintf('llm/attacker-%s.json', $skill),
        ]);

        try {
            $data = LlmJson::decode($raw);
        } catch (LlmException $exception) {
            $events->emit($runId, 'agent.attacker.error', 'Attacker returned malformed JSON: '.$exception->getMessage(), [
                'skill' => $skill,
            ], 'error');

            return [];
        }

        $items = $data['findings'] ?? $data;
        if (!is_array($items)) {
            return [];
        }
        if (!array_is_list($items)) {
            $items = [$items];
        }

        $findings = [];
        foreach ($items as $item) {
            if (!is_array($item)) {
                continue;
            }
            $finding = $this->findingFromArray($surface, $skill, $item);
            if (null === $finding) {
                continue;
            }
            $findings[$finding->type->value.'|'.strtolower($finding->contract).'|'.strtolower($finding->function)] = $finding;
        }

        $findings = array_values($findings);
        $events->emit($runId, 'agent.attacker.done', sprintf('Attacker (%s) produced %d validated candidate(s)', $skill, count($findings)), [
            'skill' => $skill,
            'count' => count($findings),
            'engine' => 'llm',
            'model' => $this->config->llmModel,
        ]);

        return $findings;
    }

    /**
     * @param array<string, mixed> $item
     */
    private function findingFromArray(SoliditySurface $surface, string $skill, array $item): ?Finding
    {
        $type = VulnType::parse($item['type'] ?? $skill);
        if (VulnType::Unknown === $type) {
            $type = VulnType::parse($skill);
        }

        $contract = trim((string) ($item['contract'] ?? ''));
        if ('' === $contract || !$surface->hasContract($contract)) {
            $contract = $surface->primaryContract();
        }

        $functionName = trim((string) ($item['function'] ?? ''));
        $function = $surface->function($contract, $functionName);
        if (null === $function && '' !== $functionName) {
            $function = $surface->function('', $functionName);
            if (null !== $function) {
                $contract = $function->contract;
            }
        }
        if (null === $function) {
            return null;
        }

        $lineCount = max(1, substr_count($surface->source, "\n") + 1);
        $lineStart = max(1, min($lineCount, (int) ($item['line_start'] ?? $function->startLine)));
        $lineEnd = max($lineStart, min($lineCount, (int) ($item['line_end'] ?? $function->endLine)));

        $plan = is_array($item['plan'] ?? null) ? AttackPlan::fromArray($item['plan']) : null;
        $vulnerableCode = trim((string) ($item['vulnerable_code'] ?? ''));
        if ('' === $vulnerableCode) {
            $vulnerableCode = $surface->excerpt($lineStart, $lineEnd);
        }

        $id = 'f-'.substr(hash('sha256', implode('|', [$skill, $type->value, $contract, $function->name, $lineStart, (string) ($item['title'] ?? '')])), 0, 8);

        return (new Finding(
            $id,
            $type,
            \App\Domain\Enum\Severity::parse($item['severity'] ?? 'high'),
            $contract,
            $function->name,
            trim((string) ($item['title'] ?? 'Untitled finding')),
            trim((string) ($item['description'] ?? '')),
            $surface->path,
            $lineStart,
            $lineEnd,
            $vulnerableCode,
            trim((string) ($item['attack_vector'] ?? '')),
            trim((string) ($item['remediation'] ?? '')),
            max(0.0, min(1.0, (float) ($item['confidence'] ?? 0.5))),
            $skill,
            [
                'source' => 'llm',
                'model' => $this->config->llmModel,
            ],
        ))->withPlan($plan);
    }
}
