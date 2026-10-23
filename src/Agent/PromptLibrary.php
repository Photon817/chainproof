<?php

declare(strict_types=1);

namespace App\Agent;

use App\Config\PlatformConfig;
use App\Domain\Model\Finding;
use App\Domain\Model\RiskMarker;
use App\Domain\Model\SoliditySurface;
use RuntimeException;

/**
 * Prompt assembly. The instruction text lives in prompts/*.md so a security
 * researcher can tune the adversarial wording without touching PHP — the same
 * separation symfony-security-auditor uses for its Attacker/Reviewer prompt
 * builders.
 */
final class PromptLibrary
{
    public function __construct(private readonly PlatformConfig $config)
    {
    }

    public function system(string $name): string
    {
        $path = $this->config->promptsDir.'/'.$name.'.system.md';
        $prompt = is_file($path) ? file_get_contents($path) : false;
        if (false === $prompt || '' === trim($prompt)) {
            throw new RuntimeException(sprintf('Prompt file %s is missing or empty.', $path));
        }

        return $prompt;
    }

    public function attackerUser(SoliditySurface $surface, string $skill): string
    {
        return implode("\n\n", [
            '## Skill focus',
            $this->skillBrief($skill),
            '## Target',
            sprintf('File: %s', $surface->path),
            sprintf('SHA-256: %s', $surface->sha256),
            sprintf('Contracts: %s', implode(', ', $surface->contractNames()) ?: 'none'),
            '## Surface map',
            $surface->summary(),
            '## Static risk markers',
            $this->markerSection($surface, $skill),
            '## Source (line-numbered)',
            $this->numberedSource($surface),
            '## Task',
            'Produce the JSON object described in the system prompt. Find exploitable paths, not code smells. If no credible path exists, return {"findings": []}.',
        ]);
    }

    public function reviewerUser(Finding $finding, SoliditySurface $surface, ?string $executionFeedback = null): string
    {
        $sections = [
            '## Finding under review',
            (string) json_encode($finding->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            '## Surface map',
            $surface->summary(),
            '## Source (line-numbered)',
            $this->numberedSource($surface),
            '## Task',
            'Verify or falsify this finding. Check reachability, modifiers, state ordering and plan shape. Return the JSON object described in the system prompt.',
        ];

        if (null !== $executionFeedback && '' !== trim($executionFeedback)) {
            $sections[] = '## chain_feedback (ground truth from Foundry/Anvil)';
            $sections[] = substr(trim($executionFeedback), 0, 6000);
        }

        return implode("\n\n", $sections);
    }

    public function skillBrief(string $skill): string
    {
        return match ($skill) {
            'reentrancy' => 'Hunt for reentrancy: an external call transfers control before the contract finishes updating its own accounting. Look for `call`, `transfer`, `send`, token callbacks, and `receive()` paths. Check for `nonReentrant` guards and CEI ordering. The PoC template expects a payable deposit and a zero-argument withdraw.',
            'access_control' => 'Hunt for missing or bypassable authorization: unprotected privileged setters, `tx.origin`, uninitialised proxies, role confusion, arbitrary `delegatecall`. The PoC template expects a single-address privilege setter plus a single-address payable sink.',
            'integer_boundary' => 'Hunt for arithmetic boundary bugs: `unchecked` blocks, unsafe downcasts, reward rounding that can be repeated, and accounting that diverges from token balances.',
            default => 'Audit the target for exploitable application-level flaws. Prefer paths that can be demonstrated with a deterministic transaction sequence.',
        };
    }

    private function markerSection(SoliditySurface $surface, string $skill): string
    {
        $relevant = array_values(array_filter(
            $surface->markers,
            static function (RiskMarker $marker) use ($skill): bool {
                return match ($skill) {
                    'reentrancy' => in_array($marker->type, ['reentrancy', 'tx_origin'], true),
                    'access_control' => in_array($marker->type, ['access_control', 'tx_origin', 'delegatecall'], true),
                    'integer_boundary' => in_array($marker->type, ['unchecked'], true),
                    default => true,
                };
            },
        ));

        if ([] === $relevant) {
            return 'The deterministic pre-scan produced no marker for this skill. You may still report a finding if the source supports it.';
        }

        $lines = [];
        foreach ($relevant as $marker) {
            $lines[] = sprintf(
                '- [%s] %s at %s.%s:%d — %s (evidence: %s)',
                $marker->severity->label(),
                $marker->type,
                $marker->contract,
                $marker->function,
                $marker->line,
                $marker->message,
                $marker->evidence,
            );
            if ([] !== $marker->meta) {
                $lines[] = '  meta: '.json_encode($marker->meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            }
        }

        return implode("\n", $lines);
    }

    private function numberedSource(SoliditySurface $surface): string
    {
        $lines = preg_split('/\R/', $surface->source) ?: [];
        $out = [];
        $budget = 140_000;

        foreach ($lines as $index => $line) {
            $rendered = sprintf('%4d | %s', $index + 1, $line);
            $budget -= strlen($rendered) + 1;
            if ($budget < 0) {
                $out[] = sprintf('... (%d more lines truncated) ...', count($lines) - $index - 1);
                break;
            }
            $out[] = $rendered;
        }

        return implode("\n", $out);
    }
}
