<?php

declare(strict_types=1);

namespace App\Analysis;

use App\Domain\Enum\Severity;
use App\Domain\Model\FunctionInfo;
use App\Domain\Model\RiskMarker;
use App\Domain\Model\SoliditySurface;

/**
 * Deterministic pre-scan. This is the cheap, non-LLM pass that gives the
 * Attacker a shortlist of interesting call sites — the same role
 * RegexStaticPreScanner plays in symfony-security-auditor. It never claims a
 * vulnerability; it only records evidence for the adversarial loop.
 */
final class StaticPreScanner
{
    private const EXTERNAL_CALL = '/(\.call\s*\{[^}]*\}|\.call\s*\(|\.transfer\s*\(|\.send\s*\()/';

    /**
     * @return list<RiskMarker>
     */
    public function scan(SoliditySurface $surface): array
    {
        $markers = [];

        foreach ($surface->functions as $function) {
            if ('constructor' === $function->name || !$function->isExternallyCallable()) {
                continue;
            }
            if (in_array($function->mutability, ['view', 'pure'], true)) {
                continue;
            }

            $reentrancy = $this->detectReentrancy($surface, $function);
            if (null !== $reentrancy) {
                $markers[] = $reentrancy;
            }

            foreach ($this->detectAccessControl($surface, $function) as $marker) {
                $markers[] = $marker;
            }

            if (str_contains($function->body, 'tx.origin')) {
                $markers[] = new RiskMarker(
                    'tx_origin',
                    Severity::Medium,
                    $function->contract,
                    $function->name,
                    $this->lineOf($function, $function->body, strpos($function->body, 'tx.origin') ?: 0),
                    'Authorization relies on tx.origin, which is phishable through an intermediate contract.',
                    'tx.origin',
                    ['modifiers' => $function->modifiers],
                );
            }

            if (1 === preg_match('/\bunchecked\s*\{/', $function->body, $match, PREG_OFFSET_CAPTURE)) {
                $markers[] = new RiskMarker(
                    'unchecked',
                    Severity::Medium,
                    $function->contract,
                    $function->name,
                    $this->lineOf($function, $function->body, $match[0][1]),
                    'Arithmetic runs inside an unchecked block; verify every reachable boundary.',
                    'unchecked { ... }',
                    ['modifiers' => $function->modifiers],
                );
            }

            if (str_contains($function->body, '.delegatecall(')) {
                $markers[] = new RiskMarker(
                    'delegatecall',
                    Severity::High,
                    $function->contract,
                    $function->name,
                    $this->lineOf($function, $function->body, strpos($function->body, '.delegatecall(') ?: 0),
                    'Delegatecall can escalate storage and privilege if the target is attacker-controlled.',
                    '.delegatecall(...)',
                    ['modifiers' => $function->modifiers],
                );
            }

            if (str_contains($function->body, 'selfdestruct')) {
                $markers[] = new RiskMarker(
                    'selfdestruct',
                    Severity::Critical,
                    $function->contract,
                    $function->name,
                    $this->lineOf($function, $function->body, strpos($function->body, 'selfdestruct') ?: 0),
                    'Destructive primitive reachable from an external entry point.',
                    'selfdestruct(...)',
                    ['modifiers' => $function->modifiers],
                );
            }
        }

        return $this->deduplicate($markers);
    }

    private function detectReentrancy(SoliditySurface $surface, FunctionInfo $function): ?RiskMarker
    {
        if (1 !== preg_match(self::EXTERNAL_CALL, $function->body, $call, PREG_OFFSET_CAPTURE)) {
            return null;
        }

        $callText = $call[0][0];
        $callOffset = $call[0][1];
        $after = substr($function->body, $callOffset + strlen($callText));

        $writeOffset = null;
        $writeText = '';
        $stateName = '';
        foreach ($surface->stateVars as $variable) {
            if (strtolower((string) $variable['contract']) !== strtolower($function->contract)) {
                continue;
            }

            $pattern = '/\b'.preg_quote((string) $variable['name'], '/').'\b\s*(?:\[[^\]]*\]|\.\w+)?\s*(?:(?:=(?!=|>))|(?:[+\-*\/]=))/';
            if (1 !== preg_match($pattern, $after, $write, PREG_OFFSET_CAPTURE)) {
                continue;
            }

            if (null === $writeOffset || $write[0][1] < $writeOffset) {
                $writeOffset = $write[0][1];
                $writeText = trim($write[0][0]);
                $stateName = (string) $variable['name'];
            }
        }

        if (null === $writeOffset) {
            return null;
        }

        $callLine = $this->lineOf($function, $function->body, $callOffset);
        $writeLine = $this->lineOf($function, $function->body, $callOffset + strlen($callText) + $writeOffset);
        $guarded = [] !== $function->modifiers;
        $reentrancyGuard = $function->hasModifier('nonReentrant');

        return new RiskMarker(
            'reentrancy',
            $reentrancyGuard ? Severity::Info : Severity::High,
            $function->contract,
            $function->name,
            $callLine,
            sprintf(
                'External call at line %d executes before the state write to "%s" at line %d (CEI violated).',
                $callLine,
                $stateName,
                $writeLine,
            ),
            sprintf('%s ... %s', preg_replace('/\s+/', ' ', $callText), $writeText),
            [
                'call_line' => $callLine,
                'write_line' => $writeLine,
                'state_var' => $stateName,
                'guarded' => $guarded,
                'reentrancy_guard' => $reentrancyGuard,
                'modifiers' => $function->modifiers,
                'signature' => $function->signature(),
            ],
        );
    }

    /**
     * @return list<RiskMarker>
     */
    private function detectAccessControl(SoliditySurface $surface, FunctionInfo $function): array
    {
        $markers = [];
        $authorityVars = array_filter(
            $surface->stateVars,
            static fn (array $variable): bool => 1 === preg_match(
                '/(owner|admin|operator|guardian|governance|implementation|manager|fee_?recipient|treasury)/i',
                (string) $variable['name'],
            ) && strtolower((string) $variable['contract']) === strtolower($function->contract),
        );

        foreach ($authorityVars as $variable) {
            $pattern = '/\b'.preg_quote((string) $variable['name'], '/').'\b\s*(?:(?:=(?!=|>))|(?:[+\-*\/]=))/';
            if (1 !== preg_match($pattern, $function->body, $write, PREG_OFFSET_CAPTURE)) {
                continue;
            }

            $guarded = [] !== $function->modifiers
                || 1 === preg_match('/require\s*\(\s*msg\.sender\s*==|_checkOwner|onlyRole|hasRole/', $function->body);
            if ($guarded) {
                continue;
            }

            $sink = $this->findPrivilegedSink($surface, $function->contract, (string) $variable['name']);
            $line = $this->lineOf($function, $function->body, $write[0][1]);

            $markers[] = new RiskMarker(
                'access_control',
                Severity::Critical,
                $function->contract,
                $function->name,
                $line,
                sprintf(
                    'Privilege variable "%s" is written without an authorization check%s.',
                    $variable['name'],
                    null !== $sink ? sprintf(' and gates the value sink %s()', $sink) : '',
                ),
                trim($write[0][0]),
                [
                    'authority_var' => $variable['name'],
                    'sink_function' => $sink,
                    'guarded' => false,
                    'modifiers' => $function->modifiers,
                    'signature' => $function->signature(),
                ],
            );
        }

        return $markers;
    }

    private function findPrivilegedSink(SoliditySurface $surface, string $contract, string $authorityVar): ?string
    {
        foreach ($surface->functions as $candidate) {
            if (strtolower($candidate->contract) !== strtolower($contract)) {
                continue;
            }
            if (1 !== preg_match('/msg\.sender\s*==\s*'.preg_quote($authorityVar, '/').'|'.preg_quote($authorityVar, '/').'\s*==\s*msg\.sender/', $candidate->body)) {
                continue;
            }
            if (1 === preg_match(self::EXTERNAL_CALL, $candidate->body)) {
                return $candidate->name;
            }
        }

        return null;
    }

    private function lineOf(FunctionInfo $function, string $body, int $offset): int
    {
        return $function->startLine + substr_count(substr($body, 0, $offset), "\n");
    }

    /**
     * @param list<RiskMarker> $markers
     *
     * @return list<RiskMarker>
     */
    private function deduplicate(array $markers): array
    {
        $unique = [];
        foreach ($markers as $marker) {
            $key = implode('|', [$marker->type, strtolower($marker->contract), strtolower($marker->function), $marker->line]);
            $unique[$key] = $marker;
        }

        $unique = array_values($unique);
        usort($unique, static fn (RiskMarker $a, RiskMarker $b): int => $b->severity->weight() <=> $a->severity->weight());

        return $unique;
    }
}
