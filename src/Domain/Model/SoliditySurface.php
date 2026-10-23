<?php

declare(strict_types=1);

namespace App\Domain\Model;

final class SoliditySurface
{
    /**
     * @param list<array<string, mixed>> $contracts
     * @param list<FunctionInfo>         $functions
     * @param list<array<string, mixed>> $stateVars
     * @param list<RiskMarker>           $markers
     */
    public function __construct(
        public string $path,
        public string $source,
        public string $sha256,
        public array $contracts,
        public array $functions,
        public array $stateVars,
        public array $markers = [],
    ) {
    }

    public function function(string $contract, string $name): ?FunctionInfo
    {
        foreach ($this->functions as $function) {
            if (strtolower($function->name) !== strtolower($name)) {
                continue;
            }
            if ('' === $contract || strtolower($function->contract) === strtolower($contract)) {
                return $function;
            }
        }

        return null;
    }

    public function hasContract(string $contract): bool
    {
        foreach ($this->contracts as $candidate) {
            if (strtolower((string) $candidate['name']) === strtolower($contract)) {
                return true;
            }
        }

        return false;
    }

    public function primaryContract(): string
    {
        foreach ($this->contracts as $contract) {
            if ('contract' === ($contract['kind'] ?? 'contract')) {
                return (string) $contract['name'];
            }
        }

        return (string) ($this->contracts[0]['name'] ?? 'Unknown');
    }

    /**
     * @return list<string>
     */
    public function contractNames(): array
    {
        return array_map(static fn (array $contract): string => (string) $contract['name'], $this->contracts);
    }

    public function markerFor(string $type, string $contract, string $function): ?RiskMarker
    {
        foreach ($this->markers as $marker) {
            if ($marker->type === $type
                && strtolower($marker->contract) === strtolower($contract)
                && strtolower($marker->function) === strtolower($function)) {
                return $marker;
            }
        }

        return null;
    }

    public function excerpt(int $startLine, int $endLine, int $padding = 2): string
    {
        $lines = preg_split('/\R/', $this->source) ?: [];
        $start = max(1, $startLine - $padding);
        $end = min(count($lines), $endLine + $padding);
        $out = [];

        for ($i = $start; $i <= $end; ++$i) {
            $out[] = sprintf('%4d | %s', $i, $lines[$i - 1] ?? '');
        }

        return implode("\n", $out);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'path' => $this->path,
            'sha256' => $this->sha256,
            'contracts' => $this->contracts,
            'functions' => array_map(static fn (FunctionInfo $function): array => $function->toArray(), $this->functions),
            'state_vars' => $this->stateVars,
            'markers' => array_map(static fn (RiskMarker $marker): array => $marker->toArray(), $this->markers),
        ];
    }

    public function summary(): string
    {
        $lines = [];
        $lines[] = sprintf('FILE: %s', $this->path);
        $lines[] = 'CONTRACTS:';

        foreach ($this->contracts as $contract) {
            $lines[] = sprintf(
                '- %s [%s] lines %d-%d%s',
                $contract['name'],
                $contract['kind'] ?? 'contract',
                $contract['startLine'] ?? 0,
                $contract['endLine'] ?? 0,
                !empty($contract['bases']) ? ' is '.$contract['bases'] : '',
            );
        }

        $lines[] = 'FUNCTIONS:';
        foreach ($this->functions as $function) {
            $lines[] = sprintf(
                '- %s.%s [%s%s] lines %d-%d modifiers: %s',
                $function->contract,
                $function->signature(),
                $function->visibility,
                'payable' === $function->mutability ? ' payable' : '',
                $function->startLine,
                $function->endLine,
                [] === $function->modifiers ? 'none' : implode(', ', $function->modifiers),
            );
        }

        $lines[] = 'STATE VARIABLES:';
        foreach ($this->stateVars as $variable) {
            $lines[] = sprintf(
                '- %s: %s [%s] line %d',
                $variable['name'],
                $variable['type'],
                $variable['contract'],
                $variable['line'],
            );
        }

        $lines[] = 'STATIC RISK MARKERS:';
        if ([] === $this->markers) {
            $lines[] = '- none';
        }
        foreach ($this->markers as $marker) {
            $lines[] = sprintf(
                '- [%s] %s %s.%s line %d: %s',
                $marker->severity->label(),
                $marker->type,
                $marker->contract,
                $marker->function,
                $marker->line,
                $marker->message,
            );
        }

        return implode("\n", $lines);
    }
}
