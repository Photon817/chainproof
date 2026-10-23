<?php

declare(strict_types=1);

namespace App\Analysis;

use App\Domain\Model\FunctionInfo;
use App\Domain\Model\SoliditySurface;
use RuntimeException;

/**
 * Lightweight Solidity surface mapper. It is intentionally not a compiler:
 * it extracts the facts the adversarial agents need (call graph seeds,
 * state-write ordering, modifiers, line numbers) without pulling PHP into
 * the Solidity parser business.
 */
final class SurfaceExtractor
{
    public function extractFile(string $absolutePath, ?string $displayPath = null): SoliditySurface
    {
        $source = file_get_contents($absolutePath);
        if (false === $source) {
            throw new RuntimeException(sprintf('Unable to read %s.', $absolutePath));
        }

        if (strlen($source) > 400_000) {
            throw new RuntimeException('Target exceeds the 400 KB audit limit.');
        }

        return $this->extract($source, $displayPath ?? basename($absolutePath));
    }

    public function extract(string $source, string $path): SoliditySurface
    {
        $contracts = $this->parseContracts($source);
        $functions = $this->parseFunctions($source, $contracts);
        $stateVars = $this->parseStateVars($source, $contracts);

        return new SoliditySurface(
            $path,
            $source,
            hash('sha256', $source),
            $contracts,
            $functions,
            $stateVars,
        );
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function parseContracts(string $source): array
    {
        $contracts = [];
        $pattern = '/\b(contract|library|interface)\s+([A-Za-z_]\w*)(?:\s+is\s+([^{]+))?\s*\{/';
        preg_match_all($pattern, $source, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);

        foreach ($matches as $match) {
            $offset = $match[0][1];
            $open = $offset + strlen($match[0][0]) - 1;
            $close = $this->findClosingBrace($source, $open);
            if (null === $close) {
                continue;
            }

            $contracts[] = [
                'name' => $match[2][0],
                'kind' => $match[1][0],
                'bases' => trim(preg_replace('/\s+/', ' ', $match[3][0] ?? '') ?? ''),
                'startLine' => $this->lineAt($source, $offset),
                'endLine' => $this->lineAt($source, $close),
                'offsetStart' => $offset,
                'offsetEnd' => $close,
                'offsetBody' => $open + 1,
                'code' => substr($source, $open + 1, $close - $open - 1),
            ];
        }

        return $contracts;
    }

    /**
     * @param list<array<string, mixed>> $contracts
     *
     * @return list<FunctionInfo>
     */
    private function parseFunctions(string $source, array $contracts): array
    {
        $functions = [];
        $pattern = '/\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{;]*)(\{|;)/s';
        preg_match_all($pattern, $source, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);

        foreach ($matches as $match) {
            $offset = $match[0][1];
            $contract = $this->contractAt($contracts, $offset);
            if (null === $contract) {
                continue;
            }

            $open = $offset + strlen($match[0][0]) - 1;
            $close = '{' === $match[4][0] ? $this->findClosingBrace($source, $open) : $open;
            $header = $match[3][0];
            $body = null === $close ? '' : substr($source, $open, $close - $open + 1);

            $functions[] = new FunctionInfo(
                $contract['name'],
                $match[1][0],
                $match[2][0],
                $this->visibility($header),
                $this->mutability($header),
                $this->modifiers($header),
                $this->returns($header),
                $this->lineAt($source, $offset),
                null === $close ? $this->lineAt($source, $offset) : $this->lineAt($source, $close),
                $body,
                trim(preg_replace('/\s+/', ' ', $header) ?? ''),
            );
        }

        $constructorPattern = '/\bconstructor\s*\(([^)]*)\)([^{;]*)(\{|;)/s';
        preg_match_all($constructorPattern, $source, $constructors, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
        foreach ($constructors as $match) {
            $offset = $match[0][1];
            $contract = $this->contractAt($contracts, $offset);
            if (null === $contract) {
                continue;
            }

            $open = $offset + strlen($match[0][0]) - 1;
            $close = '{' === $match[3][0] ? $this->findClosingBrace($source, $open) : $open;
            $header = $match[2][0];

            $functions[] = new FunctionInfo(
                $contract['name'],
                'constructor',
                $match[1][0],
                'public',
                $this->mutability($header),
                $this->modifiers($header),
                '',
                $this->lineAt($source, $offset),
                null === $close ? $this->lineAt($source, $offset) : $this->lineAt($source, $close),
                null === $close ? '' : substr($source, $open, $close - $open + 1),
                trim(preg_replace('/\s+/', ' ', $header) ?? ''),
            );
        }

        usort($functions, static fn (FunctionInfo $a, FunctionInfo $b): int => $a->startLine <=> $b->startLine);

        return $functions;
    }

    /**
     * @param list<array<string, mixed>> $contracts
     *
     * @return list<array<string, mixed>>
     */
    private function parseStateVars(string $source, array $contracts): array
    {
        $variables = [];
        $pattern = '/^[ \t]*(mapping\s*\([^;]+?\)|address(?:\s+payable)?|bool|string|bytes(?:[0-9]+)?|u?int(?:[0-9]+)?|[A-Z][A-Za-z0-9_]*(?:\[\])?)\s+((?:(?:public|private|internal|constant|immutable|override)\s+)*)([A-Za-z_]\w*)\s*(?:=[^;]*)?;/m';

        foreach ($contracts as $contract) {
            $code = (string) $contract['code'];
            preg_match_all($pattern, $code, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            foreach ($matches as $match) {
                $offset = $match[0][1];
                if (!$this->isTopLevel($code, $offset)) {
                    continue;
                }

                $line = $this->lineAt($source, (int) $contract['offsetBody'] + $offset);
                $variables[] = [
                    'contract' => $contract['name'],
                    'name' => $match[3][0],
                    'type' => trim($match[1][0]),
                    'visibility' => trim(preg_replace('/\s+/', ' ', $match[2][0]) ?? ''),
                    'line' => $line,
                ];
            }
        }

        return $variables;
    }

    /**
     * @param list<array<string, mixed>> $contracts
     *
     * @return array<string, mixed>|null
     */
    private function contractAt(array $contracts, int $offset): ?array
    {
        foreach ($contracts as $contract) {
            if ($offset >= (int) $contract['offsetStart'] && $offset <= (int) $contract['offsetEnd']) {
                return $contract;
            }
        }

        return null;
    }

    private function visibility(string $header): string
    {
        if (preg_match('/\b(external|public|internal|private)\b/', $header, $match)) {
            return $match[1];
        }

        return 'public';
    }

    private function mutability(string $header): string
    {
        foreach (['pure', 'view', 'payable'] as $mutability) {
            if (preg_match('/\b'.$mutability.'\b/', $header)) {
                return $mutability;
            }
        }

        return 'nonpayable';
    }

    /**
     * @return list<string>
     */
    private function modifiers(string $header): array
    {
        $clean = preg_replace('/\breturns\s*\([^)]*\)/s', ' ', $header) ?? '';
        $clean = preg_replace(
            '/\b(?:external|public|internal|private|pure|view|payable|virtual|override|nonpayable)\b/',
            ' ',
            $clean,
        ) ?? '';

        preg_match_all('/([A-Za-z_]\w*)\s*(?:\([^)]*\))?/', $clean, $matches);
        $modifiers = [];
        foreach ($matches[1] ?? [] as $candidate) {
            if (!in_array($candidate, ['returns'], true) && !in_array($candidate, $modifiers, true)) {
                $modifiers[] = $candidate;
            }
        }

        return $modifiers;
    }

    private function returns(string $header): string
    {
        if (preg_match('/\breturns\s*(\([^)]*\))/s', $header, $match)) {
            return trim($match[1]);
        }

        return '';
    }

    private function findClosingBrace(string $source, int $open): ?int
    {
        $depth = 0;
        $length = strlen($source);
        $string = null;
        $lineComment = false;
        $blockComment = false;

        for ($i = $open; $i < $length; ++$i) {
            $char = $source[$i];
            $next = $source[$i + 1] ?? '';

            if ($lineComment) {
                if ("\n" === $char) {
                    $lineComment = false;
                }
                continue;
            }
            if ($blockComment) {
                if ('*' === $char && '/' === $next) {
                    $blockComment = false;
                    ++$i;
                }
                continue;
            }
            if (null !== $string) {
                if ('\\' === $char) {
                    ++$i;
                    continue;
                }
                if ($char === $string) {
                    $string = null;
                }
                continue;
            }
            if ('/' === $char && '/' === $next) {
                $lineComment = true;
                ++$i;
                continue;
            }
            if ('/' === $char && '*' === $next) {
                $blockComment = true;
                ++$i;
                continue;
            }
            if ("'" === $char || '"' === $char) {
                $string = $char;
                continue;
            }
            if ('{' === $char) {
                ++$depth;
            } elseif ('}' === $char) {
                --$depth;
                if (0 === $depth) {
                    return $i;
                }
            }
        }

        return null;
    }

    private function isTopLevel(string $code, int $offset): bool
    {
        $prefix = substr($code, 0, $offset);
        $opens = substr_count($prefix, '{');
        $closes = substr_count($prefix, '}');

        return $opens === $closes;
    }

    private function lineAt(string $source, int $offset): int
    {
        return substr_count(substr($source, 0, $offset), "\n") + 1;
    }
}
