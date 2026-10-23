<?php

declare(strict_types=1);

namespace App\Config;

use RuntimeException;

/**
 * Immutable runtime configuration shared by the orchestrator, agents and
 * execution adapters. Values come from environment variables so the same
 * image can run against a local Anvil fork or a disposable CI chain.
 */
final readonly class PlatformConfig
{
    public function __construct(
        public string $projectDir,
        public string $runsDir,
        public string $targetsDir,
        public string $foundryDir,
        public string $promptsDir,
        public string $rpcUrl,
        public int $chainId,
        public string $llmMode,
        public string $llmBaseUrl,
        public string $llmApiKey,
        public string $llmModel,
        public bool $llmJsonMode,
        public string $deployerKey,
        public string $victimKey,
        public string $attackerKey,
        public string $auditorKey,
        public string $judgeKey,
        public string $deployerAddress,
        public string $auditorAddress,
        public string $judgeAddress,
        public string $bountyFundingEth,
        public string $bountyMaxRewardEth,
    ) {
    }

    public function isMock(): bool
    {
        return 'mock' === strtolower($this->llmMode);
    }

    public function isLive(): bool
    {
        return 'live' === strtolower($this->llmMode);
    }

    public function hasLlmCredentials(): bool
    {
        return '' !== trim($this->llmApiKey);
    }

    public function ethToWei(string $eth): string
    {
        $eth = trim($eth);
        if (1 !== preg_match('/^(\d+)(?:\.(\d{1,18}))?$/', $eth, $matches)) {
            throw new RuntimeException(sprintf('Invalid ETH amount "%s".', $eth));
        }

        $wei = $matches[1].str_pad($matches[2] ?? '', 18, '0');
        $wei = ltrim($wei, '0');

        return '' === $wei ? '0' : $wei;
    }

    public function weiToEth(string|int $wei): string
    {
        $wei = ltrim((string) $wei, '0');
        if ('' === $wei) {
            return '0';
        }

        if (18 >= strlen($wei)) {
            $whole = '0';
            $fraction = str_pad($wei, 18, '0', STR_PAD_LEFT);
        } else {
            $whole = substr($wei, 0, -18);
            $fraction = substr($wei, -18);
        }

        $fraction = rtrim($fraction, '0');

        return '' === $fraction ? $whole : $whole.'.'.$fraction;
    }

    public function targetPath(string $target): string
    {
        $candidate = str_contains($target, '/')
            ? $target
            : $this->targetsDir.'/'.$target;
        $real = realpath($candidate);
        $root = realpath($this->targetsDir);

        if (false === $real || false === $root || !str_starts_with($real, $root.DIRECTORY_SEPARATOR)) {
            throw new RuntimeException(sprintf('Target "%s" is not inside the sandbox target directory.', $target));
        }

        if (!str_ends_with($real, '.sol')) {
            throw new RuntimeException('Only .sol targets are supported.');
        }

        return $real;
    }

    /**
     * @return array<string, mixed>
     */
    public function targetManifest(string $target): array
    {
        $manifestPath = $this->foundryDir.'/targets.json';
        if (!is_file($manifestPath)) {
            return [];
        }

        $manifest = json_decode((string) file_get_contents($manifestPath), true, 512, JSON_THROW_ON_ERROR);
        $key = basename($target);

        return is_array($manifest[$key] ?? null) ? $manifest[$key] : [];
    }

    /**
     * @return list<string>
     */
    public function availableTargets(): array
    {
        $files = glob($this->targetsDir.'/*.sol') ?: [];
        $targets = [];
        foreach ($files as $file) {
            if ('BountyEscrow.sol' === basename($file)) {
                continue;
            }
            $targets[] = basename($file);
        }
        sort($targets);

        return $targets;
    }
}
