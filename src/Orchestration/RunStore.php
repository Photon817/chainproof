<?php

declare(strict_types=1);

namespace App\Orchestration;

use App\Config\PlatformConfig;
use App\Domain\Enum\Severity;
use App\Domain\Model\Finding;
use App\Execution\Wei;
use RuntimeException;

/**
 * File-backed run store. Every audit is a directory with immutable evidence:
 * source snapshot, surface map, events, findings, PoC scripts and receipts.
 */
final class RunStore
{
    public function __construct(private readonly PlatformConfig $config)
    {
    }

    public function newId(): string
    {
        return sprintf('run-%s-%s', gmdate('Ymd-His'), bin2hex(random_bytes(3)));
    }

    public function initialize(string $runId, array $meta = []): array
    {
        $dir = $this->dir($runId);
        if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new RuntimeException(sprintf('Unable to create run directory %s.', $dir));
        }

        $existing = $this->exists($runId) ? $this->read($runId) : [];
        $run = array_replace([
            'id' => $runId,
            'status' => 'queued',
            'created_at' => gmdate('c'),
            'started_at' => null,
            'finished_at' => null,
            'target' => null,
            'mode' => 'mock',
            'bounty_enabled' => false,
            'error' => null,
            'stats' => [
                'findings' => 0,
                'accepted' => 0,
                'rejected' => 0,
                'proven' => 0,
                'extracted_eth' => '0',
                'bounty_eth' => '0',
            ],
            'bounty' => null,
            'pid' => null,
        ], $existing, $meta);

        $this->writeJson($runId, 'run.json', $run);

        return $run;
    }

    public function exists(string $runId): bool
    {
        return is_file($this->dir($runId).'/run.json');
    }

    public function read(string $runId): array
    {
        $path = $this->dir($runId).'/run.json';
        if (!is_file($path)) {
            return [];
        }

        $data = json_decode((string) file_get_contents($path), true);

        return is_array($data) ? $data : [];
    }

    public function update(string $runId, array $patch): array
    {
        $path = $this->dir($runId).'/run.json';
        $handle = fopen($path, 'c+');
        if (false === $handle) {
            throw new RuntimeException(sprintf('Unable to open %s.', $path));
        }

        try {
            flock($handle, LOCK_EX);
            $raw = stream_get_contents($handle);
            $current = is_string($raw) && '' !== $raw ? json_decode($raw, true) : [];
            $current = is_array($current) ? $current : [];
            $next = array_replace($current, $patch);
            $encoded = json_encode($next, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            rewind($handle);
            ftruncate($handle, 0);
            fwrite($handle, (string) $encoded);
            fflush($handle);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }

        return $next;
    }

    public function appendEvent(string $runId, array $event): void
    {
        $this->ensureDir($runId);
        $line = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n";
        file_put_contents($this->dir($runId).'/events.jsonl', $line, FILE_APPEND | LOCK_EX);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function events(string $runId, int $limit = 500): array
    {
        $path = $this->dir($runId).'/events.jsonl';
        if (!is_file($path)) {
            return [];
        }

        $events = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $decoded = json_decode($line, true);
            if (is_array($decoded)) {
                $events[] = $decoded;
            }
        }

        return array_slice($events, -$limit);
    }

    /**
     * @return list<Finding>
     */
    public function findings(string $runId): array
    {
        $files = glob($this->dir($runId).'/findings/*.json') ?: [];
        $findings = [];
        foreach ($files as $file) {
            $data = json_decode((string) file_get_contents($file), true);
            if (is_array($data) && isset($data['id'])) {
                $findings[] = Finding::fromArray($data);
            }
        }

        usort($findings, static function (Finding $a, Finding $b): int {
            $severity = $b->severity->weight() <=> $a->severity->weight();

            return 0 !== $severity ? $severity : strcmp($a->id, $b->id);
        });

        return $findings;
    }

    public function saveFinding(string $runId, Finding $finding): void
    {
        $this->writeJson($runId, 'findings/'.$finding->id.'.json', $finding->toArray());
    }

    /**
     * @return array<string, mixed>
     */
    public function stats(string $runId): array
    {
        $findings = $this->findings($runId);
        $stats = [
            'findings' => count($findings),
            'accepted' => 0,
            'rejected' => 0,
            'proven' => 0,
            'extracted_eth' => '0',
            'bounty_eth' => '0',
        ];

        $extracted = '0';
        foreach ($findings as $finding) {
            if (in_array($finding->status, ['accepted', 'needs_manual_poc', 'proven'], true)) {
                ++$stats['accepted'];
            }
            if ('rejected' === $finding->status) {
                ++$stats['rejected'];
            }
            if ('proven' === $finding->status) {
                ++$stats['proven'];
                $extracted = Wei::add($extracted, (string) ($finding->proof['extracted_wei'] ?? '0'));
            }
        }

        $stats['extracted_eth'] = $this->config->weiToEth($extracted);

        $bountyPath = $this->dir($runId).'/bounty.json';
        if (is_file($bountyPath)) {
            $bounty = json_decode((string) file_get_contents($bountyPath), true);
            if (is_array($bounty) && 'paid' === ($bounty['status'] ?? null)) {
                $stats['bounty_eth'] = (string) ($bounty['reward_eth'] ?? '0');
            }
        }

        return $stats;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function listRuns(int $limit = 30): array
    {
        $runs = [];
        foreach (glob($this->config->runsDir.'/*/run.json') ?: [] as $file) {
            $data = json_decode((string) file_get_contents($file), true);
            if (is_array($data) && isset($data['id'])) {
                $runs[] = $data;
            }
        }

        usort($runs, static fn (array $a, array $b): int => strcmp((string) ($b['created_at'] ?? ''), (string) ($a['created_at'] ?? '')));

        return array_slice($runs, 0, $limit);
    }

    public function writeJson(string $runId, string $relativePath, array $data): void
    {
        $this->writeText(
            $runId,
            $relativePath,
            (string) json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        );
    }

    public function writeText(string $runId, string $relativePath, string $content): void
    {
        $path = $this->path($runId, $relativePath);
        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new RuntimeException(sprintf('Unable to create %s.', $dir));
        }

        $temporary = $path.'.tmp.'.bin2hex(random_bytes(4));
        if (false === file_put_contents($temporary, $content, LOCK_EX)) {
            throw new RuntimeException(sprintf('Unable to write %s.', $path));
        }
        rename($temporary, $path);
    }

    public function readText(string $runId, string $relativePath): ?string
    {
        $path = $this->path($runId, $relativePath);

        return is_file($path) ? (string) file_get_contents($path) : null;
    }

    public function readJson(string $runId, string $relativePath): ?array
    {
        $raw = $this->readText($runId, $relativePath);
        if (null === $raw) {
            return null;
        }
        $data = json_decode($raw, true);

        return is_array($data) ? $data : null;
    }

    public function has(string $runId, string $relativePath): bool
    {
        return is_file($this->path($runId, $relativePath));
    }

    public function dir(string $runId): string
    {
        $this->assertId($runId);

        return $this->config->runsDir.'/'.$runId;
    }

    public function path(string $runId, string $relativePath): string
    {
        $relativePath = ltrim($relativePath, '/');
        if (str_contains($relativePath, '..')) {
            throw new RuntimeException('Invalid run artifact path.');
        }

        return $this->dir($runId).'/'.$relativePath;
    }

    private function ensureDir(string $runId): void
    {
        $dir = $this->dir($runId);
        if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new RuntimeException(sprintf('Unable to create %s.', $dir));
        }
    }

    private function assertId(string $runId): void
    {
        if (1 !== preg_match('/^[a-z0-9][a-z0-9-]{3,60}$/', $runId)) {
            throw new RuntimeException('Invalid run id.');
        }
    }
}
