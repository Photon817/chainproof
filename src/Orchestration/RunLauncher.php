<?php

declare(strict_types=1);

namespace App\Orchestration;

use App\Config\PlatformConfig;
use App\Domain\Model\AuditRequest;
use RuntimeException;

/**
 * Detaches a CLI audit from the HTTP request so the dashboard can poll the
 * event stream while the attack/review/execute loop is still running.
 */
final class RunLauncher
{
    public function __construct(
        private readonly PlatformConfig $config,
        private readonly RunStore $store,
    ) {
    }

    public function launch(AuditRequest $request): string
    {
        $runId = $request->runId ?? $this->store->newId();
        $this->store->initialize($runId, [
            'status' => 'queued',
            'created_at' => gmdate('c'),
            'target' => $request->target,
            'mode' => strtolower($request->mode),
            'bounty_enabled' => $request->bounty,
        ]);

        $arguments = [
            PHP_BINARY,
            $this->config->projectDir.'/bin/console',
            'audit:run',
            $request->target,
            '--run-id='.$runId,
            '--mode='.$request->mode,
        ];
        if ($request->bounty) {
            $arguments[] = '--bounty';
        }
        if (!$request->poc) {
            $arguments[] = '--no-poc';
        }

        $log = $this->store->path($runId, 'cli.log');
        $command = 'nohup '.implode(' ', array_map('escapeshellarg', $arguments))
            .' >> '.escapeshellarg($log).' 2>&1 & echo $!';

        if (!function_exists('exec')) {
            throw new RuntimeException('exec() is disabled; run the audit from the CLI instead.');
        }

        $output = [];
        $exitCode = 0;
        exec($command, $output, $exitCode);
        if (0 !== $exitCode) {
            throw new RuntimeException('Unable to launch the detached audit process.');
        }

        $pid = (int) ($output[0] ?? 0);
        if ($pid > 0) {
            $this->store->update($runId, ['pid' => $pid]);
        }

        return $runId;
    }
}
