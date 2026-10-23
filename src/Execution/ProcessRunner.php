<?php

declare(strict_types=1);

namespace App\Execution;

use Symfony\Component\Process\Process;
use Throwable;

final class ProcessRunner
{
    /**
     * @param list<string>          $command
     * @param array<string, string> $env
     */
    public function run(array $command, ?string $cwd = null, array $env = [], int $timeout = 180): ProcessResult
    {
        try {
            $process = new Process($command, $cwd, [] === $env ? null : $env, null, (float) $timeout);
            $process->run();
        } catch (Throwable $exception) {
            throw new ExecutionException(sprintf('Unable to start %s: %s', $command[0] ?? 'process', $exception->getMessage()), 0, $exception);
        }

        return new ProcessResult(
            $process->getExitCode() ?? 1,
            $process->getOutput(),
            $process->getErrorOutput(),
            $process->getCommandLine(),
        );
    }

    /**
     * @param list<string>          $command
     * @param array<string, string> $env
     */
    public function mustRun(array $command, ?string $cwd = null, array $env = [], int $timeout = 180): ProcessResult
    {
        $result = $this->run($command, $cwd, $env, $timeout);
        if (!$result->successful()) {
            throw new ExecutionException(sprintf(
                "Command failed (%d): %s\n%s",
                $result->exitCode,
                $result->commandLine,
                substr($result->output(), 0, 4000),
            ));
        }

        return $result;
    }
}
