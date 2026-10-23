<?php

declare(strict_types=1);

namespace App\Execution;

final readonly class ProcessResult
{
    public function __construct(
        public int $exitCode,
        public string $stdout,
        public string $stderr,
        public string $commandLine,
    ) {
    }

    public function successful(): bool
    {
        return 0 === $this->exitCode;
    }

    public function output(): string
    {
        return trim($this->stdout."\n".$this->stderr);
    }
}
