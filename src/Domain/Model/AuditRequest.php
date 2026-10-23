<?php

declare(strict_types=1);

namespace App\Domain\Model;

final readonly class AuditRequest
{
    public function __construct(
        public string $target,
        public string $mode,
        public bool $bounty,
        public bool $poc = true,
        public ?string $runId = null,
    ) {
    }

    public function isMock(): bool
    {
        return 'mock' === strtolower($this->mode);
    }
}
