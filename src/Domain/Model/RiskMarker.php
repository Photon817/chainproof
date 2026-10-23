<?php

declare(strict_types=1);

namespace App\Domain\Model;

use App\Domain\Enum\Severity;

final readonly class RiskMarker
{
    /**
     * @param array<string, mixed> $meta
     */
    public function __construct(
        public string $type,
        public Severity $severity,
        public string $contract,
        public string $function,
        public int $line,
        public string $message,
        public string $evidence,
        public array $meta = [],
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'severity' => $this->severity->value,
            'contract' => $this->contract,
            'function' => $this->function,
            'line' => $this->line,
            'message' => $this->message,
            'evidence' => $this->evidence,
            'meta' => $this->meta,
        ];
    }
}
