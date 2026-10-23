<?php

declare(strict_types=1);

namespace App\Domain\Model;

final class Verdict
{
    /**
     * @param list<string> $conditions
     */
    public function __construct(
        public string $decision,
        public float $confidence,
        public string $reasoning,
        public array $conditions = [],
        public bool $chainFalsified = false,
    ) {
    }

    public function accepted(): bool
    {
        return in_array($this->decision, ['accept', 'needs_poc'], true);
    }

    public function label(): string
    {
        return strtoupper($this->decision);
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $conditions = $data['conditions'] ?? [];
        if (!is_array($conditions)) {
            $conditions = [];
        }

        return new self(
            (string) ($data['decision'] ?? 'reject'),
            max(0.0, min(1.0, (float) ($data['confidence'] ?? 0.0))),
            (string) ($data['reasoning'] ?? ''),
            array_values(array_map(static fn (mixed $value): string => (string) $value, $conditions)),
            (bool) ($data['chain_falsified'] ?? false),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'decision' => $this->decision,
            'confidence' => $this->confidence,
            'reasoning' => $this->reasoning,
            'conditions' => $this->conditions,
            'chain_falsified' => $this->chainFalsified,
        ];
    }
}
