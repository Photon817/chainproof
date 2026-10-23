<?php

declare(strict_types=1);

namespace App\Domain\Model;

final class AttackPlan
{
    /**
     * @param list<string>          $steps
     * @param array<string, string> $params
     */
    public function __construct(
        public string $template,
        public string $type,
        public string $targetContract,
        public array $steps = [],
        public string $expectedEffect = '',
        public array $params = [],
    ) {
    }

    public function param(string $key): ?string
    {
        $value = $this->params[$key] ?? null;

        return is_string($value) && '' !== trim($value) ? trim($value) : null;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $params = [];
        foreach (($data['params'] ?? []) as $key => $value) {
            if (is_scalar($value)) {
                $params[(string) $key] = (string) $value;
            }
        }

        $steps = [];
        foreach (($data['steps'] ?? []) as $step) {
            if (is_scalar($step)) {
                $steps[] = (string) $step;
            }
        }

        return new self(
            (string) ($data['template'] ?? ''),
            (string) ($data['type'] ?? ''),
            (string) ($data['target_contract'] ?? ''),
            $steps,
            (string) ($data['expected_effect'] ?? ''),
            $params,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'template' => $this->template,
            'type' => $this->type,
            'target_contract' => $this->targetContract,
            'steps' => $this->steps,
            'expected_effect' => $this->expectedEffect,
            'params' => $this->params,
        ];
    }
}
