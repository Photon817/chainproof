<?php

declare(strict_types=1);

namespace App\Domain\Model;

final class FunctionInfo
{
    /**
     * @param list<string> $modifiers
     */
    public function __construct(
        public string $contract,
        public string $name,
        public string $params,
        public string $visibility,
        public string $mutability,
        public array $modifiers,
        public string $returns,
        public int $startLine,
        public int $endLine,
        public string $body,
        public string $header,
    ) {
    }

    public function signature(): string
    {
        return sprintf('%s(%s)', $this->name, preg_replace('/\s+/', ' ', trim($this->params)));
    }

    public function isExternallyCallable(): bool
    {
        return in_array($this->visibility, ['public', 'external'], true);
    }

    public function hasModifier(string $modifier): bool
    {
        foreach ($this->modifiers as $candidate) {
            if (strtolower($candidate) === strtolower($modifier)) {
                return true;
            }
        }

        return false;
    }

    public function isGuarded(): bool
    {
        return [] !== $this->modifiers || str_contains($this->body, '_checkOwner');
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'contract' => $this->contract,
            'name' => $this->name,
            'params' => trim($this->params),
            'visibility' => $this->visibility,
            'mutability' => $this->mutability,
            'modifiers' => $this->modifiers,
            'returns' => trim($this->returns),
            'line_start' => $this->startLine,
            'line_end' => $this->endLine,
        ];
    }
}
