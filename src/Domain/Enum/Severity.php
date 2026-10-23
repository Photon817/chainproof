<?php

declare(strict_types=1);

namespace App\Domain\Enum;

enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case Info = 'info';

    public static function parse(?string $value): self
    {
        return self::tryFrom(strtolower(trim((string) $value))) ?? self::Medium;
    }

    public function weight(): int
    {
        return match ($this) {
            self::Critical => 4,
            self::High => 3,
            self::Medium => 2,
            self::Low => 1,
            self::Info => 0,
        };
    }

    public static function fromWeight(int $weight): self
    {
        return match ($weight) {
            4 => self::Critical,
            3 => self::High,
            2 => self::Medium,
            1 => self::Low,
            default => self::Info,
        };
    }

    public function label(): string
    {
        return strtoupper($this->value);
    }

    public function isBountyEligible(): bool
    {
        return $this->weight() >= self::High->weight();
    }
}
