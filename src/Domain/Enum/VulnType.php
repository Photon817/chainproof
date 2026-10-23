<?php

declare(strict_types=1);

namespace App\Domain\Enum;

enum VulnType: string
{
    case Reentrancy = 'reentrancy';
    case AccessControl = 'access_control';
    case IntegerBoundary = 'integer_boundary';
    case Unknown = 'unknown';

    public static function parse(?string $value): self
    {
        $normalised = strtolower(str_replace(['-', ' '], '_', trim((string) $value)));

        return self::tryFrom($normalised) ?? self::Unknown;
    }

    public function skill(): string
    {
        return match ($this) {
            self::Reentrancy => 'reentrancy',
            self::AccessControl => 'access_control',
            self::IntegerBoundary => 'integer_boundary',
            self::Unknown => 'unknown',
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Reentrancy => 'REENTRANCY',
            self::AccessControl => 'ACCESS CONTROL',
            self::IntegerBoundary => 'INTEGER BOUNDARY',
            self::Unknown => 'UNCLASSIFIED',
        };
    }

    public function icon(): string
    {
        return match ($this) {
            self::Reentrancy => '↺',
            self::AccessControl => '⚿',
            self::IntegerBoundary => '±',
            self::Unknown => '?',
        };
    }
}
