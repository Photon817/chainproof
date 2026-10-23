<?php

declare(strict_types=1);

namespace App\Execution;

/**
 * Minimal unsigned big-decimal arithmetic. Anvil balances routinely exceed
 * PHP_INT_MAX (10 ETH = 10^19 wei), so every wei value stays a string and is
 * compared/subtracted without floats.
 */
final class Wei
{
    public static function normalize(string|int $value): string
    {
        $value = trim((string) $value);
        if (str_starts_with($value, '0x') || str_starts_with($value, '0X')) {
            return self::fromHex(substr($value, 2));
        }

        $value = ltrim($value, '0');

        return '' === $value ? '0' : $value;
    }

    public static function cmp(string|int $a, string|int $b): int
    {
        $a = self::normalize($a);
        $b = self::normalize($b);
        if (strlen($a) !== strlen($b)) {
            return strlen($a) <=> strlen($b);
        }

        return strcmp($a, $b) <=> 0;
    }

    public static function add(string|int $a, string|int $b): string
    {
        $a = strrev(self::normalize($a));
        $b = strrev(self::normalize($b));
        $length = max(strlen($a), strlen($b));
        $carry = 0;
        $out = '';

        for ($i = 0; $i < $length; ++$i) {
            $sum = (int) ($a[$i] ?? 0) + (int) ($b[$i] ?? 0) + $carry;
            $out .= (string) ($sum % 10);
            $carry = intdiv($sum, 10);
        }
        if ($carry > 0) {
            $out .= (string) $carry;
        }

        return self::normalize(strrev($out));
    }

    public static function sub(string|int $a, string|int $b): string
    {
        $a = self::normalize($a);
        $b = self::normalize($b);
        if (self::cmp($a, $b) < 0) {
            return '0';
        }

        $a = strrev($a);
        $b = strrev($b);
        $borrow = 0;
        $out = '';

        for ($i = 0, $length = strlen($a); $i < $length; ++$i) {
            $digit = (int) $a[$i] - (int) ($b[$i] ?? 0) - $borrow;
            if ($digit < 0) {
                $digit += 10;
                $borrow = 1;
            } else {
                $borrow = 0;
            }
            $out .= (string) $digit;
        }

        return self::normalize(strrev($out));
    }

    public static function mulSmall(string $value, int $multiplier): string
    {
        $value = strrev(self::normalize($value));
        $carry = 0;
        $out = '';

        for ($i = 0, $length = strlen($value); $i < $length; ++$i) {
            $product = (int) $value[$i] * $multiplier + $carry;
            $out .= (string) ($product % 10);
            $carry = intdiv($product, 10);
        }
        while ($carry > 0) {
            $out .= (string) ($carry % 10);
            $carry = intdiv($carry, 10);
        }

        return self::normalize(strrev($out));
    }

    public static function isPositive(string|int $value): bool
    {
        return '0' !== self::normalize($value);
    }

    public static function divSmall(string $value, int $divisor): string
    {
        if ($divisor <= 0) {
            throw new \InvalidArgumentException('Divisor must be positive.');
        }

        $remainder = 0;
        $out = '';
        foreach (str_split(self::normalize($value)) as $digit) {
            $current = $remainder * 10 + (int) $digit;
            $out .= (string) intdiv($current, $divisor);
            $remainder = $current % $divisor;
        }

        return self::normalize($out);
    }

    private static function fromHex(string $hex): string
    {
        $hex = strtolower(trim($hex));
        if ('' === $hex) {
            return '0';
        }

        $decimal = '0';
        foreach (str_split($hex) as $char) {
            $digit = hexdec($char);
            if (!is_int($digit)) {
                return '0';
            }
            $decimal = self::add(self::mulSmall($decimal, 16), (string) $digit);
        }

        return $decimal;
    }
}
