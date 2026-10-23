<?php

declare(strict_types=1);

namespace App\Agent;

/**
 * Small, forgiving JSON extractor for model output. Providers occasionally
 * wrap JSON in markdown fences or prepend a sentence even when asked not to.
 */
final class LlmJson
{
    /**
     * @return array<string, mixed>
     */
    public static function decode(string $raw): array
    {
        $text = trim($raw);
        $text = preg_replace('/^\xEF\xBB\xBF/', '', $text) ?? $text;
        $text = preg_replace('/^```(?:json)?\s*/i', '', $text) ?? $text;
        $text = preg_replace('/\s*```$/', '', $text) ?? $text;

        $objectStart = strpos($text, '{');
        $objectEnd = strrpos($text, '}');
        $arrayStart = strpos($text, '[');
        $arrayEnd = strrpos($text, ']');

        if (false !== $objectStart && false !== $objectEnd && $objectEnd > $objectStart
            && (false === $arrayStart || $objectStart < $arrayStart)) {
            $candidate = substr($text, $objectStart, $objectEnd - $objectStart + 1);
        } elseif (false !== $arrayStart && false !== $arrayEnd && $arrayEnd > $arrayStart) {
            $candidate = substr($text, $arrayStart, $arrayEnd - $arrayStart + 1);
        } else {
            throw new LlmException('Model output did not contain a JSON object or array.');
        }

        $decoded = json_decode($candidate, true);
        if (!is_array($decoded)) {
            throw new LlmException('Model output was not valid JSON: '.json_last_error_msg());
        }

        return $decoded;
    }
}
