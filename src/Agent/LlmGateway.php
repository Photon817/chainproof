<?php

declare(strict_types=1);

namespace App\Agent;

interface LlmGateway
{
    public function chat(string $systemPrompt, string $userPrompt): string;
}
