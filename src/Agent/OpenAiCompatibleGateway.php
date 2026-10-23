<?php

declare(strict_types=1);

namespace App\Agent;

use App\Config\PlatformConfig;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * Provider-agnostic OpenAI-compatible chat client. DeepSeek, Qwen, GLM,
 * OpenAI, and local vLLM/Ollama gateways all speak this shape. The workbench
 * deliberately does not bind itself to one vendor SDK.
 */
final class OpenAiCompatibleGateway implements LlmGateway
{
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly PlatformConfig $config,
    ) {
    }

    public function chat(string $systemPrompt, string $userPrompt): string
    {
        if (!$this->config->hasLlmCredentials()) {
            throw new LlmException('APP_LLM_API_KEY is empty. Switch to mock mode or provide a key.');
        }

        $endpoint = rtrim($this->config->llmBaseUrl, '/').'/chat/completions';
        $payload = [
            'model' => $this->config->llmModel,
            'messages' => [
                ['role' => 'system', 'content' => $systemPrompt],
                ['role' => 'user', 'content' => $userPrompt],
            ],
            'temperature' => 0.1,
            'max_tokens' => 4096,
        ];
        if ($this->config->llmJsonMode) {
            $payload['response_format'] = ['type' => 'json_object'];
        }

        try {
            $response = $this->http->request('POST', $endpoint, [
                'headers' => [
                    'Authorization' => 'Bearer '.$this->config->llmApiKey,
                    'Content-Type' => 'application/json',
                ],
                'json' => $payload,
                'timeout' => 180,
            ]);

            $status = $response->getStatusCode();
            $body = $response->getContent(false);
        } catch (Throwable $exception) {
            throw new LlmException('LLM transport failed: '.$exception->getMessage(), 0, $exception);
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new LlmException(sprintf('LLM returned non-JSON HTTP %d: %s', $status, substr($body, 0, 400)));
        }

        if ($status >= 300) {
            $message = $decoded['error']['message'] ?? $decoded['message'] ?? substr($body, 0, 400);
            throw new LlmException(sprintf('LLM HTTP %d: %s', $status, $message));
        }

        $content = $decoded['choices'][0]['message']['content'] ?? null;
        if (is_array($content)) {
            $parts = [];
            foreach ($content as $part) {
                if (is_array($part) && isset($part['text'])) {
                    $parts[] = (string) $part['text'];
                } elseif (is_string($part)) {
                    $parts[] = $part;
                }
            }
            $content = implode("\n", $parts);
        }

        if (!is_string($content) || '' === trim($content)) {
            throw new LlmException('LLM response contained no assistant content.');
        }

        return $content;
    }
}
