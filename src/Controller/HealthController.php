<?php

declare(strict_types=1);

namespace App\Controller;

use App\Config\PlatformConfig;
use App\Execution\FoundryRunner;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class HealthController extends AbstractController
{
    public function __construct(
        private readonly PlatformConfig $config,
        private readonly FoundryRunner $foundry,
    ) {
    }

    #[Route('/api/health', name: 'api_health', methods: ['GET'])]
    public function __invoke(): JsonResponse
    {
        $node = $this->foundry->nodeStatus();
        $toolchain = $this->foundry->toolchain();

        $ready = $node['reachable']
            && (int) ($node['chain_id'] ?? 0) === $this->config->chainId
            && null !== $toolchain['forge']
            && null !== $toolchain['cast'];

        return new JsonResponse([
            'ok' => $ready,
            'llm' => [
                'mode' => $this->config->llmMode,
                'model' => $this->config->llmModel,
                'has_key' => $this->config->hasLlmCredentials(),
            ],
            'node' => $node,
            'toolchain' => $toolchain,
            'targets' => $this->config->availableTargets(),
            'bounty' => [
                'funding_eth' => $this->config->bountyFundingEth,
                'max_reward_eth' => $this->config->bountyMaxRewardEth,
            ],
        ], Response::HTTP_OK, ['Cache-Control' => 'no-store']);
    }
}
