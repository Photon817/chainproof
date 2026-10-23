<?php

declare(strict_types=1);

namespace App\Controller;

use App\Config\PlatformConfig;
use App\Domain\Model\AuditRequest;
use App\Execution\FoundryRunner;
use App\Orchestration\RunLauncher;
use App\Orchestration\RunStore;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Throwable;

final class DashboardController extends AbstractController
{
    public function __construct(
        private readonly PlatformConfig $config,
        private readonly RunStore $store,
        private readonly RunLauncher $launcher,
        private readonly FoundryRunner $foundry,
    ) {
    }

    #[Route('/', name: 'dashboard', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $session = $request->getSession();
        $token = $session->get('csrf_token');
        if (!is_string($token) || '' === $token) {
            $token = bin2hex(random_bytes(24));
            $session->set('csrf_token', $token);
        }

        return $this->render('dashboard.html.twig', [
            'targets' => $this->targets(),
            'runs' => $this->decorateRuns($this->store->listRuns(12)),
            'health' => $this->healthPayload(),
            'csrf_token' => $token,
            'default_mode' => $this->config->llmMode,
        ]);
    }

    #[Route('/audit', name: 'audit_launch', methods: ['POST'])]
    public function launch(Request $request): Response
    {
        $expected = (string) $request->getSession()->get('csrf_token', '');
        $provided = (string) $request->request->get('_token', '');
        if ('' === $expected || !hash_equals($expected, $provided)) {
            $this->addFlash('error', 'CSRF token mismatch. Reload the dashboard and try again.');

            return $this->redirectToRoute('dashboard');
        }

        $target = (string) $request->request->get('target', '');
        if (!in_array($target, $this->config->availableTargets(), true)) {
            $this->addFlash('error', 'Unknown target. Pick one of the sandboxed contracts.');

            return $this->redirectToRoute('dashboard');
        }

        $mode = strtolower((string) $request->request->get('mode', 'mock'));
        if (!in_array($mode, ['mock', 'live'], true)) {
            $mode = 'mock';
        }
        if ('live' === $mode && !$this->config->hasLlmCredentials()) {
            $this->addFlash('error', 'Live mode needs APP_LLM_API_KEY. The mock demo is fully deterministic — try that first.');

            return $this->redirectToRoute('dashboard');
        }

        $auditRequest = new AuditRequest(
            $target,
            $mode,
            $request->request->getBoolean('bounty'),
            $request->request->getBoolean('poc', true),
        );

        try {
            $runId = $this->launcher->launch($auditRequest);
        } catch (Throwable $exception) {
            $this->addFlash('error', 'Unable to launch the audit: '.$exception->getMessage());

            return $this->redirectToRoute('dashboard');
        }

        return $this->redirectToRoute('run_show', ['id' => $runId]);
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function targets(): array
    {
        $targets = [];
        foreach ($this->config->availableTargets() as $file) {
            $manifest = $this->config->targetManifest($file);
            $targets[] = [
                'file' => $file,
                'contract' => (string) ($manifest['contract'] ?? basename($file, '.sol')),
                'expected' => (string) ($manifest['expected'] ?? 'unknown'),
                'description' => (string) ($manifest['description'] ?? ''),
                'seed_eth' => (string) ($manifest['seed']['eth'] ?? '0'),
            ];
        }

        return $targets;
    }

    /**
     * @param list<array<string, mixed>> $runs
     *
     * @return list<array<string, mixed>>
     */
    private function decorateRuns(array $runs): array
    {
        foreach ($runs as &$run) {
            $run['stats'] = $this->store->stats((string) $run['id']);
        }

        return $runs;
    }

    /**
     * @return array<string, mixed>
     */
    private function healthPayload(): array
    {
        return [
            'llm_mode' => $this->config->llmMode,
            'llm_model' => $this->config->llmModel,
            'has_llm_key' => $this->config->hasLlmCredentials(),
            'node' => $this->foundry->nodeStatus(),
            'toolchain' => $this->foundry->toolchain(),
            'rpc_url' => $this->config->rpcUrl,
            'chain_id' => $this->config->chainId,
        ];
    }
}
