<?php

declare(strict_types=1);

namespace App\Controller;

use App\Orchestration\RunStore;
use App\Report\ReportBuilder;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class RunController extends AbstractController
{
    public function __construct(
        private readonly RunStore $store,
        private readonly ReportBuilder $report,
    ) {
    }

    #[Route('/runs/{id}', name: 'run_show', methods: ['GET'], requirements: ['id' => '[a-z0-9][a-z0-9-]{3,60}'])]
    public function show(string $id): Response
    {
        if (!$this->store->exists($id)) {
            throw $this->createNotFoundException('Run not found.');
        }

        $payload = $this->report->payload($id);

        return $this->render('run.html.twig', $payload + [
            'events' => $this->store->events($id, 500),
            'cli_log' => $this->tail($this->store->readText($id, 'cli.log')),
        ]);
    }

    #[Route('/api/runs/{id}', name: 'api_run', methods: ['GET'], requirements: ['id' => '[a-z0-9][a-z0-9-]{3,60}'])]
    public function api(string $id): JsonResponse
    {
        if (!$this->store->exists($id)) {
            return new JsonResponse(['error' => 'run not found'], Response::HTTP_NOT_FOUND);
        }

        $payload = $this->report->payload($id);

        return new JsonResponse($payload + [
            'events' => $this->store->events($id, 400),
            'cli_log' => $this->tail($this->store->readText($id, 'cli.log'), 40),
        ], Response::HTTP_OK, ['Cache-Control' => 'no-store']);
    }

    #[Route('/runs/{id}/report', name: 'run_report', methods: ['GET'], requirements: ['id' => '[a-z0-9][a-z0-9-]{3,60}'])]
    public function report(string $id): Response
    {
        if (!$this->store->exists($id)) {
            throw $this->createNotFoundException('Run not found.');
        }

        $html = $this->store->readText($id, 'report.html');
        if (null !== $html) {
            return new Response($html, Response::HTTP_OK, ['Content-Type' => 'text/html; charset=UTF-8']);
        }

        return $this->render('report.html.twig', $this->report->payload($id));
    }

    #[Route('/runs/{id}/artifact', name: 'run_artifact', methods: ['GET'], requirements: ['id' => '[a-z0-9][a-z0-9-]{3,60}'])]
    public function artifact(string $id, Request $request): Response
    {
        if (!$this->store->exists($id)) {
            throw $this->createNotFoundException('Run not found.');
        }

        $path = (string) $request->query->get('path', '');
        if (1 !== preg_match('#^(report\.(md|json|html)|run\.json|surface\.json|source\.sol|events\.jsonl|poc/[\w.-]+|receipts/[\w.-]+|proofs/[\w.-]+)$#', $path)) {
            throw $this->createNotFoundException('Artifact not available.');
        }

        $content = $this->store->readText($id, $path);
        if (null === $content) {
            throw $this->createNotFoundException('Artifact not found.');
        }

        $contentType = str_ends_with($path, '.json') || str_ends_with($path, '.jsonl')
            ? 'application/json; charset=UTF-8'
            : 'text/plain; charset=UTF-8';

        return new Response($content, Response::HTTP_OK, [
            'Content-Type' => $contentType,
            'Content-Disposition' => sprintf('inline; filename="%s"', basename($path)),
            'Cache-Control' => 'no-store',
        ]);
    }

    private function tail(?string $text, int $lines = 80): ?string
    {
        if (null === $text || '' === trim($text)) {
            return null;
        }

        $all = preg_split('/\R/', trim($text)) ?: [];

        return implode("\n", array_slice($all, -$lines));
    }
}
