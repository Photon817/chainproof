<?php

declare(strict_types=1);

namespace App\Orchestration;

/**
 * Append-only event feed consumed by the CLI and the web dashboard.
 * Mirrors AIxVuln's project event stream, but persists to JSONL so a run
 * survives a page reload or a crashed front-end.
 */
final class EventBus
{
    /** @var list<callable(array<string, mixed>): void> */
    private array $listeners = [];

    public function __construct(private readonly RunStore $store)
    {
    }

    public function subscribe(callable $listener): void
    {
        $this->listeners[] = $listener;
    }

    /**
     * @param array<string, mixed> $data
     */
    public function emit(string $runId, string $type, string $message, array $data = [], string $level = 'info'): void
    {
        $event = [
            'seq' => (int) round(microtime(true) * 1000),
            'at' => gmdate('c'),
            'type' => $type,
            'level' => $level,
            'message' => $message,
            'data' => $data,
        ];

        try {
            $this->store->appendEvent($runId, $event);
        } catch (\Throwable) {
            // The event feed must never abort an audit.
        }

        foreach ($this->listeners as $listener) {
            try {
                $listener($event);
            } catch (\Throwable) {
                // A broken listener (TTY, pipe) must not kill the run.
            }
        }
    }
}
