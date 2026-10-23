<?php

declare(strict_types=1);

namespace App\Command;

use App\Config\PlatformConfig;
use App\Domain\Model\AuditRequest;
use App\Orchestration\AuditOrchestrator;
use App\Orchestration\EventBus;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

#[AsCommand(
    name: 'audit:run',
    description: 'Run the adversarial audit loop against a Solidity target and prove findings on Anvil.',
)]
final class AuditRunCommand extends Command
{
    public function __construct(
        private readonly AuditOrchestrator $orchestrator,
        private readonly EventBus $events,
        private readonly PlatformConfig $config,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('target', InputArgument::REQUIRED, 'Contract file under foundry/src, e.g. Vault.sol')
            ->addOption('mode', null, InputOption::VALUE_REQUIRED, 'Agent mode: mock or live', $this->config->llmMode)
            ->addOption('bounty', null, InputOption::VALUE_NONE, 'Submit a proven finding to the local BountyEscrow')
            ->addOption('no-poc', null, InputOption::VALUE_NONE, 'Skip Foundry execution and stop after review')
            ->addOption('run-id', null, InputOption::VALUE_REQUIRED, 'Reuse an existing run id (used by the web launcher)')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Print the final result as JSON');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $mode = strtolower((string) $input->getOption('mode'));
        if (!in_array($mode, ['mock', 'live'], true)) {
            $output->writeln('<error>--mode must be "mock" or "live".</error>');

            return Command::INVALID;
        }
        if ('live' === $mode && !$this->config->hasLlmCredentials()) {
            $output->writeln('<error>Live mode requires APP_LLM_API_KEY. Falling back is safer for the demo: use --mode=mock.</error>');

            return Command::FAILURE;
        }

        $this->events->subscribe(static function (array $event) use ($output): void {
            $message = OutputFormatter::escape((string) $event['message']);
            $line = sprintf(
                '<fg=gray>%s</> <fg=cyan>%-22s</> %s',
                substr((string) $event['at'], 11, 8),
                (string) $event['type'],
                $message,
            );
            match ((string) $event['level']) {
                'error' => $output->writeln('<fg=red>'.$line.'</>'),
                'warn' => $output->writeln('<fg=yellow>'.$line.'</>'),
                'success' => $output->writeln('<fg=green>'.$line.'</>'),
                default => $output->writeln($line),
            };
        });

        $request = new AuditRequest(
            (string) $input->getArgument('target'),
            $mode,
            (bool) $input->getOption('bounty'),
            !(bool) $input->getOption('no-poc'),
            null !== $input->getOption('run-id') ? (string) $input->getOption('run-id') : null,
        );

        try {
            $result = $this->orchestrator->run($request);
        } catch (Throwable $exception) {
            $output->writeln('');
            $output->writeln('<error>Audit failed: '.OutputFormatter::escape($exception->getMessage()).'</error>');

            return Command::FAILURE;
        }

        if ((bool) $input->getOption('json')) {
            $output->writeln((string) json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

            return Command::SUCCESS;
        }

        $stats = $result['stats'];
        $output->writeln('');
        $output->writeln('<info>Audit complete.</info>');
        $output->writeln(sprintf('  run id      : %s', (string) $result['run']['id']));
        $output->writeln(sprintf('  findings    : %d (%d accepted, %d rejected)', (int) $stats['findings'], (int) $stats['accepted'], (int) $stats['rejected']));
        $output->writeln(sprintf('  proven      : %d', (int) $stats['proven']));
        $output->writeln(sprintf('  extracted   : %s ETH', (string) $stats['extracted_eth']));
        $output->writeln(sprintf('  bounty      : %s ETH', (string) $stats['bounty_eth']));
        $output->writeln(sprintf('  report      : var/runs/%s/report.md', (string) $result['run']['id']));
        $output->writeln(sprintf('  dashboard   : /runs/%s', (string) $result['run']['id']));

        return Command::SUCCESS;
    }
}
