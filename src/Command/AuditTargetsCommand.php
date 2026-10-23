<?php

declare(strict_types=1);

namespace App\Command;

use App\Config\PlatformConfig;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'audit:targets',
    description: 'List the sandboxed Solidity targets and their expected demo outcome.',
)]
final class AuditTargetsCommand extends Command
{
    public function __construct(private readonly PlatformConfig $config)
    {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $rows = [];

        foreach ($this->config->availableTargets() as $target) {
            $manifest = $this->config->targetManifest($target);
            $rows[] = [
                $target,
                (string) ($manifest['contract'] ?? '-'),
                (string) ($manifest['expected'] ?? '-'),
                (string) ($manifest['description'] ?? ''),
            ];
        }

        if ([] === $rows) {
            $io->warning('No .sol targets found under foundry/src.');

            return Command::SUCCESS;
        }

        $io->title('ChainProof targets');
        $io->table(['File', 'Contract', 'Expected', 'Scenario'], $rows);
        $io->writeln(sprintf('RPC: <info>%s</info> (chain %d)', $this->config->rpcUrl, $this->config->chainId));

        return Command::SUCCESS;
    }
}
