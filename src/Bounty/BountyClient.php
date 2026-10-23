<?php

declare(strict_types=1);

namespace App\Bounty;

use App\Config\PlatformConfig;
use App\Domain\Model\Finding;
use App\Execution\ExecutionException;
use App\Execution\FoundryRunner;
use App\Execution\ProcessRunner;
use App\Execution\Wei;
use App\Orchestration\EventBus;
use App\Orchestration\RunStore;
use Throwable;

/**
 * Drives the local BountyEscrow contract: deploy once per run, submit the
 * proven finding, have the judge approve it, then release the reward.
 *
 * This is the "agent pays itself" leg of the demo. It only ever touches the
 * disposable Anvil chain and refuses to settle anything that Foundry did not
 * prove with a real transaction.
 */
final class BountyClient
{
    /** @var array<string, string> */
    private array $addressCache = [];

    public function __construct(
        private readonly PlatformConfig $config,
        private readonly ProcessRunner $process,
        private readonly RunStore $store,
        private readonly EventBus $events,
        private readonly FoundryRunner $foundry,
    ) {
    }

    /**
     * @param array<string, mixed> $proof
     *
     * @return array<string, mixed>
     */
    public function settle(string $runId, Finding $finding, array $proof, string $report): array
    {
        $record = $this->store->readJson($runId, 'bounty.json') ?? [
            'enabled' => true,
            'status' => 'pending',
            'funding_eth' => $this->config->bountyFundingEth,
            'max_reward_eth' => $this->config->bountyMaxRewardEth,
            'transactions' => [],
            'created_at' => gmdate('c'),
        ];

        if ('paid' === ($record['status'] ?? null)) {
            return $record;
        }

        if ('proven' !== ($proof['verdict'] ?? null)) {
            return $this->skip($runId, $record, 'Foundry did not prove the finding; no bounty is claimed.');
        }
        if (!$finding->severity->isBountyEligible()) {
            return $this->skip($runId, $record, sprintf('Severity %s is below the bounty threshold.', $finding->severity->label()));
        }

        $pocTx = (string) ($proof['poc_tx_hash'] ?? '');
        if (1 !== preg_match('/^0x[0-9a-fA-F]{64}$/', $pocTx)) {
            return $this->skip($runId, $record, 'The proof has no PoC transaction hash to anchor the claim.');
        }

        $record['finding_id'] = $finding->id;
        $record['severity'] = $finding->severity->value;
        $record['report_hash'] = '0x'.hash('sha256', $report);
        $record['poc_tx_hash'] = $pocTx;
        $record['report_id'] = '0x'.hash('sha256', $runId.'|'.$finding->id);

        try {
            $record = $this->ensureEscrow($runId, $record);
            $record = $this->submit($runId, $record);
            $record = $this->approve($runId, $record, $finding);
            $record = $this->pay($runId, $record);

            $record['status'] = 'paid';
            $record['settled_at'] = gmdate('c');
            $this->store->writeJson($runId, 'bounty.json', $record);
            $this->events->emit(
                $runId,
                'bounty.paid',
                sprintf('BountyEscrow released %s ETH to the auditor for %s.', $record['reward_eth'], $finding->id),
                [
                    'escrow' => $record['escrow'],
                    'report_id' => $record['report_id'],
                    'reward_eth' => $record['reward_eth'],
                    'transactions' => $record['transactions'],
                ],
                'success',
            );

            return $record;
        } catch (Throwable $exception) {
            $record['status'] = 'failed';
            $record['error'] = $exception->getMessage();
            $record['failed_at'] = gmdate('c');
            $this->store->writeJson($runId, 'bounty.json', $record);
            $this->events->emit($runId, 'bounty.failed', $exception->getMessage(), [], 'error');

            return $record;
        }
    }

    /**
     * @param array<string, mixed> $record
     *
     * @return array<string, mixed>
     */
    private function skip(string $runId, array $record, string $reason): array
    {
        $record['status'] = 'skipped';
        $record['reason'] = $reason;
        $record['checked_at'] = gmdate('c');
        $this->store->writeJson($runId, 'bounty.json', $record);

        return $record;
    }

    /**
     * @param array<string, mixed> $record
     *
     * @return array<string, mixed>
     */
    private function ensureEscrow(string $runId, array $record): array
    {
        $existing = (string) ($record['escrow'] ?? '');
        if (1 === preg_match('/^0x[0-9a-fA-F]{40}$/', $existing)) {
            return $record;
        }

        $this->foundry->assertNode();

        $judge = $this->addressForKey($this->config->judgeKey);
        $maxRewardWei = $this->config->ethToWei($this->config->bountyMaxRewardEth);
        $fundingWei = $this->config->ethToWei($this->config->bountyFundingEth);

        $command = [
            'forge', 'create', 'src/BountyEscrow.sol:BountyEscrow',
            '--rpc-url', $this->config->rpcUrl,
            '--private-key', $this->config->deployerKey,
            '--broadcast',
            '--json',
            '--value', $fundingWei,
            '--constructor-args', $judge, $maxRewardWei,
        ];

        $result = $this->process->run($command, $this->config->foundryDir, [], 300);
        if (!$result->successful()) {
            throw new ExecutionException('Unable to deploy BountyEscrow: '.$this->firstLine($result->output()));
        }

        $created = $this->decodeJson($result->output());
        $escrow = (string) ($created['deployedTo'] ?? '');
        if (1 !== preg_match('/^0x[0-9a-fA-F]{40}$/', $escrow)) {
            throw new ExecutionException('BountyEscrow deployment did not return an address.');
        }

        $record['escrow'] = $escrow;
        $record['judge'] = $judge;
        $record['auditor'] = $this->addressForKey($this->config->auditorKey);
        $record['sponsor'] = $this->addressForKey($this->config->deployerKey);
        $record['transactions']['deploy'] = (string) ($created['transactionHash'] ?? '');
        $record['status'] = 'deployed';
        $this->store->writeJson($runId, 'bounty.json', $record);

        $this->events->emit(
            $runId,
            'bounty.deploy',
            sprintf('BountyEscrow deployed at %s with %s ETH of sponsor liquidity.', $escrow, $this->config->bountyFundingEth),
            ['escrow' => $escrow, 'max_reward_eth' => $this->config->bountyMaxRewardEth],
            'success',
        );

        return $record;
    }

    /**
     * @param array<string, mixed> $record
     *
     * @return array<string, mixed>
     */
    private function submit(string $runId, array $record): array
    {
        $tx = $this->send(
            (string) $record['escrow'],
            'submit(bytes32,bytes32,bytes32,uint8)',
            [
                (string) $record['report_id'],
                (string) $record['report_hash'],
                (string) $record['poc_tx_hash'],
                (string) $this->severityCode((string) $record['severity']),
            ],
            $this->config->auditorKey,
        );

        $record['transactions']['submit'] = $tx;
        $record['status'] = 'submitted';
        $this->store->writeJson($runId, 'bounty.json', $record);
        $this->events->emit($runId, 'bounty.submit', 'Auditor submitted the PoC receipt hash to BountyEscrow.', [
            'report_id' => $record['report_id'],
            'poc_tx_hash' => $record['poc_tx_hash'],
            'tx' => $tx,
        ]);

        return $record;
    }

    /**
     * @param array<string, mixed> $record
     *
     * @return array<string, mixed>
     */
    private function approve(string $runId, array $record, Finding $finding): array
    {
        $maxWei = $this->config->ethToWei($this->config->bountyMaxRewardEth);
        $rewardWei = 'critical' === $finding->severity->value ? $maxWei : Wei::divSmall($maxWei, 2);

        $tx = $this->send(
            (string) $record['escrow'],
            'approve(bytes32,uint256)',
            [(string) $record['report_id'], $rewardWei],
            $this->config->judgeKey,
        );

        $record['transactions']['approve'] = $tx;
        $record['reward_wei'] = $rewardWei;
        $record['reward_eth'] = $this->config->weiToEth($rewardWei);
        $record['status'] = 'approved';
        $this->store->writeJson($runId, 'bounty.json', $record);
        $this->events->emit($runId, 'bounty.approve', sprintf('Judge approved a %s ETH reward.', $record['reward_eth']), [
            'report_id' => $record['report_id'],
            'reward_eth' => $record['reward_eth'],
            'tx' => $tx,
        ]);

        return $record;
    }

    /**
     * @param array<string, mixed> $record
     *
     * @return array<string, mixed>
     */
    private function pay(string $runId, array $record): array
    {
        $before = $this->balance((string) $record['auditor']);

        $tx = $this->send(
            (string) $record['escrow'],
            'pay(bytes32)',
            [(string) $record['report_id']],
            $this->config->judgeKey,
        );

        $after = $this->balance((string) $record['auditor']);
        $record['transactions']['pay'] = $tx;
        $record['auditor_balance_before_wei'] = $before;
        $record['auditor_balance_after_wei'] = $after;
        $record['status'] = 'released';
        $this->store->writeJson($runId, 'bounty.json', $record);

        return $record;
    }

    /**
     * @param list<string> $arguments
     */
    private function send(string $to, string $signature, array $arguments, string $key): string
    {
        $command = array_merge(
            ['cast', 'send', $to, $signature],
            $arguments,
            ['--private-key', $key, '--rpc-url', $this->config->rpcUrl, '--json'],
        );

        $result = $this->process->run($command, $this->config->foundryDir, [], 180);
        if (!$result->successful()) {
            throw new ExecutionException(sprintf('Bounty transaction %s failed: %s', $signature, $this->firstLine($result->output())));
        }

        $receipt = $this->decodeJson($result->output());
        $hash = (string) ($receipt['transactionHash'] ?? '');
        if (1 !== preg_match('/^0x[0-9a-fA-F]{64}$/', $hash)) {
            throw new ExecutionException(sprintf('Bounty transaction %s did not return a receipt hash.', $signature));
        }

        return $hash;
    }

    private function balance(string $address): string
    {
        $result = $this->process->run(
            ['cast', 'balance', $address, '--rpc-url', $this->config->rpcUrl],
            $this->config->foundryDir,
            [],
            30,
        );
        if (!$result->successful()) {
            throw new ExecutionException('Unable to read the auditor balance.');
        }

        return Wei::normalize(trim($result->stdout));
    }

    private function addressForKey(string $key): string
    {
        $cacheKey = hash('sha256', $key);
        if (isset($this->addressCache[$cacheKey])) {
            return $this->addressCache[$cacheKey];
        }

        $result = $this->process->run(
            ['cast', 'wallet', 'address', '--private-key', $key],
            $this->config->foundryDir,
            [],
            30,
        );
        if (!$result->successful()) {
            throw new ExecutionException('Unable to derive an account address for the bounty flow.');
        }

        $address = trim($result->stdout);
        if (1 !== preg_match('/^0x[0-9a-fA-F]{40}$/', $address)) {
            throw new ExecutionException('cast wallet address returned an invalid address.');
        }

        return $this->addressCache[$cacheKey] = $address;
    }

    private function severityCode(string $severity): int
    {
        return match ($severity) {
            'critical' => 4,
            'high' => 3,
            default => 0,
        };
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJson(string $output): array
    {
        $trimmed = trim($output);
        if ('' === $trimmed) {
            return [];
        }

        $decoded = json_decode($trimmed, true);
        if (is_array($decoded)) {
            return $decoded;
        }

        foreach (array_reverse(preg_split('/\R/', $trimmed) ?: []) as $line) {
            $line = trim($line);
            if ('' === $line || '{' !== $line[0]) {
                continue;
            }
            $decoded = json_decode($line, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        return [];
    }

    private function firstLine(string $text): string
    {
        foreach (preg_split('/\R/', trim($text)) ?: [] as $line) {
            if ('' !== trim($line)) {
                return substr(trim($line), 0, 500);
            }
        }

        return '';
    }
}
