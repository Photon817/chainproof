<?php

declare(strict_types=1);

namespace App\Execution;

use App\Config\PlatformConfig;
use App\Domain\Model\AttackPlan;
use App\Domain\Model\Finding;
use App\Domain\Model\SoliditySurface;
use App\Orchestration\EventBus;
use App\Orchestration\RunStore;
use Throwable;

/**
 * Foundry/Anvil execution adapter. It is the final judge of the adversarial
 * loop: a finding is only "proven" when a real transaction sequence deployed
 * on the local chain moved real wei out of the target.
 *
 * The flow mirrors AIxVuln's sandboxed exploitation pipeline, but the sandbox
 * is an Anvil node and the evidence is a Foundry broadcast receipt.
 */
final class FoundryRunner
{
    /** @var array<string, string> */
    private array $addressCache = [];

    public function __construct(
        private readonly PlatformConfig $config,
        private readonly ProcessRunner $process,
        private readonly ExploitTemplateRenderer $renderer,
        private readonly RunStore $store,
        private readonly EventBus $events,
    ) {
    }

    /**
     * @return array<string, string|null>
     */
    public function toolchain(): array
    {
        $versions = [];
        foreach (['forge', 'cast', 'anvil'] as $binary) {
            try {
                $result = $this->process->run([$binary, '--version'], $this->config->foundryDir, [], 20);
                $versions[$binary] = $result->successful()
                    ? trim((string) strtok($result->output(), "\n"))
                    : null;
            } catch (Throwable) {
                $versions[$binary] = null;
            }
        }

        return $versions;
    }

    /**
     * @return array<string, mixed>
     */
    public function nodeStatus(): array
    {
        $status = [
            'reachable' => false,
            'rpc_url' => $this->config->rpcUrl,
            'expected_chain_id' => $this->config->chainId,
            'chain_id' => null,
            'block_number' => null,
            'error' => null,
        ];

        try {
            $chain = $this->process->run(
                ['cast', 'chain-id', '--rpc-url', $this->config->rpcUrl],
                $this->config->foundryDir,
                [],
                15,
            );
            if (!$chain->successful()) {
                $status['error'] = $this->firstLine($chain->output());

                return $status;
            }

            $status['chain_id'] = (int) trim($chain->stdout);
            $block = $this->process->run(
                ['cast', 'block-number', '--rpc-url', $this->config->rpcUrl],
                $this->config->foundryDir,
                [],
                15,
            );
            if ($block->successful()) {
                $status['block_number'] = (int) trim($block->stdout);
            }
            $status['reachable'] = true;
        } catch (Throwable $exception) {
            $status['error'] = $exception->getMessage();
        }

        return $status;
    }

    /**
     * @return array<string, mixed>
     */
    public function assertNode(): array
    {
        $status = $this->nodeStatus();
        if (!$status['reachable']) {
            throw new ExecutionException(sprintf(
                'Anvil is not reachable at %s. Start it with `make anvil` or `docker compose up -d anvil`. %s',
                $this->config->rpcUrl,
                (string) ($status['error'] ?? ''),
            ));
        }
        if ((int) $status['chain_id'] !== $this->config->chainId) {
            throw new ExecutionException(sprintf(
                'Refusing to broadcast: node chain id %d does not match the configured %d.',
                (int) $status['chain_id'],
                $this->config->chainId,
            ));
        }

        return $status;
    }

    /**
     * Deploy a fresh target instance, seed it according to foundry/targets.json
     * and return the deployment evidence plus the starting balance.
     *
     * @return array<string, mixed>
     */
    public function deploy(string $runId, string $targetFile, string $contractName, string $label): array
    {
        $this->assertNode();
        $manifest = $this->config->targetManifest($targetFile);
        $deployValueEth = (string) ($manifest['deploy_value_eth'] ?? '0');
        $sourceRef = 'src/'.basename($targetFile).':'.$contractName;

        $command = [
            'forge', 'create',
            '--rpc-url', $this->config->rpcUrl,
            '--private-key', $this->config->deployerKey,
            '--broadcast',
            '--json',
        ];
        if (Wei::isPositive($this->config->ethToWei($deployValueEth))) {
            $command[] = '--value';
            $command[] = $this->config->ethToWei($deployValueEth);
        }
        $command[] = $sourceRef;

        $result = $this->process->run($command, $this->config->foundryDir, [], 300);
        if (!$result->successful()) {
            throw new ExecutionException('forge create failed: '.$this->firstLine($result->output()));
        }

        $created = $this->decodeJson($result->output());
        $address = (string) ($created['deployedTo'] ?? '');
        if (1 !== preg_match('/^0x[0-9a-fA-F]{40}$/', $address)) {
            throw new ExecutionException('forge create did not return a valid contract address: '.$this->firstLine($result->output()));
        }

        $seed = is_array($manifest['seed'] ?? null) ? $manifest['seed'] : [];
        $seedEth = (string) ($seed['eth'] ?? '0');
        $seedTx = null;
        if (Wei::isPositive($this->config->ethToWei($seedEth))) {
            $seedTx = $this->seed($address, $seed, $seedEth);
        }

        $deployment = [
            'contract' => $contractName,
            'address' => $address,
            'deploy_tx' => (string) ($created['transactionHash'] ?? ''),
            'deploy_value_eth' => $deployValueEth,
            'seed_tx' => $seedTx,
            'seed_eth' => $seedEth,
            'target_before_wei' => $this->balance($address),
            'deployed_at' => gmdate('c'),
        ];

        $this->store->writeJson($runId, 'chain/'.$label.'-deploy.json', $deployment);
        $this->events->emit(
            $runId,
            'chain.deploy',
            sprintf('Deployed %s at %s with %s ETH seeded.', $contractName, $address, $seedEth),
            $deployment,
            'success',
        );

        return $deployment;
    }

    /**
     * Render, broadcast and collect a PoC for one finding.
     *
     * @return array<string, mixed>
     */
    public function prove(
        string $runId,
        string $targetFile,
        string $contractName,
        Finding $finding,
        AttackPlan $plan,
        SoliditySurface $surface,
    ): array {
        $label = $finding->id;
        $proof = [
            'verdict' => 'failed',
            'finding_id' => $label,
            'target' => ['file' => $surface->path, 'contract' => $contractName],
            'chain' => [
                'rpc_url' => $this->config->rpcUrl,
                'chain_id' => $this->config->chainId,
            ],
            'template' => $plan->template,
            'captured_at' => gmdate('c'),
            'transactions' => [],
            'target_before_wei' => '0',
            'target_after_wei' => '0',
            'extracted_wei' => '0',
            'extracted_eth' => '0',
        ];

        $scriptPath = null;

        try {
            $deployment = $this->deploy($runId, $targetFile, $contractName, $label);
            $proof['deployment'] = $deployment;
            $proof['target_before_wei'] = (string) $deployment['target_before_wei'];
            $proof['target_before_eth'] = $this->config->weiToEth($proof['target_before_wei']);
            $proof['target_after_wei'] = (string) $deployment['target_before_wei'];
            $proof['target_after_eth'] = $proof['target_before_eth'];

            $rendered = $this->renderer->render($finding, $plan, $surface);
            $proof['script'] = 'poc/'.$label.'.sol';
            $this->store->writeText($runId, $proof['script'], $rendered['source']);

            $scriptPath = $this->config->foundryDir.'/'.$rendered['file'];
            $this->writeGeneratedScript($scriptPath, $rendered['source']);

            $signature = 'reentrancy_v1' === $plan->template ? 'run(address)' : 'run(address,address)';
            $arguments = [(string) $deployment['address']];
            if ('access_control_v1' === $plan->template) {
                $arguments[] = $this->addressForKey($this->config->attackerKey);
            }

            $this->events->emit(
                $runId,
                'chain.execute',
                sprintf('Broadcasting %s against %s.', $rendered['name'], $deployment['address']),
                ['script' => $rendered['file'], 'signature' => $signature, 'template' => $plan->template],
            );

            $this->removeStaleBroadcast($rendered['name']);

            $command = array_merge([
                'forge', 'script', $rendered['file'].':'.$rendered['name'],
                '--sig', $signature,
            ], $arguments, [
                '--rpc-url', $this->config->rpcUrl,
                '--private-key', $this->config->attackerKey,
                '--broadcast',
                '-vvv',
            ]);

            $result = $this->process->run($command, $this->config->foundryDir, [], 300);
            $rawLog = $result->stdout."\n".$result->stderr;
            $log = $this->redact($rawLog);
            $this->store->writeText($runId, 'poc/'.$label.'.forge.log', $log);
            $proof['log'] = 'poc/'.$label.'.forge.log';
            $proof['forge_exit_code'] = $result->exitCode;

            if (!$result->successful()) {
                $proof['failure_kind'] = $this->classifyFailure($log);
                $proof['message'] = $this->firstFailureLine($log);
                $proof['target_after_wei'] = $this->balance((string) $deployment['address']);
                $proof['target_after_eth'] = $this->config->weiToEth($proof['target_after_wei']);

                return $this->finish($runId, $finding, $proof);
            }

            $broadcast = $this->readBroadcast($rendered['name']);
            $proof['transactions'] = $this->normalizeTransactions($broadcast, $rawLog);
            $proof['poc_tx_hash'] = $this->lastCallHash($proof['transactions']);
            $proof['target_after_wei'] = $this->balance((string) $deployment['address']);
            $proof['target_after_eth'] = $this->config->weiToEth($proof['target_after_wei']);
            $proof['extracted_wei'] = Wei::sub($proof['target_before_wei'], $proof['target_after_wei']);
            $proof['extracted_eth'] = $this->config->weiToEth($proof['extracted_wei']);

            if (Wei::isPositive($proof['extracted_wei'])) {
                $proof['verdict'] = 'proven';
            } else {
                $proof['failure_kind'] = 'no_extraction';
                $proof['message'] = 'The broadcast succeeded but the target balance did not decrease.';
            }

            $this->store->writeJson($runId, 'receipts/'.$label.'.json', [] !== $broadcast ? $broadcast : [
                'note' => 'broadcast artifact missing, forge log retained',
                'transactions' => $proof['transactions'],
            ]);
        } catch (ExecutionException $exception) {
            $proof['failure_kind'] = 'execution_error';
            $proof['message'] = $exception->getMessage();
            $this->store->writeText($runId, 'poc/'.$label.'.forge.log', $this->redact($exception->getMessage()));
            $proof['log'] = 'poc/'.$label.'.forge.log';
        } catch (Throwable $exception) {
            $proof['failure_kind'] = 'internal_error';
            $proof['message'] = $exception->getMessage();
        } finally {
            if (null !== $scriptPath && is_file($scriptPath)) {
                @unlink($scriptPath);
            }
        }

        return $this->finish($runId, $finding, $proof);
    }

    /**
     * @param array<string, mixed> $seed
     */
    private function seed(string $address, array $seed, string $seedEth): string
    {
        $function = trim((string) ($seed['function'] ?? ''));
        $account = (string) ($seed['account'] ?? 'deployer');
        $command = ['cast', 'send', $address];
        if ('' !== $function) {
            $command[] = $function;
        }
        $command = array_merge($command, [
            '--value', $this->config->ethToWei($seedEth),
            '--private-key', $this->keyFor($account),
            '--rpc-url', $this->config->rpcUrl,
            '--json',
        ]);

        $result = $this->process->run($command, $this->config->foundryDir, [], 120);
        if (!$result->successful()) {
            throw new ExecutionException(sprintf(
                'Unable to seed %s ETH into the target: %s',
                $seedEth,
                $this->firstLine($result->output()),
            ));
        }

        $receipt = $this->decodeJson($result->output());

        return (string) ($receipt['transactionHash'] ?? '');
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
            throw new ExecutionException('Unable to read the target balance: '.$this->firstLine($result->output()));
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
            throw new ExecutionException('Unable to derive the attacker address: '.$this->firstLine($result->output()));
        }

        $address = trim($result->stdout);
        if (1 !== preg_match('/^0x[0-9a-fA-F]{40}$/', $address)) {
            throw new ExecutionException('cast wallet address returned an invalid address.');
        }

        return $this->addressCache[$cacheKey] = $address;
    }

    private function keyFor(string $account): string
    {
        return match (strtolower($account)) {
            'victim' => $this->config->victimKey,
            'attacker' => $this->config->attackerKey,
            'auditor' => $this->config->auditorKey,
            'judge' => $this->config->judgeKey,
            default => $this->config->deployerKey,
        };
    }

    private function writeGeneratedScript(string $path, string $source): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new ExecutionException(sprintf('Unable to create %s.', $dir));
        }
        if (false === file_put_contents($path, $source, LOCK_EX)) {
            throw new ExecutionException(sprintf('Unable to write %s.', $path));
        }
    }

    private function removeStaleBroadcast(string $scriptName): void
    {
        $path = $this->broadcastPath($scriptName);
        if (is_file($path)) {
            @unlink($path);
        }
    }

    private function broadcastPath(string $scriptName): string
    {
        return sprintf(
            '%s/broadcast/%s.s.sol/%d/run-latest.json',
            $this->config->foundryDir,
            $scriptName,
            $this->config->chainId,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function readBroadcast(string $scriptName): array
    {
        $path = $this->broadcastPath($scriptName);
        if (!is_file($path)) {
            return [];
        }

        $data = json_decode((string) file_get_contents($path), true);

        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string, mixed> $broadcast
     *
     * @return list<array<string, mixed>>
     */
    private function normalizeTransactions(array $broadcast, string $log): array
    {
        $receipts = [];
        foreach (($broadcast['receipts'] ?? []) as $receipt) {
            if (is_array($receipt) && isset($receipt['transactionHash'])) {
                $receipts[strtolower((string) $receipt['transactionHash'])] = $receipt;
            }
        }

        $transactions = [];
        foreach (($broadcast['transactions'] ?? []) as $transaction) {
            if (!is_array($transaction)) {
                continue;
            }
            $hash = (string) ($transaction['hash'] ?? '');
            $receipt = $receipts[strtolower($hash)] ?? [];
            $transactions[] = [
                'hash' => $hash,
                'type' => (string) ($transaction['transactionType'] ?? ''),
                'contract' => (string) ($transaction['contractName'] ?? ''),
                'function' => (string) ($transaction['function'] ?? ''),
                'status' => $this->receiptStatus($receipt),
                'gas_used' => isset($receipt['gasUsed']) ? Wei::normalize((string) $receipt['gasUsed']) : null,
                'block' => isset($receipt['blockNumber']) ? Wei::normalize((string) $receipt['blockNumber']) : null,
            ];
        }

        if ([] !== $transactions) {
            return $transactions;
        }

        // Fallback for forge versions that do not leave a run-latest.json:
        // recover the hashes from the verbose log and fetch receipts via cast.
        foreach ($this->hashesFromLog($log) as $hash) {
            $receipt = $this->receiptFromNode($hash);
            $transactions[] = [
                'hash' => $hash,
                'type' => '',
                'contract' => '',
                'function' => '',
                'status' => $this->receiptStatus($receipt),
                'gas_used' => isset($receipt['gasUsed']) ? Wei::normalize((string) $receipt['gasUsed']) : null,
                'block' => isset($receipt['blockNumber']) ? Wei::normalize((string) $receipt['blockNumber']) : null,
            ];
        }

        return $transactions;
    }

    /**
     * @param array<string, mixed> $receipt
     */
    private function receiptStatus(array $receipt): string
    {
        $status = strtolower((string) ($receipt['status'] ?? ''));

        return match ($status) {
            '0x1', '1', 'success' => 'success',
            '0x0', '0', 'reverted' => 'reverted',
            default => 'unknown',
        };
    }

    /**
     * @return array<string, mixed>
     */
    private function receiptFromNode(string $hash): array
    {
        $result = $this->process->run(
            ['cast', 'receipt', $hash, '--rpc-url', $this->config->rpcUrl, '--json'],
            $this->config->foundryDir,
            [],
            30,
        );

        return $result->successful() ? $this->decodeJson($result->output()) : [];
    }

    /**
     * @return list<string>
     */
    private function hashesFromLog(string $log): array
    {
        preg_match_all('/\b(0x[0-9a-fA-F]{64})\b/', $log, $matches);

        return array_values(array_unique($matches[1] ?? []));
    }

    /**
     * @param list<array<string, mixed>> $transactions
     */
    private function lastCallHash(array $transactions): ?string
    {
        $hash = null;
        foreach ($transactions as $transaction) {
            if ('CALL' === strtoupper((string) $transaction['type'])) {
                $hash = (string) $transaction['hash'];
            }
        }

        if (null !== $hash) {
            return $hash;
        }

        return [] === $transactions ? null : (string) $transactions[count($transactions) - 1]['hash'];
    }

    /**
     * @param array<string, mixed> $proof
     *
     * @return array<string, mixed>
     */
    private function finish(string $runId, Finding $finding, array $proof): array
    {
        $this->store->writeJson($runId, 'proofs/'.$finding->id.'.json', $proof);
        $this->events->emit(
            $runId,
            'chain.proof',
            'proven' === $proof['verdict']
                ? sprintf('PoC confirmed on Anvil: %s ETH extracted in %d transactions.', $proof['extracted_eth'], count($proof['transactions']))
                : sprintf('PoC did not prove the finding (%s).', (string) ($proof['failure_kind'] ?? 'unknown')),
            [
                'verdict' => $proof['verdict'],
                'extracted_eth' => $proof['extracted_eth'],
                'transactions' => count($proof['transactions']),
                'failure_kind' => $proof['failure_kind'] ?? null,
            ],
            'proven' === $proof['verdict'] ? 'success' : 'error',
        );

        return $proof;
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

    private function classifyFailure(string $log): string
    {
        $haystack = strtolower($log);
        if (str_contains($haystack, 'compiler run failed') || str_contains($haystack, 'error (')) {
            return 'compile_error';
        }
        if (str_contains($haystack, 'connection refused') || str_contains($haystack, 'could not detect network')) {
            return 'node_unreachable';
        }
        if (str_contains($haystack, 'exploit failed') || str_contains($haystack, 'revert')) {
            return 'exploit_reverted';
        }
        if (str_contains($haystack, 'command not found') || str_contains($haystack, 'no such file or directory')) {
            return 'toolchain_missing';
        }

        return 'execution_failed';
    }

    private function firstFailureLine(string $log): string
    {
        foreach (preg_split('/\R/', $log) ?: [] as $line) {
            $line = trim($line);
            if ('' === $line) {
                continue;
            }
            if (1 === preg_match('/error|revert|failed|insufficient|not found/i', $line)) {
                return substr($line, 0, 500);
            }
        }

        return substr($this->firstLine($log), 0, 500);
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

    private function redact(string $text): string
    {
        $keys = [
            $this->config->deployerKey,
            $this->config->victimKey,
            $this->config->attackerKey,
            $this->config->auditorKey,
            $this->config->judgeKey,
        ];
        foreach ($keys as $key) {
            if (str_starts_with($key, '0x') && strlen($key) > 10) {
                $text = str_ireplace($key, '0x<redacted-key>', $text);
            }
        }

        return $text;
    }
}
