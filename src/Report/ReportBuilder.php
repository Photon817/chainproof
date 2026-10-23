<?php

declare(strict_types=1);

namespace App\Report;

use App\Config\PlatformConfig;
use App\Domain\Model\Finding;
use App\Orchestration\RunStore;
use Twig\Environment;

/**
 * Turns one run directory into the three artifacts the demo needs:
 * report.json (machine readable), report.md (judge readable) and report.html
 * (screen readable). The markdown is also the payload hash that the bounty
 * claim anchors on-chain.
 */
final class ReportBuilder
{
    public function __construct(
        private readonly PlatformConfig $config,
        private readonly RunStore $store,
        private readonly Environment $twig,
    ) {
    }

    /**
     * @return array<string, string>
     */
    public function build(string $runId): array
    {
        $payload = $this->payload($runId);
        $markdown = $this->markdownFrom($payload);

        $this->store->writeText($runId, 'report.md', $markdown);
        $this->store->writeJson($runId, 'report.json', $payload);
        $this->store->writeText(
            $runId,
            'report.html',
            $this->twig->render('report.html.twig', $payload),
        );

        return [
            'markdown' => 'report.md',
            'json' => 'report.json',
            'html' => 'report.html',
            'sha256' => hash('sha256', $markdown),
            'headline' => (string) $payload['summary']['headline'],
        ];
    }

    public function markdown(string $runId): string
    {
        return $this->markdownFrom($this->payload($runId));
    }

    /**
     * @return array<string, mixed>
     */
    public function payload(string $runId): array
    {
        $run = $this->store->read($runId);
        $findings = array_map(
            static fn (Finding $finding): array => $finding->toArray(),
            $this->store->findings($runId),
        );
        $stats = $this->store->stats($runId);
        $bounty = $this->store->readJson($runId, 'bounty.json');
        $best = $this->bestFinding($findings);

        return [
            'run' => $run,
            'findings' => $findings,
            'stats' => $stats,
            'bounty' => $bounty,
            'generated_at' => gmdate('c'),
            'summary' => [
                'headline' => sprintf(
                    '%d findings, %d proven on-chain, %s ETH extracted',
                    (int) $stats['findings'],
                    (int) $stats['proven'],
                    (string) $stats['extracted_eth'],
                ),
                'best_finding' => null !== $best ? (string) $best['title'] : null,
                'best_severity' => null !== $best ? (string) $best['severity'] : null,
                'bounty_eth' => (string) $stats['bounty_eth'],
            ],
        ];
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function markdownFrom(array $payload): string
    {
        $run = $payload['run'];
        $findings = $payload['findings'];
        $stats = $payload['stats'];
        $bounty = $payload['bounty'];
        $summary = $payload['summary'];
        $lines = [];

        $lines[] = '# ChainProof 审计报告 · '.((string) ($run['id'] ?? 'unknown'));
        $lines[] = '';
        $lines[] = '> Don\'t trust the LLM. Prove it on-chain.';
        $lines[] = '';
        $lines[] = '## 1. 结论先行';
        $lines[] = '';
        $lines[] = sprintf(
            '本次审计在 **%s** 上运行。Attacker Agent 提出候选，Reviewer Agent 进行对抗式复核，Foundry/Anvil 负责最终裁决：**%d 个发现，%d 个在本地链上真实提取了资金，共 %s ETH**。',
            (string) ($run['target'] ?? 'unknown'),
            (int) $stats['findings'],
            (int) $stats['proven'],
            (string) $stats['extracted_eth'],
        );
        $lines[] = '';
        if (null !== $summary['best_finding']) {
            $lines[] = sprintf(
                '最高优先级发现：**%s**（%s）。',
                (string) $summary['best_finding'],
                strtoupper((string) $summary['best_severity']),
            );
            $lines[] = '';
        }
        $lines[] = '| 指标 | 值 |';
        $lines[] = '| --- | --- |';
        $lines[] = sprintf('| Run ID | `%s` |', (string) ($run['id'] ?? ''));
        $lines[] = sprintf('| 目标 | `%s` |', (string) ($run['target'] ?? ''));
        $lines[] = sprintf('| 模式 | `%s` |', (string) ($run['mode'] ?? 'mock'));
        $lines[] = sprintf('| 候选 / 通过 / 驳回 / 已验证 | %d / %d / %d / %d |', (int) $stats['findings'], (int) $stats['accepted'], (int) $stats['rejected'], (int) $stats['proven']);
        $lines[] = sprintf('| 链上提取 | %s ETH |', (string) $stats['extracted_eth']);
        $lines[] = sprintf('| 赏金结算 | %s ETH |', (string) $stats['bounty_eth']);
        $lines[] = '';
        $lines[] = '## 2. 对抗式审计流程';
        $lines[] = '';
        $lines[] = '1. **静态面提取**：`SurfaceExtractor` 解析合约、函数、状态变量与行号，`StaticPreScanner` 生成重入 / 访问控制证据标记。';
        $lines[] = '2. **Attacker**：只针对收窄后的漏洞类型提出发现，并输出类型化 `AttackPlan`（`reentrancy_v1` / `access_control_v1`）。';
        $lines[] = '3. **Reviewer**：默认怀疑，检查外部可达性、修饰符、CEI 顺序与正收益；审查通过后才允许进入链上验证。';
        $lines[] = '4. **Foundry/Anvil**：部署全新靶场实例，注入受害者资金，广播真实交易，读取交易回执与余额差。';
        $lines[] = '5. **链上反馈**：若 PoC 失败，Reviewer 接收链上反馈并撤回接受；只有真实回执才能把发现标记为 `proven`。';
        $lines[] = '';
        $lines[] = '## 3. 漏洞发现';
        $lines[] = '';

        if ([] === $findings) {
            $lines[] = '_本次运行没有产生候选发现。_';
            $lines[] = '';
        }

        foreach ($findings as $index => $finding) {
            $number = $index + 1;
            $proof = is_array($finding['proof'] ?? null) ? $finding['proof'] : null;
            $verdict = is_array($finding['verdict'] ?? null) ? $finding['verdict'] : null;
            $plan = is_array($finding['plan'] ?? null) ? $finding['plan'] : null;

            $lines[] = sprintf(
                '### 3.%d [%s] %s',
                $number,
                strtoupper((string) $finding['severity']),
                (string) $finding['title'],
            );
            $lines[] = '';
            $lines[] = sprintf('- **状态**：%s', $this->statusLabel((string) $finding['status']));
            $lines[] = sprintf('- **位置**：`%s` L%d-L%d · `%s.%s()`', (string) $finding['file'], (int) $finding['line_start'], (int) $finding['line_end'], (string) $finding['contract'], (string) $finding['function']);
            $lines[] = sprintf('- **类型**：%s · **Attacker 信心**：%.2f', (string) $finding['type'], (float) $finding['confidence']);
            $lines[] = '';
            $lines[] = '**Attacker 结论**';
            $lines[] = '';
            $lines[] = (string) $finding['description'];
            $lines[] = '';

            if (null !== $verdict) {
                $lines[] = '**Reviewer 裁决**';
                $lines[] = '';
                $lines[] = sprintf(
                    '- 决策：`%s`（信心 %.2f）%s',
                    strtoupper((string) $verdict['decision']),
                    (float) $verdict['confidence'],
                    !empty($verdict['chain_falsified']) ? ' · **链上证据已推翻该声明**' : '',
                );
                $lines[] = '- 理由：'.$this->oneLine((string) $verdict['reasoning']);
                foreach (($verdict['conditions'] ?? []) as $condition) {
                    $lines[] = '- 前提：'.$this->oneLine((string) $condition);
                }
                $lines[] = '';
            }

            if (null !== $plan) {
                $lines[] = '**攻击计划**（`'.$plan['template'].'`）';
                $lines[] = '';
                foreach (($plan['steps'] ?? []) as $stepNumber => $step) {
                    $lines[] = sprintf('%d. %s', $stepNumber + 1, $this->oneLine((string) $step));
                }
                $lines[] = '';
            }

            if (null !== $proof) {
                $lines[] = '**链上证据**';
                $lines[] = '';
                $lines[] = sprintf('- PoC 脚本：`%s`', (string) ($proof['script'] ?? 'n/a'));
                $lines[] = sprintf('- 靶场合约：`%s`', (string) ($proof['deployment']['address'] ?? 'n/a'));
                $lines[] = sprintf('- 余额变化：%s ETH → %s ETH（提取 **%s ETH**）', $this->weiToEth((string) ($proof['target_before_wei'] ?? '0')), $this->weiToEth((string) ($proof['target_after_wei'] ?? '0')), (string) ($proof['extracted_eth'] ?? '0'));
                if (!empty($proof['poc_tx_hash'])) {
                    $lines[] = sprintf('- PoC 交易：`%s`', (string) $proof['poc_tx_hash']);
                }
                if ('proven' !== ($proof['verdict'] ?? '')) {
                    $lines[] = sprintf('- 失败类型：`%s` · %s', (string) ($proof['failure_kind'] ?? 'unknown'), $this->oneLine((string) ($proof['message'] ?? '')));
                }
                $lines[] = '';
                $transactions = is_array($proof['transactions'] ?? null) ? $proof['transactions'] : [];
                if ([] !== $transactions) {
                    $lines[] = '| # | 类型 | 合约 / 函数 | 回执 | Gas | 区块 | Hash |';
                    $lines[] = '| --- | --- | --- | --- | --- | --- | --- |';
                    foreach ($transactions as $transactionNumber => $transaction) {
                        $lines[] = sprintf(
                            '| %d | %s | %s / %s | %s | %s | %s | `%s` |',
                            $transactionNumber + 1,
                            (string) ($transaction['type'] ?? ''),
                            (string) ($transaction['contract'] ?? ''),
                            (string) ($transaction['function'] ?? ''),
                            (string) ($transaction['status'] ?? ''),
                            (string) ($transaction['gas_used'] ?? ''),
                            (string) ($transaction['block'] ?? ''),
                            (string) ($transaction['hash'] ?? ''),
                        );
                    }
                    $lines[] = '';
                }
            }

            $lines[] = '**修复建议**';
            $lines[] = '';
            $lines[] = (string) $finding['remediation'];
            $lines[] = '';
        }

        $lines[] = '## 4. 赏金结算';
        $lines[] = '';
        if (is_array($bounty)) {
            $lines[] = sprintf('- 状态：`%s`', (string) ($bounty['status'] ?? 'unknown'));
            $lines[] = sprintf('- BountyEscrow：`%s`', (string) ($bounty['escrow'] ?? 'n/a'));
            $lines[] = sprintf('- 报告哈希：`%s`', (string) ($bounty['report_hash'] ?? 'n/a'));
            $lines[] = sprintf('- PoC 交易哈希：`%s`', (string) ($bounty['poc_tx_hash'] ?? 'n/a'));
            if (!empty($bounty['reward_eth'])) {
                $lines[] = sprintf('- 奖励：**%s ETH**', (string) $bounty['reward_eth']);
            }
            if (!empty($bounty['reason'])) {
                $lines[] = '- 未结算原因：'.$this->oneLine((string) $bounty['reason']);
            }
            if (!empty($bounty['error'])) {
                $lines[] = '- 结算错误：'.$this->oneLine((string) $bounty['error']);
            }
            foreach (($bounty['transactions'] ?? []) as $name => $hash) {
                if (is_string($hash) && '' !== $hash) {
                    $lines[] = sprintf('- `%s` 交易：`%s`', (string) $name, $hash);
                }
            }
        } else {
            $lines[] = '_本次运行未启用赏金结算。_';
        }
        $lines[] = '';
        $lines[] = '## 5. 本地复现';
        $lines[] = '';
        $lines[] = '```bash';
        $lines[] = '# 1) 启动本地链';
        $lines[] = 'docker compose up -d anvil';
        $lines[] = '';
        $lines[] = '# 2) 重新运行审计（mock 模式无需 API Key）';
        $lines[] = sprintf('php bin/console audit:run %s --mode=mock%s', (string) ($run['target'] ?? 'Vault.sol'), !empty($run['bounty_enabled']) ? ' --bounty' : '');
        $lines[] = '';
        $lines[] = '# 3) 查看生成的 PoC 与回执';
        $lines[] = sprintf('ls var/runs/%s/poc var/runs/%s/receipts', (string) ($run['id'] ?? '<run-id>'), (string) ($run['id'] ?? '<run-id>'));
        $lines[] = '```';
        $lines[] = '';
        $lines[] = '> 所有交易只发生在 `127.0.0.1:8545` 的 Anvil 链上，不接触任何主网或第三方资产。';
        $lines[] = '';
        $lines[] = sprintf('_报告生成时间：%s · 平台：ChainProof · 引擎：Symfony + Foundry/Anvil_', (string) $payload['generated_at']);
        $lines[] = '';

        return implode("\n", $lines);
    }

    /**
     * @param list<array<string, mixed>> $findings
     *
     * @return array<string, mixed>|null
     */
    private function bestFinding(array $findings): ?array
    {
        $best = null;
        foreach ($findings as $finding) {
            if ('proven' !== ($finding['status'] ?? null)) {
                continue;
            }
            if (null === $best || $this->rank($finding) > $this->rank($best)) {
                $best = $finding;
            }
        }

        return $best;
    }

    /**
     * @param array<string, mixed> $finding
     */
    private function rank(array $finding): int
    {
        $severity = match ((string) ($finding['severity'] ?? 'info')) {
            'critical' => 4,
            'high' => 3,
            'medium' => 2,
            'low' => 1,
            default => 0,
        };

        return $severity * 1_000_000 + (int) round(((float) ($finding['confidence'] ?? 0.0)) * 100_000);
    }

    private function statusLabel(string $status): string
    {
        return match ($status) {
            'proven' => '链上已验证（proven）',
            'accepted' => '审查通过，待链上验证',
            'needs_manual_poc' => '需人工 PoC',
            'poc_failed' => 'PoC 未通过',
            'rejected' => '审查驳回',
            default => '候选',
        };
    }

    private function oneLine(string $text): string
    {
        return trim(preg_replace('/\s+/', ' ', $text) ?? $text);
    }

    private function weiToEth(string $wei): string
    {
        return $this->config->weiToEth($wei);
    }
}
