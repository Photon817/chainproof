# ChainProof

PHP 编排、Foundry 裁决的 Solidity 合约审计工作台。

思路来自 PHP2Shell 里那套 Attacker vs. Reviewer：一个 Agent 负责找洞，另一个负责拆台，最后由本地 Anvil 上的真实交易决定谁对。审计结论不是“可能存在重入”，而是一笔确实让合约余额减少的 PoC 交易，或者一次明确的驳回。

这是 ETHShenzhen 项目一的实现。只覆盖重入和访问控制两类问题，目的是跑通闭环，不是替代 Slither。

## 怎么跑的

```
Solidity 源码
   │
   ├─ SurfaceExtractor + StaticPreScanner   先做确定性的面提取和风险标记
   │
   ├─ Attacker Agent   → 类型化 AttackPlan（reentrancy_v1 / access_control_v1）
   ├─ Reviewer Agent   → accept / reject，驳回要给理由
   │
   ├─ ExploitTemplateRenderer → 用固定模板生成 PoC
   ├─ FoundryRunner → Anvil 部署靶场、注资、广播、读回执、比余额
   │
   └─ ReportBuilder + BountyClient → 报告 / 赏金 submit-approve-pay
```

几个刻意的选择：

- **LLM 不写 Solidity。** 模型只输出 JSON 计划，`AttackPlanValidator` 校验函数是否存在、是否外部可达、有没有 `onlyOwner` 之类限制，再由模板渲染出 PoC。执行面收窄到两个模板。
- **Reviewer 有否决权。** `GuardedVault.sol` 和 `Vault.sol` 的 CEI 问题一样，但有 `nonReentrant`，Reviewer 会直接驳回，不会浪费一次链上执行。
- **链上失败会反推结论。** PoC revert 或者余额没变化，失败证据会回传给 Reviewer，finding 标成 `chain_falsified`。
- **只有 proven 且 severity ≥ high 的发现才进赏金。** 本地 `BountyEscrow` 走完提交、审批、付款，交易哈希全部落盘。

## 跑起来

需要 Docker Desktop。首次构建要能访问 Composer 和 `ghcr.io`。

```bash
make up          # 构建镜像并起 Anvil + PHP，控制台在 http://localhost:8000
make demo        # 审计 Vault.sol：重入、真实回执、赏金
make demo-all    # 三个靶场各跑一遍
```

直连 Docker Hub 和 ghcr 经常超时，可以换镜像站。`Dockerfile` 留了三个 ARG，`docker-compose.yml` 的 `anvil` 也读同一个 `FOUNDRY_IMAGE`：

```bash
export PHP_IMAGE=docker.1panel.live/library/php:8.3-cli
export COMPOSER_IMAGE=docker.1panel.live/library/composer:2
export FOUNDRY_IMAGE=ghcr.dockerproxy.net/foundry-rs/foundry:stable
docker compose build
docker compose up -d
```

不想用 Docker 的话：

```bash
composer install --prefer-dist   # composer.lock 已提交，装的是锁定的版本
anvil --chain-id 31337 --accounts 10 --balance 10000
php -S 127.0.0.1:8000 -t public public/index.php

php bin/console audit:targets
php bin/console audit:run Vault.sol --mode=mock --bounty -vvv
```

`mock` 模式不需要 API Key。`live` 模式接任意 OpenAI 兼容端点：

```bash
APP_LLM_MODE=live \
APP_LLM_BASE_URL=https://api.deepseek.com/v1 \
APP_LLM_API_KEY=sk-... \
APP_LLM_MODEL=deepseek-chat \
docker compose up -d --build app
```

如果 `forge` 下不动 solc，自己准备一个二进制，导出 `FOUNDRY_SOLC=/abs/path/to/solc`。

## 实跑结果

两套环境都跑过：本机是 PHP 8.3.32 + Symfony 7.4.21 + Foundry/Anvil 1.8.6 + solc 0.8.24；
容器是 `php:8.3-cli`（PHP 8.3.36）+ Composer 2.10.3 + foundry 镜像（1.5.1）。链都是本地 31337。

| 项目 | 结果 |
| --- | --- |
| `composer install`（真实 Composer，按 `composer.lock`） | 38 个运行时包 + 27 个开发包锁定，vendor 24M |
| `docker compose build` | 通过，镜像 1.1G |
| `forge test -vv` | 本机 6 passed，容器内 6 passed |
| `audit:run Vault.sol --mode=mock --bounty -vvv` | 1 proven，提取 3 ETH，赏金 0.5 ETH |
| `audit:run Treasury.sol --mode=mock --bounty -vvv` | 1 proven，提取 5 ETH，赏金 1 ETH |
| `audit:run GuardedVault.sol --mode=mock --bounty` | Reviewer 驳回（0.96），赏金 skipped |
| Web 控制台 | `/`、`/api/health`、`/runs/{id}`、`/report`、`/artifact` 均 200 |
| Web 表单发起审计 | 302 到 run 页，轮询到 completed，5 ETH / 1 ETH 赏金 |
| `lint:yaml` / `lint:twig` / `lint:container` | 全过 |

上面三个靶场的结果在 Docker 里逐条复现过，耗时差不多，Anvil 上看到的余额变化也一致。

Vault 的完整事件流大致长这样：

```
run.started       Audit started for src/Vault.sol in mock mode.
surface.ready     Surface mapped: 1 contract(s), 2 function(s), 1 state variable(s), 1 risk marker(s).
attacker.finding  Attacker claimed [HIGH] Reentrancy in Vault.withdraw()
reviewer.verdict  Reviewer ACCEPT f-d22ac088 (confidence 0.93)
chain.deploy      Deployed Vault at 0xa513...C853 with 3 ETH seeded.
chain.proof       PoC confirmed on Anvil: 3 ETH extracted in 2 transactions.
bounty.paid       BountyEscrow released 0.5 ETH to the auditor for f-d22ac088.
report.ready      Report ready: 1 findings, 1 proven on-chain, 3 ETH extracted.
```

## 三个靶场

| 合约 | 问题 | 预期 |
| --- | --- | --- |
| `Vault.sol` | `withdraw()` 先转账后清零 | proven，提走全部余额 |
| `Treasury.sol` | `setOperator()` 不校验权限 | proven，接管后清空 |
| `GuardedVault.sol` | 同样的 CEI 问题，但有 `nonReentrant` | rejected |

## 运行产物

每个 run 在 `var/runs/<id>/` 下：

```
run.json / events.jsonl / source.sol / surface.json
findings/<id>.json      Attacker 声明、Reviewer 裁决、proof
poc/<id>.sol            实际广播的 PoC
poc/<id>.forge.log      forge 原始日志
receipts/<id>.json      交易回执
proofs/<id>.json        余额前后、提取额、失败分类
chain/*-deploy.json     靶场部署与注资
bounty.json             赏金状态和链上交易
report.md / .json / .html
cli.log
```

## 目录

```
bin/console              CLI 入口
config/                  Framework / Twig / 路由 / DI
src/Agent/               Attacker、Reviewer、LLM 网关、计划校验
src/Analysis/            Solidity surface 提取、静态预扫描
src/Execution/           FoundryRunner、模板渲染、Wei 大数
src/Orchestration/       AuditOrchestrator、RunStore、EventBus
src/Bounty/              赏金客户端
src/Report/              md / json / html 报告
foundry/src/             Vault、Treasury、GuardedVault、BountyEscrow
foundry/script/          精简 Vm/Script 基类，不用 forge install
templates/ public/       Twig 控制台 + 原生 JS 轮询
docs/REUSE.md            参考仓库的复用映射
```

## 复用了什么

- [symfony-security-auditor](https://github.com/vinceAmstoutz/symfony-security-auditor)：Attacker/Reviewer 双 Agent、PoC 合成阶段、驳回理由的记录方式。
- [AIxVuln](https://github.com/m4xxxxx/AIxVuln)：多 Agent 编排、任务状态机、事件流、沙箱隔离思路。
- [AIxVuln_Web](https://github.com/qqliushiyu/AIxVuln_Web)：状态面板、事件日志、漏洞表格。

三个仓库都是 MIT。这里复用的是架构和角色划分，没有拷业务代码。具体到文件的对应关系在 [docs/REUSE.md](docs/REUSE.md)。

## 说明

- 只连本地 Anvil（`127.0.0.1:8545`，chain id 31337），不碰主网和测试网。
- `.env` 里的私钥是 Anvil 公开的 deterministic key，不要往里面打真钱。
- 只做重入和访问控制。模板有形状限制，对不上的发现会停在 `needs_manual_poc`。
- `live` 模式效果取决于模型；演示用 `mock`，结果可复现。
- 构建镜像要能拉基础镜像，本机直连 Docker Hub 会超时，上面是用 1panel / dockerproxy 镜像站拉下来再 build 的。

## License

MIT，见 [LICENSE](LICENSE)。
