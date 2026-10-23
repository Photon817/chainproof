# 复用映射

ChainProof 的目标不是重新发明一个 Agent 框架，而是把三个成熟开源仓库里的**结构与模式**
平移到 Solidity / Foundry 场景。本文件记录“从哪来、落到哪、为什么这样落”。

三个参考仓库均为 MIT License：

- <https://github.com/vinceAmstoutz/symfony-security-auditor>
- <https://github.com/m4xxxxx/AIxVuln>
- <https://github.com/qqliushiyu/AIxVuln_Web>

> 说明：仓库根目录的 `_reference/` 只用于本地对照阅读，已加入 `.gitignore` / `.dockerignore`，
> 不参与构建，也不随项目分发。ChainProof 没有直接拷贝其业务实现，而是按下列映射重写。

## 1. symfony-security-auditor → 对抗循环

| 参考实现 | ChainProof 对应 | 平移方式 |
| --- | --- | --- |
| `src/Audit/Application/Agent/AuditOrchestrator.php` | `src/Orchestration/AuditOrchestrator.php` | 保留“Attacker → Reviewer → 迭代”的主循环；把 PHP 项目文件映射换成 Solidity surface；把最大迭代次数收敛为“每个 skill 一次”。 |
| `src/Audit/Application/Agent/AttackerAgent.php` | `src/Agent/AttackerAgent.php` + `src/Agent/MockAttacker.php` | 保留“先确定性预扫描，再让 LLM 基于 marker 提候选”的结构；攻击面从 controller/voter/form 换成重入与访问控制。 |
| `src/Audit/Application/Agent/ReviewerAgent.php` | `src/Agent/ReviewerAgent.php` + `src/Agent/MockReviewer.php` | 保留“默认怀疑、逐条裁决、给出成立条件”的审查者角色；新增链上失败反馈后的 `chain_falsified` 撤回。 |
| `src/Audit/Application/Agent/PoCSynthesizer.php` | `src/Execution/ExploitTemplateRenderer.php` + `src/Agent/AttackPlanValidator.php` | 保留“为每个 finding 生成可复现 PoC”的阶段；把 PHP 断言脚本换成 Foundry script 模板，并让 LLM 只输出类型化计划。 |
| `src/Audit/Application/Agent/RiskMarkerIndex.php` 与 StaticPreScanner 相关端口 | `src/Analysis/StaticPreScanner.php` | 保留“确定性标记先于 LLM”的原则；标记集合换成 reentrancy / access_control / tx_origin / unchecked / delegatecall / selfdestruct。 |
| `src/Audit/Application/Agent/Review/RejectionTriageRecorder.php`、`VerdictApplier.php` | `src/Orchestration/AuditOrchestrator.php::resolveFinding()` | 保留“驳回也要记录理由与条件”的裁决模型；新增 `needs_manual_poc`、`poc_failed` 两个状态。 |
| `src/Audit/Application/Pipeline/Stage/PoCSynthesisStage.php` | `src/Execution/FoundryRunner.php` | 把“合成 PoC”升级成“合成 + 广播 + 采集回执 + 余额差”的完整证据链。 |
| `prompts/` 的系统提示结构 | `prompts/attacker.system.md`、`prompts/reviewer.system.md` | 保留角色分离与结构化输出约束；字段换成 `AttackPlan` / `Verdict`。 |

**没有照搬的部分**：chunking、缓存、并发审查、预算控制、Symfony 业务映射。它们服务于大型
PHP 项目，对两天黑客松的“1–2 类漏洞闭环”是额外复杂度。

## 2. AIxVuln → 编排与沙箱

| 参考实现 | ChainProof 对应 | 平移方式 |
| --- | --- | --- |
| `agents/base.go` 的 AgentProfile / TaskAssignment / 状态机 | `src/Orchestration/AuditOrchestrator.php`、`src/Domain/Model/Finding.php` | 保留“每个 Agent 有明确角色、任务与状态”的建模；状态收敛为 finding 生命周期。 |
| `DecisionBrain/Start.go` 的全局调度循环 | `src/Orchestration/AuditOrchestrator.php::run()` | 保留“编排者决定下一步、而不是 Agent 互相直接调用”的思路；用同步 PHP 流程实现，便于复现。 |
| `toolCalling/SubmitExploitIdeaTool.go` | `src/Agent/AttackPlanValidator.php` + `AttackPlan` | 保留“工具调用必须提交结构化结果”的约束；把自由 exploit idea 收窄为两个模板。 |
| `toolCalling/SubmitExploitChainTool.go` | `src/Execution/ExploitTemplateRenderer.php` | 保留“把攻击思路落成可执行链”的阶段；执行目标从任意命令换成 Foundry script。 |
| `dockerManager/Sandbox.go`、`dockerfile/dockerfile.aisandbox/` | `docker-compose.yml` + `Dockerfile` + `FoundryRunner` | 保留“隔离环境 + 一次性执行”的沙箱原则；把通用 Docker 沙箱换成 Anvil + 每 finding 全新靶场。 |
| `misc/ReportTemplate.go`、报告生成 | `src/Report/ReportBuilder.php` | 保留“事件流 → 人类可读报告”的产物结构；报告改为中文并加入链上证据与赏金章节。 |
| 项目事件流 / 任务状态展示 | `src/Orchestration/EventBus.php` + `events.jsonl` | 保留追加式事件流；同时供 CLI 与 Web 轮询消费。 |

**没有照搬的部分**：多数字人、MCP 工具生态、任意命令执行、完整 Docker 生命周期管理。
ChainProof 的执行面只有 `forge create`、`cast send`、`forge script`、`cast balance`。

## 3. AIxVuln_Web → 控制台信息架构

| 参考实现 | ChainProof 对应 | 平移方式 |
| --- | --- | --- |
| `src/components/audit/EventLog.tsx` | `templates/run.html.twig` 的 `#event-stream` + `public/app.js` | 保留“按时间追加、自动滚动”的事件日志；用原生 JS 轮询替代 WebSocket。 |
| `src/components/audit/StatusBadge.tsx` | `templates/run.html.twig` 的 `badge-*` + `status_label` macro | 保留状态色语义；新增 proven / rejected / poc_failed 等审计状态。 |
| `src/components/audit/ProjectCard.tsx` | `templates/dashboard.html.twig` 的 target 卡片 | 保留“项目卡片 + 环境信息”的入口结构；换成靶场合约与预期结果。 |
| `src/components/audit/VulnTable.tsx` | run 页的 finding 三栏与交易回执表 | 保留“漏洞列表 + 证据表”的信息密度；增加 Attacker / Reviewer / Foundry 三列对照。 |
| `src/components/audit/EnvInfoPanel.tsx` | dashboard 的 status strip、`/api/health` | 保留环境可见性；展示 LLM 模式、Anvil、Forge、Key 状态。 |
| `src/hooks/useWebSocket.ts` | `public/app.js` | 保留“实时更新”的交互目标；为了零 Node 依赖，改为 1.5s 轮询。 |

**没有照搬的部分**：Next.js、shadcn/ui、Tailwind、WebSocket 服务端。黑客松现场只需要
一个能稳定打开、无需前端构建的控制台。

## 4. 新增的、不属于任何参考仓库的部分

这些是“平移到以太坊”真正新增的工程：

- `src/Execution/Wei.php`：wei 是 10^18 级别，超过 PHP int，必须用十进制字符串运算。
- `src/Execution/FoundryRunner.php`：部署、种子资金、广播、broadcast JSON 解析、余额差、失败分类。
- `foundry/script/ChainProofScript.sol`：极简 Vm/Script/Test 基类，避免 `forge install` 网络依赖。
- `foundry/src/BountyEscrow.sol`：Immunefi 风格的本地赏金合约。
- `src/Bounty/BountyClient.php`：把“已证明发现”转成 `submit → approve → pay` 的链上支付意图。
- `foundry/targets.json`：靶场 manifest，声明合约名、预期结果、种子资金。
- dashboard 的“PHP orchestrates · Foundry judges”叙事与实时证据链展示。

## 5. 复用边界

- 参考仓库的**架构模式、角色分离、状态机、事件流、报告结构**被复用。
- 参考仓库的**具体 PHP/Go/TS 业务实现**没有被复制进本仓库。
- 若后续需要直接引入 symfony-security-auditor 的包，应通过 Composer 依赖而非拷贝源码，
  并保留其 MIT 版权声明。
- AIxVuln 的 Docker 沙箱能力远超本项目需要；本项目只保留“隔离执行 + 一次性环境”的思想。
