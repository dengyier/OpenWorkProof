# Human Agency Profile v0.1 夜间联合审查记录

日期：2026-08-24（Asia/Shanghai）  
分支：`codex/human-agency-profile-v01`  
边界：本记录只证明本地分支实现与本轮测试结果，不等于已合并、已推送、已发布或已被外部采用。

## 已完成

Tasks 1–4 已实现：

1. 三类闭合签名对象：`HumanAgencyProfileV01`、`AgencyProfileTransitionV01`、
   `AgencyAppealV01`；
2. 不以最大时间戳兜底的唯一 current profile 图解析；
3. `WorkOrder ∩ Grant ∩ profile` 三层交集授权与稳定错误码；
4. 三类对象的 append-only SQLite 提交、不可变触发器、COMMIT-ACK exact readback、
   全历史结构校验、整行 canonical 校验与独立 `committed_at`。

关键提交：

- `d70b7bb fix: harden human agency ledger truth`
- `9f79097 docs: record human agency implementation checkpoint`

## 独立验证证据

DeepSeek Harness 先写入敌对测试，RED 为 `14 failed, 22 passed`；修复后
`tests/test_agency_ledger_v01.py` 为 `36 passed`。

Codex 随后独立运行：

```text
tests/test_agency_models_v01.py
tests/test_agency_history_v01.py
tests/test_agency_policy_v01.py
tests/test_agency_ledger_v01.py
tests/test_retraction_receipt_v05.py
tests/test_policy.py
tests/test_mcp_server.py

269 passed in 25.83s
```

同时：

- `python -m pip check`：通过；
- `python -m compileall -q src tests`：退出码 0；
- `git diff --check`：通过；
- 记录时工作树干净。

尚未运行 Task 9 的 candidate 两套件与 required-live 全量门，因此不能声称整仓全量通过。

## Task 5 安全审查结论

原计划的锁外闭包包装器不能直接实现：

- 包装器先持锁再调用现有 executor，会在新的文件描述符上第二次 `flock`，存在自锁死；
- 包装器不持锁或先释放锁再调用 executor，Acceptor 可在 profile 判定与执行器加锁之间提交
  revoke/supersede，形成 TOCTOU；
- 当前只有 repo-read、run-tests、rollback 的事务 executor，没有 `execute_apply_patch`。

推荐的最小可靠方案是：在现有 executor 已持有的 target-lock 临界区内，完成基础授权后、
任何 preflight/reservation/handler 调用前，执行可选的 profile-only authorization callback。
callback 默认 `None`，保持旧 API 默认语义不变；protected dispatcher 只负责传入延迟加载的
callback，不在锁外预先解析 history。

`apply_patch` 必须二选一：

1. v0.1 明确只保留 reserved/deny，不宣称 supersede 后可真实执行；
2. 另立任务实现具备相同 lock/reservation/publication/recovery 语义的
   `execute_apply_patch`。

## Task 6 真实性审查结论

设计要求 bundle 包含受 profile 约束的 request/decision/receipt，但当前协议存在两个事实：

- reserved deny 按规格零 receipt 写入，离线包无法证明“某次请求确实被拒绝”；
- 现有 ActionReceipt 没有 `agency_profile_id` 绑定，离线包无法证明“某次执行发生在指定
  profile 下”。

因此现阶段可真实实现的是 **agency boundary bundle**：证明 WorkOrder、公钥绑定、profiles、
transitions、appeals 以及某一冻结评估时刻的边界状态；它不能被描述为一次执行的 enforcement
proof。若要后者，需要新签名拒绝对象或带 profile 绑定的新 receipt schema，属于后续协议版本。

## 需要产品 Owner 确认的四项选择

1. v0.1 bundle 采用“授权边界证明”，还是升级协议以证明具体执行/拒绝；
2. v0.1 是否新增真实 `execute_apply_patch`，还是将其保持为 reserved/deny；
3. 是否接受 manifest 中冻结、可校验但非时间戳机构背书的 `evaluated_at`；
4. `current_status` 是否增加 `expired`，或对过期历史拒绝导出。

四项确认前，Tasks 5–6 保持未完成；这是协议真实性边界，不是测试或编码困难。

