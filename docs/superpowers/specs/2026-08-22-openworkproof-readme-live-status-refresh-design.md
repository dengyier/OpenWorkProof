# OpenWorkProof README 1.3 状态刷新设计

## 目标

同步更新 `README.md` 与 `README_en.md`，使首页同时反映 Verified Agent
Delivery、AgentTeams 真实三角色环境和最新 required-live 验证结果，并保持中英文
语义一致。

## 当前可写入事实

- `main` 已包含 Verified Agent Delivery 的模型、CLI、导出、GitHub Action、商业
  模板和 candidate inventory；
- AgentTeams controller、dashboard、Manager、Developer、Verifier 资源已运行；
- live preflight 已验证 Manager / Developer / Verifier 三种角色、三个不同 Matrix
  身份和三个不同 OpenWorkProof key id；
- required-live 全量在启用真实 AgentTeams 门后得到 `3987 passed、0 failed、
  0 skipped`；
- 上述结果证明本机真实环境与协议前置门可用，不证明一次新的 Manager → Developer
  → Verifier 真实业务执行、外部人工 Acceptor 验收、客户采用、付款或结算。

## 修改范围

1. 更新首页 AgentTeams 段落，将“真实三 Agent 环境未启用”改为分层证据状态；
2. 在当前状态列表补充 Verified Agent Delivery 已实现能力；
3. 将过期的 1.3 验证快照替换为本轮 `3987 / 0 / 0` required-live 结果；
4. 更新“尚未完成”边界，保留真实业务执行、人工验收、独立外部采用和赛事提交；
5. 中英文保持相同事实、相同数字和相同 `not_evidenced` 边界。

## 明确不做

- 不修改版本号、发布标签、PyPI 或 MCP Registry 状态；
- 不把 live preflight 写成真实业务工作流完成；
- 不宣称客户采用、付费 SOW、定金、外部付款、结算或法律审计；
- 不改动协议代码、测试代码或冻结 Schema。

## 验证

- 运行 `tests/test_documentation_boundaries.py`；
- 运行与 README/Verified Agent Delivery 相关的文档和 GitHub Action 套件；
- 搜索中英文 README，确保不再保留“AgentTeams 真实三 Agent 环境未启用”及
  `3773 passed / 1 skipped` 的过期当前状态；
- 运行 `git diff --check`。
