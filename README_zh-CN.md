# OpenWorkProof

[English](README.md) · **简体中文**

Contributors: dengyier & Tim Shing（成孝添）

**核对 AI Agent 被允许做什么、记录了什么，以及这些证据能否经得起检查。**

OpenWorkProof（OWP）是一套面向 Agent 开发者和团队的开源工具。你可以用它检查签名工作记录、核验导出的证据包，或让 Codex 在指定的预览目录内完成受限的文本修改。安全工程师还可以使用参考流程，整理和复核 Slips 告警。

是否接受或拒绝结果，仍由人作出最终决定。接入 MCP 是给 Agent 增加工具；保护 Codex 任务需要另外配置并开启 Guard。

[开始使用](#通过-mcp-开始使用) · [Codex 目录保护](#试用-codex-预览目录保护) · [文档](#文档入口) · [社区](#社区与参与)

当前版本：**1.6.1** · [PyPI](https://pypi.org/project/openworkproof/1.6.1/) · [发行说明](https://github.com/dengyier/OpenWorkProof/releases/tag/v1.6.1) · [MCP Registry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.dengyier%2FOpenWorkProof/versions/1.6.1)

## 能帮你完成哪些事？

| 你要做的事 | OWP 能提供什么 | 从哪里开始 |
| --- | --- | --- |
| 复核 Agent 的工作记录 | 核对签名任务范围、已记录的动作与证据，并导出供其他人检查的证据包；执行记录需要由你的集成提供。 | [MCP 工具](MCP_SERVER.md)、[离线验证](docs/offline-verification.md) |
| 让 Codex 修改预览副本 | 在受支持的启动方式中，明确允许一个预览目录内的文本修改，执行前拒绝越界请求。 | [Guard 接入](docs/integrations/agent-guard-onboarding.md)，实验性功能 |
| 整理 Slips 告警数据 | 将提供的 JSONL 告警按来源窗口组成案例，查看模拟决定并导出签名证据包。 | [SOC 使用流程](docs/integrations/soc-reference.md)，参考实现 |
| 给交付流程增加证据复核 | 把验证接入 GitHub Action 或自有 Agent 流程，并将人工验收保留为独立步骤。 | [GitHub Action 示例](examples/github-action/README.md)、[集成说明](docs/reference/project-overview-zh-CN.md#接入方式) |

OWP 不会自动监控电脑上所有 Agent 和工具。多个 Agent 的统一权限管理、WorkBuddy 接入和真实 SOC 主机处置，不在上述已经核验的发行路径中。

## 通过 MCP 开始使用

需要 Python **3.10+**、[uv](https://docs.astral.sh/uv/getting-started/installation/) 和支持 MCP 的客户端。在客户端的 MCP 设置中加入本地 stdio 服务：

```json
{
  "mcpServers": {
    "openworkproof": {
      "command": "uvx",
      "args": ["openworkproof==1.6.1"]
    }
  }
}
```

这是常见的 `mcpServers` 配置格式，部分客户端的文件位置或顶层字段不同，见[各客户端接入说明](MCP_SERVER.md)。首次运行时，`uvx` 会按需下载软件包和依赖。OWP 本身不要求云账户或 API Key。

连接成功后，客户端应能发现 **32 个工具**。第一次先使用内置合成数据，给 Agent 这段任务：

> 用 `owp_soc_sample_alerts` 获取 OpenWorkProof 示例，把返回的 `alerts_jsonl` 交给 `owp_soc_analyze_slips`，再将证据包交给 `owp_soc_verify_bundle`。说明生成的案例和模拟动作，不操作真实主机。没有从独立可信渠道取得公钥和检查点时，保留 UNKNOWN，并告诉我缺少什么。

你会得到案例摘要和证据包。**没有独立信任信息时返回 `UNKNOWN` 是预期行为，不代表安装失败。** 示例调查使用确定性 stub，动作在内存中模拟；它不测试真实检测准确率，也不处置主机。

要使用自己的告警，先看 [SOC 使用指南](docs/integrations/soc-reference.md)。告警内容会返回 MCP 客户端，并可能进入模型对话；只使用你有权向该客户端提供的数据。

### 可选：安装 SOC Review Skill

Skill 为 Agent 提供一套调用这些工具的操作步骤。安装了 Node.js/npm 后运行：

```sh
npx skills add dengyier/OpenWorkProof --skill openworkproof-soc-review
```

在安装器里选择 Agent 和安装范围。可以先[阅读 Skill 内容](skills/openworkproof-soc-review/SKILL.md)，也可使用[发行包中的 ZIP](https://github.com/dengyier/OpenWorkProof/releases/download/v1.6.0/openworkproof-soc-review-1.6.0.zip)。

Skill 不会自动配置 MCP 或开启 Guard，仍需单独完成前面的 MCP 配置。客户端原有的模型费用由对应服务商收取。

## 试用 Codex 预览目录保护

**实验性，需要单独开启。** Guard 适用于指定预览目录中的受支持本地文本修改。先用新建测试项目或你有权处理的副本体验。

开启前请读[完整首次使用指南](docs/integrations/agent-guard-onboarding.md)，里面包含测试项目、范围审阅、检查结果与卸载步骤。默认输出是 JSON，人工提示当前仍为中文；本人审阅范围、确认理解后再输入 `yes`，不要用信任捷径跳过审阅。

`enable` 会运行真实探针，`run` 使用你现有的 Codex 登录和模型额度。只有 `doctor` 确认安装、当前版本审阅和真实探针满足要求后，才继续任务。普通方式启动的 Codex 不会因此自动受保护。

已记录的实机基线为 **macOS、Python 3.12、Codex CLI 0.147.0**，来自 1.5.0 引入的 Guard 实现。其他环境应先核查兼容性，并在本机重新运行探针。构建、部署、在线搜索、个人 MCP/插件配置和全电脑隔离不在这条启动路径内，见[范围与限制](docs/integrations/agent-guard-codex.md)。

安装 CLI 后，在目标 Git 项目里创建 `preview` 目录和 `preview/index.html` 这样的文本文件，再运行：

```sh
uv tool install --python 3.12 'openworkproof==1.6.1'
owp-guard install --project "$(pwd -P)" --allow-dir preview
owp-guard enable --project "$(pwd -P)"
owp-guard doctor --project "$(pwd -P)"
owp-guard run --project "$(pwd -P)" --prompt "修改 preview/index.html 的标题，只保留在预览目录，不发布。"
```

## 从命令行核验证据包

已经有 OWP 证据包时，先按前面方法安装软件包，然后按包的格式选择命令：

```sh
# Core Surface Bundle
owp surface-verify /path/to/surface-bundle

# Core Acceptance Bundle
owp acceptance-bundle-verify /path/to/acceptance-bundle

# SOC 参考输出：缺少外部信任信息时，预期返回 UNKNOWN 与非零退出码
owp-aisoc verify /path/to/soc-review
```

这些包的格式和信任要求不同，请分别阅读 [Core 离线验证](docs/offline-verification.md)与 [SOC 信任说明](docs/integrations/soc-reference.md#cli-and-independent-verification)。预期公钥和检查点需要从独立可信渠道取得；从不可信包中复制同名文件，不能建立独立信任。

## 如何理解结果

- **验证检查的是指定范围、信任输入下的证据。** 它不证明业务结果一定正确。Core 的 `VERIFIED`、绑定检查的 `BOUND` 不代表客户验收或付款。
- **人工验收是独立决定。** 指定验收人保留接受或拒绝交付的权利，见[验收流程](docs/reference/project-overview-zh-CN.md#验证与验收必须分开)。
- **SOC 输出属于参考实现。** 调查使用确定性 stub，动作和验收状态为模拟结果；尚未完成真实 SOC 部署、生产检测基准、操作系统隔离或 HSM 接入。
- **签名工具涉及敏感密钥。** 通用密钥生成和签名工具可能返回或接收私钥材料；生产签名密钥应留在模型对话外，由受控的外部签名流程处理。

OWP 是开源项目，当前软件包和 Skill 可按各自许可证免费使用；模型服务和基础设施可能另收费。目录收录、自动评分和工程测试，不代表客户采用或安全认证。

## 文档入口

| 你需要什么 | 文档 |
| --- | --- |
| 配置 MCP、了解 32 个工具 | [MCP 接入与工具参考](MCP_SERVER.md) |
| 导入 Slips 告警、安装 Skill | [SOC 使用流程](docs/integrations/soc-reference.md) |
| 开启 Codex 预览任务保护 | [中文指南](docs/integrations/agent-guard-onboarding.md) · [English guide](docs/integrations/agent-guard-onboarding.en.md) |
| 开发签名任务范围与人类授权集成 | [Human Agency 协议](docs/protocol/human-agency-profile-v0.1.md) · [可运行示例](examples/human_agency_profile_v01.py) |
| 协议细节和历史验证记录 | [中文参考](docs/reference/project-overview-zh-CN.md) · [English reference](docs/reference/project-overview-en.md) · [状态记录](docs/status.md) |
| 报告复现问题或参与开发 | [贡献指南](CONTRIBUTING.md) · [Issues](https://github.com/dengyier/OpenWorkProof/issues) |

## 社区与参与

[![OpenWorkProof MCP on MCPRush](https://mcprush.com/badge/openworkproof-mcp/card.svg)](https://mcprush.com/to/openworkproof-mcp?ref=badge)

这是动态目录徽章，评分对应的版本和范围请查看平台说明。OWP 在 [MCPRush](https://mcprush.com/dengyier/openworkproof-mcp)、[Glama](https://glama.ai/mcp/servers/dengyier/OpenWorkProof) 和 [AgentSkills.in](https://www.agentskills.in/marketplace/@dengyier/openworkproof-soc-review) 有公开入口。

[社区记录](docs/reference/project-overview-zh-CN.md#社区贡献与外部记录)保留了目录贡献、外部研究、集成实验、技术文章及原始链接和核对日期。各项记录范围不同，不表示相关项目的背书或生产采用。

欢迎提交可复现问题、接入适配或文档改进。安全问题请通过 [GitHub Security Advisories](https://github.com/dengyier/OpenWorkProof/security/advisories/new) 私下报告。

## 许可证

OWP Core：[Apache-2.0](LICENSE)。Tim Shing（成孝添），GitHub 账号 `alphatin123`，贡献的 `aisoc` 组件：[MIT](LICENSES/MIT-aisoc.txt)。组合软件包的元数据使用 `Apache-2.0 AND MIT`。
