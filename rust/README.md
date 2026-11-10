# OpenWorkProof 的 Rust 迁移

此 crate 对应 Python 源码提交 `ee60496e8ac28e82fe415c32c7bdb4278d8f4072`。已迁移的功能可通过独立的 `owp-rust` 运行。Rust MCP 提供摘要、验签、公钥指纹、签名域目录、Schema 和固定 Schema 摘要六项工具，沿用相应 Python 工具的参数名称和结构化结果。

## Install the Rust MCP server

OpenWorkProof Rust 0.1.0 runs locally on Apple Silicon Macs with macOS 11 or later.
It provides six read-only tools for evidence digests, signature checks, public key
fingerprints, signing domains, and schema lookup. The [Python MCP server](../MCP_SERVER.md)
provides the complete tool set, including the SOC tools.

Download the [MCP bundle](https://github.com/dengyier/OpenWorkProof/releases/download/rust-v0.1.0/openworkproof-rust-macos-arm64.mcpb).
Open it in a client that supports MCPB binary extensions. For clients with manual
configuration, unzip the bundle and use the absolute path to the extracted binary:

```json
{
  "mcpServers": {
    "openworkproof-rust": {
      "command": "/absolute/path/to/server/owp-rust",
      "args": ["mcp"]
    }
  }
}
```

Apple Silicon Mac 用户可下载 MCPB 安装包，在支持该格式的客户端中打开。也可解压后按上述方式配置。连接后调用 `owp_list_domains` 即可检查服务是否正常。使用验签工具时，请从自己的信任来源获取公钥。

## 构建与运行

在仓库根目录执行：

```sh
cargo build --manifest-path rust/Cargo.toml --release --locked
printf '%s\n' '{"a":1}' | rust/target/release/owp-rust digest 0.1 manifest
rust/target/release/owp-rust hash-file rust/Cargo.toml
```

| 命令 | 输入 | 输出 |
| --- | --- | --- |
| `hash-file PATH` | 文件路径 | 原始文件字节的 SHA-256 |
| `canonicalize VERSION DOMAIN` | stdin 中的 JSON 对象 | 签名前的规范字节 |
| `digest VERSION DOMAIN` | stdin 中的 JSON 对象 | 摘要与规范字节长度 |
| `sign VERSION DOMAIN KEY_FILE` | stdin 中的 JSON 对象和本地 32 字节种子文件 | 带签名的 JSON |
| `verify VERSION DOMAIN PUBLIC_KEY` | stdin 中的带签名 JSON 和无填充 base64url 公钥 | JSON 布尔结果，有效返回 0，无效返回 1 |
| `sign-checkpoint KEY_FILE` | v0.4 授权检查点的 JSON 和种子文件 | 带签名的检查点 |
| `verify-checkpoint PUBLIC_KEY` | 带签名的 v0.4 检查点和无填充 base64url 公钥 | JSON 布尔结果 |
| `mcp` | MCP 客户端通过 stdio 启动 | 六项只读工具 |

MCP 客户端将编译出的 `owp-rust` 绝对路径作为命令，参数设为 `["mcp"]`。服务名称为 `openworkproof-rust`。可与现有 `owp-mcp` 并行配置。

Schema 查询在编译时嵌入 v0.1 至 v0.5 的 24 份既有资源。查询时按 Python 的固定注册表摘要逐项校验，版本与对象名称仅用于选择内嵌资源。

## 对照验证

在安装本仓库 Python 包和开发依赖的环境中执行：

```sh
cargo test --manifest-path rust/Cargo.toml --locked --all-targets
.venv/bin/python rust/tests/python_parity.py rust/target/release/owp-rust
.venv/bin/python rust/tests/mcp_parity.py rust/target/release/owp-rust
```

对照脚本使用临时文件和合成测试密钥。普通签名按 0.1、0.3、0.4 和 0.5 版本分别对比；v0.4 授权检查点使用独立的签名域和公钥字段。

Rust 对可解析负载执行 8 MiB、10,000 节点和 128 层容器深度限制，并拒绝所解析对象中的重复键。摘要和签名生成会忽略顶层旧摘要与旧签名字段的值。验签采用严格 Ed25519 检查，并要求调用方从自己的信任来源提供公钥。MCP 还接受标准的一位尾部填充公钥。超限或非法外层 MCP 帧会结束连接。

## 待迁移功能

| 范围 | 当前状态 |
| --- | --- |
| Core 签名与摘要基础 | 文件摘要、四个版本的规范字节、通用签名与验签、v0.4 授权检查点已迁移 |
| 应用入口 | Rust CLI 和 6 个原生 MCP 工具可运行。原有 Python 应用 CLI 和其余 26 个 MCP 工具待迁移 |
| 协议验证与工作流 | Schema 查询与固定摘要已迁移。数据模型与实例校验、身份绑定、权限判断、证据包、账本及验收流程待迁移 |
| AI-SOC 和 Guard | SOC 具有独立的 JSON 与签名规则；SOC、Guard、执行适配器与外部集成待迁移 |
| 运行环境 | 原生构建及 MCP 安装包验证于 macOS arm64 |
