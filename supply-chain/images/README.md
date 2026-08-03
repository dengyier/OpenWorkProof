# Day 0 candidate image supply chain

本目录保存可审计、可复建的镜像定义和最小 hash-lock；wheel、Debian
`.deb`、外部构建上下文和 OCI archive 不进入 Git。

当前本地 candidate 的闭合机器清单为
`candidates/33a485eacf4ab97b2507f00e5a824ba4a5c8c29c.json`。它绑定构建
revision、基础镜像、全部 build-context 清单哈希、本地 image ID、原样
`.RepoDigests`、运行配置、OCI manifest 和 archive 哈希。当前外部本地根为
`/Users/molin/Project/openWorkProof-day0`；清单中的外部路径必须按
`local_root + relative_path` 解析，拒绝父目录穿越，不能把这个本机路径写成
Acceptor 获取路径。

## 冻结输入

- 基础镜像：`docker.io/library/python@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de`，`linux/arm64`，Python 3.12.13，Debian 13 trixie。
- 仓库 `requirements-lock.txt`：SHA-256 `be6f8e10d7a82b978913eb2b6a73ee11efc5a9af623e5a783163e3cb78179f8c`。
- 外部 46-wheel `SHA256SUMS`：SHA-256 `e8d3ccaaa1cf735113e7bd533637cef028d710725981fbe20968179c70ea3a72`。
- 完整 wheelhouse：`/Users/molin/Project/openWorkProof-day0/wheelhouse/linux-arm64-cp312-full`。它只是仓库外输入；两个构建上下文只复制各自 lock 列出的 wheel 和对应的精确 `SHA256SUMS` 子集。

`execution` 仅安装 pytest 与 Rich 15 源码测试在 Python 3.12 上的运行依赖，
不安装被测 Rich wheel，也不安装 OpenWorkProof、MCP、pip-tools 或 setuptools。
固定 Verifier test 必须在测试代码中显式把只读 `/workspace` 插入 `sys.path`
后再 import Rich；镜像不使用 `.pth` 或 `sitecustomize.py` 隐式执行 workspace
内容。`trusted-helper-candidate` 仅复制
`SOURCE_ALLOWLIST` 中的三个 OpenWorkProof 文件及其 Python 运行闭包，并从
仓库外精确 `.deb` closure 离线安装 `/usr/bin/git`；Dockerfile 中没有 apt
更新或下载。

Git closure 由固定基础镜像中的 Debian 13 trixie sources 解析；实际获取镜像为
`https://mirrors.tuna.tsinghua.edu.cn/debian` 和
`https://mirrors.tuna.tsinghua.edu.cn/debian-security`。获取结果为 31 个包，
精确包名、版本、架构、文件名和 SHA-256 见
`trusted-helper/debian-packages.lock`；仓库外 `SHA256SUMS` 的 SHA-256 为
`79095383da9e8413666d9d8e78c04b57197adcd616358fdea87e5d0a98c8460e`。
该闭包已在新的固定基础镜像容器中以 `--network none` 完成整组
`dpkg --install`、`dpkg --audit` 和 `git version 2.47.3` 验证。

## 仓库外构建上下文

上下文必须位于 `/Users/molin/Project/openWorkProof-day0/build-contexts/` 之类的
仓库外目录。每个上下文包含其 Dockerfile、`requirements.lock`、`wheels/`；
helper 另含 `debs/` 和 `helper-src/`。`wheels/SHA256SUMS` 只列上下文内 wheel，
`debs/SHA256SUMS` 只列上下文内 `.deb`。helper 源文件按 `SOURCE_ALLOWLIST`
逐一复制，禁止复制整个 `src/openworkproof`；`helper-src/SHA256SUMS` 必须按
构建 revision 的三份精确 bytes 生成，Dockerfile 在 COPY 后再次校验并删除
该清单。

构建时固定 `--platform linux/arm64 --network none --pull=false`，并传入当前
仓库提交作为 `OWP_SOURCE_REVISION`。网络只允许出现在仓库外输入的独立获取
阶段；镜像构建本身只消费已校验的本地文件。

## 入口与边界

- execution/test：`ENTRYPOINT ["/usr/bin/env", "--"]`，默认命令为
  `/opt/venv/bin/python -I -m pytest`；这允许冻结执行计划传入完整 argv，而不
  发生入口前缀重复。
- helper：`ENTRYPOINT ["/opt/venv/bin/python", "-I"]`。当前仓库没有已冻结的
  受限 helper 调度接口，因此镜像明确命名为 `trusted-helper-candidate`，默认
  退出 64；不得把它描述为最终 trusted helper。
- 两者运行身份均为 `65532:65532`，并记录 source、revision、role 和基础
  digest OCI labels。

`*.docker-archive.tar` 是 `docker save` 产生的 Docker archive；
`*.oci-archive.tar` 是 `docker buildx --output type=oci` 产生、包含
`oci-layout` 与 `index.json` 的真实 OCI image-layout archive。两者格式和哈希
在 candidate 清单中分开记录，不能互称。项目代码/文档许可证仍待权利人确认：
清单固定记录 `status=PENDING`、`spdx=NOASSERTION`，镜像中不添加 license
OCI label。

本地构建、断网 smoke、`docker save` 和 archive SHA-256 只证明本机 candidate
产物可复核；它们不构成 Acceptor access，不构成 clean-cache reacquisition，
不构成 Day 0 PASS，也不证明外部验收、推送、发布或比赛交付。
