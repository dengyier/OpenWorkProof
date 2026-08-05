# Day 0 candidate image supply chain

本目录保存可审计、可复建的镜像定义和最小 hash-lock；wheel、Debian
`.deb`、外部构建上下文和 OCI archive 不进入 Git。

已有 `openworkproof-image-candidate-inventory/0.1` 历史清单保持原字节并继续按
各自 revision 验证；新的 current candidate 必须使用
`openworkproof-image-candidate-inventory/0.2`。只有项目 lock、execution 的
Dockerfile、requirements lock、`run_tests_runner.py`、`verifier_test.py`、helper
的 Dockerfile、requirements lock、Debian lock、source allowlist，以及
`SOURCE_ALLOWLIST` 指向的四份 helper 源码 blob 全部逐字节匹配时，清单才可被
唯一选择为 current。v0.2 的 `build_inputs.execution` 除 v0.1 的三个字段外，
还必须恰好同时记录 `runner_sha256` 与 `fixed_test_source_sha256`；任何跨版本字段
混用均拒绝。清单绑定构建
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

candidate inventory 将前两个哈希记录在闭合的 `build_inputs.global` 中；契约
测试从仓库锁文件和外部 full wheelhouse 清单读取精确 bytes 后重新计算，不能
只比较清单内的固定字符串。

`execution` 仅安装 pytest 与 Rich 15 源码测试在 Python 3.12 上的运行依赖，
不安装被测 Rich wheel，也不安装 OpenWorkProof、MCP、pip-tools 或 setuptools。
固定 Verifier test 从构建 revision 的 Git blob 写入 execution context，并以
root:root、`0444` 烘焙到不可写的 `/fixed-tests/verifier_test.py`；测试代码显式
把只读 `/workspace` 插入 `sys.path[0]` 后再 import Rich。镜像不使用 `.pth` 或
`sitecustomize.py` 隐式执行 workspace 内容。`trusted-helper-candidate` 仅复制
`SOURCE_ALLOWLIST` 中的四个 OpenWorkProof 文件及其 Python 运行闭包，并从
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

当前上下文必须位于
`/Users/molin/Project/openWorkProof-day0/build-contexts/<source-revision>/` 之类的
revision 专属仓库外目录。每个上下文包含其 Dockerfile、`requirements.lock`、`wheels/`；
execution 另含从指定 Git revision blob 逐字节复制的 `run_tests_runner.py`，
以及同一 revision 的 `verifier_test.py`；helper 另含 `debs/` 和 `helper-src/`。
execution 根 `SHA256SUMS` 精确绑定 Dockerfile、requirements lock、runner 和
Verifier test，Dockerfile 在安装前复核；`wheels/SHA256SUMS` 只列上下文内 wheel，
`debs/SHA256SUMS` 只列上下文内 `.deb`。helper 源文件按 `SOURCE_ALLOWLIST`
从指定 Git revision 的 blob 提取，禁止从 working tree 复制，也禁止复制整个
`src/openworkproof`；`helper-src/SHA256SUMS` 必须按构建 revision 的四份精确
bytes 生成，Dockerfile 在 COPY 后再次校验并删除该清单。

`prepare_context.py` 是生成这两个 context 的唯一标准入口；不得手工拼装或使用
其他脚本替代。它要求精确 40 位小写 commit SHA，先核验完整 wheelhouse 和 Deb
closure，再在同一临时根中生成并复核两个 context，最后原子发布。目标目录必须
尚不存在：

```bash
export OWP_REPO=/path/to/openWorkProof
export OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/path/to/openWorkProof-day0
export OWP_SOURCE_REVISION=0123456789abcdef0123456789abcdef01234567
python "$OWP_REPO/supply-chain/images/prepare_context.py" \
  --repo "$OWP_REPO" \
  --source-revision "$OWP_SOURCE_REVISION" \
  --wheelhouse "$OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT/wheelhouse/linux-arm64-cp312-full" \
  --deb-closure "$OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT/debs/linux-arm64-trixie-git" \
  --output-root "$OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT/build-contexts/$OWP_SOURCE_REVISION"
```

构建时固定 `--platform linux/arm64 --network none --pull=false`，并传入当前
仓库提交作为 `OWP_SOURCE_REVISION`。网络只允许出现在仓库外输入的独立获取
阶段；镜像构建本身只消费已校验的本地文件。

## 入口与边界

- execution-test candidate：`ENTRYPOINT ["/opt/venv/bin/python", "-I",
  "/opt/openworkproof/run_tests_runner.py"]`，`CMD ["execute"]`。runner 只接受
  `stage` 或 `execute`：前者从标准输入接收有界规范快照并复核 candidate
  manifest，后者只运行签名 TestProfile 绑定的固定完整命令：
  `/opt/venv/bin/python -I -m pytest -q -c /dev/null --rootdir=/fixed-tests
  --confcutdir=/fixed-tests /fixed-tests/verifier_test.py`。runner 先确认固定测试是
  预期路径下 root-owned、`0444` 的有界规范文本，并且 SHA-256 与 run contract
  的 `fixed_test_source_digest` 相等，才写入 `started.json` 和运行 pytest。
  它不安装或导入 OpenWorkProof，不接收 Sidecar
  key、Docker socket、网络或任意命令字符串；它不是最终 trusted helper，也
  不构成 registry 推送证据、不构成 Acceptor 独立验收证据、不构成 D8 证据、
  不构成 Day 0 证据。execute runner 必须是 Linux 容器私有 PID namespace 的
  PID 1；runner 与 pytest 同为 UID/GID 65532，且不给 pytest 增加 capability。
  PID 1 在启动 pytest 前关闭自身 dumpability；pytest 在 exec 前以
  `no_new_privs` 加载 unprivileged Landlock 规则，处理当前已知的全部写入、创建、
  删除、跨目录引用、截断及设备 ioctl 权限，只允许在 `/tmp` 下写入；另对精确的
  Linux `/dev/null` 字符设备仅开放写入及 ABI 支持的设备 ioctl，不开放 `/dev`
  目录或任何创建、删除、引用、截断权限。非 Linux、Landlock ABI 低于 3 或高于
  runner 已知版本、设备身份、规则加载或 `restrict_self` 失败时，
  均不得执行候选测试或生成 result。pytest 结束后，PID 1 再对 `/proc` 中全部其他
  PID 执行有界 TERM/KILL 和回收，连续确认零后代，复核 `started.json` 的 inode、
  metadata 与精确 bytes，最后才原子发布 `result.json`。PID 1、`/proc`、清理或
  复核任一条件失败均不生成 result。
- helper：`ENTRYPOINT ["/opt/venv/bin/python", "-I", "-m",
  "openworkproof.trusted_helper"]`，且 `CMD []`。trusted controller 将一个
  WorkOrder 对应的 candidate runtime root 只读挂载为 `/runtime:ro`；helper
  拒绝全部 argv，唯一 operation 为 `repo_read`。initialize、apply、rollback、
  rebuild 和 destroy 仍未提供；镜像仍明确命名为 `trusted-helper-candidate`，
  不是最终 trusted helper，也不构成 D8、Day 0 或 Acceptor 独立复现证据。
- 两者运行身份均为 `65532:65532`，并记录 source、revision、role 和基础
  digest OCI labels。

当前 archive 位于 `oci/<source-revision>/`。`*.docker-archive.tar` 是
`docker save` 产生并带 Docker `manifest.json` 的 Docker archive；
`*.oci-archive.tar` 是 `docker buildx --output type=oci` 产生、包含
`oci-layout` 与 `index.json` 且不带 Docker `manifest.json` 的真实 OCI
image-layout archive。两者格式和哈希在 candidate 清单中分开记录，不能互称。
每次 OCI export 和 live rebuild 都必须从冻结 source revision 的 commit epoch
推导 UTC RFC3339 秒值，并把它写入 manifest descriptor；不得继承 exporter wall
clock：

```bash
OWP_SOURCE_EPOCH=$(git show -s --format=%ct "$OWP_SOURCE_REVISION")
OWP_OCI_CREATED=$(./.venv/bin/python -c \
  'from datetime import datetime, timezone; import sys; print(datetime.fromtimestamp(int(sys.argv[1]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' \
  "$OWP_SOURCE_EPOCH")
docker buildx build --platform linux/arm64 --network none --pull=false \
  --provenance=false \
  --build-arg "OWP_SOURCE_REVISION=$OWP_SOURCE_REVISION" \
  --annotation \
  "manifest-descriptor:org.opencontainers.image.created=$OWP_OCI_CREATED" \
  --output "type=oci,dest=/path/to/candidate.oci-archive.tar" \
  /path/to/revision-bound-context
```

当前 `main` 仓库的 `LICENSE` 明确采用 Apache-2.0。该状态不追溯改变历史
candidate，也不改变 source revision 中尚无 `LICENSE` 的已冻结 artifact：这些
历史/冻结记录仍保持 `status=PENDING`、`spdx=NOASSERTION`，镜像中不添加
license OCI label。不得据此改写既有或 current candidate inventory 的 license
字段。

本地构建、断网 smoke、`docker save` 和 archive SHA-256 只证明本机 candidate
产物可复核；它们不构成 Acceptor access，不构成 clean-cache reacquisition，
不构成 Day 0 PASS，也不证明外部验收、推送、发布或比赛交付。

## 验证命令

普通测试不依赖仓库外个人路径；未设置 artifact root 时，`supplychain` 集成测试
精确 skip：

```bash
pytest
```

控制端必须显式提供 artifact root，并要求 live Docker。此模式下缺 root、Docker
daemon 或本地 candidate image 都是失败，不能降级为 skip：

```bash
OPENWORKPROOF_CANDIDATE_ARTIFACT_ROOT=/path/to/openWorkProof-day0 \
OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 \
pytest -m supplychain tests/test_candidate_supplychain_integration.py
```
