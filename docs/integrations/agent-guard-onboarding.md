# OWP Guard 首次启用：当前版本授权与真实检查

中文 | [English](agent-guard-onboarding.en.md)

自 1.5.0 起提供的实验性命令：承接 Codex 预览目录保护，完成安装后的启用与确认生效；当前安装示例为 1.6.1，以下 1.5.0 实现实机记录来自 2026-10-26，不代表所有 1.6.1 环境重新完成实机验收。
不改现有运行时策略，不重写用户的 Codex 配置，不使用跳过 Hook 信任检查的参数。

## 用户流程

1. `install` 继续只安装项目接入。
2. `enable` 展示允许目录、限制、当前检查版本与使用的 Codex 启动方式。用户交互确认
   或明确使用 `--trust-own-hook` 后，记录只针对这条 OWP 定义的授权，并执行真实检查。
3. `doctor` 分别显示安装完整性、宿主识别结果、当前版本授权、最近真实检查结果。
4. `run` 在原有 Codex CLI 中执行任务；每次启动前核对身份并交给原厂信任机制核验。
   升级、重装、定义或宿主版本变化会使旧授权/检查失效，需重新启用。

## 接入与失败契约

- 原厂 `hooks/list` 读取真实 key、currentHash、enabled 和 trustStatus；不自己计算
  原厂的定义哈希。只选择来源、命令、事件、位置及安装清单均匹配的唯一 OWP 条目。
- 用户授权记录放在 OWP 本地控制目录，每次受保护启动仅将这一项的精确 trusted_hash
  交给 Codex 的 session hooks.state。项目可信也限本次启动。没有全局信任绕过。
- 受保护运行使用 Codex 默认模型及原有登录，本次不载入个人 MCP/插件配置，关闭
  在线搜索。该方式避开本机桌面特有配置与 CLI 不兼容的情况；不改变其他会话设置。
- 原厂支持的 session trust 与持久全局 trust 分开标注；不称普通 Codex 启动已受保护。
- 真实检查在同一目标项目中只操作新建的独占合成目录。正常读取和修改必须成功，
  越界补丁与命令写入必须在执行前被拒绝。结果同时核对宿主事件/原厂拒绝提示、
  本次检查器决定和实际文件，模型自述或手动制造本地日志不能作为通过依据。
- 授权与检查绑定安装 ID、目录、配置和控制文件摘要、原厂 key/hash、Codex 版本。
  缺失、漂移、宿主不可读、请求没发生、仅被其他权限层阻止或超时均不标为通过。
- 检查记录是一次本地运行的证据，不是未来会话保证、签名协议凭证或客户独立验收。
  卸载仍只移除项目接入，保留本地记录，并撤去后续受保护启动的可用状态。

验收：保留此前安装/运行时测试；新增 native RPC、授权隔离、旧授权失效、探针反假绿
与失败清理测试；最后用本机真实 Codex 在无 bypass 参数的情况下完成启用与一次任务。

## 使用方法

使用当前 1.6.1 包中的独立命令；该入口始于 1.5.0。安装或连接 MCP 不会自动启用 Guard。
先准备已登录的 Codex CLI、Git 和 Python 3.12。已记录的实机基线为 macOS、Python 3.12、
Codex CLI 0.147.0，其他 POSIX 环境需先核查兼容性。软件包的一般要求是 Python 3.10+，
不能把它等同于 Guard 的实机验证范围。

`enable` 会通过真实 Codex 运行探针，`run` 会执行真实 Agent 任务，两者都使用你已有的
登录和模型额度。`doctor` 不调用模型。下面先用独立项目体验，不读取真实网站或敏感资料。

### 1. 新建独立预览项目并安装

在你拥有的工作目录里运行，保持同一终端打开。第一行创建唯一的新目录，不覆盖已有项目；
`pwd -P` 使用物理路径，因为 Guard 拒绝符号链接路径。

```sh
OWP_TRIAL_PROJECT="$(mktemp -d "$(pwd -P)/owp-guard-trial.XXXXXX")"
cd "$OWP_TRIAL_PROJECT"
git init
mkdir preview
printf '<!doctype html>\n<title>OWP preview</title>\n<h1>Original heading</h1>\n' > preview/index.html
printf '.venv/\n' > .gitignore
OWP_TRIAL_PYTHON="$(python3.12 -c 'import pathlib,sys; print(pathlib.Path(sys.executable).resolve())')"
"$OWP_TRIAL_PYTHON" -m venv --copies .venv
. .venv/bin/activate
python -m pip install 'openworkproof==1.6.1'
```

先解析 Python 的真实位置，避免 `python3.12` 是符号链接时复制出的环境无法启动。
这个虚拟环境将本次安装与其他项目隔开。`preview` 必须是已存在的项目子目录，不能直接
授权整个项目、隐藏目录或 `.codex`。这里的 HTML 文件只是预览副本，不会构建、部署或发布。

### 2. 安装接入、本人审阅并检查

```sh
owp-guard install --project "$OWP_TRIAL_PROJECT" --allow-dir preview
owp-guard enable --project "$OWP_TRIAL_PROJECT"
owp-guard doctor --project "$OWP_TRIAL_PROJECT"
```

`install` 只安装项目接入。`enable` 会展示授权目录、限制、当前检查版本和 Codex 程序位置。
本人审阅并确认理解后，交互输入小写 `yes`（也接受“确认”）才授权当前这一条检查并运行
真实探针；回车取消。这个上手流程不使用非交互信任参数代替审阅。取消不会更改现有授权，
安装成功或模型自报完成也不等于启用成功。

`doctor` 的关键字段应如下；其他字段在这里省略：

```json
{
  "configured": true,
  "review_status": "current",
  "host_trust_status": "trusted",
  "probe_status": "passed",
  "ready_for_guarded_run": true,
  "ordinary_startup_verified": false
}
```

这是当前程序的预期结果形状，不是一次新的 1.6.1 实机验收回执。若 `ready_for_guarded_run`
为 false，先查看实际原因，不能绕过信任或改用普通 Codex 启动后仍称为已保护。升级、重装、
范围、配置或宿主变化后，需要重新启用并完成检查。

### 3. 修改预览标题，再检查结果

只有 readiness 为 true 后才运行：

```sh
owp-guard run --project "$OWP_TRIAL_PROJECT" --prompt "仅将 preview/index.html 的 Original heading 改为 Reviewed preview，其他内容不变。只预览，不发布。"
```

每次受保护任务最多运行 300 秒；不载入个人 MCP/插件配置，在线搜索关闭。构建、部署、
任意命令和未支持工具不属于这条入口。结束后在编辑器或浏览器打开 `preview/index.html`，
由你决定是否保留修改。`completed` 不代表你已经验收结果，逐工具会话级证明仍为
`per_tool_session_proof=false`。

### 4. 结束时卸载项目接入

```sh
owp-guard uninstall --project "$OWP_TRIAL_PROJECT"
```

卸载移除本项目的 OWP 接入，保留本地记录与事件，不删除预览项目，也不修改全局宿主信任。

使用自定义 `--state-dir` 时，每个命令都须带同一路径。`--codex` 可以指定 Codex 程序；
授权同时绑定其解析后的绝对路径、文件摘要和版本。替换程序后须重新启用。
标准输出默认 JSON，`--human` 为中文；即使使用默认 JSON，当前授权审阅与交互提示仍为中文。
也可在仓库开发环境用 `PYTHONPATH=src .venv/bin/python -m openworkproof.guard_cli` 代替 `owp-guard`。

## 已验证与限制

- 首次启用阶段的授权、原生 RPC 和探针测试与已有守卫测试合计 218 项通过；
  推送前另补充了初始化时 KeyboardInterrupt/SystemExit 清理的两项真实子进程回归。
- 首次启用实机通过：本地只读原厂清单从未信任变为本次启动信任，未使用
  `--dangerously-bypass-hook-trust`，也未向原厂写入持久全局信任。
- 原厂信任核验后，四步真实探针同时通过原生读取、新文件内容、两项执行前拒绝、
  本次守卫决定与合成文件清理检查。
- 新 wheel 在独立环境安装，包入口 doctor 通过；随后真实 run 读取预览并仅修改
  一处标题，源网站及原始副本未变，全局 Codex 配置摘要未变。
- 升级/重装/范围或配置变化/宿主程序变化使旧 review 或 probe 失效，有相应负例。
  启用与任务运行全程持本项目锁，避免本 CLI 自己的升级、卸载在检查与执行间插入。
  Ctrl-C 结束检查/任务并清理子进程后可以卸载。

这一路径称为 **OWP 受保护启动**：用户仍使用原生 Codex 引擎，但由 OWP 带入当前已审阅
的单条 session trust。普通启动 Codex 的窗口仍须按原厂流程自行设置项目与 Hook 信任，
本轮没有把它标为已保护。

`run` 的 completed 表示 Agent 本次运行结束并通过当前身份核对；不是业务结果验收。
有原生工具活动而缺少对应时间窗内的守卫活动，或存在 Hook 失败提示时，返回未核实。
时间窗中的日志没有 session 级密码学关联，另一同项目会话的记录仍可能混入，所以
明确返回 `per_tool_session_proof=false`，不把数量对应当成逐项操作的独立证明。

本地 review/probe 由当前系统用户控制，没有密码学用户认证。无法抵御同权限外部进程
替换包装器、宿主或配置的竞态；原厂没有提供检查点的路径仍不在本组件范围。
WorkBuddy 当前只完成底层可行性核查，外部插件在真实桌面任务中还未验收。
