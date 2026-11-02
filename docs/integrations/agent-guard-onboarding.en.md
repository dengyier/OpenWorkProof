# OWP Guard: a first protected Codex task

English | [简体中文](agent-guard-onboarding.md)

OWP Guard checks supported Codex tool requests before they run. This experimental
workflow lets a guarded task read, add and edit ordinary text files inside one
chosen preview directory. It rejects out-of-scope paths, deletes and moves,
arbitrary commands, and unsupported tools.

Installing the OWP MCP server or the SOC Review Skill does **not** enable Guard.
Protection in this guide applies to a task started with `owp-guard run`; an
ordinary Codex window is not automatically protected.

## Before you start

- Use a local POSIX environment, a working Git installation and Python 3.12.
  The recorded real-host baseline is **macOS, Python 3.12 and Codex CLI 0.147.0**.
  That live record was obtained for the 1.5.0 Guard implementation; the current
  installation example uses package 1.6.0. It is not a new live acceptance claim
  for every 1.6.0 environment. Check compatibility before using another host or
  version. Windows and WorkBuddy are not verified for this Guard workflow.
- Have Codex CLI installed and signed in with your own account. `enable` runs a
  real Codex probe, and `run` executes a real Agent task. Both use your existing
  model access and quota. `doctor` does not call the model.
- Start with a copy or a new, non-sensitive project that you have permission to
  edit. The example below creates a new empty Git project with one HTML file.
  It does not build, deploy or publish a website.

The package's general Python requirement is `>=3.10`; that requirement is
different from the narrower real-host Guard baseline above.

## 1. Create a separate preview project and install OWP

Run these commands in a working directory you own. Keep the same terminal open:
later commands use `OWP_TRIAL_PROJECT` to identify the new directory.

```sh
OWP_TRIAL_PROJECT="$(mktemp -d "$(pwd -P)/owp-guard-trial.XXXXXX")"
cd "$OWP_TRIAL_PROJECT"
git init
mkdir preview
printf '<!doctype html>\n<title>OWP preview</title>\n<h1>Original heading</h1>\n' > preview/index.html
printf '.venv/\n' > .gitignore
python3.12 -m venv --copies .venv
. .venv/bin/activate
python -m pip install 'openworkproof==1.6.0'
```

The virtual environment keeps this trial's package installation separate from
other projects. `pwd -P` gives a physical path; Guard rejects symbolic-link paths.
The allowed `preview` directory must already exist and be a proper subdirectory
of the project, not the project root or a hidden directory.

## 2. Install the project hook

```sh
owp-guard install --project "$OWP_TRIAL_PROJECT" --allow-dir preview
```

This installs the project integration. It does not establish current host trust
or prove that a protected task can run. Do not treat installation success as
activation success.

## 3. Review the scope, then enable and check it

```sh
owp-guard enable --project "$OWP_TRIAL_PROJECT"
```

The default result is JSON. The interactive review and some messages are still
in Chinese; `--human` also produces Chinese output. This English guide does not
change the CLI's language.

Use this translation to check the displayed review before answering:

| Displayed text | What to check |
| --- | --- |
| 授权范围 | Only the current OWP check in this project is being authorized for a guarded launch. |
| 允许访问目录 | The directory must be this new project's `preview` directory. |
| 允许预览文件读取、增加和修改… | Read, add and edit preview text files; out-of-scope requests, deletes/moves, arbitrary commands and unknown tools are refused. |
| Codex | Check the executable path and version you intend to use. |
| 当前检查版本 | The current native hook definition being reviewed. |
| 受保护模式使用 Codex 默认模型和原有登录… | The launch uses your normal Codex model/account; personal MCP/plugin configuration is not loaded, and online search is off for this launch. Other sessions' settings are unchanged. |
| 确认后将用 Codex…执行真实的放行与阻断检查 | After confirmation, Codex performs a real allow/block probe using new synthetic files in this project. |

If you understand and agree with the displayed scope, **type lowercase `yes`
yourself** at the confirmation prompt and press Enter. Press Enter without an
answer to cancel. If the scope or executable is not what you intended, cancel
and resolve that difference first. Do not replace review with a trust shortcut.

Enabling checks actual host activity and file effects: supported reads and edits
must work, and out-of-scope write attempts must be refused before execution.
A model saying that the probe succeeded is insufficient. Failure, missing host
support or an indeterminate result does not enable a verified guarded run.

## 4. Check readiness

```sh
owp-guard doctor --project "$OWP_TRIAL_PROJECT"
```

Look for these result fields; other fields are omitted here:

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

If `ready_for_guarded_run` is false, inspect the actual reason and address it
before proceeding. Do not bypass trust or substitute an ordinary Codex launch
and describe it as protected. Upgrading, reinstalling, or changing the scope,
configuration or host identity invalidates an old review/probe and requires a
fresh enable/check cycle.

## 5. Complete one preview edit

```sh
owp-guard run --project "$OWP_TRIAL_PROJECT" --prompt "Change only the heading in preview/index.html from Original heading to Reviewed preview. Keep the remaining content unchanged. Preview only; do not publish."
```

A protected run is limited to **300 seconds**. The launch uses your existing
Codex account, without personal MCP/plugin configuration or online search.
An unsupported action can be refused even when it would be useful for the task;
builds, deployment and arbitrary commands are outside this entry point.

After the command returns, open `preview/index.html` in your editor or browser
and decide whether to keep the change. A `completed` status means that the task
ended with the required current-identity and activity checks. It is not your
acceptance of the result. The current observation is not a cryptographic proof
for every tool call: the result explicitly reports `per_tool_session_proof=false`.

## 6. Remove the project integration

```sh
owp-guard uninstall --project "$OWP_TRIAL_PROJECT"
```

Uninstall removes OWP's project integration and retains its local installation
records and events. It does not delete the preview project or change global host
trust settings. If you choose a custom `--state-dir`, use the same path on every
command, including uninstall.

## What this path does not establish

Guard is not whole-computer isolation, hardware-protected signing or a guarantee
that an Agent's work is correct. It cannot defend against every same-user process
that can replace files, the host or configuration. Host paths without a supported
pre-execution hook are outside its coverage. An installed hook, an old probe,
model self-report, or another session's activity is not proof that the current
task was protected.

The recorded 1.5.0 live checks and implementation details are retained in the
[Chinese activation record](agent-guard-onboarding.md). For the separate supplied
alert workflow, see [SOC review and evidence verification](soc-reference.md).
