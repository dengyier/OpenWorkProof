# OpenWorkProof Work-to-Settlement Pitch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a new 16-slide OpenWorkProof competition and angel-round deck that converts the teacher discussion into a five-minute “pain → solution → commercial effect” story, preserves OpenWorkProof as the main brand, introduces OpenPay only as the commercial settlement-orchestration layer, and keeps V3/V4 unchanged.

**Architecture:** Use V3 as the only visual template, inspect and duplicate mapped source slides, then edit inherited PowerPoint objects through `@oai/artifact-tool`. Build 12 core slides and 4 evidence appendices from one source-backed content contract, attach `[Sources]` notes to every slide, and export only after semantic, visual, overflow, provenance, and historical-file integrity gates pass.

**Tech Stack:** JavaScript ES modules, `@oai/artifact-tool`, native PowerPoint objects, V3 inherited masters/layouts, bundled Node/Python presentation tools, speaker-note source blocks, local evidence screenshots, ZIP/XML verification, Git for the specification and plan records only.

---

## File Map

### Product repository records

- Read: `/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-10-openworkproof-work-to-settlement-pitch-design.md`
- Create: `/Users/molin/Project/openWorkProof/docs/superpowers/plans/2026-08-10-openworkproof-work-to-settlement-pitch-implementation.md`
- Preserve existing dirty files and evidence bundles; do not stage them with this plan.

### Visual source and historical outputs

- Preserve: `/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx`
- Preserve: `/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V4_YC双线叙事版.pptx`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V5_Agent结算版.pptx`

### Build workspace

- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/package.json`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/source-notes.txt`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/qa-ledger.txt`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/design-notes.txt`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/template-audit.txt`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/template-frame-map.json`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/template-starter.pptx`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/deck-data.mjs`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/deck-contract.test.mjs`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/edit-helpers.mjs`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/compose-core.mjs`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/compose-appendix.mjs`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/build-v5.mjs`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/rendered/`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/contact-sheet.png`

### Approved reusable inputs

- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/team/dong-haoyu.jpg`
- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/team/deng-haibo.jpg`
- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/team/long-shenghai.png`
- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/dev-mikhail-receipts-retraction.png`
- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/dev-puneet-verification-cost.png`
- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/glama-openworkproof-listing.png`

## Task 1: Isolate execution and freeze source truth

- [ ] **Step 1: Create an isolated execution worktree**

At implementation time, invoke `using-git-worktrees` before changing any repository record. The current branch contains unrelated modified files and evidence bundles; never execute this plan directly on that dirty branch.

Run after the worktree skill selects a safe path:

```bash
git status --short --branch
git rev-parse HEAD
```

Expected: the execution worktree is clean and starts from the commit containing this plan and specification.

- [ ] **Step 2: Freeze V3 and V4 identities**

Run:

```bash
set -e
for file in \
  '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx' \
  '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V4_YC双线叙事版.pptx'; do
  test -s "$file"
  stat -f 'FILE=%N SIZE=%z' "$file"
  shasum -a 256 "$file"
done
```

Expected: both historical files exist and produce exact size/SHA values. Record them in `qa-ledger.txt`; do not use the older V4 QA ledger identity as current truth.

- [ ] **Step 3: Freeze the teacher-discussion interpretation**

Create `source-notes.txt` with this exact opening:

```text
Deck: OpenWorkProof V5 Agent结算版
Primary transcript: https://icnabp01o6e3.feishu.cn/docx/H9Iqdm8h9olPzYxQgsdcLJrmnUf
AI minutes: https://icnabp01o6e3.feishu.cn/docx/MRnHdPxaEoEEdfxN0vnc1BJmnvf
Recording page: https://icnabp01o6e3.feishu.cn/minutes/obcnch1bfe842ygj13gt4y43
Truth rule: transcript wins when AI minutes strengthen or alter a claim.
Partnership boundary: Worldpay/PayPal are possible future partner types; no contact, intent, partnership, endorsement, or integration is evidenced.
Product boundary: OpenWorkProof proves and accepts work; OpenPay orchestrates settlement instructions through existing systems; neither product currently claims custody, clearing, token issuance, or token exchange.
```

- [ ] **Step 4: Re-run current repository truth checks**

Run:

```bash
set -e
cd '/Users/molin/Project/openWorkProof'
git status --short --branch
git rev-parse HEAD
rg -n '^version|__version__|PyPI|Glama|MCP|test' pyproject.toml README.md src/openworkproof 2>/dev/null | head -120
if test -x .venv/bin/python; then
  .venv/bin/python -m pytest -q
else
  python3 -m pytest -q
fi
```

Expected: record the exact pass/fail/skip/warning summary and distribution-version conflicts. Do not preserve an older headline test number when the fresh suite differs.

## Task 2: Initialize presentation tooling and inspect the complete V3 template

- [ ] **Step 1: Load bundled dependencies and initialize the workspace**

Use the workspace dependency loader, then run with the returned Node path:

```bash
set -e
SKILL_DIR='/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations'
TMP_DIR='/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build'
NODE='/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
mkdir -p "$TMP_DIR"
"$NODE" "$SKILL_DIR/container_tools/setup_artifact_tool_workspace.mjs" --workspace "$TMP_DIR"
test -f "$TMP_DIR/package.json"
```

Expected: artifact-tool workspace exits 0 and `package.json` exists.

- [ ] **Step 2: Read the installed artifact-tool APIs**

Read completely before writing the builder:

```text
/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/artifact_tool_docs/API_QUICK_START.md
/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/artifact_tool_docs/api/API_DOCS.md
/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/artifact_tool_docs/api/references/master.spec.md
/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/artifact_tool_docs/api/references/layout.spec.md
/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/artifact_tool_docs/api/references/inspect.md
/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/artifact_tool_docs/api/references/cookbook/imported-deck.md
```

Expected: use only installed runtime APIs; do not use `python-pptx` or direct OOXML mutation.

- [ ] **Step 3: Inspect all V3 source slides**

Run:

```bash
set -e
SKILL_DIR='/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations'
TMP_DIR='/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build'
NODE='/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
"$NODE" "$SKILL_DIR/template_following_scripts/inspect_template_deck.mjs" \
  --workspace "$TMP_DIR" \
  --pptx '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx'
```

Expected: 16 source-slide renders, inspect NDJSON, layout JSON, media and a manifest are present. Inspect all 16 renders individually, not only the contact sheet.

- [ ] **Step 4: Create the frame map**

Create `template-frame-map.json` by reusing the already inspected V3 element targets from the V4 frame map. This avoids guessing IDs and keeps each target bound to its source slide:

```bash
set -e
OLD='/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/template-frame-map.json'
NEW='/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/template-frame-map.json'
test -s "$OLD"
jq '
  . as $old |
  [
    {outputSlide:1,sourceSlide:1,narrativeRole:"opening conflict"},
    {outputSlide:2,sourceSlide:6,narrativeRole:"future scenario"},
    {outputSlide:3,sourceSlide:2,narrativeRole:"payment pain"},
    {outputSlide:4,sourceSlide:5,narrativeRole:"missing layer"},
    {outputSlide:5,sourceSlide:6,narrativeRole:"two-layer product"},
    {outputSlide:6,sourceSlide:7,narrativeRole:"work-to-payment flow"},
    {outputSlide:7,sourceSlide:10,narrativeRole:"current product proof"},
    {outputSlide:8,sourceSlide:12,narrativeRole:"first payer"},
    {outputSlide:9,sourceSlide:12,narrativeRole:"purchased outcome"},
    {outputSlide:10,sourceSlide:13,narrativeRole:"business model"},
    {outputSlide:11,sourceSlide:13,narrativeRole:"market and moat"},
    {outputSlide:12,sourceSlide:15,narrativeRole:"team raise close"},
    {outputSlide:13,sourceSlide:6,narrativeRole:"protocol appendix"},
    {outputSlide:14,sourceSlide:9,narrativeRole:"engineering appendix"},
    {outputSlide:15,sourceSlide:11,narrativeRole:"ecosystem appendix"},
    {outputSlide:16,sourceSlide:15,narrativeRole:"assumption boundary"}
  ] as $mapping |
  {
    outputSlides: ($mapping | map(
      . as $m |
      $m + {
        reuseMode:"duplicate-slide",
        editTargets: ($old.outputSlides[] | select(.sourceSlide == $m.sourceSlide) | .editTargets)
      }
    )),
    omittedSourceSlides: [
      {sourceSlide:3,reason:"why-now metrics move to slide 11 notes"},
      {sourceSlide:4,reason:"old broad market page is replaced by a bottom-up responsibility-and-settlement model"},
      {sourceSlide:8,reason:"old comparison duplicates the new missing-layer argument"},
      {sourceSlide:14,reason:"moat content is recomposed within the inherited source-slide-13 structure"},
      {sourceSlide:16,reason:"old close is replaced by the work-to-settlement conclusion"}
    ]
  }
' "$OLD" > "$NEW"
jq -e '.outputSlides | length == 16 and all(.editTargets | length > 0)' "$NEW"
```

Expected: `jq` exits 0, all 16 slides have non-empty inherited edit targets, and no uninspected element ID is invented.

- [ ] **Step 5: Build and visually inspect the starter deck**

Run:

```bash
set -e
SKILL_DIR='/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations'
TMP_DIR='/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build'
NODE='/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
"$NODE" "$SKILL_DIR/template_following_scripts/prepare_template_starter_deck.mjs" \
  --workspace "$TMP_DIR" \
  --pptx '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx' \
  --map "$TMP_DIR/template-frame-map.json" \
  --out "$TMP_DIR/template-starter.pptx" \
  --preview-dir "$TMP_DIR/template-starter-preview" \
  --layout-dir "$TMP_DIR/template-starter-layout" \
  --contact-sheet "$TMP_DIR/template-starter-contact-sheet.png"
```

Expected: exactly 16 duplicated slides, inherited masters/layouts preserved, no unresolved default prompts.

## Task 3: Build the deck content contract with tests first

- [ ] **Step 1: Write the failing content-contract test**

Create `deck-contract.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { deckMeta, slides, assertDeckContract } from "./deck-data.mjs";

test("deck has 12 core slides and 4 appendices", () => {
  assert.equal(slides.length, 16);
  assert.deepEqual(slides.map((s) => s.n), Array.from({ length: 16 }, (_, i) => i + 1));
  assert.equal(slides.filter((s) => s.section === "core").length, 12);
  assert.equal(slides.filter((s) => s.section === "appendix").length, 4);
});

test("brand and output boundaries are fixed", () => {
  assert.equal(deckMeta.primaryBrand, "OpenWorkProof");
  assert.equal(deckMeta.commercialLayer, "OpenPay");
  assert.match(deckMeta.outputPath, /V5_Agent结算版\.pptx$/);
  assert.doesNotMatch(deckMeta.outputPath, /V3_|V4_/);
});

test("every slide has sources and no forbidden visible claim", () => {
  assert.doesNotThrow(() => assertDeckContract(slides));
  const visible = slides.flatMap((s) => [s.title, s.subtitle, ...(s.visible || [])]).join("\n");
  for (const phrase of ["已与 PayPal 合作", "已与 Worldpay 合作", "已经实现 Token 兑换", "已有客户", "形成收入"]) {
    assert.equal(visible.includes(phrase), false, phrase);
  }
});
```

- [ ] **Step 2: Run the contract test and verify RED**

Run:

```bash
NODE='/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
"$NODE" --test '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/deck-contract.test.mjs'
```

Expected: FAIL because `deck-data.mjs` does not exist.

- [ ] **Step 3: Create the minimum complete `deck-data.mjs`**

Use this exact object shape for all 16 records:

```js
export const deckMeta = {
  outputPath: "/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V5_Agent结算版.pptx",
  sourceTemplate: "/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx",
  primaryBrand: "OpenWorkProof",
  commercialLayer: "OpenPay",
  competitionEntity: "舆意科技（上海）有限公司",
  developmentEntity: "成都星火领航科技有限公司",
  fundingAsk: "人民币 200 万元",
};

export const slides = [
  {
    n: 1,
    section: "core",
    title: "Agent 已经会工作，但它还无法凭自己的工作获得支付",
    subtitle: "OpenWorkProof｜Agent 工作验收与结算基础设施",
    visible: [],
    sources: ["https://icnabp01o6e3.feishu.cn/docx/H9Iqdm8h9olPzYxQgsdcLJrmnUf"],
  },
  {
    n: 2,
    section: "core",
    title: "未来，一个人会同时经营数十个替自己工作的 Agent",
    subtitle: "Agent 能跨平台执行，收入、责任和验收却无法自动跟随",
    visible: ["开发", "研究", "运营", "交易"],
    sources: ["https://icnabp01o6e3.feishu.cn/docx/H9Iqdm8h9olPzYxQgsdcLJrmnUf"],
  },
  {
    n: 3,
    section: "core",
    title: "真正的断点不是 Agent 能不能做，而是“凭什么付钱”",
    subtitle: "一项机器工作必须同时回答四个问题",
    visible: ["谁授权", "做了什么", "谁验收", "为什么付款"],
    sources: ["https://icnabp01o6e3.feishu.cn/docx/H9Iqdm8h9olPzYxQgsdcLJrmnUf"],
  },
  {
    n: 4,
    section: "core",
    title: "MCP/A2A 让 Agent 协作，支付网络负责转钱，中间缺少可付款的工作事实",
    subtitle: "协作协议 → 可信工作层 → 支付与财务系统",
    visible: ["互操作与任务协作", "授权、证据与验收", "开票、分账与付款"],
    sources: [
      "https://modelcontextprotocol.io/specification/2026-07-28/changelog",
      "https://a2a-protocol.org/latest/specification/",
      "/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-10-openworkproof-work-to-settlement-pitch-design.md",
    ],
  },
  {
    n: 5,
    section: "core",
    title: "OpenWorkProof 证明工作，OpenPay 连接结算",
    subtitle: "开源可信工作层 + 商业结算编排层",
    visible: ["OpenWorkProof｜契约 · 授权 · 证据 · 验收", "OpenPay｜开票 · 分账 · 付款指令", "当前连接既有支付与财务系统，不托管资金"],
    sources: [
      "/Users/molin/Project/openWorkProof/README.md",
      "/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-10-openworkproof-work-to-settlement-pitch-design.md",
    ],
  },
  {
    n: 6,
    section: "core",
    title: "一项 Agent 工作，如何从任务走到付款",
    subtitle: "只有有效验收，才产生结算指令",
    visible: ["工作契约", "授权", "执行", "证据", "独立验证", "接受/拒绝", "结算指令"],
    sources: [
      "/Users/molin/Project/openWorkProof/README.md",
      "/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-10-openworkproof-work-to-settlement-pitch-design.md",
    ],
  },
  {
    n: 7,
    section: "core",
    title: "可信工作层已经完成，支付连接层进入商业验证",
    subtitle: "真实 Issue · 签名回执 · 离线验证 · 公开分发",
    visible: ["Rich #4196", "Dify #33013", "fresh suite 结果制作时覆盖"],
    sources: [
      "https://github.com/Textualize/rich/issues/4196",
      "https://github.com/langgenius/dify/issues/33013",
      "/Users/molin/Project/openWorkProof/tests/evidence-bundles/rich-4196-evidence-bundle.json",
      "/Users/molin/Project/openWorkProof/tests/evidence-bundles/dify-33013-evidence-bundle.json",
    ],
  },
  {
    n: 8,
    section: "core",
    title: "第一张采购单，来自需要按时验收和回款的 Agent 方案商",
    subtitle: "企业定义门槛，方案商承担交付，OpenWorkProof 形成验收事实",
    visible: ["企业客户｜受益与验收主体", "Agent 方案商｜首要付款方假设", "OpenWorkProof / OpenPay｜可信验收与结算指令"],
    sources: ["/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-10-openworkproof-work-to-settlement-pitch-design.md"],
  },
  {
    n: 9,
    section: "core",
    title: "客户买的不是密码学，而是更少争议、更低验收成本和更快回款",
    subtitle: "替代方案仍是日志、截图、会议确认和定制脚本",
    visible: ["减少交付争议", "降低人工验收成本", "缩短交付到回款的等待"],
    sources: ["/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-10-openworkproof-work-to-settlement-pitch-design.md"],
  },
  {
    n: 10,
    section: "core",
    title: "先从软件与实施收入开始，再验证结算服务费",
    subtitle: "收入顺序必须跟随真实客户行为",
    visible: ["可信交付诊断", "付费改造/PoC", "企业年度授权", "平台 SDK/OEM", "合作方结算服务费｜验证假设"],
    sources: [
      "/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-09-openworkproof-pitch-commercial-model-design.md",
      "/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-10-openworkproof-work-to-settlement-pitch-design.md",
    ],
  },
  {
    n: 11,
    section: "core",
    title: "我们切入的不是全部 AI 市场，而是 Agent 责任、验收与结算层",
    subtitle: "中立开源协议是入口，集成网络、规则库和争议数据形成壁垒",
    visible: ["市场规模｜自下而上假设", "竞争平台缺少主动统一的激励", "客户与客单价仍待验证"],
    sources: [
      "https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-says-agentic-ai-will-drive-over-450-billion-dollars-in-enterprise-application-software-revenue-by-2035",
      "/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-10-openworkproof-work-to-settlement-pitch-design.md",
    ],
  },
  {
    n: 12,
    section: "core",
    title: "人民币 200 万元，用 15 个月验证 Agent 工作能否进入真实结算",
    subtitle: "让每一项 Agent 劳动，都能被证明、被接受、被结算",
    visible: ["付费试点", "真实验收", "有效付款指令", "年度授权路径", "参赛主体｜舆意科技（上海）有限公司", "研发 / IP / 融资｜成都星火领航科技有限公司"],
    sources: [
      "/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-10-openworkproof-work-to-settlement-pitch-design.md",
      "Founder-provided team biographies and entity confirmations, 2026-08-09",
    ],
  },
  {
    n: 13,
    section: "appendix",
    title: "OpenWorkProof 如何形成可独立复核的工作事实",
    subtitle: "协议对象用于证明和验收，不自动创建合同或支付",
    visible: ["PolicyDecision", "ActionReceipt", "AcceptanceReceipt"],
    sources: ["/Users/molin/Project/openWorkProof/README.md"],
  },
  {
    n: 14,
    section: "appendix",
    title: "两个真实 Issue 与最新工程验证状态",
    subtitle: "通过、失败、跳过与版本漂移同时披露",
    visible: ["Rich #4196", "Dify #33013", "fresh suite 结果制作时覆盖"],
    sources: [
      "https://github.com/Textualize/rich/issues/4196",
      "https://github.com/langgenius/dify/issues/33013",
      "/Users/molin/Project/openWorkProof/pyproject.toml",
    ],
  },
  {
    n: 15,
    section: "appendix",
    title: "公开讨论已经提出验证成本、撤回语义和授权边界问题",
    subtitle: "公开讨论与目录展示，不等于客户、订单、采用或背书",
    visible: ["DEV Community", "Glama｜OpenWorkProof listing"],
    sources: [
      "/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/dev-mikhail-receipts-retraction.png",
      "/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/dev-puneet-verification-cost.png",
      "/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/glama-openworkproof-listing.png",
    ],
  },
  {
    n: 16,
    section: "appendix",
    title: "从验收到结算，还需要客户验证与持牌合作",
    subtitle: "已完成、待验证与长期愿景必须分开",
    visible: ["已完成｜可信工作协议与工程证明", "待验证｜付款方、价格与付款指令", "长期愿景｜跨平台结算网络与持牌合作"],
    sources: [
      "https://icnabp01o6e3.feishu.cn/docx/H9Iqdm8h9olPzYxQgsdcLJrmnUf",
      "/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-10-openworkproof-work-to-settlement-pitch-design.md",
    ],
  },
];

export function assertDeckContract(records) {
  if (records.length !== 16) throw new Error(`Expected 16 slides, got ${records.length}`);
  const missingSources = records.filter((s) => !Array.isArray(s.sources) || s.sources.length === 0);
  if (missingSources.length) throw new Error(`Missing sources: ${missingSources.map((s) => s.n).join(",")}`);
  const forbidden = [
    "已与 PayPal 合作",
    "已与 Worldpay 合作",
    "已经实现 Token 兑换",
    "已有客户",
    "形成收入",
  ];
  const visible = records.flatMap((s) => [s.title, s.subtitle, ...(s.visible || [])]).join("\n");
  const hit = forbidden.find((phrase) => visible.includes(phrase));
  if (hit) throw new Error(`Forbidden visible claim: ${hit}`);
}
```

- [ ] **Step 4: Run the contract test and verify GREEN**

Run the same `node --test` command.

Expected: all three tests pass.

## Task 4: Implement shared editing and notes helpers

- [ ] **Step 1: Write helper tests before implementation**

Extend `deck-contract.test.mjs` with pure-function tests:

```js
import { sourceBlock, assertSingleLineTitle, assertNoForbiddenCopy } from "./edit-helpers.mjs";

test("sourceBlock creates one notes block", () => {
  assert.deepEqual(sourceBlock(["https://example.com/a"]), ["[Sources]", "- https://example.com/a"]);
});

test("single-line titles reject line breaks", () => {
  assert.throws(() => assertSingleLineTitle("first\nsecond"), /single line/);
});

test("forbidden copy guard rejects false partnership", () => {
  assert.throws(() => assertNoForbiddenCopy("已与 PayPal 合作"), /forbidden/i);
});
```

Run the test and expect module-not-found RED.

- [ ] **Step 2: Implement the minimum helpers**

Create `edit-helpers.mjs`:

```js
const FORBIDDEN = ["已与 PayPal 合作", "已与 Worldpay 合作", "已经实现 Token 兑换", "已有客户", "形成收入"];

export function sourceBlock(sources) {
  if (!Array.isArray(sources) || sources.length === 0) throw new Error("sources required");
  return ["[Sources]", ...sources.map((source) => `- ${source}`)];
}

export function assertSingleLineTitle(text) {
  if (String(text).includes("\n")) throw new Error("title must remain single line");
}

export function assertNoForbiddenCopy(text) {
  const hit = FORBIDDEN.find((phrase) => String(text).includes(phrase));
  if (hit) throw new Error(`forbidden copy: ${hit}`);
}

export function setTextById(slide, elementId, text) {
  const matches = slide.shapes.items.filter((shape) => shape.id === elementId);
  if (matches.length !== 1) throw new Error(`Expected one inherited element ${elementId}, got ${matches.length}`);
  matches[0].text = text;
  return matches[0];
}
```

- [ ] **Step 3: Run helper and contract tests**

Expected: all tests pass and `node --check` passes for `deck-data.mjs` and `edit-helpers.mjs`.

## Task 5: Compose core slides 1—4 — the pain

- [ ] **Step 1: Implement slides 1—4 in `compose-core.mjs`**

Export one function with no file-writing side effects:

```js
import { assertSingleLineTitle, setTextById } from "./edit-helpers.mjs";

const TITLE_BY_SOURCE_SLIDE = new Map([
  [2, "sh/wjy9sry9"],
  [5, "sh/n6dcr65o"],
  [6, "sh/oryp8fah"],
  [7, "sh/n6x0fqlo"],
  [9, "sh/p0ji9kf2"],
  [10, "sh/0bit8b2d"],
  [11, "sh/o7ih0r6h"],
  [12, "sh/sb2lcnmd"],
  [13, "sh/32ponyts"],
  [15, "sh/t87ml0ji"],
]);

export function composePainSlides(presentation, records, frameMap) {
  for (const record of records.filter((s) => s.n >= 1 && s.n <= 4)) {
    assertSingleLineTitle(record.title);
    const slide = presentation.slides.items[record.n - 1];
    const mapping = frameMap.outputSlides.find((item) => item.outputSlide === record.n);
    if (record.n === 1) {
      setTextById(slide, "sh/sryl4zqx", "OpenWorkProof");
      setTextById(slide, "sh/fu94fe98", record.title);
    } else {
      const titleId = TITLE_BY_SOURCE_SLIDE.get(mapping.sourceSlide);
      if (!titleId) throw new Error(`No title id for source slide ${mapping.sourceSlide}`);
      setTextById(slide, titleId, record.title);
    }
  }
  return presentation;
}
```

Add explicit edits for subtitles, the future-scenario copy, the four payment questions, and the MCP/A2A → trusted-work → payment-system three-layer structure. Use only inherited objects or bounded native connectors declared in the validated frame map.

- [ ] **Step 2: Enforce narrative constraints**

Add assertions that slides 1—4 contain none of these strings:

```js
const EARLY_TECH = ["PolicyDecision", "ActionReceipt", "AcceptanceReceipt", "2,282", "2,283", "TAM", "SAM", "SOM"];
```

Expected: the first four slides establish the economic conflict before technical objects, testing, or market math.

- [ ] **Step 3: Export and inspect a four-slide draft**

Create a temporary four-slide draft in the build workspace, render it, run `slides_test.py`, and inspect all four pages at full size. Expected: the cover reads in under ten seconds; slide 3 makes “凭什么付钱” visually dominant; slide 4 does not imply MCP/A2A lack all security or identity features.

## Task 6: Compose core slides 5—7 — the solution and proof

- [ ] **Step 1: Add the two-layer product thesis**

Implement slide 5 with two inherited zones:

```text
OpenWorkProof
可信工作事实层
契约 · 授权 · 证据 · 验收

OpenPay
商业结算编排层
开票 · 分账 · 付款指令
```

Add the visible boundary: `当前连接既有支付与财务系统，不托管资金。`

- [ ] **Step 2: Add the work-to-payment flow**

Create all connectors before nodes, then show exactly:

```text
工作契约 → 授权 → 执行 → 证据 → 独立验证 → 接受/拒绝 → 结算指令
```

Use blue for the work/evidence path and green only for an accepted terminal state. A rejected terminal state must not be green.

- [ ] **Step 3: Add the current-proof slide**

Show real Issue evidence, offline verification, public code/distribution, and the freshly verified test summary. The title must state that the trusted-work layer exists while the payment connection remains in commercial validation.

- [ ] **Step 4: Render and inspect slides 5—7**

Expected: a non-technical reader can accurately explain the difference between OpenWorkProof and OpenPay; no token, wallet, custody or payment-partner claim appears.

## Task 7: Compose core slides 8—12 — payer, business and ask

- [ ] **Step 1: Implement the payer map on slide 8**

Show three roles with explicit labels:

```text
企业客户｜定义验收门槛并获得交付结果
Agent 方案商｜承担项目交付与回款责任｜首要付款方假设
OpenWorkProof / OpenPay｜形成可验证验收并触发结算指令
```

Do not use a customer logo or imply a signed pilot.

- [ ] **Step 2: Implement purchased outcomes on slide 9**

Use outcome language only:

```text
减少交付争议
降低人工验收成本
缩短交付到回款的等待
```

Add current alternatives: logs/screenshots, meeting confirmation, custom scripts, manual finance release. Do not invent percentages or days saved.

- [ ] **Step 3: Implement revenue order on slide 10**

Show the sequence:

```text
可信交付诊断 → 付费改造/PoC → 企业年度授权 → 平台 SDK/OEM → 合作方结算服务费
```

Every price or take-rate value must carry the visible label `验证假设`. The settlement fee is the last stage, not current revenue.

- [ ] **Step 4: Implement market and differentiation on slide 11**

Use a bottom-up responsibility-and-settlement model. Label organization counts, contract values, penetration and FX as internal assumptions. Replace “大厂不会做” with `竞争平台缺少主动统一的激励`.

- [ ] **Step 5: Implement team, raise and close on slide 12**

Use the three approved portraits and exact roles:

```text
董浩宇博士｜商业战略负责人
邓海波｜协议架构与产品工程
龙胜海｜资料整理、技术研判与生态实践
```

Show:

```text
人民币 200 万元
15 个月
验证付费试点、真实验收、有效付款指令和年度授权路径
```

Preserve entity labels: competition entity `舆意科技（上海）有限公司`; development/IP/funding entity `成都星火领航科技有限公司`.

- [ ] **Step 6: Render and inspect slides 8—12**

Expected: payer, purchased outcome, current alternative, revenue order, team/entity and fund-use logic are all visible without reading notes. Slide 12 resolves the opening rather than ending on an unexplained budget chart.

## Task 8: Compose slides 13—16 — evidence appendix

- [ ] **Step 1: Implement protocol appendix slide 13**

Show PolicyDecision, ActionReceipt and AcceptanceReceipt with short Chinese meanings. Do not imply the receipt itself creates a legal contract or payment.

- [ ] **Step 2: Implement engineering appendix slide 14**

Show Rich #4196, Dify #33013, the exact fresh test summary, version state and offline-verification boundary. If tests have failures or skips, show them adjacent to the pass count rather than burying them in notes.

- [ ] **Step 3: Implement ecosystem appendix slide 15**

Use the approved DEV and Glama screenshots mechanically cropped from the originals. Preserve usernames/dates needed for provenance, do not enlarge avatars, and add the visible footer: `公开讨论与目录展示，不等于客户、订单、采用或背书。`

- [ ] **Step 4: Implement assumptions/partner boundary slide 16**

Use three columns:

```text
已完成｜可信工作协议、真实 Issue、离线验证、公开分发
待验证｜首个付款方、价格、真实验收到付款指令
长期愿景｜跨平台 Agent 结算网络与持牌机构合作
```

Do not show PayPal, Worldpay or bank logos. If names are mentioned, label them `潜在合作方类型示例，尚未接洽或合作`.

- [ ] **Step 5: Render and inspect slides 13—16**

Expected: the appendix strengthens diligence without changing the five-minute story or making unsupported partnership claims.

## Task 9: Assemble, add sources and export atomically

- [ ] **Step 1: Create `build-v5.mjs`**

Use the installed artifact-tool import/export APIs and keep the module import-safe:

```js
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PresentationFile, FileBlob } from "@oai/artifact-tool";
import { deckMeta, slides, assertDeckContract } from "./deck-data.mjs";
import { composePainSlides, composeSolutionSlides, composeCommercialSlides } from "./compose-core.mjs";
import { composeAppendixSlides } from "./compose-appendix.mjs";

export async function buildDeck() {
  assertDeckContract(slides);
  const buildDir = path.dirname(fileURLToPath(import.meta.url));
  const presentation = await PresentationFile.importPptx(await FileBlob.load(path.join(buildDir, "template-starter.pptx")));
  composePainSlides(presentation, slides);
  composeSolutionSlides(presentation, slides);
  composeCommercialSlides(presentation, slides);
  composeAppendixSlides(presentation, slides);
  if (presentation.slides.items.length !== 16) throw new Error("Expected 16 final slides");
  for (const record of slides) {
    const notes = [record.subtitle, "", "[Sources]", ...record.sources.map((source) => `- ${source}`), "[/Sources]"];
    const slide = presentation.slides.items[record.n - 1];
    slide.speakerNotes.textFrame.setText(notes);
    slide.speakerNotes.setVisible(true);
  }
  const temp = path.join(path.dirname(deckMeta.outputPath), `.${path.basename(deckMeta.outputPath)}.${process.pid}.tmp`);
  try {
    const exported = await PresentationFile.exportPptx(presentation);
    await exported.save(temp);
    await fs.rename(temp, deckMeta.outputPath);
  } catch (error) {
    await fs.rm(temp, { force: true }).catch(() => {});
    throw error;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await buildDeck();
```

Expected: use the installed `speakerNotes.textFrame.setText`, `speakerNotes.setVisible`, and `PresentationFile.exportPptx(...).save(...)` APIs exactly as shown; preserve atomic temporary-file replacement and temp cleanup on error.

- [ ] **Step 2: Add import-safety and output-path tests**

Test that importing `build-v5.mjs` does not create or modify V5, and that V3/V4 hashes remain identical to Task 1.

- [ ] **Step 3: Build the final V5**

Run:

```bash
NODE='/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
cd '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build'
"$NODE" --check build-v5.mjs
"$NODE" --test deck-contract.test.mjs
"$NODE" build-v5.mjs
test -s '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V5_Agent结算版.pptx'
```

Expected: syntax/tests pass and one non-empty V5 file is created without modifying V3/V4.

## Task 10: Run structural, visual and narrative QA

- [ ] **Step 1: Render all 16 final slides**

Run:

```bash
PYTHON='/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'
SKILL_DIR='/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations'
FINAL='/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V5_Agent结算版.pptx'
"$PYTHON" "$SKILL_DIR/container_tools/render_slides.py" "$FINAL"
"$PYTHON" "$SKILL_DIR/container_tools/create_montage.py" \
  --input_dir '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V5_Agent结算版' \
  --output_file '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v5_settlement_build/contact-sheet.png'
```

Expected: exactly 16 PNGs. Inspect every page at original size; use the contact sheet only for deck-level flow.

- [ ] **Step 2: Run overflow and ZIP integrity tests**

Run:

```bash
set -e
PYTHON='/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'
SKILL_DIR='/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations'
FINAL='/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V5_Agent结算版.pptx'
"$PYTHON" "$SKILL_DIR/container_tools/slides_test.py" "$FINAL"
unzip -t "$FINAL"
```

Expected: no overflow and no ZIP errors. Fix every unintended overlap, clipping, broken connector, hidden placeholder or wrapped one-line title.

- [ ] **Step 3: Run visible-copy semantic gates**

Extract visible text and assert:

```text
Required: OpenWorkProof, OpenPay, 凭什么付钱, 不托管资金, 首要付款方假设, 人民币 200 万元
Forbidden: 已与 PayPal 合作, 已与 Worldpay 合作, 已实现 Token 兑换, 已有客户, 形成收入, 阿加犀实践已完成
```

Expected: all required phrases are present in their intended slides; forbidden phrases have zero matches.

- [ ] **Step 4: Verify notes and source coverage**

Expected: exactly 16 slides and 16 speaker-note parts; each slide contains exactly one `[Sources]` block with direct URLs or exact local provenance.

- [ ] **Step 5: Verify historical identities and write the QA ledger**

Recompute V3/V4/V5 size and SHA-256. Expected: V3 and V4 match Task 1; V5 has a new identity. Record build timestamp, final size/SHA, test result, render count, overflow result, notes count and visual-review result in `qa-ledger.txt`.

## Task 11: Final independent review and handoff

- [ ] **Step 1: Review the final deck against the approved specification**

Check every specification section: transcript interpretation, brand architecture, facts/assumptions/wishes, 12+4 structure, five-minute timing, forbidden claims, commercial validation commitment, entities and non-goals.

Expected: no requirement is satisfied only in notes when the specification requires visible copy.

- [ ] **Step 2: Rehearse the five-minute core sequence**

Use slides 1—12 only. Record in `design-notes.txt`:

```text
Slides 1-4: 90 seconds
Slides 5-7: 100 seconds
Slides 8-11: 90 seconds
Slide 12: 20 seconds
Appendix 13-16: Q&A only
```

Expected: the spoken story fits five minutes without reading dense slide copy.

- [ ] **Step 3: Preserve execution boundaries**

Do not stage or commit the PPTX, build workspace, existing dirty evidence bundles, `.DS_Store`, V3 or V4 unless the user separately authorizes repository integration. A local V5 plus green QA does not prove competition submission, judge acceptance, financing commitment, payment partnership, customer adoption or revenue.

- [ ] **Step 4: Commit only the completed plan record if requested**

If the execution session is authorized to update plan checkboxes, stage only:

```bash
git add docs/superpowers/plans/2026-08-10-openworkproof-work-to-settlement-pitch-implementation.md
git diff --cached --check
git commit -m 'docs: record settlement pitch execution'
```

Expected: no unrelated modified file or evidence bundle is included.

- [ ] **Step 5: Deliver the final artifact**

Report the exact V5 path, slide count, notes count, size/SHA, render/overflow results and the fact that V3/V4 remained unchanged. Do not report submission, external acceptance, financing or commercial validation without separate evidence.
