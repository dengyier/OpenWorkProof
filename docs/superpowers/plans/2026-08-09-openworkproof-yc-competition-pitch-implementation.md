# OpenWorkProof YC-Style Competition Pitch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a new 16-slide, 8–10 minute OpenWorkProof competition and angel-round pitch that follows the approved YC-style dual narrative, uses the B2 institutional-editorial visual system, includes three approved team portraits and three public-ecosystem screenshots, and preserves V2/V3 unchanged.

**Architecture:** Build V4 from scratch in a dedicated external workspace using JavaScript ES modules and `@oai/artifact-tool`; use V3 only as a validated content/source reference. Generate three small-batch image-2 hero assets, pause for designer approval, compose the 16 slides in four narrative batches, attach per-slide `[Sources]` notes, then render and inspect every slide before delivery.

**Tech Stack:** JavaScript ES modules, `@oai/artifact-tool`, built-in image-2 generation, bundled presentation render/test tools, PowerPoint speaker notes, local raster assets, ZIP/XML validation, Git for design/plan records only.

---

## Files

### Project records

- Read: `/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-09-openworkproof-yc-competition-pitch-design.md`
- Modify: `/Users/molin/Project/openWorkProof/docs/superpowers/plans/2026-08-09-openworkproof-yc-competition-pitch-implementation.md`

### Build workspace

- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/build-deck.mjs`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/deck-data.mjs`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/source-notes.txt`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/design-notes.txt`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/qa-ledger.txt`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/generated/cover-accountability-layer.png`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/generated/work-contract-stack.png`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/generated/enterprise-trust-bridge.png`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/rendered/`

### Approved source assets

- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/team/dong-haoyu.jpg`
- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/team/deng-haibo.jpg`
- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/team/long-shenghai.png`
- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/dev-mikhail-receipts-retraction.png`
- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/dev-puneet-verification-cost.png`
- Read: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/glama-openworkproof-listing.png`

### Inputs and output

- Preserve: `/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V2_含市场分析.pptx`
- Preserve: `/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V4_YC双线叙事版.pptx`

## Task 1: Freeze source artifacts and current project truth

- [ ] **Step 1: Record V2 and V3 baselines**

Run:

```bash
set -e
for f in \
  '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V2_含市场分析.pptx' \
  '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx'; do
  test -s "$f"
  stat -f 'FILE=%N SIZE_BYTES=%z' "$f"
  shasum -a 256 "$f"
done
```

Expected: both files exist, have positive sizes, and produce SHA-256 values. Copy the exact values into `qa-ledger.txt` using `apply_patch`.

- [ ] **Step 2: Read current repository version and release facts**

Run:

```bash
set -e
git -C '/Users/molin/Project/openWorkProof' status --short --branch
git -C '/Users/molin/Project/openWorkProof' rev-parse HEAD
rg -n '^version|2283|2,283|PyPI|Glama|MCP Registry|v1\.' \
  '/Users/molin/Project/openWorkProof/pyproject.toml' \
  '/Users/molin/Project/openWorkProof/README.md' \
  '/Users/molin/Documents/obsidian_openworkproof/项目概况/OpenWorkProof.md' \
  '/Users/molin/Documents/obsidian_openworkproof/工程实现/测试体系.md'
```

Expected: record the exact version, commit, test snapshot and distribution claims. Do not resolve conflicting version labels by guessing.

- [ ] **Step 3: Freshly verify the test claim**

Run from the repository's documented environment:

```bash
set -e
cd '/Users/molin/Project/openWorkProof'
if test -x '.venv/bin/python'; then
  .venv/bin/python -m pytest -q
else
  python3 -m pytest -q
fi
```

Expected: use the exact fresh result in the deck. If the result is not `2283 passed / 0 failed / 7 skipped`, update visible copy and notes to the fresh result rather than preserving the older number.

- [ ] **Step 4: Create the source and QA ledgers**

Use `apply_patch` to create:

```text
source-notes.txt
================
Deck: OpenWorkProof V4 YC双线叙事版
Build date: 2026-08-09
Claim classes: repository verification / public distribution / public discussion / market hypothesis / commercial hypothesis / team-provided biography
Rule: no local artifact, test result, listing, discussion, or plan is evidence of customer adoption, revenue, official MCP adoption, competition acceptance, or completed阿加犀 practice.
```

```text
qa-ledger.txt
=============
V2 baseline: record exact size and SHA-256 from Task 1 Step 1
V3 baseline: record exact size and SHA-256 from Task 1 Step 1
V4 build: pending
V4 render: pending
V4 overflow: pending
V4 source-note count: pending
V4 visual review: pending
```

Replace the `record exact` phrases immediately with the measured values; do not leave them in the saved file.

## Task 2: Initialize the artifact-tool workspace and content contract

- [ ] **Step 1: Load the bundled workspace runtime**

Call the workspace dependency loader and record the returned Node.js and Python paths. Use those exact paths for the remaining commands.

- [ ] **Step 2: Initialize artifact-tool**

Run:

```bash
set -e
SKILL_DIR='/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations'
TMP_DIR='/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build'
node "$SKILL_DIR/container_tools/setup_artifact_tool_workspace.mjs" --workspace "$TMP_DIR"
test -f "$TMP_DIR/package.json"
```

Expected: workspace initialization exits 0 and `package.json` exists.

- [ ] **Step 3: Read artifact-tool APIs before writing the builder**

Read completely:

```text
/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/artifact_tool_docs/API_QUICK_START.md
/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/artifact_tool_docs/api/API_DOCS.md
```

Use the APIs and import names documented by the installed runtime. Do not use `python-pptx` or direct OOXML mutation.

- [ ] **Step 4: Create `deck-data.mjs` with the complete narrative contract**

Use `apply_patch` to create a data module with this exact shape and all 16 records:

```js
export const deckMeta = {
  outputPath: "/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V4_YC双线叙事版.pptx",
  competitionEntity: "舆意科技（上海）有限公司",
  developmentEntity: "成都星火领航科技有限公司",
  fundingAsk: "人民币 200 万元",
};

export const slides = [
  { n: 1, kicker: "OPENWORKPROOF · ACCOUNTABILITY LAYER", title: "Agent 完成了，企业凭什么接受？", note: "可验证授权、因果证据与独立验收", sources: ["/Users/molin/Project/openWorkProof/README.md"] },
  { n: 2, kicker: "THE PROBLEM", title: "Agent 越能干，企业承担的责任风险越大", note: "谁授权？谁验证？谁承担？", sources: ["/Users/molin/Documents/obsidian_openworkproof/项目概况/核心问题.md"] },
  { n: 3, kicker: "WHY NOW", title: "Agent 正从试验工具进入企业工作流", note: "采用速度正在超过责任基础设施的建设速度", sources: [] },
  { n: 4, kicker: "MARKET", title: "可信 Agent 工作正在形成新的企业预算池", note: "自下而上的市场模型", sources: [] },
  { n: 5, kicker: "MISSING LAYER", title: "MCP 和 A2A 解决连接，但不决定工作是否成立", note: "连接不是授权，日志不是验收", sources: ["https://modelcontextprotocol.io/specification/2026-07-28/changelog"] },
  { n: 6, kicker: "PRODUCT", title: "OpenWorkProof 把任务意图变成机器可验证的工作契约", note: "PolicyDecision · ActionReceipt · AcceptanceReceipt", sources: ["/Users/molin/Documents/obsidian_openworkproof/协议设计/四类协议对象.md"] },
  { n: 7, kicker: "HOW IT WORKS", title: "一次 Agent 工作如何成为可结算的商业事实", note: "契约 → 授权 → 执行 → 证据 → 验收", sources: ["/Users/molin/Documents/obsidian_openworkproof/工程实现/证据链.md"] },
  { n: 8, kicker: "REAL ISSUES", title: "两个真实 Issue，复现同一套可信交付闭环", note: "Rich #4196 · Dify #33013", sources: ["https://github.com/Textualize/rich/issues/4196", "https://github.com/langgenius/dify/issues/33013"] },
  { n: 9, kicker: "ENGINEERING PROOF", title: "六角色、五阶段、2,283 项测试", note: "最终数字由 fresh test 覆盖", sources: ["/Users/molin/Documents/obsidian_openworkproof/工程实现/测试体系.md"] },
  { n: 10, kicker: "ALTERNATIVES", title: "Tracing 记录发生过什么，OpenWorkProof 证明什么可以被接受", note: "责任层与现有工具互补", sources: [] },
  { n: 11, kicker: "PUBLIC SIGNALS", title: "项目已进入公开生态，外部反馈开始形成设计约束", note: "公开讨论与目录展示，不等于客户验证", sources: [] },
  { n: 12, kicker: "FIRST PAYER", title: "Agent 方案商为了上线、交付和回款而付费", note: "企业提出门槛，方案商为交付买单", sources: ["/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-09-openworkproof-pitch-commercial-model-design.md"] },
  { n: 13, kicker: "BUSINESS MODEL", title: "先卖工作流改造，再形成年度授权与平台集成", note: "价格均为待验证假设", sources: ["/Users/molin/Documents/obsidian_openworkproof/商业方案/商业方案总览.md"] },
  { n: 14, kicker: "TEAM", title: "商业战略、协议工程与生态实践形成完整闭环", note: "三名成员均使用真实照片", sources: ["Founder-provided team biographies and role confirmations, 2026-08-09"] },
  { n: 15, kicker: "ANGEL ROUND", title: "人民币 200 万元，换取三项商业可验证性", note: "3 个付费 PoC · 1 个公开参考客户 · 1 个年度授权客户", sources: ["/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-09-openworkproof-yc-competition-pitch-design.md"] },
  { n: 16, kicker: "THE VISION", title: "让 Agent 从“能工作”走向“可以被企业正式雇用”", note: "寻找首批方案商、高责任企业试点与生态伙伴", sources: ["/Users/molin/Project/openWorkProof/docs/superpowers/specs/2026-08-09-openworkproof-yc-competition-pitch-design.md"] },
];
```

During implementation, populate the empty source arrays for slides 3, 4, 10 and 11 with the direct verified URLs and local screenshot provenance. Do not export while any `sources` array is empty.

- [ ] **Step 5: Add a source-completeness assertion**

Add to `deck-data.mjs`:

```js
export function assertCompleteSources(records) {
  const missing = records.filter((record) => !Array.isArray(record.sources) || record.sources.length === 0);
  if (missing.length > 0) {
    throw new Error(`Missing sources for slides: ${missing.map((record) => record.n).join(", ")}`);
  }
}
```

Run:

```bash
node --check '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/deck-data.mjs'
```

Expected: syntax exits 0. The source assertion is expected to fail only when explicitly called before the missing source arrays are populated.

## Task 3: Generate and approve the three image-2 hero assets

- [ ] **Step 1: Generate the cover asset**

Use built-in image generation with this complete prompt:

```text
Create a minimal premium editorial illustration for an enterprise AI infrastructure pitch deck, 16:9 landscape. Concept: a machine-verifiable signed evidence structure for AI agent work. Place the abstract subject entirely on the right 42 percent, leaving clean bright paper-white negative space on the left for a large Chinese title. Use translucent layered documents, a restrained cryptographic evidence lattice, thin navy and cyan lines, and one subtle acceptance-green signal. Institutional, precise, quiet, credible, sophisticated. No people, no robots, no hands, no locks, no gavels, no blockchain coins, no UI, no logos, no text, no letters, no numbers, no watermark, no cyberpunk HUD, no excessive glow.
```

Save the delivered raster asset as:

```text
/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/generated/cover-accountability-layer.png
```

- [ ] **Step 2: Generate the product asset**

Use built-in image generation with this complete prompt:

```text
Create a minimal isometric editorial illustration on a clean off-white background, 16:9 landscape, for an enterprise protocol pitch. Show three translucent layers representing a work contract, signed execution evidence, and independent acceptance, connected by a single causal line. The visual must suggest authorization before action, evidence during execution, and acceptance after delivery without using any words or icons. Palette: ink navy, evidence blue, acceptance green, pale glass. Large quiet margins, architectural precision, premium enterprise design. No people, no robots, no text, no letters, no numbers, no logos, no fake UI, no lock icon, no blockchain motifs, no watermark, no excessive detail.
```

Save as:

```text
/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/generated/work-contract-stack.png
```

- [ ] **Step 3: Generate the closing asset**

Use built-in image generation with this complete prompt:

```text
Create a minimal institutional editorial illustration for the closing slide of an AI infrastructure pitch deck, 16:9 landscape. Depict small autonomous agent nodes on the left crossing a precise bridge made of signed evidence segments into a stable enterprise system on the right. The bridge should communicate accountability and acceptance, not fantasy. Deep ink-navy background with restrained cyan paths and one acceptance-green terminal signal. Keep the center-left area calm enough for large white Chinese type. No people, no humanoid robots, no hands, no city skyline, no logos, no text, no letters, no numbers, no UI, no locks, no cyberpunk clutter, no watermark.
```

Save as:

```text
/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/generated/enterprise-trust-bridge.png
```

- [ ] **Step 4: Inspect all three generated images individually**

Verify:

- exact identity-free abstract content;
- no text-like artifacts or fake logos;
- sufficient title negative space;
- B2 palette consistency;
- no crypto/blockchain advertising appearance;
- no visible watermark;
- full-size sharpness.

- [ ] **Step 5: Pause for the user's designer approval**

Show the three generated images. Ask the user to mark each `accept`, `revise`, or `reject`. Do not start the 16-slide build until all three assets are accepted. Preserve rejected outputs and record the reason in `design-notes.txt`.

## Task 4: Build the B2 presentation foundation

- [ ] **Step 1: Create `build-deck.mjs` with the fixed theme**

Use `apply_patch` and the installed artifact-tool API to define:

```js
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Presentation, PresentationFile } from "@oai/artifact-tool";
import { assertCompleteSources, deckMeta, slides } from "./deck-data.mjs";

const BUILD_DIR = path.dirname(fileURLToPath(import.meta.url));
const C = {
  paper: "#FBFCFD",
  ink: "#081E36",
  blue: "#087AF0",
  green: "#0A8D72",
  muted: "#647386",
  rule: "#DCE5ED",
  pale: "#F2F6F9",
  white: "#FFFFFF",
};
const W = 1280;
const H = 720;
const M = 52;
const FONT = "Helvetica Neue";
const MONO = "SFMono-Regular";

assertCompleteSources(slides);

async function readBlob(filePath) {
  const bytes = await fs.readFile(filePath);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

async function writeBlob(filePath, blob) {
  if (blob?.data !== undefined) return writeBlob(filePath, blob.data);
  if (typeof blob?.arrayBuffer === "function") {
    await fs.writeFile(filePath, new Uint8Array(await blob.arrayBuffer()));
    return;
  }
  if (blob instanceof ArrayBuffer) {
    await fs.writeFile(filePath, new Uint8Array(blob));
    return;
  }
  if (ArrayBuffer.isView(blob)) {
    await fs.writeFile(filePath, new Uint8Array(blob.buffer, blob.byteOffset, blob.byteLength));
    return;
  }
  throw new TypeError("Unsupported exported presentation binary type");
}

const presentation = Presentation.create({ slideSize: { width: W, height: H } });
```

If the installed API uses different constructor or export names, use the exact names from Task 2 Step 3 and keep the constants/content contract unchanged.

- [ ] **Step 2: Add reusable editorial helpers**

Implement these helpers with fixed behavior:

```js
function addText(slide, value, x, y, w, h, options = {}) {
  const box = slide.shapes.add({
    geometry: "textbox",
    position: { left: x, top: y, width: w, height: h },
    fill: options.fill ?? "none",
    line: options.line ?? { style: "solid", fill: "none", width: 0 },
  });
  box.text = value;
  box.text.style = {
    typeface: options.mono ? MONO : FONT,
    fontSize: options.size ?? 22,
    bold: options.bold ?? false,
    color: options.color ?? C.ink,
    alignment: options.align ?? "left",
    verticalAlignment: options.valign ?? "top",
    autoFit: options.autoFit ?? "shrinkText",
    wrap: "square",
    lineSpacing: options.lineSpacing ?? 1.08,
    insets: options.insets ?? { top: 0, right: 0, bottom: 0, left: 0 },
  };
  return box;
}

function addRule(slide, x, y, w, color = C.rule, height = 1) {
  return slide.shapes.add({
    geometry: "rect",
    position: { left: x, top: y, width: w, height },
    fill: color,
    line: { style: "solid", fill: color, width: 0 },
  });
}

function addImage(slide, blob, alt, x, y, w, h, options = {}) {
  return slide.images.add({
    blob,
    contentType: options.contentType ?? "image/png",
    alt,
    fit: options.fit ?? "cover",
    position: { left: x, top: y, width: w, height: h },
    geometry: options.geometry ?? "rect",
  });
}

function addChrome(slide, record, dark = false) {
  addText(slide, record.kicker, M, 28, 670, 18, { size: 13, bold: true, color: dark ? "#59DDF0" : C.blue, mono: true });
  addText(slide, String(record.n).padStart(2, "0"), 1178, 28, 50, 18, { size: 13, bold: true, color: dark ? "#9FC0D7" : C.muted, align: "right", mono: true });
}

function sourceNote(record, summary) {
  return [summary, "", "[Sources]", ...record.sources.map((source) => `- ${source}`), "[/Sources]"];
}

function setNotes(slide, record, summary) {
  slide.speakerNotes.textFrame.setText(sourceNote(record, summary));
  slide.speakerNotes.setVisible(true);
}
```

Use the documented speaker-note API to attach `sourceNote(...)` to every slide.

- [ ] **Step 3: Add title fit guards**

Use a single-line title box for titles of 26 Chinese characters or fewer. For longer approved titles, use an intentional two-line title with explicit `\n`; never rely on automatic wrapping. Throw before export if an unintended newline is detected in a one-line title record.

- [ ] **Step 4: Add final export**

Export only to `deckMeta.outputPath` using `PresentationFile.exportPptx` and `writeBlob`:

```js
const pptx = await PresentationFile.exportPptx(presentation);
await writeBlob(deckMeta.outputPath, pptx);
console.log(deckMeta.outputPath);
```

Run:

```bash
node --check '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/build-deck.mjs'
```

Expected: syntax exits 0.

## Task 5: Compose slides 1–4 — opening, problem, timing, market

- [ ] **Step 1: Compose slide 1**

Use `cover-accountability-layer.png` full-bleed or right-weighted. Place the title on the left in 54–60 pt, subtitle in 20–24 pt, and the following factual footer:

```text
参赛主体｜舆意科技（上海）有限公司
天使轮融资｜人民币 200 万元
```

The title may use the intentional two lines:

```text
Agent 完成了，
企业凭什么接受？
```

- [ ] **Step 2: Compose slide 2**

Use three flat editorial columns, not UI cards:

```text
谁授权？
它是否有权执行这一步，权限是否仍然有效？

谁验证？
结果是否真实，证据能否被第三方重新计算？

谁承担？
出错如何追责，交付依据什么完成验收与结算？
```

Bottom takeaway:

```text
Agent 的“完成报告”不是企业可以签字的工作事实。
```

- [ ] **Step 3: Compose slide 3**

Use three sourced metrics with publication year and restrained typography. Reuse only claims that survive live source verification. Add a sentence tying them to the accountability gap:

```text
采用速度正在超过责任基础设施的建设速度。
```

- [ ] **Step 4: Compose slide 4**

Use the already approved bottom-up market ranges, with the formulas visible in 16–18 pt:

```text
全球 TAM 上限：2035 agentic application market × trust/accountability layer share
中国核心 SAM：目标组织数量 × 年合同价值
三年 SOM：30 家付费客户 × 平均 ACV 100 万元 = 3,000 万元
```

Footer:

```text
TAM/SAM 是透明假设；SOM 是经营目标，不代表已有收入、订单或合同。
```

- [ ] **Step 5: Render and inspect slides 1–4**

Build the draft, render all current slides, inspect each at full size, and fix title wrapping, metric source labels, visual hierarchy and image crop before continuing.

## Task 6: Compose slides 5–8 — gap, product, flow, cases

- [ ] **Step 1: Compose slide 5**

Use a four-level flat stack:

```text
模型：负责推理与生成
Agent 框架：负责编排与调用
MCP / A2A：负责连接与互操作
OpenWorkProof：负责工作契约、授权、证据与验收
```

Visible boundary:

```text
MCP 2026-07-28 支持无状态请求与扩展机制，但核心规范不替实施方完成授权和责任证明。
```

- [ ] **Step 2: Compose slide 6**

Use `work-contract-stack.png` on the right and three plain-language objects on the left:

```text
PolicyDecision｜这一步现在是否允许
ActionReceipt｜这一步实际发生了什么
AcceptanceReceipt｜独立验收者是否接受交付
```

Bottom sentence:

```text
OpenWorkProof 不判断模型聪不聪明，而是判断一项工作能不能被组织接受。
```

- [ ] **Step 3: Compose slide 7**

Draw connectors first, then five nodes:

```text
工作契约 → 权限授予 → 签名执行 → 证据合成 → 独立验收
```

Use blue for execution, green only for accepted terminal truth, and muted red only for rejected terminal truth. Keep node labels under 12 Chinese characters.

- [ ] **Step 4: Compose slide 8**

Use two equal case columns:

```text
Rich #4196
真实上游 Issue · 12 份签名回执 · 2 份组合报告 · 离线验证

Dify #33013
真实上游 Issue · 12 份签名回执 · 2 份组合报告 · 离线验证
```

Footer:

```text
证明的是协议闭环与离线可重算，不代表 Rich 或 Dify 已采用 OpenWorkProof。
```

- [ ] **Step 5: Render and inspect slides 5–8**

Verify the four layers are not presented as four direct competitors, the flow connectors stay behind nodes, both Issue identifiers are legible, and the product illustration has no text-like artifacts.

## Task 7: Compose slides 9–11 — engineering, alternatives, public signals

- [ ] **Step 1: Compose slide 9**

Use the fresh Task 1 test result and exact current version. Present no more than four proof points:

```text
6｜独立职责与密钥角色
5｜工作生命周期阶段
2｜真实开源 Issue 证据包
2,283｜测试（replace with fresh result if changed）
```

Add a distribution rail using verified facts only: GitHub, PyPI, current release, MCP/Glama listing. Do not say “正式生产部署”.

- [ ] **Step 2: Compose slide 10**

Use a five-row comparison with columns `现有方法`, `解决什么`, `仍缺什么`:

```text
日志 / Tracing｜记录执行过程｜记录者与执行者常同源，缺少验收授权
IAM / 权限系统｜控制主体访问｜不表达一次工作的目标、证据与验收
Eval / 测试｜评估结果质量｜不证明谁授权、证据是否属于这次工作
MCP / A2A｜连接工具与 Agent｜不定义完整工作责任与独立验收
OpenWorkProof｜连接契约、授权、证据与验收｜需要通过真实客户验证购买价值
```

- [ ] **Step 3: Compose slide 11 from the approved screenshots**

Crop but do not redraw:

- Mikhail screenshot: preserve `Mikhail`, `Aug 8`, the receipt/retraction paragraphs and DEV identity;
- Puneet screenshot: preserve `Puneet-Kumar2010`, `Aug 8`, the “verification becomes a side effect” response and DEV identity;
- Glama screenshot: preserve Glama navigation, `openworkproof` search, OpenWorkProof result, 14 tools and listing metadata.

Use translated one-line captions beside each crop:

```text
相邻方案存在，但撤回与“测试检查错了什么”仍是开放问题。
当 Agent 代替用户行动，验证成本会成为产品信任成本。
OpenWorkProof 已可在公开 MCP 目录中被检索和查看。
```

Footer:

```text
公开讨论与目录展示，不等于官方采纳、客户使用或商业收入。
```

- [ ] **Step 4: Render and inspect slides 9–11**

At full size, verify the screenshot text remains readable, no public username is cut in half, avatars are not enlarged, test counts match notes, and the competition table does not imply an empty field.

## Task 8: Compose slides 12–14 — payer, business model, team

- [ ] **Step 1: Compose slide 12**

Draw a four-stage payer flow:

```text
企业客户
提出安全、合规与业务验收门槛

Agent 方案商
合同与付款主体，需要上线、交付和回款

OpenWorkProof
提供契约、策略、适配器、证据包与报告

验收与结算
Acceptor 接受或拒绝，方案商据此完成交付
```

Highlight only `Agent 方案商` in green. Bottom takeaway:

```text
没有可信验收 → PoC 难以上线 → 方案商难以结算
```

- [ ] **Step 2: Compose slide 13**

Use four revenue stages with one first-channel rail:

```text
可信交付诊断｜3–5 万元
付费 PoC / 改造包｜20–50 万元/项目
企业年度授权｜30–100 万元/年
平台 OEM / SDK｜50–150 万元/年起
```

First-channel rail:

```text
首批渠道：Agent 方案商 · AI 解决方案商 · 系统集成商 · 阿加犀团队场景实践
```

Footer:

```text
价格、销售周期与续费路径均为待验证假设，不代表已有报价、合同或收入。
```

- [ ] **Step 3: Compose slide 14 with authentic portraits**

Use three equally weighted portrait crops. Do not alter identities or regenerate faces.

Visible copy:

```text
董浩宇 博士｜商业战略负责人
北京大学博士 · 20+ 年品牌与数字化经验

邓海波｜舆意科技 CTO · 协议架构与产品工程
前华为高级开发工程师 · OpenWorkProof Contributor

龙胜海｜阿加犀生态技术总监 · 共研技术成员
资料整理、技术研判与后续团队实践
```

Entity strip:

```text
参赛主体：舆意科技（上海）有限公司
研发 / IP / 融资：成都星火领航科技有限公司
技术 Owner：dengyier
```

- [ ] **Step 4: Render and inspect slides 12–14**

Verify the payer is unmistakable, prices do not appear as existing orders, all three headshots are sharp and fairly sized, names match file identity, and龙胜海's employer is only “阿加犀”.

## Task 9: Compose slides 15–16 — financing and closing

- [ ] **Step 1: Compose slide 15**

Use a large `¥2,000,000` figure and three milestones:

```text
① 3 个付费 PoC
② 1 个可公开参考客户
③ 1 个年度授权客户
```

Use five horizontal allocation bars:

```text
产品与协议研发 40% · 80 万元
企业试点与交付 30% · 60 万元
安全 / 法务 / IP 15% · 30 万元
市场与社区 10% · 20 万元
储备资金 5% · 10 万元
```

Add:

```text
同步验证：真实客单价 · 销售周期 · 交付成本 · 续费理由
```

Do not add valuation, dilution or investor-return claims.

- [ ] **Step 2: Compose slide 16**

Use `enterprise-trust-bridge.png` with large white title and this close:

```text
本轮融资不是为了证明协议能不能运行，
而是为了证明 Agent 方案商愿意为通过企业验收持续付费。

天使轮 ¥200 万 · 15 个月商业验证窗口
寻找：首批 Agent 方案商 · 高责任企业试点 · 产业与生态合作伙伴
```

Keep the competition and financing entities in a small readable footer.

- [ ] **Step 3: Render and inspect slides 15–16**

Verify bar lengths match 40/30/15/10/5, amounts sum to RMB 2 million, the close resolves slide 1, and the image retains calm text space.

## Task 10: Complete sources, build, and structural QA

- [ ] **Step 1: Populate every missing source array**

Use direct sources for slides 3, 4 and 10. For slide 11, include:

```text
Local user-provided DEV Community screenshot: dev-mikhail-receipts-retraction.png, received 2026-08-09
Local user-provided DEV Community screenshot: dev-puneet-verification-cost.png, received 2026-08-09
Local user-provided Glama screenshot: glama-openworkproof-listing.png, received 2026-08-09
https://dev.to/dengyier/agents-can-generate-results-but-on-what-authority-do-we-accept-delivery-3cnh
https://glama.ai/
```

If a more specific verified Glama permalink is available, use it in addition to the homepage; do not invent one.

- [ ] **Step 2: Scan for unsupported claims and credentials**

Run:

```bash
set -e
rg -n -i 'password|secret|token|已有客户|已有收入|已签合同|官方采纳|MCP采纳|Glama背书|Dify采用|Rich采用|阿加犀已完成' \
  '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/build-deck.mjs' \
  '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/deck-data.mjs' \
  '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/source-notes.txt' || true
```

Expected: matches are allowed only inside explicit negations/evidence boundaries. No credential material is allowed.

- [ ] **Step 3: Build V4**

Run:

```bash
set -e
node --check '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/deck-data.mjs'
node --check '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/build-deck.mjs'
node '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/build-deck.mjs'
test -s '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V4_YC双线叙事版.pptx'
```

Expected: all commands exit 0 and the V4 PPTX exists with a positive size.

- [ ] **Step 4: Render all 16 slides**

Run with the bundled Python runtime:

```bash
set -e
PYTHON='/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'
RENDER='/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/container_tools/render_slides.py'
PPTX='/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V4_YC双线叙事版.pptx'
OUT='/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/rendered'
"$PYTHON" "$RENDER" "$PPTX" --output_dir "$OUT" --width 1600 --height 900
test "$(rg --files "$OUT" | rg -c '/slide-[0-9]+\.png$')" -eq 16
```

Expected: 16 rendered PNG files.

- [ ] **Step 5: Run overflow and ZIP integrity checks**

Run:

```bash
set -e
PYTHON='/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'
PPTX='/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V4_YC双线叙事版.pptx'
"$PYTHON" '/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/container_tools/slides_test.py' "$PPTX"
unzip -t "$PPTX" | tail -n 1
```

Expected: `Test passed. No overflow detected.` and no ZIP errors.

- [ ] **Step 6: Verify 16 `[Sources]` note blocks**

Run:

```bash
set -e
PPTX='/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V4_YC双线叙事版.pptx'
count=0
missing=0
for f in $(unzip -Z1 "$PPTX" | rg '^ppt/notesSlides/notesSlide[0-9]+\.xml$'); do
  if unzip -p "$PPTX" "$f" | rg -q '\[Sources\]'; then
    count=$((count+1))
  else
    missing=$((missing+1))
  fi
done
echo "NOTES_WITH_SOURCES=$count MISSING=$missing"
test "$count" -eq 16
test "$missing" -eq 0
```

Expected: `NOTES_WITH_SOURCES=16 MISSING=0`.

## Task 11: Full visual QA and correction loop

- [ ] **Step 1: Inspect every slide individually at full size**

Check all 16 slides for:

- one clear primary claim;
- one-line titles never wrapping unintentionally;
- no body text below 16 pt;
- consistent B2 paper/navy/blue/green system;
- readable screenshot crops and source identities;
- authentic team photo identity and balanced crops;
- correct market and financing arithmetic;
- correct test number and version;
- complete page numbers `01` through `16`;
- no image-2 text artifacts, logos or watermarks;
- no false adoption, customer or revenue implications.

- [ ] **Step 2: Create a contact sheet and inspect narrative pacing**

Run:

```bash
set -e
PYTHON='/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'
"$PYTHON" '/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/container_tools/create_montage.py' \
  --input_dir '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/rendered' \
  --output_file '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/v4-contact-sheet.png'
```

Inspect slide-to-slide rhythm, adjacent silhouette variation, dark-slide frequency and repeated layouts.

- [ ] **Step 3: Correct every observed issue and rerun Task 10 Steps 3–6**

Do not waive overlap, clipping, unreadable screenshots, or unsupported claims. Record each correction in `qa-ledger.txt` with the slide number and result.

- [ ] **Step 4: Recheck V2 and V3 baselines**

Repeat Task 1 Step 1 and compare exact hashes and sizes to `qa-ledger.txt`.

Expected: V2 and V3 are byte-for-byte unchanged.

- [ ] **Step 5: Record final V4 identity**

Run:

```bash
set -e
PPTX='/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V4_YC双线叙事版.pptx'
stat -f 'SIZE_BYTES=%z' "$PPTX"
shasum -a 256 "$PPTX"
```

Write the exact final size, SHA-256, test result, slide count, source-note count and visual-review completion into `qa-ledger.txt` using `apply_patch`.

## Task 12: Record plan execution and preserve the branch

- [ ] **Step 1: Check off only completed plan steps**

Use `apply_patch` on this plan. Do not mark the image approval, full visual QA or final verification complete before the corresponding evidence exists.

- [ ] **Step 2: Run plan and repository checks**

Run:

```bash
set -e
cd '/Users/molin/Project/openWorkProof'
rg -n 'T[B]D|T[O]DO|implement la[t]er|fill in deta[i]ls' 'docs/superpowers/plans/2026-08-09-openworkproof-yc-competition-pitch-implementation.md' && exit 1 || true
git diff --check
git status --short --branch
```

Expected: no plan placeholders and no whitespace errors. Preserve the unrelated `.DS_Store` without staging it.

- [ ] **Step 3: Commit the completed execution record**

Run:

```bash
set -e
cd '/Users/molin/Project/openWorkProof'
git add 'docs/superpowers/plans/2026-08-09-openworkproof-yc-competition-pitch-implementation.md'
git diff --cached --check
git commit -m 'docs: record YC-style pitch implementation'
```

The final PPTX and build assets remain in the company output directory and are not committed to the protocol repository. Do not merge, push or delete the branch without explicit user instruction.
