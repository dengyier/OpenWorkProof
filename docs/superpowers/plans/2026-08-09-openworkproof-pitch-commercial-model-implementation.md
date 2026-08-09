# OpenWorkProof Pitch Commercial Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the OpenWorkProof pitch so a non-technical investor can identify the payer, purchase, payment trigger, acceptance result, recurring revenue path, and the 200万元 financing validation milestones.

**Architecture:** Keep the existing 16-slide artifact-tool deck and visual system. Update slide 5 with the verified MCP 2026-07-28 ecosystem boundary, replace slides 12–13 with the B2B2B payer and revenue ladder, align slides 14–16, and export a new V3 file without overwriting V2.

**Tech Stack:** JavaScript ES modules, `@oai/artifact-tool`, bundled slide renderer, `slides_test.py`, ZIP/XML and full-slide visual QA.

---

## Files

- Modify: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_build/build-deck.mjs`
- Modify: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_build/source-notes.txt`
- Modify: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_build/design-notes.txt`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx`
- Create: `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_build/rendered-v3/`

### Task 1: Preserve V2 and isolate V3

- [x] Record the V2 baseline.

```bash
shasum -a 256 '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V2_含市场分析.pptx'
stat -f 'SIZE_BYTES=%z' '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V2_含市场分析.pptx'
```

- [x] Change only the export target in `build-deck.mjs`.

```js
const PPTX_PATH = path.join(
  OUTPUT_ROOT,
  "OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx",
);
```

- [x] Verify syntax.

```bash
node --check '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_build/build-deck.mjs'
```

Expected: exit code 0.

### Task 2: Correct the MCP positioning on slide 5

- [x] Keep the existing stack comparison and add one concise evidence line below the four layers.

```js
addText(
  slide,
  "MCP 2026-07-28 已形成无状态请求与扩展机制，但核心规范仍不替实施方强制执行授权和责任证明。",
  42, 566, 1150, 30,
  { size: 18, bold: true, color: C.green, align: "center" },
);
```

- [x] Update the slide note to separate confirmed facts from inference.

```js
setNotes(slide, "官方规范确认无状态、自包含请求、逐请求能力协商和扩展机制；OpenWorkProof 可作为互补层是一项产品定位判断，不代表 MCP 采纳或认可。", [
  "https://modelcontextprotocol.io/specification/2026-07-28",
  "https://modelcontextprotocol.io/specification/2026-07-28/changelog",
  "https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/3215",
  "https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/3202",
  "https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2493",
]);
```

- [x] Do not use `最大修订`, `结构性利好`, `社区认可`, or `已被 MCP 采纳` as visible claims.

### Task 3: Replace slide 12 with the payer loop

- [x] Replace the current three-customer-column slide with a four-step flat flow.

```js
addTitle(slide, "第一张采购单，来自需要通过企业验收的 Agent 方案商", 12);
addText(slide, "终端企业提出验收门槛；Agent 方案商为了上线、交付和结算而付费。", 42, 170, 1120, 34, {
  size: 25, bold: true, color: C.blue,
});

const payerFlow = [
  [42, "企业客户", "提出安全、合规与\n业务验收要求"],
  [340, "Agent 方案商", "合同签署与付款主体\n需要项目上线和回款"],
  [638, "OpenWorkProof", "交付契约、权限策略、\n适配器、证据包与报告"],
  [936, "验收与结算", "Acceptor 接受或拒绝\n方案商据此完成交付"],
];
```

- [x] Render the four nodes with the existing typography; highlight `Agent 方案商` in green and keep the other three in navy/blue.

- [x] Replace the bottom strip with:

```js
addText(slide, "没有可信验收 → PoC 难以上线 → 方案商难以结算", 66, 601, 1148, 28, {
  size: 21, bold: true, color: C.white, align: "center",
});
```

- [x] Add speaker-note sources from the approved commercial model design and current Obsidian business files. State explicitly that this is the selected first-payer hypothesis, not a confirmed customer.

### Task 4: Replace slide 13 with the revenue ladder

- [x] Use four equal-width stages instead of the existing three-stage timeline.

```js
addTitle(slide, "不卖抽象协议：从一条工作流改造，走向年度治理授权", 13);
const revenueLadder = [
  [42, "可信交付诊断", "3—5 万", "风险清单、适配方案\n与验收基线"],
  [342, "付费 PoC／改造包", "20—50 万／项目", "契约、适配器、证据包\n与验收报告"],
  [642, "企业年度授权", "30—100 万／年", "多工作流治理、升级支持\n与周期性报告"],
  [942, "平台 OEM／SDK", "50—150 万／年起", "嵌入平台并服务其\n企业客户"],
];
```

- [x] Add the commercial progression line.

```js
addText(slide, "诊断发现边界 → 付费改造验证价值 → 年度授权形成持续收入 → OEM 放大分销", 42, 604, 1150, 30, {
  size: 21, bold: true, color: C.green, align: "center",
});
```

- [x] State in the speaker note: all four prices are validation hypotheses, not quotations, contracts, orders, or revenue.

### Task 5: Align slides 14–16

- [x] Add this distinction to slide 14 above the entity strip:

```js
addText(slide, "开源协议形成信任｜企业实施、年度授权与平台集成形成收入", 42, 552, 1196, 26, {
  size: 18, bold: true, color: C.green, align: "center",
});
```

- [x] Preserve the confirmed entities and Owner exactly:

```text
参赛主体：舆意科技（上海）有限公司
研发 / IP / 融资：成都星火领航科技有限公司
技术 Owner：dengyier
```

- [x] Change slide 15 milestones to:

```js
addText(slide, "① 3 个付费 PoC\n② 1 个可公开参考客户\n③ 1 个年度授权客户", 42, 382, 540, 128, {
  size: 25, bold: true, color: C.body, lineSpacing: 1.28,
});
addText(slide, "同步验证：真实客单价 · 销售周期 · 交付成本 · 续费理由", 42, 530, 570, 28, {
  size: 16, bold: true, color: C.green,
});
```

- [x] Preserve the 200万元 total and the 40% / 30% / 15% / 10% / 5% allocation.

- [x] Change slide 16 to close on the selected payer:

```text
本轮融资不是为了证明协议能不能运行，
而是为了证明 Agent 方案商愿意为通过企业验收持续付费。

寻找：首批 Agent 方案商 · 高责任企业试点 · 产业与生态合作伙伴
```

### Task 6: Update provenance records

- [x] Append the approved spec and verified MCP URLs to `source-notes.txt`.
- [x] Append the slide 5 and slide 12–15 narrative decisions to `design-notes.txt`.
- [x] Record these boundaries verbatim:

```text
Discussion #3215 has zero replies and is not evidence of adoption.
Discussion #3202 and #2493 show active adjacent work, not an empty competitive field.
Explicit MCP handles are state references, not equivalent to signed execution receipts.
The commercial prices are hypotheses pending interviews, quotations, contracts, delivery, and acceptance.
```

- [x] Scan for credentials and overclaims.

```bash
rg -n -i 'password|secret|token|已有客户|已有收入|已签合同|社区认可|MCP采纳' \
  '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_build/source-notes.txt' \
  '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_build/design-notes.txt' \
  '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_build/build-deck.mjs'
```

Expected: no credential or unsupported commercial/adoption claim.

### Task 7: Build and verify V3

- [x] Build with artifact-tool.

```bash
node '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_build/build-deck.mjs'
```

- [x] Recheck the V2 SHA-256 and size. Expected: identical to Task 1.

- [x] Render all 16 slides.

```bash
python '/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/container_tools/render_slides.py' \
  --output_dir '/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_build/rendered-v3' \
  '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx'
```

- [x] Inspect every rendered slide individually. Verify title wrapping, slide 5 source boundary, slide 12 payer emphasis, all four slide 13 prices, complete page numbers, slide 15 funding bars, and slide 16 ask.

- [x] Run overflow detection.

```bash
'/Users/molin/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3' \
  '/Users/molin/.codex/plugins/cache/openai-primary-runtime/presentations/26.805.11740/skills/presentations/container_tools/slides_test.py' \
  '/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx'
```

Expected: `Test passed. No overflow detected.`

- [x] Verify 16 source-note blocks, ZIP integrity, size, and SHA-256.

```bash
PPTX='/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx'
count=0
for f in $(unzip -Z1 "$PPTX" | rg '^ppt/notesSlides/notesSlide[0-9]+\.xml$'); do
  unzip -p "$PPTX" "$f" | rg -q '\[Sources\]' && count=$((count+1))
done
echo "NOTES_WITH_SOURCES=$count"
unzip -t "$PPTX" | tail -n 1
stat -f 'SIZE_BYTES=%z' "$PPTX"
shasum -a 256 "$PPTX"
```

Expected: `NOTES_WITH_SOURCES=16`, no ZIP errors, positive size, and a recorded SHA-256.

### Task 8: Record execution

- [x] Check off only steps actually completed.
- [x] Commit the updated plan on `codex/pitch-commercial-model`.

```bash
git add 'docs/superpowers/plans/2026-08-09-openworkproof-pitch-commercial-model-implementation.md'
git diff --cached --check
git commit -m 'docs: plan pitch commercial model implementation'
```

The final PPTX remains in the company output directory and is not committed as a binary to the protocol repository.
