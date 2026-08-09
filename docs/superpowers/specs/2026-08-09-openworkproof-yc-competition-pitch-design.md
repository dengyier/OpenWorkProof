# OpenWorkProof YC-Style Competition Pitch Design

**Date:** 2026-08-09  
**Status:** User-approved design  
**Primary use:** 2026 港科大百万奖金创业大赛上海赛区，8–10 分钟主路演  
**Secondary use:** 天使轮人民币 200 万元融资沟通  
**Visual direction:** B2 — 机构化技术刊物  

## 1. Communication Job

By the end of the pitch, non-technical competition judges and angel investors should believe that OpenWorkProof addresses a real enterprise accountability gap, has a working and differentiated protocol implementation, has an identifiable first payer, and has a credible 15-month plan for turning RMB 2 million into commercial evidence.

中文版：

> 路演结束时，非技术评委与天使投资人应理解：OpenWorkProof 解决的是 Agent 进入企业后的授权、执行证明与验收问题；产品已经完成可验证的工程实现；第一付费主体明确；人民币 200 万元将用于换取可复核的商业证据，而不是继续堆砌抽象平台叙事。

## 2. Approved Narrative Approach

采用“商业问题与技术证据双线推进”，而不是纯技术说明或标准融资模板：

1. 先提出企业无法接受 Agent 工作的责任问题；
2. 说明 Agent 采用与治理预算为何同时形成；
3. 解释 MCP/A2A 的边界与 OpenWorkProof 的互补位置；
4. 展示协议对象、执行闭环与真实 Issue；
5. 用工程测试、公开发布和外部讨论证明项目不是概念；
6. 明确谁付钱、购买什么以及何时愿意付钱；
7. 以团队能力与融资里程碑收口。

## 3. Evidence Classes and Boundaries

所有材料必须明确属于哪一类证据，禁止跨层推断：

| 类别 | 可支持的结论 | 不可支持的结论 |
|---|---|---|
| 本地/仓库测试 | 当前代码在指定环境通过相应测试 | 企业验收、客户使用、商业收入 |
| Rich / Dify 真实 Issue 演示 | 协议可作用于真实开源上下文 | Rich / Dify 采用、认可或合作 |
| DEV Community 公开讨论 | 外部开发者提出具体协议问题与相邻方案 | 客户需求、市场规模或付费意愿 |
| Glama 目录展示 | OpenWorkProof 可在公开 MCP 目录中被检索与展示 | MCP 官方采纳、Glama 背书、活跃使用 |
| GitHub / PyPI / Release | 项目已公开分发 | 企业部署、生产 SLA 或商业客户 |
| 价格与收入阶梯 | 商业验证假设 | 已有报价、合同、订单或收入 |
| 融资里程碑 | 资金使用与验证目标 | 已实现的经营结果 |

可见文案使用“2,283 项测试”，禁止使用“2,283 项端到端测试”。当前项目文档记录为 `2283 passed / 0 failed / 7 skipped`；制作阶段必须从当前仓库或最新版验证记录重新核对后才能进入最终 PPT。

## 4. 16-Slide Narrative

### Slide 1 — Opening Thesis

**Title:** Agent 完成了，企业凭什么接受？  
**Job:** 十秒内解释项目与核心张力。  
**Visible takeaway:** OpenWorkProof 是 AI Agent 工作的可验证授权与验收协议层。  
**Visual:** image-2 生成抽象签名证据结构，主体在右、左侧留标题空间。

### Slide 2 — Enterprise Problem

**Title:** Agent 越能干，企业承担的责任风险越大  
**Job:** 把技术问题转成企业责任问题。  
**Content:** 谁授权、谁验证、谁承担；强调“Agent 说完成”不是可验收事实。

### Slide 3 — Why Now

**Title:** Agent 正从试验工具进入企业工作流  
**Job:** 说明窗口为何现在打开。  
**Evidence:** Agent 采用、企业集成预期、治理认知以及相邻赛道融资。来源必须保留年份与口径。

### Slide 4 — Market

**Title:** 可信 Agent 工作正在形成新的企业预算池  
**Job:** 用自下而上的方式解释市场。  
**Content:** 全球 TAM 上限、中国核心 SAM、三年 SOM；公式与假设进入备注。SOM 是经营目标，不是收入。

### Slide 5 — Ecosystem Gap

**Title:** MCP 和 A2A 解决连接，但不决定工作是否成立  
**Job:** 定义缺失层。  
**Content:** 模型、Agent 框架、MCP/A2A、OpenWorkProof 四层；准确引用 MCP 2026-07-28 规范，不声称 MCP 采纳。

### Slide 6 — Product

**Title:** OpenWorkProof 把任务意图变成机器可验证的工作契约  
**Job:** 让非技术观众理解产品。  
**Content:** PolicyDecision、ActionReceipt、AcceptanceReceipt；避免一次展示全部内部类名。  
**Visual:** image-2 生成透明工作契约、授权链和验收印记的层叠结构，不含文字或 Logo。

### Slide 7 — Commercial Truth Flow

**Title:** 一次 Agent 工作如何成为可结算的商业事实  
**Job:** 展示端到端闭环。  
**Flow:** 工作契约 → 授权 → 执行 → 证据 → 独立验收。  
**Output:** 被接受或被拒绝的工作事实，而不是“Agent 自报完成”。

### Slide 8 — Real Open-Source Cases

**Title:** 两个真实 Issue，复现同一套可信交付闭环  
**Job:** 证明不是自造演示题。  
**Content:** Rich #4196、Dify #33013；每个案例只展示来源、签名回执、组合报告与离线验证结果。  
**Boundary:** 不代表两个上游项目采用或验收。

### Slide 9 — Engineering Proof

**Title:** 六角色、五阶段、2,283 项测试  
**Job:** 证明工程成熟度。  
**Content:** 六角色密钥体系、五阶段状态流、离线验证、篡改拒绝、发布入口。  
**Distribution evidence:** 当前版本、PyPI、GitHub Release、MCP/Glama 展示仅在验证后使用。

### Slide 10 — Competition and Alternatives

**Title:** Tracing 记录发生过什么，OpenWorkProof 证明什么可以被接受  
**Job:** 回答为何不能用现有方案。  
**Comparison:** 日志/Tracing、IAM、Eval、MCP/A2A、企业自建与 OpenWorkProof。  
**Position:** OpenWorkProof 是互补责任层，不把所有相邻工具描述成直接竞争者。

### Slide 11 — Public Ecosystem Signals

**Title:** 项目已进入公开生态，外部反馈开始形成设计约束  
**Job:** 展示公开性、可讨论性和外部问题质量。  
**Layout:** 左侧两张 DEV Community 裁切评论；右侧 Glama 目录裁切。  
**Visible interpretation:** 相邻方案、撤回语义、验证成本和公开目录可发现性。  
**Boundary footer:** 公开讨论与目录展示，不等于官方采纳、客户使用或商业收入。  
**Privacy decision:** 用户已允许保留公开用户名和头像；头像不额外放大。

### Slide 12 — First Payer

**Title:** Agent 方案商为了上线、交付和回款而付费  
**Job:** 明确使用者、决策者和付款者。  
**Flow:** 企业客户 → Agent 方案商 → OpenWorkProof → 验收与结算。

### Slide 13 — Business Model and Go-to-Market

**Title:** 先卖工作流改造，再形成年度授权与平台集成  
**Job:** 同时回答卖什么、多少钱、如何获得第一批客户。  
**Revenue ladder:**

- 可信交付诊断：人民币 3–5 万；
- 付费 PoC / 改造包：人民币 20–50 万/项目；
- 企业年度授权：人民币 30–100 万/年；
- 平台 OEM / SDK：人民币 50–150 万/年起。

**First channels:** Agent 方案商、AI 解决方案商、系统集成商、阿加犀团队场景实践。所有价格仍是待验证假设。

### Slide 14 — Team and Governance

**Title:** 商业战略、协议工程与生态实践形成完整闭环  
**Job:** 证明团队与角色匹配。  
**People:**

- 董浩宇博士｜商业战略负责人；北京大学博士，20+ 年品牌与数字化经验；
- 邓海波｜舆意科技 CTO / 协议架构与产品工程；前华为高级开发工程师；
- 龙胜海｜阿加犀生态技术总监 / OpenWorkProof 共研技术成员；负责资料整理、技术研判和后续实践。

**Entity strip:**

- 参赛主体：舆意科技（上海）有限公司；
- 研发 / IP / 融资：成都星火领航科技有限公司；
- 技术 Owner：dengyier。

成员履历来源为用户确认资料；制作阶段只选择与项目执行直接相关的两项证明，避免履历堆砌。

### Slide 15 — Angel Round

**Title:** 人民币 200 万元，换取三项商业可验证性  
**Job:** 说明钱买到什么。  
**Milestones:** 3 个付费 PoC、1 个公开参考客户、1 个年度授权客户。  
**Validation metrics:** 真实客单价、销售周期、交付成本、续费理由。  
**Allocation:** 产品与协议研发 40%、企业试点与交付 30%、安全/法务/IP 15%、市场与社区 10%、储备 5%。

### Slide 16 — Vision and Ask

**Title:** 让 Agent 从“能工作”走向“可以被企业正式雇用”  
**Job:** 回答五年愿景并发出行动请求。  
**Ask:** 首批 Agent 方案商、高责任企业试点、产业与生态合作伙伴。  
**Visual:** image-2 生成 Agent 节点通过可信证据桥接到企业系统的抽象结构；无人物、文字或 Logo。

## 5. Visual System — B2 Institutional Editorial

### Palette

- Paper white: `#FBFCFD`
- Ink navy: `#081E36`
- Evidence blue: `#087AF0`
- Acceptance green: `#0A8D72`
- Muted slate: `#647386`
- Light rule: `#DCE5ED`

### Typography

- 中文与主要英文：现代无衬线字体；
- 协议对象、摘要和状态：等宽字体作为小面积证据纹理；
- Deck title ≥ 50 pt；slide title ≥ 35 pt；正文 ≥ 16 pt；
- 单行标题不得自动换行；文案不适配时先缩短或换版式。

### Composition

- 采用编辑式横线、编号、短段落和大留白；
- 不使用密集 UI 卡片、标签墙或伪交互面板；
- 每页一个主结论，次要证据进入备注；
- image-2 主视觉只使用三次，且每次构图不同；
- 真实截图不生成、不重绘，只裁切、缩放和必要的色彩统一。

## 6. Image-2 Generation Rules

### Must Keep

- 简约、机构化、可信基础设施语义；
- 16:9 画幅适配；
- 封面左侧或指定区域必须留干净负空间；
- 蓝色与青绿色玻璃/光线结构与 B2 视觉系统一致。

### May Vary

- 抽象节点数量；
- 透明层、签名印记和证据路径形态；
- 暗底或浅底，但不得破坏整套白底编辑系统。

### Forbidden

- 人物、机器人、握手、法槌、锁头等陈词滥调；
- 任何文字、Logo、真实企业标识或伪造产品界面；
- 过度赛博朋克、复杂 HUD、密集光效；
- 生成或修改团队成员面貌。

### Human Judgment

- 是否足够简约；
- 是否像可信企业基础设施而非区块链宣传图；
- 是否与团队照片、真实截图和商业页共存。

## 7. Approved Local Assets

### Team Photos

- `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/team/dong-haoyu.jpg`
- `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/team/deng-haibo.jpg`
- `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/team/long-shenghai.png`

### Public Evidence Screenshots

- `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/dev-mikhail-receipts-retraction.png`
- `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/dev-puneet-verification-cost.png`
- `/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/assets/evidence/glama-openworkproof-listing.png`

These assets are locally delivered inputs. Public visibility does not prove commercial clearance, endorsement, adoption, or customer status. The user has authorized their use in this competition deck.

## 8. Output Contract

### Source Reference

`/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V3_商业模式清晰版.pptx`

The V3 deck remains unchanged. V4 uses its validated content and source notes as inputs but adopts the new approved B2 visual system and 16-slide narrative.

### Final Output

`/Users/molin/Documents/成都星火领航科技/outputs/OpenWorkProof_港科大参赛暨天使轮融资路演_V4_YC双线叙事版.pptx`

### Build Workspace

`/Users/molin/Documents/成都星火领航科技/outputs/.openworkproof_pitch_v4_build/`

Only the final PPTX is delivered outside the build workspace. V2 and V3 must retain their original SHA-256 and size.

## 9. Source and QA Requirements

- Every slide must contain a `[Sources]` block in speaker notes.
- Externally sourced non-trivial claims must link to the direct source.
- User-provided biographies are labeled as founder-provided team information in notes.
- All 16 slides must be rendered and inspected individually at full size.
- Run `slides_test.py` and fix every unintended overflow or overlap.
- Inspect final PPTX ZIP integrity and speaker-note count.
- Verify image crops, page numbers, line breaks, screenshot readability and team identity.
- Scan visible copy for unsupported claims including customer adoption, official MCP adoption, enterprise deployment, commercial revenue and completed阿加犀实践.

## 10. Out of Scope

- No customer logo wall without verified authorization and customer status.
- No financial valuation or equity dilution terms before financing terms are confirmed.
- No generated product screenshots or fabricated enterprise deployment scenes.
- No claim that Glama listing equals official MCP Registry adoption.
- No claim that planned阿加犀实践 has already been completed.
- No overwrite of V2 or V3.

