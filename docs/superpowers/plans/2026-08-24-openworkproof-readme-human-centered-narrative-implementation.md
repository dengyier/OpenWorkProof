# OpenWorkProof README 人本工程叙事实施计划

> **For Codex:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task by task, with review checkpoints after each task.

**Goal:** 将 `README.md` 与 `README_en.md` 重写为一套以人的目的、正当授权和最终判断为核心，同时能让企业负责人快速理解价值、让开发者完成首次验证的双层开源项目首页。

**Architecture:** README 采用同一套十二段信息架构。第一层先解释“为什么值得信任”和“企业为什么需要”，第二层再展开协议对象、Human Agency、离线验证与接入入口。详细版本历史、完整 CLI、Schema 和测试快照留在专门文档，README 只保留当前可验证事实及必要边界。中文负责中文读者的自然表达，英文按开源社区语境重写，但章节、事实、版本、数字和否定边界保持一致。

**Tech Stack:** Markdown、Python 3.10+、pytest、现有 OpenWorkProof CLI、相对链接审计脚本、Git。

**Design Spec:** `docs/superpowers/specs/2026-08-24-openworkproof-readme-human-centered-narrative-design.md`

---

## 实施边界

本计划只修改：

- `README.md`
- `README_en.md`
- `tests/test_documentation_boundaries.py`

除非测试发现现有链接本身已经失效，否则不修改协议代码、Schema、candidate inventory、版本号、发布元数据或其他产品文档。

不得新增或暗示：

- 已有客户采用、付费 SOW、定金、生产部署或上游采纳；
- OpenWorkProof 能保证 Agent 结果正确；
- `VERIFIED` 等于客户验收、付款、结算、法律审计或合规认证；
- Human Agency 是员工评分、绩效监控、自动担责或责任转移系统；
- 1.3.0 已经发布到 PyPI 或 MCP Registry。

---

### Task 1: 把已确认的叙事与真值边界写成失败测试

**Files:**

- Modify: `tests/test_documentation_boundaries.py`
- Test: `tests/test_documentation_boundaries.py`

**Step 1: 新增中英文首屏叙事测试**

在 `tests/test_documentation_boundaries.py` 追加测试
`test_readmes_lead_with_human_purpose_and_judgment()`，要求出现以下精确文字：

中文：

```text
让智能依人的目的而行动，让每一次行动经得起人的判断。
OpenWorkProof 是 AI Agent 工作契约与可验证执行协议。
```

英文：

```text
Let intelligence act toward human purposes, and let every action stand up to human judgment.
OpenWorkProof is an open work contract and verifiable execution protocol for AI agents.
```

测试还应断言上述使命句位于各自 README 的前 60 行内，避免未来再次被版本历史和商业信息挤出第一屏。

**Step 2: 新增叙事完整性测试**

追加 `test_readmes_preserve_purpose_authority_evidence_and_human_judgment()`，要求中文 README 包含：

```text
人的目的
签名授权
独立验证
接受、拒绝、撤销和申诉
最终判断
```

英文 README 包含：

```text
human purposes
signed authority
independent verification
accept, reject, revoke, and appeal
final judgment
```

**Step 3: 新增当前证据与发布边界测试**

追加 `test_readmes_keep_current_release_and_test_boundaries_aligned()`，要求两份 README 同时包含：

```text
1.3.0
4265 passed
0 failed
0 skipped
183 passed
```

中文必须说明 `1.3.0` 是“本地候选”且“尚未发布”；英文必须说明 `local candidate` 和 `not released`。测试不得把公开 PyPI/MCP 版本号硬编码成 1.2.0，公开状态仍由外部页面回读。

**Step 4: 新增首页禁区测试**

追加 `test_readmes_do_not_turn_the_homepage_into_fundraising_or_market_copy()`，禁止两份 README 出现：

```text
Gartner
$48M
$65M
融资
funding
百亿美元市场
$10B+ market
```

该测试只约束 README，不删除 `docs/status.md` 或历史研究材料。

**Step 5: 运行新增测试，确认先红**

Run:

```bash
python -m pytest -q \
  tests/test_documentation_boundaries.py::test_readmes_lead_with_human_purpose_and_judgment \
  tests/test_documentation_boundaries.py::test_readmes_preserve_purpose_authority_evidence_and_human_judgment \
  tests/test_documentation_boundaries.py::test_readmes_keep_current_release_and_test_boundaries_aligned \
  tests/test_documentation_boundaries.py::test_readmes_do_not_turn_the_homepage_into_fundraising_or_market_copy
```

Expected: 至少首屏叙事和首页禁区测试失败，证明测试确实捕捉到旧 README 的问题，而不是天然为绿。

**Step 6: 提交测试护栏**

```bash
git add tests/test_documentation_boundaries.py
git commit -m "test: lock readme narrative and truth boundaries"
```

---

### Task 2: 重写中文 README 的前 150 行

**Files:**

- Modify: `README.md:1-现有“工作原理”章节之前`
- Reference: `docs/superpowers/specs/2026-08-24-openworkproof-readme-human-centered-narrative-design.md`
- Test: `tests/test_documentation_boundaries.py`

**Step 1: 建立第一屏**

按以下顺序组织，不在第一屏展开版本历史或商业套餐：

1. `# OpenWorkProof`
2. 中英文切换；
3. 项目箴言；
4. 一句产品定义；
5. 一段边界说明；
6. `安装`、`五分钟验证`、`协议文档` 三个入口；
7. Apache-2.0、PyPI、MCP Registry、当前测试事实；
8. 本地候选与公开发布边界。

必须使用已确认文案：

```markdown
> 让智能依人的目的而行动，让每一次行动经得起人的判断。

OpenWorkProof 是 AI Agent 工作契约与可验证执行协议。它记录谁授权了任务、
Agent 实际执行了什么、是否超出约定范围、验证者得出了什么结论，以及验收者最终
接受还是拒绝。
```

随后用不超过两个自然段解释：OpenWorkProof 不保证 Agent 永远正确，也不替客户作出验收决定；它确保授权有来源、执行有证据，并把接受、拒绝、撤销和申诉的权利留给人。

**Step 2: 写“为什么存在”**

章节标题使用：

```markdown
## 当 AI 开始替人行动
```

正文按以下逻辑展开：

- MCP 解决 Agent 与工具的连接，A2A 解决 Agent 与 Agent 的连接；
- 连接不能独立证明一次工作是否被授权、是否越界、证据是否属于同一因果链、谁有最终验收权；
- OpenWorkProof 不让 Agent 更聪明，它让 Agent 工作更值得委托；
- 信任不依赖某个平台自证，而来自持有证据包和公钥的第三方可以离线复核。

**Step 3: 写一个具体问题**

章节标题使用：

```markdown
## Agent 说“完成了”，还缺什么
```

用五问呈现：授权、范围与配额、因果链、验证与验收差异、第三方离线复核。避免从抽象的“市场拐点”起笔。

**Step 4: 写“是什么，也不是什么”**

使用左右对照表或两个短列表。必须清楚表达：

- 是工作契约与可验证执行协议，是现有 Agent/CI/MCP/多 Agent 编排器的开放层；
- 不是 Agent OS、模型框架、员工监控、绩效评分、支付托管、法律仲裁、合规认证或业务正确性判定器。

保留现有文档测试要求的精确否定句：

```text
不是员工评分、绩效监控、法律责任转移、自动担责、资金托管或合规认证
```

**Step 5: 运行首屏测试**

```bash
python -m pytest -q \
  tests/test_documentation_boundaries.py::test_readmes_lead_with_human_purpose_and_judgment \
  tests/test_documentation_boundaries.py::test_readmes_do_not_turn_the_homepage_into_fundraising_or_market_copy
```

Expected: 英文首屏仍失败，中文相关断言通过；中文 README 不再包含被禁止的融资和市场文案。由于测试同时扫描英文 README，首页禁区测试在 Task 4 前仍可因英文旧文案失败。

**Step 6: 提交中文第一层叙事**

```bash
git add README.md
git commit -m "docs: lead chinese readme with human purpose"
```

---

### Task 3: 完成中文 README 的工程层

**Files:**

- Modify: `README.md`
- Reference: `docs/protocol/human-agency-profile-v0.1.md`
- Reference: `docs/status.md`
- Reference: `docs/commercial/verified-agent-delivery/README.md`
- Test: `tests/test_documentation_boundaries.py`

**Step 1: 写“工作原理”**

只保留读者首次理解需要的流程：

```text
WorkOrder -> CapabilityGrant -> PolicyDecision -> ActionReceipt
          -> VerificationDecision -> AcceptanceDecision
```

用紧凑表格解释“目的与范围、授权、事前判断、行动凭证、验证、人工验收”。详细 Schema 和状态历史链接至 `specs/`、`docs/protocol/` 与 `docs/status.md`。

**Step 2: 写 Human Agency 章节**

章节标题使用：

```markdown
## Human Agency：能力越强，人的决定权越不能消失
```

必须准确表达：

- `CapabilityGrant` 是系统可以授予什么；
- `HumanAgencyProfile` 是人愿意让 Agent 自主使用其中哪些能力；
- 有效权限是 WorkOrder、Grant 与 active profile 的交集；
- reserved decision 在执行前拒绝；
- appeal 只记录复核请求，`不恢复或扩大权限`；
- `只有 Acceptor 签名的 transition 才能撤销当前 profile 或将其替换为另一个 Acceptor 签名的 profile`。

保留并链接：

- `docs/protocol/human-agency-profile-v0.1.md`
- `examples/human_agency_profile_v01.py`

**Step 3: 写五分钟快速开始**

只保留一条最短路径：

```bash
python -m pip install openworkproof
owp --help
python examples/human_agency_profile_v01.py
```

再给一个离线 bundle 验证入口和对应文档链接。若当前仓库的真实 CLI 不是上述命令，先用 `python -m openworkproof.cli --help` 与现有文档回读后，使用实际可运行命令，不发明接口。

**Step 4: 写接入方式表**

只保留五行：GitHub Action、CLI、MCP、AgentTeams、Python API。每行说明适用场景和一个真实入口，删除 README 中大段重复示例，把详细操作链接到已有文档。

必须保留文档测试依赖的：

- `GitHub Action`、`AgentTeams`、`四问`；
- `AcceptanceDecisionBindingV01`；
- `prepare → sign → commit`；
- `owp acceptance-bundle-build`；
- `owp acceptance-bundle-verify`；
- `ACCEPTED=0`、`REJECTED=2`、`operational=4`；
- `--acceptance-bundle`；
- `VERIFIED != ACCEPTED != PAID/SETTLED/LEGAL AUDIT/ADOPTION`。

**Step 5: 写已有证据和诚实边界**

区分“工程证据”和“尚未证实的商业事实”。工程证据保留：

```text
required-live: 4265 passed / 0 failed / 0 skipped
candidate: 183 passed / 0 failed / 0 skipped
```

同时保留真实三 Agent preflight、离线 bundle、不可变 inventory 与供应链门的准确表述。Rich #4196、Dify #33013、AgentScope #2239 只能写为演示/复现实验，不写成客户案例或上游采纳。

显式写出：

```text
customer_adoption: not_evidenced
paid_sow: not_evidenced
deposit: not_evidenced
upstream_adoption: not_evidenced
```

**Step 6: 收束商业入口、路线图与结尾**

商业入口只用一个短节解释 Verified Agent Delivery：把一次 Agent 工作转换为可独立验证、可由客户决定是否接受的交付事实。明确 `READY_FOR_SETTLEMENT_REVIEW` 不等于付款。

路线图区分“已完成”“下一步协议闭包”“需要外部参与的生态验证”。保留 License、Contributing、Security 联系入口。

用已确认结尾收束：

```text
我们希望未来的 Agent 可以承担越来越多的工作。能力越强，越应该忠于人的目的；
系统越自动，授权、证据和申诉越不能消失。

OpenWorkProof 想做的事情很朴素：当人把工作交给 AI，仍然知道自己交出了什么、
发生了什么，以及何时可以说“不”。让智能依人的目的而行动，让每一次行动经得起人的判断。
```

**Step 7: 检查中文长度与现有边界测试**

```bash
wc -l README.md
python -m pytest -q tests/test_documentation_boundaries.py
```

Expected:

- `README.md` 约 350 到 450 行；
- 测试可能仍因英文 README 未改而失败，但不得出现中文专属断言失败；
- 不得删除现有 Acceptance 与 Human Agency 精确边界。

**Step 8: 提交中文工程层**

```bash
git add README.md
git commit -m "docs: complete chinese readme verification journey"
```

---

### Task 4: 按相同语义重写英文 README

**Files:**

- Modify: `README_en.md`
- Reference: `README.md`
- Test: `tests/test_documentation_boundaries.py`

**Step 1: 重写英文第一屏**

使用已确认主句：

```markdown
> Let intelligence act toward human purposes, and let every action stand up to human judgment.

OpenWorkProof is an open work contract and verifiable execution protocol for AI agents. It
records who authorized a job, what the agent did, whether it stayed within scope, what the
verifier concluded, and whether the acceptor accepted or rejected the delivery.
```

英文按自然开源项目语言重写，不逐句翻译中文，不使用古典哲学腔。

**Step 2: 建立与中文对应的十二段结构**

英文建议标题：

```text
When AI Acts on Our Behalf
What Is Missing When an Agent Says “Done”
What OpenWorkProof Is, and Is Not
How It Works
Human Agency: More Capability Must Not Mean Less Human Choice
Five-Minute Start
Integration Paths
Evidence You Can Verify
Verified Agent Delivery
Roadmap
Contributing and Security
Why We Keep Building
```

可因英文节奏合并最后三个短节，但语义和事实不得缺失。

**Step 3: 保留英文测试所需的精确边界**

以下原有测试文字必须保留：

```text
Human Agency Profile
WorkOrder-bound
Acceptor-signed
machine-verifiable
not employee scoring, performance monitoring, legal-liability transfer, automatic accountability, fund custody, or compliance certification
never restores or expands permission
only an Acceptor-signed transition can revoke the active profile or supersede it with another Acceptor-signed profile
```

同时保留 Acceptance bundle 精确字面量和 `external human acceptance`。

**Step 4: 对齐证据、版本与发布边界**

英文必须与中文一致写明：

- local candidate 1.3.0 is not released；
- required-live 4265 / 0 / 0；
- candidate 183 / 0 / 0；
- public PyPI / MCP Registry status must be verified on their public pages；
- 商业与外部采用字段仍为 `not_evidenced`。

**Step 5: 运行完整文档边界测试**

```bash
python -m pytest -q tests/test_documentation_boundaries.py
```

Expected: all tests pass.

**Step 6: 提交英文 README**

```bash
git add README_en.md
git commit -m "docs: align english readme with human-centered protocol story"
```

---

### Task 5: 做双语一致性、链接和 Markdown 结构审计

**Files:**

- Modify only if needed: `README.md`
- Modify only if needed: `README_en.md`
- Test: `tests/test_documentation_boundaries.py`

**Step 1: 检查章节与关键事实**

```bash
rg -n '^#{1,3} ' README.md README_en.md
rg -n '1\.3\.0|4265 passed|183 passed|not_evidenced|VERIFIED != ACCEPTED' README.md README_en.md
```

Expected: 两份 README 的章节顺序和所有当前事实一致；允许标题语言自然不同。

**Step 2: 检查代码块闭合**

```bash
python - <<'PY'
from pathlib import Path
for name in ("README.md", "README_en.md"):
    text = Path(name).read_text(encoding="utf-8")
    fences = sum(1 for line in text.splitlines() if line.startswith("```"))
    assert fences % 2 == 0, f"{name}: unclosed fenced code block"
    print(f"{name}: {fences} fences, closed")
PY
```

Expected: both files report an even fence count.

**Step 3: 检查本地相对链接**

```bash
python - <<'PY'
import re
from pathlib import Path
from urllib.parse import unquote

root = Path.cwd()
for name in ("README.md", "README_en.md"):
    missing = []
    text = Path(name).read_text(encoding="utf-8")
    for target in re.findall(r'(?<!!)\[[^]]+\]\(([^)]+)\)', text):
        target = target.split('#', 1)[0].strip()
        if not target or '://' in target or target.startswith('mailto:'):
            continue
        path = root / unquote(target)
        if not path.exists():
            missing.append(target)
    assert not missing, f"{name}: missing local links: {missing}"
    print(f"{name}: local links ok")
PY
```

Expected: both files print `local links ok`.

**Step 4: 检查未经证实的主张与人本边界**

```bash
python -m pytest -q tests/test_documentation_boundaries.py
rg -n '已有客户采用|已收定金|guarantees correctness|production proven|Gartner|\$48M|\$65M|百亿美元市场|\$10B\+ market' README.md README_en.md
```

Expected: pytest passes; `rg` exits 1 with no matches.

**Step 5: 人工通读首屏**

人工回答以下问题，任何一项答“否”都必须继续改：

1. 企业负责人只看前 150 行，能否说清楚它解决的是授权、执行证据和验收问题？
2. 是否先解释人的处境，再介绍协议术语？
3. 是否能区分 `VERIFIED`、`ACCEPTED` 与 `PAID`？
4. 是否能感受到项目守护人的决定权，但不会误以为它是哲学宣言？
5. 开发者是否可以在 README 内找到安装和首次验证命令？

**Step 6: 提交审计修正**

如果有修正：

```bash
git add README.md README_en.md tests/test_documentation_boundaries.py
git commit -m "docs: close bilingual readme consistency gaps"
```

如果没有修正，不创建空提交。

---

### Task 6: 做自然语言与工程质量终检

**Files:**

- Modify only if needed: `README.md`
- Modify only if needed: `README_en.md`

**Step 1: 执行 humanizer 审查**

逐段检查并删除：

- 没有信息增量的“行业变革”“时代浪潮”“赋能”等抽象套话；
- 过量粗体、emoji、机械三段式和同义反复；
- 用破折号制造戏剧感的句子；
- 英文逐字翻译腔、过度对称句和不自然的营销形容词；
- 把工程结果包装成商业采用的措辞。

保留术语所需的精确性，不为了“像人写的”而改坏协议名称、退出码或真值边界。

**Step 2: 检查禁用标点与占位符**

```bash
rg -n '—|–|TODO|TBD|FIXME|PLACEHOLDER' README.md README_en.md
```

Expected: no matches. 若协议命令或外部正式名称确实包含匹配字符，人工确认后在计划执行记录中说明，不静默改写正式名称。

**Step 3: 运行文档测试和轻量工程验证**

```bash
python -m pytest -q tests/test_documentation_boundaries.py
python -m pip check
python -m compileall -q src tests
git diff --check
```

Expected:

- documentation boundaries all pass；
- `pip check` reports no broken requirements；
- `compileall` exits 0；
- `git diff --check` exits 0。

**Step 4: 确认 README 相关测试入口并运行真实存在的文档契约测试**

```bash
rg -l 'README\.md|README_en\.md' tests | sort
python -m pytest -q tests/test_documentation_boundaries.py
```

Expected: 列表包含 `tests/test_documentation_boundaries.py`，该测试文件全部通过。其他命中文件只因仓库或流水线契约间接引用 README，不在本次纯文档改写中盲目扩大全量测试范围。

**Step 5: 查看最终差异范围**

```bash
git status --short
git diff --stat HEAD~5..HEAD
git diff -- README.md README_en.md tests/test_documentation_boundaries.py
```

Expected: 变化只对应 README 重构与其真值测试；不得出现协议代码、Schema、inventory 或版本文件修改。

**Step 6: 提交最终文字修正**

若终检产生修改：

```bash
git add README.md README_en.md tests/test_documentation_boundaries.py
git commit -m "docs: polish openworkproof readmes for people and builders"
```

若没有修改，不创建空提交。

---

### Task 7: 独立复核与交付报告

**Files:**

- Review: `README.md`
- Review: `README_en.md`
- Review: `tests/test_documentation_boundaries.py`

**Step 1: 做独立代码/文档复核**

使用 `requesting-code-review`，要求 reviewer 重点检查：

1. 是否忠实实现已批准的亚里士多德式核心表达；
2. 是否把人的目的、授权、证据和最终判断连成一条产品逻辑；
3. 是否有事实漂移、发布状态漂移或中英文不一致；
4. 是否误删安装、Human Agency、Acceptance、离线验证、License、Contributing 或 Security 入口；
5. 是否存在“读起来很动人，但工程含义不准确”的句子。

**Step 2: 只修复与本计划相关的复核问题**

不顺手重构其他文档或代码。修复后重新运行：

```bash
python -m pytest -q tests/test_documentation_boundaries.py
python -m pip check
python -m compileall -q src tests
git diff --check
```

Expected: all commands exit 0.

**Step 3: 输出证据边界清晰的交付报告**

报告必须分为：

- `已完成`：两份 README、测试、实际提交；
- `验证结果`：逐条命令和通过结果；
- `未执行`：远端 push、版本发布、PyPI/MCP Registry 更新、外部采用与商业验收；
- `建议下一步`：用户可选择本地保留、合并或推送。

不要把本地 README 完成写成远端已发布。

---

## 完成定义

只有同时满足以下条件，才能宣称 README 重构完成：

- 两份 README 都采用已批准的人本工程核心叙事；
- 企业负责人能在中文 README 前 150 行理解问题、价值和边界；
- 开发者能找到安装与首次验证入口；
- 中英文版本、测试数字、发布状态和 `not_evidenced` 边界一致；
- Acceptance 与 Human Agency 的现有精确字面量仍通过测试；
- README 中没有融资、市场规模、客户采用或付款的无证据叙事；
- 所有本地相对链接存在，代码块闭合；
- 文档测试、`pip check`、`compileall` 和 `git diff --check` 全部通过；
- 复核意见已闭环或明确记录；
- 未经用户指示，不推送远端、不发布版本。
