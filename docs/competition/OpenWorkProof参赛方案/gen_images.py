"""Generate competition PPT info-graphics (Pillow, Chinese fonts, light tech style)."""
import os
from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join(os.path.dirname(__file__), "images")
os.makedirs(OUT, exist_ok=True)

FONT_REG = "/System/Library/Fonts/Hiragino Sans GB.ttc"
FONT_BOLD = "/System/Library/Fonts/STHeiti Medium.ttc"
if not os.path.exists(FONT_BOLD):
    FONT_BOLD = FONT_REG

BG = (255, 255, 255)
INK = (15, 23, 42)          # slate-900
SUB = (100, 116, 139)       # slate-500
BLUE = (59, 130, 246)       # blue-500
CYAN = (6, 182, 212)        # cyan-500
CARD = (248, 250, 252)      # slate-50
BORDER = (226, 232, 240)    # slate-200
GREEN = (16, 185, 129)
AMBER = (245, 158, 11)
RED = (239, 68, 68)


def font(size, bold=False):
    return ImageFont.truetype(FONT_BOLD if bold else FONT_REG, size)


def rrect(draw, box, radius, fill, outline=None, width=1):
    draw.rounded_rectangle(box, radius=radius, fill=fill,
                           outline=outline, width=width)


def new_canvas(w, h, scale=2):
    return Image.new("RGB", (w * scale, h * scale), BG)


def text(draw, xy, s, size, fill=INK, bold=False, anchor="la"):
    draw.text(xy, s, font=font(size, bold), fill=fill, anchor=anchor)


def card(draw, box, radius=16, fill=CARD, outline=None):
    rrect(draw, box, radius, fill, outline=outline)


def save(img, name):
    img.save(os.path.join(OUT, name), "PNG")
    print("wrote", name, img.size)


# ---------------------------------------------------------------- 1. scenes
def scene_scenarios():
    W, H, S = 1098, 612, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (60, 40), "三个企业级真实场景", 40, bold=True)
    text(d, (60, 96), "痛点 → OWP 原语 → 可验证收益", 26, SUB)
    data = [
        ("场景 A · SaaS 合规审计", "EU AI Act 高风险 Agent 上线审计 3–5 天，仅凭厂商自陈", "审计 <10 分钟 · 离线可复核", BLUE),
        ("场景 B · 金融风控", "监管需不可篡改的决策依据，厂商日志可事后修改", "append-only 账本 · 独立验签", CYAN),
        ("场景 C · 研发协同", "「Agent 测试通过」不可复现，审计盲区", "Verifier 不能自证 · 同源互证", GREEN),
    ]
    y = 150
    for title, pain, gain, color in data:
        card(d, (60, y, W - 60, y + 130), 18)
        d.rounded_rectangle((60, y, 78, y + 130), 18, fill=color)
        text(d, (100, y + 22), title, 28, bold=True)
        text(d, (100, y + 66), pain, 22, SUB)
        text(d, (100, y + 96), "✓ " + gain, 24, color, bold=True)
        y += 152
    save(img, "scene_scenarios.png")


def scene_diff():
    W, H, S = 1080, 612, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (60, 40), "创新点与差异化", 40, bold=True)
    text(d, (60, 96), "对比现有 Agent 工具链，我们补的是「信任层」", 26, SUB)
    items = [
        ("Proof-Carrying Work", "交付物自带可验证据链，非自陈"),
        ("No-Cloning Authority", "子授权只衰减、不可扩权（防 A2 攻击）"),
        ("Fail-Closed 决策", "验证不了 = 拒绝，绝不默认放行"),
        ("离线复核", "第三方凭证据包 + 公钥独立验签"),
    ]
    y = 150
    for i, (t, s) in enumerate(items):
        card(d, (60, y, W - 60, y + 100), 16)
        d.ellipse((84, y + 32, 116, y + 64), fill=BLUE)
        text(d, (118, y + 48), str(i + 1), 26, (255, 255, 255), bold=True, anchor="lm")
        text(d, (150, y + 34), t, 27, bold=True)
        text(d, (150, y + 68), s, 22, SUB)
        y += 116
    save(img, "scene_diff.png")


# ---------------------------------------------------------- 2. architecture
def architecture():
    W, H, S = 1548, 864, 1
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (60, 36), "OpenWorkProof 端到端方案：Agent 工作契约与可验证执行协议", 42, bold=True)
    text(d, (60, 96), "AgentTeams 负责编排（Matrix 房间全透明），OWP 负责契约 / 授权 / 证据 / 验收", 26, SUB)

    def box(x, y, w, h, t, sub, color=BLUE, big=False):
        card(d, (x, y, x + w, y + h), 14, CARD, BORDER)
        d.rounded_rectangle((x, y, x + 10, y + h), 10, fill=color)
        text(d, (x + 28, y + (34 if big else 30)), t, 30 if big else 25, bold=True)
        if sub:
            text(d, (x + 28, y + (72 if big else 62)), sub, 20, SUB)

    # 左列：客户 / 授权
    box(60, 150, 330, 200, "客户 Acceptor", "签署 JudgmentCommitment\n（执行前业务判断）", CYAN, big=True)
    box(60, 400, 330, 180, "最小权限授权", "Acceptor→Manager→\nDeveloper 三层授权链", CYAN)

    # 中列：AgentTeams 编排
    box(440, 150, 640, 130, "AgentTeams 编排层（Matrix 房间）", "Manager 任务拆解 · 上下文传递 · 人类可介入", BLUE, big=True)
    box(440, 320, 300, 260, "dev-worker", "受限工作区修复\nActionReceipt 原生绑定", BLUE)
    box(800, 320, 280, 260, "verifier-worker", "隔离上下文独立复现\n不信任开发者的结论", GREEN)

    # 右列：证据 / 验证 / 验收
    box(1140, 150, 350, 130, "不可变证据账本", "append-only SQLite\n触发器禁 UPDATE/DELETE", CYAN, big=True)
    box(1140, 320, 350, 260, "BindingDecision 双门", "VERIFIED ∧ BOUND ∧ ACTIVE\n→ READY_FOR_SETTLEMENT_REVIEW", CYAN)

    # 底部流
    for x0, t in ((60, "授权"), (440, "编排与执行"), (1140, "验证 / 审计")):
        d.polygon([(x0 + 60, 720), (x0 + 100, 700), (x0 + 100, 740)], fill=BLUE)
        text(d, (x0 + 120, 730), t, 22, SUB)
    card(d, (60, 770, W - 60, 830), 14, (239, 246, 255))
    text(d, (90, 800), "验收闭环：接收方凭 OWP 离线包（Manifest+收据+公钥）独立复核，无需信任厂商运行时", 24, BLUE, bold=True)
    save(img, "architecture.png")


# ----------------------------------------------------- 3. multiagent roles
def multiagent_team():
    W, H, S = 1044, 576, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (60, 30), "AgentTeams + OWP 多 Agent 协同", 32, bold=True)
    text(d, (60, 78), "4 个不同职能 Agent：编排（LLM）× 验证（确定性机器）", 22, SUB)
    # Manager center
    card(d, (W // 2 - 150, 120, W // 2 + 150, 222), 16, BLUE)
    text(d, (W // 2, 152), "Manager", 30, (255, 255, 255), bold=True, anchor="mm")
    text(d, (W // 2, 192), "任务拆解 / 分派 / 汇总", 20, (255, 255, 255), anchor="mm")
    # three workers in a row
    workers = [
        ("dev-worker", "修复执行 · repo_read / apply_patch", "deepseek-v4-pro · openclaw", BLUE),
        ("verifier-worker", "LLM 独立复核 · 证据核对", "deepseek-v4-pro · openclaw", GREEN),
        ("owp-verifier", "确定性机器验证 · M4 真值基准", "OWP 协议栈 · 可离线复核", (83, 74, 183)),
    ]
    col_w = (W - 120 - 2 * 24) // 3
    x = 60
    for name, duty, model, color in workers:
        card(d, (x, 290, x + col_w, 428), 16, CARD, BORDER)
        d.rounded_rectangle((x, 290, x + 14, 428), 12, fill=color)
        text(d, (x + 30, 320), name, 24, bold=True)
        text(d, (x + 30, 358), duty, 18, SUB)
        text(d, (x + 30, 392), model, 16, color, bold=True)
        x += col_w + 24
    # human
    card(d, (W // 2 - 140, 458, W // 2 + 140, 546), 14, (254, 249, 195))
    text(d, (W // 2, 486), "人类监督 / Acceptor 审批（Element）", 21, (133, 100, 4), bold=True, anchor="mm")
    text(d, (W // 2, 522), "高风险操作授权 · 终态验收", 17, (133, 100, 4), anchor="mm")
    # arrows Manager -> workers
    for cx in (W // 2 - 120, W // 2, W // 2 + 120):
        d.line([(cx, 222), (cx, 290)], fill=BLUE, width=3)
        d.polygon([(cx - 8, 290), (cx + 8, 290), (cx, 272)], fill=BLUE)
    # arrow workers -> human (summary)
    d.line([(W // 2, 428), (W // 2, 458)], fill=AMBER, width=3)
    d.polygon([(W // 2 - 8, 458), (W // 2 + 8, 458), (W // 2, 440)], fill=AMBER)
    save(img, "multiagent_team.png")


def multiagent_roles():
    W, H, S = 1044, 576, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (60, 30), "六职能 Agent 分工（OWP 信任模型）", 32, bold=True)
    text(d, (60, 78), "角色编排映射到 AgentTeams Team / Worker 机制", 22, SUB)
    roles = [
        ("Maintainer", "维护工作区与根授权"),
        ("Manager", "拆解任务 · 签发最小权限授权"),
        ("Developer", "受限工作区执行"),
        ("Verifier", "隔离上下文独立复现"),
        ("Sidecar", "旁路观察 · 防篡改"),
        ("Acceptor", "终态验收 · 签名终局"),
    ]
    colors = [CYAN, BLUE, BLUE, GREEN, AMBER, RED]
    x0, y0, cw, ch, gx, gy = 60, 150, 300, 130, 24, 18
    for i, ((name, duty), color) in enumerate(zip(roles, colors)):
        x = x0 + (i % 3) * (cw + gx)
        y = y0 + (i // 3) * (ch + gy)
        card(d, (x, y, x + cw, y + ch), 16)
        d.rounded_rectangle((x, y, x + 14, y + ch), 12, fill=color)
        text(d, (x + 30, y + 30), name, 27, bold=True)
        text(d, (x + 30, y + 78), duty, 20, SUB)
    save(img, "multiagent_roles.png")


# ------------------------------------------------------------- 4. skills
def skills_s1s8():
    W, H, S = 1134, 630, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (60, 30), "OWP Skill 工程体系（S1–S8）", 34, bold=True)
    text(d, (60, 82), "任务能力抽象层 · 每个 Skill 有输入输出 / 失败处理 / 复用价值 · 已暴露 25 个 MCP 工具", 22, SUB)
    rows = [
        ("S1", "owp.authorize", "任务拆解与最小权限授权", BLUE),
        ("S2", "owp.repo_read", "受限仓库读取", BLUE),
        ("S3", "owp.apply_patch", "受限补丁应用", BLUE),
        ("S4", "owp.run_tests", "可信测试执行（离线 / Docker）", BLUE),
        ("S5", "owp.compose_proof", "证据合成与证明链闭合", CYAN),
        ("S6", "owp.acceptance", "终态验收 / 拒绝与离线验签", CYAN),
        ("S7", "owp.rollback", "高风险动作回滚（复赛前补齐）", AMBER),
        ("S8", "owp.audit", "全链审计与离线复核", GREEN),
    ]
    x0, y0, cw, ch, gx, gy = 60, 140, 510, 108, 24, 16
    for i, (sid, name, duty, color) in enumerate(rows):
        x = x0 + (i % 2) * (cw + gx)
        y = y0 + (i // 2) * (ch + gy)
        card(d, (x, y, x + cw, y + ch), 14, CARD, BORDER)
        d.rounded_rectangle((x, y, x + 46, y + ch), 12, fill=color)
        text(d, (x + 12, y + ch // 2), sid, 22, (255, 255, 255), bold=True, anchor="mm")
        text(d, (x + 66, y + 26), name, 24, bold=True)
        text(d, (x + 66, y + 64), duty, 20, SUB)
    save(img, "skills_s1s8.png")


# ------------------------------------------------------------ 5. engineering
def eng_verification():
    W, H, S = 756, 432, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (44, 34), "可运行性 · 测试证据", 27, bold=True)
    text(d, (44, 82), "required-live 全量", 22, SUB)
    text(d, (44, 130), "3056", 54, GREEN, bold=True)
    text(d, (44, 196), "passed · 0 failed · 0 skipped", 22, INK, bold=True)
    text(d, (44, 240), "严格线程告警门生效", 20, SUB)
    text(d, (44, 290), "聚焦 v0.4 334 · 冻结兼容 161", 20, SUB)
    text(d, (44, 340), "candidate 两套件 68 + 98", 20, SUB)
    save(img, "eng_verification.png")


def eng_evidence():
    W, H, S = 756, 432, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (44, 34), "运行证据 · 不可变账本", 27, bold=True)
    text(d, (44, 82), "每个动作 = 哈希 + 签名收据", 22, SUB)
    steps = [("WorkOrder 契约", BLUE), ("ActionReceipt", BLUE),
             ("append-only 账本", CYAN), ("离线验签包", GREEN)]
    y = 140
    for t, c in steps:
        d.ellipse((50, y + 12, 74, y + 36), fill=c)
        text(d, (92, y + 24), t, 23, bold=True, anchor="lm")
        y += 58
    text(d, (44, 380), "触发器禁 UPDATE/DELETE · ACK-loss 恢复", 19, SUB)
    save(img, "eng_evidence.png")


def eng_observability():
    W, H, S = 756, 432, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (44, 34), "可观测与检索链路", 27, bold=True)
    text(d, (44, 82), "三条接口，同一份数据", 22, SUB)
    for i, t in enumerate(["Python API（services.py）", "CLI（owp binding history …）", "只读 MCP（4+ 工具）"]):
        card(d, (44, 140 + i * 88, W - 44, 140 + i * 88 + 68), 14)
        text(d, (72, 140 + i * 88 + 34), t, 23, bold=True, anchor="lm")
    text(d, (44, 400), "拒绝私钥参数 · 只读不签名不提交", 19, SUB)
    save(img, "eng_observability.png")


def eng_security():
    W, H, S = 756, 432, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (44, 34), "安全治理机制", 27, bold=True)
    text(d, (44, 82), "Fail-Closed 默认拒绝", 22, SUB)
    items = [("最小权限授权链", BLUE), ("Acceptor 独立密钥", RED),
             ("外部权威 as-of 校验", CYAN), ("攻击矩阵 19 例全拒", GREEN)]
    y = 150
    for t, c in items:
        d.ellipse((50, y + 12, 74, y + 36), fill=c)
        text(d, (92, y + 24), t, 23, bold=True, anchor="lm")
        y += 62
    save(img, "eng_security.png")


# ----------------------------------------------------------- 6. plan
def plan_milestones():
    W, H, S = 972, 540, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (50, 32), "里程碑与落地计划", 30, bold=True)
    text(d, (50, 80), "对照官方赛程（初赛 8.16 / 复赛 8.25–9.3 / 决赛 9.22）", 21, SUB)
    ms = [
        ("Phase 0 · 初赛（8.16 截止）", "本方案 PPT + 500 字简介 + 代码包", "提交中", BLUE),
        ("Phase 1 · 接入基座（8.17–24）", "AgentTeams 部署 + 双适配器 + 最小闭环", "已完成", GREEN),
        ("Phase 2 · 复赛 Demo（8.25–9.3）", "AgentScope #2239 多 Agent 全流程 + MCP + 审计", "进行中", AMBER),
        ("决赛（9.22）", "现场路演 + 证据链回放 + 答辩", "待定", CYAN),
    ]
    y = 130
    for t, sub, status, c in ms:
        card(d, (50, y, W - 50, y + 88), 14, CARD, BORDER)
        d.rounded_rectangle((50, y, 66, y + 88), 10, fill=c)
        text(d, (88, y + 24), t, 23, bold=True)
        text(d, (88, y + 58), sub, 19, SUB)
        text(d, (W - 70, y + 44), status, 19, c, bold=True, anchor="rm")
        y += 100
    save(img, "plan_milestones.png")


def plan_risks():
    W, H, S = 1044, 486, 2
    img = new_canvas(W, H, S)
    d = ImageDraw.Draw(img)
    text(d, (50, 30), "风险控制", 30, bold=True)
    text(d, (50, 78), "诚实边界：工程演示，不声称生产就绪 / 客户采用 / 付款", 21, SUB)
    rows = [
        ("Worker 实时执行", "openclaw 路由绑定受配置同步覆盖", "官方 channelPolicy 机制修复", AMBER),
        ("MCP HTTP 挂载", "stdio→HTTP 需新依赖（影响供应链）", "复赛前补依赖 + allowlist", AMBER),
        ("LLM 兼容", "DeepSeek V4 思考模式参数", "降级 REASONING=false 可跑", BLUE),
        ("商业状态", "无客户采用 / 定金（not_evidenced）", "21 天付费试点材料已就绪", CYAN),
    ]
    y = 130
    for name, risk, fix, c in rows:
        card(d, (50, y, W - 50, y + 76), 12, CARD, BORDER)
        text(d, (74, y + 24), name, 21, bold=True)
        text(d, (74, y + 50), risk, 17, SUB)
        d.rounded_rectangle((W - 320, y + 16, W - 70, y + 60), 10, fill=(239, 246, 255))
        text(d, (W - 300, y + 38), "✓ " + fix, 17, BLUE, bold=True, anchor="lm")
        y += 88
    save(img, "plan_risks.png")


if __name__ == "__main__":
    scene_scenarios()
    scene_diff()
    architecture()
    multiagent_team()
    multiagent_roles()
    skills_s1s8()
    eng_verification()
    eng_evidence()
    eng_observability()
    eng_security()
    plan_milestones()
    plan_risks()
    print("ALL DONE")
