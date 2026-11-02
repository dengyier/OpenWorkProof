"""Command line entry point.

    python -m aisoc simulate --out demo-output/aisoc-run
    python -m aisoc verify demo-output/aisoc-run
    python -m aisoc slips-ingest <slips-output>/alerts.json [--conn-log <slips-output>/zeek_files/conn.log]
    python -m aisoc aisoc-bundle-verify bundle.json [--hmac-key KEY]
    python -m aisoc aisoc-push demo-output/slips-run --base-url http://localhost:8000 --token ... [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from .canonical import digest
from .crypto import Clock, Ed25519Signer, TrustedKeys
from .idps import MODEL_RELEASE_ROLE, DualModel, release_model
from .sandbox import HeuristicStubAgent
from .scenarios import ALL_SCENARIOS
from .simulate import FAMILIES, detection_metrics, generate, summarize_requests
from .soc import AISOC

# ── 【老師註解】DISCLAIMER ───────────────────────────────────────
# 做什麼：每份輸出報告的第一句話：資料是合成的、agent 是確定性 stub、數字只描述這個參考實作。
# 為什麼：這是論文「誠實範圍」的一部分——不讓讀者把模擬結果誤讀成「對真實流量的偵測率」或「零日免疫證明」。
# 對應：準則 #13
DISCLAIMER = (
    "All data is synthetic and all agents are deterministic stubs. Numbers describe this reference "
    "implementation only; they are not detection results on real traffic, not a security certification, "
    "and not evidence of zero-day immunity or unconditional containment."
)


# ── 【老師註解】_train ───────────────────────────────────────────
# 做什麼：用固定 seed 產生合成資料集（可選擇「留一個家族不訓練」），訓練一個 dual_model，並把 seed／留出家族寫進 model_version。
# 為什麼：可重現是一切評估的前提；held_out 讓我們能問「沒看過這個攻擊家族時，異常分支抓不抓得到」——這就是零日的模擬。
# 對應：準則 #12、#13；（此處無直接測試，由 simulate 整體覆蓋）
def _train(seed: int, held_out: str | None = None) -> tuple[DualModel, Any]:
    ds = generate(seed=seed, held_out_family=held_out)
    model = DualModel.train(ds.train, ds.val, model_version=f"dual_model/synthetic-seed{seed}" + (f"-lofo-{held_out}" if held_out else ""))
    return model, ds


# ── 【老師註解】cmd_simulate ─────────────────────────────────────
# 做什麼：`python -m aisoc simulate` 的主體，四步：①時間切分訓練＋評估 ②留一家族（LOFO）評估 ③經簽名發佈閘門載入模型、跑完整 SOC 管線並匯出帳本
#         ④跑全部安全情境與消融，最後寫 report.json / report.md。任何情境 FAIL ⇒ 回傳碼 1。
# 為什麼：這一個指令就是論文的「可重現實驗」：讀者不用信我們的話，自己跑一次就能看到每個控制點有沒有守住。
# 怎麼看：第 3 步的模型不是直接 new 出來用，而是走 _release_and_load（簽名 manifest → 驗證 → 載入），展示準則 #10；
#         每筆案件之間 clock.advance(7) 是為了避免去重把所有案件壓成同一個視窗。
# 拿掉會怎樣：沒有這個入口，情境與消融就只存在於 pytest 裡，非開發者無法自行重現。
# 對應：準則 #10、#12、#13；（此處無直接測試，情境本身由 tests/test_end_to_end.py::test_scenarios_behave_as_specified 覆蓋）
def cmd_simulate(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {"disclaimer": DISCLAIMER, "seed": args.seed}

    # 步驟 1/4：依時間順序切分（訓練在前、測試在後），避免「用未來預測過去」的洩漏
    print("1/4 training dual_model on time-ordered synthetic split ...")
    model, ds = _train(args.seed)
    report["detection_time_split"] = detection_metrics(model, ds.test)

    # 步驟 2/4：每次拿掉一個攻擊家族重新訓練，再只用「那個沒看過的家族 + 良性」評估——模擬零日
    print("2/4 leave-one-family-out ...")
    lofo: Dict[str, Any] = {}
    for fam in FAMILIES:
        m, d = _train(args.seed, held_out=fam)
        held = [f for f in d.test if f.family == fam]
        benign = [f for f in d.test if f.label == "benign"]
        metrics = detection_metrics(m, held + benign)
        lofo[fam] = {
            "recall_on_held_out_family": metrics["recall_by_family"].get(fam),
            "benign_fpr": metrics["benign_fpr_at_fixed_thresholds"],
            "status_counts_on_held_out": {k: v for k, v in metrics["status_counts"].items()},
        }
    report["leave_one_family_out"] = lofo

    # 步驟 3/4：模型先走簽名發佈閘門才能載入；再把測試流量逐筆餵進 SOC，最後把帳本／見證／收據匯出到 out
    print("3/4 running SOC pipeline with heuristic agent (model loaded through the signed release gate) ...")
    clock = Clock(start=Clock().now())
    soc, manifest = _release_and_load(model, ds, clock, report["detection_time_split"], lofo)
    report["model_release"] = manifest.payload
    _seed_synthetic_context(soc, ds.test[: args.max_cases], args.seed)
    n = 0
    for f in ds.test[: args.max_cases]:
        soc.ingest(f)
        clock.advance(7)  # avoid dedup collapsing everything onto one window
        n += 1
    soc.export(out)
    report["soc_run"] = {
        "cases": n,
        "investigated": sum(1 for r in soc.results if r.investigated),
        "deduplicated": sum(1 for r in soc.results if r.deduplicated),
        "requests": summarize_requests(soc.results),
        "verification_status_counts": _count(r.verification_status for r in soc.results if r.investigated),
        "acceptance_status_counts": _count(r.acceptance_status for r in soc.results if r.investigated),
        "ledger_entries": len(soc.ledger.entries),
        "witness_checkpoints": len(soc.witness.checkpoints()),
    }

    # 步驟 4/4：逐一跑情境與消融；每個情境自己帶 passed 判準，這裡只印 [ok]/[FAIL] 並彙整
    print("4/4 running security scenarios and ablations ...")
    scen: List[Dict[str, Any]] = []
    for fn in ALL_SCENARIOS:
        r = fn(model)
        scen.append(r)
        print(f"   [{'ok' if r['passed'] else 'FAIL'}] {r['name']}")
    report["scenarios"] = scen

    (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    (out / "report.md").write_text(_markdown(report))
    print(f"\nwritten to {out}/report.json and report.md")
    # 任何一個情境沒守住 ⇒ 非零回傳碼，讓 CI 直接紅燈
    return 0 if all(s["passed"] for s in scen) else 1


# ── 【老師註解】_release_and_load ────────────────────────────────
# 做什麼：模擬「訓練域 → 推論域」的交接：訓練域用 model-release 角色的鑰匙簽一張發佈 manifest（含資料集摘要、評估數字）；
#         推論域只信任這把鑰匙，用 AISOC.from_release 驗證 manifest 與模型位元組的雜湊後才載入。
# 為什麼：模型是「製品」，不是隨手 new 出來的物件；誰發佈、用什麼資料、評估結果如何，都要釘在簽名裡，推論端才能拒絕被調包的模型。
# 怎麼看：trust 裡只放 release_signer 一把鑰匙，示範「一角色一鑰匙」；manifest.payload 後面會被原封寫進 report。
# 拿掉會怎樣：任何人把模型檔換掉，推論端照樣載入，偵測結果就不再可追溯。
# 對應：準則 #9、#10；測試 tests/test_egress_release_grant.py::test_release_gate_accepts_only_exact_signed_artefact、::test_soc_from_release_records_verified_manifest_and_plain_init_records_unverified
def _release_and_load(model: DualModel, ds: Any, clock: Clock, metrics: Dict[str, Any], lofo: Dict[str, Any]) -> tuple[AISOC, Any]:
    """Training-domain step: sign a release manifest; inference-domain step: load only if it verifies."""
    # 訓練域：建立發佈角色的鑰匙，並把它（只有它）放進推論端的信任清單
    release_signer = Ed25519Signer(MODEL_RELEASE_ROLE)
    trust = TrustedKeys()
    trust.trust(release_signer)
    # 訓練資料集的摘要也進 manifest：日後能證明「這個模型是用哪批資料訓練的」
    dataset_digest = digest([f.__dict__ for f in ds.train])
    evaluation = {
        "benign_fpr": metrics["benign_fpr_at_fixed_thresholds"],
        "recall_by_family": metrics["recall_by_family"],
        "lofo_recall": {fam: v["recall_on_held_out_family"] for fam, v in lofo.items()},
    }
    manifest = release_model(model, dataset_digest, release_signer, clock, approved_by="simulated-release-board", evaluation=evaluation)
    # 推論域：只給「位元組 + manifest + 信任清單」，from_release 內部驗簽名、比雜湊，不過就拒載
    soc = AISOC.from_release(model.to_bytes(), manifest, trust, HeuristicStubAgent(clock), clock=clock)
    return soc, manifest


# ── 【老師註解】cmd_slips_ingest ─────────────────────────────────
# 做什麼：`python -m aisoc slips-ingest alerts.json [--conn-log conn.log]`：把真實 Slips 輸出當「外部已知／異常分支」餵進 SOC，
#         匯出帳本、見證、收據與 slips-summary.json。
# 為什麼：這是把論文從「合成資料」接到「真實 IDS 輸出」的橋；合成訓練的 dual_model 在這裡只借用它的發佈閘門與閾值。
# 怎麼看：--internal-normality 預設關閉——合成基線訓練的正常模型對真實流量沒有意義，開了就是誤用（印出的訊息會明講）；
#         --tau-k 是部署設定，不是校準後的機率門檻；summary 的 disclaimer 也再次強調 Slips 信心值不是機率。
# 拿掉會怎樣：沒有這條指令，Slips 轉接器只能在測試裡跑，無法對使用者自己的 alerts.json 做可驗證的處理。
# 對應：準則 #11、#12、#13；測試 tests/test_egress_release_grant.py::test_cli_slips_ingest_verify_bundle_and_push_dry_run
def cmd_slips_ingest(args: argparse.Namespace) -> int:
    """Run Slips alerts.json (IDMEFv2) through the SOC as the external known/anomaly branch."""
    from .adapters.slips import run_slips_alerts

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print("training dual_model on synthetic data (only its release gate and thresholds are used; the internal "
          f"normality model is {'ENABLED' if args.internal_normality else 'disabled'} for real traffic) ...")
    model, ds = _train(args.seed)
    clock = Clock(start=Clock().now())
    metrics = detection_metrics(model, ds.test)
    # 即使是真實資料，模型一樣要走簽名發佈閘門才載入
    soc, manifest = _release_and_load(model, ds, clock, metrics, {})
    # 核心：解析 alerts.json（+ conn.log），每個 (來源 IP, 時間窗) 成一案，走完整 SOC 管線
    summ = run_slips_alerts(soc, args.alerts, tenant=args.tenant, conn_log=args.conn_log,
                            use_internal_normality=args.internal_normality, tau_k=args.tau_k)
    # 匯出帳本等檔案，之後可用 `python -m aisoc verify <out>` 離線重驗
    soc.export(out)
    cases = summ.export_cases()
    summary = {"disclaimer": DISCLAIMER + " Slips confidences are not calibrated probabilities; tau_k is a deployment setting.",
               "source": {"alerts": str(args.alerts), "conn_log": str(args.conn_log) if args.conn_log else None,
                          "slips_versions": summ.slips_versions},
               "model_release": manifest.payload, **summ.to_dict(), "case_results": cases}
    (out / "slips-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str))
    print(json.dumps({k: summary[k] for k in ("evidence", "incidents", "malformed", "cases", "status_counts", "requires_human_review", "known_families")}, indent=2))
    print(f"\nwritten to {out}/ (ledger.json, witness-checkpoints.json, slips-summary.json); verify with: python -m aisoc verify {out}")
    return 0


# ── 【老師註解】cmd_aisoc_bundle_verify ──────────────────────────
# 做什麼：`python -m aisoc aisoc-bundle-verify bundle.json [--hmac-key KEY]`：重新算 AiSOC 調查包的 payload_sha256，有鑰匙就連 HMAC 一起驗。
# 為什麼：AiSOC 匯出的包聲稱「有完整性保護」，但聲稱不等於驗證；這條指令讓使用者自己重算，不必信任產出方。
# 怎麼看：沒給 --hmac-key 時會在 stderr 提醒「sha256 只能抓意外損毀，抓不到偽造」——因為任何人都能改內容後重算 sha256；
#         形狀不對（AiSOCBundleError）直接回 1 並列出問題，不會「勉強通過」。
# 拿掉會怎樣：使用者只能相信 bundle 裡自帶的 sha256 欄位，那和沒有驗證一樣。
# 對應：準則 #7、#8、#11；測試 tests/test_egress_release_grant.py::test_cli_slips_ingest_verify_bundle_and_push_dry_run
def cmd_aisoc_bundle_verify(args: argparse.Namespace) -> int:
    from .adapters.aisoc_stack import AiSOCBundleError, verify_aisoc_bundle

    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    try:
        check = verify_aisoc_bundle(bundle, args.hmac_key)
    except AiSOCBundleError as exc:
        print(json.dumps({"ok": False, "problems": [str(exc)]}, indent=2))
        return 1
    print(json.dumps(check.to_dict(), indent=2))
    if check.ok and not check.hmac_checked:
        print("note: only payload_sha256 was checked (no --hmac-key). sha256 alone detects accidental corruption, not forgery.", file=sys.stderr)
    return 0 if check.ok else 1


# ── 【老師註解】cmd_aisoc_push ───────────────────────────────────
# 做什麼：`python -m aisoc aisoc-push <run_dir> --base-url ... --token ... [--dry-run]`：把 slips-ingest 匯出的每個案件轉成 AiSOC 事件，
#         帶著帳本頭雜湊與最新 Merkle 根（ledger_anchors），用 Idempotency-Key 逐案送到 alerts/submit（或串流 ingest）。
# 為什麼：分析師在 AiSOC 看警報；把我們的案件推過去時，一併附上帳本錨點，他們日後能回頭對照我們的帳本。
# 怎麼看：--dry-run 只印「將會送什麼」且完全不碰網路，是檢查格式的安全方式；沒 token 又不是 dry-run ⇒ 回傳碼 2，拒絕匿名送出。
#         每案的 Idempotency-Key 由 idempotency_key_for 算出，重跑指令不會在 AiSOC 產生重複警報。
# 拿掉會怎樣：手動複製貼上案件到 AiSOC，既會重複，也會失去帳本錨點的對應關係。
# 對應：準則 #7；測試 tests/test_egress_release_grant.py::test_cli_slips_ingest_verify_bundle_and_push_dry_run（dry-run 路徑）
def cmd_aisoc_push(args: argparse.Namespace) -> int:
    """Push the cases of an exported run (from slips-ingest or simulate) to AiSOC as alerts."""
    from .adapters.aisoc_stack import AiSOCClient, AiSOCConfig, AiSOCError, case_to_event, idempotency_key_for
    from .soc import CaseResult

    d = Path(args.run_dir)
    summary_path = d / "slips-summary.json"
    # 目前只吃 slips-ingest 的輸出（需要 slips-summary.json 裡的 case_results）
    if not summary_path.exists():
        print(f"{summary_path} not found; aisoc-push currently consumes slips-ingest output", file=sys.stderr)
        return 2
    summary = json.loads(summary_path.read_text())
    entries = json.loads((d / "ledger.json").read_text())
    cps = json.loads((d / "witness-checkpoints.json").read_text())
    # 帳本錨點：最後一筆 entry_hash（鏈頭）與最新見證的 Merkle 根，會嵌進每個事件
    head = entries[-1]["entry_hash"] if entries else None
    root = cps[-1]["payload"]["merkle_root"] if cps else None
    events = []
    for c in summary["case_results"]:
        res = CaseResult.from_dict(c)
        flow = _flow_stub(c)
        technique = (c.get("slips") or {}).get("known", {}).get("technique")
        events.append(case_to_event(res, flow, head, root, techniques=[technique] if technique else None))
    # dry-run：只印不送；之後才檢查 token，所以 dry-run 不需要憑證
    if args.dry_run:
        print(json.dumps({"would_post": f"{args.base_url.rstrip('/')}/api/v1/alerts/submit", "events": events}, indent=2, default=str))
        return 0
    if not args.token:
        print("--token (or AISOC_TOKEN) is required unless --dry-run", file=sys.stderr)
        return 2
    client = AiSOCClient(AiSOCConfig(base_url=args.base_url, token=args.token, ingest_url=args.ingest_url))
    ok = 0
    # 逐案送出：有 --ingest-url 走串流 ingest，否則走 alerts/submit 並帶 Idempotency-Key；單案失敗不會中斷其他案
    for ev, c in zip(events, summary["case_results"]):
        try:
            if args.ingest_url:
                resp = client.ingest_batch([ev])
            else:
                resp = client.submit_alert([ev], ev["title"], ev["description"], ev["severity"], ev["tags"],
                                           idempotency_key=idempotency_key_for(CaseResult.from_dict(c)))
            ok += 1
            print(f"[ok] {c['case_id']} -> {resp.get('id', resp)}")
        except AiSOCError as exc:
            print(f"[FAIL] {c['case_id']}: {exc}", file=sys.stderr)
    return 0 if ok == len(events) else 1


# ── 【老師註解】_flow_stub ───────────────────────────────────────
# 做什麼：從匯出的案件 dict 裡只取 AiSOC 事件需要的幾個欄位（租戶、來源主機、目的 IP／埠、時間），其餘流量數值一律填 0。
# 為什麼：aisoc-push 是在「事後」讀檔案，手上沒有原始 FlowRecord；填 0 是為了湊出型別，不代表真的觀測到 0 位元組。
# 怎麼看：這些 0 不會被 case_to_event 當成證據使用（事件只取身份欄位），但讀程式的人要知道它們是佔位，不是資料。
# 對應：準則 #11；（此處無直接測試）
def _flow_stub(case: Dict[str, Any]):
    """Rebuild the few FlowRecord fields the AiSOC event needs from an exported case dict."""
    from .idps import FlowRecord

    f = case.get("flow", {})
    return FlowRecord(flow_id=case["flow_id"], tenant=f.get("tenant", ""), src_host=f.get("src_host", ""), dst_ip=f.get("dst_ip", ""),
                      dst_port=int(f.get("dst_port", 0) or 0), bytes_in=0, bytes_out=0, pkts_in=0, pkts_out=0, duration_s=0,
                      mean_iat_ms=0, conn_failures=0, short_window_conns=0, distinct_dst_ports=0, login_failures=0,
                      observed_at=f.get("observed_at", ""))


# ── 【老師註解】cmd_verify ───────────────────────────────────────
# 做什麼：`python -m aisoc verify <dir>`：離線、獨立地重驗一個匯出的 run。只讀四個檔案（ledger.json、trusted-keys.json、
#         witness-checkpoints.json、tool-side-receipts.json），做五項檢查：①哈希鏈 ②見證簽名與 Merkle 根 ③出口中介 ④收據簽名與繞過對賬 ⑤給出狀態。
# 為什麼：帳本是產生方自己寫的，自己說自己對沒有意義；驗證器必須能在另一台機器、不 import SOC 物件、只靠公鑰就重算出同樣結論。
# 怎麼看：這個函式刻意「自己重寫」檢查邏輯，而不是呼叫 aisoc.owp.verifier——這樣讀者可以逐行對照兩邊是否一致；
#         狀態只有三種：有任何問題 ⇒ FAILED；沒問題但沒有任何見證檢查點 ⇒ UNKNOWN（不是 VERIFIED！）；否則 VERIFIED。
#         「無見證 ⇒ UNKNOWN」是準則 #8 的精神：沒人見證過的鏈，就算內部一致，也可能是整本重寫的。
# 拿掉會怎樣：所有「可驗證」的宣稱都退化成「請相信我們的 JSON」。
# 對應：準則 #2、#7、#8、#9；測試 tests/test_egress_release_grant.py::test_cli_slips_ingest_verify_bundle_and_push_dry_run（verify 子命令）、
#       tests/test_ledger_verifier.py::test_verifier_unknown_without_witness（同一規則在 verifier 模組的對照）
def cmd_verify(args: argparse.Namespace) -> int:
    """Offline re-verification of an exported run: chain, witness, receipts."""
    from .canonical import digest
    from .crypto import TrustedKeys
    from .owp.ledger import GENESIS, merkle_root

    d = Path(args.dir)
    entries = json.loads((d / "ledger.json").read_text())
    keys = json.loads((d / "trusted-keys.json").read_text())
    cps = json.loads((d / "witness-checkpoints.json").read_text())
    receipts = json.loads((d / "tool-side-receipts.json").read_text())
    # 步驟 0：只載入「公鑰 + 角色」；驗證器手上沒有任何私鑰，所以它不可能偽造，也不需要被信任
    trusted = TrustedKeys()
    for kid, info in keys.items():
        trusted.trust_raw(kid, info["role"], bytes.fromhex(info["public_raw_hex"]))

    problems: List[str] = []
    prev = GENESIS
    # 步驟 1：哈希鏈——每筆的 prev_hash 要等於前一筆的 entry_hash；entry_hash 要等於自己內容的摘要；index 要連號
    for i, e in enumerate(entries):
        body = {k: e[k] for k in e if k != "entry_hash"}
        if e["prev_hash"] != prev or digest(body) != e["entry_hash"] or e["index"] != i:
            problems.append(f"chain broken at {i}")
        prev = e["entry_hash"]
    hashes = [e["entry_hash"] for e in entries]
    # 步驟 2：見證檢查點——簽名必須來自 ledger 角色的鑰匙（角色錯 ⇒ 無效）；帳本不能比見證過的長度短（截斷）；
    #         重算前 length 筆的 Merkle 根必須和見證時一致（改動／分叉）
    for cp in cps:
        p = cp["payload"]
        if not any(trusted.verify(p, s, expected_role="ledger") for s in cp["signatures"]):
            problems.append("checkpoint signature invalid")
        elif p["length"] > len(hashes):
            problems.append(f"truncated below witnessed length {p['length']}")
        elif merkle_root(hashes[: p["length"]]) != p["merkle_root"]:
            problems.append(f"merkle mismatch at witnessed length {p['length']}")
    # 步驟 3：出口中介——每個 action_request 的摘要，必須「先」出現在某筆 agent_egress 的 msg_digest 裡；
    #         否則這張請求不是從受控出口進來的（有人繞過出口代理直接塞請求）
    egress_seen: Dict[str, int] = {}
    for e in entries:
        if e["entry_type"] == "agent_egress":
            egress_seen.setdefault(e["refs"].get("msg_digest", ""), e["index"])
        elif e["entry_type"] == "action_request":
            idx = egress_seen.get(e["object_digest"])
            if idx is None or idx > e["index"]:
                problems.append(f"entry {e['index']}: action_request without a prior audited egress record")
    # 步驟 4：收據對賬——收據要由 executor 角色簽名；凡是「executed」的收據，帳本裡必須同時有這張收據的摘要
    #         和對應請求的 authorization，缺一就是「有做卻沒授權／沒記帳」= 繞過（bypass）
    recorded = {e["object_digest"] for e in entries if e["entry_type"] == "action_receipt"}
    authorized = {e["refs"].get("request_digest") for e in entries if e["entry_type"] == "authorization"}
    for r in receipts:
        p = r["payload"]
        if not any(trusted.verify(p, s, expected_role="executor") for s in r["signatures"]):
            problems.append(f"receipt {p['receipt_id']} signature invalid")
        if p["outcome"] == "executed" and (digest(p) not in recorded or p["request_digest"] not in authorized):
            problems.append(f"receipt {p['receipt_id']} executed without ledger authorization (bypass)")

    # 步驟 5：定案——有問題 ⇒ FAILED；沒有見證檢查點 ⇒ UNKNOWN（不敢說 VERIFIED）；都好 ⇒ VERIFIED。只有 VERIFIED 回傳 0
    status = "FAILED" if problems else ("UNKNOWN" if not cps else "VERIFIED")
    print(json.dumps({"status": status, "entries": len(entries), "checkpoints": len(cps), "receipts": len(receipts), "problems": problems}, indent=2))
    return 0 if status == "VERIFIED" else 1


# ── 【老師註解】_seed_synthetic_context ──────────────────────────
# 做什麼：在 simulate 跑 SOC 之前，往唯讀工具的假資料庫塞兩種「可關聯的旁證」：約一半惡意流量的目的 IP 放進 IOC 情報；每台主機給一個行為視窗
#         （惡意主機的新程序數 25–60，良性 0–10）。
# 為什麼：沒有旁證，HeuristicStubAgent 永遠只有一條流量可看，分數上不去，就展示不出「高影響動作送人簽」那條路徑。
# 怎麼看：用固定 seed 的 random，所以每次 simulate 的結果一致；這是「合成情境」，不是真實情報來源（準則 #13）。
# 對應：準則 #13；（此處無直接測試）
def _seed_synthetic_context(soc: AISOC, flows, seed: int) -> None:
    """Give the read-only tools something to correlate: a synthetic IOC feed and host windows."""
    import random

    rng = random.Random(seed)
    for f in flows:
        if f.label != "benign" and rng.random() < 0.5:
            soc.telemetry.ioc[f.dst_ip] = {"indicator": f.dst_ip, "match": True, "source": "synthetic-feed"}
        soc.telemetry.host_windows[f"{f.tenant}/{f.src_host}"] = {
            "new_process_count": rng.randint(25, 60) if f.label != "benign" else rng.randint(0, 10),
            "window_s": 300,
        }


# ── 【老師註解】_count / _markdown ───────────────────────────────
# 做什麼：_count 把一串狀態值數成 {狀態: 次數}；_markdown 把 report dict 排成人看的 report.md（偵測表、LOFO 表、SOC 統計、情境表）。
# 為什麼：report.json 給機器與測試，report.md 給人；兩者內容相同，只是呈現不同——不要只看 md 就下結論，數字出處在 json。
# 對應：準則 #13；（此處無直接測試）
def _count(it) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for x in it:
        out[str(x)] = out.get(str(x), 0) + 1
    return out


def _markdown(r: Dict[str, Any]) -> str:
    lines = ["# AI SOC reference run", "", f"> {r['disclaimer']}", ""]
    dt = r["detection_time_split"]
    lines += ["## Detection (time-ordered split, synthetic)", "",
              f"- benign FPR at validation-fixed thresholds: {dt['benign_fpr_at_fixed_thresholds']}",
              f"- recall by family: {dt['recall_by_family']}", f"- status mix: {dt['status_counts']}", "",
              "## Leave-one-family-out", "", "| held-out family | recall | benign FPR |", "|---|---|---|"]
    for fam, v in r["leave_one_family_out"].items():
        lines.append(f"| {fam} | {v['recall_on_held_out_family']} | {v['benign_fpr']} |")
    s = r["soc_run"]
    lines += ["", "## SOC run", "", f"- cases: {s['cases']}, investigated: {s['investigated']}, dedup-suppressed: {s['deduplicated']}",
              f"- requests: {s['requests']}", f"- verification: {s['verification_status_counts']}",
              f"- acceptance: {s['acceptance_status_counts']}", f"- ledger entries: {s['ledger_entries']}, witnessed checkpoints: {s['witness_checkpoints']}",
              "", "## Scenarios and ablations", "", "| result | scenario | expected |", "|---|---|---|"]
    for sc in r["scenarios"]:
        lines.append(f"| {'ok' if sc['passed'] else 'FAIL'} | {sc['name']} | {sc['expected']} |")
    return "\n".join(lines) + "\n"


# ── 【老師註解】main ─────────────────────────────────────────────
# 做什麼：argparse 入口。五個子命令：simulate（可重現實驗）、verify（離線重驗）、slips-ingest（真實 Slips 輸出）、
#         aisoc-bundle-verify（重算 AiSOC 調查包完整性）、aisoc-push（把案件推到 AiSOC）。每個子命令用 set_defaults(fn=...) 綁到對應函式。
# 為什麼：所有功能都從同一個 `python -m aisoc` 進入，使用者不用知道模組結構；回傳碼就是結論（0 成功／1 驗證失敗／2 用法錯誤）。
# 怎麼看：aisoc-push 的 --token 預設讀環境變數 AISOC_TOKEN，所以憑證不必出現在命令列歷史裡；
#         slips-ingest 的 --internal-normality 是 store_true（預設關），要「明確要求」才會開，呼應 help 文字的警告。
# 對應：準則 #13；測試 tests/test_egress_release_grant.py::test_cli_slips_ingest_verify_bundle_and_push_dry_run
def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aisoc")
    sub = ap.add_subparsers(dest="cmd", required=True)
    # simulate：--out 輸出目錄、--seed 亂數種子、--max-cases 餵進 SOC 的測試流量上限
    s = sub.add_parser("simulate", help="train dual_model, run the SOC pipeline, scenarios and ablations")
    s.add_argument("--out", default="demo-output/aisoc-run")
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--max-cases", type=int, default=200)
    s.set_defaults(fn=cmd_simulate)
    # verify：唯一參數是匯出目錄
    v = sub.add_parser("verify", help="offline verification of an exported run directory")
    v.add_argument("dir")
    v.set_defaults(fn=cmd_verify)
    # slips-ingest：alerts.json 必填；conn.log 選填（補流量數值）；--tau-k 是已知分支的信心門檻；--internal-normality 預設關
    si = sub.add_parser("slips-ingest", help="run a Slips alerts.json (IDMEFv2) through the SOC as the external detector branch")
    si.add_argument("alerts", help="path to Slips <output>/alerts.json")
    si.add_argument("--conn-log", default=None, help="Zeek conn.log from the same Slips output dir (adds flow volumetrics)")
    si.add_argument("--tenant", default="tenant-slips")
    si.add_argument("--out", default="demo-output/slips-run")
    si.add_argument("--seed", type=int, default=1)
    si.add_argument("--tau-k", type=float, default=0.5, help="min Slips confidence for the known branch to accept a class")
    si.add_argument("--internal-normality", action="store_true",
                    help="score real flows with the synthetic-trained normality model (only meaningful after retraining on your own baseline)")
    si.set_defaults(fn=cmd_slips_ingest)
    # aisoc-bundle-verify：bundle 路徑必填；--hmac-key 選填（沒給就只驗 sha256，並在 stderr 提醒其限制）
    bv = sub.add_parser("aisoc-bundle-verify", help="re-derive the integrity fields of an AiSOC investigation bundle")
    bv.add_argument("bundle")
    bv.add_argument("--hmac-key", default=None, help="AiSOC bundle signing key; without it only payload_sha256 is checked")
    bv.set_defaults(fn=cmd_aisoc_bundle_verify)
    # aisoc-push：run_dir 必填；--token 預設讀 AISOC_TOKEN；--ingest-url 改走串流端點；--dry-run 不碰網路
    ap_push = sub.add_parser("aisoc-push", help="submit the cases of an exported slips-ingest run to AiSOC as alerts")
    ap_push.add_argument("run_dir")
    ap_push.add_argument("--base-url", default="http://localhost:8000")
    ap_push.add_argument("--token", default=__import__("os").environ.get("AISOC_TOKEN", ""))
    ap_push.add_argument("--ingest-url", default=None, help="use the streaming ingest endpoint (e.g. http://localhost:8081/v1/ingest/batch) instead of alerts/submit")
    ap_push.add_argument("--dry-run", action="store_true", help="print the events that would be posted; no network")
    ap_push.set_defaults(fn=cmd_aisoc_push)
    # 解析完直接呼叫對應的 cmd_* 函式，回傳碼原樣交給 sys.exit
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
