"""Controlled egress proxy: the sandbox's *only* channel to the SOC control plane.

In production this sits on the host side of a vsock/unix socket and is the
single way anything leaves the agent sandbox. It implements complete mediation
and accountability (paper §VII, CISSP "complete mediation" / "fail-secure"):

* every message is written to the audit ledger **before** it is forwarded; if
  the audit write fails the message is dropped (``AUDIT_UNAVAILABLE``);
* only known message types up to a size limit pass (``REJECTED_BY_PROXY``);
* a per-minute rate limit bounds how much a compromised agent can push;
* the agent identity is bound to the channel. Whatever ``agent_id`` the
  payload claims is ignored and replaced, so an escaped agent cannot
  impersonate another agent or a human.

The proxy never adds authority: a forwarded ``action_request`` is still only a
request and goes through policy, approval, signing and the PEP as before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol

from ..canonical import canonical_bytes, digest
from ..crypto import Clock

MSG_INVESTIGATION_REPORT = "investigation_report"
MSG_ACTION_REQUEST = "action_request"
ALLOWED_MESSAGE_TYPES = frozenset({MSG_INVESTIGATION_REPORT, MSG_ACTION_REQUEST})


class AuditSink(Protocol):
    def append(self, entry_type: str, case_id: str, obj: Dict[str, Any], refs: Optional[Dict[str, str]] = None) -> Any: ...


class AuditUnavailable(Exception):
    """Raised by an audit sink that cannot persist (disk full, ledger domain down, ...)."""


@dataclass
class EgressConfig:
    max_msg_bytes: int = 32768
    max_per_minute: int = 30
    # Ablation only: when True the proxy forwards even if the audit write failed.
    fail_open_on_audit_error: bool = False


@dataclass
class EgressResult:
    ok: bool
    code: str  # OK | MALFORMED | REJECTED_BY_PROXY | RATE_LIMITED | AUDIT_UNAVAILABLE
    msg_type: Optional[str]
    msg_digest: Optional[str]
    agent_id: str
    size: int = 0


# ── 【老師註解】ControlledEgressProxy ─────────────────────────────
# 做什麼：沙箱唯一的出口。Agent 想對外說任何話（報告、動作請求）都必須經過這裡；它負責「先記帳、後放行」。
# 為什麼：論文假設 Agent 可能已被攻陷（assume breach）。既然攔不住它「想」做壞事，就要保證它每句話都
#         (a) 先留下不可抹去的紀錄、(b) 只能說有限幾種格式、(c) 說不快、說不大、(d) 冒充不了別人。
# 怎麼看：channel_agent_id 是「通道綁定」的身份——payload 裡自稱 agent_id 是誰都不算數，以通道為準。
#         dropped 清單記錄所有被丟棄的訊息，情境測試用它證明「審計掛了→什麼都沒出去」。
# 拿掉會怎樣：Agent 的請求直接到政策引擎，一旦審計域故障就出現「做了事卻沒紀錄」的盲區；
#         驗證器也無法證明「每個請求都來自受控通道」。
# 對應：準則 #2；測試 tests/test_egress_release_grant.py::test_egress_proxy_logs_before_forwarding_and_binds_identity
@dataclass
class ControlledEgressProxy:
    audit: AuditSink
    channel_agent_id: str
    clock: Clock
    config: EgressConfig = field(default_factory=EgressConfig)
    _times: List[datetime] = field(default_factory=list)
    dropped: List[EgressResult] = field(default_factory=list)

    def _log(self, entry_type: str, case_id: str, obj: Dict[str, Any], refs: Optional[Dict[str, str]] = None) -> bool:
        try:
            self.audit.append(entry_type, case_id, obj, refs)
            return True
        except Exception:  # any persistence failure is treated as "audit unavailable"
            return False

    # ── 【老師註解】ControlledEgressProxy.forward ─────────────────
    # 做什麼：五道關卡依序檢查一則訊息：規範化 → 類型/大小白名單 → 速率 → 寫審計 → 放行。任何一關失敗就回 ok=False。
    # 為什麼：順序很重要——「寫審計」是放行前的最後一步，所以「有出去的訊息一定有紀錄」永遠成立；
    #         反過來「有紀錄但沒出去」是可能的（例如寫完帳本後下游拒絕），這方向無害。
    # 怎麼看：回傳的 EgressResult.msg_digest 會被寫進帳本 refs，之後驗證器用它比對 action_request，
    #         證明「這個請求確實經過出口」。呼叫者（soc.py）必須尊重 ok，不能自己繞過。
    # 拿掉會怎樣：見消融情境「egress proxy fails open」——請求照樣出去，但 verify 會回 FAILED。
    # 對應：準則 #2；測試 tests/test_egress_release_grant.py::test_egress_proxy_fail_closed_vs_fail_open
    def forward(self, msg_type: str, payload: Dict[str, Any], case_id: str) -> EgressResult:
        """Audit then admit ``payload``. Returns a result; the caller must honour ``ok``."""
        try:
            raw = canonical_bytes(payload)  # 關卡 1：必須能規範化（不能有 NaN、非字串 key）
            size = len(raw)
            mdigest = digest(payload)
        except (TypeError, ValueError):
            res = EgressResult(False, "MALFORMED", None, None, self.channel_agent_id)
            self.dropped.append(res)
            return res

        if msg_type not in ALLOWED_MESSAGE_TYPES or size > self.config.max_msg_bytes:
            # 關卡 2：只放行白名單類型且不超過大小上限；被攻陷的 Agent 想塞 32 KB 以上的「資料」出去會被擋
            self._log("egress_dropped", case_id, {"reason": "type_or_size", "msg_type": msg_type, "size": size},
                      {"agent_id": self.channel_agent_id})
            res = EgressResult(False, "REJECTED_BY_PROXY", msg_type, mdigest, self.channel_agent_id, size)
            self.dropped.append(res)
            return res

        now = self.clock.now()
        self._times = [t for t in self._times if (now - t).total_seconds() < 60]
        if len(self._times) >= self.config.max_per_minute:
            # 關卡 3：每分鐘訊息數上限，限制被攻陷 Agent 的「吞吐量」
            self._log("egress_dropped", case_id, {"reason": "rate_limit", "msg_type": msg_type},
                      {"agent_id": self.channel_agent_id})
            res = EgressResult(False, "RATE_LIMITED", msg_type, mdigest, self.channel_agent_id, size)
            self.dropped.append(res)
            return res
        self._times.append(now)

        # Log first. The claimed identity inside the payload is irrelevant; the channel decides.
        # 關卡 4：先寫帳本（agent_egress），身份用通道綁定的 channel_agent_id，不看 payload 自稱
        logged = self._log("agent_egress", case_id, {"msg_type": msg_type, "msg_digest": mdigest, "size": size},
                           {"agent_id": self.channel_agent_id, "msg_digest": mdigest})
        if not logged and not self.config.fail_open_on_audit_error:
            # 關卡 5：帳本寫不進去 ⇒ 丟棄（fail-closed）。fail_open_on_audit_error 只給消融實驗用
            res = EgressResult(False, "AUDIT_UNAVAILABLE", msg_type, mdigest, self.channel_agent_id, size)
            self.dropped.append(res)
            return res
        return EgressResult(True, "OK", msg_type, mdigest, self.channel_agent_id, size)


class FailingAudit:
    """Test double: an audit sink whose writes fail (simulates the log domain being down)."""

    def __init__(self, inner: Optional[AuditSink] = None, fail: bool = True) -> None:
        self.inner = inner
        self.fail = fail
        self.attempts = 0

    def append(self, entry_type: str, case_id: str, obj: Dict[str, Any], refs: Optional[Dict[str, str]] = None) -> Any:
        self.attempts += 1
        if self.fail:
            raise AuditUnavailable("audit domain unreachable")
        if self.inner is not None:
            return self.inner.append(entry_type, case_id, obj, refs)
        return None
