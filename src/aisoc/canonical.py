"""JSON canonicalization (RFC 8785 subset) and digest helpers.

Only the subset of JCS needed for the SOC protocol objects is implemented:
objects with string keys, strings, booleans, null, integers and finite
floats. NaN / Infinity are rejected because JCS cannot represent them.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


class CanonicalizationError(ValueError):
    pass


# ── 【老師註解】_check ────────────────────────────────────────────
# 做什麼：在規範化之前先檢查資料「能不能被規範化」：只接受 None / bool / str / int / 有限 float / dict / list。
# 為什麼：簽名與哈希的前提是「同一份資料永遠產生同一串位元組」。NaN、Infinity 在 JSON 裡沒有標準寫法，
#         不同語言會印出不同字串，簽名就對不上，所以一律拒絕，而不是默默轉成 null。
# 拿掉會怎樣：Slips 缺失的流量統計若變成 NaN 混進來，驗證器算出的哈希會和簽名時不同 → 整條鏈「看起來」被竄改。
# 對應：準則 #7；測試 tests/test_canonical_crypto.py::test_canonical_rejects_nan_and_non_string_keys
def _check(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(f"{path}: non-finite float not allowed")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _check(v, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check(v, f"{path}[{i}]")
        return
    raise CanonicalizationError(f"{path}: unsupported type {type(value).__name__}")


def _normalize(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    return value


# ── 【老師註解】canonical_bytes ───────────────────────────────────
# 做什麼：把一個 Python dict/list 變成「唯一的」一串 UTF-8 位元組（RFC 8785 JCS 的子集）。
# 為什麼：{"a":1,"b":2} 和 {"b":2,"a":1} 在 Python 裡相等，但原始 JSON 字串不同；若直接對字串簽名，
#         換個欄位順序簽名就失效。所以先「排序 key、去掉空白、整數化 2.0 → 2」，再簽名／哈希。
# 怎麼看：sort_keys=True 排序、separators 去空白、ensure_ascii=False 保留中文、allow_nan=False 擋非法浮點。
# 拿掉會怎樣：同一筆決策在不同程式序列化後摘要不同，帳本和外部見證永遠對不上，驗證器形同虛設。
# 對應：準則 #7；測試 tests/test_canonical_crypto.py::test_canonical_is_key_sorted_and_compact
def canonical_bytes(value: Any) -> bytes:
    """Return the JCS-style canonical UTF-8 encoding of ``value``."""
    _check(value)
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── 【老師註解】digest ────────────────────────────────────────────
# 做什麼：對 canonical_bytes 的結果做 SHA-256，回傳 "sha256:<64 個十六進位字元>"。
# 為什麼：整個系統（帳本、PEP 的綁定檢查、Slips 證據、AiSOC bundle）都用這一個函數算「指紋」。
#         前面加 "sha256:" 是讓十年後的人一眼知道用了哪個演算法，可以安全升級到 sha3 而不混淆。
# 怎麼看：欄位名字叫 *_digest 的，例如 request_digest、params_digest、msg_digest，全部都是它算出來的。
# 對應：準則 #4、#7；測試 tests/test_canonical_crypto.py::test_digest_stable_across_ordering
def digest(value: Any) -> str:
    """sha256 over the canonical encoding, prefixed so the algorithm is explicit."""
    return "sha256:" + sha256_hex(canonical_bytes(value))
