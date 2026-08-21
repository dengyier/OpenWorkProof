"""Narrow GitHub Action helper for signed Surface Bundle generation."""

from __future__ import annotations

import argparse
from collections import ChainMap
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import get_args

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import rfc8785

from openworkproof.adapters.github_surface import (
    GitHubExecutionSourceV01,
    GitHubSurfaceError,
    project_github_environment,
)
from openworkproof.delivery_case import DeliveryCaseResultV01
from openworkproof.environment_fingerprint import sign_environment_fingerprint
from openworkproof.surface_bundle import (
    SurfaceBundleError,
    build_surface_bundle,
    verify_surface_bundle,
)
from openworkproof.verification_report import ReportReasonCode


_DIGEST64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_INPUT_FILE_BYTES = 8 * 1024 * 1024
_ARTIFACT_PATH = "openworkproof-evidence-bundle.tar.gz"
_REPORT_REASON_CODES = frozenset(get_args(ReportReasonCode))


class GitHubActionError(RuntimeError):
    """The Action helper cannot safely complete its bounded operation."""


def _read_regular(path: Path, *, max_bytes: int) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > max_bytes
        ):
            raise GitHubActionError("Action input must be a bounded regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
        )
        if identity != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise GitHubActionError("Action input changed before read")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) != opened.st_size or identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise GitHubActionError("Action input changed while read")
        return payload
    except GitHubActionError:
        raise
    except OSError as error:
        raise GitHubActionError("Action input cannot be read") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _digest_file(path: Path) -> str:
    return hashlib.sha256(
        _read_regular(path, max_bytes=_MAX_INPUT_FILE_BYTES)
    ).hexdigest()


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    payload = _read_regular(path, max_bytes=128)
    try:
        encoded = payload.decode("ascii").strip()
        if len(encoded) != 64 or encoded.lower() != encoded:
            raise ValueError
        raw = bytes.fromhex(encoded)
        if len(raw) != 32:
            raise ValueError
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise GitHubActionError(
            "collector key file must contain one lowercase Ed25519 seed"
        ) from error


def build_action_surface(
    delivery_package: Path,
    collector_key_file: Path,
    toolchain_lock_file: Path,
    sandbox_policy_file: Path,
    output: Path,
) -> dict[str, object]:
    expected_revision = os.environ.get("OWP_EXPECTED_SOURCE_REVISION")
    collector_actor = os.environ.get("OWP_COLLECTOR_ACTOR_ID")
    if not expected_revision or not collector_actor:
        raise GitHubActionError(
            "expected source revision and collector actor are required"
        )
    delivery_manifest = _read_regular(
        delivery_package / "manifest.json",
        max_bytes=_MAX_INPUT_FILE_BYTES,
    )
    command_digest = hashlib.sha256(
        rfc8785.dumps(["owp", "surface-verify"])
    ).hexdigest()
    arguments_digest = hashlib.sha256(
        rfc8785.dumps(
            {"delivery_manifest_digest": hashlib.sha256(delivery_manifest).hexdigest()}
        )
    ).hexdigest()
    overrides = {
        "OWP_TOOLCHAIN_LOCK_DIGEST": _digest_file(toolchain_lock_file),
        "OWP_SANDBOX_POLICY_DIGEST": _digest_file(sandbox_policy_file),
        "OWP_COMMAND_DIGEST": command_digest,
        "OWP_ARGUMENTS_DIGEST": arguments_digest,
        "OWP_COLLECTED_AT": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "OWP_COLLECTOR_ACTOR_ID": collector_actor,
    }
    source = GitHubExecutionSourceV01.from_environment(
        ChainMap(overrides, os.environ)
    )
    payload = project_github_environment(
        source,
        expected_revision=expected_revision,
    )
    private_key = _load_private_key(collector_key_file)
    fingerprint = sign_environment_fingerprint(payload, private_key)
    build_surface_bundle(delivery_package, (fingerprint,), output)
    verified = verify_surface_bundle(output)
    return {
        "decision_status": verified.report.decision_status,
        "reason_codes": list(verified.report.reason_codes),
        "bundle_digest": verified.report.bundle_digest,
    }


def _load_result(path: Path) -> dict[str, object]:
    payload = _read_regular(path, max_bytes=64 * 1024)
    try:
        result = json.loads(payload)
    except (UnicodeDecodeError, ValueError) as error:
        raise GitHubActionError("surface result is not valid JSON") from error
    if type(result) is not dict or set(result) != {
        "decision_status",
        "reason_codes",
        "bundle_digest",
    }:
        raise GitHubActionError("surface result envelope is not closed")
    status = result["decision_status"]
    reasons = result["reason_codes"]
    digest = result["bundle_digest"]
    if status not in {"VERIFIED", "REFUTED", "UNKNOWN"}:
        raise GitHubActionError("surface result status is invalid")
    if (
        type(reasons) is not list
        or len(reasons) > 16
        or any(
            type(reason) is not str or reason not in _REPORT_REASON_CODES
            for reason in reasons
        )
        or reasons
        != sorted(set(reasons), key=lambda value: value.encode("utf-8"))
    ):
        raise GitHubActionError("surface result reasons are invalid")
    if (
        (status == "VERIFIED" and reasons)
        or (status == "REFUTED" and "DELIVERY_REFUTED" not in reasons)
        or (status == "UNKNOWN" and not reasons)
        or (status != "REFUTED" and "DELIVERY_REFUTED" in reasons)
        or (status == "REFUTED" and "DELIVERY_UNKNOWN" in reasons)
    ):
        raise GitHubActionError("surface result status and reasons conflict")
    if type(digest) is not str or _DIGEST64.fullmatch(digest) is None:
        raise GitHubActionError("surface result digest is invalid")
    return result


def write_summary(result_path: Path, summary_path: Path, output_path: Path) -> None:
    result = _load_result(result_path)
    status = str(result["decision_status"])
    digest = str(result["bundle_digest"])
    reasons = result["reason_codes"]
    reason_text = ", ".join(str(reason) for reason in reasons) or "无"
    summary = (
        "# OpenWorkProof 验证摘要\n\n"
        "| 问题 | 结果 |\n|---|---|\n"
        "| 谁授权 | 已签交付包中的授权链；请下载后离线复核 |\n"
        "| Agent 做了什么 | 见交付包中的因果回执与证据索引 |\n"
        "| 谁验证 | 见已签环境指纹及受信 Verifier key binding |\n"
        f"| 当前能否验收 | **{status}** |\n\n"
        f"Reason codes: `{reason_text}`  \n"
        f"Bundle digest: `{digest}`\n\n"
        "边界：该结果不代表付款或人工验收；归档不是新的信任根。"
        "下载、解包后"
        "仍须运行 `owp surface-verify`。\n"
    )
    with summary_path.open("a", encoding="utf-8") as handle:
        handle.write(summary)
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write(f"decision={status}\n")
        handle.write(f"bundle_digest={digest}\n")
        handle.write(f"artifact_path={_ARTIFACT_PATH}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openworkproof-github-action")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--delivery-package", required=True)
    build.add_argument("--collector-key-file", required=True)
    build.add_argument("--toolchain-lock-file", required=True)
    build.add_argument("--sandbox-policy-file", required=True)
    build.add_argument("--output", required=True)
    summary = commands.add_parser("write-summary")
    summary.add_argument("result")
    summary.add_argument("summary")
    summary.add_argument("outputs")
    delivery_case = commands.add_parser("write-delivery-case-summary")
    delivery_case.add_argument("result")
    delivery_case.add_argument("summary")
    delivery_case.add_argument("outputs")
    return parser


_DELIVERY_CASE_ARTIFACT_PATH = "delivery-case-export"


def _load_delivery_case_result(payload: bytes) -> DeliveryCaseResultV01 | dict:
    try:
        return DeliveryCaseResultV01.model_validate_json(payload)
    except Exception:
        try:
            raw = json.loads(payload)
        except Exception as error:
            raise GitHubActionError(
                "delivery case result is not valid JSON"
            ) from error
        if (
            type(raw) is not dict
            or raw.get("schema_version")
            != "openworkproof-delivery-case-result/0.1"
            or raw.get("case_stage") is not None
            or raw.get("reason_codes") != ["OPERATIONAL_ERROR"]
            or raw.get("boundary")
            != "not payment, completed settlement, legal audit, or customer adoption"
        ):
            raise GitHubActionError("delivery case result is invalid")
        return raw


def write_delivery_case_summary(
    result_path: Path, summary_path: Path, output_path: Path
) -> None:
    payload = _read_regular(result_path, max_bytes=64 * 1024)
    result = _load_delivery_case_result(payload)
    if isinstance(result, DeliveryCaseResultV01):
        case_id = result.case_id
        case_stage = str(result.case_stage)
        reasons = ", ".join(result.reason_codes) or "—"
        boundary = str(result.boundary)
    else:
        case_id = ""
        case_stage = ""
        reasons = "OPERATIONAL_ERROR"
        boundary = "not payment, completed settlement, legal audit, or customer adoption"
    summary = (
        "# OpenWorkProof Verified Agent Delivery\n\n"
        f"- Case id: `{(case_id or '—')[:12]}`\n"
        f"- Case stage: `{case_stage or '—'}`\n"
        f"- Reason codes: `{reasons}`\n\n"
        f"Boundary: {boundary}\n"
    )
    with summary_path.open("a", encoding="utf-8") as handle:
        handle.write(summary)
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write(f"case_stage={case_stage}\n")
        handle.write(f"case_id={case_id}\n")
        handle.write(f"artifact_path={_DELIVERY_CASE_ARTIFACT_PATH}\n")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            result = build_action_surface(
                Path(args.delivery_package),
                Path(args.collector_key_file),
                Path(args.toolchain_lock_file),
                Path(args.sandbox_policy_file),
                Path(args.output),
            )
            print(json.dumps(result, sort_keys=True))
        elif args.command == "write-delivery-case-summary":
            write_delivery_case_summary(
                Path(args.result), Path(args.summary), Path(args.outputs)
            )
        else:
            write_summary(
                Path(args.result), Path(args.summary), Path(args.outputs)
            )
    except (GitHubActionError, GitHubSurfaceError, SurfaceBundleError) as error:
        print(f"OpenWorkProof GitHub Action error: {error}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
