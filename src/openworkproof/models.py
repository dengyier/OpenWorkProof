"""Closed, immutable protocol models for OpenWorkProof v0.1."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Annotated, Any, ClassVar, Literal, get_args

import rfc8785
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_serializer,
    model_validator,
)
from pydantic_core import core_schema


MAX_SAFE_INTEGER = 9_007_199_254_740_991
BUNDLE_FINALIZATION_GRACE_SECONDS = 3600
MAX_PATCH_BYTES = 65_536
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_TOTAL_DECLARED_EVIDENCE_BYTES = 16 * 1024 * 1024

_LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_LOWER_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{64}$")
_UTC_SECONDS = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})Z$"
)
_ROOT_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

_ALL_TOOLS = frozenset(
    {
        "owp.activate_root_grant",
        "owp.apply_patch",
        "owp.compose_proof",
        "owp.create_pr_proposal",
        "owp.delegate_grant",
        "owp.repo_read",
        "owp.request_acceptance",
        "owp.request_pr_proposal",
        "owp.revoke_grant",
        "owp.rollback_patch",
        "owp.run_tests",
        "owp.start_retry",
    }
)
_MANAGER_DIRECT_TOOLS = frozenset(
    {
        "owp.activate_root_grant",
        "owp.compose_proof",
        "owp.create_pr_proposal",
        "owp.delegate_grant",
        "owp.request_acceptance",
        "owp.request_pr_proposal",
        "owp.revoke_grant",
        "owp.start_retry",
    }
)
_DELEGABLE_CHILD_TOOLS = frozenset(
    {
        "owp.apply_patch",
        "owp.repo_read",
        "owp.rollback_patch",
        "owp.run_tests",
    }
)
_PREDICATE_TOOLS = frozenset(
    {
        "owp.repo_read",
        "owp.apply_patch",
        "owp.run_tests",
        "owp.create_pr_proposal",
        "owp.compose_proof",
    }
)
_VERIFIER_ARGV = (
    "/opt/venv/bin/python",
    "-I",
    "-m",
    "pytest",
    "-q",
    "-c",
    "/dev/null",
    "--rootdir=/fixed-tests",
    "--confcutdir=/fixed-tests",
    "/fixed-tests/verifier_test.py",
)
_FIXED_ENV = {
    "HOME": "/nonexistent",
    "LC_ALL": "C.UTF-8",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    "TZ": "UTC",
}
_EVIDENCE_DIMENSIONS = (
    "authority",
    "scope",
    "execution",
    "result",
    "independent_result",
)
_KEY_ROLES = (
    "Maintainer",
    "Manager",
    "Developer",
    "Verifier",
    "Sidecar",
    "Acceptor",
)
_PURPOSE_ORDER = {
    "patch_input": 0,
    "patch_result": 1,
    "patch_denial_audit": 2,
    "developer_test_result": 3,
    "verifier_result": 4,
    "verifier_independent_result": 5,
}
_PURPOSE_BINDINGS = {
    "patch_input": ("text/x-diff", "scope"),
    "patch_result": ("application/json", "execution"),
    "patch_denial_audit": ("text/x-diff", "none"),
    "developer_test_result": ("application/json", "execution"),
    "verifier_result": ("application/json", "result"),
    "verifier_independent_result": ("application/json", "independent_result"),
}
_RESERVED_EVIDENCE_ROOTS = frozenset(
    {
        ".pending",
        "evidence",
        "manifest.json",
        "manifest.sig",
        "keys",
        "protocol",
        "source",
        "fixed-tests",
        "schemas",
    }
)


def _require_exact_int(value: Any, *, positive: bool) -> int:
    if type(value) is not int:
        raise ValueError("value must be a strict JSON integer")
    minimum = 1 if positive else 0
    if not minimum <= value <= MAX_SAFE_INTEGER:
        raise ValueError(f"value must be in {minimum}..{MAX_SAFE_INTEGER}")
    return value


SafeNonNegativeInt = Annotated[
    int, BeforeValidator(lambda value: _require_exact_int(value, positive=False))
]
SafePositiveInt = Annotated[
    int, BeforeValidator(lambda value: _require_exact_int(value, positive=True))
]


def _parse_canonical_time(value: Any) -> datetime:
    if type(value) is not str:
        raise ValueError("timestamp must be a canonical RFC 3339 string")
    match = _UTC_SECONDS.fullmatch(value)
    if match is None:
        raise ValueError("timestamp must use YYYY-MM-DDTHH:MM:SSZ")
    year, month, day, hour, minute, second = map(int, match.groups())
    if second > 59:
        raise ValueError("leap seconds are not permitted")
    try:
        parsed = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError as error:
        raise ValueError("timestamp is not a valid UTC second") from error
    if parsed < datetime(1970, 1, 1, tzinfo=timezone.utc):
        raise ValueError("timestamp precedes the Unix epoch")
    return parsed


def _serialize_canonical_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


CanonicalUTCTime = Annotated[
    datetime,
    BeforeValidator(_parse_canonical_time),
    PlainSerializer(_serialize_canonical_time, return_type=str),
]


def _strict_text(value: Any, *, max_bytes: int, field_name: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{field_name} must be a strict string")
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > max_bytes:
        raise ValueError(f"{field_name} must contain 1..{max_bytes} UTF-8 bytes")
    return value


def _identifier(value: Any) -> str:
    return _strict_text(value, max_bytes=128, field_name="identifier")


def _ordinary_string(value: Any) -> str:
    return _strict_text(value, max_bytes=4096, field_name="string")


def _digest64(value: Any) -> str:
    if type(value) is not str or _LOWER_HEX_64.fullmatch(value) is None:
        raise ValueError("digest must be 64 lowercase hexadecimal characters")
    return value


def _oid40(value: Any) -> str:
    if type(value) is not str or _LOWER_HEX_40.fullmatch(value) is None:
        raise ValueError("object id must be 40 lowercase hexadecimal characters")
    return value


def _image_digest(value: Any) -> str:
    if type(value) is not str or _IMAGE_DIGEST.fullmatch(value) is None:
        raise ValueError("image digest must use sha256:<64 lowercase hex>")
    return value


def _key_id(value: Any) -> str:
    if type(value) is not str or _KEY_ID.fullmatch(value) is None:
        raise ValueError("key id must use ed25519:<64 lowercase hex>")
    return value


Identifier = Annotated[str, BeforeValidator(_identifier)]
ProtocolString = Annotated[str, BeforeValidator(_ordinary_string)]
Digest64 = Annotated[str, BeforeValidator(_digest64)]
ObjectId40 = Annotated[str, BeforeValidator(_oid40)]
ImageDigest = Annotated[str, BeforeValidator(_image_digest)]
KeyId = Annotated[str, BeforeValidator(_key_id)]


def _strict_bounded_text(max_bytes: int, field_name: str):
    return BeforeValidator(
        lambda value: _strict_text(
            value, max_bytes=max_bytes, field_name=field_name
        )
    )


class FrozenDict(Mapping[str, Any]):
    """A JSON-object mapping that cannot be changed after validation."""

    __slots__ = ("_data",)

    def __init__(self, value: Mapping[str, Any]) -> None:
        frozen = _freeze_json(dict(value), freeze_mapping=False)
        object.__setattr__(self, "_data", MappingProxyType(frozen))

    def __setattr__(self, name: str, value: Any) -> None:
        del name, value
        raise TypeError("FrozenDict is immutable")

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"FrozenDict({self._data!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return dict(self.items()) == dict(other.items())
        return False

    def __deepcopy__(self, memo: dict[int, Any]) -> FrozenDict:
        return self

    @classmethod
    def _from_frozen(cls, value: dict[str, Any]) -> FrozenDict:
        instance = object.__new__(cls)
        object.__setattr__(instance, "_data", MappingProxyType(value))
        return instance

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: Any
    ) -> core_schema.CoreSchema:
        del source_type, handler
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda value: _jsonable(value),
                info_arg=False,
                return_schema=core_schema.dict_schema(),
                when_used="json",
            ),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, schema: core_schema.CoreSchema, handler: Any
    ) -> dict[str, Any]:
        del cls, schema, handler
        return {"type": "object", "additionalProperties": True}

    @classmethod
    def _validate(cls, value: Any) -> FrozenDict:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ValueError("value must be a JSON object")
        return cls(value)


def _freeze_json(
    value: Any,
    depth: int = 1,
    *,
    freeze_mapping: bool = True,
    max_array_items: int = 64,
) -> Any:
    if depth > 16:
        raise ValueError("JSON nesting depth exceeds 16")
    if isinstance(value, BaseModel):
        raise ValueError("nested BaseModel values are not strict JSON")
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise ValueError("JSON map exceeds 64 entries")
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON map keys must be strings")
            if len(key.encode("utf-8")) > 4096:
                raise ValueError("JSON map key exceeds 4096 UTF-8 bytes")
            frozen[key] = _freeze_json(
                item, depth + 1, max_array_items=max_array_items
            )
        return FrozenDict._from_frozen(frozen) if freeze_mapping else frozen
    if isinstance(value, (list, tuple)):
        if len(value) > max_array_items:
            raise ValueError(f"JSON array exceeds {max_array_items} items")
        return tuple(
            _freeze_json(item, depth + 1, max_array_items=max_array_items)
            for item in value
        )
    if type(value) is str:
        if len(value.encode("utf-8")) > 4096:
            raise ValueError("JSON string exceeds 4096 UTF-8 bytes")
        return value
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        return _require_exact_int(value, positive=False)
    raise ValueError("unsupported or non-strict JSON scalar")


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, datetime):
        return _serialize_canonical_time(value)
    return value


def _jcs_digest(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(_jsonable(value))).hexdigest()


def _decode_unpadded_base64url(value: Any, expected_bytes: int) -> bytes:
    if type(value) is not str or not value or "=" in value:
        raise ValueError("value must be unpadded base64url")
    if _BASE64URL.fullmatch(value) is None:
        raise ValueError("value must contain only base64url characters")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise ValueError("value is not valid base64url") from error
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if canonical != value or len(raw) != expected_bytes:
        raise ValueError(f"value must canonically encode {expected_bytes} bytes")
    return raw


def _signature(value: Any) -> str:
    _decode_unpadded_base64url(value, 64)
    return value


Signature = Annotated[str, BeforeValidator(_signature)]


def _public_key_b64url(value: Any) -> str:
    _decode_unpadded_base64url(value, 32)
    return value


PublicKeyB64Url = Annotated[str, BeforeValidator(_public_key_b64url)]


def _is_utf8_sorted_unique(values: tuple[str, ...]) -> bool:
    return list(values) == sorted(set(values), key=lambda item: item.encode("utf-8"))


def _validate_root(value: str) -> str:
    if type(value) is not str:
        raise ValueError("root must be a strict string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("root must be ASCII") from error
    if not encoded or len(encoded) > 512:
        raise ValueError("root must contain 1..512 ASCII bytes")
    if (
        value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(token in value for token in ("*", "?", "[", "]"))
        or _ROOT_PATH.fullmatch(value) is None
    ):
        raise ValueError("root is not a canonical relative POSIX path")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ValueError("root contains a forbidden segment")
    if segments[0] == ".git":
        raise ValueError(".git is a protected root")
    return value


CanonicalRoot = Annotated[str, BeforeValidator(_validate_root)]


def _validate_scope_locator(value: Any) -> str:
    if type(value) is not str:
        raise ValueError("scope locator must be a strict string")
    if not value or len(value.encode("utf-8")) > 4096:
        raise ValueError("scope locator must contain 1..4096 UTF-8 bytes")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("scope locator must be NFC-normalized")
    if "\\" in value or "\x00" in value or any(
        unicodedata.category(character) == "Cc" for character in value
    ):
        raise ValueError("scope locator contains a forbidden character")

    root, separator, node_suffix = value.partition("::")
    _validate_root(root)
    if not separator:
        return value
    if not node_suffix or node_suffix.startswith(":") or node_suffix.endswith(":"):
        raise ValueError("test-case locator requires a pytest node suffix")
    if any(part in {"", ".", ".."} for part in node_suffix.split("::")):
        raise ValueError("test-case locator contains a forbidden node segment")
    return value


ScopeLocator = Annotated[str, BeforeValidator(_validate_scope_locator)]


def _validate_sorted_roots(values: tuple[str, ...], *, allow_empty: bool) -> None:
    if not allow_empty and not values:
        raise ValueError("at least one root is required")
    if not _is_utf8_sorted_unique(values):
        raise ValueError("roots must be UTF-8 sorted and unique")


def _root_covers(parent: str, child: str) -> bool:
    return child == parent or child.startswith(parent + "/")


def _write_roots_within_read(
    read_roots: tuple[str, ...], write_roots: tuple[str, ...]
) -> bool:
    return all(
        any(_root_covers(read_root, write_root) for read_root in read_roots)
        for write_root in write_roots
    )


def _validate_tools(values: tuple[str, ...], *, allow_empty: bool = False) -> None:
    if not allow_empty and not values:
        raise ValueError("at least one tool is required")
    if not _is_utf8_sorted_unique(values):
        raise ValueError("tools must be UTF-8 sorted and unique")
    if any(value not in _ALL_TOOLS for value in values):
        raise ValueError("unknown tool")


class ProtocolModel(BaseModel):
    """Base for all closed and immutable v0.1 protocol shapes."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_assignment=True,
    )

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ValueError("protocol object must be a JSON object")
        return _freeze_json(dict(value), freeze_mapping=False)


class SignedProtocolModel(ProtocolModel):
    _signed_domain: ClassVar[str | None] = None
    _signed_version: ClassVar[str] = "0.1"

    digest: Digest64
    signature_alg: Literal["Ed25519"]
    signer_key_id: KeyId
    signature: Signature

    @model_validator(mode="after")
    def _validate_signed_digest(self) -> SignedProtocolModel:
        if self._signed_domain is None:
            return self
        payload = self.model_dump(
            mode="json",
            exclude={"digest", "signature"},
        )
        expected = _jcs_digest(
            {
                "domain": (
                    f"openworkproof/{self._signed_domain}/v"
                    f"{self._signed_version}"
                ),
                "payload": payload,
            }
        )
        if self.digest != expected:
            raise ValueError("digest does not match canonical signed payload")
        return self


class Quota(ProtocolModel):
    tool_calls: SafeNonNegativeInt
    repair_rounds: SafeNonNegativeInt


class ApprovalGate(ProtocolModel):
    gate_id: Digest64
    tool_name: Literal["owp.create_pr_proposal"]
    required_role: Literal["Maintainer"]
    max_validity_seconds: SafePositiveInt
    scope_schema: Literal["openworkproof/pr-proposal-scope/0.1"]

    @model_validator(mode="after")
    def _validate_gate(self) -> ApprovalGate:
        if self.max_validity_seconds > 3600:
            raise ValueError("gate validity must not exceed 3600 seconds")
        expected = _jcs_digest(
            {
                "domain": "openworkproof/approval-gate-id/v0.1",
                "tool_name": self.tool_name,
                "required_role": self.required_role,
                "max_validity_seconds": self.max_validity_seconds,
                "scope_schema": self.scope_schema,
            }
        )
        if self.gate_id != expected:
            raise ValueError("gate_id does not match the canonical gate")
        return self


class PredicateSpec(ProtocolModel):
    predicate_id: Digest64
    name: Literal[
        "path_allowed",
        "tool_allowed",
        "quota_remaining",
        "tests_passed",
        "artifact_digest_matches",
        "human_signature_present",
    ]
    version: Literal["0.1"]
    applies_to_tools: tuple[str, ...]
    arguments: FrozenDict

    @classmethod
    def from_parts(
        cls,
        *,
        name: str,
        version: str,
        applies_to_tools: tuple[str, ...],
        arguments: Mapping[str, Any],
    ) -> PredicateSpec:
        tools = tuple(
            sorted(set(applies_to_tools), key=lambda value: value.encode("utf-8"))
        )
        frozen_arguments = FrozenDict(arguments)
        predicate_id = _jcs_digest(
            {
                "domain": "openworkproof/predicate-id/v0.1",
                "name": name,
                "version": version,
                "applies_to_tools": tools,
                "arguments": frozen_arguments,
            }
        )
        return cls.model_validate(
            {
                "predicate_id": predicate_id,
                "name": name,
                "version": version,
                "applies_to_tools": tools,
                "arguments": frozen_arguments,
            }
        )

    @model_validator(mode="after")
    def _validate_frozen_registry(self) -> PredicateSpec:
        tools = self.applies_to_tools
        if not _is_utf8_sorted_unique(tools):
            raise ValueError("predicate tools must be sorted and unique")
        if any(value not in _PREDICATE_TOOLS for value in tools):
            raise ValueError("predicate references an unsupported tool")
        if self.name == "human_signature_present":
            if tools:
                raise ValueError(
                    "human signature predicate cannot apply to tools"
                )
        elif not tools:
            raise ValueError("tool predicate must apply to at least one tool")

        arguments = self.arguments
        argument_keys = {
            "path_allowed": frozenset({"allowed_roots"}),
            "tool_allowed": frozenset({"allowed_tools", "tool_name"}),
            "quota_remaining": frozenset({"metric", "amount"}),
            "tests_passed": frozenset(
                {
                    "test_mode",
                    "command_digest",
                    "expected_exit_code",
                    "fixed_test_source_digest",
                }
            ),
            "artifact_digest_matches": frozenset(
                {"artifact_path", "expected_digest"}
            ),
            "human_signature_present": frozenset({"required_role"}),
        }
        if set(arguments) != argument_keys[self.name]:
            raise ValueError("predicate arguments do not match the registry")

        if self.name == "path_allowed":
            allowed_roots = arguments["allowed_roots"]
            if (
                type(allowed_roots) is not tuple
                or not 1 <= len(allowed_roots) <= 32
                or any(type(root) is not str for root in allowed_roots)
            ):
                raise ValueError("allowed_roots must contain 1..32 roots")
            for root in allowed_roots:
                _validate_root(root)
            _validate_sorted_roots(allowed_roots, allow_empty=False)
        elif self.name == "tool_allowed":
            allowed_tools = arguments["allowed_tools"]
            tool_name = arguments["tool_name"]
            if (
                type(allowed_tools) is not tuple
                or not allowed_tools
                or any(type(tool) is not str for tool in allowed_tools)
                or not _is_utf8_sorted_unique(allowed_tools)
                or any(tool not in _PREDICATE_TOOLS for tool in allowed_tools)
            ):
                raise ValueError(
                    "allowed_tools must be a non-empty canonical tool array"
                )
            if (
                type(tool_name) is not str
                or tool_name not in _PREDICATE_TOOLS
                or tool_name not in allowed_tools
            ):
                raise ValueError("tool_name must name an allowed predicate tool")
        elif self.name == "quota_remaining":
            metric = arguments["metric"]
            if (
                type(metric) is not str
                or metric not in {"tool_calls", "repair_rounds"}
            ):
                raise ValueError("quota metric is not registered")
            _require_exact_int(arguments["amount"], positive=True)
        elif self.name == "tests_passed":
            if arguments["test_mode"] != "verifier":
                raise ValueError("tests_passed requires verifier mode")
            _digest64(arguments["command_digest"])
            _digest64(arguments["fixed_test_source_digest"])
            expected_exit_code = _require_exact_int(
                arguments["expected_exit_code"],
                positive=False,
            )
            if expected_exit_code > 255:
                raise ValueError("expected_exit_code must be in 0..255")
        elif self.name == "artifact_digest_matches":
            _validate_root(arguments["artifact_path"])
            _digest64(arguments["expected_digest"])
        elif arguments["required_role"] != "Maintainer":
            raise ValueError(
                "human signature predicate requires the Maintainer role"
            )

        expected = _jcs_digest(
            {
                "domain": "openworkproof/predicate-id/v0.1",
                "name": self.name,
                "version": self.version,
                "applies_to_tools": self.applies_to_tools,
                "arguments": self.arguments,
            }
        )
        if self.predicate_id != expected:
            raise ValueError("predicate_id does not match predicate fields")
        return self


class ResolvedPathEntry(ProtocolModel):
    requested_path: CanonicalRoot
    resolved_relative_path: CanonicalRoot | None


class PathAllowedPredicateInput(ProtocolModel):
    requested_paths: tuple[CanonicalRoot, ...]
    resolved_entries: tuple[ResolvedPathEntry, ...]
    resolution_manifest_digest: Digest64 | None

    @model_validator(mode="after")
    def _validate_paths(self) -> PathAllowedPredicateInput:
        if (
            not self.requested_paths
            or len(self.requested_paths) > 32
            or not _is_utf8_sorted_unique(self.requested_paths)
            or len(self.resolved_entries) != len(self.requested_paths)
            or tuple(entry.requested_path for entry in self.resolved_entries)
            != self.requested_paths
        ):
            raise ValueError("path predicate vectors are not aligned/canonical")
        if self.resolution_manifest_digest is None and any(
            entry.resolved_relative_path is not None
            for entry in self.resolved_entries
        ):
            raise ValueError("resolved paths require a resolution manifest")
        return self


class ToolAllowedPredicateInput(ProtocolModel):
    actual_tool_name: Literal[
        "owp.repo_read",
        "owp.apply_patch",
        "owp.run_tests",
        "owp.create_pr_proposal",
        "owp.compose_proof",
    ]


class QuotaRemainingPredicateInput(ProtocolModel):
    grant_id: Digest64
    metric: Literal["tool_calls", "repair_rounds"]
    amount: SafePositiveInt
    grant_remaining_before: SafeNonNegativeInt
    ledger_prefix_digest: Digest64


class TestsPassedPredicateInput(ProtocolModel):
    test_mode: Literal["verifier"]
    command_digest: Digest64
    expected_exit_code: SafeNonNegativeInt
    actual_exit_code: SafeNonNegativeInt | None
    test_evidence_digest: Digest64 | None
    source_commit: ObjectId40
    candidate_commit: ObjectId40
    workspace_manifest_digest: Digest64
    container_image_digest: ImageDigest
    fixed_test_source_digest: Digest64

    @model_validator(mode="after")
    def _validate_exit(self) -> TestsPassedPredicateInput:
        if self.expected_exit_code > 255 or (
            self.actual_exit_code is not None and self.actual_exit_code > 255
        ):
            raise ValueError("test exit code must be in 0..255")
        if (self.actual_exit_code is None) != (self.test_evidence_digest is None):
            raise ValueError("test exit and evidence digest nullability must match")
        return self


class ArtifactDigestPredicateInput(ProtocolModel):
    artifact_path: CanonicalRoot
    expected_digest: Digest64
    actual_digest: Digest64 | None
    size_bytes: SafeNonNegativeInt | None
    workspace_manifest_digest: Digest64 | None

    @model_validator(mode="after")
    def _validate_actual(self) -> ArtifactDigestPredicateInput:
        present = (
            self.actual_digest is not None,
            self.size_bytes is not None,
            self.workspace_manifest_digest is not None,
        )
        if len(set(present)) != 1:
            raise ValueError("artifact actual fields must be all-null or all-present")
        return self


class HumanSignaturePredicateInput(ProtocolModel):
    decision_type: Literal[
        "approval_decision", "termination_decision", "final_acceptance"
    ]
    required_role: Literal["Maintainer"]
    actor_key_id: KeyId
    claim_digest: Digest64
    decision: Literal["approved", "denied", "rejected", "accepted"]
    expires_at: CanonicalUTCTime | None
    validated_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_expiry(self) -> HumanSignaturePredicateInput:
        if (self.decision_type == "termination_decision") != (
            self.expires_at is None
        ):
            raise ValueError("human-signature expiry does not match decision type")
        return self


PredicateInput = (
    PathAllowedPredicateInput
    | ToolAllowedPredicateInput
    | QuotaRemainingPredicateInput
    | TestsPassedPredicateInput
    | ArtifactDigestPredicateInput
    | HumanSignaturePredicateInput
)


class PredicateResult(ProtocolModel):
    predicate_id: Digest64
    name: Literal[
        "path_allowed",
        "tool_allowed",
        "quota_remaining",
        "tests_passed",
        "artifact_digest_matches",
        "human_signature_present",
    ]
    version: Identifier
    arguments_digest: Digest64
    input: PredicateInput
    input_digest: Digest64
    passed: bool
    error_code: Literal["PREDICATE_FALSE", "FAIL_CLOSED"] | None

    @model_validator(mode="after")
    def _validate_result(self) -> PredicateResult:
        expected_types = {
            "path_allowed": PathAllowedPredicateInput,
            "tool_allowed": ToolAllowedPredicateInput,
            "quota_remaining": QuotaRemainingPredicateInput,
            "tests_passed": TestsPassedPredicateInput,
            "artifact_digest_matches": ArtifactDigestPredicateInput,
            "human_signature_present": HumanSignaturePredicateInput,
        }
        if not isinstance(self.input, expected_types[self.name]):
            raise ValueError("predicate input does not match predicate name")
        expected = _jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": self.predicate_id,
                "input": self.input,
            }
        )
        if self.input_digest != expected:
            raise ValueError("input_digest does not match predicate input")
        if self.passed != (self.error_code is None):
            raise ValueError("passed and error_code are inconsistent")
        return self

    def matches_spec(self, spec: PredicateSpec) -> bool:
        return (
            self.predicate_id == spec.predicate_id
            and self.name == spec.name
            and self.version == spec.version
            and self.arguments_digest == _jcs_digest(spec.arguments)
        )

    def validate_against(self, spec: PredicateSpec) -> PredicateResult:
        if not self.matches_spec(spec):
            raise ValueError("PredicateResult does not match PredicateSpec")
        return self


class KeyBinding(ProtocolModel):
    role: Literal[
        "Maintainer",
        "Manager",
        "Developer",
        "Verifier",
        "Sidecar",
        "Acceptor",
    ]
    subject_id: Identifier
    key_id: KeyId
    public_key_b64url: str

    @model_validator(mode="after")
    def _validate_binding(self) -> KeyBinding:
        raw = _decode_unpadded_base64url(self.public_key_b64url, 32)
        expected = f"ed25519:{hashlib.sha256(raw).hexdigest()}"
        if self.key_id != expected:
            raise ValueError("key_id does not match the public key")
        return self


class SourceArtifact(ProtocolModel):
    path: Literal["source/base.owpsrc"]
    media_type: Literal["application/vnd.openworkproof.source+zip"]
    sha256: Digest64
    size_bytes: SafePositiveInt

    @model_validator(mode="after")
    def _validate_size(self) -> SourceArtifact:
        if self.size_bytes > MAX_ARTIFACT_BYTES:
            raise ValueError("source artifact exceeds 8 MiB")
        return self


class ReplayProfile(ProtocolModel):
    schema_version: Literal["openworkproof-replay-profile/0.1"]
    patch_profile_id: Literal["openworkproof/canonical-text-patch/0.1"]
    object_format: Literal["sha1"]
    source_artifact_sha256: Digest64
    trusted_helper_image_digest: ImageDigest
    author_name: Literal["OpenWorkProof Sidecar"]
    author_email: Literal["sidecar@openworkproof.invalid"]
    commit_message_prefix: Literal["OpenWorkProof patch "]
    timestamp_rule: Literal["receipt-occurred-at-utc-seconds"]
    worktree_profile: Literal["linux-posix-case-sensitive-v0.1"]


class Command(ProtocolModel):
    argv: tuple[str, ...]
    working_directory: Literal["/workspace"]
    env: FrozenDict

    @model_validator(mode="after")
    def _validate_command(self) -> Command:
        if not 1 <= len(self.argv) <= 16:
            raise ValueError("argv must contain 1..16 items")
        for argument in self.argv:
            _strict_text(argument, max_bytes=256, field_name="argv item")
        if not self.argv[0].startswith("/"):
            raise ValueError("argv[0] must be an absolute executable path")
        executable_name = self.argv[0].rsplit("/", 1)[-1]
        if executable_name in {
            "sh",
            "bash",
            "zsh",
            "dash",
            "ksh",
            "fish",
            "csh",
            "tcsh",
            "env",
        }:
            raise ValueError("shell and PATH-dispatch executables are forbidden")
        if self.env != _FIXED_ENV:
            raise ValueError("command environment is not the fixed v0.1 environment")
        return self


class FixedTestSource(ProtocolModel):
    path: Literal["fixed-tests/verifier_test.py"]
    media_type: Literal["text/x-python"]
    sha256: Digest64
    size_bytes: SafePositiveInt

    @model_validator(mode="after")
    def _validate_size(self) -> FixedTestSource:
        if self.size_bytes > 65_536:
            raise ValueError("fixed test source exceeds 64 KiB")
        return self


def validate_fixed_test_source_bytes(
    source: FixedTestSource, content: bytes
) -> FixedTestSource:
    if type(content) is not bytes:
        raise ValueError("fixed test content must be exact bytes")
    if len(content) > 65_536:
        raise ValueError("fixed test content exceeds 64 KiB")
    if len(content) != source.size_bytes:
        raise ValueError("fixed test content size does not match metadata")
    if hashlib.sha256(content).hexdigest() != source.sha256:
        raise ValueError("fixed test content SHA-256 does not match metadata")
    if content.startswith(b"\xef\xbb\xbf"):
        raise ValueError("fixed test content must not contain a UTF-8 BOM")
    if b"\x00" in content:
        raise ValueError("fixed test content must not contain NUL")
    if b"\r" in content:
        raise ValueError("fixed test content must not contain CR")
    if not content.endswith(b"\n"):
        raise ValueError("fixed test content must end with LF")
    return source


class TestProfile(ProtocolModel):
    test_mode: Literal["developer", "verifier"]
    command: Command
    command_digest: Digest64
    expected_exit_code: SafeNonNegativeInt
    container_image_digest: ImageDigest
    fixed_test_source: FixedTestSource | None
    fixed_test_source_digest: Digest64 | None

    @model_validator(mode="after")
    def _validate_profile(self) -> TestProfile:
        if self.expected_exit_code > 255:
            raise ValueError("expected_exit_code must be in 0..255")
        expected_command_digest = _jcs_digest(
            {
                "domain": "openworkproof/test-command/v0.1",
                "command": self.command,
            }
        )
        if self.command_digest != expected_command_digest:
            raise ValueError("command_digest does not match command")
        if self.test_mode == "developer":
            if (
                self.fixed_test_source is not None
                or self.fixed_test_source_digest is not None
            ):
                raise ValueError("developer fixed test fields must both be null")
        else:
            if self.command.argv != _VERIFIER_ARGV:
                raise ValueError("verifier argv is not the fixed v0.1 command")
            if self.fixed_test_source is None:
                raise ValueError("verifier fixed_test_source is required")
            if self.fixed_test_source_digest != self.fixed_test_source.sha256:
                raise ValueError("fixed test source digest does not match source")
        return self


class Artifact(ProtocolModel):
    name: Identifier
    path: str
    media_type: Literal["text/x-diff", "application/json"]
    max_size_bytes: SafePositiveInt
    evidence_dimension: Literal[
        "none", "scope", "execution", "result", "independent_result"
    ]
    purpose: Literal[
        "patch_input",
        "patch_result",
        "patch_denial_audit",
        "developer_test_result",
        "verifier_result",
        "verifier_independent_result",
    ]
    ordinal: SafePositiveInt

    @model_validator(mode="after")
    def _validate_artifact(self) -> Artifact:
        try:
            encoded = self.path.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("artifact path must be ASCII") from error
        if (
            not encoded
            or len(encoded) > 503
            or len(b"evidence/" + encoded) > 512
            or self.path.startswith("/")
            or self.path.endswith("/")
            or "\\" in self.path
            or any(token in self.path for token in ("*", "?", "[", "]"))
        ):
            raise ValueError("artifact path is not canonical")
        segments = self.path.split("/")
        if any(segment in {"", ".", ".."} for segment in segments):
            raise ValueError("artifact path contains a forbidden segment")
        if segments[0] in _RESERVED_EVIDENCE_ROOTS:
            raise ValueError("artifact path collides with a reserved root")
        expected_media, expected_dimension = _PURPOSE_BINDINGS[self.purpose]
        if (self.media_type, self.evidence_dimension) != (
            expected_media,
            expected_dimension,
        ):
            raise ValueError("artifact purpose/media/dimension binding is invalid")
        if self.max_size_bytes > MAX_ARTIFACT_BYTES:
            raise ValueError("artifact maximum exceeds 8 MiB")
        if (
            self.purpose in {"patch_input", "patch_denial_audit"}
            and self.max_size_bytes > MAX_PATCH_BYTES
        ):
            raise ValueError("patch evidence maximum exceeds 64 KiB")
        return self


class EvidencePolicy(ProtocolModel):
    evidence_root: Literal["evidence"]
    redaction_policy_id: Literal["owp-public-evidence-v0.1"]
    artifacts: tuple[Artifact, ...]

    @model_validator(mode="after")
    def _validate_inventory(self) -> EvidencePolicy:
        artifacts = self.artifacts
        names = [item.name for item in artifacts]
        paths = [item.path for item in artifacts]
        purpose_ordinals = [(item.purpose, item.ordinal) for item in artifacts]
        if len(names) != len(set(names)):
            raise ValueError("artifact names must be unique")
        if len(paths) != len(set(paths)):
            raise ValueError("artifact paths must be unique")
        if len(purpose_ordinals) != len(set(purpose_ordinals)):
            raise ValueError("artifact purpose/ordinal pairs must be unique")
        order = [(_PURPOSE_ORDER[item.purpose], item.ordinal) for item in artifacts]
        if order != sorted(order):
            raise ValueError("artifact inventory is not purpose/ordinal sorted")

        by_purpose: dict[str, list[int]] = {
            purpose: [] for purpose in _PURPOSE_ORDER
        }
        for artifact in artifacts:
            by_purpose[artifact.purpose].append(artifact.ordinal)
        for ordinals in by_purpose.values():
            if ordinals and ordinals != list(range(1, len(ordinals) + 1)):
                raise ValueError("artifact ordinals must be contiguous from one")

        patch_inputs = by_purpose["patch_input"]
        patch_results = by_purpose["patch_result"]
        denials = by_purpose["patch_denial_audit"]
        developer = by_purpose["developer_test_result"]
        verifier = by_purpose["verifier_result"]
        independent = by_purpose["verifier_independent_result"]
        if not 1 <= len(patch_inputs) <= 4 or patch_inputs != patch_results:
            raise ValueError("patch input/result inventories must pair 1..4 ordinals")
        if denials != [1, 2]:
            raise ValueError("exactly two denial audit slots are required")
        if len(developer) > 4:
            raise ValueError("developer result inventory exceeds four")
        if not 1 <= len(verifier) <= 4:
            raise ValueError("verifier result inventory must contain 1..4 slots")
        if len(independent) > 1:
            raise ValueError("independent result inventory exceeds one")
        expected_range = (6, 19) if independent else (5, 18)
        if not expected_range[0] <= len(artifacts) <= expected_range[1]:
            raise ValueError("artifact inventory count is invalid")
        if sum(item.max_size_bytes for item in artifacts) > (
            MAX_TOTAL_DECLARED_EVIDENCE_BYTES
        ):
            raise ValueError("declared evidence exceeds 16 MiB")
        return self


class RootGrantTemplate(ProtocolModel):
    grant_id: Digest64
    parent_grant_id: None
    issuer_key_id: KeyId
    subject_agent_id: Identifier
    subject_key_id: KeyId
    allowed_tools: tuple[str, ...]
    allowed_read_roots: tuple[CanonicalRoot, ...]
    allowed_write_roots: tuple[CanonicalRoot, ...]
    usage_mode: Literal["single_use", "metered"]
    quota: Quota
    valid_from: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    may_delegate: bool
    issued_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_root_template(self) -> RootGrantTemplate:
        _validate_tools(self.allowed_tools)
        _validate_sorted_roots(self.allowed_read_roots, allow_empty=False)
        _validate_sorted_roots(self.allowed_write_roots, allow_empty=True)
        if not _write_roots_within_read(
            self.allowed_read_roots, self.allowed_write_roots
        ):
            raise ValueError("write roots are not contained in read roots")
        if self.usage_mode != "metered":
            raise ValueError("root grant must use metered usage")
        if self.quota.tool_calls == 0 or self.quota.repair_rounds not in {0, 1}:
            raise ValueError("root grant quota is structurally invalid")
        if self.may_delegate is not True:
            raise ValueError("root grant must permit delegation")
        if not self.issued_at <= self.valid_from < self.expires_at:
            raise ValueError("root grant times are not ordered")
        return self


class CapabilityGrant(SignedProtocolModel):
    grant_id: Digest64
    work_order_digest: Digest64
    parent_grant_id: Digest64 | None
    issuer_key_id: KeyId
    subject_agent_id: Identifier
    subject_key_id: KeyId
    allowed_tools: tuple[str, ...]
    allowed_read_roots: tuple[CanonicalRoot, ...]
    allowed_write_roots: tuple[CanonicalRoot, ...]
    usage_mode: Literal["single_use", "metered"]
    quota: Quota
    valid_from: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    may_delegate: bool
    issued_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_grant(self) -> CapabilityGrant:
        _validate_tools(self.allowed_tools)
        _validate_sorted_roots(self.allowed_read_roots, allow_empty=False)
        _validate_sorted_roots(self.allowed_write_roots, allow_empty=True)
        if not _write_roots_within_read(
            self.allowed_read_roots, self.allowed_write_roots
        ):
            raise ValueError("write roots are not contained in read roots")
        if self.signer_key_id != self.issuer_key_id:
            raise ValueError("grant signer must equal grant issuer")
        if not self.issued_at <= self.valid_from < self.expires_at:
            raise ValueError("grant times are not ordered")
        if self.quota.tool_calls == 0:
            raise ValueError("grant tool_calls must be positive")
        if self.parent_grant_id is None:
            if (
                self.usage_mode != "metered"
                or self.may_delegate is not True
                or self.quota.repair_rounds not in {0, 1}
            ):
                raise ValueError("root grant structure is invalid")
        elif self.may_delegate is not False or self.quota.repair_rounds != 0:
            raise ValueError("child grant structure is invalid")
        return self


class WorkOrder(SignedProtocolModel):
    work_order_id: Digest64
    protocol_version: Literal["0.1"]
    issuer_id: Identifier
    acceptor_key_ids: tuple[KeyId, ...]
    objective: Annotated[str, _strict_bounded_text(4096, "objective")]
    preconditions: tuple[PredicateSpec, ...]
    invariants: tuple[PredicateSpec, ...]
    repository: Annotated[str, _strict_bounded_text(1024, "repository")]
    branch: Annotated[str, _strict_bounded_text(255, "branch")]
    allowed_read_roots: tuple[CanonicalRoot, ...]
    allowed_write_roots: tuple[CanonicalRoot, ...]
    source_commit: ObjectId40
    source_artifact: SourceArtifact
    patch_profile_id: Literal["openworkproof/canonical-text-patch/0.1"]
    replay_profile: ReplayProfile
    replay_profile_digest: Digest64
    test_profiles: tuple[TestProfile, ...]
    allowed_tools: tuple[str, ...]
    quota_ceiling: Quota
    deadline: CanonicalUTCTime
    retention_until: CanonicalUTCTime
    acceptance_criteria: Annotated[
        str, _strict_bounded_text(4096, "acceptance_criteria")
    ]
    postconditions: tuple[PredicateSpec, ...]
    approval_gates: tuple[ApprovalGate, ...]
    required_evidence_dimensions: tuple[
        Literal[
            "authority", "scope", "execution", "result", "independent_result"
        ],
        ...,
    ]
    independence_policy: Literal[
        "disclose_only", "independent_test_source_required"
    ]
    evidence_policy: EvidencePolicy
    root_grant_template: RootGrantTemplate
    key_bindings: tuple[KeyBinding, ...]
    issued_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_work_order(self) -> WorkOrder:
        if not self.issued_at < self.deadline:
            raise ValueError("WorkOrder issued_at must precede deadline")
        if self.deadline + timedelta(
            seconds=BUNDLE_FINALIZATION_GRACE_SECONDS
        ) > self.retention_until:
            raise ValueError("retention does not include finalization grace")

        _validate_tools(self.allowed_tools)
        _validate_sorted_roots(self.allowed_read_roots, allow_empty=False)
        _validate_sorted_roots(self.allowed_write_roots, allow_empty=True)
        if not _write_roots_within_read(
            self.allowed_read_roots, self.allowed_write_roots
        ):
            raise ValueError("WorkOrder write roots are not contained in read roots")

        if (
            self.replay_profile.source_artifact_sha256
            != self.source_artifact.sha256
        ):
            raise ValueError("replay profile is not bound to source artifact")
        expected_replay_digest = _jcs_digest(
            {
                "domain": "openworkproof/replay-profile/v0.1",
                "profile": self.replay_profile,
            }
        )
        if self.replay_profile_digest != expected_replay_digest:
            raise ValueError("replay_profile_digest does not match profile")

        if not 1 <= len(self.test_profiles) <= 2:
            raise ValueError("one verifier and at most one developer profile required")
        modes = tuple(profile.test_mode for profile in self.test_profiles)
        if modes not in {("verifier",), ("developer", "verifier")}:
            raise ValueError("test profiles must be ordered developer, verifier")
        verifier_profile = next(
            profile
            for profile in self.test_profiles
            if profile.test_mode == "verifier"
        )
        has_developer_profile = any(
            profile.test_mode == "developer" for profile in self.test_profiles
        )

        self._validate_conditions(verifier_profile)

        if len(self.approval_gates) != 1:
            raise ValueError("exactly one PR proposal approval gate is required")
        if self.required_evidence_dimensions not in {
            _EVIDENCE_DIMENSIONS[:4],
            _EVIDENCE_DIMENSIONS,
        }:
            raise ValueError("evidence dimensions are incomplete or out of order")
        has_independent_dimension = (
            "independent_result" in self.required_evidence_dimensions
        )
        expected_policy = (
            "independent_test_source_required"
            if has_independent_dimension
            else "disclose_only"
        )
        if self.independence_policy != expected_policy:
            raise ValueError("independence policy does not match dimensions")
        independent_slots = sum(
            artifact.purpose == "verifier_independent_result"
            for artifact in self.evidence_policy.artifacts
        )
        if independent_slots != int(has_independent_dimension):
            raise ValueError("independent evidence inventory does not match policy")
        developer_slots = sum(
            artifact.purpose == "developer_test_result"
            for artifact in self.evidence_policy.artifacts
        )
        if has_developer_profile != (developer_slots > 0):
            raise ValueError(
                "developer profile and developer evidence inventory must coexist"
            )

        roles = tuple(binding.role for binding in self.key_bindings)
        if roles != _KEY_ROLES:
            raise ValueError("key bindings must use the fixed role order")
        subject_ids = tuple(binding.subject_id for binding in self.key_bindings)
        key_ids = tuple(binding.key_id for binding in self.key_bindings)
        if (
            len(set(subject_ids)) != 6
            or len(set(key_ids)) != 6
        ):
            raise ValueError("key binding subjects and keys must be unique")
        maintainer, manager, _, _, _, acceptor = self.key_bindings
        if (
            self.issuer_id != maintainer.subject_id
            or self.signer_key_id != maintainer.key_id
            or self.acceptor_key_ids != (acceptor.key_id,)
        ):
            raise ValueError(
                "Maintainer must issue/sign and Acceptor must accept"
            )

        template = self.root_grant_template
        if (
            template.issuer_key_id != maintainer.key_id
            or template.subject_agent_id != manager.subject_id
            or template.subject_key_id != manager.key_id
            or template.issued_at != self.issued_at
            or template.expires_at != self.deadline
        ):
            raise ValueError("root grant template identity/time binding is invalid")
        if not set(template.allowed_tools).issubset(self.allowed_tools):
            raise ValueError("root template tools exceed WorkOrder tools")
        required_root_tools = _MANAGER_DIRECT_TOOLS | (
            set(self.allowed_tools) & _DELEGABLE_CHILD_TOOLS
        )
        if not required_root_tools.issubset(template.allowed_tools):
            raise ValueError("root template omits required Manager or child tools")
        if not all(
            any(_root_covers(parent, child) for parent in self.allowed_read_roots)
            for child in template.allowed_read_roots
        ):
            raise ValueError("root template read roots exceed WorkOrder roots")
        if not all(
            any(_root_covers(parent, child) for parent in self.allowed_write_roots)
            for child in template.allowed_write_roots
        ):
            raise ValueError("root template write roots exceed WorkOrder roots")
        if (
            template.quota.tool_calls > self.quota_ceiling.tool_calls
            or template.quota.repair_rounds > self.quota_ceiling.repair_rounds
        ):
            raise ValueError("root template quota exceeds WorkOrder ceiling")
        return self

    def _validate_conditions(self, verifier_profile: TestProfile) -> None:
        partitions = (
            ("preconditions", self.preconditions, {"path_allowed", "tool_allowed", "quota_remaining"}),
            ("invariants", self.invariants, {"path_allowed", "tool_allowed"}),
            ("postconditions", self.postconditions, {"tests_passed", "artifact_digest_matches"}),
        )
        all_ids: list[str] = []
        for name, conditions, allowed_names in partitions:
            if len(conditions) > 32:
                raise ValueError(f"{name} exceeds 32 predicates")
            ids = [condition.predicate_id for condition in conditions]
            if ids != sorted(ids):
                raise ValueError(f"{name} is not predicate_id sorted")
            if any(condition.name not in allowed_names for condition in conditions):
                raise ValueError(f"{name} contains a predicate in the wrong phase")
            for condition in conditions:
                if not set(condition.applies_to_tools).intersection(
                    self.allowed_tools
                ):
                    raise ValueError("predicate does not apply to an allowed tool")
            all_ids.extend(ids)
        if len(all_ids) != len(set(all_ids)):
            raise ValueError("predicate ids must be globally unique")
        all_conditions = self.preconditions + self.invariants + self.postconditions
        for tool_name in _PREDICATE_TOOLS:
            applicable_ids = {
                condition.predicate_id
                for condition in all_conditions
                if tool_name in condition.applies_to_tools
            }
            if len(applicable_ids) > 64:
                raise ValueError("applicable predicate union exceeds 64")

        for condition in self.preconditions + self.invariants:
            if condition.name == "path_allowed" and not set(
                condition.applies_to_tools
            ).issubset({"owp.repo_read", "owp.apply_patch"}):
                raise ValueError("path_allowed references a tool without path projection")
        for condition in self.postconditions:
            if condition.applies_to_tools != ("owp.run_tests",):
                raise ValueError("postconditions are verifier run_tests only")
        tests_passed = [
            condition
            for condition in self.postconditions
            if condition.name == "tests_passed"
        ]
        if len(tests_passed) != 1:
            raise ValueError("exactly one tests_passed postcondition is required")
        expected_arguments = {
            "test_mode": "verifier",
            "command_digest": verifier_profile.command_digest,
            "expected_exit_code": verifier_profile.expected_exit_code,
            "fixed_test_source_digest": verifier_profile.fixed_test_source_digest,
        }
        if tests_passed[0].arguments != expected_arguments:
            raise ValueError("tests_passed does not match verifier profile")


class SubjectClaim(SignedProtocolModel):
    _signed_domain = "subject-claim"

    schema_version: Literal["openworkproof-subject-claim/0.1"]
    claim_id: Digest64
    work_order_digest: Digest64
    claim_statement: Annotated[
        str, _strict_bounded_text(4096, "claim_statement")
    ]
    delivery_target: Annotated[
        str, _strict_bounded_text(1024, "delivery_target")
    ]
    source_revision: ObjectId40
    acceptance_conditions: tuple[Identifier, ...]
    excluded_scope: tuple[Identifier, ...]
    required_artifacts: tuple[CanonicalRoot, ...]
    customer_acceptor_key_id: KeyId
    created_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _closed_claim(self) -> SubjectClaim:
        for values, label in (
            (self.acceptance_conditions, "acceptance_conditions"),
            (self.excluded_scope, "excluded_scope"),
            (self.required_artifacts, "required_artifacts"),
        ):
            if not values or values != tuple(sorted(set(values))):
                raise ValueError(f"{label} must be non-empty sorted and unique")
        return self


class PolicyAnchor(ProtocolModel):
    schema_version: Literal["openworkproof-policy-anchor/0.1"]
    policy_registry_uri: Annotated[
        str, _strict_bounded_text(2048, "policy_registry_uri")
    ]
    policy_version: Identifier
    policy_digest: Digest64
    effective_at: CanonicalUTCTime
    resolved_at: CanonicalUTCTime
    resolver_identity: Identifier

    @model_validator(mode="after")
    def _ordered_times(self) -> PolicyAnchor:
        if self.resolved_at < self.effective_at:
            raise ValueError("policy anchor times are not ordered")
        return self


class CommitmentAnchor(ProtocolModel):
    schema_version: Literal["openworkproof-commitment-anchor/0.1"]
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    anchored_at: CanonicalUTCTime
    anchor_provider: Literal[
        "git_commit",
        "git_tag",
        "github_release",
        "customer_signed_document",
        "enterprise_timestamp",
    ]
    anchor_reference: Annotated[
        str, _strict_bounded_text(2048, "anchor_reference")
    ]


ScopeMemberKind = Literal["source_file", "test_case", "delivery_artifact"]
ScopeSelectorKind = Literal["explicit", "git_diff_closure", "pytest_collection"]
ScopeRequirementKind = Literal["acceptance_condition", "required_artifact"]


class ScopeMember(ProtocolModel):
    member_id: Digest64
    member_kind: ScopeMemberKind
    locator: ScopeLocator
    locator_digest: Digest64
    content_digest: Digest64
    source_revision: ObjectId40

    @model_validator(mode="after")
    def _closed_member(self) -> ScopeMember:
        is_test_locator = "::" in self.locator
        if (self.member_kind == "test_case") != is_test_locator:
            raise ValueError("locator form does not match member_kind")
        expected_locator_digest = hashlib.sha256(
            self.locator.encode("utf-8")
        ).hexdigest()
        if self.locator_digest != expected_locator_digest:
            raise ValueError("locator_digest does not match locator")
        expected_member_id = _jcs_digest(
            {
                "domain": "openworkproof/scope-member/v0.3",
                "payload": {
                    "member_kind": self.member_kind,
                    "locator": self.locator,
                },
            }
        )
        if self.member_id != expected_member_id:
            raise ValueError("member_id does not match canonical identity")
        return self


class ScopeSelectorRule(ProtocolModel):
    rule_id: Digest64
    selector_kind: ScopeSelectorKind
    selector_spec_digest: Digest64
    selector_engine_digest: Digest64
    required_evidence_paths: tuple[CanonicalRoot, ...]

    @model_validator(mode="after")
    def _closed_selector(self) -> ScopeSelectorRule:
        if not self.required_evidence_paths or not _is_utf8_sorted_unique(
            self.required_evidence_paths
        ):
            raise ValueError(
                "required_evidence_paths must be non-empty UTF-8 sorted and unique"
            )
        return self


class ScopeRequirementBinding(ProtocolModel):
    requirement_kind: ScopeRequirementKind
    requirement_digest: Digest64
    member_ids: tuple[Digest64, ...]

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ValueError("protocol object must be a JSON object")
        return _freeze_json(
            dict(value), freeze_mapping=False, max_array_items=4096
        )

    @model_validator(mode="after")
    def _closed_binding(self) -> ScopeRequirementBinding:
        if not self.member_ids or not _is_utf8_sorted_unique(self.member_ids):
            raise ValueError("member_ids must be non-empty sorted and unique")
        return self


def _validate_evaluation_scope(value: Any) -> None:
    if not 1 <= len(value.members) <= 4096:
        raise ValueError("members must contain 1..4096 items")
    if value.member_count != len(value.members):
        raise ValueError("member_count does not match members")
    if not value.created_at < value.expires_at:
        raise ValueError("scope manifest times are not ordered")

    member_sort_keys = tuple(
        (member.member_kind, member.locator_digest, member.member_id)
        for member in value.members
    )
    if member_sort_keys != tuple(sorted(set(member_sort_keys))):
        raise ValueError("members must be sorted and unique")
    if not any(
        member.member_kind in {"source_file", "test_case"}
        for member in value.members
    ):
        raise ValueError("scope requires a source_file or test_case member")
    if any(member.source_revision != value.source_revision for member in value.members):
        raise ValueError("member source_revision does not match manifest")

    folded_locators = tuple(member.locator.casefold() for member in value.members)
    if len(set(folded_locators)) != len(folded_locators):
        raise ValueError("member locators contain a case-fold collision")

    selector_keys = tuple(
        (rule.selector_kind.encode("utf-8"), rule.rule_id)
        for rule in value.selector_rules
    )
    if not selector_keys or selector_keys != tuple(sorted(set(selector_keys))):
        raise ValueError("selector_rules must be non-empty sorted and unique")

    population = [
        {
            "member_id": member.member_id,
            "member_kind": member.member_kind,
            "locator_digest": member.locator_digest,
        }
        for member in value.members
    ]
    expected_population_digest = _jcs_digest(
        {
            "domain": "openworkproof/scope-population/v0.3",
            "payload": population,
        }
    )
    if value.population_digest != expected_population_digest:
        raise ValueError("population_digest does not match members")

    binding_keys = tuple(
        (binding.requirement_kind.encode("utf-8"), binding.requirement_digest)
        for binding in value.requirement_bindings
    )
    if not binding_keys or binding_keys != tuple(sorted(set(binding_keys))):
        raise ValueError("requirement_bindings must be non-empty sorted and unique")

    members_by_id = {member.member_id: member for member in value.members}
    population_ids = set(members_by_id)
    bound_ids = {
        member_id
        for binding in value.requirement_bindings
        for member_id in binding.member_ids
    }
    if not bound_ids.issubset(population_ids):
        raise ValueError("requirement binding references a non-member")
    if any(
        binding.requirement_kind == "required_artifact"
        and any(
            members_by_id[member_id].member_kind == "test_case"
            for member_id in binding.member_ids
        )
        for binding in value.requirement_bindings
    ):
        raise ValueError("required_artifact cannot bind a test_case")
    if (
        not value.required_target_ids
        or not _is_utf8_sorted_unique(value.required_target_ids)
        or set(value.required_target_ids) != bound_ids
    ):
        raise ValueError(
            "required_target_ids must equal the sorted binding-member union"
        )

    if not _is_utf8_sorted_unique(value.excluded_locator_digests):
        raise ValueError("excluded_locator_digests must be sorted and unique")
    member_locator_digests = {member.locator_digest for member in value.members}
    if member_locator_digests.intersection(value.excluded_locator_digests):
        raise ValueError("excluded locator cannot also be a scope member")

    identity = value.model_dump(
        mode="json",
        exclude={
            "scope_id",
            "digest",
            "signature_alg",
            "signer_key_id",
            "signature",
        },
    )
    expected_scope_id = _jcs_digest(
        {
            "domain": "openworkproof/evaluation-scope/v0.3",
            "payload": identity,
        }
    )
    if value.scope_id != expected_scope_id:
        raise ValueError("scope_id does not match canonical scope payload")

    canonical_size = len(
        rfc8785.dumps(
            {
                "domain": "openworkproof/evaluation-scope/v0.3",
                "payload": value.model_dump(mode="json"),
            }
        )
    )
    if canonical_size > MAX_ARTIFACT_BYTES:
        raise ValueError("evaluation scope canonical payload exceeds 8 MiB")


def _freeze_evaluation_scope_payload(value: Any) -> Any:
    if not isinstance(value, Mapping):
        raise ValueError("protocol object must be a JSON object")
    members = value.get("members")
    if isinstance(members, (list, tuple)) and not 1 <= len(members) <= 4096:
        raise ValueError("members must contain 1..4096 items")
    return _freeze_json(
        dict(value), freeze_mapping=False, max_array_items=4096
    )


class EvaluationScopeDraft(ProtocolModel):
    schema_version: Literal["openworkproof-evaluation-scope/0.3"]
    scope_id: Digest64
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    source_revision: ObjectId40
    candidate_commit: ObjectId40
    selector_rules: tuple[ScopeSelectorRule, ...]
    members: tuple[ScopeMember, ...]
    member_count: SafePositiveInt
    population_digest: Digest64
    requirement_bindings: tuple[ScopeRequirementBinding, ...]
    required_target_ids: tuple[Digest64, ...]
    excluded_locator_digests: tuple[Digest64, ...]
    workspace_manifest_digest: Digest64
    freshness_mode: Literal["immutable_git_revision"]
    created_at: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        if isinstance(value, cls):
            return value
        return _freeze_evaluation_scope_payload(value)

    @model_validator(mode="after")
    def _closed_scope(self) -> EvaluationScopeDraft:
        _validate_evaluation_scope(self)
        return self


class EvaluationScopeManifest(SignedProtocolModel):
    _signed_domain = "evaluation-scope"
    _signed_version = "0.3"

    schema_version: Literal["openworkproof-evaluation-scope/0.3"]
    scope_id: Digest64
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    source_revision: ObjectId40
    candidate_commit: ObjectId40
    selector_rules: tuple[ScopeSelectorRule, ...]
    members: tuple[ScopeMember, ...]
    member_count: SafePositiveInt
    population_digest: Digest64
    requirement_bindings: tuple[ScopeRequirementBinding, ...]
    required_target_ids: tuple[Digest64, ...]
    excluded_locator_digests: tuple[Digest64, ...]
    workspace_manifest_digest: Digest64
    freshness_mode: Literal["immutable_git_revision"]
    created_at: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        if isinstance(value, cls):
            return value
        return _freeze_evaluation_scope_payload(value)

    @model_validator(mode="after")
    def _closed_scope(self) -> EvaluationScopeManifest:
        _validate_evaluation_scope(self)
        return self


class VerificationArm(ProtocolModel):
    arm_id: Digest64
    arm_kind: Literal["positive", "negative"]
    source_commit: ObjectId40
    candidate_commit: ObjectId40
    mutant_patch_digest: Digest64 | None
    workspace_manifest_digest: Digest64
    command_digest: Digest64
    container_image_digest: ImageDigest
    fixed_test_source_digest: Digest64
    expected_exit_codes: tuple[SafeNonNegativeInt, ...]
    expected_outcome: Literal["pass", "fail"]
    required_evidence_purposes: tuple[Identifier, ...]
    result_artifact_paths: tuple[CanonicalRoot, ...]

    @model_validator(mode="after")
    def _closed_arm(self) -> VerificationArm:
        if (self.arm_kind == "positive") != (self.mutant_patch_digest is None):
            raise ValueError("positive arm forbids and negative arm requires mutant")
        for values, label in (
            (self.expected_exit_codes, "expected_exit_codes"),
            (self.required_evidence_purposes, "required_evidence_purposes"),
            (self.result_artifact_paths, "result_artifact_paths"),
        ):
            if not values or values != tuple(sorted(set(values))):
                raise ValueError(f"{label} must be non-empty sorted and unique")
        return self


class VerifierBinding(ProtocolModel):
    binding_id: Digest64
    verifier_subject_id: Identifier
    verifier_key_id: KeyId
    verifier_public_key_b64url: PublicKeyB64Url
    controller_factors: tuple[Identifier, ...]
    execution_context_factors: tuple[Identifier, ...]
    valid_from: CanonicalUTCTime
    expires_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _closed_binding(self) -> VerifierBinding:
        raw = _decode_unpadded_base64url(self.verifier_public_key_b64url, 32)
        if self.verifier_key_id != f"ed25519:{hashlib.sha256(raw).hexdigest()}":
            raise ValueError("verifier key id does not match public key")
        for values, label in (
            (self.controller_factors, "controller_factors"),
            (self.execution_context_factors, "execution_context_factors"),
        ):
            if not values or values != tuple(sorted(set(values))):
                raise ValueError(f"{label} must be non-empty sorted and unique")
        if not self.valid_from < self.expires_at:
            raise ValueError("verifier binding times are not ordered")
        return self


class VerificationProfileV02(SignedProtocolModel):
    _signed_domain = "verification-profile"

    schema_version: Literal["openworkproof-verification-profile/0.2"]
    profile_id: Digest64
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    delivery_trust_level: Literal[1, 2, 3]
    policy_anchor_digest: Digest64 | None
    commitment_anchor_digest: Digest64 | None
    subject_kind: Literal["tests_passed"]
    assurance_level: Literal["standard", "high_risk"]
    verifier_bindings: tuple[VerifierBinding, ...]
    positive_arm: VerificationArm
    negative_arms: tuple[VerificationArm, ...]
    max_evidence_bytes: SafePositiveInt
    max_output_bytes: SafePositiveInt
    created_at: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _closed_profile(self) -> VerificationProfileV02:
        if not self.created_at < self.expires_at:
            raise ValueError("profile times are not ordered")
        if self.delivery_trust_level in {2, 3} and (
            self.commitment_anchor_digest is None
        ):
            raise ValueError("commitment_anchor_digest is required for level 2/3")
        if self.delivery_trust_level == 3 and self.assurance_level != "high_risk":
            raise ValueError("level 3 requires high_risk assurance")

        expected_bindings = 2 if self.assurance_level == "high_risk" else 1
        if len(self.verifier_bindings) != expected_bindings:
            label = "two distinct" if expected_bindings == 2 else "one"
            raise ValueError(f"{label} verifier bindings required")
        binding_ids = tuple(binding.binding_id for binding in self.verifier_bindings)
        if binding_ids != tuple(sorted(set(binding_ids))):
            raise ValueError("verifier bindings must be sorted and unique")
        if expected_bindings == 2:
            for values in (
                {binding.verifier_subject_id for binding in self.verifier_bindings},
                {binding.verifier_key_id for binding in self.verifier_bindings},
                {binding.controller_factors for binding in self.verifier_bindings},
                {
                    binding.execution_context_factors
                    for binding in self.verifier_bindings
                },
            ):
                if len(values) != 2:
                    raise ValueError("two distinct verifier bindings required")

        if self.positive_arm.arm_kind != "positive":
            raise ValueError("positive_arm must be positive")
        if not self.negative_arms:
            raise ValueError("at least one negative arm is required")
        negative_ids = tuple(arm.arm_id for arm in self.negative_arms)
        if negative_ids != tuple(sorted(set(negative_ids))):
            raise ValueError("negative arms must be sorted and unique")
        if self.positive_arm.arm_id in set(negative_ids) or any(
            arm.arm_kind != "negative" for arm in self.negative_arms
        ):
            raise ValueError("profile arm kinds or ids are invalid")
        mutant_digests = tuple(arm.mutant_patch_digest for arm in self.negative_arms)
        if len(set(mutant_digests)) != len(mutant_digests):
            raise ValueError("negative arm mutants must be unique")
        frozen_inputs = (
            "source_commit",
            "candidate_commit",
            "workspace_manifest_digest",
            "command_digest",
            "container_image_digest",
            "fixed_test_source_digest",
        )
        if any(
            any(
                getattr(arm, field) != getattr(self.positive_arm, field)
                for field in frozen_inputs
            )
            for arm in self.negative_arms
        ):
            raise ValueError("negative arms must share the pinned positive inputs")
        return self


class VerificationProfileV03(VerificationProfileV02):
    _signed_version = "0.3"

    schema_version: Literal["openworkproof-verification-profile/0.3"]
    evaluation_scope_id: Digest64
    evaluation_scope_digest: Digest64
    scope_requirement: Literal["exact_match"]


class EvidenceRef(ProtocolModel):
    path: CanonicalRoot
    sha256: Digest64
    media_type: Literal["text/x-diff", "application/json"]
    size_bytes: SafePositiveInt

    @model_validator(mode="after")
    def _validate_size(self) -> EvidenceRef:
        if self.size_bytes > MAX_ARTIFACT_BYTES:
            raise ValueError("evidence reference exceeds 8 MiB")
        return self


VerificationReasonCode = Literal[
    "AUTH_SIGNATURE_INVALID",
    "AUTH_GRANT_EXPIRED",
    "AUTH_GRANT_REVOKED",
    "AUTH_ROLE_MISMATCH",
    "AUTH_CAPABILITY_MISSING",
    "AUTH_NONCE_REUSED",
    "AUTH_SUBJECT_MISMATCH",
    "AUTH_POLICY_ANCHOR_UNAVAILABLE",
    "EXEC_COMMAND_FAILED",
    "EXEC_TIMEOUT",
    "EXEC_CRASHED",
    "EXEC_RESOURCE_EXHAUSTED",
    "EXEC_OUTPUT_LIMIT",
    "EXEC_WORKSPACE_DRIFT",
    "EXEC_DEPENDENCY_DRIFT",
    "MUTATION_APPLIED",
    "MUTATION_NOT_APPLIED",
    "MUTATION_SURVIVED",
    "MUTATION_CAUGHT",
    "MUTATION_TARGET_MISMATCH",
    "MUTATION_CLASSIFIER_UNAVAILABLE",
    "EVIDENCE_MISSING",
    "EVIDENCE_DIGEST_MISMATCH",
    "EVIDENCE_SIGNATURE_INVALID",
    "EVIDENCE_CAUSAL_PARENT_MISSING",
    "EVIDENCE_SIZE_LIMIT_EXCEEDED",
    "EVIDENCE_PUBLICATION_INCOMPLETE",
    "EVIDENCE_BUNDLE_REPLAY_FAILED",
    "INDEPENDENCE_KEY_REUSED",
    "INDEPENDENCE_DOMAIN_OVERLAP",
    "INDEPENDENCE_BUILD_NOT_DISTINCT",
    "INDEPENDENCE_CONTEXT_REUSED",
    "INDEPENDENCE_INSUFFICIENT",
    "INDEPENDENCE_UNPROVEN",
    "ACCEPTANCE_DIGEST_MISMATCH",
    "ACCEPTANCE_ACTOR_UNAUTHORIZED",
    "ACCEPTANCE_ALREADY_TERMINAL",
    "ACCEPTANCE_PREDECESSOR_STALE",
    "ACCEPTANCE_WITHDRAWN",
    "ACCEPTANCE_SUPERSEDED",
    "ACCEPTANCE_TRANSITION_INVALID",
]

VerificationReasonCodeV03 = VerificationReasonCode | Literal[
    "SCOPE_MANIFEST_INVALID",
    "SCOPE_MANIFEST_UNAVAILABLE",
    "SCOPE_EMPTY",
    "SCOPE_SELECTOR_MISMATCH",
    "SCOPE_REQUIRED_TARGET_MISSING",
    "SCOPE_WORKSPACE_DRIFT",
    "SCOPE_POPULATION_DRIFT",
    "SCOPE_EVIDENCE_MISSING",
    "SCOPE_CROSS_ARM_MISMATCH",
    "SCOPE_UNPROVEN",
]


class VerificationArmResult(SignedProtocolModel):
    _signed_domain = "verification-arm-result"

    schema_version: Literal["openworkproof-verification-arm-result/0.2"]
    arm_result_id: Digest64
    profile_digest: Digest64
    arm_id: Digest64
    arm_kind: Literal["positive", "negative"]
    mutation_status: Literal["not_applicable", "applied", "not_applied"]
    execution_status: Literal[
        "completed",
        "timed_out",
        "crashed",
        "resource_exhausted",
        "evidence_unavailable",
    ]
    expectation_status: Literal["satisfied", "contradicted", "indeterminate"]
    reason_codes: tuple[VerificationReasonCode, ...]
    action_receipt_ids: tuple[Digest64, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    verifier_subject_id: Identifier
    verifier_key_id: KeyId
    verifier_build_digest: Digest64
    dependency_lock_digest: Digest64
    controller_factors: tuple[Identifier, ...]
    execution_context_factors: tuple[Identifier, ...]
    created_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _closed_result(self) -> VerificationArmResult:
        if self.signer_key_id != self.verifier_key_id:
            raise ValueError("arm result signer must equal verifier key")
        if self.arm_kind == "positive":
            if self.mutation_status != "not_applicable":
                raise ValueError("positive arm cannot apply a mutant")
        elif self.mutation_status == "not_applicable":
            raise ValueError("negative arm must report mutation status")

        if self.mutation_status == "not_applied" and (
            self.expectation_status != "indeterminate"
        ):
            raise ValueError("not-applied mutation must be indeterminate")
        if self.execution_status != "completed" and (
            self.expectation_status != "indeterminate"
        ):
            raise ValueError("incomplete execution must be indeterminate")

        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("reason codes must be sorted and unique")
        if not self.action_receipt_ids or self.action_receipt_ids != tuple(
            sorted(set(self.action_receipt_ids))
        ):
            raise ValueError("receipt ids must be non-empty sorted and unique")
        for values, label in (
            (self.controller_factors, "controller_factors"),
            (self.execution_context_factors, "execution_context_factors"),
        ):
            if not values or values != tuple(sorted(set(values))):
                raise ValueError(f"{label} must be non-empty sorted and unique")

        evidence_paths = tuple(ref.path for ref in self.evidence_refs)
        if evidence_paths != tuple(sorted(set(evidence_paths))):
            raise ValueError("evidence refs must be path sorted and unique")
        if self.expectation_status in {"satisfied", "contradicted"} and (
            not self.evidence_refs
        ):
            raise ValueError("conclusive arm result requires evidence")

        reasons = set(self.reason_codes)
        if self.arm_kind == "negative" and self.mutation_status == "applied":
            if "MUTATION_APPLIED" not in reasons:
                raise ValueError("applied mutant requires MUTATION_APPLIED")
            if self.execution_status == "completed":
                expected_reason = (
                    "MUTATION_CAUGHT"
                    if self.expectation_status == "satisfied"
                    else "MUTATION_SURVIVED"
                    if self.expectation_status == "contradicted"
                    else None
                )
                if expected_reason is not None and expected_reason not in reasons:
                    raise ValueError("mutation outcome reason is missing")
        if self.mutation_status == "not_applied" and (
            "MUTATION_NOT_APPLIED" not in reasons
        ):
            raise ValueError("not-applied mutant requires reason code")

        required_execution_reason = {
            "timed_out": "EXEC_TIMEOUT",
            "crashed": "EXEC_CRASHED",
            "resource_exhausted": "EXEC_RESOURCE_EXHAUSTED",
            "evidence_unavailable": "EVIDENCE_MISSING",
        }.get(self.execution_status)
        if (
            required_execution_reason is not None
            and required_execution_reason not in reasons
        ):
            raise ValueError("execution status reason is missing")
        return self


class VerificationArmResultV03(VerificationArmResult):
    _signed_version = "0.3"

    schema_version: Literal["openworkproof-verification-arm-result/0.3"]
    reason_codes: tuple[VerificationReasonCodeV03, ...]
    scope_manifest_digest: Digest64
    observed_member_count: SafeNonNegativeInt
    observed_population_digest: Digest64
    observed_required_target_ids: tuple[Digest64, ...]
    scope_expectation_status: Literal[
        "satisfied", "contradicted", "indeterminate"
    ]
    scope_evidence_refs: tuple[EvidenceRef, ...]

    @model_validator(mode="after")
    def _closed_scope_result(self) -> VerificationArmResultV03:
        if self.observed_required_target_ids != tuple(
            sorted(set(self.observed_required_target_ids))
        ):
            raise ValueError(
                "observed_required_target_ids must be sorted and unique"
            )
        paths = tuple(ref.path for ref in self.scope_evidence_refs)
        if paths != tuple(sorted(set(paths))):
            raise ValueError("scope evidence refs must be path sorted and unique")
        if self.scope_expectation_status in {"satisfied", "contradicted"} and (
            not self.scope_evidence_refs
        ):
            raise ValueError("conclusive scope result requires scope evidence")
        return self


class VerificationIndependenceAssessment(ProtocolModel):
    distinct_subjects: bool
    distinct_keys: bool
    distinct_controllers: bool
    distinct_execution_contexts: bool
    reason_codes: tuple[VerificationReasonCode, ...]

    @property
    def is_sufficient(self) -> bool:
        return (
            self.distinct_subjects
            and self.distinct_keys
            and self.distinct_controllers
            and self.distinct_execution_contexts
        )

    @model_validator(mode="after")
    def _closed_assessment(self) -> VerificationIndependenceAssessment:
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("independence reason codes must be sorted and unique")
        expected = tuple(
            sorted(
                code
                for satisfied, code in (
                    (self.distinct_subjects, "INDEPENDENCE_INSUFFICIENT"),
                    (self.distinct_keys, "INDEPENDENCE_KEY_REUSED"),
                    (self.distinct_controllers, "INDEPENDENCE_DOMAIN_OVERLAP"),
                    (
                        self.distinct_execution_contexts,
                        "INDEPENDENCE_CONTEXT_REUSED",
                    ),
                )
                if not satisfied
            )
        )
        if self.reason_codes != expected:
            raise ValueError("independence reason codes do not match checks")
        return self


class VerificationArmResultReference(ProtocolModel):
    arm_id: Digest64
    arm_result_id: Digest64
    arm_result_digest: Digest64
    evidence_snapshot_digest: Digest64


class VerificationDecisionSignature(ProtocolModel):
    verifier_subject_id: Identifier
    verifier_key_id: KeyId
    signature_alg: Literal["Ed25519"]
    signature: Signature


def _validate_verification_decision_content(
    *,
    arm_results: tuple[VerificationArmResultReference, ...],
    reason_codes: tuple[str, ...],
    supersedes_decision_id: str | None,
    supersedes_decision_digest: str | None,
    causal_parent_receipt_ids: tuple[str, ...],
    causal_parent_decision_ids: tuple[str, ...],
) -> None:
    arm_result_ids = tuple(item.arm_result_id for item in arm_results)
    if not arm_results or arm_result_ids != tuple(sorted(set(arm_result_ids))):
        raise ValueError("arm results must be non-empty sorted and unique")
    arm_ids = tuple(item.arm_id for item in arm_results)
    if len(set(arm_ids)) != len(arm_ids):
        raise ValueError("arm references must be one-to-one")
    if reason_codes != tuple(sorted(set(reason_codes))):
        raise ValueError("decision reason codes must be sorted and unique")
    if (supersedes_decision_id is None) != (supersedes_decision_digest is None):
        raise ValueError("supersedes id and digest must be paired")
    if not causal_parent_receipt_ids or causal_parent_receipt_ids != tuple(
        sorted(set(causal_parent_receipt_ids))
    ):
        raise ValueError("causal receipt parents must be non-empty sorted and unique")
    expected_decision_parents = (
        () if supersedes_decision_id is None else (supersedes_decision_id,)
    )
    if causal_parent_decision_ids != expected_decision_parents:
        raise ValueError("causal decision parents do not match supersedes")


class VerificationDecisionDraft(ProtocolModel):
    decision_id: Digest64
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    profile_id: Digest64
    profile_digest: Digest64
    arm_results: tuple[VerificationArmResultReference, ...]
    assurance_level: Literal["standard", "high_risk"]
    decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    independence: VerificationIndependenceAssessment
    reason_codes: tuple[VerificationReasonCode, ...]
    supersedes_decision_id: Digest64 | None
    supersedes_decision_digest: Digest64 | None
    causal_parent_receipt_ids: tuple[Digest64, ...]
    causal_parent_decision_ids: tuple[Digest64, ...]
    decided_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _closed_draft(self) -> VerificationDecisionDraft:
        _validate_verification_decision_content(
            arm_results=self.arm_results,
            reason_codes=self.reason_codes,
            supersedes_decision_id=self.supersedes_decision_id,
            supersedes_decision_digest=self.supersedes_decision_digest,
            causal_parent_receipt_ids=self.causal_parent_receipt_ids,
            causal_parent_decision_ids=self.causal_parent_decision_ids,
        )
        return self


class ScopeAssessment(ProtocolModel):
    declared_member_count: SafePositiveInt
    observed_member_counts: tuple[SafeNonNegativeInt, ...]
    population_digest: Digest64
    required_target_count: SafePositiveInt
    missing_required_target_ids: tuple[Digest64, ...]
    scope_status: Literal["satisfied", "contradicted", "indeterminate"]

    @model_validator(mode="after")
    def _closed_scope_assessment(self) -> ScopeAssessment:
        if not self.observed_member_counts:
            raise ValueError("observed_member_counts must be non-empty")
        if self.missing_required_target_ids != tuple(
            sorted(set(self.missing_required_target_ids))
        ):
            raise ValueError(
                "missing_required_target_ids must be sorted and unique"
            )
        if self.scope_status == "satisfied" and (
            self.missing_required_target_ids
            or any(
                count != self.declared_member_count
                for count in self.observed_member_counts
            )
        ):
            raise ValueError("satisfied scope assessment is internally inconsistent")
        return self


class VerificationDecisionDraftV03(VerificationDecisionDraft):
    reason_codes: tuple[VerificationReasonCodeV03, ...]
    scope_manifest_digest: Digest64
    scope_assessment: ScopeAssessment

    @model_validator(mode="after")
    def _closed_scope_decision(self) -> VerificationDecisionDraftV03:
        if self.scope_assessment.scope_status != "satisfied" and (
            self.decision != "UNKNOWN"
        ):
            raise ValueError("non-satisfied scope requires UNKNOWN")
        return self


class DecisionDraftRequest(ProtocolModel):
    decision_id: Digest64
    decided_at: CanonicalUTCTime
    nonce: Digest64


class VerificationDecision(ProtocolModel):
    schema_version: Literal["openworkproof-verification-decision/0.2"]
    decision_id: Digest64
    digest: Digest64
    work_order_digest: Digest64
    subject_claim_digest: Digest64
    profile_id: Digest64
    profile_digest: Digest64
    arm_results: tuple[VerificationArmResultReference, ...]
    assurance_level: Literal["standard", "high_risk"]
    decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"]
    independence: VerificationIndependenceAssessment
    reason_codes: tuple[VerificationReasonCode, ...]
    supersedes_decision_id: Digest64 | None
    supersedes_decision_digest: Digest64 | None
    causal_parent_receipt_ids: tuple[Digest64, ...]
    causal_parent_decision_ids: tuple[Digest64, ...]
    decided_at: CanonicalUTCTime
    nonce: Digest64
    verifier_signatures: tuple[VerificationDecisionSignature, ...]

    @model_validator(mode="after")
    def _closed_decision(self) -> VerificationDecision:
        _validate_verification_decision_content(
            arm_results=self.arm_results,
            reason_codes=self.reason_codes,
            supersedes_decision_id=self.supersedes_decision_id,
            supersedes_decision_digest=self.supersedes_decision_digest,
            causal_parent_receipt_ids=self.causal_parent_receipt_ids,
            causal_parent_decision_ids=self.causal_parent_decision_ids,
        )
        expected_signatures = 2 if self.assurance_level == "high_risk" else 1
        if len(self.verifier_signatures) != expected_signatures:
            raise ValueError("decision signature set has the wrong size")
        signature_keys = tuple(
            signature.verifier_key_id for signature in self.verifier_signatures
        )
        if signature_keys != tuple(
            sorted(set(signature_keys), key=lambda value: value.encode("utf-8"))
        ):
            raise ValueError("decision signatures must be key-sorted and unique")
        payload = self.model_dump(
            mode="json", exclude={"digest", "verifier_signatures"}
        )
        expected_digest = _jcs_digest(
            {
                "domain": "openworkproof/verification-decision/v0.1",
                "payload": payload,
            }
        )
        if self.digest != expected_digest:
            raise ValueError("digest does not match verification decision payload")
        return self


class VerificationDecisionV03(VerificationDecision):
    schema_version: Literal["openworkproof-verification-decision/0.3"]
    reason_codes: tuple[VerificationReasonCodeV03, ...]
    scope_manifest_digest: Digest64
    scope_assessment: ScopeAssessment

    @model_validator(mode="after")
    def _closed_decision(self) -> VerificationDecisionV03:
        _validate_verification_decision_content(
            arm_results=self.arm_results,
            reason_codes=self.reason_codes,
            supersedes_decision_id=self.supersedes_decision_id,
            supersedes_decision_digest=self.supersedes_decision_digest,
            causal_parent_receipt_ids=self.causal_parent_receipt_ids,
            causal_parent_decision_ids=self.causal_parent_decision_ids,
        )
        if self.scope_assessment.scope_status != "satisfied" and (
            self.decision != "UNKNOWN"
        ):
            raise ValueError("non-satisfied scope requires UNKNOWN")
        expected_signatures = 2 if self.assurance_level == "high_risk" else 1
        if len(self.verifier_signatures) != expected_signatures:
            raise ValueError("decision signature set has the wrong size")
        signature_keys = tuple(
            signature.verifier_key_id for signature in self.verifier_signatures
        )
        if signature_keys != tuple(
            sorted(set(signature_keys), key=lambda value: value.encode("utf-8"))
        ):
            raise ValueError("decision signatures must be key-sorted and unique")
        payload = self.model_dump(
            mode="json", exclude={"digest", "verifier_signatures"}
        )
        expected_digest = _jcs_digest(
            {
                "domain": "openworkproof/verification-decision/v0.3",
                "payload": payload,
            }
        )
        if self.digest != expected_digest:
            raise ValueError("digest does not match verification decision payload")
        return self


VerificationArmExecutionStatus = Literal[
    "completed",
    "timed_out",
    "crashed",
    "resource_exhausted",
    "evidence_unavailable",
]

VerificationIntegrityReasonCode = Literal[
    "NO_ELIGIBLE_POPULATION",
    "POPULATION_CAPTURE_FAILED",
    "POPULATION_RULE_DRIFT",
    "POPULATION_ENGINE_DRIFT",
    "POPULATION_DIGEST_MISMATCH",
    "POPULATION_CROSS_ARM_MISMATCH",
    "POPULATION_EVIDENCE_MISSING",
    "CONTROL_CONTRACT_EXPIRED",
    "CONTROL_FIXTURE_DRIFT",
    "CONTROL_PROVOCATION_DRIFT",
    "CONTROL_FAILURE_SIGNATURE_MISMATCH",
    "CONTROL_SURVIVED",
    "CONTROL_EVIDENCE_MISSING",
]

VerificationReasonCodeV05 = (
    VerificationReasonCodeV03 | VerificationIntegrityReasonCode
)

_POPULATION_INTEGRITY_CODES = frozenset(
    {
        "NO_ELIGIBLE_POPULATION",
        "POPULATION_CAPTURE_FAILED",
        "POPULATION_RULE_DRIFT",
        "POPULATION_ENGINE_DRIFT",
        "POPULATION_DIGEST_MISMATCH",
        "POPULATION_CROSS_ARM_MISMATCH",
        "POPULATION_EVIDENCE_MISSING",
    }
)
_POPULATION_DRIFT_CODES = frozenset(
    {
        "POPULATION_RULE_DRIFT",
        "POPULATION_ENGINE_DRIFT",
        "POPULATION_DIGEST_MISMATCH",
        "POPULATION_CROSS_ARM_MISMATCH",
    }
)
_CONTROL_INTEGRITY_CODES = frozenset(
    {
        "CONTROL_CONTRACT_EXPIRED",
        "CONTROL_FIXTURE_DRIFT",
        "CONTROL_PROVOCATION_DRIFT",
        "CONTROL_FAILURE_SIGNATURE_MISMATCH",
        "CONTROL_SURVIVED",
        "CONTROL_EVIDENCE_MISSING",
    }
)
_CONTROL_MISMATCH_CODES = frozenset(
    {
        "CONTROL_FIXTURE_DRIFT",
        "CONTROL_PROVOCATION_DRIFT",
        "CONTROL_FAILURE_SIGNATURE_MISMATCH",
    }
)
_VERIFICATION_INTEGRITY_CODES = (
    _POPULATION_INTEGRITY_CODES | _CONTROL_INTEGRITY_CODES
)


def _identity_payload(
    value: ProtocolModel | dict[str, object],
    own_id: str,
    model_type: type[ProtocolModel],
) -> dict[str, Any]:
    if type(value) is model_type:
        source: dict[str, object] = value.model_dump(mode="json")
    elif type(value) is dict:
        source = value
    else:
        raise ValueError(
            "identity payload must be the exact model or exact built-in dict"
        )
    payload = _freeze_exact_json_payload(source, max_array_items=4096)
    payload.pop(own_id, None)
    return payload


def _validate_exact_json_containers(
    value: Any, *, max_array_items: int, depth: int = 1
) -> None:
    if depth > 16:
        raise ValueError("JSON nesting depth exceeds 16")
    if type(value) is dict:
        if len(value) > 64:
            raise ValueError("JSON map exceeds 64 entries")
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON map keys must be strings")
            _validate_exact_json_containers(
                item,
                max_array_items=max_array_items,
                depth=depth + 1,
            )
        return
    if type(value) in {list, tuple}:
        if len(value) > max_array_items:
            raise ValueError(
                f"JSON array exceeds {max_array_items} items"
            )
        for item in value:
            _validate_exact_json_containers(
                item,
                max_array_items=max_array_items,
                depth=depth + 1,
            )
        return
    if value is None or type(value) in {str, int, bool}:
        return
    if isinstance(value, (Mapping, Sequence)):
        raise ValueError(
            "JSON containers must use exact built-in dict, list, or tuple"
        )


def _freeze_exact_json_payload(
    value: dict[str, object], *, max_array_items: int
) -> dict[str, Any]:
    _validate_exact_json_containers(
        value, max_array_items=max_array_items
    )
    return _freeze_json(
        value,
        freeze_mapping=False,
        max_array_items=max_array_items,
    )


def _thaw_frozen_mappings(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _thaw_frozen_mappings(item) for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(_thaw_frozen_mappings(item) for item in value)
    return value


def _freeze_bounded_protocol_payload(
    value: Any, model_type: type[ProtocolModel], *, max_array_items: int
) -> Any:
    if type(value) is model_type:
        return value
    if type(value) is not dict:
        raise ValueError(
            "protocol object must be the exact model or exact built-in dict"
        )
    return _thaw_frozen_mappings(
        _freeze_exact_json_payload(value, max_array_items=max_array_items)
    )


def population_contract_id(
    contract: PopulationContractV05 | dict[str, object],
) -> str:
    return _jcs_digest(
        {
            "domain": "openworkproof/population-contract/v0.5",
            "payload": _identity_payload(
                contract, "contract_id", PopulationContractV05
            ),
        }
    )


def population_member_digest(member_ids: list[str] | tuple[str, ...]) -> str:
    if type(member_ids) not in {list, tuple}:
        raise ValueError("member ids must use exact built-in list or tuple")
    declared_length = len(member_ids)
    if declared_length > 4096:
        raise ValueError("member ids exceed 4096 items")
    values = tuple(member_ids)
    for value in values:
        _digest64(value)
    if not _is_utf8_sorted_unique(values):
        raise ValueError("member ids must be sorted and unique")
    payload = _freeze_json(values, max_array_items=4096)
    return _jcs_digest(
        {
            "domain": "openworkproof/population-members/v0.5",
            "payload": payload,
        }
    )


_V05_MODEL_CONFIG = ConfigDict(revalidate_instances="subclass-instances")


class PopulationContractV05(ProtocolModel):
    model_config = _V05_MODEL_CONFIG

    contract_id: Digest64
    selector_rule_id: Digest64
    member_kind: Literal["source_file", "test_case"]
    selector_spec_digest: Digest64
    selector_engine_digest: Digest64
    declared_selected_member_ids: tuple[Digest64, ...]
    minimum_eligible_count: SafeNonNegativeInt
    minimum_selected_count: SafeNonNegativeInt
    maximum_eligible_count: SafeNonNegativeInt
    maximum_selected_count: SafeNonNegativeInt
    minimum_capture_numerator: SafeNonNegativeInt
    minimum_capture_denominator: SafePositiveInt
    empty_population_policy: Literal["unknown"]
    required_population_evidence_purposes: tuple[Identifier, ...]

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        return _freeze_bounded_protocol_payload(
            value, cls, max_array_items=4096
        )

    @model_validator(mode="after")
    def _closed_population_contract(self) -> PopulationContractV05:
        if not self.declared_selected_member_ids or not _is_utf8_sorted_unique(
            self.declared_selected_member_ids
        ):
            raise ValueError(
                "declared_selected_member_ids must be non-empty sorted and unique"
            )
        if (
            not self.required_population_evidence_purposes
            or not _is_utf8_sorted_unique(
                self.required_population_evidence_purposes
            )
        ):
            raise ValueError(
                "required_population_evidence_purposes must be non-empty sorted and unique"
            )
        if len(self.declared_selected_member_ids) > 4096:
            raise ValueError(
                "declared_selected_member_ids must not exceed 4096 items"
            )
        if len(self.required_population_evidence_purposes) > 256:
            raise ValueError(
                "required_population_evidence_purposes must not exceed 256 items"
            )
        if self.maximum_eligible_count > 4096 or self.maximum_selected_count > 4096:
            raise ValueError("population maximums must not exceed 4096")
        if self.maximum_selected_count > self.maximum_eligible_count:
            raise ValueError("selected maximum must not exceed eligible maximum")
        if self.minimum_eligible_count > self.maximum_eligible_count:
            raise ValueError(
                "minimum_eligible_count must not exceed maximum_eligible_count"
            )
        if self.minimum_selected_count > self.maximum_selected_count:
            raise ValueError(
                "minimum_selected_count must not exceed maximum_selected_count"
            )
        if self.minimum_capture_numerator > self.minimum_capture_denominator:
            raise ValueError("minimum capture fraction is outside 0..1")
        if self.minimum_capture_numerator == 0 and (
            self.minimum_capture_denominator != 1
        ):
            raise ValueError("0/1 is the only zero minimum capture representation")
        if self.contract_id != population_contract_id(self):
            raise ValueError("contract_id does not match population contract")
        return self


class PopulationObservationV05(ProtocolModel):
    model_config = _V05_MODEL_CONFIG

    contract_id: Digest64
    selector_rule_id: Digest64
    selector_spec_digest: Digest64
    selector_engine_digest: Digest64
    eligible_seen: SafeNonNegativeInt
    eligible_population_digest: Digest64
    selected_count: SafeNonNegativeInt
    selected_population_digest: Digest64
    capture_numerator: SafeNonNegativeInt
    capture_denominator: SafePositiveInt
    observed_at: CanonicalUTCTime
    evidence_refs: tuple[EvidenceRef, ...]

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        return _freeze_bounded_protocol_payload(
            value, cls, max_array_items=256
        )

    @model_validator(mode="after")
    def _closed_population_observation(self) -> PopulationObservationV05:
        if self.eligible_seen > 4096 or self.selected_count > 4096:
            raise ValueError("population observation counts must not exceed 4096")
        if self.selected_count > self.eligible_seen:
            raise ValueError("selected_count must not exceed eligible_seen")
        paths = tuple(reference.path for reference in self.evidence_refs)
        if not _is_utf8_sorted_unique(paths):
            raise ValueError("evidence refs must be path sorted and unique")
        if self.eligible_seen == 0:
            empty_digest = population_member_digest(())
            if (
                self.selected_count != 0
                or (self.capture_numerator, self.capture_denominator) != (0, 1)
                or self.eligible_population_digest != empty_digest
                or self.selected_population_digest != empty_digest
            ):
                raise ValueError("empty population requires zero counts, 0/1, and empty digests")
            return self
        if math.gcd(self.capture_numerator, self.capture_denominator) != 1:
            raise ValueError("non-empty capture fraction must be reduced")
        if (
            self.capture_numerator * self.eligible_seen
            != self.selected_count * self.capture_denominator
        ):
            raise ValueError("capture fraction must exactly equal selected/eligible")
        return self


class FailureSignatureV05(ProtocolModel):
    model_config = _V05_MODEL_CONFIG

    execution_status: VerificationArmExecutionStatus
    exit_codes: tuple[SafeNonNegativeInt, ...]
    reason_codes: tuple[VerificationReasonCodeV03, ...]
    predicate_ids: tuple[Identifier, ...]
    required_evidence_purposes: tuple[Identifier, ...]

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        return _freeze_bounded_protocol_payload(
            value, cls, max_array_items=256
        )

    @model_validator(mode="after")
    def _closed_failure_signature(self) -> FailureSignatureV05:
        for values, maximum, label in (
            (self.exit_codes, 64, "exit_codes"),
            (self.reason_codes, 256, "reason_codes"),
            (self.predicate_ids, 256, "predicate_ids"),
            (
                self.required_evidence_purposes,
                256,
                "required_evidence_purposes",
            ),
        ):
            if not values:
                raise ValueError(f"{label} must be non-empty")
            if len(values) > maximum:
                raise ValueError(f"{label} must not exceed {maximum} items")
            if tuple(values) != tuple(sorted(set(values))):
                raise ValueError(f"{label} must be sorted and unique")
        return self


def failure_signature_digest(
    signature: FailureSignatureV05 | dict[str, object],
) -> str:
    if type(signature) is FailureSignatureV05:
        source: dict[str, object] = signature.model_dump(mode="json")
    elif type(signature) is dict:
        source = signature
    else:
        raise ValueError(
            "failure signature must be the exact model or exact built-in dict"
        )
    payload = _freeze_exact_json_payload(
        source, max_array_items=256
    )
    return _jcs_digest(
        {
            "domain": "openworkproof/failure-signature/v0.5",
            "payload": payload,
        }
    )


def control_contract_id(
    contract: ControlContractV05 | dict[str, object],
) -> str:
    return _jcs_digest(
        {
            "domain": "openworkproof/control-contract/v0.5",
            "payload": _identity_payload(
                contract, "control_id", ControlContractV05
            ),
        }
    )


class ControlContractV05(ProtocolModel):
    model_config = _V05_MODEL_CONFIG

    control_id: Digest64
    arm_id: Digest64
    control_target: Literal["semantic_regression", "required_target_coverage"]
    fixture_digest: Digest64
    provocation_digest: Digest64
    expected_failure_signature: FailureSignatureV05
    expected_failure_signature_digest: Digest64
    valid_from: CanonicalUTCTime
    expires_at: CanonicalUTCTime

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        return _freeze_bounded_protocol_payload(
            value, cls, max_array_items=256
        )

    @model_validator(mode="after")
    def _closed_control_contract(self) -> ControlContractV05:
        if self.expected_failure_signature_digest != failure_signature_digest(
            self.expected_failure_signature
        ):
            raise ValueError("expected failure signature digest does not match")
        if self.expected_failure_signature.execution_status != "completed":
            raise ValueError("expected failure signature must be completed")
        if not self.valid_from < self.expires_at:
            raise ValueError("control contract times are not ordered")
        if self.control_id != control_contract_id(self):
            raise ValueError("control_id does not match control contract")
        return self


class ControlObservationV05(ProtocolModel):
    model_config = _V05_MODEL_CONFIG

    control_id: Digest64
    fixture_digest: Digest64
    provocation_digest: Digest64
    observed_failure_signature: FailureSignatureV05
    observed_failure_signature_digest: Digest64
    control_status: Literal["proven", "survived", "mismatched", "unavailable"]
    evidence_refs: tuple[EvidenceRef, ...]

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        return _freeze_bounded_protocol_payload(
            value, cls, max_array_items=256
        )

    @model_validator(mode="after")
    def _closed_control_observation(self) -> ControlObservationV05:
        if self.observed_failure_signature_digest != failure_signature_digest(
            self.observed_failure_signature
        ):
            raise ValueError("observed failure signature digest does not match")
        paths = tuple(reference.path for reference in self.evidence_refs)
        if not _is_utf8_sorted_unique(paths):
            raise ValueError("evidence refs must be path sorted and unique")
        if self.control_status in {"proven", "survived", "mismatched"} and (
            self.observed_failure_signature.execution_status != "completed"
        ):
            raise ValueError(f"{self.control_status} control must be completed")
        if self.control_status in {"proven", "survived", "mismatched"} and (
            not self.evidence_refs
        ):
            raise ValueError(f"{self.control_status} control requires evidence")
        return self


class VerificationIntegrityAssessmentV05(ProtocolModel):
    model_config = _V05_MODEL_CONFIG

    population_status: Literal[
        "matched", "empty", "capture_failed", "drifted", "unavailable"
    ]
    control_status: Literal["proven", "survived", "mismatched", "unavailable"]
    reason_codes: tuple[VerificationIntegrityReasonCode, ...]

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        return _freeze_bounded_protocol_payload(
            value, cls, max_array_items=64
        )

    @model_validator(mode="after")
    def _closed_integrity_assessment(self) -> VerificationIntegrityAssessmentV05:
        if not _is_utf8_sorted_unique(self.reason_codes):
            raise ValueError("integrity reason codes must be sorted and unique")
        reasons = set(self.reason_codes)
        population_reasons = reasons & _POPULATION_INTEGRITY_CODES
        control_reasons = reasons & _CONTROL_INTEGRITY_CODES
        allowed_population = {
            "matched": frozenset(),
            "empty": frozenset({"NO_ELIGIBLE_POPULATION"}),
            "capture_failed": frozenset({"POPULATION_CAPTURE_FAILED"}),
            "drifted": _POPULATION_DRIFT_CODES,
            "unavailable": frozenset({"POPULATION_EVIDENCE_MISSING"}),
        }[self.population_status]
        allowed_control = {
            "proven": frozenset(),
            "survived": frozenset({"CONTROL_SURVIVED"}),
            "mismatched": _CONTROL_MISMATCH_CODES,
            "unavailable": frozenset(
                {"CONTROL_CONTRACT_EXPIRED", "CONTROL_EVIDENCE_MISSING"}
            ),
        }[self.control_status]
        if not population_reasons <= allowed_population or (
            self.population_status != "matched" and not population_reasons
        ):
            raise ValueError("population reason codes do not match status")
        if not control_reasons <= allowed_control or (
            self.control_status != "proven" and not control_reasons
        ):
            raise ValueError("control reason codes do not match status")
        return self


class VerificationProfileV05(VerificationProfileV03):
    model_config = _V05_MODEL_CONFIG

    _signed_version = "0.5"

    schema_version: Literal["openworkproof-verification-profile/0.5"]
    population_contracts: tuple[PopulationContractV05, ...]
    control_contracts: tuple[ControlContractV05, ...]

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        return _freeze_bounded_protocol_payload(
            value, cls, max_array_items=4096
        )

    @model_validator(mode="after")
    def _closed_v05_profile(self) -> VerificationProfileV05:
        population_ids = tuple(
            contract.contract_id for contract in self.population_contracts
        )
        if not population_ids or not _is_utf8_sorted_unique(population_ids):
            raise ValueError("population contracts must be non-empty sorted and unique")
        selector_ids = tuple(
            contract.selector_rule_id for contract in self.population_contracts
        )
        if len(selector_ids) != len(set(selector_ids)):
            raise ValueError("population contracts must have unique selector rules")
        control_ids = tuple(contract.control_id for contract in self.control_contracts)
        if not control_ids or not _is_utf8_sorted_unique(control_ids):
            raise ValueError("control contracts must be non-empty sorted and unique")
        controlled_arm_ids = tuple(
            contract.arm_id for contract in self.control_contracts
        )
        if len(controlled_arm_ids) != len(set(controlled_arm_ids)):
            raise ValueError("control contracts must have unique arm ids")
        if self.positive_arm.arm_id in set(controlled_arm_ids):
            raise ValueError("positive arm cannot have a control contract")
        negative_by_id = {arm.arm_id: arm for arm in self.negative_arms}
        if set(controlled_arm_ids) != set(negative_by_id):
            raise ValueError("every negative arm requires exactly one control contract")
        for contract in self.control_contracts:
            if contract.fixture_digest != negative_by_id[contract.arm_id].mutant_patch_digest:
                raise ValueError("control fixture_digest must equal arm mutant_patch_digest")
        return self


class VerificationArmResultV05(VerificationArmResultV03):
    model_config = _V05_MODEL_CONFIG

    _signed_version = "0.5"

    schema_version: Literal["openworkproof-verification-arm-result/0.5"]
    population_observations: tuple[PopulationObservationV05, ...]
    control_observation: ControlObservationV05 | None

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        return _freeze_bounded_protocol_payload(
            value, cls, max_array_items=4096
        )

    @model_validator(mode="after")
    def _closed_v05_result(self) -> VerificationArmResultV05:
        contract_ids = tuple(
            observation.contract_id for observation in self.population_observations
        )
        if not contract_ids or not _is_utf8_sorted_unique(contract_ids):
            raise ValueError(
                "population observations must be non-empty sorted and unique"
            )
        if self.arm_kind == "positive" and self.control_observation is not None:
            raise ValueError("positive arm forbids a control observation")
        if self.arm_kind == "negative" and self.control_observation is None:
            raise ValueError("negative arm requires a control observation")
        return self


def _validate_v05_decision_status(
    decision: str, assessment: VerificationIntegrityAssessmentV05
) -> None:
    if assessment.population_status != "matched":
        if decision != "UNKNOWN":
            raise ValueError("non-matched population requires UNKNOWN")
        return
    if assessment.control_status == "survived":
        if decision != "REFUTED":
            raise ValueError("survived control with matched population requires REFUTED")
    elif assessment.control_status in {"mismatched", "unavailable"} and (
        decision != "UNKNOWN"
    ):
        raise ValueError("mismatched or unavailable control requires UNKNOWN")


def _validate_v05_decision_reason_codes(
    reason_codes: tuple[str, ...],
    assessment: VerificationIntegrityAssessmentV05,
) -> None:
    top_level_integrity_codes = set(reason_codes) & _VERIFICATION_INTEGRITY_CODES
    if top_level_integrity_codes != set(assessment.reason_codes):
        raise ValueError(
            "top-level integrity reason codes must exactly match assessment"
        )


class VerificationDecisionDraftV05(VerificationDecisionDraftV03):
    model_config = _V05_MODEL_CONFIG

    reason_codes: tuple[VerificationReasonCodeV05, ...]
    integrity_assessment: VerificationIntegrityAssessmentV05

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        return _freeze_bounded_protocol_payload(
            value, cls, max_array_items=256
        )

    @model_validator(mode="after")
    def _closed_v05_draft(self) -> VerificationDecisionDraftV05:
        _validate_v05_decision_status(self.decision, self.integrity_assessment)
        _validate_v05_decision_reason_codes(
            self.reason_codes, self.integrity_assessment
        )
        return self


class VerificationDecisionV05(VerificationDecisionV03):
    model_config = _V05_MODEL_CONFIG

    schema_version: Literal["openworkproof-verification-decision/0.5"]
    reason_codes: tuple[VerificationReasonCodeV05, ...]
    integrity_assessment: VerificationIntegrityAssessmentV05

    @model_validator(mode="before")
    @classmethod
    def _validate_json_shape(cls, value: Any) -> Any:
        return _freeze_bounded_protocol_payload(
            value, cls, max_array_items=256
        )

    @model_validator(mode="after")
    def _closed_decision(self) -> VerificationDecisionV05:
        _validate_verification_decision_content(
            arm_results=self.arm_results,
            reason_codes=self.reason_codes,
            supersedes_decision_id=self.supersedes_decision_id,
            supersedes_decision_digest=self.supersedes_decision_digest,
            causal_parent_receipt_ids=self.causal_parent_receipt_ids,
            causal_parent_decision_ids=self.causal_parent_decision_ids,
        )
        if self.scope_assessment.scope_status != "satisfied" and (
            self.decision != "UNKNOWN"
        ):
            raise ValueError("non-satisfied scope requires UNKNOWN")
        _validate_v05_decision_status(self.decision, self.integrity_assessment)
        _validate_v05_decision_reason_codes(
            self.reason_codes, self.integrity_assessment
        )
        expected_signatures = 2 if self.assurance_level == "high_risk" else 1
        if len(self.verifier_signatures) != expected_signatures:
            raise ValueError("decision signature set has the wrong size")
        signature_keys = tuple(
            signature.verifier_key_id for signature in self.verifier_signatures
        )
        if signature_keys != tuple(
            sorted(set(signature_keys), key=lambda value: value.encode("utf-8"))
        ):
            raise ValueError("decision signatures must be key-sorted and unique")
        payload = self.model_dump(
            mode="json", exclude={"digest", "verifier_signatures"}
        )
        expected_digest = _jcs_digest(
            {
                "domain": "openworkproof/verification-decision/v0.5",
                "payload": payload,
            }
        )
        if self.digest != expected_digest:
            raise ValueError("digest does not match verification decision payload")
        return self


class QuotaCharge(ProtocolModel):
    grant_id: Digest64
    metric: Literal["tool_calls", "repair_rounds"]
    amount: SafePositiveInt
    remaining_after: SafeNonNegativeInt


class CorrelationFactors(ProtocolModel):
    model_id: ProtocolString
    model_version: ProtocolString
    prompt_template_digest: Digest64
    context_source_digest: Digest64
    toolchain_id: Digest64 | None
    execution_context_id: Digest64 | None
    container_instance_id_digest: Digest64 | None
    controller_id: KeyId
    fixed_test_source_digest: Digest64 | None


class AgentRequest(SignedProtocolModel):
    claim_type: Literal["agent-request"]
    work_order_digest: Digest64
    grant_id: Digest64
    actor_id: Identifier
    actor_key_id: KeyId
    tool_name: Literal[
        "owp.activate_root_grant",
        "owp.apply_patch",
        "owp.compose_proof",
        "owp.create_pr_proposal",
        "owp.delegate_grant",
        "owp.repo_read",
        "owp.request_acceptance",
        "owp.request_pr_proposal",
        "owp.revoke_grant",
        "owp.rollback_patch",
        "owp.run_tests",
        "owp.start_retry",
    ]
    arguments_digest: Digest64
    nonce: Digest64
    requested_at: CanonicalUTCTime
    authentication_method: Literal["agent_signature"]
    model_id: ProtocolString
    model_version: ProtocolString
    prompt_template_digest: Digest64
    context_source_digest: Digest64

    @model_validator(mode="after")
    def _validate_signer_identity(self) -> AgentRequest:
        if self.signer_key_id != self.actor_key_id:
            raise ValueError("AgentRequest signer must equal actor key")
        return self


BindingOutcome = Literal["BOUND", "UNBOUND", "INDETERMINATE"]
AuthorityStatus = Literal[
    "not_required", "current", "missing", "stale", "forked", "unavailable"
]
BindingReasonCode = Literal[
    "JUDGMENT_SIGNATURE_INVALID",
    "JUDGMENT_EXPIRED",
    "JUDGMENT_ARTIFACT_MISSING",
    "JUDGMENT_DIGEST_MISMATCH",
    "JUDGMENT_FACTS_DIGEST_MISMATCH",
    "JUDGMENT_DISPOSITION_DIGEST_MISMATCH",
    "JUDGMENT_SUPERSEDED",
    "ADAPTER_PROFILE_DIGEST_MISMATCH",
    "ACTION_DIGEST_MISMATCH",
    "ACTION_ARGUMENTS_MISMATCH",
    "ACTION_MAPPING_REJECTED",
    "ACTION_OUTSIDE_APPROVED_SCOPE",
    "ACTION_SIDE_EFFECT_UNDECLARED",
    "REPLAY_UNAVAILABLE",
    "REPLAY_DIVERGED",
    "EVALUATOR_VERSION_DRIFT",
    "AUTHORITY_CHECKPOINT_MISSING",
    "AUTHORITY_CHECKPOINT_STALE",
    "AUTHORITY_CHECKPOINT_SIGNATURE_INVALID",
    "AUTHORITY_FORK_DETECTED",
    "AUTHORITY_ROLLBACK_DETECTED",
    "ALTERNATIVE_WORK_ORDER_DETECTED",
    "UNSIGNED_METADATA_REFERENCE",
    "EVIDENCE_INCOMPLETE",
    "VERIFICATION_NOT_CURRENT",
    "INDEPENDENCE_UNPROVEN",
]

_UNBOUND_BINDING_REASONS = frozenset(
    {
        "JUDGMENT_DIGEST_MISMATCH",
        "JUDGMENT_FACTS_DIGEST_MISMATCH",
        "JUDGMENT_DISPOSITION_DIGEST_MISMATCH",
        "JUDGMENT_SUPERSEDED",
        "ADAPTER_PROFILE_DIGEST_MISMATCH",
        "ACTION_DIGEST_MISMATCH",
        "ACTION_ARGUMENTS_MISMATCH",
        "ACTION_MAPPING_REJECTED",
        "ACTION_OUTSIDE_APPROVED_SCOPE",
        "ACTION_SIDE_EFFECT_UNDECLARED",
        "REPLAY_DIVERGED",
        "AUTHORITY_CHECKPOINT_STALE",
        "AUTHORITY_FORK_DETECTED",
        "AUTHORITY_ROLLBACK_DETECTED",
        "ALTERNATIVE_WORK_ORDER_DETECTED",
    }
)
_INDETERMINATE_BINDING_REASONS = frozenset(
    {
        "JUDGMENT_ARTIFACT_MISSING",
        "REPLAY_UNAVAILABLE",
        "EVALUATOR_VERSION_DRIFT",
        "AUTHORITY_CHECKPOINT_MISSING",
        "ALTERNATIVE_WORK_ORDER_DETECTED",
        "UNSIGNED_METADATA_REFERENCE",
        "EVIDENCE_INCOMPLETE",
        "VERIFICATION_NOT_CURRENT",
        "INDEPENDENCE_UNPROVEN",
    }
)
_AUTHORITY_CHECKPOINT_FAILURE_REASONS = frozenset(
    {
        "AUTHORITY_CHECKPOINT_MISSING",
        "AUTHORITY_CHECKPOINT_STALE",
        "AUTHORITY_CHECKPOINT_SIGNATURE_INVALID",
        "AUTHORITY_FORK_DETECTED",
        "AUTHORITY_ROLLBACK_DETECTED",
    }
)


def _validate_named_nonempty_sorted_unique(
    values: tuple[str, ...], label: str
) -> None:
    if not values or not _is_utf8_sorted_unique(values):
        raise ValueError(f"{label} must be non-empty UTF-8 sorted and unique")


class JudgmentCommitment(SignedProtocolModel):
    _signed_domain = "judgment-commitment"
    _signed_version = "0.4"

    schema_version: Literal["openworkproof-judgment-commitment/0.4"]
    commitment_id: Digest64
    authority_namespace: Identifier
    subject_id: Identifier
    judgment_kind: Identifier
    judgment_artifact_uri: ProtocolString
    judgment_artifact_digest: Digest64
    normalized_facts_digest: Digest64
    disposition_digest: Digest64
    action_constraint_digest: Digest64
    adapter_id: ProtocolString
    adapter_version: ProtocolString
    adapter_profile_digest: Digest64
    repository: ProtocolString
    source_revision: ObjectId40
    target_branch: ProtocolString
    acceptance_condition_digests: tuple[Digest64, ...]
    excluded_scope_digests: tuple[Digest64, ...]
    required_artifact_digests: tuple[Digest64, ...]
    valid_from: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    created_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _closed_commitment(self) -> JudgmentCommitment:
        for values, label in (
            (self.acceptance_condition_digests, "acceptance_condition_digests"),
            (self.excluded_scope_digests, "excluded_scope_digests"),
            (self.required_artifact_digests, "required_artifact_digests"),
        ):
            _validate_named_nonempty_sorted_unique(values, label)
        if not self.created_at <= self.valid_from < self.expires_at:
            raise ValueError("commitment created/valid/expiry times are not ordered")
        return self


class ActionBindingManifest(SignedProtocolModel):
    _signed_domain = "action-binding-manifest"
    _signed_version = "0.4"

    schema_version: Literal["openworkproof-action-binding-manifest/0.4"]
    binding_manifest_id: Digest64
    work_order_digest: Digest64
    judgment_commitment_id: Digest64
    judgment_commitment_digest: Digest64
    evaluation_scope_id: Digest64
    evaluation_scope_digest: Digest64
    adapter_id: ProtocolString
    adapter_version: ProtocolString
    adapter_profile_digest: Digest64
    allowed_tool_names: tuple[ProtocolString, ...]
    allowed_action_kinds: tuple[Identifier, ...]
    allowed_path_roots: tuple[CanonicalRoot, ...]
    required_test_profile_digests: tuple[Digest64, ...]
    source_revision: ObjectId40
    supersedes_binding_manifest_id: Digest64 | None
    supersedes_binding_manifest_digest: Digest64 | None
    causal_parent_manifest_ids: tuple[Digest64, ...]
    created_at: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _closed_manifest(self) -> ActionBindingManifest:
        for values, label in (
            (self.allowed_tool_names, "allowed_tool_names"),
            (self.allowed_action_kinds, "allowed_action_kinds"),
            (self.allowed_path_roots, "allowed_path_roots"),
            (self.required_test_profile_digests, "required_test_profile_digests"),
        ):
            _validate_named_nonempty_sorted_unique(values, label)
        if any(tool not in _ALL_TOOLS for tool in self.allowed_tool_names):
            raise ValueError("allowed_tool_names contains an unknown tool")
        if not _is_utf8_sorted_unique(self.causal_parent_manifest_ids):
            raise ValueError("causal_parent_manifest_ids must be sorted and unique")
        if (self.supersedes_binding_manifest_id is None) != (
            self.supersedes_binding_manifest_digest is None
        ):
            raise ValueError("supersedes manifest id and digest must be paired")
        expected_parents = (
            ()
            if self.supersedes_binding_manifest_id is None
            else (self.supersedes_binding_manifest_id,)
        )
        if self.causal_parent_manifest_ids != expected_parents:
            raise ValueError("causal manifest parents do not match supersedes")
        if not self.created_at < self.expires_at:
            raise ValueError("manifest created_at must precede expires_at")
        return self


class AuthorityCheckpoint(ProtocolModel):
    schema_version: Literal["openworkproof-authority-checkpoint/0.4"]
    checkpoint_id: Digest64
    authority_namespace: Identifier
    subject_id: Identifier
    monotonic_revision: SafePositiveInt
    current_judgment_commitment_digest: Digest64
    predecessor_checkpoint_digest: Digest64 | None
    effective_at: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    authority_key_id: KeyId
    signature_alg: Literal["Ed25519"]
    signature: Signature
    digest: Digest64

    @model_validator(mode="after")
    def _closed_checkpoint(self) -> AuthorityCheckpoint:
        if (self.monotonic_revision == 1) != (
            self.predecessor_checkpoint_digest is None
        ):
            raise ValueError("checkpoint predecessor does not match revision")
        if not self.effective_at < self.expires_at:
            raise ValueError("checkpoint effective_at must precede expires_at")
        payload = self.model_dump(mode="json", exclude={"digest", "signature"})
        expected_digest = _jcs_digest(
            {
                "domain": "openworkproof/authority-checkpoint/v0.4",
                "payload": payload,
            }
        )
        if self.digest != expected_digest:
            raise ValueError("digest does not match authority checkpoint payload")
        return self


class AgentRequestV04(AgentRequest):
    _signed_domain = "agent-request"
    _signed_version = "0.4"

    schema_version: Literal["openworkproof-agent-request/0.4"]
    judgment_commitment_id: Digest64
    judgment_commitment_digest: Digest64
    action_binding_manifest_id: Digest64
    action_binding_manifest_digest: Digest64


def parse_agent_request(value: object) -> AgentRequest | AgentRequestV04:
    """Parse only the explicitly versioned v0.4 AgentRequest sibling."""

    if type(value) is AgentRequest:
        return value
    if type(value) is AgentRequestV04:
        return value
    if not isinstance(value, Mapping):
        raise ValueError("AgentRequest payload is malformed")
    schema_version = value.get("schema_version")
    if schema_version is None:
        return AgentRequest.model_validate(value)
    if schema_version == "openworkproof-agent-request/0.4":
        return AgentRequestV04.model_validate(value)
    raise ValueError("AgentRequest schema version is unsupported")


class BindingDecisionSignature(ProtocolModel):
    verifier_subject_id: Identifier
    verifier_key_id: KeyId
    signature_alg: Literal["Ed25519"]
    signature: Signature


def _validate_binding_decision_content(
    *,
    action_receipt_ids: tuple[str, ...],
    action_receipt_digests: tuple[str, ...],
    decision: BindingOutcome,
    reason_codes: tuple[BindingReasonCode, ...],
    authority_status: AuthorityStatus,
    authority_checkpoint_digest: str | None,
    causal_parent_decision_ids: tuple[str, ...],
    supersedes_binding_decision_id: str | None,
    supersedes_binding_decision_digest: str | None,
) -> None:
    if not action_receipt_ids or not _is_utf8_sorted_unique(action_receipt_ids):
        raise ValueError("action receipt ids must be non-empty sorted and unique")
    if len(action_receipt_ids) != len(action_receipt_digests):
        raise ValueError("action receipt ids and digests must be one-to-one")
    if len(set(action_receipt_digests)) != len(action_receipt_digests):
        raise ValueError("action receipt digests must be one-to-one")
    if reason_codes != tuple(sorted(set(reason_codes))):
        raise ValueError("binding reason codes must be sorted and unique")
    if decision == "BOUND":
        if reason_codes:
            raise ValueError("BOUND requires no reason codes")
        if authority_status not in {"not_required", "current"}:
            raise ValueError("BOUND requires current or not-required authority")
    else:
        if not reason_codes:
            raise ValueError(f"{decision} requires at least one reason code")
        allowed = (
            _UNBOUND_BINDING_REASONS
            if decision == "UNBOUND"
            else _INDETERMINATE_BINDING_REASONS
        )
        if any(code not in allowed for code in reason_codes):
            raise ValueError(f"reason code is not compatible with {decision}")
    reason_set = set(reason_codes)
    authority_failure_reasons = reason_set.intersection(
        _AUTHORITY_CHECKPOINT_FAILURE_REASONS
    )
    if authority_status == "not_required":
        if authority_checkpoint_digest is not None or authority_failure_reasons:
            raise ValueError(
                "not-required authority forbids checkpoint evidence or failures"
            )
    elif authority_status == "current":
        if authority_checkpoint_digest is None or authority_failure_reasons:
            raise ValueError(
                "current authority requires a checkpoint and no checkpoint failure"
            )
    elif authority_status == "missing":
        if (
            authority_checkpoint_digest is not None
            or authority_failure_reasons != {"AUTHORITY_CHECKPOINT_MISSING"}
        ):
            raise ValueError(
                "missing authority requires only the missing-checkpoint failure"
            )
    elif authority_status == "stale":
        stale_reasons = {
            "AUTHORITY_CHECKPOINT_STALE",
            "AUTHORITY_ROLLBACK_DETECTED",
        }
        if (
            authority_checkpoint_digest is None
            or not authority_failure_reasons.intersection(stale_reasons)
            or not authority_failure_reasons.issubset(stale_reasons)
        ):
            raise ValueError(
                "stale authority requires a checkpoint and stale or rollback failure"
            )
    elif authority_status == "forked":
        if (
            authority_checkpoint_digest is None
            or authority_failure_reasons != {"AUTHORITY_FORK_DETECTED"}
        ):
            raise ValueError(
                "forked authority requires a checkpoint and fork failure"
            )
    elif (
        authority_checkpoint_digest is not None
        or "REPLAY_UNAVAILABLE" not in reason_set
        or authority_failure_reasons
    ):
        raise ValueError(
            "unavailable authority requires replay-unavailable without checkpoint"
        )
    if not _is_utf8_sorted_unique(causal_parent_decision_ids):
        raise ValueError("causal decision parents must be sorted and unique")
    if (supersedes_binding_decision_id is None) != (
        supersedes_binding_decision_digest is None
    ):
        raise ValueError("supersedes decision id and digest must be paired")
    expected_parents = (
        ()
        if supersedes_binding_decision_id is None
        else (supersedes_binding_decision_id,)
    )
    if causal_parent_decision_ids != expected_parents:
        raise ValueError("causal decision parents do not match supersedes")


class BindingDecisionDraft(ProtocolModel):
    binding_decision_id: Digest64
    work_order_digest: Digest64
    judgment_commitment_digest: Digest64
    action_binding_manifest_digest: Digest64
    verification_decision_id: Digest64
    verification_decision_digest: Digest64
    action_receipt_ids: tuple[Digest64, ...]
    action_receipt_digests: tuple[Digest64, ...]
    adapter_replay_digest: Digest64
    authority_checkpoint_digest: Digest64 | None
    decision: BindingOutcome
    reason_codes: tuple[BindingReasonCode, ...]
    authority_status: AuthorityStatus
    causal_parent_decision_ids: tuple[Digest64, ...]
    supersedes_binding_decision_id: Digest64 | None
    supersedes_binding_decision_digest: Digest64 | None
    decided_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _closed_draft(self) -> BindingDecisionDraft:
        _validate_binding_decision_content(
            action_receipt_ids=self.action_receipt_ids,
            action_receipt_digests=self.action_receipt_digests,
            decision=self.decision,
            reason_codes=self.reason_codes,
            authority_status=self.authority_status,
            authority_checkpoint_digest=self.authority_checkpoint_digest,
            causal_parent_decision_ids=self.causal_parent_decision_ids,
            supersedes_binding_decision_id=self.supersedes_binding_decision_id,
            supersedes_binding_decision_digest=(
                self.supersedes_binding_decision_digest
            ),
        )
        return self


class BindingDecision(ProtocolModel):
    schema_version: Literal["openworkproof-binding-decision/0.4"]
    binding_decision_id: Digest64
    work_order_digest: Digest64
    judgment_commitment_digest: Digest64
    action_binding_manifest_digest: Digest64
    verification_decision_id: Digest64
    verification_decision_digest: Digest64
    action_receipt_ids: tuple[Digest64, ...]
    action_receipt_digests: tuple[Digest64, ...]
    adapter_replay_digest: Digest64
    authority_checkpoint_digest: Digest64 | None
    decision: BindingOutcome
    reason_codes: tuple[BindingReasonCode, ...]
    authority_status: AuthorityStatus
    causal_parent_decision_ids: tuple[Digest64, ...]
    supersedes_binding_decision_id: Digest64 | None
    supersedes_binding_decision_digest: Digest64 | None
    decided_at: CanonicalUTCTime
    nonce: Digest64
    verifier_signatures: tuple[BindingDecisionSignature, ...]
    digest: Digest64

    @model_validator(mode="after")
    def _closed_decision(self) -> BindingDecision:
        _validate_binding_decision_content(
            action_receipt_ids=self.action_receipt_ids,
            action_receipt_digests=self.action_receipt_digests,
            decision=self.decision,
            reason_codes=self.reason_codes,
            authority_status=self.authority_status,
            authority_checkpoint_digest=self.authority_checkpoint_digest,
            causal_parent_decision_ids=self.causal_parent_decision_ids,
            supersedes_binding_decision_id=self.supersedes_binding_decision_id,
            supersedes_binding_decision_digest=(
                self.supersedes_binding_decision_digest
            ),
        )
        if not 1 <= len(self.verifier_signatures) <= 2:
            raise ValueError("binding decision requires 1..2 verifier signatures")
        signature_keys = tuple(
            signature.verifier_key_id for signature in self.verifier_signatures
        )
        if not _is_utf8_sorted_unique(signature_keys):
            raise ValueError("decision signatures must be key-sorted and unique")
        signature_subjects = tuple(
            signature.verifier_subject_id
            for signature in self.verifier_signatures
        )
        if len(set(signature_subjects)) != len(signature_subjects):
            raise ValueError("decision signature subjects must be unique")
        payload = self.model_dump(
            mode="json", exclude={"digest", "verifier_signatures"}
        )
        expected_digest = _jcs_digest(
            {
                "domain": "openworkproof/binding-decision/v0.4",
                "payload": payload,
            }
        )
        if self.digest != expected_digest:
            raise ValueError("digest does not match binding decision payload")
        return self


class ApprovalHumanDecision(SignedProtocolModel):
    claim_type: Literal["human-decision"]
    decision_type: Literal["approval_decision"]
    work_order_digest: Digest64
    decision: Literal["approved", "denied"]
    reason: Literal["APPROVAL_GRANTED", "APPROVAL_DENIED"]
    decided_at: CanonicalUTCTime
    actor_id: Identifier
    actor_key_id: KeyId
    request_receipt_id: Digest64
    request_receipt_digest: Digest64
    approved_scope: FrozenDict
    expires_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_decision(self) -> ApprovalHumanDecision:
        if self.signer_key_id != self.actor_key_id:
            raise ValueError("HumanDecision signer must equal actor key")
        expected_reason = (
            "APPROVAL_GRANTED" if self.decision == "approved" else "APPROVAL_DENIED"
        )
        if self.reason != expected_reason:
            raise ValueError("approval decision reason does not match decision")
        return self


class TerminationHumanDecision(SignedProtocolModel):
    claim_type: Literal["human-decision"]
    decision_type: Literal["termination_decision"]
    work_order_digest: Digest64
    decision: Literal["rejected"]
    reason: Literal["MAINTAINER_REJECTED"]
    decided_at: CanonicalUTCTime
    actor_id: Identifier
    actor_key_id: KeyId
    target_work_order_digest: Digest64

    @model_validator(mode="after")
    def _validate_decision(self) -> TerminationHumanDecision:
        if self.signer_key_id != self.actor_key_id:
            raise ValueError("HumanDecision signer must equal actor key")
        if self.target_work_order_digest != self.work_order_digest:
            raise ValueError("termination target must equal WorkOrder digest")
        return self


HumanDecision = Annotated[
    ApprovalHumanDecision | TerminationHumanDecision,
    Field(discriminator="decision_type"),
]


class CompositionCause(ProtocolModel):
    initiator_receipt_digest: Digest64
    composition_report_digest: Digest64
    state_version_before: SafeNonNegativeInt


class ContractExpiredCause(ProtocolModel):
    deadline: CanonicalUTCTime
    observed_at: CanonicalUTCTime
    tip_receipt_digest: Digest64 | None

    @model_validator(mode="after")
    def _validate_observation(self) -> ContractExpiredCause:
        if self.observed_at <= self.deadline:
            raise ValueError("contract expiry observation must be after deadline")
        return self


SystemEventCause = CompositionCause | ContractExpiredCause


class SidecarEvent(ProtocolModel):
    claim_type: Literal["sidecar-event"]
    work_order_digest: Digest64
    event_name: Literal[
        "proof_composed", "contract_expired", "security_violation"
    ]
    cause: SystemEventCause
    input_digest: Digest64
    occurred_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_event(self) -> SidecarEvent:
        if self.event_name == "contract_expired":
            if not isinstance(self.cause, ContractExpiredCause):
                raise ValueError("contract_expired requires its closed cause")
            if self.cause.observed_at != self.occurred_at:
                raise ValueError("expiry observation must equal event time")
        elif not isinstance(self.cause, CompositionCause):
            raise ValueError("composition event requires its closed cause")
        expected = _jcs_digest(
            {
                "domain": "openworkproof/system-event-input/v0.1",
                "event_name": self.event_name,
                "work_order_digest": self.work_order_digest,
                "cause": self.cause,
            }
        )
        if self.input_digest != expected:
            raise ValueError("system-event input digest does not match cause")
        return self


class RepoReadArguments(ProtocolModel):
    path: CanonicalRoot


class ApplyPatchArguments(ProtocolModel):
    target_paths: tuple[CanonicalRoot, ...]
    patch_digest: Digest64
    patch_size_bytes: SafePositiveInt

    @model_validator(mode="after")
    def _validate_arguments(self) -> ApplyPatchArguments:
        if not 1 <= len(self.target_paths) <= 32:
            raise ValueError("target_paths must contain 1..32 paths")
        if not _is_utf8_sorted_unique(self.target_paths):
            raise ValueError("target_paths must be UTF-8 sorted and unique")
        if self.patch_size_bytes > MAX_PATCH_BYTES:
            raise ValueError("patch exceeds MAX_PATCH_BYTES")
        return self


class RunTestsArguments(ProtocolModel):
    test_mode: Literal["developer", "verifier"]
    command_digest: Digest64
    source_commit: ObjectId40
    candidate_commit: ObjectId40
    workspace_manifest_digest: Digest64
    container_image_digest: ImageDigest
    fixed_test_source_digest: Digest64 | None

    @model_validator(mode="after")
    def _validate_mode(self) -> RunTestsArguments:
        if (self.test_mode == "verifier") != (
            self.fixed_test_source_digest is not None
        ):
            raise ValueError("fixed test source does not match test mode")
        return self


class CreatePrProposalArguments(ProtocolModel):
    target_patch_digest: Digest64
    approval_receipt_id: Digest64
    approval_receipt_digest: Digest64


class ComposeProofArguments(ProtocolModel):
    expected_state_version: SafeNonNegativeInt
    previous_report_digest: Digest64 | None


ToolRequestArguments = (
    RepoReadArguments
    | ApplyPatchArguments
    | RunTestsArguments
    | CreatePrProposalArguments
    | ComposeProofArguments
)


class PatchResultEvidence(ProtocolModel):
    schema_version: Literal["openworkproof-patch-result/0.1"]
    parent_commit: ObjectId40
    parent_manifest_digest: Digest64
    candidate_commit: ObjectId40
    workspace_manifest_digest: Digest64
    patch_digest: Digest64
    patch_size_bytes: SafePositiveInt
    replay_profile_digest: Digest64

    @model_validator(mode="after")
    def _validate_size(self) -> PatchResultEvidence:
        if self.patch_size_bytes > MAX_PATCH_BYTES:
            raise ValueError("patch result exceeds MAX_PATCH_BYTES")
        return self


class TestResultEvidence(ProtocolModel):
    schema_version: Literal["openworkproof-test-result/0.1"]
    test_mode: Literal["developer", "verifier"]
    command_digest: Digest64
    source_commit: ObjectId40
    candidate_commit: ObjectId40
    workspace_manifest_digest: Digest64
    container_image_digest: ImageDigest
    fixed_test_source_digest: Digest64 | None
    actual_exit_code: SafeNonNegativeInt

    @model_validator(mode="after")
    def _validate_result(self) -> TestResultEvidence:
        if self.actual_exit_code > 255:
            raise ValueError("actual_exit_code must be in 0..255")
        if (self.test_mode == "verifier") != (
            self.fixed_test_source_digest is not None
        ):
            raise ValueError("fixed test source does not match test mode")
        return self


class ReportDiagnostic(ProtocolModel):
    code: Literal[
        "SHARED_MODEL",
        "SHARED_PROMPT_TEMPLATE",
        "SHARED_CONTEXT_SOURCE",
        "SHARED_TOOLCHAIN",
        "SHARED_EXECUTION_CONTEXT",
        "SHARED_CONTROLLER",
        "SHARED_TEST_SOURCE",
        "MISSING_EVIDENCE_DIMENSION",
        "CAUSAL_INCOMPLETE",
        "INDEPENDENCE_UNSATISFIED",
        "GLOBAL_POSTCONDITION_FAILED",
    ]
    subject_ref: ProtocolString


class CorrelationReference(ProtocolModel):
    receipt_digest: Digest64
    factors: CorrelationFactors


_SHARED_FACTOR_ORDER = (
    "model",
    "prompt_template",
    "context_source",
    "toolchain",
    "execution_context",
    "controller",
    "test_source",
)


class IndependenceAssessment(ProtocolModel):
    policy: Literal["disclose_only", "independent_test_source_required"]
    developer_reference: CorrelationReference
    verifier_reference: CorrelationReference | None
    shared_factors: tuple[
        Literal[
            "model",
            "prompt_template",
            "context_source",
            "toolchain",
            "execution_context",
            "controller",
            "test_source",
        ],
        ...,
    ]
    satisfied: bool

    @model_validator(mode="after")
    def _validate_assessment(self) -> IndependenceAssessment:
        positions = [_SHARED_FACTOR_ORDER.index(value) for value in self.shared_factors]
        if positions != sorted(set(positions)):
            raise ValueError("shared factors must be registry ordered and unique")
        if self.satisfied and self.verifier_reference is None:
            raise ValueError("satisfied assessment requires a verifier reference")
        if self.verifier_reference is None and self.shared_factors:
            raise ValueError("shared factors require a verifier reference")
        expected, _ = _recompute_shared_factors(self)
        if self.shared_factors != expected:
            raise ValueError("shared factors do not match correlation references")
        if self.satisfied and self.policy == "independent_test_source_required":
            developer = self.developer_reference.factors
            verifier = self.verifier_reference
            if verifier is None or (
                developer.execution_context_id
                == verifier.factors.execution_context_id
                or developer.container_instance_id_digest
                == verifier.factors.container_instance_id_digest
                or developer.fixed_test_source_digest is not None
                or verifier.factors.fixed_test_source_digest is None
            ):
                raise ValueError("independent verifier context is not fresh/bound")
        return self


def _recompute_shared_factors(
    assessment: IndependenceAssessment,
) -> tuple[tuple[str, ...], dict[str, Any]]:
    verifier_reference = assessment.verifier_reference
    if verifier_reference is None:
        return (), {}
    developer = assessment.developer_reference.factors
    verifier = verifier_reference.factors
    comparisons: tuple[tuple[str, Any, bool], ...] = (
        (
            "model",
            {"model_id": developer.model_id, "model_version": developer.model_version},
            (developer.model_id, developer.model_version)
            == (verifier.model_id, verifier.model_version),
        ),
        (
            "prompt_template",
            developer.prompt_template_digest,
            developer.prompt_template_digest == verifier.prompt_template_digest,
        ),
        (
            "context_source",
            developer.context_source_digest,
            developer.context_source_digest == verifier.context_source_digest,
        ),
        (
            "toolchain",
            developer.toolchain_id,
            developer.toolchain_id is not None
            and developer.toolchain_id == verifier.toolchain_id,
        ),
        (
            "execution_context",
            {
                "execution_context_id": developer.execution_context_id,
                "container_instance_id_digest": (
                    developer.container_instance_id_digest
                ),
            },
            developer.execution_context_id is not None
            and developer.container_instance_id_digest is not None
            and (
                developer.execution_context_id,
                developer.container_instance_id_digest,
            )
            == (
                verifier.execution_context_id,
                verifier.container_instance_id_digest,
            ),
        ),
        (
            "controller",
            developer.controller_id,
            developer.controller_id == verifier.controller_id,
        ),
        (
            "test_source",
            developer.fixed_test_source_digest,
            developer.fixed_test_source_digest is not None
            and developer.fixed_test_source_digest
            == verifier.fixed_test_source_digest,
        ),
    )
    values = {name: value for name, value, shared in comparisons if shared}
    return tuple(name for name, _, shared in comparisons if shared), values


class FinalArtifact(ProtocolModel):
    active_patch_receipt_digest: Digest64
    candidate_commit: ObjectId40
    workspace_manifest_digest: Digest64


_MCP_ERROR_CODES = Literal[
    "REQUEST_INTEGRITY_INVALID",
    "ROOT_ACTIVATION_INVALID",
    "RECOVERY_REQUIRED",
    "HANDLER_UNAVAILABLE",
    "EVIDENCE_SLOT_UNAVAILABLE",
    "INDEPENDENT_RESULT_NOT_READY",
    "EVIDENCE_FAILURE_SEALED",
    "COMPLETION_RESERVE_UNAVAILABLE",
    "DENIAL_AUDIT_LIMIT_EXCEEDED",
    "BUNDLE_CAPACITY_EXCEEDED",
    "CONTRACT_EXPIRED",
]


class McpErrorEnvelope(ProtocolModel):
    schema_version: Literal["openworkproof-mcp-error/0.1"]
    code: _MCP_ERROR_CODES
    work_order_digest: Digest64 | None
    nonce: Digest64 | None

    @classmethod
    def from_untrusted(
        cls,
        *,
        code: _MCP_ERROR_CODES,
        work_order_digest: Any,
        nonce: Any,
    ) -> McpErrorEnvelope:
        return cls(
            schema_version="openworkproof-mcp-error/0.1",
            code=code,
            work_order_digest=(
                work_order_digest
                if type(work_order_digest) is str
                and _LOWER_HEX_64.fullmatch(work_order_digest)
                else None
            ),
            nonce=(
                nonce
                if type(nonce) is str and _LOWER_HEX_64.fullmatch(nonce)
                else None
            ),
        )

    @classmethod
    def startup_expiry(cls, work_order_digest: str) -> McpErrorEnvelope:
        return cls(
            schema_version="openworkproof-mcp-error/0.1",
            code="CONTRACT_EXPIRED",
            work_order_digest=work_order_digest,
            nonce=None,
        )

    @classmethod
    def request_expiry(
        cls, work_order_digest: str, nonce: str
    ) -> McpErrorEnvelope:
        return cls(
            schema_version="openworkproof-mcp-error/0.1",
            code="CONTRACT_EXPIRED",
            work_order_digest=work_order_digest,
            nonce=nonce,
        )


_TASK_STATES = Literal[
    "issued",
    "running",
    "needs_rework",
    "retrying",
    "locally_verified",
    "evidence_incomplete",
    "proof_ready",
    "awaiting_human",
    "accepted",
    "rejected",
    "frozen",
]

_POLICY_ERROR_CODES = Literal[
    "STATE_DENIED",
    "ROLE_DENIED",
    "CAPABILITY_DENIED",
    "APPROVAL_DENIED",
    "PREDICATE_DENIED",
    "QUOTA_EXHAUSTED",
]
POLICY_ERROR_CODES = frozenset(get_args(_POLICY_ERROR_CODES))

_POLICY_ERROR_CODES_V04 = Literal[
    "STATE_DENIED",
    "ROLE_DENIED",
    "CAPABILITY_DENIED",
    "APPROVAL_DENIED",
    "PREDICATE_DENIED",
    "QUOTA_EXHAUSTED",
    "ACTION_ARGUMENTS_MISMATCH",
    "ACTION_OUTSIDE_APPROVED_SCOPE",
    "ADAPTER_PROFILE_UNSUPPORTED",
    "ALTERNATIVE_WORK_ORDER_DETECTED",
    "AUTH_FRESHNESS_INVALID",
    "AUTH_NONCE_REUSED",
    "AUTH_SIGNATURE_INVALID",
    "AUTH_SUBJECT_MISMATCH",
    "AUTHORITY_CHECKPOINT_MISSING",
    "BINDING_HISTORY_INVALID",
    "BINDING_MANIFEST_EXPIRED",
    "BINDING_MANIFEST_NOT_CURRENT",
    "BINDING_MANIFEST_UNAVAILABLE",
    "BINDING_REFERENCE_MISMATCH",
    "JUDGMENT_EXPIRED",
    "UNSIGNED_METADATA_REFERENCE",
]
POLICY_ERROR_CODES_V04 = frozenset(get_args(_POLICY_ERROR_CODES_V04))

_EXECUTION_ERROR_CODES = Literal[
    "HANDLER_ERROR",
    "OUTPUT_LIMIT",
    "TIMEOUT",
    "DISK_LIMIT",
    "WORKSPACE_INTEGRITY_FAILED",
    "EVIDENCE_POLICY_VIOLATION",
    "ROLLBACK_FAILED",
]

_ALLOWED_RECEIPT_OUTCOMES = {
    "grant_issued": {("allow", "succeeded"), ("deny", "denied")},
    "grant_consumed": {("allow", "succeeded"), ("deny", "denied")},
    "grant_revoked": {("allow", "succeeded"), ("deny", "denied")},
    "tool_call": {
        ("allow", "succeeded"),
        ("allow", "failed"),
        ("deny", "denied"),
    },
    "system_event": {("not_applicable", "succeeded")},
    "approval_requested": {("allow", "succeeded"), ("deny", "denied")},
    "approval_decision": {("allow", "succeeded"), ("deny", "denied")},
    "termination_decision": {("allow", "succeeded"), ("deny", "denied")},
    "rollback": {
        ("allow", "succeeded"),
        ("allow", "failed"),
        ("deny", "denied"),
    },
}


def request_arguments_digest(tool_name: str, arguments: Any) -> str:
    if tool_name not in _ALL_TOOLS:
        raise ValueError("unknown Agent request tool")
    return _jcs_digest(
        {
            "domain": "openworkproof/agent-arguments/v0.1",
            "tool_name": tool_name,
            "arguments": arguments,
        }
    )


class ActionReceiptEnvelope(SignedProtocolModel):
    protocol_version: Literal["0.1"]
    receipt_id: Digest64
    work_order_digest: Digest64
    actor_type: Literal["agent", "human", "sidecar"]
    actor_id: Identifier
    actor_key_id: KeyId
    nested_claim_type: Literal["agent-request", "human-decision", "sidecar-event"]
    nested_claim_digest: Digest64
    nested_claim: (
        AgentRequest
        | ApprovalHumanDecision
        | TerminationHumanDecision
        | SidecarEvent
    )
    gateway_signer_key_id: KeyId
    event_type: Literal[
        "grant_issued",
        "grant_consumed",
        "grant_revoked",
        "tool_call",
        "system_event",
        "approval_requested",
        "approval_decision",
        "termination_decision",
        "rollback",
    ]
    policy_decision: Literal["allow", "deny", "not_applicable"]
    policy_error_code: _POLICY_ERROR_CODES | None
    execution_status: Literal["succeeded", "failed", "denied"]
    execution_error_code: _EXECUTION_ERROR_CODES | None
    quota_charge: QuotaCharge | None
    state_before: _TASK_STATES
    state_after: _TASK_STATES
    parent_receipt_ids: tuple[Digest64, ...]
    correlation_factors: CorrelationFactors | None
    evidence_refs: tuple[EvidenceRef, ...]
    occurred_at: CanonicalUTCTime
    sequence: SafePositiveInt
    nonce: Digest64
    previous_receipt_digest: Digest64 | None

    @model_validator(mode="after")
    def _validate_envelope(self) -> ActionReceiptEnvelope:
        if self.signer_key_id != self.gateway_signer_key_id:
            raise ValueError("receipt signer must equal gateway signer")
        if len(self.parent_receipt_ids) > 16 or len(
            set(self.parent_receipt_ids)
        ) != len(self.parent_receipt_ids):
            raise ValueError("receipt parents exceed bounds or contain duplicates")
        paths = [reference.path for reference in self.evidence_refs]
        if (
            len(paths) > 8
            or paths != sorted(paths, key=lambda value: value.encode("utf-8"))
            or len(set(paths)) != len(paths)
        ):
            raise ValueError("evidence refs must be path-sorted, unique, and bounded")
        pair = (self.policy_decision, self.execution_status)
        if pair not in _ALLOWED_RECEIPT_OUTCOMES[self.event_type]:
            raise ValueError("receipt outcome is not legal for event")
        denied = pair == ("deny", "denied")
        failed = pair == ("allow", "failed")
        if denied != (self.policy_error_code is not None):
            raise ValueError("policy error nullability does not match outcome")
        if failed != (self.execution_error_code is not None):
            raise ValueError("execution error nullability does not match outcome")
        if denied and self.state_before != self.state_after:
            raise ValueError("denied receipt must be same-state")
        if self.event_type != "tool_call" and self.correlation_factors is not None:
            raise ValueError("correlation factors are tool-call-only")
        return self

    def validate_against_work_order(
        self, work_order: WorkOrder
    ) -> ActionReceiptEnvelope:
        bindings = {binding.role: binding for binding in work_order.key_bindings}
        sidecar = bindings["Sidecar"]
        if (
            self.work_order_digest != work_order.digest
            or self.gateway_signer_key_id != sidecar.key_id
            or self.signer_key_id != sidecar.key_id
        ):
            raise ValueError("receipt gateway is not bound to WorkOrder Sidecar")
        if self.actor_type == "sidecar":
            allowed = (sidecar,)
        elif self.actor_type == "human":
            allowed = (bindings["Maintainer"],)
        else:
            allowed = (
                bindings["Manager"],
                bindings["Developer"],
                bindings["Verifier"],
            )
        if not any(
            self.actor_id == binding.subject_id
            and self.actor_key_id == binding.key_id
            for binding in allowed
        ):
            raise ValueError("receipt actor is not bound to WorkOrder")
        return self


class AgentReceiptEnvelope(ActionReceiptEnvelope):
    actor_type: Literal["agent"]
    nested_claim_type: Literal["agent-request"]
    nested_claim: AgentRequest

    def _expected_agent_request(self) -> tuple[str, dict[str, Any], str]:
        raise NotImplementedError

    @model_validator(mode="after")
    def _validate_agent_claim(self) -> AgentReceiptEnvelope:
        claim = self.nested_claim
        if (
            self.nested_claim_digest != claim.digest
            or self.work_order_digest != claim.work_order_digest
            or self.actor_id != claim.actor_id
            or self.actor_key_id != claim.actor_key_id
            or self.nonce != claim.nonce
        ):
            raise ValueError("outer Agent receipt does not match nested claim")
        expected_tool, arguments, expected_grant = self._expected_agent_request()
        if claim.grant_id != expected_grant or claim.tool_name != expected_tool:
            raise ValueError("Agent claim Grant or tool does not match branch")
        expected_digest = request_arguments_digest(expected_tool, arguments)
        if claim.arguments_digest != expected_digest:
            raise ValueError("Agent semantic arguments do not match branch")
        return self


class HumanReceiptEnvelope(ActionReceiptEnvelope):
    actor_type: Literal["human"]
    nested_claim_type: Literal["human-decision"]
    nested_claim: ApprovalHumanDecision | TerminationHumanDecision

    @model_validator(mode="after")
    def _validate_human_claim(self) -> HumanReceiptEnvelope:
        claim = self.nested_claim
        if (
            self.nested_claim_digest != claim.digest
            or self.work_order_digest != claim.work_order_digest
            or self.actor_id != claim.actor_id
            or self.actor_key_id != claim.actor_key_id
        ):
            raise ValueError("outer Human receipt does not match nested claim")
        if self.quota_charge is not None:
            raise ValueError("human decisions never charge quota")
        return self


class GrantIssuedReceipt(AgentReceiptEnvelope):
    event_type: Literal["grant_issued"]
    authorizing_grant_id: Digest64
    candidate_grant_digest: Digest64
    parent_grant_id: Digest64 | None
    issued_grant_id: Digest64 | None = None

    def _expected_agent_request(self) -> tuple[str, dict[str, Any], str]:
        root = self.parent_grant_id is None
        arguments = {
            "operation": "activate_root" if root else "delegate_child",
            "authorizing_grant_id": self.authorizing_grant_id,
            "candidate_grant_digest": self.candidate_grant_digest,
        }
        return (
            "owp.activate_root_grant" if root else "owp.delegate_grant",
            arguments,
            self.authorizing_grant_id,
        )

    @model_validator(mode="after")
    def _validate_issuance(self) -> GrantIssuedReceipt:
        denied = self.policy_decision == "deny"
        field_present = "issued_grant_id" in self.model_fields_set
        if denied:
            if self.parent_grant_id is None or field_present:
                raise ValueError("root denial or denied issued_grant_id is forbidden")
        elif not field_present or self.issued_grant_id is None:
            raise ValueError("successful issuance requires issued_grant_id")
        if self.parent_grant_id is None and (
            self.authorizing_grant_id != self.issued_grant_id
        ):
            raise ValueError("root authorizer and issued Grant must match")
        if self.parent_grant_id is not None and (
            self.parent_grant_id != self.authorizing_grant_id
        ):
            raise ValueError("child parent and authorizer must match")
        if self.quota_charge is not None:
            raise ValueError("grant issuance does not carry a direct charge")
        return self

    def validate_candidate(self, candidate: CapabilityGrant) -> GrantIssuedReceipt:
        if (
            candidate.digest != self.candidate_grant_digest
            or candidate.parent_grant_id != self.parent_grant_id
            or (
                self.policy_decision == "allow"
                and candidate.grant_id != self.issued_grant_id
            )
        ):
            raise ValueError("candidate Grant does not match issuance receipt")
        return self

    @model_serializer(mode="wrap")
    def _serialize_conditional_fields(self, handler: Any) -> dict[str, Any]:
        data = handler(self)
        if "issued_grant_id" not in self.model_fields_set:
            data.pop("issued_grant_id", None)
        return data


class GrantConsumedReceipt(AgentReceiptEnvelope):
    event_type: Literal["grant_consumed"]
    grant_id: Digest64
    metric: Literal["repair_rounds"]
    amount: SafePositiveInt
    remaining_after: SafeNonNegativeInt | None

    def _expected_agent_request(self) -> tuple[str, dict[str, Any], str]:
        return (
            "owp.start_retry",
            {"grant_id": self.grant_id, "metric": self.metric, "amount": self.amount},
            self.grant_id,
        )

    @model_validator(mode="after")
    def _validate_consumption(self) -> GrantConsumedReceipt:
        if self.policy_decision == "deny":
            if self.remaining_after is not None or self.quota_charge is not None:
                raise ValueError("denied consumption cannot charge quota")
        else:
            charge = self.quota_charge
            if charge is None or (
                charge.grant_id,
                charge.metric,
                charge.amount,
                charge.remaining_after,
            ) != (
                self.grant_id,
                self.metric,
                self.amount,
                self.remaining_after,
            ):
                raise ValueError("grant consumption charge does not match branch")
        return self


class GrantRevokedReceipt(AgentReceiptEnvelope):
    event_type: Literal["grant_revoked"]
    authorizing_grant_id: Digest64
    revoked_grant_id: Digest64
    revocation_reason: Literal["LEAST_PRIVILEGE", "SUPERSEDED", "WORK_STOPPED"]

    def _expected_agent_request(self) -> tuple[str, dict[str, Any], str]:
        return (
            "owp.revoke_grant",
            {
                "authorizing_grant_id": self.authorizing_grant_id,
                "revoked_grant_id": self.revoked_grant_id,
                "revocation_reason": self.revocation_reason,
            },
            self.authorizing_grant_id,
        )

    @model_validator(mode="after")
    def _validate_revocation(self) -> GrantRevokedReceipt:
        if self.quota_charge is not None:
            raise ValueError("grant revocation does not carry a direct charge")
        return self


class ToolCallReceipt(AgentReceiptEnvelope):
    event_type: Literal["tool_call"]
    grant_id: Digest64
    tool_name: Literal[
        "owp.repo_read",
        "owp.apply_patch",
        "owp.run_tests",
        "owp.create_pr_proposal",
        "owp.compose_proof",
    ]
    tool_version: Literal["0.1"]
    request_arguments: ToolRequestArguments
    arguments_digest: Digest64
    output_digest: Digest64 | None
    predicate_results: tuple[PredicateResult, ...]
    approval_receipt_id: Digest64 | None = None
    approval_receipt_digest: Digest64 | None = None

    def _expected_agent_request(self) -> tuple[str, dict[str, Any], str]:
        return (
            self.tool_name,
            self.request_arguments.model_dump(mode="json"),
            self.grant_id,
        )

    @model_validator(mode="after")
    def _validate_tool_call(self) -> ToolCallReceipt:
        expected_types = {
            "owp.repo_read": RepoReadArguments,
            "owp.apply_patch": ApplyPatchArguments,
            "owp.run_tests": RunTestsArguments,
            "owp.create_pr_proposal": CreatePrProposalArguments,
            "owp.compose_proof": ComposeProofArguments,
        }
        if not isinstance(self.request_arguments, expected_types[self.tool_name]):
            raise ValueError("request arguments do not match registered tool")
        if len(rfc8785.dumps(_jsonable(self.request_arguments))) > 65_536:
            raise ValueError("request_arguments exceeds 64 KiB")
        expected_arguments_digest = request_arguments_digest(
            self.tool_name, self.request_arguments
        )
        if (
            self.arguments_digest != expected_arguments_digest
            or self.nested_claim.arguments_digest != self.arguments_digest
        ):
            raise ValueError("tool arguments digest does not match request")
        ids = [result.predicate_id for result in self.predicate_results]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise ValueError("predicate results must be sorted and unique")

        high_risk = self.tool_name == "owp.create_pr_proposal"
        approval_fields = {
            "approval_receipt_id",
            "approval_receipt_digest",
        }
        present = approval_fields.issubset(self.model_fields_set)
        any_present = bool(approval_fields.intersection(self.model_fields_set))
        if high_risk:
            args = self.request_arguments
            if (
                not present
                or self.approval_receipt_id is None
                or self.approval_receipt_digest is None
                or not isinstance(args, CreatePrProposalArguments)
                or args.approval_receipt_id != self.approval_receipt_id
                or args.approval_receipt_digest != self.approval_receipt_digest
            ):
                raise ValueError("high-risk tool requires exact approval references")
        elif any_present:
            raise ValueError("low-risk tool forbids approval references")

        denied = self.policy_decision == "deny"
        failed = self.execution_status == "failed"
        factors = self.correlation_factors
        if factors is None:
            raise ValueError("tool call requires correlation factors")
        if (
            factors.model_id,
            factors.model_version,
            factors.prompt_template_digest,
            factors.context_source_digest,
        ) != (
            self.nested_claim.model_id,
            self.nested_claim.model_version,
            self.nested_claim.prompt_template_digest,
            self.nested_claim.context_source_digest,
        ):
            raise ValueError("correlation disclosure does not match AgentRequest")
        control_tool = self.tool_name in {
            "owp.create_pr_proposal",
            "owp.compose_proof",
        }
        derived = (
            factors.toolchain_id,
            factors.execution_context_id,
            factors.container_instance_id_digest,
        )
        if denied or control_tool:
            if any(value is not None for value in derived) or (
                factors.fixed_test_source_digest is not None
            ):
                raise ValueError("non-started/control tool cannot claim container context")
            if failed:
                raise ValueError("control tools cannot produce failed receipts")
        elif any(value is None for value in derived):
            raise ValueError("started container tool requires runtime correlation")

        if isinstance(self.request_arguments, RunTestsArguments) and not denied:
            if (
                factors.fixed_test_source_digest
                != self.request_arguments.fixed_test_source_digest
            ):
                raise ValueError("fixed test correlation does not match request")
        elif not isinstance(self.request_arguments, RunTestsArguments) and (
            factors.fixed_test_source_digest is not None
        ):
            raise ValueError("fixed test digest is run_tests-only")

        if denied:
            if self.output_digest is not None or self.quota_charge is not None:
                raise ValueError("denied tool has no output or quota charge")
        else:
            charge = self.quota_charge
            if charge is None or (
                charge.grant_id != self.grant_id
                or charge.metric != "tool_calls"
                or charge.amount != 1
            ):
                raise ValueError("started tool requires exact tool_calls charge")
            if self.output_digest is None:
                raise ValueError("started tool requires a closed output digest")
            if failed:
                expected = _jcs_digest(
                    {
                        "status": "failed",
                        "error_code": self.execution_error_code,
                    }
                )
                if self.output_digest != expected:
                    raise ValueError("failed tool output digest is not redacted form")
            elif self.tool_name == "owp.create_pr_proposal":
                expected = _jcs_digest(
                    {
                        "status": "local_pr_proposal_created",
                        "target_patch_digest": self.request_arguments.target_patch_digest,
                    }
                )
                if self.output_digest != expected:
                    raise ValueError("PR proposal output digest does not match")
            elif self.tool_name == "owp.compose_proof":
                if self.output_digest != _jcs_digest(
                    {"status": "composition_request_accepted"}
                ):
                    raise ValueError("composition output digest does not match")

        refs = self.evidence_refs
        if self.tool_name == "owp.apply_patch":
            expected_ref_count = 1 if denied or failed else 2
            if len(refs) != expected_ref_count:
                raise ValueError("apply_patch evidence publication shape is invalid")
            diff_refs = [ref for ref in refs if ref.media_type == "text/x-diff"]
            json_refs = [ref for ref in refs if ref.media_type == "application/json"]
            if len(diff_refs) != 1 or (
                not (denied or failed) and len(json_refs) != 1
            ) or ((denied or failed) and json_refs):
                raise ValueError("apply_patch evidence media pair is invalid")
            args = self.request_arguments
            if not isinstance(args, ApplyPatchArguments) or (
                diff_refs[0].sha256 != args.patch_digest
                or diff_refs[0].size_bytes != args.patch_size_bytes
            ):
                raise ValueError("patch EvidenceRef does not match request")
            if not (denied or failed) and self.output_digest != json_refs[0].sha256:
                raise ValueError("patch output digest does not match result ref")
        elif self.tool_name == "owp.run_tests":
            if self.execution_status == "succeeded":
                if (
                    len(refs) != 1
                    or refs[0].media_type != "application/json"
                    or self.output_digest != refs[0].sha256
                ):
                    raise ValueError("run_tests result EvidenceRef is invalid")
            elif refs:
                raise ValueError("non-successful run_tests publishes no result")
        elif refs:
            raise ValueError("tool does not publish evidence")
        return self

    def validate_against_work_order(self, work_order: WorkOrder) -> ToolCallReceipt:
        super().validate_against_work_order(work_order)
        sidecar = next(
            binding
            for binding in work_order.key_bindings
            if binding.role == "Sidecar"
        )
        factors = self.correlation_factors
        if (
            factors is None
            or factors.controller_id != sidecar.key_id
            or self.gateway_signer_key_id != factors.controller_id
        ):
            raise ValueError(
                "tool controller and gateway signer must equal WorkOrder Sidecar"
            )
        return self

    def validate_predicates_against(self, work_order: WorkOrder) -> ToolCallReceipt:
        pre = tuple(
            spec
            for spec in work_order.preconditions + work_order.invariants
            if self.tool_name in spec.applies_to_tools
        )
        post: tuple[PredicateSpec, ...] = ()
        if (
            self.tool_name == "owp.run_tests"
            and isinstance(self.request_arguments, RunTestsArguments)
            and self.request_arguments.test_mode == "verifier"
            and self.policy_decision == "allow"
        ):
            post = tuple(
                spec
                for spec in work_order.postconditions
                if self.tool_name in spec.applies_to_tools
            )
        expected = sorted(pre + post, key=lambda spec: spec.predicate_id)
        if [item.predicate_id for item in self.predicate_results] != [
            item.predicate_id for item in expected
        ]:
            raise ValueError("predicate stage set does not match WorkOrder")
        for result, spec in zip(self.predicate_results, expected, strict=True):
            result.validate_against(spec)
            if spec in pre and self.policy_decision == "allow" and not result.passed:
                raise ValueError("failed precondition/invariant cannot authorize")
            if (
                spec in post
                and self.execution_status == "failed"
                and (result.passed or result.error_code != "FAIL_CLOSED")
            ):
                raise ValueError("failed Verifier postconditions must fail closed")
        return self

    def validate_handler_output(self, output: Any) -> ToolCallReceipt:
        if self.execution_status != "succeeded" or self.output_digest is None:
            raise ValueError("only successful tool output can be validated")
        if self.tool_name == "owp.repo_read":
            parsed = RepoReadOutput.model_validate(output)
            expected = _jcs_digest(
                {
                    "domain": "openworkproof/repo-read-output/v0.1",
                    "output": parsed,
                }
            )
        elif self.tool_name == "owp.create_pr_proposal":
            if not isinstance(output, Mapping):
                raise ValueError("PR proposal output must be a closed object")
            parsed = FrozenDict(output)
            expected_object = {
                "status": "local_pr_proposal_created",
                "target_patch_digest": self.request_arguments.target_patch_digest,
            }
            if dict(parsed) != expected_object:
                raise ValueError("PR proposal output is not the closed result")
            expected = _jcs_digest(parsed)
        elif self.tool_name == "owp.compose_proof":
            if output != {"status": "composition_request_accepted"}:
                raise ValueError("composition output is not the closed result")
            expected = _jcs_digest(output)
        else:
            raise ValueError("tool output is validated through evidence bytes")
        if self.output_digest != expected:
            raise ValueError("handler output digest does not match receipt")
        return self

    def validate_evidence_payloads(
        self,
        payloads: Mapping[str, bytes],
        work_order: WorkOrder,
    ) -> ToolCallReceipt:
        if set(payloads) != {reference.path for reference in self.evidence_refs}:
            raise ValueError("evidence payload set does not match receipt refs")
        policy_slots = {
            f"{work_order.evidence_policy.evidence_root}/{artifact.path}": artifact
            for artifact in work_order.evidence_policy.artifacts
        }
        referenced_slots: dict[str, Artifact] = {}
        for reference in self.evidence_refs:
            slot = policy_slots.get(reference.path)
            if slot is None or (
                slot.media_type != reference.media_type
                or reference.size_bytes > slot.max_size_bytes
            ):
                raise ValueError("evidence ref is not bound to a WorkOrder slot")
            referenced_slots[reference.path] = slot
            payload = payloads[reference.path]
            if type(payload) is not bytes:
                raise ValueError("evidence payload must be exact bytes")
            if (
                len(payload) != reference.size_bytes
                or hashlib.sha256(payload).hexdigest() != reference.sha256
            ):
                raise ValueError("evidence payload does not match reference")
        if self.tool_name == "owp.apply_patch":
            diff_ref = next(
                ref for ref in self.evidence_refs if ref.media_type == "text/x-diff"
            )
            diff_slot = referenced_slots[diff_ref.path]
            expected_diff_purpose = (
                "patch_denial_audit"
                if self.policy_decision == "deny"
                else "patch_input"
            )
            if diff_slot.purpose != expected_diff_purpose:
                raise ValueError("patch evidence ref has the wrong slot purpose")

        if self.tool_name == "owp.apply_patch" and self.execution_status == "succeeded":
            json_ref = next(
                ref
                for ref in self.evidence_refs
                if ref.media_type == "application/json"
            )
            result_slot = referenced_slots[json_ref.path]
            if (
                result_slot.purpose != "patch_result"
                or result_slot.ordinal != diff_slot.ordinal
            ):
                raise ValueError("patch result slot must match patch input ordinal")
            result = PatchResultEvidence.model_validate(
                _load_canonical_json(payloads[json_ref.path])
            )
            args = self.request_arguments
            if not isinstance(args, ApplyPatchArguments) or (
                result.patch_digest != args.patch_digest
                or result.patch_size_bytes != args.patch_size_bytes
                or result.replay_profile_digest != work_order.replay_profile_digest
                or hashlib.sha256(payloads[diff_ref.path]).hexdigest()
                != result.patch_digest
            ):
                raise ValueError("PatchResultEvidence does not match request/context")
        elif self.tool_name == "owp.run_tests" and self.execution_status == "succeeded":
            result_ref = self.evidence_refs[0]
            args = self.request_arguments
            if not isinstance(args, RunTestsArguments):
                raise ValueError("run_tests request arguments are invalid")
            expected_purpose = (
                "verifier_result"
                if args.test_mode == "verifier"
                else "developer_test_result"
            )
            # The slot-to-episode mapping is strictly one-to-one: an
            # evidence_incomplete prior state is the independent episode
            # signature and must use the verifier_independent_result slot
            # exclusively; every primary-episode Verifier receipt must use
            # the verifier_result slot.
            if args.test_mode == "verifier":
                if self.state_before == "evidence_incomplete":
                    allowed = {"verifier_independent_result"}
                else:
                    allowed = {"verifier_result"}
                if referenced_slots[result_ref.path].purpose not in allowed:
                    raise ValueError(
                        "test result evidence has the wrong slot purpose"
                    )
            else:
                if referenced_slots[result_ref.path].purpose != expected_purpose:
                    raise ValueError(
                        "test result evidence has the wrong slot purpose"
                    )
            result = TestResultEvidence.model_validate(
                _load_canonical_json(payloads[result_ref.path])
            )
            profile = next(
                (
                    profile
                    for profile in work_order.test_profiles
                    if profile.test_mode == args.test_mode
                ),
                None,
            )
            if profile is None or (
                result.test_mode,
                result.command_digest,
                result.source_commit,
                result.candidate_commit,
                result.workspace_manifest_digest,
                result.container_image_digest,
                result.fixed_test_source_digest,
            ) != (
                args.test_mode,
                args.command_digest,
                args.source_commit,
                args.candidate_commit,
                args.workspace_manifest_digest,
                args.container_image_digest,
                args.fixed_test_source_digest,
            ) or (
                args.command_digest != profile.command_digest
                or args.source_commit != work_order.source_commit
                or args.container_image_digest != profile.container_image_digest
                or args.fixed_test_source_digest != profile.fixed_test_source_digest
            ):
                raise ValueError("TestResultEvidence does not match request/profile")
        return self

    @model_serializer(mode="wrap")
    def _serialize_conditional_fields(self, handler: Any) -> dict[str, Any]:
        data = handler(self)
        for field_name in ("approval_receipt_id", "approval_receipt_digest"):
            if field_name not in self.model_fields_set:
                data.pop(field_name, None)
        return data


def _load_canonical_json(payload: bytes) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("evidence JSON is invalid") from error
    if rfc8785.dumps(value) != payload:
        raise ValueError("evidence JSON is not canonical JCS")
    return value


class RepoReadOutput(ProtocolModel):
    path: CanonicalRoot
    content_sha256: Digest64
    size_bytes: SafeNonNegativeInt
    workspace_manifest_digest: Digest64

    @model_validator(mode="after")
    def _validate_size(self) -> RepoReadOutput:
        if self.size_bytes > 65_536:
            raise ValueError("repo_read output exceeds 64 KiB")
        return self


class SystemEventReceipt(ActionReceiptEnvelope):
    event_type: Literal["system_event"]
    actor_type: Literal["sidecar"]
    nested_claim_type: Literal["sidecar-event"]
    nested_claim: SidecarEvent
    system_event_name: Literal[
        "proof_composed", "contract_expired", "security_violation"
    ]
    cause: SystemEventCause
    input_digest: Digest64
    error_code: Literal["CONTRACT_EXPIRED", "SECURITY_VIOLATION"] | None

    @model_validator(mode="after")
    def _validate_system_event(self) -> SystemEventReceipt:
        claim = self.nested_claim
        if (
            self.actor_key_id != self.gateway_signer_key_id
            or self.nested_claim_digest != claim.input_digest
            or self.work_order_digest != claim.work_order_digest
            or self.system_event_name != claim.event_name
            or self.cause != claim.cause
            or self.input_digest != claim.input_digest
            or self.occurred_at != claim.occurred_at
            or self.quota_charge is not None
            or self.correlation_factors is not None
        ):
            raise ValueError("system event does not match Sidecar claim")
        if self.system_event_name == "proof_composed":
            if (
                self.error_code is not None
                or not isinstance(self.cause, CompositionCause)
                or self.state_after not in {"evidence_incomplete", "proof_ready"}
                or self.state_before not in {"locally_verified", "evidence_incomplete"}
            ):
                raise ValueError("proof_composed name/error/state matrix is invalid")
        elif self.system_event_name == "security_violation":
            if (
                self.error_code != "SECURITY_VIOLATION"
                or not isinstance(self.cause, CompositionCause)
                or self.state_before
                not in {"locally_verified", "evidence_incomplete"}
                or self.state_after != "frozen"
            ):
                raise ValueError("security_violation matrix is invalid")
        elif (
            self.error_code != "CONTRACT_EXPIRED"
            or not isinstance(self.cause, ContractExpiredCause)
            or self.state_before
            not in {
                "issued",
                "running",
                "needs_rework",
                "retrying",
                "locally_verified",
                "evidence_incomplete",
                "proof_ready",
                "awaiting_human",
            }
            or self.state_after != "frozen"
        ):
            raise ValueError("contract_expired matrix is invalid")
        if self.state_before == self.state_after:
            raise ValueError("system events cannot be same-state")
        return self


class ApprovalRequestedReceipt(AgentReceiptEnvelope):
    event_type: Literal["approval_requested"]
    grant_id: Digest64
    request_kind: Literal["high_risk_action", "final_acceptance"]
    target_action_digest: Digest64
    required_role: Literal["Maintainer", "Acceptor"]
    requested_scope: FrozenDict
    expires_at: CanonicalUTCTime

    def _expected_agent_request(self) -> tuple[str, dict[str, Any], str]:
        return (
            (
                "owp.request_acceptance"
                if self.request_kind == "final_acceptance"
                else "owp.request_pr_proposal"
            ),
            {
                "request_kind": self.request_kind,
                "target_action_digest": self.target_action_digest,
                "required_role": self.required_role,
                "requested_scope": self.requested_scope,
                "expires_at": _serialize_canonical_time(self.expires_at),
            },
            self.grant_id,
        )

    @model_validator(mode="after")
    def _validate_request(self) -> ApprovalRequestedReceipt:
        scope = dict(self.requested_scope)
        if self.request_kind == "high_risk_action":
            if set(scope) != {
                "work_order_digest",
                "operation",
                "target_patch_digest",
            } or scope.get("work_order_digest") != self.work_order_digest or scope.get(
                "operation"
            ) != "create_local_pr_proposal":
                raise ValueError("high-risk approval scope is invalid")
            expected = _jcs_digest(
                {
                    "domain": "openworkproof/high-risk-action/v0.1",
                    "tool_name": "owp.create_pr_proposal",
                    "requested_scope": self.requested_scope,
                }
            )
        else:
            if set(scope) != {
                "work_order_digest",
                "operation",
                "composition_report_digest",
            } or scope.get("work_order_digest") != self.work_order_digest or scope.get(
                "operation"
            ) != "submit_final_acceptance":
                raise ValueError("final acceptance scope is invalid")
            expected = _jcs_digest(
                {
                    "domain": "openworkproof/final-acceptance-action/v0.1",
                    "requested_scope": self.requested_scope,
                }
            )
        if self.target_action_digest != expected:
            raise ValueError("approval target_action_digest does not match scope")
        expected_role = (
            "Maintainer"
            if self.request_kind == "high_risk_action"
            else "Acceptor"
        )
        if self.required_role != expected_role:
            raise ValueError("approval request role does not match request kind")
        if self.policy_decision == "deny":
            if self.quota_charge is not None:
                raise ValueError("denied approval request cannot charge quota")
        else:
            charge = self.quota_charge
            if charge is None or (
                charge.grant_id != self.grant_id
                or charge.metric != "tool_calls"
                or charge.amount != 1
            ):
                raise ValueError("successful approval request requires exact charge")
        return self


class ApprovalDecisionReceipt(HumanReceiptEnvelope):
    event_type: Literal["approval_decision"]
    nested_claim: ApprovalHumanDecision
    request_receipt_id: Digest64
    request_receipt_digest: Digest64
    decision: Literal["approved", "denied"]
    approved_scope: FrozenDict
    expires_at: CanonicalUTCTime
    decision_reason: Literal["APPROVAL_GRANTED", "APPROVAL_DENIED"]
    decided_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_approval(self) -> ApprovalDecisionReceipt:
        claim = self.nested_claim
        if (
            claim.decision_type != self.event_type
            or claim.request_receipt_id != self.request_receipt_id
            or claim.request_receipt_digest != self.request_receipt_digest
            or claim.decision != self.decision
            or claim.approved_scope != self.approved_scope
            or claim.expires_at != self.expires_at
            or claim.reason != self.decision_reason
            or claim.decided_at != self.decided_at
        ):
            raise ValueError("approval branch does not match HumanDecision")
        return self


class TerminationDecisionReceipt(HumanReceiptEnvelope):
    event_type: Literal["termination_decision"]
    nested_claim: TerminationHumanDecision
    target_work_order_digest: Digest64
    decision: Literal["rejected"]
    termination_reason: Literal["MAINTAINER_REJECTED"]
    decided_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_termination(self) -> TerminationDecisionReceipt:
        claim = self.nested_claim
        if (
            claim.decision_type != self.event_type
            or self.target_work_order_digest != self.work_order_digest
            or claim.target_work_order_digest != self.target_work_order_digest
            or claim.decision != self.decision
            or claim.reason != self.termination_reason
            or claim.decided_at != self.decided_at
        ):
            raise ValueError("termination branch does not match HumanDecision")
        return self


class RollbackReceipt(AgentReceiptEnvelope):
    event_type: Literal["rollback"]
    grant_id: Digest64
    target_patch_receipt_id: Digest64
    target_patch_digest: Digest64
    before_commit: ObjectId40
    after_commit: ObjectId40
    after_manifest_digest: Digest64 | None
    rollback_result: Literal["succeeded", "failed", "denied"]

    def _expected_agent_request(self) -> tuple[str, dict[str, Any], str]:
        return (
            "owp.rollback_patch",
            {
                "target_patch_receipt_id": self.target_patch_receipt_id,
                "target_patch_digest": self.target_patch_digest,
                "before_commit": self.before_commit,
            },
            self.grant_id,
        )

    @model_validator(mode="after")
    def _validate_rollback(self) -> RollbackReceipt:
        if self.rollback_result != self.execution_status:
            raise ValueError("rollback_result must mirror execution_status")
        if self.execution_status == "denied":
            if (
                self.after_commit != self.before_commit
                or self.after_manifest_digest is not None
                or self.quota_charge is not None
            ):
                raise ValueError("denied rollback must not start")
        else:
            charge = self.quota_charge
            if charge is None or (
                charge.grant_id != self.grant_id
                or charge.metric != "tool_calls"
                or charge.amount != 1
            ):
                raise ValueError("started rollback requires exact charge")
            if self.execution_status == "failed" and (
                self.after_commit != self.before_commit
                or self.after_manifest_digest is None
            ):
                raise ValueError("failed rollback must preserve candidate")
            if self.execution_status == "succeeded" and (
                self.after_commit == self.before_commit
                or self.after_manifest_digest is None
            ):
                raise ValueError("successful rollback must restore parent")
        return self

    def validate_target_patch(
        self,
        target: ToolCallReceipt,
        result: PatchResultEvidence,
    ) -> RollbackReceipt:
        if (
            target.tool_name != "owp.apply_patch"
            or target.policy_decision != "allow"
            or target.execution_status != "succeeded"
            or self.target_patch_receipt_id != target.receipt_id
            or self.target_patch_digest != target.digest
            or self.before_commit != result.candidate_commit
        ):
            raise ValueError("rollback target is not the referenced successful patch")
        if self.execution_status == "failed" and (
            self.after_commit != result.candidate_commit
            or self.after_manifest_digest != result.workspace_manifest_digest
        ):
            raise ValueError("failed rollback does not preserve candidate context")
        if self.execution_status == "succeeded" and (
            self.after_commit != result.parent_commit
            or self.after_manifest_digest != result.parent_manifest_digest
        ):
            raise ValueError("successful rollback does not restore parent context")
        return self


class ToolCallReceiptV04(ToolCallReceipt):
    """Native v0.4 tool receipt with an explicit bound AgentRequest."""

    protocol_version: Literal["0.4"]
    nested_claim: AgentRequestV04
    policy_error_code: _POLICY_ERROR_CODES_V04 | None


class RollbackReceiptV04(RollbackReceipt):
    """Native v0.4 rollback receipt with an explicit bound AgentRequest."""

    protocol_version: Literal["0.4"]
    nested_claim: AgentRequestV04
    policy_error_code: _POLICY_ERROR_CODES_V04 | None


ActionReceipt = Annotated[
    GrantIssuedReceipt
    | GrantConsumedReceipt
    | GrantRevokedReceipt
    | ToolCallReceipt
    | SystemEventReceipt
    | ApprovalRequestedReceipt
    | ApprovalDecisionReceipt
    | TerminationDecisionReceipt
    | RollbackReceipt,
    Field(discriminator="event_type"),
]

# Low-level structural parser only. Protocol entrypoints must additionally bind
# the parsed receipt to its WorkOrder via validate_receipt_or_error().
ACTION_RECEIPT_ADAPTER = TypeAdapter(ActionReceipt)

ActionReceiptV04 = Annotated[
    ToolCallReceiptV04 | RollbackReceiptV04,
    Field(discriminator="event_type"),
]
ACTION_RECEIPT_V04_ADAPTER = TypeAdapter(ActionReceiptV04)


def action_receipt_adapter(value: Any) -> TypeAdapter:
    """Select the exact frozen receipt parser from an explicit version field."""

    source = (
        value.model_dump(mode="json")
        if isinstance(value, BaseModel)
        else value
    )
    if not isinstance(source, Mapping):
        raise ValueError("ActionReceipt must be an object")
    version = source.get("protocol_version")
    if version == "0.1":
        return ACTION_RECEIPT_ADAPTER
    if version == "0.4":
        return ACTION_RECEIPT_V04_ADAPTER
    raise ValueError("unsupported ActionReceipt protocol version")


def parse_action_receipt(value: Any) -> ActionReceipt | ActionReceiptV04:
    return action_receipt_adapter(value).validate_python(value)


def parse_action_receipt_json(
    value: str | bytes,
) -> ActionReceipt | ActionReceiptV04:
    try:
        decoded = json.loads(value)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("ActionReceipt JSON is invalid") from error
    return action_receipt_adapter(decoded).validate_json(value)


def validate_receipt_or_error(
    value: Any,
    *,
    work_order: WorkOrder | None = None,
) -> ActionReceipt | ActionReceiptV04 | McpErrorEnvelope:
    try:
        receipt = parse_action_receipt(value)
        if not isinstance(work_order, WorkOrder):
            raise ValueError("WorkOrder context is required")
        receipt.validate_against_work_order(work_order)
        if isinstance(receipt, ToolCallReceipt):
            receipt.validate_predicates_against(work_order)
        return receipt
    except (ValidationError, ValueError):
        source = value if isinstance(value, Mapping) else {}
        return McpErrorEnvelope.from_untrusted(
            code="REQUEST_INTEGRITY_INVALID",
            work_order_digest=source.get("work_order_digest"),
            nonce=source.get("nonce"),
        )


_WARNING_CODES = {
    "SHARED_MODEL",
    "SHARED_PROMPT_TEMPLATE",
    "SHARED_CONTEXT_SOURCE",
    "SHARED_TOOLCHAIN",
    "SHARED_EXECUTION_CONTEXT",
    "SHARED_CONTROLLER",
    "SHARED_TEST_SOURCE",
}


class CompositionReport(ProtocolModel):
    schema_version: Literal["openworkproof-composition-report/0.1"]
    work_order_digest: Digest64
    initiator_receipt_id: Digest64
    initiator_receipt_digest: Digest64
    final_artifact: FinalArtifact
    artifact_digests: tuple[EvidenceRef, ...]
    evidence_snapshot_digest: Digest64
    receipt_digests: tuple[Digest64, ...]
    causal_graph_root: Digest64
    causal_complete: bool
    evidence_coverage: FrozenDict
    independence_assessment: IndependenceAssessment
    test_evidence_refs: tuple[EvidenceRef, ...]
    unresolved_failures: tuple[ReportDiagnostic, ...]
    warnings: tuple[ReportDiagnostic, ...]
    global_postconditions: tuple[PredicateResult, ...]
    global_postconditions_satisfied: bool
    verifier_conclusion: Literal["proof_ready", "evidence_incomplete"]
    composed_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_report(self) -> CompositionReport:
        coverage = dict(self.evidence_coverage)
        if (
            not coverage
            or not set(coverage).issubset(_EVIDENCE_DIMENSIONS)
            or any(type(value) is not bool for value in coverage.values())
        ):
            raise ValueError("report evidence coverage must be closed")
        for values, key in (
            (self.artifact_digests, lambda item: item.path.encode("utf-8")),
            (self.test_evidence_refs, lambda item: item.path.encode("utf-8")),
            (
                self.warnings,
                lambda item: (
                    item.code.encode("utf-8"),
                    item.subject_ref.encode("utf-8"),
                ),
            ),
            (
                self.unresolved_failures,
                lambda item: (
                    item.code.encode("utf-8"),
                    item.subject_ref.encode("utf-8"),
                ),
            ),
            (
                self.global_postconditions,
                lambda item: item.predicate_id.encode("utf-8"),
            ),
        ):
            keys = [key(item) for item in values]
            if keys != sorted(keys) or len(keys) != len(set(keys)):
                raise ValueError("report arrays must be sorted and unique")
        if (
            not self.receipt_digests
            or len(set(self.receipt_digests)) != len(self.receipt_digests)
        ):
            raise ValueError("report receipt digests must be non-empty and unique")
        if any(item.code not in _WARNING_CODES for item in self.warnings):
            raise ValueError("report warnings use the warning registry only")
        shared_factors, shared_values = _recompute_shared_factors(
            self.independence_assessment
        )
        warning_codes = {
            "model": "SHARED_MODEL",
            "prompt_template": "SHARED_PROMPT_TEMPLATE",
            "context_source": "SHARED_CONTEXT_SOURCE",
            "toolchain": "SHARED_TOOLCHAIN",
            "execution_context": "SHARED_EXECUTION_CONTEXT",
            "controller": "SHARED_CONTROLLER",
            "test_source": "SHARED_TEST_SOURCE",
        }
        expected_warnings = tuple(
            sorted(
                (
                    ReportDiagnostic(
                        code=warning_codes[factor],
                        subject_ref=_jcs_digest(
                            {
                                "domain": "openworkproof/shared-factor-ref/v0.1",
                                "factor": factor,
                                "value": shared_values[factor],
                            }
                        ),
                    )
                    for factor in shared_factors
                ),
                key=lambda item: (
                    item.code.encode("utf-8"),
                    item.subject_ref.encode("utf-8"),
                ),
            )
        )
        if self.warnings != expected_warnings:
            raise ValueError("report warnings do not match shared factors")
        if self.verifier_conclusion == "proof_ready":
            if (
                not self.causal_complete
                or self.unresolved_failures
                or not self.independence_assessment.satisfied
                or not self.global_postconditions_satisfied
                or any(
                    type(value) is not bool or not value
                    for value in coverage.values()
                )
            ):
                raise ValueError("proof-ready report is not closed")
        else:
            if not self.unresolved_failures:
                raise ValueError("incomplete report requires closed diagnostics")
        return self


class AcceptanceReceipt(SignedProtocolModel):
    protocol_version: Literal["0.1"]
    acceptance_id: Digest64
    work_order_digest: Digest64
    acceptance_request_receipt_id: Digest64
    acceptance_request_receipt_digest: Digest64
    composition_report_digest: Digest64
    final_artifact: FinalArtifact
    artifact_digests: tuple[EvidenceRef, ...]
    evidence_snapshot_digest: Digest64
    receipt_digests: tuple[Digest64, ...]
    causal_graph_root: Digest64
    causal_complete: Literal[True]
    evidence_coverage: FrozenDict
    independence_assessment: IndependenceAssessment
    test_evidence_refs: tuple[EvidenceRef, ...]
    decision: Literal["accepted"]
    unresolved_failures: tuple[ReportDiagnostic, ...]
    warnings: tuple[ReportDiagnostic, ...]
    global_postconditions: tuple[PredicateResult, ...]
    global_postconditions_satisfied: Literal[True]
    verifier_conclusion: Literal["proof_ready"]
    accepted_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_acceptance(self) -> AcceptanceReceipt:
        coverage = dict(self.evidence_coverage)
        if (
            not coverage
            or not set(coverage).issubset(_EVIDENCE_DIMENSIONS)
            or any(type(value) is not bool or not value for value in coverage.values())
        ):
            raise ValueError("acceptance evidence coverage must be closed and true")
        if not self.independence_assessment.satisfied:
            raise ValueError("acceptance requires satisfied independence")
        if self.unresolved_failures:
            raise ValueError("acceptance cannot contain unresolved failures")
        for values, key in (
            (self.artifact_digests, lambda item: item.path.encode("utf-8")),
            (self.test_evidence_refs, lambda item: item.path.encode("utf-8")),
            (
                self.warnings,
                lambda item: (
                    item.code.encode("utf-8"),
                    item.subject_ref.encode("utf-8"),
                ),
            ),
            (
                self.global_postconditions,
                lambda item: item.predicate_id.encode("utf-8"),
            ),
        ):
            keys = [key(item) for item in values]
            if keys != sorted(keys) or len(keys) != len(set(keys)):
                raise ValueError("acceptance arrays must be sorted and unique")
        if any(item.code not in _WARNING_CODES for item in self.warnings):
            raise ValueError("acceptance warnings use the warning registry only")
        shared_factors, shared_values = _recompute_shared_factors(
            self.independence_assessment
        )
        warning_codes = {
            "model": "SHARED_MODEL",
            "prompt_template": "SHARED_PROMPT_TEMPLATE",
            "context_source": "SHARED_CONTEXT_SOURCE",
            "toolchain": "SHARED_TOOLCHAIN",
            "execution_context": "SHARED_EXECUTION_CONTEXT",
            "controller": "SHARED_CONTROLLER",
            "test_source": "SHARED_TEST_SOURCE",
        }
        expected_warnings = tuple(
            sorted(
                (
                    ReportDiagnostic(
                        code=warning_codes[factor],
                        subject_ref=_jcs_digest(
                            {
                                "domain": "openworkproof/shared-factor-ref/v0.1",
                                "factor": factor,
                                "value": shared_values[factor],
                            }
                        ),
                    )
                    for factor in shared_factors
                ),
                key=lambda item: (
                    item.code.encode("utf-8"),
                    item.subject_ref.encode("utf-8"),
                ),
            )
        )
        if self.warnings != expected_warnings:
            raise ValueError("acceptance warnings do not match shared factors")
        if (
            not self.receipt_digests
            or len(set(self.receipt_digests)) != len(self.receipt_digests)
        ):
            raise ValueError("receipt digests must be non-empty and unique")
        if not self.global_postconditions or any(
            not result.passed for result in self.global_postconditions
        ):
            raise ValueError("acceptance requires passed global postconditions")
        return self

    def validate_against_work_order(self, work_order: WorkOrder) -> AcceptanceReceipt:
        maintainer = work_order.key_bindings[0]
        acceptor = work_order.key_bindings[5]
        if (
            self.work_order_digest != work_order.digest
            or self.signer_key_id != acceptor.key_id
            or self.signer_key_id == maintainer.key_id
            or set(self.evidence_coverage)
            != set(work_order.required_evidence_dimensions)
            or [result.predicate_id for result in self.global_postconditions]
            != [result.predicate_id for result in work_order.postconditions]
        ):
            raise ValueError("AcceptanceReceipt does not match WorkOrder")
        for result, spec in zip(
            self.global_postconditions, work_order.postconditions, strict=True
        ):
            result.validate_against(spec)
        return self


class AcceptanceRejectionReceipt(SignedProtocolModel):
    protocol_version: Literal["0.1"]
    rejection_id: Digest64
    work_order_digest: Digest64
    acceptance_request_receipt_id: Digest64
    acceptance_request_receipt_digest: Digest64
    composition_report_digest: Digest64
    evidence_snapshot_digest: Digest64
    receipt_digests: tuple[Digest64, ...]
    causal_graph_root: Digest64
    reason_code: Literal[
        "EVIDENCE_INSUFFICIENT",
        "INDEPENDENCE_UNSATISFIED",
        "GLOBAL_POSTCONDITION_FAILED",
        "BUSINESS_DECISION",
    ]
    reason_detail: str
    decision: Literal["rejected"]
    rejected_at: CanonicalUTCTime

    @model_validator(mode="after")
    def _validate_rejection(self) -> AcceptanceRejectionReceipt:
        if type(self.reason_detail) is not str or len(self.reason_detail) > 1024:
            raise ValueError("rejection reason detail is invalid")
        if (
            not self.receipt_digests
            or len(set(self.receipt_digests)) != len(self.receipt_digests)
        ):
            raise ValueError("receipt digests must be non-empty and unique")
        return self

    def validate_against_work_order(
        self, work_order: WorkOrder
    ) -> AcceptanceRejectionReceipt:
        maintainer = work_order.key_bindings[0]
        acceptor = work_order.key_bindings[5]
        if (
            self.work_order_digest != work_order.digest
            or self.signer_key_id != acceptor.key_id
            or self.signer_key_id == maintainer.key_id
        ):
            raise ValueError(
                "AcceptanceRejectionReceipt does not match WorkOrder"
            )
        return self


class AcceptanceTransitionReceipt(SignedProtocolModel):
    _signed_domain = "acceptance-transition"

    schema_version: Literal["openworkproof-acceptance-transition/0.2"]
    protocol_version: Literal["0.2"]
    transition_id: Digest64
    work_order_digest: Digest64
    target_acceptance_id: Digest64
    target_acceptance_digest: Digest64
    verification_decision_id: Digest64
    verification_decision_digest: Digest64
    transition: Literal["withdrawn", "superseded"]
    replacement_acceptance_id: Digest64 | None
    replacement_acceptance_digest: Digest64 | None
    reason_code: Literal[
        "EVIDENCE_REFUTED",
        "EVIDENCE_UNKNOWN",
        "SCOPE_CHANGED",
        "REPLACED_DELIVERY",
        "MANUAL_WITHDRAWAL",
    ]
    causal_parent_ids: tuple[Digest64, ...]
    decided_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _closed_transition(self) -> AcceptanceTransitionReceipt:
        if self.causal_parent_ids != tuple(sorted(set(self.causal_parent_ids))):
            raise ValueError("transition causal parents must be sorted and unique")
        expected_parents = {
            self.target_acceptance_id,
            self.verification_decision_id,
        }
        if self.transition == "withdrawn":
            if (
                self.replacement_acceptance_id is not None
                or self.replacement_acceptance_digest is not None
            ):
                raise ValueError("withdrawal forbids a replacement acceptance")
        else:
            if (
                self.replacement_acceptance_id is None
                or self.replacement_acceptance_digest is None
                or self.replacement_acceptance_id == self.target_acceptance_id
            ):
                raise ValueError(
                    "supersession requires a different replacement acceptance"
                )
            expected_parents.add(self.replacement_acceptance_id)
        if set(self.causal_parent_ids) != expected_parents:
            raise ValueError("transition causal parents do not match its bindings")
        return self

    def validate_against_work_order(
        self,
        work_order: WorkOrder,
    ) -> AcceptanceTransitionReceipt:
        acceptor = next(
            (
                binding
                for binding in work_order.key_bindings
                if binding.role == "Acceptor"
            ),
            None,
        )
        if (
            acceptor is None
            or self.work_order_digest != work_order.digest
            or self.signer_key_id != acceptor.key_id
        ):
            raise ValueError(
                "AcceptanceTransitionReceipt does not match WorkOrder"
            )
        return self


class PolicyDecision(ProtocolModel):
    allowed: bool
    decision: Literal["allow", "deny"]
    error_code: ProtocolString | None
    reason: ProtocolString

    @model_validator(mode="after")
    def _validate_decision(self) -> PolicyDecision:
        if self.allowed != (self.decision == "allow"):
            raise ValueError("allowed and decision are inconsistent")
        if self.allowed != (self.error_code is None):
            raise ValueError("allowed and error_code are inconsistent")
        return self


class TransitionDecision(ProtocolModel):
    allowed: bool
    error_code: ProtocolString | None
    reason: ProtocolString

    @model_validator(mode="after")
    def _validate_decision(self) -> TransitionDecision:
        if self.allowed != (self.error_code is None):
            raise ValueError("allowed and error_code are inconsistent")
        return self


__all__ = [
    "ACTION_RECEIPT_ADAPTER",
    "ACTION_RECEIPT_V04_ADAPTER",
    "AcceptanceReceipt",
    "ActionBindingManifest",
    "ActionReceipt",
    "ActionReceiptV04",
    "AgentRequest",
    "AgentRequestV04",
    "ApprovalGate",
    "ApprovalDecisionReceipt",
    "ApprovalHumanDecision",
    "ApprovalRequestedReceipt",
    "AuthorityCheckpoint",
    "AuthorityStatus",
    "Artifact",
    "BUNDLE_FINALIZATION_GRACE_SECONDS",
    "BindingDecision",
    "BindingDecisionDraft",
    "BindingDecisionSignature",
    "BindingOutcome",
    "BindingReasonCode",
    "CapabilityGrant",
    "Command",
    "CommitmentAnchor",
    "CompositionReport",
    "ControlContractV05",
    "ControlObservationV05",
    "CorrelationFactors",
    "EvidencePolicy",
    "EvidenceRef",
    "FixedTestSource",
    "FailureSignatureV05",
    "GrantConsumedReceipt",
    "GrantIssuedReceipt",
    "GrantRevokedReceipt",
    "HumanDecision",
    "IndependenceAssessment",
    "KeyBinding",
    "JudgmentCommitment",
    "McpErrorEnvelope",
    "PatchResultEvidence",
    "PolicyAnchor",
    "POLICY_ERROR_CODES",
    "PolicyDecision",
    "POLICY_ERROR_CODES_V04",
    "PredicateResult",
    "PredicateSpec",
    "PopulationContractV05",
    "PopulationObservationV05",
    "ProtocolModel",
    "PublicKeyB64Url",
    "QuotaCharge",
    "ReportDiagnostic",
    "ReplayProfile",
    "RepoReadOutput",
    "RootGrantTemplate",
    "RollbackReceipt",
    "RollbackReceiptV04",
    "SafeNonNegativeInt",
    "SafePositiveInt",
    "SidecarEvent",
    "SignedProtocolModel",
    "SourceArtifact",
    "SubjectClaim",
    "SystemEventReceipt",
    "TestProfile",
    "TestResultEvidence",
    "TerminationDecisionReceipt",
    "TerminationHumanDecision",
    "ToolCallReceipt",
    "ToolCallReceiptV04",
    "TransitionDecision",
    "VerificationArm",
    "VerificationArmExecutionStatus",
    "VerificationArmResult",
    "VerificationArmResultV05",
    "VerificationDecisionDraftV05",
    "VerificationDecisionV05",
    "VerificationIntegrityAssessmentV05",
    "VerificationIntegrityReasonCode",
    "VerificationProfileV02",
    "VerificationProfileV05",
    "VerificationReasonCode",
    "VerificationReasonCodeV05",
    "VerifierBinding",
    "WorkOrder",
    "request_arguments_digest",
    "control_contract_id",
    "failure_signature_digest",
    "parse_agent_request",
    "parse_action_receipt",
    "parse_action_receipt_json",
    "population_contract_id",
    "population_member_digest",
    "validate_receipt_or_error",
    "validate_fixed_test_source_bytes",
]
