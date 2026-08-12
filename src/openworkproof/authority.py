"""AuthorityCheckpoint chain validation and as-of evaluation (Task 10).

The checkpoint authority is an external trust root: OpenWorkProof only
verifies the format, signature, chain and binding of checkpoints. It never
owns the external governance or trust root, and resolver unavailability is
an input status, never an unsigned replacement checkpoint.
"""

from __future__ import annotations

import dataclasses

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from openworkproof.models import AuthorityCheckpoint
from openworkproof.signing import verify_authority_checkpoint


@dataclasses.dataclass(frozen=True, slots=True)
class AuthorityChainVerdict:
    """One chain validation result.

    status values: current | stale | forked | rollback | missing |
                   unavailable | invalid
    """

    status: str
    head: AuthorityCheckpoint | None = None
    fork_digest: str | None = None


def validate_authority_chain(
    checkpoints: tuple[AuthorityCheckpoint, ...],
    *,
    authority_namespace: str,
    subject_id: str,
    authority_key: Ed25519PublicKey,
) -> AuthorityChainVerdict:
    """Validate one checkpoint chain with an explicit external authority key.

    Checks, in order: non-empty chain, namespace/subject identity, signature
    under the external key, monotonic contiguous revisions, exact predecessor
    digests, same-revision forks, and revision rollback.
    """

    if not checkpoints:
        return AuthorityChainVerdict("missing")
    if not isinstance(authority_key, Ed25519PublicKey):
        return AuthorityChainVerdict("invalid")

    by_revision: dict[int, list[AuthorityCheckpoint]] = {}
    previous: AuthorityCheckpoint | None = None
    for checkpoint in checkpoints:
        if (
            not isinstance(checkpoint, AuthorityCheckpoint)
            or checkpoint.authority_namespace != authority_namespace
            or checkpoint.subject_id != subject_id
        ):
            return AuthorityChainVerdict("invalid")
        if not verify_authority_checkpoint(checkpoint, authority_key):
            return AuthorityChainVerdict("invalid")
        by_revision.setdefault(
            checkpoint.monotonic_revision, []
        ).append(checkpoint)

    # Same-revision forks are detected before monotonic sequencing so that a
    # forked pair is reported as a fork, not as a sequencing error.
    for revision, candidates in by_revision.items():
        if len({candidate.digest for candidate in candidates}) > 1:
            return AuthorityChainVerdict(
                "forked", fork_digest=candidates[0].digest
            )

    # Rollback is a property of the order the resolver supplied, so it is
    # detected against the input sequence before we sort for chain checks.
    for previous_cp, current_cp in zip(checkpoints, checkpoints[1:]):
        if (
            current_cp.monotonic_revision
            < previous_cp.monotonic_revision
        ):
            return AuthorityChainVerdict("rollback")

    previous = None
    for checkpoint in sorted(
        checkpoints, key=lambda item: item.monotonic_revision
    ):
        revision = checkpoint.monotonic_revision
        if previous is None:
            if revision != 1 or checkpoint.predecessor_checkpoint_digest is not None:
                return AuthorityChainVerdict("invalid")
        else:
            if revision < previous.monotonic_revision:
                return AuthorityChainVerdict("rollback")
            if revision != previous.monotonic_revision + 1:
                return AuthorityChainVerdict("invalid")
            if checkpoint.predecessor_checkpoint_digest != previous.digest:
                return AuthorityChainVerdict("invalid")
        previous = checkpoint
    head = checkpoints[-1]
    return AuthorityChainVerdict("current", head=head)


def evaluate_authority_status(
    checkpoints: tuple[AuthorityCheckpoint, ...],
    *,
    authority_namespace: str,
    subject_id: str,
    authority_key: Ed25519PublicKey,
    occurred_at,
    resolver_unavailable: bool = False,
) -> tuple[str, str | None]:
    """Evaluate the authority status at the action's as-of time.

    Returns ``(status, checkpoint_digest)``. The as-of rule: a checkpoint is
    current when ``effective_at <= occurred_at < expires_at``. A checkpoint
    that was current at ``occurred_at`` stays current even if it expires
    before the review; only the occurred_at window matters.
    """

    if resolver_unavailable:
        return "unavailable", None
    verdict = validate_authority_chain(
        checkpoints,
        authority_namespace=authority_namespace,
        subject_id=subject_id,
        authority_key=authority_key,
    )
    if verdict.status == "rollback":
        # A rollback verdict still has an observable chain head; carry its
        # digest so the decision can reference the stale authority evidence.
        return "rollback", checkpoints[-1].digest
    if verdict.status != "current":
        return verdict.status, verdict.fork_digest
    assert verdict.head is not None
    head = verdict.head
    if head.effective_at <= occurred_at < head.expires_at:
        return "current", head.digest
    # The head exists but was not effective at the action time: the action
    # relied on an outdated authority window.
    return "stale", head.digest
