from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

MEMORY_RECORD_SCHEMA = "openline.verified-memory.earned.v1"
AIRLOCK_GENERATION_SCHEMA = "airlock.improvement.generation.v1"
AIRLOCK_PROMOTION_SCHEMA = "airlock.improvement.promotion.v1"
AIRLOCK_STANDING_SCHEMA = "airlock.improvement.standing.v1"

_HEX40_64 = re.compile(r"^[0-9a-f]{40,64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(ValueError):
    """Evidence cannot support the requested memory state."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def signed_record_sha256(record: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(record))


def verify_hmac_record(record: Mapping[str, Any], key: bytes) -> bool:
    if not isinstance(key, bytes) or not key:
        return False
    if not isinstance(record, Mapping) or record.get("alg") != "HMAC-SHA256":
        return False
    payload = record.get("payload")
    signature = record.get("signature")
    if not isinstance(payload, Mapping) or not isinstance(signature, str) or not _HEX64.fullmatch(signature):
        return False
    expected = hmac.new(key, canonical_json_bytes(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _require_signed(record: Mapping[str, Any], key: bytes, schema: str, label: str) -> Mapping[str, Any]:
    if not verify_hmac_record(record, key):
        raise EvidenceError(f"{label}_signature_invalid")
    payload = record.get("payload")
    if not isinstance(payload, Mapping) or payload.get("schema") != schema:
        raise EvidenceError(f"{label}_schema_invalid")
    return payload


def _selected_commit(payload: Mapping[str, Any]) -> str:
    selection = payload.get("selection")
    if not isinstance(selection, Mapping) or selection.get("status") != "UNIQUE_WINNER":
        raise EvidenceError("generation_has_no_unique_winner")
    winner = selection.get("winner")
    if not isinstance(winner, Mapping):
        raise EvidenceError("generation_winner_missing")
    commit = winner.get("commit")
    if not isinstance(commit, str) or not _HEX40_64.fullmatch(commit):
        raise EvidenceError("generation_selected_commit_invalid")
    if payload.get("decision") != "UNIQUE_WINNER":
        raise EvidenceError("generation_decision_not_unique_winner")
    recorded = payload.get("promoted_commit")
    if recorded is not None and recorded != commit:
        raise EvidenceError("generation_selected_commit_binding_mismatch")
    return commit


@dataclass(frozen=True)
class EarnedMemory:
    lesson_id: str
    title: str
    text: str
    status: str
    selected_commit: str
    survived: int
    witness: str
    reuse: str
    evidence: tuple[dict[str, str], ...]
    installed_state_action: str = "NONE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": MEMORY_RECORD_SCHEMA,
            "lesson_id": self.lesson_id,
            "title": self.title,
            "text": self.text,
            "status": self.status,
            "selected_commit": self.selected_commit,
            "survived": self.survived,
            "witness": self.witness,
            "reuse": self.reuse,
            "evidence": [dict(row) for row in self.evidence],
            "installed_state_action": self.installed_state_action,
            "trust": {
                "status_source": "derived_from_verified_evidence",
                "survival_source": "counted_exact_promotion_execution",
                "caller_may_override_status": False,
                "caller_may_override_survived": False,
                "caller_may_override_witness": False,
            },
        }


def derive_airlock_memory(
    *,
    lesson_id: str,
    title: str,
    text: str,
    generation_record: Mapping[str, Any],
    key: bytes,
    promotion_record: Mapping[str, Any] | None = None,
    standing_record: Mapping[str, Any] | None = None,
) -> EarnedMemory:
    """Derive reuse standing from Airlock evidence rather than caller-supplied trust fields.

    A signed generation selection earns CANDIDATE only. Exact installation earns
    INHERITED. A later signed REOPEN event makes the lesson QUESTIONED while
    carrying no rollback authority. The function never changes installed state.
    """
    for name, value in (("lesson_id", lesson_id), ("title", title), ("text", text)):
        if not isinstance(value, str) or not value.strip():
            raise EvidenceError(f"{name}_required")

    generation = _require_signed(
        generation_record, key, AIRLOCK_GENERATION_SCHEMA, "generation"
    )
    selected = _selected_commit(generation)
    generation_sha = signed_record_sha256(generation_record)
    evidence: list[dict[str, str]] = [
        {
            "kind": "airlock_generation_selection",
            "sha256": generation_sha,
            "run_id": str(generation.get("run_id") or ""),
            "generation": str(generation.get("generation") or ""),
        }
    ]

    if promotion_record is None:
        return EarnedMemory(
            lesson_id=lesson_id,
            title=title,
            text=text,
            status="candidate",
            selected_commit=selected,
            survived=0,
            witness="airlock-selection",
            reuse="not established; do not inherit",
            evidence=tuple(evidence),
        )

    promotion = _require_signed(
        promotion_record, key, AIRLOCK_PROMOTION_SCHEMA, "promotion"
    )
    if promotion.get("generation_receipt_sha256") != generation_sha:
        raise EvidenceError("promotion_generation_receipt_binding_mismatch")
    if promotion.get("run_id") != generation.get("run_id"):
        raise EvidenceError("promotion_run_binding_mismatch")
    if promotion.get("generation") != generation.get("generation"):
        raise EvidenceError("promotion_generation_binding_mismatch")
    if promotion.get("base_commit") != generation.get("base_commit"):
        raise EvidenceError("promotion_base_binding_mismatch")
    if promotion.get("selected_commit") != selected:
        raise EvidenceError("promotion_selected_commit_binding_mismatch")
    if promotion.get("observed_branch_after") != selected:
        raise EvidenceError("promotion_execution_not_observed")
    if promotion.get("status") != "INSTALLED":
        raise EvidenceError("promotion_status_not_installed")
    promotion_sha = signed_record_sha256(promotion_record)
    evidence.append(
        {
            "kind": "airlock_promotion_execution",
            "sha256": promotion_sha,
            "run_id": str(promotion.get("run_id") or ""),
            "generation": str(promotion.get("generation") or ""),
        }
    )

    status = "inherited"
    witness = "airlock-promotion-execution"
    reuse = "established for reuse while supporting standing remains live"

    if standing_record is not None:
        standing = _require_signed(
            standing_record, key, AIRLOCK_STANDING_SCHEMA, "standing"
        )
        if standing.get("promotion_receipt_sha256") != promotion_sha:
            raise EvidenceError("standing_promotion_binding_mismatch")
        if standing.get("selected_commit") != selected:
            raise EvidenceError("standing_selected_commit_binding_mismatch")
        decision = standing.get("decision")
        if decision not in {"RETAIN", "REOPEN"}:
            raise EvidenceError("standing_decision_invalid")
        evidence.append(
            {
                "kind": "airlock_standing",
                "sha256": signed_record_sha256(standing_record),
                "decision": str(decision),
            }
        )
        if decision == "REOPEN":
            status = "questioned"
            witness = "airlock-standing-reopened"
            reuse = "hold; do not present as established to the next generation"

    return EarnedMemory(
        lesson_id=lesson_id,
        title=title,
        text=text,
        status=status,
        selected_commit=selected,
        survived=1,
        witness=witness,
        reuse=reuse,
        evidence=tuple(evidence),
        installed_state_action="NONE",
    )


def established(memories: Iterable[EarnedMemory]) -> list[EarnedMemory]:
    """Return only lessons currently earned for inheritance."""
    return [memory for memory in memories if memory.status == "inherited"]
