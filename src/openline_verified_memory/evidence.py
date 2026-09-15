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
AIRLOCK_LINEAGE_SCHEMA = "airlock.improvement.lineage.v1"

LINEAGE_DECLARATION_ROOT = "ROOT"
LINEAGE_DECLARATION_REQUIRED = "REQUIRED"

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


def _derive_local(
    *,
    generation_record: Mapping[str, Any],
    key: bytes,
    promotion_record: Mapping[str, Any] | None = None,
    standing_record: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive one generation's standing from its own records only.

    This is the exact pre-repair rule set, shared by the generation-local API
    and the lineage-aware path (which derives local standing first, then
    propagates). Returns status, witness, reuse text, evidence rows, and the
    generation/promotion receipt shas plus the selected commit.
    """
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
        return {
            "status": "candidate",
            "witness": "airlock-selection",
            "reuse": "not established; do not inherit",
            "evidence": evidence,
            "selected_commit": selected,
            "survived": 0,
            "generation_sha": generation_sha,
            "promotion_sha": None,
        }

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

    return {
        "status": status,
        "witness": witness,
        "reuse": reuse,
        "evidence": evidence,
        "selected_commit": selected,
        "survived": 1,
        "generation_sha": generation_sha,
        "promotion_sha": promotion_sha,
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

    This generation-local API is unchanged by the lineage repair: it derives
    standing from one generation's own records only. For lineage-aware
    projection see derive_airlock_memory_with_lineage.
    """
    for name, value in (("lesson_id", lesson_id), ("title", title), ("text", text)):
        if not isinstance(value, str) or not value.strip():
            raise EvidenceError(f"{name}_required")

    local = _derive_local(
        generation_record=generation_record,
        key=key,
        promotion_record=promotion_record,
        standing_record=standing_record,
    )
    return EarnedMemory(
        lesson_id=lesson_id,
        title=title,
        text=text,
        status=local["status"],
        selected_commit=local["selected_commit"],
        survived=local["survived"],
        witness=local["witness"],
        reuse=local["reuse"],
        evidence=tuple(local["evidence"]),
        installed_state_action="NONE",
    )


def established(memories: Iterable[EarnedMemory]) -> list[EarnedMemory]:
    """Return only lessons currently earned for inheritance."""
    return [memory for memory in memories if memory.status == "inherited"]


def _require_hex(value: Any, length: int, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % length, value):
        raise EvidenceError(label)
    return value


def _validate_lineage_graph(
    *,
    lineage_records: Iterable[Mapping[str, Any]],
    local: Mapping[str, dict[str, Any]],
    installed_policies: Mapping[str, bytes],
    key: bytes,
) -> dict[str, str | None]:
    """Verify receiver-signed lineage evidence and return child -> parent map.

    Every generation must carry exactly one lineage record. ROOT declares a
    chain root; REQUIRED declares one parent and binds the child promotion
    receipt, the parent promotion receipt, the parent selected commit, and the
    exact SHA-256 of the parent installed policy bytes. Missing, forged,
    conflicting, dangling, incomplete, or cyclic lineage fails closed: no clean
    inheritance is earned from it.
    """
    if not isinstance(installed_policies, Mapping):
        raise EvidenceError("installed_policies_invalid")

    parents: dict[str, str | None] = {}
    for raw in lineage_records:
        payload = _require_signed(raw, key, AIRLOCK_LINEAGE_SCHEMA, "lineage")
        declaration = payload.get("declaration")
        if declaration not in (LINEAGE_DECLARATION_ROOT, LINEAGE_DECLARATION_REQUIRED):
            raise EvidenceError("lineage_declaration_invalid")
        subject = payload.get("subject_lesson_id")
        if not isinstance(subject, str) or not subject.strip() or subject not in local:
            raise EvidenceError("lineage_subject_unknown")
        if subject in parents:
            raise EvidenceError("lineage_conflicting_declarations")
        bound_promotion = payload.get("subject_promotion_receipt_sha256")
        if bound_promotion != local[subject]["promotion_sha"]:
            raise EvidenceError("lineage_subject_promotion_binding_mismatch")

        parent_fields = (
            "parent_lesson_id",
            "parent_promotion_receipt_sha256",
            "parent_selected_commit",
            "parent_installed_policy_sha256",
        )
        if declaration == LINEAGE_DECLARATION_ROOT:
            if any(payload.get(field) is not None for field in parent_fields):
                raise EvidenceError("lineage_root_with_parent_fields")
            parents[subject] = None
            continue

        parent = payload.get("parent_lesson_id")
        if not isinstance(parent, str) or not parent.strip():
            raise EvidenceError("lineage_required_fields_invalid")
        if parent not in local:
            raise EvidenceError("lineage_parent_dangling")
        if parent == subject:
            raise EvidenceError("lineage_cycle_detected")
        _require_hex(
            payload.get("parent_promotion_receipt_sha256"), 64,
            "lineage_required_fields_invalid",
        )
        if not _HEX40_64.fullmatch(str(payload.get("parent_selected_commit"))):
            raise EvidenceError("lineage_required_fields_invalid")
        _require_hex(
            payload.get("parent_installed_policy_sha256"), 64,
            "lineage_required_fields_invalid",
        )
        if payload["parent_promotion_receipt_sha256"] != local[parent]["promotion_sha"]:
            raise EvidenceError("lineage_parent_promotion_binding_mismatch")
        if payload["parent_selected_commit"] != local[parent]["selected_commit"]:
            raise EvidenceError("lineage_parent_selected_commit_mismatch")
        policy_bytes = installed_policies.get(parent)
        if not isinstance(policy_bytes, bytes) or not policy_bytes:
            raise EvidenceError("lineage_parent_policy_bytes_missing")
        if sha256_bytes(policy_bytes) != payload["parent_installed_policy_sha256"]:
            raise EvidenceError("lineage_parent_policy_hash_mismatch")
        parents[subject] = parent

    missing = sorted(set(local) - set(parents))
    if missing:
        raise EvidenceError(f"lineage_missing:{','.join(missing)}")

    # Deterministic cycle detection over REQUIRED edges. A cycle cannot
    # self-authorize: lineage must ground out in explicit ROOT declarations.
    for start in sorted(parents):
        seen: set[str] = set()
        node: str | None = start
        while node is not None:
            if node in seen:
                raise EvidenceError("lineage_cycle_detected")
            seen.add(node)
            node = parents[node]
    return parents


def _propagate_questioned(
    local_questioned: set[str],
    parents: Mapping[str, str | None],
) -> tuple[set[str], dict[str, list[str]]]:
    """Transitive questioned-standing propagation to a deterministic fixed point.

    Follows the Claim Graph impact pattern: iterate the required-dependency
    edges in sorted order until no generation changes state. Returns the full
    questioned set and, for each propagated generation, the deterministic
    ancestor path from the subject up to its questioned origin.
    """
    questioned = set(local_questioned)
    changed = True
    while changed:
        changed = False
        for lesson_id in sorted(parents):
            if lesson_id in questioned:
                continue
            parent = parents[lesson_id]
            if parent is not None and parent in questioned:
                questioned.add(lesson_id)
                changed = True

    paths: dict[str, list[str]] = {}
    for lesson_id in sorted(questioned - local_questioned):
        path = [lesson_id]
        node = parents[lesson_id]
        while node is not None and node not in local_questioned:
            path.append(node)
            node = parents[node]
        if node is not None:
            path.append(node)
        paths[lesson_id] = path
    return questioned, paths


def derive_airlock_memory_with_lineage(
    *,
    generations: Iterable[Mapping[str, Any]],
    lineage_records: Iterable[Mapping[str, Any]],
    installed_policies: Mapping[str, bytes],
    key: bytes,
) -> dict[str, EarnedMemory]:
    """Project lineage-aware inheritance standing for a set of generations.

    Each generation entry carries ``lesson_id``, ``title``, ``text``,
    ``generation_record``, ``promotion_record`` (required), and optional
    ``standing_record``. Local standing is derived first with the exact
    pre-repair rules; then questioned standing propagates transitively through
    REQUIRED lineage dependencies to a deterministic fixed point. Unrelated
    accepted branches are preserved. Historical receipts and installed state
    are never mutated.

    Returns lesson_id -> EarnedMemory in deterministic (sorted) order.
    Raises EvidenceError fail-closed on any lineage defect.
    """
    entries = list(generations)
    if not entries:
        raise EvidenceError("generations_empty")
    local: dict[str, dict[str, Any]] = {}
    titles: dict[str, str] = {}
    texts: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise EvidenceError("generation_entry_invalid")
        lesson_id = entry.get("lesson_id")
        title = entry.get("title")
        text = entry.get("text")
        for name, value in (("lesson_id", lesson_id), ("title", title), ("text", text)):
            if not isinstance(value, str) or not value.strip():
                raise EvidenceError(f"{name}_required")
        if lesson_id in local:
            raise EvidenceError("generation_lesson_duplicate")
        if entry.get("promotion_record") is None:
            raise EvidenceError("lineage_subject_not_installed")
        # Snapshot the caller's records; the projector never mutates them.
        local[lesson_id] = _derive_local(
            generation_record=entry.get("generation_record"),
            key=key,
            promotion_record=entry.get("promotion_record"),
            standing_record=entry.get("standing_record"),
        )
        titles[lesson_id] = title
        texts[lesson_id] = text

    parents = _validate_lineage_graph(
        lineage_records=lineage_records,
        local=local,
        installed_policies=installed_policies,
        key=key,
    )
    local_questioned = {lid for lid, info in local.items() if info["status"] == "questioned"}
    questioned, paths = _propagate_questioned(local_questioned, parents)

    lineage_shas: dict[str, str] = {}
    for raw in lineage_records:
        payload = _require_signed(raw, key, AIRLOCK_LINEAGE_SCHEMA, "lineage")
        lineage_shas[payload["subject_lesson_id"]] = signed_record_sha256(raw)

    result: dict[str, EarnedMemory] = {}
    for lesson_id in sorted(local):
        info = local[lesson_id]
        evidence = list(info["evidence"])
        status = info["status"]
        witness = info["witness"]
        reuse = info["reuse"]
        if lesson_id in paths:
            path = paths[lesson_id]
            origin = path[-1]
            for child, parent in zip(path, path[1:]):
                parent_info = local[parent]
                evidence.append(
                    {
                        "kind": "airlock_lineage_edge",
                        "child_lesson_id": child,
                        "parent_lesson_id": parent,
                        "parent_promotion_receipt_sha256": str(parent_info["promotion_sha"]),
                        "parent_selected_commit": parent_info["selected_commit"],
                        "parent_installed_policy_sha256": sha256_bytes(
                            installed_policies[parent]
                        ),
                        "lineage_record_sha256": lineage_shas[child],
                    }
                )
            status = "questioned"
            witness = "airlock-lineage-questioned"
            reuse = (
                f"hold; questioned ancestry ({origin}); "
                "do not present as established to the next generation"
            )
        result[lesson_id] = EarnedMemory(
            lesson_id=lesson_id,
            title=titles[lesson_id],
            text=texts[lesson_id],
            status=status,
            selected_commit=info["selected_commit"],
            survived=info["survived"],
            witness=witness,
            reuse=reuse,
            evidence=tuple(evidence),
            installed_state_action="NONE",
        )
    return result
