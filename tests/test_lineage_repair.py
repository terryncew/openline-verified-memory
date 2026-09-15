"""Adversarial tests for the lineage-aware repair.

derive_airlock_memory_with_lineage() is a separate projection path: the
generation-local derive_airlock_memory() is untouched. These tests attack the
new path's receiver-signed lineage evidence and its deterministic fixed-point
propagation from every angle a hostile or confused caller could.
"""
import hashlib
import hmac
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from openline_verified_memory import (
    AIRLOCK_LINEAGE_SCHEMA,
    EvidenceError,
    derive_airlock_memory,
    derive_airlock_memory_with_lineage,
    established,
    signed_record_sha256,
)
from openline_verified_memory.evidence import canonical_json_bytes, sha256_bytes


KEY = b"k" * 32
WRONG_KEY = b"z" * 32
BASE = "a" * 40
POLICIES = {}


def sign(payload, key=KEY):
    return {
        "alg": "HMAC-SHA256",
        "payload": payload,
        "signature": hmac.new(key, canonical_json_bytes(payload), hashlib.sha256).hexdigest(),
    }


def commit_for(tag):
    return hashlib.sha256(tag.encode()).hexdigest()[:40]


def policy_bytes(lesson_id):
    body = f"# installed policy for {lesson_id}\nSTEP = 2\n".encode()
    POLICIES[lesson_id] = body
    return body


def generation(gen_no, tag, run_id="rsi-004"):
    winner_commit = commit_for(f"{tag}-winner")
    winner = {"candidate_id": f"candidate-{gen_no}", "commit": winner_commit, "disposition": "ELIGIBLE"}
    return sign(
        {
            "schema": "airlock.improvement.generation.v1",
            "run_id": run_id,
            "generation": gen_no,
            "base_commit": BASE,
            "decision": "UNIQUE_WINNER",
            "selection": {"status": "UNIQUE_WINNER", "winner": winner, "eligible": 1},
            "promoted_commit": winner_commit,
        }
    )


def promotion(gen, gen_no, tag, run_id="rsi-004"):
    winner_commit = commit_for(f"{tag}-winner")
    return sign(
        {
            "schema": "airlock.improvement.promotion.v1",
            "run_id": run_id,
            "generation": gen_no,
            "base_commit": BASE,
            "selected_commit": winner_commit,
            "improvement_branch": f"airlock/improve/{tag}",
            "expected_branch_before": BASE,
            "observed_branch_after": winner_commit,
            "generation_receipt_sha256": signed_record_sha256(gen),
            "status": "INSTALLED",
        }
    )


def standing(prom, tag, decision="REOPEN"):
    winner_commit = commit_for(f"{tag}-winner")
    return sign(
        {
            "schema": "airlock.improvement.standing.v1",
            "promotion_receipt_sha256": signed_record_sha256(prom),
            "selected_commit": winner_commit,
            "decision": decision,
            "execution_authority": "NONE",
        }
    )


def gen_entry(lesson_id, tag, gen_no, standing_decision=None):
    policy_bytes(lesson_id)
    gen = generation(gen_no, tag)
    prom = promotion(gen, gen_no, tag)
    return {
        "lesson_id": lesson_id,
        "title": f"title {lesson_id}",
        "text": f"text {lesson_id}",
        "generation_record": gen,
        "promotion_record": prom,
        "standing_record": standing(prom, tag, standing_decision) if standing_decision else None,
    }


def lineage(declaration, subject_entry, parent_entry=None, key=KEY):
    payload = {
        "schema": AIRLOCK_LINEAGE_SCHEMA,
        "declaration": declaration,
        "subject_lesson_id": subject_entry["lesson_id"],
        "subject_promotion_receipt_sha256": signed_record_sha256(
            subject_entry["promotion_record"]
        ),
    }
    if declaration == "REQUIRED":
        parent_payload = parent_entry["generation_record"]["payload"]
        payload.update(
            {
                "parent_lesson_id": parent_entry["lesson_id"],
                "parent_promotion_receipt_sha256": signed_record_sha256(
                    parent_entry["promotion_record"]
                ),
                "parent_selected_commit": parent_payload["promoted_commit"],
                "parent_installed_policy_sha256": sha256_bytes(
                    POLICIES[parent_entry["lesson_id"]]
                ),
            }
        )
    return sign(payload, key)


def chain_fixture():
    """gen1 -> gen2 -> gen3 plus an unrelated accepted root, all healthy."""
    POLICIES.clear()
    gen1 = gen_entry("gen1", "gen1", 1)
    gen2 = gen_entry("gen2", "gen2", 2)
    gen3 = gen_entry("gen3", "gen3", 3)
    root_u = gen_entry("rootU", "rootU", 1, standing_decision="RETAIN")
    generations = [gen1, gen2, gen3, root_u]
    lineage_records = [
        lineage("ROOT", gen1),
        lineage("REQUIRED", gen2, gen1),
        lineage("REQUIRED", gen3, gen2),
        lineage("ROOT", root_u),
    ]
    policies = dict(POLICIES)
    return generations, lineage_records, policies


def project(generations, lineage_records, policies, key=KEY):
    return derive_airlock_memory_with_lineage(
        generations=generations,
        lineage_records=lineage_records,
        installed_policies=policies,
        key=key,
    )


class LineageRepairTests(unittest.TestCase):
    def test_three_generation_transitive_propagation(self):
        generations, lineage_records, policies = chain_fixture()
        generations[0]["standing_record"] = standing(
            generations[0]["promotion_record"], "gen1", "REOPEN"
        )
        out = project(generations, lineage_records, policies)
        self.assertEqual(out["gen1"].status, "questioned")
        self.assertEqual(out["gen1"].witness, "airlock-standing-reopened")
        for lid in ("gen2", "gen3"):
            self.assertEqual(out[lid].status, "questioned")
            self.assertEqual(out[lid].witness, "airlock-lineage-questioned")
            self.assertIn("gen1", out[lid].reuse)
            self.assertEqual(out[lid].installed_state_action, "NONE")
        # deterministic ancestor path gen3 -> gen2 -> gen1 recorded
        edge_rows = [r for r in out["gen3"].evidence if r["kind"] == "airlock_lineage_edge"]
        self.assertEqual(
            [(r["child_lesson_id"], r["parent_lesson_id"]) for r in edge_rows],
            [("gen3", "gen2"), ("gen2", "gen1")],
        )
        self.assertEqual(established(list(out.values())), [out["rootU"]])

    def test_unrelated_accepted_branch_survives(self):
        generations, lineage_records, policies = chain_fixture()
        generations[0]["standing_record"] = standing(
            generations[0]["promotion_record"], "gen1", "REOPEN"
        )
        out = project(generations, lineage_records, policies)
        self.assertEqual(out["rootU"].status, "inherited")
        self.assertEqual(established(list(out.values())), [out["rootU"]])

    def test_healthy_chain_stays_inherited(self):
        out = project(*chain_fixture())
        for lid in ("gen1", "gen2", "gen3", "rootU"):
            self.assertEqual(out[lid].status, "inherited")
        self.assertEqual(len(established(list(out.values()))), 4)

    def test_missing_lineage_fails_closed(self):
        generations, lineage_records, policies = chain_fixture()
        lineage_records = [r for r in lineage_records
                           if r["payload"]["subject_lesson_id"] != "gen2"]
        with self.assertRaisesRegex(EvidenceError, "lineage_missing"):
            project(generations, lineage_records, policies)

    def test_forged_lineage_fails_closed(self):
        generations, lineage_records, policies = chain_fixture()
        bad = lineage("REQUIRED", generations[1], generations[0], key=WRONG_KEY)
        lineage_records = [r for r in lineage_records
                           if r["payload"]["subject_lesson_id"] != "gen2"] + [bad]
        with self.assertRaisesRegex(EvidenceError, "lineage_signature_invalid"):
            project(generations, lineage_records, policies)

    def test_wrong_parent_promotion_hash_fails_closed(self):
        generations, lineage_records, policies = chain_fixture()
        rec = lineage("REQUIRED", generations[1], generations[0])
        rec["payload"]["parent_promotion_receipt_sha256"] = "0" * 64
        rec["signature"] = hmac.new(
            KEY, canonical_json_bytes(rec["payload"]), hashlib.sha256).hexdigest()
        lineage_records = [r for r in lineage_records
                           if r["payload"]["subject_lesson_id"] != "gen2"] + [rec]
        with self.assertRaisesRegex(EvidenceError, "lineage_parent_promotion_binding_mismatch"):
            project(generations, lineage_records, policies)

    def test_wrong_installed_policy_hash_fails_closed(self):
        generations, lineage_records, policies = chain_fixture()
        rec = lineage("REQUIRED", generations[1], generations[0])
        rec["payload"]["parent_installed_policy_sha256"] = "f" * 64
        rec["signature"] = hmac.new(
            KEY, canonical_json_bytes(rec["payload"]), hashlib.sha256).hexdigest()
        lineage_records = [r for r in lineage_records
                           if r["payload"]["subject_lesson_id"] != "gen2"] + [rec]
        with self.assertRaisesRegex(EvidenceError, "lineage_parent_policy_hash_mismatch"):
            project(generations, lineage_records, policies)

    def test_dangling_parent_fails_closed(self):
        generations, lineage_records, policies = chain_fixture()
        ghost = gen_entry("ghost", "ghost", 9)
        rec = lineage("REQUIRED", generations[1], ghost)
        lineage_records = [r for r in lineage_records
                           if r["payload"]["subject_lesson_id"] != "gen2"] + [rec]
        with self.assertRaisesRegex(EvidenceError, "lineage_parent_dangling"):
            project(generations, lineage_records, policies)

    def test_conflicting_parent_declarations_fail_closed(self):
        generations, lineage_records, policies = chain_fixture()
        extra = lineage("REQUIRED", generations[2], generations[0])
        with self.assertRaisesRegex(EvidenceError, "lineage_conflicting_declarations"):
            project(generations, lineage_records + [extra], policies)

    def test_root_with_parent_fields_fails_closed(self):
        generations, lineage_records, policies = chain_fixture()
        rec = lineage("ROOT", generations[0])
        rec["payload"]["parent_lesson_id"] = "gen1"
        rec["signature"] = hmac.new(
            KEY, canonical_json_bytes(rec["payload"]), hashlib.sha256).hexdigest()
        lineage_records = [r for r in lineage_records
                           if r["payload"]["subject_lesson_id"] != "gen1"] + [rec]
        with self.assertRaisesRegex(EvidenceError, "lineage_root_with_parent_fields"):
            project(generations, lineage_records, policies)

    def test_cycle_cannot_self_authorize(self):
        generations, lineage_records, policies = chain_fixture()
        # gen1 -> gen2 -> gen1: a healthy cycle must still fail closed
        rec1 = lineage("REQUIRED", generations[0], generations[1])
        lineage_records = [r for r in lineage_records
                           if r["payload"]["subject_lesson_id"] != "gen1"] + [rec1]
        with self.assertRaisesRegex(EvidenceError, "lineage_cycle_detected"):
            project(generations, lineage_records, policies)

    def test_lineage_subject_promotion_binding_mismatch_fails_closed(self):
        generations, lineage_records, policies = chain_fixture()
        rec = lineage("REQUIRED", generations[1], generations[0])
        other_prom = generations[2]["promotion_record"]
        rec["payload"]["subject_promotion_receipt_sha256"] = signed_record_sha256(other_prom)
        rec["signature"] = hmac.new(
            KEY, canonical_json_bytes(rec["payload"]), hashlib.sha256).hexdigest()
        lineage_records = [r for r in lineage_records
                           if r["payload"]["subject_lesson_id"] != "gen2"] + [rec]
        with self.assertRaisesRegex(EvidenceError, "lineage_subject_promotion_binding_mismatch"):
            project(generations, lineage_records, policies)

    def test_historical_receipts_and_inputs_not_mutated(self):
        generations, lineage_records, policies = chain_fixture()
        generations[0]["standing_record"] = standing(
            generations[0]["promotion_record"], "gen1", "REOPEN"
        )
        before = canonical_json_bytes(
            {"g": generations, "l": lineage_records,
             "p": {k: v.hex() for k, v in policies.items()}})
        project(generations, lineage_records, policies)
        after = canonical_json_bytes(
            {"g": generations, "l": lineage_records,
             "p": {k: v.hex() for k, v in policies.items()}})
        self.assertEqual(sha256_bytes(before), sha256_bytes(after))

    def test_restart_reprojection_determinism(self):
        script = (
            "import sys, json; sys.path.insert(0, 'src');"
            "sys.path.insert(0, 'tests');"
            "from test_lineage_repair import chain_fixture, project, standing;"
            "from openline_verified_memory.evidence import canonical_json_bytes;"
            "generations, lineage_records, policies = chain_fixture();"
            "generations[0]['standing_record'] = standing(generations[0]['promotion_record'], 'gen1', 'REOPEN');"
            "out = project(generations, lineage_records, policies);"
            "print(canonical_json_bytes({k: v.to_dict() for k, v in out.items()}).decode())"
        )
        runs = []
        for _ in range(2):
            cp = subprocess.run(
                [sys.executable, "-c", script],
                cwd=str(Path(__file__).resolve().parents[1]),
                capture_output=True, text=True, check=True,
            )
            runs.append(cp.stdout)
        self.assertEqual(runs[0], runs[1])
        decoded = json.loads(runs[0])
        self.assertEqual(decoded["gen3"]["status"], "questioned")

    def test_missing_lineage_never_implies_root(self):
        """A generation with no lineage record must fail closed, never default to ROOT."""
        generations, lineage_records, policies = chain_fixture()
        lineage_records = [r for r in lineage_records
                           if r["payload"]["subject_lesson_id"] != "gen3"]
        try:
            project(generations, lineage_records, policies)
        except EvidenceError as exc:
            self.assertIn("lineage_missing", str(exc))
            self.assertIn("gen3", str(exc))
        else:
            self.fail("missing lineage must not earn any standing, root or otherwise")

    def test_policy_bytes_recomputed_inside_verifier(self):
        """The verifier recomputes SHA-256 over the supplied bytes; a validly
        signed record cannot authorize bytes whose digest it does not match."""
        generations, lineage_records, policies = chain_fixture()
        # Lineage records are honestly minted; the CALLER then supplies
        # tampered installed-policy bytes for gen1. The signed binding is
        # valid, but the recomputed digest of the supplied bytes differs,
        # so the verifier must reject rather than trust the record's digest.
        policies = dict(policies)
        policies["gen1"] = b"# tampered policy bytes\nSTEP = 999\n"
        with self.assertRaisesRegex(EvidenceError, "lineage_parent_policy_hash_mismatch"):
            project(generations, lineage_records, policies)
        # And the honest bytes still verify against the same signed records.
        out = project(*chain_fixture())
        self.assertEqual(out["gen3"].status, "inherited")

    def test_generation_local_api_backward_compatible(self):
        """The pinned per-generation API behaves exactly as before the repair."""
        POLICIES.clear()
        entry = gen_entry("solo", "solo", 1, standing_decision="REOPEN")
        mem = derive_airlock_memory(
            lesson_id="solo", title="t", text="x",
            generation_record=entry["generation_record"],
            promotion_record=entry["promotion_record"],
            standing_record=entry["standing_record"],
            key=KEY,
        )
        self.assertEqual(mem.status, "questioned")
        self.assertEqual(mem.witness, "airlock-standing-reopened")
        entry2 = gen_entry("solo2", "solo2", 1)
        mem2 = derive_airlock_memory(
            lesson_id="solo2", title="t", text="x",
            generation_record=entry2["generation_record"],
            promotion_record=entry2["promotion_record"],
            key=KEY,
        )
        self.assertEqual(mem2.status, "inherited")
        self.assertEqual(established([mem, mem2]), [mem2])


if __name__ == "__main__":
    unittest.main()
