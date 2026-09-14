import hashlib
import hmac
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from openline_verified_memory import (
    EvidenceError,
    derive_airlock_memory,
    established,
    signed_record_sha256,
)
from openline_verified_memory.evidence import canonical_json_bytes


KEY = b"k" * 32
BASE = "a" * 40
WINNER = "b" * 40


def sign(payload):
    return {
        "alg": "HMAC-SHA256",
        "payload": payload,
        "signature": hmac.new(KEY, canonical_json_bytes(payload), hashlib.sha256).hexdigest(),
    }


def generation():
    winner = {"candidate_id": "candidate-01", "commit": WINNER, "disposition": "ELIGIBLE"}
    return sign(
        {
            "schema": "airlock.improvement.generation.v1",
            "run_id": "rsi-001",
            "generation": 1,
            "base_commit": BASE,
            "decision": "UNIQUE_WINNER",
            "selection": {"status": "UNIQUE_WINNER", "winner": winner, "eligible": 1},
            "promoted_commit": WINNER,
        }
    )


def promotion(gen):
    return sign(
        {
            "schema": "airlock.improvement.promotion.v1",
            "run_id": "rsi-001",
            "generation": 1,
            "base_commit": BASE,
            "selected_commit": WINNER,
            "improvement_branch": "airlock/improve/rsi-001",
            "expected_branch_before": BASE,
            "observed_branch_after": WINNER,
            "generation_receipt_sha256": signed_record_sha256(gen),
            "status": "INSTALLED",
        }
    )


def standing(prom, decision="REOPEN"):
    return sign(
        {
            "schema": "airlock.improvement.standing.v1",
            "promotion_receipt_sha256": signed_record_sha256(prom),
            "selected_commit": WINNER,
            "decision": decision,
            "execution_authority": "NONE",
        }
    )


class EarnedMemoryTests(unittest.TestCase):
    def test_selection_without_installation_stays_candidate(self):
        memory = derive_airlock_memory(
            lesson_id="lesson-1", title="bounded retry", text="use bounded retry",
            generation_record=generation(), key=KEY,
        )
        self.assertEqual(memory.status, "candidate")
        self.assertEqual(memory.survived, 0)
        self.assertEqual(established([memory]), [])

    def test_exact_installed_promotion_earns_inherited(self):
        gen = generation()
        prom = promotion(gen)
        memory = derive_airlock_memory(
            lesson_id="lesson-1", title="bounded retry", text="use bounded retry",
            generation_record=gen, promotion_record=prom, key=KEY,
        )
        self.assertEqual(memory.status, "inherited")
        self.assertEqual(memory.survived, 1)
        self.assertEqual(established([memory]), [memory])

    def test_reopen_questions_memory_without_rollback_authority(self):
        gen = generation()
        prom = promotion(gen)
        memory = derive_airlock_memory(
            lesson_id="lesson-1", title="bounded retry", text="use bounded retry",
            generation_record=gen, promotion_record=prom,
            standing_record=standing(prom), key=KEY,
        )
        self.assertEqual(memory.status, "questioned")
        self.assertEqual(memory.survived, 1)
        self.assertEqual(memory.installed_state_action, "NONE")
        self.assertEqual(established([memory]), [])

    def test_original_valid_signatures_do_not_override_newer_reopen(self):
        gen = generation()
        prom = promotion(gen)
        before = derive_airlock_memory(
            lesson_id="lesson-1", title="bounded retry", text="use bounded retry",
            generation_record=gen, promotion_record=prom, key=KEY,
        )
        after = derive_airlock_memory(
            lesson_id="lesson-1", title="bounded retry", text="use bounded retry",
            generation_record=gen, promotion_record=prom,
            standing_record=standing(prom), key=KEY,
        )
        self.assertEqual(before.status, "inherited")
        self.assertEqual(after.status, "questioned")

    def test_mismatched_promotion_cannot_earn_inheritance(self):
        gen = generation()
        prom = promotion(gen)
        bad = dict(prom)
        bad["payload"] = dict(prom["payload"])
        bad["payload"]["selected_commit"] = "c" * 40
        bad["signature"] = hmac.new(KEY, canonical_json_bytes(bad["payload"]), hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(EvidenceError, "promotion_selected_commit_binding_mismatch"):
            derive_airlock_memory(
                lesson_id="lesson-1", title="bounded retry", text="use bounded retry",
                generation_record=gen, promotion_record=bad, key=KEY,
            )

    def test_unsigned_claimed_inherited_state_is_not_evidence(self):
        gen = generation()
        fake = {"status": "inherited", "survived": 99, "witness": "github actions"}
        with self.assertRaisesRegex(EvidenceError, "promotion_signature_invalid"):
            derive_airlock_memory(
                lesson_id="lesson-1", title="bounded retry", text="use bounded retry",
                generation_record=gen, promotion_record=fake, key=KEY,
            )

    def test_tampered_generation_fails_closed(self):
        gen = generation()
        gen["payload"]["selection"]["winner"]["commit"] = "d" * 40
        with self.assertRaisesRegex(EvidenceError, "generation_signature_invalid"):
            derive_airlock_memory(
                lesson_id="lesson-1", title="bounded retry", text="use bounded retry",
                generation_record=gen, key=KEY,
            )


if __name__ == "__main__":
    unittest.main()
