import unittest
from pathlib import Path

import verified_memory_map_demo as vmm


class VerifiedMemoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipts = vmm.load_receipts(Path("examples/sample_receipts.jsonl"))

    def test_jsonl_has_six_receipts(self):
        self.assertEqual(len(self.receipts), 6)

    def test_quarantined_trap_surfaces_first_for_negated_query(self):
        ranked = vmm.rank("agent retry loop with no error handling", self.receipts)
        self.assertEqual(ranked[0][2].status, "quarantined")
        self.assertIn("Infinite while-loop", ranked[0][2].title)
        self.assertEqual(ranked[1][2].status, "inherited")
        self.assertIn("bounded retries", ranked[1][2].title)

    def test_positive_error_handling_prefers_fix(self):
        ranked = vmm.rank("agent retry loop with error handling", self.receipts)
        self.assertEqual(ranked[0][2].status, "inherited")
        self.assertIn("bounded retries", ranked[0][2].title)

    def test_unrelated_query_does_not_surface_quarantined_trap_first(self):
        ranked = vmm.rank("deploy a postgres migration", self.receipts)
        self.assertNotEqual(ranked[0][2].status, "quarantined")

    def test_negation_tokens_are_preserved(self):
        no_error = vmm.tokenize("no error handling")
        with_error = vmm.tokenize("with error handling")
        self.assertIn("NEG_error", no_error)
        self.assertIn("NEG_handling", no_error)
        self.assertNotIn("NEG_error", with_error)


if __name__ == "__main__":
    unittest.main()
