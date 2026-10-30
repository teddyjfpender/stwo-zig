"""Prevent performance claims from silently changing proof obligations."""
import copy
import json
import unittest
from pathlib import Path
from scripts import riscv64_prover_profile_compare as compare


class ProfileComparisonTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[2]
        source = root / 'vectors/reports/rv64-qualification-20261030/csp-full-parallel.json'
        self.before = json.loads(source.read_text())
        self.before['cases'] = self.before['cases'][:1]
        self.after = copy.deepcopy(self.before)

    def test_unchanged_verified_work_is_admitted(self):
        self.assertEqual(1, len(compare.compare(self.before, self.after)))

    def test_weaker_security_or_extra_workers_cannot_claim_a_speedup(self):
        for field in ('fri_queries', 'workers', 'instructions'):
            changed = copy.deepcopy(self.after)
            changed['cases'][0]['prover'][field] += 1
            with self.assertRaisesRegex(ValueError, 'geometry or security'):
                compare.compare(self.before, changed)

    def test_changed_proof_is_rejected(self):
        self.after['cases'][0]['artifact_sha256']['proof.bin'] = 'different'
        with self.assertRaisesRegex(ValueError, 'proof bytes changed'):
            compare.compare(self.before, self.after)

    def test_missing_receiver_authority_is_rejected(self):
        self.after['cases'][0]['independent_statement_binding'] = False
        with self.assertRaisesRegex(ValueError, 'independent expected-state'):
            compare.compare(self.before, self.after)

    def test_duplicate_or_incomplete_coverage_is_rejected(self):
        self.after['cases'] *= 2
        with self.assertRaisesRegex(ValueError, 'coverage differs'):
            compare.compare(self.before, self.after)
