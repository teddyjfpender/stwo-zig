"""Explicit software suite admission and retained-transcript parity."""
from __future__ import annotations
import copy
import unittest
from types import SimpleNamespace
from scripts.riscv_csp_benchmark_lib import validation as v
from scripts.riscv_csp_benchmark_lib.contract import BenchmarkError, sha256_bytes

class ProofSuiteTests(unittest.TestCase):
    def setUp(self):
        self.case = SimpleNamespace(target='sha256', input_size=32, expected_cycles=99)
        self.admission = SimpleNamespace(release_status='release_gated', experimental=False)
        self.transcript = {'suite': 'blake3', 'version': 2, 'digest': 'c' * 64}
        self.report = dict(schema='riscv_proof_v4', mode='bench', release_status='release_gated',
            experimental=False, recursion_enabled=False, warmups=0, samples=1, verified_samples=1,
            total_steps=99, implementation_commit='a' * 40, implementation_dirty=False,
            statement_sha256='b' * 64, transcript_receipt=self.transcript)
        self.receipt = dict(schema='riscv_verify_v2', artifact_schema_version=5, status='verified',
            statement_sha256='b' * 64, proof_bytes=3, proof_sha256=sha256_bytes(b'air'),
            implementation_commit='a' * 40, implementation_dirty=False, transcript_receipt=self.transcript)

    def check_report(self, report, suite='blake3'):
        return v.validate_benchmark_report(report, self.case, warmups=0, samples=1,
                                          admission=self.admission, proof_suite=suite)

    def check_receipt(self, receipt):
        v.validate_verify_receipt(receipt, self.case, statement_digest='b' * 64,
            proof_bytes=b'air', proof_sha256=sha256_bytes(b'air'), implementation_commit='a' * 40,
            proof_suite='blake3', expected_transcript_digest=v.transcript_digest(self.report, 'blake3'))

    def test_modern_report_and_independent_receipt_match(self):
        self.assertEqual(self.check_report(self.report), 'a' * 40)
        self.check_receipt(self.receipt)

    def test_legacy_request_cannot_admit_modern_report(self):
        with self.assertRaises(BenchmarkError): self.check_report(self.report, 'blake2s')

    def test_wrong_schema_and_artifact_version_are_rejected(self):
        for key, value in [('schema', 'riscv_verify_v1'), ('artifact_schema_version', 4)]:
            receipt = copy.deepcopy(self.receipt); receipt[key] = value
            with self.subTest(key=key), self.assertRaises(BenchmarkError): self.check_receipt(receipt)

    def test_ambiguous_or_noncanonical_receipts_are_rejected(self):
        for patch in ({'suite': 'blake2s'}, {'version': True}, {'version': 1},
                      {'digest': 'C' * 64}, {'digest': 'cc'}, {'extra': 1}):
            report = copy.deepcopy(self.report); report['transcript_receipt'].update(patch)
            with self.subTest(patch=patch), self.assertRaises(BenchmarkError): self.check_report(report)
        report = copy.deepcopy(self.report); report['transcript_state_blake2s'] = 'c' * 64
        with self.assertRaises(BenchmarkError): self.check_report(report)

    def test_valid_but_different_verified_transcript_is_rejected(self):
        receipt = copy.deepcopy(self.receipt); receipt['transcript_receipt']['digest'] = 'd' * 64
        with self.assertRaisesRegex(BenchmarkError, 'differs from benchmark'): self.check_receipt(receipt)

    def test_unknown_requested_suite_is_rejected(self):
        with self.assertRaises(BenchmarkError): self.check_report(self.report, 'unknown')

    def test_cohort_cannot_mix_or_omit_requested_suite(self):
        v.validate_cohort_suite([{'protocol': {'proof_suite': 'blake3'}}], 'blake3')
        for row in ({}, {'protocol': None}, {'protocol': {'proof_suite': 'blake2s'}}):
            with self.subTest(row=row), self.assertRaises(BenchmarkError):
                v.validate_cohort_suite([{'protocol': {'proof_suite': 'blake3'}}, row], 'blake3')
