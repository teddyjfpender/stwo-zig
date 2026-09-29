from __future__ import annotations

import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_cairo_cuda import CAIRO_REVISION, SECURITY, STWO_REVISION, check_receipts


class CanonicalCudaReceiptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.proof = Path(self.directory.name) / 'proof.json'
        self.proof.write_bytes(b'actual emitted proof bytes\n')
        digest = hashlib.sha256(self.proof.read_bytes()).digest()
        self.backend = {'schema': 'stwo-zig-cairo-cuda-canonical-receipt-v2',
                        'completed_trials': [{'protocol': dict(SECURITY, fri_lifting_log_size=None,
                            preprocessed_variant='canonical'), 'proof_sha256': list(digest),
                            'proof_bytes': self.proof.stat().st_size, 'input_sha256': [1] * 32,
                            'executable_sha256': [2] * 32, 'verdict': {'provider': 'nvidia_cuda',
                            'counters': {'cpu_fallback_attempts': 0, 'cpu_fallbacks_completed': 0}}}]}
        self.oracle = {'schema_version': 1, 'channel': 'blake2s', 'proof_format': 'json',
                       'verified': True, 'proof_sha256': digest.hex(), 'error': None,
                       'stwo_cairo_revision': CAIRO_REVISION, 'stwo_revision': STWO_REVISION}

    def check(self, backend, oracle):
        return check_receipts(backend, oracle, self.proof, input_sha256='01' * 32,
                              executable_sha256='02' * 32)

    def test_wrong_benchmark_or_provider_cannot_borrow_verified_proof(self):
        for key in ('input_sha256', 'executable_sha256'):
            backend = copy.deepcopy(self.backend)
            backend['completed_trials'][0][key] = [0] * 32
            with self.assertRaises(ValueError):
                self.check(backend, self.oracle)
        backend = copy.deepcopy(self.backend)
        backend['completed_trials'][0]['verdict']['provider'] = 'cumetal'
        with self.assertRaises(ValueError):
            self.check(backend, self.oracle)
        backend['completed_trials'][0]['verdict']['provider'] = 'nvidia_cuda'
        backend['completed_trials'][0]['verdict']['counters']['cpu_fallback_attempts'] = 1
        with self.assertRaises(ValueError):
            self.check(backend, self.oracle)

    def test_matching_independent_verifier_receipt_is_accepted(self):
        self.assertEqual(self.backend['completed_trials'][0],
                         self.check(self.backend, self.oracle))

    def test_protocol_changes_cannot_be_reported_as_canonical(self):
        mutations = dict(SECURITY, fri_lifting_log_size=25, preprocessed_variant='canonical_small')
        for key, value in mutations.items():
            with self.subTest(key=key):
                backend = copy.deepcopy(self.backend)
                backend['completed_trials'][0]['protocol'][key] = value + 1 if isinstance(value, int) else value
                with self.assertRaises(ValueError):
                    self.check(backend, self.oracle)
        backend = copy.deepcopy(self.backend)
        del backend['completed_trials'][0]['protocol']['fri_lifting_log_size']
        with self.assertRaises(ValueError):
            self.check(backend, self.oracle)

    def test_mutated_or_truncated_proof_is_rejected(self):
        for payload in (b'actual emitted proof byteX\n', b'actual emitted'):
            self.proof.write_bytes(payload)
            with self.assertRaises(ValueError):
                self.check(self.backend, self.oracle)

    def test_wrong_or_unverified_oracle_cannot_qualify_a_benchmark(self):
        for key, value in {'verified': False, 'proof_sha256': '00' * 32,
                           'stwo_cairo_revision': '00' * 20, 'stwo_revision': '00' * 20,
                           'channel': 'poseidon252', 'proof_format': 'binary',
                           'schema_version': 2, 'error': 'InvalidFriDegree'}.items():
            with self.subTest(key=key):
                oracle = dict(self.oracle, **{key: value})
                with self.assertRaises(ValueError):
                    self.check(self.backend, oracle)

    def test_wrong_publication_size_or_receipt_shape_is_rejected(self):
        backend = copy.deepcopy(self.backend)
        backend['completed_trials'][0]['proof_bytes'] += 1
        with self.assertRaises(ValueError):
            self.check(backend, self.oracle)
        for trials in ([], self.backend['completed_trials'] * 2):
            with self.assertRaises(ValueError):
                self.check(dict(self.backend, completed_trials=trials), self.oracle)


if __name__ == '__main__':
    unittest.main()
