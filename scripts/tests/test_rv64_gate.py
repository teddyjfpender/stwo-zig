import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_gate as gate
import rv64_m5_negative_corpus as corpus


class GateTests(unittest.TestCase):
    def test_parity_refuses_missing_extra_and_changed_proofs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proof = root / 'recursion-om31/root.proof'
            proof.parent.mkdir()
            proof.write_bytes(b'accepted')
            golden = {'recursion-om31/root.proof': {'sha256': gate.stack.sha(proof), 'bytes': 8}}
            self.assertTrue(gate.frozen_parity(root, golden)['byte_identical'])
            # Diagnostics can change without changing the proof.
            (root / 'report.json').write_text('{}')
            (root / 'physical-0000.stages.json').write_text('{"seconds": 1}')
            (root / 'candidate-fixed-setup.json').write_text('{"source_validations": 11}')
            self.assertTrue(gate.frozen_parity(root, golden)['byte_identical'])
            extra = root / 'cpu-9.bin'
            extra.write_bytes(b'extra')
            with self.assertRaises(RuntimeError): gate.frozen_parity(root, golden)
            extra.unlink()
            proof.write_bytes(b'mutated!')
            with self.assertRaises(RuntimeError): gate.frozen_parity(root, golden)
            proof.unlink()
            with self.assertRaises(RuntimeError): gate.frozen_parity(root, golden)

    def test_extra_environment_accepts_only_unique_stwo_keys(self):
        self.assertEqual(gate.extra_environment(['STWO_RV64_M8_JOBS=1', 'STWO_X=a=b']),
                         {'STWO_RV64_M8_JOBS': '1', 'STWO_X': 'a=b'})
        self.assertEqual(gate.extra_environment([]), {})
        for bad in (['PATH=/tmp'], ['STWO_RV64_M8_JOBS'], ['stwo_x=1'], ['STWO_A=1', 'STWO_A=2'], ['STWO_A-B=1']):
            with self.assertRaises(ValueError): gate.extra_environment(bad)

    def test_corpus_cannot_pass_by_running_nothing_or_skipping(self):
        good = {'results': [{'id': name, 'passed': True} for name in gate.CASES]}
        gate.check_corpus(good)
        for bad in ({'results': []}, {'results': good['results'][:-1]},
                    dict(good, unsupported=[{'id': gate.CASES[0]}]),
                    dict(good, crashes=['C00-control']),
                    {'results': good['results'] + good['results'][:1]}):
            with self.assertRaises(RuntimeError): gate.check_corpus(bad)
        known = {c['id'] for c in corpus.CASES if 'mutate' in c}
        self.assertLessEqual(set(gate.CASES), known)

    def test_resident_corpus_selects_cold_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proof = root / 'actual-proof'
            proof.mkdir()
            (proof / 'bundle.json').write_text('{}')
            (root / 'plan.json').write_text(json.dumps({'jobs': [{'block': 26235156}]}))
            (root / 'receipt.json').write_text(json.dumps({'requests': [
                {'block': 26235156, 'trial': 0, 'proof': str(proof)},
                {'block': 26235156, 'trial': 1, 'proof': 'not-cold'}]}))
            self.assertEqual(corpus.proof_dir(root)[2], proof)


if __name__ == '__main__':
    unittest.main()
