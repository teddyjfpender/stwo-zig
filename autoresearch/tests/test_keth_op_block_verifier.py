"""Genuine-STARK composition acceptance and rejection on a synthetic block."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import keth_types.patches
from autoresearch.experiments.evm_keth.op_compiler import compile_owned
from autoresearch.experiments.evm_keth.proof_statement import PRIME, program_claim
from autoresearch.experiments.evm_keth.verify_op_block import verify

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/op-verifier-contract-fixture'
ORACLE = ROOT / 'tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier'


@unittest.skipUnless(ORACLE.is_file() and (FIXTURE/'manifest.json').is_file(), 'build verifier and retain genuine fixture first')
class OpBlockVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = json.loads((FIXTURE/'case.json').read_text())
        source = ROOT / 'autoresearch/experiments/evm_keth/cairo/op_stack/execution_partitioned.cairo'
        program = compile_owned(source, proof_mode=True)
        cls.compiled = dict(data=[hex(value) for value in program.data])
        if program_claim(cls.compiled) != cls.case['program_claim_words']:
            raise ValueError('fixture bytecode differs from current owned compiler/source')

    def check(self, mutation=None, *, accepted=False, tamper_proof=False, wrong_program=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for proof in FIXTURE.glob('*.proof.json'):
                shutil.copyfile(proof, path/proof.name)
            manifest = json.loads((FIXTURE/'manifest.json').read_text())
            compiled = copy.deepcopy(self.compiled)
            if mutation:
                mutation(manifest)
            if tamper_proof:
                part = manifest['proofs'][0]['phases'][0]
                proof = path/part['proof']
                data = json.loads(proof.read_text())
                data['stark_proof']['commitments'][1][0] ^= 1
                raw = json.dumps(data).encode()
                proof.write_bytes(raw)
                # Match the untrusted manifest hash so cryptographic verification
                # must reject, rather than only the filesystem identity check.
                part['proof_sha256'] = hashlib.sha256(raw).hexdigest()
            if wrong_program:
                compiled['data'][0] = hex((int(compiled['data'][0], 16) + 1) % PRIME)
            (path/'manifest.json').write_text(json.dumps(manifest))
            (path/'compiled.json').write_text(json.dumps(compiled))
            def run():
                return verify(path/'manifest.json', path/'compiled.json', ORACLE,
                              self.case['block_hash'], self.case['parent_state_root'])
            if accepted:
                result = run()
                self.assertTrue(result['op_block_execution_proved'])
                self.assertEqual(result['transactions'], 1)
                self.assertEqual(result['gas_used'], 21000)
                self.assertFalse(result['derivation_proved'])
                self.assertFalse(result['recursive_aggregation_proved'])
                self.assertFalse(result['l1_verifier_compatible'])
            else:
                with self.assertRaises((ValueError, KeyError, subprocess.CalledProcessError)):
                    run()

    def test_complete_synthetic_execution_certificate(self):
        self.check(accepted=True)

    def test_incomplete_child_and_phase_coverage_reject(self):
        self.check(lambda m: m['proofs'].pop())
        self.check(lambda m: m['proofs'][0]['phases'].pop())

    def test_reordered_and_substituted_valid_phases_reject(self):
        def swap(m):
            p = m['proofs'][0]['phases']
            p[0], p[1] = p[1], p[0]
        def substitute(m):
            m['proofs'][1]['phases'][1] = m['proofs'][0]['phases'][1]
        self.check(swap)
        self.check(substitute)

    def test_trusted_program_and_proof_commitment_changes_reject(self):
        self.check(wrong_program=True)
        self.check(tamper_proof=True)

    def test_public_body_receipts_and_parent_identity_reject(self):
        self.check(lambda m: m['block']['transactions'][0].update(value='0x8'))
        self.check(lambda m: m['receipts'][0].update(cumulativeGasUsed='0x1'))
        self.check(lambda m: m['parent_header'].update(stateRoot='0x'+'00'*32))

    def test_final_message_passer_membership_is_required(self):
        self.check(lambda m: m.update(final_state_nodes=[]))


if __name__ == '__main__':
    unittest.main()
