"""The accelerated runner authenticates routes, artifacts and verifier receipts."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from scripts.riscv_csp_benchmark_lib import precompile as p
from scripts.riscv_csp_benchmark_lib.contract import validate_manifest, SECURE_PCS_CONFIG, BenchmarkError, sha256_bytes


class PrecompileTests(unittest.TestCase):
    def setUp(self):
        _, cases, _ = validate_manifest()
        self.case = next(case for case in cases if case.target == 'ecdsa_secp256k1')
        self.manifest = p.validate_manifest()

    def run_case(self, route=0, mutate=lambda _: None, receipt_mutate=lambda _: None, backend='cpu', suite='blake2s'):
        guest = self.manifest['guests']['0']
        version, artifact_version, hasher = {'blake2s': (1, 2, 1), 'blake3': (2, 6, 3)}[suite]
        header = bytearray(80)
        header[:8] = b'STWGPF01'
        header[8:10] = artifact_version.to_bytes(2, 'little')
        header[26:28] = hasher.to_bytes(2, 'little')
        encoded = bytes(header) + b'fixture proof'
        transcript = dict(version=version, suite=suite, digest='d' * 64)
        report = dict(schema='stwo.csp.ecdsa-guest-benchmark.v2', backend=backend,
                      transcript_receipt=transcript, proof_scope='riscv_guest', uses_precompile=True, recursion_enabled=False,
                      implementation_dirty=False, implementation_commit='b' * 40,
                      pcs_config=SECURE_PCS_CONFIG, warmups=0, samples=1, verified_samples=1,
                      workers=16, input_sha256=self.case.input_sha256, elf_sha256=guest['sha256'],
                      output_digest=self.case.expected_digest, recovery_id=0, statement_sha256='a' * 64,
                      artifact_sha256=sha256_bytes(encoded), artifact_bytes=len(encoded),
                      proof_bytes=5, cycles=1828,
                      measurements=[dict(execution_ns=1, witness_and_proving_ns=2, verification_ns=3,
                                         metal_dispatches=1 if backend == 'metal' else 0, cpu_fallbacks=0)])
        receipt = {key: report[key] for key in ('artifact_sha256', 'statement_sha256', 'elf_sha256', 'input_sha256', 'pcs_config', 'transcript_receipt')}
        receipt.update(schema='stwo.csp.ecdsa-verify.v2', status='verified')
        if suite == 'blake3':
            from scripts.tests.test_riscv_csp_full_width import FullWidthTests
            fixture = FullWidthTests(); fixture.setUp()
            fixture.case.guest_sha256 = guest['sha256']
            fixture.case.input_sha256 = self.case.input_sha256
            encoded = fixture.artifact(ethereum=True)
            report = fixture.report
            report.update(elf_sha256=guest['sha256'], input_sha256=self.case.input_sha256,
                          output_sha256=sha256_bytes(bytes.fromhex(self.case.expected_digest)),
                          workers=16, csp_ecdsa=True, signer_calls=1, keccak_calls=0, halt_flag=True,
                          artifact_magic='B3EVART1', execution_profile='rv32im_zkvm_ethereum_v1',
                          proof_bytes=len(encoded), proof_sha256=sha256_bytes(encoded))
            receipt = dict(report, schema='riscv_full_width_verify_v1', status='verified')
        receipt = copy.deepcopy(receipt)
        mutate(report)
        receipt_mutate(receipt)
        self.software = Mock(return_value=({'execution_mode': 'software'}, 'b' * 40))
        def run(args, **kwargs):
            if args[1] == "--proof-suite":
                self.assertEqual(args[2], suite)
                args = [args[0], *args[3:]]
            if args[1] == 'ecdsa-csp-select':
                value = dict(schema='stwo.csp.ecdsa-route.v1', input_sha256=self.case.input_sha256, recovery_id=route)
            elif args[1] == 'ecdsa-csp-bench':
                Path(args[args.index('--proof-out') + 1]).write_bytes(encoded)
                Path(args[args.index('--report-out') + 1]).write_text(json.dumps(report))
                value = report
            else:
                value = receipt
            return SimpleNamespace(stdout=json.dumps(value).encode(), stderr=b'')
        with tempfile.TemporaryDirectory() as directory:
            return p.benchmark_case(self.case, Path('cli'), Path('trace'), run=run,
                                    software_benchmark=self.software, backend=backend,
                                    warmups=0, samples=1, timeout=1, admission=SimpleNamespace(experimental=False),
                                    env={}, work_dir=Path(directory), proof_suite=suite)

    def test_full_guest_evidence_and_timing(self):
        row, _ = self.run_case()
        self.assertTrue(row['uses_precompile'])
        self.assertEqual(3, row['proof_duration'])
        self.assertEqual('riscv_guest', row['proof_scope'])
        self.software.assert_not_called()

    def test_blake3_suite_is_preserved(self):
        row, _ = self.run_case(suite='blake3')
        self.assertEqual('blake3', row['protocol']['proof_suite'])
        self.assertEqual('full_width_blake3', row['protocol']['commitment_model'])

    def test_transcript_substitutions_fail_closed(self):
        for field, value in [('suite', 'poseidon2'), ('version', True), ('version', 2), ('digest', 'x')]:
            with self.subTest(field=field), self.assertRaises(BenchmarkError):
                self.run_case(mutate=lambda r: r['transcript_receipt'].update({field: value}))
        with self.assertRaises(BenchmarkError):
            self.run_case(mutate=lambda r: r['transcript_receipt'].update(suite='blake3', version=2))
        for change in ({'digest': 'e' * 64}, {'version': True}):
            with self.assertRaises(BenchmarkError):
                self.run_case(receipt_mutate=lambda r: r['transcript_receipt'].update(change))

    def test_full_width_precompile_public_contract_and_receipt(self):
        row, _ = self.run_case(suite='blake3')
        self.assertEqual(row['execution_mode'], 'precompile')
        self.assertEqual(row['protocol']['commitment_model'], 'full_width_blake3')
        self.assertNotIn('public_values_sha256', row['evidence'])
        for field, value in [('signer_calls', 0), ('keccak_calls', 1), ('halt_flag', False),
                             ('csp_ecdsa', False), ('output_sha256', '0' * 64), ('total_steps', 8)]:
            with self.subTest(field=field), self.assertRaises(BenchmarkError):
                self.run_case(suite='blake3', receipt_mutate=lambda r: r.update({field: value}))
        for field, value in [('signer_calls', 2), ('keccak_calls', 1), ('halt_flag', False)]:
            with self.subTest(field=field), self.assertRaises(BenchmarkError):
                self.run_case(suite='blake3', mutate=lambda r: r.update({field: value}))

    def test_unsupported_inputs_receive_software_proof(self):
        row, _ = self.run_case(route=None)
        self.assertEqual('software_fallback', row['execution_mode'])
        self.software.assert_called_once()

    def test_invalid_routing_hints_fail_closed(self):
        for route in (True, 2, '0'):
            with self.assertRaises(BenchmarkError):
                self.run_case(route=route)

    def test_report_substitutions_fail_closed(self):
        for key, value in [('input_sha256', 'c' * 64), ('elf_sha256', 'd' * 64),
                           ('artifact_sha256', 'e' * 64), ('uses_precompile', False),
                           ('implementation_dirty', True), ('verified_samples', 0),
                           ('proof_scope', 'provider'), ('pcs_config', {})]:
            with self.subTest(key=key), self.assertRaises(BenchmarkError):
                self.run_case(mutate=lambda report: report.update({key: value}))

    def test_retained_receipt_must_bind_same_artifact(self):
        with self.assertRaises(BenchmarkError):
            self.run_case(receipt_mutate=lambda receipt: receipt.update(artifact_sha256='f' * 64))

    def test_metal_requires_measured_dispatch(self):
        self.run_case(backend='metal')
        with self.assertRaises(BenchmarkError):
            self.run_case(backend='metal', mutate=lambda report: report['measurements'][0].update(metal_dispatches=0))

    def test_source_and_guest_hash_drift_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['guests']['0']['sha256'] = '0' * 64
        with patch.object(p, 'load_json', return_value=manifest), self.assertRaises(BenchmarkError):
            p.validate_manifest()


if __name__ == '__main__':
    unittest.main()
