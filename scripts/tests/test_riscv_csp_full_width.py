"""Adversarial framing and measurement checks; proof validity is checked by CLI."""
import copy
import json
import tempfile
from pathlib import Path
import struct
import unittest
from types import SimpleNamespace

from scripts.riscv_csp_benchmark_lib import full_width as fw
from scripts.riscv_csp_benchmark_lib.contract import BenchmarkError, SECURE_PCS_CONFIG, sha256_bytes


class FullWidthTests(unittest.TestCase):
    def setUp(self):
        self.case = SimpleNamespace(expected_cycles=7, guest_sha256='a' * 64,
                                    input_sha256='b' * 64, expected_digest='01' * 32)
        timing = {p: i + 1 for i, p in enumerate(fw.PHASES)}
        timing['total_ns'] = sum(timing.values())
        self.report = dict(schema='riscv_full_width_execution_v2', mode='bench',
            proof_suite='blake3', security_policy='secure', backend='cpu',
            release_status='experimental_full_width', experimental=False,
            verified_in_process=True, recursion_enabled=False, warmups=0, samples=1,
            verified_samples=1, total_steps=7, timing_unit='nanoseconds',
            timing_partition=fw.PARTITION, elf_sha256=self.case.guest_sha256,
            input_sha256=self.case.input_sha256, output_len=32,
            output_sha256=sha256_bytes(bytes.fromhex(self.case.expected_digest)),
            implementation_dirty=False, implementation_commit='c' * 40,
            pcs_config=copy.deepcopy(SECURE_PCS_CONFIG), statement_blake3='d' * 64,
            transcript_digest_blake3='e' * 64, proof_sha256='f' * 64,
            executable_sha256='1' * 64, timings=[timing],
            median_seconds=timing['total_ns'] / 1e9,
            proof_device_counts=[dict(dispatches=0, cpu_fallbacks=0)])

    def check(self, report=None, backend='cpu'):
        return fw.validate_report(report or self.report, self.case, backend=backend,
                                  warmups=0, samples=1, experimental=False)

    def test_valid_phase_partition_and_omitted_null_policy(self):
        self.check()
        del self.report['pcs_config']['lifting_log_size']
        self.check()

    def test_security_source_and_output_drift_rejected(self):
        for field, value in [('output_sha256', '0' * 64), ('output_len', 31),
            ('elf_sha256', '0' * 64), ('input_sha256', '0' * 64),
            ('total_steps', 8), ('implementation_dirty', True),
            ('verified_in_process', False), ('samples', True)]:
            report = copy.deepcopy(self.report); report[field] = value
            with self.subTest(field=field), self.assertRaises(BenchmarkError): self.check(report)
        for key, value in [('n_queries', 69), ('fold_step', True)]:
            report = copy.deepcopy(self.report); report['pcs_config']['fri_config'][key] = value
            with self.subTest(key=key), self.assertRaises(BenchmarkError): self.check(report)

    def test_timing_forgery_rejected(self):
        for patch in ({'proving_ns': -1}, {'total_ns': 1}, {'witness_ns': True}, {'extra': 0}):
            report = copy.deepcopy(self.report); report['timings'][0].update(patch)
            with self.subTest(patch=patch), self.assertRaises(BenchmarkError): self.check(report)
        for value in (float('nan'), float('inf'), 10, True):
            report = copy.deepcopy(self.report); report['median_seconds'] = value
            with self.subTest(value=value), self.assertRaises(BenchmarkError): self.check(report)

    def test_metal_requires_real_proof_dispatch_and_preserves_fallbacks(self):
        self.report['backend'] = 'metal'
        with self.assertRaises(BenchmarkError): self.check(backend='metal')
        self.report['proof_device_counts'][0] = dict(dispatches=2, cpu_fallbacks=3)
        self.check(backend='metal')
        self.report['proof_device_counts'][0]['dispatches'] = True
        with self.assertRaises(BenchmarkError): self.check(backend='metal')

    def artifact(self, ethereum=False, *, poseidon=False, compact=False):
        metadata = bytearray(184)
        metadata[:12] = b'B3EXADM1\x01\0\0\0'
        metadata[12:44] = bytes.fromhex(self.case.guest_sha256)
        metadata[44:76] = bytes.fromhex(self.case.input_sha256)
        struct.pack_into('<7I', metadata, 76, 26, 1, 0, 70, 1, 0, 0)
        extended = ethereum or poseidon
        header = 64 if extended else 56
        claims = 4 if compact else 1
        body = bytearray(header + 16 * claims + 3)
        body[:12] = (b'B3EHART1' if ethereum else b'B3P2ART1' if poseidon else b'B3EXART1') + struct.pack('<I', 2 if compact else 1)
        struct.pack_into('<I', body, 44, claims)
        struct.pack_into('<Q', body, 56 if extended else 48, 3)
        body[-3:] = b'air'
        geometry = bytes(32) + b'CRNGEO01\x01\0\0\0' + struct.pack('<6I', 0, 4, 1, 4, 16, 4)
        if extended:
            prefix = (b'B3EHADM1' if ethereum else b'B3P2ADM1') + struct.pack('<I', 2 if compact else 1) + bytes(456 if ethereum else 278)
            metadata = prefix + (geometry if compact else b'') + metadata
        elif compact:
            metadata = b'B3CRADM1\x01\0\0\0' + geometry + metadata
        magic = b'B3EVART1' if ethereum else b'B3PVART1' if poseidon else b'B3RVART1'
        return magic + struct.pack('<IQQ', 1, len(metadata), len(body)) + metadata + body

    def test_payload_size_excludes_metadata_and_claims_for_both_profiles(self):
        for ethereum in (False, True):
            magic, elf, input_hash, proof = fw.artifact_sections(self.artifact(ethereum))
            self.assertEqual(elf, self.case.guest_sha256)
            self.assertEqual(input_hash, self.case.input_sha256)
            self.assertEqual(proof, b'air')

    def test_compact_payloads_and_version_geometry_rejections(self):
        for ethereum, poseidon in ((False, False), (True, False), (False, True)):
            for compact in (False, True):
                raw = self.artifact(ethereum, poseidon=poseidon, compact=compact)
                with self.subTest(ethereum=ethereum, poseidon=poseidon, compact=compact):
                    _, elf, input_hash, proof = fw.artifact_sections(raw)
                    self.assertEqual((elf, input_hash, proof),
                                     (self.case.guest_sha256, self.case.input_sha256, b'air'))
                    metadata_size = struct.unpack_from('<Q', raw, 12)[0]
                    bad = bytearray(raw)
                    struct.pack_into('<I', bad, 28 + metadata_size + 8, 1 if compact else 2)
                    with self.assertRaises(BenchmarkError):
                        fw.artifact_sections(bad)
                    if compact:
                        geometry_at = 28 + (468 if ethereum else 290 if poseidon else 12)
                        for offset, value in ((32, 0), (40, 2), (44, 0xffffffff), (48, 5)):
                            bad = bytearray(raw)
                            struct.pack_into('<I', bad, geometry_at + offset, value)
                            with self.assertRaises(BenchmarkError):
                                fw.artifact_sections(bad)

    def test_malformed_binary_and_noncanonical_policy_rejected(self):
        raw = self.artifact()
        for bad in (raw[:-1], raw + b'x', b'WRONGTAG' + raw[8:], raw[:27]):
            with self.assertRaises(BenchmarkError): fw.artifact_sections(bad)
        mutated = bytearray(raw); struct.pack_into('<I', mutated, 28 + 76, 25)
        with self.assertRaises(BenchmarkError): fw.artifact_sections(mutated)
        mutated = bytearray(raw); struct.pack_into('<Q', mutated, 28 + 184 + 48, 1)
        with self.assertRaises(BenchmarkError): fw.artifact_sections(mutated)

    def test_fresh_receipt_binds_output_transcript_and_stark_size(self):
        self.case.target = 'sha256'
        self.case.input_size = 128
        self.case.guest_bytes = 10
        self.case.uses_precompile = False
        self.case.guest_path = Path('guest.elf')
        self.case.input_path = Path('input.bin')
        raw = self.artifact()
        self.report.update(artifact_magic='B3RVART1', execution_profile='rv32im_zkvm_v1',
                           proof_bytes=len(raw), proof_sha256=sha256_bytes(raw))
        receipt = {k: self.report[k] for k in ('artifact_magic', 'execution_profile',
            'proof_suite', 'security_policy', 'release_status', 'statement_blake3',
            'transcript_digest_blake3', 'proof_bytes', 'proof_sha256', 'total_steps',
            'elf_sha256', 'input_sha256', 'output_len', 'output_sha256',
            'implementation_commit', 'implementation_dirty', 'executable_sha256', 'pcs_config')}
        receipt.update(schema='riscv_full_width_verify_v1', status='verified')
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / 'proof.bin'; artifact.write_bytes(raw)
            def invoke(command, **kwargs):
                self.assertIn('--input', command)
                self.assertEqual(command[command.index('--expect-statement-digest') + 1], self.report['statement_blake3'])
                return SimpleNamespace(stdout=json.dumps(receipt).encode())
            def finish():
                return fw.finish(self.case, self.report, cli=Path('cli'), backend='cpu',
                    warmups=0, samples=1, admission=SimpleNamespace(experimental=False),
                    env={}, timeout=1, artifact_path=artifact,
                    bench_path=Path(directory) / 'bench.json',
                    execution=dict(cycles=7, output_digest=self.case.expected_digest,
                                   public_values_sha256='0' * 64),
                    completed=SimpleNamespace(stdout=b'', stderr=b''), wall_duration_ns=100,
                    run=invoke, report_path=str)
            row, commit = finish()
            self.assertEqual(row['proof_size'], 3)
            self.assertEqual(row['proof_duration'], 10)
            self.assertEqual(row['evidence']['proof_sha256'], sha256_bytes(b'air'))
            for field in ('output_sha256', 'transcript_digest_blake3', 'elf_sha256'):
                saved = receipt[field]; receipt[field] = '0' * 64
                with self.subTest(field=field), self.assertRaises(BenchmarkError): finish()
                receipt[field] = saved


if __name__ == '__main__': unittest.main()
