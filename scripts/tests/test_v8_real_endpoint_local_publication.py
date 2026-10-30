"""Exercise runner publication with a fake prover; no cryptographic claims."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import v8_real_endpoint_local as runner


class PublicationTest(unittest.TestCase):
    def test_invocation_publication_preserves_every_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            snapshots = base / 'snapshots'
            snapshots.mkdir()
            window = dict(skip_cycles=1, cycles=4)
            pins = dict(elf_sha256='a' * 64, incoming_sha256='b' * 64,
                        outgoing_sha256='c' * 64)
            capture = dict(window=window, **pins)
            cap = snapshots / 'capture.json'
            cap.write_text(json.dumps(capture))
            binary = base / 'binary'
            binary.write_bytes(b'fake prover')
            manifest = base / 'build.json'
            manifest.write_text(json.dumps(dict(binary_sha256=runner.sha(binary))))
            destination = base / 'output'
            policy = dict(cohort_count=1, max_cohort_cycles=4)

            def fake_prover(*_args, **_kwargs):
                artifacts = destination / 'artifacts'
                artifacts.mkdir()
                data = {
                    'bridge-0.proof': b'bridge',
                    'global-memory.proof': b'global',
                    'global-public.json': json.dumps(dict(
                        schema='stwo-b8-local-compact-global-memory-metadata-v1',
                        window=window, cohort_policy=policy, **pins)).encode(),
                    'local-0.json': json.dumps(dict(schema=
                        'stwo-v8-local-native-endpoint-sparse-rom-metadata-v1')).encode(),
                    'local-0.proof': b'B8LCS001fake',
                    'local-0.stats.json': json.dumps(dict(security_queries=70,
                        security_pow_bits=26, cohort_ordinal=0, cohort_count=1)).encode(),
                }
                records = []
                for name, contents in sorted(data.items()):
                    (artifacts / name).write_bytes(contents)
                    records.append(dict(name=name, bytes=len(contents),
                        sha256=hashlib.sha256(contents).hexdigest()))
                report = dict(schema='stwo-b8-local-endpoint-compact-global-pipeline-benchmark-v1',
                    window=window, security_queries=70, security_pow_bits=26, workers=8,
                    program_flavor='sparse_elf', layout_version=2, cohort_policy=policy,
                    stats=dict(cycles=4, cohorts=1, bridge_batches=1,
                        parallel_local_proofs=2, local_core_proof_ns=10, charged_peak_bytes=100),
                    verified=dict(scope='declared_window_originals_closed', cycles=4,
                        cohorts=1, global_argument='compact_endpoint'),
                    artifacts=records, whole_including_loading_and_publication_ns=100)
                (destination / 'report.json').write_text(json.dumps(report))
                return type('Completed', (), {'returncode': 0})()

            arguments = ['runner', '--bundle', str(base), '--snapshots', str(snapshots),
                '--capture-sha256', runner.sha(cap), '--binary', str(binary),
                '--build-manifest', str(manifest), '--destination', str(destination),
                '--cohort-cycles', '4', '--parallel-local-proofs', '2', '--compact', '--sparse-rom']
            with patch.object(sys, 'argv', arguments), \
                 patch.object(runner, 'PINS', {'guest.elf': ('a' * 64, 0)}), \
                 patch.object(runner, 'checked_bytes'), \
                 patch.object(runner, 'snapshot_bytes', return_value=b'snapshot'), \
                 patch.object(runner.subprocess, 'run', side_effect=fake_prover):
                self.assertEqual(runner.main(), 0)
            invocation = json.loads((destination / 'invocation.json').read_text())
            self.assertTrue(invocation['report_checked'])
            report = json.loads((destination / 'report.json').read_text())
            for entry in report['artifacts']:
                self.assertEqual(runner.sha(destination / 'artifacts' / entry['name']), entry['sha256'])
            self.assertEqual(json.loads((destination / 'artifacts/local-0.stats.json').read_text())['cohort_ordinal'], 0)


if __name__ == '__main__':
    unittest.main()
