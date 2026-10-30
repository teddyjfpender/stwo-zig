"""Regression checks for cheap postprocessing; never invoke Zig/proving."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import v8_real_endpoint_group_bundle as runner


class GroupPublicationTests(unittest.TestCase):
    def test_summary_uses_source_stage_and_reports_closed_originals(self):
        stats = dict(whole_ns=10_000_000_000, source=dict(original_ns=5_000_000_000,
            original=dict(core_ns=4_000_000_000), cohorts=8), bridge_ns=1_000_000_000,
            global_proof_ns=2_000_000_000, fresh_bundle_ns=2_000_000_000, charged_peak_bytes=123)
        result = runner.result_summary(Path('output'), stats)
        self.assertEqual(result['group_core_s'], 4)
        self.assertEqual(result['cohorts'], 8)
        self.assertEqual(result['original_proofs'], 3)
        self.assertTrue(result['global_ram_closed'])
        self.assertFalse(result['recursive_root'])

    def test_validate_only_never_executes_or_prepares_proving_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            snapshots, destination = root / 'snapshots', root / 'existing'
            snapshots.mkdir(); destination.mkdir()
            binary = root / 'benchmark'; binary.write_bytes(b'fake-binary')
            pin = hashlib.sha256(b'elf').hexdigest()
            capture = dict(elf_sha256=pin, window=dict(skip_cycles=1, cycles=8))
            cap = snapshots / 'capture.json'; cap.write_text(json.dumps(capture))
            binary_sha = runner.sha(binary)
            build = root / 'build.json'
            build.write_text(json.dumps(dict(binary_sha256=binary_sha, source_unchanged_during_build=True)))
            invocation = dict(returncode=0, binary_sha256=binary_sha, capture_sha256=runner.sha(cap),
                workers=8, cohort_cycles=4, group_profile='compact_v1', native_batch=False)
            (destination / 'invocation.json').write_text(json.dumps(invocation))
            argv = ['runner', '--bundle', str(root), '--snapshots', str(snapshots), '--binary', str(binary),
                '--build-manifest', str(build), '--destination', str(destination), '--capture-sha256', runner.sha(cap),
                '--cohort-cycles', '4', '--validate-only']
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(runner, 'PINS', {'guest.elf': (pin, 100)}), \
                 mock.patch.object(runner, 'checked_bytes', return_value=b'elf'), \
                 mock.patch.object(runner, 'validate_report', return_value={}) as validate, \
                 mock.patch.object(runner.subprocess, 'run', side_effect=AssertionError('must not prove')), \
                 mock.patch.object(runner, 'snapshot_bytes', side_effect=AssertionError('must not prepare')), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 0)
                validate.assert_called_once()


if __name__ == '__main__': unittest.main()
