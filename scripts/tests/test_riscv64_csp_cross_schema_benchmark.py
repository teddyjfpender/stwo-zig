import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scripts import riscv64_csp_cross_schema_benchmark as bench


class RunnerTests(unittest.TestCase):
    def test_existing_directory_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(output=directory, tools=directory, assets=directory)
            with self.assertRaisesRegex(ValueError, 'Exclusive'):
                bench.run(args)

    def test_failing_fresh_process_never_returns_success_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            class Failure: returncode = 3
            with patch.object(bench.subprocess, 'run', return_value=Failure()):
                with self.assertRaisesRegex(RuntimeError, 'fresh failed'):
                    bench.timed(['/pinned/fresh-verifier'], Path(directory), 'fresh')

    def test_rss_and_footprint_remain_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            def process(command, stdout, stderr, env, check):
                self.assertEqual(env['STWO_ZIG_WORKERS'], '8')
                Path(command[3]).write_text('1.50 real 2.00 user 0.25 sys\n123 maximum resident set size\n99 peak memory footprint\n4 page reclaims\n0 page faults\n')
                stdout.write(b'{"verified":true}')
                class Success: returncode = 0
                return Success()
            with patch.object(bench.subprocess, 'run', side_effect=process):
                report, timing = bench.timed(['/pinned/prover'], Path(directory), 'prove')
            self.assertTrue(report['verified'])
            self.assertEqual(timing['maximum_rss_bytes'], 123)
            self.assertEqual(timing['peak_memory_footprint_bytes'], 99)
            self.assertEqual(timing['system_seconds'], .25)

if __name__ == '__main__': unittest.main()
