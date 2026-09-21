"""The benchmark must prove the requested workload, including rejected signatures."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_csp_benchmark as csp
from scripts.riscv_csp_benchmark_lib.evidence import EvidenceRun, prove_negative_case
from scripts.riscv_csp_benchmark_lib.validation import validate_workload_binding


from scripts.tests.riscv_csp_provenance_fixture import artifact_workload


class WorkloadBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.cases, cls.negatives = csp.validate_manifest()
        cls.case = cls.cases[-1]

    def test_canonical_public_io_matches(self):
        for case in self.cases:
            validate_workload_binding(artifact_workload(case), case)

    def test_source_output_input_and_partial_execution_substitution_are_rejected(self):
        original = artifact_workload(self.case)
        def output(a): a['statement']['public_data']['output_words'][1]['value'] ^= 1
        def input_word(a): a['statement']['public_data']['input_words'][0] ^= 1
        def source(a): a['source']['elf_sha256'] = '0' * 64
        def segment(a): a['statement']['segment_count'] = 2
        def cycle(a): a['statement']['public_data']['clock'] += 1
        def padding(a): a['statement']['public_data']['input_words'][-1] |= 0xff000000
        for mutate in (output, input_word, source, segment, cycle, padding):
            with self.subTest(mutate=mutate.__name__):
                artifact = copy.deepcopy(original)
                mutate(artifact)
                with self.assertRaises(csp.BenchmarkError):
                    validate_workload_binding(artifact, self.case)

    def test_negative_case_runs_the_same_proof_validator_on_the_bad_input(self):
        negative = self.negatives[0]
        def benchmark(case, *args, **options):
            self.assertEqual(negative.input_sha256, case.input_sha256)
            self.assertEqual(negative.expected_cycles, case.expected_cycles)
            self.assertEqual((0, 1), (options['warmups'], options['samples']))
            validate_workload_binding(artifact_workload(case), case)
            return {'cycles': case.expected_cycles, 'evidence': {
                'status': 'verified', 'output_digest': case.expected_digest,
                'public_values_sha256': 'a' * 64}}, 'b' * 40
        with tempfile.TemporaryDirectory() as directory:
            item, _ = prove_negative_case(negative, self.cases, Path('cli'), Path('trace'),
                                         benchmark=benchmark, work_dir=Path(directory))
        self.assertEqual('verified', item['proof_status'])
        self.assertEqual('00' * 32, item['output_digest'])

    def test_failed_proof_preserves_prior_evidence_without_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            run = EvidenceRun(Path(directory) / 'report.json')
            with self.assertRaisesRegex(csp.BenchmarkError, 'proof failed'):
                with run:
                    run.record('measurement', {'target': 'sha256'})
                    raise csp.BenchmarkError('proof failed')
            progress = json.loads((run.directory / 'progress.json').read_text())
            self.assertEqual('failed', progress['status'])
            self.assertEqual(1, len(progress['results']))
            self.assertFalse((Path(directory) / 'report.json').exists())

    def test_precompile_inventory_authenticates_without_launching_a_binary(self):
        with mock.patch.object(csp, '_run', side_effect=AssertionError('launched binary')):
            inventory = csp.workload_inventory(self.cases)
            csp.require_execution_mode('precompile')
        self.assertEqual('available', inventory['precompile']['status'])
        self.assertEqual('riscv_guest', inventory['precompile']['proof_scope'])
        self.assertEqual({'0', '1'}, set(inventory['precompile']['guests']))

    def test_nonfinite_phase_times_are_not_publishable(self):
        for value in (float('nan'), float('inf'), -1, True):
            report = {name: 1 for name in ('mean_execution_seconds', 'mean_witness_seconds',
                                          'mean_proving_seconds', 'mean_verification_seconds')}
            report['mean_proving_seconds'] = value
            with self.assertRaises(csp.BenchmarkError):
                csp._phase_seconds(report)


if __name__ == '__main__':
    unittest.main()
