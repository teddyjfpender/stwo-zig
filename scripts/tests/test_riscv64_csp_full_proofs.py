"""Fail-closed evidence and checkpoint coverage for full CSP proof orchestration."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import riscv64_csp_full_proofs as driver


class FullProofDriverTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.work = self.root / 'work'
        self.input = self.root / 'input.bin'
        self.input.write_bytes(b'expected input')
        self.elf = self.work / 'target' / driver.ISA[1] / 'release' / driver.BINARIES['sha256']
        self.elf.parent.mkdir(parents=True)
        self.elf.write_bytes(b'pinned ELF')
        manifest_path = self.root / 'vectors/riscv_csp/manifest-v2.json'
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text(json.dumps({'targets': {'sha256': {'cases': [
            {'input_sha256': driver.digest(self.input), 'input_path': 'input.bin'}]}},
            'negative_fixtures': []}))
        self.row = {'target': 'sha256', 'size': 1, 'negative': False,
                    'rv64_instructions': 100, 'input_sha256': driver.digest(self.input),
                    'elf_sha256': {driver.ISA[1]: driver.digest(self.elf)}, 'output': '0' * 64}
        self.execution = {'complete': True, 'oracle': 'Unicorn 2.1.4', 'rows': [self.row]}
        self.execution_path = self.root / 'execution.json'
        self.execution_path.write_text(json.dumps(self.execution))
        self.report_path = self.root / 'report.json'
        binaries = self.root / 'zig-out/bin'
        binaries.mkdir(parents=True)
        for name in ('rv64-csp-full', 'rv64-full-verify'):
            (binaries / name).write_bytes(name.encode())
        self.args = ['--execution-report', str(self.execution_path), '--work-dir', str(self.work),
                     '--report', str(self.report_path), '--target', 'sha256', '--size', '1',
                     '--negative', 'false']
        self.symbols = dict(zip(('__' + name for name in
                                ('input_start', 'input_end', 'halt_flag', 'output_len',
                                 'output_data', 'output_end', 'stack_bottom', 'stack_top')),
                                (0x2000, 0x3000, 0x3000, 0x3004, 0x3008, 0x4000, 0x4000, 0x5000)))
        self.addCleanup(patch.stopall)
        patch.object(driver, 'ROOT', self.root).start()
        patch.object(driver, 'elf_info', return_value=(0x100001000, self.symbols,
                     [(0x100001000, 4, b'\x13\0\0\0', 5)])).start()

    def statement(self):
        registers = [0] * 32
        registers[2] = 0x5000
        cells = [{'address': address, 'initial': 0,
                  'final': 0x2000000001 if address == 0x3000 else 0,
                  'readable': True, 'writable': True}
                 for address in range(0x3000, 0x3028, 8)]
        return {'program': {'base': 0x100001000, 'words': [0x13], 'addresses': [0x100001000]},
                'steps': 100, 'initial_pc': 0x100001000, 'final_pc': 0x100001004,
                'initial_registers': registers, 'final_registers': list(registers),
                'cells': cells, 'register_clocks': [0] * 32,
                'memory_clocks': [4, 8, 12, 16, 20], 'opcodes': [True] + [False] * 64}

    def process(self, command, timeout, label):
        if label == 'Fresh verifier':
            self.assertEqual([path.name for path in command[1:]],
                             ['statement.json', 'claims.json', 'proof.bin'])
            return {'verified': True, 'whole_guest_proof': True}, 2
        config = json.loads(Path(command[1]).read_text())
        if config['profile_only']:
            return {'instructions': 100, 'profile_only': True, 'whole_guest_proof': False}, 1
        for name in ('statement.json', 'claims.json', 'proof.bin'):
            (Path(config['artifact_dir']) / name).write_bytes(b'artifact')
        (Path(config['artifact_dir']) / 'statement.json').write_text(json.dumps(self.statement()))
        return {'instructions': 100, 'verified': True, 'whole_guest_proof': True}, 1

    def test_full_evidence_requires_fresh_verification_and_pins_all_artifacts(self):
        with patch.object(driver, 'run_json', side_effect=self.process) as process:
            result = driver.main(self.args)
        self.assertTrue(result['complete'])
        self.assertTrue(result['whole_guest_proof'])
        self.assertEqual(process.call_count, 2)
        self.assertEqual(len(result['cases'][0]['artifact_sha256']), 3)
        self.assertTrue(result['cases'][0]['independent_statement_binding'])
        self.assertEqual(result, json.loads(self.report_path.read_text()))

    def test_packed_policy_is_explicit_in_prover_config_and_trusted_receiver_argument(self):
        def selected(command, timeout, label):
            if label == 'Fresh verifier':
                self.assertEqual(command[-1], 'limbs24_v2')
                result, elapsed = self.process(command[:-1], timeout, label)
            else:
                config = json.loads(Path(command[1]).read_text())
                self.assertEqual(config['control_policy'], 'limbs24_v2')
                result, elapsed = self.process(command, timeout, label)
            result['control_policy'] = 'limbs24_v2'
            return result, elapsed
        with patch.object(driver, 'run_json', side_effect=selected):
            report = driver.main(self.args + ['--control-policy', 'limbs24_v2'])
        self.assertTrue(report['complete'])
        self.assertEqual(report['control_policy'], 'limbs24_v2')

    def test_unbound_packed_producer_or_receiver_policy_cannot_complete(self):
        for missing in ('Full prover', 'Fresh verifier'):
            with self.subTest(missing=missing):
                def selected(command, timeout, label):
                    result, elapsed = self.process(command[:-1] if label == 'Fresh verifier' else command, timeout, label)
                    if label != missing:
                        result['control_policy'] = 'limbs24_v2'
                    return result, elapsed
                with patch.object(driver, 'run_json', side_effect=selected):
                    with self.assertRaisesRegex(ValueError, 'control policy'):
                        driver.main(self.args + ['--control-policy', 'limbs24_v2'])
                self.assertFalse(json.loads(self.report_path.read_text())['complete'])

    def test_requested_stage_profile_is_required(self):
        with patch.object(driver, 'run_json', side_effect=self.process):
            with self.assertRaisesRegex(ValueError, 'stage profile is missing'):
                driver.main(self.args + ['--profile-stages'])
        report = json.loads(self.report_path.read_text())
        self.assertFalse(report['complete'])
        self.assertTrue(report['profile_stages'])

    def test_changed_input_during_proving_cannot_complete(self):
        def changed(command, timeout, label):
            result = self.process(command, timeout, label)
            self.input.write_bytes(b'changed during proof')
            return result
        with patch.object(driver, 'run_json', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed during benchmark'):
                driver.main(self.args)
        report = json.loads(self.report_path.read_text())
        self.assertFalse(report['complete'])
        self.assertEqual('failed', report['cases'][0]['status'])

    def test_profile_does_not_run_verifier_or_claim_proof_completion(self):
        with patch.object(driver, 'run_json', side_effect=self.process) as process:
            result = driver.main(self.args + ['--profile-only'])
        self.assertFalse(result['complete'])
        self.assertFalse(result['whole_guest_proof'])
        self.assertTrue(result['all_selected_profiled'])
        self.assertEqual(process.call_count, 1)
        self.assertNotIn('artifact_sha256', result['cases'][0])

    def test_fresh_verification_failure_is_checkpointed(self):
        def fail(command, timeout, label):
            if label == 'Fresh verifier':
                return {'verified': False, 'whole_guest_proof': False}, 2
            return self.process(command, timeout, label)
        with patch.object(driver, 'run_json', side_effect=fail):
            with self.assertRaisesRegex(ValueError, 'Fresh verifier'):
                driver.main(self.args)
        report = json.loads(self.report_path.read_text())
        self.assertFalse(report['complete'])
        self.assertEqual(report['cases'][0]['status'], 'failed')

    def test_changed_input_rejected_before_running_prover(self):
        self.input.write_bytes(b'substituted input')
        with patch.object(driver, 'run_json') as process:
            with self.assertRaisesRegex(ValueError, 'Guest input differs'):
                driver.main(self.args)
            process.assert_not_called()
        self.assertEqual(json.loads(self.report_path.read_text())['cases'][0]['status'], 'failed')

    def test_case_order_and_filters_preserve_smallest_first(self):
        large = dict(self.row, size=2, rv64_instructions=200)
        negative = dict(self.row, size=3, negative=True, rv64_instructions=50)
        execution = dict(self.execution, rows=[large, self.row, negative])
        self.assertEqual([row['size'] for row in driver.selected_rows(execution)], [3, 1, 2])
        self.assertEqual(driver.selected_rows(execution, negative='true'), [negative])
        with self.assertRaisesRegex(ValueError, 'No execution cases'):
            driver.selected_rows(execution, sizes=[99])
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            driver.selected_rows(dict(self.execution, rows=[self.row, self.row]))

    def test_failed_atomic_json_keeps_prior_checkpoint(self):
        driver.atomic_json(self.report_path, {'complete': False})
        with self.assertRaises(ValueError):
            driver.atomic_json(self.report_path, {'invalid': float('nan')})
        self.assertEqual(json.loads(self.report_path.read_text()), {'complete': False})
        self.assertEqual(list(self.root.glob('report.json.*.tmp')), [])

    def test_independent_statement_binding_rejects_program_initial_state_and_terminal_substitutions(self):
        config = driver.case_config(self.row, json.loads(
            (self.root / 'vectors/riscv_csp/manifest-v2.json').read_text()),
            self.work, False, 48 * 1024 ** 3)
        statement = self.statement()
        driver.validate_expected_statement(statement, config)
        mutations = []
        changed = copy.deepcopy(statement)
        changed['program']['addresses'][0] = 0x1000
        mutations.append(changed)
        changed = copy.deepcopy(statement)
        changed['initial_registers'][1] = 1
        mutations.append(changed)
        changed = copy.deepcopy(statement)
        changed['cells'][0]['initial'] = 1
        mutations.append(changed)
        changed = copy.deepcopy(statement)
        changed['cells'][0]['writable'] = False
        mutations.append(changed)
        changed = copy.deepcopy(statement)
        changed['cells'][0]['final'] = 0x2000000000
        mutations.append(changed)
        changed = copy.deepcopy(statement)
        changed['cells'].pop()
        mutations.append(changed)
        changed = copy.deepcopy(statement)
        changed['cells'][1]['final'] = 1
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    driver.validate_expected_statement(changed, config)


if __name__ == '__main__':
    unittest.main()
