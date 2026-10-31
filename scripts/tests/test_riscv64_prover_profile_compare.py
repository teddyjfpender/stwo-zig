"""Prevent performance claims from silently changing proof obligations."""
import copy
import json
import unittest
from pathlib import Path
from scripts import riscv64_prover_profile_compare as compare


class ProfileComparisonTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[2]
        source = root / 'vectors/reports/rv64-qualification-20261030/csp-full-parallel.json'
        self.before = json.loads(source.read_text())
        self.before['cases'] = self.before['cases'][:1]
        self.after = copy.deepcopy(self.before)

    def test_unchanged_verified_work_is_admitted(self):
        self.assertEqual(1, len(compare.compare(self.before, self.after)))

    def test_weaker_security_or_extra_workers_cannot_claim_a_speedup(self):
        for field in ('fri_queries', 'workers', 'instructions'):
            changed = copy.deepcopy(self.after)
            changed['cases'][0]['prover'][field] += 1
            with self.assertRaisesRegex(ValueError, 'geometry or security'):
                compare.compare(self.before, changed)

    def test_changed_proof_is_rejected(self):
        self.after['cases'][0]['artifact_sha256']['proof.bin'] = 'different'
        with self.assertRaisesRegex(ValueError, 'proof bytes changed'):
            compare.compare(self.before, self.after)

    def test_missing_receiver_authority_is_rejected(self):
        self.after['cases'][0]['independent_statement_binding'] = False
        with self.assertRaisesRegex(ValueError, 'independent expected-state'):
            compare.compare(self.before, self.after)

    def test_duplicate_or_incomplete_coverage_is_rejected(self):
        self.after['cases'] *= 2
        with self.assertRaisesRegex(ValueError, 'coverage differs'):
            compare.compare(self.before, self.after)

    def test_empty_reports_do_not_qualify_an_execution(self):
        self.before['cases'] = []
        self.after['cases'] = []
        with self.assertRaisesRegex(ValueError, 'coverage differs'):
            compare.compare(self.before, self.after)

    def semantic_reports(self):
        for report in (self.before, self.after):
            case = report['cases'][0]
            config = {'pow_bits': case['prover']['pow_bits'], 'lifting_log_size': None,
                      'fri_config': {'n_queries': case['prover']['fri_queries'],
                                     'log_blowup_factor': 1,
                                     'log_last_layer_degree_bound': 0, 'fold_step': 1}}
            case['semantic_statement_sha256'] = 'a' * 64
            case['fresh_claim_verification'] = True
            case['pcs_config'] = config
            case['prover']['pcs_config'] = copy.deepcopy(config)
            case['fresh_process']['pcs_config'] = copy.deepcopy(config)

    def test_semantic_gate_admits_new_encoding_and_reports_geometry_change(self):
        self.semantic_reports()
        case = self.after['cases'][0]
        case['prover']['main_columns'] -= 10
        case['prover']['interaction_columns'] += 3
        case['prover']['rows'] *= 2
        case['artifact_sha256'] = {name: 'b' * 64 for name in case['artifact_sha256']}
        rows = compare.compare(self.before, self.after, 'semantic')
        self.assertFalse(rows[0]['exact_artifact_parity'])
        self.assertEqual(rows[0]['before_rows'] * 2, rows[0]['after_rows'])
        self.assertEqual('semantic', rows[0]['parity_gate'])

    def test_semantic_gate_rejects_changed_execution_statement(self):
        self.semantic_reports()
        self.after['cases'][0]['semantic_statement_sha256'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'statement semantics'):
            compare.compare(self.before, self.after, 'semantic')

    def test_different_instrumentation_does_not_report_a_total_speedup(self):
        self.semantic_reports()
        self.after['profile_stages'] = not self.before.get('profile_stages', False)
        row = compare.compare(self.before, self.after, 'semantic')[0]
        self.assertFalse(row['timing_metadata_match'])
        self.assertIsNone(row['total_speedup'])

    def test_semantic_gate_requires_fresh_claim_verification_and_explicit_security(self):
        self.semantic_reports()
        for field in ('semantic_statement_sha256', 'fresh_claim_verification', 'pcs_config'):
            changed = copy.deepcopy(self.after)
            del changed['cases'][0][field]
            with self.assertRaises(ValueError):
                compare.compare(self.before, changed, 'semantic')
        changed = copy.deepcopy(self.after)
        del changed['cases'][0]['fresh_process']['pcs_config']
        with self.assertRaisesRegex(ValueError, 'receiver security'):
            compare.compare(self.before, changed, 'semantic')

    def test_semantic_gate_rejects_changed_blowup_even_with_same_query_count(self):
        self.semantic_reports()
        case = self.after['cases'][0]
        for config in (case['pcs_config'], case['prover']['pcs_config'],
                       case['fresh_process']['pcs_config']):
            config['fri_config']['log_blowup_factor'] = 2
        with self.assertRaisesRegex(ValueError, 'security configuration changed'):
            compare.compare(self.before, self.after, 'semantic')

    def test_semantic_gate_rejects_ambiguous_or_partial_security_schema(self):
        self.semantic_reports()
        for bad in (True, -1, 0, '1'):
            changed = copy.deepcopy(self.after)
            changed['cases'][0]['pcs_config']['fri_config']['log_blowup_factor'] = bad
            with self.assertRaisesRegex(ValueError, 'Invalid PCS'):
                compare.compare(self.before, changed, 'semantic')
