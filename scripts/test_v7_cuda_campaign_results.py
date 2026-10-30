import json
import tempfile
import unittest
from pathlib import Path
from v7_cuda_campaign_results import collect, stage_rows, read_run


class CampaignTests(unittest.TestCase):
    def test_nested_stage_containment(self):
        rows = list(stage_rows([{'id': 'outer', 'seconds': 3,
            'children': [{'id': 'inner', 'seconds': 2, 'children': None}]}]))
        self.assertEqual(rows[0]['exclusive_seconds'], 1)
        self.assertEqual(rows[1]['inclusive_seconds'], 2)
        with self.assertRaises(ValueError):
            list(stage_rows([{'id': 'outer', 'seconds': 1,
                'children': [{'id': 'inner', 'seconds': 2}]}]))

    def test_missing_and_failure_are_not_parity(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)/'pair'
            (base/'cpu').mkdir(parents=True)
            (base/'cpu/invocation.json').write_text(json.dumps({'returncode': 1}))
            output = Path(name)/'output'
            collect([('failure', base)], output)
            pair = json.loads((output/'index.json').read_text())['pairs'][0]
            self.assertFalse(pair['both_passed'])
            self.assertIsNone(pair['all_proof_bytes_equal'])

    def test_artifact_mismatch_is_explicit(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)/'pair'
            for mode in ('cpu', 'gpu'):
                run = base/mode
                run.mkdir(parents=True)
                (run/'invocation.json').write_text(json.dumps({'returncode': 0,
                    'report_checked': True, 'binary_sha256': 'same'}))
                (run/'report.json').write_text('{}')
                (run/'original-0.postcard').write_bytes(mode.encode())
            output = Path(name)/'output'
            collect([('mismatch', base)], output)
            pair = json.loads((output/'index.json').read_text())['pairs'][0]
            self.assertTrue(pair['both_passed'])
            self.assertFalse(pair['all_proof_bytes_equal'])

    def test_composition_requires_exact_recursive_coverage(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            run = base/'gpu'
            (run/'gpu').mkdir(parents=True)
            (run/'invocation.json').write_text(json.dumps({'returncode':0,'report_checked':True,'cuda_composition':True}))
            (run/'root.proof').write_bytes(b'proof')
            (run/'report.json').write_text(json.dumps({'external_composition_executor':True,'recursive_proof_count':1}))
            with self.assertRaises(ValueError):
                read_run('missing', 'gpu', base)
            receipt = {'complete_helper_succeeded':True,'fallback_allowed':False,'resident_proof':False,'stats':{'calls':1,'kernel_launches':22}}
            (run/'gpu/cuda-composition-receipt.json').write_text(json.dumps(receipt))
            (run/'gpu/cuda-composition-calls.jsonl').write_text(json.dumps({'index':0,'kernel_launches':22})+'\n')
            row, calls, *_ = read_run('good', 'gpu', base)
            self.assertEqual(row['cuda_composition_calls'], 1)
            self.assertEqual(calls[0]['stage'], 'composition')
            receipt['stats']['calls'] = 2
            (run/'gpu/cuda-composition-receipt.json').write_text(json.dumps(receipt))
            with self.assertRaises(ValueError):
                read_run('wrong', 'gpu', base)


if __name__ == '__main__':
    unittest.main()
