from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import benchmark_cairo as benchmark
from scripts import benchmark_cairo_suite as suite
from scripts import benchmark_cairo_pair as pair


class BenchmarkEvidenceTests(unittest.TestCase):
    def test_physical_memory_is_separate_from_rss_and_requires_complete_evidence(self):
        def trial(peak):
            return {"process": {"max_process_tree_rss_bytes": 9999}, "prover_process_usage": {
                "source": "darwin_proc_pid_rusage_v6", "lifetime_peak_physical_footprint_bytes": peak}}
        result = benchmark.physical_footprint_summary([trial(100), trial(200)])
        self.assertEqual(result["peak_product_physical_footprint_bytes"], 200)
        self.assertEqual(result["physical_footprint_sample_count"], 2)
        partial = benchmark.physical_footprint_summary([trial(100), {}])
        self.assertIsNone(partial["peak_product_physical_footprint_bytes"])
        self.assertEqual(partial["physical_footprint_sample_count"], 1)
        for trials in ([], [{}], [trial(None)], [trial(-1)], [trial(True)]):
            self.assertIsNone(benchmark.physical_footprint_summary(trials)["peak_product_physical_footprint_bytes"])

    def test_pair_environment_isolates_variants_and_retains_common_controls(self):
        base = {"PATH": "/bin", "STWO_CAIRO_PREPROCESSED_CACHE_BUDGET": "6442450944"}
        before = pair.variant_environment(base, ["STWO_CAIRO_METAL_RESIDENT_LOGUP=0"])
        after = pair.variant_environment(base, ["STWO_CAIRO_METAL_RESIDENT_LOGUP=1"])
        self.assertNotIn("STWO_CAIRO_METAL_RESIDENT_LOGUP", base)
        self.assertEqual(before["STWO_CAIRO_METAL_RESIDENT_LOGUP"], "0")
        self.assertEqual(after["STWO_CAIRO_METAL_RESIDENT_LOGUP"], "1")
        self.assertEqual(after["STWO_CAIRO_PREPROCESSED_CACHE_BUDGET"], "6442450944")
        for overrides in (["PATH=/tmp"], ["STWO_ZIG_WORKERS"], ["STWO_ZIG_WORKERS=4", "STWO_ZIG_WORKERS=8"]):
            with self.assertRaises(ValueError):
                pair.variant_environment(base, overrides)

    def test_nonzero_process_retains_time_memory_and_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            result = benchmark.measure([sys.executable, "-c", "raise SystemExit(7)"], Path(directory) / "failure.log")
            self.assertEqual(result["exit_code"], 7)
            self.assertGreater(result["wall_ns"], 0)
            self.assertGreater(result["max_process_tree_rss_bytes"], 0)

    def request(self, root: Path, queries=70, oracle_exit=0):
        workload = root / "input.json"
        workload.write_text(json.dumps({"queries": queries, "oracle_exit": oracle_exit}))
        product = root / "product"
        product.write_text("#!" + sys.executable + "\n" + '''
import hashlib, json, sys
from pathlib import Path
args = dict(zip(sys.argv[2::2], sys.argv[3::2]))
source = json.loads(Path(args['--prover-input']).read_text())
proof = Path(args['--proof'])
proof.write_text(json.dumps({'stark_proof': {'config': {'pow_bits':26,'fri_config':{'n_queries':source['queries'],'log_blowup_factor':1,'log_last_layer_degree_bound':0,'fold_step':1},'min_lifting_log_size':0}}, 'fixture_oracle_exit':source['oracle_exit']}))
sha = hashlib.sha256(proof.read_bytes()).hexdigest()
Path(args['--report-out']).write_text(json.dumps({'backend':'cpu','input':{'sha256':hashlib.sha256(Path(args['--prover-input']).read_bytes()).hexdigest()},'proof':{'sha256':sha,'bytes':proof.stat().st_size},'verification':{'requested':True,'zig':True},'timing':{'prove_ns':17},'profile':'test-fixture','backend_evidence':{}}))
Path(args['--stage-profile-out']).write_text(json.dumps({'stages':[]}))
''')
        product.chmod(0o755)
        oracle = root / "oracle"
        oracle.write_text("#!" + sys.executable + "\n" + '''
import hashlib, json, sys
from pathlib import Path
args = dict(zip(sys.argv[2::2], sys.argv[3::2]))
proof = Path(args['--proof'])
value = json.loads(proof.read_text())
if value['fixture_oracle_exit']: raise SystemExit(value['fixture_oracle_exit'])
Path(args['--result']).write_text(json.dumps({'verified':True,'proof_sha256':hashlib.sha256(proof.read_bytes()).hexdigest()}))
''')
        oracle.chmod(0o755)
        return argparse.Namespace(product=product, oracle=oracle, prover_input=workload, program=None, program_type=None, arguments=None, params=None, trials=2, out=root / "results")

    def test_reduced_security_is_rejected_despite_product_success(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.request(Path(directory), queries=69)
            with self.assertRaisesRegex(RuntimeError, "security"):
                benchmark.run_benchmark(args)
            result = json.loads((args.out / "results.json").read_text())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["trials"][0]["phase"], "receipt_validation")
            self.assertEqual(result["trials"][0]["process"]["exit_code"], 0)
            self.assertNotIn("summary", result)

    def test_official_failure_retains_both_measurements(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.request(Path(directory), oracle_exit=9)
            with self.assertRaisesRegex(RuntimeError, "verifier exited 9"):
                benchmark.run_benchmark(args)
            trial = json.loads((args.out / "results.json").read_text())["trials"][0]
            self.assertEqual(trial["status"], "failed")
            self.assertEqual(trial["process"]["exit_code"], 0)
            self.assertEqual(trial["official_verifier"]["exit_code"], 9)

    def test_repeated_process_summary_preserves_the_initial_trial(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.request(Path(directory))
            result = benchmark.run_benchmark(args)
            self.assertEqual(result["status"], "qualified")
            self.assertEqual(len(result["trials"]), 2)
            self.assertEqual(result["subsequent_trials_summary"]["indices"], [2])
            self.assertFalse(result["subsequent_trials_summary"]["cache_state_inferred"])

    def test_manifest_bytes_are_pinned_and_missing_pies_are_explicit(self):
        manifest = suite.load_manifest(suite.DEFAULT_MANIFEST)
        self.assertGreaterEqual(len(manifest["workloads"]), 15)
        for workload in manifest["workloads"]:
            if workload["source"] == "repository":
                suite.resolve_assets(workload, None)
            else:
                with self.assertRaisesRegex(FileNotFoundError, "PIE directory"):
                    suite.resolve_assets(workload, None)
        mutated = copy.deepcopy(manifest)
        mutated["security"]["fri_config"]["n_queries"] = 69
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(mutated))
            with self.assertRaisesRegex(ValueError, "security"):
                suite.load_manifest(path)

    def test_parity_keeps_incomplete_and_mismatching_results_visible(self):
        records = [{'workload':'one','workers':4,'backend':'cpu','status':'qualified','result':{'trials':[{'proof_sha256':'a'}]}},
                   {'workload':'one','workers':4,'backend':'metal','status':'failed'}]
        self.assertEqual(suite.qualify_parity(records)[0]['status'], 'incomplete')
        records[1].update({'status':'qualified','result':{'trials':[{'proof_sha256':'b'}]}})
        self.assertEqual(suite.qualify_parity(records)[0]['status'], 'mismatch')
        records[1]['result']['trials'][0]['proof_sha256'] = 'a'
        self.assertEqual(suite.qualify_parity(records)[0]['status'], 'identical')


if __name__ == "__main__":
    unittest.main()
