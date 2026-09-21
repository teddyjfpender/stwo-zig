"""Check the process gate's decisions; these fixtures are not STARK proofs."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import ethereum_wrapper_root_check as check


class RootProcessGateTests(unittest.TestCase):
    def exercise(self, *, initial=False, failure=None, wrong_endpoint=False,
                 fixtures=False, corrupt_fixture=None, admission_error=False,
                 failure_case=None, fixture_sizes=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            bundle.mkdir()
            verifier = root / "verifier"
            verifier.write_bytes(b"mock process boundary, not a proof verifier")
            (bundle / "key.json").write_bytes(b"independently pinned fixture key")
            (bundle / "proof.bin").write_bytes(b"process fixture")
            original = {
                "proof_sha256": list(hashlib.sha256(b"process fixture").digest()),
                "proof_bytes": len(b"process fixture"),
                "node": {"coordinate": {"height": 0, "index": 0}, "statement_words": [3], "output_digest": [4]},
                "claims": {"values": [{"c0": {"a": {"v": 0}}} for _ in range(38 if initial else 36)]},
                "interaction_pow_nonce": 7,
            }
            check.write_json(bundle / "inputs.json", original)
            if initial:
                alternate = copy.deepcopy(original)
                alternate["node"]["output_digest"] = [5]
                check.write_json(bundle / "rejected-public-inputs.json", alternate)
            pin = check.sha(bundle / "key.json")
            fixture_dir = root / "fixtures" if fixtures else None
            fixture_pin = None
            if fixtures:
                fixture_dir.mkdir()
                cases = []
                for index, name in enumerate(check.PUBLIC_FIXTURE_CASES + check.KEY_FIXTURE_CASES):
                    inputs = copy.deepcopy(original)
                    alternate_key = name in check.KEY_FIXTURE_CASES
                    key = (name.encode() if alternate_key else (bundle / "key.json").read_bytes())
                    if not alternate_key:
                        inputs["node"]["statement_words"] = [index + 10]
                    key_file, inputs_file = name + "-key.json", name + "-inputs.json"
                    (fixture_dir / key_file).write_bytes(key)
                    check.write_json(fixture_dir / inputs_file, inputs)
                    cases.append(dict(name=name, key_file=key_file, inputs_file=inputs_file,
                                      inputs_sha256=check.sha(fixture_dir / inputs_file),
                                      expected_key_sha256=check.sha(fixture_dir / key_file),
                                      test_only_alternate_key=alternate_key))
                manifest = dict(version=1, initial_profile=initial, original_key_sha256=pin,
                                original_inputs_sha256=check.sha(bundle / "inputs.json"),
                                proof_sha256=check.sha(bundle / "proof.bin"), proof_bytes=original["proof_bytes"], cases=cases)
                if corrupt_fixture:
                    corrupt_fixture(fixture_dir, manifest)
                check.write_json(fixture_dir / "manifest.json", manifest)
                fixture_pin = check.sha(fixture_dir / "manifest.json")
            calls = []
            original_stat = Path.stat

            def fixture_stat(path, *args, **kwargs):
                result = original_stat(path, *args, **kwargs)
                # Exercise transport size admission without writing hundreds of
                # megabytes across the ten mocked verifier cases.
                if fixture_sizes and path.parent == fixture_dir:
                    for suffix, size in fixture_sizes.items():
                        if path.name.endswith(suffix):
                            values = list(result)
                            values[6] = size
                            return os.stat_result(values)
                return result

            def execute(argv, *, stdout, stderr, **kwargs):
                self.assertEqual(argv[1:-2], ["--initial-v1"] if initial else [])
                directory = Path(argv[-2])
                name = directory.name
                calls.append(name)
                if name == "genuine":
                    endpoint = "verified_ethereum_initial_field_leaf_wrapper" if initial and not wrong_endpoint else "verified_ethereum_field_leaf_wrapper"
                    receipt = dict(endpoint=endpoint, verified=True, native_inputs_used=False,
                                   key_sha256=list(bytes.fromhex(pin)), proof_sha256=original["proof_sha256"],
                                   proof_bytes=original["proof_bytes"], **original["node"])
                    stdout.write(json.dumps(receipt).encode())
                    return subprocess.CompletedProcess(argv, 0)
                if failure is not None and (failure_case is None or name == failure_case):
                    if isinstance(failure, Exception):
                        raise failure
                    code, message = failure
                    stderr.write(message.encode())
                    return subprocess.CompletedProcess(argv, code)
                if name.startswith("changed-initial-"):
                    changed = json.loads((directory / "inputs.json").read_text())
                    index = 36 if name == "changed-initial-lane-claim" else 37
                    self.assertEqual(changed["claims"]["values"][index]["c0"]["a"]["v"], 1)
                if name in check.PUBLIC_FIXTURE_CASES + check.KEY_FIXTURE_CASES:
                    self.assertEqual((directory / "proof.bin").read_bytes(), b"process fixture")
                    self.assertEqual(argv[-1], check.sha(directory / "key.json"))
                    changed = json.loads((directory / "inputs.json").read_text())
                    if name in check.PUBLIC_FIXTURE_CASES:
                        self.assertNotEqual(changed["node"], original["node"])
                    else:
                        self.assertEqual(changed, original)
                errors = {"wrong-key-pin": "EthereumRootKeyHashMismatch", "changed-nonce": "InvalidEthereumRootInteractionPow", "changed-proof": "ProofOfWork", "changed-protocol": "InvalidTemporalParentProtocolAuthority"}
                stderr.write(("error: " + errors.get(name, "InvalidEthereumRootClaimClosure") + "\n").encode())
                return subprocess.CompletedProcess(argv, 1)

            with mock.patch.object(check, "build_lock", side_effect=lambda **_: contextlib.nullcontext()) as lock, \
                    mock.patch.object(check.subprocess, "run", side_effect=execute) as process, \
                    mock.patch.object(Path, "stat", new=fixture_stat), contextlib.redirect_stdout(io.StringIO()):
                if admission_error:
                    with self.assertRaises(ValueError):
                        check.run(verifier, bundle, pin, root / "results", 1, initial=initial,
                                  fixtures=fixture_dir, fixture_manifest_pin=fixture_pin)
                    process.assert_not_called()
                    lock.assert_not_called()
                    return
                passed = check.run(verifier, bundle, pin, root / "results", 1, initial=initial,
                                   fixtures=fixture_dir, fixture_manifest_pin=fixture_pin)
            self.assertEqual(lock.call_count, len(calls))
            self.assertEqual(json.loads((bundle / "inputs.json").read_text()), original)
            receipt = json.loads((root / "results/receipt.json").read_text())
            self.assertEqual(receipt["passed"], passed)
            return passed, calls, receipt

    def test_semantic_rejections_and_fresh_genuine_receipt_pass(self):
        passed, calls, _ = self.exercise()
        self.assertTrue(passed)
        self.assertEqual(len(calls), 5)

    def test_resource_io_crash_timeout_and_unknown_errors_do_not_prove_rejection(self):
        failures = [
            (1, "error: OutOfMemory\n"),
            (1, "error: InputOutput\n"),
            (1, "error: NewUnclassifiedError\n"),
            (-9, "error: EthereumRootKeyHashMismatch\n"),
            (1, "error: EthereumRootKeyHashMismatch\nthread panic: failed\n"),
            subprocess.TimeoutExpired(["mock verifier"], 1),
            OSError("cannot start verifier"),
        ]
        for failure in failures:
            with self.subTest(failure=failure):
                passed, calls, _ = self.exercise(failure=failure)
                self.assertFalse(passed)
                self.assertEqual(calls, ["genuine", "wrong-key-pin"])

    def test_initial_selection_checks_both_extra_claims(self):
        passed, calls, _ = self.exercise(initial=True)
        self.assertTrue(passed)
        self.assertEqual(calls[-2:], ["changed-initial-lane-claim", "changed-initial-packet-claim"])

    def test_initial_selection_rejects_ordinary_endpoint_receipt(self):
        passed, calls, _ = self.exercise(initial=True, wrong_endpoint=True)
        self.assertFalse(passed)
        self.assertEqual(calls, ["genuine"])

    def test_same_proof_statement_boundary_and_profile_cases_use_explicit_custody(self):
        passed, calls, _ = self.exercise(fixtures=True)
        self.assertTrue(passed)
        self.assertEqual(calls[-5:], list(check.PUBLIC_FIXTURE_CASES + check.KEY_FIXTURE_CASES))
        self.assertEqual(len(calls), 10)

    def test_profile_cases_require_their_own_semantic_rejection(self):
        for name, message in (
            ("changed-protocol", "error: InvalidEthereumRootClaimClosure\n"),
            ("changed-circuit-parameter", "error: InvalidTemporalParentProtocolAuthority\n"),
            ("changed-boundary", "error: OutOfMemory\n"),
        ):
            with self.subTest(case=name):
                passed, calls, _ = self.exercise(fixtures=True, failure=(1, message), failure_case=name)
                self.assertFalse(passed)
                self.assertEqual(calls[-1], name)

    def test_real_key_size_and_distinct_transport_budgets(self):
        # Retained wrapper2 produced a 20,912,431-byte key. The former common
        # 16 MiB fixture cap rejected it before the independent verifier ran.
        passed, _, _ = self.exercise(fixtures=True, fixture_sizes={"-key.json": 20_912_431})
        self.assertTrue(passed)
        for sizes in ({"-key.json": 64 * 1024 * 1024 + 1},
                      {"-inputs.json": 128 * 1024 + 1}):
            with self.subTest(sizes=sizes):
                self.exercise(fixtures=True, fixture_sizes=sizes, admission_error=True)

    def test_fixture_transport_and_scope_mismatches_are_rejected_before_processes(self):
        def changed_claim(directory, manifest):
            case = manifest["cases"][0]
            path = directory / case["inputs_file"]
            inputs = json.loads(path.read_bytes())
            inputs["interaction_pow_nonce"] += 1
            path.write_text(json.dumps(inputs))
            case["inputs_sha256"] = check.sha(path)

        mutations = [
            lambda _, m: m.update(proof_sha256="0" * 64),
            lambda _, m: m["cases"].pop(),
            lambda _, m: m["cases"].__setitem__(1, m["cases"][0]),
            lambda _, m: m["cases"][0].update(inputs_file="../inputs.json"),
            lambda _, m: m["cases"][0].update(inputs_sha256="0" * 64),
            lambda _, m: m["cases"][-1].update(test_only_alternate_key=False),
            changed_claim,
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.exercise(fixtures=True, corrupt_fixture=mutation, admission_error=True)


if __name__ == "__main__":
    unittest.main()
