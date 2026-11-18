import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from opstack.resident import prepare, validate_case


class ResidentInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.elf, self.input = self.root / "guest.elf", self.root / "input.opx"
        self.elf.write_bytes(b"test-elf")
        self.input.write_bytes(b"test-input")
        output = (bytes(32) + b"\1" + (11155420).to_bytes(8, "little") + b"OP").hex()
        self.request = {
            "elf": str(self.elf),
            "input": str(self.input),
            "elf_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest(),
            "input_sha256": hashlib.sha256(self.input.read_bytes()).hexdigest(),
            "execution_profile": "ethereum_services_v3",
            "terminal_pc": 100,
            "expected_output": output,
        }
        self.execution = {
            "status": "completed",
            "verified_output": True,
            "proof_verified": False,
            "output": output,
            "pc": 100,
            "instructions": 9,
            "final_registers": [0] * 32,
            "sponge_calls": 3,
        }
        self.oracle = {
            "oracle": "Unicorn2.1.4",
            "completed": True,
            "proof_verified": False,
            "exact_steps_verified": 9,
            "output": output,
            "post_store_pc": 100,
            "final_registers": [0] * 32,
            "services": {"sponge_calls": 3},
            **{k: self.request[k] for k in ("elf_sha256", "input_sha256")},
        }
        for name, data in [
            ("proof-config", self.request),
            ("rv64", self.execution),
            ("oracle", self.oracle),
        ]:
            (self.root / f"case-{name}.json").write_text(json.dumps(data))
        # Small synthetic budgets test packaging only; never hardware qualification.
        self.template = {
            "schema": "rv64-ethereum-basket-inputs/v1",
            "resources": {
                "park_main": False,
                "fixed_setup_bytes": 1,
                "retained_frontend_bytes": 1,
                "schedule": {"lanes": 1, "workers_per_lane": 2},
            },
            "repeat": 2,
        }

    def test_portable_assets_pins_and_exact_segment_coverage(self):
        out = self.root / "package"
        result = prepare(self.root, self.template, ["case"], out, 4, 2, 1)
        self.assertEqual(result["execution_order"], [0])
        self.assertEqual(result["repeat"], 1)
        self.assertEqual(result["blocks"]["0"]["expected_cpu_segments"], 3)
        request = json.loads((out / "requests/0.json").read_text())
        self.assertEqual(request["max_steps"], 10)
        self.assertEqual((out / request["input"]).read_bytes(), b"test-input")
        package = json.loads((out / "package.json").read_text())
        self.assertIs(package["proof_verified"], False)
        self.assertIs(package["capacity_qualified"], False)
        for path, digest in package["files"].items():
            self.assertEqual(
                hashlib.sha256((out / path).read_bytes()).hexdigest(), digest
            )

    def test_independent_count_register_service_and_identity_changes_reject(self):
        for key, value in [
            ("exact_steps_verified", 8),
            ("final_registers", [1] * 32),
            ("post_store_pc", 104),
            ("services", {"sponge_calls": 2}),
            ("input_sha256", "ff" * 32),
            ("proof_verified", True),
        ]:
            oracle = copy.deepcopy(self.oracle)
            oracle[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_case(self.request, self.execution, oracle)

    def test_legacy_schema_prefix_and_tampered_asset_reject_before_publication(self):
        request = copy.deepcopy(self.request)
        request["expected_output"] = request["expected_output"][:-4] + "5353"
        with self.assertRaises(ValueError):
            validate_case(request, self.execution, self.oracle)
        request = dict(self.request, max_batches=1)
        with self.assertRaises(ValueError):
            validate_case(request, self.execution, self.oracle)
        self.input.write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            prepare(self.root, self.template, ["case"], self.root / "bad", 4, 2, 1)
        self.assertFalse((self.root / "bad").exists())

    def test_closed_multi_gpu_policy_and_invalid_cases_cannot_be_bypassed(self):
        for cases, devices in [
            (["case"], 2),
            (["case", "case"], 1),
            (["../escape"], 1),
        ]:
            with (
                self.subTest(cases=cases, devices=devices),
                self.assertRaises(ValueError),
            ):
                prepare(
                    self.root, self.template, cases, self.root / "bad", 4, 2, devices
                )


if __name__ == "__main__":
    unittest.main()
