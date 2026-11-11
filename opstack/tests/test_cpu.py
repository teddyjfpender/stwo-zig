"""Fresh receiver reports must bind successful complete mainnet output."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "cpu", Path(__file__).parents[1] / "cpu.py"
)
cpu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cpu)


class CPUReceiptTests(unittest.TestCase):
    def test_full_native_production_does_not_require_a_duplicate_capture(self):
        """Stop at the first native call; no mock proof is ever accepted."""

        class FirstNativeCall(Exception):
            pass

        for plan_first in (False, True):
            with (
                self.subTest(plan_first=plan_first),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                for name in ("elf", "input", "runner"):
                    (root / name).write_bytes(name.encode())
                output = (
                    bytes(32) + b"\x01" + (10).to_bytes(8, "little") + b"OP"
                ).hex()
                request = {
                    "elf": str(root / "elf"),
                    "input": str(root / "input"),
                    "elf_sha256": cpu.sha(root / "elf"),
                    "input_sha256": cpu.sha(root / "input"),
                    "expected_output": output,
                    "terminal_pc": 4,
                    "execution_profile": "ethereum_services_v3",
                }
                execution = {
                    "status": "completed",
                    "verified_output": True,
                    "output": output,
                    "pc": 4,
                    "instructions": 32,
                }
                (root / "request.json").write_text(json.dumps(request))
                (root / "execution.json").write_text(json.dumps(execution))
                argv = [
                    "cpu.py",
                    "--request",
                    str(root / "request.json"),
                    "--execution",
                    str(root / "execution.json"),
                    "--runner",
                    str(root / "runner"),
                    "--artifacts",
                    str(root / "out"),
                ]
                if plan_first:
                    argv.append("--plan-first")
                with (
                    patch.object(sys, "argv", argv),
                    patch.dict(os.environ, {}, clear=True),
                    patch.object(
                        cpu, "measured", side_effect=FirstNativeCall
                    ) as native,
                    self.assertRaises(FirstNativeCall),
                ):
                    cpu.main()
                self.assertEqual(native.call_count, 1)
                command = native.call_args.args[0]
                self.assertEqual(
                    command[3], "plan-candidate" if plan_first else "produce-candidate"
                )
                admitted = json.loads((root / "out/request.json").read_text())
                self.assertEqual(admitted["max_batches"], 0)
                self.assertEqual(admitted["expected_output"], output)

    def test_mantle_admission_binds_input_before_native_call(self):
        from opstack.tests.test_mantle_input import fixture
        from opstack.mantle.input import statement
        raw = json.dumps(fixture()).encode();public = statement(raw)
        for bad in (None, 'digest', 'tag', 'chain'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as directory:
                root = Path(directory);(root/'elf').write_bytes(b'elf');(root/'input').write_bytes(raw)
                expected = public if bad is None else (bytes(32)+public[32:] if bad == 'digest' else public[:-2]+b'OP' if bad == 'tag' else public[:33]+(10).to_bytes(8,'little')+b'ME')
                request = {'elf':str(root/'elf'), 'input':str(root/'input'),
                           'elf_sha256':cpu.sha(root/'elf'), 'input_sha256':cpu.sha(root/'input'),
                           'expected_output':expected.hex(), 'terminal_pc':4, 'execution_profile':'ethereum_services_v3'}
                execution = {'status':'completed','verified_output':True,'output':expected.hex(),'pc':4,'instructions':32}
                (root/'request.json').write_text(json.dumps(request));(root/'execution.json').write_text(json.dumps(execution))
                argv = ['cpu.py','--request',str(root/'request.json'),'--execution',str(root/'execution.json'),
                        '--runner',str(root/'elf'),'--artifacts',str(root/'out')]
                # Stop at the first native call; never return/accept a mock proof.
                with patch.object(sys,'argv',argv), patch.object(cpu,'measured',side_effect=RuntimeError('native boundary')) as native:
                    with self.assertRaises(RuntimeError if bad is None else ValueError):cpu.main()
                self.assertEqual(native.call_count, 1 if bad is None else 0)

    def test_geometry_is_preserved_and_only_explicitly_overridden(self):
        self.assertEqual(cpu.batch_steps({"batch_steps": 1048575}), 1048575)
        self.assertEqual(cpu.batch_steps({"batch_steps": 131071}), 131071)
        self.assertEqual(cpu.batch_steps({"batch_steps": 1048575}, 262143), 262143)
        self.assertEqual(cpu.batch_steps({}), 1048575)
        for bad in [0, -1, 1 << 23, True, "1048575", None]:
            with self.assertRaises(ValueError):
                cpu.batch_steps({"batch_steps": bad})

    def test_corruption_never_counts_resource_errors_and_always_restores_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / "proof"
            proof.mkdir()
            data = b"real proof bytes for custody test"
            metadata = b'{"cpus":[{"proof":{"sha256":[]}}]}'
            (proof / "cpu-0.bin").write_bytes(data)
            (proof / "bundle.json").write_bytes(metadata)
            command = [
                sys.executable,
                "-c",
                "import sys; print('error: OutOfMemory',file=sys.stderr);sys.exit(1)",
            ]
            with self.assertRaisesRegex(ValueError, "expected rejection"):
                cpu.corruption_trials(proof, command, root, 5, dict(os.environ))
            self.assertEqual((proof / "cpu-0.bin").read_bytes(), data)
            self.assertEqual((proof / "bundle.json").read_bytes(), metadata)

    def test_accept_complete_output(self):
        report = {
            "accepted": True,
            "completed_ethereum_block": True,
            "security_qualified": False,
            "output": [255] * 43,
        }
        cpu.accept(report, "ff" * 43)
        for field, value in (
            ("accepted", False),
            ("completed_ethereum_block", False),
            ("security_qualified", True),
            ("output", [0] * 43),
        ):
            bad = dict(report)
            bad[field] = value
            with self.assertRaises(ValueError):
                cpu.accept(bad, "ff" * 43)

    def test_timeout_writes_failure_receipt_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "timeout"
            receipt = cpu.measured(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                prefix,
                0.01,
                dict(os.environ),
                True,
            )
            self.assertFalse(prefix.with_suffix(".heartbeat.json").exists())
            self.assertTrue(receipt["timed_out"])
            self.assertLess(receipt["returncode"], 0)
            self.assertEqual(
                json.loads(prefix.with_suffix(".json").read_text()), receipt
            )

    def test_valid_utf8_wire_output(self):
        cpu.accept(
            {
                "accepted": True,
                "completed_ethereum_block": True,
                "security_qualified": False,
                "output": "A" * 43,
            },
            "41" * 43,
        )


if __name__ == "__main__":
    unittest.main()
