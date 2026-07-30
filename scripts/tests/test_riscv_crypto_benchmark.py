import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_crypto_benchmark as crypto
from scripts.riscv_crypto_benchmark import METAL_CELL, input_for, is_proof_size
from scripts.riscv_csp_benchmark_lib import build_identity as csp_build_identity
from scripts.riscv_csp_benchmark_lib.contract import BenchmarkError


class ProofClassificationTests(unittest.TestCase):
    def test_provable_guest_proves_at_every_size(self) -> None:
        spec = {"eval": "provable", "kind": "input_sweep"}
        for label in ("128B", "512B", "2048B"):
            self.assertTrue(is_proof_size("sha2_input", spec, label))

    def test_single_block_guest_proves_only_at_128(self) -> None:
        spec = {"eval": "provable_single_block_only", "kind": "input_sweep"}
        self.assertTrue(is_proof_size("keccak_input", spec, "128B"))
        for label in ("256B", "512B", "1024B", "2048B"):
            self.assertFalse(is_proof_size("keccak_input", spec, label))

    def test_execution_only_guest_never_proves(self) -> None:
        for guest, spec in (
            ("ecdsa", {"eval": "execution_only", "kind": "fixed"}),
            ("poseidon2_m31", {"eval": "execution_only", "kind": "field_sweep"}),
        ):
            self.assertFalse(is_proof_size(guest, spec, "fixed"))
            self.assertFalse(is_proof_size(guest, spec, "16fe"))


class SweepShapeTests(unittest.TestCase):
    PROVENANCE = {"byte_input_sizes": [128, 256], "poseidon_field_widths": [2, 16]}

    def test_byte_sweep_labels_and_paths(self) -> None:
        pairs = input_for("sha2_input", {"kind": "input_sweep"}, self.PROVENANCE)
        self.assertEqual([label for label, _ in pairs], ["128B", "256B"])
        self.assertTrue(all(path is not None for _, path in pairs))

    def test_field_sweep_uses_field_inputs(self) -> None:
        pairs = input_for("poseidon2_m31", {"kind": "field_sweep"}, self.PROVENANCE)
        self.assertEqual([label for label, _ in pairs], ["2fe", "16fe"])
        self.assertTrue(all("field_" in path.name for _, path in pairs))

    def test_fixed_guest_has_no_input(self) -> None:
        pairs = input_for("ecdsa", {"kind": "fixed"}, self.PROVENANCE)
        self.assertEqual(pairs, [("fixed", None)])


class MetalColumnTests(unittest.TestCase):
    def test_riscv_metal_cell_is_gated(self) -> None:
        # The RISC-V adapter is CPU-only; no lane has a RISC-V Metal prover.
        self.assertEqual(METAL_CELL, "gated")


class CycleEvidenceTests(unittest.TestCase):
    """A missing cycle count must fail the row, not disable the only check on it.

    Cycle parity against the Rust lane is an execution row's whole correctness
    argument.  Both places that could drop a count used to do it silently: the
    trace dump's ``total_steps`` was parsed inside a bare ``except: pass``, and the
    parity comparison was guarded by ``is not None`` on both sides, so a row with
    no evidence printed ``ok``.
    """

    @staticmethod
    def completed(stdout: str, returncode: int = 0):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr="")

    def zig_execute(self, dump: str, returncode: int = 0) -> dict:
        # Timing samples succeed; only the authoritative step-count pass varies.
        outcomes = [self.completed("", 0)] * 2 + [self.completed(dump, returncode)]
        with mock.patch.object(crypto.subprocess, "run", side_effect=outcomes):
            return crypto.zig_execute(Path("guest.elf"), None, 2)

    def test_a_readable_dump_yields_the_step_count(self) -> None:
        lane = self.zig_execute(json.dumps({"total_steps": 1234}))
        self.assertEqual(1234, lane["steps"])
        self.assertNotIn("error", lane)

    def test_an_unparseable_dump_fails_the_lane(self) -> None:
        lane = self.zig_execute("not json")
        self.assertIn("no total_steps", lane["error"])

    def test_a_dump_without_total_steps_fails_the_lane(self) -> None:
        lane = self.zig_execute(json.dumps({"clock": 7}))
        self.assertIn("no total_steps", lane["error"])

    def test_a_failing_step_count_pass_fails_the_lane(self) -> None:
        lane = self.zig_execute("", returncode=1)
        self.assertIn("error", lane)

    def test_the_row_loop_treats_an_absent_count_as_a_failure(self) -> None:
        # The Rust lanes can still yield ``cycles: None`` on their own, so the
        # comparison itself must refuse to be skipped rather than trusting each
        # lane to have failed first. Asserted at the call site because the loop
        # runs only inside a full two-lane benchmark.
        source = inspect.getsource(crypto.main)
        self.assertIn("missing cycle evidence", source)
        self.assertNotIn(
            "zsteps is not None and rcycles is not None and zsteps != rcycles", source,
        )


class TraceProvenanceReachabilityTests(unittest.TestCase):
    """Every published cycle count comes from a binary this harness validated.

    The gate itself lives with the CSP harness; what is pinned here is that this
    sibling *reaches* it, before the first sample, and that it is the same gate
    rather than a second copy of one.
    """

    def test_the_gate_is_the_shared_implementation(self) -> None:
        self.assertIs(
            csp_build_identity.read_trace_provenance, crypto.read_trace_provenance,
        )

    def test_the_probe_asks_for_the_committed_fixture_it_authenticates(self) -> None:
        provenance = json.loads(crypto.PROVENANCE.read_text(encoding="utf-8"))
        seen: dict[str, object] = {}

        def record(trace_cli, case, **kwargs):
            seen.update(trace_cli=trace_cli, case=case, **kwargs)
            return {"implementation_commit": "a" * 40}

        with mock.patch.object(crypto, "read_trace_provenance", record):
            with mock.patch.object(crypto, "repository_head", lambda: "a" * 40):
                crypto.admit_trace_executable(provenance)
        case = seen["case"]
        guest = provenance["guests"]["sha2_input"]
        self.assertEqual(crypto.ZIG_TRACE, seen["trace_cli"])
        self.assertEqual("a" * 40, seen["repository_head"])
        # The digests come from the committed provenance file, so the probe
        # authenticates the ELF and input as well as the executable.
        self.assertEqual(guest["elf_sha256"], case.guest_sha256)
        self.assertEqual(
            provenance["input_sha256"]["msg_128.bin"], case.input_sha256,
        )
        self.assertTrue(case.guest_path.exists())
        self.assertTrue(case.input_path.exists())

    def test_a_refused_trace_executable_aborts_before_any_sample(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw)
            (source / "target/release").mkdir(parents=True)
            (source / "target/release/stark-v-bench").write_bytes(b"")
            with mock.patch.multiple(
                crypto,
                read_trace_provenance=mock.Mock(
                    side_effect=BenchmarkError("built at another commit"),
                ),
                repository_head=lambda: "a" * 40,
                zig_prove=mock.Mock(side_effect=AssertionError("proved anyway")),
                zig_execute=mock.Mock(side_effect=AssertionError("executed anyway")),
            ):
                with mock.patch.object(
                    crypto.riscv_cli_admission,
                    "resolve",
                    lambda *_, **__: crypto.riscv_cli_admission.Admission(
                        "candidate", "release_gated", False,
                    ),
                ):
                    with self.assertRaisesRegex(SystemExit, "not publishable"):
                        crypto.main(["--stark-v-source", str(source)])
