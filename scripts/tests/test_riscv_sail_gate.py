"""Contracts for the fail-closed Sail differential gate.

Runtime: under two seconds, no external toolchain. The committed-binding test
doubles as the always-on staleness gate: it runs in the static lane on every
PR, so corpus or pin movement without regenerated live evidence goes red even
on hosts that have never built Sail. The live differential itself is
exercised by the hosted riscv-sail-differential workflow and by
`riscv_sail_gate.py run`; nothing here pretends to consult Sail.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts import riscv_sail_gate as gate

ROOT = Path(__file__).resolve().parents[2]


def _copy_binding_inputs(destination: Path) -> tuple[Path, Path]:
    """Copy exactly the files bind_errors reads into an isolated tree."""
    evidence = destination / gate.EVIDENCE_PATH
    manifest = destination / gate.MANIFEST_PATH
    patch = destination / "conformance" / "riscv" / "sail-rvfi-zkvm-entry.patch"
    for source, target in (
        (ROOT / gate.EVIDENCE_PATH, evidence),
        (ROOT / gate.MANIFEST_PATH, manifest),
        (ROOT / "conformance" / "riscv" / "sail-rvfi-zkvm-entry.patch", patch),
    ):
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return evidence, manifest


class BindingTest(unittest.TestCase):
    def test_committed_evidence_binds_to_committed_corpus(self) -> None:
        self.assertEqual(gate.bind_errors(ROOT), [])

    def _tampered_errors(self, mutate) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence_path, manifest_path = _copy_binding_inputs(root)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            mutate(evidence, manifest)
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            return gate.bind_errors(root)

    def test_fixture_drift_without_fresh_evidence_fails(self) -> None:
        def mutate(evidence, manifest):
            manifest["vectors"][0]["trace_sha256"] = "0" * 64

        errors = self._tampered_errors(mutate)
        self.assertTrue(any("comparison_digest" in error for error in errors))
        self.assertTrue(any("re-run" in error for error in errors))

    def test_pin_drift_without_fresh_evidence_fails(self) -> None:
        def mutate(evidence, manifest):
            evidence["sail"]["model_tag"] = "2099-01-01-deadbee"

        errors = self._tampered_errors(mutate)
        self.assertTrue(any("sail.model_tag" in error for error in errors))

    def test_dropped_vector_breaks_counts_and_digest(self) -> None:
        def mutate(evidence, manifest):
            manifest["vectors"].pop()

        errors = self._tampered_errors(mutate)
        joined = "\n".join(errors)
        for field in ("programs", "retirements", "comparison_digest"):
            self.assertIn(f"evidence {field}", joined)

    def test_binary_hash_is_volatile_but_must_stay_a_sha256(self) -> None:
        def rebuild(evidence, manifest):
            evidence["sail"]["binary_sha256"] = "f" * 64

        self.assertEqual(self._tampered_errors(rebuild), [])

        def corrupt(evidence, manifest):
            evidence["sail"]["binary_sha256"] = "not-a-hash"

        errors = self._tampered_errors(corrupt)
        self.assertTrue(any("binary_sha256" in error for error in errors))


class EvidenceDriftTest(unittest.TestCase):
    def setUp(self) -> None:
        self.committed = json.loads(
            (ROOT / gate.EVIDENCE_PATH).read_text(encoding="utf-8")
        )

    def test_rebuilt_binaries_are_the_only_tolerated_difference(self) -> None:
        fresh = json.loads(json.dumps(self.committed))
        fresh["sail"]["binary_sha256"] = "a" * 64
        fresh["spike"]["binary_sha256"] = "b" * 64
        self.assertEqual(gate.evidence_drift(fresh, self.committed), [])

    def test_any_semantic_difference_is_drift(self) -> None:
        fresh = json.loads(json.dumps(self.committed))
        fresh["comparison_digest"] = "c" * 64
        fresh["retirements"] += 1
        drift = gate.evidence_drift(fresh, self.committed)
        joined = "\n".join(drift)
        self.assertIn("comparison_digest", joined)
        self.assertIn("retirements", joined)

    def test_identity_differences_are_drift(self) -> None:
        fresh = json.loads(json.dumps(self.committed))
        fresh["sail"]["model_tag"] = "other-tag"
        drift = gate.evidence_drift(fresh, self.committed)
        self.assertTrue(any("sail.model_tag" in line for line in drift))


class ScopeTest(unittest.TestCase):
    def test_semantics_bearing_paths_require_the_live_gate(self) -> None:
        for path in (
            "vectors/riscv_elfs/alu_test.elf",
            "conformance/riscv/rv32im-sail-profile.json",
            "conformance/upstream.md",
            "scripts/riscv_equivalence.py",
            "scripts/riscv_trace_vectors_lib/corpus.py",
            "src/frontends/riscv/isa/authority.zig",
            "src/frontends/riscv/runner/trace_dump.zig",
            ".github/workflows/riscv-sail-differential.yml",
        ):
            required, matched = gate.live_scope([path])
            self.assertTrue(required, path)
            self.assertIn(path, matched)

    def test_unrelated_paths_do_not(self) -> None:
        required, matched = gate.live_scope(
            [
                "README.md",
                "src/core/fields/m31.zig",
                "src/frontends/riscv/air/component.zig",
                "scripts/riscv_sail_oracle.py",
            ]
        )
        self.assertFalse(required)
        self.assertEqual(matched, {})

    def test_prefixes_stay_files_or_directories_that_exist(self) -> None:
        # A deleted trigger path would quietly stop selecting the live gate;
        # tie the policy to the tree so renames must update it.
        for prefix in gate.LIVE_TRIGGER_PREFIXES:
            self.assertTrue((ROOT / prefix).exists(), prefix)


class RunFailClosedTest(unittest.TestCase):
    def test_missing_workspace_is_red_and_names_what_was_not_checked(self) -> None:
        # Regardless of whether this host has the pinned Sail compiler, an
        # absent workspace must be the unavailability exit code with the
        # not-checked inventory -- never a pass and never a silent skip.
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                returncode = gate.run_gate(
                    workspace=Path(tmp) / "never-prepared",
                    sail_compiler=None,
                    prepare_on_miss=False,
                    jobs=1,
                    trace_dump_bin=None,
                    report_out=None,
                )
        self.assertEqual(returncode, gate.EXIT_TOOLCHAIN_UNAVAILABLE)
        output = stderr.getvalue()
        self.assertIn("did NOT run", output)
        committed = json.loads(
            (ROOT / gate.EVIDENCE_PATH).read_text(encoding="utf-8")
        )
        self.assertIn(
            f"{committed['retirements']} retirements were NOT re-checked",
            output,
        )


if __name__ == "__main__":
    unittest.main()
