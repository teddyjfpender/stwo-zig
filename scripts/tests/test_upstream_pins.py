from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.check_upstream_pins import PinLedgerError, parse_ledger, validate_repository
from scripts.upstream_pins_lib import (
    cairo_vm_adapter,
    official_cairo_air,
    official_cairo_air_templates,
    official_cairo_vectors,
)


ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "conformance" / "upstream.md"


class UpstreamPinTests(unittest.TestCase):
    def test_repository_pin_carriers_match_ledger(self) -> None:
        self.assertEqual([], validate_repository(ROOT))

    def test_cairo_program_corpus_rejects_release_gate_omission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(
                ROOT / "vectors/cairo/programs",
                root / "vectors/cairo/programs",
            )
            gate = root / cairo_vm_adapter.ORACLE_GATE
            gate.parent.mkdir(parents=True)
            source_gate = (ROOT / cairo_vm_adapter.ORACLE_GATE).read_text(
                encoding="utf-8"
            )
            omitted = (
                "vectors/cairo/programs/"
                "test_prove_verify_pedersen_builtin/compiled.json"
            )
            gate.write_text(
                source_gate.replace(f'"{omitted}"', '"omitted"'),
                encoding="utf-8",
            )

            errors = cairo_vm_adapter._check_program_corpus(
                root,
                cairo_repository="https://github.com/starkware-libs/stwo-cairo",
                cairo_revision="82f21252a68ec006d73e299f5bf1ce6d4db0ee78",
                cairo_vm_version="3.2.0",
            )

        self.assertIn("program is absent", "\n".join(errors))

    def test_cairo_executable_rejects_artifact_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(
                ROOT / "vectors/cairo/programs/executable",
                root / "vectors/cairo/programs/executable",
            )
            gate = root / cairo_vm_adapter.ORACLE_GATE
            gate.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / cairo_vm_adapter.ORACLE_GATE, gate)
            program = (
                root
                / "vectors/cairo/programs/executable/add_one.executable.json"
            )
            program.write_bytes(program.read_bytes() + b"\n")

            errors = cairo_vm_adapter._check_executable(
                root,
                cairo_language_repository=(
                    "https://github.com/starkware-libs/cairo"
                ),
                cairo_language_revision=(
                    "eea264fa54fac04a1a5745ad533a0c0ab3106ab3"
                ),
                cairo_language_version="2.20.0",
                cairo_vm_version="3.2.0",
            )

        self.assertIn("program byte length drifted", "\n".join(errors))
        self.assertIn("program digest drifted", "\n".join(errors))

    def test_cairo_ledger_drift_reaches_every_carrier_class(self) -> None:
        drifted = LEDGER.read_text(encoding="utf-8").replace(
            "dcd5834565b7a26a27a614e353c9c60109ebc1d9",
            "0" * 40,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstream.md"
            path.write_text(drifted, encoding="utf-8")
            errors = validate_repository(ROOT, path)

        joined = "\n".join(errors)
        for carrier in (
            "tools/stwo-cairo-verifier-rs/src/lib.rs",
            "tools/stwo-cairo-verifier-rs/Cargo.toml",
            "tools/stwo-cairo-verifier-rs/Cargo.lock",
            ".github/workflows/ci.yml",
            "src/tools/metal_prover_session/state.zig",
            "src/frontends/cairo/prover.zig",
            "archive/cairo/legacy_claim_registry.zig",
        ):
            self.assertIn(carrier, joined)

    def test_official_cairo_drift_reaches_registry_generator_and_output(self) -> None:
        drifted = LEDGER.read_text(encoding="utf-8").replace(
            "82f21252a68ec006d73e299f5bf1ce6d4db0ee78",
            "1" * 40,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstream.md"
            path.write_text(drifted, encoding="utf-8")
            errors = validate_repository(ROOT, path)

        joined = "\n".join(errors)
        self.assertIn("scripts/generate_cairo_claim_registry.py", joined)
        self.assertIn(
            "src/frontends/cairo/air/official_claim_registry.zig",
            joined,
        )
        self.assertIn(
            "tools/stwo-cairo-official-verifier-rs/Cargo.toml",
            joined,
        )
        self.assertIn(
            "tools/stwo-cairo-official-verifier-rs/Cargo.lock",
            joined,
        )
        self.assertIn(
            "tools/stwo-cairo-official-verifier-rs/src/lib.rs",
            joined,
        )
        self.assertIn(
            "vectors/cairo/official/all_opcodes_blake2s.provenance.json",
            joined,
        )
        self.assertIn(
            "vectors/cairo/official/all_builtins.provenance.json",
            joined,
        )
        self.assertIn(
            "vectors/cairo/official/all_opcodes.interaction_trace_checkpoint.json",
            joined,
        )
        self.assertIn(
            "vectors/cairo/official/all_builtins.interaction_trace_checkpoint.json",
            joined,
        )
        self.assertIn(
            "vectors/cairo/official/witness_programs_v1.provenance.json",
            joined,
        )
        self.assertIn("tools/stwo-cairo-trace-oracle/Cargo.toml", joined)
        self.assertIn("tools/stwo-cairo-trace-oracle/Cargo.lock", joined)

    def test_legacy_cairo_prover_stwo_drift_excludes_official_trace_oracle(self) -> None:
        drifted = LEDGER.read_text(encoding="utf-8").replace(
            "3fe684648ff31e55b71525ad689fab7dfbd88880",
            "2" * 40,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstream.md"
            path.write_text(drifted, encoding="utf-8")
            errors = validate_repository(ROOT, path)

        joined = "\n".join(errors)
        self.assertNotIn("tools/stwo-cairo-trace-oracle/Cargo.toml", joined)
        self.assertNotIn("tools/stwo-cairo-trace-oracle/Cargo.lock", joined)

    def test_native_ledger_drift_reaches_source_manifests_and_locks(self) -> None:
        drifted = LEDGER.read_text(encoding="utf-8").replace(
            "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
            "f" * 40,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstream.md"
            path.write_text(drifted, encoding="utf-8")
            errors = validate_repository(ROOT, path)

        joined = "\n".join(errors)
        self.assertIn("src/interop/examples_artifact.zig", joined)
        self.assertIn("scripts/e2e_interop_lib/controller.py", joined)
        self.assertIn("scripts/prove_checkpoints.py", joined)
        self.assertIn("tools/stwo-interop-rs/Cargo.toml", joined)
        self.assertIn("tools/stwo-interop-rs/upstream_blake_provenance.json", joined)
        self.assertIn("Blake oracle provenance commit", joined)
        self.assertIn("tools/stwo-vector-gen/Cargo.lock", joined)
        self.assertIn("tools/stwo-cf-vector-gen/Cargo.toml", joined)

    def test_riscv_sail_drift_reaches_executable_and_machine_readable_carriers(self) -> None:
        drifted = LEDGER.read_text(encoding="utf-8").replace(
            "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
            "e" * 40,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstream.md"
            path.write_text(drifted, encoding="utf-8")
            errors = validate_repository(ROOT, path)

        joined = "\n".join(errors)
        self.assertIn("scripts/riscv_equivalence.py", joined)
        self.assertIn("src/frontends/riscv/isa/authority.zig", joined)
        self.assertIn("conformance/riscv/rv32im-sail-profile.json", joined)

    def test_riscv_spike_and_arch_test_drift_reach_formal_profile(self) -> None:
        for revision in (
            "520a5f185083ac3c97b751501dfac02a6c1f5970",
            "426e1598ebc3688eaf9aba7b4a1b8a81dae9807f",
        ):
            with self.subTest(revision=revision):
                drifted = LEDGER.read_text(encoding="utf-8").replace(revision, "d" * 40)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "upstream.md"
                    path.write_text(drifted, encoding="utf-8")
                    errors = validate_repository(ROOT, path)

                joined = "\n".join(errors)
                self.assertIn("src/frontends/riscv/isa/authority.zig", joined)
                self.assertIn("conformance/riscv/rv32im-sail-profile.json", joined)

    def test_riscv_legacy_layout_drift_does_not_masquerade_as_isa_authority(self) -> None:
        drifted = LEDGER.read_text(encoding="utf-8").replace(
            "d478f783055aa0d73a93768a433a3c6c31c91d1c",
            "c" * 40,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstream.md"
            path.write_text(drifted, encoding="utf-8")
            errors = validate_repository(ROOT, path)

        joined = "\n".join(errors)
        self.assertIn("src/frontends/riscv/isa/authority.zig", joined)
        self.assertIn("src/frontends/riscv/opcode_manifest.zig", joined)
        self.assertIn("vectors/riscv_elfs/trace_vectors.json", joined)
        self.assertIn("conformance/riscv/rv32im-sail-profile.json", joined)
        self.assertNotIn("scripts/riscv_equivalence.py", joined)

    def test_cairo_repository_drift_reaches_manifest_lock_source_and_ci(self) -> None:
        drifted = LEDGER.read_text(encoding="utf-8").replace(
            "https://github.com/teddyjfpender/stwo-cairo",
            "https://example.invalid/stwo-cairo",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstream.md"
            path.write_text(drifted, encoding="utf-8")
            errors = validate_repository(ROOT, path)

        joined = "\n".join(errors)
        self.assertIn("tools/stwo-cairo-verifier-rs/src/lib.rs", joined)
        self.assertIn("tools/stwo-cairo-verifier-rs/Cargo.toml", joined)
        self.assertIn("tools/stwo-cairo-verifier-rs/Cargo.lock", joined)
        self.assertIn(".github/workflows/ci.yml", joined)

    def test_standard_and_strict_release_gates_enforce_pin_ledger(self) -> None:
        internal = (ROOT / "build_support/internal_build.zig").read_text(encoding="utf-8")
        release = (ROOT / "build_support/gates/release.zig").read_text(encoding="utf-8")
        command = '"python3", "scripts/check_upstream_pins.py"'
        self.assertEqual(3, internal.count(command) + release.count(command))
        self.assertEqual(2, release.count(command))
        self.assertLess(
            release.index('"scripts/check_upstream_pins.py"'),
            release.index('"scripts/check_source_conformance.py"'),
        )

    def test_official_witness_bundle_parser_rejects_instruction_mutation(self) -> None:
        path = ROOT / "vectors/cairo/official/witness_programs_v1.bin"
        encoded = path.read_bytes()
        parsed, errors = official_cairo_vectors._parse_witness_bundle(
            encoded,
            str(path.relative_to(ROOT)),
        )
        self.assertEqual([], errors)
        self.assertIsNotNone(parsed)
        self.assertEqual(64, len(parsed[0]))
        self.assertEqual(157_733, parsed[1])

        mutated = bytearray(encoded)
        first_instruction = 16 + 4 + 28 + 8 + len("add_opcode")
        mutated[first_instruction + 12] ^= 1
        parsed, errors = official_cairo_vectors._parse_witness_bundle(
            bytes(mutated),
            str(path.relative_to(ROOT)),
        )
        self.assertIsNone(parsed)
        self.assertIn("semantic hash mismatch", "\n".join(errors))

    def test_official_air_program_mutation_is_rejected(self) -> None:
        provenance = json.loads(
            (
                ROOT
                / "vectors/cairo/official/all_opcodes_blake2s.provenance.json"
            ).read_text(encoding="utf-8")
        )
        artifact = provenance["air_programs"]
        encoded = bytearray((ROOT / artifact["path"]).read_bytes())
        encoded[-1] ^= 1

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            path = temporary_root / artifact["path"]
            path.parent.mkdir(parents=True)
            path.write_bytes(encoded)
            shutil.copytree(
                ROOT / "tools/stwo-cairo-air-compiler",
                temporary_root / "tools/stwo-cairo-air-compiler",
                ignore=shutil.ignore_patterns("target", "__pycache__", "*.pyc"),
            )
            errors = official_cairo_air.check(
                temporary_root,
                "vectors/cairo/official/all_opcodes_blake2s.provenance.json",
                artifact,
                closure_sha256=official_cairo_vectors._closure_sha256,
            )

        self.assertIn("AIR program digest drifted", "\n".join(errors))
        self.assertIn("AIR program plan hash drifted", "\n".join(errors))

    def test_official_air_template_library_mutation_is_rejected(self) -> None:
        provenance_path = Path(
            "vectors/cairo/official/air_template_library_v1.provenance.json"
        )
        provenance = json.loads((ROOT / provenance_path).read_text())
        canonical = provenance["sources"][1]["bundle"]["path"]
        required = [
            provenance_path.as_posix(),
            provenance["library"]["path"],
            *[
                source["input"]["path"]
                for source in provenance["sources"]
            ],
            *[
                source["bundle"]["path"]
                for source in provenance["sources"]
            ],
        ]
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            for relative in set(required):
                destination = temporary_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            shutil.copytree(
                ROOT / "tools/stwo-cairo-air-compiler",
                temporary_root / "tools/stwo-cairo-air-compiler",
                ignore=shutil.ignore_patterns("target", "__pycache__", "*.pyc"),
            )
            mutated = bytearray((temporary_root / canonical).read_bytes())
            mutated[-1] ^= 1
            (temporary_root / canonical).write_bytes(mutated)
            errors = official_cairo_air_templates.check(
                temporary_root,
                provenance["source"],
                closure_sha256=official_cairo_vectors._closure_sha256,
            )

        joined = "\n".join(errors)
        self.assertIn("AIR program digest drifted", joined)
        self.assertIn("AIR program plan hash drifted", joined)

    def test_official_witness_compiler_receipt_mutation_is_rejected(self) -> None:
        provenance = json.loads(
            (
                ROOT
                / "vectors/cairo/official/witness_programs_v1.provenance.json"
            ).read_text(encoding="utf-8")
        )
        encoded = (
            ROOT / "vectors/cairo/official/witness_programs_v1.bin"
        ).read_bytes()
        parsed, parse_errors = official_cairo_vectors._parse_witness_bundle(
            encoded,
            "vectors/cairo/official/witness_programs_v1.bin",
        )
        self.assertEqual([], parse_errors)
        self.assertIsNotNone(parsed)
        labels, instruction_count = parsed

        receipt_relative = provenance["compiler"]["receipt"]["path"]
        receipt = (ROOT / receipt_relative).read_text(encoding="utf-8")
        mutated = receipt.replace(
            f'"artifact_bytes": {len(encoded)}',
            f'"artifact_bytes": {len(encoded) + 1}',
        )
        self.assertNotEqual(receipt, mutated)
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            receipt_path = temporary_root / receipt_relative
            receipt_path.parent.mkdir(parents=True)
            receipt_path.write_text(mutated, encoding="utf-8")
            shutil.copytree(
                ROOT / "tools/cairo-witness-compiler",
                temporary_root / "tools/cairo-witness-compiler",
                ignore=shutil.ignore_patterns("target", "__pycache__", "*.pyc"),
            )
            errors = official_cairo_vectors._check_witness_compiler(
                temporary_root,
                "vectors/cairo/official/witness_programs_v1.provenance.json",
                provenance["compiler"],
                provenance["source"],
                provenance["artifact"],
                labels,
                instruction_count,
                encoded,
            )
        joined = "\n".join(errors)
        self.assertIn("compiler receipt digest drifted", joined)
        self.assertIn("compiler receipt artifact identity drifted", joined)

    def test_ledger_rejects_ambiguous_native_pin(self) -> None:
        text = LEDGER.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upstream.md"
            path.write_text(text + "\n- Pinned commit: `" + "1" * 40 + "`\n", encoding="utf-8")
            with self.assertRaisesRegex(PinLedgerError, "exactly one Native Stwo revision"):
                parse_ledger(path)


if __name__ == "__main__":
    unittest.main()
