from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts import cairo_csp_fixtures as fixtures


ROOT = Path(__file__).resolve().parents[2]
PROVENANCE = ROOT / "vectors/cairo/csp/fixture-provenance-v1.json"


class CairoCspFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provenance = fixtures.load_json(PROVENANCE)

    def _temporary_root_with_source(
        self, name: str, transform
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, dict]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        required = (
            "vectors/riscv_csp/inputs/msg_2048.bin",
            "vectors/cairo/zkvm/corpus.provenance.json",
            "vectors/cairo/csp/comparison-manifest-v1.json",
            "vectors/cairo/csp/empty.arguments.json",
            "vectors/cairo/csp/sources/sha256_2048_bytes.cairo",
            "vectors/cairo/csp/sources/keccak256_2048_bytes.cairo",
        )
        for relative in required:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        changed = copy.deepcopy(self.provenance)
        descriptor = changed["fixtures"][name]["source"]
        source = root / descriptor["path"]
        rewritten = transform(source.read_text(encoding="utf-8"))
        source.write_text(rewritten, encoding="utf-8")
        encoded = source.read_bytes()
        descriptor["bytes"] = len(encoded)
        descriptor["sha256"] = hashlib.sha256(encoded).hexdigest()
        return temporary, root, changed

    def test_committed_sources_are_exact_but_not_yet_runnable(self) -> None:
        plan = fixtures.validate_provenance(self.provenance, root=ROOT)
        self.assertEqual(plan["source_ready"], 2)
        self.assertEqual(plan["compiled_ready"], 0)
        self.assertEqual(plan["exact_runnable"], 0)
        self.assertEqual(
            [(row["id"], row["embedded_words"], row["output_felts"]) for row in plan["fixtures"]],
            [
                ("keccak256_2048_bytes", 256, 2),
                ("sha256_2048_bytes", 512, 8),
            ],
        )

    def test_sha_public_felts_reconstruct_raw_digest_big_endian(self) -> None:
        fixture = self.provenance["fixtures"]["sha256_2048_bytes"]
        values = [int(value) for value in fixture["output_projection"]["felt_decimal"]]
        self.assertEqual(
            b"".join(value.to_bytes(4, "big") for value in values).hex(),
            fixture["output_projection"]["canonical_hex"],
        )

    def test_keccak_public_limbs_reconstruct_raw_digest_little_endian(self) -> None:
        fixture = self.provenance["fixtures"]["keccak256_2048_bytes"]
        values = [int(value) for value in fixture["output_projection"]["felt_decimal"]]
        self.assertEqual(
            b"".join(value.to_bytes(16, "little") for value in values).hex(),
            fixture["output_projection"]["canonical_hex"],
        )

    def test_sources_have_no_program_input_hint(self) -> None:
        for descriptor in (
            self.provenance["fixtures"]["sha256_2048_bytes"]["source"],
            self.provenance["fixtures"]["keccak256_2048_bytes"]["source"],
        ):
            source = (ROOT / descriptor["path"]).read_text(encoding="utf-8")
            self.assertNotIn("program_input", source)
            self.assertNotIn("local iterations", source)

    def test_driver_refuses_source_only_rows_as_runnable(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = fixtures.main(
                [
                    "--root",
                    str(ROOT),
                    "--provenance",
                    str(PROVENANCE),
                    "--require-runnable",
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("source readiness is not proof readiness", stderr.getvalue())

    def test_json_driver_reports_source_stage(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = fixtures.main(
                [
                    "--root",
                    str(ROOT),
                    "--provenance",
                    str(PROVENANCE),
                    "--json",
                ]
            )
        self.assertEqual(status, 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["source_ready"], 2)
        self.assertEqual(result["exact_runnable"], 0)

    def test_source_digest_mutation_fails_closed(self) -> None:
        changed = copy.deepcopy(self.provenance)
        changed["fixtures"]["sha256_2048_bytes"]["source"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(fixtures.FixtureError, "digest mismatch"):
            fixtures.validate_provenance(changed, root=ROOT)

    def test_repinning_a_wrong_embedded_word_still_fails_semantics(self) -> None:
        temporary, root, changed = self._temporary_root_with_source(
            "keccak256_2048_bytes",
            lambda source: source.replace(
                "assert input[0] = 0x25d7550589bfe811;",
                "assert input[0] = 0x25d7550589bfe810;",
            ),
        )
        with temporary:
            with self.assertRaisesRegex(fixtures.FixtureError, "embedded logical input"):
                fixtures.validate_provenance(changed, root=root)

    def test_repinning_source_without_finalizer_still_fails(self) -> None:
        temporary, root, changed = self._temporary_root_with_source(
            "keccak256_2048_bytes",
            lambda source: source.replace(
                "    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=hash_ptr);\n",
                "",
            ),
        )
        with temporary:
            with self.assertRaisesRegex(fixtures.FixtureError, "mandatory finalizer"):
                fixtures.validate_provenance(changed, root=root)

    def test_repinning_source_without_public_output_still_fails(self) -> None:
        temporary, root, changed = self._temporary_root_with_source(
            "sha256_2048_bytes",
            lambda source: source.replace(
                "    assert [output_ptr + 7] = hash[7];\n",
                "",
            ),
        )
        with temporary:
            with self.assertRaisesRegex(fixtures.FixtureError, "public output projection"):
                fixtures.validate_provenance(changed, root=root)

    def test_repinning_source_with_host_input_hint_still_fails(self) -> None:
        temporary, root, changed = self._temporary_root_with_source(
            "sha256_2048_bytes",
            lambda source: source.replace(
                "    let (inputs: felt*) = alloc();",
                "    // program_input must not participate here.\n"
                "    let (inputs: felt*) = alloc();",
            ),
        )
        with temporary:
            with self.assertRaisesRegex(fixtures.FixtureError, "host-input hint"):
                fixtures.validate_provenance(changed, root=root)

    def test_status_flip_without_compiled_artifact_fails_closed(self) -> None:
        changed = copy.deepcopy(self.provenance)
        changed["fixtures"]["sha256_2048_bytes"]["status"] = (
            "compiled_ready_derivation_pending"
        )
        with self.assertRaisesRegex(fixtures.FixtureError, "must be an object"):
            fixtures.validate_provenance(changed, root=ROOT)

    def test_v1_schema_rejects_every_exact_runnable_promotion(self) -> None:
        changed = copy.deepcopy(self.provenance)
        changed["fixtures"]["sha256_2048_bytes"]["status"] = "exact_runnable"
        changed["fixtures"]["sha256_2048_bytes"]["promotion_blockers"] = []
        with self.assertRaisesRegex(fixtures.FixtureError, "schema upgrade"):
            fixtures.validate_provenance(changed, root=ROOT)

    def test_declared_output_felt_mutation_fails_projection(self) -> None:
        changed = copy.deepcopy(self.provenance)
        changed["fixtures"]["keccak256_2048_bytes"]["output_projection"][
            "felt_decimal"
        ][0] = "1"
        with self.assertRaisesRegex(fixtures.FixtureError, "do not reconstruct digest"):
            fixtures.validate_provenance(changed, root=ROOT)

    def test_compiler_version_is_exact(self) -> None:
        changed = copy.deepcopy(self.provenance)
        changed["compiler"]["version"] = "0.14.0"
        with self.assertRaisesRegex(fixtures.FixtureError, "compiler identity"):
            fixtures.validate_provenance(changed, root=ROOT)

    def test_pr171_base_source_pin_cannot_drift(self) -> None:
        changed = copy.deepcopy(self.provenance)
        changed["source_authority"]["base_programs"]["sha2"]["source_sha256"] = (
            "0" * 64
        )
        with self.assertRaisesRegex(fixtures.FixtureError, "base digest drifted"):
            fixtures.validate_provenance(changed, root=ROOT)

    def test_empty_arguments_are_mandatory(self) -> None:
        changed = copy.deepcopy(self.provenance)
        source = changed["fixtures"]["sha256_2048_bytes"]["arguments"]
        replacement = ROOT / "vectors/cairo/zkvm/sha2_medium.arguments.json"
        encoded = replacement.read_bytes()
        source.update(
            {
                "path": str(replacement.relative_to(ROOT)),
                "bytes": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
        )
        with self.assertRaisesRegex(fixtures.FixtureError, "must take no arguments"):
            fixtures.validate_provenance(changed, root=ROOT)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schema":"first","schema":"second"}', encoding="utf-8")
            with self.assertRaisesRegex(fixtures.FixtureError, "duplicate JSON key"):
                fixtures.load_json(path)


if __name__ == "__main__":
    unittest.main()
