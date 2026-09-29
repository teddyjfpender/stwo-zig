"""Circuit recursion lane: pin carriers, provenance, and the AIR projection."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.check_upstream_pins import parse_ledger, validate_repository
from scripts.upstream_pins_lib import circuit_recursion as lane


ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "conformance" / "upstream.md"


def _check(root: Path) -> list[str]:
    ledger = parse_ledger(LEDGER)
    return lane.check(
        root,
        repository=ledger.circuit_recursion_repository,
        revision=ledger.circuit_recursion_revision,
        toolchain=ledger.circuit_recursion_toolchain,
    )


class CircuitRecursionLaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        shutil.copytree(
            ROOT / lane.ORACLE,
            self.root / lane.ORACLE,
            ignore=shutil.ignore_patterns("target"),
        )
        shutil.copytree(ROOT / lane.EVAL_PROGRAM_ABI, self.root / lane.EVAL_PROGRAM_ABI)
        shutil.copytree(ROOT / lane.TRACE_DIGEST, self.root / lane.TRACE_DIGEST)
        (self.root / lane.R0_FRI_ZIG_TEST).parent.mkdir(parents=True)
        shutil.copyfile(ROOT / lane.R0_FRI_ZIG_TEST, self.root / lane.R0_FRI_ZIG_TEST)
        shutil.copytree(ROOT / lane.VECTORS, self.root / lane.VECTORS)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_committed_lane_is_consistent(self) -> None:
        self.assertEqual([], _check(ROOT))
        self.assertEqual([], _check(self.root))

    def test_ledger_drift_reaches_every_carrier_class(self) -> None:
        ledger = parse_ledger(LEDGER)
        drifted = LEDGER.read_text(encoding="utf-8").replace(
            f"- Pinned circuit recursion commit: `{ledger.circuit_recursion_revision}`",
            f"- Pinned circuit recursion commit: `{'1' * 40}`",
        )
        path = self.root / "upstream.md"
        path.write_text(drifted, encoding="utf-8")
        joined = "\n".join(validate_repository(ROOT, path))
        for carrier in (
            lane.MANIFEST,
            lane.LOCK,
            lane.AUTHORITY_SOURCE,
            lane.PROVENANCE,
            lane.PROJECTION,
            "vectors/circuit/r0/primitives.json",
        ):
            self.assertIn(carrier, joined)

    def test_hand_edited_fixture_is_rejected(self) -> None:
        fixture = self.root / "vectors/circuit/r0/primitives.json"
        fixture.write_bytes(fixture.read_bytes().replace(b'"r0"', b'"r9"', 1))
        self.assertIn("fixture bytes differ", "\n".join(_check(self.root)))

    def test_unlisted_fixture_is_rejected(self) -> None:
        (self.root / "vectors/circuit/r3/extra.json").write_text("{}\n", encoding="utf-8")
        self.assertIn("is not listed", "\n".join(_check(self.root)))

    def test_oracle_edit_requires_regeneration(self) -> None:
        source = self.root / lane.ORACLE / "src/goldens.rs"
        source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        self.assertIn("oracle source digest drifted", "\n".join(_check(self.root)))

    def test_shared_abi_edit_requires_regeneration(self) -> None:
        source = self.root / lane.EVAL_PROGRAM_ABI / "src/encoding.rs"
        source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        self.assertIn("oracle source digest drifted", "\n".join(_check(self.root)))

    def test_shared_trace_digest_edit_requires_regeneration(self) -> None:
        source = self.root / lane.TRACE_DIGEST / "src/lib.rs"
        source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        self.assertIn("oracle source digest drifted", "\n".join(_check(self.root)))

    def test_inlined_r0_fri_vector_must_match_the_fixture(self) -> None:
        test = self.root / lane.R0_FRI_ZIG_TEST
        source = test.read_text(encoding="utf-8")
        digest = "d5c4299b10a98d577d3b24240c7d7854732120dbafa02f844dee8566a6ed02e4"
        self.assertIn(digest, source)
        test.write_text(source.replace(digest, "0" * 64), encoding="utf-8")
        self.assertIn("inlined R0 fri digests differ", "\n".join(_check(self.root)))
        test.write_text(
            source.replace("1266552422, 1856893702", "1266552423, 1856893702"), encoding="utf-8"
        )
        self.assertIn("alphas or last layer differ", "\n".join(_check(self.root)))
        test.write_text(source.replace(lane.R0_FRI_ZIG_TEST_NAME, "renamed"), encoding="utf-8")
        self.assertIn("missing test", "\n".join(_check(self.root)))

    def test_provenance_is_host_independent(self) -> None:
        provenance = json.loads((ROOT / lane.PROVENANCE).read_text(encoding="utf-8"))
        self.assertNotIn("host", provenance)
        self.assertEqual(lane.sha256_file(ROOT / lane.LOCK), provenance["oracle"]["lock_sha256"])
        provenance["host"] = "Darwin arm64"
        (self.root / lane.PROVENANCE).write_text(json.dumps(provenance), encoding="utf-8")
        self.assertIn("'host' is host-dependent", "\n".join(_check(self.root)))

    def test_every_subcommand_has_a_committed_checkpoint(self) -> None:
        subcommands = {subcommand for _, _, subcommand, _ in lane.ORACLE_ARTIFACTS}
        self.assertEqual(
            {
                "primitives",
                "gadgets",
                "components",
                "statement-trace",
                "project-air",
                "verifier-stages",
                "finalize",
                "topology",
                "prove-small",
                "prove-profiles",
                "air-programs",
                "cairo-statement",
                "prove-lifted-example",
            },
            subcommands,
        )
        for path, *_ in lane.ORACLE_ARTIFACTS:
            self.assertTrue((ROOT / path).is_file(), path)
        self.assertTrue((ROOT / lane.MULTIVERIFIER_INPUTS).is_file())
        for path, _ in lane.VERIFY_VERDICTS:
            self.assertTrue((ROOT / path).is_file(), path)

    def test_air_programs_bundle_geometry_is_checked(self) -> None:
        bundle = self.root / lane.AIR_PROGRAMS
        data = bytearray(bundle.read_bytes())
        data[32] ^= 0x01
        bundle.write_bytes(bytes(data))
        joined = "\n".join(_check(self.root))
        self.assertIn("AIR program geometry drifted", joined)
        self.assertIn("AIR program plan hash drifted", joined)

    def test_topology_must_match_the_registry_copies(self) -> None:
        path = self.root / lane.TOPOLOGY
        topology = json.loads(path.read_text(encoding="utf-8"))
        topology["body"]["folds"][0]["circuit_hash"][0] ^= 1
        path.write_text(json.dumps(topology), encoding="utf-8")
        self.assertIn("multiverifier circuit_hash differs", "\n".join(_check(self.root)))

    def test_manifest_rejects_path_dependencies_and_patches(self) -> None:
        manifest = self.root / lane.MANIFEST
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "[dependencies]\n",
                '[dependencies]\nlocal = { path = "../local" }\n',
            )
            + '\n[patch.crates-io]\nhex = { path = "../hex" }\n',
            encoding="utf-8",
        )
        joined = "\n".join(_check(self.root))
        self.assertIn("path dependency 'local' is forbidden", joined)
        self.assertIn("[patch] is forbidden", joined)

    def test_projection_decodes_with_the_documented_grammar(self) -> None:
        summary = lane.parse_projection((ROOT / lane.PROJECTION).read_bytes())
        self.assertEqual(parse_ledger(LEDGER).circuit_recursion_revision, summary["revision"])
        self.assertEqual(
            {
                "LARGE_MEMORY_VALUE_ID_BASE": 0x4000_0000,
                "MAX_SEQUENCE_LOG_SIZE": 25,
                "MEMORY_ADDRESS_TO_ID_SPLIT": 16,
            },
            summary["constants"],
        )
        cairo, circuit = summary["sources"]["cairo"], summary["sources"]["circuit"]
        self.assertEqual(83, len(cairo["slots"]))
        self.assertEqual(11, len(circuit["slots"]))
        for name in ("memory_address_to_id", "memory_id_to_big", "verify_bitwise_xor_12"):
            self.assertIn(name, cairo["hand_written"])
            self.assertNotIn(name, cairo["functions"])
        self.assertIn("qm_31_ops", circuit["hand_written"])
        self.assertIn("blake_g_gate", circuit["functions"])
        components = json.loads((ROOT / lane.COMPONENTS).read_text(encoding="utf-8"))
        generated = {
            evaluator["name"]
            for evaluator in components["body"]["evaluators"]
            if evaluator["air"] == "cairo" and not evaluator["hand_written"]
        }
        self.assertLessEqual(generated, set(cairo["functions"]))

    def test_projection_digest_covers_interned_strings(self) -> None:
        # Version 2 hashes each record with its strings inline: editing a string in the shared
        # table (here the first byte of the first string) changes every record that uses it.
        data = bytearray((ROOT / lane.PROJECTION).read_bytes())
        first_string = 8 + 4 + 4 + 4
        data[first_string] ^= 0x20
        with self.assertRaises(lane.ProjectionError):
            lane.parse_projection(bytes(data))

    def test_projection_rejects_a_corrupted_record(self) -> None:
        encoded = (ROOT / lane.PROJECTION).read_bytes()
        offset = lane.parse_projection(encoded)["sources"]["circuit"]["digest_offsets"][-1]
        data = bytearray(encoded)
        data[offset] ^= 0x01
        with self.assertRaisesRegex(lane.ProjectionError, "bad digest"):
            lane.parse_projection(bytes(data))
        data = bytearray(encoded)
        data[-2] ^= 0x01
        with self.assertRaises(lane.ProjectionError):
            lane.parse_projection(bytes(data))
        with self.assertRaisesRegex(lane.ProjectionError, "trailing bytes"):
            lane.parse_projection(encoded + b"\0")


if __name__ == "__main__":
    unittest.main()
