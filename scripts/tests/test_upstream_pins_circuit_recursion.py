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

    def test_projection_rejects_a_corrupted_record(self) -> None:
        data = bytearray((ROOT / lane.PROJECTION).read_bytes())
        data[-2] ^= 0x01
        with self.assertRaisesRegex(lane.ProjectionError, "bad digest"):
            lane.parse_projection(bytes(data))
        with self.assertRaisesRegex(lane.ProjectionError, "trailing bytes"):
            lane.parse_projection((ROOT / lane.PROJECTION).read_bytes() + b"\0")


if __name__ == "__main__":
    unittest.main()
