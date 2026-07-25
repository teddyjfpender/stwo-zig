from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import cairo_four_pie_source_coverage_lib as MODULE
from scripts.cairo_four_pie_source_coverage_lib import report as REPORT
from scripts.cairo_four_pie_source_coverage_lib import source as SOURCE

ROOT = Path(__file__).resolve().parents[2]


def shape(component: str, rows: int = 9, padded: int = 16) -> dict:
    return {
        "schema_version": MODULE.SHAPE_SCHEMA,
        "input": "/runtime/path/is/not/authority.bin",
        "components": [
            {
                "component": component,
                "parts": [
                    {
                        "part": "Main",
                        "n_real_rows": rows,
                        "padded_rows": padded,
                        "trace_log_size": padded.bit_length() - 1,
                    }
                ],
                "total_padded_rows": padded,
            }
        ],
    }


class ShapeReportTests(unittest.TestCase):
    def write_json(self, directory: str, value: dict) -> Path:
        path = Path(directory) / "shape.json"
        path.write_bytes(MODULE.json_bytes(value))
        return path

    def test_normalization_discards_input_path_and_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            value = shape("add_opcode_small")
            first = MODULE.normalize_shape_report(
                "SN_PIE_1", self.write_json(directory, value)
            )
            value["input"] = "/different/path.bin"
            second = MODULE.normalize_shape_report(
                "SN_PIE_1", self.write_json(directory, value)
            )
        self.assertEqual(first, second)
        self.assertNotIn("input", first)

    def test_rejects_proof_selected_semantic_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            value = shape("add_opcode_small")
            value["components"][0]["semantic_artifact"] = "from-proof"
            with self.assertRaisesRegex(MODULE.CoverageError, "unexpected"):
                MODULE.normalize_shape_report(
                    "SN_PIE_1", self.write_json(directory, value)
                )

    def test_rejects_invalid_geometry(self):
        with tempfile.TemporaryDirectory() as directory:
            value = shape("add_opcode_small", rows=17, padded=16)
            with self.assertRaisesRegex(MODULE.CoverageError, "row geometry"):
                MODULE.normalize_shape_report(
                    "SN_PIE_1", self.write_json(directory, value)
                )


class CensusTests(unittest.TestCase):
    CENSUS = """\
======================================================================
witness_genericize CENSUS
======================================================================
Files scanned:                          3
  with write_trace_simd:                2
  MATCHED (rewritable):                 1
  MATCHED (needs trait ext: u32/input):  1
  skipped:                              1

--- MATCHED files (rewritable now) ---
  alpha                              cols=1    lookup_words=2    sub_words=3
--- MATCHED files (needs trait extension: u32/input/w27/deduce; census-only, NOT emitted) ---
  beta                               cols=4    lookup_words=5    sub_words=6    u32_sites=1
--- SKIPPED files (loud reasons) ---
  gamma                              [skeleton] no `fn write_trace_simd`
--- deduce_output census (device-kernel backlog) ---
"""

    def test_parses_writer_and_rewrite_status(self):
        summary, entries = MODULE.parse_census(self.CENSUS)
        self.assertEqual(summary["files_scanned"], 3)
        self.assertEqual(entries["alpha"]["status"], "rewritable")
        self.assertEqual(entries["beta"]["status"], "trait_extension")
        self.assertFalse(entries["gamma"]["source_writer_present"])


class ReconciliationTests(unittest.TestCase):
    def build_with(
        self,
        components: tuple[str, ...],
        census: dict[str, dict],
        semantic_names: tuple[str, ...] = (),
        *,
        gate_captured: bool = True,
        sealed_decoder: bool = True,
    ) -> dict:
        reports = {
            name: {
                "name": name,
                "components": [
                    {
                        "component": component,
                        "parts": [
                            {
                                "part": "Main",
                                "n_real_rows": 9,
                                "padded_rows": 16,
                                "trace_log_size": 4,
                            }
                        ],
                        "total_padded_rows": 16,
                    }
                    for component in components
                ],
            }
            for name in MODULE.CANONICAL_PIES
        }
        fake_paths = {name: Path(name) for name in MODULE.CANONICAL_PIES}
        census_copy = copy.deepcopy(census)
        for entry in census_copy.values():
            entry.setdefault("source_sha256", "a" * 64)
        semantic = {
            name: {"artifact_sha256": "a" * 64} for name in semantic_names
        }
        decoder = {
            "cairo_source": {
                "revision": "c" * 40,
                "tree": "d" * 40,
                "clean": True,
                "dirty_paths": [],
            },
            "stwo_source": {
                "revision": "e" * 40,
                "tree": "1" * 40,
                "clean": True,
                "dirty_paths": [],
            },
            "gpu_bench": dict(MODULE.DECODER_BINARY_IDENTITIES["gpu_bench"]),
            "kernel_emit": dict(MODULE.DECODER_BINARY_IDENTITIES["kernel_emit"]),
            "shape_schema": MODULE.SHAPE_SCHEMA,
            "shape_capture": (
                "gate_invoked_kernel_emit_on_sealed_adapted_inputs"
                if gate_captured
                else "caller_supplied_shape_reports"
            ),
        }
        if not sealed_decoder:
            decoder["kernel_emit"]["sha256"] = "0" * 64
        with (
            mock.patch.object(
                REPORT,
                "authenticate_source",
                return_value=(
                    {
                        "repository": "https://github.com/teddyjfpender/stwo-cairo.git",
                        "revision": "c" * 40,
                        "tree": "d" * 40,
                        "stwo_binding_kind": "clean_local_path_patch",
                        "stwo_declared_revision": "2" * 40,
                        "stwo_resolved_revision": "e" * 40,
                        "stwo_resolved_tree": "1" * 40,
                    },
                    census_copy,
                ),
            ),
            mock.patch.object(
                REPORT,
                "load_semantic_registry",
                return_value=({"registered_components": list(semantic_names)}, semantic),
            ),
            mock.patch.object(
                REPORT,
                "decode_pie",
                side_effect=lambda name, _path: {"name": name},
            ),
            mock.patch.object(
                REPORT,
                "decode_adapted",
                return_value={"bytes": 1, "sha256": "f" * 64},
            ),
            mock.patch.object(
                REPORT,
                "normalize_shape_report",
                side_effect=lambda name, _path: reports[name],
            ),
            mock.patch.object(
                REPORT,
                "normalized_shape_sha256",
                side_effect=lambda value: MODULE.SHAPE_IDENTITIES[value["name"]],
            ),
        ):
            return MODULE.build_report(
                fake_paths,
                fake_paths,
                fake_paths,
                Path("."),
                Path("census"),
                decoder,
            )

    def test_union_is_sorted_and_source_pack_is_source_owned(self):
        census = {
            "beta": {"status": "rewritable", "source_writer_present": True},
            "alpha": {"status": "rewritable", "source_writer_present": True},
        }
        report = self.build_with(("beta", "alpha"), census, ("alpha", "beta"))
        self.assertEqual(report["component_union"], ["alpha", "beta"])
        self.assertTrue(report["source_coverage_admissible"])
        self.assertEqual(report["authority"]["pie_role"], "runtime_coverage_only")
        self.assertFalse(
            report["authority"]["proof_selected_semantic_artifacts_allowed"]
        )

    def test_unknown_component_fails_closed(self):
        with self.assertRaisesRegex(MODULE.CoverageError, "unknown"):
            self.build_with(
                ("unknown",),
                {"known": {"status": "rewritable", "source_writer_present": True}},
            )

    def test_favorable_caller_supplied_shape_cannot_open_readiness(self):
        report = self.build_with(
            ("alpha",),
            {"alpha": {"status": "rewritable", "source_writer_present": True}},
            ("alpha",),
            gate_captured=False,
        )
        self.assertFalse(report["source_coverage_admissible"])
        self.assertEqual(
            report["blockers"]["shape_reports_not_gate_captured"],
            ["caller_supplied_shape_reports"],
        )

    def test_favorable_shape_with_unsealed_decoder_cannot_open_readiness(self):
        report = self.build_with(
            ("alpha",),
            {"alpha": {"status": "rewritable", "source_writer_present": True}},
            ("alpha",),
            sealed_decoder=False,
        )
        self.assertFalse(report["source_coverage_admissible"])
        self.assertEqual(
            report["blockers"]["decoder_binary_identity_mismatch"],
            ["kernel_emit"],
        )

    def test_missing_writer_blocks_source_coverage(self):
        report = self.build_with(
            ("memory",),
            {"memory": {"status": "skipped", "source_writer_present": False}},
            ("memory",),
        )
        self.assertFalse(report["source_coverage_admissible"])
        self.assertEqual(report["blockers"]["missing_source_writers"], ["memory"])


class SourceAuthenticationTests(unittest.TestCase):
    def test_rejects_non_source_manifest_before_reading_runtime_inputs(self):
        manifest = MODULE.load_json(MODULE.MANIFEST_PATH)
        manifest["provenance"] = "proof-derived"
        with self.assertRaisesRegex(MODULE.CoverageError, "not source-derived"):
            MODULE.authenticate_source(Path("."), manifest, Path("missing"))

    def test_rejects_revision_drift(self):
        manifest = MODULE.load_json(MODULE.MANIFEST_PATH)
        with mock.patch.object(
            SOURCE,
            "git_output",
            side_effect=["0" * 40, manifest["source"]["tree"]],
        ):
            with self.assertRaisesRegex(MODULE.CoverageError, "source mismatch"):
                MODULE.authenticate_source(Path("."), manifest, Path("missing"))

    def test_rejects_legacy_ambiguous_stwo_identity_schema(self):
        manifest = MODULE.load_json(MODULE.MANIFEST_PATH)
        source = manifest["source"]
        source["stwo_revision"] = source.pop("stwo_resolved_revision")
        source.pop("stwo_binding_kind")
        source.pop("stwo_declared_revision")
        source.pop("stwo_resolved_tree")
        with self.assertRaisesRegex(MODULE.CoverageError, "keys differ"):
            MODULE.authenticate_source(Path("."), manifest, Path("missing"))


class CheckedEvidenceTests(unittest.TestCase):
    def verify_mutation_fails(self, report: dict, pattern: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(MODULE.json_bytes(report))
            with self.assertRaisesRegex(MODULE.CoverageError, pattern):
                MODULE.verify_record(report, path)

    def test_checked_report_is_canonical_when_present(self):
        if not MODULE.DEFAULT_REPORT.exists():
            self.skipTest("coverage capture has not produced the checked report")
        report = MODULE.load_json(MODULE.DEFAULT_REPORT)
        MODULE.verify_record(report)

    def test_deleting_component_cannot_rewrite_checked_union(self):
        report = copy.deepcopy(MODULE.load_json(MODULE.DEFAULT_REPORT))
        removed = report["component_union"][0]
        for pie in report["pies"]:
            pie["components"] = [
                component
                for component in pie["components"]
                if component["component"] != removed
            ]
            forged = {"name": pie["name"], "components": pie["components"]}
            pie["normalized_shape_sha256"] = MODULE.normalized_shape_sha256(forged)
        report["component_union"].remove(removed)
        report["reconciliation"] = [
            entry for entry in report["reconciliation"] if entry["name"] != removed
        ]
        report["blockers"] = REPORT._blockers(
            report["source"], report["decoder"], report["reconciliation"]
        )
        report["source_coverage_admissible"] = not any(
            report["blockers"].values()
        )
        self.verify_mutation_fails(report, "normalized shape identity")

    def test_altering_rows_cannot_rewrite_checked_shape(self):
        report = copy.deepcopy(MODULE.load_json(MODULE.DEFAULT_REPORT))
        pie = report["pies"][0]
        part = pie["components"][0]["parts"][0]
        if part["n_real_rows"] < part["padded_rows"]:
            part["n_real_rows"] += 1
        else:
            part["n_real_rows"] -= 1
        forged = {"name": pie["name"], "components": pie["components"]}
        pie["normalized_shape_sha256"] = MODULE.normalized_shape_sha256(forged)
        self.verify_mutation_fails(report, "normalized shape identity")

    def test_altering_resolved_stwo_tree_cannot_rewrite_checked_source(self):
        report = copy.deepcopy(MODULE.load_json(MODULE.DEFAULT_REPORT))
        report["source"]["stwo_resolved_tree"] = "0" * 40
        self.verify_mutation_fails(report, "source stwo_resolved_tree differs")


if __name__ == "__main__":
    unittest.main()
