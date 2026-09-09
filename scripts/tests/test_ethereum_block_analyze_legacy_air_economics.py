from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch" / "benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_analyze_legacy_air_economics as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def identity(seed: str) -> dict:
    return {"bytes": 1, "path": f"/private/tmp/{seed}", "sha256": seed * 64}


def candidate_components() -> list[dict]:
    return [
        subject._component("scan", 796_670, 82, 1, 2, implemented=True),
        subject._component("bitmap", 41_558, 75, 32, 2, implemented=True),
        subject._component(
            "caller-minimum-model", 115, 14, 3, 2, implemented=False,
        ),
    ]


def fixture() -> dict:
    components = candidate_components()
    return protocol.seal({
        "candidate_lower_bound": {
            "components": components,
            "excluded_unmodeled_cells": [
                "source-byte/read-clock relation",
                "caller/output-memory relation",
                "registered STARK wrapper and proof geometry",
            ],
            "scope": "padded-pre-source-output-relation-lower-bound",
            "shape_authority": {},
            "totals": {
                "interaction_cells": 8_389_632,
                "main_cells": 90_900_224,
                "preprocessed_cells": 2_228_480,
                "total_padded_cells": subject.CANDIDATE_LOWER_BOUND_CELLS,
            },
        },
        "claim_boundary": subject._claim_boundary(),
        "comparison": {
            "asymmetric_conservative_candidate_is_padded_software_is_active_only": True,
            "break_even_unmodeled_relation_cell_budget": 378_629_559,
            "candidate_fraction_scaled_1e9_floor": 211_431_388,
            "cell_delta_before_unmodeled_relations": 378_629_559,
            "reduction_percent_scaled_1e6_floor": 78_856_861,
        },
        "inputs": {
            "candidate_sources": {"authority": identity("1")},
            "pc_observation": identity("2"),
            "pc_observation_content_sha256": "3" * 64,
            "production_sources": {"composition": identity("4")},
            "semantic_observation": identity("5"),
            "semantic_observation_content_sha256": "6" * 64,
        },
        "production": False,
        "recommendation": {
            "economics_headroom_meaningful": True,
            "next_authorized_scope": "source-output-relation-microproof-only",
            "result": "conditional-go-source-output-join-microproof",
            "stark_inclusion_ready": False,
        },
        "retained_workload": {
            "bitmap_word_rows": 41_558,
            "call_count": 115,
            "function_end_exclusive": subject.FUNCTION_END,
            "function_start": subject.FUNCTION_START,
            "observed_function_rows": 6_846_967,
            "scan_rows": 796_670,
            "semantic_observation_scope": "retained-prefix31-no-extrapolation",
        },
        "schema": subject.SCHEMA,
        "software_comparator": {
            "families": [
                {"family": family} for family in subject.EXPECTED_FAMILY_ROWS
            ],
            "scope": "canonical-typed-software-active-main-plus-interaction-only",
            "totals": {
                "active_rows": 6_846_967,
                "interaction_cells": 202_273_356,
                "main_cells": 277_874_539,
                "padded_cells": None,
                "preprocessed_cells": None,
                "total_active_cells": subject.SOFTWARE_ACTIVE_CELLS,
            },
        },
        "soundness_seams": subject._soundness_seams(),
        "status": subject.STATUS,
    })


class AnalyzeLegacyAirEconomicsTests(unittest.TestCase):
    def test_source_derived_row_widths_and_candidate_padding(self) -> None:
        scan = subject._source(subject.SCAN_SOURCE, "scan")
        bitmap = subject._source(subject.BITMAP_SOURCE, "bitmap")
        self.assertEqual(subject._row_width(scan, "scan")[0], 82)
        self.assertEqual(subject._row_width(bitmap, "bitmap")[0], 75)
        observation = {
            "aggregate": {"call_count": 115, "scan_iterations_sum": 796_670},
            "calls": ([{"length": 1}] * 114) + [{"length": 1_326_177}],
        }
        candidate, shape = subject._candidate_geometry(observation)
        self.assertEqual(
            candidate["totals"]["total_padded_cells"], 101_518_336,
        )
        self.assertEqual(
            [row["padded_rows"] for row in candidate["components"]],
            [1 << 20, 1 << 16, 1 << 7],
        )
        self.assertEqual(shape["caller_main_column_derivation"],
                         "active1+caller3+descriptor3+summary7")

    def test_pc_family_slice_and_production_widths_close_exactly(self) -> None:
        rows = []
        for offset, (family, count) in enumerate(
            subject.EXPECTED_FAMILY_ROWS.items()
        ):
            rows.append({
                "count": count,
                "opcode_family": family,
                "pc": subject.FUNCTION_START + offset,
            })
        derived = subject._family_rows({"per_pc": rows})
        families, totals = subject._production_geometry(derived)
        self.assertEqual(totals["main_cells"], 277_874_539)
        self.assertEqual(totals["interaction_cells"], 202_273_356)
        self.assertEqual(totals["total_active_cells"], 480_147_895)
        widths = {
            row["family"]: (row["main_columns"], row["interaction_columns"])
            for row in families
        }
        self.assertEqual(widths["load_store"], (50, 36))
        self.assertEqual(widths["mul"], (39, 64))
        self.assertEqual(widths["shifts_reg"], (60, 40))

    def test_resealed_type_geometry_scope_and_seam_mutations_reject(self) -> None:
        original = fixture()
        mutations = (
            lambda value: value.__setitem__("production", 0),
            lambda value: value["candidate_lower_bound"]["components"][0].__setitem__(
                "air_implemented", 1,
            ),
            lambda value: value["candidate_lower_bound"]["components"][0].__setitem__(
                "log_size", 19,
            ),
            lambda value: value["candidate_lower_bound"]["totals"].__setitem__(
                "main_cells", 90_900_225,
            ),
            lambda value: value["software_comparator"]["totals"].__setitem__(
                "padded_cells", 0,
            ),
            lambda value: value["comparison"].__setitem__(
                "asymmetric_conservative_candidate_is_padded_software_is_active_only", 1,
            ),
            lambda value: value["recommendation"].__setitem__(
                "stark_inclusion_ready", True,
            ),
            lambda value: value["soundness_seams"][0].__setitem__("ready", True),
        )
        with (
            mock.patch.object(
                subject, "_validate_identity", side_effect=lambda value, _: value,
            ),
            mock.patch.object(subject, "build", return_value=original),
        ):
            self.assertIs(subject.validate(original), original)
            for mutate in mutations:
                changed = copy.deepcopy(original)
                mutate(changed)
                changed["content_sha256"] = protocol.content_sha256(changed)
                with self.assertRaises(subject.AnalyzeLegacyAirEconomicsError):
                    subject.validate(changed)

    def test_resealed_source_and_family_mutations_reject_against_rebuild(self) -> None:
        original = fixture()
        mutations = (
            lambda value: value["inputs"].__setitem__(
                "semantic_observation_content_sha256", "7" * 64,
            ),
            lambda value: value["software_comparator"]["families"][0].__setitem__(
                "family", "mutated",
            ),
            lambda value: value["retained_workload"].__setitem__("scan_rows", 796_671),
        )
        with (
            mock.patch.object(
                subject, "_validate_identity", side_effect=lambda value, _: value,
            ),
            mock.patch.object(subject, "build", return_value=original),
        ):
            for mutate in mutations:
                changed = copy.deepcopy(original)
                mutate(changed)
                changed["content_sha256"] = protocol.content_sha256(changed)
                with self.assertRaises(subject.AnalyzeLegacyAirEconomicsError):
                    subject.validate(changed)

    def test_unsealed_mutation_rejects(self) -> None:
        changed = fixture()
        changed["comparison"]["cell_delta_before_unmodeled_relations"] -= 1
        with self.assertRaises(subject.AnalyzeLegacyAirEconomicsError):
            subject.validate(changed)


if __name__ == "__main__":
    unittest.main()
