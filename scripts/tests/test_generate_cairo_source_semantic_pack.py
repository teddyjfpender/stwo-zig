from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import generate_cairo_source_semantic_pack as MODULE


class SourceSemanticGeneratorTests(unittest.TestCase):
    def test_parses_only_immediately_rewritable_geometry(self):
        census = """\
--- MATCHED files (rewritable now) ---
  alpha cols=3 lookup_words=5 sub_words=7
--- MATCHED files (needs trait extension: u32/input/w27/deduce; census-only, NOT emitted) ---
  beta cols=11 lookup_words=13 sub_words=17 u32_sites=1
"""
        self.assertEqual(
            MODULE.parse_rewritable_census(census),
            {
                "alpha": {
                    "trace_columns": 3,
                    "lookup_words": 5,
                    "sub_input_words": 7,
                }
            },
        )

    def test_feed_parser_uses_downstream_state_not_field_alias(self):
        source = """\
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("range_check_9_9_b", 0, "range_check_9_9_state", 1, 12, 2),
];
"""
        feeds = MODULE.parse_feeds(source, "producer")
        self.assertEqual(len(feeds), 1)
        self.assertEqual(feeds[0].field, "range_check_9_9_b")
        self.assertEqual(feeds[0].target, "range_check_9_9")
        self.assertEqual(MODULE.relation_outputs(feeds), ["range_check_9_9"])

    def test_closed_topology_derives_contiguous_producer_edge(self):
        feeds = {
            "producer": [
                MODULE.Feed("consumer", 0, "consumer", 0, 7, 3),
                MODULE.Feed("consumer", 1, "consumer", 0, 10, 3),
            ],
            "consumer": [],
        }
        edges, capacities = MODULE.derive_closed_topology(
            ["producer", "consumer"], feeds
        )
        self.assertEqual(
            edges["consumer"],
            [
                {
                    "producer": "producer",
                    "word_base": 7,
                    "words_per_instance": 3,
                    "instances": 2,
                }
            ],
        )
        self.assertEqual(
            capacities["consumer"], [{"producer": "producer", "instances": 2}]
        )

    def test_closed_topology_rejects_noncontiguous_feed(self):
        feeds = {
            "producer": [
                MODULE.Feed("consumer", 0, "consumer", 0, 7, 3),
                MODULE.Feed("consumer", 1, "consumer", 0, 11, 3),
            ],
            "consumer": [],
        }
        with self.assertRaisesRegex(SystemExit, "not one contiguous uniform feed"):
            MODULE.derive_closed_topology(["producer", "consumer"], feeds)

    def test_all_checked_selection_excludes_fresh_generation(self):
        geometry = {
            "alpha": {"trace_columns": 1, "lookup_words": 2, "sub_input_words": 3},
            "beta": {"trace_columns": 4, "lookup_words": 5, "sub_input_words": 6},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "alpha.rs").write_text(
                MODULE.GENERATED_MARKER + "\n", encoding="ascii"
            )
            (root / "beta.rs").write_text("// source only\n", encoding="ascii")
            selected = MODULE.select_components(
                ["beta", "alpha"], geometry, None, True, root
            )
        self.assertEqual(selected, ["alpha"])

    def test_local_patch_mismatch_requires_explicit_oracle_pin(self):
        binding = MODULE.StwoBinding(
            declared_revision="1" * 40,
            resolved_revision="2" * 40,
            resolved_tree="3" * 40,
            kind="clean_local_path_patch",
        )
        with self.assertRaisesRegex(SystemExit, "local Stwo patch overrides"):
            MODULE.validate_stwo_binding(binding, None)
        MODULE.validate_stwo_binding(binding, "2" * 40)
        with self.assertRaisesRegex(SystemExit, "revision mismatch"):
            MODULE.validate_stwo_binding(binding, "4" * 40)

    def test_identity_separately_binds_declared_resolved_and_tree(self):
        source = {
            "repository": MODULE.SOURCE_REPOSITORY,
            "revision": "1" * 40,
            "tree": "2" * 40,
            "stwo_binding_kind": "clean_local_path_patch",
            "stwo_declared_revision": "3" * 40,
            "stwo_resolved_revision": "4" * 40,
            "stwo_resolved_tree": "5" * 40,
        }
        toolchain = {
            "rustc": "rustc",
            "cargo": "cargo",
            "rustfmt": "rustfmt",
            "source_cargo_lock_sha256": "6" * 64,
            "generator_cargo_lock_sha256": "7" * 64,
            "generator_sha256": "8" * 64,
        }
        baseline = MODULE.identity(source, toolchain, "9" * 64)
        for field in (
            "repository",
            "stwo_binding_kind",
            "stwo_declared_revision",
            "stwo_resolved_revision",
            "stwo_resolved_tree",
        ):
            changed = dict(source)
            changed[field] = changed[field] + "x"
            self.assertNotEqual(
                MODULE.identity(changed, toolchain, "9" * 64),
                baseline,
                field,
            )


if __name__ == "__main__":
    unittest.main()
