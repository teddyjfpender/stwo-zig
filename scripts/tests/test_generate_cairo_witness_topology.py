from __future__ import annotations

import unittest

from scripts import generate_cairo_witness_topology as topology


class CairoWitnessTopologyTests(unittest.TestCase):
    def test_parses_feed_layout_and_flattened_geometry(self) -> None:
        source = """\
pub(crate) const N_SUB_INPUT_WORDS: usize = 7;
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("range_check_9_9_b", 0, "range_check_9_9_state", 1, 3, 2),
    ("memory_address_to_id", 0, "memory_address_to_id_state", 0, 5, 1),
];
"""
        component = topology.parse_component(source, "verify_instruction")
        self.assertEqual(component.producer, "verify_instruction")
        self.assertEqual(component.sub_words_per_row, 7)
        self.assertEqual(component.feeds[0].target, "range_check_9_9")
        self.assertEqual(component.feeds[0].relation, 1)
        self.assertEqual(component.feeds[0].word_base, 3)

    def test_rejects_feed_outside_flattened_words(self) -> None:
        source = """\
pub(crate) const N_SUB_INPUT_WORDS: usize = 4;
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("range_check_9_9", 0, "range_check_9_9_state", 0, 3, 2),
];
"""
        with self.assertRaisesRegex(ValueError, "exceeds"):
            topology.parse_component(source, "producer")

    def test_rejects_duplicate_field_instance(self) -> None:
        source = """\
pub(crate) const N_SUB_INPUT_WORDS: usize = 2;
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("range_check_9_9", 0, "range_check_9_9_state", 0, 0, 2),
    ("range_check_9_9", 0, "range_check_9_9_state", 0, 0, 2),
];
"""
        with self.assertRaisesRegex(ValueError, "duplicate"):
            topology.parse_component(source, "producer")


if __name__ == "__main__":
    unittest.main()
