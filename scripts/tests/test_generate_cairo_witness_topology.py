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
crate::jit_lookup_accessor! {
    5;
    relation_0: 4,
    mults_0: scalar,
}
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    ("relation_0", "mults_0", false, "", "", false),
];
"""
        component = topology.parse_component(source, "verify_instruction")
        self.assertEqual(component.producer, "verify_instruction")
        self.assertEqual(component.sub_words_per_row, 7)
        self.assertEqual(component.feeds[0].target, "range_check_9_9")
        self.assertEqual(component.feeds[0].relation, 1)
        self.assertEqual(component.feeds[0].word_base, 3)
        self.assertEqual(component.lookup_words_per_row, 5)
        self.assertEqual(component.lookup_fields[1].word_base, 4)
        self.assertEqual(component.logup_columns[0].a.multiplicity, "mults_0")
        self.assertIsNone(component.logup_columns[0].b)

    def test_rejects_feed_outside_flattened_words(self) -> None:
        source = """\
pub(crate) const N_SUB_INPUT_WORDS: usize = 4;
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("range_check_9_9", 0, "range_check_9_9_state", 0, 3, 2),
];
crate::jit_lookup_accessor! {
    fixed 3;
    relation_0: 2,
    mults_0: scalar,
}
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    ("relation_0", "mults_0", true, "", "", false),
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
crate::jit_lookup_accessor! {
    3;
    relation_0: 2,
    mults_0: scalar,
}
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    ("relation_0", "mults_0", false, "", "", false),
];
"""
        with self.assertRaisesRegex(ValueError, "duplicate"):
            topology.parse_component(source, "producer")

    def test_rejects_unknown_logup_multiplicity_field(self) -> None:
        source = """\
pub(crate) const N_SUB_INPUT_WORDS: usize = 0;
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[];
crate::jit_lookup_accessor! {
    with_n_rows 2;
    relation_0: 2,
}
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    ("relation_0", "missing", false, "", "", false),
];
"""
        with self.assertRaisesRegex(ValueError, "multiplicity"):
            topology.parse_component(source, "producer")


if __name__ == "__main__":
    unittest.main()
