import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/cairo/generate_cairo_claim_registry.py"
SPEC = importlib.util.spec_from_file_location("generate_cairo_claim_registry", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CairoClaimRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rust_root = MODULE.DEFAULT_RUST_ROOT.resolve()
        if not rust_root.exists():
            raise unittest.SkipTest(
                "pinned stwo-cairo checkout unavailable; set STWO_CAIRO_RUST_ROOT"
            )
        cls.registry = MODULE.load_registry(rust_root)

    def test_exact_claim_field_and_enable_slot_shapes(self):
        self.assertEqual(len(self.registry.claim_fields), 68)
        self.assertEqual(len(self.registry.enable_slots), 83)
        self.assertEqual(self.registry.memory_id_to_big_slots, 16)

        self.assertEqual(self.registry.claim_fields[0].name, "add_opcode")
        self.assertEqual(self.registry.claim_fields[48].name, "memory_address_to_id")
        memory = self.registry.claim_fields[49]
        self.assertEqual(memory.name, "memory_id_to_big")
        self.assertEqual(memory.first_enable_slot, 49)
        self.assertEqual(memory.enable_slot_count, 16)
        self.assertEqual(memory.log_size_shape, "special_dynamic_prefix")
        self.assertEqual(self.registry.claim_fields[50].name, "memory_id_to_small")
        self.assertEqual(self.registry.claim_fields[50].first_enable_slot, 65)
        self.assertEqual(self.registry.claim_fields[-1].name, "verify_bitwise_xor_9")
        self.assertEqual(self.registry.enable_slots[-1].enable_slot, 82)

    def test_fixed_and_dynamic_log_size_metadata(self):
        fields = {field.name: field for field in self.registry.claim_fields}
        shapes = [field.log_size_shape for field in self.registry.claim_fields]
        self.assertEqual(shapes.count("dynamic"), 45)
        self.assertEqual(shapes.count("fixed"), 22)
        self.assertEqual(shapes.count("special_dynamic_prefix"), 1)
        self.assertEqual(fields["add_opcode"].log_size_shape, "dynamic")
        self.assertIsNone(fields["add_opcode"].fixed_log_size)
        self.assertEqual(fields["blake_round_sigma"].log_size_shape, "fixed")
        self.assertEqual(fields["blake_round_sigma"].fixed_log_size, 4)
        self.assertEqual(fields["pedersen_points_table_window_bits_18"].fixed_log_size, 23)
        self.assertEqual(fields["poseidon_round_keys"].fixed_log_size, 6)
        self.assertEqual(fields["range_check_9_9"].fixed_log_size, 18)
        self.assertEqual(fields["verify_bitwise_xor_9"].fixed_log_size, 18)

    def test_source_revisions_and_generated_module_are_exact(self):
        rendered = MODULE.render_zig(self.registry)
        self.assertEqual(MODULE.DEFAULT_OUTPUT.read_text(), rendered)
        self.assertIn(MODULE.PINNED_STWO_CAIRO_REVISION, rendered)
        self.assertIn(MODULE.PINNED_STWO_REVISION, rendered)
        self.assertEqual(len(self.registry.registry_sha256), 64)
        self.assertGreater(len(self.registry.source_files), 5)

    def test_parser_rejects_claim_cardinality_drift(self):
        claims = (MODULE.DEFAULT_RUST_ROOT / MODULE.CLAIMS_PATH).read_text()
        changed = claims.replace(
            "    pub verify_bitwise_xor_9: Option<verify_bitwise_xor_9::Claim>,\n",
            "",
            1,
        )
        with self.assertRaisesRegex(MODULE.RegistryError, "expected 68"):
            MODULE.parse_claim_fields(changed)

    def test_parser_rejects_memory_split_drift(self):
        root = MODULE.DEFAULT_RUST_ROOT
        address = (root / MODULE.MEMORY_ADDRESS_PATH).read_text()
        memory = (root / MODULE.MEMORY_CONSTANTS_PATH).read_text()
        preprocessed = (root / MODULE.PREPROCESSED_PATH).read_text()
        changed = preprocessed.replace(
            "pub const MAX_SEQUENCE_LOG_SIZE: u32 = 25;",
            "pub const MAX_SEQUENCE_LOG_SIZE: u32 = 26;",
            1,
        )
        with self.assertRaisesRegex(MODULE.RegistryError, "expected 16"):
            MODULE.parse_memory_slot_count(address, memory, changed)


if __name__ == "__main__":
    unittest.main()
