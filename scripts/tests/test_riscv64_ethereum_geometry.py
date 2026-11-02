import copy
import unittest

from scripts.riscv64_ethereum_geometry import domain_rows, model


def census():
    names = ["ECALL", "ADD", "DIV", "DIVU", "REM", "REMU", "DIVW", "DIVUW", "REMW", "REMUW"]
    return dict(status="completed", verified_output=True, instructions=1,
                keccak_calls=0, execution_profile="keccak_service_v1", elf_sha256="a" * 64,
                opcode_names=names, access_census_chunk_bytes=[512],
                access_batches=[dict(first_step=0, end_step=1, instructions=1,
                                     opcode_counts=[0, 1] + [0] * 8, unclassified_instructions=0,
                                     touched_chunks=[1], net_changed_chunks=[1],
                                     touched_internal_nodes=[55], net_changed_internal_nodes=[55])])


class GeometryTest(unittest.TestCase):
    def test_padding_and_value_only_tree_cost(self):
        self.assertEqual([domain_rows(n) for n in [0, 1, 31, 32, 33]], [32, 32, 32, 32, 64])
        result = model(census())
        # Two 512B leaves: 38 permutations each. Two depth55 paths: 4/hash.
        self.assertEqual(result["ram_candidates"][0]["total_permutations"], 516)
        self.assertEqual(result["ram_candidates"][0]["peak_hash_source_bytes"], 1024 * 312 * 4)
        self.assertEqual(result["batches"][0]["shared_lookup_mass"]["bytes"], 1280)
        self.assertFalse(result["cpu_width_included"])

    def test_invalid_census_coverage_and_characteristic_are_rejected(self):
        good = census()
        for changed in ["gap", "unclassified", "counter", "changed_chunk"]:
            bad = copy.deepcopy(good)
            row = bad["access_batches"][0]
            if changed == "gap":
                row["first_step"] = 1
            elif changed == "unclassified":
                row["unclassified_instructions"] = 1
            elif changed == "counter":
                row["opcode_counts"][1] = 2
            else:
                row["net_changed_chunks"] = [2]
            with self.assertRaises(ValueError, msg=changed):
                model(bad)
        bad = census()
        bad["instructions"] = bad["keccak_calls"] = 111849
        row = bad["access_batches"][0]
        row["instructions"] = row["end_step"] = 111849
        row["opcode_counts"] = [111849] + [0] * 9
        with self.assertRaisesRegex(ValueError, "characteristic"):
            model(bad)

    def test_typed_services_independent_padding_and_shared_mass(self):
        c = census()
        c.update(execution_profile="ethereum_services_v2", instructions=6,
                 keccak_calls=1, secp_add_calls=2, secp_double_calls=3)
        row = c["access_batches"][0]
        row.update(end_step=6, instructions=6, opcode_counts=[6] + [0] * 9,
                   keccak_calls=1, secp_add_calls=2, secp_double_calls=3)
        result = model(c, arithmetic_policy="division_multiplication_services_v3")
        parts = result["batches"][0]["components"]
        # ADD2 has32 active products: the qualified tail requires64 rows.
        self.assertEqual(parts["secp_add_product"]["rows"], 64)
        self.assertEqual(parts["secp_add_linear"]["rows"], 64)
        self.assertEqual(parts["secp_double_product"]["rows"], 64)
        self.assertEqual(parts["secp_double_linear"]["rows"], 32)
        self.assertEqual(result["keccak_calls"], 1)
        expected = 40 * 32 + 96 * 32 + 284 * 128 + 128 * 96 + 42 * 64
        self.assertEqual(result["batches"][0]["shared_lookup_mass"]["bytes"], expected)
        for key, replacement in [("secp_add_calls", 3), ("keccak_calls", None)]:
            bad = copy.deepcopy(c)
            bad["access_batches"][0][key] = replacement
            with self.assertRaises(ValueError):
                model(bad)
        bad = copy.deepcopy(c)
        bad["secp_double_calls"] = 4
        with self.assertRaises(ValueError):
            model(bad)

    def test_cpu_width_requires_exact_program_identity_and_immutable_policy(self):
        c = census()
        cpu = dict(opcodes_from_immutable_rom=True, execution_profile=c["execution_profile"],
                   elf_sha256=c["elf_sha256"], fixed_columns=3, main_columns=400,
                   interaction_columns=250, range_queries_per_row=134)
        result = model(c, cpu)
        self.assertTrue(result["cpu_width_included"])
        self.assertEqual(result["batches"][0]["shared_lookup_mass"]["bytes"], 1280 + 32 * 134)
        for key, value in [("opcodes_from_immutable_rom", False), ("elf_sha256", "b" * 64), ("execution_profile", "software")]:
            bad = dict(cpu, **{key: value})
            with self.assertRaises(ValueError):
                model(c, bad)


if __name__ == "__main__":
    unittest.main()
