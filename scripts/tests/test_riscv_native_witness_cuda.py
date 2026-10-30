"""Fail-closed translation and canonical finite-family checks."""
import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("native_cuda_export", ROOT / "scripts/riscv_native_witness_cuda.py")
export = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export)


class NativeWitnessCudaTest(unittest.TestCase):
    def test_transitive_static_references_are_preserved(self):
        lines = [
            "static uint32_t const unused;",
            "static uint32_t const root;",
            "static uint32_t const leaf;",
            "static uint32_t const root = leaf;",
            "static uint32_t const leaf = 31;",
            "static uint32_t function(void) { return root; }",
        ]
        at, used = export.reachable_globals(lines)
        self.assertEqual(used, {"root", "leaf"})
        self.assertEqual(set(at.values()), {"unused", "root", "leaf"})

    def test_referenced_data_is_rejected_instead_of_rewritten(self):
        source = '#include "zig.h"\nstatic uint32_t const table = 1;\nstatic uint32_t f(void) { return table; }\n'
        with self.assertRaisesRegex(ValueError, "static runtime data"):
            export.decorate(source, "")

    def test_only_explicit_numeric_constants_can_be_retained_on_device(self):
        header = "#define zig_minInt_i8 0\nzig_int_helpers(64, uint64_t)\nstatic inline bool zig_addo_u32"
        source = '#include "zig.h"\nstatic uint32_t const table[2];\nstatic uint32_t const table[2] = {UINT32_C(1),UINT32_C(2)};\nstatic uint32_t f(void) {\nreturn table[0];\n}\n'
        code, counts = export.decorate(source, header, families=(), constant_symbols=frozenset({"table"}))
        self.assertIn("extern __device__ __constant__ uint32_t const table[2];", code)
        self.assertIn("__device__ __constant__ uint32_t const table[2] =", code)
        self.assertEqual(counts["retained_static_symbols"], 1)
        with self.assertRaisesRegex(ValueError, "non-numeric"):
            export.decorate(source.replace("UINT32_C(2)", "other_table"), header, families=(), constant_symbols=frozenset({"table"}))

    def test_finite_family_roster_matches_canonical_manifest(self):
        source = (ROOT / "src/frontends/riscv/opcode_manifest.zig").read_text()
        body = source.split("pub const Family = enum(u8) {", 1)[1].split("};", 1)[0]
        actual = tuple(re.findall(r"^\s*([a-z_]+),", body, re.M))
        self.assertEqual(export.FAMILIES, actual)
        self.assertEqual(len(actual), 17)

    def test_c_byte_arrays_preserve_exact_length_and_escaped_bytes(self):
        line = r' static uint8_t const digest[5] zig_nonstring = "\377\000A\n\"";'
        self.assertEqual(export.byte_string_initializer(line), " static uint8_t const digest[5] zig_nonstring = {255,0,65,10,34};")
        self.assertEqual(export.byte_string_initializer(' static uint8_t const a[3] = "x";'), ' static uint8_t const a[3] = {120,0,0};')
        with self.assertRaisesRegex(ValueError, "exceeds array"):
            export.byte_string_initializer(' static uint8_t const a[1] = "xx";')
        with self.assertRaisesRegex(ValueError, "unsupported"):
            export.byte_string_initializer(r' static uint8_t const a[1] = "\q";')

    def test_generated_launch_contract_has_no_host_witness_work(self):
        source = export.wrappers()
        self.assertEqual(source.count("__global__ void"), 17)
        self.assertNotIn("cudaMemcpy", source)
        self.assertNotIn("cudaMalloc", source)
        self.assertNotIn("cudaDeviceSynchronize", source)
        self.assertIn("indices[i-1] >= source", source)
        self.assertIn("source >= source_count", source)
        self.assertIn("active_count > padded_rows", source)


if __name__ == "__main__":
    unittest.main()
