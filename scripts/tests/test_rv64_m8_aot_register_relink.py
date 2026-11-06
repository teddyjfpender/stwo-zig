"""Host checks for the M8 T5 flag-gated catalogue dispatcher (no GPU, no pod paths)."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_m8_aot_register_relink as R

TRUTH = """#pragma once
struct StwoTruthKernelPart { const void *kernel; uint32_t groups; };
struct StwoTruthKernelSpan { const StwoTruthKernelPart *parts; uint32_t count; };
static const StwoTruthKernelPart truth_parts_0[]={{(const void*)rv64_truth_domain_0_shard_4,4u},{(const void*)rv64_truth_domain_0_shard_47,1u},{(const void*)rv64_truth_domain_0_shard_48,1u}};
static const StwoTruthKernelPart truth_parts_1[]={{(const void*)rv64_truth_domain_1,1u}};
static const StwoTruthKernelSpan truth_catalog[]={{truth_parts_0,3u},{truth_parts_1,1u}};
"""
CORE = """#pragma once
struct CorePart { const void *kernel; uint32_t grouping, groups; };
struct CoreSpan { const CorePart *parts; uint32_t count; };
static const CorePart core_parts_0[]={{(const void*)rv64_joined_domain_0,0u,0u}};
static const CorePart core_parts_20[]={{(const void*)rv64_joined_domain_20,0u,0u}};
static const CoreSpan core_catalog[]={{core_parts_0,1u},{core_parts_20,1u}};
"""


class Dispatcher(unittest.TestCase):
    def test_copies_rename_only_selected_kernels(self):
        lines, n = R.catalogue_copy(TRUTH, ["rv64_truth_domain_0_shard_47"], "truth_parts", "StwoTruthKernelPart", "StwoTruthKernelSpan", "truth_catalog")
        self.assertEqual(n, 1)
        text = "\n".join(lines)
        self.assertIn("(const void*)rv64_truth_domain_0_shard_47_t5,1u}", text)
        self.assertIn("(const void*)rv64_truth_domain_0_shard_48,1u}", text)  # not selected: admitted kernel
        self.assertIn("(const void*)rv64_truth_domain_0_shard_4,4u}", text)  # prefix-only match is not renamed
        self.assertIn("static const StwoTruthKernelSpan t5_truth_catalog[]={{t5_truth_parts_0,3u},{t5_truth_parts_1,1u}};", text)

    def test_dispatcher_selects_by_flag_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "truth_composition_launches.h").write_text(TRUTH)
            (Path(d) / "real_composition_launches.h").write_text(CORE)
            src = R.dispatcher_source(Path(d), ["rv64_truth_domain_0_shard_47"], ["rv64_joined_domain_20"])
            self.assertIn('getenv("STWO_RV64_M8_AOT_REGISTER_SCHEDULE")', src)
            self.assertIn("(mode?t5_truth_catalog:truth_catalog)", src)
            self.assertIn("(mode?t5_core_catalog:core_catalog)", src)
            self.assertIn("if (mode<0) return int(cudaErrorInvalidValue);", src)
            self.assertIn('extern "C" __global__ void rv64_joined_domain_20_t5(', src)
            with self.assertRaises(RuntimeError):
                R.dispatcher_source(Path(d), ["rv64_truth_domain_0_shard_99"], [])


if __name__ == "__main__":
    unittest.main()
