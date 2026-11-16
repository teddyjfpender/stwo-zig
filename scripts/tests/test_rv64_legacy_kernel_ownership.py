"""Preserve actual CUDA launch/fixture bodies; no CUDA execution qualification."""
from pathlib import Path
import hashlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "src/backends/cuda/native/rv64"
EXPECTED = {
    "deep_prepare": "4f1f8fa29e2ab9fd881cde57af56f781d9fe340d33668f1082748a98beb04164",
    "deep_combine": "fa2a65e2d12c3e5df3f9ea26d7d659899128aeccd8d41ef0bdeae5e81ec4d889",
    "sample_evaluate": "2e552ee435544ff834c15bc66d08d8fea5a4186a59b1177b4d750ad1889e8549",
    "benchmark": "a7ef7c5ad5292be7df059e834606de9df67cb04eec3755f9bcdcaabe0dc1cdbf",
}


def body(source, signature):
    begin = source.index("{", source.index(signature))
    depth = 0
    for at in range(begin, len(source)):
        if source[at] == "{":
            depth += 1
        elif source[at] == "}":
            depth -= 1
            if depth == 0:
                return source[begin + 1:at]
    raise ValueError(signature)


def digest(source):
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
    return hashlib.sha256(re.sub(r"\s+", " ", source).strip().encode()).hexdigest()


class LegacyKernelOwnership(unittest.TestCase):
    def test_typed_private_launchers_preserve_complete_original_bodies(self):
        for name, filename in (("deep_prepare", "deep.cu"), ("deep_combine", "deep.cu"), ("sample_evaluate", "samples.cu")):
            source = (NATIVE / filename).read_text()
            actual = body(source, "int stwo::cuda::rv64::detail::" + name + "(")
            self.assertEqual(EXPECTED[name], digest(actual), name)

    def test_public_abi_always_selects_unchanged_default_without_process_override(self):
        for name, filename, public in (("deep_prepare", "deep.cu", "stwo_rv64_deep_prepare_on"), ("deep_combine", "deep.cu", "stwo_rv64_deep_combine_on"), ("sample_evaluate", "samples.cu", "stwo_rv64_sample_evaluate_on")):
            source = (NATIVE / filename).read_text()
            actual = body(source, 'extern "C" int ' + public + '(')
            self.assertEqual("return stwo::cuda::rv64::detail::" + name + "(ctx, lane, input, false);", actual.strip())
        self.assertNotIn("deep_legacy()", (NATIVE / "deep.cu").read_text())

    def test_existing_physical_benchmark_preserves_every_case_and_timing_boundary(self):
        source = (ROOT / "tests/cuda/rv64/deep_t3_parity_bench.cu").read_text()
        source = source.replace('#include "rv64/detail/kernel_variants.h"\n', "")
        self.assertEqual(EXPECTED["benchmark"], digest(source))
        self.assertNotIn("setenv(", source)

    def test_private_header_has_real_c_layouts_and_no_new_c_export(self):
        header = NATIVE / "detail/kernel_variants.h"
        source = header.read_text()
        self.assertEqual(3, source.count('__attribute__((visibility("hidden")))'))
        self.assertNotIn('extern "C"', source)
        compiler = shutil.which("clang++") or shutil.which("c++")
        if not compiler:
            self.skipTest("no host C++ compiler; CUDA qualification remains unrun")
        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "header.cpp"
            probe.write_text('#include "rv64/detail/kernel_variants.h"\n#include <type_traits>\nstatic_assert(std::is_same_v<decltype(&stwo::cuda::rv64::detail::deep_prepare), int(*)(void*, uint32_t, const StwoRv64DeepPrepare*, bool)>);\nstatic_assert(std::is_same_v<decltype(&stwo::cuda::rv64::detail::deep_combine), int(*)(void*, uint32_t, const StwoRv64DeepCombine*, bool)>);\nstatic_assert(std::is_same_v<decltype(&stwo::cuda::rv64::detail::sample_evaluate), int(*)(void*, uint32_t, const StwoRv64SampleEvaluation*, bool)>);\n')
            result = subprocess.run([compiler, "-std=c++17", "-Werror", "-fsyntax-only", "-I", str(NATIVE.parent), str(probe)], capture_output=True, text=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stderr)
