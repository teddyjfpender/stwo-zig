"""Independent bigint differential checks for the actual CUDA modulo source.

The host harness substitutes CUDA qualifiers and the device fault instruction,
not arithmetic. GPU qualification remains a separate required gate.
"""
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "src/tools/cairo_cuda_witness_aot/deductions_integer.cuh"


def felt_words(value):
    return [(value >> (9 * limb)) & 511 for limb in range(28)]


def u384_words(value):
    return [word for felt in range(4) for word in
            felt_words((value >> (96 * felt)) & ((1 << 96) - 1))]


class CanonicalModuloTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("c++")
        if compiler is None:
            raise unittest.SkipTest("C++ compiler unavailable")
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        source = root / "oracle.cpp"
        source.write_text('''#include <cstdlib>
#include <iostream>
#define __device__
#define __forceinline__ inline
#define __noinline__
#define STWO_CUDA_DEDUCTION_INVALID() std::abort()
#include "''' + str(HEADER) + '''"
int main() {
    unsigned mode;
    while (std::cin >> mode) {
        unsigned input[448] = {}, output[32] = {};
        for (unsigned i=0; i<(mode==15 ? 336u : 448u); ++i)
            if (!(std::cin >> input[i])) return 2;
        if (mode==15) stwo_wit_deduce_add_mod_is_zero(input,output);
        else stwo_wit_deduce_mul_mod_quotient(input,output);
        for (unsigned i=0; i<(mode==15 ? 1u : 32u); ++i)
            std::cout << output[i] << ' ';
        std::cout << '\\n';
    }
}
''')
        cls.exe = root / "oracle"
        subprocess.run([compiler, "-std=c++17", "-O2", str(source), "-o", str(cls.exe)],
                       check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_cases(self, cases):
        payload = "\n".join(" ".join(map(str, [mode] +
            [w for value in values for w in u384_words(value)])) for mode, values in cases)
        result = subprocess.run([str(self.exe)], input=payload, capture_output=True,
                                text=True, timeout=15, check=True)
        return [[int(x) for x in line.split()] for line in result.stdout.splitlines()]

    def test_full_width_arithmetic_against_python_bigints(self):
        rng = random.Random(0xCA1A0)
        modulus = 1 << 384
        cases, expected = [], []
        for a, b in [(0, 0), (modulus-1, 1), (modulus-1, modulus-1)] + [
                (rng.getrandbits(384), rng.getrandbits(384)) for _ in range(100)]:
            c = (a+b) % modulus
            for target in (c, (c+1) % modulus):
                cases.append((15, [a, b, target]))
                expected.append([int((a+b-target) % modulus == 0)])
        for _ in range(100):
            # Full-width divisors ensure the quotient fits the upstream 384-bit ABI.
            p = rng.getrandbits(384) | (1 << 383)
            a, b = rng.getrandbits(384) % p, rng.getrandbits(384) % p
            c = (a*b) % p
            q = (a*b-c)//p
            cases.append((16, [p, a, b, c]))
            expected.append([(q >> (12*i)) & 4095 for i in range(32)])
        # Wrapping u768 subtraction is part of the upstream deduction contract.
        p = modulus-1
        q = ((0-1) % (1 << 768)) // p
        self.assertGreaterEqual(q, modulus)  # Must be rejected, not truncated.
        self.assertEqual(self.run_cases(cases), expected)

    def test_invalid_divisors_and_oversized_quotients_fail(self):
        for values in ([0, 1, 1, 0], [1, (1 << 384)-1, (1 << 384)-1, 0],
                       [(1 << 384)-1, 0, 0, 1]):
            payload = " ".join(map(str, [16] + [w for v in values for w in u384_words(v)]))
            result = subprocess.run([str(self.exe)], input=payload, capture_output=True,
                                    text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
