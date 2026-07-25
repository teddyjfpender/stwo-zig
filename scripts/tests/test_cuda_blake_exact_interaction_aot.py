from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.cuda_build_lib.aot_identity import source_closure_identity
from scripts.tests import test_cuda_blake_aot as oracle


ROOT = Path(__file__).resolve().parents[2]
NATIVE_AOT = ROOT / "src/backends/cuda/aot/native"
LABEL = "blake_exact_interaction"


def scheduler_batches() -> list[tuple[oracle.Q, oracle.Q]]:
    row = 1

    def round_value(round_index: int) -> oracle.Q:
        columns = list(range(32 + round_index * 32, 96 + round_index * 32))
        for message in oracle.SIGMA[round_index]:
            columns.extend((2 * message, 2 * message + 1))
        return oracle.combine(
            1,
            [oracle.base(oracle.source(0, column, row)) for column in columns],
        )

    entries = [
        (oracle.base(1), round_value(index))
        for index in range(10)
    ]
    columns = list(range(32, 64)) + list(range(352, 384)) + list(range(32))
    entries.append(
        (
            oracle.base(0),
            oracle.combine(
                0,
                [oracle.base(oracle.source(0, column, row)) for column in columns],
            ),
        )
    )
    return [
        oracle.pair(entries[index], entries[index + 1])
        for index in range(0, 10, 2)
    ] + [entries[-1]]


def round_batches(component: int, trace_log: int) -> list[tuple[oracle.Q, oracle.Q]]:
    value = oracle.Round(component, trace_log, 0)
    value.evaluate()
    return [
        oracle.pair(value.entries[index], value.entries[index + 1])
        for index in range(0, 128, 2)
    ] + [value.entries[-1]]


def xor_batches(component: int, table: int) -> list[tuple[oracle.Q, oracle.Q]]:
    row = 1
    counts = (256, 16, 16, 16, 1)
    limbs = (8, 7, 6, 5, 4)
    expands = (4, 2, 2, 2, 0)
    entries: list[tuple[oracle.Q, oracle.Q]] = []
    for column in range(counts[table]):
        ah = column >> expands[table]
        bh = column & ((1 << expands[table]) - 1)
        values = [
            oracle.base(oracle.source(component, index, row) + high)
            for index, high in enumerate(
                (
                    ah << limbs[table],
                    bh << limbs[table],
                    (ah ^ bh) << limbs[table],
                )
            )
        ]
        entries.append(
            (
                oracle.sub(
                    oracle.base(0),
                    oracle.base(oracle.source(component, 3 + column, row)),
                ),
                oracle.combine(2 + table, values),
            )
        )
    output = [
        oracle.pair(entries[index], entries[index + 1])
        for index in range(0, len(entries) - 1, 2)
    ]
    if len(entries) & 1:
        output.append(entries[-1])
    return output


class CudaBlakeExactInteractionAotTests(unittest.TestCase):
    def test_pair_kernel_matches_independent_exact_air(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        entry = next(item for item in manifest if item["label"] == LABEL)
        source = NATIVE_AOT / str(entry["file"])
        self.assertEqual(
            source_closure_identity(NATIVE_AOT, source),
            entry["program_identity"],
        )

        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            harness = root / "interaction.cpp"
            executable = root / "interaction"
            harness.write_text(self._harness(source), encoding="utf-8")
            subprocess.run(
                [compiler, "-std=c++17", "-O2", str(harness), "-o", str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                [str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
        actual = [int(word) for word in result.stdout.split()]
        expected_batches = scheduler_batches()
        expected_batches += round_batches(1, 7)
        expected_batches += round_batches(2, 5)
        for table in range(5):
            expected_batches += xor_batches(3 + table, table)
        expected = [
            coordinate
            for batch in expected_batches
            for value in batch
            for coordinate in value
        ]
        self.assertEqual(expected, actual)

    def test_public_claim_mapping_is_not_component_order(self) -> None:
        mapping = (0, 6, 7, 1, 2, 3, 4, 5)
        self.assertEqual(set(range(8)), set(mapping))
        self.assertNotEqual(tuple(range(8)), mapping)

    @staticmethod
    def _harness(source: Path) -> str:
        return f"""
#include <cstdint>
#include <iostream>
#include <vector>
#define __device__
#define __global__
#define __forceinline__ inline
#define __launch_bounds__(...)
struct Dim3 {{ unsigned x, y, z; }};
static Dim3 blockIdx{{0,0,0}}, blockDim{{128,1,1}}, threadIdx{{0,0,0}};
static unsigned __brev(unsigned value) {{
  value=((value&0x55555555u)<<1)|((value>>1)&0x55555555u);
  value=((value&0x33333333u)<<2)|((value>>2)&0x33333333u);
  value=((value&0x0f0f0f0fu)<<4)|((value>>4)&0x0f0f0f0fu);
  value=((value&0x00ff00ffu)<<8)|((value>>8)&0x00ff00ffu);
  return (value<<16)|(value>>16);
}}
#include {json.dumps(str(source))}

unsigned source_word(unsigned component, unsigned column, unsigned row) {{
  return (component * 101u + column * 17u + row * 13u + 5u) % kPrime;
}}

void print_qm31(Qm31 value) {{
  std::cout << value.a.a << ' ' << value.a.b << ' '
            << value.b.a << ' ' << value.b.b << ' ';
}}

std::vector<unsigned> relations() {{
  std::vector<unsigned> output(56u);
  for (unsigned relation = 0; relation < 7u; ++relation) {{
    for (unsigned coordinate = 0; coordinate < 4u; ++coordinate) {{
      output[(2u * relation) * 4u + coordinate] =
          relation * 31u + coordinate * 7u + 11u;
      output[(2u * relation + 1u) * 4u + coordinate] =
          relation * 37u + coordinate * 13u + 17u;
    }}
  }}
  return output;
}}

void run_component(unsigned component, unsigned columns, unsigned secure) {{
  constexpr unsigned rows = 4u;
  std::vector<unsigned> main(columns * rows);
  for (unsigned column = 0; column < columns; ++column)
    for (unsigned row = 0; row < rows; ++row)
      main[column * rows + row] = source_word(component, column, row);
  std::vector<unsigned> preprocessed(3u * rows);
  if (component >= 3u) {{
    for (unsigned column = 0; column < 3u; ++column)
      for (unsigned row = 0; row < rows; ++row)
        preprocessed[column * rows + row] =
            source_word(component, column, row);
    for (unsigned column = 0; column < columns; ++column)
      for (unsigned row = 0; row < rows; ++row)
        main[column * rows + row] =
            source_word(component, 3u + column, row);
  }}
  auto elements = relations();
  std::vector<unsigned> output(4u * secure * rows);
  std::vector<Qm31> denominators(secure * rows);
  if (component == 0u)
    generate_scheduler_fractions(
        main.data(), rows, 1u, elements.data(), output.data(),
        denominators.data());
  else if (component < 3u)
    generate_round_fractions(
        main.data(), rows, 1u, elements.data(), output.data(),
        denominators.data());
  else
    generate_xor_fractions(
        preprocessed.data(), main.data(), rows, 1u, elements.data(),
        output.data(), denominators.data(), component - 3u);
  for (unsigned batch = 0; batch < secure; ++batch) {{
    Qm31 numerator = {{
      {{output[(4u * batch) * rows + 1u],
        output[(4u * batch + 1u) * rows + 1u]}},
      {{output[(4u * batch + 2u) * rows + 1u],
        output[(4u * batch + 3u) * rows + 1u]}},
    }};
    print_qm31(numerator);
    print_qm31(denominators[batch * rows + 1u]);
  }}
}}

int main() {{
  run_component(0u, 384u, 6u);
  run_component(1u, 384u, 65u);
  run_component(2u, 384u, 65u);
  run_component(3u, 256u, 128u);
  run_component(4u, 16u, 8u);
  run_component(5u, 16u, 8u);
  run_component(6u, 16u, 8u);
  run_component(7u, 1u, 1u);
}}
"""


if __name__ == "__main__":
    unittest.main()
