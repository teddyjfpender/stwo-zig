from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
NATIVE_AOT = ROOT / "src/backends/cuda/aot/native"
P = 2_147_483_647
Q = tuple[int, int, int, int]
F = tuple[Q, Q]
SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)


def add(x: Q, y: Q) -> Q:
    return tuple((a + b) % P for a, b in zip(x, y))  # type: ignore[return-value]


def sub(x: Q, y: Q) -> Q:
    return tuple((a - b) % P for a, b in zip(x, y))  # type: ignore[return-value]


def cmul(x: tuple[int, int], y: tuple[int, int]) -> tuple[int, int]:
    return ((x[0] * y[0] - x[1] * y[1]) % P,
            (x[0] * y[1] + x[1] * y[0]) % P)


def mul(x: Q, y: Q) -> Q:
    v0, v1 = cmul(x[:2], y[:2]), cmul(x[2:], y[2:])
    v2 = cmul(((x[0] + x[2]) % P, (x[1] + x[3]) % P),
              ((y[0] + y[2]) % P, (y[1] + y[3]) % P))
    ext = ((2 * v1[0] - v1[1]) % P, (v1[0] + 2 * v1[1]) % P)
    return ((v0[0] + ext[0]) % P, (v0[1] + ext[1]) % P,
            (v2[0] - v0[0] - v1[0]) % P,
            (v2[1] - v0[1] - v1[1]) % P)


def base(value: int) -> Q:
    return (value % P, 0, 0, 0)


def mul_base(value: Q, scalar: int) -> Q:
    return tuple((item * scalar) % P for item in value)  # type: ignore[return-value]


def source(component: int, column: int, row: int) -> int:
    return (component * 101 + column * 17 + row * 13 + 5) % P


def power(index: int) -> Q:
    return tuple((index * 19 + c * 23 + 7) % P for c in range(4))  # type: ignore[return-value]


def relation(index: int) -> tuple[Q, Q]:
    return (
        tuple((index * 31 + c * 7 + 11) % P for c in range(4)),
        tuple((index * 37 + c * 13 + 17) % P for c in range(4)),
    )  # type: ignore[return-value]


def claim(index: int) -> Q:
    return tuple((index * 41 + c * 17 + 19) % P for c in range(4))  # type: ignore[return-value]


def combine(relation_index: int, values: list[Q]) -> Q:
    z, alpha = relation(relation_index)
    result, alpha_power = sub(base(0), z), base(1)
    for value in values:
        result = add(result, mul(alpha_power, value))
        alpha_power = mul(alpha_power, alpha)
    return result


def pair(first: tuple[Q, Q], second: tuple[Q, Q]) -> tuple[Q, Q]:
    return (add(mul(first[0], second[1]), mul(second[0], first[1])),
            mul(first[1], second[1]))


def logup(
    batches: list[tuple[Q, Q]],
    currents: list[Q],
    previous_last: Q,
    claimed: Q,
    trace_log: int,
) -> list[Q]:
    output, previous = [], base(0)
    for index, (numerator, denominator) in enumerate(batches):
        difference = sub(currents[index], previous)
        if index + 1 == len(batches):
            difference = add(sub(difference, previous_last),
                             mul_base(claimed, 1 << (31 - trace_log)))
        output.append(sub(mul(difference, denominator), numerator))
        previous = currents[index]
    return output


def weighted(constraints: list[Q], power_start: int) -> Q:
    result = base(0)
    for index, constraint in enumerate(constraints):
        result = add(result, mul(
            power(power_start + len(constraints) - 1 - index),
            constraint,
        ))
    return result


def scheduler(previous: int = 2) -> Q:
    row = 1
    def round_value(round_index: int) -> Q:
        columns = list(range(32 + round_index * 32, 96 + round_index * 32))
        for message in SIGMA[round_index]:
            columns.extend((2 * message, 2 * message + 1))
        return combine(1, [base(source(0, col, row)) for col in columns])
    entries = [(base(1), round_value(index)) for index in range(10)]
    blake_columns = list(range(32, 64)) + list(range(352, 384)) + list(range(32))
    entries.append((base(0), combine(
        0, [base(source(0, col, row)) for col in blake_columns])))
    batches = [pair(entries[i], entries[i + 1]) for i in range(0, 10, 2)]
    batches.append(entries[-1])
    currents = [tuple(source(0, 384 + 4 * i + c, row)
                      for c in range(4)) for i in range(6)]
    previous_last = tuple(source(0, 404 + c, previous) for c in range(4))
    return weighted(logup(batches, currents, previous_last, claim(0), 4), 411)


class Round:
    def __init__(
        self,
        component: int,
        trace_log: int,
        power_start: int,
        previous: int = 2,
    ):
        self.component, self.trace_log = component, trace_log
        self.power_start, self.row, self.previous = power_start, 1, previous
        self.column, self.constraints = 0, []
        self.entries: list[tuple[Q, Q]] = []

    def next(self) -> Q:
        result = base(source(self.component, self.column, self.row))
        self.column += 1
        return result

    def word(self) -> F:
        return self.next(), self.next()

    def add2(self, x: F, y: F) -> F:
        low, high = self.next(), self.next()
        c0 = mul_base(sub(add(x[0], y[0]), low), 1 << 15)
        c1 = mul_base(sub(add(add(x[1], y[1]), c0), high), 1 << 15)
        self.constraints.extend((mul(c0, sub(c0, base(1))),
                                 mul(c1, sub(c1, base(1)))))
        return low, high

    def add3(self, x: F, y: F, z: F) -> F:
        low, high = self.next(), self.next()
        c0 = mul_base(sub(add(add(x[0], y[0]), z[0]), low), 1 << 15)
        c1 = mul_base(sub(add(add(add(x[1], y[1]), z[1]), c0), high), 1 << 15)
        self.constraints.extend((
            mul(mul(c0, sub(c0, base(1))), sub(c0, base(2))),
            mul(mul(c1, sub(c1, base(1))), sub(c1, base(2))),
        ))
        return low, high

    def split(self, value: Q, width: int) -> tuple[Q, Q]:
        high = self.next()
        return sub(value, mul_base(high, 1 << width)), high

    def xor2(self, width: int, a: tuple[Q, Q], b: tuple[Q, Q]) -> tuple[Q, Q]:
        result = self.next(), self.next()
        relation_index = {12: 2, 9: 3, 8: 4, 7: 5, 4: 6}[width]
        for index in range(2):
            self.entries.append((base(1), combine(
                relation_index, [a[index], b[index], result[index]])))
        return result

    def rotate(self, x: F, y: F, width: int) -> F:
        al, ah = self.split(x[0], width), self.split(x[1], width)
        bl, bh = self.split(y[0], width), self.split(y[1], width)
        low = self.xor2(width, (al[0], ah[0]), (bl[0], bh[0]))
        high_width = 16 - width
        high = self.xor2(high_width, (al[1], ah[1]), (bl[1], bh[1]))
        factor = 1 << high_width
        return add(mul_base(low[1], factor), high[0]), \
            add(mul_base(low[0], factor), high[1])

    def rotate16(self, x: F, y: F) -> F:
        al, ah = self.split(x[0], 8), self.split(x[1], 8)
        bl, bh = self.split(y[0], 8), self.split(y[1], 8)
        low = self.xor2(8, (al[0], ah[0]), (bl[0], bh[0]))
        high = self.xor2(8, (al[1], ah[1]), (bl[1], bh[1]))
        return add(mul_base(high[1], 256), low[1]), \
            add(mul_base(high[0], 256), low[0])

    def g(self, state: list[F], indices: tuple[int, int, int, int], m0: F, m1: F) -> None:
        a, b, c, d = indices
        state[a] = self.add3(state[a], state[b], m0)
        state[d] = self.rotate16(state[a], state[d])
        state[c] = self.add2(state[c], state[d])
        state[b] = self.rotate(state[b], state[c], 12)
        state[a] = self.add3(state[a], state[b], m1)
        state[d] = self.rotate(state[a], state[d], 8)
        state[c] = self.add2(state[c], state[d])
        state[b] = self.rotate(state[b], state[c], 7)

    def evaluate(self) -> Q:
        state = [self.word() for _ in range(16)]
        initial = state.copy()
        message = [self.word() for _ in range(16)]
        for indices, pair_indices in zip(
            ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
             (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)),
            ((0, 1), (2, 3), (4, 5), (6, 7), (8, 9), (10, 11), (12, 13), (14, 15)),
        ):
            self.g(state, indices, message[pair_indices[0]], message[pair_indices[1]])
        tuple_values = [value for word in initial + state + message for value in word]
        self.entries.append((sub(base(0), base(1)), combine(1, tuple_values)))
        batches = [pair(self.entries[i], self.entries[i + 1])
                   for i in range(0, 128, 2)] + [self.entries[-1]]
        currents = [tuple(source(self.component, 384 + 4 * i + c, self.row)
                          for c in range(4)) for i in range(65)]
        previous_last = tuple(source(self.component, 640 + c, self.previous)
                              for c in range(4))
        claim_index = 6 if self.component == 1 else 7
        self.constraints.extend(logup(
            batches, currents, previous_last, claim(claim_index), self.trace_log))
        self.assert_shape()
        return weighted(self.constraints, self.power_start)

    def assert_shape(self) -> None:
        assert self.column == 384 and len(self.entries) == 129
        assert len(self.constraints) == 129


def xor_component(component: int, table: int, previous: int = 2) -> Q:
    row = 1
    counts, secure = (256, 16, 16, 16, 1), (128, 8, 8, 8, 1)
    limbs, expands = (8, 7, 6, 5, 4), (4, 2, 2, 2, 0)
    starts, logs = (25, 17, 9, 1, 0), (16, 14, 12, 10, 8)
    entries = []
    for column in range(counts[table]):
        ah, bh = column >> expands[table], column & ((1 << expands[table]) - 1)
        values = [
            base(source(component, index, row) + high)
            for index, high in enumerate((
                ah << limbs[table], bh << limbs[table],
                (ah ^ bh) << limbs[table],
            ))
        ]
        entries.append((
            sub(base(0), base(source(component, 3 + column, row))),
            combine(2 + table, values),
        ))
    batches = [pair(entries[i], entries[i + 1])
               for i in range(0, len(entries) - 1, 2)]
    if len(entries) & 1:
        batches.append(entries[-1])
    interaction = 3 + counts[table]
    currents = [tuple(source(component, interaction + 4 * i + c, row)
                      for c in range(4)) for i in range(secure[table])]
    previous_last = tuple(
        source(component, interaction + 4 * (secure[table] - 1) + c, previous)
        for c in range(4)
    )
    constraints = logup(
        batches, currents, previous_last, claim(1 + table), logs[table])
    return weighted(constraints, starts[table])


def previous_storage(row: int, evaluation_log: int) -> int:
    def reverse(value: int, bits: int) -> int:
        return int(f"{value:0{bits}b}"[::-1], 2)

    half = 1 << (evaluation_log - 1)
    natural = reverse(row, evaluation_log)
    if natural < half:
        natural = half - 1 if natural == 0 else natural - 1
    else:
        offset = natural - half
        natural = half + (0 if offset + 1 == half else offset + 1)
    return reverse(natural, evaluation_log)


class CudaBlakeAotTests(unittest.TestCase):
    def test_aot_matches_independent_exact_mixed_height_air(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        manifest = json.loads((NATIVE_AOT / "aot_manifest.json").read_text())
        entry = next(item for item in manifest if item["label"] == "blake")
        path = NATIVE_AOT / entry["file"]
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         entry["program_identity"])
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            source_path = Path(temporary) / "blake.cpp"
            executable = Path(temporary) / "blake"
            source_path.write_text(self._harness(path), encoding="utf-8")
            subprocess.run([compiler, "-std=c++17", "-O2", str(source_path),
                            "-o", str(executable)], check=True, capture_output=True)
            result = subprocess.run([str(executable)], check=True,
                                    capture_output=True, text=True)
        actual = [int(value) for value in result.stdout.split()]
        expected = [scheduler(), Round(1, 7, 282).evaluate(),
                    Round(2, 5, 153).evaluate()]
        expected.extend(xor_component(3 + table, table) for table in range(5))
        flattened = [item for value in expected for item in value]
        lifted = [0] * (4 * 32)
        lift_value = (101, 103, 107, 109)
        for repeat in range(4):
            target = 2 * ((3 >> 1) * 4 + repeat) + (3 & 1)
            for coordinate in range(4):
                lifted[coordinate * 32 + target] = lift_value[coordinate]
        exported = [
            mul_base(scheduler(previous_storage(1, 5)), 3),
            mul_base(
                Round(1, 7, 282, previous_storage(1, 8)).evaluate(),
                3,
            ),
            mul_base(
                Round(2, 5, 153, previous_storage(1, 6)).evaluate(),
                3,
            ),
            mul_base(
                xor_component(7, 4, previous_storage(1, 9)),
                3,
            ),
        ]
        flattened.extend(item for value in exported for item in value)
        self.assertEqual(flattened + lifted, actual)

    def test_differential_is_sensitive_to_structural_bindings(self) -> None:
        round_component = Round(1, 7, 282)
        exact_round = round_component.evaluate()
        self.assertNotEqual(
            exact_round,
            weighted(round_component.constraints, 283),
            "power interval boundary mutation was invisible",
        )
        original_relation = relation
        exact_scheduler = scheduler()
        with mock.patch(
            f"{__name__}.relation",
            side_effect=lambda index: original_relation((index + 1) % 7),
        ):
            mutated_relation = scheduler()
        self.assertNotEqual(exact_scheduler, mutated_relation)
        original_claim = claim
        with mock.patch(
            f"{__name__}.claim",
            side_effect=lambda index: original_claim((index + 1) % 8),
        ):
            mutated_claim = xor_component(7, 4)
        self.assertNotEqual(xor_component(7, 4), mutated_claim)
        exact_round_claim = Round(1, 7, 282).evaluate()
        with mock.patch(
            f"{__name__}.claim",
            side_effect=lambda index: original_claim(1 if index == 6 else index),
        ):
            component_order_round = Round(1, 7, 282).evaluate()
        self.assertNotEqual(exact_round_claim, component_order_round)
        exact_xor_claim = xor_component(3, 0)
        with mock.patch(
            f"{__name__}.claim",
            side_effect=lambda index: original_claim(3 if index == 1 else index),
        ):
            component_order_xor = xor_component(3, 0)
        self.assertNotEqual(exact_xor_claim, component_order_xor)
        exact_targets = [
            2 * ((3 >> 1) * 4 + repeat) + (3 & 1)
            for repeat in range(4)
        ]
        wrong_targets = [
            ((3 << 2) + repeat) % 32
            for repeat in range(4)
        ]
        self.assertNotEqual(exact_targets, wrong_targets)

    @staticmethod
    def _harness(source_path: Path) -> str:
        return f"""
#include <algorithm>
#include <iostream>
#include <vector>
#define __device__
#define __global__
#define __forceinline__ inline
#define __launch_bounds__(...)
struct Dim3 {{ unsigned x, y, z; }};
static Dim3 blockIdx{{0,0,0}}, blockDim{{64,1,1}}, threadIdx{{0,0,0}};
static unsigned __brev(unsigned v) {{
  v=((v&0x55555555u)<<1)|((v>>1)&0x55555555u);
  v=((v&0x33333333u)<<2)|((v>>2)&0x33333333u);
  v=((v&0x0f0f0f0fu)<<4)|((v>>4)&0x0f0f0f0fu);
  v=((v&0x00ff00ffu)<<8)|((v>>8)&0x00ff00ffu);
  return (v<<16)|(v>>16);
}}
#include {json.dumps(str(source_path))}
unsigned value(unsigned component, unsigned column, unsigned row) {{
  return (component*101u+column*17u+row*13u+5u)%kPrime;
}}
std::vector<unsigned> sources(unsigned component, unsigned columns) {{
  std::vector<unsigned> out(columns*4u);
  for(unsigned c=0;c<columns;++c) for(unsigned r=0;r<4;++r)
    out[c*4u+r]=value(component,c,r);
  return out;
}}
std::vector<unsigned> sources_at_stride(
    unsigned component, unsigned columns, unsigned stride) {{
  std::vector<unsigned> out(static_cast<std::size_t>(columns)*stride);
  for(unsigned c=0;c<columns;++c) for(unsigned r=0;r<stride;++r)
    out[static_cast<std::size_t>(c)*stride+r]=value(component,c,r);
  return out;
}}
void print(Qm31 x) {{
  std::cout<<x.a.a<<' '<<x.a.b<<' '<<x.b.a<<' '<<x.b.b<<' ';
}}
int main() {{
  std::vector<unsigned> powers(4u*417u), relations(4u*14u), claims(4u*8u);
  for(unsigned i=0;i<417;++i) for(unsigned c=0;c<4;++c)
    powers[4*i+c]=(i*19u+c*23u+7u)%kPrime;
  for(unsigned i=0;i<7;++i) for(unsigned c=0;c<4;++c) {{
    relations[8*i+c]=(i*31u+c*7u+11u)%kPrime;
    relations[8*i+4+c]=(i*37u+c*13u+17u)%kPrime;
  }}
  for(unsigned i=0;i<8;++i) for(unsigned c=0;c<4;++c)
    claims[4*i+c]=(i*41u+c*17u+19u)%kPrime;
  auto s=sources(0,408);
  print(evaluate_scheduler(s.data(),4,1,2,powers.data(),relations.data(),
                           claims.data(),1u<<27));
  s=sources(1,644);
  print(evaluate_round(s.data(),4,1,2,powers.data(),282,relations.data(),
                       claims.data(),6,1u<<24));
  s=sources(2,644);
  print(evaluate_round(s.data(),4,1,2,powers.data(),153,relations.data(),
                       claims.data(),7,1u<<26));
  const unsigned columns[5]={{771,51,51,51,8}};
  const unsigned inverses[5]={{1u<<15,1u<<17,1u<<19,1u<<21,1u<<23}};
  for(unsigned table=0;table<5;++table) {{
    s=sources(3+table,columns[table]);
    print(evaluate_xor(s.data(),4,1,2,powers.data(),relations.data(),
                       claims.data(),table,inverses[table]));
  }}
  constexpr unsigned maximum_stride=1u<<17;
  std::vector<unsigned> coordinates(4u*maximum_stride);
  unsigned denominators[2]={{3u,5u}};
  threadIdx={{1,0,0}};
  s=sources_at_stride(0,408,1u<<5);
  stwo_native_constraint_blake_component_v1_64a336ee32f09d7e(
      s.data(),s.size(),1u<<5,powers.data(),powers.size(),
      denominators,2,relations.data(),relations.size(),
      claims.data(),claims.size(),coordinates.data(),coordinates.size(),
      maximum_stride,1u<<5,4,5,17,0,1);
  for(unsigned c=0;c<4;++c) std::cout<<coordinates[c*maximum_stride+1]<<' ';
  std::fill(coordinates.begin(),coordinates.end(),0u);
  s=sources_at_stride(1,644,1u<<8);
  stwo_native_constraint_blake_component_v1_64a336ee32f09d7e(
      s.data(),s.size(),1u<<8,powers.data(),powers.size(),
      denominators,2,relations.data(),relations.size(),
      claims.data(),claims.size(),coordinates.data(),coordinates.size(),
      maximum_stride,1u<<8,7,8,17,1,0);
  for(unsigned c=0;c<4;++c) std::cout<<coordinates[c*maximum_stride+1]<<' ';
  std::fill(coordinates.begin(),coordinates.end(),0u);
  s=sources_at_stride(2,644,1u<<6);
  stwo_native_constraint_blake_component_v1_64a336ee32f09d7e(
      s.data(),s.size(),1u<<6,powers.data(),powers.size(),
      denominators,2,relations.data(),relations.size(),
      claims.data(),claims.size(),coordinates.data(),coordinates.size(),
      maximum_stride,1u<<6,5,6,17,2,0);
  for(unsigned c=0;c<4;++c) std::cout<<coordinates[c*maximum_stride+1]<<' ';
  std::fill(coordinates.begin(),coordinates.end(),0u);
  s=sources_at_stride(7,8,1u<<9);
  stwo_native_constraint_blake_component_v1_64a336ee32f09d7e(
      s.data(),s.size(),1u<<9,powers.data(),powers.size(),
      denominators,2,relations.data(),relations.size(),
      claims.data(),claims.size(),coordinates.data(),coordinates.size(),
      maximum_stride,1u<<9,8,9,17,7,0);
  for(unsigned c=0;c<4;++c) std::cout<<coordinates[c*maximum_stride+1]<<' ';
  unsigned lifted[4u*32u]={{}};
  Qm31 lift_value={{{{101u,103u}},{{107u,109u}}}};
  store_lifted(lifted,32,3,3,5,lift_value,true);
  for(unsigned i=0;i<4u*32u;++i) std::cout<<lifted[i]<<' ';
}}
"""


if __name__ == "__main__":
    unittest.main()
