// Host arithmetic differential for the actual CUDA row body. This does not
// qualify CUDA code generation, register pressure, or device performance.
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

#define __host__
#define __device__
#define __global__
#define __forceinline__ inline
#include "../../../backends/cuda/native/oods/field.cuh"

using uint = std::uint32_t;
using ulong = unsigned long;
namespace field = stwo::cuda::oods;
struct RiscvQm31 { uint a, b, c, d; };
struct Position { uint x = 0; };
static Position blockIdx, threadIdx;
static Position blockDim{1};
static uint inversions = 0;
static field::QM31 convert(RiscvQm31 q) { return {{q.a, q.b}, {q.c, q.d}}; }
static RiscvQm31 convert(field::QM31 q) { return {q.a.a, q.a.b, q.b.a, q.b.b}; }
static RiscvQm31 riscv_qm_mul(RiscvQm31 a, RiscvQm31 b) { return convert(field::mul(convert(a), convert(b))); }
static RiscvQm31 riscv_qm_add(RiscvQm31 a, RiscvQm31 b) { return convert(field::add(convert(a), convert(b))); }
static RiscvQm31 riscv_qm_sub(RiscvQm31 a, RiscvQm31 b) { return convert(field::sub(convert(a), convert(b))); }
static RiscvQm31 framework_inverse(RiscvQm31 a) { ++inversions; return convert(field::inverse(convert(a))); }
static RiscvQm31 framework_load(const uint* p, uint rows, uint column, uint row) {
    return {p[ulong(4 * column) * rows + row], p[ulong(4 * column + 1) * rows + row],
            p[ulong(4 * column + 2) * rows + row], p[ulong(4 * column + 3) * rows + row]};
}
static void framework_store(uint* p, uint rows, uint column, uint row, RiscvQm31 q) {
    p[ulong(4 * column) * rows + row] = q.a; p[ulong(4 * column + 1) * rows + row] = q.b;
    p[ulong(4 * column + 2) * rows + row] = q.c; p[ulong(4 * column + 3) * rows + row] = q.d;
}
static void atomicOr(uint* p, uint value) { *p |= value; }
#include "../resident_native_access_interaction_v1.cuh"

static std::uint64_t state = 0x83e744b2c6195d01ull;
static uint random_word() {
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    return uint(state % field::kPrime);
}
static constexpr uint sentinel = 0xf7efdead;
static uint cases = 0;
static void run(uint rows, int bad_denominator = -1, int bad_limb = -1,
                bool inactive = false, int bad_active = -1, bool zero = false) {
    std::vector<uint> input(72 * rows);
    for (auto& word : input) word = random_word();
    for (uint row = 0; row < rows; ++row) {
        for (uint i = 0; i < 17; ++i) {
            // Exercise base/subfield elements and p-1, not just random QM31.
            if ((row + i) % 5 == 0) framework_store(input.data(), rows, i, row, {field::kPrime - 1, 0, 0, 0});
            if (bad_denominator == int(i)) {
                auto q = framework_load(input.data(), rows, i, row);
                if (zero) q = {0, 0, 0, 0};
                else {
                    std::array<uint, 4> limbs{q.a, q.b, q.c, q.d};
                    limbs.at(bad_limb) = (row & 1) ? 0xffffffffu : field::kPrime;
                    q = {limbs[0], limbs[1], limbs[2], limbs[3]};
                }
                framework_store(input.data(), rows, i, row, q);
            }
        }
        RiscvQm31 active{inactive ? 0u : 1u, 0, 0, 0};
        if (bad_active == 0) active.a = 2;
        if (bad_active > 0) {
            std::array<uint, 4> limbs{active.a, 0, 0, 0}; limbs.at(bad_active) = 1;
            active = {limbs[0], limbs[1], limbs[2], limbs[3]};
        }
        framework_store(input.data(), rows, 17, row, active);
    }
    const auto original = input;
    const ulong stride = 4ul * rows + 4;
    std::vector<uint> actual(10 * stride + 2, sentinel), expected = actual;
    std::vector<uint> terms(12 * rows + 2, sentinel), expected_terms = terms;
    uint status = 0x100, expected_status = status;
    inversions = 0;
    for (uint row = 0; row < rows; ++row) {
        // Independent scalar implementation of the previous exact algorithm.
        auto active = framework_load(input.data(), rows, 17, row);
        uint error = active.a > 1 || active.b || active.c || active.d ? 1 : 0;
        std::array<RiscvQm31, 17> inv{};
        for (uint i = 0; !error && i < 17; ++i) {
            auto d = framework_load(input.data(), rows, i, row);
            if (d.a >= field::kPrime || d.b >= field::kPrime || d.c >= field::kPrime || d.d >= field::kPrime) error = 2;
            else if (active.a && !(d.a | d.b | d.c | d.d)) error = 4;
            else if (active.a) inv[i] = convert(field::inverse(convert(d)));
        }
        expected_status |= error;
        if (!error) {
            for (uint i = 0; i < 3; ++i) framework_store(expected_terms.data() + 1, rows, i, row, inv[i]);
            framework_store(expected.data() + 1, rows, 0, row, inv[0]);
            framework_store(expected.data() + 1 + stride, rows, 0, row, active);
            for (uint i = 0; i < 7; ++i) framework_store(expected.data() + 1 + (2 + i) * stride, rows, 0, row, riscv_qm_add(inv[3 + 2 * i], inv[4 + 2 * i]));
            framework_store(expected.data() + 1 + 9 * stride, rows, 0, row, riscv_qm_sub(inv[1], inv[2]));
        }
        threadIdx.x = row;
        native_access_fraction_rows(input.data(), actual.data() + 1, terms.data() + 1, &status, rows);
    }
    assert(input == original);
    assert(actual == expected && terms == expected_terms && status == expected_status);
    const uint expected_inversions = expected_status == 0x100 && !inactive ? rows : 0;
    assert(inversions == expected_inversions);
    // Launch tails must not touch status, input, output, or perform inversions.
    threadIdx.x = rows;
    native_access_fraction_rows(input.data(), actual.data() + 1, terms.data() + 1, &status, rows);
    assert(actual == expected && terms == expected_terms && status == expected_status);
    assert(inversions == expected_inversions);
    ++cases;
}

int main() {
    for (uint rows : {2u, 4u, 8u, 32u, 256u}) {
        for (uint repeat = 0; repeat < 8; ++repeat) { run(rows); run(rows, -1, -1, true); }
        for (int i = 0; i < 17; ++i) {
            run(rows, i, -1, false, -1, true);
            run(rows, i, -1, true, -1, true);
            for (int limb = 0; limb < 4; ++limb) {
                run(rows, i, limb); run(rows, i, limb, true);
            }
        }
        for (int limb = 0; limb < 4; ++limb) run(rows, -1, -1, false, limb);
    }
    std::printf("PASS %u access fraction cases; exact scalar parity, 17->1 inversions, inactive/hostile/tail checks\n", cases);
}
