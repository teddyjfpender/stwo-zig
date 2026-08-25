// Capture-safe native witness writer for Cairo's ec_op_builtin.
//
// One thread owns one EC-op instance, but keeps the 252-round dependency chain
// projective. A second, round-major grid normalizes the saved states in tiles
// and emits the exact affine columns consumed by partial_ec_mul_generic. The
// temporary projective words reuse dead columns in that final 127-column slab;
// there is no separate scratch allocation or ABI.

#include <cuda_runtime.h>
#include <cstddef>
#include <cstdint>

#include "ec_ops.cuh"

namespace {

// Production traces showed the old 64-thread launch taking the same ~84 ms at
// 8, 16, and 32 blocks: the serial affine-inversion chain, not row throughput,
// set latency. Projective arithmetic removes that chain; 16-row half-warps
// retain contiguous 64-byte column accesses while exposing 32/64/128 blocks
// for the measured 512/1024/2048-row shapes (twice the 32-thread frontier).
constexpr uint32_t EC_OP_CHAIN_BLOCK = 16;
constexpr uint32_t EC_OP_NORMALIZE_BLOCK = 64;
constexpr uint32_t EC_OP_PADDING_BLOCK = 64;
constexpr uint32_t EC_OP_REGISTER_CEILING_THREADS = 64;
// SM90 ptxas sweep: tile 1 = 78 registers, tile 2 = 120, tile 4 = 156; all
// use the same 176-byte intentional stack frame and have zero spills. Tile 4
// leaves at least 12 resident warps/SM at 64 threads/block while cutting the
// normalization inversions per row from 252 to 63.
constexpr uint32_t EC_OP_NORMALIZE_ROUND_TILE = 4;
constexpr uint32_t EC_OP_TRACE_COLUMNS = 273;
constexpr uint32_t PARTIAL_INPUT_COLUMNS = 127;
constexpr uint32_t PARTIAL_ROUNDS = 252;
constexpr uint32_t PARTIAL_PADDED_ROUNDS = 256;
constexpr uint32_t FELT_LIMBS = 28;
constexpr uint32_t W27_WORDS = 10;

constexpr uint32_t SCRATCH_Q_X = 12;
constexpr uint32_t SCRATCH_Q_Y = 20;
constexpr uint32_t SCRATCH_Q_Z = 28;
constexpr uint32_t SCRATCH_ACC_X = 36;
constexpr uint32_t SCRATCH_ACC_Y = 44;
constexpr uint32_t SCRATCH_ACC_Z = 52;

static_assert(PARTIAL_ROUNDS % EC_OP_NORMALIZE_ROUND_TILE == 0);
static_assert(SCRATCH_Q_X == 12);
static_assert(SCRATCH_Q_Y == SCRATCH_Q_X + 8);
static_assert(SCRATCH_Q_Z == SCRATCH_Q_Y + 8);
static_assert(SCRATCH_ACC_X == SCRATCH_Q_Z + 8);
static_assert(SCRATCH_ACC_Y == SCRATCH_ACC_X + 8);
static_assert(SCRATCH_ACC_Z == SCRATCH_ACC_Y + 8);
static_assert(SCRATCH_ACC_Z + 8 == 60);
static_assert(60 <= 68, "scratch must end before accumulator output");

constexpr uint32_t MEMORY_ADDRESS_RELATION = 1444891767u;
constexpr uint32_t MEMORY_BIG_RELATION = 1662111297u;
constexpr uint32_t RANGE_CHECK_8_RELATION = 1420243005u;
constexpr uint32_t PARTIAL_EC_MUL_RELATION = 183619546u;

struct EcOpTraceColumns {
    uint32_t *columns[EC_OP_TRACE_COLUMNS];
};

struct PartialInputColumns {
    uint32_t *columns[PARTIAL_INPUT_COLUMNS];
};

__device__ __forceinline__ bool felt_equal(const felt252 &a, const felt252 &b) {
    for (uint32_t limb = 0; limb < 8; ++limb) {
        if (a.limbs[limb] != b.limbs[limb]) {
            return false;
        }
    }
    return true;
}

__device__ __forceinline__ bool felt_is_zero(const felt252 &value) {
    felt252 zero = {};
    return felt_equal(value, zero);
}

// The host writer rejects an EC-op whose accepted affine chain reaches
// infinity. Preserve that fail-closed boundary instead of feeding Z=0 to a
// batch inverse and silently manufacturing a witness.
__device__ __forceinline__ void require_finite(const ProjectivePointCuda &point) {
    if (felt_is_zero(point.Z)) {
        asm volatile("trap;");
    }
}

// Homogeneous projective coordinates use x = X/Z and y = Y/Z. This is the
// alpha=1 dbl-2007-bl formula, kept in Montgomery form throughout the chain.
__device__ __forceinline__ void ec_double_projective_exact(
    const ProjectivePointCuda &point, ProjectivePointCuda &result) {
    const felt252 xx = felt_mul(point.X, point.X);
    const felt252 zz = felt_mul(point.Z, point.Z);
    felt252 w = felt_add(felt_add(xx, xx), xx);
    w = felt_add(w, zz);

    const felt252 yz = felt_mul(point.Y, point.Z);
    const felt252 s = felt_add(yz, yz);
    const felt252 ss = felt_mul(s, s);
    const felt252 sss = felt_mul(s, ss);
    const felt252 r = felt_mul(point.Y, s);
    const felt252 rr = felt_mul(r, r);
    felt252 b = felt_mul(felt_add(point.X, r), felt_add(point.X, r));
    b = felt_sub(felt_sub(b, xx), rr);
    const felt252 h = felt_sub(felt_mul(w, w), felt_add(b, b));

    result.X = felt_mul(h, s);
    result.Y = felt_sub(felt_mul(w, felt_sub(b, h)), felt_add(rr, rr));
    result.Z = sss;
    require_finite(result);
}

// Complete for every finite result accepted by the host writer. Equal points
// take the exact doubling path; opposite-y equal-x inputs trap as infinity.
__device__ __forceinline__ void ec_add_projective_exact(
    const ProjectivePointCuda &left,
    const ProjectivePointCuda &right,
    ProjectivePointCuda &result) {
    const felt252 x1z2 = felt_mul(left.X, right.Z);
    const felt252 x2z1 = felt_mul(right.X, left.Z);
    const felt252 y1z2 = felt_mul(left.Y, right.Z);
    const felt252 y2z1 = felt_mul(right.Y, left.Z);
    const felt252 v = felt_sub(x2z1, x1z2);
    const felt252 u = felt_sub(y2z1, y1z2);
    if (felt_is_zero(v)) {
        if (felt_is_zero(u)) {
            ec_double_projective_exact(left, result);
            return;
        }
        asm volatile("trap;");
    }

    const felt252 uu = felt_mul(u, u);
    const felt252 vv = felt_mul(v, v);
    const felt252 vvv = felt_mul(v, vv);
    const felt252 z1z2 = felt_mul(left.Z, right.Z);
    const felt252 r = felt_mul(felt_mul(vv, left.X), right.Z);
    const felt252 a = felt_sub(
        felt_sub(felt_mul(uu, z1z2), vvv), felt_add(r, r));

    result.X = felt_mul(v, a);
    result.Y = felt_sub(
        felt_mul(u, felt_sub(r, a)),
        felt_mul(felt_mul(vvv, left.Y), right.Z));
    result.Z = felt_mul(vvv, z1z2);
    require_finite(result);
}

__device__ __forceinline__ AffinePointCuda projective_to_affine_with_inverse(
    const ProjectivePointCuda &point, const felt252 &z_inverse) {
    AffinePointCuda result;
    result.x = felt_from_mont(felt_mul(point.X, z_inverse));
    result.y = felt_from_mont(felt_mul(point.Y, z_inverse));
    return result;
}

__device__ __forceinline__ void projective_pair_to_affine(
    const ProjectivePointCuda &first,
    const ProjectivePointCuda &second,
    AffinePointCuda &first_affine,
    AffinePointCuda &second_affine) {
    require_finite(first);
    require_finite(second);
    const felt252 inverse_product = felt_inverse(felt_mul(first.Z, second.Z));
    first_affine = projective_to_affine_with_inverse(
        first, felt_mul(inverse_product, second.Z));
    second_affine = projective_to_affine_with_inverse(
        second, felt_mul(inverse_product, first.Z));
}

__device__ __forceinline__ bool load_memory_value(
    const uint32_t *const *tables,
    uint32_t n_big,
    uint32_t n_small,
    uint32_t id,
    uint32_t *limbs) {
    uint32_t tag = id >> 30;
    uint32_t index = id & 0x3fffffffu;
    if (tag == 1u) {
        if (index >= n_big) {
            return false;
        }
        for (uint32_t limb = 0; limb < FELT_LIMBS; ++limb) {
            limbs[limb] = tables[1u + limb][index];
        }
        return true;
    }
    if (tag == 0u && index < n_small) {
        for (uint32_t limb = 0; limb < 8; ++limb) {
            limbs[limb] = tables[29u + limb][index];
        }
        for (uint32_t limb = 8; limb < FELT_LIMBS; ++limb) {
            limbs[limb] = 0;
        }
        return true;
    }
    return false;
}

__device__ __forceinline__ void store_trace_limbs(
    EcOpTraceColumns trace,
    uint32_t first_column,
    uint32_t row,
    const uint32_t *limbs) {
    for (uint32_t limb = 0; limb < FELT_LIMBS; ++limb) {
        trace.columns[first_column + limb][row] = limbs[limb];
    }
}

__device__ __forceinline__ void store_lookup_word(
    uint32_t *lookup,
    uint32_t rows,
    uint32_t row,
    uint32_t word,
    uint32_t value) {
    lookup[static_cast<size_t>(word) * rows + row] = value;
}

__device__ __forceinline__ void store_memory_address_lookup(
    uint32_t *lookup,
    uint32_t rows,
    uint32_t row,
    uint32_t word,
    uint32_t address,
    uint32_t id) {
    store_lookup_word(lookup, rows, row, word, MEMORY_ADDRESS_RELATION);
    store_lookup_word(lookup, rows, row, word + 1u, address);
    store_lookup_word(lookup, rows, row, word + 2u, id);
}

__device__ __forceinline__ void store_memory_big_lookup(
    uint32_t *lookup,
    uint32_t rows,
    uint32_t row,
    uint32_t word,
    uint32_t id,
    const uint32_t *limbs) {
    store_lookup_word(lookup, rows, row, word, MEMORY_BIG_RELATION);
    store_lookup_word(lookup, rows, row, word + 1u, id);
    for (uint32_t limb = 0; limb < FELT_LIMBS; ++limb) {
        store_lookup_word(lookup, rows, row, word + 2u + limb, limbs[limb]);
    }
}

__device__ __forceinline__ void count_memory_input(
    uint32_t address,
    uint32_t id,
    uint32_t *address_counts,
    uint32_t *big_counts,
    uint32_t *small_counts) {
    // memory_address_to_id's canonical row key is address - 1.  The encoded
    // memory-id tag selects the exact big/small runtime multiplicity slab.
    atomicAdd(&address_counts[address - 1u], 1u);
    uint32_t tag = id >> 30;
    uint32_t index = id & 0x3fffffffu;
    if (tag == 1u) {
        atomicAdd(&big_counts[index], 1u);
    } else if (tag == 0u) {
        atomicAdd(&small_counts[index], 1u);
    }
}

__device__ __forceinline__ void felt_to_limbs(
    const felt252 &value, uint32_t *limbs) {
    felt252_to_m31_limbs(value, reinterpret_cast<m31 *>(limbs));
}

__device__ __forceinline__ void store_projective_coordinate(
    PartialInputColumns output,
    uint32_t first_column,
    uint32_t destination,
    const felt252 &value) {
    for (uint32_t limb = 0; limb < 8; ++limb) {
        output.columns[first_column + limb][destination] = value.limbs[limb];
    }
}

__device__ __forceinline__ felt252 load_projective_coordinate(
    PartialInputColumns input,
    uint32_t first_column,
    uint32_t destination) {
    felt252 value;
    for (uint32_t limb = 0; limb < 8; ++limb) {
        value.limbs[limb] = input.columns[first_column + limb][destination];
    }
    return value;
}

__device__ __forceinline__ ProjectivePointCuda load_projective_point(
    PartialInputColumns input,
    uint32_t x_column,
    uint32_t y_column,
    uint32_t z_column,
    uint32_t destination) {
    return ProjectivePointCuda{
        load_projective_coordinate(input, x_column, destination),
        load_projective_coordinate(input, y_column, destination),
        load_projective_coordinate(input, z_column, destination),
    };
}

__device__ __forceinline__ void store_partial_projective_input(
    PartialInputColumns output,
    uint32_t destination,
    uint32_t chain,
    uint32_t round,
    const uint32_t *m,
    const ProjectivePointCuda &q,
    const ProjectivePointCuda &accumulator,
    uint32_t counter,
    uint32_t enabler) {
    output.columns[0][destination] = chain;
    output.columns[1][destination] = round;
    for (uint32_t word = 0; word < W27_WORDS; ++word) {
        output.columns[2u + word][destination] = m[word];
    }
    store_projective_coordinate(output, SCRATCH_Q_X, destination, q.X);
    store_projective_coordinate(output, SCRATCH_Q_Y, destination, q.Y);
    store_projective_coordinate(output, SCRATCH_Q_Z, destination, q.Z);
    store_projective_coordinate(output, SCRATCH_ACC_X, destination, accumulator.X);
    store_projective_coordinate(output, SCRATCH_ACC_Y, destination, accumulator.Y);
    store_projective_coordinate(output, SCRATCH_ACC_Z, destination, accumulator.Z);
    output.columns[124][destination] = counter;
    output.columns[125][destination] = enabler;
    output.columns[126][destination] = destination;
}

__device__ __forceinline__ void store_affine_point_columns(
    PartialInputColumns output,
    uint32_t destination,
    uint32_t x_column,
    uint32_t y_column,
    const AffinePointCuda &point) {
    uint32_t limbs[FELT_LIMBS];
    felt_to_limbs(point.x, limbs);
    for (uint32_t limb = 0; limb < FELT_LIMBS; ++limb) {
        output.columns[x_column + limb][destination] = limbs[limb];
    }
    felt_to_limbs(point.y, limbs);
    for (uint32_t limb = 0; limb < FELT_LIMBS; ++limb) {
        output.columns[y_column + limb][destination] = limbs[limb];
    }
}

__device__ __forceinline__ void store_partial_lookup(
    uint32_t *lookup,
    uint32_t rows,
    uint32_t row,
    uint32_t first_word,
    uint32_t chain,
    uint32_t round,
    const uint32_t *m,
    const AffinePointCuda &q,
    const AffinePointCuda &accumulator,
    uint32_t counter) {
    uint32_t limbs[FELT_LIMBS];
    uint32_t word = first_word;
    store_lookup_word(lookup, rows, row, word++, PARTIAL_EC_MUL_RELATION);
    store_lookup_word(lookup, rows, row, word++, chain);
    store_lookup_word(lookup, rows, row, word++, round);
    for (uint32_t i = 0; i < W27_WORDS; ++i) {
        store_lookup_word(lookup, rows, row, word++, m[i]);
    }
    felt_to_limbs(q.x, limbs);
    for (uint32_t limb = 0; limb < FELT_LIMBS; ++limb) {
        store_lookup_word(lookup, rows, row, word++, limbs[limb]);
    }
    felt_to_limbs(q.y, limbs);
    for (uint32_t limb = 0; limb < FELT_LIMBS; ++limb) {
        store_lookup_word(lookup, rows, row, word++, limbs[limb]);
    }
    felt_to_limbs(accumulator.x, limbs);
    for (uint32_t limb = 0; limb < FELT_LIMBS; ++limb) {
        store_lookup_word(lookup, rows, row, word++, limbs[limb]);
    }
    felt_to_limbs(accumulator.y, limbs);
    for (uint32_t limb = 0; limb < FELT_LIMBS; ++limb) {
        store_lookup_word(lookup, rows, row, word++, limbs[limb]);
    }
    store_lookup_word(lookup, rows, row, word, counter);
}

__global__ void __launch_bounds__(EC_OP_REGISTER_CEILING_THREADS)
ec_op_projective_chain_kernel(
    const uint32_t *const *tables,
    uint32_t n_addresses,
    uint32_t n_big,
    uint32_t n_small,
    const uint32_t *segment_start_source,
    uint32_t rows,
    EcOpTraceColumns trace,
    uint32_t *lookup,
    PartialInputColumns partial,
    uint32_t *address_counts,
    uint32_t *big_counts,
    uint32_t *small_counts,
    uint32_t *range_check_8_counts) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) {
        return;
    }

    // This is also round-zero's final enabler. Clearing it before any
    // fallible input load prevents the normalization phase from consuming a
    // stale scratch row when the raw ABI is given malformed memory tables.
    partial.columns[125][row] = 0;

    const uint32_t *addr_to_id = tables[0];
    uint32_t segment_start = *segment_start_source;
    uint64_t end = static_cast<uint64_t>(segment_start) +
                   static_cast<uint64_t>(rows) * 7u;
    if (segment_start == 0u || end > n_addresses) {
        return;
    }
    uint32_t base = segment_start + 7u * row;
    uint32_t limbs[FELT_LIMBS];
    uint32_t m[W27_WORDS];
    AffinePointCuda accumulator_affine;
    AffinePointCuda q_affine;

    // Five input cells: P.x, P.y, Q.x, Q.y, scalar m.
    uint32_t id = addr_to_id[base];
    if (!load_memory_value(tables, n_big, n_small, id, limbs)) return;
    trace.columns[0][row] = id;
    count_memory_input(base, id, address_counts, big_counts, small_counts);
    store_trace_limbs(trace, 1, row, limbs);
    store_memory_address_lookup(lookup, rows, row, 0, base, id);
    store_memory_big_lookup(lookup, rows, row, 3, id, limbs);
    felt252_from_m31_limbs(accumulator_affine.x, reinterpret_cast<m31 *>(limbs));

    id = addr_to_id[base + 1u];
    if (!load_memory_value(tables, n_big, n_small, id, limbs)) return;
    trace.columns[29][row] = id;
    count_memory_input(base + 1u, id, address_counts, big_counts, small_counts);
    store_trace_limbs(trace, 30, row, limbs);
    store_memory_address_lookup(lookup, rows, row, 33, base + 1u, id);
    store_memory_big_lookup(lookup, rows, row, 36, id, limbs);
    felt252_from_m31_limbs(accumulator_affine.y, reinterpret_cast<m31 *>(limbs));

    id = addr_to_id[base + 2u];
    if (!load_memory_value(tables, n_big, n_small, id, limbs)) return;
    trace.columns[58][row] = id;
    count_memory_input(base + 2u, id, address_counts, big_counts, small_counts);
    store_trace_limbs(trace, 59, row, limbs);
    store_memory_address_lookup(lookup, rows, row, 66, base + 2u, id);
    store_memory_big_lookup(lookup, rows, row, 69, id, limbs);
    felt252_from_m31_limbs(q_affine.x, reinterpret_cast<m31 *>(limbs));

    id = addr_to_id[base + 3u];
    if (!load_memory_value(tables, n_big, n_small, id, limbs)) return;
    trace.columns[87][row] = id;
    count_memory_input(base + 3u, id, address_counts, big_counts, small_counts);
    store_trace_limbs(trace, 88, row, limbs);
    store_memory_address_lookup(lookup, rows, row, 99, base + 3u, id);
    store_memory_big_lookup(lookup, rows, row, 102, id, limbs);
    felt252_from_m31_limbs(q_affine.y, reinterpret_cast<m31 *>(limbs));

    id = addr_to_id[base + 4u];
    if (!load_memory_value(tables, n_big, n_small, id, limbs)) return;
    trace.columns[116][row] = id;
    count_memory_input(base + 4u, id, address_counts, big_counts, small_counts);
    store_trace_limbs(trace, 117, row, limbs);
    store_memory_address_lookup(lookup, rows, row, 132, base + 4u, id);
    store_memory_big_lookup(lookup, rows, row, 135, id, limbs);
    for (uint32_t word = 0; word < 9; ++word) {
        m[word] = limbs[3u * word] | (limbs[3u * word + 1u] << 9) |
                  (limbs[3u * word + 2u] << 18);
    }
    m[9] = limbs[27];

    uint32_t ms_is_max = limbs[27] == 256u;
    uint32_t ms_and_mid_are_max = ms_is_max && limbs[21] == 136u;
    uint32_t rc0 = limbs[27] - ms_is_max;
    uint32_t rc1 = ms_is_max * (120u + limbs[21] - ms_and_mid_are_max);
    trace.columns[145][row] = ms_is_max;
    trace.columns[146][row] = ms_and_mid_are_max;
    trace.columns[147][row] = rc1;
    store_lookup_word(lookup, rows, row, 165, RANGE_CHECK_8_RELATION);
    store_lookup_word(lookup, rows, row, 166, rc0);
    store_lookup_word(lookup, rows, row, 167, RANGE_CHECK_8_RELATION);
    store_lookup_word(lookup, rows, row, 168, rc1);
    atomicAdd(&range_check_8_counts[rc0], 1u);
    atomicAdd(&range_check_8_counts[rc1], 1u);

    uint32_t counter = 26;
    store_partial_lookup(
        lookup, rows, row, 169, row, 0, m, q_affine, accumulator_affine, counter);

    ProjectivePointCuda q = affine_to_projective(q_affine);
    ProjectivePointCuda accumulator = affine_to_projective(accumulator_affine);

    for (uint32_t round = 0; round < PARTIAL_ROUNDS; ++round) {
        uint32_t destination = round * rows + row;
        store_partial_projective_input(
            partial, destination, row, round, m, q, accumulator, counter, 1);

        if ((m[0] & 1u) != 0) {
            ProjectivePointCuda sum;
            ec_add_projective_exact(accumulator, q, sum);
            accumulator = sum;
        }
        ProjectivePointCuda doubled;
        ec_double_projective_exact(q, doubled);
        q = doubled;

        if (counter == 0) {
            for (uint32_t word = 0; word + 1u < W27_WORDS; ++word) {
                m[word] = m[word + 1u];
            }
            m[W27_WORDS - 1u] = 0;
            counter = 26;
        } else {
            m[0] >>= 1;
            --counter;
        }
    }

    projective_pair_to_affine(q, accumulator, q_affine, accumulator_affine);

    for (uint32_t word = 0; word < W27_WORDS; ++word) {
        trace.columns[148u + word][row] = m[word];
    }
    felt_to_limbs(q_affine.x, limbs);
    store_trace_limbs(trace, 158, row, limbs);
    felt_to_limbs(q_affine.y, limbs);
    store_trace_limbs(trace, 186, row, limbs);
    felt_to_limbs(accumulator_affine.x, limbs);
    store_trace_limbs(trace, 214, row, limbs);
    felt_to_limbs(accumulator_affine.y, limbs);
    store_trace_limbs(trace, 242, row, limbs);
    trace.columns[270][row] = counter;
    store_partial_lookup(
        lookup,
        rows,
        row,
        295,
        row,
        PARTIAL_ROUNDS,
        m,
        q_affine,
        accumulator_affine,
        counter);

    uint32_t result_x_id = addr_to_id[base + 5u];
    trace.columns[271][row] = result_x_id;
    count_memory_input(base + 5u, result_x_id, address_counts, big_counts, small_counts);
    store_memory_address_lookup(lookup, rows, row, 421, base + 5u, result_x_id);
    felt_to_limbs(accumulator_affine.x, limbs);
    store_memory_big_lookup(lookup, rows, row, 424, result_x_id, limbs);

    uint32_t result_y_id = addr_to_id[base + 6u];
    trace.columns[272][row] = result_y_id;
    count_memory_input(base + 6u, result_y_id, address_counts, big_counts, small_counts);
    store_memory_address_lookup(lookup, rows, row, 454, base + 6u, result_y_id);
    felt_to_limbs(accumulator_affine.y, limbs);
    store_memory_big_lookup(lookup, rows, row, 457, result_y_id, limbs);
    store_lookup_word(lookup, rows, row, 487, 1);
}

__device__ __forceinline__ void normalize_saved_projective(
    PartialInputColumns partial,
    uint32_t destination,
    bool accumulator,
    const felt252 &z_inverse) {
    const ProjectivePointCuda point = accumulator
        ? load_projective_point(
              partial,
              SCRATCH_ACC_X,
              SCRATCH_ACC_Y,
              SCRATCH_ACC_Z,
              destination)
        : load_projective_point(
              partial, SCRATCH_Q_X, SCRATCH_Q_Y, SCRATCH_Q_Z, destination);
    require_finite(point);
    const AffinePointCuda affine =
        projective_to_affine_with_inverse(point, z_inverse);
    if (accumulator) {
        // Accumulator output (68..123) does not overlap scratch (12..59), so
        // it must be written before q output overwrites accumulator scratch.
        store_affine_point_columns(partial, destination, 68, 96, affine);
    } else {
        store_affine_point_columns(partial, destination, 12, 40, affine);
    }
}

// Threads are round-tile-major: adjacent lanes own adjacent component rows,
// preserving coalescing for every scratch read and final column write. Each
// thread batch-normalizes q and accumulator for a compile-time round tile with
// one inversion. 252 is divisible by the selected 1/2/4 candidates.
__global__ void __launch_bounds__(EC_OP_NORMALIZE_BLOCK)
ec_op_normalize_round_tiles_kernel(uint32_t rows, PartialInputColumns partial) {
    constexpr uint32_t POINTS_PER_TILE = 2u * EC_OP_NORMALIZE_ROUND_TILE;
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) {
        return;
    }
    if (partial.columns[125][row] != 1u) {
        return;
    }
    const uint32_t round_tile = blockIdx.y;
    const uint32_t first_round = round_tile * EC_OP_NORMALIZE_ROUND_TILE;
    felt252 prefixes[POINTS_PER_TILE];

#pragma unroll
    for (uint32_t offset = 0; offset < EC_OP_NORMALIZE_ROUND_TILE; ++offset) {
        const uint32_t destination = (first_round + offset) * rows + row;
        const felt252 q_z =
            load_projective_coordinate(partial, SCRATCH_Q_Z, destination);
        const felt252 accumulator_z =
            load_projective_coordinate(partial, SCRATCH_ACC_Z, destination);
        if (felt_is_zero(q_z) || felt_is_zero(accumulator_z)) {
            asm volatile("trap;");
        }
        const uint32_t q_index = 2u * offset;
        prefixes[q_index] = q_index == 0
            ? q_z
            : felt_mul(prefixes[q_index - 1u], q_z);
        prefixes[q_index + 1u] = felt_mul(prefixes[q_index], accumulator_z);
    }

    felt252 inverse_product = felt_inverse(prefixes[POINTS_PER_TILE - 1u]);
#pragma unroll
    for (int index = POINTS_PER_TILE - 1; index > 0; --index) {
        const uint32_t point_index = static_cast<uint32_t>(index);
        const uint32_t offset = point_index >> 1u;
        const bool accumulator = (point_index & 1u) != 0;
        const uint32_t destination = (first_round + offset) * rows + row;
        const felt252 z = load_projective_coordinate(
            partial, accumulator ? SCRATCH_ACC_Z : SCRATCH_Q_Z, destination);
        const felt252 z_inverse = felt_mul(inverse_product, prefixes[index - 1]);
        inverse_product = felt_mul(inverse_product, z);
        normalize_saved_projective(partial, destination, accumulator, z_inverse);
    }
    normalize_saved_projective(
        partial, first_round * rows + row, false, inverse_product);
}

// The generated partial_ec_mul_generic writer pads its packed-input vector to
// the next power of two by repeating packed input 0.  Since an EC-op component
// has a power-of-two row count, 252 rounds pad to exactly 256 rounds.  Every
// appended SIMD pack therefore repeats source rows 0..15 from round zero.
__global__ void __launch_bounds__(EC_OP_PADDING_BLOCK) partial_input_padding_kernel(
    uint32_t rows, PartialInputColumns partial) {
    uint32_t pad_row = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t padding_rows = (PARTIAL_PADDED_ROUNDS - PARTIAL_ROUNDS) * rows;
    if (pad_row >= padding_rows) {
        return;
    }
    uint32_t destination = PARTIAL_ROUNDS * rows + pad_row;
    uint32_t source = pad_row & 15u;
    for (uint32_t column = 0; column < 125; ++column) {
        partial.columns[column][destination] = partial.columns[column][source];
    }
    partial.columns[125][destination] = 0;
    partial.columns[126][destination] = destination;
}

} // namespace

extern "C" int ec_op_builtin_witness_on(
    const uint32_t *const *execution_tables,
    uint32_t n_addresses,
    uint32_t n_big,
    uint32_t n_small,
    const uint32_t *segment_start_source,
    uint32_t row_count,
    uint32_t *const *trace_columns_host,
    uint32_t *lookup_words,
    uint32_t *const *partial_input_columns_host,
    uint32_t partial_row_count,
    uint32_t *address_counts,
    uint32_t address_count_words,
    uint32_t *big_counts,
    uint32_t big_count_words,
    uint32_t *small_counts,
    uint32_t small_count_words,
    uint32_t *range_check_8_counts,
    uint32_t range_check_8_count_words,
    cudaStream_t stream) {
    if (execution_tables == nullptr || trace_columns_host == nullptr ||
        lookup_words == nullptr || partial_input_columns_host == nullptr ||
        segment_start_source == nullptr || address_counts == nullptr ||
        big_counts == nullptr || small_counts == nullptr ||
        range_check_8_counts == nullptr || stream == nullptr || row_count < 16u ||
        address_count_words < n_addresses - 1u || big_count_words < n_big ||
        small_count_words < n_small || range_check_8_count_words < 256u ||
        partial_row_count != PARTIAL_PADDED_ROUNDS * row_count) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    EcOpTraceColumns trace = {};
    PartialInputColumns partial = {};
    for (uint32_t column = 0; column < EC_OP_TRACE_COLUMNS; ++column) {
        if (trace_columns_host[column] == nullptr) {
            return static_cast<int>(cudaErrorInvalidDevicePointer);
        }
        trace.columns[column] = trace_columns_host[column];
    }
    for (uint32_t column = 0; column < PARTIAL_INPUT_COLUMNS; ++column) {
        if (partial_input_columns_host[column] == nullptr) {
            return static_cast<int>(cudaErrorInvalidDevicePointer);
        }
        partial.columns[column] = partial_input_columns_host[column];
    }

    uint32_t blocks =
        (row_count + EC_OP_CHAIN_BLOCK - 1u) / EC_OP_CHAIN_BLOCK;
    ec_op_projective_chain_kernel<<<blocks, EC_OP_CHAIN_BLOCK, 0, stream>>>(
        execution_tables, n_addresses, n_big, n_small, segment_start_source,
        row_count, trace, lookup_words, partial, address_counts, big_counts,
        small_counts, range_check_8_counts);
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        return static_cast<int>(error);
    }

    const dim3 normalize_grid(
        (row_count + EC_OP_NORMALIZE_BLOCK - 1u) / EC_OP_NORMALIZE_BLOCK,
        PARTIAL_ROUNDS / EC_OP_NORMALIZE_ROUND_TILE);
    ec_op_normalize_round_tiles_kernel<<<
        normalize_grid, EC_OP_NORMALIZE_BLOCK, 0, stream>>>(row_count, partial);
    error = cudaGetLastError();
    if (error != cudaSuccess) {
        return static_cast<int>(error);
    }

    uint32_t padding_rows = partial_row_count - PARTIAL_ROUNDS * row_count;
    blocks = (padding_rows + EC_OP_PADDING_BLOCK - 1u) / EC_OP_PADDING_BLOCK;
    partial_input_padding_kernel<<<blocks, EC_OP_PADDING_BLOCK, 0, stream>>>(
        row_count, partial);
    return static_cast<int>(cudaGetLastError());
}
