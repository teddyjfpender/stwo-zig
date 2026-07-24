// Computed-deduce device functions for the witness-JIT lane (ISA-V3 kinds 2/3).
//
// Transcribed 1:1 from `stwo-cairo`'s host reference
// (`witness/fast_deduction/pedersen.rs::PartialEcMul::<14>::deduce_output` and
// `PackedPedersenPointsTableWindowBits18::deduce_output`) onto the proven fp256
// primitives in `ec_ops.cuh`. The register ABI (flat `unsigned` banks) is the
// recorder's packing in `witness_eval/recording.rs` — change either side only
// with the other, and bump `WITNESS_CODEGEN_VERSION`.
//
// This header is compiled in TWO translation contexts:
//   1. NVRTC witness-JIT kernels: `codegen.rs` textually embeds the fp256 chain
//      (storage/ptx/carry-chain/config/dispatch/ec_ops, includes stripped) and
//      then this header, only when a program uses deduce kinds 2/3.
//   2. nvcc, via `stwo_wit_deduce_oracle.cu`: the precompiled truth-oracle
//      launcher that qualifies these functions against the host fast_deduction
//      over real rows, isolating fp256-math bugs from codegen bugs.
//
// Correctness perimeter: `ec_add_affine` is an INCOMPLETE affine add (no
// doubling/infinity branch). The pedersen shift-point table construction keeps
// all real (and, by the recording interp gates, all padding) additions on
// distinct-x points; the pod differential (`STWO_CUDA_WITNESS_VERIFY`) compares
// every row, so a violated premise fails loudly instead of shipping bytes.
#ifndef STWO_WIT_DEDUCE_CUH
#define STWO_WIT_DEDUCE_CUH

#include "poseidon_witness_round_keys.cuh"

#if !defined(STWO_WIT_EMBED) || defined(STWO_WIT_NEEDS_PEDERSEN)
// Module-local pedersen table globals — DEFINITIONS, not externs. Device
// globals never cross CUmodule boundaries, so each module embedding this
// header carries its own copy; `runtime_jit.cu` fills them right after
// `cuModuleLoadDataEx` (and the oracle launcher fills its own at init).
// Layout: column c of row r = 9-bit M31 limb c of the point coordinate
// (x limbs in columns 0..28, y limbs in 28..56), rows flat per the host
// `PEDERSEN_TABLE_18` section layout [low0 | high0 | low2 | high2].
__device__ m31* g_stwo_wit_pedersen_cols[56];
__device__ unsigned g_stwo_wit_pedersen_n_rows;

// DeduceKind::PedersenPointsTableW18 (=3): in[1] = row index ->
// out[56] = [x limbs 0..28 | y limbs 28..56].
static __device__ __forceinline__ void stwo_wit_deduce_pedersen_points_w18(
    const unsigned* in, unsigned* out) {
    // n_rows is a power of two; the mask keeps a garbage index (poisoned or
    // adversarial recording) memory-safe. It is a no-op for every in-range row
    // — the differential gates own value correctness, this owns memory safety.
    unsigned row = in[0] & (g_stwo_wit_pedersen_n_rows - 1u);
    for (int c = 0; c < 56; ++c) {
        out[c] = g_stwo_wit_pedersen_cols[c][row];
    }
}

// DeduceKind::PartialEcMulW18 (=2): one W18 EC-mul round.
//   in[72]  = [chain, round, w0..w13, acc_x limbs 16..44, acc_y limbs 44..72]
//   out[72] = [chain, round+1, w1..w13,0, new_x limbs, new_y limbs]
// where table_row = round * 2^18 + w0 and (new_x, new_y) = acc + table[row].
static __device__ __forceinline__ void stwo_wit_deduce_partial_ec_mul_w18(
    const unsigned* in, unsigned* out) {
    AffinePointCuda acc, tbl, sum;
    felt252_from_m31_limbs(acc.x, in + 16);
    felt252_from_m31_limbs(acc.y, in + 44);

    // round < 28 and w0 < 2^18 on every recorded row (host-interp-gated), so
    // the product stays far below both 2^32 and the padded row count; the mask
    // is the same memory-safety clamp as above.
    unsigned row = in[1] * 262144u + in[2];
    row &= (g_stwo_wit_pedersen_n_rows - 1u);
    m31 limbs[28];
    for (int c = 0; c < 28; ++c) {
        limbs[c] = g_stwo_wit_pedersen_cols[c][row];
    }
    felt252_from_m31_limbs(tbl.x, limbs);
    for (int c = 0; c < 28; ++c) {
        limbs[c] = g_stwo_wit_pedersen_cols[28 + c][row];
    }
    felt252_from_m31_limbs(tbl.y, limbs);

    ec_add_affine(acc, tbl, sum);

    out[0] = in[0];      // chain passthrough
    out[1] = in[1] + 1u; // round+1; round < 28 << M31 P, so ++ IS the m31 add
    for (int i = 0; i < 13; ++i) {
        out[2 + i] = in[3 + i]; // windows shift left one
    }
    out[15] = 0u;
    felt252_to_m31_limbs(sum.x, out + 16);
    felt252_to_m31_limbs(sum.y, out + 44);
}
#endif

// ---- DeduceKind::Felt{Add,Sub,Mul,Div} (4-7): fp256 body arithmetic ---------------
//
// in[56] = [a limbs 0..28 | b limbs 28..56], out[28] = result limbs. Host
// reference: stwo-cairo `Felt252`'s operators, whose Montgomery compensation
// factors make the limb encoding CANONICAL VALUES in and out (cpu.rs — the
// `FELT252_MONT_MUL_FACTOR` construction). Add/sub are linear, so raw-word
// modular add/sub is already canonical; mul/div convert to Montgomery, operate,
// and convert back — the exact operand pattern `ec_add_affine` uses internally
// (lambda = dy * dx^-1 with both operands in Montgomery form), so no novel
// fp256 algebra is introduced here.
//
// Division by zero: the host PANICS ("Division by zero"). Real writer traces
// never divide by zero (the sites are EC slope denominators, and padding rows
// replicate real rows); on device `felt_inverse(0)` yields an unspecified word
// and the differential gates fail loudly if that premise ever breaks.

static __device__ __forceinline__ void stwo_wit_deduce_felt_add(
    const unsigned* in, unsigned* out) {
    felt252 a, b;
    felt252_from_m31_limbs(a, in);
    felt252_from_m31_limbs(b, in + 28);
    felt252 r = felt_add(a, b);
    felt252_to_m31_limbs(r, out);
}

static __device__ __forceinline__ void stwo_wit_deduce_felt_sub(
    const unsigned* in, unsigned* out) {
    felt252 a, b;
    felt252_from_m31_limbs(a, in);
    felt252_from_m31_limbs(b, in + 28);
    felt252 r = felt_sub(a, b);
    felt252_to_m31_limbs(r, out);
}

static __device__ __forceinline__ void stwo_wit_deduce_felt_mul(
    const unsigned* in, unsigned* out) {
    felt252 a, b;
    felt252_from_m31_limbs(a, in);
    felt252_from_m31_limbs(b, in + 28);
    felt252 r = felt_from_mont(felt_mul(felt_to_mont(a), felt_to_mont(b)));
    felt252_to_m31_limbs(r, out);
}

static __device__ __forceinline__ void stwo_wit_deduce_felt_div(
    const unsigned* in, unsigned* out) {
    felt252 a, b;
    felt252_from_m31_limbs(a, in);
    felt252_from_m31_limbs(b, in + 28);
    felt252 r =
        felt_from_mont(felt_mul(felt_to_mont(a), felt_inverse(felt_to_mont(b))));
    felt252_to_m31_limbs(r, out);
}

// ---- Cairo Poseidon fast-deduction ABI (kinds 8-11) -----------------------------
// Width27 values are ten canonical M31 words. Convert through the same canonical
// 28x9 representation used by the existing fp256 helpers; no Montgomery state is
// exposed across the ABI.
static __device__ __forceinline__ void stwo_wit_felt_from_w27(
    felt252& out, const unsigned* words) {
    m31 limbs[28];
    for (int j = 0; j < 9; ++j) {
        limbs[3 * j] = words[j] & 0x1ffu;
        limbs[3 * j + 1] = (words[j] >> 9) & 0x1ffu;
        limbs[3 * j + 2] = (words[j] >> 18) & 0x1ffu;
    }
    limbs[27] = words[9] & 0x1ffu;
    felt252_from_m31_limbs(out, limbs);
}

static __device__ __forceinline__ void stwo_wit_felt_to_w27(
    const felt252& value, unsigned* words) {
    m31 limbs[28];
    felt252_to_m31_limbs(value, limbs);
    for (int j = 0; j < 9; ++j) {
        words[j] = limbs[3 * j] | (limbs[3 * j + 1] << 9) |
                   (limbs[3 * j + 2] << 18);
    }
    words[9] = limbs[27];
}

static __device__ __forceinline__ felt252 stwo_wit_felt_value_mul(
    const felt252& a, const felt252& b) {
    return felt_from_mont(felt_mul(felt_to_mont(a), felt_to_mont(b)));
}

static __device__ __forceinline__ felt252 stwo_wit_felt_value_cube(
    const felt252& a) {
    felt252 square = stwo_wit_felt_value_mul(a, a);
    return stwo_wit_felt_value_mul(square, a);
}

static __device__ __forceinline__ felt252 stwo_wit_poseidon_key(
    unsigned round, int key) {
    felt252 result;
    unsigned safe_round = round < 35u ? round : 0u;
    stwo_wit_felt_from_w27(result, &STWO_WIT_POSEIDON_ROUND_KEYS[safe_round][key * 10]);
    return result;
}

static __device__ __forceinline__ void stwo_wit_deduce_poseidon_round_keys(
    const unsigned* in, unsigned* out) {
    unsigned round = in[0] < 35u ? in[0] : 0u;
    for (int word = 0; word < 30; ++word) {
        out[word] = STWO_WIT_POSEIDON_ROUND_KEYS[round][word];
    }
}

static __device__ __forceinline__ void stwo_wit_deduce_cube_252(
    const unsigned* in, unsigned* out) {
    felt252 value;
    stwo_wit_felt_from_w27(value, in);
    felt252 cube = stwo_wit_felt_value_cube(value);
    stwo_wit_felt_to_w27(cube, out);
}

static __device__ __forceinline__ void stwo_wit_deduce_poseidon_full_round_chain(
    const unsigned* in, unsigned* out) {
    felt252 x, y, z;
    stwo_wit_felt_from_w27(x, in + 2);
    stwo_wit_felt_from_w27(y, in + 12);
    stwo_wit_felt_from_w27(z, in + 22);
    x = stwo_wit_felt_value_cube(x);
    y = stwo_wit_felt_value_cube(y);
    z = stwo_wit_felt_value_cube(z);

    felt252 y_z = felt_sub(y, z);
    felt252 x_y_z = felt_sub(x, y_z);
    felt252 x_y_z_neg = felt_add(x, y_z);
    felt252 x_y = felt_add(x, y);
    felt252 two_x_y = felt_add(x_y, x_y);
    felt252 new_x = felt_add(felt_add(two_x_y, x_y_z), stwo_wit_poseidon_key(in[1], 0));
    felt252 new_y = felt_add(x_y_z, stwo_wit_poseidon_key(in[1], 1));
    felt252 new_z = felt_add(felt_sub(x_y_z_neg, z), stwo_wit_poseidon_key(in[1], 2));

    out[0] = in[0];
    out[1] = in[1] + 1u;
    stwo_wit_felt_to_w27(new_x, out + 2);
    stwo_wit_felt_to_w27(new_y, out + 12);
    stwo_wit_felt_to_w27(new_z, out + 22);
}

static __device__ __forceinline__ void stwo_wit_deduce_poseidon_3_partial_rounds_chain(
    const unsigned* in, unsigned* out) {
    felt252 state[4];
    for (int i = 0; i < 4; ++i) {
        stwo_wit_felt_from_w27(state[i], in + 2 + i * 10);
    }
    for (int key = 0; key < 3; ++key) {
        felt252 z23 = stwo_wit_felt_value_cube(state[3]);
        felt252 z03_z13 = felt_add(state[0], state[2]);
        felt252 z03_z13_z1 = felt_add(z03_z13, state[1]);
        felt252 longsum = felt_add(
            felt_sub(felt_add(z03_z13_z1, state[3]), z23),
            stwo_wit_poseidon_key(in[1], key));
        felt252 half_z3 = felt_add(
            felt_add(felt_add(longsum, z03_z13_z1), z03_z13), state[0]);
        felt252 z3 = felt_add(half_z3, half_z3);
        state[0] = state[2];
        state[1] = state[3];
        state[2] = z23;
        state[3] = z3;
    }
    out[0] = in[0];
    out[1] = in[1] + 1u;
    for (int i = 0; i < 4; ++i) {
        stwo_wit_felt_to_w27(state[i], out + 2 + i * 10);
    }
}

#endif // STWO_WIT_DEDUCE_CUH
