// Device logup PAIR GENERATION from the witness-JIT lane's word-major lookup flats
// (ENDGAME §6a: the interaction trace born on device).
//
// The host interaction writer does, per logup column pair:
//     denomA = combine(tupleA) = sum_i alpha^i * tupleA[i]  -  z
//     denomB = combine(tupleB)
//     numerator   = denomA * multB + denomB * multA     (QM31)
//     denominator = denomA * denomB
// and for the trailing solo column: numerator = -mult, denominator = combine(tuple).
// This kernel computes exactly those values straight from the flats the witness
// kernel produced (word-major, `flats[w * n_rows + r]` — fully coalesced reads),
// writing numerators as four coordinate columns (the `logup_fraction_chain_dense`
// numerator form) and denominators as row-major dense qm31 (its denominator form).
// The remaining finalize (batched inversion, fraction chain, claimed sum, cumsum)
// is the existing proven `logup_finalize.cu` path.
//
// Descriptor layout (8 u32 per logup column):
//   [0] kind: 0 = pair, 1 = solo (B slots ignored)
//   [1] offA (word offset of tuple A), [2] widthA, [3] multA word offset (FLAT kind)
//   [4] offB,                          [5] widthB, [6] multB word offset (FLAT kind)
//   [7] flags: bit0 negA, bit1 negB, bits2-3 multKindA, bits4-5 multKindB
//       mult kinds: 0 = FLAT (scalar column at the mult word offset),
//                   1 = ONE (constant 1), 2 = ENABLER (row < n_real).
// Signs are explicit — the generated writers negate yields in arbitrary
// positions; nothing is implicit (the old "solo = negated" rule is now
// flags bit0 on the emitting side).
//
// Correctness gate: the device pairs + finalize must match the HOST
// `write_interaction_trace` byte-for-byte per column and in claimed sum — the
// device-interaction differential (pod gate) compares both.

#include <cstring>

#include "fields.cuh"
#include "utils.cuh"

static constexpr uint32_t LOGUP_PAIRS_BLOCK = 256;
static constexpr uint32_t DESC_WORDS = 8;

// combine(tuple) = sum_i alpha^i * v_i - z, alphas passed as dense qm31 [i][4].
static __device__ __forceinline__ qm31 combine_tuple(
    const uint32_t *flats,
    uint32_t n_rows,
    uint32_t row,
    uint32_t off,
    uint32_t width,
    const qm31 *alphas,
    qm31 z
) {
    qm31 zero = {{0, 0}, {0, 0}};
    qm31 acc = sub(zero, z);
    for (uint32_t i = 0; i < width; ++i) {
        m31 v = flats[(off + i) * n_rows + row];
        acc = add(acc, mul(v, alphas[i]));
    }
    return acc;
}

// Multiplier fetch per the descriptor's mult kind; sign applied in-field.
static __device__ __forceinline__ m31 fetch_mult(
    const uint32_t *flats,
    uint32_t n_rows,
    uint32_t row,
    uint32_t off,
    uint32_t kind,
    uint32_t n_real,
    bool neg
) {
    m31 m;
    if (kind == 1u) {
        m = 1u;
    } else if (kind == 2u) {
        m = row < n_real ? 1u : 0u;
    } else {
        m = flats[off * n_rows + row];
    }
    if (neg && m != 0u) {
        m = P - m;
    }
    return m;
}

__global__ void logup_pairs_from_flats_kernel(
    const uint32_t *flats,
    uint32_t n_rows,
    uint32_t n_real,
    const uint32_t *descs,
    uint32_t n_cols,
    const qm31 *alphas,
    qm31 z,
    uint32_t *const *num_cols,   // [col*4 + coord] -> column of length n_rows
    uint32_t *const *den_dense   // [col] -> dense qm31 buffer (4*n_rows u32)
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= n_rows) {
        return;
    }
    for (uint32_t c = 0; c < n_cols; ++c) {
        const uint32_t *d = descs + c * DESC_WORDS;
        uint32_t flags = d[7];
        m31 ma = fetch_mult(flats, n_rows, row, d[3], (flags >> 2) & 3u, n_real,
                            (flags & 1u) != 0u);
        qm31 num, den;
        if (d[0] == 0) {
            qm31 da = combine_tuple(flats, n_rows, row, d[1], d[2], alphas, z);
            qm31 db = combine_tuple(flats, n_rows, row, d[4], d[5], alphas, z);
            m31 mb = fetch_mult(flats, n_rows, row, d[6], (flags >> 4) & 3u, n_real,
                                (flags & 2u) != 0u);
            // num/den = ma/da + mb/db (signs already folded into ma/mb).
            num = add(mul(mb, da), mul(ma, db));
            den = mul(da, db);
        } else {
            num = qm31{{ma, 0}, {0, 0}};
            den = combine_tuple(flats, n_rows, row, d[1], d[2], alphas, z);
        }
        num_cols[c * 4 + 0][row] = num.a.a;
        num_cols[c * 4 + 1][row] = num.a.b;
        num_cols[c * 4 + 2][row] = num.b.a;
        num_cols[c * 4 + 3][row] = num.b.b;
        qm31 *den_out = reinterpret_cast<qm31 *>(den_dense[c]);
        den_out[row] = den;
    }
}

extern "C" bool stwo_logup_pairs_from_flats(
    const uint32_t *flats,
    uint32_t n_rows,
    uint32_t n_real,
    const uint32_t *descs_host,
    uint32_t n_cols,
    const uint32_t *alphas_host,  // n_alphas * 4 u32 (qm31 coords per power)
    uint32_t n_alphas,
    const uint32_t *z_host,       // 4 u32
    uint32_t *const *num_cols_device_table,
    uint32_t *const *den_dense_device_table
) {
    uint32_t *descs = cuda_proving_malloc<uint32_t>(n_cols * DESC_WORDS);
    cudaMemcpy(descs, descs_host, sizeof(uint32_t) * n_cols * DESC_WORDS,
               cudaMemcpyHostToDevice);
    qm31 *alphas = cuda_proving_malloc<qm31>(n_alphas);
    cudaMemcpy(alphas, alphas_host, sizeof(qm31) * n_alphas, cudaMemcpyHostToDevice);
    qm31 z;
    memcpy(&z, z_host, sizeof(qm31));

    uint32_t blocks = (n_rows + LOGUP_PAIRS_BLOCK - 1) / LOGUP_PAIRS_BLOCK;
    logup_pairs_from_flats_kernel<<<blocks, LOGUP_PAIRS_BLOCK>>>(
        flats, n_rows, n_real, descs, n_cols, alphas, z,
        num_cols_device_table, den_dense_device_table);
    cudaError_t err = cudaGetLastError();
    cuda_proving_free(descs);
    cuda_proving_free(alphas);
    return err == cudaSuccess;
}
