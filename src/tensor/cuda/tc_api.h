/* C ABI of the tensor-prover CUDA backend (libtensor_cuda).
 *
 * One implementation (tc_host.cu) builds two ways:
 *   - nvcc -> libtensor_cuda.so (real device; zig build -Dcuda=true),
 *   - clang++ with the CPU emulation of the kernels (tc_emu.cpp; zig build
 *     test-cuda-emu), so this whole surface is exercised on machines
 *     without an NVIDIA GPU.
 * QM31 values are 4 u32 limbs (a, b, c, d) = (a + b i) + (c + d i) u; QM31
 * vectors are arrays of such limbs (the host QM31 slice layout).
 * Every function returns 0 on success; on failure, nonzero and
 * tc_last_error() describes it. A failed context must be destroyed. */
#ifndef TENSOR_CUDA_TC_API_H
#define TENSOR_CUDA_TC_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tc_ctx tc_ctx;
typedef struct tc_sc tc_sc;

typedef struct {
    uint64_t launches;
    uint64_t h2d_bytes;
    uint64_t d2h_bytes;
    uint64_t syncs;
    uint64_t device_allocs;
    uint64_t resident_hits;
    uint64_t sc_sessions;
    uint64_t sc_rounds;
    uint64_t commits;
    uint64_t weight_passes;
    uint64_t matmuls;
    uint64_t mles;
    uint64_t gkr_layers;
} tc_stats;

/* Sumcheck term table (same layout as tc::ScTerms). */
typedef struct {
    uint32_t n_factors, n_terms, deg, pad;
    uint32_t term_len[4];
    uint32_t term_fac[4][3];
    uint32_t coeff[4][4];
} tc_terms;

/* Implicit sumcheck factors (accel.FactorSpec). */
typedef struct {
    uint64_t offset;
    const uint32_t *point; /* point_len QM31 */
    uint32_t point_len;
    uint32_t gamma[4];
} tc_claim;

enum { TC_SPEC_INT = 0, TC_SPEC_EQ = 1, TC_SPEC_EQ_PREFIX = 2 };

typedef struct {
    uint32_t kind;
    uint32_t free_bits;   /* EQ_PREFIX */
    const int32_t *ints;  /* INT */
    uint64_t n_ints;
    const tc_claim *claims; /* EQ (n_claims), EQ_PREFIX (one claim, gamma = 1) */
    uint32_t n_claims;
    uint32_t pad;
} tc_spec;

int tc_backend_kind(void); /* 1 = CUDA device, 2 = CPU emulation */
tc_ctx *tc_create(int device);
void tc_destroy(tc_ctx *ctx);
const char *tc_last_error(tc_ctx *ctx);
void tc_get_stats(tc_ctx *ctx, tc_stats *out);
const char *tc_device_name(tc_ctx *ctx);

/* Resident host buffers: an explicitly pinned (host pointer, bytes) range is
 * uploaded once and reused by every later call that passes the same range
 * (weights: commit, combine, row dots). The caller unpins before freeing. */
int tc_pin(tc_ctx *ctx, const void *host, uint64_t bytes);
void tc_unpin_all(tc_ctx *ctx);

/* Field reference entry points (tests). */
int tc_qm_mul_batch(tc_ctx *ctx, const uint32_t *x, const uint32_t *y, uint64_t n, uint32_t *out);
int tc_eq_table(tc_ctx *ctx, const uint32_t *point, uint32_t n, const uint32_t gamma[4], uint32_t *out);

/* Weight passes: out[g][c] = sum_i coeffs[g][i] m[i][c] (rows R, cols C);
 * out[k] = sum_n m[k][n] vec[n]. */
int tc_combine_rows(tc_ctx *ctx, const void *m, int is_i8, uint64_t R, uint64_t C, const uint32_t *coeffs, uint32_t G, uint32_t *out);
int tc_row_dots_i8(tc_ctx *ctx, const int8_t *m, uint64_t R, uint64_t C, const uint32_t *vec, uint32_t *out);
int tc_matmul_i32_i8(tc_ctx *ctx, const int32_t *x, const int8_t *w, uint32_t T, uint32_t K, uint32_t N, int64_t *out);
int tc_mle_i32(tc_ctx *ctx, const int32_t *v, uint32_t log_n, const uint32_t *point, uint32_t out[4]);

/* Sumcheck sessions (accel.sc_*): factors stay on the device; each round is
 * one launch and a 48-byte readback. */
tc_sc *tc_sc_begin(tc_ctx *ctx, const uint32_t *const *factors, uint32_t nf, uint64_t len, uint64_t active, const tc_terms *terms);
tc_sc *tc_sc_begin_specs(tc_ctx *ctx, const tc_spec *specs, uint32_t nf, uint64_t len, uint64_t active, const tc_terms *terms);
int tc_sc_round(tc_ctx *ctx, tc_sc *s, const uint32_t *r_prev /* null: none */, uint32_t out[12]);
int tc_sc_finish(tc_ctx *ctx, tc_sc *s, const uint32_t r_last[4], uint32_t *const *out);
uint64_t tc_sc_len(tc_sc *s);
void tc_sc_abort(tc_ctx *ctx, tc_sc *s);

/* PCS commitment: circle-FFT RS encoding of the R x 2^log_c integer matrix
 * to 2^(log_c + log_b) columns, column-major codeword, Blake2s leaves and
 * nodes. *enc_out receives R * E host-visible words (CUDA managed memory:
 * the openings' column reads migrate only the opened pages); free with
 * tc_free_visible. nodes_out: 2 E hashes of 32 bytes, nodes[1] = root. */
int tc_commit(tc_ctx *ctx, const void *m, int is_i8, uint64_t R, uint32_t log_c, uint32_t log_b, const uint32_t *twiddles, uint32_t tw_len, uint32_t **enc_out, uint8_t *nodes_out);
void tc_free_visible(tc_ctx *ctx, void *p);
/* Rows per commit chunk (multiple of 16); 0 = by memory budget. */
void tc_set_commit_chunk_rows(tc_ctx *ctx, uint64_t rows);

/* One LogUp-GKR fraction layer for many instances (one launch). Offsets are
 * in QM31 elements; out_off has n_inst + 1 entries. */
int tc_gkr_layer(tc_ctx *ctx, const uint64_t *in_off, const uint64_t *out_off, uint32_t n_inst, const uint32_t *num, const uint32_t *den, uint64_t n_in, uint32_t *num_out, uint32_t *den_out);

#ifdef __cplusplus
}
#endif

#endif
