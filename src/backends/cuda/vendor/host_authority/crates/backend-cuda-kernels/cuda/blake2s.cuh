#ifndef BLAKE2S_H
#define BLAKE2S_H

#include <stddef.h>
#include "fields.cuh"
#include "utils.cuh"

const unsigned int BLOCK_SIZE = 256;

// Clonable state for domain-progressive commitment leaves. This is a public
// device ABI: Rust sizes arena ping/pong slots from the same 96-byte stride.
// Every row in a launch has absorbed the same canonical column prefix, so the
// counter and pending length are launch scalars. Only the per-row chaining
// value and lazy final block belong in HBM.
typedef struct {
    uint32_t h[8];
    uint32_t pending[16];
} ProgressiveBlake2sState;

static_assert(sizeof(ProgressiveBlake2sState) == 96,
              "progressive Blake2s state ABI must be 96 bytes");
static_assert(offsetof(ProgressiveBlake2sState, pending) == 32,
              "invalid pending offset");

// Host-owned descriptor for reconstructing the compact h[8]-only state's
// lazy final block. CUDA launch capture copies this descriptor into kernel
// parameters; the addressed retained evaluation columns remain arena-owned.
struct alignas(8) CompactBlake2sTailDescriptor {
    uint64_t column_addresses[16];
    uint32_t log_ratios[16];
};

__host__ __device__ constexpr uint32_t stwo_compact_pending_words(
    uint32_t absorbed_columns) {
    return absorbed_columns == 0 ? 0 : (absorbed_columns - 1) % 16 + 1;
}

inline bool stwo_compact_tail_descriptor_valid(
    uint32_t size,
    uint32_t absorbed_columns,
    const CompactBlake2sTailDescriptor &tail) {
    uint32_t target_log_size = 0;
    for (uint32_t rows = size; rows > 1; rows >>= 1) ++target_log_size;
    const uint32_t pending_words = stwo_compact_pending_words(absorbed_columns);
    for (uint32_t word = 0; word < 16; ++word) {
        const uint64_t address = tail.column_addresses[word];
        const uint32_t log_ratio = tail.log_ratios[word];
        if (word < pending_words) {
            if (address == 0 || (address & 3u) != 0 ||
                log_ratio > target_log_size) {
                return false;
            }
        } else if (address != 0 || log_ratio != 0) {
            return false;
        }
    }
    return true;
}

static_assert(sizeof(CompactBlake2sTailDescriptor) == 192,
              "compact Blake2s tail descriptor must be 192 bytes");
static_assert(alignof(CompactBlake2sTailDescriptor) == 8,
              "compact Blake2s tail descriptor must be 8-byte aligned");
static_assert(offsetof(CompactBlake2sTailDescriptor, column_addresses) == 0,
              "invalid compact tail column offset");
static_assert(offsetof(CompactBlake2sTailDescriptor, log_ratios) == 128,
              "invalid compact tail log-ratio offset");
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
              "progressive pending words require little-endian CUDA targets");
#endif

// Shared device primitive for the transcript engine.  It is defined by
// blake2s.cu so the channel and Merkle paths use one compression
// implementation.  Inputs are byte strings exactly as consumed by the Rust
// `Blake2sHasher`; no domain tag is inserted here.
#ifdef __CUDACC__
__device__ void stwo_blake2s_hash2_device(
    const uint8_t *first,
    size_t first_len,
    const uint8_t *second,
    size_t second_len,
    Blake2sHash *out);

// Cross-translation-unit sink for the fused N2B→leaf kernel. `message` is one
// exact 16-word block; `state` already contains the running h[8].
__device__ void stwo_blake2s_compress_leaf_block_device(
    Blake2sHash *state,
    const uint32_t message[16],
    uint32_t total_bytes,
    uint32_t lastblock);

// Cooperative low-register counterparts. Exactly one aligned four-lane warp
// subgroup calls each function for one state/message.
__device__ void stwo_blake2s_init_leaf_state_quad_device(Blake2sHash *state);
__device__ void stwo_blake2s_compress_leaf_block_quad_device(
    Blake2sHash *state,
    const uint32_t message[16],
    uint32_t total_bytes,
    uint32_t lastblock);
#endif

// Occupancy lever for the register-capped commit/leaf-hash kernels. The
// STWO_COMMIT_PROBE measured them pinned at 255 registers => 1 block/SM => 12.5%
// occupancy, already spilling to local memory (blake2s full-unroll register
// explosion). The minBlocksPerMultiprocessor argument to __launch_bounds__ forces
// the compiler to cap registers so >=N blocks co-reside on an SM, trading register
// spilling for latency-hiding occupancy. Compile-time tunable to sweep the
// trade-off; 1 reproduces the prior (uncapped, 255-reg) behavior. Byte-identical
// either way — this is purely a scheduling/occupancy hint.
//
// MEASURED 2026-07-06: minBlocks=2 doubles occupancy (12.5%→25%, regs 255→128, no
// added spilling) but is FLAT on total prove within run-to-run noise (~0.8s on
// SN_PIE_2): the leaf-hash is blake2s-COMPUTE-bound, so latency-hiding occupancy
// doesn't help, and the commit-Merkle slice is small. Default kept at 1 (no forced
// cap = original behavior); the knob + STWO_COMMIT_PROBE stay as diagnostics.
#ifndef STWO_LEAF_MIN_BLOCKS
#define STWO_LEAF_MIN_BLOCKS 1
#endif

extern "C"
void commit_on_first_layer(uint32_t size, uint32_t number_of_columns, uint32_t **columns, Blake2sHash* result);

extern "C"
void commit_on_first_layer_lifted(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t **columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    Blake2sHash* result
);

extern "C"
void commit_on_layer_with_previous(uint32_t size, uint32_t number_of_columns, uint32_t **columns, Blake2sHash* previous_layer, Blake2sHash* result);

// Streaming leaf commit (VRAM diet): the lifted first layer split so the caller
// LDEs base columns one group at a time. `state` holds h[8] per leaf (init ->
// update per group -> finalize). Non-final groups pass a multiple-of-16
// `group_n_cols`; `cols_done` is the running column offset. Byte-identical to
// commit_on_first_layer_lifted.
extern "C"
void stream_leaf_init(uint32_t size, Blake2sHash *state);
extern "C"
void stream_leaf_update(uint32_t size, uint32_t group_n_cols, uint32_t **columns, const uint32_t *column_log_sizes, uint32_t lifting_log_size, uint32_t cols_done, Blake2sHash *state);
// ILP2 leaf-update lane (Step 3.2, opt-in STWO_CUDA_BLAKE2S_LEAF_ILP=1): one
// thread hashes TWO adjacent rows with interleaved G-function streams; grid
// halves (one thread per row pair). Byte-identical to stream_leaf_update; odd
// row counts hash the final unpaired row through the scalar stream.
extern "C"
void stream_leaf_update_ilp2(uint32_t size, uint32_t group_n_cols, uint32_t **columns, const uint32_t *column_log_sizes, uint32_t lifting_log_size, uint32_t cols_done, Blake2sHash *state);
extern "C"
void stream_leaf_finalize(uint32_t size, uint32_t rem_cols, uint32_t **columns, const uint32_t *column_log_sizes, uint32_t lifting_log_size, uint32_t cols_done, Blake2sHash *result);

// Allocation-free explicit-stream variants used by transcript-bounded graph
// segments. All pointer tables, state, and outputs are caller-owned device memory.
extern "C"
int stwo_blake2s_leaf_init_on(uint32_t size, Blake2sHash *state, void *stream);

// Domain-progressive leaf ABI.  `columns` is a device pointer table in exact
// canonical commitment order, and every column has exactly `size` words.
// Expansion is output-parallel and requires disjoint input/output buffers.
extern "C"
int stwo_blake2s_progressive_init_on(
    uint32_t size, ProgressiveBlake2sState *states, void *stream);
extern "C"
int stwo_blake2s_progressive_absorb_on(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    ProgressiveBlake2sState *states,
    void *stream);
// Four-lane retained-domain twin. Unlike the aligned Blake2sHash quad, this
// consumes arbitrary lazy prefixes through ProgressiveBlake2sState and may
// initialize the first domain in the same launch.
extern "C"
int stwo_blake2s_progressive_absorb_quad_on(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    uint32_t initializes_state,
    ProgressiveBlake2sState *states,
    void *stream);
// Compact retained-domain successor. Only h[8] persists in `states`; the lazy
// 1..=16-word prefix is reconstructed from `tail` at every later boundary.
// The host wrapper copies `tail` by value into the captured kernel parameters.
extern "C"
int stwo_blake2s_compact_absorb_quad_on(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    uint32_t initializes_state,
    const CompactBlake2sTailDescriptor *tail,
    Blake2sHash *states,
    void *stream);
// Source-major disjoint successor to compact expand + absorb. One four-lane
// owner loads each source h8 once and emits all circle-ordered lifted children.
extern "C"
int stwo_blake2s_compact_expand_absorb_quad_on(
    uint32_t from_log_size,
    uint32_t to_log_size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **columns,
    const CompactBlake2sTailDescriptor *tail,
    const Blake2sHash *source_states,
    Blake2sHash *destination_states,
    void *stream);
// Terminal-retained direct-N2B twin. Each eight-lane owner loads both
// pre-final siblings before either canonical evaluation is written, then the
// two four-lane halves absorb the two rows using the compact h8 protocol.
extern "C"
int stwo_blake2s_compact_absorb_n2b_terminal_pair_on(
    uint32_t size,
    uint32_t number_of_columns,
    uint32_t absorbed_columns_before,
    uint32_t **prefinal_columns,
    uint32_t initializes_state,
    const CompactBlake2sTailDescriptor *tail,
    uint32_t *twiddles,
    uint32_t twiddle_words,
    Blake2sHash *states,
    void *stream);
extern "C"
int stwo_blake2s_progressive_expand_on(
    uint32_t from_log_size,
    uint32_t to_log_size,
    const ProgressiveBlake2sState *states_in,
    ProgressiveBlake2sState *states_out,
    void *stream);
extern "C"
int stwo_blake2s_compact_expand_in_place_on(
    uint32_t from_log_size,
    uint32_t to_log_size,
    Blake2sHash *states,
    Blake2sHash *scratch_pair,
    void *stream);
extern "C"
int stwo_blake2s_progressive_finalize_on(
    uint32_t size,
    uint32_t absorbed_columns,
    const ProgressiveBlake2sState *states,
    Blake2sHash *result,
    void *stream);
extern "C"
int stwo_blake2s_compact_finalize_quad_in_place_on(
    uint32_t size,
    uint32_t absorbed_columns,
    const CompactBlake2sTailDescriptor *tail,
    Blake2sHash *states_and_hashes,
    void *stream);
extern "C"
int stwo_blake2s_leaf_update_on(uint32_t size, uint32_t group_n_cols, uint32_t **columns, const uint32_t *column_log_sizes, uint32_t lifting_log_size, uint32_t cols_done, Blake2sHash *state, void *stream);
// ILP2 explicit-stream twin of stwo_blake2s_leaf_update_on (same contract,
// two rows per thread, halved grid; byte-identical digests).
extern "C"
int stwo_blake2s_leaf_update_ilp2_on(uint32_t size, uint32_t group_n_cols, uint32_t **columns, const uint32_t *column_log_sizes, uint32_t lifting_log_size, uint32_t cols_done, Blake2sHash *state, void *stream);
// Four-lane cooperative update. One warp owns eight independent leaves; each
// quad distributes one Blake2s compression across four lanes and exchanges
// diagonal words with warp shuffles. The byte stream and state ABI are
// identical to stwo_blake2s_leaf_update_on.
extern "C"
int stwo_blake2s_leaf_update_quad_on(uint32_t size, uint32_t group_n_cols, uint32_t **columns, const uint32_t *column_log_sizes, uint32_t lifting_log_size, uint32_t cols_done, Blake2sHash *state, void *stream);
extern "C"
int stwo_blake2s_leaf_finalize_on(uint32_t size, uint32_t rem_cols, uint32_t **columns, const uint32_t *column_log_sizes, uint32_t lifting_log_size, uint32_t cols_done, Blake2sHash *result, void *stream);
// Consume columns stopped immediately before their final circle butterfly.
// Each 256-leaf block computes that last value and feeds it straight into the
// running Blake2s state, so no completed LDE is written and reread.
extern "C"
int stwo_blake2s_leaf_group_from_lde_on(
    uint32_t size,
    uint32_t group_n_cols,
    uint32_t **prefinal_columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    uint32_t is_final,
    uint32_t *twiddles,
    uint32_t twiddle_words,
    Blake2sHash *state,
    void *stream);
extern "C"
int stwo_blake2s_layer_on(const Blake2sHash *previous_layer, uint32_t output_size, Blake2sHash *result, void *stream);
extern "C"
int stwo_blake2s_tail_on(const Blake2sHash *first, uint32_t first_size, Blake2sHash *const *out_levels, uint32_t n_levels, void *stream);

// FRI leaf hashing directly from four coordinate columns. `log_rows_per_leaf`
// is exactly 0 (four-word leaf) or 2 (the verifier's 4-row packed leaf). This
// avoids materializing the 16 packed columns while preserving their byte order.
extern "C"
int stwo_blake2s_fri_leaf_on(uint32_t evaluation_size,
                             uint32_t **coordinate_columns,
                             uint32_t log_rows_per_leaf,
                             Blake2sHash *result,
                             void *stream);

// Sparse counterpart of the streaming lifted-leaf commit. `leaf_indices` and
// `leaf_count` stay on device and are produced from transcript queries. A
// non-final group must contain a multiple of 16 columns; the final group has
// 1..=16. The word stream is identical to stream_leaf_{update,finalize}.
extern "C"
int stwo_blake2s_sparse_leaf_group_on(
    const uint32_t *leaf_indices,
    const uint32_t *leaf_count,
    uint32_t max_leaf_count,
    uint32_t group_n_cols,
    uint32_t **columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states,
    void *stream);

// Workstream D layer-pair fusion: hash two internal (column-free) tree levels per
// launch. `size` = number of grandparent hashes; `previous_layer` holds 4*size.
extern "C"
void commit_on_two_layers_with_previous(uint32_t size, Blake2sHash* previous_layer, Blake2sHash* result);

#endif // BLAKE2S_H
