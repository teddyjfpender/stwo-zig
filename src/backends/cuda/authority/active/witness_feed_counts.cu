// Generalized multiplicity count feed for the witness-JIT lane (the device
// component DAG, B2): consumes a witness kernel's WORD-MAJOR sub-input buffer
// directly on device (`sub[w * column_length + row]`) — deleting the sub D2H,
// the host packed-vector rebuild, and the DashMap `add_input` storm for every
// COUNT-STYLE relation (range checks, xor tables, points-table mults).
//
// Per descriptor: key = fold of the tuple's words (key = (key << bits[i]) |
// word_i), optionally mapped through the consumer's input->row LUT (the actual
// preprocessed layout, uploaded from the host generator — never a closed form),
// then atomicAdd into counts[rel_index * table_size + row]. Equivalence to the
// host path: the same multiset of increments the host `add_input` calls
// produce, merged commutatively — the certified `blake_g_xor_count_kernel`
// argument, generalized.
//
// Descriptor ABI is FLAT u32 (stride WFC_DESC_STRIDE), no structs across FFI:
//   [0] word_base   [1] n_words (1..=WFC_MAX_WORDS)
//   [2..7] bits[5]  [7] rel_index
//   [8] table_size  [9] lut_index (WFC_NO_LUT = identity)
//   [10] counts_index
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>

#include "cuda_mem_pool.cuh"

#define WFC_DESC_STRIDE 14u
#define WFC_MAX_WORDS 5u
#define WFC_NO_LUT 0xFFFFFFFFu

// Collapse identical counter destinations within a warp before touching
// global memory. Every participating lane contributes exactly +1; replacing
// N atomicAdd(+1) operations with one atomicAdd(+N) preserves the exact
// wrapping-u32 sum. The fallback keeps pre-Volta builds semantically intact.
static __device__ __forceinline__ void wfc_atomic_increment(uint32_t *counter) {
#if __CUDA_ARCH__ >= 700
    const uint32_t active = __activemask();
    const uint32_t peers = __match_any_sync(
        active, reinterpret_cast<unsigned long long>(counter));
    const uint32_t leader = (uint32_t)(__ffs(peers) - 1);
    if ((threadIdx.x & 31u) == leader) {
        atomicAdd(counter, (uint32_t)__popc(peers));
    }
#else
    atomicAdd(counter, 1u);
#endif
}

__global__ void witness_feed_counts_kernel(
    const uint32_t *sub_words,
    uint32_t column_length,
    const uint32_t *descs,
    uint32_t n_descs,
    const uint32_t *const *luts,
    uint32_t *const *counts
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    for (uint32_t d = 0; d < n_descs; ++d) {
        const uint32_t *e = descs + (size_t)d * WFC_DESC_STRIDE;
        uint32_t word_base = e[0];
        uint32_t n_words = e[1];
        uint32_t rel_index = e[7];
        uint32_t table_size = e[8];
        uint32_t lut_index = e[9];
        uint32_t kind = e[11];

        if (kind == 1u) {
            // MEM-ID DECODE (memory_id_to_big): tag = id >> 30 (0 = small,
            // 1 = big), val = id & 0x3FFFFFFF; DEFAULT_ID (empty cell) skipped
            // defensively — the host feed panics on it, a valid trace never
            // produces one. e[8] = big table size, e[12] = small table size,
            // e[10] = big counts slot, e[13] = small counts slot.
            uint32_t v = sub_words[(size_t)word_base * column_length + row];
            if (v == ((1u << 30) - 1u)) {
                continue;
            }
            uint32_t tag = v >> 30;
            uint32_t val = v & 0x3FFFFFFFu;
            if (tag == 1u) {
                if (val < table_size) {
                    wfc_atomic_increment(
                        &counts[e[10]][(size_t)rel_index * table_size + val]);
                }
            } else if (tag == 0u) {
                uint32_t small_size = e[12];
                if (val < small_size) {
                    wfc_atomic_increment(
                        &counts[e[13]][(size_t)rel_index * small_size + val]);
                }
            }
            continue;
        }

        if (kind == 2u) {
            // Dependent XOR tuple. The consumer table is indexed by (a,b),
            // while the recorded tuple also carries c. Validate that c is the
            // canonical AOT-produced xor result before using the exact
            // input-to-row LUT; never fold all three words into a larger key.
            uint32_t bits = e[2];
            uint32_t mask = (1u << bits) - 1u;
            uint32_t a = sub_words[(size_t)word_base * column_length + row];
            uint32_t b = sub_words[(size_t)(word_base + 1u) * column_length + row];
            uint32_t c = sub_words[(size_t)(word_base + 2u) * column_length + row];
            if ((a | b | c) > mask || c != (a ^ b)) {
                continue;
            }
            uint32_t key = (a << bits) | b;
            uint32_t idx = luts[lut_index][key];
            if (idx < table_size) {
                wfc_atomic_increment(
                    &counts[e[10]][(size_t)rel_index * table_size + idx]);
            }
            continue;
        }

        if (kind == 3u) {
            // xor12's AIR table is expanded: high two-bit limbs select one of
            // 16 multiplicity columns, low ten-bit limbs select its row.
            uint32_t a = sub_words[(size_t)word_base * column_length + row];
            uint32_t b = sub_words[(size_t)(word_base + 1u) * column_length + row];
            uint32_t c = sub_words[(size_t)(word_base + 2u) * column_length + row];
            if ((a | b | c) >= (1u << 12) || c != (a ^ b)) {
                continue;
            }
            uint32_t column = ((a >> 10) << 2) | (b >> 10);
            uint32_t table_row = ((a & 0x3ffu) << 10) | (b & 0x3ffu);
            // Memory safety FIRST: the slab holds 16 columns of table_size
            // words each, but the folded table_row ranges over the full 2^20
            // limb space regardless of table_size (a descriptor field). Clamp
            // per row — for the validated 2^20 xor12 table this is always
            // true, so results are unchanged; a smaller registered table must
            // skip (never spill into a neighboring column) exactly like every
            // other arm's `idx < table_size` check.
            if (table_row < table_size) {
                wfc_atomic_increment(
                    &counts[e[10]][(size_t)column * table_size + table_row]);
            }
            continue;
        }

        // FOLD (+ optional signed key offset e[12], e.g. addr - 1; + optional LUT).
        uint32_t key = 0;
        for (uint32_t i = 0; i < n_words; ++i) {
            key = (key << e[2 + i]) |
                  sub_words[(size_t)(word_base + i) * column_length + row];
        }
        long long keyed = (long long)key + (long long)(int32_t)e[12];
        // Memory safety FIRST: the key must be in the LUT/table domain BEFORE
        // any dereference (an out-of-width tuple — impossible on a valid trace,
        // where the host feed would panic — must never become an OOB read).
        // LUT domains equal table_size for every registered family (the LUT
        // covers the full tuple space).
        if (keyed < 0 || (uint64_t)keyed >= table_size) {
            continue;
        }
        uint32_t k = (uint32_t)keyed;
        uint32_t idx = (lut_index == WFC_NO_LUT) ? k : luts[lut_index][k];
        if (idx < table_size) {
            wfc_atomic_increment(
                &counts[e[10]][(size_t)rel_index * table_size + idx]);
        }
    }
}

// Launch over every padded row (the host feeds padding rows too — mults_0 = 1
// everywhere; truncating at the real count is an invalid-proof bug). All
// pointer arrays are DEVICE arrays built by the caller. Returns 0 on success.
static int witness_feed_counts_on(
    const uint32_t *sub_words_dev,
    uint32_t column_length,
    const uint32_t *descs_dev,
    uint32_t n_descs,
    const uint32_t *const *luts_dev,
    uint32_t *const *counts_dev,
    cudaStream_t stream
) {
    if (n_descs == 0 || column_length == 0) {
        return 0;
    }
    const uint32_t block = 256;
    uint32_t grid = 1u + (column_length - 1u) / block;
    witness_feed_counts_kernel<<<grid, block, 0, stream>>>(
        sub_words_dev, column_length, descs_dev, n_descs, luts_dev, counts_dev);
    if (cudaGetLastError() != cudaSuccess) {
        fprintf(stderr, "stwo_witness_feed_counts: launch failed\n");
        return 1;
    }
    return 0;
}

extern "C" int stwo_witness_feed_counts(
    const uint32_t *sub_words_dev,
    uint32_t column_length,
    const uint32_t *descs_dev,
    uint32_t n_descs,
    const uint32_t *const *luts_dev,
    uint32_t *const *counts_dev
) {
    return witness_feed_counts_on(
        sub_words_dev, column_length, descs_dev, n_descs, luts_dev, counts_dev,
        (cudaStream_t)0);
}

extern "C" int stwo_witness_feed_counts_on(
    const uint32_t *sub_words_dev,
    uint32_t column_length,
    const uint32_t *descs_dev,
    uint32_t n_descs,
    const uint32_t *const *luts_dev,
    uint32_t *const *counts_dev,
    void *stream
) {
    return witness_feed_counts_on(
        sub_words_dev, column_length, descs_dev, n_descs, luts_dev, counts_dev,
        (cudaStream_t)stream);
}

// ---------------------------------------------------------------------------
// Step 4.3: feed-atomics privatization (opt-in via STWO_CUDA_FEED_PRIVATIZED=1
// on the Rust side; both symbols are always compiled).
//
// Per-block shared-memory histograms replace the global atomicAdd scatter for
// every descriptor whose TOUCHED counter footprint fits the 48KB static
// shared-memory budget: table words per relation column times the number of
// relation columns the descriptor writes, times 4 bytes per u32 counter. The
// decision is a pure function of existing descriptor fields (no ABI change)
// and is uniform across the block, so the privatized branch (with its
// __syncthreads barriers) never diverges within a block.
//
// Byte-identity argument: every count is a u32 sum of +1 increments merged
// with wrapping (mod 2^32) atomic adds. Privatization only reassociates that
// sum — block-local partial sums in shared memory, then one UNCONDITIONAL
// (branchless: every covered word is merged, zero or not) atomicAdd of each
// partial into the same global word — and u32 wrapping addition is commutative
// and associative, so the final slabs are exactly equal in both modes.
// Oversized families (e.g. xor12's 16 x 2^20-word expanded table) keep the
// proven global-atomic path inside the SAME launch.
#define WFC_PRIV_SHARED_BYTES (48u * 1024u)
#define WFC_PRIV_SHARED_WORDS (WFC_PRIV_SHARED_BYTES / 4u)

// Touched counter words for one descriptor — the words the privatized kernel
// must cover in shared memory. Mirrored EXACTLY by the pure host sizing math
// in prepared_witness_feed.rs (witness_feed_privatized_footprint_words).
static __host__ __device__ inline uint64_t wfc_privatized_footprint_words(
    const uint32_t *e
) {
    uint64_t table_size = e[8];
    switch (e[11]) {
        case 1u:
            // MEM-ID DECODE writes one big relation column (table_size words)
            // and one small relation column (e[12] words).
            return table_size + (uint64_t)e[12];
        case 3u:
            // xor12 addresses all sixteen expanded multiplicity columns.
            return 16ull * table_size;
        default:
            // FOLD / dependent-XOR write one relation column of the table.
            return table_size;
    }
}

__global__ void witness_feed_counts_privatized_kernel(
    const uint32_t *sub_words,
    uint32_t column_length,
    const uint32_t *descs,
    uint32_t n_descs,
    const uint32_t *const *luts,
    uint32_t *const *counts
) {
    __shared__ uint32_t hist[WFC_PRIV_SHARED_WORDS];
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    // Out-of-range threads must NOT return: they still participate in the
    // shared-histogram zero/merge loops and their barriers.
    bool live = row < column_length;
    for (uint32_t d = 0; d < n_descs; ++d) {
        const uint32_t *e = descs + (size_t)d * WFC_DESC_STRIDE;
        uint32_t word_base = e[0];
        uint32_t n_words = e[1];
        uint32_t rel_index = e[7];
        uint32_t table_size = e[8];
        uint32_t lut_index = e[9];
        uint32_t kind = e[11];
        // Uniform per-descriptor decision: every thread of every block reads
        // the same descriptor words, so `privatize` never diverges.
        uint64_t footprint = wfc_privatized_footprint_words(e);
        bool privatize = footprint <= (uint64_t)WFC_PRIV_SHARED_WORDS;
        if (privatize) {
            for (uint32_t i = threadIdx.x; i < (uint32_t)footprint;
                 i += blockDim.x) {
                hist[i] = 0;
            }
            __syncthreads();
        }

        if (live && kind == 1u) {
            // MEM-ID DECODE — identical selection logic to the global kernel;
            // shared layout is [0, table_size) big, [table_size,
            // table_size + small_size) small.
            uint32_t v = sub_words[(size_t)word_base * column_length + row];
            if (v != ((1u << 30) - 1u)) {
                uint32_t tag = v >> 30;
                uint32_t val = v & 0x3FFFFFFFu;
                if (tag == 1u) {
                    if (val < table_size) {
                        if (privatize) {
                            atomicAdd(&hist[val], 1u);
                        } else {
                            atomicAdd(
                                &counts[e[10]]
                                       [(size_t)rel_index * table_size + val],
                                1u);
                        }
                    }
                } else if (tag == 0u) {
                    uint32_t small_size = e[12];
                    if (val < small_size) {
                        if (privatize) {
                            atomicAdd(&hist[table_size + val], 1u);
                        } else {
                            atomicAdd(
                                &counts[e[13]]
                                       [(size_t)rel_index * small_size + val],
                                1u);
                        }
                    }
                }
            }
        } else if (live && kind == 2u) {
            // Dependent XOR tuple — identical validation to the global kernel.
            uint32_t bits = e[2];
            uint32_t mask = (1u << bits) - 1u;
            uint32_t a = sub_words[(size_t)word_base * column_length + row];
            uint32_t b =
                sub_words[(size_t)(word_base + 1u) * column_length + row];
            uint32_t c =
                sub_words[(size_t)(word_base + 2u) * column_length + row];
            if ((a | b | c) <= mask && c == (a ^ b)) {
                uint32_t key = (a << bits) | b;
                uint32_t idx = luts[lut_index][key];
                if (idx < table_size) {
                    if (privatize) {
                        atomicAdd(&hist[idx], 1u);
                    } else {
                        atomicAdd(
                            &counts[e[10]]
                                   [(size_t)rel_index * table_size + idx],
                            1u);
                    }
                }
            }
        } else if (live && kind == 3u) {
            // xor12's expanded table: 16 x table_size words. The validated
            // 2^20 table never fits the 48KB budget, so it takes the global
            // path; a SMALLER registered table (table_size <= 768) privatizes,
            // and its histogram covers exactly `footprint` = 16 x table_size
            // words. The folded table_row ranges over the full 2^20 limb
            // space regardless of table_size, so it MUST be clamped against
            // table_size before either dereference — byte-identical to the
            // global kernel's clamp (always true for the 2^20 table).
            uint32_t a = sub_words[(size_t)word_base * column_length + row];
            uint32_t b =
                sub_words[(size_t)(word_base + 1u) * column_length + row];
            uint32_t c =
                sub_words[(size_t)(word_base + 2u) * column_length + row];
            if ((a | b | c) < (1u << 12) && c == (a ^ b)) {
                uint32_t column = ((a >> 10) << 2) | (b >> 10);
                uint32_t table_row = ((a & 0x3ffu) << 10) | (b & 0x3ffu);
                if (table_row < table_size) {
                    size_t offset = (size_t)column * table_size + table_row;
                    if (privatize) {
                        atomicAdd(&hist[offset], 1u);
                    } else {
                        atomicAdd(&counts[e[10]][offset], 1u);
                    }
                }
            }
        } else if (live) {
            // FOLD — identical key fold, signed offset, bounds and LUT logic.
            uint32_t key = 0;
            for (uint32_t i = 0; i < n_words; ++i) {
                key = (key << e[2 + i]) |
                      sub_words[(size_t)(word_base + i) * column_length + row];
            }
            long long keyed = (long long)key + (long long)(int32_t)e[12];
            if (keyed >= 0 && (uint64_t)keyed < table_size) {
                uint32_t k = (uint32_t)keyed;
                uint32_t idx =
                    (lut_index == WFC_NO_LUT) ? k : luts[lut_index][k];
                if (idx < table_size) {
                    if (privatize) {
                        atomicAdd(&hist[idx], 1u);
                    } else {
                        atomicAdd(
                            &counts[e[10]]
                                   [(size_t)rel_index * table_size + idx],
                            1u);
                    }
                }
            }
        }

        if (privatize) {
            __syncthreads();
            // Unconditional (branchless) merge: every covered word is added,
            // zero or not — no data-dependent skip, and wrapping u32 adds make
            // the result exactly equal to the direct-scatter slabs.
            if (kind == 1u) {
                uint32_t small_size = e[12];
                uint32_t *big =
                    counts[e[10]] + (size_t)rel_index * table_size;
                uint32_t *small_dst =
                    counts[e[13]] + (size_t)rel_index * small_size;
                for (uint32_t i = threadIdx.x; i < table_size;
                     i += blockDim.x) {
                    atomicAdd(&big[i], hist[i]);
                }
                for (uint32_t i = threadIdx.x; i < small_size;
                     i += blockDim.x) {
                    atomicAdd(&small_dst[i], hist[table_size + i]);
                }
            } else {
                // kind 3 addresses the whole expanded slab from offset 0; the
                // other kinds one relation column at rel_index * table_size.
                size_t base =
                    (kind == 3u) ? 0 : (size_t)rel_index * table_size;
                uint32_t *dst = counts[e[10]] + base;
                for (uint32_t i = threadIdx.x; i < (uint32_t)footprint;
                     i += blockDim.x) {
                    atomicAdd(&dst[i], hist[i]);
                }
            }
            // The histogram is reused by the next descriptor: its zeroing
            // loop must not race this merge.
            __syncthreads();
        }
    }
}

// Same launch geometry and ABI as witness_feed_counts_on; only the kernel
// body differs. Returns 0 on success.
static int witness_feed_counts_privatized_on(
    const uint32_t *sub_words_dev,
    uint32_t column_length,
    const uint32_t *descs_dev,
    uint32_t n_descs,
    const uint32_t *const *luts_dev,
    uint32_t *const *counts_dev,
    cudaStream_t stream
) {
    if (n_descs == 0 || column_length == 0) {
        return 0;
    }
    const uint32_t block = 256;
    uint32_t grid = 1u + (column_length - 1u) / block;
    witness_feed_counts_privatized_kernel<<<grid, block, 0, stream>>>(
        sub_words_dev, column_length, descs_dev, n_descs, luts_dev,
        counts_dev);
    if (cudaGetLastError() != cudaSuccess) {
        fprintf(stderr, "stwo_witness_feed_counts_privatized: launch failed\n");
        return 1;
    }
    return 0;
}

extern "C" int stwo_witness_feed_counts_privatized(
    const uint32_t *sub_words_dev,
    uint32_t column_length,
    const uint32_t *descs_dev,
    uint32_t n_descs,
    const uint32_t *const *luts_dev,
    uint32_t *const *counts_dev
) {
    return witness_feed_counts_privatized_on(
        sub_words_dev, column_length, descs_dev, n_descs, luts_dev, counts_dev,
        (cudaStream_t)0);
}

extern "C" int stwo_witness_feed_counts_privatized_on(
    const uint32_t *sub_words_dev,
    uint32_t column_length,
    const uint32_t *descs_dev,
    uint32_t n_descs,
    const uint32_t *const *luts_dev,
    uint32_t *const *counts_dev,
    void *stream
) {
    return witness_feed_counts_privatized_on(
        sub_words_dev, column_length, descs_dev, n_descs, luts_dev, counts_dev,
        (cudaStream_t)stream);
}

__global__ void witness_feed_clear_kernel(
    uint32_t *const *destinations,
    const uint32_t *lengths
) {
    uint32_t destination = blockIdx.y;
    uint32_t word = blockIdx.x * blockDim.x + threadIdx.x;
    if (word < lengths[destination]) {
        destinations[destination][word] = 0;
    }
}

// One capture-safe launch clears every shared fixed-table multiplicity slab.
// Pointer/length tables are immutable arena data prepared before capture.
extern "C" int stwo_witness_feed_clear_on(
    uint32_t *const *destinations_dev,
    const uint32_t *lengths_dev,
    uint32_t n_destinations,
    uint32_t max_words,
    void *stream
) {
    if (n_destinations == 0 || max_words == 0) {
        return 0;
    }
    const uint32_t block = 256;
    dim3 grid(1u + (max_words - 1u) / block, n_destinations, 1);
    witness_feed_clear_kernel<<<grid, block, 0, (cudaStream_t)stream>>>(
        destinations_dev, lengths_dev);
    if (cudaGetLastError() != cudaSuccess) {
        fprintf(stderr, "stwo_witness_feed_clear: launch failed\n");
        return 1;
    }
    return 0;
}
