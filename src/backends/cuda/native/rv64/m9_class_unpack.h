#ifndef STWO_CUDA_RV64_M9_CLASS_UNPACK_H
#define STWO_CUDA_RV64_M9_CLASS_UNPACK_H
#include <stdint.h>
// M9 L1a (STWO_RV64_M9_CLASS_PACKED_INGRESS): device decoder for the
// producer-cache `lz4_blocks` encoding of circuit_cpu/om31/cache_pack.zig.
//
// Each Packed value is `words` u32 in row-major records of `channels` u32.
// It is cut into independent blocks of BLOCK_WORDS (16384) words. A block is
// the LZ4 block-format compression (or, if `raw`, a verbatim copy) of the
// per-channel wrapping deltas, stored as four byte planes per channel:
//   plane[c][b][r] = byte b of (x[r][c] - x[r-1][c]),   x[-1][c] = 0.
// The decoder writes exactly the u32 words cache_pack.unpack writes, so the
// consumer kernels see the same device layout as after a host unpack + H2D.
//
// Producer cache only: no proof, wire or verifier depends on this encoding.
// Malformed input sets a status bit and leaves that block's output undefined;
// the caller must refuse the node (never prove from a nonzero status).
#define STWO_RV64_M9_BLOCK_WORDS 16384u
struct StwoRv64M9PackedBlock {
  uint64_t offset;  // byte offset of the payload inside the job's data
  uint32_t bytes;   // payload bytes
  uint32_t raw;     // 1 = verbatim filtered bytes, 0 = LZ4 block
};
struct StwoRv64M9PackedJob {
  const uint8_t *data;                   // device: concatenated payloads
  const StwoRv64M9PackedBlock *blocks;   // device: ceil(words/BLOCK_WORDS)
  uint32_t *output;                      // device: words u32 (consumer layout)
  uint64_t data_bytes;
  uint64_t words;
  uint32_t channels;  // power of two, 1..128 (BLOCK_WORDS % channels == 0)
  uint32_t first_block;  // prefix over the batch: global CTA index of block 0
};
static_assert(sizeof(StwoRv64M9PackedBlock) == 16, "abi");
static_assert(sizeof(StwoRv64M9PackedJob) == 48, "abi");
// Status bits (atomicOr).
#define STWO_RV64_M9_UNPACK_SHAPE 1u
#define STWO_RV64_M9_UNPACK_LENGTH 2u
#define STWO_RV64_M9_UNPACK_LZ4 4u
#define STWO_RV64_M9_UNPACK_OFFSET 8u

// Batched decode of `n_jobs` Packed values (device array `jobs`) into their
// outputs; `total_blocks` = sum of blocks; jobs[i].first_block must be the
// exclusive prefix. Context-free entry point (standalone tests, jobs runtime).
extern "C" int stwo_rv64_m9_class_unpack_stream(void *stream,
                                                const StwoRv64M9PackedJob *jobs,
                                                uint32_t n_jobs,
                                                uint32_t total_blocks,
                                                uint32_t *status);
// Measurement only: `passes` bit 0 = warp LZ4 pass, bit 1 = unshuffle/scan.
extern "C" int stwo_rv64_m9_class_unpack_passes(void *stream, const StwoRv64M9PackedJob *jobs,
                                                uint32_t n_jobs, uint32_t total_blocks,
                                                uint32_t *status, uint32_t passes);
// Exec-context lane entry (same convention as stwo_rv64_sample_order_on).
// Only the status and job table are custody-checked here; each job's data,
// blocks and output are validated by the caller's arena (host-built table).
extern "C" int stwo_rv64_m9_class_unpack_on(void *ctx, uint32_t lane,
                                            const StwoRv64M9PackedJob *jobs,
                                            uint32_t n_jobs,
                                            uint32_t total_blocks,
                                            uint32_t *status);
#endif
