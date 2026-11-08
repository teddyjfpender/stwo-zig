// M9 L1a packed class ingress: device decoder for cache_pack.zig lz4_blocks.
//
// Two passes over the batch, both on the caller's stream:
//  (1) lz4_pass   one WARP per 16384-word block: LZ4 block decode (or raw
//                 copy) of the filtered byte planes straight into the block's
//                 own output region (it is exactly count*4 bytes). Lanes
//                 share the serial parse; copies are lane-parallel with one
//                 __syncwarp per match. Many warps per SM hide the parse
//                 latency, which a CTA-wide decoder cannot (v0: 17.7 GB/s on
//                 tasks [M], see vectors/reports/rv64-m9-prep/packed-ingress).
//  (2) scan_pass  one CTA per block: load the region into shared memory, gather
//                 byte planes + per-channel wrapping prefix sum in registers,
//                 store the exact host-unpack u32 layout back in place.
#include "m9_class_unpack.h"
#include <cuda_runtime.h>
#ifndef STWO_RV64_M9_STANDALONE
#include "custody.cuh"
#endif

namespace stwo::cuda::rv64::m9 {
constexpr uint32_t kThreads = 512;
constexpr uint32_t kLz4Warps = 4;
constexpr uint32_t kBlockWords = STWO_RV64_M9_BLOCK_WORDS;
constexpr uint32_t kRowsPerThread = kBlockWords / kThreads;  // 32
// Output staging is padded by one word per thread chunk (<= kThreads words).
constexpr uint32_t kStageWords = kBlockWords + kThreads;
constexpr uint32_t kScanSmemBytes = kStageWords * 4 + kThreads * 4;
// LZ4 block-format end rules (lz4_Block_format.md): the last 5 bytes are
// literals and the last match starts >= 12 bytes before the end.
constexpr uint32_t kLastLiterals = 5, kMfLimit = 12;

__device__ __forceinline__ uint32_t find_job(const StwoRv64M9PackedJob *jobs, uint32_t n, uint32_t block) {
  uint32_t lo = 0, hi = n;  // last job with first_block <= block
  while (hi - lo > 1) {
    const uint32_t mid = (lo + hi) / 2;
    if (jobs[mid].first_block <= block) lo = mid; else hi = mid;
  }
  return lo;
}

struct BlockRef {
  const uint8_t *src;
  uint8_t *out;
  uint32_t bytes, out_n, count, channels, raw, error;
};
// Shape + payload-chain validation shared by both passes (the host format
// invariant: payloads contiguous and in order, last ends at data_bytes).
__device__ BlockRef resolve(const StwoRv64M9PackedJob *jobs, uint32_t n_jobs, uint32_t gblock) {
  BlockRef r{};
  const StwoRv64M9PackedJob job = jobs[find_job(jobs, n_jobs, gblock)];
  const uint32_t index = gblock - job.first_block;
  const uint32_t ch = job.channels;
  const uint64_t n_blocks = (job.words + kBlockWords - 1) / kBlockWords;
  if (ch == 0 || ch > 128 || (ch & (ch - 1)) || job.words % ch || index >= n_blocks) {
    r.error = STWO_RV64_M9_UNPACK_SHAPE;
    return r;
  }
  const StwoRv64M9PackedBlock blk = job.blocks[index];
  const uint64_t first = uint64_t(index) * kBlockWords;
  r.count = uint32_t(job.words - first < kBlockWords ? job.words - first : kBlockWords);
  r.out_n = r.count * 4;
  r.channels = ch;
  if (blk.offset > job.data_bytes || blk.bytes > job.data_bytes - blk.offset || (index == 0 && blk.offset != 0) ||
      (index > 0 && blk.offset != job.blocks[index - 1].offset + job.blocks[index - 1].bytes) ||
      (index + 1 == n_blocks && blk.offset + blk.bytes != job.data_bytes) || (blk.raw && blk.bytes != r.out_n)) {
    r.error = STWO_RV64_M9_UNPACK_LENGTH;
    return r;
  }
  r.src = job.data + blk.offset;
  r.out = reinterpret_cast<uint8_t *>(job.output + first);
  r.bytes = blk.bytes;
  r.raw = blk.raw;
  return r;
}

// Warp-cooperative LZ4 block decode. Every lane parses the same bytes
// (broadcast loads, uniform control flow). Returns 0 or a status bit.
// kGlobal: `ip` is global memory (read-only path); else shared memory.
template <bool kGlobal>
__device__ __forceinline__ uint32_t in8(const uint8_t *p) {
  if constexpr (kGlobal) return __ldg(p); else return *p;
}
template <bool kGlobal>
__device__ uint32_t lz4_warp(const uint8_t *__restrict__ ip, const uint8_t *iend, uint8_t *out, uint32_t out_n) {
  const uint32_t lane = threadIdx.x & 31;
  uint32_t op = 0;
  while (true) {
    if (ip >= iend) return STWO_RV64_M9_UNPACK_LZ4;
    const uint32_t token = in8<kGlobal>(ip++);
    uint32_t lit = token >> 4;
    if (lit == 15) {
      uint32_t b;
      do {
        if (ip >= iend) return STWO_RV64_M9_UNPACK_LZ4;
        b = in8<kGlobal>(ip++);
        lit += b;
        if (lit > out_n) return STWO_RV64_M9_UNPACK_LZ4;
      } while (b == 255);
    }
    if (lit > uint32_t(iend - ip) || lit > out_n - op) return STWO_RV64_M9_UNPACK_LZ4;
    for (uint32_t i = lane; i < lit; i += 32) out[op + i] = in8<kGlobal>(ip + i);
    ip += lit;
    op += lit;
    if (ip == iend) return op == out_n ? 0u : STWO_RV64_M9_UNPACK_LENGTH;  // literals-only last sequence
    if (iend - ip < 2) return STWO_RV64_M9_UNPACK_LZ4;
    const uint32_t off = uint32_t(in8<kGlobal>(ip)) | (uint32_t(in8<kGlobal>(ip + 1)) << 8);
    ip += 2;
    uint32_t ml = token & 15;
    if (ml == 15) {
      uint32_t b;
      do {
        if (ip >= iend) return STWO_RV64_M9_UNPACK_LZ4;
        b = in8<kGlobal>(ip++);
        ml += b;
        if (ml > out_n) return STWO_RV64_M9_UNPACK_LZ4;
      } while (b == 255);
    }
    ml += 4;
    if (off == 0 || off > op) return STWO_RV64_M9_UNPACK_OFFSET;
    if (op + kMfLimit > out_n || ml > out_n - kLastLiterals - op) return STWO_RV64_M9_UNPACK_LZ4;
    __syncwarp();  // literals and earlier matches written by any lane visible
    const uint8_t *src = out + op - off;
    // Overlapping copy (off < ml) = period-`off` repetition of the fully
    // written window [op-off, op): every byte is independent.
    if (off >= ml) {
      for (uint32_t i = lane; i < ml; i += 32) out[op + i] = src[i];
    } else if (off == 1) {
      const uint8_t b = src[0];
      for (uint32_t i = lane; i < ml; i += 32) out[op + i] = b;
    } else {
      // Lane-local i % off, advanced by 32 % off per step (no per-byte urem).
      const uint32_t step = 32 % off;
      uint32_t j = lane % off;
      for (uint32_t i = lane; i < ml; i += 32) {
        out[op + i] = src[j];
        j += step;
        if (j >= off) j -= off;
      }
    }
    op += ml;
  }
}

// Job-table coverage (warp 0 of CTA 0). Per-block checks catch a block that
// maps past its job's end, but not one that is never launched: a first_block
// prefix that undercounts job j (its tail blocks are then attributed to job
// j+1) or a total_blocks below the sum. Those would leave stale output words
// with status 0, so the table itself must be the exact exclusive prefix.
__device__ void check_table(const StwoRv64M9PackedJob *jobs, uint32_t n_jobs, uint32_t total_blocks, uint32_t *status) {
  const uint32_t lane = threadIdx.x & 31;
  bool bad = false;
  for (uint32_t j = lane; j < n_jobs; j += 32) {
    const uint64_t nb = (jobs[j].words + kBlockWords - 1) / kBlockWords;
    const uint64_t expect = j == 0 ? 0 : uint64_t(jobs[j - 1].first_block) + (jobs[j - 1].words + kBlockWords - 1) / kBlockWords;
    bad |= nb == 0 || jobs[j].first_block != expect;
    if (j + 1 == n_jobs) bad |= uint64_t(jobs[j].first_block) + nb != total_blocks;
  }
  if (__any_sync(0xffffffffu, bad) && lane == 0) atomicOr(status, STWO_RV64_M9_UNPACK_SHAPE);
}

__global__ void __launch_bounds__(kLz4Warps * 32)
lz4_pass(const StwoRv64M9PackedJob *jobs, uint32_t n_jobs, uint32_t total_blocks, uint32_t *status) {
  if (blockIdx.x == 0 && threadIdx.x < 32) check_table(jobs, n_jobs, total_blocks, status);
  const uint32_t gblock = blockIdx.x * kLz4Warps + threadIdx.x / 32;
  if (gblock >= total_blocks) return;
  const uint32_t lane = threadIdx.x & 31;
  const BlockRef r = resolve(jobs, n_jobs, gblock);
  if (r.error) {
    if (lane == 0) atomicOr(status, r.error);
    return;
  }
  if (r.raw) {
    if (((reinterpret_cast<uintptr_t>(r.src) | reinterpret_cast<uintptr_t>(r.out)) & 15) == 0) {
      const uint4 *s = reinterpret_cast<const uint4 *>(r.src);
      uint4 *o = reinterpret_cast<uint4 *>(r.out);
      for (uint32_t i = lane; i < r.out_n / 16; i += 32) o[i] = __ldg(s + i);
      for (uint32_t i = (r.out_n / 16) * 16 + lane; i < r.out_n; i += 32) r.out[i] = r.src[i];
    } else {
      for (uint32_t i = lane; i < r.out_n; i += 32) r.out[i] = __ldg(r.src + i);
    }
    return;
  }
  const uint32_t err = lz4_warp<true>(r.src, r.src + r.bytes, r.out, r.out_n);
  if (err && lane == 0) atomicOr(status, err);
}

// Filtered bytes of one block are in smem[0, count); writes the final words
// to `region` (the block's output). Whole CTA (kThreads) participates.
__device__ void scan_block(uint32_t *smem, uint32_t *totals, uint32_t count, uint32_t ch, uint32_t *region) {
  const uint8_t *bytes = reinterpret_cast<const uint8_t *>(smem);
  const uint32_t t = threadIdx.x;
  const bool aligned = (reinterpret_cast<uintptr_t>(region) & 15) == 0;
  // Thread t owns rows [r0, r1) of channel c.
  const uint32_t rows = count / ch;
  const uint32_t per = kThreads / ch;  // threads per channel
  const uint32_t c = t / per, k = t % per;
  const uint32_t chunk = (rows + per - 1) / per;  // <= kRowsPerThread
  const uint32_t r0 = min(k * chunk, rows), r1 = min(r0 + chunk, rows);
  const uint8_t *plane = bytes + c * rows * 4;
  uint32_t v[kRowsPerThread];
  uint32_t acc = 0;
  if (chunk == kRowsPerThread && rows % 16 == 0) {
    // Full block: 2 x uint4 per byte plane, 4x4 byte transposes.
    uint32_t pw[4][8];
#pragma unroll
    for (uint32_t p = 0; p < 4; ++p) {
      const uint4 *q = reinterpret_cast<const uint4 *>(plane + p * rows + r0);
      const uint4 a = q[0], b = q[1];
      pw[p][0] = a.x; pw[p][1] = a.y; pw[p][2] = a.z; pw[p][3] = a.w;
      pw[p][4] = b.x; pw[p][5] = b.y; pw[p][6] = b.z; pw[p][7] = b.w;
    }
#pragma unroll
    for (uint32_t g = 0; g < 8; ++g) {
      const uint32_t lo = __byte_perm(pw[0][g], pw[1][g], 0x5140), hi = __byte_perm(pw[2][g], pw[3][g], 0x5140);
      const uint32_t lo2 = __byte_perm(pw[0][g], pw[1][g], 0x7362), hi2 = __byte_perm(pw[2][g], pw[3][g], 0x7362);
      acc += __byte_perm(lo, hi, 0x5410); v[4 * g + 0] = acc;
      acc += __byte_perm(lo, hi, 0x7632); v[4 * g + 1] = acc;
      acc += __byte_perm(lo2, hi2, 0x5410); v[4 * g + 2] = acc;
      acc += __byte_perm(lo2, hi2, 0x7632); v[4 * g + 3] = acc;
    }
  } else {
#pragma unroll
    for (uint32_t j = 0; j < kRowsPerThread; ++j) {
      const uint32_t row = r0 + j;
      uint32_t d = 0;
      if (row < r1)
        d = uint32_t(plane[row]) | (uint32_t(plane[rows + row]) << 8) | (uint32_t(plane[2 * rows + row]) << 16) |
            (uint32_t(plane[3 * rows + row]) << 24);
      acc += d;
      v[j] = acc;
    }
  }
  totals[t] = acc;
  __syncthreads();
  // Segmented inclusive scan of chunk totals within each channel group.
  for (uint32_t s = 1; s < per; s <<= 1) {
    const uint32_t x = k >= s ? totals[t - s] : 0u;
    __syncthreads();
    totals[t] += x;
    __syncthreads();
  }
  const uint32_t base = totals[t] - acc;
  // Padded staging (one pad word per `stride` words) keeps the strided
  // register->shared writes conflict-free; every plane read finished before
  // the first scan barrier, so it reuses the byte buffer.
  const uint32_t stride = max(chunk * ch, 1u);
#pragma unroll
  for (uint32_t j = 0; j < kRowsPerThread; ++j) {
    const uint32_t row = r0 + j;
    if (row < r1) {
      const uint32_t w = row * ch + c;
      smem[w + w / stride] = v[j] + base;
    }
  }
  __syncthreads();
  if (aligned && stride % 4 == 0) {
    uint4 *out4 = reinterpret_cast<uint4 *>(region);
    for (uint32_t q = t; q < count / 4; q += kThreads) {
      const uint32_t w = q * 4, p = w + w / stride;
      out4[q] = make_uint4(smem[p], smem[p + 1], smem[p + 2], smem[p + 3]);
    }
    for (uint32_t w = (count / 4) * 4 + t; w < count; w += kThreads) region[w] = smem[w + w / stride];
  } else {
    for (uint32_t w = t; w < count; w += kThreads) region[w] = smem[w + w / stride];
  }
}

__global__ void __launch_bounds__(kThreads, 1)
scan_pass(const StwoRv64M9PackedJob *jobs, uint32_t n_jobs) {
  extern __shared__ __align__(16) uint32_t smem[];
  const uint32_t t = threadIdx.x;
  const BlockRef r = resolve(jobs, n_jobs, blockIdx.x);
  if (r.error) return;  // already reported by lz4_pass
  uint32_t *region = reinterpret_cast<uint32_t *>(r.out);
  const uint32_t count = r.count;
  if ((reinterpret_cast<uintptr_t>(region) & 15) == 0) {
    const uint4 *s = reinterpret_cast<const uint4 *>(region);
    uint4 *d = reinterpret_cast<uint4 *>(smem);
    for (uint32_t q = t; q < count / 4; q += kThreads) d[q] = s[q];
    for (uint32_t w = (count / 4) * 4 + t; w < count; w += kThreads) smem[w] = region[w];
  } else {
    for (uint32_t w = t; w < count; w += kThreads) smem[w] = region[w];
  }
  __syncthreads();
  scan_block(smem, smem + kStageWords, count, r.channels, region);
}

}  // namespace stwo::cuda::rv64::m9

extern "C" int stwo_rv64_m9_class_unpack_passes(void *stream, const StwoRv64M9PackedJob *jobs, uint32_t n_jobs,
                                                uint32_t total_blocks, uint32_t *status, uint32_t passes) {
  using namespace stwo::cuda::rv64::m9;
  if (!jobs || !status || !n_jobs || !total_blocks || !passes || passes > 3) return int(cudaErrorInvalidValue);
  // The opt-in is per device (a process-wide "configured" flag left the second
  // GPU at the 48 KiB default, so scan_pass failed to launch there) and is
  // cheap and idempotent: set it on every launch, as transform/wide_tile.cuh.
  if (passes & 2) {
    const cudaError_t e = cudaFuncSetAttribute(scan_pass, cudaFuncAttributeMaxDynamicSharedMemorySize, int(kScanSmemBytes));
    if (e != cudaSuccess) return int(e);
  }
  const cudaStream_t s = static_cast<cudaStream_t>(stream);
  if (passes & 1) lz4_pass<<<(total_blocks + kLz4Warps - 1) / kLz4Warps, kLz4Warps * 32, 0, s>>>(jobs, n_jobs, total_blocks, status);
  if (passes & 2) scan_pass<<<total_blocks, kThreads, kScanSmemBytes, s>>>(jobs, n_jobs);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_m9_class_unpack_stream(void *stream, const StwoRv64M9PackedJob *jobs, uint32_t n_jobs,
                                                uint32_t total_blocks, uint32_t *status) {
  return stwo_rv64_m9_class_unpack_passes(stream, jobs, n_jobs, total_blocks, status, 3);
}

#ifndef STWO_RV64_M9_STANDALONE
extern "C" int stwo_rv64_m9_class_unpack_on(void *ctx, uint32_t lane, const StwoRv64M9PackedJob *jobs, uint32_t n_jobs,
                                            uint32_t total_blocks, uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (!n_jobs || n_jobs > 4096 || !total_blocks) return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(reinterpret_cast<const uint32_t *>(jobs), uint64_t(n_jobs) * sizeof(StwoRv64M9PackedJob) / 4, false) ||
      !c.range(status, 1, true))
    return c.status;
  return stwo_rv64_m9_class_unpack_stream(c.stream, jobs, n_jobs, total_blocks, status);
}
#endif
