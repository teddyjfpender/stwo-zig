// M9 GPU capture replay (prototype; STWO_RV64_M9_GPU_REPLAY, default off).
//
// Re-executes RV64 guest chunks from fast-first-pass seeds and emits the compact tape
// steps (compact_tape.Step, 48 B) of the CPU recorder (fast_execution.Engine.runTraced /
// compact_tape.Tape.appendRecord), byte for byte. The guest RAM is never read: every
// load/store takes its aligned before-word from the memory tape the first pass recorded
// (the CPU recorder's own memory_before stream). Host-retired steps (services, traps,
// absent pages) are scattered from the host list. One thread per chunk.
//
// Inputs and their producers: src/integrations/riscv_cpu/rv64_m9_gpu_replay.zig.
// Standalone parity/microbenchmark harness: build with -DM9_STANDALONE (see
// scripts/rv64_m9/gpu_replay_bench.sh). Prover-side witness only; no proof authority.
#include <cuda_runtime.h>
#include <stdint.h>

namespace m9 {

struct Step {
  uint64_t next_pc, lhs, rhs, previous_rd, result;
  uint32_t memory_index, flags;
};
struct Seed {
  uint64_t regs[32];
  uint64_t pc;
  uint32_t first_step, steps, first_mem, check_next;
};
struct SlowStep {
  uint32_t pos, pc_slot;  // pc_slot: ROM slot of the step's own pc (NO_SLOT outside the table)
  Step step;
  uint8_t rd;             // register the host step writes (NO_RD: none)
  uint8_t reserved[7];
};
struct Slot {
  uint8_t op, rd, rs1, rs2;
  uint32_t target;
  uint64_t imm;
};
static_assert(sizeof(Step) == 48 && sizeof(Seed) == 280 && sizeof(SlowStep) == 64 && sizeof(Slot) == 16, "ABI");

// Index into OP_NAMES of rv64_m9_gpu_replay.zig.
enum Op : uint8_t {
  SLOW, NOP, ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND, ADDI, SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI,
  SRAI, ADDW, SUBW, SLLW, SRLW, SRAW, ADDIW, SLLIW, SRLIW, SRAIW, LI, MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM,
  REMU, MULW, DIVW, DIVUW, REMW, REMUW, ANDN, ORN, XNOR, REV8, SEXT_B, SEXT_H, ZEXT_H, LB, LH, LW, LD, LBU,
  LHU, LWU, SB, SH, SW, SD, BEQ, BNE, BLT, BGE, BLTU, BGEU, JAL, JALR, OP_COUNT
};
static_assert(OP_COUNT == 70, "op table");

constexpr uint32_t NO_MEMORY = 0xffffffffu;
constexpr uint32_t NO_SLOT = 0xffffffffu;
constexpr uint8_t NO_RD = 0xff;
// ST_CONTINUITY: a chunk's end state disagrees with what follows it (next seed: regs, pc,
// memory cursor; host step: pc, memory cursor, r[rd] == previous_rd and, when the next seed
// follows the host step directly, every other register, its pc and memory cursor;
// segment end: pc and tape length).
// ST_BOUNDS: a seed points outside its segment's steps or memory tape (never read/written).
constexpr uint32_t ST_SLOW_SLOT = 1, ST_MISALIGNED = 2, ST_CONTINUITY = 4, ST_PC_RANGE = 8, ST_BOUNDS = 16;

struct Segment {
  uint64_t out_base;    // first global step index of the segment
  uint64_t mem_base;    // first global memory-tape word of the segment
  uint32_t steps;       // segment length
  uint32_t mem_words;   // memory-tape length
  uint32_t slow_base;   // first host step of the segment in Job::slow (sorted by pos)
  uint32_t slow_count;
  uint32_t end_slot;    // ROM slot of the pc after the segment's last step (NO_SLOT outside)
  uint32_t reserved;
};
static_assert(sizeof(Segment) == 40, "ABI");
struct Job {
  const Slot *rom;
  uint64_t code_lo;
  uint32_t slots;
  uint32_t chunks;
  const Seed *seeds;          // all segments, concatenated
  const uint32_t *chunk_seg;  // segment of each chunk
  const Segment *segs;
  const uint64_t *mem;        // all memory tapes, concatenated
  const SlowStep *slow;       // all host steps, concatenated per segment, sorted by pos
  Step *out;                  // all segments' steps, concatenated
  uint32_t *status;
};

__device__ __forceinline__ uint64_t sext32(uint32_t v) { return uint64_t(int64_t(int32_t(v))); }
__device__ __forceinline__ uint64_t div64(int64_t a, int64_t b, bool rem) {
  if (b == 0) return rem ? uint64_t(a) : ~0ull;
  if (a == INT64_MIN && b == -1) return rem ? 0 : uint64_t(a);
  return uint64_t(rem ? a % b : a / b);
}
__device__ __forceinline__ uint32_t div32(int32_t a, int32_t b, bool rem) {
  if (b == 0) return rem ? uint32_t(a) : ~0u;
  if (a == INT32_MIN && b == -1) return rem ? 0 : uint32_t(a);
  return uint32_t(rem ? a % b : a / b);
}

__device__ __forceinline__ void store_step(Step *dst, const Step &s) {
  // 48 B as three 16 B stores (steps are 16 B aligned).
  const uint4 *src = reinterpret_cast<const uint4 *>(&s);
  uint4 *d = reinterpret_cast<uint4 *>(dst);
  d[0] = src[0];
  d[1] = src[1];
  d[2] = src[2];
}

__global__ void __launch_bounds__(128) replay(Job j) {
  const uint32_t c = blockIdx.x * blockDim.x + threadIdx.x;
  if (c >= j.chunks) return;
  const Seed &seed = j.seeds[c];
  const Segment seg = j.segs[j.chunk_seg[c]];
  uint64_t r[33];
#pragma unroll
  for (int k = 0; k < 32; ++k) r[k] = seed.regs[k];
  r[0] = 0;
  r[32] = 0;
  if (seed.pc < j.code_lo || ((seed.pc - j.code_lo) >> 2) >= j.slots || (seed.pc & 3)) {
    atomicOr(j.status, ST_PC_RANGE);
    return;
  }
  if (uint64_t(seed.first_step) + seed.steps > seg.steps || seed.first_mem > seg.mem_words) {
    atomicOr(j.status, ST_BOUNDS);
    return;
  }
  uint32_t i = uint32_t((seed.pc - j.code_lo) >> 2);
  uint32_t m = seed.first_mem;
  const uint64_t *mem = j.mem + seg.mem_base;
  Step *out = j.out + seg.out_base + seed.first_step;
  const uint32_t n = seed.steps;
  uint32_t bad = 0;
  for (uint32_t k = 0; k < n; ++k) {
    if (i >= j.slots) { bad |= ST_PC_RANGE; break; }  // fallthrough off the table
    const uint4 raw = __ldg(reinterpret_cast<const uint4 *>(j.rom + i));
    const uint8_t op = raw.x & 0xff, rd = (raw.x >> 8) & 0xff, rs1 = (raw.x >> 16) & 0xff, rs2 = raw.x >> 24;
    const uint32_t target = raw.y;
    const uint64_t imm = uint64_t(raw.z) | (uint64_t(raw.w) << 32);
    const uint64_t x = r[rs1], y = r[rs2];
    const uint64_t here = j.code_lo + 4ull * i;
    Step s;
    s.next_pc = here + 4;
    s.lhs = x;
    s.rhs = y;
    s.previous_rd = r[rd];
    s.memory_index = NO_MEMORY;
    s.flags = 0;
    uint64_t v = 0;
    bool write = true;
    uint32_t next = i + 1;
    const int64_t sx = int64_t(x), sy = int64_t(y);
    const uint32_t xw = uint32_t(x), yw = uint32_t(y);
    switch (op) {
      case NOP: s.lhs = s.rhs = s.previous_rd = 0; write = false; break;
      case LI: s.lhs = s.rhs = 0; v = imm; break;
      case ADD: v = x + y; break;
      case SUB: v = x - y; break;
      case SLL: v = x << (y & 63); break;
      case SLT: v = sx < sy; break;
      case SLTU: v = x < y; break;
      case XOR: v = x ^ y; break;
      case SRL: v = x >> (y & 63); break;
      case SRA: v = uint64_t(sx >> (y & 63)); break;
      case OR: v = x | y; break;
      case AND: v = x & y; break;
      case ADDI: v = x + imm; break;
      case SLTI: v = sx < int64_t(imm); break;
      case SLTIU: v = x < imm; break;
      case XORI: v = x ^ imm; break;
      case ORI: v = x | imm; break;
      case ANDI: v = x & imm; break;
      case SLLI: v = x << (imm & 63); break;
      case SRLI: v = x >> (imm & 63); break;
      case SRAI: v = uint64_t(sx >> (imm & 63)); break;
      case ADDW: v = sext32(xw + yw); break;
      case SUBW: v = sext32(xw - yw); break;
      case SLLW: v = sext32(xw << (y & 31)); break;
      case SRLW: v = sext32(xw >> (y & 31)); break;
      case SRAW: v = sext32(uint32_t(int32_t(xw) >> (y & 31))); break;
      case ADDIW: v = sext32(xw + uint32_t(imm)); break;
      case SLLIW: v = sext32(xw << (imm & 31)); break;
      case SRLIW: v = sext32(xw >> (imm & 31)); break;
      case SRAIW: v = sext32(uint32_t(int32_t(xw) >> (imm & 31))); break;
      case MUL: v = x * y; break;
      case MULH: v = uint64_t(__mul64hi(sx, sy)); break;
      case MULHU: v = __umul64hi(x, y); break;
      case MULHSU: {
        // signed x unsigned: hi(x*y) = umulhi(x, y) - (x < 0 ? y : 0)
        v = __umul64hi(x, y) - (sx < 0 ? y : 0);
        break;
      }
      case MULW: v = sext32(xw * yw); break;
      case DIV: v = div64(sx, sy, false); break;
      case REM: v = div64(sx, sy, true); break;
      case DIVU: v = y == 0 ? ~0ull : x / y; break;
      case REMU: v = y == 0 ? x : x % y; break;
      case DIVW: v = sext32(div32(int32_t(xw), int32_t(yw), false)); break;
      case REMW: v = sext32(div32(int32_t(xw), int32_t(yw), true)); break;
      case DIVUW: v = sext32(yw == 0 ? ~0u : xw / yw); break;
      case REMUW: v = sext32(yw == 0 ? xw : xw % yw); break;
      case ANDN: v = x & ~y; break;
      case ORN: v = x | ~y; break;
      case XNOR: v = ~(x ^ y); break;
      case REV8: v = __byte_perm(uint32_t(x >> 32), 0, 0x0123) | (uint64_t(__byte_perm(xw, 0, 0x0123)) << 32); break;
      case SEXT_B: v = uint64_t(int64_t(int8_t(xw))); break;
      case SEXT_H: v = uint64_t(int64_t(int16_t(xw))); break;
      case ZEXT_H: v = x & 0xffff; break;
      case LB: case LH: case LW: case LD: case LBU: case LHU: case LWU: {
        const uint32_t width = (op == LB || op == LBU) ? 1 : (op == LH || op == LHU) ? 2 : (op == LW || op == LWU) ? 4 : 8;
        const uint64_t address = x + imm;
        if (address & (width - 1)) bad |= ST_MISALIGNED;
        if (m >= seg.mem_words) { bad |= ST_BOUNDS; break; }
        const uint64_t word = mem[m];
        s.memory_index = m++;
        s.rhs = 0;
        const uint64_t lane = word >> ((address & 7) * 8);
        switch (op) {
          case LB: v = uint64_t(int64_t(int8_t(lane))); break;
          case LH: v = uint64_t(int64_t(int16_t(lane))); break;
          case LW: v = sext32(uint32_t(lane)); break;
          case LBU: v = lane & 0xff; break;
          case LHU: v = lane & 0xffff; break;
          case LWU: v = lane & 0xffffffffull; break;
          default: v = lane; break;
        }
        break;
      }
      case SB: case SH: case SW: case SD: {
        const uint32_t width = op == SB ? 1 : op == SH ? 2 : op == SW ? 4 : 8;
        if ((x + imm) & (width - 1)) bad |= ST_MISALIGNED;
        if (m >= seg.mem_words) { bad |= ST_BOUNDS; break; }
        s.memory_index = m++;
        s.previous_rd = 0;
        write = false;
        break;
      }
      case BEQ: case BNE: case BLT: case BGE: case BLTU: case BGEU: {
        const bool taken = op == BEQ ? x == y : op == BNE ? x != y : op == BLT ? sx < sy : op == BGE ? sx >= sy : op == BLTU ? x < y : x >= y;
        if (taken) next = target;
        s.next_pc = j.code_lo + 4ull * next;
        s.previous_rd = 0;
        s.flags = taken;
        write = false;
        break;
      }
      case JAL:
        s.lhs = s.rhs = 0;
        v = imm;
        next = target;
        s.next_pc = j.code_lo + 4ull * next;
        s.flags = 1;
        break;
      case JALR: {
        const uint64_t t = (x + imm) & ~1ull;
        s.rhs = 0;
        v = here + 4;
        s.next_pc = t;
        s.flags = 1;
        if ((t & 3) || t < j.code_lo || ((t - j.code_lo) >> 2) >= j.slots) bad |= ST_PC_RANGE;
        next = uint32_t((t - j.code_lo) >> 2);
        break;
      }
      default: bad |= ST_SLOW_SLOT; write = false; break;
    }
    // Immediate-only and register-free ops carry the engine's rs fields (0 => r[0] = 0).
    s.result = (op >= SB && op <= BGEU) ? 0 : v;
    if (write) r[rd] = v;
    r[32] = 0;
    store_step(out + k, s);
    i = next;
    if (bad) break;
  }
  if (!bad && seed.check_next) {
    const Seed &nx = j.seeds[c + 1];
    if (j.code_lo + 4ull * i != nx.pc || m != nx.first_mem) bad |= ST_CONTINUITY;
    for (int k = 1; k < 32; ++k)
      if (r[k] != nx.regs[k]) bad |= ST_CONTINUITY;
  } else if (!bad) {
    // The chunk ends at a host step or at the segment end: check the pc it stops at and
    // the memory cursor there; at a host step also the registers it leaves alone.
    const uint32_t end = seed.first_step + n;
    const uint32_t got = i < j.slots ? i : NO_SLOT;
    if (end == seg.steps) {
      if (got != seg.end_slot || m != seg.mem_words) bad |= ST_CONTINUITY;
    } else {
      uint32_t lo = seg.slow_base, hi = seg.slow_base + seg.slow_count;  // first pos >= end
      while (lo < hi) {
        const uint32_t mid = (lo + hi) >> 1;
        if (j.slow[mid].pos < end) lo = mid + 1; else hi = mid;
      }
      if (lo == seg.slow_base + seg.slow_count || j.slow[lo].pos != end) bad |= ST_CONTINUITY;  // ends at nothing
      else {
        const SlowStep &h = j.slow[lo];
        if (got != h.pc_slot) bad |= ST_CONTINUITY;
        if (h.step.memory_index != NO_MEMORY && h.step.memory_index != m) bad |= ST_CONTINUITY;
        if (h.rd < 32 && r[h.rd] != h.step.previous_rd) bad |= ST_CONTINUITY;
        // hostStep seeds the state right after every host step; it survives in `seeds`
        // unless another host step follows at once.
        if (c + 1 < j.chunks && j.chunk_seg[c + 1] == j.chunk_seg[c] && j.seeds[c + 1].first_step == end + 1) {
          const Seed &nx = j.seeds[c + 1];
          if (nx.pc != h.step.next_pc || nx.first_mem != m + (h.step.memory_index != NO_MEMORY)) bad |= ST_CONTINUITY;
          for (int k = 1; k < 32; ++k)
            if (k != h.rd && r[k] != nx.regs[k]) bad |= ST_CONTINUITY;
        }
      }
    }
  }
  if (bad) atomicOr(j.status, bad);
}

__global__ void scatter_slow(const SlowStep *slow, const uint64_t *slow_out_base, uint32_t n, Step *out) {
  const uint32_t t = blockIdx.x * blockDim.x + threadIdx.x;
  if (t >= n) return;
  // SlowStep is 64 B: its embedded step (offset 8) is only 8 B aligned, so copy it out first.
  const Step s = slow[t].step;
  store_step(out + slow_out_base[t] + slow[t].pos, s);
}

}  // namespace m9

extern "C" int stwo_rv64_m9_gpu_replay_on(cudaStream_t stream, const m9::Job *job, const m9::SlowStep *slow,
                                          const uint64_t *slow_out_base, uint32_t slow_count) {
  if (!job || !job->rom || !job->seeds || !job->segs || !job->out || !job->status || (slow_count && !job->slow)) return int(cudaErrorInvalidValue);
  if (job->chunks) m9::replay<<<(job->chunks + 127) / 128, 128, 0, stream>>>(*job);
  if (slow_count) m9::scatter_slow<<<(slow_count + 255) / 256, 256, 0, stream>>>(slow, slow_out_base, slow_count, job->out);
  return int(cudaPeekAtLastError());
}

#ifdef M9_STANDALONE
// ---------------------------------------------------------------------------------------
// Standalone harness: m9_gpu_replay DUMP_DIR [ITERS] [SEGMENT|-1]
//   loads rom/seeds/mem/slow of every segment, replays all chunks (or one segment) on the
//   GPU, times with CUDA events, checks SHA-256 of each segment's steps against the CPU
//   recorder's digest in meta.txt and, where seg<k>.ref exists, compares byte for byte.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace sha {
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
static inline uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static void block(uint32_t h[8], const uint8_t *p) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i) w[i] = uint32_t(p[4 * i]) << 24 | uint32_t(p[4 * i + 1]) << 16 | uint32_t(p[4 * i + 2]) << 8 | p[4 * i + 3];
  for (int i = 16; i < 64; ++i) {
    const uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int i = 0; i < 64; ++i) {
    const uint32_t t1 = hh + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
    const uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}
static std::string hex(const uint8_t *data, size_t n) {
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  size_t i = 0;
  for (; i + 64 <= n; i += 64) block(h, data + i);
  uint8_t tail[128] = {0};
  const size_t rem = n - i;
  memcpy(tail, data + i, rem);
  tail[rem] = 0x80;
  const size_t tl = rem < 56 ? 64 : 128;
  const uint64_t bits = uint64_t(n) * 8;
  for (int k = 0; k < 8; ++k) tail[tl - 1 - k] = uint8_t(bits >> (8 * k));
  block(h, tail);
  if (tl == 128) block(h, tail + 64);
  char s[65];
  for (int k = 0; k < 8; ++k) snprintf(s + 8 * k, 9, "%08x", h[k]);
  return std::string(s, 64);
}
}  // namespace sha

#define CK(x)                                                                              \
  do {                                                                                     \
    cudaError_t e_ = (x);                                                                  \
    if (e_ != cudaSuccess) { fprintf(stderr, "CUDA %s at %d: %s\n", #x, __LINE__, cudaGetErrorString(e_)); exit(2); } \
  } while (0)

static std::vector<uint8_t> slurp(const std::string &path, bool must = true) {
  std::vector<uint8_t> v;
  FILE *f = fopen(path.c_str(), "rb");
  if (!f) { if (must) { fprintf(stderr, "missing %s\n", path.c_str()); exit(2); } return v; }
  fseek(f, 0, SEEK_END);
  v.resize(size_t(ftell(f)));
  fseek(f, 0, SEEK_SET);
  if (!v.empty() && fread(v.data(), 1, v.size(), f) != v.size()) { fprintf(stderr, "short read %s\n", path.c_str()); exit(2); }
  fclose(f);
  return v;
}
template <class T> static T *upload(const std::vector<T> &v) {
  T *d = nullptr;
  CK(cudaMalloc(&d, std::max<size_t>(v.size() * sizeof(T), 16)));
  if (!v.empty()) CK(cudaMemcpy(d, v.data(), v.size() * sizeof(T), cudaMemcpyHostToDevice));
  return d;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s DUMP_DIR [ITERS] [SEGMENT|-1]\n", argv[0]); return 2; }
  const std::string dir = argv[1];
  const int iters = argc > 2 ? atoi(argv[2]) : 10;
  const int only = argc > 3 ? atoi(argv[3]) : -1;
  std::vector<uint8_t> meta = slurp(dir + "/meta.txt");
  meta.push_back(0);
  uint64_t code_lo = 0, slots = 0, chunk = 0, nseg = 0;
  struct SegMeta { uint64_t steps, seeds, words, slow; std::string sha; uint64_t end_slot; };
  std::vector<SegMeta> sm;
  {
    char *save = nullptr;
    for (char *line = strtok_r(reinterpret_cast<char *>(meta.data()), "\n", &save); line; line = strtok_r(nullptr, "\n", &save)) {
      char key[32], shabuf[80];
      unsigned long long a0, a1, a2, a3, a4, a5;
      if (sscanf(line, "seg %llu %llu %llu %llu %llu %70s %llu", &a0, &a1, &a2, &a3, &a4, shabuf, &a5) == 7) {
        sm.push_back({a1, a2, a3, a4, shabuf, a5});
      } else if (sscanf(line, "%31s %llu", key, &a0) == 2) {
        if (!strcmp(key, "code_lo")) code_lo = a0;
        if (!strcmp(key, "slots")) slots = a0;
        if (!strcmp(key, "chunk")) chunk = a0;
        if (!strcmp(key, "segments")) nseg = a0;
      }
    }
  }
  if (sm.size() != nseg) { fprintf(stderr, "meta: %zu segment rows, %llu declared\n", sm.size(), (unsigned long long)nseg); return 2; }
  std::vector<uint8_t> rom_b = slurp(dir + "/rom.bin");
  if (rom_b.size() != slots * sizeof(m9::Slot)) { fprintf(stderr, "rom size\n"); return 2; }
  std::vector<m9::Seed> seeds;
  std::vector<uint32_t> chunk_seg;
  std::vector<m9::Segment> segs;
  std::vector<uint64_t> mem;
  std::vector<m9::SlowStep> slow;
  std::vector<uint64_t> slow_base;
  uint64_t out_total = 0;
  for (uint64_t k = 0; k < nseg; ++k) {
    if (only >= 0 && int(k) != only) { segs.push_back({0, 0, 0, 0, 0, 0, m9::NO_SLOT, 0}); continue; }
    auto sb = slurp(dir + "/seg" + std::to_string(k) + ".seeds");
    auto mb = slurp(dir + "/seg" + std::to_string(k) + ".mem");
    auto lb = slurp(dir + "/seg" + std::to_string(k) + ".slow");
    const size_t s0 = seeds.size(), l0 = slow.size(), m0 = mem.size();
    segs.push_back({out_total, m0, uint32_t(sm[k].steps), uint32_t(mb.size() / 8), uint32_t(l0), uint32_t(lb.size() / sizeof(m9::SlowStep)), uint32_t(sm[k].end_slot), 0});
    seeds.resize(s0 + sb.size() / sizeof(m9::Seed));
    memcpy(seeds.data() + s0, sb.data(), sb.size());
    chunk_seg.resize(seeds.size(), uint32_t(k));
    mem.resize(m0 + mb.size() / 8);
    memcpy(mem.data() + m0, mb.data(), mb.size());
    slow.resize(l0 + lb.size() / sizeof(m9::SlowStep));
    memcpy(slow.data() + l0, lb.data(), lb.size());
    slow_base.resize(slow.size(), out_total);
    out_total += sm[k].steps;
  }
  // M9_INJECT=<kind>: corrupt one input to show the status guard fires (expects status != 0).
  //   pc / mem: the host step right after the first chunk that ends at a host step (with a
  //   memory word, for mem): its pc_slot / memory index; end: end_slot of the first
  //   segment whose last chunk ends at the segment end; reg / regh: see below.
  if (const char *inj = getenv("M9_INJECT")) {
    const std::string w = inj;
    bool done = false;
    for (size_t c = 0; c < seeds.size() && !done && (w == "pc" || w == "mem"); ++c) {
      if (seeds[c].check_next) continue;
      const m9::Segment &sg = segs[chunk_seg[c]];
      const uint32_t end = seeds[c].first_step + seeds[c].steps;
      for (uint32_t h = sg.slow_base; h < sg.slow_base + sg.slow_count; ++h) {
        if (slow[h].pos != end) continue;
        if (w == "pc") { slow[h].pc_slot ^= 1; done = true; }
        if (w == "mem" && slow[h].step.memory_index != m9::NO_MEMORY) { slow[h].step.memory_index += 1; done = true; }
        break;
      }
    }
    for (size_t c = 0; c < seeds.size() && !done && w == "end"; ++c) {
      m9::Segment &sg = segs[chunk_seg[c]];
      if (!seeds[c].check_next && seeds[c].first_step + seeds[c].steps == sg.steps) { sg.end_slot ^= 1; done = true; }
    }
    // reg: a0 of a seed that a continuity-checked chunk ends at; regh: of a seed right
    // after a host step that a chunk ends at (checks the registers across host steps).
    for (size_t c = 0; c + 1 < seeds.size() && !done && (w == "reg" || w == "regh"); ++c) {
      if (chunk_seg[c] != chunk_seg[c + 1]) continue;
      const uint32_t end = seeds[c].first_step + seeds[c].steps;
      if (w == "reg" && seeds[c].check_next) { seeds[c + 1].regs[10] ^= 1; done = true; }
      if (w == "regh" && !seeds[c].check_next && seeds[c + 1].first_step == end + 1) {
        const m9::Segment &sg = segs[chunk_seg[c]];
        for (uint32_t h = sg.slow_base; h < sg.slow_base + sg.slow_count; ++h)
          if (slow[h].pos == end && slow[h].rd != 10) { seeds[c + 1].regs[10] ^= 1; done = true; break; }
      }
    }
    fprintf(stderr, "M9_INJECT=%s applied=%d\n", inj, int(done));
  }
  // Count the chunks each guard covers (for the report).
  uint64_t ends_seed = 0, ends_host = 0, ends_segment = 0;
  for (auto &sd : seeds) {
    if (sd.check_next) ++ends_seed;
    else if (sd.first_step + sd.steps == segs[chunk_seg[&sd - seeds.data()]].steps) ++ends_segment;
    else ++ends_host;
  }
  // Chunk-step histogram (for the report).
  uint64_t chunk_steps = 0, max_chunk = 0;
  for (auto &s : seeds) { chunk_steps += s.steps; max_chunk = std::max<uint64_t>(max_chunk, s.steps); }
  int dev = 0;
  CK(cudaSetDevice(dev));
  cudaDeviceProp prop{};
  CK(cudaGetDeviceProperties(&prop, dev));
  m9::Job j{};
  j.rom = reinterpret_cast<const m9::Slot *>(upload(rom_b));
  j.code_lo = code_lo;
  j.slots = uint32_t(slots);
  j.chunks = uint32_t(seeds.size());
  j.seeds = upload(seeds);
  j.chunk_seg = upload(chunk_seg);
  j.segs = upload(segs);
  j.mem = upload(mem);
  const m9::SlowStep *d_slow = upload(slow);
  const uint64_t *d_slow_base = upload(slow_base);
  j.slow = d_slow;
  m9::Step *d_out = nullptr;
  CK(cudaMalloc(&d_out, out_total * sizeof(m9::Step)));
  j.out = d_out;
  uint32_t *d_status = nullptr;
  CK(cudaMalloc(&d_status, 4));
  j.status = d_status;
  cudaStream_t st;
  CK(cudaStreamCreate(&st));
  cudaEvent_t e0, e1;
  CK(cudaEventCreate(&e0));
  CK(cudaEventCreate(&e1));
  std::vector<float> ms;
  for (int it = 0; it < iters + 2; ++it) {
    CK(cudaMemsetAsync(d_status, 0, 4, st));
    CK(cudaMemsetAsync(d_out, 0xa5, out_total * sizeof(m9::Step), st));
    CK(cudaEventRecord(e0, st));
    CK(cudaError_t(stwo_rv64_m9_gpu_replay_on(st, &j, d_slow, d_slow_base, uint32_t(slow.size()))));
    CK(cudaEventRecord(e1, st));
    CK(cudaEventSynchronize(e1));
    float t = 0;
    CK(cudaEventElapsedTime(&t, e0, e1));
    if (it >= 2) ms.push_back(t);
  }
  uint32_t status = 0;
  CK(cudaMemcpy(&status, d_status, 4, cudaMemcpyDeviceToHost));
  std::vector<m9::Step> out(out_total);
  CK(cudaMemcpy(out.data(), d_out, out_total * sizeof(m9::Step), cudaMemcpyDeviceToHost));
  std::sort(ms.begin(), ms.end());
  const double med = ms[ms.size() / 2];
  // Parity per segment.
  int ok = 0, checked = 0;
  std::string rows;
  for (uint64_t k = 0; k < nseg; ++k) {
    if (only >= 0 && int(k) != only) continue;
    const uint8_t *p = reinterpret_cast<const uint8_t *>(out.data() + segs[k].out_base);
    const size_t n = sm[k].steps * sizeof(m9::Step);
    const std::string got = sha::hex(p, n);
    const bool same = got == sm[k].sha;
    ++checked;
    ok += same;
    long long first_diff = -1;
    auto ref = slurp(dir + "/seg" + std::to_string(k) + ".ref", false);
    if (!ref.empty()) {
      if (ref.size() != n) first_diff = -2;
      else for (size_t b = 0; b < n; ++b) if (ref[b] != p[b]) { first_diff = (long long)(b / sizeof(m9::Step)); break; }
      if (first_diff >= 0) {
        const m9::Step *rs = reinterpret_cast<const m9::Step *>(ref.data()) + first_diff, *gs = out.data() + segs[k].out_base + first_diff;
        fprintf(stderr, "seg %llu step %lld: ref{npc %llx lhs %llx rhs %llx prd %llx res %llx mi %u f %u} gpu{npc %llx lhs %llx rhs %llx prd %llx res %llx mi %u f %u}\n",
                (unsigned long long)k, first_diff, (unsigned long long)rs->next_pc, (unsigned long long)rs->lhs, (unsigned long long)rs->rhs, (unsigned long long)rs->previous_rd, (unsigned long long)rs->result, rs->memory_index, rs->flags,
                (unsigned long long)gs->next_pc, (unsigned long long)gs->lhs, (unsigned long long)gs->rhs, (unsigned long long)gs->previous_rd, (unsigned long long)gs->result, gs->memory_index, gs->flags);
      }
    }
    char buf[256];
    snprintf(buf, sizeof buf, "%s{\"segment\": %llu, \"steps\": %llu, \"sha256_match\": %s, \"ref_bytes_compared\": %s, \"first_diff\": %lld}", rows.empty() ? "" : ", ",
             (unsigned long long)k, (unsigned long long)sm[k].steps, same ? "true" : "false", ref.empty() ? "false" : "true", first_diff);
    rows += buf;
  }
  const double in_bytes = double(seeds.size() * sizeof(m9::Seed) + mem.size() * 8 + slow.size() * sizeof(m9::SlowStep));
  printf("{\"scope\": \"M9 GPU replay prototype kernel (thread per chunk)\", \"gpu\": \"%s\", \"dump\": \"%s\", \"chunk_target\": %llu, \"segment\": %d, \"steps\": %llu, \"chunks\": %zu, \"mean_chunk_steps\": %.1f, \"max_chunk_steps\": %llu, \"host_steps\": %zu,"
         " \"iters\": %zu, \"kernel_ms_median\": %.3f, \"kernel_ms_min\": %.3f, \"kernel_ms_max\": %.3f, \"gpu_mips\": %.0f, \"input_bytes\": %.0f, \"output_bytes\": %llu, \"status\": %u, \"chunk_ends\": {\"seed\": %llu, \"host_step\": %llu, \"segment_end\": %llu}, \"segments_sha_match\": \"%d/%d\", \"rows\": [%s]}\n",
         prop.name, dir.c_str(), (unsigned long long)chunk, only, (unsigned long long)out_total, seeds.size(), double(chunk_steps) / std::max<size_t>(1, seeds.size()), (unsigned long long)max_chunk, slow.size(),
         ms.size(), med, ms.front(), ms.back(), double(out_total) / (med * 1e3), in_bytes, (unsigned long long)(out_total * sizeof(m9::Step)), status,
         (unsigned long long)ends_seed, (unsigned long long)ends_host, (unsigned long long)ends_segment, ok, checked, rows.c_str());
  return (status == 0 && ok == checked) ? 0 : 1;
}
#endif
