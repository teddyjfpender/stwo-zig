// GPU-native recursion node: device seed fill from the children's encoded
// slab regions + the fold statement / transcript checkpoint (M8 gn-node,
// design rv64-m8-gpu-native.md §3.3, host work H16/H17/H19). Host side, ABI
// and the bit-exact host mirror: integrations/riscv_cuda/rv64/jobs/
// outer_seed_device.zig (fillHost / statementHost).
//
// Inputs: a per-class seed program (built at warm), the children's regions
// ([byte length][om31 wire words][PCS readback image at a class offset]).
// Outputs: the node's assignment seed records {var, limb0..3} (the exact
// values fold_tape.record / leaf_tape emit on the host), the fold's outputs
// and its transcript checkpoint, and two Verdict words: seed_tape (0x0305)
// and child_binding (0x0306).
//
// Four launches, enqueue only, fixed per class (graph-capturable):
//   begin    <<<1,32>>>          program / region / image header checks
//   caps     <<<n_caps,128>>>    Merkle caps (fromNativeCapped + hostCap):
//                                leaf hash + walk per query, cap assembly,
//                                coverage, cap -> committed root
//   gather   <<<n_ops+1,256>>>   one block per op (+ constants)
//   finish   <<<1,1>>>           seed_tape word; fold statement + checkpoint
// Several refusals: the lowest detail rank wins (atomicMin), as in the mirror.
#include "rv64/custody.cuh"
#include "commitment/blake2s_core.cuh"
#include <stdint.h>

struct StwoRv64OuterSeedIo {
  const uint32_t *program;
  uint64_t program_words;
  const uint32_t *children[8];
  uint64_t children_words[8];
  uint32_t *seeds;
  uint64_t seeds_words;
  uint32_t *scratch;
  uint64_t scratch_words;
  uint32_t *seed_status;
  uint32_t *bind_status;  // fold statement outputs (optional, with outputs + checkpoint)
  uint32_t *outputs;
  uint32_t *checkpoint;
  uint32_t *outputs_copy;     // optional second copies
  uint32_t *checkpoint_copy;
  uint32_t outputs_words;
  uint32_t n_children;
  uint32_t n_ops;  // host copies of the program's n_ops / n_caps (launch geometry)
  uint32_t n_caps;
};
static_assert(sizeof(StwoRv64OuterSeedIo) == 240, "outer seed Io ABI");

namespace stwo::cuda::rv64 {
namespace {
constexpr uint32_t kModulus = 0x7fffffffu;
constexpr uint32_t kSeedTape = 0x0305u, kChildBinding = 0x0306u;
constexpr uint32_t kProgramMagic = 0x3144534fu, kImageMagic = 0x52564d4fu;
constexpr uint32_t kWireMagic0 = 0x4f575453u, kWireMagic1 = 0x314d4f43u;
constexpr uint32_t kNone = 0xffffu;
enum : uint32_t {  // outer_seed_device.zig P
  pMagic = 0, pVersion = 1, pWords = 2, pSeeds = 3, pConstants = 4, pChildren = 5, pOps = 6, pOpsAt = 7,
  pVars = 8, pConstantsAt = 9, pCaps = 10, pCapsAt = 11, pScratch = 12, pChildrenAt = 13, pCapLog = 14,
  pTape = 15, pStatement = 16, pDomain = 17, pVersionWord = 18, pOutputs = 19, pPrefix = 20, pSelfKey = 21,
  pProfile = 22, pOutputMap = 23, pOutputsAt = 24, pHeader = 32,
};
enum : uint32_t { cImage = 0, cImageWords = 1, cOutputs = 2, cWireWords = 3, cIdentity = 4, cFixedRoot = 12, cWords = 20 };
enum : uint32_t { kHash = 1, kWord = 2, kM31 = 3, kOm31 = 4, kQ = 5 };
enum : uint32_t { aRegion = 0, aImage = 1, aScratch = 2 };
enum : uint32_t { sProgram = 1, sRegion = 2, sImageHeader = 3, sQueryRange = 4, sNoncanonical = 5, sCapMismatch = 6, sCapUncovered = 7, sCapRoot = 8 };
enum : uint32_t { bRegion = 1, bMagic = 2, bProfile = 3, bIdentity = 4, bOutputs = 5, bFixedRoot = 6, bNoncanonical = 7 };
constexpr uint32_t kRootsAt = 14 + 1 + 16;  // image header + status + state

struct Op { uint32_t kind, child, area, offset, count, stride, rows, row_stride, dst, reserved; };
struct Cap {
  uint32_t kind, child, height, cl, values, width, paths, path_stride, level0, root, scratch, queries, nq;
  uint32_t from_log, to_log, layer_log, pack, reserved[3];
};
static_assert(sizeof(Op) == 40 && sizeof(Cap) == 80, "seed program ABI");

struct Stream {
  uint32_t h[8];
  uint32_t buf[16];
  uint32_t n;
  uint64_t total;
};
__device__ inline void s_init(Stream &s, uint32_t tag) {
  blake2s::initialize(s.h);
  s.n = 0;
  s.total = 0;
  if (tag) {
    for (int i = 0; i < 16; ++i) s.buf[i] = 0;
    s.buf[0] = tag;
    s.n = 16;
    s.total = 64;
  }
}
__device__ inline void s_word(Stream &s, uint32_t w) {
  if (s.n == 16) {
    blake2s::compress(s.h, s.buf, s.total, 0);
    s.n = 0;
  }
  s.buf[s.n++] = w;
  s.total += 4;
}
__device__ inline void s_final(Stream &s, uint32_t out[8]) {
  for (uint32_t i = s.n; i < 16; ++i) s.buf[i] = 0;
  blake2s::compress(s.h, s.buf, s.total, 0xffffffffu);
  for (int i = 0; i < 8; ++i) out[i] = s.h[i];
}
__device__ inline void node_hash(const uint32_t l[8], const uint32_t r[8], uint32_t out[8]) {
  Stream s;
  s_init(s, blake2s::kNodeTag);
  for (int i = 0; i < 8; ++i) s_word(s, l[i]);
  for (int i = 0; i < 8; ++i) s_word(s, r[i]);
  s_final(s, out);
}
__device__ inline void note(uint32_t *rank, uint32_t d) { atomicMin(rank, d); }

__device__ inline uint32_t lift(uint32_t row, uint32_t from, uint32_t to) {
  return from >= to ? (((row >> (from - to + 1)) << 1) | (row & 1)) : (((row >> 1) << (to - from + 1)) | (row & 1));
}

__global__ void seed_begin(StwoRv64OuterSeedIo io) {
  uint32_t *rank = io.scratch + (io.scratch_words - 8);
  if (threadIdx.x == 0) *rank = kNone;
  __syncthreads();
  const uint32_t *p = io.program;
  if (p[pMagic] != kProgramMagic || p[pVersion] != 1 || p[pWords] != io.program_words || p[pChildren] != io.n_children ||
      p[pOps] != io.n_ops || p[pCaps] != io.n_caps ||
      io.seeds_words < 5ull * p[pSeeds] || io.scratch_words < uint64_t(p[pScratch]) + 8) {
    if (threadIdx.x == 0) note(rank, sProgram);
    return;
  }
  const uint32_t k = threadIdx.x;
  if (k >= io.n_children) return;
  const uint32_t *e = p + p[pChildrenAt] + k * cWords;
  const uint32_t *r = io.children[k];
  if (!r || io.children_words[k] < uint64_t(e[cImage]) + e[cImageWords] || e[cImageWords] < kRootsAt + 8) {
    note(rank, sRegion);
    return;
  }
  if (r[0] == 0) note(rank, sRegion);
  const uint32_t *img = r + e[cImage];
  if (img[0] != kImageMagic || img[1] != 2) note(rank, sImageHeader);
}

// One block per cap job; one thread per query (strided).
__global__ void seed_caps(StwoRv64OuterSeedIo io) {
  uint32_t *rank = io.scratch + (io.scratch_words - 8);
  if (*rank <= sImageHeader) return;
  const uint32_t *p = io.program;
  const Cap c = reinterpret_cast<const Cap *>(p + p[pCapsAt])[blockIdx.x];
  const uint32_t *e = p + p[pChildrenAt] + c.child * cWords;
  const uint32_t *img = io.children[c.child] + e[cImage];
  const uint32_t n_cap = 1u << c.cl;
  __shared__ uint32_t at_of[1024];
  __shared__ uint32_t nodes[1024][8];
  __shared__ int bad;
  if (threadIdx.x == 0) bad = 0;
  __syncthreads();
  const uint32_t walk = c.height - c.cl;
  for (uint32_t qi = threadIdx.x; qi < c.nq; qi += blockDim.x) {
    const uint32_t q = img[c.queries + qi];
    uint32_t node[8];
    uint32_t pos;
    if (c.kind == 0) {
      if (c.from_log >= 32 || q >= (1u << c.from_log)) {
        note(rank, sQueryRange);
        bad = 1;
        at_of[qi] = 0xffffffffu;
        continue;
      }
      Stream s;
      s_init(s, blake2s::kLeafTag);
      for (uint32_t ci = 0; ci < c.width; ++ci) {
        const uint32_t v = img[c.values + ci * c.nq + qi];
        if (v >= kModulus) note(rank, sNoncanonical);
        s_word(s, v);
      }
      s_final(s, node);
      pos = lift(q, c.from_log, c.to_log);
    } else {
      const uint32_t *vals = img + c.values + qi * c.width * 8;
      const uint32_t width = c.pack ? 4 : 1;
      const uint32_t n_leaves = c.width / width;
      uint32_t level[16][8];
      for (uint32_t i = 0; i < n_leaves; ++i) {
        Stream s;
        s_init(s, blake2s::kLeafTag);
        for (uint32_t j = 0; j < width * 8; ++j) {
          const uint32_t v = vals[i * width * 8 + j];
          if (v >= kModulus) note(rank, sNoncanonical);
          s_word(s, v);
        }
        s_final(s, level[i]);
      }
      const uint32_t nfolds = c.to_log - (c.pack ? 2 : 0);
      uint32_t n = n_leaves;
      for (uint32_t f = 0; f < nfolds; ++f) {
        n /= 2;
        for (uint32_t i = 0; i < n; ++i) node_hash(level[2 * i], level[2 * i + 1], level[i]);
      }
      for (int i = 0; i < 8; ++i) node[i] = level[0][i];
      pos = (q >> c.from_log) >> c.to_log;
    }
    const uint32_t *path = img + c.paths + qi * c.path_stride;
    for (uint32_t l = 0; l < walk; ++l) {
      uint32_t next[8];
      if ((pos >> l) & 1) node_hash(path + l * 8, node, next);
      else node_hash(node, path + l * 8, next);
      for (int i = 0; i < 8; ++i) node[i] = next[i];
    }
    if (c.cl == 0) {  // full path: the walk must end at the committed root
      for (int i = 0; i < 8; ++i)
        if (node[i] != img[c.root + i]) {
          note(rank, sCapRoot);
          break;
        }
      at_of[qi] = 0;
      continue;
    }
    const uint32_t at = pos >> walk;
    if (at >= n_cap) {
      note(rank, sQueryRange);
      bad = 1;
      at_of[qi] = 0xffffffffu;
      continue;
    }
    at_of[qi] = at;
    for (int i = 0; i < 8; ++i) nodes[qi][i] = node[i];
  }
  __syncthreads();
  if (threadIdx.x != 0 || bad || c.cl == 0) return;
  // Assemble in query order (the host's first-writer wins, later must agree).
  uint32_t *cap = io.scratch + c.scratch;
  uint64_t known = 0;
  for (uint32_t qi = 0; qi < c.nq; ++qi) {
    const uint32_t at = at_of[qi];
    const uint32_t *sib = img + c.paths + qi * c.path_stride + walk * 8;
    const uint32_t idx[2] = {at, at ^ 1u};
    for (int k = 0; k < 2; ++k) {
      const uint32_t *h = k == 0 ? nodes[qi] : sib;
      if (known >> idx[k] & 1) {
        for (int i = 0; i < 8; ++i)
          if (cap[idx[k] * 8 + i] != h[i]) {
            note(rank, sCapMismatch);
            break;
          }
      } else {
        for (int i = 0; i < 8; ++i) cap[idx[k] * 8 + i] = h[i];
        known |= 1ull << idx[k];
      }
    }
  }
  const uint64_t all = n_cap == 64 ? ~0ull : ((1ull << n_cap) - 1);
  if ((known & all) != all) {
    note(rank, sCapUncovered);
    return;
  }
  uint32_t layer[64][8];
  for (uint32_t i = 0; i < n_cap; ++i)
    for (int j = 0; j < 8; ++j) layer[i][j] = cap[i * 8 + j];
  for (uint32_t n = n_cap; n > 1;) {
    n /= 2;
    for (uint32_t i = 0; i < n; ++i) node_hash(layer[2 * i], layer[2 * i + 1], layer[i]);
  }
  for (int i = 0; i < 8; ++i)
    if (layer[0][i] != img[c.root + i]) {
      note(rank, sCapRoot);
      return;
    }
}

__device__ inline void put(uint32_t *out, const uint32_t *vars, uint32_t i, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
  uint32_t *r = out + 5ull * i;
  r[0] = vars[i];
  r[1] = a;
  r[2] = b;
  r[3] = c;
  r[4] = d;
}

// Block b < n_ops: op b; block n_ops: the class constants.
__global__ void seed_gather(StwoRv64OuterSeedIo io) {
  uint32_t *rank = io.scratch + (io.scratch_words - 8);
  if (*rank <= sImageHeader) return;
  const uint32_t *p = io.program;
  const uint32_t *vars = p + p[pVars];
  if (blockIdx.x == p[pOps]) {
    const uint32_t *k = p + p[pConstantsAt];
    for (uint32_t i = threadIdx.x; i < p[pConstants]; i += blockDim.x) put(io.seeds, vars, i, k[4 * i], k[4 * i + 1], k[4 * i + 2], k[4 * i + 3]);
    return;
  }
  const Op o = reinterpret_cast<const Op *>(p + p[pOpsAt])[blockIdx.x];
  const uint32_t *e = p + p[pChildrenAt] + o.child * cWords;
  const uint32_t *src;
  uint64_t len;
  if (o.area == aRegion) {
    src = io.children[o.child];
    len = io.children_words[o.child];
  } else if (o.area == aImage) {
    src = io.children[o.child] + e[cImage];
    len = e[cImageWords];
  } else {
    src = io.scratch;
    len = p[pScratch];
  }
  const uint32_t per = (o.kind == kHash || o.kind == kOm31) ? 8 : (o.kind == kQ ? 4 : 1);
  const uint32_t seeds_per = o.kind == kHash ? 16 : ((o.kind == kWord || o.kind == kOm31) ? 2 : 1);
  const uint64_t units = uint64_t(o.count) * o.rows;
  for (uint64_t u = threadIdx.x; u < units; u += blockDim.x) {
    const uint32_t r = uint32_t(u / o.count), x = uint32_t(u % o.count);
    const uint64_t s = uint64_t(o.offset) + uint64_t(r) * o.row_stride + uint64_t(x) * o.stride;
    if (s + per > len) {
      note(rank, sProgram);
      return;
    }
    const uint32_t *v = src + s;
    const uint32_t d = o.dst + uint32_t(u) * seeds_per;
    switch (o.kind) {
      case kHash:
        for (int i = 0; i < 8; ++i) {
          put(io.seeds, vars, d + 2 * i, v[i] & 0xffffu, 0, 0, 0);
          put(io.seeds, vars, d + 2 * i + 1, v[i] >> 16, 0, 0, 0);
        }
        break;
      case kWord:
        put(io.seeds, vars, d, v[0] & 0xffffu, 0, 0, 0);
        put(io.seeds, vars, d + 1, v[0] >> 16, 0, 0, 0);
        break;
      case kM31:
        if (v[0] >= kModulus) note(rank, sNoncanonical);
        put(io.seeds, vars, d, v[0], 0, 0, 0);
        break;
      case kOm31:
        for (int i = 0; i < 8; ++i)
          if (v[i] >= kModulus) note(rank, sNoncanonical);
        put(io.seeds, vars, d, v[0], v[1], v[2], v[3]);
        put(io.seeds, vars, d + 1, v[4], v[5], v[6], v[7]);
        break;
      case kQ:
        for (int i = 0; i < 4; ++i)
          if (v[i] >= kModulus) note(rank, sNoncanonical);
        put(io.seeds, vars, d, v[0], v[1], v[2], v[3]);
        break;
      default:
        note(rank, sProgram);
        return;
    }
  }
}

__global__ void seed_finish(StwoRv64OuterSeedIo io) {
  uint32_t *rank = io.scratch + (io.scratch_words - 8);
  const uint32_t worst = *rank;
  *io.seed_status = worst == kNone ? 0u : ((kSeedTape << 16) | worst);
  if (!io.bind_status) return;
  const uint32_t *p = io.program;
  const uint32_t kind = p[pStatement];
  const uint32_t n_self = p[pOutputs];
  if (worst <= sImageHeader || (kind != 1 && kind != 2) || io.outputs_words < 4 * n_self) {
    *io.bind_status = (kChildBinding << 16) | bRegion;
    return;
  }
  uint32_t bworst = kNone;
  if (kind == 2) {
    const uint32_t at = p[pOutputsAt];
    if (io.children_words[0] < uint64_t(at) + 4 * n_self) {
      *io.bind_status = (kChildBinding << 16) | bRegion;
      return;
    }
    const uint32_t *r = io.children[0];
    for (uint32_t i = 0; i < 4 * n_self; ++i) {
      if (r[at + i] >= kModulus) bworst = min(bworst, uint32_t(bNoncanonical));
      io.outputs[i] = r[at + i];
    }
  } else {
    Stream m;
    s_init(m, 0);
    s_word(m, p[pDomain]);
    s_word(m, p[pVersionWord]);
    const uint32_t *profile = p + p[pProfile];
    for (uint32_t k = 0; k < io.n_children; ++k) {
      const uint32_t *e = p + p[pChildrenAt] + k * cWords;
      const uint32_t *r = io.children[k];
      const uint32_t n_out = e[cOutputs];
      if (r[0] < 4u * (19 + 4 * n_out) || e[cImage] < 20 + 4 * n_out) {
        bworst = min(bworst, uint32_t(bRegion));
        continue;
      }
      if (r[1] != kWireMagic0 || r[2] != kWireMagic1) bworst = min(bworst, uint32_t(bMagic));
      for (int i = 0; i < 8; ++i) {
        if (r[3 + i] != profile[i]) bworst = min(bworst, uint32_t(bProfile));
        if (r[11 + i] != e[cIdentity + i]) bworst = min(bworst, uint32_t(bIdentity));
      }
      if (r[19] != n_out) bworst = min(bworst, uint32_t(bOutputs));
      const uint32_t *img = r + e[cImage];
      for (int i = 0; i < 8; ++i)
        if (img[kRootsAt + i] != e[cFixedRoot + i]) bworst = min(bworst, uint32_t(bFixedRoot));
      for (uint32_t i = 0; i < 4 * n_out; ++i)
        if (r[20 + i] >= kModulus) bworst = min(bworst, uint32_t(bNoncanonical));
      for (int i = 0; i < 8; ++i) s_word(m, r[11 + i]);
      for (int i = 0; i < 8; ++i) s_word(m, img[kRootsAt + i]);
      s_word(m, n_out);
      for (uint32_t i = 0; i < 4 * n_out; ++i) s_word(m, r[20 + i]);
    }
    uint32_t digest[8];
    s_final(m, digest);
    for (uint32_t i = 0; i < n_self; ++i) {
      const uint32_t v = i < 8 ? digest[i] : 0;
      io.outputs[4 * i] = v & 0xffffu;
      io.outputs[4 * i + 1] = v >> 16;
      io.outputs[4 * i + 2] = 0;
      io.outputs[4 * i + 3] = 0;
    }
  }
  const uint32_t *self_key = p + p[pSelfKey];
  Stream c1;
  s_init(c1, 0);
  for (int i = 0; i < 8; ++i) s_word(c1, p[p[pPrefix] + i]);
  for (int i = 0; i < 8; ++i) s_word(c1, self_key[i]);
  s_word(c1, n_self);
  for (uint32_t i = 0; i < 4 * n_self; ++i) s_word(c1, io.outputs[i]);
  uint32_t d1[8];
  s_final(c1, d1);
  Stream c2;
  s_init(c2, 0);
  for (int i = 0; i < 8; ++i) s_word(c2, d1[i]);
  for (int i = 0; i < 8; ++i) s_word(c2, self_key[8 + i]);
  uint32_t d2[8];
  s_final(c2, d2);
  for (int i = 0; i < 8; ++i) io.checkpoint[i] = d2[i];
  io.checkpoint[8] = 0;
  if (io.checkpoint_copy)
    for (int i = 0; i < 9; ++i) io.checkpoint_copy[i] = io.checkpoint[i];
  if (io.outputs_copy)
    for (uint32_t i = 0; i < 4 * n_self; ++i) io.outputs_copy[i] = io.outputs[i];
  *io.bind_status = bworst == kNone ? 0u : ((kChildBinding << 16) | bworst);
}
}  // namespace
}  // namespace stwo::cuda::rv64

extern "C" int stwo_rv64_outer_seed_fill_v1_on(void *context, uint32_t lane, const StwoRv64OuterSeedIo *io) {
  using namespace stwo::cuda::rv64;
  if (!io || !io->program || io->program_words < pHeader || !io->n_children || io->n_children > 8 ||
      io->scratch_words < 16)
    return int(cudaErrorInvalidValue);
  RangeCustody<20> custody(context, lane);
  bool ok = custody.range(io->program, io->program_words, false);
  for (uint32_t k = 0; k < io->n_children && ok; ++k) ok = custody.range(io->children[k], io->children_words[k], false);
  ok = ok && custody.range(io->seeds, io->seeds_words, true) && custody.range(io->scratch, io->scratch_words, true) &&
       custody.range(io->seed_status, 1, true);
  if (ok && io->bind_status)
    ok = custody.range(io->bind_status, 1, true) && custody.range(io->outputs, io->outputs_words, true) &&
         custody.range(io->checkpoint, 9, true);
  if (ok && io->bind_status && io->outputs_copy) ok = custody.range(io->outputs_copy, io->outputs_words, true);
  if (ok && io->bind_status && io->checkpoint_copy) ok = custody.range(io->checkpoint_copy, 9, true);
  if (!ok) return custody.status ? custody.status : int(cudaErrorInvalidValue);
  seed_begin<<<1, 32, 0, custody.stream>>>(*io);
  if (io->n_caps) seed_caps<<<io->n_caps, 128, 0, custody.stream>>>(*io);
  seed_gather<<<io->n_ops + 1, 256, 0, custody.stream>>>(*io);
  seed_finish<<<1, 1, 0, custody.stream>>>(*io);
  return int(cudaPeekAtLastError());
}

extern "C" uint32_t stwo_rv64_outer_seed_version(void) { return 1; }
