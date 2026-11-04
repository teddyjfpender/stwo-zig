// Adversarial check of the eager (SoA) Blake2s prefix-state chain: for many
// split plans, the eager chain, the classic chain and the single unchunked
// mixed leaf call must give identical leaf hashes. Prefix banks are poisoned
// so a read of an unwritten state word changes the result.
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "commitment/mixed_layout.h"
using stwo::cuda::blake2s::MixedSegment;
extern "C" int stwo_blake2s_mixed_leaf_on(uint32_t, uint32_t, const MixedSegment *, void *, void *);
extern "C" int stwo_blake2s_mixed_seeded_on(uint32_t, uint32_t, const MixedSegment *, uint32_t, uint32_t, const void *, void *, void *, void *);
extern "C" int stwo_blake2s_mixed_seeded_eager_on(uint32_t, uint32_t, const MixedSegment *, uint32_t, uint32_t, const void *, void *, void *, void *);
#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { std::printf("CUDAERR %s:%d %s\n", __FILE__, __LINE__, cudaGetErrorString(e_)); std::exit(2);} } while (0)
__global__ void fill(uint32_t *x, size_t n, uint64_t seed) {
  for (size_t i = blockIdx.x * size_t(blockDim.x) + threadIdx.x; i < n; i += size_t(gridDim.x) * blockDim.x) {
    uint64_t z = (i + 1) * 0x9E3779B97F4A7C15ull ^ (seed * 0xD1B54A32D192ED03ull);
    z ^= z >> 31; z *= 0xBF58476D1CE4E5B9ull; z ^= z >> 29;
    x[i] = uint32_t(z % 2147483647ull);
  }
}
struct Col { uint32_t log, cols; };
// calls: number of column-groups (entries of `groups`) per call, in order.
struct Case { const char *name; uint32_t leaves_log; std::vector<Col> groups; std::vector<uint32_t> calls; };
using Fn = int (*)(uint32_t, uint32_t, const MixedSegment *, uint32_t, uint32_t, const void *, void *, void *, void *);
static std::vector<uint32_t> chain(Fn fn, const Case &c, const std::vector<uint32_t *> &data, cudaStream_t s, int *err) {
  const uint32_t leaves = 1u << c.leaves_log;
  std::vector<void *> live;
  void *seed = nullptr; uint32_t seed_size = 0, absorbed = 0; size_t g = 0;
  uint32_t *hashes = nullptr; CK(cudaMalloc(&hashes, size_t(leaves) * 32));
  for (size_t k = 0; k < c.calls.size(); ++k) {
    const bool final = k + 1 == c.calls.size();
    std::vector<MixedSegment> segs;
    uint32_t size = 0, words = 0;
    for (uint32_t i = 0; i < c.calls[k]; ++i, ++g) {
      const uint32_t n = 1u << c.groups[g].log;
      segs.push_back({data[g], n, size_t(n) * c.groups[g].cols, n, 0});
      size = size > n ? size : n; words += c.groups[g].cols;
    }
    if (size < seed_size) size = seed_size;
    if (final) size = leaves;
    void *out = nullptr;
    if (!final) {
      CK(cudaMalloc(&out, size_t(size) * 96));
      if (!getenv("NOPOISON")) CK(cudaMemsetAsync(out, 0xC3, size_t(size) * 96, s));  // poison
      live.push_back(out);
    }
    const int r = fn(size, uint32_t(segs.size()), segs.data(), absorbed, seed_size, seed, final ? nullptr : out, final ? hashes : nullptr, s);
    if (r) { *err = r; break; }
    absorbed += words; seed = out; seed_size = size;
  }
  CK(cudaStreamSynchronize(s));
  std::vector<uint32_t> h(size_t(leaves) * 8);
  CK(cudaMemcpy(h.data(), hashes, h.size() * 4, cudaMemcpyDeviceToHost));
  for (void *p : live) CK(cudaFree(p));
  CK(cudaFree(hashes));
  return h;
}
int main() {
  cudaStream_t s; CK(cudaStreamCreate(&s));
  std::vector<Case> cases = {
    {"same16x2+5", 10, {{10,16},{10,16},{10,5}}, {1,1,1}},
    {"15+1+1", 10, {{10,15},{10,1},{10,1}}, {1,1,1}},
    {"17+16+1", 10, {{10,17},{10,16},{10,1}}, {1,1,1}},
    {"1+31+16+16+1", 10, {{10,1},{10,31},{10,16},{10,16},{10,1}}, {1,1,1,1,1}},
    {"40+8", 10, {{10,40},{10,8}}, {1,1}},
    {"48+16(final exact block)", 10, {{10,48},{10,16}}, {1,1}},
    {"lift16,16,3->leaves", 12, {{6,16},{8,16},{10,3},{12,4}}, {1,1,1,1}},
    {"lift 32 then final 1", 12, {{6,32},{12,1}}, {1,1}},
    {"lift multi-seg calls", 12, {{6,7},{6,9},{8,16},{9,13},{12,20}}, {2,1,1,1}},
    {"lift seed_size<size", 13, {{5,16},{11,16},{13,17}}, {1,1,1}},
    {"many 16-boundaries", 11, {{11,16},{11,16},{11,16},{11,16},{11,16},{11,3}}, {1,1,1,1,1,1}},
    {"odd chunks", 11, {{7,5},{7,11},{9,16},{9,33},{11,2},{11,14},{11,16}}, {2,1,1,1,1,1}},
  };
  int bad = 0;
  for (const auto &c : cases) {
    std::vector<uint32_t *> data;
    for (size_t g = 0; g < c.groups.size(); ++g) {
      const size_t words = (size_t(1) << c.groups[g].log) * c.groups[g].cols;
      uint32_t *p; CK(cudaMalloc(&p, words * 4)); fill<<<256, 256, 0, s>>>(p, words, 101 + g * 7 + c.leaves_log);
      data.push_back(p);
    }
    int e1 = 0, e2 = 0;
    const auto classic = chain(stwo_blake2s_mixed_seeded_on, c, data, s, &e1);
    const auto eager = chain(stwo_blake2s_mixed_seeded_eager_on, c, data, s, &e2);
    // Unchunked reference: one call with every segment at leaves size.
    Case one = c; one.calls = {uint32_t(c.groups.size())};
    int e3 = 0;
    const auto single = chain(stwo_blake2s_mixed_seeded_on, one, data, s, &e3);
    const bool ok = !e1 && !e2 && !e3 && classic == eager && classic == single;
    std::printf("%-28s classic_rc=%d eager_rc=%d single_rc=%d classic==eager:%d classic==single:%d %s\n", c.name, e1, e2, e3,
                int(classic == eager), int(classic == single), ok ? "OK" : "MISMATCH");
    bad += !ok;
    for (auto *p : data) CK(cudaFree(p));
  }
  // Fail-closed check: an eager final call that absorbs no word must be rejected.
  {
    uint32_t *col; CK(cudaMalloc(&col, 1024 * 16 * 4)); fill<<<64, 256, 0, s>>>(col, 1024 * 16, 5);
    void *pre; CK(cudaMalloc(&pre, 1024 * 96)); uint32_t *h; CK(cudaMalloc(&h, 1024 * 32));
    MixedSegment seg{col, 1024, 1024 * 16, 1024, 0};
    int r1 = stwo_blake2s_mixed_seeded_eager_on(1024, 1, &seg, 0, 0, nullptr, pre, nullptr, s);
    MixedSegment empty{col, 1024, 0, 1024, 0};
    int r2 = stwo_blake2s_mixed_seeded_eager_on(1024, 1, &empty, 16, 1024, pre, nullptr, h, s);
    std::printf("empty-final eager rc first=%d final=%d (%s)\n", r1, r2, r2 ? "rejected" : "ACCEPTED");
    CK(cudaStreamSynchronize(s));
  }
  std::printf("DONE bad=%d\n", bad);
  return bad;
}
