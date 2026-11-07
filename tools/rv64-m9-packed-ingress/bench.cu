// M9 L1a standalone parity + throughput bench for m9_class_unpack.cu.
//   bench <corpus.m9pk> [reps]
// Decodes every lz4_blocks value of the corpus on the device in ONE batched
// launch (as a node prestage would), compares every word against the host
// cache_pack unpack recorded in the corpus, then times warm decodes with CUDA
// events. Also runs negative tests (corrupt payload / chain / offset) and a
// misaligned-output pass. Prints one M9_BENCH line per section.
#include "../../src/backends/cuda/native/rv64/m9_class_unpack.h"
#include <cuda_runtime.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <string>

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { fprintf(stderr, "CUDA %s at %s:%d\n", cudaGetErrorString(e_), __FILE__, __LINE__); exit(2); } } while (0)

struct Value {
  uint32_t tag, channels, encoding;
  uint64_t words, data_bytes;
  std::vector<StwoRv64M9PackedBlock> blocks;
  std::vector<uint8_t> data;
  std::vector<uint32_t> expected;
};

static std::vector<Value> load(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) { perror(path); exit(2); }
  char magic[8];
  uint32_t n = 0;
  if (fread(magic, 1, 8, f) != 8 || memcmp(magic, "M9PKCLS1", 8) || fread(&n, 4, 1, f) != 1) { fprintf(stderr, "bad corpus\n"); exit(2); }
  std::vector<Value> out(n);
  for (auto &v : out) {
    uint32_t nb;
    if (fread(&v.tag, 4, 1, f) != 1 || fread(&v.channels, 4, 1, f) != 1 || fread(&v.words, 8, 1, f) != 1 ||
        fread(&v.encoding, 4, 1, f) != 1 || fread(&nb, 4, 1, f) != 1 || fread(&v.data_bytes, 8, 1, f) != 1) exit(3);
    v.blocks.resize(nb);
    for (auto &b : v.blocks) if (fread(&b.offset, 8, 1, f) != 1 || fread(&b.bytes, 4, 1, f) != 1 || fread(&b.raw, 4, 1, f) != 1) exit(3);
    v.data.resize(v.data_bytes);
    v.expected.resize(v.words);
    if (fread(v.data.data(), 1, v.data_bytes, f) != v.data_bytes || fread(v.expected.data(), 4, v.words, f) != v.words) exit(3);
  }
  fclose(f);
  return out;
}

struct Device {
  std::vector<StwoRv64M9PackedJob> jobs;
  uint8_t *data = nullptr;
  StwoRv64M9PackedBlock *blocks = nullptr;
  uint32_t *output = nullptr, *status = nullptr;
  StwoRv64M9PackedJob *djobs = nullptr;
  uint32_t total_blocks = 0;
  uint64_t logical = 0, physical = 0, out_words = 0;
};

// One arena per batch, as a node prestage would lay it out: payloads, block
// tables and outputs each contiguous; `skew` misaligns every output by words.
static Device stage(const std::vector<Value> &vals, const std::vector<size_t> &pick, uint32_t skew) {
  Device d;
  uint64_t data = 0, nblocks = 0, words = 0;
  for (size_t i : pick) { data += vals[i].data_bytes; nblocks += vals[i].blocks.size(); words += vals[i].words + 4 + skew; }
  CK(cudaMalloc(&d.data, data + 16));
  CK(cudaMalloc(&d.blocks, nblocks * sizeof(StwoRv64M9PackedBlock)));
  CK(cudaMalloc(&d.output, words * 4));
  CK(cudaMalloc(&d.status, 4));
  CK(cudaMemset(d.status, 0, 4));
  uint64_t at = 0, bt = 0, wt = 0;
  for (size_t i : pick) {
    const Value &v = vals[i];
    CK(cudaMemcpy(d.data + at, v.data.data(), v.data_bytes, cudaMemcpyHostToDevice));
    CK(cudaMemcpy(d.blocks + bt, v.blocks.data(), v.blocks.size() * sizeof(StwoRv64M9PackedBlock), cudaMemcpyHostToDevice));
    wt = (wt + 3) / 4 * 4 + skew;  // 16-byte aligned unless skewed
    StwoRv64M9PackedJob j{};
    j.data = d.data + at; j.blocks = d.blocks + bt; j.output = d.output + wt;
    j.data_bytes = v.data_bytes; j.words = v.words; j.channels = v.channels; j.first_block = uint32_t(d.total_blocks);
    d.jobs.push_back(j);
    d.total_blocks += uint32_t(v.blocks.size());
    at += v.data_bytes; bt += v.blocks.size(); wt += v.words;
    d.logical += v.words * 4;
    d.physical += v.data_bytes + v.blocks.size() * sizeof(StwoRv64M9PackedBlock);
  }
  d.out_words = words;
  CK(cudaMalloc(&d.djobs, d.jobs.size() * sizeof(StwoRv64M9PackedJob)));
  CK(cudaMemcpy(d.djobs, d.jobs.data(), d.jobs.size() * sizeof(StwoRv64M9PackedJob), cudaMemcpyHostToDevice));
  return d;
}
static void release(Device &d) {
  cudaFree(d.data); cudaFree(d.blocks); cudaFree(d.output); cudaFree(d.status); cudaFree(d.djobs);
  d = Device{};
}
static uint32_t run(Device &d, cudaStream_t s) {
  CK(cudaMemsetAsync(d.status, 0, 4, s));
  const int rc = stwo_rv64_m9_class_unpack_passes(s, d.djobs, uint32_t(d.jobs.size()), d.total_blocks, d.status, 3);
  if (rc) { fprintf(stderr, "launch rc=%d\n", rc); exit(2); }
  uint32_t st = 0;
  CK(cudaMemcpyAsync(&st, d.status, 4, cudaMemcpyDeviceToHost, s));
  CK(cudaStreamSynchronize(s));
  return st;
}
static uint64_t compare(const Device &d, const std::vector<Value> &vals, const std::vector<size_t> &pick) {
  uint64_t bad = 0;
  std::vector<uint32_t> host;
  for (size_t k = 0; k < pick.size(); ++k) {
    const Value &v = vals[pick[k]];
    host.resize(v.words);
    CK(cudaMemcpy(host.data(), d.jobs[k].output, v.words * 4, cudaMemcpyDeviceToHost));
    for (uint64_t w = 0; w < v.words; ++w) bad += host[w] != v.expected[w];
  }
  return bad;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: bench corpus.m9pk [reps]\n"); return 2; }
  const int reps = argc > 2 ? atoi(argv[2]) : 20;
  auto vals = load(argv[1]);
  cudaDeviceProp prop{};
  CK(cudaGetDeviceProperties(&prop, 0));
  std::vector<size_t> all, fixed, tasks;
  size_t skipped = 0;
  for (size_t i = 0; i < vals.size(); ++i) {
    if (vals[i].encoding != 2) { ++skipped; continue; }  // host path keeps raw / delta_varint
    all.push_back(i);
    (vals[i].tag == 1 ? tasks : fixed).push_back(i);
  }
  printf("M9_BENCH device=\"%s\" sms=%d corpus=%s values=%zu lz4_values=%zu non_lz4_skipped=%zu\n", prop.name, prop.multiProcessorCount, argv[1], vals.size(), all.size(), skipped);
  cudaStream_t s;
  CK(cudaStreamCreate(&s));
  int failures = 0;
  // Parity, aligned and misaligned outputs.
  for (uint32_t skew : {0u, 1u}) {
    Device d = stage(vals, all, skew);
    CK(cudaMemset(d.output, 0xa5, d.out_words * 4));
    const uint32_t st = run(d, s);
    const uint64_t bad = compare(d, vals, all);
    printf("M9_BENCH parity skew=%u status=%u mismatched_words=%llu logical_bytes=%llu blocks=%u %s\n", skew, st, (unsigned long long)bad, (unsigned long long)d.logical, d.total_blocks, (st == 0 && bad == 0) ? "PASS" : "FAIL");
    failures += !(st == 0 && bad == 0);
    release(d);
  }
  // Throughput: whole batch (one node), then FIXED-only and tasks-only.
  struct Section { const char *name; std::vector<size_t> *pick; } sections[] = {{"batch", &all}, {"fixed", &fixed}, {"tasks", &tasks}};
  cudaEvent_t e0, e1;
  CK(cudaEventCreate(&e0)); CK(cudaEventCreate(&e1));
  for (auto &sec : sections) {
    if (sec.pick->empty()) continue;
    Device d = stage(vals, *sec.pick, 0);
    run(d, s);  // warm (attribute, caches)
    std::vector<float> ms;
    for (int r = 0; r < reps; ++r) {
      CK(cudaEventRecord(e0, s));
      stwo_rv64_m9_class_unpack_passes(s, d.djobs, uint32_t(d.jobs.size()), d.total_blocks, d.status, 3);
      CK(cudaEventRecord(e1, s));
      CK(cudaEventSynchronize(e1));
      float t; CK(cudaEventElapsedTime(&t, e0, e1)); ms.push_back(t);
    }
    std::sort(ms.begin(), ms.end());
    const float med = ms[ms.size() / 2], best = ms[0];
    float pass_ms[2] = {0, 0};
    for (uint32_t p = 0; p < 2; ++p) {
      std::vector<float> pm;
      for (int r = 0; r < 5; ++r) {
        CK(cudaEventRecord(e0, s));
        stwo_rv64_m9_class_unpack_passes(s, d.djobs, uint32_t(d.jobs.size()), d.total_blocks, d.status, 1u << p);
        CK(cudaEventRecord(e1, s));
        CK(cudaEventSynchronize(e1));
        float t; CK(cudaEventElapsedTime(&t, e0, e1)); pm.push_back(t);
      }
      std::sort(pm.begin(), pm.end());
      pass_ms[p] = pm[pm.size() / 2];
    }
    // Host-side LZ4 sequence census of the section (serial critical path).
    uint64_t seqs = 0, max_seq = 0, max_bytes = 0;
    std::vector<uint64_t> per;
    for (size_t i : *sec.pick) for (auto &b : vals[i].blocks) {
      uint64_t n = 0;
      if (!b.raw) {
        const uint8_t *p = vals[i].data.data() + b.offset, *e = p + b.bytes;
        while (p < e) {
          const uint32_t tok = *p++; uint32_t lit = tok >> 4;
          if (lit == 15) { uint8_t x; do { x = *p++; lit += x; } while (x == 255); }
          p += lit; ++n;
          if (p >= e) break;
          p += 2;
          if ((tok & 15) == 15) { uint8_t x; do { x = *p++; } while (x == 255); }
        }
      }
      per.push_back(n); seqs += n; max_seq = std::max(max_seq, n); max_bytes = std::max<uint64_t>(max_bytes, b.bytes);
    }
    std::sort(per.begin(), per.end());
    printf("M9_BENCH census section=%s sequences=%llu per_block_mean=%.0f p50=%llu p99=%llu max=%llu max_block_bytes=%llu lz4_pass_ms=%.3f scan_pass_ms=%.3f\n", sec.name,
           (unsigned long long)seqs, double(seqs) / per.size(), (unsigned long long)per[per.size() / 2], (unsigned long long)per[per.size() * 99 / 100],
           (unsigned long long)max_seq, (unsigned long long)max_bytes, pass_ms[0], pass_ms[1]);
    uint32_t st = 0; CK(cudaMemcpy(&st, d.status, 4, cudaMemcpyDeviceToHost));
    printf("M9_BENCH decode section=%s values=%zu blocks=%u logical_bytes=%llu physical_bytes=%llu ratio=%.1f median_ms=%.3f best_ms=%.3f out_GBps=%.1f in_GBps=%.2f status=%u reps=%d\n",
           sec.name, sec.pick->size(), d.total_blocks, (unsigned long long)d.logical, (unsigned long long)d.physical, double(d.logical) / double(d.physical),
           med, best, d.logical / (med * 1e6), d.physical / (med * 1e6), st, reps);
    // H2D of the packed bytes from pinned memory (what L1a puts on the link).
    void *pinned = nullptr;
    CK(cudaMallocHost(&pinned, d.physical));
    memset(pinned, 0, d.physical);
    uint8_t *dst = nullptr;
    CK(cudaMalloc(&dst, d.physical));
    CK(cudaEventRecord(e0, s));
    CK(cudaMemcpyAsync(dst, pinned, d.physical, cudaMemcpyHostToDevice, s));
    CK(cudaEventRecord(e1, s));
    CK(cudaEventSynchronize(e1));
    float h2d; CK(cudaEventElapsedTime(&h2d, e0, e1));
    printf("M9_BENCH h2d_packed section=%s bytes=%llu ms=%.3f GBps=%.2f\n", sec.name, (unsigned long long)d.physical, h2d, d.physical / (h2d * 1e6));
    cudaFree(dst); cudaFreeHost(pinned);
    release(d);
  }
  // Negative tests on the first multi-block LZ4 value: each corruption must be
  // refused by status or (for payload bit flips the LZ4 grammar accepts)
  // surface as a mismatch; never an out-of-bounds access (run under
  // compute-sanitizer for the latter).
  for (size_t i : all) {
    Value v = vals[i];
    size_t lz = SIZE_MAX;
    for (size_t b = 1; b < v.blocks.size(); ++b) if (!v.blocks[b].raw && v.blocks[b].bytes > 8) { lz = b; break; }
    if (lz == SIZE_MAX) continue;
    struct Case { const char *name; int kind; } cases[] = {{"chain", 0}, {"offset_zero", 1}, {"truncate", 2}, {"flip", 3}, {"shape", 4}};
    for (auto &c : cases) {
      std::vector<Value> m{v};
      Value &x = m[0];
      if (c.kind == 0) x.blocks[lz].offset += 1;
      if (c.kind == 1) {  // first sequence's match offset -> 0 (token + literals known)
        const uint8_t *p = x.data.data() + x.blocks[lz].offset;
        uint32_t lit = p[0] >> 4; size_t q = 1;
        if (lit == 15) { uint8_t b; do { b = p[q++]; lit += b; } while (b == 255); }
        q += lit;
        x.data[x.blocks[lz].offset + q] = 0; x.data[x.blocks[lz].offset + q + 1] = 0;
      }
      if (c.kind == 2) { x.blocks.back().bytes -= 1; x.data_bytes -= 1; x.data.pop_back(); }  // truncated final payload
      if (c.kind == 3) x.data[x.blocks[lz].offset + x.blocks[lz].bytes / 2] ^= 0x40;
      if (c.kind == 4) x.channels = 3;
      std::vector<size_t> one{0};
      Device d = stage(m, one, 0);
      const uint32_t st = run(d, s);
      const uint64_t bad = st ? 0 : compare(d, m, one);
      const bool refused = st != 0 || bad != 0;
      printf("M9_BENCH negative case=%s status=%u mismatched_words=%llu %s\n", c.name, st, (unsigned long long)bad, refused ? "REFUSED" : "ACCEPTED-FAIL");
      failures += !refused;
      release(d);
    }
    break;
  }
  printf("M9_BENCH result=%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
  return failures ? 1 : 0;
}
