// fused_blake2s_v1 GPU self-test and fill benchmark (stream blake-gadget).
//
//   nvcc -O3 -std=c++17 -gencode arch=compute_120,code=sm_120 \
//     -I src/backends/cuda/native tests/cuda/rv64/fused_blake2s_selftest.cu -o fused_blake2s_selftest
//   ./fused_blake2s_selftest [total_rows=16777216] [batch_rows=262144] [dump_path] [dump_rows=4096]
//
// 1. Host reference compression reproduces RFC 7693 Blake2s("abc") and the
//    empty-message digest (the reference the device checker is ported from).
// 2. `total_rows` random compressions (counter-based SplitMix64 tape, the
//    same generator as the Zig spec's `randomRecord`): GPU fill, then the GPU
//    checker re-evaluates every constraint, every XOR table lookup, the Gate
//    limbs vs the tape and the outputs vs an independent reference
//    compression. Must report 0 violations.
// 3. Multiplicity balance: the XOR table counters sum to rows x lookups.
// 4. Host spot check: 1,024 rows' output words read back from the columns
//    equal the host reference compression.
// 5. Negative: corrupting single cells (byte, carry, flag-like) of a filled
//    batch must raise violations.
// 6. Timing: fill kernel at 2^12..2^18 rows, with and without multiplicity
//    atomics (median of 7, CUDA events).
// 7. Optional dump of the first `dump_rows` rows (column-major) for
//    `test "fused_blake2s_v1: GPU fill dump equals the CPU fill"`.
#include "rv64/fused_blake2s.cu"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

#define CK(x)                                                                         \
  do {                                                                                \
    cudaError_t e_ = (x);                                                             \
    if (e_ != cudaSuccess) {                                                          \
      std::fprintf(stderr, "CUDA %s at %s:%d\n", cudaGetErrorString(e_), __FILE__, __LINE__); \
      std::exit(2);                                                                   \
    }                                                                                 \
  } while (0)

static const uint32_t H_IV[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                                 0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
static const uint8_t H_SIGMA[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};
static const uint8_t H_G[8][4] = {{0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
                                  {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}};

static void host_compress(const uint32_t* w, uint32_t out[8]) {
  uint32_t v[16];
  for (int i = 0; i < 8; i++) v[i] = w[i];
  for (int i = 0; i < 8; i++) v[8 + i] = H_IV[i];
  v[12] ^= w[24];
  if (w[25] & 1) v[14] = ~v[14];
  const uint32_t* m = w + 8;
  for (int r = 0; r < 10; r++)
    for (int g = 0; g < 8; g++) {
      uint32_t& a = v[H_G[g][0]];
      uint32_t& b = v[H_G[g][1]];
      uint32_t& c = v[H_G[g][2]];
      uint32_t& d = v[H_G[g][3]];
      a = a + b + m[H_SIGMA[r][2 * g]];
      d = rotr(d ^ a, 16);
      c = c + d;
      b = rotr(b ^ c, 12);
      a = a + b + m[H_SIGMA[r][2 * g + 1]];
      d = rotr(d ^ a, 8);
      c = c + d;
      b = rotr(b ^ c, 7);
    }
  for (int i = 0; i < 8; i++) out[i] = w[i] ^ v[i] ^ v[i + 8];
}

static void host_blake2s(const uint8_t* msg, size_t len, uint8_t digest[32]) {
  uint32_t h[8];
  for (int i = 0; i < 8; i++) h[i] = H_IV[i];
  h[0] ^= 0x01010020u;
  size_t blocks = len == 0 ? 1 : (len + 63) / 64;
  for (size_t b = 0; b < blocks; b++) {
    uint8_t block[64] = {0};
    size_t start = b * 64, end = std::min(len, start + 64);
    if (end > start) std::memcpy(block, msg + start, end - start);
    uint32_t w[26];
    for (int i = 0; i < 8; i++) w[i] = h[i];
    for (int k = 0; k < 16; k++) std::memcpy(&w[8 + k], block + 4 * k, 4);
    w[24] = (uint32_t)std::min(len, (b + 1) * 64);
    w[25] = b + 1 == blocks;
    host_compress(w, h);
  }
  std::memcpy(digest, h, 32);
}

static bool hex_eq(const uint8_t d[32], const char* hex) {
  for (int i = 0; i < 32; i++) {
    unsigned x;
    std::sscanf(hex + 2 * i, "%2x", &x);
    if (d[i] != x) return false;
  }
  return true;
}

int main(int argc, char** argv) {
  const uint64_t total = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : (1ull << 24);
  const uint64_t batch = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : (1ull << 18);
  const char* dump_path = argc > 3 ? argv[3] : nullptr;
  const uint64_t dump_rows = argc > 4 ? std::strtoull(argv[4], nullptr, 10) : 4096;
  const uint64_t seed = 0x5eedf05edb1a4e01ull;
  int failures = 0;

  // 1. Host reference vs RFC 7693.
  uint8_t d[32];
  host_blake2s((const uint8_t*)"abc", 3, d);
  const bool abc_ok = hex_eq(d, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
  host_blake2s(nullptr, 0, d);
  const bool empty_ok = hex_eq(d, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
  std::printf("FUSED_BLAKE2S_V1 host_reference abc=%d empty=%d\n", abc_ok, empty_ok);
  failures += !abc_ok + !empty_ok;

  cudaStream_t stream;
  CK(cudaStreamCreate(&stream));
  uint32_t *tape, *cols, *counts;
  unsigned long long* viol;
  CK(cudaMalloc(&tape, batch * TAPE_WORDS * 4));
  CK(cudaMalloc(&cols, batch * (uint64_t)N_COLUMNS * 4));
  CK(cudaMalloc(&counts, 3u * (1u << 16) * 4));
  CK(cudaMalloc(&viol, sizeof(unsigned long long)));
  CK(cudaMemset(counts, 0, 3u * (1u << 16) * 4));
  CK(cudaMemset(viol, 0, sizeof(unsigned long long)));

  // 2-4. Random completeness.
  cudaEvent_t e0, e1;
  CK(cudaEventCreate(&e0));
  CK(cudaEventCreate(&e1));
  float fill_ms_total = 0, check_ms_total = 0;
  uint64_t spot_bad = 0;
  std::vector<uint32_t> host_cols;
  for (uint64_t first = 0; first < total; first += batch) {
    const uint64_t n = std::min(batch, total - first);
    if (stwo_fused_blake2s_v1_random_tape_on(seed, first, n, tape, stream)) failures++;
    CK(cudaEventRecord(e0, stream));
    if (stwo_fused_blake2s_v1_fill_on(tape, n, 0, n, cols, batch, counts, stream)) failures++;
    CK(cudaEventRecord(e1, stream));
    if (stwo_fused_blake2s_v1_check_on(cols, batch, tape, n, 0, n, viol, stream)) failures++;
    CK(cudaStreamSynchronize(stream));
    float ms;
    CK(cudaEventElapsedTime(&ms, e0, e1));
    fill_ms_total += ms;
    if (first == 0) {
      // Spot check outputs: the last 64 columns hold 8 x (u, out) byte words.
      const uint64_t k = std::min<uint64_t>(n, 1024);
      host_cols.resize(N_COLUMNS * k);
      for (int c = 0; c < N_COLUMNS; c++)
        CK(cudaMemcpy(host_cols.data() + c * k, cols + (uint64_t)c * batch, k * 4, cudaMemcpyDeviceToHost));
      for (uint64_t r = 0; r < k; r++) {
        uint32_t w[26], want[8];
        random_record(seed, r, w);
        host_compress(w, want);
        for (int i = 0; i < 8; i++) {
          uint32_t got = 0;
          for (int j = 0; j < 4; j++) got |= host_cols[(N_COLUMNS - 64 + 8 * i + 4 + j) * k + r] << (8 * j);
          if (got != want[i]) spot_bad++;
        }
      }
      if (dump_path) {
        const uint64_t dn = std::min(dump_rows, n);
        std::vector<uint32_t> dump(N_COLUMNS * dn);
        for (int c = 0; c < N_COLUMNS; c++)
          CK(cudaMemcpy(dump.data() + c * dn, cols + (uint64_t)c * batch, dn * 4, cudaMemcpyDeviceToHost));
        FILE* f = std::fopen(dump_path, "wb");
        const uint64_t header[4] = {0x31763273656b616cull, seed, dn, 0};
        std::fwrite(header, 8, 4, f);
        std::fwrite(dump.data(), 4, dump.size(), f);
        std::fclose(f);
        std::printf("FUSED_BLAKE2S_V1 dump path=%s rows=%llu\n", dump_path, (unsigned long long)dn);
      }
    }
  }
  unsigned long long violations = 0;
  CK(cudaMemcpy(&violations, viol, sizeof(violations), cudaMemcpyDeviceToHost));
  std::vector<uint32_t> hc(3u << 16);
  CK(cudaMemcpy(hc.data(), counts, hc.size() * 4, cudaMemcpyDeviceToHost));
  uint64_t sums[3] = {0, 0, 0};
  for (uint32_t i = 0; i < (1u << 16); i++) {
    sums[0] += hc[i];
    sums[1] += hc[(1u << 16) + i];
    sums[2] += hc[(2u << 16) + i];
  }
  const bool mult_ok = sums[0] == total * N_XOR8_LOOKUPS && sums[1] == total * N_SPLIT_LOOKUPS && sums[2] == total * N_SPLIT_LOOKUPS;
  std::printf("FUSED_BLAKE2S_V1 gpu_random rows=%llu violations=%llu spot_rows=1024 spot_bad=%llu mult_sums=%llu,%llu,%llu mult_ok=%d fill_ms_total=%.3f\n",
              (unsigned long long)total, violations, (unsigned long long)spot_bad, (unsigned long long)sums[0],
              (unsigned long long)sums[1], (unsigned long long)sums[2], mult_ok, fill_ms_total);
  failures += violations != 0;
  failures += spot_bad != 0;
  failures += !mult_ok;

  // 5. Negative: single-cell corruptions must be caught.
  {
    const uint64_t n = std::min<uint64_t>(batch, 4096);
    stwo_fused_blake2s_v1_random_tape_on(seed ^ 1, 0, n, tape, stream);
    stwo_fused_blake2s_v1_fill_on(tape, n, 0, n, cols, batch, nullptr, stream);
    CK(cudaStreamSynchronize(stream));
    const int probes[][2] = {{0, 0}, {33, 1}, {64, 7}, {70, 9}, {75, 11}, {100, 13}, {N_COLUMNS / 2, 17}, {N_COLUMNS - 1, 21}, {N_COLUMNS - 33, 23}};
    int caught = 0, total_probes = 0;
    for (auto& pr : probes) {
      for (uint32_t delta : {1u, 256u, 65536u}) {
        uint32_t* cell = cols + (uint64_t)pr[0] * batch + pr[1];
        uint32_t saved;
        CK(cudaMemcpy(&saved, cell, 4, cudaMemcpyDeviceToHost));
        uint32_t bad = (saved + delta) % P;
        CK(cudaMemcpy(cell, &bad, 4, cudaMemcpyHostToDevice));
        CK(cudaMemset(viol, 0, sizeof(unsigned long long)));
        stwo_fused_blake2s_v1_check_on(cols, batch, tape, n, 0, n, viol, stream);
        unsigned long long v = 0;
        CK(cudaMemcpy(&v, viol, sizeof(v), cudaMemcpyDeviceToHost));
        CK(cudaMemcpy(cell, &saved, 4, cudaMemcpyHostToDevice));
        caught += v > 0;
        total_probes++;
      }
    }
    std::printf("FUSED_BLAKE2S_V1 gpu_negative probes=%d caught=%d\n", total_probes, caught);
    failures += caught != total_probes;
  }

  // 6. Timing at production-like instance sizes.
  for (uint32_t log = 12; log <= 18; log += 2) {
    const uint64_t n = 1ull << log;
    if (n > batch) break;
    stwo_fused_blake2s_v1_random_tape_on(seed, 0, n, tape, stream);
    for (int with_counts = 1; with_counts >= 0; with_counts--) {
      std::vector<float> t;
      for (int rep = 0; rep < 7; rep++) {
        CK(cudaEventRecord(e0, stream));
        stwo_fused_blake2s_v1_fill_on(tape, n, 0, n, cols, n, with_counts ? counts : nullptr, stream);
        CK(cudaEventRecord(e1, stream));
        CK(cudaEventSynchronize(e1));
        float ms;
        CK(cudaEventElapsedTime(&ms, e0, e1));
        t.push_back(ms);
      }
      std::sort(t.begin(), t.end());
      const double ms = t[3];
      const double bytes = (double)n * N_COLUMNS * 4;
      std::printf("FUSED_BLAKE2S_V1 fill_timing log_rows=%u counts=%d median_ms=%.4f ns_per_compression=%.2f write_GBps=%.1f\n", log,
                  with_counts, ms, ms * 1e6 / n, bytes / (ms * 1e-3) / 1e9);
    }
  }
  int dev;
  cudaGetDevice(&dev);
  cudaDeviceProp prop;
  cudaGetDeviceProperties(&prop, dev);
  std::printf("FUSED_BLAKE2S_V1 device=%s failures=%d %s\n", prop.name, failures, failures ? "FAIL" : "PASS");
  return failures ? 1 : 0;
}
