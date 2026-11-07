// r-truth kernel parity: NAT/rv64/jobs/truth_ops.cu against host references
// (jobs/truth_params.zig gather model; the legacy host checks the verdict
// kernels replace), positive and negative cases for every entry point.
//
// build: nvcc -O2 -std=c++17 -gencode arch=compute_120,code=sm_120 \
//   -I src/backends/cuda/native -I tests/cuda/rv64 tests/cuda/rv64/jobs/truth_ops_parity.cu \
//   -L<base dir> -l:libstwo-rv64-native.so -L<addon dir> -l:libstwo-rv64-jobs.so \
//   -Xlinker=-rpath,<base dir> -Xlinker=-rpath,<addon dir> -o truth_ops_parity
// run:   truth_ops_parity <device>   (prints PASS truth_ops_parity cases=<n>)
#include "context_owner.cuh"
#include <random>
#include <cstring>

extern "C" int stwo_rv64_truth_params_gather_v1_on(void *, uint32_t, const uint32_t *, const uint32_t *,
                                                   const uint32_t *, const uint32_t *, const void *, uint32_t,
                                                   const uint32_t[4], uint32_t *, uint32_t *);
extern "C" int stwo_rv64_truth_status_v1_on(void *, uint32_t, const uint32_t *, const uint32_t *,
                                            const uint32_t *, const void *, uint32_t *);
extern "C" int stwo_rv64_truth_root_match_v1_on(void *, uint32_t, const uint32_t *, const uint32_t *, uint32_t,
                                                uint32_t, uint32_t *);
extern "C" int stwo_rv64_truth_channel_order_v1_on(void *, uint32_t, const uint32_t *, uint32_t, uint64_t,
                                                   uint32_t *);
extern "C" int stwo_rv64_truth_pcs_status_v1_on(void *, uint32_t, const uint32_t *, uint64_t, const uint32_t *,
                                                const void *, uint32_t *);

namespace {
constexpr uint32_t P = 0x7fffffffu;
struct StatusConstants { uint32_t n_status, n_claims, n_zero, classic, check, reserved[3]; };
struct PcsExpect { uint32_t header[14], header_mask, trees, reserved[2]; };
static_assert(sizeof(StatusConstants) == 32 && sizeof(PcsExpect) == 72, "ABI");

struct Ctx {
  Owner owner;
  explicit Ctx(int device) : owner(device) {}
  uint32_t *dev(const std::vector<uint32_t> &host) {
    uint32_t *p = owner.plane(host.empty() ? 1 : host.size(), 1).words;
    if (!host.empty()) CHECK(stwo_exec_context_memcpy_h2d_async(owner.ctx, p, host.data(), host.size() * 4));
    return p;
  }
  std::vector<uint32_t> read(const uint32_t *p, size_t words) {
    std::vector<uint32_t> out(words);
    CHECK(stwo_exec_context_sync(owner.ctx));
    CHECK(stwo_exec_context_memcpy_d2h_async(owner.ctx, out.data(), p, words * 4));
    CHECK(stwo_exec_context_sync(owner.ctx));
    return out;
  }
};
int failures = 0, cases = 0;
void expect(bool ok, const char *what, uint32_t got = 0, uint32_t want = 0) {
  ++cases;
  if (!ok) {
    ++failures;
    std::fprintf(stderr, "FAIL %s got=0x%x want=0x%x\n", what, got, want);
  }
}
uint32_t reject(uint32_t check, uint32_t detail) { return (check << 16) | (detail ? detail : 1u); }
std::vector<uint32_t> felts(std::mt19937 &rng, size_t n) {
  std::vector<uint32_t> v(n * 8);
  for (auto &w : v) w = rng() % P;
  return v;
}

void gather(Ctx &c, std::mt19937 &rng) {
  const uint32_t bounds[4] = {11, 16, 59, 5};
  const auto staged = felts(rng, bounds[0]), local = felts(rng, bounds[1]), shared = felts(rng, bounds[2]),
             claims = felts(rng, bounds[3]);
  const std::vector<uint32_t> *src[4] = {&staged, &local, &shared, &claims};
  for (uint32_t count : {1u, 7u, 43u, 300u}) {
    std::vector<uint32_t> entries(count * 2), want(count * 8);
    for (uint32_t i = 0; i < count; ++i) {
      const uint32_t s = rng() % 4, idx = rng() % bounds[s];
      entries[2 * i] = s;
      entries[2 * i + 1] = idx;
      std::memcpy(&want[8 * i], &(*src[s])[8 * idx], 32);
    }
    uint32_t *out = c.dev(std::vector<uint32_t>(count * 8, 0xdeadbeef)), *status = c.dev({0});
    CHECK(stwo_rv64_truth_params_gather_v1_on(c.owner.ctx, 0, c.dev(staged), c.dev(local), c.dev(shared), c.dev(claims),
                                              c.dev(entries), count, bounds, out, status));
    expect(c.read(out, count * 8) == want, "gather words equal the host model");
    expect(c.read(status, 1)[0] == 0, "gather status clean");
    // Negative: one out-of-range entry latches the status and writes zeros there.
    entries[0] = 1;
    entries[1] = bounds[1];
    uint32_t *out2 = c.dev(std::vector<uint32_t>(count * 8, 7)), *status2 = c.dev({0});
    CHECK(stwo_rv64_truth_params_gather_v1_on(c.owner.ctx, 0, c.dev(staged), c.dev(local), c.dev(shared), c.dev(claims),
                                              c.dev(entries), count, bounds, out2, status2));
    const auto bad = c.read(out2, 8);
    expect(c.read(status2, 1)[0] != 0, "gather out-of-range latches status");
    expect(bad == std::vector<uint32_t>(8, 0), "gather out-of-range writes zeros");
    // Unknown source.
    entries[0] = 9;
    entries[1] = 0;
    uint32_t *status3 = c.dev({0});
    CHECK(stwo_rv64_truth_params_gather_v1_on(c.owner.ctx, 0, c.dev(staged), c.dev(local), c.dev(shared), c.dev(claims),
                                              c.dev(entries), count, bounds, out2, status3));
    expect(c.read(status3, 1)[0] != 0, "gather unknown source latches status");
  }
}

uint32_t runStatus(Ctx &c, const std::vector<uint32_t> &status, const std::vector<uint32_t> &claims,
                   const std::vector<uint32_t> &zero, StatusConstants k) {
  uint32_t *verdict = c.dev({0xffffffffu});
  CHECK(stwo_rv64_truth_status_v1_on(c.owner.ctx, 0, c.dev(status), claims.empty() ? nullptr : c.dev(claims),
                                     zero.empty() ? nullptr : c.dev(zero), &k, verdict));
  return c.read(verdict, 1)[0];
}

void status(Ctx &c, std::mt19937 &rng) {
  // Classic: claims[0] + claims[1] + claims[2] == 0 coordinate-wise, claims[4] == 0.
  auto claims = felts(rng, 5);
  for (int i = 0; i < 8; ++i) {
    claims[16 + i] = (2 * P - claims[i] - claims[8 + i]) % P;
    claims[32 + i] = 0;
  }
  const StatusConstants classic{6, 5, 0, 1, 0x0301, {}};
  const std::vector<uint32_t> ok(6, 0);
  expect(runStatus(c, ok, claims, {}, classic) == 0, "classic accepted");
  for (uint32_t i = 0; i < 6; ++i) {
    auto s = ok;
    s[i] = 3;
    const uint32_t got = runStatus(c, s, claims, {}, classic);
    expect(got == reject(0x0301, 1 | (i << 8)), "producer word rejects with its index", got, reject(0x0301, 1 | (i << 8)));
  }
  auto bad = claims;
  bad[9] = P;
  expect(runStatus(c, ok, bad, {}, classic) == reject(0x0301, 2), "noncanonical claim rejects");
  bad = claims;
  bad[0] = (bad[0] + 1) % P;
  expect(runStatus(c, ok, bad, {}, classic) == reject(0x0301, 3), "local closure rejects");
  bad = claims;
  bad[33] = 1;
  expect(runStatus(c, ok, bad, {}, classic) == reject(0x0301, 4), "absent claim rejects");
  // Delegated with a local closing group.
  const StatusConstants delegated{4, 1, 1, 0, 0x0301, {}};
  const auto one = felts(rng, 1);
  const std::vector<uint32_t> z(8, 0);
  expect(runStatus(c, std::vector<uint32_t>(4, 0), one, z, delegated) == 0, "delegated accepted");
  auto zb = z;
  zb[5] = 2;
  expect(runStatus(c, std::vector<uint32_t>(4, 0), one, zb, delegated) == reject(0x0301, 5), "nonzero closing group rejects");
  // Stage 1: one producer word, no claims, check id truth_root.
  const StatusConstants stage1{1, 0, 0, 0, 0x0307, {}};
  expect(runStatus(c, {0}, {}, {}, stage1) == 0, "stage1 accepted");
  expect(runStatus(c, {9}, {}, {}, stage1) == reject(0x0307, 1), "stage1 witness rejects as truth_root");
  // Invalid constants are refused at the launcher (no verdict written).
  StatusConstants wrong = stage1;
  wrong.check = 0x0302;
  uint32_t *verdict = c.dev({0xffffffffu});
  expect(stwo_rv64_truth_status_v1_on(c.owner.ctx, 0, c.dev({0}), nullptr, nullptr, &wrong, verdict) != 0, "foreign check id refused");
  expect(c.read(verdict, 1)[0] == 0xffffffffu, "refused launch leaves the word unset");
}

void roots(Ctx &c, std::mt19937 &rng) {
  const auto a = felts(rng, 2);
  uint32_t *v = c.dev({0xffffffffu});
  CHECK(stwo_rv64_truth_root_match_v1_on(c.owner.ctx, 0, c.dev(a), c.dev(a), 2, 0x0208, v));
  expect(c.read(v, 1)[0] == 0, "equal roots accepted");
  auto b = a;
  b[12] ^= 1;
  CHECK(stwo_rv64_truth_root_match_v1_on(c.owner.ctx, 0, c.dev(a), c.dev(b), 2, 0x0208, v));
  expect(c.read(v, 1)[0] == reject(0x0208, 2), "second root differs: detail 2");
  b = a;
  b[0] ^= 1;
  CHECK(stwo_rv64_truth_root_match_v1_on(c.owner.ctx, 0, c.dev(a), c.dev(b), 1, 0x0208, v));
  expect(c.read(v, 1)[0] == reject(0x0208, 1), "first root differs: detail 1");
}

void order(Ctx &c) {
  std::vector<uint32_t> state(16, 0);
  state[9] = 41;           // cursor
  const uint64_t chain = 0x4a4f425300000029ull;
  state[12] = uint32_t(chain);
  state[13] = uint32_t(chain >> 32);
  uint32_t *v = c.dev({0xffffffffu});
  CHECK(stwo_rv64_truth_channel_order_v1_on(c.owner.ctx, 0, c.dev(state), 41, chain, v));
  expect(c.read(v, 1)[0] == 0, "channel order accepted");
  auto s = state;
  s[10] = 1;
  CHECK(stwo_rv64_truth_channel_order_v1_on(c.owner.ctx, 0, c.dev(s), 41, chain, v));
  expect(c.read(v, 1)[0] == reject(0x0101, 1), "status latch rejects");
  CHECK(stwo_rv64_truth_channel_order_v1_on(c.owner.ctx, 0, c.dev(state), 42, chain, v));
  expect(c.read(v, 1)[0] == reject(0x0101, 3), "cursor mismatch rejects");
  CHECK(stwo_rv64_truth_channel_order_v1_on(c.owner.ctx, 0, c.dev(state), 41, chain + 1, v));
  expect(c.read(v, 1)[0] == reject(0x0101, 4), "chain mismatch rejects");
}

void pcs(Ctx &c, std::mt19937 &rng) {
  const uint32_t trees = 4;
  std::vector<uint32_t> words(31 + 8 * trees + 64, 0);
  words[0] = 0x52564d4f;
  words[1] = 2;
  words[7] = trees;
  words[13] = 5;           // PoW / transcript steps
  words[14] = 0;           // numerical status
  words[15 + 9] = 5;
  words[15 + 12] = 22;     // 17 + steps
  const auto r = felts(rng, trees);
  std::memcpy(&words[31], r.data(), r.size() * 4);
  PcsExpect x{};
  x.header[0] = 0x52564d4f;
  x.header[1] = 2;
  x.header[7] = trees;
  x.header_mask = 1 | 2 | (1 << 7);
  x.trees = trees;
  auto runPcs = [&](const std::vector<uint32_t> &w, const std::vector<uint32_t> &roots, const PcsExpect &e) {
    uint32_t *v = c.dev({0xffffffffu});
    CHECK(stwo_rv64_truth_pcs_status_v1_on(c.owner.ctx, 0, c.dev(w), w.size(), c.dev(roots), &e, v));
    return c.read(v, 1)[0];
  };
  expect(runPcs(words, r, x) == 0, "pcs accepted");
  auto w = words;
  w[1] = 3;
  expect(runPcs(w, r, x) == reject(0x0207, 1 | (1 << 8)), "pcs header version rejects");
  w = words;
  w[14] = 1;
  expect(runPcs(w, r, x) == reject(0x0207, 2), "pcs numerical status rejects");
  w = words;
  w[15 + 12] = 21;
  expect(runPcs(w, r, x) == reject(0x0207, 3), "pcs channel state rejects");
  auto rr = r;
  rr[8 * 2 + 3] ^= 1;
  expect(runPcs(words, rr, x) == reject(0x0207, 4 | (2 << 8)), "pcs root 2 mismatch rejects");
}
}  // namespace

int main(int argc, char **argv) {
  const int device = argc > 1 ? std::atoi(argv[1]) : 0;
  try {
    Ctx c(device);
    std::mt19937 rng(0x72747275);
    gather(c, rng);
    status(c, rng);
    roots(c, rng);
    order(c);
    pcs(c, rng);
  } catch (const std::exception &e) {
    std::fprintf(stderr, "ERROR %s\n", e.what());
    return 2;
  }
  if (failures) {
    std::printf("FAIL truth_ops_parity failures=%d cases=%d\n", failures, cases);
    return 1;
  }
  std::printf("PASS truth_ops_parity cases=%d\n", cases);
  return 0;
}
