// Byte parity: legacy rv64_pcs_pipeline::run (joined owner, host readback)
// versus the enqueue-only job PCS (one stream, device seed/point, D2D slab),
// on the same exported native PCS fixture. The job arm has exactly ONE host
// wait (the final stream join) and one D2H of the slab, done by this harness
// standing in for the worker. Exit 0 only when every arm is byte-identical.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/pcs_pipeline.cuh"
#include "rv64/jobs/pcs_enqueue.h"
#include "rv64/jobs/oods_points.h"
#include "rv64/channel.h"
#include <fstream>
// The frozen a25 base image (the gate runtime) predates these two exports.
// The legacy arm's allocation-observer hook is diagnostic only (no proof word
// depends on it): this harness defines it as a no-op. The compact-eager hash
// is referenced weakly; that arm is only run against an image exporting it.
extern "C" int stwo_exec_context_allocation_observer_next_v1(void *, uint32_t, uint32_t) {
  return 0;
}
extern "C" int stwo_blake2s_mixed_seeded_eager_compact_on(
    uint32_t, uint32_t, const stwo::cuda::blake2s::MixedSegment *, uint32_t, uint32_t,
    const uint32_t *, uint64_t, uint32_t *, uint64_t, uint32_t *, uint64_t, void *)
    __attribute__((weak));
namespace rv64_pcs_pipeline {
// Identical to tests/cuda/rv64/pcs_masks_pipeline_smoke.cu parse().
inline Input parse(FixtureWords &file) {
  Input input;
  auto take = [&](size_t n) {
    if (n > file.data.size() - file.position)
      throw std::runtime_error("fixture bounds");
    Words v{file.data.data() + file.position, n};
    file.position += n;
    return v;
  };
  input.sections[0] = take(24);
  const auto h = input.sections[0];
  if (h[4] > 28 || h[8] > 65536 || h[9] > 65536 || h[10] > 1024 || h[11] > 96 ||
      h[12] > 4 || h[14] > 28)
    throw std::runtime_error("fixture bounds");
  const size_t sizes[] = {9, h[21] ? 16u : 0u, size_t(h[8]) * 4, size_t(h[9]) * 4,
                          size_t(h[10]) * 8, size_t(h[11]) * 8, size_t(h[12]) * 6,
                          size_t(h[10]) * 4, size_t(h[10]) * 2, h[13], h[8]};
  for (size_t i = 0; i < 11; ++i)
    input.sections[i + 1] = take(sizes[i]);
  const auto warehouse = take(h[15]);
  for (uint32_t c = 0; c < h[8]; ++c) {
    const auto src = input.sections[3];
    const uint64_t offset = uint64_t(src[4 * c]) | (uint64_t(src[4 * c + 1]) << 32);
    const uint32_t log = src[4 * c + 3];
    if (log > 28 || offset > warehouse.size() || (uint64_t(1) << log) > warehouse.size() - offset)
      throw std::runtime_error("source bounds");
    input.coefficients.push_back({{warehouse.data() + offset, size_t(1) << log}, 0, 0, 0});
  }
  input.sections[12] = take(h[19]);
  input.sections[13] = take(size_t(h[14]) * 8);
  input.sections[14] = take(h[20]);
  input.domain = take(size_t(2) << h[4]);
  input.sections[15] = take(size_t(h[12]) * 8);
  (void)take(17);
  if (file.position != file.data.size())
    throw std::runtime_error("fixture trailing words");
  return input;
}
} // namespace rv64_pcs_pipeline
// Identical to the masks smoke FileOwner: the legacy reference arm.
struct FileOwner : Owner {
  explicit FileOwner(int device) : Owner(device) {}
  std::vector<StwoRv64Plane> temporaries;
  std::vector<uint32_t *> protected_sources;
  StwoRv64Plane plane(uint64_t count, uint32_t coordinates) {
    const auto p = Owner::plane(count, coordinates);
    temporaries.push_back(p);
    return p;
  }
  StwoRv64Plane sourcePlane(uint64_t count, uint32_t coordinates) {
    const auto p = plane(count, coordinates);
    protected_sources.push_back(p.words);
    return p;
  }
  void retirePlanes(const std::vector<StwoRv64Plane> &planes) {
    std::vector<uint32_t *> selected;
    for (const auto &p : planes) selected.push_back(p.words);
    CHECK(stwo_exec_context_sync(ctx));
    for (auto pointer : selected) {
      CHECK(stwo_exec_context_free_u32(ctx, pointer));
      allocations.erase(std::find(allocations.begin(), allocations.end(), pointer));
    }
  }
  void uploadBorrowed(StwoRv64Plane p, const uint32_t *data, size_t words) {
    if (words) CHECK(stwo_exec_context_memcpy_h2d_async(ctx, p.words, data, words * 4));
  }
  uint32_t validateCoefficient(rv64_pcs_pipeline::Coefficient source, const uint32_t *) const {
    if (source.kind) throw std::runtime_error("device coefficients require a native session");
    return 0;
  }
  void uploadCoefficient(StwoRv64Plane destination, rv64_pcs_pipeline::Coefficient source, const uint32_t *) {
    uploadBorrowed(destination, source.data(), source.size());
  }
  StwoRv64Plane domain(uint32_t, rv64_pcs_pipeline::Words data, rv64_pcs_pipeline::Words) {
    auto p = sourcePlane(data.size(), 1);
    uploadBorrowed(p, data.data(), data.size());
    return p;
  }
};
// Test arena standing in for the job runtime's stream-ordered arena. Frees
// are deferred to after the single join (context free joins every lane).
struct TestArena {
  void *ctx;
  std::vector<uint32_t *> live, retired;
  uint64_t peak = 0, current = 0, calls = 0;
  static uint32_t *alloc(void *user, uint64_t words) {
    auto *self = static_cast<TestArena *>(user);
    uint32_t *p = nullptr;
    if (stwo_exec_context_alloc_u32(self->ctx, words, &p)) return nullptr;
    self->live.push_back(p);
    self->current += words * 4;
    self->peak = std::max(self->peak, self->current);
    ++self->calls;
    return p;
  }
  static void release(void *user, uint32_t *p, uint64_t words) {
    auto *self = static_cast<TestArena *>(user);
    self->retired.push_back(p);
    self->current -= words * 4;
  }
  void drain() {
    for (auto *p : retired) {
      auto i = std::find(live.begin(), live.end(), p);
      if (i == live.end()) throw std::runtime_error("arena double release");
      live.erase(i);
      CHECK(stwo_exec_context_free_u32(ctx, p));
    }
    retired.clear();
  }
};
static void write_words(const std::string &path, const std::vector<uint32_t> &words) {
  std::ofstream out(path, std::ios::binary);
  out.write(reinterpret_cast<const char *>(words.data()), words.size() * 4);
  if (!out) throw std::runtime_error("write " + path);
}
static StwoRv64PcsNativeRequest nativeRequest(const rv64_pcs_pipeline::Input &input, uint32_t params[4]) {
  const auto h = input.sections[0];
  constexpr uint64_t p = 0x7fffffffu;
  const uint64_t x = input.domain[0], y = input.domain[1];
  const uint64_t nx = input.domain[(size_t(1) << (h[4] - 1)) * 2],
                 ny = input.domain[(size_t(1) << (h[4] - 1)) * 2 + 1];
  params[0] = uint32_t(x);
  params[1] = uint32_t(y);
  params[2] = uint32_t((nx * x + ny * y) % p);
  params[3] = uint32_t((ny * x + (p - nx) * y % p) % p);
  StwoRv64PcsNativeRequest request{};
  request.version = 1;
  request.section_count = 17;
  for (size_t i = 0; i < 16; ++i)
    request.sections[i] = {input.sections[i].data(), input.sections[i].size()};
  request.sections[16] = {params, 4};
  return request;
}
// Device transcript from the PLAIN fixture's initial channel: mix the four
// tree roots, draw t, build the OODS point and base point on device, then run
// the job PCS in imported mode from those device values. Must equal the legacy
// pipeline on the IMPORTED fixture (whose seed/point the host derived).
static int oods_mode(const char *plain_path, const char *imported_path, const std::string &prefix) {
  FixtureWords plain_file(plain_path), imported_file(imported_path);
  auto plain = rv64_pcs_pipeline::parse(plain_file);
  auto imported = rv64_pcs_pipeline::parse(imported_file);
  if (plain.sections[0][21] != 0 || imported.sections[0][21] != 1)
    throw std::runtime_error("oods mode needs plain then imported fixtures");
  std::vector<uint32_t> legacy;
  {
    FileOwner owner(0);
    legacy = rv64_pcs_pipeline::run(owner, imported).words;
    owner.close();
  }
  uint32_t params[4];
  auto request = nativeRequest(imported, params);
  std::vector<uint32_t> poison_seed(9, 0x13579bdf), poison_point(16, 0x2468ace0 & 0x3fffffff);
  request.sections[1] = {poison_seed.data(), 9};
  request.sections[2] = {poison_point.data(), 16};
  std::vector<StwoRv64PcsColumn> columns;
  for (const auto &c : imported.coefficients)
    columns.push_back({0, uint32_t(__builtin_ctzll(c.size())), c.data(), c.size(), 0, 0});
  request.coefficients = columns.data();
  request.coefficient_count = columns.size();
  StwoCudaContextOptions options{1, 0, 1, 8};
  void *ctx = nullptr;
  CHECK(stwo_exec_context_create_options(&options, &ctx));
  TestArena arena{ctx};
  StwoRv64PcsJobPlan plan{};
  if (stwo_rv64_pcs_job_plan_v1(&request, &plan))
    throw std::runtime_error(std::string("plan: ") + stwo_rv64_pcs_job_error_v1());
  uint32_t *pinned = nullptr;
  CHECK(cudaMallocHost(reinterpret_cast<void **>(&pinned), (plan.ingress_words + 64) * 4));
  // Staged inputs (phase 1 stand-in): initial seed and the four roots.
  std::copy(plain.sections[1].begin(), plain.sections[1].end(), pinned);
  std::copy(plain.sections[15].begin(), plain.sections[15].end(), pinned + 16);
  uint32_t *seed = TestArena::alloc(&arena, 9), *roots = TestArena::alloc(&arena, 32),
           *state = TestArena::alloc(&arena, 16), *boundary = TestArena::alloc(&arena, 16),
           *draw = TestArena::alloc(&arena, 8), *points = TestArena::alloc(&arena, 32),
           *status = TestArena::alloc(&arena, 1), *output = TestArena::alloc(&arena, plan.output_words);
  void *stream_raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(ctx, 0, &stream_raw));
  auto stream = reinterpret_cast<cudaStream_t>(stream_raw);
  CHECK(cudaMemcpyAsync(seed, pinned, 36, cudaMemcpyHostToDevice, stream));
  CHECK(cudaMemcpyAsync(roots, pinned + 16, 128, cudaMemcpyHostToDevice, stream));
  CHECK(cudaMemsetAsync(status, 0, 4, stream));
  // Phase 2: device transcript (chain ids are local to this harness).
  CHECK(stwo_rv64_channel_init_on(ctx, 0, state, seed, 100));
  for (uint32_t t = 0; t < 4; ++t)
    CHECK(stwo_rv64_channel_mix_on(ctx, 0, state, t, 100 + t, 101 + t, roots + 8 * t, 8, 0, boundary));
  CHECK(stwo_rv64_channel_draw_on(ctx, 0, state, 4, 104, 105, 1, draw, boundary));
  // Fixture tree 0 column 1 has mask {0}: the base shift is the identity.
  CHECK(stwo_rv64_job_oods_points_v1(ctx, 0, draw, 1, 0, points, status));
  StwoRv64PcsJobMemory memory{&arena, TestArena::alloc, TestArena::release, pinned + 64, plan.ingress_words};
  StwoRv64PcsJobIo io{state, points + 16, nullptr, output, plan.output_words};
  if (stwo_rv64_pcs_job_enqueue_v1(ctx, 0, &request, &memory, &io))
    throw std::runtime_error(std::string("enqueue: ") + stwo_rv64_pcs_job_error_v1());
  CHECK(cudaStreamSynchronize(stream)); // the single host wait
  std::vector<uint32_t> job(plan.output_words), point_words(32), state_words(16);
  uint32_t status_word = 1;
  CHECK(cudaMemcpy(job.data(), output, job.size() * 4, cudaMemcpyDeviceToHost));
  CHECK(cudaMemcpy(point_words.data(), points, 128, cudaMemcpyDeviceToHost));
  CHECK(cudaMemcpy(state_words.data(), state, 64, cudaMemcpyDeviceToHost));
  CHECK(cudaMemcpy(&status_word, status, 4, cudaMemcpyDeviceToHost));
  write_words(prefix + ".oods-job.bin", job);
  const bool seed_equal = std::equal(imported.sections[1].begin(), imported.sections[1].end(), state_words.begin());
  const bool point_equal = std::equal(imported.sections[2].begin(), imported.sections[2].end(), point_words.begin() + 16);
  const bool equal = job == legacy;
  std::printf("PCS_JOB_OODS device_seed_equals_host=%d device_point_equals_host=%d oods_status=%u "
              "channel_status=%u byte_identical=%d output_words=%zu\n",
              int(seed_equal), int(point_equal), status_word, state_words[10], int(equal), job.size());
  arena.drain();
  CHECK(cudaFreeHost(pinned));
  if (!seed_equal || !point_equal || status_word || !equal)
    throw std::runtime_error("device OODS + job PCS differ from legacy imported path");
  std::printf("PASS pcs_enqueue_parity mode=oods\n");
  return 0;
}
// Bump arena over one context allocation (the runtime's static-arena shape).
struct BumpArena {
  uint32_t *base = nullptr;
  uint64_t words = 0, used = 0, allocs = 0;
  static uint32_t *alloc(void *user, uint64_t n) {
    auto *self = static_cast<BumpArena *>(user);
    const uint64_t at = (self->used + 63) & ~uint64_t(63);
    if (at > self->words || n > self->words - at) return nullptr;
    self->used = at + n;
    ++self->allocs;
    return self->base + at;
  }
  static void release(void *, uint32_t *, uint64_t) {}
};
// Enqueue-only proof: the whole PCS enqueue is captured into a CUDA graph in
// GLOBAL capture mode, where any synchronizing call (stream/event/device sync,
// synchronous memcpy, cudaMalloc, D2H read by the host) invalidates capture.
// The graph is then replayed twice; both replays must equal the legacy words.
static int capture_mode(const char *fixture, const std::string &prefix) {
  FixtureWords file(fixture);
  auto input = rv64_pcs_pipeline::parse(file);
  std::vector<uint32_t> legacy;
  {
    FileOwner owner(0);
    legacy = rv64_pcs_pipeline::run(owner, input).words;
    owner.close();
  }
  uint32_t params[4];
  auto request = nativeRequest(input, params);
  std::vector<StwoRv64PcsColumn> columns;
  for (const auto &c : input.coefficients)
    columns.push_back({0, uint32_t(__builtin_ctzll(c.size())), c.data(), c.size(), 0, 0});
  request.coefficients = columns.data();
  request.coefficient_count = columns.size();
  StwoCudaContextOptions options{1, 0, 1, 8};
  void *ctx = nullptr;
  CHECK(stwo_exec_context_create_options(&options, &ctx));
  StwoRv64PcsJobPlan plan{};
  if (stwo_rv64_pcs_job_plan_v1(&request, &plan))
    throw std::runtime_error(std::string("plan: ") + stwo_rv64_pcs_job_error_v1());
  BumpArena arena;
  arena.words = uint64_t(64) << 20;
  CHECK(stwo_exec_context_alloc_u32(ctx, arena.words, &arena.base));
  uint32_t *seed = BumpArena::alloc(&arena, 16), *point = BumpArena::alloc(&arena, 16),
           *output = BumpArena::alloc(&arena, plan.output_words);
  std::vector<uint32_t> state(16, 0);
  std::copy(input.sections[1].begin(), input.sections[1].end(), state.begin());
  CHECK(cudaMemcpy(seed, state.data(), 64, cudaMemcpyHostToDevice));
  if (input.sections[0][21])
    CHECK(cudaMemcpy(point, input.sections[2].data(), 64, cudaMemcpyHostToDevice));
  CHECK(cudaDeviceSynchronize());
  uint32_t *pinned = nullptr;
  CHECK(cudaMallocHost(reinterpret_cast<void **>(&pinned), plan.ingress_words * 4));
  void *stream_raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(ctx, 0, &stream_raw));
  auto stream = reinterpret_cast<cudaStream_t>(stream_raw);
  StwoRv64PcsJobMemory memory{&arena, BumpArena::alloc, BumpArena::release, pinned, plan.ingress_words};
  StwoRv64PcsJobIo io{seed, input.sections[0][21] ? point : nullptr, nullptr, output, plan.output_words};
  cudaGraph_t graph = nullptr;
  CHECK(cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal));
  const int rc = stwo_rv64_pcs_job_enqueue_v1(ctx, 0, &request, &memory, &io);
  const auto end = cudaStreamEndCapture(stream, &graph);
  if (rc) throw std::runtime_error(std::string("captured enqueue: ") + stwo_rv64_pcs_job_error_v1());
  CHECK(end);
  size_t nodes = 0;
  CHECK(cudaGraphGetNodes(graph, nullptr, &nodes));
  std::vector<cudaGraphNode_t> all(nodes);
  CHECK(cudaGraphGetNodes(graph, all.data(), &nodes));
  size_t kernels = 0, copies = 0;
  for (auto n : all) {
    cudaGraphNodeType type;
    CHECK(cudaGraphNodeGetType(n, &type));
    kernels += type == cudaGraphNodeTypeKernel;
    copies += type == cudaGraphNodeTypeMemcpy;
  }
  cudaGraphExec_t exec = nullptr;
  CHECK(cudaGraphInstantiate(&exec, graph, 0));
  int identical = 0;
  for (int run = 0; run < 2; ++run) {
    CHECK(cudaMemsetAsync(output, 0, plan.output_words * 4, stream));
    cudaEvent_t b, e;
    CHECK(cudaEventCreate(&b));
    CHECK(cudaEventCreate(&e));
    CHECK(cudaEventRecord(b, stream));
    CHECK(cudaGraphLaunch(exec, stream));
    CHECK(cudaEventRecord(e, stream));
    CHECK(cudaEventSynchronize(e));
    float ms = 0;
    CHECK(cudaEventElapsedTime(&ms, b, e));
    std::vector<uint32_t> job(plan.output_words);
    CHECK(cudaMemcpy(job.data(), output, job.size() * 4, cudaMemcpyDeviceToHost));
    write_words(prefix + ".graph" + std::to_string(run) + ".bin", job);
    identical += job == legacy;
    std::printf("PCS_JOB_GRAPH run=%d capture_mode=global graph_nodes=%zu kernel_nodes=%zu memcpy_nodes=%zu "
                "arena_allocs=%llu arena_used_words=%llu gpu_ms=%.6f byte_identical=%d\n",
                run, nodes, kernels, copies, (unsigned long long)arena.allocs,
                (unsigned long long)arena.used, ms, int(job == legacy));
    CHECK(cudaEventDestroy(b));
    CHECK(cudaEventDestroy(e));
  }
  CHECK(cudaGraphExecDestroy(exec));
  CHECK(cudaGraphDestroy(graph));
  CHECK(cudaFreeHost(pinned));
  if (identical != 2) throw std::runtime_error("captured job PCS differs from legacy");
  std::printf("PASS pcs_enqueue_parity mode=capture\n");
  return 0;
}
int main(int argc, char **argv) {
  try {
    if (argc == 4 && std::string(argv[1]) == "capture")
      return capture_mode(argv[2], argv[3]);
    if (argc == 5 && std::string(argv[1]) == "oods")
      return oods_mode(argv[2], argv[3], argv[4]);
    if (argc != 4 || (std::string(argv[2]) != "host" && std::string(argv[2]) != "device"))
      throw std::runtime_error("usage: pcs_enqueue_parity FIXTURE host|device OUT_PREFIX");
    const bool device_columns = std::string(argv[2]) == "device";
    FixtureWords file(argv[1]);
    auto input = rv64_pcs_pipeline::parse(file);
    std::vector<uint32_t> legacy;
    {
      FileOwner owner(0);
      legacy = rv64_pcs_pipeline::run(owner, input).words;
      owner.close();
    }
    write_words(std::string(argv[3]) + ".legacy.bin", legacy);
    const auto h = input.sections[0];
    // Native request: section 16 = half-coset parameters derived from the
    // fixture's bit-reversed domain, as pcs_native_fixture_check.py does.
    constexpr uint64_t p = 0x7fffffffu;
    const uint64_t x = input.domain[0], y = input.domain[1];
    const uint64_t nx = input.domain[(size_t(1) << (h[4] - 1)) * 2],
                   ny = input.domain[(size_t(1) << (h[4] - 1)) * 2 + 1];
    const uint32_t params[4] = {uint32_t(x), uint32_t(y), uint32_t((nx * x + ny * y) % p),
                                uint32_t((ny * x + (p - nx) * y % p) % p)};
    StwoRv64PcsNativeRequest request{};
    request.version = 1;
    request.section_count = 17;
    for (size_t i = 0; i < 16; ++i)
      request.sections[i] = {input.sections[i].data(), input.sections[i].size()};
    request.sections[16] = {params, 4};
    StwoCudaContextOptions options{1, 0, 1, 8};
    void *ctx = nullptr;
    CHECK(stwo_exec_context_create_options(&options, &ctx));
    TestArena arena{ctx};
    // Device transcript stand-ins: a 16-word channel state whose first nine
    // words are the PCS seed, and the imported OODS point, both device-resident.
    std::vector<uint32_t> state(16, 0);
    std::copy(input.sections[1].begin(), input.sections[1].end(), state.begin());
    uint32_t *seed = TestArena::alloc(&arena, 16), *point = nullptr;
    CHECK(cudaMemcpy(seed, state.data(), 64, cudaMemcpyHostToDevice));
    if (h[21]) {
      point = TestArena::alloc(&arena, 16);
      CHECK(cudaMemcpy(point, input.sections[2].data(), 64, cudaMemcpyHostToDevice));
    }
    // Replace the host seed/point sections by poison: only device values count.
    std::vector<uint32_t> poison_seed(9, 0x13579bdf), poison_point(16, 0x2468ace0 & 0x3fffffff);
    request.sections[1] = {poison_seed.data(), 9};
    if (h[21]) request.sections[2] = {poison_point.data(), 16};
    std::vector<StwoRv64PcsColumn> columns;
    uint32_t *warehouse = nullptr;
    uint64_t total = 0;
    for (const auto &c : input.coefficients) total += c.size();
    if (device_columns) {
      warehouse = TestArena::alloc(&arena, total);
      uint64_t at = 0;
      for (const auto &c : input.coefficients) {
        CHECK(cudaMemcpy(warehouse + at, c.data(), c.size() * 4, cudaMemcpyHostToDevice));
        at += c.size();
      }
    }
    uint64_t at = 0;
    for (const auto &c : input.coefficients) {
      const uint32_t log = uint32_t(__builtin_ctzll(c.size()));
      if (device_columns) columns.push_back({1, log, warehouse + at, c.size(), 1, 1});
      else columns.push_back({0, log, c.data(), c.size(), 0, 0});
      at += c.size();
    }
    request.coefficients = columns.data();
    request.coefficient_count = columns.size();
    StwoRv64PcsJobPlan plan{};
    if (stwo_rv64_pcs_job_plan_v1(&request, &plan))
      throw std::runtime_error(std::string("plan: ") + stwo_rv64_pcs_job_error_v1());
    if (plan.output_words != legacy.size())
      throw std::runtime_error("plan output words differ from legacy readback");
    uint32_t *pinned = nullptr;
    CHECK(cudaMallocHost(reinterpret_cast<void **>(&pinned), plan.ingress_words * 4));
    void *stream = nullptr;
    CHECK(stwo_exec_context_lane_stream(ctx, 0, &stream));
    int identical = 0;
    for (int run = 0; run < 2; ++run) {
      uint32_t *output = TestArena::alloc(&arena, plan.output_words);
      StwoRv64PcsJobMemory memory{&arena, TestArena::alloc, TestArena::release, pinned, plan.ingress_words};
      StwoRv64PcsJobIo io{seed, point, nullptr, output, plan.output_words};
      const uint64_t calls_before = arena.calls;
      cudaEvent_t begin, end;
      CHECK(cudaEventCreate(&begin));
      CHECK(cudaEventCreate(&end));
      CHECK(cudaEventRecord(begin, reinterpret_cast<cudaStream_t>(stream)));
      if (stwo_rv64_pcs_job_enqueue_v1(ctx, 0, &request, &memory, &io))
        throw std::runtime_error(std::string("enqueue: ") + stwo_rv64_pcs_job_error_v1());
      CHECK(cudaEventRecord(end, reinterpret_cast<cudaStream_t>(stream)));
      CHECK(cudaEventSynchronize(end)); // the worker's single host wait
      std::vector<uint32_t> job(plan.output_words);
      CHECK(cudaMemcpy(job.data(), output, job.size() * 4, cudaMemcpyDeviceToHost));
      float ms = 0;
      CHECK(cudaEventElapsedTime(&ms, begin, end));
      write_words(std::string(argv[3]) + ".job" + std::to_string(run) + ".bin", job);
      const bool equal = job == legacy;
      identical += equal;
      std::printf("PCS_JOB_PARITY run=%d columns=%s rolling=%u imported=%u output_words=%llu "
                  "ingress_words=%llu steps=%u arena_allocs=%llu arena_peak_bytes=%llu "
                  "gpu_ms=%.6f byte_identical=%d\n",
                  run, argv[2], plan.rolling, h[21], (unsigned long long)plan.output_words,
                  (unsigned long long)plan.ingress_words, plan.steps,
                  (unsigned long long)(arena.calls - calls_before),
                  (unsigned long long)arena.peak, ms, int(equal));
      if (!equal) {
        size_t first = 0;
        while (first < job.size() && job[first] == legacy[first]) ++first;
        std::fprintf(stderr, "first differing word %zu of %zu\n", first, job.size());
      }
      TestArena::release(&arena, output, plan.output_words);
      arena.drain();
      CHECK(cudaEventDestroy(begin));
      CHECK(cudaEventDestroy(end));
    }
    CHECK(cudaFreeHost(pinned));
    if (identical != 2) throw std::runtime_error("job PCS proof words differ from legacy");
    std::printf("PASS pcs_enqueue_parity columns=%s byte_identical_runs=2\n", argv[2]);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "FAIL %s\n", e.what());
    return 1;
  }
}
