// Production hybrid helper: invoked by the native proof's composition stage.
// Compact coefficients in, joined quotient evaluations out; no CPU evaluation.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "real_composition_launches.h"
#include <chrono>
#include <fstream>
extern "C" int stwo_lde_n2b_addressed_on(uint32_t *, size_t, const void *,
                                         uint32_t, size_t, uint32_t,
                                         const uint32_t *, uint32_t, uint32_t,
                                         void *, uint32_t, uint32_t *);
static void execute(const char *input, const char *output) {
  const auto wall_start = std::chrono::steady_clock::now();
  FixtureWords f(input);
  const auto head = f.take(4);
  if (head[0] != 0x52565243 || head[1] != 1 || head[2] > 96 || head[3] > 1)
    throw std::runtime_error("real composition header");
  std::ofstream result(output, std::ios::binary);
  if (!result)
    throw std::runtime_error("composition output");
  double gpu_ms = 0;
  uint64_t input_cells = 0, eval_cells = 0, peak_bytes = 0;
  for (uint32_t role = 0; role < head[2]; ++role) {
    const auto h = f.take(12);
    const uint32_t id = h[0], trace_log = h[1], log = h[2],
                   columns = h[3] + h[4] + h[5];
    if (id >= 49 || !real_kernels[id] || trace_log < 5 ||
        log != trace_log + 1 || log > 24 || !columns || columns > 8192 ||
        h[6] > 65536 || h[7] > 1024 || !h[8] || h[8] > 8192 || h[11])
      throw std::runtime_error("real composition shape");
    const uint64_t n = uint64_t(1) << log;
    const auto offsets = f.take(h[6] * 2);
    auto metadata = f.take(columns * 3);
    // Header flag0 is the first native producer's carry[8],first,second ABI;
    // flag1 is canonical IR first,second,carry[8]. Normalize descriptors only.
    if (head[3] == 0 && id < 47) {
      if (h[5] < 10)
        throw std::runtime_error("missing public auxiliaries");
      const size_t first = (columns - 10) * 3;
      const auto old = metadata;
      constexpr uint32_t order[] = {8, 9, 0, 1, 2, 3, 4, 5, 6, 7};
      for (size_t c = 0; c < 10; ++c)
        for (size_t word = 0; word < 3; ++word)
          metadata[first + c * 3 + word] = old[first + order[c] * 3 + word];
    }
    const auto coefficients = f.take(h[9]), twiddles = f.take(h[10]),
               params = f.take(h[7] * 8), powers = f.take(h[8] * 8),
               denom = f.take(2);
    const uint64_t eval_base = h[9], twiddle_base = eval_base + columns * n,
                   desc_base = twiddle_base + h[10],
                   arena_words = desc_base + columns * 6;
    if ((arena_words + 8 * n) * 4 > (uint64_t(30) << 30))
      throw std::runtime_error("real composition VRAM admission");
    Owner o(0);
    auto upload = [&](const std::vector<uint32_t> &v) {
      auto p = o.plane(std::max(size_t(1), v.size()), 1);
      if (!v.empty())
        o.upload(p, v);
      return p;
    };
    auto arena = o.plane(arena_words, 1), out = o.plane(8 * n, 1);
    o.upload({arena.words, h[9], 1, 0}, coefficients);
    o.upload({arena.words + twiddle_base, h[10], 1, 0}, twiddles);
    std::vector<uint32_t> descriptors;
    for (uint32_t c = 0; c < columns; ++c) {
      const uint32_t degree = metadata[c * 3];
      const uint64_t source = uint64_t(metadata[c * 3 + 1]) |
                              (uint64_t(metadata[c * 3 + 2]) << 32),
                     destination = eval_base + c * n;
      if (degree > log || degree < 1 || source + (uint64_t(1) << degree) > h[9])
        throw std::runtime_error("coefficient metadata");
      descriptors.insert(descriptors.end(),
                         {uint32_t(source), uint32_t(source >> 32),
                          uint32_t(destination), uint32_t(destination >> 32),
                          degree, 0});
    }
    o.upload({arena.words + desc_base, uint64_t(columns) * 6, 1, 0},
             descriptors);
    auto off = upload(offsets), parameters = upload(params),
         weights = upload(powers), inverses = upload(denom);
    void *raw = nullptr;
    CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
    auto stream = reinterpret_cast<cudaStream_t>(raw);
    void *ingress_raw = nullptr;
    CHECK(stwo_exec_context_lane_stream(o.ctx, 0, &ingress_raw));
    CHECK(cudaMemsetAsync(out.words, 0, 8 * n * 4,
                          reinterpret_cast<cudaStream_t>(ingress_raw)));
    StwoCudaDependency ready{};
    CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
    CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
    cudaEvent_t begin, end;
    CHECK(cudaEventCreate(&begin));
    CHECK(cudaEventCreate(&end));
    o.events.push_back(begin);
    o.events.push_back(end);
    CHECK(cudaEventRecord(begin, stream));
    uint32_t launches = 0;
    CHECK(stwo_lde_n2b_addressed_on(arena.words, arena_words,
                                    arena.words + desc_base, columns, eval_base,
                                    log, arena.words + twiddle_base, h[10],
                                    uint32_t(n / 2), raw, 1, &launches));
    const uint32_t *t0 = arena.words + eval_base, *t1 = t0 + h[3] * n,
                   *t2 = t1 + h[4] * n, *p = parameters.words,
                   *pw = weights.words, *d = inverses.words;
    const uint64_t *offset = reinterpret_cast<const uint64_t *>(off.words);
    uint32_t *destination = out.words, first = 0, rows = uint32_t(n),
             tl = trace_log, el = log;
    void *args[] = {&t0, &t1,          &t2, &offset, &p,     &pw,
                    &d,  &destination, &tl, &el,     &first, &rows};
    CHECK(cudaLaunchKernel(real_kernels[id], dim3((rows + 127) / 128, real_root_group_sizes[id] ?
                               (h[8] + real_root_group_sizes[id] - 1) / real_root_group_sizes[id] : 1),
                           dim3(128), args, 0, stream));
    CHECK(cudaEventRecord(end, stream));
    CHECK(cudaEventSynchronize(end));
    float elapsed = 0;
    CHECK(cudaEventElapsedTime(&elapsed, begin, end));
    gpu_ms += elapsed;
    input_cells += h[9];
    eval_cells += columns * n;
    peak_bytes = std::max(peak_bytes, o.allocated_bytes);
    const auto values = o.read(out);
    result.write(reinterpret_cast<const char *>(values.data()),
                 values.size() * 4);
    if (!result)
      throw std::runtime_error("composition write");
    std::printf("ROLE id=%u trace_log=%u columns=%u gpu_ms=%.6f\n", id,
                trace_log, columns, elapsed);
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    o.close();
  }
  if (f.position != f.data.size())
    throw std::runtime_error("trailing composition job");
  const double wall_ms = std::chrono::duration<double, std::milli>(
                             std::chrono::steady_clock::now() - wall_start)
                             .count();
  std::printf("REAL_COMPOSITION roles=%u gpu_ms=%.6f helper_wall_ms=%.6f "
              "input_coefficient_cells=%llu evaluated_base_cells=%llu "
              "device_ns_per_evaluated_cell=%.6f peak_allocated_bytes=%llu\n",
              head[2], gpu_ms, wall_ms, (unsigned long long)input_cells,
              (unsigned long long)eval_cells,
              eval_cells ? gpu_ms * 1e6 / eval_cells : 0,
              (unsigned long long)peak_bytes);
}
int main(int argc, char **argv) {
  try {
    if (argc != 3)
      throw std::runtime_error("expected input/output paths");
    execute(argv[1], argv[2]);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
