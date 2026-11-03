#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/cpu_witness.h"
#include <chrono>
static void exercise(const std::string &directory, uint32_t id) {
  FixtureWords f(directory + "/case-" + std::to_string(id) + ".bin");
  const auto h = f.take(8);
  if (h[0] != 0x52564357 || h[1] != 2 || h[2] != id || h[3] < 5 || h[3] > 22 ||
      h[4] >= (1u << h[3]) || h[5] != 5 || h[6] != 8192 || h[7] != 37)
    throw std::runtime_error("CPU witness fixture shape");
  const uint32_t n = 1u << h[3], count = h[4];
  const auto metadata = f.take(uint64_t(count) * 14), rom = f.take(32 * 32);
  const auto expected = f.take(uint64_t(37) * n), c16 = f.take(65536),
             c8 = f.take(256), cr = f.take(32), cp = f.take(65536);
  if (f.position != f.data.size()) throw std::runtime_error("trailing fixture data");
  Owner o(0);
  auto input = o.plane(std::max(uint64_t(1), uint64_t(count) * 14), 1),
       fixed = o.plane(32 * 32, 1), main = o.plane(n, 37),
       counts16 = o.plane(65536, 1), counts8 = o.plane(256, 1),
       counts_rom = o.plane(32, 1), status = o.plane(1, 1), pairs = o.plane(65536, 1);
  if (count) o.upload(input, metadata);
  o.upload(fixed, rom);
  o.upload(counts16, std::vector<uint32_t>(65536));
  o.upload(counts8, std::vector<uint32_t>(256));
  o.upload(counts_rom, std::vector<uint32_t>(32));
  o.upload(status, {0});
  o.upload(pairs, std::vector<uint32_t>(65536));
  CHECK(stwo_exec_context_sync(o.ctx));
  StwoRv64CpuWitness j{input.words, fixed.words, main.words, counts16.words,
                       counts8.words, counts_rom.words, status.words,
                       count, h[3], h[5], h[6], pairs.words};
  void *raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
  const auto stream = reinterpret_cast<cudaStream_t>(raw);
  const auto begin = o.event(), end = o.event();
  CHECK(cudaEventRecord(begin, stream));
  CHECK(stwo_rv64_cpu_witness_on(o.ctx, 1, &j));
  CHECK(cudaEventRecord(end, stream));
  CHECK(cudaEventSynchronize(end));
  float ms = 0;
  CHECK(cudaEventElapsedTime(&ms, begin, end));
  fixture_equal("compact CPU MAIN", o.read(main), expected);
  fixture_equal("CPU U16 multiplicities", o.read(counts16), c16);
  fixture_equal("CPU U8 multiplicities", o.read(counts8), c8);
  fixture_equal("CPU ROM multiplicities", o.read(counts_rom), cr);
  fixture_equal("CPU U8-pair multiplicities", o.read(pairs), cp);
  if (o.read(status)[0]) throw std::runtime_error("valid CPU metadata rejected");
  if (id == 1) {
    auto bad = metadata;
    bad[10] = 1; // row zero, rs1 tick 1, previous clock must be strictly less.
    o.upload(input, bad); CHECK(stwo_exec_context_sync(o.ctx));
    CHECK(stwo_rv64_cpu_witness_on(o.ctx, 1, &j));
    if (!o.read(status)[0]) throw std::runtime_error("invalid clock admitted");
    auto alias = j; alias.main = input.words;
    if (!stwo_rv64_cpu_witness_on(o.ctx, 1, &alias))
      throw std::runtime_error("input/output alias admitted");
    Owner foreign(0); auto foreign_status = foreign.plane(1, 1);
    auto cross = j; cross.status = foreign_status.words;
    if (!stwo_rv64_cpu_witness_on(o.ctx, 1, &cross))
      throw std::runtime_error("foreign status admitted");
    foreign.close();
    auto geometry = j; geometry.count = n;
    if (!stwo_rv64_cpu_witness_on(o.ctx, 1, &geometry))
      throw std::runtime_error("missing padding admitted");
  }
  std::printf("{\"case\":%u,\"log\":%u,\"active_rows\":%u,\"main_cells\":%llu,\"gpu_ms\":%.6f,\"native_main_and_histogram_parity\":true}\n",
      id, h[3], count, (unsigned long long)37 * n, ms);
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc < 2 || argc > 3) throw std::runtime_error("expected fixture directory [large]");
    for (uint32_t i = 0; i < (argc == 3 ? 4u : 3u); ++i) exercise(argv[1], i);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "FAIL %s\n", e.what()); return 1;
  }
}
