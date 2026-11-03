#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/ls_dword_witness.h"
#include <algorithm>
#include <numeric>
static void exercise(const std::string &directory, uint32_t id) {
  FixtureWords f(directory + "/case-" + std::to_string(id) + ".bin");
  const auto h = f.take(8);
  if (h[0] != 0x52564457 || h[1] != 1 || h[2] != id || h[3] < 5 || h[3] > 22 ||
      h[4] >= (1u << h[3]) || h[5] != 39 || h[6] != 14 || h[7])
    throw std::runtime_error("LS-D64 fixture shape");
  const uint32_t log = h[3], n = 1u << log, count = h[4];
  const auto input = f.take(uint64_t(count) * 14);
  const auto expected = f.take(uint64_t(n) * 39);
  if (f.position != f.data.size())
    throw std::runtime_error("LS-D64 fixture trailing words");
  Owner o(0);
  const auto events = o.plane(std::max(1u, count * 14), 1),
             output = o.plane(n, 39), verdict = o.plane(1, 1);
  if (count)
    o.upload(events, input);
  o.upload(verdict, {0});
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  void *raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
  const auto stream = reinterpret_cast<cudaStream_t>(raw);
  CHECK(stwo_rv64_ls_dword_witness_on(o.ctx, 1, events.words, count, log,
                                      output.words, verdict.words));
  CHECK(cudaStreamSynchronize(stream));
  const auto begin = o.event(), end = o.event();
  std::vector<float> times;
  for (uint32_t rep = 0; rep < 9; ++rep) {
    CHECK(cudaEventRecord(begin, stream));
    CHECK(stwo_rv64_ls_dword_witness_on(o.ctx, 1, events.words, count, log,
                                        output.words, verdict.words));
    CHECK(cudaEventRecord(end, stream));
    CHECK(cudaEventSynchronize(end));
    float ms = 0;
    CHECK(cudaEventElapsedTime(&ms, begin, end));
    times.push_back(ms);
  }
  fixture_equal("LS-D64 native physical MAIN", o.read(output), expected);
  if (o.read(verdict)[0])
    throw std::runtime_error("valid LS-D64 event rejected");
  std::sort(times.begin(), times.end());
  const double median_ms = times[times.size() / 2];
  std::printf(
      "{\"case\":%u,\"log\":%u,\"events\":%u,\"main_cells\":%llu,\"gpu_ms_"
      "median\":%.9f,\"ns_per_main_cell\":%.9f,\"native_parity\":true}\n",
      id, log, count, static_cast<unsigned long long>(uint64_t(n) * 39),
      median_ms, median_ms * 1e6 / (uint64_t(n) * 39));
  if (id == 1) {
    Owner foreign(0);
    const auto wrong_owner = foreign.plane(n, 39);
    if (!stwo_rv64_ls_dword_witness_on(o.ctx, 1, events.words, count, log,
                                       wrong_owner.words, verdict.words))
      throw std::runtime_error("LS-D64 foreign output admitted");
    foreign.close();
    if (!stwo_rv64_ls_dword_witness_on(o.ctx, 1, events.words, n, log,
                                       output.words, verdict.words))
      throw std::runtime_error("LS-D64 missing padding row admitted");
    if (!stwo_rv64_ls_dword_witness_on(o.ctx, 1, output.words, count, log,
                                       output.words, verdict.words))
      throw std::runtime_error("LS-D64 input/output alias admitted");
    for (uint32_t fault = 0; fault < 14; ++fault) {
      auto bad = input;
      switch (fault) {
      case 0:
        bad[11] = 0;
        break;
      case 1:
        bad[9] = 65536;
        break;
      case 2:
        bad[8] = 65536;
        break;
      case 3:
        bad[10] = 1u << 24;
        break;
      case 4:
        bad[11] = 1u << 24;
        break;
      case 5:
        bad[8] = 1;
        bad[9] = 0;
        break;
      case 6:
        bad[12] = 0;
        break;
      case 7:
        bad[12] = 4;
        break;
      case 8:
        bad[13] = 2;
        break;
      case 9:
        bad[0] |= 1;
        break;
      case 10:
        bad[10] = bad[11];
        break;
      case 11:
        bad[13] = 0;
        bad[4] = 1;
        break;
      case 12:
        bad[12] = 1;
        break;
      case 13:
        bad[13] = 0;
        bad[4] = bad[5] = 0;
        bad[12] = 2;
        break;
      }
      const uint32_t zero = 0;
      CHECK(cudaMemcpyAsync(events.words, bad.data(), bad.size() * 4,
                            cudaMemcpyHostToDevice, stream));
      CHECK(cudaMemcpyAsync(verdict.words, &zero, 4, cudaMemcpyHostToDevice,
                            stream));
      CHECK(stwo_rv64_ls_dword_witness_on(o.ctx, 1, events.words, count, log,
                                          output.words, verdict.words));
      if (!o.read(verdict)[0])
        throw std::runtime_error("LS-D64 malformed event admitted");
      auto repaired = expected;
      for (uint32_t c = 0; c < 39; ++c)
        repaired[uint64_t(c) * n] = 0;
      fixture_equal("LS-D64 invalid event row is zero", o.read(output),
                    repaired);
    }
  }
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected native LS-D64 fixtures");
    for (uint32_t id = 0; id < 4; ++id)
      exercise(argv[1], id);
    std::printf("PASS LS-D64 native MAIN parity cases=4 event_mutations=14\n");
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "FAIL %s\n", e.what());
    return 1;
  }
}
