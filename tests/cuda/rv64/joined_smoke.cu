// Numerical joined AIR qualification. Synthetic metadata is not execution
// admission, authenticated PCS masks, or a complete GPU proof.
#include "context_owner.cuh"
#include "fixture_reader.h"
#include "joined_launches.h"
#include "rv64/parameters.h"
#include <algorithm>
#include <array>

static void exercise(const std::string &directory, uint32_t index) {
  rv64_fixture::Fixture f(directory + "/case-" + std::to_string(index) +
                          ".bin");
  const auto h = f.take(8);
  if (h[0] != 0x52564a50 || h[1] != 1 || h[2] != index || h[3] > 65536 ||
      !h[4] || h[4] > STWO_RV64_JOINED_PARAMETER_COUNT || h[5] > 65536 ||
      h[6] != 3 || h[7] != STWO_RV64_JOINED_PARAMETER_COUNT)
    throw std::runtime_error("joined fixture geometry");
  const auto addresses = f.take(2 * h[4]);
  for (uint32_t mode = 0; mode < 3; ++mode) {
    if (f.take(1)[0] != mode)
      throw std::runtime_error("joined mode order");
    Owner o(0);
    auto upload = [&](std::vector<uint32_t> words) {
      const auto p = o.plane(std::max(size_t(1), words.size()), 1);
      if (!words.empty())
        o.upload(p, words);
      return p;
    };
    const auto inputs = upload(f.take(8 * h[3]));
    StwoRv64JoinedParameters job{};
    for (uint32_t ns = 0; ns < 5; ++ns) {
      const uint32_t n =
          STWO_RV64_JOINED_NAMESPACE_COUNTS[ns] * (ns == 0 ? 1 : 8);
      job.sources[ns] = upload(f.take(n)).words;
    }
    job.addresses = upload(addresses).words;
    std::vector<uint32_t> guarded(8 * h[4] + 8, 0xdeadbeefu);
    const auto params = upload(guarded), status = upload({0});
    job.output = params.words;
    job.status = status.words;
    job.count = h[4];
    const auto powers = upload(f.take(8 * h[5]));
    const auto inverse = upload(f.take(8));
    auto output_words = f.take(8);
    output_words.resize(16, 0xcafef00du);
    const auto output = upload(output_words);
    auto expected = f.take(8);
    expected.resize(16, 0xcafef00du);
    StwoCudaDependency ready{};
    CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
    CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
    void *raw = nullptr;
    CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
    CHECK(stwo_rv64_joined_parameter_gather_on(o.ctx, 1, &job));
    const uint32_t *in = inputs.words, *p = params.words, *pw = powers.words,
                   *d = inverse.words;
    uint32_t *out = output.words;
    void *arguments[] = {&in, &p, &pw, &d, &out};
    CHECK(cudaLaunchKernel(joined_kernels[index], dim3(2), dim3(32), arguments,
                           0, reinterpret_cast<cudaStream_t>(raw)));
    rv64_fixture::equal(o.read(output), expected, "joined native residual",
                        index);
    const auto got = o.read(params);
    for (size_t i = 8 * h[4]; i < got.size(); ++i)
      if (got[i] != 0xdeadbeefu)
        throw std::runtime_error("parameter guard");
    if (o.read(status)[0] != 0)
      throw std::runtime_error("valid metadata rejected");
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    o.close();
  }
  if (f.cursor != f.data.size())
    throw std::runtime_error("trailing joined fixture");
}

static void poisoned_map(uint32_t ns, uint32_t fault) {
  Owner o(0);
  StwoRv64JoinedParameters job{};
  for (uint32_t i = 0; i < 5; ++i) {
    const uint32_t count =
        STWO_RV64_JOINED_NAMESPACE_COUNTS[i] * (i == 0 ? 1 : 8);
    auto p = o.plane(count, 1);
    std::vector<uint32_t> source(count, 1);
    if (fault == 0 && i == ns)
      source[0] = 0xffffffffu;
    o.upload(p, source);
    job.sources[i] = p.words;
  }
  const auto map = o.plane(2, 1), out = o.plane(16, 1), status = o.plane(1, 1);
  o.upload(map, {fault == 1 ? 5 : ns,
                 fault == 2 ? STWO_RV64_JOINED_NAMESPACE_COUNTS[ns] : 0});
  o.upload(out, std::vector<uint32_t>(16, 0xdeadbeefu));
  o.upload(status, {0x10});
  job.addresses = map.words;
  job.output = out.words;
  job.status = status.words;
  job.count = 1;
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  CHECK(stwo_rv64_joined_parameter_gather_on(o.ctx, 1, &job));
  if (o.read(status)[0] != (0x10u | (fault == 0 ? 1u : 2u)))
    throw std::runtime_error("metadata poison verdict");
  const auto got = o.read(out);
  for (uint32_t i = 0; i < 16; ++i) {
    const uint32_t expected = i >= 8                            ? 0xdeadbeefu
                              : fault != 0 || ns == 0 || i == 0 ? 0
                                                                : 1;
    if (got[i] != expected)
      throw std::runtime_error("metadata poison guard");
  }
  // Host-side custody rejection must leave the queue usable and output intact.
  auto invalid = job;
  invalid.reserved = 1;
  if (!stwo_rv64_joined_parameter_gather_on(o.ctx, 1, &invalid))
    throw std::runtime_error("reserved metadata accepted");
  invalid = job;
  invalid.count = STWO_RV64_JOINED_PARAMETER_COUNT + 1;
  if (!stwo_rv64_joined_parameter_gather_on(o.ctx, 1, &invalid))
    throw std::runtime_error("excess metadata accepted");
  invalid = job;
  invalid.output = const_cast<uint32_t *>(job.sources[0]);
  if (!stwo_rv64_joined_parameter_gather_on(o.ctx, 1, &invalid))
    throw std::runtime_error("aliased metadata accepted");
  {
    Owner foreign(0);
    const auto foreign_source = foreign.plane(24, 1);
    invalid = job;
    invalid.sources[4] = foreign_source.words;
    if (!stwo_rv64_joined_parameter_gather_on(o.ctx, 1, &invalid))
      throw std::runtime_error("foreign metadata accepted");
    foreign.close();
  }
  if (o.read(out) != got)
    throw std::runtime_error("rejected metadata mutated output");
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected fixture directory");
    for (uint32_t id = 0; id < joined_case_count; ++id)
      exercise(argv[1], id);
    for (uint32_t ns = 0; ns < 5; ++ns)
      poisoned_map(ns, 0);
    poisoned_map(0, 1);
    poisoned_map(0, 2);
    std::printf(
        "JOINED_OM31 layouts=%u modes=3 poison_cases=7 native_parity=PASS\n",
        joined_case_count);
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
  }
}
