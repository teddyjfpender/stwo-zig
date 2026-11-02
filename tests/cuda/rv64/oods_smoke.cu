// Full extension-field OODS evaluation of offline-generated native AIR DAGs.
// Numerical qualification only: this driver does not authenticate PCS masks.
#include "composition_launches.h"
#include "context_owner.cuh"
#include "fixture_reader.h"
#include <algorithm>

static void exercise(const std::string &directory, uint32_t index) {
  rv64_fixture::Fixture file(directory + "/oods-" + std::to_string(index) +
                             ".bin");
  const auto h = file.take(6);
  if (h[0] != 0x52564f44 || h[1] != 1 || h[2] != index || h[3] > 65536 ||
      h[4] > 65536 || h[5] > 65536)
    throw std::runtime_error("OODS fixture geometry");
  Owner owner(0);
  auto upload = [&](std::vector<uint32_t> words) {
    const auto allocation = owner.plane(std::max(size_t(1), words.size()), 1);
    if (!words.empty())
      owner.upload(allocation, words);
    return allocation;
  };
  const auto inputs = upload(file.take(8 * h[3]));
  const auto parameters = upload(file.take(8 * h[4]));
  const auto powers = upload(file.take(8 * h[5]));
  const auto inverse = upload(file.take(8));
  const auto output = upload(file.take(8));
  const auto expected = file.take(8);
  if (file.cursor != file.data.size())
    throw std::runtime_error("trailing OODS fixture");
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(owner.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(owner.ctx, 1, &ready));
  void *raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(owner.ctx, 1, &raw));
  const uint32_t *i = inputs.words, *p = parameters.words, *w = powers.words,
                 *d = inverse.words;
  uint32_t *out = output.words;
  void *arguments[] = {&i, &p, &w, &d, &out};
  CHECK(cudaLaunchKernel(oods_kernels[index], dim3(2), dim3(32), arguments, 0,
                         reinterpret_cast<cudaStream_t>(raw)));
  if (owner.read(output) != expected)
    throw std::runtime_error("native OM31 OODS mismatch");
  CHECK(stwo_exec_context_dependency_release(owner.ctx, &ready));
  owner.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected fixture directory");
    for (uint32_t i = 0; i < composition_case_count; ++i)
      exercise(argv[1], i);
    std::printf("OM31_OODS cases=%u native_parity=PASS\n",
                composition_case_count);
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
  }
}
