// Offline-generated native AIR kernels; no runtime compilation or CPU fallback.
#include "context_owner.cuh"
#include "rv64/composition.cuh"
#include <algorithm>
#include <fstream>
#include <iterator>
#define DECL(N)                                                                \
  extern "C" __global__ void rv64_composition_fixture_##N(                     \
      const uint32_t *, const uint32_t *, const uint32_t *, const uint64_t *,  \
      const uint32_t *, const uint32_t *, const uint32_t *, uint32_t *,        \
      uint32_t, uint32_t, uint32_t, uint32_t);
DECL(0)
DECL(1)
DECL(2)
DECL(3) DECL(4) DECL(5) DECL(6) DECL(7) DECL(8) static const void *kernels[] = {
    (void *)rv64_composition_fixture_0, (void *)rv64_composition_fixture_1,
    (void *)rv64_composition_fixture_2, (void *)rv64_composition_fixture_3,
    (void *)rv64_composition_fixture_4, (void *)rv64_composition_fixture_5,
    (void *)rv64_composition_fixture_6, (void *)rv64_composition_fixture_7,
    (void *)rv64_composition_fixture_8};
static void exercise(const std::string &directory, uint32_t index,
                     uint32_t tiles) {
  const auto file = directory + "/case-" + std::to_string(index) + ".bin";
  std::ifstream f(file, std::ios::binary | std::ios::ate);
  if (!f)
    throw std::runtime_error("missing fixture: " + file);
  const auto bytes = f.tellg();
  if (bytes < 48 || bytes > uint64_t(1) << 30 || uint64_t(bytes) % 4)
    throw std::runtime_error("fixture size");
  std::vector<uint32_t> data(size_t(bytes) / 4);
  f.seekg(0);
  f.read(reinterpret_cast<char *>(data.data()), bytes);
  size_t cursor = 0;
  auto take = [&](size_t n) {
    if (n > data.size() - cursor)
      throw std::runtime_error("truncated fixture");
    std::vector<uint32_t> v(data.begin() + cursor, data.begin() + cursor + n);
    cursor += n;
    return v;
  };
  const auto h = take(12);
  if (h[0] != 0x52564350 || h[1] != 1 || h[2] > h[3] || h[3] > 22 ||
      h[7] > 65536 || h[8] > 65536 || h[9] > 65536 || h[10] > (1u << 22) ||
      h[11] != index)
    throw std::runtime_error("fixture geometry");
  const uint32_t rows = 1u << h[3];
  Owner o(0);
  auto upload = [&](std::vector<uint32_t> v) {
    const auto p = o.plane(std::max(size_t(1), v.size()), 1);
    if (!v.empty())
      o.upload(p, v);
    return p;
  };
  const auto t0 = upload(take(size_t(h[4]) * rows));
  const auto t1 = upload(take(size_t(h[5]) * rows));
  const auto t2 = upload(take(size_t(h[6]) * rows));
  const auto offsets = upload(take(2 * h[7]));
  const auto params = upload(take(8 * h[8]));
  const auto powers = upload(take(8 * h[9]));
  const auto denom = upload(take(1u << (h[3] - h[2])));
  const auto output = upload(take(8 * rows));
  const auto expected = take(8 * rows);
  if (cursor != data.size())
    throw std::runtime_error("trailing fixture");
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  void *raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
  const uint32_t *a = t0.words, *b = t1.words, *c = t2.words, *p = params.words,
                 *pw = powers.words, *d = denom.words;
  const uint64_t *off = reinterpret_cast<const uint64_t *>(offsets.words);
  uint32_t *out = output.words, trace_log = h[2], eval_log = h[3];
  for (uint32_t tile = 0; tile < tiles; ++tile) {
    uint32_t first = uint64_t(rows) * tile / tiles;
    uint32_t count = uint64_t(rows) * (tile + 1) / tiles - first;
    void *arguments[] = {&a, &b,   &c,         &off,      &p,     &pw,
                         &d, &out, &trace_log, &eval_log, &first, &count};
    CHECK(cudaLaunchKernel(kernels[index], dim3((count + 127) / 128), dim3(128),
                           arguments, 0, reinterpret_cast<cudaStream_t>(raw)));
  }
  const auto got = o.read(output);
  if (got != expected) {
    for (size_t i = 0; i < got.size(); ++i)
      if (got[i] != expected[i]) {
        std::fprintf(stderr, "role=%u tiles=%u word=%zu got=%u expected=%u\n",
                     index, tiles, i, got[i], expected[i]);
        break;
      }
    throw std::runtime_error("native OM31 composition mismatch");
  }
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
}
__global__ void mask_rows(const uint32_t *records, uint32_t count,
                          uint32_t *out) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < count)
    out[i] = stwo::cuda::rv64::composition_mask_row(
        records[5 * i], records[5 * i + 1], records[5 * i + 2],
        int32_t(records[5 * i + 3]));
}
static uint32_t check_masks(const std::string &directory) {
  std::ifstream f(directory + "/mask-positions.bin",
                  std::ios::binary | std::ios::ate);
  const auto bytes = f.tellg();
  if (!f || bytes <= 0 || uint64_t(bytes) % 20)
    throw std::runtime_error("mask fixture");
  std::vector<uint32_t> records(size_t(bytes) / 4);
  f.seekg(0);
  f.read(reinterpret_cast<char *>(records.data()), bytes);
  const uint32_t count = records.size() / 5;
  Owner o(0);
  const auto input = o.plane(records.size(), 1), output = o.plane(count + 8, 1);
  o.upload(input, records);
  o.upload(output, std::vector<uint32_t>(count + 8, 0xcafef00du));
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  void *raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
  mask_rows<<<(count + 127) / 128, 128, 0,
              reinterpret_cast<cudaStream_t>(raw)>>>(input.words, count,
                                                     output.words);
  CHECK(cudaPeekAtLastError());
  const auto got = o.read(output);
  for (uint32_t i = 0; i < count; ++i)
    if (got[i] != records[5 * i + 4])
      throw std::runtime_error("global lifted mask mismatch");
  for (uint32_t i = count; i < count + 8; ++i)
    if (got[i] != 0xcafef00du)
      throw std::runtime_error("mask canary");
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
  return count;
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected native fixture directory");
    const auto mask_cases = check_masks(argv[1]);
    for (uint32_t role = 0; role < 9; ++role)
      for (uint32_t tiles : {1u, 3u})
        exercise(argv[1], role, tiles);
    std::printf(
        "{\"schema\":\"rv64-om31-composition-v1\",\"native_roles\":8,"
        "\"cases\":18,\"mask_cases\":%u,\"full_block_verified\":false}\n",
        mask_cases);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
