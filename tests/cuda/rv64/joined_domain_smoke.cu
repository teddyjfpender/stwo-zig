// Offline-generated native AIR kernels; no runtime compilation or CPU fallback.
#include "composition_launches.h"
#include "context_owner.cuh"
#include "rv64/composition.cuh"
#include "rv64/composition_dispatch.h"
#include <algorithm>
#include <fstream>
#include <iterator>
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
#ifdef STWO_RV64_NATIVE_ROLE_DISPATCH
    StwoRv64CompositionRole job{};
    job.role=index; job.trace_log=trace_log; job.eval_log=eval_log;
    job.first_row=first; job.row_count=count;
    job.trees[0]=a; job.trees[1]=b; job.trees[2]=c;
    for(uint32_t tree=0;tree<3;++tree) job.tree_words[tree]=std::max(uint64_t(1),uint64_t(h[4+tree])*rows);
    job.column_offsets=off; job.mask_count=h[7]; job.parameters=p;
    job.parameter_count=h[8]; job.powers=pw; job.constraint_count=h[9];
    job.denominator_inverses=d; job.output=out;
    uint32_t launches=0;
    CHECK(stwo_rv64_composition_role_on(o.ctx,1,&job,&launches));
    if(launches!=1) throw std::runtime_error("missing native role launch receipt");
#else
    CHECK(cudaLaunchKernel(kernels[index], dim3((count + 127) / 128, composition_groups[index]),
                           dim3(128), arguments, 0, reinterpret_cast<cudaStream_t>(raw)));
#endif
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
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected joined domain fixtures");
    for (uint32_t id = 0; id < composition_case_count; ++id)
      for (uint32_t tiles : {1u, 3u})
        exercise(argv[1], id, tiles);
    std::printf("PASS joined DOMAIN layouts=%u tile_cases=%u "
                "native_parity=true full_block_verified=false\n",
                composition_case_count, composition_case_count * 2);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
