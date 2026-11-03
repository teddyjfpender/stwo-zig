#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/channel.h"
#include "rv64/trace.h"
#include <fstream>
namespace b = stwo::cuda::blake2s;
static void words(std::ofstream &f, const std::vector<uint32_t> &data) {
  for (auto word : data) {
    const unsigned char bytes[] = {static_cast<unsigned char>(word),
                                   static_cast<unsigned char>(word >> 8),
                                   static_cast<unsigned char>(word >> 16),
                                   static_cast<unsigned char>(word >> 24)};
    f.write(reinterpret_cast<const char *>(bytes), 4);
  }
  if (!f)
    throw std::runtime_error("trace capture write");
}
__global__ void trace_bad_query(uint32_t *q, uint32_t value) { *q = value; }
__global__ void trace_bad_value(uint32_t *slab, const uint32_t *queries,
                                uint32_t lifting, uint32_t source_log) {
  const uint32_t q = queries[0];
  const uint32_t row = lifting >= source_log
                           ? ((q >> (lifting - source_log + 1)) << 1) | (q & 1)
                           : ((q >> 1) << (source_log - lifting + 1)) | (q & 1);
  slab[row] = 0x7fffffffu;
}
static void exercise(const std::string &fixtures, const std::string &outputs,
                     uint32_t id, uint32_t fault = 0) {
  FixtureWords f(fixtures + "/case-" + std::to_string(id) + ".bin");
  const auto h = f.take(11);
  if (h[0] != 0x52565452 || h[1] != 1 || h[2] != id)
    throw std::runtime_error("trace fixture header");
  const uint32_t log = h[3], lifting = h[4], queries = h[5], columns = h[6],
                 segments = h[7];
  const auto logs = f.take(columns), order = f.take(columns),
             metadata = f.take(segments * 6), seed = f.take(9),
             expected_root = f.take(8), expected_queries = f.take(queries),
             expected_channel = f.take(16), slab_values = f.take(h[8]);
  f.take(uint64_t(columns) * h[10]);
  f.take(uint64_t(h[9]) * 8);
  if (f.position != f.data.size())
    throw std::runtime_error("trace fixture trailing words");
  Owner o(0);
  auto upload = [&](const std::vector<uint32_t> &v) {
    auto p = o.plane(v.size(), 1);
    o.upload(p, v);
    return p;
  };
  auto slab = upload(slab_values), checkpoint = upload(seed);
  const uint64_t tree_words = ((uint64_t(2) << log) - 1) * 8,
                 value_words = uint64_t(columns) * queries,
                 path_words = uint64_t(queries) * log * 8;
  uint64_t prefix_rows = 0;
  for (uint32_t i = 0; i + 1 < segments; ++i)
    if (metadata[6 * i + 4] != metadata[6 * (i + 1) + 4])
      prefix_rows = metadata[6 * i + 4];
  const uint64_t tree_capacity = tree_words + 48 * prefix_rows;
  auto tree = o.plane(tree_capacity + 8, 1), values = o.plane(value_words + 8, 1),
       paths = o.plane(path_words + 8, 1), raw = o.plane(queries, 1),
       state = o.plane(16, 1), boundary = o.plane(16, 1),
       status = o.plane(1, 1);
  o.upload(tree, std::vector<uint32_t>(tree_capacity + 8, 0x1234567));
  o.upload(values, std::vector<uint32_t>(value_words + 8, 0x1234567));
  o.upload(paths, std::vector<uint32_t>(path_words + 8, 0x1234567));
  o.upload(status, {fault == 3 ? 0x40000000u : 0u});
  std::vector<b::MixedSegment> input;
  for (uint32_t i = 0; i < segments; ++i) {
    const auto *m = metadata.data() + i * 6;
    const uint64_t offset = uint64_t(m[0]) | (uint64_t(m[1]) << 32);
    if (m[5] || offset + uint64_t(m[2]) * m[3] > slab_values.size())
      throw std::runtime_error("trace segment fixture");
    input.push_back(
        {slab.words + offset, m[2], uint64_t(m[2]) * m[3], m[4], 0});
  }
  CHECK(stwo_exec_context_sync(o.ctx));
  CHECK(stwo_rv64_trace_tree_on(o.ctx, 1, input.data(), segments, log,
                                tree.words, tree_capacity));
  CHECK(stwo_rv64_channel_init_on(o.ctx, 1, state.words, checkpoint.words, 1));
  CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, state.words, 0, 1, 2,
                                 tree.words + tree_words - 8, 8, 0,
                                 boundary.words));
  CHECK(stwo_rv64_channel_queries_on(o.ctx, 1, state.words, 1, 2, 3, lifting,
                                     queries, raw.words, boundary.words));
  void *native_stream = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &native_stream));
  auto stream = reinterpret_cast<cudaStream_t>(native_stream);
  if (fault == 1)
    trace_bad_query<<<1, 1, 0, stream>>>(raw.words, 1u << lifting);
  if (fault == 2)
    trace_bad_value<<<1, 1, 0, stream>>>(slab.words, raw.words, lifting,
                                         __builtin_ctz(input[0].source_size));
  StwoRv64TraceOpen job{tree.words,   raw.words,  values.words, paths.words,
                        status.words, tree_words, value_words,  path_words,
                        log,          lifting,    queries,      0};
  CHECK(stwo_rv64_trace_open_on(o.ctx, 1, input.data(), segments, &job));
  const auto verdict = o.read(status)[0];
  if (fault) {
    if (!verdict)
      throw std::runtime_error("trace mutant accepted");
    o.close();
    return;
  }
  if (verdict)
    throw std::runtime_error("honest trace rejected");
  auto actual_tree = o.read(tree), actual_raw = o.read(raw),
       actual_values = o.read(values), actual_paths = o.read(paths),
       actual_channel = o.read(state);
  if (!std::equal(expected_root.begin(), expected_root.end(),
                  actual_tree.begin() + tree_words - 8) ||
      actual_raw != expected_queries || actual_channel != expected_channel)
    throw std::runtime_error("native trace root/channel/query mismatch");
  for (uint64_t i = tree_capacity; i < actual_tree.size(); ++i)
    if (actual_tree[i] != 0x1234567)
      throw std::runtime_error("trace tree guard overwritten");
  for (uint64_t i = value_words; i < actual_values.size(); ++i)
    if (actual_values[i] != 0x1234567)
      throw std::runtime_error("trace value guard overwritten");
  for (uint64_t i = path_words; i < actual_paths.size(); ++i)
    if (actual_paths[i] != 0x1234567)
      throw std::runtime_error("trace path guard overwritten");
  // The compatibility path must produce the exact same complete Merkle tree.
  CHECK(stwo_rv64_trace_tree_on(o.ctx, 1, input.data(), segments, log,
                               tree.words, tree_words));
  const auto compatibility_tree = o.read(tree);
  if (!std::equal(actual_tree.begin(), actual_tree.begin() + tree_words,
                  compatibility_tree.begin()))
    throw std::runtime_error("owned scratch changed native Merkle tree");
  if (!stwo_rv64_trace_tree_on(o.ctx, 1, input.data(), segments, log,
                               tree.words, tree_words - 1))
    throw std::runtime_error("short tree accepted");
  if (!stwo_rv64_trace_tree_on(o.ctx, 1, input.data(), segments, log,
                               slab.words, tree_words))
    throw std::runtime_error("source/tree alias accepted");
  auto bad = input;
  bad[0].reserved = 1;
  if (!stwo_rv64_trace_tree_on(o.ctx, 1, bad.data(), segments, log, tree.words,
                               tree_words))
    throw std::runtime_error("reserved segment accepted");
  bad = input;
  bad[0].source_size = 3;
  if (!stwo_rv64_trace_tree_on(o.ctx, 1, bad.data(), segments, log, tree.words,
                               tree_words))
    throw std::runtime_error("invalid source size accepted");
  if (segments > 1) {
    bad = input;
    std::swap(bad[0], bad.back());
    if (!stwo_rv64_trace_tree_on(o.ctx, 1, bad.data(), segments, log,
                                 tree.words, tree_words))
      throw std::runtime_error("noncanonical segment order accepted");
  }
  auto bad_job = job;
  bad_job.paths = values.words;
  if (!stwo_rv64_trace_open_on(o.ctx, 1, input.data(), segments, &bad_job))
    throw std::runtime_error("opening alias accepted");
  bad_job = job;
  bad_job.value_words = value_words - 1;
  if (!stwo_rv64_trace_open_on(o.ctx, 1, input.data(), segments, &bad_job))
    throw std::runtime_error("short opening accepted");
  bad_job = job;
  bad_job.query_count = 0;
  if (!stwo_rv64_trace_open_on(o.ctx, 1, input.data(), segments, &bad_job))
    throw std::runtime_error("empty query set accepted");
  Owner other(0);
  auto foreign = other.plane(1, 1);
  bad_job = job;
  bad_job.status = foreign.words;
  if (!stwo_rv64_trace_open_on(o.ctx, 1, input.data(), segments, &bad_job))
    throw std::runtime_error("foreign status accepted");
  other.close();
  std::ofstream out(outputs + "/case-" + std::to_string(id) + ".bin",
                    std::ios::binary);
  words(out, {0x5256544f, 1, id, queries, columns, log});
  words(out, {actual_tree.begin() + tree_words - 8,
              actual_tree.begin() + tree_words});
  words(out, actual_raw);
  words(out, {actual_values.begin(), actual_values.begin() + value_words});
  words(out, {actual_paths.begin(), actual_paths.begin() + path_words});
  words(out, {verdict});
  words(out, actual_channel);
  std::printf("TRACE case=%u columns=%u tree_log=%u lifting_log=%u "
              "hot_readbacks=0 native_exact=true\n",
              id, columns, log, lifting);
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 3)
      throw std::runtime_error("expected fixture and readback directories");
    for (uint32_t id = 0; id < 6; ++id)
      exercise(argv[1], argv[2], id);
    for (uint32_t fault = 1; fault <= 3; ++fault)
      exercise(argv[1], argv[2], 0, fault);
    std::puts("PASS native trace cases=6 mutants=3");
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "FAIL %s\n", e.what());
    return 1;
  }
}
