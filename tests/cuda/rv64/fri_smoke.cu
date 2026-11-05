// Resident FRI commit, raw query draw and compact opening readback. A separate
// native process assembles/verifies the resulting FriProof after GPU
// completion.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/channel.h"
#include "rv64/fri.h"
#include <filesystem>
__global__ void fri_tamper(uint32_t *p, uint32_t value) { *p = value; }
static void write_words(std::ofstream &f, const std::vector<uint32_t> &words) {
  for (auto word : words) {
    const unsigned char bytes[4] = {static_cast<unsigned char>(word),
                                    static_cast<unsigned char>(word >> 8),
                                    static_cast<unsigned char>(word >> 16),
                                    static_cast<unsigned char>(word >> 24)};
    f.write(reinterpret_cast<const char *>(bytes), 4);
  }
  if (!f)
    throw std::runtime_error("FRI capture write");
}
struct LayerStorage {
  StwoRv64Plane column{}, tree{}, alpha{}, values{}, paths{};
  uint32_t count = 0, steps = 0, leaf = 0, shift = 0, height = 0;
  uint64_t tree_words = 0, value_words = 0, path_words = 0;
};
static void exercise(const std::string &directory, const std::string &outputs,
                     uint32_t id, uint32_t fault = 0) {
  FixtureWords f(directory + "/case-" + std::to_string(id) + ".bin");
  const auto h = f.take(10);
  if (h[0] != 0x52564652 || h[1] != 1 || h[2] != id || !h[8] || h[8] > 28 ||
      !h[6] || h[6] > 1024)
    throw std::runtime_error("FRI fixture header");
  const uint32_t layers = h[8], queries = h[6], rows = 1u << h[7];
  const auto seed = f.take(9), description = f.take(layers * 8),
             twiddles = f.take(h[9]), input = f.take(uint64_t(rows) * 8),
             roots = f.take(layers * 8), alphas = f.take(layers * 8),
             expected_terminal = f.take(8), expected_queries = f.take(queries),
             expected_channel = f.take(16);
  if (f.position != f.data.size())
    throw std::runtime_error("FRI fixture trailing bytes");
  Owner o(0);
  auto upload = [&](const std::vector<uint32_t> &v) {
    auto p = o.plane(v.size(), 1);
    o.upload(p, v);
    return p;
  };
  const auto checkpoint = upload(seed), tw = upload(twiddles),
             state = o.plane(16, 1), boundary = o.plane(16, 1),
             raw = o.plane(queries + 4, 1), terminal = o.plane(16, 1),
             status = upload({fault == 4 ? 32u : 0u});
  o.upload(raw, std::vector<uint32_t>(queries + 4, 0xdeadbeefu));
  o.upload(terminal, std::vector<uint32_t>(16, 0xdeadbeefu));
  std::vector<LayerStorage> storage(layers);
  for (uint32_t i = 0; i < layers; ++i) {
    const auto *d = description.data() + i * 8;
    auto &s = storage[i];
    s.count = d[0];
    s.steps = d[1];
    s.leaf = d[2];
    s.shift = d[3];
    const uint32_t leaves = s.count >> s.leaf;
    s.height = 31u - uint32_t(__builtin_clz(leaves));
    s.tree_words = (uint64_t(leaves) * 2 - 1) * 8;
    s.value_words = uint64_t(queries) * (8u << s.steps);
    s.path_words =
        uint64_t(queries) * (1u << (s.steps - s.leaf)) * s.height * 8;
    s.column = o.plane(s.count, 8);
    s.tree = o.plane(s.tree_words + 8, 1);
    o.upload({s.tree.words + s.tree_words, 8, 1, 0},
             std::vector<uint32_t>(8, 0xdeadbeefu));
    s.alpha = o.plane(8, 1);
    s.values = o.plane(s.value_words + 4, 1);
    s.paths = o.plane(s.path_words + 4, 1);
    o.upload(s.values, std::vector<uint32_t>(s.value_words + 4, 0xdeadbeefu));
    o.upload(s.paths, std::vector<uint32_t>(s.path_words + 4, 0xdeadbeefu));
  }
  o.upload(storage[0].column, input);
  const auto last = o.plane(1u << h[4], 8);
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  void *handle = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &handle));
  const auto stream = reinterpret_cast<cudaStream_t>(handle);
  CHECK(stwo_rv64_channel_init_on(o.ctx, 1, state.words, checkpoint.words, 17));
  uint32_t step = 0;
  for (uint32_t i = 0; i < layers; ++i) {
    auto &s = storage[i];
    auto short_words = s.tree_words - 1;
    if (!stwo_rv64_fri_tree_on(o.ctx, 1, s.column, s.count, s.leaf,
                               s.tree.words, short_words))
      throw std::runtime_error("FRI undersized tree accepted");
    if (!stwo_rv64_fri_tree_on(o.ctx, 1, s.column, s.count, s.leaf,
                               s.tree.words + 1, s.tree_words))
      throw std::runtime_error("FRI misaligned hash tree accepted");
    CHECK(stwo_rv64_fri_tree_on(o.ctx, 1, s.column, s.count, s.leaf,
                                s.tree.words, s.tree_words));
    const uint32_t *root = s.tree.words + s.tree_words - 8;
    CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, state.words, step, 17 + step,
                                   18 + step, root, 8, 0, boundary.words));
    ++step;
    CHECK(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, step, 17 + step,
                                    18 + step, 1, s.alpha.words,
                                    boundary.words));
    ++step;
    StwoRv64FriFold fold{};
    fold.input = s.column;
    fold.output = i + 1 < layers ? storage[i + 1].column : last;
    fold.twiddles = tw.words;
    fold.twiddle_words = twiddles.size();
    fold.alpha = s.alpha.words;
    for (uint32_t k = 0; k < 4; ++k)
      fold.offsets[k] = description[i * 8 + 4 + k];
    fold.count = s.count;
    fold.steps = s.steps;
    fold.first_is_circle = i == 0;
    CHECK(stwo_rv64_fri_fold_on(o.ctx, 1, &fold));
  }
  if (fault == 1)
    fri_tamper<<<1, 1, 0, stream>>>(last.words, 42);
  if (fault == 2)
    fri_tamper<<<1, 1, 0, stream>>>(last.words, 0x7fffffffu);
  if (!stwo_rv64_fri_terminal_on(o.ctx, 1, last, 1u << h[4], last.words,
                                 status.words))
    throw std::runtime_error("FRI terminal alias accepted");
  CHECK(stwo_rv64_fri_terminal_on(o.ctx, 1, last, 1u << h[4], terminal.words,
                                  status.words));
  CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, state.words, step, 17 + step,
                                 18 + step, terminal.words, 8, 1,
                                 boundary.words));
  ++step;
  CHECK(stwo_rv64_channel_queries_on(o.ctx, 1, state.words, step, 17 + step,
                                     18 + step, h[7], queries, raw.words,
                                     boundary.words));
  ++step;
  if (fault == 3)
    fri_tamper<<<1, 1, 0, stream>>>(raw.words, 0xffffffffu);
  for (auto &s : storage) {
    StwoRv64FriOpen open{s.column,       s.tree.words,  raw.words,
                         s.values.words, s.paths.words, status.words,
                         s.tree_words,   s.value_words, s.path_words,
                         s.count,        queries,       s.steps,
                         s.leaf,         s.shift,       0};
    auto invalid = open;
    invalid.values = s.tree.words;
    if (!stwo_rv64_fri_open_on(o.ctx, 1, &invalid))
      throw std::runtime_error("FRI opening alias accepted");
    invalid = open;
    invalid.value_words = s.value_words - 1;
    if (!stwo_rv64_fri_open_on(o.ctx, 1, &invalid))
      throw std::runtime_error("FRI short opening accepted");
    CHECK(stwo_rv64_fri_open_on(o.ctx, 1, &open));
  }
  const auto verdict = o.read(status)[0];
  const auto actual_raw = o.read(raw), actual_terminal = o.read(terminal),
             actual_channel = o.read(state);
  for (size_t i = queries; i < actual_raw.size(); ++i)
    if (actual_raw[i] != 0xdeadbeefu)
      throw std::runtime_error("query guard");
  for (size_t i = 8; i < actual_terminal.size(); ++i)
    if (actual_terminal[i] != 0xdeadbeefu)
      throw std::runtime_error("terminal guard");
  std::vector<std::vector<uint32_t>> collected_values, collected_paths,
      collected_roots;
  for (uint32_t i = 0; i < layers; ++i) {
    auto &s = storage[i];
    auto values = o.read(s.values), paths = o.read(s.paths);
    for (size_t j = s.value_words; j < values.size(); ++j)
      if (values[j] != 0xdeadbeefu)
        throw std::runtime_error("FRI value guard");
    for (size_t j = s.path_words; j < paths.size(); ++j)
      if (paths[j] != 0xdeadbeefu)
        throw std::runtime_error("FRI path guard");
    values.resize(s.value_words);
    paths.resize(s.path_words);
    const StwoRv64Plane root{s.tree.words + s.tree_words - 8, 8, 1, 0};
    fixture_equal("FRI tree guard",
                  o.read({s.tree.words + s.tree_words, 8, 1, 0}),
                  std::vector<uint32_t>(8, 0xdeadbeefu));
    auto root_words = o.read(root);
    if (!fault) {
      fixture_equal("native FRI root", root_words,
                    {roots.begin() + i * 8, roots.begin() + i * 8 + 8});
      fixture_equal("native FRI fold alpha", o.read(s.alpha),
                    {alphas.begin() + i * 8, alphas.begin() + i * 8 + 8});
    }
    collected_values.push_back(std::move(values));
    collected_paths.push_back(std::move(paths));
    collected_roots.push_back(std::move(root_words));
  }
  if (!fault) {
    if (verdict)
      throw std::runtime_error("honest FRI status");
    fixture_equal("native FRI terminal",
                  {actual_terminal.begin(), actual_terminal.begin() + 8},
                  expected_terminal);
    fixture_equal("native FRI raw queries",
                  {actual_raw.begin(), actual_raw.begin() + queries},
                  expected_queries);
    fixture_equal("native FRI terminal channel", actual_channel,
                  expected_channel);
    std::ofstream out(outputs + "/case-" + std::to_string(id) + ".bin",
                      std::ios::binary);
    write_words(out, {0x5256464f, 1, id, layers, queries});
    write_words(out, actual_channel);
    write_words(out, {verdict});
    write_words(out, {actual_terminal.begin(), actual_terminal.begin() + 8});
    write_words(out, {actual_raw.begin(), actual_raw.begin() + queries});
    for (uint32_t i = 0; i < layers; ++i) {
      write_words(out, collected_roots[i]);
      write_words(out, collected_values[i]);
      write_words(out, collected_paths[i]);
    }
  } else if (!verdict)
    throw std::runtime_error("FRI mutant accepted");
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
  std::printf("{\"case\":%u,\"layers\":%u,\"queries\":%u,\"fault\":%u,"
              "\"status\":%u,\"result\":\"PASS\"}\n",
              id, layers, queries, fault, verdict);
}
int main(int argc, char **argv) {
  try {
    if (argc != 3)
      throw std::runtime_error("usage: fri-smoke FIXTURES OUTPUTS");
    std::filesystem::create_directories(argv[2]);
    for (uint32_t i = 0; i < 6; ++i)
      exercise(argv[1], argv[2], i);
    for (uint32_t fault = 1; fault <= 4; ++fault)
      exercise(argv[1], argv[2], 0, fault);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "FRI FAIL: %s\n", e.what());
    return 1;
  }
}
