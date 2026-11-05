// Complete resident native PCS path. Only compact proof material is read back.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/channel.h"
#include "rv64/deep.h"
#include "rv64/fri.h"
#include "rv64/samples.h"
#include "rv64/trace.h"
#include <fstream>
extern "C" int stwo_lde_n2b_addressed_on(uint32_t *, size_t, const void *,
                                         uint32_t, size_t, uint32_t,
                                         const uint32_t *, uint32_t, uint32_t,
                                         void *, uint32_t, uint32_t *);
namespace b = stwo::cuda::blake2s;
static void write_words(std::ofstream &f, const std::vector<uint32_t> &data) {
  for (auto word : data) {
    const unsigned char bytes[] = {static_cast<unsigned char>(word),
                                   static_cast<unsigned char>(word >> 8),
                                   static_cast<unsigned char>(word >> 16),
                                   static_cast<unsigned char>(word >> 24)};
    f.write(reinterpret_cast<const char *>(bytes), 4);
  }
  if (!f)
    throw std::runtime_error("PCS capture write");
}
struct FriStorage {
  StwoRv64Plane column, tree, alpha, values, paths;
  uint32_t count, steps, leaf, shift;
  uint64_t tree_words, value_words, path_words;
};
static void exercise(const std::string &input_path,
                     const std::string &output_path) {
  FixtureWords f(input_path);
  const auto h = f.take(20);
  if (h[0] != 0x52565043 || h[1] != 1 || h[2] || h[17] || h[18] || h[19])
    throw std::runtime_error("PCS fixture header");
  const uint32_t degree = h[3], log = h[4], queries = h[6], sc = h[8],
                 gc = h[9], layers = h[10], rows = 1u << log;
  const auto initial_seed = f.take(9), sources = f.take(sc * 4),
             terms = f.take(sc * 4), groups = f.take(gc * 8),
             source_groups = f.take(gc * 8), recipes = f.take(gc * 4),
             source_coefficients = f.take(h[11]), twiddles = f.take(h[13]),
             descriptions = f.take(layers * 8), fri_twiddles = f.take(h[16]),
             domain = f.take(rows * 2), expected_root = f.take(8),
             expected_proof_hash = f.take(8), expected_channel = f.take(9);
  if (f.position != f.data.size())
    throw std::runtime_error("PCS fixture trailing words");
  Owner o(0);
  auto upload = [&](const std::vector<uint32_t> &v) {
    auto p = o.plane(v.size(), 1);
    o.upload(p, v);
    return p;
  };
  const uint64_t source_eval_base = h[11],
                 combined_coeff_base = source_eval_base + h[12],
                 combined_eval_base = combined_coeff_base + h[14],
                 twiddle_base = combined_eval_base + h[15],
                 descriptor_base = twiddle_base + h[13];
  const uint64_t arena_words = descriptor_base + uint64_t(sc + 8 * gc) * 6;
  const auto arena = o.plane(arena_words, 1);
  o.upload({arena.words, h[11], 1, 0}, source_coefficients);
  o.upload({arena.words + twiddle_base, h[13], 1, 0}, twiddles);
  std::vector<StwoRv64Plane> source_descriptors, combined_descriptors;
  std::vector<b::MixedSegment> trace_segments;
  uint64_t descriptor_offset = descriptor_base;
  auto descriptor = [&](uint64_t source, uint64_t destination,
                        uint32_t coefficient_log, std::vector<uint32_t> &v) {
    v.insert(v.end(),
             {uint32_t(source), uint32_t(source >> 32), uint32_t(destination),
              uint32_t(destination >> 32), coefficient_log, 0});
  };
  uint64_t sample_scratch_words = 0;
  for (uint32_t g = 0; g < gc; ++g) {
    const auto *s = source_groups.data() + g * 8, *d = groups.data() + g * 8;
    const uint64_t eval_offset = uint64_t(s[0]) | (uint64_t(s[1]) << 32);
    const uint32_t n = 1u << s[2], m = 1u << s[3];
    if (s[4] + s[5] > sc || s[3] != s[2] + h[5] || s[5] != d[1] - d[0])
      throw std::runtime_error("PCS source geometry");
    std::vector<uint32_t> source_packets, combined_packets;
    for (uint32_t j = 0; j < s[5]; ++j) {
      const uint32_t *c = sources.data() + (s[4] + j) * 4;
      descriptor(uint64_t(c[0]) | (uint64_t(c[1]) << 32),
                 source_eval_base + eval_offset + uint64_t(j) * m, s[2],
                 source_packets);
    }
    for (uint32_t c = 0; c < 8; ++c)
      descriptor(
          combined_coeff_base + (uint64_t(d[4]) | (uint64_t(d[5]) << 32)) +
              uint64_t(c) * n,
          combined_eval_base + (uint64_t(d[6]) | (uint64_t(d[7]) << 32)) +
              uint64_t(c) * m,
          s[2], combined_packets);
    StwoRv64Plane packet{arena.words + descriptor_offset, source_packets.size(),
                         1, 0};
    o.upload(packet, source_packets);
    source_descriptors.push_back(packet);
    descriptor_offset += source_packets.size();
    packet = {arena.words + descriptor_offset, combined_packets.size(), 1, 0};
    o.upload(packet, combined_packets);
    combined_descriptors.push_back(packet);
    descriptor_offset += combined_packets.size();
    trace_segments.push_back({arena.words + source_eval_base + eval_offset, m,
                              uint64_t(m) * s[5], m, 0});
    sample_scratch_words =
        std::max(sample_scratch_words, uint64_t((n + 1023) / 1024) * s[5] * 8);
  }
  if (descriptor_offset != arena_words)
    throw std::runtime_error("PCS arena plan mismatch");
  const auto seed = upload(initial_seed), src = upload(sources),
             term = upload(terms), grp = upload(groups),
             recipe = upload(recipes), xy = upload(domain),
             fri_tw = upload(fri_twiddles);
  const auto state = o.plane(16, 1), boundary = o.plane(16, 1),
             parameter = o.plane(8, 1), point_arena = o.plane((gc + 1) * 16, 1),
             factors = o.plane(gc * 28 * 8, 1),
             point_ready = o.plane(gc + 1, 1),
             sample_scratch_a = o.plane(sample_scratch_words, 1),
             sample_scratch_b = o.plane(sample_scratch_words, 1),
             sample_valid = o.plane(2, 1), values = o.plane(sc * 8, 1),
             alpha = o.plane(8, 1), weights = o.plane(sc * 8, 1),
             linear = o.plane(gc * 16, 1), deep_valid = o.plane(2, 1),
             deep = o.plane(rows, 8), terminal = o.plane(8, 1),
             raw = o.plane(queries, 1), nonce = upload({0, 0}),
             status = upload({0});
  const uint64_t trace_words = (uint64_t(2) * rows - 1) * 8;
  const auto trace = o.plane(trace_words, 1),
             trace_values = o.plane(uint64_t(sc) * queries, 1),
             trace_paths = o.plane(uint64_t(queries) * log * 8, 1),
             last = o.plane(1u << h[5], 8);
  std::vector<FriStorage> storage;
  for (uint32_t i = 0; i < layers; ++i) {
    const auto *d = descriptions.data() + i * 8;
    FriStorage s{};
    s.count = d[0];
    s.steps = d[1];
    s.leaf = d[2];
    s.shift = d[3];
    s.column = i == 0 ? deep : o.plane(s.count, 8);
    s.tree_words = (2ull * (s.count >> s.leaf) - 1) * 8;
    s.value_words = (uint64_t(queries) << s.steps) * 8;
    s.path_words = (uint64_t(queries) << (s.steps - s.leaf)) *
                   (uint32_t(__builtin_ctz(s.count)) - s.leaf) * 8;
    s.tree = o.plane(s.tree_words, 1);
    s.alpha = o.plane(8, 1);
    s.values = o.plane(s.value_words, 1);
    s.paths = o.plane(s.path_words, 1);
    storage.push_back(s);
  }
  CHECK(stwo_exec_context_sync(o.ctx));
  void *stream_raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &stream_raw));
  auto stream = reinterpret_cast<cudaStream_t>(stream_raw);
  auto begin = o.event(), end = o.event();
  CHECK(cudaEventRecord(begin, stream));
  auto extend = [&](uint32_t g, bool combined) {
    const auto *s = source_groups.data() + g * 8, *d = groups.data() + g * 8;
    uint32_t launches = 0;
    const uint64_t offset =
        combined
            ? combined_eval_base + (uint64_t(d[6]) | (uint64_t(d[7]) << 32))
            : source_eval_base + (uint64_t(s[0]) | (uint64_t(s[1]) << 32));
    const auto packet =
        combined ? combined_descriptors[g] : source_descriptors[g];
    CHECK(stwo_lde_n2b_addressed_on(
        arena.words, arena_words, packet.words, combined ? 8 : s[5], offset,
        s[3], arena.words + twiddle_base + s[6], s[7], 1u << (s[3] - 1),
        stream_raw, 1, &launches));
  };
  for (uint32_t g = 0; g < gc; ++g)
    extend(g, false);
  CHECK(stwo_rv64_trace_tree_on(o.ctx, 1, trace_segments.data(), gc, log,
                                trace.words, trace_words));
  CHECK(stwo_rv64_channel_init_on(o.ctx, 1, state.words, seed.words, 17));
  uint32_t step = 0;
  auto mix = [&](const uint32_t *p, uint32_t count, uint32_t field) {
    CHECK(stwo_rv64_channel_mix_on(o.ctx, 1, state.words, step, 17 + step,
                                   18 + step, p, count, field, boundary.words));
    ++step;
  };
  auto draw = [&](uint32_t *p) {
    CHECK(stwo_rv64_channel_draw_on(o.ctx, 1, state.words, step, 17 + step,
                                    18 + step, 1, p, boundary.words));
    ++step;
  };
  mix(trace.words + trace_words - 8, 8, 0);
  draw(parameter.words);
  StwoRv64SamplePoints point_job{
      parameter.words,
      reinterpret_cast<const StwoRv64PointRecipe *>(recipe.words),
      point_arena.words,
      factors.words,
      point_ready.words,
      status.words,
      gc,
      0};
  CHECK(stwo_rv64_sample_points_on(o.ctx, 1, &point_job));
  for (uint32_t g = 0; g < gc; ++g) {
    const auto *s = source_groups.data() + g * 8;
    StwoRv64SampleEvaluation sample{};
    sample.trees[0] = arena.words;
    sample.tree_words[0] = h[11];
    sample.sources = reinterpret_cast<const StwoRv64DeepSource *>(src.words);
    sample.terms = reinterpret_cast<const StwoRv64DeepTerm *>(term.words);
    sample.recipes =
        reinterpret_cast<const StwoRv64PointRecipe *>(recipe.words);
    sample.factors = factors.words;
    sample.point_ready = point_ready.words;
    sample.scratch_a = sample_scratch_a.words;
    sample.scratch_b = sample_scratch_b.words;
    sample.values = values.words;
    sample.valid = sample_valid.words;
    sample.status = status.words;
    sample.scratch_words = sample_scratch_words;
    sample.value_words = sc * 8;
    sample.source_count = sc;
    sample.term_capacity = sc;
    sample.group_count = gc;
    sample.first = s[4];
    sample.count = s[5];
    sample.coefficient_log = s[2];
    CHECK(stwo_rv64_sample_evaluate_on(o.ctx, 1, &sample));
  }
  mix(values.words, sc * 8, 1);
  draw(alpha.words);
  StwoRv64DeepPrepare prepare{};
  prepare.trees[0] = arena.words;
  prepare.tree_words[0] = h[11];
  prepare.sources = reinterpret_cast<const StwoRv64DeepSource *>(src.words);
  prepare.terms = reinterpret_cast<const StwoRv64DeepTerm *>(term.words);
  prepare.groups = reinterpret_cast<const StwoRv64DeepGroup *>(grp.words);
  prepare.points = point_arena.words + 16;
  prepare.values = values.words;
  prepare.alpha = alpha.words;
  prepare.weights = weights.words;
  prepare.linear = linear.words;
  prepare.coefficients = arena.words + combined_coeff_base;
  prepare.valid = deep_valid.words;
  prepare.status = status.words;
  prepare.coefficient_words = h[14];
  prepare.source_count = sc;
  prepare.term_count = sc;
  prepare.group_count = gc;
  CHECK(stwo_rv64_deep_prepare_on(o.ctx, 1, &prepare));
  for (uint32_t g = 0; g < gc; ++g)
    extend(g, true);
  StwoRv64DeepCombine combine{};
  combine.groups = reinterpret_cast<const StwoRv64DeepGroup *>(grp.words);
  combine.points = point_arena.words + 16;
  combine.linear = linear.words;
  combine.evaluations = arena.words + combined_eval_base;
  combine.domain_xy = xy.words;
  combine.valid = deep_valid.words;
  combine.output = deep;
  combine.status = status.words;
  combine.evaluation_words = h[15];
  combine.group_count = gc;
  combine.output_log = log;
  CHECK(stwo_rv64_deep_combine_on(o.ctx, 1, &combine));
  for (uint32_t i = 0; i < layers; ++i) {
    auto &s = storage[i];
    CHECK(stwo_rv64_fri_tree_on(o.ctx, 1, s.column, s.count, s.leaf,
                                s.tree.words, s.tree_words));
    mix(s.tree.words + s.tree_words - 8, 8, 0);
    draw(s.alpha.words);
    StwoRv64FriFold fold{};
    fold.input = s.column;
    fold.output = i + 1 < layers ? storage[i + 1].column : last;
    fold.twiddles = fri_tw.words;
    fold.twiddle_words = fri_twiddles.size();
    fold.alpha = s.alpha.words;
    for (uint32_t k = 0; k < 4; ++k)
      fold.offsets[k] = descriptions[i * 8 + 4 + k];
    fold.count = s.count;
    fold.steps = s.steps;
    fold.first_is_circle = i == 0;
    CHECK(stwo_rv64_fri_fold_on(o.ctx, 1, &fold));
  }
  CHECK(stwo_rv64_fri_terminal_on(o.ctx, 1, last, 1u << h[5], terminal.words,
                                  status.words));
  mix(terminal.words, 8, 1);
  mix(nonce.words, 2, 0);
  CHECK(stwo_rv64_channel_queries_on(o.ctx, 1, state.words, step, 17 + step,
                                     18 + step, log, queries, raw.words,
                                     boundary.words));
  ++step;
  for (auto &s : storage) {
    StwoRv64FriOpen open{s.column,       s.tree.words,  raw.words,
                         s.values.words, s.paths.words, status.words,
                         s.tree_words,   s.value_words, s.path_words,
                         s.count,        queries,       s.steps,
                         s.leaf,         s.shift,       0};
    CHECK(stwo_rv64_fri_open_on(o.ctx, 1, &open));
  }
  StwoRv64TraceOpen trace_open{trace.words,
                               raw.words,
                               trace_values.words,
                               trace_paths.words,
                               status.words,
                               trace_words,
                               uint64_t(sc) * queries,
                               uint64_t(queries) * log * 8,
                               log,
                               log,
                               queries,
                               0};
  CHECK(stwo_rv64_trace_open_on(o.ctx, 1, trace_segments.data(), gc,
                                &trace_open));
  CHECK(cudaEventRecord(end, stream));
  CHECK(cudaEventSynchronize(end));
  const auto verdict = o.read(status)[0];
  const auto final = o.read(state);
  const auto trace_root = o.read({trace.words + trace_words - 8, 8, 1, 0});
  if (verdict || final[10] || final[9] != step) {
    std::fprintf(stderr, "verdict=%u channel_status=%u step=%u wanted=%u\n",
                 verdict, final[10], final[9], step);
    throw std::runtime_error("resident PCS numerical failure");
  }
  if (!std::equal(expected_root.begin(), expected_root.end(),
                  trace_root.begin()))
    throw std::runtime_error("native PCS trace commitment mismatch");
  // Compact proof assembly happens only after this joined completion. No
  // downloaded value is used to launch or steer any prover kernel.
  std::ofstream out(output_path, std::ios::binary);
  write_words(out,
              {0x5256504f, 1, 0, sc, gc, layers, log, queries, degree, step});
  write_words(out, {verdict});
  write_words(out, final);
  write_words(out, {trace_root.begin(), trace_root.end()});
  write_words(out, o.read(values));
  write_words(out, o.read(nonce));
  write_words(out, o.read(terminal));
  write_words(out, o.read(raw));
  for (const auto &s : storage) {
    write_words(out, o.read({s.tree.words + s.tree_words - 8, 8, 1, 0}));
    write_words(out, o.read(s.values));
    write_words(out, o.read(s.paths));
  }
  write_words(out, o.read(trace_values));
  write_words(out, o.read(trace_paths));
  float ms = 0;
  CHECK(cudaEventElapsedTime(&ms, begin, end));
  std::printf("PCS columns=%u groups=%u log=%u q=%u resident_ms=%.6f "
              "device_bytes=%llu hot_d2h=0 hot_h2d=0\n",
              sc, gc, log, queries, ms,
              static_cast<unsigned long long>(o.allocated_bytes));
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 3)
      throw std::runtime_error("expected PCS fixture and readback paths");
    exercise(argv[1], argv[2]);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "FAIL %s\n", e.what());
    return 1;
  }
}
