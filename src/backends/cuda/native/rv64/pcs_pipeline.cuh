#pragma once
// One shared PCS pipeline for the CLI and the in-process persistent service.
#include "rv64/channel.h"
#include "rv64/deep.h"
#include "rv64/fri.h"
#include "rv64/pcs_native.h"
#include "rv64/sample_order.h"
#include "rv64/samples.h"
#include "rv64/trace.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cuda_runtime.h>
#include <stdexcept>
#include <vector>
extern "C" int stwo_exec_context_lane_stream(void *, uint32_t, void **);
extern "C" int stwo_exec_context_sync(void *);
extern "C" int stwo_exec_context_memcpy_d2h_async(void *, void *, const void *,
                                                  size_t);
#ifndef CHECK
inline void pcsCheck(int status, const char *operation) {
  if (status)
    throw std::runtime_error(std::string(operation) + ": " +
                             cudaGetErrorString(cudaError_t(status)));
}
#define CHECK(expr) pcsCheck((expr), #expr)
#endif
extern "C" int stwo_lde_n2b_addressed_on(uint32_t *, size_t, const void *,
                                         uint32_t, size_t, uint32_t,
                                         const uint32_t *, uint32_t, uint32_t,
                                         void *, uint32_t, uint32_t *);
extern "C" int stwo_blake2s_pow_persistent_on(const uint32_t *, uint32_t,
                                              unsigned long long, uint32_t *,
                                              unsigned long long *, uint32_t *,
                                              uint32_t *, void *);
namespace rv64_pcs_pipeline {
namespace b = stwo::cuda::blake2s;
struct Words {
  const uint32_t *pointer = nullptr;
  size_t count = 0;
  const uint32_t *data() const { return pointer; }
  size_t size() const { return count; }
  const uint32_t *begin() const { return pointer; }
  const uint32_t *end() const { return count ? pointer + count : pointer; }
  uint32_t operator[](size_t i) const {
    if (i >= count)
      throw std::runtime_error("metadata bounds");
    return pointer[i];
  }
};
struct Coefficient : Words {
  uint32_t kind = 0;
  uint64_t token = 0, generation = 0;
};
struct Input {
  std::array<Words, 17> sections{};
  std::vector<Coefficient> coefficients;
  std::array<uint32_t, 8> scope{};
  Words domain{}; // legacy file path only; native mode generates/caches on GPU
};
struct Result {
  std::vector<uint32_t> words;
  uint64_t device_ns, requested_bytes;
};
inline void sizeIs(Words span, size_t size) {
  if (span.size() != size || (size && !span.data()))
    throw std::runtime_error("native PCS span shape");
}
struct FriStorage {
  StwoRv64Plane column, tree, alpha, values, paths;
  uint32_t count, steps, leaf, shift;
  uint64_t tree_words, value_words, path_words;
};
template <class OwnerT> Result run(OwnerT &o, const Input &input) {
  const auto h = input.sections[0];
  sizeIs(h, 24);
  if (h[0] != 0x52564d53 || h[1] != 2 || h[2] || h[21] > 1 || h[22] > 32 ||
      h[23])
    throw std::runtime_error("masked PCS header");
  const uint32_t degree = h[3], log = h[4], queries = h[6], sc = h[8],
                 tc = h[9], gc = h[10], sgc = h[11], nt = h[12],
                 sample_count = h[13], layers = h[14];
  if (log > 28 || !nt || nt > 4 || !sc || sc > 65536 || !tc || tc > 65536 ||
      !gc || gc > 1024 || !sgc || sgc > 96 || !sample_count ||
      sample_count > 65536 || !queries || queries > 1024 || layers > 28 ||
      input.coefficients.size() != sc)
    throw std::runtime_error("masked PCS shape");
  const uint32_t rows = 1u << log;
  const auto initial_seed = input.sections[1],
             imported_point = input.sections[2], sources = input.sections[3],
             terms = input.sections[4], groups = input.sections[5],
             source_groups = input.sections[6], tree_info = input.sections[7],
             recipes = input.sections[8], deep_tw = input.sections[9],
             sample_map = input.sections[10],
             sample_counts = input.sections[11], twiddles = input.sections[12],
             descriptions = input.sections[13],
             fri_twiddles = input.sections[14],
             expected_roots = input.sections[15];
  const size_t sizes[] = {24,
                          9,
                          h[21] ? 16u : 0u,
                          size_t(sc) * 4,
                          size_t(tc) * 4,
                          size_t(gc) * 8,
                          size_t(sgc) * 8,
                          size_t(nt) * 6,
                          size_t(gc) * 4,
                          size_t(gc) * 2,
                          sample_count,
                          sc,
                          h[19],
                          size_t(layers) * 8,
                          h[20],
                          size_t(nt) * 8};
  for (size_t i = 0; i < 16; ++i)
    sizeIs(input.sections[i], sizes[i]);
  if (!input.domain.size())
    sizeIs(input.sections[16], 4);
  auto upload = [&](Words v) {
    auto p = o.plane(v.size(), 1);
    o.uploadBorrowed(p, v.data(), v.size());
    return p;
  };
  auto uploadOwned = [&](std::vector<uint32_t> values) {
    auto p = o.plane(values.size(), 1);
    o.upload(p, values);
    return p;
  };
  const uint64_t source_eval_base = h[15],
                 combined_coeff_base = source_eval_base + h[16],
                 combined_eval_base = combined_coeff_base + h[17],
                 twiddle_base = combined_eval_base + h[18],
                 descriptor_base = twiddle_base + h[19];
  const uint64_t arena_words = descriptor_base + uint64_t(sc + 8 * gc) * 6;
  const auto arena = o.plane(arena_words, 1);
  for (uint32_t c = 0; c < sc; ++c) {
    const uint64_t offset =
        uint64_t(sources[4 * c]) | (uint64_t(sources[4 * c + 1]) << 32);
    const auto coefficients = input.coefficients[c];
    if (coefficients.size() != (uint64_t(1) << sources[4 * c + 3]) ||
        offset > h[15] || coefficients.size() > h[15] - offset)
      throw std::runtime_error("coefficient span geometry");
    o.uploadCoefficient({arena.words + offset, coefficients.size(), 1, 0},
                        coefficients, input.scope.data());
  }
  o.uploadBorrowed({arena.words + twiddle_base, h[19], 1, 0}, twiddles.data(),
                   twiddles.size());
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
  uint32_t max_group_terms = 0;
  for (uint32_t g = 0; g < sgc; ++g) {
    const auto *s = source_groups.data() + g * 8;
    const uint64_t eval_offset = uint64_t(s[0]) | (uint64_t(s[1]) << 32);
    const uint32_t m = 1u << s[3];
    if (s[4] + s[5] > sc || s[3] != s[2] + h[5])
      throw std::runtime_error("source group geometry");
    std::vector<uint32_t> packets;
    for (uint32_t j = 0; j < s[5]; ++j) {
      const auto *c = sources.data() + (s[4] + j) * 4;
      descriptor(uint64_t(c[0]) | (uint64_t(c[1]) << 32),
                 source_eval_base + eval_offset + uint64_t(j) * m, s[2],
                 packets);
    }
    StwoRv64Plane p{arena.words + descriptor_offset, packets.size(), 1, 0};
    o.upload(p, packets);
    source_descriptors.push_back(p);
    descriptor_offset += packets.size();
    trace_segments.push_back({arena.words + source_eval_base + eval_offset, m,
                              uint64_t(m) * s[5], m, 0});
  }
  for (uint32_t g = 0; g < gc; ++g) {
    const auto *d = groups.data() + g * 8;
    const uint32_t n = 1u << d[2], m = 1u << d[3], count = d[1] - d[0];
    if (!count || d[1] > tc)
      throw std::runtime_error("DEEP group geometry");
    std::vector<uint32_t> packets;
    for (uint32_t c = 0; c < 8; ++c)
      descriptor(
          combined_coeff_base + (uint64_t(d[4]) | (uint64_t(d[5]) << 32)) +
              uint64_t(c) * n,
          combined_eval_base + (uint64_t(d[6]) | (uint64_t(d[7]) << 32)) +
              uint64_t(c) * m,
          d[2], packets);
    StwoRv64Plane p{arena.words + descriptor_offset, packets.size(), 1, 0};
    o.upload(p, packets);
    combined_descriptors.push_back(p);
    descriptor_offset += packets.size();
    sample_scratch_words =
        std::max(sample_scratch_words, uint64_t((n + 1023) / 1024) * count * 8);
    max_group_terms = std::max(max_group_terms, count);
  }
  if (descriptor_offset != arena_words)
    throw std::runtime_error("PCS arena plan mismatch");
  const auto permutation = upload(sample_map),
             ordered_values = o.plane(sample_count * 8, 1);
  const auto seed = upload(initial_seed), src = upload(sources),
             term = upload(terms), grp = upload(groups),
             recipe = upload(recipes),
             xy = o.domain(log, input.domain, input.sections[16]),
             fri_tw = upload(fri_twiddles);
  const auto state = o.plane(16, 1), boundary = o.plane(16, 1),
             parameter = h[21] ? upload(imported_point) : o.plane(8, 1),
             point_arena = o.plane((gc + 1) * 16, 1),
             factors = o.plane(gc * 28 * 8, 1),
             point_ready = o.plane(gc + 1, 1),
             sample_scratch_a = o.plane(sample_scratch_words, 1),
             sample_scratch_b = o.plane(sample_scratch_words, 1),
             sample_valid = o.plane(max_group_terms, 1),
             values = o.plane(tc * 8, 1), alpha = o.plane(8, 1),
             weights = o.plane(tc * 8, 1), linear = o.plane(gc * 16, 1),
             deep_valid = o.plane(2, 1), deep = o.plane(rows, 8),
             terminal = o.plane(8, 1), raw = o.plane(queries, 1),
             nonce = uploadOwned({0, 0}), status = uploadOwned({0}),
             pow_prefix = o.plane(8, 1), pow_best = o.plane(2, 1),
             pow_blocks = o.plane(1, 1);
  struct TraceStorage {
    StwoRv64Plane tree, values, paths;
    uint32_t first, columns, group, groups, log;
    uint64_t tree_words;
  };
  std::vector<TraceStorage> traces;
  for (uint32_t t = 0; t < nt; ++t) {
    const auto *d = tree_info.data() + t * 6;
    if (d[5] || d[0] + d[1] > sc || d[2] + d[3] > sgc || d[4] > log)
      throw std::runtime_error("tree geometry");
    TraceStorage v{};
    v.first = d[0];
    v.columns = d[1];
    v.group = d[2];
    v.groups = d[3];
    v.log = d[4];
    v.tree_words = ((uint64_t(2) << v.log) - 1) * 8;
    v.tree = o.plane(v.tree_words, 1);
    v.values = o.plane(uint64_t(v.columns) * queries, 1);
    v.paths = o.plane(uint64_t(queries) * v.log * 8, 1);
    traces.push_back(v);
  }
  const auto last = o.plane(1u << h[5], 8);
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
  auto extend_source = [&](uint32_t g) {
    const auto *d = source_groups.data() + g * 8;
    uint32_t launches = 0;
    CHECK(stwo_lde_n2b_addressed_on(
        arena.words, arena_words, source_descriptors[g].words, d[5],
        source_eval_base + (uint64_t(d[0]) | (uint64_t(d[1]) << 32)), d[3],
        arena.words + twiddle_base + d[6], d[7], 1u << (d[3] - 1), stream_raw,
        1, &launches));
  };
  auto extend_combined = [&](uint32_t g) {
    const auto *d = groups.data() + g * 8;
    uint32_t launches = 0;
    CHECK(stwo_lde_n2b_addressed_on(
        arena.words, arena_words, combined_descriptors[g].words, 8,
        combined_eval_base + (uint64_t(d[6]) | (uint64_t(d[7]) << 32)), d[3],
        arena.words + twiddle_base + deep_tw[g * 2], deep_tw[g * 2 + 1],
        1u << (d[3] - 1), stream_raw, 1, &launches));
  };
  for (uint32_t g = 0; g < sgc; ++g)
    extend_source(g);
  for (auto &t : traces)
    CHECK(stwo_rv64_trace_tree_on(o.ctx, 1, trace_segments.data() + t.group,
                                  t.groups, t.log, t.tree.words, t.tree_words));
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
  if (!h[21]) {
    for (const auto &t : traces)
      mix(t.tree.words + t.tree_words - 8, 8, 0);
    draw(parameter.words);
  }
  StwoRv64SamplePoints point_job{
      parameter.words,
      reinterpret_cast<const StwoRv64PointRecipe *>(recipe.words),
      point_arena.words,
      factors.words,
      point_ready.words,
      status.words,
      gc,
      0};
  CHECK(h[21] ? stwo_rv64_sample_points_from_point_on(o.ctx, 1, &point_job)
              : stwo_rv64_sample_points_on(o.ctx, 1, &point_job));
  for (uint32_t g = 0; g < gc; ++g) {
    const auto *d = groups.data() + g * 8;
    StwoRv64SampleEvaluation sample{};
    sample.trees[0] = arena.words;
    sample.tree_words[0] = h[15];
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
    sample.value_words = tc * 8;
    sample.source_count = sc;
    sample.term_capacity = tc;
    sample.group_count = gc;
    sample.first = d[0];
    sample.count = d[1] - d[0];
    sample.coefficient_log = d[2];
    CHECK(stwo_rv64_sample_evaluate_on(o.ctx, 1, &sample));
  }
  CHECK(stwo_rv64_sample_order_on(o.ctx, 1, values.words, tc, permutation.words,
                                  sample_count, ordered_values.words,
                                  status.words));
  mix(ordered_values.words, sample_count * 8, 1);
  draw(alpha.words);
  StwoRv64DeepPrepare prepare{};
  prepare.trees[0] = arena.words;
  prepare.tree_words[0] = h[15];
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
  prepare.coefficient_words = h[17];
  prepare.source_count = sc;
  prepare.term_count = tc;
  prepare.group_count = gc;
  CHECK(stwo_rv64_deep_prepare_on(o.ctx, 1, &prepare));
  for (uint32_t g = 0; g < gc; ++g)
    extend_combined(g);
  StwoRv64DeepCombine combine{};
  combine.groups = reinterpret_cast<const StwoRv64DeepGroup *>(grp.words);
  combine.points = point_arena.words + 16;
  combine.linear = linear.words;
  combine.evaluations = arena.words + combined_eval_base;
  combine.domain_xy = xy.words;
  combine.valid = deep_valid.words;
  combine.output = deep;
  combine.status = status.words;
  combine.evaluation_words = h[18];
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
  if (h[22]) {
    CHECK(stwo_blake2s_pow_persistent_on(
        state.words, h[22], 1ull << 40, pow_prefix.words,
        reinterpret_cast<unsigned long long *>(pow_best.words),
        pow_blocks.words, nonce.words, stream_raw));
  }
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
  for (auto &t : traces) {
    StwoRv64TraceOpen open{t.tree.words,
                           raw.words,
                           t.values.words,
                           t.paths.words,
                           status.words,
                           t.tree_words,
                           uint64_t(t.columns) * queries,
                           uint64_t(queries) * t.log * 8,
                           t.log,
                           log,
                           queries,
                           0};
    CHECK(stwo_rv64_trace_open_on(o.ctx, 1, trace_segments.data() + t.group,
                                  t.groups, &open));
  }
  CHECK(cudaEventRecord(end, stream));
  CHECK(cudaEventSynchronize(end));
  // All compute is joined above. Queue every compact D2H slice into one
  // stable result allocation and join once; no value feeds a prover kernel.
  std::vector<StwoRv64Plane> readbacks{status, state};
  for (const auto &t : traces)
    readbacks.push_back({t.tree.words + t.tree_words - 8, 8, 1, 0});
  readbacks.push_back(ordered_values);
  readbacks.push_back(nonce);
  readbacks.push_back(terminal);
  readbacks.push_back(raw);
  for (const auto &s : storage) {
    readbacks.push_back({s.tree.words + s.tree_words - 8, 8, 1, 0});
    readbacks.push_back(s.values);
    readbacks.push_back(s.paths);
  }
  for (const auto &t : traces) {
    readbacks.push_back(t.values);
    readbacks.push_back(t.paths);
  }
  size_t total = 14;
  for (const auto &p : readbacks) {
    if (p.stride > SIZE_MAX / p.coordinates ||
        p.stride * p.coordinates > SIZE_MAX - total)
      throw std::runtime_error("proof output overflow");
    total += p.stride * p.coordinates;
  }
  Result result{};
  result.words.resize(total);
  const uint32_t out_header[] = {
      0x52564d4f,   2,      0,   sc,      tc,     gc,  sgc, nt,
      sample_count, layers, log, queries, degree, step};
  std::copy(std::begin(out_header), std::end(out_header), result.words.begin());
  size_t cursor = 14;
  for (const auto &p : readbacks) {
    const size_t count = p.stride * p.coordinates;
    CHECK(stwo_exec_context_memcpy_d2h_async(
        o.ctx, result.words.data() + cursor, p.words, count * 4));
    cursor += count;
  }
  CHECK(stwo_exec_context_sync(o.ctx));
  const uint32_t verdict = result.words[14];
  const auto *final = result.words.data() + 15;
  if (verdict || final[10] || final[9] != step)
    throw std::runtime_error("resident PCS numerical failure");
  for (uint32_t t = 0; t < nt; ++t)
    if (!std::equal(result.words.begin() + 31 + t * 8,
                    result.words.begin() + 31 + (t + 1) * 8,
                    expected_roots.begin() + t * 8))
      throw std::runtime_error("native PCS tree root mismatch");
  float ms = 0;
  CHECK(cudaEventElapsedTime(&ms, begin, end));
  result.device_ns = uint64_t(ms * 1000000.0);
  result.requested_bytes = o.allocated_bytes;
  std::printf("MASKED_PCS columns=%u groups=%u log=%u q=%u resident_ms=%.6f "
              "device_bytes=%llu hot_d2h=0 hot_h2d=0\n",
              sc, gc, log, queries, ms,
              static_cast<unsigned long long>(o.allocated_bytes));
  return result;
}
} // namespace rv64_pcs_pipeline
