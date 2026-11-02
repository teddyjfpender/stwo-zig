// Full native GKR circuit proof and artifact parity. All expected values are
// used only after the complete GPU child has finished, never as GPU inputs.
#include "context_owner.cuh"
#include "fixture_reader.h"
#include "rv64/batch.h"
#include "rv64/gkr_loop.h"
#include "rv64/round.cuh"
#include <algorithm>
using namespace stwo::cuda::rv64;
using rv64_fixture::equal;
using rv64_fixture::Fixture;
struct LayerFraction {
  StwoRv64Plane n, d;
  uint32_t count;
};
struct Worker {
  uint32_t variables;
  std::vector<LayerFraction> tree;
  StwoRv64Plane banks_n[2]{}, banks_d[2]{}, raw{}, a{}, b{};
};
struct Layer {
  uint32_t depth, active;
  StwoRv64Plane records{}, masks{}, begin_snapshot{}, close_snapshot{};
  std::vector<uint32_t> expected_records, expected_masks, expected_begin,
      expected_close;
};
__global__ void corrupt_word(uint32_t *out, uint32_t value) { *out = value; }
static void exercise(const std::string &directory, uint32_t id,
                     uint32_t attack = 0) {
  Fixture f(directory + "/case-" + std::to_string(id) + ".bin");
  const auto h = f.take(8);
  const uint32_t count = h[2], layers = h[3];
  if (h[0] != 0x5256474b || h[1] != 1 || !count || count > 64 || !layers ||
      layers > 20 || h[4] != id)
    throw std::runtime_error("bad full GKR fixture");
  Owner o(0);
  auto upload = [&](const std::vector<uint32_t> &v) {
    const auto p = o.plane(std::max(size_t(1), v.size()), 1);
    if (!v.empty())
      o.upload(p, v);
    return p;
  };
  const auto seed = upload(f.take(9));
  std::vector<Worker> workers(count);
  std::vector<uint32_t> variables(count);
  std::vector<StwoRv64Root> roots(count);
  for (uint32_t i = 0; i < count; ++i) {
    auto &w = workers[i];
    const auto meta = f.take(2);
    variables[i] = w.variables = meta[0];
    if (!w.variables || w.variables > layers || meta[1] > 1)
      throw std::runtime_error("input height");
    const uint32_t n = 1u << w.variables;
    LayerFraction input{o.plane(n, meta[1] ? 1 : 8), o.plane(n, 8), n};
    o.upload(input.n, f.take(size_t(n) * input.n.coordinates));
    o.upload(input.d, f.take(size_t(n) * 8));
    w.tree.push_back(input);
    for (uint32_t level = 1; level <= w.variables; ++level)
      w.tree.push_back(
          {o.plane(n >> level, 8), o.plane(n >> level, 8), n >> level});
    roots[i] = {w.tree.back().n, w.tree.back().d};
    for (uint32_t bank = 0; bank < 2; ++bank) {
      const uint32_t capacity = std::max(1u, n >> (bank + 1));
      w.banks_n[bank] = o.plane(capacity, 8);
      w.banks_d[bank] = o.plane(capacity, 8);
    }
    w.raw = o.plane(2, 8);
    const uint32_t groups = std::max(1u, (n / 4 + 127) / 128);
    w.a = o.plane(2 * groups, 8);
    w.b = o.plane(2 * groups, 8);
  }
  const auto expected_roots = f.take(16 * count);
  std::vector<Layer> plans;
  for (uint32_t depth = 0; depth < layers; ++depth) {
    const auto meta = f.take(2);
    Layer l{};
    l.depth = depth;
    l.active = meta[1];
    uint32_t expected_active = 0;
    for (auto v : variables)
      expected_active += v >= layers - depth;
    if (meta[0] != depth || l.active != expected_active)
      throw std::runtime_error("bad active roster");
    l.expected_begin = f.take(25 + 8 * l.active);
    l.expected_records = f.take(depth * round_record_words);
    l.expected_masks = f.take(32 * l.active);
    l.expected_close = f.take(9 + 8 * (depth + 1) + 16 * l.active);
    l.records = o.plane(std::max(1u, depth * round_record_words), 1);
    l.masks = o.plane(32 * l.active, 1);
    l.begin_snapshot = o.plane(l.expected_begin.size(), 1);
    l.close_snapshot = o.plane(l.expected_close.size(), 1);
    plans.push_back(std::move(l));
  }
  const auto expected_point = f.take(8 * layers),
             expected_claims = f.take(16 * count);
  if (f.cursor != f.data.size())
    throw std::runtime_error("trailing full GKR fixture");
  const auto state = o.plane(STWO_RV64_GKR_STATE_WORDS, 1),
             batch = o.plane(STWO_RV64_BATCH_STATE_WORDS, 1),
             root_words = o.plane(16 * count, 1),
             projected = o.plane(8 * count, 1),
             eq = o.plane(layers > 1 ? 1u << (layers - 2) : 1, 8);
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  void *raw = nullptr;
  CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
  const auto stream = reinterpret_cast<cudaStream_t>(raw);
  auto capture = [&](uint32_t *destination, const uint32_t *source,
                     size_t words) {
    if (words)
      CHECK(cudaMemcpyAsync(destination, source, words * 4,
                            cudaMemcpyDeviceToDevice, stream));
  };
  for (auto &w : workers)
    for (uint32_t level = 1; level <= w.variables; ++level) {
      const auto &before = w.tree[level - 1], &after = w.tree[level];
      CHECK(stwo_rv64_gkr_layer_on(o.ctx, 1, before.n, before.d, before.count,
                                   1, after.n, after.d));
    }
  CHECK(stwo_rv64_gkr_pack_roots_on(o.ctx, 1, roots.data(), count,
                                    root_words.words));
  if (attack == 6)
    corrupt_word<<<1, 1, 0, stream>>>(seed.words + 8, UINT32_MAX);
  CHECK(stwo_rv64_gkr_init_on(o.ctx, 1, state.words, seed.words,
                              variables.data(), count, layers,
                              0x1632aabbccddull));
  if (attack == 7)
    corrupt_word<<<1, 1, 0, stream>>>(root_words.words, 2147483647);
  if (attack == 8)
    corrupt_word<<<1, 1, 0, stream>>>(state.words + 20, layers + 1);
  for (auto &l : plans) {
    const uint32_t remaining = layers - l.depth;
    std::vector<uint32_t> ids;
    std::vector<LayerFraction> current;
    std::vector<StwoRv64BatchOracle> descriptors;
    std::vector<uint32_t> folds;
    for (uint32_t i = 0; i < count; ++i)
      if (variables[i] >= remaining) {
        ids.push_back(i);
        current.push_back(workers[i].tree[remaining - 1]);
        folds.push_back(0);
        const auto v = variables[i] - remaining;
        descriptors.push_back(v ? StwoRv64BatchOracle{workers[i].raw.words,
                                                      workers[i].raw.stride, v,
                                                      0}
                                : StwoRv64BatchOracle{nullptr, 0, 0, 0});
      }
    if (attack == 1 && l.depth == 0)
      CHECK(stwo_rv64_gkr_begin_on(o.ctx, 1, state.words, 1, count, l.active,
                                   root_words.words, projected.words));
    CHECK(stwo_rv64_gkr_begin_on(o.ctx, 1, state.words, l.depth, count,
                                 l.active, root_words.words, projected.words));
    capture(l.begin_snapshot.words, state.words + STWO_RV64_GKR_ALPHA_WORD, 25);
    capture(l.begin_snapshot.words + 25, projected.words, 8 * l.active);
    CHECK(stwo_rv64_batch_init_on(
        o.ctx, 1, batch.words, state.words + STWO_RV64_GKR_SEED_WORD,
        projected.words, state.words + STWO_RV64_GKR_ALPHA_WORD,
        descriptors.data(), l.active, l.depth));
    const auto *point = state.words + STWO_RV64_GKR_POINT_WORD;
    const auto *lambda = state.words + STWO_RV64_GKR_LAMBDA_WORD;
    if (l.depth)
      CHECK(stwo_rv64_gkr_eq_on(o.ctx, 1, point, l.depth, eq));
    for (uint32_t round = 0; round < l.depth; ++round) {
      const auto left = l.depth - round;
      for (uint32_t j = 0; j < l.active; ++j)
        if (descriptors[j].variables >= left) {
          auto &w = workers[ids[j]];
          const auto c = current[j];
          CHECK(stwo_rv64_gkr_sum_on(o.ctx, 1, c.n, c.d, c.count, eq, lambda,
                                     w.a, w.b, w.raw));
        }
      auto *record = l.records.words + round * round_record_words;
      CHECK(stwo_rv64_batch_round_on(o.ctx, 1, batch.words, descriptors.data(),
                                     l.active, l.depth, round, point, record));
      for (uint32_t j = 0; j < l.active; ++j)
        if (descriptors[j].variables >= left) {
          auto &w = workers[ids[j]];
          const uint32_t bank = folds[j]++ % 2;
          auto &c = current[j];
          CHECK(stwo_rv64_gkr_fold_on(o.ctx, 1, c.n, c.d, c.count, record + 32,
                                      w.banks_n[bank], w.banks_d[bank]));
          c = {w.banks_n[bank], w.banks_d[bank], c.count / 2};
        }
    }
    for (uint32_t j = 0; j < l.active; ++j)
      CHECK(stwo_rv64_batch_mask_on(o.ctx, 1, current[j].n, current[j].d,
                                    l.masks.words + 32 * j));
    if (l.depth == 1) {
      // The preceding single-oracle tests qualify numerical poisoning; these
      // cases target parent/batch custody and compact proof framing.
      if (attack == 2)
        corrupt_word<<<1, 1, 0, stream>>>(batch.words + 1653, 2147483647);
      if (attack == 3)
        corrupt_word<<<1, 1, 0, stream>>>(batch.words + 1652, UINT32_MAX);
      if (attack == 4)
        corrupt_word<<<1, 1, 0, stream>>>(l.records.words + 41, UINT32_MAX);
      if (attack == 5)
        corrupt_word<<<1, 1, 0, stream>>>(l.masks.words, 2147483647);
      if (attack == 9)
        corrupt_word<<<1, 1, 0, stream>>>(l.records.words, 2147483647);
    }
    CHECK(stwo_rv64_gkr_close_on(o.ctx, 1, state.words, batch.words,
                                 l.depth ? l.records.words : nullptr,
                                 l.masks.words, l.depth, count, l.active));
    capture(l.close_snapshot.words, state.words, 9);
    capture(l.close_snapshot.words + 9, point, 8 * (l.depth + 1));
    for (uint32_t j = 0; j < l.active; ++j)
      capture(l.close_snapshot.words + 9 + 8 * (l.depth + 1) + 16 * j,
              state.words + STWO_RV64_GKR_CLAIMS_WORD + 16 * ids[j], 16);
  }
  // Only now, after the complete parent loop, may validation data leave CUDA.
  const auto final = o.read(state);
  if (attack) {
    if (final[10] == 0)
      throw std::runtime_error("parent mutation silently accepted");
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    o.close();
    return;
  }
  if (final[10] || final[9] != 2 * layers || final[16] != layers ||
      final[17] != count || final[18] != layers || final[19] != 2)
    throw std::runtime_error("full GKR terminal status");
  equal(o.read(root_words), expected_roots, "GKR roots", id);
  equal({final.begin() + STWO_RV64_GKR_POINT_WORD,
         final.begin() + STWO_RV64_GKR_POINT_WORD + 8 * layers},
        expected_point, "GKR final point", id);
  equal({final.begin() + STWO_RV64_GKR_CLAIMS_WORD,
         final.begin() + STWO_RV64_GKR_CLAIMS_WORD + 16 * count},
        expected_claims, "GKR input marginals", id);
  for (const auto &l : plans) {
    equal(o.read(l.begin_snapshot), l.expected_begin, "GKR begin", id);
    if (l.depth)
      equal(o.read(l.records), l.expected_records, "GKR records", id);
    equal(o.read(l.masks), l.expected_masks, "GKR masks", id);
    equal(o.read(l.close_snapshot), l.expected_close, "GKR close", id);
  }
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected full native GKR fixture directory");
    for (uint32_t id = 0; id < 8; ++id)
      exercise(argv[1], id);
    for (uint32_t attack = 1; attack <= 9; ++attack)
      exercise(argv[1], 3, attack);
    std::printf(
        "{\"schema\":\"rv64-om31-full-gkr-v1\",\"cases\":8,\"poison_cases\":9,"
        "\"native_proof_and_"
        "artifact_parity\":true,\"hot_h2d_bytes\":0,\"hot_d2h_bytes\":0,"
        "\"physical_binding_verified\":false,\"full_block_verified\":false}\n");
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
