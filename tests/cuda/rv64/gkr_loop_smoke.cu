// Full native GKR circuit proof and artifact parity. All expected values are
// used only after the complete GPU child has finished, never as GPU inputs.
#include "context_owner.cuh"
#include "fixture_reader.h"
#include "fixture_words.cuh"
#include "rv64/batch.h"
#include "rv64/binding.h"
#include "rv64/closure.h"
#include "rv64/gkr_loop.h"
#include "rv64/round.cuh"
#include <algorithm>
#include <cstdlib>
using namespace stwo::cuda::rv64;
using rv64_fixture::equal;
using rv64_fixture::Fixture;
enum class Fusion { separate, fold_sum, tail };
static uint64_t fused_calls=0,fused_kernel_launches=0,tail_calls=0;
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
__global__ void add_word(uint32_t *out) { *out = q::add(*out, 1u); }
static void exercise(const std::string &directory, uint32_t id, Fusion fusion,
                     uint32_t attack = 0, uint32_t binding_attack = 0) {
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
  FixtureWords closure_fixture(directory + "/closure-" + std::to_string(id) +
                          ".bin");
  const auto expected_closure = closure_fixture.take(1);
  const auto closure_status = upload({0});
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
  struct BindingCase {
    StwoRv64BindingMetadata job{};
    StwoRv64Plane reservoir, row, carry, seed, status, witness, scratch, claim;
    std::vector<uint32_t> expected, expected_witness;
    uint64_t scratch_words;
  };
  std::vector<BindingCase> bindings;
  if (!attack) {
    Fixture bf(directory + "/binding-" + std::to_string(id) + ".bin");
    const auto bh = bf.take(8);
    if (bh[0] != 0x5256424d || bh[1] != 2 || bh[2] != id ||
        bh[3] != 2 * count || bh[4] != layers)
      throw std::runtime_error("binding fixture header");
    for (uint32_t i = 0; i < bh[3]; ++i) {
      const auto m = bf.take(4);
      if (m[0] >= count || !m[1] || m[1] > 22 || m[2] > 8 ||
          m[1] + m[2] != variables[m[0]] || m[3])
        throw std::runtime_error("binding fixture geometry");
      BindingCase b;
      b.reservoir = o.plane(260 * 8, 1);
      b.row = o.plane(m[1] * 8, 1);
      b.carry = o.plane(m[1] * 16, 1);
      b.seed = o.plane(9, 1);
      b.status = upload({0});
      b.job = {state.words,
               b.reservoir.words,
               b.row.words,
               b.carry.words,
               b.seed.words,
               b.status.words,
               0x1632aabbccddull,
               m[0],
               m[1],
               m[2],
               count,
               layers,
               0};
      b.expected = bf.take(260 * 8 + 24 * m[1] + 9);
      const uint32_t rows = 1u << m[1];
      b.witness = o.plane(rows, 16);
      b.scratch_words = 0;
      for (uint32_t n = rows; n > 1;) {
        n = (n + 127) / 128;
        b.scratch_words += uint64_t(n) * 8;
      }
      b.scratch = o.plane(b.scratch_words, 1);
      b.claim = o.plane(8, 1);
      b.expected_witness = bf.take(16 * rows);
      bindings.push_back(std::move(b));
    }
    if (bf.cursor != bf.data.size())
      throw std::runtime_error("binding trailing data");
  }
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
  CHECK(stwo_rv64_local_close_on(o.ctx, 1, root_words.words, count,
                                 closure_status.words));
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
        // tree[0] is immutable raw input here (unlike Zig Plan.tree). Only
        // already proved smaller levels may become destructive fold banks.
        auto &w = workers[i];
        const uint32_t bank_levels[2] = {remaining, std::min(remaining + 1, w.variables)};
        for (uint32_t bank = 0; bank < 2; ++bank) {
          w.banks_n[bank] = w.tree[bank_levels[bank]].n;
          w.banks_d[bank] = w.tree[bank_levels[bank]].d;
        }
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
    bool tail_packed_masks = false;
    std::vector<bool> prefetched(l.active,false);
    for (uint32_t round = 0; round < l.depth; ++round) {
      const auto left = l.depth - round;
      if (fusion == Fusion::tail && left <= 4) {
        std::vector<StwoRv64BatchTailOracle> jobs;
        for (uint32_t j = 0; j < l.active; ++j) {
          const auto c = current[j]; auto &w = workers[ids[j]];
          const bool folds_more = descriptors[j].variables != 0;
          const uint32_t bank = folds[j] % 2;
          if (c.n.stride != c.d.stride || c.n.stride > UINT32_MAX)
            throw std::runtime_error("tail input stride");
          jobs.push_back({c.n.words,c.d.words,
              folds_more ? w.banks_n[bank].words : nullptr,
              folds_more ? w.banks_d[bank].words : nullptr,
              l.masks.words + 32*j, uint32_t(c.n.stride),
              folds_more ? uint32_t(w.banks_n[bank].stride) : 0u,
              descriptors[j].variables,c.n.coordinates});
        }
        // A failed preflight must leave the shared transcript untouched.
        if (!stwo_rv64_batch_tail_on(o.ctx,1,batch.words,jobs.data(),l.active,
                                     l.depth,round,point,eq,lambda,batch.words))
          throw std::runtime_error("tail accepted record/state alias");
        auto bad = jobs;
        bad[0].variables = l.depth + 1;
        if (!stwo_rv64_batch_tail_on(o.ctx,1,batch.words,bad.data(),l.active,
                                     l.depth,round,point,eq,lambda,
                                     l.records.words+round*round_record_words))
          throw std::runtime_error("tail accepted invalid oracle height");
        CHECK(stwo_rv64_batch_tail_on(o.ctx,1,batch.words,jobs.data(),l.active,
                                      l.depth,round,point,eq,lambda,
                                      l.records.words+round*round_record_words));
        ++tail_calls;
        tail_packed_masks = true;
        break;
      }
      for (uint32_t j = 0; j < l.active; ++j)
        if (descriptors[j].variables >= left && !prefetched[j]) {
          auto &w = workers[ids[j]];
          const auto c = current[j];
          CHECK(stwo_rv64_gkr_sum_on(o.ctx, 1, c.n, c.d, c.count, eq, lambda,
                                     w.a, w.b, w.raw));
        }
      auto *record = l.records.words + round * round_record_words;
      CHECK(stwo_rv64_batch_round_on(o.ctx, 1, batch.words, descriptors.data(),
                                     l.active, l.depth, round, point, record));
      std::fill(prefetched.begin(),prefetched.end(),false);
      const bool fused=fusion == Fusion::fold_sum && left>1;
      std::vector<StwoRv64BatchFoldSumJob> jobs;
      std::vector<uint32_t> ready;
      for (uint32_t j = 0; j < l.active; ++j)
        if (descriptors[j].variables >= left) {
          auto &w = workers[ids[j]];
          const uint32_t bank = folds[j]++ % 2;
          auto &c = current[j];
          if(fused) {
            jobs.push_back({c.n,c.d,w.banks_n[bank],w.banks_d[bank],w.a,w.b,w.raw});
            ready.push_back(j);
          } else CHECK(stwo_rv64_gkr_fold_on(o.ctx, 1, c.n, c.d, c.count, record + 32,
                                             w.banks_n[bank], w.banks_d[bank]));
          c = {w.banks_n[bank], w.banks_d[bank], c.count / 2};
        }
      if(fused) {
        auto bad=jobs;bad[0].out_d=bad[0].d;uint32_t launches=123;
        if(!stwo_rv64_batch_fold_sum_on(o.ctx,1,bad.data(),bad.size(),2u<<left,record+32,eq,lambda,&launches)||launches)
          throw std::runtime_error("fold-sum accepted input/output alias or enqueued before preflight");
        CHECK(stwo_rv64_batch_fold_sum_on(o.ctx,1,jobs.data(),jobs.size(),2u<<left,record+32,eq,lambda,&launches));
        if(!launches)throw std::runtime_error("fold-sum route did not launch");
        ++fused_calls;fused_kernel_launches+=launches;
        for(auto j:ready)prefetched[j]=true;
      }
    }
    if (!tail_packed_masks) for (uint32_t j = 0; j < l.active; ++j)
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
  if (binding_attack == 1)
    corrupt_word<<<1, 1, 0, stream>>>(state.words + 19, 1);
  if (binding_attack == 2 || binding_attack == 7)
    for (uint32_t c = 0; c < 8; ++c)
      corrupt_word<<<1, 1, 0, stream>>>(state.words + STWO_RV64_GKR_POINT_WORD +
                                            c,
                                        binding_attack == 7 && c == 0 ? 1 : 0);
  if (binding_attack == 3)
    corrupt_word<<<1, 1, 0, stream>>>(state.words + STWO_RV64_GKR_POINT_WORD,
                                      2147483647u);
  if (binding_attack == 4)
    corrupt_word<<<1, 1, 0, stream>>>(state.words + STWO_RV64_GKR_CLAIMS_WORD,
                                      2147483647u);
  for (auto &b : bindings) {
    if (binding_attack == 5)
      b.job.chain ^= 1;
    if (binding_attack == 6)
      corrupt_word<<<1, 1, 0, stream>>>(state.words + 20 + b.job.instance,
                                        layers + 1);
    auto bad = b.job;
    bad.row_log = 0;
    if (!stwo_rv64_gkr_binding_metadata_on(o.ctx, 1, &bad))
      throw std::runtime_error("empty binding geometry accepted");
    bad = b.job;
    bad.row_point = state.words;
    if (!stwo_rv64_gkr_binding_metadata_on(o.ctx, 1, &bad))
      throw std::runtime_error("binding-state alias accepted");
    CHECK(stwo_rv64_gkr_binding_metadata_on(o.ctx, 1, &b.job));
    const uint32_t rows = 1u << b.job.row_log;
    StwoRv64Plane eq_column{b.witness.words, rows, 8, 0};
    StwoRv64Plane prefix_column{b.witness.words + 8 * rows, rows, 8, 0};
    CHECK(stwo_rv64_binding_eq_on(o.ctx, 1, b.row.words, b.job.row_log,
                                  eq_column, b.status.words));
    if (binding_attack == 8)
      add_word<<<1, 1, 0, stream>>>(b.reservoir.words + 8 * 257);
    if (binding_attack == 9)
      add_word<<<1, 1, 0, stream>>>(workers[b.job.instance].tree[0].n.words);
    if (binding_attack == 10)
      add_word<<<1, 1, 0, stream>>>(workers[b.job.instance].tree[0].d.words);
    StwoRv64BindingProjection projection{workers[b.job.instance].tree[0].n,
                                         workers[b.job.instance].tree[0].d,
                                         eq_column,
                                         prefix_column,
                                         b.reservoir.words,
                                         b.status.words,
                                         b.job.row_log,
                                         b.job.lane_log,
                                         {0, 0}};
    CHECK(stwo_rv64_binding_project_on(o.ctx, 1, &projection));
    if (binding_attack == 11)
      corrupt_word<<<1, 1, 0, stream>>>(prefix_column.words, 2147483647u);
    StwoRv64PrefixScan scan{prefix_column,
                            b.scratch.words,
                            b.scratch_words,
                            b.claim.words,
                            b.status.words,
                            b.job.row_log,
                            0,
                            {0, 0}};
    CHECK(stwo_rv64_prefix_scan_on(o.ctx, 1, &scan));
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
  if (binding_attack) {
    if (o.read(bindings[0].status)[0] == 0 ||
        (binding_attack <= 7 && o.read(bindings[0].seed)[8] <= (1u << 20)))
      throw std::runtime_error("binding mutation " +
                               std::to_string(binding_attack) +
                               " accepted or valid continuation exposed");
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    o.close();
    return;
  }
  for (const auto &b : bindings) {
    if (o.read(b.status)[0])
      throw std::runtime_error("valid binding metadata rejected");
    auto actual = o.read(b.reservoir);
    for (auto region : {b.row, b.carry, b.seed}) {
      const auto values = o.read(region);
      actual.insert(actual.end(), values.begin(), values.end());
    }
    equal(actual, b.expected, "GKR-derived binding metadata", id);
    equal(o.read(b.witness), b.expected_witness,
          "GKR-derived Eq/prefix witness", id);
    equal(o.read(b.claim), std::vector<uint32_t>(8, 0), "GKR binding debt", id);
  }
  if (final[10] || final[9] != 2 * layers || final[16] != layers ||
      final[17] != count || final[18] != layers || final[19] != 2)
    throw std::runtime_error("full GKR terminal status");
  equal(o.read(root_words), expected_roots, "GKR roots", id);
  equal(o.read(closure_status), expected_closure, "GKR rational root closure",
        id);
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
    for (const auto fusion : {Fusion::separate, Fusion::fold_sum, Fusion::tail}) {
      fused_calls = fused_kernel_launches = tail_calls = 0;
      for (uint32_t id = 0; id < 9; ++id)
        exercise(argv[1], id, fusion);
      for (uint32_t attack = 1; attack <= 9; ++attack)
        exercise(argv[1], 3, fusion, attack);
      for (uint32_t attack = 1; attack <= 11; ++attack)
        exercise(argv[1], 5, fusion, 0, attack);
      if (fusion == Fusion::fold_sum && (!fused_calls || !fused_kernel_launches))
        throw std::runtime_error("fold-sum route not exercised");
      if (fusion == Fusion::tail && !tail_calls)
        throw std::runtime_error("small-tail route not exercised");
      if ((fusion != Fusion::fold_sum && (fused_calls || fused_kernel_launches)) ||
          (fusion != Fusion::tail && tail_calls))
        throw std::runtime_error("unexpected GKR fusion route");
      const char *variant = fusion == Fusion::separate ? "separate" :
                            fusion == Fusion::fold_sum ? "fold_sum" : "small_tail";
      std::printf("GKR_VARIANT variant=%s fold_sum_calls=%llu fold_sum_launches=%llu tail_calls=%llu\n", variant,
          static_cast<unsigned long long>(fused_calls),
          static_cast<unsigned long long>(fused_kernel_launches),
          static_cast<unsigned long long>(tail_calls));
      std::printf(
          "{\"schema\":\"rv64-om31-full-gkr-binding-v3\",\"variant\":\"%s\",\"cases\":9,\"poison_"
          "cases\":9,"
          "\"native_proof_and_"
          "artifact_parity\":true,\"hot_h2d_bytes\":0,\"hot_d2h_bytes\":0,"
          "\"binding_metadata_cases\":178,\"binding_witness_cases\":178,"
          "\"binding_poison_cases\":11,\"physical_"
          "binding_verified\":false,\"full_block_verified\":false}\n", variant);
    }
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
