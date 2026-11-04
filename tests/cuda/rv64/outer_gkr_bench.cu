// Outer LogUp-GKR GPU prover bench (stream outer-gkr, profile outer_gkr_om31_strict_v1).
// Drives the EXISTING native OM31 GKR traversal kernels (gkr.cu, gkr_loop.cu, batch.cu, round.cu)
// in the same order as gkr_loop_smoke.cu / riscv_cuda/rv64/gkr.zig, on the outer class's instance
// roster, with deterministic synthetic inputs (same generator as outer_gkr/section.zig Rng), and
// writes the section in the outer-GKR wire format so the fresh Zig receiver checks it.
//
//   outer_gkr_bench OUT CLASS_ID INPUT_SEED SALT "s0,..,s8" REPS v0 v1 ... vk-1
// Exit 0 ok, 3 = a round polynomial was trimmed (re-salt), 1 = failure.
// Timing: CUDA events on the compute lane, per rep (tree build + full traversal), after one warmup.
// Inputs are generated and uploaded once, outside every timed region.
#include "context_owner.cuh"
#include "rv64/batch.h"
#include "rv64/gkr_loop.h"
#include "rv64/round.cuh"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
using namespace stwo::cuda::rv64;
static constexpr uint32_t kP = 0x7fffffffu;
struct Rng {
  uint64_t s;
  Rng(uint64_t seed, size_t instance) : s(seed ^ (0x9E3779B97F4A7C15ull * (uint64_t(instance) + 1))) {}
  uint64_t next() {
    s += 0x9E3779B97F4A7C15ull;
    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  }
};
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
  StwoRv64Plane records{}, masks{};
};
static void h2d(Owner &o, StwoRv64Plane p, const std::vector<uint32_t> &v) {
  CHECK(stwo_exec_context_memcpy_h2d_async(o.ctx, p.words, v.data(), v.size() * 4));
  CHECK(stwo_exec_context_sync(o.ctx));
}
int main(int argc, char **argv) {
  try {
    if (argc < 8) throw std::runtime_error("usage: OUT CLASS_ID INPUT_SEED SALT seed9 REPS v...");
    const std::string out_path = argv[1];
    const uint32_t class_id = std::stoul(argv[2], nullptr, 0);
    const uint64_t input_seed = std::stoull(argv[3], nullptr, 0);
    const uint32_t salt = std::stoul(argv[4], nullptr, 0);
    std::vector<uint32_t> seed_words;
    {
      std::stringstream ss(argv[5]);
      std::string item;
      while (std::getline(ss, item, ',')) seed_words.push_back(std::stoul(item, nullptr, 0));
      if (seed_words.size() != 9) throw std::runtime_error("seed must be 9 words");
    }
    const int reps = std::max(1, std::atoi(argv[6]));
    std::vector<uint32_t> variables;
    for (int i = 7; i < argc; ++i) variables.push_back(std::stoul(argv[i]));
    const uint32_t count = variables.size();
    uint32_t layers = 0;
    uint64_t fractions = 0;
    for (auto v : variables) {
      if (!v || v > 28) throw std::runtime_error("bad variables");
      layers = std::max(layers, v);
      fractions += 1ull << v;
    }
    if (!count || count > 64) throw std::runtime_error("bad instance count");
    Owner o(0);
    const auto t_gen = std::chrono::steady_clock::now();
    const auto seed = o.plane(9, 1);
    h2d(o, seed, seed_words);
    std::vector<Worker> workers(count);
    std::vector<StwoRv64Root> roots(count);
    for (uint32_t i = 0; i < count; ++i) {
      auto &w = workers[i];
      w.variables = variables[i];
      const uint32_t n = 1u << w.variables;
      LayerFraction input{o.plane(n, 1), o.plane(n, 8), n};
      std::vector<uint32_t> nv(n), dv(size_t(n) * 8);
      Rng rng(input_seed, i);
      for (uint32_t j = 0; j < n; ++j) {
        nv[j] = uint32_t(rng.next() % 7 + 1);
        for (uint32_t c = 0; c < 8; ++c) dv[size_t(c) * n + j] = uint32_t((rng.next() >> 32) % kP);
      }
      h2d(o, input.n, nv);
      h2d(o, input.d, dv);
      w.tree.push_back(input);
      for (uint32_t level = 1; level <= w.variables; ++level)
        w.tree.push_back({o.plane(n >> level, 8), o.plane(n >> level, 8), n >> level});
      roots[i] = {w.tree.back().n, w.tree.back().d};
      w.raw = o.plane(2, 8);
      const uint32_t groups = std::max(1u, (n / 4 + 127) / 128);
      w.a = o.plane(2 * groups, 8);
      w.b = o.plane(2 * groups, 8);
    }
    const double gen_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t_gen).count();
    std::vector<Layer> plans;
    for (uint32_t depth = 0; depth < layers; ++depth) {
      Layer l{};
      l.depth = depth;
      for (auto v : variables) l.active += v >= layers - depth;
      l.records = o.plane(std::max(1u, depth * round_record_words), 1);
      l.masks = o.plane(32 * l.active, 1);
      plans.push_back(l);
    }
    const auto state = o.plane(STWO_RV64_GKR_STATE_WORDS, 1), batch = o.plane(STWO_RV64_BATCH_STATE_WORDS, 1),
               root_words = o.plane(16 * count, 1), projected = o.plane(8 * count, 1),
               eq = o.plane(layers > 1 ? 1u << (layers - 2) : 1, 8);
    StwoCudaDependency ready{};
    CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
    CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
    void *raw_stream = nullptr;
    CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw_stream));
    const auto stream = reinterpret_cast<cudaStream_t>(raw_stream);
    cudaEvent_t e0 = o.event(), e1 = o.event(), e2 = o.event();
    std::vector<float> tree_ms, traversal_ms;
    uint64_t launches = 0;
    for (int rep = 0; rep <= reps; ++rep) {
      launches = 0;
      CHECK(cudaEventRecord(e0, stream));
      for (auto &w : workers)
        for (uint32_t level = 1; level <= w.variables; ++level) {
          const auto &before = w.tree[level - 1], &after = w.tree[level];
          CHECK(stwo_rv64_gkr_layer_on(o.ctx, 1, before.n, before.d, before.count, 1, after.n, after.d));
          ++launches;
        }
      CHECK(stwo_rv64_gkr_pack_roots_on(o.ctx, 1, roots.data(), count, root_words.words));
      CHECK(cudaEventRecord(e1, stream));
      CHECK(stwo_rv64_gkr_init_on(o.ctx, 1, state.words, seed.words, variables.data(), count, layers, 0x0675b9e5ull));
      launches += 2;
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
            auto &w = workers[i];
            const uint32_t bank_levels[2] = {remaining, std::min(remaining + 1, w.variables)};
            for (uint32_t bank = 0; bank < 2; ++bank) {
              w.banks_n[bank] = w.tree[bank_levels[bank]].n;
              w.banks_d[bank] = w.tree[bank_levels[bank]].d;
            }
            folds.push_back(0);
            const auto v = variables[i] - remaining;
            descriptors.push_back(v ? StwoRv64BatchOracle{w.raw.words, w.raw.stride, v, 0} : StwoRv64BatchOracle{nullptr, 0, 0, 0});
          }
        CHECK(stwo_rv64_gkr_begin_on(o.ctx, 1, state.words, l.depth, count, l.active, root_words.words, projected.words));
        CHECK(stwo_rv64_batch_init_on(o.ctx, 1, batch.words, state.words + STWO_RV64_GKR_SEED_WORD, projected.words,
                                      state.words + STWO_RV64_GKR_ALPHA_WORD, descriptors.data(), l.active, l.depth));
        launches += 2;
        const auto *point = state.words + STWO_RV64_GKR_POINT_WORD;
        const auto *lambda = state.words + STWO_RV64_GKR_LAMBDA_WORD;
        if (l.depth) {
          CHECK(stwo_rv64_gkr_eq_on(o.ctx, 1, point, l.depth, eq));
          launches += l.depth;
        }
        for (uint32_t round = 0; round < l.depth; ++round) {
          const auto left = l.depth - round;
          for (uint32_t j = 0; j < l.active; ++j)
            if (descriptors[j].variables >= left) {
              auto &w = workers[ids[j]];
              const auto c = current[j];
              CHECK(stwo_rv64_gkr_sum_on(o.ctx, 1, c.n, c.d, c.count, eq, lambda, w.a, w.b, w.raw));
              ++launches;
            }
          auto *record = l.records.words + round * round_record_words;
          CHECK(stwo_rv64_batch_round_on(o.ctx, 1, batch.words, descriptors.data(), l.active, l.depth, round, point, record));
          ++launches;
          for (uint32_t j = 0; j < l.active; ++j)
            if (descriptors[j].variables >= left) {
              auto &w = workers[ids[j]];
              const uint32_t bank = folds[j]++ % 2;
              auto &c = current[j];
              CHECK(stwo_rv64_gkr_fold_on(o.ctx, 1, c.n, c.d, c.count, record + 32, w.banks_n[bank], w.banks_d[bank]));
              ++launches;
              c = {w.banks_n[bank], w.banks_d[bank], c.count / 2};
            }
        }
        for (uint32_t j = 0; j < l.active; ++j) {
          CHECK(stwo_rv64_batch_mask_on(o.ctx, 1, current[j].n, current[j].d, l.masks.words + 32 * j));
          ++launches;
        }
        CHECK(stwo_rv64_gkr_close_on(o.ctx, 1, state.words, batch.words, l.depth ? l.records.words : nullptr, l.masks.words, l.depth, count, l.active));
        ++launches;
      }
      CHECK(cudaEventRecord(e2, stream));
      CHECK(cudaEventSynchronize(e2));
      float a = 0, b = 0;
      CHECK(cudaEventElapsedTime(&a, e0, e1));
      CHECK(cudaEventElapsedTime(&b, e1, e2));
      if (rep) {
        tree_ms.push_back(a);
        traversal_ms.push_back(b);
      }
    }
    const auto final = o.read(state);
    if (final[10] || final[9] != 2 * layers || final[16] != layers || final[17] != count || final[18] != layers || final[19] != 2)
      throw std::runtime_error("GKR traversal terminal status");
    // Encode the section: header, salt, roots, then per layer rounds (4 coefficients) and masks.
    std::vector<uint32_t> outw = {0x524b474fu, 1u, class_id, count, layers};
    outw.push_back(salt);
    for (int i = 0; i < 7; ++i) outw.push_back(0);
    const auto rw = o.read(root_words);
    outw.insert(outw.end(), rw.begin(), rw.end());
    bool trimmed = false;
    for (auto &l : plans) {
      if (l.depth) {
        const auto rec = o.read(l.records);
        for (uint32_t r = 0; r < l.depth; ++r) {
          const uint32_t *x = rec.data() + r * round_record_words;
          if (x[40] != 4) trimmed = true;
          outw.insert(outw.end(), x, x + 32);
        }
      }
      const auto m = o.read(l.masks);
      outw.insert(outw.end(), m.begin(), m.begin() + 32 * l.active);
    }
    std::ofstream f(out_path, std::ios::binary);
    f.write(reinterpret_cast<const char *>(outw.data()), outw.size() * 4);
    f.close();
    auto median = [](std::vector<float> v) {
      std::sort(v.begin(), v.end());
      return v[v.size() / 2];
    };
    size_t free_b = 0, total_b = 0;
    CHECK(cudaMemGetInfo(&free_b, &total_b));
    std::printf("{\"schema\":\"rv64-outer-gkr-gpu-bench/v1\",\"class_id\":%u,\"instances\":%u,\"layers\":%u,"
                "\"fractions\":%llu,\"reps\":%d,\"tree_ms_median\":%.3f,\"traversal_ms_median\":%.3f,"
                "\"total_ms_median\":%.3f,\"tree_ms\":[",
                class_id, count, layers, (unsigned long long)fractions, reps, median(tree_ms), median(traversal_ms),
                median(tree_ms) + median(traversal_ms));
    for (size_t i = 0; i < tree_ms.size(); ++i) std::printf("%s%.3f", i ? "," : "", tree_ms[i]);
    std::printf("],\"traversal_ms\":[");
    for (size_t i = 0; i < traversal_ms.size(); ++i) std::printf("%s%.3f", i ? "," : "", traversal_ms[i]);
    std::printf("],\"kernel_calls_per_rep\":%llu,\"device_allocated_bytes\":%llu,\"device_total_bytes\":%zu,"
                "\"device_free_bytes_after\":%zu,\"input_gen_upload_s\":%.3f,\"section_words\":%zu,\"trimmed_round\":%s}\n",
                (unsigned long long)launches, (unsigned long long)o.allocated_bytes, total_b, free_b, gen_s, outw.size(),
                trimmed ? "true" : "false");
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    o.close();
    return trimmed ? 3 : 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
