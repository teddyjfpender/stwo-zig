// Complete mixed-height sumcheck, compared directly with the native OM31
// prover. The host submits geometry only; no field challenge or claim comes
// back per round.
#include "context_owner.cuh"
#include "fixture_reader.h"
#include "rv64/batch.h"
#include "rv64/round.cuh"
#include <algorithm>
#include <fstream>
using namespace stwo::cuda::rv64;
using rv64_fixture::equal;
using rv64_fixture::Fixture;
struct Oracle {
  uint32_t variables, count, folds = 0;
  StwoRv64Plane n{}, d{}, banks_n[2]{}, banks_d[2]{}, raw{}, a{}, b{}, mask{};
  StwoRv64Plane original_n{}, original_d{};
};
static void exercise(const std::string &directory, uint32_t id,
                     uint32_t attack = 0) {
  Fixture f(directory + "/case-" + std::to_string(id) + ".bin");
  const auto h = f.take(8);
  const uint32_t count = h[2], variables = h[3];
  if (h[0] != 0x52564253 || h[1] != 1 || !count ||
      count > STWO_RV64_BATCH_MAX_ORACLES || variables > 20 || h[4] != id)
    throw std::runtime_error("bad batch fixture");
  Owner o(0);
  auto upload = [&](const std::vector<uint32_t> &v) {
    const auto p = o.plane(std::max(size_t(1), v.size()), 1);
    if (!v.empty())
      o.upload(p, v);
    return p;
  };
  auto seed_words = f.take(9), alpha_words = f.take(8),
       lambda_words = f.take(8), point_words = f.take(8 * variables),
       claim_words = f.take(8 * count);
  if (attack == 2) {
    std::fill(point_words.begin(), point_words.begin() + 8, 0);
    point_words[0] = 1;
  }
  if (attack == 3)
    claim_words[0] = 2147483647u;
  if (attack == 4)
    seed_words[8] = (1u << 20) + 1;
  const auto seed = upload(seed_words), alpha = upload(alpha_words),
             lambda = upload(lambda_words), point = upload(point_words),
             claims = upload(claim_words);
  std::vector<Oracle> oracles(count);
  std::vector<StwoRv64BatchOracle> descriptors(count);
  for (uint32_t i = 0; i < count; ++i) {
    auto &job = oracles[i];
    const auto meta = f.take(2);
    job.variables = meta[0];
    if (meta[0] > variables || meta[1] > 1)
      throw std::runtime_error("bad oracle fixture");
    job.count = 1u << (job.variables + 1);
    job.n = o.plane(job.count, meta[1] ? 1 : 8);
    job.d = o.plane(job.count, 8);
    job.original_n = job.n;
    job.original_d = job.d;
    o.upload(job.n, f.take(size_t(job.count) * job.n.coordinates));
    o.upload(job.d, f.take(size_t(job.count) * 8));
    job.mask = o.plane(32, 1);
    if (job.variables) {
      job.raw = o.plane(2, 8);
      for (uint32_t bank = 0; bank < 2; ++bank) {
        const uint32_t capacity = std::max(1u, job.count >> (bank + 1));
        job.banks_n[bank] = o.plane(capacity, 8);
        job.banks_d[bank] = o.plane(capacity, 8);
      }
      const uint32_t groups = (job.count / 4 + 127) / 128;
      job.a = o.plane(2 * groups, 8);
      job.b = o.plane(2 * groups, 8);
      descriptors[i] = {job.raw.words, job.raw.stride, job.variables, 0};
    } else
      descriptors[i] = {nullptr, 0, 0, 0};
  }
  const auto expected_records = f.take(size_t(variables) * round_record_words),
             expected_checkpoint = f.take(9), expected_claim = f.take(8);
  std::vector<std::vector<uint32_t>> expected_masks;
  for (uint32_t i = 0; i < count; ++i)
    expected_masks.push_back(f.take(32));
  if (f.cursor != f.data.size())
    throw std::runtime_error("trailing batch fixture");
  const auto eq = o.plane(variables ? 1u << (variables - 1) : 1, 8),
             state = o.plane(STWO_RV64_BATCH_STATE_WORDS, 1),
             records = o.plane(std::max(1u, variables * round_record_words), 1);
  StwoCudaDependency ready{};
  CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ready));
  CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ready));
  // Metadata failures are pre-enqueue and do not poison a usable execution.
  auto bad = descriptors;
  bad[0].reserved = 1;
  if (stwo_rv64_batch_init_on(o.ctx, 1, state.words, seed.words, claims.words,
                              alpha.words, bad.data(), count,
                              variables) != int(cudaErrorInvalidValue))
    throw std::runtime_error("bad descriptor admitted");
  if (stwo_rv64_batch_init_on(o.ctx, 1, state.words, state.words, claims.words,
                              alpha.words, descriptors.data(), count,
                              variables) != int(cudaErrorInvalidValue))
    throw std::runtime_error("aliased batch checkpoint admitted");
  if (variables) {
    const auto it = std::find_if(oracles.begin(), oracles.end(), [](const Oracle &j) { return j.variables != 0; });
    if (it == oracles.end()) throw std::runtime_error("missing active oracle");
    const auto &j = *it;
    StwoRv64BatchSumJob sum{j.n, j.d, j.a, j.b, j.raw};
    uint32_t launches = 99;
    if (stwo_rv64_batch_sum_on(o.ctx, 1, &sum, 0, j.count, eq, lambda.words, &launches) != int(cudaErrorInvalidValue) || launches)
      throw std::runtime_error("empty sum batch admitted");
    sum.out = sum.a;
    if (stwo_rv64_batch_sum_on(o.ctx, 1, &sum, 1, j.count, eq, lambda.words, &launches) != int(cudaErrorInvalidValue) || launches)
      throw std::runtime_error("aliased sum output admitted");
    StwoRv64BatchFoldJob fold{j.n, j.d, j.banks_n[0], j.d};
    if (stwo_rv64_batch_fold_on(o.ctx, 1, &fold, 1, j.count, alpha.words, &launches) != int(cudaErrorInvalidValue) || launches)
      throw std::runtime_error("in-place fold admitted");
  }
  CHECK(stwo_rv64_batch_init_on(o.ctx, 1, state.words, seed.words, claims.words,
                                alpha.words, descriptors.data(), count,
                                variables));
  auto round_descriptors = descriptors;
  if (attack == 1)
    round_descriptors[1].variables += 1;
  if (variables)
    CHECK(stwo_rv64_gkr_eq_on(o.ctx, 1, point.words, variables, eq));
  for (uint32_t round = 0; round < variables; ++round) {
    const uint32_t remaining = variables - round;
    std::vector<StwoRv64BatchSumJob> sum_jobs;
    for (auto &job : oracles)
      if (job.variables >= remaining) {
        if (job.count != (2u << remaining)) throw std::runtime_error("active count mismatch");
        sum_jobs.push_back({job.n, job.d, job.a, job.b, job.raw});
      }
    uint32_t sum_launches = 0;
    CHECK(stwo_rv64_batch_sum_on(o.ctx, 1, sum_jobs.data(), sum_jobs.size(),
        2u << remaining, eq, lambda.words, &sum_launches));
    if (!sum_launches) throw std::runtime_error("missing sum launch");
    auto *record = records.words + round * round_record_words;
    CHECK(stwo_rv64_batch_round_on(
        o.ctx, 1, state.words, round_descriptors.data(), count, variables,
        (attack == 5 && round == 0) ? 1 : round, point.words, record));
    const auto *challenge = record + 32;
    std::vector<StwoRv64BatchFoldJob> fold_jobs;
    for (auto &job : oracles)
      if (job.variables >= remaining) {
        const uint32_t bank = job.folds++ % 2;
        fold_jobs.push_back({job.n, job.d, job.banks_n[bank], job.banks_d[bank]});
        job.n = job.banks_n[bank]; job.d = job.banks_d[bank]; job.count /= 2;
      }
    uint32_t fold_launches = 0;
    CHECK(stwo_rv64_batch_fold_on(o.ctx, 1, fold_jobs.data(), fold_jobs.size(),
        2u << remaining, challenge, &fold_launches));
    if (fold_launches != 1) throw std::runtime_error("missing fold launch");
  }
  for (auto &job : oracles)
    CHECK(stwo_rv64_batch_mask_on(o.ctx, 1, job.n, job.d, job.mask.words));
  const auto final = o.read(state);
  if (attack) {
    const uint32_t expected_status = attack == 2   ? round_pole
                                     : attack == 3 ? round_field
                                                   : round_order;
    if (final[10] != expected_status || final[9] != 0)
      throw std::runtime_error("batch poison not sticky");
    const auto dead = o.read(records);
    for (uint32_t r = 0; r < variables; ++r) {
      const auto *row = dead.data() + r * round_record_words;
      for (uint32_t c = 0; c < 41; ++c)
        if (row[c] != 0)
          throw std::runtime_error("poison retained proof data");
      if (row[41] != UINT32_MAX || row[42] || row[43])
        throw std::runtime_error("poison record tag");
    }
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
    o.close();
    return;
  }

  if (final[9] != variables || final[10] || final[11] != variables ||
      final[40] != count)
    throw std::runtime_error("batch terminal status");
  equal({final.begin(), final.begin() + 9}, expected_checkpoint, "checkpoint",
        id);
  equal({final.begin() + 12, final.begin() + 20}, expected_claim, "claim", id);
  if (variables)
    equal(o.read(records), expected_records, "records", id);
  for (uint32_t i = 0; i < count; ++i)
    equal(o.read(oracles[i].mask), expected_masks[i], "mask", id);
  CHECK(stwo_exec_context_dependency_release(o.ctx, &ready));
  o.close();
}
int main(int argc, char **argv) {
  try {
    if (argc != 2)
      throw std::runtime_error("expected native fixture directory");
    for (uint32_t id = 0; id < 15; ++id)
      exercise(argv[1], id);
    for (uint32_t attack = 1; attack <= 5; ++attack)
      exercise(argv[1], 3, attack);
    std::printf("{\"schema\":\"rv64-om31-mixed-sumcheck-v1\",\"cases\":15,"
                "\"poison_cases\":5,\"native_"
                "proof_parity\":true,\"full_block_verified\":false}\n");
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
