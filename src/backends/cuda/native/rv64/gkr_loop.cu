// Complete native GKR parent transcript flow; numerical state never leaves
// CUDA.
#include "batch_state.cuh"
#include "custody.cuh"
#include "gkr_loop.h"
#include "transcript/state.cuh"
namespace stwo::cuda::rv64 {
namespace t = stwo::cuda::transcript;
constexpr uint32_t max_layers = 28;
struct GkrState {
  t::State channel;
  uint32_t layers, count, next_layer, phase;
  uint32_t variables[max_oracles], active_ids[max_oracles];
  uint32_t active_count, reserved[3];
  OM31 alpha, lambda;
  uint32_t seed[9], pad[3];
  OM31 claims[2 * max_oracles], point[max_layers];
};
static_assert(sizeof(GkrState) == STWO_RV64_GKR_STATE_WORDS * 4,
              "GKR parent ABI");
static_assert(offsetof(GkrState, alpha) / 4 == STWO_RV64_GKR_ALPHA_WORD,
              "alpha offset");
static_assert(offsetof(GkrState, lambda) / 4 == STWO_RV64_GKR_LAMBDA_WORD,
              "lambda offset");
static_assert(offsetof(GkrState, seed) / 4 == STWO_RV64_GKR_SEED_WORD,
              "seed offset");
static_assert(offsetof(GkrState, claims) / 4 == STWO_RV64_GKR_CLAIMS_WORD,
              "claims offset");
static_assert(offsetof(GkrState, point) / 4 == STWO_RV64_GKR_POINT_WORD,
              "point offset");
struct Plan {
  uint32_t variables[max_oracles], count, layers;
};
struct Roots {
  StwoRv64Root entries[max_oracles];
  uint32_t count;
};
static_assert(sizeof(Roots) < 4096, "bounded root metadata");
__device__ bool same(OM31 a, OM31 b) { return is_zero(sub(a, b)); }
__global__ void pack_roots(Roots roots, uint32_t *out) {
  const uint32_t i = blockIdx.x, c = threadIdx.x;
  if (i < roots.count && c < 8) {
    out[16 * i + c] = roots.entries[i].n.words[c * roots.entries[i].n.stride];
    out[16 * i + 8 + c] =
        roots.entries[i].d.words[c * roots.entries[i].d.stride];
  }
}
__global__ void init_parent(uint32_t *words, const uint32_t *seed, Plan plan,
                            uint64_t chain) {
  auto *s = reinterpret_cast<GkrState *>(words);
  t::copy_words(s->channel.digest, seed, 8);
  s->channel.draws = seed[8];
  s->channel.cursor = 0;
  s->channel.status =
      seed[8] <= t::kMaximumSeedDraws ? t::kOk : t::kInvalidSeed;
  s->channel.reserved = 0;
  s->channel.chain = chain;
  s->channel.padding[0] = s->channel.padding[1] = 0;
  s->layers = plan.layers;
  s->count = plan.count;
  s->next_layer = s->phase = s->active_count = 0;
  for (uint32_t i = 0; i < max_oracles; ++i) {
    s->variables[i] = plan.variables[i];
    s->active_ids[i] = 0;
    s->claims[2 * i] = s->claims[2 * i + 1] = zero();
  }
  for (auto &v : s->point)
    v = zero();
  s->alpha = s->lambda = zero();
  for (auto &v : s->seed)
    v = 0;
  for (auto &v : s->pad)
    v = 0;
  for (auto &v : s->reserved)
    v = 0;
}
__global__ void begin_layer(uint32_t *words, uint32_t layer, uint32_t count,
                            uint32_t active, const uint32_t *roots,
                            uint32_t *claims) {
  auto *s = reinterpret_cast<GkrState *>(words);
  for (uint32_t i = 0; i < 8 * active; ++i)
    claims[i] = 0;
  for (auto &v : s->seed)
    v = 0;
  s->seed[8] =
      t::kMaximumSeedDraws + 1; // poison any dependent batch after failure
  s->alpha = s->lambda = zero();
  if (s->channel.status != t::kOk)
    return;
  if (s->phase != 0 || s->next_layer != layer || layer >= s->layers ||
      s->count != count || s->channel.cursor != 2 * layer ||
      s->channel.reserved) {
    s->channel.status = t::kOrder;
    return;
  }
  const uint32_t remaining = s->layers - layer;
  uint32_t found = 0;
  for (uint32_t i = 0; i < count; ++i)
    if (s->variables[i] == 0 || s->variables[i] > s->layers) {
      s->channel.status = t::kOrder;
      return;
    }
  for (uint32_t i = 0; i < count; ++i)
    if (s->variables[i] >= remaining) {
      s->active_ids[found++] = i;
      const auto n = s->variables[i] == remaining ? from_words(roots + 16 * i)
                                                  : s->claims[2 * i];
      const auto d = s->variables[i] == remaining
                         ? from_words(roots + 16 * i + 8)
                         : s->claims[2 * i + 1];
      if (!canonical(n) || !canonical(d)) {
        s->channel.status = t::kInvalidField;
        return;
      }
    }
  if (found != active) {
    s->channel.status = t::kOrder;
    return;
  }
  s->active_count = found;
  for (uint32_t j = 0; j < active; ++j) {
    const uint32_t i = s->active_ids[j];
    if (s->variables[i] == remaining) {
      s->claims[2 * i] = from_words(roots + 16 * i);
      s->claims[2 * i + 1] = from_words(roots + 16 * i + 8);
    }
    t::update_digest(&s->channel,
                     reinterpret_cast<const uint32_t *>(&s->claims[2 * i]), 16);
  }
  s->alpha = draw_raw_om(s->channel.digest, &s->channel.draws);
  s->lambda = draw_raw_om(s->channel.digest, &s->channel.draws);
  for (uint32_t j = 0; j < active; ++j) {
    const uint32_t i = s->active_ids[j];
    const auto c = add(s->claims[2 * i], mul(s->lambda, s->claims[2 * i + 1]));
    for (uint32_t k = 0; k < 8; ++k)
      claims[8 * j + k] = coordinate(c, k);
  }
  t::copy_words(s->seed, s->channel.digest, 8);
  s->seed[8] = s->channel.draws;
  s->phase = 1;
  ++s->channel.cursor;
}
__global__ void close_layer(uint32_t *words, const uint32_t *batch_words,
                            const uint32_t *record_words, const uint32_t *masks,
                            uint32_t layer, uint32_t count, uint32_t active) {
  auto *s = reinterpret_cast<GkrState *>(words);
  const auto *b = reinterpret_cast<const BatchState *>(batch_words);
  if (s->channel.status != t::kOk)
    return;
  if (s->phase != 1 || s->next_layer != layer || layer >= s->layers ||
      s->count != count || s->active_count != active ||
      s->channel.cursor != 2 * layer + 1) {
    s->channel.status = t::kOrder;
    return;
  }
  bool valid = b->round.status == round_ok && b->round.variables == layer &&
               b->round.next_round == layer && b->count == active &&
               same(b->initial_alpha, s->alpha) &&
               b->round.draws == (layer ? 1u : s->seed[8]) &&
               same(b->round.correction, one()) && canonical(b->round.claim) &&
               canonical(b->round.prefix);
  for (auto v : b->round.reserved)
    valid = valid && v == 0;
  for (auto v : b->reserved)
    valid = valid && v == 0;
  for (uint32_t i = 0; i < 9; ++i)
    valid = valid && b->initial_seed[i] == s->seed[i];
  const uint32_t remaining = s->layers - layer;
  for (uint32_t j = 0; j < active; ++j) {
    const uint32_t i = s->active_ids[j];
    if (i >= count || s->variables[i] < remaining ||
        s->variables[i] > s->layers || (j && i <= s->active_ids[j - 1])) {
      s->channel.status = t::kOrder;
      return;
    }
    valid = valid && b->initial_variables[j] == s->variables[i] - remaining &&
            same(b->initial_claims[j],
                 add(s->claims[2 * i], mul(s->lambda, s->claims[2 * i + 1])));
  }
  if (!valid) {
    s->channel.status = t::kInvalidStatement;
    return;
  }
  const auto *records = reinterpret_cast<const RoundRecord *>(record_words);
  for (uint32_t r = 0; r < layer; ++r) {
    if (records[r].ordinal != r || records[r].length > 4 ||
        records[r].reserved[0] || records[r].reserved[1] ||
        !canonical(records[r].challenge)) {
      s->channel.status = t::kInvalidStatement;
      return;
    }
  }
  for (uint32_t r = 0; r < layer; ++r) {
    const auto &record = records[r];
    for (uint32_t k = 0; k < 4; ++k) {
      if (!canonical(record.coefficients[k]) ||
          (k >= record.length && !is_zero(record.coefficients[k]))) {
        s->channel.status = t::kInvalidStatement;
        return;
      }
    }
    if (record.length && is_zero(record.coefficients[record.length - 1])) {
      s->channel.status = t::kInvalidStatement;
      return;
    }
  }
  for (uint32_t i = 0; i < 32 * active; ++i)
    if (masks[i] >= q::kPrime) {
      s->channel.status = t::kInvalidField;
      return;
    }
  t::copy_words(s->channel.digest, b->round.digest, 8);
  s->channel.draws = b->round.draws;
  for (uint32_t j = 0; j < active; ++j)
    t::update_digest(&s->channel, masks + 32 * j, 32);
  const auto z = draw_raw_om(s->channel.digest, &s->channel.draws);
  for (uint32_t r = 0; r < layer; ++r)
    s->point[r] = records[r].challenge;
  s->point[layer] = z;
  for (uint32_t j = 0; j < active; ++j) {
    const uint32_t i = s->active_ids[j];
    s->claims[2 * i] =
        fold(from_words(masks + 32 * j), from_words(masks + 32 * j + 8), z);
    s->claims[2 * i + 1] = fold(from_words(masks + 32 * j + 16),
                                from_words(masks + 32 * j + 24), z);
  }
  ++s->next_layer;
  ++s->channel.cursor;
  s->phase = s->next_layer == s->layers ? 2 : 0;
}
__global__ void derive_binding(StwoRv64BindingMetadata job) {
  auto *out = reinterpret_cast<OM31 *>(job.reservoir);
  auto *row = reinterpret_cast<OM31 *>(job.row_point);
  auto *carry = reinterpret_cast<OM31 *>(job.carry);
  for (uint32_t i = 0; i < 260; ++i)
    out[i] = zero();
  for (uint32_t i = 0; i < job.row_log; ++i)
    row[i] = zero();
  for (uint32_t i = 0; i < 2 * job.row_log; ++i)
    carry[i] = zero();
  for (uint32_t i = 0; i < 9; ++i)
    job.seed[i] = 0;
  job.seed[8] = t::kMaximumSeedDraws + 1;
  if (*job.status)
    return;
  const auto *s = reinterpret_cast<const GkrState *>(job.state);
  if (s->channel.status != t::kOk || s->channel.reserved ||
      s->channel.padding[0] || s->channel.padding[1] ||
      s->channel.chain != job.chain || s->channel.cursor != 2 * job.layers ||
      s->channel.draws != 1 || s->phase != 2 || s->next_layer != job.layers ||
      s->layers != job.layers || s->count != job.count ||
      s->variables[job.instance] != job.row_log + job.lane_log) {
    atomicOr(job.status, 1u);
    return;
  }
  const uint32_t start = job.layers - job.row_log - job.lane_log;
  for (uint32_t i = start; i < job.layers; ++i) {
    if (!canonical(s->point[i])) {
      atomicOr(job.status, 2u);
      return;
    }
    if (i < start + job.row_log &&
        (is_zero(s->point[i]) || same(s->point[i], one()))) {
      atomicOr(job.status, 4u);
      return;
    }
  }
  const OM31 numerator = s->claims[2 * job.instance];
  const OM31 denominator = s->claims[2 * job.instance + 1];
  if (!canonical(numerator) || !canonical(denominator)) {
    atomicOr(job.status, 2u);
    return;
  }
  auto channel = s->channel;
  const OM31 eta = draw_raw_om(channel.digest, &channel.draws);
  const uint32_t lanes = 1u << job.lane_log;
  for (uint32_t lane = 0; lane < lanes; ++lane) {
    OM31 value = one();
    for (uint32_t k = 0; k < job.lane_log; ++k) {
      const OM31 coordinate = s->point[start + job.row_log + k];
      value = mul(value, ((lane >> (job.lane_log - 1 - k)) & 1u)
                             ? coordinate
                             : sub(one(), coordinate));
    }
    out[lane] = value;
  }
  OM31 ones = one(), zeros = one();
  for (uint32_t i = 0; i < job.row_log; ++i) {
    const OM31 v = s->point[start + i];
    row[i] = v;
    const OM31 numerator = mul(ones, sub(one(), v));
    const OM31 denominator = mul(zeros, v);
    carry[i] = mul(numerator, inverse_nonzero(denominator));
    ones = mul(ones, v);
    zeros = mul(zeros, sub(one(), v));
  }
  const OM31 last = row[job.row_log - 1];
  carry[job.row_log - 1] =
      mul(carry[job.row_log - 1], mul(last, inverse_nonzero(sub(one(), last))));
  for (uint32_t i = 0; i < job.row_log; ++i)
    carry[job.row_log + i] = inverse_nonzero(carry[i]);
  out[256] = eta;
  out[257] = scale(add(numerator, mul(eta, denominator)),
                   q::inverse(1u << job.row_log));
  out[258] = zeros;
  out[259] = ones;
  t::copy_words(job.seed, channel.digest, 8);
  job.seed[8] = channel.draws;
}

} // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int stwo_rv64_gkr_pack_roots_on(void *ctx, uint32_t lane,
                                           const StwoRv64Root *sources,
                                           uint32_t count, uint32_t *output) {
  if (!sources || !count || count > max_oracles)
    return int(cudaErrorInvalidValue);
  RangeCustody<2 * max_oracles + 1> c(ctx, lane);
  Roots roots{};
  roots.count = count;
  for (uint32_t i = 0; i < count; ++i) {
    if (!c.plane(sources[i].n, 1, 8, false) ||
        !c.plane(sources[i].d, 1, 8, false))
      return c.status;
    roots.entries[i] = sources[i];
  }
  if (!c.range(output, 16ull * count, true))
    return c.status;
  pack_roots<<<count, 32, 0, c.stream>>>(roots, output);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_gkr_init_on(void *ctx, uint32_t lane, uint32_t *state,
                                     const uint32_t *seed,
                                     const uint32_t *variables, uint32_t count,
                                     uint32_t layers, uint64_t chain) {
  if (!variables || !count || count > max_oracles || !layers ||
      layers > max_layers)
    return int(cudaErrorInvalidValue);
  Plan plan{};
  plan.count = count;
  plan.layers = layers;
  uint32_t largest = 0;
  for (uint32_t i = 0; i < count; ++i) {
    if (!variables[i] || variables[i] > layers)
      return int(cudaErrorInvalidValue);
    plan.variables[i] = variables[i];
    largest = largest > variables[i] ? largest : variables[i];
  }
  if (largest != layers ||
      reinterpret_cast<uintptr_t>(state) % alignof(GkrState))
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(state, STWO_RV64_GKR_STATE_WORDS, true) ||
      !c.range(seed, 9, false))
    return c.status;
  init_parent<<<1, 1, 0, c.stream>>>(state, seed, plan, chain);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_gkr_begin_on(void *ctx, uint32_t lane, uint32_t *state,
                                      uint32_t layer, uint32_t count,
                                      uint32_t active, const uint32_t *roots,
                                      uint32_t *claims) {
  if (!count || count > max_oracles || !active || active > count ||
      layer >= max_layers ||
      reinterpret_cast<uintptr_t>(state) % alignof(GkrState))
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(state, STWO_RV64_GKR_STATE_WORDS, true) ||
      !c.range(roots, 16ull * count, false) ||
      !c.range(claims, 8ull * active, true))
    return c.status;
  begin_layer<<<1, 1, 0, c.stream>>>(state, layer, count, active, roots,
                                     claims);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_gkr_close_on(void *ctx, uint32_t lane, uint32_t *state,
                                      const uint32_t *batch,
                                      const uint32_t *records,
                                      const uint32_t *masks, uint32_t layer,
                                      uint32_t count, uint32_t active) {
  if (!count || count > max_oracles || !active || active > count ||
      layer >= max_layers || (layer == 0 && records != nullptr) ||
      reinterpret_cast<uintptr_t>(state) % alignof(GkrState))
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(state, STWO_RV64_GKR_STATE_WORDS, true) ||
      !c.range(batch, STWO_RV64_BATCH_STATE_WORDS, false) ||
      (layer &&
       !c.range(records, uint64_t(layer) * round_record_words, false)) ||
      !c.range(masks, 32ull * active, false))
    return c.status;
  close_layer<<<1, 1, 0, c.stream>>>(state, batch, records, masks, layer, count,
                                     active);
  return int(cudaPeekAtLastError());
}

extern "C" int
stwo_rv64_gkr_binding_metadata_on(void *ctx, uint32_t lane,
                                  const StwoRv64BindingMetadata *input) {
  if (!input || input->reserved || !input->count ||
      input->count > max_oracles || input->instance >= input->count ||
      !input->layers || input->layers > 28 || !input->row_log ||
      input->row_log > 22 || input->lane_log > 8 ||
      input->row_log + input->lane_log > input->layers ||
      reinterpret_cast<uintptr_t>(input->state) % alignof(GkrState))
    return int(cudaErrorInvalidValue);
  const auto job = *input;
  Custody c(ctx, lane);
  if (!c.range(job.state, STWO_RV64_GKR_STATE_WORDS, false) ||
      !c.range(job.reservoir, 260 * 8, true) ||
      !c.range(job.row_point, job.row_log * 8, true) ||
      !c.range(job.carry, job.row_log * 16, true) ||
      !c.range(job.seed, 9, true) || !c.range(job.status, 1, true))
    return c.status;
  derive_binding<<<1, 1, 0, c.stream>>>(job);
  return int(cudaPeekAtLastError());
}
