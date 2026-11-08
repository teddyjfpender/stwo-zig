#ifndef STWO_CUDA_RV64_ROUND_CUH
#define STWO_CUDA_RV64_ROUND_CUH
#include "om31.cuh"
#include "transcript/blake2s_words.cuh"

namespace stwo::cuda::rv64 {
constexpr uint32_t round_state_words = 40;
constexpr uint32_t round_record_words = 44;
enum RoundStatus : uint32_t { round_ok = 0, round_order = 1, round_field = 2, round_pole = 3 };
struct RoundState {
    uint32_t digest[8];
    uint32_t draws, next_round, status, variables;
    OM31 claim, correction, prefix;
    uint32_t reserved[4];
};
struct RoundRecord {
    OM31 coefficients[4];
    OM31 challenge;
    uint32_t length, ordinal, reserved[2];
};
static_assert(sizeof(RoundState) == round_state_words * 4, "round state ABI");
static_assert(sizeof(RoundRecord) == round_record_words * 4, "round record ABI");
static_assert(offsetof(RoundRecord, challenge) == 128, "challenge offset");
static_assert(offsetof(RoundRecord, length) == 160, "trimmed-length offset");

__device__ __forceinline__ OM31 draw_raw_om(uint32_t digest[8], uint32_t* draws) {
    const auto hash = transcript::hash_draw(digest, (*draws)++);
    uint32_t words[8];
    for (uint32_t i = 0; i < 8; ++i) {
        const uint32_t x = hash.words[i];
        const uint32_t v = (x & q::kPrime) + (x >> 31);
        words[i] = v >= q::kPrime ? v - q::kPrime : v;
    }
    return from_words(words);
}
__device__ __forceinline__ void initialize_round(RoundState* s, const uint32_t seed[9],
                                                 OM31 claim, uint32_t variables) {
    for (uint32_t i = 0; i < 8; ++i) s->digest[i] = seed[i];
    s->draws = seed[8];
    s->next_round = 0;
    s->variables = variables;
    s->status = canonical(claim) ? round_ok : round_field;
    s->claim = claim;
    s->correction = one();
    s->prefix = one();
    for (auto& v : s->reserved) v = 0;
}
__device__ __forceinline__ OM31 eval_poly(const OM31 coefficients[4], OM31 x) {
    OM31 result = zero();
    for (int i = 3; i >= 0; --i) result = add(mul(result, x), coefficients[i]);
    return result;
}
// Exact native GKR correctSumAsPolyInFirstVariable + native single-oracle
// sumcheck transcript step. No scalar leaves the device for interpolation.
__device__ __forceinline__ bool advance_round_with_constant(RoundState* s, uint32_t expected_round, Pair raw,
                                              OM31 y, RoundRecord* record, OM31 constant) {
    if (s->status != round_ok) return false;
    if (s->next_round != expected_round || expected_round >= s->variables) {
        s->status = round_order;
        return false;
    }
    if (!canonical(y) || !canonical(raw.at0) || !canonical(raw.at2)) {
        s->status = round_field;
        return false;
    }
    const OM31 ym = sub(one(), y), prefix = mul(s->prefix, ym);
    const OM31 denominator = sub(one(), add(y, y));
    if (is_zero(prefix) || is_zero(denominator)) {
        s->status = round_pole;
        return false;
    }
    const OM31 eq2 = sub(scale(y, 3), one());
    // b=(1-y)/(1-2y). Then b(b-1)(b-2)=(1-y)*y*(3y-1)/t^3.
    // Clear t from Newton interpolation before inversion, retaining t!=0 as
    // the native pole gate. Batch-invert prefix and the cubic denominator
    // with ONE norm descent rather than three sequential OM31 inversions.
    const OM31 cubic_denominator = mul(mul(ym, y), eq2);
    if (is_zero(cubic_denominator)) {
        s->status = round_pole;
        return false;
    }
    const OM31 reciprocal_product = inverse_nonzero(mul(prefix, cubic_denominator));
    const OM31 a = mul(cubic_denominator, reciprocal_product);
    const OM31 inverse_cubic = mul(prefix, reciprocal_product);
    const OM31 r0 = mul(mul(mul(raw.at0, s->correction), ym), a);
    const OM31 r1 = sub(sub(s->claim, scale(constant, 2)), r0);
    const OM31 r2 = mul(mul(mul(raw.at2, s->correction), eq2), a);
    const OM31 delta = sub(r1, r0);
    const OM31 quadratic = scale(add(sub(r2, add(r1, r1)), r0), 1073741824u);
    const OM31 scaled_at_b =
        mul(denominator, add(mul(denominator, add(mul(r0, denominator), mul(delta, ym))),
                             mul(quadratic, mul(ym, y))));
    const OM31 cubic = mul(sub(zero(), scaled_at_b), inverse_cubic);
    const OM31 coeffs[4] = {add(r0, constant), add(sub(delta, quadratic), add(cubic, cubic)),
                            sub(quadratic, scale(cubic, 3)), cubic};
    uint32_t length = 4;
    while (length && is_zero(coeffs[length - 1])) --length;
    // No transcript state change occurs before all pole/field/order checks.
    for (uint32_t i = 0; i < 4; ++i) record->coefficients[i] = coeffs[i];
    record->length = length;
    record->ordinal = expected_round;
    record->reserved[0] = record->reserved[1] = 0;
    const auto hash = transcript::hash_digest_and_words(
        s->digest, reinterpret_cast<const uint32_t*>(record->coefficients), 8 * length);
    for (uint32_t i = 0; i < 8; ++i) s->digest[i] = hash.words[i];
    s->draws = 0;
    const OM31 challenge = draw_raw_om(s->digest, &s->draws);
    record->challenge = challenge;
    s->claim = eval_poly(coeffs, challenge);
    s->correction = mul(s->correction, add(mul(sub(one(), challenge), ym), mul(challenge, y)));
    s->prefix = prefix;
    ++s->next_round;
    return true;
}
// STWO_RV64_M8_GKR_BATCH_PAR split of advance_round_with_constant for the
// cooperative mixed-oracle round (batch_transition.cuh). The arithmetic is an
// exact re-association of the same field expressions (canonical M31 results
// do not depend on association order), so records, digests, challenges and
// claims are bit-identical; batch_par_bench.cu checks it against the serial
// transition. Everything that depends only on y and the incoming prefix (the
// batch round always enters with correction == one()) is precomputed:
//   r0 = raw0 k0, r2 = raw2 k2, k0 = (1-y) a, k2 = (3y-1) a,
//   cubic = raw0 p0 + raw2 p2 + (claim - 2 constant) ps,
// which is the serial Newton/interpolation cubic expanded linearly in r0, r2
// and r1 = claim - 2 constant - r0. Status precedence is unchanged: state
// status, order, field, then pole; no state changes before all checks pass.
struct RoundPrelude {
    OM31 y, prefix, k0, k2, p0, p2, ps;
    uint32_t pole;
};
// Transcript part of advance_round_with_constant given the prelude and the
// raw-dependent products (computed in parallel by the caller). On success the
// caller finishes s->claim = eval_poly(coefficients, record->challenge) and
// resets s->correction; the batch round leaves correction at one().
__device__ __forceinline__ bool advance_round_with_terms(RoundState* s, uint32_t expected_round,
                                                         Pair raw, const RoundPrelude& p,
                                                         OM31 r0, OM31 r2, OM31 cubic,
                                                         RoundRecord* record, OM31 constant,
                                                         OM31 coefficients[4]) {
    if (s->status != round_ok) return false;
    if (s->next_round != expected_round || expected_round >= s->variables) {
        s->status = round_order;
        return false;
    }
    if (!canonical(p.y) || !canonical(raw.at0) || !canonical(raw.at2)) {
        s->status = round_field;
        return false;
    }
    if (p.pole) {
        s->status = round_pole;
        return false;
    }
    const OM31 r1 = sub(sub(s->claim, scale(constant, 2)), r0);
    const OM31 delta = sub(r1, r0);
    const OM31 quadratic = scale(add(sub(r2, add(r1, r1)), r0), 1073741824u);
    coefficients[0] = add(r0, constant);
    coefficients[1] = add(sub(delta, quadratic), add(cubic, cubic));
    coefficients[2] = sub(quadratic, scale(cubic, 3));
    coefficients[3] = cubic;
    uint32_t length = 4;
    while (length && is_zero(coefficients[length - 1])) --length;
    uint32_t words[32];
    for (uint32_t i = 0; i < 4; ++i) {
        record->coefficients[i] = coefficients[i];
        for (uint32_t c = 0; c < 8; ++c) words[8 * i + c] = coordinate(coefficients[i], c);
    }
    record->length = length;
    record->ordinal = expected_round;
    record->reserved[0] = record->reserved[1] = 0;
    const auto hash = transcript::hash_digest_and_words(s->digest, words, 8 * length);
    for (uint32_t i = 0; i < 8; ++i) s->digest[i] = hash.words[i];
    s->draws = 0;
    record->challenge = draw_raw_om(s->digest, &s->draws);
    s->prefix = p.prefix;
    ++s->next_round;
    return true;
}
// The single-oracle path is exactly the zero-constant specialization.
__device__ __forceinline__ bool advance_round(RoundState* s, uint32_t expected_round, Pair raw,
                                              OM31 y, RoundRecord* record) {
    return advance_round_with_constant(s, expected_round, raw, y, record, zero());
}
// Clear first, including when an earlier queued round already poisoned state.
__device__ __forceinline__ bool prepare_record(RoundState* owner, uint32_t variables,
                                               RoundRecord* record) {
    auto* words = reinterpret_cast<uint32_t*>(record);
    for (uint32_t i = 0; i < round_record_words; ++i) words[i] = 0;
    record->ordinal = UINT32_MAX;
    if (owner->status != round_ok) return false;
    if (owner->variables != variables) {
        owner->status = round_order;
        return false;
    }
    return true;
}
__device__ __forceinline__ void advance_record(RoundState* owner, uint32_t variables,
                                               uint32_t expected, Pair raw, OM31 y,
                                               RoundRecord* record) {
    if (prepare_record(owner, variables, record))
        advance_round(owner, expected, raw, y, record);
}
}  // namespace stwo::cuda::rv64
#endif
