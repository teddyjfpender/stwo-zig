// Challenge-derived State Machine statement transaction.
//
// One lane advances the resident transcript through statement0, two secure
// draws, public input, and statement1. No challenge or statement data crosses
// the host boundary.

#include "../../native/oods/field.cuh"
#include "../../native/transcript/state.cuh"

#include <cstdint>

namespace {

using stwo::cuda::oods::M31;
using stwo::cuda::oods::QM31;
using stwo::cuda::transcript::Hash;
using stwo::cuda::transcript::State;

__device__ bool is_zero(QM31 value) {
    return value.a.a == 0u && value.a.b == 0u &&
        value.b.a == 0u && value.b.b == 0u;
}

__device__ QM31 load_qm31(const std::uint32_t *words) {
    return {{words[0], words[1]}, {words[2], words[3]}};
}

__device__ void store_qm31(std::uint32_t *words, QM31 value) {
    words[0] = value.a.a;
    words[1] = value.a.b;
    words[2] = value.b.a;
    words[3] = value.b.b;
}

__device__ bool draw_secure_one(State *state, QM31 *output) {
    for (std::uint32_t attempt = 0; attempt < 64u; ++attempt) {
        const Hash words = stwo::cuda::transcript::draw(state);
        bool accepted = true;
#pragma unroll
        for (std::uint32_t word = 0; word < 8u; ++word) {
            if (words.words[word] >=
                2u * stwo::cuda::transcript::kM31Prime) {
                accepted = false;
            }
        }
        if (!accepted) continue;
        std::uint32_t reduced[4];
#pragma unroll
        for (std::uint32_t word = 0; word < 4u; ++word) {
            reduced[word] =
                words.words[word] >= stwo::cuda::transcript::kM31Prime
                ? words.words[word] -
                    stwo::cuda::transcript::kM31Prime
                : words.words[word];
        }
        *output = load_qm31(reduced);
        return true;
    }
    state->status = stwo::cuda::transcript::kRejectionLimit;
    return false;
}

__device__ QM31 combine(
    M31 x,
    M31 y,
    QM31 z,
    QM31 alpha) {
    return stwo::cuda::oods::sub(
        stwo::cuda::oods::add(
            x,
            stwo::cuda::oods::mul(y, alpha)),
        z);
}

}  // namespace

extern "C" __global__ void
stwo_native_statement_state_machine_v1_6324a81f31d00d9e(
    std::uint32_t *state_words,
    std::uint32_t expected_step,
    std::uint64_t expected_chain,
    std::uint64_t next_chain,
    std::uint32_t *statement_words,
    std::uint64_t statement_word_count,
    std::uint32_t *input_snapshot,
    std::uint64_t input_snapshot_words,
    std::uint32_t *output_snapshot,
    std::uint64_t output_snapshot_words,
    std::uint32_t *boundary_snapshot) {
    State *state = stwo::cuda::transcript::as_state(state_words);
    if (stwo::cuda::transcript::begin_step(
            state, expected_step, expected_chain)) {
        if (statement_words == nullptr || statement_word_count != 14u ||
            input_snapshot == nullptr || input_snapshot_words < 14u ||
            output_snapshot == nullptr || output_snapshot_words < 8u) {
            state->status =
                stwo::cuda::transcript::kInvalidStatement;
        } else {
            const std::uint32_t log_rows = statement_words[0];
            const M31 initial_x = statement_words[2];
            const M31 initial_y = statement_words[3];
            if (log_rows == 0u || log_rows >= 31u ||
                statement_words[1] != log_rows - 1u ||
                initial_x >= stwo::cuda::oods::kPrime ||
                initial_y >= stwo::cuda::oods::kPrime) {
                state->status =
                    stwo::cuda::transcript::kInvalidStatement;
            } else {
                stwo::cuda::transcript::update_digest(
                    state, statement_words, 2u);
                QM31 z{};
                QM31 alpha{};
                if (draw_secure_one(state, &z) &&
                    draw_secure_one(state, &alpha)) {
                    store_qm31(output_snapshot, z);
                    store_qm31(output_snapshot + 4, alpha);

                    const M31 x_delta = 1u << log_rows;
                    const M31 y_delta = 1u << (log_rows - 1u);
                    const M31 intermediate_x =
                        stwo::cuda::oods::add(initial_x, x_delta);
                    const M31 final_y =
                        stwo::cuda::oods::add(initial_y, y_delta);
                    statement_words[4] = intermediate_x;
                    statement_words[5] = final_y;

                    const QM31 initial = combine(
                        initial_x, initial_y, z, alpha);
                    const QM31 intermediate = combine(
                        intermediate_x, initial_y, z, alpha);
                    const QM31 final = combine(
                        intermediate_x, final_y, z, alpha);
                    if (is_zero(initial) || is_zero(intermediate) ||
                        is_zero(final)) {
                        state->status =
                            stwo::cuda::transcript::kInvalidStatement;
                    } else {
                        const QM31 x_sum = stwo::cuda::oods::sub(
                            stwo::cuda::oods::inverse(initial),
                            stwo::cuda::oods::inverse(intermediate));
                        const QM31 y_sum = stwo::cuda::oods::sub(
                            stwo::cuda::oods::inverse(intermediate),
                            stwo::cuda::oods::inverse(final));
                        store_qm31(statement_words + 6, x_sum);
                        store_qm31(statement_words + 10, y_sum);
                        stwo::cuda::transcript::update_digest(
                            state, statement_words + 2, 4u);
                        stwo::cuda::transcript::update_digest(
                            state, statement_words + 6, 8u);
                        stwo::cuda::transcript::copy_words(
                            input_snapshot, statement_words, 14u);
                    }
                }
            }
        }
    }
    stwo::cuda::transcript::finish_step(
        state, next_chain, boundary_snapshot);
}
