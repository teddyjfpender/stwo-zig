#ifndef STWO_ZIG_TESTS_CUDA_NATIVE_FRI_REFERENCE_H
#define STWO_ZIG_TESTS_CUDA_NATIVE_FRI_REFERENCE_H

std::vector<std::uint32_t> final_reference(
    const std::vector<std::uint32_t> &evaluation,
    std::uint32_t stride,
    std::uint32_t log_size,
    const std::vector<std::uint32_t> &twiddles) {
    const std::uint32_t size = 1u << log_size;
    std::vector<std::uint32_t> coefficients(4 * size);
    for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
        for (std::uint32_t row = 0; row < size; ++row) {
            coefficients[coordinate * size + row] =
                evaluation[coordinate * stride + bit_reverse(row, log_size)];
        }
    }
    for (std::uint32_t stage = log_size; stage > 0; --stage) {
        const std::uint32_t domain_size = 1u << stage;
        const std::uint32_t half = domain_size / 2;
        for (std::uint32_t butterfly = 0; butterfly < size / 2; ++butterfly) {
            const std::uint32_t chunk = butterfly / half;
            const std::uint32_t index = butterfly - chunk * half;
            const std::uint32_t left = chunk * domain_size + index;
            const std::uint32_t right = left + half;
            const std::uint32_t twiddle_index =
                stage == 1 ? 0 : bit_reverse(index, stage - 1);
            const std::uint32_t twiddle =
                twiddles[twiddles.size() - domain_size + twiddle_index];
            for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
                auto *column = coefficients.data() + coordinate * size;
                const std::uint32_t left_value = column[left];
                const std::uint32_t right_value = column[right];
                column[left] = add(left_value, right_value);
                column[right] = mul(sub(left_value, right_value), twiddle);
            }
        }
    }
    const std::uint32_t factor = 1u << (31u - log_size);
    for (auto &coefficient : coefficients) {
        coefficient = mul(coefficient, factor);
    }
    return coefficients;
}

std::vector<std::uint32_t> transcript_coefficients(
    const std::vector<std::uint32_t> &coefficients,
    std::uint32_t log_size,
    std::uint32_t log_bound,
    bool *degree_error) {
    const std::uint32_t size = 1u << log_size;
    const std::uint32_t bound = 1u << log_bound;
    *degree_error = false;
    for (std::uint32_t ordered = bound; ordered < size; ++ordered) {
        const std::uint32_t source = bit_reverse(ordered, log_size);
        for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
            *degree_error |= coefficients[coordinate * size + source] != 0;
        }
    }
    std::vector<std::uint32_t> result(4 * bound);
    for (std::uint32_t output = 0; output < bound; ++output) {
        const std::uint32_t ordered =
            log_bound == 0 ? 0 : bit_reverse(output, log_bound);
        const std::uint32_t source = bit_reverse(ordered, log_size);
        for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
            result[4 * output + coordinate] =
                coefficients[coordinate * size + source];
        }
    }
    if (*degree_error) result[0] = kPrime;
    return result;
}

#endif
