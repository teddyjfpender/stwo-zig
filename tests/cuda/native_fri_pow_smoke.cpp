#include "transcript_reference.h"

#include <cuda_runtime_api.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <vector>

extern "C" int stwo_exec_context_create(void **);
extern "C" int stwo_exec_context_destroy(void *);
extern "C" int stwo_exec_context_sync(void *);
extern "C" int stwo_exec_context_stream(void *, void **);
extern "C" int stwo_exec_context_alloc_u32(
    void *, std::size_t, std::uint32_t **);
extern "C" int stwo_exec_context_free_u32(void *, std::uint32_t *);
extern "C" int stwo_exec_context_fill_u32_async(
    void *, std::uint32_t *, std::uint32_t, std::size_t);
extern "C" int stwo_exec_context_memcpy_h2d_async(
    void *, void *, const void *, std::size_t);
extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *, void *, const void *, std::size_t);

struct Qm31 {
    std::uint32_t words[4];
};

extern "C" int stwo_fold_circle_into_line_on(
    const std::uint32_t *, std::size_t, std::uint32_t, std::uint32_t,
    const std::uint32_t *, std::size_t, std::uint32_t, const Qm31 *,
    std::uint32_t, std::uint32_t *, std::size_t, std::uint32_t, void *);
extern "C" int stwo_fold_line_on(
    const std::uint32_t *, std::size_t, std::uint32_t, std::uint32_t,
    const std::uint32_t *, std::size_t, std::uint32_t, const Qm31 *,
    std::uint32_t, std::uint32_t *, std::size_t, std::uint32_t, void *);
extern "C" int stwo_fri_fold_fused3_on(
    const std::uint32_t *, std::size_t, std::uint32_t, std::uint32_t,
    std::uint32_t, std::uint32_t, std::uint32_t, const std::uint32_t *,
    std::size_t, std::uint32_t, const Qm31 *, std::uint32_t *,
    std::size_t, std::uint32_t, void *);
extern "C" int stwo_fri_last_layer_on(
    const std::uint32_t *, std::size_t, std::uint32_t, std::uint32_t,
    const std::uint32_t *, std::uint32_t, std::uint32_t, std::uint32_t *,
    std::size_t, std::uint32_t *, std::size_t, std::uint32_t *,
    std::size_t, void *);
extern "C" int stwo_blake2s_pow_persistent_on(
    const std::uint32_t *, std::uint32_t, unsigned long long,
    std::uint32_t *, unsigned long long *, std::uint32_t *,
    std::uint32_t *, void *);

namespace {

constexpr std::uint32_t kPrime = 0x7fffffffu;

std::uint32_t add(std::uint32_t left, std::uint32_t right) {
    const std::uint64_t sum = std::uint64_t(left) + right;
    return static_cast<std::uint32_t>(sum < kPrime ? sum : sum - kPrime);
}

std::uint32_t sub(std::uint32_t left, std::uint32_t right) {
    return add(left, kPrime - right);
}

std::uint32_t mul(std::uint32_t left, std::uint32_t right) {
    const std::uint64_t product = std::uint64_t(left) * right;
    const std::uint64_t folded = product + (product >> 31);
    return static_cast<std::uint32_t>(
        (product + (folded >> 31)) & kPrime);
}

Qm31 add(Qm31 left, Qm31 right) {
    Qm31 result{};
    for (int index = 0; index < 4; ++index) {
        result.words[index] = add(left.words[index], right.words[index]);
    }
    return result;
}

Qm31 sub(Qm31 left, Qm31 right) {
    Qm31 result{};
    for (int index = 0; index < 4; ++index) {
        result.words[index] = sub(left.words[index], right.words[index]);
    }
    return result;
}

Qm31 scalar_mul(std::uint32_t scalar, Qm31 value) {
    Qm31 result{};
    for (int index = 0; index < 4; ++index) {
        result.words[index] = mul(scalar, value.words[index]);
    }
    return result;
}

Qm31 secure_mul(Qm31 left, Qm31 right) {
    auto complex_mul = [](const std::uint32_t *x, const std::uint32_t *y) {
        return std::array<std::uint32_t, 2>{
            sub(mul(x[0], y[0]), mul(x[1], y[1])),
            add(mul(x[0], y[1]), mul(x[1], y[0])),
        };
    };
    const auto p0 = complex_mul(left.words, right.words);
    const auto p1 = complex_mul(left.words + 2, right.words + 2);
    const std::uint32_t left_sum[2] = {
        add(left.words[0], left.words[2]),
        add(left.words[1], left.words[3]),
    };
    const std::uint32_t right_sum[2] = {
        add(right.words[0], right.words[2]),
        add(right.words[1], right.words[3]),
    };
    const auto ps = complex_mul(left_sum, right_sum);
    Qm31 result{};
    result.words[0] = add(p0[0], sub(add(p1[0], p1[0]), p1[1]));
    result.words[1] = add(p0[1], add(p1[0], add(p1[1], p1[1])));
    result.words[2] = sub(ps[0], add(p0[0], p1[0]));
    result.words[3] = sub(ps[1], add(p0[1], p1[1]));
    return result;
}

Qm31 load(
    const std::vector<std::uint32_t> &slab,
    std::uint32_t stride,
    std::uint32_t index) {
    Qm31 result{};
    for (int coordinate = 0; coordinate < 4; ++coordinate) {
        result.words[coordinate] = slab[coordinate * stride + index];
    }
    return result;
}

void store(
    std::vector<std::uint32_t> &slab,
    std::uint32_t stride,
    std::uint32_t index,
    Qm31 value) {
    for (int coordinate = 0; coordinate < 4; ++coordinate) {
        slab[coordinate * stride + index] = value.words[coordinate];
    }
}

std::uint32_t circle_twiddle(
    const std::vector<std::uint32_t> &domain,
    std::uint32_t offset,
    std::uint32_t index) {
    const std::uint32_t pair = index >> 2;
    switch (index & 3u) {
        case 0: return domain[offset + 2 * pair + 1];
        case 1: return sub(0, domain[offset + 2 * pair + 1]);
        case 2: return sub(0, domain[offset + 2 * pair]);
        default: return domain[offset + 2 * pair];
    }
}

Qm31 fold_pair(Qm31 left, Qm31 right, std::uint32_t twiddle, Qm31 alpha) {
    return add(
        add(left, right),
        secure_mul(alpha, scalar_mul(twiddle, sub(left, right))));
}

Qm31 square_n(Qm31 value, std::uint32_t count) {
    while (count-- != 0) value = secure_mul(value, value);
    return value;
}

std::uint32_t bit_reverse(std::uint32_t value, std::uint32_t bits) {
    std::uint32_t result = 0;
    for (std::uint32_t bit = 0; bit < bits; ++bit) {
        result = (result << 1) | ((value >> bit) & 1u);
    }
    return result;
}

bool check(int status, const char *operation) {
    if (status == 0) return true;
    std::fprintf(
        stderr, "%s: status=%d (%s)\n", operation, status,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

struct Arena {
    void *context = nullptr;
    void *stream = nullptr;
    std::vector<std::uint32_t *> allocations;

    std::uint32_t *allocate(std::size_t words) {
        std::uint32_t *result = nullptr;
        if (!check(
                stwo_exec_context_alloc_u32(context, words, &result),
                "allocate")) {
            return nullptr;
        }
        allocations.push_back(result);
        return result;
    }

    bool upload(void *destination, const void *source, std::size_t bytes) {
        return check(
            stwo_exec_context_memcpy_h2d_async(
                context, destination, source, bytes),
            "upload");
    }

    bool read(void *destination, const void *source, std::size_t bytes) {
        return check(
            stwo_exec_context_memcpy_d2h_async(
                context, destination, source, bytes),
            "read");
    }

    bool close() {
        for (std::uint32_t *pointer : allocations) {
            if (!check(stwo_exec_context_free_u32(context, pointer), "free")) {
                return false;
            }
        }
        return check(stwo_exec_context_sync(context), "wait for frees") &&
            check(stwo_exec_context_destroy(context), "destroy context");
    }
};

bool expect(
    const std::vector<std::uint32_t> &actual,
    const std::vector<std::uint32_t> &expected,
    const char *label) {
    if (actual.size() != expected.size()) return false;
    for (std::size_t index = 0; index < actual.size(); ++index) {
        if (actual[index] != expected[index]) {
            std::fprintf(
                stderr, "%s mismatch at %zu: expected=%08x actual=%08x\n",
                label, index, expected[index], actual[index]);
            return false;
        }
    }
    return true;
}

bool test_folds(Arena &arena) {
    constexpr std::uint32_t size = 32;
    constexpr std::uint32_t source_stride = 35;
    constexpr std::uint32_t fold_stride = 18;
    constexpr std::uint32_t fused_stride = 6;
    constexpr std::uint32_t circle_offset = 3;
    constexpr std::uint32_t line_offset = 20;
    constexpr std::uint32_t final_offset = 40;
    std::vector<std::uint32_t> domain(64);
    std::vector<std::uint32_t> source(4 * source_stride);
    std::vector<std::uint32_t> initial(4 * fold_stride);
    for (std::uint32_t index = 0; index < domain.size(); ++index) {
        domain[index] = 17 * index + 3;
    }
    for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
        for (std::uint32_t row = 0; row < source_stride; ++row) {
            source[coordinate * source_stride + row] =
                1009 * coordinate + 31 * row + 7;
        }
        for (std::uint32_t row = 0; row < fold_stride; ++row) {
            initial[coordinate * fold_stride + row] =
                97 * coordinate + 13 * row + 1;
        }
    }
    const Qm31 alpha{{3, 5, 7, 11}};
    std::vector<std::uint32_t> circle_expected = initial;
    const Qm31 circle_alpha = square_n(alpha, 2);
    for (std::uint32_t row = 0; row < size / 2; ++row) {
        const Qm31 value = fold_pair(
            load(source, source_stride, 2 * row),
            load(source, source_stride, 2 * row + 1),
            circle_twiddle(domain, circle_offset, row),
            circle_alpha);
        store(
            circle_expected, fold_stride, row,
            add(
                secure_mul(
                    secure_mul(circle_alpha, circle_alpha),
                    load(initial, fold_stride, row)),
                value));
    }
    std::vector<std::uint32_t> line_expected(4 * fold_stride);
    const Qm31 line_alpha = square_n(alpha, 1);
    for (std::uint32_t row = 0; row < size / 2; ++row) {
        store(
            line_expected, fold_stride, row,
            fold_pair(
                load(source, source_stride, 2 * row),
                load(source, source_stride, 2 * row + 1),
                domain[line_offset + row],
                line_alpha));
    }

    auto fused_reference = [&](bool first_circle) {
        std::vector<std::uint32_t> output(4 * fused_stride);
        const Qm31 alpha_1 = secure_mul(alpha, alpha);
        const Qm31 alpha_2 = secure_mul(alpha_1, alpha_1);
        for (std::uint32_t row = 0; row < size / 8; ++row) {
            Qm31 stage_0[4];
            for (std::uint32_t pair = 0; pair < 4; ++pair) {
                const std::uint32_t index = 4 * row + pair;
                stage_0[pair] = fold_pair(
                    load(source, source_stride, 2 * index),
                    load(source, source_stride, 2 * index + 1),
                    first_circle
                        ? circle_twiddle(domain, circle_offset, index)
                        : domain[circle_offset + index],
                    alpha);
            }
            Qm31 stage_1[2];
            for (std::uint32_t pair = 0; pair < 2; ++pair) {
                const std::uint32_t index = 2 * row + pair;
                stage_1[pair] = fold_pair(
                    stage_0[2 * pair], stage_0[2 * pair + 1],
                    domain[line_offset + index], alpha_1);
            }
            store(
                output, fused_stride, row,
                fold_pair(
                    stage_1[0], stage_1[1],
                    domain[final_offset + row], alpha_2));
        }
        return output;
    };
    const auto fused_circle_expected = fused_reference(true);
    const auto fused_line_expected = fused_reference(false);

    auto *device_domain = arena.allocate(domain.size());
    auto *device_source = arena.allocate(source.size());
    auto *device_alpha = arena.allocate(4);
    auto *device_circle = arena.allocate(initial.size());
    auto *device_line = arena.allocate(line_expected.size());
    auto *device_fused_circle = arena.allocate(4 * fused_stride);
    auto *device_fused_line = arena.allocate(4 * fused_stride);
    if (device_domain == nullptr || device_source == nullptr ||
        device_alpha == nullptr || device_circle == nullptr ||
        device_line == nullptr || device_fused_circle == nullptr ||
        device_fused_line == nullptr ||
        !arena.upload(device_domain, domain.data(), domain.size() * 4) ||
        !arena.upload(device_source, source.data(), source.size() * 4) ||
        !arena.upload(device_alpha, &alpha, sizeof(alpha)) ||
        !arena.upload(device_circle, initial.data(), initial.size() * 4) ||
        !check(
            stwo_exec_context_fill_u32_async(
                arena.context, device_line, 0, line_expected.size()),
            "clear line output") ||
        !check(
            stwo_exec_context_fill_u32_async(
                arena.context, device_fused_circle, 0, 4 * fused_stride),
            "clear fused circle output") ||
        !check(
            stwo_exec_context_fill_u32_async(
                arena.context, device_fused_line, 0, 4 * fused_stride),
            "clear fused line output")) {
        return false;
    }

    if (!check(
            stwo_fold_circle_into_line_on(
                device_domain, domain.size(), circle_offset, size,
                device_source, source.size(), source_stride,
                reinterpret_cast<Qm31 *>(device_alpha), 2,
                device_circle, initial.size(), fold_stride, arena.stream),
            "circle fold") ||
        !check(
            stwo_fold_line_on(
                device_domain, domain.size(), line_offset, size,
                device_source, source.size(), source_stride,
                reinterpret_cast<Qm31 *>(device_alpha), 1,
                device_line, line_expected.size(), fold_stride, arena.stream),
            "line fold") ||
        !check(
            stwo_fri_fold_fused3_on(
                device_domain, domain.size(), circle_offset, line_offset,
                final_offset, size, 1, device_source, source.size(),
                source_stride, reinterpret_cast<Qm31 *>(device_alpha),
                device_fused_circle, 4 * fused_stride, fused_stride,
                arena.stream),
            "fused circle fold") ||
        !check(
            stwo_fri_fold_fused3_on(
                device_domain, domain.size(), circle_offset, line_offset,
                final_offset, size, 0, device_source, source.size(),
                source_stride, reinterpret_cast<Qm31 *>(device_alpha),
                device_fused_line, 4 * fused_stride, fused_stride,
                arena.stream),
            "fused line fold")) {
        return false;
    }
    if (stwo_fold_line_on(
            device_domain, domain.size(), line_offset, size,
            device_source, source.size() - 1, source_stride,
            reinterpret_cast<Qm31 *>(device_alpha), 0,
            device_line, line_expected.size(), fold_stride,
            arena.stream) == static_cast<int>(cudaSuccess) ||
        stwo_fold_line_on(
            device_domain, domain.size(), line_offset, size,
            device_source, source.size(), source_stride,
            reinterpret_cast<Qm31 *>(device_alpha), 0,
            device_source, source.size(), source_stride,
            arena.stream) == static_cast<int>(cudaSuccess) ||
        stwo_fri_fold_fused3_on(
            device_domain, final_offset + size / 8 - 1, circle_offset,
            line_offset, final_offset, size, 1, device_source, source.size(),
            source_stride, reinterpret_cast<Qm31 *>(device_alpha),
            device_fused_circle, 4 * fused_stride, fused_stride,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "FRI fold accepted invalid capacity or alias\n");
        return false;
    }

    std::vector<std::uint32_t> circle_actual(initial.size());
    std::vector<std::uint32_t> line_actual(line_expected.size());
    std::vector<std::uint32_t> fused_circle_actual(4 * fused_stride);
    std::vector<std::uint32_t> fused_line_actual(4 * fused_stride);
    if (!arena.read(
            circle_actual.data(), device_circle, circle_actual.size() * 4) ||
        !arena.read(line_actual.data(), device_line, line_actual.size() * 4) ||
        !arena.read(
            fused_circle_actual.data(), device_fused_circle,
            fused_circle_actual.size() * 4) ||
        !arena.read(
            fused_line_actual.data(), device_fused_line,
            fused_line_actual.size() * 4) ||
        !check(stwo_exec_context_sync(arena.context), "wait for folds")) {
        return false;
    }
    return expect(circle_actual, circle_expected, "circle fold") &&
        expect(line_actual, line_expected, "line fold") &&
        expect(fused_circle_actual, fused_circle_expected, "fused circle") &&
        expect(fused_line_actual, fused_line_expected, "fused line");
}

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

bool test_final(Arena &arena) {
    constexpr std::uint32_t log_size = 3;
    constexpr std::uint32_t size = 1u << log_size;
    constexpr std::uint32_t stride = 10;
    std::vector<std::uint32_t> evaluation(4 * stride);
    std::vector<std::uint32_t> twiddles(size);
    for (std::uint32_t index = 0; index < evaluation.size(); ++index) {
        evaluation[index] = 19 * index + 5;
    }
    for (std::uint32_t index = 0; index < twiddles.size(); ++index) {
        twiddles[index] = 23 * index + 7;
    }
    const auto coefficient_expected =
        final_reference(evaluation, stride, log_size, twiddles);
    bool full_error = false;
    const auto full_transcript = transcript_coefficients(
        coefficient_expected, log_size, log_size, &full_error);
    bool bounded_error = false;
    const auto bounded_transcript = transcript_coefficients(
        coefficient_expected, log_size, 2, &bounded_error);
    if (full_error || !bounded_error) {
        std::fprintf(stderr, "invalid CPU final-layer test fixture\n");
        return false;
    }

    auto *device_evaluation = arena.allocate(evaluation.size());
    auto *device_twiddles = arena.allocate(twiddles.size());
    auto *device_coefficients = arena.allocate(coefficient_expected.size());
    auto *device_error = arena.allocate(1);
    auto *device_transcript = arena.allocate(full_transcript.size());
    if (device_evaluation == nullptr || device_twiddles == nullptr ||
        device_coefficients == nullptr || device_error == nullptr ||
        device_transcript == nullptr ||
        !arena.upload(
            device_evaluation, evaluation.data(), evaluation.size() * 4) ||
        !arena.upload(
            device_twiddles, twiddles.data(), twiddles.size() * 4) ||
        !check(
            stwo_exec_context_fill_u32_async(
                arena.context, device_error, 123, 1),
            "poison degree error") ||
        !check(
            stwo_fri_last_layer_on(
                device_evaluation, evaluation.size(), stride, log_size,
                device_twiddles, twiddles.size(), log_size,
                device_coefficients, coefficient_expected.size(),
                device_error, 1, device_transcript, full_transcript.size(),
                arena.stream),
            "FRI final full degree")) {
        return false;
    }
    std::vector<std::uint32_t> coefficient_actual(coefficient_expected.size());
    std::vector<std::uint32_t> transcript_actual(full_transcript.size());
    std::uint32_t error_actual = 1;
    if (!arena.read(
            coefficient_actual.data(), device_coefficients,
            coefficient_actual.size() * 4) ||
        !arena.read(
            transcript_actual.data(), device_transcript,
            transcript_actual.size() * 4) ||
        !arena.read(&error_actual, device_error, sizeof(error_actual)) ||
        !check(stwo_exec_context_sync(arena.context), "wait full final")) {
        return false;
    }
    if (error_actual != 0 ||
        !expect(coefficient_actual, coefficient_expected, "FRI coefficients") ||
        !expect(transcript_actual, full_transcript, "FRI full transcript")) {
        return false;
    }

    if (!check(
            stwo_fri_last_layer_on(
                device_evaluation, evaluation.size(), stride, log_size,
                device_twiddles, twiddles.size(), 2,
                device_coefficients, coefficient_expected.size(),
                device_error, 1, device_transcript, bounded_transcript.size(),
                arena.stream),
            "FRI final bounded degree")) {
        return false;
    }
    std::vector<std::uint32_t> bounded_actual(bounded_transcript.size());
    if (!arena.read(
            bounded_actual.data(), device_transcript,
            bounded_actual.size() * 4) ||
        !arena.read(&error_actual, device_error, sizeof(error_actual)) ||
        !check(stwo_exec_context_sync(arena.context), "wait bounded final")) {
        return false;
    }
    if (error_actual != 1 ||
        !expect(bounded_actual, bounded_transcript, "FRI bounded transcript")) {
        return false;
    }
    if (stwo_fri_last_layer_on(
            device_evaluation, evaluation.size(), stride, log_size,
            device_twiddles, twiddles.size(), log_size,
            device_evaluation, coefficient_expected.size(),
            device_error, 1, device_transcript, full_transcript.size(),
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "FRI final accepted aliased coefficient slab\n");
        return false;
    }
    return true;
}

blake2s_reference::Hash pow_prefix(
    const std::array<std::uint32_t, 16> &state,
    std::uint32_t bits) {
    std::vector<std::uint8_t> bytes;
    transcript_reference::append_word(bytes, 0x12345678u);
    bytes.insert(bytes.end(), 12, 0);
    for (int index = 0; index < 8; ++index) {
        transcript_reference::append_word(bytes, state[index]);
    }
    transcript_reference::append_word(bytes, bits);
    return transcript_reference::hash_bytes(bytes);
}

bool valid_pow(
    const blake2s_reference::Hash &prefix,
    std::uint32_t bits,
    std::uint64_t nonce) {
    const auto digest = blake2s_reference::hash_words({
        prefix.words[0], prefix.words[1], prefix.words[2], prefix.words[3],
        prefix.words[4], prefix.words[5], prefix.words[6], prefix.words[7],
        static_cast<std::uint32_t>(nonce),
        static_cast<std::uint32_t>(nonce >> 32),
    });
    const std::uint32_t zeros = digest.words[0] == 0
        ? 32
        : static_cast<std::uint32_t>(__builtin_ctz(digest.words[0]));
    return zeros >= bits;
}

std::uint64_t index_to_nonce(std::uint64_t index) {
    return ((index >> 20) << 32) | (index & ((1ull << 20) - 1));
}

bool test_pow(Arena &arena) {
    constexpr std::uint32_t bits = 10;
    constexpr std::uint64_t search_end = 1ull << 16;
    const std::array<std::uint32_t, 16> state = {
        0x93458da8u, 0xf7b79301u, 0x9b64ee9fu, 0xc65f8fc1u,
        0xf448640cu, 0x8fd2a8b0u, 0xfaf31f8eu, 0x4c63437eu,
        2u, 8u, 0u, 0u, 0x58687888u, 0x18283848u, 0u, 0u,
    };
    const auto expected_prefix = pow_prefix(state, bits);
    std::uint64_t expected_nonce = std::numeric_limits<std::uint64_t>::max();
    for (std::uint64_t index = 0; index < search_end; ++index) {
        const std::uint64_t nonce = index_to_nonce(index);
        if (valid_pow(expected_prefix, bits, nonce)) {
            expected_nonce = nonce;
            break;
        }
    }
    if (expected_nonce == 0 ||
        expected_nonce == std::numeric_limits<std::uint64_t>::max()) {
        std::fprintf(stderr, "invalid deterministic PoW fixture\n");
        return false;
    }

    auto *device_state = arena.allocate(state.size());
    auto *device_prefix = arena.allocate(8);
    auto *device_best_words = arena.allocate(2);
    auto *device_completed = arena.allocate(1);
    auto *device_nonce = arena.allocate(2);
    if (device_state == nullptr || device_prefix == nullptr ||
        device_best_words == nullptr || device_completed == nullptr ||
        device_nonce == nullptr ||
        !arena.upload(device_state, state.data(), sizeof(state)) ||
        !check(
            stwo_blake2s_pow_persistent_on(
                device_state, bits, search_end, device_prefix,
                reinterpret_cast<unsigned long long *>(device_best_words),
                device_completed, device_nonce, arena.stream),
            "bounded persistent PoW")) {
        return false;
    }
    if (stwo_blake2s_pow_persistent_on(
            device_state, bits, 0, device_prefix,
            reinterpret_cast<unsigned long long *>(device_best_words),
            device_completed, device_nonce, arena.stream) ==
            static_cast<int>(cudaSuccess) ||
        stwo_blake2s_pow_persistent_on(
            device_state, bits, search_end, device_prefix,
            reinterpret_cast<unsigned long long *>(device_best_words),
            device_completed, device_prefix, arena.stream) ==
            static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "PoW accepted an invalid bound or alias\n");
        return false;
    }

    std::array<std::uint32_t, 8> actual_prefix{};
    std::array<std::uint32_t, 2> actual_nonce_words{};
    std::uint64_t actual_best = 0;
    std::uint32_t completed = 0;
    if (!arena.read(
            actual_prefix.data(), device_prefix, sizeof(actual_prefix)) ||
        !arena.read(&actual_best, device_best_words, sizeof(actual_best)) ||
        !arena.read(
            actual_nonce_words.data(), device_nonce,
            sizeof(actual_nonce_words)) ||
        !arena.read(&completed, device_completed, sizeof(completed)) ||
        !check(stwo_exec_context_sync(arena.context), "wait for PoW")) {
        return false;
    }
    const std::uint64_t actual_nonce =
        std::uint64_t(actual_nonce_words[0]) |
        (std::uint64_t(actual_nonce_words[1]) << 32);
    std::vector<std::uint32_t> expected_prefix_words(
        expected_prefix.words, expected_prefix.words + 8);
    std::vector<std::uint32_t> actual_prefix_words(
        actual_prefix.begin(), actual_prefix.end());
    if (completed != 1024 || actual_best != expected_nonce ||
        actual_nonce != expected_nonce ||
        !expect(actual_prefix_words, expected_prefix_words, "PoW prefix")) {
        return false;
    }

    constexpr std::uint32_t exhaustion_bits = 32;
    const auto exhaustion_prefix = pow_prefix(state, exhaustion_bits);
    if (valid_pow(exhaustion_prefix, exhaustion_bits, 0) ||
        !check(
            stwo_blake2s_pow_persistent_on(
                device_state, exhaustion_bits, 1, device_prefix,
                reinterpret_cast<unsigned long long *>(device_best_words),
                device_completed, device_nonce, arena.stream),
            "exhausted persistent PoW")) {
        std::fprintf(stderr, "invalid PoW exhaustion fixture\n");
        return false;
    }

    actual_best = 0;
    completed = 0;
    actual_nonce_words = {};
    if (!arena.read(&actual_best, device_best_words, sizeof(actual_best)) ||
        !arena.read(
            actual_nonce_words.data(), device_nonce,
            sizeof(actual_nonce_words)) ||
        !arena.read(&completed, device_completed, sizeof(completed)) ||
        !check(stwo_exec_context_sync(arena.context), "wait exhausted PoW")) {
        return false;
    }
    return completed == 1024 &&
        actual_best == std::numeric_limits<std::uint64_t>::max() &&
        actual_nonce_words[0] == std::numeric_limits<std::uint32_t>::max() &&
        actual_nonce_words[1] == std::numeric_limits<std::uint32_t>::max();
}

}  // namespace

int main() {
    Arena arena;
    if (!check(stwo_exec_context_create(&arena.context), "create context") ||
        !check(
            stwo_exec_context_stream(arena.context, &arena.stream),
            "get proof stream") ||
        !test_folds(arena) || !test_final(arena) || !test_pow(arena) ||
        !arena.close()) {
        return 1;
    }
    std::printf(
        "native CUDA FRI/PoW smoke passed: contiguous folds, final IFFT, "
        "bounded deterministic grind\n");
    return 0;
}
