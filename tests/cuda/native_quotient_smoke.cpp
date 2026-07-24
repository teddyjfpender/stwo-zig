#include "oods_reference.h"

#include <cuda_runtime_api.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

using oods_reference::CM31;
using oods_reference::CirclePoint;
using oods_reference::M31;
using oods_reference::QM31;
using oods_reference::SecureCirclePoint;

struct PreparedTermDescriptor {
    std::uint32_t sample_index;
    std::uint32_t exponent;
    std::uint32_t periodic;
    std::uint32_t period_x;
    std::uint32_t period_y;
};

struct BatchTermDescriptor {
    std::uint32_t source_index;
    std::uint32_t term_index;
    std::uint32_t source_log_size;
};

static_assert(sizeof(PreparedTermDescriptor) == 20);
static_assert(sizeof(BatchTermDescriptor) == 12);

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_sync(void *handle);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle,
    std::size_t count,
    std::uint32_t **out_pointer);
extern "C" int stwo_exec_context_free_u32(
    void *handle,
    std::uint32_t *pointer);
extern "C" int stwo_exec_context_memcpy_h2d_async(
    void *handle,
    void *destination,
    const void *source,
    std::size_t bytes);
extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle,
    void *destination,
    const void *source,
    std::size_t bytes);

extern "C" int stwo_prepare_quotient_numerator_terms_on(
    const PreparedTermDescriptor *term_descriptors,
    std::uint32_t term_count,
    const SecureCirclePoint *sample_points,
    const QM31 *sample_values,
    std::uint32_t sample_count,
    const QM31 *random_coefficient,
    SecureCirclePoint *term_points,
    QM31 *line_coefficients,
    void *stream);
extern "C" int stwo_finalize_quotient_numerator_groups_on(
    const std::uint32_t *group_offsets,
    const std::uint32_t *group_term_indices,
    std::uint32_t group_term_index_count,
    std::uint32_t group_count,
    const SecureCirclePoint *term_points,
    std::uint32_t term_count,
    QM31 *line_coefficients,
    SecureCirclePoint *sample_points,
    QM31 *first_linear_terms,
    void *stream);
extern "C" int stwo_zero_quotient_numerator_outputs_on(
    const std::uint32_t *group_log_sizes,
    std::uint32_t group_count,
    std::uint32_t max_output_size,
    std::uint32_t *output_0,
    std::uint32_t *output_1,
    std::uint32_t *output_2,
    std::uint32_t *output_3,
    std::size_t output_stride_words,
    void *stream);
extern "C" int stwo_accumulate_quotient_numerator_single_write_on(
    const std::uint32_t *group_offsets,
    const BatchTermDescriptor *term_descriptors,
    std::uint32_t term_count,
    std::uint32_t group_count,
    std::uint32_t max_output_size,
    const std::uint32_t *source_evaluations,
    std::size_t source_stride_words,
    std::uint32_t source_count,
    const QM31 *line_coefficients,
    std::uint32_t line_term_count,
    const std::uint32_t *group_log_sizes,
    std::uint32_t *output_0,
    std::uint32_t *output_1,
    std::uint32_t *output_2,
    std::uint32_t *output_3,
    std::size_t output_stride_words,
    void *stream);
extern "C" int stwo_combine_quotients_from_numerators_on(
    std::uint32_t half_coset_initial_index,
    std::uint32_t half_coset_step_size,
    std::uint32_t domain_size,
    std::uint32_t domain_log_size,
    const SecureCirclePoint *sample_points,
    std::uint32_t sample_count,
    const QM31 *first_linear_terms,
    const std::uint32_t *partial_log_sizes,
    const std::uint32_t *partial_0,
    const std::uint32_t *partial_1,
    const std::uint32_t *partial_2,
    const std::uint32_t *partial_3,
    std::size_t partial_stride_words,
    std::uint32_t *result_0,
    std::uint32_t *result_1,
    std::uint32_t *result_2,
    std::uint32_t *result_3,
    void *stream);

namespace {

bool check(int status, const char *operation) {
    if (status == static_cast<int>(cudaSuccess)) return true;
    std::fprintf(
        stderr,
        "%s: %s\n",
        operation,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

bool expect_invalid(int status, const char *operation) {
    if (status == static_cast<int>(cudaErrorInvalidValue)) return true;
    std::fprintf(stderr, "%s did not reject its descriptor\n", operation);
    return false;
}

bool equal(QM31 actual, QM31 expected, const char *label, std::size_t index) {
    if (oods_reference::equal(actual, expected)) return true;
    std::fprintf(stderr, "%s mismatch at %zu\n", label, index);
    return false;
}

struct DeviceArena {
    void *context = nullptr;
    void *stream = nullptr;
    std::vector<std::uint32_t *> allocations;

    bool init() {
        return check(stwo_exec_context_create(&context), "create context") &&
               check(
                   stwo_exec_context_stream(context, &stream),
                   "get proof stream");
    }

    template <typename T>
    T *allocate(std::size_t count) {
        std::uint32_t *pointer = nullptr;
        const std::size_t words =
            (count * sizeof(T) + sizeof(std::uint32_t) - 1) /
            sizeof(std::uint32_t);
        if (!check(
                stwo_exec_context_alloc_u32(context, words, &pointer),
                "allocate resident buffer")) {
            return nullptr;
        }
        allocations.push_back(pointer);
        return reinterpret_cast<T *>(pointer);
    }

    template <typename T>
    bool upload(T *destination, const std::vector<T> &source) {
        return check(
            stwo_exec_context_memcpy_h2d_async(
                context,
                destination,
                source.data(),
                source.size() * sizeof(T)),
            "upload");
    }

    template <typename T>
    bool upload_one(T *destination, const T &source) {
        return check(
            stwo_exec_context_memcpy_h2d_async(
                context,
                destination,
                &source,
                sizeof(T)),
            "upload scalar");
    }

    template <typename T>
    bool read(std::vector<T> *destination, const T *source) {
        return check(
            stwo_exec_context_memcpy_d2h_async(
                context,
                destination->data(),
                source,
                destination->size() * sizeof(T)),
            "download");
    }

    bool sync() { return check(stwo_exec_context_sync(context), "sync"); }

    bool close() {
        for (std::uint32_t *pointer : allocations) {
            if (!check(
                    stwo_exec_context_free_u32(context, pointer),
                    "free resident buffer")) {
                return false;
            }
        }
        return sync() &&
               check(stwo_exec_context_destroy(context), "destroy context");
    }
};

QM31 power(QM31 value, std::uint32_t exponent) {
    QM31 result = oods_reference::one();
    while (exponent != 0) {
        if ((exponent & 1u) != 0) result = oods_reference::mul(result, value);
        value = oods_reference::square(value);
        exponent >>= 1;
    }
    return result;
}

void line_coefficients(
    SecureCirclePoint point,
    QM31 value,
    QM31 alpha,
    QM31 *a,
    QM31 *b,
    QM31 *c) {
    const QM31 value_difference = oods_reference::sub(
        QM31{value.a, oods_reference::neg(value.b)},
        value);
    const QM31 point_difference = oods_reference::sub(
        QM31{point.y.a, oods_reference::neg(point.y.b)},
        point.y);
    const QM31 constant = oods_reference::sub(
        oods_reference::mul(value, point_difference),
        oods_reference::mul(value_difference, point.y));
    *a = oods_reference::mul(alpha, value_difference);
    *b = oods_reference::mul(alpha, constant);
    *c = oods_reference::mul(alpha, point_difference);
}

QM31 coordinate_value(
    const std::vector<std::uint32_t> (&coordinates)[4],
    std::size_t index) {
    return {
        {coordinates[0][index], coordinates[1][index]},
        {coordinates[2][index], coordinates[3][index]},
    };
}

bool test_prepare_and_finalize(DeviceArena &arena) {
    const std::vector<SecureCirclePoint> host_samples{
        {{{3u, 5u}, {7u, 11u}}, {{13u, 17u}, {19u, 23u}}},
        {{{29u, 31u}, {37u, 41u}}, {{43u, 47u}, {53u, 59u}}},
    };
    const std::vector<QM31> host_values{
        {{61u, 67u}, {71u, 73u}},
        {{79u, 83u}, {89u, 97u}},
    };
    const std::vector<PreparedTermDescriptor> descriptors{
        {0u, 1u, 0u, 1u, 0u},
        {1u, 2u, 1u, 2u, 1268011823u},
        {0u, 5u, 1u, 1u, 0u},
    };
    const QM31 random{{101u, 103u}, {107u, 109u}};
    std::vector<SecureCirclePoint> expected_points(3);
    std::vector<QM31> expected_lines(9);
    for (std::size_t term = 0; term < descriptors.size(); ++term) {
        const PreparedTermDescriptor descriptor = descriptors[term];
        SecureCirclePoint point = host_samples[descriptor.sample_index];
        if (descriptor.periodic != 0) {
            point = oods_reference::add_base(
                point,
                {descriptor.period_x, descriptor.period_y});
        }
        expected_points[term] = point;
        line_coefficients(
            point,
            host_values[descriptor.sample_index],
            power(random, descriptor.exponent),
            &expected_lines[3 * term],
            &expected_lines[3 * term + 1],
            &expected_lines[3 * term + 2]);
    }

    auto *device_descriptors =
        arena.allocate<PreparedTermDescriptor>(descriptors.size());
    auto *device_samples =
        arena.allocate<SecureCirclePoint>(host_samples.size());
    auto *device_values = arena.allocate<QM31>(host_values.size());
    auto *device_random = arena.allocate<QM31>(1);
    auto *device_points =
        arena.allocate<SecureCirclePoint>(expected_points.size());
    auto *device_lines = arena.allocate<QM31>(expected_lines.size());
    if (device_descriptors == nullptr || device_samples == nullptr ||
        device_values == nullptr || device_random == nullptr ||
        device_points == nullptr || device_lines == nullptr ||
        !arena.upload(device_descriptors, descriptors) ||
        !arena.upload(device_samples, host_samples) ||
        !arena.upload(device_values, host_values) ||
        !arena.upload_one(device_random, random)) {
        return false;
    }
    if (!check(
            stwo_prepare_quotient_numerator_terms_on(
                device_descriptors,
                descriptors.size(),
                device_samples,
                device_values,
                host_samples.size(),
                device_random,
                device_points,
                device_lines,
                arena.stream),
            "prepare quotient terms")) {
        return false;
    }
    std::vector<SecureCirclePoint> actual_points(expected_points.size());
    std::vector<QM31> actual_lines(expected_lines.size());
    if (!arena.read(&actual_points, device_points) ||
        !arena.read(&actual_lines, device_lines) || !arena.sync()) {
        return false;
    }
    for (std::size_t index = 0; index < expected_points.size(); ++index) {
        if (!oods_reference::equal(actual_points[index], expected_points[index])) {
            std::fprintf(stderr, "prepared point mismatch at %zu\n", index);
            return false;
        }
    }
    for (std::size_t index = 0; index < expected_lines.size(); ++index) {
        if (!equal(actual_lines[index], expected_lines[index], "line", index))
            return false;
    }

    const std::vector<std::uint32_t> offsets{0u, 2u, 3u};
    const std::vector<std::uint32_t> indices{0u, 2u, 1u};
    auto *device_offsets = arena.allocate<std::uint32_t>(offsets.size());
    auto *device_indices = arena.allocate<std::uint32_t>(indices.size());
    auto *group_points = arena.allocate<SecureCirclePoint>(2);
    auto *first_terms = arena.allocate<QM31>(2);
    if (device_offsets == nullptr || device_indices == nullptr ||
        group_points == nullptr || first_terms == nullptr ||
        !arena.upload(device_offsets, offsets) ||
        !arena.upload(device_indices, indices) ||
        !check(
            stwo_finalize_quotient_numerator_groups_on(
                device_offsets,
                device_indices,
                indices.size(),
                2,
                device_points,
                expected_points.size(),
                device_lines,
                group_points,
                first_terms,
                arena.stream),
            "finalize quotient groups")) {
        return false;
    }
    std::vector<SecureCirclePoint> actual_group_points(2);
    std::vector<QM31> actual_first(2);
    if (!arena.read(&actual_group_points, group_points) ||
        !arena.read(&actual_first, first_terms) ||
        !arena.read(&actual_lines, device_lines) || !arena.sync()) {
        return false;
    }
    const QM31 expected_first[] = {
        oods_reference::add(expected_lines[0], expected_lines[6]),
        expected_lines[3],
    };
    const QM31 expected_b[] = {
        oods_reference::add(expected_lines[1], expected_lines[7]),
        expected_lines[4],
    };
    if (!oods_reference::equal(actual_group_points[0], expected_points[0]) ||
        !oods_reference::equal(actual_group_points[1], expected_points[1]) ||
        !equal(actual_first[0], expected_first[0], "first term", 0) ||
        !equal(actual_first[1], expected_first[1], "first term", 1) ||
        !equal(actual_lines[0], expected_b[0], "group B", 0) ||
        !equal(actual_lines[3], expected_b[1], "group B", 1)) {
        return false;
    }

    return expect_invalid(
               stwo_prepare_quotient_numerator_terms_on(
                   device_descriptors,
                   descriptors.size(),
                   device_samples,
                   device_values,
                   0,
                   device_random,
                   device_points,
                   device_lines,
                   arena.stream),
               "prepare sample bound") &&
           expect_invalid(
               stwo_prepare_quotient_numerator_terms_on(
                   device_descriptors,
                   descriptors.size(),
                   device_samples,
                   device_values,
                   host_samples.size(),
                   device_random,
                   reinterpret_cast<SecureCirclePoint *>(device_lines),
                   device_lines,
                   arena.stream),
               "prepare output alias") &&
           expect_invalid(
               stwo_finalize_quotient_numerator_groups_on(
                   device_offsets,
                   device_indices,
                   0,
                   2,
                   device_points,
                   expected_points.size(),
                   device_lines,
                   group_points,
                   first_terms,
                   arena.stream),
               "finalize index bound") &&
           expect_invalid(
               stwo_finalize_quotient_numerator_groups_on(
                   device_offsets,
                   device_indices,
                   indices.size(),
                   2,
                   device_points,
                   expected_points.size(),
                   device_lines,
                   device_points,
                   first_terms,
                   arena.stream),
               "finalize input alias");
}

bool test_zero_and_accumulate(DeviceArena &arena) {
    constexpr std::uint32_t group_count = 2;
    constexpr std::uint32_t max_output = 16;
    constexpr std::size_t output_stride = 19;
    constexpr std::size_t output_words = group_count * output_stride;
    constexpr std::uint32_t sentinel = 0xdeadbeefu;
    const std::vector<std::uint32_t> logs{3u, 4u};
    auto *device_logs = arena.allocate<std::uint32_t>(logs.size());
    std::uint32_t *outputs[4];
    std::vector<std::uint32_t> initial(output_words, sentinel);
    if (device_logs == nullptr || !arena.upload(device_logs, logs)) return false;
    for (auto &output : outputs) {
        output = arena.allocate<std::uint32_t>(output_words);
        if (output == nullptr || !arena.upload(output, initial)) return false;
    }
    if (!check(
            stwo_zero_quotient_numerator_outputs_on(
                device_logs,
                group_count,
                max_output,
                outputs[0],
                outputs[1],
                outputs[2],
                outputs[3],
                output_stride,
                arena.stream),
            "zero quotient numerators")) {
        return false;
    }
    std::vector<std::uint32_t> actual_zero[4]{
        initial, initial, initial, initial};
    for (int coordinate = 0; coordinate < 4; ++coordinate) {
        if (!arena.read(&actual_zero[coordinate], outputs[coordinate]))
            return false;
    }
    if (!arena.sync()) return false;
    for (int coordinate = 0; coordinate < 4; ++coordinate) {
        for (std::size_t index = 0; index < output_words; ++index) {
            const std::size_t group = index / output_stride;
            const std::size_t row = index % output_stride;
            const std::uint32_t expected =
                row < (1u << logs[group]) ? 0u : sentinel;
            if (actual_zero[coordinate][index] != expected) {
                std::fprintf(stderr, "zero mismatch at %zu\n", index);
                return false;
            }
        }
    }

    constexpr std::size_t source_stride = 16;
    const std::vector<std::uint32_t> source{
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
        61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
    };
    const std::vector<std::uint32_t> offsets{0u, 2u, 3u};
    const std::vector<BatchTermDescriptor> descriptors{
        {0u, 0u, 3u},
        {1u, 1u, 2u},
        {0u, 2u, 3u},
    };
    const std::vector<QM31> lines{
        {{1, 2}, {3, 4}}, {{5, 7}, {11, 13}}, {{17, 19}, {23, 29}},
        {{31, 37}, {41, 43}}, {{47, 53}, {59, 61}}, {{67, 71}, {73, 79}},
        {{83, 89}, {97, 101}}, {{103, 107}, {109, 113}}, {{127, 131}, {137, 139}},
    };
    auto *device_source = arena.allocate<std::uint32_t>(source.size());
    auto *device_offsets = arena.allocate<std::uint32_t>(offsets.size());
    auto *device_descriptors =
        arena.allocate<BatchTermDescriptor>(descriptors.size());
    auto *device_lines = arena.allocate<QM31>(lines.size());
    if (device_source == nullptr || device_offsets == nullptr ||
        device_descriptors == nullptr || device_lines == nullptr ||
        !arena.upload(device_source, source) ||
        !arena.upload(device_offsets, offsets) ||
        !arena.upload(device_descriptors, descriptors) ||
        !arena.upload(device_lines, lines) ||
        !check(
            stwo_accumulate_quotient_numerator_single_write_on(
                device_offsets,
                device_descriptors,
                descriptors.size(),
                group_count,
                max_output,
                device_source,
                source_stride,
                2,
                device_lines,
                3,
                device_logs,
                outputs[0],
                outputs[1],
                outputs[2],
                outputs[3],
                output_stride,
                arena.stream),
            "accumulate quotient numerators")) {
        return false;
    }
    std::vector<std::uint32_t> actual[4]{initial, initial, initial, initial};
    for (int coordinate = 0; coordinate < 4; ++coordinate) {
        if (!arena.read(&actual[coordinate], outputs[coordinate])) return false;
    }
    if (!arena.sync()) return false;
    for (std::uint32_t group = 0; group < group_count; ++group) {
        for (std::uint32_t row = 0; row < (1u << logs[group]); ++row) {
            QM31 expected = oods_reference::zero();
            for (std::uint32_t index = offsets[group];
                 index < offsets[group + 1];
                 ++index) {
                const BatchTermDescriptor descriptor = descriptors[index];
                const std::uint32_t ratio =
                    logs[group] - descriptor.source_log_size;
                const std::uint32_t source_row =
                    (row >> (ratio + 1) << 1) + (row & 1u);
                expected = oods_reference::add(
                    expected,
                    oods_reference::sub(
                        oods_reference::mul(
                            source[descriptor.source_index * source_stride +
                                   source_row],
                            lines[descriptor.term_index * 3 + 2]),
                        lines[descriptor.term_index * 3 + 1]));
            }
            const std::size_t output_index = group * output_stride + row;
            if (!equal(
                    coordinate_value(actual, output_index),
                    expected,
                    "numerator",
                    output_index)) {
                return false;
            }
        }
    }
    return expect_invalid(
               stwo_zero_quotient_numerator_outputs_on(
                   device_logs,
                   group_count,
                   max_output,
                   outputs[0],
                   outputs[1],
                   outputs[2],
                   outputs[3],
                   max_output - 1,
                   arena.stream),
               "zero output bound") &&
           expect_invalid(
               stwo_zero_quotient_numerator_outputs_on(
                   device_logs,
                   group_count,
                   max_output,
                   outputs[0],
                   outputs[0],
                   outputs[2],
                   outputs[3],
                   output_stride,
                   arena.stream),
               "zero output alias") &&
           expect_invalid(
               stwo_accumulate_quotient_numerator_single_write_on(
                   device_offsets,
                   device_descriptors,
                   descriptors.size(),
                   group_count,
                   max_output,
                   device_source,
                   0,
                   2,
                   device_lines,
                   3,
                   device_logs,
                   outputs[0],
                   outputs[1],
                   outputs[2],
                   outputs[3],
                   output_stride,
                   arena.stream),
               "accumulate source bound") &&
           expect_invalid(
               stwo_accumulate_quotient_numerator_single_write_on(
                   device_offsets,
                   device_descriptors,
                   descriptors.size(),
                   group_count,
                   max_output,
                   device_source,
                   source_stride,
                   2,
                   device_lines,
                   3,
                   device_logs,
                   device_source,
                   outputs[1],
                   outputs[2],
                   outputs[3],
                   output_stride,
                   arena.stream),
               "accumulate source alias");
}

CM31 denominator(SecureCirclePoint sample, CirclePoint domain) {
    return oods_reference::sub(
        oods_reference::mul(
            CM31{oods_reference::sub(sample.x.a.a, domain.x), sample.x.a.b},
            sample.y.b),
        oods_reference::mul(
            CM31{oods_reference::sub(sample.y.a.a, domain.y), sample.y.a.b},
            sample.x.b));
}

bool test_combine(DeviceArena &arena) {
    constexpr std::uint32_t domain_log = 4;
    constexpr std::uint32_t domain_size = 1u << domain_log;
    constexpr std::size_t partial_stride = 19;
    const std::vector<SecureCirclePoint> samples{
        {{{3u, 5u}, {7u, 11u}}, {{13u, 17u}, {19u, 23u}}},
        {{{29u, 31u}, {37u, 41u}}, {{43u, 47u}, {53u, 59u}}},
    };
    const std::vector<QM31> first{
        {{61u, 67u}, {71u, 73u}},
        {{79u, 83u}, {89u, 97u}},
    };
    const std::vector<std::uint32_t> logs{3u, 4u};
    std::vector<std::uint32_t> partials[4];
    for (int coordinate = 0; coordinate < 4; ++coordinate) {
        partials[coordinate].resize(samples.size() * partial_stride);
        for (std::size_t index = 0; index < partials[coordinate].size(); ++index) {
            partials[coordinate][index] =
                (17u * coordinate + 13u * index + 7u) %
                oods_reference::prime;
        }
    }
    std::vector<std::uint32_t> expected[4];
    for (auto &coordinate : expected) coordinate.resize(domain_size);
    for (std::uint32_t row = 0; row < domain_size; ++row) {
        const CirclePoint domain = oods_reference::domain_at_index(
            3u,
            7u,
            oods_reference::bit_reverse(row, domain_log),
            domain_size);
        QM31 quotient = oods_reference::zero();
        for (std::size_t sample = 0; sample < samples.size(); ++sample) {
            const std::uint32_t ratio = domain_log - logs[sample];
            const std::uint32_t lifted =
                (row >> (ratio + 1) << 1) + (row & 1u);
            const std::size_t index = sample * partial_stride + lifted;
            const QM31 partial = coordinate_value(partials, index);
            const QM31 full = oods_reference::sub(
                partial,
                oods_reference::mul(domain.y, first[sample]));
            const CM31 inverse =
                oods_reference::inverse(denominator(samples[sample], domain));
            quotient = oods_reference::add(
                quotient,
                oods_reference::mul(
                    full,
                    QM31{inverse, CM31{0u, 0u}}));
        }
        expected[0][row] = quotient.a.a;
        expected[1][row] = quotient.a.b;
        expected[2][row] = quotient.b.a;
        expected[3][row] = quotient.b.b;
    }

    auto *device_samples = arena.allocate<SecureCirclePoint>(samples.size());
    auto *device_first = arena.allocate<QM31>(first.size());
    auto *device_logs = arena.allocate<std::uint32_t>(logs.size());
    std::uint32_t *device_partials[4];
    std::uint32_t *device_results[4];
    if (device_samples == nullptr || device_first == nullptr ||
        device_logs == nullptr || !arena.upload(device_samples, samples) ||
        !arena.upload(device_first, first) ||
        !arena.upload(device_logs, logs)) {
        return false;
    }
    for (int coordinate = 0; coordinate < 4; ++coordinate) {
        device_partials[coordinate] =
            arena.allocate<std::uint32_t>(partials[coordinate].size());
        device_results[coordinate] =
            arena.allocate<std::uint32_t>(domain_size);
        if (device_partials[coordinate] == nullptr ||
            device_results[coordinate] == nullptr ||
            !arena.upload(device_partials[coordinate], partials[coordinate])) {
            return false;
        }
    }
    if (!check(
            stwo_combine_quotients_from_numerators_on(
                3u,
                7u,
                domain_size,
                domain_log,
                device_samples,
                samples.size(),
                device_first,
                device_logs,
                device_partials[0],
                device_partials[1],
                device_partials[2],
                device_partials[3],
                partial_stride,
                device_results[0],
                device_results[1],
                device_results[2],
                device_results[3],
                arena.stream),
            "combine quotients")) {
        return false;
    }
    std::vector<std::uint32_t> actual[4];
    for (int coordinate = 0; coordinate < 4; ++coordinate) {
        actual[coordinate].resize(domain_size);
        if (!arena.read(&actual[coordinate], device_results[coordinate]))
            return false;
    }
    if (!arena.sync()) return false;
    for (int coordinate = 0; coordinate < 4; ++coordinate) {
        if (actual[coordinate] != expected[coordinate]) {
            std::fprintf(stderr, "combined coordinate %d mismatch\n", coordinate);
            return false;
        }
    }
    return expect_invalid(
               stwo_combine_quotients_from_numerators_on(
                   3u,
                   7u,
                   domain_size - 1,
                   domain_log,
                   device_samples,
                   samples.size(),
                   device_first,
                   device_logs,
                   device_partials[0],
                   device_partials[1],
                   device_partials[2],
                   device_partials[3],
                   partial_stride,
                   device_results[0],
                   device_results[1],
                   device_results[2],
                   device_results[3],
                   arena.stream),
               "combine domain bound") &&
           expect_invalid(
               stwo_combine_quotients_from_numerators_on(
                   3u,
                   7u,
                   domain_size,
                   domain_log,
                   device_samples,
                   samples.size(),
                   device_first,
                   device_logs,
                   device_partials[0],
                   device_partials[1],
                   device_partials[2],
                   device_partials[3],
                   partial_stride,
                   device_partials[0],
                   device_results[1],
                   device_results[2],
                   device_results[3],
                   arena.stream),
               "combine partial alias");
}

}  // namespace

int main() {
    DeviceArena arena;
    if (!arena.init()) return 1;
    const bool passed =
        test_prepare_and_finalize(arena) &&
        test_zero_and_accumulate(arena) &&
        test_combine(arena);
    if (!arena.close() || !passed) return 1;
    std::puts(
        "Native CUDA quotient smoke passed: five resident stages match "
        "independent CPU references and reject invalid ranges");
    return 0;
}
