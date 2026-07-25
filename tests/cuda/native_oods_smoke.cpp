#include "oods_reference.h"

#include <cuda_runtime_api.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

using oods_reference::CirclePoint;
using oods_reference::M31;
using oods_reference::QM31;
using oods_reference::SecureCirclePoint;

static_assert(sizeof(QM31) == 16);
static_assert(sizeof(SecureCirclePoint) == 32);

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_sync(void *handle);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle, std::size_t count, std::uint32_t **out_pointer);
extern "C" int stwo_exec_context_free_u32(
    void *handle, std::uint32_t *pointer);
extern "C" int stwo_exec_context_memcpy_h2d_async(
    void *handle, void *destination, const void *source, std::size_t bytes);
extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle, void *destination, const void *source, std::size_t bytes);

extern "C" int stwo_oods_derive_points_on(
    const QM31 *oods_parameter,
    const CirclePoint *offset_points,
    const std::uint32_t *fold_counts,
    const std::uint32_t *output_indices,
    std::uint32_t sample_count,
    std::uint32_t coefficient_log_size,
    SecureCirclePoint *sample_points,
    std::size_t sample_point_capacity,
    SecureCirclePoint *evaluation_points,
    QM31 *folding_factors,
    void *stream);
extern "C" int stwo_oods_eval_first_on(
    const M31 *coefficients,
    std::size_t column_stride_words,
    std::uint32_t coefficient_size,
    std::uint32_t sample_count,
    const QM31 *folding_factors,
    QM31 *scratch,
    void *stream);
extern "C" int stwo_oods_eval_reduce_on(
    const QM31 *input,
    std::uint32_t input_size,
    std::uint32_t input_stride,
    std::uint32_t factor_index,
    std::uint32_t coefficient_log_size,
    std::uint32_t sample_count,
    const QM31 *folding_factors,
    QM31 *output,
    std::uint32_t output_stride,
    void *stream);
extern "C" int stwo_oods_store_results_on(
    const QM31 *reduced,
    std::uint32_t reduced_stride,
    const std::uint32_t *output_indices,
    std::uint32_t sample_count,
    QM31 *sampled_values,
    std::size_t sampled_value_capacity,
    void *stream);
extern "C" int stwo_oods_barycentric_weights_on(
    std::uint32_t half_coset_initial_index,
    std::uint32_t half_coset_step_size,
    std::uint32_t size,
    std::uint32_t log_size,
    const SecureCirclePoint *evaluation_point,
    QM31 si0,
    CirclePoint vanishing_rotation,
    QM31 *numerator_inverses,
    QM31 *weights,
    QM31 *scales,
    void *stream);
extern "C" int stwo_oods_barycentric_eval_many_on(
    const M31 *columns,
    std::size_t column_stride_words,
    std::uint32_t column_count,
    const QM31 *weights,
    std::uint32_t size,
    QM31 *partial_sums,
    std::uint32_t reduction_blocks,
    const std::uint32_t *output_indices,
    QM31 *sampled_values,
    std::size_t sampled_value_capacity,
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
    std::fprintf(stderr, "%s did not reject its invalid descriptor\n", operation);
    return false;
}

bool expect_equal(
    QM31 actual,
    QM31 expected,
    const char *operation,
    std::size_t index) {
    if (oods_reference::equal(actual, expected)) return true;
    std::fprintf(stderr, "%s mismatch at %zu\n", operation, index);
    return false;
}

bool expect_equal(
    SecureCirclePoint actual,
    SecureCirclePoint expected,
    const char *operation,
    std::size_t index) {
    if (oods_reference::equal(actual, expected)) return true;
    std::fprintf(stderr, "%s mismatch at %zu\n", operation, index);
    return false;
}

struct DeviceArena {
    void *context = nullptr;
    void *stream = nullptr;
    std::vector<std::uint32_t *> allocations;

    template <typename T>
    T *allocate(std::size_t count) {
        const std::size_t bytes = count * sizeof(T);
        std::uint32_t *pointer = nullptr;
        if (!check(
                stwo_exec_context_alloc_u32(
                    context, (bytes + sizeof(std::uint32_t) - 1) / 4, &pointer),
                "allocate")) {
            return nullptr;
        }
        allocations.push_back(pointer);
        return reinterpret_cast<T *>(pointer);
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

    bool sync() {
        return check(stwo_exec_context_sync(context), "sync");
    }

    bool close() {
        for (std::uint32_t *pointer : allocations) {
            if (!check(stwo_exec_context_free_u32(context, pointer), "free")) {
                return false;
            }
        }
        return sync() &&
               check(stwo_exec_context_destroy(context), "destroy context");
    }
};

struct EvaluationFixture {
    static constexpr std::uint32_t sample_count = 3;
    static constexpr std::uint32_t coefficient_log_size = 13;
    static constexpr std::uint32_t coefficient_size =
        1u << coefficient_log_size;
    static constexpr std::uint32_t first_coefficients_per_block = 4096;
    static constexpr std::uint32_t first_pass_size =
        coefficient_size / first_coefficients_per_block;
    static_assert(first_pass_size == 2);

    QM31 parameter{{7u, 2u}, {3u, 4u}};
    std::vector<CirclePoint> offsets{
        {1u, 0u},
        oods_reference::circle_generator,
        oods_reference::point_pow(oods_reference::circle_generator, 5u),
    };
    std::vector<std::uint32_t> fold_counts{0u, 1u, 47u};
    std::vector<std::uint32_t> output_indices{2u, 0u, 1u};
    std::vector<std::vector<M31>> coefficients;
    std::vector<SecureCirclePoint> sample_points;
    std::vector<SecureCirclePoint> evaluation_points;
    std::vector<QM31> factors;
    std::vector<QM31> evaluations;

    EvaluationFixture()
        : coefficients(
              sample_count,
              std::vector<M31>(coefficient_size)),
          sample_points(sample_count),
          evaluation_points(sample_count),
          factors(sample_count * coefficient_log_size),
          evaluations(sample_count) {
        for (std::uint32_t sample = 0; sample < sample_count; ++sample) {
            SecureCirclePoint point =
                oods_reference::derive_point(parameter, offsets[sample]);
            sample_points[output_indices[sample]] = point;
            const std::uint32_t folds =
                std::min(fold_counts[sample], 31u);
            for (std::uint32_t fold = 0; fold < folds; ++fold) {
                point = oods_reference::double_point(point);
            }
            evaluation_points[sample] = point;
            const std::vector<QM31> sample_factors =
                oods_reference::folding_factors(
                    point, coefficient_log_size);
            for (std::uint32_t index = 0;
                 index < coefficient_log_size;
                 ++index) {
                factors[sample * coefficient_log_size + index] =
                    sample_factors[index];
            }
            for (std::uint32_t index = 0; index < coefficient_size; ++index) {
                coefficients[sample][index] =
                    (97u * sample + 13u * index + 11u) %
                    oods_reference::prime;
            }
            evaluations[sample] = oods_reference::evaluate(
                coefficients[sample], sample_factors);
        }
    }
};

bool test_evaluation(
    DeviceArena &arena,
    const EvaluationFixture &fixture) {
    auto *parameter = arena.allocate<QM31>(1);
    auto *offsets = arena.allocate<CirclePoint>(fixture.sample_count);
    auto *fold_counts = arena.allocate<std::uint32_t>(fixture.sample_count);
    auto *output_indices = arena.allocate<std::uint32_t>(fixture.sample_count);
    auto *sample_points =
        arena.allocate<SecureCirclePoint>(fixture.sample_count);
    auto *evaluation_points =
        arena.allocate<SecureCirclePoint>(fixture.sample_count);
    auto *factors = arena.allocate<QM31>(
        fixture.sample_count * fixture.coefficient_log_size);
    if (parameter == nullptr || offsets == nullptr || fold_counts == nullptr ||
        output_indices == nullptr || sample_points == nullptr ||
        evaluation_points == nullptr || factors == nullptr ||
        !arena.upload(parameter, &fixture.parameter, sizeof(fixture.parameter)) ||
        !arena.upload(
            offsets, fixture.offsets.data(),
            fixture.offsets.size() * sizeof(CirclePoint)) ||
        !arena.upload(
            fold_counts, fixture.fold_counts.data(),
            fixture.fold_counts.size() * sizeof(std::uint32_t)) ||
        !arena.upload(
            output_indices, fixture.output_indices.data(),
            fixture.output_indices.size() * sizeof(std::uint32_t))) {
        return false;
    }
    if (!check(
            stwo_oods_derive_points_on(
                parameter,
                offsets,
                fold_counts,
                output_indices,
                fixture.sample_count,
                fixture.coefficient_log_size,
                sample_points,
                fixture.sample_count,
                evaluation_points,
                factors,
                arena.stream),
            "derive points")) {
        return false;
    }

    constexpr std::size_t column_stride =
        EvaluationFixture::coefficient_size + 7;
    std::vector<M31> coefficient_slab(
        fixture.sample_count * column_stride);
    for (std::uint32_t sample = 0; sample < fixture.sample_count; ++sample) {
        std::copy(
            fixture.coefficients[sample].begin(),
            fixture.coefficients[sample].end(),
            coefficient_slab.begin() + sample * column_stride);
    }
    auto *device_coefficients =
        arena.allocate<M31>(coefficient_slab.size());
    auto *scratch = arena.allocate<QM31>(
        fixture.sample_count * fixture.first_pass_size);
    auto *reduced = arena.allocate<QM31>(fixture.sample_count);
    auto *sampled = arena.allocate<QM31>(fixture.sample_count);
    if (device_coefficients == nullptr || scratch == nullptr ||
        reduced == nullptr ||
        sampled == nullptr ||
        !arena.upload(
            device_coefficients,
            coefficient_slab.data(),
            coefficient_slab.size() * sizeof(M31)) ||
        !check(
            stwo_oods_eval_first_on(
                device_coefficients,
                column_stride,
                fixture.coefficient_size,
                fixture.sample_count,
                factors,
                scratch,
                arena.stream),
            "evaluate first") ||
        !check(
            stwo_oods_eval_reduce_on(
                scratch,
                fixture.first_pass_size,
                fixture.first_pass_size,
                0,
                fixture.coefficient_log_size,
                fixture.sample_count,
                factors,
                reduced,
                1,
                arena.stream),
            "evaluate reduce") ||
        !check(
            stwo_oods_store_results_on(
                reduced,
                1,
                output_indices,
                fixture.sample_count,
                sampled,
                fixture.sample_count,
                arena.stream),
            "store results")) {
        return false;
    }

    std::vector<SecureCirclePoint> actual_samples(fixture.sample_count);
    std::vector<SecureCirclePoint> actual_evaluation_points(
        fixture.sample_count);
    std::vector<QM31> actual_factors(
        fixture.sample_count * fixture.coefficient_log_size);
    std::vector<QM31> actual_sampled(fixture.sample_count);
    if (!arena.read(
            actual_samples.data(),
            sample_points,
            actual_samples.size() * sizeof(SecureCirclePoint)) ||
        !arena.read(
            actual_evaluation_points.data(),
            evaluation_points,
            actual_evaluation_points.size() * sizeof(SecureCirclePoint)) ||
        !arena.read(
            actual_factors.data(),
            factors,
            actual_factors.size() * sizeof(QM31)) ||
        !arena.read(
            actual_sampled.data(),
            sampled,
            actual_sampled.size() * sizeof(QM31)) ||
        !arena.sync()) {
        return false;
    }
    for (std::size_t index = 0; index < fixture.sample_count; ++index) {
        if (!expect_equal(
                actual_samples[index],
                fixture.sample_points[index],
                "sample point",
                index) ||
            !expect_equal(
                actual_evaluation_points[index],
                fixture.evaluation_points[index],
                "evaluation point",
                index)) {
            return false;
        }
    }
    for (std::size_t index = 0; index < actual_factors.size(); ++index) {
        if (!expect_equal(
                actual_factors[index],
                fixture.factors[index],
                "folding factor",
                index)) {
            return false;
        }
    }
    for (std::size_t sample = 0; sample < fixture.sample_count; ++sample) {
        if (!expect_equal(
                actual_sampled[fixture.output_indices[sample]],
                fixture.evaluations[sample],
                "sampled value",
                sample)) {
            return false;
        }
    }
    return true;
}

bool test_barycentric(
    DeviceArena &arena,
    const EvaluationFixture &fixture) {
    constexpr std::uint32_t log_size = 3;
    constexpr std::uint32_t size = 1u << log_size;
    constexpr std::uint32_t initial = 37;
    constexpr std::uint32_t step = 1u << (31 - log_size);
    const QM31 si0{{19u, 5u}, {2u, 9u}};
    const CirclePoint rotation =
        oods_reference::point_pow(oods_reference::circle_generator, 7u);
    const SecureCirclePoint point = fixture.evaluation_points[1];

    auto *device_point = arena.allocate<SecureCirclePoint>(1);
    auto *numerators = arena.allocate<QM31>(size);
    auto *weights = arena.allocate<QM31>(size);
    auto *scales = arena.allocate<QM31>(2);
    if (device_point == nullptr || numerators == nullptr ||
        weights == nullptr || scales == nullptr ||
        !arena.upload(device_point, &point, sizeof(point))) {
        return false;
    }
    if (!expect_invalid(
            stwo_oods_barycentric_weights_on(
                initial,
                step,
                size,
                log_size,
                device_point,
                si0,
                rotation,
                numerators,
                numerators,
                scales,
                arena.stream),
            "valid-shape barycentric alias") ||
        !check(
            stwo_oods_barycentric_weights_on(
                initial,
                step,
                size,
                log_size,
                device_point,
                si0,
                rotation,
                numerators,
                weights,
                scales,
                arena.stream),
            "barycentric weights")) {
        return false;
    }

    SecureCirclePoint rotated = oods_reference::add_base(point, rotation);
    QM31 vanishing = rotated.x;
    for (std::uint32_t index = 1; index < log_size; ++index) {
        vanishing = oods_reference::sub(
            oods_reference::add(
                oods_reference::square(vanishing),
                oods_reference::square(vanishing)),
            oods_reference::one());
    }
    const std::vector<QM31> expected_scales{
        oods_reference::mul(si0, vanishing),
        oods_reference::sub(
            oods_reference::zero(),
            oods_reference::mul(si0, vanishing)),
    };
    std::vector<QM31> expected_numerators(size);
    std::vector<QM31> expected_weights(size);
    for (std::uint32_t index = 0; index < size; ++index) {
        const CirclePoint domain = oods_reference::domain_at_index(
            initial,
            step,
            oods_reference::bit_reverse(index, log_size),
            size);
        const QM31 hx = oods_reference::add(
            oods_reference::mul(domain.x, point.x),
            oods_reference::mul(domain.y, point.y));
        const QM31 hy = oods_reference::sub(
            oods_reference::mul(domain.x, point.y),
            oods_reference::mul(domain.y, point.x));
        expected_numerators[index] = oods_reference::inverse(hy);
        expected_weights[index] = oods_reference::mul(
            oods_reference::mul(
                oods_reference::add(oods_reference::one(), hx),
                expected_numerators[index]),
            expected_scales[index & 1u]);
    }

    std::vector<QM31> actual_numerators(size);
    std::vector<QM31> actual_weights(size);
    std::vector<QM31> actual_scales(2);
    if (!arena.read(
            actual_numerators.data(),
            numerators,
            size * sizeof(QM31)) ||
        !arena.read(actual_weights.data(), weights, size * sizeof(QM31)) ||
        !arena.read(actual_scales.data(), scales, 2 * sizeof(QM31)) ||
        !arena.sync()) {
        return false;
    }
    for (std::uint32_t index = 0; index < size; ++index) {
        if (!expect_equal(
                actual_numerators[index],
                expected_numerators[index],
                "barycentric inverse",
                index) ||
            !expect_equal(
                actual_weights[index],
                expected_weights[index],
                "barycentric weight",
                index)) {
            return false;
        }
    }
    for (std::uint32_t index = 0; index < 2; ++index) {
        if (!expect_equal(
                actual_scales[index],
                expected_scales[index],
                "barycentric scale",
                index)) {
            return false;
        }
    }

    constexpr std::uint32_t large_log_size = 10;
    constexpr std::uint32_t large_size = 1u << large_log_size;
    constexpr std::uint32_t large_step = 1u << (31 - large_log_size);
    auto *large_numerators = arena.allocate<QM31>(large_size);
    auto *large_weights = arena.allocate<QM31>(large_size);
    auto *large_scales = arena.allocate<QM31>(2);
    if (large_numerators == nullptr || large_weights == nullptr ||
        large_scales == nullptr ||
        !check(
            stwo_oods_barycentric_weights_on(
                initial,
                large_step,
                large_size,
                large_log_size,
                device_point,
                si0,
                rotation,
                large_numerators,
                large_weights,
                large_scales,
                arena.stream),
            "large barycentric weights")) {
        return false;
    }
    std::vector<QM31> actual_large_numerators(large_size);
    std::vector<QM31> actual_large_weights(large_size);
    if (!arena.read(
            actual_large_numerators.data(),
            large_numerators,
            large_size * sizeof(QM31)) ||
        !arena.read(
            actual_large_weights.data(),
            large_weights,
            large_size * sizeof(QM31)) ||
        !arena.sync()) {
        return false;
    }
    SecureCirclePoint large_rotated =
        oods_reference::add_base(point, rotation);
    QM31 large_vanishing = large_rotated.x;
    for (std::uint32_t index = 1; index < large_log_size; ++index) {
        large_vanishing = oods_reference::sub(
            oods_reference::add(
                oods_reference::square(large_vanishing),
                oods_reference::square(large_vanishing)),
            oods_reference::one());
    }
    const QM31 large_scale =
        oods_reference::mul(si0, large_vanishing);
    for (std::uint32_t index = 0; index < large_size; ++index) {
        const CirclePoint domain = oods_reference::domain_at_index(
            initial,
            large_step,
            oods_reference::bit_reverse(index, large_log_size),
            large_size);
        const QM31 hx = oods_reference::add(
            oods_reference::mul(domain.x, point.x),
            oods_reference::mul(domain.y, point.y));
        const QM31 hy = oods_reference::sub(
            oods_reference::mul(domain.x, point.y),
            oods_reference::mul(domain.y, point.x));
        const QM31 inverse = oods_reference::inverse(hy);
        const QM31 scale = (index & 1u) == 0
                               ? large_scale
                               : oods_reference::sub(
                                     oods_reference::zero(), large_scale);
        const QM31 weight = oods_reference::mul(
            oods_reference::mul(
                oods_reference::add(oods_reference::one(), hx), inverse),
            scale);
        if (!expect_equal(
                actual_large_numerators[index],
                inverse,
                "large barycentric inverse",
                index) ||
            !expect_equal(
                actual_large_weights[index],
                weight,
                "large barycentric weight",
                index)) {
            return false;
        }
    }

    constexpr std::uint32_t column_count = 2;
    constexpr std::uint32_t reduction_blocks = 3;
    constexpr std::size_t column_stride = size + 3;
    std::vector<std::vector<M31>> columns(
        column_count, std::vector<M31>(size));
    std::vector<M31> column_slab(column_count * column_stride);
    for (std::uint32_t column = 0; column < column_count; ++column) {
        for (std::uint32_t row = 0; row < size; ++row) {
            columns[column][row] = 41u * column + 17u * row + 3u;
        }
        std::copy(
            columns[column].begin(),
            columns[column].end(),
            column_slab.begin() + column * column_stride);
    }
    auto *device_columns = arena.allocate<M31>(column_slab.size());
    auto *partial =
        arena.allocate<QM31>(column_count * reduction_blocks);
    auto *output_indices = arena.allocate<std::uint32_t>(column_count);
    auto *sampled = arena.allocate<QM31>(column_count);
    const std::vector<std::uint32_t> host_output_indices{1u, 0u};
    if (device_columns == nullptr || partial == nullptr ||
        output_indices == nullptr || sampled == nullptr ||
        !arena.upload(
            device_columns,
            column_slab.data(),
            column_slab.size() * sizeof(M31)) ||
        !arena.upload(
            output_indices,
            host_output_indices.data(),
            column_count * sizeof(std::uint32_t)) ||
        !check(
            stwo_oods_barycentric_eval_many_on(
                device_columns,
                column_stride,
                column_count,
                weights,
                size,
                partial,
                reduction_blocks,
                output_indices,
                sampled,
                column_count,
                arena.stream),
            "barycentric evaluate")) {
        return false;
    }
    std::vector<QM31> actual_sampled(column_count);
    if (!arena.read(
            actual_sampled.data(),
            sampled,
            column_count * sizeof(QM31)) ||
        !arena.sync()) {
        return false;
    }
    for (std::uint32_t column = 0; column < column_count; ++column) {
        QM31 expected = oods_reference::zero();
        for (std::uint32_t row = 0; row < size; ++row) {
            expected = oods_reference::add(
                expected,
                oods_reference::mul(
                    columns[column][row],
                    expected_weights[row]));
        }
        if (!expect_equal(
                actual_sampled[host_output_indices[column]],
                expected,
                "barycentric sampled value",
                column)) {
            return false;
        }
    }
    return true;
}

bool test_scatter_capacities(DeviceArena &arena) {
    const QM31 parameter{{3u, 1u}, {4u, 1u}};
    const CirclePoint offset{1u, 0u};
    const std::uint32_t fold_count = 0;
    const std::uint32_t out_of_range_index = 7;
    const SecureCirclePoint point_sentinel{
        {{101u, 102u}, {103u, 104u}},
        {{105u, 106u}, {107u, 108u}},
    };
    const QM31 value_sentinel{{201u, 202u}, {203u, 204u}};
    const QM31 reduced_value{{11u, 12u}, {13u, 14u}};
    const M31 column_value = 17u;
    const QM31 weight = oods_reference::one();

    auto *device_parameter = arena.allocate<QM31>(1);
    auto *device_offset = arena.allocate<CirclePoint>(1);
    auto *device_fold = arena.allocate<std::uint32_t>(1);
    auto *device_index = arena.allocate<std::uint32_t>(1);
    auto *sample_points = arena.allocate<SecureCirclePoint>(1);
    auto *evaluation_points = arena.allocate<SecureCirclePoint>(1);
    auto *factors = arena.allocate<QM31>(1);
    auto *reduced = arena.allocate<QM31>(1);
    auto *sampled = arena.allocate<QM31>(1);
    auto *column = arena.allocate<M31>(1);
    auto *device_weight = arena.allocate<QM31>(1);
    auto *partial = arena.allocate<QM31>(1);
    if (device_parameter == nullptr || device_offset == nullptr ||
        device_fold == nullptr || device_index == nullptr ||
        sample_points == nullptr || evaluation_points == nullptr ||
        factors == nullptr || reduced == nullptr || sampled == nullptr ||
        column == nullptr || device_weight == nullptr || partial == nullptr ||
        !arena.upload(device_parameter, &parameter, sizeof(parameter)) ||
        !arena.upload(device_offset, &offset, sizeof(offset)) ||
        !arena.upload(device_fold, &fold_count, sizeof(fold_count)) ||
        !arena.upload(
            device_index, &out_of_range_index, sizeof(out_of_range_index)) ||
        !arena.upload(sample_points, &point_sentinel, sizeof(point_sentinel)) ||
        !arena.upload(reduced, &reduced_value, sizeof(reduced_value)) ||
        !arena.upload(sampled, &value_sentinel, sizeof(value_sentinel)) ||
        !arena.upload(column, &column_value, sizeof(column_value)) ||
        !arena.upload(device_weight, &weight, sizeof(weight)) ||
        !check(
            stwo_oods_derive_points_on(
                device_parameter,
                device_offset,
                device_fold,
                device_index,
                1,
                1,
                sample_points,
                1,
                evaluation_points,
                factors,
                arena.stream),
            "bounded derive scatter") ||
        !check(
            stwo_oods_store_results_on(
                reduced, 1, device_index, 1, sampled, 1, arena.stream),
            "bounded result scatter") ||
        !check(
            stwo_oods_barycentric_eval_many_on(
                column,
                1,
                1,
                device_weight,
                1,
                partial,
                1,
                device_index,
                sampled,
                1,
                arena.stream),
            "bounded barycentric scatter")) {
        return false;
    }
    SecureCirclePoint actual_point;
    QM31 actual_value;
    return arena.read(
               &actual_point, sample_points, sizeof(actual_point)) &&
           arena.read(&actual_value, sampled, sizeof(actual_value)) &&
           arena.sync() &&
           expect_equal(
               actual_point, point_sentinel, "bounded point scatter", 0) &&
           expect_equal(
               actual_value, value_sentinel, "bounded value scatter", 0);
}

bool test_invalid_descriptors(DeviceArena &arena) {
    QM31 q{};
    CirclePoint p{};
    SecureCirclePoint secure_point{};
    std::uint32_t word = 0;
    return
        expect_invalid(
            stwo_oods_derive_points_on(
                &q, &p, &word, &word, 1, 0, &secure_point, 1,
                &secure_point, &q, arena.stream),
            "zero-log derive") &&
        expect_invalid(
            stwo_oods_derive_points_on(
                &q, &p, &word, &word, 1, 1, &secure_point, 1,
                &secure_point, &q, nullptr),
            "null-stream derive") &&
        expect_invalid(
            stwo_oods_eval_first_on(
                &word, 3, 3, 1, &q, &q, arena.stream),
            "non-power-of-two first reduction") &&
        expect_invalid(
            stwo_oods_eval_reduce_on(
                &q, 2, 2, 0, 2, 1, &q, &q, 2, arena.stream),
            "wrong reduction stride") &&
        expect_invalid(
            stwo_oods_eval_reduce_on(
                &q, 8, 8, 1, 4, 1, &q, &q, 1, arena.stream),
            "underflowing reduction factors") &&
        expect_invalid(
            stwo_oods_store_results_on(
                &q, 1, &word, 1, &q, 1, nullptr),
            "null-stream store") &&
        expect_invalid(
            stwo_oods_barycentric_weights_on(
                1, 1, 8, 2, &secure_point, q, p, &q, &q, &q,
                arena.stream),
            "mismatched barycentric shape") &&
        expect_invalid(
            stwo_oods_barycentric_eval_many_on(
                &word, 1, 1, &q, 1, &q, 0, &word, &q, 1,
                arena.stream),
            "zero-block barycentric evaluation");
}

}  // namespace

int main() {
    DeviceArena arena;
    if (!check(stwo_exec_context_create(&arena.context), "create context") ||
        !check(
            stwo_exec_context_stream(arena.context, &arena.stream),
            "get proof stream")) {
        return 1;
    }
    const EvaluationFixture fixture;
    if (!test_invalid_descriptors(arena) ||
        !test_evaluation(arena, fixture) ||
        !test_barycentric(arena, fixture) ||
        !test_scatter_capacities(arena) ||
        !arena.close()) {
        return 1;
    }
    std::printf("native CUDA OODS smoke passed\n");
    return 0;
}
