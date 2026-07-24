#include <cuda_runtime_api.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

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
extern "C" int stwo_exec_context_pool_current(
    void *handle,
    std::size_t *used_current,
    std::size_t *reserved_current);

extern "C" int stwo_ntt_b2n_columns_to_retained_on(
    const std::uint32_t *inputs,
    std::size_t input_column_stride_words,
    std::uint32_t *retained_outputs,
    std::size_t output_column_stride_words,
    std::uint32_t log_n,
    std::uint32_t polynomial_count,
    const std::uint32_t *twiddles,
    std::uint32_t twiddle_words,
    std::uint32_t evaluation_domain_size,
    void *stream,
    std::uint32_t *launches_out);
extern "C" int stwo_ntt_n2b_columns_on(
    std::uint32_t *columns,
    std::size_t column_stride_words,
    std::uint32_t log_n,
    std::uint32_t polynomial_count,
    const std::uint32_t *twiddles,
    std::uint32_t twiddle_words,
    std::uint32_t evaluation_domain_size,
    void *stream,
    std::uint32_t *launches_out);
extern "C" int stwo_lde_n2b_columns_on(
    const std::uint32_t *coefficients,
    std::size_t coefficient_column_stride_words,
    const std::uint32_t *coefficient_log_sizes,
    std::uint32_t *evaluations,
    std::size_t evaluation_column_stride_words,
    std::uint32_t log_n,
    std::uint32_t polynomial_count,
    const std::uint32_t *twiddles,
    std::uint32_t twiddle_words,
    std::uint32_t evaluation_domain_size,
    void *stream,
    std::uint32_t *launches_out);
extern "C" int stwo_lde_n2b_columns_before_circle_on(
    const std::uint32_t *coefficients,
    std::size_t coefficient_column_stride_words,
    const std::uint32_t *coefficient_log_sizes,
    std::uint32_t *evaluations,
    std::size_t evaluation_column_stride_words,
    std::uint32_t log_n,
    std::uint32_t polynomial_count,
    const std::uint32_t *twiddles,
    std::uint32_t twiddle_words,
    std::uint32_t evaluation_domain_size,
    void *stream,
    std::uint32_t *launches_out);

namespace {

constexpr std::uint32_t kM31Prime = 2147483647u;

std::uint32_t b2n_launches(std::uint32_t log_n) {
    if (log_n >= 13u && log_n <= 18u) return 2;
    if (log_n >= 19u && log_n <= 23u) return 3;
    return log_n;
}

std::uint32_t n2b_launches(
    std::uint32_t log_n,
    bool include_circle) {
    if (log_n >= 13u && log_n <= 19u) return 2;
    if (log_n >= 20u && log_n <= 23u) return 3;
    return include_circle ? log_n : log_n - 1u;
}

bool check_launches(
    std::uint32_t actual,
    std::uint32_t expected,
    const char *operation) {
    if (actual == expected) return true;
    std::fprintf(
        stderr,
        "%s launch telemetry mismatch: expected=%u actual=%u\n",
        operation,
        expected,
        actual);
    return false;
}

std::uint32_t add(std::uint32_t left, std::uint32_t right) {
    const std::uint64_t sum =
        static_cast<std::uint64_t>(left) + right;
    return static_cast<std::uint32_t>(
        sum < kM31Prime ? sum : sum - kM31Prime);
}

std::uint32_t sub(std::uint32_t left, std::uint32_t right) {
    return add(left, kM31Prime - right);
}

std::uint32_t mul(std::uint32_t left, std::uint32_t right) {
    const std::uint64_t product =
        static_cast<std::uint64_t>(left) * right;
    const std::uint64_t folded = product + (product >> 31);
    return static_cast<std::uint32_t>(
        (product + (folded >> 31)) & kM31Prime);
}

std::uint32_t power(std::uint32_t base, std::uint32_t exponent) {
    std::uint32_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1u) != 0) result = mul(result, base);
        base = mul(base, base);
        exponent >>= 1;
    }
    return result;
}

std::uint32_t inverse(std::uint32_t value) {
    return power(value, kM31Prime - 2u);
}

std::uint32_t circle_twiddle(
    const std::vector<std::uint32_t> &twiddles,
    std::uint32_t index) {
    const std::uint32_t pair = index >> 2;
    switch (index & 3u) {
        case 0:
            return twiddles[2u * pair + 1u];
        case 1:
            return sub(0, twiddles[2u * pair + 1u]);
        case 2:
            return sub(0, twiddles[2u * pair]);
        default:
            return twiddles[2u * pair];
    }
}

void n2b_reference(
    std::vector<std::uint32_t> &values,
    std::uint32_t log_n,
    const std::vector<std::uint32_t> &twiddles,
    bool include_circle) {
    const std::uint32_t pair_count = 1u << (log_n - 1u);
    std::uint32_t layer_size = 1;
    std::uint32_t layer_offset = pair_count - 2u;
    const std::uint32_t final_stage =
        include_circle ? log_n : log_n - 1u;
    for (std::uint32_t stage = 1; stage <= final_stage; ++stage) {
        const std::uint32_t stride = 1u << (log_n - stage);
        for (std::uint32_t pair_index = 0;
             pair_index < pair_count;
             ++pair_index) {
            const std::uint32_t group = pair_index & (stride - 1u);
            const std::uint32_t butterfly =
                pair_index >> (log_n - stage);
            const std::uint32_t left_index =
                group + butterfly * 2u * stride;
            const std::uint32_t right_index = left_index + stride;
            const std::uint32_t left = values[left_index];
            const std::uint32_t twiddle = stage == log_n
                ? circle_twiddle(twiddles, butterfly)
                : twiddles[layer_offset + butterfly];
            const std::uint32_t product =
                mul(twiddle, values[right_index]);
            values[left_index] = add(left, product);
            values[right_index] = sub(left, product);
        }
        if (stage < log_n - 1u) {
            layer_size <<= 1;
            layer_offset -= layer_size;
        }
    }
}

std::vector<std::uint32_t> b2n_retained_reference(
    const std::vector<std::uint32_t> &input,
    std::uint32_t log_n,
    const std::vector<std::uint32_t> &inverse_twiddles) {
    const std::uint32_t size = 1u << log_n;
    const std::uint32_t pair_count = size / 2u;
    std::vector<std::uint32_t> values = input;
    std::uint32_t layer_size = pair_count;
    std::uint32_t layer_offset = 0;
    const std::uint32_t scale = inverse(power(2, log_n));
    for (std::uint32_t stage = 1; stage <= log_n; ++stage) {
        const std::uint32_t stride = 1u << (stage - 1u);
        for (std::uint32_t pair_index = 0;
             pair_index < pair_count;
             ++pair_index) {
            const std::uint32_t group = pair_index & (stride - 1u);
            const std::uint32_t butterfly =
                pair_index >> (stage - 1u);
            const std::uint32_t left_index =
                group + butterfly * 2u * stride;
            const std::uint32_t right_index = left_index + stride;
            const std::uint32_t left = values[left_index];
            const std::uint32_t right = values[right_index];
            const std::uint32_t twiddle = stage == 1
                ? circle_twiddle(inverse_twiddles, butterfly)
                : inverse_twiddles[layer_offset + butterfly];
            std::uint32_t left_result = add(left, right);
            std::uint32_t right_result = mul(sub(left, right), twiddle);
            if (stage == log_n) {
                left_result = mul(left_result, scale);
                right_result = mul(right_result, scale);
            }
            values[left_index] = left_result;
            values[right_index] = right_result;
        }
        if (stage >= 2u && stage != log_n) {
            layer_size >>= 1;
            layer_offset += layer_size;
        }
    }
    values.insert(values.end(), values.begin(), values.end());
    return values;
}

bool check_status(int status, const char *operation) {
    if (status == 0) return true;
    std::fprintf(
        stderr,
        "%s: status=%d (%s)\n",
        operation,
        status,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

bool expect_invalid(int status, const char *operation) {
    if (status == static_cast<int>(cudaErrorInvalidValue)) return true;
    std::fprintf(
        stderr,
        "%s: expected cudaErrorInvalidValue, got %d\n",
        operation,
        status);
    return false;
}

struct DeviceSession {
    void *context = nullptr;
    void *stream = nullptr;
    std::vector<std::uint32_t *> allocations;

    bool init() {
        return check_status(
                   stwo_exec_context_create(&context),
                   "create context") &&
            check_status(
                   stwo_exec_context_stream(context, &stream),
                   "get proof stream");
    }

    std::uint32_t *allocate(std::size_t words) {
        std::uint32_t *pointer = nullptr;
        if (!check_status(
                stwo_exec_context_alloc_u32(context, words, &pointer),
                "allocate resident words")) {
            return nullptr;
        }
        allocations.push_back(pointer);
        return pointer;
    }

    bool upload(
        void *destination,
        const void *source,
        std::size_t bytes) const {
        return check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                destination,
                source,
                bytes),
            "upload resident words");
    }

    bool download(
        void *destination,
        const void *source,
        std::size_t bytes) const {
        return check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                destination,
                source,
                bytes),
            "download resident words");
    }

    bool finish() {
        for (auto iterator = allocations.rbegin();
             iterator != allocations.rend();
             ++iterator) {
            if (!check_status(
                    stwo_exec_context_free_u32(context, *iterator),
                    "free resident words")) {
                return false;
            }
        }
        allocations.clear();
        if (!check_status(
                stwo_exec_context_sync(context),
                "wait for resident frees")) {
            return false;
        }
        std::size_t used = 1;
        std::size_t reserved = 0;
        if (!check_status(
                stwo_exec_context_pool_current(
                    context,
                    &used,
                    &reserved),
                "read pool counters") ||
            used != 0) {
            std::fprintf(stderr, "pool has %zu live bytes\n", used);
            return false;
        }
        const bool result = check_status(
            stwo_exec_context_destroy(context),
            "destroy context");
        context = nullptr;
        stream = nullptr;
        return result;
    }
};

bool compare(
    const std::vector<std::uint32_t> &expected,
    const std::vector<std::uint32_t> &actual,
    const char *operation,
    std::uint32_t log_n,
    std::uint32_t column) {
    for (std::size_t index = 0; index < expected.size(); ++index) {
        if (expected[index] != actual[index]) {
            std::fprintf(
                stderr,
                "%s mismatch log=%u column=%u index=%zu "
                "expected=%u actual=%u\n",
                operation,
                log_n,
                column,
                index,
                expected[index],
                actual[index]);
            return false;
        }
    }
    return true;
}

bool run_case(std::uint32_t log_n, std::uint32_t width) {
    const std::uint32_t size = 1u << log_n;
    const std::uint32_t domain_size = size / 2u;
    DeviceSession session;
    if (!session.init()) return false;

    std::vector<std::uint32_t> twiddles(domain_size);
    std::vector<std::uint32_t> inverse_twiddles(domain_size);
    for (std::uint32_t index = 0; index < domain_size; ++index) {
        twiddles[index] =
            static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(index + 11u) *
                 (index + 29u) + 7u) %
                (kM31Prime - 1u)) +
            1u;
        inverse_twiddles[index] = inverse(twiddles[index]);
    }
    auto *device_twiddles = session.allocate(domain_size);
    auto *device_inverse_twiddles = session.allocate(domain_size);
    if (device_twiddles == nullptr ||
        device_inverse_twiddles == nullptr ||
        !session.upload(
            device_twiddles,
            twiddles.data(),
            twiddles.size() * sizeof(twiddles[0])) ||
        !session.upload(
            device_inverse_twiddles,
            inverse_twiddles.data(),
            inverse_twiddles.size() * sizeof(inverse_twiddles[0]))) {
        return false;
    }

    std::vector<std::vector<std::uint32_t>> source(
        width,
        std::vector<std::uint32_t>(size));
    const std::size_t retained_stride = 2u * size + 3u;
    std::vector<std::uint32_t> retained_host(
        static_cast<std::size_t>(width) * retained_stride,
        0);
    for (std::uint32_t column = 0; column < width; ++column) {
        for (std::uint32_t row = 0; row < size; ++row) {
            source[column][row] =
                static_cast<std::uint32_t>(
                    (static_cast<std::uint64_t>(column + 3u) *
                     (row + 17u) * 104729u + row * row + 1u) %
                    kM31Prime);
            retained_host[
                static_cast<std::size_t>(column) * retained_stride + row] =
                source[column][row];
        }
    }
    auto *device_retained = session.allocate(retained_host.size());
    std::uint32_t retained_launches = 0;
    if (device_retained == nullptr ||
        !session.upload(
            device_retained,
            retained_host.data(),
            retained_host.size() * sizeof(std::uint32_t)) ||
        !check_status(
            stwo_ntt_b2n_columns_to_retained_on(
                device_retained,
                retained_stride,
                device_retained,
                retained_stride,
                log_n,
                width,
                device_inverse_twiddles,
                domain_size,
                domain_size,
                session.stream,
                &retained_launches),
            "launch retained B2N")) {
        return false;
    }
    if (!check_launches(
            retained_launches,
            b2n_launches(log_n),
            "retained B2N")) {
        return false;
    }
    std::uint32_t rejected_launches = 17;
    if (!expect_invalid(
            stwo_ntt_b2n_columns_to_retained_on(
                device_retained + 1,
                retained_stride,
                device_retained,
                retained_stride,
                log_n,
                width,
                device_inverse_twiddles,
                domain_size,
                domain_size,
                session.stream,
                &rejected_launches),
            "reject partial B2N alias") ||
        !expect_invalid(
            stwo_ntt_b2n_columns_to_retained_on(
                device_retained,
                retained_stride,
                device_retained,
                2u * size - 1u,
                log_n,
                width,
                device_inverse_twiddles,
                domain_size,
                domain_size,
                session.stream,
                &rejected_launches),
            "reject short B2N stride")) {
        return false;
    }
    if (!check_launches(rejected_launches, 0, "rejected B2N")) return false;
    std::vector<std::uint32_t> retained_actual(retained_host.size());
    if (!session.download(
            retained_actual.data(),
            device_retained,
            retained_actual.size() * sizeof(std::uint32_t))) {
        return false;
    }
    if (!check_status(
            stwo_exec_context_sync(session.context),
            "wait for retained B2N")) {
        return false;
    }
    for (std::uint32_t column = 0; column < width; ++column) {
        const auto expected = b2n_retained_reference(
            source[column],
            log_n,
            inverse_twiddles);
        const auto first = retained_actual.begin() +
            static_cast<std::size_t>(column) * retained_stride;
        const std::vector<std::uint32_t> actual(
            first,
            first + 2u * size);
        if (!compare(
                expected,
                actual,
                "retained B2N",
                log_n,
                column)) {
            return false;
        }
    }

    std::vector<std::vector<std::uint32_t>> forward_expected = source;
    const std::size_t forward_stride = size + 5u;
    std::vector<std::uint32_t> forward_host(
        static_cast<std::size_t>(width) * forward_stride);
    for (std::uint32_t column = 0; column < width; ++column) {
        n2b_reference(forward_expected[column], log_n, twiddles, true);
        std::copy(
            source[column].begin(),
            source[column].end(),
            forward_host.begin() +
                static_cast<std::size_t>(column) * forward_stride);
    }
    auto *device_forward = session.allocate(forward_host.size());
    std::uint32_t forward_launches = 0;
    if (device_forward == nullptr ||
        !session.upload(
            device_forward,
            forward_host.data(),
            forward_host.size() * sizeof(std::uint32_t)) ||
        !check_status(
            stwo_ntt_n2b_columns_on(
                device_forward,
                forward_stride,
                log_n,
                width,
                device_twiddles,
                domain_size,
                domain_size,
                session.stream,
                &forward_launches),
            "launch N2B")) {
        return false;
    }
    if (!check_launches(
            forward_launches,
            n2b_launches(log_n, true),
            "N2B")) {
        return false;
    }
    rejected_launches = 17;
    if (!expect_invalid(
            stwo_ntt_n2b_columns_on(
                device_forward,
                size - 1u,
                log_n,
                width,
                device_twiddles,
                domain_size,
                domain_size,
                session.stream,
                &rejected_launches),
            "reject short N2B stride")) {
        return false;
    }
    if (!check_launches(rejected_launches, 0, "rejected N2B")) return false;
    std::vector<std::uint32_t> forward_actual(forward_host.size());
    if (!session.download(
            forward_actual.data(),
            device_forward,
            forward_actual.size() * sizeof(std::uint32_t))) {
        return false;
    }
    if (!check_status(
            stwo_exec_context_sync(session.context),
            "wait for N2B")) {
        return false;
    }
    for (std::uint32_t column = 0; column < width; ++column) {
        const auto first = forward_actual.begin() +
            static_cast<std::size_t>(column) * forward_stride;
        const std::vector<std::uint32_t> actual(first, first + size);
        if (!compare(
                forward_expected[column],
                actual,
                "N2B",
                log_n,
                column)) {
            return false;
        }
    }

    std::vector<std::vector<std::uint32_t>> coefficients(
        width,
        std::vector<std::uint32_t>(domain_size));
    std::vector<std::uint32_t> coefficient_log_sizes(width);
    const std::size_t coefficient_stride = domain_size + 3u;
    const std::size_t evaluation_stride = size + 7u;
    std::vector<std::uint32_t> coefficient_host(
        static_cast<std::size_t>(width) * coefficient_stride);
    for (std::uint32_t column = 0; column < width; ++column) {
        coefficient_log_sizes[column] =
            column + 1u == width
            ? log_n - 1u
            : (column * 13u + log_n) % log_n;
        for (std::uint32_t row = 0; row < domain_size; ++row) {
            coefficients[column][row] =
                static_cast<std::uint32_t>(
                    (static_cast<std::uint64_t>(column + 19u) *
                     (row + 23u) * 65537u + 5u) %
                    kM31Prime);
            coefficient_host[
                static_cast<std::size_t>(column) * coefficient_stride + row] =
                coefficients[column][row];
        }
    }
    auto *device_coefficients = session.allocate(coefficient_host.size());
    auto *device_lde = session.allocate(
        static_cast<std::size_t>(width) * evaluation_stride);
    auto *device_pre_circle = session.allocate(
        static_cast<std::size_t>(width) * evaluation_stride);
    auto *device_sizes = session.allocate(width);
    std::uint32_t lde_launches = 0;
    std::uint32_t pre_circle_launches = 0;
    if (device_coefficients == nullptr ||
        device_lde == nullptr ||
        device_pre_circle == nullptr ||
        device_sizes == nullptr ||
        !session.upload(
            device_coefficients,
            coefficient_host.data(),
            coefficient_host.size() * sizeof(std::uint32_t)) ||
        !session.upload(
            device_sizes,
            coefficient_log_sizes.data(),
            width * sizeof(std::uint32_t)) ||
        !check_status(
            stwo_lde_n2b_columns_on(
                device_coefficients,
                coefficient_stride,
                device_sizes,
                device_lde,
                evaluation_stride,
                log_n,
                width,
                device_twiddles,
                domain_size,
                domain_size,
                session.stream,
                &lde_launches),
            "launch full LDE") ||
        !check_status(
            stwo_lde_n2b_columns_before_circle_on(
                device_coefficients,
                coefficient_stride,
                device_sizes,
                device_pre_circle,
                evaluation_stride,
                log_n,
                width,
                device_twiddles,
                domain_size,
                domain_size,
                session.stream,
                &pre_circle_launches),
            "launch pre-circle LDE")) {
        return false;
    }
    if (!check_launches(
            lde_launches,
            1u + n2b_launches(log_n, true),
            "full LDE") ||
        !check_launches(
            pre_circle_launches,
            1u + n2b_launches(log_n, false),
            "pre-circle LDE")) {
        return false;
    }
    rejected_launches = 17;
    if (!expect_invalid(
            stwo_lde_n2b_columns_on(
                device_coefficients,
                coefficient_stride,
                device_sizes,
                device_coefficients,
                evaluation_stride,
                log_n,
                width,
                device_twiddles,
                domain_size,
                domain_size,
                session.stream,
                &rejected_launches),
            "reject overlapping LDE slabs")) {
        return false;
    }
    if (!check_launches(rejected_launches, 0, "rejected LDE")) return false;

    std::vector<std::uint32_t> lde_actual(
        static_cast<std::size_t>(width) * evaluation_stride);
    std::vector<std::uint32_t> pre_circle_actual(
        static_cast<std::size_t>(width) * evaluation_stride);
    if (!session.download(
            lde_actual.data(),
            device_lde,
            lde_actual.size() * sizeof(std::uint32_t)) ||
        !session.download(
            pre_circle_actual.data(),
            device_pre_circle,
            pre_circle_actual.size() * sizeof(std::uint32_t))) {
        return false;
    }
    if (!check_status(
            stwo_exec_context_sync(session.context),
            "wait for LDE")) {
        return false;
    }
    for (std::uint32_t column = 0; column < width; ++column) {
        const std::uint32_t count =
            1u << coefficient_log_sizes[column];
        std::vector<std::uint32_t> staged(size, 0);
        std::copy_n(
            coefficients[column].begin(),
            count,
            staged.begin());
        auto full_expected = staged;
        auto pre_circle_expected = staged;
        n2b_reference(full_expected, log_n, twiddles, true);
        n2b_reference(pre_circle_expected, log_n, twiddles, false);
        const auto lde_first = lde_actual.begin() +
            static_cast<std::size_t>(column) * evaluation_stride;
        const auto pre_circle_first = pre_circle_actual.begin() +
            static_cast<std::size_t>(column) * evaluation_stride;
        const std::vector<std::uint32_t> full_actual(
            lde_first,
            lde_first + size);
        const std::vector<std::uint32_t> before_circle_actual(
            pre_circle_first,
            pre_circle_first + size);
        if (!compare(
                full_expected,
                full_actual,
                "full LDE",
                log_n,
                column) ||
            !compare(
                pre_circle_expected,
                before_circle_actual,
                "pre-circle LDE",
                log_n,
                column)) {
            return false;
        }
    }
    return session.finish();
}

}  // namespace

int main() {
    const struct {
        std::uint32_t log_n;
        std::uint32_t width;
    } cases[] = {
        {3, 3},
        {8, 5},
        {9, 37},
        {10, 5},
        {13, 37},
        {16, 3},
        {18, 3},
    };
    for (const auto &test_case : cases) {
        if (!run_case(test_case.log_n, test_case.width)) return 1;
    }
    std::printf(
        "native CUDA transform smoke passed: %zu shapes, "
        "including width 37 and fused log 13/16/18 schedules\n",
        sizeof(cases) / sizeof(cases[0]));
    return 0;
}
