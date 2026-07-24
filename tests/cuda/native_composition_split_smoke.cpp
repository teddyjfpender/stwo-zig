#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_sync(void *handle);
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
extern "C" int stwo_ntt_b2n_composition_split_compact_on(
    std::uint32_t *coordinate_values,
    std::size_t coordinate_capacity_words,
    std::size_t coordinate_stride_words,
    std::uint32_t *coefficients,
    std::size_t coefficient_capacity_words,
    std::size_t coefficient_stride_words,
    std::uint32_t log_n,
    const std::uint32_t *inverse_twiddles,
    std::uint32_t inverse_twiddle_words,
    std::uint32_t evaluation_domain_size,
    void *stream);

namespace {

constexpr std::uint32_t kPrime = 2147483647u;
constexpr std::uint32_t kCoordinates = 4u;
constexpr std::uint32_t kCoefficientColumns = 8u;

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

std::uint32_t add(std::uint32_t left, std::uint32_t right) {
    const std::uint64_t sum =
        static_cast<std::uint64_t>(left) + right;
    return static_cast<std::uint32_t>(
        sum < kPrime ? sum : sum - kPrime);
}

std::uint32_t sub(std::uint32_t left, std::uint32_t right) {
    return add(left, kPrime - right);
}

std::uint32_t mul(std::uint32_t left, std::uint32_t right) {
    const std::uint64_t product =
        static_cast<std::uint64_t>(left) * right;
    const std::uint64_t folded = product + (product >> 31);
    return static_cast<std::uint32_t>(
        (product + (folded >> 31)) & kPrime);
}

std::uint32_t power(std::uint32_t base, std::uint32_t exponent) {
    std::uint32_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1u) != 0) result = mul(result, base);
        base = mul(base, base);
        exponent >>= 1u;
    }
    return result;
}

std::uint32_t circle_twiddle(
    const std::vector<std::uint32_t> &twiddles,
    std::uint32_t index) {
    const std::uint32_t pair = index >> 2u;
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

void inverse_transform(
    std::vector<std::uint32_t> &values,
    std::uint32_t log_n,
    const std::vector<std::uint32_t> &twiddles) {
    const std::uint32_t pair_count = 1u << (log_n - 1u);
    std::uint32_t layer_size = pair_count;
    std::uint32_t layer_offset = 0;
    const std::uint32_t scale =
        power(power(2u, log_n), kPrime - 2u);
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
                ? circle_twiddle(twiddles, butterfly)
                : twiddles[layer_offset + butterfly];
            std::uint32_t left_result = add(left, right);
            std::uint32_t right_result =
                mul(sub(left, right), twiddle);
            if (stage == log_n) {
                left_result = mul(left_result, scale);
                right_result = mul(right_result, scale);
            }
            values[left_index] = left_result;
            values[right_index] = right_result;
        }
        if (stage >= 2u && stage != log_n) {
            layer_size >>= 1u;
            layer_offset += layer_size;
        }
    }
}

bool run_case(std::uint32_t log_n) {
    const std::size_t values = std::size_t{1} << log_n;
    const std::size_t domain = values / 2u;
    const std::size_t input_words = kCoordinates * values;
    const std::size_t output_words = kCoefficientColumns * domain;
    void *context = nullptr;
    void *stream = nullptr;
    std::uint32_t *device_input = nullptr;
    std::uint32_t *device_output = nullptr;
    std::uint32_t *device_twiddles = nullptr;
    if (!check_status(stwo_exec_context_create(&context), "create context") ||
        !check_status(
            stwo_exec_context_stream(context, &stream),
            "read proof stream") ||
        stream == nullptr ||
        !check_status(
            stwo_exec_context_alloc_u32(
                context,
                input_words,
                &device_input),
            "allocate coordinate slab") ||
        !check_status(
            stwo_exec_context_alloc_u32(
                context,
                output_words,
                &device_output),
            "allocate coefficient slab") ||
        !check_status(
            stwo_exec_context_alloc_u32(
                context,
                domain,
                &device_twiddles),
            "allocate inverse twiddles")) {
        return false;
    }

    std::vector<std::uint32_t> input(input_words);
    std::vector<std::uint32_t> twiddles(domain);
    for (std::size_t index = 0; index < domain; ++index) {
        const std::uint32_t value = static_cast<std::uint32_t>(
            (index * index * 17u + index * 97u + 13u) %
            (kPrime - 1u));
        twiddles[index] = value + 1u;
    }
    for (std::size_t coordinate = 0;
         coordinate < kCoordinates;
         ++coordinate) {
        for (std::size_t row = 0; row < values; ++row) {
            input[coordinate * values + row] =
                static_cast<std::uint32_t>(
                    ((coordinate + 5u) * (row + 11u) * 65537u +
                     row * row + 3u) %
                    kPrime);
        }
    }
    if (!check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                device_input,
                input.data(),
                input_words * sizeof(std::uint32_t)),
            "upload coordinates") ||
        !check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                device_twiddles,
                twiddles.data(),
                domain * sizeof(std::uint32_t)),
            "upload inverse twiddles") ||
        !check_status(
            stwo_ntt_b2n_composition_split_compact_on(
                device_input,
                input_words,
                values,
                device_output,
                output_words,
                domain,
                log_n,
                device_twiddles,
                static_cast<std::uint32_t>(domain),
                static_cast<std::uint32_t>(domain),
                stream),
            "interpolate and split composition")) {
        return false;
    }

    if (stwo_ntt_b2n_composition_split_compact_on(
            device_input,
            input_words - 1u,
            values,
            device_output,
            output_words,
            domain,
            log_n,
            device_twiddles,
            static_cast<std::uint32_t>(domain),
            static_cast<std::uint32_t>(domain),
            stream) == 0 ||
        stwo_ntt_b2n_composition_split_compact_on(
            device_input,
            input_words,
            values,
            device_output,
            output_words,
            domain,
            log_n,
            device_twiddles,
            static_cast<std::uint32_t>(domain),
            static_cast<std::uint32_t>(domain),
            nullptr) == 0 ||
        stwo_ntt_b2n_composition_split_compact_on(
            device_input,
            input_words,
            values,
            device_input,
            output_words,
            domain,
            log_n,
            device_twiddles,
            static_cast<std::uint32_t>(domain),
            static_cast<std::uint32_t>(domain),
            stream) == 0) {
        std::fprintf(stderr, "invalid composition slab was admitted\n");
        return false;
    }

    std::vector<std::uint32_t> actual(output_words);
    if (!check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                actual.data(),
                device_output,
                output_words * sizeof(std::uint32_t)),
            "read compact coefficients") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for composition split")) {
        return false;
    }

    const std::size_t half = values / 2u;
    for (std::size_t coordinate = 0;
         coordinate < kCoordinates;
         ++coordinate) {
        std::vector<std::uint32_t> coefficients(
            input.begin() + coordinate * values,
            input.begin() + (coordinate + 1u) * values);
        inverse_transform(coefficients, log_n, twiddles);
        for (std::size_t side = 0; side < 2; ++side) {
            const std::size_t output_column =
                coordinate + kCoordinates * side;
            for (std::size_t row = 0; row < half; ++row) {
                const std::uint32_t expected =
                    coefficients[side * half + row];
                const std::uint32_t observed =
                    actual[output_column * half + row];
                if (observed != expected) {
                    std::fprintf(
                        stderr,
                        "composition mismatch log=%u column=%zu row=%zu "
                        "expected=%u actual=%u\n",
                        log_n,
                        output_column,
                        row,
                        expected,
                        observed);
                    return false;
                }
            }
        }
    }

    if (!check_status(
            stwo_exec_context_free_u32(context, device_twiddles),
            "free twiddles") ||
        !check_status(
            stwo_exec_context_free_u32(context, device_output),
            "free output") ||
        !check_status(
            stwo_exec_context_free_u32(context, device_input),
            "free input") ||
        !check_status(stwo_exec_context_sync(context), "wait for frees")) {
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
        std::fprintf(stderr, "pool retained %zu live bytes\n", used);
        return false;
    }
    return check_status(
        stwo_exec_context_destroy(context),
        "destroy context");
}

}  // namespace

int main() {
    if (!run_case(4) || !run_case(8)) return 1;
    std::printf("native CUDA composition-split smoke passed\n");
    return 0;
}
