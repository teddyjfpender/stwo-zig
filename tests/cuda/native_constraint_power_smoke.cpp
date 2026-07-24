#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

struct SecureField {
    std::uint32_t a;
    std::uint32_t b;
    std::uint32_t c;
    std::uint32_t d;
};

static_assert(sizeof(SecureField) == 4 * sizeof(std::uint32_t));

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
extern "C" int stwo_constraint_expand_powers_on(
    const SecureField *alpha,
    SecureField *output,
    std::size_t output_capacity,
    std::uint32_t count,
    void *stream);

namespace {

constexpr std::uint32_t kPrime = 2147483647u;

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

std::uint32_t m31_add(std::uint32_t left, std::uint32_t right) {
    const std::uint64_t sum =
        static_cast<std::uint64_t>(left) + right;
    return static_cast<std::uint32_t>(
        sum < kPrime ? sum : sum - kPrime);
}

std::uint32_t m31_sub(std::uint32_t left, std::uint32_t right) {
    return m31_add(left, kPrime - right);
}

std::uint32_t m31_mul(std::uint32_t left, std::uint32_t right) {
    const std::uint64_t product =
        static_cast<std::uint64_t>(left) * right;
    const std::uint64_t folded = product + (product >> 31);
    return static_cast<std::uint32_t>(
        (product + (folded >> 31)) & kPrime);
}

struct Complex {
    std::uint32_t real;
    std::uint32_t imag;
};

Complex add(Complex left, Complex right) {
    return {
        m31_add(left.real, right.real),
        m31_add(left.imag, right.imag),
    };
}

Complex sub(Complex left, Complex right) {
    return {
        m31_sub(left.real, right.real),
        m31_sub(left.imag, right.imag),
    };
}

Complex mul(Complex left, Complex right) {
    return {
        m31_sub(
            m31_mul(left.real, right.real),
            m31_mul(left.imag, right.imag)),
        m31_add(
            m31_mul(left.real, right.imag),
            m31_mul(left.imag, right.real)),
    };
}

SecureField multiply(SecureField left, SecureField right) {
    const Complex left_first{left.a, left.b};
    const Complex left_second{left.c, left.d};
    const Complex right_first{right.a, right.b};
    const Complex right_second{right.c, right.d};
    const Complex product_0 = mul(left_first, right_first);
    const Complex product_1 = mul(left_second, right_second);
    const Complex product_sum = mul(
        add(left_first, left_second),
        add(right_first, right_second));
    const Complex extension_product{
        m31_sub(
            m31_add(product_1.real, product_1.real),
            product_1.imag),
        m31_add(
            product_1.real,
            m31_add(product_1.imag, product_1.imag)),
    };
    const Complex first = add(product_0, extension_product);
    const Complex second = sub(
        product_sum,
        add(product_0, product_1));
    return {first.real, first.imag, second.real, second.imag};
}

bool equal(SecureField left, SecureField right) {
    return left.a == right.a && left.b == right.b &&
        left.c == right.c && left.d == right.d;
}

}  // namespace

int main() {
    void *context = nullptr;
    void *stream = nullptr;
    if (!check_status(stwo_exec_context_create(&context), "create context") ||
        !check_status(
            stwo_exec_context_stream(context, &stream),
            "read proof stream") ||
        stream == nullptr) {
        return 1;
    }

    constexpr std::uint32_t count = 9;
    const SecureField alpha{2, 3, 5, 7};
    std::uint32_t *alpha_words = nullptr;
    std::uint32_t *output_words = nullptr;
    if (!check_status(
            stwo_exec_context_alloc_u32(context, 4, &alpha_words),
            "allocate alpha") ||
        !check_status(
            stwo_exec_context_alloc_u32(
                context,
                count * 4,
                &output_words),
            "allocate powers") ||
        !check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                alpha_words,
                &alpha,
                sizeof(alpha)),
            "upload alpha")) {
        return 1;
    }

    if (!check_status(
            stwo_constraint_expand_powers_on(
                reinterpret_cast<const SecureField *>(alpha_words),
                reinterpret_cast<SecureField *>(output_words),
                count,
                count,
                stream),
            "expand resident powers")) {
        return 1;
    }
    if (stwo_constraint_expand_powers_on(
            reinterpret_cast<const SecureField *>(alpha_words),
            reinterpret_cast<SecureField *>(output_words),
            count - 1,
            count,
            stream) == 0 ||
        stwo_constraint_expand_powers_on(
            reinterpret_cast<const SecureField *>(alpha_words),
            reinterpret_cast<SecureField *>(output_words),
            count,
            count,
            nullptr) == 0) {
        std::fprintf(stderr, "invalid power launch was admitted\n");
        return 1;
    }

    std::vector<SecureField> actual(count);
    if (!check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                actual.data(),
                output_words,
                actual.size() * sizeof(SecureField)),
            "read powers") ||
        !check_status(stwo_exec_context_sync(context), "wait for powers")) {
        return 1;
    }

    SecureField expected{1, 0, 0, 0};
    for (std::uint32_t index = 0; index < count; ++index) {
        if (!equal(actual[index], expected)) {
            std::fprintf(stderr, "power mismatch at index %u\n", index);
            return 1;
        }
        expected = multiply(expected, alpha);
    }

    if (!check_status(
            stwo_exec_context_free_u32(context, output_words),
            "free powers") ||
        !check_status(
            stwo_exec_context_free_u32(context, alpha_words),
            "free alpha") ||
        !check_status(stwo_exec_context_sync(context), "wait for frees") ||
        !check_status(stwo_exec_context_destroy(context), "destroy context")) {
        return 1;
    }
    std::printf("native CUDA constraint-power smoke passed\n");
    return 0;
}
