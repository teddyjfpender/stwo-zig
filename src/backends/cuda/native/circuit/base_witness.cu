// The five circuit gate components, in the exact column and table order of
// frontends/circuit/witness/components.zig. All inputs and outputs are device
// resident; pointer lists are copied into launch parameters on the host.
#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::circuit_base {

#if !defined(STWO_CIRCUIT_BASE_HOST_EMULATION)
constexpr unsigned kThreads = 256;
#endif
constexpr unsigned kMaxPreprocessed = 11;
constexpr unsigned kMaxOutput = 52;
constexpr unsigned kCountColumns = 22;
constexpr std::uint32_t kM31 = 0x7fffffffu;

struct Columns {
    const std::uint32_t *pp[kMaxPreprocessed];
    std::uint32_t *out[kMaxOutput];
    std::uint32_t *counts[kCountColumns];
};

__device__ __forceinline__ std::uint32_t mul(std::uint32_t a, std::uint32_t b) {
    const std::uint64_t product = static_cast<std::uint64_t>(a) * b;
    std::uint32_t reduced = static_cast<std::uint32_t>(
        (product & kM31) + (product >> 31u));
    if (reduced >= kM31) reduced -= kM31;
    return reduced;
}

__device__ __forceinline__ std::uint32_t inverse(std::uint32_t x) {
    if (x == 0) x = 1;
    std::uint32_t result = 1;
    std::uint32_t power = x;
    constexpr std::uint32_t exponent = kM31 - 2;
    for (unsigned bit = 0; bit < 31; ++bit) {
        if ((exponent >> bit) & 1u) result = mul(result, power);
        power = mul(power, power);
    }
    return result;
}

__device__ __forceinline__ void fail(std::uint32_t *error) {
    atomicOr(error, 1u);
}

__device__ __forceinline__ bool read_value(
    const std::uint32_t *values, std::uint32_t value_count,
    std::uint32_t address, std::uint32_t *limbs, std::uint32_t *error) {
    if (address >= value_count) {
        fail(error);
        return false;
    }
    const std::size_t at = 4ull * address;
    for (unsigned i = 0; i < 4; ++i) limbs[i] = values[at + i];
    return true;
}

__device__ __forceinline__ std::uint32_t word(const std::uint32_t *limbs) {
    return limbs[0] | (limbs[1] << 16);
}

__device__ __forceinline__ void xor_count(
    Columns columns, unsigned relation, unsigned bits, std::uint32_t a,
    std::uint32_t b, std::uint32_t expected, std::uint32_t *error) {
    const std::uint32_t limit = 1u << bits;
    if (a >= limit || b >= limit || (a ^ b) != expected) {
        fail(error);
        return;
    }
    if (relation == 2) {
        const unsigned column = 2u + ((a >> 10u) << 2u) + (b >> 10u);
        const unsigned row = ((a & 1023u) << 10u) | (b & 1023u);
        atomicAdd(columns.counts[column] + row, 1u);
    } else {
        atomicAdd(columns.counts[relation] + (a << bits) + b, 1u);
    }
}

template <unsigned Kind>
__device__ void generate_row(
    const std::uint32_t *values, std::uint32_t value_count,
    std::uint32_t row_count, std::uint32_t first_permutation_row,
    Columns columns, std::uint32_t *error, unsigned row) {
    (void)row_count;
    std::uint32_t result[kMaxOutput] = {};
    std::uint32_t limbs[4];
    if constexpr (Kind == 0) {
        if (!read_value(values, value_count, columns.pp[0][row], limbs, error)) return;
        for (unsigned i = 0; i < 4; ++i) result[i] = limbs[i];
    } else if constexpr (Kind == 1) {
        if (row < first_permutation_row) {
            for (unsigned input = 0; input < 3; ++input) {
                if (!read_value(values, value_count, columns.pp[4 + input][row], limbs, error)) return;
                for (unsigned i = 0; i < 4; ++i) result[4 * input + i] = limbs[i];
            }
        } else {
            const unsigned pair = row - ((row - first_permutation_row) & 1u);
            const unsigned address = row == pair ? columns.pp[5][pair] : columns.pp[6][pair + 1];
            if (!read_value(values, value_count, address, limbs, error)) return;
            for (unsigned i = 0; i < 4; ++i) {
                result[4 + i] = limbs[i];
                result[8 + i] = limbs[i];
            }
        }
    } else if constexpr (Kind == 2) {
        std::uint32_t words[4];
        for (unsigned input = 0; input < 4; ++input) {
            if (!read_value(values, value_count, columns.pp[input][row], limbs, error)) return;
            words[input] = word(limbs);
        }
        for (unsigned i = 0; i < 4; ++i) {
            const unsigned lo = words[i] & 0xffffu;
            const unsigned hi = words[i] >> 16u;
            result[2 * i] = lo;
            result[2 * i + 1] = hi;
            result[8 + 2 * i] = lo >> 8u;
            result[9 + 2 * i] = hi >> 8u;
        }
        for (unsigned byte = 0; byte < 4; ++byte) {
            const unsigned shift = byte * 8u;
            result[16 + byte] = ((words[0] >> shift) ^ (words[1] >> shift)) & 255u;
            xor_count(columns, 0, 8, (words[0] >> shift) & 255u,
                (words[1] >> shift) & 255u, result[16 + byte], error);
            xor_count(columns, 0, 8, result[16 + byte],
                (words[2] >> shift) & 255u, (words[3] >> shift) & 255u, error);
        }
    } else if constexpr (Kind == 3) {
        if (!read_value(values, value_count, columns.pp[0][row], limbs, error)) return;
        const unsigned x = limbs[0];
        result[0] = x;
        result[1] = x & 0xffffu;
        result[2] = x >> 16u;
        result[3] = inverse(x);
        atomicAdd(columns.counts[21] + result[1], 1u);
        atomicAdd(columns.counts[21] + result[2], 1u);
        atomicAdd(columns.counts[21] + (32767u - result[2]), 1u);
    } else {
        std::uint32_t words[10];
        for (unsigned input = 0; input < 10; ++input) {
            if (!read_value(values, value_count, columns.pp[input][row], limbs, error)) return;
            words[input] = word(limbs);
            result[2 * input] = words[input] & 0xffffu;
            result[2 * input + 1] = words[input] >> 16u;
        }
        const unsigned a = words[0], b = words[1], c = words[2];
        const unsigned t0 = a + b + words[4];
        result[20] = t0 & 0xffffu; result[21] = t0 >> 16u;
        result[22] = result[20] >> 8u; result[23] = result[21] >> 8u;
        result[24] = result[6] >> 8u; result[25] = result[7] >> 8u;
        result[26] = (result[20] & 255u) ^ (result[6] & 255u);
        result[27] = result[22] ^ result[24];
        result[28] = (result[21] & 255u) ^ (result[7] & 255u);
        result[29] = result[23] ^ result[25];
        const unsigned xr16 = (result[28] + (result[29] << 8u)) |
            ((result[26] + (result[27] << 8u)) << 16u);
        const unsigned t1 = c + xr16;
        result[30] = t1 & 0xffffu; result[31] = t1 >> 16u;
        result[32] = result[2] >> 12u; result[33] = result[3] >> 12u;
        result[34] = result[30] >> 12u; result[35] = result[31] >> 12u;
        result[36] = (result[2] & 0xfffu) ^ (result[30] & 0xfffu);
        result[37] = result[32] ^ result[34];
        result[38] = (result[3] & 0xfffu) ^ (result[31] & 0xfffu);
        result[39] = result[33] ^ result[35];
        const unsigned xr12 = (result[37] + (result[38] << 4u)) |
            ((result[39] + (result[36] << 4u)) << 16u);
        result[40] = (words[6] & 0xffffu) >> 8u;
        result[41] = words[6] >> 24u;
        result[42] = (xr16 & 0xffffu) >> 8u;
        result[43] = xr16 >> 24u;
        result[44] = (words[9] & 0xffffu) >> 8u;
        result[45] = words[9] >> 24u;
        result[46] = (xr12 & 0xffffu) >> 7u;
        result[47] = xr12 >> 23u;
        result[48] = (words[8] & 0xffffu) >> 7u;
        result[49] = words[8] >> 23u;
        result[50] = (words[7] & 0xffffu) >> 9u;
        result[51] = words[7] >> 25u;

        xor_count(columns, 0, 8, result[20] & 255u, result[6] & 255u, result[26], error);
        xor_count(columns, 0, 8, result[22], result[24], result[27], error);
        xor_count(columns, 1, 8, result[21] & 255u, result[7] & 255u, result[28], error);
        xor_count(columns, 1, 8, result[23], result[25], result[29], error);
        xor_count(columns, 2, 12, result[2] & 0xfffu, result[30] & 0xfffu, result[36], error);
        xor_count(columns, 18, 4, result[32], result[34], result[37], error);
        xor_count(columns, 2, 12, result[3] & 0xfffu, result[31] & 0xfffu, result[38], error);
        xor_count(columns, 18, 4, result[33], result[35], result[39], error);
        xor_count(columns, 0, 8, result[40], result[42], (result[18] & 255u), error);
        xor_count(columns, 0, 8, result[13] & 255u, (xr16 >> 16u) & 255u,
            result[44], error);
        xor_count(columns, 0, 8, result[41], result[43], result[19] & 255u, error);
        xor_count(columns, 0, 8, result[12] & 255u, xr16 & 255u,
            result[45], error);
        xor_count(columns, 20, 9, result[46], result[48], result[14] & 511u, error);
        xor_count(columns, 19, 7, (xr12 >> 16u) & 127u, result[17] & 127u,
            result[50], error);
        xor_count(columns, 20, 9, result[47], result[49], result[15] & 511u, error);
        xor_count(columns, 19, 7, xr12 & 127u, result[16] & 127u,
            result[51], error);
    }
    constexpr unsigned widths[] = {4, 12, 20, 4, 52};
    for (unsigned column = 0; column < widths[Kind]; ++column)
        columns.out[column][row] = result[column];
}

#if !defined(STWO_CIRCUIT_BASE_HOST_EMULATION)
template <unsigned Kind>
__global__ void generate(
    const std::uint32_t *values, std::uint32_t value_count,
    std::uint32_t row_count, std::uint32_t first_permutation_row,
    Columns columns, std::uint32_t *error) {
    const unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row < row_count)
        generate_row<Kind>(values, value_count, row_count,
            first_permutation_row, columns, error, row);
}

template <unsigned Kind>
int launch(const std::uint32_t *values, std::uint32_t value_count,
    std::uint32_t row_count, std::uint32_t first_permutation_row,
    Columns columns, std::uint32_t *error, cudaStream_t stream) {
    const unsigned blocks = 1u + (row_count - 1u) / kThreads;
    generate<Kind><<<blocks, kThreads, 0, stream>>>(values, value_count,
        row_count, first_permutation_row, columns, error);
    return static_cast<int>(cudaGetLastError());
}
#endif

} // namespace stwo::cuda::circuit_base

#if !defined(STWO_CIRCUIT_BASE_HOST_EMULATION)
extern "C" int stwo_circuit_base_witness_on(
    unsigned component, const std::uint32_t *values, std::uint32_t value_count,
    std::uint32_t row_count, std::uint32_t first_permutation_row,
    const std::uint32_t *const *pp_host, unsigned pp_count,
    std::uint32_t *const *out_host, unsigned out_count,
    std::uint32_t *const *counts_host, unsigned count_count,
    std::uint32_t *error, void *stream) {
    using namespace stwo::cuda::circuit_base;
    constexpr unsigned pp_widths[] = {1, 7, 4, 1, 10};
    constexpr unsigned out_widths[] = {4, 12, 20, 4, 52};
    if (component >= 5 || values == nullptr || value_count == 0 ||
        row_count < 16 || (row_count & (row_count - 1u)) != 0 ||
        pp_host == nullptr || pp_count != pp_widths[component] ||
        out_host == nullptr || out_count != out_widths[component] ||
        counts_host == nullptr || count_count != kCountColumns ||
        error == nullptr || stream == nullptr ||
        (component == 1 && (first_permutation_row > row_count ||
            ((row_count - first_permutation_row) & 1u) != 0)))
        return static_cast<int>(cudaErrorInvalidValue);
    Columns columns{};
    for (unsigned i = 0; i < pp_count; ++i) {
        if (pp_host[i] == nullptr) return static_cast<int>(cudaErrorInvalidValue);
        columns.pp[i] = pp_host[i];
    }
    for (unsigned i = 0; i < out_count; ++i) {
        if (out_host[i] == nullptr) return static_cast<int>(cudaErrorInvalidValue);
        columns.out[i] = out_host[i];
    }
    for (unsigned i = 0; i < count_count; ++i) {
        if (counts_host[i] == nullptr) return static_cast<int>(cudaErrorInvalidValue);
        columns.counts[i] = counts_host[i];
    }
    const cudaStream_t cuda_stream = static_cast<cudaStream_t>(stream);
    switch (component) {
        case 0: return launch<0>(values, value_count, row_count, first_permutation_row, columns, error, cuda_stream);
        case 1: return launch<1>(values, value_count, row_count, first_permutation_row, columns, error, cuda_stream);
        case 2: return launch<2>(values, value_count, row_count, first_permutation_row, columns, error, cuda_stream);
        case 3: return launch<3>(values, value_count, row_count, first_permutation_row, columns, error, cuda_stream);
        default: return launch<4>(values, value_count, row_count, first_permutation_row, columns, error, cuda_stream);
    }
}
#else
extern "C" int stwo_circuit_base_witness_emulate(
    unsigned component, const std::uint32_t *values, std::uint32_t value_count,
    std::uint32_t row_count, std::uint32_t first_permutation_row,
    const std::uint32_t *const *pp_host, unsigned pp_count,
    std::uint32_t *const *out_host, unsigned out_count,
    std::uint32_t *const *counts_host, unsigned count_count,
    std::uint32_t *error) {
    using namespace stwo::cuda::circuit_base;
    constexpr unsigned pp_widths[] = {1, 7, 4, 1, 10};
    constexpr unsigned out_widths[] = {4, 12, 20, 4, 52};
    if (component >= 5 || values == nullptr || value_count == 0 ||
        row_count < 16 || (row_count & (row_count - 1u)) != 0 ||
        pp_host == nullptr || pp_count != pp_widths[component] ||
        out_host == nullptr || out_count != out_widths[component] ||
        counts_host == nullptr || count_count != kCountColumns || error == nullptr)
        return 1;
    Columns columns{};
    for (unsigned i = 0; i < pp_count; ++i) columns.pp[i] = pp_host[i];
    for (unsigned i = 0; i < out_count; ++i) columns.out[i] = out_host[i];
    for (unsigned i = 0; i < count_count; ++i) columns.counts[i] = counts_host[i];
    for (unsigned row = 0; row < row_count; ++row) {
        switch (component) {
            case 0: generate_row<0>(values, value_count, row_count, first_permutation_row, columns, error, row); break;
            case 1: generate_row<1>(values, value_count, row_count, first_permutation_row, columns, error, row); break;
            case 2: generate_row<2>(values, value_count, row_count, first_permutation_row, columns, error, row); break;
            case 3: generate_row<3>(values, value_count, row_count, first_permutation_row, columns, error, row); break;
            default: generate_row<4>(values, value_count, row_count, first_permutation_row, columns, error, row); break;
        }
    }
    return 0;
}
#endif
