// Resident Cairo memory execution-table construction.
//
// The 9-bit split is formula-for-formula equivalent to stwo-cairo-common's
// little-endian `split` and the imported CUDA authority's memory_witness.cu.

#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>

namespace {

constexpr std::uint32_t kBlockThreads = 256;
constexpr std::uint32_t kLimbBits = 9;
constexpr std::uint32_t kLimbMask = (1u << kLimbBits) - 1u;
constexpr std::uint32_t kMaximumLimbs = 28;

struct OutputColumns {
    std::uint32_t *values[kMaximumLimbs];
};

template <int WordCount, int LimbCount>
__device__ __forceinline__ void split_le_9bit(
    const std::uint32_t *words,
    std::uint32_t *limbs) {
    std::uint32_t bits_in_word = 32;
    std::uint32_t word_index = 0;
    std::uint32_t word = words[0];
    for (int limb = 0; limb < LimbCount; ++limb) {
        if (bits_in_word > kLimbBits) {
            limbs[limb] = word & kLimbMask;
            word >>= kLimbBits;
            bits_in_word -= kLimbBits;
            continue;
        }
        limbs[limb] = word;
        ++word_index;
        word = word_index < WordCount ? words[word_index] : 0;
        if (bits_in_word < kLimbBits) {
            limbs[limb] |=
                (word << bits_in_word) & kLimbMask;
            word >>= kLimbBits - bits_in_word;
        }
        bits_in_word += 32 - kLimbBits;
    }
}

template <int WordCount, int LimbCount>
__global__ void split_columns(
    const std::uint32_t *values,
    std::uint32_t value_count,
    std::uint32_t row_count,
    OutputColumns outputs) {
    const std::uint32_t row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) return;
    std::uint32_t words[WordCount] = {};
    if (row < value_count) {
        for (int word = 0; word < WordCount; ++word) {
            words[word] =
                values[static_cast<std::size_t>(row) * WordCount + word];
        }
    }
    std::uint32_t limbs[LimbCount];
    split_le_9bit<WordCount, LimbCount>(words, limbs);
    for (int limb = 0; limb < LimbCount; ++limb) {
        outputs.values[limb][row] = limbs[limb];
    }
}

template <int WordCount, int LimbCount>
int launch_split(
    const std::uint32_t *values,
    std::uint32_t value_count,
    std::uint32_t row_count,
    std::uint32_t *const *outputs_host,
    cudaStream_t stream) {
    if (row_count == 0 || value_count > row_count ||
        (value_count != 0 && values == nullptr) ||
        outputs_host == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    OutputColumns outputs{};
    for (int limb = 0; limb < LimbCount; ++limb) {
        if (outputs_host[limb] == nullptr) {
            return static_cast<int>(cudaErrorInvalidDevicePointer);
        }
        outputs.values[limb] = outputs_host[limb];
    }
    const std::uint32_t blocks =
        1u + (row_count - 1u) / kBlockThreads;
    split_columns<WordCount, LimbCount>
        <<<blocks, kBlockThreads, 0, stream>>>(
            values,
            value_count,
            row_count,
            outputs);
    return static_cast<int>(cudaGetLastError());
}

}  // namespace

extern "C" int stwo_cairo_memory_split_big_on(
    const std::uint32_t *values,
    std::uint32_t value_count,
    std::uint32_t row_count,
    std::uint32_t *const *outputs_host,
    void *stream) {
    return launch_split<8, 28>(
        values,
        value_count,
        row_count,
        outputs_host,
        static_cast<cudaStream_t>(stream));
}

extern "C" int stwo_cairo_memory_split_small_on(
    const std::uint32_t *values,
    std::uint32_t value_count,
    std::uint32_t row_count,
    std::uint32_t *const *outputs_host,
    void *stream) {
    return launch_split<4, 8>(
        values,
        value_count,
        row_count,
        outputs_host,
        static_cast<cudaStream_t>(stream));
}
