#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>

namespace {

constexpr std::uint32_t kM31P = 2147483647u;
constexpr std::uint32_t kBlock = 256u;

enum ExtSourceKind : std::uint32_t {
    kConstant = 0,
    kLookupZ = 1,
    kLookupAlphaPower = 2,
    kClaimedSumScaled = 3,
    kLookupAlphaPowerScaled = 4,
};

struct ExtSourceDescriptor {
    ExtSourceKind kind;
    std::uint32_t source_index;
    std::uint32_t scale;
    std::uint32_t reserved;
    std::uint32_t constant[4];
};

static_assert(sizeof(ExtSourceDescriptor) == 32);

__device__ __forceinline__ std::uint32_t m31_mul(
    std::uint32_t lhs,
    std::uint32_t rhs) {
    std::uint64_t value =
        static_cast<std::uint64_t>(lhs) * rhs;
    value = (value & kM31P) + (value >> 31u);
    value = (value & kM31P) + (value >> 31u);
    return value == kM31P
        ? 0u
        : static_cast<std::uint32_t>(value);
}

__global__ void materialize_params(
    std::uint32_t *arena,
    const ExtSourceDescriptor *descriptors,
    std::uint32_t descriptor_count,
    std::uint64_t z_offset,
    std::uint64_t alpha_power_offset,
    std::uint32_t alpha_power_count,
    std::uint64_t claimed_sum_offset,
    std::uint32_t claimed_sum_count,
    std::uint64_t output_offset) {
    const std::uint32_t index =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= descriptor_count) return;

    const ExtSourceDescriptor descriptor = descriptors[index];
    const std::uint32_t *source = nullptr;
    switch (descriptor.kind) {
        case kConstant:
            source = descriptor.constant;
            break;
        case kLookupZ:
            source = arena + z_offset;
            break;
        case kLookupAlphaPower:
        case kLookupAlphaPowerScaled:
            if (descriptor.source_index >= alpha_power_count) return;
            source = arena + alpha_power_offset +
                static_cast<std::uint64_t>(descriptor.source_index) * 4u;
            break;
        case kClaimedSumScaled:
            if (descriptor.source_index >= claimed_sum_count) return;
            source = arena + claimed_sum_offset +
                static_cast<std::uint64_t>(descriptor.source_index) * 4u;
            break;
        default:
            return;
    }
    const std::uint64_t destination =
        output_offset + static_cast<std::uint64_t>(index) * 4u;
    #pragma unroll
    for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
        arena[destination + coordinate] =
            m31_mul(source[coordinate], descriptor.scale);
    }
}

bool range_valid(
    std::uint64_t offset,
    std::uint64_t count,
    std::uint64_t capacity) {
    return count != 0 && offset < capacity &&
        count <= capacity - offset;
}

}  // namespace

extern "C" int stwo_cairo_eval_materialize_params_on(
    std::uint32_t *arena,
    std::uint64_t arena_words,
    std::uint64_t descriptor_offset,
    std::uint32_t descriptor_count,
    std::uint64_t z_offset,
    std::uint64_t alpha_power_offset,
    std::uint32_t alpha_power_count,
    std::uint64_t claimed_sum_offset,
    std::uint32_t claimed_sum_count,
    std::uint64_t output_offset,
    std::uint64_t output_words,
    cudaStream_t proof_stream,
    std::uint32_t *launches_out) {
    const std::uint64_t descriptor_words =
        static_cast<std::uint64_t>(descriptor_count) * 8u;
    if (arena == nullptr || proof_stream == nullptr ||
        launches_out == nullptr || descriptor_count == 0 ||
        alpha_power_count == 0 || claimed_sum_count == 0 ||
        output_words !=
            static_cast<std::uint64_t>(descriptor_count) * 4u ||
        !range_valid(descriptor_offset, descriptor_words, arena_words) ||
        !range_valid(z_offset, 4, arena_words) ||
        !range_valid(
            alpha_power_offset,
            static_cast<std::uint64_t>(alpha_power_count) * 4u,
            arena_words) ||
        !range_valid(
            claimed_sum_offset,
            static_cast<std::uint64_t>(claimed_sum_count) * 4u,
            arena_words) ||
        !range_valid(output_offset, output_words, arena_words)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const auto *descriptors =
        reinterpret_cast<const ExtSourceDescriptor *>(
            arena + descriptor_offset);
    const std::uint32_t blocks =
        (descriptor_count + kBlock - 1u) / kBlock;
    materialize_params<<<blocks, kBlock, 0, proof_stream>>>(
        arena,
        descriptors,
        descriptor_count,
        z_offset,
        alpha_power_offset,
        alpha_power_count,
        claimed_sum_offset,
        claimed_sum_count,
        output_offset);
    const cudaError_t status = cudaGetLastError();
    if (status != cudaSuccess) return static_cast<int>(status);
    *launches_out = 1;
    return 0;
}
