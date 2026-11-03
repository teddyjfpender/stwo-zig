#ifndef STWO_CUDA_MIXED_LAYOUT_H
#define STWO_CUDA_MIXED_LAYOUT_H
#include <stddef.h>
#include <stdint.h>
namespace stwo::cuda::blake2s {
struct MixedSegment {
  const uint32_t *columns;
  size_t stride_words, capacity_words;
  uint32_t source_size, reserved;
};
static constexpr uint32_t kMaxMixedSegments = 96;
static_assert(sizeof(MixedSegment) == 32, "mixed leaf segment ABI");
} // namespace stwo::cuda::blake2s
#endif
