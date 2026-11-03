#ifndef STWO_CUDA_RV64_TRACE_H
#define STWO_CUDA_RV64_TRACE_H
#include "../commitment/mixed_layout.h"
struct StwoRv64TraceOpen {
  const uint32_t *tree, *queries;
  uint32_t *values, *paths, *status;
  uint64_t tree_words, value_words, path_words;
  uint32_t tree_log, lifting_log, query_count, reserved;
};
static_assert(sizeof(StwoRv64TraceOpen) == 80, "trace opening ABI");
// Segments are in stable ascending column-height order, as native lifted PCS.
// Each segment is a contiguous column-major slab. Numeric buffers stay device
// resident; host segment geometry is copied into the launch parameters.
extern "C" int
stwo_rv64_trace_tree_on(void *, uint32_t,
                        const stwo::cuda::blake2s::MixedSegment *, uint32_t,
                        uint32_t, uint32_t *, uint64_t);
extern "C" int
stwo_rv64_trace_open_on(void *, uint32_t,
                        const stwo::cuda::blake2s::MixedSegment *, uint32_t,
                        const StwoRv64TraceOpen *);
#endif
