#ifndef FRI_FOLD_LINE_H
#define FRI_FOLD_LINE_H

#include "fields.cuh"

extern "C"
void fold_line(uint32_t *gpu_domain, uint32_t twiddle_offset, uint32_t n, uint32_t **eval_values, qm31 alpha, uint32_t **folded_values);

// Allocation-free, graph-capturable variant. Both pointer tables already live
// on the device and the launch is enqueued on the caller's explicit stream.
extern "C"
int stwo_fold_line_on(const uint32_t *gpu_domain,
                      uint32_t twiddle_offset,
                      uint32_t n,
                      uint32_t **eval_values,
                      const qm31 *alpha,
                      uint32_t alpha_squarings,
                      uint32_t **folded_values,
                      void *stream);

#endif // FRI_FOLD_LINE_H
