#ifndef STWO_CUDA_RV64_JOBS_OODS_POINTS_H
#define STWO_CUDA_RV64_JOBS_OODS_POINTS_H
// Device OODS point for the M8 jobs (libstwo-rv64-jobs.so). The secure-field
// draw t (8 M31 words, already drawn on the device channel) becomes the OODS
// circle point ((1-t^2)/(1+t^2), 2t/(1+t^2)) -- the host
// secureFieldPointFromRandomSeedCheckedFor -- and the PCS-imported base point
// oods + shift, where shift is the challenge-independent M31 mask offset of the
// request's first sample (jobs/native_pcs.zig baseShift).
// out[0..16] = oods x[8], y[8]; out[16..32] = base x[8], y[8].
// *status = 0 (ok), 2 (noncanonical t or shift) or 4 (1+t^2 == 0 or shift off
// circle); on failure both points are zero, so the PCS on-circle check of the
// imported point also fails closed. Single-thread kernel, enqueue only.
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int stwo_rv64_job_oods_points_v1(void *ctx, uint32_t lane, const uint32_t *draw,
                                 uint32_t shift_x, uint32_t shift_y,
                                 uint32_t *out, uint32_t *status);
#ifdef __cplusplus
}
#endif
#endif
