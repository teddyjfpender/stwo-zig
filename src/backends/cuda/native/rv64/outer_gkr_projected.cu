// Source-specialized callbacks for the shared lazy-fraction GKR traversal.
// Requires native-path's projected_gkr.cuh; no host synchronization or input
// fraction allocation occurs in these entry points.
#include "outer_gkr_projector.cuh"
#include "projected_gkr.cuh"

namespace stwo::cuda::rv64::outer_gkr {
template<class Invoke> int dispatch(const void *raw, Invoke invoke) {
  if (!raw) return int(cudaErrorInvalidValue);
  const auto input = *static_cast<const StwoCircuitOuterGkrSource *>(raw);
  if (!valid_source(input)) return int(cudaErrorInvalidValue);
  switch (input.component) {
    case 2: return invoke(Source<2>{input});
    case 3: return invoke(Source<3>{input});
    case 4: return invoke(Source<4>{input});
    case 6: return invoke(Source<6>{input});
    default: return int(cudaErrorInvalidValue);
  }
}
} // namespace stwo::cuda::rv64::outer_gkr

extern "C" int stwo_circuit_outer_gkr_validate_on(void *ctx, uint32_t lane,
                                                 const void *raw, uint32_t count) {
  using namespace stwo::cuda::rv64;
  return outer_gkr::dispatch(raw, [&](auto source) {
    return projected::validate_on<decltype(source)>(ctx, lane, &source, count);
  });
}
extern "C" int stwo_circuit_outer_gkr_layer_on(void *ctx, uint32_t lane,
                                              const void *raw, uint32_t count,
                                              uint32_t levels, StwoRv64Plane n,
                                              StwoRv64Plane d) {
  using namespace stwo::cuda::rv64;
  return outer_gkr::dispatch(raw, [&](auto source) {
    return projected::layer_on<decltype(source)>(ctx, lane, &source, count, levels, n, d);
  });
}
extern "C" int stwo_circuit_outer_gkr_sum_on(void *ctx, uint32_t lane,
                                            const void *raw, uint32_t count,
                                            StwoRv64Plane eq, const uint32_t *lambda,
                                            StwoRv64Plane a, StwoRv64Plane b,
                                            StwoRv64Plane out) {
  using namespace stwo::cuda::rv64;
  return outer_gkr::dispatch(raw, [&](auto source) {
    return projected::sum_on<decltype(source)>(ctx, lane, &source, count, eq, lambda, a, b, out);
  });
}
extern "C" int stwo_circuit_outer_gkr_fold_on(void *ctx, uint32_t lane,
                                             const void *raw, uint32_t count,
                                             const uint32_t *assignment,
                                             StwoRv64Plane n, StwoRv64Plane d) {
  using namespace stwo::cuda::rv64;
  return outer_gkr::dispatch(raw, [&](auto source) {
    return projected::fold_on<decltype(source)>(ctx, lane, &source, count, assignment, n, d);
  });
}
extern "C" int stwo_circuit_outer_gkr_mask_on(void *ctx, uint32_t lane,
                                             const void *raw, uint32_t *out) {
  using namespace stwo::cuda::rv64;
  return outer_gkr::dispatch(raw, [&](auto source) {
    return projected::mask_on<decltype(source)>(ctx, lane, &source, out);
  });
}
