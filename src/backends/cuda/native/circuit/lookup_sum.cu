// Circuit global LogUp check: eleven claimed sums, the public output gates,
// and the fixed u wire. A nonzero sum disqualifies the proof on device.
#include <cuda_runtime_api.h>
#include "../oods/field.cuh"

#include <cstdint>

namespace stwo::cuda::circuit_lookup_sum {
namespace f = stwo::cuda::oods;
using QM31 = f::QM31;
constexpr unsigned kGate = 378353459u;
constexpr unsigned kUVariable = 2u;

__host__ __device__ __forceinline__ bool is_zero(QM31 x) {
    return (x.a.a | x.a.b | x.b.a | x.b.b) == 0u;
}

__host__ __device__ __forceinline__ QM31 gate_denominator(
    const QM31 *powers, QM31 z, unsigned address, QM31 value) {
    QM31 combined = f::sub(f::zero(), z);
    combined = f::add(combined, f::mul(kGate, powers[0]));
    combined = f::add(combined, f::mul(address, powers[1]));
    combined = f::add(combined, f::mul(value.a.a, powers[2]));
    combined = f::add(combined, f::mul(value.a.b, powers[3]));
    combined = f::add(combined, f::mul(value.b.a, powers[4]));
    combined = f::add(combined, f::mul(value.b.b, powers[5]));
    return combined;
}

__host__ __device__ __forceinline__ void check(
    const QM31 *claims, const QM31 *outputs, unsigned output_count,
    const QM31 *powers, QM31 z, unsigned *error) {
    QM31 total = f::zero();
    for (unsigned i = 0; i < 11; ++i) total = f::add(total, claims[i]);
    for (unsigned i = 0; i < output_count; ++i) {
        const QM31 denominator = gate_denominator(powers, z, kUVariable + 1u + i, outputs[i]);
        if (is_zero(denominator)) { atomicOr(error, 4u); return; }
        total = f::add(total, f::inverse(denominator));
    }
    const QM31 u_value{{0u, 0u}, {1u, 0u}};
    const QM31 denominator = gate_denominator(powers, z, kUVariable, u_value);
    if (is_zero(denominator)) { atomicOr(error, 4u); return; }
    total = f::add(total, f::inverse(denominator));
    if (!is_zero(total)) atomicOr(error, 4u);
}

#if !defined(STWO_CIRCUIT_LOOKUP_SUM_HOST_EMULATION)
__global__ void kernel(const QM31 *claims, const QM31 *outputs,
    unsigned output_count, const QM31 *powers, const QM31 *z, unsigned *error) {
    if (blockIdx.x == 0u && threadIdx.x == 0u)
        check(claims, outputs, output_count, powers, z[0], error);
}
#endif
} // namespace stwo::cuda::circuit_lookup_sum

#if !defined(STWO_CIRCUIT_LOOKUP_SUM_HOST_EMULATION)
extern "C" int stwo_circuit_lookup_sum_on(
    const stwo::cuda::oods::QM31 *claims,
    const stwo::cuda::oods::QM31 *outputs, unsigned output_count,
    const stwo::cuda::oods::QM31 *powers, unsigned power_count,
    const stwo::cuda::oods::QM31 *z, unsigned *error, void *stream) {
    if (claims == nullptr || (outputs == nullptr && output_count != 0u) ||
        powers == nullptr || power_count != 6u || z == nullptr ||
        error == nullptr || stream == nullptr)
        return static_cast<int>(cudaErrorInvalidValue);
    stwo::cuda::circuit_lookup_sum::kernel<<<1, 1, 0,
        static_cast<cudaStream_t>(stream)>>>(claims, outputs,
        output_count, powers, z, error);
    return static_cast<int>(cudaGetLastError());
}
#else
extern "C" int stwo_circuit_lookup_sum_emulate(
    const stwo::cuda::oods::QM31 *claims,
    const stwo::cuda::oods::QM31 *outputs, unsigned output_count,
    const stwo::cuda::oods::QM31 *powers, unsigned power_count,
    const stwo::cuda::oods::QM31 *z, unsigned *error) {
    if (claims == nullptr || (outputs == nullptr && output_count != 0u) ||
        powers == nullptr || power_count != 6u || z == nullptr || error == nullptr)
        return 1;
    stwo::cuda::circuit_lookup_sum::check(claims, outputs,
        output_count, powers, z[0], error);
    return 0;
}
#endif
