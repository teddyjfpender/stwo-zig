#include "lookup_tuples.cuh"

namespace stwo::cuda::circuit_interaction {
__host__ __device__ __forceinline__ QM31 combine(const Lookup &lookup, const QM31 *powers, QM31 z) {
    QM31 sum = f::sub(f::zero(), z);
    for (unsigned i = 0; i < lookup.len; ++i)
        sum = f::add(sum, f::mul(lookup.tuple[i], powers[i]));
    return sum;
}

__host__ __device__ __forceinline__ bool is_zero(QM31 value) {
    return (value.a.a | value.a.b | value.b.a | value.b.b) == 0u;
}

template <unsigned Kind>
__host__ __device__ __forceinline__ void fraction_at(
    unsigned row, unsigned column, unsigned rows, const Columns &columns,
    const QM31 *powers, QM31 z, QM31 *denominators, unsigned *error) {
    const unsigned first_index = 2u * column;
    const Lookup first = lookup_at<Kind>(first_index, row, columns);
    const QM31 d0 = combine(first, powers, z);
    QM31 numerator, denominator;
    if (first_index + 1u < lookup_count<Kind>()) {
        const Lookup second = lookup_at<Kind>(first_index + 1u, row, columns);
        const QM31 d1 = combine(second, powers, z);
        numerator = f::add(f::mul(first.numerator, d1), f::mul(second.numerator, d0));
        denominator = f::mul(d0, d1);
    } else {
        numerator = f::mul(first.numerator, f::one());
        denominator = d0;
    }
    if (is_zero(denominator)) {
#if defined(__CUDA_ARCH__)
        atomicOr(error, 2u);
#else
        *error |= 2u;
#endif
    }
    const unsigned at = 4u * column;
    columns.out[at][row] = numerator.a.a;
    columns.out[at + 1u][row] = numerator.a.b;
    columns.out[at + 2u][row] = numerator.b.a;
    columns.out[at + 3u][row] = numerator.b.b;
    denominators[column * rows + row] = denominator;
}

#if !defined(STWO_CIRCUIT_INTERACTION_HOST_EMULATION)
template <unsigned Kind>
__global__ void generate(unsigned rows, Columns columns, const QM31 *powers,
    const QM31 *z, QM31 *denominators, unsigned *error) {
    const unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
    const unsigned column = blockIdx.y;
    if (row < rows) fraction_at<Kind>(row, column, rows, columns,
        powers, z[0], denominators, error);
}

template <unsigned Kind>
int launch(unsigned rows, Columns columns, const QM31 *powers,
    const QM31 *z, QM31 *denominators, unsigned *error, cudaStream_t stream) {
    const dim3 blocks(1u + (rows - 1u) / kThreads, kSecure[Kind]);
    generate<Kind><<<blocks, kThreads, 0, stream>>>(rows, columns,
        powers, z, denominators, error);
    return static_cast<int>(cudaGetLastError());
}
#endif

} // namespace stwo::cuda::circuit_interaction

#if !defined(STWO_CIRCUIT_INTERACTION_HOST_EMULATION)
extern "C" int stwo_circuit_interaction_fractions_on(
    unsigned component, unsigned rows,
    const std::uint32_t *const *pp_host, unsigned pp_count,
    const std::uint32_t *const *base_host, unsigned base_count,
    std::uint32_t *const *out_host, unsigned out_count,
    const stwo::cuda::oods::QM31 *powers, unsigned power_count,
    const stwo::cuda::oods::QM31 *z,
    stwo::cuda::oods::QM31 *denominators, unsigned denominator_count,
    unsigned *error, void *stream) {
    using namespace stwo::cuda::circuit_interaction;
    if (component >= kComponents || rows < 16u || (rows & (rows - 1u)) != 0u ||
        pp_count != kPpWidths[component] || base_count != kBaseWidths[component] ||
        out_count != 4u * kSecure[component] || power_count != 6u ||
        denominator_count != kSecure[component] * rows ||
        pp_host == nullptr || base_host == nullptr || out_host == nullptr ||
        powers == nullptr || z == nullptr || denominators == nullptr ||
        error == nullptr || stream == nullptr)
        return static_cast<int>(cudaErrorInvalidValue);
    Columns columns{};
    for (unsigned i = 0; i < pp_count; ++i) {
        if (pp_host[i] == nullptr) return static_cast<int>(cudaErrorInvalidValue);
        columns.pp[i] = pp_host[i];
    }
    for (unsigned i = 0; i < base_count; ++i) {
        if (base_host[i] == nullptr) return static_cast<int>(cudaErrorInvalidValue);
        columns.base[i] = base_host[i];
    }
    for (unsigned i = 0; i < out_count; ++i) {
        if (out_host[i] == nullptr) return static_cast<int>(cudaErrorInvalidValue);
        columns.out[i] = out_host[i];
    }
    const cudaStream_t cuda_stream = static_cast<cudaStream_t>(stream);
    switch (component) {
        case 0: return launch<0>(rows, columns, powers, z, denominators, error, cuda_stream);
        case 1: return launch<1>(rows, columns, powers, z, denominators, error, cuda_stream);
        case 2: return launch<2>(rows, columns, powers, z, denominators, error, cuda_stream);
        case 3: return launch<3>(rows, columns, powers, z, denominators, error, cuda_stream);
        case 4: return launch<4>(rows, columns, powers, z, denominators, error, cuda_stream);
        case 5: return launch<5>(rows, columns, powers, z, denominators, error, cuda_stream);
        case 6: return launch<6>(rows, columns, powers, z, denominators, error, cuda_stream);
        case 7: return launch<7>(rows, columns, powers, z, denominators, error, cuda_stream);
        case 8: return launch<8>(rows, columns, powers, z, denominators, error, cuda_stream);
        case 9: return launch<9>(rows, columns, powers, z, denominators, error, cuda_stream);
        default: return launch<10>(rows, columns, powers, z, denominators, error, cuda_stream);
    }
}
#else
extern "C" int stwo_circuit_interaction_fractions_emulate(
    unsigned component, unsigned rows,
    const std::uint32_t *const *pp_host, unsigned pp_count,
    const std::uint32_t *const *base_host, unsigned base_count,
    std::uint32_t *const *out_host, unsigned out_count,
    const stwo::cuda::oods::QM31 *powers, unsigned power_count,
    const stwo::cuda::oods::QM31 *z,
    stwo::cuda::oods::QM31 *denominators, unsigned denominator_count,
    unsigned *error) {
    using namespace stwo::cuda::circuit_interaction;
    if (component >= kComponents || rows < 16u || (rows & (rows - 1u)) != 0u ||
        pp_count != kPpWidths[component] || base_count != kBaseWidths[component] ||
        out_count != 4u * kSecure[component] || power_count != 6u ||
        denominator_count != kSecure[component] * rows)
        return 1;
    Columns columns{};
    for (unsigned i = 0; i < pp_count; ++i) columns.pp[i] = pp_host[i];
    for (unsigned i = 0; i < base_count; ++i) columns.base[i] = base_host[i];
    for (unsigned i = 0; i < out_count; ++i) columns.out[i] = out_host[i];
#define STWO_EMULATE_CASE(K) case K: fraction_at<K>(row, column, rows, columns, powers, z[0], denominators, error); break
    for (unsigned column = 0; column < kSecure[component]; ++column)
        for (unsigned row = 0; row < rows; ++row)
            switch (component) {
                STWO_EMULATE_CASE(0); STWO_EMULATE_CASE(1); STWO_EMULATE_CASE(2);
                STWO_EMULATE_CASE(3); STWO_EMULATE_CASE(4); STWO_EMULATE_CASE(5);
                STWO_EMULATE_CASE(6); STWO_EMULATE_CASE(7); STWO_EMULATE_CASE(8);
                STWO_EMULATE_CASE(9); STWO_EMULATE_CASE(10);
            }
#undef STWO_EMULATE_CASE
    return 0;
}
#endif
