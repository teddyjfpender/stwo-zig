#pragma once
#include "../oods/field.cuh"
namespace stwo::cuda::quotient_tiny {
// The DEEP subdomain retains the initial point of the full canonical domain.
// In particular its two-row inverse is NOT the canonical two-row inverse.
// This is the original circle inverse butterfly for two/four arbitrary coset
// points; all point construction and inverses occur on the device.
__host__ __device__ __forceinline__ bool invert(
    std::uint32_t* values, std::uint32_t log, std::uint32_t initial_index) {
    using namespace stwo::cuda::oods;
    if (log < 1 || log > 2 || initial_index != (1u << (29u-log))) return false;
    const CirclePoint point = point_pow(kCircleGenerator, initial_index);
    if (!point.y || (log == 2 && !point.x)) return false;
    const M31 yi = inverse(point.y), ni = 1u << (31u-log);
    const M31 a=values[0], b=values[1];
    values[0]=add(a,b); values[1]=mul(sub(a,b),yi);
    if (log == 2) {
        const M31 c=values[2], d=values[3], xi=inverse(point.x);
        values[2]=add(c,d); values[3]=mul(sub(c,d),neg(yi));
        const M31 e=values[0], f=values[2], g=values[1], h=values[3];
        values[0]=add(e,f); values[2]=mul(sub(e,f),xi);
        values[1]=add(g,h); values[3]=mul(sub(g,h),xi);
    }
    for (std::uint32_t i=0;i<(1u<<log);++i) values[i]=mul(values[i],ni);
    return true;
}
}
