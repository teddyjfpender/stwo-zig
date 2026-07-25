typedef unsigned long long u64;

#define STWO_M31_P 2147483647u

#ifndef STWO_M31_FAST32_GLOBAL
#define STWO_M31_FAST32_GLOBAL 0
#endif
#if STWO_M31_FAST32_GLOBAL != 0 && STWO_M31_FAST32_GLOBAL != 1
#error "STWO_M31_FAST32_GLOBAL must be 0 or 1"
#endif

__device__ __forceinline__ unsigned stwo_m31_add(unsigned lhs, unsigned rhs) {
    unsigned sum = lhs + rhs;
    return sum >= STWO_M31_P ? sum - STWO_M31_P : sum;
}

__device__ __forceinline__ unsigned stwo_m31_sub(unsigned lhs, unsigned rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
}

__device__ __forceinline__ unsigned stwo_m31_neg(unsigned value) {
    unsigned negated = STWO_M31_P - value;
    return negated == STWO_M31_P ? 0u : negated;
}

__device__ __forceinline__ unsigned stwo_m31_mul(unsigned lhs, unsigned rhs) {
#if STWO_M31_FAST32_GLOBAL
    unsigned lo = lhs * rhs;
    unsigned hi = __umulhi(lhs, rhs);
    unsigned quotient = (hi << 1) | (lo >> 31);
    unsigned reduced = (lo & STWO_M31_P) + quotient;
    reduced = (reduced & STWO_M31_P) + (reduced >> 31);
    return reduced == STWO_M31_P ? 0u : reduced;
#else
    u64 product = (u64)lhs * (u64)rhs;
    u64 reduced = (((((product >> 31) + product + 1u) >> 31) + product) & (u64)STWO_M31_P);
    return (unsigned)reduced;
#endif
}

#define STWO_WIT_NEEDS_PEDERSEN 1
// ---- fp256/EC embed prelude (self-contained TU: no headers resolved) ----
#define STWO_WIT_EMBED 1
namespace std {}
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned int m31;
#define UINT32_MAX 0xFFFFFFFFu
#if !defined(__align__)
#define __align__(n) alignas(n)
#endif
// NVRTC compiles device code ONLY and its JIT mode hard-errors on any function
// carrying __host__ (alone). HOST_* therefore lower to plain __device__ here:
// host-only chain functions become dead device functions and are discarded,
// while literal `__host__` sites in the chain sit behind !__CUDACC_RTC__ guards.
#define HOST_INLINE __device__ __forceinline__
#define DEVICE_INLINE __device__ __forceinline__
#define HOST_DEVICE_INLINE __device__ __forceinline__
extern "C" __device__ int printf(const char*, ...);


using namespace std;

#define LIMBS_ALIGNMENT(x) ((x) % 4 == 0 ? 16 : ((x) % 2 == 0 ? 8 : 4))

template <unsigned LIMBS_COUNT> struct __align__(LIMBS_ALIGNMENT(LIMBS_COUNT)) ff_storage
{
    static constexpr unsigned LC = LIMBS_COUNT;
    uint32_t limbs[LIMBS_COUNT];
};

template <unsigned LIMBS_COUNT> struct __align__(LIMBS_ALIGNMENT(LIMBS_COUNT)) ff_storage_wide
{
    // Message form: NVRTC JIT mode (the witness embed) rejects one-arg static_assert.
    static_assert(LIMBS_COUNT ^ 1, "ff_storage_wide requires LIMBS_COUNT != 1");
    static constexpr unsigned LC = LIMBS_COUNT;
    static constexpr unsigned LC2 = LIMBS_COUNT * 2;
    uint32_t limbs[LC2];

    void __device__ __forceinline__ set_lo(const ff_storage<LIMBS_COUNT> &in)
    {
#pragma unroll
        for (unsigned i = 0; i < LC; i++)
            limbs[i] = in.limbs[i];
    }

    void __device__ __forceinline__ set_hi(const ff_storage<LIMBS_COUNT> &in)
    {
#pragma unroll
        for (unsigned i = 0; i < LC; i++)
            limbs[i + LC].x = in.limbs[i];
    }

    ff_storage<LC> __device__ __forceinline__ get_lo()
    {
        ff_storage<LC> out{};
#pragma unroll
        for (unsigned i = 0; i < LC; i++)
            out.limbs[i] = limbs[i];
        return out;
    }

    ff_storage<LC> __device__ __forceinline__ get_hi()
    {
        ff_storage<LC> out{};
#pragma unroll
        for (unsigned i = 0; i < LC; i++)
            out.limbs[i] = limbs[i + LC].x;
        return out;
    }
};

namespace ptx
{

__device__ __forceinline__ uint32_t add(const uint32_t x, const uint32_t y)
{
    uint32_t result;
    asm("add.u32 %0, %1, %2;" : "=r"(result) : "r"(x), "r"(y));
    return result;
}

__device__ __forceinline__ uint32_t add_cc(const uint32_t x, const uint32_t y)
{
    uint32_t result;
    asm volatile("add.cc.u32 %0, %1, %2;" : "=r"(result) : "r"(x), "r"(y));
    return result;
}

__device__ __forceinline__ uint32_t addc(const uint32_t x, const uint32_t y)
{
    uint32_t result;
    asm volatile("addc.u32 %0, %1, %2;" : "=r"(result) : "r"(x), "r"(y));
    return result;
}

__device__ __forceinline__ uint32_t addc_cc(const uint32_t x, const uint32_t y)
{
    uint32_t result;
    asm volatile("addc.cc.u32 %0, %1, %2;" : "=r"(result) : "r"(x), "r"(y));
    return result;
}

__device__ __forceinline__ uint32_t sub(const uint32_t x, const uint32_t y)
{
    uint32_t result;
    asm("sub.u32 %0, %1, %2;" : "=r"(result) : "r"(x), "r"(y));
    return result;
}

__device__ __forceinline__ uint32_t sub_cc(const uint32_t x, const uint32_t y)
{
    uint32_t result;
    asm volatile("sub.cc.u32 %0, %1, %2;" : "=r"(result) : "r"(x), "r"(y));
    return result;
}

__device__ __forceinline__ uint32_t subc(const uint32_t x, const uint32_t y)
{
    uint32_t result;
    asm volatile("subc.u32 %0, %1, %2;" : "=r"(result) : "r"(x), "r"(y));
    return result;
}

__device__ __forceinline__ uint32_t subc_cc(const uint32_t x, const uint32_t y)
{
    uint32_t result;
    asm volatile("subc.cc.u32 %0, %1, %2;" : "=r"(result) : "r"(x), "r"(y));
    return result;
}

__device__ __forceinline__ uint32_t mul_lo(const uint32_t x, const uint32_t y)
{
    uint32_t result;
    asm("mul.lo.u32 %0, %1, %2;" : "=r"(result) : "r"(x), "r"(y));
    return result;
}

__device__ __forceinline__ uint32_t mul_hi(const uint32_t x, const uint32_t y)
{
    uint32_t result;
    asm("mul.hi.u32 %0, %1, %2;" : "=r"(result) : "r"(x), "r"(y));
    return result;
}

__device__ __forceinline__ uint32_t mad_lo(const uint32_t x, const uint32_t y, const uint32_t z)
{
    uint32_t result;
    asm("mad.lo.u32 %0, %1, %2, %3;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}

__device__ __forceinline__ uint32_t mad_hi(const uint32_t x, const uint32_t y, const uint32_t z)
{
    uint32_t result;
    asm("mad.hi.u32 %0, %1, %2, %3;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}

__device__ __forceinline__ uint32_t mad_lo_cc(const uint32_t x, const uint32_t y, const uint32_t z)
{
    uint32_t result;
    asm volatile("mad.lo.cc.u32 %0, %1, %2, %3;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}

__device__ __forceinline__ uint32_t mad_hi_cc(const uint32_t x, const uint32_t y, const uint32_t z)
{
    uint32_t result;
    asm volatile("mad.hi.cc.u32 %0, %1, %2, %3;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}

__device__ __forceinline__ uint32_t madc_lo(const uint32_t x, const uint32_t y, const uint32_t z)
{
    uint32_t result;
    asm volatile("madc.lo.u32 %0, %1, %2, %3;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}

__device__ __forceinline__ uint32_t madc_hi(const uint32_t x, const uint32_t y, const uint32_t z)
{
    uint32_t result;
    asm volatile("madc.hi.u32 %0, %1, %2, %3;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}

__device__ __forceinline__ uint32_t madc_lo_cc(const uint32_t x, const uint32_t y, const uint32_t z)
{
    uint32_t result;
    asm volatile("madc.lo.cc.u32 %0, %1, %2, %3;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}

__device__ __forceinline__ uint32_t madc_hi_cc(const uint32_t x, const uint32_t y, const uint32_t z)
{
    uint32_t result;
    asm volatile("madc.hi.cc.u32 %0, %1, %2, %3;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}

__device__ __forceinline__ uint64_t mov_b64(uint32_t lo, uint32_t hi)
{
    uint64_t result;
    asm("mov.b64 %0, {%1,%2};" : "=l"(result) : "r"(lo), "r"(hi));
    return result;
}

// Gives u64 overloads a dedicated namespace.
// Callers should know exactly what they're calling (no implicit conversions).
namespace u64
{

__device__ __forceinline__ uint64_t add(const uint64_t x, const uint64_t y)
{
    uint64_t result;
    asm("add.u64 %0, %1, %2;" : "=l"(result) : "l"(x), "l"(y));
    return result;
}

__device__ __forceinline__ uint64_t add_cc(const uint64_t x, const uint64_t y)
{
    uint64_t result;
    asm volatile("add.cc.u64 %0, %1, %2;" : "=l"(result) : "l"(x), "l"(y));
    return result;
}

__device__ __forceinline__ uint64_t addc(const uint64_t x, const uint64_t y)
{
    uint64_t result;
    asm volatile("addc.u64 %0, %1, %2;" : "=l"(result) : "l"(x), "l"(y));
    return result;
}

__device__ __forceinline__ uint64_t addc_cc(const uint64_t x, const uint64_t y)
{
    uint64_t result;
    asm volatile("addc.cc.u64 %0, %1, %2;" : "=l"(result) : "l"(x), "l"(y));
    return result;
}

__device__ __forceinline__ uint64_t sub(const uint64_t x, const uint64_t y)
{
    uint64_t result;
    asm("sub.u64 %0, %1, %2;" : "=l"(result) : "l"(x), "l"(y));
    return result;
}

__device__ __forceinline__ uint64_t sub_cc(const uint64_t x, const uint64_t y)
{
    uint64_t result;
    asm volatile("sub.cc.u64 %0, %1, %2;" : "=l"(result) : "l"(x), "l"(y));
    return result;
}

__device__ __forceinline__ uint64_t subc(const uint64_t x, const uint64_t y)
{
    uint64_t result;
    asm volatile("subc.u64 %0, %1, %2;" : "=l"(result) : "l"(x), "l"(y));
    return result;
}

__device__ __forceinline__ uint64_t subc_cc(const uint64_t x, const uint64_t y)
{
    uint64_t result;
    asm volatile("subc.cc.u64 %0, %1, %2;" : "=l"(result) : "l"(x), "l"(y));
    return result;
}

__device__ __forceinline__ uint64_t mul_lo(const uint64_t x, const uint64_t y)
{
    uint64_t result;
    asm("mul.lo.u64 %0, %1, %2;" : "=l"(result) : "l"(x), "l"(y));
    return result;
}

__device__ __forceinline__ uint64_t mul_hi(const uint64_t x, const uint64_t y)
{
    uint64_t result;
    asm("mul.hi.u64 %0, %1, %2;" : "=l"(result) : "l"(x), "l"(y));
    return result;
}

__device__ __forceinline__ uint64_t mad_lo(const uint64_t x, const uint64_t y, const uint64_t z)
{
    uint64_t result;
    asm("mad.lo.u64 %0, %1, %2, %3;" : "=l"(result) : "l"(x), "l"(y), "l"(z));
    return result;
}

__device__ __forceinline__ uint64_t mad_hi(const uint64_t x, const uint64_t y, const uint64_t z)
{
    uint64_t result;
    asm("mad.hi.u64 %0, %1, %2, %3;" : "=l"(result) : "l"(x), "l"(y), "l"(z));
    return result;
}

__device__ __forceinline__ uint64_t mad_lo_cc(const uint64_t x, const uint64_t y, const uint64_t z)
{
    uint64_t result;
    asm volatile("mad.lo.cc.u64 %0, %1, %2, %3;" : "=l"(result) : "l"(x), "l"(y), "l"(z));
    return result;
}

__device__ __forceinline__ uint64_t mad_hi_cc(const uint64_t x, const uint64_t y, const uint64_t z)
{
    uint64_t result;
    asm volatile("mad.hi.cc.u64 %0, %1, %2, %3;" : "=l"(result) : "l"(x), "l"(y), "l"(z));
    return result;
}

__device__ __forceinline__ uint64_t madc_lo(const uint64_t x, const uint64_t y, const uint64_t z)
{
    uint64_t result;
    asm volatile("madc.lo.u64 %0, %1, %2, %3;" : "=l"(result) : "l"(x), "l"(y), "l"(z));
    return result;
}

__device__ __forceinline__ uint64_t madc_hi(const uint64_t x, const uint64_t y, const uint64_t z)
{
    uint64_t result;
    asm volatile("madc.hi.u64 %0, %1, %2, %3;" : "=l"(result) : "l"(x), "l"(y), "l"(z));
    return result;
}

__device__ __forceinline__ uint64_t madc_lo_cc(const uint64_t x, const uint64_t y, const uint64_t z)
{
    uint64_t result;
    asm volatile("madc.lo.cc.u64 %0, %1, %2, %3;" : "=l"(result) : "l"(x), "l"(y), "l"(z));
    return result;
}

__device__ __forceinline__ uint64_t madc_hi_cc(const uint64_t x, const uint64_t y, const uint64_t z)
{
    uint64_t result;
    asm volatile("madc.hi.cc.u64 %0, %1, %2, %3;" : "=l"(result) : "l"(x), "l"(y), "l"(z));
    return result;
}

} // namespace u64

__device__ __forceinline__ void bar_arrive(const unsigned name, const unsigned count)
{
    asm volatile("bar.arrive %0, %1;" : : "r"(name), "r"(count) : "memory");
}

__device__ __forceinline__ void bar_sync(const unsigned name, const unsigned count)
{
    asm volatile("bar.sync %0, %1;" : : "r"(name), "r"(count) : "memory");
}

} // namespace ptx


namespace host_math
{

// Host-side fallbacks only: under NVRTC (the witness-JIT embed, device-only
// compilation) pure-__host__ functions are hard errors and nothing here is
// reachable — every host caller is itself guarded out. Offline nvcc builds
// (no __CUDACC_RTC__) are unchanged.
#if !defined(__CUDACC_RTC__)

// return x + y with uint32_t operands
static __host__ uint32_t add(const uint32_t x, const uint32_t y)
{
    return x + y;
}

// return x + y + carry with uint32_t operands
static __host__ uint32_t addc(const uint32_t x, const uint32_t y, const uint32_t carry)
{
    return x + y + carry;
}

// return x + y and carry out with uint32_t operands
static __host__ uint32_t add_cc(const uint32_t x, const uint32_t y, uint32_t &carry)
{
    uint32_t result;
    result = x + y;
    carry = x > result;
    return result;
}

// return x + y + carry and carry out  with uint32_t operands
static __host__ uint32_t addc_cc(const uint32_t x, const uint32_t y, uint32_t &carry)
{
    const uint32_t result = x + y + carry;
    carry = carry && x >= result || !carry && x > result;
    return result;
}

// return x - y with uint32_t operands
static __host__ uint32_t sub(const uint32_t x, const uint32_t y)
{
    return x - y;
}

// 	return x - y - borrow with uint32_t operands
static __host__ uint32_t subc(const uint32_t x, const uint32_t y, const uint32_t borrow)
{
    return x - y - borrow;
}

//	return x - y and borrow out with uint32_t operands
static __host__ uint32_t sub_cc(const uint32_t x, const uint32_t y, uint32_t &borrow)
{
    uint32_t result;
    result = x - y;
    borrow = x < result;
    return result;
}

//	return x - y - borrow and borrow out with uint32_t operands
static __host__ uint32_t subc_cc(const uint32_t x, const uint32_t y, uint32_t &borrow)
{
    const uint32_t result = x - y - borrow;
    borrow = borrow && x <= result || !borrow && x < result;
    return result;
}

// return x * y + z + carry and carry out with uint32_t operands
static __host__ uint32_t madc_cc(const uint32_t x, const uint32_t y, const uint32_t z, uint32_t &carry)
{
    uint32_t result;
    uint64_t r = static_cast<uint64_t>(x) * y + z + carry;
    carry = r >> 32;
    result = r & 0xffffffff;
    return result;
}

#endif // !defined(__CUDACC_RTC__)

} // namespace host_math


template <unsigned OPS_COUNT = UINT32_MAX, bool CARRY_IN = false, bool CARRY_OUT = false> struct carry_chain
{
    unsigned index;

    constexpr __host__ __device__ __forceinline__ carry_chain() : index(0)
    {
    }

// NVRTC (the witness-JIT embed) compiles device-only: pure-__host__ functions are
// hard errors in JIT mode, and no host caller can exist there. Offline nvcc builds
// (which never define __CUDACC_RTC__) keep them verbatim.
#if !defined(__CUDACC_RTC__)
    __host__ __forceinline__ uint32_t add(const uint32_t x, const uint32_t y, uint32_t &carry)
    {
        index++;
        if (index == 1 && OPS_COUNT == 1 && !CARRY_IN && !CARRY_OUT)
            return host_math::add(x, y);
        else if (index == 1 && !CARRY_IN)
            return host_math::add_cc(x, y, carry);
        else if (index < OPS_COUNT || CARRY_OUT)
            return host_math::addc_cc(x, y, carry);
        else
            return host_math::addc(x, y, carry);
    }
#endif

    __device__ __forceinline__ uint32_t add(const uint32_t x, const uint32_t y)
    {
        index++;
        if (index == 1 && OPS_COUNT == 1 && !CARRY_IN && !CARRY_OUT)
            return ptx::add(x, y);
        else if (index == 1 && !CARRY_IN)
            return ptx::add_cc(x, y);
        else if (index < OPS_COUNT || CARRY_OUT)
            return ptx::addc_cc(x, y);
        else
            return ptx::addc(x, y);
    }

#if !defined(__CUDACC_RTC__)
    __host__ __forceinline__ uint32_t sub(const uint32_t x, const uint32_t y, uint32_t &carry)
    {
        index++;
        if (index == 1 && OPS_COUNT == 1 && !CARRY_IN && !CARRY_OUT)
            return host_math::sub(x, y);
        else if (index == 1 && !CARRY_IN)
            return host_math::sub_cc(x, y, carry);
        else if (index < OPS_COUNT || CARRY_OUT)
            return host_math::subc_cc(x, y, carry);
        else
            return host_math::subc(x, y, carry);
    }
#endif

    __device__ __forceinline__ uint32_t sub(const uint32_t x, const uint32_t y)
    {
        index++;
        if (index == 1 && OPS_COUNT == 1 && !CARRY_IN && !CARRY_OUT)
            return ptx::sub(x, y);
        else if (index == 1 && !CARRY_IN)
            return ptx::sub_cc(x, y);
        else if (index < OPS_COUNT || CARRY_OUT)
            return ptx::subc_cc(x, y);
        else
            return ptx::subc(x, y);
    }

    __device__ __forceinline__ uint32_t mad_lo(const uint32_t x, const uint32_t y, const uint32_t z)
    {
        index++;
        if (index == 1 && OPS_COUNT == 1 && !CARRY_IN && !CARRY_OUT)
            return ptx::mad_lo(x, y, z);
        else if (index == 1 && !CARRY_IN)
            return ptx::mad_lo_cc(x, y, z);
        else if (index < OPS_COUNT || CARRY_OUT)
            return ptx::madc_lo_cc(x, y, z);
        else
            return ptx::madc_lo(x, y, z);
    }

    __device__ __forceinline__ uint32_t mad_hi(const uint32_t x, const uint32_t y, const uint32_t z)
    {
        index++;
        if (index == 1 && OPS_COUNT == 1 && !CARRY_IN && !CARRY_OUT)
            return ptx::mad_hi(x, y, z);
        else if (index == 1 && !CARRY_IN)
            return ptx::mad_hi_cc(x, y, z);
        else if (index < OPS_COUNT || CARRY_OUT)
            return ptx::madc_hi_cc(x, y, z);
        else
            return ptx::madc_hi(x, y, z);
    }
};
// finite field definitions for Starknet



struct ff_config_starknet
{
    // field structure size = 8 * 32 bit
    static constexpr unsigned limbs_count = 8;
    
    // Starknet modulus: 2^251 + 17 * 2^192 + 1
    // = 3618502788666131213697322783095070105623107215331596699973092056135872020481
    // = 0x800000000000011000000000000000000000000000000000000000000000001
    // In little-endian 32-bit limbs:
    static constexpr ff_storage<limbs_count> modulus = {
        0x00000001, // limb[0]
        0x00000000, // limb[1]
        0x00000000, // limb[2]
        0x00000000, // limb[3]
        0x00000000, // limb[4]
        0x00000000, // limb[5]
        0x00000011, // limb[6] = 17
        0x08000000  // limb[7] = 2^27 (since 251 = 7*32 + 27)
    };
    
    // modulus * 2
    static constexpr ff_storage<limbs_count> modulus_2 = {
        0x00000002, // limb[0]
        0x00000000, // limb[1]
        0x00000000, // limb[2]
        0x00000000, // limb[3]
        0x00000000, // limb[4]
        0x00000000, // limb[5]
        0x00000022, // limb[6] = 34
        0x10000000  // limb[7] = 2^28
    };
    
    // modulus * 4
    static constexpr ff_storage<limbs_count> modulus_4 = {
        0x00000004, // limb[0]
        0x00000000, // limb[1]
        0x00000000, // limb[2]
        0x00000000, // limb[3]
        0x00000000, // limb[4]
        0x00000000, // limb[5]
        0x00000044, // limb[6] = 68
        0x20000000  // limb[7] = 2^29
    };
    
    // modulus^2 (computed offline)
    // (2^251 + 17*2^192 + 1)^2
    static constexpr ff_storage_wide<limbs_count> modulus_squared = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000022, 0x10000000,
        0x00000121, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00400000
    };
    
    // 2*modulus^2
    static constexpr ff_storage_wide<limbs_count> modulus_squared_2 = {
        0x00000002, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000044, 0x20000000,
        0x00000242, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00800000
    };
    
    // 4*modulus^2
    static constexpr ff_storage_wide<limbs_count> modulus_squared_4 = {
        0x00000004, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000088, 0x40000000,
        0x00000484, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x01000000
    };
    
    // R^2 mod p for Montgomery form
    // R = 2^256, R^2 = 2^512 mod p
    // Pre-computed value from starknet_field_ops.c:
    static constexpr ff_storage<limbs_count> r2 = {
        0x7e000401, // limb[0]
        0xfffffd73, // limb[1]
        0x330fffff, // limb[2]
        0x00000001, // limb[3]
        0xff6f8000, // limb[4]
        0xffffffff, // limb[5]
        0x5e008810, // limb[6]
        0x07ffd4ab  // limb[7]
    };
    
    // Montgomery inverse: -p^(-1) mod 2^32
    // Since p ≡ 1 (mod 2^32), we have -p^(-1) ≡ -1 ≡ 0xFFFFFFFF (mod 2^32)
    static constexpr uint32_t inv = 0xFFFFFFFF;
    
    // 1 in Montgomery form (R mod p)
    // R = 2^256 mod p where p = 2^251 + 17*2^192 + 1
    // R mod p = 0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1
    // Pre-computed:
    static constexpr ff_storage<limbs_count> one = {
        0xffffffe1, // limb[0]
        0xffffffff, // limb[1]
        0xffffffff, // limb[2]
        0xffffffff, // limb[3]
        0xffffffff, // limb[4]
        0xffffffff, // limb[5]
        0xfffffdf0, // limb[6]
        0x07ffffff  // limb[7]
    };
    
    static constexpr unsigned modulus_bits_count = 252; // Actually 251.xxx bits
};

// Default configuration type aliases for Starknet
using ff_config_q = ff_config_starknet;
using ff_config_r = ff_config_starknet;



template <class FF_CONFIG> struct ff_dispatch_st
{
    // allows consumers to access the underlying config (e.g., "fd_q::CONFIG") if needed
    using CONFIG = FF_CONFIG;

    static constexpr int LPT = CONFIG::limbs_count;
    static constexpr int TPF = 1;
    static constexpr unsigned TLC = CONFIG::limbs_count;

    typedef ff_storage<TLC> storage;
    typedef ff_storage_wide<TLC> storage_wide;

    // return number of bits in modulus
    static constexpr unsigned MBC = CONFIG::modulus_bits_count;

    // HOST_DEVICE_INLINE (house style): NVRTC JIT mode rejects unannotated functions.
    static constexpr HOST_DEVICE_INLINE uint32_t get_inv()
    {
        return FF_CONFIG::inv;
    }

    static constexpr HOST_DEVICE_INLINE storage get_zero()
    {
        return storage{0};
    }
    // return modulus
    template <unsigned MULTIPLIER = 1> static constexpr HOST_DEVICE_INLINE storage get_modulus()
    {
        switch (MULTIPLIER)
        {
        case 1:
            return CONFIG::modulus;
        case 2:
            return CONFIG::modulus_2;
        case 4:
            return CONFIG::modulus_4;
        default:
            return {};
        }
    }

    // return modulus^2, helpful for ab +/- cd
    template <unsigned MULTIPLIER = 1> static constexpr HOST_DEVICE_INLINE storage_wide get_modulus_squared()
    {
        switch (MULTIPLIER)
        {
        case 1:
            return CONFIG::modulus_squared;
        case 2:
            return CONFIG::modulus_squared_2;
        case 4:
            return CONFIG::modulus_squared_4;
        default:
            return {};
        }
    }

    // return r^2
    static constexpr HOST_DEVICE_INLINE storage get_r2()
    {
        return CONFIG::r2;
    }

    // return one in montgomery form
    static constexpr HOST_DEVICE_INLINE storage get_one()
    {
        return CONFIG::one;
    }

    // add or subtract limbs
#ifdef __CUDA_ARCH__
    template <bool SUBTRACT, bool CARRY_OUT>
    static constexpr DEVICE_INLINE uint32_t add_sub_limbs_device(const storage &xs, const storage &ys, storage &rs)
    {
        const uint32_t *x = xs.limbs;
        const uint32_t *y = ys.limbs;
        uint32_t *r = rs.limbs;
        carry_chain<CARRY_OUT ? TLC + 1 : TLC> chain;
#pragma unroll
        for (unsigned i = 0; i < TLC; i++)
            r[i] = SUBTRACT ? chain.sub(x[i], y[i]) : chain.add(x[i], y[i]);
        if (!CARRY_OUT)
            return 0;
        return SUBTRACT ? chain.sub(0, 0) : chain.add(0, 0);
    }

    // If we want, we could make "2*TLC" a template parameter to deduplicate with "storage" overload, but that's a minor
    // issue.
    template <bool SUBTRACT, bool CARRY_OUT>
    static constexpr DEVICE_INLINE uint32_t add_sub_limbs_device(const storage_wide &xs, const storage_wide &ys,
                                                                 storage_wide &rs)
    {
        const uint32_t *x = xs.limbs;
        const uint32_t *y = ys.limbs;
        uint32_t *r = rs.limbs;
        carry_chain<CARRY_OUT ? 2 * TLC + 1 : 2 * TLC> chain;
#pragma unroll
        for (unsigned i = 0; i < 2 * TLC; i++)
        {
            r[i] = SUBTRACT ? chain.sub(x[i], y[i]) : chain.add(x[i], y[i]);
        }
        if (!CARRY_OUT)
            return 0;
        return SUBTRACT ? chain.sub(0, 0) : chain.add(0, 0);
    }
#endif

    template <bool SUBTRACT, bool CARRY_OUT>
    static constexpr HOST_INLINE uint32_t add_sub_limbs_host(const storage &xs, const storage &ys, storage &rs)
    {
        const uint32_t *x = xs.limbs;
        const uint32_t *y = ys.limbs;
        uint32_t *r = rs.limbs;
        uint32_t carry = 0;
        carry_chain<TLC, false, CARRY_OUT> chain;
        for (unsigned i = 0; i < TLC; i++)
            r[i] = SUBTRACT ? chain.sub(x[i], y[i], carry) : chain.add(x[i], y[i], carry);
        return CARRY_OUT ? carry : 0;
    }

    template <bool SUBTRACT, bool CARRY_OUT, typename T>
    static constexpr HOST_DEVICE_INLINE uint32_t add_sub_limbs(const T &xs, const T &ys, T &rs)
    {
        // No need for static_assert(std::is_same<T, storage>::value || std::is_same<T, storage_wide>::value).
        // Instantiation will fail if appropriate add_sub_limbs_device overload does not exist.
#ifdef __CUDA_ARCH__
        return add_sub_limbs_device<SUBTRACT, CARRY_OUT>(xs, ys, rs);
#else
        return add_sub_limbs_host<SUBTRACT, CARRY_OUT>(xs, ys, rs);
#endif
    }

    template <bool CARRY_OUT, typename T>
    static constexpr HOST_DEVICE_INLINE uint32_t add_limbs(const T &xs, const T &ys, T &rs)
    {
        return add_sub_limbs<false, CARRY_OUT>(xs, ys, rs);
    }

    template <bool CARRY_OUT, typename T>
    static constexpr HOST_DEVICE_INLINE uint32_t sub_limbs(const T &xs, const T &ys, T &rs)
    {
        return add_sub_limbs<true, CARRY_OUT>(xs, ys, rs);
    }

    // return xs == 0 with field operands
#ifdef __CUDA_ARCH__
    static constexpr DEVICE_INLINE bool is_zero_device(const storage &xs)
    {
        const uint32_t *x = xs.limbs;
        uint32_t limbs_or = x[0];
#pragma unroll
        for (unsigned i = 1; i < TLC; i++)
            limbs_or |= x[i];
        return limbs_or == 0;
    }
#endif

    static constexpr HOST_INLINE bool is_zero_host(const storage &xs)
    {
        for (unsigned i = 0; i < TLC; i++)
            if (xs.limbs[i])
                return false;
        return true;
    }

    static constexpr HOST_DEVICE_INLINE bool is_zero(const storage &xs)
    {
#ifdef __CUDA_ARCH__
        return is_zero_device(xs);
#else
        return is_zero_host(xs);
#endif
    }

    // return xs == ys with field operands
#ifdef __CUDA_ARCH__
    static constexpr DEVICE_INLINE bool eq_device(const storage &xs, const storage &ys)
    {
        const uint32_t *x = xs.limbs;
        const uint32_t *y = ys.limbs;
        uint32_t limbs_or = x[0] ^ y[0];
#pragma unroll
        for (unsigned i = 1; i < TLC; i++)
            limbs_or |= x[i] ^ y[i];
        return limbs_or == 0;
    }
#endif

    static constexpr HOST_INLINE bool eq_host(const storage &xs, const storage &ys)
    {
        for (unsigned i = 0; i < TLC; i++)
            if (xs.limbs[i] != ys.limbs[i])
                return false;
        return true;
    }

    static constexpr HOST_DEVICE_INLINE bool eq(const storage &xs, const storage &ys)
    {
#ifdef __CUDA_ARCH__
        return eq_device(xs, ys);
#else
        return eq_host(xs, ys);
#endif
    }

    template <unsigned REDUCTION_SIZE = 1> static constexpr HOST_DEVICE_INLINE storage reduce(const storage &xs)
    {
        if (REDUCTION_SIZE == 0)
            return xs;
        const storage modulus = get_modulus<REDUCTION_SIZE>();
        storage rs = {};
        return sub_limbs<true>(xs, modulus, rs) ? xs : rs;
    }

    template <unsigned REDUCTION_SIZE = 1>
    static constexpr HOST_DEVICE_INLINE storage_wide reduce_wide(const storage_wide &xs)
    {
        if (REDUCTION_SIZE == 0)
            return xs;
        const storage_wide modulus_squared = get_modulus_squared<REDUCTION_SIZE>();
        storage_wide rs = {};
        return sub_limbs<true>(xs, modulus_squared, rs) ? xs : rs;
    }

    // return xs + ys with field operands
    template <unsigned REDUCTION_SIZE = 1>
    static constexpr HOST_DEVICE_INLINE storage add(const storage &xs, const storage &ys)
    {
        storage rs = {};
        add_limbs<false>(xs, ys, rs);
        return reduce<REDUCTION_SIZE>(rs);
    }

    template <unsigned REDUCTION_SIZE = 1>
    static constexpr HOST_DEVICE_INLINE storage_wide add_wide(const storage_wide &xs, const storage_wide &ys)
    {
        storage_wide rs = {};
        add_limbs<false>(xs, ys, rs);
        return reduce_wide<REDUCTION_SIZE>(rs);
    }

    // return xs - ys with field operands
    template <unsigned REDUCTION_SIZE = 1> static HOST_DEVICE_INLINE storage sub(const storage &xs, const storage &ys)
    {
        storage rs = {};
        if (REDUCTION_SIZE == 0)
        {
            sub_limbs<false>(xs, ys, rs);
        }
        else
        {
            uint32_t carry = sub_limbs<true>(xs, ys, rs);
            if (carry == 0)
                return rs;
            const storage modulus = get_modulus<REDUCTION_SIZE>();
            add_limbs<false>(rs, modulus, rs);
        }
        return rs;
    }

    template <unsigned REDUCTION_SIZE = 1>
    static HOST_DEVICE_INLINE storage_wide sub_wide(const storage_wide &xs, const storage_wide &ys)
    {
        storage_wide rs = {};
        if (REDUCTION_SIZE == 0)
        {
            sub_limbs<false>(xs, ys, rs);
        }
        else
        {
            uint32_t carry = sub_limbs<true>(xs, ys, rs);
            if (carry == 0)
                return rs;
            const storage_wide modulus_squared = get_modulus_squared<REDUCTION_SIZE>();
            add_limbs<false>(rs, modulus_squared, rs);
        }
        return rs;
    }

#ifdef __CUDA_ARCH__

    // The following algorithms are adaptations of
    // http://www.acsel-lab.com/arithmetic/arith23/data/1616a047.pdf,
    // taken from https://github.com/z-prize/test-msm-gpu (under Apache 2.0 license)
    // and modified to use our datatypes.
    // We had our own implementation of http://www.acsel-lab.com/arithmetic/arith23/data/1616a047.pdf,
    // but the sppark versions achieved lower instruction count thanks to clever carry handling,
    // so we decided to just use theirs.

    static DEVICE_INLINE void mul_n(uint32_t *acc, const uint32_t *a, uint32_t bi, size_t n = TLC)
    {
#pragma unroll
        for (size_t i = 0; i < n; i += 2)
        {
            acc[i] = ptx::mul_lo(a[i], bi);
            acc[i + 1] = ptx::mul_hi(a[i], bi);
        }
    }

    static DEVICE_INLINE void cmad_n(uint32_t *acc, const uint32_t *a, uint32_t bi, size_t n = TLC)
    {
        acc[0] = ptx::mad_lo_cc(a[0], bi, acc[0]);
        acc[1] = ptx::madc_hi_cc(a[0], bi, acc[1]);
#pragma unroll
        for (size_t i = 2; i < n; i += 2)
        {
            acc[i] = ptx::madc_lo_cc(a[i], bi, acc[i]);
            acc[i + 1] = ptx::madc_hi_cc(a[i], bi, acc[i + 1]);
        }
        // return carry flag
    }

    static DEVICE_INLINE void madc_n_rshift(uint32_t *odd, const uint32_t *a, uint32_t bi)
    {
        constexpr uint32_t n = TLC;
#pragma unroll
        for (size_t i = 0; i < n - 2; i += 2)
        {
            odd[i] = ptx::madc_lo_cc(a[i], bi, odd[i + 2]);
            odd[i + 1] = ptx::madc_hi_cc(a[i], bi, odd[i + 3]);
        }
        odd[n - 2] = ptx::madc_lo_cc(a[n - 2], bi, 0);
        odd[n - 1] = ptx::madc_hi(a[n - 2], bi, 0);
    }

    static DEVICE_INLINE void mad_n_redc(uint32_t *even, uint32_t *odd, const uint32_t *a, uint32_t bi,
                                         bool first = false)
    {
        constexpr uint32_t n = TLC;
        constexpr auto modulus = CONFIG::modulus;
        const uint32_t *const MOD = modulus.limbs;
        if (first)
        {
            mul_n(odd, a + 1, bi);
            mul_n(even, a, bi);
        }
        else
        {
            even[0] = ptx::add_cc(even[0], odd[1]);
            madc_n_rshift(odd, a + 1, bi);
            cmad_n(even, a, bi);
            odd[n - 1] = ptx::addc(odd[n - 1], 0);
        }
        uint32_t mi = even[0] * get_inv();
        cmad_n(odd, MOD + 1, mi);
        cmad_n(even, MOD, mi);
        odd[n - 1] = ptx::addc(odd[n - 1], 0);
    }

    static DEVICE_INLINE void mad_row(uint32_t *odd, uint32_t *even, const uint32_t *a, uint32_t bi, size_t n = TLC)
    {
        cmad_n(odd, a + 1, bi, n - 2);
        odd[n - 2] = ptx::madc_lo_cc(a[n - 1], bi, 0);
        odd[n - 1] = ptx::madc_hi(a[n - 1], bi, 0);
        cmad_n(even, a, bi, n);
        odd[n - 1] = ptx::addc(odd[n - 1], 0);
    }

    static DEVICE_INLINE void qad_row(uint32_t *odd, uint32_t *even, const uint32_t *a, uint32_t bi, size_t n = TLC)
    {
        cmad_n(odd, a, bi, n - 2);
        odd[n - 2] = ptx::madc_lo_cc(a[n - 2], bi, 0);
        odd[n - 1] = ptx::madc_hi(a[n - 2], bi, 0);
        cmad_n(even, a + 1, bi, n - 2);
        odd[n - 1] = ptx::addc(odd[n - 1], 0);
    }

    static DEVICE_INLINE void multiply_raw(const storage &as, const storage &bs, storage_wide &rs)
    {
        const uint32_t *a = as.limbs;
        const uint32_t *b = bs.limbs;
        uint32_t *even = rs.limbs;
        __align__(8) uint32_t odd[2 * TLC - 2];
        mul_n(even, a, b[0]);
        mul_n(odd, a + 1, b[0]);
        mad_row(&even[2], &odd[0], a, b[1]);
        size_t i;
#pragma unroll
        for (i = 2; i < TLC - 1; i += 2)
        {
            mad_row(&odd[i], &even[i], a, b[i]);
            mad_row(&even[i + 2], &odd[i], a, b[i + 1]);
        }
        // merge |even| and |odd|
        even[1] = ptx::add_cc(even[1], odd[0]);
        for (i = 1; i < 2 * TLC - 2; i++)
            even[i + 1] = ptx::addc_cc(even[i + 1], odd[i]);
        even[i + 1] = ptx::addc(even[i + 1], 0);
    }

    static DEVICE_INLINE void sqr_raw(const storage &as, storage_wide &rs)
    {
        const uint32_t *a = as.limbs;
        uint32_t *even = rs.limbs;
        size_t i = 0, j;
        __align__(8) uint32_t odd[2 * TLC - 2];

        // perform |a[i]|*|a[j]| for all j>i
        mul_n(even + 2, a + 2, a[0], TLC - 2);
        mul_n(odd, a + 1, a[0], TLC);

#pragma unroll
        while (i < TLC - 4)
        {
            ++i;
            mad_row(&even[2 * i + 2], &odd[2 * i], &a[i + 1], a[i], TLC - i - 1);
            ++i;
            qad_row(&odd[2 * i], &even[2 * i + 2], &a[i + 1], a[i], TLC - i);
        }

        even[2 * TLC - 4] = ptx::mul_lo(a[TLC - 1], a[TLC - 3]);
        even[2 * TLC - 3] = ptx::mul_hi(a[TLC - 1], a[TLC - 3]);
        odd[2 * TLC - 6] = ptx::mad_lo_cc(a[TLC - 2], a[TLC - 3], odd[2 * TLC - 6]);
        odd[2 * TLC - 5] = ptx::madc_hi_cc(a[TLC - 2], a[TLC - 3], odd[2 * TLC - 5]);
        even[2 * TLC - 3] = ptx::addc(even[2 * TLC - 3], 0);

        odd[2 * TLC - 4] = ptx::mul_lo(a[TLC - 1], a[TLC - 2]);
        odd[2 * TLC - 3] = ptx::mul_hi(a[TLC - 1], a[TLC - 2]);

        // merge |even[2:]| and |odd[1:]|
        even[2] = ptx::add_cc(even[2], odd[1]);
        for (j = 2; j < 2 * TLC - 3; j++)
            even[j + 1] = ptx::addc_cc(even[j + 1], odd[j]);
        even[j + 1] = ptx::addc(odd[j], 0);

        // double |even|
        even[0] = 0;
        even[1] = ptx::add_cc(odd[0], odd[0]);
        for (j = 2; j < 2 * TLC - 1; j++)
            even[j] = ptx::addc_cc(even[j], even[j]);
        even[j] = ptx::addc(0, 0);

        // accumulate "diagonal" |a[i]|*|a[i]| product
        i = 0;
        even[2 * i] = ptx::mad_lo_cc(a[i], a[i], even[2 * i]);
        even[2 * i + 1] = ptx::madc_hi_cc(a[i], a[i], even[2 * i + 1]);
        for (++i; i < TLC; i++)
        {
            even[2 * i] = ptx::madc_lo_cc(a[i], a[i], even[2 * i]);
            even[2 * i + 1] = ptx::madc_hi_cc(a[i], a[i], even[2 * i + 1]);
        }
    }

    static DEVICE_INLINE void mul_by_1_row(uint32_t *even, uint32_t *odd, bool first = false)
    {
        uint32_t mi;
        constexpr auto modulus = CONFIG::modulus;
        const uint32_t *const MOD = modulus.limbs;
        if (first)
        {
            mi = even[0] * get_inv();
            mul_n(odd, MOD + 1, mi);
            cmad_n(even, MOD, mi);
            odd[TLC - 1] = ptx::addc(odd[TLC - 1], 0);
        }
        else
        {
            even[0] = ptx::add_cc(even[0], odd[1]);
            // we trust the compiler to *not* touch the carry flag here
            // this code sits in between two "asm volatile" instructions which should guarantee that nothing else
            // interferes with the carry flag
            mi = even[0] * get_inv();
            madc_n_rshift(odd, MOD + 1, mi);
            cmad_n(even, MOD, mi);
            odd[TLC - 1] = ptx::addc(odd[TLC - 1], 0);
        }
    }

    // Performs Montgomery reduction on a storage_wide input. Input value must be in the range [0, mod*2^(32*TLC)).
    // Does not implement an in-place reduce<REDUCTION_SIZE> epilogue. If you want to further reduce the result,
    // call reduce<whatever>(xs.get_lo()) after the call to redc_wide_inplace.
    static DEVICE_INLINE void redc_wide_inplace(storage_wide &xs)
    {
        uint32_t *even = xs.limbs;
        // Yields montmul of lo TLC limbs * 1.
        // Since the hi TLC limbs don't participate in computing the "mi" factor at each mul-and-rightshift stage,
        // it's ok to ignore the hi TLC limbs during this process and just add them in afterward.
        uint32_t odd[TLC];
        size_t i;
#pragma unroll
        for (i = 0; i < TLC; i += 2)
        {
            mul_by_1_row(&even[0], &odd[0], i == 0);
            mul_by_1_row(&odd[0], &even[0]);
        }
        even[0] = ptx::add_cc(even[0], odd[1]);
#pragma unroll
        for (i = 1; i < TLC - 1; i++)
            even[i] = ptx::addc_cc(even[i], odd[i + 1]);
        even[i] = ptx::addc(even[i], 0);
        // Adds in (hi TLC limbs), implicitly right-shifting them by TLC limbs as if they had participated in the
        // add-and-rightshift stages above.
        xs.limbs[0] = ptx::add_cc(xs.limbs[0], xs.limbs[TLC]);
#pragma unroll
        for (i = 1; i < TLC - 1; i++)
            xs.limbs[i] = ptx::addc_cc(xs.limbs[i], xs.limbs[i + TLC]);
        xs.limbs[TLC - 1] = ptx::addc(xs.limbs[TLC - 1], xs.limbs[2 * TLC - 1]);
    }

    static DEVICE_INLINE void montmul_raw(const storage &a_in, const storage &b_in, storage &r_in)
    {
        constexpr uint32_t n = TLC;
        constexpr auto modulus = CONFIG::modulus;
        const uint32_t *const MOD = modulus.limbs;
        const uint32_t *a = a_in.limbs;
        const uint32_t *b = b_in.limbs;
        uint32_t *even = r_in.limbs;
        __align__(8) uint32_t odd[n + 1];
        size_t i;
#pragma unroll
        for (i = 0; i < n; i += 2)
        {
            mad_n_redc(&even[0], &odd[0], a, b[i], i == 0);
            mad_n_redc(&odd[0], &even[0], a, b[i + 1]);
        }
        // merge |even| and |odd|
        even[0] = ptx::add_cc(even[0], odd[1]);
#pragma unroll
        for (i = 1; i < n - 1; i++)
            even[i] = ptx::addc_cc(even[i], odd[i + 1]);
        even[i] = ptx::addc(even[i], 0);
        // final reduction from [0, 2*mod) to [0, mod) not done here, instead performed optionally in mul_device wrapper
    }

    // Returns xs * ys without Montgomery reduction.
    template <unsigned REDUCTION_SIZE = 1>
    static constexpr DEVICE_INLINE storage_wide mul_wide(const storage &xs, const storage &ys)
    {
        // Forces us to think more carefully about the last carry bit if we use a modulus with fewer than 2 leading
        // zeroes of slack
        static_assert(!(CONFIG::modulus.limbs[TLC - 1] >> 30), "modulus top limb must leave 2 spare bits");
        storage_wide rs = {0};
        multiply_raw(xs, ys, rs);
        return reduce_wide<REDUCTION_SIZE>(rs);
    }

    // Performs Montgomery reduction on a storage_wide input. Input value must be in the range [0, mod*2^(32*TLC)).
    template <unsigned REDUCTION_SIZE = 1> static constexpr DEVICE_INLINE storage redc_wide(const storage_wide &xs)
    {
        storage_wide tmp{xs};
        redc_wide_inplace(tmp); // after reduce_twopass, tmp's low TLC limbs should represent a value in [0, 2*mod)
        return reduce<REDUCTION_SIZE>(tmp.get_lo());
    }

    template <unsigned REDUCTION_SIZE>
    static constexpr DEVICE_INLINE storage mul_device(const storage &xs, const storage &ys)
    {
        // Forces us to think more carefully about the last carry bit if we use a modulus with fewer than 2 leading
        // zeroes of slack
        static_assert(!(CONFIG::modulus.limbs[TLC - 1] >> 30), "modulus top limb must leave 2 spare bits");
        storage rs = {0};
        montmul_raw(xs, ys, rs);
        return reduce<REDUCTION_SIZE>(rs);
    }

    template <unsigned REDUCTION_SIZE> static constexpr DEVICE_INLINE storage sqr_device(const storage &xs)
    {
        // Forces us to think more carefully about the last carry bit if we use a modulus with fewer than 2 leading
        // zeroes of slack
        static_assert(!(CONFIG::modulus.limbs[TLC - 1] >> 30), "modulus top limb must leave 2 spare bits");
        storage_wide rs = {0};
        sqr_raw(xs, rs);
        redc_wide_inplace(rs); // after reduce_twopass, tmp's low TLC limbs should represent a value in [0, 2*mod)
        return reduce<REDUCTION_SIZE>(rs.get_lo());
    }

#endif // #ifdef __CUDA_ARCH__

    template <unsigned REDUCTION_SIZE>
    static constexpr HOST_INLINE storage mul_host(const storage &xs, const storage &ys)
    {
        const uint32_t *x = xs.limbs;
        const uint32_t *y = ys.limbs;
        constexpr storage ms = CONFIG::modulus;
        const uint32_t *const n = ms.limbs;
        constexpr uint32_t q = CONFIG::inv;
        uint32_t t[TLC + 2] = {};
        for (const uint32_t y_limb : ys.limbs)
        {
            uint32_t carry = 0;
            for (unsigned i = 0; i < TLC; i++)
                t[i] = host_math::madc_cc(x[i], y_limb, t[i], carry);
            t[TLC] = host_math::add_cc(t[TLC], carry, carry);
            t[TLC + 1] = carry;
            carry = 0;
            const uint32_t m = q * t[0];
            host_math::madc_cc(m, n[0], t[0], carry);
            for (unsigned i = 1; i < TLC; i++)
                t[i - 1] = host_math::madc_cc(m, n[i], t[i], carry);
            t[TLC - 1] = host_math::add_cc(t[TLC], carry, carry);
            t[TLC] = t[TLC + 1] + carry;
        }
        const storage rs = *reinterpret_cast<storage *>(t);
        return reduce<REDUCTION_SIZE>(rs);
    }

    // return xs * ys with field operands
    // Device path adapts http://www.acsel-lab.com/arithmetic/arith23/data/1616a047.pdf to use IMAD.WIDE.
    // Host path uses CIOS.
    template <unsigned REDUCTION_SIZE = 1>
    static constexpr HOST_DEVICE_INLINE storage mul(const storage &xs, const storage &ys)
    {
#ifdef __CUDA_ARCH__
        return mul_device<REDUCTION_SIZE>(xs, ys);
#else
        return mul_host<REDUCTION_SIZE>(xs, ys);
#endif
    }

    // convert field to montgomery form
    template <unsigned REDUCTION_SIZE = 1> static constexpr HOST_DEVICE_INLINE storage to_montgomery(const storage &xs)
    {
        constexpr storage r2 = CONFIG::r2;
        return mul<REDUCTION_SIZE>(xs, r2);
    }

    // convert field from montgomery form
    template <unsigned REDUCTION_SIZE = 1>
    static constexpr HOST_DEVICE_INLINE storage from_montgomery(const storage &xs)
    {
        return mul<REDUCTION_SIZE>(xs, {1});
    }

    // return xs^2 with field operands
    template <unsigned REDUCTION_SIZE = 1> static constexpr HOST_DEVICE_INLINE storage sqr(const storage &xs)
    {
#ifdef __CUDA_ARCH__
        return sqr_device<REDUCTION_SIZE>(xs);
#else
        return mul_host<REDUCTION_SIZE>(xs, xs);
#endif
    }

// return 2*x with field operands
#ifdef __CUDA_ARCH__
    template <unsigned REDUCTION_SIZE> static constexpr DEVICE_INLINE storage dbl_device(const storage &xs)
    {
        const uint32_t *x = xs.limbs;
        storage rs = {};
        uint32_t *r = rs.limbs;
        r[0] = x[0] << 1;
#pragma unroll
        for (unsigned i = 1; i < TLC; i++)
            r[i] = __funnelshift_r(x[i - 1], x[i], 31);
        return reduce<REDUCTION_SIZE>(rs);
    }
#endif

    template <unsigned REDUCTION_SIZE> static constexpr HOST_INLINE storage dbl_host(const storage &xs)
    {
        const uint32_t *x = xs.limbs;
        storage rs = {};
        uint32_t *r = rs.limbs;
        r[0] = x[0] << 1;
        for (unsigned i = 1; i < TLC; i++)
            r[i] = (x[i] << 1) | (x[i - 1] >> 31);
        return reduce<REDUCTION_SIZE>(rs);
    }

    template <unsigned REDUCTION_SIZE = 1> static constexpr HOST_DEVICE_INLINE storage dbl(const storage &xs)
    {
#ifdef __CUDA_ARCH__
        return dbl_device<REDUCTION_SIZE>(xs);
#else
        return dbl_host<REDUCTION_SIZE>(xs);
#endif
    }

    // return x/2 with field operands
#ifdef __CUDA_ARCH__
    template <unsigned REDUCTION_SIZE> static constexpr DEVICE_INLINE storage div2_device(const storage &xs)
    {
        const uint32_t *x = xs.limbs;
        storage rs = {};
        uint32_t *r = rs.limbs;
#pragma unroll
        for (unsigned i = 0; i < TLC - 1; i++)
            r[i] = __funnelshift_rc(x[i], x[i + 1], 1);
        r[TLC - 1] = x[TLC - 1] >> 1;
        return reduce<REDUCTION_SIZE>(rs);
    }
#endif

    template <unsigned REDUCTION_SIZE> static constexpr HOST_INLINE storage div2_host(const storage &xs)
    {
        const uint32_t *x = xs.limbs;
        storage rs = {};
        uint32_t *r = rs.limbs;
        for (unsigned i = 0; i < TLC - 1; i++)
            r[i] = (x[i] >> 1) | (x[i + 1] << 31);
        r[TLC - 1] = x[TLC - 1] >> 1;
        return reduce<REDUCTION_SIZE>(rs);
    }

    template <unsigned REDUCTION_SIZE = 1> static constexpr HOST_DEVICE_INLINE storage div2(const storage &xs)
    {
#ifdef __CUDA_ARCH__
        return div2_device<REDUCTION_SIZE>(xs);
#else
        return div2_host<REDUCTION_SIZE>(xs);
#endif
    }

    // return -xs with field operand
    template <unsigned MODULUS_SIZE = 1> static constexpr HOST_DEVICE_INLINE storage neg(const storage &xs)
    {
        if (unlikely(is_zero(xs)))
            return xs;

        const storage modulus = get_modulus<MODULUS_SIZE>();
        storage rs = {};
        sub_limbs<false>(modulus, xs, rs);
        return rs;
    }

    // extract a given count of bits at a given offset from the field
    static constexpr DEVICE_INLINE uint32_t extract_bits(const storage &xs, const unsigned offset, const unsigned count)
    {
        const unsigned limb_index = offset / warpSize;
        const uint32_t *x = xs.limbs;
        const uint32_t low_limb = x[limb_index];
        const uint32_t high_limb = limb_index < (TLC - 1) ? x[limb_index + 1] : 0;
        uint32_t result = __funnelshift_r(low_limb, high_limb, offset);
        result &= (1 << count) - 1;
        return result;
    }

    template <unsigned REDUCTION_SIZE = 1, unsigned LAST_REDUCTION_SIZE = REDUCTION_SIZE>
    static constexpr HOST_DEVICE_INLINE storage mul(const unsigned scalar, const storage &xs)
    {
        storage rs = {};
        storage temp = xs;
        unsigned l = scalar;
        bool is_zero = true;
#ifdef __CUDA_ARCH__
#pragma unroll
#endif
        for (unsigned i = 0; i < 32; i++)
        {
            if (l & 1)
            {
                rs = is_zero ? temp : (l >> 1) ? add<REDUCTION_SIZE>(rs, temp) : add<LAST_REDUCTION_SIZE>(rs, temp);
                is_zero = false;
            }
            l >>= 1;
            if (l == 0)
                break;
            temp = dbl<REDUCTION_SIZE>(temp);
        }
        return rs;
    }

    static constexpr HOST_DEVICE_INLINE bool is_odd(const storage &xs)
    {
        return xs.limbs[0] & 1;
    }

    static constexpr HOST_DEVICE_INLINE bool is_even(const storage &xs)
    {
        return ~xs.limbs[0] & 1;
    }

    static constexpr HOST_DEVICE_INLINE bool lt(const storage &xs, const storage &ys)
    {
        storage dummy = {};
        uint32_t carry = sub_limbs<true>(xs, ys, dummy);
        return carry;
    }

    static constexpr HOST_DEVICE_INLINE storage inverse(const storage &xs)
    {
        if (is_zero(xs))
            return xs;
        constexpr storage one = {1};
        constexpr storage modulus = CONFIG::modulus;
        storage u = xs;
        storage v = modulus;
        storage b = CONFIG::r2;
        storage c = {};
        while (!eq(u, one) && !eq(v, one))
        {
            while (is_even(u))
            {
                u = div2(u);
                if (is_odd(b))
                    add_limbs<false>(b, modulus, b);
                b = div2(b);
            }
            while (is_even(v))
            {
                v = div2(v);
                if (is_odd(c))
                    add_limbs<false>(c, modulus, c);
                c = div2(c);
            }
            if (lt(v, u))
            {
                sub_limbs<false>(u, v, u);
                b = sub(b, c);
            }
            else
            {
                sub_limbs<false>(v, u, v);
                c = sub(c, b);
            }
        }
        return eq(u, one) ? b : c;
    }

    static DEVICE_INLINE storage pow_u32(const storage &a, unsigned exp)
    {
        if (unlikely(exp == 0))
            return get_one();
        int i = 31 - __clz(exp);
        storage ret = a;
        i--;
        for (; i >= 0; i--)
        {
            ret = sqr(ret);
            bool bit = (exp >> i) & 1;
            if (bit)
                ret = mul(ret, a);
        }
        return ret;
    }

    static HOST_DEVICE_INLINE void print_self(const storage &xs)
    {
        printf("[%08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x]\n", xs.limbs[0], xs.limbs[1], xs.limbs[2], xs.limbs[3],
               xs.limbs[4], xs.limbs[5], xs.limbs[6], xs.limbs[7]);
    }

    // Test-utility only; curand headers don't exist in the witness embed —
    // neither under NVRTC nor as an offline-nvcc self-contained TU (the AOT
    // pack). STWO_WIT_EMBED is defined by the embed prelude in both modes.
#if !defined(__CUDACC_RTC__) && !defined(STWO_WIT_EMBED)
    static DEVICE_INLINE storage device_random(curandState *state)
    {
        storage ret;
#pragma unroll
        for (unsigned i = 0; i < 8; i++)
            ret.limbs[i] = curand(state);
        ret.limbs[7] = 0x3fffffff & ret.limbs[7];
        return reduce<1>(ret);
    }
#endif
};

typedef ff_dispatch_st<ff_config_q> fd_q;
typedef ff_dispatch_st<ff_config_r> fd_r;
// Elliptic curve operations for Starknet curve
// Used for Pedersen hash computation
//
// Curve: y^2 = x^3 + alpha*x + beta over Starknet field
// alpha = 1, beta = 0x6f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89

#ifndef EC_OPS_CUH
#define EC_OPS_CUH


// Type alias for 256-bit field element (Felt252)
typedef ff_storage<8> felt252;

// Affine point on the Starknet curve
struct AffinePointCuda {
    felt252 x;
    felt252 y;
};

// Projective point on the Starknet curve (X, Y, Z) where x = X/Z, y = Y/Z
struct ProjectivePointCuda {
    felt252 X;
    felt252 Y;
    felt252 Z;
};

// Field operations using Starknet config
__device__ __forceinline__ felt252 felt_add(const felt252& a, const felt252& b) {
    return ff_dispatch_st<ff_config_starknet>::add(a, b);
}

__device__ __forceinline__ felt252 felt_sub(const felt252& a, const felt252& b) {
    return ff_dispatch_st<ff_config_starknet>::sub(a, b);
}

__device__ __forceinline__ felt252 felt_mul(const felt252& a, const felt252& b) {
    return ff_dispatch_st<ff_config_starknet>::mul(a, b);
}

__device__ __forceinline__ felt252 felt_to_mont(const felt252& a) {
    return ff_dispatch_st<ff_config_starknet>::to_montgomery(a);
}

__device__ __forceinline__ felt252 felt_from_mont(const felt252& a) {
    return ff_dispatch_st<ff_config_starknet>::from_montgomery(a);
}

__device__ __forceinline__ felt252 felt_inverse(const felt252& a) {
    return ff_dispatch_st<ff_config_starknet>::inverse(a);
}

// Check if projective point is at infinity (Z = 0)
__device__ __forceinline__ bool is_infinity(const ProjectivePointCuda& p) {
    // Check if Z is zero
    for (int i = 0; i < 8; i++) {
        if (p.Z.limbs[i] != 0) return false;
    }
    return true;
}

// Create projective point from affine point
// Converts all coordinates to Montgomery form for subsequent EC operations
__device__ __forceinline__ ProjectivePointCuda affine_to_projective(const AffinePointCuda& p) {
    ProjectivePointCuda result;
    // Convert X and Y from standard form to Montgomery form
    result.X = felt_to_mont(p.x);
    result.Y = felt_to_mont(p.y);
    // Z = 1 in Montgomery form
    result.Z = ff_config_starknet::one;
    return result;
}

// Mixed addition: Projective + Affine -> Projective
// Uses the formula for adding an affine point to a projective point
// This is more efficient than general projective addition
//
// Input: P = (X1, Y1, Z1) in projective, Q = (x2, y2) in affine
// Output: P + Q in projective
//
// Algorithm (from https://hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-madd-1998-cmo):
// u = Y2*Z1-Y1
// uu = u^2
// v = X2*Z1-X1
// vv = v^2
// vvv = v*vv
// R = vv*X1
// A = uu*Z1-vvv-2*R
// X3 = v*A
// Y3 = u*(R-A)-vvv*Y1
// Z3 = vvv*Z1
__device__ __forceinline__ void ec_add_mixed(
    ProjectivePointCuda& P,  // Input/Output projective point
    const AffinePointCuda& Q,  // Input affine point (from table)
    bool debug = false  // Enable debug output
) {
    // All operations in Montgomery form
    felt252 X1 = P.X;
    felt252 Y1 = P.Y;
    felt252 Z1 = P.Z;

    // Convert Q to Montgomery form
    felt252 X2 = felt_to_mont(Q.x);
    felt252 Y2 = felt_to_mont(Q.y);

    if (debug) {
        printf("ec_add_mixed debug:\n");
        printf("  X1: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               X1.limbs[0], X1.limbs[1], X1.limbs[2], X1.limbs[3],
               X1.limbs[4], X1.limbs[5], X1.limbs[6], X1.limbs[7]);
        printf("  Y1: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               Y1.limbs[0], Y1.limbs[1], Y1.limbs[2], Y1.limbs[3],
               Y1.limbs[4], Y1.limbs[5], Y1.limbs[6], Y1.limbs[7]);
        printf("  Z1: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               Z1.limbs[0], Z1.limbs[1], Z1.limbs[2], Z1.limbs[3],
               Z1.limbs[4], Z1.limbs[5], Z1.limbs[6], Z1.limbs[7]);
        printf("  X2: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               X2.limbs[0], X2.limbs[1], X2.limbs[2], X2.limbs[3],
               X2.limbs[4], X2.limbs[5], X2.limbs[6], X2.limbs[7]);
        printf("  Y2: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               Y2.limbs[0], Y2.limbs[1], Y2.limbs[2], Y2.limbs[3],
               Y2.limbs[4], Y2.limbs[5], Y2.limbs[6], Y2.limbs[7]);
    }

    // u = Y2*Z1 - Y1
    felt252 Y2_Z1 = felt_mul(Y2, Z1);
    felt252 u = felt_sub(Y2_Z1, Y1);

    // v = X2*Z1 - X1
    felt252 X2_Z1 = felt_mul(X2, Z1);
    felt252 v = felt_sub(X2_Z1, X1);

    // uu = u^2
    felt252 uu = felt_mul(u, u);

    // vv = v^2
    felt252 vv = felt_mul(v, v);

    // vvv = v * vv
    felt252 vvv = felt_mul(v, vv);

    // R = vv * X1
    felt252 R = felt_mul(vv, X1);

    // A = uu*Z1 - vvv - 2*R
    felt252 uu_Z1 = felt_mul(uu, Z1);
    felt252 two_R = felt_add(R, R);
    felt252 A = felt_sub(felt_sub(uu_Z1, vvv), two_R);

    if (debug) {
        printf("  u: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               u.limbs[0], u.limbs[1], u.limbs[2], u.limbs[3],
               u.limbs[4], u.limbs[5], u.limbs[6], u.limbs[7]);
        printf("  v: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               v.limbs[0], v.limbs[1], v.limbs[2], v.limbs[3],
               v.limbs[4], v.limbs[5], v.limbs[6], v.limbs[7]);
        printf("  vvv: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               vvv.limbs[0], vvv.limbs[1], vvv.limbs[2], vvv.limbs[3],
               vvv.limbs[4], vvv.limbs[5], vvv.limbs[6], vvv.limbs[7]);
        printf("  R: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               R.limbs[0], R.limbs[1], R.limbs[2], R.limbs[3],
               R.limbs[4], R.limbs[5], R.limbs[6], R.limbs[7]);
        printf("  A: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               A.limbs[0], A.limbs[1], A.limbs[2], A.limbs[3],
               A.limbs[4], A.limbs[5], A.limbs[6], A.limbs[7]);
    }

    // X3 = v * A
    P.X = felt_mul(v, A);

    // Y3 = u*(R-A) - vvv*Y1
    felt252 R_minus_A = felt_sub(R, A);
    felt252 u_R_A = felt_mul(u, R_minus_A);
    felt252 vvv_Y1 = felt_mul(vvv, Y1);
    P.Y = felt_sub(u_R_A, vvv_Y1);

    // Z3 = vvv * Z1
    P.Z = felt_mul(vvv, Z1);

    if (debug) {
        printf("  X3: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               P.X.limbs[0], P.X.limbs[1], P.X.limbs[2], P.X.limbs[3],
               P.X.limbs[4], P.X.limbs[5], P.X.limbs[6], P.X.limbs[7]);
        printf("  Y3: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               P.Y.limbs[0], P.Y.limbs[1], P.Y.limbs[2], P.Y.limbs[3],
               P.Y.limbs[4], P.Y.limbs[5], P.Y.limbs[6], P.Y.limbs[7]);
        printf("  Z3: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               P.Z.limbs[0], P.Z.limbs[1], P.Z.limbs[2], P.Z.limbs[3],
               P.Z.limbs[4], P.Z.limbs[5], P.Z.limbs[6], P.Z.limbs[7]);
    }
}

// Convert projective point to affine (requires field inversion)
// Computes x = X/Z, y = Y/Z using field inversion
// This is expensive (~251 squarings + ~128 multiplications), so should be done sparingly
__device__ __forceinline__ void projective_to_affine(
    const ProjectivePointCuda& P,
    AffinePointCuda& result,
    bool debug = false
) {
    // Compute Z^(-1) using extended Euclidean algorithm
    felt252 z_inv = felt_inverse(P.Z);

    if (debug) {
        printf("projective_to_affine debug:\n");
        printf("  Input X: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               P.X.limbs[0], P.X.limbs[1], P.X.limbs[2], P.X.limbs[3],
               P.X.limbs[4], P.X.limbs[5], P.X.limbs[6], P.X.limbs[7]);
        printf("  Input Y: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               P.Y.limbs[0], P.Y.limbs[1], P.Y.limbs[2], P.Y.limbs[3],
               P.Y.limbs[4], P.Y.limbs[5], P.Y.limbs[6], P.Y.limbs[7]);
        printf("  Input Z: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               P.Z.limbs[0], P.Z.limbs[1], P.Z.limbs[2], P.Z.limbs[3],
               P.Z.limbs[4], P.Z.limbs[5], P.Z.limbs[6], P.Z.limbs[7]);
        printf("  Z^(-1):  %08x %08x %08x %08x %08x %08x %08x %08x\n",
               z_inv.limbs[0], z_inv.limbs[1], z_inv.limbs[2], z_inv.limbs[3],
               z_inv.limbs[4], z_inv.limbs[5], z_inv.limbs[6], z_inv.limbs[7]);
    }

    // result.x = X * Z^(-1) (in Montgomery form)
    // result.y = Y * Z^(-1) (in Montgomery form)
    felt252 x_mont = felt_mul(P.X, z_inv);
    felt252 y_mont = felt_mul(P.Y, z_inv);

    if (debug) {
        printf("  X*Z^(-1): %08x %08x %08x %08x %08x %08x %08x %08x\n",
               x_mont.limbs[0], x_mont.limbs[1], x_mont.limbs[2], x_mont.limbs[3],
               x_mont.limbs[4], x_mont.limbs[5], x_mont.limbs[6], x_mont.limbs[7]);
        printf("  Y*Z^(-1): %08x %08x %08x %08x %08x %08x %08x %08x\n",
               y_mont.limbs[0], y_mont.limbs[1], y_mont.limbs[2], y_mont.limbs[3],
               y_mont.limbs[4], y_mont.limbs[5], y_mont.limbs[6], y_mont.limbs[7]);
    }

    // Convert from Montgomery form to standard form
    result.x = felt_from_mont(x_mont);
    result.y = felt_from_mont(y_mont);

    if (debug) {
        printf("  Result x: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               result.x.limbs[0], result.x.limbs[1], result.x.limbs[2], result.x.limbs[3],
               result.x.limbs[4], result.x.limbs[5], result.x.limbs[6], result.x.limbs[7]);
        printf("  Result y: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               result.y.limbs[0], result.y.limbs[1], result.y.limbs[2], result.y.limbs[3],
               result.y.limbs[4], result.y.limbs[5], result.y.limbs[6], result.y.limbs[7]);
    }
}

// Simple affine addition (slower but simpler, for verification)
// Computes Q = P + R for distinct points P != R
// Formula: lambda = (y2 - y1) / (x2 - x1)
//          x3 = lambda^2 - x1 - x2
//          y3 = lambda * (x1 - x3) - y1
__device__ __forceinline__ void ec_add_affine(
    const AffinePointCuda& P,  // First point (in standard form)
    const AffinePointCuda& R,  // Second point (in standard form)
    AffinePointCuda& result,   // Result (in standard form)
    bool debug = false
) {
    // Convert to Montgomery form
    felt252 x1 = felt_to_mont(P.x);
    felt252 y1 = felt_to_mont(P.y);
    felt252 x2 = felt_to_mont(R.x);
    felt252 y2 = felt_to_mont(R.y);

    // lambda = (y2 - y1) / (x2 - x1)
    felt252 dy = felt_sub(y2, y1);
    felt252 dx = felt_sub(x2, x1);
    felt252 dx_inv = felt_inverse(dx);
    felt252 lambda = felt_mul(dy, dx_inv);

    if (debug) {
        printf("ec_add_affine debug:\n");
        printf("  x1 (mont): %08x %08x %08x %08x %08x %08x %08x %08x\n",
               x1.limbs[0], x1.limbs[1], x1.limbs[2], x1.limbs[3],
               x1.limbs[4], x1.limbs[5], x1.limbs[6], x1.limbs[7]);
        printf("  y1 (mont): %08x %08x %08x %08x %08x %08x %08x %08x\n",
               y1.limbs[0], y1.limbs[1], y1.limbs[2], y1.limbs[3],
               y1.limbs[4], y1.limbs[5], y1.limbs[6], y1.limbs[7]);
        printf("  x2 (mont): %08x %08x %08x %08x %08x %08x %08x %08x\n",
               x2.limbs[0], x2.limbs[1], x2.limbs[2], x2.limbs[3],
               x2.limbs[4], x2.limbs[5], x2.limbs[6], x2.limbs[7]);
        printf("  y2 (mont): %08x %08x %08x %08x %08x %08x %08x %08x\n",
               y2.limbs[0], y2.limbs[1], y2.limbs[2], y2.limbs[3],
               y2.limbs[4], y2.limbs[5], y2.limbs[6], y2.limbs[7]);
        printf("  dy = y2-y1: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               dy.limbs[0], dy.limbs[1], dy.limbs[2], dy.limbs[3],
               dy.limbs[4], dy.limbs[5], dy.limbs[6], dy.limbs[7]);
        printf("  dx = x2-x1: %08x %08x %08x %08x %08x %08x %08x %08x (mont)\n",
               dx.limbs[0], dx.limbs[1], dx.limbs[2], dx.limbs[3],
               dx.limbs[4], dx.limbs[5], dx.limbs[6], dx.limbs[7]);
        // Print dx in standard form for comparison with CPU
        felt252 dx_std = felt_from_mont(dx);
        printf("  dx (std):   %08x %08x %08x %08x %08x %08x %08x %08x\n",
               dx_std.limbs[0], dx_std.limbs[1], dx_std.limbs[2], dx_std.limbs[3],
               dx_std.limbs[4], dx_std.limbs[5], dx_std.limbs[6], dx_std.limbs[7]);
        felt252 dy_std = felt_from_mont(dy);
        printf("  dy (std):   %08x %08x %08x %08x %08x %08x %08x %08x\n",
               dy_std.limbs[0], dy_std.limbs[1], dy_std.limbs[2], dy_std.limbs[3],
               dy_std.limbs[4], dy_std.limbs[5], dy_std.limbs[6], dy_std.limbs[7]);
        felt252 lambda_std = felt_from_mont(lambda);
        printf("  lambda(std):%08x %08x %08x %08x %08x %08x %08x %08x\n",
               lambda_std.limbs[0], lambda_std.limbs[1], lambda_std.limbs[2], lambda_std.limbs[3],
               lambda_std.limbs[4], lambda_std.limbs[5], lambda_std.limbs[6], lambda_std.limbs[7]);
        printf("  dx_inv:     %08x %08x %08x %08x %08x %08x %08x %08x\n",
               dx_inv.limbs[0], dx_inv.limbs[1], dx_inv.limbs[2], dx_inv.limbs[3],
               dx_inv.limbs[4], dx_inv.limbs[5], dx_inv.limbs[6], dx_inv.limbs[7]);
        // Verify: dx * dx_inv should equal 1 in Montgomery form (= R mod p)
        felt252 product = felt_mul(dx, dx_inv);
        printf("  dx*dx_inv:  %08x %08x %08x %08x %08x %08x %08x %08x (should be 1_mont)\n",
               product.limbs[0], product.limbs[1], product.limbs[2], product.limbs[3],
               product.limbs[4], product.limbs[5], product.limbs[6], product.limbs[7]);
        // What is 1 in Montgomery form? 1_mont = R mod p
        // For Starknet: R = 2^256, p = 2^251 + 17*2^192 + 1
        // R mod p = 2^256 mod p = 2^256 - 2^251 - 17*2^192 = 2^251 * (2 - 1) - 17*2^192 = 2^251 - 17*2^192
        // Actually let's print the one constant from config
        felt252 one_mont = ff_dispatch_st<ff_config_starknet>::get_one();
        printf("  1_mont:     %08x %08x %08x %08x %08x %08x %08x %08x\n",
               one_mont.limbs[0], one_mont.limbs[1], one_mont.limbs[2], one_mont.limbs[3],
               one_mont.limbs[4], one_mont.limbs[5], one_mont.limbs[6], one_mont.limbs[7]);
        printf("  lambda:     %08x %08x %08x %08x %08x %08x %08x %08x\n",
               lambda.limbs[0], lambda.limbs[1], lambda.limbs[2], lambda.limbs[3],
               lambda.limbs[4], lambda.limbs[5], lambda.limbs[6], lambda.limbs[7]);
    }

    // x3 = lambda^2 - x1 - x2
    felt252 lambda_sq = felt_mul(lambda, lambda);
    felt252 x3 = felt_sub(felt_sub(lambda_sq, x1), x2);

    // y3 = lambda * (x1 - x3) - y1
    felt252 x1_minus_x3 = felt_sub(x1, x3);
    felt252 y3 = felt_sub(felt_mul(lambda, x1_minus_x3), y1);

    if (debug) {
        printf("  x3: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               x3.limbs[0], x3.limbs[1], x3.limbs[2], x3.limbs[3],
               x3.limbs[4], x3.limbs[5], x3.limbs[6], x3.limbs[7]);
        printf("  y3: %08x %08x %08x %08x %08x %08x %08x %08x\n",
               y3.limbs[0], y3.limbs[1], y3.limbs[2], y3.limbs[3],
               y3.limbs[4], y3.limbs[5], y3.limbs[6], y3.limbs[7]);
    }

    // Convert back to standard form
    result.x = felt_from_mont(x3);
    result.y = felt_from_mont(y3);
}

// Reconstruct Felt252 from 28 M31 limbs (9-bit each)
// The Felt252 is stored as 28 * 9 = 252 bits split into 28 M31 values
__device__ __forceinline__ void felt252_from_m31_limbs(felt252& result, const m31* limbs) {
    // Clear result
    for (int i = 0; i < 8; i++) {
        result.limbs[i] = 0;
    }

    // Each M31 limb is 9 bits
    // We need to combine them into 8 * 32 = 256 bits
    // Limb layout: limbs[0] = bits 0-8, limbs[1] = bits 9-17, etc.

    uint64_t accumulator = 0;
    int bit_pos = 0;
    int result_limb = 0;

    for (int i = 0; i < 28 && result_limb < 8; i++) {
        uint64_t value = limbs[i];
        accumulator |= (value << (bit_pos % 32));
        bit_pos += 9;

        // Extract 32-bit limbs when we have enough bits
        while (bit_pos >= 32 && result_limb < 8) {
            result.limbs[result_limb] = (uint32_t)(accumulator & 0xFFFFFFFF);
            accumulator >>= 32;
            bit_pos -= 32;
            result_limb++;
        }
    }

    // Handle remaining bits
    if (result_limb < 8 && accumulator != 0) {
        result.limbs[result_limb] = (uint32_t)accumulator;
    }
}

// Store Felt252 into 28 M31 limbs (9-bit each)
__device__ __forceinline__ void felt252_to_m31_limbs(const felt252& value, m31* limbs) {
    // Extract 9 bits at a time from the 256-bit value
    uint64_t accumulator = 0;
    int bits_in_acc = 0;
    int limb_idx = 0;
    int result_idx = 0;

    while (result_idx < 28) {
        // Load more bits if needed
        while (bits_in_acc < 9 && limb_idx < 8) {
            accumulator |= ((uint64_t)value.limbs[limb_idx]) << bits_in_acc;
            bits_in_acc += 32;
            limb_idx++;
        }

        // Extract 9 bits
        limbs[result_idx] = m31{(uint32_t)(accumulator & 0x1FF)}; // brace-init: NVRTC has no compound literals
        accumulator >>= 9;
        bits_in_acc -= 9;
        result_idx++;
    }
}

#endif // EC_OPS_CUH
// Generated from stwo-cairo preprocessed_columns/poseidon_round_keys.rs.
// Canonical Felt252Width27 words; checked by the Poseidon deduce oracle.
#ifndef STWO_WIT_POSEIDON_ROUND_KEYS_CUH
#define STWO_WIT_POSEIDON_ROUND_KEYS_CUH
static __device__ __constant__ unsigned STWO_WIT_POSEIDON_ROUND_KEYS[35][30] = {
    {108983501u,67515900u,54991392u,75273041u,93491655u,71472462u,72290464u,34668303u,113539709u,196u,33937062u,130217817u,98349751u,132532806u,32690983u,36806568u,116766677u,52963354u,25557217u,241u,68589311u,96069254u,57701456u,87317035u,71069222u,15362084u,1251686u,61383961u,41881734u,168u},
    {82221527u,79479259u,53357585u,23260394u,72894413u,108925191u,22075484u,119945546u,117980982u,181u,87591042u,130945919u,19688221u,50108412u,38982551u,32466597u,87986141u,119440234u,118948285u,250u,40574270u,45123791u,128521102u,41635071u,99271094u,73667640u,118079017u,16828420u,64620168u,192u},
    {105200221u,124970046u,109948292u,70811273u,81718232u,132707747u,60715908u,116488516u,53112683u,134u,79329511u,85548395u,92494631u,10311551u,132430248u,10213468u,79964179u,53633858u,84852577u,167u,44826300u,126198461u,39041135u,80726338u,44484655u,118490394u,112818930u,37891098u,74082441u,166u},
    {93447587u,42978619u,31834720u,95484188u,45640010u,98135881u,30983986u,62031093u,11133505u,170u,40398848u,49453908u,36477101u,111111102u,14742666u,131835566u,43556303u,69045853u,31247543u,67u,88752026u,13205534u,111564362u,55955178u,66274107u,109621929u,85259045u,128003169u,8776477u,150u},
    {39976036u,125368084u,90162789u,21698025u,32223256u,55515373u,102746996u,33190869u,47808605u,241u,8056734u,38977152u,21774454u,70696684u,111793298u,92929314u,112520153u,104842155u,21493055u,203u,44075553u,111547962u,77453055u,104012182u,40046921u,134143042u,111559922u,10704274u,102956839u,0u},
    {1711939u,66523566u,128212418u,63485427u,44607407u,17137846u,25886264u,55136874u,53872891u,116u,110866280u,5485363u,32820040u,125587568u,92287253u,11445001u,37401821u,114376336u,101439796u,130u,21987121u,90708963u,71045079u,117728796u,38848826u,58111634u,38621656u,85298676u,65270799u,40u},
    {111678102u,103895240u,110909397u,13131207u,13651789u,130710896u,5071650u,61337970u,129255144u,174u,1598026u,11704857u,101294714u,119953447u,108916189u,63420334u,27301061u,83813870u,29750814u,181u,32639279u,74332121u,42929712u,68484522u,98560429u,5720540u,36834833u,71912052u,119871757u,81u},
    {41172392u,32357482u,118090980u,116711172u,128717827u,60826968u,45451923u,63866405u,103704690u,104u,106987778u,55807011u,103830882u,124078208u,34059158u,52302877u,23703067u,77523823u,75160024u,149u,100846244u,122128702u,48500601u,102873573u,20263569u,103326749u,63944989u,77616037u,77351902u,27u},
    {99215504u,125336187u,66571659u,119304461u,104159322u,129985631u,110290820u,69147331u,89663212u,215u,74386638u,51179127u,104316437u,103010844u,82084313u,2285518u,112644485u,72913905u,105967681u,56u,21926084u,31997324u,22511931u,40593311u,123658302u,76270133u,88028412u,108690577u,99433080u,148u},
    {69671876u,119724050u,26245253u,23091177u,48500346u,104626275u,127444958u,108342054u,81530714u,15u,59080470u,129436966u,129354960u,60555563u,131993044u,120605018u,45716686u,74930377u,78796281u,109u,17046537u,29746446u,69904145u,132748579u,75962983u,74545923u,132040380u,9635435u,71318113u,37u},
    {70994281u,15649251u,59282030u,78715495u,82263208u,48948665u,17258119u,60185797u,107179700u,128u,107123517u,13251769u,76764622u,35381761u,49356727u,108392889u,131814381u,31593357u,113324283u,75u,8508271u,85170950u,40913088u,27162716u,26613119u,128698067u,66970122u,75299283u,121026487u,12u},
    {86802109u,44164532u,9590658u,39740483u,8107918u,5253500u,4668629u,106059765u,52684185u,229u,97826562u,69294000u,73240386u,3179827u,22187410u,10243701u,69420423u,38876317u,117450044u,219u,110213694u,88582530u,93156210u,646947u,20675283u,119129750u,11639708u,118132320u,130620913u,13u},
    {82529911u,131496339u,57476185u,111763u,83161050u,67508093u,11327048u,63595286u,117117243u,37u,17454110u,7117494u,103723805u,53398470u,20387586u,84324697u,113730575u,69889433u,28310577u,88u,117985912u,70749428u,61947424u,81348061u,48771836u,25188666u,42857083u,97967350u,78794549u,13u},
    {117972071u,65440412u,20559128u,90510202u,27408740u,55527714u,8075281u,88246709u,84328702u,169u,6397352u,17350878u,19703354u,78372292u,102110545u,58408604u,78662428u,38680773u,10354551u,188u,119156955u,46246999u,92808705u,13384731u,123240462u,18731563u,76814091u,133485574u,22726564u,38u},
    {5533154u,78105520u,39963550u,3468184u,65445573u,125399853u,21314099u,129018851u,79266015u,54u,126833221u,27671003u,90406181u,113697758u,121857210u,105746760u,25968616u,117870993u,67826037u,199u,27529425u,80612229u,33179767u,120028204u,33194119u,15956825u,46295054u,24215457u,33634763u,10u},
    {111783143u,28665396u,47900070u,34644686u,79653623u,120497294u,48064430u,131941661u,35572006u,226u,51217707u,104640594u,72704380u,65028965u,98380761u,23990130u,125517100u,27601012u,53518553u,207u,133479618u,63553962u,15908778u,101923625u,17942223u,102594958u,93597475u,73197345u,99999213u,109u},
    {111388242u,132704297u,115403576u,72395683u,24884071u,50069099u,25000097u,37912587u,61632636u,5u,11469590u,76087799u,112376752u,98317795u,63029975u,123845884u,97136379u,128392999u,6216466u,166u,41874923u,44771572u,56170941u,129360156u,93287380u,119849512u,98996361u,97894935u,44718723u,95u},
    {89435560u,74515172u,98848456u,101360667u,62602978u,87032076u,15324749u,100782423u,29690828u,40u,18087495u,81798234u,97248439u,126171917u,25517180u,63049317u,93293424u,70472061u,69322325u,49u,15385509u,117730236u,60139493u,24140369u,72679294u,58317039u,16973852u,121224801u,49682833u,224u},
    {10128945u,37568066u,106126912u,58146226u,126680393u,45106596u,34946075u,75750958u,118853327u,176u,118371483u,57230519u,41879949u,32453175u,75906104u,53808979u,100104834u,69032416u,104916650u,139u,9403170u,133657895u,38080630u,52743195u,117167590u,71038343u,123125705u,113082261u,10407436u,18u},
    {111217896u,37491581u,81159394u,79205292u,24461001u,99920103u,63264749u,70182276u,116355232u,1u,46685718u,36383461u,42323886u,54241076u,54262788u,105769837u,122845963u,123445208u,49388190u,181u,89357053u,88759127u,27963533u,42447105u,19321370u,90119768u,47427647u,102821300u,54221568u,221u},
    {120531333u,129954016u,27253900u,85530403u,97904035u,7006377u,42771073u,46779856u,84146220u,87u,69592926u,77282489u,32761144u,40428556u,24510854u,22836361u,85926882u,4694578u,65160521u,43u,42955159u,45384478u,72761801u,18718250u,69135180u,128315727u,111135163u,62269903u,44268u,232u},
    {90186835u,62963394u,69748637u,72827423u,126387257u,134029375u,46212479u,41614174u,113999832u,46u,17076785u,45265593u,17382223u,74351878u,48417200u,65473211u,5624050u,13820104u,74370985u,47u,27214899u,30317536u,61795093u,96159715u,115350666u,45514885u,23706920u,60473532u,123299068u,149u},
    {56648052u,115546634u,32356807u,128054390u,64096549u,7589803u,113817664u,34345618u,71237846u,60u,62758061u,76096974u,88140287u,133687653u,6288265u,92032321u,45947681u,101306397u,117190744u,41u,40130390u,112268854u,60046484u,23427888u,121776403u,15645435u,69672312u,103235975u,67254594u,74u},
    {17043256u,58581780u,15470278u,62699119u,44818741u,78145099u,68432787u,30929066u,4962008u,222u,53856330u,103709778u,90485387u,66402180u,89261680u,36809070u,9795240u,8885568u,127261430u,36u,121662456u,23499840u,93750973u,96478600u,76621848u,94096686u,60692495u,17058363u,10885942u,242u},
    {106432673u,10544470u,27937359u,76743612u,35019372u,116506230u,130781539u,17367742u,28807129u,190u,36399072u,61834203u,15799846u,132829338u,49341625u,105096617u,73534595u,14299552u,13791966u,84u,56603562u,21826038u,85705463u,79392785u,81447842u,75747243u,24535171u,30750338u,19847025u,194u},
    {120411281u,17070385u,19492729u,120256629u,123627478u,8019866u,76062298u,118115707u,16889650u,187u,129352505u,91926763u,46253588u,133534918u,107871916u,100289629u,37161341u,125270054u,105028473u,218u,66846407u,96699385u,81224993u,128383429u,44941374u,55196800u,97127118u,131438183u,75819828u,185u},
    {32594100u,66503823u,47221313u,40352239u,113148638u,130548883u,60109654u,107456586u,115011622u,31u,92240073u,91243898u,107569686u,31500980u,3066576u,78151245u,72879471u,45648767u,64656783u,204u,99176548u,77994379u,75692502u,20385625u,22578008u,26327991u,10960774u,128966450u,102154995u,177u},
    {78238806u,71460648u,122775639u,70773192u,67148792u,131728138u,106201667u,126088607u,30158816u,176u,129003663u,100573627u,124578154u,99237933u,118894389u,41215589u,133744660u,119262918u,38463397u,129u,127782681u,45001356u,85287172u,877590u,1801195u,87672866u,18355902u,76569100u,101916970u,23u},
    {63197605u,55364223u,71507238u,84800515u,118113846u,72145601u,76671293u,38037069u,134105344u,115u,93983890u,55994403u,55526800u,14913127u,72532654u,27194586u,88473048u,1969185u,46269214u,221u,97662451u,126706253u,94653324u,127259974u,97185346u,38299392u,37726545u,37008711u,14742460u,193u},
    {2904184u,18510435u,1146157u,43950542u,56270672u,29429534u,132144059u,110819150u,131592638u,75u,61718709u,29665114u,88742254u,96947403u,71432162u,34306510u,97879137u,107275032u,130250554u,220u,76392468u,117554362u,124083224u,31923102u,7459009u,19127459u,85389610u,22256068u,40705332u,21u},
    {123117644u,52674201u,112969018u,40148099u,129069093u,34257475u,37165945u,81832526u,133194821u,27u,24880048u,24171112u,56298041u,87500203u,44068429u,119245250u,122878691u,130828209u,25206227u,182u,27159447u,101227101u,124895958u,67252156u,18547804u,77171144u,48339189u,118072484u,11003477u,44u},
    {67024801u,95241349u,49807313u,5442204u,94841965u,84959361u,88368645u,2711569u,53802843u,10u,84583473u,20634516u,26550069u,119896438u,107542542u,87756341u,4227890u,114229942u,11489227u,186u,1777253u,120760050u,89057642u,115345294u,738969u,9282716u,4532327u,131935050u,20036834u,96u},
    {108562789u,49070565u,116977957u,33069232u,29702393u,31087816u,80937428u,101545013u,74093991u,172u,89047066u,29265775u,78465828u,128527540u,65504641u,101983208u,132844936u,94471740u,32674263u,151u,48241171u,35449175u,87412578u,124237429u,75751435u,38669915u,111557732u,27527072u,7158077u,160u},
    {40344960u,95974989u,85718144u,58815321u,6999887u,36317282u,60763688u,83482928u,77414937u,197u,72816549u,62085211u,45961980u,28792300u,46620776u,21133054u,73411690u,114984143u,41210002u,162u,134155355u,55686679u,57652760u,10979022u,42942814u,89430346u,112475870u,123449099u,130372280u,195u},
    {0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u,0u},
};
#endif
// Computed-deduce device functions for the witness-JIT lane (ISA-V3 kinds 2/3).
//
// Transcribed 1:1 from `stwo-cairo`'s host reference
// (`witness/fast_deduction/pedersen.rs::PartialEcMul::<14>::deduce_output` and
// `PackedPedersenPointsTableWindowBits18::deduce_output`) onto the proven fp256
// primitives in `ec_ops.cuh`. The register ABI (flat `unsigned` banks) is the
// recorder's packing in `witness_eval/recording.rs` — change either side only
// with the other, and bump `WITNESS_CODEGEN_VERSION`.
//
// This header is compiled in TWO translation contexts:
//   1. NVRTC witness-JIT kernels: `codegen.rs` textually embeds the fp256 chain
//      (storage/ptx/carry-chain/config/dispatch/ec_ops, includes stripped) and
//      then this header, only when a program uses deduce kinds 2/3.
//   2. nvcc, via `stwo_wit_deduce_oracle.cu`: the precompiled truth-oracle
//      launcher that qualifies these functions against the host fast_deduction
//      over real rows, isolating fp256-math bugs from codegen bugs.
//
// Correctness perimeter: `ec_add_affine` is an INCOMPLETE affine add (no
// doubling/infinity branch). The pedersen shift-point table construction keeps
// all real (and, by the recording interp gates, all padding) additions on
// distinct-x points; the pod differential (`STWO_CUDA_WITNESS_VERIFY`) compares
// every row, so a violated premise fails loudly instead of shipping bytes.
#ifndef STWO_WIT_DEDUCE_CUH
#define STWO_WIT_DEDUCE_CUH


#if !defined(STWO_WIT_EMBED) || defined(STWO_WIT_NEEDS_PEDERSEN)
// Module-local pedersen table globals — DEFINITIONS, not externs. Device
// globals never cross CUmodule boundaries, so each module embedding this
// header carries its own copy; `runtime_jit.cu` fills them right after
// `cuModuleLoadDataEx` (and the oracle launcher fills its own at init).
// Layout: column c of row r = 9-bit M31 limb c of the point coordinate
// (x limbs in columns 0..28, y limbs in 28..56), rows flat per the host
// `PEDERSEN_TABLE_18` section layout [low0 | high0 | low2 | high2].
__device__ m31* g_stwo_wit_pedersen_cols[56];
__device__ unsigned g_stwo_wit_pedersen_n_rows;

// DeduceKind::PedersenPointsTableW18 (=3): in[1] = row index ->
// out[56] = [x limbs 0..28 | y limbs 28..56].
static __device__ __forceinline__ void stwo_wit_deduce_pedersen_points_w18(
    const unsigned* in, unsigned* out) {
    // n_rows is a power of two; the mask keeps a garbage index (poisoned or
    // adversarial recording) memory-safe. It is a no-op for every in-range row
    // — the differential gates own value correctness, this owns memory safety.
    unsigned row = in[0] & (g_stwo_wit_pedersen_n_rows - 1u);
    for (int c = 0; c < 56; ++c) {
        out[c] = g_stwo_wit_pedersen_cols[c][row];
    }
}

// DeduceKind::PartialEcMulW18 (=2): one W18 EC-mul round.
//   in[72]  = [chain, round, w0..w13, acc_x limbs 16..44, acc_y limbs 44..72]
//   out[72] = [chain, round+1, w1..w13,0, new_x limbs, new_y limbs]
// where table_row = round * 2^18 + w0 and (new_x, new_y) = acc + table[row].
static __device__ __forceinline__ void stwo_wit_deduce_partial_ec_mul_w18(
    const unsigned* in, unsigned* out) {
    AffinePointCuda acc, tbl, sum;
    felt252_from_m31_limbs(acc.x, in + 16);
    felt252_from_m31_limbs(acc.y, in + 44);

    // round < 28 and w0 < 2^18 on every recorded row (host-interp-gated), so
    // the product stays far below both 2^32 and the padded row count; the mask
    // is the same memory-safety clamp as above.
    unsigned row = in[1] * 262144u + in[2];
    row &= (g_stwo_wit_pedersen_n_rows - 1u);
    m31 limbs[28];
    for (int c = 0; c < 28; ++c) {
        limbs[c] = g_stwo_wit_pedersen_cols[c][row];
    }
    felt252_from_m31_limbs(tbl.x, limbs);
    for (int c = 0; c < 28; ++c) {
        limbs[c] = g_stwo_wit_pedersen_cols[28 + c][row];
    }
    felt252_from_m31_limbs(tbl.y, limbs);

    ec_add_affine(acc, tbl, sum);

    out[0] = in[0];      // chain passthrough
    out[1] = in[1] + 1u; // round+1; round < 28 << M31 P, so ++ IS the m31 add
    for (int i = 0; i < 13; ++i) {
        out[2 + i] = in[3 + i]; // windows shift left one
    }
    out[15] = 0u;
    felt252_to_m31_limbs(sum.x, out + 16);
    felt252_to_m31_limbs(sum.y, out + 44);
}
#endif

// ---- DeduceKind::Felt{Add,Sub,Mul,Div} (4-7): fp256 body arithmetic ---------------
//
// in[56] = [a limbs 0..28 | b limbs 28..56], out[28] = result limbs. Host
// reference: stwo-cairo `Felt252`'s operators, whose Montgomery compensation
// factors make the limb encoding CANONICAL VALUES in and out (cpu.rs — the
// `FELT252_MONT_MUL_FACTOR` construction). Add/sub are linear, so raw-word
// modular add/sub is already canonical; mul/div convert to Montgomery, operate,
// and convert back — the exact operand pattern `ec_add_affine` uses internally
// (lambda = dy * dx^-1 with both operands in Montgomery form), so no novel
// fp256 algebra is introduced here.
//
// Division by zero: the host PANICS ("Division by zero"). Real writer traces
// never divide by zero (the sites are EC slope denominators, and padding rows
// replicate real rows); on device `felt_inverse(0)` yields an unspecified word
// and the differential gates fail loudly if that premise ever breaks.

static __device__ __forceinline__ void stwo_wit_deduce_felt_add(
    const unsigned* in, unsigned* out) {
    felt252 a, b;
    felt252_from_m31_limbs(a, in);
    felt252_from_m31_limbs(b, in + 28);
    felt252 r = felt_add(a, b);
    felt252_to_m31_limbs(r, out);
}

static __device__ __forceinline__ void stwo_wit_deduce_felt_sub(
    const unsigned* in, unsigned* out) {
    felt252 a, b;
    felt252_from_m31_limbs(a, in);
    felt252_from_m31_limbs(b, in + 28);
    felt252 r = felt_sub(a, b);
    felt252_to_m31_limbs(r, out);
}

static __device__ __noinline__ void stwo_wit_deduce_felt_mul(
    const unsigned* in, unsigned* out) {
    felt252 a, b;
    felt252_from_m31_limbs(a, in);
    felt252_from_m31_limbs(b, in + 28);
    felt252 r = felt_from_mont(felt_mul(felt_to_mont(a), felt_to_mont(b)));
    felt252_to_m31_limbs(r, out);
}

static __device__ __forceinline__ void stwo_wit_deduce_felt_div(
    const unsigned* in, unsigned* out) {
    felt252 a, b;
    felt252_from_m31_limbs(a, in);
    felt252_from_m31_limbs(b, in + 28);
    felt252 r =
        felt_from_mont(felt_mul(felt_to_mont(a), felt_inverse(felt_to_mont(b))));
    felt252_to_m31_limbs(r, out);
}

// ---- Cairo Poseidon fast-deduction ABI (kinds 8-11) -----------------------------
// Width27 values are ten canonical M31 words. Convert through the same canonical
// 28x9 representation used by the existing fp256 helpers; no Montgomery state is
// exposed across the ABI.
static __device__ __forceinline__ void stwo_wit_felt_from_w27(
    felt252& out, const unsigned* words) {
    m31 limbs[28];
    for (int j = 0; j < 9; ++j) {
        limbs[3 * j] = words[j] & 0x1ffu;
        limbs[3 * j + 1] = (words[j] >> 9) & 0x1ffu;
        limbs[3 * j + 2] = (words[j] >> 18) & 0x1ffu;
    }
    limbs[27] = words[9] & 0x1ffu;
    felt252_from_m31_limbs(out, limbs);
}

static __device__ __forceinline__ void stwo_wit_felt_to_w27(
    const felt252& value, unsigned* words) {
    m31 limbs[28];
    felt252_to_m31_limbs(value, limbs);
    for (int j = 0; j < 9; ++j) {
        words[j] = limbs[3 * j] | (limbs[3 * j + 1] << 9) |
                   (limbs[3 * j + 2] << 18);
    }
    words[9] = limbs[27];
}

static __device__ __forceinline__ felt252 stwo_wit_felt_value_mul(
    const felt252& a, const felt252& b) {
    return felt_from_mont(felt_mul(felt_to_mont(a), felt_to_mont(b)));
}

static __device__ __forceinline__ felt252 stwo_wit_felt_value_cube(
    const felt252& a) {
    felt252 square = stwo_wit_felt_value_mul(a, a);
    return stwo_wit_felt_value_mul(square, a);
}

static __device__ __forceinline__ felt252 stwo_wit_poseidon_key(
    unsigned round, int key) {
    felt252 result;
    unsigned safe_round = round < 35u ? round : 0u;
    stwo_wit_felt_from_w27(result, &STWO_WIT_POSEIDON_ROUND_KEYS[safe_round][key * 10]);
    return result;
}

static __device__ __forceinline__ void stwo_wit_deduce_poseidon_round_keys(
    const unsigned* in, unsigned* out) {
    unsigned round = in[0] < 35u ? in[0] : 0u;
    for (int word = 0; word < 30; ++word) {
        out[word] = STWO_WIT_POSEIDON_ROUND_KEYS[round][word];
    }
}

static __device__ __forceinline__ void stwo_wit_deduce_cube_252(
    const unsigned* in, unsigned* out) {
    felt252 value;
    stwo_wit_felt_from_w27(value, in);
    felt252 cube = stwo_wit_felt_value_cube(value);
    stwo_wit_felt_to_w27(cube, out);
}

static __device__ __forceinline__ void stwo_wit_deduce_poseidon_full_round_chain(
    const unsigned* in, unsigned* out) {
    felt252 x, y, z;
    stwo_wit_felt_from_w27(x, in + 2);
    stwo_wit_felt_from_w27(y, in + 12);
    stwo_wit_felt_from_w27(z, in + 22);
    x = stwo_wit_felt_value_cube(x);
    y = stwo_wit_felt_value_cube(y);
    z = stwo_wit_felt_value_cube(z);

    felt252 y_z = felt_sub(y, z);
    felt252 x_y_z = felt_sub(x, y_z);
    felt252 x_y_z_neg = felt_add(x, y_z);
    felt252 x_y = felt_add(x, y);
    felt252 two_x_y = felt_add(x_y, x_y);
    felt252 new_x = felt_add(felt_add(two_x_y, x_y_z), stwo_wit_poseidon_key(in[1], 0));
    felt252 new_y = felt_add(x_y_z, stwo_wit_poseidon_key(in[1], 1));
    felt252 new_z = felt_add(felt_sub(x_y_z_neg, z), stwo_wit_poseidon_key(in[1], 2));

    out[0] = in[0];
    out[1] = in[1] + 1u;
    stwo_wit_felt_to_w27(new_x, out + 2);
    stwo_wit_felt_to_w27(new_y, out + 12);
    stwo_wit_felt_to_w27(new_z, out + 22);
}

static __device__ __forceinline__ void stwo_wit_deduce_poseidon_3_partial_rounds_chain(
    const unsigned* in, unsigned* out) {
    felt252 state[4];
    for (int i = 0; i < 4; ++i) {
        stwo_wit_felt_from_w27(state[i], in + 2 + i * 10);
    }
    for (int key = 0; key < 3; ++key) {
        felt252 z23 = stwo_wit_felt_value_cube(state[3]);
        felt252 z03_z13 = felt_add(state[0], state[2]);
        felt252 z03_z13_z1 = felt_add(z03_z13, state[1]);
        felt252 longsum = felt_add(
            felt_sub(felt_add(z03_z13_z1, state[3]), z23),
            stwo_wit_poseidon_key(in[1], key));
        felt252 half_z3 = felt_add(
            felt_add(felt_add(longsum, z03_z13_z1), z03_z13), state[0]);
        felt252 z3 = felt_add(half_z3, half_z3);
        state[0] = state[2];
        state[1] = state[3];
        state[2] = z23;
        state[3] = z3;
    }
    out[0] = in[0];
    out[1] = in[1] + 1u;
    for (int i = 0; i < 4; ++i) {
        stwo_wit_felt_to_w27(state[i], out + 2 + i * 10);
    }
}

#endif // STWO_WIT_DEDUCE_CUH

static __device__ __forceinline__ unsigned stwo_m31_inverse(unsigned a) {
    unsigned result = a;                 // consumes exponent bit 30
    for (int bit = 29; bit >= 0; --bit) {
        result = stwo_m31_mul(result, result);
        if (bit != 1) { result = stwo_m31_mul(result, a); }
    }
    return result;
}

static __device__ __forceinline__ unsigned stwo_wit_deduce_limb(
    const unsigned *const *tb, const unsigned *ts, unsigned id, unsigned limb) {
    unsigned tag = id >> 30u;
    unsigned val = id & 0x3FFFFFFFu;
    if (tag == 1u) { return val < ts[1] ? tb[1u + limb][val] : 0u; }
    return (limb < 8u && val < ts[2]) ? tb[29u + limb][val] : 0u;
}

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_d14e690e89d48795(
    const unsigned *const *input_cols,   // [n_inputs][row]
    const unsigned *const *table_bases,  // deduce_output LUTs, per table
    const unsigned *table_strides,       // words per key, per table
    unsigned *const *out_cols,           // [n_cols][row]
    unsigned *const *mult_counts,        // atomic count tables, per mult table
    unsigned *lookup_words,              // [k * row_count + row] (word-major)
    unsigned *sub_words,                 // [k * row_count + row] (word-major)
    unsigned row_count
) {
    unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) { return; }

    unsigned r0 = 0u;
    lookup_words[89u * row_count + row] = r0;
    unsigned r1 = 1u;
    unsigned r2 = 2u;
    unsigned r3 = 4u;
    unsigned r4 = 8u;
    unsigned r5 = 32u;
    unsigned r6 = 64u;
    unsigned r7 = 136u;
    unsigned r8 = 65536u;
    unsigned r9 = 262144u;
    unsigned r10 = 524288u;
    unsigned r11 = 4194304u;
    unsigned r12 = 134217728u;
    unsigned r13 = 447122465u;
    lookup_words[318u * row_count + row] = r13;
    lookup_words[320u * row_count + row] = r13;
    lookup_words[322u * row_count + row] = r13;
    lookup_words[324u * row_count + row] = r13;
    lookup_words[326u * row_count + row] = r13;
    lookup_words[328u * row_count + row] = r13;
    lookup_words[330u * row_count + row] = r13;
    lookup_words[332u * row_count + row] = r13;
    lookup_words[334u * row_count + row] = r13;
    unsigned r14 = 463900084u;
    lookup_words[336u * row_count + row] = r14;
    lookup_words[338u * row_count + row] = r14;
    lookup_words[340u * row_count + row] = r14;
    lookup_words[342u * row_count + row] = r14;
    lookup_words[344u * row_count + row] = r14;
    lookup_words[346u * row_count + row] = r14;
    lookup_words[348u * row_count + row] = r14;
    lookup_words[350u * row_count + row] = r14;
    lookup_words[352u * row_count + row] = r14;
    unsigned r15 = 480677703u;
    lookup_words[276u * row_count + row] = r15;
    lookup_words[278u * row_count + row] = r15;
    lookup_words[280u * row_count + row] = r15;
    lookup_words[282u * row_count + row] = r15;
    lookup_words[284u * row_count + row] = r15;
    lookup_words[286u * row_count + row] = r15;
    lookup_words[288u * row_count + row] = r15;
    lookup_words[290u * row_count + row] = r15;
    lookup_words[292u * row_count + row] = r15;
    lookup_words[294u * row_count + row] = r15;
    lookup_words[296u * row_count + row] = r15;
    lookup_words[298u * row_count + row] = r15;
    unsigned r16 = 497455322u;
    lookup_words[300u * row_count + row] = r16;
    lookup_words[302u * row_count + row] = r16;
    lookup_words[304u * row_count + row] = r16;
    lookup_words[306u * row_count + row] = r16;
    lookup_words[308u * row_count + row] = r16;
    lookup_words[310u * row_count + row] = r16;
    lookup_words[312u * row_count + row] = r16;
    lookup_words[314u * row_count + row] = r16;
    lookup_words[316u * row_count + row] = r16;
    unsigned r17 = 514232941u;
    lookup_words[228u * row_count + row] = r17;
    lookup_words[230u * row_count + row] = r17;
    lookup_words[232u * row_count + row] = r17;
    lookup_words[234u * row_count + row] = r17;
    lookup_words[236u * row_count + row] = r17;
    lookup_words[238u * row_count + row] = r17;
    lookup_words[240u * row_count + row] = r17;
    lookup_words[242u * row_count + row] = r17;
    lookup_words[244u * row_count + row] = r17;
    lookup_words[246u * row_count + row] = r17;
    lookup_words[248u * row_count + row] = r17;
    lookup_words[250u * row_count + row] = r17;
    unsigned r18 = 517791011u;
    lookup_words[372u * row_count + row] = r18;
    lookup_words[375u * row_count + row] = r18;
    lookup_words[378u * row_count + row] = r18;
    lookup_words[381u * row_count + row] = r18;
    lookup_words[384u * row_count + row] = r18;
    lookup_words[387u * row_count + row] = r18;
    unsigned r19 = 531010560u;
    lookup_words[252u * row_count + row] = r19;
    lookup_words[254u * row_count + row] = r19;
    lookup_words[256u * row_count + row] = r19;
    lookup_words[258u * row_count + row] = r19;
    lookup_words[260u * row_count + row] = r19;
    lookup_words[262u * row_count + row] = r19;
    lookup_words[264u * row_count + row] = r19;
    lookup_words[266u * row_count + row] = r19;
    lookup_words[268u * row_count + row] = r19;
    lookup_words[270u * row_count + row] = r19;
    lookup_words[272u * row_count + row] = r19;
    lookup_words[274u * row_count + row] = r19;
    unsigned r20 = 682009131u;
    lookup_words[354u * row_count + row] = r20;
    lookup_words[356u * row_count + row] = r20;
    lookup_words[358u * row_count + row] = r20;
    lookup_words[360u * row_count + row] = r20;
    lookup_words[362u * row_count + row] = r20;
    lookup_words[364u * row_count + row] = r20;
    lookup_words[366u * row_count + row] = r20;
    lookup_words[368u * row_count + row] = r20;
    lookup_words[370u * row_count + row] = r20;
    unsigned r21 = 1410849886u;
    lookup_words[204u * row_count + row] = r21;
    lookup_words[206u * row_count + row] = r21;
    lookup_words[208u * row_count + row] = r21;
    lookup_words[210u * row_count + row] = r21;
    lookup_words[212u * row_count + row] = r21;
    lookup_words[214u * row_count + row] = r21;
    lookup_words[216u * row_count + row] = r21;
    lookup_words[218u * row_count + row] = r21;
    lookup_words[220u * row_count + row] = r21;
    lookup_words[222u * row_count + row] = r21;
    lookup_words[224u * row_count + row] = r21;
    lookup_words[226u * row_count + row] = r21;
    unsigned r22 = 1444721856u;
    lookup_words[146u * row_count + row] = r22;
    unsigned r23 = 1621226978u;
    lookup_words[0u * row_count + row] = r23;
    lookup_words[73u * row_count + row] = r23;
    unsigned r24 = 1813904000u;
    lookup_words[480u * row_count + row] = r24;
    lookup_words[483u * row_count + row] = r24;
    lookup_words[486u * row_count + row] = r24;
    unsigned r25 = 1830681619u;
    lookup_words[462u * row_count + row] = r25;
    lookup_words[465u * row_count + row] = r25;
    lookup_words[468u * row_count + row] = r25;
    lookup_words[471u * row_count + row] = r25;
    lookup_words[474u * row_count + row] = r25;
    lookup_words[477u * row_count + row] = r25;
    unsigned r26 = 1847459238u;
    lookup_words[444u * row_count + row] = r26;
    lookup_words[447u * row_count + row] = r26;
    lookup_words[450u * row_count + row] = r26;
    lookup_words[453u * row_count + row] = r26;
    lookup_words[456u * row_count + row] = r26;
    lookup_words[459u * row_count + row] = r26;
    unsigned r27 = 1864236857u;
    lookup_words[426u * row_count + row] = r27;
    lookup_words[429u * row_count + row] = r27;
    lookup_words[432u * row_count + row] = r27;
    lookup_words[435u * row_count + row] = r27;
    lookup_words[438u * row_count + row] = r27;
    lookup_words[441u * row_count + row] = r27;
    unsigned r28 = 1881014476u;
    lookup_words[408u * row_count + row] = r28;
    lookup_words[411u * row_count + row] = r28;
    lookup_words[414u * row_count + row] = r28;
    lookup_words[417u * row_count + row] = r28;
    lookup_words[420u * row_count + row] = r28;
    lookup_words[423u * row_count + row] = r28;
    unsigned r29 = 1897792095u;
    lookup_words[390u * row_count + row] = r29;
    lookup_words[393u * row_count + row] = r29;
    lookup_words[396u * row_count + row] = r29;
    lookup_words[399u * row_count + row] = r29;
    lookup_words[402u * row_count + row] = r29;
    lookup_words[405u * row_count + row] = r29;
    unsigned r30 = 2065568285u;
    lookup_words[489u * row_count + row] = r30;
    lookup_words[492u * row_count + row] = r30;
    lookup_words[495u * row_count + row] = r30;
    unsigned r31 = input_cols[0u][row];
    out_cols[0u][row] = r31;
    lookup_words[1u * row_count + row] = r31;
    lookup_words[74u * row_count + row] = r31;
    unsigned r32 = input_cols[1u][row];
    unsigned r33 = input_cols[2u][row];
    unsigned r34 = input_cols[3u][row];
    out_cols[3u][row] = r34;
    lookup_words[4u * row_count + row] = r34;
    lookup_words[76u * row_count + row] = r34;
    unsigned r35 = input_cols[4u][row];
    out_cols[4u][row] = r35;
    lookup_words[5u * row_count + row] = r35;
    lookup_words[77u * row_count + row] = r35;
    unsigned r36 = input_cols[5u][row];
    out_cols[5u][row] = r36;
    lookup_words[6u * row_count + row] = r36;
    lookup_words[78u * row_count + row] = r36;
    unsigned r37 = input_cols[6u][row];
    out_cols[6u][row] = r37;
    lookup_words[7u * row_count + row] = r37;
    lookup_words[79u * row_count + row] = r37;
    unsigned r38 = input_cols[7u][row];
    out_cols[7u][row] = r38;
    lookup_words[8u * row_count + row] = r38;
    lookup_words[80u * row_count + row] = r38;
    unsigned r39 = input_cols[8u][row];
    out_cols[8u][row] = r39;
    lookup_words[9u * row_count + row] = r39;
    lookup_words[81u * row_count + row] = r39;
    unsigned r40 = input_cols[9u][row];
    out_cols[9u][row] = r40;
    lookup_words[10u * row_count + row] = r40;
    lookup_words[82u * row_count + row] = r40;
    unsigned r41 = input_cols[10u][row];
    out_cols[10u][row] = r41;
    lookup_words[11u * row_count + row] = r41;
    lookup_words[83u * row_count + row] = r41;
    unsigned r42 = input_cols[11u][row];
    out_cols[11u][row] = r42;
    lookup_words[12u * row_count + row] = r42;
    lookup_words[84u * row_count + row] = r42;
    unsigned r43 = input_cols[12u][row];
    out_cols[12u][row] = r43;
    lookup_words[13u * row_count + row] = r43;
    lookup_words[85u * row_count + row] = r43;
    unsigned r44 = input_cols[13u][row];
    out_cols[13u][row] = r44;
    lookup_words[14u * row_count + row] = r44;
    lookup_words[86u * row_count + row] = r44;
    unsigned r45 = input_cols[14u][row];
    out_cols[14u][row] = r45;
    lookup_words[15u * row_count + row] = r45;
    lookup_words[87u * row_count + row] = r45;
    unsigned r46 = input_cols[15u][row];
    out_cols[15u][row] = r46;
    lookup_words[16u * row_count + row] = r46;
    lookup_words[88u * row_count + row] = r46;
    unsigned r47 = input_cols[16u][row];
    unsigned r48 = input_cols[17u][row];
    unsigned r49 = input_cols[18u][row];
    unsigned r50 = input_cols[19u][row];
    unsigned r51 = input_cols[20u][row];
    unsigned r52 = input_cols[21u][row];
    unsigned r53 = input_cols[22u][row];
    unsigned r54 = input_cols[23u][row];
    unsigned r55 = input_cols[24u][row];
    unsigned r56 = input_cols[25u][row];
    unsigned r57 = input_cols[26u][row];
    unsigned r58 = input_cols[27u][row];
    unsigned r59 = input_cols[28u][row];
    unsigned r60 = input_cols[29u][row];
    unsigned r61 = input_cols[30u][row];
    unsigned r62 = input_cols[31u][row];
    unsigned r63 = input_cols[32u][row];
    unsigned r64 = input_cols[33u][row];
    unsigned r65 = input_cols[34u][row];
    unsigned r66 = input_cols[35u][row];
    unsigned r67 = input_cols[36u][row];
    unsigned r68 = input_cols[37u][row];
    unsigned r69 = input_cols[38u][row];
    unsigned r70 = input_cols[39u][row];
    unsigned r71 = input_cols[40u][row];
    unsigned r72 = input_cols[41u][row];
    unsigned r73 = input_cols[42u][row];
    unsigned r74 = input_cols[43u][row];
    unsigned r75 = input_cols[16u][row];
    unsigned r76 = input_cols[17u][row];
    unsigned r77 = input_cols[18u][row];
    unsigned r78 = input_cols[19u][row];
    unsigned r79 = input_cols[20u][row];
    unsigned r80 = input_cols[21u][row];
    unsigned r81 = input_cols[22u][row];
    unsigned r82 = input_cols[23u][row];
    unsigned r83 = input_cols[24u][row];
    unsigned r84 = input_cols[25u][row];
    unsigned r85 = input_cols[26u][row];
    unsigned r86 = input_cols[27u][row];
    unsigned r87 = input_cols[28u][row];
    unsigned r88 = input_cols[29u][row];
    unsigned r89 = input_cols[30u][row];
    unsigned r90 = input_cols[31u][row];
    unsigned r91 = input_cols[32u][row];
    unsigned r92 = input_cols[33u][row];
    unsigned r93 = input_cols[34u][row];
    unsigned r94 = input_cols[35u][row];
    unsigned r95 = input_cols[36u][row];
    unsigned r96 = input_cols[37u][row];
    unsigned r97 = input_cols[38u][row];
    unsigned r98 = input_cols[39u][row];
    unsigned r99 = input_cols[40u][row];
    unsigned r100 = input_cols[41u][row];
    unsigned r101 = input_cols[42u][row];
    unsigned r102 = input_cols[43u][row];
    unsigned r103 = input_cols[16u][row];
    unsigned r104 = input_cols[17u][row];
    unsigned r105 = input_cols[18u][row];
    unsigned r106 = input_cols[19u][row];
    unsigned r107 = input_cols[20u][row];
    unsigned r108 = input_cols[21u][row];
    unsigned r109 = input_cols[22u][row];
    unsigned r110 = input_cols[23u][row];
    unsigned r111 = input_cols[24u][row];
    unsigned r112 = input_cols[25u][row];
    unsigned r113 = input_cols[26u][row];
    unsigned r114 = input_cols[27u][row];
    unsigned r115 = input_cols[28u][row];
    unsigned r116 = input_cols[29u][row];
    unsigned r117 = input_cols[30u][row];
    unsigned r118 = input_cols[31u][row];
    unsigned r119 = input_cols[32u][row];
    unsigned r120 = input_cols[33u][row];
    unsigned r121 = input_cols[34u][row];
    unsigned r122 = input_cols[35u][row];
    unsigned r123 = input_cols[36u][row];
    unsigned r124 = input_cols[37u][row];
    unsigned r125 = input_cols[38u][row];
    unsigned r126 = input_cols[39u][row];
    unsigned r127 = input_cols[40u][row];
    unsigned r128 = input_cols[41u][row];
    unsigned r129 = input_cols[42u][row];
    unsigned r130 = input_cols[43u][row];
    unsigned r131 = input_cols[16u][row];
    unsigned r132 = input_cols[17u][row];
    unsigned r133 = input_cols[18u][row];
    unsigned r134 = input_cols[19u][row];
    unsigned r135 = input_cols[20u][row];
    unsigned r136 = input_cols[21u][row];
    unsigned r137 = input_cols[22u][row];
    unsigned r138 = input_cols[23u][row];
    unsigned r139 = input_cols[24u][row];
    unsigned r140 = input_cols[25u][row];
    unsigned r141 = input_cols[26u][row];
    unsigned r142 = input_cols[27u][row];
    unsigned r143 = input_cols[28u][row];
    unsigned r144 = input_cols[29u][row];
    unsigned r145 = input_cols[30u][row];
    unsigned r146 = input_cols[31u][row];
    unsigned r147 = input_cols[32u][row];
    unsigned r148 = input_cols[33u][row];
    unsigned r149 = input_cols[34u][row];
    unsigned r150 = input_cols[35u][row];
    unsigned r151 = input_cols[36u][row];
    unsigned r152 = input_cols[37u][row];
    unsigned r153 = input_cols[38u][row];
    unsigned r154 = input_cols[39u][row];
    unsigned r155 = input_cols[40u][row];
    unsigned r156 = input_cols[41u][row];
    unsigned r157 = input_cols[42u][row];
    unsigned r158 = input_cols[43u][row];
    unsigned r159 = input_cols[16u][row];
    unsigned r160 = input_cols[17u][row];
    unsigned r161 = input_cols[18u][row];
    unsigned r162 = input_cols[19u][row];
    unsigned r163 = input_cols[20u][row];
    unsigned r164 = input_cols[21u][row];
    unsigned r165 = input_cols[22u][row];
    unsigned r166 = input_cols[23u][row];
    unsigned r167 = input_cols[24u][row];
    unsigned r168 = input_cols[25u][row];
    unsigned r169 = input_cols[26u][row];
    unsigned r170 = input_cols[27u][row];
    unsigned r171 = input_cols[28u][row];
    unsigned r172 = input_cols[29u][row];
    unsigned r173 = input_cols[30u][row];
    unsigned r174 = input_cols[31u][row];
    unsigned r175 = input_cols[32u][row];
    unsigned r176 = input_cols[33u][row];
    unsigned r177 = input_cols[34u][row];
    unsigned r178 = input_cols[35u][row];
    unsigned r179 = input_cols[36u][row];
    unsigned r180 = input_cols[37u][row];
    unsigned r181 = input_cols[38u][row];
    unsigned r182 = input_cols[39u][row];
    unsigned r183 = input_cols[40u][row];
    unsigned r184 = input_cols[41u][row];
    unsigned r185 = input_cols[42u][row];
    unsigned r186 = input_cols[43u][row];
    unsigned r187 = input_cols[16u][row];
    unsigned r188 = input_cols[17u][row];
    unsigned r189 = input_cols[18u][row];
    unsigned r190 = input_cols[19u][row];
    unsigned r191 = input_cols[20u][row];
    unsigned r192 = input_cols[21u][row];
    unsigned r193 = input_cols[22u][row];
    unsigned r194 = input_cols[23u][row];
    unsigned r195 = input_cols[24u][row];
    unsigned r196 = input_cols[25u][row];
    unsigned r197 = input_cols[26u][row];
    unsigned r198 = input_cols[27u][row];
    unsigned r199 = input_cols[28u][row];
    unsigned r200 = input_cols[29u][row];
    unsigned r201 = input_cols[30u][row];
    unsigned r202 = input_cols[31u][row];
    unsigned r203 = input_cols[32u][row];
    unsigned r204 = input_cols[33u][row];
    unsigned r205 = input_cols[34u][row];
    unsigned r206 = input_cols[35u][row];
    unsigned r207 = input_cols[36u][row];
    unsigned r208 = input_cols[37u][row];
    unsigned r209 = input_cols[38u][row];
    unsigned r210 = input_cols[39u][row];
    unsigned r211 = input_cols[40u][row];
    unsigned r212 = input_cols[41u][row];
    unsigned r213 = input_cols[42u][row];
    unsigned r214 = input_cols[43u][row];
    unsigned r215 = input_cols[16u][row];
    unsigned r216 = input_cols[17u][row];
    unsigned r217 = input_cols[18u][row];
    unsigned r218 = input_cols[19u][row];
    unsigned r219 = input_cols[20u][row];
    unsigned r220 = input_cols[21u][row];
    unsigned r221 = input_cols[22u][row];
    unsigned r222 = input_cols[23u][row];
    unsigned r223 = input_cols[24u][row];
    unsigned r224 = input_cols[25u][row];
    unsigned r225 = input_cols[26u][row];
    unsigned r226 = input_cols[27u][row];
    unsigned r227 = input_cols[28u][row];
    unsigned r228 = input_cols[29u][row];
    unsigned r229 = input_cols[30u][row];
    unsigned r230 = input_cols[31u][row];
    unsigned r231 = input_cols[32u][row];
    unsigned r232 = input_cols[33u][row];
    unsigned r233 = input_cols[34u][row];
    unsigned r234 = input_cols[35u][row];
    unsigned r235 = input_cols[36u][row];
    unsigned r236 = input_cols[37u][row];
    unsigned r237 = input_cols[38u][row];
    unsigned r238 = input_cols[39u][row];
    unsigned r239 = input_cols[40u][row];
    unsigned r240 = input_cols[41u][row];
    unsigned r241 = input_cols[42u][row];
    unsigned r242 = input_cols[43u][row];
    unsigned r243 = input_cols[16u][row];
    unsigned r244 = input_cols[17u][row];
    unsigned r245 = input_cols[18u][row];
    unsigned r246 = input_cols[19u][row];
    unsigned r247 = input_cols[20u][row];
    unsigned r248 = input_cols[21u][row];
    unsigned r249 = input_cols[22u][row];
    unsigned r250 = input_cols[23u][row];
    unsigned r251 = input_cols[24u][row];
    unsigned r252 = input_cols[25u][row];
    unsigned r253 = input_cols[26u][row];
    unsigned r254 = input_cols[27u][row];
    unsigned r255 = input_cols[28u][row];
    unsigned r256 = input_cols[29u][row];
    unsigned r257 = input_cols[30u][row];
    unsigned r258 = input_cols[31u][row];
    unsigned r259 = input_cols[32u][row];
    unsigned r260 = input_cols[33u][row];
    unsigned r261 = input_cols[34u][row];
    unsigned r262 = input_cols[35u][row];
    unsigned r263 = input_cols[36u][row];
    unsigned r264 = input_cols[37u][row];
    unsigned r265 = input_cols[38u][row];
    unsigned r266 = input_cols[39u][row];
    unsigned r267 = input_cols[40u][row];
    unsigned r268 = input_cols[41u][row];
    unsigned r269 = input_cols[42u][row];
    unsigned r270 = input_cols[43u][row];
    unsigned r271 = input_cols[16u][row];
    unsigned r272 = input_cols[17u][row];
    unsigned r273 = input_cols[18u][row];
    unsigned r274 = input_cols[19u][row];
    unsigned r275 = input_cols[20u][row];
    unsigned r276 = input_cols[21u][row];
    unsigned r277 = input_cols[22u][row];
    unsigned r278 = input_cols[23u][row];
    unsigned r279 = input_cols[24u][row];
    unsigned r280 = input_cols[25u][row];
    unsigned r281 = input_cols[26u][row];
    unsigned r282 = input_cols[27u][row];
    unsigned r283 = input_cols[28u][row];
    unsigned r284 = input_cols[29u][row];
    unsigned r285 = input_cols[30u][row];
    unsigned r286 = input_cols[31u][row];
    unsigned r287 = input_cols[32u][row];
    unsigned r288 = input_cols[33u][row];
    unsigned r289 = input_cols[34u][row];
    unsigned r290 = input_cols[35u][row];
    unsigned r291 = input_cols[36u][row];
    unsigned r292 = input_cols[37u][row];
    unsigned r293 = input_cols[38u][row];
    unsigned r294 = input_cols[39u][row];
    unsigned r295 = input_cols[40u][row];
    unsigned r296 = input_cols[41u][row];
    unsigned r297 = input_cols[42u][row];
    unsigned r298 = input_cols[43u][row];
    unsigned r299 = input_cols[16u][row];
    unsigned r300 = input_cols[17u][row];
    unsigned r301 = input_cols[18u][row];
    unsigned r302 = input_cols[19u][row];
    unsigned r303 = input_cols[20u][row];
    unsigned r304 = input_cols[21u][row];
    unsigned r305 = input_cols[22u][row];
    unsigned r306 = input_cols[23u][row];
    unsigned r307 = input_cols[24u][row];
    unsigned r308 = input_cols[25u][row];
    unsigned r309 = input_cols[26u][row];
    unsigned r310 = input_cols[27u][row];
    unsigned r311 = input_cols[28u][row];
    unsigned r312 = input_cols[29u][row];
    unsigned r313 = input_cols[30u][row];
    unsigned r314 = input_cols[31u][row];
    unsigned r315 = input_cols[32u][row];
    unsigned r316 = input_cols[33u][row];
    unsigned r317 = input_cols[34u][row];
    unsigned r318 = input_cols[35u][row];
    unsigned r319 = input_cols[36u][row];
    unsigned r320 = input_cols[37u][row];
    unsigned r321 = input_cols[38u][row];
    unsigned r322 = input_cols[39u][row];
    unsigned r323 = input_cols[40u][row];
    unsigned r324 = input_cols[41u][row];
    unsigned r325 = input_cols[42u][row];
    unsigned r326 = input_cols[43u][row];
    unsigned r327 = input_cols[16u][row];
    unsigned r328 = input_cols[17u][row];
    unsigned r329 = input_cols[18u][row];
    unsigned r330 = input_cols[19u][row];
    unsigned r331 = input_cols[20u][row];
    unsigned r332 = input_cols[21u][row];
    unsigned r333 = input_cols[22u][row];
    unsigned r334 = input_cols[23u][row];
    unsigned r335 = input_cols[24u][row];
    unsigned r336 = input_cols[25u][row];
    unsigned r337 = input_cols[26u][row];
    unsigned r338 = input_cols[27u][row];
    unsigned r339 = input_cols[28u][row];
    unsigned r340 = input_cols[29u][row];
    unsigned r341 = input_cols[30u][row];
    unsigned r342 = input_cols[31u][row];
    unsigned r343 = input_cols[32u][row];
    unsigned r344 = input_cols[33u][row];
    unsigned r345 = input_cols[34u][row];
    unsigned r346 = input_cols[35u][row];
    unsigned r347 = input_cols[36u][row];
    unsigned r348 = input_cols[37u][row];
    unsigned r349 = input_cols[38u][row];
    unsigned r350 = input_cols[39u][row];
    unsigned r351 = input_cols[40u][row];
    unsigned r352 = input_cols[41u][row];
    unsigned r353 = input_cols[42u][row];
    unsigned r354 = input_cols[43u][row];
    unsigned r355 = input_cols[16u][row];
    unsigned r356 = input_cols[17u][row];
    unsigned r357 = input_cols[18u][row];
    unsigned r358 = input_cols[19u][row];
    unsigned r359 = input_cols[20u][row];
    unsigned r360 = input_cols[21u][row];
    unsigned r361 = input_cols[22u][row];
    unsigned r362 = input_cols[23u][row];
    unsigned r363 = input_cols[24u][row];
    unsigned r364 = input_cols[25u][row];
    unsigned r365 = input_cols[26u][row];
    unsigned r366 = input_cols[27u][row];
    unsigned r367 = input_cols[28u][row];
    unsigned r368 = input_cols[29u][row];
    unsigned r369 = input_cols[30u][row];
    unsigned r370 = input_cols[31u][row];
    unsigned r371 = input_cols[32u][row];
    unsigned r372 = input_cols[33u][row];
    unsigned r373 = input_cols[34u][row];
    unsigned r374 = input_cols[35u][row];
    unsigned r375 = input_cols[36u][row];
    unsigned r376 = input_cols[37u][row];
    unsigned r377 = input_cols[38u][row];
    unsigned r378 = input_cols[39u][row];
    unsigned r379 = input_cols[40u][row];
    unsigned r380 = input_cols[41u][row];
    unsigned r381 = input_cols[42u][row];
    unsigned r382 = input_cols[43u][row];
    unsigned r383 = input_cols[16u][row];
    unsigned r384 = input_cols[17u][row];
    unsigned r385 = input_cols[18u][row];
    unsigned r386 = input_cols[19u][row];
    unsigned r387 = input_cols[20u][row];
    unsigned r388 = input_cols[21u][row];
    unsigned r389 = input_cols[22u][row];
    unsigned r390 = input_cols[23u][row];
    unsigned r391 = input_cols[24u][row];
    unsigned r392 = input_cols[25u][row];
    unsigned r393 = input_cols[26u][row];
    unsigned r394 = input_cols[27u][row];
    unsigned r395 = input_cols[28u][row];
    unsigned r396 = input_cols[29u][row];
    unsigned r397 = input_cols[30u][row];
    unsigned r398 = input_cols[31u][row];
    unsigned r399 = input_cols[32u][row];
    unsigned r400 = input_cols[33u][row];
    unsigned r401 = input_cols[34u][row];
    unsigned r402 = input_cols[35u][row];
    unsigned r403 = input_cols[36u][row];
    unsigned r404 = input_cols[37u][row];
    unsigned r405 = input_cols[38u][row];
    unsigned r406 = input_cols[39u][row];
    unsigned r407 = input_cols[40u][row];
    unsigned r408 = input_cols[41u][row];
    unsigned r409 = input_cols[42u][row];
    unsigned r410 = input_cols[43u][row];
    unsigned r411 = input_cols[16u][row];
    unsigned r412 = input_cols[17u][row];
    unsigned r413 = input_cols[18u][row];
    unsigned r414 = input_cols[19u][row];
    unsigned r415 = input_cols[20u][row];
    unsigned r416 = input_cols[21u][row];
    unsigned r417 = input_cols[22u][row];
    unsigned r418 = input_cols[23u][row];
    unsigned r419 = input_cols[24u][row];
    unsigned r420 = input_cols[25u][row];
    unsigned r421 = input_cols[26u][row];
    unsigned r422 = input_cols[27u][row];
    unsigned r423 = input_cols[28u][row];
    unsigned r424 = input_cols[29u][row];
    unsigned r425 = input_cols[30u][row];
    unsigned r426 = input_cols[31u][row];
    unsigned r427 = input_cols[32u][row];
    unsigned r428 = input_cols[33u][row];
    unsigned r429 = input_cols[34u][row];
    unsigned r430 = input_cols[35u][row];
    unsigned r431 = input_cols[36u][row];
    unsigned r432 = input_cols[37u][row];
    unsigned r433 = input_cols[38u][row];
    unsigned r434 = input_cols[39u][row];
    unsigned r435 = input_cols[40u][row];
    unsigned r436 = input_cols[41u][row];
    unsigned r437 = input_cols[42u][row];
    unsigned r438 = input_cols[43u][row];
    unsigned r439 = input_cols[16u][row];
    unsigned r440 = input_cols[17u][row];
    unsigned r441 = input_cols[18u][row];
    unsigned r442 = input_cols[19u][row];
    unsigned r443 = input_cols[20u][row];
    unsigned r444 = input_cols[21u][row];
    unsigned r445 = input_cols[22u][row];
    unsigned r446 = input_cols[23u][row];
    unsigned r447 = input_cols[24u][row];
    unsigned r448 = input_cols[25u][row];
    unsigned r449 = input_cols[26u][row];
    unsigned r450 = input_cols[27u][row];
    unsigned r451 = input_cols[28u][row];
    unsigned r452 = input_cols[29u][row];
    unsigned r453 = input_cols[30u][row];
    unsigned r454 = input_cols[31u][row];
    unsigned r455 = input_cols[32u][row];
    unsigned r456 = input_cols[33u][row];
    unsigned r457 = input_cols[34u][row];
    unsigned r458 = input_cols[35u][row];
    unsigned r459 = input_cols[36u][row];
    unsigned r460 = input_cols[37u][row];
    unsigned r461 = input_cols[38u][row];
    unsigned r462 = input_cols[39u][row];
    unsigned r463 = input_cols[40u][row];
    unsigned r464 = input_cols[41u][row];
    unsigned r465 = input_cols[42u][row];
    unsigned r466 = input_cols[43u][row];
    unsigned r467 = input_cols[16u][row];
    unsigned r468 = input_cols[17u][row];
    unsigned r469 = input_cols[18u][row];
    unsigned r470 = input_cols[19u][row];
    unsigned r471 = input_cols[20u][row];
    unsigned r472 = input_cols[21u][row];
    unsigned r473 = input_cols[22u][row];
    unsigned r474 = input_cols[23u][row];
    unsigned r475 = input_cols[24u][row];
    unsigned r476 = input_cols[25u][row];
    unsigned r477 = input_cols[26u][row];
    unsigned r478 = input_cols[27u][row];
    unsigned r479 = input_cols[28u][row];
    unsigned r480 = input_cols[29u][row];
    unsigned r481 = input_cols[30u][row];
    unsigned r482 = input_cols[31u][row];
    unsigned r483 = input_cols[32u][row];
    unsigned r484 = input_cols[33u][row];
    unsigned r485 = input_cols[34u][row];
    unsigned r486 = input_cols[35u][row];
    unsigned r487 = input_cols[36u][row];
    unsigned r488 = input_cols[37u][row];
    unsigned r489 = input_cols[38u][row];
    unsigned r490 = input_cols[39u][row];
    unsigned r491 = input_cols[40u][row];
    unsigned r492 = input_cols[41u][row];
    unsigned r493 = input_cols[42u][row];
    unsigned r494 = input_cols[43u][row];
    unsigned r495 = input_cols[16u][row];
    unsigned r496 = input_cols[17u][row];
    unsigned r497 = input_cols[18u][row];
    unsigned r498 = input_cols[19u][row];
    unsigned r499 = input_cols[20u][row];
    unsigned r500 = input_cols[21u][row];
    unsigned r501 = input_cols[22u][row];
    unsigned r502 = input_cols[23u][row];
    unsigned r503 = input_cols[24u][row];
    unsigned r504 = input_cols[25u][row];
    unsigned r505 = input_cols[26u][row];
    unsigned r506 = input_cols[27u][row];
    unsigned r507 = input_cols[28u][row];
    unsigned r508 = input_cols[29u][row];
    unsigned r509 = input_cols[30u][row];
    unsigned r510 = input_cols[31u][row];
    unsigned r511 = input_cols[32u][row];
    unsigned r512 = input_cols[33u][row];
    unsigned r513 = input_cols[34u][row];
    unsigned r514 = input_cols[35u][row];
    unsigned r515 = input_cols[36u][row];
    unsigned r516 = input_cols[37u][row];
    unsigned r517 = input_cols[38u][row];
    unsigned r518 = input_cols[39u][row];
    unsigned r519 = input_cols[40u][row];
    unsigned r520 = input_cols[41u][row];
    unsigned r521 = input_cols[42u][row];
    unsigned r522 = input_cols[43u][row];
    unsigned r523 = input_cols[16u][row];
    unsigned r524 = input_cols[17u][row];
    unsigned r525 = input_cols[18u][row];
    unsigned r526 = input_cols[19u][row];
    unsigned r527 = input_cols[20u][row];
    unsigned r528 = input_cols[21u][row];
    unsigned r529 = input_cols[22u][row];
    unsigned r530 = input_cols[23u][row];
    unsigned r531 = input_cols[24u][row];
    unsigned r532 = input_cols[25u][row];
    unsigned r533 = input_cols[26u][row];
    unsigned r534 = input_cols[27u][row];
    unsigned r535 = input_cols[28u][row];
    unsigned r536 = input_cols[29u][row];
    unsigned r537 = input_cols[30u][row];
    unsigned r538 = input_cols[31u][row];
    unsigned r539 = input_cols[32u][row];
    unsigned r540 = input_cols[33u][row];
    unsigned r541 = input_cols[34u][row];
    unsigned r542 = input_cols[35u][row];
    unsigned r543 = input_cols[36u][row];
    unsigned r544 = input_cols[37u][row];
    unsigned r545 = input_cols[38u][row];
    unsigned r546 = input_cols[39u][row];
    unsigned r547 = input_cols[40u][row];
    unsigned r548 = input_cols[41u][row];
    unsigned r549 = input_cols[42u][row];
    unsigned r550 = input_cols[43u][row];
    unsigned r551 = input_cols[16u][row];
    unsigned r552 = input_cols[17u][row];
    unsigned r553 = input_cols[18u][row];
    unsigned r554 = input_cols[19u][row];
    unsigned r555 = input_cols[20u][row];
    unsigned r556 = input_cols[21u][row];
    unsigned r557 = input_cols[22u][row];
    unsigned r558 = input_cols[23u][row];
    unsigned r559 = input_cols[24u][row];
    unsigned r560 = input_cols[25u][row];
    unsigned r561 = input_cols[26u][row];
    unsigned r562 = input_cols[27u][row];
    unsigned r563 = input_cols[28u][row];
    unsigned r564 = input_cols[29u][row];
    unsigned r565 = input_cols[30u][row];
    unsigned r566 = input_cols[31u][row];
    unsigned r567 = input_cols[32u][row];
    unsigned r568 = input_cols[33u][row];
    unsigned r569 = input_cols[34u][row];
    unsigned r570 = input_cols[35u][row];
    unsigned r571 = input_cols[36u][row];
    unsigned r572 = input_cols[37u][row];
    unsigned r573 = input_cols[38u][row];
    unsigned r574 = input_cols[39u][row];
    unsigned r575 = input_cols[40u][row];
    unsigned r576 = input_cols[41u][row];
    unsigned r577 = input_cols[42u][row];
    unsigned r578 = input_cols[43u][row];
    unsigned r579 = input_cols[16u][row];
    unsigned r580 = input_cols[17u][row];
    unsigned r581 = input_cols[18u][row];
    unsigned r582 = input_cols[19u][row];
    unsigned r583 = input_cols[20u][row];
    unsigned r584 = input_cols[21u][row];
    unsigned r585 = input_cols[22u][row];
    unsigned r586 = input_cols[23u][row];
    unsigned r587 = input_cols[24u][row];
    unsigned r588 = input_cols[25u][row];
    unsigned r589 = input_cols[26u][row];
    unsigned r590 = input_cols[27u][row];
    unsigned r591 = input_cols[28u][row];
    unsigned r592 = input_cols[29u][row];
    unsigned r593 = input_cols[30u][row];
    unsigned r594 = input_cols[31u][row];
    unsigned r595 = input_cols[32u][row];
    unsigned r596 = input_cols[33u][row];
    unsigned r597 = input_cols[34u][row];
    unsigned r598 = input_cols[35u][row];
    unsigned r599 = input_cols[36u][row];
    unsigned r600 = input_cols[37u][row];
    unsigned r601 = input_cols[38u][row];
    unsigned r602 = input_cols[39u][row];
    unsigned r603 = input_cols[40u][row];
    unsigned r604 = input_cols[41u][row];
    unsigned r605 = input_cols[42u][row];
    unsigned r606 = input_cols[43u][row];
    unsigned r607 = input_cols[16u][row];
    unsigned r608 = input_cols[17u][row];
    unsigned r609 = input_cols[18u][row];
    unsigned r610 = input_cols[19u][row];
    unsigned r611 = input_cols[20u][row];
    unsigned r612 = input_cols[21u][row];
    unsigned r613 = input_cols[22u][row];
    unsigned r614 = input_cols[23u][row];
    unsigned r615 = input_cols[24u][row];
    unsigned r616 = input_cols[25u][row];
    unsigned r617 = input_cols[26u][row];
    unsigned r618 = input_cols[27u][row];
    unsigned r619 = input_cols[28u][row];
    unsigned r620 = input_cols[29u][row];
    unsigned r621 = input_cols[30u][row];
    unsigned r622 = input_cols[31u][row];
    unsigned r623 = input_cols[32u][row];
    unsigned r624 = input_cols[33u][row];
    unsigned r625 = input_cols[34u][row];
    unsigned r626 = input_cols[35u][row];
    unsigned r627 = input_cols[36u][row];
    unsigned r628 = input_cols[37u][row];
    unsigned r629 = input_cols[38u][row];
    unsigned r630 = input_cols[39u][row];
    unsigned r631 = input_cols[40u][row];
    unsigned r632 = input_cols[41u][row];
    unsigned r633 = input_cols[42u][row];
    unsigned r634 = input_cols[43u][row];
    unsigned r635 = input_cols[16u][row];
    unsigned r636 = input_cols[17u][row];
    unsigned r637 = input_cols[18u][row];
    unsigned r638 = input_cols[19u][row];
    unsigned r639 = input_cols[20u][row];
    unsigned r640 = input_cols[21u][row];
    unsigned r641 = input_cols[22u][row];
    unsigned r642 = input_cols[23u][row];
    unsigned r643 = input_cols[24u][row];
    unsigned r644 = input_cols[25u][row];
    unsigned r645 = input_cols[26u][row];
    unsigned r646 = input_cols[27u][row];
    unsigned r647 = input_cols[28u][row];
    unsigned r648 = input_cols[29u][row];
    unsigned r649 = input_cols[30u][row];
    unsigned r650 = input_cols[31u][row];
    unsigned r651 = input_cols[32u][row];
    unsigned r652 = input_cols[33u][row];
    unsigned r653 = input_cols[34u][row];
    unsigned r654 = input_cols[35u][row];
    unsigned r655 = input_cols[36u][row];
    unsigned r656 = input_cols[37u][row];
    unsigned r657 = input_cols[38u][row];
    unsigned r658 = input_cols[39u][row];
    unsigned r659 = input_cols[40u][row];
    unsigned r660 = input_cols[41u][row];
    unsigned r661 = input_cols[42u][row];
    unsigned r662 = input_cols[43u][row];
    unsigned r663 = input_cols[16u][row];
    unsigned r664 = input_cols[17u][row];
    unsigned r665 = input_cols[18u][row];
    unsigned r666 = input_cols[19u][row];
    unsigned r667 = input_cols[20u][row];
    unsigned r668 = input_cols[21u][row];
    unsigned r669 = input_cols[22u][row];
    unsigned r670 = input_cols[23u][row];
    unsigned r671 = input_cols[24u][row];
    unsigned r672 = input_cols[25u][row];
    unsigned r673 = input_cols[26u][row];
    unsigned r674 = input_cols[27u][row];
    unsigned r675 = input_cols[28u][row];
    unsigned r676 = input_cols[29u][row];
    unsigned r677 = input_cols[30u][row];
    unsigned r678 = input_cols[31u][row];
    unsigned r679 = input_cols[32u][row];
    unsigned r680 = input_cols[33u][row];
    unsigned r681 = input_cols[34u][row];
    unsigned r682 = input_cols[35u][row];
    unsigned r683 = input_cols[36u][row];
    unsigned r684 = input_cols[37u][row];
    unsigned r685 = input_cols[38u][row];
    unsigned r686 = input_cols[39u][row];
    unsigned r687 = input_cols[40u][row];
    unsigned r688 = input_cols[41u][row];
    unsigned r689 = input_cols[42u][row];
    unsigned r690 = input_cols[43u][row];
    unsigned r691 = input_cols[16u][row];
    unsigned r692 = input_cols[17u][row];
    unsigned r693 = input_cols[18u][row];
    unsigned r694 = input_cols[19u][row];
    unsigned r695 = input_cols[20u][row];
    unsigned r696 = input_cols[21u][row];
    unsigned r697 = input_cols[22u][row];
    unsigned r698 = input_cols[23u][row];
    unsigned r699 = input_cols[24u][row];
    unsigned r700 = input_cols[25u][row];
    unsigned r701 = input_cols[26u][row];
    unsigned r702 = input_cols[27u][row];
    unsigned r703 = input_cols[28u][row];
    unsigned r704 = input_cols[29u][row];
    unsigned r705 = input_cols[30u][row];
    unsigned r706 = input_cols[31u][row];
    unsigned r707 = input_cols[32u][row];
    unsigned r708 = input_cols[33u][row];
    unsigned r709 = input_cols[34u][row];
    unsigned r710 = input_cols[35u][row];
    unsigned r711 = input_cols[36u][row];
    unsigned r712 = input_cols[37u][row];
    unsigned r713 = input_cols[38u][row];
    unsigned r714 = input_cols[39u][row];
    unsigned r715 = input_cols[40u][row];
    unsigned r716 = input_cols[41u][row];
    unsigned r717 = input_cols[42u][row];
    unsigned r718 = input_cols[43u][row];
    unsigned r719 = input_cols[16u][row];
    unsigned r720 = input_cols[17u][row];
    unsigned r721 = input_cols[18u][row];
    unsigned r722 = input_cols[19u][row];
    unsigned r723 = input_cols[20u][row];
    unsigned r724 = input_cols[21u][row];
    unsigned r725 = input_cols[22u][row];
    unsigned r726 = input_cols[23u][row];
    unsigned r727 = input_cols[24u][row];
    unsigned r728 = input_cols[25u][row];
    unsigned r729 = input_cols[26u][row];
    unsigned r730 = input_cols[27u][row];
    unsigned r731 = input_cols[28u][row];
    unsigned r732 = input_cols[29u][row];
    unsigned r733 = input_cols[30u][row];
    unsigned r734 = input_cols[31u][row];
    unsigned r735 = input_cols[32u][row];
    unsigned r736 = input_cols[33u][row];
    unsigned r737 = input_cols[34u][row];
    unsigned r738 = input_cols[35u][row];
    unsigned r739 = input_cols[36u][row];
    unsigned r740 = input_cols[37u][row];
    unsigned r741 = input_cols[38u][row];
    unsigned r742 = input_cols[39u][row];
    unsigned r743 = input_cols[40u][row];
    unsigned r744 = input_cols[41u][row];
    unsigned r745 = input_cols[42u][row];
    unsigned r746 = input_cols[43u][row];
    unsigned r747 = input_cols[16u][row];
    unsigned r748 = input_cols[17u][row];
    unsigned r749 = input_cols[18u][row];
    unsigned r750 = input_cols[19u][row];
    unsigned r751 = input_cols[20u][row];
    unsigned r752 = input_cols[21u][row];
    unsigned r753 = input_cols[22u][row];
    unsigned r754 = input_cols[23u][row];
    unsigned r755 = input_cols[24u][row];
    unsigned r756 = input_cols[25u][row];
    unsigned r757 = input_cols[26u][row];
    unsigned r758 = input_cols[27u][row];
    unsigned r759 = input_cols[28u][row];
    unsigned r760 = input_cols[29u][row];
    unsigned r761 = input_cols[30u][row];
    unsigned r762 = input_cols[31u][row];
    unsigned r763 = input_cols[32u][row];
    unsigned r764 = input_cols[33u][row];
    unsigned r765 = input_cols[34u][row];
    unsigned r766 = input_cols[35u][row];
    unsigned r767 = input_cols[36u][row];
    unsigned r768 = input_cols[37u][row];
    unsigned r769 = input_cols[38u][row];
    unsigned r770 = input_cols[39u][row];
    unsigned r771 = input_cols[40u][row];
    unsigned r772 = input_cols[41u][row];
    unsigned r773 = input_cols[42u][row];
    unsigned r774 = input_cols[43u][row];
    unsigned r775 = input_cols[16u][row];
    unsigned r776 = input_cols[17u][row];
    unsigned r777 = input_cols[18u][row];
    unsigned r778 = input_cols[19u][row];
    unsigned r779 = input_cols[20u][row];
    unsigned r780 = input_cols[21u][row];
    unsigned r781 = input_cols[22u][row];
    unsigned r782 = input_cols[23u][row];
    unsigned r783 = input_cols[24u][row];
    unsigned r784 = input_cols[25u][row];
    unsigned r785 = input_cols[26u][row];
    unsigned r786 = input_cols[27u][row];
    unsigned r787 = input_cols[28u][row];
    unsigned r788 = input_cols[29u][row];
    unsigned r789 = input_cols[30u][row];
    unsigned r790 = input_cols[31u][row];
    unsigned r791 = input_cols[32u][row];
    unsigned r792 = input_cols[33u][row];
    unsigned r793 = input_cols[34u][row];
    unsigned r794 = input_cols[35u][row];
    unsigned r795 = input_cols[36u][row];
    unsigned r796 = input_cols[37u][row];
    unsigned r797 = input_cols[38u][row];
    unsigned r798 = input_cols[39u][row];
    unsigned r799 = input_cols[40u][row];
    unsigned r800 = input_cols[41u][row];
    unsigned r801 = input_cols[42u][row];
    unsigned r802 = input_cols[43u][row];
    unsigned r803 = input_cols[16u][row];
    unsigned r804 = input_cols[17u][row];
    unsigned r805 = input_cols[18u][row];
    unsigned r806 = input_cols[19u][row];
    unsigned r807 = input_cols[20u][row];
    unsigned r808 = input_cols[21u][row];
    unsigned r809 = input_cols[22u][row];
    unsigned r810 = input_cols[23u][row];
    unsigned r811 = input_cols[24u][row];
    unsigned r812 = input_cols[25u][row];
    unsigned r813 = input_cols[26u][row];
    unsigned r814 = input_cols[27u][row];
    unsigned r815 = input_cols[28u][row];
    unsigned r816 = input_cols[29u][row];
    unsigned r817 = input_cols[30u][row];
    unsigned r818 = input_cols[31u][row];
    unsigned r819 = input_cols[32u][row];
    unsigned r820 = input_cols[33u][row];
    unsigned r821 = input_cols[34u][row];
    unsigned r822 = input_cols[35u][row];
    unsigned r823 = input_cols[36u][row];
    unsigned r824 = input_cols[37u][row];
    unsigned r825 = input_cols[38u][row];
    unsigned r826 = input_cols[39u][row];
    unsigned r827 = input_cols[40u][row];
    unsigned r828 = input_cols[41u][row];
    unsigned r829 = input_cols[42u][row];
    unsigned r830 = input_cols[43u][row];
    unsigned r831 = input_cols[44u][row];
    unsigned r832 = input_cols[45u][row];
    unsigned r833 = input_cols[46u][row];
    unsigned r834 = input_cols[47u][row];
    unsigned r835 = input_cols[48u][row];
    unsigned r836 = input_cols[49u][row];
    unsigned r837 = input_cols[50u][row];
    unsigned r838 = input_cols[51u][row];
    unsigned r839 = input_cols[52u][row];
    unsigned r840 = input_cols[53u][row];
    unsigned r841 = input_cols[54u][row];
    unsigned r842 = input_cols[55u][row];
    unsigned r843 = input_cols[56u][row];
    unsigned r844 = input_cols[57u][row];
    unsigned r845 = input_cols[58u][row];
    unsigned r846 = input_cols[59u][row];
    unsigned r847 = input_cols[60u][row];
    unsigned r848 = input_cols[61u][row];
    unsigned r849 = input_cols[62u][row];
    unsigned r850 = input_cols[63u][row];
    unsigned r851 = input_cols[64u][row];
    unsigned r852 = input_cols[65u][row];
    unsigned r853 = input_cols[66u][row];
    unsigned r854 = input_cols[67u][row];
    unsigned r855 = input_cols[68u][row];
    unsigned r856 = input_cols[69u][row];
    unsigned r857 = input_cols[70u][row];
    unsigned r858 = input_cols[71u][row];
    unsigned r859 = input_cols[44u][row];
    unsigned r860 = input_cols[45u][row];
    unsigned r861 = input_cols[46u][row];
    unsigned r862 = input_cols[47u][row];
    unsigned r863 = input_cols[48u][row];
    unsigned r864 = input_cols[49u][row];
    unsigned r865 = input_cols[50u][row];
    unsigned r866 = input_cols[51u][row];
    unsigned r867 = input_cols[52u][row];
    unsigned r868 = input_cols[53u][row];
    unsigned r869 = input_cols[54u][row];
    unsigned r870 = input_cols[55u][row];
    unsigned r871 = input_cols[56u][row];
    unsigned r872 = input_cols[57u][row];
    unsigned r873 = input_cols[58u][row];
    unsigned r874 = input_cols[59u][row];
    unsigned r875 = input_cols[60u][row];
    unsigned r876 = input_cols[61u][row];
    unsigned r877 = input_cols[62u][row];
    unsigned r878 = input_cols[63u][row];
    unsigned r879 = input_cols[64u][row];
    unsigned r880 = input_cols[65u][row];
    unsigned r881 = input_cols[66u][row];
    unsigned r882 = input_cols[67u][row];
    unsigned r883 = input_cols[68u][row];
    unsigned r884 = input_cols[69u][row];
    unsigned r885 = input_cols[70u][row];
    unsigned r886 = input_cols[71u][row];
    unsigned r887 = input_cols[44u][row];
    unsigned r888 = input_cols[45u][row];
    unsigned r889 = input_cols[46u][row];
    unsigned r890 = input_cols[47u][row];
    unsigned r891 = input_cols[48u][row];
    unsigned r892 = input_cols[49u][row];
    unsigned r893 = input_cols[50u][row];
    unsigned r894 = input_cols[51u][row];
    unsigned r895 = input_cols[52u][row];
    unsigned r896 = input_cols[53u][row];
    unsigned r897 = input_cols[54u][row];
    unsigned r898 = input_cols[55u][row];
    unsigned r899 = input_cols[56u][row];
    unsigned r900 = input_cols[57u][row];
    unsigned r901 = input_cols[58u][row];
    unsigned r902 = input_cols[59u][row];
    unsigned r903 = input_cols[60u][row];
    unsigned r904 = input_cols[61u][row];
    unsigned r905 = input_cols[62u][row];
    unsigned r906 = input_cols[63u][row];
    unsigned r907 = input_cols[64u][row];
    unsigned r908 = input_cols[65u][row];
    unsigned r909 = input_cols[66u][row];
    unsigned r910 = input_cols[67u][row];
    unsigned r911 = input_cols[68u][row];
    unsigned r912 = input_cols[69u][row];
    unsigned r913 = input_cols[70u][row];
    unsigned r914 = input_cols[71u][row];
    unsigned r915 = input_cols[44u][row];
    unsigned r916 = input_cols[45u][row];
    unsigned r917 = input_cols[46u][row];
    unsigned r918 = input_cols[47u][row];
    unsigned r919 = input_cols[48u][row];
    unsigned r920 = input_cols[49u][row];
    unsigned r921 = input_cols[50u][row];
    unsigned r922 = input_cols[51u][row];
    unsigned r923 = input_cols[52u][row];
    unsigned r924 = input_cols[53u][row];
    unsigned r925 = input_cols[54u][row];
    unsigned r926 = input_cols[55u][row];
    unsigned r927 = input_cols[56u][row];
    unsigned r928 = input_cols[57u][row];
    unsigned r929 = input_cols[58u][row];
    unsigned r930 = input_cols[59u][row];
    unsigned r931 = input_cols[60u][row];
    unsigned r932 = input_cols[61u][row];
    unsigned r933 = input_cols[62u][row];
    unsigned r934 = input_cols[63u][row];
    unsigned r935 = input_cols[64u][row];
    unsigned r936 = input_cols[65u][row];
    unsigned r937 = input_cols[66u][row];
    unsigned r938 = input_cols[67u][row];
    unsigned r939 = input_cols[68u][row];
    unsigned r940 = input_cols[69u][row];
    unsigned r941 = input_cols[70u][row];
    unsigned r942 = input_cols[71u][row];
    unsigned r943 = input_cols[44u][row];
    unsigned r944 = input_cols[45u][row];
    unsigned r945 = input_cols[46u][row];
    unsigned r946 = input_cols[47u][row];
    unsigned r947 = input_cols[48u][row];
    unsigned r948 = input_cols[49u][row];
    unsigned r949 = input_cols[50u][row];
    unsigned r950 = input_cols[51u][row];
    unsigned r951 = input_cols[52u][row];
    unsigned r952 = input_cols[53u][row];
    unsigned r953 = input_cols[54u][row];
    unsigned r954 = input_cols[55u][row];
    unsigned r955 = input_cols[56u][row];
    unsigned r956 = input_cols[57u][row];
    unsigned r957 = input_cols[58u][row];
    unsigned r958 = input_cols[59u][row];
    unsigned r959 = input_cols[60u][row];
    unsigned r960 = input_cols[61u][row];
    unsigned r961 = input_cols[62u][row];
    unsigned r962 = input_cols[63u][row];
    unsigned r963 = input_cols[64u][row];
    unsigned r964 = input_cols[65u][row];
    unsigned r965 = input_cols[66u][row];
    unsigned r966 = input_cols[67u][row];
    unsigned r967 = input_cols[68u][row];
    unsigned r968 = input_cols[69u][row];
    unsigned r969 = input_cols[70u][row];
    unsigned r970 = input_cols[71u][row];
    unsigned r971 = input_cols[44u][row];
    unsigned r972 = input_cols[45u][row];
    unsigned r973 = input_cols[46u][row];
    unsigned r974 = input_cols[47u][row];
    unsigned r975 = input_cols[48u][row];
    unsigned r976 = input_cols[49u][row];
    unsigned r977 = input_cols[50u][row];
    unsigned r978 = input_cols[51u][row];
    unsigned r979 = input_cols[52u][row];
    unsigned r980 = input_cols[53u][row];
    unsigned r981 = input_cols[54u][row];
    unsigned r982 = input_cols[55u][row];
    unsigned r983 = input_cols[56u][row];
    unsigned r984 = input_cols[57u][row];
    unsigned r985 = input_cols[58u][row];
    unsigned r986 = input_cols[59u][row];
    unsigned r987 = input_cols[60u][row];
    unsigned r988 = input_cols[61u][row];
    unsigned r989 = input_cols[62u][row];
    unsigned r990 = input_cols[63u][row];
    unsigned r991 = input_cols[64u][row];
    unsigned r992 = input_cols[65u][row];
    unsigned r993 = input_cols[66u][row];
    unsigned r994 = input_cols[67u][row];
    unsigned r995 = input_cols[68u][row];
    unsigned r996 = input_cols[69u][row];
    unsigned r997 = input_cols[70u][row];
    unsigned r998 = input_cols[71u][row];
    unsigned r999 = input_cols[44u][row];
    unsigned r1000 = input_cols[45u][row];
    unsigned r1001 = input_cols[46u][row];
    unsigned r1002 = input_cols[47u][row];
    unsigned r1003 = input_cols[48u][row];
    unsigned r1004 = input_cols[49u][row];
    unsigned r1005 = input_cols[50u][row];
    unsigned r1006 = input_cols[51u][row];
    unsigned r1007 = input_cols[52u][row];
    unsigned r1008 = input_cols[53u][row];
    unsigned r1009 = input_cols[54u][row];
    unsigned r1010 = input_cols[55u][row];
    unsigned r1011 = input_cols[56u][row];
    unsigned r1012 = input_cols[57u][row];
    unsigned r1013 = input_cols[58u][row];
    unsigned r1014 = input_cols[59u][row];
    unsigned r1015 = input_cols[60u][row];
    unsigned r1016 = input_cols[61u][row];
    unsigned r1017 = input_cols[62u][row];
    unsigned r1018 = input_cols[63u][row];
    unsigned r1019 = input_cols[64u][row];
    unsigned r1020 = input_cols[65u][row];
    unsigned r1021 = input_cols[66u][row];
    unsigned r1022 = input_cols[67u][row];
    unsigned r1023 = input_cols[68u][row];
    unsigned r1024 = input_cols[69u][row];
    unsigned r1025 = input_cols[70u][row];
    unsigned r1026 = input_cols[71u][row];
    unsigned r1027 = input_cols[44u][row];
    unsigned r1028 = input_cols[45u][row];
    unsigned r1029 = input_cols[46u][row];
    unsigned r1030 = input_cols[47u][row];
    unsigned r1031 = input_cols[48u][row];
    unsigned r1032 = input_cols[49u][row];
    unsigned r1033 = input_cols[50u][row];
    unsigned r1034 = input_cols[51u][row];
    unsigned r1035 = input_cols[52u][row];
    unsigned r1036 = input_cols[53u][row];
    unsigned r1037 = input_cols[54u][row];
    unsigned r1038 = input_cols[55u][row];
    unsigned r1039 = input_cols[56u][row];
    unsigned r1040 = input_cols[57u][row];
    unsigned r1041 = input_cols[58u][row];
    unsigned r1042 = input_cols[59u][row];
    unsigned r1043 = input_cols[60u][row];
    unsigned r1044 = input_cols[61u][row];
    unsigned r1045 = input_cols[62u][row];
    unsigned r1046 = input_cols[63u][row];
    unsigned r1047 = input_cols[64u][row];
    unsigned r1048 = input_cols[65u][row];
    unsigned r1049 = input_cols[66u][row];
    unsigned r1050 = input_cols[67u][row];
    unsigned r1051 = input_cols[68u][row];
    unsigned r1052 = input_cols[69u][row];
    unsigned r1053 = input_cols[70u][row];
    unsigned r1054 = input_cols[71u][row];
    unsigned r1055 = input_cols[44u][row];
    unsigned r1056 = input_cols[45u][row];
    unsigned r1057 = input_cols[46u][row];
    unsigned r1058 = input_cols[47u][row];
    unsigned r1059 = input_cols[48u][row];
    unsigned r1060 = input_cols[49u][row];
    unsigned r1061 = input_cols[50u][row];
    unsigned r1062 = input_cols[51u][row];
    unsigned r1063 = input_cols[52u][row];
    unsigned r1064 = input_cols[53u][row];
    unsigned r1065 = input_cols[54u][row];
    unsigned r1066 = input_cols[55u][row];
    unsigned r1067 = input_cols[56u][row];
    unsigned r1068 = input_cols[57u][row];
    unsigned r1069 = input_cols[58u][row];
    unsigned r1070 = input_cols[59u][row];
    unsigned r1071 = input_cols[60u][row];
    unsigned r1072 = input_cols[61u][row];
    unsigned r1073 = input_cols[62u][row];
    unsigned r1074 = input_cols[63u][row];
    unsigned r1075 = input_cols[64u][row];
    unsigned r1076 = input_cols[65u][row];
    unsigned r1077 = input_cols[66u][row];
    unsigned r1078 = input_cols[67u][row];
    unsigned r1079 = input_cols[68u][row];
    unsigned r1080 = input_cols[69u][row];
    unsigned r1081 = input_cols[70u][row];
    unsigned r1082 = input_cols[71u][row];
    unsigned r1083 = input_cols[44u][row];
    unsigned r1084 = input_cols[45u][row];
    unsigned r1085 = input_cols[46u][row];
    unsigned r1086 = input_cols[47u][row];
    unsigned r1087 = input_cols[48u][row];
    unsigned r1088 = input_cols[49u][row];
    unsigned r1089 = input_cols[50u][row];
    unsigned r1090 = input_cols[51u][row];
    unsigned r1091 = input_cols[52u][row];
    unsigned r1092 = input_cols[53u][row];
    unsigned r1093 = input_cols[54u][row];
    unsigned r1094 = input_cols[55u][row];
    unsigned r1095 = input_cols[56u][row];
    unsigned r1096 = input_cols[57u][row];
    unsigned r1097 = input_cols[58u][row];
    unsigned r1098 = input_cols[59u][row];
    unsigned r1099 = input_cols[60u][row];
    unsigned r1100 = input_cols[61u][row];
    unsigned r1101 = input_cols[62u][row];
    unsigned r1102 = input_cols[63u][row];
    unsigned r1103 = input_cols[64u][row];
    unsigned r1104 = input_cols[65u][row];
    unsigned r1105 = input_cols[66u][row];
    unsigned r1106 = input_cols[67u][row];
    unsigned r1107 = input_cols[68u][row];
    unsigned r1108 = input_cols[69u][row];
    unsigned r1109 = input_cols[70u][row];
    unsigned r1110 = input_cols[71u][row];
    unsigned r1111 = input_cols[44u][row];
    unsigned r1112 = input_cols[45u][row];
    unsigned r1113 = input_cols[46u][row];
    unsigned r1114 = input_cols[47u][row];
    unsigned r1115 = input_cols[48u][row];
    unsigned r1116 = input_cols[49u][row];
    unsigned r1117 = input_cols[50u][row];
    unsigned r1118 = input_cols[51u][row];
    unsigned r1119 = input_cols[52u][row];
    unsigned r1120 = input_cols[53u][row];
    unsigned r1121 = input_cols[54u][row];
    unsigned r1122 = input_cols[55u][row];
    unsigned r1123 = input_cols[56u][row];
    unsigned r1124 = input_cols[57u][row];
    unsigned r1125 = input_cols[58u][row];
    unsigned r1126 = input_cols[59u][row];
    unsigned r1127 = input_cols[60u][row];
    unsigned r1128 = input_cols[61u][row];
    unsigned r1129 = input_cols[62u][row];
    unsigned r1130 = input_cols[63u][row];
    unsigned r1131 = input_cols[64u][row];
    unsigned r1132 = input_cols[65u][row];
    unsigned r1133 = input_cols[66u][row];
    unsigned r1134 = input_cols[67u][row];
    unsigned r1135 = input_cols[68u][row];
    unsigned r1136 = input_cols[69u][row];
    unsigned r1137 = input_cols[70u][row];
    unsigned r1138 = input_cols[71u][row];
    unsigned r1139 = input_cols[44u][row];
    unsigned r1140 = input_cols[45u][row];
    unsigned r1141 = input_cols[46u][row];
    unsigned r1142 = input_cols[47u][row];
    unsigned r1143 = input_cols[48u][row];
    unsigned r1144 = input_cols[49u][row];
    unsigned r1145 = input_cols[50u][row];
    unsigned r1146 = input_cols[51u][row];
    unsigned r1147 = input_cols[52u][row];
    unsigned r1148 = input_cols[53u][row];
    unsigned r1149 = input_cols[54u][row];
    unsigned r1150 = input_cols[55u][row];
    unsigned r1151 = input_cols[56u][row];
    unsigned r1152 = input_cols[57u][row];
    unsigned r1153 = input_cols[58u][row];
    unsigned r1154 = input_cols[59u][row];
    unsigned r1155 = input_cols[60u][row];
    unsigned r1156 = input_cols[61u][row];
    unsigned r1157 = input_cols[62u][row];
    unsigned r1158 = input_cols[63u][row];
    unsigned r1159 = input_cols[64u][row];
    unsigned r1160 = input_cols[65u][row];
    unsigned r1161 = input_cols[66u][row];
    unsigned r1162 = input_cols[67u][row];
    unsigned r1163 = input_cols[68u][row];
    unsigned r1164 = input_cols[69u][row];
    unsigned r1165 = input_cols[70u][row];
    unsigned r1166 = input_cols[71u][row];
    unsigned r1167 = input_cols[44u][row];
    unsigned r1168 = input_cols[45u][row];
    unsigned r1169 = input_cols[46u][row];
    unsigned r1170 = input_cols[47u][row];
    unsigned r1171 = input_cols[48u][row];
    unsigned r1172 = input_cols[49u][row];
    unsigned r1173 = input_cols[50u][row];
    unsigned r1174 = input_cols[51u][row];
    unsigned r1175 = input_cols[52u][row];
    unsigned r1176 = input_cols[53u][row];
    unsigned r1177 = input_cols[54u][row];
    unsigned r1178 = input_cols[55u][row];
    unsigned r1179 = input_cols[56u][row];
    unsigned r1180 = input_cols[57u][row];
    unsigned r1181 = input_cols[58u][row];
    unsigned r1182 = input_cols[59u][row];
    unsigned r1183 = input_cols[60u][row];
    unsigned r1184 = input_cols[61u][row];
    unsigned r1185 = input_cols[62u][row];
    unsigned r1186 = input_cols[63u][row];
    unsigned r1187 = input_cols[64u][row];
    unsigned r1188 = input_cols[65u][row];
    unsigned r1189 = input_cols[66u][row];
    unsigned r1190 = input_cols[67u][row];
    unsigned r1191 = input_cols[68u][row];
    unsigned r1192 = input_cols[69u][row];
    unsigned r1193 = input_cols[70u][row];
    unsigned r1194 = input_cols[71u][row];
    unsigned r1195 = input_cols[44u][row];
    unsigned r1196 = input_cols[45u][row];
    unsigned r1197 = input_cols[46u][row];
    unsigned r1198 = input_cols[47u][row];
    unsigned r1199 = input_cols[48u][row];
    unsigned r1200 = input_cols[49u][row];
    unsigned r1201 = input_cols[50u][row];
    unsigned r1202 = input_cols[51u][row];
    unsigned r1203 = input_cols[52u][row];
    unsigned r1204 = input_cols[53u][row];
    unsigned r1205 = input_cols[54u][row];
    unsigned r1206 = input_cols[55u][row];
    unsigned r1207 = input_cols[56u][row];
    unsigned r1208 = input_cols[57u][row];
    unsigned r1209 = input_cols[58u][row];
    unsigned r1210 = input_cols[59u][row];
    unsigned r1211 = input_cols[60u][row];
    unsigned r1212 = input_cols[61u][row];
    unsigned r1213 = input_cols[62u][row];
    unsigned r1214 = input_cols[63u][row];
    unsigned r1215 = input_cols[64u][row];
    unsigned r1216 = input_cols[65u][row];
    unsigned r1217 = input_cols[66u][row];
    unsigned r1218 = input_cols[67u][row];
    unsigned r1219 = input_cols[68u][row];
    unsigned r1220 = input_cols[69u][row];
    unsigned r1221 = input_cols[70u][row];
    unsigned r1222 = input_cols[71u][row];
    unsigned r1223 = input_cols[44u][row];
    unsigned r1224 = input_cols[45u][row];
    unsigned r1225 = input_cols[46u][row];
    unsigned r1226 = input_cols[47u][row];
    unsigned r1227 = input_cols[48u][row];
    unsigned r1228 = input_cols[49u][row];
    unsigned r1229 = input_cols[50u][row];
    unsigned r1230 = input_cols[51u][row];
    unsigned r1231 = input_cols[52u][row];
    unsigned r1232 = input_cols[53u][row];
    unsigned r1233 = input_cols[54u][row];
    unsigned r1234 = input_cols[55u][row];
    unsigned r1235 = input_cols[56u][row];
    unsigned r1236 = input_cols[57u][row];
    unsigned r1237 = input_cols[58u][row];
    unsigned r1238 = input_cols[59u][row];
    unsigned r1239 = input_cols[60u][row];
    unsigned r1240 = input_cols[61u][row];
    unsigned r1241 = input_cols[62u][row];
    unsigned r1242 = input_cols[63u][row];
    unsigned r1243 = input_cols[64u][row];
    unsigned r1244 = input_cols[65u][row];
    unsigned r1245 = input_cols[66u][row];
    unsigned r1246 = input_cols[67u][row];
    unsigned r1247 = input_cols[68u][row];
    unsigned r1248 = input_cols[69u][row];
    unsigned r1249 = input_cols[70u][row];
    unsigned r1250 = input_cols[71u][row];
    unsigned r1251 = input_cols[44u][row];
    unsigned r1252 = input_cols[45u][row];
    unsigned r1253 = input_cols[46u][row];
    unsigned r1254 = input_cols[47u][row];
    unsigned r1255 = input_cols[48u][row];
    unsigned r1256 = input_cols[49u][row];
    unsigned r1257 = input_cols[50u][row];
    unsigned r1258 = input_cols[51u][row];
    unsigned r1259 = input_cols[52u][row];
    unsigned r1260 = input_cols[53u][row];
    unsigned r1261 = input_cols[54u][row];
    unsigned r1262 = input_cols[55u][row];
    unsigned r1263 = input_cols[56u][row];
    unsigned r1264 = input_cols[57u][row];
    unsigned r1265 = input_cols[58u][row];
    unsigned r1266 = input_cols[59u][row];
    unsigned r1267 = input_cols[60u][row];
    unsigned r1268 = input_cols[61u][row];
    unsigned r1269 = input_cols[62u][row];
    unsigned r1270 = input_cols[63u][row];
    unsigned r1271 = input_cols[64u][row];
    unsigned r1272 = input_cols[65u][row];
    unsigned r1273 = input_cols[66u][row];
    unsigned r1274 = input_cols[67u][row];
    unsigned r1275 = input_cols[68u][row];
    unsigned r1276 = input_cols[69u][row];
    unsigned r1277 = input_cols[70u][row];
    unsigned r1278 = input_cols[71u][row];
    unsigned r1279 = input_cols[44u][row];
    unsigned r1280 = input_cols[45u][row];
    unsigned r1281 = input_cols[46u][row];
    unsigned r1282 = input_cols[47u][row];
    unsigned r1283 = input_cols[48u][row];
    unsigned r1284 = input_cols[49u][row];
    unsigned r1285 = input_cols[50u][row];
    unsigned r1286 = input_cols[51u][row];
    unsigned r1287 = input_cols[52u][row];
    unsigned r1288 = input_cols[53u][row];
    unsigned r1289 = input_cols[54u][row];
    unsigned r1290 = input_cols[55u][row];
    unsigned r1291 = input_cols[56u][row];
    unsigned r1292 = input_cols[57u][row];
    unsigned r1293 = input_cols[58u][row];
    unsigned r1294 = input_cols[59u][row];
    unsigned r1295 = input_cols[60u][row];
    unsigned r1296 = input_cols[61u][row];
    unsigned r1297 = input_cols[62u][row];
    unsigned r1298 = input_cols[63u][row];
    unsigned r1299 = input_cols[64u][row];
    unsigned r1300 = input_cols[65u][row];
    unsigned r1301 = input_cols[66u][row];
    unsigned r1302 = input_cols[67u][row];
    unsigned r1303 = input_cols[68u][row];
    unsigned r1304 = input_cols[69u][row];
    unsigned r1305 = input_cols[70u][row];
    unsigned r1306 = input_cols[71u][row];
    unsigned r1307 = input_cols[44u][row];
    unsigned r1308 = input_cols[45u][row];
    unsigned r1309 = input_cols[46u][row];
    unsigned r1310 = input_cols[47u][row];
    unsigned r1311 = input_cols[48u][row];
    unsigned r1312 = input_cols[49u][row];
    unsigned r1313 = input_cols[50u][row];
    unsigned r1314 = input_cols[51u][row];
    unsigned r1315 = input_cols[52u][row];
    unsigned r1316 = input_cols[53u][row];
    unsigned r1317 = input_cols[54u][row];
    unsigned r1318 = input_cols[55u][row];
    unsigned r1319 = input_cols[56u][row];
    unsigned r1320 = input_cols[57u][row];
    unsigned r1321 = input_cols[58u][row];
    unsigned r1322 = input_cols[59u][row];
    unsigned r1323 = input_cols[60u][row];
    unsigned r1324 = input_cols[61u][row];
    unsigned r1325 = input_cols[62u][row];
    unsigned r1326 = input_cols[63u][row];
    unsigned r1327 = input_cols[64u][row];
    unsigned r1328 = input_cols[65u][row];
    unsigned r1329 = input_cols[66u][row];
    unsigned r1330 = input_cols[67u][row];
    unsigned r1331 = input_cols[68u][row];
    unsigned r1332 = input_cols[69u][row];
    unsigned r1333 = input_cols[70u][row];
    unsigned r1334 = input_cols[71u][row];
    unsigned r1335 = input_cols[44u][row];
    unsigned r1336 = input_cols[45u][row];
    unsigned r1337 = input_cols[46u][row];
    unsigned r1338 = input_cols[47u][row];
    unsigned r1339 = input_cols[48u][row];
    unsigned r1340 = input_cols[49u][row];
    unsigned r1341 = input_cols[50u][row];
    unsigned r1342 = input_cols[51u][row];
    unsigned r1343 = input_cols[52u][row];
    unsigned r1344 = input_cols[53u][row];
    unsigned r1345 = input_cols[54u][row];
    unsigned r1346 = input_cols[55u][row];
    unsigned r1347 = input_cols[56u][row];
    unsigned r1348 = input_cols[57u][row];
    unsigned r1349 = input_cols[58u][row];
    unsigned r1350 = input_cols[59u][row];
    unsigned r1351 = input_cols[60u][row];
    unsigned r1352 = input_cols[61u][row];
    unsigned r1353 = input_cols[62u][row];
    unsigned r1354 = input_cols[63u][row];
    unsigned r1355 = input_cols[64u][row];
    unsigned r1356 = input_cols[65u][row];
    unsigned r1357 = input_cols[66u][row];
    unsigned r1358 = input_cols[67u][row];
    unsigned r1359 = input_cols[68u][row];
    unsigned r1360 = input_cols[69u][row];
    unsigned r1361 = input_cols[70u][row];
    unsigned r1362 = input_cols[71u][row];
    unsigned r1363 = input_cols[44u][row];
    unsigned r1364 = input_cols[45u][row];
    unsigned r1365 = input_cols[46u][row];
    unsigned r1366 = input_cols[47u][row];
    unsigned r1367 = input_cols[48u][row];
    unsigned r1368 = input_cols[49u][row];
    unsigned r1369 = input_cols[50u][row];
    unsigned r1370 = input_cols[51u][row];
    unsigned r1371 = input_cols[52u][row];
    unsigned r1372 = input_cols[53u][row];
    unsigned r1373 = input_cols[54u][row];
    unsigned r1374 = input_cols[55u][row];
    unsigned r1375 = input_cols[56u][row];
    unsigned r1376 = input_cols[57u][row];
    unsigned r1377 = input_cols[58u][row];
    unsigned r1378 = input_cols[59u][row];
    unsigned r1379 = input_cols[60u][row];
    unsigned r1380 = input_cols[61u][row];
    unsigned r1381 = input_cols[62u][row];
    unsigned r1382 = input_cols[63u][row];
    unsigned r1383 = input_cols[64u][row];
    unsigned r1384 = input_cols[65u][row];
    unsigned r1385 = input_cols[66u][row];
    unsigned r1386 = input_cols[67u][row];
    unsigned r1387 = input_cols[68u][row];
    unsigned r1388 = input_cols[69u][row];
    unsigned r1389 = input_cols[70u][row];
    unsigned r1390 = input_cols[71u][row];
    unsigned r1391 = input_cols[44u][row];
    unsigned r1392 = input_cols[45u][row];
    unsigned r1393 = input_cols[46u][row];
    unsigned r1394 = input_cols[47u][row];
    unsigned r1395 = input_cols[48u][row];
    unsigned r1396 = input_cols[49u][row];
    unsigned r1397 = input_cols[50u][row];
    unsigned r1398 = input_cols[51u][row];
    unsigned r1399 = input_cols[52u][row];
    unsigned r1400 = input_cols[53u][row];
    unsigned r1401 = input_cols[54u][row];
    unsigned r1402 = input_cols[55u][row];
    unsigned r1403 = input_cols[56u][row];
    unsigned r1404 = input_cols[57u][row];
    unsigned r1405 = input_cols[58u][row];
    unsigned r1406 = input_cols[59u][row];
    unsigned r1407 = input_cols[60u][row];
    unsigned r1408 = input_cols[61u][row];
    unsigned r1409 = input_cols[62u][row];
    unsigned r1410 = input_cols[63u][row];
    unsigned r1411 = input_cols[64u][row];
    unsigned r1412 = input_cols[65u][row];
    unsigned r1413 = input_cols[66u][row];
    unsigned r1414 = input_cols[67u][row];
    unsigned r1415 = input_cols[68u][row];
    unsigned r1416 = input_cols[69u][row];
    unsigned r1417 = input_cols[70u][row];
    unsigned r1418 = input_cols[71u][row];
    unsigned r1419 = input_cols[44u][row];
    unsigned r1420 = input_cols[45u][row];
    unsigned r1421 = input_cols[46u][row];
    unsigned r1422 = input_cols[47u][row];
    unsigned r1423 = input_cols[48u][row];
    unsigned r1424 = input_cols[49u][row];
    unsigned r1425 = input_cols[50u][row];
    unsigned r1426 = input_cols[51u][row];
    unsigned r1427 = input_cols[52u][row];
    unsigned r1428 = input_cols[53u][row];
    unsigned r1429 = input_cols[54u][row];
    unsigned r1430 = input_cols[55u][row];
    unsigned r1431 = input_cols[56u][row];
    unsigned r1432 = input_cols[57u][row];
    unsigned r1433 = input_cols[58u][row];
    unsigned r1434 = input_cols[59u][row];
    unsigned r1435 = input_cols[60u][row];
    unsigned r1436 = input_cols[61u][row];
    unsigned r1437 = input_cols[62u][row];
    unsigned r1438 = input_cols[63u][row];
    unsigned r1439 = input_cols[64u][row];
    unsigned r1440 = input_cols[65u][row];
    unsigned r1441 = input_cols[66u][row];
    unsigned r1442 = input_cols[67u][row];
    unsigned r1443 = input_cols[68u][row];
    unsigned r1444 = input_cols[69u][row];
    unsigned r1445 = input_cols[70u][row];
    unsigned r1446 = input_cols[71u][row];
    unsigned r1447 = input_cols[44u][row];
    unsigned r1448 = input_cols[45u][row];
    unsigned r1449 = input_cols[46u][row];
    unsigned r1450 = input_cols[47u][row];
    unsigned r1451 = input_cols[48u][row];
    unsigned r1452 = input_cols[49u][row];
    unsigned r1453 = input_cols[50u][row];
    unsigned r1454 = input_cols[51u][row];
    unsigned r1455 = input_cols[52u][row];
    unsigned r1456 = input_cols[53u][row];
    unsigned r1457 = input_cols[54u][row];
    unsigned r1458 = input_cols[55u][row];
    unsigned r1459 = input_cols[56u][row];
    unsigned r1460 = input_cols[57u][row];
    unsigned r1461 = input_cols[58u][row];
    unsigned r1462 = input_cols[59u][row];
    unsigned r1463 = input_cols[60u][row];
    unsigned r1464 = input_cols[61u][row];
    unsigned r1465 = input_cols[62u][row];
    unsigned r1466 = input_cols[63u][row];
    unsigned r1467 = input_cols[64u][row];
    unsigned r1468 = input_cols[65u][row];
    unsigned r1469 = input_cols[66u][row];
    unsigned r1470 = input_cols[67u][row];
    unsigned r1471 = input_cols[68u][row];
    unsigned r1472 = input_cols[69u][row];
    unsigned r1473 = input_cols[70u][row];
    unsigned r1474 = input_cols[71u][row];
    unsigned r1475 = input_cols[44u][row];
    unsigned r1476 = input_cols[45u][row];
    unsigned r1477 = input_cols[46u][row];
    unsigned r1478 = input_cols[47u][row];
    unsigned r1479 = input_cols[48u][row];
    unsigned r1480 = input_cols[49u][row];
    unsigned r1481 = input_cols[50u][row];
    unsigned r1482 = input_cols[51u][row];
    unsigned r1483 = input_cols[52u][row];
    unsigned r1484 = input_cols[53u][row];
    unsigned r1485 = input_cols[54u][row];
    unsigned r1486 = input_cols[55u][row];
    unsigned r1487 = input_cols[56u][row];
    unsigned r1488 = input_cols[57u][row];
    unsigned r1489 = input_cols[58u][row];
    unsigned r1490 = input_cols[59u][row];
    unsigned r1491 = input_cols[60u][row];
    unsigned r1492 = input_cols[61u][row];
    unsigned r1493 = input_cols[62u][row];
    unsigned r1494 = input_cols[63u][row];
    unsigned r1495 = input_cols[64u][row];
    unsigned r1496 = input_cols[65u][row];
    unsigned r1497 = input_cols[66u][row];
    unsigned r1498 = input_cols[67u][row];
    unsigned r1499 = input_cols[68u][row];
    unsigned r1500 = input_cols[69u][row];
    unsigned r1501 = input_cols[70u][row];
    unsigned r1502 = input_cols[71u][row];
    unsigned r1503 = input_cols[44u][row];
    unsigned r1504 = input_cols[45u][row];
    unsigned r1505 = input_cols[46u][row];
    unsigned r1506 = input_cols[47u][row];
    unsigned r1507 = input_cols[48u][row];
    unsigned r1508 = input_cols[49u][row];
    unsigned r1509 = input_cols[50u][row];
    unsigned r1510 = input_cols[51u][row];
    unsigned r1511 = input_cols[52u][row];
    unsigned r1512 = input_cols[53u][row];
    unsigned r1513 = input_cols[54u][row];
    unsigned r1514 = input_cols[55u][row];
    unsigned r1515 = input_cols[56u][row];
    unsigned r1516 = input_cols[57u][row];
    unsigned r1517 = input_cols[58u][row];
    unsigned r1518 = input_cols[59u][row];
    unsigned r1519 = input_cols[60u][row];
    unsigned r1520 = input_cols[61u][row];
    unsigned r1521 = input_cols[62u][row];
    unsigned r1522 = input_cols[63u][row];
    unsigned r1523 = input_cols[64u][row];
    unsigned r1524 = input_cols[65u][row];
    unsigned r1525 = input_cols[66u][row];
    unsigned r1526 = input_cols[67u][row];
    unsigned r1527 = input_cols[68u][row];
    unsigned r1528 = input_cols[69u][row];
    unsigned r1529 = input_cols[70u][row];
    unsigned r1530 = input_cols[71u][row];
    unsigned r1531 = input_cols[44u][row];
    unsigned r1532 = input_cols[45u][row];
    unsigned r1533 = input_cols[46u][row];
    unsigned r1534 = input_cols[47u][row];
    unsigned r1535 = input_cols[48u][row];
    unsigned r1536 = input_cols[49u][row];
    unsigned r1537 = input_cols[50u][row];
    unsigned r1538 = input_cols[51u][row];
    unsigned r1539 = input_cols[52u][row];
    unsigned r1540 = input_cols[53u][row];
    unsigned r1541 = input_cols[54u][row];
    unsigned r1542 = input_cols[55u][row];
    unsigned r1543 = input_cols[56u][row];
    unsigned r1544 = input_cols[57u][row];
    unsigned r1545 = input_cols[58u][row];
    unsigned r1546 = input_cols[59u][row];
    unsigned r1547 = input_cols[60u][row];
    unsigned r1548 = input_cols[61u][row];
    unsigned r1549 = input_cols[62u][row];
    unsigned r1550 = input_cols[63u][row];
    unsigned r1551 = input_cols[64u][row];
    unsigned r1552 = input_cols[65u][row];
    unsigned r1553 = input_cols[66u][row];
    unsigned r1554 = input_cols[67u][row];
    unsigned r1555 = input_cols[68u][row];
    unsigned r1556 = input_cols[69u][row];
    unsigned r1557 = input_cols[70u][row];
    unsigned r1558 = input_cols[71u][row];
    unsigned r1559 = input_cols[44u][row];
    unsigned r1560 = input_cols[45u][row];
    unsigned r1561 = input_cols[46u][row];
    unsigned r1562 = input_cols[47u][row];
    unsigned r1563 = input_cols[48u][row];
    unsigned r1564 = input_cols[49u][row];
    unsigned r1565 = input_cols[50u][row];
    unsigned r1566 = input_cols[51u][row];
    unsigned r1567 = input_cols[52u][row];
    unsigned r1568 = input_cols[53u][row];
    unsigned r1569 = input_cols[54u][row];
    unsigned r1570 = input_cols[55u][row];
    unsigned r1571 = input_cols[56u][row];
    unsigned r1572 = input_cols[57u][row];
    unsigned r1573 = input_cols[58u][row];
    unsigned r1574 = input_cols[59u][row];
    unsigned r1575 = input_cols[60u][row];
    unsigned r1576 = input_cols[61u][row];
    unsigned r1577 = input_cols[62u][row];
    unsigned r1578 = input_cols[63u][row];
    unsigned r1579 = input_cols[64u][row];
    unsigned r1580 = input_cols[65u][row];
    unsigned r1581 = input_cols[66u][row];
    unsigned r1582 = input_cols[67u][row];
    unsigned r1583 = input_cols[68u][row];
    unsigned r1584 = input_cols[69u][row];
    unsigned r1585 = input_cols[70u][row];
    unsigned r1586 = input_cols[71u][row];
    unsigned r1587 = input_cols[44u][row];
    unsigned r1588 = input_cols[45u][row];
    unsigned r1589 = input_cols[46u][row];
    unsigned r1590 = input_cols[47u][row];
    unsigned r1591 = input_cols[48u][row];
    unsigned r1592 = input_cols[49u][row];
    unsigned r1593 = input_cols[50u][row];
    unsigned r1594 = input_cols[51u][row];
    unsigned r1595 = input_cols[52u][row];
    unsigned r1596 = input_cols[53u][row];
    unsigned r1597 = input_cols[54u][row];
    unsigned r1598 = input_cols[55u][row];
    unsigned r1599 = input_cols[56u][row];
    unsigned r1600 = input_cols[57u][row];
    unsigned r1601 = input_cols[58u][row];
    unsigned r1602 = input_cols[59u][row];
    unsigned r1603 = input_cols[60u][row];
    unsigned r1604 = input_cols[61u][row];
    unsigned r1605 = input_cols[62u][row];
    unsigned r1606 = input_cols[63u][row];
    unsigned r1607 = input_cols[64u][row];
    unsigned r1608 = input_cols[65u][row];
    unsigned r1609 = input_cols[66u][row];
    unsigned r1610 = input_cols[67u][row];
    unsigned r1611 = input_cols[68u][row];
    unsigned r1612 = input_cols[69u][row];
    unsigned r1613 = input_cols[70u][row];
    unsigned r1614 = input_cols[71u][row];
    unsigned r1615 = stwo_m31_mul(r9, r32);
    unsigned r1616 = stwo_m31_add(r1615, r33);
    sub_words[0u * row_count + row] = r1616;
    unsigned r1617 = stwo_m31_mul(r9, r32);
    unsigned r1618 = stwo_m31_add(r1617, r33);
    const unsigned dargs0[1] = { r1618 };
    unsigned douts0[56];
    stwo_wit_deduce_pedersen_points_w18(dargs0, douts0);
    unsigned r1619 = douts0[0];
    unsigned r1620 = douts0[1];
    unsigned r1621 = douts0[2];
    unsigned r1622 = douts0[3];
    unsigned r1623 = douts0[4];
    unsigned r1624 = douts0[5];
    unsigned r1625 = douts0[6];
    unsigned r1626 = douts0[7];
    unsigned r1627 = douts0[8];
    unsigned r1628 = douts0[9];
    unsigned r1629 = douts0[10];
    unsigned r1630 = douts0[11];
    unsigned r1631 = douts0[12];
    unsigned r1632 = douts0[13];
    unsigned r1633 = douts0[14];
    unsigned r1634 = douts0[15];
    unsigned r1635 = douts0[16];
    unsigned r1636 = douts0[17];
    unsigned r1637 = douts0[18];
    unsigned r1638 = douts0[19];
    unsigned r1639 = douts0[20];
    unsigned r1640 = douts0[21];
    unsigned r1641 = douts0[22];
    unsigned r1642 = douts0[23];
    unsigned r1643 = douts0[24];
    unsigned r1644 = douts0[25];
    unsigned r1645 = douts0[26];
    unsigned r1646 = douts0[27];
    unsigned r1647 = douts0[28];
    unsigned r1648 = douts0[29];
    unsigned r1649 = douts0[30];
    unsigned r1650 = douts0[31];
    unsigned r1651 = douts0[32];
    unsigned r1652 = douts0[33];
    unsigned r1653 = douts0[34];
    unsigned r1654 = douts0[35];
    unsigned r1655 = douts0[36];
    unsigned r1656 = douts0[37];
    unsigned r1657 = douts0[38];
    unsigned r1658 = douts0[39];
    unsigned r1659 = douts0[40];
    unsigned r1660 = douts0[41];
    unsigned r1661 = douts0[42];
    unsigned r1662 = douts0[43];
    unsigned r1663 = douts0[44];
    unsigned r1664 = douts0[45];
    unsigned r1665 = douts0[46];
    unsigned r1666 = douts0[47];
    unsigned r1667 = douts0[48];
    unsigned r1668 = douts0[49];
    unsigned r1669 = douts0[50];
    unsigned r1670 = douts0[51];
    unsigned r1671 = douts0[52];
    unsigned r1672 = douts0[53];
    unsigned r1673 = douts0[54];
    unsigned r1674 = douts0[55];
    unsigned r1675 = stwo_m31_mul(r9, r32);
    unsigned r1676 = stwo_m31_add(r1675, r33);
    out_cols[2u][row] = r33;
    lookup_words[147u * row_count + row] = r1676;
    lookup_words[3u * row_count + row] = r33;
    unsigned r1677 = input_cols[44u][row];
    unsigned r1678 = input_cols[45u][row];
    unsigned r1679 = input_cols[46u][row];
    unsigned r1680 = input_cols[47u][row];
    unsigned r1681 = input_cols[48u][row];
    unsigned r1682 = input_cols[49u][row];
    unsigned r1683 = input_cols[50u][row];
    unsigned r1684 = input_cols[51u][row];
    unsigned r1685 = input_cols[52u][row];
    unsigned r1686 = input_cols[53u][row];
    unsigned r1687 = input_cols[54u][row];
    unsigned r1688 = input_cols[55u][row];
    unsigned r1689 = input_cols[56u][row];
    unsigned r1690 = input_cols[57u][row];
    unsigned r1691 = input_cols[58u][row];
    unsigned r1692 = input_cols[59u][row];
    unsigned r1693 = input_cols[60u][row];
    unsigned r1694 = input_cols[61u][row];
    unsigned r1695 = input_cols[62u][row];
    unsigned r1696 = input_cols[63u][row];
    unsigned r1697 = input_cols[64u][row];
    unsigned r1698 = input_cols[65u][row];
    unsigned r1699 = input_cols[66u][row];
    unsigned r1700 = input_cols[67u][row];
    unsigned r1701 = input_cols[68u][row];
    unsigned r1702 = input_cols[69u][row];
    unsigned r1703 = input_cols[70u][row];
    unsigned r1704 = input_cols[71u][row];
    const unsigned dargs1[56] = { r1647, r1648, r1649, r1650, r1651, r1652, r1653, r1654, r1655, r1656, r1657, r1658, r1659, r1660, r1661, r1662, r1663, r1664, r1665, r1666, r1667, r1668, r1669, r1670, r1671, r1672, r1673, r1674, r1677, r1678, r1679, r1680, r1681, r1682, r1683, r1684, r1685, r1686, r1687, r1688, r1689, r1690, r1691, r1692, r1693, r1694, r1695, r1696, r1697, r1698, r1699, r1700, r1701, r1702, r1703, r1704 };
    unsigned douts1[28];
    stwo_wit_deduce_felt_sub(dargs1, douts1);
    unsigned r1705 = douts1[0];
    unsigned r1706 = douts1[1];
    unsigned r1707 = douts1[2];
    unsigned r1708 = douts1[3];
    unsigned r1709 = douts1[4];
    unsigned r1710 = douts1[5];
    unsigned r1711 = douts1[6];
    unsigned r1712 = douts1[7];
    unsigned r1713 = douts1[8];
    unsigned r1714 = douts1[9];
    unsigned r1715 = douts1[10];
    unsigned r1716 = douts1[11];
    unsigned r1717 = douts1[12];
    unsigned r1718 = douts1[13];
    unsigned r1719 = douts1[14];
    unsigned r1720 = douts1[15];
    unsigned r1721 = douts1[16];
    unsigned r1722 = douts1[17];
    unsigned r1723 = douts1[18];
    unsigned r1724 = douts1[19];
    unsigned r1725 = douts1[20];
    unsigned r1726 = douts1[21];
    unsigned r1727 = douts1[22];
    unsigned r1728 = douts1[23];
    unsigned r1729 = douts1[24];
    unsigned r1730 = douts1[25];
    unsigned r1731 = douts1[26];
    unsigned r1732 = douts1[27];
    unsigned r1733 = input_cols[16u][row];
    unsigned r1734 = input_cols[17u][row];
    unsigned r1735 = input_cols[18u][row];
    unsigned r1736 = input_cols[19u][row];
    unsigned r1737 = input_cols[20u][row];
    unsigned r1738 = input_cols[21u][row];
    unsigned r1739 = input_cols[22u][row];
    unsigned r1740 = input_cols[23u][row];
    unsigned r1741 = input_cols[24u][row];
    unsigned r1742 = input_cols[25u][row];
    unsigned r1743 = input_cols[26u][row];
    unsigned r1744 = input_cols[27u][row];
    unsigned r1745 = input_cols[28u][row];
    unsigned r1746 = input_cols[29u][row];
    unsigned r1747 = input_cols[30u][row];
    unsigned r1748 = input_cols[31u][row];
    unsigned r1749 = input_cols[32u][row];
    unsigned r1750 = input_cols[33u][row];
    unsigned r1751 = input_cols[34u][row];
    unsigned r1752 = input_cols[35u][row];
    unsigned r1753 = input_cols[36u][row];
    unsigned r1754 = input_cols[37u][row];
    unsigned r1755 = input_cols[38u][row];
    unsigned r1756 = input_cols[39u][row];
    unsigned r1757 = input_cols[40u][row];
    unsigned r1758 = input_cols[41u][row];
    unsigned r1759 = input_cols[42u][row];
    unsigned r1760 = input_cols[43u][row];
    const unsigned dargs2[56] = { r1619, r1620, r1621, r1622, r1623, r1624, r1625, r1626, r1627, r1628, r1629, r1630, r1631, r1632, r1633, r1634, r1635, r1636, r1637, r1638, r1639, r1640, r1641, r1642, r1643, r1644, r1645, r1646, r1733, r1734, r1735, r1736, r1737, r1738, r1739, r1740, r1741, r1742, r1743, r1744, r1745, r1746, r1747, r1748, r1749, r1750, r1751, r1752, r1753, r1754, r1755, r1756, r1757, r1758, r1759, r1760 };
    unsigned douts2[28];
    stwo_wit_deduce_felt_sub(dargs2, douts2);
    unsigned r1761 = douts2[0];
    unsigned r1762 = douts2[1];
    unsigned r1763 = douts2[2];
    unsigned r1764 = douts2[3];
    unsigned r1765 = douts2[4];
    unsigned r1766 = douts2[5];
    unsigned r1767 = douts2[6];
    unsigned r1768 = douts2[7];
    unsigned r1769 = douts2[8];
    unsigned r1770 = douts2[9];
    unsigned r1771 = douts2[10];
    unsigned r1772 = douts2[11];
    unsigned r1773 = douts2[12];
    unsigned r1774 = douts2[13];
    unsigned r1775 = douts2[14];
    unsigned r1776 = douts2[15];
    unsigned r1777 = douts2[16];
    unsigned r1778 = douts2[17];
    unsigned r1779 = douts2[18];
    unsigned r1780 = douts2[19];
    unsigned r1781 = douts2[20];
    unsigned r1782 = douts2[21];
    unsigned r1783 = douts2[22];
    unsigned r1784 = douts2[23];
    unsigned r1785 = douts2[24];
    unsigned r1786 = douts2[25];
    unsigned r1787 = douts2[26];
    unsigned r1788 = douts2[27];
    const unsigned dargs3[56] = { r1705, r1706, r1707, r1708, r1709, r1710, r1711, r1712, r1713, r1714, r1715, r1716, r1717, r1718, r1719, r1720, r1721, r1722, r1723, r1724, r1725, r1726, r1727, r1728, r1729, r1730, r1731, r1732, r1761, r1762, r1763, r1764, r1765, r1766, r1767, r1768, r1769, r1770, r1771, r1772, r1773, r1774, r1775, r1776, r1777, r1778, r1779, r1780, r1781, r1782, r1783, r1784, r1785, r1786, r1787, r1788 };
    unsigned douts3[28];
    stwo_wit_deduce_felt_div(dargs3, douts3);
    unsigned r1789 = douts3[0];
    unsigned r1790 = douts3[1];
    unsigned r1791 = douts3[2];
    unsigned r1792 = douts3[3];
    unsigned r1793 = douts3[4];
    unsigned r1794 = douts3[5];
    unsigned r1795 = douts3[6];
    unsigned r1796 = douts3[7];
    unsigned r1797 = douts3[8];
    unsigned r1798 = douts3[9];
    unsigned r1799 = douts3[10];
    unsigned r1800 = douts3[11];
    unsigned r1801 = douts3[12];
    unsigned r1802 = douts3[13];
    unsigned r1803 = douts3[14];
    unsigned r1804 = douts3[15];
    unsigned r1805 = douts3[16];
    unsigned r1806 = douts3[17];
    unsigned r1807 = douts3[18];
    unsigned r1808 = douts3[19];
    unsigned r1809 = douts3[20];
    unsigned r1810 = douts3[21];
    unsigned r1811 = douts3[22];
    unsigned r1812 = douts3[23];
    unsigned r1813 = douts3[24];
    unsigned r1814 = douts3[25];
    unsigned r1815 = douts3[26];
    unsigned r1816 = douts3[27];
    unsigned r1817 = stwo_m31_sub(r1619, r47);
    unsigned r1818 = stwo_m31_mul(r1789, r1817);
    unsigned r1819 = stwo_m31_sub(r1620, r76);
    unsigned r1820 = stwo_m31_mul(r1789, r1819);
    unsigned r1821 = stwo_m31_sub(r1619, r47);
    unsigned r1822 = stwo_m31_mul(r1790, r1821);
    unsigned r1823 = stwo_m31_add(r1820, r1822);
    unsigned r1824 = stwo_m31_sub(r1621, r105);
    unsigned r1825 = stwo_m31_mul(r1789, r1824);
    unsigned r1826 = stwo_m31_sub(r1620, r76);
    unsigned r1827 = stwo_m31_mul(r1790, r1826);
    unsigned r1828 = stwo_m31_add(r1825, r1827);
    unsigned r1829 = stwo_m31_sub(r1619, r47);
    unsigned r1830 = stwo_m31_mul(r1791, r1829);
    unsigned r1831 = stwo_m31_add(r1828, r1830);
    unsigned r1832 = stwo_m31_sub(r1622, r134);
    unsigned r1833 = stwo_m31_mul(r1789, r1832);
    unsigned r1834 = stwo_m31_sub(r1621, r105);
    unsigned r1835 = stwo_m31_mul(r1790, r1834);
    unsigned r1836 = stwo_m31_add(r1833, r1835);
    unsigned r1837 = stwo_m31_sub(r1620, r76);
    unsigned r1838 = stwo_m31_mul(r1791, r1837);
    unsigned r1839 = stwo_m31_add(r1836, r1838);
    unsigned r1840 = stwo_m31_sub(r1619, r47);
    unsigned r1841 = stwo_m31_mul(r1792, r1840);
    unsigned r1842 = stwo_m31_add(r1839, r1841);
    unsigned r1843 = stwo_m31_sub(r1623, r163);
    unsigned r1844 = stwo_m31_mul(r1789, r1843);
    unsigned r1845 = stwo_m31_sub(r1622, r134);
    unsigned r1846 = stwo_m31_mul(r1790, r1845);
    unsigned r1847 = stwo_m31_add(r1844, r1846);
    unsigned r1848 = stwo_m31_sub(r1621, r105);
    unsigned r1849 = stwo_m31_mul(r1791, r1848);
    unsigned r1850 = stwo_m31_add(r1847, r1849);
    unsigned r1851 = stwo_m31_sub(r1620, r76);
    unsigned r1852 = stwo_m31_mul(r1792, r1851);
    unsigned r1853 = stwo_m31_add(r1850, r1852);
    unsigned r1854 = stwo_m31_sub(r1619, r47);
    unsigned r1855 = stwo_m31_mul(r1793, r1854);
    unsigned r1856 = stwo_m31_add(r1853, r1855);
    unsigned r1857 = stwo_m31_sub(r1624, r192);
    unsigned r1858 = stwo_m31_mul(r1789, r1857);
    unsigned r1859 = stwo_m31_sub(r1623, r163);
    unsigned r1860 = stwo_m31_mul(r1790, r1859);
    unsigned r1861 = stwo_m31_add(r1858, r1860);
    unsigned r1862 = stwo_m31_sub(r1622, r134);
    unsigned r1863 = stwo_m31_mul(r1791, r1862);
    unsigned r1864 = stwo_m31_add(r1861, r1863);
    unsigned r1865 = stwo_m31_sub(r1621, r105);
    unsigned r1866 = stwo_m31_mul(r1792, r1865);
    unsigned r1867 = stwo_m31_add(r1864, r1866);
    unsigned r1868 = stwo_m31_sub(r1620, r76);
    unsigned r1869 = stwo_m31_mul(r1793, r1868);
    unsigned r1870 = stwo_m31_add(r1867, r1869);
    unsigned r1871 = stwo_m31_sub(r1619, r47);
    unsigned r1872 = stwo_m31_mul(r1794, r1871);
    unsigned r1873 = stwo_m31_add(r1870, r1872);
    unsigned r1874 = stwo_m31_sub(r1625, r221);
    unsigned r1875 = stwo_m31_mul(r1789, r1874);
    unsigned r1876 = stwo_m31_sub(r1624, r192);
    unsigned r1877 = stwo_m31_mul(r1790, r1876);
    unsigned r1878 = stwo_m31_add(r1875, r1877);
    unsigned r1879 = stwo_m31_sub(r1623, r163);
    unsigned r1880 = stwo_m31_mul(r1791, r1879);
    unsigned r1881 = stwo_m31_add(r1878, r1880);
    unsigned r1882 = stwo_m31_sub(r1622, r134);
    unsigned r1883 = stwo_m31_mul(r1792, r1882);
    unsigned r1884 = stwo_m31_add(r1881, r1883);
    unsigned r1885 = stwo_m31_sub(r1621, r105);
    unsigned r1886 = stwo_m31_mul(r1793, r1885);
    unsigned r1887 = stwo_m31_add(r1884, r1886);
    unsigned r1888 = stwo_m31_sub(r1620, r76);
    unsigned r1889 = stwo_m31_mul(r1794, r1888);
    unsigned r1890 = stwo_m31_add(r1887, r1889);
    unsigned r1891 = stwo_m31_sub(r1619, r47);
    unsigned r1892 = stwo_m31_mul(r1795, r1891);
    unsigned r1893 = stwo_m31_add(r1890, r1892);
    unsigned r1894 = stwo_m31_sub(r1625, r221);
    unsigned r1895 = stwo_m31_mul(r1790, r1894);
    unsigned r1896 = stwo_m31_sub(r1624, r192);
    unsigned r1897 = stwo_m31_mul(r1791, r1896);
    unsigned r1898 = stwo_m31_add(r1895, r1897);
    unsigned r1899 = stwo_m31_sub(r1623, r163);
    unsigned r1900 = stwo_m31_mul(r1792, r1899);
    unsigned r1901 = stwo_m31_add(r1898, r1900);
    unsigned r1902 = stwo_m31_sub(r1622, r134);
    unsigned r1903 = stwo_m31_mul(r1793, r1902);
    unsigned r1904 = stwo_m31_add(r1901, r1903);
    unsigned r1905 = stwo_m31_sub(r1621, r105);
    unsigned r1906 = stwo_m31_mul(r1794, r1905);
    unsigned r1907 = stwo_m31_add(r1904, r1906);
    unsigned r1908 = stwo_m31_sub(r1620, r76);
    unsigned r1909 = stwo_m31_mul(r1795, r1908);
    unsigned r1910 = stwo_m31_add(r1907, r1909);
    unsigned r1911 = stwo_m31_sub(r1625, r221);
    unsigned r1912 = stwo_m31_mul(r1791, r1911);
    unsigned r1913 = stwo_m31_sub(r1624, r192);
    unsigned r1914 = stwo_m31_mul(r1792, r1913);
    unsigned r1915 = stwo_m31_add(r1912, r1914);
    unsigned r1916 = stwo_m31_sub(r1623, r163);
    unsigned r1917 = stwo_m31_mul(r1793, r1916);
    unsigned r1918 = stwo_m31_add(r1915, r1917);
    unsigned r1919 = stwo_m31_sub(r1622, r134);
    unsigned r1920 = stwo_m31_mul(r1794, r1919);
    unsigned r1921 = stwo_m31_add(r1918, r1920);
    unsigned r1922 = stwo_m31_sub(r1621, r105);
    unsigned r1923 = stwo_m31_mul(r1795, r1922);
    unsigned r1924 = stwo_m31_add(r1921, r1923);
    unsigned r1925 = stwo_m31_sub(r1625, r221);
    unsigned r1926 = stwo_m31_mul(r1792, r1925);
    unsigned r1927 = stwo_m31_sub(r1624, r192);
    unsigned r1928 = stwo_m31_mul(r1793, r1927);
    unsigned r1929 = stwo_m31_add(r1926, r1928);
    unsigned r1930 = stwo_m31_sub(r1623, r163);
    unsigned r1931 = stwo_m31_mul(r1794, r1930);
    unsigned r1932 = stwo_m31_add(r1929, r1931);
    unsigned r1933 = stwo_m31_sub(r1622, r134);
    unsigned r1934 = stwo_m31_mul(r1795, r1933);
    unsigned r1935 = stwo_m31_add(r1932, r1934);
    unsigned r1936 = stwo_m31_sub(r1625, r221);
    unsigned r1937 = stwo_m31_mul(r1793, r1936);
    unsigned r1938 = stwo_m31_sub(r1624, r192);
    unsigned r1939 = stwo_m31_mul(r1794, r1938);
    unsigned r1940 = stwo_m31_add(r1937, r1939);
    unsigned r1941 = stwo_m31_sub(r1623, r163);
    unsigned r1942 = stwo_m31_mul(r1795, r1941);
    unsigned r1943 = stwo_m31_add(r1940, r1942);
    unsigned r1944 = stwo_m31_sub(r1625, r221);
    unsigned r1945 = stwo_m31_mul(r1794, r1944);
    unsigned r1946 = stwo_m31_sub(r1624, r192);
    unsigned r1947 = stwo_m31_mul(r1795, r1946);
    unsigned r1948 = stwo_m31_add(r1945, r1947);
    unsigned r1949 = stwo_m31_sub(r1625, r221);
    unsigned r1950 = stwo_m31_mul(r1795, r1949);
    unsigned r1951 = stwo_m31_sub(r1626, r250);
    unsigned r1952 = stwo_m31_mul(r1796, r1951);
    unsigned r1953 = stwo_m31_sub(r1627, r279);
    unsigned r1954 = stwo_m31_mul(r1796, r1953);
    unsigned r1955 = stwo_m31_sub(r1626, r250);
    unsigned r1956 = stwo_m31_mul(r1797, r1955);
    unsigned r1957 = stwo_m31_add(r1954, r1956);
    unsigned r1958 = stwo_m31_sub(r1628, r308);
    unsigned r1959 = stwo_m31_mul(r1796, r1958);
    unsigned r1960 = stwo_m31_sub(r1627, r279);
    unsigned r1961 = stwo_m31_mul(r1797, r1960);
    unsigned r1962 = stwo_m31_add(r1959, r1961);
    unsigned r1963 = stwo_m31_sub(r1626, r250);
    unsigned r1964 = stwo_m31_mul(r1798, r1963);
    unsigned r1965 = stwo_m31_add(r1962, r1964);
    unsigned r1966 = stwo_m31_sub(r1629, r337);
    unsigned r1967 = stwo_m31_mul(r1796, r1966);
    unsigned r1968 = stwo_m31_sub(r1628, r308);
    unsigned r1969 = stwo_m31_mul(r1797, r1968);
    unsigned r1970 = stwo_m31_add(r1967, r1969);
    unsigned r1971 = stwo_m31_sub(r1627, r279);
    unsigned r1972 = stwo_m31_mul(r1798, r1971);
    unsigned r1973 = stwo_m31_add(r1970, r1972);
    unsigned r1974 = stwo_m31_sub(r1626, r250);
    unsigned r1975 = stwo_m31_mul(r1799, r1974);
    unsigned r1976 = stwo_m31_add(r1973, r1975);
    unsigned r1977 = stwo_m31_sub(r1630, r366);
    unsigned r1978 = stwo_m31_mul(r1796, r1977);
    unsigned r1979 = stwo_m31_sub(r1629, r337);
    unsigned r1980 = stwo_m31_mul(r1797, r1979);
    unsigned r1981 = stwo_m31_add(r1978, r1980);
    unsigned r1982 = stwo_m31_sub(r1628, r308);
    unsigned r1983 = stwo_m31_mul(r1798, r1982);
    unsigned r1984 = stwo_m31_add(r1981, r1983);
    unsigned r1985 = stwo_m31_sub(r1627, r279);
    unsigned r1986 = stwo_m31_mul(r1799, r1985);
    unsigned r1987 = stwo_m31_add(r1984, r1986);
    unsigned r1988 = stwo_m31_sub(r1626, r250);
    unsigned r1989 = stwo_m31_mul(r1800, r1988);
    unsigned r1990 = stwo_m31_add(r1987, r1989);
    unsigned r1991 = stwo_m31_sub(r1631, r395);
    unsigned r1992 = stwo_m31_mul(r1796, r1991);
    unsigned r1993 = stwo_m31_sub(r1630, r366);
    unsigned r1994 = stwo_m31_mul(r1797, r1993);
    unsigned r1995 = stwo_m31_add(r1992, r1994);
    unsigned r1996 = stwo_m31_sub(r1629, r337);
    unsigned r1997 = stwo_m31_mul(r1798, r1996);
    unsigned r1998 = stwo_m31_add(r1995, r1997);
    unsigned r1999 = stwo_m31_sub(r1628, r308);
    unsigned r2000 = stwo_m31_mul(r1799, r1999);
    unsigned r2001 = stwo_m31_add(r1998, r2000);
    unsigned r2002 = stwo_m31_sub(r1627, r279);
    unsigned r2003 = stwo_m31_mul(r1800, r2002);
    unsigned r2004 = stwo_m31_add(r2001, r2003);
    unsigned r2005 = stwo_m31_sub(r1626, r250);
    unsigned r2006 = stwo_m31_mul(r1801, r2005);
    unsigned r2007 = stwo_m31_add(r2004, r2006);
    unsigned r2008 = stwo_m31_sub(r1632, r424);
    unsigned r2009 = stwo_m31_mul(r1796, r2008);
    unsigned r2010 = stwo_m31_sub(r1631, r395);
    unsigned r2011 = stwo_m31_mul(r1797, r2010);
    unsigned r2012 = stwo_m31_add(r2009, r2011);
    unsigned r2013 = stwo_m31_sub(r1630, r366);
    unsigned r2014 = stwo_m31_mul(r1798, r2013);
    unsigned r2015 = stwo_m31_add(r2012, r2014);
    unsigned r2016 = stwo_m31_sub(r1629, r337);
    unsigned r2017 = stwo_m31_mul(r1799, r2016);
    unsigned r2018 = stwo_m31_add(r2015, r2017);
    unsigned r2019 = stwo_m31_sub(r1628, r308);
    unsigned r2020 = stwo_m31_mul(r1800, r2019);
    unsigned r2021 = stwo_m31_add(r2018, r2020);
    unsigned r2022 = stwo_m31_sub(r1627, r279);
    unsigned r2023 = stwo_m31_mul(r1801, r2022);
    unsigned r2024 = stwo_m31_add(r2021, r2023);
    unsigned r2025 = stwo_m31_sub(r1626, r250);
    unsigned r2026 = stwo_m31_mul(r1802, r2025);
    unsigned r2027 = stwo_m31_add(r2024, r2026);
    unsigned r2028 = stwo_m31_sub(r1632, r424);
    unsigned r2029 = stwo_m31_mul(r1797, r2028);
    unsigned r2030 = stwo_m31_sub(r1631, r395);
    unsigned r2031 = stwo_m31_mul(r1798, r2030);
    unsigned r2032 = stwo_m31_add(r2029, r2031);
    unsigned r2033 = stwo_m31_sub(r1630, r366);
    unsigned r2034 = stwo_m31_mul(r1799, r2033);
    unsigned r2035 = stwo_m31_add(r2032, r2034);
    unsigned r2036 = stwo_m31_sub(r1629, r337);
    unsigned r2037 = stwo_m31_mul(r1800, r2036);
    unsigned r2038 = stwo_m31_add(r2035, r2037);
    unsigned r2039 = stwo_m31_sub(r1628, r308);
    unsigned r2040 = stwo_m31_mul(r1801, r2039);
    unsigned r2041 = stwo_m31_add(r2038, r2040);
    unsigned r2042 = stwo_m31_sub(r1627, r279);
    unsigned r2043 = stwo_m31_mul(r1802, r2042);
    unsigned r2044 = stwo_m31_add(r2041, r2043);
    unsigned r2045 = stwo_m31_sub(r1632, r424);
    unsigned r2046 = stwo_m31_mul(r1798, r2045);
    unsigned r2047 = stwo_m31_sub(r1631, r395);
    unsigned r2048 = stwo_m31_mul(r1799, r2047);
    unsigned r2049 = stwo_m31_add(r2046, r2048);
    unsigned r2050 = stwo_m31_sub(r1630, r366);
    unsigned r2051 = stwo_m31_mul(r1800, r2050);
    unsigned r2052 = stwo_m31_add(r2049, r2051);
    unsigned r2053 = stwo_m31_sub(r1629, r337);
    unsigned r2054 = stwo_m31_mul(r1801, r2053);
    unsigned r2055 = stwo_m31_add(r2052, r2054);
    unsigned r2056 = stwo_m31_sub(r1628, r308);
    unsigned r2057 = stwo_m31_mul(r1802, r2056);
    unsigned r2058 = stwo_m31_add(r2055, r2057);
    unsigned r2059 = stwo_m31_sub(r1632, r424);
    unsigned r2060 = stwo_m31_mul(r1799, r2059);
    unsigned r2061 = stwo_m31_sub(r1631, r395);
    unsigned r2062 = stwo_m31_mul(r1800, r2061);
    unsigned r2063 = stwo_m31_add(r2060, r2062);
    unsigned r2064 = stwo_m31_sub(r1630, r366);
    unsigned r2065 = stwo_m31_mul(r1801, r2064);
    unsigned r2066 = stwo_m31_add(r2063, r2065);
    unsigned r2067 = stwo_m31_sub(r1629, r337);
    unsigned r2068 = stwo_m31_mul(r1802, r2067);
    unsigned r2069 = stwo_m31_add(r2066, r2068);
    unsigned r2070 = stwo_m31_sub(r1632, r424);
    unsigned r2071 = stwo_m31_mul(r1800, r2070);
    unsigned r2072 = stwo_m31_sub(r1631, r395);
    unsigned r2073 = stwo_m31_mul(r1801, r2072);
    unsigned r2074 = stwo_m31_add(r2071, r2073);
    unsigned r2075 = stwo_m31_sub(r1630, r366);
    unsigned r2076 = stwo_m31_mul(r1802, r2075);
    unsigned r2077 = stwo_m31_add(r2074, r2076);
    unsigned r2078 = stwo_m31_sub(r1632, r424);
    unsigned r2079 = stwo_m31_mul(r1801, r2078);
    unsigned r2080 = stwo_m31_sub(r1631, r395);
    unsigned r2081 = stwo_m31_mul(r1802, r2080);
    unsigned r2082 = stwo_m31_add(r2079, r2081);
    unsigned r2083 = stwo_m31_sub(r1632, r424);
    unsigned r2084 = stwo_m31_mul(r1802, r2083);
    unsigned r2085 = stwo_m31_add(r1789, r1796);
    unsigned r2086 = stwo_m31_add(r1790, r1797);
    unsigned r2087 = stwo_m31_add(r1791, r1798);
    unsigned r2088 = stwo_m31_add(r1792, r1799);
    unsigned r2089 = stwo_m31_add(r1793, r1800);
    unsigned r2090 = stwo_m31_add(r1794, r1801);
    unsigned r2091 = stwo_m31_add(r1795, r1802);
    unsigned r2092 = stwo_m31_sub(r1619, r47);
    unsigned r2093 = stwo_m31_sub(r1626, r250);
    unsigned r2094 = stwo_m31_add(r2092, r2093);
    unsigned r2095 = stwo_m31_sub(r1620, r76);
    unsigned r2096 = stwo_m31_sub(r1627, r279);
    unsigned r2097 = stwo_m31_add(r2095, r2096);
    unsigned r2098 = stwo_m31_sub(r1621, r105);
    unsigned r2099 = stwo_m31_sub(r1628, r308);
    unsigned r2100 = stwo_m31_add(r2098, r2099);
    unsigned r2101 = stwo_m31_sub(r1622, r134);
    unsigned r2102 = stwo_m31_sub(r1629, r337);
    unsigned r2103 = stwo_m31_add(r2101, r2102);
    unsigned r2104 = stwo_m31_sub(r1623, r163);
    unsigned r2105 = stwo_m31_sub(r1630, r366);
    unsigned r2106 = stwo_m31_add(r2104, r2105);
    unsigned r2107 = stwo_m31_sub(r1624, r192);
    unsigned r2108 = stwo_m31_sub(r1631, r395);
    unsigned r2109 = stwo_m31_add(r2107, r2108);
    unsigned r2110 = stwo_m31_sub(r1625, r221);
    unsigned r2111 = stwo_m31_sub(r1632, r424);
    unsigned r2112 = stwo_m31_add(r2110, r2111);
    unsigned r2113 = stwo_m31_mul(r2085, r2094);
    unsigned r2114 = stwo_m31_sub(r2113, r1818);
    unsigned r2115 = stwo_m31_sub(r2114, r1952);
    unsigned r2116 = stwo_m31_add(r1910, r2115);
    unsigned r2117 = stwo_m31_mul(r2085, r2097);
    unsigned r2118 = stwo_m31_mul(r2086, r2094);
    unsigned r2119 = stwo_m31_add(r2117, r2118);
    unsigned r2120 = stwo_m31_sub(r2119, r1823);
    unsigned r2121 = stwo_m31_sub(r2120, r1957);
    unsigned r2122 = stwo_m31_add(r1924, r2121);
    unsigned r2123 = stwo_m31_mul(r2085, r2100);
    unsigned r2124 = stwo_m31_mul(r2086, r2097);
    unsigned r2125 = stwo_m31_add(r2123, r2124);
    unsigned r2126 = stwo_m31_mul(r2087, r2094);
    unsigned r2127 = stwo_m31_add(r2125, r2126);
    unsigned r2128 = stwo_m31_sub(r2127, r1831);
    unsigned r2129 = stwo_m31_sub(r2128, r1965);
    unsigned r2130 = stwo_m31_add(r1935, r2129);
    unsigned r2131 = stwo_m31_mul(r2085, r2103);
    unsigned r2132 = stwo_m31_mul(r2086, r2100);
    unsigned r2133 = stwo_m31_add(r2131, r2132);
    unsigned r2134 = stwo_m31_mul(r2087, r2097);
    unsigned r2135 = stwo_m31_add(r2133, r2134);
    unsigned r2136 = stwo_m31_mul(r2088, r2094);
    unsigned r2137 = stwo_m31_add(r2135, r2136);
    unsigned r2138 = stwo_m31_sub(r2137, r1842);
    unsigned r2139 = stwo_m31_sub(r2138, r1976);
    unsigned r2140 = stwo_m31_add(r1943, r2139);
    unsigned r2141 = stwo_m31_mul(r2085, r2106);
    unsigned r2142 = stwo_m31_mul(r2086, r2103);
    unsigned r2143 = stwo_m31_add(r2141, r2142);
    unsigned r2144 = stwo_m31_mul(r2087, r2100);
    unsigned r2145 = stwo_m31_add(r2143, r2144);
    unsigned r2146 = stwo_m31_mul(r2088, r2097);
    unsigned r2147 = stwo_m31_add(r2145, r2146);
    unsigned r2148 = stwo_m31_mul(r2089, r2094);
    unsigned r2149 = stwo_m31_add(r2147, r2148);
    unsigned r2150 = stwo_m31_sub(r2149, r1856);
    unsigned r2151 = stwo_m31_sub(r2150, r1990);
    unsigned r2152 = stwo_m31_add(r1948, r2151);
    unsigned r2153 = stwo_m31_mul(r2085, r2109);
    unsigned r2154 = stwo_m31_mul(r2086, r2106);
    unsigned r2155 = stwo_m31_add(r2153, r2154);
    unsigned r2156 = stwo_m31_mul(r2087, r2103);
    unsigned r2157 = stwo_m31_add(r2155, r2156);
    unsigned r2158 = stwo_m31_mul(r2088, r2100);
    unsigned r2159 = stwo_m31_add(r2157, r2158);
    unsigned r2160 = stwo_m31_mul(r2089, r2097);
    unsigned r2161 = stwo_m31_add(r2159, r2160);
    unsigned r2162 = stwo_m31_mul(r2090, r2094);
    unsigned r2163 = stwo_m31_add(r2161, r2162);
    unsigned r2164 = stwo_m31_sub(r2163, r1873);
    unsigned r2165 = stwo_m31_sub(r2164, r2007);
    unsigned r2166 = stwo_m31_add(r1950, r2165);
    unsigned r2167 = stwo_m31_mul(r2085, r2112);
    unsigned r2168 = stwo_m31_mul(r2086, r2109);
    unsigned r2169 = stwo_m31_add(r2167, r2168);
    unsigned r2170 = stwo_m31_mul(r2087, r2106);
    unsigned r2171 = stwo_m31_add(r2169, r2170);
    unsigned r2172 = stwo_m31_mul(r2088, r2103);
    unsigned r2173 = stwo_m31_add(r2171, r2172);
    unsigned r2174 = stwo_m31_mul(r2089, r2100);
    unsigned r2175 = stwo_m31_add(r2173, r2174);
    unsigned r2176 = stwo_m31_mul(r2090, r2097);
    unsigned r2177 = stwo_m31_add(r2175, r2176);
    unsigned r2178 = stwo_m31_mul(r2091, r2094);
    unsigned r2179 = stwo_m31_add(r2177, r2178);
    unsigned r2180 = stwo_m31_sub(r2179, r1893);
    unsigned r2181 = stwo_m31_sub(r2180, r2027);
    unsigned r2182 = stwo_m31_mul(r2086, r2112);
    unsigned r2183 = stwo_m31_mul(r2087, r2109);
    unsigned r2184 = stwo_m31_add(r2182, r2183);
    unsigned r2185 = stwo_m31_mul(r2088, r2106);
    unsigned r2186 = stwo_m31_add(r2184, r2185);
    unsigned r2187 = stwo_m31_mul(r2089, r2103);
    unsigned r2188 = stwo_m31_add(r2186, r2187);
    unsigned r2189 = stwo_m31_mul(r2090, r2100);
    unsigned r2190 = stwo_m31_add(r2188, r2189);
    unsigned r2191 = stwo_m31_mul(r2091, r2097);
    unsigned r2192 = stwo_m31_add(r2190, r2191);
    unsigned r2193 = stwo_m31_sub(r2192, r1910);
    unsigned r2194 = stwo_m31_sub(r2193, r2044);
    unsigned r2195 = stwo_m31_add(r1952, r2194);
    unsigned r2196 = stwo_m31_mul(r2087, r2112);
    unsigned r2197 = stwo_m31_mul(r2088, r2109);
    unsigned r2198 = stwo_m31_add(r2196, r2197);
    unsigned r2199 = stwo_m31_mul(r2089, r2106);
    unsigned r2200 = stwo_m31_add(r2198, r2199);
    unsigned r2201 = stwo_m31_mul(r2090, r2103);
    unsigned r2202 = stwo_m31_add(r2200, r2201);
    unsigned r2203 = stwo_m31_mul(r2091, r2100);
    unsigned r2204 = stwo_m31_add(r2202, r2203);
    unsigned r2205 = stwo_m31_sub(r2204, r1924);
    unsigned r2206 = stwo_m31_sub(r2205, r2058);
    unsigned r2207 = stwo_m31_add(r1957, r2206);
    unsigned r2208 = stwo_m31_mul(r2088, r2112);
    unsigned r2209 = stwo_m31_mul(r2089, r2109);
    unsigned r2210 = stwo_m31_add(r2208, r2209);
    unsigned r2211 = stwo_m31_mul(r2090, r2106);
    unsigned r2212 = stwo_m31_add(r2210, r2211);
    unsigned r2213 = stwo_m31_mul(r2091, r2103);
    unsigned r2214 = stwo_m31_add(r2212, r2213);
    unsigned r2215 = stwo_m31_sub(r2214, r1935);
    unsigned r2216 = stwo_m31_sub(r2215, r2069);
    unsigned r2217 = stwo_m31_add(r1965, r2216);
    unsigned r2218 = stwo_m31_mul(r2089, r2112);
    unsigned r2219 = stwo_m31_mul(r2090, r2109);
    unsigned r2220 = stwo_m31_add(r2218, r2219);
    unsigned r2221 = stwo_m31_mul(r2091, r2106);
    unsigned r2222 = stwo_m31_add(r2220, r2221);
    unsigned r2223 = stwo_m31_sub(r2222, r1943);
    unsigned r2224 = stwo_m31_sub(r2223, r2077);
    unsigned r2225 = stwo_m31_add(r1976, r2224);
    unsigned r2226 = stwo_m31_mul(r2090, r2112);
    unsigned r2227 = stwo_m31_mul(r2091, r2109);
    unsigned r2228 = stwo_m31_add(r2226, r2227);
    unsigned r2229 = stwo_m31_sub(r2228, r1948);
    unsigned r2230 = stwo_m31_sub(r2229, r2082);
    unsigned r2231 = stwo_m31_add(r1990, r2230);
    unsigned r2232 = stwo_m31_mul(r2091, r2112);
    unsigned r2233 = stwo_m31_sub(r2232, r1950);
    unsigned r2234 = stwo_m31_sub(r2233, r2084);
    unsigned r2235 = stwo_m31_add(r2007, r2234);
    unsigned r2236 = stwo_m31_sub(r1633, r453);
    unsigned r2237 = stwo_m31_mul(r1803, r2236);
    unsigned r2238 = stwo_m31_sub(r1634, r482);
    unsigned r2239 = stwo_m31_mul(r1803, r2238);
    unsigned r2240 = stwo_m31_sub(r1633, r453);
    unsigned r2241 = stwo_m31_mul(r1804, r2240);
    unsigned r2242 = stwo_m31_add(r2239, r2241);
    unsigned r2243 = stwo_m31_sub(r1635, r511);
    unsigned r2244 = stwo_m31_mul(r1803, r2243);
    unsigned r2245 = stwo_m31_sub(r1634, r482);
    unsigned r2246 = stwo_m31_mul(r1804, r2245);
    unsigned r2247 = stwo_m31_add(r2244, r2246);
    unsigned r2248 = stwo_m31_sub(r1633, r453);
    unsigned r2249 = stwo_m31_mul(r1805, r2248);
    unsigned r2250 = stwo_m31_add(r2247, r2249);
    unsigned r2251 = stwo_m31_sub(r1636, r540);
    unsigned r2252 = stwo_m31_mul(r1803, r2251);
    unsigned r2253 = stwo_m31_sub(r1635, r511);
    unsigned r2254 = stwo_m31_mul(r1804, r2253);
    unsigned r2255 = stwo_m31_add(r2252, r2254);
    unsigned r2256 = stwo_m31_sub(r1634, r482);
    unsigned r2257 = stwo_m31_mul(r1805, r2256);
    unsigned r2258 = stwo_m31_add(r2255, r2257);
    unsigned r2259 = stwo_m31_sub(r1633, r453);
    unsigned r2260 = stwo_m31_mul(r1806, r2259);
    unsigned r2261 = stwo_m31_add(r2258, r2260);
    unsigned r2262 = stwo_m31_sub(r1637, r569);
    unsigned r2263 = stwo_m31_mul(r1803, r2262);
    unsigned r2264 = stwo_m31_sub(r1636, r540);
    unsigned r2265 = stwo_m31_mul(r1804, r2264);
    unsigned r2266 = stwo_m31_add(r2263, r2265);
    unsigned r2267 = stwo_m31_sub(r1635, r511);
    unsigned r2268 = stwo_m31_mul(r1805, r2267);
    unsigned r2269 = stwo_m31_add(r2266, r2268);
    unsigned r2270 = stwo_m31_sub(r1634, r482);
    unsigned r2271 = stwo_m31_mul(r1806, r2270);
    unsigned r2272 = stwo_m31_add(r2269, r2271);
    unsigned r2273 = stwo_m31_sub(r1633, r453);
    unsigned r2274 = stwo_m31_mul(r1807, r2273);
    unsigned r2275 = stwo_m31_add(r2272, r2274);
    unsigned r2276 = stwo_m31_sub(r1638, r598);
    unsigned r2277 = stwo_m31_mul(r1803, r2276);
    unsigned r2278 = stwo_m31_sub(r1637, r569);
    unsigned r2279 = stwo_m31_mul(r1804, r2278);
    unsigned r2280 = stwo_m31_add(r2277, r2279);
    unsigned r2281 = stwo_m31_sub(r1636, r540);
    unsigned r2282 = stwo_m31_mul(r1805, r2281);
    unsigned r2283 = stwo_m31_add(r2280, r2282);
    unsigned r2284 = stwo_m31_sub(r1635, r511);
    unsigned r2285 = stwo_m31_mul(r1806, r2284);
    unsigned r2286 = stwo_m31_add(r2283, r2285);
    unsigned r2287 = stwo_m31_sub(r1634, r482);
    unsigned r2288 = stwo_m31_mul(r1807, r2287);
    unsigned r2289 = stwo_m31_add(r2286, r2288);
    unsigned r2290 = stwo_m31_sub(r1633, r453);
    unsigned r2291 = stwo_m31_mul(r1808, r2290);
    unsigned r2292 = stwo_m31_add(r2289, r2291);
    unsigned r2293 = stwo_m31_sub(r1639, r627);
    unsigned r2294 = stwo_m31_mul(r1803, r2293);
    unsigned r2295 = stwo_m31_sub(r1638, r598);
    unsigned r2296 = stwo_m31_mul(r1804, r2295);
    unsigned r2297 = stwo_m31_add(r2294, r2296);
    unsigned r2298 = stwo_m31_sub(r1637, r569);
    unsigned r2299 = stwo_m31_mul(r1805, r2298);
    unsigned r2300 = stwo_m31_add(r2297, r2299);
    unsigned r2301 = stwo_m31_sub(r1636, r540);
    unsigned r2302 = stwo_m31_mul(r1806, r2301);
    unsigned r2303 = stwo_m31_add(r2300, r2302);
    unsigned r2304 = stwo_m31_sub(r1635, r511);
    unsigned r2305 = stwo_m31_mul(r1807, r2304);
    unsigned r2306 = stwo_m31_add(r2303, r2305);
    unsigned r2307 = stwo_m31_sub(r1634, r482);
    unsigned r2308 = stwo_m31_mul(r1808, r2307);
    unsigned r2309 = stwo_m31_add(r2306, r2308);
    unsigned r2310 = stwo_m31_sub(r1633, r453);
    unsigned r2311 = stwo_m31_mul(r1809, r2310);
    unsigned r2312 = stwo_m31_add(r2309, r2311);
    unsigned r2313 = stwo_m31_sub(r1639, r627);
    unsigned r2314 = stwo_m31_mul(r1804, r2313);
    unsigned r2315 = stwo_m31_sub(r1638, r598);
    unsigned r2316 = stwo_m31_mul(r1805, r2315);
    unsigned r2317 = stwo_m31_add(r2314, r2316);
    unsigned r2318 = stwo_m31_sub(r1637, r569);
    unsigned r2319 = stwo_m31_mul(r1806, r2318);
    unsigned r2320 = stwo_m31_add(r2317, r2319);
    unsigned r2321 = stwo_m31_sub(r1636, r540);
    unsigned r2322 = stwo_m31_mul(r1807, r2321);
    unsigned r2323 = stwo_m31_add(r2320, r2322);
    unsigned r2324 = stwo_m31_sub(r1635, r511);
    unsigned r2325 = stwo_m31_mul(r1808, r2324);
    unsigned r2326 = stwo_m31_add(r2323, r2325);
    unsigned r2327 = stwo_m31_sub(r1634, r482);
    unsigned r2328 = stwo_m31_mul(r1809, r2327);
    unsigned r2329 = stwo_m31_add(r2326, r2328);
    unsigned r2330 = stwo_m31_sub(r1639, r627);
    unsigned r2331 = stwo_m31_mul(r1805, r2330);
    unsigned r2332 = stwo_m31_sub(r1638, r598);
    unsigned r2333 = stwo_m31_mul(r1806, r2332);
    unsigned r2334 = stwo_m31_add(r2331, r2333);
    unsigned r2335 = stwo_m31_sub(r1637, r569);
    unsigned r2336 = stwo_m31_mul(r1807, r2335);
    unsigned r2337 = stwo_m31_add(r2334, r2336);
    unsigned r2338 = stwo_m31_sub(r1636, r540);
    unsigned r2339 = stwo_m31_mul(r1808, r2338);
    unsigned r2340 = stwo_m31_add(r2337, r2339);
    unsigned r2341 = stwo_m31_sub(r1635, r511);
    unsigned r2342 = stwo_m31_mul(r1809, r2341);
    unsigned r2343 = stwo_m31_add(r2340, r2342);
    unsigned r2344 = stwo_m31_sub(r1639, r627);
    unsigned r2345 = stwo_m31_mul(r1806, r2344);
    unsigned r2346 = stwo_m31_sub(r1638, r598);
    unsigned r2347 = stwo_m31_mul(r1807, r2346);
    unsigned r2348 = stwo_m31_add(r2345, r2347);
    unsigned r2349 = stwo_m31_sub(r1637, r569);
    unsigned r2350 = stwo_m31_mul(r1808, r2349);
    unsigned r2351 = stwo_m31_add(r2348, r2350);
    unsigned r2352 = stwo_m31_sub(r1636, r540);
    unsigned r2353 = stwo_m31_mul(r1809, r2352);
    unsigned r2354 = stwo_m31_add(r2351, r2353);
    unsigned r2355 = stwo_m31_sub(r1639, r627);
    unsigned r2356 = stwo_m31_mul(r1807, r2355);
    unsigned r2357 = stwo_m31_sub(r1638, r598);
    unsigned r2358 = stwo_m31_mul(r1808, r2357);
    unsigned r2359 = stwo_m31_add(r2356, r2358);
    unsigned r2360 = stwo_m31_sub(r1637, r569);
    unsigned r2361 = stwo_m31_mul(r1809, r2360);
    unsigned r2362 = stwo_m31_add(r2359, r2361);
    unsigned r2363 = stwo_m31_sub(r1639, r627);
    unsigned r2364 = stwo_m31_mul(r1808, r2363);
    unsigned r2365 = stwo_m31_sub(r1638, r598);
    unsigned r2366 = stwo_m31_mul(r1809, r2365);
    unsigned r2367 = stwo_m31_add(r2364, r2366);
    unsigned r2368 = stwo_m31_sub(r1639, r627);
    unsigned r2369 = stwo_m31_mul(r1809, r2368);
    unsigned r2370 = stwo_m31_sub(r1640, r656);
    unsigned r2371 = stwo_m31_mul(r1810, r2370);
    unsigned r2372 = stwo_m31_sub(r1641, r685);
    unsigned r2373 = stwo_m31_mul(r1810, r2372);
    unsigned r2374 = stwo_m31_sub(r1640, r656);
    unsigned r2375 = stwo_m31_mul(r1811, r2374);
    unsigned r2376 = stwo_m31_add(r2373, r2375);
    unsigned r2377 = stwo_m31_sub(r1642, r714);
    unsigned r2378 = stwo_m31_mul(r1810, r2377);
    unsigned r2379 = stwo_m31_sub(r1641, r685);
    unsigned r2380 = stwo_m31_mul(r1811, r2379);
    unsigned r2381 = stwo_m31_add(r2378, r2380);
    unsigned r2382 = stwo_m31_sub(r1640, r656);
    unsigned r2383 = stwo_m31_mul(r1812, r2382);
    unsigned r2384 = stwo_m31_add(r2381, r2383);
    unsigned r2385 = stwo_m31_sub(r1643, r743);
    unsigned r2386 = stwo_m31_mul(r1810, r2385);
    unsigned r2387 = stwo_m31_sub(r1642, r714);
    unsigned r2388 = stwo_m31_mul(r1811, r2387);
    unsigned r2389 = stwo_m31_add(r2386, r2388);
    unsigned r2390 = stwo_m31_sub(r1641, r685);
    unsigned r2391 = stwo_m31_mul(r1812, r2390);
    unsigned r2392 = stwo_m31_add(r2389, r2391);
    unsigned r2393 = stwo_m31_sub(r1640, r656);
    unsigned r2394 = stwo_m31_mul(r1813, r2393);
    unsigned r2395 = stwo_m31_add(r2392, r2394);
    unsigned r2396 = stwo_m31_sub(r1644, r772);
    unsigned r2397 = stwo_m31_mul(r1810, r2396);
    unsigned r2398 = stwo_m31_sub(r1643, r743);
    unsigned r2399 = stwo_m31_mul(r1811, r2398);
    unsigned r2400 = stwo_m31_add(r2397, r2399);
    unsigned r2401 = stwo_m31_sub(r1642, r714);
    unsigned r2402 = stwo_m31_mul(r1812, r2401);
    unsigned r2403 = stwo_m31_add(r2400, r2402);
    unsigned r2404 = stwo_m31_sub(r1641, r685);
    unsigned r2405 = stwo_m31_mul(r1813, r2404);
    unsigned r2406 = stwo_m31_add(r2403, r2405);
    unsigned r2407 = stwo_m31_sub(r1640, r656);
    unsigned r2408 = stwo_m31_mul(r1814, r2407);
    unsigned r2409 = stwo_m31_add(r2406, r2408);
    unsigned r2410 = stwo_m31_sub(r1645, r801);
    unsigned r2411 = stwo_m31_mul(r1810, r2410);
    unsigned r2412 = stwo_m31_sub(r1644, r772);
    unsigned r2413 = stwo_m31_mul(r1811, r2412);
    unsigned r2414 = stwo_m31_add(r2411, r2413);
    unsigned r2415 = stwo_m31_sub(r1643, r743);
    unsigned r2416 = stwo_m31_mul(r1812, r2415);
    unsigned r2417 = stwo_m31_add(r2414, r2416);
    unsigned r2418 = stwo_m31_sub(r1642, r714);
    unsigned r2419 = stwo_m31_mul(r1813, r2418);
    unsigned r2420 = stwo_m31_add(r2417, r2419);
    unsigned r2421 = stwo_m31_sub(r1641, r685);
    unsigned r2422 = stwo_m31_mul(r1814, r2421);
    unsigned r2423 = stwo_m31_add(r2420, r2422);
    unsigned r2424 = stwo_m31_sub(r1640, r656);
    unsigned r2425 = stwo_m31_mul(r1815, r2424);
    unsigned r2426 = stwo_m31_add(r2423, r2425);
    unsigned r2427 = stwo_m31_sub(r1646, r830);
    unsigned r2428 = stwo_m31_mul(r1810, r2427);
    unsigned r2429 = stwo_m31_sub(r1645, r801);
    unsigned r2430 = stwo_m31_mul(r1811, r2429);
    unsigned r2431 = stwo_m31_add(r2428, r2430);
    unsigned r2432 = stwo_m31_sub(r1644, r772);
    unsigned r2433 = stwo_m31_mul(r1812, r2432);
    unsigned r2434 = stwo_m31_add(r2431, r2433);
    unsigned r2435 = stwo_m31_sub(r1643, r743);
    unsigned r2436 = stwo_m31_mul(r1813, r2435);
    unsigned r2437 = stwo_m31_add(r2434, r2436);
    unsigned r2438 = stwo_m31_sub(r1642, r714);
    unsigned r2439 = stwo_m31_mul(r1814, r2438);
    unsigned r2440 = stwo_m31_add(r2437, r2439);
    unsigned r2441 = stwo_m31_sub(r1641, r685);
    unsigned r2442 = stwo_m31_mul(r1815, r2441);
    unsigned r2443 = stwo_m31_add(r2440, r2442);
    unsigned r2444 = stwo_m31_sub(r1640, r656);
    unsigned r2445 = stwo_m31_mul(r1816, r2444);
    unsigned r2446 = stwo_m31_add(r2443, r2445);
    unsigned r2447 = stwo_m31_sub(r1646, r830);
    unsigned r2448 = stwo_m31_mul(r1811, r2447);
    unsigned r2449 = stwo_m31_sub(r1645, r801);
    unsigned r2450 = stwo_m31_mul(r1812, r2449);
    unsigned r2451 = stwo_m31_add(r2448, r2450);
    unsigned r2452 = stwo_m31_sub(r1644, r772);
    unsigned r2453 = stwo_m31_mul(r1813, r2452);
    unsigned r2454 = stwo_m31_add(r2451, r2453);
    unsigned r2455 = stwo_m31_sub(r1643, r743);
    unsigned r2456 = stwo_m31_mul(r1814, r2455);
    unsigned r2457 = stwo_m31_add(r2454, r2456);
    unsigned r2458 = stwo_m31_sub(r1642, r714);
    unsigned r2459 = stwo_m31_mul(r1815, r2458);
    unsigned r2460 = stwo_m31_add(r2457, r2459);
    unsigned r2461 = stwo_m31_sub(r1641, r685);
    unsigned r2462 = stwo_m31_mul(r1816, r2461);
    unsigned r2463 = stwo_m31_add(r2460, r2462);
    unsigned r2464 = stwo_m31_sub(r1646, r830);
    unsigned r2465 = stwo_m31_mul(r1812, r2464);
    unsigned r2466 = stwo_m31_sub(r1645, r801);
    unsigned r2467 = stwo_m31_mul(r1813, r2466);
    unsigned r2468 = stwo_m31_add(r2465, r2467);
    unsigned r2469 = stwo_m31_sub(r1644, r772);
    unsigned r2470 = stwo_m31_mul(r1814, r2469);
    unsigned r2471 = stwo_m31_add(r2468, r2470);
    unsigned r2472 = stwo_m31_sub(r1643, r743);
    unsigned r2473 = stwo_m31_mul(r1815, r2472);
    unsigned r2474 = stwo_m31_add(r2471, r2473);
    unsigned r2475 = stwo_m31_sub(r1642, r714);
    unsigned r2476 = stwo_m31_mul(r1816, r2475);
    unsigned r2477 = stwo_m31_add(r2474, r2476);
    unsigned r2478 = stwo_m31_sub(r1646, r830);
    unsigned r2479 = stwo_m31_mul(r1813, r2478);
    unsigned r2480 = stwo_m31_sub(r1645, r801);
    unsigned r2481 = stwo_m31_mul(r1814, r2480);
    unsigned r2482 = stwo_m31_add(r2479, r2481);
    unsigned r2483 = stwo_m31_sub(r1644, r772);
    unsigned r2484 = stwo_m31_mul(r1815, r2483);
    unsigned r2485 = stwo_m31_add(r2482, r2484);
    unsigned r2486 = stwo_m31_sub(r1643, r743);
    unsigned r2487 = stwo_m31_mul(r1816, r2486);
    unsigned r2488 = stwo_m31_add(r2485, r2487);
    unsigned r2489 = stwo_m31_sub(r1646, r830);
    unsigned r2490 = stwo_m31_mul(r1814, r2489);
    unsigned r2491 = stwo_m31_sub(r1645, r801);
    unsigned r2492 = stwo_m31_mul(r1815, r2491);
    unsigned r2493 = stwo_m31_add(r2490, r2492);
    unsigned r2494 = stwo_m31_sub(r1644, r772);
    unsigned r2495 = stwo_m31_mul(r1816, r2494);
    unsigned r2496 = stwo_m31_add(r2493, r2495);
    unsigned r2497 = stwo_m31_sub(r1646, r830);
    unsigned r2498 = stwo_m31_mul(r1815, r2497);
    unsigned r2499 = stwo_m31_sub(r1645, r801);
    unsigned r2500 = stwo_m31_mul(r1816, r2499);
    unsigned r2501 = stwo_m31_add(r2498, r2500);
    unsigned r2502 = stwo_m31_sub(r1646, r830);
    unsigned r2503 = stwo_m31_mul(r1816, r2502);
    unsigned r2504 = stwo_m31_add(r1803, r1810);
    unsigned r2505 = stwo_m31_add(r1804, r1811);
    unsigned r2506 = stwo_m31_add(r1805, r1812);
    unsigned r2507 = stwo_m31_add(r1806, r1813);
    unsigned r2508 = stwo_m31_add(r1807, r1814);
    unsigned r2509 = stwo_m31_add(r1808, r1815);
    unsigned r2510 = stwo_m31_add(r1809, r1816);
    unsigned r2511 = stwo_m31_sub(r1633, r453);
    unsigned r2512 = stwo_m31_sub(r1640, r656);
    unsigned r2513 = stwo_m31_add(r2511, r2512);
    unsigned r2514 = stwo_m31_sub(r1634, r482);
    unsigned r2515 = stwo_m31_sub(r1641, r685);
    unsigned r2516 = stwo_m31_add(r2514, r2515);
    unsigned r2517 = stwo_m31_sub(r1635, r511);
    unsigned r2518 = stwo_m31_sub(r1642, r714);
    unsigned r2519 = stwo_m31_add(r2517, r2518);
    unsigned r2520 = stwo_m31_sub(r1636, r540);
    unsigned r2521 = stwo_m31_sub(r1643, r743);
    unsigned r2522 = stwo_m31_add(r2520, r2521);
    unsigned r2523 = stwo_m31_sub(r1637, r569);
    unsigned r2524 = stwo_m31_sub(r1644, r772);
    unsigned r2525 = stwo_m31_add(r2523, r2524);
    unsigned r2526 = stwo_m31_sub(r1638, r598);
    unsigned r2527 = stwo_m31_sub(r1645, r801);
    unsigned r2528 = stwo_m31_add(r2526, r2527);
    unsigned r2529 = stwo_m31_sub(r1639, r627);
    unsigned r2530 = stwo_m31_sub(r1646, r830);
    unsigned r2531 = stwo_m31_add(r2529, r2530);
    unsigned r2532 = stwo_m31_mul(r2504, r2513);
    unsigned r2533 = stwo_m31_sub(r2532, r2237);
    unsigned r2534 = stwo_m31_sub(r2533, r2371);
    unsigned r2535 = stwo_m31_add(r2329, r2534);
    unsigned r2536 = stwo_m31_mul(r2504, r2516);
    unsigned r2537 = stwo_m31_mul(r2505, r2513);
    unsigned r2538 = stwo_m31_add(r2536, r2537);
    unsigned r2539 = stwo_m31_sub(r2538, r2242);
    unsigned r2540 = stwo_m31_sub(r2539, r2376);
    unsigned r2541 = stwo_m31_add(r2343, r2540);
    unsigned r2542 = stwo_m31_mul(r2504, r2519);
    unsigned r2543 = stwo_m31_mul(r2505, r2516);
    unsigned r2544 = stwo_m31_add(r2542, r2543);
    unsigned r2545 = stwo_m31_mul(r2506, r2513);
    unsigned r2546 = stwo_m31_add(r2544, r2545);
    unsigned r2547 = stwo_m31_sub(r2546, r2250);
    unsigned r2548 = stwo_m31_sub(r2547, r2384);
    unsigned r2549 = stwo_m31_add(r2354, r2548);
    unsigned r2550 = stwo_m31_mul(r2504, r2522);
    unsigned r2551 = stwo_m31_mul(r2505, r2519);
    unsigned r2552 = stwo_m31_add(r2550, r2551);
    unsigned r2553 = stwo_m31_mul(r2506, r2516);
    unsigned r2554 = stwo_m31_add(r2552, r2553);
    unsigned r2555 = stwo_m31_mul(r2507, r2513);
    unsigned r2556 = stwo_m31_add(r2554, r2555);
    unsigned r2557 = stwo_m31_sub(r2556, r2261);
    unsigned r2558 = stwo_m31_sub(r2557, r2395);
    unsigned r2559 = stwo_m31_add(r2362, r2558);
    unsigned r2560 = stwo_m31_mul(r2504, r2525);
    unsigned r2561 = stwo_m31_mul(r2505, r2522);
    unsigned r2562 = stwo_m31_add(r2560, r2561);
    unsigned r2563 = stwo_m31_mul(r2506, r2519);
    unsigned r2564 = stwo_m31_add(r2562, r2563);
    unsigned r2565 = stwo_m31_mul(r2507, r2516);
    unsigned r2566 = stwo_m31_add(r2564, r2565);
    unsigned r2567 = stwo_m31_mul(r2508, r2513);
    unsigned r2568 = stwo_m31_add(r2566, r2567);
    unsigned r2569 = stwo_m31_sub(r2568, r2275);
    unsigned r2570 = stwo_m31_sub(r2569, r2409);
    unsigned r2571 = stwo_m31_add(r2367, r2570);
    unsigned r2572 = stwo_m31_mul(r2504, r2528);
    unsigned r2573 = stwo_m31_mul(r2505, r2525);
    unsigned r2574 = stwo_m31_add(r2572, r2573);
    unsigned r2575 = stwo_m31_mul(r2506, r2522);
    unsigned r2576 = stwo_m31_add(r2574, r2575);
    unsigned r2577 = stwo_m31_mul(r2507, r2519);
    unsigned r2578 = stwo_m31_add(r2576, r2577);
    unsigned r2579 = stwo_m31_mul(r2508, r2516);
    unsigned r2580 = stwo_m31_add(r2578, r2579);
    unsigned r2581 = stwo_m31_mul(r2509, r2513);
    unsigned r2582 = stwo_m31_add(r2580, r2581);
    unsigned r2583 = stwo_m31_sub(r2582, r2292);
    unsigned r2584 = stwo_m31_sub(r2583, r2426);
    unsigned r2585 = stwo_m31_add(r2369, r2584);
    unsigned r2586 = stwo_m31_mul(r2504, r2531);
    unsigned r2587 = stwo_m31_mul(r2505, r2528);
    unsigned r2588 = stwo_m31_add(r2586, r2587);
    unsigned r2589 = stwo_m31_mul(r2506, r2525);
    unsigned r2590 = stwo_m31_add(r2588, r2589);
    unsigned r2591 = stwo_m31_mul(r2507, r2522);
    unsigned r2592 = stwo_m31_add(r2590, r2591);
    unsigned r2593 = stwo_m31_mul(r2508, r2519);
    unsigned r2594 = stwo_m31_add(r2592, r2593);
    unsigned r2595 = stwo_m31_mul(r2509, r2516);
    unsigned r2596 = stwo_m31_add(r2594, r2595);
    unsigned r2597 = stwo_m31_mul(r2510, r2513);
    unsigned r2598 = stwo_m31_add(r2596, r2597);
    unsigned r2599 = stwo_m31_sub(r2598, r2312);
    unsigned r2600 = stwo_m31_sub(r2599, r2446);
    unsigned r2601 = stwo_m31_mul(r2505, r2531);
    unsigned r2602 = stwo_m31_mul(r2506, r2528);
    unsigned r2603 = stwo_m31_add(r2601, r2602);
    unsigned r2604 = stwo_m31_mul(r2507, r2525);
    unsigned r2605 = stwo_m31_add(r2603, r2604);
    unsigned r2606 = stwo_m31_mul(r2508, r2522);
    unsigned r2607 = stwo_m31_add(r2605, r2606);
    unsigned r2608 = stwo_m31_mul(r2509, r2519);
    unsigned r2609 = stwo_m31_add(r2607, r2608);
    unsigned r2610 = stwo_m31_mul(r2510, r2516);
    unsigned r2611 = stwo_m31_add(r2609, r2610);
    unsigned r2612 = stwo_m31_sub(r2611, r2329);
    unsigned r2613 = stwo_m31_sub(r2612, r2463);
    unsigned r2614 = stwo_m31_add(r2371, r2613);
    unsigned r2615 = stwo_m31_mul(r2506, r2531);
    unsigned r2616 = stwo_m31_mul(r2507, r2528);
    unsigned r2617 = stwo_m31_add(r2615, r2616);
    unsigned r2618 = stwo_m31_mul(r2508, r2525);
    unsigned r2619 = stwo_m31_add(r2617, r2618);
    unsigned r2620 = stwo_m31_mul(r2509, r2522);
    unsigned r2621 = stwo_m31_add(r2619, r2620);
    unsigned r2622 = stwo_m31_mul(r2510, r2519);
    unsigned r2623 = stwo_m31_add(r2621, r2622);
    unsigned r2624 = stwo_m31_sub(r2623, r2343);
    unsigned r2625 = stwo_m31_sub(r2624, r2477);
    unsigned r2626 = stwo_m31_add(r2376, r2625);
    unsigned r2627 = stwo_m31_mul(r2507, r2531);
    unsigned r2628 = stwo_m31_mul(r2508, r2528);
    unsigned r2629 = stwo_m31_add(r2627, r2628);
    unsigned r2630 = stwo_m31_mul(r2509, r2525);
    unsigned r2631 = stwo_m31_add(r2629, r2630);
    unsigned r2632 = stwo_m31_mul(r2510, r2522);
    unsigned r2633 = stwo_m31_add(r2631, r2632);
    unsigned r2634 = stwo_m31_sub(r2633, r2354);
    unsigned r2635 = stwo_m31_sub(r2634, r2488);
    unsigned r2636 = stwo_m31_add(r2384, r2635);
    unsigned r2637 = stwo_m31_mul(r2508, r2531);
    unsigned r2638 = stwo_m31_mul(r2509, r2528);
    unsigned r2639 = stwo_m31_add(r2637, r2638);
    unsigned r2640 = stwo_m31_mul(r2510, r2525);
    unsigned r2641 = stwo_m31_add(r2639, r2640);
    unsigned r2642 = stwo_m31_sub(r2641, r2362);
    unsigned r2643 = stwo_m31_sub(r2642, r2496);
    unsigned r2644 = stwo_m31_add(r2395, r2643);
    unsigned r2645 = stwo_m31_mul(r2509, r2531);
    unsigned r2646 = stwo_m31_mul(r2510, r2528);
    unsigned r2647 = stwo_m31_add(r2645, r2646);
    unsigned r2648 = stwo_m31_sub(r2647, r2367);
    unsigned r2649 = stwo_m31_sub(r2648, r2501);
    unsigned r2650 = stwo_m31_add(r2409, r2649);
    unsigned r2651 = stwo_m31_mul(r2510, r2531);
    unsigned r2652 = stwo_m31_sub(r2651, r2369);
    unsigned r2653 = stwo_m31_sub(r2652, r2503);
    unsigned r2654 = stwo_m31_add(r2426, r2653);
    unsigned r2655 = stwo_m31_add(r1789, r1803);
    unsigned r2656 = stwo_m31_add(r1790, r1804);
    unsigned r2657 = stwo_m31_add(r1791, r1805);
    unsigned r2658 = stwo_m31_add(r1792, r1806);
    unsigned r2659 = stwo_m31_add(r1793, r1807);
    unsigned r2660 = stwo_m31_add(r1794, r1808);
    unsigned r2661 = stwo_m31_add(r1795, r1809);
    unsigned r2662 = stwo_m31_add(r1796, r1810);
    unsigned r2663 = stwo_m31_add(r1797, r1811);
    unsigned r2664 = stwo_m31_add(r1798, r1812);
    unsigned r2665 = stwo_m31_add(r1799, r1813);
    unsigned r2666 = stwo_m31_add(r1800, r1814);
    unsigned r2667 = stwo_m31_add(r1801, r1815);
    unsigned r2668 = stwo_m31_add(r1802, r1816);
    unsigned r2669 = stwo_m31_sub(r1619, r47);
    unsigned r2670 = stwo_m31_sub(r1633, r453);
    unsigned r2671 = stwo_m31_add(r2669, r2670);
    unsigned r2672 = stwo_m31_sub(r1620, r76);
    unsigned r2673 = stwo_m31_sub(r1634, r482);
    unsigned r2674 = stwo_m31_add(r2672, r2673);
    unsigned r2675 = stwo_m31_sub(r1621, r105);
    unsigned r2676 = stwo_m31_sub(r1635, r511);
    unsigned r2677 = stwo_m31_add(r2675, r2676);
    unsigned r2678 = stwo_m31_sub(r1622, r134);
    unsigned r2679 = stwo_m31_sub(r1636, r540);
    unsigned r2680 = stwo_m31_add(r2678, r2679);
    unsigned r2681 = stwo_m31_sub(r1623, r163);
    unsigned r2682 = stwo_m31_sub(r1637, r569);
    unsigned r2683 = stwo_m31_add(r2681, r2682);
    unsigned r2684 = stwo_m31_sub(r1624, r192);
    unsigned r2685 = stwo_m31_sub(r1638, r598);
    unsigned r2686 = stwo_m31_add(r2684, r2685);
    unsigned r2687 = stwo_m31_sub(r1625, r221);
    unsigned r2688 = stwo_m31_sub(r1639, r627);
    unsigned r2689 = stwo_m31_add(r2687, r2688);
    unsigned r2690 = stwo_m31_sub(r1626, r250);
    unsigned r2691 = stwo_m31_sub(r1640, r656);
    unsigned r2692 = stwo_m31_add(r2690, r2691);
    unsigned r2693 = stwo_m31_sub(r1627, r279);
    unsigned r2694 = stwo_m31_sub(r1641, r685);
    unsigned r2695 = stwo_m31_add(r2693, r2694);
    unsigned r2696 = stwo_m31_sub(r1628, r308);
    unsigned r2697 = stwo_m31_sub(r1642, r714);
    unsigned r2698 = stwo_m31_add(r2696, r2697);
    unsigned r2699 = stwo_m31_sub(r1629, r337);
    unsigned r2700 = stwo_m31_sub(r1643, r743);
    unsigned r2701 = stwo_m31_add(r2699, r2700);
    unsigned r2702 = stwo_m31_sub(r1630, r366);
    unsigned r2703 = stwo_m31_sub(r1644, r772);
    unsigned r2704 = stwo_m31_add(r2702, r2703);
    unsigned r2705 = stwo_m31_sub(r1631, r395);
    unsigned r2706 = stwo_m31_sub(r1645, r801);
    unsigned r2707 = stwo_m31_add(r2705, r2706);
    unsigned r2708 = stwo_m31_sub(r1632, r424);
    unsigned r2709 = stwo_m31_sub(r1646, r830);
    unsigned r2710 = stwo_m31_add(r2708, r2709);
    unsigned r2711 = stwo_m31_mul(r2655, r2671);
    unsigned r2712 = stwo_m31_mul(r2655, r2674);
    unsigned r2713 = stwo_m31_mul(r2656, r2671);
    unsigned r2714 = stwo_m31_add(r2712, r2713);
    unsigned r2715 = stwo_m31_mul(r2655, r2677);
    unsigned r2716 = stwo_m31_mul(r2656, r2674);
    unsigned r2717 = stwo_m31_add(r2715, r2716);
    unsigned r2718 = stwo_m31_mul(r2657, r2671);
    unsigned r2719 = stwo_m31_add(r2717, r2718);
    unsigned r2720 = stwo_m31_mul(r2655, r2680);
    unsigned r2721 = stwo_m31_mul(r2656, r2677);
    unsigned r2722 = stwo_m31_add(r2720, r2721);
    unsigned r2723 = stwo_m31_mul(r2657, r2674);
    unsigned r2724 = stwo_m31_add(r2722, r2723);
    unsigned r2725 = stwo_m31_mul(r2658, r2671);
    unsigned r2726 = stwo_m31_add(r2724, r2725);
    unsigned r2727 = stwo_m31_mul(r2655, r2683);
    unsigned r2728 = stwo_m31_mul(r2656, r2680);
    unsigned r2729 = stwo_m31_add(r2727, r2728);
    unsigned r2730 = stwo_m31_mul(r2657, r2677);
    unsigned r2731 = stwo_m31_add(r2729, r2730);
    unsigned r2732 = stwo_m31_mul(r2658, r2674);
    unsigned r2733 = stwo_m31_add(r2731, r2732);
    unsigned r2734 = stwo_m31_mul(r2659, r2671);
    unsigned r2735 = stwo_m31_add(r2733, r2734);
    unsigned r2736 = stwo_m31_mul(r2655, r2686);
    unsigned r2737 = stwo_m31_mul(r2656, r2683);
    unsigned r2738 = stwo_m31_add(r2736, r2737);
    unsigned r2739 = stwo_m31_mul(r2657, r2680);
    unsigned r2740 = stwo_m31_add(r2738, r2739);
    unsigned r2741 = stwo_m31_mul(r2658, r2677);
    unsigned r2742 = stwo_m31_add(r2740, r2741);
    unsigned r2743 = stwo_m31_mul(r2659, r2674);
    unsigned r2744 = stwo_m31_add(r2742, r2743);
    unsigned r2745 = stwo_m31_mul(r2660, r2671);
    unsigned r2746 = stwo_m31_add(r2744, r2745);
    unsigned r2747 = stwo_m31_mul(r2655, r2689);
    unsigned r2748 = stwo_m31_mul(r2656, r2686);
    unsigned r2749 = stwo_m31_add(r2747, r2748);
    unsigned r2750 = stwo_m31_mul(r2657, r2683);
    unsigned r2751 = stwo_m31_add(r2749, r2750);
    unsigned r2752 = stwo_m31_mul(r2658, r2680);
    unsigned r2753 = stwo_m31_add(r2751, r2752);
    unsigned r2754 = stwo_m31_mul(r2659, r2677);
    unsigned r2755 = stwo_m31_add(r2753, r2754);
    unsigned r2756 = stwo_m31_mul(r2660, r2674);
    unsigned r2757 = stwo_m31_add(r2755, r2756);
    unsigned r2758 = stwo_m31_mul(r2661, r2671);
    unsigned r2759 = stwo_m31_add(r2757, r2758);
    unsigned r2760 = stwo_m31_mul(r2656, r2689);
    unsigned r2761 = stwo_m31_mul(r2657, r2686);
    unsigned r2762 = stwo_m31_add(r2760, r2761);
    unsigned r2763 = stwo_m31_mul(r2658, r2683);
    unsigned r2764 = stwo_m31_add(r2762, r2763);
    unsigned r2765 = stwo_m31_mul(r2659, r2680);
    unsigned r2766 = stwo_m31_add(r2764, r2765);
    unsigned r2767 = stwo_m31_mul(r2660, r2677);
    unsigned r2768 = stwo_m31_add(r2766, r2767);
    unsigned r2769 = stwo_m31_mul(r2661, r2674);
    unsigned r2770 = stwo_m31_add(r2768, r2769);
    unsigned r2771 = stwo_m31_mul(r2657, r2689);
    unsigned r2772 = stwo_m31_mul(r2658, r2686);
    unsigned r2773 = stwo_m31_add(r2771, r2772);
    unsigned r2774 = stwo_m31_mul(r2659, r2683);
    unsigned r2775 = stwo_m31_add(r2773, r2774);
    unsigned r2776 = stwo_m31_mul(r2660, r2680);
    unsigned r2777 = stwo_m31_add(r2775, r2776);
    unsigned r2778 = stwo_m31_mul(r2661, r2677);
    unsigned r2779 = stwo_m31_add(r2777, r2778);
    unsigned r2780 = stwo_m31_mul(r2658, r2689);
    unsigned r2781 = stwo_m31_mul(r2659, r2686);
    unsigned r2782 = stwo_m31_add(r2780, r2781);
    unsigned r2783 = stwo_m31_mul(r2660, r2683);
    unsigned r2784 = stwo_m31_add(r2782, r2783);
    unsigned r2785 = stwo_m31_mul(r2661, r2680);
    unsigned r2786 = stwo_m31_add(r2784, r2785);
    unsigned r2787 = stwo_m31_mul(r2659, r2689);
    unsigned r2788 = stwo_m31_mul(r2660, r2686);
    unsigned r2789 = stwo_m31_add(r2787, r2788);
    unsigned r2790 = stwo_m31_mul(r2661, r2683);
    unsigned r2791 = stwo_m31_add(r2789, r2790);
    unsigned r2792 = stwo_m31_mul(r2660, r2689);
    unsigned r2793 = stwo_m31_mul(r2661, r2686);
    unsigned r2794 = stwo_m31_add(r2792, r2793);
    unsigned r2795 = stwo_m31_mul(r2661, r2689);
    unsigned r2796 = stwo_m31_mul(r2662, r2692);
    unsigned r2797 = stwo_m31_mul(r2662, r2695);
    unsigned r2798 = stwo_m31_mul(r2663, r2692);
    unsigned r2799 = stwo_m31_add(r2797, r2798);
    unsigned r2800 = stwo_m31_mul(r2662, r2698);
    unsigned r2801 = stwo_m31_mul(r2663, r2695);
    unsigned r2802 = stwo_m31_add(r2800, r2801);
    unsigned r2803 = stwo_m31_mul(r2664, r2692);
    unsigned r2804 = stwo_m31_add(r2802, r2803);
    unsigned r2805 = stwo_m31_mul(r2662, r2701);
    unsigned r2806 = stwo_m31_mul(r2663, r2698);
    unsigned r2807 = stwo_m31_add(r2805, r2806);
    unsigned r2808 = stwo_m31_mul(r2664, r2695);
    unsigned r2809 = stwo_m31_add(r2807, r2808);
    unsigned r2810 = stwo_m31_mul(r2665, r2692);
    unsigned r2811 = stwo_m31_add(r2809, r2810);
    unsigned r2812 = stwo_m31_mul(r2662, r2704);
    unsigned r2813 = stwo_m31_mul(r2663, r2701);
    unsigned r2814 = stwo_m31_add(r2812, r2813);
    unsigned r2815 = stwo_m31_mul(r2664, r2698);
    unsigned r2816 = stwo_m31_add(r2814, r2815);
    unsigned r2817 = stwo_m31_mul(r2665, r2695);
    unsigned r2818 = stwo_m31_add(r2816, r2817);
    unsigned r2819 = stwo_m31_mul(r2666, r2692);
    unsigned r2820 = stwo_m31_add(r2818, r2819);
    unsigned r2821 = stwo_m31_mul(r2662, r2707);
    unsigned r2822 = stwo_m31_mul(r2663, r2704);
    unsigned r2823 = stwo_m31_add(r2821, r2822);
    unsigned r2824 = stwo_m31_mul(r2664, r2701);
    unsigned r2825 = stwo_m31_add(r2823, r2824);
    unsigned r2826 = stwo_m31_mul(r2665, r2698);
    unsigned r2827 = stwo_m31_add(r2825, r2826);
    unsigned r2828 = stwo_m31_mul(r2666, r2695);
    unsigned r2829 = stwo_m31_add(r2827, r2828);
    unsigned r2830 = stwo_m31_mul(r2667, r2692);
    unsigned r2831 = stwo_m31_add(r2829, r2830);
    unsigned r2832 = stwo_m31_mul(r2662, r2710);
    unsigned r2833 = stwo_m31_mul(r2663, r2707);
    unsigned r2834 = stwo_m31_add(r2832, r2833);
    unsigned r2835 = stwo_m31_mul(r2664, r2704);
    unsigned r2836 = stwo_m31_add(r2834, r2835);
    unsigned r2837 = stwo_m31_mul(r2665, r2701);
    unsigned r2838 = stwo_m31_add(r2836, r2837);
    unsigned r2839 = stwo_m31_mul(r2666, r2698);
    unsigned r2840 = stwo_m31_add(r2838, r2839);
    unsigned r2841 = stwo_m31_mul(r2667, r2695);
    unsigned r2842 = stwo_m31_add(r2840, r2841);
    unsigned r2843 = stwo_m31_mul(r2668, r2692);
    unsigned r2844 = stwo_m31_add(r2842, r2843);
    unsigned r2845 = stwo_m31_mul(r2663, r2710);
    unsigned r2846 = stwo_m31_mul(r2664, r2707);
    unsigned r2847 = stwo_m31_add(r2845, r2846);
    unsigned r2848 = stwo_m31_mul(r2665, r2704);
    unsigned r2849 = stwo_m31_add(r2847, r2848);
    unsigned r2850 = stwo_m31_mul(r2666, r2701);
    unsigned r2851 = stwo_m31_add(r2849, r2850);
    unsigned r2852 = stwo_m31_mul(r2667, r2698);
    unsigned r2853 = stwo_m31_add(r2851, r2852);
    unsigned r2854 = stwo_m31_mul(r2668, r2695);
    unsigned r2855 = stwo_m31_add(r2853, r2854);
    unsigned r2856 = stwo_m31_mul(r2664, r2710);
    unsigned r2857 = stwo_m31_mul(r2665, r2707);
    unsigned r2858 = stwo_m31_add(r2856, r2857);
    unsigned r2859 = stwo_m31_mul(r2666, r2704);
    unsigned r2860 = stwo_m31_add(r2858, r2859);
    unsigned r2861 = stwo_m31_mul(r2667, r2701);
    unsigned r2862 = stwo_m31_add(r2860, r2861);
    unsigned r2863 = stwo_m31_mul(r2668, r2698);
    unsigned r2864 = stwo_m31_add(r2862, r2863);
    unsigned r2865 = stwo_m31_mul(r2665, r2710);
    unsigned r2866 = stwo_m31_mul(r2666, r2707);
    unsigned r2867 = stwo_m31_add(r2865, r2866);
    unsigned r2868 = stwo_m31_mul(r2667, r2704);
    unsigned r2869 = stwo_m31_add(r2867, r2868);
    unsigned r2870 = stwo_m31_mul(r2668, r2701);
    unsigned r2871 = stwo_m31_add(r2869, r2870);
    unsigned r2872 = stwo_m31_mul(r2666, r2710);
    unsigned r2873 = stwo_m31_mul(r2667, r2707);
    unsigned r2874 = stwo_m31_add(r2872, r2873);
    unsigned r2875 = stwo_m31_mul(r2668, r2704);
    unsigned r2876 = stwo_m31_add(r2874, r2875);
    unsigned r2877 = stwo_m31_mul(r2667, r2710);
    unsigned r2878 = stwo_m31_mul(r2668, r2707);
    unsigned r2879 = stwo_m31_add(r2877, r2878);
    unsigned r2880 = stwo_m31_mul(r2668, r2710);
    unsigned r2881 = stwo_m31_add(r2655, r2662);
    unsigned r2882 = stwo_m31_add(r2656, r2663);
    unsigned r2883 = stwo_m31_add(r2657, r2664);
    unsigned r2884 = stwo_m31_add(r2658, r2665);
    unsigned r2885 = stwo_m31_add(r2659, r2666);
    unsigned r2886 = stwo_m31_add(r2660, r2667);
    unsigned r2887 = stwo_m31_add(r2661, r2668);
    unsigned r2888 = stwo_m31_add(r2671, r2692);
    unsigned r2889 = stwo_m31_add(r2674, r2695);
    unsigned r2890 = stwo_m31_add(r2677, r2698);
    unsigned r2891 = stwo_m31_add(r2680, r2701);
    unsigned r2892 = stwo_m31_add(r2683, r2704);
    unsigned r2893 = stwo_m31_add(r2686, r2707);
    unsigned r2894 = stwo_m31_add(r2689, r2710);
    unsigned r2895 = stwo_m31_mul(r2881, r2888);
    unsigned r2896 = stwo_m31_sub(r2895, r2711);
    unsigned r2897 = stwo_m31_sub(r2896, r2796);
    unsigned r2898 = stwo_m31_add(r2770, r2897);
    unsigned r2899 = stwo_m31_mul(r2881, r2889);
    unsigned r2900 = stwo_m31_mul(r2882, r2888);
    unsigned r2901 = stwo_m31_add(r2899, r2900);
    unsigned r2902 = stwo_m31_sub(r2901, r2714);
    unsigned r2903 = stwo_m31_sub(r2902, r2799);
    unsigned r2904 = stwo_m31_add(r2779, r2903);
    unsigned r2905 = stwo_m31_mul(r2881, r2890);
    unsigned r2906 = stwo_m31_mul(r2882, r2889);
    unsigned r2907 = stwo_m31_add(r2905, r2906);
    unsigned r2908 = stwo_m31_mul(r2883, r2888);
    unsigned r2909 = stwo_m31_add(r2907, r2908);
    unsigned r2910 = stwo_m31_sub(r2909, r2719);
    unsigned r2911 = stwo_m31_sub(r2910, r2804);
    unsigned r2912 = stwo_m31_add(r2786, r2911);
    unsigned r2913 = stwo_m31_mul(r2881, r2891);
    unsigned r2914 = stwo_m31_mul(r2882, r2890);
    unsigned r2915 = stwo_m31_add(r2913, r2914);
    unsigned r2916 = stwo_m31_mul(r2883, r2889);
    unsigned r2917 = stwo_m31_add(r2915, r2916);
    unsigned r2918 = stwo_m31_mul(r2884, r2888);
    unsigned r2919 = stwo_m31_add(r2917, r2918);
    unsigned r2920 = stwo_m31_sub(r2919, r2726);
    unsigned r2921 = stwo_m31_sub(r2920, r2811);
    unsigned r2922 = stwo_m31_add(r2791, r2921);
    unsigned r2923 = stwo_m31_mul(r2881, r2892);
    unsigned r2924 = stwo_m31_mul(r2882, r2891);
    unsigned r2925 = stwo_m31_add(r2923, r2924);
    unsigned r2926 = stwo_m31_mul(r2883, r2890);
    unsigned r2927 = stwo_m31_add(r2925, r2926);
    unsigned r2928 = stwo_m31_mul(r2884, r2889);
    unsigned r2929 = stwo_m31_add(r2927, r2928);
    unsigned r2930 = stwo_m31_mul(r2885, r2888);
    unsigned r2931 = stwo_m31_add(r2929, r2930);
    unsigned r2932 = stwo_m31_sub(r2931, r2735);
    unsigned r2933 = stwo_m31_sub(r2932, r2820);
    unsigned r2934 = stwo_m31_add(r2794, r2933);
    unsigned r2935 = stwo_m31_mul(r2881, r2893);
    unsigned r2936 = stwo_m31_mul(r2882, r2892);
    unsigned r2937 = stwo_m31_add(r2935, r2936);
    unsigned r2938 = stwo_m31_mul(r2883, r2891);
    unsigned r2939 = stwo_m31_add(r2937, r2938);
    unsigned r2940 = stwo_m31_mul(r2884, r2890);
    unsigned r2941 = stwo_m31_add(r2939, r2940);
    unsigned r2942 = stwo_m31_mul(r2885, r2889);
    unsigned r2943 = stwo_m31_add(r2941, r2942);
    unsigned r2944 = stwo_m31_mul(r2886, r2888);
    unsigned r2945 = stwo_m31_add(r2943, r2944);
    unsigned r2946 = stwo_m31_sub(r2945, r2746);
    unsigned r2947 = stwo_m31_sub(r2946, r2831);
    unsigned r2948 = stwo_m31_add(r2795, r2947);
    unsigned r2949 = stwo_m31_mul(r2881, r2894);
    unsigned r2950 = stwo_m31_mul(r2882, r2893);
    unsigned r2951 = stwo_m31_add(r2949, r2950);
    unsigned r2952 = stwo_m31_mul(r2883, r2892);
    unsigned r2953 = stwo_m31_add(r2951, r2952);
    unsigned r2954 = stwo_m31_mul(r2884, r2891);
    unsigned r2955 = stwo_m31_add(r2953, r2954);
    unsigned r2956 = stwo_m31_mul(r2885, r2890);
    unsigned r2957 = stwo_m31_add(r2955, r2956);
    unsigned r2958 = stwo_m31_mul(r2886, r2889);
    unsigned r2959 = stwo_m31_add(r2957, r2958);
    unsigned r2960 = stwo_m31_mul(r2887, r2888);
    unsigned r2961 = stwo_m31_add(r2959, r2960);
    unsigned r2962 = stwo_m31_sub(r2961, r2759);
    unsigned r2963 = stwo_m31_sub(r2962, r2844);
    unsigned r2964 = stwo_m31_mul(r2882, r2894);
    unsigned r2965 = stwo_m31_mul(r2883, r2893);
    unsigned r2966 = stwo_m31_add(r2964, r2965);
    unsigned r2967 = stwo_m31_mul(r2884, r2892);
    unsigned r2968 = stwo_m31_add(r2966, r2967);
    unsigned r2969 = stwo_m31_mul(r2885, r2891);
    unsigned r2970 = stwo_m31_add(r2968, r2969);
    unsigned r2971 = stwo_m31_mul(r2886, r2890);
    unsigned r2972 = stwo_m31_add(r2970, r2971);
    unsigned r2973 = stwo_m31_mul(r2887, r2889);
    unsigned r2974 = stwo_m31_add(r2972, r2973);
    unsigned r2975 = stwo_m31_sub(r2974, r2770);
    unsigned r2976 = stwo_m31_sub(r2975, r2855);
    unsigned r2977 = stwo_m31_add(r2796, r2976);
    unsigned r2978 = stwo_m31_mul(r2883, r2894);
    unsigned r2979 = stwo_m31_mul(r2884, r2893);
    unsigned r2980 = stwo_m31_add(r2978, r2979);
    unsigned r2981 = stwo_m31_mul(r2885, r2892);
    unsigned r2982 = stwo_m31_add(r2980, r2981);
    unsigned r2983 = stwo_m31_mul(r2886, r2891);
    unsigned r2984 = stwo_m31_add(r2982, r2983);
    unsigned r2985 = stwo_m31_mul(r2887, r2890);
    unsigned r2986 = stwo_m31_add(r2984, r2985);
    unsigned r2987 = stwo_m31_sub(r2986, r2779);
    unsigned r2988 = stwo_m31_sub(r2987, r2864);
    unsigned r2989 = stwo_m31_add(r2799, r2988);
    unsigned r2990 = stwo_m31_mul(r2884, r2894);
    unsigned r2991 = stwo_m31_mul(r2885, r2893);
    unsigned r2992 = stwo_m31_add(r2990, r2991);
    unsigned r2993 = stwo_m31_mul(r2886, r2892);
    unsigned r2994 = stwo_m31_add(r2992, r2993);
    unsigned r2995 = stwo_m31_mul(r2887, r2891);
    unsigned r2996 = stwo_m31_add(r2994, r2995);
    unsigned r2997 = stwo_m31_sub(r2996, r2786);
    unsigned r2998 = stwo_m31_sub(r2997, r2871);
    unsigned r2999 = stwo_m31_add(r2804, r2998);
    unsigned r3000 = stwo_m31_mul(r2885, r2894);
    unsigned r3001 = stwo_m31_mul(r2886, r2893);
    unsigned r3002 = stwo_m31_add(r3000, r3001);
    unsigned r3003 = stwo_m31_mul(r2887, r2892);
    unsigned r3004 = stwo_m31_add(r3002, r3003);
    unsigned r3005 = stwo_m31_sub(r3004, r2791);
    unsigned r3006 = stwo_m31_sub(r3005, r2876);
    unsigned r3007 = stwo_m31_add(r2811, r3006);
    unsigned r3008 = stwo_m31_mul(r2886, r2894);
    unsigned r3009 = stwo_m31_mul(r2887, r2893);
    unsigned r3010 = stwo_m31_add(r3008, r3009);
    unsigned r3011 = stwo_m31_sub(r3010, r2794);
    unsigned r3012 = stwo_m31_sub(r3011, r2879);
    unsigned r3013 = stwo_m31_add(r2820, r3012);
    unsigned r3014 = stwo_m31_mul(r2887, r2894);
    unsigned r3015 = stwo_m31_sub(r3014, r2795);
    unsigned r3016 = stwo_m31_sub(r3015, r2880);
    unsigned r3017 = stwo_m31_add(r2831, r3016);
    unsigned r3018 = stwo_m31_sub(r2711, r1818);
    unsigned r3019 = stwo_m31_sub(r3018, r2237);
    unsigned r3020 = stwo_m31_add(r2195, r3019);
    unsigned r3021 = stwo_m31_sub(r2714, r1823);
    unsigned r3022 = stwo_m31_sub(r3021, r2242);
    unsigned r3023 = stwo_m31_add(r2207, r3022);
    unsigned r3024 = stwo_m31_sub(r2719, r1831);
    unsigned r3025 = stwo_m31_sub(r3024, r2250);
    unsigned r3026 = stwo_m31_add(r2217, r3025);
    unsigned r3027 = stwo_m31_sub(r2726, r1842);
    unsigned r3028 = stwo_m31_sub(r3027, r2261);
    unsigned r3029 = stwo_m31_add(r2225, r3028);
    unsigned r3030 = stwo_m31_sub(r2735, r1856);
    unsigned r3031 = stwo_m31_sub(r3030, r2275);
    unsigned r3032 = stwo_m31_add(r2231, r3031);
    unsigned r3033 = stwo_m31_sub(r2746, r1873);
    unsigned r3034 = stwo_m31_sub(r3033, r2292);
    unsigned r3035 = stwo_m31_add(r2235, r3034);
    unsigned r3036 = stwo_m31_sub(r2759, r1893);
    unsigned r3037 = stwo_m31_sub(r3036, r2312);
    unsigned r3038 = stwo_m31_add(r2027, r3037);
    unsigned r3039 = stwo_m31_sub(r2898, r2116);
    unsigned r3040 = stwo_m31_sub(r3039, r2535);
    unsigned r3041 = stwo_m31_add(r2044, r3040);
    unsigned r3042 = stwo_m31_sub(r2904, r2122);
    unsigned r3043 = stwo_m31_sub(r3042, r2541);
    unsigned r3044 = stwo_m31_add(r2058, r3043);
    unsigned r3045 = stwo_m31_sub(r2912, r2130);
    unsigned r3046 = stwo_m31_sub(r3045, r2549);
    unsigned r3047 = stwo_m31_add(r2069, r3046);
    unsigned r3048 = stwo_m31_sub(r2922, r2140);
    unsigned r3049 = stwo_m31_sub(r3048, r2559);
    unsigned r3050 = stwo_m31_add(r2077, r3049);
    unsigned r3051 = stwo_m31_sub(r2934, r2152);
    unsigned r3052 = stwo_m31_sub(r3051, r2571);
    unsigned r3053 = stwo_m31_add(r2082, r3052);
    unsigned r3054 = stwo_m31_sub(r2948, r2166);
    unsigned r3055 = stwo_m31_sub(r3054, r2585);
    unsigned r3056 = stwo_m31_add(r2084, r3055);
    unsigned r3057 = stwo_m31_sub(r2963, r2181);
    unsigned r3058 = stwo_m31_sub(r3057, r2600);
    unsigned r3059 = stwo_m31_sub(r2977, r2195);
    unsigned r3060 = stwo_m31_sub(r3059, r2614);
    unsigned r3061 = stwo_m31_add(r2237, r3060);
    unsigned r3062 = stwo_m31_sub(r2989, r2207);
    unsigned r3063 = stwo_m31_sub(r3062, r2626);
    unsigned r3064 = stwo_m31_add(r2242, r3063);
    unsigned r3065 = stwo_m31_sub(r2999, r2217);
    unsigned r3066 = stwo_m31_sub(r3065, r2636);
    unsigned r3067 = stwo_m31_add(r2250, r3066);
    unsigned r3068 = stwo_m31_sub(r3007, r2225);
    unsigned r3069 = stwo_m31_sub(r3068, r2644);
    unsigned r3070 = stwo_m31_add(r2261, r3069);
    unsigned r3071 = stwo_m31_sub(r3013, r2231);
    unsigned r3072 = stwo_m31_sub(r3071, r2650);
    unsigned r3073 = stwo_m31_add(r2275, r3072);
    unsigned r3074 = stwo_m31_sub(r3017, r2235);
    unsigned r3075 = stwo_m31_sub(r3074, r2654);
    unsigned r3076 = stwo_m31_add(r2292, r3075);
    unsigned r3077 = stwo_m31_sub(r2844, r2027);
    unsigned r3078 = stwo_m31_sub(r3077, r2446);
    unsigned r3079 = stwo_m31_add(r2312, r3078);
    unsigned r3080 = stwo_m31_sub(r2855, r2044);
    unsigned r3081 = stwo_m31_sub(r3080, r2463);
    unsigned r3082 = stwo_m31_add(r2535, r3081);
    unsigned r3083 = stwo_m31_sub(r2864, r2058);
    unsigned r3084 = stwo_m31_sub(r3083, r2477);
    unsigned r3085 = stwo_m31_add(r2541, r3084);
    unsigned r3086 = stwo_m31_sub(r2871, r2069);
    unsigned r3087 = stwo_m31_sub(r3086, r2488);
    unsigned r3088 = stwo_m31_add(r2549, r3087);
    unsigned r3089 = stwo_m31_sub(r2876, r2077);
    unsigned r3090 = stwo_m31_sub(r3089, r2496);
    unsigned r3091 = stwo_m31_add(r2559, r3090);
    unsigned r3092 = stwo_m31_sub(r2879, r2082);
    unsigned r3093 = stwo_m31_sub(r3092, r2501);
    unsigned r3094 = stwo_m31_add(r2571, r3093);
    unsigned r3095 = stwo_m31_sub(r2880, r2084);
    unsigned r3096 = stwo_m31_sub(r3095, r2503);
    unsigned r3097 = stwo_m31_add(r2585, r3096);
    unsigned r3098 = stwo_m31_sub(r1647, r831);
    out_cols[100u][row] = r1647;
    lookup_words[176u * row_count + row] = r1647;
    unsigned r3099 = stwo_m31_sub(r1818, r3098);
    unsigned r3100 = stwo_m31_sub(r1648, r860);
    out_cols[101u][row] = r1648;
    lookup_words[177u * row_count + row] = r1648;
    unsigned r3101 = stwo_m31_sub(r1823, r3100);
    unsigned r3102 = stwo_m31_sub(r1649, r889);
    out_cols[102u][row] = r1649;
    lookup_words[178u * row_count + row] = r1649;
    unsigned r3103 = stwo_m31_sub(r1831, r3102);
    unsigned r3104 = stwo_m31_sub(r1650, r918);
    out_cols[103u][row] = r1650;
    lookup_words[179u * row_count + row] = r1650;
    unsigned r3105 = stwo_m31_sub(r1842, r3104);
    unsigned r3106 = stwo_m31_sub(r1651, r947);
    out_cols[104u][row] = r1651;
    lookup_words[180u * row_count + row] = r1651;
    unsigned r3107 = stwo_m31_sub(r1856, r3106);
    unsigned r3108 = stwo_m31_sub(r1652, r976);
    out_cols[105u][row] = r1652;
    lookup_words[181u * row_count + row] = r1652;
    unsigned r3109 = stwo_m31_sub(r1873, r3108);
    unsigned r3110 = stwo_m31_sub(r1653, r1005);
    out_cols[106u][row] = r1653;
    lookup_words[182u * row_count + row] = r1653;
    unsigned r3111 = stwo_m31_sub(r1893, r3110);
    unsigned r3112 = stwo_m31_sub(r1654, r1034);
    out_cols[107u][row] = r1654;
    lookup_words[183u * row_count + row] = r1654;
    unsigned r3113 = stwo_m31_sub(r2116, r3112);
    unsigned r3114 = stwo_m31_sub(r1655, r1063);
    out_cols[108u][row] = r1655;
    lookup_words[184u * row_count + row] = r1655;
    unsigned r3115 = stwo_m31_sub(r2122, r3114);
    unsigned r3116 = stwo_m31_sub(r1656, r1092);
    out_cols[109u][row] = r1656;
    lookup_words[185u * row_count + row] = r1656;
    unsigned r3117 = stwo_m31_sub(r2130, r3116);
    unsigned r3118 = stwo_m31_sub(r1657, r1121);
    out_cols[110u][row] = r1657;
    lookup_words[186u * row_count + row] = r1657;
    unsigned r3119 = stwo_m31_sub(r2140, r3118);
    unsigned r3120 = stwo_m31_sub(r1658, r1150);
    out_cols[111u][row] = r1658;
    lookup_words[187u * row_count + row] = r1658;
    unsigned r3121 = stwo_m31_sub(r2152, r3120);
    unsigned r3122 = stwo_m31_sub(r1659, r1179);
    out_cols[112u][row] = r1659;
    lookup_words[188u * row_count + row] = r1659;
    unsigned r3123 = stwo_m31_sub(r2166, r3122);
    unsigned r3124 = stwo_m31_sub(r1660, r1208);
    out_cols[113u][row] = r1660;
    lookup_words[189u * row_count + row] = r1660;
    unsigned r3125 = stwo_m31_sub(r2181, r3124);
    unsigned r3126 = stwo_m31_sub(r1661, r1237);
    out_cols[114u][row] = r1661;
    lookup_words[190u * row_count + row] = r1661;
    unsigned r3127 = stwo_m31_sub(r3020, r3126);
    unsigned r3128 = stwo_m31_sub(r1662, r1266);
    out_cols[115u][row] = r1662;
    lookup_words[191u * row_count + row] = r1662;
    unsigned r3129 = stwo_m31_sub(r3023, r3128);
    unsigned r3130 = stwo_m31_sub(r1663, r1295);
    out_cols[116u][row] = r1663;
    lookup_words[192u * row_count + row] = r1663;
    unsigned r3131 = stwo_m31_sub(r3026, r3130);
    unsigned r3132 = stwo_m31_sub(r1664, r1324);
    out_cols[117u][row] = r1664;
    lookup_words[193u * row_count + row] = r1664;
    unsigned r3133 = stwo_m31_sub(r3029, r3132);
    unsigned r3134 = stwo_m31_sub(r1665, r1353);
    out_cols[118u][row] = r1665;
    lookup_words[194u * row_count + row] = r1665;
    unsigned r3135 = stwo_m31_sub(r3032, r3134);
    unsigned r3136 = stwo_m31_sub(r1666, r1382);
    out_cols[119u][row] = r1666;
    lookup_words[195u * row_count + row] = r1666;
    unsigned r3137 = stwo_m31_sub(r3035, r3136);
    unsigned r3138 = stwo_m31_sub(r1667, r1411);
    out_cols[120u][row] = r1667;
    lookup_words[196u * row_count + row] = r1667;
    unsigned r3139 = stwo_m31_sub(r3038, r3138);
    unsigned r3140 = stwo_m31_sub(r1668, r1440);
    out_cols[121u][row] = r1668;
    lookup_words[197u * row_count + row] = r1668;
    unsigned r3141 = stwo_m31_sub(r3041, r3140);
    unsigned r3142 = stwo_m31_sub(r1669, r1469);
    out_cols[122u][row] = r1669;
    lookup_words[198u * row_count + row] = r1669;
    unsigned r3143 = stwo_m31_sub(r3044, r3142);
    unsigned r3144 = stwo_m31_sub(r1670, r1498);
    out_cols[123u][row] = r1670;
    lookup_words[199u * row_count + row] = r1670;
    unsigned r3145 = stwo_m31_sub(r3047, r3144);
    unsigned r3146 = stwo_m31_sub(r1671, r1527);
    out_cols[124u][row] = r1671;
    lookup_words[200u * row_count + row] = r1671;
    unsigned r3147 = stwo_m31_sub(r3050, r3146);
    unsigned r3148 = stwo_m31_sub(r1672, r1556);
    out_cols[125u][row] = r1672;
    lookup_words[201u * row_count + row] = r1672;
    unsigned r3149 = stwo_m31_sub(r3053, r3148);
    unsigned r3150 = stwo_m31_sub(r1673, r1585);
    out_cols[126u][row] = r1673;
    lookup_words[202u * row_count + row] = r1673;
    unsigned r3151 = stwo_m31_sub(r3056, r3150);
    unsigned r3152 = stwo_m31_sub(r1674, r1614);
    out_cols[127u][row] = r1674;
    lookup_words[203u * row_count + row] = r1674;
    unsigned r3153 = stwo_m31_sub(r3058, r3152);
    unsigned r3154 = stwo_m31_mul(r5, r3099);
    unsigned r3155 = stwo_m31_mul(r3, r3141);
    unsigned r3156 = stwo_m31_sub(r3154, r3155);
    unsigned r3157 = stwo_m31_mul(r4, r2463);
    unsigned r3158 = stwo_m31_add(r3156, r3157);
    unsigned r3159 = stwo_m31_mul(r5, r3101);
    unsigned r3160 = stwo_m31_add(r3099, r3159);
    unsigned r3161 = stwo_m31_mul(r3, r3143);
    unsigned r3162 = stwo_m31_sub(r3160, r3161);
    unsigned r3163 = stwo_m31_mul(r4, r2477);
    unsigned r3164 = stwo_m31_add(r3162, r3163);
    unsigned r3165 = stwo_m31_mul(r5, r3103);
    unsigned r3166 = stwo_m31_add(r3101, r3165);
    unsigned r3167 = stwo_m31_mul(r3, r3145);
    unsigned r3168 = stwo_m31_sub(r3166, r3167);
    unsigned r3169 = stwo_m31_mul(r4, r2488);
    unsigned r3170 = stwo_m31_add(r3168, r3169);
    unsigned r3171 = stwo_m31_mul(r5, r3105);
    unsigned r3172 = stwo_m31_add(r3103, r3171);
    unsigned r3173 = stwo_m31_mul(r3, r3147);
    unsigned r3174 = stwo_m31_sub(r3172, r3173);
    unsigned r3175 = stwo_m31_mul(r4, r2496);
    unsigned r3176 = stwo_m31_add(r3174, r3175);
    unsigned r3177 = stwo_m31_mul(r5, r3107);
    unsigned r3178 = stwo_m31_add(r3105, r3177);
    unsigned r3179 = stwo_m31_mul(r3, r3149);
    unsigned r3180 = stwo_m31_sub(r3178, r3179);
    unsigned r3181 = stwo_m31_mul(r4, r2501);
    unsigned r3182 = stwo_m31_add(r3180, r3181);
    unsigned r3183 = stwo_m31_mul(r5, r3109);
    unsigned r3184 = stwo_m31_add(r3107, r3183);
    unsigned r3185 = stwo_m31_mul(r3, r3151);
    unsigned r3186 = stwo_m31_sub(r3184, r3185);
    unsigned r3187 = stwo_m31_mul(r4, r2503);
    unsigned r3188 = stwo_m31_add(r3186, r3187);
    unsigned r3189 = stwo_m31_mul(r5, r3111);
    unsigned r3190 = stwo_m31_add(r3109, r3189);
    unsigned r3191 = stwo_m31_mul(r3, r3153);
    unsigned r3192 = stwo_m31_sub(r3190, r3191);
    unsigned r3193 = stwo_m31_mul(r2, r3099);
    unsigned r3194 = stwo_m31_add(r3193, r3111);
    unsigned r3195 = stwo_m31_mul(r5, r3113);
    unsigned r3196 = stwo_m31_add(r3194, r3195);
    unsigned r3197 = stwo_m31_mul(r3, r3061);
    unsigned r3198 = stwo_m31_sub(r3196, r3197);
    unsigned r3199 = stwo_m31_mul(r2, r3101);
    unsigned r3200 = stwo_m31_add(r3199, r3113);
    unsigned r3201 = stwo_m31_mul(r5, r3115);
    unsigned r3202 = stwo_m31_add(r3200, r3201);
    unsigned r3203 = stwo_m31_mul(r3, r3064);
    unsigned r3204 = stwo_m31_sub(r3202, r3203);
    unsigned r3205 = stwo_m31_mul(r2, r3103);
    unsigned r3206 = stwo_m31_add(r3205, r3115);
    unsigned r3207 = stwo_m31_mul(r5, r3117);
    unsigned r3208 = stwo_m31_add(r3206, r3207);
    unsigned r3209 = stwo_m31_mul(r3, r3067);
    unsigned r3210 = stwo_m31_sub(r3208, r3209);
    unsigned r3211 = stwo_m31_mul(r2, r3105);
    unsigned r3212 = stwo_m31_add(r3211, r3117);
    unsigned r3213 = stwo_m31_mul(r5, r3119);
    unsigned r3214 = stwo_m31_add(r3212, r3213);
    unsigned r3215 = stwo_m31_mul(r3, r3070);
    unsigned r3216 = stwo_m31_sub(r3214, r3215);
    unsigned r3217 = stwo_m31_mul(r2, r3107);
    unsigned r3218 = stwo_m31_add(r3217, r3119);
    unsigned r3219 = stwo_m31_mul(r5, r3121);
    unsigned r3220 = stwo_m31_add(r3218, r3219);
    unsigned r3221 = stwo_m31_mul(r3, r3073);
    unsigned r3222 = stwo_m31_sub(r3220, r3221);
    unsigned r3223 = stwo_m31_mul(r2, r3109);
    unsigned r3224 = stwo_m31_add(r3223, r3121);
    unsigned r3225 = stwo_m31_mul(r5, r3123);
    unsigned r3226 = stwo_m31_add(r3224, r3225);
    unsigned r3227 = stwo_m31_mul(r3, r3076);
    unsigned r3228 = stwo_m31_sub(r3226, r3227);
    unsigned r3229 = stwo_m31_mul(r2, r3111);
    unsigned r3230 = stwo_m31_add(r3229, r3123);
    unsigned r3231 = stwo_m31_mul(r5, r3125);
    unsigned r3232 = stwo_m31_add(r3230, r3231);
    unsigned r3233 = stwo_m31_mul(r3, r3079);
    unsigned r3234 = stwo_m31_sub(r3232, r3233);
    unsigned r3235 = stwo_m31_mul(r2, r3113);
    unsigned r3236 = stwo_m31_add(r3235, r3125);
    unsigned r3237 = stwo_m31_mul(r5, r3127);
    unsigned r3238 = stwo_m31_add(r3236, r3237);
    unsigned r3239 = stwo_m31_mul(r3, r3082);
    unsigned r3240 = stwo_m31_sub(r3238, r3239);
    unsigned r3241 = stwo_m31_mul(r2, r3115);
    unsigned r3242 = stwo_m31_add(r3241, r3127);
    unsigned r3243 = stwo_m31_mul(r5, r3129);
    unsigned r3244 = stwo_m31_add(r3242, r3243);
    unsigned r3245 = stwo_m31_mul(r3, r3085);
    unsigned r3246 = stwo_m31_sub(r3244, r3245);
    unsigned r3247 = stwo_m31_mul(r2, r3117);
    unsigned r3248 = stwo_m31_add(r3247, r3129);
    unsigned r3249 = stwo_m31_mul(r5, r3131);
    unsigned r3250 = stwo_m31_add(r3248, r3249);
    unsigned r3251 = stwo_m31_mul(r3, r3088);
    unsigned r3252 = stwo_m31_sub(r3250, r3251);
    unsigned r3253 = stwo_m31_mul(r2, r3119);
    unsigned r3254 = stwo_m31_add(r3253, r3131);
    unsigned r3255 = stwo_m31_mul(r5, r3133);
    unsigned r3256 = stwo_m31_add(r3254, r3255);
    unsigned r3257 = stwo_m31_mul(r3, r3091);
    unsigned r3258 = stwo_m31_sub(r3256, r3257);
    unsigned r3259 = stwo_m31_mul(r2, r3121);
    unsigned r3260 = stwo_m31_add(r3259, r3133);
    unsigned r3261 = stwo_m31_mul(r5, r3135);
    unsigned r3262 = stwo_m31_add(r3260, r3261);
    unsigned r3263 = stwo_m31_mul(r3, r3094);
    unsigned r3264 = stwo_m31_sub(r3262, r3263);
    unsigned r3265 = stwo_m31_mul(r2, r3123);
    unsigned r3266 = stwo_m31_add(r3265, r3135);
    unsigned r3267 = stwo_m31_mul(r5, r3137);
    unsigned r3268 = stwo_m31_add(r3266, r3267);
    unsigned r3269 = stwo_m31_mul(r3, r3097);
    unsigned r3270 = stwo_m31_sub(r3268, r3269);
    unsigned r3271 = stwo_m31_mul(r2, r3125);
    unsigned r3272 = stwo_m31_add(r3271, r3137);
    unsigned r3273 = stwo_m31_mul(r5, r3139);
    unsigned r3274 = stwo_m31_add(r3272, r3273);
    unsigned r3275 = stwo_m31_mul(r3, r2600);
    unsigned r3276 = stwo_m31_sub(r3274, r3275);
    unsigned r3277 = stwo_m31_mul(r2, r3127);
    unsigned r3278 = stwo_m31_add(r3277, r3139);
    unsigned r3279 = stwo_m31_mul(r3, r2614);
    unsigned r3280 = stwo_m31_sub(r3278, r3279);
    unsigned r3281 = stwo_m31_mul(r6, r2463);
    unsigned r3282 = stwo_m31_add(r3280, r3281);
    unsigned r3283 = stwo_m31_mul(r2, r3129);
    unsigned r3284 = stwo_m31_mul(r3, r2626);
    unsigned r3285 = stwo_m31_sub(r3283, r3284);
    unsigned r3286 = stwo_m31_mul(r2, r2463);
    unsigned r3287 = stwo_m31_add(r3285, r3286);
    unsigned r3288 = stwo_m31_mul(r6, r2477);
    unsigned r3289 = stwo_m31_add(r3287, r3288);
    unsigned r3290 = stwo_m31_mul(r2, r3131);
    unsigned r3291 = stwo_m31_mul(r3, r2636);
    unsigned r3292 = stwo_m31_sub(r3290, r3291);
    unsigned r3293 = stwo_m31_mul(r2, r2477);
    unsigned r3294 = stwo_m31_add(r3292, r3293);
    unsigned r3295 = stwo_m31_mul(r6, r2488);
    unsigned r3296 = stwo_m31_add(r3294, r3295);
    unsigned r3297 = stwo_m31_mul(r2, r3133);
    unsigned r3298 = stwo_m31_mul(r3, r2644);
    unsigned r3299 = stwo_m31_sub(r3297, r3298);
    unsigned r3300 = stwo_m31_mul(r2, r2488);
    unsigned r3301 = stwo_m31_add(r3299, r3300);
    unsigned r3302 = stwo_m31_mul(r6, r2496);
    unsigned r3303 = stwo_m31_add(r3301, r3302);
    unsigned r3304 = stwo_m31_mul(r2, r3135);
    unsigned r3305 = stwo_m31_mul(r3, r2650);
    unsigned r3306 = stwo_m31_sub(r3304, r3305);
    unsigned r3307 = stwo_m31_mul(r2, r2496);
    unsigned r3308 = stwo_m31_add(r3306, r3307);
    unsigned r3309 = stwo_m31_mul(r6, r2501);
    unsigned r3310 = stwo_m31_add(r3308, r3309);
    unsigned r3311 = stwo_m31_mul(r2, r3137);
    unsigned r3312 = stwo_m31_mul(r3, r2654);
    unsigned r3313 = stwo_m31_sub(r3311, r3312);
    unsigned r3314 = stwo_m31_mul(r2, r2501);
    unsigned r3315 = stwo_m31_add(r3313, r3314);
    unsigned r3316 = stwo_m31_mul(r6, r2503);
    unsigned r3317 = stwo_m31_add(r3315, r3316);
    unsigned r3318 = stwo_m31_mul(r2, r3139);
    unsigned r3319 = stwo_m31_mul(r3, r2446);
    unsigned r3320 = stwo_m31_sub(r3318, r3319);
    unsigned r3321 = stwo_m31_mul(r2, r2503);
    unsigned r3322 = stwo_m31_add(r3320, r3321);
    unsigned r3323 = stwo_m31_add(r3158, r12);
    unsigned r3324 = stwo_m31_add(r3164, r12);
    unsigned r3325 = (r3324 & 511u);
    unsigned r3326 = (r3325 << 9u);
    unsigned r3327 = (r3323 + r3326);
    unsigned r3328 = 131072u;
    unsigned r3329 = (r3327 + r3328);
    unsigned r3330 = (r3329 & 262143u);
    unsigned r3331 = (r3330 & 65535u);
    unsigned r3332 = (r3331 % STWO_M31_P);
    unsigned r3333 = (r3330 >> 16u);
    unsigned r3334 = (r3333 % STWO_M31_P);
    unsigned r3335 = stwo_m31_sub(r3334, r2);
    unsigned r3336 = stwo_m31_mul(r3335, r8);
    unsigned r3337 = stwo_m31_add(r3332, r3336);
    unsigned r3338 = stwo_m31_add(r3337, r10);
    sub_words[85u * row_count + row] = r3338;
    unsigned r3339 = stwo_m31_add(r3337, r10);
    lookup_words[205u * row_count + row] = r3339;
    unsigned r3340 = stwo_m31_sub(r3158, r3337);
    unsigned r3341 = stwo_m31_mul(r3340, r11);
    unsigned r3342 = stwo_m31_add(r3341, r10);
    sub_words[97u * row_count + row] = r3342;
    unsigned r3343 = stwo_m31_add(r3341, r10);
    lookup_words[229u * row_count + row] = r3343;
    unsigned r3344 = stwo_m31_add(r3164, r3341);
    out_cols[157u][row] = r3341;
    unsigned r3345 = stwo_m31_mul(r3344, r11);
    unsigned r3346 = stwo_m31_add(r3345, r10);
    sub_words[109u * row_count + row] = r3346;
    unsigned r3347 = stwo_m31_add(r3345, r10);
    lookup_words[253u * row_count + row] = r3347;
    unsigned r3348 = stwo_m31_add(r3170, r3345);
    out_cols[158u][row] = r3345;
    unsigned r3349 = stwo_m31_mul(r3348, r11);
    unsigned r3350 = stwo_m31_add(r3349, r10);
    sub_words[121u * row_count + row] = r3350;
    unsigned r3351 = stwo_m31_add(r3349, r10);
    lookup_words[277u * row_count + row] = r3351;
    unsigned r3352 = stwo_m31_add(r3176, r3349);
    out_cols[159u][row] = r3349;
    unsigned r3353 = stwo_m31_mul(r3352, r11);
    unsigned r3354 = stwo_m31_add(r3353, r10);
    sub_words[133u * row_count + row] = r3354;
    unsigned r3355 = stwo_m31_add(r3353, r10);
    lookup_words[301u * row_count + row] = r3355;
    unsigned r3356 = stwo_m31_add(r3182, r3353);
    out_cols[160u][row] = r3353;
    unsigned r3357 = stwo_m31_mul(r3356, r11);
    unsigned r3358 = stwo_m31_add(r3357, r10);
    sub_words[142u * row_count + row] = r3358;
    unsigned r3359 = stwo_m31_add(r3357, r10);
    lookup_words[319u * row_count + row] = r3359;
    unsigned r3360 = stwo_m31_add(r3188, r3357);
    out_cols[161u][row] = r3357;
    unsigned r3361 = stwo_m31_mul(r3360, r11);
    unsigned r3362 = stwo_m31_add(r3361, r10);
    sub_words[151u * row_count + row] = r3362;
    unsigned r3363 = stwo_m31_add(r3361, r10);
    lookup_words[337u * row_count + row] = r3363;
    unsigned r3364 = stwo_m31_add(r3192, r3361);
    out_cols[162u][row] = r3361;
    unsigned r3365 = stwo_m31_mul(r3364, r11);
    unsigned r3366 = stwo_m31_add(r3365, r10);
    sub_words[160u * row_count + row] = r3366;
    unsigned r3367 = stwo_m31_add(r3365, r10);
    lookup_words[355u * row_count + row] = r3367;
    unsigned r3368 = stwo_m31_add(r3198, r3365);
    out_cols[163u][row] = r3365;
    unsigned r3369 = stwo_m31_mul(r3368, r11);
    unsigned r3370 = stwo_m31_add(r3369, r10);
    sub_words[86u * row_count + row] = r3370;
    unsigned r3371 = stwo_m31_add(r3369, r10);
    lookup_words[207u * row_count + row] = r3371;
    unsigned r3372 = stwo_m31_add(r3204, r3369);
    out_cols[164u][row] = r3369;
    unsigned r3373 = stwo_m31_mul(r3372, r11);
    unsigned r3374 = stwo_m31_add(r3373, r10);
    sub_words[98u * row_count + row] = r3374;
    unsigned r3375 = stwo_m31_add(r3373, r10);
    lookup_words[231u * row_count + row] = r3375;
    unsigned r3376 = stwo_m31_add(r3210, r3373);
    out_cols[165u][row] = r3373;
    unsigned r3377 = stwo_m31_mul(r3376, r11);
    unsigned r3378 = stwo_m31_add(r3377, r10);
    sub_words[110u * row_count + row] = r3378;
    unsigned r3379 = stwo_m31_add(r3377, r10);
    lookup_words[255u * row_count + row] = r3379;
    unsigned r3380 = stwo_m31_add(r3216, r3377);
    out_cols[166u][row] = r3377;
    unsigned r3381 = stwo_m31_mul(r3380, r11);
    unsigned r3382 = stwo_m31_add(r3381, r10);
    sub_words[122u * row_count + row] = r3382;
    unsigned r3383 = stwo_m31_add(r3381, r10);
    lookup_words[279u * row_count + row] = r3383;
    unsigned r3384 = stwo_m31_add(r3222, r3381);
    out_cols[167u][row] = r3381;
    unsigned r3385 = stwo_m31_mul(r3384, r11);
    unsigned r3386 = stwo_m31_add(r3385, r10);
    sub_words[134u * row_count + row] = r3386;
    unsigned r3387 = stwo_m31_add(r3385, r10);
    lookup_words[303u * row_count + row] = r3387;
    unsigned r3388 = stwo_m31_add(r3228, r3385);
    out_cols[168u][row] = r3385;
    unsigned r3389 = stwo_m31_mul(r3388, r11);
    unsigned r3390 = stwo_m31_add(r3389, r10);
    sub_words[143u * row_count + row] = r3390;
    unsigned r3391 = stwo_m31_add(r3389, r10);
    lookup_words[321u * row_count + row] = r3391;
    unsigned r3392 = stwo_m31_add(r3234, r3389);
    out_cols[169u][row] = r3389;
    unsigned r3393 = stwo_m31_mul(r3392, r11);
    unsigned r3394 = stwo_m31_add(r3393, r10);
    sub_words[152u * row_count + row] = r3394;
    unsigned r3395 = stwo_m31_add(r3393, r10);
    lookup_words[339u * row_count + row] = r3395;
    unsigned r3396 = stwo_m31_add(r3240, r3393);
    out_cols[170u][row] = r3393;
    unsigned r3397 = stwo_m31_mul(r3396, r11);
    unsigned r3398 = stwo_m31_add(r3397, r10);
    sub_words[161u * row_count + row] = r3398;
    unsigned r3399 = stwo_m31_add(r3397, r10);
    lookup_words[357u * row_count + row] = r3399;
    unsigned r3400 = stwo_m31_add(r3246, r3397);
    out_cols[171u][row] = r3397;
    unsigned r3401 = stwo_m31_mul(r3400, r11);
    unsigned r3402 = stwo_m31_add(r3401, r10);
    sub_words[87u * row_count + row] = r3402;
    unsigned r3403 = stwo_m31_add(r3401, r10);
    lookup_words[209u * row_count + row] = r3403;
    unsigned r3404 = stwo_m31_add(r3252, r3401);
    out_cols[172u][row] = r3401;
    unsigned r3405 = stwo_m31_mul(r3404, r11);
    unsigned r3406 = stwo_m31_add(r3405, r10);
    sub_words[99u * row_count + row] = r3406;
    unsigned r3407 = stwo_m31_add(r3405, r10);
    lookup_words[233u * row_count + row] = r3407;
    unsigned r3408 = stwo_m31_add(r3258, r3405);
    out_cols[173u][row] = r3405;
    unsigned r3409 = stwo_m31_mul(r3408, r11);
    unsigned r3410 = stwo_m31_add(r3409, r10);
    sub_words[111u * row_count + row] = r3410;
    unsigned r3411 = stwo_m31_add(r3409, r10);
    lookup_words[257u * row_count + row] = r3411;
    unsigned r3412 = stwo_m31_add(r3264, r3409);
    out_cols[174u][row] = r3409;
    unsigned r3413 = stwo_m31_mul(r3412, r11);
    unsigned r3414 = stwo_m31_add(r3413, r10);
    sub_words[123u * row_count + row] = r3414;
    unsigned r3415 = stwo_m31_add(r3413, r10);
    lookup_words[281u * row_count + row] = r3415;
    unsigned r3416 = stwo_m31_add(r3270, r3413);
    out_cols[175u][row] = r3413;
    unsigned r3417 = stwo_m31_mul(r3416, r11);
    unsigned r3418 = stwo_m31_add(r3417, r10);
    sub_words[135u * row_count + row] = r3418;
    unsigned r3419 = stwo_m31_add(r3417, r10);
    lookup_words[305u * row_count + row] = r3419;
    unsigned r3420 = stwo_m31_add(r3276, r3417);
    out_cols[176u][row] = r3417;
    unsigned r3421 = stwo_m31_mul(r3420, r11);
    unsigned r3422 = stwo_m31_add(r3421, r10);
    sub_words[144u * row_count + row] = r3422;
    unsigned r3423 = stwo_m31_add(r3421, r10);
    lookup_words[323u * row_count + row] = r3423;
    unsigned r3424 = stwo_m31_mul(r7, r3337);
    out_cols[156u][row] = r3337;
    unsigned r3425 = stwo_m31_sub(r3282, r3424);
    unsigned r3426 = stwo_m31_add(r3425, r3421);
    out_cols[177u][row] = r3421;
    unsigned r3427 = stwo_m31_mul(r3426, r11);
    unsigned r3428 = stwo_m31_add(r3427, r10);
    sub_words[153u * row_count + row] = r3428;
    unsigned r3429 = stwo_m31_add(r3427, r10);
    lookup_words[341u * row_count + row] = r3429;
    unsigned r3430 = stwo_m31_add(r3289, r3427);
    out_cols[178u][row] = r3427;
    unsigned r3431 = stwo_m31_mul(r3430, r11);
    unsigned r3432 = stwo_m31_add(r3431, r10);
    sub_words[162u * row_count + row] = r3432;
    unsigned r3433 = stwo_m31_add(r3431, r10);
    lookup_words[359u * row_count + row] = r3433;
    unsigned r3434 = stwo_m31_add(r3296, r3431);
    out_cols[179u][row] = r3431;
    unsigned r3435 = stwo_m31_mul(r3434, r11);
    unsigned r3436 = stwo_m31_add(r3435, r10);
    sub_words[88u * row_count + row] = r3436;
    unsigned r3437 = stwo_m31_add(r3435, r10);
    lookup_words[211u * row_count + row] = r3437;
    unsigned r3438 = stwo_m31_add(r3303, r3435);
    out_cols[180u][row] = r3435;
    unsigned r3439 = stwo_m31_mul(r3438, r11);
    unsigned r3440 = stwo_m31_add(r3439, r10);
    sub_words[100u * row_count + row] = r3440;
    unsigned r3441 = stwo_m31_add(r3439, r10);
    lookup_words[235u * row_count + row] = r3441;
    unsigned r3442 = stwo_m31_add(r3310, r3439);
    out_cols[181u][row] = r3439;
    unsigned r3443 = stwo_m31_mul(r3442, r11);
    unsigned r3444 = stwo_m31_add(r3443, r10);
    sub_words[112u * row_count + row] = r3444;
    unsigned r3445 = stwo_m31_add(r3443, r10);
    lookup_words[259u * row_count + row] = r3445;
    unsigned r3446 = stwo_m31_add(r3317, r3443);
    out_cols[182u][row] = r3443;
    unsigned r3447 = stwo_m31_mul(r3446, r11);
    unsigned r3448 = stwo_m31_add(r3447, r10);
    sub_words[124u * row_count + row] = r3448;
    unsigned r3449 = stwo_m31_add(r3447, r10);
    out_cols[183u][row] = r3447;
    lookup_words[283u * row_count + row] = r3449;
    const unsigned dargs4[56] = { r1789, r1790, r1791, r1792, r1793, r1794, r1795, r1796, r1797, r1798, r1799, r1800, r1801, r1802, r1803, r1804, r1805, r1806, r1807, r1808, r1809, r1810, r1811, r1812, r1813, r1814, r1815, r1816, r1789, r1790, r1791, r1792, r1793, r1794, r1795, r1796, r1797, r1798, r1799, r1800, r1801, r1802, r1803, r1804, r1805, r1806, r1807, r1808, r1809, r1810, r1811, r1812, r1813, r1814, r1815, r1816 };
    unsigned douts4[28];
    stwo_wit_deduce_felt_mul(dargs4, douts4);
    unsigned r3450 = douts4[0];
    unsigned r3451 = douts4[1];
    unsigned r3452 = douts4[2];
    unsigned r3453 = douts4[3];
    unsigned r3454 = douts4[4];
    unsigned r3455 = douts4[5];
    unsigned r3456 = douts4[6];
    unsigned r3457 = douts4[7];
    unsigned r3458 = douts4[8];
    unsigned r3459 = douts4[9];
    unsigned r3460 = douts4[10];
    unsigned r3461 = douts4[11];
    unsigned r3462 = douts4[12];
    unsigned r3463 = douts4[13];
    unsigned r3464 = douts4[14];
    unsigned r3465 = douts4[15];
    unsigned r3466 = douts4[16];
    unsigned r3467 = douts4[17];
    unsigned r3468 = douts4[18];
    unsigned r3469 = douts4[19];
    unsigned r3470 = douts4[20];
    unsigned r3471 = douts4[21];
    unsigned r3472 = douts4[22];
    unsigned r3473 = douts4[23];
    unsigned r3474 = douts4[24];
    unsigned r3475 = douts4[25];
    unsigned r3476 = douts4[26];
    unsigned r3477 = douts4[27];
    unsigned r3478 = input_cols[16u][row];
    unsigned r3479 = input_cols[17u][row];
    unsigned r3480 = input_cols[18u][row];
    unsigned r3481 = input_cols[19u][row];
    unsigned r3482 = input_cols[20u][row];
    unsigned r3483 = input_cols[21u][row];
    unsigned r3484 = input_cols[22u][row];
    unsigned r3485 = input_cols[23u][row];
    unsigned r3486 = input_cols[24u][row];
    unsigned r3487 = input_cols[25u][row];
    unsigned r3488 = input_cols[26u][row];
    unsigned r3489 = input_cols[27u][row];
    unsigned r3490 = input_cols[28u][row];
    unsigned r3491 = input_cols[29u][row];
    unsigned r3492 = input_cols[30u][row];
    unsigned r3493 = input_cols[31u][row];
    unsigned r3494 = input_cols[32u][row];
    unsigned r3495 = input_cols[33u][row];
    unsigned r3496 = input_cols[34u][row];
    unsigned r3497 = input_cols[35u][row];
    unsigned r3498 = input_cols[36u][row];
    unsigned r3499 = input_cols[37u][row];
    unsigned r3500 = input_cols[38u][row];
    unsigned r3501 = input_cols[39u][row];
    unsigned r3502 = input_cols[40u][row];
    unsigned r3503 = input_cols[41u][row];
    unsigned r3504 = input_cols[42u][row];
    unsigned r3505 = input_cols[43u][row];
    const unsigned dargs5[56] = { r3450, r3451, r3452, r3453, r3454, r3455, r3456, r3457, r3458, r3459, r3460, r3461, r3462, r3463, r3464, r3465, r3466, r3467, r3468, r3469, r3470, r3471, r3472, r3473, r3474, r3475, r3476, r3477, r3478, r3479, r3480, r3481, r3482, r3483, r3484, r3485, r3486, r3487, r3488, r3489, r3490, r3491, r3492, r3493, r3494, r3495, r3496, r3497, r3498, r3499, r3500, r3501, r3502, r3503, r3504, r3505 };
    unsigned douts5[28];
    stwo_wit_deduce_felt_sub(dargs5, douts5);
    unsigned r3506 = douts5[0];
    unsigned r3507 = douts5[1];
    unsigned r3508 = douts5[2];
    unsigned r3509 = douts5[3];
    unsigned r3510 = douts5[4];
    unsigned r3511 = douts5[5];
    unsigned r3512 = douts5[6];
    unsigned r3513 = douts5[7];
    unsigned r3514 = douts5[8];
    unsigned r3515 = douts5[9];
    unsigned r3516 = douts5[10];
    unsigned r3517 = douts5[11];
    unsigned r3518 = douts5[12];
    unsigned r3519 = douts5[13];
    unsigned r3520 = douts5[14];
    unsigned r3521 = douts5[15];
    unsigned r3522 = douts5[16];
    unsigned r3523 = douts5[17];
    unsigned r3524 = douts5[18];
    unsigned r3525 = douts5[19];
    unsigned r3526 = douts5[20];
    unsigned r3527 = douts5[21];
    unsigned r3528 = douts5[22];
    unsigned r3529 = douts5[23];
    unsigned r3530 = douts5[24];
    unsigned r3531 = douts5[25];
    unsigned r3532 = douts5[26];
    unsigned r3533 = douts5[27];
    const unsigned dargs6[56] = { r3506, r3507, r3508, r3509, r3510, r3511, r3512, r3513, r3514, r3515, r3516, r3517, r3518, r3519, r3520, r3521, r3522, r3523, r3524, r3525, r3526, r3527, r3528, r3529, r3530, r3531, r3532, r3533, r1619, r1620, r1621, r1622, r1623, r1624, r1625, r1626, r1627, r1628, r1629, r1630, r1631, r1632, r1633, r1634, r1635, r1636, r1637, r1638, r1639, r1640, r1641, r1642, r1643, r1644, r1645, r1646 };
    unsigned douts6[28];
    stwo_wit_deduce_felt_sub(dargs6, douts6);
    unsigned r3534 = douts6[0];
    unsigned r3535 = douts6[1];
    unsigned r3536 = douts6[2];
    unsigned r3537 = douts6[3];
    unsigned r3538 = douts6[4];
    unsigned r3539 = douts6[5];
    unsigned r3540 = douts6[6];
    unsigned r3541 = douts6[7];
    unsigned r3542 = douts6[8];
    unsigned r3543 = douts6[9];
    unsigned r3544 = douts6[10];
    unsigned r3545 = douts6[11];
    unsigned r3546 = douts6[12];
    unsigned r3547 = douts6[13];
    unsigned r3548 = douts6[14];
    unsigned r3549 = douts6[15];
    unsigned r3550 = douts6[16];
    unsigned r3551 = douts6[17];
    unsigned r3552 = douts6[18];
    unsigned r3553 = douts6[19];
    unsigned r3554 = douts6[20];
    unsigned r3555 = douts6[21];
    unsigned r3556 = douts6[22];
    unsigned r3557 = douts6[23];
    unsigned r3558 = douts6[24];
    unsigned r3559 = douts6[25];
    unsigned r3560 = douts6[26];
    unsigned r3561 = douts6[27];
    unsigned r3562 = stwo_m31_mul(r1789, r1789);
    unsigned r3563 = stwo_m31_mul(r1789, r1790);
    unsigned r3564 = stwo_m31_mul(r1790, r1789);
    unsigned r3565 = stwo_m31_add(r3563, r3564);
    unsigned r3566 = stwo_m31_mul(r1789, r1791);
    unsigned r3567 = stwo_m31_mul(r1790, r1790);
    unsigned r3568 = stwo_m31_add(r3566, r3567);
    unsigned r3569 = stwo_m31_mul(r1791, r1789);
    unsigned r3570 = stwo_m31_add(r3568, r3569);
    unsigned r3571 = stwo_m31_mul(r1789, r1792);
    unsigned r3572 = stwo_m31_mul(r1790, r1791);
    unsigned r3573 = stwo_m31_add(r3571, r3572);
    unsigned r3574 = stwo_m31_mul(r1791, r1790);
    unsigned r3575 = stwo_m31_add(r3573, r3574);
    unsigned r3576 = stwo_m31_mul(r1792, r1789);
    unsigned r3577 = stwo_m31_add(r3575, r3576);
    unsigned r3578 = stwo_m31_mul(r1789, r1793);
    unsigned r3579 = stwo_m31_mul(r1790, r1792);
    unsigned r3580 = stwo_m31_add(r3578, r3579);
    unsigned r3581 = stwo_m31_mul(r1791, r1791);
    unsigned r3582 = stwo_m31_add(r3580, r3581);
    unsigned r3583 = stwo_m31_mul(r1792, r1790);
    unsigned r3584 = stwo_m31_add(r3582, r3583);
    unsigned r3585 = stwo_m31_mul(r1793, r1789);
    unsigned r3586 = stwo_m31_add(r3584, r3585);
    unsigned r3587 = stwo_m31_mul(r1789, r1794);
    unsigned r3588 = stwo_m31_mul(r1790, r1793);
    unsigned r3589 = stwo_m31_add(r3587, r3588);
    unsigned r3590 = stwo_m31_mul(r1791, r1792);
    unsigned r3591 = stwo_m31_add(r3589, r3590);
    unsigned r3592 = stwo_m31_mul(r1792, r1791);
    unsigned r3593 = stwo_m31_add(r3591, r3592);
    unsigned r3594 = stwo_m31_mul(r1793, r1790);
    unsigned r3595 = stwo_m31_add(r3593, r3594);
    unsigned r3596 = stwo_m31_mul(r1794, r1789);
    unsigned r3597 = stwo_m31_add(r3595, r3596);
    unsigned r3598 = stwo_m31_mul(r1789, r1795);
    unsigned r3599 = stwo_m31_mul(r1790, r1794);
    unsigned r3600 = stwo_m31_add(r3598, r3599);
    unsigned r3601 = stwo_m31_mul(r1791, r1793);
    unsigned r3602 = stwo_m31_add(r3600, r3601);
    unsigned r3603 = stwo_m31_mul(r1792, r1792);
    unsigned r3604 = stwo_m31_add(r3602, r3603);
    unsigned r3605 = stwo_m31_mul(r1793, r1791);
    unsigned r3606 = stwo_m31_add(r3604, r3605);
    unsigned r3607 = stwo_m31_mul(r1794, r1790);
    unsigned r3608 = stwo_m31_add(r3606, r3607);
    unsigned r3609 = stwo_m31_mul(r1795, r1789);
    unsigned r3610 = stwo_m31_add(r3608, r3609);
    unsigned r3611 = stwo_m31_mul(r1790, r1795);
    unsigned r3612 = stwo_m31_mul(r1791, r1794);
    unsigned r3613 = stwo_m31_add(r3611, r3612);
    unsigned r3614 = stwo_m31_mul(r1792, r1793);
    unsigned r3615 = stwo_m31_add(r3613, r3614);
    unsigned r3616 = stwo_m31_mul(r1793, r1792);
    unsigned r3617 = stwo_m31_add(r3615, r3616);
    unsigned r3618 = stwo_m31_mul(r1794, r1791);
    unsigned r3619 = stwo_m31_add(r3617, r3618);
    unsigned r3620 = stwo_m31_mul(r1795, r1790);
    unsigned r3621 = stwo_m31_add(r3619, r3620);
    unsigned r3622 = stwo_m31_mul(r1791, r1795);
    unsigned r3623 = stwo_m31_mul(r1792, r1794);
    unsigned r3624 = stwo_m31_add(r3622, r3623);
    unsigned r3625 = stwo_m31_mul(r1793, r1793);
    unsigned r3626 = stwo_m31_add(r3624, r3625);
    unsigned r3627 = stwo_m31_mul(r1794, r1792);
    unsigned r3628 = stwo_m31_add(r3626, r3627);
    unsigned r3629 = stwo_m31_mul(r1795, r1791);
    unsigned r3630 = stwo_m31_add(r3628, r3629);
    unsigned r3631 = stwo_m31_mul(r1792, r1795);
    unsigned r3632 = stwo_m31_mul(r1793, r1794);
    unsigned r3633 = stwo_m31_add(r3631, r3632);
    unsigned r3634 = stwo_m31_mul(r1794, r1793);
    unsigned r3635 = stwo_m31_add(r3633, r3634);
    unsigned r3636 = stwo_m31_mul(r1795, r1792);
    unsigned r3637 = stwo_m31_add(r3635, r3636);
    unsigned r3638 = stwo_m31_mul(r1793, r1795);
    unsigned r3639 = stwo_m31_mul(r1794, r1794);
    unsigned r3640 = stwo_m31_add(r3638, r3639);
    unsigned r3641 = stwo_m31_mul(r1795, r1793);
    unsigned r3642 = stwo_m31_add(r3640, r3641);
    unsigned r3643 = stwo_m31_mul(r1794, r1795);
    unsigned r3644 = stwo_m31_mul(r1795, r1794);
    unsigned r3645 = stwo_m31_add(r3643, r3644);
    unsigned r3646 = stwo_m31_mul(r1795, r1795);
    unsigned r3647 = stwo_m31_mul(r1796, r1796);
    unsigned r3648 = stwo_m31_mul(r1796, r1797);
    unsigned r3649 = stwo_m31_mul(r1797, r1796);
    unsigned r3650 = stwo_m31_add(r3648, r3649);
    unsigned r3651 = stwo_m31_mul(r1796, r1798);
    unsigned r3652 = stwo_m31_mul(r1797, r1797);
    unsigned r3653 = stwo_m31_add(r3651, r3652);
    unsigned r3654 = stwo_m31_mul(r1798, r1796);
    unsigned r3655 = stwo_m31_add(r3653, r3654);
    unsigned r3656 = stwo_m31_mul(r1796, r1799);
    unsigned r3657 = stwo_m31_mul(r1797, r1798);
    unsigned r3658 = stwo_m31_add(r3656, r3657);
    unsigned r3659 = stwo_m31_mul(r1798, r1797);
    unsigned r3660 = stwo_m31_add(r3658, r3659);
    unsigned r3661 = stwo_m31_mul(r1799, r1796);
    unsigned r3662 = stwo_m31_add(r3660, r3661);
    unsigned r3663 = stwo_m31_mul(r1796, r1800);
    unsigned r3664 = stwo_m31_mul(r1797, r1799);
    unsigned r3665 = stwo_m31_add(r3663, r3664);
    unsigned r3666 = stwo_m31_mul(r1798, r1798);
    unsigned r3667 = stwo_m31_add(r3665, r3666);
    unsigned r3668 = stwo_m31_mul(r1799, r1797);
    unsigned r3669 = stwo_m31_add(r3667, r3668);
    unsigned r3670 = stwo_m31_mul(r1800, r1796);
    unsigned r3671 = stwo_m31_add(r3669, r3670);
    unsigned r3672 = stwo_m31_mul(r1796, r1801);
    unsigned r3673 = stwo_m31_mul(r1797, r1800);
    unsigned r3674 = stwo_m31_add(r3672, r3673);
    unsigned r3675 = stwo_m31_mul(r1798, r1799);
    unsigned r3676 = stwo_m31_add(r3674, r3675);
    unsigned r3677 = stwo_m31_mul(r1799, r1798);
    unsigned r3678 = stwo_m31_add(r3676, r3677);
    unsigned r3679 = stwo_m31_mul(r1800, r1797);
    unsigned r3680 = stwo_m31_add(r3678, r3679);
    unsigned r3681 = stwo_m31_mul(r1801, r1796);
    unsigned r3682 = stwo_m31_add(r3680, r3681);
    unsigned r3683 = stwo_m31_mul(r1796, r1802);
    unsigned r3684 = stwo_m31_mul(r1797, r1801);
    unsigned r3685 = stwo_m31_add(r3683, r3684);
    unsigned r3686 = stwo_m31_mul(r1798, r1800);
    unsigned r3687 = stwo_m31_add(r3685, r3686);
    unsigned r3688 = stwo_m31_mul(r1799, r1799);
    unsigned r3689 = stwo_m31_add(r3687, r3688);
    unsigned r3690 = stwo_m31_mul(r1800, r1798);
    unsigned r3691 = stwo_m31_add(r3689, r3690);
    unsigned r3692 = stwo_m31_mul(r1801, r1797);
    unsigned r3693 = stwo_m31_add(r3691, r3692);
    unsigned r3694 = stwo_m31_mul(r1802, r1796);
    unsigned r3695 = stwo_m31_add(r3693, r3694);
    unsigned r3696 = stwo_m31_mul(r1797, r1802);
    unsigned r3697 = stwo_m31_mul(r1798, r1801);
    unsigned r3698 = stwo_m31_add(r3696, r3697);
    unsigned r3699 = stwo_m31_mul(r1799, r1800);
    unsigned r3700 = stwo_m31_add(r3698, r3699);
    unsigned r3701 = stwo_m31_mul(r1800, r1799);
    unsigned r3702 = stwo_m31_add(r3700, r3701);
    unsigned r3703 = stwo_m31_mul(r1801, r1798);
    unsigned r3704 = stwo_m31_add(r3702, r3703);
    unsigned r3705 = stwo_m31_mul(r1802, r1797);
    unsigned r3706 = stwo_m31_add(r3704, r3705);
    unsigned r3707 = stwo_m31_mul(r1798, r1802);
    unsigned r3708 = stwo_m31_mul(r1799, r1801);
    unsigned r3709 = stwo_m31_add(r3707, r3708);
    unsigned r3710 = stwo_m31_mul(r1800, r1800);
    unsigned r3711 = stwo_m31_add(r3709, r3710);
    unsigned r3712 = stwo_m31_mul(r1801, r1799);
    unsigned r3713 = stwo_m31_add(r3711, r3712);
    unsigned r3714 = stwo_m31_mul(r1802, r1798);
    unsigned r3715 = stwo_m31_add(r3713, r3714);
    unsigned r3716 = stwo_m31_mul(r1799, r1802);
    unsigned r3717 = stwo_m31_mul(r1800, r1801);
    unsigned r3718 = stwo_m31_add(r3716, r3717);
    unsigned r3719 = stwo_m31_mul(r1801, r1800);
    unsigned r3720 = stwo_m31_add(r3718, r3719);
    unsigned r3721 = stwo_m31_mul(r1802, r1799);
    unsigned r3722 = stwo_m31_add(r3720, r3721);
    unsigned r3723 = stwo_m31_mul(r1800, r1802);
    unsigned r3724 = stwo_m31_mul(r1801, r1801);
    unsigned r3725 = stwo_m31_add(r3723, r3724);
    unsigned r3726 = stwo_m31_mul(r1802, r1800);
    unsigned r3727 = stwo_m31_add(r3725, r3726);
    unsigned r3728 = stwo_m31_mul(r1801, r1802);
    unsigned r3729 = stwo_m31_mul(r1802, r1801);
    unsigned r3730 = stwo_m31_add(r3728, r3729);
    unsigned r3731 = stwo_m31_mul(r1802, r1802);
    unsigned r3732 = stwo_m31_add(r1789, r1796);
    unsigned r3733 = stwo_m31_add(r1790, r1797);
    unsigned r3734 = stwo_m31_add(r1791, r1798);
    unsigned r3735 = stwo_m31_add(r1792, r1799);
    unsigned r3736 = stwo_m31_add(r1793, r1800);
    unsigned r3737 = stwo_m31_add(r1794, r1801);
    unsigned r3738 = stwo_m31_add(r1795, r1802);
    unsigned r3739 = stwo_m31_add(r1789, r1796);
    unsigned r3740 = stwo_m31_add(r1790, r1797);
    unsigned r3741 = stwo_m31_add(r1791, r1798);
    unsigned r3742 = stwo_m31_add(r1792, r1799);
    unsigned r3743 = stwo_m31_add(r1793, r1800);
    unsigned r3744 = stwo_m31_add(r1794, r1801);
    unsigned r3745 = stwo_m31_add(r1795, r1802);
    unsigned r3746 = stwo_m31_mul(r3732, r3739);
    unsigned r3747 = stwo_m31_sub(r3746, r3562);
    unsigned r3748 = stwo_m31_sub(r3747, r3647);
    unsigned r3749 = stwo_m31_add(r3621, r3748);
    unsigned r3750 = stwo_m31_mul(r3732, r3740);
    unsigned r3751 = stwo_m31_mul(r3733, r3739);
    unsigned r3752 = stwo_m31_add(r3750, r3751);
    unsigned r3753 = stwo_m31_sub(r3752, r3565);
    unsigned r3754 = stwo_m31_sub(r3753, r3650);
    unsigned r3755 = stwo_m31_add(r3630, r3754);
    unsigned r3756 = stwo_m31_mul(r3732, r3741);
    unsigned r3757 = stwo_m31_mul(r3733, r3740);
    unsigned r3758 = stwo_m31_add(r3756, r3757);
    unsigned r3759 = stwo_m31_mul(r3734, r3739);
    unsigned r3760 = stwo_m31_add(r3758, r3759);
    unsigned r3761 = stwo_m31_sub(r3760, r3570);
    unsigned r3762 = stwo_m31_sub(r3761, r3655);
    unsigned r3763 = stwo_m31_add(r3637, r3762);
    unsigned r3764 = stwo_m31_mul(r3732, r3742);
    unsigned r3765 = stwo_m31_mul(r3733, r3741);
    unsigned r3766 = stwo_m31_add(r3764, r3765);
    unsigned r3767 = stwo_m31_mul(r3734, r3740);
    unsigned r3768 = stwo_m31_add(r3766, r3767);
    unsigned r3769 = stwo_m31_mul(r3735, r3739);
    unsigned r3770 = stwo_m31_add(r3768, r3769);
    unsigned r3771 = stwo_m31_sub(r3770, r3577);
    unsigned r3772 = stwo_m31_sub(r3771, r3662);
    unsigned r3773 = stwo_m31_add(r3642, r3772);
    unsigned r3774 = stwo_m31_mul(r3732, r3743);
    unsigned r3775 = stwo_m31_mul(r3733, r3742);
    unsigned r3776 = stwo_m31_add(r3774, r3775);
    unsigned r3777 = stwo_m31_mul(r3734, r3741);
    unsigned r3778 = stwo_m31_add(r3776, r3777);
    unsigned r3779 = stwo_m31_mul(r3735, r3740);
    unsigned r3780 = stwo_m31_add(r3778, r3779);
    unsigned r3781 = stwo_m31_mul(r3736, r3739);
    unsigned r3782 = stwo_m31_add(r3780, r3781);
    unsigned r3783 = stwo_m31_sub(r3782, r3586);
    unsigned r3784 = stwo_m31_sub(r3783, r3671);
    unsigned r3785 = stwo_m31_add(r3645, r3784);
    unsigned r3786 = stwo_m31_mul(r3732, r3744);
    unsigned r3787 = stwo_m31_mul(r3733, r3743);
    unsigned r3788 = stwo_m31_add(r3786, r3787);
    unsigned r3789 = stwo_m31_mul(r3734, r3742);
    unsigned r3790 = stwo_m31_add(r3788, r3789);
    unsigned r3791 = stwo_m31_mul(r3735, r3741);
    unsigned r3792 = stwo_m31_add(r3790, r3791);
    unsigned r3793 = stwo_m31_mul(r3736, r3740);
    unsigned r3794 = stwo_m31_add(r3792, r3793);
    unsigned r3795 = stwo_m31_mul(r3737, r3739);
    unsigned r3796 = stwo_m31_add(r3794, r3795);
    unsigned r3797 = stwo_m31_sub(r3796, r3597);
    unsigned r3798 = stwo_m31_sub(r3797, r3682);
    unsigned r3799 = stwo_m31_add(r3646, r3798);
    unsigned r3800 = stwo_m31_mul(r3732, r3745);
    unsigned r3801 = stwo_m31_mul(r3733, r3744);
    unsigned r3802 = stwo_m31_add(r3800, r3801);
    unsigned r3803 = stwo_m31_mul(r3734, r3743);
    unsigned r3804 = stwo_m31_add(r3802, r3803);
    unsigned r3805 = stwo_m31_mul(r3735, r3742);
    unsigned r3806 = stwo_m31_add(r3804, r3805);
    unsigned r3807 = stwo_m31_mul(r3736, r3741);
    unsigned r3808 = stwo_m31_add(r3806, r3807);
    unsigned r3809 = stwo_m31_mul(r3737, r3740);
    unsigned r3810 = stwo_m31_add(r3808, r3809);
    unsigned r3811 = stwo_m31_mul(r3738, r3739);
    unsigned r3812 = stwo_m31_add(r3810, r3811);
    unsigned r3813 = stwo_m31_sub(r3812, r3610);
    unsigned r3814 = stwo_m31_sub(r3813, r3695);
    unsigned r3815 = stwo_m31_mul(r3733, r3745);
    unsigned r3816 = stwo_m31_mul(r3734, r3744);
    unsigned r3817 = stwo_m31_add(r3815, r3816);
    unsigned r3818 = stwo_m31_mul(r3735, r3743);
    unsigned r3819 = stwo_m31_add(r3817, r3818);
    unsigned r3820 = stwo_m31_mul(r3736, r3742);
    unsigned r3821 = stwo_m31_add(r3819, r3820);
    unsigned r3822 = stwo_m31_mul(r3737, r3741);
    unsigned r3823 = stwo_m31_add(r3821, r3822);
    unsigned r3824 = stwo_m31_mul(r3738, r3740);
    unsigned r3825 = stwo_m31_add(r3823, r3824);
    unsigned r3826 = stwo_m31_sub(r3825, r3621);
    unsigned r3827 = stwo_m31_sub(r3826, r3706);
    unsigned r3828 = stwo_m31_add(r3647, r3827);
    unsigned r3829 = stwo_m31_mul(r3734, r3745);
    unsigned r3830 = stwo_m31_mul(r3735, r3744);
    unsigned r3831 = stwo_m31_add(r3829, r3830);
    unsigned r3832 = stwo_m31_mul(r3736, r3743);
    unsigned r3833 = stwo_m31_add(r3831, r3832);
    unsigned r3834 = stwo_m31_mul(r3737, r3742);
    unsigned r3835 = stwo_m31_add(r3833, r3834);
    unsigned r3836 = stwo_m31_mul(r3738, r3741);
    unsigned r3837 = stwo_m31_add(r3835, r3836);
    unsigned r3838 = stwo_m31_sub(r3837, r3630);
    unsigned r3839 = stwo_m31_sub(r3838, r3715);
    unsigned r3840 = stwo_m31_add(r3650, r3839);
    unsigned r3841 = stwo_m31_mul(r3735, r3745);
    unsigned r3842 = stwo_m31_mul(r3736, r3744);
    unsigned r3843 = stwo_m31_add(r3841, r3842);
    unsigned r3844 = stwo_m31_mul(r3737, r3743);
    unsigned r3845 = stwo_m31_add(r3843, r3844);
    unsigned r3846 = stwo_m31_mul(r3738, r3742);
    unsigned r3847 = stwo_m31_add(r3845, r3846);
    unsigned r3848 = stwo_m31_sub(r3847, r3637);
    unsigned r3849 = stwo_m31_sub(r3848, r3722);
    unsigned r3850 = stwo_m31_add(r3655, r3849);
    unsigned r3851 = stwo_m31_mul(r3736, r3745);
    unsigned r3852 = stwo_m31_mul(r3737, r3744);
    unsigned r3853 = stwo_m31_add(r3851, r3852);
    unsigned r3854 = stwo_m31_mul(r3738, r3743);
    unsigned r3855 = stwo_m31_add(r3853, r3854);
    unsigned r3856 = stwo_m31_sub(r3855, r3642);
    unsigned r3857 = stwo_m31_sub(r3856, r3727);
    unsigned r3858 = stwo_m31_add(r3662, r3857);
    unsigned r3859 = stwo_m31_mul(r3737, r3745);
    unsigned r3860 = stwo_m31_mul(r3738, r3744);
    unsigned r3861 = stwo_m31_add(r3859, r3860);
    unsigned r3862 = stwo_m31_sub(r3861, r3645);
    unsigned r3863 = stwo_m31_sub(r3862, r3730);
    unsigned r3864 = stwo_m31_add(r3671, r3863);
    unsigned r3865 = stwo_m31_mul(r3738, r3745);
    unsigned r3866 = stwo_m31_sub(r3865, r3646);
    unsigned r3867 = stwo_m31_sub(r3866, r3731);
    unsigned r3868 = stwo_m31_add(r3682, r3867);
    unsigned r3869 = stwo_m31_mul(r1803, r1803);
    unsigned r3870 = stwo_m31_mul(r1803, r1804);
    unsigned r3871 = stwo_m31_mul(r1804, r1803);
    unsigned r3872 = stwo_m31_add(r3870, r3871);
    unsigned r3873 = stwo_m31_mul(r1803, r1805);
    unsigned r3874 = stwo_m31_mul(r1804, r1804);
    unsigned r3875 = stwo_m31_add(r3873, r3874);
    unsigned r3876 = stwo_m31_mul(r1805, r1803);
    unsigned r3877 = stwo_m31_add(r3875, r3876);
    unsigned r3878 = stwo_m31_mul(r1803, r1806);
    unsigned r3879 = stwo_m31_mul(r1804, r1805);
    unsigned r3880 = stwo_m31_add(r3878, r3879);
    unsigned r3881 = stwo_m31_mul(r1805, r1804);
    unsigned r3882 = stwo_m31_add(r3880, r3881);
    unsigned r3883 = stwo_m31_mul(r1806, r1803);
    unsigned r3884 = stwo_m31_add(r3882, r3883);
    unsigned r3885 = stwo_m31_mul(r1803, r1807);
    unsigned r3886 = stwo_m31_mul(r1804, r1806);
    unsigned r3887 = stwo_m31_add(r3885, r3886);
    unsigned r3888 = stwo_m31_mul(r1805, r1805);
    unsigned r3889 = stwo_m31_add(r3887, r3888);
    unsigned r3890 = stwo_m31_mul(r1806, r1804);
    unsigned r3891 = stwo_m31_add(r3889, r3890);
    unsigned r3892 = stwo_m31_mul(r1807, r1803);
    unsigned r3893 = stwo_m31_add(r3891, r3892);
    unsigned r3894 = stwo_m31_mul(r1803, r1808);
    unsigned r3895 = stwo_m31_mul(r1804, r1807);
    unsigned r3896 = stwo_m31_add(r3894, r3895);
    unsigned r3897 = stwo_m31_mul(r1805, r1806);
    unsigned r3898 = stwo_m31_add(r3896, r3897);
    unsigned r3899 = stwo_m31_mul(r1806, r1805);
    unsigned r3900 = stwo_m31_add(r3898, r3899);
    unsigned r3901 = stwo_m31_mul(r1807, r1804);
    unsigned r3902 = stwo_m31_add(r3900, r3901);
    unsigned r3903 = stwo_m31_mul(r1808, r1803);
    unsigned r3904 = stwo_m31_add(r3902, r3903);
    unsigned r3905 = stwo_m31_mul(r1803, r1809);
    unsigned r3906 = stwo_m31_mul(r1804, r1808);
    unsigned r3907 = stwo_m31_add(r3905, r3906);
    unsigned r3908 = stwo_m31_mul(r1805, r1807);
    unsigned r3909 = stwo_m31_add(r3907, r3908);
    unsigned r3910 = stwo_m31_mul(r1806, r1806);
    unsigned r3911 = stwo_m31_add(r3909, r3910);
    unsigned r3912 = stwo_m31_mul(r1807, r1805);
    unsigned r3913 = stwo_m31_add(r3911, r3912);
    unsigned r3914 = stwo_m31_mul(r1808, r1804);
    unsigned r3915 = stwo_m31_add(r3913, r3914);
    unsigned r3916 = stwo_m31_mul(r1809, r1803);
    unsigned r3917 = stwo_m31_add(r3915, r3916);
    unsigned r3918 = stwo_m31_mul(r1804, r1809);
    unsigned r3919 = stwo_m31_mul(r1805, r1808);
    unsigned r3920 = stwo_m31_add(r3918, r3919);
    unsigned r3921 = stwo_m31_mul(r1806, r1807);
    unsigned r3922 = stwo_m31_add(r3920, r3921);
    unsigned r3923 = stwo_m31_mul(r1807, r1806);
    unsigned r3924 = stwo_m31_add(r3922, r3923);
    unsigned r3925 = stwo_m31_mul(r1808, r1805);
    unsigned r3926 = stwo_m31_add(r3924, r3925);
    unsigned r3927 = stwo_m31_mul(r1809, r1804);
    unsigned r3928 = stwo_m31_add(r3926, r3927);
    unsigned r3929 = stwo_m31_mul(r1805, r1809);
    unsigned r3930 = stwo_m31_mul(r1806, r1808);
    unsigned r3931 = stwo_m31_add(r3929, r3930);
    unsigned r3932 = stwo_m31_mul(r1807, r1807);
    unsigned r3933 = stwo_m31_add(r3931, r3932);
    unsigned r3934 = stwo_m31_mul(r1808, r1806);
    unsigned r3935 = stwo_m31_add(r3933, r3934);
    unsigned r3936 = stwo_m31_mul(r1809, r1805);
    unsigned r3937 = stwo_m31_add(r3935, r3936);
    unsigned r3938 = stwo_m31_mul(r1806, r1809);
    unsigned r3939 = stwo_m31_mul(r1807, r1808);
    unsigned r3940 = stwo_m31_add(r3938, r3939);
    unsigned r3941 = stwo_m31_mul(r1808, r1807);
    unsigned r3942 = stwo_m31_add(r3940, r3941);
    unsigned r3943 = stwo_m31_mul(r1809, r1806);
    unsigned r3944 = stwo_m31_add(r3942, r3943);
    unsigned r3945 = stwo_m31_mul(r1807, r1809);
    unsigned r3946 = stwo_m31_mul(r1808, r1808);
    unsigned r3947 = stwo_m31_add(r3945, r3946);
    unsigned r3948 = stwo_m31_mul(r1809, r1807);
    unsigned r3949 = stwo_m31_add(r3947, r3948);
    unsigned r3950 = stwo_m31_mul(r1808, r1809);
    unsigned r3951 = stwo_m31_mul(r1809, r1808);
    unsigned r3952 = stwo_m31_add(r3950, r3951);
    unsigned r3953 = stwo_m31_mul(r1809, r1809);
    unsigned r3954 = stwo_m31_mul(r1810, r1810);
    unsigned r3955 = stwo_m31_mul(r1810, r1811);
    unsigned r3956 = stwo_m31_mul(r1811, r1810);
    unsigned r3957 = stwo_m31_add(r3955, r3956);
    unsigned r3958 = stwo_m31_mul(r1810, r1812);
    unsigned r3959 = stwo_m31_mul(r1811, r1811);
    unsigned r3960 = stwo_m31_add(r3958, r3959);
    unsigned r3961 = stwo_m31_mul(r1812, r1810);
    unsigned r3962 = stwo_m31_add(r3960, r3961);
    unsigned r3963 = stwo_m31_mul(r1810, r1813);
    unsigned r3964 = stwo_m31_mul(r1811, r1812);
    unsigned r3965 = stwo_m31_add(r3963, r3964);
    unsigned r3966 = stwo_m31_mul(r1812, r1811);
    unsigned r3967 = stwo_m31_add(r3965, r3966);
    unsigned r3968 = stwo_m31_mul(r1813, r1810);
    unsigned r3969 = stwo_m31_add(r3967, r3968);
    unsigned r3970 = stwo_m31_mul(r1810, r1814);
    unsigned r3971 = stwo_m31_mul(r1811, r1813);
    unsigned r3972 = stwo_m31_add(r3970, r3971);
    unsigned r3973 = stwo_m31_mul(r1812, r1812);
    unsigned r3974 = stwo_m31_add(r3972, r3973);
    unsigned r3975 = stwo_m31_mul(r1813, r1811);
    unsigned r3976 = stwo_m31_add(r3974, r3975);
    unsigned r3977 = stwo_m31_mul(r1814, r1810);
    unsigned r3978 = stwo_m31_add(r3976, r3977);
    unsigned r3979 = stwo_m31_mul(r1810, r1815);
    unsigned r3980 = stwo_m31_mul(r1811, r1814);
    unsigned r3981 = stwo_m31_add(r3979, r3980);
    unsigned r3982 = stwo_m31_mul(r1812, r1813);
    unsigned r3983 = stwo_m31_add(r3981, r3982);
    unsigned r3984 = stwo_m31_mul(r1813, r1812);
    unsigned r3985 = stwo_m31_add(r3983, r3984);
    unsigned r3986 = stwo_m31_mul(r1814, r1811);
    unsigned r3987 = stwo_m31_add(r3985, r3986);
    unsigned r3988 = stwo_m31_mul(r1815, r1810);
    unsigned r3989 = stwo_m31_add(r3987, r3988);
    unsigned r3990 = stwo_m31_mul(r1810, r1816);
    unsigned r3991 = stwo_m31_mul(r1811, r1815);
    unsigned r3992 = stwo_m31_add(r3990, r3991);
    unsigned r3993 = stwo_m31_mul(r1812, r1814);
    unsigned r3994 = stwo_m31_add(r3992, r3993);
    unsigned r3995 = stwo_m31_mul(r1813, r1813);
    unsigned r3996 = stwo_m31_add(r3994, r3995);
    unsigned r3997 = stwo_m31_mul(r1814, r1812);
    unsigned r3998 = stwo_m31_add(r3996, r3997);
    unsigned r3999 = stwo_m31_mul(r1815, r1811);
    unsigned r4000 = stwo_m31_add(r3998, r3999);
    unsigned r4001 = stwo_m31_mul(r1816, r1810);
    unsigned r4002 = stwo_m31_add(r4000, r4001);
    unsigned r4003 = stwo_m31_mul(r1811, r1816);
    unsigned r4004 = stwo_m31_mul(r1812, r1815);
    unsigned r4005 = stwo_m31_add(r4003, r4004);
    unsigned r4006 = stwo_m31_mul(r1813, r1814);
    unsigned r4007 = stwo_m31_add(r4005, r4006);
    unsigned r4008 = stwo_m31_mul(r1814, r1813);
    unsigned r4009 = stwo_m31_add(r4007, r4008);
    unsigned r4010 = stwo_m31_mul(r1815, r1812);
    unsigned r4011 = stwo_m31_add(r4009, r4010);
    unsigned r4012 = stwo_m31_mul(r1816, r1811);
    unsigned r4013 = stwo_m31_add(r4011, r4012);
    unsigned r4014 = stwo_m31_mul(r1812, r1816);
    unsigned r4015 = stwo_m31_mul(r1813, r1815);
    unsigned r4016 = stwo_m31_add(r4014, r4015);
    unsigned r4017 = stwo_m31_mul(r1814, r1814);
    unsigned r4018 = stwo_m31_add(r4016, r4017);
    unsigned r4019 = stwo_m31_mul(r1815, r1813);
    unsigned r4020 = stwo_m31_add(r4018, r4019);
    unsigned r4021 = stwo_m31_mul(r1816, r1812);
    unsigned r4022 = stwo_m31_add(r4020, r4021);
    unsigned r4023 = stwo_m31_mul(r1813, r1816);
    unsigned r4024 = stwo_m31_mul(r1814, r1815);
    unsigned r4025 = stwo_m31_add(r4023, r4024);
    unsigned r4026 = stwo_m31_mul(r1815, r1814);
    unsigned r4027 = stwo_m31_add(r4025, r4026);
    unsigned r4028 = stwo_m31_mul(r1816, r1813);
    unsigned r4029 = stwo_m31_add(r4027, r4028);
    unsigned r4030 = stwo_m31_mul(r1814, r1816);
    unsigned r4031 = stwo_m31_mul(r1815, r1815);
    unsigned r4032 = stwo_m31_add(r4030, r4031);
    unsigned r4033 = stwo_m31_mul(r1816, r1814);
    unsigned r4034 = stwo_m31_add(r4032, r4033);
    unsigned r4035 = stwo_m31_mul(r1815, r1816);
    unsigned r4036 = stwo_m31_mul(r1816, r1815);
    unsigned r4037 = stwo_m31_add(r4035, r4036);
    unsigned r4038 = stwo_m31_mul(r1816, r1816);
    unsigned r4039 = stwo_m31_add(r1803, r1810);
    unsigned r4040 = stwo_m31_add(r1804, r1811);
    unsigned r4041 = stwo_m31_add(r1805, r1812);
    unsigned r4042 = stwo_m31_add(r1806, r1813);
    unsigned r4043 = stwo_m31_add(r1807, r1814);
    unsigned r4044 = stwo_m31_add(r1808, r1815);
    unsigned r4045 = stwo_m31_add(r1809, r1816);
    unsigned r4046 = stwo_m31_add(r1803, r1810);
    unsigned r4047 = stwo_m31_add(r1804, r1811);
    unsigned r4048 = stwo_m31_add(r1805, r1812);
    unsigned r4049 = stwo_m31_add(r1806, r1813);
    unsigned r4050 = stwo_m31_add(r1807, r1814);
    unsigned r4051 = stwo_m31_add(r1808, r1815);
    unsigned r4052 = stwo_m31_add(r1809, r1816);
    unsigned r4053 = stwo_m31_mul(r4039, r4046);
    unsigned r4054 = stwo_m31_sub(r4053, r3869);
    unsigned r4055 = stwo_m31_sub(r4054, r3954);
    unsigned r4056 = stwo_m31_add(r3928, r4055);
    unsigned r4057 = stwo_m31_mul(r4039, r4047);
    unsigned r4058 = stwo_m31_mul(r4040, r4046);
    unsigned r4059 = stwo_m31_add(r4057, r4058);
    unsigned r4060 = stwo_m31_sub(r4059, r3872);
    unsigned r4061 = stwo_m31_sub(r4060, r3957);
    unsigned r4062 = stwo_m31_add(r3937, r4061);
    unsigned r4063 = stwo_m31_mul(r4039, r4048);
    unsigned r4064 = stwo_m31_mul(r4040, r4047);
    unsigned r4065 = stwo_m31_add(r4063, r4064);
    unsigned r4066 = stwo_m31_mul(r4041, r4046);
    unsigned r4067 = stwo_m31_add(r4065, r4066);
    unsigned r4068 = stwo_m31_sub(r4067, r3877);
    unsigned r4069 = stwo_m31_sub(r4068, r3962);
    unsigned r4070 = stwo_m31_add(r3944, r4069);
    unsigned r4071 = stwo_m31_mul(r4039, r4049);
    unsigned r4072 = stwo_m31_mul(r4040, r4048);
    unsigned r4073 = stwo_m31_add(r4071, r4072);
    unsigned r4074 = stwo_m31_mul(r4041, r4047);
    unsigned r4075 = stwo_m31_add(r4073, r4074);
    unsigned r4076 = stwo_m31_mul(r4042, r4046);
    unsigned r4077 = stwo_m31_add(r4075, r4076);
    unsigned r4078 = stwo_m31_sub(r4077, r3884);
    unsigned r4079 = stwo_m31_sub(r4078, r3969);
    unsigned r4080 = stwo_m31_add(r3949, r4079);
    unsigned r4081 = stwo_m31_mul(r4039, r4050);
    unsigned r4082 = stwo_m31_mul(r4040, r4049);
    unsigned r4083 = stwo_m31_add(r4081, r4082);
    unsigned r4084 = stwo_m31_mul(r4041, r4048);
    unsigned r4085 = stwo_m31_add(r4083, r4084);
    unsigned r4086 = stwo_m31_mul(r4042, r4047);
    unsigned r4087 = stwo_m31_add(r4085, r4086);
    unsigned r4088 = stwo_m31_mul(r4043, r4046);
    unsigned r4089 = stwo_m31_add(r4087, r4088);
    unsigned r4090 = stwo_m31_sub(r4089, r3893);
    unsigned r4091 = stwo_m31_sub(r4090, r3978);
    unsigned r4092 = stwo_m31_add(r3952, r4091);
    unsigned r4093 = stwo_m31_mul(r4039, r4051);
    unsigned r4094 = stwo_m31_mul(r4040, r4050);
    unsigned r4095 = stwo_m31_add(r4093, r4094);
    unsigned r4096 = stwo_m31_mul(r4041, r4049);
    unsigned r4097 = stwo_m31_add(r4095, r4096);
    unsigned r4098 = stwo_m31_mul(r4042, r4048);
    unsigned r4099 = stwo_m31_add(r4097, r4098);
    unsigned r4100 = stwo_m31_mul(r4043, r4047);
    unsigned r4101 = stwo_m31_add(r4099, r4100);
    unsigned r4102 = stwo_m31_mul(r4044, r4046);
    unsigned r4103 = stwo_m31_add(r4101, r4102);
    unsigned r4104 = stwo_m31_sub(r4103, r3904);
    unsigned r4105 = stwo_m31_sub(r4104, r3989);
    unsigned r4106 = stwo_m31_add(r3953, r4105);
    unsigned r4107 = stwo_m31_mul(r4039, r4052);
    unsigned r4108 = stwo_m31_mul(r4040, r4051);
    unsigned r4109 = stwo_m31_add(r4107, r4108);
    unsigned r4110 = stwo_m31_mul(r4041, r4050);
    unsigned r4111 = stwo_m31_add(r4109, r4110);
    unsigned r4112 = stwo_m31_mul(r4042, r4049);
    unsigned r4113 = stwo_m31_add(r4111, r4112);
    unsigned r4114 = stwo_m31_mul(r4043, r4048);
    unsigned r4115 = stwo_m31_add(r4113, r4114);
    unsigned r4116 = stwo_m31_mul(r4044, r4047);
    unsigned r4117 = stwo_m31_add(r4115, r4116);
    unsigned r4118 = stwo_m31_mul(r4045, r4046);
    unsigned r4119 = stwo_m31_add(r4117, r4118);
    unsigned r4120 = stwo_m31_sub(r4119, r3917);
    unsigned r4121 = stwo_m31_sub(r4120, r4002);
    unsigned r4122 = stwo_m31_mul(r4040, r4052);
    unsigned r4123 = stwo_m31_mul(r4041, r4051);
    unsigned r4124 = stwo_m31_add(r4122, r4123);
    unsigned r4125 = stwo_m31_mul(r4042, r4050);
    unsigned r4126 = stwo_m31_add(r4124, r4125);
    unsigned r4127 = stwo_m31_mul(r4043, r4049);
    unsigned r4128 = stwo_m31_add(r4126, r4127);
    unsigned r4129 = stwo_m31_mul(r4044, r4048);
    unsigned r4130 = stwo_m31_add(r4128, r4129);
    unsigned r4131 = stwo_m31_mul(r4045, r4047);
    unsigned r4132 = stwo_m31_add(r4130, r4131);
    unsigned r4133 = stwo_m31_sub(r4132, r3928);
    unsigned r4134 = stwo_m31_sub(r4133, r4013);
    unsigned r4135 = stwo_m31_add(r3954, r4134);
    unsigned r4136 = stwo_m31_mul(r4041, r4052);
    unsigned r4137 = stwo_m31_mul(r4042, r4051);
    unsigned r4138 = stwo_m31_add(r4136, r4137);
    unsigned r4139 = stwo_m31_mul(r4043, r4050);
    unsigned r4140 = stwo_m31_add(r4138, r4139);
    unsigned r4141 = stwo_m31_mul(r4044, r4049);
    unsigned r4142 = stwo_m31_add(r4140, r4141);
    unsigned r4143 = stwo_m31_mul(r4045, r4048);
    unsigned r4144 = stwo_m31_add(r4142, r4143);
    unsigned r4145 = stwo_m31_sub(r4144, r3937);
    unsigned r4146 = stwo_m31_sub(r4145, r4022);
    unsigned r4147 = stwo_m31_add(r3957, r4146);
    unsigned r4148 = stwo_m31_mul(r4042, r4052);
    unsigned r4149 = stwo_m31_mul(r4043, r4051);
    unsigned r4150 = stwo_m31_add(r4148, r4149);
    unsigned r4151 = stwo_m31_mul(r4044, r4050);
    unsigned r4152 = stwo_m31_add(r4150, r4151);
    unsigned r4153 = stwo_m31_mul(r4045, r4049);
    unsigned r4154 = stwo_m31_add(r4152, r4153);
    unsigned r4155 = stwo_m31_sub(r4154, r3944);
    unsigned r4156 = stwo_m31_sub(r4155, r4029);
    unsigned r4157 = stwo_m31_add(r3962, r4156);
    unsigned r4158 = stwo_m31_mul(r4043, r4052);
    unsigned r4159 = stwo_m31_mul(r4044, r4051);
    unsigned r4160 = stwo_m31_add(r4158, r4159);
    unsigned r4161 = stwo_m31_mul(r4045, r4050);
    unsigned r4162 = stwo_m31_add(r4160, r4161);
    unsigned r4163 = stwo_m31_sub(r4162, r3949);
    unsigned r4164 = stwo_m31_sub(r4163, r4034);
    unsigned r4165 = stwo_m31_add(r3969, r4164);
    unsigned r4166 = stwo_m31_mul(r4044, r4052);
    unsigned r4167 = stwo_m31_mul(r4045, r4051);
    unsigned r4168 = stwo_m31_add(r4166, r4167);
    unsigned r4169 = stwo_m31_sub(r4168, r3952);
    unsigned r4170 = stwo_m31_sub(r4169, r4037);
    unsigned r4171 = stwo_m31_add(r3978, r4170);
    unsigned r4172 = stwo_m31_mul(r4045, r4052);
    unsigned r4173 = stwo_m31_sub(r4172, r3953);
    unsigned r4174 = stwo_m31_sub(r4173, r4038);
    unsigned r4175 = stwo_m31_add(r3989, r4174);
    unsigned r4176 = stwo_m31_add(r1789, r1803);
    unsigned r4177 = stwo_m31_add(r1790, r1804);
    unsigned r4178 = stwo_m31_add(r1791, r1805);
    unsigned r4179 = stwo_m31_add(r1792, r1806);
    unsigned r4180 = stwo_m31_add(r1793, r1807);
    unsigned r4181 = stwo_m31_add(r1794, r1808);
    unsigned r4182 = stwo_m31_add(r1795, r1809);
    unsigned r4183 = stwo_m31_add(r1796, r1810);
    unsigned r4184 = stwo_m31_add(r1797, r1811);
    unsigned r4185 = stwo_m31_add(r1798, r1812);
    unsigned r4186 = stwo_m31_add(r1799, r1813);
    unsigned r4187 = stwo_m31_add(r1800, r1814);
    unsigned r4188 = stwo_m31_add(r1801, r1815);
    unsigned r4189 = stwo_m31_add(r1802, r1816);
    unsigned r4190 = stwo_m31_add(r1789, r1803);
    unsigned r4191 = stwo_m31_add(r1790, r1804);
    unsigned r4192 = stwo_m31_add(r1791, r1805);
    unsigned r4193 = stwo_m31_add(r1792, r1806);
    unsigned r4194 = stwo_m31_add(r1793, r1807);
    unsigned r4195 = stwo_m31_add(r1794, r1808);
    unsigned r4196 = stwo_m31_add(r1795, r1809);
    unsigned r4197 = stwo_m31_add(r1796, r1810);
    unsigned r4198 = stwo_m31_add(r1797, r1811);
    unsigned r4199 = stwo_m31_add(r1798, r1812);
    unsigned r4200 = stwo_m31_add(r1799, r1813);
    unsigned r4201 = stwo_m31_add(r1800, r1814);
    unsigned r4202 = stwo_m31_add(r1801, r1815);
    unsigned r4203 = stwo_m31_add(r1802, r1816);
    unsigned r4204 = stwo_m31_mul(r4176, r4190);
    unsigned r4205 = stwo_m31_mul(r4176, r4191);
    unsigned r4206 = stwo_m31_mul(r4177, r4190);
    unsigned r4207 = stwo_m31_add(r4205, r4206);
    unsigned r4208 = stwo_m31_mul(r4176, r4192);
    unsigned r4209 = stwo_m31_mul(r4177, r4191);
    unsigned r4210 = stwo_m31_add(r4208, r4209);
    unsigned r4211 = stwo_m31_mul(r4178, r4190);
    unsigned r4212 = stwo_m31_add(r4210, r4211);
    unsigned r4213 = stwo_m31_mul(r4176, r4193);
    unsigned r4214 = stwo_m31_mul(r4177, r4192);
    unsigned r4215 = stwo_m31_add(r4213, r4214);
    unsigned r4216 = stwo_m31_mul(r4178, r4191);
    unsigned r4217 = stwo_m31_add(r4215, r4216);
    unsigned r4218 = stwo_m31_mul(r4179, r4190);
    unsigned r4219 = stwo_m31_add(r4217, r4218);
    unsigned r4220 = stwo_m31_mul(r4176, r4194);
    unsigned r4221 = stwo_m31_mul(r4177, r4193);
    unsigned r4222 = stwo_m31_add(r4220, r4221);
    unsigned r4223 = stwo_m31_mul(r4178, r4192);
    unsigned r4224 = stwo_m31_add(r4222, r4223);
    unsigned r4225 = stwo_m31_mul(r4179, r4191);
    unsigned r4226 = stwo_m31_add(r4224, r4225);
    unsigned r4227 = stwo_m31_mul(r4180, r4190);
    unsigned r4228 = stwo_m31_add(r4226, r4227);
    unsigned r4229 = stwo_m31_mul(r4176, r4195);
    unsigned r4230 = stwo_m31_mul(r4177, r4194);
    unsigned r4231 = stwo_m31_add(r4229, r4230);
    unsigned r4232 = stwo_m31_mul(r4178, r4193);
    unsigned r4233 = stwo_m31_add(r4231, r4232);
    unsigned r4234 = stwo_m31_mul(r4179, r4192);
    unsigned r4235 = stwo_m31_add(r4233, r4234);
    unsigned r4236 = stwo_m31_mul(r4180, r4191);
    unsigned r4237 = stwo_m31_add(r4235, r4236);
    unsigned r4238 = stwo_m31_mul(r4181, r4190);
    unsigned r4239 = stwo_m31_add(r4237, r4238);
    unsigned r4240 = stwo_m31_mul(r4176, r4196);
    unsigned r4241 = stwo_m31_mul(r4177, r4195);
    unsigned r4242 = stwo_m31_add(r4240, r4241);
    unsigned r4243 = stwo_m31_mul(r4178, r4194);
    unsigned r4244 = stwo_m31_add(r4242, r4243);
    unsigned r4245 = stwo_m31_mul(r4179, r4193);
    unsigned r4246 = stwo_m31_add(r4244, r4245);
    unsigned r4247 = stwo_m31_mul(r4180, r4192);
    unsigned r4248 = stwo_m31_add(r4246, r4247);
    unsigned r4249 = stwo_m31_mul(r4181, r4191);
    unsigned r4250 = stwo_m31_add(r4248, r4249);
    unsigned r4251 = stwo_m31_mul(r4182, r4190);
    unsigned r4252 = stwo_m31_add(r4250, r4251);
    unsigned r4253 = stwo_m31_mul(r4177, r4196);
    unsigned r4254 = stwo_m31_mul(r4178, r4195);
    unsigned r4255 = stwo_m31_add(r4253, r4254);
    unsigned r4256 = stwo_m31_mul(r4179, r4194);
    unsigned r4257 = stwo_m31_add(r4255, r4256);
    unsigned r4258 = stwo_m31_mul(r4180, r4193);
    unsigned r4259 = stwo_m31_add(r4257, r4258);
    unsigned r4260 = stwo_m31_mul(r4181, r4192);
    unsigned r4261 = stwo_m31_add(r4259, r4260);
    unsigned r4262 = stwo_m31_mul(r4182, r4191);
    unsigned r4263 = stwo_m31_add(r4261, r4262);
    unsigned r4264 = stwo_m31_mul(r4178, r4196);
    unsigned r4265 = stwo_m31_mul(r4179, r4195);
    unsigned r4266 = stwo_m31_add(r4264, r4265);
    unsigned r4267 = stwo_m31_mul(r4180, r4194);
    unsigned r4268 = stwo_m31_add(r4266, r4267);
    unsigned r4269 = stwo_m31_mul(r4181, r4193);
    unsigned r4270 = stwo_m31_add(r4268, r4269);
    unsigned r4271 = stwo_m31_mul(r4182, r4192);
    unsigned r4272 = stwo_m31_add(r4270, r4271);
    unsigned r4273 = stwo_m31_mul(r4179, r4196);
    unsigned r4274 = stwo_m31_mul(r4180, r4195);
    unsigned r4275 = stwo_m31_add(r4273, r4274);
    unsigned r4276 = stwo_m31_mul(r4181, r4194);
    unsigned r4277 = stwo_m31_add(r4275, r4276);
    unsigned r4278 = stwo_m31_mul(r4182, r4193);
    unsigned r4279 = stwo_m31_add(r4277, r4278);
    unsigned r4280 = stwo_m31_mul(r4180, r4196);
    unsigned r4281 = stwo_m31_mul(r4181, r4195);
    unsigned r4282 = stwo_m31_add(r4280, r4281);
    unsigned r4283 = stwo_m31_mul(r4182, r4194);
    unsigned r4284 = stwo_m31_add(r4282, r4283);
    unsigned r4285 = stwo_m31_mul(r4181, r4196);
    unsigned r4286 = stwo_m31_mul(r4182, r4195);
    unsigned r4287 = stwo_m31_add(r4285, r4286);
    unsigned r4288 = stwo_m31_mul(r4182, r4196);
    unsigned r4289 = stwo_m31_mul(r4183, r4197);
    unsigned r4290 = stwo_m31_mul(r4183, r4198);
    unsigned r4291 = stwo_m31_mul(r4184, r4197);
    unsigned r4292 = stwo_m31_add(r4290, r4291);
    unsigned r4293 = stwo_m31_mul(r4183, r4199);
    unsigned r4294 = stwo_m31_mul(r4184, r4198);
    unsigned r4295 = stwo_m31_add(r4293, r4294);
    unsigned r4296 = stwo_m31_mul(r4185, r4197);
    unsigned r4297 = stwo_m31_add(r4295, r4296);
    unsigned r4298 = stwo_m31_mul(r4183, r4200);
    unsigned r4299 = stwo_m31_mul(r4184, r4199);
    unsigned r4300 = stwo_m31_add(r4298, r4299);
    unsigned r4301 = stwo_m31_mul(r4185, r4198);
    unsigned r4302 = stwo_m31_add(r4300, r4301);
    unsigned r4303 = stwo_m31_mul(r4186, r4197);
    unsigned r4304 = stwo_m31_add(r4302, r4303);
    unsigned r4305 = stwo_m31_mul(r4183, r4201);
    unsigned r4306 = stwo_m31_mul(r4184, r4200);
    unsigned r4307 = stwo_m31_add(r4305, r4306);
    unsigned r4308 = stwo_m31_mul(r4185, r4199);
    unsigned r4309 = stwo_m31_add(r4307, r4308);
    unsigned r4310 = stwo_m31_mul(r4186, r4198);
    unsigned r4311 = stwo_m31_add(r4309, r4310);
    unsigned r4312 = stwo_m31_mul(r4187, r4197);
    unsigned r4313 = stwo_m31_add(r4311, r4312);
    unsigned r4314 = stwo_m31_mul(r4183, r4202);
    unsigned r4315 = stwo_m31_mul(r4184, r4201);
    unsigned r4316 = stwo_m31_add(r4314, r4315);
    unsigned r4317 = stwo_m31_mul(r4185, r4200);
    unsigned r4318 = stwo_m31_add(r4316, r4317);
    unsigned r4319 = stwo_m31_mul(r4186, r4199);
    unsigned r4320 = stwo_m31_add(r4318, r4319);
    unsigned r4321 = stwo_m31_mul(r4187, r4198);
    unsigned r4322 = stwo_m31_add(r4320, r4321);
    unsigned r4323 = stwo_m31_mul(r4188, r4197);
    unsigned r4324 = stwo_m31_add(r4322, r4323);
    unsigned r4325 = stwo_m31_mul(r4183, r4203);
    unsigned r4326 = stwo_m31_mul(r4184, r4202);
    unsigned r4327 = stwo_m31_add(r4325, r4326);
    unsigned r4328 = stwo_m31_mul(r4185, r4201);
    unsigned r4329 = stwo_m31_add(r4327, r4328);
    unsigned r4330 = stwo_m31_mul(r4186, r4200);
    unsigned r4331 = stwo_m31_add(r4329, r4330);
    unsigned r4332 = stwo_m31_mul(r4187, r4199);
    unsigned r4333 = stwo_m31_add(r4331, r4332);
    unsigned r4334 = stwo_m31_mul(r4188, r4198);
    unsigned r4335 = stwo_m31_add(r4333, r4334);
    unsigned r4336 = stwo_m31_mul(r4189, r4197);
    unsigned r4337 = stwo_m31_add(r4335, r4336);
    unsigned r4338 = stwo_m31_mul(r4184, r4203);
    unsigned r4339 = stwo_m31_mul(r4185, r4202);
    unsigned r4340 = stwo_m31_add(r4338, r4339);
    unsigned r4341 = stwo_m31_mul(r4186, r4201);
    unsigned r4342 = stwo_m31_add(r4340, r4341);
    unsigned r4343 = stwo_m31_mul(r4187, r4200);
    unsigned r4344 = stwo_m31_add(r4342, r4343);
    unsigned r4345 = stwo_m31_mul(r4188, r4199);
    unsigned r4346 = stwo_m31_add(r4344, r4345);
    unsigned r4347 = stwo_m31_mul(r4189, r4198);
    unsigned r4348 = stwo_m31_add(r4346, r4347);
    unsigned r4349 = stwo_m31_mul(r4185, r4203);
    unsigned r4350 = stwo_m31_mul(r4186, r4202);
    unsigned r4351 = stwo_m31_add(r4349, r4350);
    unsigned r4352 = stwo_m31_mul(r4187, r4201);
    unsigned r4353 = stwo_m31_add(r4351, r4352);
    unsigned r4354 = stwo_m31_mul(r4188, r4200);
    unsigned r4355 = stwo_m31_add(r4353, r4354);
    unsigned r4356 = stwo_m31_mul(r4189, r4199);
    unsigned r4357 = stwo_m31_add(r4355, r4356);
    unsigned r4358 = stwo_m31_mul(r4186, r4203);
    unsigned r4359 = stwo_m31_mul(r4187, r4202);
    unsigned r4360 = stwo_m31_add(r4358, r4359);
    unsigned r4361 = stwo_m31_mul(r4188, r4201);
    unsigned r4362 = stwo_m31_add(r4360, r4361);
    unsigned r4363 = stwo_m31_mul(r4189, r4200);
    unsigned r4364 = stwo_m31_add(r4362, r4363);
    unsigned r4365 = stwo_m31_mul(r4187, r4203);
    unsigned r4366 = stwo_m31_mul(r4188, r4202);
    unsigned r4367 = stwo_m31_add(r4365, r4366);
    unsigned r4368 = stwo_m31_mul(r4189, r4201);
    unsigned r4369 = stwo_m31_add(r4367, r4368);
    unsigned r4370 = stwo_m31_mul(r4188, r4203);
    unsigned r4371 = stwo_m31_mul(r4189, r4202);
    unsigned r4372 = stwo_m31_add(r4370, r4371);
    unsigned r4373 = stwo_m31_mul(r4189, r4203);
    unsigned r4374 = stwo_m31_add(r4176, r4183);
    unsigned r4375 = stwo_m31_add(r4177, r4184);
    unsigned r4376 = stwo_m31_add(r4178, r4185);
    unsigned r4377 = stwo_m31_add(r4179, r4186);
    unsigned r4378 = stwo_m31_add(r4180, r4187);
    unsigned r4379 = stwo_m31_add(r4181, r4188);
    unsigned r4380 = stwo_m31_add(r4182, r4189);
    unsigned r4381 = stwo_m31_add(r4190, r4197);
    unsigned r4382 = stwo_m31_add(r4191, r4198);
    unsigned r4383 = stwo_m31_add(r4192, r4199);
    unsigned r4384 = stwo_m31_add(r4193, r4200);
    unsigned r4385 = stwo_m31_add(r4194, r4201);
    unsigned r4386 = stwo_m31_add(r4195, r4202);
    unsigned r4387 = stwo_m31_add(r4196, r4203);
    unsigned r4388 = stwo_m31_mul(r4374, r4381);
    unsigned r4389 = stwo_m31_sub(r4388, r4204);
    unsigned r4390 = stwo_m31_sub(r4389, r4289);
    unsigned r4391 = stwo_m31_add(r4263, r4390);
    unsigned r4392 = stwo_m31_mul(r4374, r4382);
    unsigned r4393 = stwo_m31_mul(r4375, r4381);
    unsigned r4394 = stwo_m31_add(r4392, r4393);
    unsigned r4395 = stwo_m31_sub(r4394, r4207);
    unsigned r4396 = stwo_m31_sub(r4395, r4292);
    unsigned r4397 = stwo_m31_add(r4272, r4396);
    unsigned r4398 = stwo_m31_mul(r4374, r4383);
    unsigned r4399 = stwo_m31_mul(r4375, r4382);
    unsigned r4400 = stwo_m31_add(r4398, r4399);
    unsigned r4401 = stwo_m31_mul(r4376, r4381);
    unsigned r4402 = stwo_m31_add(r4400, r4401);
    unsigned r4403 = stwo_m31_sub(r4402, r4212);
    unsigned r4404 = stwo_m31_sub(r4403, r4297);
    unsigned r4405 = stwo_m31_add(r4279, r4404);
    unsigned r4406 = stwo_m31_mul(r4374, r4384);
    unsigned r4407 = stwo_m31_mul(r4375, r4383);
    unsigned r4408 = stwo_m31_add(r4406, r4407);
    unsigned r4409 = stwo_m31_mul(r4376, r4382);
    unsigned r4410 = stwo_m31_add(r4408, r4409);
    unsigned r4411 = stwo_m31_mul(r4377, r4381);
    unsigned r4412 = stwo_m31_add(r4410, r4411);
    unsigned r4413 = stwo_m31_sub(r4412, r4219);
    unsigned r4414 = stwo_m31_sub(r4413, r4304);
    unsigned r4415 = stwo_m31_add(r4284, r4414);
    unsigned r4416 = stwo_m31_mul(r4374, r4385);
    unsigned r4417 = stwo_m31_mul(r4375, r4384);
    unsigned r4418 = stwo_m31_add(r4416, r4417);
    unsigned r4419 = stwo_m31_mul(r4376, r4383);
    unsigned r4420 = stwo_m31_add(r4418, r4419);
    unsigned r4421 = stwo_m31_mul(r4377, r4382);
    unsigned r4422 = stwo_m31_add(r4420, r4421);
    unsigned r4423 = stwo_m31_mul(r4378, r4381);
    unsigned r4424 = stwo_m31_add(r4422, r4423);
    unsigned r4425 = stwo_m31_sub(r4424, r4228);
    unsigned r4426 = stwo_m31_sub(r4425, r4313);
    unsigned r4427 = stwo_m31_add(r4287, r4426);
    unsigned r4428 = stwo_m31_mul(r4374, r4386);
    unsigned r4429 = stwo_m31_mul(r4375, r4385);
    unsigned r4430 = stwo_m31_add(r4428, r4429);
    unsigned r4431 = stwo_m31_mul(r4376, r4384);
    unsigned r4432 = stwo_m31_add(r4430, r4431);
    unsigned r4433 = stwo_m31_mul(r4377, r4383);
    unsigned r4434 = stwo_m31_add(r4432, r4433);
    unsigned r4435 = stwo_m31_mul(r4378, r4382);
    unsigned r4436 = stwo_m31_add(r4434, r4435);
    unsigned r4437 = stwo_m31_mul(r4379, r4381);
    unsigned r4438 = stwo_m31_add(r4436, r4437);
    unsigned r4439 = stwo_m31_sub(r4438, r4239);
    unsigned r4440 = stwo_m31_sub(r4439, r4324);
    unsigned r4441 = stwo_m31_add(r4288, r4440);
    unsigned r4442 = stwo_m31_mul(r4374, r4387);
    unsigned r4443 = stwo_m31_mul(r4375, r4386);
    unsigned r4444 = stwo_m31_add(r4442, r4443);
    unsigned r4445 = stwo_m31_mul(r4376, r4385);
    unsigned r4446 = stwo_m31_add(r4444, r4445);
    unsigned r4447 = stwo_m31_mul(r4377, r4384);
    unsigned r4448 = stwo_m31_add(r4446, r4447);
    unsigned r4449 = stwo_m31_mul(r4378, r4383);
    unsigned r4450 = stwo_m31_add(r4448, r4449);
    unsigned r4451 = stwo_m31_mul(r4379, r4382);
    unsigned r4452 = stwo_m31_add(r4450, r4451);
    unsigned r4453 = stwo_m31_mul(r4380, r4381);
    unsigned r4454 = stwo_m31_add(r4452, r4453);
    unsigned r4455 = stwo_m31_sub(r4454, r4252);
    unsigned r4456 = stwo_m31_sub(r4455, r4337);
    unsigned r4457 = stwo_m31_mul(r4375, r4387);
    unsigned r4458 = stwo_m31_mul(r4376, r4386);
    unsigned r4459 = stwo_m31_add(r4457, r4458);
    unsigned r4460 = stwo_m31_mul(r4377, r4385);
    unsigned r4461 = stwo_m31_add(r4459, r4460);
    unsigned r4462 = stwo_m31_mul(r4378, r4384);
    unsigned r4463 = stwo_m31_add(r4461, r4462);
    unsigned r4464 = stwo_m31_mul(r4379, r4383);
    unsigned r4465 = stwo_m31_add(r4463, r4464);
    unsigned r4466 = stwo_m31_mul(r4380, r4382);
    unsigned r4467 = stwo_m31_add(r4465, r4466);
    unsigned r4468 = stwo_m31_sub(r4467, r4263);
    unsigned r4469 = stwo_m31_sub(r4468, r4348);
    unsigned r4470 = stwo_m31_add(r4289, r4469);
    unsigned r4471 = stwo_m31_mul(r4376, r4387);
    unsigned r4472 = stwo_m31_mul(r4377, r4386);
    unsigned r4473 = stwo_m31_add(r4471, r4472);
    unsigned r4474 = stwo_m31_mul(r4378, r4385);
    unsigned r4475 = stwo_m31_add(r4473, r4474);
    unsigned r4476 = stwo_m31_mul(r4379, r4384);
    unsigned r4477 = stwo_m31_add(r4475, r4476);
    unsigned r4478 = stwo_m31_mul(r4380, r4383);
    unsigned r4479 = stwo_m31_add(r4477, r4478);
    unsigned r4480 = stwo_m31_sub(r4479, r4272);
    unsigned r4481 = stwo_m31_sub(r4480, r4357);
    unsigned r4482 = stwo_m31_add(r4292, r4481);
    unsigned r4483 = stwo_m31_mul(r4377, r4387);
    unsigned r4484 = stwo_m31_mul(r4378, r4386);
    unsigned r4485 = stwo_m31_add(r4483, r4484);
    unsigned r4486 = stwo_m31_mul(r4379, r4385);
    unsigned r4487 = stwo_m31_add(r4485, r4486);
    unsigned r4488 = stwo_m31_mul(r4380, r4384);
    unsigned r4489 = stwo_m31_add(r4487, r4488);
    unsigned r4490 = stwo_m31_sub(r4489, r4279);
    unsigned r4491 = stwo_m31_sub(r4490, r4364);
    unsigned r4492 = stwo_m31_add(r4297, r4491);
    unsigned r4493 = stwo_m31_mul(r4378, r4387);
    unsigned r4494 = stwo_m31_mul(r4379, r4386);
    unsigned r4495 = stwo_m31_add(r4493, r4494);
    unsigned r4496 = stwo_m31_mul(r4380, r4385);
    unsigned r4497 = stwo_m31_add(r4495, r4496);
    unsigned r4498 = stwo_m31_sub(r4497, r4284);
    unsigned r4499 = stwo_m31_sub(r4498, r4369);
    unsigned r4500 = stwo_m31_add(r4304, r4499);
    unsigned r4501 = stwo_m31_mul(r4379, r4387);
    unsigned r4502 = stwo_m31_mul(r4380, r4386);
    unsigned r4503 = stwo_m31_add(r4501, r4502);
    unsigned r4504 = stwo_m31_sub(r4503, r4287);
    unsigned r4505 = stwo_m31_sub(r4504, r4372);
    unsigned r4506 = stwo_m31_add(r4313, r4505);
    unsigned r4507 = stwo_m31_mul(r4380, r4387);
    unsigned r4508 = stwo_m31_sub(r4507, r4288);
    unsigned r4509 = stwo_m31_sub(r4508, r4373);
    unsigned r4510 = stwo_m31_add(r4324, r4509);
    unsigned r4511 = stwo_m31_sub(r4204, r3562);
    unsigned r4512 = stwo_m31_sub(r4511, r3869);
    unsigned r4513 = stwo_m31_add(r3828, r4512);
    unsigned r4514 = stwo_m31_sub(r4207, r3565);
    unsigned r4515 = stwo_m31_sub(r4514, r3872);
    unsigned r4516 = stwo_m31_add(r3840, r4515);
    unsigned r4517 = stwo_m31_sub(r4212, r3570);
    unsigned r4518 = stwo_m31_sub(r4517, r3877);
    unsigned r4519 = stwo_m31_add(r3850, r4518);
    unsigned r4520 = stwo_m31_sub(r4219, r3577);
    unsigned r4521 = stwo_m31_sub(r4520, r3884);
    unsigned r4522 = stwo_m31_add(r3858, r4521);
    unsigned r4523 = stwo_m31_sub(r4228, r3586);
    unsigned r4524 = stwo_m31_sub(r4523, r3893);
    unsigned r4525 = stwo_m31_add(r3864, r4524);
    unsigned r4526 = stwo_m31_sub(r4239, r3597);
    unsigned r4527 = stwo_m31_sub(r4526, r3904);
    unsigned r4528 = stwo_m31_add(r3868, r4527);
    unsigned r4529 = stwo_m31_sub(r4252, r3610);
    unsigned r4530 = stwo_m31_sub(r4529, r3917);
    unsigned r4531 = stwo_m31_add(r3695, r4530);
    unsigned r4532 = stwo_m31_sub(r4391, r3749);
    unsigned r4533 = stwo_m31_sub(r4532, r4056);
    unsigned r4534 = stwo_m31_add(r3706, r4533);
    unsigned r4535 = stwo_m31_sub(r4397, r3755);
    unsigned r4536 = stwo_m31_sub(r4535, r4062);
    unsigned r4537 = stwo_m31_add(r3715, r4536);
    unsigned r4538 = stwo_m31_sub(r4405, r3763);
    unsigned r4539 = stwo_m31_sub(r4538, r4070);
    unsigned r4540 = stwo_m31_add(r3722, r4539);
    unsigned r4541 = stwo_m31_sub(r4415, r3773);
    unsigned r4542 = stwo_m31_sub(r4541, r4080);
    unsigned r4543 = stwo_m31_add(r3727, r4542);
    unsigned r4544 = stwo_m31_sub(r4427, r3785);
    unsigned r4545 = stwo_m31_sub(r4544, r4092);
    unsigned r4546 = stwo_m31_add(r3730, r4545);
    unsigned r4547 = stwo_m31_sub(r4441, r3799);
    unsigned r4548 = stwo_m31_sub(r4547, r4106);
    unsigned r4549 = stwo_m31_add(r3731, r4548);
    unsigned r4550 = stwo_m31_sub(r4456, r3814);
    unsigned r4551 = stwo_m31_sub(r4550, r4121);
    unsigned r4552 = stwo_m31_sub(r4470, r3828);
    unsigned r4553 = stwo_m31_sub(r4552, r4135);
    unsigned r4554 = stwo_m31_add(r3869, r4553);
    unsigned r4555 = stwo_m31_sub(r4482, r3840);
    unsigned r4556 = stwo_m31_sub(r4555, r4147);
    unsigned r4557 = stwo_m31_add(r3872, r4556);
    unsigned r4558 = stwo_m31_sub(r4492, r3850);
    unsigned r4559 = stwo_m31_sub(r4558, r4157);
    unsigned r4560 = stwo_m31_add(r3877, r4559);
    unsigned r4561 = stwo_m31_sub(r4500, r3858);
    unsigned r4562 = stwo_m31_sub(r4561, r4165);
    unsigned r4563 = stwo_m31_add(r3884, r4562);
    unsigned r4564 = stwo_m31_sub(r4506, r3864);
    unsigned r4565 = stwo_m31_sub(r4564, r4171);
    unsigned r4566 = stwo_m31_add(r3893, r4565);
    unsigned r4567 = stwo_m31_sub(r4510, r3868);
    unsigned r4568 = stwo_m31_sub(r4567, r4175);
    unsigned r4569 = stwo_m31_add(r3904, r4568);
    unsigned r4570 = stwo_m31_sub(r4337, r3695);
    unsigned r4571 = stwo_m31_sub(r4570, r4002);
    unsigned r4572 = stwo_m31_add(r3917, r4571);
    unsigned r4573 = stwo_m31_sub(r4348, r3706);
    unsigned r4574 = stwo_m31_sub(r4573, r4013);
    unsigned r4575 = stwo_m31_add(r4056, r4574);
    unsigned r4576 = stwo_m31_sub(r4357, r3715);
    unsigned r4577 = stwo_m31_sub(r4576, r4022);
    unsigned r4578 = stwo_m31_add(r4062, r4577);
    unsigned r4579 = stwo_m31_sub(r4364, r3722);
    unsigned r4580 = stwo_m31_sub(r4579, r4029);
    unsigned r4581 = stwo_m31_add(r4070, r4580);
    unsigned r4582 = stwo_m31_sub(r4369, r3727);
    unsigned r4583 = stwo_m31_sub(r4582, r4034);
    unsigned r4584 = stwo_m31_add(r4080, r4583);
    unsigned r4585 = stwo_m31_sub(r4372, r3730);
    unsigned r4586 = stwo_m31_sub(r4585, r4037);
    unsigned r4587 = stwo_m31_add(r4092, r4586);
    unsigned r4588 = stwo_m31_sub(r4373, r3731);
    unsigned r4589 = stwo_m31_sub(r4588, r4038);
    unsigned r4590 = stwo_m31_add(r4106, r4589);
    unsigned r4591 = stwo_m31_add(r47, r1619);
    out_cols[72u][row] = r1619;
    lookup_words[148u * row_count + row] = r1619;
    unsigned r4592 = stwo_m31_add(r4591, r3534);
    unsigned r4593 = stwo_m31_sub(r3562, r4592);
    unsigned r4594 = stwo_m31_add(r76, r1620);
    out_cols[73u][row] = r1620;
    lookup_words[149u * row_count + row] = r1620;
    unsigned r4595 = stwo_m31_add(r4594, r3535);
    unsigned r4596 = stwo_m31_sub(r3565, r4595);
    unsigned r4597 = stwo_m31_add(r105, r1621);
    out_cols[74u][row] = r1621;
    lookup_words[150u * row_count + row] = r1621;
    unsigned r4598 = stwo_m31_add(r4597, r3536);
    unsigned r4599 = stwo_m31_sub(r3570, r4598);
    unsigned r4600 = stwo_m31_add(r134, r1622);
    out_cols[75u][row] = r1622;
    lookup_words[151u * row_count + row] = r1622;
    unsigned r4601 = stwo_m31_add(r4600, r3537);
    unsigned r4602 = stwo_m31_sub(r3577, r4601);
    unsigned r4603 = stwo_m31_add(r163, r1623);
    out_cols[76u][row] = r1623;
    lookup_words[152u * row_count + row] = r1623;
    unsigned r4604 = stwo_m31_add(r4603, r3538);
    unsigned r4605 = stwo_m31_sub(r3586, r4604);
    unsigned r4606 = stwo_m31_add(r192, r1624);
    out_cols[77u][row] = r1624;
    lookup_words[153u * row_count + row] = r1624;
    unsigned r4607 = stwo_m31_add(r4606, r3539);
    unsigned r4608 = stwo_m31_sub(r3597, r4607);
    unsigned r4609 = stwo_m31_add(r221, r1625);
    out_cols[78u][row] = r1625;
    lookup_words[154u * row_count + row] = r1625;
    unsigned r4610 = stwo_m31_add(r4609, r3540);
    unsigned r4611 = stwo_m31_sub(r3610, r4610);
    unsigned r4612 = stwo_m31_add(r250, r1626);
    out_cols[79u][row] = r1626;
    lookup_words[155u * row_count + row] = r1626;
    unsigned r4613 = stwo_m31_add(r4612, r3541);
    unsigned r4614 = stwo_m31_sub(r3749, r4613);
    unsigned r4615 = stwo_m31_add(r279, r1627);
    out_cols[80u][row] = r1627;
    lookup_words[156u * row_count + row] = r1627;
    unsigned r4616 = stwo_m31_add(r4615, r3542);
    unsigned r4617 = stwo_m31_sub(r3755, r4616);
    unsigned r4618 = stwo_m31_add(r308, r1628);
    out_cols[81u][row] = r1628;
    lookup_words[157u * row_count + row] = r1628;
    unsigned r4619 = stwo_m31_add(r4618, r3543);
    unsigned r4620 = stwo_m31_sub(r3763, r4619);
    unsigned r4621 = stwo_m31_add(r337, r1629);
    out_cols[82u][row] = r1629;
    lookup_words[158u * row_count + row] = r1629;
    unsigned r4622 = stwo_m31_add(r4621, r3544);
    unsigned r4623 = stwo_m31_sub(r3773, r4622);
    unsigned r4624 = stwo_m31_add(r366, r1630);
    out_cols[83u][row] = r1630;
    lookup_words[159u * row_count + row] = r1630;
    unsigned r4625 = stwo_m31_add(r4624, r3545);
    unsigned r4626 = stwo_m31_sub(r3785, r4625);
    unsigned r4627 = stwo_m31_add(r395, r1631);
    out_cols[84u][row] = r1631;
    lookup_words[160u * row_count + row] = r1631;
    unsigned r4628 = stwo_m31_add(r4627, r3546);
    unsigned r4629 = stwo_m31_sub(r3799, r4628);
    unsigned r4630 = stwo_m31_add(r424, r1632);
    out_cols[85u][row] = r1632;
    lookup_words[161u * row_count + row] = r1632;
    unsigned r4631 = stwo_m31_add(r4630, r3547);
    unsigned r4632 = stwo_m31_sub(r3814, r4631);
    unsigned r4633 = stwo_m31_add(r453, r1633);
    out_cols[86u][row] = r1633;
    lookup_words[162u * row_count + row] = r1633;
    unsigned r4634 = stwo_m31_add(r4633, r3548);
    unsigned r4635 = stwo_m31_sub(r4513, r4634);
    unsigned r4636 = stwo_m31_add(r482, r1634);
    out_cols[87u][row] = r1634;
    lookup_words[163u * row_count + row] = r1634;
    unsigned r4637 = stwo_m31_add(r4636, r3549);
    unsigned r4638 = stwo_m31_sub(r4516, r4637);
    unsigned r4639 = stwo_m31_add(r511, r1635);
    out_cols[88u][row] = r1635;
    lookup_words[164u * row_count + row] = r1635;
    unsigned r4640 = stwo_m31_add(r4639, r3550);
    unsigned r4641 = stwo_m31_sub(r4519, r4640);
    unsigned r4642 = stwo_m31_add(r540, r1636);
    out_cols[89u][row] = r1636;
    lookup_words[165u * row_count + row] = r1636;
    unsigned r4643 = stwo_m31_add(r4642, r3551);
    unsigned r4644 = stwo_m31_sub(r4522, r4643);
    unsigned r4645 = stwo_m31_add(r569, r1637);
    out_cols[90u][row] = r1637;
    lookup_words[166u * row_count + row] = r1637;
    unsigned r4646 = stwo_m31_add(r4645, r3552);
    unsigned r4647 = stwo_m31_sub(r4525, r4646);
    unsigned r4648 = stwo_m31_add(r598, r1638);
    out_cols[91u][row] = r1638;
    lookup_words[167u * row_count + row] = r1638;
    unsigned r4649 = stwo_m31_add(r4648, r3553);
    unsigned r4650 = stwo_m31_sub(r4528, r4649);
    unsigned r4651 = stwo_m31_add(r627, r1639);
    out_cols[92u][row] = r1639;
    lookup_words[168u * row_count + row] = r1639;
    unsigned r4652 = stwo_m31_add(r4651, r3554);
    unsigned r4653 = stwo_m31_sub(r4531, r4652);
    unsigned r4654 = stwo_m31_add(r656, r1640);
    out_cols[93u][row] = r1640;
    lookup_words[169u * row_count + row] = r1640;
    unsigned r4655 = stwo_m31_add(r4654, r3555);
    unsigned r4656 = stwo_m31_sub(r4534, r4655);
    unsigned r4657 = stwo_m31_add(r685, r1641);
    out_cols[94u][row] = r1641;
    lookup_words[170u * row_count + row] = r1641;
    unsigned r4658 = stwo_m31_add(r4657, r3556);
    unsigned r4659 = stwo_m31_sub(r4537, r4658);
    unsigned r4660 = stwo_m31_add(r714, r1642);
    out_cols[95u][row] = r1642;
    lookup_words[171u * row_count + row] = r1642;
    unsigned r4661 = stwo_m31_add(r4660, r3557);
    unsigned r4662 = stwo_m31_sub(r4540, r4661);
    unsigned r4663 = stwo_m31_add(r743, r1643);
    out_cols[96u][row] = r1643;
    lookup_words[172u * row_count + row] = r1643;
    unsigned r4664 = stwo_m31_add(r4663, r3558);
    unsigned r4665 = stwo_m31_sub(r4543, r4664);
    unsigned r4666 = stwo_m31_add(r772, r1644);
    out_cols[97u][row] = r1644;
    lookup_words[173u * row_count + row] = r1644;
    unsigned r4667 = stwo_m31_add(r4666, r3559);
    unsigned r4668 = stwo_m31_sub(r4546, r4667);
    unsigned r4669 = stwo_m31_add(r801, r1645);
    out_cols[98u][row] = r1645;
    lookup_words[174u * row_count + row] = r1645;
    unsigned r4670 = stwo_m31_add(r4669, r3560);
    unsigned r4671 = stwo_m31_sub(r4549, r4670);
    unsigned r4672 = stwo_m31_add(r830, r1646);
    out_cols[99u][row] = r1646;
    lookup_words[175u * row_count + row] = r1646;
    unsigned r4673 = stwo_m31_add(r4672, r3561);
    unsigned r4674 = stwo_m31_sub(r4551, r4673);
    unsigned r4675 = stwo_m31_mul(r5, r4593);
    unsigned r4676 = stwo_m31_mul(r3, r4656);
    unsigned r4677 = stwo_m31_sub(r4675, r4676);
    unsigned r4678 = stwo_m31_mul(r4, r4013);
    unsigned r4679 = stwo_m31_add(r4677, r4678);
    unsigned r4680 = stwo_m31_mul(r5, r4596);
    unsigned r4681 = stwo_m31_add(r4593, r4680);
    unsigned r4682 = stwo_m31_mul(r3, r4659);
    unsigned r4683 = stwo_m31_sub(r4681, r4682);
    unsigned r4684 = stwo_m31_mul(r4, r4022);
    unsigned r4685 = stwo_m31_add(r4683, r4684);
    unsigned r4686 = stwo_m31_mul(r5, r4599);
    unsigned r4687 = stwo_m31_add(r4596, r4686);
    unsigned r4688 = stwo_m31_mul(r3, r4662);
    unsigned r4689 = stwo_m31_sub(r4687, r4688);
    unsigned r4690 = stwo_m31_mul(r4, r4029);
    unsigned r4691 = stwo_m31_add(r4689, r4690);
    unsigned r4692 = stwo_m31_mul(r5, r4602);
    unsigned r4693 = stwo_m31_add(r4599, r4692);
    unsigned r4694 = stwo_m31_mul(r3, r4665);
    unsigned r4695 = stwo_m31_sub(r4693, r4694);
    unsigned r4696 = stwo_m31_mul(r4, r4034);
    unsigned r4697 = stwo_m31_add(r4695, r4696);
    unsigned r4698 = stwo_m31_mul(r5, r4605);
    unsigned r4699 = stwo_m31_add(r4602, r4698);
    unsigned r4700 = stwo_m31_mul(r3, r4668);
    unsigned r4701 = stwo_m31_sub(r4699, r4700);
    unsigned r4702 = stwo_m31_mul(r4, r4037);
    unsigned r4703 = stwo_m31_add(r4701, r4702);
    unsigned r4704 = stwo_m31_mul(r5, r4608);
    unsigned r4705 = stwo_m31_add(r4605, r4704);
    unsigned r4706 = stwo_m31_mul(r3, r4671);
    unsigned r4707 = stwo_m31_sub(r4705, r4706);
    unsigned r4708 = stwo_m31_mul(r4, r4038);
    unsigned r4709 = stwo_m31_add(r4707, r4708);
    unsigned r4710 = stwo_m31_mul(r5, r4611);
    unsigned r4711 = stwo_m31_add(r4608, r4710);
    unsigned r4712 = stwo_m31_mul(r3, r4674);
    unsigned r4713 = stwo_m31_sub(r4711, r4712);
    unsigned r4714 = stwo_m31_mul(r2, r4593);
    unsigned r4715 = stwo_m31_add(r4714, r4611);
    unsigned r4716 = stwo_m31_mul(r5, r4614);
    unsigned r4717 = stwo_m31_add(r4715, r4716);
    unsigned r4718 = stwo_m31_mul(r3, r4554);
    unsigned r4719 = stwo_m31_sub(r4717, r4718);
    unsigned r4720 = stwo_m31_mul(r2, r4596);
    unsigned r4721 = stwo_m31_add(r4720, r4614);
    unsigned r4722 = stwo_m31_mul(r5, r4617);
    unsigned r4723 = stwo_m31_add(r4721, r4722);
    unsigned r4724 = stwo_m31_mul(r3, r4557);
    unsigned r4725 = stwo_m31_sub(r4723, r4724);
    unsigned r4726 = stwo_m31_mul(r2, r4599);
    unsigned r4727 = stwo_m31_add(r4726, r4617);
    unsigned r4728 = stwo_m31_mul(r5, r4620);
    unsigned r4729 = stwo_m31_add(r4727, r4728);
    unsigned r4730 = stwo_m31_mul(r3, r4560);
    unsigned r4731 = stwo_m31_sub(r4729, r4730);
    unsigned r4732 = stwo_m31_mul(r2, r4602);
    unsigned r4733 = stwo_m31_add(r4732, r4620);
    unsigned r4734 = stwo_m31_mul(r5, r4623);
    unsigned r4735 = stwo_m31_add(r4733, r4734);
    unsigned r4736 = stwo_m31_mul(r3, r4563);
    unsigned r4737 = stwo_m31_sub(r4735, r4736);
    unsigned r4738 = stwo_m31_mul(r2, r4605);
    unsigned r4739 = stwo_m31_add(r4738, r4623);
    unsigned r4740 = stwo_m31_mul(r5, r4626);
    unsigned r4741 = stwo_m31_add(r4739, r4740);
    unsigned r4742 = stwo_m31_mul(r3, r4566);
    unsigned r4743 = stwo_m31_sub(r4741, r4742);
    unsigned r4744 = stwo_m31_mul(r2, r4608);
    unsigned r4745 = stwo_m31_add(r4744, r4626);
    unsigned r4746 = stwo_m31_mul(r5, r4629);
    unsigned r4747 = stwo_m31_add(r4745, r4746);
    unsigned r4748 = stwo_m31_mul(r3, r4569);
    unsigned r4749 = stwo_m31_sub(r4747, r4748);
    unsigned r4750 = stwo_m31_mul(r2, r4611);
    unsigned r4751 = stwo_m31_add(r4750, r4629);
    unsigned r4752 = stwo_m31_mul(r5, r4632);
    unsigned r4753 = stwo_m31_add(r4751, r4752);
    unsigned r4754 = stwo_m31_mul(r3, r4572);
    unsigned r4755 = stwo_m31_sub(r4753, r4754);
    unsigned r4756 = stwo_m31_mul(r2, r4614);
    unsigned r4757 = stwo_m31_add(r4756, r4632);
    unsigned r4758 = stwo_m31_mul(r5, r4635);
    unsigned r4759 = stwo_m31_add(r4757, r4758);
    unsigned r4760 = stwo_m31_mul(r3, r4575);
    unsigned r4761 = stwo_m31_sub(r4759, r4760);
    unsigned r4762 = stwo_m31_mul(r2, r4617);
    unsigned r4763 = stwo_m31_add(r4762, r4635);
    unsigned r4764 = stwo_m31_mul(r5, r4638);
    unsigned r4765 = stwo_m31_add(r4763, r4764);
    unsigned r4766 = stwo_m31_mul(r3, r4578);
    unsigned r4767 = stwo_m31_sub(r4765, r4766);
    unsigned r4768 = stwo_m31_mul(r2, r4620);
    unsigned r4769 = stwo_m31_add(r4768, r4638);
    unsigned r4770 = stwo_m31_mul(r5, r4641);
    unsigned r4771 = stwo_m31_add(r4769, r4770);
    unsigned r4772 = stwo_m31_mul(r3, r4581);
    unsigned r4773 = stwo_m31_sub(r4771, r4772);
    unsigned r4774 = stwo_m31_mul(r2, r4623);
    unsigned r4775 = stwo_m31_add(r4774, r4641);
    unsigned r4776 = stwo_m31_mul(r5, r4644);
    unsigned r4777 = stwo_m31_add(r4775, r4776);
    unsigned r4778 = stwo_m31_mul(r3, r4584);
    unsigned r4779 = stwo_m31_sub(r4777, r4778);
    unsigned r4780 = stwo_m31_mul(r2, r4626);
    unsigned r4781 = stwo_m31_add(r4780, r4644);
    unsigned r4782 = stwo_m31_mul(r5, r4647);
    unsigned r4783 = stwo_m31_add(r4781, r4782);
    unsigned r4784 = stwo_m31_mul(r3, r4587);
    unsigned r4785 = stwo_m31_sub(r4783, r4784);
    unsigned r4786 = stwo_m31_mul(r2, r4629);
    unsigned r4787 = stwo_m31_add(r4786, r4647);
    unsigned r4788 = stwo_m31_mul(r5, r4650);
    unsigned r4789 = stwo_m31_add(r4787, r4788);
    unsigned r4790 = stwo_m31_mul(r3, r4590);
    unsigned r4791 = stwo_m31_sub(r4789, r4790);
    unsigned r4792 = stwo_m31_mul(r2, r4632);
    unsigned r4793 = stwo_m31_add(r4792, r4650);
    unsigned r4794 = stwo_m31_mul(r5, r4653);
    unsigned r4795 = stwo_m31_add(r4793, r4794);
    unsigned r4796 = stwo_m31_mul(r3, r4121);
    unsigned r4797 = stwo_m31_sub(r4795, r4796);
    unsigned r4798 = stwo_m31_mul(r2, r4635);
    unsigned r4799 = stwo_m31_add(r4798, r4653);
    unsigned r4800 = stwo_m31_mul(r3, r4135);
    unsigned r4801 = stwo_m31_sub(r4799, r4800);
    unsigned r4802 = stwo_m31_mul(r6, r4013);
    unsigned r4803 = stwo_m31_add(r4801, r4802);
    unsigned r4804 = stwo_m31_mul(r2, r4638);
    unsigned r4805 = stwo_m31_mul(r3, r4147);
    unsigned r4806 = stwo_m31_sub(r4804, r4805);
    unsigned r4807 = stwo_m31_mul(r2, r4013);
    unsigned r4808 = stwo_m31_add(r4806, r4807);
    unsigned r4809 = stwo_m31_mul(r6, r4022);
    unsigned r4810 = stwo_m31_add(r4808, r4809);
    unsigned r4811 = stwo_m31_mul(r2, r4641);
    unsigned r4812 = stwo_m31_mul(r3, r4157);
    unsigned r4813 = stwo_m31_sub(r4811, r4812);
    unsigned r4814 = stwo_m31_mul(r2, r4022);
    unsigned r4815 = stwo_m31_add(r4813, r4814);
    unsigned r4816 = stwo_m31_mul(r6, r4029);
    unsigned r4817 = stwo_m31_add(r4815, r4816);
    unsigned r4818 = stwo_m31_mul(r2, r4644);
    unsigned r4819 = stwo_m31_mul(r3, r4165);
    unsigned r4820 = stwo_m31_sub(r4818, r4819);
    unsigned r4821 = stwo_m31_mul(r2, r4029);
    unsigned r4822 = stwo_m31_add(r4820, r4821);
    unsigned r4823 = stwo_m31_mul(r6, r4034);
    unsigned r4824 = stwo_m31_add(r4822, r4823);
    unsigned r4825 = stwo_m31_mul(r2, r4647);
    unsigned r4826 = stwo_m31_mul(r3, r4171);
    unsigned r4827 = stwo_m31_sub(r4825, r4826);
    unsigned r4828 = stwo_m31_mul(r2, r4034);
    unsigned r4829 = stwo_m31_add(r4827, r4828);
    unsigned r4830 = stwo_m31_mul(r6, r4037);
    unsigned r4831 = stwo_m31_add(r4829, r4830);
    unsigned r4832 = stwo_m31_mul(r2, r4650);
    unsigned r4833 = stwo_m31_mul(r3, r4175);
    unsigned r4834 = stwo_m31_sub(r4832, r4833);
    unsigned r4835 = stwo_m31_mul(r2, r4037);
    unsigned r4836 = stwo_m31_add(r4834, r4835);
    unsigned r4837 = stwo_m31_mul(r6, r4038);
    unsigned r4838 = stwo_m31_add(r4836, r4837);
    unsigned r4839 = stwo_m31_mul(r2, r4653);
    unsigned r4840 = stwo_m31_mul(r3, r4002);
    unsigned r4841 = stwo_m31_sub(r4839, r4840);
    unsigned r4842 = stwo_m31_mul(r2, r4038);
    unsigned r4843 = stwo_m31_add(r4841, r4842);
    unsigned r4844 = stwo_m31_add(r4679, r12);
    unsigned r4845 = stwo_m31_add(r4685, r12);
    unsigned r4846 = (r4845 & 511u);
    unsigned r4847 = (r4846 << 9u);
    unsigned r4848 = (r4844 + r4847);
    unsigned r4849 = 131072u;
    unsigned r4850 = (r4848 + r4849);
    unsigned r4851 = (r4850 & 262143u);
    unsigned r4852 = (r4851 & 65535u);
    unsigned r4853 = (r4852 % STWO_M31_P);
    unsigned r4854 = (r4851 >> 16u);
    unsigned r4855 = (r4854 % STWO_M31_P);
    unsigned r4856 = stwo_m31_sub(r4855, r2);
    unsigned r4857 = stwo_m31_mul(r4856, r8);
    unsigned r4858 = stwo_m31_add(r4853, r4857);
    unsigned r4859 = stwo_m31_add(r4858, r10);
    sub_words[89u * row_count + row] = r4859;
    unsigned r4860 = stwo_m31_add(r4858, r10);
    lookup_words[213u * row_count + row] = r4860;
    unsigned r4861 = stwo_m31_sub(r4679, r4858);
    unsigned r4862 = stwo_m31_mul(r4861, r11);
    unsigned r4863 = stwo_m31_add(r4862, r10);
    sub_words[101u * row_count + row] = r4863;
    unsigned r4864 = stwo_m31_add(r4862, r10);
    lookup_words[237u * row_count + row] = r4864;
    unsigned r4865 = stwo_m31_add(r4685, r4862);
    out_cols[213u][row] = r4862;
    unsigned r4866 = stwo_m31_mul(r4865, r11);
    unsigned r4867 = stwo_m31_add(r4866, r10);
    sub_words[113u * row_count + row] = r4867;
    unsigned r4868 = stwo_m31_add(r4866, r10);
    lookup_words[261u * row_count + row] = r4868;
    unsigned r4869 = stwo_m31_add(r4691, r4866);
    out_cols[214u][row] = r4866;
    unsigned r4870 = stwo_m31_mul(r4869, r11);
    unsigned r4871 = stwo_m31_add(r4870, r10);
    sub_words[125u * row_count + row] = r4871;
    unsigned r4872 = stwo_m31_add(r4870, r10);
    lookup_words[285u * row_count + row] = r4872;
    unsigned r4873 = stwo_m31_add(r4697, r4870);
    out_cols[215u][row] = r4870;
    unsigned r4874 = stwo_m31_mul(r4873, r11);
    unsigned r4875 = stwo_m31_add(r4874, r10);
    sub_words[136u * row_count + row] = r4875;
    unsigned r4876 = stwo_m31_add(r4874, r10);
    lookup_words[307u * row_count + row] = r4876;
    unsigned r4877 = stwo_m31_add(r4703, r4874);
    out_cols[216u][row] = r4874;
    unsigned r4878 = stwo_m31_mul(r4877, r11);
    unsigned r4879 = stwo_m31_add(r4878, r10);
    sub_words[145u * row_count + row] = r4879;
    unsigned r4880 = stwo_m31_add(r4878, r10);
    lookup_words[325u * row_count + row] = r4880;
    unsigned r4881 = stwo_m31_add(r4709, r4878);
    out_cols[217u][row] = r4878;
    unsigned r4882 = stwo_m31_mul(r4881, r11);
    unsigned r4883 = stwo_m31_add(r4882, r10);
    sub_words[154u * row_count + row] = r4883;
    unsigned r4884 = stwo_m31_add(r4882, r10);
    lookup_words[343u * row_count + row] = r4884;
    unsigned r4885 = stwo_m31_add(r4713, r4882);
    out_cols[218u][row] = r4882;
    unsigned r4886 = stwo_m31_mul(r4885, r11);
    unsigned r4887 = stwo_m31_add(r4886, r10);
    sub_words[163u * row_count + row] = r4887;
    unsigned r4888 = stwo_m31_add(r4886, r10);
    lookup_words[361u * row_count + row] = r4888;
    unsigned r4889 = stwo_m31_add(r4719, r4886);
    out_cols[219u][row] = r4886;
    unsigned r4890 = stwo_m31_mul(r4889, r11);
    unsigned r4891 = stwo_m31_add(r4890, r10);
    sub_words[90u * row_count + row] = r4891;
    unsigned r4892 = stwo_m31_add(r4890, r10);
    lookup_words[215u * row_count + row] = r4892;
    unsigned r4893 = stwo_m31_add(r4725, r4890);
    out_cols[220u][row] = r4890;
    unsigned r4894 = stwo_m31_mul(r4893, r11);
    unsigned r4895 = stwo_m31_add(r4894, r10);
    sub_words[102u * row_count + row] = r4895;
    unsigned r4896 = stwo_m31_add(r4894, r10);
    lookup_words[239u * row_count + row] = r4896;
    unsigned r4897 = stwo_m31_add(r4731, r4894);
    out_cols[221u][row] = r4894;
    unsigned r4898 = stwo_m31_mul(r4897, r11);
    unsigned r4899 = stwo_m31_add(r4898, r10);
    sub_words[114u * row_count + row] = r4899;
    unsigned r4900 = stwo_m31_add(r4898, r10);
    lookup_words[263u * row_count + row] = r4900;
    unsigned r4901 = stwo_m31_add(r4737, r4898);
    out_cols[222u][row] = r4898;
    unsigned r4902 = stwo_m31_mul(r4901, r11);
    unsigned r4903 = stwo_m31_add(r4902, r10);
    sub_words[126u * row_count + row] = r4903;
    unsigned r4904 = stwo_m31_add(r4902, r10);
    lookup_words[287u * row_count + row] = r4904;
    unsigned r4905 = stwo_m31_add(r4743, r4902);
    out_cols[223u][row] = r4902;
    unsigned r4906 = stwo_m31_mul(r4905, r11);
    unsigned r4907 = stwo_m31_add(r4906, r10);
    sub_words[137u * row_count + row] = r4907;
    unsigned r4908 = stwo_m31_add(r4906, r10);
    lookup_words[309u * row_count + row] = r4908;
    unsigned r4909 = stwo_m31_add(r4749, r4906);
    out_cols[224u][row] = r4906;
    unsigned r4910 = stwo_m31_mul(r4909, r11);
    unsigned r4911 = stwo_m31_add(r4910, r10);
    sub_words[146u * row_count + row] = r4911;
    unsigned r4912 = stwo_m31_add(r4910, r10);
    lookup_words[327u * row_count + row] = r4912;
    unsigned r4913 = stwo_m31_add(r4755, r4910);
    out_cols[225u][row] = r4910;
    unsigned r4914 = stwo_m31_mul(r4913, r11);
    unsigned r4915 = stwo_m31_add(r4914, r10);
    sub_words[155u * row_count + row] = r4915;
    unsigned r4916 = stwo_m31_add(r4914, r10);
    lookup_words[345u * row_count + row] = r4916;
    unsigned r4917 = stwo_m31_add(r4761, r4914);
    out_cols[226u][row] = r4914;
    unsigned r4918 = stwo_m31_mul(r4917, r11);
    unsigned r4919 = stwo_m31_add(r4918, r10);
    sub_words[164u * row_count + row] = r4919;
    unsigned r4920 = stwo_m31_add(r4918, r10);
    lookup_words[363u * row_count + row] = r4920;
    unsigned r4921 = stwo_m31_add(r4767, r4918);
    out_cols[227u][row] = r4918;
    unsigned r4922 = stwo_m31_mul(r4921, r11);
    unsigned r4923 = stwo_m31_add(r4922, r10);
    sub_words[91u * row_count + row] = r4923;
    unsigned r4924 = stwo_m31_add(r4922, r10);
    lookup_words[217u * row_count + row] = r4924;
    unsigned r4925 = stwo_m31_add(r4773, r4922);
    out_cols[228u][row] = r4922;
    unsigned r4926 = stwo_m31_mul(r4925, r11);
    unsigned r4927 = stwo_m31_add(r4926, r10);
    sub_words[103u * row_count + row] = r4927;
    unsigned r4928 = stwo_m31_add(r4926, r10);
    lookup_words[241u * row_count + row] = r4928;
    unsigned r4929 = stwo_m31_add(r4779, r4926);
    out_cols[229u][row] = r4926;
    unsigned r4930 = stwo_m31_mul(r4929, r11);
    unsigned r4931 = stwo_m31_add(r4930, r10);
    sub_words[115u * row_count + row] = r4931;
    unsigned r4932 = stwo_m31_add(r4930, r10);
    lookup_words[265u * row_count + row] = r4932;
    unsigned r4933 = stwo_m31_add(r4785, r4930);
    out_cols[230u][row] = r4930;
    unsigned r4934 = stwo_m31_mul(r4933, r11);
    unsigned r4935 = stwo_m31_add(r4934, r10);
    sub_words[127u * row_count + row] = r4935;
    unsigned r4936 = stwo_m31_add(r4934, r10);
    lookup_words[289u * row_count + row] = r4936;
    unsigned r4937 = stwo_m31_add(r4791, r4934);
    out_cols[231u][row] = r4934;
    unsigned r4938 = stwo_m31_mul(r4937, r11);
    unsigned r4939 = stwo_m31_add(r4938, r10);
    sub_words[138u * row_count + row] = r4939;
    unsigned r4940 = stwo_m31_add(r4938, r10);
    lookup_words[311u * row_count + row] = r4940;
    unsigned r4941 = stwo_m31_add(r4797, r4938);
    out_cols[232u][row] = r4938;
    unsigned r4942 = stwo_m31_mul(r4941, r11);
    unsigned r4943 = stwo_m31_add(r4942, r10);
    sub_words[147u * row_count + row] = r4943;
    unsigned r4944 = stwo_m31_add(r4942, r10);
    lookup_words[329u * row_count + row] = r4944;
    unsigned r4945 = stwo_m31_mul(r7, r4858);
    out_cols[212u][row] = r4858;
    unsigned r4946 = stwo_m31_sub(r4803, r4945);
    unsigned r4947 = stwo_m31_add(r4946, r4942);
    out_cols[233u][row] = r4942;
    unsigned r4948 = stwo_m31_mul(r4947, r11);
    unsigned r4949 = stwo_m31_add(r4948, r10);
    sub_words[156u * row_count + row] = r4949;
    unsigned r4950 = stwo_m31_add(r4948, r10);
    lookup_words[347u * row_count + row] = r4950;
    unsigned r4951 = stwo_m31_add(r4810, r4948);
    out_cols[234u][row] = r4948;
    unsigned r4952 = stwo_m31_mul(r4951, r11);
    unsigned r4953 = stwo_m31_add(r4952, r10);
    sub_words[165u * row_count + row] = r4953;
    unsigned r4954 = stwo_m31_add(r4952, r10);
    lookup_words[365u * row_count + row] = r4954;
    unsigned r4955 = stwo_m31_add(r4817, r4952);
    out_cols[235u][row] = r4952;
    unsigned r4956 = stwo_m31_mul(r4955, r11);
    unsigned r4957 = stwo_m31_add(r4956, r10);
    sub_words[92u * row_count + row] = r4957;
    unsigned r4958 = stwo_m31_add(r4956, r10);
    lookup_words[219u * row_count + row] = r4958;
    unsigned r4959 = stwo_m31_add(r4824, r4956);
    out_cols[236u][row] = r4956;
    unsigned r4960 = stwo_m31_mul(r4959, r11);
    unsigned r4961 = stwo_m31_add(r4960, r10);
    sub_words[104u * row_count + row] = r4961;
    unsigned r4962 = stwo_m31_add(r4960, r10);
    lookup_words[243u * row_count + row] = r4962;
    unsigned r4963 = stwo_m31_add(r4831, r4960);
    out_cols[237u][row] = r4960;
    unsigned r4964 = stwo_m31_mul(r4963, r11);
    unsigned r4965 = stwo_m31_add(r4964, r10);
    sub_words[116u * row_count + row] = r4965;
    unsigned r4966 = stwo_m31_add(r4964, r10);
    lookup_words[267u * row_count + row] = r4966;
    unsigned r4967 = stwo_m31_add(r4838, r4964);
    out_cols[238u][row] = r4964;
    unsigned r4968 = stwo_m31_mul(r4967, r11);
    unsigned r4969 = stwo_m31_add(r4968, r10);
    sub_words[128u * row_count + row] = r4969;
    unsigned r4970 = stwo_m31_add(r4968, r10);
    out_cols[239u][row] = r4968;
    lookup_words[291u * row_count + row] = r4970;
    unsigned r4971 = input_cols[16u][row];
    unsigned r4972 = input_cols[17u][row];
    unsigned r4973 = input_cols[18u][row];
    unsigned r4974 = input_cols[19u][row];
    unsigned r4975 = input_cols[20u][row];
    unsigned r4976 = input_cols[21u][row];
    unsigned r4977 = input_cols[22u][row];
    unsigned r4978 = input_cols[23u][row];
    unsigned r4979 = input_cols[24u][row];
    unsigned r4980 = input_cols[25u][row];
    unsigned r4981 = input_cols[26u][row];
    unsigned r4982 = input_cols[27u][row];
    unsigned r4983 = input_cols[28u][row];
    unsigned r4984 = input_cols[29u][row];
    unsigned r4985 = input_cols[30u][row];
    unsigned r4986 = input_cols[31u][row];
    unsigned r4987 = input_cols[32u][row];
    unsigned r4988 = input_cols[33u][row];
    unsigned r4989 = input_cols[34u][row];
    unsigned r4990 = input_cols[35u][row];
    unsigned r4991 = input_cols[36u][row];
    unsigned r4992 = input_cols[37u][row];
    unsigned r4993 = input_cols[38u][row];
    unsigned r4994 = input_cols[39u][row];
    unsigned r4995 = input_cols[40u][row];
    unsigned r4996 = input_cols[41u][row];
    unsigned r4997 = input_cols[42u][row];
    unsigned r4998 = input_cols[43u][row];
    const unsigned dargs7[56] = { r4971, r4972, r4973, r4974, r4975, r4976, r4977, r4978, r4979, r4980, r4981, r4982, r4983, r4984, r4985, r4986, r4987, r4988, r4989, r4990, r4991, r4992, r4993, r4994, r4995, r4996, r4997, r4998, r3534, r3535, r3536, r3537, r3538, r3539, r3540, r3541, r3542, r3543, r3544, r3545, r3546, r3547, r3548, r3549, r3550, r3551, r3552, r3553, r3554, r3555, r3556, r3557, r3558, r3559, r3560, r3561 };
    unsigned douts7[28];
    stwo_wit_deduce_felt_sub(dargs7, douts7);
    unsigned r4999 = douts7[0];
    unsigned r5000 = douts7[1];
    unsigned r5001 = douts7[2];
    unsigned r5002 = douts7[3];
    unsigned r5003 = douts7[4];
    unsigned r5004 = douts7[5];
    unsigned r5005 = douts7[6];
    unsigned r5006 = douts7[7];
    unsigned r5007 = douts7[8];
    unsigned r5008 = douts7[9];
    unsigned r5009 = douts7[10];
    unsigned r5010 = douts7[11];
    unsigned r5011 = douts7[12];
    unsigned r5012 = douts7[13];
    unsigned r5013 = douts7[14];
    unsigned r5014 = douts7[15];
    unsigned r5015 = douts7[16];
    unsigned r5016 = douts7[17];
    unsigned r5017 = douts7[18];
    unsigned r5018 = douts7[19];
    unsigned r5019 = douts7[20];
    unsigned r5020 = douts7[21];
    unsigned r5021 = douts7[22];
    unsigned r5022 = douts7[23];
    unsigned r5023 = douts7[24];
    unsigned r5024 = douts7[25];
    unsigned r5025 = douts7[26];
    unsigned r5026 = douts7[27];
    const unsigned dargs8[56] = { r1789, r1790, r1791, r1792, r1793, r1794, r1795, r1796, r1797, r1798, r1799, r1800, r1801, r1802, r1803, r1804, r1805, r1806, r1807, r1808, r1809, r1810, r1811, r1812, r1813, r1814, r1815, r1816, r4999, r5000, r5001, r5002, r5003, r5004, r5005, r5006, r5007, r5008, r5009, r5010, r5011, r5012, r5013, r5014, r5015, r5016, r5017, r5018, r5019, r5020, r5021, r5022, r5023, r5024, r5025, r5026 };
    unsigned douts8[28];
    stwo_wit_deduce_felt_mul(dargs8, douts8);
    unsigned r5027 = douts8[0];
    unsigned r5028 = douts8[1];
    unsigned r5029 = douts8[2];
    unsigned r5030 = douts8[3];
    unsigned r5031 = douts8[4];
    unsigned r5032 = douts8[5];
    unsigned r5033 = douts8[6];
    unsigned r5034 = douts8[7];
    unsigned r5035 = douts8[8];
    unsigned r5036 = douts8[9];
    unsigned r5037 = douts8[10];
    unsigned r5038 = douts8[11];
    unsigned r5039 = douts8[12];
    unsigned r5040 = douts8[13];
    unsigned r5041 = douts8[14];
    unsigned r5042 = douts8[15];
    unsigned r5043 = douts8[16];
    unsigned r5044 = douts8[17];
    unsigned r5045 = douts8[18];
    unsigned r5046 = douts8[19];
    unsigned r5047 = douts8[20];
    unsigned r5048 = douts8[21];
    unsigned r5049 = douts8[22];
    unsigned r5050 = douts8[23];
    unsigned r5051 = douts8[24];
    unsigned r5052 = douts8[25];
    unsigned r5053 = douts8[26];
    unsigned r5054 = douts8[27];
    unsigned r5055 = input_cols[44u][row];
    unsigned r5056 = input_cols[45u][row];
    unsigned r5057 = input_cols[46u][row];
    unsigned r5058 = input_cols[47u][row];
    unsigned r5059 = input_cols[48u][row];
    unsigned r5060 = input_cols[49u][row];
    unsigned r5061 = input_cols[50u][row];
    unsigned r5062 = input_cols[51u][row];
    unsigned r5063 = input_cols[52u][row];
    unsigned r5064 = input_cols[53u][row];
    unsigned r5065 = input_cols[54u][row];
    unsigned r5066 = input_cols[55u][row];
    unsigned r5067 = input_cols[56u][row];
    unsigned r5068 = input_cols[57u][row];
    unsigned r5069 = input_cols[58u][row];
    unsigned r5070 = input_cols[59u][row];
    unsigned r5071 = input_cols[60u][row];
    unsigned r5072 = input_cols[61u][row];
    unsigned r5073 = input_cols[62u][row];
    unsigned r5074 = input_cols[63u][row];
    unsigned r5075 = input_cols[64u][row];
    unsigned r5076 = input_cols[65u][row];
    unsigned r5077 = input_cols[66u][row];
    unsigned r5078 = input_cols[67u][row];
    unsigned r5079 = input_cols[68u][row];
    unsigned r5080 = input_cols[69u][row];
    unsigned r5081 = input_cols[70u][row];
    unsigned r5082 = input_cols[71u][row];
    const unsigned dargs9[56] = { r5027, r5028, r5029, r5030, r5031, r5032, r5033, r5034, r5035, r5036, r5037, r5038, r5039, r5040, r5041, r5042, r5043, r5044, r5045, r5046, r5047, r5048, r5049, r5050, r5051, r5052, r5053, r5054, r5055, r5056, r5057, r5058, r5059, r5060, r5061, r5062, r5063, r5064, r5065, r5066, r5067, r5068, r5069, r5070, r5071, r5072, r5073, r5074, r5075, r5076, r5077, r5078, r5079, r5080, r5081, r5082 };
    unsigned douts9[28];
    stwo_wit_deduce_felt_sub(dargs9, douts9);
    unsigned r5083 = douts9[0];
    unsigned r5084 = douts9[1];
    unsigned r5085 = douts9[2];
    unsigned r5086 = douts9[3];
    unsigned r5087 = douts9[4];
    unsigned r5088 = douts9[5];
    unsigned r5089 = douts9[6];
    unsigned r5090 = douts9[7];
    unsigned r5091 = douts9[8];
    unsigned r5092 = douts9[9];
    unsigned r5093 = douts9[10];
    unsigned r5094 = douts9[11];
    unsigned r5095 = douts9[12];
    unsigned r5096 = douts9[13];
    unsigned r5097 = douts9[14];
    unsigned r5098 = douts9[15];
    unsigned r5099 = douts9[16];
    unsigned r5100 = douts9[17];
    unsigned r5101 = douts9[18];
    unsigned r5102 = douts9[19];
    unsigned r5103 = douts9[20];
    unsigned r5104 = douts9[21];
    unsigned r5105 = douts9[22];
    unsigned r5106 = douts9[23];
    unsigned r5107 = douts9[24];
    unsigned r5108 = douts9[25];
    unsigned r5109 = douts9[26];
    unsigned r5110 = douts9[27];
    unsigned r5111 = stwo_m31_sub(r47, r3534);
    unsigned r5112 = stwo_m31_mul(r1789, r5111);
    unsigned r5113 = stwo_m31_sub(r76, r3535);
    unsigned r5114 = stwo_m31_mul(r1789, r5113);
    unsigned r5115 = stwo_m31_sub(r47, r3534);
    unsigned r5116 = stwo_m31_mul(r1790, r5115);
    unsigned r5117 = stwo_m31_add(r5114, r5116);
    unsigned r5118 = stwo_m31_sub(r105, r3536);
    unsigned r5119 = stwo_m31_mul(r1789, r5118);
    unsigned r5120 = stwo_m31_sub(r76, r3535);
    unsigned r5121 = stwo_m31_mul(r1790, r5120);
    unsigned r5122 = stwo_m31_add(r5119, r5121);
    unsigned r5123 = stwo_m31_sub(r47, r3534);
    unsigned r5124 = stwo_m31_mul(r1791, r5123);
    unsigned r5125 = stwo_m31_add(r5122, r5124);
    unsigned r5126 = stwo_m31_sub(r134, r3537);
    unsigned r5127 = stwo_m31_mul(r1789, r5126);
    unsigned r5128 = stwo_m31_sub(r105, r3536);
    unsigned r5129 = stwo_m31_mul(r1790, r5128);
    unsigned r5130 = stwo_m31_add(r5127, r5129);
    unsigned r5131 = stwo_m31_sub(r76, r3535);
    unsigned r5132 = stwo_m31_mul(r1791, r5131);
    unsigned r5133 = stwo_m31_add(r5130, r5132);
    unsigned r5134 = stwo_m31_sub(r47, r3534);
    unsigned r5135 = stwo_m31_mul(r1792, r5134);
    unsigned r5136 = stwo_m31_add(r5133, r5135);
    unsigned r5137 = stwo_m31_sub(r163, r3538);
    unsigned r5138 = stwo_m31_mul(r1789, r5137);
    unsigned r5139 = stwo_m31_sub(r134, r3537);
    unsigned r5140 = stwo_m31_mul(r1790, r5139);
    unsigned r5141 = stwo_m31_add(r5138, r5140);
    unsigned r5142 = stwo_m31_sub(r105, r3536);
    unsigned r5143 = stwo_m31_mul(r1791, r5142);
    unsigned r5144 = stwo_m31_add(r5141, r5143);
    unsigned r5145 = stwo_m31_sub(r76, r3535);
    unsigned r5146 = stwo_m31_mul(r1792, r5145);
    unsigned r5147 = stwo_m31_add(r5144, r5146);
    unsigned r5148 = stwo_m31_sub(r47, r3534);
    unsigned r5149 = stwo_m31_mul(r1793, r5148);
    unsigned r5150 = stwo_m31_add(r5147, r5149);
    unsigned r5151 = stwo_m31_sub(r192, r3539);
    unsigned r5152 = stwo_m31_mul(r1789, r5151);
    unsigned r5153 = stwo_m31_sub(r163, r3538);
    unsigned r5154 = stwo_m31_mul(r1790, r5153);
    unsigned r5155 = stwo_m31_add(r5152, r5154);
    unsigned r5156 = stwo_m31_sub(r134, r3537);
    unsigned r5157 = stwo_m31_mul(r1791, r5156);
    unsigned r5158 = stwo_m31_add(r5155, r5157);
    unsigned r5159 = stwo_m31_sub(r105, r3536);
    unsigned r5160 = stwo_m31_mul(r1792, r5159);
    unsigned r5161 = stwo_m31_add(r5158, r5160);
    unsigned r5162 = stwo_m31_sub(r76, r3535);
    unsigned r5163 = stwo_m31_mul(r1793, r5162);
    unsigned r5164 = stwo_m31_add(r5161, r5163);
    unsigned r5165 = stwo_m31_sub(r47, r3534);
    unsigned r5166 = stwo_m31_mul(r1794, r5165);
    unsigned r5167 = stwo_m31_add(r5164, r5166);
    unsigned r5168 = stwo_m31_sub(r221, r3540);
    unsigned r5169 = stwo_m31_mul(r1789, r5168);
    unsigned r5170 = stwo_m31_sub(r192, r3539);
    unsigned r5171 = stwo_m31_mul(r1790, r5170);
    unsigned r5172 = stwo_m31_add(r5169, r5171);
    unsigned r5173 = stwo_m31_sub(r163, r3538);
    unsigned r5174 = stwo_m31_mul(r1791, r5173);
    unsigned r5175 = stwo_m31_add(r5172, r5174);
    unsigned r5176 = stwo_m31_sub(r134, r3537);
    unsigned r5177 = stwo_m31_mul(r1792, r5176);
    unsigned r5178 = stwo_m31_add(r5175, r5177);
    unsigned r5179 = stwo_m31_sub(r105, r3536);
    unsigned r5180 = stwo_m31_mul(r1793, r5179);
    unsigned r5181 = stwo_m31_add(r5178, r5180);
    unsigned r5182 = stwo_m31_sub(r76, r3535);
    unsigned r5183 = stwo_m31_mul(r1794, r5182);
    unsigned r5184 = stwo_m31_add(r5181, r5183);
    unsigned r5185 = stwo_m31_sub(r47, r3534);
    unsigned r5186 = stwo_m31_mul(r1795, r5185);
    unsigned r5187 = stwo_m31_add(r5184, r5186);
    unsigned r5188 = stwo_m31_sub(r221, r3540);
    unsigned r5189 = stwo_m31_mul(r1790, r5188);
    unsigned r5190 = stwo_m31_sub(r192, r3539);
    unsigned r5191 = stwo_m31_mul(r1791, r5190);
    unsigned r5192 = stwo_m31_add(r5189, r5191);
    unsigned r5193 = stwo_m31_sub(r163, r3538);
    unsigned r5194 = stwo_m31_mul(r1792, r5193);
    unsigned r5195 = stwo_m31_add(r5192, r5194);
    unsigned r5196 = stwo_m31_sub(r134, r3537);
    unsigned r5197 = stwo_m31_mul(r1793, r5196);
    unsigned r5198 = stwo_m31_add(r5195, r5197);
    unsigned r5199 = stwo_m31_sub(r105, r3536);
    unsigned r5200 = stwo_m31_mul(r1794, r5199);
    unsigned r5201 = stwo_m31_add(r5198, r5200);
    unsigned r5202 = stwo_m31_sub(r76, r3535);
    unsigned r5203 = stwo_m31_mul(r1795, r5202);
    unsigned r5204 = stwo_m31_add(r5201, r5203);
    unsigned r5205 = stwo_m31_sub(r221, r3540);
    unsigned r5206 = stwo_m31_mul(r1791, r5205);
    unsigned r5207 = stwo_m31_sub(r192, r3539);
    unsigned r5208 = stwo_m31_mul(r1792, r5207);
    unsigned r5209 = stwo_m31_add(r5206, r5208);
    unsigned r5210 = stwo_m31_sub(r163, r3538);
    unsigned r5211 = stwo_m31_mul(r1793, r5210);
    unsigned r5212 = stwo_m31_add(r5209, r5211);
    unsigned r5213 = stwo_m31_sub(r134, r3537);
    unsigned r5214 = stwo_m31_mul(r1794, r5213);
    unsigned r5215 = stwo_m31_add(r5212, r5214);
    unsigned r5216 = stwo_m31_sub(r105, r3536);
    unsigned r5217 = stwo_m31_mul(r1795, r5216);
    unsigned r5218 = stwo_m31_add(r5215, r5217);
    unsigned r5219 = stwo_m31_sub(r221, r3540);
    unsigned r5220 = stwo_m31_mul(r1792, r5219);
    unsigned r5221 = stwo_m31_sub(r192, r3539);
    unsigned r5222 = stwo_m31_mul(r1793, r5221);
    unsigned r5223 = stwo_m31_add(r5220, r5222);
    unsigned r5224 = stwo_m31_sub(r163, r3538);
    unsigned r5225 = stwo_m31_mul(r1794, r5224);
    unsigned r5226 = stwo_m31_add(r5223, r5225);
    unsigned r5227 = stwo_m31_sub(r134, r3537);
    unsigned r5228 = stwo_m31_mul(r1795, r5227);
    unsigned r5229 = stwo_m31_add(r5226, r5228);
    unsigned r5230 = stwo_m31_sub(r221, r3540);
    unsigned r5231 = stwo_m31_mul(r1793, r5230);
    unsigned r5232 = stwo_m31_sub(r192, r3539);
    unsigned r5233 = stwo_m31_mul(r1794, r5232);
    unsigned r5234 = stwo_m31_add(r5231, r5233);
    unsigned r5235 = stwo_m31_sub(r163, r3538);
    unsigned r5236 = stwo_m31_mul(r1795, r5235);
    unsigned r5237 = stwo_m31_add(r5234, r5236);
    unsigned r5238 = stwo_m31_sub(r221, r3540);
    unsigned r5239 = stwo_m31_mul(r1794, r5238);
    unsigned r5240 = stwo_m31_sub(r192, r3539);
    unsigned r5241 = stwo_m31_mul(r1795, r5240);
    unsigned r5242 = stwo_m31_add(r5239, r5241);
    unsigned r5243 = stwo_m31_sub(r221, r3540);
    unsigned r5244 = stwo_m31_mul(r1795, r5243);
    unsigned r5245 = stwo_m31_sub(r250, r3541);
    unsigned r5246 = stwo_m31_mul(r1796, r5245);
    unsigned r5247 = stwo_m31_sub(r279, r3542);
    unsigned r5248 = stwo_m31_mul(r1796, r5247);
    unsigned r5249 = stwo_m31_sub(r250, r3541);
    unsigned r5250 = stwo_m31_mul(r1797, r5249);
    unsigned r5251 = stwo_m31_add(r5248, r5250);
    unsigned r5252 = stwo_m31_sub(r308, r3543);
    unsigned r5253 = stwo_m31_mul(r1796, r5252);
    unsigned r5254 = stwo_m31_sub(r279, r3542);
    unsigned r5255 = stwo_m31_mul(r1797, r5254);
    unsigned r5256 = stwo_m31_add(r5253, r5255);
    unsigned r5257 = stwo_m31_sub(r250, r3541);
    unsigned r5258 = stwo_m31_mul(r1798, r5257);
    unsigned r5259 = stwo_m31_add(r5256, r5258);
    unsigned r5260 = stwo_m31_sub(r337, r3544);
    unsigned r5261 = stwo_m31_mul(r1796, r5260);
    unsigned r5262 = stwo_m31_sub(r308, r3543);
    unsigned r5263 = stwo_m31_mul(r1797, r5262);
    unsigned r5264 = stwo_m31_add(r5261, r5263);
    unsigned r5265 = stwo_m31_sub(r279, r3542);
    unsigned r5266 = stwo_m31_mul(r1798, r5265);
    unsigned r5267 = stwo_m31_add(r5264, r5266);
    unsigned r5268 = stwo_m31_sub(r250, r3541);
    unsigned r5269 = stwo_m31_mul(r1799, r5268);
    unsigned r5270 = stwo_m31_add(r5267, r5269);
    unsigned r5271 = stwo_m31_sub(r366, r3545);
    unsigned r5272 = stwo_m31_mul(r1796, r5271);
    unsigned r5273 = stwo_m31_sub(r337, r3544);
    unsigned r5274 = stwo_m31_mul(r1797, r5273);
    unsigned r5275 = stwo_m31_add(r5272, r5274);
    unsigned r5276 = stwo_m31_sub(r308, r3543);
    unsigned r5277 = stwo_m31_mul(r1798, r5276);
    unsigned r5278 = stwo_m31_add(r5275, r5277);
    unsigned r5279 = stwo_m31_sub(r279, r3542);
    unsigned r5280 = stwo_m31_mul(r1799, r5279);
    unsigned r5281 = stwo_m31_add(r5278, r5280);
    unsigned r5282 = stwo_m31_sub(r250, r3541);
    unsigned r5283 = stwo_m31_mul(r1800, r5282);
    unsigned r5284 = stwo_m31_add(r5281, r5283);
    unsigned r5285 = stwo_m31_sub(r395, r3546);
    unsigned r5286 = stwo_m31_mul(r1796, r5285);
    unsigned r5287 = stwo_m31_sub(r366, r3545);
    unsigned r5288 = stwo_m31_mul(r1797, r5287);
    unsigned r5289 = stwo_m31_add(r5286, r5288);
    unsigned r5290 = stwo_m31_sub(r337, r3544);
    unsigned r5291 = stwo_m31_mul(r1798, r5290);
    unsigned r5292 = stwo_m31_add(r5289, r5291);
    unsigned r5293 = stwo_m31_sub(r308, r3543);
    unsigned r5294 = stwo_m31_mul(r1799, r5293);
    unsigned r5295 = stwo_m31_add(r5292, r5294);
    unsigned r5296 = stwo_m31_sub(r279, r3542);
    unsigned r5297 = stwo_m31_mul(r1800, r5296);
    unsigned r5298 = stwo_m31_add(r5295, r5297);
    unsigned r5299 = stwo_m31_sub(r250, r3541);
    unsigned r5300 = stwo_m31_mul(r1801, r5299);
    unsigned r5301 = stwo_m31_add(r5298, r5300);
    unsigned r5302 = stwo_m31_sub(r424, r3547);
    unsigned r5303 = stwo_m31_mul(r1796, r5302);
    unsigned r5304 = stwo_m31_sub(r395, r3546);
    unsigned r5305 = stwo_m31_mul(r1797, r5304);
    unsigned r5306 = stwo_m31_add(r5303, r5305);
    unsigned r5307 = stwo_m31_sub(r366, r3545);
    unsigned r5308 = stwo_m31_mul(r1798, r5307);
    unsigned r5309 = stwo_m31_add(r5306, r5308);
    unsigned r5310 = stwo_m31_sub(r337, r3544);
    unsigned r5311 = stwo_m31_mul(r1799, r5310);
    unsigned r5312 = stwo_m31_add(r5309, r5311);
    unsigned r5313 = stwo_m31_sub(r308, r3543);
    unsigned r5314 = stwo_m31_mul(r1800, r5313);
    unsigned r5315 = stwo_m31_add(r5312, r5314);
    unsigned r5316 = stwo_m31_sub(r279, r3542);
    unsigned r5317 = stwo_m31_mul(r1801, r5316);
    unsigned r5318 = stwo_m31_add(r5315, r5317);
    unsigned r5319 = stwo_m31_sub(r250, r3541);
    unsigned r5320 = stwo_m31_mul(r1802, r5319);
    unsigned r5321 = stwo_m31_add(r5318, r5320);
    unsigned r5322 = stwo_m31_sub(r424, r3547);
    unsigned r5323 = stwo_m31_mul(r1797, r5322);
    unsigned r5324 = stwo_m31_sub(r395, r3546);
    unsigned r5325 = stwo_m31_mul(r1798, r5324);
    unsigned r5326 = stwo_m31_add(r5323, r5325);
    unsigned r5327 = stwo_m31_sub(r366, r3545);
    unsigned r5328 = stwo_m31_mul(r1799, r5327);
    unsigned r5329 = stwo_m31_add(r5326, r5328);
    unsigned r5330 = stwo_m31_sub(r337, r3544);
    unsigned r5331 = stwo_m31_mul(r1800, r5330);
    unsigned r5332 = stwo_m31_add(r5329, r5331);
    unsigned r5333 = stwo_m31_sub(r308, r3543);
    unsigned r5334 = stwo_m31_mul(r1801, r5333);
    unsigned r5335 = stwo_m31_add(r5332, r5334);
    unsigned r5336 = stwo_m31_sub(r279, r3542);
    unsigned r5337 = stwo_m31_mul(r1802, r5336);
    unsigned r5338 = stwo_m31_add(r5335, r5337);
    unsigned r5339 = stwo_m31_sub(r424, r3547);
    unsigned r5340 = stwo_m31_mul(r1798, r5339);
    unsigned r5341 = stwo_m31_sub(r395, r3546);
    unsigned r5342 = stwo_m31_mul(r1799, r5341);
    unsigned r5343 = stwo_m31_add(r5340, r5342);
    unsigned r5344 = stwo_m31_sub(r366, r3545);
    unsigned r5345 = stwo_m31_mul(r1800, r5344);
    unsigned r5346 = stwo_m31_add(r5343, r5345);
    unsigned r5347 = stwo_m31_sub(r337, r3544);
    unsigned r5348 = stwo_m31_mul(r1801, r5347);
    unsigned r5349 = stwo_m31_add(r5346, r5348);
    unsigned r5350 = stwo_m31_sub(r308, r3543);
    unsigned r5351 = stwo_m31_mul(r1802, r5350);
    unsigned r5352 = stwo_m31_add(r5349, r5351);
    unsigned r5353 = stwo_m31_sub(r424, r3547);
    unsigned r5354 = stwo_m31_mul(r1799, r5353);
    unsigned r5355 = stwo_m31_sub(r395, r3546);
    unsigned r5356 = stwo_m31_mul(r1800, r5355);
    unsigned r5357 = stwo_m31_add(r5354, r5356);
    unsigned r5358 = stwo_m31_sub(r366, r3545);
    unsigned r5359 = stwo_m31_mul(r1801, r5358);
    unsigned r5360 = stwo_m31_add(r5357, r5359);
    unsigned r5361 = stwo_m31_sub(r337, r3544);
    unsigned r5362 = stwo_m31_mul(r1802, r5361);
    unsigned r5363 = stwo_m31_add(r5360, r5362);
    unsigned r5364 = stwo_m31_sub(r424, r3547);
    unsigned r5365 = stwo_m31_mul(r1800, r5364);
    unsigned r5366 = stwo_m31_sub(r395, r3546);
    unsigned r5367 = stwo_m31_mul(r1801, r5366);
    unsigned r5368 = stwo_m31_add(r5365, r5367);
    unsigned r5369 = stwo_m31_sub(r366, r3545);
    unsigned r5370 = stwo_m31_mul(r1802, r5369);
    unsigned r5371 = stwo_m31_add(r5368, r5370);
    unsigned r5372 = stwo_m31_sub(r424, r3547);
    unsigned r5373 = stwo_m31_mul(r1801, r5372);
    unsigned r5374 = stwo_m31_sub(r395, r3546);
    unsigned r5375 = stwo_m31_mul(r1802, r5374);
    unsigned r5376 = stwo_m31_add(r5373, r5375);
    unsigned r5377 = stwo_m31_sub(r424, r3547);
    unsigned r5378 = stwo_m31_mul(r1802, r5377);
    unsigned r5379 = stwo_m31_add(r1789, r1796);
    unsigned r5380 = stwo_m31_add(r1790, r1797);
    unsigned r5381 = stwo_m31_add(r1791, r1798);
    unsigned r5382 = stwo_m31_add(r1792, r1799);
    unsigned r5383 = stwo_m31_add(r1793, r1800);
    unsigned r5384 = stwo_m31_add(r1794, r1801);
    unsigned r5385 = stwo_m31_add(r1795, r1802);
    unsigned r5386 = stwo_m31_sub(r47, r3534);
    unsigned r5387 = stwo_m31_sub(r250, r3541);
    unsigned r5388 = stwo_m31_add(r5386, r5387);
    unsigned r5389 = stwo_m31_sub(r76, r3535);
    unsigned r5390 = stwo_m31_sub(r279, r3542);
    unsigned r5391 = stwo_m31_add(r5389, r5390);
    unsigned r5392 = stwo_m31_sub(r105, r3536);
    unsigned r5393 = stwo_m31_sub(r308, r3543);
    unsigned r5394 = stwo_m31_add(r5392, r5393);
    unsigned r5395 = stwo_m31_sub(r134, r3537);
    unsigned r5396 = stwo_m31_sub(r337, r3544);
    unsigned r5397 = stwo_m31_add(r5395, r5396);
    unsigned r5398 = stwo_m31_sub(r163, r3538);
    unsigned r5399 = stwo_m31_sub(r366, r3545);
    unsigned r5400 = stwo_m31_add(r5398, r5399);
    unsigned r5401 = stwo_m31_sub(r192, r3539);
    unsigned r5402 = stwo_m31_sub(r395, r3546);
    unsigned r5403 = stwo_m31_add(r5401, r5402);
    unsigned r5404 = stwo_m31_sub(r221, r3540);
    unsigned r5405 = stwo_m31_sub(r424, r3547);
    unsigned r5406 = stwo_m31_add(r5404, r5405);
    unsigned r5407 = stwo_m31_mul(r5379, r5388);
    unsigned r5408 = stwo_m31_sub(r5407, r5112);
    unsigned r5409 = stwo_m31_sub(r5408, r5246);
    unsigned r5410 = stwo_m31_add(r5204, r5409);
    unsigned r5411 = stwo_m31_mul(r5379, r5391);
    unsigned r5412 = stwo_m31_mul(r5380, r5388);
    unsigned r5413 = stwo_m31_add(r5411, r5412);
    unsigned r5414 = stwo_m31_sub(r5413, r5117);
    unsigned r5415 = stwo_m31_sub(r5414, r5251);
    unsigned r5416 = stwo_m31_add(r5218, r5415);
    unsigned r5417 = stwo_m31_mul(r5379, r5394);
    unsigned r5418 = stwo_m31_mul(r5380, r5391);
    unsigned r5419 = stwo_m31_add(r5417, r5418);
    unsigned r5420 = stwo_m31_mul(r5381, r5388);
    unsigned r5421 = stwo_m31_add(r5419, r5420);
    unsigned r5422 = stwo_m31_sub(r5421, r5125);
    unsigned r5423 = stwo_m31_sub(r5422, r5259);
    unsigned r5424 = stwo_m31_add(r5229, r5423);
    unsigned r5425 = stwo_m31_mul(r5379, r5397);
    unsigned r5426 = stwo_m31_mul(r5380, r5394);
    unsigned r5427 = stwo_m31_add(r5425, r5426);
    unsigned r5428 = stwo_m31_mul(r5381, r5391);
    unsigned r5429 = stwo_m31_add(r5427, r5428);
    unsigned r5430 = stwo_m31_mul(r5382, r5388);
    unsigned r5431 = stwo_m31_add(r5429, r5430);
    unsigned r5432 = stwo_m31_sub(r5431, r5136);
    unsigned r5433 = stwo_m31_sub(r5432, r5270);
    unsigned r5434 = stwo_m31_add(r5237, r5433);
    unsigned r5435 = stwo_m31_mul(r5379, r5400);
    unsigned r5436 = stwo_m31_mul(r5380, r5397);
    unsigned r5437 = stwo_m31_add(r5435, r5436);
    unsigned r5438 = stwo_m31_mul(r5381, r5394);
    unsigned r5439 = stwo_m31_add(r5437, r5438);
    unsigned r5440 = stwo_m31_mul(r5382, r5391);
    unsigned r5441 = stwo_m31_add(r5439, r5440);
    unsigned r5442 = stwo_m31_mul(r5383, r5388);
    unsigned r5443 = stwo_m31_add(r5441, r5442);
    unsigned r5444 = stwo_m31_sub(r5443, r5150);
    unsigned r5445 = stwo_m31_sub(r5444, r5284);
    unsigned r5446 = stwo_m31_add(r5242, r5445);
    unsigned r5447 = stwo_m31_mul(r5379, r5403);
    unsigned r5448 = stwo_m31_mul(r5380, r5400);
    unsigned r5449 = stwo_m31_add(r5447, r5448);
    unsigned r5450 = stwo_m31_mul(r5381, r5397);
    unsigned r5451 = stwo_m31_add(r5449, r5450);
    unsigned r5452 = stwo_m31_mul(r5382, r5394);
    unsigned r5453 = stwo_m31_add(r5451, r5452);
    unsigned r5454 = stwo_m31_mul(r5383, r5391);
    unsigned r5455 = stwo_m31_add(r5453, r5454);
    unsigned r5456 = stwo_m31_mul(r5384, r5388);
    unsigned r5457 = stwo_m31_add(r5455, r5456);
    unsigned r5458 = stwo_m31_sub(r5457, r5167);
    unsigned r5459 = stwo_m31_sub(r5458, r5301);
    unsigned r5460 = stwo_m31_add(r5244, r5459);
    unsigned r5461 = stwo_m31_mul(r5379, r5406);
    unsigned r5462 = stwo_m31_mul(r5380, r5403);
    unsigned r5463 = stwo_m31_add(r5461, r5462);
    unsigned r5464 = stwo_m31_mul(r5381, r5400);
    unsigned r5465 = stwo_m31_add(r5463, r5464);
    unsigned r5466 = stwo_m31_mul(r5382, r5397);
    unsigned r5467 = stwo_m31_add(r5465, r5466);
    unsigned r5468 = stwo_m31_mul(r5383, r5394);
    unsigned r5469 = stwo_m31_add(r5467, r5468);
    unsigned r5470 = stwo_m31_mul(r5384, r5391);
    unsigned r5471 = stwo_m31_add(r5469, r5470);
    unsigned r5472 = stwo_m31_mul(r5385, r5388);
    unsigned r5473 = stwo_m31_add(r5471, r5472);
    unsigned r5474 = stwo_m31_sub(r5473, r5187);
    unsigned r5475 = stwo_m31_sub(r5474, r5321);
    unsigned r5476 = stwo_m31_mul(r5380, r5406);
    unsigned r5477 = stwo_m31_mul(r5381, r5403);
    unsigned r5478 = stwo_m31_add(r5476, r5477);
    unsigned r5479 = stwo_m31_mul(r5382, r5400);
    unsigned r5480 = stwo_m31_add(r5478, r5479);
    unsigned r5481 = stwo_m31_mul(r5383, r5397);
    unsigned r5482 = stwo_m31_add(r5480, r5481);
    unsigned r5483 = stwo_m31_mul(r5384, r5394);
    unsigned r5484 = stwo_m31_add(r5482, r5483);
    unsigned r5485 = stwo_m31_mul(r5385, r5391);
    unsigned r5486 = stwo_m31_add(r5484, r5485);
    unsigned r5487 = stwo_m31_sub(r5486, r5204);
    unsigned r5488 = stwo_m31_sub(r5487, r5338);
    unsigned r5489 = stwo_m31_add(r5246, r5488);
    unsigned r5490 = stwo_m31_mul(r5381, r5406);
    unsigned r5491 = stwo_m31_mul(r5382, r5403);
    unsigned r5492 = stwo_m31_add(r5490, r5491);
    unsigned r5493 = stwo_m31_mul(r5383, r5400);
    unsigned r5494 = stwo_m31_add(r5492, r5493);
    unsigned r5495 = stwo_m31_mul(r5384, r5397);
    unsigned r5496 = stwo_m31_add(r5494, r5495);
    unsigned r5497 = stwo_m31_mul(r5385, r5394);
    unsigned r5498 = stwo_m31_add(r5496, r5497);
    unsigned r5499 = stwo_m31_sub(r5498, r5218);
    unsigned r5500 = stwo_m31_sub(r5499, r5352);
    unsigned r5501 = stwo_m31_add(r5251, r5500);
    unsigned r5502 = stwo_m31_mul(r5382, r5406);
    unsigned r5503 = stwo_m31_mul(r5383, r5403);
    unsigned r5504 = stwo_m31_add(r5502, r5503);
    unsigned r5505 = stwo_m31_mul(r5384, r5400);
    unsigned r5506 = stwo_m31_add(r5504, r5505);
    unsigned r5507 = stwo_m31_mul(r5385, r5397);
    unsigned r5508 = stwo_m31_add(r5506, r5507);
    unsigned r5509 = stwo_m31_sub(r5508, r5229);
    unsigned r5510 = stwo_m31_sub(r5509, r5363);
    unsigned r5511 = stwo_m31_add(r5259, r5510);
    unsigned r5512 = stwo_m31_mul(r5383, r5406);
    unsigned r5513 = stwo_m31_mul(r5384, r5403);
    unsigned r5514 = stwo_m31_add(r5512, r5513);
    unsigned r5515 = stwo_m31_mul(r5385, r5400);
    unsigned r5516 = stwo_m31_add(r5514, r5515);
    unsigned r5517 = stwo_m31_sub(r5516, r5237);
    unsigned r5518 = stwo_m31_sub(r5517, r5371);
    unsigned r5519 = stwo_m31_add(r5270, r5518);
    unsigned r5520 = stwo_m31_mul(r5384, r5406);
    unsigned r5521 = stwo_m31_mul(r5385, r5403);
    unsigned r5522 = stwo_m31_add(r5520, r5521);
    unsigned r5523 = stwo_m31_sub(r5522, r5242);
    unsigned r5524 = stwo_m31_sub(r5523, r5376);
    unsigned r5525 = stwo_m31_add(r5284, r5524);
    unsigned r5526 = stwo_m31_mul(r5385, r5406);
    unsigned r5527 = stwo_m31_sub(r5526, r5244);
    unsigned r5528 = stwo_m31_sub(r5527, r5378);
    unsigned r5529 = stwo_m31_add(r5301, r5528);
    unsigned r5530 = stwo_m31_sub(r453, r3548);
    unsigned r5531 = stwo_m31_mul(r1803, r5530);
    unsigned r5532 = stwo_m31_sub(r482, r3549);
    unsigned r5533 = stwo_m31_mul(r1803, r5532);
    unsigned r5534 = stwo_m31_sub(r453, r3548);
    unsigned r5535 = stwo_m31_mul(r1804, r5534);
    unsigned r5536 = stwo_m31_add(r5533, r5535);
    unsigned r5537 = stwo_m31_sub(r511, r3550);
    unsigned r5538 = stwo_m31_mul(r1803, r5537);
    unsigned r5539 = stwo_m31_sub(r482, r3549);
    unsigned r5540 = stwo_m31_mul(r1804, r5539);
    unsigned r5541 = stwo_m31_add(r5538, r5540);
    unsigned r5542 = stwo_m31_sub(r453, r3548);
    unsigned r5543 = stwo_m31_mul(r1805, r5542);
    unsigned r5544 = stwo_m31_add(r5541, r5543);
    unsigned r5545 = stwo_m31_sub(r540, r3551);
    unsigned r5546 = stwo_m31_mul(r1803, r5545);
    unsigned r5547 = stwo_m31_sub(r511, r3550);
    unsigned r5548 = stwo_m31_mul(r1804, r5547);
    unsigned r5549 = stwo_m31_add(r5546, r5548);
    unsigned r5550 = stwo_m31_sub(r482, r3549);
    unsigned r5551 = stwo_m31_mul(r1805, r5550);
    unsigned r5552 = stwo_m31_add(r5549, r5551);
    unsigned r5553 = stwo_m31_sub(r453, r3548);
    unsigned r5554 = stwo_m31_mul(r1806, r5553);
    unsigned r5555 = stwo_m31_add(r5552, r5554);
    unsigned r5556 = stwo_m31_sub(r569, r3552);
    unsigned r5557 = stwo_m31_mul(r1803, r5556);
    unsigned r5558 = stwo_m31_sub(r540, r3551);
    unsigned r5559 = stwo_m31_mul(r1804, r5558);
    unsigned r5560 = stwo_m31_add(r5557, r5559);
    unsigned r5561 = stwo_m31_sub(r511, r3550);
    unsigned r5562 = stwo_m31_mul(r1805, r5561);
    unsigned r5563 = stwo_m31_add(r5560, r5562);
    unsigned r5564 = stwo_m31_sub(r482, r3549);
    unsigned r5565 = stwo_m31_mul(r1806, r5564);
    unsigned r5566 = stwo_m31_add(r5563, r5565);
    unsigned r5567 = stwo_m31_sub(r453, r3548);
    unsigned r5568 = stwo_m31_mul(r1807, r5567);
    unsigned r5569 = stwo_m31_add(r5566, r5568);
    unsigned r5570 = stwo_m31_sub(r598, r3553);
    unsigned r5571 = stwo_m31_mul(r1803, r5570);
    unsigned r5572 = stwo_m31_sub(r569, r3552);
    unsigned r5573 = stwo_m31_mul(r1804, r5572);
    unsigned r5574 = stwo_m31_add(r5571, r5573);
    unsigned r5575 = stwo_m31_sub(r540, r3551);
    unsigned r5576 = stwo_m31_mul(r1805, r5575);
    unsigned r5577 = stwo_m31_add(r5574, r5576);
    unsigned r5578 = stwo_m31_sub(r511, r3550);
    unsigned r5579 = stwo_m31_mul(r1806, r5578);
    unsigned r5580 = stwo_m31_add(r5577, r5579);
    unsigned r5581 = stwo_m31_sub(r482, r3549);
    unsigned r5582 = stwo_m31_mul(r1807, r5581);
    unsigned r5583 = stwo_m31_add(r5580, r5582);
    unsigned r5584 = stwo_m31_sub(r453, r3548);
    unsigned r5585 = stwo_m31_mul(r1808, r5584);
    unsigned r5586 = stwo_m31_add(r5583, r5585);
    unsigned r5587 = stwo_m31_sub(r627, r3554);
    unsigned r5588 = stwo_m31_mul(r1803, r5587);
    unsigned r5589 = stwo_m31_sub(r598, r3553);
    unsigned r5590 = stwo_m31_mul(r1804, r5589);
    unsigned r5591 = stwo_m31_add(r5588, r5590);
    unsigned r5592 = stwo_m31_sub(r569, r3552);
    unsigned r5593 = stwo_m31_mul(r1805, r5592);
    unsigned r5594 = stwo_m31_add(r5591, r5593);
    unsigned r5595 = stwo_m31_sub(r540, r3551);
    unsigned r5596 = stwo_m31_mul(r1806, r5595);
    unsigned r5597 = stwo_m31_add(r5594, r5596);
    unsigned r5598 = stwo_m31_sub(r511, r3550);
    unsigned r5599 = stwo_m31_mul(r1807, r5598);
    unsigned r5600 = stwo_m31_add(r5597, r5599);
    unsigned r5601 = stwo_m31_sub(r482, r3549);
    unsigned r5602 = stwo_m31_mul(r1808, r5601);
    unsigned r5603 = stwo_m31_add(r5600, r5602);
    unsigned r5604 = stwo_m31_sub(r453, r3548);
    unsigned r5605 = stwo_m31_mul(r1809, r5604);
    unsigned r5606 = stwo_m31_add(r5603, r5605);
    unsigned r5607 = stwo_m31_sub(r627, r3554);
    unsigned r5608 = stwo_m31_mul(r1804, r5607);
    unsigned r5609 = stwo_m31_sub(r598, r3553);
    unsigned r5610 = stwo_m31_mul(r1805, r5609);
    unsigned r5611 = stwo_m31_add(r5608, r5610);
    unsigned r5612 = stwo_m31_sub(r569, r3552);
    unsigned r5613 = stwo_m31_mul(r1806, r5612);
    unsigned r5614 = stwo_m31_add(r5611, r5613);
    unsigned r5615 = stwo_m31_sub(r540, r3551);
    unsigned r5616 = stwo_m31_mul(r1807, r5615);
    unsigned r5617 = stwo_m31_add(r5614, r5616);
    unsigned r5618 = stwo_m31_sub(r511, r3550);
    unsigned r5619 = stwo_m31_mul(r1808, r5618);
    unsigned r5620 = stwo_m31_add(r5617, r5619);
    unsigned r5621 = stwo_m31_sub(r482, r3549);
    unsigned r5622 = stwo_m31_mul(r1809, r5621);
    unsigned r5623 = stwo_m31_add(r5620, r5622);
    unsigned r5624 = stwo_m31_sub(r627, r3554);
    unsigned r5625 = stwo_m31_mul(r1805, r5624);
    unsigned r5626 = stwo_m31_sub(r598, r3553);
    unsigned r5627 = stwo_m31_mul(r1806, r5626);
    unsigned r5628 = stwo_m31_add(r5625, r5627);
    unsigned r5629 = stwo_m31_sub(r569, r3552);
    unsigned r5630 = stwo_m31_mul(r1807, r5629);
    unsigned r5631 = stwo_m31_add(r5628, r5630);
    unsigned r5632 = stwo_m31_sub(r540, r3551);
    unsigned r5633 = stwo_m31_mul(r1808, r5632);
    unsigned r5634 = stwo_m31_add(r5631, r5633);
    unsigned r5635 = stwo_m31_sub(r511, r3550);
    unsigned r5636 = stwo_m31_mul(r1809, r5635);
    unsigned r5637 = stwo_m31_add(r5634, r5636);
    unsigned r5638 = stwo_m31_sub(r627, r3554);
    unsigned r5639 = stwo_m31_mul(r1806, r5638);
    unsigned r5640 = stwo_m31_sub(r598, r3553);
    unsigned r5641 = stwo_m31_mul(r1807, r5640);
    unsigned r5642 = stwo_m31_add(r5639, r5641);
    unsigned r5643 = stwo_m31_sub(r569, r3552);
    unsigned r5644 = stwo_m31_mul(r1808, r5643);
    unsigned r5645 = stwo_m31_add(r5642, r5644);
    unsigned r5646 = stwo_m31_sub(r540, r3551);
    unsigned r5647 = stwo_m31_mul(r1809, r5646);
    unsigned r5648 = stwo_m31_add(r5645, r5647);
    unsigned r5649 = stwo_m31_sub(r627, r3554);
    unsigned r5650 = stwo_m31_mul(r1807, r5649);
    unsigned r5651 = stwo_m31_sub(r598, r3553);
    unsigned r5652 = stwo_m31_mul(r1808, r5651);
    unsigned r5653 = stwo_m31_add(r5650, r5652);
    unsigned r5654 = stwo_m31_sub(r569, r3552);
    unsigned r5655 = stwo_m31_mul(r1809, r5654);
    unsigned r5656 = stwo_m31_add(r5653, r5655);
    unsigned r5657 = stwo_m31_sub(r627, r3554);
    unsigned r5658 = stwo_m31_mul(r1808, r5657);
    unsigned r5659 = stwo_m31_sub(r598, r3553);
    unsigned r5660 = stwo_m31_mul(r1809, r5659);
    unsigned r5661 = stwo_m31_add(r5658, r5660);
    unsigned r5662 = stwo_m31_sub(r627, r3554);
    unsigned r5663 = stwo_m31_mul(r1809, r5662);
    unsigned r5664 = stwo_m31_sub(r656, r3555);
    unsigned r5665 = stwo_m31_mul(r1810, r5664);
    unsigned r5666 = stwo_m31_sub(r685, r3556);
    unsigned r5667 = stwo_m31_mul(r1810, r5666);
    unsigned r5668 = stwo_m31_sub(r656, r3555);
    unsigned r5669 = stwo_m31_mul(r1811, r5668);
    unsigned r5670 = stwo_m31_add(r5667, r5669);
    unsigned r5671 = stwo_m31_sub(r714, r3557);
    unsigned r5672 = stwo_m31_mul(r1810, r5671);
    unsigned r5673 = stwo_m31_sub(r685, r3556);
    unsigned r5674 = stwo_m31_mul(r1811, r5673);
    unsigned r5675 = stwo_m31_add(r5672, r5674);
    unsigned r5676 = stwo_m31_sub(r656, r3555);
    unsigned r5677 = stwo_m31_mul(r1812, r5676);
    unsigned r5678 = stwo_m31_add(r5675, r5677);
    unsigned r5679 = stwo_m31_sub(r743, r3558);
    unsigned r5680 = stwo_m31_mul(r1810, r5679);
    unsigned r5681 = stwo_m31_sub(r714, r3557);
    unsigned r5682 = stwo_m31_mul(r1811, r5681);
    unsigned r5683 = stwo_m31_add(r5680, r5682);
    unsigned r5684 = stwo_m31_sub(r685, r3556);
    unsigned r5685 = stwo_m31_mul(r1812, r5684);
    unsigned r5686 = stwo_m31_add(r5683, r5685);
    unsigned r5687 = stwo_m31_sub(r656, r3555);
    unsigned r5688 = stwo_m31_mul(r1813, r5687);
    unsigned r5689 = stwo_m31_add(r5686, r5688);
    unsigned r5690 = stwo_m31_sub(r772, r3559);
    unsigned r5691 = stwo_m31_mul(r1810, r5690);
    unsigned r5692 = stwo_m31_sub(r743, r3558);
    unsigned r5693 = stwo_m31_mul(r1811, r5692);
    unsigned r5694 = stwo_m31_add(r5691, r5693);
    unsigned r5695 = stwo_m31_sub(r714, r3557);
    unsigned r5696 = stwo_m31_mul(r1812, r5695);
    unsigned r5697 = stwo_m31_add(r5694, r5696);
    unsigned r5698 = stwo_m31_sub(r685, r3556);
    unsigned r5699 = stwo_m31_mul(r1813, r5698);
    unsigned r5700 = stwo_m31_add(r5697, r5699);
    unsigned r5701 = stwo_m31_sub(r656, r3555);
    unsigned r5702 = stwo_m31_mul(r1814, r5701);
    unsigned r5703 = stwo_m31_add(r5700, r5702);
    unsigned r5704 = stwo_m31_sub(r801, r3560);
    unsigned r5705 = stwo_m31_mul(r1810, r5704);
    unsigned r5706 = stwo_m31_sub(r772, r3559);
    unsigned r5707 = stwo_m31_mul(r1811, r5706);
    unsigned r5708 = stwo_m31_add(r5705, r5707);
    unsigned r5709 = stwo_m31_sub(r743, r3558);
    unsigned r5710 = stwo_m31_mul(r1812, r5709);
    unsigned r5711 = stwo_m31_add(r5708, r5710);
    unsigned r5712 = stwo_m31_sub(r714, r3557);
    unsigned r5713 = stwo_m31_mul(r1813, r5712);
    unsigned r5714 = stwo_m31_add(r5711, r5713);
    unsigned r5715 = stwo_m31_sub(r685, r3556);
    unsigned r5716 = stwo_m31_mul(r1814, r5715);
    unsigned r5717 = stwo_m31_add(r5714, r5716);
    unsigned r5718 = stwo_m31_sub(r656, r3555);
    unsigned r5719 = stwo_m31_mul(r1815, r5718);
    unsigned r5720 = stwo_m31_add(r5717, r5719);
    unsigned r5721 = stwo_m31_sub(r830, r3561);
    unsigned r5722 = stwo_m31_mul(r1810, r5721);
    unsigned r5723 = stwo_m31_sub(r801, r3560);
    unsigned r5724 = stwo_m31_mul(r1811, r5723);
    unsigned r5725 = stwo_m31_add(r5722, r5724);
    unsigned r5726 = stwo_m31_sub(r772, r3559);
    unsigned r5727 = stwo_m31_mul(r1812, r5726);
    unsigned r5728 = stwo_m31_add(r5725, r5727);
    unsigned r5729 = stwo_m31_sub(r743, r3558);
    unsigned r5730 = stwo_m31_mul(r1813, r5729);
    unsigned r5731 = stwo_m31_add(r5728, r5730);
    unsigned r5732 = stwo_m31_sub(r714, r3557);
    unsigned r5733 = stwo_m31_mul(r1814, r5732);
    unsigned r5734 = stwo_m31_add(r5731, r5733);
    unsigned r5735 = stwo_m31_sub(r685, r3556);
    unsigned r5736 = stwo_m31_mul(r1815, r5735);
    unsigned r5737 = stwo_m31_add(r5734, r5736);
    unsigned r5738 = stwo_m31_sub(r656, r3555);
    unsigned r5739 = stwo_m31_mul(r1816, r5738);
    unsigned r5740 = stwo_m31_add(r5737, r5739);
    unsigned r5741 = stwo_m31_sub(r830, r3561);
    unsigned r5742 = stwo_m31_mul(r1811, r5741);
    unsigned r5743 = stwo_m31_sub(r801, r3560);
    unsigned r5744 = stwo_m31_mul(r1812, r5743);
    unsigned r5745 = stwo_m31_add(r5742, r5744);
    unsigned r5746 = stwo_m31_sub(r772, r3559);
    unsigned r5747 = stwo_m31_mul(r1813, r5746);
    unsigned r5748 = stwo_m31_add(r5745, r5747);
    unsigned r5749 = stwo_m31_sub(r743, r3558);
    unsigned r5750 = stwo_m31_mul(r1814, r5749);
    unsigned r5751 = stwo_m31_add(r5748, r5750);
    unsigned r5752 = stwo_m31_sub(r714, r3557);
    unsigned r5753 = stwo_m31_mul(r1815, r5752);
    unsigned r5754 = stwo_m31_add(r5751, r5753);
    unsigned r5755 = stwo_m31_sub(r685, r3556);
    unsigned r5756 = stwo_m31_mul(r1816, r5755);
    unsigned r5757 = stwo_m31_add(r5754, r5756);
    unsigned r5758 = stwo_m31_sub(r830, r3561);
    unsigned r5759 = stwo_m31_mul(r1812, r5758);
    unsigned r5760 = stwo_m31_sub(r801, r3560);
    unsigned r5761 = stwo_m31_mul(r1813, r5760);
    unsigned r5762 = stwo_m31_add(r5759, r5761);
    unsigned r5763 = stwo_m31_sub(r772, r3559);
    unsigned r5764 = stwo_m31_mul(r1814, r5763);
    unsigned r5765 = stwo_m31_add(r5762, r5764);
    unsigned r5766 = stwo_m31_sub(r743, r3558);
    unsigned r5767 = stwo_m31_mul(r1815, r5766);
    unsigned r5768 = stwo_m31_add(r5765, r5767);
    unsigned r5769 = stwo_m31_sub(r714, r3557);
    unsigned r5770 = stwo_m31_mul(r1816, r5769);
    unsigned r5771 = stwo_m31_add(r5768, r5770);
    unsigned r5772 = stwo_m31_sub(r830, r3561);
    unsigned r5773 = stwo_m31_mul(r1813, r5772);
    unsigned r5774 = stwo_m31_sub(r801, r3560);
    unsigned r5775 = stwo_m31_mul(r1814, r5774);
    unsigned r5776 = stwo_m31_add(r5773, r5775);
    unsigned r5777 = stwo_m31_sub(r772, r3559);
    unsigned r5778 = stwo_m31_mul(r1815, r5777);
    unsigned r5779 = stwo_m31_add(r5776, r5778);
    unsigned r5780 = stwo_m31_sub(r743, r3558);
    unsigned r5781 = stwo_m31_mul(r1816, r5780);
    unsigned r5782 = stwo_m31_add(r5779, r5781);
    unsigned r5783 = stwo_m31_sub(r830, r3561);
    unsigned r5784 = stwo_m31_mul(r1814, r5783);
    unsigned r5785 = stwo_m31_sub(r801, r3560);
    unsigned r5786 = stwo_m31_mul(r1815, r5785);
    unsigned r5787 = stwo_m31_add(r5784, r5786);
    unsigned r5788 = stwo_m31_sub(r772, r3559);
    unsigned r5789 = stwo_m31_mul(r1816, r5788);
    unsigned r5790 = stwo_m31_add(r5787, r5789);
    unsigned r5791 = stwo_m31_sub(r830, r3561);
    unsigned r5792 = stwo_m31_mul(r1815, r5791);
    unsigned r5793 = stwo_m31_sub(r801, r3560);
    unsigned r5794 = stwo_m31_mul(r1816, r5793);
    unsigned r5795 = stwo_m31_add(r5792, r5794);
    unsigned r5796 = stwo_m31_sub(r830, r3561);
    unsigned r5797 = stwo_m31_mul(r1816, r5796);
    unsigned r5798 = stwo_m31_add(r1803, r1810);
    unsigned r5799 = stwo_m31_add(r1804, r1811);
    unsigned r5800 = stwo_m31_add(r1805, r1812);
    unsigned r5801 = stwo_m31_add(r1806, r1813);
    unsigned r5802 = stwo_m31_add(r1807, r1814);
    unsigned r5803 = stwo_m31_add(r1808, r1815);
    unsigned r5804 = stwo_m31_add(r1809, r1816);
    unsigned r5805 = stwo_m31_sub(r453, r3548);
    unsigned r5806 = stwo_m31_sub(r656, r3555);
    unsigned r5807 = stwo_m31_add(r5805, r5806);
    unsigned r5808 = stwo_m31_sub(r482, r3549);
    unsigned r5809 = stwo_m31_sub(r685, r3556);
    unsigned r5810 = stwo_m31_add(r5808, r5809);
    unsigned r5811 = stwo_m31_sub(r511, r3550);
    unsigned r5812 = stwo_m31_sub(r714, r3557);
    unsigned r5813 = stwo_m31_add(r5811, r5812);
    unsigned r5814 = stwo_m31_sub(r540, r3551);
    unsigned r5815 = stwo_m31_sub(r743, r3558);
    unsigned r5816 = stwo_m31_add(r5814, r5815);
    unsigned r5817 = stwo_m31_sub(r569, r3552);
    unsigned r5818 = stwo_m31_sub(r772, r3559);
    unsigned r5819 = stwo_m31_add(r5817, r5818);
    unsigned r5820 = stwo_m31_sub(r598, r3553);
    unsigned r5821 = stwo_m31_sub(r801, r3560);
    unsigned r5822 = stwo_m31_add(r5820, r5821);
    unsigned r5823 = stwo_m31_sub(r627, r3554);
    unsigned r5824 = stwo_m31_sub(r830, r3561);
    unsigned r5825 = stwo_m31_add(r5823, r5824);
    unsigned r5826 = stwo_m31_mul(r5798, r5807);
    unsigned r5827 = stwo_m31_sub(r5826, r5531);
    unsigned r5828 = stwo_m31_sub(r5827, r5665);
    unsigned r5829 = stwo_m31_add(r5623, r5828);
    unsigned r5830 = stwo_m31_mul(r5798, r5810);
    unsigned r5831 = stwo_m31_mul(r5799, r5807);
    unsigned r5832 = stwo_m31_add(r5830, r5831);
    unsigned r5833 = stwo_m31_sub(r5832, r5536);
    unsigned r5834 = stwo_m31_sub(r5833, r5670);
    unsigned r5835 = stwo_m31_add(r5637, r5834);
    unsigned r5836 = stwo_m31_mul(r5798, r5813);
    unsigned r5837 = stwo_m31_mul(r5799, r5810);
    unsigned r5838 = stwo_m31_add(r5836, r5837);
    unsigned r5839 = stwo_m31_mul(r5800, r5807);
    unsigned r5840 = stwo_m31_add(r5838, r5839);
    unsigned r5841 = stwo_m31_sub(r5840, r5544);
    unsigned r5842 = stwo_m31_sub(r5841, r5678);
    unsigned r5843 = stwo_m31_add(r5648, r5842);
    unsigned r5844 = stwo_m31_mul(r5798, r5816);
    unsigned r5845 = stwo_m31_mul(r5799, r5813);
    unsigned r5846 = stwo_m31_add(r5844, r5845);
    unsigned r5847 = stwo_m31_mul(r5800, r5810);
    unsigned r5848 = stwo_m31_add(r5846, r5847);
    unsigned r5849 = stwo_m31_mul(r5801, r5807);
    unsigned r5850 = stwo_m31_add(r5848, r5849);
    unsigned r5851 = stwo_m31_sub(r5850, r5555);
    unsigned r5852 = stwo_m31_sub(r5851, r5689);
    unsigned r5853 = stwo_m31_add(r5656, r5852);
    unsigned r5854 = stwo_m31_mul(r5798, r5819);
    unsigned r5855 = stwo_m31_mul(r5799, r5816);
    unsigned r5856 = stwo_m31_add(r5854, r5855);
    unsigned r5857 = stwo_m31_mul(r5800, r5813);
    unsigned r5858 = stwo_m31_add(r5856, r5857);
    unsigned r5859 = stwo_m31_mul(r5801, r5810);
    unsigned r5860 = stwo_m31_add(r5858, r5859);
    unsigned r5861 = stwo_m31_mul(r5802, r5807);
    unsigned r5862 = stwo_m31_add(r5860, r5861);
    unsigned r5863 = stwo_m31_sub(r5862, r5569);
    unsigned r5864 = stwo_m31_sub(r5863, r5703);
    unsigned r5865 = stwo_m31_add(r5661, r5864);
    unsigned r5866 = stwo_m31_mul(r5798, r5822);
    unsigned r5867 = stwo_m31_mul(r5799, r5819);
    unsigned r5868 = stwo_m31_add(r5866, r5867);
    unsigned r5869 = stwo_m31_mul(r5800, r5816);
    unsigned r5870 = stwo_m31_add(r5868, r5869);
    unsigned r5871 = stwo_m31_mul(r5801, r5813);
    unsigned r5872 = stwo_m31_add(r5870, r5871);
    unsigned r5873 = stwo_m31_mul(r5802, r5810);
    unsigned r5874 = stwo_m31_add(r5872, r5873);
    unsigned r5875 = stwo_m31_mul(r5803, r5807);
    unsigned r5876 = stwo_m31_add(r5874, r5875);
    unsigned r5877 = stwo_m31_sub(r5876, r5586);
    unsigned r5878 = stwo_m31_sub(r5877, r5720);
    unsigned r5879 = stwo_m31_add(r5663, r5878);
    unsigned r5880 = stwo_m31_mul(r5798, r5825);
    unsigned r5881 = stwo_m31_mul(r5799, r5822);
    unsigned r5882 = stwo_m31_add(r5880, r5881);
    unsigned r5883 = stwo_m31_mul(r5800, r5819);
    unsigned r5884 = stwo_m31_add(r5882, r5883);
    unsigned r5885 = stwo_m31_mul(r5801, r5816);
    unsigned r5886 = stwo_m31_add(r5884, r5885);
    unsigned r5887 = stwo_m31_mul(r5802, r5813);
    unsigned r5888 = stwo_m31_add(r5886, r5887);
    unsigned r5889 = stwo_m31_mul(r5803, r5810);
    unsigned r5890 = stwo_m31_add(r5888, r5889);
    unsigned r5891 = stwo_m31_mul(r5804, r5807);
    unsigned r5892 = stwo_m31_add(r5890, r5891);
    unsigned r5893 = stwo_m31_sub(r5892, r5606);
    unsigned r5894 = stwo_m31_sub(r5893, r5740);
    unsigned r5895 = stwo_m31_mul(r5799, r5825);
    unsigned r5896 = stwo_m31_mul(r5800, r5822);
    unsigned r5897 = stwo_m31_add(r5895, r5896);
    unsigned r5898 = stwo_m31_mul(r5801, r5819);
    unsigned r5899 = stwo_m31_add(r5897, r5898);
    unsigned r5900 = stwo_m31_mul(r5802, r5816);
    unsigned r5901 = stwo_m31_add(r5899, r5900);
    unsigned r5902 = stwo_m31_mul(r5803, r5813);
    unsigned r5903 = stwo_m31_add(r5901, r5902);
    unsigned r5904 = stwo_m31_mul(r5804, r5810);
    unsigned r5905 = stwo_m31_add(r5903, r5904);
    unsigned r5906 = stwo_m31_sub(r5905, r5623);
    unsigned r5907 = stwo_m31_sub(r5906, r5757);
    unsigned r5908 = stwo_m31_add(r5665, r5907);
    unsigned r5909 = stwo_m31_mul(r5800, r5825);
    unsigned r5910 = stwo_m31_mul(r5801, r5822);
    unsigned r5911 = stwo_m31_add(r5909, r5910);
    unsigned r5912 = stwo_m31_mul(r5802, r5819);
    unsigned r5913 = stwo_m31_add(r5911, r5912);
    unsigned r5914 = stwo_m31_mul(r5803, r5816);
    unsigned r5915 = stwo_m31_add(r5913, r5914);
    unsigned r5916 = stwo_m31_mul(r5804, r5813);
    unsigned r5917 = stwo_m31_add(r5915, r5916);
    unsigned r5918 = stwo_m31_sub(r5917, r5637);
    unsigned r5919 = stwo_m31_sub(r5918, r5771);
    unsigned r5920 = stwo_m31_add(r5670, r5919);
    unsigned r5921 = stwo_m31_mul(r5801, r5825);
    unsigned r5922 = stwo_m31_mul(r5802, r5822);
    unsigned r5923 = stwo_m31_add(r5921, r5922);
    unsigned r5924 = stwo_m31_mul(r5803, r5819);
    unsigned r5925 = stwo_m31_add(r5923, r5924);
    unsigned r5926 = stwo_m31_mul(r5804, r5816);
    unsigned r5927 = stwo_m31_add(r5925, r5926);
    unsigned r5928 = stwo_m31_sub(r5927, r5648);
    unsigned r5929 = stwo_m31_sub(r5928, r5782);
    unsigned r5930 = stwo_m31_add(r5678, r5929);
    unsigned r5931 = stwo_m31_mul(r5802, r5825);
    unsigned r5932 = stwo_m31_mul(r5803, r5822);
    unsigned r5933 = stwo_m31_add(r5931, r5932);
    unsigned r5934 = stwo_m31_mul(r5804, r5819);
    unsigned r5935 = stwo_m31_add(r5933, r5934);
    unsigned r5936 = stwo_m31_sub(r5935, r5656);
    unsigned r5937 = stwo_m31_sub(r5936, r5790);
    unsigned r5938 = stwo_m31_add(r5689, r5937);
    unsigned r5939 = stwo_m31_mul(r5803, r5825);
    unsigned r5940 = stwo_m31_mul(r5804, r5822);
    unsigned r5941 = stwo_m31_add(r5939, r5940);
    unsigned r5942 = stwo_m31_sub(r5941, r5661);
    unsigned r5943 = stwo_m31_sub(r5942, r5795);
    unsigned r5944 = stwo_m31_add(r5703, r5943);
    unsigned r5945 = stwo_m31_mul(r5804, r5825);
    unsigned r5946 = stwo_m31_sub(r5945, r5663);
    unsigned r5947 = stwo_m31_sub(r5946, r5797);
    unsigned r5948 = stwo_m31_add(r5720, r5947);
    unsigned r5949 = stwo_m31_add(r1789, r1803);
    out_cols[128u][row] = r1789;
    out_cols[142u][row] = r1803;
    sub_words[1u * row_count + row] = r1789;
    lookup_words[373u * row_count + row] = r1789;
    sub_words[79u * row_count + row] = r1803;
    lookup_words[490u * row_count + row] = r1803;
    unsigned r5950 = stwo_m31_add(r1790, r1804);
    out_cols[129u][row] = r1790;
    out_cols[143u][row] = r1804;
    sub_words[2u * row_count + row] = r1790;
    lookup_words[374u * row_count + row] = r1790;
    sub_words[80u * row_count + row] = r1804;
    lookup_words[491u * row_count + row] = r1804;
    unsigned r5951 = stwo_m31_add(r1791, r1805);
    out_cols[130u][row] = r1791;
    out_cols[144u][row] = r1805;
    sub_words[13u * row_count + row] = r1791;
    lookup_words[391u * row_count + row] = r1791;
    sub_words[3u * row_count + row] = r1805;
    lookup_words[376u * row_count + row] = r1805;
    unsigned r5952 = stwo_m31_add(r1792, r1806);
    out_cols[131u][row] = r1792;
    out_cols[145u][row] = r1806;
    sub_words[14u * row_count + row] = r1792;
    lookup_words[392u * row_count + row] = r1792;
    sub_words[4u * row_count + row] = r1806;
    lookup_words[377u * row_count + row] = r1806;
    unsigned r5953 = stwo_m31_add(r1793, r1807);
    out_cols[132u][row] = r1793;
    out_cols[146u][row] = r1807;
    sub_words[25u * row_count + row] = r1793;
    lookup_words[409u * row_count + row] = r1793;
    sub_words[15u * row_count + row] = r1807;
    lookup_words[394u * row_count + row] = r1807;
    unsigned r5954 = stwo_m31_add(r1794, r1808);
    out_cols[133u][row] = r1794;
    out_cols[147u][row] = r1808;
    sub_words[26u * row_count + row] = r1794;
    lookup_words[410u * row_count + row] = r1794;
    sub_words[16u * row_count + row] = r1808;
    lookup_words[395u * row_count + row] = r1808;
    unsigned r5955 = stwo_m31_add(r1795, r1809);
    out_cols[134u][row] = r1795;
    out_cols[148u][row] = r1809;
    sub_words[37u * row_count + row] = r1795;
    lookup_words[427u * row_count + row] = r1795;
    sub_words[27u * row_count + row] = r1809;
    lookup_words[412u * row_count + row] = r1809;
    unsigned r5956 = stwo_m31_add(r1796, r1810);
    out_cols[135u][row] = r1796;
    out_cols[149u][row] = r1810;
    sub_words[38u * row_count + row] = r1796;
    lookup_words[428u * row_count + row] = r1796;
    sub_words[28u * row_count + row] = r1810;
    lookup_words[413u * row_count + row] = r1810;
    unsigned r5957 = stwo_m31_add(r1797, r1811);
    out_cols[136u][row] = r1797;
    out_cols[150u][row] = r1811;
    sub_words[49u * row_count + row] = r1797;
    lookup_words[445u * row_count + row] = r1797;
    sub_words[39u * row_count + row] = r1811;
    lookup_words[430u * row_count + row] = r1811;
    unsigned r5958 = stwo_m31_add(r1798, r1812);
    out_cols[137u][row] = r1798;
    out_cols[151u][row] = r1812;
    sub_words[50u * row_count + row] = r1798;
    lookup_words[446u * row_count + row] = r1798;
    sub_words[40u * row_count + row] = r1812;
    lookup_words[431u * row_count + row] = r1812;
    unsigned r5959 = stwo_m31_add(r1799, r1813);
    out_cols[138u][row] = r1799;
    out_cols[152u][row] = r1813;
    sub_words[61u * row_count + row] = r1799;
    lookup_words[463u * row_count + row] = r1799;
    sub_words[51u * row_count + row] = r1813;
    lookup_words[448u * row_count + row] = r1813;
    unsigned r5960 = stwo_m31_add(r1800, r1814);
    out_cols[139u][row] = r1800;
    out_cols[153u][row] = r1814;
    sub_words[62u * row_count + row] = r1800;
    lookup_words[464u * row_count + row] = r1800;
    sub_words[52u * row_count + row] = r1814;
    lookup_words[449u * row_count + row] = r1814;
    unsigned r5961 = stwo_m31_add(r1801, r1815);
    out_cols[140u][row] = r1801;
    out_cols[154u][row] = r1815;
    sub_words[73u * row_count + row] = r1801;
    lookup_words[481u * row_count + row] = r1801;
    sub_words[63u * row_count + row] = r1815;
    lookup_words[466u * row_count + row] = r1815;
    unsigned r5962 = stwo_m31_add(r1802, r1816);
    out_cols[141u][row] = r1802;
    out_cols[155u][row] = r1816;
    sub_words[74u * row_count + row] = r1802;
    lookup_words[482u * row_count + row] = r1802;
    sub_words[64u * row_count + row] = r1816;
    lookup_words[467u * row_count + row] = r1816;
    unsigned r5963 = stwo_m31_sub(r47, r3534);
    out_cols[16u][row] = r47;
    out_cols[184u][row] = r3534;
    sub_words[5u * row_count + row] = r3534;
    lookup_words[379u * row_count + row] = r3534;
    lookup_words[17u * row_count + row] = r47;
    lookup_words[90u * row_count + row] = r3534;
    unsigned r5964 = stwo_m31_sub(r453, r3548);
    out_cols[30u][row] = r453;
    out_cols[198u][row] = r3548;
    sub_words[81u * row_count + row] = r3548;
    lookup_words[493u * row_count + row] = r3548;
    lookup_words[31u * row_count + row] = r453;
    lookup_words[104u * row_count + row] = r3548;
    unsigned r5965 = stwo_m31_add(r5963, r5964);
    unsigned r5966 = stwo_m31_sub(r76, r3535);
    out_cols[17u][row] = r76;
    out_cols[185u][row] = r3535;
    sub_words[6u * row_count + row] = r3535;
    lookup_words[380u * row_count + row] = r3535;
    lookup_words[18u * row_count + row] = r76;
    lookup_words[91u * row_count + row] = r3535;
    unsigned r5967 = stwo_m31_sub(r482, r3549);
    out_cols[31u][row] = r482;
    out_cols[199u][row] = r3549;
    sub_words[82u * row_count + row] = r3549;
    lookup_words[494u * row_count + row] = r3549;
    lookup_words[32u * row_count + row] = r482;
    lookup_words[105u * row_count + row] = r3549;
    unsigned r5968 = stwo_m31_add(r5966, r5967);
    unsigned r5969 = stwo_m31_sub(r105, r3536);
    out_cols[18u][row] = r105;
    out_cols[186u][row] = r3536;
    sub_words[17u * row_count + row] = r3536;
    lookup_words[397u * row_count + row] = r3536;
    lookup_words[19u * row_count + row] = r105;
    lookup_words[92u * row_count + row] = r3536;
    unsigned r5970 = stwo_m31_sub(r511, r3550);
    out_cols[32u][row] = r511;
    out_cols[200u][row] = r3550;
    sub_words[7u * row_count + row] = r3550;
    lookup_words[382u * row_count + row] = r3550;
    lookup_words[33u * row_count + row] = r511;
    lookup_words[106u * row_count + row] = r3550;
    unsigned r5971 = stwo_m31_add(r5969, r5970);
    unsigned r5972 = stwo_m31_sub(r134, r3537);
    out_cols[19u][row] = r134;
    out_cols[187u][row] = r3537;
    sub_words[18u * row_count + row] = r3537;
    lookup_words[398u * row_count + row] = r3537;
    lookup_words[20u * row_count + row] = r134;
    lookup_words[93u * row_count + row] = r3537;
    unsigned r5973 = stwo_m31_sub(r540, r3551);
    out_cols[33u][row] = r540;
    out_cols[201u][row] = r3551;
    sub_words[8u * row_count + row] = r3551;
    lookup_words[383u * row_count + row] = r3551;
    lookup_words[34u * row_count + row] = r540;
    lookup_words[107u * row_count + row] = r3551;
    unsigned r5974 = stwo_m31_add(r5972, r5973);
    unsigned r5975 = stwo_m31_sub(r163, r3538);
    out_cols[20u][row] = r163;
    out_cols[188u][row] = r3538;
    sub_words[29u * row_count + row] = r3538;
    lookup_words[415u * row_count + row] = r3538;
    lookup_words[21u * row_count + row] = r163;
    lookup_words[94u * row_count + row] = r3538;
    unsigned r5976 = stwo_m31_sub(r569, r3552);
    out_cols[34u][row] = r569;
    out_cols[202u][row] = r3552;
    sub_words[19u * row_count + row] = r3552;
    lookup_words[400u * row_count + row] = r3552;
    lookup_words[35u * row_count + row] = r569;
    lookup_words[108u * row_count + row] = r3552;
    unsigned r5977 = stwo_m31_add(r5975, r5976);
    unsigned r5978 = stwo_m31_sub(r192, r3539);
    out_cols[21u][row] = r192;
    out_cols[189u][row] = r3539;
    sub_words[30u * row_count + row] = r3539;
    lookup_words[416u * row_count + row] = r3539;
    lookup_words[22u * row_count + row] = r192;
    lookup_words[95u * row_count + row] = r3539;
    unsigned r5979 = stwo_m31_sub(r598, r3553);
    out_cols[35u][row] = r598;
    out_cols[203u][row] = r3553;
    sub_words[20u * row_count + row] = r3553;
    lookup_words[401u * row_count + row] = r3553;
    lookup_words[36u * row_count + row] = r598;
    lookup_words[109u * row_count + row] = r3553;
    unsigned r5980 = stwo_m31_add(r5978, r5979);
    unsigned r5981 = stwo_m31_sub(r221, r3540);
    out_cols[22u][row] = r221;
    out_cols[190u][row] = r3540;
    sub_words[41u * row_count + row] = r3540;
    lookup_words[433u * row_count + row] = r3540;
    lookup_words[23u * row_count + row] = r221;
    lookup_words[96u * row_count + row] = r3540;
    unsigned r5982 = stwo_m31_sub(r627, r3554);
    out_cols[36u][row] = r627;
    out_cols[204u][row] = r3554;
    sub_words[31u * row_count + row] = r3554;
    lookup_words[418u * row_count + row] = r3554;
    lookup_words[37u * row_count + row] = r627;
    lookup_words[110u * row_count + row] = r3554;
    unsigned r5983 = stwo_m31_add(r5981, r5982);
    unsigned r5984 = stwo_m31_sub(r250, r3541);
    out_cols[23u][row] = r250;
    out_cols[191u][row] = r3541;
    sub_words[42u * row_count + row] = r3541;
    lookup_words[434u * row_count + row] = r3541;
    lookup_words[24u * row_count + row] = r250;
    lookup_words[97u * row_count + row] = r3541;
    unsigned r5985 = stwo_m31_sub(r656, r3555);
    out_cols[37u][row] = r656;
    out_cols[205u][row] = r3555;
    sub_words[32u * row_count + row] = r3555;
    lookup_words[419u * row_count + row] = r3555;
    lookup_words[38u * row_count + row] = r656;
    lookup_words[111u * row_count + row] = r3555;
    unsigned r5986 = stwo_m31_add(r5984, r5985);
    unsigned r5987 = stwo_m31_sub(r279, r3542);
    out_cols[24u][row] = r279;
    out_cols[192u][row] = r3542;
    sub_words[53u * row_count + row] = r3542;
    lookup_words[451u * row_count + row] = r3542;
    lookup_words[25u * row_count + row] = r279;
    lookup_words[98u * row_count + row] = r3542;
    unsigned r5988 = stwo_m31_sub(r685, r3556);
    out_cols[38u][row] = r685;
    out_cols[206u][row] = r3556;
    sub_words[43u * row_count + row] = r3556;
    lookup_words[436u * row_count + row] = r3556;
    lookup_words[39u * row_count + row] = r685;
    lookup_words[112u * row_count + row] = r3556;
    unsigned r5989 = stwo_m31_add(r5987, r5988);
    unsigned r5990 = stwo_m31_sub(r308, r3543);
    out_cols[25u][row] = r308;
    out_cols[193u][row] = r3543;
    sub_words[54u * row_count + row] = r3543;
    lookup_words[452u * row_count + row] = r3543;
    lookup_words[26u * row_count + row] = r308;
    lookup_words[99u * row_count + row] = r3543;
    unsigned r5991 = stwo_m31_sub(r714, r3557);
    out_cols[39u][row] = r714;
    out_cols[207u][row] = r3557;
    sub_words[44u * row_count + row] = r3557;
    lookup_words[437u * row_count + row] = r3557;
    lookup_words[40u * row_count + row] = r714;
    lookup_words[113u * row_count + row] = r3557;
    unsigned r5992 = stwo_m31_add(r5990, r5991);
    unsigned r5993 = stwo_m31_sub(r337, r3544);
    out_cols[26u][row] = r337;
    out_cols[194u][row] = r3544;
    sub_words[65u * row_count + row] = r3544;
    lookup_words[469u * row_count + row] = r3544;
    lookup_words[27u * row_count + row] = r337;
    lookup_words[100u * row_count + row] = r3544;
    unsigned r5994 = stwo_m31_sub(r743, r3558);
    out_cols[40u][row] = r743;
    out_cols[208u][row] = r3558;
    sub_words[55u * row_count + row] = r3558;
    lookup_words[454u * row_count + row] = r3558;
    lookup_words[41u * row_count + row] = r743;
    lookup_words[114u * row_count + row] = r3558;
    unsigned r5995 = stwo_m31_add(r5993, r5994);
    unsigned r5996 = stwo_m31_sub(r366, r3545);
    out_cols[27u][row] = r366;
    out_cols[195u][row] = r3545;
    sub_words[66u * row_count + row] = r3545;
    lookup_words[470u * row_count + row] = r3545;
    lookup_words[28u * row_count + row] = r366;
    lookup_words[101u * row_count + row] = r3545;
    unsigned r5997 = stwo_m31_sub(r772, r3559);
    out_cols[41u][row] = r772;
    out_cols[209u][row] = r3559;
    sub_words[56u * row_count + row] = r3559;
    lookup_words[455u * row_count + row] = r3559;
    lookup_words[42u * row_count + row] = r772;
    lookup_words[115u * row_count + row] = r3559;
    unsigned r5998 = stwo_m31_add(r5996, r5997);
    unsigned r5999 = stwo_m31_sub(r395, r3546);
    out_cols[28u][row] = r395;
    out_cols[196u][row] = r3546;
    sub_words[75u * row_count + row] = r3546;
    lookup_words[484u * row_count + row] = r3546;
    lookup_words[29u * row_count + row] = r395;
    lookup_words[102u * row_count + row] = r3546;
    unsigned r6000 = stwo_m31_sub(r801, r3560);
    out_cols[42u][row] = r801;
    out_cols[210u][row] = r3560;
    sub_words[67u * row_count + row] = r3560;
    lookup_words[472u * row_count + row] = r3560;
    lookup_words[43u * row_count + row] = r801;
    lookup_words[116u * row_count + row] = r3560;
    unsigned r6001 = stwo_m31_add(r5999, r6000);
    unsigned r6002 = stwo_m31_sub(r424, r3547);
    out_cols[29u][row] = r424;
    out_cols[197u][row] = r3547;
    sub_words[76u * row_count + row] = r3547;
    lookup_words[485u * row_count + row] = r3547;
    lookup_words[30u * row_count + row] = r424;
    lookup_words[103u * row_count + row] = r3547;
    unsigned r6003 = stwo_m31_sub(r830, r3561);
    out_cols[43u][row] = r830;
    out_cols[211u][row] = r3561;
    sub_words[68u * row_count + row] = r3561;
    lookup_words[473u * row_count + row] = r3561;
    lookup_words[44u * row_count + row] = r830;
    lookup_words[117u * row_count + row] = r3561;
    unsigned r6004 = stwo_m31_add(r6002, r6003);
    unsigned r6005 = stwo_m31_mul(r5949, r5965);
    unsigned r6006 = stwo_m31_mul(r5949, r5968);
    unsigned r6007 = stwo_m31_mul(r5950, r5965);
    unsigned r6008 = stwo_m31_add(r6006, r6007);
    unsigned r6009 = stwo_m31_mul(r5949, r5971);
    unsigned r6010 = stwo_m31_mul(r5950, r5968);
    unsigned r6011 = stwo_m31_add(r6009, r6010);
    unsigned r6012 = stwo_m31_mul(r5951, r5965);
    unsigned r6013 = stwo_m31_add(r6011, r6012);
    unsigned r6014 = stwo_m31_mul(r5949, r5974);
    unsigned r6015 = stwo_m31_mul(r5950, r5971);
    unsigned r6016 = stwo_m31_add(r6014, r6015);
    unsigned r6017 = stwo_m31_mul(r5951, r5968);
    unsigned r6018 = stwo_m31_add(r6016, r6017);
    unsigned r6019 = stwo_m31_mul(r5952, r5965);
    unsigned r6020 = stwo_m31_add(r6018, r6019);
    unsigned r6021 = stwo_m31_mul(r5949, r5977);
    unsigned r6022 = stwo_m31_mul(r5950, r5974);
    unsigned r6023 = stwo_m31_add(r6021, r6022);
    unsigned r6024 = stwo_m31_mul(r5951, r5971);
    unsigned r6025 = stwo_m31_add(r6023, r6024);
    unsigned r6026 = stwo_m31_mul(r5952, r5968);
    unsigned r6027 = stwo_m31_add(r6025, r6026);
    unsigned r6028 = stwo_m31_mul(r5953, r5965);
    unsigned r6029 = stwo_m31_add(r6027, r6028);
    unsigned r6030 = stwo_m31_mul(r5949, r5980);
    unsigned r6031 = stwo_m31_mul(r5950, r5977);
    unsigned r6032 = stwo_m31_add(r6030, r6031);
    unsigned r6033 = stwo_m31_mul(r5951, r5974);
    unsigned r6034 = stwo_m31_add(r6032, r6033);
    unsigned r6035 = stwo_m31_mul(r5952, r5971);
    unsigned r6036 = stwo_m31_add(r6034, r6035);
    unsigned r6037 = stwo_m31_mul(r5953, r5968);
    unsigned r6038 = stwo_m31_add(r6036, r6037);
    unsigned r6039 = stwo_m31_mul(r5954, r5965);
    unsigned r6040 = stwo_m31_add(r6038, r6039);
    unsigned r6041 = stwo_m31_mul(r5949, r5983);
    unsigned r6042 = stwo_m31_mul(r5950, r5980);
    unsigned r6043 = stwo_m31_add(r6041, r6042);
    unsigned r6044 = stwo_m31_mul(r5951, r5977);
    unsigned r6045 = stwo_m31_add(r6043, r6044);
    unsigned r6046 = stwo_m31_mul(r5952, r5974);
    unsigned r6047 = stwo_m31_add(r6045, r6046);
    unsigned r6048 = stwo_m31_mul(r5953, r5971);
    unsigned r6049 = stwo_m31_add(r6047, r6048);
    unsigned r6050 = stwo_m31_mul(r5954, r5968);
    unsigned r6051 = stwo_m31_add(r6049, r6050);
    unsigned r6052 = stwo_m31_mul(r5955, r5965);
    unsigned r6053 = stwo_m31_add(r6051, r6052);
    unsigned r6054 = stwo_m31_mul(r5950, r5983);
    unsigned r6055 = stwo_m31_mul(r5951, r5980);
    unsigned r6056 = stwo_m31_add(r6054, r6055);
    unsigned r6057 = stwo_m31_mul(r5952, r5977);
    unsigned r6058 = stwo_m31_add(r6056, r6057);
    unsigned r6059 = stwo_m31_mul(r5953, r5974);
    unsigned r6060 = stwo_m31_add(r6058, r6059);
    unsigned r6061 = stwo_m31_mul(r5954, r5971);
    unsigned r6062 = stwo_m31_add(r6060, r6061);
    unsigned r6063 = stwo_m31_mul(r5955, r5968);
    unsigned r6064 = stwo_m31_add(r6062, r6063);
    unsigned r6065 = stwo_m31_mul(r5951, r5983);
    unsigned r6066 = stwo_m31_mul(r5952, r5980);
    unsigned r6067 = stwo_m31_add(r6065, r6066);
    unsigned r6068 = stwo_m31_mul(r5953, r5977);
    unsigned r6069 = stwo_m31_add(r6067, r6068);
    unsigned r6070 = stwo_m31_mul(r5954, r5974);
    unsigned r6071 = stwo_m31_add(r6069, r6070);
    unsigned r6072 = stwo_m31_mul(r5955, r5971);
    unsigned r6073 = stwo_m31_add(r6071, r6072);
    unsigned r6074 = stwo_m31_mul(r5952, r5983);
    unsigned r6075 = stwo_m31_mul(r5953, r5980);
    unsigned r6076 = stwo_m31_add(r6074, r6075);
    unsigned r6077 = stwo_m31_mul(r5954, r5977);
    unsigned r6078 = stwo_m31_add(r6076, r6077);
    unsigned r6079 = stwo_m31_mul(r5955, r5974);
    unsigned r6080 = stwo_m31_add(r6078, r6079);
    unsigned r6081 = stwo_m31_mul(r5953, r5983);
    unsigned r6082 = stwo_m31_mul(r5954, r5980);
    unsigned r6083 = stwo_m31_add(r6081, r6082);
    unsigned r6084 = stwo_m31_mul(r5955, r5977);
    unsigned r6085 = stwo_m31_add(r6083, r6084);
    unsigned r6086 = stwo_m31_mul(r5954, r5983);
    unsigned r6087 = stwo_m31_mul(r5955, r5980);
    unsigned r6088 = stwo_m31_add(r6086, r6087);
    unsigned r6089 = stwo_m31_mul(r5955, r5983);
    unsigned r6090 = stwo_m31_mul(r5956, r5986);
    unsigned r6091 = stwo_m31_mul(r5956, r5989);
    unsigned r6092 = stwo_m31_mul(r5957, r5986);
    unsigned r6093 = stwo_m31_add(r6091, r6092);
    unsigned r6094 = stwo_m31_mul(r5956, r5992);
    unsigned r6095 = stwo_m31_mul(r5957, r5989);
    unsigned r6096 = stwo_m31_add(r6094, r6095);
    unsigned r6097 = stwo_m31_mul(r5958, r5986);
    unsigned r6098 = stwo_m31_add(r6096, r6097);
    unsigned r6099 = stwo_m31_mul(r5956, r5995);
    unsigned r6100 = stwo_m31_mul(r5957, r5992);
    unsigned r6101 = stwo_m31_add(r6099, r6100);
    unsigned r6102 = stwo_m31_mul(r5958, r5989);
    unsigned r6103 = stwo_m31_add(r6101, r6102);
    unsigned r6104 = stwo_m31_mul(r5959, r5986);
    unsigned r6105 = stwo_m31_add(r6103, r6104);
    unsigned r6106 = stwo_m31_mul(r5956, r5998);
    unsigned r6107 = stwo_m31_mul(r5957, r5995);
    unsigned r6108 = stwo_m31_add(r6106, r6107);
    unsigned r6109 = stwo_m31_mul(r5958, r5992);
    unsigned r6110 = stwo_m31_add(r6108, r6109);
    unsigned r6111 = stwo_m31_mul(r5959, r5989);
    unsigned r6112 = stwo_m31_add(r6110, r6111);
    unsigned r6113 = stwo_m31_mul(r5960, r5986);
    unsigned r6114 = stwo_m31_add(r6112, r6113);
    unsigned r6115 = stwo_m31_mul(r5956, r6001);
    unsigned r6116 = stwo_m31_mul(r5957, r5998);
    unsigned r6117 = stwo_m31_add(r6115, r6116);
    unsigned r6118 = stwo_m31_mul(r5958, r5995);
    unsigned r6119 = stwo_m31_add(r6117, r6118);
    unsigned r6120 = stwo_m31_mul(r5959, r5992);
    unsigned r6121 = stwo_m31_add(r6119, r6120);
    unsigned r6122 = stwo_m31_mul(r5960, r5989);
    unsigned r6123 = stwo_m31_add(r6121, r6122);
    unsigned r6124 = stwo_m31_mul(r5961, r5986);
    unsigned r6125 = stwo_m31_add(r6123, r6124);
    unsigned r6126 = stwo_m31_mul(r5956, r6004);
    unsigned r6127 = stwo_m31_mul(r5957, r6001);
    unsigned r6128 = stwo_m31_add(r6126, r6127);
    unsigned r6129 = stwo_m31_mul(r5958, r5998);
    unsigned r6130 = stwo_m31_add(r6128, r6129);
    unsigned r6131 = stwo_m31_mul(r5959, r5995);
    unsigned r6132 = stwo_m31_add(r6130, r6131);
    unsigned r6133 = stwo_m31_mul(r5960, r5992);
    unsigned r6134 = stwo_m31_add(r6132, r6133);
    unsigned r6135 = stwo_m31_mul(r5961, r5989);
    unsigned r6136 = stwo_m31_add(r6134, r6135);
    unsigned r6137 = stwo_m31_mul(r5962, r5986);
    unsigned r6138 = stwo_m31_add(r6136, r6137);
    unsigned r6139 = stwo_m31_mul(r5957, r6004);
    unsigned r6140 = stwo_m31_mul(r5958, r6001);
    unsigned r6141 = stwo_m31_add(r6139, r6140);
    unsigned r6142 = stwo_m31_mul(r5959, r5998);
    unsigned r6143 = stwo_m31_add(r6141, r6142);
    unsigned r6144 = stwo_m31_mul(r5960, r5995);
    unsigned r6145 = stwo_m31_add(r6143, r6144);
    unsigned r6146 = stwo_m31_mul(r5961, r5992);
    unsigned r6147 = stwo_m31_add(r6145, r6146);
    unsigned r6148 = stwo_m31_mul(r5962, r5989);
    unsigned r6149 = stwo_m31_add(r6147, r6148);
    unsigned r6150 = stwo_m31_mul(r5958, r6004);
    unsigned r6151 = stwo_m31_mul(r5959, r6001);
    unsigned r6152 = stwo_m31_add(r6150, r6151);
    unsigned r6153 = stwo_m31_mul(r5960, r5998);
    unsigned r6154 = stwo_m31_add(r6152, r6153);
    unsigned r6155 = stwo_m31_mul(r5961, r5995);
    unsigned r6156 = stwo_m31_add(r6154, r6155);
    unsigned r6157 = stwo_m31_mul(r5962, r5992);
    unsigned r6158 = stwo_m31_add(r6156, r6157);
    unsigned r6159 = stwo_m31_mul(r5959, r6004);
    unsigned r6160 = stwo_m31_mul(r5960, r6001);
    unsigned r6161 = stwo_m31_add(r6159, r6160);
    unsigned r6162 = stwo_m31_mul(r5961, r5998);
    unsigned r6163 = stwo_m31_add(r6161, r6162);
    unsigned r6164 = stwo_m31_mul(r5962, r5995);
    unsigned r6165 = stwo_m31_add(r6163, r6164);
    unsigned r6166 = stwo_m31_mul(r5960, r6004);
    unsigned r6167 = stwo_m31_mul(r5961, r6001);
    unsigned r6168 = stwo_m31_add(r6166, r6167);
    unsigned r6169 = stwo_m31_mul(r5962, r5998);
    unsigned r6170 = stwo_m31_add(r6168, r6169);
    unsigned r6171 = stwo_m31_mul(r5961, r6004);
    unsigned r6172 = stwo_m31_mul(r5962, r6001);
    unsigned r6173 = stwo_m31_add(r6171, r6172);
    unsigned r6174 = stwo_m31_mul(r5962, r6004);
    unsigned r6175 = stwo_m31_add(r5949, r5956);
    unsigned r6176 = stwo_m31_add(r5950, r5957);
    unsigned r6177 = stwo_m31_add(r5951, r5958);
    unsigned r6178 = stwo_m31_add(r5952, r5959);
    unsigned r6179 = stwo_m31_add(r5953, r5960);
    unsigned r6180 = stwo_m31_add(r5954, r5961);
    unsigned r6181 = stwo_m31_add(r5955, r5962);
    unsigned r6182 = stwo_m31_add(r5965, r5986);
    unsigned r6183 = stwo_m31_add(r5968, r5989);
    unsigned r6184 = stwo_m31_add(r5971, r5992);
    unsigned r6185 = stwo_m31_add(r5974, r5995);
    unsigned r6186 = stwo_m31_add(r5977, r5998);
    unsigned r6187 = stwo_m31_add(r5980, r6001);
    unsigned r6188 = stwo_m31_add(r5983, r6004);
    unsigned r6189 = stwo_m31_mul(r6175, r6182);
    unsigned r6190 = stwo_m31_sub(r6189, r6005);
    unsigned r6191 = stwo_m31_sub(r6190, r6090);
    unsigned r6192 = stwo_m31_add(r6064, r6191);
    unsigned r6193 = stwo_m31_mul(r6175, r6183);
    unsigned r6194 = stwo_m31_mul(r6176, r6182);
    unsigned r6195 = stwo_m31_add(r6193, r6194);
    unsigned r6196 = stwo_m31_sub(r6195, r6008);
    unsigned r6197 = stwo_m31_sub(r6196, r6093);
    unsigned r6198 = stwo_m31_add(r6073, r6197);
    unsigned r6199 = stwo_m31_mul(r6175, r6184);
    unsigned r6200 = stwo_m31_mul(r6176, r6183);
    unsigned r6201 = stwo_m31_add(r6199, r6200);
    unsigned r6202 = stwo_m31_mul(r6177, r6182);
    unsigned r6203 = stwo_m31_add(r6201, r6202);
    unsigned r6204 = stwo_m31_sub(r6203, r6013);
    unsigned r6205 = stwo_m31_sub(r6204, r6098);
    unsigned r6206 = stwo_m31_add(r6080, r6205);
    unsigned r6207 = stwo_m31_mul(r6175, r6185);
    unsigned r6208 = stwo_m31_mul(r6176, r6184);
    unsigned r6209 = stwo_m31_add(r6207, r6208);
    unsigned r6210 = stwo_m31_mul(r6177, r6183);
    unsigned r6211 = stwo_m31_add(r6209, r6210);
    unsigned r6212 = stwo_m31_mul(r6178, r6182);
    unsigned r6213 = stwo_m31_add(r6211, r6212);
    unsigned r6214 = stwo_m31_sub(r6213, r6020);
    unsigned r6215 = stwo_m31_sub(r6214, r6105);
    unsigned r6216 = stwo_m31_add(r6085, r6215);
    unsigned r6217 = stwo_m31_mul(r6175, r6186);
    unsigned r6218 = stwo_m31_mul(r6176, r6185);
    unsigned r6219 = stwo_m31_add(r6217, r6218);
    unsigned r6220 = stwo_m31_mul(r6177, r6184);
    unsigned r6221 = stwo_m31_add(r6219, r6220);
    unsigned r6222 = stwo_m31_mul(r6178, r6183);
    unsigned r6223 = stwo_m31_add(r6221, r6222);
    unsigned r6224 = stwo_m31_mul(r6179, r6182);
    unsigned r6225 = stwo_m31_add(r6223, r6224);
    unsigned r6226 = stwo_m31_sub(r6225, r6029);
    unsigned r6227 = stwo_m31_sub(r6226, r6114);
    unsigned r6228 = stwo_m31_add(r6088, r6227);
    unsigned r6229 = stwo_m31_mul(r6175, r6187);
    unsigned r6230 = stwo_m31_mul(r6176, r6186);
    unsigned r6231 = stwo_m31_add(r6229, r6230);
    unsigned r6232 = stwo_m31_mul(r6177, r6185);
    unsigned r6233 = stwo_m31_add(r6231, r6232);
    unsigned r6234 = stwo_m31_mul(r6178, r6184);
    unsigned r6235 = stwo_m31_add(r6233, r6234);
    unsigned r6236 = stwo_m31_mul(r6179, r6183);
    unsigned r6237 = stwo_m31_add(r6235, r6236);
    unsigned r6238 = stwo_m31_mul(r6180, r6182);
    unsigned r6239 = stwo_m31_add(r6237, r6238);
    unsigned r6240 = stwo_m31_sub(r6239, r6040);
    unsigned r6241 = stwo_m31_sub(r6240, r6125);
    unsigned r6242 = stwo_m31_add(r6089, r6241);
    unsigned r6243 = stwo_m31_mul(r6175, r6188);
    unsigned r6244 = stwo_m31_mul(r6176, r6187);
    unsigned r6245 = stwo_m31_add(r6243, r6244);
    unsigned r6246 = stwo_m31_mul(r6177, r6186);
    unsigned r6247 = stwo_m31_add(r6245, r6246);
    unsigned r6248 = stwo_m31_mul(r6178, r6185);
    unsigned r6249 = stwo_m31_add(r6247, r6248);
    unsigned r6250 = stwo_m31_mul(r6179, r6184);
    unsigned r6251 = stwo_m31_add(r6249, r6250);
    unsigned r6252 = stwo_m31_mul(r6180, r6183);
    unsigned r6253 = stwo_m31_add(r6251, r6252);
    unsigned r6254 = stwo_m31_mul(r6181, r6182);
    unsigned r6255 = stwo_m31_add(r6253, r6254);
    unsigned r6256 = stwo_m31_sub(r6255, r6053);
    unsigned r6257 = stwo_m31_sub(r6256, r6138);
    unsigned r6258 = stwo_m31_mul(r6176, r6188);
    unsigned r6259 = stwo_m31_mul(r6177, r6187);
    unsigned r6260 = stwo_m31_add(r6258, r6259);
    unsigned r6261 = stwo_m31_mul(r6178, r6186);
    unsigned r6262 = stwo_m31_add(r6260, r6261);
    unsigned r6263 = stwo_m31_mul(r6179, r6185);
    unsigned r6264 = stwo_m31_add(r6262, r6263);
    unsigned r6265 = stwo_m31_mul(r6180, r6184);
    unsigned r6266 = stwo_m31_add(r6264, r6265);
    unsigned r6267 = stwo_m31_mul(r6181, r6183);
    unsigned r6268 = stwo_m31_add(r6266, r6267);
    unsigned r6269 = stwo_m31_sub(r6268, r6064);
    unsigned r6270 = stwo_m31_sub(r6269, r6149);
    unsigned r6271 = stwo_m31_add(r6090, r6270);
    unsigned r6272 = stwo_m31_mul(r6177, r6188);
    unsigned r6273 = stwo_m31_mul(r6178, r6187);
    unsigned r6274 = stwo_m31_add(r6272, r6273);
    unsigned r6275 = stwo_m31_mul(r6179, r6186);
    unsigned r6276 = stwo_m31_add(r6274, r6275);
    unsigned r6277 = stwo_m31_mul(r6180, r6185);
    unsigned r6278 = stwo_m31_add(r6276, r6277);
    unsigned r6279 = stwo_m31_mul(r6181, r6184);
    unsigned r6280 = stwo_m31_add(r6278, r6279);
    unsigned r6281 = stwo_m31_sub(r6280, r6073);
    unsigned r6282 = stwo_m31_sub(r6281, r6158);
    unsigned r6283 = stwo_m31_add(r6093, r6282);
    unsigned r6284 = stwo_m31_mul(r6178, r6188);
    unsigned r6285 = stwo_m31_mul(r6179, r6187);
    unsigned r6286 = stwo_m31_add(r6284, r6285);
    unsigned r6287 = stwo_m31_mul(r6180, r6186);
    unsigned r6288 = stwo_m31_add(r6286, r6287);
    unsigned r6289 = stwo_m31_mul(r6181, r6185);
    unsigned r6290 = stwo_m31_add(r6288, r6289);
    unsigned r6291 = stwo_m31_sub(r6290, r6080);
    unsigned r6292 = stwo_m31_sub(r6291, r6165);
    unsigned r6293 = stwo_m31_add(r6098, r6292);
    unsigned r6294 = stwo_m31_mul(r6179, r6188);
    unsigned r6295 = stwo_m31_mul(r6180, r6187);
    unsigned r6296 = stwo_m31_add(r6294, r6295);
    unsigned r6297 = stwo_m31_mul(r6181, r6186);
    unsigned r6298 = stwo_m31_add(r6296, r6297);
    unsigned r6299 = stwo_m31_sub(r6298, r6085);
    unsigned r6300 = stwo_m31_sub(r6299, r6170);
    unsigned r6301 = stwo_m31_add(r6105, r6300);
    unsigned r6302 = stwo_m31_mul(r6180, r6188);
    unsigned r6303 = stwo_m31_mul(r6181, r6187);
    unsigned r6304 = stwo_m31_add(r6302, r6303);
    unsigned r6305 = stwo_m31_sub(r6304, r6088);
    unsigned r6306 = stwo_m31_sub(r6305, r6173);
    unsigned r6307 = stwo_m31_add(r6114, r6306);
    unsigned r6308 = stwo_m31_mul(r6181, r6188);
    unsigned r6309 = stwo_m31_sub(r6308, r6089);
    unsigned r6310 = stwo_m31_sub(r6309, r6174);
    unsigned r6311 = stwo_m31_add(r6125, r6310);
    unsigned r6312 = stwo_m31_sub(r6005, r5112);
    unsigned r6313 = stwo_m31_sub(r6312, r5531);
    unsigned r6314 = stwo_m31_add(r5489, r6313);
    unsigned r6315 = stwo_m31_sub(r6008, r5117);
    unsigned r6316 = stwo_m31_sub(r6315, r5536);
    unsigned r6317 = stwo_m31_add(r5501, r6316);
    unsigned r6318 = stwo_m31_sub(r6013, r5125);
    unsigned r6319 = stwo_m31_sub(r6318, r5544);
    unsigned r6320 = stwo_m31_add(r5511, r6319);
    unsigned r6321 = stwo_m31_sub(r6020, r5136);
    unsigned r6322 = stwo_m31_sub(r6321, r5555);
    unsigned r6323 = stwo_m31_add(r5519, r6322);
    unsigned r6324 = stwo_m31_sub(r6029, r5150);
    unsigned r6325 = stwo_m31_sub(r6324, r5569);
    unsigned r6326 = stwo_m31_add(r5525, r6325);
    unsigned r6327 = stwo_m31_sub(r6040, r5167);
    unsigned r6328 = stwo_m31_sub(r6327, r5586);
    unsigned r6329 = stwo_m31_add(r5529, r6328);
    unsigned r6330 = stwo_m31_sub(r6053, r5187);
    unsigned r6331 = stwo_m31_sub(r6330, r5606);
    unsigned r6332 = stwo_m31_add(r5321, r6331);
    unsigned r6333 = stwo_m31_sub(r6192, r5410);
    unsigned r6334 = stwo_m31_sub(r6333, r5829);
    unsigned r6335 = stwo_m31_add(r5338, r6334);
    unsigned r6336 = stwo_m31_sub(r6198, r5416);
    unsigned r6337 = stwo_m31_sub(r6336, r5835);
    unsigned r6338 = stwo_m31_add(r5352, r6337);
    unsigned r6339 = stwo_m31_sub(r6206, r5424);
    unsigned r6340 = stwo_m31_sub(r6339, r5843);
    unsigned r6341 = stwo_m31_add(r5363, r6340);
    unsigned r6342 = stwo_m31_sub(r6216, r5434);
    unsigned r6343 = stwo_m31_sub(r6342, r5853);
    unsigned r6344 = stwo_m31_add(r5371, r6343);
    unsigned r6345 = stwo_m31_sub(r6228, r5446);
    unsigned r6346 = stwo_m31_sub(r6345, r5865);
    unsigned r6347 = stwo_m31_add(r5376, r6346);
    unsigned r6348 = stwo_m31_sub(r6242, r5460);
    unsigned r6349 = stwo_m31_sub(r6348, r5879);
    unsigned r6350 = stwo_m31_add(r5378, r6349);
    unsigned r6351 = stwo_m31_sub(r6257, r5475);
    unsigned r6352 = stwo_m31_sub(r6351, r5894);
    unsigned r6353 = stwo_m31_sub(r6271, r5489);
    unsigned r6354 = stwo_m31_sub(r6353, r5908);
    unsigned r6355 = stwo_m31_add(r5531, r6354);
    unsigned r6356 = stwo_m31_sub(r6283, r5501);
    unsigned r6357 = stwo_m31_sub(r6356, r5920);
    unsigned r6358 = stwo_m31_add(r5536, r6357);
    unsigned r6359 = stwo_m31_sub(r6293, r5511);
    unsigned r6360 = stwo_m31_sub(r6359, r5930);
    unsigned r6361 = stwo_m31_add(r5544, r6360);
    unsigned r6362 = stwo_m31_sub(r6301, r5519);
    unsigned r6363 = stwo_m31_sub(r6362, r5938);
    unsigned r6364 = stwo_m31_add(r5555, r6363);
    unsigned r6365 = stwo_m31_sub(r6307, r5525);
    unsigned r6366 = stwo_m31_sub(r6365, r5944);
    unsigned r6367 = stwo_m31_add(r5569, r6366);
    unsigned r6368 = stwo_m31_sub(r6311, r5529);
    unsigned r6369 = stwo_m31_sub(r6368, r5948);
    unsigned r6370 = stwo_m31_add(r5586, r6369);
    unsigned r6371 = stwo_m31_sub(r6138, r5321);
    unsigned r6372 = stwo_m31_sub(r6371, r5740);
    unsigned r6373 = stwo_m31_add(r5606, r6372);
    unsigned r6374 = stwo_m31_sub(r6149, r5338);
    unsigned r6375 = stwo_m31_sub(r6374, r5757);
    unsigned r6376 = stwo_m31_add(r5829, r6375);
    unsigned r6377 = stwo_m31_sub(r6158, r5352);
    unsigned r6378 = stwo_m31_sub(r6377, r5771);
    unsigned r6379 = stwo_m31_add(r5835, r6378);
    unsigned r6380 = stwo_m31_sub(r6165, r5363);
    unsigned r6381 = stwo_m31_sub(r6380, r5782);
    unsigned r6382 = stwo_m31_add(r5843, r6381);
    unsigned r6383 = stwo_m31_sub(r6170, r5371);
    unsigned r6384 = stwo_m31_sub(r6383, r5790);
    unsigned r6385 = stwo_m31_add(r5853, r6384);
    unsigned r6386 = stwo_m31_sub(r6173, r5376);
    unsigned r6387 = stwo_m31_sub(r6386, r5795);
    unsigned r6388 = stwo_m31_add(r5865, r6387);
    unsigned r6389 = stwo_m31_sub(r6174, r5378);
    unsigned r6390 = stwo_m31_sub(r6389, r5797);
    unsigned r6391 = stwo_m31_add(r5879, r6390);
    unsigned r6392 = stwo_m31_add(r831, r5083);
    out_cols[44u][row] = r831;
    out_cols[240u][row] = r5083;
    sub_words[9u * row_count + row] = r5083;
    lookup_words[385u * row_count + row] = r5083;
    lookup_words[45u * row_count + row] = r831;
    lookup_words[118u * row_count + row] = r5083;
    unsigned r6393 = stwo_m31_sub(r5112, r6392);
    unsigned r6394 = stwo_m31_add(r860, r5084);
    out_cols[45u][row] = r860;
    out_cols[241u][row] = r5084;
    sub_words[10u * row_count + row] = r5084;
    lookup_words[386u * row_count + row] = r5084;
    lookup_words[46u * row_count + row] = r860;
    lookup_words[119u * row_count + row] = r5084;
    unsigned r6395 = stwo_m31_sub(r5117, r6394);
    unsigned r6396 = stwo_m31_add(r889, r5085);
    out_cols[46u][row] = r889;
    out_cols[242u][row] = r5085;
    sub_words[21u * row_count + row] = r5085;
    lookup_words[403u * row_count + row] = r5085;
    lookup_words[47u * row_count + row] = r889;
    lookup_words[120u * row_count + row] = r5085;
    unsigned r6397 = stwo_m31_sub(r5125, r6396);
    unsigned r6398 = stwo_m31_add(r918, r5086);
    out_cols[47u][row] = r918;
    out_cols[243u][row] = r5086;
    sub_words[22u * row_count + row] = r5086;
    lookup_words[404u * row_count + row] = r5086;
    lookup_words[48u * row_count + row] = r918;
    lookup_words[121u * row_count + row] = r5086;
    unsigned r6399 = stwo_m31_sub(r5136, r6398);
    unsigned r6400 = stwo_m31_add(r947, r5087);
    out_cols[48u][row] = r947;
    out_cols[244u][row] = r5087;
    sub_words[33u * row_count + row] = r5087;
    lookup_words[421u * row_count + row] = r5087;
    lookup_words[49u * row_count + row] = r947;
    lookup_words[122u * row_count + row] = r5087;
    unsigned r6401 = stwo_m31_sub(r5150, r6400);
    unsigned r6402 = stwo_m31_add(r976, r5088);
    out_cols[49u][row] = r976;
    out_cols[245u][row] = r5088;
    sub_words[34u * row_count + row] = r5088;
    lookup_words[422u * row_count + row] = r5088;
    lookup_words[50u * row_count + row] = r976;
    lookup_words[123u * row_count + row] = r5088;
    unsigned r6403 = stwo_m31_sub(r5167, r6402);
    unsigned r6404 = stwo_m31_add(r1005, r5089);
    out_cols[50u][row] = r1005;
    out_cols[246u][row] = r5089;
    sub_words[45u * row_count + row] = r5089;
    lookup_words[439u * row_count + row] = r5089;
    lookup_words[51u * row_count + row] = r1005;
    lookup_words[124u * row_count + row] = r5089;
    unsigned r6405 = stwo_m31_sub(r5187, r6404);
    unsigned r6406 = stwo_m31_add(r1034, r5090);
    out_cols[51u][row] = r1034;
    out_cols[247u][row] = r5090;
    sub_words[46u * row_count + row] = r5090;
    lookup_words[440u * row_count + row] = r5090;
    lookup_words[52u * row_count + row] = r1034;
    lookup_words[125u * row_count + row] = r5090;
    unsigned r6407 = stwo_m31_sub(r5410, r6406);
    unsigned r6408 = stwo_m31_add(r1063, r5091);
    out_cols[52u][row] = r1063;
    out_cols[248u][row] = r5091;
    sub_words[57u * row_count + row] = r5091;
    lookup_words[457u * row_count + row] = r5091;
    lookup_words[53u * row_count + row] = r1063;
    lookup_words[126u * row_count + row] = r5091;
    unsigned r6409 = stwo_m31_sub(r5416, r6408);
    unsigned r6410 = stwo_m31_add(r1092, r5092);
    out_cols[53u][row] = r1092;
    out_cols[249u][row] = r5092;
    sub_words[58u * row_count + row] = r5092;
    lookup_words[458u * row_count + row] = r5092;
    lookup_words[54u * row_count + row] = r1092;
    lookup_words[127u * row_count + row] = r5092;
    unsigned r6411 = stwo_m31_sub(r5424, r6410);
    unsigned r6412 = stwo_m31_add(r1121, r5093);
    out_cols[54u][row] = r1121;
    out_cols[250u][row] = r5093;
    sub_words[69u * row_count + row] = r5093;
    lookup_words[475u * row_count + row] = r5093;
    lookup_words[55u * row_count + row] = r1121;
    lookup_words[128u * row_count + row] = r5093;
    unsigned r6413 = stwo_m31_sub(r5434, r6412);
    unsigned r6414 = stwo_m31_add(r1150, r5094);
    out_cols[55u][row] = r1150;
    out_cols[251u][row] = r5094;
    sub_words[70u * row_count + row] = r5094;
    lookup_words[476u * row_count + row] = r5094;
    lookup_words[56u * row_count + row] = r1150;
    lookup_words[129u * row_count + row] = r5094;
    unsigned r6415 = stwo_m31_sub(r5446, r6414);
    unsigned r6416 = stwo_m31_add(r1179, r5095);
    out_cols[56u][row] = r1179;
    out_cols[252u][row] = r5095;
    sub_words[77u * row_count + row] = r5095;
    lookup_words[487u * row_count + row] = r5095;
    lookup_words[57u * row_count + row] = r1179;
    lookup_words[130u * row_count + row] = r5095;
    unsigned r6417 = stwo_m31_sub(r5460, r6416);
    unsigned r6418 = stwo_m31_add(r1208, r5096);
    out_cols[57u][row] = r1208;
    out_cols[253u][row] = r5096;
    sub_words[78u * row_count + row] = r5096;
    lookup_words[488u * row_count + row] = r5096;
    lookup_words[58u * row_count + row] = r1208;
    lookup_words[131u * row_count + row] = r5096;
    unsigned r6419 = stwo_m31_sub(r5475, r6418);
    unsigned r6420 = stwo_m31_add(r1237, r5097);
    out_cols[58u][row] = r1237;
    out_cols[254u][row] = r5097;
    sub_words[83u * row_count + row] = r5097;
    lookup_words[496u * row_count + row] = r5097;
    lookup_words[59u * row_count + row] = r1237;
    lookup_words[132u * row_count + row] = r5097;
    unsigned r6421 = stwo_m31_sub(r6314, r6420);
    unsigned r6422 = stwo_m31_add(r1266, r5098);
    out_cols[59u][row] = r1266;
    out_cols[255u][row] = r5098;
    sub_words[84u * row_count + row] = r5098;
    lookup_words[497u * row_count + row] = r5098;
    lookup_words[60u * row_count + row] = r1266;
    lookup_words[133u * row_count + row] = r5098;
    unsigned r6423 = stwo_m31_sub(r6317, r6422);
    unsigned r6424 = stwo_m31_add(r1295, r5099);
    out_cols[60u][row] = r1295;
    out_cols[256u][row] = r5099;
    sub_words[11u * row_count + row] = r5099;
    lookup_words[388u * row_count + row] = r5099;
    lookup_words[61u * row_count + row] = r1295;
    lookup_words[134u * row_count + row] = r5099;
    unsigned r6425 = stwo_m31_sub(r6320, r6424);
    unsigned r6426 = stwo_m31_add(r1324, r5100);
    out_cols[61u][row] = r1324;
    out_cols[257u][row] = r5100;
    sub_words[12u * row_count + row] = r5100;
    lookup_words[389u * row_count + row] = r5100;
    lookup_words[62u * row_count + row] = r1324;
    lookup_words[135u * row_count + row] = r5100;
    unsigned r6427 = stwo_m31_sub(r6323, r6426);
    unsigned r6428 = stwo_m31_add(r1353, r5101);
    out_cols[62u][row] = r1353;
    out_cols[258u][row] = r5101;
    sub_words[23u * row_count + row] = r5101;
    lookup_words[406u * row_count + row] = r5101;
    lookup_words[63u * row_count + row] = r1353;
    lookup_words[136u * row_count + row] = r5101;
    unsigned r6429 = stwo_m31_sub(r6326, r6428);
    unsigned r6430 = stwo_m31_add(r1382, r5102);
    out_cols[63u][row] = r1382;
    out_cols[259u][row] = r5102;
    sub_words[24u * row_count + row] = r5102;
    lookup_words[407u * row_count + row] = r5102;
    lookup_words[64u * row_count + row] = r1382;
    lookup_words[137u * row_count + row] = r5102;
    unsigned r6431 = stwo_m31_sub(r6329, r6430);
    unsigned r6432 = stwo_m31_add(r1411, r5103);
    out_cols[64u][row] = r1411;
    out_cols[260u][row] = r5103;
    sub_words[35u * row_count + row] = r5103;
    lookup_words[424u * row_count + row] = r5103;
    lookup_words[65u * row_count + row] = r1411;
    lookup_words[138u * row_count + row] = r5103;
    unsigned r6433 = stwo_m31_sub(r6332, r6432);
    unsigned r6434 = stwo_m31_add(r1440, r5104);
    out_cols[65u][row] = r1440;
    out_cols[261u][row] = r5104;
    sub_words[36u * row_count + row] = r5104;
    lookup_words[425u * row_count + row] = r5104;
    lookup_words[66u * row_count + row] = r1440;
    lookup_words[139u * row_count + row] = r5104;
    unsigned r6435 = stwo_m31_sub(r6335, r6434);
    unsigned r6436 = stwo_m31_add(r1469, r5105);
    out_cols[66u][row] = r1469;
    out_cols[262u][row] = r5105;
    sub_words[47u * row_count + row] = r5105;
    lookup_words[442u * row_count + row] = r5105;
    lookup_words[67u * row_count + row] = r1469;
    lookup_words[140u * row_count + row] = r5105;
    unsigned r6437 = stwo_m31_sub(r6338, r6436);
    unsigned r6438 = stwo_m31_add(r1498, r5106);
    out_cols[67u][row] = r1498;
    out_cols[263u][row] = r5106;
    sub_words[48u * row_count + row] = r5106;
    lookup_words[443u * row_count + row] = r5106;
    lookup_words[68u * row_count + row] = r1498;
    lookup_words[141u * row_count + row] = r5106;
    unsigned r6439 = stwo_m31_sub(r6341, r6438);
    unsigned r6440 = stwo_m31_add(r1527, r5107);
    out_cols[68u][row] = r1527;
    out_cols[264u][row] = r5107;
    sub_words[59u * row_count + row] = r5107;
    lookup_words[460u * row_count + row] = r5107;
    lookup_words[69u * row_count + row] = r1527;
    lookup_words[142u * row_count + row] = r5107;
    unsigned r6441 = stwo_m31_sub(r6344, r6440);
    unsigned r6442 = stwo_m31_add(r1556, r5108);
    out_cols[69u][row] = r1556;
    out_cols[265u][row] = r5108;
    sub_words[60u * row_count + row] = r5108;
    lookup_words[461u * row_count + row] = r5108;
    lookup_words[70u * row_count + row] = r1556;
    lookup_words[143u * row_count + row] = r5108;
    unsigned r6443 = stwo_m31_sub(r6347, r6442);
    unsigned r6444 = stwo_m31_add(r1585, r5109);
    out_cols[70u][row] = r1585;
    out_cols[266u][row] = r5109;
    sub_words[71u * row_count + row] = r5109;
    lookup_words[478u * row_count + row] = r5109;
    lookup_words[71u * row_count + row] = r1585;
    lookup_words[144u * row_count + row] = r5109;
    unsigned r6445 = stwo_m31_sub(r6350, r6444);
    unsigned r6446 = stwo_m31_add(r1614, r5110);
    out_cols[71u][row] = r1614;
    out_cols[267u][row] = r5110;
    sub_words[72u * row_count + row] = r5110;
    lookup_words[479u * row_count + row] = r5110;
    lookup_words[72u * row_count + row] = r1614;
    lookup_words[145u * row_count + row] = r5110;
    unsigned r6447 = stwo_m31_sub(r6352, r6446);
    unsigned r6448 = stwo_m31_mul(r5, r6393);
    unsigned r6449 = stwo_m31_mul(r3, r6435);
    unsigned r6450 = stwo_m31_sub(r6448, r6449);
    unsigned r6451 = stwo_m31_mul(r4, r5757);
    unsigned r6452 = stwo_m31_add(r6450, r6451);
    unsigned r6453 = stwo_m31_mul(r5, r6395);
    unsigned r6454 = stwo_m31_add(r6393, r6453);
    unsigned r6455 = stwo_m31_mul(r3, r6437);
    unsigned r6456 = stwo_m31_sub(r6454, r6455);
    unsigned r6457 = stwo_m31_mul(r4, r5771);
    unsigned r6458 = stwo_m31_add(r6456, r6457);
    unsigned r6459 = stwo_m31_mul(r5, r6397);
    unsigned r6460 = stwo_m31_add(r6395, r6459);
    unsigned r6461 = stwo_m31_mul(r3, r6439);
    unsigned r6462 = stwo_m31_sub(r6460, r6461);
    unsigned r6463 = stwo_m31_mul(r4, r5782);
    unsigned r6464 = stwo_m31_add(r6462, r6463);
    unsigned r6465 = stwo_m31_mul(r5, r6399);
    unsigned r6466 = stwo_m31_add(r6397, r6465);
    unsigned r6467 = stwo_m31_mul(r3, r6441);
    unsigned r6468 = stwo_m31_sub(r6466, r6467);
    unsigned r6469 = stwo_m31_mul(r4, r5790);
    unsigned r6470 = stwo_m31_add(r6468, r6469);
    unsigned r6471 = stwo_m31_mul(r5, r6401);
    unsigned r6472 = stwo_m31_add(r6399, r6471);
    unsigned r6473 = stwo_m31_mul(r3, r6443);
    unsigned r6474 = stwo_m31_sub(r6472, r6473);
    unsigned r6475 = stwo_m31_mul(r4, r5795);
    unsigned r6476 = stwo_m31_add(r6474, r6475);
    unsigned r6477 = stwo_m31_mul(r5, r6403);
    unsigned r6478 = stwo_m31_add(r6401, r6477);
    unsigned r6479 = stwo_m31_mul(r3, r6445);
    unsigned r6480 = stwo_m31_sub(r6478, r6479);
    unsigned r6481 = stwo_m31_mul(r4, r5797);
    unsigned r6482 = stwo_m31_add(r6480, r6481);
    unsigned r6483 = stwo_m31_mul(r5, r6405);
    unsigned r6484 = stwo_m31_add(r6403, r6483);
    unsigned r6485 = stwo_m31_mul(r3, r6447);
    unsigned r6486 = stwo_m31_sub(r6484, r6485);
    unsigned r6487 = stwo_m31_mul(r2, r6393);
    unsigned r6488 = stwo_m31_add(r6487, r6405);
    unsigned r6489 = stwo_m31_mul(r5, r6407);
    unsigned r6490 = stwo_m31_add(r6488, r6489);
    unsigned r6491 = stwo_m31_mul(r3, r6355);
    unsigned r6492 = stwo_m31_sub(r6490, r6491);
    unsigned r6493 = stwo_m31_mul(r2, r6395);
    unsigned r6494 = stwo_m31_add(r6493, r6407);
    unsigned r6495 = stwo_m31_mul(r5, r6409);
    unsigned r6496 = stwo_m31_add(r6494, r6495);
    unsigned r6497 = stwo_m31_mul(r3, r6358);
    unsigned r6498 = stwo_m31_sub(r6496, r6497);
    unsigned r6499 = stwo_m31_mul(r2, r6397);
    unsigned r6500 = stwo_m31_add(r6499, r6409);
    unsigned r6501 = stwo_m31_mul(r5, r6411);
    unsigned r6502 = stwo_m31_add(r6500, r6501);
    unsigned r6503 = stwo_m31_mul(r3, r6361);
    unsigned r6504 = stwo_m31_sub(r6502, r6503);
    unsigned r6505 = stwo_m31_mul(r2, r6399);
    unsigned r6506 = stwo_m31_add(r6505, r6411);
    unsigned r6507 = stwo_m31_mul(r5, r6413);
    unsigned r6508 = stwo_m31_add(r6506, r6507);
    unsigned r6509 = stwo_m31_mul(r3, r6364);
    unsigned r6510 = stwo_m31_sub(r6508, r6509);
    unsigned r6511 = stwo_m31_mul(r2, r6401);
    unsigned r6512 = stwo_m31_add(r6511, r6413);
    unsigned r6513 = stwo_m31_mul(r5, r6415);
    unsigned r6514 = stwo_m31_add(r6512, r6513);
    unsigned r6515 = stwo_m31_mul(r3, r6367);
    unsigned r6516 = stwo_m31_sub(r6514, r6515);
    unsigned r6517 = stwo_m31_mul(r2, r6403);
    unsigned r6518 = stwo_m31_add(r6517, r6415);
    unsigned r6519 = stwo_m31_mul(r5, r6417);
    unsigned r6520 = stwo_m31_add(r6518, r6519);
    unsigned r6521 = stwo_m31_mul(r3, r6370);
    unsigned r6522 = stwo_m31_sub(r6520, r6521);
    unsigned r6523 = stwo_m31_mul(r2, r6405);
    unsigned r6524 = stwo_m31_add(r6523, r6417);
    unsigned r6525 = stwo_m31_mul(r5, r6419);
    unsigned r6526 = stwo_m31_add(r6524, r6525);
    unsigned r6527 = stwo_m31_mul(r3, r6373);
    unsigned r6528 = stwo_m31_sub(r6526, r6527);
    unsigned r6529 = stwo_m31_mul(r2, r6407);
    unsigned r6530 = stwo_m31_add(r6529, r6419);
    unsigned r6531 = stwo_m31_mul(r5, r6421);
    unsigned r6532 = stwo_m31_add(r6530, r6531);
    unsigned r6533 = stwo_m31_mul(r3, r6376);
    unsigned r6534 = stwo_m31_sub(r6532, r6533);
    unsigned r6535 = stwo_m31_mul(r2, r6409);
    unsigned r6536 = stwo_m31_add(r6535, r6421);
    unsigned r6537 = stwo_m31_mul(r5, r6423);
    unsigned r6538 = stwo_m31_add(r6536, r6537);
    unsigned r6539 = stwo_m31_mul(r3, r6379);
    unsigned r6540 = stwo_m31_sub(r6538, r6539);
    unsigned r6541 = stwo_m31_mul(r2, r6411);
    unsigned r6542 = stwo_m31_add(r6541, r6423);
    unsigned r6543 = stwo_m31_mul(r5, r6425);
    unsigned r6544 = stwo_m31_add(r6542, r6543);
    unsigned r6545 = stwo_m31_mul(r3, r6382);
    unsigned r6546 = stwo_m31_sub(r6544, r6545);
    unsigned r6547 = stwo_m31_mul(r2, r6413);
    unsigned r6548 = stwo_m31_add(r6547, r6425);
    unsigned r6549 = stwo_m31_mul(r5, r6427);
    unsigned r6550 = stwo_m31_add(r6548, r6549);
    unsigned r6551 = stwo_m31_mul(r3, r6385);
    unsigned r6552 = stwo_m31_sub(r6550, r6551);
    unsigned r6553 = stwo_m31_mul(r2, r6415);
    unsigned r6554 = stwo_m31_add(r6553, r6427);
    unsigned r6555 = stwo_m31_mul(r5, r6429);
    unsigned r6556 = stwo_m31_add(r6554, r6555);
    unsigned r6557 = stwo_m31_mul(r3, r6388);
    unsigned r6558 = stwo_m31_sub(r6556, r6557);
    unsigned r6559 = stwo_m31_mul(r2, r6417);
    unsigned r6560 = stwo_m31_add(r6559, r6429);
    unsigned r6561 = stwo_m31_mul(r5, r6431);
    unsigned r6562 = stwo_m31_add(r6560, r6561);
    unsigned r6563 = stwo_m31_mul(r3, r6391);
    unsigned r6564 = stwo_m31_sub(r6562, r6563);
    unsigned r6565 = stwo_m31_mul(r2, r6419);
    unsigned r6566 = stwo_m31_add(r6565, r6431);
    unsigned r6567 = stwo_m31_mul(r5, r6433);
    unsigned r6568 = stwo_m31_add(r6566, r6567);
    unsigned r6569 = stwo_m31_mul(r3, r5894);
    unsigned r6570 = stwo_m31_sub(r6568, r6569);
    unsigned r6571 = stwo_m31_mul(r2, r6421);
    unsigned r6572 = stwo_m31_add(r6571, r6433);
    unsigned r6573 = stwo_m31_mul(r3, r5908);
    unsigned r6574 = stwo_m31_sub(r6572, r6573);
    unsigned r6575 = stwo_m31_mul(r6, r5757);
    unsigned r6576 = stwo_m31_add(r6574, r6575);
    unsigned r6577 = stwo_m31_mul(r2, r6423);
    unsigned r6578 = stwo_m31_mul(r3, r5920);
    unsigned r6579 = stwo_m31_sub(r6577, r6578);
    unsigned r6580 = stwo_m31_mul(r2, r5757);
    unsigned r6581 = stwo_m31_add(r6579, r6580);
    unsigned r6582 = stwo_m31_mul(r6, r5771);
    unsigned r6583 = stwo_m31_add(r6581, r6582);
    unsigned r6584 = stwo_m31_mul(r2, r6425);
    unsigned r6585 = stwo_m31_mul(r3, r5930);
    unsigned r6586 = stwo_m31_sub(r6584, r6585);
    unsigned r6587 = stwo_m31_mul(r2, r5771);
    unsigned r6588 = stwo_m31_add(r6586, r6587);
    unsigned r6589 = stwo_m31_mul(r6, r5782);
    unsigned r6590 = stwo_m31_add(r6588, r6589);
    unsigned r6591 = stwo_m31_mul(r2, r6427);
    unsigned r6592 = stwo_m31_mul(r3, r5938);
    unsigned r6593 = stwo_m31_sub(r6591, r6592);
    unsigned r6594 = stwo_m31_mul(r2, r5782);
    unsigned r6595 = stwo_m31_add(r6593, r6594);
    unsigned r6596 = stwo_m31_mul(r6, r5790);
    unsigned r6597 = stwo_m31_add(r6595, r6596);
    unsigned r6598 = stwo_m31_mul(r2, r6429);
    unsigned r6599 = stwo_m31_mul(r3, r5944);
    unsigned r6600 = stwo_m31_sub(r6598, r6599);
    unsigned r6601 = stwo_m31_mul(r2, r5790);
    unsigned r6602 = stwo_m31_add(r6600, r6601);
    unsigned r6603 = stwo_m31_mul(r6, r5795);
    unsigned r6604 = stwo_m31_add(r6602, r6603);
    unsigned r6605 = stwo_m31_mul(r2, r6431);
    unsigned r6606 = stwo_m31_mul(r3, r5948);
    unsigned r6607 = stwo_m31_sub(r6605, r6606);
    unsigned r6608 = stwo_m31_mul(r2, r5795);
    unsigned r6609 = stwo_m31_add(r6607, r6608);
    unsigned r6610 = stwo_m31_mul(r6, r5797);
    unsigned r6611 = stwo_m31_add(r6609, r6610);
    unsigned r6612 = stwo_m31_mul(r2, r6433);
    unsigned r6613 = stwo_m31_mul(r3, r5740);
    unsigned r6614 = stwo_m31_sub(r6612, r6613);
    unsigned r6615 = stwo_m31_mul(r2, r5797);
    unsigned r6616 = stwo_m31_add(r6614, r6615);
    unsigned r6617 = stwo_m31_add(r6452, r12);
    unsigned r6618 = stwo_m31_add(r6458, r12);
    unsigned r6619 = (r6618 & 511u);
    unsigned r6620 = (r6619 << 9u);
    unsigned r6621 = (r6617 + r6620);
    unsigned r6622 = 131072u;
    unsigned r6623 = (r6621 + r6622);
    unsigned r6624 = (r6623 & 262143u);
    unsigned r6625 = (r6624 & 65535u);
    unsigned r6626 = (r6625 % STWO_M31_P);
    unsigned r6627 = (r6624 >> 16u);
    unsigned r6628 = (r6627 % STWO_M31_P);
    unsigned r6629 = stwo_m31_sub(r6628, r2);
    unsigned r6630 = stwo_m31_mul(r6629, r8);
    unsigned r6631 = stwo_m31_add(r6626, r6630);
    unsigned r6632 = stwo_m31_add(r6631, r10);
    sub_words[93u * row_count + row] = r6632;
    unsigned r6633 = stwo_m31_add(r6631, r10);
    lookup_words[221u * row_count + row] = r6633;
    unsigned r6634 = stwo_m31_sub(r6452, r6631);
    unsigned r6635 = stwo_m31_mul(r6634, r11);
    unsigned r6636 = stwo_m31_add(r6635, r10);
    sub_words[105u * row_count + row] = r6636;
    unsigned r6637 = stwo_m31_add(r6635, r10);
    lookup_words[245u * row_count + row] = r6637;
    unsigned r6638 = stwo_m31_add(r6458, r6635);
    out_cols[269u][row] = r6635;
    unsigned r6639 = stwo_m31_mul(r6638, r11);
    unsigned r6640 = stwo_m31_add(r6639, r10);
    sub_words[117u * row_count + row] = r6640;
    unsigned r6641 = stwo_m31_add(r6639, r10);
    lookup_words[269u * row_count + row] = r6641;
    unsigned r6642 = stwo_m31_add(r6464, r6639);
    out_cols[270u][row] = r6639;
    unsigned r6643 = stwo_m31_mul(r6642, r11);
    unsigned r6644 = stwo_m31_add(r6643, r10);
    sub_words[129u * row_count + row] = r6644;
    unsigned r6645 = stwo_m31_add(r6643, r10);
    lookup_words[293u * row_count + row] = r6645;
    unsigned r6646 = stwo_m31_add(r6470, r6643);
    out_cols[271u][row] = r6643;
    unsigned r6647 = stwo_m31_mul(r6646, r11);
    unsigned r6648 = stwo_m31_add(r6647, r10);
    sub_words[139u * row_count + row] = r6648;
    unsigned r6649 = stwo_m31_add(r6647, r10);
    lookup_words[313u * row_count + row] = r6649;
    unsigned r6650 = stwo_m31_add(r6476, r6647);
    out_cols[272u][row] = r6647;
    unsigned r6651 = stwo_m31_mul(r6650, r11);
    unsigned r6652 = stwo_m31_add(r6651, r10);
    sub_words[148u * row_count + row] = r6652;
    unsigned r6653 = stwo_m31_add(r6651, r10);
    lookup_words[331u * row_count + row] = r6653;
    unsigned r6654 = stwo_m31_add(r6482, r6651);
    out_cols[273u][row] = r6651;
    unsigned r6655 = stwo_m31_mul(r6654, r11);
    unsigned r6656 = stwo_m31_add(r6655, r10);
    sub_words[157u * row_count + row] = r6656;
    unsigned r6657 = stwo_m31_add(r6655, r10);
    lookup_words[349u * row_count + row] = r6657;
    unsigned r6658 = stwo_m31_add(r6486, r6655);
    out_cols[274u][row] = r6655;
    unsigned r6659 = stwo_m31_mul(r6658, r11);
    unsigned r6660 = stwo_m31_add(r6659, r10);
    sub_words[166u * row_count + row] = r6660;
    unsigned r6661 = stwo_m31_add(r6659, r10);
    lookup_words[367u * row_count + row] = r6661;
    unsigned r6662 = stwo_m31_add(r6492, r6659);
    out_cols[275u][row] = r6659;
    unsigned r6663 = stwo_m31_mul(r6662, r11);
    unsigned r6664 = stwo_m31_add(r6663, r10);
    sub_words[94u * row_count + row] = r6664;
    unsigned r6665 = stwo_m31_add(r6663, r10);
    lookup_words[223u * row_count + row] = r6665;
    unsigned r6666 = stwo_m31_add(r6498, r6663);
    out_cols[276u][row] = r6663;
    unsigned r6667 = stwo_m31_mul(r6666, r11);
    unsigned r6668 = stwo_m31_add(r6667, r10);
    sub_words[106u * row_count + row] = r6668;
    unsigned r6669 = stwo_m31_add(r6667, r10);
    lookup_words[247u * row_count + row] = r6669;
    unsigned r6670 = stwo_m31_add(r6504, r6667);
    out_cols[277u][row] = r6667;
    unsigned r6671 = stwo_m31_mul(r6670, r11);
    unsigned r6672 = stwo_m31_add(r6671, r10);
    sub_words[118u * row_count + row] = r6672;
    unsigned r6673 = stwo_m31_add(r6671, r10);
    lookup_words[271u * row_count + row] = r6673;
    unsigned r6674 = stwo_m31_add(r6510, r6671);
    out_cols[278u][row] = r6671;
    unsigned r6675 = stwo_m31_mul(r6674, r11);
    unsigned r6676 = stwo_m31_add(r6675, r10);
    sub_words[130u * row_count + row] = r6676;
    unsigned r6677 = stwo_m31_add(r6675, r10);
    lookup_words[295u * row_count + row] = r6677;
    unsigned r6678 = stwo_m31_add(r6516, r6675);
    out_cols[279u][row] = r6675;
    unsigned r6679 = stwo_m31_mul(r6678, r11);
    unsigned r6680 = stwo_m31_add(r6679, r10);
    sub_words[140u * row_count + row] = r6680;
    unsigned r6681 = stwo_m31_add(r6679, r10);
    lookup_words[315u * row_count + row] = r6681;
    unsigned r6682 = stwo_m31_add(r6522, r6679);
    out_cols[280u][row] = r6679;
    unsigned r6683 = stwo_m31_mul(r6682, r11);
    unsigned r6684 = stwo_m31_add(r6683, r10);
    sub_words[149u * row_count + row] = r6684;
    unsigned r6685 = stwo_m31_add(r6683, r10);
    lookup_words[333u * row_count + row] = r6685;
    unsigned r6686 = stwo_m31_add(r6528, r6683);
    out_cols[281u][row] = r6683;
    unsigned r6687 = stwo_m31_mul(r6686, r11);
    unsigned r6688 = stwo_m31_add(r6687, r10);
    sub_words[158u * row_count + row] = r6688;
    unsigned r6689 = stwo_m31_add(r6687, r10);
    lookup_words[351u * row_count + row] = r6689;
    unsigned r6690 = stwo_m31_add(r6534, r6687);
    out_cols[282u][row] = r6687;
    unsigned r6691 = stwo_m31_mul(r6690, r11);
    unsigned r6692 = stwo_m31_add(r6691, r10);
    sub_words[167u * row_count + row] = r6692;
    unsigned r6693 = stwo_m31_add(r6691, r10);
    lookup_words[369u * row_count + row] = r6693;
    unsigned r6694 = stwo_m31_add(r6540, r6691);
    out_cols[283u][row] = r6691;
    unsigned r6695 = stwo_m31_mul(r6694, r11);
    unsigned r6696 = stwo_m31_add(r6695, r10);
    sub_words[95u * row_count + row] = r6696;
    unsigned r6697 = stwo_m31_add(r6695, r10);
    lookup_words[225u * row_count + row] = r6697;
    unsigned r6698 = stwo_m31_add(r6546, r6695);
    out_cols[284u][row] = r6695;
    unsigned r6699 = stwo_m31_mul(r6698, r11);
    unsigned r6700 = stwo_m31_add(r6699, r10);
    sub_words[107u * row_count + row] = r6700;
    unsigned r6701 = stwo_m31_add(r6699, r10);
    lookup_words[249u * row_count + row] = r6701;
    unsigned r6702 = stwo_m31_add(r6552, r6699);
    out_cols[285u][row] = r6699;
    unsigned r6703 = stwo_m31_mul(r6702, r11);
    unsigned r6704 = stwo_m31_add(r6703, r10);
    sub_words[119u * row_count + row] = r6704;
    unsigned r6705 = stwo_m31_add(r6703, r10);
    lookup_words[273u * row_count + row] = r6705;
    unsigned r6706 = stwo_m31_add(r6558, r6703);
    out_cols[286u][row] = r6703;
    unsigned r6707 = stwo_m31_mul(r6706, r11);
    unsigned r6708 = stwo_m31_add(r6707, r10);
    sub_words[131u * row_count + row] = r6708;
    unsigned r6709 = stwo_m31_add(r6707, r10);
    lookup_words[297u * row_count + row] = r6709;
    unsigned r6710 = stwo_m31_add(r6564, r6707);
    out_cols[287u][row] = r6707;
    unsigned r6711 = stwo_m31_mul(r6710, r11);
    unsigned r6712 = stwo_m31_add(r6711, r10);
    sub_words[141u * row_count + row] = r6712;
    unsigned r6713 = stwo_m31_add(r6711, r10);
    lookup_words[317u * row_count + row] = r6713;
    unsigned r6714 = stwo_m31_add(r6570, r6711);
    out_cols[288u][row] = r6711;
    unsigned r6715 = stwo_m31_mul(r6714, r11);
    unsigned r6716 = stwo_m31_add(r6715, r10);
    sub_words[150u * row_count + row] = r6716;
    unsigned r6717 = stwo_m31_add(r6715, r10);
    lookup_words[335u * row_count + row] = r6717;
    unsigned r6718 = stwo_m31_mul(r7, r6631);
    out_cols[268u][row] = r6631;
    unsigned r6719 = stwo_m31_sub(r6576, r6718);
    unsigned r6720 = stwo_m31_add(r6719, r6715);
    out_cols[289u][row] = r6715;
    unsigned r6721 = stwo_m31_mul(r6720, r11);
    unsigned r6722 = stwo_m31_add(r6721, r10);
    sub_words[159u * row_count + row] = r6722;
    unsigned r6723 = stwo_m31_add(r6721, r10);
    lookup_words[353u * row_count + row] = r6723;
    unsigned r6724 = stwo_m31_add(r6583, r6721);
    out_cols[290u][row] = r6721;
    unsigned r6725 = stwo_m31_mul(r6724, r11);
    unsigned r6726 = stwo_m31_add(r6725, r10);
    sub_words[168u * row_count + row] = r6726;
    unsigned r6727 = stwo_m31_add(r6725, r10);
    lookup_words[371u * row_count + row] = r6727;
    unsigned r6728 = stwo_m31_add(r6590, r6725);
    out_cols[291u][row] = r6725;
    unsigned r6729 = stwo_m31_mul(r6728, r11);
    unsigned r6730 = stwo_m31_add(r6729, r10);
    sub_words[96u * row_count + row] = r6730;
    unsigned r6731 = stwo_m31_add(r6729, r10);
    lookup_words[227u * row_count + row] = r6731;
    unsigned r6732 = stwo_m31_add(r6597, r6729);
    out_cols[292u][row] = r6729;
    unsigned r6733 = stwo_m31_mul(r6732, r11);
    unsigned r6734 = stwo_m31_add(r6733, r10);
    sub_words[108u * row_count + row] = r6734;
    unsigned r6735 = stwo_m31_add(r6733, r10);
    lookup_words[251u * row_count + row] = r6735;
    unsigned r6736 = stwo_m31_add(r6604, r6733);
    out_cols[293u][row] = r6733;
    unsigned r6737 = stwo_m31_mul(r6736, r11);
    unsigned r6738 = stwo_m31_add(r6737, r10);
    sub_words[120u * row_count + row] = r6738;
    unsigned r6739 = stwo_m31_add(r6737, r10);
    lookup_words[275u * row_count + row] = r6739;
    unsigned r6740 = stwo_m31_add(r6611, r6737);
    out_cols[294u][row] = r6737;
    unsigned r6741 = stwo_m31_mul(r6740, r11);
    unsigned r6742 = stwo_m31_add(r6741, r10);
    sub_words[132u * row_count + row] = r6742;
    unsigned r6743 = stwo_m31_add(r6741, r10);
    out_cols[295u][row] = r6741;
    lookup_words[299u * row_count + row] = r6743;
    unsigned r6744 = stwo_m31_add(r32, r1);
    out_cols[1u][row] = r32;
    lookup_words[2u * row_count + row] = r32;
    lookup_words[75u * row_count + row] = r6744;
    unsigned r6745 = input_cols[72u][row];
    out_cols[296u][row] = r6745;
}
