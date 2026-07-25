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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_b0eb28f739a39f20(
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
    unsigned r1 = 1u;
    unsigned r2 = 2u;
    unsigned r3 = 3u;
    unsigned r4 = 4u;
    unsigned r5 = 5u;
    unsigned r6 = 6u;
    unsigned r7 = 7u;
    unsigned r8 = 8u;
    unsigned r9 = 9u;
    unsigned r10 = 10u;
    unsigned r11 = 11u;
    unsigned r12 = 12u;
    unsigned r13 = 13u;
    unsigned r14 = 14u;
    unsigned r15 = 15u;
    unsigned r16 = 16u;
    unsigned r17 = 17u;
    unsigned r18 = 18u;
    unsigned r19 = 19u;
    unsigned r20 = 20u;
    unsigned r21 = 21u;
    unsigned r22 = 22u;
    unsigned r23 = 23u;
    unsigned r24 = 24u;
    unsigned r25 = 25u;
    unsigned r26 = 26u;
    unsigned r27 = 27u;
    unsigned r28 = 28u;
    lookup_words[289u * row_count + row] = r28;
    unsigned r29 = 49u;
    unsigned r30 = 54u;
    unsigned r31 = 64u;
    unsigned r32 = 68u;
    unsigned r33 = 72u;
    unsigned r34 = 79u;
    unsigned r35 = 97u;
    unsigned r36 = 98u;
    unsigned r37 = 101u;
    unsigned r38 = 108u;
    unsigned r39 = 115u;
    unsigned r40 = 120u;
    unsigned r41 = 124u;
    unsigned r42 = 135u;
    unsigned r43 = 136u;
    unsigned r44 = 140u;
    unsigned r45 = 141u;
    unsigned r46 = 155u;
    unsigned r47 = 156u;
    unsigned r48 = 160u;
    unsigned r49 = 162u;
    unsigned r50 = 169u;
    unsigned r51 = 191u;
    unsigned r52 = 199u;
    unsigned r53 = 202u;
    unsigned r54 = 208u;
    unsigned r55 = 213u;
    unsigned r56 = 222u;
    unsigned r57 = 223u;
    unsigned r58 = 225u;
    unsigned r59 = 256u;
    unsigned r60 = 297u;
    unsigned r61 = 303u;
    unsigned r62 = 314u;
    unsigned r63 = 315u;
    unsigned r64 = 325u;
    unsigned r65 = 334u;
    unsigned r66 = 373u;
    unsigned r67 = 377u;
    unsigned r68 = 379u;
    unsigned r69 = 389u;
    unsigned r70 = 418u;
    unsigned r71 = 420u;
    unsigned r72 = 428u;
    unsigned r73 = 449u;
    unsigned r74 = 464u;
    unsigned r75 = 466u;
    unsigned r76 = 473u;
    unsigned r77 = 480u;
    unsigned r78 = 484u;
    unsigned r79 = 497u;
    unsigned r80 = 498u;
    unsigned r81 = 510u;
    unsigned r82 = 512u;
    unsigned r83 = 520578465u;
    lookup_words[390u * row_count + row] = r83;
    unsigned r84 = 1420243005u;
    lookup_words[60u * row_count + row] = r84;
    lookup_words[62u * row_count + row] = r84;
    lookup_words[64u * row_count + row] = r84;
    lookup_words[66u * row_count + row] = r84;
    unsigned r85 = 1621226978u;
    lookup_words[68u * row_count + row] = r85;
    lookup_words[141u * row_count + row] = r85;
    lookup_words[214u * row_count + row] = r85;
    lookup_words[287u * row_count + row] = r85;
    unsigned r86 = 1662111297u;
    lookup_words[0u * row_count + row] = r86;
    lookup_words[30u * row_count + row] = r86;
    lookup_words[360u * row_count + row] = r86;
    unsigned r87 = input_cols[4u][row];
    unsigned r88 = input_cols[0u][row];
    unsigned r89 = input_cols[1u][row];
    unsigned r90 = input_cols[2u][row];
    out_cols[2u][row] = r90;
    sub_words[2u * row_count + row] = r90;
    lookup_words[361u * row_count + row] = r90;
    lookup_words[393u * row_count + row] = r90;
    unsigned r91 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 0u);
    unsigned r92 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 1u);
    unsigned r93 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 2u);
    unsigned r94 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 3u);
    unsigned r95 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 4u);
    unsigned r96 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 5u);
    unsigned r97 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 6u);
    unsigned r98 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 7u);
    unsigned r99 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 8u);
    unsigned r100 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 9u);
    unsigned r101 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 10u);
    unsigned r102 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 11u);
    unsigned r103 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 12u);
    unsigned r104 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 13u);
    unsigned r105 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 14u);
    unsigned r106 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 15u);
    unsigned r107 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 16u);
    unsigned r108 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 17u);
    unsigned r109 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 18u);
    unsigned r110 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 19u);
    unsigned r111 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 20u);
    unsigned r112 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 21u);
    unsigned r113 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 22u);
    unsigned r114 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 23u);
    unsigned r115 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 24u);
    unsigned r116 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 25u);
    unsigned r117 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 26u);
    unsigned r118 = stwo_wit_deduce_limb(table_bases, table_strides, r88, 27u);
    out_cols[0u][row] = r88;
    sub_words[0u * row_count + row] = r88;
    lookup_words[1u * row_count + row] = r88;
    lookup_words[391u * row_count + row] = r88;
    unsigned r119 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 0u);
    unsigned r120 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 1u);
    unsigned r121 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 2u);
    unsigned r122 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 3u);
    unsigned r123 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 4u);
    unsigned r124 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 5u);
    unsigned r125 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 6u);
    unsigned r126 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 7u);
    unsigned r127 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 8u);
    unsigned r128 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 9u);
    unsigned r129 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 10u);
    unsigned r130 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 11u);
    unsigned r131 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 12u);
    unsigned r132 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 13u);
    unsigned r133 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 14u);
    unsigned r134 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 15u);
    unsigned r135 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 16u);
    unsigned r136 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 17u);
    unsigned r137 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 18u);
    unsigned r138 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 19u);
    unsigned r139 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 20u);
    unsigned r140 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 21u);
    unsigned r141 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 22u);
    unsigned r142 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 23u);
    unsigned r143 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 24u);
    unsigned r144 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 25u);
    unsigned r145 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 26u);
    unsigned r146 = stwo_wit_deduce_limb(table_bases, table_strides, r89, 27u);
    out_cols[1u][row] = r89;
    sub_words[1u * row_count + row] = r89;
    lookup_words[31u * row_count + row] = r89;
    lookup_words[392u * row_count + row] = r89;
    unsigned r147 = (r118 == r59 ? 1u : 0u);
    unsigned r148 = (r118 == r59 ? 1u : 0u);
    unsigned r149 = (r112 == r43 ? 1u : 0u);
    unsigned r150 = stwo_m31_mul(r148, r149);
    unsigned r151 = stwo_m31_sub(r118, r147);
    sub_words[3u * row_count + row] = r151;
    unsigned r152 = stwo_m31_sub(r118, r147);
    lookup_words[61u * row_count + row] = r152;
    unsigned r153 = stwo_m31_add(r40, r112);
    unsigned r154 = stwo_m31_sub(r153, r150);
    out_cols[60u][row] = r150;
    unsigned r155 = stwo_m31_mul(r147, r154);
    out_cols[59u][row] = r147;
    out_cols[61u][row] = r155;
    sub_words[4u * row_count + row] = r155;
    lookup_words[63u * row_count + row] = r155;
    unsigned r156 = (r146 == r59 ? 1u : 0u);
    unsigned r157 = (r146 == r59 ? 1u : 0u);
    unsigned r158 = (r140 == r43 ? 1u : 0u);
    unsigned r159 = stwo_m31_mul(r157, r158);
    unsigned r160 = stwo_m31_sub(r146, r156);
    sub_words[5u * row_count + row] = r160;
    unsigned r161 = stwo_m31_sub(r146, r156);
    lookup_words[65u * row_count + row] = r161;
    unsigned r162 = stwo_m31_add(r40, r140);
    unsigned r163 = stwo_m31_sub(r162, r159);
    out_cols[63u][row] = r159;
    unsigned r164 = stwo_m31_mul(r156, r163);
    out_cols[62u][row] = r156;
    out_cols[64u][row] = r164;
    sub_words[6u * row_count + row] = r164;
    lookup_words[67u * row_count + row] = r164;
    unsigned r165 = stwo_m31_mul(r87, r2);
    unsigned r166 = stwo_m31_mul(r92, r82);
    unsigned r167 = stwo_m31_add(r91, r166);
    lookup_words[71u * row_count + row] = r167;
    unsigned r168 = stwo_m31_mul(r94, r82);
    unsigned r169 = stwo_m31_add(r93, r168);
    lookup_words[72u * row_count + row] = r169;
    unsigned r170 = stwo_m31_mul(r96, r82);
    unsigned r171 = stwo_m31_add(r95, r170);
    lookup_words[73u * row_count + row] = r171;
    unsigned r172 = stwo_m31_mul(r98, r82);
    unsigned r173 = stwo_m31_add(r97, r172);
    lookup_words[74u * row_count + row] = r173;
    unsigned r174 = stwo_m31_mul(r100, r82);
    unsigned r175 = stwo_m31_add(r99, r174);
    lookup_words[75u * row_count + row] = r175;
    unsigned r176 = stwo_m31_mul(r102, r82);
    unsigned r177 = stwo_m31_add(r101, r176);
    lookup_words[76u * row_count + row] = r177;
    unsigned r178 = stwo_m31_mul(r104, r82);
    unsigned r179 = stwo_m31_add(r103, r178);
    lookup_words[77u * row_count + row] = r179;
    unsigned r180 = stwo_m31_mul(r106, r82);
    unsigned r181 = stwo_m31_add(r105, r180);
    lookup_words[78u * row_count + row] = r181;
    unsigned r182 = stwo_m31_mul(r108, r82);
    unsigned r183 = stwo_m31_add(r107, r182);
    lookup_words[79u * row_count + row] = r183;
    unsigned r184 = stwo_m31_mul(r110, r82);
    unsigned r185 = stwo_m31_add(r109, r184);
    lookup_words[80u * row_count + row] = r185;
    unsigned r186 = stwo_m31_mul(r112, r82);
    unsigned r187 = stwo_m31_add(r111, r186);
    lookup_words[81u * row_count + row] = r187;
    unsigned r188 = stwo_m31_mul(r114, r82);
    unsigned r189 = stwo_m31_add(r113, r188);
    lookup_words[82u * row_count + row] = r189;
    unsigned r190 = stwo_m31_mul(r116, r82);
    unsigned r191 = stwo_m31_add(r115, r190);
    lookup_words[83u * row_count + row] = r191;
    unsigned r192 = stwo_m31_mul(r118, r82);
    unsigned r193 = stwo_m31_add(r117, r192);
    lookup_words[84u * row_count + row] = r193;
    unsigned r194 = stwo_m31_mul(r92, r82);
    unsigned r195 = stwo_m31_add(r91, r194);
    sub_words[9u * row_count + row] = r195;
    unsigned r196 = stwo_m31_mul(r94, r82);
    unsigned r197 = stwo_m31_add(r93, r196);
    sub_words[10u * row_count + row] = r197;
    unsigned r198 = stwo_m31_mul(r96, r82);
    unsigned r199 = stwo_m31_add(r95, r198);
    sub_words[11u * row_count + row] = r199;
    unsigned r200 = stwo_m31_mul(r98, r82);
    unsigned r201 = stwo_m31_add(r97, r200);
    sub_words[12u * row_count + row] = r201;
    unsigned r202 = stwo_m31_mul(r100, r82);
    unsigned r203 = stwo_m31_add(r99, r202);
    sub_words[13u * row_count + row] = r203;
    unsigned r204 = stwo_m31_mul(r102, r82);
    unsigned r205 = stwo_m31_add(r101, r204);
    sub_words[14u * row_count + row] = r205;
    unsigned r206 = stwo_m31_mul(r104, r82);
    unsigned r207 = stwo_m31_add(r103, r206);
    sub_words[15u * row_count + row] = r207;
    unsigned r208 = stwo_m31_mul(r106, r82);
    unsigned r209 = stwo_m31_add(r105, r208);
    sub_words[16u * row_count + row] = r209;
    unsigned r210 = stwo_m31_mul(r108, r82);
    unsigned r211 = stwo_m31_add(r107, r210);
    sub_words[17u * row_count + row] = r211;
    unsigned r212 = stwo_m31_mul(r110, r82);
    unsigned r213 = stwo_m31_add(r109, r212);
    sub_words[18u * row_count + row] = r213;
    unsigned r214 = stwo_m31_mul(r112, r82);
    unsigned r215 = stwo_m31_add(r111, r214);
    sub_words[19u * row_count + row] = r215;
    unsigned r216 = stwo_m31_mul(r114, r82);
    unsigned r217 = stwo_m31_add(r113, r216);
    sub_words[20u * row_count + row] = r217;
    unsigned r218 = stwo_m31_mul(r116, r82);
    unsigned r219 = stwo_m31_add(r115, r218);
    sub_words[21u * row_count + row] = r219;
    unsigned r220 = stwo_m31_mul(r118, r82);
    unsigned r221 = stwo_m31_add(r117, r220);
    sub_words[22u * row_count + row] = r221;
    unsigned r222 = stwo_m31_mul(r92, r82);
    out_cols[4u][row] = r92;
    lookup_words[3u * row_count + row] = r92;
    unsigned r223 = stwo_m31_add(r91, r222);
    out_cols[3u][row] = r91;
    lookup_words[2u * row_count + row] = r91;
    unsigned r224 = stwo_m31_mul(r94, r82);
    out_cols[6u][row] = r94;
    lookup_words[5u * row_count + row] = r94;
    unsigned r225 = stwo_m31_add(r93, r224);
    out_cols[5u][row] = r93;
    lookup_words[4u * row_count + row] = r93;
    unsigned r226 = stwo_m31_mul(r96, r82);
    out_cols[8u][row] = r96;
    lookup_words[7u * row_count + row] = r96;
    unsigned r227 = stwo_m31_add(r95, r226);
    out_cols[7u][row] = r95;
    lookup_words[6u * row_count + row] = r95;
    unsigned r228 = stwo_m31_mul(r98, r82);
    out_cols[10u][row] = r98;
    lookup_words[9u * row_count + row] = r98;
    unsigned r229 = stwo_m31_add(r97, r228);
    out_cols[9u][row] = r97;
    lookup_words[8u * row_count + row] = r97;
    unsigned r230 = stwo_m31_mul(r100, r82);
    out_cols[12u][row] = r100;
    lookup_words[11u * row_count + row] = r100;
    unsigned r231 = stwo_m31_add(r99, r230);
    out_cols[11u][row] = r99;
    lookup_words[10u * row_count + row] = r99;
    unsigned r232 = stwo_m31_mul(r102, r82);
    out_cols[14u][row] = r102;
    lookup_words[13u * row_count + row] = r102;
    unsigned r233 = stwo_m31_add(r101, r232);
    out_cols[13u][row] = r101;
    lookup_words[12u * row_count + row] = r101;
    unsigned r234 = stwo_m31_mul(r104, r82);
    out_cols[16u][row] = r104;
    lookup_words[15u * row_count + row] = r104;
    unsigned r235 = stwo_m31_add(r103, r234);
    out_cols[15u][row] = r103;
    lookup_words[14u * row_count + row] = r103;
    unsigned r236 = stwo_m31_mul(r106, r82);
    out_cols[18u][row] = r106;
    lookup_words[17u * row_count + row] = r106;
    unsigned r237 = stwo_m31_add(r105, r236);
    out_cols[17u][row] = r105;
    lookup_words[16u * row_count + row] = r105;
    unsigned r238 = stwo_m31_mul(r108, r82);
    out_cols[20u][row] = r108;
    lookup_words[19u * row_count + row] = r108;
    unsigned r239 = stwo_m31_add(r107, r238);
    out_cols[19u][row] = r107;
    lookup_words[18u * row_count + row] = r107;
    unsigned r240 = stwo_m31_mul(r110, r82);
    out_cols[22u][row] = r110;
    lookup_words[21u * row_count + row] = r110;
    unsigned r241 = stwo_m31_add(r109, r240);
    out_cols[21u][row] = r109;
    lookup_words[20u * row_count + row] = r109;
    unsigned r242 = stwo_m31_mul(r112, r82);
    out_cols[24u][row] = r112;
    lookup_words[23u * row_count + row] = r112;
    unsigned r243 = stwo_m31_add(r111, r242);
    out_cols[23u][row] = r111;
    lookup_words[22u * row_count + row] = r111;
    unsigned r244 = stwo_m31_mul(r114, r82);
    out_cols[26u][row] = r114;
    lookup_words[25u * row_count + row] = r114;
    unsigned r245 = stwo_m31_add(r113, r244);
    out_cols[25u][row] = r113;
    lookup_words[24u * row_count + row] = r113;
    unsigned r246 = stwo_m31_mul(r116, r82);
    out_cols[28u][row] = r116;
    lookup_words[27u * row_count + row] = r116;
    unsigned r247 = stwo_m31_add(r115, r246);
    out_cols[27u][row] = r115;
    lookup_words[26u * row_count + row] = r115;
    unsigned r248 = stwo_m31_mul(r118, r82);
    out_cols[30u][row] = r118;
    lookup_words[29u * row_count + row] = r118;
    unsigned r249 = stwo_m31_add(r117, r248);
    out_cols[29u][row] = r117;
    lookup_words[28u * row_count + row] = r117;
    const unsigned dargs0[72] = { r165, r0, r223, r225, r227, r229, r231, r233, r235, r237, r239, r241, r243, r245, r247, r249, r81, r63, r54, r77, r70, r39, r46, r30, r49, r73, r72, r75, r78, r50, r79, r66, r36, r31, r74, r80, r41, r32, r68, r44, r26, r22, r42, r53, r47, r40, r55, r69, r67, r20, r64, r61, r76, r65, r57, r48, r58, r60, r37, r71, r67, r33, r51, r29, r62, r27, r52, r56, r34, r35, r38, r45 };
    unsigned douts0[72];
    lookup_words[70u * row_count + row] = r0;
    lookup_words[85u * row_count + row] = r81;
    lookup_words[86u * row_count + row] = r63;
    lookup_words[87u * row_count + row] = r54;
    lookup_words[88u * row_count + row] = r77;
    lookup_words[89u * row_count + row] = r70;
    lookup_words[90u * row_count + row] = r39;
    lookup_words[91u * row_count + row] = r46;
    lookup_words[92u * row_count + row] = r30;
    lookup_words[93u * row_count + row] = r49;
    lookup_words[94u * row_count + row] = r73;
    lookup_words[95u * row_count + row] = r72;
    lookup_words[96u * row_count + row] = r75;
    lookup_words[97u * row_count + row] = r78;
    lookup_words[98u * row_count + row] = r50;
    lookup_words[99u * row_count + row] = r79;
    lookup_words[100u * row_count + row] = r66;
    lookup_words[101u * row_count + row] = r36;
    lookup_words[102u * row_count + row] = r31;
    lookup_words[103u * row_count + row] = r74;
    lookup_words[104u * row_count + row] = r80;
    lookup_words[105u * row_count + row] = r41;
    lookup_words[106u * row_count + row] = r32;
    lookup_words[107u * row_count + row] = r68;
    lookup_words[108u * row_count + row] = r44;
    lookup_words[111u * row_count + row] = r42;
    lookup_words[112u * row_count + row] = r53;
    lookup_words[113u * row_count + row] = r47;
    lookup_words[114u * row_count + row] = r40;
    lookup_words[115u * row_count + row] = r55;
    lookup_words[116u * row_count + row] = r69;
    lookup_words[117u * row_count + row] = r67;
    lookup_words[119u * row_count + row] = r64;
    lookup_words[120u * row_count + row] = r61;
    lookup_words[121u * row_count + row] = r76;
    lookup_words[122u * row_count + row] = r65;
    lookup_words[123u * row_count + row] = r57;
    lookup_words[124u * row_count + row] = r48;
    lookup_words[125u * row_count + row] = r58;
    lookup_words[126u * row_count + row] = r60;
    lookup_words[127u * row_count + row] = r37;
    lookup_words[128u * row_count + row] = r71;
    lookup_words[129u * row_count + row] = r67;
    lookup_words[130u * row_count + row] = r33;
    lookup_words[131u * row_count + row] = r51;
    lookup_words[132u * row_count + row] = r29;
    lookup_words[133u * row_count + row] = r62;
    lookup_words[135u * row_count + row] = r52;
    lookup_words[136u * row_count + row] = r56;
    lookup_words[137u * row_count + row] = r34;
    lookup_words[138u * row_count + row] = r35;
    lookup_words[139u * row_count + row] = r38;
    lookup_words[140u * row_count + row] = r45;
    sub_words[8u * row_count + row] = r0;
    sub_words[23u * row_count + row] = r81;
    sub_words[24u * row_count + row] = r63;
    sub_words[25u * row_count + row] = r54;
    sub_words[26u * row_count + row] = r77;
    sub_words[27u * row_count + row] = r70;
    sub_words[28u * row_count + row] = r39;
    sub_words[29u * row_count + row] = r46;
    sub_words[30u * row_count + row] = r30;
    sub_words[31u * row_count + row] = r49;
    sub_words[32u * row_count + row] = r73;
    sub_words[33u * row_count + row] = r72;
    sub_words[34u * row_count + row] = r75;
    sub_words[35u * row_count + row] = r78;
    sub_words[36u * row_count + row] = r50;
    sub_words[37u * row_count + row] = r79;
    sub_words[38u * row_count + row] = r66;
    sub_words[39u * row_count + row] = r36;
    sub_words[40u * row_count + row] = r31;
    sub_words[41u * row_count + row] = r74;
    sub_words[42u * row_count + row] = r80;
    sub_words[43u * row_count + row] = r41;
    sub_words[44u * row_count + row] = r32;
    sub_words[45u * row_count + row] = r68;
    sub_words[46u * row_count + row] = r44;
    sub_words[49u * row_count + row] = r42;
    sub_words[50u * row_count + row] = r53;
    sub_words[51u * row_count + row] = r47;
    sub_words[52u * row_count + row] = r40;
    sub_words[53u * row_count + row] = r55;
    sub_words[54u * row_count + row] = r69;
    sub_words[55u * row_count + row] = r67;
    sub_words[57u * row_count + row] = r64;
    sub_words[58u * row_count + row] = r61;
    sub_words[59u * row_count + row] = r76;
    sub_words[60u * row_count + row] = r65;
    sub_words[61u * row_count + row] = r57;
    sub_words[62u * row_count + row] = r48;
    sub_words[63u * row_count + row] = r58;
    sub_words[64u * row_count + row] = r60;
    sub_words[65u * row_count + row] = r37;
    sub_words[66u * row_count + row] = r71;
    sub_words[67u * row_count + row] = r67;
    sub_words[68u * row_count + row] = r33;
    sub_words[69u * row_count + row] = r51;
    sub_words[70u * row_count + row] = r29;
    sub_words[71u * row_count + row] = r62;
    sub_words[73u * row_count + row] = r52;
    sub_words[74u * row_count + row] = r56;
    sub_words[75u * row_count + row] = r34;
    sub_words[76u * row_count + row] = r35;
    sub_words[77u * row_count + row] = r38;
    sub_words[78u * row_count + row] = r45;
    stwo_wit_deduce_partial_ec_mul_w18(dargs0, douts0);
    unsigned r250 = douts0[0];
    unsigned r251 = douts0[1];
    unsigned r252 = douts0[2];
    unsigned r253 = douts0[3];
    unsigned r254 = douts0[4];
    unsigned r255 = douts0[5];
    unsigned r256 = douts0[6];
    unsigned r257 = douts0[7];
    unsigned r258 = douts0[8];
    unsigned r259 = douts0[9];
    unsigned r260 = douts0[10];
    unsigned r261 = douts0[11];
    unsigned r262 = douts0[12];
    unsigned r263 = douts0[13];
    unsigned r264 = douts0[14];
    unsigned r265 = douts0[15];
    unsigned r266 = douts0[16];
    unsigned r267 = douts0[17];
    unsigned r268 = douts0[18];
    unsigned r269 = douts0[19];
    unsigned r270 = douts0[20];
    unsigned r271 = douts0[21];
    unsigned r272 = douts0[22];
    unsigned r273 = douts0[23];
    unsigned r274 = douts0[24];
    unsigned r275 = douts0[25];
    unsigned r276 = douts0[26];
    unsigned r277 = douts0[27];
    unsigned r278 = douts0[28];
    unsigned r279 = douts0[29];
    unsigned r280 = douts0[30];
    unsigned r281 = douts0[31];
    unsigned r282 = douts0[32];
    unsigned r283 = douts0[33];
    unsigned r284 = douts0[34];
    unsigned r285 = douts0[35];
    unsigned r286 = douts0[36];
    unsigned r287 = douts0[37];
    unsigned r288 = douts0[38];
    unsigned r289 = douts0[39];
    unsigned r290 = douts0[40];
    unsigned r291 = douts0[41];
    unsigned r292 = douts0[42];
    unsigned r293 = douts0[43];
    unsigned r294 = douts0[44];
    unsigned r295 = douts0[45];
    unsigned r296 = douts0[46];
    unsigned r297 = douts0[47];
    unsigned r298 = douts0[48];
    unsigned r299 = douts0[49];
    unsigned r300 = douts0[50];
    unsigned r301 = douts0[51];
    unsigned r302 = douts0[52];
    unsigned r303 = douts0[53];
    unsigned r304 = douts0[54];
    unsigned r305 = douts0[55];
    unsigned r306 = douts0[56];
    unsigned r307 = douts0[57];
    unsigned r308 = douts0[58];
    unsigned r309 = douts0[59];
    unsigned r310 = douts0[60];
    unsigned r311 = douts0[61];
    unsigned r312 = douts0[62];
    unsigned r313 = douts0[63];
    unsigned r314 = douts0[64];
    unsigned r315 = douts0[65];
    unsigned r316 = douts0[66];
    unsigned r317 = douts0[67];
    unsigned r318 = douts0[68];
    unsigned r319 = douts0[69];
    unsigned r320 = douts0[70];
    unsigned r321 = douts0[71];
    const unsigned dargs1[72] = { r165, r1, r252, r253, r254, r255, r256, r257, r258, r259, r260, r261, r262, r263, r264, r265, r266, r267, r268, r269, r270, r271, r272, r273, r274, r275, r276, r277, r278, r279, r280, r281, r282, r283, r284, r285, r286, r287, r288, r289, r290, r291, r292, r293, r294, r295, r296, r297, r298, r299, r300, r301, r302, r303, r304, r305, r306, r307, r308, r309, r310, r311, r312, r313, r314, r315, r316, r317, r318, r319, r320, r321 };
    unsigned douts1[72];
    sub_words[81u * row_count + row] = r252;
    sub_words[82u * row_count + row] = r253;
    sub_words[83u * row_count + row] = r254;
    sub_words[84u * row_count + row] = r255;
    sub_words[85u * row_count + row] = r256;
    sub_words[86u * row_count + row] = r257;
    sub_words[87u * row_count + row] = r258;
    sub_words[88u * row_count + row] = r259;
    sub_words[89u * row_count + row] = r260;
    sub_words[90u * row_count + row] = r261;
    sub_words[91u * row_count + row] = r262;
    sub_words[92u * row_count + row] = r263;
    sub_words[93u * row_count + row] = r264;
    sub_words[94u * row_count + row] = r265;
    sub_words[95u * row_count + row] = r266;
    sub_words[96u * row_count + row] = r267;
    sub_words[97u * row_count + row] = r268;
    sub_words[98u * row_count + row] = r269;
    sub_words[99u * row_count + row] = r270;
    sub_words[100u * row_count + row] = r271;
    sub_words[101u * row_count + row] = r272;
    sub_words[102u * row_count + row] = r273;
    sub_words[103u * row_count + row] = r274;
    sub_words[104u * row_count + row] = r275;
    sub_words[105u * row_count + row] = r276;
    sub_words[106u * row_count + row] = r277;
    sub_words[107u * row_count + row] = r278;
    sub_words[108u * row_count + row] = r279;
    sub_words[109u * row_count + row] = r280;
    sub_words[110u * row_count + row] = r281;
    sub_words[111u * row_count + row] = r282;
    sub_words[112u * row_count + row] = r283;
    sub_words[113u * row_count + row] = r284;
    sub_words[114u * row_count + row] = r285;
    sub_words[115u * row_count + row] = r286;
    sub_words[116u * row_count + row] = r287;
    sub_words[117u * row_count + row] = r288;
    sub_words[118u * row_count + row] = r289;
    sub_words[119u * row_count + row] = r290;
    sub_words[120u * row_count + row] = r291;
    sub_words[121u * row_count + row] = r292;
    sub_words[122u * row_count + row] = r293;
    sub_words[123u * row_count + row] = r294;
    sub_words[124u * row_count + row] = r295;
    sub_words[125u * row_count + row] = r296;
    sub_words[126u * row_count + row] = r297;
    sub_words[127u * row_count + row] = r298;
    sub_words[128u * row_count + row] = r299;
    sub_words[129u * row_count + row] = r300;
    sub_words[130u * row_count + row] = r301;
    sub_words[131u * row_count + row] = r302;
    sub_words[132u * row_count + row] = r303;
    sub_words[133u * row_count + row] = r304;
    sub_words[134u * row_count + row] = r305;
    sub_words[135u * row_count + row] = r306;
    sub_words[136u * row_count + row] = r307;
    sub_words[137u * row_count + row] = r308;
    sub_words[138u * row_count + row] = r309;
    sub_words[139u * row_count + row] = r310;
    sub_words[140u * row_count + row] = r311;
    sub_words[141u * row_count + row] = r312;
    sub_words[142u * row_count + row] = r313;
    sub_words[143u * row_count + row] = r314;
    sub_words[144u * row_count + row] = r315;
    sub_words[145u * row_count + row] = r316;
    sub_words[146u * row_count + row] = r317;
    sub_words[147u * row_count + row] = r318;
    sub_words[148u * row_count + row] = r319;
    sub_words[149u * row_count + row] = r320;
    sub_words[150u * row_count + row] = r321;
    stwo_wit_deduce_partial_ec_mul_w18(dargs1, douts1);
    unsigned r322 = douts1[0];
    unsigned r323 = douts1[1];
    unsigned r324 = douts1[2];
    unsigned r325 = douts1[3];
    unsigned r326 = douts1[4];
    unsigned r327 = douts1[5];
    unsigned r328 = douts1[6];
    unsigned r329 = douts1[7];
    unsigned r330 = douts1[8];
    unsigned r331 = douts1[9];
    unsigned r332 = douts1[10];
    unsigned r333 = douts1[11];
    unsigned r334 = douts1[12];
    unsigned r335 = douts1[13];
    unsigned r336 = douts1[14];
    unsigned r337 = douts1[15];
    unsigned r338 = douts1[16];
    unsigned r339 = douts1[17];
    unsigned r340 = douts1[18];
    unsigned r341 = douts1[19];
    unsigned r342 = douts1[20];
    unsigned r343 = douts1[21];
    unsigned r344 = douts1[22];
    unsigned r345 = douts1[23];
    unsigned r346 = douts1[24];
    unsigned r347 = douts1[25];
    unsigned r348 = douts1[26];
    unsigned r349 = douts1[27];
    unsigned r350 = douts1[28];
    unsigned r351 = douts1[29];
    unsigned r352 = douts1[30];
    unsigned r353 = douts1[31];
    unsigned r354 = douts1[32];
    unsigned r355 = douts1[33];
    unsigned r356 = douts1[34];
    unsigned r357 = douts1[35];
    unsigned r358 = douts1[36];
    unsigned r359 = douts1[37];
    unsigned r360 = douts1[38];
    unsigned r361 = douts1[39];
    unsigned r362 = douts1[40];
    unsigned r363 = douts1[41];
    unsigned r364 = douts1[42];
    unsigned r365 = douts1[43];
    unsigned r366 = douts1[44];
    unsigned r367 = douts1[45];
    unsigned r368 = douts1[46];
    unsigned r369 = douts1[47];
    unsigned r370 = douts1[48];
    unsigned r371 = douts1[49];
    unsigned r372 = douts1[50];
    unsigned r373 = douts1[51];
    unsigned r374 = douts1[52];
    unsigned r375 = douts1[53];
    unsigned r376 = douts1[54];
    unsigned r377 = douts1[55];
    unsigned r378 = douts1[56];
    unsigned r379 = douts1[57];
    unsigned r380 = douts1[58];
    unsigned r381 = douts1[59];
    unsigned r382 = douts1[60];
    unsigned r383 = douts1[61];
    unsigned r384 = douts1[62];
    unsigned r385 = douts1[63];
    unsigned r386 = douts1[64];
    unsigned r387 = douts1[65];
    unsigned r388 = douts1[66];
    unsigned r389 = douts1[67];
    unsigned r390 = douts1[68];
    unsigned r391 = douts1[69];
    unsigned r392 = douts1[70];
    unsigned r393 = douts1[71];
    const unsigned dargs2[72] = { r165, r2, r324, r325, r326, r327, r328, r329, r330, r331, r332, r333, r334, r335, r336, r337, r338, r339, r340, r341, r342, r343, r344, r345, r346, r347, r348, r349, r350, r351, r352, r353, r354, r355, r356, r357, r358, r359, r360, r361, r362, r363, r364, r365, r366, r367, r368, r369, r370, r371, r372, r373, r374, r375, r376, r377, r378, r379, r380, r381, r382, r383, r384, r385, r386, r387, r388, r389, r390, r391, r392, r393 };
    unsigned douts2[72];
    sub_words[152u * row_count + row] = r2;
    sub_words[153u * row_count + row] = r324;
    sub_words[154u * row_count + row] = r325;
    sub_words[155u * row_count + row] = r326;
    sub_words[156u * row_count + row] = r327;
    sub_words[157u * row_count + row] = r328;
    sub_words[158u * row_count + row] = r329;
    sub_words[159u * row_count + row] = r330;
    sub_words[160u * row_count + row] = r331;
    sub_words[161u * row_count + row] = r332;
    sub_words[162u * row_count + row] = r333;
    sub_words[163u * row_count + row] = r334;
    sub_words[164u * row_count + row] = r335;
    sub_words[165u * row_count + row] = r336;
    sub_words[166u * row_count + row] = r337;
    sub_words[167u * row_count + row] = r338;
    sub_words[168u * row_count + row] = r339;
    sub_words[169u * row_count + row] = r340;
    sub_words[170u * row_count + row] = r341;
    sub_words[171u * row_count + row] = r342;
    sub_words[172u * row_count + row] = r343;
    sub_words[173u * row_count + row] = r344;
    sub_words[174u * row_count + row] = r345;
    sub_words[175u * row_count + row] = r346;
    sub_words[176u * row_count + row] = r347;
    sub_words[177u * row_count + row] = r348;
    sub_words[178u * row_count + row] = r349;
    sub_words[179u * row_count + row] = r350;
    sub_words[180u * row_count + row] = r351;
    sub_words[181u * row_count + row] = r352;
    sub_words[182u * row_count + row] = r353;
    sub_words[183u * row_count + row] = r354;
    sub_words[184u * row_count + row] = r355;
    sub_words[185u * row_count + row] = r356;
    sub_words[186u * row_count + row] = r357;
    sub_words[187u * row_count + row] = r358;
    sub_words[188u * row_count + row] = r359;
    sub_words[189u * row_count + row] = r360;
    sub_words[190u * row_count + row] = r361;
    sub_words[191u * row_count + row] = r362;
    sub_words[192u * row_count + row] = r363;
    sub_words[193u * row_count + row] = r364;
    sub_words[194u * row_count + row] = r365;
    sub_words[195u * row_count + row] = r366;
    sub_words[196u * row_count + row] = r367;
    sub_words[197u * row_count + row] = r368;
    sub_words[198u * row_count + row] = r369;
    sub_words[199u * row_count + row] = r370;
    sub_words[200u * row_count + row] = r371;
    sub_words[201u * row_count + row] = r372;
    sub_words[202u * row_count + row] = r373;
    sub_words[203u * row_count + row] = r374;
    sub_words[204u * row_count + row] = r375;
    sub_words[205u * row_count + row] = r376;
    sub_words[206u * row_count + row] = r377;
    sub_words[207u * row_count + row] = r378;
    sub_words[208u * row_count + row] = r379;
    sub_words[209u * row_count + row] = r380;
    sub_words[210u * row_count + row] = r381;
    sub_words[211u * row_count + row] = r382;
    sub_words[212u * row_count + row] = r383;
    sub_words[213u * row_count + row] = r384;
    sub_words[214u * row_count + row] = r385;
    sub_words[215u * row_count + row] = r386;
    sub_words[216u * row_count + row] = r387;
    sub_words[217u * row_count + row] = r388;
    sub_words[218u * row_count + row] = r389;
    sub_words[219u * row_count + row] = r390;
    sub_words[220u * row_count + row] = r391;
    sub_words[221u * row_count + row] = r392;
    sub_words[222u * row_count + row] = r393;
    stwo_wit_deduce_partial_ec_mul_w18(dargs2, douts2);
    unsigned r394 = douts2[0];
    unsigned r395 = douts2[1];
    unsigned r396 = douts2[2];
    unsigned r397 = douts2[3];
    unsigned r398 = douts2[4];
    unsigned r399 = douts2[5];
    unsigned r400 = douts2[6];
    unsigned r401 = douts2[7];
    unsigned r402 = douts2[8];
    unsigned r403 = douts2[9];
    unsigned r404 = douts2[10];
    unsigned r405 = douts2[11];
    unsigned r406 = douts2[12];
    unsigned r407 = douts2[13];
    unsigned r408 = douts2[14];
    unsigned r409 = douts2[15];
    unsigned r410 = douts2[16];
    unsigned r411 = douts2[17];
    unsigned r412 = douts2[18];
    unsigned r413 = douts2[19];
    unsigned r414 = douts2[20];
    unsigned r415 = douts2[21];
    unsigned r416 = douts2[22];
    unsigned r417 = douts2[23];
    unsigned r418 = douts2[24];
    unsigned r419 = douts2[25];
    unsigned r420 = douts2[26];
    unsigned r421 = douts2[27];
    unsigned r422 = douts2[28];
    unsigned r423 = douts2[29];
    unsigned r424 = douts2[30];
    unsigned r425 = douts2[31];
    unsigned r426 = douts2[32];
    unsigned r427 = douts2[33];
    unsigned r428 = douts2[34];
    unsigned r429 = douts2[35];
    unsigned r430 = douts2[36];
    unsigned r431 = douts2[37];
    unsigned r432 = douts2[38];
    unsigned r433 = douts2[39];
    unsigned r434 = douts2[40];
    unsigned r435 = douts2[41];
    unsigned r436 = douts2[42];
    unsigned r437 = douts2[43];
    unsigned r438 = douts2[44];
    unsigned r439 = douts2[45];
    unsigned r440 = douts2[46];
    unsigned r441 = douts2[47];
    unsigned r442 = douts2[48];
    unsigned r443 = douts2[49];
    unsigned r444 = douts2[50];
    unsigned r445 = douts2[51];
    unsigned r446 = douts2[52];
    unsigned r447 = douts2[53];
    unsigned r448 = douts2[54];
    unsigned r449 = douts2[55];
    unsigned r450 = douts2[56];
    unsigned r451 = douts2[57];
    unsigned r452 = douts2[58];
    unsigned r453 = douts2[59];
    unsigned r454 = douts2[60];
    unsigned r455 = douts2[61];
    unsigned r456 = douts2[62];
    unsigned r457 = douts2[63];
    unsigned r458 = douts2[64];
    unsigned r459 = douts2[65];
    unsigned r460 = douts2[66];
    unsigned r461 = douts2[67];
    unsigned r462 = douts2[68];
    unsigned r463 = douts2[69];
    unsigned r464 = douts2[70];
    unsigned r465 = douts2[71];
    const unsigned dargs3[72] = { r165, r3, r396, r397, r398, r399, r400, r401, r402, r403, r404, r405, r406, r407, r408, r409, r410, r411, r412, r413, r414, r415, r416, r417, r418, r419, r420, r421, r422, r423, r424, r425, r426, r427, r428, r429, r430, r431, r432, r433, r434, r435, r436, r437, r438, r439, r440, r441, r442, r443, r444, r445, r446, r447, r448, r449, r450, r451, r452, r453, r454, r455, r456, r457, r458, r459, r460, r461, r462, r463, r464, r465 };
    unsigned douts3[72];
    sub_words[224u * row_count + row] = r3;
    sub_words[225u * row_count + row] = r396;
    sub_words[226u * row_count + row] = r397;
    sub_words[227u * row_count + row] = r398;
    sub_words[228u * row_count + row] = r399;
    sub_words[229u * row_count + row] = r400;
    sub_words[230u * row_count + row] = r401;
    sub_words[231u * row_count + row] = r402;
    sub_words[232u * row_count + row] = r403;
    sub_words[233u * row_count + row] = r404;
    sub_words[234u * row_count + row] = r405;
    sub_words[235u * row_count + row] = r406;
    sub_words[236u * row_count + row] = r407;
    sub_words[237u * row_count + row] = r408;
    sub_words[238u * row_count + row] = r409;
    sub_words[239u * row_count + row] = r410;
    sub_words[240u * row_count + row] = r411;
    sub_words[241u * row_count + row] = r412;
    sub_words[242u * row_count + row] = r413;
    sub_words[243u * row_count + row] = r414;
    sub_words[244u * row_count + row] = r415;
    sub_words[245u * row_count + row] = r416;
    sub_words[246u * row_count + row] = r417;
    sub_words[247u * row_count + row] = r418;
    sub_words[248u * row_count + row] = r419;
    sub_words[249u * row_count + row] = r420;
    sub_words[250u * row_count + row] = r421;
    sub_words[251u * row_count + row] = r422;
    sub_words[252u * row_count + row] = r423;
    sub_words[253u * row_count + row] = r424;
    sub_words[254u * row_count + row] = r425;
    sub_words[255u * row_count + row] = r426;
    sub_words[256u * row_count + row] = r427;
    sub_words[257u * row_count + row] = r428;
    sub_words[258u * row_count + row] = r429;
    sub_words[259u * row_count + row] = r430;
    sub_words[260u * row_count + row] = r431;
    sub_words[261u * row_count + row] = r432;
    sub_words[262u * row_count + row] = r433;
    sub_words[263u * row_count + row] = r434;
    sub_words[264u * row_count + row] = r435;
    sub_words[265u * row_count + row] = r436;
    sub_words[266u * row_count + row] = r437;
    sub_words[267u * row_count + row] = r438;
    sub_words[268u * row_count + row] = r439;
    sub_words[269u * row_count + row] = r440;
    sub_words[270u * row_count + row] = r441;
    sub_words[271u * row_count + row] = r442;
    sub_words[272u * row_count + row] = r443;
    sub_words[273u * row_count + row] = r444;
    sub_words[274u * row_count + row] = r445;
    sub_words[275u * row_count + row] = r446;
    sub_words[276u * row_count + row] = r447;
    sub_words[277u * row_count + row] = r448;
    sub_words[278u * row_count + row] = r449;
    sub_words[279u * row_count + row] = r450;
    sub_words[280u * row_count + row] = r451;
    sub_words[281u * row_count + row] = r452;
    sub_words[282u * row_count + row] = r453;
    sub_words[283u * row_count + row] = r454;
    sub_words[284u * row_count + row] = r455;
    sub_words[285u * row_count + row] = r456;
    sub_words[286u * row_count + row] = r457;
    sub_words[287u * row_count + row] = r458;
    sub_words[288u * row_count + row] = r459;
    sub_words[289u * row_count + row] = r460;
    sub_words[290u * row_count + row] = r461;
    sub_words[291u * row_count + row] = r462;
    sub_words[292u * row_count + row] = r463;
    sub_words[293u * row_count + row] = r464;
    sub_words[294u * row_count + row] = r465;
    stwo_wit_deduce_partial_ec_mul_w18(dargs3, douts3);
    unsigned r466 = douts3[0];
    unsigned r467 = douts3[1];
    unsigned r468 = douts3[2];
    unsigned r469 = douts3[3];
    unsigned r470 = douts3[4];
    unsigned r471 = douts3[5];
    unsigned r472 = douts3[6];
    unsigned r473 = douts3[7];
    unsigned r474 = douts3[8];
    unsigned r475 = douts3[9];
    unsigned r476 = douts3[10];
    unsigned r477 = douts3[11];
    unsigned r478 = douts3[12];
    unsigned r479 = douts3[13];
    unsigned r480 = douts3[14];
    unsigned r481 = douts3[15];
    unsigned r482 = douts3[16];
    unsigned r483 = douts3[17];
    unsigned r484 = douts3[18];
    unsigned r485 = douts3[19];
    unsigned r486 = douts3[20];
    unsigned r487 = douts3[21];
    unsigned r488 = douts3[22];
    unsigned r489 = douts3[23];
    unsigned r490 = douts3[24];
    unsigned r491 = douts3[25];
    unsigned r492 = douts3[26];
    unsigned r493 = douts3[27];
    unsigned r494 = douts3[28];
    unsigned r495 = douts3[29];
    unsigned r496 = douts3[30];
    unsigned r497 = douts3[31];
    unsigned r498 = douts3[32];
    unsigned r499 = douts3[33];
    unsigned r500 = douts3[34];
    unsigned r501 = douts3[35];
    unsigned r502 = douts3[36];
    unsigned r503 = douts3[37];
    unsigned r504 = douts3[38];
    unsigned r505 = douts3[39];
    unsigned r506 = douts3[40];
    unsigned r507 = douts3[41];
    unsigned r508 = douts3[42];
    unsigned r509 = douts3[43];
    unsigned r510 = douts3[44];
    unsigned r511 = douts3[45];
    unsigned r512 = douts3[46];
    unsigned r513 = douts3[47];
    unsigned r514 = douts3[48];
    unsigned r515 = douts3[49];
    unsigned r516 = douts3[50];
    unsigned r517 = douts3[51];
    unsigned r518 = douts3[52];
    unsigned r519 = douts3[53];
    unsigned r520 = douts3[54];
    unsigned r521 = douts3[55];
    unsigned r522 = douts3[56];
    unsigned r523 = douts3[57];
    unsigned r524 = douts3[58];
    unsigned r525 = douts3[59];
    unsigned r526 = douts3[60];
    unsigned r527 = douts3[61];
    unsigned r528 = douts3[62];
    unsigned r529 = douts3[63];
    unsigned r530 = douts3[64];
    unsigned r531 = douts3[65];
    unsigned r532 = douts3[66];
    unsigned r533 = douts3[67];
    unsigned r534 = douts3[68];
    unsigned r535 = douts3[69];
    unsigned r536 = douts3[70];
    unsigned r537 = douts3[71];
    const unsigned dargs4[72] = { r165, r4, r468, r469, r470, r471, r472, r473, r474, r475, r476, r477, r478, r479, r480, r481, r482, r483, r484, r485, r486, r487, r488, r489, r490, r491, r492, r493, r494, r495, r496, r497, r498, r499, r500, r501, r502, r503, r504, r505, r506, r507, r508, r509, r510, r511, r512, r513, r514, r515, r516, r517, r518, r519, r520, r521, r522, r523, r524, r525, r526, r527, r528, r529, r530, r531, r532, r533, r534, r535, r536, r537 };
    unsigned douts4[72];
    sub_words[296u * row_count + row] = r4;
    sub_words[297u * row_count + row] = r468;
    sub_words[298u * row_count + row] = r469;
    sub_words[299u * row_count + row] = r470;
    sub_words[300u * row_count + row] = r471;
    sub_words[301u * row_count + row] = r472;
    sub_words[302u * row_count + row] = r473;
    sub_words[303u * row_count + row] = r474;
    sub_words[304u * row_count + row] = r475;
    sub_words[305u * row_count + row] = r476;
    sub_words[306u * row_count + row] = r477;
    sub_words[307u * row_count + row] = r478;
    sub_words[308u * row_count + row] = r479;
    sub_words[309u * row_count + row] = r480;
    sub_words[310u * row_count + row] = r481;
    sub_words[311u * row_count + row] = r482;
    sub_words[312u * row_count + row] = r483;
    sub_words[313u * row_count + row] = r484;
    sub_words[314u * row_count + row] = r485;
    sub_words[315u * row_count + row] = r486;
    sub_words[316u * row_count + row] = r487;
    sub_words[317u * row_count + row] = r488;
    sub_words[318u * row_count + row] = r489;
    sub_words[319u * row_count + row] = r490;
    sub_words[320u * row_count + row] = r491;
    sub_words[321u * row_count + row] = r492;
    sub_words[322u * row_count + row] = r493;
    sub_words[323u * row_count + row] = r494;
    sub_words[324u * row_count + row] = r495;
    sub_words[325u * row_count + row] = r496;
    sub_words[326u * row_count + row] = r497;
    sub_words[327u * row_count + row] = r498;
    sub_words[328u * row_count + row] = r499;
    sub_words[329u * row_count + row] = r500;
    sub_words[330u * row_count + row] = r501;
    sub_words[331u * row_count + row] = r502;
    sub_words[332u * row_count + row] = r503;
    sub_words[333u * row_count + row] = r504;
    sub_words[334u * row_count + row] = r505;
    sub_words[335u * row_count + row] = r506;
    sub_words[336u * row_count + row] = r507;
    sub_words[337u * row_count + row] = r508;
    sub_words[338u * row_count + row] = r509;
    sub_words[339u * row_count + row] = r510;
    sub_words[340u * row_count + row] = r511;
    sub_words[341u * row_count + row] = r512;
    sub_words[342u * row_count + row] = r513;
    sub_words[343u * row_count + row] = r514;
    sub_words[344u * row_count + row] = r515;
    sub_words[345u * row_count + row] = r516;
    sub_words[346u * row_count + row] = r517;
    sub_words[347u * row_count + row] = r518;
    sub_words[348u * row_count + row] = r519;
    sub_words[349u * row_count + row] = r520;
    sub_words[350u * row_count + row] = r521;
    sub_words[351u * row_count + row] = r522;
    sub_words[352u * row_count + row] = r523;
    sub_words[353u * row_count + row] = r524;
    sub_words[354u * row_count + row] = r525;
    sub_words[355u * row_count + row] = r526;
    sub_words[356u * row_count + row] = r527;
    sub_words[357u * row_count + row] = r528;
    sub_words[358u * row_count + row] = r529;
    sub_words[359u * row_count + row] = r530;
    sub_words[360u * row_count + row] = r531;
    sub_words[361u * row_count + row] = r532;
    sub_words[362u * row_count + row] = r533;
    sub_words[363u * row_count + row] = r534;
    sub_words[364u * row_count + row] = r535;
    sub_words[365u * row_count + row] = r536;
    sub_words[366u * row_count + row] = r537;
    stwo_wit_deduce_partial_ec_mul_w18(dargs4, douts4);
    unsigned r538 = douts4[0];
    unsigned r539 = douts4[1];
    unsigned r540 = douts4[2];
    unsigned r541 = douts4[3];
    unsigned r542 = douts4[4];
    unsigned r543 = douts4[5];
    unsigned r544 = douts4[6];
    unsigned r545 = douts4[7];
    unsigned r546 = douts4[8];
    unsigned r547 = douts4[9];
    unsigned r548 = douts4[10];
    unsigned r549 = douts4[11];
    unsigned r550 = douts4[12];
    unsigned r551 = douts4[13];
    unsigned r552 = douts4[14];
    unsigned r553 = douts4[15];
    unsigned r554 = douts4[16];
    unsigned r555 = douts4[17];
    unsigned r556 = douts4[18];
    unsigned r557 = douts4[19];
    unsigned r558 = douts4[20];
    unsigned r559 = douts4[21];
    unsigned r560 = douts4[22];
    unsigned r561 = douts4[23];
    unsigned r562 = douts4[24];
    unsigned r563 = douts4[25];
    unsigned r564 = douts4[26];
    unsigned r565 = douts4[27];
    unsigned r566 = douts4[28];
    unsigned r567 = douts4[29];
    unsigned r568 = douts4[30];
    unsigned r569 = douts4[31];
    unsigned r570 = douts4[32];
    unsigned r571 = douts4[33];
    unsigned r572 = douts4[34];
    unsigned r573 = douts4[35];
    unsigned r574 = douts4[36];
    unsigned r575 = douts4[37];
    unsigned r576 = douts4[38];
    unsigned r577 = douts4[39];
    unsigned r578 = douts4[40];
    unsigned r579 = douts4[41];
    unsigned r580 = douts4[42];
    unsigned r581 = douts4[43];
    unsigned r582 = douts4[44];
    unsigned r583 = douts4[45];
    unsigned r584 = douts4[46];
    unsigned r585 = douts4[47];
    unsigned r586 = douts4[48];
    unsigned r587 = douts4[49];
    unsigned r588 = douts4[50];
    unsigned r589 = douts4[51];
    unsigned r590 = douts4[52];
    unsigned r591 = douts4[53];
    unsigned r592 = douts4[54];
    unsigned r593 = douts4[55];
    unsigned r594 = douts4[56];
    unsigned r595 = douts4[57];
    unsigned r596 = douts4[58];
    unsigned r597 = douts4[59];
    unsigned r598 = douts4[60];
    unsigned r599 = douts4[61];
    unsigned r600 = douts4[62];
    unsigned r601 = douts4[63];
    unsigned r602 = douts4[64];
    unsigned r603 = douts4[65];
    unsigned r604 = douts4[66];
    unsigned r605 = douts4[67];
    unsigned r606 = douts4[68];
    unsigned r607 = douts4[69];
    unsigned r608 = douts4[70];
    unsigned r609 = douts4[71];
    const unsigned dargs5[72] = { r165, r5, r540, r541, r542, r543, r544, r545, r546, r547, r548, r549, r550, r551, r552, r553, r554, r555, r556, r557, r558, r559, r560, r561, r562, r563, r564, r565, r566, r567, r568, r569, r570, r571, r572, r573, r574, r575, r576, r577, r578, r579, r580, r581, r582, r583, r584, r585, r586, r587, r588, r589, r590, r591, r592, r593, r594, r595, r596, r597, r598, r599, r600, r601, r602, r603, r604, r605, r606, r607, r608, r609 };
    unsigned douts5[72];
    sub_words[368u * row_count + row] = r5;
    sub_words[369u * row_count + row] = r540;
    sub_words[370u * row_count + row] = r541;
    sub_words[371u * row_count + row] = r542;
    sub_words[372u * row_count + row] = r543;
    sub_words[373u * row_count + row] = r544;
    sub_words[374u * row_count + row] = r545;
    sub_words[375u * row_count + row] = r546;
    sub_words[376u * row_count + row] = r547;
    sub_words[377u * row_count + row] = r548;
    sub_words[378u * row_count + row] = r549;
    sub_words[379u * row_count + row] = r550;
    sub_words[380u * row_count + row] = r551;
    sub_words[381u * row_count + row] = r552;
    sub_words[382u * row_count + row] = r553;
    sub_words[383u * row_count + row] = r554;
    sub_words[384u * row_count + row] = r555;
    sub_words[385u * row_count + row] = r556;
    sub_words[386u * row_count + row] = r557;
    sub_words[387u * row_count + row] = r558;
    sub_words[388u * row_count + row] = r559;
    sub_words[389u * row_count + row] = r560;
    sub_words[390u * row_count + row] = r561;
    sub_words[391u * row_count + row] = r562;
    sub_words[392u * row_count + row] = r563;
    sub_words[393u * row_count + row] = r564;
    sub_words[394u * row_count + row] = r565;
    sub_words[395u * row_count + row] = r566;
    sub_words[396u * row_count + row] = r567;
    sub_words[397u * row_count + row] = r568;
    sub_words[398u * row_count + row] = r569;
    sub_words[399u * row_count + row] = r570;
    sub_words[400u * row_count + row] = r571;
    sub_words[401u * row_count + row] = r572;
    sub_words[402u * row_count + row] = r573;
    sub_words[403u * row_count + row] = r574;
    sub_words[404u * row_count + row] = r575;
    sub_words[405u * row_count + row] = r576;
    sub_words[406u * row_count + row] = r577;
    sub_words[407u * row_count + row] = r578;
    sub_words[408u * row_count + row] = r579;
    sub_words[409u * row_count + row] = r580;
    sub_words[410u * row_count + row] = r581;
    sub_words[411u * row_count + row] = r582;
    sub_words[412u * row_count + row] = r583;
    sub_words[413u * row_count + row] = r584;
    sub_words[414u * row_count + row] = r585;
    sub_words[415u * row_count + row] = r586;
    sub_words[416u * row_count + row] = r587;
    sub_words[417u * row_count + row] = r588;
    sub_words[418u * row_count + row] = r589;
    sub_words[419u * row_count + row] = r590;
    sub_words[420u * row_count + row] = r591;
    sub_words[421u * row_count + row] = r592;
    sub_words[422u * row_count + row] = r593;
    sub_words[423u * row_count + row] = r594;
    sub_words[424u * row_count + row] = r595;
    sub_words[425u * row_count + row] = r596;
    sub_words[426u * row_count + row] = r597;
    sub_words[427u * row_count + row] = r598;
    sub_words[428u * row_count + row] = r599;
    sub_words[429u * row_count + row] = r600;
    sub_words[430u * row_count + row] = r601;
    sub_words[431u * row_count + row] = r602;
    sub_words[432u * row_count + row] = r603;
    sub_words[433u * row_count + row] = r604;
    sub_words[434u * row_count + row] = r605;
    sub_words[435u * row_count + row] = r606;
    sub_words[436u * row_count + row] = r607;
    sub_words[437u * row_count + row] = r608;
    sub_words[438u * row_count + row] = r609;
    stwo_wit_deduce_partial_ec_mul_w18(dargs5, douts5);
    unsigned r610 = douts5[0];
    unsigned r611 = douts5[1];
    unsigned r612 = douts5[2];
    unsigned r613 = douts5[3];
    unsigned r614 = douts5[4];
    unsigned r615 = douts5[5];
    unsigned r616 = douts5[6];
    unsigned r617 = douts5[7];
    unsigned r618 = douts5[8];
    unsigned r619 = douts5[9];
    unsigned r620 = douts5[10];
    unsigned r621 = douts5[11];
    unsigned r622 = douts5[12];
    unsigned r623 = douts5[13];
    unsigned r624 = douts5[14];
    unsigned r625 = douts5[15];
    unsigned r626 = douts5[16];
    unsigned r627 = douts5[17];
    unsigned r628 = douts5[18];
    unsigned r629 = douts5[19];
    unsigned r630 = douts5[20];
    unsigned r631 = douts5[21];
    unsigned r632 = douts5[22];
    unsigned r633 = douts5[23];
    unsigned r634 = douts5[24];
    unsigned r635 = douts5[25];
    unsigned r636 = douts5[26];
    unsigned r637 = douts5[27];
    unsigned r638 = douts5[28];
    unsigned r639 = douts5[29];
    unsigned r640 = douts5[30];
    unsigned r641 = douts5[31];
    unsigned r642 = douts5[32];
    unsigned r643 = douts5[33];
    unsigned r644 = douts5[34];
    unsigned r645 = douts5[35];
    unsigned r646 = douts5[36];
    unsigned r647 = douts5[37];
    unsigned r648 = douts5[38];
    unsigned r649 = douts5[39];
    unsigned r650 = douts5[40];
    unsigned r651 = douts5[41];
    unsigned r652 = douts5[42];
    unsigned r653 = douts5[43];
    unsigned r654 = douts5[44];
    unsigned r655 = douts5[45];
    unsigned r656 = douts5[46];
    unsigned r657 = douts5[47];
    unsigned r658 = douts5[48];
    unsigned r659 = douts5[49];
    unsigned r660 = douts5[50];
    unsigned r661 = douts5[51];
    unsigned r662 = douts5[52];
    unsigned r663 = douts5[53];
    unsigned r664 = douts5[54];
    unsigned r665 = douts5[55];
    unsigned r666 = douts5[56];
    unsigned r667 = douts5[57];
    unsigned r668 = douts5[58];
    unsigned r669 = douts5[59];
    unsigned r670 = douts5[60];
    unsigned r671 = douts5[61];
    unsigned r672 = douts5[62];
    unsigned r673 = douts5[63];
    unsigned r674 = douts5[64];
    unsigned r675 = douts5[65];
    unsigned r676 = douts5[66];
    unsigned r677 = douts5[67];
    unsigned r678 = douts5[68];
    unsigned r679 = douts5[69];
    unsigned r680 = douts5[70];
    unsigned r681 = douts5[71];
    const unsigned dargs6[72] = { r165, r6, r612, r613, r614, r615, r616, r617, r618, r619, r620, r621, r622, r623, r624, r625, r626, r627, r628, r629, r630, r631, r632, r633, r634, r635, r636, r637, r638, r639, r640, r641, r642, r643, r644, r645, r646, r647, r648, r649, r650, r651, r652, r653, r654, r655, r656, r657, r658, r659, r660, r661, r662, r663, r664, r665, r666, r667, r668, r669, r670, r671, r672, r673, r674, r675, r676, r677, r678, r679, r680, r681 };
    unsigned douts6[72];
    sub_words[440u * row_count + row] = r6;
    sub_words[441u * row_count + row] = r612;
    sub_words[442u * row_count + row] = r613;
    sub_words[443u * row_count + row] = r614;
    sub_words[444u * row_count + row] = r615;
    sub_words[445u * row_count + row] = r616;
    sub_words[446u * row_count + row] = r617;
    sub_words[447u * row_count + row] = r618;
    sub_words[448u * row_count + row] = r619;
    sub_words[449u * row_count + row] = r620;
    sub_words[450u * row_count + row] = r621;
    sub_words[451u * row_count + row] = r622;
    sub_words[452u * row_count + row] = r623;
    sub_words[453u * row_count + row] = r624;
    sub_words[454u * row_count + row] = r625;
    sub_words[455u * row_count + row] = r626;
    sub_words[456u * row_count + row] = r627;
    sub_words[457u * row_count + row] = r628;
    sub_words[458u * row_count + row] = r629;
    sub_words[459u * row_count + row] = r630;
    sub_words[460u * row_count + row] = r631;
    sub_words[461u * row_count + row] = r632;
    sub_words[462u * row_count + row] = r633;
    sub_words[463u * row_count + row] = r634;
    sub_words[464u * row_count + row] = r635;
    sub_words[465u * row_count + row] = r636;
    sub_words[466u * row_count + row] = r637;
    sub_words[467u * row_count + row] = r638;
    sub_words[468u * row_count + row] = r639;
    sub_words[469u * row_count + row] = r640;
    sub_words[470u * row_count + row] = r641;
    sub_words[471u * row_count + row] = r642;
    sub_words[472u * row_count + row] = r643;
    sub_words[473u * row_count + row] = r644;
    sub_words[474u * row_count + row] = r645;
    sub_words[475u * row_count + row] = r646;
    sub_words[476u * row_count + row] = r647;
    sub_words[477u * row_count + row] = r648;
    sub_words[478u * row_count + row] = r649;
    sub_words[479u * row_count + row] = r650;
    sub_words[480u * row_count + row] = r651;
    sub_words[481u * row_count + row] = r652;
    sub_words[482u * row_count + row] = r653;
    sub_words[483u * row_count + row] = r654;
    sub_words[484u * row_count + row] = r655;
    sub_words[485u * row_count + row] = r656;
    sub_words[486u * row_count + row] = r657;
    sub_words[487u * row_count + row] = r658;
    sub_words[488u * row_count + row] = r659;
    sub_words[489u * row_count + row] = r660;
    sub_words[490u * row_count + row] = r661;
    sub_words[491u * row_count + row] = r662;
    sub_words[492u * row_count + row] = r663;
    sub_words[493u * row_count + row] = r664;
    sub_words[494u * row_count + row] = r665;
    sub_words[495u * row_count + row] = r666;
    sub_words[496u * row_count + row] = r667;
    sub_words[497u * row_count + row] = r668;
    sub_words[498u * row_count + row] = r669;
    sub_words[499u * row_count + row] = r670;
    sub_words[500u * row_count + row] = r671;
    sub_words[501u * row_count + row] = r672;
    sub_words[502u * row_count + row] = r673;
    sub_words[503u * row_count + row] = r674;
    sub_words[504u * row_count + row] = r675;
    sub_words[505u * row_count + row] = r676;
    sub_words[506u * row_count + row] = r677;
    sub_words[507u * row_count + row] = r678;
    sub_words[508u * row_count + row] = r679;
    sub_words[509u * row_count + row] = r680;
    sub_words[510u * row_count + row] = r681;
    stwo_wit_deduce_partial_ec_mul_w18(dargs6, douts6);
    unsigned r682 = douts6[0];
    unsigned r683 = douts6[1];
    unsigned r684 = douts6[2];
    unsigned r685 = douts6[3];
    unsigned r686 = douts6[4];
    unsigned r687 = douts6[5];
    unsigned r688 = douts6[6];
    unsigned r689 = douts6[7];
    unsigned r690 = douts6[8];
    unsigned r691 = douts6[9];
    unsigned r692 = douts6[10];
    unsigned r693 = douts6[11];
    unsigned r694 = douts6[12];
    unsigned r695 = douts6[13];
    unsigned r696 = douts6[14];
    unsigned r697 = douts6[15];
    unsigned r698 = douts6[16];
    unsigned r699 = douts6[17];
    unsigned r700 = douts6[18];
    unsigned r701 = douts6[19];
    unsigned r702 = douts6[20];
    unsigned r703 = douts6[21];
    unsigned r704 = douts6[22];
    unsigned r705 = douts6[23];
    unsigned r706 = douts6[24];
    unsigned r707 = douts6[25];
    unsigned r708 = douts6[26];
    unsigned r709 = douts6[27];
    unsigned r710 = douts6[28];
    unsigned r711 = douts6[29];
    unsigned r712 = douts6[30];
    unsigned r713 = douts6[31];
    unsigned r714 = douts6[32];
    unsigned r715 = douts6[33];
    unsigned r716 = douts6[34];
    unsigned r717 = douts6[35];
    unsigned r718 = douts6[36];
    unsigned r719 = douts6[37];
    unsigned r720 = douts6[38];
    unsigned r721 = douts6[39];
    unsigned r722 = douts6[40];
    unsigned r723 = douts6[41];
    unsigned r724 = douts6[42];
    unsigned r725 = douts6[43];
    unsigned r726 = douts6[44];
    unsigned r727 = douts6[45];
    unsigned r728 = douts6[46];
    unsigned r729 = douts6[47];
    unsigned r730 = douts6[48];
    unsigned r731 = douts6[49];
    unsigned r732 = douts6[50];
    unsigned r733 = douts6[51];
    unsigned r734 = douts6[52];
    unsigned r735 = douts6[53];
    unsigned r736 = douts6[54];
    unsigned r737 = douts6[55];
    unsigned r738 = douts6[56];
    unsigned r739 = douts6[57];
    unsigned r740 = douts6[58];
    unsigned r741 = douts6[59];
    unsigned r742 = douts6[60];
    unsigned r743 = douts6[61];
    unsigned r744 = douts6[62];
    unsigned r745 = douts6[63];
    unsigned r746 = douts6[64];
    unsigned r747 = douts6[65];
    unsigned r748 = douts6[66];
    unsigned r749 = douts6[67];
    unsigned r750 = douts6[68];
    unsigned r751 = douts6[69];
    unsigned r752 = douts6[70];
    unsigned r753 = douts6[71];
    const unsigned dargs7[72] = { r165, r7, r684, r685, r686, r687, r688, r689, r690, r691, r692, r693, r694, r695, r696, r697, r698, r699, r700, r701, r702, r703, r704, r705, r706, r707, r708, r709, r710, r711, r712, r713, r714, r715, r716, r717, r718, r719, r720, r721, r722, r723, r724, r725, r726, r727, r728, r729, r730, r731, r732, r733, r734, r735, r736, r737, r738, r739, r740, r741, r742, r743, r744, r745, r746, r747, r748, r749, r750, r751, r752, r753 };
    unsigned douts7[72];
    sub_words[512u * row_count + row] = r7;
    sub_words[513u * row_count + row] = r684;
    sub_words[514u * row_count + row] = r685;
    sub_words[515u * row_count + row] = r686;
    sub_words[516u * row_count + row] = r687;
    sub_words[517u * row_count + row] = r688;
    sub_words[518u * row_count + row] = r689;
    sub_words[519u * row_count + row] = r690;
    sub_words[520u * row_count + row] = r691;
    sub_words[521u * row_count + row] = r692;
    sub_words[522u * row_count + row] = r693;
    sub_words[523u * row_count + row] = r694;
    sub_words[524u * row_count + row] = r695;
    sub_words[525u * row_count + row] = r696;
    sub_words[526u * row_count + row] = r697;
    sub_words[527u * row_count + row] = r698;
    sub_words[528u * row_count + row] = r699;
    sub_words[529u * row_count + row] = r700;
    sub_words[530u * row_count + row] = r701;
    sub_words[531u * row_count + row] = r702;
    sub_words[532u * row_count + row] = r703;
    sub_words[533u * row_count + row] = r704;
    sub_words[534u * row_count + row] = r705;
    sub_words[535u * row_count + row] = r706;
    sub_words[536u * row_count + row] = r707;
    sub_words[537u * row_count + row] = r708;
    sub_words[538u * row_count + row] = r709;
    sub_words[539u * row_count + row] = r710;
    sub_words[540u * row_count + row] = r711;
    sub_words[541u * row_count + row] = r712;
    sub_words[542u * row_count + row] = r713;
    sub_words[543u * row_count + row] = r714;
    sub_words[544u * row_count + row] = r715;
    sub_words[545u * row_count + row] = r716;
    sub_words[546u * row_count + row] = r717;
    sub_words[547u * row_count + row] = r718;
    sub_words[548u * row_count + row] = r719;
    sub_words[549u * row_count + row] = r720;
    sub_words[550u * row_count + row] = r721;
    sub_words[551u * row_count + row] = r722;
    sub_words[552u * row_count + row] = r723;
    sub_words[553u * row_count + row] = r724;
    sub_words[554u * row_count + row] = r725;
    sub_words[555u * row_count + row] = r726;
    sub_words[556u * row_count + row] = r727;
    sub_words[557u * row_count + row] = r728;
    sub_words[558u * row_count + row] = r729;
    sub_words[559u * row_count + row] = r730;
    sub_words[560u * row_count + row] = r731;
    sub_words[561u * row_count + row] = r732;
    sub_words[562u * row_count + row] = r733;
    sub_words[563u * row_count + row] = r734;
    sub_words[564u * row_count + row] = r735;
    sub_words[565u * row_count + row] = r736;
    sub_words[566u * row_count + row] = r737;
    sub_words[567u * row_count + row] = r738;
    sub_words[568u * row_count + row] = r739;
    sub_words[569u * row_count + row] = r740;
    sub_words[570u * row_count + row] = r741;
    sub_words[571u * row_count + row] = r742;
    sub_words[572u * row_count + row] = r743;
    sub_words[573u * row_count + row] = r744;
    sub_words[574u * row_count + row] = r745;
    sub_words[575u * row_count + row] = r746;
    sub_words[576u * row_count + row] = r747;
    sub_words[577u * row_count + row] = r748;
    sub_words[578u * row_count + row] = r749;
    sub_words[579u * row_count + row] = r750;
    sub_words[580u * row_count + row] = r751;
    sub_words[581u * row_count + row] = r752;
    sub_words[582u * row_count + row] = r753;
    stwo_wit_deduce_partial_ec_mul_w18(dargs7, douts7);
    unsigned r754 = douts7[0];
    unsigned r755 = douts7[1];
    unsigned r756 = douts7[2];
    unsigned r757 = douts7[3];
    unsigned r758 = douts7[4];
    unsigned r759 = douts7[5];
    unsigned r760 = douts7[6];
    unsigned r761 = douts7[7];
    unsigned r762 = douts7[8];
    unsigned r763 = douts7[9];
    unsigned r764 = douts7[10];
    unsigned r765 = douts7[11];
    unsigned r766 = douts7[12];
    unsigned r767 = douts7[13];
    unsigned r768 = douts7[14];
    unsigned r769 = douts7[15];
    unsigned r770 = douts7[16];
    unsigned r771 = douts7[17];
    unsigned r772 = douts7[18];
    unsigned r773 = douts7[19];
    unsigned r774 = douts7[20];
    unsigned r775 = douts7[21];
    unsigned r776 = douts7[22];
    unsigned r777 = douts7[23];
    unsigned r778 = douts7[24];
    unsigned r779 = douts7[25];
    unsigned r780 = douts7[26];
    unsigned r781 = douts7[27];
    unsigned r782 = douts7[28];
    unsigned r783 = douts7[29];
    unsigned r784 = douts7[30];
    unsigned r785 = douts7[31];
    unsigned r786 = douts7[32];
    unsigned r787 = douts7[33];
    unsigned r788 = douts7[34];
    unsigned r789 = douts7[35];
    unsigned r790 = douts7[36];
    unsigned r791 = douts7[37];
    unsigned r792 = douts7[38];
    unsigned r793 = douts7[39];
    unsigned r794 = douts7[40];
    unsigned r795 = douts7[41];
    unsigned r796 = douts7[42];
    unsigned r797 = douts7[43];
    unsigned r798 = douts7[44];
    unsigned r799 = douts7[45];
    unsigned r800 = douts7[46];
    unsigned r801 = douts7[47];
    unsigned r802 = douts7[48];
    unsigned r803 = douts7[49];
    unsigned r804 = douts7[50];
    unsigned r805 = douts7[51];
    unsigned r806 = douts7[52];
    unsigned r807 = douts7[53];
    unsigned r808 = douts7[54];
    unsigned r809 = douts7[55];
    unsigned r810 = douts7[56];
    unsigned r811 = douts7[57];
    unsigned r812 = douts7[58];
    unsigned r813 = douts7[59];
    unsigned r814 = douts7[60];
    unsigned r815 = douts7[61];
    unsigned r816 = douts7[62];
    unsigned r817 = douts7[63];
    unsigned r818 = douts7[64];
    unsigned r819 = douts7[65];
    unsigned r820 = douts7[66];
    unsigned r821 = douts7[67];
    unsigned r822 = douts7[68];
    unsigned r823 = douts7[69];
    unsigned r824 = douts7[70];
    unsigned r825 = douts7[71];
    const unsigned dargs8[72] = { r165, r8, r756, r757, r758, r759, r760, r761, r762, r763, r764, r765, r766, r767, r768, r769, r770, r771, r772, r773, r774, r775, r776, r777, r778, r779, r780, r781, r782, r783, r784, r785, r786, r787, r788, r789, r790, r791, r792, r793, r794, r795, r796, r797, r798, r799, r800, r801, r802, r803, r804, r805, r806, r807, r808, r809, r810, r811, r812, r813, r814, r815, r816, r817, r818, r819, r820, r821, r822, r823, r824, r825 };
    unsigned douts8[72];
    sub_words[584u * row_count + row] = r8;
    sub_words[585u * row_count + row] = r756;
    sub_words[586u * row_count + row] = r757;
    sub_words[587u * row_count + row] = r758;
    sub_words[588u * row_count + row] = r759;
    sub_words[589u * row_count + row] = r760;
    sub_words[590u * row_count + row] = r761;
    sub_words[591u * row_count + row] = r762;
    sub_words[592u * row_count + row] = r763;
    sub_words[593u * row_count + row] = r764;
    sub_words[594u * row_count + row] = r765;
    sub_words[595u * row_count + row] = r766;
    sub_words[596u * row_count + row] = r767;
    sub_words[597u * row_count + row] = r768;
    sub_words[598u * row_count + row] = r769;
    sub_words[599u * row_count + row] = r770;
    sub_words[600u * row_count + row] = r771;
    sub_words[601u * row_count + row] = r772;
    sub_words[602u * row_count + row] = r773;
    sub_words[603u * row_count + row] = r774;
    sub_words[604u * row_count + row] = r775;
    sub_words[605u * row_count + row] = r776;
    sub_words[606u * row_count + row] = r777;
    sub_words[607u * row_count + row] = r778;
    sub_words[608u * row_count + row] = r779;
    sub_words[609u * row_count + row] = r780;
    sub_words[610u * row_count + row] = r781;
    sub_words[611u * row_count + row] = r782;
    sub_words[612u * row_count + row] = r783;
    sub_words[613u * row_count + row] = r784;
    sub_words[614u * row_count + row] = r785;
    sub_words[615u * row_count + row] = r786;
    sub_words[616u * row_count + row] = r787;
    sub_words[617u * row_count + row] = r788;
    sub_words[618u * row_count + row] = r789;
    sub_words[619u * row_count + row] = r790;
    sub_words[620u * row_count + row] = r791;
    sub_words[621u * row_count + row] = r792;
    sub_words[622u * row_count + row] = r793;
    sub_words[623u * row_count + row] = r794;
    sub_words[624u * row_count + row] = r795;
    sub_words[625u * row_count + row] = r796;
    sub_words[626u * row_count + row] = r797;
    sub_words[627u * row_count + row] = r798;
    sub_words[628u * row_count + row] = r799;
    sub_words[629u * row_count + row] = r800;
    sub_words[630u * row_count + row] = r801;
    sub_words[631u * row_count + row] = r802;
    sub_words[632u * row_count + row] = r803;
    sub_words[633u * row_count + row] = r804;
    sub_words[634u * row_count + row] = r805;
    sub_words[635u * row_count + row] = r806;
    sub_words[636u * row_count + row] = r807;
    sub_words[637u * row_count + row] = r808;
    sub_words[638u * row_count + row] = r809;
    sub_words[639u * row_count + row] = r810;
    sub_words[640u * row_count + row] = r811;
    sub_words[641u * row_count + row] = r812;
    sub_words[642u * row_count + row] = r813;
    sub_words[643u * row_count + row] = r814;
    sub_words[644u * row_count + row] = r815;
    sub_words[645u * row_count + row] = r816;
    sub_words[646u * row_count + row] = r817;
    sub_words[647u * row_count + row] = r818;
    sub_words[648u * row_count + row] = r819;
    sub_words[649u * row_count + row] = r820;
    sub_words[650u * row_count + row] = r821;
    sub_words[651u * row_count + row] = r822;
    sub_words[652u * row_count + row] = r823;
    sub_words[653u * row_count + row] = r824;
    sub_words[654u * row_count + row] = r825;
    stwo_wit_deduce_partial_ec_mul_w18(dargs8, douts8);
    unsigned r826 = douts8[0];
    unsigned r827 = douts8[1];
    unsigned r828 = douts8[2];
    unsigned r829 = douts8[3];
    unsigned r830 = douts8[4];
    unsigned r831 = douts8[5];
    unsigned r832 = douts8[6];
    unsigned r833 = douts8[7];
    unsigned r834 = douts8[8];
    unsigned r835 = douts8[9];
    unsigned r836 = douts8[10];
    unsigned r837 = douts8[11];
    unsigned r838 = douts8[12];
    unsigned r839 = douts8[13];
    unsigned r840 = douts8[14];
    unsigned r841 = douts8[15];
    unsigned r842 = douts8[16];
    unsigned r843 = douts8[17];
    unsigned r844 = douts8[18];
    unsigned r845 = douts8[19];
    unsigned r846 = douts8[20];
    unsigned r847 = douts8[21];
    unsigned r848 = douts8[22];
    unsigned r849 = douts8[23];
    unsigned r850 = douts8[24];
    unsigned r851 = douts8[25];
    unsigned r852 = douts8[26];
    unsigned r853 = douts8[27];
    unsigned r854 = douts8[28];
    unsigned r855 = douts8[29];
    unsigned r856 = douts8[30];
    unsigned r857 = douts8[31];
    unsigned r858 = douts8[32];
    unsigned r859 = douts8[33];
    unsigned r860 = douts8[34];
    unsigned r861 = douts8[35];
    unsigned r862 = douts8[36];
    unsigned r863 = douts8[37];
    unsigned r864 = douts8[38];
    unsigned r865 = douts8[39];
    unsigned r866 = douts8[40];
    unsigned r867 = douts8[41];
    unsigned r868 = douts8[42];
    unsigned r869 = douts8[43];
    unsigned r870 = douts8[44];
    unsigned r871 = douts8[45];
    unsigned r872 = douts8[46];
    unsigned r873 = douts8[47];
    unsigned r874 = douts8[48];
    unsigned r875 = douts8[49];
    unsigned r876 = douts8[50];
    unsigned r877 = douts8[51];
    unsigned r878 = douts8[52];
    unsigned r879 = douts8[53];
    unsigned r880 = douts8[54];
    unsigned r881 = douts8[55];
    unsigned r882 = douts8[56];
    unsigned r883 = douts8[57];
    unsigned r884 = douts8[58];
    unsigned r885 = douts8[59];
    unsigned r886 = douts8[60];
    unsigned r887 = douts8[61];
    unsigned r888 = douts8[62];
    unsigned r889 = douts8[63];
    unsigned r890 = douts8[64];
    unsigned r891 = douts8[65];
    unsigned r892 = douts8[66];
    unsigned r893 = douts8[67];
    unsigned r894 = douts8[68];
    unsigned r895 = douts8[69];
    unsigned r896 = douts8[70];
    unsigned r897 = douts8[71];
    const unsigned dargs9[72] = { r165, r9, r828, r829, r830, r831, r832, r833, r834, r835, r836, r837, r838, r839, r840, r841, r842, r843, r844, r845, r846, r847, r848, r849, r850, r851, r852, r853, r854, r855, r856, r857, r858, r859, r860, r861, r862, r863, r864, r865, r866, r867, r868, r869, r870, r871, r872, r873, r874, r875, r876, r877, r878, r879, r880, r881, r882, r883, r884, r885, r886, r887, r888, r889, r890, r891, r892, r893, r894, r895, r896, r897 };
    unsigned douts9[72];
    sub_words[656u * row_count + row] = r9;
    sub_words[657u * row_count + row] = r828;
    sub_words[658u * row_count + row] = r829;
    sub_words[659u * row_count + row] = r830;
    sub_words[660u * row_count + row] = r831;
    sub_words[661u * row_count + row] = r832;
    sub_words[662u * row_count + row] = r833;
    sub_words[663u * row_count + row] = r834;
    sub_words[664u * row_count + row] = r835;
    sub_words[665u * row_count + row] = r836;
    sub_words[666u * row_count + row] = r837;
    sub_words[667u * row_count + row] = r838;
    sub_words[668u * row_count + row] = r839;
    sub_words[669u * row_count + row] = r840;
    sub_words[670u * row_count + row] = r841;
    sub_words[671u * row_count + row] = r842;
    sub_words[672u * row_count + row] = r843;
    sub_words[673u * row_count + row] = r844;
    sub_words[674u * row_count + row] = r845;
    sub_words[675u * row_count + row] = r846;
    sub_words[676u * row_count + row] = r847;
    sub_words[677u * row_count + row] = r848;
    sub_words[678u * row_count + row] = r849;
    sub_words[679u * row_count + row] = r850;
    sub_words[680u * row_count + row] = r851;
    sub_words[681u * row_count + row] = r852;
    sub_words[682u * row_count + row] = r853;
    sub_words[683u * row_count + row] = r854;
    sub_words[684u * row_count + row] = r855;
    sub_words[685u * row_count + row] = r856;
    sub_words[686u * row_count + row] = r857;
    sub_words[687u * row_count + row] = r858;
    sub_words[688u * row_count + row] = r859;
    sub_words[689u * row_count + row] = r860;
    sub_words[690u * row_count + row] = r861;
    sub_words[691u * row_count + row] = r862;
    sub_words[692u * row_count + row] = r863;
    sub_words[693u * row_count + row] = r864;
    sub_words[694u * row_count + row] = r865;
    sub_words[695u * row_count + row] = r866;
    sub_words[696u * row_count + row] = r867;
    sub_words[697u * row_count + row] = r868;
    sub_words[698u * row_count + row] = r869;
    sub_words[699u * row_count + row] = r870;
    sub_words[700u * row_count + row] = r871;
    sub_words[701u * row_count + row] = r872;
    sub_words[702u * row_count + row] = r873;
    sub_words[703u * row_count + row] = r874;
    sub_words[704u * row_count + row] = r875;
    sub_words[705u * row_count + row] = r876;
    sub_words[706u * row_count + row] = r877;
    sub_words[707u * row_count + row] = r878;
    sub_words[708u * row_count + row] = r879;
    sub_words[709u * row_count + row] = r880;
    sub_words[710u * row_count + row] = r881;
    sub_words[711u * row_count + row] = r882;
    sub_words[712u * row_count + row] = r883;
    sub_words[713u * row_count + row] = r884;
    sub_words[714u * row_count + row] = r885;
    sub_words[715u * row_count + row] = r886;
    sub_words[716u * row_count + row] = r887;
    sub_words[717u * row_count + row] = r888;
    sub_words[718u * row_count + row] = r889;
    sub_words[719u * row_count + row] = r890;
    sub_words[720u * row_count + row] = r891;
    sub_words[721u * row_count + row] = r892;
    sub_words[722u * row_count + row] = r893;
    sub_words[723u * row_count + row] = r894;
    sub_words[724u * row_count + row] = r895;
    sub_words[725u * row_count + row] = r896;
    sub_words[726u * row_count + row] = r897;
    stwo_wit_deduce_partial_ec_mul_w18(dargs9, douts9);
    unsigned r898 = douts9[0];
    unsigned r899 = douts9[1];
    unsigned r900 = douts9[2];
    unsigned r901 = douts9[3];
    unsigned r902 = douts9[4];
    unsigned r903 = douts9[5];
    unsigned r904 = douts9[6];
    unsigned r905 = douts9[7];
    unsigned r906 = douts9[8];
    unsigned r907 = douts9[9];
    unsigned r908 = douts9[10];
    unsigned r909 = douts9[11];
    unsigned r910 = douts9[12];
    unsigned r911 = douts9[13];
    unsigned r912 = douts9[14];
    unsigned r913 = douts9[15];
    unsigned r914 = douts9[16];
    unsigned r915 = douts9[17];
    unsigned r916 = douts9[18];
    unsigned r917 = douts9[19];
    unsigned r918 = douts9[20];
    unsigned r919 = douts9[21];
    unsigned r920 = douts9[22];
    unsigned r921 = douts9[23];
    unsigned r922 = douts9[24];
    unsigned r923 = douts9[25];
    unsigned r924 = douts9[26];
    unsigned r925 = douts9[27];
    unsigned r926 = douts9[28];
    unsigned r927 = douts9[29];
    unsigned r928 = douts9[30];
    unsigned r929 = douts9[31];
    unsigned r930 = douts9[32];
    unsigned r931 = douts9[33];
    unsigned r932 = douts9[34];
    unsigned r933 = douts9[35];
    unsigned r934 = douts9[36];
    unsigned r935 = douts9[37];
    unsigned r936 = douts9[38];
    unsigned r937 = douts9[39];
    unsigned r938 = douts9[40];
    unsigned r939 = douts9[41];
    unsigned r940 = douts9[42];
    unsigned r941 = douts9[43];
    unsigned r942 = douts9[44];
    unsigned r943 = douts9[45];
    unsigned r944 = douts9[46];
    unsigned r945 = douts9[47];
    unsigned r946 = douts9[48];
    unsigned r947 = douts9[49];
    unsigned r948 = douts9[50];
    unsigned r949 = douts9[51];
    unsigned r950 = douts9[52];
    unsigned r951 = douts9[53];
    unsigned r952 = douts9[54];
    unsigned r953 = douts9[55];
    unsigned r954 = douts9[56];
    unsigned r955 = douts9[57];
    unsigned r956 = douts9[58];
    unsigned r957 = douts9[59];
    unsigned r958 = douts9[60];
    unsigned r959 = douts9[61];
    unsigned r960 = douts9[62];
    unsigned r961 = douts9[63];
    unsigned r962 = douts9[64];
    unsigned r963 = douts9[65];
    unsigned r964 = douts9[66];
    unsigned r965 = douts9[67];
    unsigned r966 = douts9[68];
    unsigned r967 = douts9[69];
    unsigned r968 = douts9[70];
    unsigned r969 = douts9[71];
    const unsigned dargs10[72] = { r165, r10, r900, r901, r902, r903, r904, r905, r906, r907, r908, r909, r910, r911, r912, r913, r914, r915, r916, r917, r918, r919, r920, r921, r922, r923, r924, r925, r926, r927, r928, r929, r930, r931, r932, r933, r934, r935, r936, r937, r938, r939, r940, r941, r942, r943, r944, r945, r946, r947, r948, r949, r950, r951, r952, r953, r954, r955, r956, r957, r958, r959, r960, r961, r962, r963, r964, r965, r966, r967, r968, r969 };
    unsigned douts10[72];
    sub_words[728u * row_count + row] = r10;
    sub_words[729u * row_count + row] = r900;
    sub_words[730u * row_count + row] = r901;
    sub_words[731u * row_count + row] = r902;
    sub_words[732u * row_count + row] = r903;
    sub_words[733u * row_count + row] = r904;
    sub_words[734u * row_count + row] = r905;
    sub_words[735u * row_count + row] = r906;
    sub_words[736u * row_count + row] = r907;
    sub_words[737u * row_count + row] = r908;
    sub_words[738u * row_count + row] = r909;
    sub_words[739u * row_count + row] = r910;
    sub_words[740u * row_count + row] = r911;
    sub_words[741u * row_count + row] = r912;
    sub_words[742u * row_count + row] = r913;
    sub_words[743u * row_count + row] = r914;
    sub_words[744u * row_count + row] = r915;
    sub_words[745u * row_count + row] = r916;
    sub_words[746u * row_count + row] = r917;
    sub_words[747u * row_count + row] = r918;
    sub_words[748u * row_count + row] = r919;
    sub_words[749u * row_count + row] = r920;
    sub_words[750u * row_count + row] = r921;
    sub_words[751u * row_count + row] = r922;
    sub_words[752u * row_count + row] = r923;
    sub_words[753u * row_count + row] = r924;
    sub_words[754u * row_count + row] = r925;
    sub_words[755u * row_count + row] = r926;
    sub_words[756u * row_count + row] = r927;
    sub_words[757u * row_count + row] = r928;
    sub_words[758u * row_count + row] = r929;
    sub_words[759u * row_count + row] = r930;
    sub_words[760u * row_count + row] = r931;
    sub_words[761u * row_count + row] = r932;
    sub_words[762u * row_count + row] = r933;
    sub_words[763u * row_count + row] = r934;
    sub_words[764u * row_count + row] = r935;
    sub_words[765u * row_count + row] = r936;
    sub_words[766u * row_count + row] = r937;
    sub_words[767u * row_count + row] = r938;
    sub_words[768u * row_count + row] = r939;
    sub_words[769u * row_count + row] = r940;
    sub_words[770u * row_count + row] = r941;
    sub_words[771u * row_count + row] = r942;
    sub_words[772u * row_count + row] = r943;
    sub_words[773u * row_count + row] = r944;
    sub_words[774u * row_count + row] = r945;
    sub_words[775u * row_count + row] = r946;
    sub_words[776u * row_count + row] = r947;
    sub_words[777u * row_count + row] = r948;
    sub_words[778u * row_count + row] = r949;
    sub_words[779u * row_count + row] = r950;
    sub_words[780u * row_count + row] = r951;
    sub_words[781u * row_count + row] = r952;
    sub_words[782u * row_count + row] = r953;
    sub_words[783u * row_count + row] = r954;
    sub_words[784u * row_count + row] = r955;
    sub_words[785u * row_count + row] = r956;
    sub_words[786u * row_count + row] = r957;
    sub_words[787u * row_count + row] = r958;
    sub_words[788u * row_count + row] = r959;
    sub_words[789u * row_count + row] = r960;
    sub_words[790u * row_count + row] = r961;
    sub_words[791u * row_count + row] = r962;
    sub_words[792u * row_count + row] = r963;
    sub_words[793u * row_count + row] = r964;
    sub_words[794u * row_count + row] = r965;
    sub_words[795u * row_count + row] = r966;
    sub_words[796u * row_count + row] = r967;
    sub_words[797u * row_count + row] = r968;
    sub_words[798u * row_count + row] = r969;
    stwo_wit_deduce_partial_ec_mul_w18(dargs10, douts10);
    unsigned r970 = douts10[0];
    unsigned r971 = douts10[1];
    unsigned r972 = douts10[2];
    unsigned r973 = douts10[3];
    unsigned r974 = douts10[4];
    unsigned r975 = douts10[5];
    unsigned r976 = douts10[6];
    unsigned r977 = douts10[7];
    unsigned r978 = douts10[8];
    unsigned r979 = douts10[9];
    unsigned r980 = douts10[10];
    unsigned r981 = douts10[11];
    unsigned r982 = douts10[12];
    unsigned r983 = douts10[13];
    unsigned r984 = douts10[14];
    unsigned r985 = douts10[15];
    unsigned r986 = douts10[16];
    unsigned r987 = douts10[17];
    unsigned r988 = douts10[18];
    unsigned r989 = douts10[19];
    unsigned r990 = douts10[20];
    unsigned r991 = douts10[21];
    unsigned r992 = douts10[22];
    unsigned r993 = douts10[23];
    unsigned r994 = douts10[24];
    unsigned r995 = douts10[25];
    unsigned r996 = douts10[26];
    unsigned r997 = douts10[27];
    unsigned r998 = douts10[28];
    unsigned r999 = douts10[29];
    unsigned r1000 = douts10[30];
    unsigned r1001 = douts10[31];
    unsigned r1002 = douts10[32];
    unsigned r1003 = douts10[33];
    unsigned r1004 = douts10[34];
    unsigned r1005 = douts10[35];
    unsigned r1006 = douts10[36];
    unsigned r1007 = douts10[37];
    unsigned r1008 = douts10[38];
    unsigned r1009 = douts10[39];
    unsigned r1010 = douts10[40];
    unsigned r1011 = douts10[41];
    unsigned r1012 = douts10[42];
    unsigned r1013 = douts10[43];
    unsigned r1014 = douts10[44];
    unsigned r1015 = douts10[45];
    unsigned r1016 = douts10[46];
    unsigned r1017 = douts10[47];
    unsigned r1018 = douts10[48];
    unsigned r1019 = douts10[49];
    unsigned r1020 = douts10[50];
    unsigned r1021 = douts10[51];
    unsigned r1022 = douts10[52];
    unsigned r1023 = douts10[53];
    unsigned r1024 = douts10[54];
    unsigned r1025 = douts10[55];
    unsigned r1026 = douts10[56];
    unsigned r1027 = douts10[57];
    unsigned r1028 = douts10[58];
    unsigned r1029 = douts10[59];
    unsigned r1030 = douts10[60];
    unsigned r1031 = douts10[61];
    unsigned r1032 = douts10[62];
    unsigned r1033 = douts10[63];
    unsigned r1034 = douts10[64];
    unsigned r1035 = douts10[65];
    unsigned r1036 = douts10[66];
    unsigned r1037 = douts10[67];
    unsigned r1038 = douts10[68];
    unsigned r1039 = douts10[69];
    unsigned r1040 = douts10[70];
    unsigned r1041 = douts10[71];
    const unsigned dargs11[72] = { r165, r11, r972, r973, r974, r975, r976, r977, r978, r979, r980, r981, r982, r983, r984, r985, r986, r987, r988, r989, r990, r991, r992, r993, r994, r995, r996, r997, r998, r999, r1000, r1001, r1002, r1003, r1004, r1005, r1006, r1007, r1008, r1009, r1010, r1011, r1012, r1013, r1014, r1015, r1016, r1017, r1018, r1019, r1020, r1021, r1022, r1023, r1024, r1025, r1026, r1027, r1028, r1029, r1030, r1031, r1032, r1033, r1034, r1035, r1036, r1037, r1038, r1039, r1040, r1041 };
    unsigned douts11[72];
    sub_words[800u * row_count + row] = r11;
    sub_words[801u * row_count + row] = r972;
    sub_words[802u * row_count + row] = r973;
    sub_words[803u * row_count + row] = r974;
    sub_words[804u * row_count + row] = r975;
    sub_words[805u * row_count + row] = r976;
    sub_words[806u * row_count + row] = r977;
    sub_words[807u * row_count + row] = r978;
    sub_words[808u * row_count + row] = r979;
    sub_words[809u * row_count + row] = r980;
    sub_words[810u * row_count + row] = r981;
    sub_words[811u * row_count + row] = r982;
    sub_words[812u * row_count + row] = r983;
    sub_words[813u * row_count + row] = r984;
    sub_words[814u * row_count + row] = r985;
    sub_words[815u * row_count + row] = r986;
    sub_words[816u * row_count + row] = r987;
    sub_words[817u * row_count + row] = r988;
    sub_words[818u * row_count + row] = r989;
    sub_words[819u * row_count + row] = r990;
    sub_words[820u * row_count + row] = r991;
    sub_words[821u * row_count + row] = r992;
    sub_words[822u * row_count + row] = r993;
    sub_words[823u * row_count + row] = r994;
    sub_words[824u * row_count + row] = r995;
    sub_words[825u * row_count + row] = r996;
    sub_words[826u * row_count + row] = r997;
    sub_words[827u * row_count + row] = r998;
    sub_words[828u * row_count + row] = r999;
    sub_words[829u * row_count + row] = r1000;
    sub_words[830u * row_count + row] = r1001;
    sub_words[831u * row_count + row] = r1002;
    sub_words[832u * row_count + row] = r1003;
    sub_words[833u * row_count + row] = r1004;
    sub_words[834u * row_count + row] = r1005;
    sub_words[835u * row_count + row] = r1006;
    sub_words[836u * row_count + row] = r1007;
    sub_words[837u * row_count + row] = r1008;
    sub_words[838u * row_count + row] = r1009;
    sub_words[839u * row_count + row] = r1010;
    sub_words[840u * row_count + row] = r1011;
    sub_words[841u * row_count + row] = r1012;
    sub_words[842u * row_count + row] = r1013;
    sub_words[843u * row_count + row] = r1014;
    sub_words[844u * row_count + row] = r1015;
    sub_words[845u * row_count + row] = r1016;
    sub_words[846u * row_count + row] = r1017;
    sub_words[847u * row_count + row] = r1018;
    sub_words[848u * row_count + row] = r1019;
    sub_words[849u * row_count + row] = r1020;
    sub_words[850u * row_count + row] = r1021;
    sub_words[851u * row_count + row] = r1022;
    sub_words[852u * row_count + row] = r1023;
    sub_words[853u * row_count + row] = r1024;
    sub_words[854u * row_count + row] = r1025;
    sub_words[855u * row_count + row] = r1026;
    sub_words[856u * row_count + row] = r1027;
    sub_words[857u * row_count + row] = r1028;
    sub_words[858u * row_count + row] = r1029;
    sub_words[859u * row_count + row] = r1030;
    sub_words[860u * row_count + row] = r1031;
    sub_words[861u * row_count + row] = r1032;
    sub_words[862u * row_count + row] = r1033;
    sub_words[863u * row_count + row] = r1034;
    sub_words[864u * row_count + row] = r1035;
    sub_words[865u * row_count + row] = r1036;
    sub_words[866u * row_count + row] = r1037;
    sub_words[867u * row_count + row] = r1038;
    sub_words[868u * row_count + row] = r1039;
    sub_words[869u * row_count + row] = r1040;
    sub_words[870u * row_count + row] = r1041;
    stwo_wit_deduce_partial_ec_mul_w18(dargs11, douts11);
    unsigned r1042 = douts11[0];
    unsigned r1043 = douts11[1];
    unsigned r1044 = douts11[2];
    unsigned r1045 = douts11[3];
    unsigned r1046 = douts11[4];
    unsigned r1047 = douts11[5];
    unsigned r1048 = douts11[6];
    unsigned r1049 = douts11[7];
    unsigned r1050 = douts11[8];
    unsigned r1051 = douts11[9];
    unsigned r1052 = douts11[10];
    unsigned r1053 = douts11[11];
    unsigned r1054 = douts11[12];
    unsigned r1055 = douts11[13];
    unsigned r1056 = douts11[14];
    unsigned r1057 = douts11[15];
    unsigned r1058 = douts11[16];
    unsigned r1059 = douts11[17];
    unsigned r1060 = douts11[18];
    unsigned r1061 = douts11[19];
    unsigned r1062 = douts11[20];
    unsigned r1063 = douts11[21];
    unsigned r1064 = douts11[22];
    unsigned r1065 = douts11[23];
    unsigned r1066 = douts11[24];
    unsigned r1067 = douts11[25];
    unsigned r1068 = douts11[26];
    unsigned r1069 = douts11[27];
    unsigned r1070 = douts11[28];
    unsigned r1071 = douts11[29];
    unsigned r1072 = douts11[30];
    unsigned r1073 = douts11[31];
    unsigned r1074 = douts11[32];
    unsigned r1075 = douts11[33];
    unsigned r1076 = douts11[34];
    unsigned r1077 = douts11[35];
    unsigned r1078 = douts11[36];
    unsigned r1079 = douts11[37];
    unsigned r1080 = douts11[38];
    unsigned r1081 = douts11[39];
    unsigned r1082 = douts11[40];
    unsigned r1083 = douts11[41];
    unsigned r1084 = douts11[42];
    unsigned r1085 = douts11[43];
    unsigned r1086 = douts11[44];
    unsigned r1087 = douts11[45];
    unsigned r1088 = douts11[46];
    unsigned r1089 = douts11[47];
    unsigned r1090 = douts11[48];
    unsigned r1091 = douts11[49];
    unsigned r1092 = douts11[50];
    unsigned r1093 = douts11[51];
    unsigned r1094 = douts11[52];
    unsigned r1095 = douts11[53];
    unsigned r1096 = douts11[54];
    unsigned r1097 = douts11[55];
    unsigned r1098 = douts11[56];
    unsigned r1099 = douts11[57];
    unsigned r1100 = douts11[58];
    unsigned r1101 = douts11[59];
    unsigned r1102 = douts11[60];
    unsigned r1103 = douts11[61];
    unsigned r1104 = douts11[62];
    unsigned r1105 = douts11[63];
    unsigned r1106 = douts11[64];
    unsigned r1107 = douts11[65];
    unsigned r1108 = douts11[66];
    unsigned r1109 = douts11[67];
    unsigned r1110 = douts11[68];
    unsigned r1111 = douts11[69];
    unsigned r1112 = douts11[70];
    unsigned r1113 = douts11[71];
    const unsigned dargs12[72] = { r165, r12, r1044, r1045, r1046, r1047, r1048, r1049, r1050, r1051, r1052, r1053, r1054, r1055, r1056, r1057, r1058, r1059, r1060, r1061, r1062, r1063, r1064, r1065, r1066, r1067, r1068, r1069, r1070, r1071, r1072, r1073, r1074, r1075, r1076, r1077, r1078, r1079, r1080, r1081, r1082, r1083, r1084, r1085, r1086, r1087, r1088, r1089, r1090, r1091, r1092, r1093, r1094, r1095, r1096, r1097, r1098, r1099, r1100, r1101, r1102, r1103, r1104, r1105, r1106, r1107, r1108, r1109, r1110, r1111, r1112, r1113 };
    unsigned douts12[72];
    sub_words[872u * row_count + row] = r12;
    sub_words[873u * row_count + row] = r1044;
    sub_words[874u * row_count + row] = r1045;
    sub_words[875u * row_count + row] = r1046;
    sub_words[876u * row_count + row] = r1047;
    sub_words[877u * row_count + row] = r1048;
    sub_words[878u * row_count + row] = r1049;
    sub_words[879u * row_count + row] = r1050;
    sub_words[880u * row_count + row] = r1051;
    sub_words[881u * row_count + row] = r1052;
    sub_words[882u * row_count + row] = r1053;
    sub_words[883u * row_count + row] = r1054;
    sub_words[884u * row_count + row] = r1055;
    sub_words[885u * row_count + row] = r1056;
    sub_words[886u * row_count + row] = r1057;
    sub_words[887u * row_count + row] = r1058;
    sub_words[888u * row_count + row] = r1059;
    sub_words[889u * row_count + row] = r1060;
    sub_words[890u * row_count + row] = r1061;
    sub_words[891u * row_count + row] = r1062;
    sub_words[892u * row_count + row] = r1063;
    sub_words[893u * row_count + row] = r1064;
    sub_words[894u * row_count + row] = r1065;
    sub_words[895u * row_count + row] = r1066;
    sub_words[896u * row_count + row] = r1067;
    sub_words[897u * row_count + row] = r1068;
    sub_words[898u * row_count + row] = r1069;
    sub_words[899u * row_count + row] = r1070;
    sub_words[900u * row_count + row] = r1071;
    sub_words[901u * row_count + row] = r1072;
    sub_words[902u * row_count + row] = r1073;
    sub_words[903u * row_count + row] = r1074;
    sub_words[904u * row_count + row] = r1075;
    sub_words[905u * row_count + row] = r1076;
    sub_words[906u * row_count + row] = r1077;
    sub_words[907u * row_count + row] = r1078;
    sub_words[908u * row_count + row] = r1079;
    sub_words[909u * row_count + row] = r1080;
    sub_words[910u * row_count + row] = r1081;
    sub_words[911u * row_count + row] = r1082;
    sub_words[912u * row_count + row] = r1083;
    sub_words[913u * row_count + row] = r1084;
    sub_words[914u * row_count + row] = r1085;
    sub_words[915u * row_count + row] = r1086;
    sub_words[916u * row_count + row] = r1087;
    sub_words[917u * row_count + row] = r1088;
    sub_words[918u * row_count + row] = r1089;
    sub_words[919u * row_count + row] = r1090;
    sub_words[920u * row_count + row] = r1091;
    sub_words[921u * row_count + row] = r1092;
    sub_words[922u * row_count + row] = r1093;
    sub_words[923u * row_count + row] = r1094;
    sub_words[924u * row_count + row] = r1095;
    sub_words[925u * row_count + row] = r1096;
    sub_words[926u * row_count + row] = r1097;
    sub_words[927u * row_count + row] = r1098;
    sub_words[928u * row_count + row] = r1099;
    sub_words[929u * row_count + row] = r1100;
    sub_words[930u * row_count + row] = r1101;
    sub_words[931u * row_count + row] = r1102;
    sub_words[932u * row_count + row] = r1103;
    sub_words[933u * row_count + row] = r1104;
    sub_words[934u * row_count + row] = r1105;
    sub_words[935u * row_count + row] = r1106;
    sub_words[936u * row_count + row] = r1107;
    sub_words[937u * row_count + row] = r1108;
    sub_words[938u * row_count + row] = r1109;
    sub_words[939u * row_count + row] = r1110;
    sub_words[940u * row_count + row] = r1111;
    sub_words[941u * row_count + row] = r1112;
    sub_words[942u * row_count + row] = r1113;
    stwo_wit_deduce_partial_ec_mul_w18(dargs12, douts12);
    unsigned r1114 = douts12[0];
    unsigned r1115 = douts12[1];
    unsigned r1116 = douts12[2];
    unsigned r1117 = douts12[3];
    unsigned r1118 = douts12[4];
    unsigned r1119 = douts12[5];
    unsigned r1120 = douts12[6];
    unsigned r1121 = douts12[7];
    unsigned r1122 = douts12[8];
    unsigned r1123 = douts12[9];
    unsigned r1124 = douts12[10];
    unsigned r1125 = douts12[11];
    unsigned r1126 = douts12[12];
    unsigned r1127 = douts12[13];
    unsigned r1128 = douts12[14];
    unsigned r1129 = douts12[15];
    unsigned r1130 = douts12[16];
    unsigned r1131 = douts12[17];
    unsigned r1132 = douts12[18];
    unsigned r1133 = douts12[19];
    unsigned r1134 = douts12[20];
    unsigned r1135 = douts12[21];
    unsigned r1136 = douts12[22];
    unsigned r1137 = douts12[23];
    unsigned r1138 = douts12[24];
    unsigned r1139 = douts12[25];
    unsigned r1140 = douts12[26];
    unsigned r1141 = douts12[27];
    unsigned r1142 = douts12[28];
    unsigned r1143 = douts12[29];
    unsigned r1144 = douts12[30];
    unsigned r1145 = douts12[31];
    unsigned r1146 = douts12[32];
    unsigned r1147 = douts12[33];
    unsigned r1148 = douts12[34];
    unsigned r1149 = douts12[35];
    unsigned r1150 = douts12[36];
    unsigned r1151 = douts12[37];
    unsigned r1152 = douts12[38];
    unsigned r1153 = douts12[39];
    unsigned r1154 = douts12[40];
    unsigned r1155 = douts12[41];
    unsigned r1156 = douts12[42];
    unsigned r1157 = douts12[43];
    unsigned r1158 = douts12[44];
    unsigned r1159 = douts12[45];
    unsigned r1160 = douts12[46];
    unsigned r1161 = douts12[47];
    unsigned r1162 = douts12[48];
    unsigned r1163 = douts12[49];
    unsigned r1164 = douts12[50];
    unsigned r1165 = douts12[51];
    unsigned r1166 = douts12[52];
    unsigned r1167 = douts12[53];
    unsigned r1168 = douts12[54];
    unsigned r1169 = douts12[55];
    unsigned r1170 = douts12[56];
    unsigned r1171 = douts12[57];
    unsigned r1172 = douts12[58];
    unsigned r1173 = douts12[59];
    unsigned r1174 = douts12[60];
    unsigned r1175 = douts12[61];
    unsigned r1176 = douts12[62];
    unsigned r1177 = douts12[63];
    unsigned r1178 = douts12[64];
    unsigned r1179 = douts12[65];
    unsigned r1180 = douts12[66];
    unsigned r1181 = douts12[67];
    unsigned r1182 = douts12[68];
    unsigned r1183 = douts12[69];
    unsigned r1184 = douts12[70];
    unsigned r1185 = douts12[71];
    const unsigned dargs13[72] = { r165, r13, r1116, r1117, r1118, r1119, r1120, r1121, r1122, r1123, r1124, r1125, r1126, r1127, r1128, r1129, r1130, r1131, r1132, r1133, r1134, r1135, r1136, r1137, r1138, r1139, r1140, r1141, r1142, r1143, r1144, r1145, r1146, r1147, r1148, r1149, r1150, r1151, r1152, r1153, r1154, r1155, r1156, r1157, r1158, r1159, r1160, r1161, r1162, r1163, r1164, r1165, r1166, r1167, r1168, r1169, r1170, r1171, r1172, r1173, r1174, r1175, r1176, r1177, r1178, r1179, r1180, r1181, r1182, r1183, r1184, r1185 };
    unsigned douts13[72];
    sub_words[944u * row_count + row] = r13;
    sub_words[945u * row_count + row] = r1116;
    sub_words[946u * row_count + row] = r1117;
    sub_words[947u * row_count + row] = r1118;
    sub_words[948u * row_count + row] = r1119;
    sub_words[949u * row_count + row] = r1120;
    sub_words[950u * row_count + row] = r1121;
    sub_words[951u * row_count + row] = r1122;
    sub_words[952u * row_count + row] = r1123;
    sub_words[953u * row_count + row] = r1124;
    sub_words[954u * row_count + row] = r1125;
    sub_words[955u * row_count + row] = r1126;
    sub_words[956u * row_count + row] = r1127;
    sub_words[957u * row_count + row] = r1128;
    sub_words[958u * row_count + row] = r1129;
    sub_words[959u * row_count + row] = r1130;
    sub_words[960u * row_count + row] = r1131;
    sub_words[961u * row_count + row] = r1132;
    sub_words[962u * row_count + row] = r1133;
    sub_words[963u * row_count + row] = r1134;
    sub_words[964u * row_count + row] = r1135;
    sub_words[965u * row_count + row] = r1136;
    sub_words[966u * row_count + row] = r1137;
    sub_words[967u * row_count + row] = r1138;
    sub_words[968u * row_count + row] = r1139;
    sub_words[969u * row_count + row] = r1140;
    sub_words[970u * row_count + row] = r1141;
    sub_words[971u * row_count + row] = r1142;
    sub_words[972u * row_count + row] = r1143;
    sub_words[973u * row_count + row] = r1144;
    sub_words[974u * row_count + row] = r1145;
    sub_words[975u * row_count + row] = r1146;
    sub_words[976u * row_count + row] = r1147;
    sub_words[977u * row_count + row] = r1148;
    sub_words[978u * row_count + row] = r1149;
    sub_words[979u * row_count + row] = r1150;
    sub_words[980u * row_count + row] = r1151;
    sub_words[981u * row_count + row] = r1152;
    sub_words[982u * row_count + row] = r1153;
    sub_words[983u * row_count + row] = r1154;
    sub_words[984u * row_count + row] = r1155;
    sub_words[985u * row_count + row] = r1156;
    sub_words[986u * row_count + row] = r1157;
    sub_words[987u * row_count + row] = r1158;
    sub_words[988u * row_count + row] = r1159;
    sub_words[989u * row_count + row] = r1160;
    sub_words[990u * row_count + row] = r1161;
    sub_words[991u * row_count + row] = r1162;
    sub_words[992u * row_count + row] = r1163;
    sub_words[993u * row_count + row] = r1164;
    sub_words[994u * row_count + row] = r1165;
    sub_words[995u * row_count + row] = r1166;
    sub_words[996u * row_count + row] = r1167;
    sub_words[997u * row_count + row] = r1168;
    sub_words[998u * row_count + row] = r1169;
    sub_words[999u * row_count + row] = r1170;
    sub_words[1000u * row_count + row] = r1171;
    sub_words[1001u * row_count + row] = r1172;
    sub_words[1002u * row_count + row] = r1173;
    sub_words[1003u * row_count + row] = r1174;
    sub_words[1004u * row_count + row] = r1175;
    sub_words[1005u * row_count + row] = r1176;
    sub_words[1006u * row_count + row] = r1177;
    sub_words[1007u * row_count + row] = r1178;
    sub_words[1008u * row_count + row] = r1179;
    sub_words[1009u * row_count + row] = r1180;
    sub_words[1010u * row_count + row] = r1181;
    sub_words[1011u * row_count + row] = r1182;
    sub_words[1012u * row_count + row] = r1183;
    sub_words[1013u * row_count + row] = r1184;
    sub_words[1014u * row_count + row] = r1185;
    stwo_wit_deduce_partial_ec_mul_w18(dargs13, douts13);
    unsigned r1186 = douts13[0];
    unsigned r1187 = douts13[1];
    unsigned r1188 = douts13[2];
    out_cols[65u][row] = r1188;
    lookup_words[144u * row_count + row] = r1188;
    unsigned r1189 = douts13[3];
    out_cols[66u][row] = r1189;
    lookup_words[145u * row_count + row] = r1189;
    unsigned r1190 = douts13[4];
    out_cols[67u][row] = r1190;
    lookup_words[146u * row_count + row] = r1190;
    unsigned r1191 = douts13[5];
    out_cols[68u][row] = r1191;
    lookup_words[147u * row_count + row] = r1191;
    unsigned r1192 = douts13[6];
    out_cols[69u][row] = r1192;
    lookup_words[148u * row_count + row] = r1192;
    unsigned r1193 = douts13[7];
    out_cols[70u][row] = r1193;
    lookup_words[149u * row_count + row] = r1193;
    unsigned r1194 = douts13[8];
    out_cols[71u][row] = r1194;
    lookup_words[150u * row_count + row] = r1194;
    unsigned r1195 = douts13[9];
    out_cols[72u][row] = r1195;
    lookup_words[151u * row_count + row] = r1195;
    unsigned r1196 = douts13[10];
    out_cols[73u][row] = r1196;
    lookup_words[152u * row_count + row] = r1196;
    unsigned r1197 = douts13[11];
    out_cols[74u][row] = r1197;
    lookup_words[153u * row_count + row] = r1197;
    unsigned r1198 = douts13[12];
    out_cols[75u][row] = r1198;
    lookup_words[154u * row_count + row] = r1198;
    unsigned r1199 = douts13[13];
    out_cols[76u][row] = r1199;
    lookup_words[155u * row_count + row] = r1199;
    unsigned r1200 = douts13[14];
    out_cols[77u][row] = r1200;
    lookup_words[156u * row_count + row] = r1200;
    unsigned r1201 = douts13[15];
    out_cols[78u][row] = r1201;
    lookup_words[157u * row_count + row] = r1201;
    unsigned r1202 = douts13[16];
    unsigned r1203 = douts13[17];
    unsigned r1204 = douts13[18];
    unsigned r1205 = douts13[19];
    unsigned r1206 = douts13[20];
    unsigned r1207 = douts13[21];
    unsigned r1208 = douts13[22];
    unsigned r1209 = douts13[23];
    unsigned r1210 = douts13[24];
    unsigned r1211 = douts13[25];
    unsigned r1212 = douts13[26];
    unsigned r1213 = douts13[27];
    unsigned r1214 = douts13[28];
    unsigned r1215 = douts13[29];
    unsigned r1216 = douts13[30];
    unsigned r1217 = douts13[31];
    unsigned r1218 = douts13[32];
    unsigned r1219 = douts13[33];
    unsigned r1220 = douts13[34];
    unsigned r1221 = douts13[35];
    unsigned r1222 = douts13[36];
    unsigned r1223 = douts13[37];
    unsigned r1224 = douts13[38];
    unsigned r1225 = douts13[39];
    unsigned r1226 = douts13[40];
    unsigned r1227 = douts13[41];
    unsigned r1228 = douts13[42];
    unsigned r1229 = douts13[43];
    unsigned r1230 = douts13[44];
    unsigned r1231 = douts13[45];
    unsigned r1232 = douts13[46];
    unsigned r1233 = douts13[47];
    unsigned r1234 = douts13[48];
    unsigned r1235 = douts13[49];
    unsigned r1236 = douts13[50];
    unsigned r1237 = douts13[51];
    unsigned r1238 = douts13[52];
    unsigned r1239 = douts13[53];
    unsigned r1240 = douts13[54];
    unsigned r1241 = douts13[55];
    unsigned r1242 = douts13[56];
    unsigned r1243 = douts13[57];
    unsigned r1244 = douts13[58];
    unsigned r1245 = douts13[59];
    unsigned r1246 = douts13[60];
    unsigned r1247 = douts13[61];
    unsigned r1248 = douts13[62];
    unsigned r1249 = douts13[63];
    unsigned r1250 = douts13[64];
    unsigned r1251 = douts13[65];
    unsigned r1252 = douts13[66];
    unsigned r1253 = douts13[67];
    unsigned r1254 = douts13[68];
    unsigned r1255 = douts13[69];
    unsigned r1256 = douts13[70];
    unsigned r1257 = douts13[71];
    unsigned r1258 = stwo_m31_add(r165, r1);
    lookup_words[69u * row_count + row] = r165;
    sub_words[7u * row_count + row] = r165;
    sub_words[79u * row_count + row] = r165;
    sub_words[80u * row_count + row] = r1;
    sub_words[151u * row_count + row] = r165;
    sub_words[223u * row_count + row] = r165;
    sub_words[295u * row_count + row] = r165;
    sub_words[367u * row_count + row] = r165;
    sub_words[439u * row_count + row] = r165;
    sub_words[511u * row_count + row] = r165;
    sub_words[583u * row_count + row] = r165;
    sub_words[655u * row_count + row] = r165;
    sub_words[727u * row_count + row] = r165;
    sub_words[799u * row_count + row] = r165;
    sub_words[871u * row_count + row] = r165;
    sub_words[943u * row_count + row] = r165;
    lookup_words[142u * row_count + row] = r165;
    lookup_words[394u * row_count + row] = r1;
    unsigned r1259 = stwo_m31_mul(r120, r82);
    unsigned r1260 = stwo_m31_add(r119, r1259);
    lookup_words[217u * row_count + row] = r1260;
    unsigned r1261 = stwo_m31_mul(r122, r82);
    unsigned r1262 = stwo_m31_add(r121, r1261);
    lookup_words[218u * row_count + row] = r1262;
    unsigned r1263 = stwo_m31_mul(r124, r82);
    unsigned r1264 = stwo_m31_add(r123, r1263);
    lookup_words[219u * row_count + row] = r1264;
    unsigned r1265 = stwo_m31_mul(r126, r82);
    unsigned r1266 = stwo_m31_add(r125, r1265);
    lookup_words[220u * row_count + row] = r1266;
    unsigned r1267 = stwo_m31_mul(r128, r82);
    unsigned r1268 = stwo_m31_add(r127, r1267);
    lookup_words[221u * row_count + row] = r1268;
    unsigned r1269 = stwo_m31_mul(r130, r82);
    unsigned r1270 = stwo_m31_add(r129, r1269);
    lookup_words[222u * row_count + row] = r1270;
    unsigned r1271 = stwo_m31_mul(r132, r82);
    unsigned r1272 = stwo_m31_add(r131, r1271);
    lookup_words[223u * row_count + row] = r1272;
    unsigned r1273 = stwo_m31_mul(r134, r82);
    unsigned r1274 = stwo_m31_add(r133, r1273);
    lookup_words[224u * row_count + row] = r1274;
    unsigned r1275 = stwo_m31_mul(r136, r82);
    unsigned r1276 = stwo_m31_add(r135, r1275);
    lookup_words[225u * row_count + row] = r1276;
    unsigned r1277 = stwo_m31_mul(r138, r82);
    unsigned r1278 = stwo_m31_add(r137, r1277);
    lookup_words[226u * row_count + row] = r1278;
    unsigned r1279 = stwo_m31_mul(r140, r82);
    unsigned r1280 = stwo_m31_add(r139, r1279);
    lookup_words[227u * row_count + row] = r1280;
    unsigned r1281 = stwo_m31_mul(r142, r82);
    unsigned r1282 = stwo_m31_add(r141, r1281);
    lookup_words[228u * row_count + row] = r1282;
    unsigned r1283 = stwo_m31_mul(r144, r82);
    unsigned r1284 = stwo_m31_add(r143, r1283);
    lookup_words[229u * row_count + row] = r1284;
    unsigned r1285 = stwo_m31_mul(r146, r82);
    unsigned r1286 = stwo_m31_add(r145, r1285);
    lookup_words[230u * row_count + row] = r1286;
    unsigned r1287 = stwo_m31_mul(r120, r82);
    unsigned r1288 = stwo_m31_add(r119, r1287);
    sub_words[1017u * row_count + row] = r1288;
    unsigned r1289 = stwo_m31_mul(r122, r82);
    unsigned r1290 = stwo_m31_add(r121, r1289);
    sub_words[1018u * row_count + row] = r1290;
    unsigned r1291 = stwo_m31_mul(r124, r82);
    unsigned r1292 = stwo_m31_add(r123, r1291);
    sub_words[1019u * row_count + row] = r1292;
    unsigned r1293 = stwo_m31_mul(r126, r82);
    unsigned r1294 = stwo_m31_add(r125, r1293);
    sub_words[1020u * row_count + row] = r1294;
    unsigned r1295 = stwo_m31_mul(r128, r82);
    unsigned r1296 = stwo_m31_add(r127, r1295);
    sub_words[1021u * row_count + row] = r1296;
    unsigned r1297 = stwo_m31_mul(r130, r82);
    unsigned r1298 = stwo_m31_add(r129, r1297);
    sub_words[1022u * row_count + row] = r1298;
    unsigned r1299 = stwo_m31_mul(r132, r82);
    unsigned r1300 = stwo_m31_add(r131, r1299);
    sub_words[1023u * row_count + row] = r1300;
    unsigned r1301 = stwo_m31_mul(r134, r82);
    unsigned r1302 = stwo_m31_add(r133, r1301);
    sub_words[1024u * row_count + row] = r1302;
    unsigned r1303 = stwo_m31_mul(r136, r82);
    unsigned r1304 = stwo_m31_add(r135, r1303);
    sub_words[1025u * row_count + row] = r1304;
    unsigned r1305 = stwo_m31_mul(r138, r82);
    unsigned r1306 = stwo_m31_add(r137, r1305);
    sub_words[1026u * row_count + row] = r1306;
    unsigned r1307 = stwo_m31_mul(r140, r82);
    unsigned r1308 = stwo_m31_add(r139, r1307);
    sub_words[1027u * row_count + row] = r1308;
    unsigned r1309 = stwo_m31_mul(r142, r82);
    unsigned r1310 = stwo_m31_add(r141, r1309);
    sub_words[1028u * row_count + row] = r1310;
    unsigned r1311 = stwo_m31_mul(r144, r82);
    unsigned r1312 = stwo_m31_add(r143, r1311);
    sub_words[1029u * row_count + row] = r1312;
    unsigned r1313 = stwo_m31_mul(r146, r82);
    unsigned r1314 = stwo_m31_add(r145, r1313);
    sub_words[1030u * row_count + row] = r1314;
    unsigned r1315 = stwo_m31_mul(r120, r82);
    out_cols[32u][row] = r120;
    lookup_words[33u * row_count + row] = r120;
    unsigned r1316 = stwo_m31_add(r119, r1315);
    out_cols[31u][row] = r119;
    lookup_words[32u * row_count + row] = r119;
    unsigned r1317 = stwo_m31_mul(r122, r82);
    out_cols[34u][row] = r122;
    lookup_words[35u * row_count + row] = r122;
    unsigned r1318 = stwo_m31_add(r121, r1317);
    out_cols[33u][row] = r121;
    lookup_words[34u * row_count + row] = r121;
    unsigned r1319 = stwo_m31_mul(r124, r82);
    out_cols[36u][row] = r124;
    lookup_words[37u * row_count + row] = r124;
    unsigned r1320 = stwo_m31_add(r123, r1319);
    out_cols[35u][row] = r123;
    lookup_words[36u * row_count + row] = r123;
    unsigned r1321 = stwo_m31_mul(r126, r82);
    out_cols[38u][row] = r126;
    lookup_words[39u * row_count + row] = r126;
    unsigned r1322 = stwo_m31_add(r125, r1321);
    out_cols[37u][row] = r125;
    lookup_words[38u * row_count + row] = r125;
    unsigned r1323 = stwo_m31_mul(r128, r82);
    out_cols[40u][row] = r128;
    lookup_words[41u * row_count + row] = r128;
    unsigned r1324 = stwo_m31_add(r127, r1323);
    out_cols[39u][row] = r127;
    lookup_words[40u * row_count + row] = r127;
    unsigned r1325 = stwo_m31_mul(r130, r82);
    out_cols[42u][row] = r130;
    lookup_words[43u * row_count + row] = r130;
    unsigned r1326 = stwo_m31_add(r129, r1325);
    out_cols[41u][row] = r129;
    lookup_words[42u * row_count + row] = r129;
    unsigned r1327 = stwo_m31_mul(r132, r82);
    out_cols[44u][row] = r132;
    lookup_words[45u * row_count + row] = r132;
    unsigned r1328 = stwo_m31_add(r131, r1327);
    out_cols[43u][row] = r131;
    lookup_words[44u * row_count + row] = r131;
    unsigned r1329 = stwo_m31_mul(r134, r82);
    out_cols[46u][row] = r134;
    lookup_words[47u * row_count + row] = r134;
    unsigned r1330 = stwo_m31_add(r133, r1329);
    out_cols[45u][row] = r133;
    lookup_words[46u * row_count + row] = r133;
    unsigned r1331 = stwo_m31_mul(r136, r82);
    out_cols[48u][row] = r136;
    lookup_words[49u * row_count + row] = r136;
    unsigned r1332 = stwo_m31_add(r135, r1331);
    out_cols[47u][row] = r135;
    lookup_words[48u * row_count + row] = r135;
    unsigned r1333 = stwo_m31_mul(r138, r82);
    out_cols[50u][row] = r138;
    lookup_words[51u * row_count + row] = r138;
    unsigned r1334 = stwo_m31_add(r137, r1333);
    out_cols[49u][row] = r137;
    lookup_words[50u * row_count + row] = r137;
    unsigned r1335 = stwo_m31_mul(r140, r82);
    out_cols[52u][row] = r140;
    lookup_words[53u * row_count + row] = r140;
    unsigned r1336 = stwo_m31_add(r139, r1335);
    out_cols[51u][row] = r139;
    lookup_words[52u * row_count + row] = r139;
    unsigned r1337 = stwo_m31_mul(r142, r82);
    out_cols[54u][row] = r142;
    lookup_words[55u * row_count + row] = r142;
    unsigned r1338 = stwo_m31_add(r141, r1337);
    out_cols[53u][row] = r141;
    lookup_words[54u * row_count + row] = r141;
    unsigned r1339 = stwo_m31_mul(r144, r82);
    out_cols[56u][row] = r144;
    lookup_words[57u * row_count + row] = r144;
    unsigned r1340 = stwo_m31_add(r143, r1339);
    out_cols[55u][row] = r143;
    lookup_words[56u * row_count + row] = r143;
    unsigned r1341 = stwo_m31_mul(r146, r82);
    out_cols[58u][row] = r146;
    lookup_words[59u * row_count + row] = r146;
    unsigned r1342 = stwo_m31_add(r145, r1341);
    out_cols[57u][row] = r145;
    lookup_words[58u * row_count + row] = r145;
    const unsigned dargs14[72] = { r1258, r14, r1316, r1318, r1320, r1322, r1324, r1326, r1328, r1330, r1332, r1334, r1336, r1338, r1340, r1342, r1202, r1203, r1204, r1205, r1206, r1207, r1208, r1209, r1210, r1211, r1212, r1213, r1214, r1215, r1216, r1217, r1218, r1219, r1220, r1221, r1222, r1223, r1224, r1225, r1226, r1227, r1228, r1229, r1230, r1231, r1232, r1233, r1234, r1235, r1236, r1237, r1238, r1239, r1240, r1241, r1242, r1243, r1244, r1245, r1246, r1247, r1248, r1249, r1250, r1251, r1252, r1253, r1254, r1255, r1256, r1257 };
    unsigned douts14[72];
    out_cols[79u][row] = r1202;
    out_cols[80u][row] = r1203;
    out_cols[81u][row] = r1204;
    out_cols[82u][row] = r1205;
    out_cols[83u][row] = r1206;
    out_cols[84u][row] = r1207;
    out_cols[85u][row] = r1208;
    out_cols[86u][row] = r1209;
    out_cols[87u][row] = r1210;
    out_cols[88u][row] = r1211;
    out_cols[89u][row] = r1212;
    out_cols[90u][row] = r1213;
    out_cols[91u][row] = r1214;
    out_cols[92u][row] = r1215;
    out_cols[93u][row] = r1216;
    out_cols[94u][row] = r1217;
    out_cols[95u][row] = r1218;
    out_cols[96u][row] = r1219;
    out_cols[97u][row] = r1220;
    out_cols[98u][row] = r1221;
    out_cols[99u][row] = r1222;
    out_cols[100u][row] = r1223;
    out_cols[101u][row] = r1224;
    out_cols[102u][row] = r1225;
    out_cols[103u][row] = r1226;
    out_cols[104u][row] = r1227;
    out_cols[105u][row] = r1228;
    out_cols[106u][row] = r1229;
    out_cols[107u][row] = r1230;
    out_cols[108u][row] = r1231;
    out_cols[109u][row] = r1232;
    out_cols[110u][row] = r1233;
    out_cols[111u][row] = r1234;
    out_cols[112u][row] = r1235;
    out_cols[113u][row] = r1236;
    out_cols[114u][row] = r1237;
    out_cols[115u][row] = r1238;
    out_cols[116u][row] = r1239;
    out_cols[117u][row] = r1240;
    out_cols[118u][row] = r1241;
    out_cols[119u][row] = r1242;
    out_cols[120u][row] = r1243;
    out_cols[121u][row] = r1244;
    out_cols[122u][row] = r1245;
    out_cols[123u][row] = r1246;
    out_cols[124u][row] = r1247;
    out_cols[125u][row] = r1248;
    out_cols[126u][row] = r1249;
    out_cols[127u][row] = r1250;
    out_cols[128u][row] = r1251;
    out_cols[129u][row] = r1252;
    out_cols[130u][row] = r1253;
    out_cols[131u][row] = r1254;
    out_cols[132u][row] = r1255;
    out_cols[133u][row] = r1256;
    out_cols[134u][row] = r1257;
    lookup_words[143u * row_count + row] = r14;
    lookup_words[158u * row_count + row] = r1202;
    lookup_words[159u * row_count + row] = r1203;
    lookup_words[160u * row_count + row] = r1204;
    lookup_words[161u * row_count + row] = r1205;
    lookup_words[162u * row_count + row] = r1206;
    lookup_words[163u * row_count + row] = r1207;
    lookup_words[164u * row_count + row] = r1208;
    lookup_words[165u * row_count + row] = r1209;
    lookup_words[166u * row_count + row] = r1210;
    lookup_words[167u * row_count + row] = r1211;
    lookup_words[168u * row_count + row] = r1212;
    lookup_words[169u * row_count + row] = r1213;
    lookup_words[170u * row_count + row] = r1214;
    lookup_words[171u * row_count + row] = r1215;
    lookup_words[172u * row_count + row] = r1216;
    lookup_words[173u * row_count + row] = r1217;
    lookup_words[174u * row_count + row] = r1218;
    lookup_words[175u * row_count + row] = r1219;
    lookup_words[176u * row_count + row] = r1220;
    lookup_words[177u * row_count + row] = r1221;
    lookup_words[178u * row_count + row] = r1222;
    lookup_words[179u * row_count + row] = r1223;
    lookup_words[180u * row_count + row] = r1224;
    lookup_words[181u * row_count + row] = r1225;
    lookup_words[182u * row_count + row] = r1226;
    lookup_words[183u * row_count + row] = r1227;
    lookup_words[184u * row_count + row] = r1228;
    lookup_words[185u * row_count + row] = r1229;
    lookup_words[186u * row_count + row] = r1230;
    lookup_words[187u * row_count + row] = r1231;
    lookup_words[188u * row_count + row] = r1232;
    lookup_words[189u * row_count + row] = r1233;
    lookup_words[190u * row_count + row] = r1234;
    lookup_words[191u * row_count + row] = r1235;
    lookup_words[192u * row_count + row] = r1236;
    lookup_words[193u * row_count + row] = r1237;
    lookup_words[194u * row_count + row] = r1238;
    lookup_words[195u * row_count + row] = r1239;
    lookup_words[196u * row_count + row] = r1240;
    lookup_words[197u * row_count + row] = r1241;
    lookup_words[198u * row_count + row] = r1242;
    lookup_words[199u * row_count + row] = r1243;
    lookup_words[200u * row_count + row] = r1244;
    lookup_words[201u * row_count + row] = r1245;
    lookup_words[202u * row_count + row] = r1246;
    lookup_words[203u * row_count + row] = r1247;
    lookup_words[204u * row_count + row] = r1248;
    lookup_words[205u * row_count + row] = r1249;
    lookup_words[206u * row_count + row] = r1250;
    lookup_words[207u * row_count + row] = r1251;
    lookup_words[208u * row_count + row] = r1252;
    lookup_words[209u * row_count + row] = r1253;
    lookup_words[210u * row_count + row] = r1254;
    lookup_words[211u * row_count + row] = r1255;
    lookup_words[212u * row_count + row] = r1256;
    lookup_words[213u * row_count + row] = r1257;
    lookup_words[216u * row_count + row] = r14;
    lookup_words[231u * row_count + row] = r1202;
    lookup_words[232u * row_count + row] = r1203;
    lookup_words[233u * row_count + row] = r1204;
    lookup_words[234u * row_count + row] = r1205;
    lookup_words[235u * row_count + row] = r1206;
    lookup_words[236u * row_count + row] = r1207;
    lookup_words[237u * row_count + row] = r1208;
    lookup_words[238u * row_count + row] = r1209;
    lookup_words[239u * row_count + row] = r1210;
    lookup_words[240u * row_count + row] = r1211;
    lookup_words[241u * row_count + row] = r1212;
    lookup_words[242u * row_count + row] = r1213;
    lookup_words[243u * row_count + row] = r1214;
    lookup_words[244u * row_count + row] = r1215;
    lookup_words[245u * row_count + row] = r1216;
    lookup_words[246u * row_count + row] = r1217;
    lookup_words[247u * row_count + row] = r1218;
    lookup_words[248u * row_count + row] = r1219;
    lookup_words[249u * row_count + row] = r1220;
    lookup_words[250u * row_count + row] = r1221;
    lookup_words[251u * row_count + row] = r1222;
    lookup_words[252u * row_count + row] = r1223;
    lookup_words[253u * row_count + row] = r1224;
    lookup_words[254u * row_count + row] = r1225;
    lookup_words[255u * row_count + row] = r1226;
    lookup_words[256u * row_count + row] = r1227;
    lookup_words[257u * row_count + row] = r1228;
    lookup_words[258u * row_count + row] = r1229;
    lookup_words[259u * row_count + row] = r1230;
    lookup_words[260u * row_count + row] = r1231;
    lookup_words[261u * row_count + row] = r1232;
    lookup_words[262u * row_count + row] = r1233;
    lookup_words[263u * row_count + row] = r1234;
    lookup_words[264u * row_count + row] = r1235;
    lookup_words[265u * row_count + row] = r1236;
    lookup_words[266u * row_count + row] = r1237;
    lookup_words[267u * row_count + row] = r1238;
    lookup_words[268u * row_count + row] = r1239;
    lookup_words[269u * row_count + row] = r1240;
    lookup_words[270u * row_count + row] = r1241;
    lookup_words[271u * row_count + row] = r1242;
    lookup_words[272u * row_count + row] = r1243;
    lookup_words[273u * row_count + row] = r1244;
    lookup_words[274u * row_count + row] = r1245;
    lookup_words[275u * row_count + row] = r1246;
    lookup_words[276u * row_count + row] = r1247;
    lookup_words[277u * row_count + row] = r1248;
    lookup_words[278u * row_count + row] = r1249;
    lookup_words[279u * row_count + row] = r1250;
    lookup_words[280u * row_count + row] = r1251;
    lookup_words[281u * row_count + row] = r1252;
    lookup_words[282u * row_count + row] = r1253;
    lookup_words[283u * row_count + row] = r1254;
    lookup_words[284u * row_count + row] = r1255;
    lookup_words[285u * row_count + row] = r1256;
    lookup_words[286u * row_count + row] = r1257;
    sub_words[1016u * row_count + row] = r14;
    sub_words[1031u * row_count + row] = r1202;
    sub_words[1032u * row_count + row] = r1203;
    sub_words[1033u * row_count + row] = r1204;
    sub_words[1034u * row_count + row] = r1205;
    sub_words[1035u * row_count + row] = r1206;
    sub_words[1036u * row_count + row] = r1207;
    sub_words[1037u * row_count + row] = r1208;
    sub_words[1038u * row_count + row] = r1209;
    sub_words[1039u * row_count + row] = r1210;
    sub_words[1040u * row_count + row] = r1211;
    sub_words[1041u * row_count + row] = r1212;
    sub_words[1042u * row_count + row] = r1213;
    sub_words[1043u * row_count + row] = r1214;
    sub_words[1044u * row_count + row] = r1215;
    sub_words[1045u * row_count + row] = r1216;
    sub_words[1046u * row_count + row] = r1217;
    sub_words[1047u * row_count + row] = r1218;
    sub_words[1048u * row_count + row] = r1219;
    sub_words[1049u * row_count + row] = r1220;
    sub_words[1050u * row_count + row] = r1221;
    sub_words[1051u * row_count + row] = r1222;
    sub_words[1052u * row_count + row] = r1223;
    sub_words[1053u * row_count + row] = r1224;
    sub_words[1054u * row_count + row] = r1225;
    sub_words[1055u * row_count + row] = r1226;
    sub_words[1056u * row_count + row] = r1227;
    sub_words[1057u * row_count + row] = r1228;
    sub_words[1058u * row_count + row] = r1229;
    sub_words[1059u * row_count + row] = r1230;
    sub_words[1060u * row_count + row] = r1231;
    sub_words[1061u * row_count + row] = r1232;
    sub_words[1062u * row_count + row] = r1233;
    sub_words[1063u * row_count + row] = r1234;
    sub_words[1064u * row_count + row] = r1235;
    sub_words[1065u * row_count + row] = r1236;
    sub_words[1066u * row_count + row] = r1237;
    sub_words[1067u * row_count + row] = r1238;
    sub_words[1068u * row_count + row] = r1239;
    sub_words[1069u * row_count + row] = r1240;
    sub_words[1070u * row_count + row] = r1241;
    sub_words[1071u * row_count + row] = r1242;
    sub_words[1072u * row_count + row] = r1243;
    sub_words[1073u * row_count + row] = r1244;
    sub_words[1074u * row_count + row] = r1245;
    sub_words[1075u * row_count + row] = r1246;
    sub_words[1076u * row_count + row] = r1247;
    sub_words[1077u * row_count + row] = r1248;
    sub_words[1078u * row_count + row] = r1249;
    sub_words[1079u * row_count + row] = r1250;
    sub_words[1080u * row_count + row] = r1251;
    sub_words[1081u * row_count + row] = r1252;
    sub_words[1082u * row_count + row] = r1253;
    sub_words[1083u * row_count + row] = r1254;
    sub_words[1084u * row_count + row] = r1255;
    sub_words[1085u * row_count + row] = r1256;
    sub_words[1086u * row_count + row] = r1257;
    stwo_wit_deduce_partial_ec_mul_w18(dargs14, douts14);
    unsigned r1343 = douts14[0];
    unsigned r1344 = douts14[1];
    unsigned r1345 = douts14[2];
    unsigned r1346 = douts14[3];
    unsigned r1347 = douts14[4];
    unsigned r1348 = douts14[5];
    unsigned r1349 = douts14[6];
    unsigned r1350 = douts14[7];
    unsigned r1351 = douts14[8];
    unsigned r1352 = douts14[9];
    unsigned r1353 = douts14[10];
    unsigned r1354 = douts14[11];
    unsigned r1355 = douts14[12];
    unsigned r1356 = douts14[13];
    unsigned r1357 = douts14[14];
    unsigned r1358 = douts14[15];
    unsigned r1359 = douts14[16];
    unsigned r1360 = douts14[17];
    unsigned r1361 = douts14[18];
    unsigned r1362 = douts14[19];
    unsigned r1363 = douts14[20];
    unsigned r1364 = douts14[21];
    unsigned r1365 = douts14[22];
    unsigned r1366 = douts14[23];
    unsigned r1367 = douts14[24];
    unsigned r1368 = douts14[25];
    unsigned r1369 = douts14[26];
    unsigned r1370 = douts14[27];
    unsigned r1371 = douts14[28];
    unsigned r1372 = douts14[29];
    unsigned r1373 = douts14[30];
    unsigned r1374 = douts14[31];
    unsigned r1375 = douts14[32];
    unsigned r1376 = douts14[33];
    unsigned r1377 = douts14[34];
    unsigned r1378 = douts14[35];
    unsigned r1379 = douts14[36];
    unsigned r1380 = douts14[37];
    unsigned r1381 = douts14[38];
    unsigned r1382 = douts14[39];
    unsigned r1383 = douts14[40];
    unsigned r1384 = douts14[41];
    unsigned r1385 = douts14[42];
    unsigned r1386 = douts14[43];
    unsigned r1387 = douts14[44];
    unsigned r1388 = douts14[45];
    unsigned r1389 = douts14[46];
    unsigned r1390 = douts14[47];
    unsigned r1391 = douts14[48];
    unsigned r1392 = douts14[49];
    unsigned r1393 = douts14[50];
    unsigned r1394 = douts14[51];
    unsigned r1395 = douts14[52];
    unsigned r1396 = douts14[53];
    unsigned r1397 = douts14[54];
    unsigned r1398 = douts14[55];
    unsigned r1399 = douts14[56];
    unsigned r1400 = douts14[57];
    unsigned r1401 = douts14[58];
    unsigned r1402 = douts14[59];
    unsigned r1403 = douts14[60];
    unsigned r1404 = douts14[61];
    unsigned r1405 = douts14[62];
    unsigned r1406 = douts14[63];
    unsigned r1407 = douts14[64];
    unsigned r1408 = douts14[65];
    unsigned r1409 = douts14[66];
    unsigned r1410 = douts14[67];
    unsigned r1411 = douts14[68];
    unsigned r1412 = douts14[69];
    unsigned r1413 = douts14[70];
    unsigned r1414 = douts14[71];
    const unsigned dargs15[72] = { r1258, r15, r1345, r1346, r1347, r1348, r1349, r1350, r1351, r1352, r1353, r1354, r1355, r1356, r1357, r1358, r1359, r1360, r1361, r1362, r1363, r1364, r1365, r1366, r1367, r1368, r1369, r1370, r1371, r1372, r1373, r1374, r1375, r1376, r1377, r1378, r1379, r1380, r1381, r1382, r1383, r1384, r1385, r1386, r1387, r1388, r1389, r1390, r1391, r1392, r1393, r1394, r1395, r1396, r1397, r1398, r1399, r1400, r1401, r1402, r1403, r1404, r1405, r1406, r1407, r1408, r1409, r1410, r1411, r1412, r1413, r1414 };
    unsigned douts15[72];
    sub_words[1088u * row_count + row] = r15;
    sub_words[1089u * row_count + row] = r1345;
    sub_words[1090u * row_count + row] = r1346;
    sub_words[1091u * row_count + row] = r1347;
    sub_words[1092u * row_count + row] = r1348;
    sub_words[1093u * row_count + row] = r1349;
    sub_words[1094u * row_count + row] = r1350;
    sub_words[1095u * row_count + row] = r1351;
    sub_words[1096u * row_count + row] = r1352;
    sub_words[1097u * row_count + row] = r1353;
    sub_words[1098u * row_count + row] = r1354;
    sub_words[1099u * row_count + row] = r1355;
    sub_words[1100u * row_count + row] = r1356;
    sub_words[1101u * row_count + row] = r1357;
    sub_words[1102u * row_count + row] = r1358;
    sub_words[1103u * row_count + row] = r1359;
    sub_words[1104u * row_count + row] = r1360;
    sub_words[1105u * row_count + row] = r1361;
    sub_words[1106u * row_count + row] = r1362;
    sub_words[1107u * row_count + row] = r1363;
    sub_words[1108u * row_count + row] = r1364;
    sub_words[1109u * row_count + row] = r1365;
    sub_words[1110u * row_count + row] = r1366;
    sub_words[1111u * row_count + row] = r1367;
    sub_words[1112u * row_count + row] = r1368;
    sub_words[1113u * row_count + row] = r1369;
    sub_words[1114u * row_count + row] = r1370;
    sub_words[1115u * row_count + row] = r1371;
    sub_words[1116u * row_count + row] = r1372;
    sub_words[1117u * row_count + row] = r1373;
    sub_words[1118u * row_count + row] = r1374;
    sub_words[1119u * row_count + row] = r1375;
    sub_words[1120u * row_count + row] = r1376;
    sub_words[1121u * row_count + row] = r1377;
    sub_words[1122u * row_count + row] = r1378;
    sub_words[1123u * row_count + row] = r1379;
    sub_words[1124u * row_count + row] = r1380;
    sub_words[1125u * row_count + row] = r1381;
    sub_words[1126u * row_count + row] = r1382;
    sub_words[1127u * row_count + row] = r1383;
    sub_words[1128u * row_count + row] = r1384;
    sub_words[1129u * row_count + row] = r1385;
    sub_words[1130u * row_count + row] = r1386;
    sub_words[1131u * row_count + row] = r1387;
    sub_words[1132u * row_count + row] = r1388;
    sub_words[1133u * row_count + row] = r1389;
    sub_words[1134u * row_count + row] = r1390;
    sub_words[1135u * row_count + row] = r1391;
    sub_words[1136u * row_count + row] = r1392;
    sub_words[1137u * row_count + row] = r1393;
    sub_words[1138u * row_count + row] = r1394;
    sub_words[1139u * row_count + row] = r1395;
    sub_words[1140u * row_count + row] = r1396;
    sub_words[1141u * row_count + row] = r1397;
    sub_words[1142u * row_count + row] = r1398;
    sub_words[1143u * row_count + row] = r1399;
    sub_words[1144u * row_count + row] = r1400;
    sub_words[1145u * row_count + row] = r1401;
    sub_words[1146u * row_count + row] = r1402;
    sub_words[1147u * row_count + row] = r1403;
    sub_words[1148u * row_count + row] = r1404;
    sub_words[1149u * row_count + row] = r1405;
    sub_words[1150u * row_count + row] = r1406;
    sub_words[1151u * row_count + row] = r1407;
    sub_words[1152u * row_count + row] = r1408;
    sub_words[1153u * row_count + row] = r1409;
    sub_words[1154u * row_count + row] = r1410;
    sub_words[1155u * row_count + row] = r1411;
    sub_words[1156u * row_count + row] = r1412;
    sub_words[1157u * row_count + row] = r1413;
    sub_words[1158u * row_count + row] = r1414;
    stwo_wit_deduce_partial_ec_mul_w18(dargs15, douts15);
    unsigned r1415 = douts15[0];
    unsigned r1416 = douts15[1];
    unsigned r1417 = douts15[2];
    unsigned r1418 = douts15[3];
    unsigned r1419 = douts15[4];
    unsigned r1420 = douts15[5];
    unsigned r1421 = douts15[6];
    unsigned r1422 = douts15[7];
    unsigned r1423 = douts15[8];
    unsigned r1424 = douts15[9];
    unsigned r1425 = douts15[10];
    unsigned r1426 = douts15[11];
    unsigned r1427 = douts15[12];
    unsigned r1428 = douts15[13];
    unsigned r1429 = douts15[14];
    unsigned r1430 = douts15[15];
    unsigned r1431 = douts15[16];
    unsigned r1432 = douts15[17];
    unsigned r1433 = douts15[18];
    unsigned r1434 = douts15[19];
    unsigned r1435 = douts15[20];
    unsigned r1436 = douts15[21];
    unsigned r1437 = douts15[22];
    unsigned r1438 = douts15[23];
    unsigned r1439 = douts15[24];
    unsigned r1440 = douts15[25];
    unsigned r1441 = douts15[26];
    unsigned r1442 = douts15[27];
    unsigned r1443 = douts15[28];
    unsigned r1444 = douts15[29];
    unsigned r1445 = douts15[30];
    unsigned r1446 = douts15[31];
    unsigned r1447 = douts15[32];
    unsigned r1448 = douts15[33];
    unsigned r1449 = douts15[34];
    unsigned r1450 = douts15[35];
    unsigned r1451 = douts15[36];
    unsigned r1452 = douts15[37];
    unsigned r1453 = douts15[38];
    unsigned r1454 = douts15[39];
    unsigned r1455 = douts15[40];
    unsigned r1456 = douts15[41];
    unsigned r1457 = douts15[42];
    unsigned r1458 = douts15[43];
    unsigned r1459 = douts15[44];
    unsigned r1460 = douts15[45];
    unsigned r1461 = douts15[46];
    unsigned r1462 = douts15[47];
    unsigned r1463 = douts15[48];
    unsigned r1464 = douts15[49];
    unsigned r1465 = douts15[50];
    unsigned r1466 = douts15[51];
    unsigned r1467 = douts15[52];
    unsigned r1468 = douts15[53];
    unsigned r1469 = douts15[54];
    unsigned r1470 = douts15[55];
    unsigned r1471 = douts15[56];
    unsigned r1472 = douts15[57];
    unsigned r1473 = douts15[58];
    unsigned r1474 = douts15[59];
    unsigned r1475 = douts15[60];
    unsigned r1476 = douts15[61];
    unsigned r1477 = douts15[62];
    unsigned r1478 = douts15[63];
    unsigned r1479 = douts15[64];
    unsigned r1480 = douts15[65];
    unsigned r1481 = douts15[66];
    unsigned r1482 = douts15[67];
    unsigned r1483 = douts15[68];
    unsigned r1484 = douts15[69];
    unsigned r1485 = douts15[70];
    unsigned r1486 = douts15[71];
    const unsigned dargs16[72] = { r1258, r16, r1417, r1418, r1419, r1420, r1421, r1422, r1423, r1424, r1425, r1426, r1427, r1428, r1429, r1430, r1431, r1432, r1433, r1434, r1435, r1436, r1437, r1438, r1439, r1440, r1441, r1442, r1443, r1444, r1445, r1446, r1447, r1448, r1449, r1450, r1451, r1452, r1453, r1454, r1455, r1456, r1457, r1458, r1459, r1460, r1461, r1462, r1463, r1464, r1465, r1466, r1467, r1468, r1469, r1470, r1471, r1472, r1473, r1474, r1475, r1476, r1477, r1478, r1479, r1480, r1481, r1482, r1483, r1484, r1485, r1486 };
    unsigned douts16[72];
    sub_words[1160u * row_count + row] = r16;
    sub_words[1161u * row_count + row] = r1417;
    sub_words[1162u * row_count + row] = r1418;
    sub_words[1163u * row_count + row] = r1419;
    sub_words[1164u * row_count + row] = r1420;
    sub_words[1165u * row_count + row] = r1421;
    sub_words[1166u * row_count + row] = r1422;
    sub_words[1167u * row_count + row] = r1423;
    sub_words[1168u * row_count + row] = r1424;
    sub_words[1169u * row_count + row] = r1425;
    sub_words[1170u * row_count + row] = r1426;
    sub_words[1171u * row_count + row] = r1427;
    sub_words[1172u * row_count + row] = r1428;
    sub_words[1173u * row_count + row] = r1429;
    sub_words[1174u * row_count + row] = r1430;
    sub_words[1175u * row_count + row] = r1431;
    sub_words[1176u * row_count + row] = r1432;
    sub_words[1177u * row_count + row] = r1433;
    sub_words[1178u * row_count + row] = r1434;
    sub_words[1179u * row_count + row] = r1435;
    sub_words[1180u * row_count + row] = r1436;
    sub_words[1181u * row_count + row] = r1437;
    sub_words[1182u * row_count + row] = r1438;
    sub_words[1183u * row_count + row] = r1439;
    sub_words[1184u * row_count + row] = r1440;
    sub_words[1185u * row_count + row] = r1441;
    sub_words[1186u * row_count + row] = r1442;
    sub_words[1187u * row_count + row] = r1443;
    sub_words[1188u * row_count + row] = r1444;
    sub_words[1189u * row_count + row] = r1445;
    sub_words[1190u * row_count + row] = r1446;
    sub_words[1191u * row_count + row] = r1447;
    sub_words[1192u * row_count + row] = r1448;
    sub_words[1193u * row_count + row] = r1449;
    sub_words[1194u * row_count + row] = r1450;
    sub_words[1195u * row_count + row] = r1451;
    sub_words[1196u * row_count + row] = r1452;
    sub_words[1197u * row_count + row] = r1453;
    sub_words[1198u * row_count + row] = r1454;
    sub_words[1199u * row_count + row] = r1455;
    sub_words[1200u * row_count + row] = r1456;
    sub_words[1201u * row_count + row] = r1457;
    sub_words[1202u * row_count + row] = r1458;
    sub_words[1203u * row_count + row] = r1459;
    sub_words[1204u * row_count + row] = r1460;
    sub_words[1205u * row_count + row] = r1461;
    sub_words[1206u * row_count + row] = r1462;
    sub_words[1207u * row_count + row] = r1463;
    sub_words[1208u * row_count + row] = r1464;
    sub_words[1209u * row_count + row] = r1465;
    sub_words[1210u * row_count + row] = r1466;
    sub_words[1211u * row_count + row] = r1467;
    sub_words[1212u * row_count + row] = r1468;
    sub_words[1213u * row_count + row] = r1469;
    sub_words[1214u * row_count + row] = r1470;
    sub_words[1215u * row_count + row] = r1471;
    sub_words[1216u * row_count + row] = r1472;
    sub_words[1217u * row_count + row] = r1473;
    sub_words[1218u * row_count + row] = r1474;
    sub_words[1219u * row_count + row] = r1475;
    sub_words[1220u * row_count + row] = r1476;
    sub_words[1221u * row_count + row] = r1477;
    sub_words[1222u * row_count + row] = r1478;
    sub_words[1223u * row_count + row] = r1479;
    sub_words[1224u * row_count + row] = r1480;
    sub_words[1225u * row_count + row] = r1481;
    sub_words[1226u * row_count + row] = r1482;
    sub_words[1227u * row_count + row] = r1483;
    sub_words[1228u * row_count + row] = r1484;
    sub_words[1229u * row_count + row] = r1485;
    sub_words[1230u * row_count + row] = r1486;
    stwo_wit_deduce_partial_ec_mul_w18(dargs16, douts16);
    unsigned r1487 = douts16[0];
    unsigned r1488 = douts16[1];
    unsigned r1489 = douts16[2];
    unsigned r1490 = douts16[3];
    unsigned r1491 = douts16[4];
    unsigned r1492 = douts16[5];
    unsigned r1493 = douts16[6];
    unsigned r1494 = douts16[7];
    unsigned r1495 = douts16[8];
    unsigned r1496 = douts16[9];
    unsigned r1497 = douts16[10];
    unsigned r1498 = douts16[11];
    unsigned r1499 = douts16[12];
    unsigned r1500 = douts16[13];
    unsigned r1501 = douts16[14];
    unsigned r1502 = douts16[15];
    unsigned r1503 = douts16[16];
    unsigned r1504 = douts16[17];
    unsigned r1505 = douts16[18];
    unsigned r1506 = douts16[19];
    unsigned r1507 = douts16[20];
    unsigned r1508 = douts16[21];
    unsigned r1509 = douts16[22];
    unsigned r1510 = douts16[23];
    unsigned r1511 = douts16[24];
    unsigned r1512 = douts16[25];
    unsigned r1513 = douts16[26];
    unsigned r1514 = douts16[27];
    unsigned r1515 = douts16[28];
    unsigned r1516 = douts16[29];
    unsigned r1517 = douts16[30];
    unsigned r1518 = douts16[31];
    unsigned r1519 = douts16[32];
    unsigned r1520 = douts16[33];
    unsigned r1521 = douts16[34];
    unsigned r1522 = douts16[35];
    unsigned r1523 = douts16[36];
    unsigned r1524 = douts16[37];
    unsigned r1525 = douts16[38];
    unsigned r1526 = douts16[39];
    unsigned r1527 = douts16[40];
    unsigned r1528 = douts16[41];
    unsigned r1529 = douts16[42];
    unsigned r1530 = douts16[43];
    unsigned r1531 = douts16[44];
    unsigned r1532 = douts16[45];
    unsigned r1533 = douts16[46];
    unsigned r1534 = douts16[47];
    unsigned r1535 = douts16[48];
    unsigned r1536 = douts16[49];
    unsigned r1537 = douts16[50];
    unsigned r1538 = douts16[51];
    unsigned r1539 = douts16[52];
    unsigned r1540 = douts16[53];
    unsigned r1541 = douts16[54];
    unsigned r1542 = douts16[55];
    unsigned r1543 = douts16[56];
    unsigned r1544 = douts16[57];
    unsigned r1545 = douts16[58];
    unsigned r1546 = douts16[59];
    unsigned r1547 = douts16[60];
    unsigned r1548 = douts16[61];
    unsigned r1549 = douts16[62];
    unsigned r1550 = douts16[63];
    unsigned r1551 = douts16[64];
    unsigned r1552 = douts16[65];
    unsigned r1553 = douts16[66];
    unsigned r1554 = douts16[67];
    unsigned r1555 = douts16[68];
    unsigned r1556 = douts16[69];
    unsigned r1557 = douts16[70];
    unsigned r1558 = douts16[71];
    const unsigned dargs17[72] = { r1258, r17, r1489, r1490, r1491, r1492, r1493, r1494, r1495, r1496, r1497, r1498, r1499, r1500, r1501, r1502, r1503, r1504, r1505, r1506, r1507, r1508, r1509, r1510, r1511, r1512, r1513, r1514, r1515, r1516, r1517, r1518, r1519, r1520, r1521, r1522, r1523, r1524, r1525, r1526, r1527, r1528, r1529, r1530, r1531, r1532, r1533, r1534, r1535, r1536, r1537, r1538, r1539, r1540, r1541, r1542, r1543, r1544, r1545, r1546, r1547, r1548, r1549, r1550, r1551, r1552, r1553, r1554, r1555, r1556, r1557, r1558 };
    unsigned douts17[72];
    sub_words[1232u * row_count + row] = r17;
    sub_words[1233u * row_count + row] = r1489;
    sub_words[1234u * row_count + row] = r1490;
    sub_words[1235u * row_count + row] = r1491;
    sub_words[1236u * row_count + row] = r1492;
    sub_words[1237u * row_count + row] = r1493;
    sub_words[1238u * row_count + row] = r1494;
    sub_words[1239u * row_count + row] = r1495;
    sub_words[1240u * row_count + row] = r1496;
    sub_words[1241u * row_count + row] = r1497;
    sub_words[1242u * row_count + row] = r1498;
    sub_words[1243u * row_count + row] = r1499;
    sub_words[1244u * row_count + row] = r1500;
    sub_words[1245u * row_count + row] = r1501;
    sub_words[1246u * row_count + row] = r1502;
    sub_words[1247u * row_count + row] = r1503;
    sub_words[1248u * row_count + row] = r1504;
    sub_words[1249u * row_count + row] = r1505;
    sub_words[1250u * row_count + row] = r1506;
    sub_words[1251u * row_count + row] = r1507;
    sub_words[1252u * row_count + row] = r1508;
    sub_words[1253u * row_count + row] = r1509;
    sub_words[1254u * row_count + row] = r1510;
    sub_words[1255u * row_count + row] = r1511;
    sub_words[1256u * row_count + row] = r1512;
    sub_words[1257u * row_count + row] = r1513;
    sub_words[1258u * row_count + row] = r1514;
    sub_words[1259u * row_count + row] = r1515;
    sub_words[1260u * row_count + row] = r1516;
    sub_words[1261u * row_count + row] = r1517;
    sub_words[1262u * row_count + row] = r1518;
    sub_words[1263u * row_count + row] = r1519;
    sub_words[1264u * row_count + row] = r1520;
    sub_words[1265u * row_count + row] = r1521;
    sub_words[1266u * row_count + row] = r1522;
    sub_words[1267u * row_count + row] = r1523;
    sub_words[1268u * row_count + row] = r1524;
    sub_words[1269u * row_count + row] = r1525;
    sub_words[1270u * row_count + row] = r1526;
    sub_words[1271u * row_count + row] = r1527;
    sub_words[1272u * row_count + row] = r1528;
    sub_words[1273u * row_count + row] = r1529;
    sub_words[1274u * row_count + row] = r1530;
    sub_words[1275u * row_count + row] = r1531;
    sub_words[1276u * row_count + row] = r1532;
    sub_words[1277u * row_count + row] = r1533;
    sub_words[1278u * row_count + row] = r1534;
    sub_words[1279u * row_count + row] = r1535;
    sub_words[1280u * row_count + row] = r1536;
    sub_words[1281u * row_count + row] = r1537;
    sub_words[1282u * row_count + row] = r1538;
    sub_words[1283u * row_count + row] = r1539;
    sub_words[1284u * row_count + row] = r1540;
    sub_words[1285u * row_count + row] = r1541;
    sub_words[1286u * row_count + row] = r1542;
    sub_words[1287u * row_count + row] = r1543;
    sub_words[1288u * row_count + row] = r1544;
    sub_words[1289u * row_count + row] = r1545;
    sub_words[1290u * row_count + row] = r1546;
    sub_words[1291u * row_count + row] = r1547;
    sub_words[1292u * row_count + row] = r1548;
    sub_words[1293u * row_count + row] = r1549;
    sub_words[1294u * row_count + row] = r1550;
    sub_words[1295u * row_count + row] = r1551;
    sub_words[1296u * row_count + row] = r1552;
    sub_words[1297u * row_count + row] = r1553;
    sub_words[1298u * row_count + row] = r1554;
    sub_words[1299u * row_count + row] = r1555;
    sub_words[1300u * row_count + row] = r1556;
    sub_words[1301u * row_count + row] = r1557;
    sub_words[1302u * row_count + row] = r1558;
    stwo_wit_deduce_partial_ec_mul_w18(dargs17, douts17);
    unsigned r1559 = douts17[0];
    unsigned r1560 = douts17[1];
    unsigned r1561 = douts17[2];
    unsigned r1562 = douts17[3];
    unsigned r1563 = douts17[4];
    unsigned r1564 = douts17[5];
    unsigned r1565 = douts17[6];
    unsigned r1566 = douts17[7];
    unsigned r1567 = douts17[8];
    unsigned r1568 = douts17[9];
    unsigned r1569 = douts17[10];
    unsigned r1570 = douts17[11];
    unsigned r1571 = douts17[12];
    unsigned r1572 = douts17[13];
    unsigned r1573 = douts17[14];
    unsigned r1574 = douts17[15];
    unsigned r1575 = douts17[16];
    unsigned r1576 = douts17[17];
    unsigned r1577 = douts17[18];
    unsigned r1578 = douts17[19];
    unsigned r1579 = douts17[20];
    unsigned r1580 = douts17[21];
    unsigned r1581 = douts17[22];
    unsigned r1582 = douts17[23];
    unsigned r1583 = douts17[24];
    unsigned r1584 = douts17[25];
    unsigned r1585 = douts17[26];
    unsigned r1586 = douts17[27];
    unsigned r1587 = douts17[28];
    unsigned r1588 = douts17[29];
    unsigned r1589 = douts17[30];
    unsigned r1590 = douts17[31];
    unsigned r1591 = douts17[32];
    unsigned r1592 = douts17[33];
    unsigned r1593 = douts17[34];
    unsigned r1594 = douts17[35];
    unsigned r1595 = douts17[36];
    unsigned r1596 = douts17[37];
    unsigned r1597 = douts17[38];
    unsigned r1598 = douts17[39];
    unsigned r1599 = douts17[40];
    unsigned r1600 = douts17[41];
    unsigned r1601 = douts17[42];
    unsigned r1602 = douts17[43];
    unsigned r1603 = douts17[44];
    unsigned r1604 = douts17[45];
    unsigned r1605 = douts17[46];
    unsigned r1606 = douts17[47];
    unsigned r1607 = douts17[48];
    unsigned r1608 = douts17[49];
    unsigned r1609 = douts17[50];
    unsigned r1610 = douts17[51];
    unsigned r1611 = douts17[52];
    unsigned r1612 = douts17[53];
    unsigned r1613 = douts17[54];
    unsigned r1614 = douts17[55];
    unsigned r1615 = douts17[56];
    unsigned r1616 = douts17[57];
    unsigned r1617 = douts17[58];
    unsigned r1618 = douts17[59];
    unsigned r1619 = douts17[60];
    unsigned r1620 = douts17[61];
    unsigned r1621 = douts17[62];
    unsigned r1622 = douts17[63];
    unsigned r1623 = douts17[64];
    unsigned r1624 = douts17[65];
    unsigned r1625 = douts17[66];
    unsigned r1626 = douts17[67];
    unsigned r1627 = douts17[68];
    unsigned r1628 = douts17[69];
    unsigned r1629 = douts17[70];
    unsigned r1630 = douts17[71];
    const unsigned dargs18[72] = { r1258, r18, r1561, r1562, r1563, r1564, r1565, r1566, r1567, r1568, r1569, r1570, r1571, r1572, r1573, r1574, r1575, r1576, r1577, r1578, r1579, r1580, r1581, r1582, r1583, r1584, r1585, r1586, r1587, r1588, r1589, r1590, r1591, r1592, r1593, r1594, r1595, r1596, r1597, r1598, r1599, r1600, r1601, r1602, r1603, r1604, r1605, r1606, r1607, r1608, r1609, r1610, r1611, r1612, r1613, r1614, r1615, r1616, r1617, r1618, r1619, r1620, r1621, r1622, r1623, r1624, r1625, r1626, r1627, r1628, r1629, r1630 };
    unsigned douts18[72];
    sub_words[1304u * row_count + row] = r18;
    sub_words[1305u * row_count + row] = r1561;
    sub_words[1306u * row_count + row] = r1562;
    sub_words[1307u * row_count + row] = r1563;
    sub_words[1308u * row_count + row] = r1564;
    sub_words[1309u * row_count + row] = r1565;
    sub_words[1310u * row_count + row] = r1566;
    sub_words[1311u * row_count + row] = r1567;
    sub_words[1312u * row_count + row] = r1568;
    sub_words[1313u * row_count + row] = r1569;
    sub_words[1314u * row_count + row] = r1570;
    sub_words[1315u * row_count + row] = r1571;
    sub_words[1316u * row_count + row] = r1572;
    sub_words[1317u * row_count + row] = r1573;
    sub_words[1318u * row_count + row] = r1574;
    sub_words[1319u * row_count + row] = r1575;
    sub_words[1320u * row_count + row] = r1576;
    sub_words[1321u * row_count + row] = r1577;
    sub_words[1322u * row_count + row] = r1578;
    sub_words[1323u * row_count + row] = r1579;
    sub_words[1324u * row_count + row] = r1580;
    sub_words[1325u * row_count + row] = r1581;
    sub_words[1326u * row_count + row] = r1582;
    sub_words[1327u * row_count + row] = r1583;
    sub_words[1328u * row_count + row] = r1584;
    sub_words[1329u * row_count + row] = r1585;
    sub_words[1330u * row_count + row] = r1586;
    sub_words[1331u * row_count + row] = r1587;
    sub_words[1332u * row_count + row] = r1588;
    sub_words[1333u * row_count + row] = r1589;
    sub_words[1334u * row_count + row] = r1590;
    sub_words[1335u * row_count + row] = r1591;
    sub_words[1336u * row_count + row] = r1592;
    sub_words[1337u * row_count + row] = r1593;
    sub_words[1338u * row_count + row] = r1594;
    sub_words[1339u * row_count + row] = r1595;
    sub_words[1340u * row_count + row] = r1596;
    sub_words[1341u * row_count + row] = r1597;
    sub_words[1342u * row_count + row] = r1598;
    sub_words[1343u * row_count + row] = r1599;
    sub_words[1344u * row_count + row] = r1600;
    sub_words[1345u * row_count + row] = r1601;
    sub_words[1346u * row_count + row] = r1602;
    sub_words[1347u * row_count + row] = r1603;
    sub_words[1348u * row_count + row] = r1604;
    sub_words[1349u * row_count + row] = r1605;
    sub_words[1350u * row_count + row] = r1606;
    sub_words[1351u * row_count + row] = r1607;
    sub_words[1352u * row_count + row] = r1608;
    sub_words[1353u * row_count + row] = r1609;
    sub_words[1354u * row_count + row] = r1610;
    sub_words[1355u * row_count + row] = r1611;
    sub_words[1356u * row_count + row] = r1612;
    sub_words[1357u * row_count + row] = r1613;
    sub_words[1358u * row_count + row] = r1614;
    sub_words[1359u * row_count + row] = r1615;
    sub_words[1360u * row_count + row] = r1616;
    sub_words[1361u * row_count + row] = r1617;
    sub_words[1362u * row_count + row] = r1618;
    sub_words[1363u * row_count + row] = r1619;
    sub_words[1364u * row_count + row] = r1620;
    sub_words[1365u * row_count + row] = r1621;
    sub_words[1366u * row_count + row] = r1622;
    sub_words[1367u * row_count + row] = r1623;
    sub_words[1368u * row_count + row] = r1624;
    sub_words[1369u * row_count + row] = r1625;
    sub_words[1370u * row_count + row] = r1626;
    sub_words[1371u * row_count + row] = r1627;
    sub_words[1372u * row_count + row] = r1628;
    sub_words[1373u * row_count + row] = r1629;
    sub_words[1374u * row_count + row] = r1630;
    stwo_wit_deduce_partial_ec_mul_w18(dargs18, douts18);
    unsigned r1631 = douts18[0];
    unsigned r1632 = douts18[1];
    unsigned r1633 = douts18[2];
    unsigned r1634 = douts18[3];
    unsigned r1635 = douts18[4];
    unsigned r1636 = douts18[5];
    unsigned r1637 = douts18[6];
    unsigned r1638 = douts18[7];
    unsigned r1639 = douts18[8];
    unsigned r1640 = douts18[9];
    unsigned r1641 = douts18[10];
    unsigned r1642 = douts18[11];
    unsigned r1643 = douts18[12];
    unsigned r1644 = douts18[13];
    unsigned r1645 = douts18[14];
    unsigned r1646 = douts18[15];
    unsigned r1647 = douts18[16];
    unsigned r1648 = douts18[17];
    unsigned r1649 = douts18[18];
    unsigned r1650 = douts18[19];
    unsigned r1651 = douts18[20];
    unsigned r1652 = douts18[21];
    unsigned r1653 = douts18[22];
    unsigned r1654 = douts18[23];
    unsigned r1655 = douts18[24];
    unsigned r1656 = douts18[25];
    unsigned r1657 = douts18[26];
    unsigned r1658 = douts18[27];
    unsigned r1659 = douts18[28];
    unsigned r1660 = douts18[29];
    unsigned r1661 = douts18[30];
    unsigned r1662 = douts18[31];
    unsigned r1663 = douts18[32];
    unsigned r1664 = douts18[33];
    unsigned r1665 = douts18[34];
    unsigned r1666 = douts18[35];
    unsigned r1667 = douts18[36];
    unsigned r1668 = douts18[37];
    unsigned r1669 = douts18[38];
    unsigned r1670 = douts18[39];
    unsigned r1671 = douts18[40];
    unsigned r1672 = douts18[41];
    unsigned r1673 = douts18[42];
    unsigned r1674 = douts18[43];
    unsigned r1675 = douts18[44];
    unsigned r1676 = douts18[45];
    unsigned r1677 = douts18[46];
    unsigned r1678 = douts18[47];
    unsigned r1679 = douts18[48];
    unsigned r1680 = douts18[49];
    unsigned r1681 = douts18[50];
    unsigned r1682 = douts18[51];
    unsigned r1683 = douts18[52];
    unsigned r1684 = douts18[53];
    unsigned r1685 = douts18[54];
    unsigned r1686 = douts18[55];
    unsigned r1687 = douts18[56];
    unsigned r1688 = douts18[57];
    unsigned r1689 = douts18[58];
    unsigned r1690 = douts18[59];
    unsigned r1691 = douts18[60];
    unsigned r1692 = douts18[61];
    unsigned r1693 = douts18[62];
    unsigned r1694 = douts18[63];
    unsigned r1695 = douts18[64];
    unsigned r1696 = douts18[65];
    unsigned r1697 = douts18[66];
    unsigned r1698 = douts18[67];
    unsigned r1699 = douts18[68];
    unsigned r1700 = douts18[69];
    unsigned r1701 = douts18[70];
    unsigned r1702 = douts18[71];
    const unsigned dargs19[72] = { r1258, r19, r1633, r1634, r1635, r1636, r1637, r1638, r1639, r1640, r1641, r1642, r1643, r1644, r1645, r1646, r1647, r1648, r1649, r1650, r1651, r1652, r1653, r1654, r1655, r1656, r1657, r1658, r1659, r1660, r1661, r1662, r1663, r1664, r1665, r1666, r1667, r1668, r1669, r1670, r1671, r1672, r1673, r1674, r1675, r1676, r1677, r1678, r1679, r1680, r1681, r1682, r1683, r1684, r1685, r1686, r1687, r1688, r1689, r1690, r1691, r1692, r1693, r1694, r1695, r1696, r1697, r1698, r1699, r1700, r1701, r1702 };
    unsigned douts19[72];
    sub_words[1376u * row_count + row] = r19;
    sub_words[1377u * row_count + row] = r1633;
    sub_words[1378u * row_count + row] = r1634;
    sub_words[1379u * row_count + row] = r1635;
    sub_words[1380u * row_count + row] = r1636;
    sub_words[1381u * row_count + row] = r1637;
    sub_words[1382u * row_count + row] = r1638;
    sub_words[1383u * row_count + row] = r1639;
    sub_words[1384u * row_count + row] = r1640;
    sub_words[1385u * row_count + row] = r1641;
    sub_words[1386u * row_count + row] = r1642;
    sub_words[1387u * row_count + row] = r1643;
    sub_words[1388u * row_count + row] = r1644;
    sub_words[1389u * row_count + row] = r1645;
    sub_words[1390u * row_count + row] = r1646;
    sub_words[1391u * row_count + row] = r1647;
    sub_words[1392u * row_count + row] = r1648;
    sub_words[1393u * row_count + row] = r1649;
    sub_words[1394u * row_count + row] = r1650;
    sub_words[1395u * row_count + row] = r1651;
    sub_words[1396u * row_count + row] = r1652;
    sub_words[1397u * row_count + row] = r1653;
    sub_words[1398u * row_count + row] = r1654;
    sub_words[1399u * row_count + row] = r1655;
    sub_words[1400u * row_count + row] = r1656;
    sub_words[1401u * row_count + row] = r1657;
    sub_words[1402u * row_count + row] = r1658;
    sub_words[1403u * row_count + row] = r1659;
    sub_words[1404u * row_count + row] = r1660;
    sub_words[1405u * row_count + row] = r1661;
    sub_words[1406u * row_count + row] = r1662;
    sub_words[1407u * row_count + row] = r1663;
    sub_words[1408u * row_count + row] = r1664;
    sub_words[1409u * row_count + row] = r1665;
    sub_words[1410u * row_count + row] = r1666;
    sub_words[1411u * row_count + row] = r1667;
    sub_words[1412u * row_count + row] = r1668;
    sub_words[1413u * row_count + row] = r1669;
    sub_words[1414u * row_count + row] = r1670;
    sub_words[1415u * row_count + row] = r1671;
    sub_words[1416u * row_count + row] = r1672;
    sub_words[1417u * row_count + row] = r1673;
    sub_words[1418u * row_count + row] = r1674;
    sub_words[1419u * row_count + row] = r1675;
    sub_words[1420u * row_count + row] = r1676;
    sub_words[1421u * row_count + row] = r1677;
    sub_words[1422u * row_count + row] = r1678;
    sub_words[1423u * row_count + row] = r1679;
    sub_words[1424u * row_count + row] = r1680;
    sub_words[1425u * row_count + row] = r1681;
    sub_words[1426u * row_count + row] = r1682;
    sub_words[1427u * row_count + row] = r1683;
    sub_words[1428u * row_count + row] = r1684;
    sub_words[1429u * row_count + row] = r1685;
    sub_words[1430u * row_count + row] = r1686;
    sub_words[1431u * row_count + row] = r1687;
    sub_words[1432u * row_count + row] = r1688;
    sub_words[1433u * row_count + row] = r1689;
    sub_words[1434u * row_count + row] = r1690;
    sub_words[1435u * row_count + row] = r1691;
    sub_words[1436u * row_count + row] = r1692;
    sub_words[1437u * row_count + row] = r1693;
    sub_words[1438u * row_count + row] = r1694;
    sub_words[1439u * row_count + row] = r1695;
    sub_words[1440u * row_count + row] = r1696;
    sub_words[1441u * row_count + row] = r1697;
    sub_words[1442u * row_count + row] = r1698;
    sub_words[1443u * row_count + row] = r1699;
    sub_words[1444u * row_count + row] = r1700;
    sub_words[1445u * row_count + row] = r1701;
    sub_words[1446u * row_count + row] = r1702;
    stwo_wit_deduce_partial_ec_mul_w18(dargs19, douts19);
    unsigned r1703 = douts19[0];
    unsigned r1704 = douts19[1];
    unsigned r1705 = douts19[2];
    unsigned r1706 = douts19[3];
    unsigned r1707 = douts19[4];
    unsigned r1708 = douts19[5];
    unsigned r1709 = douts19[6];
    unsigned r1710 = douts19[7];
    unsigned r1711 = douts19[8];
    unsigned r1712 = douts19[9];
    unsigned r1713 = douts19[10];
    unsigned r1714 = douts19[11];
    unsigned r1715 = douts19[12];
    unsigned r1716 = douts19[13];
    unsigned r1717 = douts19[14];
    unsigned r1718 = douts19[15];
    unsigned r1719 = douts19[16];
    unsigned r1720 = douts19[17];
    unsigned r1721 = douts19[18];
    unsigned r1722 = douts19[19];
    unsigned r1723 = douts19[20];
    unsigned r1724 = douts19[21];
    unsigned r1725 = douts19[22];
    unsigned r1726 = douts19[23];
    unsigned r1727 = douts19[24];
    unsigned r1728 = douts19[25];
    unsigned r1729 = douts19[26];
    unsigned r1730 = douts19[27];
    unsigned r1731 = douts19[28];
    unsigned r1732 = douts19[29];
    unsigned r1733 = douts19[30];
    unsigned r1734 = douts19[31];
    unsigned r1735 = douts19[32];
    unsigned r1736 = douts19[33];
    unsigned r1737 = douts19[34];
    unsigned r1738 = douts19[35];
    unsigned r1739 = douts19[36];
    unsigned r1740 = douts19[37];
    unsigned r1741 = douts19[38];
    unsigned r1742 = douts19[39];
    unsigned r1743 = douts19[40];
    unsigned r1744 = douts19[41];
    unsigned r1745 = douts19[42];
    unsigned r1746 = douts19[43];
    unsigned r1747 = douts19[44];
    unsigned r1748 = douts19[45];
    unsigned r1749 = douts19[46];
    unsigned r1750 = douts19[47];
    unsigned r1751 = douts19[48];
    unsigned r1752 = douts19[49];
    unsigned r1753 = douts19[50];
    unsigned r1754 = douts19[51];
    unsigned r1755 = douts19[52];
    unsigned r1756 = douts19[53];
    unsigned r1757 = douts19[54];
    unsigned r1758 = douts19[55];
    unsigned r1759 = douts19[56];
    unsigned r1760 = douts19[57];
    unsigned r1761 = douts19[58];
    unsigned r1762 = douts19[59];
    unsigned r1763 = douts19[60];
    unsigned r1764 = douts19[61];
    unsigned r1765 = douts19[62];
    unsigned r1766 = douts19[63];
    unsigned r1767 = douts19[64];
    unsigned r1768 = douts19[65];
    unsigned r1769 = douts19[66];
    unsigned r1770 = douts19[67];
    unsigned r1771 = douts19[68];
    unsigned r1772 = douts19[69];
    unsigned r1773 = douts19[70];
    unsigned r1774 = douts19[71];
    const unsigned dargs20[72] = { r1258, r20, r1705, r1706, r1707, r1708, r1709, r1710, r1711, r1712, r1713, r1714, r1715, r1716, r1717, r1718, r1719, r1720, r1721, r1722, r1723, r1724, r1725, r1726, r1727, r1728, r1729, r1730, r1731, r1732, r1733, r1734, r1735, r1736, r1737, r1738, r1739, r1740, r1741, r1742, r1743, r1744, r1745, r1746, r1747, r1748, r1749, r1750, r1751, r1752, r1753, r1754, r1755, r1756, r1757, r1758, r1759, r1760, r1761, r1762, r1763, r1764, r1765, r1766, r1767, r1768, r1769, r1770, r1771, r1772, r1773, r1774 };
    unsigned douts20[72];
    lookup_words[118u * row_count + row] = r20;
    sub_words[56u * row_count + row] = r20;
    sub_words[1448u * row_count + row] = r20;
    sub_words[1449u * row_count + row] = r1705;
    sub_words[1450u * row_count + row] = r1706;
    sub_words[1451u * row_count + row] = r1707;
    sub_words[1452u * row_count + row] = r1708;
    sub_words[1453u * row_count + row] = r1709;
    sub_words[1454u * row_count + row] = r1710;
    sub_words[1455u * row_count + row] = r1711;
    sub_words[1456u * row_count + row] = r1712;
    sub_words[1457u * row_count + row] = r1713;
    sub_words[1458u * row_count + row] = r1714;
    sub_words[1459u * row_count + row] = r1715;
    sub_words[1460u * row_count + row] = r1716;
    sub_words[1461u * row_count + row] = r1717;
    sub_words[1462u * row_count + row] = r1718;
    sub_words[1463u * row_count + row] = r1719;
    sub_words[1464u * row_count + row] = r1720;
    sub_words[1465u * row_count + row] = r1721;
    sub_words[1466u * row_count + row] = r1722;
    sub_words[1467u * row_count + row] = r1723;
    sub_words[1468u * row_count + row] = r1724;
    sub_words[1469u * row_count + row] = r1725;
    sub_words[1470u * row_count + row] = r1726;
    sub_words[1471u * row_count + row] = r1727;
    sub_words[1472u * row_count + row] = r1728;
    sub_words[1473u * row_count + row] = r1729;
    sub_words[1474u * row_count + row] = r1730;
    sub_words[1475u * row_count + row] = r1731;
    sub_words[1476u * row_count + row] = r1732;
    sub_words[1477u * row_count + row] = r1733;
    sub_words[1478u * row_count + row] = r1734;
    sub_words[1479u * row_count + row] = r1735;
    sub_words[1480u * row_count + row] = r1736;
    sub_words[1481u * row_count + row] = r1737;
    sub_words[1482u * row_count + row] = r1738;
    sub_words[1483u * row_count + row] = r1739;
    sub_words[1484u * row_count + row] = r1740;
    sub_words[1485u * row_count + row] = r1741;
    sub_words[1486u * row_count + row] = r1742;
    sub_words[1487u * row_count + row] = r1743;
    sub_words[1488u * row_count + row] = r1744;
    sub_words[1489u * row_count + row] = r1745;
    sub_words[1490u * row_count + row] = r1746;
    sub_words[1491u * row_count + row] = r1747;
    sub_words[1492u * row_count + row] = r1748;
    sub_words[1493u * row_count + row] = r1749;
    sub_words[1494u * row_count + row] = r1750;
    sub_words[1495u * row_count + row] = r1751;
    sub_words[1496u * row_count + row] = r1752;
    sub_words[1497u * row_count + row] = r1753;
    sub_words[1498u * row_count + row] = r1754;
    sub_words[1499u * row_count + row] = r1755;
    sub_words[1500u * row_count + row] = r1756;
    sub_words[1501u * row_count + row] = r1757;
    sub_words[1502u * row_count + row] = r1758;
    sub_words[1503u * row_count + row] = r1759;
    sub_words[1504u * row_count + row] = r1760;
    sub_words[1505u * row_count + row] = r1761;
    sub_words[1506u * row_count + row] = r1762;
    sub_words[1507u * row_count + row] = r1763;
    sub_words[1508u * row_count + row] = r1764;
    sub_words[1509u * row_count + row] = r1765;
    sub_words[1510u * row_count + row] = r1766;
    sub_words[1511u * row_count + row] = r1767;
    sub_words[1512u * row_count + row] = r1768;
    sub_words[1513u * row_count + row] = r1769;
    sub_words[1514u * row_count + row] = r1770;
    sub_words[1515u * row_count + row] = r1771;
    sub_words[1516u * row_count + row] = r1772;
    sub_words[1517u * row_count + row] = r1773;
    sub_words[1518u * row_count + row] = r1774;
    stwo_wit_deduce_partial_ec_mul_w18(dargs20, douts20);
    unsigned r1775 = douts20[0];
    unsigned r1776 = douts20[1];
    unsigned r1777 = douts20[2];
    unsigned r1778 = douts20[3];
    unsigned r1779 = douts20[4];
    unsigned r1780 = douts20[5];
    unsigned r1781 = douts20[6];
    unsigned r1782 = douts20[7];
    unsigned r1783 = douts20[8];
    unsigned r1784 = douts20[9];
    unsigned r1785 = douts20[10];
    unsigned r1786 = douts20[11];
    unsigned r1787 = douts20[12];
    unsigned r1788 = douts20[13];
    unsigned r1789 = douts20[14];
    unsigned r1790 = douts20[15];
    unsigned r1791 = douts20[16];
    unsigned r1792 = douts20[17];
    unsigned r1793 = douts20[18];
    unsigned r1794 = douts20[19];
    unsigned r1795 = douts20[20];
    unsigned r1796 = douts20[21];
    unsigned r1797 = douts20[22];
    unsigned r1798 = douts20[23];
    unsigned r1799 = douts20[24];
    unsigned r1800 = douts20[25];
    unsigned r1801 = douts20[26];
    unsigned r1802 = douts20[27];
    unsigned r1803 = douts20[28];
    unsigned r1804 = douts20[29];
    unsigned r1805 = douts20[30];
    unsigned r1806 = douts20[31];
    unsigned r1807 = douts20[32];
    unsigned r1808 = douts20[33];
    unsigned r1809 = douts20[34];
    unsigned r1810 = douts20[35];
    unsigned r1811 = douts20[36];
    unsigned r1812 = douts20[37];
    unsigned r1813 = douts20[38];
    unsigned r1814 = douts20[39];
    unsigned r1815 = douts20[40];
    unsigned r1816 = douts20[41];
    unsigned r1817 = douts20[42];
    unsigned r1818 = douts20[43];
    unsigned r1819 = douts20[44];
    unsigned r1820 = douts20[45];
    unsigned r1821 = douts20[46];
    unsigned r1822 = douts20[47];
    unsigned r1823 = douts20[48];
    unsigned r1824 = douts20[49];
    unsigned r1825 = douts20[50];
    unsigned r1826 = douts20[51];
    unsigned r1827 = douts20[52];
    unsigned r1828 = douts20[53];
    unsigned r1829 = douts20[54];
    unsigned r1830 = douts20[55];
    unsigned r1831 = douts20[56];
    unsigned r1832 = douts20[57];
    unsigned r1833 = douts20[58];
    unsigned r1834 = douts20[59];
    unsigned r1835 = douts20[60];
    unsigned r1836 = douts20[61];
    unsigned r1837 = douts20[62];
    unsigned r1838 = douts20[63];
    unsigned r1839 = douts20[64];
    unsigned r1840 = douts20[65];
    unsigned r1841 = douts20[66];
    unsigned r1842 = douts20[67];
    unsigned r1843 = douts20[68];
    unsigned r1844 = douts20[69];
    unsigned r1845 = douts20[70];
    unsigned r1846 = douts20[71];
    const unsigned dargs21[72] = { r1258, r21, r1777, r1778, r1779, r1780, r1781, r1782, r1783, r1784, r1785, r1786, r1787, r1788, r1789, r1790, r1791, r1792, r1793, r1794, r1795, r1796, r1797, r1798, r1799, r1800, r1801, r1802, r1803, r1804, r1805, r1806, r1807, r1808, r1809, r1810, r1811, r1812, r1813, r1814, r1815, r1816, r1817, r1818, r1819, r1820, r1821, r1822, r1823, r1824, r1825, r1826, r1827, r1828, r1829, r1830, r1831, r1832, r1833, r1834, r1835, r1836, r1837, r1838, r1839, r1840, r1841, r1842, r1843, r1844, r1845, r1846 };
    unsigned douts21[72];
    sub_words[1520u * row_count + row] = r21;
    sub_words[1521u * row_count + row] = r1777;
    sub_words[1522u * row_count + row] = r1778;
    sub_words[1523u * row_count + row] = r1779;
    sub_words[1524u * row_count + row] = r1780;
    sub_words[1525u * row_count + row] = r1781;
    sub_words[1526u * row_count + row] = r1782;
    sub_words[1527u * row_count + row] = r1783;
    sub_words[1528u * row_count + row] = r1784;
    sub_words[1529u * row_count + row] = r1785;
    sub_words[1530u * row_count + row] = r1786;
    sub_words[1531u * row_count + row] = r1787;
    sub_words[1532u * row_count + row] = r1788;
    sub_words[1533u * row_count + row] = r1789;
    sub_words[1534u * row_count + row] = r1790;
    sub_words[1535u * row_count + row] = r1791;
    sub_words[1536u * row_count + row] = r1792;
    sub_words[1537u * row_count + row] = r1793;
    sub_words[1538u * row_count + row] = r1794;
    sub_words[1539u * row_count + row] = r1795;
    sub_words[1540u * row_count + row] = r1796;
    sub_words[1541u * row_count + row] = r1797;
    sub_words[1542u * row_count + row] = r1798;
    sub_words[1543u * row_count + row] = r1799;
    sub_words[1544u * row_count + row] = r1800;
    sub_words[1545u * row_count + row] = r1801;
    sub_words[1546u * row_count + row] = r1802;
    sub_words[1547u * row_count + row] = r1803;
    sub_words[1548u * row_count + row] = r1804;
    sub_words[1549u * row_count + row] = r1805;
    sub_words[1550u * row_count + row] = r1806;
    sub_words[1551u * row_count + row] = r1807;
    sub_words[1552u * row_count + row] = r1808;
    sub_words[1553u * row_count + row] = r1809;
    sub_words[1554u * row_count + row] = r1810;
    sub_words[1555u * row_count + row] = r1811;
    sub_words[1556u * row_count + row] = r1812;
    sub_words[1557u * row_count + row] = r1813;
    sub_words[1558u * row_count + row] = r1814;
    sub_words[1559u * row_count + row] = r1815;
    sub_words[1560u * row_count + row] = r1816;
    sub_words[1561u * row_count + row] = r1817;
    sub_words[1562u * row_count + row] = r1818;
    sub_words[1563u * row_count + row] = r1819;
    sub_words[1564u * row_count + row] = r1820;
    sub_words[1565u * row_count + row] = r1821;
    sub_words[1566u * row_count + row] = r1822;
    sub_words[1567u * row_count + row] = r1823;
    sub_words[1568u * row_count + row] = r1824;
    sub_words[1569u * row_count + row] = r1825;
    sub_words[1570u * row_count + row] = r1826;
    sub_words[1571u * row_count + row] = r1827;
    sub_words[1572u * row_count + row] = r1828;
    sub_words[1573u * row_count + row] = r1829;
    sub_words[1574u * row_count + row] = r1830;
    sub_words[1575u * row_count + row] = r1831;
    sub_words[1576u * row_count + row] = r1832;
    sub_words[1577u * row_count + row] = r1833;
    sub_words[1578u * row_count + row] = r1834;
    sub_words[1579u * row_count + row] = r1835;
    sub_words[1580u * row_count + row] = r1836;
    sub_words[1581u * row_count + row] = r1837;
    sub_words[1582u * row_count + row] = r1838;
    sub_words[1583u * row_count + row] = r1839;
    sub_words[1584u * row_count + row] = r1840;
    sub_words[1585u * row_count + row] = r1841;
    sub_words[1586u * row_count + row] = r1842;
    sub_words[1587u * row_count + row] = r1843;
    sub_words[1588u * row_count + row] = r1844;
    sub_words[1589u * row_count + row] = r1845;
    sub_words[1590u * row_count + row] = r1846;
    stwo_wit_deduce_partial_ec_mul_w18(dargs21, douts21);
    unsigned r1847 = douts21[0];
    unsigned r1848 = douts21[1];
    unsigned r1849 = douts21[2];
    unsigned r1850 = douts21[3];
    unsigned r1851 = douts21[4];
    unsigned r1852 = douts21[5];
    unsigned r1853 = douts21[6];
    unsigned r1854 = douts21[7];
    unsigned r1855 = douts21[8];
    unsigned r1856 = douts21[9];
    unsigned r1857 = douts21[10];
    unsigned r1858 = douts21[11];
    unsigned r1859 = douts21[12];
    unsigned r1860 = douts21[13];
    unsigned r1861 = douts21[14];
    unsigned r1862 = douts21[15];
    unsigned r1863 = douts21[16];
    unsigned r1864 = douts21[17];
    unsigned r1865 = douts21[18];
    unsigned r1866 = douts21[19];
    unsigned r1867 = douts21[20];
    unsigned r1868 = douts21[21];
    unsigned r1869 = douts21[22];
    unsigned r1870 = douts21[23];
    unsigned r1871 = douts21[24];
    unsigned r1872 = douts21[25];
    unsigned r1873 = douts21[26];
    unsigned r1874 = douts21[27];
    unsigned r1875 = douts21[28];
    unsigned r1876 = douts21[29];
    unsigned r1877 = douts21[30];
    unsigned r1878 = douts21[31];
    unsigned r1879 = douts21[32];
    unsigned r1880 = douts21[33];
    unsigned r1881 = douts21[34];
    unsigned r1882 = douts21[35];
    unsigned r1883 = douts21[36];
    unsigned r1884 = douts21[37];
    unsigned r1885 = douts21[38];
    unsigned r1886 = douts21[39];
    unsigned r1887 = douts21[40];
    unsigned r1888 = douts21[41];
    unsigned r1889 = douts21[42];
    unsigned r1890 = douts21[43];
    unsigned r1891 = douts21[44];
    unsigned r1892 = douts21[45];
    unsigned r1893 = douts21[46];
    unsigned r1894 = douts21[47];
    unsigned r1895 = douts21[48];
    unsigned r1896 = douts21[49];
    unsigned r1897 = douts21[50];
    unsigned r1898 = douts21[51];
    unsigned r1899 = douts21[52];
    unsigned r1900 = douts21[53];
    unsigned r1901 = douts21[54];
    unsigned r1902 = douts21[55];
    unsigned r1903 = douts21[56];
    unsigned r1904 = douts21[57];
    unsigned r1905 = douts21[58];
    unsigned r1906 = douts21[59];
    unsigned r1907 = douts21[60];
    unsigned r1908 = douts21[61];
    unsigned r1909 = douts21[62];
    unsigned r1910 = douts21[63];
    unsigned r1911 = douts21[64];
    unsigned r1912 = douts21[65];
    unsigned r1913 = douts21[66];
    unsigned r1914 = douts21[67];
    unsigned r1915 = douts21[68];
    unsigned r1916 = douts21[69];
    unsigned r1917 = douts21[70];
    unsigned r1918 = douts21[71];
    const unsigned dargs22[72] = { r1258, r22, r1849, r1850, r1851, r1852, r1853, r1854, r1855, r1856, r1857, r1858, r1859, r1860, r1861, r1862, r1863, r1864, r1865, r1866, r1867, r1868, r1869, r1870, r1871, r1872, r1873, r1874, r1875, r1876, r1877, r1878, r1879, r1880, r1881, r1882, r1883, r1884, r1885, r1886, r1887, r1888, r1889, r1890, r1891, r1892, r1893, r1894, r1895, r1896, r1897, r1898, r1899, r1900, r1901, r1902, r1903, r1904, r1905, r1906, r1907, r1908, r1909, r1910, r1911, r1912, r1913, r1914, r1915, r1916, r1917, r1918 };
    unsigned douts22[72];
    lookup_words[110u * row_count + row] = r22;
    sub_words[48u * row_count + row] = r22;
    sub_words[1592u * row_count + row] = r22;
    sub_words[1593u * row_count + row] = r1849;
    sub_words[1594u * row_count + row] = r1850;
    sub_words[1595u * row_count + row] = r1851;
    sub_words[1596u * row_count + row] = r1852;
    sub_words[1597u * row_count + row] = r1853;
    sub_words[1598u * row_count + row] = r1854;
    sub_words[1599u * row_count + row] = r1855;
    sub_words[1600u * row_count + row] = r1856;
    sub_words[1601u * row_count + row] = r1857;
    sub_words[1602u * row_count + row] = r1858;
    sub_words[1603u * row_count + row] = r1859;
    sub_words[1604u * row_count + row] = r1860;
    sub_words[1605u * row_count + row] = r1861;
    sub_words[1606u * row_count + row] = r1862;
    sub_words[1607u * row_count + row] = r1863;
    sub_words[1608u * row_count + row] = r1864;
    sub_words[1609u * row_count + row] = r1865;
    sub_words[1610u * row_count + row] = r1866;
    sub_words[1611u * row_count + row] = r1867;
    sub_words[1612u * row_count + row] = r1868;
    sub_words[1613u * row_count + row] = r1869;
    sub_words[1614u * row_count + row] = r1870;
    sub_words[1615u * row_count + row] = r1871;
    sub_words[1616u * row_count + row] = r1872;
    sub_words[1617u * row_count + row] = r1873;
    sub_words[1618u * row_count + row] = r1874;
    sub_words[1619u * row_count + row] = r1875;
    sub_words[1620u * row_count + row] = r1876;
    sub_words[1621u * row_count + row] = r1877;
    sub_words[1622u * row_count + row] = r1878;
    sub_words[1623u * row_count + row] = r1879;
    sub_words[1624u * row_count + row] = r1880;
    sub_words[1625u * row_count + row] = r1881;
    sub_words[1626u * row_count + row] = r1882;
    sub_words[1627u * row_count + row] = r1883;
    sub_words[1628u * row_count + row] = r1884;
    sub_words[1629u * row_count + row] = r1885;
    sub_words[1630u * row_count + row] = r1886;
    sub_words[1631u * row_count + row] = r1887;
    sub_words[1632u * row_count + row] = r1888;
    sub_words[1633u * row_count + row] = r1889;
    sub_words[1634u * row_count + row] = r1890;
    sub_words[1635u * row_count + row] = r1891;
    sub_words[1636u * row_count + row] = r1892;
    sub_words[1637u * row_count + row] = r1893;
    sub_words[1638u * row_count + row] = r1894;
    sub_words[1639u * row_count + row] = r1895;
    sub_words[1640u * row_count + row] = r1896;
    sub_words[1641u * row_count + row] = r1897;
    sub_words[1642u * row_count + row] = r1898;
    sub_words[1643u * row_count + row] = r1899;
    sub_words[1644u * row_count + row] = r1900;
    sub_words[1645u * row_count + row] = r1901;
    sub_words[1646u * row_count + row] = r1902;
    sub_words[1647u * row_count + row] = r1903;
    sub_words[1648u * row_count + row] = r1904;
    sub_words[1649u * row_count + row] = r1905;
    sub_words[1650u * row_count + row] = r1906;
    sub_words[1651u * row_count + row] = r1907;
    sub_words[1652u * row_count + row] = r1908;
    sub_words[1653u * row_count + row] = r1909;
    sub_words[1654u * row_count + row] = r1910;
    sub_words[1655u * row_count + row] = r1911;
    sub_words[1656u * row_count + row] = r1912;
    sub_words[1657u * row_count + row] = r1913;
    sub_words[1658u * row_count + row] = r1914;
    sub_words[1659u * row_count + row] = r1915;
    sub_words[1660u * row_count + row] = r1916;
    sub_words[1661u * row_count + row] = r1917;
    sub_words[1662u * row_count + row] = r1918;
    stwo_wit_deduce_partial_ec_mul_w18(dargs22, douts22);
    unsigned r1919 = douts22[0];
    unsigned r1920 = douts22[1];
    unsigned r1921 = douts22[2];
    unsigned r1922 = douts22[3];
    unsigned r1923 = douts22[4];
    unsigned r1924 = douts22[5];
    unsigned r1925 = douts22[6];
    unsigned r1926 = douts22[7];
    unsigned r1927 = douts22[8];
    unsigned r1928 = douts22[9];
    unsigned r1929 = douts22[10];
    unsigned r1930 = douts22[11];
    unsigned r1931 = douts22[12];
    unsigned r1932 = douts22[13];
    unsigned r1933 = douts22[14];
    unsigned r1934 = douts22[15];
    unsigned r1935 = douts22[16];
    unsigned r1936 = douts22[17];
    unsigned r1937 = douts22[18];
    unsigned r1938 = douts22[19];
    unsigned r1939 = douts22[20];
    unsigned r1940 = douts22[21];
    unsigned r1941 = douts22[22];
    unsigned r1942 = douts22[23];
    unsigned r1943 = douts22[24];
    unsigned r1944 = douts22[25];
    unsigned r1945 = douts22[26];
    unsigned r1946 = douts22[27];
    unsigned r1947 = douts22[28];
    unsigned r1948 = douts22[29];
    unsigned r1949 = douts22[30];
    unsigned r1950 = douts22[31];
    unsigned r1951 = douts22[32];
    unsigned r1952 = douts22[33];
    unsigned r1953 = douts22[34];
    unsigned r1954 = douts22[35];
    unsigned r1955 = douts22[36];
    unsigned r1956 = douts22[37];
    unsigned r1957 = douts22[38];
    unsigned r1958 = douts22[39];
    unsigned r1959 = douts22[40];
    unsigned r1960 = douts22[41];
    unsigned r1961 = douts22[42];
    unsigned r1962 = douts22[43];
    unsigned r1963 = douts22[44];
    unsigned r1964 = douts22[45];
    unsigned r1965 = douts22[46];
    unsigned r1966 = douts22[47];
    unsigned r1967 = douts22[48];
    unsigned r1968 = douts22[49];
    unsigned r1969 = douts22[50];
    unsigned r1970 = douts22[51];
    unsigned r1971 = douts22[52];
    unsigned r1972 = douts22[53];
    unsigned r1973 = douts22[54];
    unsigned r1974 = douts22[55];
    unsigned r1975 = douts22[56];
    unsigned r1976 = douts22[57];
    unsigned r1977 = douts22[58];
    unsigned r1978 = douts22[59];
    unsigned r1979 = douts22[60];
    unsigned r1980 = douts22[61];
    unsigned r1981 = douts22[62];
    unsigned r1982 = douts22[63];
    unsigned r1983 = douts22[64];
    unsigned r1984 = douts22[65];
    unsigned r1985 = douts22[66];
    unsigned r1986 = douts22[67];
    unsigned r1987 = douts22[68];
    unsigned r1988 = douts22[69];
    unsigned r1989 = douts22[70];
    unsigned r1990 = douts22[71];
    const unsigned dargs23[72] = { r1258, r23, r1921, r1922, r1923, r1924, r1925, r1926, r1927, r1928, r1929, r1930, r1931, r1932, r1933, r1934, r1935, r1936, r1937, r1938, r1939, r1940, r1941, r1942, r1943, r1944, r1945, r1946, r1947, r1948, r1949, r1950, r1951, r1952, r1953, r1954, r1955, r1956, r1957, r1958, r1959, r1960, r1961, r1962, r1963, r1964, r1965, r1966, r1967, r1968, r1969, r1970, r1971, r1972, r1973, r1974, r1975, r1976, r1977, r1978, r1979, r1980, r1981, r1982, r1983, r1984, r1985, r1986, r1987, r1988, r1989, r1990 };
    unsigned douts23[72];
    sub_words[1664u * row_count + row] = r23;
    sub_words[1665u * row_count + row] = r1921;
    sub_words[1666u * row_count + row] = r1922;
    sub_words[1667u * row_count + row] = r1923;
    sub_words[1668u * row_count + row] = r1924;
    sub_words[1669u * row_count + row] = r1925;
    sub_words[1670u * row_count + row] = r1926;
    sub_words[1671u * row_count + row] = r1927;
    sub_words[1672u * row_count + row] = r1928;
    sub_words[1673u * row_count + row] = r1929;
    sub_words[1674u * row_count + row] = r1930;
    sub_words[1675u * row_count + row] = r1931;
    sub_words[1676u * row_count + row] = r1932;
    sub_words[1677u * row_count + row] = r1933;
    sub_words[1678u * row_count + row] = r1934;
    sub_words[1679u * row_count + row] = r1935;
    sub_words[1680u * row_count + row] = r1936;
    sub_words[1681u * row_count + row] = r1937;
    sub_words[1682u * row_count + row] = r1938;
    sub_words[1683u * row_count + row] = r1939;
    sub_words[1684u * row_count + row] = r1940;
    sub_words[1685u * row_count + row] = r1941;
    sub_words[1686u * row_count + row] = r1942;
    sub_words[1687u * row_count + row] = r1943;
    sub_words[1688u * row_count + row] = r1944;
    sub_words[1689u * row_count + row] = r1945;
    sub_words[1690u * row_count + row] = r1946;
    sub_words[1691u * row_count + row] = r1947;
    sub_words[1692u * row_count + row] = r1948;
    sub_words[1693u * row_count + row] = r1949;
    sub_words[1694u * row_count + row] = r1950;
    sub_words[1695u * row_count + row] = r1951;
    sub_words[1696u * row_count + row] = r1952;
    sub_words[1697u * row_count + row] = r1953;
    sub_words[1698u * row_count + row] = r1954;
    sub_words[1699u * row_count + row] = r1955;
    sub_words[1700u * row_count + row] = r1956;
    sub_words[1701u * row_count + row] = r1957;
    sub_words[1702u * row_count + row] = r1958;
    sub_words[1703u * row_count + row] = r1959;
    sub_words[1704u * row_count + row] = r1960;
    sub_words[1705u * row_count + row] = r1961;
    sub_words[1706u * row_count + row] = r1962;
    sub_words[1707u * row_count + row] = r1963;
    sub_words[1708u * row_count + row] = r1964;
    sub_words[1709u * row_count + row] = r1965;
    sub_words[1710u * row_count + row] = r1966;
    sub_words[1711u * row_count + row] = r1967;
    sub_words[1712u * row_count + row] = r1968;
    sub_words[1713u * row_count + row] = r1969;
    sub_words[1714u * row_count + row] = r1970;
    sub_words[1715u * row_count + row] = r1971;
    sub_words[1716u * row_count + row] = r1972;
    sub_words[1717u * row_count + row] = r1973;
    sub_words[1718u * row_count + row] = r1974;
    sub_words[1719u * row_count + row] = r1975;
    sub_words[1720u * row_count + row] = r1976;
    sub_words[1721u * row_count + row] = r1977;
    sub_words[1722u * row_count + row] = r1978;
    sub_words[1723u * row_count + row] = r1979;
    sub_words[1724u * row_count + row] = r1980;
    sub_words[1725u * row_count + row] = r1981;
    sub_words[1726u * row_count + row] = r1982;
    sub_words[1727u * row_count + row] = r1983;
    sub_words[1728u * row_count + row] = r1984;
    sub_words[1729u * row_count + row] = r1985;
    sub_words[1730u * row_count + row] = r1986;
    sub_words[1731u * row_count + row] = r1987;
    sub_words[1732u * row_count + row] = r1988;
    sub_words[1733u * row_count + row] = r1989;
    sub_words[1734u * row_count + row] = r1990;
    stwo_wit_deduce_partial_ec_mul_w18(dargs23, douts23);
    unsigned r1991 = douts23[0];
    unsigned r1992 = douts23[1];
    unsigned r1993 = douts23[2];
    unsigned r1994 = douts23[3];
    unsigned r1995 = douts23[4];
    unsigned r1996 = douts23[5];
    unsigned r1997 = douts23[6];
    unsigned r1998 = douts23[7];
    unsigned r1999 = douts23[8];
    unsigned r2000 = douts23[9];
    unsigned r2001 = douts23[10];
    unsigned r2002 = douts23[11];
    unsigned r2003 = douts23[12];
    unsigned r2004 = douts23[13];
    unsigned r2005 = douts23[14];
    unsigned r2006 = douts23[15];
    unsigned r2007 = douts23[16];
    unsigned r2008 = douts23[17];
    unsigned r2009 = douts23[18];
    unsigned r2010 = douts23[19];
    unsigned r2011 = douts23[20];
    unsigned r2012 = douts23[21];
    unsigned r2013 = douts23[22];
    unsigned r2014 = douts23[23];
    unsigned r2015 = douts23[24];
    unsigned r2016 = douts23[25];
    unsigned r2017 = douts23[26];
    unsigned r2018 = douts23[27];
    unsigned r2019 = douts23[28];
    unsigned r2020 = douts23[29];
    unsigned r2021 = douts23[30];
    unsigned r2022 = douts23[31];
    unsigned r2023 = douts23[32];
    unsigned r2024 = douts23[33];
    unsigned r2025 = douts23[34];
    unsigned r2026 = douts23[35];
    unsigned r2027 = douts23[36];
    unsigned r2028 = douts23[37];
    unsigned r2029 = douts23[38];
    unsigned r2030 = douts23[39];
    unsigned r2031 = douts23[40];
    unsigned r2032 = douts23[41];
    unsigned r2033 = douts23[42];
    unsigned r2034 = douts23[43];
    unsigned r2035 = douts23[44];
    unsigned r2036 = douts23[45];
    unsigned r2037 = douts23[46];
    unsigned r2038 = douts23[47];
    unsigned r2039 = douts23[48];
    unsigned r2040 = douts23[49];
    unsigned r2041 = douts23[50];
    unsigned r2042 = douts23[51];
    unsigned r2043 = douts23[52];
    unsigned r2044 = douts23[53];
    unsigned r2045 = douts23[54];
    unsigned r2046 = douts23[55];
    unsigned r2047 = douts23[56];
    unsigned r2048 = douts23[57];
    unsigned r2049 = douts23[58];
    unsigned r2050 = douts23[59];
    unsigned r2051 = douts23[60];
    unsigned r2052 = douts23[61];
    unsigned r2053 = douts23[62];
    unsigned r2054 = douts23[63];
    unsigned r2055 = douts23[64];
    unsigned r2056 = douts23[65];
    unsigned r2057 = douts23[66];
    unsigned r2058 = douts23[67];
    unsigned r2059 = douts23[68];
    unsigned r2060 = douts23[69];
    unsigned r2061 = douts23[70];
    unsigned r2062 = douts23[71];
    const unsigned dargs24[72] = { r1258, r24, r1993, r1994, r1995, r1996, r1997, r1998, r1999, r2000, r2001, r2002, r2003, r2004, r2005, r2006, r2007, r2008, r2009, r2010, r2011, r2012, r2013, r2014, r2015, r2016, r2017, r2018, r2019, r2020, r2021, r2022, r2023, r2024, r2025, r2026, r2027, r2028, r2029, r2030, r2031, r2032, r2033, r2034, r2035, r2036, r2037, r2038, r2039, r2040, r2041, r2042, r2043, r2044, r2045, r2046, r2047, r2048, r2049, r2050, r2051, r2052, r2053, r2054, r2055, r2056, r2057, r2058, r2059, r2060, r2061, r2062 };
    unsigned douts24[72];
    sub_words[1736u * row_count + row] = r24;
    sub_words[1737u * row_count + row] = r1993;
    sub_words[1738u * row_count + row] = r1994;
    sub_words[1739u * row_count + row] = r1995;
    sub_words[1740u * row_count + row] = r1996;
    sub_words[1741u * row_count + row] = r1997;
    sub_words[1742u * row_count + row] = r1998;
    sub_words[1743u * row_count + row] = r1999;
    sub_words[1744u * row_count + row] = r2000;
    sub_words[1745u * row_count + row] = r2001;
    sub_words[1746u * row_count + row] = r2002;
    sub_words[1747u * row_count + row] = r2003;
    sub_words[1748u * row_count + row] = r2004;
    sub_words[1749u * row_count + row] = r2005;
    sub_words[1750u * row_count + row] = r2006;
    sub_words[1751u * row_count + row] = r2007;
    sub_words[1752u * row_count + row] = r2008;
    sub_words[1753u * row_count + row] = r2009;
    sub_words[1754u * row_count + row] = r2010;
    sub_words[1755u * row_count + row] = r2011;
    sub_words[1756u * row_count + row] = r2012;
    sub_words[1757u * row_count + row] = r2013;
    sub_words[1758u * row_count + row] = r2014;
    sub_words[1759u * row_count + row] = r2015;
    sub_words[1760u * row_count + row] = r2016;
    sub_words[1761u * row_count + row] = r2017;
    sub_words[1762u * row_count + row] = r2018;
    sub_words[1763u * row_count + row] = r2019;
    sub_words[1764u * row_count + row] = r2020;
    sub_words[1765u * row_count + row] = r2021;
    sub_words[1766u * row_count + row] = r2022;
    sub_words[1767u * row_count + row] = r2023;
    sub_words[1768u * row_count + row] = r2024;
    sub_words[1769u * row_count + row] = r2025;
    sub_words[1770u * row_count + row] = r2026;
    sub_words[1771u * row_count + row] = r2027;
    sub_words[1772u * row_count + row] = r2028;
    sub_words[1773u * row_count + row] = r2029;
    sub_words[1774u * row_count + row] = r2030;
    sub_words[1775u * row_count + row] = r2031;
    sub_words[1776u * row_count + row] = r2032;
    sub_words[1777u * row_count + row] = r2033;
    sub_words[1778u * row_count + row] = r2034;
    sub_words[1779u * row_count + row] = r2035;
    sub_words[1780u * row_count + row] = r2036;
    sub_words[1781u * row_count + row] = r2037;
    sub_words[1782u * row_count + row] = r2038;
    sub_words[1783u * row_count + row] = r2039;
    sub_words[1784u * row_count + row] = r2040;
    sub_words[1785u * row_count + row] = r2041;
    sub_words[1786u * row_count + row] = r2042;
    sub_words[1787u * row_count + row] = r2043;
    sub_words[1788u * row_count + row] = r2044;
    sub_words[1789u * row_count + row] = r2045;
    sub_words[1790u * row_count + row] = r2046;
    sub_words[1791u * row_count + row] = r2047;
    sub_words[1792u * row_count + row] = r2048;
    sub_words[1793u * row_count + row] = r2049;
    sub_words[1794u * row_count + row] = r2050;
    sub_words[1795u * row_count + row] = r2051;
    sub_words[1796u * row_count + row] = r2052;
    sub_words[1797u * row_count + row] = r2053;
    sub_words[1798u * row_count + row] = r2054;
    sub_words[1799u * row_count + row] = r2055;
    sub_words[1800u * row_count + row] = r2056;
    sub_words[1801u * row_count + row] = r2057;
    sub_words[1802u * row_count + row] = r2058;
    sub_words[1803u * row_count + row] = r2059;
    sub_words[1804u * row_count + row] = r2060;
    sub_words[1805u * row_count + row] = r2061;
    sub_words[1806u * row_count + row] = r2062;
    stwo_wit_deduce_partial_ec_mul_w18(dargs24, douts24);
    unsigned r2063 = douts24[0];
    unsigned r2064 = douts24[1];
    unsigned r2065 = douts24[2];
    unsigned r2066 = douts24[3];
    unsigned r2067 = douts24[4];
    unsigned r2068 = douts24[5];
    unsigned r2069 = douts24[6];
    unsigned r2070 = douts24[7];
    unsigned r2071 = douts24[8];
    unsigned r2072 = douts24[9];
    unsigned r2073 = douts24[10];
    unsigned r2074 = douts24[11];
    unsigned r2075 = douts24[12];
    unsigned r2076 = douts24[13];
    unsigned r2077 = douts24[14];
    unsigned r2078 = douts24[15];
    unsigned r2079 = douts24[16];
    unsigned r2080 = douts24[17];
    unsigned r2081 = douts24[18];
    unsigned r2082 = douts24[19];
    unsigned r2083 = douts24[20];
    unsigned r2084 = douts24[21];
    unsigned r2085 = douts24[22];
    unsigned r2086 = douts24[23];
    unsigned r2087 = douts24[24];
    unsigned r2088 = douts24[25];
    unsigned r2089 = douts24[26];
    unsigned r2090 = douts24[27];
    unsigned r2091 = douts24[28];
    unsigned r2092 = douts24[29];
    unsigned r2093 = douts24[30];
    unsigned r2094 = douts24[31];
    unsigned r2095 = douts24[32];
    unsigned r2096 = douts24[33];
    unsigned r2097 = douts24[34];
    unsigned r2098 = douts24[35];
    unsigned r2099 = douts24[36];
    unsigned r2100 = douts24[37];
    unsigned r2101 = douts24[38];
    unsigned r2102 = douts24[39];
    unsigned r2103 = douts24[40];
    unsigned r2104 = douts24[41];
    unsigned r2105 = douts24[42];
    unsigned r2106 = douts24[43];
    unsigned r2107 = douts24[44];
    unsigned r2108 = douts24[45];
    unsigned r2109 = douts24[46];
    unsigned r2110 = douts24[47];
    unsigned r2111 = douts24[48];
    unsigned r2112 = douts24[49];
    unsigned r2113 = douts24[50];
    unsigned r2114 = douts24[51];
    unsigned r2115 = douts24[52];
    unsigned r2116 = douts24[53];
    unsigned r2117 = douts24[54];
    unsigned r2118 = douts24[55];
    unsigned r2119 = douts24[56];
    unsigned r2120 = douts24[57];
    unsigned r2121 = douts24[58];
    unsigned r2122 = douts24[59];
    unsigned r2123 = douts24[60];
    unsigned r2124 = douts24[61];
    unsigned r2125 = douts24[62];
    unsigned r2126 = douts24[63];
    unsigned r2127 = douts24[64];
    unsigned r2128 = douts24[65];
    unsigned r2129 = douts24[66];
    unsigned r2130 = douts24[67];
    unsigned r2131 = douts24[68];
    unsigned r2132 = douts24[69];
    unsigned r2133 = douts24[70];
    unsigned r2134 = douts24[71];
    const unsigned dargs25[72] = { r1258, r25, r2065, r2066, r2067, r2068, r2069, r2070, r2071, r2072, r2073, r2074, r2075, r2076, r2077, r2078, r2079, r2080, r2081, r2082, r2083, r2084, r2085, r2086, r2087, r2088, r2089, r2090, r2091, r2092, r2093, r2094, r2095, r2096, r2097, r2098, r2099, r2100, r2101, r2102, r2103, r2104, r2105, r2106, r2107, r2108, r2109, r2110, r2111, r2112, r2113, r2114, r2115, r2116, r2117, r2118, r2119, r2120, r2121, r2122, r2123, r2124, r2125, r2126, r2127, r2128, r2129, r2130, r2131, r2132, r2133, r2134 };
    unsigned douts25[72];
    sub_words[1808u * row_count + row] = r25;
    sub_words[1809u * row_count + row] = r2065;
    sub_words[1810u * row_count + row] = r2066;
    sub_words[1811u * row_count + row] = r2067;
    sub_words[1812u * row_count + row] = r2068;
    sub_words[1813u * row_count + row] = r2069;
    sub_words[1814u * row_count + row] = r2070;
    sub_words[1815u * row_count + row] = r2071;
    sub_words[1816u * row_count + row] = r2072;
    sub_words[1817u * row_count + row] = r2073;
    sub_words[1818u * row_count + row] = r2074;
    sub_words[1819u * row_count + row] = r2075;
    sub_words[1820u * row_count + row] = r2076;
    sub_words[1821u * row_count + row] = r2077;
    sub_words[1822u * row_count + row] = r2078;
    sub_words[1823u * row_count + row] = r2079;
    sub_words[1824u * row_count + row] = r2080;
    sub_words[1825u * row_count + row] = r2081;
    sub_words[1826u * row_count + row] = r2082;
    sub_words[1827u * row_count + row] = r2083;
    sub_words[1828u * row_count + row] = r2084;
    sub_words[1829u * row_count + row] = r2085;
    sub_words[1830u * row_count + row] = r2086;
    sub_words[1831u * row_count + row] = r2087;
    sub_words[1832u * row_count + row] = r2088;
    sub_words[1833u * row_count + row] = r2089;
    sub_words[1834u * row_count + row] = r2090;
    sub_words[1835u * row_count + row] = r2091;
    sub_words[1836u * row_count + row] = r2092;
    sub_words[1837u * row_count + row] = r2093;
    sub_words[1838u * row_count + row] = r2094;
    sub_words[1839u * row_count + row] = r2095;
    sub_words[1840u * row_count + row] = r2096;
    sub_words[1841u * row_count + row] = r2097;
    sub_words[1842u * row_count + row] = r2098;
    sub_words[1843u * row_count + row] = r2099;
    sub_words[1844u * row_count + row] = r2100;
    sub_words[1845u * row_count + row] = r2101;
    sub_words[1846u * row_count + row] = r2102;
    sub_words[1847u * row_count + row] = r2103;
    sub_words[1848u * row_count + row] = r2104;
    sub_words[1849u * row_count + row] = r2105;
    sub_words[1850u * row_count + row] = r2106;
    sub_words[1851u * row_count + row] = r2107;
    sub_words[1852u * row_count + row] = r2108;
    sub_words[1853u * row_count + row] = r2109;
    sub_words[1854u * row_count + row] = r2110;
    sub_words[1855u * row_count + row] = r2111;
    sub_words[1856u * row_count + row] = r2112;
    sub_words[1857u * row_count + row] = r2113;
    sub_words[1858u * row_count + row] = r2114;
    sub_words[1859u * row_count + row] = r2115;
    sub_words[1860u * row_count + row] = r2116;
    sub_words[1861u * row_count + row] = r2117;
    sub_words[1862u * row_count + row] = r2118;
    sub_words[1863u * row_count + row] = r2119;
    sub_words[1864u * row_count + row] = r2120;
    sub_words[1865u * row_count + row] = r2121;
    sub_words[1866u * row_count + row] = r2122;
    sub_words[1867u * row_count + row] = r2123;
    sub_words[1868u * row_count + row] = r2124;
    sub_words[1869u * row_count + row] = r2125;
    sub_words[1870u * row_count + row] = r2126;
    sub_words[1871u * row_count + row] = r2127;
    sub_words[1872u * row_count + row] = r2128;
    sub_words[1873u * row_count + row] = r2129;
    sub_words[1874u * row_count + row] = r2130;
    sub_words[1875u * row_count + row] = r2131;
    sub_words[1876u * row_count + row] = r2132;
    sub_words[1877u * row_count + row] = r2133;
    sub_words[1878u * row_count + row] = r2134;
    stwo_wit_deduce_partial_ec_mul_w18(dargs25, douts25);
    unsigned r2135 = douts25[0];
    unsigned r2136 = douts25[1];
    unsigned r2137 = douts25[2];
    unsigned r2138 = douts25[3];
    unsigned r2139 = douts25[4];
    unsigned r2140 = douts25[5];
    unsigned r2141 = douts25[6];
    unsigned r2142 = douts25[7];
    unsigned r2143 = douts25[8];
    unsigned r2144 = douts25[9];
    unsigned r2145 = douts25[10];
    unsigned r2146 = douts25[11];
    unsigned r2147 = douts25[12];
    unsigned r2148 = douts25[13];
    unsigned r2149 = douts25[14];
    unsigned r2150 = douts25[15];
    unsigned r2151 = douts25[16];
    unsigned r2152 = douts25[17];
    unsigned r2153 = douts25[18];
    unsigned r2154 = douts25[19];
    unsigned r2155 = douts25[20];
    unsigned r2156 = douts25[21];
    unsigned r2157 = douts25[22];
    unsigned r2158 = douts25[23];
    unsigned r2159 = douts25[24];
    unsigned r2160 = douts25[25];
    unsigned r2161 = douts25[26];
    unsigned r2162 = douts25[27];
    unsigned r2163 = douts25[28];
    unsigned r2164 = douts25[29];
    unsigned r2165 = douts25[30];
    unsigned r2166 = douts25[31];
    unsigned r2167 = douts25[32];
    unsigned r2168 = douts25[33];
    unsigned r2169 = douts25[34];
    unsigned r2170 = douts25[35];
    unsigned r2171 = douts25[36];
    unsigned r2172 = douts25[37];
    unsigned r2173 = douts25[38];
    unsigned r2174 = douts25[39];
    unsigned r2175 = douts25[40];
    unsigned r2176 = douts25[41];
    unsigned r2177 = douts25[42];
    unsigned r2178 = douts25[43];
    unsigned r2179 = douts25[44];
    unsigned r2180 = douts25[45];
    unsigned r2181 = douts25[46];
    unsigned r2182 = douts25[47];
    unsigned r2183 = douts25[48];
    unsigned r2184 = douts25[49];
    unsigned r2185 = douts25[50];
    unsigned r2186 = douts25[51];
    unsigned r2187 = douts25[52];
    unsigned r2188 = douts25[53];
    unsigned r2189 = douts25[54];
    unsigned r2190 = douts25[55];
    unsigned r2191 = douts25[56];
    unsigned r2192 = douts25[57];
    unsigned r2193 = douts25[58];
    unsigned r2194 = douts25[59];
    unsigned r2195 = douts25[60];
    unsigned r2196 = douts25[61];
    unsigned r2197 = douts25[62];
    unsigned r2198 = douts25[63];
    unsigned r2199 = douts25[64];
    unsigned r2200 = douts25[65];
    unsigned r2201 = douts25[66];
    unsigned r2202 = douts25[67];
    unsigned r2203 = douts25[68];
    unsigned r2204 = douts25[69];
    unsigned r2205 = douts25[70];
    unsigned r2206 = douts25[71];
    const unsigned dargs26[72] = { r1258, r26, r2137, r2138, r2139, r2140, r2141, r2142, r2143, r2144, r2145, r2146, r2147, r2148, r2149, r2150, r2151, r2152, r2153, r2154, r2155, r2156, r2157, r2158, r2159, r2160, r2161, r2162, r2163, r2164, r2165, r2166, r2167, r2168, r2169, r2170, r2171, r2172, r2173, r2174, r2175, r2176, r2177, r2178, r2179, r2180, r2181, r2182, r2183, r2184, r2185, r2186, r2187, r2188, r2189, r2190, r2191, r2192, r2193, r2194, r2195, r2196, r2197, r2198, r2199, r2200, r2201, r2202, r2203, r2204, r2205, r2206 };
    unsigned douts26[72];
    lookup_words[109u * row_count + row] = r26;
    sub_words[47u * row_count + row] = r26;
    sub_words[1880u * row_count + row] = r26;
    sub_words[1881u * row_count + row] = r2137;
    sub_words[1882u * row_count + row] = r2138;
    sub_words[1883u * row_count + row] = r2139;
    sub_words[1884u * row_count + row] = r2140;
    sub_words[1885u * row_count + row] = r2141;
    sub_words[1886u * row_count + row] = r2142;
    sub_words[1887u * row_count + row] = r2143;
    sub_words[1888u * row_count + row] = r2144;
    sub_words[1889u * row_count + row] = r2145;
    sub_words[1890u * row_count + row] = r2146;
    sub_words[1891u * row_count + row] = r2147;
    sub_words[1892u * row_count + row] = r2148;
    sub_words[1893u * row_count + row] = r2149;
    sub_words[1894u * row_count + row] = r2150;
    sub_words[1895u * row_count + row] = r2151;
    sub_words[1896u * row_count + row] = r2152;
    sub_words[1897u * row_count + row] = r2153;
    sub_words[1898u * row_count + row] = r2154;
    sub_words[1899u * row_count + row] = r2155;
    sub_words[1900u * row_count + row] = r2156;
    sub_words[1901u * row_count + row] = r2157;
    sub_words[1902u * row_count + row] = r2158;
    sub_words[1903u * row_count + row] = r2159;
    sub_words[1904u * row_count + row] = r2160;
    sub_words[1905u * row_count + row] = r2161;
    sub_words[1906u * row_count + row] = r2162;
    sub_words[1907u * row_count + row] = r2163;
    sub_words[1908u * row_count + row] = r2164;
    sub_words[1909u * row_count + row] = r2165;
    sub_words[1910u * row_count + row] = r2166;
    sub_words[1911u * row_count + row] = r2167;
    sub_words[1912u * row_count + row] = r2168;
    sub_words[1913u * row_count + row] = r2169;
    sub_words[1914u * row_count + row] = r2170;
    sub_words[1915u * row_count + row] = r2171;
    sub_words[1916u * row_count + row] = r2172;
    sub_words[1917u * row_count + row] = r2173;
    sub_words[1918u * row_count + row] = r2174;
    sub_words[1919u * row_count + row] = r2175;
    sub_words[1920u * row_count + row] = r2176;
    sub_words[1921u * row_count + row] = r2177;
    sub_words[1922u * row_count + row] = r2178;
    sub_words[1923u * row_count + row] = r2179;
    sub_words[1924u * row_count + row] = r2180;
    sub_words[1925u * row_count + row] = r2181;
    sub_words[1926u * row_count + row] = r2182;
    sub_words[1927u * row_count + row] = r2183;
    sub_words[1928u * row_count + row] = r2184;
    sub_words[1929u * row_count + row] = r2185;
    sub_words[1930u * row_count + row] = r2186;
    sub_words[1931u * row_count + row] = r2187;
    sub_words[1932u * row_count + row] = r2188;
    sub_words[1933u * row_count + row] = r2189;
    sub_words[1934u * row_count + row] = r2190;
    sub_words[1935u * row_count + row] = r2191;
    sub_words[1936u * row_count + row] = r2192;
    sub_words[1937u * row_count + row] = r2193;
    sub_words[1938u * row_count + row] = r2194;
    sub_words[1939u * row_count + row] = r2195;
    sub_words[1940u * row_count + row] = r2196;
    sub_words[1941u * row_count + row] = r2197;
    sub_words[1942u * row_count + row] = r2198;
    sub_words[1943u * row_count + row] = r2199;
    sub_words[1944u * row_count + row] = r2200;
    sub_words[1945u * row_count + row] = r2201;
    sub_words[1946u * row_count + row] = r2202;
    sub_words[1947u * row_count + row] = r2203;
    sub_words[1948u * row_count + row] = r2204;
    sub_words[1949u * row_count + row] = r2205;
    sub_words[1950u * row_count + row] = r2206;
    stwo_wit_deduce_partial_ec_mul_w18(dargs26, douts26);
    unsigned r2207 = douts26[0];
    unsigned r2208 = douts26[1];
    unsigned r2209 = douts26[2];
    unsigned r2210 = douts26[3];
    unsigned r2211 = douts26[4];
    unsigned r2212 = douts26[5];
    unsigned r2213 = douts26[6];
    unsigned r2214 = douts26[7];
    unsigned r2215 = douts26[8];
    unsigned r2216 = douts26[9];
    unsigned r2217 = douts26[10];
    unsigned r2218 = douts26[11];
    unsigned r2219 = douts26[12];
    unsigned r2220 = douts26[13];
    unsigned r2221 = douts26[14];
    unsigned r2222 = douts26[15];
    unsigned r2223 = douts26[16];
    unsigned r2224 = douts26[17];
    unsigned r2225 = douts26[18];
    unsigned r2226 = douts26[19];
    unsigned r2227 = douts26[20];
    unsigned r2228 = douts26[21];
    unsigned r2229 = douts26[22];
    unsigned r2230 = douts26[23];
    unsigned r2231 = douts26[24];
    unsigned r2232 = douts26[25];
    unsigned r2233 = douts26[26];
    unsigned r2234 = douts26[27];
    unsigned r2235 = douts26[28];
    unsigned r2236 = douts26[29];
    unsigned r2237 = douts26[30];
    unsigned r2238 = douts26[31];
    unsigned r2239 = douts26[32];
    unsigned r2240 = douts26[33];
    unsigned r2241 = douts26[34];
    unsigned r2242 = douts26[35];
    unsigned r2243 = douts26[36];
    unsigned r2244 = douts26[37];
    unsigned r2245 = douts26[38];
    unsigned r2246 = douts26[39];
    unsigned r2247 = douts26[40];
    unsigned r2248 = douts26[41];
    unsigned r2249 = douts26[42];
    unsigned r2250 = douts26[43];
    unsigned r2251 = douts26[44];
    unsigned r2252 = douts26[45];
    unsigned r2253 = douts26[46];
    unsigned r2254 = douts26[47];
    unsigned r2255 = douts26[48];
    unsigned r2256 = douts26[49];
    unsigned r2257 = douts26[50];
    unsigned r2258 = douts26[51];
    unsigned r2259 = douts26[52];
    unsigned r2260 = douts26[53];
    unsigned r2261 = douts26[54];
    unsigned r2262 = douts26[55];
    unsigned r2263 = douts26[56];
    unsigned r2264 = douts26[57];
    unsigned r2265 = douts26[58];
    unsigned r2266 = douts26[59];
    unsigned r2267 = douts26[60];
    unsigned r2268 = douts26[61];
    unsigned r2269 = douts26[62];
    unsigned r2270 = douts26[63];
    unsigned r2271 = douts26[64];
    unsigned r2272 = douts26[65];
    unsigned r2273 = douts26[66];
    unsigned r2274 = douts26[67];
    unsigned r2275 = douts26[68];
    unsigned r2276 = douts26[69];
    unsigned r2277 = douts26[70];
    unsigned r2278 = douts26[71];
    const unsigned dargs27[72] = { r1258, r27, r2209, r2210, r2211, r2212, r2213, r2214, r2215, r2216, r2217, r2218, r2219, r2220, r2221, r2222, r2223, r2224, r2225, r2226, r2227, r2228, r2229, r2230, r2231, r2232, r2233, r2234, r2235, r2236, r2237, r2238, r2239, r2240, r2241, r2242, r2243, r2244, r2245, r2246, r2247, r2248, r2249, r2250, r2251, r2252, r2253, r2254, r2255, r2256, r2257, r2258, r2259, r2260, r2261, r2262, r2263, r2264, r2265, r2266, r2267, r2268, r2269, r2270, r2271, r2272, r2273, r2274, r2275, r2276, r2277, r2278 };
    unsigned douts27[72];
    lookup_words[134u * row_count + row] = r27;
    sub_words[72u * row_count + row] = r27;
    lookup_words[215u * row_count + row] = r1258;
    sub_words[1015u * row_count + row] = r1258;
    sub_words[1087u * row_count + row] = r1258;
    sub_words[1159u * row_count + row] = r1258;
    sub_words[1231u * row_count + row] = r1258;
    sub_words[1303u * row_count + row] = r1258;
    sub_words[1375u * row_count + row] = r1258;
    sub_words[1447u * row_count + row] = r1258;
    sub_words[1519u * row_count + row] = r1258;
    sub_words[1591u * row_count + row] = r1258;
    sub_words[1663u * row_count + row] = r1258;
    sub_words[1735u * row_count + row] = r1258;
    sub_words[1807u * row_count + row] = r1258;
    sub_words[1879u * row_count + row] = r1258;
    sub_words[1951u * row_count + row] = r1258;
    sub_words[1952u * row_count + row] = r27;
    sub_words[1953u * row_count + row] = r2209;
    sub_words[1954u * row_count + row] = r2210;
    sub_words[1955u * row_count + row] = r2211;
    sub_words[1956u * row_count + row] = r2212;
    sub_words[1957u * row_count + row] = r2213;
    sub_words[1958u * row_count + row] = r2214;
    sub_words[1959u * row_count + row] = r2215;
    sub_words[1960u * row_count + row] = r2216;
    sub_words[1961u * row_count + row] = r2217;
    sub_words[1962u * row_count + row] = r2218;
    sub_words[1963u * row_count + row] = r2219;
    sub_words[1964u * row_count + row] = r2220;
    sub_words[1965u * row_count + row] = r2221;
    sub_words[1966u * row_count + row] = r2222;
    sub_words[1967u * row_count + row] = r2223;
    sub_words[1968u * row_count + row] = r2224;
    sub_words[1969u * row_count + row] = r2225;
    sub_words[1970u * row_count + row] = r2226;
    sub_words[1971u * row_count + row] = r2227;
    sub_words[1972u * row_count + row] = r2228;
    sub_words[1973u * row_count + row] = r2229;
    sub_words[1974u * row_count + row] = r2230;
    sub_words[1975u * row_count + row] = r2231;
    sub_words[1976u * row_count + row] = r2232;
    sub_words[1977u * row_count + row] = r2233;
    sub_words[1978u * row_count + row] = r2234;
    sub_words[1979u * row_count + row] = r2235;
    sub_words[1980u * row_count + row] = r2236;
    sub_words[1981u * row_count + row] = r2237;
    sub_words[1982u * row_count + row] = r2238;
    sub_words[1983u * row_count + row] = r2239;
    sub_words[1984u * row_count + row] = r2240;
    sub_words[1985u * row_count + row] = r2241;
    sub_words[1986u * row_count + row] = r2242;
    sub_words[1987u * row_count + row] = r2243;
    sub_words[1988u * row_count + row] = r2244;
    sub_words[1989u * row_count + row] = r2245;
    sub_words[1990u * row_count + row] = r2246;
    sub_words[1991u * row_count + row] = r2247;
    sub_words[1992u * row_count + row] = r2248;
    sub_words[1993u * row_count + row] = r2249;
    sub_words[1994u * row_count + row] = r2250;
    sub_words[1995u * row_count + row] = r2251;
    sub_words[1996u * row_count + row] = r2252;
    sub_words[1997u * row_count + row] = r2253;
    sub_words[1998u * row_count + row] = r2254;
    sub_words[1999u * row_count + row] = r2255;
    sub_words[2000u * row_count + row] = r2256;
    sub_words[2001u * row_count + row] = r2257;
    sub_words[2002u * row_count + row] = r2258;
    sub_words[2003u * row_count + row] = r2259;
    sub_words[2004u * row_count + row] = r2260;
    sub_words[2005u * row_count + row] = r2261;
    sub_words[2006u * row_count + row] = r2262;
    sub_words[2007u * row_count + row] = r2263;
    sub_words[2008u * row_count + row] = r2264;
    sub_words[2009u * row_count + row] = r2265;
    sub_words[2010u * row_count + row] = r2266;
    sub_words[2011u * row_count + row] = r2267;
    sub_words[2012u * row_count + row] = r2268;
    sub_words[2013u * row_count + row] = r2269;
    sub_words[2014u * row_count + row] = r2270;
    sub_words[2015u * row_count + row] = r2271;
    sub_words[2016u * row_count + row] = r2272;
    sub_words[2017u * row_count + row] = r2273;
    sub_words[2018u * row_count + row] = r2274;
    sub_words[2019u * row_count + row] = r2275;
    sub_words[2020u * row_count + row] = r2276;
    sub_words[2021u * row_count + row] = r2277;
    sub_words[2022u * row_count + row] = r2278;
    lookup_words[288u * row_count + row] = r1258;
    stwo_wit_deduce_partial_ec_mul_w18(dargs27, douts27);
    unsigned r2279 = douts27[0];
    unsigned r2280 = douts27[1];
    unsigned r2281 = douts27[2];
    out_cols[135u][row] = r2281;
    lookup_words[290u * row_count + row] = r2281;
    unsigned r2282 = douts27[3];
    out_cols[136u][row] = r2282;
    lookup_words[291u * row_count + row] = r2282;
    unsigned r2283 = douts27[4];
    out_cols[137u][row] = r2283;
    lookup_words[292u * row_count + row] = r2283;
    unsigned r2284 = douts27[5];
    out_cols[138u][row] = r2284;
    lookup_words[293u * row_count + row] = r2284;
    unsigned r2285 = douts27[6];
    out_cols[139u][row] = r2285;
    lookup_words[294u * row_count + row] = r2285;
    unsigned r2286 = douts27[7];
    out_cols[140u][row] = r2286;
    lookup_words[295u * row_count + row] = r2286;
    unsigned r2287 = douts27[8];
    out_cols[141u][row] = r2287;
    lookup_words[296u * row_count + row] = r2287;
    unsigned r2288 = douts27[9];
    out_cols[142u][row] = r2288;
    lookup_words[297u * row_count + row] = r2288;
    unsigned r2289 = douts27[10];
    out_cols[143u][row] = r2289;
    lookup_words[298u * row_count + row] = r2289;
    unsigned r2290 = douts27[11];
    out_cols[144u][row] = r2290;
    lookup_words[299u * row_count + row] = r2290;
    unsigned r2291 = douts27[12];
    out_cols[145u][row] = r2291;
    lookup_words[300u * row_count + row] = r2291;
    unsigned r2292 = douts27[13];
    out_cols[146u][row] = r2292;
    lookup_words[301u * row_count + row] = r2292;
    unsigned r2293 = douts27[14];
    out_cols[147u][row] = r2293;
    lookup_words[302u * row_count + row] = r2293;
    unsigned r2294 = douts27[15];
    out_cols[148u][row] = r2294;
    lookup_words[303u * row_count + row] = r2294;
    unsigned r2295 = douts27[16];
    out_cols[149u][row] = r2295;
    lookup_words[304u * row_count + row] = r2295;
    lookup_words[362u * row_count + row] = r2295;
    unsigned r2296 = douts27[17];
    out_cols[150u][row] = r2296;
    lookup_words[305u * row_count + row] = r2296;
    lookup_words[363u * row_count + row] = r2296;
    unsigned r2297 = douts27[18];
    out_cols[151u][row] = r2297;
    lookup_words[306u * row_count + row] = r2297;
    lookup_words[364u * row_count + row] = r2297;
    unsigned r2298 = douts27[19];
    out_cols[152u][row] = r2298;
    lookup_words[307u * row_count + row] = r2298;
    lookup_words[365u * row_count + row] = r2298;
    unsigned r2299 = douts27[20];
    out_cols[153u][row] = r2299;
    lookup_words[308u * row_count + row] = r2299;
    lookup_words[366u * row_count + row] = r2299;
    unsigned r2300 = douts27[21];
    out_cols[154u][row] = r2300;
    lookup_words[309u * row_count + row] = r2300;
    lookup_words[367u * row_count + row] = r2300;
    unsigned r2301 = douts27[22];
    out_cols[155u][row] = r2301;
    lookup_words[310u * row_count + row] = r2301;
    lookup_words[368u * row_count + row] = r2301;
    unsigned r2302 = douts27[23];
    out_cols[156u][row] = r2302;
    lookup_words[311u * row_count + row] = r2302;
    lookup_words[369u * row_count + row] = r2302;
    unsigned r2303 = douts27[24];
    out_cols[157u][row] = r2303;
    lookup_words[312u * row_count + row] = r2303;
    lookup_words[370u * row_count + row] = r2303;
    unsigned r2304 = douts27[25];
    out_cols[158u][row] = r2304;
    lookup_words[313u * row_count + row] = r2304;
    lookup_words[371u * row_count + row] = r2304;
    unsigned r2305 = douts27[26];
    out_cols[159u][row] = r2305;
    lookup_words[314u * row_count + row] = r2305;
    lookup_words[372u * row_count + row] = r2305;
    unsigned r2306 = douts27[27];
    out_cols[160u][row] = r2306;
    lookup_words[315u * row_count + row] = r2306;
    lookup_words[373u * row_count + row] = r2306;
    unsigned r2307 = douts27[28];
    out_cols[161u][row] = r2307;
    lookup_words[316u * row_count + row] = r2307;
    lookup_words[374u * row_count + row] = r2307;
    unsigned r2308 = douts27[29];
    out_cols[162u][row] = r2308;
    lookup_words[317u * row_count + row] = r2308;
    lookup_words[375u * row_count + row] = r2308;
    unsigned r2309 = douts27[30];
    out_cols[163u][row] = r2309;
    lookup_words[318u * row_count + row] = r2309;
    lookup_words[376u * row_count + row] = r2309;
    unsigned r2310 = douts27[31];
    out_cols[164u][row] = r2310;
    lookup_words[319u * row_count + row] = r2310;
    lookup_words[377u * row_count + row] = r2310;
    unsigned r2311 = douts27[32];
    out_cols[165u][row] = r2311;
    lookup_words[320u * row_count + row] = r2311;
    lookup_words[378u * row_count + row] = r2311;
    unsigned r2312 = douts27[33];
    out_cols[166u][row] = r2312;
    lookup_words[321u * row_count + row] = r2312;
    lookup_words[379u * row_count + row] = r2312;
    unsigned r2313 = douts27[34];
    out_cols[167u][row] = r2313;
    lookup_words[322u * row_count + row] = r2313;
    lookup_words[380u * row_count + row] = r2313;
    unsigned r2314 = douts27[35];
    out_cols[168u][row] = r2314;
    lookup_words[323u * row_count + row] = r2314;
    lookup_words[381u * row_count + row] = r2314;
    unsigned r2315 = douts27[36];
    out_cols[169u][row] = r2315;
    lookup_words[324u * row_count + row] = r2315;
    lookup_words[382u * row_count + row] = r2315;
    unsigned r2316 = douts27[37];
    out_cols[170u][row] = r2316;
    lookup_words[325u * row_count + row] = r2316;
    lookup_words[383u * row_count + row] = r2316;
    unsigned r2317 = douts27[38];
    out_cols[171u][row] = r2317;
    lookup_words[326u * row_count + row] = r2317;
    lookup_words[384u * row_count + row] = r2317;
    unsigned r2318 = douts27[39];
    out_cols[172u][row] = r2318;
    lookup_words[327u * row_count + row] = r2318;
    lookup_words[385u * row_count + row] = r2318;
    unsigned r2319 = douts27[40];
    out_cols[173u][row] = r2319;
    lookup_words[328u * row_count + row] = r2319;
    lookup_words[386u * row_count + row] = r2319;
    unsigned r2320 = douts27[41];
    out_cols[174u][row] = r2320;
    lookup_words[329u * row_count + row] = r2320;
    lookup_words[387u * row_count + row] = r2320;
    unsigned r2321 = douts27[42];
    out_cols[175u][row] = r2321;
    lookup_words[330u * row_count + row] = r2321;
    lookup_words[388u * row_count + row] = r2321;
    unsigned r2322 = douts27[43];
    out_cols[176u][row] = r2322;
    lookup_words[331u * row_count + row] = r2322;
    lookup_words[389u * row_count + row] = r2322;
    unsigned r2323 = douts27[44];
    out_cols[177u][row] = r2323;
    lookup_words[332u * row_count + row] = r2323;
    unsigned r2324 = douts27[45];
    out_cols[178u][row] = r2324;
    lookup_words[333u * row_count + row] = r2324;
    unsigned r2325 = douts27[46];
    out_cols[179u][row] = r2325;
    lookup_words[334u * row_count + row] = r2325;
    unsigned r2326 = douts27[47];
    out_cols[180u][row] = r2326;
    lookup_words[335u * row_count + row] = r2326;
    unsigned r2327 = douts27[48];
    out_cols[181u][row] = r2327;
    lookup_words[336u * row_count + row] = r2327;
    unsigned r2328 = douts27[49];
    out_cols[182u][row] = r2328;
    lookup_words[337u * row_count + row] = r2328;
    unsigned r2329 = douts27[50];
    out_cols[183u][row] = r2329;
    lookup_words[338u * row_count + row] = r2329;
    unsigned r2330 = douts27[51];
    out_cols[184u][row] = r2330;
    lookup_words[339u * row_count + row] = r2330;
    unsigned r2331 = douts27[52];
    out_cols[185u][row] = r2331;
    lookup_words[340u * row_count + row] = r2331;
    unsigned r2332 = douts27[53];
    out_cols[186u][row] = r2332;
    lookup_words[341u * row_count + row] = r2332;
    unsigned r2333 = douts27[54];
    out_cols[187u][row] = r2333;
    lookup_words[342u * row_count + row] = r2333;
    unsigned r2334 = douts27[55];
    out_cols[188u][row] = r2334;
    lookup_words[343u * row_count + row] = r2334;
    unsigned r2335 = douts27[56];
    out_cols[189u][row] = r2335;
    lookup_words[344u * row_count + row] = r2335;
    unsigned r2336 = douts27[57];
    out_cols[190u][row] = r2336;
    lookup_words[345u * row_count + row] = r2336;
    unsigned r2337 = douts27[58];
    out_cols[191u][row] = r2337;
    lookup_words[346u * row_count + row] = r2337;
    unsigned r2338 = douts27[59];
    out_cols[192u][row] = r2338;
    lookup_words[347u * row_count + row] = r2338;
    unsigned r2339 = douts27[60];
    out_cols[193u][row] = r2339;
    lookup_words[348u * row_count + row] = r2339;
    unsigned r2340 = douts27[61];
    out_cols[194u][row] = r2340;
    lookup_words[349u * row_count + row] = r2340;
    unsigned r2341 = douts27[62];
    out_cols[195u][row] = r2341;
    lookup_words[350u * row_count + row] = r2341;
    unsigned r2342 = douts27[63];
    out_cols[196u][row] = r2342;
    lookup_words[351u * row_count + row] = r2342;
    unsigned r2343 = douts27[64];
    out_cols[197u][row] = r2343;
    lookup_words[352u * row_count + row] = r2343;
    unsigned r2344 = douts27[65];
    out_cols[198u][row] = r2344;
    lookup_words[353u * row_count + row] = r2344;
    unsigned r2345 = douts27[66];
    out_cols[199u][row] = r2345;
    lookup_words[354u * row_count + row] = r2345;
    unsigned r2346 = douts27[67];
    out_cols[200u][row] = r2346;
    lookup_words[355u * row_count + row] = r2346;
    unsigned r2347 = douts27[68];
    out_cols[201u][row] = r2347;
    lookup_words[356u * row_count + row] = r2347;
    unsigned r2348 = douts27[69];
    out_cols[202u][row] = r2348;
    lookup_words[357u * row_count + row] = r2348;
    unsigned r2349 = douts27[70];
    out_cols[203u][row] = r2349;
    lookup_words[358u * row_count + row] = r2349;
    unsigned r2350 = douts27[71];
    out_cols[204u][row] = r2350;
    lookup_words[359u * row_count + row] = r2350;
    unsigned r2351 = input_cols[5u][row];
    out_cols[205u][row] = r2351;
    lookup_words[395u * row_count + row] = r2351;
}
