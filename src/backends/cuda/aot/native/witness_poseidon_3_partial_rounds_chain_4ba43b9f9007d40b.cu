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

static __device__ __forceinline__ void stwo_wit_deduce_felt_mul(
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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_d6df0fe1ca333aac(
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
    unsigned r5 = 16u;
    unsigned r6 = 136u;
    unsigned r7 = 512u;
    unsigned r8 = 262144u;
    unsigned r9 = 134217729u;
    unsigned r10 = 268435458u;
    unsigned r11 = 1024310512u;
    lookup_words[0u * row_count + row] = r11;
    unsigned r12 = 1027333874u;
    lookup_words[53u * row_count + row] = r12;
    lookup_words[58u * row_count + row] = r12;
    lookup_words[98u * row_count + row] = r12;
    lookup_words[103u * row_count + row] = r12;
    lookup_words[143u * row_count + row] = r12;
    lookup_words[148u * row_count + row] = r12;
    unsigned r13 = 1090315331u;
    lookup_words[66u * row_count + row] = r13;
    lookup_words[111u * row_count + row] = r13;
    lookup_words[156u * row_count + row] = r13;
    unsigned r14 = 1343313504u;
    lookup_words[167u * row_count + row] = r14;
    lookup_words[210u * row_count + row] = r14;
    unsigned r15 = 1651211826u;
    lookup_words[63u * row_count + row] = r15;
    lookup_words[108u * row_count + row] = r15;
    lookup_words[153u * row_count + row] = r15;
    unsigned r16 = 1987997202u;
    lookup_words[32u * row_count + row] = r16;
    lookup_words[77u * row_count + row] = r16;
    lookup_words[122u * row_count + row] = r16;
    unsigned r17 = input_cols[0u][row];
    out_cols[0u][row] = r17;
    lookup_words[168u * row_count + row] = r17;
    lookup_words[211u * row_count + row] = r17;
    unsigned r18 = input_cols[1u][row];
    unsigned r19 = input_cols[2u][row];
    unsigned r20 = input_cols[3u][row];
    unsigned r21 = input_cols[4u][row];
    unsigned r22 = input_cols[5u][row];
    unsigned r23 = input_cols[6u][row];
    unsigned r24 = input_cols[7u][row];
    unsigned r25 = input_cols[8u][row];
    unsigned r26 = input_cols[9u][row];
    unsigned r27 = input_cols[10u][row];
    unsigned r28 = input_cols[11u][row];
    unsigned r29 = input_cols[2u][row];
    unsigned r30 = input_cols[3u][row];
    unsigned r31 = input_cols[4u][row];
    unsigned r32 = input_cols[5u][row];
    unsigned r33 = input_cols[6u][row];
    unsigned r34 = input_cols[7u][row];
    unsigned r35 = input_cols[8u][row];
    unsigned r36 = input_cols[9u][row];
    unsigned r37 = input_cols[10u][row];
    unsigned r38 = input_cols[11u][row];
    unsigned r39 = input_cols[2u][row];
    unsigned r40 = input_cols[3u][row];
    unsigned r41 = input_cols[4u][row];
    unsigned r42 = input_cols[5u][row];
    unsigned r43 = input_cols[6u][row];
    unsigned r44 = input_cols[7u][row];
    unsigned r45 = input_cols[8u][row];
    unsigned r46 = input_cols[9u][row];
    unsigned r47 = input_cols[10u][row];
    unsigned r48 = input_cols[11u][row];
    unsigned r49 = input_cols[2u][row];
    unsigned r50 = input_cols[3u][row];
    unsigned r51 = input_cols[4u][row];
    unsigned r52 = input_cols[5u][row];
    unsigned r53 = input_cols[6u][row];
    unsigned r54 = input_cols[7u][row];
    unsigned r55 = input_cols[8u][row];
    unsigned r56 = input_cols[9u][row];
    unsigned r57 = input_cols[10u][row];
    unsigned r58 = input_cols[11u][row];
    unsigned r59 = input_cols[2u][row];
    unsigned r60 = input_cols[3u][row];
    unsigned r61 = input_cols[4u][row];
    unsigned r62 = input_cols[5u][row];
    unsigned r63 = input_cols[6u][row];
    unsigned r64 = input_cols[7u][row];
    unsigned r65 = input_cols[8u][row];
    unsigned r66 = input_cols[9u][row];
    unsigned r67 = input_cols[10u][row];
    unsigned r68 = input_cols[11u][row];
    unsigned r69 = input_cols[2u][row];
    unsigned r70 = input_cols[3u][row];
    unsigned r71 = input_cols[4u][row];
    unsigned r72 = input_cols[5u][row];
    unsigned r73 = input_cols[6u][row];
    unsigned r74 = input_cols[7u][row];
    unsigned r75 = input_cols[8u][row];
    unsigned r76 = input_cols[9u][row];
    unsigned r77 = input_cols[10u][row];
    unsigned r78 = input_cols[11u][row];
    unsigned r79 = input_cols[2u][row];
    unsigned r80 = input_cols[3u][row];
    unsigned r81 = input_cols[4u][row];
    unsigned r82 = input_cols[5u][row];
    unsigned r83 = input_cols[6u][row];
    unsigned r84 = input_cols[7u][row];
    unsigned r85 = input_cols[8u][row];
    unsigned r86 = input_cols[9u][row];
    unsigned r87 = input_cols[10u][row];
    unsigned r88 = input_cols[11u][row];
    unsigned r89 = input_cols[2u][row];
    unsigned r90 = input_cols[3u][row];
    unsigned r91 = input_cols[4u][row];
    unsigned r92 = input_cols[5u][row];
    unsigned r93 = input_cols[6u][row];
    unsigned r94 = input_cols[7u][row];
    unsigned r95 = input_cols[8u][row];
    unsigned r96 = input_cols[9u][row];
    unsigned r97 = input_cols[10u][row];
    unsigned r98 = input_cols[11u][row];
    unsigned r99 = input_cols[2u][row];
    unsigned r100 = input_cols[3u][row];
    unsigned r101 = input_cols[4u][row];
    unsigned r102 = input_cols[5u][row];
    unsigned r103 = input_cols[6u][row];
    unsigned r104 = input_cols[7u][row];
    unsigned r105 = input_cols[8u][row];
    unsigned r106 = input_cols[9u][row];
    unsigned r107 = input_cols[10u][row];
    unsigned r108 = input_cols[11u][row];
    unsigned r109 = input_cols[2u][row];
    unsigned r110 = input_cols[3u][row];
    unsigned r111 = input_cols[4u][row];
    unsigned r112 = input_cols[5u][row];
    unsigned r113 = input_cols[6u][row];
    unsigned r114 = input_cols[7u][row];
    unsigned r115 = input_cols[8u][row];
    unsigned r116 = input_cols[9u][row];
    unsigned r117 = input_cols[10u][row];
    unsigned r118 = input_cols[11u][row];
    out_cols[11u][row] = r118;
    lookup_words[179u * row_count + row] = r118;
    unsigned r119 = input_cols[12u][row];
    unsigned r120 = input_cols[13u][row];
    unsigned r121 = input_cols[14u][row];
    unsigned r122 = input_cols[15u][row];
    unsigned r123 = input_cols[16u][row];
    unsigned r124 = input_cols[17u][row];
    unsigned r125 = input_cols[18u][row];
    unsigned r126 = input_cols[19u][row];
    unsigned r127 = input_cols[20u][row];
    unsigned r128 = input_cols[21u][row];
    unsigned r129 = input_cols[12u][row];
    unsigned r130 = input_cols[13u][row];
    unsigned r131 = input_cols[14u][row];
    unsigned r132 = input_cols[15u][row];
    unsigned r133 = input_cols[16u][row];
    unsigned r134 = input_cols[17u][row];
    unsigned r135 = input_cols[18u][row];
    unsigned r136 = input_cols[19u][row];
    unsigned r137 = input_cols[20u][row];
    unsigned r138 = input_cols[21u][row];
    unsigned r139 = input_cols[12u][row];
    unsigned r140 = input_cols[13u][row];
    unsigned r141 = input_cols[14u][row];
    unsigned r142 = input_cols[15u][row];
    unsigned r143 = input_cols[16u][row];
    unsigned r144 = input_cols[17u][row];
    unsigned r145 = input_cols[18u][row];
    unsigned r146 = input_cols[19u][row];
    unsigned r147 = input_cols[20u][row];
    unsigned r148 = input_cols[21u][row];
    unsigned r149 = input_cols[12u][row];
    unsigned r150 = input_cols[13u][row];
    unsigned r151 = input_cols[14u][row];
    unsigned r152 = input_cols[15u][row];
    unsigned r153 = input_cols[16u][row];
    unsigned r154 = input_cols[17u][row];
    unsigned r155 = input_cols[18u][row];
    unsigned r156 = input_cols[19u][row];
    unsigned r157 = input_cols[20u][row];
    unsigned r158 = input_cols[21u][row];
    unsigned r159 = input_cols[12u][row];
    unsigned r160 = input_cols[13u][row];
    unsigned r161 = input_cols[14u][row];
    unsigned r162 = input_cols[15u][row];
    unsigned r163 = input_cols[16u][row];
    unsigned r164 = input_cols[17u][row];
    unsigned r165 = input_cols[18u][row];
    unsigned r166 = input_cols[19u][row];
    unsigned r167 = input_cols[20u][row];
    unsigned r168 = input_cols[21u][row];
    unsigned r169 = input_cols[12u][row];
    unsigned r170 = input_cols[13u][row];
    unsigned r171 = input_cols[14u][row];
    unsigned r172 = input_cols[15u][row];
    unsigned r173 = input_cols[16u][row];
    unsigned r174 = input_cols[17u][row];
    unsigned r175 = input_cols[18u][row];
    unsigned r176 = input_cols[19u][row];
    unsigned r177 = input_cols[20u][row];
    unsigned r178 = input_cols[21u][row];
    unsigned r179 = input_cols[12u][row];
    unsigned r180 = input_cols[13u][row];
    unsigned r181 = input_cols[14u][row];
    unsigned r182 = input_cols[15u][row];
    unsigned r183 = input_cols[16u][row];
    unsigned r184 = input_cols[17u][row];
    unsigned r185 = input_cols[18u][row];
    unsigned r186 = input_cols[19u][row];
    unsigned r187 = input_cols[20u][row];
    unsigned r188 = input_cols[21u][row];
    unsigned r189 = input_cols[12u][row];
    unsigned r190 = input_cols[13u][row];
    unsigned r191 = input_cols[14u][row];
    unsigned r192 = input_cols[15u][row];
    unsigned r193 = input_cols[16u][row];
    unsigned r194 = input_cols[17u][row];
    unsigned r195 = input_cols[18u][row];
    unsigned r196 = input_cols[19u][row];
    unsigned r197 = input_cols[20u][row];
    unsigned r198 = input_cols[21u][row];
    unsigned r199 = input_cols[12u][row];
    unsigned r200 = input_cols[13u][row];
    unsigned r201 = input_cols[14u][row];
    unsigned r202 = input_cols[15u][row];
    unsigned r203 = input_cols[16u][row];
    unsigned r204 = input_cols[17u][row];
    unsigned r205 = input_cols[18u][row];
    unsigned r206 = input_cols[19u][row];
    unsigned r207 = input_cols[20u][row];
    unsigned r208 = input_cols[21u][row];
    unsigned r209 = input_cols[12u][row];
    unsigned r210 = input_cols[13u][row];
    unsigned r211 = input_cols[14u][row];
    unsigned r212 = input_cols[15u][row];
    unsigned r213 = input_cols[16u][row];
    unsigned r214 = input_cols[17u][row];
    unsigned r215 = input_cols[18u][row];
    unsigned r216 = input_cols[19u][row];
    unsigned r217 = input_cols[20u][row];
    unsigned r218 = input_cols[21u][row];
    out_cols[21u][row] = r218;
    lookup_words[189u * row_count + row] = r218;
    unsigned r219 = input_cols[22u][row];
    unsigned r220 = input_cols[23u][row];
    unsigned r221 = input_cols[24u][row];
    unsigned r222 = input_cols[25u][row];
    unsigned r223 = input_cols[26u][row];
    unsigned r224 = input_cols[27u][row];
    unsigned r225 = input_cols[28u][row];
    unsigned r226 = input_cols[29u][row];
    unsigned r227 = input_cols[30u][row];
    unsigned r228 = input_cols[31u][row];
    unsigned r229 = input_cols[22u][row];
    unsigned r230 = input_cols[23u][row];
    unsigned r231 = input_cols[24u][row];
    unsigned r232 = input_cols[25u][row];
    unsigned r233 = input_cols[26u][row];
    unsigned r234 = input_cols[27u][row];
    unsigned r235 = input_cols[28u][row];
    unsigned r236 = input_cols[29u][row];
    unsigned r237 = input_cols[30u][row];
    unsigned r238 = input_cols[31u][row];
    unsigned r239 = input_cols[22u][row];
    unsigned r240 = input_cols[23u][row];
    unsigned r241 = input_cols[24u][row];
    unsigned r242 = input_cols[25u][row];
    unsigned r243 = input_cols[26u][row];
    unsigned r244 = input_cols[27u][row];
    unsigned r245 = input_cols[28u][row];
    unsigned r246 = input_cols[29u][row];
    unsigned r247 = input_cols[30u][row];
    unsigned r248 = input_cols[31u][row];
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
    unsigned r259 = input_cols[22u][row];
    unsigned r260 = input_cols[23u][row];
    unsigned r261 = input_cols[24u][row];
    unsigned r262 = input_cols[25u][row];
    unsigned r263 = input_cols[26u][row];
    unsigned r264 = input_cols[27u][row];
    unsigned r265 = input_cols[28u][row];
    unsigned r266 = input_cols[29u][row];
    unsigned r267 = input_cols[30u][row];
    unsigned r268 = input_cols[31u][row];
    unsigned r269 = input_cols[22u][row];
    unsigned r270 = input_cols[23u][row];
    unsigned r271 = input_cols[24u][row];
    unsigned r272 = input_cols[25u][row];
    unsigned r273 = input_cols[26u][row];
    unsigned r274 = input_cols[27u][row];
    unsigned r275 = input_cols[28u][row];
    unsigned r276 = input_cols[29u][row];
    unsigned r277 = input_cols[30u][row];
    unsigned r278 = input_cols[31u][row];
    unsigned r279 = input_cols[22u][row];
    unsigned r280 = input_cols[23u][row];
    unsigned r281 = input_cols[24u][row];
    unsigned r282 = input_cols[25u][row];
    unsigned r283 = input_cols[26u][row];
    unsigned r284 = input_cols[27u][row];
    unsigned r285 = input_cols[28u][row];
    unsigned r286 = input_cols[29u][row];
    unsigned r287 = input_cols[30u][row];
    unsigned r288 = input_cols[31u][row];
    unsigned r289 = input_cols[22u][row];
    unsigned r290 = input_cols[23u][row];
    unsigned r291 = input_cols[24u][row];
    unsigned r292 = input_cols[25u][row];
    unsigned r293 = input_cols[26u][row];
    unsigned r294 = input_cols[27u][row];
    unsigned r295 = input_cols[28u][row];
    unsigned r296 = input_cols[29u][row];
    unsigned r297 = input_cols[30u][row];
    unsigned r298 = input_cols[31u][row];
    unsigned r299 = input_cols[22u][row];
    unsigned r300 = input_cols[23u][row];
    unsigned r301 = input_cols[24u][row];
    unsigned r302 = input_cols[25u][row];
    unsigned r303 = input_cols[26u][row];
    unsigned r304 = input_cols[27u][row];
    unsigned r305 = input_cols[28u][row];
    unsigned r306 = input_cols[29u][row];
    unsigned r307 = input_cols[30u][row];
    unsigned r308 = input_cols[31u][row];
    unsigned r309 = input_cols[22u][row];
    unsigned r310 = input_cols[23u][row];
    unsigned r311 = input_cols[24u][row];
    unsigned r312 = input_cols[25u][row];
    unsigned r313 = input_cols[26u][row];
    unsigned r314 = input_cols[27u][row];
    unsigned r315 = input_cols[28u][row];
    unsigned r316 = input_cols[29u][row];
    unsigned r317 = input_cols[30u][row];
    unsigned r318 = input_cols[31u][row];
    out_cols[31u][row] = r318;
    lookup_words[199u * row_count + row] = r318;
    unsigned r319 = input_cols[32u][row];
    unsigned r320 = input_cols[33u][row];
    unsigned r321 = input_cols[34u][row];
    unsigned r322 = input_cols[35u][row];
    unsigned r323 = input_cols[36u][row];
    unsigned r324 = input_cols[37u][row];
    unsigned r325 = input_cols[38u][row];
    unsigned r326 = input_cols[39u][row];
    unsigned r327 = input_cols[40u][row];
    unsigned r328 = input_cols[41u][row];
    unsigned r329 = input_cols[32u][row];
    unsigned r330 = input_cols[33u][row];
    unsigned r331 = input_cols[34u][row];
    unsigned r332 = input_cols[35u][row];
    unsigned r333 = input_cols[36u][row];
    unsigned r334 = input_cols[37u][row];
    unsigned r335 = input_cols[38u][row];
    unsigned r336 = input_cols[39u][row];
    unsigned r337 = input_cols[40u][row];
    unsigned r338 = input_cols[41u][row];
    unsigned r339 = input_cols[32u][row];
    unsigned r340 = input_cols[33u][row];
    unsigned r341 = input_cols[34u][row];
    unsigned r342 = input_cols[35u][row];
    unsigned r343 = input_cols[36u][row];
    unsigned r344 = input_cols[37u][row];
    unsigned r345 = input_cols[38u][row];
    unsigned r346 = input_cols[39u][row];
    unsigned r347 = input_cols[40u][row];
    unsigned r348 = input_cols[41u][row];
    unsigned r349 = input_cols[32u][row];
    unsigned r350 = input_cols[33u][row];
    unsigned r351 = input_cols[34u][row];
    unsigned r352 = input_cols[35u][row];
    unsigned r353 = input_cols[36u][row];
    unsigned r354 = input_cols[37u][row];
    unsigned r355 = input_cols[38u][row];
    unsigned r356 = input_cols[39u][row];
    unsigned r357 = input_cols[40u][row];
    unsigned r358 = input_cols[41u][row];
    unsigned r359 = input_cols[32u][row];
    unsigned r360 = input_cols[33u][row];
    unsigned r361 = input_cols[34u][row];
    unsigned r362 = input_cols[35u][row];
    unsigned r363 = input_cols[36u][row];
    unsigned r364 = input_cols[37u][row];
    unsigned r365 = input_cols[38u][row];
    unsigned r366 = input_cols[39u][row];
    unsigned r367 = input_cols[40u][row];
    unsigned r368 = input_cols[41u][row];
    unsigned r369 = input_cols[32u][row];
    unsigned r370 = input_cols[33u][row];
    unsigned r371 = input_cols[34u][row];
    unsigned r372 = input_cols[35u][row];
    unsigned r373 = input_cols[36u][row];
    unsigned r374 = input_cols[37u][row];
    unsigned r375 = input_cols[38u][row];
    unsigned r376 = input_cols[39u][row];
    unsigned r377 = input_cols[40u][row];
    unsigned r378 = input_cols[41u][row];
    unsigned r379 = input_cols[32u][row];
    unsigned r380 = input_cols[33u][row];
    unsigned r381 = input_cols[34u][row];
    unsigned r382 = input_cols[35u][row];
    unsigned r383 = input_cols[36u][row];
    unsigned r384 = input_cols[37u][row];
    unsigned r385 = input_cols[38u][row];
    unsigned r386 = input_cols[39u][row];
    unsigned r387 = input_cols[40u][row];
    unsigned r388 = input_cols[41u][row];
    unsigned r389 = input_cols[32u][row];
    unsigned r390 = input_cols[33u][row];
    unsigned r391 = input_cols[34u][row];
    unsigned r392 = input_cols[35u][row];
    unsigned r393 = input_cols[36u][row];
    unsigned r394 = input_cols[37u][row];
    unsigned r395 = input_cols[38u][row];
    unsigned r396 = input_cols[39u][row];
    unsigned r397 = input_cols[40u][row];
    unsigned r398 = input_cols[41u][row];
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
    unsigned r409 = input_cols[32u][row];
    unsigned r410 = input_cols[33u][row];
    unsigned r411 = input_cols[34u][row];
    unsigned r412 = input_cols[35u][row];
    unsigned r413 = input_cols[36u][row];
    unsigned r414 = input_cols[37u][row];
    unsigned r415 = input_cols[38u][row];
    unsigned r416 = input_cols[39u][row];
    unsigned r417 = input_cols[40u][row];
    unsigned r418 = input_cols[41u][row];
    out_cols[41u][row] = r418;
    lookup_words[42u * row_count + row] = r418;
    lookup_words[209u * row_count + row] = r418;
    const unsigned dargs0[1] = { r18 };
    unsigned douts0[30];
    stwo_wit_deduce_poseidon_round_keys(dargs0, douts0);
    unsigned r419 = douts0[0];
    unsigned r420 = douts0[1];
    unsigned r421 = douts0[2];
    unsigned r422 = douts0[3];
    unsigned r423 = douts0[4];
    unsigned r424 = douts0[5];
    unsigned r425 = douts0[6];
    unsigned r426 = douts0[7];
    unsigned r427 = douts0[8];
    unsigned r428 = douts0[9];
    unsigned r429 = douts0[10];
    unsigned r430 = douts0[11];
    unsigned r431 = douts0[12];
    unsigned r432 = douts0[13];
    unsigned r433 = douts0[14];
    unsigned r434 = douts0[15];
    unsigned r435 = douts0[16];
    unsigned r436 = douts0[17];
    unsigned r437 = douts0[18];
    unsigned r438 = douts0[19];
    unsigned r439 = douts0[20];
    unsigned r440 = douts0[21];
    unsigned r441 = douts0[22];
    unsigned r442 = douts0[23];
    unsigned r443 = douts0[24];
    unsigned r444 = douts0[25];
    unsigned r445 = douts0[26];
    unsigned r446 = douts0[27];
    unsigned r447 = douts0[28];
    unsigned r448 = douts0[29];
    unsigned r449 = input_cols[32u][row];
    sub_words[1u * row_count + row] = r449;
    unsigned r450 = input_cols[33u][row];
    sub_words[2u * row_count + row] = r450;
    unsigned r451 = input_cols[34u][row];
    sub_words[3u * row_count + row] = r451;
    unsigned r452 = input_cols[35u][row];
    sub_words[4u * row_count + row] = r452;
    unsigned r453 = input_cols[36u][row];
    sub_words[5u * row_count + row] = r453;
    unsigned r454 = input_cols[37u][row];
    sub_words[6u * row_count + row] = r454;
    unsigned r455 = input_cols[38u][row];
    sub_words[7u * row_count + row] = r455;
    unsigned r456 = input_cols[39u][row];
    sub_words[8u * row_count + row] = r456;
    unsigned r457 = input_cols[40u][row];
    sub_words[9u * row_count + row] = r457;
    unsigned r458 = input_cols[41u][row];
    sub_words[10u * row_count + row] = r458;
    unsigned r459 = input_cols[32u][row];
    unsigned r460 = input_cols[33u][row];
    unsigned r461 = input_cols[34u][row];
    unsigned r462 = input_cols[35u][row];
    unsigned r463 = input_cols[36u][row];
    unsigned r464 = input_cols[37u][row];
    unsigned r465 = input_cols[38u][row];
    unsigned r466 = input_cols[39u][row];
    unsigned r467 = input_cols[40u][row];
    unsigned r468 = input_cols[41u][row];
    const unsigned dargs1[10] = { r459, r460, r461, r462, r463, r464, r465, r466, r467, r468 };
    unsigned douts1[10];
    stwo_wit_deduce_cube_252(dargs1, douts1);
    unsigned r469 = douts1[0];
    unsigned r470 = douts1[1];
    unsigned r471 = douts1[2];
    unsigned r472 = douts1[3];
    unsigned r473 = douts1[4];
    unsigned r474 = douts1[5];
    unsigned r475 = douts1[6];
    unsigned r476 = douts1[7];
    unsigned r477 = douts1[8];
    unsigned r478 = douts1[9];
    unsigned r479 = input_cols[2u][row];
    unsigned r480 = input_cols[3u][row];
    unsigned r481 = input_cols[4u][row];
    unsigned r482 = input_cols[5u][row];
    unsigned r483 = input_cols[6u][row];
    unsigned r484 = input_cols[7u][row];
    unsigned r485 = input_cols[8u][row];
    unsigned r486 = input_cols[9u][row];
    unsigned r487 = input_cols[10u][row];
    unsigned r488 = input_cols[11u][row];
    unsigned r489 = (r479 & 511u);
    unsigned r490 = (r479 >> 9u);
    unsigned r491 = (r490 & 511u);
    unsigned r492 = (r479 >> 18u);
    unsigned r493 = (r492 & 511u);
    unsigned r494 = (r480 & 511u);
    unsigned r495 = (r480 >> 9u);
    unsigned r496 = (r495 & 511u);
    unsigned r497 = (r480 >> 18u);
    unsigned r498 = (r497 & 511u);
    unsigned r499 = (r481 & 511u);
    unsigned r500 = (r481 >> 9u);
    unsigned r501 = (r500 & 511u);
    unsigned r502 = (r481 >> 18u);
    unsigned r503 = (r502 & 511u);
    unsigned r504 = (r482 & 511u);
    unsigned r505 = (r482 >> 9u);
    unsigned r506 = (r505 & 511u);
    unsigned r507 = (r482 >> 18u);
    unsigned r508 = (r507 & 511u);
    unsigned r509 = (r483 & 511u);
    unsigned r510 = (r483 >> 9u);
    unsigned r511 = (r510 & 511u);
    unsigned r512 = (r483 >> 18u);
    unsigned r513 = (r512 & 511u);
    unsigned r514 = (r484 & 511u);
    unsigned r515 = (r484 >> 9u);
    unsigned r516 = (r515 & 511u);
    unsigned r517 = (r484 >> 18u);
    unsigned r518 = (r517 & 511u);
    unsigned r519 = (r485 & 511u);
    unsigned r520 = (r485 >> 9u);
    unsigned r521 = (r520 & 511u);
    unsigned r522 = (r485 >> 18u);
    unsigned r523 = (r522 & 511u);
    unsigned r524 = (r486 & 511u);
    unsigned r525 = (r486 >> 9u);
    unsigned r526 = (r525 & 511u);
    unsigned r527 = (r486 >> 18u);
    unsigned r528 = (r527 & 511u);
    unsigned r529 = (r487 & 511u);
    unsigned r530 = (r487 >> 9u);
    unsigned r531 = (r530 & 511u);
    unsigned r532 = (r487 >> 18u);
    unsigned r533 = (r532 & 511u);
    unsigned r534 = (r488 & 511u);
    const unsigned dargs2[56] = { r4, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r489, r491, r493, r494, r496, r498, r499, r501, r503, r504, r506, r508, r509, r511, r513, r514, r516, r518, r519, r521, r523, r524, r526, r528, r529, r531, r533, r534 };
    unsigned douts2[28];
    stwo_wit_deduce_felt_mul(dargs2, douts2);
    unsigned r535 = douts2[0];
    unsigned r536 = douts2[1];
    unsigned r537 = douts2[2];
    unsigned r538 = douts2[3];
    unsigned r539 = douts2[4];
    unsigned r540 = douts2[5];
    unsigned r541 = douts2[6];
    unsigned r542 = douts2[7];
    unsigned r543 = douts2[8];
    unsigned r544 = douts2[9];
    unsigned r545 = douts2[10];
    unsigned r546 = douts2[11];
    unsigned r547 = douts2[12];
    unsigned r548 = douts2[13];
    unsigned r549 = douts2[14];
    unsigned r550 = douts2[15];
    unsigned r551 = douts2[16];
    unsigned r552 = douts2[17];
    unsigned r553 = douts2[18];
    unsigned r554 = douts2[19];
    unsigned r555 = douts2[20];
    unsigned r556 = douts2[21];
    unsigned r557 = douts2[22];
    unsigned r558 = douts2[23];
    unsigned r559 = douts2[24];
    unsigned r560 = douts2[25];
    unsigned r561 = douts2[26];
    unsigned r562 = douts2[27];
    const unsigned dargs3[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r535, r536, r537, r538, r539, r540, r541, r542, r543, r544, r545, r546, r547, r548, r549, r550, r551, r552, r553, r554, r555, r556, r557, r558, r559, r560, r561, r562 };
    unsigned douts3[28];
    stwo_wit_deduce_felt_add(dargs3, douts3);
    unsigned r563 = douts3[0];
    unsigned r564 = douts3[1];
    unsigned r565 = douts3[2];
    unsigned r566 = douts3[3];
    unsigned r567 = douts3[4];
    unsigned r568 = douts3[5];
    unsigned r569 = douts3[6];
    unsigned r570 = douts3[7];
    unsigned r571 = douts3[8];
    unsigned r572 = douts3[9];
    unsigned r573 = douts3[10];
    unsigned r574 = douts3[11];
    unsigned r575 = douts3[12];
    unsigned r576 = douts3[13];
    unsigned r577 = douts3[14];
    unsigned r578 = douts3[15];
    unsigned r579 = douts3[16];
    unsigned r580 = douts3[17];
    unsigned r581 = douts3[18];
    unsigned r582 = douts3[19];
    unsigned r583 = douts3[20];
    unsigned r584 = douts3[21];
    unsigned r585 = douts3[22];
    unsigned r586 = douts3[23];
    unsigned r587 = douts3[24];
    unsigned r588 = douts3[25];
    unsigned r589 = douts3[26];
    unsigned r590 = douts3[27];
    unsigned r591 = input_cols[12u][row];
    unsigned r592 = input_cols[13u][row];
    unsigned r593 = input_cols[14u][row];
    unsigned r594 = input_cols[15u][row];
    unsigned r595 = input_cols[16u][row];
    unsigned r596 = input_cols[17u][row];
    unsigned r597 = input_cols[18u][row];
    unsigned r598 = input_cols[19u][row];
    unsigned r599 = input_cols[20u][row];
    unsigned r600 = input_cols[21u][row];
    unsigned r601 = (r591 & 511u);
    unsigned r602 = (r591 >> 9u);
    unsigned r603 = (r602 & 511u);
    unsigned r604 = (r591 >> 18u);
    unsigned r605 = (r604 & 511u);
    unsigned r606 = (r592 & 511u);
    unsigned r607 = (r592 >> 9u);
    unsigned r608 = (r607 & 511u);
    unsigned r609 = (r592 >> 18u);
    unsigned r610 = (r609 & 511u);
    unsigned r611 = (r593 & 511u);
    unsigned r612 = (r593 >> 9u);
    unsigned r613 = (r612 & 511u);
    unsigned r614 = (r593 >> 18u);
    unsigned r615 = (r614 & 511u);
    unsigned r616 = (r594 & 511u);
    unsigned r617 = (r594 >> 9u);
    unsigned r618 = (r617 & 511u);
    unsigned r619 = (r594 >> 18u);
    unsigned r620 = (r619 & 511u);
    unsigned r621 = (r595 & 511u);
    unsigned r622 = (r595 >> 9u);
    unsigned r623 = (r622 & 511u);
    unsigned r624 = (r595 >> 18u);
    unsigned r625 = (r624 & 511u);
    unsigned r626 = (r596 & 511u);
    unsigned r627 = (r596 >> 9u);
    unsigned r628 = (r627 & 511u);
    unsigned r629 = (r596 >> 18u);
    unsigned r630 = (r629 & 511u);
    unsigned r631 = (r597 & 511u);
    unsigned r632 = (r597 >> 9u);
    unsigned r633 = (r632 & 511u);
    unsigned r634 = (r597 >> 18u);
    unsigned r635 = (r634 & 511u);
    unsigned r636 = (r598 & 511u);
    unsigned r637 = (r598 >> 9u);
    unsigned r638 = (r637 & 511u);
    unsigned r639 = (r598 >> 18u);
    unsigned r640 = (r639 & 511u);
    unsigned r641 = (r599 & 511u);
    unsigned r642 = (r599 >> 9u);
    unsigned r643 = (r642 & 511u);
    unsigned r644 = (r599 >> 18u);
    unsigned r645 = (r644 & 511u);
    unsigned r646 = (r600 & 511u);
    const unsigned dargs4[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r601, r603, r605, r606, r608, r610, r611, r613, r615, r616, r618, r620, r621, r623, r625, r626, r628, r630, r631, r633, r635, r636, r638, r640, r641, r643, r645, r646 };
    unsigned douts4[28];
    stwo_wit_deduce_felt_mul(dargs4, douts4);
    unsigned r647 = douts4[0];
    unsigned r648 = douts4[1];
    unsigned r649 = douts4[2];
    unsigned r650 = douts4[3];
    unsigned r651 = douts4[4];
    unsigned r652 = douts4[5];
    unsigned r653 = douts4[6];
    unsigned r654 = douts4[7];
    unsigned r655 = douts4[8];
    unsigned r656 = douts4[9];
    unsigned r657 = douts4[10];
    unsigned r658 = douts4[11];
    unsigned r659 = douts4[12];
    unsigned r660 = douts4[13];
    unsigned r661 = douts4[14];
    unsigned r662 = douts4[15];
    unsigned r663 = douts4[16];
    unsigned r664 = douts4[17];
    unsigned r665 = douts4[18];
    unsigned r666 = douts4[19];
    unsigned r667 = douts4[20];
    unsigned r668 = douts4[21];
    unsigned r669 = douts4[22];
    unsigned r670 = douts4[23];
    unsigned r671 = douts4[24];
    unsigned r672 = douts4[25];
    unsigned r673 = douts4[26];
    unsigned r674 = douts4[27];
    const unsigned dargs5[56] = { r563, r564, r565, r566, r567, r568, r569, r570, r571, r572, r573, r574, r575, r576, r577, r578, r579, r580, r581, r582, r583, r584, r585, r586, r587, r588, r589, r590, r647, r648, r649, r650, r651, r652, r653, r654, r655, r656, r657, r658, r659, r660, r661, r662, r663, r664, r665, r666, r667, r668, r669, r670, r671, r672, r673, r674 };
    unsigned douts5[28];
    stwo_wit_deduce_felt_add(dargs5, douts5);
    unsigned r675 = douts5[0];
    unsigned r676 = douts5[1];
    unsigned r677 = douts5[2];
    unsigned r678 = douts5[3];
    unsigned r679 = douts5[4];
    unsigned r680 = douts5[5];
    unsigned r681 = douts5[6];
    unsigned r682 = douts5[7];
    unsigned r683 = douts5[8];
    unsigned r684 = douts5[9];
    unsigned r685 = douts5[10];
    unsigned r686 = douts5[11];
    unsigned r687 = douts5[12];
    unsigned r688 = douts5[13];
    unsigned r689 = douts5[14];
    unsigned r690 = douts5[15];
    unsigned r691 = douts5[16];
    unsigned r692 = douts5[17];
    unsigned r693 = douts5[18];
    unsigned r694 = douts5[19];
    unsigned r695 = douts5[20];
    unsigned r696 = douts5[21];
    unsigned r697 = douts5[22];
    unsigned r698 = douts5[23];
    unsigned r699 = douts5[24];
    unsigned r700 = douts5[25];
    unsigned r701 = douts5[26];
    unsigned r702 = douts5[27];
    unsigned r703 = input_cols[22u][row];
    unsigned r704 = input_cols[23u][row];
    unsigned r705 = input_cols[24u][row];
    unsigned r706 = input_cols[25u][row];
    unsigned r707 = input_cols[26u][row];
    unsigned r708 = input_cols[27u][row];
    unsigned r709 = input_cols[28u][row];
    unsigned r710 = input_cols[29u][row];
    unsigned r711 = input_cols[30u][row];
    unsigned r712 = input_cols[31u][row];
    unsigned r713 = (r703 & 511u);
    unsigned r714 = (r703 >> 9u);
    unsigned r715 = (r714 & 511u);
    unsigned r716 = (r703 >> 18u);
    unsigned r717 = (r716 & 511u);
    unsigned r718 = (r704 & 511u);
    unsigned r719 = (r704 >> 9u);
    unsigned r720 = (r719 & 511u);
    unsigned r721 = (r704 >> 18u);
    unsigned r722 = (r721 & 511u);
    unsigned r723 = (r705 & 511u);
    unsigned r724 = (r705 >> 9u);
    unsigned r725 = (r724 & 511u);
    unsigned r726 = (r705 >> 18u);
    unsigned r727 = (r726 & 511u);
    unsigned r728 = (r706 & 511u);
    unsigned r729 = (r706 >> 9u);
    unsigned r730 = (r729 & 511u);
    unsigned r731 = (r706 >> 18u);
    unsigned r732 = (r731 & 511u);
    unsigned r733 = (r707 & 511u);
    unsigned r734 = (r707 >> 9u);
    unsigned r735 = (r734 & 511u);
    unsigned r736 = (r707 >> 18u);
    unsigned r737 = (r736 & 511u);
    unsigned r738 = (r708 & 511u);
    unsigned r739 = (r708 >> 9u);
    unsigned r740 = (r739 & 511u);
    unsigned r741 = (r708 >> 18u);
    unsigned r742 = (r741 & 511u);
    unsigned r743 = (r709 & 511u);
    unsigned r744 = (r709 >> 9u);
    unsigned r745 = (r744 & 511u);
    unsigned r746 = (r709 >> 18u);
    unsigned r747 = (r746 & 511u);
    unsigned r748 = (r710 & 511u);
    unsigned r749 = (r710 >> 9u);
    unsigned r750 = (r749 & 511u);
    unsigned r751 = (r710 >> 18u);
    unsigned r752 = (r751 & 511u);
    unsigned r753 = (r711 & 511u);
    unsigned r754 = (r711 >> 9u);
    unsigned r755 = (r754 & 511u);
    unsigned r756 = (r711 >> 18u);
    unsigned r757 = (r756 & 511u);
    unsigned r758 = (r712 & 511u);
    const unsigned dargs6[56] = { r3, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r713, r715, r717, r718, r720, r722, r723, r725, r727, r728, r730, r732, r733, r735, r737, r738, r740, r742, r743, r745, r747, r748, r750, r752, r753, r755, r757, r758 };
    unsigned douts6[28];
    stwo_wit_deduce_felt_mul(dargs6, douts6);
    unsigned r759 = douts6[0];
    unsigned r760 = douts6[1];
    unsigned r761 = douts6[2];
    unsigned r762 = douts6[3];
    unsigned r763 = douts6[4];
    unsigned r764 = douts6[5];
    unsigned r765 = douts6[6];
    unsigned r766 = douts6[7];
    unsigned r767 = douts6[8];
    unsigned r768 = douts6[9];
    unsigned r769 = douts6[10];
    unsigned r770 = douts6[11];
    unsigned r771 = douts6[12];
    unsigned r772 = douts6[13];
    unsigned r773 = douts6[14];
    unsigned r774 = douts6[15];
    unsigned r775 = douts6[16];
    unsigned r776 = douts6[17];
    unsigned r777 = douts6[18];
    unsigned r778 = douts6[19];
    unsigned r779 = douts6[20];
    unsigned r780 = douts6[21];
    unsigned r781 = douts6[22];
    unsigned r782 = douts6[23];
    unsigned r783 = douts6[24];
    unsigned r784 = douts6[25];
    unsigned r785 = douts6[26];
    unsigned r786 = douts6[27];
    const unsigned dargs7[56] = { r675, r676, r677, r678, r679, r680, r681, r682, r683, r684, r685, r686, r687, r688, r689, r690, r691, r692, r693, r694, r695, r696, r697, r698, r699, r700, r701, r702, r759, r760, r761, r762, r763, r764, r765, r766, r767, r768, r769, r770, r771, r772, r773, r774, r775, r776, r777, r778, r779, r780, r781, r782, r783, r784, r785, r786 };
    unsigned douts7[28];
    stwo_wit_deduce_felt_add(dargs7, douts7);
    unsigned r787 = douts7[0];
    unsigned r788 = douts7[1];
    unsigned r789 = douts7[2];
    unsigned r790 = douts7[3];
    unsigned r791 = douts7[4];
    unsigned r792 = douts7[5];
    unsigned r793 = douts7[6];
    unsigned r794 = douts7[7];
    unsigned r795 = douts7[8];
    unsigned r796 = douts7[9];
    unsigned r797 = douts7[10];
    unsigned r798 = douts7[11];
    unsigned r799 = douts7[12];
    unsigned r800 = douts7[13];
    unsigned r801 = douts7[14];
    unsigned r802 = douts7[15];
    unsigned r803 = douts7[16];
    unsigned r804 = douts7[17];
    unsigned r805 = douts7[18];
    unsigned r806 = douts7[19];
    unsigned r807 = douts7[20];
    unsigned r808 = douts7[21];
    unsigned r809 = douts7[22];
    unsigned r810 = douts7[23];
    unsigned r811 = douts7[24];
    unsigned r812 = douts7[25];
    unsigned r813 = douts7[26];
    unsigned r814 = douts7[27];
    unsigned r815 = input_cols[32u][row];
    unsigned r816 = input_cols[33u][row];
    unsigned r817 = input_cols[34u][row];
    unsigned r818 = input_cols[35u][row];
    unsigned r819 = input_cols[36u][row];
    unsigned r820 = input_cols[37u][row];
    unsigned r821 = input_cols[38u][row];
    unsigned r822 = input_cols[39u][row];
    unsigned r823 = input_cols[40u][row];
    unsigned r824 = input_cols[41u][row];
    unsigned r825 = (r815 & 511u);
    unsigned r826 = (r815 >> 9u);
    unsigned r827 = (r826 & 511u);
    unsigned r828 = (r815 >> 18u);
    unsigned r829 = (r828 & 511u);
    unsigned r830 = (r816 & 511u);
    unsigned r831 = (r816 >> 9u);
    unsigned r832 = (r831 & 511u);
    unsigned r833 = (r816 >> 18u);
    unsigned r834 = (r833 & 511u);
    unsigned r835 = (r817 & 511u);
    unsigned r836 = (r817 >> 9u);
    unsigned r837 = (r836 & 511u);
    unsigned r838 = (r817 >> 18u);
    unsigned r839 = (r838 & 511u);
    unsigned r840 = (r818 & 511u);
    unsigned r841 = (r818 >> 9u);
    unsigned r842 = (r841 & 511u);
    unsigned r843 = (r818 >> 18u);
    unsigned r844 = (r843 & 511u);
    unsigned r845 = (r819 & 511u);
    unsigned r846 = (r819 >> 9u);
    unsigned r847 = (r846 & 511u);
    unsigned r848 = (r819 >> 18u);
    unsigned r849 = (r848 & 511u);
    unsigned r850 = (r820 & 511u);
    unsigned r851 = (r820 >> 9u);
    unsigned r852 = (r851 & 511u);
    unsigned r853 = (r820 >> 18u);
    unsigned r854 = (r853 & 511u);
    unsigned r855 = (r821 & 511u);
    unsigned r856 = (r821 >> 9u);
    unsigned r857 = (r856 & 511u);
    unsigned r858 = (r821 >> 18u);
    unsigned r859 = (r858 & 511u);
    unsigned r860 = (r822 & 511u);
    unsigned r861 = (r822 >> 9u);
    unsigned r862 = (r861 & 511u);
    unsigned r863 = (r822 >> 18u);
    unsigned r864 = (r863 & 511u);
    unsigned r865 = (r823 & 511u);
    unsigned r866 = (r823 >> 9u);
    unsigned r867 = (r866 & 511u);
    unsigned r868 = (r823 >> 18u);
    unsigned r869 = (r868 & 511u);
    unsigned r870 = (r824 & 511u);
    const unsigned dargs8[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r825, r827, r829, r830, r832, r834, r835, r837, r839, r840, r842, r844, r845, r847, r849, r850, r852, r854, r855, r857, r859, r860, r862, r864, r865, r867, r869, r870 };
    unsigned douts8[28];
    stwo_wit_deduce_felt_mul(dargs8, douts8);
    unsigned r871 = douts8[0];
    unsigned r872 = douts8[1];
    unsigned r873 = douts8[2];
    unsigned r874 = douts8[3];
    unsigned r875 = douts8[4];
    unsigned r876 = douts8[5];
    unsigned r877 = douts8[6];
    unsigned r878 = douts8[7];
    unsigned r879 = douts8[8];
    unsigned r880 = douts8[9];
    unsigned r881 = douts8[10];
    unsigned r882 = douts8[11];
    unsigned r883 = douts8[12];
    unsigned r884 = douts8[13];
    unsigned r885 = douts8[14];
    unsigned r886 = douts8[15];
    unsigned r887 = douts8[16];
    unsigned r888 = douts8[17];
    unsigned r889 = douts8[18];
    unsigned r890 = douts8[19];
    unsigned r891 = douts8[20];
    unsigned r892 = douts8[21];
    unsigned r893 = douts8[22];
    unsigned r894 = douts8[23];
    unsigned r895 = douts8[24];
    unsigned r896 = douts8[25];
    unsigned r897 = douts8[26];
    unsigned r898 = douts8[27];
    const unsigned dargs9[56] = { r787, r788, r789, r790, r791, r792, r793, r794, r795, r796, r797, r798, r799, r800, r801, r802, r803, r804, r805, r806, r807, r808, r809, r810, r811, r812, r813, r814, r871, r872, r873, r874, r875, r876, r877, r878, r879, r880, r881, r882, r883, r884, r885, r886, r887, r888, r889, r890, r891, r892, r893, r894, r895, r896, r897, r898 };
    unsigned douts9[28];
    stwo_wit_deduce_felt_add(dargs9, douts9);
    unsigned r899 = douts9[0];
    unsigned r900 = douts9[1];
    unsigned r901 = douts9[2];
    unsigned r902 = douts9[3];
    unsigned r903 = douts9[4];
    unsigned r904 = douts9[5];
    unsigned r905 = douts9[6];
    unsigned r906 = douts9[7];
    unsigned r907 = douts9[8];
    unsigned r908 = douts9[9];
    unsigned r909 = douts9[10];
    unsigned r910 = douts9[11];
    unsigned r911 = douts9[12];
    unsigned r912 = douts9[13];
    unsigned r913 = douts9[14];
    unsigned r914 = douts9[15];
    unsigned r915 = douts9[16];
    unsigned r916 = douts9[17];
    unsigned r917 = douts9[18];
    unsigned r918 = douts9[19];
    unsigned r919 = douts9[20];
    unsigned r920 = douts9[21];
    unsigned r921 = douts9[22];
    unsigned r922 = douts9[23];
    unsigned r923 = douts9[24];
    unsigned r924 = douts9[25];
    unsigned r925 = douts9[26];
    unsigned r926 = douts9[27];
    unsigned r927 = (r469 & 511u);
    unsigned r928 = (r469 >> 9u);
    unsigned r929 = (r928 & 511u);
    unsigned r930 = (r469 >> 18u);
    unsigned r931 = (r930 & 511u);
    unsigned r932 = (r470 & 511u);
    unsigned r933 = (r470 >> 9u);
    unsigned r934 = (r933 & 511u);
    unsigned r935 = (r470 >> 18u);
    unsigned r936 = (r935 & 511u);
    unsigned r937 = (r471 & 511u);
    unsigned r938 = (r471 >> 9u);
    unsigned r939 = (r938 & 511u);
    unsigned r940 = (r471 >> 18u);
    unsigned r941 = (r940 & 511u);
    unsigned r942 = (r472 & 511u);
    unsigned r943 = (r472 >> 9u);
    unsigned r944 = (r943 & 511u);
    unsigned r945 = (r472 >> 18u);
    unsigned r946 = (r945 & 511u);
    unsigned r947 = (r473 & 511u);
    unsigned r948 = (r473 >> 9u);
    unsigned r949 = (r948 & 511u);
    unsigned r950 = (r473 >> 18u);
    unsigned r951 = (r950 & 511u);
    unsigned r952 = (r474 & 511u);
    unsigned r953 = (r474 >> 9u);
    unsigned r954 = (r953 & 511u);
    unsigned r955 = (r474 >> 18u);
    unsigned r956 = (r955 & 511u);
    unsigned r957 = (r475 & 511u);
    unsigned r958 = (r475 >> 9u);
    unsigned r959 = (r958 & 511u);
    unsigned r960 = (r475 >> 18u);
    unsigned r961 = (r960 & 511u);
    unsigned r962 = (r476 & 511u);
    unsigned r963 = (r476 >> 9u);
    unsigned r964 = (r963 & 511u);
    unsigned r965 = (r476 >> 18u);
    unsigned r966 = (r965 & 511u);
    unsigned r967 = (r477 & 511u);
    unsigned r968 = (r477 >> 9u);
    unsigned r969 = (r968 & 511u);
    unsigned r970 = (r477 >> 18u);
    unsigned r971 = (r970 & 511u);
    unsigned r972 = (r478 & 511u);
    const unsigned dargs10[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r927, r929, r931, r932, r934, r936, r937, r939, r941, r942, r944, r946, r947, r949, r951, r952, r954, r956, r957, r959, r961, r962, r964, r966, r967, r969, r971, r972 };
    unsigned douts10[28];
    stwo_wit_deduce_felt_mul(dargs10, douts10);
    unsigned r973 = douts10[0];
    unsigned r974 = douts10[1];
    unsigned r975 = douts10[2];
    unsigned r976 = douts10[3];
    unsigned r977 = douts10[4];
    unsigned r978 = douts10[5];
    unsigned r979 = douts10[6];
    unsigned r980 = douts10[7];
    unsigned r981 = douts10[8];
    unsigned r982 = douts10[9];
    unsigned r983 = douts10[10];
    unsigned r984 = douts10[11];
    unsigned r985 = douts10[12];
    unsigned r986 = douts10[13];
    unsigned r987 = douts10[14];
    unsigned r988 = douts10[15];
    unsigned r989 = douts10[16];
    unsigned r990 = douts10[17];
    unsigned r991 = douts10[18];
    unsigned r992 = douts10[19];
    unsigned r993 = douts10[20];
    unsigned r994 = douts10[21];
    unsigned r995 = douts10[22];
    unsigned r996 = douts10[23];
    unsigned r997 = douts10[24];
    unsigned r998 = douts10[25];
    unsigned r999 = douts10[26];
    unsigned r1000 = douts10[27];
    const unsigned dargs11[56] = { r899, r900, r901, r902, r903, r904, r905, r906, r907, r908, r909, r910, r911, r912, r913, r914, r915, r916, r917, r918, r919, r920, r921, r922, r923, r924, r925, r926, r973, r974, r975, r976, r977, r978, r979, r980, r981, r982, r983, r984, r985, r986, r987, r988, r989, r990, r991, r992, r993, r994, r995, r996, r997, r998, r999, r1000 };
    unsigned douts11[28];
    stwo_wit_deduce_felt_sub(dargs11, douts11);
    unsigned r1001 = douts11[0];
    unsigned r1002 = douts11[1];
    unsigned r1003 = douts11[2];
    unsigned r1004 = douts11[3];
    unsigned r1005 = douts11[4];
    unsigned r1006 = douts11[5];
    unsigned r1007 = douts11[6];
    unsigned r1008 = douts11[7];
    unsigned r1009 = douts11[8];
    unsigned r1010 = douts11[9];
    unsigned r1011 = douts11[10];
    unsigned r1012 = douts11[11];
    unsigned r1013 = douts11[12];
    unsigned r1014 = douts11[13];
    unsigned r1015 = douts11[14];
    unsigned r1016 = douts11[15];
    unsigned r1017 = douts11[16];
    unsigned r1018 = douts11[17];
    unsigned r1019 = douts11[18];
    unsigned r1020 = douts11[19];
    unsigned r1021 = douts11[20];
    unsigned r1022 = douts11[21];
    unsigned r1023 = douts11[22];
    unsigned r1024 = douts11[23];
    unsigned r1025 = douts11[24];
    unsigned r1026 = douts11[25];
    unsigned r1027 = douts11[26];
    unsigned r1028 = douts11[27];
    unsigned r1029 = (r419 & 511u);
    unsigned r1030 = (r419 >> 9u);
    unsigned r1031 = (r1030 & 511u);
    unsigned r1032 = (r419 >> 18u);
    unsigned r1033 = (r1032 & 511u);
    unsigned r1034 = (r420 & 511u);
    unsigned r1035 = (r420 >> 9u);
    unsigned r1036 = (r1035 & 511u);
    unsigned r1037 = (r420 >> 18u);
    unsigned r1038 = (r1037 & 511u);
    unsigned r1039 = (r421 & 511u);
    unsigned r1040 = (r421 >> 9u);
    unsigned r1041 = (r1040 & 511u);
    unsigned r1042 = (r421 >> 18u);
    unsigned r1043 = (r1042 & 511u);
    unsigned r1044 = (r422 & 511u);
    unsigned r1045 = (r422 >> 9u);
    unsigned r1046 = (r1045 & 511u);
    unsigned r1047 = (r422 >> 18u);
    unsigned r1048 = (r1047 & 511u);
    unsigned r1049 = (r423 & 511u);
    unsigned r1050 = (r423 >> 9u);
    unsigned r1051 = (r1050 & 511u);
    unsigned r1052 = (r423 >> 18u);
    unsigned r1053 = (r1052 & 511u);
    unsigned r1054 = (r424 & 511u);
    unsigned r1055 = (r424 >> 9u);
    unsigned r1056 = (r1055 & 511u);
    unsigned r1057 = (r424 >> 18u);
    unsigned r1058 = (r1057 & 511u);
    unsigned r1059 = (r425 & 511u);
    unsigned r1060 = (r425 >> 9u);
    unsigned r1061 = (r1060 & 511u);
    unsigned r1062 = (r425 >> 18u);
    unsigned r1063 = (r1062 & 511u);
    unsigned r1064 = (r426 & 511u);
    unsigned r1065 = (r426 >> 9u);
    unsigned r1066 = (r1065 & 511u);
    unsigned r1067 = (r426 >> 18u);
    unsigned r1068 = (r1067 & 511u);
    unsigned r1069 = (r427 & 511u);
    unsigned r1070 = (r427 >> 9u);
    unsigned r1071 = (r1070 & 511u);
    unsigned r1072 = (r427 >> 18u);
    unsigned r1073 = (r1072 & 511u);
    unsigned r1074 = (r428 & 511u);
    out_cols[51u][row] = r428;
    lookup_words[11u * row_count + row] = r428;
    const unsigned dargs12[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1029, r1031, r1033, r1034, r1036, r1038, r1039, r1041, r1043, r1044, r1046, r1048, r1049, r1051, r1053, r1054, r1056, r1058, r1059, r1061, r1063, r1064, r1066, r1068, r1069, r1071, r1073, r1074 };
    unsigned douts12[28];
    stwo_wit_deduce_felt_mul(dargs12, douts12);
    unsigned r1075 = douts12[0];
    unsigned r1076 = douts12[1];
    unsigned r1077 = douts12[2];
    unsigned r1078 = douts12[3];
    unsigned r1079 = douts12[4];
    unsigned r1080 = douts12[5];
    unsigned r1081 = douts12[6];
    unsigned r1082 = douts12[7];
    unsigned r1083 = douts12[8];
    unsigned r1084 = douts12[9];
    unsigned r1085 = douts12[10];
    unsigned r1086 = douts12[11];
    unsigned r1087 = douts12[12];
    unsigned r1088 = douts12[13];
    unsigned r1089 = douts12[14];
    unsigned r1090 = douts12[15];
    unsigned r1091 = douts12[16];
    unsigned r1092 = douts12[17];
    unsigned r1093 = douts12[18];
    unsigned r1094 = douts12[19];
    unsigned r1095 = douts12[20];
    unsigned r1096 = douts12[21];
    unsigned r1097 = douts12[22];
    unsigned r1098 = douts12[23];
    unsigned r1099 = douts12[24];
    unsigned r1100 = douts12[25];
    unsigned r1101 = douts12[26];
    unsigned r1102 = douts12[27];
    const unsigned dargs13[56] = { r1001, r1002, r1003, r1004, r1005, r1006, r1007, r1008, r1009, r1010, r1011, r1012, r1013, r1014, r1015, r1016, r1017, r1018, r1019, r1020, r1021, r1022, r1023, r1024, r1025, r1026, r1027, r1028, r1075, r1076, r1077, r1078, r1079, r1080, r1081, r1082, r1083, r1084, r1085, r1086, r1087, r1088, r1089, r1090, r1091, r1092, r1093, r1094, r1095, r1096, r1097, r1098, r1099, r1100, r1101, r1102 };
    unsigned douts13[28];
    stwo_wit_deduce_felt_add(dargs13, douts13);
    unsigned r1103 = douts13[0];
    unsigned r1104 = douts13[1];
    unsigned r1105 = douts13[2];
    unsigned r1106 = douts13[3];
    unsigned r1107 = douts13[4];
    unsigned r1108 = douts13[5];
    unsigned r1109 = douts13[6];
    unsigned r1110 = douts13[7];
    unsigned r1111 = douts13[8];
    unsigned r1112 = douts13[9];
    unsigned r1113 = douts13[10];
    unsigned r1114 = douts13[11];
    unsigned r1115 = douts13[12];
    unsigned r1116 = douts13[13];
    unsigned r1117 = douts13[14];
    unsigned r1118 = douts13[15];
    unsigned r1119 = douts13[16];
    unsigned r1120 = douts13[17];
    unsigned r1121 = douts13[18];
    unsigned r1122 = douts13[19];
    unsigned r1123 = douts13[20];
    unsigned r1124 = douts13[21];
    unsigned r1125 = douts13[22];
    unsigned r1126 = douts13[23];
    unsigned r1127 = douts13[24];
    unsigned r1128 = douts13[25];
    unsigned r1129 = douts13[26];
    unsigned r1130 = douts13[27];
    unsigned r1131 = stwo_m31_mul(r1104, r7);
    unsigned r1132 = stwo_m31_add(r1103, r1131);
    unsigned r1133 = stwo_m31_mul(r1105, r8);
    unsigned r1134 = stwo_m31_add(r1132, r1133);
    unsigned r1135 = stwo_m31_mul(r1107, r7);
    unsigned r1136 = stwo_m31_add(r1106, r1135);
    unsigned r1137 = stwo_m31_mul(r1108, r8);
    unsigned r1138 = stwo_m31_add(r1136, r1137);
    unsigned r1139 = stwo_m31_mul(r1110, r7);
    unsigned r1140 = stwo_m31_add(r1109, r1139);
    unsigned r1141 = stwo_m31_mul(r1111, r8);
    unsigned r1142 = stwo_m31_add(r1140, r1141);
    unsigned r1143 = stwo_m31_mul(r1113, r7);
    unsigned r1144 = stwo_m31_add(r1112, r1143);
    unsigned r1145 = stwo_m31_mul(r1114, r8);
    unsigned r1146 = stwo_m31_add(r1144, r1145);
    unsigned r1147 = stwo_m31_mul(r1116, r7);
    unsigned r1148 = stwo_m31_add(r1115, r1147);
    unsigned r1149 = stwo_m31_mul(r1117, r8);
    unsigned r1150 = stwo_m31_add(r1148, r1149);
    unsigned r1151 = stwo_m31_mul(r1119, r7);
    unsigned r1152 = stwo_m31_add(r1118, r1151);
    unsigned r1153 = stwo_m31_mul(r1120, r8);
    unsigned r1154 = stwo_m31_add(r1152, r1153);
    unsigned r1155 = stwo_m31_mul(r1122, r7);
    unsigned r1156 = stwo_m31_add(r1121, r1155);
    unsigned r1157 = stwo_m31_mul(r1123, r8);
    unsigned r1158 = stwo_m31_add(r1156, r1157);
    unsigned r1159 = stwo_m31_mul(r1125, r7);
    unsigned r1160 = stwo_m31_add(r1124, r1159);
    unsigned r1161 = stwo_m31_mul(r1126, r8);
    unsigned r1162 = stwo_m31_add(r1160, r1161);
    unsigned r1163 = stwo_m31_mul(r1128, r7);
    unsigned r1164 = stwo_m31_add(r1127, r1163);
    unsigned r1165 = stwo_m31_mul(r1129, r8);
    unsigned r1166 = stwo_m31_add(r1164, r1165);
    unsigned r1167 = stwo_m31_mul(r4, r19);
    unsigned r1168 = stwo_m31_mul(r2, r119);
    unsigned r1169 = stwo_m31_add(r1167, r1168);
    unsigned r1170 = stwo_m31_mul(r3, r219);
    unsigned r1171 = stwo_m31_add(r1169, r1170);
    unsigned r1172 = stwo_m31_add(r1171, r319);
    unsigned r1173 = stwo_m31_sub(r1172, r469);
    unsigned r1174 = stwo_m31_add(r1173, r419);
    unsigned r1175 = stwo_m31_sub(r1174, r1134);
    unsigned r1176 = stwo_m31_add(r1175, r10);
    unsigned r1177 = (r1176 & 65535u);
    unsigned r1178 = (r1177 % STWO_M31_P);
    unsigned r1179 = stwo_m31_sub(r1178, r2);
    unsigned r1180 = stwo_m31_mul(r4, r19);
    out_cols[2u][row] = r19;
    lookup_words[170u * row_count + row] = r19;
    unsigned r1181 = stwo_m31_mul(r2, r119);
    out_cols[12u][row] = r119;
    lookup_words[180u * row_count + row] = r119;
    unsigned r1182 = stwo_m31_add(r1180, r1181);
    unsigned r1183 = stwo_m31_mul(r3, r219);
    unsigned r1184 = stwo_m31_add(r1182, r1183);
    unsigned r1185 = stwo_m31_add(r1184, r319);
    unsigned r1186 = stwo_m31_sub(r1185, r469);
    unsigned r1187 = stwo_m31_add(r1186, r419);
    out_cols[42u][row] = r419;
    lookup_words[2u * row_count + row] = r419;
    unsigned r1188 = stwo_m31_sub(r1187, r1134);
    unsigned r1189 = stwo_m31_sub(r1188, r1179);
    unsigned r1190 = stwo_m31_mul(r1189, r5);
    unsigned r1191 = stwo_m31_mul(r4, r30);
    out_cols[3u][row] = r30;
    lookup_words[171u * row_count + row] = r30;
    unsigned r1192 = stwo_m31_add(r1190, r1191);
    unsigned r1193 = stwo_m31_mul(r2, r130);
    out_cols[13u][row] = r130;
    lookup_words[181u * row_count + row] = r130;
    unsigned r1194 = stwo_m31_add(r1192, r1193);
    unsigned r1195 = stwo_m31_mul(r3, r230);
    unsigned r1196 = stwo_m31_add(r1194, r1195);
    unsigned r1197 = stwo_m31_add(r1196, r330);
    unsigned r1198 = stwo_m31_sub(r1197, r470);
    unsigned r1199 = stwo_m31_add(r1198, r420);
    out_cols[43u][row] = r420;
    lookup_words[3u * row_count + row] = r420;
    unsigned r1200 = stwo_m31_sub(r1199, r1138);
    unsigned r1201 = stwo_m31_mul(r1200, r5);
    unsigned r1202 = stwo_m31_mul(r4, r41);
    out_cols[4u][row] = r41;
    lookup_words[172u * row_count + row] = r41;
    unsigned r1203 = stwo_m31_add(r1201, r1202);
    unsigned r1204 = stwo_m31_mul(r2, r141);
    out_cols[14u][row] = r141;
    lookup_words[182u * row_count + row] = r141;
    unsigned r1205 = stwo_m31_add(r1203, r1204);
    unsigned r1206 = stwo_m31_mul(r3, r241);
    unsigned r1207 = stwo_m31_add(r1205, r1206);
    unsigned r1208 = stwo_m31_add(r1207, r341);
    unsigned r1209 = stwo_m31_sub(r1208, r471);
    unsigned r1210 = stwo_m31_add(r1209, r421);
    out_cols[44u][row] = r421;
    lookup_words[4u * row_count + row] = r421;
    unsigned r1211 = stwo_m31_sub(r1210, r1142);
    unsigned r1212 = stwo_m31_mul(r1211, r5);
    unsigned r1213 = stwo_m31_mul(r4, r52);
    out_cols[5u][row] = r52;
    lookup_words[173u * row_count + row] = r52;
    unsigned r1214 = stwo_m31_add(r1212, r1213);
    unsigned r1215 = stwo_m31_mul(r2, r152);
    out_cols[15u][row] = r152;
    lookup_words[183u * row_count + row] = r152;
    unsigned r1216 = stwo_m31_add(r1214, r1215);
    unsigned r1217 = stwo_m31_mul(r3, r252);
    unsigned r1218 = stwo_m31_add(r1216, r1217);
    unsigned r1219 = stwo_m31_add(r1218, r352);
    unsigned r1220 = stwo_m31_sub(r1219, r472);
    unsigned r1221 = stwo_m31_add(r1220, r422);
    out_cols[45u][row] = r422;
    lookup_words[5u * row_count + row] = r422;
    unsigned r1222 = stwo_m31_sub(r1221, r1146);
    unsigned r1223 = stwo_m31_mul(r1222, r5);
    unsigned r1224 = stwo_m31_mul(r4, r63);
    out_cols[6u][row] = r63;
    lookup_words[174u * row_count + row] = r63;
    unsigned r1225 = stwo_m31_add(r1223, r1224);
    unsigned r1226 = stwo_m31_mul(r2, r163);
    out_cols[16u][row] = r163;
    lookup_words[184u * row_count + row] = r163;
    unsigned r1227 = stwo_m31_add(r1225, r1226);
    unsigned r1228 = stwo_m31_mul(r3, r263);
    unsigned r1229 = stwo_m31_add(r1227, r1228);
    unsigned r1230 = stwo_m31_add(r1229, r363);
    unsigned r1231 = stwo_m31_sub(r1230, r473);
    unsigned r1232 = stwo_m31_add(r1231, r423);
    out_cols[46u][row] = r423;
    lookup_words[6u * row_count + row] = r423;
    unsigned r1233 = stwo_m31_sub(r1232, r1150);
    unsigned r1234 = stwo_m31_mul(r1233, r5);
    unsigned r1235 = stwo_m31_mul(r4, r74);
    out_cols[7u][row] = r74;
    lookup_words[175u * row_count + row] = r74;
    unsigned r1236 = stwo_m31_add(r1234, r1235);
    unsigned r1237 = stwo_m31_mul(r2, r174);
    out_cols[17u][row] = r174;
    lookup_words[185u * row_count + row] = r174;
    unsigned r1238 = stwo_m31_add(r1236, r1237);
    unsigned r1239 = stwo_m31_mul(r3, r274);
    unsigned r1240 = stwo_m31_add(r1238, r1239);
    unsigned r1241 = stwo_m31_add(r1240, r374);
    unsigned r1242 = stwo_m31_sub(r1241, r474);
    unsigned r1243 = stwo_m31_add(r1242, r424);
    out_cols[47u][row] = r424;
    lookup_words[7u * row_count + row] = r424;
    unsigned r1244 = stwo_m31_sub(r1243, r1154);
    unsigned r1245 = stwo_m31_mul(r1244, r5);
    unsigned r1246 = stwo_m31_mul(r4, r85);
    out_cols[8u][row] = r85;
    lookup_words[176u * row_count + row] = r85;
    unsigned r1247 = stwo_m31_add(r1245, r1246);
    unsigned r1248 = stwo_m31_mul(r2, r185);
    out_cols[18u][row] = r185;
    lookup_words[186u * row_count + row] = r185;
    unsigned r1249 = stwo_m31_add(r1247, r1248);
    unsigned r1250 = stwo_m31_mul(r3, r285);
    unsigned r1251 = stwo_m31_add(r1249, r1250);
    unsigned r1252 = stwo_m31_add(r1251, r385);
    unsigned r1253 = stwo_m31_sub(r1252, r475);
    unsigned r1254 = stwo_m31_add(r1253, r425);
    out_cols[48u][row] = r425;
    lookup_words[8u * row_count + row] = r425;
    unsigned r1255 = stwo_m31_sub(r1254, r1158);
    unsigned r1256 = stwo_m31_mul(r1255, r5);
    unsigned r1257 = stwo_m31_mul(r4, r96);
    out_cols[9u][row] = r96;
    lookup_words[177u * row_count + row] = r96;
    unsigned r1258 = stwo_m31_add(r1256, r1257);
    unsigned r1259 = stwo_m31_mul(r2, r196);
    out_cols[19u][row] = r196;
    lookup_words[187u * row_count + row] = r196;
    unsigned r1260 = stwo_m31_add(r1258, r1259);
    unsigned r1261 = stwo_m31_mul(r3, r296);
    unsigned r1262 = stwo_m31_add(r1260, r1261);
    unsigned r1263 = stwo_m31_add(r1262, r396);
    unsigned r1264 = stwo_m31_sub(r1263, r476);
    unsigned r1265 = stwo_m31_add(r1264, r426);
    out_cols[49u][row] = r426;
    lookup_words[9u * row_count + row] = r426;
    unsigned r1266 = stwo_m31_sub(r1265, r1162);
    unsigned r1267 = stwo_m31_mul(r1179, r6);
    unsigned r1268 = stwo_m31_sub(r1266, r1267);
    unsigned r1269 = stwo_m31_mul(r1268, r5);
    unsigned r1270 = stwo_m31_mul(r4, r107);
    out_cols[10u][row] = r107;
    lookup_words[178u * row_count + row] = r107;
    unsigned r1271 = stwo_m31_add(r1269, r1270);
    unsigned r1272 = stwo_m31_mul(r2, r207);
    out_cols[20u][row] = r207;
    lookup_words[188u * row_count + row] = r207;
    unsigned r1273 = stwo_m31_add(r1271, r1272);
    unsigned r1274 = stwo_m31_mul(r3, r307);
    unsigned r1275 = stwo_m31_add(r1273, r1274);
    unsigned r1276 = stwo_m31_add(r1275, r407);
    unsigned r1277 = stwo_m31_sub(r1276, r477);
    unsigned r1278 = stwo_m31_add(r1277, r427);
    out_cols[50u][row] = r427;
    lookup_words[10u * row_count + row] = r427;
    unsigned r1279 = stwo_m31_sub(r1278, r1166);
    unsigned r1280 = stwo_m31_mul(r1279, r5);
    unsigned r1281 = stwo_m31_add(r1179, r2);
    sub_words[31u * row_count + row] = r1281;
    unsigned r1282 = stwo_m31_add(r1190, r2);
    sub_words[32u * row_count + row] = r1282;
    unsigned r1283 = stwo_m31_add(r1201, r2);
    sub_words[33u * row_count + row] = r1283;
    unsigned r1284 = stwo_m31_add(r1212, r2);
    sub_words[34u * row_count + row] = r1284;
    unsigned r1285 = stwo_m31_add(r1179, r2);
    out_cols[92u][row] = r1179;
    lookup_words[54u * row_count + row] = r1285;
    unsigned r1286 = stwo_m31_add(r1190, r2);
    lookup_words[55u * row_count + row] = r1286;
    unsigned r1287 = stwo_m31_add(r1201, r2);
    lookup_words[56u * row_count + row] = r1287;
    unsigned r1288 = stwo_m31_add(r1212, r2);
    lookup_words[57u * row_count + row] = r1288;
    unsigned r1289 = stwo_m31_add(r1223, r2);
    sub_words[35u * row_count + row] = r1289;
    unsigned r1290 = stwo_m31_add(r1234, r2);
    sub_words[36u * row_count + row] = r1290;
    unsigned r1291 = stwo_m31_add(r1245, r2);
    sub_words[37u * row_count + row] = r1291;
    unsigned r1292 = stwo_m31_add(r1256, r2);
    sub_words[38u * row_count + row] = r1292;
    unsigned r1293 = stwo_m31_add(r1223, r2);
    lookup_words[59u * row_count + row] = r1293;
    unsigned r1294 = stwo_m31_add(r1234, r2);
    lookup_words[60u * row_count + row] = r1294;
    unsigned r1295 = stwo_m31_add(r1245, r2);
    lookup_words[61u * row_count + row] = r1295;
    unsigned r1296 = stwo_m31_add(r1256, r2);
    lookup_words[62u * row_count + row] = r1296;
    unsigned r1297 = stwo_m31_add(r1269, r2);
    sub_words[55u * row_count + row] = r1297;
    unsigned r1298 = stwo_m31_add(r1280, r2);
    sub_words[56u * row_count + row] = r1298;
    unsigned r1299 = stwo_m31_add(r1269, r2);
    lookup_words[64u * row_count + row] = r1299;
    unsigned r1300 = stwo_m31_add(r1280, r2);
    lookup_words[65u * row_count + row] = r1300;
    unsigned r1301 = (r1134 & 511u);
    unsigned r1302 = (r1134 >> 9u);
    unsigned r1303 = (r1302 & 511u);
    unsigned r1304 = (r1134 >> 18u);
    unsigned r1305 = (r1304 & 511u);
    unsigned r1306 = (r1138 & 511u);
    unsigned r1307 = (r1138 >> 9u);
    unsigned r1308 = (r1307 & 511u);
    unsigned r1309 = (r1138 >> 18u);
    unsigned r1310 = (r1309 & 511u);
    unsigned r1311 = (r1142 & 511u);
    unsigned r1312 = (r1142 >> 9u);
    unsigned r1313 = (r1312 & 511u);
    unsigned r1314 = (r1142 >> 18u);
    unsigned r1315 = (r1314 & 511u);
    unsigned r1316 = (r1146 & 511u);
    unsigned r1317 = (r1146 >> 9u);
    unsigned r1318 = (r1317 & 511u);
    unsigned r1319 = (r1146 >> 18u);
    unsigned r1320 = (r1319 & 511u);
    unsigned r1321 = (r1150 & 511u);
    unsigned r1322 = (r1150 >> 9u);
    unsigned r1323 = (r1322 & 511u);
    unsigned r1324 = (r1150 >> 18u);
    unsigned r1325 = (r1324 & 511u);
    unsigned r1326 = (r1154 & 511u);
    unsigned r1327 = (r1154 >> 9u);
    unsigned r1328 = (r1327 & 511u);
    unsigned r1329 = (r1154 >> 18u);
    unsigned r1330 = (r1329 & 511u);
    unsigned r1331 = (r1158 & 511u);
    unsigned r1332 = (r1158 >> 9u);
    unsigned r1333 = (r1332 & 511u);
    unsigned r1334 = (r1158 >> 18u);
    unsigned r1335 = (r1334 & 511u);
    unsigned r1336 = (r1162 & 511u);
    unsigned r1337 = (r1162 >> 9u);
    unsigned r1338 = (r1337 & 511u);
    unsigned r1339 = (r1162 >> 18u);
    unsigned r1340 = (r1339 & 511u);
    unsigned r1341 = (r1166 & 511u);
    unsigned r1342 = (r1166 >> 9u);
    unsigned r1343 = (r1342 & 511u);
    unsigned r1344 = (r1166 >> 18u);
    unsigned r1345 = (r1344 & 511u);
    unsigned r1346 = (r1130 & 511u);
    out_cols[91u][row] = r1130;
    sub_words[70u * row_count + row] = r1130;
    lookup_words[76u * row_count + row] = r1130;
    const unsigned dargs14[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1301, r1303, r1305, r1306, r1308, r1310, r1311, r1313, r1315, r1316, r1318, r1320, r1321, r1323, r1325, r1326, r1328, r1330, r1331, r1333, r1335, r1336, r1338, r1340, r1341, r1343, r1345, r1346 };
    unsigned douts14[28];
    stwo_wit_deduce_felt_mul(dargs14, douts14);
    unsigned r1347 = douts14[0];
    unsigned r1348 = douts14[1];
    unsigned r1349 = douts14[2];
    unsigned r1350 = douts14[3];
    unsigned r1351 = douts14[4];
    unsigned r1352 = douts14[5];
    unsigned r1353 = douts14[6];
    unsigned r1354 = douts14[7];
    unsigned r1355 = douts14[8];
    unsigned r1356 = douts14[9];
    unsigned r1357 = douts14[10];
    unsigned r1358 = douts14[11];
    unsigned r1359 = douts14[12];
    unsigned r1360 = douts14[13];
    unsigned r1361 = douts14[14];
    unsigned r1362 = douts14[15];
    unsigned r1363 = douts14[16];
    unsigned r1364 = douts14[17];
    unsigned r1365 = douts14[18];
    unsigned r1366 = douts14[19];
    unsigned r1367 = douts14[20];
    unsigned r1368 = douts14[21];
    unsigned r1369 = douts14[22];
    unsigned r1370 = douts14[23];
    unsigned r1371 = douts14[24];
    unsigned r1372 = douts14[25];
    unsigned r1373 = douts14[26];
    unsigned r1374 = douts14[27];
    const unsigned dargs15[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1347, r1348, r1349, r1350, r1351, r1352, r1353, r1354, r1355, r1356, r1357, r1358, r1359, r1360, r1361, r1362, r1363, r1364, r1365, r1366, r1367, r1368, r1369, r1370, r1371, r1372, r1373, r1374 };
    unsigned douts15[28];
    stwo_wit_deduce_felt_add(dargs15, douts15);
    unsigned r1375 = douts15[0];
    unsigned r1376 = douts15[1];
    unsigned r1377 = douts15[2];
    unsigned r1378 = douts15[3];
    unsigned r1379 = douts15[4];
    unsigned r1380 = douts15[5];
    unsigned r1381 = douts15[6];
    unsigned r1382 = douts15[7];
    unsigned r1383 = douts15[8];
    unsigned r1384 = douts15[9];
    unsigned r1385 = douts15[10];
    unsigned r1386 = douts15[11];
    unsigned r1387 = douts15[12];
    unsigned r1388 = douts15[13];
    unsigned r1389 = douts15[14];
    unsigned r1390 = douts15[15];
    unsigned r1391 = douts15[16];
    unsigned r1392 = douts15[17];
    unsigned r1393 = douts15[18];
    unsigned r1394 = douts15[19];
    unsigned r1395 = douts15[20];
    unsigned r1396 = douts15[21];
    unsigned r1397 = douts15[22];
    unsigned r1398 = douts15[23];
    unsigned r1399 = douts15[24];
    unsigned r1400 = douts15[25];
    unsigned r1401 = douts15[26];
    unsigned r1402 = douts15[27];
    unsigned r1403 = stwo_m31_mul(r1376, r7);
    unsigned r1404 = stwo_m31_add(r1375, r1403);
    unsigned r1405 = stwo_m31_mul(r1377, r8);
    unsigned r1406 = stwo_m31_add(r1404, r1405);
    unsigned r1407 = stwo_m31_mul(r1379, r7);
    unsigned r1408 = stwo_m31_add(r1378, r1407);
    unsigned r1409 = stwo_m31_mul(r1380, r8);
    unsigned r1410 = stwo_m31_add(r1408, r1409);
    unsigned r1411 = stwo_m31_mul(r1382, r7);
    unsigned r1412 = stwo_m31_add(r1381, r1411);
    unsigned r1413 = stwo_m31_mul(r1383, r8);
    unsigned r1414 = stwo_m31_add(r1412, r1413);
    unsigned r1415 = stwo_m31_mul(r1385, r7);
    unsigned r1416 = stwo_m31_add(r1384, r1415);
    unsigned r1417 = stwo_m31_mul(r1386, r8);
    unsigned r1418 = stwo_m31_add(r1416, r1417);
    unsigned r1419 = stwo_m31_mul(r1388, r7);
    unsigned r1420 = stwo_m31_add(r1387, r1419);
    unsigned r1421 = stwo_m31_mul(r1389, r8);
    unsigned r1422 = stwo_m31_add(r1420, r1421);
    unsigned r1423 = stwo_m31_mul(r1391, r7);
    unsigned r1424 = stwo_m31_add(r1390, r1423);
    unsigned r1425 = stwo_m31_mul(r1392, r8);
    unsigned r1426 = stwo_m31_add(r1424, r1425);
    unsigned r1427 = stwo_m31_mul(r1394, r7);
    unsigned r1428 = stwo_m31_add(r1393, r1427);
    unsigned r1429 = stwo_m31_mul(r1395, r8);
    unsigned r1430 = stwo_m31_add(r1428, r1429);
    unsigned r1431 = stwo_m31_mul(r1397, r7);
    unsigned r1432 = stwo_m31_add(r1396, r1431);
    unsigned r1433 = stwo_m31_mul(r1398, r8);
    unsigned r1434 = stwo_m31_add(r1432, r1433);
    unsigned r1435 = stwo_m31_mul(r1400, r7);
    unsigned r1436 = stwo_m31_add(r1399, r1435);
    unsigned r1437 = stwo_m31_mul(r1401, r8);
    unsigned r1438 = stwo_m31_add(r1436, r1437);
    unsigned r1439 = stwo_m31_mul(r2, r1134);
    unsigned r1440 = stwo_m31_sub(r1439, r1406);
    unsigned r1441 = stwo_m31_add(r1440, r9);
    unsigned r1442 = (r1441 & 65535u);
    unsigned r1443 = (r1442 % STWO_M31_P);
    unsigned r1444 = stwo_m31_sub(r1443, r1);
    unsigned r1445 = stwo_m31_mul(r2, r1134);
    out_cols[82u][row] = r1134;
    sub_words[61u * row_count + row] = r1134;
    lookup_words[67u * row_count + row] = r1134;
    unsigned r1446 = stwo_m31_sub(r1445, r1406);
    unsigned r1447 = stwo_m31_sub(r1446, r1444);
    unsigned r1448 = stwo_m31_mul(r1447, r5);
    unsigned r1449 = stwo_m31_mul(r2, r1138);
    out_cols[83u][row] = r1138;
    sub_words[62u * row_count + row] = r1138;
    lookup_words[68u * row_count + row] = r1138;
    unsigned r1450 = stwo_m31_add(r1448, r1449);
    unsigned r1451 = stwo_m31_sub(r1450, r1410);
    unsigned r1452 = stwo_m31_mul(r1451, r5);
    unsigned r1453 = stwo_m31_mul(r2, r1142);
    out_cols[84u][row] = r1142;
    sub_words[63u * row_count + row] = r1142;
    lookup_words[69u * row_count + row] = r1142;
    unsigned r1454 = stwo_m31_add(r1452, r1453);
    unsigned r1455 = stwo_m31_sub(r1454, r1414);
    unsigned r1456 = stwo_m31_mul(r1455, r5);
    unsigned r1457 = stwo_m31_mul(r2, r1146);
    out_cols[85u][row] = r1146;
    sub_words[64u * row_count + row] = r1146;
    lookup_words[70u * row_count + row] = r1146;
    unsigned r1458 = stwo_m31_add(r1456, r1457);
    unsigned r1459 = stwo_m31_sub(r1458, r1418);
    unsigned r1460 = stwo_m31_mul(r1459, r5);
    unsigned r1461 = stwo_m31_mul(r2, r1150);
    out_cols[86u][row] = r1150;
    sub_words[65u * row_count + row] = r1150;
    lookup_words[71u * row_count + row] = r1150;
    unsigned r1462 = stwo_m31_add(r1460, r1461);
    unsigned r1463 = stwo_m31_sub(r1462, r1422);
    unsigned r1464 = stwo_m31_mul(r1463, r5);
    unsigned r1465 = stwo_m31_mul(r2, r1154);
    out_cols[87u][row] = r1154;
    sub_words[66u * row_count + row] = r1154;
    lookup_words[72u * row_count + row] = r1154;
    unsigned r1466 = stwo_m31_add(r1464, r1465);
    unsigned r1467 = stwo_m31_sub(r1466, r1426);
    unsigned r1468 = stwo_m31_mul(r1467, r5);
    unsigned r1469 = stwo_m31_mul(r2, r1158);
    out_cols[88u][row] = r1158;
    sub_words[67u * row_count + row] = r1158;
    lookup_words[73u * row_count + row] = r1158;
    unsigned r1470 = stwo_m31_add(r1468, r1469);
    unsigned r1471 = stwo_m31_sub(r1470, r1430);
    unsigned r1472 = stwo_m31_mul(r1471, r5);
    unsigned r1473 = stwo_m31_mul(r2, r1162);
    out_cols[89u][row] = r1162;
    sub_words[68u * row_count + row] = r1162;
    lookup_words[74u * row_count + row] = r1162;
    unsigned r1474 = stwo_m31_add(r1472, r1473);
    unsigned r1475 = stwo_m31_sub(r1474, r1434);
    unsigned r1476 = stwo_m31_mul(r1444, r6);
    out_cols[103u][row] = r1444;
    unsigned r1477 = stwo_m31_sub(r1475, r1476);
    unsigned r1478 = stwo_m31_mul(r1477, r5);
    unsigned r1479 = stwo_m31_mul(r2, r1166);
    out_cols[90u][row] = r1166;
    sub_words[69u * row_count + row] = r1166;
    lookup_words[75u * row_count + row] = r1166;
    unsigned r1480 = stwo_m31_add(r1478, r1479);
    unsigned r1481 = stwo_m31_sub(r1480, r1438);
    unsigned r1482 = stwo_m31_mul(r1481, r5);
    const unsigned dargs16[10] = { r1406, r1410, r1414, r1418, r1422, r1426, r1430, r1434, r1438, r1402 };
    unsigned douts16[10];
    stwo_wit_deduce_cube_252(dargs16, douts16);
    unsigned r1483 = douts16[0];
    unsigned r1484 = douts16[1];
    unsigned r1485 = douts16[2];
    unsigned r1486 = douts16[3];
    unsigned r1487 = douts16[4];
    unsigned r1488 = douts16[5];
    unsigned r1489 = douts16[6];
    unsigned r1490 = douts16[7];
    unsigned r1491 = douts16[8];
    unsigned r1492 = douts16[9];
    unsigned r1493 = input_cols[22u][row];
    unsigned r1494 = input_cols[23u][row];
    unsigned r1495 = input_cols[24u][row];
    unsigned r1496 = input_cols[25u][row];
    unsigned r1497 = input_cols[26u][row];
    unsigned r1498 = input_cols[27u][row];
    unsigned r1499 = input_cols[28u][row];
    unsigned r1500 = input_cols[29u][row];
    unsigned r1501 = input_cols[30u][row];
    unsigned r1502 = input_cols[31u][row];
    unsigned r1503 = (r1493 & 511u);
    unsigned r1504 = (r1493 >> 9u);
    unsigned r1505 = (r1504 & 511u);
    unsigned r1506 = (r1493 >> 18u);
    unsigned r1507 = (r1506 & 511u);
    unsigned r1508 = (r1494 & 511u);
    unsigned r1509 = (r1494 >> 9u);
    unsigned r1510 = (r1509 & 511u);
    unsigned r1511 = (r1494 >> 18u);
    unsigned r1512 = (r1511 & 511u);
    unsigned r1513 = (r1495 & 511u);
    unsigned r1514 = (r1495 >> 9u);
    unsigned r1515 = (r1514 & 511u);
    unsigned r1516 = (r1495 >> 18u);
    unsigned r1517 = (r1516 & 511u);
    unsigned r1518 = (r1496 & 511u);
    unsigned r1519 = (r1496 >> 9u);
    unsigned r1520 = (r1519 & 511u);
    unsigned r1521 = (r1496 >> 18u);
    unsigned r1522 = (r1521 & 511u);
    unsigned r1523 = (r1497 & 511u);
    unsigned r1524 = (r1497 >> 9u);
    unsigned r1525 = (r1524 & 511u);
    unsigned r1526 = (r1497 >> 18u);
    unsigned r1527 = (r1526 & 511u);
    unsigned r1528 = (r1498 & 511u);
    unsigned r1529 = (r1498 >> 9u);
    unsigned r1530 = (r1529 & 511u);
    unsigned r1531 = (r1498 >> 18u);
    unsigned r1532 = (r1531 & 511u);
    unsigned r1533 = (r1499 & 511u);
    unsigned r1534 = (r1499 >> 9u);
    unsigned r1535 = (r1534 & 511u);
    unsigned r1536 = (r1499 >> 18u);
    unsigned r1537 = (r1536 & 511u);
    unsigned r1538 = (r1500 & 511u);
    unsigned r1539 = (r1500 >> 9u);
    unsigned r1540 = (r1539 & 511u);
    unsigned r1541 = (r1500 >> 18u);
    unsigned r1542 = (r1541 & 511u);
    unsigned r1543 = (r1501 & 511u);
    unsigned r1544 = (r1501 >> 9u);
    unsigned r1545 = (r1544 & 511u);
    unsigned r1546 = (r1501 >> 18u);
    unsigned r1547 = (r1546 & 511u);
    unsigned r1548 = (r1502 & 511u);
    const unsigned dargs17[56] = { r4, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1503, r1505, r1507, r1508, r1510, r1512, r1513, r1515, r1517, r1518, r1520, r1522, r1523, r1525, r1527, r1528, r1530, r1532, r1533, r1535, r1537, r1538, r1540, r1542, r1543, r1545, r1547, r1548 };
    unsigned douts17[28];
    stwo_wit_deduce_felt_mul(dargs17, douts17);
    unsigned r1549 = douts17[0];
    unsigned r1550 = douts17[1];
    unsigned r1551 = douts17[2];
    unsigned r1552 = douts17[3];
    unsigned r1553 = douts17[4];
    unsigned r1554 = douts17[5];
    unsigned r1555 = douts17[6];
    unsigned r1556 = douts17[7];
    unsigned r1557 = douts17[8];
    unsigned r1558 = douts17[9];
    unsigned r1559 = douts17[10];
    unsigned r1560 = douts17[11];
    unsigned r1561 = douts17[12];
    unsigned r1562 = douts17[13];
    unsigned r1563 = douts17[14];
    unsigned r1564 = douts17[15];
    unsigned r1565 = douts17[16];
    unsigned r1566 = douts17[17];
    unsigned r1567 = douts17[18];
    unsigned r1568 = douts17[19];
    unsigned r1569 = douts17[20];
    unsigned r1570 = douts17[21];
    unsigned r1571 = douts17[22];
    unsigned r1572 = douts17[23];
    unsigned r1573 = douts17[24];
    unsigned r1574 = douts17[25];
    unsigned r1575 = douts17[26];
    unsigned r1576 = douts17[27];
    const unsigned dargs18[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1549, r1550, r1551, r1552, r1553, r1554, r1555, r1556, r1557, r1558, r1559, r1560, r1561, r1562, r1563, r1564, r1565, r1566, r1567, r1568, r1569, r1570, r1571, r1572, r1573, r1574, r1575, r1576 };
    unsigned douts18[28];
    stwo_wit_deduce_felt_add(dargs18, douts18);
    unsigned r1577 = douts18[0];
    unsigned r1578 = douts18[1];
    unsigned r1579 = douts18[2];
    unsigned r1580 = douts18[3];
    unsigned r1581 = douts18[4];
    unsigned r1582 = douts18[5];
    unsigned r1583 = douts18[6];
    unsigned r1584 = douts18[7];
    unsigned r1585 = douts18[8];
    unsigned r1586 = douts18[9];
    unsigned r1587 = douts18[10];
    unsigned r1588 = douts18[11];
    unsigned r1589 = douts18[12];
    unsigned r1590 = douts18[13];
    unsigned r1591 = douts18[14];
    unsigned r1592 = douts18[15];
    unsigned r1593 = douts18[16];
    unsigned r1594 = douts18[17];
    unsigned r1595 = douts18[18];
    unsigned r1596 = douts18[19];
    unsigned r1597 = douts18[20];
    unsigned r1598 = douts18[21];
    unsigned r1599 = douts18[22];
    unsigned r1600 = douts18[23];
    unsigned r1601 = douts18[24];
    unsigned r1602 = douts18[25];
    unsigned r1603 = douts18[26];
    unsigned r1604 = douts18[27];
    unsigned r1605 = input_cols[32u][row];
    unsigned r1606 = input_cols[33u][row];
    unsigned r1607 = input_cols[34u][row];
    unsigned r1608 = input_cols[35u][row];
    unsigned r1609 = input_cols[36u][row];
    unsigned r1610 = input_cols[37u][row];
    unsigned r1611 = input_cols[38u][row];
    unsigned r1612 = input_cols[39u][row];
    unsigned r1613 = input_cols[40u][row];
    unsigned r1614 = input_cols[41u][row];
    unsigned r1615 = (r1605 & 511u);
    unsigned r1616 = (r1605 >> 9u);
    unsigned r1617 = (r1616 & 511u);
    unsigned r1618 = (r1605 >> 18u);
    unsigned r1619 = (r1618 & 511u);
    unsigned r1620 = (r1606 & 511u);
    unsigned r1621 = (r1606 >> 9u);
    unsigned r1622 = (r1621 & 511u);
    unsigned r1623 = (r1606 >> 18u);
    unsigned r1624 = (r1623 & 511u);
    unsigned r1625 = (r1607 & 511u);
    unsigned r1626 = (r1607 >> 9u);
    unsigned r1627 = (r1626 & 511u);
    unsigned r1628 = (r1607 >> 18u);
    unsigned r1629 = (r1628 & 511u);
    unsigned r1630 = (r1608 & 511u);
    unsigned r1631 = (r1608 >> 9u);
    unsigned r1632 = (r1631 & 511u);
    unsigned r1633 = (r1608 >> 18u);
    unsigned r1634 = (r1633 & 511u);
    unsigned r1635 = (r1609 & 511u);
    unsigned r1636 = (r1609 >> 9u);
    unsigned r1637 = (r1636 & 511u);
    unsigned r1638 = (r1609 >> 18u);
    unsigned r1639 = (r1638 & 511u);
    unsigned r1640 = (r1610 & 511u);
    unsigned r1641 = (r1610 >> 9u);
    unsigned r1642 = (r1641 & 511u);
    unsigned r1643 = (r1610 >> 18u);
    unsigned r1644 = (r1643 & 511u);
    unsigned r1645 = (r1611 & 511u);
    unsigned r1646 = (r1611 >> 9u);
    unsigned r1647 = (r1646 & 511u);
    unsigned r1648 = (r1611 >> 18u);
    unsigned r1649 = (r1648 & 511u);
    unsigned r1650 = (r1612 & 511u);
    unsigned r1651 = (r1612 >> 9u);
    unsigned r1652 = (r1651 & 511u);
    unsigned r1653 = (r1612 >> 18u);
    unsigned r1654 = (r1653 & 511u);
    unsigned r1655 = (r1613 & 511u);
    unsigned r1656 = (r1613 >> 9u);
    unsigned r1657 = (r1656 & 511u);
    unsigned r1658 = (r1613 >> 18u);
    unsigned r1659 = (r1658 & 511u);
    unsigned r1660 = (r1614 & 511u);
    const unsigned dargs19[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1615, r1617, r1619, r1620, r1622, r1624, r1625, r1627, r1629, r1630, r1632, r1634, r1635, r1637, r1639, r1640, r1642, r1644, r1645, r1647, r1649, r1650, r1652, r1654, r1655, r1657, r1659, r1660 };
    unsigned douts19[28];
    stwo_wit_deduce_felt_mul(dargs19, douts19);
    unsigned r1661 = douts19[0];
    unsigned r1662 = douts19[1];
    unsigned r1663 = douts19[2];
    unsigned r1664 = douts19[3];
    unsigned r1665 = douts19[4];
    unsigned r1666 = douts19[5];
    unsigned r1667 = douts19[6];
    unsigned r1668 = douts19[7];
    unsigned r1669 = douts19[8];
    unsigned r1670 = douts19[9];
    unsigned r1671 = douts19[10];
    unsigned r1672 = douts19[11];
    unsigned r1673 = douts19[12];
    unsigned r1674 = douts19[13];
    unsigned r1675 = douts19[14];
    unsigned r1676 = douts19[15];
    unsigned r1677 = douts19[16];
    unsigned r1678 = douts19[17];
    unsigned r1679 = douts19[18];
    unsigned r1680 = douts19[19];
    unsigned r1681 = douts19[20];
    unsigned r1682 = douts19[21];
    unsigned r1683 = douts19[22];
    unsigned r1684 = douts19[23];
    unsigned r1685 = douts19[24];
    unsigned r1686 = douts19[25];
    unsigned r1687 = douts19[26];
    unsigned r1688 = douts19[27];
    const unsigned dargs20[56] = { r1577, r1578, r1579, r1580, r1581, r1582, r1583, r1584, r1585, r1586, r1587, r1588, r1589, r1590, r1591, r1592, r1593, r1594, r1595, r1596, r1597, r1598, r1599, r1600, r1601, r1602, r1603, r1604, r1661, r1662, r1663, r1664, r1665, r1666, r1667, r1668, r1669, r1670, r1671, r1672, r1673, r1674, r1675, r1676, r1677, r1678, r1679, r1680, r1681, r1682, r1683, r1684, r1685, r1686, r1687, r1688 };
    unsigned douts20[28];
    stwo_wit_deduce_felt_add(dargs20, douts20);
    unsigned r1689 = douts20[0];
    unsigned r1690 = douts20[1];
    unsigned r1691 = douts20[2];
    unsigned r1692 = douts20[3];
    unsigned r1693 = douts20[4];
    unsigned r1694 = douts20[5];
    unsigned r1695 = douts20[6];
    unsigned r1696 = douts20[7];
    unsigned r1697 = douts20[8];
    unsigned r1698 = douts20[9];
    unsigned r1699 = douts20[10];
    unsigned r1700 = douts20[11];
    unsigned r1701 = douts20[12];
    unsigned r1702 = douts20[13];
    unsigned r1703 = douts20[14];
    unsigned r1704 = douts20[15];
    unsigned r1705 = douts20[16];
    unsigned r1706 = douts20[17];
    unsigned r1707 = douts20[18];
    unsigned r1708 = douts20[19];
    unsigned r1709 = douts20[20];
    unsigned r1710 = douts20[21];
    unsigned r1711 = douts20[22];
    unsigned r1712 = douts20[23];
    unsigned r1713 = douts20[24];
    unsigned r1714 = douts20[25];
    unsigned r1715 = douts20[26];
    unsigned r1716 = douts20[27];
    unsigned r1717 = (r469 & 511u);
    unsigned r1718 = (r469 >> 9u);
    unsigned r1719 = (r1718 & 511u);
    unsigned r1720 = (r469 >> 18u);
    unsigned r1721 = (r1720 & 511u);
    unsigned r1722 = (r470 & 511u);
    unsigned r1723 = (r470 >> 9u);
    unsigned r1724 = (r1723 & 511u);
    unsigned r1725 = (r470 >> 18u);
    unsigned r1726 = (r1725 & 511u);
    unsigned r1727 = (r471 & 511u);
    unsigned r1728 = (r471 >> 9u);
    unsigned r1729 = (r1728 & 511u);
    unsigned r1730 = (r471 >> 18u);
    unsigned r1731 = (r1730 & 511u);
    unsigned r1732 = (r472 & 511u);
    unsigned r1733 = (r472 >> 9u);
    unsigned r1734 = (r1733 & 511u);
    unsigned r1735 = (r472 >> 18u);
    unsigned r1736 = (r1735 & 511u);
    unsigned r1737 = (r473 & 511u);
    unsigned r1738 = (r473 >> 9u);
    unsigned r1739 = (r1738 & 511u);
    unsigned r1740 = (r473 >> 18u);
    unsigned r1741 = (r1740 & 511u);
    unsigned r1742 = (r474 & 511u);
    unsigned r1743 = (r474 >> 9u);
    unsigned r1744 = (r1743 & 511u);
    unsigned r1745 = (r474 >> 18u);
    unsigned r1746 = (r1745 & 511u);
    unsigned r1747 = (r475 & 511u);
    unsigned r1748 = (r475 >> 9u);
    unsigned r1749 = (r1748 & 511u);
    unsigned r1750 = (r475 >> 18u);
    unsigned r1751 = (r1750 & 511u);
    unsigned r1752 = (r476 & 511u);
    unsigned r1753 = (r476 >> 9u);
    unsigned r1754 = (r1753 & 511u);
    unsigned r1755 = (r476 >> 18u);
    unsigned r1756 = (r1755 & 511u);
    unsigned r1757 = (r477 & 511u);
    unsigned r1758 = (r477 >> 9u);
    unsigned r1759 = (r1758 & 511u);
    unsigned r1760 = (r477 >> 18u);
    unsigned r1761 = (r1760 & 511u);
    unsigned r1762 = (r478 & 511u);
    const unsigned dargs21[56] = { r3, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1717, r1719, r1721, r1722, r1724, r1726, r1727, r1729, r1731, r1732, r1734, r1736, r1737, r1739, r1741, r1742, r1744, r1746, r1747, r1749, r1751, r1752, r1754, r1756, r1757, r1759, r1761, r1762 };
    unsigned douts21[28];
    stwo_wit_deduce_felt_mul(dargs21, douts21);
    unsigned r1763 = douts21[0];
    unsigned r1764 = douts21[1];
    unsigned r1765 = douts21[2];
    unsigned r1766 = douts21[3];
    unsigned r1767 = douts21[4];
    unsigned r1768 = douts21[5];
    unsigned r1769 = douts21[6];
    unsigned r1770 = douts21[7];
    unsigned r1771 = douts21[8];
    unsigned r1772 = douts21[9];
    unsigned r1773 = douts21[10];
    unsigned r1774 = douts21[11];
    unsigned r1775 = douts21[12];
    unsigned r1776 = douts21[13];
    unsigned r1777 = douts21[14];
    unsigned r1778 = douts21[15];
    unsigned r1779 = douts21[16];
    unsigned r1780 = douts21[17];
    unsigned r1781 = douts21[18];
    unsigned r1782 = douts21[19];
    unsigned r1783 = douts21[20];
    unsigned r1784 = douts21[21];
    unsigned r1785 = douts21[22];
    unsigned r1786 = douts21[23];
    unsigned r1787 = douts21[24];
    unsigned r1788 = douts21[25];
    unsigned r1789 = douts21[26];
    unsigned r1790 = douts21[27];
    const unsigned dargs22[56] = { r1689, r1690, r1691, r1692, r1693, r1694, r1695, r1696, r1697, r1698, r1699, r1700, r1701, r1702, r1703, r1704, r1705, r1706, r1707, r1708, r1709, r1710, r1711, r1712, r1713, r1714, r1715, r1716, r1763, r1764, r1765, r1766, r1767, r1768, r1769, r1770, r1771, r1772, r1773, r1774, r1775, r1776, r1777, r1778, r1779, r1780, r1781, r1782, r1783, r1784, r1785, r1786, r1787, r1788, r1789, r1790 };
    unsigned douts22[28];
    stwo_wit_deduce_felt_add(dargs22, douts22);
    unsigned r1791 = douts22[0];
    unsigned r1792 = douts22[1];
    unsigned r1793 = douts22[2];
    unsigned r1794 = douts22[3];
    unsigned r1795 = douts22[4];
    unsigned r1796 = douts22[5];
    unsigned r1797 = douts22[6];
    unsigned r1798 = douts22[7];
    unsigned r1799 = douts22[8];
    unsigned r1800 = douts22[9];
    unsigned r1801 = douts22[10];
    unsigned r1802 = douts22[11];
    unsigned r1803 = douts22[12];
    unsigned r1804 = douts22[13];
    unsigned r1805 = douts22[14];
    unsigned r1806 = douts22[15];
    unsigned r1807 = douts22[16];
    unsigned r1808 = douts22[17];
    unsigned r1809 = douts22[18];
    unsigned r1810 = douts22[19];
    unsigned r1811 = douts22[20];
    unsigned r1812 = douts22[21];
    unsigned r1813 = douts22[22];
    unsigned r1814 = douts22[23];
    unsigned r1815 = douts22[24];
    unsigned r1816 = douts22[25];
    unsigned r1817 = douts22[26];
    unsigned r1818 = douts22[27];
    unsigned r1819 = (r1406 & 511u);
    unsigned r1820 = (r1406 >> 9u);
    unsigned r1821 = (r1820 & 511u);
    unsigned r1822 = (r1406 >> 18u);
    unsigned r1823 = (r1822 & 511u);
    unsigned r1824 = (r1410 & 511u);
    unsigned r1825 = (r1410 >> 9u);
    unsigned r1826 = (r1825 & 511u);
    unsigned r1827 = (r1410 >> 18u);
    unsigned r1828 = (r1827 & 511u);
    unsigned r1829 = (r1414 & 511u);
    unsigned r1830 = (r1414 >> 9u);
    unsigned r1831 = (r1830 & 511u);
    unsigned r1832 = (r1414 >> 18u);
    unsigned r1833 = (r1832 & 511u);
    unsigned r1834 = (r1418 & 511u);
    unsigned r1835 = (r1418 >> 9u);
    unsigned r1836 = (r1835 & 511u);
    unsigned r1837 = (r1418 >> 18u);
    unsigned r1838 = (r1837 & 511u);
    unsigned r1839 = (r1422 & 511u);
    unsigned r1840 = (r1422 >> 9u);
    unsigned r1841 = (r1840 & 511u);
    unsigned r1842 = (r1422 >> 18u);
    unsigned r1843 = (r1842 & 511u);
    unsigned r1844 = (r1426 & 511u);
    unsigned r1845 = (r1426 >> 9u);
    unsigned r1846 = (r1845 & 511u);
    unsigned r1847 = (r1426 >> 18u);
    unsigned r1848 = (r1847 & 511u);
    unsigned r1849 = (r1430 & 511u);
    unsigned r1850 = (r1430 >> 9u);
    unsigned r1851 = (r1850 & 511u);
    unsigned r1852 = (r1430 >> 18u);
    unsigned r1853 = (r1852 & 511u);
    unsigned r1854 = (r1434 & 511u);
    unsigned r1855 = (r1434 >> 9u);
    unsigned r1856 = (r1855 & 511u);
    unsigned r1857 = (r1434 >> 18u);
    unsigned r1858 = (r1857 & 511u);
    unsigned r1859 = (r1438 & 511u);
    unsigned r1860 = (r1438 >> 9u);
    unsigned r1861 = (r1860 & 511u);
    unsigned r1862 = (r1438 >> 18u);
    unsigned r1863 = (r1862 & 511u);
    unsigned r1864 = (r1402 & 511u);
    const unsigned dargs23[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1819, r1821, r1823, r1824, r1826, r1828, r1829, r1831, r1833, r1834, r1836, r1838, r1839, r1841, r1843, r1844, r1846, r1848, r1849, r1851, r1853, r1854, r1856, r1858, r1859, r1861, r1863, r1864 };
    unsigned douts23[28];
    stwo_wit_deduce_felt_mul(dargs23, douts23);
    unsigned r1865 = douts23[0];
    unsigned r1866 = douts23[1];
    unsigned r1867 = douts23[2];
    unsigned r1868 = douts23[3];
    unsigned r1869 = douts23[4];
    unsigned r1870 = douts23[5];
    unsigned r1871 = douts23[6];
    unsigned r1872 = douts23[7];
    unsigned r1873 = douts23[8];
    unsigned r1874 = douts23[9];
    unsigned r1875 = douts23[10];
    unsigned r1876 = douts23[11];
    unsigned r1877 = douts23[12];
    unsigned r1878 = douts23[13];
    unsigned r1879 = douts23[14];
    unsigned r1880 = douts23[15];
    unsigned r1881 = douts23[16];
    unsigned r1882 = douts23[17];
    unsigned r1883 = douts23[18];
    unsigned r1884 = douts23[19];
    unsigned r1885 = douts23[20];
    unsigned r1886 = douts23[21];
    unsigned r1887 = douts23[22];
    unsigned r1888 = douts23[23];
    unsigned r1889 = douts23[24];
    unsigned r1890 = douts23[25];
    unsigned r1891 = douts23[26];
    unsigned r1892 = douts23[27];
    const unsigned dargs24[56] = { r1791, r1792, r1793, r1794, r1795, r1796, r1797, r1798, r1799, r1800, r1801, r1802, r1803, r1804, r1805, r1806, r1807, r1808, r1809, r1810, r1811, r1812, r1813, r1814, r1815, r1816, r1817, r1818, r1865, r1866, r1867, r1868, r1869, r1870, r1871, r1872, r1873, r1874, r1875, r1876, r1877, r1878, r1879, r1880, r1881, r1882, r1883, r1884, r1885, r1886, r1887, r1888, r1889, r1890, r1891, r1892 };
    unsigned douts24[28];
    stwo_wit_deduce_felt_add(dargs24, douts24);
    unsigned r1893 = douts24[0];
    unsigned r1894 = douts24[1];
    unsigned r1895 = douts24[2];
    unsigned r1896 = douts24[3];
    unsigned r1897 = douts24[4];
    unsigned r1898 = douts24[5];
    unsigned r1899 = douts24[6];
    unsigned r1900 = douts24[7];
    unsigned r1901 = douts24[8];
    unsigned r1902 = douts24[9];
    unsigned r1903 = douts24[10];
    unsigned r1904 = douts24[11];
    unsigned r1905 = douts24[12];
    unsigned r1906 = douts24[13];
    unsigned r1907 = douts24[14];
    unsigned r1908 = douts24[15];
    unsigned r1909 = douts24[16];
    unsigned r1910 = douts24[17];
    unsigned r1911 = douts24[18];
    unsigned r1912 = douts24[19];
    unsigned r1913 = douts24[20];
    unsigned r1914 = douts24[21];
    unsigned r1915 = douts24[22];
    unsigned r1916 = douts24[23];
    unsigned r1917 = douts24[24];
    unsigned r1918 = douts24[25];
    unsigned r1919 = douts24[26];
    unsigned r1920 = douts24[27];
    unsigned r1921 = (r1483 & 511u);
    unsigned r1922 = (r1483 >> 9u);
    unsigned r1923 = (r1922 & 511u);
    unsigned r1924 = (r1483 >> 18u);
    unsigned r1925 = (r1924 & 511u);
    unsigned r1926 = (r1484 & 511u);
    unsigned r1927 = (r1484 >> 9u);
    unsigned r1928 = (r1927 & 511u);
    unsigned r1929 = (r1484 >> 18u);
    unsigned r1930 = (r1929 & 511u);
    unsigned r1931 = (r1485 & 511u);
    unsigned r1932 = (r1485 >> 9u);
    unsigned r1933 = (r1932 & 511u);
    unsigned r1934 = (r1485 >> 18u);
    unsigned r1935 = (r1934 & 511u);
    unsigned r1936 = (r1486 & 511u);
    unsigned r1937 = (r1486 >> 9u);
    unsigned r1938 = (r1937 & 511u);
    unsigned r1939 = (r1486 >> 18u);
    unsigned r1940 = (r1939 & 511u);
    unsigned r1941 = (r1487 & 511u);
    unsigned r1942 = (r1487 >> 9u);
    unsigned r1943 = (r1942 & 511u);
    unsigned r1944 = (r1487 >> 18u);
    unsigned r1945 = (r1944 & 511u);
    unsigned r1946 = (r1488 & 511u);
    unsigned r1947 = (r1488 >> 9u);
    unsigned r1948 = (r1947 & 511u);
    unsigned r1949 = (r1488 >> 18u);
    unsigned r1950 = (r1949 & 511u);
    unsigned r1951 = (r1489 & 511u);
    unsigned r1952 = (r1489 >> 9u);
    unsigned r1953 = (r1952 & 511u);
    unsigned r1954 = (r1489 >> 18u);
    unsigned r1955 = (r1954 & 511u);
    unsigned r1956 = (r1490 & 511u);
    unsigned r1957 = (r1490 >> 9u);
    unsigned r1958 = (r1957 & 511u);
    unsigned r1959 = (r1490 >> 18u);
    unsigned r1960 = (r1959 & 511u);
    unsigned r1961 = (r1491 & 511u);
    unsigned r1962 = (r1491 >> 9u);
    unsigned r1963 = (r1962 & 511u);
    unsigned r1964 = (r1491 >> 18u);
    unsigned r1965 = (r1964 & 511u);
    unsigned r1966 = (r1492 & 511u);
    const unsigned dargs25[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1921, r1923, r1925, r1926, r1928, r1930, r1931, r1933, r1935, r1936, r1938, r1940, r1941, r1943, r1945, r1946, r1948, r1950, r1951, r1953, r1955, r1956, r1958, r1960, r1961, r1963, r1965, r1966 };
    unsigned douts25[28];
    stwo_wit_deduce_felt_mul(dargs25, douts25);
    unsigned r1967 = douts25[0];
    unsigned r1968 = douts25[1];
    unsigned r1969 = douts25[2];
    unsigned r1970 = douts25[3];
    unsigned r1971 = douts25[4];
    unsigned r1972 = douts25[5];
    unsigned r1973 = douts25[6];
    unsigned r1974 = douts25[7];
    unsigned r1975 = douts25[8];
    unsigned r1976 = douts25[9];
    unsigned r1977 = douts25[10];
    unsigned r1978 = douts25[11];
    unsigned r1979 = douts25[12];
    unsigned r1980 = douts25[13];
    unsigned r1981 = douts25[14];
    unsigned r1982 = douts25[15];
    unsigned r1983 = douts25[16];
    unsigned r1984 = douts25[17];
    unsigned r1985 = douts25[18];
    unsigned r1986 = douts25[19];
    unsigned r1987 = douts25[20];
    unsigned r1988 = douts25[21];
    unsigned r1989 = douts25[22];
    unsigned r1990 = douts25[23];
    unsigned r1991 = douts25[24];
    unsigned r1992 = douts25[25];
    unsigned r1993 = douts25[26];
    unsigned r1994 = douts25[27];
    const unsigned dargs26[56] = { r1893, r1894, r1895, r1896, r1897, r1898, r1899, r1900, r1901, r1902, r1903, r1904, r1905, r1906, r1907, r1908, r1909, r1910, r1911, r1912, r1913, r1914, r1915, r1916, r1917, r1918, r1919, r1920, r1967, r1968, r1969, r1970, r1971, r1972, r1973, r1974, r1975, r1976, r1977, r1978, r1979, r1980, r1981, r1982, r1983, r1984, r1985, r1986, r1987, r1988, r1989, r1990, r1991, r1992, r1993, r1994 };
    unsigned douts26[28];
    stwo_wit_deduce_felt_sub(dargs26, douts26);
    unsigned r1995 = douts26[0];
    unsigned r1996 = douts26[1];
    unsigned r1997 = douts26[2];
    unsigned r1998 = douts26[3];
    unsigned r1999 = douts26[4];
    unsigned r2000 = douts26[5];
    unsigned r2001 = douts26[6];
    unsigned r2002 = douts26[7];
    unsigned r2003 = douts26[8];
    unsigned r2004 = douts26[9];
    unsigned r2005 = douts26[10];
    unsigned r2006 = douts26[11];
    unsigned r2007 = douts26[12];
    unsigned r2008 = douts26[13];
    unsigned r2009 = douts26[14];
    unsigned r2010 = douts26[15];
    unsigned r2011 = douts26[16];
    unsigned r2012 = douts26[17];
    unsigned r2013 = douts26[18];
    unsigned r2014 = douts26[19];
    unsigned r2015 = douts26[20];
    unsigned r2016 = douts26[21];
    unsigned r2017 = douts26[22];
    unsigned r2018 = douts26[23];
    unsigned r2019 = douts26[24];
    unsigned r2020 = douts26[25];
    unsigned r2021 = douts26[26];
    unsigned r2022 = douts26[27];
    unsigned r2023 = (r429 & 511u);
    unsigned r2024 = (r429 >> 9u);
    unsigned r2025 = (r2024 & 511u);
    unsigned r2026 = (r429 >> 18u);
    unsigned r2027 = (r2026 & 511u);
    unsigned r2028 = (r430 & 511u);
    unsigned r2029 = (r430 >> 9u);
    unsigned r2030 = (r2029 & 511u);
    unsigned r2031 = (r430 >> 18u);
    unsigned r2032 = (r2031 & 511u);
    unsigned r2033 = (r431 & 511u);
    unsigned r2034 = (r431 >> 9u);
    unsigned r2035 = (r2034 & 511u);
    unsigned r2036 = (r431 >> 18u);
    unsigned r2037 = (r2036 & 511u);
    unsigned r2038 = (r432 & 511u);
    unsigned r2039 = (r432 >> 9u);
    unsigned r2040 = (r2039 & 511u);
    unsigned r2041 = (r432 >> 18u);
    unsigned r2042 = (r2041 & 511u);
    unsigned r2043 = (r433 & 511u);
    unsigned r2044 = (r433 >> 9u);
    unsigned r2045 = (r2044 & 511u);
    unsigned r2046 = (r433 >> 18u);
    unsigned r2047 = (r2046 & 511u);
    unsigned r2048 = (r434 & 511u);
    unsigned r2049 = (r434 >> 9u);
    unsigned r2050 = (r2049 & 511u);
    unsigned r2051 = (r434 >> 18u);
    unsigned r2052 = (r2051 & 511u);
    unsigned r2053 = (r435 & 511u);
    unsigned r2054 = (r435 >> 9u);
    unsigned r2055 = (r2054 & 511u);
    unsigned r2056 = (r435 >> 18u);
    unsigned r2057 = (r2056 & 511u);
    unsigned r2058 = (r436 & 511u);
    unsigned r2059 = (r436 >> 9u);
    unsigned r2060 = (r2059 & 511u);
    unsigned r2061 = (r436 >> 18u);
    unsigned r2062 = (r2061 & 511u);
    unsigned r2063 = (r437 & 511u);
    unsigned r2064 = (r437 >> 9u);
    unsigned r2065 = (r2064 & 511u);
    unsigned r2066 = (r437 >> 18u);
    unsigned r2067 = (r2066 & 511u);
    unsigned r2068 = (r438 & 511u);
    out_cols[61u][row] = r438;
    lookup_words[21u * row_count + row] = r438;
    const unsigned dargs27[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r2023, r2025, r2027, r2028, r2030, r2032, r2033, r2035, r2037, r2038, r2040, r2042, r2043, r2045, r2047, r2048, r2050, r2052, r2053, r2055, r2057, r2058, r2060, r2062, r2063, r2065, r2067, r2068 };
    unsigned douts27[28];
    stwo_wit_deduce_felt_mul(dargs27, douts27);
    unsigned r2069 = douts27[0];
    unsigned r2070 = douts27[1];
    unsigned r2071 = douts27[2];
    unsigned r2072 = douts27[3];
    unsigned r2073 = douts27[4];
    unsigned r2074 = douts27[5];
    unsigned r2075 = douts27[6];
    unsigned r2076 = douts27[7];
    unsigned r2077 = douts27[8];
    unsigned r2078 = douts27[9];
    unsigned r2079 = douts27[10];
    unsigned r2080 = douts27[11];
    unsigned r2081 = douts27[12];
    unsigned r2082 = douts27[13];
    unsigned r2083 = douts27[14];
    unsigned r2084 = douts27[15];
    unsigned r2085 = douts27[16];
    unsigned r2086 = douts27[17];
    unsigned r2087 = douts27[18];
    unsigned r2088 = douts27[19];
    unsigned r2089 = douts27[20];
    unsigned r2090 = douts27[21];
    unsigned r2091 = douts27[22];
    unsigned r2092 = douts27[23];
    unsigned r2093 = douts27[24];
    unsigned r2094 = douts27[25];
    unsigned r2095 = douts27[26];
    unsigned r2096 = douts27[27];
    const unsigned dargs28[56] = { r1995, r1996, r1997, r1998, r1999, r2000, r2001, r2002, r2003, r2004, r2005, r2006, r2007, r2008, r2009, r2010, r2011, r2012, r2013, r2014, r2015, r2016, r2017, r2018, r2019, r2020, r2021, r2022, r2069, r2070, r2071, r2072, r2073, r2074, r2075, r2076, r2077, r2078, r2079, r2080, r2081, r2082, r2083, r2084, r2085, r2086, r2087, r2088, r2089, r2090, r2091, r2092, r2093, r2094, r2095, r2096 };
    unsigned douts28[28];
    stwo_wit_deduce_felt_add(dargs28, douts28);
    unsigned r2097 = douts28[0];
    unsigned r2098 = douts28[1];
    unsigned r2099 = douts28[2];
    unsigned r2100 = douts28[3];
    unsigned r2101 = douts28[4];
    unsigned r2102 = douts28[5];
    unsigned r2103 = douts28[6];
    unsigned r2104 = douts28[7];
    unsigned r2105 = douts28[8];
    unsigned r2106 = douts28[9];
    unsigned r2107 = douts28[10];
    unsigned r2108 = douts28[11];
    unsigned r2109 = douts28[12];
    unsigned r2110 = douts28[13];
    unsigned r2111 = douts28[14];
    unsigned r2112 = douts28[15];
    unsigned r2113 = douts28[16];
    unsigned r2114 = douts28[17];
    unsigned r2115 = douts28[18];
    unsigned r2116 = douts28[19];
    unsigned r2117 = douts28[20];
    unsigned r2118 = douts28[21];
    unsigned r2119 = douts28[22];
    unsigned r2120 = douts28[23];
    unsigned r2121 = douts28[24];
    unsigned r2122 = douts28[25];
    unsigned r2123 = douts28[26];
    unsigned r2124 = douts28[27];
    unsigned r2125 = stwo_m31_mul(r2098, r7);
    unsigned r2126 = stwo_m31_add(r2097, r2125);
    unsigned r2127 = stwo_m31_mul(r2099, r8);
    unsigned r2128 = stwo_m31_add(r2126, r2127);
    unsigned r2129 = stwo_m31_mul(r2101, r7);
    unsigned r2130 = stwo_m31_add(r2100, r2129);
    unsigned r2131 = stwo_m31_mul(r2102, r8);
    unsigned r2132 = stwo_m31_add(r2130, r2131);
    unsigned r2133 = stwo_m31_mul(r2104, r7);
    unsigned r2134 = stwo_m31_add(r2103, r2133);
    unsigned r2135 = stwo_m31_mul(r2105, r8);
    unsigned r2136 = stwo_m31_add(r2134, r2135);
    unsigned r2137 = stwo_m31_mul(r2107, r7);
    unsigned r2138 = stwo_m31_add(r2106, r2137);
    unsigned r2139 = stwo_m31_mul(r2108, r8);
    unsigned r2140 = stwo_m31_add(r2138, r2139);
    unsigned r2141 = stwo_m31_mul(r2110, r7);
    unsigned r2142 = stwo_m31_add(r2109, r2141);
    unsigned r2143 = stwo_m31_mul(r2111, r8);
    unsigned r2144 = stwo_m31_add(r2142, r2143);
    unsigned r2145 = stwo_m31_mul(r2113, r7);
    unsigned r2146 = stwo_m31_add(r2112, r2145);
    unsigned r2147 = stwo_m31_mul(r2114, r8);
    unsigned r2148 = stwo_m31_add(r2146, r2147);
    unsigned r2149 = stwo_m31_mul(r2116, r7);
    unsigned r2150 = stwo_m31_add(r2115, r2149);
    unsigned r2151 = stwo_m31_mul(r2117, r8);
    unsigned r2152 = stwo_m31_add(r2150, r2151);
    unsigned r2153 = stwo_m31_mul(r2119, r7);
    unsigned r2154 = stwo_m31_add(r2118, r2153);
    unsigned r2155 = stwo_m31_mul(r2120, r8);
    unsigned r2156 = stwo_m31_add(r2154, r2155);
    unsigned r2157 = stwo_m31_mul(r2122, r7);
    unsigned r2158 = stwo_m31_add(r2121, r2157);
    unsigned r2159 = stwo_m31_mul(r2123, r8);
    unsigned r2160 = stwo_m31_add(r2158, r2159);
    unsigned r2161 = stwo_m31_mul(r4, r219);
    unsigned r2162 = stwo_m31_mul(r2, r319);
    unsigned r2163 = stwo_m31_add(r2161, r2162);
    unsigned r2164 = stwo_m31_mul(r3, r469);
    unsigned r2165 = stwo_m31_add(r2163, r2164);
    unsigned r2166 = stwo_m31_add(r2165, r1406);
    unsigned r2167 = stwo_m31_sub(r2166, r1483);
    unsigned r2168 = stwo_m31_add(r2167, r429);
    unsigned r2169 = stwo_m31_sub(r2168, r2128);
    unsigned r2170 = stwo_m31_add(r2169, r10);
    unsigned r2171 = (r2170 & 65535u);
    unsigned r2172 = (r2171 % STWO_M31_P);
    unsigned r2173 = stwo_m31_sub(r2172, r2);
    unsigned r2174 = stwo_m31_mul(r4, r219);
    out_cols[22u][row] = r219;
    lookup_words[190u * row_count + row] = r219;
    unsigned r2175 = stwo_m31_mul(r2, r319);
    out_cols[32u][row] = r319;
    lookup_words[33u * row_count + row] = r319;
    lookup_words[200u * row_count + row] = r319;
    unsigned r2176 = stwo_m31_add(r2174, r2175);
    unsigned r2177 = stwo_m31_mul(r3, r469);
    unsigned r2178 = stwo_m31_add(r2176, r2177);
    unsigned r2179 = stwo_m31_add(r2178, r1406);
    unsigned r2180 = stwo_m31_sub(r2179, r1483);
    unsigned r2181 = stwo_m31_add(r2180, r429);
    out_cols[52u][row] = r429;
    lookup_words[12u * row_count + row] = r429;
    unsigned r2182 = stwo_m31_sub(r2181, r2128);
    unsigned r2183 = stwo_m31_sub(r2182, r2173);
    unsigned r2184 = stwo_m31_mul(r2183, r5);
    unsigned r2185 = stwo_m31_mul(r4, r230);
    out_cols[23u][row] = r230;
    lookup_words[191u * row_count + row] = r230;
    unsigned r2186 = stwo_m31_add(r2184, r2185);
    unsigned r2187 = stwo_m31_mul(r2, r330);
    out_cols[33u][row] = r330;
    lookup_words[34u * row_count + row] = r330;
    lookup_words[201u * row_count + row] = r330;
    unsigned r2188 = stwo_m31_add(r2186, r2187);
    unsigned r2189 = stwo_m31_mul(r3, r470);
    unsigned r2190 = stwo_m31_add(r2188, r2189);
    unsigned r2191 = stwo_m31_add(r2190, r1410);
    unsigned r2192 = stwo_m31_sub(r2191, r1484);
    unsigned r2193 = stwo_m31_add(r2192, r430);
    out_cols[53u][row] = r430;
    lookup_words[13u * row_count + row] = r430;
    unsigned r2194 = stwo_m31_sub(r2193, r2132);
    unsigned r2195 = stwo_m31_mul(r2194, r5);
    unsigned r2196 = stwo_m31_mul(r4, r241);
    out_cols[24u][row] = r241;
    lookup_words[192u * row_count + row] = r241;
    unsigned r2197 = stwo_m31_add(r2195, r2196);
    unsigned r2198 = stwo_m31_mul(r2, r341);
    out_cols[34u][row] = r341;
    lookup_words[35u * row_count + row] = r341;
    lookup_words[202u * row_count + row] = r341;
    unsigned r2199 = stwo_m31_add(r2197, r2198);
    unsigned r2200 = stwo_m31_mul(r3, r471);
    unsigned r2201 = stwo_m31_add(r2199, r2200);
    unsigned r2202 = stwo_m31_add(r2201, r1414);
    unsigned r2203 = stwo_m31_sub(r2202, r1485);
    unsigned r2204 = stwo_m31_add(r2203, r431);
    out_cols[54u][row] = r431;
    lookup_words[14u * row_count + row] = r431;
    unsigned r2205 = stwo_m31_sub(r2204, r2136);
    unsigned r2206 = stwo_m31_mul(r2205, r5);
    unsigned r2207 = stwo_m31_mul(r4, r252);
    out_cols[25u][row] = r252;
    lookup_words[193u * row_count + row] = r252;
    unsigned r2208 = stwo_m31_add(r2206, r2207);
    unsigned r2209 = stwo_m31_mul(r2, r352);
    out_cols[35u][row] = r352;
    lookup_words[36u * row_count + row] = r352;
    lookup_words[203u * row_count + row] = r352;
    unsigned r2210 = stwo_m31_add(r2208, r2209);
    unsigned r2211 = stwo_m31_mul(r3, r472);
    unsigned r2212 = stwo_m31_add(r2210, r2211);
    unsigned r2213 = stwo_m31_add(r2212, r1418);
    unsigned r2214 = stwo_m31_sub(r2213, r1486);
    unsigned r2215 = stwo_m31_add(r2214, r432);
    out_cols[55u][row] = r432;
    lookup_words[15u * row_count + row] = r432;
    unsigned r2216 = stwo_m31_sub(r2215, r2140);
    unsigned r2217 = stwo_m31_mul(r2216, r5);
    unsigned r2218 = stwo_m31_mul(r4, r263);
    out_cols[26u][row] = r263;
    lookup_words[194u * row_count + row] = r263;
    unsigned r2219 = stwo_m31_add(r2217, r2218);
    unsigned r2220 = stwo_m31_mul(r2, r363);
    out_cols[36u][row] = r363;
    lookup_words[37u * row_count + row] = r363;
    lookup_words[204u * row_count + row] = r363;
    unsigned r2221 = stwo_m31_add(r2219, r2220);
    unsigned r2222 = stwo_m31_mul(r3, r473);
    unsigned r2223 = stwo_m31_add(r2221, r2222);
    unsigned r2224 = stwo_m31_add(r2223, r1422);
    unsigned r2225 = stwo_m31_sub(r2224, r1487);
    unsigned r2226 = stwo_m31_add(r2225, r433);
    out_cols[56u][row] = r433;
    lookup_words[16u * row_count + row] = r433;
    unsigned r2227 = stwo_m31_sub(r2226, r2144);
    unsigned r2228 = stwo_m31_mul(r2227, r5);
    unsigned r2229 = stwo_m31_mul(r4, r274);
    out_cols[27u][row] = r274;
    lookup_words[195u * row_count + row] = r274;
    unsigned r2230 = stwo_m31_add(r2228, r2229);
    unsigned r2231 = stwo_m31_mul(r2, r374);
    out_cols[37u][row] = r374;
    lookup_words[38u * row_count + row] = r374;
    lookup_words[205u * row_count + row] = r374;
    unsigned r2232 = stwo_m31_add(r2230, r2231);
    unsigned r2233 = stwo_m31_mul(r3, r474);
    unsigned r2234 = stwo_m31_add(r2232, r2233);
    unsigned r2235 = stwo_m31_add(r2234, r1426);
    unsigned r2236 = stwo_m31_sub(r2235, r1488);
    unsigned r2237 = stwo_m31_add(r2236, r434);
    out_cols[57u][row] = r434;
    lookup_words[17u * row_count + row] = r434;
    unsigned r2238 = stwo_m31_sub(r2237, r2148);
    unsigned r2239 = stwo_m31_mul(r2238, r5);
    unsigned r2240 = stwo_m31_mul(r4, r285);
    out_cols[28u][row] = r285;
    lookup_words[196u * row_count + row] = r285;
    unsigned r2241 = stwo_m31_add(r2239, r2240);
    unsigned r2242 = stwo_m31_mul(r2, r385);
    out_cols[38u][row] = r385;
    lookup_words[39u * row_count + row] = r385;
    lookup_words[206u * row_count + row] = r385;
    unsigned r2243 = stwo_m31_add(r2241, r2242);
    unsigned r2244 = stwo_m31_mul(r3, r475);
    unsigned r2245 = stwo_m31_add(r2243, r2244);
    unsigned r2246 = stwo_m31_add(r2245, r1430);
    unsigned r2247 = stwo_m31_sub(r2246, r1489);
    unsigned r2248 = stwo_m31_add(r2247, r435);
    out_cols[58u][row] = r435;
    lookup_words[18u * row_count + row] = r435;
    unsigned r2249 = stwo_m31_sub(r2248, r2152);
    unsigned r2250 = stwo_m31_mul(r2249, r5);
    unsigned r2251 = stwo_m31_mul(r4, r296);
    out_cols[29u][row] = r296;
    lookup_words[197u * row_count + row] = r296;
    unsigned r2252 = stwo_m31_add(r2250, r2251);
    unsigned r2253 = stwo_m31_mul(r2, r396);
    out_cols[39u][row] = r396;
    lookup_words[40u * row_count + row] = r396;
    lookup_words[207u * row_count + row] = r396;
    unsigned r2254 = stwo_m31_add(r2252, r2253);
    unsigned r2255 = stwo_m31_mul(r3, r476);
    unsigned r2256 = stwo_m31_add(r2254, r2255);
    unsigned r2257 = stwo_m31_add(r2256, r1434);
    unsigned r2258 = stwo_m31_sub(r2257, r1490);
    unsigned r2259 = stwo_m31_add(r2258, r436);
    out_cols[59u][row] = r436;
    lookup_words[19u * row_count + row] = r436;
    unsigned r2260 = stwo_m31_sub(r2259, r2156);
    unsigned r2261 = stwo_m31_mul(r2173, r6);
    unsigned r2262 = stwo_m31_sub(r2260, r2261);
    unsigned r2263 = stwo_m31_mul(r2262, r5);
    unsigned r2264 = stwo_m31_mul(r4, r307);
    out_cols[30u][row] = r307;
    lookup_words[198u * row_count + row] = r307;
    unsigned r2265 = stwo_m31_add(r2263, r2264);
    unsigned r2266 = stwo_m31_mul(r2, r407);
    out_cols[40u][row] = r407;
    lookup_words[41u * row_count + row] = r407;
    lookup_words[208u * row_count + row] = r407;
    unsigned r2267 = stwo_m31_add(r2265, r2266);
    unsigned r2268 = stwo_m31_mul(r3, r477);
    unsigned r2269 = stwo_m31_add(r2267, r2268);
    unsigned r2270 = stwo_m31_add(r2269, r1438);
    unsigned r2271 = stwo_m31_sub(r2270, r1491);
    unsigned r2272 = stwo_m31_add(r2271, r437);
    out_cols[60u][row] = r437;
    lookup_words[20u * row_count + row] = r437;
    unsigned r2273 = stwo_m31_sub(r2272, r2160);
    unsigned r2274 = stwo_m31_mul(r2273, r5);
    unsigned r2275 = stwo_m31_add(r2173, r2);
    sub_words[39u * row_count + row] = r2275;
    unsigned r2276 = stwo_m31_add(r2184, r2);
    sub_words[40u * row_count + row] = r2276;
    unsigned r2277 = stwo_m31_add(r2195, r2);
    sub_words[41u * row_count + row] = r2277;
    unsigned r2278 = stwo_m31_add(r2206, r2);
    sub_words[42u * row_count + row] = r2278;
    unsigned r2279 = stwo_m31_add(r2173, r2);
    out_cols[124u][row] = r2173;
    lookup_words[99u * row_count + row] = r2279;
    unsigned r2280 = stwo_m31_add(r2184, r2);
    lookup_words[100u * row_count + row] = r2280;
    unsigned r2281 = stwo_m31_add(r2195, r2);
    lookup_words[101u * row_count + row] = r2281;
    unsigned r2282 = stwo_m31_add(r2206, r2);
    lookup_words[102u * row_count + row] = r2282;
    unsigned r2283 = stwo_m31_add(r2217, r2);
    sub_words[43u * row_count + row] = r2283;
    unsigned r2284 = stwo_m31_add(r2228, r2);
    sub_words[44u * row_count + row] = r2284;
    unsigned r2285 = stwo_m31_add(r2239, r2);
    sub_words[45u * row_count + row] = r2285;
    unsigned r2286 = stwo_m31_add(r2250, r2);
    sub_words[46u * row_count + row] = r2286;
    unsigned r2287 = stwo_m31_add(r2217, r2);
    lookup_words[104u * row_count + row] = r2287;
    unsigned r2288 = stwo_m31_add(r2228, r2);
    lookup_words[105u * row_count + row] = r2288;
    unsigned r2289 = stwo_m31_add(r2239, r2);
    lookup_words[106u * row_count + row] = r2289;
    unsigned r2290 = stwo_m31_add(r2250, r2);
    lookup_words[107u * row_count + row] = r2290;
    unsigned r2291 = stwo_m31_add(r2263, r2);
    sub_words[57u * row_count + row] = r2291;
    unsigned r2292 = stwo_m31_add(r2274, r2);
    sub_words[58u * row_count + row] = r2292;
    unsigned r2293 = stwo_m31_add(r2263, r2);
    lookup_words[109u * row_count + row] = r2293;
    unsigned r2294 = stwo_m31_add(r2274, r2);
    lookup_words[110u * row_count + row] = r2294;
    unsigned r2295 = (r2128 & 511u);
    unsigned r2296 = (r2128 >> 9u);
    unsigned r2297 = (r2296 & 511u);
    unsigned r2298 = (r2128 >> 18u);
    unsigned r2299 = (r2298 & 511u);
    unsigned r2300 = (r2132 & 511u);
    unsigned r2301 = (r2132 >> 9u);
    unsigned r2302 = (r2301 & 511u);
    unsigned r2303 = (r2132 >> 18u);
    unsigned r2304 = (r2303 & 511u);
    unsigned r2305 = (r2136 & 511u);
    unsigned r2306 = (r2136 >> 9u);
    unsigned r2307 = (r2306 & 511u);
    unsigned r2308 = (r2136 >> 18u);
    unsigned r2309 = (r2308 & 511u);
    unsigned r2310 = (r2140 & 511u);
    unsigned r2311 = (r2140 >> 9u);
    unsigned r2312 = (r2311 & 511u);
    unsigned r2313 = (r2140 >> 18u);
    unsigned r2314 = (r2313 & 511u);
    unsigned r2315 = (r2144 & 511u);
    unsigned r2316 = (r2144 >> 9u);
    unsigned r2317 = (r2316 & 511u);
    unsigned r2318 = (r2144 >> 18u);
    unsigned r2319 = (r2318 & 511u);
    unsigned r2320 = (r2148 & 511u);
    unsigned r2321 = (r2148 >> 9u);
    unsigned r2322 = (r2321 & 511u);
    unsigned r2323 = (r2148 >> 18u);
    unsigned r2324 = (r2323 & 511u);
    unsigned r2325 = (r2152 & 511u);
    unsigned r2326 = (r2152 >> 9u);
    unsigned r2327 = (r2326 & 511u);
    unsigned r2328 = (r2152 >> 18u);
    unsigned r2329 = (r2328 & 511u);
    unsigned r2330 = (r2156 & 511u);
    unsigned r2331 = (r2156 >> 9u);
    unsigned r2332 = (r2331 & 511u);
    unsigned r2333 = (r2156 >> 18u);
    unsigned r2334 = (r2333 & 511u);
    unsigned r2335 = (r2160 & 511u);
    unsigned r2336 = (r2160 >> 9u);
    unsigned r2337 = (r2336 & 511u);
    unsigned r2338 = (r2160 >> 18u);
    unsigned r2339 = (r2338 & 511u);
    unsigned r2340 = (r2124 & 511u);
    out_cols[123u][row] = r2124;
    sub_words[80u * row_count + row] = r2124;
    lookup_words[121u * row_count + row] = r2124;
    const unsigned dargs29[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r2295, r2297, r2299, r2300, r2302, r2304, r2305, r2307, r2309, r2310, r2312, r2314, r2315, r2317, r2319, r2320, r2322, r2324, r2325, r2327, r2329, r2330, r2332, r2334, r2335, r2337, r2339, r2340 };
    unsigned douts29[28];
    stwo_wit_deduce_felt_mul(dargs29, douts29);
    unsigned r2341 = douts29[0];
    unsigned r2342 = douts29[1];
    unsigned r2343 = douts29[2];
    unsigned r2344 = douts29[3];
    unsigned r2345 = douts29[4];
    unsigned r2346 = douts29[5];
    unsigned r2347 = douts29[6];
    unsigned r2348 = douts29[7];
    unsigned r2349 = douts29[8];
    unsigned r2350 = douts29[9];
    unsigned r2351 = douts29[10];
    unsigned r2352 = douts29[11];
    unsigned r2353 = douts29[12];
    unsigned r2354 = douts29[13];
    unsigned r2355 = douts29[14];
    unsigned r2356 = douts29[15];
    unsigned r2357 = douts29[16];
    unsigned r2358 = douts29[17];
    unsigned r2359 = douts29[18];
    unsigned r2360 = douts29[19];
    unsigned r2361 = douts29[20];
    unsigned r2362 = douts29[21];
    unsigned r2363 = douts29[22];
    unsigned r2364 = douts29[23];
    unsigned r2365 = douts29[24];
    unsigned r2366 = douts29[25];
    unsigned r2367 = douts29[26];
    unsigned r2368 = douts29[27];
    const unsigned dargs30[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r2341, r2342, r2343, r2344, r2345, r2346, r2347, r2348, r2349, r2350, r2351, r2352, r2353, r2354, r2355, r2356, r2357, r2358, r2359, r2360, r2361, r2362, r2363, r2364, r2365, r2366, r2367, r2368 };
    unsigned douts30[28];
    stwo_wit_deduce_felt_add(dargs30, douts30);
    unsigned r2369 = douts30[0];
    unsigned r2370 = douts30[1];
    unsigned r2371 = douts30[2];
    unsigned r2372 = douts30[3];
    unsigned r2373 = douts30[4];
    unsigned r2374 = douts30[5];
    unsigned r2375 = douts30[6];
    unsigned r2376 = douts30[7];
    unsigned r2377 = douts30[8];
    unsigned r2378 = douts30[9];
    unsigned r2379 = douts30[10];
    unsigned r2380 = douts30[11];
    unsigned r2381 = douts30[12];
    unsigned r2382 = douts30[13];
    unsigned r2383 = douts30[14];
    unsigned r2384 = douts30[15];
    unsigned r2385 = douts30[16];
    unsigned r2386 = douts30[17];
    unsigned r2387 = douts30[18];
    unsigned r2388 = douts30[19];
    unsigned r2389 = douts30[20];
    unsigned r2390 = douts30[21];
    unsigned r2391 = douts30[22];
    unsigned r2392 = douts30[23];
    unsigned r2393 = douts30[24];
    unsigned r2394 = douts30[25];
    unsigned r2395 = douts30[26];
    unsigned r2396 = douts30[27];
    unsigned r2397 = stwo_m31_mul(r2370, r7);
    unsigned r2398 = stwo_m31_add(r2369, r2397);
    unsigned r2399 = stwo_m31_mul(r2371, r8);
    unsigned r2400 = stwo_m31_add(r2398, r2399);
    unsigned r2401 = stwo_m31_mul(r2373, r7);
    unsigned r2402 = stwo_m31_add(r2372, r2401);
    unsigned r2403 = stwo_m31_mul(r2374, r8);
    unsigned r2404 = stwo_m31_add(r2402, r2403);
    unsigned r2405 = stwo_m31_mul(r2376, r7);
    unsigned r2406 = stwo_m31_add(r2375, r2405);
    unsigned r2407 = stwo_m31_mul(r2377, r8);
    unsigned r2408 = stwo_m31_add(r2406, r2407);
    unsigned r2409 = stwo_m31_mul(r2379, r7);
    unsigned r2410 = stwo_m31_add(r2378, r2409);
    unsigned r2411 = stwo_m31_mul(r2380, r8);
    unsigned r2412 = stwo_m31_add(r2410, r2411);
    unsigned r2413 = stwo_m31_mul(r2382, r7);
    unsigned r2414 = stwo_m31_add(r2381, r2413);
    unsigned r2415 = stwo_m31_mul(r2383, r8);
    unsigned r2416 = stwo_m31_add(r2414, r2415);
    unsigned r2417 = stwo_m31_mul(r2385, r7);
    unsigned r2418 = stwo_m31_add(r2384, r2417);
    unsigned r2419 = stwo_m31_mul(r2386, r8);
    unsigned r2420 = stwo_m31_add(r2418, r2419);
    unsigned r2421 = stwo_m31_mul(r2388, r7);
    unsigned r2422 = stwo_m31_add(r2387, r2421);
    unsigned r2423 = stwo_m31_mul(r2389, r8);
    unsigned r2424 = stwo_m31_add(r2422, r2423);
    unsigned r2425 = stwo_m31_mul(r2391, r7);
    unsigned r2426 = stwo_m31_add(r2390, r2425);
    unsigned r2427 = stwo_m31_mul(r2392, r8);
    unsigned r2428 = stwo_m31_add(r2426, r2427);
    unsigned r2429 = stwo_m31_mul(r2394, r7);
    unsigned r2430 = stwo_m31_add(r2393, r2429);
    unsigned r2431 = stwo_m31_mul(r2395, r8);
    unsigned r2432 = stwo_m31_add(r2430, r2431);
    unsigned r2433 = stwo_m31_mul(r2, r2128);
    unsigned r2434 = stwo_m31_sub(r2433, r2400);
    unsigned r2435 = stwo_m31_add(r2434, r9);
    unsigned r2436 = (r2435 & 65535u);
    unsigned r2437 = (r2436 % STWO_M31_P);
    unsigned r2438 = stwo_m31_sub(r2437, r1);
    unsigned r2439 = stwo_m31_mul(r2, r2128);
    out_cols[114u][row] = r2128;
    sub_words[71u * row_count + row] = r2128;
    lookup_words[112u * row_count + row] = r2128;
    unsigned r2440 = stwo_m31_sub(r2439, r2400);
    unsigned r2441 = stwo_m31_sub(r2440, r2438);
    unsigned r2442 = stwo_m31_mul(r2441, r5);
    unsigned r2443 = stwo_m31_mul(r2, r2132);
    out_cols[115u][row] = r2132;
    sub_words[72u * row_count + row] = r2132;
    lookup_words[113u * row_count + row] = r2132;
    unsigned r2444 = stwo_m31_add(r2442, r2443);
    unsigned r2445 = stwo_m31_sub(r2444, r2404);
    unsigned r2446 = stwo_m31_mul(r2445, r5);
    unsigned r2447 = stwo_m31_mul(r2, r2136);
    out_cols[116u][row] = r2136;
    sub_words[73u * row_count + row] = r2136;
    lookup_words[114u * row_count + row] = r2136;
    unsigned r2448 = stwo_m31_add(r2446, r2447);
    unsigned r2449 = stwo_m31_sub(r2448, r2408);
    unsigned r2450 = stwo_m31_mul(r2449, r5);
    unsigned r2451 = stwo_m31_mul(r2, r2140);
    out_cols[117u][row] = r2140;
    sub_words[74u * row_count + row] = r2140;
    lookup_words[115u * row_count + row] = r2140;
    unsigned r2452 = stwo_m31_add(r2450, r2451);
    unsigned r2453 = stwo_m31_sub(r2452, r2412);
    unsigned r2454 = stwo_m31_mul(r2453, r5);
    unsigned r2455 = stwo_m31_mul(r2, r2144);
    out_cols[118u][row] = r2144;
    sub_words[75u * row_count + row] = r2144;
    lookup_words[116u * row_count + row] = r2144;
    unsigned r2456 = stwo_m31_add(r2454, r2455);
    unsigned r2457 = stwo_m31_sub(r2456, r2416);
    unsigned r2458 = stwo_m31_mul(r2457, r5);
    unsigned r2459 = stwo_m31_mul(r2, r2148);
    out_cols[119u][row] = r2148;
    sub_words[76u * row_count + row] = r2148;
    lookup_words[117u * row_count + row] = r2148;
    unsigned r2460 = stwo_m31_add(r2458, r2459);
    unsigned r2461 = stwo_m31_sub(r2460, r2420);
    unsigned r2462 = stwo_m31_mul(r2461, r5);
    unsigned r2463 = stwo_m31_mul(r2, r2152);
    out_cols[120u][row] = r2152;
    sub_words[77u * row_count + row] = r2152;
    lookup_words[118u * row_count + row] = r2152;
    unsigned r2464 = stwo_m31_add(r2462, r2463);
    unsigned r2465 = stwo_m31_sub(r2464, r2424);
    unsigned r2466 = stwo_m31_mul(r2465, r5);
    unsigned r2467 = stwo_m31_mul(r2, r2156);
    out_cols[121u][row] = r2156;
    sub_words[78u * row_count + row] = r2156;
    lookup_words[119u * row_count + row] = r2156;
    unsigned r2468 = stwo_m31_add(r2466, r2467);
    unsigned r2469 = stwo_m31_sub(r2468, r2428);
    unsigned r2470 = stwo_m31_mul(r2438, r6);
    out_cols[135u][row] = r2438;
    unsigned r2471 = stwo_m31_sub(r2469, r2470);
    unsigned r2472 = stwo_m31_mul(r2471, r5);
    unsigned r2473 = stwo_m31_mul(r2, r2160);
    out_cols[122u][row] = r2160;
    sub_words[79u * row_count + row] = r2160;
    lookup_words[120u * row_count + row] = r2160;
    unsigned r2474 = stwo_m31_add(r2472, r2473);
    unsigned r2475 = stwo_m31_sub(r2474, r2432);
    unsigned r2476 = stwo_m31_mul(r2475, r5);
    const unsigned dargs31[10] = { r2400, r2404, r2408, r2412, r2416, r2420, r2424, r2428, r2432, r2396 };
    unsigned douts31[10];
    stwo_wit_deduce_cube_252(dargs31, douts31);
    unsigned r2477 = douts31[0];
    unsigned r2478 = douts31[1];
    unsigned r2479 = douts31[2];
    unsigned r2480 = douts31[3];
    unsigned r2481 = douts31[4];
    unsigned r2482 = douts31[5];
    unsigned r2483 = douts31[6];
    unsigned r2484 = douts31[7];
    unsigned r2485 = douts31[8];
    unsigned r2486 = douts31[9];
    unsigned r2487 = (r469 & 511u);
    unsigned r2488 = (r469 >> 9u);
    unsigned r2489 = (r2488 & 511u);
    unsigned r2490 = (r469 >> 18u);
    unsigned r2491 = (r2490 & 511u);
    unsigned r2492 = (r470 & 511u);
    unsigned r2493 = (r470 >> 9u);
    unsigned r2494 = (r2493 & 511u);
    unsigned r2495 = (r470 >> 18u);
    unsigned r2496 = (r2495 & 511u);
    unsigned r2497 = (r471 & 511u);
    unsigned r2498 = (r471 >> 9u);
    unsigned r2499 = (r2498 & 511u);
    unsigned r2500 = (r471 >> 18u);
    unsigned r2501 = (r2500 & 511u);
    unsigned r2502 = (r472 & 511u);
    unsigned r2503 = (r472 >> 9u);
    unsigned r2504 = (r2503 & 511u);
    unsigned r2505 = (r472 >> 18u);
    unsigned r2506 = (r2505 & 511u);
    unsigned r2507 = (r473 & 511u);
    unsigned r2508 = (r473 >> 9u);
    unsigned r2509 = (r2508 & 511u);
    unsigned r2510 = (r473 >> 18u);
    unsigned r2511 = (r2510 & 511u);
    unsigned r2512 = (r474 & 511u);
    unsigned r2513 = (r474 >> 9u);
    unsigned r2514 = (r2513 & 511u);
    unsigned r2515 = (r474 >> 18u);
    unsigned r2516 = (r2515 & 511u);
    unsigned r2517 = (r475 & 511u);
    unsigned r2518 = (r475 >> 9u);
    unsigned r2519 = (r2518 & 511u);
    unsigned r2520 = (r475 >> 18u);
    unsigned r2521 = (r2520 & 511u);
    unsigned r2522 = (r476 & 511u);
    unsigned r2523 = (r476 >> 9u);
    unsigned r2524 = (r2523 & 511u);
    unsigned r2525 = (r476 >> 18u);
    unsigned r2526 = (r2525 & 511u);
    unsigned r2527 = (r477 & 511u);
    unsigned r2528 = (r477 >> 9u);
    unsigned r2529 = (r2528 & 511u);
    unsigned r2530 = (r477 >> 18u);
    unsigned r2531 = (r2530 & 511u);
    unsigned r2532 = (r478 & 511u);
    out_cols[81u][row] = r478;
    lookup_words[52u * row_count + row] = r478;
    const unsigned dargs32[56] = { r4, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r2487, r2489, r2491, r2492, r2494, r2496, r2497, r2499, r2501, r2502, r2504, r2506, r2507, r2509, r2511, r2512, r2514, r2516, r2517, r2519, r2521, r2522, r2524, r2526, r2527, r2529, r2531, r2532 };
    unsigned douts32[28];
    stwo_wit_deduce_felt_mul(dargs32, douts32);
    unsigned r2533 = douts32[0];
    unsigned r2534 = douts32[1];
    unsigned r2535 = douts32[2];
    unsigned r2536 = douts32[3];
    unsigned r2537 = douts32[4];
    unsigned r2538 = douts32[5];
    unsigned r2539 = douts32[6];
    unsigned r2540 = douts32[7];
    unsigned r2541 = douts32[8];
    unsigned r2542 = douts32[9];
    unsigned r2543 = douts32[10];
    unsigned r2544 = douts32[11];
    unsigned r2545 = douts32[12];
    unsigned r2546 = douts32[13];
    unsigned r2547 = douts32[14];
    unsigned r2548 = douts32[15];
    unsigned r2549 = douts32[16];
    unsigned r2550 = douts32[17];
    unsigned r2551 = douts32[18];
    unsigned r2552 = douts32[19];
    unsigned r2553 = douts32[20];
    unsigned r2554 = douts32[21];
    unsigned r2555 = douts32[22];
    unsigned r2556 = douts32[23];
    unsigned r2557 = douts32[24];
    unsigned r2558 = douts32[25];
    unsigned r2559 = douts32[26];
    unsigned r2560 = douts32[27];
    const unsigned dargs33[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r2533, r2534, r2535, r2536, r2537, r2538, r2539, r2540, r2541, r2542, r2543, r2544, r2545, r2546, r2547, r2548, r2549, r2550, r2551, r2552, r2553, r2554, r2555, r2556, r2557, r2558, r2559, r2560 };
    unsigned douts33[28];
    stwo_wit_deduce_felt_add(dargs33, douts33);
    unsigned r2561 = douts33[0];
    unsigned r2562 = douts33[1];
    unsigned r2563 = douts33[2];
    unsigned r2564 = douts33[3];
    unsigned r2565 = douts33[4];
    unsigned r2566 = douts33[5];
    unsigned r2567 = douts33[6];
    unsigned r2568 = douts33[7];
    unsigned r2569 = douts33[8];
    unsigned r2570 = douts33[9];
    unsigned r2571 = douts33[10];
    unsigned r2572 = douts33[11];
    unsigned r2573 = douts33[12];
    unsigned r2574 = douts33[13];
    unsigned r2575 = douts33[14];
    unsigned r2576 = douts33[15];
    unsigned r2577 = douts33[16];
    unsigned r2578 = douts33[17];
    unsigned r2579 = douts33[18];
    unsigned r2580 = douts33[19];
    unsigned r2581 = douts33[20];
    unsigned r2582 = douts33[21];
    unsigned r2583 = douts33[22];
    unsigned r2584 = douts33[23];
    unsigned r2585 = douts33[24];
    unsigned r2586 = douts33[25];
    unsigned r2587 = douts33[26];
    unsigned r2588 = douts33[27];
    unsigned r2589 = (r1406 & 511u);
    unsigned r2590 = (r1406 >> 9u);
    unsigned r2591 = (r2590 & 511u);
    unsigned r2592 = (r1406 >> 18u);
    unsigned r2593 = (r2592 & 511u);
    unsigned r2594 = (r1410 & 511u);
    unsigned r2595 = (r1410 >> 9u);
    unsigned r2596 = (r2595 & 511u);
    unsigned r2597 = (r1410 >> 18u);
    unsigned r2598 = (r2597 & 511u);
    unsigned r2599 = (r1414 & 511u);
    unsigned r2600 = (r1414 >> 9u);
    unsigned r2601 = (r2600 & 511u);
    unsigned r2602 = (r1414 >> 18u);
    unsigned r2603 = (r2602 & 511u);
    unsigned r2604 = (r1418 & 511u);
    unsigned r2605 = (r1418 >> 9u);
    unsigned r2606 = (r2605 & 511u);
    unsigned r2607 = (r1418 >> 18u);
    unsigned r2608 = (r2607 & 511u);
    unsigned r2609 = (r1422 & 511u);
    unsigned r2610 = (r1422 >> 9u);
    unsigned r2611 = (r2610 & 511u);
    unsigned r2612 = (r1422 >> 18u);
    unsigned r2613 = (r2612 & 511u);
    unsigned r2614 = (r1426 & 511u);
    unsigned r2615 = (r1426 >> 9u);
    unsigned r2616 = (r2615 & 511u);
    unsigned r2617 = (r1426 >> 18u);
    unsigned r2618 = (r2617 & 511u);
    unsigned r2619 = (r1430 & 511u);
    unsigned r2620 = (r1430 >> 9u);
    unsigned r2621 = (r2620 & 511u);
    unsigned r2622 = (r1430 >> 18u);
    unsigned r2623 = (r2622 & 511u);
    unsigned r2624 = (r1434 & 511u);
    unsigned r2625 = (r1434 >> 9u);
    unsigned r2626 = (r2625 & 511u);
    unsigned r2627 = (r1434 >> 18u);
    unsigned r2628 = (r2627 & 511u);
    unsigned r2629 = (r1438 & 511u);
    unsigned r2630 = (r1438 >> 9u);
    unsigned r2631 = (r2630 & 511u);
    unsigned r2632 = (r1438 >> 18u);
    unsigned r2633 = (r2632 & 511u);
    unsigned r2634 = (r1402 & 511u);
    out_cols[102u][row] = r1402;
    sub_words[20u * row_count + row] = r1402;
    lookup_words[87u * row_count + row] = r1402;
    const unsigned dargs34[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r2589, r2591, r2593, r2594, r2596, r2598, r2599, r2601, r2603, r2604, r2606, r2608, r2609, r2611, r2613, r2614, r2616, r2618, r2619, r2621, r2623, r2624, r2626, r2628, r2629, r2631, r2633, r2634 };
    unsigned douts34[28];
    stwo_wit_deduce_felt_mul(dargs34, douts34);
    unsigned r2635 = douts34[0];
    unsigned r2636 = douts34[1];
    unsigned r2637 = douts34[2];
    unsigned r2638 = douts34[3];
    unsigned r2639 = douts34[4];
    unsigned r2640 = douts34[5];
    unsigned r2641 = douts34[6];
    unsigned r2642 = douts34[7];
    unsigned r2643 = douts34[8];
    unsigned r2644 = douts34[9];
    unsigned r2645 = douts34[10];
    unsigned r2646 = douts34[11];
    unsigned r2647 = douts34[12];
    unsigned r2648 = douts34[13];
    unsigned r2649 = douts34[14];
    unsigned r2650 = douts34[15];
    unsigned r2651 = douts34[16];
    unsigned r2652 = douts34[17];
    unsigned r2653 = douts34[18];
    unsigned r2654 = douts34[19];
    unsigned r2655 = douts34[20];
    unsigned r2656 = douts34[21];
    unsigned r2657 = douts34[22];
    unsigned r2658 = douts34[23];
    unsigned r2659 = douts34[24];
    unsigned r2660 = douts34[25];
    unsigned r2661 = douts34[26];
    unsigned r2662 = douts34[27];
    const unsigned dargs35[56] = { r2561, r2562, r2563, r2564, r2565, r2566, r2567, r2568, r2569, r2570, r2571, r2572, r2573, r2574, r2575, r2576, r2577, r2578, r2579, r2580, r2581, r2582, r2583, r2584, r2585, r2586, r2587, r2588, r2635, r2636, r2637, r2638, r2639, r2640, r2641, r2642, r2643, r2644, r2645, r2646, r2647, r2648, r2649, r2650, r2651, r2652, r2653, r2654, r2655, r2656, r2657, r2658, r2659, r2660, r2661, r2662 };
    unsigned douts35[28];
    stwo_wit_deduce_felt_add(dargs35, douts35);
    unsigned r2663 = douts35[0];
    unsigned r2664 = douts35[1];
    unsigned r2665 = douts35[2];
    unsigned r2666 = douts35[3];
    unsigned r2667 = douts35[4];
    unsigned r2668 = douts35[5];
    unsigned r2669 = douts35[6];
    unsigned r2670 = douts35[7];
    unsigned r2671 = douts35[8];
    unsigned r2672 = douts35[9];
    unsigned r2673 = douts35[10];
    unsigned r2674 = douts35[11];
    unsigned r2675 = douts35[12];
    unsigned r2676 = douts35[13];
    unsigned r2677 = douts35[14];
    unsigned r2678 = douts35[15];
    unsigned r2679 = douts35[16];
    unsigned r2680 = douts35[17];
    unsigned r2681 = douts35[18];
    unsigned r2682 = douts35[19];
    unsigned r2683 = douts35[20];
    unsigned r2684 = douts35[21];
    unsigned r2685 = douts35[22];
    unsigned r2686 = douts35[23];
    unsigned r2687 = douts35[24];
    unsigned r2688 = douts35[25];
    unsigned r2689 = douts35[26];
    unsigned r2690 = douts35[27];
    unsigned r2691 = (r1483 & 511u);
    unsigned r2692 = (r1483 >> 9u);
    unsigned r2693 = (r2692 & 511u);
    unsigned r2694 = (r1483 >> 18u);
    unsigned r2695 = (r2694 & 511u);
    unsigned r2696 = (r1484 & 511u);
    unsigned r2697 = (r1484 >> 9u);
    unsigned r2698 = (r2697 & 511u);
    unsigned r2699 = (r1484 >> 18u);
    unsigned r2700 = (r2699 & 511u);
    unsigned r2701 = (r1485 & 511u);
    unsigned r2702 = (r1485 >> 9u);
    unsigned r2703 = (r2702 & 511u);
    unsigned r2704 = (r1485 >> 18u);
    unsigned r2705 = (r2704 & 511u);
    unsigned r2706 = (r1486 & 511u);
    unsigned r2707 = (r1486 >> 9u);
    unsigned r2708 = (r2707 & 511u);
    unsigned r2709 = (r1486 >> 18u);
    unsigned r2710 = (r2709 & 511u);
    unsigned r2711 = (r1487 & 511u);
    unsigned r2712 = (r1487 >> 9u);
    unsigned r2713 = (r2712 & 511u);
    unsigned r2714 = (r1487 >> 18u);
    unsigned r2715 = (r2714 & 511u);
    unsigned r2716 = (r1488 & 511u);
    unsigned r2717 = (r1488 >> 9u);
    unsigned r2718 = (r2717 & 511u);
    unsigned r2719 = (r1488 >> 18u);
    unsigned r2720 = (r2719 & 511u);
    unsigned r2721 = (r1489 & 511u);
    unsigned r2722 = (r1489 >> 9u);
    unsigned r2723 = (r2722 & 511u);
    unsigned r2724 = (r1489 >> 18u);
    unsigned r2725 = (r2724 & 511u);
    unsigned r2726 = (r1490 & 511u);
    unsigned r2727 = (r1490 >> 9u);
    unsigned r2728 = (r2727 & 511u);
    unsigned r2729 = (r1490 >> 18u);
    unsigned r2730 = (r2729 & 511u);
    unsigned r2731 = (r1491 & 511u);
    unsigned r2732 = (r1491 >> 9u);
    unsigned r2733 = (r2732 & 511u);
    unsigned r2734 = (r1491 >> 18u);
    unsigned r2735 = (r2734 & 511u);
    unsigned r2736 = (r1492 & 511u);
    out_cols[113u][row] = r1492;
    lookup_words[97u * row_count + row] = r1492;
    lookup_words[222u * row_count + row] = r1492;
    const unsigned dargs36[56] = { r3, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r2691, r2693, r2695, r2696, r2698, r2700, r2701, r2703, r2705, r2706, r2708, r2710, r2711, r2713, r2715, r2716, r2718, r2720, r2721, r2723, r2725, r2726, r2728, r2730, r2731, r2733, r2735, r2736 };
    unsigned douts36[28];
    stwo_wit_deduce_felt_mul(dargs36, douts36);
    unsigned r2737 = douts36[0];
    unsigned r2738 = douts36[1];
    unsigned r2739 = douts36[2];
    unsigned r2740 = douts36[3];
    unsigned r2741 = douts36[4];
    unsigned r2742 = douts36[5];
    unsigned r2743 = douts36[6];
    unsigned r2744 = douts36[7];
    unsigned r2745 = douts36[8];
    unsigned r2746 = douts36[9];
    unsigned r2747 = douts36[10];
    unsigned r2748 = douts36[11];
    unsigned r2749 = douts36[12];
    unsigned r2750 = douts36[13];
    unsigned r2751 = douts36[14];
    unsigned r2752 = douts36[15];
    unsigned r2753 = douts36[16];
    unsigned r2754 = douts36[17];
    unsigned r2755 = douts36[18];
    unsigned r2756 = douts36[19];
    unsigned r2757 = douts36[20];
    unsigned r2758 = douts36[21];
    unsigned r2759 = douts36[22];
    unsigned r2760 = douts36[23];
    unsigned r2761 = douts36[24];
    unsigned r2762 = douts36[25];
    unsigned r2763 = douts36[26];
    unsigned r2764 = douts36[27];
    const unsigned dargs37[56] = { r2663, r2664, r2665, r2666, r2667, r2668, r2669, r2670, r2671, r2672, r2673, r2674, r2675, r2676, r2677, r2678, r2679, r2680, r2681, r2682, r2683, r2684, r2685, r2686, r2687, r2688, r2689, r2690, r2737, r2738, r2739, r2740, r2741, r2742, r2743, r2744, r2745, r2746, r2747, r2748, r2749, r2750, r2751, r2752, r2753, r2754, r2755, r2756, r2757, r2758, r2759, r2760, r2761, r2762, r2763, r2764 };
    unsigned douts37[28];
    stwo_wit_deduce_felt_add(dargs37, douts37);
    unsigned r2765 = douts37[0];
    unsigned r2766 = douts37[1];
    unsigned r2767 = douts37[2];
    unsigned r2768 = douts37[3];
    unsigned r2769 = douts37[4];
    unsigned r2770 = douts37[5];
    unsigned r2771 = douts37[6];
    unsigned r2772 = douts37[7];
    unsigned r2773 = douts37[8];
    unsigned r2774 = douts37[9];
    unsigned r2775 = douts37[10];
    unsigned r2776 = douts37[11];
    unsigned r2777 = douts37[12];
    unsigned r2778 = douts37[13];
    unsigned r2779 = douts37[14];
    unsigned r2780 = douts37[15];
    unsigned r2781 = douts37[16];
    unsigned r2782 = douts37[17];
    unsigned r2783 = douts37[18];
    unsigned r2784 = douts37[19];
    unsigned r2785 = douts37[20];
    unsigned r2786 = douts37[21];
    unsigned r2787 = douts37[22];
    unsigned r2788 = douts37[23];
    unsigned r2789 = douts37[24];
    unsigned r2790 = douts37[25];
    unsigned r2791 = douts37[26];
    unsigned r2792 = douts37[27];
    unsigned r2793 = (r2400 & 511u);
    unsigned r2794 = (r2400 >> 9u);
    unsigned r2795 = (r2794 & 511u);
    unsigned r2796 = (r2400 >> 18u);
    unsigned r2797 = (r2796 & 511u);
    unsigned r2798 = (r2404 & 511u);
    unsigned r2799 = (r2404 >> 9u);
    unsigned r2800 = (r2799 & 511u);
    unsigned r2801 = (r2404 >> 18u);
    unsigned r2802 = (r2801 & 511u);
    unsigned r2803 = (r2408 & 511u);
    unsigned r2804 = (r2408 >> 9u);
    unsigned r2805 = (r2804 & 511u);
    unsigned r2806 = (r2408 >> 18u);
    unsigned r2807 = (r2806 & 511u);
    unsigned r2808 = (r2412 & 511u);
    unsigned r2809 = (r2412 >> 9u);
    unsigned r2810 = (r2809 & 511u);
    unsigned r2811 = (r2412 >> 18u);
    unsigned r2812 = (r2811 & 511u);
    unsigned r2813 = (r2416 & 511u);
    unsigned r2814 = (r2416 >> 9u);
    unsigned r2815 = (r2814 & 511u);
    unsigned r2816 = (r2416 >> 18u);
    unsigned r2817 = (r2816 & 511u);
    unsigned r2818 = (r2420 & 511u);
    unsigned r2819 = (r2420 >> 9u);
    unsigned r2820 = (r2819 & 511u);
    unsigned r2821 = (r2420 >> 18u);
    unsigned r2822 = (r2821 & 511u);
    unsigned r2823 = (r2424 & 511u);
    unsigned r2824 = (r2424 >> 9u);
    unsigned r2825 = (r2824 & 511u);
    unsigned r2826 = (r2424 >> 18u);
    unsigned r2827 = (r2826 & 511u);
    unsigned r2828 = (r2428 & 511u);
    unsigned r2829 = (r2428 >> 9u);
    unsigned r2830 = (r2829 & 511u);
    unsigned r2831 = (r2428 >> 18u);
    unsigned r2832 = (r2831 & 511u);
    unsigned r2833 = (r2432 & 511u);
    unsigned r2834 = (r2432 >> 9u);
    unsigned r2835 = (r2834 & 511u);
    unsigned r2836 = (r2432 >> 18u);
    unsigned r2837 = (r2836 & 511u);
    unsigned r2838 = (r2396 & 511u);
    out_cols[134u][row] = r2396;
    sub_words[30u * row_count + row] = r2396;
    lookup_words[132u * row_count + row] = r2396;
    lookup_words[232u * row_count + row] = r2396;
    const unsigned dargs38[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r2793, r2795, r2797, r2798, r2800, r2802, r2803, r2805, r2807, r2808, r2810, r2812, r2813, r2815, r2817, r2818, r2820, r2822, r2823, r2825, r2827, r2828, r2830, r2832, r2833, r2835, r2837, r2838 };
    unsigned douts38[28];
    stwo_wit_deduce_felt_mul(dargs38, douts38);
    unsigned r2839 = douts38[0];
    unsigned r2840 = douts38[1];
    unsigned r2841 = douts38[2];
    unsigned r2842 = douts38[3];
    unsigned r2843 = douts38[4];
    unsigned r2844 = douts38[5];
    unsigned r2845 = douts38[6];
    unsigned r2846 = douts38[7];
    unsigned r2847 = douts38[8];
    unsigned r2848 = douts38[9];
    unsigned r2849 = douts38[10];
    unsigned r2850 = douts38[11];
    unsigned r2851 = douts38[12];
    unsigned r2852 = douts38[13];
    unsigned r2853 = douts38[14];
    unsigned r2854 = douts38[15];
    unsigned r2855 = douts38[16];
    unsigned r2856 = douts38[17];
    unsigned r2857 = douts38[18];
    unsigned r2858 = douts38[19];
    unsigned r2859 = douts38[20];
    unsigned r2860 = douts38[21];
    unsigned r2861 = douts38[22];
    unsigned r2862 = douts38[23];
    unsigned r2863 = douts38[24];
    unsigned r2864 = douts38[25];
    unsigned r2865 = douts38[26];
    unsigned r2866 = douts38[27];
    const unsigned dargs39[56] = { r2765, r2766, r2767, r2768, r2769, r2770, r2771, r2772, r2773, r2774, r2775, r2776, r2777, r2778, r2779, r2780, r2781, r2782, r2783, r2784, r2785, r2786, r2787, r2788, r2789, r2790, r2791, r2792, r2839, r2840, r2841, r2842, r2843, r2844, r2845, r2846, r2847, r2848, r2849, r2850, r2851, r2852, r2853, r2854, r2855, r2856, r2857, r2858, r2859, r2860, r2861, r2862, r2863, r2864, r2865, r2866 };
    unsigned douts39[28];
    stwo_wit_deduce_felt_add(dargs39, douts39);
    unsigned r2867 = douts39[0];
    unsigned r2868 = douts39[1];
    unsigned r2869 = douts39[2];
    unsigned r2870 = douts39[3];
    unsigned r2871 = douts39[4];
    unsigned r2872 = douts39[5];
    unsigned r2873 = douts39[6];
    unsigned r2874 = douts39[7];
    unsigned r2875 = douts39[8];
    unsigned r2876 = douts39[9];
    unsigned r2877 = douts39[10];
    unsigned r2878 = douts39[11];
    unsigned r2879 = douts39[12];
    unsigned r2880 = douts39[13];
    unsigned r2881 = douts39[14];
    unsigned r2882 = douts39[15];
    unsigned r2883 = douts39[16];
    unsigned r2884 = douts39[17];
    unsigned r2885 = douts39[18];
    unsigned r2886 = douts39[19];
    unsigned r2887 = douts39[20];
    unsigned r2888 = douts39[21];
    unsigned r2889 = douts39[22];
    unsigned r2890 = douts39[23];
    unsigned r2891 = douts39[24];
    unsigned r2892 = douts39[25];
    unsigned r2893 = douts39[26];
    unsigned r2894 = douts39[27];
    unsigned r2895 = (r2477 & 511u);
    unsigned r2896 = (r2477 >> 9u);
    unsigned r2897 = (r2896 & 511u);
    unsigned r2898 = (r2477 >> 18u);
    unsigned r2899 = (r2898 & 511u);
    unsigned r2900 = (r2478 & 511u);
    unsigned r2901 = (r2478 >> 9u);
    unsigned r2902 = (r2901 & 511u);
    unsigned r2903 = (r2478 >> 18u);
    unsigned r2904 = (r2903 & 511u);
    unsigned r2905 = (r2479 & 511u);
    unsigned r2906 = (r2479 >> 9u);
    unsigned r2907 = (r2906 & 511u);
    unsigned r2908 = (r2479 >> 18u);
    unsigned r2909 = (r2908 & 511u);
    unsigned r2910 = (r2480 & 511u);
    unsigned r2911 = (r2480 >> 9u);
    unsigned r2912 = (r2911 & 511u);
    unsigned r2913 = (r2480 >> 18u);
    unsigned r2914 = (r2913 & 511u);
    unsigned r2915 = (r2481 & 511u);
    unsigned r2916 = (r2481 >> 9u);
    unsigned r2917 = (r2916 & 511u);
    unsigned r2918 = (r2481 >> 18u);
    unsigned r2919 = (r2918 & 511u);
    unsigned r2920 = (r2482 & 511u);
    unsigned r2921 = (r2482 >> 9u);
    unsigned r2922 = (r2921 & 511u);
    unsigned r2923 = (r2482 >> 18u);
    unsigned r2924 = (r2923 & 511u);
    unsigned r2925 = (r2483 & 511u);
    unsigned r2926 = (r2483 >> 9u);
    unsigned r2927 = (r2926 & 511u);
    unsigned r2928 = (r2483 >> 18u);
    unsigned r2929 = (r2928 & 511u);
    unsigned r2930 = (r2484 & 511u);
    unsigned r2931 = (r2484 >> 9u);
    unsigned r2932 = (r2931 & 511u);
    unsigned r2933 = (r2484 >> 18u);
    unsigned r2934 = (r2933 & 511u);
    unsigned r2935 = (r2485 & 511u);
    unsigned r2936 = (r2485 >> 9u);
    unsigned r2937 = (r2936 & 511u);
    unsigned r2938 = (r2485 >> 18u);
    unsigned r2939 = (r2938 & 511u);
    unsigned r2940 = (r2486 & 511u);
    out_cols[145u][row] = r2486;
    lookup_words[142u * row_count + row] = r2486;
    lookup_words[242u * row_count + row] = r2486;
    const unsigned dargs40[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r2895, r2897, r2899, r2900, r2902, r2904, r2905, r2907, r2909, r2910, r2912, r2914, r2915, r2917, r2919, r2920, r2922, r2924, r2925, r2927, r2929, r2930, r2932, r2934, r2935, r2937, r2939, r2940 };
    unsigned douts40[28];
    stwo_wit_deduce_felt_mul(dargs40, douts40);
    unsigned r2941 = douts40[0];
    unsigned r2942 = douts40[1];
    unsigned r2943 = douts40[2];
    unsigned r2944 = douts40[3];
    unsigned r2945 = douts40[4];
    unsigned r2946 = douts40[5];
    unsigned r2947 = douts40[6];
    unsigned r2948 = douts40[7];
    unsigned r2949 = douts40[8];
    unsigned r2950 = douts40[9];
    unsigned r2951 = douts40[10];
    unsigned r2952 = douts40[11];
    unsigned r2953 = douts40[12];
    unsigned r2954 = douts40[13];
    unsigned r2955 = douts40[14];
    unsigned r2956 = douts40[15];
    unsigned r2957 = douts40[16];
    unsigned r2958 = douts40[17];
    unsigned r2959 = douts40[18];
    unsigned r2960 = douts40[19];
    unsigned r2961 = douts40[20];
    unsigned r2962 = douts40[21];
    unsigned r2963 = douts40[22];
    unsigned r2964 = douts40[23];
    unsigned r2965 = douts40[24];
    unsigned r2966 = douts40[25];
    unsigned r2967 = douts40[26];
    unsigned r2968 = douts40[27];
    const unsigned dargs41[56] = { r2867, r2868, r2869, r2870, r2871, r2872, r2873, r2874, r2875, r2876, r2877, r2878, r2879, r2880, r2881, r2882, r2883, r2884, r2885, r2886, r2887, r2888, r2889, r2890, r2891, r2892, r2893, r2894, r2941, r2942, r2943, r2944, r2945, r2946, r2947, r2948, r2949, r2950, r2951, r2952, r2953, r2954, r2955, r2956, r2957, r2958, r2959, r2960, r2961, r2962, r2963, r2964, r2965, r2966, r2967, r2968 };
    unsigned douts41[28];
    stwo_wit_deduce_felt_sub(dargs41, douts41);
    unsigned r2969 = douts41[0];
    unsigned r2970 = douts41[1];
    unsigned r2971 = douts41[2];
    unsigned r2972 = douts41[3];
    unsigned r2973 = douts41[4];
    unsigned r2974 = douts41[5];
    unsigned r2975 = douts41[6];
    unsigned r2976 = douts41[7];
    unsigned r2977 = douts41[8];
    unsigned r2978 = douts41[9];
    unsigned r2979 = douts41[10];
    unsigned r2980 = douts41[11];
    unsigned r2981 = douts41[12];
    unsigned r2982 = douts41[13];
    unsigned r2983 = douts41[14];
    unsigned r2984 = douts41[15];
    unsigned r2985 = douts41[16];
    unsigned r2986 = douts41[17];
    unsigned r2987 = douts41[18];
    unsigned r2988 = douts41[19];
    unsigned r2989 = douts41[20];
    unsigned r2990 = douts41[21];
    unsigned r2991 = douts41[22];
    unsigned r2992 = douts41[23];
    unsigned r2993 = douts41[24];
    unsigned r2994 = douts41[25];
    unsigned r2995 = douts41[26];
    unsigned r2996 = douts41[27];
    unsigned r2997 = (r439 & 511u);
    unsigned r2998 = (r439 >> 9u);
    unsigned r2999 = (r2998 & 511u);
    unsigned r3000 = (r439 >> 18u);
    unsigned r3001 = (r3000 & 511u);
    unsigned r3002 = (r440 & 511u);
    unsigned r3003 = (r440 >> 9u);
    unsigned r3004 = (r3003 & 511u);
    unsigned r3005 = (r440 >> 18u);
    unsigned r3006 = (r3005 & 511u);
    unsigned r3007 = (r441 & 511u);
    unsigned r3008 = (r441 >> 9u);
    unsigned r3009 = (r3008 & 511u);
    unsigned r3010 = (r441 >> 18u);
    unsigned r3011 = (r3010 & 511u);
    unsigned r3012 = (r442 & 511u);
    unsigned r3013 = (r442 >> 9u);
    unsigned r3014 = (r3013 & 511u);
    unsigned r3015 = (r442 >> 18u);
    unsigned r3016 = (r3015 & 511u);
    unsigned r3017 = (r443 & 511u);
    unsigned r3018 = (r443 >> 9u);
    unsigned r3019 = (r3018 & 511u);
    unsigned r3020 = (r443 >> 18u);
    unsigned r3021 = (r3020 & 511u);
    unsigned r3022 = (r444 & 511u);
    unsigned r3023 = (r444 >> 9u);
    unsigned r3024 = (r3023 & 511u);
    unsigned r3025 = (r444 >> 18u);
    unsigned r3026 = (r3025 & 511u);
    unsigned r3027 = (r445 & 511u);
    unsigned r3028 = (r445 >> 9u);
    unsigned r3029 = (r3028 & 511u);
    unsigned r3030 = (r445 >> 18u);
    unsigned r3031 = (r3030 & 511u);
    unsigned r3032 = (r446 & 511u);
    unsigned r3033 = (r446 >> 9u);
    unsigned r3034 = (r3033 & 511u);
    unsigned r3035 = (r446 >> 18u);
    unsigned r3036 = (r3035 & 511u);
    unsigned r3037 = (r447 & 511u);
    unsigned r3038 = (r447 >> 9u);
    unsigned r3039 = (r3038 & 511u);
    unsigned r3040 = (r447 >> 18u);
    unsigned r3041 = (r3040 & 511u);
    unsigned r3042 = (r448 & 511u);
    out_cols[71u][row] = r448;
    lookup_words[31u * row_count + row] = r448;
    const unsigned dargs42[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r2997, r2999, r3001, r3002, r3004, r3006, r3007, r3009, r3011, r3012, r3014, r3016, r3017, r3019, r3021, r3022, r3024, r3026, r3027, r3029, r3031, r3032, r3034, r3036, r3037, r3039, r3041, r3042 };
    unsigned douts42[28];
    stwo_wit_deduce_felt_mul(dargs42, douts42);
    unsigned r3043 = douts42[0];
    unsigned r3044 = douts42[1];
    unsigned r3045 = douts42[2];
    unsigned r3046 = douts42[3];
    unsigned r3047 = douts42[4];
    unsigned r3048 = douts42[5];
    unsigned r3049 = douts42[6];
    unsigned r3050 = douts42[7];
    unsigned r3051 = douts42[8];
    unsigned r3052 = douts42[9];
    unsigned r3053 = douts42[10];
    unsigned r3054 = douts42[11];
    unsigned r3055 = douts42[12];
    unsigned r3056 = douts42[13];
    unsigned r3057 = douts42[14];
    unsigned r3058 = douts42[15];
    unsigned r3059 = douts42[16];
    unsigned r3060 = douts42[17];
    unsigned r3061 = douts42[18];
    unsigned r3062 = douts42[19];
    unsigned r3063 = douts42[20];
    unsigned r3064 = douts42[21];
    unsigned r3065 = douts42[22];
    unsigned r3066 = douts42[23];
    unsigned r3067 = douts42[24];
    unsigned r3068 = douts42[25];
    unsigned r3069 = douts42[26];
    unsigned r3070 = douts42[27];
    const unsigned dargs43[56] = { r2969, r2970, r2971, r2972, r2973, r2974, r2975, r2976, r2977, r2978, r2979, r2980, r2981, r2982, r2983, r2984, r2985, r2986, r2987, r2988, r2989, r2990, r2991, r2992, r2993, r2994, r2995, r2996, r3043, r3044, r3045, r3046, r3047, r3048, r3049, r3050, r3051, r3052, r3053, r3054, r3055, r3056, r3057, r3058, r3059, r3060, r3061, r3062, r3063, r3064, r3065, r3066, r3067, r3068, r3069, r3070 };
    unsigned douts43[28];
    stwo_wit_deduce_felt_add(dargs43, douts43);
    unsigned r3071 = douts43[0];
    unsigned r3072 = douts43[1];
    unsigned r3073 = douts43[2];
    unsigned r3074 = douts43[3];
    unsigned r3075 = douts43[4];
    unsigned r3076 = douts43[5];
    unsigned r3077 = douts43[6];
    unsigned r3078 = douts43[7];
    unsigned r3079 = douts43[8];
    unsigned r3080 = douts43[9];
    unsigned r3081 = douts43[10];
    unsigned r3082 = douts43[11];
    unsigned r3083 = douts43[12];
    unsigned r3084 = douts43[13];
    unsigned r3085 = douts43[14];
    unsigned r3086 = douts43[15];
    unsigned r3087 = douts43[16];
    unsigned r3088 = douts43[17];
    unsigned r3089 = douts43[18];
    unsigned r3090 = douts43[19];
    unsigned r3091 = douts43[20];
    unsigned r3092 = douts43[21];
    unsigned r3093 = douts43[22];
    unsigned r3094 = douts43[23];
    unsigned r3095 = douts43[24];
    unsigned r3096 = douts43[25];
    unsigned r3097 = douts43[26];
    unsigned r3098 = douts43[27];
    unsigned r3099 = stwo_m31_mul(r3072, r7);
    unsigned r3100 = stwo_m31_add(r3071, r3099);
    unsigned r3101 = stwo_m31_mul(r3073, r8);
    unsigned r3102 = stwo_m31_add(r3100, r3101);
    unsigned r3103 = stwo_m31_mul(r3075, r7);
    unsigned r3104 = stwo_m31_add(r3074, r3103);
    unsigned r3105 = stwo_m31_mul(r3076, r8);
    unsigned r3106 = stwo_m31_add(r3104, r3105);
    unsigned r3107 = stwo_m31_mul(r3078, r7);
    unsigned r3108 = stwo_m31_add(r3077, r3107);
    unsigned r3109 = stwo_m31_mul(r3079, r8);
    unsigned r3110 = stwo_m31_add(r3108, r3109);
    unsigned r3111 = stwo_m31_mul(r3081, r7);
    unsigned r3112 = stwo_m31_add(r3080, r3111);
    unsigned r3113 = stwo_m31_mul(r3082, r8);
    unsigned r3114 = stwo_m31_add(r3112, r3113);
    unsigned r3115 = stwo_m31_mul(r3084, r7);
    unsigned r3116 = stwo_m31_add(r3083, r3115);
    unsigned r3117 = stwo_m31_mul(r3085, r8);
    unsigned r3118 = stwo_m31_add(r3116, r3117);
    unsigned r3119 = stwo_m31_mul(r3087, r7);
    unsigned r3120 = stwo_m31_add(r3086, r3119);
    unsigned r3121 = stwo_m31_mul(r3088, r8);
    unsigned r3122 = stwo_m31_add(r3120, r3121);
    unsigned r3123 = stwo_m31_mul(r3090, r7);
    unsigned r3124 = stwo_m31_add(r3089, r3123);
    unsigned r3125 = stwo_m31_mul(r3091, r8);
    unsigned r3126 = stwo_m31_add(r3124, r3125);
    unsigned r3127 = stwo_m31_mul(r3093, r7);
    unsigned r3128 = stwo_m31_add(r3092, r3127);
    unsigned r3129 = stwo_m31_mul(r3094, r8);
    unsigned r3130 = stwo_m31_add(r3128, r3129);
    unsigned r3131 = stwo_m31_mul(r3096, r7);
    unsigned r3132 = stwo_m31_add(r3095, r3131);
    unsigned r3133 = stwo_m31_mul(r3097, r8);
    unsigned r3134 = stwo_m31_add(r3132, r3133);
    unsigned r3135 = stwo_m31_mul(r4, r469);
    unsigned r3136 = stwo_m31_mul(r2, r1406);
    unsigned r3137 = stwo_m31_add(r3135, r3136);
    unsigned r3138 = stwo_m31_mul(r3, r1483);
    unsigned r3139 = stwo_m31_add(r3137, r3138);
    unsigned r3140 = stwo_m31_add(r3139, r2400);
    unsigned r3141 = stwo_m31_sub(r3140, r2477);
    unsigned r3142 = stwo_m31_add(r3141, r439);
    unsigned r3143 = stwo_m31_sub(r3142, r3102);
    unsigned r3144 = stwo_m31_add(r3143, r10);
    unsigned r3145 = (r3144 & 65535u);
    unsigned r3146 = (r3145 % STWO_M31_P);
    unsigned r3147 = stwo_m31_sub(r3146, r2);
    unsigned r3148 = stwo_m31_mul(r4, r469);
    out_cols[72u][row] = r469;
    lookup_words[43u * row_count + row] = r469;
    unsigned r3149 = stwo_m31_mul(r2, r1406);
    out_cols[93u][row] = r1406;
    sub_words[11u * row_count + row] = r1406;
    lookup_words[78u * row_count + row] = r1406;
    unsigned r3150 = stwo_m31_add(r3148, r3149);
    unsigned r3151 = stwo_m31_mul(r3, r1483);
    out_cols[104u][row] = r1483;
    lookup_words[88u * row_count + row] = r1483;
    lookup_words[213u * row_count + row] = r1483;
    unsigned r3152 = stwo_m31_add(r3150, r3151);
    unsigned r3153 = stwo_m31_add(r3152, r2400);
    out_cols[125u][row] = r2400;
    sub_words[21u * row_count + row] = r2400;
    lookup_words[123u * row_count + row] = r2400;
    lookup_words[223u * row_count + row] = r2400;
    unsigned r3154 = stwo_m31_sub(r3153, r2477);
    out_cols[136u][row] = r2477;
    lookup_words[133u * row_count + row] = r2477;
    lookup_words[233u * row_count + row] = r2477;
    unsigned r3155 = stwo_m31_add(r3154, r439);
    out_cols[62u][row] = r439;
    lookup_words[22u * row_count + row] = r439;
    unsigned r3156 = stwo_m31_sub(r3155, r3102);
    unsigned r3157 = stwo_m31_sub(r3156, r3147);
    unsigned r3158 = stwo_m31_mul(r3157, r5);
    unsigned r3159 = stwo_m31_mul(r4, r470);
    out_cols[73u][row] = r470;
    lookup_words[44u * row_count + row] = r470;
    unsigned r3160 = stwo_m31_add(r3158, r3159);
    unsigned r3161 = stwo_m31_mul(r2, r1410);
    out_cols[94u][row] = r1410;
    sub_words[12u * row_count + row] = r1410;
    lookup_words[79u * row_count + row] = r1410;
    unsigned r3162 = stwo_m31_add(r3160, r3161);
    unsigned r3163 = stwo_m31_mul(r3, r1484);
    out_cols[105u][row] = r1484;
    lookup_words[89u * row_count + row] = r1484;
    lookup_words[214u * row_count + row] = r1484;
    unsigned r3164 = stwo_m31_add(r3162, r3163);
    unsigned r3165 = stwo_m31_add(r3164, r2404);
    out_cols[126u][row] = r2404;
    sub_words[22u * row_count + row] = r2404;
    lookup_words[124u * row_count + row] = r2404;
    lookup_words[224u * row_count + row] = r2404;
    unsigned r3166 = stwo_m31_sub(r3165, r2478);
    out_cols[137u][row] = r2478;
    lookup_words[134u * row_count + row] = r2478;
    lookup_words[234u * row_count + row] = r2478;
    unsigned r3167 = stwo_m31_add(r3166, r440);
    out_cols[63u][row] = r440;
    lookup_words[23u * row_count + row] = r440;
    unsigned r3168 = stwo_m31_sub(r3167, r3106);
    unsigned r3169 = stwo_m31_mul(r3168, r5);
    unsigned r3170 = stwo_m31_mul(r4, r471);
    out_cols[74u][row] = r471;
    lookup_words[45u * row_count + row] = r471;
    unsigned r3171 = stwo_m31_add(r3169, r3170);
    unsigned r3172 = stwo_m31_mul(r2, r1414);
    out_cols[95u][row] = r1414;
    sub_words[13u * row_count + row] = r1414;
    lookup_words[80u * row_count + row] = r1414;
    unsigned r3173 = stwo_m31_add(r3171, r3172);
    unsigned r3174 = stwo_m31_mul(r3, r1485);
    out_cols[106u][row] = r1485;
    lookup_words[90u * row_count + row] = r1485;
    lookup_words[215u * row_count + row] = r1485;
    unsigned r3175 = stwo_m31_add(r3173, r3174);
    unsigned r3176 = stwo_m31_add(r3175, r2408);
    out_cols[127u][row] = r2408;
    sub_words[23u * row_count + row] = r2408;
    lookup_words[125u * row_count + row] = r2408;
    lookup_words[225u * row_count + row] = r2408;
    unsigned r3177 = stwo_m31_sub(r3176, r2479);
    out_cols[138u][row] = r2479;
    lookup_words[135u * row_count + row] = r2479;
    lookup_words[235u * row_count + row] = r2479;
    unsigned r3178 = stwo_m31_add(r3177, r441);
    out_cols[64u][row] = r441;
    lookup_words[24u * row_count + row] = r441;
    unsigned r3179 = stwo_m31_sub(r3178, r3110);
    unsigned r3180 = stwo_m31_mul(r3179, r5);
    unsigned r3181 = stwo_m31_mul(r4, r472);
    out_cols[75u][row] = r472;
    lookup_words[46u * row_count + row] = r472;
    unsigned r3182 = stwo_m31_add(r3180, r3181);
    unsigned r3183 = stwo_m31_mul(r2, r1418);
    out_cols[96u][row] = r1418;
    sub_words[14u * row_count + row] = r1418;
    lookup_words[81u * row_count + row] = r1418;
    unsigned r3184 = stwo_m31_add(r3182, r3183);
    unsigned r3185 = stwo_m31_mul(r3, r1486);
    out_cols[107u][row] = r1486;
    lookup_words[91u * row_count + row] = r1486;
    lookup_words[216u * row_count + row] = r1486;
    unsigned r3186 = stwo_m31_add(r3184, r3185);
    unsigned r3187 = stwo_m31_add(r3186, r2412);
    out_cols[128u][row] = r2412;
    sub_words[24u * row_count + row] = r2412;
    lookup_words[126u * row_count + row] = r2412;
    lookup_words[226u * row_count + row] = r2412;
    unsigned r3188 = stwo_m31_sub(r3187, r2480);
    out_cols[139u][row] = r2480;
    lookup_words[136u * row_count + row] = r2480;
    lookup_words[236u * row_count + row] = r2480;
    unsigned r3189 = stwo_m31_add(r3188, r442);
    out_cols[65u][row] = r442;
    lookup_words[25u * row_count + row] = r442;
    unsigned r3190 = stwo_m31_sub(r3189, r3114);
    unsigned r3191 = stwo_m31_mul(r3190, r5);
    unsigned r3192 = stwo_m31_mul(r4, r473);
    out_cols[76u][row] = r473;
    lookup_words[47u * row_count + row] = r473;
    unsigned r3193 = stwo_m31_add(r3191, r3192);
    unsigned r3194 = stwo_m31_mul(r2, r1422);
    out_cols[97u][row] = r1422;
    sub_words[15u * row_count + row] = r1422;
    lookup_words[82u * row_count + row] = r1422;
    unsigned r3195 = stwo_m31_add(r3193, r3194);
    unsigned r3196 = stwo_m31_mul(r3, r1487);
    out_cols[108u][row] = r1487;
    lookup_words[92u * row_count + row] = r1487;
    lookup_words[217u * row_count + row] = r1487;
    unsigned r3197 = stwo_m31_add(r3195, r3196);
    unsigned r3198 = stwo_m31_add(r3197, r2416);
    out_cols[129u][row] = r2416;
    sub_words[25u * row_count + row] = r2416;
    lookup_words[127u * row_count + row] = r2416;
    lookup_words[227u * row_count + row] = r2416;
    unsigned r3199 = stwo_m31_sub(r3198, r2481);
    out_cols[140u][row] = r2481;
    lookup_words[137u * row_count + row] = r2481;
    lookup_words[237u * row_count + row] = r2481;
    unsigned r3200 = stwo_m31_add(r3199, r443);
    out_cols[66u][row] = r443;
    lookup_words[26u * row_count + row] = r443;
    unsigned r3201 = stwo_m31_sub(r3200, r3118);
    unsigned r3202 = stwo_m31_mul(r3201, r5);
    unsigned r3203 = stwo_m31_mul(r4, r474);
    out_cols[77u][row] = r474;
    lookup_words[48u * row_count + row] = r474;
    unsigned r3204 = stwo_m31_add(r3202, r3203);
    unsigned r3205 = stwo_m31_mul(r2, r1426);
    out_cols[98u][row] = r1426;
    sub_words[16u * row_count + row] = r1426;
    lookup_words[83u * row_count + row] = r1426;
    unsigned r3206 = stwo_m31_add(r3204, r3205);
    unsigned r3207 = stwo_m31_mul(r3, r1488);
    out_cols[109u][row] = r1488;
    lookup_words[93u * row_count + row] = r1488;
    lookup_words[218u * row_count + row] = r1488;
    unsigned r3208 = stwo_m31_add(r3206, r3207);
    unsigned r3209 = stwo_m31_add(r3208, r2420);
    out_cols[130u][row] = r2420;
    sub_words[26u * row_count + row] = r2420;
    lookup_words[128u * row_count + row] = r2420;
    lookup_words[228u * row_count + row] = r2420;
    unsigned r3210 = stwo_m31_sub(r3209, r2482);
    out_cols[141u][row] = r2482;
    lookup_words[138u * row_count + row] = r2482;
    lookup_words[238u * row_count + row] = r2482;
    unsigned r3211 = stwo_m31_add(r3210, r444);
    out_cols[67u][row] = r444;
    lookup_words[27u * row_count + row] = r444;
    unsigned r3212 = stwo_m31_sub(r3211, r3122);
    unsigned r3213 = stwo_m31_mul(r3212, r5);
    unsigned r3214 = stwo_m31_mul(r4, r475);
    out_cols[78u][row] = r475;
    lookup_words[49u * row_count + row] = r475;
    unsigned r3215 = stwo_m31_add(r3213, r3214);
    unsigned r3216 = stwo_m31_mul(r2, r1430);
    out_cols[99u][row] = r1430;
    sub_words[17u * row_count + row] = r1430;
    lookup_words[84u * row_count + row] = r1430;
    unsigned r3217 = stwo_m31_add(r3215, r3216);
    unsigned r3218 = stwo_m31_mul(r3, r1489);
    out_cols[110u][row] = r1489;
    lookup_words[94u * row_count + row] = r1489;
    lookup_words[219u * row_count + row] = r1489;
    unsigned r3219 = stwo_m31_add(r3217, r3218);
    unsigned r3220 = stwo_m31_add(r3219, r2424);
    out_cols[131u][row] = r2424;
    sub_words[27u * row_count + row] = r2424;
    lookup_words[129u * row_count + row] = r2424;
    lookup_words[229u * row_count + row] = r2424;
    unsigned r3221 = stwo_m31_sub(r3220, r2483);
    out_cols[142u][row] = r2483;
    lookup_words[139u * row_count + row] = r2483;
    lookup_words[239u * row_count + row] = r2483;
    unsigned r3222 = stwo_m31_add(r3221, r445);
    out_cols[68u][row] = r445;
    lookup_words[28u * row_count + row] = r445;
    unsigned r3223 = stwo_m31_sub(r3222, r3126);
    unsigned r3224 = stwo_m31_mul(r3223, r5);
    unsigned r3225 = stwo_m31_mul(r4, r476);
    out_cols[79u][row] = r476;
    lookup_words[50u * row_count + row] = r476;
    unsigned r3226 = stwo_m31_add(r3224, r3225);
    unsigned r3227 = stwo_m31_mul(r2, r1434);
    out_cols[100u][row] = r1434;
    sub_words[18u * row_count + row] = r1434;
    lookup_words[85u * row_count + row] = r1434;
    unsigned r3228 = stwo_m31_add(r3226, r3227);
    unsigned r3229 = stwo_m31_mul(r3, r1490);
    out_cols[111u][row] = r1490;
    lookup_words[95u * row_count + row] = r1490;
    lookup_words[220u * row_count + row] = r1490;
    unsigned r3230 = stwo_m31_add(r3228, r3229);
    unsigned r3231 = stwo_m31_add(r3230, r2428);
    out_cols[132u][row] = r2428;
    sub_words[28u * row_count + row] = r2428;
    lookup_words[130u * row_count + row] = r2428;
    lookup_words[230u * row_count + row] = r2428;
    unsigned r3232 = stwo_m31_sub(r3231, r2484);
    out_cols[143u][row] = r2484;
    lookup_words[140u * row_count + row] = r2484;
    lookup_words[240u * row_count + row] = r2484;
    unsigned r3233 = stwo_m31_add(r3232, r446);
    out_cols[69u][row] = r446;
    lookup_words[29u * row_count + row] = r446;
    unsigned r3234 = stwo_m31_sub(r3233, r3130);
    unsigned r3235 = stwo_m31_mul(r3147, r6);
    unsigned r3236 = stwo_m31_sub(r3234, r3235);
    unsigned r3237 = stwo_m31_mul(r3236, r5);
    unsigned r3238 = stwo_m31_mul(r4, r477);
    out_cols[80u][row] = r477;
    lookup_words[51u * row_count + row] = r477;
    unsigned r3239 = stwo_m31_add(r3237, r3238);
    unsigned r3240 = stwo_m31_mul(r2, r1438);
    out_cols[101u][row] = r1438;
    sub_words[19u * row_count + row] = r1438;
    lookup_words[86u * row_count + row] = r1438;
    unsigned r3241 = stwo_m31_add(r3239, r3240);
    unsigned r3242 = stwo_m31_mul(r3, r1491);
    out_cols[112u][row] = r1491;
    lookup_words[96u * row_count + row] = r1491;
    lookup_words[221u * row_count + row] = r1491;
    unsigned r3243 = stwo_m31_add(r3241, r3242);
    unsigned r3244 = stwo_m31_add(r3243, r2432);
    out_cols[133u][row] = r2432;
    sub_words[29u * row_count + row] = r2432;
    lookup_words[131u * row_count + row] = r2432;
    lookup_words[231u * row_count + row] = r2432;
    unsigned r3245 = stwo_m31_sub(r3244, r2485);
    out_cols[144u][row] = r2485;
    lookup_words[141u * row_count + row] = r2485;
    lookup_words[241u * row_count + row] = r2485;
    unsigned r3246 = stwo_m31_add(r3245, r447);
    out_cols[70u][row] = r447;
    lookup_words[30u * row_count + row] = r447;
    unsigned r3247 = stwo_m31_sub(r3246, r3134);
    unsigned r3248 = stwo_m31_mul(r3247, r5);
    unsigned r3249 = stwo_m31_add(r3147, r2);
    sub_words[47u * row_count + row] = r3249;
    unsigned r3250 = stwo_m31_add(r3158, r2);
    sub_words[48u * row_count + row] = r3250;
    unsigned r3251 = stwo_m31_add(r3169, r2);
    sub_words[49u * row_count + row] = r3251;
    unsigned r3252 = stwo_m31_add(r3180, r2);
    sub_words[50u * row_count + row] = r3252;
    unsigned r3253 = stwo_m31_add(r3147, r2);
    out_cols[156u][row] = r3147;
    lookup_words[144u * row_count + row] = r3253;
    unsigned r3254 = stwo_m31_add(r3158, r2);
    lookup_words[145u * row_count + row] = r3254;
    unsigned r3255 = stwo_m31_add(r3169, r2);
    lookup_words[146u * row_count + row] = r3255;
    unsigned r3256 = stwo_m31_add(r3180, r2);
    lookup_words[147u * row_count + row] = r3256;
    unsigned r3257 = stwo_m31_add(r3191, r2);
    sub_words[51u * row_count + row] = r3257;
    unsigned r3258 = stwo_m31_add(r3202, r2);
    sub_words[52u * row_count + row] = r3258;
    unsigned r3259 = stwo_m31_add(r3213, r2);
    sub_words[53u * row_count + row] = r3259;
    unsigned r3260 = stwo_m31_add(r3224, r2);
    sub_words[54u * row_count + row] = r3260;
    unsigned r3261 = stwo_m31_add(r3191, r2);
    lookup_words[149u * row_count + row] = r3261;
    unsigned r3262 = stwo_m31_add(r3202, r2);
    lookup_words[150u * row_count + row] = r3262;
    unsigned r3263 = stwo_m31_add(r3213, r2);
    lookup_words[151u * row_count + row] = r3263;
    unsigned r3264 = stwo_m31_add(r3224, r2);
    lookup_words[152u * row_count + row] = r3264;
    unsigned r3265 = stwo_m31_add(r3237, r2);
    sub_words[59u * row_count + row] = r3265;
    unsigned r3266 = stwo_m31_add(r3248, r2);
    sub_words[60u * row_count + row] = r3266;
    unsigned r3267 = stwo_m31_add(r3237, r2);
    lookup_words[154u * row_count + row] = r3267;
    unsigned r3268 = stwo_m31_add(r3248, r2);
    lookup_words[155u * row_count + row] = r3268;
    unsigned r3269 = (r3102 & 511u);
    unsigned r3270 = (r3102 >> 9u);
    unsigned r3271 = (r3270 & 511u);
    unsigned r3272 = (r3102 >> 18u);
    unsigned r3273 = (r3272 & 511u);
    unsigned r3274 = (r3106 & 511u);
    unsigned r3275 = (r3106 >> 9u);
    unsigned r3276 = (r3275 & 511u);
    unsigned r3277 = (r3106 >> 18u);
    unsigned r3278 = (r3277 & 511u);
    unsigned r3279 = (r3110 & 511u);
    unsigned r3280 = (r3110 >> 9u);
    unsigned r3281 = (r3280 & 511u);
    unsigned r3282 = (r3110 >> 18u);
    unsigned r3283 = (r3282 & 511u);
    unsigned r3284 = (r3114 & 511u);
    unsigned r3285 = (r3114 >> 9u);
    unsigned r3286 = (r3285 & 511u);
    unsigned r3287 = (r3114 >> 18u);
    unsigned r3288 = (r3287 & 511u);
    unsigned r3289 = (r3118 & 511u);
    unsigned r3290 = (r3118 >> 9u);
    unsigned r3291 = (r3290 & 511u);
    unsigned r3292 = (r3118 >> 18u);
    unsigned r3293 = (r3292 & 511u);
    unsigned r3294 = (r3122 & 511u);
    unsigned r3295 = (r3122 >> 9u);
    unsigned r3296 = (r3295 & 511u);
    unsigned r3297 = (r3122 >> 18u);
    unsigned r3298 = (r3297 & 511u);
    unsigned r3299 = (r3126 & 511u);
    unsigned r3300 = (r3126 >> 9u);
    unsigned r3301 = (r3300 & 511u);
    unsigned r3302 = (r3126 >> 18u);
    unsigned r3303 = (r3302 & 511u);
    unsigned r3304 = (r3130 & 511u);
    unsigned r3305 = (r3130 >> 9u);
    unsigned r3306 = (r3305 & 511u);
    unsigned r3307 = (r3130 >> 18u);
    unsigned r3308 = (r3307 & 511u);
    unsigned r3309 = (r3134 & 511u);
    unsigned r3310 = (r3134 >> 9u);
    unsigned r3311 = (r3310 & 511u);
    unsigned r3312 = (r3134 >> 18u);
    unsigned r3313 = (r3312 & 511u);
    unsigned r3314 = (r3098 & 511u);
    out_cols[155u][row] = r3098;
    sub_words[90u * row_count + row] = r3098;
    lookup_words[166u * row_count + row] = r3098;
    const unsigned dargs44[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r3269, r3271, r3273, r3274, r3276, r3278, r3279, r3281, r3283, r3284, r3286, r3288, r3289, r3291, r3293, r3294, r3296, r3298, r3299, r3301, r3303, r3304, r3306, r3308, r3309, r3311, r3313, r3314 };
    unsigned douts44[28];
    stwo_wit_deduce_felt_mul(dargs44, douts44);
    unsigned r3315 = douts44[0];
    unsigned r3316 = douts44[1];
    unsigned r3317 = douts44[2];
    unsigned r3318 = douts44[3];
    unsigned r3319 = douts44[4];
    unsigned r3320 = douts44[5];
    unsigned r3321 = douts44[6];
    unsigned r3322 = douts44[7];
    unsigned r3323 = douts44[8];
    unsigned r3324 = douts44[9];
    unsigned r3325 = douts44[10];
    unsigned r3326 = douts44[11];
    unsigned r3327 = douts44[12];
    unsigned r3328 = douts44[13];
    unsigned r3329 = douts44[14];
    unsigned r3330 = douts44[15];
    unsigned r3331 = douts44[16];
    unsigned r3332 = douts44[17];
    unsigned r3333 = douts44[18];
    unsigned r3334 = douts44[19];
    unsigned r3335 = douts44[20];
    unsigned r3336 = douts44[21];
    unsigned r3337 = douts44[22];
    unsigned r3338 = douts44[23];
    unsigned r3339 = douts44[24];
    unsigned r3340 = douts44[25];
    unsigned r3341 = douts44[26];
    unsigned r3342 = douts44[27];
    const unsigned dargs45[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r3315, r3316, r3317, r3318, r3319, r3320, r3321, r3322, r3323, r3324, r3325, r3326, r3327, r3328, r3329, r3330, r3331, r3332, r3333, r3334, r3335, r3336, r3337, r3338, r3339, r3340, r3341, r3342 };
    unsigned douts45[28];
    stwo_wit_deduce_felt_add(dargs45, douts45);
    unsigned r3343 = douts45[0];
    unsigned r3344 = douts45[1];
    unsigned r3345 = douts45[2];
    unsigned r3346 = douts45[3];
    unsigned r3347 = douts45[4];
    unsigned r3348 = douts45[5];
    unsigned r3349 = douts45[6];
    unsigned r3350 = douts45[7];
    unsigned r3351 = douts45[8];
    unsigned r3352 = douts45[9];
    unsigned r3353 = douts45[10];
    unsigned r3354 = douts45[11];
    unsigned r3355 = douts45[12];
    unsigned r3356 = douts45[13];
    unsigned r3357 = douts45[14];
    unsigned r3358 = douts45[15];
    unsigned r3359 = douts45[16];
    unsigned r3360 = douts45[17];
    unsigned r3361 = douts45[18];
    unsigned r3362 = douts45[19];
    unsigned r3363 = douts45[20];
    unsigned r3364 = douts45[21];
    unsigned r3365 = douts45[22];
    unsigned r3366 = douts45[23];
    unsigned r3367 = douts45[24];
    unsigned r3368 = douts45[25];
    unsigned r3369 = douts45[26];
    unsigned r3370 = douts45[27];
    out_cols[166u][row] = r3370;
    lookup_words[252u * row_count + row] = r3370;
    unsigned r3371 = stwo_m31_mul(r3344, r7);
    unsigned r3372 = stwo_m31_add(r3343, r3371);
    unsigned r3373 = stwo_m31_mul(r3345, r8);
    unsigned r3374 = stwo_m31_add(r3372, r3373);
    unsigned r3375 = stwo_m31_mul(r3347, r7);
    unsigned r3376 = stwo_m31_add(r3346, r3375);
    unsigned r3377 = stwo_m31_mul(r3348, r8);
    unsigned r3378 = stwo_m31_add(r3376, r3377);
    unsigned r3379 = stwo_m31_mul(r3350, r7);
    unsigned r3380 = stwo_m31_add(r3349, r3379);
    unsigned r3381 = stwo_m31_mul(r3351, r8);
    unsigned r3382 = stwo_m31_add(r3380, r3381);
    unsigned r3383 = stwo_m31_mul(r3353, r7);
    unsigned r3384 = stwo_m31_add(r3352, r3383);
    unsigned r3385 = stwo_m31_mul(r3354, r8);
    unsigned r3386 = stwo_m31_add(r3384, r3385);
    unsigned r3387 = stwo_m31_mul(r3356, r7);
    unsigned r3388 = stwo_m31_add(r3355, r3387);
    unsigned r3389 = stwo_m31_mul(r3357, r8);
    unsigned r3390 = stwo_m31_add(r3388, r3389);
    unsigned r3391 = stwo_m31_mul(r3359, r7);
    unsigned r3392 = stwo_m31_add(r3358, r3391);
    unsigned r3393 = stwo_m31_mul(r3360, r8);
    unsigned r3394 = stwo_m31_add(r3392, r3393);
    unsigned r3395 = stwo_m31_mul(r3362, r7);
    unsigned r3396 = stwo_m31_add(r3361, r3395);
    unsigned r3397 = stwo_m31_mul(r3363, r8);
    unsigned r3398 = stwo_m31_add(r3396, r3397);
    unsigned r3399 = stwo_m31_mul(r3365, r7);
    unsigned r3400 = stwo_m31_add(r3364, r3399);
    unsigned r3401 = stwo_m31_mul(r3366, r8);
    unsigned r3402 = stwo_m31_add(r3400, r3401);
    unsigned r3403 = stwo_m31_mul(r3368, r7);
    unsigned r3404 = stwo_m31_add(r3367, r3403);
    unsigned r3405 = stwo_m31_mul(r3369, r8);
    unsigned r3406 = stwo_m31_add(r3404, r3405);
    unsigned r3407 = stwo_m31_mul(r2, r3102);
    unsigned r3408 = stwo_m31_sub(r3407, r3374);
    unsigned r3409 = stwo_m31_add(r3408, r9);
    unsigned r3410 = (r3409 & 65535u);
    unsigned r3411 = (r3410 % STWO_M31_P);
    unsigned r3412 = stwo_m31_sub(r3411, r1);
    unsigned r3413 = stwo_m31_mul(r2, r3102);
    out_cols[146u][row] = r3102;
    sub_words[81u * row_count + row] = r3102;
    lookup_words[157u * row_count + row] = r3102;
    unsigned r3414 = stwo_m31_sub(r3413, r3374);
    out_cols[157u][row] = r3374;
    lookup_words[243u * row_count + row] = r3374;
    unsigned r3415 = stwo_m31_sub(r3414, r3412);
    unsigned r3416 = stwo_m31_mul(r3415, r5);
    unsigned r3417 = stwo_m31_mul(r2, r3106);
    out_cols[147u][row] = r3106;
    sub_words[82u * row_count + row] = r3106;
    lookup_words[158u * row_count + row] = r3106;
    unsigned r3418 = stwo_m31_add(r3416, r3417);
    unsigned r3419 = stwo_m31_sub(r3418, r3378);
    out_cols[158u][row] = r3378;
    lookup_words[244u * row_count + row] = r3378;
    unsigned r3420 = stwo_m31_mul(r3419, r5);
    unsigned r3421 = stwo_m31_mul(r2, r3110);
    out_cols[148u][row] = r3110;
    sub_words[83u * row_count + row] = r3110;
    lookup_words[159u * row_count + row] = r3110;
    unsigned r3422 = stwo_m31_add(r3420, r3421);
    unsigned r3423 = stwo_m31_sub(r3422, r3382);
    out_cols[159u][row] = r3382;
    lookup_words[245u * row_count + row] = r3382;
    unsigned r3424 = stwo_m31_mul(r3423, r5);
    unsigned r3425 = stwo_m31_mul(r2, r3114);
    out_cols[149u][row] = r3114;
    sub_words[84u * row_count + row] = r3114;
    lookup_words[160u * row_count + row] = r3114;
    unsigned r3426 = stwo_m31_add(r3424, r3425);
    unsigned r3427 = stwo_m31_sub(r3426, r3386);
    out_cols[160u][row] = r3386;
    lookup_words[246u * row_count + row] = r3386;
    unsigned r3428 = stwo_m31_mul(r3427, r5);
    unsigned r3429 = stwo_m31_mul(r2, r3118);
    out_cols[150u][row] = r3118;
    sub_words[85u * row_count + row] = r3118;
    lookup_words[161u * row_count + row] = r3118;
    unsigned r3430 = stwo_m31_add(r3428, r3429);
    unsigned r3431 = stwo_m31_sub(r3430, r3390);
    out_cols[161u][row] = r3390;
    lookup_words[247u * row_count + row] = r3390;
    unsigned r3432 = stwo_m31_mul(r3431, r5);
    unsigned r3433 = stwo_m31_mul(r2, r3122);
    out_cols[151u][row] = r3122;
    sub_words[86u * row_count + row] = r3122;
    lookup_words[162u * row_count + row] = r3122;
    unsigned r3434 = stwo_m31_add(r3432, r3433);
    unsigned r3435 = stwo_m31_sub(r3434, r3394);
    out_cols[162u][row] = r3394;
    lookup_words[248u * row_count + row] = r3394;
    unsigned r3436 = stwo_m31_mul(r3435, r5);
    unsigned r3437 = stwo_m31_mul(r2, r3126);
    out_cols[152u][row] = r3126;
    sub_words[87u * row_count + row] = r3126;
    lookup_words[163u * row_count + row] = r3126;
    unsigned r3438 = stwo_m31_add(r3436, r3437);
    unsigned r3439 = stwo_m31_sub(r3438, r3398);
    out_cols[163u][row] = r3398;
    lookup_words[249u * row_count + row] = r3398;
    unsigned r3440 = stwo_m31_mul(r3439, r5);
    unsigned r3441 = stwo_m31_mul(r2, r3130);
    out_cols[153u][row] = r3130;
    sub_words[88u * row_count + row] = r3130;
    lookup_words[164u * row_count + row] = r3130;
    unsigned r3442 = stwo_m31_add(r3440, r3441);
    unsigned r3443 = stwo_m31_sub(r3442, r3402);
    out_cols[164u][row] = r3402;
    lookup_words[250u * row_count + row] = r3402;
    unsigned r3444 = stwo_m31_mul(r3412, r6);
    out_cols[167u][row] = r3412;
    unsigned r3445 = stwo_m31_sub(r3443, r3444);
    unsigned r3446 = stwo_m31_mul(r3445, r5);
    unsigned r3447 = stwo_m31_mul(r2, r3134);
    out_cols[154u][row] = r3134;
    sub_words[89u * row_count + row] = r3134;
    lookup_words[165u * row_count + row] = r3134;
    unsigned r3448 = stwo_m31_add(r3446, r3447);
    unsigned r3449 = stwo_m31_sub(r3448, r3406);
    out_cols[165u][row] = r3406;
    lookup_words[251u * row_count + row] = r3406;
    unsigned r3450 = stwo_m31_mul(r3449, r5);
    unsigned r3451 = input_cols[42u][row];
    out_cols[168u][row] = r3451;
    lookup_words[254u * row_count + row] = r3451;
    unsigned r3452 = stwo_m31_add(r18, r1);
    out_cols[1u][row] = r18;
    sub_words[0u * row_count + row] = r18;
    lookup_words[1u * row_count + row] = r18;
    lookup_words[169u * row_count + row] = r18;
    lookup_words[212u * row_count + row] = r3452;
    lookup_words[253u * row_count + row] = r1;
}
