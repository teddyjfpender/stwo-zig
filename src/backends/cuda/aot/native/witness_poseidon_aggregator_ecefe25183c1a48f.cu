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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_eebaf3650dcb7ba3(
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
    unsigned r29 = 29u;
    unsigned r30 = 30u;
    unsigned r31 = 31u;
    unsigned r32 = 32u;
    unsigned r33 = 33u;
    unsigned r34 = 34u;
    unsigned r35 = 35u;
    lookup_words[392u * row_count + row] = r35;
    unsigned r36 = 39u;
    unsigned r37 = 40u;
    unsigned r38 = 42u;
    unsigned r39 = 44u;
    unsigned r40 = 57u;
    unsigned r41 = 60u;
    unsigned r42 = 61u;
    unsigned r43 = 66u;
    unsigned r44 = 67u;
    unsigned r45 = 70u;
    unsigned r46 = 71u;
    unsigned r47 = 73u;
    unsigned r48 = 77u;
    unsigned r49 = 86u;
    unsigned r50 = 87u;
    unsigned r51 = 88u;
    unsigned r52 = 94u;
    unsigned r53 = 96u;
    unsigned r54 = 97u;
    unsigned r55 = 99u;
    unsigned r56 = 100u;
    unsigned r57 = 109u;
    unsigned r58 = 111u;
    unsigned r59 = 112u;
    unsigned r60 = 116u;
    unsigned r61 = 120u;
    unsigned r62 = 127u;
    unsigned r63 = 129u;
    unsigned r64 = 131u;
    unsigned r65 = 132u;
    unsigned r66 = 135u;
    unsigned r67 = 136u;
    unsigned r68 = 138u;
    unsigned r69 = 139u;
    unsigned r70 = 140u;
    unsigned r71 = 143u;
    unsigned r72 = 145u;
    unsigned r73 = 148u;
    unsigned r74 = 154u;
    unsigned r75 = 157u;
    unsigned r76 = 163u;
    unsigned r77 = 164u;
    unsigned r78 = 170u;
    unsigned r79 = 171u;
    unsigned r80 = 173u;
    unsigned r81 = 181u;
    unsigned r82 = 182u;
    unsigned r83 = 183u;
    unsigned r84 = 184u;
    unsigned r85 = 186u;
    unsigned r86 = 187u;
    unsigned r87 = 189u;
    unsigned r88 = 190u;
    unsigned r89 = 192u;
    unsigned r90 = 193u;
    unsigned r91 = 196u;
    unsigned r92 = 199u;
    unsigned r93 = 200u;
    unsigned r94 = 201u;
    unsigned r95 = 207u;
    unsigned r96 = 208u;
    unsigned r97 = 211u;
    unsigned r98 = 213u;
    unsigned r99 = 215u;
    unsigned r100 = 220u;
    unsigned r101 = 221u;
    unsigned r102 = 223u;
    unsigned r103 = 226u;
    unsigned r104 = 228u;
    unsigned r105 = 229u;
    unsigned r106 = 231u;
    unsigned r107 = 236u;
    unsigned r108 = 237u;
    unsigned r109 = 238u;
    unsigned r110 = 241u;
    unsigned r111 = 248u;
    unsigned r112 = 250u;
    unsigned r113 = 256u;
    unsigned r114 = 259u;
    unsigned r115 = 261u;
    unsigned r116 = 263u;
    unsigned r117 = 265u;
    unsigned r118 = 267u;
    unsigned r119 = 275u;
    unsigned r120 = 281u;
    unsigned r121 = 285u;
    unsigned r122 = 286u;
    unsigned r123 = 289u;
    unsigned r124 = 290u;
    unsigned r125 = 291u;
    unsigned r126 = 294u;
    unsigned r127 = 295u;
    unsigned r128 = 300u;
    unsigned r129 = 301u;
    unsigned r130 = 303u;
    unsigned r131 = 315u;
    unsigned r132 = 320u;
    unsigned r133 = 321u;
    unsigned r134 = 330u;
    unsigned r135 = 331u;
    unsigned r136 = 338u;
    unsigned r137 = 339u;
    unsigned r138 = 344u;
    unsigned r139 = 346u;
    unsigned r140 = 347u;
    unsigned r141 = 350u;
    unsigned r142 = 354u;
    unsigned r143 = 357u;
    unsigned r144 = 360u;
    unsigned r145 = 362u;
    unsigned r146 = 363u;
    unsigned r147 = 365u;
    unsigned r148 = 381u;
    unsigned r149 = 382u;
    unsigned r150 = 386u;
    unsigned r151 = 389u;
    unsigned r152 = 393u;
    unsigned r153 = 395u;
    unsigned r154 = 398u;
    unsigned r155 = 399u;
    unsigned r156 = 402u;
    unsigned r157 = 409u;
    unsigned r158 = 413u;
    unsigned r159 = 418u;
    unsigned r160 = 421u;
    unsigned r161 = 424u;
    unsigned r162 = 426u;
    unsigned r163 = 428u;
    unsigned r164 = 429u;
    unsigned r165 = 430u;
    unsigned r166 = 431u;
    unsigned r167 = 434u;
    unsigned r168 = 446u;
    unsigned r169 = 447u;
    unsigned r170 = 453u;
    unsigned r171 = 454u;
    unsigned r172 = 459u;
    unsigned r173 = 461u;
    unsigned r174 = 462u;
    unsigned r175 = 463u;
    unsigned r176 = 464u;
    unsigned r177 = 466u;
    unsigned r178 = 469u;
    unsigned r179 = 472u;
    unsigned r180 = 478u;
    unsigned r181 = 481u;
    unsigned r182 = 488u;
    unsigned r183 = 490u;
    unsigned r184 = 493u;
    unsigned r185 = 494u;
    unsigned r186 = 497u;
    unsigned r187 = 500u;
    unsigned r188 = 505u;
    unsigned r189 = 508u;
    unsigned r190 = 511u;
    unsigned r191 = 512u;
    unsigned r192 = 8192u;
    unsigned r193 = 262144u;
    unsigned r194 = 4883209u;
    unsigned r195 = 4974792u;
    unsigned r196 = 16173996u;
    unsigned r197 = 18765944u;
    unsigned r198 = 19292069u;
    unsigned r199 = 22899501u;
    unsigned r200 = 28820206u;
    unsigned r201 = 33413160u;
    unsigned r202 = 33439011u;
    unsigned r203 = 36279186u;
    unsigned r204 = 40454143u;
    unsigned r205 = 41224388u;
    unsigned r206 = 41320857u;
    unsigned r207 = 44781849u;
    unsigned r208 = 44848225u;
    unsigned r209 = 45351266u;
    unsigned r210 = 45553283u;
    unsigned r211 = 48193339u;
    unsigned r212 = 48383197u;
    unsigned r213 = 48945103u;
    unsigned r214 = 49157069u;
    unsigned r215 = 49554771u;
    unsigned r216 = 50468641u;
    unsigned r217 = 50758155u;
    unsigned r218 = 54415179u;
    unsigned r219 = 55508188u;
    unsigned r220 = 55955004u;
    unsigned r221 = 58475513u;
    unsigned r222 = 59852719u;
    unsigned r223 = 60124463u;
    unsigned r224 = 60709090u;
    unsigned r225 = 62360091u;
    unsigned r226 = 62439890u;
    unsigned r227 = 65659846u;
    unsigned r228 = 68491350u;
    unsigned r229 = 72285071u;
    unsigned r230 = 74972783u;
    unsigned r231 = 75104388u;
    unsigned r232 = 77099918u;
    unsigned r233 = 78826183u;
    unsigned r234 = 79012328u;
    unsigned r235 = 86573645u;
    unsigned r236 = 88680813u;
    unsigned r237 = 90391646u;
    unsigned r238 = 90842759u;
    unsigned r239 = 91013252u;
    unsigned r240 = 94624323u;
    unsigned r241 = 95050340u;
    unsigned r242 = 102193642u;
    unsigned r243 = 103094260u;
    unsigned r244 = 108487870u;
    unsigned r245 = 112479959u;
    unsigned r246 = 112795138u;
    unsigned r247 = 116986206u;
    unsigned r248 = 117420501u;
    unsigned r249 = 119023582u;
    unsigned r250 = 120369218u;
    unsigned r251 = 121146754u;
    unsigned r252 = 121657377u;
    unsigned r253 = 122233508u;
    unsigned r254 = 129717753u;
    unsigned r255 = 130418270u;
    unsigned r256 = 133303902u;
    unsigned r257 = 134217729u;
    unsigned r258 = 402653187u;
    unsigned r259 = 502259093u;
    lookup_words[199u * row_count + row] = r259;
    lookup_words[205u * row_count + row] = r259;
    unsigned r260 = 1027333874u;
    lookup_words[232u * row_count + row] = r260;
    lookup_words[237u * row_count + row] = r260;
    lookup_words[331u * row_count + row] = r260;
    lookup_words[336u * row_count + row] = r260;
    lookup_words[344u * row_count + row] = r260;
    lookup_words[349u * row_count + row] = r260;
    unsigned r261 = 1090315331u;
    lookup_words[156u * row_count + row] = r261;
    lookup_words[167u * row_count + row] = r261;
    unsigned r262 = 1343313504u;
    lookup_words[245u * row_count + row] = r262;
    lookup_words[288u * row_count + row] = r262;
    unsigned r263 = 1480369132u;
    lookup_words[90u * row_count + row] = r263;
    lookup_words[123u * row_count + row] = r263;
    lookup_words[357u * row_count + row] = r263;
    lookup_words[390u * row_count + row] = r263;
    unsigned r264 = 1551892206u;
    lookup_words[513u * row_count + row] = r264;
    unsigned r265 = 1651211826u;
    lookup_words[242u * row_count + row] = r265;
    lookup_words[341u * row_count + row] = r265;
    lookup_words[354u * row_count + row] = r265;
    unsigned r266 = 1662111297u;
    lookup_words[0u * row_count + row] = r266;
    lookup_words[30u * row_count + row] = r266;
    lookup_words[60u * row_count + row] = r266;
    lookup_words[423u * row_count + row] = r266;
    lookup_words[453u * row_count + row] = r266;
    lookup_words[483u * row_count + row] = r266;
    unsigned r267 = 1987997202u;
    lookup_words[178u * row_count + row] = r267;
    lookup_words[211u * row_count + row] = r267;
    unsigned r268 = input_cols[7u][row];
    unsigned r269 = input_cols[0u][row];
    unsigned r270 = input_cols[1u][row];
    unsigned r271 = input_cols[2u][row];
    unsigned r272 = input_cols[3u][row];
    out_cols[3u][row] = r272;
    sub_words[3u * row_count + row] = r272;
    lookup_words[424u * row_count + row] = r272;
    lookup_words[517u * row_count + row] = r272;
    unsigned r273 = input_cols[4u][row];
    out_cols[4u][row] = r273;
    sub_words[4u * row_count + row] = r273;
    lookup_words[454u * row_count + row] = r273;
    lookup_words[518u * row_count + row] = r273;
    unsigned r274 = input_cols[5u][row];
    out_cols[5u][row] = r274;
    sub_words[5u * row_count + row] = r274;
    lookup_words[484u * row_count + row] = r274;
    lookup_words[519u * row_count + row] = r274;
    unsigned r275 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 0u);
    unsigned r276 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 1u);
    unsigned r277 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 2u);
    unsigned r278 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 3u);
    unsigned r279 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 4u);
    unsigned r280 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 5u);
    unsigned r281 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 6u);
    unsigned r282 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 7u);
    unsigned r283 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 8u);
    unsigned r284 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 9u);
    unsigned r285 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 10u);
    unsigned r286 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 11u);
    unsigned r287 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 12u);
    unsigned r288 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 13u);
    unsigned r289 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 14u);
    unsigned r290 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 15u);
    unsigned r291 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 16u);
    unsigned r292 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 17u);
    unsigned r293 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 18u);
    unsigned r294 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 19u);
    unsigned r295 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 20u);
    unsigned r296 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 21u);
    unsigned r297 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 22u);
    unsigned r298 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 23u);
    unsigned r299 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 24u);
    unsigned r300 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 25u);
    unsigned r301 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 26u);
    unsigned r302 = stwo_wit_deduce_limb(table_bases, table_strides, r269, 27u);
    out_cols[0u][row] = r269;
    sub_words[0u * row_count + row] = r269;
    lookup_words[1u * row_count + row] = r269;
    lookup_words[514u * row_count + row] = r269;
    unsigned r303 = stwo_m31_mul(r276, r191);
    out_cols[7u][row] = r276;
    lookup_words[3u * row_count + row] = r276;
    unsigned r304 = stwo_m31_add(r275, r303);
    out_cols[6u][row] = r275;
    lookup_words[2u * row_count + row] = r275;
    unsigned r305 = stwo_m31_mul(r277, r193);
    out_cols[8u][row] = r277;
    lookup_words[4u * row_count + row] = r277;
    unsigned r306 = stwo_m31_add(r304, r305);
    unsigned r307 = stwo_m31_mul(r279, r191);
    out_cols[10u][row] = r279;
    lookup_words[6u * row_count + row] = r279;
    unsigned r308 = stwo_m31_add(r278, r307);
    out_cols[9u][row] = r278;
    lookup_words[5u * row_count + row] = r278;
    unsigned r309 = stwo_m31_mul(r280, r193);
    out_cols[11u][row] = r280;
    lookup_words[7u * row_count + row] = r280;
    unsigned r310 = stwo_m31_add(r308, r309);
    unsigned r311 = stwo_m31_mul(r282, r191);
    out_cols[13u][row] = r282;
    lookup_words[9u * row_count + row] = r282;
    unsigned r312 = stwo_m31_add(r281, r311);
    out_cols[12u][row] = r281;
    lookup_words[8u * row_count + row] = r281;
    unsigned r313 = stwo_m31_mul(r283, r193);
    out_cols[14u][row] = r283;
    lookup_words[10u * row_count + row] = r283;
    unsigned r314 = stwo_m31_add(r312, r313);
    unsigned r315 = stwo_m31_mul(r285, r191);
    out_cols[16u][row] = r285;
    lookup_words[12u * row_count + row] = r285;
    unsigned r316 = stwo_m31_add(r284, r315);
    out_cols[15u][row] = r284;
    lookup_words[11u * row_count + row] = r284;
    unsigned r317 = stwo_m31_mul(r286, r193);
    out_cols[17u][row] = r286;
    lookup_words[13u * row_count + row] = r286;
    unsigned r318 = stwo_m31_add(r316, r317);
    unsigned r319 = stwo_m31_mul(r288, r191);
    out_cols[19u][row] = r288;
    lookup_words[15u * row_count + row] = r288;
    unsigned r320 = stwo_m31_add(r287, r319);
    out_cols[18u][row] = r287;
    lookup_words[14u * row_count + row] = r287;
    unsigned r321 = stwo_m31_mul(r289, r193);
    out_cols[20u][row] = r289;
    lookup_words[16u * row_count + row] = r289;
    unsigned r322 = stwo_m31_add(r320, r321);
    unsigned r323 = stwo_m31_mul(r291, r191);
    out_cols[22u][row] = r291;
    lookup_words[18u * row_count + row] = r291;
    unsigned r324 = stwo_m31_add(r290, r323);
    out_cols[21u][row] = r290;
    lookup_words[17u * row_count + row] = r290;
    unsigned r325 = stwo_m31_mul(r292, r193);
    out_cols[23u][row] = r292;
    lookup_words[19u * row_count + row] = r292;
    unsigned r326 = stwo_m31_add(r324, r325);
    unsigned r327 = stwo_m31_mul(r294, r191);
    out_cols[25u][row] = r294;
    lookup_words[21u * row_count + row] = r294;
    unsigned r328 = stwo_m31_add(r293, r327);
    out_cols[24u][row] = r293;
    lookup_words[20u * row_count + row] = r293;
    unsigned r329 = stwo_m31_mul(r295, r193);
    out_cols[26u][row] = r295;
    lookup_words[22u * row_count + row] = r295;
    unsigned r330 = stwo_m31_add(r328, r329);
    unsigned r331 = stwo_m31_mul(r297, r191);
    out_cols[28u][row] = r297;
    lookup_words[24u * row_count + row] = r297;
    unsigned r332 = stwo_m31_add(r296, r331);
    out_cols[27u][row] = r296;
    lookup_words[23u * row_count + row] = r296;
    unsigned r333 = stwo_m31_mul(r298, r193);
    out_cols[29u][row] = r298;
    lookup_words[25u * row_count + row] = r298;
    unsigned r334 = stwo_m31_add(r332, r333);
    unsigned r335 = stwo_m31_mul(r300, r191);
    out_cols[31u][row] = r300;
    lookup_words[27u * row_count + row] = r300;
    unsigned r336 = stwo_m31_add(r299, r335);
    out_cols[30u][row] = r299;
    lookup_words[26u * row_count + row] = r299;
    unsigned r337 = stwo_m31_mul(r301, r193);
    out_cols[32u][row] = r301;
    lookup_words[28u * row_count + row] = r301;
    unsigned r338 = stwo_m31_add(r336, r337);
    unsigned r339 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 0u);
    unsigned r340 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 1u);
    unsigned r341 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 2u);
    unsigned r342 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 3u);
    unsigned r343 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 4u);
    unsigned r344 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 5u);
    unsigned r345 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 6u);
    unsigned r346 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 7u);
    unsigned r347 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 8u);
    unsigned r348 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 9u);
    unsigned r349 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 10u);
    unsigned r350 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 11u);
    unsigned r351 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 12u);
    unsigned r352 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 13u);
    unsigned r353 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 14u);
    unsigned r354 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 15u);
    unsigned r355 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 16u);
    unsigned r356 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 17u);
    unsigned r357 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 18u);
    unsigned r358 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 19u);
    unsigned r359 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 20u);
    unsigned r360 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 21u);
    unsigned r361 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 22u);
    unsigned r362 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 23u);
    unsigned r363 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 24u);
    unsigned r364 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 25u);
    unsigned r365 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 26u);
    unsigned r366 = stwo_wit_deduce_limb(table_bases, table_strides, r270, 27u);
    out_cols[1u][row] = r270;
    sub_words[1u * row_count + row] = r270;
    lookup_words[31u * row_count + row] = r270;
    lookup_words[515u * row_count + row] = r270;
    unsigned r367 = stwo_m31_mul(r340, r191);
    out_cols[35u][row] = r340;
    lookup_words[33u * row_count + row] = r340;
    unsigned r368 = stwo_m31_add(r339, r367);
    out_cols[34u][row] = r339;
    lookup_words[32u * row_count + row] = r339;
    unsigned r369 = stwo_m31_mul(r341, r193);
    out_cols[36u][row] = r341;
    lookup_words[34u * row_count + row] = r341;
    unsigned r370 = stwo_m31_add(r368, r369);
    unsigned r371 = stwo_m31_mul(r343, r191);
    out_cols[38u][row] = r343;
    lookup_words[36u * row_count + row] = r343;
    unsigned r372 = stwo_m31_add(r342, r371);
    out_cols[37u][row] = r342;
    lookup_words[35u * row_count + row] = r342;
    unsigned r373 = stwo_m31_mul(r344, r193);
    out_cols[39u][row] = r344;
    lookup_words[37u * row_count + row] = r344;
    unsigned r374 = stwo_m31_add(r372, r373);
    unsigned r375 = stwo_m31_mul(r346, r191);
    out_cols[41u][row] = r346;
    lookup_words[39u * row_count + row] = r346;
    unsigned r376 = stwo_m31_add(r345, r375);
    out_cols[40u][row] = r345;
    lookup_words[38u * row_count + row] = r345;
    unsigned r377 = stwo_m31_mul(r347, r193);
    out_cols[42u][row] = r347;
    lookup_words[40u * row_count + row] = r347;
    unsigned r378 = stwo_m31_add(r376, r377);
    unsigned r379 = stwo_m31_mul(r349, r191);
    out_cols[44u][row] = r349;
    lookup_words[42u * row_count + row] = r349;
    unsigned r380 = stwo_m31_add(r348, r379);
    out_cols[43u][row] = r348;
    lookup_words[41u * row_count + row] = r348;
    unsigned r381 = stwo_m31_mul(r350, r193);
    out_cols[45u][row] = r350;
    lookup_words[43u * row_count + row] = r350;
    unsigned r382 = stwo_m31_add(r380, r381);
    unsigned r383 = stwo_m31_mul(r352, r191);
    out_cols[47u][row] = r352;
    lookup_words[45u * row_count + row] = r352;
    unsigned r384 = stwo_m31_add(r351, r383);
    out_cols[46u][row] = r351;
    lookup_words[44u * row_count + row] = r351;
    unsigned r385 = stwo_m31_mul(r353, r193);
    out_cols[48u][row] = r353;
    lookup_words[46u * row_count + row] = r353;
    unsigned r386 = stwo_m31_add(r384, r385);
    unsigned r387 = stwo_m31_mul(r355, r191);
    out_cols[50u][row] = r355;
    lookup_words[48u * row_count + row] = r355;
    unsigned r388 = stwo_m31_add(r354, r387);
    out_cols[49u][row] = r354;
    lookup_words[47u * row_count + row] = r354;
    unsigned r389 = stwo_m31_mul(r356, r193);
    out_cols[51u][row] = r356;
    lookup_words[49u * row_count + row] = r356;
    unsigned r390 = stwo_m31_add(r388, r389);
    unsigned r391 = stwo_m31_mul(r358, r191);
    out_cols[53u][row] = r358;
    lookup_words[51u * row_count + row] = r358;
    unsigned r392 = stwo_m31_add(r357, r391);
    out_cols[52u][row] = r357;
    lookup_words[50u * row_count + row] = r357;
    unsigned r393 = stwo_m31_mul(r359, r193);
    out_cols[54u][row] = r359;
    lookup_words[52u * row_count + row] = r359;
    unsigned r394 = stwo_m31_add(r392, r393);
    unsigned r395 = stwo_m31_mul(r361, r191);
    out_cols[56u][row] = r361;
    lookup_words[54u * row_count + row] = r361;
    unsigned r396 = stwo_m31_add(r360, r395);
    out_cols[55u][row] = r360;
    lookup_words[53u * row_count + row] = r360;
    unsigned r397 = stwo_m31_mul(r362, r193);
    out_cols[57u][row] = r362;
    lookup_words[55u * row_count + row] = r362;
    unsigned r398 = stwo_m31_add(r396, r397);
    unsigned r399 = stwo_m31_mul(r364, r191);
    out_cols[59u][row] = r364;
    lookup_words[57u * row_count + row] = r364;
    unsigned r400 = stwo_m31_add(r363, r399);
    out_cols[58u][row] = r363;
    lookup_words[56u * row_count + row] = r363;
    unsigned r401 = stwo_m31_mul(r365, r193);
    out_cols[60u][row] = r365;
    lookup_words[58u * row_count + row] = r365;
    unsigned r402 = stwo_m31_add(r400, r401);
    unsigned r403 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 0u);
    unsigned r404 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 1u);
    unsigned r405 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 2u);
    unsigned r406 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 3u);
    unsigned r407 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 4u);
    unsigned r408 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 5u);
    unsigned r409 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 6u);
    unsigned r410 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 7u);
    unsigned r411 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 8u);
    unsigned r412 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 9u);
    unsigned r413 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 10u);
    unsigned r414 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 11u);
    unsigned r415 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 12u);
    unsigned r416 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 13u);
    unsigned r417 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 14u);
    unsigned r418 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 15u);
    unsigned r419 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 16u);
    unsigned r420 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 17u);
    unsigned r421 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 18u);
    unsigned r422 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 19u);
    unsigned r423 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 20u);
    unsigned r424 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 21u);
    unsigned r425 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 22u);
    unsigned r426 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 23u);
    unsigned r427 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 24u);
    unsigned r428 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 25u);
    unsigned r429 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 26u);
    unsigned r430 = stwo_wit_deduce_limb(table_bases, table_strides, r271, 27u);
    out_cols[2u][row] = r271;
    sub_words[2u * row_count + row] = r271;
    lookup_words[61u * row_count + row] = r271;
    lookup_words[516u * row_count + row] = r271;
    unsigned r431 = stwo_m31_mul(r404, r191);
    out_cols[63u][row] = r404;
    lookup_words[63u * row_count + row] = r404;
    unsigned r432 = stwo_m31_add(r403, r431);
    out_cols[62u][row] = r403;
    lookup_words[62u * row_count + row] = r403;
    unsigned r433 = stwo_m31_mul(r405, r193);
    out_cols[64u][row] = r405;
    lookup_words[64u * row_count + row] = r405;
    unsigned r434 = stwo_m31_add(r432, r433);
    unsigned r435 = stwo_m31_mul(r407, r191);
    out_cols[66u][row] = r407;
    lookup_words[66u * row_count + row] = r407;
    unsigned r436 = stwo_m31_add(r406, r435);
    out_cols[65u][row] = r406;
    lookup_words[65u * row_count + row] = r406;
    unsigned r437 = stwo_m31_mul(r408, r193);
    out_cols[67u][row] = r408;
    lookup_words[67u * row_count + row] = r408;
    unsigned r438 = stwo_m31_add(r436, r437);
    unsigned r439 = stwo_m31_mul(r410, r191);
    out_cols[69u][row] = r410;
    lookup_words[69u * row_count + row] = r410;
    unsigned r440 = stwo_m31_add(r409, r439);
    out_cols[68u][row] = r409;
    lookup_words[68u * row_count + row] = r409;
    unsigned r441 = stwo_m31_mul(r411, r193);
    out_cols[70u][row] = r411;
    lookup_words[70u * row_count + row] = r411;
    unsigned r442 = stwo_m31_add(r440, r441);
    unsigned r443 = stwo_m31_mul(r413, r191);
    out_cols[72u][row] = r413;
    lookup_words[72u * row_count + row] = r413;
    unsigned r444 = stwo_m31_add(r412, r443);
    out_cols[71u][row] = r412;
    lookup_words[71u * row_count + row] = r412;
    unsigned r445 = stwo_m31_mul(r414, r193);
    out_cols[73u][row] = r414;
    lookup_words[73u * row_count + row] = r414;
    unsigned r446 = stwo_m31_add(r444, r445);
    unsigned r447 = stwo_m31_mul(r416, r191);
    out_cols[75u][row] = r416;
    lookup_words[75u * row_count + row] = r416;
    unsigned r448 = stwo_m31_add(r415, r447);
    out_cols[74u][row] = r415;
    lookup_words[74u * row_count + row] = r415;
    unsigned r449 = stwo_m31_mul(r417, r193);
    out_cols[76u][row] = r417;
    lookup_words[76u * row_count + row] = r417;
    unsigned r450 = stwo_m31_add(r448, r449);
    unsigned r451 = stwo_m31_mul(r419, r191);
    out_cols[78u][row] = r419;
    lookup_words[78u * row_count + row] = r419;
    unsigned r452 = stwo_m31_add(r418, r451);
    out_cols[77u][row] = r418;
    lookup_words[77u * row_count + row] = r418;
    unsigned r453 = stwo_m31_mul(r420, r193);
    out_cols[79u][row] = r420;
    lookup_words[79u * row_count + row] = r420;
    unsigned r454 = stwo_m31_add(r452, r453);
    unsigned r455 = stwo_m31_mul(r422, r191);
    out_cols[81u][row] = r422;
    lookup_words[81u * row_count + row] = r422;
    unsigned r456 = stwo_m31_add(r421, r455);
    out_cols[80u][row] = r421;
    lookup_words[80u * row_count + row] = r421;
    unsigned r457 = stwo_m31_mul(r423, r193);
    out_cols[82u][row] = r423;
    lookup_words[82u * row_count + row] = r423;
    unsigned r458 = stwo_m31_add(r456, r457);
    unsigned r459 = stwo_m31_mul(r425, r191);
    out_cols[84u][row] = r425;
    lookup_words[84u * row_count + row] = r425;
    unsigned r460 = stwo_m31_add(r424, r459);
    out_cols[83u][row] = r424;
    lookup_words[83u * row_count + row] = r424;
    unsigned r461 = stwo_m31_mul(r426, r193);
    out_cols[85u][row] = r426;
    lookup_words[85u * row_count + row] = r426;
    unsigned r462 = stwo_m31_add(r460, r461);
    unsigned r463 = stwo_m31_mul(r428, r191);
    out_cols[87u][row] = r428;
    lookup_words[87u * row_count + row] = r428;
    unsigned r464 = stwo_m31_add(r427, r463);
    out_cols[86u][row] = r427;
    lookup_words[86u * row_count + row] = r427;
    unsigned r465 = stwo_m31_mul(r429, r193);
    out_cols[88u][row] = r429;
    lookup_words[88u * row_count + row] = r429;
    unsigned r466 = stwo_m31_add(r464, r465);
    unsigned r467 = (r306 & 511u);
    unsigned r468 = (r306 >> 9u);
    unsigned r469 = (r468 & 511u);
    unsigned r470 = (r306 >> 18u);
    unsigned r471 = (r470 & 511u);
    unsigned r472 = (r310 & 511u);
    unsigned r473 = (r310 >> 9u);
    unsigned r474 = (r473 & 511u);
    unsigned r475 = (r310 >> 18u);
    unsigned r476 = (r475 & 511u);
    unsigned r477 = (r314 & 511u);
    unsigned r478 = (r314 >> 9u);
    unsigned r479 = (r478 & 511u);
    unsigned r480 = (r314 >> 18u);
    unsigned r481 = (r480 & 511u);
    unsigned r482 = (r318 & 511u);
    unsigned r483 = (r318 >> 9u);
    unsigned r484 = (r483 & 511u);
    unsigned r485 = (r318 >> 18u);
    unsigned r486 = (r485 & 511u);
    unsigned r487 = (r322 & 511u);
    unsigned r488 = (r322 >> 9u);
    unsigned r489 = (r488 & 511u);
    unsigned r490 = (r322 >> 18u);
    unsigned r491 = (r490 & 511u);
    unsigned r492 = (r326 & 511u);
    unsigned r493 = (r326 >> 9u);
    unsigned r494 = (r493 & 511u);
    unsigned r495 = (r326 >> 18u);
    unsigned r496 = (r495 & 511u);
    unsigned r497 = (r330 & 511u);
    unsigned r498 = (r330 >> 9u);
    unsigned r499 = (r498 & 511u);
    unsigned r500 = (r330 >> 18u);
    unsigned r501 = (r500 & 511u);
    unsigned r502 = (r334 & 511u);
    unsigned r503 = (r334 >> 9u);
    unsigned r504 = (r503 & 511u);
    unsigned r505 = (r334 >> 18u);
    unsigned r506 = (r505 & 511u);
    unsigned r507 = (r338 & 511u);
    unsigned r508 = (r338 >> 9u);
    unsigned r509 = (r508 & 511u);
    unsigned r510 = (r338 >> 18u);
    unsigned r511 = (r510 & 511u);
    unsigned r512 = (r302 & 511u);
    out_cols[33u][row] = r302;
    lookup_words[29u * row_count + row] = r302;
    const unsigned dargs0[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r467, r469, r471, r472, r474, r476, r477, r479, r481, r482, r484, r486, r487, r489, r491, r492, r494, r496, r497, r499, r501, r502, r504, r506, r507, r509, r511, r512 };
    unsigned douts0[28];
    stwo_wit_deduce_felt_mul(dargs0, douts0);
    unsigned r513 = douts0[0];
    unsigned r514 = douts0[1];
    unsigned r515 = douts0[2];
    unsigned r516 = douts0[3];
    unsigned r517 = douts0[4];
    unsigned r518 = douts0[5];
    unsigned r519 = douts0[6];
    unsigned r520 = douts0[7];
    unsigned r521 = douts0[8];
    unsigned r522 = douts0[9];
    unsigned r523 = douts0[10];
    unsigned r524 = douts0[11];
    unsigned r525 = douts0[12];
    unsigned r526 = douts0[13];
    unsigned r527 = douts0[14];
    unsigned r528 = douts0[15];
    unsigned r529 = douts0[16];
    unsigned r530 = douts0[17];
    unsigned r531 = douts0[18];
    unsigned r532 = douts0[19];
    unsigned r533 = douts0[20];
    unsigned r534 = douts0[21];
    unsigned r535 = douts0[22];
    unsigned r536 = douts0[23];
    unsigned r537 = douts0[24];
    unsigned r538 = douts0[25];
    unsigned r539 = douts0[26];
    unsigned r540 = douts0[27];
    const unsigned dargs1[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r513, r514, r515, r516, r517, r518, r519, r520, r521, r522, r523, r524, r525, r526, r527, r528, r529, r530, r531, r532, r533, r534, r535, r536, r537, r538, r539, r540 };
    unsigned douts1[28];
    stwo_wit_deduce_felt_add(dargs1, douts1);
    unsigned r541 = douts1[0];
    unsigned r542 = douts1[1];
    unsigned r543 = douts1[2];
    unsigned r544 = douts1[3];
    unsigned r545 = douts1[4];
    unsigned r546 = douts1[5];
    unsigned r547 = douts1[6];
    unsigned r548 = douts1[7];
    unsigned r549 = douts1[8];
    unsigned r550 = douts1[9];
    unsigned r551 = douts1[10];
    unsigned r552 = douts1[11];
    unsigned r553 = douts1[12];
    unsigned r554 = douts1[13];
    unsigned r555 = douts1[14];
    unsigned r556 = douts1[15];
    unsigned r557 = douts1[16];
    unsigned r558 = douts1[17];
    unsigned r559 = douts1[18];
    unsigned r560 = douts1[19];
    unsigned r561 = douts1[20];
    unsigned r562 = douts1[21];
    unsigned r563 = douts1[22];
    unsigned r564 = douts1[23];
    unsigned r565 = douts1[24];
    unsigned r566 = douts1[25];
    unsigned r567 = douts1[26];
    unsigned r568 = douts1[27];
    const unsigned dargs2[56] = { r541, r542, r543, r544, r545, r546, r547, r548, r549, r550, r551, r552, r553, r554, r555, r556, r557, r558, r559, r560, r561, r562, r563, r564, r565, r566, r567, r568, r58, r190, r121, r178, r179, r169, r2, r71, r165, r65, r53, r140, r103, r128, r106, r54, r38, r79, r88, r167, r158, r120, r161, r78, r183, r163, r151, r96 };
    unsigned douts2[28];
    stwo_wit_deduce_felt_add(dargs2, douts2);
    unsigned r569 = douts2[0];
    unsigned r570 = douts2[1];
    unsigned r571 = douts2[2];
    unsigned r572 = douts2[3];
    unsigned r573 = douts2[4];
    unsigned r574 = douts2[5];
    unsigned r575 = douts2[6];
    unsigned r576 = douts2[7];
    unsigned r577 = douts2[8];
    unsigned r578 = douts2[9];
    unsigned r579 = douts2[10];
    unsigned r580 = douts2[11];
    unsigned r581 = douts2[12];
    unsigned r582 = douts2[13];
    unsigned r583 = douts2[14];
    unsigned r584 = douts2[15];
    unsigned r585 = douts2[16];
    unsigned r586 = douts2[17];
    unsigned r587 = douts2[18];
    unsigned r588 = douts2[19];
    unsigned r589 = douts2[20];
    unsigned r590 = douts2[21];
    unsigned r591 = douts2[22];
    unsigned r592 = douts2[23];
    unsigned r593 = douts2[24];
    unsigned r594 = douts2[25];
    unsigned r595 = douts2[26];
    unsigned r596 = douts2[27];
    unsigned r597 = stwo_m31_mul(r570, r191);
    unsigned r598 = stwo_m31_add(r569, r597);
    unsigned r599 = stwo_m31_mul(r571, r193);
    unsigned r600 = stwo_m31_add(r598, r599);
    unsigned r601 = stwo_m31_mul(r573, r191);
    unsigned r602 = stwo_m31_add(r572, r601);
    unsigned r603 = stwo_m31_mul(r574, r193);
    unsigned r604 = stwo_m31_add(r602, r603);
    unsigned r605 = stwo_m31_mul(r576, r191);
    unsigned r606 = stwo_m31_add(r575, r605);
    unsigned r607 = stwo_m31_mul(r577, r193);
    unsigned r608 = stwo_m31_add(r606, r607);
    unsigned r609 = stwo_m31_mul(r579, r191);
    unsigned r610 = stwo_m31_add(r578, r609);
    unsigned r611 = stwo_m31_mul(r580, r193);
    unsigned r612 = stwo_m31_add(r610, r611);
    unsigned r613 = stwo_m31_mul(r582, r191);
    unsigned r614 = stwo_m31_add(r581, r613);
    unsigned r615 = stwo_m31_mul(r583, r193);
    unsigned r616 = stwo_m31_add(r614, r615);
    unsigned r617 = stwo_m31_mul(r585, r191);
    unsigned r618 = stwo_m31_add(r584, r617);
    unsigned r619 = stwo_m31_mul(r586, r193);
    unsigned r620 = stwo_m31_add(r618, r619);
    unsigned r621 = stwo_m31_mul(r588, r191);
    unsigned r622 = stwo_m31_add(r587, r621);
    unsigned r623 = stwo_m31_mul(r589, r193);
    unsigned r624 = stwo_m31_add(r622, r623);
    unsigned r625 = stwo_m31_mul(r591, r191);
    unsigned r626 = stwo_m31_add(r590, r625);
    unsigned r627 = stwo_m31_mul(r592, r193);
    unsigned r628 = stwo_m31_add(r626, r627);
    unsigned r629 = stwo_m31_mul(r594, r191);
    unsigned r630 = stwo_m31_add(r593, r629);
    unsigned r631 = stwo_m31_mul(r595, r193);
    unsigned r632 = stwo_m31_add(r630, r631);
    unsigned r633 = stwo_m31_add(r306, r230);
    unsigned r634 = stwo_m31_sub(r633, r600);
    unsigned r635 = stwo_m31_add(r634, r257);
    unsigned r636 = (r635 & 65535u);
    unsigned r637 = (r636 % STWO_M31_P);
    unsigned r638 = stwo_m31_sub(r637, r1);
    unsigned r639 = stwo_m31_add(r306, r230);
    unsigned r640 = stwo_m31_sub(r639, r600);
    unsigned r641 = stwo_m31_sub(r640, r638);
    unsigned r642 = stwo_m31_mul(r641, r16);
    unsigned r643 = stwo_m31_add(r642, r310);
    unsigned r644 = stwo_m31_add(r643, r248);
    unsigned r645 = stwo_m31_sub(r644, r604);
    unsigned r646 = stwo_m31_mul(r645, r16);
    unsigned r647 = stwo_m31_add(r646, r314);
    unsigned r648 = stwo_m31_add(r647, r246);
    unsigned r649 = stwo_m31_sub(r648, r608);
    unsigned r650 = stwo_m31_mul(r649, r16);
    unsigned r651 = stwo_m31_add(r650, r318);
    unsigned r652 = stwo_m31_add(r651, r239);
    unsigned r653 = stwo_m31_sub(r652, r612);
    unsigned r654 = stwo_m31_mul(r653, r16);
    unsigned r655 = stwo_m31_add(r654, r322);
    unsigned r656 = stwo_m31_add(r655, r224);
    unsigned r657 = stwo_m31_sub(r656, r616);
    unsigned r658 = stwo_m31_mul(r657, r16);
    unsigned r659 = stwo_m31_add(r658, r326);
    unsigned r660 = stwo_m31_add(r659, r208);
    unsigned r661 = stwo_m31_sub(r660, r620);
    unsigned r662 = stwo_m31_mul(r661, r16);
    unsigned r663 = stwo_m31_add(r662, r330);
    unsigned r664 = stwo_m31_add(r663, r244);
    unsigned r665 = stwo_m31_sub(r664, r624);
    unsigned r666 = stwo_m31_mul(r665, r16);
    unsigned r667 = stwo_m31_add(r666, r334);
    unsigned r668 = stwo_m31_add(r667, r207);
    unsigned r669 = stwo_m31_sub(r668, r628);
    unsigned r670 = stwo_m31_mul(r638, r67);
    out_cols[100u][row] = r638;
    unsigned r671 = stwo_m31_sub(r669, r670);
    unsigned r672 = stwo_m31_mul(r671, r16);
    unsigned r673 = stwo_m31_add(r672, r338);
    unsigned r674 = stwo_m31_add(r673, r242);
    unsigned r675 = stwo_m31_sub(r674, r632);
    unsigned r676 = stwo_m31_mul(r675, r16);
    unsigned r677 = (r370 & 511u);
    unsigned r678 = (r370 >> 9u);
    unsigned r679 = (r678 & 511u);
    unsigned r680 = (r370 >> 18u);
    unsigned r681 = (r680 & 511u);
    unsigned r682 = (r374 & 511u);
    unsigned r683 = (r374 >> 9u);
    unsigned r684 = (r683 & 511u);
    unsigned r685 = (r374 >> 18u);
    unsigned r686 = (r685 & 511u);
    unsigned r687 = (r378 & 511u);
    unsigned r688 = (r378 >> 9u);
    unsigned r689 = (r688 & 511u);
    unsigned r690 = (r378 >> 18u);
    unsigned r691 = (r690 & 511u);
    unsigned r692 = (r382 & 511u);
    unsigned r693 = (r382 >> 9u);
    unsigned r694 = (r693 & 511u);
    unsigned r695 = (r382 >> 18u);
    unsigned r696 = (r695 & 511u);
    unsigned r697 = (r386 & 511u);
    unsigned r698 = (r386 >> 9u);
    unsigned r699 = (r698 & 511u);
    unsigned r700 = (r386 >> 18u);
    unsigned r701 = (r700 & 511u);
    unsigned r702 = (r390 & 511u);
    unsigned r703 = (r390 >> 9u);
    unsigned r704 = (r703 & 511u);
    unsigned r705 = (r390 >> 18u);
    unsigned r706 = (r705 & 511u);
    unsigned r707 = (r394 & 511u);
    unsigned r708 = (r394 >> 9u);
    unsigned r709 = (r708 & 511u);
    unsigned r710 = (r394 >> 18u);
    unsigned r711 = (r710 & 511u);
    unsigned r712 = (r398 & 511u);
    unsigned r713 = (r398 >> 9u);
    unsigned r714 = (r713 & 511u);
    unsigned r715 = (r398 >> 18u);
    unsigned r716 = (r715 & 511u);
    unsigned r717 = (r402 & 511u);
    unsigned r718 = (r402 >> 9u);
    unsigned r719 = (r718 & 511u);
    unsigned r720 = (r402 >> 18u);
    unsigned r721 = (r720 & 511u);
    unsigned r722 = (r366 & 511u);
    out_cols[61u][row] = r366;
    lookup_words[59u * row_count + row] = r366;
    const unsigned dargs3[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r677, r679, r681, r682, r684, r686, r687, r689, r691, r692, r694, r696, r697, r699, r701, r702, r704, r706, r707, r709, r711, r712, r714, r716, r717, r719, r721, r722 };
    unsigned douts3[28];
    stwo_wit_deduce_felt_mul(dargs3, douts3);
    unsigned r723 = douts3[0];
    unsigned r724 = douts3[1];
    unsigned r725 = douts3[2];
    unsigned r726 = douts3[3];
    unsigned r727 = douts3[4];
    unsigned r728 = douts3[5];
    unsigned r729 = douts3[6];
    unsigned r730 = douts3[7];
    unsigned r731 = douts3[8];
    unsigned r732 = douts3[9];
    unsigned r733 = douts3[10];
    unsigned r734 = douts3[11];
    unsigned r735 = douts3[12];
    unsigned r736 = douts3[13];
    unsigned r737 = douts3[14];
    unsigned r738 = douts3[15];
    unsigned r739 = douts3[16];
    unsigned r740 = douts3[17];
    unsigned r741 = douts3[18];
    unsigned r742 = douts3[19];
    unsigned r743 = douts3[20];
    unsigned r744 = douts3[21];
    unsigned r745 = douts3[22];
    unsigned r746 = douts3[23];
    unsigned r747 = douts3[24];
    unsigned r748 = douts3[25];
    unsigned r749 = douts3[26];
    unsigned r750 = douts3[27];
    const unsigned dargs4[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r723, r724, r725, r726, r727, r728, r729, r730, r731, r732, r733, r734, r735, r736, r737, r738, r739, r740, r741, r742, r743, r744, r745, r746, r747, r748, r749, r750 };
    unsigned douts4[28];
    stwo_wit_deduce_felt_add(dargs4, douts4);
    unsigned r751 = douts4[0];
    unsigned r752 = douts4[1];
    unsigned r753 = douts4[2];
    unsigned r754 = douts4[3];
    unsigned r755 = douts4[4];
    unsigned r756 = douts4[5];
    unsigned r757 = douts4[6];
    unsigned r758 = douts4[7];
    unsigned r759 = douts4[8];
    unsigned r760 = douts4[9];
    unsigned r761 = douts4[10];
    unsigned r762 = douts4[11];
    unsigned r763 = douts4[12];
    unsigned r764 = douts4[13];
    unsigned r765 = douts4[14];
    unsigned r766 = douts4[15];
    unsigned r767 = douts4[16];
    unsigned r768 = douts4[17];
    unsigned r769 = douts4[18];
    unsigned r770 = douts4[19];
    unsigned r771 = douts4[20];
    unsigned r772 = douts4[21];
    unsigned r773 = douts4[22];
    unsigned r774 = douts4[23];
    unsigned r775 = douts4[24];
    unsigned r776 = douts4[25];
    unsigned r777 = douts4[26];
    unsigned r778 = douts4[27];
    const unsigned dargs5[56] = { r751, r752, r753, r754, r755, r756, r757, r758, r759, r760, r761, r762, r763, r764, r765, r766, r767, r768, r769, r770, r771, r772, r773, r774, r775, r776, r777, r778, r91, r65, r75, r52, r159, r138, r156, r94, r68, r188, r162, r185, r44, r184, r144, r65, r113, r122, r52, r116, r189, r175, r146, r85, r157, r132, r75, r59 };
    unsigned douts5[28];
    stwo_wit_deduce_felt_add(dargs5, douts5);
    unsigned r779 = douts5[0];
    unsigned r780 = douts5[1];
    unsigned r781 = douts5[2];
    unsigned r782 = douts5[3];
    unsigned r783 = douts5[4];
    unsigned r784 = douts5[5];
    unsigned r785 = douts5[6];
    unsigned r786 = douts5[7];
    unsigned r787 = douts5[8];
    unsigned r788 = douts5[9];
    unsigned r789 = douts5[10];
    unsigned r790 = douts5[11];
    unsigned r791 = douts5[12];
    unsigned r792 = douts5[13];
    unsigned r793 = douts5[14];
    unsigned r794 = douts5[15];
    unsigned r795 = douts5[16];
    unsigned r796 = douts5[17];
    unsigned r797 = douts5[18];
    unsigned r798 = douts5[19];
    unsigned r799 = douts5[20];
    unsigned r800 = douts5[21];
    unsigned r801 = douts5[22];
    unsigned r802 = douts5[23];
    unsigned r803 = douts5[24];
    unsigned r804 = douts5[25];
    unsigned r805 = douts5[26];
    unsigned r806 = douts5[27];
    unsigned r807 = stwo_m31_mul(r780, r191);
    unsigned r808 = stwo_m31_add(r779, r807);
    unsigned r809 = stwo_m31_mul(r781, r193);
    unsigned r810 = stwo_m31_add(r808, r809);
    unsigned r811 = stwo_m31_mul(r783, r191);
    unsigned r812 = stwo_m31_add(r782, r811);
    unsigned r813 = stwo_m31_mul(r784, r193);
    unsigned r814 = stwo_m31_add(r812, r813);
    unsigned r815 = stwo_m31_mul(r786, r191);
    unsigned r816 = stwo_m31_add(r785, r815);
    unsigned r817 = stwo_m31_mul(r787, r193);
    unsigned r818 = stwo_m31_add(r816, r817);
    unsigned r819 = stwo_m31_mul(r789, r191);
    unsigned r820 = stwo_m31_add(r788, r819);
    unsigned r821 = stwo_m31_mul(r790, r193);
    unsigned r822 = stwo_m31_add(r820, r821);
    unsigned r823 = stwo_m31_mul(r792, r191);
    unsigned r824 = stwo_m31_add(r791, r823);
    unsigned r825 = stwo_m31_mul(r793, r193);
    unsigned r826 = stwo_m31_add(r824, r825);
    unsigned r827 = stwo_m31_mul(r795, r191);
    unsigned r828 = stwo_m31_add(r794, r827);
    unsigned r829 = stwo_m31_mul(r796, r193);
    unsigned r830 = stwo_m31_add(r828, r829);
    unsigned r831 = stwo_m31_mul(r798, r191);
    unsigned r832 = stwo_m31_add(r797, r831);
    unsigned r833 = stwo_m31_mul(r799, r193);
    unsigned r834 = stwo_m31_add(r832, r833);
    unsigned r835 = stwo_m31_mul(r801, r191);
    unsigned r836 = stwo_m31_add(r800, r835);
    unsigned r837 = stwo_m31_mul(r802, r193);
    unsigned r838 = stwo_m31_add(r836, r837);
    unsigned r839 = stwo_m31_mul(r804, r191);
    unsigned r840 = stwo_m31_add(r803, r839);
    unsigned r841 = stwo_m31_mul(r805, r193);
    unsigned r842 = stwo_m31_add(r840, r841);
    unsigned r843 = stwo_m31_add(r370, r205);
    unsigned r844 = stwo_m31_sub(r843, r810);
    unsigned r845 = stwo_m31_add(r844, r257);
    unsigned r846 = (r845 & 65535u);
    unsigned r847 = (r846 % STWO_M31_P);
    unsigned r848 = stwo_m31_sub(r847, r1);
    unsigned r849 = stwo_m31_add(r370, r205);
    unsigned r850 = stwo_m31_sub(r849, r810);
    unsigned r851 = stwo_m31_sub(r850, r848);
    unsigned r852 = stwo_m31_mul(r851, r16);
    unsigned r853 = stwo_m31_add(r852, r374);
    unsigned r854 = stwo_m31_add(r853, r237);
    unsigned r855 = stwo_m31_sub(r854, r814);
    unsigned r856 = stwo_m31_mul(r855, r16);
    unsigned r857 = stwo_m31_add(r856, r378);
    unsigned r858 = stwo_m31_add(r857, r203);
    unsigned r859 = stwo_m31_sub(r858, r818);
    unsigned r860 = stwo_m31_mul(r859, r16);
    unsigned r861 = stwo_m31_add(r860, r382);
    unsigned r862 = stwo_m31_add(r861, r254);
    unsigned r863 = stwo_m31_sub(r862, r822);
    unsigned r864 = stwo_m31_mul(r863, r16);
    unsigned r865 = stwo_m31_add(r864, r386);
    unsigned r866 = stwo_m31_add(r865, r240);
    unsigned r867 = stwo_m31_sub(r866, r826);
    unsigned r868 = stwo_m31_mul(r867, r16);
    unsigned r869 = stwo_m31_add(r868, r390);
    unsigned r870 = stwo_m31_add(r869, r231);
    unsigned r871 = stwo_m31_sub(r870, r830);
    unsigned r872 = stwo_m31_mul(r871, r16);
    unsigned r873 = stwo_m31_add(r872, r394);
    unsigned r874 = stwo_m31_add(r873, r256);
    unsigned r875 = stwo_m31_sub(r874, r834);
    unsigned r876 = stwo_m31_mul(r875, r16);
    unsigned r877 = stwo_m31_add(r876, r398);
    unsigned r878 = stwo_m31_add(r877, r213);
    unsigned r879 = stwo_m31_sub(r878, r838);
    unsigned r880 = stwo_m31_mul(r848, r67);
    out_cols[111u][row] = r848;
    unsigned r881 = stwo_m31_sub(r879, r880);
    unsigned r882 = stwo_m31_mul(r881, r16);
    unsigned r883 = stwo_m31_add(r882, r402);
    unsigned r884 = stwo_m31_add(r883, r206);
    unsigned r885 = stwo_m31_sub(r884, r842);
    unsigned r886 = stwo_m31_mul(r885, r16);
    unsigned r887 = (r434 & 511u);
    unsigned r888 = (r434 >> 9u);
    unsigned r889 = (r888 & 511u);
    unsigned r890 = (r434 >> 18u);
    unsigned r891 = (r890 & 511u);
    unsigned r892 = (r438 & 511u);
    unsigned r893 = (r438 >> 9u);
    unsigned r894 = (r893 & 511u);
    unsigned r895 = (r438 >> 18u);
    unsigned r896 = (r895 & 511u);
    unsigned r897 = (r442 & 511u);
    unsigned r898 = (r442 >> 9u);
    unsigned r899 = (r898 & 511u);
    unsigned r900 = (r442 >> 18u);
    unsigned r901 = (r900 & 511u);
    unsigned r902 = (r446 & 511u);
    unsigned r903 = (r446 >> 9u);
    unsigned r904 = (r903 & 511u);
    unsigned r905 = (r446 >> 18u);
    unsigned r906 = (r905 & 511u);
    unsigned r907 = (r450 & 511u);
    unsigned r908 = (r450 >> 9u);
    unsigned r909 = (r908 & 511u);
    unsigned r910 = (r450 >> 18u);
    unsigned r911 = (r910 & 511u);
    unsigned r912 = (r454 & 511u);
    unsigned r913 = (r454 >> 9u);
    unsigned r914 = (r913 & 511u);
    unsigned r915 = (r454 >> 18u);
    unsigned r916 = (r915 & 511u);
    unsigned r917 = (r458 & 511u);
    unsigned r918 = (r458 >> 9u);
    unsigned r919 = (r918 & 511u);
    unsigned r920 = (r458 >> 18u);
    unsigned r921 = (r920 & 511u);
    unsigned r922 = (r462 & 511u);
    unsigned r923 = (r462 >> 9u);
    unsigned r924 = (r923 & 511u);
    unsigned r925 = (r462 >> 18u);
    unsigned r926 = (r925 & 511u);
    unsigned r927 = (r466 & 511u);
    unsigned r928 = (r466 >> 9u);
    unsigned r929 = (r928 & 511u);
    unsigned r930 = (r466 >> 18u);
    unsigned r931 = (r930 & 511u);
    unsigned r932 = (r430 & 511u);
    out_cols[89u][row] = r430;
    lookup_words[89u * row_count + row] = r430;
    const unsigned dargs6[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r887, r889, r891, r892, r894, r896, r897, r899, r901, r902, r904, r906, r907, r909, r911, r912, r914, r916, r917, r919, r921, r922, r924, r926, r927, r929, r931, r932 };
    unsigned douts6[28];
    stwo_wit_deduce_felt_mul(dargs6, douts6);
    unsigned r933 = douts6[0];
    unsigned r934 = douts6[1];
    unsigned r935 = douts6[2];
    unsigned r936 = douts6[3];
    unsigned r937 = douts6[4];
    unsigned r938 = douts6[5];
    unsigned r939 = douts6[6];
    unsigned r940 = douts6[7];
    unsigned r941 = douts6[8];
    unsigned r942 = douts6[9];
    unsigned r943 = douts6[10];
    unsigned r944 = douts6[11];
    unsigned r945 = douts6[12];
    unsigned r946 = douts6[13];
    unsigned r947 = douts6[14];
    unsigned r948 = douts6[15];
    unsigned r949 = douts6[16];
    unsigned r950 = douts6[17];
    unsigned r951 = douts6[18];
    unsigned r952 = douts6[19];
    unsigned r953 = douts6[20];
    unsigned r954 = douts6[21];
    unsigned r955 = douts6[22];
    unsigned r956 = douts6[23];
    unsigned r957 = douts6[24];
    unsigned r958 = douts6[25];
    unsigned r959 = douts6[26];
    unsigned r960 = douts6[27];
    const unsigned dargs7[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r933, r934, r935, r936, r937, r938, r939, r940, r941, r942, r943, r944, r945, r946, r947, r948, r949, r950, r951, r952, r953, r954, r955, r956, r957, r958, r959, r960 };
    unsigned douts7[28];
    stwo_wit_deduce_felt_add(dargs7, douts7);
    unsigned r961 = douts7[0];
    unsigned r962 = douts7[1];
    unsigned r963 = douts7[2];
    unsigned r964 = douts7[3];
    unsigned r965 = douts7[4];
    unsigned r966 = douts7[5];
    unsigned r967 = douts7[6];
    unsigned r968 = douts7[7];
    unsigned r969 = douts7[8];
    unsigned r970 = douts7[9];
    unsigned r971 = douts7[10];
    unsigned r972 = douts7[11];
    unsigned r973 = douts7[12];
    unsigned r974 = douts7[13];
    unsigned r975 = douts7[14];
    unsigned r976 = douts7[15];
    unsigned r977 = douts7[16];
    unsigned r978 = douts7[17];
    unsigned r979 = douts7[18];
    unsigned r980 = douts7[19];
    unsigned r981 = douts7[20];
    unsigned r982 = douts7[21];
    unsigned r983 = douts7[22];
    unsigned r984 = douts7[23];
    unsigned r985 = douts7[24];
    unsigned r986 = douts7[25];
    unsigned r987 = douts7[26];
    unsigned r988 = douts7[27];
    const unsigned dargs8[56] = { r961, r962, r963, r964, r965, r966, r967, r968, r969, r970, r971, r972, r973, r974, r975, r976, r977, r978, r979, r980, r981, r982, r983, r984, r985, r986, r987, r988, r117, r133, r18, r109, r181, r57, r182, r96, r129, r173, r117, r86, r92, r143, r128, r155, r148, r119, r37, r107, r62, r66, r119, r139, r130, r82, r105, r60 };
    unsigned douts8[28];
    stwo_wit_deduce_felt_add(dargs8, douts8);
    unsigned r989 = douts8[0];
    unsigned r990 = douts8[1];
    unsigned r991 = douts8[2];
    unsigned r992 = douts8[3];
    unsigned r993 = douts8[4];
    unsigned r994 = douts8[5];
    unsigned r995 = douts8[6];
    unsigned r996 = douts8[7];
    unsigned r997 = douts8[8];
    unsigned r998 = douts8[9];
    unsigned r999 = douts8[10];
    unsigned r1000 = douts8[11];
    unsigned r1001 = douts8[12];
    unsigned r1002 = douts8[13];
    unsigned r1003 = douts8[14];
    unsigned r1004 = douts8[15];
    unsigned r1005 = douts8[16];
    unsigned r1006 = douts8[17];
    unsigned r1007 = douts8[18];
    unsigned r1008 = douts8[19];
    unsigned r1009 = douts8[20];
    unsigned r1010 = douts8[21];
    unsigned r1011 = douts8[22];
    unsigned r1012 = douts8[23];
    unsigned r1013 = douts8[24];
    unsigned r1014 = douts8[25];
    unsigned r1015 = douts8[26];
    unsigned r1016 = douts8[27];
    unsigned r1017 = stwo_m31_mul(r990, r191);
    unsigned r1018 = stwo_m31_add(r989, r1017);
    unsigned r1019 = stwo_m31_mul(r991, r193);
    unsigned r1020 = stwo_m31_add(r1018, r1019);
    unsigned r1021 = stwo_m31_mul(r993, r191);
    unsigned r1022 = stwo_m31_add(r992, r1021);
    unsigned r1023 = stwo_m31_mul(r994, r193);
    unsigned r1024 = stwo_m31_add(r1022, r1023);
    unsigned r1025 = stwo_m31_mul(r996, r191);
    unsigned r1026 = stwo_m31_add(r995, r1025);
    unsigned r1027 = stwo_m31_mul(r997, r193);
    unsigned r1028 = stwo_m31_add(r1026, r1027);
    unsigned r1029 = stwo_m31_mul(r999, r191);
    unsigned r1030 = stwo_m31_add(r998, r1029);
    unsigned r1031 = stwo_m31_mul(r1000, r193);
    unsigned r1032 = stwo_m31_add(r1030, r1031);
    unsigned r1033 = stwo_m31_mul(r1002, r191);
    unsigned r1034 = stwo_m31_add(r1001, r1033);
    unsigned r1035 = stwo_m31_mul(r1003, r193);
    unsigned r1036 = stwo_m31_add(r1034, r1035);
    unsigned r1037 = stwo_m31_mul(r1005, r191);
    unsigned r1038 = stwo_m31_add(r1004, r1037);
    unsigned r1039 = stwo_m31_mul(r1006, r193);
    unsigned r1040 = stwo_m31_add(r1038, r1039);
    unsigned r1041 = stwo_m31_mul(r1008, r191);
    unsigned r1042 = stwo_m31_add(r1007, r1041);
    unsigned r1043 = stwo_m31_mul(r1009, r193);
    unsigned r1044 = stwo_m31_add(r1042, r1043);
    unsigned r1045 = stwo_m31_mul(r1011, r191);
    unsigned r1046 = stwo_m31_add(r1010, r1045);
    unsigned r1047 = stwo_m31_mul(r1012, r193);
    unsigned r1048 = stwo_m31_add(r1046, r1047);
    unsigned r1049 = stwo_m31_mul(r1014, r191);
    unsigned r1050 = stwo_m31_add(r1013, r1049);
    unsigned r1051 = stwo_m31_mul(r1015, r193);
    unsigned r1052 = stwo_m31_add(r1050, r1051);
    unsigned r1053 = stwo_m31_add(r434, r194);
    unsigned r1054 = stwo_m31_sub(r1053, r1020);
    unsigned r1055 = stwo_m31_add(r1054, r257);
    unsigned r1056 = (r1055 & 65535u);
    unsigned r1057 = (r1056 % STWO_M31_P);
    unsigned r1058 = stwo_m31_sub(r1057, r1);
    unsigned r1059 = stwo_m31_add(r434, r194);
    unsigned r1060 = stwo_m31_sub(r1059, r1020);
    unsigned r1061 = stwo_m31_sub(r1060, r1058);
    unsigned r1062 = stwo_m31_mul(r1061, r16);
    unsigned r1063 = stwo_m31_add(r1062, r438);
    unsigned r1064 = stwo_m31_add(r1063, r200);
    unsigned r1065 = stwo_m31_sub(r1064, r1024);
    unsigned r1066 = stwo_m31_mul(r1065, r16);
    unsigned r1067 = stwo_m31_add(r1066, r442);
    unsigned r1068 = stwo_m31_add(r1067, r234);
    unsigned r1069 = stwo_m31_sub(r1068, r1028);
    unsigned r1070 = stwo_m31_mul(r1069, r16);
    unsigned r1071 = stwo_m31_add(r1070, r446);
    unsigned r1072 = stwo_m31_add(r1071, r214);
    unsigned r1073 = stwo_m31_sub(r1072, r1032);
    unsigned r1074 = stwo_m31_mul(r1073, r16);
    unsigned r1075 = stwo_m31_add(r1074, r450);
    unsigned r1076 = stwo_m31_add(r1075, r233);
    unsigned r1077 = stwo_m31_sub(r1076, r1036);
    unsigned r1078 = stwo_m31_mul(r1077, r16);
    unsigned r1079 = stwo_m31_add(r1078, r454);
    unsigned r1080 = stwo_m31_add(r1079, r229);
    unsigned r1081 = stwo_m31_sub(r1080, r1040);
    unsigned r1082 = stwo_m31_mul(r1081, r16);
    unsigned r1083 = stwo_m31_add(r1082, r458);
    unsigned r1084 = stwo_m31_add(r1083, r201);
    unsigned r1085 = stwo_m31_sub(r1084, r1044);
    unsigned r1086 = stwo_m31_mul(r1085, r16);
    unsigned r1087 = stwo_m31_add(r1086, r462);
    unsigned r1088 = stwo_m31_add(r1087, r238);
    unsigned r1089 = stwo_m31_sub(r1088, r1048);
    unsigned r1090 = stwo_m31_mul(r1058, r67);
    out_cols[122u][row] = r1058;
    unsigned r1091 = stwo_m31_sub(r1089, r1090);
    unsigned r1092 = stwo_m31_mul(r1091, r16);
    unsigned r1093 = stwo_m31_add(r1092, r466);
    unsigned r1094 = stwo_m31_add(r1093, r223);
    unsigned r1095 = stwo_m31_sub(r1094, r1052);
    unsigned r1096 = stwo_m31_mul(r1095, r16);
    unsigned r1097 = stwo_m31_mul(r268, r2);
    const unsigned dargs9[32] = { r1097, r0, r600, r604, r608, r612, r616, r620, r624, r628, r632, r596, r810, r814, r818, r822, r826, r830, r834, r838, r842, r806, r1020, r1024, r1028, r1032, r1036, r1040, r1044, r1048, r1052, r1016 };
    unsigned douts9[32];
    out_cols[90u][row] = r600;
    out_cols[91u][row] = r604;
    out_cols[92u][row] = r608;
    out_cols[93u][row] = r612;
    out_cols[94u][row] = r616;
    out_cols[95u][row] = r620;
    out_cols[96u][row] = r624;
    out_cols[97u][row] = r628;
    out_cols[98u][row] = r632;
    out_cols[99u][row] = r596;
    out_cols[101u][row] = r810;
    out_cols[102u][row] = r814;
    out_cols[103u][row] = r818;
    out_cols[104u][row] = r822;
    out_cols[105u][row] = r826;
    out_cols[106u][row] = r830;
    out_cols[107u][row] = r834;
    out_cols[108u][row] = r838;
    out_cols[109u][row] = r842;
    out_cols[110u][row] = r806;
    out_cols[112u][row] = r1020;
    out_cols[113u][row] = r1024;
    out_cols[114u][row] = r1028;
    out_cols[115u][row] = r1032;
    out_cols[116u][row] = r1036;
    out_cols[117u][row] = r1040;
    out_cols[118u][row] = r1044;
    out_cols[119u][row] = r1048;
    out_cols[120u][row] = r1052;
    out_cols[121u][row] = r1016;
    lookup_words[93u * row_count + row] = r600;
    lookup_words[94u * row_count + row] = r604;
    lookup_words[95u * row_count + row] = r608;
    lookup_words[96u * row_count + row] = r612;
    lookup_words[97u * row_count + row] = r616;
    lookup_words[98u * row_count + row] = r620;
    lookup_words[99u * row_count + row] = r624;
    lookup_words[100u * row_count + row] = r628;
    lookup_words[101u * row_count + row] = r632;
    lookup_words[102u * row_count + row] = r596;
    lookup_words[103u * row_count + row] = r810;
    lookup_words[104u * row_count + row] = r814;
    lookup_words[105u * row_count + row] = r818;
    lookup_words[106u * row_count + row] = r822;
    lookup_words[107u * row_count + row] = r826;
    lookup_words[108u * row_count + row] = r830;
    lookup_words[109u * row_count + row] = r834;
    lookup_words[110u * row_count + row] = r838;
    lookup_words[111u * row_count + row] = r842;
    lookup_words[112u * row_count + row] = r806;
    lookup_words[113u * row_count + row] = r1020;
    lookup_words[114u * row_count + row] = r1024;
    lookup_words[115u * row_count + row] = r1028;
    lookup_words[116u * row_count + row] = r1032;
    lookup_words[117u * row_count + row] = r1036;
    lookup_words[118u * row_count + row] = r1040;
    lookup_words[119u * row_count + row] = r1044;
    lookup_words[120u * row_count + row] = r1048;
    lookup_words[121u * row_count + row] = r1052;
    lookup_words[122u * row_count + row] = r1016;
    sub_words[8u * row_count + row] = r600;
    sub_words[9u * row_count + row] = r604;
    sub_words[10u * row_count + row] = r608;
    sub_words[11u * row_count + row] = r612;
    sub_words[12u * row_count + row] = r616;
    sub_words[13u * row_count + row] = r620;
    sub_words[14u * row_count + row] = r624;
    sub_words[15u * row_count + row] = r628;
    sub_words[16u * row_count + row] = r632;
    sub_words[17u * row_count + row] = r596;
    sub_words[18u * row_count + row] = r810;
    sub_words[19u * row_count + row] = r814;
    sub_words[20u * row_count + row] = r818;
    sub_words[21u * row_count + row] = r822;
    sub_words[22u * row_count + row] = r826;
    sub_words[23u * row_count + row] = r830;
    sub_words[24u * row_count + row] = r834;
    sub_words[25u * row_count + row] = r838;
    sub_words[26u * row_count + row] = r842;
    sub_words[27u * row_count + row] = r806;
    sub_words[28u * row_count + row] = r1020;
    sub_words[29u * row_count + row] = r1024;
    sub_words[30u * row_count + row] = r1028;
    sub_words[31u * row_count + row] = r1032;
    sub_words[32u * row_count + row] = r1036;
    sub_words[33u * row_count + row] = r1040;
    sub_words[34u * row_count + row] = r1044;
    sub_words[35u * row_count + row] = r1048;
    sub_words[36u * row_count + row] = r1052;
    sub_words[37u * row_count + row] = r1016;
    stwo_wit_deduce_poseidon_full_round_chain(dargs9, douts9);
    unsigned r1098 = douts9[0];
    unsigned r1099 = douts9[1];
    unsigned r1100 = douts9[2];
    unsigned r1101 = douts9[3];
    unsigned r1102 = douts9[4];
    unsigned r1103 = douts9[5];
    unsigned r1104 = douts9[6];
    unsigned r1105 = douts9[7];
    unsigned r1106 = douts9[8];
    unsigned r1107 = douts9[9];
    unsigned r1108 = douts9[10];
    unsigned r1109 = douts9[11];
    unsigned r1110 = douts9[12];
    unsigned r1111 = douts9[13];
    unsigned r1112 = douts9[14];
    unsigned r1113 = douts9[15];
    unsigned r1114 = douts9[16];
    unsigned r1115 = douts9[17];
    unsigned r1116 = douts9[18];
    unsigned r1117 = douts9[19];
    unsigned r1118 = douts9[20];
    unsigned r1119 = douts9[21];
    unsigned r1120 = douts9[22];
    unsigned r1121 = douts9[23];
    unsigned r1122 = douts9[24];
    unsigned r1123 = douts9[25];
    unsigned r1124 = douts9[26];
    unsigned r1125 = douts9[27];
    unsigned r1126 = douts9[28];
    unsigned r1127 = douts9[29];
    unsigned r1128 = douts9[30];
    unsigned r1129 = douts9[31];
    const unsigned dargs10[32] = { r1097, r1, r1100, r1101, r1102, r1103, r1104, r1105, r1106, r1107, r1108, r1109, r1110, r1111, r1112, r1113, r1114, r1115, r1116, r1117, r1118, r1119, r1120, r1121, r1122, r1123, r1124, r1125, r1126, r1127, r1128, r1129 };
    unsigned douts10[32];
    sub_words[40u * row_count + row] = r1100;
    sub_words[41u * row_count + row] = r1101;
    sub_words[42u * row_count + row] = r1102;
    sub_words[43u * row_count + row] = r1103;
    sub_words[44u * row_count + row] = r1104;
    sub_words[45u * row_count + row] = r1105;
    sub_words[46u * row_count + row] = r1106;
    sub_words[47u * row_count + row] = r1107;
    sub_words[48u * row_count + row] = r1108;
    sub_words[49u * row_count + row] = r1109;
    sub_words[50u * row_count + row] = r1110;
    sub_words[51u * row_count + row] = r1111;
    sub_words[52u * row_count + row] = r1112;
    sub_words[53u * row_count + row] = r1113;
    sub_words[54u * row_count + row] = r1114;
    sub_words[55u * row_count + row] = r1115;
    sub_words[56u * row_count + row] = r1116;
    sub_words[57u * row_count + row] = r1117;
    sub_words[58u * row_count + row] = r1118;
    sub_words[59u * row_count + row] = r1119;
    sub_words[60u * row_count + row] = r1120;
    sub_words[61u * row_count + row] = r1121;
    sub_words[62u * row_count + row] = r1122;
    sub_words[63u * row_count + row] = r1123;
    sub_words[64u * row_count + row] = r1124;
    sub_words[65u * row_count + row] = r1125;
    sub_words[66u * row_count + row] = r1126;
    sub_words[67u * row_count + row] = r1127;
    sub_words[68u * row_count + row] = r1128;
    sub_words[69u * row_count + row] = r1129;
    stwo_wit_deduce_poseidon_full_round_chain(dargs10, douts10);
    unsigned r1130 = douts10[0];
    unsigned r1131 = douts10[1];
    unsigned r1132 = douts10[2];
    unsigned r1133 = douts10[3];
    unsigned r1134 = douts10[4];
    unsigned r1135 = douts10[5];
    unsigned r1136 = douts10[6];
    unsigned r1137 = douts10[7];
    unsigned r1138 = douts10[8];
    unsigned r1139 = douts10[9];
    unsigned r1140 = douts10[10];
    unsigned r1141 = douts10[11];
    unsigned r1142 = douts10[12];
    unsigned r1143 = douts10[13];
    unsigned r1144 = douts10[14];
    unsigned r1145 = douts10[15];
    unsigned r1146 = douts10[16];
    unsigned r1147 = douts10[17];
    unsigned r1148 = douts10[18];
    unsigned r1149 = douts10[19];
    unsigned r1150 = douts10[20];
    unsigned r1151 = douts10[21];
    unsigned r1152 = douts10[22];
    unsigned r1153 = douts10[23];
    unsigned r1154 = douts10[24];
    unsigned r1155 = douts10[25];
    unsigned r1156 = douts10[26];
    unsigned r1157 = douts10[27];
    unsigned r1158 = douts10[28];
    unsigned r1159 = douts10[29];
    unsigned r1160 = douts10[30];
    unsigned r1161 = douts10[31];
    const unsigned dargs11[32] = { r1097, r2, r1132, r1133, r1134, r1135, r1136, r1137, r1138, r1139, r1140, r1141, r1142, r1143, r1144, r1145, r1146, r1147, r1148, r1149, r1150, r1151, r1152, r1153, r1154, r1155, r1156, r1157, r1158, r1159, r1160, r1161 };
    unsigned douts11[32];
    sub_words[72u * row_count + row] = r1132;
    sub_words[73u * row_count + row] = r1133;
    sub_words[74u * row_count + row] = r1134;
    sub_words[75u * row_count + row] = r1135;
    sub_words[76u * row_count + row] = r1136;
    sub_words[77u * row_count + row] = r1137;
    sub_words[78u * row_count + row] = r1138;
    sub_words[79u * row_count + row] = r1139;
    sub_words[80u * row_count + row] = r1140;
    sub_words[81u * row_count + row] = r1141;
    sub_words[82u * row_count + row] = r1142;
    sub_words[83u * row_count + row] = r1143;
    sub_words[84u * row_count + row] = r1144;
    sub_words[85u * row_count + row] = r1145;
    sub_words[86u * row_count + row] = r1146;
    sub_words[87u * row_count + row] = r1147;
    sub_words[88u * row_count + row] = r1148;
    sub_words[89u * row_count + row] = r1149;
    sub_words[90u * row_count + row] = r1150;
    sub_words[91u * row_count + row] = r1151;
    sub_words[92u * row_count + row] = r1152;
    sub_words[93u * row_count + row] = r1153;
    sub_words[94u * row_count + row] = r1154;
    sub_words[95u * row_count + row] = r1155;
    sub_words[96u * row_count + row] = r1156;
    sub_words[97u * row_count + row] = r1157;
    sub_words[98u * row_count + row] = r1158;
    sub_words[99u * row_count + row] = r1159;
    sub_words[100u * row_count + row] = r1160;
    sub_words[101u * row_count + row] = r1161;
    stwo_wit_deduce_poseidon_full_round_chain(dargs11, douts11);
    unsigned r1162 = douts11[0];
    unsigned r1163 = douts11[1];
    unsigned r1164 = douts11[2];
    unsigned r1165 = douts11[3];
    unsigned r1166 = douts11[4];
    unsigned r1167 = douts11[5];
    unsigned r1168 = douts11[6];
    unsigned r1169 = douts11[7];
    unsigned r1170 = douts11[8];
    unsigned r1171 = douts11[9];
    unsigned r1172 = douts11[10];
    unsigned r1173 = douts11[11];
    unsigned r1174 = douts11[12];
    unsigned r1175 = douts11[13];
    unsigned r1176 = douts11[14];
    unsigned r1177 = douts11[15];
    unsigned r1178 = douts11[16];
    unsigned r1179 = douts11[17];
    unsigned r1180 = douts11[18];
    unsigned r1181 = douts11[19];
    unsigned r1182 = douts11[20];
    unsigned r1183 = douts11[21];
    unsigned r1184 = douts11[22];
    unsigned r1185 = douts11[23];
    unsigned r1186 = douts11[24];
    unsigned r1187 = douts11[25];
    unsigned r1188 = douts11[26];
    unsigned r1189 = douts11[27];
    unsigned r1190 = douts11[28];
    unsigned r1191 = douts11[29];
    unsigned r1192 = douts11[30];
    unsigned r1193 = douts11[31];
    const unsigned dargs12[32] = { r1097, r3, r1164, r1165, r1166, r1167, r1168, r1169, r1170, r1171, r1172, r1173, r1174, r1175, r1176, r1177, r1178, r1179, r1180, r1181, r1182, r1183, r1184, r1185, r1186, r1187, r1188, r1189, r1190, r1191, r1192, r1193 };
    unsigned douts12[32];
    sub_words[104u * row_count + row] = r1164;
    sub_words[105u * row_count + row] = r1165;
    sub_words[106u * row_count + row] = r1166;
    sub_words[107u * row_count + row] = r1167;
    sub_words[108u * row_count + row] = r1168;
    sub_words[109u * row_count + row] = r1169;
    sub_words[110u * row_count + row] = r1170;
    sub_words[111u * row_count + row] = r1171;
    sub_words[112u * row_count + row] = r1172;
    sub_words[113u * row_count + row] = r1173;
    sub_words[114u * row_count + row] = r1174;
    sub_words[115u * row_count + row] = r1175;
    sub_words[116u * row_count + row] = r1176;
    sub_words[117u * row_count + row] = r1177;
    sub_words[118u * row_count + row] = r1178;
    sub_words[119u * row_count + row] = r1179;
    sub_words[120u * row_count + row] = r1180;
    sub_words[121u * row_count + row] = r1181;
    sub_words[122u * row_count + row] = r1182;
    sub_words[123u * row_count + row] = r1183;
    sub_words[124u * row_count + row] = r1184;
    sub_words[125u * row_count + row] = r1185;
    sub_words[126u * row_count + row] = r1186;
    sub_words[127u * row_count + row] = r1187;
    sub_words[128u * row_count + row] = r1188;
    sub_words[129u * row_count + row] = r1189;
    sub_words[130u * row_count + row] = r1190;
    sub_words[131u * row_count + row] = r1191;
    sub_words[132u * row_count + row] = r1192;
    sub_words[133u * row_count + row] = r1193;
    stwo_wit_deduce_poseidon_full_round_chain(dargs12, douts12);
    unsigned r1194 = douts12[0];
    unsigned r1195 = douts12[1];
    unsigned r1196 = douts12[2];
    unsigned r1197 = douts12[3];
    unsigned r1198 = douts12[4];
    unsigned r1199 = douts12[5];
    unsigned r1200 = douts12[6];
    unsigned r1201 = douts12[7];
    unsigned r1202 = douts12[8];
    unsigned r1203 = douts12[9];
    unsigned r1204 = douts12[10];
    unsigned r1205 = douts12[11];
    unsigned r1206 = douts12[12];
    unsigned r1207 = douts12[13];
    unsigned r1208 = douts12[14];
    unsigned r1209 = douts12[15];
    unsigned r1210 = douts12[16];
    unsigned r1211 = douts12[17];
    unsigned r1212 = douts12[18];
    unsigned r1213 = douts12[19];
    unsigned r1214 = douts12[20];
    unsigned r1215 = douts12[21];
    unsigned r1216 = douts12[22];
    unsigned r1217 = douts12[23];
    unsigned r1218 = douts12[24];
    unsigned r1219 = douts12[25];
    unsigned r1220 = douts12[26];
    unsigned r1221 = douts12[27];
    unsigned r1222 = douts12[28];
    unsigned r1223 = douts12[29];
    unsigned r1224 = douts12[30];
    unsigned r1225 = douts12[31];
    const unsigned dargs13[10] = { r1216, r1217, r1218, r1219, r1220, r1221, r1222, r1223, r1224, r1225 };
    unsigned douts13[10];
    out_cols[143u][row] = r1216;
    out_cols[144u][row] = r1217;
    out_cols[145u][row] = r1218;
    out_cols[146u][row] = r1219;
    out_cols[147u][row] = r1220;
    out_cols[148u][row] = r1221;
    out_cols[149u][row] = r1222;
    out_cols[150u][row] = r1223;
    out_cols[151u][row] = r1224;
    out_cols[152u][row] = r1225;
    lookup_words[146u * row_count + row] = r1216;
    lookup_words[147u * row_count + row] = r1217;
    lookup_words[148u * row_count + row] = r1218;
    lookup_words[149u * row_count + row] = r1219;
    lookup_words[150u * row_count + row] = r1220;
    lookup_words[151u * row_count + row] = r1221;
    lookup_words[152u * row_count + row] = r1222;
    lookup_words[153u * row_count + row] = r1223;
    lookup_words[154u * row_count + row] = r1224;
    lookup_words[155u * row_count + row] = r1225;
    sub_words[282u * row_count + row] = r1216;
    sub_words[283u * row_count + row] = r1217;
    sub_words[284u * row_count + row] = r1218;
    sub_words[285u * row_count + row] = r1219;
    sub_words[286u * row_count + row] = r1220;
    sub_words[287u * row_count + row] = r1221;
    sub_words[288u * row_count + row] = r1222;
    sub_words[289u * row_count + row] = r1223;
    sub_words[290u * row_count + row] = r1224;
    sub_words[291u * row_count + row] = r1225;
    lookup_words[179u * row_count + row] = r1216;
    lookup_words[180u * row_count + row] = r1217;
    lookup_words[181u * row_count + row] = r1218;
    lookup_words[182u * row_count + row] = r1219;
    lookup_words[183u * row_count + row] = r1220;
    lookup_words[184u * row_count + row] = r1221;
    lookup_words[185u * row_count + row] = r1222;
    lookup_words[186u * row_count + row] = r1223;
    lookup_words[187u * row_count + row] = r1224;
    lookup_words[188u * row_count + row] = r1225;
    stwo_wit_deduce_cube_252(dargs13, douts13);
    unsigned r1226 = douts13[0];
    unsigned r1227 = douts13[1];
    unsigned r1228 = douts13[2];
    unsigned r1229 = douts13[3];
    unsigned r1230 = douts13[4];
    unsigned r1231 = douts13[5];
    unsigned r1232 = douts13[6];
    unsigned r1233 = douts13[7];
    unsigned r1234 = douts13[8];
    unsigned r1235 = douts13[9];
    unsigned r1236 = (r1196 & 511u);
    unsigned r1237 = (r1196 >> 9u);
    unsigned r1238 = (r1237 & 511u);
    unsigned r1239 = (r1196 >> 18u);
    unsigned r1240 = (r1239 & 511u);
    unsigned r1241 = (r1197 & 511u);
    unsigned r1242 = (r1197 >> 9u);
    unsigned r1243 = (r1242 & 511u);
    unsigned r1244 = (r1197 >> 18u);
    unsigned r1245 = (r1244 & 511u);
    unsigned r1246 = (r1198 & 511u);
    unsigned r1247 = (r1198 >> 9u);
    unsigned r1248 = (r1247 & 511u);
    unsigned r1249 = (r1198 >> 18u);
    unsigned r1250 = (r1249 & 511u);
    unsigned r1251 = (r1199 & 511u);
    unsigned r1252 = (r1199 >> 9u);
    unsigned r1253 = (r1252 & 511u);
    unsigned r1254 = (r1199 >> 18u);
    unsigned r1255 = (r1254 & 511u);
    unsigned r1256 = (r1200 & 511u);
    unsigned r1257 = (r1200 >> 9u);
    unsigned r1258 = (r1257 & 511u);
    unsigned r1259 = (r1200 >> 18u);
    unsigned r1260 = (r1259 & 511u);
    unsigned r1261 = (r1201 & 511u);
    unsigned r1262 = (r1201 >> 9u);
    unsigned r1263 = (r1262 & 511u);
    unsigned r1264 = (r1201 >> 18u);
    unsigned r1265 = (r1264 & 511u);
    unsigned r1266 = (r1202 & 511u);
    unsigned r1267 = (r1202 >> 9u);
    unsigned r1268 = (r1267 & 511u);
    unsigned r1269 = (r1202 >> 18u);
    unsigned r1270 = (r1269 & 511u);
    unsigned r1271 = (r1203 & 511u);
    unsigned r1272 = (r1203 >> 9u);
    unsigned r1273 = (r1272 & 511u);
    unsigned r1274 = (r1203 >> 18u);
    unsigned r1275 = (r1274 & 511u);
    unsigned r1276 = (r1204 & 511u);
    unsigned r1277 = (r1204 >> 9u);
    unsigned r1278 = (r1277 & 511u);
    unsigned r1279 = (r1204 >> 18u);
    unsigned r1280 = (r1279 & 511u);
    unsigned r1281 = (r1205 & 511u);
    const unsigned dargs14[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1236, r1238, r1240, r1241, r1243, r1245, r1246, r1248, r1250, r1251, r1253, r1255, r1256, r1258, r1260, r1261, r1263, r1265, r1266, r1268, r1270, r1271, r1273, r1275, r1276, r1278, r1280, r1281 };
    unsigned douts14[28];
    stwo_wit_deduce_felt_mul(dargs14, douts14);
    unsigned r1282 = douts14[0];
    unsigned r1283 = douts14[1];
    unsigned r1284 = douts14[2];
    unsigned r1285 = douts14[3];
    unsigned r1286 = douts14[4];
    unsigned r1287 = douts14[5];
    unsigned r1288 = douts14[6];
    unsigned r1289 = douts14[7];
    unsigned r1290 = douts14[8];
    unsigned r1291 = douts14[9];
    unsigned r1292 = douts14[10];
    unsigned r1293 = douts14[11];
    unsigned r1294 = douts14[12];
    unsigned r1295 = douts14[13];
    unsigned r1296 = douts14[14];
    unsigned r1297 = douts14[15];
    unsigned r1298 = douts14[16];
    unsigned r1299 = douts14[17];
    unsigned r1300 = douts14[18];
    unsigned r1301 = douts14[19];
    unsigned r1302 = douts14[20];
    unsigned r1303 = douts14[21];
    unsigned r1304 = douts14[22];
    unsigned r1305 = douts14[23];
    unsigned r1306 = douts14[24];
    unsigned r1307 = douts14[25];
    unsigned r1308 = douts14[26];
    unsigned r1309 = douts14[27];
    const unsigned dargs15[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1282, r1283, r1284, r1285, r1286, r1287, r1288, r1289, r1290, r1291, r1292, r1293, r1294, r1295, r1296, r1297, r1298, r1299, r1300, r1301, r1302, r1303, r1304, r1305, r1306, r1307, r1308, r1309 };
    unsigned douts15[28];
    stwo_wit_deduce_felt_add(dargs15, douts15);
    unsigned r1310 = douts15[0];
    unsigned r1311 = douts15[1];
    unsigned r1312 = douts15[2];
    unsigned r1313 = douts15[3];
    unsigned r1314 = douts15[4];
    unsigned r1315 = douts15[5];
    unsigned r1316 = douts15[6];
    unsigned r1317 = douts15[7];
    unsigned r1318 = douts15[8];
    unsigned r1319 = douts15[9];
    unsigned r1320 = douts15[10];
    unsigned r1321 = douts15[11];
    unsigned r1322 = douts15[12];
    unsigned r1323 = douts15[13];
    unsigned r1324 = douts15[14];
    unsigned r1325 = douts15[15];
    unsigned r1326 = douts15[16];
    unsigned r1327 = douts15[17];
    unsigned r1328 = douts15[18];
    unsigned r1329 = douts15[19];
    unsigned r1330 = douts15[20];
    unsigned r1331 = douts15[21];
    unsigned r1332 = douts15[22];
    unsigned r1333 = douts15[23];
    unsigned r1334 = douts15[24];
    unsigned r1335 = douts15[25];
    unsigned r1336 = douts15[26];
    unsigned r1337 = douts15[27];
    unsigned r1338 = (r1206 & 511u);
    unsigned r1339 = (r1206 >> 9u);
    unsigned r1340 = (r1339 & 511u);
    unsigned r1341 = (r1206 >> 18u);
    unsigned r1342 = (r1341 & 511u);
    unsigned r1343 = (r1207 & 511u);
    unsigned r1344 = (r1207 >> 9u);
    unsigned r1345 = (r1344 & 511u);
    unsigned r1346 = (r1207 >> 18u);
    unsigned r1347 = (r1346 & 511u);
    unsigned r1348 = (r1208 & 511u);
    unsigned r1349 = (r1208 >> 9u);
    unsigned r1350 = (r1349 & 511u);
    unsigned r1351 = (r1208 >> 18u);
    unsigned r1352 = (r1351 & 511u);
    unsigned r1353 = (r1209 & 511u);
    unsigned r1354 = (r1209 >> 9u);
    unsigned r1355 = (r1354 & 511u);
    unsigned r1356 = (r1209 >> 18u);
    unsigned r1357 = (r1356 & 511u);
    unsigned r1358 = (r1210 & 511u);
    unsigned r1359 = (r1210 >> 9u);
    unsigned r1360 = (r1359 & 511u);
    unsigned r1361 = (r1210 >> 18u);
    unsigned r1362 = (r1361 & 511u);
    unsigned r1363 = (r1211 & 511u);
    unsigned r1364 = (r1211 >> 9u);
    unsigned r1365 = (r1364 & 511u);
    unsigned r1366 = (r1211 >> 18u);
    unsigned r1367 = (r1366 & 511u);
    unsigned r1368 = (r1212 & 511u);
    unsigned r1369 = (r1212 >> 9u);
    unsigned r1370 = (r1369 & 511u);
    unsigned r1371 = (r1212 >> 18u);
    unsigned r1372 = (r1371 & 511u);
    unsigned r1373 = (r1213 & 511u);
    unsigned r1374 = (r1213 >> 9u);
    unsigned r1375 = (r1374 & 511u);
    unsigned r1376 = (r1213 >> 18u);
    unsigned r1377 = (r1376 & 511u);
    unsigned r1378 = (r1214 & 511u);
    unsigned r1379 = (r1214 >> 9u);
    unsigned r1380 = (r1379 & 511u);
    unsigned r1381 = (r1214 >> 18u);
    unsigned r1382 = (r1381 & 511u);
    unsigned r1383 = (r1215 & 511u);
    out_cols[142u][row] = r1215;
    lookup_words[145u * row_count + row] = r1215;
    sub_words[281u * row_count + row] = r1215;
    lookup_words[177u * row_count + row] = r1215;
    const unsigned dargs16[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1338, r1340, r1342, r1343, r1345, r1347, r1348, r1350, r1352, r1353, r1355, r1357, r1358, r1360, r1362, r1363, r1365, r1367, r1368, r1370, r1372, r1373, r1375, r1377, r1378, r1380, r1382, r1383 };
    unsigned douts16[28];
    stwo_wit_deduce_felt_mul(dargs16, douts16);
    unsigned r1384 = douts16[0];
    unsigned r1385 = douts16[1];
    unsigned r1386 = douts16[2];
    unsigned r1387 = douts16[3];
    unsigned r1388 = douts16[4];
    unsigned r1389 = douts16[5];
    unsigned r1390 = douts16[6];
    unsigned r1391 = douts16[7];
    unsigned r1392 = douts16[8];
    unsigned r1393 = douts16[9];
    unsigned r1394 = douts16[10];
    unsigned r1395 = douts16[11];
    unsigned r1396 = douts16[12];
    unsigned r1397 = douts16[13];
    unsigned r1398 = douts16[14];
    unsigned r1399 = douts16[15];
    unsigned r1400 = douts16[16];
    unsigned r1401 = douts16[17];
    unsigned r1402 = douts16[18];
    unsigned r1403 = douts16[19];
    unsigned r1404 = douts16[20];
    unsigned r1405 = douts16[21];
    unsigned r1406 = douts16[22];
    unsigned r1407 = douts16[23];
    unsigned r1408 = douts16[24];
    unsigned r1409 = douts16[25];
    unsigned r1410 = douts16[26];
    unsigned r1411 = douts16[27];
    const unsigned dargs17[56] = { r1310, r1311, r1312, r1313, r1314, r1315, r1316, r1317, r1318, r1319, r1320, r1321, r1322, r1323, r1324, r1325, r1326, r1327, r1328, r1329, r1330, r1331, r1332, r1333, r1334, r1335, r1336, r1337, r1384, r1385, r1386, r1387, r1388, r1389, r1390, r1391, r1392, r1393, r1394, r1395, r1396, r1397, r1398, r1399, r1400, r1401, r1402, r1403, r1404, r1405, r1406, r1407, r1408, r1409, r1410, r1411 };
    unsigned douts17[28];
    stwo_wit_deduce_felt_add(dargs17, douts17);
    unsigned r1412 = douts17[0];
    unsigned r1413 = douts17[1];
    unsigned r1414 = douts17[2];
    unsigned r1415 = douts17[3];
    unsigned r1416 = douts17[4];
    unsigned r1417 = douts17[5];
    unsigned r1418 = douts17[6];
    unsigned r1419 = douts17[7];
    unsigned r1420 = douts17[8];
    unsigned r1421 = douts17[9];
    unsigned r1422 = douts17[10];
    unsigned r1423 = douts17[11];
    unsigned r1424 = douts17[12];
    unsigned r1425 = douts17[13];
    unsigned r1426 = douts17[14];
    unsigned r1427 = douts17[15];
    unsigned r1428 = douts17[16];
    unsigned r1429 = douts17[17];
    unsigned r1430 = douts17[18];
    unsigned r1431 = douts17[19];
    unsigned r1432 = douts17[20];
    unsigned r1433 = douts17[21];
    unsigned r1434 = douts17[22];
    unsigned r1435 = douts17[23];
    unsigned r1436 = douts17[24];
    unsigned r1437 = douts17[25];
    unsigned r1438 = douts17[26];
    unsigned r1439 = douts17[27];
    unsigned r1440 = (r1226 & 511u);
    unsigned r1441 = (r1226 >> 9u);
    unsigned r1442 = (r1441 & 511u);
    unsigned r1443 = (r1226 >> 18u);
    unsigned r1444 = (r1443 & 511u);
    unsigned r1445 = (r1227 & 511u);
    unsigned r1446 = (r1227 >> 9u);
    unsigned r1447 = (r1446 & 511u);
    unsigned r1448 = (r1227 >> 18u);
    unsigned r1449 = (r1448 & 511u);
    unsigned r1450 = (r1228 & 511u);
    unsigned r1451 = (r1228 >> 9u);
    unsigned r1452 = (r1451 & 511u);
    unsigned r1453 = (r1228 >> 18u);
    unsigned r1454 = (r1453 & 511u);
    unsigned r1455 = (r1229 & 511u);
    unsigned r1456 = (r1229 >> 9u);
    unsigned r1457 = (r1456 & 511u);
    unsigned r1458 = (r1229 >> 18u);
    unsigned r1459 = (r1458 & 511u);
    unsigned r1460 = (r1230 & 511u);
    unsigned r1461 = (r1230 >> 9u);
    unsigned r1462 = (r1461 & 511u);
    unsigned r1463 = (r1230 >> 18u);
    unsigned r1464 = (r1463 & 511u);
    unsigned r1465 = (r1231 & 511u);
    unsigned r1466 = (r1231 >> 9u);
    unsigned r1467 = (r1466 & 511u);
    unsigned r1468 = (r1231 >> 18u);
    unsigned r1469 = (r1468 & 511u);
    unsigned r1470 = (r1232 & 511u);
    unsigned r1471 = (r1232 >> 9u);
    unsigned r1472 = (r1471 & 511u);
    unsigned r1473 = (r1232 >> 18u);
    unsigned r1474 = (r1473 & 511u);
    unsigned r1475 = (r1233 & 511u);
    unsigned r1476 = (r1233 >> 9u);
    unsigned r1477 = (r1476 & 511u);
    unsigned r1478 = (r1233 >> 18u);
    unsigned r1479 = (r1478 & 511u);
    unsigned r1480 = (r1234 & 511u);
    unsigned r1481 = (r1234 >> 9u);
    unsigned r1482 = (r1481 & 511u);
    unsigned r1483 = (r1234 >> 18u);
    unsigned r1484 = (r1483 & 511u);
    unsigned r1485 = (r1235 & 511u);
    const unsigned dargs18[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1440, r1442, r1444, r1445, r1447, r1449, r1450, r1452, r1454, r1455, r1457, r1459, r1460, r1462, r1464, r1465, r1467, r1469, r1470, r1472, r1474, r1475, r1477, r1479, r1480, r1482, r1484, r1485 };
    unsigned douts18[28];
    stwo_wit_deduce_felt_mul(dargs18, douts18);
    unsigned r1486 = douts18[0];
    unsigned r1487 = douts18[1];
    unsigned r1488 = douts18[2];
    unsigned r1489 = douts18[3];
    unsigned r1490 = douts18[4];
    unsigned r1491 = douts18[5];
    unsigned r1492 = douts18[6];
    unsigned r1493 = douts18[7];
    unsigned r1494 = douts18[8];
    unsigned r1495 = douts18[9];
    unsigned r1496 = douts18[10];
    unsigned r1497 = douts18[11];
    unsigned r1498 = douts18[12];
    unsigned r1499 = douts18[13];
    unsigned r1500 = douts18[14];
    unsigned r1501 = douts18[15];
    unsigned r1502 = douts18[16];
    unsigned r1503 = douts18[17];
    unsigned r1504 = douts18[18];
    unsigned r1505 = douts18[19];
    unsigned r1506 = douts18[20];
    unsigned r1507 = douts18[21];
    unsigned r1508 = douts18[22];
    unsigned r1509 = douts18[23];
    unsigned r1510 = douts18[24];
    unsigned r1511 = douts18[25];
    unsigned r1512 = douts18[26];
    unsigned r1513 = douts18[27];
    const unsigned dargs19[56] = { r1412, r1413, r1414, r1415, r1416, r1417, r1418, r1419, r1420, r1421, r1422, r1423, r1424, r1425, r1426, r1427, r1428, r1429, r1430, r1431, r1432, r1433, r1434, r1435, r1436, r1437, r1438, r1439, r1486, r1487, r1488, r1489, r1490, r1491, r1492, r1493, r1494, r1495, r1496, r1497, r1498, r1499, r1500, r1501, r1502, r1503, r1504, r1505, r1506, r1507, r1508, r1509, r1510, r1511, r1512, r1513 };
    unsigned douts19[28];
    stwo_wit_deduce_felt_sub(dargs19, douts19);
    unsigned r1514 = douts19[0];
    unsigned r1515 = douts19[1];
    unsigned r1516 = douts19[2];
    unsigned r1517 = douts19[3];
    unsigned r1518 = douts19[4];
    unsigned r1519 = douts19[5];
    unsigned r1520 = douts19[6];
    unsigned r1521 = douts19[7];
    unsigned r1522 = douts19[8];
    unsigned r1523 = douts19[9];
    unsigned r1524 = douts19[10];
    unsigned r1525 = douts19[11];
    unsigned r1526 = douts19[12];
    unsigned r1527 = douts19[13];
    unsigned r1528 = douts19[14];
    unsigned r1529 = douts19[15];
    unsigned r1530 = douts19[16];
    unsigned r1531 = douts19[17];
    unsigned r1532 = douts19[18];
    unsigned r1533 = douts19[19];
    unsigned r1534 = douts19[20];
    unsigned r1535 = douts19[21];
    unsigned r1536 = douts19[22];
    unsigned r1537 = douts19[23];
    unsigned r1538 = douts19[24];
    unsigned r1539 = douts19[25];
    unsigned r1540 = douts19[26];
    unsigned r1541 = douts19[27];
    const unsigned dargs20[56] = { r1514, r1515, r1516, r1517, r1518, r1519, r1520, r1521, r1522, r1523, r1524, r1525, r1526, r1527, r1528, r1529, r1530, r1531, r1532, r1533, r1534, r1535, r1536, r1537, r1538, r1539, r1540, r1541, r187, r69, r152, r150, r45, r174, r56, r129, r145, r163, r143, r42, r11, r133, r90, r135, r127, r95, r160, r130, r47, r142, r0, r80, r77, r72, r177, r111 };
    unsigned douts20[28];
    stwo_wit_deduce_felt_add(dargs20, douts20);
    unsigned r1542 = douts20[0];
    unsigned r1543 = douts20[1];
    unsigned r1544 = douts20[2];
    unsigned r1545 = douts20[3];
    unsigned r1546 = douts20[4];
    unsigned r1547 = douts20[5];
    unsigned r1548 = douts20[6];
    unsigned r1549 = douts20[7];
    unsigned r1550 = douts20[8];
    unsigned r1551 = douts20[9];
    unsigned r1552 = douts20[10];
    unsigned r1553 = douts20[11];
    unsigned r1554 = douts20[12];
    unsigned r1555 = douts20[13];
    unsigned r1556 = douts20[14];
    unsigned r1557 = douts20[15];
    unsigned r1558 = douts20[16];
    unsigned r1559 = douts20[17];
    unsigned r1560 = douts20[18];
    unsigned r1561 = douts20[19];
    unsigned r1562 = douts20[20];
    unsigned r1563 = douts20[21];
    unsigned r1564 = douts20[22];
    unsigned r1565 = douts20[23];
    unsigned r1566 = douts20[24];
    unsigned r1567 = douts20[25];
    unsigned r1568 = douts20[26];
    unsigned r1569 = douts20[27];
    unsigned r1570 = stwo_m31_mul(r1543, r191);
    unsigned r1571 = stwo_m31_add(r1542, r1570);
    unsigned r1572 = stwo_m31_mul(r1544, r193);
    unsigned r1573 = stwo_m31_add(r1571, r1572);
    unsigned r1574 = stwo_m31_mul(r1546, r191);
    unsigned r1575 = stwo_m31_add(r1545, r1574);
    unsigned r1576 = stwo_m31_mul(r1547, r193);
    unsigned r1577 = stwo_m31_add(r1575, r1576);
    unsigned r1578 = stwo_m31_mul(r1549, r191);
    unsigned r1579 = stwo_m31_add(r1548, r1578);
    unsigned r1580 = stwo_m31_mul(r1550, r193);
    unsigned r1581 = stwo_m31_add(r1579, r1580);
    unsigned r1582 = stwo_m31_mul(r1552, r191);
    unsigned r1583 = stwo_m31_add(r1551, r1582);
    unsigned r1584 = stwo_m31_mul(r1553, r193);
    unsigned r1585 = stwo_m31_add(r1583, r1584);
    unsigned r1586 = stwo_m31_mul(r1555, r191);
    unsigned r1587 = stwo_m31_add(r1554, r1586);
    unsigned r1588 = stwo_m31_mul(r1556, r193);
    unsigned r1589 = stwo_m31_add(r1587, r1588);
    unsigned r1590 = stwo_m31_mul(r1558, r191);
    unsigned r1591 = stwo_m31_add(r1557, r1590);
    unsigned r1592 = stwo_m31_mul(r1559, r193);
    unsigned r1593 = stwo_m31_add(r1591, r1592);
    unsigned r1594 = stwo_m31_mul(r1561, r191);
    unsigned r1595 = stwo_m31_add(r1560, r1594);
    unsigned r1596 = stwo_m31_mul(r1562, r193);
    unsigned r1597 = stwo_m31_add(r1595, r1596);
    unsigned r1598 = stwo_m31_mul(r1564, r191);
    unsigned r1599 = stwo_m31_add(r1563, r1598);
    unsigned r1600 = stwo_m31_mul(r1565, r193);
    unsigned r1601 = stwo_m31_add(r1599, r1600);
    unsigned r1602 = stwo_m31_mul(r1567, r191);
    unsigned r1603 = stwo_m31_add(r1566, r1602);
    unsigned r1604 = stwo_m31_mul(r1568, r193);
    unsigned r1605 = stwo_m31_add(r1603, r1604);
    unsigned r1606 = stwo_m31_add(r1196, r1206);
    unsigned r1607 = stwo_m31_mul(r2, r1226);
    unsigned r1608 = stwo_m31_sub(r1606, r1607);
    unsigned r1609 = stwo_m31_add(r1608, r243);
    unsigned r1610 = stwo_m31_sub(r1609, r1573);
    unsigned r1611 = stwo_m31_add(r1610, r258);
    unsigned r1612 = (r1611 & 65535u);
    unsigned r1613 = (r1612 % STWO_M31_P);
    unsigned r1614 = stwo_m31_sub(r1613, r3);
    unsigned r1615 = stwo_m31_add(r1196, r1206);
    out_cols[133u][row] = r1206;
    lookup_words[136u * row_count + row] = r1206;
    sub_words[272u * row_count + row] = r1206;
    lookup_words[168u * row_count + row] = r1206;
    unsigned r1616 = stwo_m31_mul(r2, r1226);
    unsigned r1617 = stwo_m31_sub(r1615, r1616);
    unsigned r1618 = stwo_m31_add(r1617, r243);
    unsigned r1619 = stwo_m31_sub(r1618, r1573);
    unsigned r1620 = stwo_m31_sub(r1619, r1614);
    unsigned r1621 = stwo_m31_mul(r1620, r16);
    unsigned r1622 = stwo_m31_add(r1621, r1197);
    unsigned r1623 = stwo_m31_add(r1622, r1207);
    out_cols[134u][row] = r1207;
    lookup_words[137u * row_count + row] = r1207;
    sub_words[273u * row_count + row] = r1207;
    lookup_words[169u * row_count + row] = r1207;
    unsigned r1624 = stwo_m31_mul(r2, r1227);
    unsigned r1625 = stwo_m31_sub(r1623, r1624);
    unsigned r1626 = stwo_m31_add(r1625, r251);
    unsigned r1627 = stwo_m31_sub(r1626, r1577);
    unsigned r1628 = stwo_m31_mul(r1627, r16);
    unsigned r1629 = stwo_m31_add(r1628, r1198);
    unsigned r1630 = stwo_m31_add(r1629, r1208);
    out_cols[135u][row] = r1208;
    lookup_words[138u * row_count + row] = r1208;
    sub_words[274u * row_count + row] = r1208;
    lookup_words[170u * row_count + row] = r1208;
    unsigned r1631 = stwo_m31_mul(r2, r1228);
    unsigned r1632 = stwo_m31_sub(r1630, r1631);
    unsigned r1633 = stwo_m31_add(r1632, r241);
    unsigned r1634 = stwo_m31_sub(r1633, r1581);
    unsigned r1635 = stwo_m31_mul(r1634, r16);
    unsigned r1636 = stwo_m31_add(r1635, r1199);
    unsigned r1637 = stwo_m31_add(r1636, r1209);
    out_cols[136u][row] = r1209;
    lookup_words[139u * row_count + row] = r1209;
    sub_words[275u * row_count + row] = r1209;
    lookup_words[171u * row_count + row] = r1209;
    unsigned r1638 = stwo_m31_mul(r2, r1229);
    unsigned r1639 = stwo_m31_sub(r1637, r1638);
    unsigned r1640 = stwo_m31_add(r1639, r196);
    unsigned r1641 = stwo_m31_sub(r1640, r1585);
    unsigned r1642 = stwo_m31_mul(r1641, r16);
    unsigned r1643 = stwo_m31_add(r1642, r1200);
    unsigned r1644 = stwo_m31_add(r1643, r1210);
    out_cols[137u][row] = r1210;
    lookup_words[140u * row_count + row] = r1210;
    sub_words[276u * row_count + row] = r1210;
    lookup_words[172u * row_count + row] = r1210;
    unsigned r1645 = stwo_m31_mul(r2, r1230);
    unsigned r1646 = stwo_m31_sub(r1644, r1645);
    unsigned r1647 = stwo_m31_add(r1646, r217);
    unsigned r1648 = stwo_m31_sub(r1647, r1589);
    unsigned r1649 = stwo_m31_mul(r1648, r16);
    unsigned r1650 = stwo_m31_add(r1649, r1201);
    unsigned r1651 = stwo_m31_add(r1650, r1211);
    out_cols[138u][row] = r1211;
    lookup_words[141u * row_count + row] = r1211;
    sub_words[277u * row_count + row] = r1211;
    lookup_words[173u * row_count + row] = r1211;
    unsigned r1652 = stwo_m31_mul(r2, r1231);
    unsigned r1653 = stwo_m31_sub(r1651, r1652);
    unsigned r1654 = stwo_m31_add(r1653, r218);
    unsigned r1655 = stwo_m31_sub(r1654, r1593);
    unsigned r1656 = stwo_m31_mul(r1655, r16);
    unsigned r1657 = stwo_m31_add(r1656, r1202);
    unsigned r1658 = stwo_m31_add(r1657, r1212);
    out_cols[139u][row] = r1212;
    lookup_words[142u * row_count + row] = r1212;
    sub_words[278u * row_count + row] = r1212;
    lookup_words[174u * row_count + row] = r1212;
    unsigned r1659 = stwo_m31_mul(r2, r1232);
    unsigned r1660 = stwo_m31_sub(r1658, r1659);
    unsigned r1661 = stwo_m31_add(r1660, r198);
    unsigned r1662 = stwo_m31_sub(r1661, r1597);
    unsigned r1663 = stwo_m31_mul(r1662, r16);
    unsigned r1664 = stwo_m31_add(r1663, r1203);
    unsigned r1665 = stwo_m31_add(r1664, r1213);
    out_cols[140u][row] = r1213;
    lookup_words[143u * row_count + row] = r1213;
    sub_words[279u * row_count + row] = r1213;
    lookup_words[175u * row_count + row] = r1213;
    unsigned r1666 = stwo_m31_mul(r2, r1233);
    unsigned r1667 = stwo_m31_sub(r1665, r1666);
    unsigned r1668 = stwo_m31_add(r1667, r209);
    unsigned r1669 = stwo_m31_sub(r1668, r1601);
    unsigned r1670 = stwo_m31_mul(r1614, r67);
    unsigned r1671 = stwo_m31_sub(r1669, r1670);
    unsigned r1672 = stwo_m31_mul(r1671, r16);
    unsigned r1673 = stwo_m31_add(r1672, r1204);
    unsigned r1674 = stwo_m31_add(r1673, r1214);
    out_cols[141u][row] = r1214;
    lookup_words[144u * row_count + row] = r1214;
    sub_words[280u * row_count + row] = r1214;
    lookup_words[176u * row_count + row] = r1214;
    unsigned r1675 = stwo_m31_mul(r2, r1234);
    unsigned r1676 = stwo_m31_sub(r1674, r1675);
    unsigned r1677 = stwo_m31_add(r1676, r253);
    unsigned r1678 = stwo_m31_sub(r1677, r1605);
    unsigned r1679 = stwo_m31_mul(r1678, r16);
    unsigned r1680 = stwo_m31_add(r1614, r3);
    sub_words[302u * row_count + row] = r1680;
    unsigned r1681 = stwo_m31_add(r1621, r3);
    sub_words[303u * row_count + row] = r1681;
    unsigned r1682 = stwo_m31_add(r1628, r3);
    sub_words[304u * row_count + row] = r1682;
    unsigned r1683 = stwo_m31_add(r1635, r3);
    sub_words[305u * row_count + row] = r1683;
    unsigned r1684 = stwo_m31_add(r1642, r3);
    sub_words[306u * row_count + row] = r1684;
    unsigned r1685 = stwo_m31_add(r1614, r3);
    out_cols[173u][row] = r1614;
    lookup_words[200u * row_count + row] = r1685;
    unsigned r1686 = stwo_m31_add(r1621, r3);
    lookup_words[201u * row_count + row] = r1686;
    unsigned r1687 = stwo_m31_add(r1628, r3);
    lookup_words[202u * row_count + row] = r1687;
    unsigned r1688 = stwo_m31_add(r1635, r3);
    lookup_words[203u * row_count + row] = r1688;
    unsigned r1689 = stwo_m31_add(r1642, r3);
    lookup_words[204u * row_count + row] = r1689;
    unsigned r1690 = stwo_m31_add(r1649, r3);
    sub_words[307u * row_count + row] = r1690;
    unsigned r1691 = stwo_m31_add(r1656, r3);
    sub_words[308u * row_count + row] = r1691;
    unsigned r1692 = stwo_m31_add(r1663, r3);
    sub_words[309u * row_count + row] = r1692;
    unsigned r1693 = stwo_m31_add(r1672, r3);
    sub_words[310u * row_count + row] = r1693;
    unsigned r1694 = stwo_m31_add(r1679, r3);
    sub_words[311u * row_count + row] = r1694;
    unsigned r1695 = stwo_m31_add(r1649, r3);
    lookup_words[206u * row_count + row] = r1695;
    unsigned r1696 = stwo_m31_add(r1656, r3);
    lookup_words[207u * row_count + row] = r1696;
    unsigned r1697 = stwo_m31_add(r1663, r3);
    lookup_words[208u * row_count + row] = r1697;
    unsigned r1698 = stwo_m31_add(r1672, r3);
    lookup_words[209u * row_count + row] = r1698;
    unsigned r1699 = stwo_m31_add(r1679, r3);
    lookup_words[210u * row_count + row] = r1699;
    const unsigned dargs21[10] = { r1573, r1577, r1581, r1585, r1589, r1593, r1597, r1601, r1605, r1569 };
    unsigned douts21[10];
    stwo_wit_deduce_cube_252(dargs21, douts21);
    unsigned r1700 = douts21[0];
    unsigned r1701 = douts21[1];
    unsigned r1702 = douts21[2];
    unsigned r1703 = douts21[3];
    unsigned r1704 = douts21[4];
    unsigned r1705 = douts21[5];
    unsigned r1706 = douts21[6];
    unsigned r1707 = douts21[7];
    unsigned r1708 = douts21[8];
    unsigned r1709 = douts21[9];
    unsigned r1710 = (r1196 & 511u);
    unsigned r1711 = (r1196 >> 9u);
    unsigned r1712 = (r1711 & 511u);
    unsigned r1713 = (r1196 >> 18u);
    unsigned r1714 = (r1713 & 511u);
    unsigned r1715 = (r1197 & 511u);
    unsigned r1716 = (r1197 >> 9u);
    unsigned r1717 = (r1716 & 511u);
    unsigned r1718 = (r1197 >> 18u);
    unsigned r1719 = (r1718 & 511u);
    unsigned r1720 = (r1198 & 511u);
    unsigned r1721 = (r1198 >> 9u);
    unsigned r1722 = (r1721 & 511u);
    unsigned r1723 = (r1198 >> 18u);
    unsigned r1724 = (r1723 & 511u);
    unsigned r1725 = (r1199 & 511u);
    unsigned r1726 = (r1199 >> 9u);
    unsigned r1727 = (r1726 & 511u);
    unsigned r1728 = (r1199 >> 18u);
    unsigned r1729 = (r1728 & 511u);
    unsigned r1730 = (r1200 & 511u);
    unsigned r1731 = (r1200 >> 9u);
    unsigned r1732 = (r1731 & 511u);
    unsigned r1733 = (r1200 >> 18u);
    unsigned r1734 = (r1733 & 511u);
    unsigned r1735 = (r1201 & 511u);
    unsigned r1736 = (r1201 >> 9u);
    unsigned r1737 = (r1736 & 511u);
    unsigned r1738 = (r1201 >> 18u);
    unsigned r1739 = (r1738 & 511u);
    unsigned r1740 = (r1202 & 511u);
    unsigned r1741 = (r1202 >> 9u);
    unsigned r1742 = (r1741 & 511u);
    unsigned r1743 = (r1202 >> 18u);
    unsigned r1744 = (r1743 & 511u);
    unsigned r1745 = (r1203 & 511u);
    unsigned r1746 = (r1203 >> 9u);
    unsigned r1747 = (r1746 & 511u);
    unsigned r1748 = (r1203 >> 18u);
    unsigned r1749 = (r1748 & 511u);
    unsigned r1750 = (r1204 & 511u);
    unsigned r1751 = (r1204 >> 9u);
    unsigned r1752 = (r1751 & 511u);
    unsigned r1753 = (r1204 >> 18u);
    unsigned r1754 = (r1753 & 511u);
    unsigned r1755 = (r1205 & 511u);
    out_cols[132u][row] = r1205;
    lookup_words[135u * row_count + row] = r1205;
    sub_words[271u * row_count + row] = r1205;
    lookup_words[166u * row_count + row] = r1205;
    const unsigned dargs22[56] = { r4, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1710, r1712, r1714, r1715, r1717, r1719, r1720, r1722, r1724, r1725, r1727, r1729, r1730, r1732, r1734, r1735, r1737, r1739, r1740, r1742, r1744, r1745, r1747, r1749, r1750, r1752, r1754, r1755 };
    unsigned douts22[28];
    stwo_wit_deduce_felt_mul(dargs22, douts22);
    unsigned r1756 = douts22[0];
    unsigned r1757 = douts22[1];
    unsigned r1758 = douts22[2];
    unsigned r1759 = douts22[3];
    unsigned r1760 = douts22[4];
    unsigned r1761 = douts22[5];
    unsigned r1762 = douts22[6];
    unsigned r1763 = douts22[7];
    unsigned r1764 = douts22[8];
    unsigned r1765 = douts22[9];
    unsigned r1766 = douts22[10];
    unsigned r1767 = douts22[11];
    unsigned r1768 = douts22[12];
    unsigned r1769 = douts22[13];
    unsigned r1770 = douts22[14];
    unsigned r1771 = douts22[15];
    unsigned r1772 = douts22[16];
    unsigned r1773 = douts22[17];
    unsigned r1774 = douts22[18];
    unsigned r1775 = douts22[19];
    unsigned r1776 = douts22[20];
    unsigned r1777 = douts22[21];
    unsigned r1778 = douts22[22];
    unsigned r1779 = douts22[23];
    unsigned r1780 = douts22[24];
    unsigned r1781 = douts22[25];
    unsigned r1782 = douts22[26];
    unsigned r1783 = douts22[27];
    const unsigned dargs23[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1756, r1757, r1758, r1759, r1760, r1761, r1762, r1763, r1764, r1765, r1766, r1767, r1768, r1769, r1770, r1771, r1772, r1773, r1774, r1775, r1776, r1777, r1778, r1779, r1780, r1781, r1782, r1783 };
    unsigned douts23[28];
    stwo_wit_deduce_felt_add(dargs23, douts23);
    unsigned r1784 = douts23[0];
    unsigned r1785 = douts23[1];
    unsigned r1786 = douts23[2];
    unsigned r1787 = douts23[3];
    unsigned r1788 = douts23[4];
    unsigned r1789 = douts23[5];
    unsigned r1790 = douts23[6];
    unsigned r1791 = douts23[7];
    unsigned r1792 = douts23[8];
    unsigned r1793 = douts23[9];
    unsigned r1794 = douts23[10];
    unsigned r1795 = douts23[11];
    unsigned r1796 = douts23[12];
    unsigned r1797 = douts23[13];
    unsigned r1798 = douts23[14];
    unsigned r1799 = douts23[15];
    unsigned r1800 = douts23[16];
    unsigned r1801 = douts23[17];
    unsigned r1802 = douts23[18];
    unsigned r1803 = douts23[19];
    unsigned r1804 = douts23[20];
    unsigned r1805 = douts23[21];
    unsigned r1806 = douts23[22];
    unsigned r1807 = douts23[23];
    unsigned r1808 = douts23[24];
    unsigned r1809 = douts23[25];
    unsigned r1810 = douts23[26];
    unsigned r1811 = douts23[27];
    unsigned r1812 = (r1226 & 511u);
    unsigned r1813 = (r1226 >> 9u);
    unsigned r1814 = (r1813 & 511u);
    unsigned r1815 = (r1226 >> 18u);
    unsigned r1816 = (r1815 & 511u);
    unsigned r1817 = (r1227 & 511u);
    unsigned r1818 = (r1227 >> 9u);
    unsigned r1819 = (r1818 & 511u);
    unsigned r1820 = (r1227 >> 18u);
    unsigned r1821 = (r1820 & 511u);
    unsigned r1822 = (r1228 & 511u);
    unsigned r1823 = (r1228 >> 9u);
    unsigned r1824 = (r1823 & 511u);
    unsigned r1825 = (r1228 >> 18u);
    unsigned r1826 = (r1825 & 511u);
    unsigned r1827 = (r1229 & 511u);
    unsigned r1828 = (r1229 >> 9u);
    unsigned r1829 = (r1828 & 511u);
    unsigned r1830 = (r1229 >> 18u);
    unsigned r1831 = (r1830 & 511u);
    unsigned r1832 = (r1230 & 511u);
    unsigned r1833 = (r1230 >> 9u);
    unsigned r1834 = (r1833 & 511u);
    unsigned r1835 = (r1230 >> 18u);
    unsigned r1836 = (r1835 & 511u);
    unsigned r1837 = (r1231 & 511u);
    unsigned r1838 = (r1231 >> 9u);
    unsigned r1839 = (r1838 & 511u);
    unsigned r1840 = (r1231 >> 18u);
    unsigned r1841 = (r1840 & 511u);
    unsigned r1842 = (r1232 & 511u);
    unsigned r1843 = (r1232 >> 9u);
    unsigned r1844 = (r1843 & 511u);
    unsigned r1845 = (r1232 >> 18u);
    unsigned r1846 = (r1845 & 511u);
    unsigned r1847 = (r1233 & 511u);
    unsigned r1848 = (r1233 >> 9u);
    unsigned r1849 = (r1848 & 511u);
    unsigned r1850 = (r1233 >> 18u);
    unsigned r1851 = (r1850 & 511u);
    unsigned r1852 = (r1234 & 511u);
    unsigned r1853 = (r1234 >> 9u);
    unsigned r1854 = (r1853 & 511u);
    unsigned r1855 = (r1234 >> 18u);
    unsigned r1856 = (r1855 & 511u);
    unsigned r1857 = (r1235 & 511u);
    const unsigned dargs24[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1812, r1814, r1816, r1817, r1819, r1821, r1822, r1824, r1826, r1827, r1829, r1831, r1832, r1834, r1836, r1837, r1839, r1841, r1842, r1844, r1846, r1847, r1849, r1851, r1852, r1854, r1856, r1857 };
    unsigned douts24[28];
    stwo_wit_deduce_felt_mul(dargs24, douts24);
    unsigned r1858 = douts24[0];
    unsigned r1859 = douts24[1];
    unsigned r1860 = douts24[2];
    unsigned r1861 = douts24[3];
    unsigned r1862 = douts24[4];
    unsigned r1863 = douts24[5];
    unsigned r1864 = douts24[6];
    unsigned r1865 = douts24[7];
    unsigned r1866 = douts24[8];
    unsigned r1867 = douts24[9];
    unsigned r1868 = douts24[10];
    unsigned r1869 = douts24[11];
    unsigned r1870 = douts24[12];
    unsigned r1871 = douts24[13];
    unsigned r1872 = douts24[14];
    unsigned r1873 = douts24[15];
    unsigned r1874 = douts24[16];
    unsigned r1875 = douts24[17];
    unsigned r1876 = douts24[18];
    unsigned r1877 = douts24[19];
    unsigned r1878 = douts24[20];
    unsigned r1879 = douts24[21];
    unsigned r1880 = douts24[22];
    unsigned r1881 = douts24[23];
    unsigned r1882 = douts24[24];
    unsigned r1883 = douts24[25];
    unsigned r1884 = douts24[26];
    unsigned r1885 = douts24[27];
    const unsigned dargs25[56] = { r1784, r1785, r1786, r1787, r1788, r1789, r1790, r1791, r1792, r1793, r1794, r1795, r1796, r1797, r1798, r1799, r1800, r1801, r1802, r1803, r1804, r1805, r1806, r1807, r1808, r1809, r1810, r1811, r1858, r1859, r1860, r1861, r1862, r1863, r1864, r1865, r1866, r1867, r1868, r1869, r1870, r1871, r1872, r1873, r1874, r1875, r1876, r1877, r1878, r1879, r1880, r1881, r1882, r1883, r1884, r1885 };
    unsigned douts25[28];
    stwo_wit_deduce_felt_add(dargs25, douts25);
    unsigned r1886 = douts25[0];
    unsigned r1887 = douts25[1];
    unsigned r1888 = douts25[2];
    unsigned r1889 = douts25[3];
    unsigned r1890 = douts25[4];
    unsigned r1891 = douts25[5];
    unsigned r1892 = douts25[6];
    unsigned r1893 = douts25[7];
    unsigned r1894 = douts25[8];
    unsigned r1895 = douts25[9];
    unsigned r1896 = douts25[10];
    unsigned r1897 = douts25[11];
    unsigned r1898 = douts25[12];
    unsigned r1899 = douts25[13];
    unsigned r1900 = douts25[14];
    unsigned r1901 = douts25[15];
    unsigned r1902 = douts25[16];
    unsigned r1903 = douts25[17];
    unsigned r1904 = douts25[18];
    unsigned r1905 = douts25[19];
    unsigned r1906 = douts25[20];
    unsigned r1907 = douts25[21];
    unsigned r1908 = douts25[22];
    unsigned r1909 = douts25[23];
    unsigned r1910 = douts25[24];
    unsigned r1911 = douts25[25];
    unsigned r1912 = douts25[26];
    unsigned r1913 = douts25[27];
    unsigned r1914 = (r1700 & 511u);
    unsigned r1915 = (r1700 >> 9u);
    unsigned r1916 = (r1915 & 511u);
    unsigned r1917 = (r1700 >> 18u);
    unsigned r1918 = (r1917 & 511u);
    unsigned r1919 = (r1701 & 511u);
    unsigned r1920 = (r1701 >> 9u);
    unsigned r1921 = (r1920 & 511u);
    unsigned r1922 = (r1701 >> 18u);
    unsigned r1923 = (r1922 & 511u);
    unsigned r1924 = (r1702 & 511u);
    unsigned r1925 = (r1702 >> 9u);
    unsigned r1926 = (r1925 & 511u);
    unsigned r1927 = (r1702 >> 18u);
    unsigned r1928 = (r1927 & 511u);
    unsigned r1929 = (r1703 & 511u);
    unsigned r1930 = (r1703 >> 9u);
    unsigned r1931 = (r1930 & 511u);
    unsigned r1932 = (r1703 >> 18u);
    unsigned r1933 = (r1932 & 511u);
    unsigned r1934 = (r1704 & 511u);
    unsigned r1935 = (r1704 >> 9u);
    unsigned r1936 = (r1935 & 511u);
    unsigned r1937 = (r1704 >> 18u);
    unsigned r1938 = (r1937 & 511u);
    unsigned r1939 = (r1705 & 511u);
    unsigned r1940 = (r1705 >> 9u);
    unsigned r1941 = (r1940 & 511u);
    unsigned r1942 = (r1705 >> 18u);
    unsigned r1943 = (r1942 & 511u);
    unsigned r1944 = (r1706 & 511u);
    unsigned r1945 = (r1706 >> 9u);
    unsigned r1946 = (r1945 & 511u);
    unsigned r1947 = (r1706 >> 18u);
    unsigned r1948 = (r1947 & 511u);
    unsigned r1949 = (r1707 & 511u);
    unsigned r1950 = (r1707 >> 9u);
    unsigned r1951 = (r1950 & 511u);
    unsigned r1952 = (r1707 >> 18u);
    unsigned r1953 = (r1952 & 511u);
    unsigned r1954 = (r1708 & 511u);
    unsigned r1955 = (r1708 >> 9u);
    unsigned r1956 = (r1955 & 511u);
    unsigned r1957 = (r1708 >> 18u);
    unsigned r1958 = (r1957 & 511u);
    unsigned r1959 = (r1709 & 511u);
    const unsigned dargs26[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1914, r1916, r1918, r1919, r1921, r1923, r1924, r1926, r1928, r1929, r1931, r1933, r1934, r1936, r1938, r1939, r1941, r1943, r1944, r1946, r1948, r1949, r1951, r1953, r1954, r1956, r1958, r1959 };
    unsigned douts26[28];
    stwo_wit_deduce_felt_mul(dargs26, douts26);
    unsigned r1960 = douts26[0];
    unsigned r1961 = douts26[1];
    unsigned r1962 = douts26[2];
    unsigned r1963 = douts26[3];
    unsigned r1964 = douts26[4];
    unsigned r1965 = douts26[5];
    unsigned r1966 = douts26[6];
    unsigned r1967 = douts26[7];
    unsigned r1968 = douts26[8];
    unsigned r1969 = douts26[9];
    unsigned r1970 = douts26[10];
    unsigned r1971 = douts26[11];
    unsigned r1972 = douts26[12];
    unsigned r1973 = douts26[13];
    unsigned r1974 = douts26[14];
    unsigned r1975 = douts26[15];
    unsigned r1976 = douts26[16];
    unsigned r1977 = douts26[17];
    unsigned r1978 = douts26[18];
    unsigned r1979 = douts26[19];
    unsigned r1980 = douts26[20];
    unsigned r1981 = douts26[21];
    unsigned r1982 = douts26[22];
    unsigned r1983 = douts26[23];
    unsigned r1984 = douts26[24];
    unsigned r1985 = douts26[25];
    unsigned r1986 = douts26[26];
    unsigned r1987 = douts26[27];
    const unsigned dargs27[56] = { r1886, r1887, r1888, r1889, r1890, r1891, r1892, r1893, r1894, r1895, r1896, r1897, r1898, r1899, r1900, r1901, r1902, r1903, r1904, r1905, r1906, r1907, r1908, r1909, r1910, r1911, r1912, r1913, r1960, r1961, r1962, r1963, r1964, r1965, r1966, r1967, r1968, r1969, r1970, r1971, r1972, r1973, r1974, r1975, r1976, r1977, r1978, r1979, r1980, r1981, r1982, r1983, r1984, r1985, r1986, r1987 };
    unsigned douts27[28];
    stwo_wit_deduce_felt_sub(dargs27, douts27);
    unsigned r1988 = douts27[0];
    unsigned r1989 = douts27[1];
    unsigned r1990 = douts27[2];
    unsigned r1991 = douts27[3];
    unsigned r1992 = douts27[4];
    unsigned r1993 = douts27[5];
    unsigned r1994 = douts27[6];
    unsigned r1995 = douts27[7];
    unsigned r1996 = douts27[8];
    unsigned r1997 = douts27[9];
    unsigned r1998 = douts27[10];
    unsigned r1999 = douts27[11];
    unsigned r2000 = douts27[12];
    unsigned r2001 = douts27[13];
    unsigned r2002 = douts27[14];
    unsigned r2003 = douts27[15];
    unsigned r2004 = douts27[16];
    unsigned r2005 = douts27[17];
    unsigned r2006 = douts27[18];
    unsigned r2007 = douts27[19];
    unsigned r2008 = douts27[20];
    unsigned r2009 = douts27[21];
    unsigned r2010 = douts27[22];
    unsigned r2011 = douts27[23];
    unsigned r2012 = douts27[24];
    unsigned r2013 = douts27[25];
    unsigned r2014 = douts27[26];
    unsigned r2015 = douts27[27];
    const unsigned dargs28[56] = { r1988, r1989, r1990, r1991, r1992, r1993, r1994, r1995, r1996, r1997, r1998, r1999, r2000, r2001, r2002, r2003, r2004, r2005, r2006, r2007, r2008, r2009, r2010, r2011, r2012, r2013, r2014, r2015, r33, r39, r176, r99, r36, r164, r52, r114, r186, r93, r187, r18, r166, r76, r104, r43, r51, r172, r177, r53, r109, r123, r118, r89, r48, r63, r134, r74 };
    unsigned douts28[28];
    stwo_wit_deduce_felt_add(dargs28, douts28);
    unsigned r2016 = douts28[0];
    unsigned r2017 = douts28[1];
    unsigned r2018 = douts28[2];
    unsigned r2019 = douts28[3];
    unsigned r2020 = douts28[4];
    unsigned r2021 = douts28[5];
    unsigned r2022 = douts28[6];
    unsigned r2023 = douts28[7];
    unsigned r2024 = douts28[8];
    unsigned r2025 = douts28[9];
    unsigned r2026 = douts28[10];
    unsigned r2027 = douts28[11];
    unsigned r2028 = douts28[12];
    unsigned r2029 = douts28[13];
    unsigned r2030 = douts28[14];
    unsigned r2031 = douts28[15];
    unsigned r2032 = douts28[16];
    unsigned r2033 = douts28[17];
    unsigned r2034 = douts28[18];
    unsigned r2035 = douts28[19];
    unsigned r2036 = douts28[20];
    unsigned r2037 = douts28[21];
    unsigned r2038 = douts28[22];
    unsigned r2039 = douts28[23];
    unsigned r2040 = douts28[24];
    unsigned r2041 = douts28[25];
    unsigned r2042 = douts28[26];
    unsigned r2043 = douts28[27];
    unsigned r2044 = stwo_m31_mul(r2017, r191);
    unsigned r2045 = stwo_m31_add(r2016, r2044);
    unsigned r2046 = stwo_m31_mul(r2018, r193);
    unsigned r2047 = stwo_m31_add(r2045, r2046);
    unsigned r2048 = stwo_m31_mul(r2020, r191);
    unsigned r2049 = stwo_m31_add(r2019, r2048);
    unsigned r2050 = stwo_m31_mul(r2021, r193);
    unsigned r2051 = stwo_m31_add(r2049, r2050);
    unsigned r2052 = stwo_m31_mul(r2023, r191);
    unsigned r2053 = stwo_m31_add(r2022, r2052);
    unsigned r2054 = stwo_m31_mul(r2024, r193);
    unsigned r2055 = stwo_m31_add(r2053, r2054);
    unsigned r2056 = stwo_m31_mul(r2026, r191);
    unsigned r2057 = stwo_m31_add(r2025, r2056);
    unsigned r2058 = stwo_m31_mul(r2027, r193);
    unsigned r2059 = stwo_m31_add(r2057, r2058);
    unsigned r2060 = stwo_m31_mul(r2029, r191);
    unsigned r2061 = stwo_m31_add(r2028, r2060);
    unsigned r2062 = stwo_m31_mul(r2030, r193);
    unsigned r2063 = stwo_m31_add(r2061, r2062);
    unsigned r2064 = stwo_m31_mul(r2032, r191);
    unsigned r2065 = stwo_m31_add(r2031, r2064);
    unsigned r2066 = stwo_m31_mul(r2033, r193);
    unsigned r2067 = stwo_m31_add(r2065, r2066);
    unsigned r2068 = stwo_m31_mul(r2035, r191);
    unsigned r2069 = stwo_m31_add(r2034, r2068);
    unsigned r2070 = stwo_m31_mul(r2036, r193);
    unsigned r2071 = stwo_m31_add(r2069, r2070);
    unsigned r2072 = stwo_m31_mul(r2038, r191);
    unsigned r2073 = stwo_m31_add(r2037, r2072);
    unsigned r2074 = stwo_m31_mul(r2039, r193);
    unsigned r2075 = stwo_m31_add(r2073, r2074);
    unsigned r2076 = stwo_m31_mul(r2041, r191);
    unsigned r2077 = stwo_m31_add(r2040, r2076);
    unsigned r2078 = stwo_m31_mul(r2042, r193);
    unsigned r2079 = stwo_m31_add(r2077, r2078);
    unsigned r2080 = stwo_m31_mul(r4, r1196);
    unsigned r2081 = stwo_m31_mul(r2, r1226);
    unsigned r2082 = stwo_m31_add(r2080, r2081);
    unsigned r2083 = stwo_m31_mul(r2, r1700);
    unsigned r2084 = stwo_m31_sub(r2082, r2083);
    unsigned r2085 = stwo_m31_add(r2084, r252);
    unsigned r2086 = stwo_m31_sub(r2085, r2047);
    unsigned r2087 = stwo_m31_add(r2086, r258);
    unsigned r2088 = (r2087 & 65535u);
    unsigned r2089 = (r2088 % STWO_M31_P);
    unsigned r2090 = stwo_m31_sub(r2089, r3);
    unsigned r2091 = stwo_m31_mul(r4, r1196);
    out_cols[123u][row] = r1196;
    lookup_words[126u * row_count + row] = r1196;
    sub_words[262u * row_count + row] = r1196;
    lookup_words[157u * row_count + row] = r1196;
    unsigned r2092 = stwo_m31_mul(r2, r1226);
    unsigned r2093 = stwo_m31_add(r2091, r2092);
    unsigned r2094 = stwo_m31_mul(r2, r1700);
    unsigned r2095 = stwo_m31_sub(r2093, r2094);
    unsigned r2096 = stwo_m31_add(r2095, r252);
    unsigned r2097 = stwo_m31_sub(r2096, r2047);
    unsigned r2098 = stwo_m31_sub(r2097, r2090);
    unsigned r2099 = stwo_m31_mul(r2098, r16);
    unsigned r2100 = stwo_m31_mul(r4, r1197);
    out_cols[124u][row] = r1197;
    lookup_words[127u * row_count + row] = r1197;
    sub_words[263u * row_count + row] = r1197;
    lookup_words[158u * row_count + row] = r1197;
    unsigned r2101 = stwo_m31_add(r2099, r2100);
    unsigned r2102 = stwo_m31_mul(r2, r1227);
    unsigned r2103 = stwo_m31_add(r2101, r2102);
    unsigned r2104 = stwo_m31_mul(r2, r1701);
    unsigned r2105 = stwo_m31_sub(r2103, r2104);
    unsigned r2106 = stwo_m31_add(r2105, r245);
    unsigned r2107 = stwo_m31_sub(r2106, r2051);
    unsigned r2108 = stwo_m31_mul(r2107, r16);
    unsigned r2109 = stwo_m31_mul(r4, r1198);
    out_cols[125u][row] = r1198;
    lookup_words[128u * row_count + row] = r1198;
    sub_words[264u * row_count + row] = r1198;
    lookup_words[159u * row_count + row] = r1198;
    unsigned r2110 = stwo_m31_add(r2108, r2109);
    unsigned r2111 = stwo_m31_mul(r2, r1228);
    unsigned r2112 = stwo_m31_add(r2110, r2111);
    unsigned r2113 = stwo_m31_mul(r2, r1702);
    unsigned r2114 = stwo_m31_sub(r2112, r2113);
    unsigned r2115 = stwo_m31_add(r2114, r255);
    unsigned r2116 = stwo_m31_sub(r2115, r2055);
    unsigned r2117 = stwo_m31_mul(r2116, r16);
    unsigned r2118 = stwo_m31_mul(r4, r1199);
    out_cols[126u][row] = r1199;
    lookup_words[129u * row_count + row] = r1199;
    sub_words[265u * row_count + row] = r1199;
    lookup_words[160u * row_count + row] = r1199;
    unsigned r2119 = stwo_m31_add(r2117, r2118);
    unsigned r2120 = stwo_m31_mul(r2, r1229);
    unsigned r2121 = stwo_m31_add(r2119, r2120);
    unsigned r2122 = stwo_m31_mul(r2, r1703);
    unsigned r2123 = stwo_m31_sub(r2121, r2122);
    unsigned r2124 = stwo_m31_add(r2123, r195);
    unsigned r2125 = stwo_m31_sub(r2124, r2059);
    unsigned r2126 = stwo_m31_mul(r2125, r16);
    unsigned r2127 = stwo_m31_mul(r4, r1200);
    out_cols[127u][row] = r1200;
    lookup_words[130u * row_count + row] = r1200;
    sub_words[266u * row_count + row] = r1200;
    lookup_words[161u * row_count + row] = r1200;
    unsigned r2128 = stwo_m31_add(r2126, r2127);
    unsigned r2129 = stwo_m31_mul(r2, r1230);
    unsigned r2130 = stwo_m31_add(r2128, r2129);
    unsigned r2131 = stwo_m31_mul(r2, r1704);
    unsigned r2132 = stwo_m31_sub(r2130, r2131);
    unsigned r2133 = stwo_m31_add(r2132, r222);
    unsigned r2134 = stwo_m31_sub(r2133, r2063);
    unsigned r2135 = stwo_m31_mul(r2134, r16);
    unsigned r2136 = stwo_m31_mul(r4, r1201);
    out_cols[128u][row] = r1201;
    lookup_words[131u * row_count + row] = r1201;
    sub_words[267u * row_count + row] = r1201;
    lookup_words[162u * row_count + row] = r1201;
    unsigned r2137 = stwo_m31_add(r2135, r2136);
    unsigned r2138 = stwo_m31_mul(r2, r1231);
    unsigned r2139 = stwo_m31_add(r2137, r2138);
    unsigned r2140 = stwo_m31_mul(r2, r1705);
    unsigned r2141 = stwo_m31_sub(r2139, r2140);
    unsigned r2142 = stwo_m31_add(r2141, r250);
    unsigned r2143 = stwo_m31_sub(r2142, r2067);
    unsigned r2144 = stwo_m31_mul(r2143, r16);
    unsigned r2145 = stwo_m31_mul(r4, r1202);
    out_cols[129u][row] = r1202;
    lookup_words[132u * row_count + row] = r1202;
    sub_words[268u * row_count + row] = r1202;
    lookup_words[163u * row_count + row] = r1202;
    unsigned r2146 = stwo_m31_add(r2144, r2145);
    unsigned r2147 = stwo_m31_mul(r2, r1232);
    unsigned r2148 = stwo_m31_add(r2146, r2147);
    unsigned r2149 = stwo_m31_mul(r2, r1706);
    unsigned r2150 = stwo_m31_sub(r2148, r2149);
    unsigned r2151 = stwo_m31_add(r2150, r226);
    unsigned r2152 = stwo_m31_sub(r2151, r2071);
    unsigned r2153 = stwo_m31_mul(r2152, r16);
    unsigned r2154 = stwo_m31_mul(r4, r1203);
    out_cols[130u][row] = r1203;
    lookup_words[133u * row_count + row] = r1203;
    sub_words[269u * row_count + row] = r1203;
    lookup_words[164u * row_count + row] = r1203;
    unsigned r2155 = stwo_m31_add(r2153, r2154);
    unsigned r2156 = stwo_m31_mul(r2, r1233);
    unsigned r2157 = stwo_m31_add(r2155, r2156);
    unsigned r2158 = stwo_m31_mul(r2, r1707);
    unsigned r2159 = stwo_m31_sub(r2157, r2158);
    unsigned r2160 = stwo_m31_add(r2159, r216);
    unsigned r2161 = stwo_m31_sub(r2160, r2075);
    unsigned r2162 = stwo_m31_mul(r2090, r67);
    unsigned r2163 = stwo_m31_sub(r2161, r2162);
    unsigned r2164 = stwo_m31_mul(r2163, r16);
    unsigned r2165 = stwo_m31_mul(r4, r1204);
    out_cols[131u][row] = r1204;
    lookup_words[134u * row_count + row] = r1204;
    sub_words[270u * row_count + row] = r1204;
    lookup_words[165u * row_count + row] = r1204;
    unsigned r2166 = stwo_m31_add(r2164, r2165);
    unsigned r2167 = stwo_m31_mul(r2, r1234);
    unsigned r2168 = stwo_m31_add(r2166, r2167);
    unsigned r2169 = stwo_m31_mul(r2, r1708);
    unsigned r2170 = stwo_m31_sub(r2168, r2169);
    unsigned r2171 = stwo_m31_add(r2170, r235);
    unsigned r2172 = stwo_m31_sub(r2171, r2079);
    unsigned r2173 = stwo_m31_mul(r2172, r16);
    unsigned r2174 = stwo_m31_add(r2090, r3);
    sub_words[312u * row_count + row] = r2174;
    unsigned r2175 = stwo_m31_add(r2099, r3);
    sub_words[313u * row_count + row] = r2175;
    unsigned r2176 = stwo_m31_add(r2108, r3);
    sub_words[314u * row_count + row] = r2176;
    unsigned r2177 = stwo_m31_add(r2117, r3);
    sub_words[315u * row_count + row] = r2177;
    unsigned r2178 = stwo_m31_add(r2090, r3);
    out_cols[194u][row] = r2090;
    lookup_words[233u * row_count + row] = r2178;
    unsigned r2179 = stwo_m31_add(r2099, r3);
    lookup_words[234u * row_count + row] = r2179;
    unsigned r2180 = stwo_m31_add(r2108, r3);
    lookup_words[235u * row_count + row] = r2180;
    unsigned r2181 = stwo_m31_add(r2117, r3);
    lookup_words[236u * row_count + row] = r2181;
    unsigned r2182 = stwo_m31_add(r2126, r3);
    sub_words[316u * row_count + row] = r2182;
    unsigned r2183 = stwo_m31_add(r2135, r3);
    sub_words[317u * row_count + row] = r2183;
    unsigned r2184 = stwo_m31_add(r2144, r3);
    sub_words[318u * row_count + row] = r2184;
    unsigned r2185 = stwo_m31_add(r2153, r3);
    sub_words[319u * row_count + row] = r2185;
    unsigned r2186 = stwo_m31_add(r2126, r3);
    lookup_words[238u * row_count + row] = r2186;
    unsigned r2187 = stwo_m31_add(r2135, r3);
    lookup_words[239u * row_count + row] = r2187;
    unsigned r2188 = stwo_m31_add(r2144, r3);
    lookup_words[240u * row_count + row] = r2188;
    unsigned r2189 = stwo_m31_add(r2153, r3);
    lookup_words[241u * row_count + row] = r2189;
    unsigned r2190 = stwo_m31_add(r2164, r3);
    sub_words[336u * row_count + row] = r2190;
    unsigned r2191 = stwo_m31_add(r2173, r3);
    sub_words[337u * row_count + row] = r2191;
    unsigned r2192 = stwo_m31_add(r2164, r3);
    lookup_words[243u * row_count + row] = r2192;
    unsigned r2193 = stwo_m31_add(r2173, r3);
    sub_words[103u * row_count + row] = r3;
    lookup_words[244u * row_count + row] = r2193;
    const unsigned dargs29[42] = { r268, r4, r1226, r1227, r1228, r1229, r1230, r1231, r1232, r1233, r1234, r1235, r1573, r1577, r1581, r1585, r1589, r1593, r1597, r1601, r1605, r1569, r1700, r1701, r1702, r1703, r1704, r1705, r1706, r1707, r1708, r1709, r2047, r2051, r2055, r2059, r2063, r2067, r2071, r2075, r2079, r2043 };
    unsigned douts29[42];
    out_cols[153u][row] = r1226;
    out_cols[154u][row] = r1227;
    out_cols[155u][row] = r1228;
    out_cols[156u][row] = r1229;
    out_cols[157u][row] = r1230;
    out_cols[158u][row] = r1231;
    out_cols[159u][row] = r1232;
    out_cols[160u][row] = r1233;
    out_cols[161u][row] = r1234;
    out_cols[162u][row] = r1235;
    lookup_words[189u * row_count + row] = r1226;
    lookup_words[190u * row_count + row] = r1227;
    lookup_words[191u * row_count + row] = r1228;
    lookup_words[192u * row_count + row] = r1229;
    lookup_words[193u * row_count + row] = r1230;
    lookup_words[194u * row_count + row] = r1231;
    lookup_words[195u * row_count + row] = r1232;
    lookup_words[196u * row_count + row] = r1233;
    lookup_words[197u * row_count + row] = r1234;
    lookup_words[198u * row_count + row] = r1235;
    out_cols[163u][row] = r1573;
    out_cols[164u][row] = r1577;
    out_cols[165u][row] = r1581;
    out_cols[166u][row] = r1585;
    out_cols[167u][row] = r1589;
    out_cols[168u][row] = r1593;
    out_cols[169u][row] = r1597;
    out_cols[170u][row] = r1601;
    out_cols[171u][row] = r1605;
    out_cols[172u][row] = r1569;
    sub_words[292u * row_count + row] = r1573;
    sub_words[293u * row_count + row] = r1577;
    sub_words[294u * row_count + row] = r1581;
    sub_words[295u * row_count + row] = r1585;
    sub_words[296u * row_count + row] = r1589;
    sub_words[297u * row_count + row] = r1593;
    sub_words[298u * row_count + row] = r1597;
    sub_words[299u * row_count + row] = r1601;
    sub_words[300u * row_count + row] = r1605;
    sub_words[301u * row_count + row] = r1569;
    out_cols[174u][row] = r1700;
    out_cols[175u][row] = r1701;
    out_cols[176u][row] = r1702;
    out_cols[177u][row] = r1703;
    out_cols[178u][row] = r1704;
    out_cols[179u][row] = r1705;
    out_cols[180u][row] = r1706;
    out_cols[181u][row] = r1707;
    out_cols[182u][row] = r1708;
    out_cols[183u][row] = r1709;
    lookup_words[212u * row_count + row] = r1573;
    lookup_words[213u * row_count + row] = r1577;
    lookup_words[214u * row_count + row] = r1581;
    lookup_words[215u * row_count + row] = r1585;
    lookup_words[216u * row_count + row] = r1589;
    lookup_words[217u * row_count + row] = r1593;
    lookup_words[218u * row_count + row] = r1597;
    lookup_words[219u * row_count + row] = r1601;
    lookup_words[220u * row_count + row] = r1605;
    lookup_words[221u * row_count + row] = r1569;
    lookup_words[222u * row_count + row] = r1700;
    lookup_words[223u * row_count + row] = r1701;
    lookup_words[224u * row_count + row] = r1702;
    lookup_words[225u * row_count + row] = r1703;
    lookup_words[226u * row_count + row] = r1704;
    lookup_words[227u * row_count + row] = r1705;
    lookup_words[228u * row_count + row] = r1706;
    lookup_words[229u * row_count + row] = r1707;
    lookup_words[230u * row_count + row] = r1708;
    lookup_words[231u * row_count + row] = r1709;
    out_cols[184u][row] = r2047;
    out_cols[185u][row] = r2051;
    out_cols[186u][row] = r2055;
    out_cols[187u][row] = r2059;
    out_cols[188u][row] = r2063;
    out_cols[189u][row] = r2067;
    out_cols[190u][row] = r2071;
    out_cols[191u][row] = r2075;
    out_cols[192u][row] = r2079;
    out_cols[193u][row] = r2043;
    lookup_words[248u * row_count + row] = r1226;
    lookup_words[249u * row_count + row] = r1227;
    lookup_words[250u * row_count + row] = r1228;
    lookup_words[251u * row_count + row] = r1229;
    lookup_words[252u * row_count + row] = r1230;
    lookup_words[253u * row_count + row] = r1231;
    lookup_words[254u * row_count + row] = r1232;
    lookup_words[255u * row_count + row] = r1233;
    lookup_words[256u * row_count + row] = r1234;
    lookup_words[257u * row_count + row] = r1235;
    lookup_words[258u * row_count + row] = r1573;
    lookup_words[259u * row_count + row] = r1577;
    lookup_words[260u * row_count + row] = r1581;
    lookup_words[261u * row_count + row] = r1585;
    lookup_words[262u * row_count + row] = r1589;
    lookup_words[263u * row_count + row] = r1593;
    lookup_words[264u * row_count + row] = r1597;
    lookup_words[265u * row_count + row] = r1601;
    lookup_words[266u * row_count + row] = r1605;
    lookup_words[267u * row_count + row] = r1569;
    lookup_words[268u * row_count + row] = r1700;
    lookup_words[269u * row_count + row] = r1701;
    lookup_words[270u * row_count + row] = r1702;
    lookup_words[271u * row_count + row] = r1703;
    lookup_words[272u * row_count + row] = r1704;
    lookup_words[273u * row_count + row] = r1705;
    lookup_words[274u * row_count + row] = r1706;
    lookup_words[275u * row_count + row] = r1707;
    lookup_words[276u * row_count + row] = r1708;
    lookup_words[277u * row_count + row] = r1709;
    lookup_words[278u * row_count + row] = r2047;
    lookup_words[279u * row_count + row] = r2051;
    lookup_words[280u * row_count + row] = r2055;
    lookup_words[281u * row_count + row] = r2059;
    lookup_words[282u * row_count + row] = r2063;
    lookup_words[283u * row_count + row] = r2067;
    lookup_words[284u * row_count + row] = r2071;
    lookup_words[285u * row_count + row] = r2075;
    lookup_words[286u * row_count + row] = r2079;
    lookup_words[287u * row_count + row] = r2043;
    sub_words[344u * row_count + row] = r1226;
    sub_words[345u * row_count + row] = r1227;
    sub_words[346u * row_count + row] = r1228;
    sub_words[347u * row_count + row] = r1229;
    sub_words[348u * row_count + row] = r1230;
    sub_words[349u * row_count + row] = r1231;
    sub_words[350u * row_count + row] = r1232;
    sub_words[351u * row_count + row] = r1233;
    sub_words[352u * row_count + row] = r1234;
    sub_words[353u * row_count + row] = r1235;
    sub_words[354u * row_count + row] = r1573;
    sub_words[355u * row_count + row] = r1577;
    sub_words[356u * row_count + row] = r1581;
    sub_words[357u * row_count + row] = r1585;
    sub_words[358u * row_count + row] = r1589;
    sub_words[359u * row_count + row] = r1593;
    sub_words[360u * row_count + row] = r1597;
    sub_words[361u * row_count + row] = r1601;
    sub_words[362u * row_count + row] = r1605;
    sub_words[363u * row_count + row] = r1569;
    sub_words[364u * row_count + row] = r1700;
    sub_words[365u * row_count + row] = r1701;
    sub_words[366u * row_count + row] = r1702;
    sub_words[367u * row_count + row] = r1703;
    sub_words[368u * row_count + row] = r1704;
    sub_words[369u * row_count + row] = r1705;
    sub_words[370u * row_count + row] = r1706;
    sub_words[371u * row_count + row] = r1707;
    sub_words[372u * row_count + row] = r1708;
    sub_words[373u * row_count + row] = r1709;
    sub_words[374u * row_count + row] = r2047;
    sub_words[375u * row_count + row] = r2051;
    sub_words[376u * row_count + row] = r2055;
    sub_words[377u * row_count + row] = r2059;
    sub_words[378u * row_count + row] = r2063;
    sub_words[379u * row_count + row] = r2067;
    sub_words[380u * row_count + row] = r2071;
    sub_words[381u * row_count + row] = r2075;
    sub_words[382u * row_count + row] = r2079;
    sub_words[383u * row_count + row] = r2043;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs29, douts29);
    unsigned r2194 = douts29[0];
    unsigned r2195 = douts29[1];
    unsigned r2196 = douts29[2];
    unsigned r2197 = douts29[3];
    unsigned r2198 = douts29[4];
    unsigned r2199 = douts29[5];
    unsigned r2200 = douts29[6];
    unsigned r2201 = douts29[7];
    unsigned r2202 = douts29[8];
    unsigned r2203 = douts29[9];
    unsigned r2204 = douts29[10];
    unsigned r2205 = douts29[11];
    unsigned r2206 = douts29[12];
    unsigned r2207 = douts29[13];
    unsigned r2208 = douts29[14];
    unsigned r2209 = douts29[15];
    unsigned r2210 = douts29[16];
    unsigned r2211 = douts29[17];
    unsigned r2212 = douts29[18];
    unsigned r2213 = douts29[19];
    unsigned r2214 = douts29[20];
    unsigned r2215 = douts29[21];
    unsigned r2216 = douts29[22];
    unsigned r2217 = douts29[23];
    unsigned r2218 = douts29[24];
    unsigned r2219 = douts29[25];
    unsigned r2220 = douts29[26];
    unsigned r2221 = douts29[27];
    unsigned r2222 = douts29[28];
    unsigned r2223 = douts29[29];
    unsigned r2224 = douts29[30];
    unsigned r2225 = douts29[31];
    unsigned r2226 = douts29[32];
    unsigned r2227 = douts29[33];
    unsigned r2228 = douts29[34];
    unsigned r2229 = douts29[35];
    unsigned r2230 = douts29[36];
    unsigned r2231 = douts29[37];
    unsigned r2232 = douts29[38];
    unsigned r2233 = douts29[39];
    unsigned r2234 = douts29[40];
    unsigned r2235 = douts29[41];
    const unsigned dargs30[42] = { r268, r5, r2196, r2197, r2198, r2199, r2200, r2201, r2202, r2203, r2204, r2205, r2206, r2207, r2208, r2209, r2210, r2211, r2212, r2213, r2214, r2215, r2216, r2217, r2218, r2219, r2220, r2221, r2222, r2223, r2224, r2225, r2226, r2227, r2228, r2229, r2230, r2231, r2232, r2233, r2234, r2235 };
    unsigned douts30[42];
    sub_words[385u * row_count + row] = r5;
    sub_words[386u * row_count + row] = r2196;
    sub_words[387u * row_count + row] = r2197;
    sub_words[388u * row_count + row] = r2198;
    sub_words[389u * row_count + row] = r2199;
    sub_words[390u * row_count + row] = r2200;
    sub_words[391u * row_count + row] = r2201;
    sub_words[392u * row_count + row] = r2202;
    sub_words[393u * row_count + row] = r2203;
    sub_words[394u * row_count + row] = r2204;
    sub_words[395u * row_count + row] = r2205;
    sub_words[396u * row_count + row] = r2206;
    sub_words[397u * row_count + row] = r2207;
    sub_words[398u * row_count + row] = r2208;
    sub_words[399u * row_count + row] = r2209;
    sub_words[400u * row_count + row] = r2210;
    sub_words[401u * row_count + row] = r2211;
    sub_words[402u * row_count + row] = r2212;
    sub_words[403u * row_count + row] = r2213;
    sub_words[404u * row_count + row] = r2214;
    sub_words[405u * row_count + row] = r2215;
    sub_words[406u * row_count + row] = r2216;
    sub_words[407u * row_count + row] = r2217;
    sub_words[408u * row_count + row] = r2218;
    sub_words[409u * row_count + row] = r2219;
    sub_words[410u * row_count + row] = r2220;
    sub_words[411u * row_count + row] = r2221;
    sub_words[412u * row_count + row] = r2222;
    sub_words[413u * row_count + row] = r2223;
    sub_words[414u * row_count + row] = r2224;
    sub_words[415u * row_count + row] = r2225;
    sub_words[416u * row_count + row] = r2226;
    sub_words[417u * row_count + row] = r2227;
    sub_words[418u * row_count + row] = r2228;
    sub_words[419u * row_count + row] = r2229;
    sub_words[420u * row_count + row] = r2230;
    sub_words[421u * row_count + row] = r2231;
    sub_words[422u * row_count + row] = r2232;
    sub_words[423u * row_count + row] = r2233;
    sub_words[424u * row_count + row] = r2234;
    sub_words[425u * row_count + row] = r2235;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs30, douts30);
    unsigned r2236 = douts30[0];
    unsigned r2237 = douts30[1];
    unsigned r2238 = douts30[2];
    unsigned r2239 = douts30[3];
    unsigned r2240 = douts30[4];
    unsigned r2241 = douts30[5];
    unsigned r2242 = douts30[6];
    unsigned r2243 = douts30[7];
    unsigned r2244 = douts30[8];
    unsigned r2245 = douts30[9];
    unsigned r2246 = douts30[10];
    unsigned r2247 = douts30[11];
    unsigned r2248 = douts30[12];
    unsigned r2249 = douts30[13];
    unsigned r2250 = douts30[14];
    unsigned r2251 = douts30[15];
    unsigned r2252 = douts30[16];
    unsigned r2253 = douts30[17];
    unsigned r2254 = douts30[18];
    unsigned r2255 = douts30[19];
    unsigned r2256 = douts30[20];
    unsigned r2257 = douts30[21];
    unsigned r2258 = douts30[22];
    unsigned r2259 = douts30[23];
    unsigned r2260 = douts30[24];
    unsigned r2261 = douts30[25];
    unsigned r2262 = douts30[26];
    unsigned r2263 = douts30[27];
    unsigned r2264 = douts30[28];
    unsigned r2265 = douts30[29];
    unsigned r2266 = douts30[30];
    unsigned r2267 = douts30[31];
    unsigned r2268 = douts30[32];
    unsigned r2269 = douts30[33];
    unsigned r2270 = douts30[34];
    unsigned r2271 = douts30[35];
    unsigned r2272 = douts30[36];
    unsigned r2273 = douts30[37];
    unsigned r2274 = douts30[38];
    unsigned r2275 = douts30[39];
    unsigned r2276 = douts30[40];
    unsigned r2277 = douts30[41];
    const unsigned dargs31[42] = { r268, r6, r2238, r2239, r2240, r2241, r2242, r2243, r2244, r2245, r2246, r2247, r2248, r2249, r2250, r2251, r2252, r2253, r2254, r2255, r2256, r2257, r2258, r2259, r2260, r2261, r2262, r2263, r2264, r2265, r2266, r2267, r2268, r2269, r2270, r2271, r2272, r2273, r2274, r2275, r2276, r2277 };
    unsigned douts31[42];
    sub_words[427u * row_count + row] = r6;
    sub_words[428u * row_count + row] = r2238;
    sub_words[429u * row_count + row] = r2239;
    sub_words[430u * row_count + row] = r2240;
    sub_words[431u * row_count + row] = r2241;
    sub_words[432u * row_count + row] = r2242;
    sub_words[433u * row_count + row] = r2243;
    sub_words[434u * row_count + row] = r2244;
    sub_words[435u * row_count + row] = r2245;
    sub_words[436u * row_count + row] = r2246;
    sub_words[437u * row_count + row] = r2247;
    sub_words[438u * row_count + row] = r2248;
    sub_words[439u * row_count + row] = r2249;
    sub_words[440u * row_count + row] = r2250;
    sub_words[441u * row_count + row] = r2251;
    sub_words[442u * row_count + row] = r2252;
    sub_words[443u * row_count + row] = r2253;
    sub_words[444u * row_count + row] = r2254;
    sub_words[445u * row_count + row] = r2255;
    sub_words[446u * row_count + row] = r2256;
    sub_words[447u * row_count + row] = r2257;
    sub_words[448u * row_count + row] = r2258;
    sub_words[449u * row_count + row] = r2259;
    sub_words[450u * row_count + row] = r2260;
    sub_words[451u * row_count + row] = r2261;
    sub_words[452u * row_count + row] = r2262;
    sub_words[453u * row_count + row] = r2263;
    sub_words[454u * row_count + row] = r2264;
    sub_words[455u * row_count + row] = r2265;
    sub_words[456u * row_count + row] = r2266;
    sub_words[457u * row_count + row] = r2267;
    sub_words[458u * row_count + row] = r2268;
    sub_words[459u * row_count + row] = r2269;
    sub_words[460u * row_count + row] = r2270;
    sub_words[461u * row_count + row] = r2271;
    sub_words[462u * row_count + row] = r2272;
    sub_words[463u * row_count + row] = r2273;
    sub_words[464u * row_count + row] = r2274;
    sub_words[465u * row_count + row] = r2275;
    sub_words[466u * row_count + row] = r2276;
    sub_words[467u * row_count + row] = r2277;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs31, douts31);
    unsigned r2278 = douts31[0];
    unsigned r2279 = douts31[1];
    unsigned r2280 = douts31[2];
    unsigned r2281 = douts31[3];
    unsigned r2282 = douts31[4];
    unsigned r2283 = douts31[5];
    unsigned r2284 = douts31[6];
    unsigned r2285 = douts31[7];
    unsigned r2286 = douts31[8];
    unsigned r2287 = douts31[9];
    unsigned r2288 = douts31[10];
    unsigned r2289 = douts31[11];
    unsigned r2290 = douts31[12];
    unsigned r2291 = douts31[13];
    unsigned r2292 = douts31[14];
    unsigned r2293 = douts31[15];
    unsigned r2294 = douts31[16];
    unsigned r2295 = douts31[17];
    unsigned r2296 = douts31[18];
    unsigned r2297 = douts31[19];
    unsigned r2298 = douts31[20];
    unsigned r2299 = douts31[21];
    unsigned r2300 = douts31[22];
    unsigned r2301 = douts31[23];
    unsigned r2302 = douts31[24];
    unsigned r2303 = douts31[25];
    unsigned r2304 = douts31[26];
    unsigned r2305 = douts31[27];
    unsigned r2306 = douts31[28];
    unsigned r2307 = douts31[29];
    unsigned r2308 = douts31[30];
    unsigned r2309 = douts31[31];
    unsigned r2310 = douts31[32];
    unsigned r2311 = douts31[33];
    unsigned r2312 = douts31[34];
    unsigned r2313 = douts31[35];
    unsigned r2314 = douts31[36];
    unsigned r2315 = douts31[37];
    unsigned r2316 = douts31[38];
    unsigned r2317 = douts31[39];
    unsigned r2318 = douts31[40];
    unsigned r2319 = douts31[41];
    const unsigned dargs32[42] = { r268, r7, r2280, r2281, r2282, r2283, r2284, r2285, r2286, r2287, r2288, r2289, r2290, r2291, r2292, r2293, r2294, r2295, r2296, r2297, r2298, r2299, r2300, r2301, r2302, r2303, r2304, r2305, r2306, r2307, r2308, r2309, r2310, r2311, r2312, r2313, r2314, r2315, r2316, r2317, r2318, r2319 };
    unsigned douts32[42];
    sub_words[469u * row_count + row] = r7;
    sub_words[470u * row_count + row] = r2280;
    sub_words[471u * row_count + row] = r2281;
    sub_words[472u * row_count + row] = r2282;
    sub_words[473u * row_count + row] = r2283;
    sub_words[474u * row_count + row] = r2284;
    sub_words[475u * row_count + row] = r2285;
    sub_words[476u * row_count + row] = r2286;
    sub_words[477u * row_count + row] = r2287;
    sub_words[478u * row_count + row] = r2288;
    sub_words[479u * row_count + row] = r2289;
    sub_words[480u * row_count + row] = r2290;
    sub_words[481u * row_count + row] = r2291;
    sub_words[482u * row_count + row] = r2292;
    sub_words[483u * row_count + row] = r2293;
    sub_words[484u * row_count + row] = r2294;
    sub_words[485u * row_count + row] = r2295;
    sub_words[486u * row_count + row] = r2296;
    sub_words[487u * row_count + row] = r2297;
    sub_words[488u * row_count + row] = r2298;
    sub_words[489u * row_count + row] = r2299;
    sub_words[490u * row_count + row] = r2300;
    sub_words[491u * row_count + row] = r2301;
    sub_words[492u * row_count + row] = r2302;
    sub_words[493u * row_count + row] = r2303;
    sub_words[494u * row_count + row] = r2304;
    sub_words[495u * row_count + row] = r2305;
    sub_words[496u * row_count + row] = r2306;
    sub_words[497u * row_count + row] = r2307;
    sub_words[498u * row_count + row] = r2308;
    sub_words[499u * row_count + row] = r2309;
    sub_words[500u * row_count + row] = r2310;
    sub_words[501u * row_count + row] = r2311;
    sub_words[502u * row_count + row] = r2312;
    sub_words[503u * row_count + row] = r2313;
    sub_words[504u * row_count + row] = r2314;
    sub_words[505u * row_count + row] = r2315;
    sub_words[506u * row_count + row] = r2316;
    sub_words[507u * row_count + row] = r2317;
    sub_words[508u * row_count + row] = r2318;
    sub_words[509u * row_count + row] = r2319;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs32, douts32);
    unsigned r2320 = douts32[0];
    unsigned r2321 = douts32[1];
    unsigned r2322 = douts32[2];
    unsigned r2323 = douts32[3];
    unsigned r2324 = douts32[4];
    unsigned r2325 = douts32[5];
    unsigned r2326 = douts32[6];
    unsigned r2327 = douts32[7];
    unsigned r2328 = douts32[8];
    unsigned r2329 = douts32[9];
    unsigned r2330 = douts32[10];
    unsigned r2331 = douts32[11];
    unsigned r2332 = douts32[12];
    unsigned r2333 = douts32[13];
    unsigned r2334 = douts32[14];
    unsigned r2335 = douts32[15];
    unsigned r2336 = douts32[16];
    unsigned r2337 = douts32[17];
    unsigned r2338 = douts32[18];
    unsigned r2339 = douts32[19];
    unsigned r2340 = douts32[20];
    unsigned r2341 = douts32[21];
    unsigned r2342 = douts32[22];
    unsigned r2343 = douts32[23];
    unsigned r2344 = douts32[24];
    unsigned r2345 = douts32[25];
    unsigned r2346 = douts32[26];
    unsigned r2347 = douts32[27];
    unsigned r2348 = douts32[28];
    unsigned r2349 = douts32[29];
    unsigned r2350 = douts32[30];
    unsigned r2351 = douts32[31];
    unsigned r2352 = douts32[32];
    unsigned r2353 = douts32[33];
    unsigned r2354 = douts32[34];
    unsigned r2355 = douts32[35];
    unsigned r2356 = douts32[36];
    unsigned r2357 = douts32[37];
    unsigned r2358 = douts32[38];
    unsigned r2359 = douts32[39];
    unsigned r2360 = douts32[40];
    unsigned r2361 = douts32[41];
    const unsigned dargs33[42] = { r268, r8, r2322, r2323, r2324, r2325, r2326, r2327, r2328, r2329, r2330, r2331, r2332, r2333, r2334, r2335, r2336, r2337, r2338, r2339, r2340, r2341, r2342, r2343, r2344, r2345, r2346, r2347, r2348, r2349, r2350, r2351, r2352, r2353, r2354, r2355, r2356, r2357, r2358, r2359, r2360, r2361 };
    unsigned douts33[42];
    sub_words[511u * row_count + row] = r8;
    sub_words[512u * row_count + row] = r2322;
    sub_words[513u * row_count + row] = r2323;
    sub_words[514u * row_count + row] = r2324;
    sub_words[515u * row_count + row] = r2325;
    sub_words[516u * row_count + row] = r2326;
    sub_words[517u * row_count + row] = r2327;
    sub_words[518u * row_count + row] = r2328;
    sub_words[519u * row_count + row] = r2329;
    sub_words[520u * row_count + row] = r2330;
    sub_words[521u * row_count + row] = r2331;
    sub_words[522u * row_count + row] = r2332;
    sub_words[523u * row_count + row] = r2333;
    sub_words[524u * row_count + row] = r2334;
    sub_words[525u * row_count + row] = r2335;
    sub_words[526u * row_count + row] = r2336;
    sub_words[527u * row_count + row] = r2337;
    sub_words[528u * row_count + row] = r2338;
    sub_words[529u * row_count + row] = r2339;
    sub_words[530u * row_count + row] = r2340;
    sub_words[531u * row_count + row] = r2341;
    sub_words[532u * row_count + row] = r2342;
    sub_words[533u * row_count + row] = r2343;
    sub_words[534u * row_count + row] = r2344;
    sub_words[535u * row_count + row] = r2345;
    sub_words[536u * row_count + row] = r2346;
    sub_words[537u * row_count + row] = r2347;
    sub_words[538u * row_count + row] = r2348;
    sub_words[539u * row_count + row] = r2349;
    sub_words[540u * row_count + row] = r2350;
    sub_words[541u * row_count + row] = r2351;
    sub_words[542u * row_count + row] = r2352;
    sub_words[543u * row_count + row] = r2353;
    sub_words[544u * row_count + row] = r2354;
    sub_words[545u * row_count + row] = r2355;
    sub_words[546u * row_count + row] = r2356;
    sub_words[547u * row_count + row] = r2357;
    sub_words[548u * row_count + row] = r2358;
    sub_words[549u * row_count + row] = r2359;
    sub_words[550u * row_count + row] = r2360;
    sub_words[551u * row_count + row] = r2361;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs33, douts33);
    unsigned r2362 = douts33[0];
    unsigned r2363 = douts33[1];
    unsigned r2364 = douts33[2];
    unsigned r2365 = douts33[3];
    unsigned r2366 = douts33[4];
    unsigned r2367 = douts33[5];
    unsigned r2368 = douts33[6];
    unsigned r2369 = douts33[7];
    unsigned r2370 = douts33[8];
    unsigned r2371 = douts33[9];
    unsigned r2372 = douts33[10];
    unsigned r2373 = douts33[11];
    unsigned r2374 = douts33[12];
    unsigned r2375 = douts33[13];
    unsigned r2376 = douts33[14];
    unsigned r2377 = douts33[15];
    unsigned r2378 = douts33[16];
    unsigned r2379 = douts33[17];
    unsigned r2380 = douts33[18];
    unsigned r2381 = douts33[19];
    unsigned r2382 = douts33[20];
    unsigned r2383 = douts33[21];
    unsigned r2384 = douts33[22];
    unsigned r2385 = douts33[23];
    unsigned r2386 = douts33[24];
    unsigned r2387 = douts33[25];
    unsigned r2388 = douts33[26];
    unsigned r2389 = douts33[27];
    unsigned r2390 = douts33[28];
    unsigned r2391 = douts33[29];
    unsigned r2392 = douts33[30];
    unsigned r2393 = douts33[31];
    unsigned r2394 = douts33[32];
    unsigned r2395 = douts33[33];
    unsigned r2396 = douts33[34];
    unsigned r2397 = douts33[35];
    unsigned r2398 = douts33[36];
    unsigned r2399 = douts33[37];
    unsigned r2400 = douts33[38];
    unsigned r2401 = douts33[39];
    unsigned r2402 = douts33[40];
    unsigned r2403 = douts33[41];
    const unsigned dargs34[42] = { r268, r9, r2364, r2365, r2366, r2367, r2368, r2369, r2370, r2371, r2372, r2373, r2374, r2375, r2376, r2377, r2378, r2379, r2380, r2381, r2382, r2383, r2384, r2385, r2386, r2387, r2388, r2389, r2390, r2391, r2392, r2393, r2394, r2395, r2396, r2397, r2398, r2399, r2400, r2401, r2402, r2403 };
    unsigned douts34[42];
    sub_words[553u * row_count + row] = r9;
    sub_words[554u * row_count + row] = r2364;
    sub_words[555u * row_count + row] = r2365;
    sub_words[556u * row_count + row] = r2366;
    sub_words[557u * row_count + row] = r2367;
    sub_words[558u * row_count + row] = r2368;
    sub_words[559u * row_count + row] = r2369;
    sub_words[560u * row_count + row] = r2370;
    sub_words[561u * row_count + row] = r2371;
    sub_words[562u * row_count + row] = r2372;
    sub_words[563u * row_count + row] = r2373;
    sub_words[564u * row_count + row] = r2374;
    sub_words[565u * row_count + row] = r2375;
    sub_words[566u * row_count + row] = r2376;
    sub_words[567u * row_count + row] = r2377;
    sub_words[568u * row_count + row] = r2378;
    sub_words[569u * row_count + row] = r2379;
    sub_words[570u * row_count + row] = r2380;
    sub_words[571u * row_count + row] = r2381;
    sub_words[572u * row_count + row] = r2382;
    sub_words[573u * row_count + row] = r2383;
    sub_words[574u * row_count + row] = r2384;
    sub_words[575u * row_count + row] = r2385;
    sub_words[576u * row_count + row] = r2386;
    sub_words[577u * row_count + row] = r2387;
    sub_words[578u * row_count + row] = r2388;
    sub_words[579u * row_count + row] = r2389;
    sub_words[580u * row_count + row] = r2390;
    sub_words[581u * row_count + row] = r2391;
    sub_words[582u * row_count + row] = r2392;
    sub_words[583u * row_count + row] = r2393;
    sub_words[584u * row_count + row] = r2394;
    sub_words[585u * row_count + row] = r2395;
    sub_words[586u * row_count + row] = r2396;
    sub_words[587u * row_count + row] = r2397;
    sub_words[588u * row_count + row] = r2398;
    sub_words[589u * row_count + row] = r2399;
    sub_words[590u * row_count + row] = r2400;
    sub_words[591u * row_count + row] = r2401;
    sub_words[592u * row_count + row] = r2402;
    sub_words[593u * row_count + row] = r2403;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs34, douts34);
    unsigned r2404 = douts34[0];
    unsigned r2405 = douts34[1];
    unsigned r2406 = douts34[2];
    unsigned r2407 = douts34[3];
    unsigned r2408 = douts34[4];
    unsigned r2409 = douts34[5];
    unsigned r2410 = douts34[6];
    unsigned r2411 = douts34[7];
    unsigned r2412 = douts34[8];
    unsigned r2413 = douts34[9];
    unsigned r2414 = douts34[10];
    unsigned r2415 = douts34[11];
    unsigned r2416 = douts34[12];
    unsigned r2417 = douts34[13];
    unsigned r2418 = douts34[14];
    unsigned r2419 = douts34[15];
    unsigned r2420 = douts34[16];
    unsigned r2421 = douts34[17];
    unsigned r2422 = douts34[18];
    unsigned r2423 = douts34[19];
    unsigned r2424 = douts34[20];
    unsigned r2425 = douts34[21];
    unsigned r2426 = douts34[22];
    unsigned r2427 = douts34[23];
    unsigned r2428 = douts34[24];
    unsigned r2429 = douts34[25];
    unsigned r2430 = douts34[26];
    unsigned r2431 = douts34[27];
    unsigned r2432 = douts34[28];
    unsigned r2433 = douts34[29];
    unsigned r2434 = douts34[30];
    unsigned r2435 = douts34[31];
    unsigned r2436 = douts34[32];
    unsigned r2437 = douts34[33];
    unsigned r2438 = douts34[34];
    unsigned r2439 = douts34[35];
    unsigned r2440 = douts34[36];
    unsigned r2441 = douts34[37];
    unsigned r2442 = douts34[38];
    unsigned r2443 = douts34[39];
    unsigned r2444 = douts34[40];
    unsigned r2445 = douts34[41];
    const unsigned dargs35[42] = { r268, r10, r2406, r2407, r2408, r2409, r2410, r2411, r2412, r2413, r2414, r2415, r2416, r2417, r2418, r2419, r2420, r2421, r2422, r2423, r2424, r2425, r2426, r2427, r2428, r2429, r2430, r2431, r2432, r2433, r2434, r2435, r2436, r2437, r2438, r2439, r2440, r2441, r2442, r2443, r2444, r2445 };
    unsigned douts35[42];
    sub_words[595u * row_count + row] = r10;
    sub_words[596u * row_count + row] = r2406;
    sub_words[597u * row_count + row] = r2407;
    sub_words[598u * row_count + row] = r2408;
    sub_words[599u * row_count + row] = r2409;
    sub_words[600u * row_count + row] = r2410;
    sub_words[601u * row_count + row] = r2411;
    sub_words[602u * row_count + row] = r2412;
    sub_words[603u * row_count + row] = r2413;
    sub_words[604u * row_count + row] = r2414;
    sub_words[605u * row_count + row] = r2415;
    sub_words[606u * row_count + row] = r2416;
    sub_words[607u * row_count + row] = r2417;
    sub_words[608u * row_count + row] = r2418;
    sub_words[609u * row_count + row] = r2419;
    sub_words[610u * row_count + row] = r2420;
    sub_words[611u * row_count + row] = r2421;
    sub_words[612u * row_count + row] = r2422;
    sub_words[613u * row_count + row] = r2423;
    sub_words[614u * row_count + row] = r2424;
    sub_words[615u * row_count + row] = r2425;
    sub_words[616u * row_count + row] = r2426;
    sub_words[617u * row_count + row] = r2427;
    sub_words[618u * row_count + row] = r2428;
    sub_words[619u * row_count + row] = r2429;
    sub_words[620u * row_count + row] = r2430;
    sub_words[621u * row_count + row] = r2431;
    sub_words[622u * row_count + row] = r2432;
    sub_words[623u * row_count + row] = r2433;
    sub_words[624u * row_count + row] = r2434;
    sub_words[625u * row_count + row] = r2435;
    sub_words[626u * row_count + row] = r2436;
    sub_words[627u * row_count + row] = r2437;
    sub_words[628u * row_count + row] = r2438;
    sub_words[629u * row_count + row] = r2439;
    sub_words[630u * row_count + row] = r2440;
    sub_words[631u * row_count + row] = r2441;
    sub_words[632u * row_count + row] = r2442;
    sub_words[633u * row_count + row] = r2443;
    sub_words[634u * row_count + row] = r2444;
    sub_words[635u * row_count + row] = r2445;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs35, douts35);
    unsigned r2446 = douts35[0];
    unsigned r2447 = douts35[1];
    unsigned r2448 = douts35[2];
    unsigned r2449 = douts35[3];
    unsigned r2450 = douts35[4];
    unsigned r2451 = douts35[5];
    unsigned r2452 = douts35[6];
    unsigned r2453 = douts35[7];
    unsigned r2454 = douts35[8];
    unsigned r2455 = douts35[9];
    unsigned r2456 = douts35[10];
    unsigned r2457 = douts35[11];
    unsigned r2458 = douts35[12];
    unsigned r2459 = douts35[13];
    unsigned r2460 = douts35[14];
    unsigned r2461 = douts35[15];
    unsigned r2462 = douts35[16];
    unsigned r2463 = douts35[17];
    unsigned r2464 = douts35[18];
    unsigned r2465 = douts35[19];
    unsigned r2466 = douts35[20];
    unsigned r2467 = douts35[21];
    unsigned r2468 = douts35[22];
    unsigned r2469 = douts35[23];
    unsigned r2470 = douts35[24];
    unsigned r2471 = douts35[25];
    unsigned r2472 = douts35[26];
    unsigned r2473 = douts35[27];
    unsigned r2474 = douts35[28];
    unsigned r2475 = douts35[29];
    unsigned r2476 = douts35[30];
    unsigned r2477 = douts35[31];
    unsigned r2478 = douts35[32];
    unsigned r2479 = douts35[33];
    unsigned r2480 = douts35[34];
    unsigned r2481 = douts35[35];
    unsigned r2482 = douts35[36];
    unsigned r2483 = douts35[37];
    unsigned r2484 = douts35[38];
    unsigned r2485 = douts35[39];
    unsigned r2486 = douts35[40];
    unsigned r2487 = douts35[41];
    const unsigned dargs36[42] = { r268, r11, r2448, r2449, r2450, r2451, r2452, r2453, r2454, r2455, r2456, r2457, r2458, r2459, r2460, r2461, r2462, r2463, r2464, r2465, r2466, r2467, r2468, r2469, r2470, r2471, r2472, r2473, r2474, r2475, r2476, r2477, r2478, r2479, r2480, r2481, r2482, r2483, r2484, r2485, r2486, r2487 };
    unsigned douts36[42];
    sub_words[637u * row_count + row] = r11;
    sub_words[638u * row_count + row] = r2448;
    sub_words[639u * row_count + row] = r2449;
    sub_words[640u * row_count + row] = r2450;
    sub_words[641u * row_count + row] = r2451;
    sub_words[642u * row_count + row] = r2452;
    sub_words[643u * row_count + row] = r2453;
    sub_words[644u * row_count + row] = r2454;
    sub_words[645u * row_count + row] = r2455;
    sub_words[646u * row_count + row] = r2456;
    sub_words[647u * row_count + row] = r2457;
    sub_words[648u * row_count + row] = r2458;
    sub_words[649u * row_count + row] = r2459;
    sub_words[650u * row_count + row] = r2460;
    sub_words[651u * row_count + row] = r2461;
    sub_words[652u * row_count + row] = r2462;
    sub_words[653u * row_count + row] = r2463;
    sub_words[654u * row_count + row] = r2464;
    sub_words[655u * row_count + row] = r2465;
    sub_words[656u * row_count + row] = r2466;
    sub_words[657u * row_count + row] = r2467;
    sub_words[658u * row_count + row] = r2468;
    sub_words[659u * row_count + row] = r2469;
    sub_words[660u * row_count + row] = r2470;
    sub_words[661u * row_count + row] = r2471;
    sub_words[662u * row_count + row] = r2472;
    sub_words[663u * row_count + row] = r2473;
    sub_words[664u * row_count + row] = r2474;
    sub_words[665u * row_count + row] = r2475;
    sub_words[666u * row_count + row] = r2476;
    sub_words[667u * row_count + row] = r2477;
    sub_words[668u * row_count + row] = r2478;
    sub_words[669u * row_count + row] = r2479;
    sub_words[670u * row_count + row] = r2480;
    sub_words[671u * row_count + row] = r2481;
    sub_words[672u * row_count + row] = r2482;
    sub_words[673u * row_count + row] = r2483;
    sub_words[674u * row_count + row] = r2484;
    sub_words[675u * row_count + row] = r2485;
    sub_words[676u * row_count + row] = r2486;
    sub_words[677u * row_count + row] = r2487;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs36, douts36);
    unsigned r2488 = douts36[0];
    unsigned r2489 = douts36[1];
    unsigned r2490 = douts36[2];
    unsigned r2491 = douts36[3];
    unsigned r2492 = douts36[4];
    unsigned r2493 = douts36[5];
    unsigned r2494 = douts36[6];
    unsigned r2495 = douts36[7];
    unsigned r2496 = douts36[8];
    unsigned r2497 = douts36[9];
    unsigned r2498 = douts36[10];
    unsigned r2499 = douts36[11];
    unsigned r2500 = douts36[12];
    unsigned r2501 = douts36[13];
    unsigned r2502 = douts36[14];
    unsigned r2503 = douts36[15];
    unsigned r2504 = douts36[16];
    unsigned r2505 = douts36[17];
    unsigned r2506 = douts36[18];
    unsigned r2507 = douts36[19];
    unsigned r2508 = douts36[20];
    unsigned r2509 = douts36[21];
    unsigned r2510 = douts36[22];
    unsigned r2511 = douts36[23];
    unsigned r2512 = douts36[24];
    unsigned r2513 = douts36[25];
    unsigned r2514 = douts36[26];
    unsigned r2515 = douts36[27];
    unsigned r2516 = douts36[28];
    unsigned r2517 = douts36[29];
    unsigned r2518 = douts36[30];
    unsigned r2519 = douts36[31];
    unsigned r2520 = douts36[32];
    unsigned r2521 = douts36[33];
    unsigned r2522 = douts36[34];
    unsigned r2523 = douts36[35];
    unsigned r2524 = douts36[36];
    unsigned r2525 = douts36[37];
    unsigned r2526 = douts36[38];
    unsigned r2527 = douts36[39];
    unsigned r2528 = douts36[40];
    unsigned r2529 = douts36[41];
    const unsigned dargs37[42] = { r268, r12, r2490, r2491, r2492, r2493, r2494, r2495, r2496, r2497, r2498, r2499, r2500, r2501, r2502, r2503, r2504, r2505, r2506, r2507, r2508, r2509, r2510, r2511, r2512, r2513, r2514, r2515, r2516, r2517, r2518, r2519, r2520, r2521, r2522, r2523, r2524, r2525, r2526, r2527, r2528, r2529 };
    unsigned douts37[42];
    sub_words[679u * row_count + row] = r12;
    sub_words[680u * row_count + row] = r2490;
    sub_words[681u * row_count + row] = r2491;
    sub_words[682u * row_count + row] = r2492;
    sub_words[683u * row_count + row] = r2493;
    sub_words[684u * row_count + row] = r2494;
    sub_words[685u * row_count + row] = r2495;
    sub_words[686u * row_count + row] = r2496;
    sub_words[687u * row_count + row] = r2497;
    sub_words[688u * row_count + row] = r2498;
    sub_words[689u * row_count + row] = r2499;
    sub_words[690u * row_count + row] = r2500;
    sub_words[691u * row_count + row] = r2501;
    sub_words[692u * row_count + row] = r2502;
    sub_words[693u * row_count + row] = r2503;
    sub_words[694u * row_count + row] = r2504;
    sub_words[695u * row_count + row] = r2505;
    sub_words[696u * row_count + row] = r2506;
    sub_words[697u * row_count + row] = r2507;
    sub_words[698u * row_count + row] = r2508;
    sub_words[699u * row_count + row] = r2509;
    sub_words[700u * row_count + row] = r2510;
    sub_words[701u * row_count + row] = r2511;
    sub_words[702u * row_count + row] = r2512;
    sub_words[703u * row_count + row] = r2513;
    sub_words[704u * row_count + row] = r2514;
    sub_words[705u * row_count + row] = r2515;
    sub_words[706u * row_count + row] = r2516;
    sub_words[707u * row_count + row] = r2517;
    sub_words[708u * row_count + row] = r2518;
    sub_words[709u * row_count + row] = r2519;
    sub_words[710u * row_count + row] = r2520;
    sub_words[711u * row_count + row] = r2521;
    sub_words[712u * row_count + row] = r2522;
    sub_words[713u * row_count + row] = r2523;
    sub_words[714u * row_count + row] = r2524;
    sub_words[715u * row_count + row] = r2525;
    sub_words[716u * row_count + row] = r2526;
    sub_words[717u * row_count + row] = r2527;
    sub_words[718u * row_count + row] = r2528;
    sub_words[719u * row_count + row] = r2529;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs37, douts37);
    unsigned r2530 = douts37[0];
    unsigned r2531 = douts37[1];
    unsigned r2532 = douts37[2];
    unsigned r2533 = douts37[3];
    unsigned r2534 = douts37[4];
    unsigned r2535 = douts37[5];
    unsigned r2536 = douts37[6];
    unsigned r2537 = douts37[7];
    unsigned r2538 = douts37[8];
    unsigned r2539 = douts37[9];
    unsigned r2540 = douts37[10];
    unsigned r2541 = douts37[11];
    unsigned r2542 = douts37[12];
    unsigned r2543 = douts37[13];
    unsigned r2544 = douts37[14];
    unsigned r2545 = douts37[15];
    unsigned r2546 = douts37[16];
    unsigned r2547 = douts37[17];
    unsigned r2548 = douts37[18];
    unsigned r2549 = douts37[19];
    unsigned r2550 = douts37[20];
    unsigned r2551 = douts37[21];
    unsigned r2552 = douts37[22];
    unsigned r2553 = douts37[23];
    unsigned r2554 = douts37[24];
    unsigned r2555 = douts37[25];
    unsigned r2556 = douts37[26];
    unsigned r2557 = douts37[27];
    unsigned r2558 = douts37[28];
    unsigned r2559 = douts37[29];
    unsigned r2560 = douts37[30];
    unsigned r2561 = douts37[31];
    unsigned r2562 = douts37[32];
    unsigned r2563 = douts37[33];
    unsigned r2564 = douts37[34];
    unsigned r2565 = douts37[35];
    unsigned r2566 = douts37[36];
    unsigned r2567 = douts37[37];
    unsigned r2568 = douts37[38];
    unsigned r2569 = douts37[39];
    unsigned r2570 = douts37[40];
    unsigned r2571 = douts37[41];
    const unsigned dargs38[42] = { r268, r13, r2532, r2533, r2534, r2535, r2536, r2537, r2538, r2539, r2540, r2541, r2542, r2543, r2544, r2545, r2546, r2547, r2548, r2549, r2550, r2551, r2552, r2553, r2554, r2555, r2556, r2557, r2558, r2559, r2560, r2561, r2562, r2563, r2564, r2565, r2566, r2567, r2568, r2569, r2570, r2571 };
    unsigned douts38[42];
    sub_words[721u * row_count + row] = r13;
    sub_words[722u * row_count + row] = r2532;
    sub_words[723u * row_count + row] = r2533;
    sub_words[724u * row_count + row] = r2534;
    sub_words[725u * row_count + row] = r2535;
    sub_words[726u * row_count + row] = r2536;
    sub_words[727u * row_count + row] = r2537;
    sub_words[728u * row_count + row] = r2538;
    sub_words[729u * row_count + row] = r2539;
    sub_words[730u * row_count + row] = r2540;
    sub_words[731u * row_count + row] = r2541;
    sub_words[732u * row_count + row] = r2542;
    sub_words[733u * row_count + row] = r2543;
    sub_words[734u * row_count + row] = r2544;
    sub_words[735u * row_count + row] = r2545;
    sub_words[736u * row_count + row] = r2546;
    sub_words[737u * row_count + row] = r2547;
    sub_words[738u * row_count + row] = r2548;
    sub_words[739u * row_count + row] = r2549;
    sub_words[740u * row_count + row] = r2550;
    sub_words[741u * row_count + row] = r2551;
    sub_words[742u * row_count + row] = r2552;
    sub_words[743u * row_count + row] = r2553;
    sub_words[744u * row_count + row] = r2554;
    sub_words[745u * row_count + row] = r2555;
    sub_words[746u * row_count + row] = r2556;
    sub_words[747u * row_count + row] = r2557;
    sub_words[748u * row_count + row] = r2558;
    sub_words[749u * row_count + row] = r2559;
    sub_words[750u * row_count + row] = r2560;
    sub_words[751u * row_count + row] = r2561;
    sub_words[752u * row_count + row] = r2562;
    sub_words[753u * row_count + row] = r2563;
    sub_words[754u * row_count + row] = r2564;
    sub_words[755u * row_count + row] = r2565;
    sub_words[756u * row_count + row] = r2566;
    sub_words[757u * row_count + row] = r2567;
    sub_words[758u * row_count + row] = r2568;
    sub_words[759u * row_count + row] = r2569;
    sub_words[760u * row_count + row] = r2570;
    sub_words[761u * row_count + row] = r2571;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs38, douts38);
    unsigned r2572 = douts38[0];
    unsigned r2573 = douts38[1];
    unsigned r2574 = douts38[2];
    unsigned r2575 = douts38[3];
    unsigned r2576 = douts38[4];
    unsigned r2577 = douts38[5];
    unsigned r2578 = douts38[6];
    unsigned r2579 = douts38[7];
    unsigned r2580 = douts38[8];
    unsigned r2581 = douts38[9];
    unsigned r2582 = douts38[10];
    unsigned r2583 = douts38[11];
    unsigned r2584 = douts38[12];
    unsigned r2585 = douts38[13];
    unsigned r2586 = douts38[14];
    unsigned r2587 = douts38[15];
    unsigned r2588 = douts38[16];
    unsigned r2589 = douts38[17];
    unsigned r2590 = douts38[18];
    unsigned r2591 = douts38[19];
    unsigned r2592 = douts38[20];
    unsigned r2593 = douts38[21];
    unsigned r2594 = douts38[22];
    unsigned r2595 = douts38[23];
    unsigned r2596 = douts38[24];
    unsigned r2597 = douts38[25];
    unsigned r2598 = douts38[26];
    unsigned r2599 = douts38[27];
    unsigned r2600 = douts38[28];
    unsigned r2601 = douts38[29];
    unsigned r2602 = douts38[30];
    unsigned r2603 = douts38[31];
    unsigned r2604 = douts38[32];
    unsigned r2605 = douts38[33];
    unsigned r2606 = douts38[34];
    unsigned r2607 = douts38[35];
    unsigned r2608 = douts38[36];
    unsigned r2609 = douts38[37];
    unsigned r2610 = douts38[38];
    unsigned r2611 = douts38[39];
    unsigned r2612 = douts38[40];
    unsigned r2613 = douts38[41];
    const unsigned dargs39[42] = { r268, r14, r2574, r2575, r2576, r2577, r2578, r2579, r2580, r2581, r2582, r2583, r2584, r2585, r2586, r2587, r2588, r2589, r2590, r2591, r2592, r2593, r2594, r2595, r2596, r2597, r2598, r2599, r2600, r2601, r2602, r2603, r2604, r2605, r2606, r2607, r2608, r2609, r2610, r2611, r2612, r2613 };
    unsigned douts39[42];
    sub_words[763u * row_count + row] = r14;
    sub_words[764u * row_count + row] = r2574;
    sub_words[765u * row_count + row] = r2575;
    sub_words[766u * row_count + row] = r2576;
    sub_words[767u * row_count + row] = r2577;
    sub_words[768u * row_count + row] = r2578;
    sub_words[769u * row_count + row] = r2579;
    sub_words[770u * row_count + row] = r2580;
    sub_words[771u * row_count + row] = r2581;
    sub_words[772u * row_count + row] = r2582;
    sub_words[773u * row_count + row] = r2583;
    sub_words[774u * row_count + row] = r2584;
    sub_words[775u * row_count + row] = r2585;
    sub_words[776u * row_count + row] = r2586;
    sub_words[777u * row_count + row] = r2587;
    sub_words[778u * row_count + row] = r2588;
    sub_words[779u * row_count + row] = r2589;
    sub_words[780u * row_count + row] = r2590;
    sub_words[781u * row_count + row] = r2591;
    sub_words[782u * row_count + row] = r2592;
    sub_words[783u * row_count + row] = r2593;
    sub_words[784u * row_count + row] = r2594;
    sub_words[785u * row_count + row] = r2595;
    sub_words[786u * row_count + row] = r2596;
    sub_words[787u * row_count + row] = r2597;
    sub_words[788u * row_count + row] = r2598;
    sub_words[789u * row_count + row] = r2599;
    sub_words[790u * row_count + row] = r2600;
    sub_words[791u * row_count + row] = r2601;
    sub_words[792u * row_count + row] = r2602;
    sub_words[793u * row_count + row] = r2603;
    sub_words[794u * row_count + row] = r2604;
    sub_words[795u * row_count + row] = r2605;
    sub_words[796u * row_count + row] = r2606;
    sub_words[797u * row_count + row] = r2607;
    sub_words[798u * row_count + row] = r2608;
    sub_words[799u * row_count + row] = r2609;
    sub_words[800u * row_count + row] = r2610;
    sub_words[801u * row_count + row] = r2611;
    sub_words[802u * row_count + row] = r2612;
    sub_words[803u * row_count + row] = r2613;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs39, douts39);
    unsigned r2614 = douts39[0];
    unsigned r2615 = douts39[1];
    unsigned r2616 = douts39[2];
    unsigned r2617 = douts39[3];
    unsigned r2618 = douts39[4];
    unsigned r2619 = douts39[5];
    unsigned r2620 = douts39[6];
    unsigned r2621 = douts39[7];
    unsigned r2622 = douts39[8];
    unsigned r2623 = douts39[9];
    unsigned r2624 = douts39[10];
    unsigned r2625 = douts39[11];
    unsigned r2626 = douts39[12];
    unsigned r2627 = douts39[13];
    unsigned r2628 = douts39[14];
    unsigned r2629 = douts39[15];
    unsigned r2630 = douts39[16];
    unsigned r2631 = douts39[17];
    unsigned r2632 = douts39[18];
    unsigned r2633 = douts39[19];
    unsigned r2634 = douts39[20];
    unsigned r2635 = douts39[21];
    unsigned r2636 = douts39[22];
    unsigned r2637 = douts39[23];
    unsigned r2638 = douts39[24];
    unsigned r2639 = douts39[25];
    unsigned r2640 = douts39[26];
    unsigned r2641 = douts39[27];
    unsigned r2642 = douts39[28];
    unsigned r2643 = douts39[29];
    unsigned r2644 = douts39[30];
    unsigned r2645 = douts39[31];
    unsigned r2646 = douts39[32];
    unsigned r2647 = douts39[33];
    unsigned r2648 = douts39[34];
    unsigned r2649 = douts39[35];
    unsigned r2650 = douts39[36];
    unsigned r2651 = douts39[37];
    unsigned r2652 = douts39[38];
    unsigned r2653 = douts39[39];
    unsigned r2654 = douts39[40];
    unsigned r2655 = douts39[41];
    const unsigned dargs40[42] = { r268, r15, r2616, r2617, r2618, r2619, r2620, r2621, r2622, r2623, r2624, r2625, r2626, r2627, r2628, r2629, r2630, r2631, r2632, r2633, r2634, r2635, r2636, r2637, r2638, r2639, r2640, r2641, r2642, r2643, r2644, r2645, r2646, r2647, r2648, r2649, r2650, r2651, r2652, r2653, r2654, r2655 };
    unsigned douts40[42];
    sub_words[805u * row_count + row] = r15;
    sub_words[806u * row_count + row] = r2616;
    sub_words[807u * row_count + row] = r2617;
    sub_words[808u * row_count + row] = r2618;
    sub_words[809u * row_count + row] = r2619;
    sub_words[810u * row_count + row] = r2620;
    sub_words[811u * row_count + row] = r2621;
    sub_words[812u * row_count + row] = r2622;
    sub_words[813u * row_count + row] = r2623;
    sub_words[814u * row_count + row] = r2624;
    sub_words[815u * row_count + row] = r2625;
    sub_words[816u * row_count + row] = r2626;
    sub_words[817u * row_count + row] = r2627;
    sub_words[818u * row_count + row] = r2628;
    sub_words[819u * row_count + row] = r2629;
    sub_words[820u * row_count + row] = r2630;
    sub_words[821u * row_count + row] = r2631;
    sub_words[822u * row_count + row] = r2632;
    sub_words[823u * row_count + row] = r2633;
    sub_words[824u * row_count + row] = r2634;
    sub_words[825u * row_count + row] = r2635;
    sub_words[826u * row_count + row] = r2636;
    sub_words[827u * row_count + row] = r2637;
    sub_words[828u * row_count + row] = r2638;
    sub_words[829u * row_count + row] = r2639;
    sub_words[830u * row_count + row] = r2640;
    sub_words[831u * row_count + row] = r2641;
    sub_words[832u * row_count + row] = r2642;
    sub_words[833u * row_count + row] = r2643;
    sub_words[834u * row_count + row] = r2644;
    sub_words[835u * row_count + row] = r2645;
    sub_words[836u * row_count + row] = r2646;
    sub_words[837u * row_count + row] = r2647;
    sub_words[838u * row_count + row] = r2648;
    sub_words[839u * row_count + row] = r2649;
    sub_words[840u * row_count + row] = r2650;
    sub_words[841u * row_count + row] = r2651;
    sub_words[842u * row_count + row] = r2652;
    sub_words[843u * row_count + row] = r2653;
    sub_words[844u * row_count + row] = r2654;
    sub_words[845u * row_count + row] = r2655;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs40, douts40);
    unsigned r2656 = douts40[0];
    unsigned r2657 = douts40[1];
    unsigned r2658 = douts40[2];
    unsigned r2659 = douts40[3];
    unsigned r2660 = douts40[4];
    unsigned r2661 = douts40[5];
    unsigned r2662 = douts40[6];
    unsigned r2663 = douts40[7];
    unsigned r2664 = douts40[8];
    unsigned r2665 = douts40[9];
    unsigned r2666 = douts40[10];
    unsigned r2667 = douts40[11];
    unsigned r2668 = douts40[12];
    unsigned r2669 = douts40[13];
    unsigned r2670 = douts40[14];
    unsigned r2671 = douts40[15];
    unsigned r2672 = douts40[16];
    unsigned r2673 = douts40[17];
    unsigned r2674 = douts40[18];
    unsigned r2675 = douts40[19];
    unsigned r2676 = douts40[20];
    unsigned r2677 = douts40[21];
    unsigned r2678 = douts40[22];
    unsigned r2679 = douts40[23];
    unsigned r2680 = douts40[24];
    unsigned r2681 = douts40[25];
    unsigned r2682 = douts40[26];
    unsigned r2683 = douts40[27];
    unsigned r2684 = douts40[28];
    unsigned r2685 = douts40[29];
    unsigned r2686 = douts40[30];
    unsigned r2687 = douts40[31];
    unsigned r2688 = douts40[32];
    unsigned r2689 = douts40[33];
    unsigned r2690 = douts40[34];
    unsigned r2691 = douts40[35];
    unsigned r2692 = douts40[36];
    unsigned r2693 = douts40[37];
    unsigned r2694 = douts40[38];
    unsigned r2695 = douts40[39];
    unsigned r2696 = douts40[40];
    unsigned r2697 = douts40[41];
    const unsigned dargs41[42] = { r268, r16, r2658, r2659, r2660, r2661, r2662, r2663, r2664, r2665, r2666, r2667, r2668, r2669, r2670, r2671, r2672, r2673, r2674, r2675, r2676, r2677, r2678, r2679, r2680, r2681, r2682, r2683, r2684, r2685, r2686, r2687, r2688, r2689, r2690, r2691, r2692, r2693, r2694, r2695, r2696, r2697 };
    unsigned douts41[42];
    sub_words[848u * row_count + row] = r2658;
    sub_words[849u * row_count + row] = r2659;
    sub_words[850u * row_count + row] = r2660;
    sub_words[851u * row_count + row] = r2661;
    sub_words[852u * row_count + row] = r2662;
    sub_words[853u * row_count + row] = r2663;
    sub_words[854u * row_count + row] = r2664;
    sub_words[855u * row_count + row] = r2665;
    sub_words[856u * row_count + row] = r2666;
    sub_words[857u * row_count + row] = r2667;
    sub_words[858u * row_count + row] = r2668;
    sub_words[859u * row_count + row] = r2669;
    sub_words[860u * row_count + row] = r2670;
    sub_words[861u * row_count + row] = r2671;
    sub_words[862u * row_count + row] = r2672;
    sub_words[863u * row_count + row] = r2673;
    sub_words[864u * row_count + row] = r2674;
    sub_words[865u * row_count + row] = r2675;
    sub_words[866u * row_count + row] = r2676;
    sub_words[867u * row_count + row] = r2677;
    sub_words[868u * row_count + row] = r2678;
    sub_words[869u * row_count + row] = r2679;
    sub_words[870u * row_count + row] = r2680;
    sub_words[871u * row_count + row] = r2681;
    sub_words[872u * row_count + row] = r2682;
    sub_words[873u * row_count + row] = r2683;
    sub_words[874u * row_count + row] = r2684;
    sub_words[875u * row_count + row] = r2685;
    sub_words[876u * row_count + row] = r2686;
    sub_words[877u * row_count + row] = r2687;
    sub_words[878u * row_count + row] = r2688;
    sub_words[879u * row_count + row] = r2689;
    sub_words[880u * row_count + row] = r2690;
    sub_words[881u * row_count + row] = r2691;
    sub_words[882u * row_count + row] = r2692;
    sub_words[883u * row_count + row] = r2693;
    sub_words[884u * row_count + row] = r2694;
    sub_words[885u * row_count + row] = r2695;
    sub_words[886u * row_count + row] = r2696;
    sub_words[887u * row_count + row] = r2697;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs41, douts41);
    unsigned r2698 = douts41[0];
    unsigned r2699 = douts41[1];
    unsigned r2700 = douts41[2];
    unsigned r2701 = douts41[3];
    unsigned r2702 = douts41[4];
    unsigned r2703 = douts41[5];
    unsigned r2704 = douts41[6];
    unsigned r2705 = douts41[7];
    unsigned r2706 = douts41[8];
    unsigned r2707 = douts41[9];
    unsigned r2708 = douts41[10];
    unsigned r2709 = douts41[11];
    unsigned r2710 = douts41[12];
    unsigned r2711 = douts41[13];
    unsigned r2712 = douts41[14];
    unsigned r2713 = douts41[15];
    unsigned r2714 = douts41[16];
    unsigned r2715 = douts41[17];
    unsigned r2716 = douts41[18];
    unsigned r2717 = douts41[19];
    unsigned r2718 = douts41[20];
    unsigned r2719 = douts41[21];
    unsigned r2720 = douts41[22];
    unsigned r2721 = douts41[23];
    unsigned r2722 = douts41[24];
    unsigned r2723 = douts41[25];
    unsigned r2724 = douts41[26];
    unsigned r2725 = douts41[27];
    unsigned r2726 = douts41[28];
    unsigned r2727 = douts41[29];
    unsigned r2728 = douts41[30];
    unsigned r2729 = douts41[31];
    unsigned r2730 = douts41[32];
    unsigned r2731 = douts41[33];
    unsigned r2732 = douts41[34];
    unsigned r2733 = douts41[35];
    unsigned r2734 = douts41[36];
    unsigned r2735 = douts41[37];
    unsigned r2736 = douts41[38];
    unsigned r2737 = douts41[39];
    unsigned r2738 = douts41[40];
    unsigned r2739 = douts41[41];
    const unsigned dargs42[42] = { r268, r17, r2700, r2701, r2702, r2703, r2704, r2705, r2706, r2707, r2708, r2709, r2710, r2711, r2712, r2713, r2714, r2715, r2716, r2717, r2718, r2719, r2720, r2721, r2722, r2723, r2724, r2725, r2726, r2727, r2728, r2729, r2730, r2731, r2732, r2733, r2734, r2735, r2736, r2737, r2738, r2739 };
    unsigned douts42[42];
    sub_words[889u * row_count + row] = r17;
    sub_words[890u * row_count + row] = r2700;
    sub_words[891u * row_count + row] = r2701;
    sub_words[892u * row_count + row] = r2702;
    sub_words[893u * row_count + row] = r2703;
    sub_words[894u * row_count + row] = r2704;
    sub_words[895u * row_count + row] = r2705;
    sub_words[896u * row_count + row] = r2706;
    sub_words[897u * row_count + row] = r2707;
    sub_words[898u * row_count + row] = r2708;
    sub_words[899u * row_count + row] = r2709;
    sub_words[900u * row_count + row] = r2710;
    sub_words[901u * row_count + row] = r2711;
    sub_words[902u * row_count + row] = r2712;
    sub_words[903u * row_count + row] = r2713;
    sub_words[904u * row_count + row] = r2714;
    sub_words[905u * row_count + row] = r2715;
    sub_words[906u * row_count + row] = r2716;
    sub_words[907u * row_count + row] = r2717;
    sub_words[908u * row_count + row] = r2718;
    sub_words[909u * row_count + row] = r2719;
    sub_words[910u * row_count + row] = r2720;
    sub_words[911u * row_count + row] = r2721;
    sub_words[912u * row_count + row] = r2722;
    sub_words[913u * row_count + row] = r2723;
    sub_words[914u * row_count + row] = r2724;
    sub_words[915u * row_count + row] = r2725;
    sub_words[916u * row_count + row] = r2726;
    sub_words[917u * row_count + row] = r2727;
    sub_words[918u * row_count + row] = r2728;
    sub_words[919u * row_count + row] = r2729;
    sub_words[920u * row_count + row] = r2730;
    sub_words[921u * row_count + row] = r2731;
    sub_words[922u * row_count + row] = r2732;
    sub_words[923u * row_count + row] = r2733;
    sub_words[924u * row_count + row] = r2734;
    sub_words[925u * row_count + row] = r2735;
    sub_words[926u * row_count + row] = r2736;
    sub_words[927u * row_count + row] = r2737;
    sub_words[928u * row_count + row] = r2738;
    sub_words[929u * row_count + row] = r2739;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs42, douts42);
    unsigned r2740 = douts42[0];
    unsigned r2741 = douts42[1];
    unsigned r2742 = douts42[2];
    unsigned r2743 = douts42[3];
    unsigned r2744 = douts42[4];
    unsigned r2745 = douts42[5];
    unsigned r2746 = douts42[6];
    unsigned r2747 = douts42[7];
    unsigned r2748 = douts42[8];
    unsigned r2749 = douts42[9];
    unsigned r2750 = douts42[10];
    unsigned r2751 = douts42[11];
    unsigned r2752 = douts42[12];
    unsigned r2753 = douts42[13];
    unsigned r2754 = douts42[14];
    unsigned r2755 = douts42[15];
    unsigned r2756 = douts42[16];
    unsigned r2757 = douts42[17];
    unsigned r2758 = douts42[18];
    unsigned r2759 = douts42[19];
    unsigned r2760 = douts42[20];
    unsigned r2761 = douts42[21];
    unsigned r2762 = douts42[22];
    unsigned r2763 = douts42[23];
    unsigned r2764 = douts42[24];
    unsigned r2765 = douts42[25];
    unsigned r2766 = douts42[26];
    unsigned r2767 = douts42[27];
    unsigned r2768 = douts42[28];
    unsigned r2769 = douts42[29];
    unsigned r2770 = douts42[30];
    unsigned r2771 = douts42[31];
    unsigned r2772 = douts42[32];
    unsigned r2773 = douts42[33];
    unsigned r2774 = douts42[34];
    unsigned r2775 = douts42[35];
    unsigned r2776 = douts42[36];
    unsigned r2777 = douts42[37];
    unsigned r2778 = douts42[38];
    unsigned r2779 = douts42[39];
    unsigned r2780 = douts42[40];
    unsigned r2781 = douts42[41];
    const unsigned dargs43[42] = { r268, r18, r2742, r2743, r2744, r2745, r2746, r2747, r2748, r2749, r2750, r2751, r2752, r2753, r2754, r2755, r2756, r2757, r2758, r2759, r2760, r2761, r2762, r2763, r2764, r2765, r2766, r2767, r2768, r2769, r2770, r2771, r2772, r2773, r2774, r2775, r2776, r2777, r2778, r2779, r2780, r2781 };
    unsigned douts43[42];
    sub_words[932u * row_count + row] = r2742;
    sub_words[933u * row_count + row] = r2743;
    sub_words[934u * row_count + row] = r2744;
    sub_words[935u * row_count + row] = r2745;
    sub_words[936u * row_count + row] = r2746;
    sub_words[937u * row_count + row] = r2747;
    sub_words[938u * row_count + row] = r2748;
    sub_words[939u * row_count + row] = r2749;
    sub_words[940u * row_count + row] = r2750;
    sub_words[941u * row_count + row] = r2751;
    sub_words[942u * row_count + row] = r2752;
    sub_words[943u * row_count + row] = r2753;
    sub_words[944u * row_count + row] = r2754;
    sub_words[945u * row_count + row] = r2755;
    sub_words[946u * row_count + row] = r2756;
    sub_words[947u * row_count + row] = r2757;
    sub_words[948u * row_count + row] = r2758;
    sub_words[949u * row_count + row] = r2759;
    sub_words[950u * row_count + row] = r2760;
    sub_words[951u * row_count + row] = r2761;
    sub_words[952u * row_count + row] = r2762;
    sub_words[953u * row_count + row] = r2763;
    sub_words[954u * row_count + row] = r2764;
    sub_words[955u * row_count + row] = r2765;
    sub_words[956u * row_count + row] = r2766;
    sub_words[957u * row_count + row] = r2767;
    sub_words[958u * row_count + row] = r2768;
    sub_words[959u * row_count + row] = r2769;
    sub_words[960u * row_count + row] = r2770;
    sub_words[961u * row_count + row] = r2771;
    sub_words[962u * row_count + row] = r2772;
    sub_words[963u * row_count + row] = r2773;
    sub_words[964u * row_count + row] = r2774;
    sub_words[965u * row_count + row] = r2775;
    sub_words[966u * row_count + row] = r2776;
    sub_words[967u * row_count + row] = r2777;
    sub_words[968u * row_count + row] = r2778;
    sub_words[969u * row_count + row] = r2779;
    sub_words[970u * row_count + row] = r2780;
    sub_words[971u * row_count + row] = r2781;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs43, douts43);
    unsigned r2782 = douts43[0];
    unsigned r2783 = douts43[1];
    unsigned r2784 = douts43[2];
    unsigned r2785 = douts43[3];
    unsigned r2786 = douts43[4];
    unsigned r2787 = douts43[5];
    unsigned r2788 = douts43[6];
    unsigned r2789 = douts43[7];
    unsigned r2790 = douts43[8];
    unsigned r2791 = douts43[9];
    unsigned r2792 = douts43[10];
    unsigned r2793 = douts43[11];
    unsigned r2794 = douts43[12];
    unsigned r2795 = douts43[13];
    unsigned r2796 = douts43[14];
    unsigned r2797 = douts43[15];
    unsigned r2798 = douts43[16];
    unsigned r2799 = douts43[17];
    unsigned r2800 = douts43[18];
    unsigned r2801 = douts43[19];
    unsigned r2802 = douts43[20];
    unsigned r2803 = douts43[21];
    unsigned r2804 = douts43[22];
    unsigned r2805 = douts43[23];
    unsigned r2806 = douts43[24];
    unsigned r2807 = douts43[25];
    unsigned r2808 = douts43[26];
    unsigned r2809 = douts43[27];
    unsigned r2810 = douts43[28];
    unsigned r2811 = douts43[29];
    unsigned r2812 = douts43[30];
    unsigned r2813 = douts43[31];
    unsigned r2814 = douts43[32];
    unsigned r2815 = douts43[33];
    unsigned r2816 = douts43[34];
    unsigned r2817 = douts43[35];
    unsigned r2818 = douts43[36];
    unsigned r2819 = douts43[37];
    unsigned r2820 = douts43[38];
    unsigned r2821 = douts43[39];
    unsigned r2822 = douts43[40];
    unsigned r2823 = douts43[41];
    const unsigned dargs44[42] = { r268, r19, r2784, r2785, r2786, r2787, r2788, r2789, r2790, r2791, r2792, r2793, r2794, r2795, r2796, r2797, r2798, r2799, r2800, r2801, r2802, r2803, r2804, r2805, r2806, r2807, r2808, r2809, r2810, r2811, r2812, r2813, r2814, r2815, r2816, r2817, r2818, r2819, r2820, r2821, r2822, r2823 };
    unsigned douts44[42];
    sub_words[974u * row_count + row] = r2784;
    sub_words[975u * row_count + row] = r2785;
    sub_words[976u * row_count + row] = r2786;
    sub_words[977u * row_count + row] = r2787;
    sub_words[978u * row_count + row] = r2788;
    sub_words[979u * row_count + row] = r2789;
    sub_words[980u * row_count + row] = r2790;
    sub_words[981u * row_count + row] = r2791;
    sub_words[982u * row_count + row] = r2792;
    sub_words[983u * row_count + row] = r2793;
    sub_words[984u * row_count + row] = r2794;
    sub_words[985u * row_count + row] = r2795;
    sub_words[986u * row_count + row] = r2796;
    sub_words[987u * row_count + row] = r2797;
    sub_words[988u * row_count + row] = r2798;
    sub_words[989u * row_count + row] = r2799;
    sub_words[990u * row_count + row] = r2800;
    sub_words[991u * row_count + row] = r2801;
    sub_words[992u * row_count + row] = r2802;
    sub_words[993u * row_count + row] = r2803;
    sub_words[994u * row_count + row] = r2804;
    sub_words[995u * row_count + row] = r2805;
    sub_words[996u * row_count + row] = r2806;
    sub_words[997u * row_count + row] = r2807;
    sub_words[998u * row_count + row] = r2808;
    sub_words[999u * row_count + row] = r2809;
    sub_words[1000u * row_count + row] = r2810;
    sub_words[1001u * row_count + row] = r2811;
    sub_words[1002u * row_count + row] = r2812;
    sub_words[1003u * row_count + row] = r2813;
    sub_words[1004u * row_count + row] = r2814;
    sub_words[1005u * row_count + row] = r2815;
    sub_words[1006u * row_count + row] = r2816;
    sub_words[1007u * row_count + row] = r2817;
    sub_words[1008u * row_count + row] = r2818;
    sub_words[1009u * row_count + row] = r2819;
    sub_words[1010u * row_count + row] = r2820;
    sub_words[1011u * row_count + row] = r2821;
    sub_words[1012u * row_count + row] = r2822;
    sub_words[1013u * row_count + row] = r2823;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs44, douts44);
    unsigned r2824 = douts44[0];
    unsigned r2825 = douts44[1];
    unsigned r2826 = douts44[2];
    unsigned r2827 = douts44[3];
    unsigned r2828 = douts44[4];
    unsigned r2829 = douts44[5];
    unsigned r2830 = douts44[6];
    unsigned r2831 = douts44[7];
    unsigned r2832 = douts44[8];
    unsigned r2833 = douts44[9];
    unsigned r2834 = douts44[10];
    unsigned r2835 = douts44[11];
    unsigned r2836 = douts44[12];
    unsigned r2837 = douts44[13];
    unsigned r2838 = douts44[14];
    unsigned r2839 = douts44[15];
    unsigned r2840 = douts44[16];
    unsigned r2841 = douts44[17];
    unsigned r2842 = douts44[18];
    unsigned r2843 = douts44[19];
    unsigned r2844 = douts44[20];
    unsigned r2845 = douts44[21];
    unsigned r2846 = douts44[22];
    unsigned r2847 = douts44[23];
    unsigned r2848 = douts44[24];
    unsigned r2849 = douts44[25];
    unsigned r2850 = douts44[26];
    unsigned r2851 = douts44[27];
    unsigned r2852 = douts44[28];
    unsigned r2853 = douts44[29];
    unsigned r2854 = douts44[30];
    unsigned r2855 = douts44[31];
    unsigned r2856 = douts44[32];
    unsigned r2857 = douts44[33];
    unsigned r2858 = douts44[34];
    unsigned r2859 = douts44[35];
    unsigned r2860 = douts44[36];
    unsigned r2861 = douts44[37];
    unsigned r2862 = douts44[38];
    unsigned r2863 = douts44[39];
    unsigned r2864 = douts44[40];
    unsigned r2865 = douts44[41];
    const unsigned dargs45[42] = { r268, r20, r2826, r2827, r2828, r2829, r2830, r2831, r2832, r2833, r2834, r2835, r2836, r2837, r2838, r2839, r2840, r2841, r2842, r2843, r2844, r2845, r2846, r2847, r2848, r2849, r2850, r2851, r2852, r2853, r2854, r2855, r2856, r2857, r2858, r2859, r2860, r2861, r2862, r2863, r2864, r2865 };
    unsigned douts45[42];
    sub_words[1016u * row_count + row] = r2826;
    sub_words[1017u * row_count + row] = r2827;
    sub_words[1018u * row_count + row] = r2828;
    sub_words[1019u * row_count + row] = r2829;
    sub_words[1020u * row_count + row] = r2830;
    sub_words[1021u * row_count + row] = r2831;
    sub_words[1022u * row_count + row] = r2832;
    sub_words[1023u * row_count + row] = r2833;
    sub_words[1024u * row_count + row] = r2834;
    sub_words[1025u * row_count + row] = r2835;
    sub_words[1026u * row_count + row] = r2836;
    sub_words[1027u * row_count + row] = r2837;
    sub_words[1028u * row_count + row] = r2838;
    sub_words[1029u * row_count + row] = r2839;
    sub_words[1030u * row_count + row] = r2840;
    sub_words[1031u * row_count + row] = r2841;
    sub_words[1032u * row_count + row] = r2842;
    sub_words[1033u * row_count + row] = r2843;
    sub_words[1034u * row_count + row] = r2844;
    sub_words[1035u * row_count + row] = r2845;
    sub_words[1036u * row_count + row] = r2846;
    sub_words[1037u * row_count + row] = r2847;
    sub_words[1038u * row_count + row] = r2848;
    sub_words[1039u * row_count + row] = r2849;
    sub_words[1040u * row_count + row] = r2850;
    sub_words[1041u * row_count + row] = r2851;
    sub_words[1042u * row_count + row] = r2852;
    sub_words[1043u * row_count + row] = r2853;
    sub_words[1044u * row_count + row] = r2854;
    sub_words[1045u * row_count + row] = r2855;
    sub_words[1046u * row_count + row] = r2856;
    sub_words[1047u * row_count + row] = r2857;
    sub_words[1048u * row_count + row] = r2858;
    sub_words[1049u * row_count + row] = r2859;
    sub_words[1050u * row_count + row] = r2860;
    sub_words[1051u * row_count + row] = r2861;
    sub_words[1052u * row_count + row] = r2862;
    sub_words[1053u * row_count + row] = r2863;
    sub_words[1054u * row_count + row] = r2864;
    sub_words[1055u * row_count + row] = r2865;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs45, douts45);
    unsigned r2866 = douts45[0];
    unsigned r2867 = douts45[1];
    unsigned r2868 = douts45[2];
    unsigned r2869 = douts45[3];
    unsigned r2870 = douts45[4];
    unsigned r2871 = douts45[5];
    unsigned r2872 = douts45[6];
    unsigned r2873 = douts45[7];
    unsigned r2874 = douts45[8];
    unsigned r2875 = douts45[9];
    unsigned r2876 = douts45[10];
    unsigned r2877 = douts45[11];
    unsigned r2878 = douts45[12];
    unsigned r2879 = douts45[13];
    unsigned r2880 = douts45[14];
    unsigned r2881 = douts45[15];
    unsigned r2882 = douts45[16];
    unsigned r2883 = douts45[17];
    unsigned r2884 = douts45[18];
    unsigned r2885 = douts45[19];
    unsigned r2886 = douts45[20];
    unsigned r2887 = douts45[21];
    unsigned r2888 = douts45[22];
    unsigned r2889 = douts45[23];
    unsigned r2890 = douts45[24];
    unsigned r2891 = douts45[25];
    unsigned r2892 = douts45[26];
    unsigned r2893 = douts45[27];
    unsigned r2894 = douts45[28];
    unsigned r2895 = douts45[29];
    unsigned r2896 = douts45[30];
    unsigned r2897 = douts45[31];
    unsigned r2898 = douts45[32];
    unsigned r2899 = douts45[33];
    unsigned r2900 = douts45[34];
    unsigned r2901 = douts45[35];
    unsigned r2902 = douts45[36];
    unsigned r2903 = douts45[37];
    unsigned r2904 = douts45[38];
    unsigned r2905 = douts45[39];
    unsigned r2906 = douts45[40];
    unsigned r2907 = douts45[41];
    const unsigned dargs46[42] = { r268, r21, r2868, r2869, r2870, r2871, r2872, r2873, r2874, r2875, r2876, r2877, r2878, r2879, r2880, r2881, r2882, r2883, r2884, r2885, r2886, r2887, r2888, r2889, r2890, r2891, r2892, r2893, r2894, r2895, r2896, r2897, r2898, r2899, r2900, r2901, r2902, r2903, r2904, r2905, r2906, r2907 };
    unsigned douts46[42];
    sub_words[1057u * row_count + row] = r21;
    sub_words[1058u * row_count + row] = r2868;
    sub_words[1059u * row_count + row] = r2869;
    sub_words[1060u * row_count + row] = r2870;
    sub_words[1061u * row_count + row] = r2871;
    sub_words[1062u * row_count + row] = r2872;
    sub_words[1063u * row_count + row] = r2873;
    sub_words[1064u * row_count + row] = r2874;
    sub_words[1065u * row_count + row] = r2875;
    sub_words[1066u * row_count + row] = r2876;
    sub_words[1067u * row_count + row] = r2877;
    sub_words[1068u * row_count + row] = r2878;
    sub_words[1069u * row_count + row] = r2879;
    sub_words[1070u * row_count + row] = r2880;
    sub_words[1071u * row_count + row] = r2881;
    sub_words[1072u * row_count + row] = r2882;
    sub_words[1073u * row_count + row] = r2883;
    sub_words[1074u * row_count + row] = r2884;
    sub_words[1075u * row_count + row] = r2885;
    sub_words[1076u * row_count + row] = r2886;
    sub_words[1077u * row_count + row] = r2887;
    sub_words[1078u * row_count + row] = r2888;
    sub_words[1079u * row_count + row] = r2889;
    sub_words[1080u * row_count + row] = r2890;
    sub_words[1081u * row_count + row] = r2891;
    sub_words[1082u * row_count + row] = r2892;
    sub_words[1083u * row_count + row] = r2893;
    sub_words[1084u * row_count + row] = r2894;
    sub_words[1085u * row_count + row] = r2895;
    sub_words[1086u * row_count + row] = r2896;
    sub_words[1087u * row_count + row] = r2897;
    sub_words[1088u * row_count + row] = r2898;
    sub_words[1089u * row_count + row] = r2899;
    sub_words[1090u * row_count + row] = r2900;
    sub_words[1091u * row_count + row] = r2901;
    sub_words[1092u * row_count + row] = r2902;
    sub_words[1093u * row_count + row] = r2903;
    sub_words[1094u * row_count + row] = r2904;
    sub_words[1095u * row_count + row] = r2905;
    sub_words[1096u * row_count + row] = r2906;
    sub_words[1097u * row_count + row] = r2907;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs46, douts46);
    unsigned r2908 = douts46[0];
    unsigned r2909 = douts46[1];
    unsigned r2910 = douts46[2];
    unsigned r2911 = douts46[3];
    unsigned r2912 = douts46[4];
    unsigned r2913 = douts46[5];
    unsigned r2914 = douts46[6];
    unsigned r2915 = douts46[7];
    unsigned r2916 = douts46[8];
    unsigned r2917 = douts46[9];
    unsigned r2918 = douts46[10];
    unsigned r2919 = douts46[11];
    unsigned r2920 = douts46[12];
    unsigned r2921 = douts46[13];
    unsigned r2922 = douts46[14];
    unsigned r2923 = douts46[15];
    unsigned r2924 = douts46[16];
    unsigned r2925 = douts46[17];
    unsigned r2926 = douts46[18];
    unsigned r2927 = douts46[19];
    unsigned r2928 = douts46[20];
    unsigned r2929 = douts46[21];
    unsigned r2930 = douts46[22];
    unsigned r2931 = douts46[23];
    unsigned r2932 = douts46[24];
    unsigned r2933 = douts46[25];
    unsigned r2934 = douts46[26];
    unsigned r2935 = douts46[27];
    unsigned r2936 = douts46[28];
    unsigned r2937 = douts46[29];
    unsigned r2938 = douts46[30];
    unsigned r2939 = douts46[31];
    unsigned r2940 = douts46[32];
    unsigned r2941 = douts46[33];
    unsigned r2942 = douts46[34];
    unsigned r2943 = douts46[35];
    unsigned r2944 = douts46[36];
    unsigned r2945 = douts46[37];
    unsigned r2946 = douts46[38];
    unsigned r2947 = douts46[39];
    unsigned r2948 = douts46[40];
    unsigned r2949 = douts46[41];
    const unsigned dargs47[42] = { r268, r22, r2910, r2911, r2912, r2913, r2914, r2915, r2916, r2917, r2918, r2919, r2920, r2921, r2922, r2923, r2924, r2925, r2926, r2927, r2928, r2929, r2930, r2931, r2932, r2933, r2934, r2935, r2936, r2937, r2938, r2939, r2940, r2941, r2942, r2943, r2944, r2945, r2946, r2947, r2948, r2949 };
    unsigned douts47[42];
    sub_words[1099u * row_count + row] = r22;
    sub_words[1100u * row_count + row] = r2910;
    sub_words[1101u * row_count + row] = r2911;
    sub_words[1102u * row_count + row] = r2912;
    sub_words[1103u * row_count + row] = r2913;
    sub_words[1104u * row_count + row] = r2914;
    sub_words[1105u * row_count + row] = r2915;
    sub_words[1106u * row_count + row] = r2916;
    sub_words[1107u * row_count + row] = r2917;
    sub_words[1108u * row_count + row] = r2918;
    sub_words[1109u * row_count + row] = r2919;
    sub_words[1110u * row_count + row] = r2920;
    sub_words[1111u * row_count + row] = r2921;
    sub_words[1112u * row_count + row] = r2922;
    sub_words[1113u * row_count + row] = r2923;
    sub_words[1114u * row_count + row] = r2924;
    sub_words[1115u * row_count + row] = r2925;
    sub_words[1116u * row_count + row] = r2926;
    sub_words[1117u * row_count + row] = r2927;
    sub_words[1118u * row_count + row] = r2928;
    sub_words[1119u * row_count + row] = r2929;
    sub_words[1120u * row_count + row] = r2930;
    sub_words[1121u * row_count + row] = r2931;
    sub_words[1122u * row_count + row] = r2932;
    sub_words[1123u * row_count + row] = r2933;
    sub_words[1124u * row_count + row] = r2934;
    sub_words[1125u * row_count + row] = r2935;
    sub_words[1126u * row_count + row] = r2936;
    sub_words[1127u * row_count + row] = r2937;
    sub_words[1128u * row_count + row] = r2938;
    sub_words[1129u * row_count + row] = r2939;
    sub_words[1130u * row_count + row] = r2940;
    sub_words[1131u * row_count + row] = r2941;
    sub_words[1132u * row_count + row] = r2942;
    sub_words[1133u * row_count + row] = r2943;
    sub_words[1134u * row_count + row] = r2944;
    sub_words[1135u * row_count + row] = r2945;
    sub_words[1136u * row_count + row] = r2946;
    sub_words[1137u * row_count + row] = r2947;
    sub_words[1138u * row_count + row] = r2948;
    sub_words[1139u * row_count + row] = r2949;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs47, douts47);
    unsigned r2950 = douts47[0];
    unsigned r2951 = douts47[1];
    unsigned r2952 = douts47[2];
    unsigned r2953 = douts47[3];
    unsigned r2954 = douts47[4];
    unsigned r2955 = douts47[5];
    unsigned r2956 = douts47[6];
    unsigned r2957 = douts47[7];
    unsigned r2958 = douts47[8];
    unsigned r2959 = douts47[9];
    unsigned r2960 = douts47[10];
    unsigned r2961 = douts47[11];
    unsigned r2962 = douts47[12];
    unsigned r2963 = douts47[13];
    unsigned r2964 = douts47[14];
    unsigned r2965 = douts47[15];
    unsigned r2966 = douts47[16];
    unsigned r2967 = douts47[17];
    unsigned r2968 = douts47[18];
    unsigned r2969 = douts47[19];
    unsigned r2970 = douts47[20];
    unsigned r2971 = douts47[21];
    unsigned r2972 = douts47[22];
    unsigned r2973 = douts47[23];
    unsigned r2974 = douts47[24];
    unsigned r2975 = douts47[25];
    unsigned r2976 = douts47[26];
    unsigned r2977 = douts47[27];
    unsigned r2978 = douts47[28];
    unsigned r2979 = douts47[29];
    unsigned r2980 = douts47[30];
    unsigned r2981 = douts47[31];
    unsigned r2982 = douts47[32];
    unsigned r2983 = douts47[33];
    unsigned r2984 = douts47[34];
    unsigned r2985 = douts47[35];
    unsigned r2986 = douts47[36];
    unsigned r2987 = douts47[37];
    unsigned r2988 = douts47[38];
    unsigned r2989 = douts47[39];
    unsigned r2990 = douts47[40];
    unsigned r2991 = douts47[41];
    const unsigned dargs48[42] = { r268, r23, r2952, r2953, r2954, r2955, r2956, r2957, r2958, r2959, r2960, r2961, r2962, r2963, r2964, r2965, r2966, r2967, r2968, r2969, r2970, r2971, r2972, r2973, r2974, r2975, r2976, r2977, r2978, r2979, r2980, r2981, r2982, r2983, r2984, r2985, r2986, r2987, r2988, r2989, r2990, r2991 };
    unsigned douts48[42];
    sub_words[1141u * row_count + row] = r23;
    sub_words[1142u * row_count + row] = r2952;
    sub_words[1143u * row_count + row] = r2953;
    sub_words[1144u * row_count + row] = r2954;
    sub_words[1145u * row_count + row] = r2955;
    sub_words[1146u * row_count + row] = r2956;
    sub_words[1147u * row_count + row] = r2957;
    sub_words[1148u * row_count + row] = r2958;
    sub_words[1149u * row_count + row] = r2959;
    sub_words[1150u * row_count + row] = r2960;
    sub_words[1151u * row_count + row] = r2961;
    sub_words[1152u * row_count + row] = r2962;
    sub_words[1153u * row_count + row] = r2963;
    sub_words[1154u * row_count + row] = r2964;
    sub_words[1155u * row_count + row] = r2965;
    sub_words[1156u * row_count + row] = r2966;
    sub_words[1157u * row_count + row] = r2967;
    sub_words[1158u * row_count + row] = r2968;
    sub_words[1159u * row_count + row] = r2969;
    sub_words[1160u * row_count + row] = r2970;
    sub_words[1161u * row_count + row] = r2971;
    sub_words[1162u * row_count + row] = r2972;
    sub_words[1163u * row_count + row] = r2973;
    sub_words[1164u * row_count + row] = r2974;
    sub_words[1165u * row_count + row] = r2975;
    sub_words[1166u * row_count + row] = r2976;
    sub_words[1167u * row_count + row] = r2977;
    sub_words[1168u * row_count + row] = r2978;
    sub_words[1169u * row_count + row] = r2979;
    sub_words[1170u * row_count + row] = r2980;
    sub_words[1171u * row_count + row] = r2981;
    sub_words[1172u * row_count + row] = r2982;
    sub_words[1173u * row_count + row] = r2983;
    sub_words[1174u * row_count + row] = r2984;
    sub_words[1175u * row_count + row] = r2985;
    sub_words[1176u * row_count + row] = r2986;
    sub_words[1177u * row_count + row] = r2987;
    sub_words[1178u * row_count + row] = r2988;
    sub_words[1179u * row_count + row] = r2989;
    sub_words[1180u * row_count + row] = r2990;
    sub_words[1181u * row_count + row] = r2991;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs48, douts48);
    unsigned r2992 = douts48[0];
    unsigned r2993 = douts48[1];
    unsigned r2994 = douts48[2];
    unsigned r2995 = douts48[3];
    unsigned r2996 = douts48[4];
    unsigned r2997 = douts48[5];
    unsigned r2998 = douts48[6];
    unsigned r2999 = douts48[7];
    unsigned r3000 = douts48[8];
    unsigned r3001 = douts48[9];
    unsigned r3002 = douts48[10];
    unsigned r3003 = douts48[11];
    unsigned r3004 = douts48[12];
    unsigned r3005 = douts48[13];
    unsigned r3006 = douts48[14];
    unsigned r3007 = douts48[15];
    unsigned r3008 = douts48[16];
    unsigned r3009 = douts48[17];
    unsigned r3010 = douts48[18];
    unsigned r3011 = douts48[19];
    unsigned r3012 = douts48[20];
    unsigned r3013 = douts48[21];
    unsigned r3014 = douts48[22];
    unsigned r3015 = douts48[23];
    unsigned r3016 = douts48[24];
    unsigned r3017 = douts48[25];
    unsigned r3018 = douts48[26];
    unsigned r3019 = douts48[27];
    unsigned r3020 = douts48[28];
    unsigned r3021 = douts48[29];
    unsigned r3022 = douts48[30];
    unsigned r3023 = douts48[31];
    unsigned r3024 = douts48[32];
    unsigned r3025 = douts48[33];
    unsigned r3026 = douts48[34];
    unsigned r3027 = douts48[35];
    unsigned r3028 = douts48[36];
    unsigned r3029 = douts48[37];
    unsigned r3030 = douts48[38];
    unsigned r3031 = douts48[39];
    unsigned r3032 = douts48[40];
    unsigned r3033 = douts48[41];
    const unsigned dargs49[42] = { r268, r24, r2994, r2995, r2996, r2997, r2998, r2999, r3000, r3001, r3002, r3003, r3004, r3005, r3006, r3007, r3008, r3009, r3010, r3011, r3012, r3013, r3014, r3015, r3016, r3017, r3018, r3019, r3020, r3021, r3022, r3023, r3024, r3025, r3026, r3027, r3028, r3029, r3030, r3031, r3032, r3033 };
    unsigned douts49[42];
    sub_words[1183u * row_count + row] = r24;
    sub_words[1184u * row_count + row] = r2994;
    sub_words[1185u * row_count + row] = r2995;
    sub_words[1186u * row_count + row] = r2996;
    sub_words[1187u * row_count + row] = r2997;
    sub_words[1188u * row_count + row] = r2998;
    sub_words[1189u * row_count + row] = r2999;
    sub_words[1190u * row_count + row] = r3000;
    sub_words[1191u * row_count + row] = r3001;
    sub_words[1192u * row_count + row] = r3002;
    sub_words[1193u * row_count + row] = r3003;
    sub_words[1194u * row_count + row] = r3004;
    sub_words[1195u * row_count + row] = r3005;
    sub_words[1196u * row_count + row] = r3006;
    sub_words[1197u * row_count + row] = r3007;
    sub_words[1198u * row_count + row] = r3008;
    sub_words[1199u * row_count + row] = r3009;
    sub_words[1200u * row_count + row] = r3010;
    sub_words[1201u * row_count + row] = r3011;
    sub_words[1202u * row_count + row] = r3012;
    sub_words[1203u * row_count + row] = r3013;
    sub_words[1204u * row_count + row] = r3014;
    sub_words[1205u * row_count + row] = r3015;
    sub_words[1206u * row_count + row] = r3016;
    sub_words[1207u * row_count + row] = r3017;
    sub_words[1208u * row_count + row] = r3018;
    sub_words[1209u * row_count + row] = r3019;
    sub_words[1210u * row_count + row] = r3020;
    sub_words[1211u * row_count + row] = r3021;
    sub_words[1212u * row_count + row] = r3022;
    sub_words[1213u * row_count + row] = r3023;
    sub_words[1214u * row_count + row] = r3024;
    sub_words[1215u * row_count + row] = r3025;
    sub_words[1216u * row_count + row] = r3026;
    sub_words[1217u * row_count + row] = r3027;
    sub_words[1218u * row_count + row] = r3028;
    sub_words[1219u * row_count + row] = r3029;
    sub_words[1220u * row_count + row] = r3030;
    sub_words[1221u * row_count + row] = r3031;
    sub_words[1222u * row_count + row] = r3032;
    sub_words[1223u * row_count + row] = r3033;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs49, douts49);
    unsigned r3034 = douts49[0];
    unsigned r3035 = douts49[1];
    unsigned r3036 = douts49[2];
    unsigned r3037 = douts49[3];
    unsigned r3038 = douts49[4];
    unsigned r3039 = douts49[5];
    unsigned r3040 = douts49[6];
    unsigned r3041 = douts49[7];
    unsigned r3042 = douts49[8];
    unsigned r3043 = douts49[9];
    unsigned r3044 = douts49[10];
    unsigned r3045 = douts49[11];
    unsigned r3046 = douts49[12];
    unsigned r3047 = douts49[13];
    unsigned r3048 = douts49[14];
    unsigned r3049 = douts49[15];
    unsigned r3050 = douts49[16];
    unsigned r3051 = douts49[17];
    unsigned r3052 = douts49[18];
    unsigned r3053 = douts49[19];
    unsigned r3054 = douts49[20];
    unsigned r3055 = douts49[21];
    unsigned r3056 = douts49[22];
    unsigned r3057 = douts49[23];
    unsigned r3058 = douts49[24];
    unsigned r3059 = douts49[25];
    unsigned r3060 = douts49[26];
    unsigned r3061 = douts49[27];
    unsigned r3062 = douts49[28];
    unsigned r3063 = douts49[29];
    unsigned r3064 = douts49[30];
    unsigned r3065 = douts49[31];
    unsigned r3066 = douts49[32];
    unsigned r3067 = douts49[33];
    unsigned r3068 = douts49[34];
    unsigned r3069 = douts49[35];
    unsigned r3070 = douts49[36];
    unsigned r3071 = douts49[37];
    unsigned r3072 = douts49[38];
    unsigned r3073 = douts49[39];
    unsigned r3074 = douts49[40];
    unsigned r3075 = douts49[41];
    const unsigned dargs50[42] = { r268, r25, r3036, r3037, r3038, r3039, r3040, r3041, r3042, r3043, r3044, r3045, r3046, r3047, r3048, r3049, r3050, r3051, r3052, r3053, r3054, r3055, r3056, r3057, r3058, r3059, r3060, r3061, r3062, r3063, r3064, r3065, r3066, r3067, r3068, r3069, r3070, r3071, r3072, r3073, r3074, r3075 };
    unsigned douts50[42];
    sub_words[1225u * row_count + row] = r25;
    sub_words[1226u * row_count + row] = r3036;
    sub_words[1227u * row_count + row] = r3037;
    sub_words[1228u * row_count + row] = r3038;
    sub_words[1229u * row_count + row] = r3039;
    sub_words[1230u * row_count + row] = r3040;
    sub_words[1231u * row_count + row] = r3041;
    sub_words[1232u * row_count + row] = r3042;
    sub_words[1233u * row_count + row] = r3043;
    sub_words[1234u * row_count + row] = r3044;
    sub_words[1235u * row_count + row] = r3045;
    sub_words[1236u * row_count + row] = r3046;
    sub_words[1237u * row_count + row] = r3047;
    sub_words[1238u * row_count + row] = r3048;
    sub_words[1239u * row_count + row] = r3049;
    sub_words[1240u * row_count + row] = r3050;
    sub_words[1241u * row_count + row] = r3051;
    sub_words[1242u * row_count + row] = r3052;
    sub_words[1243u * row_count + row] = r3053;
    sub_words[1244u * row_count + row] = r3054;
    sub_words[1245u * row_count + row] = r3055;
    sub_words[1246u * row_count + row] = r3056;
    sub_words[1247u * row_count + row] = r3057;
    sub_words[1248u * row_count + row] = r3058;
    sub_words[1249u * row_count + row] = r3059;
    sub_words[1250u * row_count + row] = r3060;
    sub_words[1251u * row_count + row] = r3061;
    sub_words[1252u * row_count + row] = r3062;
    sub_words[1253u * row_count + row] = r3063;
    sub_words[1254u * row_count + row] = r3064;
    sub_words[1255u * row_count + row] = r3065;
    sub_words[1256u * row_count + row] = r3066;
    sub_words[1257u * row_count + row] = r3067;
    sub_words[1258u * row_count + row] = r3068;
    sub_words[1259u * row_count + row] = r3069;
    sub_words[1260u * row_count + row] = r3070;
    sub_words[1261u * row_count + row] = r3071;
    sub_words[1262u * row_count + row] = r3072;
    sub_words[1263u * row_count + row] = r3073;
    sub_words[1264u * row_count + row] = r3074;
    sub_words[1265u * row_count + row] = r3075;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs50, douts50);
    unsigned r3076 = douts50[0];
    unsigned r3077 = douts50[1];
    unsigned r3078 = douts50[2];
    unsigned r3079 = douts50[3];
    unsigned r3080 = douts50[4];
    unsigned r3081 = douts50[5];
    unsigned r3082 = douts50[6];
    unsigned r3083 = douts50[7];
    unsigned r3084 = douts50[8];
    unsigned r3085 = douts50[9];
    unsigned r3086 = douts50[10];
    unsigned r3087 = douts50[11];
    unsigned r3088 = douts50[12];
    unsigned r3089 = douts50[13];
    unsigned r3090 = douts50[14];
    unsigned r3091 = douts50[15];
    unsigned r3092 = douts50[16];
    unsigned r3093 = douts50[17];
    unsigned r3094 = douts50[18];
    unsigned r3095 = douts50[19];
    unsigned r3096 = douts50[20];
    unsigned r3097 = douts50[21];
    unsigned r3098 = douts50[22];
    unsigned r3099 = douts50[23];
    unsigned r3100 = douts50[24];
    unsigned r3101 = douts50[25];
    unsigned r3102 = douts50[26];
    unsigned r3103 = douts50[27];
    unsigned r3104 = douts50[28];
    unsigned r3105 = douts50[29];
    unsigned r3106 = douts50[30];
    unsigned r3107 = douts50[31];
    unsigned r3108 = douts50[32];
    unsigned r3109 = douts50[33];
    unsigned r3110 = douts50[34];
    unsigned r3111 = douts50[35];
    unsigned r3112 = douts50[36];
    unsigned r3113 = douts50[37];
    unsigned r3114 = douts50[38];
    unsigned r3115 = douts50[39];
    unsigned r3116 = douts50[40];
    unsigned r3117 = douts50[41];
    const unsigned dargs51[42] = { r268, r26, r3078, r3079, r3080, r3081, r3082, r3083, r3084, r3085, r3086, r3087, r3088, r3089, r3090, r3091, r3092, r3093, r3094, r3095, r3096, r3097, r3098, r3099, r3100, r3101, r3102, r3103, r3104, r3105, r3106, r3107, r3108, r3109, r3110, r3111, r3112, r3113, r3114, r3115, r3116, r3117 };
    unsigned douts51[42];
    sub_words[1267u * row_count + row] = r26;
    sub_words[1268u * row_count + row] = r3078;
    sub_words[1269u * row_count + row] = r3079;
    sub_words[1270u * row_count + row] = r3080;
    sub_words[1271u * row_count + row] = r3081;
    sub_words[1272u * row_count + row] = r3082;
    sub_words[1273u * row_count + row] = r3083;
    sub_words[1274u * row_count + row] = r3084;
    sub_words[1275u * row_count + row] = r3085;
    sub_words[1276u * row_count + row] = r3086;
    sub_words[1277u * row_count + row] = r3087;
    sub_words[1278u * row_count + row] = r3088;
    sub_words[1279u * row_count + row] = r3089;
    sub_words[1280u * row_count + row] = r3090;
    sub_words[1281u * row_count + row] = r3091;
    sub_words[1282u * row_count + row] = r3092;
    sub_words[1283u * row_count + row] = r3093;
    sub_words[1284u * row_count + row] = r3094;
    sub_words[1285u * row_count + row] = r3095;
    sub_words[1286u * row_count + row] = r3096;
    sub_words[1287u * row_count + row] = r3097;
    sub_words[1288u * row_count + row] = r3098;
    sub_words[1289u * row_count + row] = r3099;
    sub_words[1290u * row_count + row] = r3100;
    sub_words[1291u * row_count + row] = r3101;
    sub_words[1292u * row_count + row] = r3102;
    sub_words[1293u * row_count + row] = r3103;
    sub_words[1294u * row_count + row] = r3104;
    sub_words[1295u * row_count + row] = r3105;
    sub_words[1296u * row_count + row] = r3106;
    sub_words[1297u * row_count + row] = r3107;
    sub_words[1298u * row_count + row] = r3108;
    sub_words[1299u * row_count + row] = r3109;
    sub_words[1300u * row_count + row] = r3110;
    sub_words[1301u * row_count + row] = r3111;
    sub_words[1302u * row_count + row] = r3112;
    sub_words[1303u * row_count + row] = r3113;
    sub_words[1304u * row_count + row] = r3114;
    sub_words[1305u * row_count + row] = r3115;
    sub_words[1306u * row_count + row] = r3116;
    sub_words[1307u * row_count + row] = r3117;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs51, douts51);
    unsigned r3118 = douts51[0];
    unsigned r3119 = douts51[1];
    unsigned r3120 = douts51[2];
    unsigned r3121 = douts51[3];
    unsigned r3122 = douts51[4];
    unsigned r3123 = douts51[5];
    unsigned r3124 = douts51[6];
    unsigned r3125 = douts51[7];
    unsigned r3126 = douts51[8];
    unsigned r3127 = douts51[9];
    unsigned r3128 = douts51[10];
    unsigned r3129 = douts51[11];
    unsigned r3130 = douts51[12];
    unsigned r3131 = douts51[13];
    unsigned r3132 = douts51[14];
    unsigned r3133 = douts51[15];
    unsigned r3134 = douts51[16];
    unsigned r3135 = douts51[17];
    unsigned r3136 = douts51[18];
    unsigned r3137 = douts51[19];
    unsigned r3138 = douts51[20];
    unsigned r3139 = douts51[21];
    unsigned r3140 = douts51[22];
    unsigned r3141 = douts51[23];
    unsigned r3142 = douts51[24];
    unsigned r3143 = douts51[25];
    unsigned r3144 = douts51[26];
    unsigned r3145 = douts51[27];
    unsigned r3146 = douts51[28];
    unsigned r3147 = douts51[29];
    unsigned r3148 = douts51[30];
    unsigned r3149 = douts51[31];
    unsigned r3150 = douts51[32];
    unsigned r3151 = douts51[33];
    unsigned r3152 = douts51[34];
    unsigned r3153 = douts51[35];
    unsigned r3154 = douts51[36];
    unsigned r3155 = douts51[37];
    unsigned r3156 = douts51[38];
    unsigned r3157 = douts51[39];
    unsigned r3158 = douts51[40];
    unsigned r3159 = douts51[41];
    const unsigned dargs52[42] = { r268, r27, r3120, r3121, r3122, r3123, r3124, r3125, r3126, r3127, r3128, r3129, r3130, r3131, r3132, r3133, r3134, r3135, r3136, r3137, r3138, r3139, r3140, r3141, r3142, r3143, r3144, r3145, r3146, r3147, r3148, r3149, r3150, r3151, r3152, r3153, r3154, r3155, r3156, r3157, r3158, r3159 };
    unsigned douts52[42];
    sub_words[1310u * row_count + row] = r3120;
    sub_words[1311u * row_count + row] = r3121;
    sub_words[1312u * row_count + row] = r3122;
    sub_words[1313u * row_count + row] = r3123;
    sub_words[1314u * row_count + row] = r3124;
    sub_words[1315u * row_count + row] = r3125;
    sub_words[1316u * row_count + row] = r3126;
    sub_words[1317u * row_count + row] = r3127;
    sub_words[1318u * row_count + row] = r3128;
    sub_words[1319u * row_count + row] = r3129;
    sub_words[1320u * row_count + row] = r3130;
    sub_words[1321u * row_count + row] = r3131;
    sub_words[1322u * row_count + row] = r3132;
    sub_words[1323u * row_count + row] = r3133;
    sub_words[1324u * row_count + row] = r3134;
    sub_words[1325u * row_count + row] = r3135;
    sub_words[1326u * row_count + row] = r3136;
    sub_words[1327u * row_count + row] = r3137;
    sub_words[1328u * row_count + row] = r3138;
    sub_words[1329u * row_count + row] = r3139;
    sub_words[1330u * row_count + row] = r3140;
    sub_words[1331u * row_count + row] = r3141;
    sub_words[1332u * row_count + row] = r3142;
    sub_words[1333u * row_count + row] = r3143;
    sub_words[1334u * row_count + row] = r3144;
    sub_words[1335u * row_count + row] = r3145;
    sub_words[1336u * row_count + row] = r3146;
    sub_words[1337u * row_count + row] = r3147;
    sub_words[1338u * row_count + row] = r3148;
    sub_words[1339u * row_count + row] = r3149;
    sub_words[1340u * row_count + row] = r3150;
    sub_words[1341u * row_count + row] = r3151;
    sub_words[1342u * row_count + row] = r3152;
    sub_words[1343u * row_count + row] = r3153;
    sub_words[1344u * row_count + row] = r3154;
    sub_words[1345u * row_count + row] = r3155;
    sub_words[1346u * row_count + row] = r3156;
    sub_words[1347u * row_count + row] = r3157;
    sub_words[1348u * row_count + row] = r3158;
    sub_words[1349u * row_count + row] = r3159;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs52, douts52);
    unsigned r3160 = douts52[0];
    unsigned r3161 = douts52[1];
    unsigned r3162 = douts52[2];
    unsigned r3163 = douts52[3];
    unsigned r3164 = douts52[4];
    unsigned r3165 = douts52[5];
    unsigned r3166 = douts52[6];
    unsigned r3167 = douts52[7];
    unsigned r3168 = douts52[8];
    unsigned r3169 = douts52[9];
    unsigned r3170 = douts52[10];
    unsigned r3171 = douts52[11];
    unsigned r3172 = douts52[12];
    unsigned r3173 = douts52[13];
    unsigned r3174 = douts52[14];
    unsigned r3175 = douts52[15];
    unsigned r3176 = douts52[16];
    unsigned r3177 = douts52[17];
    unsigned r3178 = douts52[18];
    unsigned r3179 = douts52[19];
    unsigned r3180 = douts52[20];
    unsigned r3181 = douts52[21];
    unsigned r3182 = douts52[22];
    unsigned r3183 = douts52[23];
    unsigned r3184 = douts52[24];
    unsigned r3185 = douts52[25];
    unsigned r3186 = douts52[26];
    unsigned r3187 = douts52[27];
    unsigned r3188 = douts52[28];
    unsigned r3189 = douts52[29];
    unsigned r3190 = douts52[30];
    unsigned r3191 = douts52[31];
    unsigned r3192 = douts52[32];
    unsigned r3193 = douts52[33];
    unsigned r3194 = douts52[34];
    unsigned r3195 = douts52[35];
    unsigned r3196 = douts52[36];
    unsigned r3197 = douts52[37];
    unsigned r3198 = douts52[38];
    unsigned r3199 = douts52[39];
    unsigned r3200 = douts52[40];
    unsigned r3201 = douts52[41];
    const unsigned dargs53[42] = { r268, r28, r3162, r3163, r3164, r3165, r3166, r3167, r3168, r3169, r3170, r3171, r3172, r3173, r3174, r3175, r3176, r3177, r3178, r3179, r3180, r3181, r3182, r3183, r3184, r3185, r3186, r3187, r3188, r3189, r3190, r3191, r3192, r3193, r3194, r3195, r3196, r3197, r3198, r3199, r3200, r3201 };
    unsigned douts53[42];
    sub_words[1351u * row_count + row] = r28;
    sub_words[1352u * row_count + row] = r3162;
    sub_words[1353u * row_count + row] = r3163;
    sub_words[1354u * row_count + row] = r3164;
    sub_words[1355u * row_count + row] = r3165;
    sub_words[1356u * row_count + row] = r3166;
    sub_words[1357u * row_count + row] = r3167;
    sub_words[1358u * row_count + row] = r3168;
    sub_words[1359u * row_count + row] = r3169;
    sub_words[1360u * row_count + row] = r3170;
    sub_words[1361u * row_count + row] = r3171;
    sub_words[1362u * row_count + row] = r3172;
    sub_words[1363u * row_count + row] = r3173;
    sub_words[1364u * row_count + row] = r3174;
    sub_words[1365u * row_count + row] = r3175;
    sub_words[1366u * row_count + row] = r3176;
    sub_words[1367u * row_count + row] = r3177;
    sub_words[1368u * row_count + row] = r3178;
    sub_words[1369u * row_count + row] = r3179;
    sub_words[1370u * row_count + row] = r3180;
    sub_words[1371u * row_count + row] = r3181;
    sub_words[1372u * row_count + row] = r3182;
    sub_words[1373u * row_count + row] = r3183;
    sub_words[1374u * row_count + row] = r3184;
    sub_words[1375u * row_count + row] = r3185;
    sub_words[1376u * row_count + row] = r3186;
    sub_words[1377u * row_count + row] = r3187;
    sub_words[1378u * row_count + row] = r3188;
    sub_words[1379u * row_count + row] = r3189;
    sub_words[1380u * row_count + row] = r3190;
    sub_words[1381u * row_count + row] = r3191;
    sub_words[1382u * row_count + row] = r3192;
    sub_words[1383u * row_count + row] = r3193;
    sub_words[1384u * row_count + row] = r3194;
    sub_words[1385u * row_count + row] = r3195;
    sub_words[1386u * row_count + row] = r3196;
    sub_words[1387u * row_count + row] = r3197;
    sub_words[1388u * row_count + row] = r3198;
    sub_words[1389u * row_count + row] = r3199;
    sub_words[1390u * row_count + row] = r3200;
    sub_words[1391u * row_count + row] = r3201;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs53, douts53);
    unsigned r3202 = douts53[0];
    unsigned r3203 = douts53[1];
    unsigned r3204 = douts53[2];
    unsigned r3205 = douts53[3];
    unsigned r3206 = douts53[4];
    unsigned r3207 = douts53[5];
    unsigned r3208 = douts53[6];
    unsigned r3209 = douts53[7];
    unsigned r3210 = douts53[8];
    unsigned r3211 = douts53[9];
    unsigned r3212 = douts53[10];
    unsigned r3213 = douts53[11];
    unsigned r3214 = douts53[12];
    unsigned r3215 = douts53[13];
    unsigned r3216 = douts53[14];
    unsigned r3217 = douts53[15];
    unsigned r3218 = douts53[16];
    unsigned r3219 = douts53[17];
    unsigned r3220 = douts53[18];
    unsigned r3221 = douts53[19];
    unsigned r3222 = douts53[20];
    unsigned r3223 = douts53[21];
    unsigned r3224 = douts53[22];
    unsigned r3225 = douts53[23];
    unsigned r3226 = douts53[24];
    unsigned r3227 = douts53[25];
    unsigned r3228 = douts53[26];
    unsigned r3229 = douts53[27];
    unsigned r3230 = douts53[28];
    unsigned r3231 = douts53[29];
    unsigned r3232 = douts53[30];
    unsigned r3233 = douts53[31];
    unsigned r3234 = douts53[32];
    unsigned r3235 = douts53[33];
    unsigned r3236 = douts53[34];
    unsigned r3237 = douts53[35];
    unsigned r3238 = douts53[36];
    unsigned r3239 = douts53[37];
    unsigned r3240 = douts53[38];
    unsigned r3241 = douts53[39];
    unsigned r3242 = douts53[40];
    unsigned r3243 = douts53[41];
    const unsigned dargs54[42] = { r268, r29, r3204, r3205, r3206, r3207, r3208, r3209, r3210, r3211, r3212, r3213, r3214, r3215, r3216, r3217, r3218, r3219, r3220, r3221, r3222, r3223, r3224, r3225, r3226, r3227, r3228, r3229, r3230, r3231, r3232, r3233, r3234, r3235, r3236, r3237, r3238, r3239, r3240, r3241, r3242, r3243 };
    unsigned douts54[42];
    sub_words[1393u * row_count + row] = r29;
    sub_words[1394u * row_count + row] = r3204;
    sub_words[1395u * row_count + row] = r3205;
    sub_words[1396u * row_count + row] = r3206;
    sub_words[1397u * row_count + row] = r3207;
    sub_words[1398u * row_count + row] = r3208;
    sub_words[1399u * row_count + row] = r3209;
    sub_words[1400u * row_count + row] = r3210;
    sub_words[1401u * row_count + row] = r3211;
    sub_words[1402u * row_count + row] = r3212;
    sub_words[1403u * row_count + row] = r3213;
    sub_words[1404u * row_count + row] = r3214;
    sub_words[1405u * row_count + row] = r3215;
    sub_words[1406u * row_count + row] = r3216;
    sub_words[1407u * row_count + row] = r3217;
    sub_words[1408u * row_count + row] = r3218;
    sub_words[1409u * row_count + row] = r3219;
    sub_words[1410u * row_count + row] = r3220;
    sub_words[1411u * row_count + row] = r3221;
    sub_words[1412u * row_count + row] = r3222;
    sub_words[1413u * row_count + row] = r3223;
    sub_words[1414u * row_count + row] = r3224;
    sub_words[1415u * row_count + row] = r3225;
    sub_words[1416u * row_count + row] = r3226;
    sub_words[1417u * row_count + row] = r3227;
    sub_words[1418u * row_count + row] = r3228;
    sub_words[1419u * row_count + row] = r3229;
    sub_words[1420u * row_count + row] = r3230;
    sub_words[1421u * row_count + row] = r3231;
    sub_words[1422u * row_count + row] = r3232;
    sub_words[1423u * row_count + row] = r3233;
    sub_words[1424u * row_count + row] = r3234;
    sub_words[1425u * row_count + row] = r3235;
    sub_words[1426u * row_count + row] = r3236;
    sub_words[1427u * row_count + row] = r3237;
    sub_words[1428u * row_count + row] = r3238;
    sub_words[1429u * row_count + row] = r3239;
    sub_words[1430u * row_count + row] = r3240;
    sub_words[1431u * row_count + row] = r3241;
    sub_words[1432u * row_count + row] = r3242;
    sub_words[1433u * row_count + row] = r3243;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs54, douts54);
    unsigned r3244 = douts54[0];
    unsigned r3245 = douts54[1];
    unsigned r3246 = douts54[2];
    unsigned r3247 = douts54[3];
    unsigned r3248 = douts54[4];
    unsigned r3249 = douts54[5];
    unsigned r3250 = douts54[6];
    unsigned r3251 = douts54[7];
    unsigned r3252 = douts54[8];
    unsigned r3253 = douts54[9];
    unsigned r3254 = douts54[10];
    unsigned r3255 = douts54[11];
    unsigned r3256 = douts54[12];
    unsigned r3257 = douts54[13];
    unsigned r3258 = douts54[14];
    unsigned r3259 = douts54[15];
    unsigned r3260 = douts54[16];
    unsigned r3261 = douts54[17];
    unsigned r3262 = douts54[18];
    unsigned r3263 = douts54[19];
    unsigned r3264 = douts54[20];
    unsigned r3265 = douts54[21];
    unsigned r3266 = douts54[22];
    unsigned r3267 = douts54[23];
    unsigned r3268 = douts54[24];
    unsigned r3269 = douts54[25];
    unsigned r3270 = douts54[26];
    unsigned r3271 = douts54[27];
    unsigned r3272 = douts54[28];
    unsigned r3273 = douts54[29];
    unsigned r3274 = douts54[30];
    unsigned r3275 = douts54[31];
    unsigned r3276 = douts54[32];
    unsigned r3277 = douts54[33];
    unsigned r3278 = douts54[34];
    unsigned r3279 = douts54[35];
    unsigned r3280 = douts54[36];
    unsigned r3281 = douts54[37];
    unsigned r3282 = douts54[38];
    unsigned r3283 = douts54[39];
    unsigned r3284 = douts54[40];
    unsigned r3285 = douts54[41];
    const unsigned dargs55[42] = { r268, r30, r3246, r3247, r3248, r3249, r3250, r3251, r3252, r3253, r3254, r3255, r3256, r3257, r3258, r3259, r3260, r3261, r3262, r3263, r3264, r3265, r3266, r3267, r3268, r3269, r3270, r3271, r3272, r3273, r3274, r3275, r3276, r3277, r3278, r3279, r3280, r3281, r3282, r3283, r3284, r3285 };
    unsigned douts55[42];
    lookup_words[246u * row_count + row] = r268;
    sub_words[342u * row_count + row] = r268;
    sub_words[384u * row_count + row] = r268;
    sub_words[426u * row_count + row] = r268;
    sub_words[468u * row_count + row] = r268;
    sub_words[510u * row_count + row] = r268;
    sub_words[552u * row_count + row] = r268;
    sub_words[594u * row_count + row] = r268;
    sub_words[636u * row_count + row] = r268;
    sub_words[678u * row_count + row] = r268;
    sub_words[720u * row_count + row] = r268;
    sub_words[762u * row_count + row] = r268;
    sub_words[804u * row_count + row] = r268;
    sub_words[846u * row_count + row] = r268;
    sub_words[888u * row_count + row] = r268;
    sub_words[930u * row_count + row] = r268;
    sub_words[972u * row_count + row] = r268;
    sub_words[1014u * row_count + row] = r268;
    sub_words[1056u * row_count + row] = r268;
    sub_words[1098u * row_count + row] = r268;
    sub_words[1140u * row_count + row] = r268;
    sub_words[1182u * row_count + row] = r268;
    sub_words[1224u * row_count + row] = r268;
    sub_words[1266u * row_count + row] = r268;
    sub_words[1308u * row_count + row] = r268;
    sub_words[1350u * row_count + row] = r268;
    sub_words[1392u * row_count + row] = r268;
    sub_words[1434u * row_count + row] = r268;
    sub_words[1435u * row_count + row] = r30;
    sub_words[1436u * row_count + row] = r3246;
    sub_words[1437u * row_count + row] = r3247;
    sub_words[1438u * row_count + row] = r3248;
    sub_words[1439u * row_count + row] = r3249;
    sub_words[1440u * row_count + row] = r3250;
    sub_words[1441u * row_count + row] = r3251;
    sub_words[1442u * row_count + row] = r3252;
    sub_words[1443u * row_count + row] = r3253;
    sub_words[1444u * row_count + row] = r3254;
    sub_words[1445u * row_count + row] = r3255;
    sub_words[1446u * row_count + row] = r3256;
    sub_words[1447u * row_count + row] = r3257;
    sub_words[1448u * row_count + row] = r3258;
    sub_words[1449u * row_count + row] = r3259;
    sub_words[1450u * row_count + row] = r3260;
    sub_words[1451u * row_count + row] = r3261;
    sub_words[1452u * row_count + row] = r3262;
    sub_words[1453u * row_count + row] = r3263;
    sub_words[1454u * row_count + row] = r3264;
    sub_words[1455u * row_count + row] = r3265;
    sub_words[1456u * row_count + row] = r3266;
    sub_words[1457u * row_count + row] = r3267;
    sub_words[1458u * row_count + row] = r3268;
    sub_words[1459u * row_count + row] = r3269;
    sub_words[1460u * row_count + row] = r3270;
    sub_words[1461u * row_count + row] = r3271;
    sub_words[1462u * row_count + row] = r3272;
    sub_words[1463u * row_count + row] = r3273;
    sub_words[1464u * row_count + row] = r3274;
    sub_words[1465u * row_count + row] = r3275;
    sub_words[1466u * row_count + row] = r3276;
    sub_words[1467u * row_count + row] = r3277;
    sub_words[1468u * row_count + row] = r3278;
    sub_words[1469u * row_count + row] = r3279;
    sub_words[1470u * row_count + row] = r3280;
    sub_words[1471u * row_count + row] = r3281;
    sub_words[1472u * row_count + row] = r3282;
    sub_words[1473u * row_count + row] = r3283;
    sub_words[1474u * row_count + row] = r3284;
    sub_words[1475u * row_count + row] = r3285;
    lookup_words[289u * row_count + row] = r268;
    stwo_wit_deduce_poseidon_3_partial_rounds_chain(dargs55, douts55);
    unsigned r3286 = douts55[0];
    unsigned r3287 = douts55[1];
    unsigned r3288 = douts55[2];
    unsigned r3289 = douts55[3];
    unsigned r3290 = douts55[4];
    unsigned r3291 = douts55[5];
    unsigned r3292 = douts55[6];
    unsigned r3293 = douts55[7];
    unsigned r3294 = douts55[8];
    unsigned r3295 = douts55[9];
    unsigned r3296 = douts55[10];
    unsigned r3297 = douts55[11];
    unsigned r3298 = douts55[12];
    unsigned r3299 = douts55[13];
    unsigned r3300 = douts55[14];
    unsigned r3301 = douts55[15];
    unsigned r3302 = douts55[16];
    unsigned r3303 = douts55[17];
    unsigned r3304 = douts55[18];
    unsigned r3305 = douts55[19];
    unsigned r3306 = douts55[20];
    unsigned r3307 = douts55[21];
    unsigned r3308 = douts55[22];
    unsigned r3309 = douts55[23];
    unsigned r3310 = douts55[24];
    unsigned r3311 = douts55[25];
    unsigned r3312 = douts55[26];
    unsigned r3313 = douts55[27];
    unsigned r3314 = douts55[28];
    unsigned r3315 = douts55[29];
    unsigned r3316 = douts55[30];
    unsigned r3317 = douts55[31];
    unsigned r3318 = douts55[32];
    unsigned r3319 = douts55[33];
    unsigned r3320 = douts55[34];
    unsigned r3321 = douts55[35];
    unsigned r3322 = douts55[36];
    unsigned r3323 = douts55[37];
    unsigned r3324 = douts55[38];
    unsigned r3325 = douts55[39];
    unsigned r3326 = douts55[40];
    unsigned r3327 = douts55[41];
    unsigned r3328 = (r3288 & 511u);
    unsigned r3329 = (r3288 >> 9u);
    unsigned r3330 = (r3329 & 511u);
    unsigned r3331 = (r3288 >> 18u);
    unsigned r3332 = (r3331 & 511u);
    unsigned r3333 = (r3289 & 511u);
    unsigned r3334 = (r3289 >> 9u);
    unsigned r3335 = (r3334 & 511u);
    unsigned r3336 = (r3289 >> 18u);
    unsigned r3337 = (r3336 & 511u);
    unsigned r3338 = (r3290 & 511u);
    unsigned r3339 = (r3290 >> 9u);
    unsigned r3340 = (r3339 & 511u);
    unsigned r3341 = (r3290 >> 18u);
    unsigned r3342 = (r3341 & 511u);
    unsigned r3343 = (r3291 & 511u);
    unsigned r3344 = (r3291 >> 9u);
    unsigned r3345 = (r3344 & 511u);
    unsigned r3346 = (r3291 >> 18u);
    unsigned r3347 = (r3346 & 511u);
    unsigned r3348 = (r3292 & 511u);
    unsigned r3349 = (r3292 >> 9u);
    unsigned r3350 = (r3349 & 511u);
    unsigned r3351 = (r3292 >> 18u);
    unsigned r3352 = (r3351 & 511u);
    unsigned r3353 = (r3293 & 511u);
    unsigned r3354 = (r3293 >> 9u);
    unsigned r3355 = (r3354 & 511u);
    unsigned r3356 = (r3293 >> 18u);
    unsigned r3357 = (r3356 & 511u);
    unsigned r3358 = (r3294 & 511u);
    unsigned r3359 = (r3294 >> 9u);
    unsigned r3360 = (r3359 & 511u);
    unsigned r3361 = (r3294 >> 18u);
    unsigned r3362 = (r3361 & 511u);
    unsigned r3363 = (r3295 & 511u);
    unsigned r3364 = (r3295 >> 9u);
    unsigned r3365 = (r3364 & 511u);
    unsigned r3366 = (r3295 >> 18u);
    unsigned r3367 = (r3366 & 511u);
    unsigned r3368 = (r3296 & 511u);
    unsigned r3369 = (r3296 >> 9u);
    unsigned r3370 = (r3369 & 511u);
    unsigned r3371 = (r3296 >> 18u);
    unsigned r3372 = (r3371 & 511u);
    unsigned r3373 = (r3297 & 511u);
    out_cols[204u][row] = r3297;
    lookup_words[300u * row_count + row] = r3297;
    const unsigned dargs56[56] = { r4, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r3328, r3330, r3332, r3333, r3335, r3337, r3338, r3340, r3342, r3343, r3345, r3347, r3348, r3350, r3352, r3353, r3355, r3357, r3358, r3360, r3362, r3363, r3365, r3367, r3368, r3370, r3372, r3373 };
    unsigned douts56[28];
    stwo_wit_deduce_felt_mul(dargs56, douts56);
    unsigned r3374 = douts56[0];
    unsigned r3375 = douts56[1];
    unsigned r3376 = douts56[2];
    unsigned r3377 = douts56[3];
    unsigned r3378 = douts56[4];
    unsigned r3379 = douts56[5];
    unsigned r3380 = douts56[6];
    unsigned r3381 = douts56[7];
    unsigned r3382 = douts56[8];
    unsigned r3383 = douts56[9];
    unsigned r3384 = douts56[10];
    unsigned r3385 = douts56[11];
    unsigned r3386 = douts56[12];
    unsigned r3387 = douts56[13];
    unsigned r3388 = douts56[14];
    unsigned r3389 = douts56[15];
    unsigned r3390 = douts56[16];
    unsigned r3391 = douts56[17];
    unsigned r3392 = douts56[18];
    unsigned r3393 = douts56[19];
    unsigned r3394 = douts56[20];
    unsigned r3395 = douts56[21];
    unsigned r3396 = douts56[22];
    unsigned r3397 = douts56[23];
    unsigned r3398 = douts56[24];
    unsigned r3399 = douts56[25];
    unsigned r3400 = douts56[26];
    unsigned r3401 = douts56[27];
    const unsigned dargs57[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r3374, r3375, r3376, r3377, r3378, r3379, r3380, r3381, r3382, r3383, r3384, r3385, r3386, r3387, r3388, r3389, r3390, r3391, r3392, r3393, r3394, r3395, r3396, r3397, r3398, r3399, r3400, r3401 };
    unsigned douts57[28];
    stwo_wit_deduce_felt_add(dargs57, douts57);
    unsigned r3402 = douts57[0];
    unsigned r3403 = douts57[1];
    unsigned r3404 = douts57[2];
    unsigned r3405 = douts57[3];
    unsigned r3406 = douts57[4];
    unsigned r3407 = douts57[5];
    unsigned r3408 = douts57[6];
    unsigned r3409 = douts57[7];
    unsigned r3410 = douts57[8];
    unsigned r3411 = douts57[9];
    unsigned r3412 = douts57[10];
    unsigned r3413 = douts57[11];
    unsigned r3414 = douts57[12];
    unsigned r3415 = douts57[13];
    unsigned r3416 = douts57[14];
    unsigned r3417 = douts57[15];
    unsigned r3418 = douts57[16];
    unsigned r3419 = douts57[17];
    unsigned r3420 = douts57[18];
    unsigned r3421 = douts57[19];
    unsigned r3422 = douts57[20];
    unsigned r3423 = douts57[21];
    unsigned r3424 = douts57[22];
    unsigned r3425 = douts57[23];
    unsigned r3426 = douts57[24];
    unsigned r3427 = douts57[25];
    unsigned r3428 = douts57[26];
    unsigned r3429 = douts57[27];
    unsigned r3430 = (r3298 & 511u);
    unsigned r3431 = (r3298 >> 9u);
    unsigned r3432 = (r3431 & 511u);
    unsigned r3433 = (r3298 >> 18u);
    unsigned r3434 = (r3433 & 511u);
    unsigned r3435 = (r3299 & 511u);
    unsigned r3436 = (r3299 >> 9u);
    unsigned r3437 = (r3436 & 511u);
    unsigned r3438 = (r3299 >> 18u);
    unsigned r3439 = (r3438 & 511u);
    unsigned r3440 = (r3300 & 511u);
    unsigned r3441 = (r3300 >> 9u);
    unsigned r3442 = (r3441 & 511u);
    unsigned r3443 = (r3300 >> 18u);
    unsigned r3444 = (r3443 & 511u);
    unsigned r3445 = (r3301 & 511u);
    unsigned r3446 = (r3301 >> 9u);
    unsigned r3447 = (r3446 & 511u);
    unsigned r3448 = (r3301 >> 18u);
    unsigned r3449 = (r3448 & 511u);
    unsigned r3450 = (r3302 & 511u);
    unsigned r3451 = (r3302 >> 9u);
    unsigned r3452 = (r3451 & 511u);
    unsigned r3453 = (r3302 >> 18u);
    unsigned r3454 = (r3453 & 511u);
    unsigned r3455 = (r3303 & 511u);
    unsigned r3456 = (r3303 >> 9u);
    unsigned r3457 = (r3456 & 511u);
    unsigned r3458 = (r3303 >> 18u);
    unsigned r3459 = (r3458 & 511u);
    unsigned r3460 = (r3304 & 511u);
    unsigned r3461 = (r3304 >> 9u);
    unsigned r3462 = (r3461 & 511u);
    unsigned r3463 = (r3304 >> 18u);
    unsigned r3464 = (r3463 & 511u);
    unsigned r3465 = (r3305 & 511u);
    unsigned r3466 = (r3305 >> 9u);
    unsigned r3467 = (r3466 & 511u);
    unsigned r3468 = (r3305 >> 18u);
    unsigned r3469 = (r3468 & 511u);
    unsigned r3470 = (r3306 & 511u);
    unsigned r3471 = (r3306 >> 9u);
    unsigned r3472 = (r3471 & 511u);
    unsigned r3473 = (r3306 >> 18u);
    unsigned r3474 = (r3473 & 511u);
    unsigned r3475 = (r3307 & 511u);
    out_cols[214u][row] = r3307;
    lookup_words[310u * row_count + row] = r3307;
    const unsigned dargs58[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r3430, r3432, r3434, r3435, r3437, r3439, r3440, r3442, r3444, r3445, r3447, r3449, r3450, r3452, r3454, r3455, r3457, r3459, r3460, r3462, r3464, r3465, r3467, r3469, r3470, r3472, r3474, r3475 };
    unsigned douts58[28];
    stwo_wit_deduce_felt_mul(dargs58, douts58);
    unsigned r3476 = douts58[0];
    unsigned r3477 = douts58[1];
    unsigned r3478 = douts58[2];
    unsigned r3479 = douts58[3];
    unsigned r3480 = douts58[4];
    unsigned r3481 = douts58[5];
    unsigned r3482 = douts58[6];
    unsigned r3483 = douts58[7];
    unsigned r3484 = douts58[8];
    unsigned r3485 = douts58[9];
    unsigned r3486 = douts58[10];
    unsigned r3487 = douts58[11];
    unsigned r3488 = douts58[12];
    unsigned r3489 = douts58[13];
    unsigned r3490 = douts58[14];
    unsigned r3491 = douts58[15];
    unsigned r3492 = douts58[16];
    unsigned r3493 = douts58[17];
    unsigned r3494 = douts58[18];
    unsigned r3495 = douts58[19];
    unsigned r3496 = douts58[20];
    unsigned r3497 = douts58[21];
    unsigned r3498 = douts58[22];
    unsigned r3499 = douts58[23];
    unsigned r3500 = douts58[24];
    unsigned r3501 = douts58[25];
    unsigned r3502 = douts58[26];
    unsigned r3503 = douts58[27];
    const unsigned dargs59[56] = { r3402, r3403, r3404, r3405, r3406, r3407, r3408, r3409, r3410, r3411, r3412, r3413, r3414, r3415, r3416, r3417, r3418, r3419, r3420, r3421, r3422, r3423, r3424, r3425, r3426, r3427, r3428, r3429, r3476, r3477, r3478, r3479, r3480, r3481, r3482, r3483, r3484, r3485, r3486, r3487, r3488, r3489, r3490, r3491, r3492, r3493, r3494, r3495, r3496, r3497, r3498, r3499, r3500, r3501, r3502, r3503 };
    unsigned douts59[28];
    stwo_wit_deduce_felt_add(dargs59, douts59);
    unsigned r3504 = douts59[0];
    unsigned r3505 = douts59[1];
    unsigned r3506 = douts59[2];
    unsigned r3507 = douts59[3];
    unsigned r3508 = douts59[4];
    unsigned r3509 = douts59[5];
    unsigned r3510 = douts59[6];
    unsigned r3511 = douts59[7];
    unsigned r3512 = douts59[8];
    unsigned r3513 = douts59[9];
    unsigned r3514 = douts59[10];
    unsigned r3515 = douts59[11];
    unsigned r3516 = douts59[12];
    unsigned r3517 = douts59[13];
    unsigned r3518 = douts59[14];
    unsigned r3519 = douts59[15];
    unsigned r3520 = douts59[16];
    unsigned r3521 = douts59[17];
    unsigned r3522 = douts59[18];
    unsigned r3523 = douts59[19];
    unsigned r3524 = douts59[20];
    unsigned r3525 = douts59[21];
    unsigned r3526 = douts59[22];
    unsigned r3527 = douts59[23];
    unsigned r3528 = douts59[24];
    unsigned r3529 = douts59[25];
    unsigned r3530 = douts59[26];
    unsigned r3531 = douts59[27];
    unsigned r3532 = (r3308 & 511u);
    unsigned r3533 = (r3308 >> 9u);
    unsigned r3534 = (r3533 & 511u);
    unsigned r3535 = (r3308 >> 18u);
    unsigned r3536 = (r3535 & 511u);
    unsigned r3537 = (r3309 & 511u);
    unsigned r3538 = (r3309 >> 9u);
    unsigned r3539 = (r3538 & 511u);
    unsigned r3540 = (r3309 >> 18u);
    unsigned r3541 = (r3540 & 511u);
    unsigned r3542 = (r3310 & 511u);
    unsigned r3543 = (r3310 >> 9u);
    unsigned r3544 = (r3543 & 511u);
    unsigned r3545 = (r3310 >> 18u);
    unsigned r3546 = (r3545 & 511u);
    unsigned r3547 = (r3311 & 511u);
    unsigned r3548 = (r3311 >> 9u);
    unsigned r3549 = (r3548 & 511u);
    unsigned r3550 = (r3311 >> 18u);
    unsigned r3551 = (r3550 & 511u);
    unsigned r3552 = (r3312 & 511u);
    unsigned r3553 = (r3312 >> 9u);
    unsigned r3554 = (r3553 & 511u);
    unsigned r3555 = (r3312 >> 18u);
    unsigned r3556 = (r3555 & 511u);
    unsigned r3557 = (r3313 & 511u);
    unsigned r3558 = (r3313 >> 9u);
    unsigned r3559 = (r3558 & 511u);
    unsigned r3560 = (r3313 >> 18u);
    unsigned r3561 = (r3560 & 511u);
    unsigned r3562 = (r3314 & 511u);
    unsigned r3563 = (r3314 >> 9u);
    unsigned r3564 = (r3563 & 511u);
    unsigned r3565 = (r3314 >> 18u);
    unsigned r3566 = (r3565 & 511u);
    unsigned r3567 = (r3315 & 511u);
    unsigned r3568 = (r3315 >> 9u);
    unsigned r3569 = (r3568 & 511u);
    unsigned r3570 = (r3315 >> 18u);
    unsigned r3571 = (r3570 & 511u);
    unsigned r3572 = (r3316 & 511u);
    unsigned r3573 = (r3316 >> 9u);
    unsigned r3574 = (r3573 & 511u);
    unsigned r3575 = (r3316 >> 18u);
    unsigned r3576 = (r3575 & 511u);
    unsigned r3577 = (r3317 & 511u);
    const unsigned dargs60[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r3532, r3534, r3536, r3537, r3539, r3541, r3542, r3544, r3546, r3547, r3549, r3551, r3552, r3554, r3556, r3557, r3559, r3561, r3562, r3564, r3566, r3567, r3569, r3571, r3572, r3574, r3576, r3577 };
    unsigned douts60[28];
    stwo_wit_deduce_felt_mul(dargs60, douts60);
    unsigned r3578 = douts60[0];
    unsigned r3579 = douts60[1];
    unsigned r3580 = douts60[2];
    unsigned r3581 = douts60[3];
    unsigned r3582 = douts60[4];
    unsigned r3583 = douts60[5];
    unsigned r3584 = douts60[6];
    unsigned r3585 = douts60[7];
    unsigned r3586 = douts60[8];
    unsigned r3587 = douts60[9];
    unsigned r3588 = douts60[10];
    unsigned r3589 = douts60[11];
    unsigned r3590 = douts60[12];
    unsigned r3591 = douts60[13];
    unsigned r3592 = douts60[14];
    unsigned r3593 = douts60[15];
    unsigned r3594 = douts60[16];
    unsigned r3595 = douts60[17];
    unsigned r3596 = douts60[18];
    unsigned r3597 = douts60[19];
    unsigned r3598 = douts60[20];
    unsigned r3599 = douts60[21];
    unsigned r3600 = douts60[22];
    unsigned r3601 = douts60[23];
    unsigned r3602 = douts60[24];
    unsigned r3603 = douts60[25];
    unsigned r3604 = douts60[26];
    unsigned r3605 = douts60[27];
    const unsigned dargs61[56] = { r3504, r3505, r3506, r3507, r3508, r3509, r3510, r3511, r3512, r3513, r3514, r3515, r3516, r3517, r3518, r3519, r3520, r3521, r3522, r3523, r3524, r3525, r3526, r3527, r3528, r3529, r3530, r3531, r3578, r3579, r3580, r3581, r3582, r3583, r3584, r3585, r3586, r3587, r3588, r3589, r3590, r3591, r3592, r3593, r3594, r3595, r3596, r3597, r3598, r3599, r3600, r3601, r3602, r3603, r3604, r3605 };
    unsigned douts61[28];
    stwo_wit_deduce_felt_add(dargs61, douts61);
    unsigned r3606 = douts61[0];
    unsigned r3607 = douts61[1];
    unsigned r3608 = douts61[2];
    unsigned r3609 = douts61[3];
    unsigned r3610 = douts61[4];
    unsigned r3611 = douts61[5];
    unsigned r3612 = douts61[6];
    unsigned r3613 = douts61[7];
    unsigned r3614 = douts61[8];
    unsigned r3615 = douts61[9];
    unsigned r3616 = douts61[10];
    unsigned r3617 = douts61[11];
    unsigned r3618 = douts61[12];
    unsigned r3619 = douts61[13];
    unsigned r3620 = douts61[14];
    unsigned r3621 = douts61[15];
    unsigned r3622 = douts61[16];
    unsigned r3623 = douts61[17];
    unsigned r3624 = douts61[18];
    unsigned r3625 = douts61[19];
    unsigned r3626 = douts61[20];
    unsigned r3627 = douts61[21];
    unsigned r3628 = douts61[22];
    unsigned r3629 = douts61[23];
    unsigned r3630 = douts61[24];
    unsigned r3631 = douts61[25];
    unsigned r3632 = douts61[26];
    unsigned r3633 = douts61[27];
    const unsigned dargs62[56] = { r3606, r3607, r3608, r3609, r3610, r3611, r3612, r3613, r3614, r3615, r3616, r3617, r3618, r3619, r3620, r3621, r3622, r3623, r3624, r3625, r3626, r3627, r3628, r3629, r3630, r3631, r3632, r3633, r190, r76, r74, r137, r18, r87, r100, r149, r97, r141, r67, r168, r147, r73, r136, r64, r153, r80, r27, r170, r108, r154, r40, r126, r129, r81, r50, r55 };
    unsigned douts62[28];
    sub_words[931u * row_count + row] = r18;
    sub_words[1309u * row_count + row] = r27;
    stwo_wit_deduce_felt_add(dargs62, douts62);
    unsigned r3634 = douts62[0];
    unsigned r3635 = douts62[1];
    unsigned r3636 = douts62[2];
    unsigned r3637 = douts62[3];
    unsigned r3638 = douts62[4];
    unsigned r3639 = douts62[5];
    unsigned r3640 = douts62[6];
    unsigned r3641 = douts62[7];
    unsigned r3642 = douts62[8];
    unsigned r3643 = douts62[9];
    unsigned r3644 = douts62[10];
    unsigned r3645 = douts62[11];
    unsigned r3646 = douts62[12];
    unsigned r3647 = douts62[13];
    unsigned r3648 = douts62[14];
    unsigned r3649 = douts62[15];
    unsigned r3650 = douts62[16];
    unsigned r3651 = douts62[17];
    unsigned r3652 = douts62[18];
    unsigned r3653 = douts62[19];
    unsigned r3654 = douts62[20];
    unsigned r3655 = douts62[21];
    unsigned r3656 = douts62[22];
    unsigned r3657 = douts62[23];
    unsigned r3658 = douts62[24];
    unsigned r3659 = douts62[25];
    unsigned r3660 = douts62[26];
    unsigned r3661 = douts62[27];
    unsigned r3662 = stwo_m31_mul(r3635, r191);
    unsigned r3663 = stwo_m31_add(r3634, r3662);
    unsigned r3664 = stwo_m31_mul(r3636, r193);
    unsigned r3665 = stwo_m31_add(r3663, r3664);
    unsigned r3666 = stwo_m31_mul(r3638, r191);
    unsigned r3667 = stwo_m31_add(r3637, r3666);
    unsigned r3668 = stwo_m31_mul(r3639, r193);
    unsigned r3669 = stwo_m31_add(r3667, r3668);
    unsigned r3670 = stwo_m31_mul(r3641, r191);
    unsigned r3671 = stwo_m31_add(r3640, r3670);
    unsigned r3672 = stwo_m31_mul(r3642, r193);
    unsigned r3673 = stwo_m31_add(r3671, r3672);
    unsigned r3674 = stwo_m31_mul(r3644, r191);
    unsigned r3675 = stwo_m31_add(r3643, r3674);
    unsigned r3676 = stwo_m31_mul(r3645, r193);
    unsigned r3677 = stwo_m31_add(r3675, r3676);
    unsigned r3678 = stwo_m31_mul(r3647, r191);
    unsigned r3679 = stwo_m31_add(r3646, r3678);
    unsigned r3680 = stwo_m31_mul(r3648, r193);
    unsigned r3681 = stwo_m31_add(r3679, r3680);
    unsigned r3682 = stwo_m31_mul(r3650, r191);
    unsigned r3683 = stwo_m31_add(r3649, r3682);
    unsigned r3684 = stwo_m31_mul(r3651, r193);
    unsigned r3685 = stwo_m31_add(r3683, r3684);
    unsigned r3686 = stwo_m31_mul(r3653, r191);
    unsigned r3687 = stwo_m31_add(r3652, r3686);
    unsigned r3688 = stwo_m31_mul(r3654, r193);
    unsigned r3689 = stwo_m31_add(r3687, r3688);
    unsigned r3690 = stwo_m31_mul(r3656, r191);
    unsigned r3691 = stwo_m31_add(r3655, r3690);
    unsigned r3692 = stwo_m31_mul(r3657, r193);
    unsigned r3693 = stwo_m31_add(r3691, r3692);
    unsigned r3694 = stwo_m31_mul(r3659, r191);
    unsigned r3695 = stwo_m31_add(r3658, r3694);
    unsigned r3696 = stwo_m31_mul(r3660, r193);
    unsigned r3697 = stwo_m31_add(r3695, r3696);
    unsigned r3698 = stwo_m31_mul(r4, r3288);
    unsigned r3699 = stwo_m31_mul(r2, r3298);
    unsigned r3700 = stwo_m31_add(r3698, r3699);
    unsigned r3701 = stwo_m31_add(r3700, r3308);
    unsigned r3702 = stwo_m31_add(r3701, r204);
    unsigned r3703 = stwo_m31_sub(r3702, r3665);
    unsigned r3704 = stwo_m31_add(r3703, r257);
    unsigned r3705 = (r3704 & 65535u);
    unsigned r3706 = (r3705 % STWO_M31_P);
    unsigned r3707 = stwo_m31_sub(r3706, r1);
    unsigned r3708 = stwo_m31_mul(r4, r3288);
    out_cols[195u][row] = r3288;
    lookup_words[291u * row_count + row] = r3288;
    unsigned r3709 = stwo_m31_mul(r2, r3298);
    out_cols[205u][row] = r3298;
    lookup_words[301u * row_count + row] = r3298;
    unsigned r3710 = stwo_m31_add(r3708, r3709);
    unsigned r3711 = stwo_m31_add(r3710, r3308);
    unsigned r3712 = stwo_m31_add(r3711, r204);
    unsigned r3713 = stwo_m31_sub(r3712, r3665);
    unsigned r3714 = stwo_m31_sub(r3713, r3707);
    unsigned r3715 = stwo_m31_mul(r3714, r16);
    unsigned r3716 = stwo_m31_mul(r4, r3289);
    out_cols[196u][row] = r3289;
    lookup_words[292u * row_count + row] = r3289;
    unsigned r3717 = stwo_m31_add(r3715, r3716);
    unsigned r3718 = stwo_m31_mul(r2, r3299);
    out_cols[206u][row] = r3299;
    lookup_words[302u * row_count + row] = r3299;
    unsigned r3719 = stwo_m31_add(r3717, r3718);
    unsigned r3720 = stwo_m31_add(r3719, r3309);
    unsigned r3721 = stwo_m31_add(r3720, r215);
    unsigned r3722 = stwo_m31_sub(r3721, r3669);
    unsigned r3723 = stwo_m31_mul(r3722, r16);
    unsigned r3724 = stwo_m31_mul(r4, r3290);
    out_cols[197u][row] = r3290;
    lookup_words[293u * row_count + row] = r3290;
    unsigned r3725 = stwo_m31_add(r3723, r3724);
    unsigned r3726 = stwo_m31_mul(r2, r3300);
    out_cols[207u][row] = r3300;
    lookup_words[303u * row_count + row] = r3300;
    unsigned r3727 = stwo_m31_add(r3725, r3726);
    unsigned r3728 = stwo_m31_add(r3727, r3310);
    unsigned r3729 = stwo_m31_add(r3728, r219);
    unsigned r3730 = stwo_m31_sub(r3729, r3673);
    unsigned r3731 = stwo_m31_mul(r3730, r16);
    unsigned r3732 = stwo_m31_mul(r4, r3291);
    out_cols[198u][row] = r3291;
    lookup_words[294u * row_count + row] = r3291;
    unsigned r3733 = stwo_m31_add(r3731, r3732);
    unsigned r3734 = stwo_m31_mul(r2, r3301);
    out_cols[208u][row] = r3301;
    lookup_words[304u * row_count + row] = r3301;
    unsigned r3735 = stwo_m31_add(r3733, r3734);
    unsigned r3736 = stwo_m31_add(r3735, r3311);
    unsigned r3737 = stwo_m31_add(r3736, r247);
    unsigned r3738 = stwo_m31_sub(r3737, r3677);
    unsigned r3739 = stwo_m31_mul(r3738, r16);
    unsigned r3740 = stwo_m31_mul(r4, r3292);
    out_cols[199u][row] = r3292;
    lookup_words[295u * row_count + row] = r3292;
    unsigned r3741 = stwo_m31_add(r3739, r3740);
    unsigned r3742 = stwo_m31_mul(r2, r3302);
    out_cols[209u][row] = r3302;
    lookup_words[305u * row_count + row] = r3302;
    unsigned r3743 = stwo_m31_add(r3741, r3742);
    unsigned r3744 = stwo_m31_add(r3743, r3312);
    unsigned r3745 = stwo_m31_add(r3744, r236);
    unsigned r3746 = stwo_m31_sub(r3745, r3681);
    unsigned r3747 = stwo_m31_mul(r3746, r16);
    unsigned r3748 = stwo_m31_mul(r4, r3293);
    out_cols[200u][row] = r3293;
    lookup_words[296u * row_count + row] = r3293;
    unsigned r3749 = stwo_m31_add(r3747, r3748);
    unsigned r3750 = stwo_m31_mul(r2, r3303);
    out_cols[210u][row] = r3303;
    lookup_words[306u * row_count + row] = r3303;
    unsigned r3751 = stwo_m31_add(r3749, r3750);
    unsigned r3752 = stwo_m31_add(r3751, r3313);
    unsigned r3753 = stwo_m31_add(r3752, r210);
    unsigned r3754 = stwo_m31_sub(r3753, r3685);
    unsigned r3755 = stwo_m31_mul(r3754, r16);
    unsigned r3756 = stwo_m31_mul(r4, r3294);
    out_cols[201u][row] = r3294;
    lookup_words[297u * row_count + row] = r3294;
    unsigned r3757 = stwo_m31_add(r3755, r3756);
    unsigned r3758 = stwo_m31_mul(r2, r3304);
    out_cols[211u][row] = r3304;
    lookup_words[307u * row_count + row] = r3304;
    unsigned r3759 = stwo_m31_add(r3757, r3758);
    unsigned r3760 = stwo_m31_add(r3759, r3314);
    unsigned r3761 = stwo_m31_add(r3760, r225);
    unsigned r3762 = stwo_m31_sub(r3761, r3689);
    unsigned r3763 = stwo_m31_mul(r3762, r16);
    unsigned r3764 = stwo_m31_mul(r4, r3295);
    out_cols[202u][row] = r3295;
    lookup_words[298u * row_count + row] = r3295;
    unsigned r3765 = stwo_m31_add(r3763, r3764);
    unsigned r3766 = stwo_m31_mul(r2, r3305);
    out_cols[212u][row] = r3305;
    lookup_words[308u * row_count + row] = r3305;
    unsigned r3767 = stwo_m31_add(r3765, r3766);
    unsigned r3768 = stwo_m31_add(r3767, r3315);
    unsigned r3769 = stwo_m31_add(r3768, r232);
    unsigned r3770 = stwo_m31_sub(r3769, r3693);
    unsigned r3771 = stwo_m31_mul(r3707, r67);
    unsigned r3772 = stwo_m31_sub(r3770, r3771);
    unsigned r3773 = stwo_m31_mul(r3772, r16);
    unsigned r3774 = stwo_m31_mul(r4, r3296);
    out_cols[203u][row] = r3296;
    lookup_words[299u * row_count + row] = r3296;
    unsigned r3775 = stwo_m31_add(r3773, r3774);
    unsigned r3776 = stwo_m31_mul(r2, r3306);
    out_cols[213u][row] = r3306;
    lookup_words[309u * row_count + row] = r3306;
    unsigned r3777 = stwo_m31_add(r3775, r3776);
    unsigned r3778 = stwo_m31_add(r3777, r3316);
    unsigned r3779 = stwo_m31_add(r3778, r199);
    unsigned r3780 = stwo_m31_sub(r3779, r3697);
    unsigned r3781 = stwo_m31_mul(r3780, r16);
    unsigned r3782 = stwo_m31_add(r3707, r1);
    sub_words[320u * row_count + row] = r3782;
    unsigned r3783 = stwo_m31_add(r3715, r1);
    sub_words[321u * row_count + row] = r3783;
    unsigned r3784 = stwo_m31_add(r3723, r1);
    sub_words[322u * row_count + row] = r3784;
    unsigned r3785 = stwo_m31_add(r3731, r1);
    sub_words[323u * row_count + row] = r3785;
    unsigned r3786 = stwo_m31_add(r3707, r1);
    out_cols[245u][row] = r3707;
    lookup_words[332u * row_count + row] = r3786;
    unsigned r3787 = stwo_m31_add(r3715, r1);
    lookup_words[333u * row_count + row] = r3787;
    unsigned r3788 = stwo_m31_add(r3723, r1);
    lookup_words[334u * row_count + row] = r3788;
    unsigned r3789 = stwo_m31_add(r3731, r1);
    lookup_words[335u * row_count + row] = r3789;
    unsigned r3790 = stwo_m31_add(r3739, r1);
    sub_words[324u * row_count + row] = r3790;
    unsigned r3791 = stwo_m31_add(r3747, r1);
    sub_words[325u * row_count + row] = r3791;
    unsigned r3792 = stwo_m31_add(r3755, r1);
    sub_words[326u * row_count + row] = r3792;
    unsigned r3793 = stwo_m31_add(r3763, r1);
    sub_words[327u * row_count + row] = r3793;
    unsigned r3794 = stwo_m31_add(r3739, r1);
    lookup_words[337u * row_count + row] = r3794;
    unsigned r3795 = stwo_m31_add(r3747, r1);
    lookup_words[338u * row_count + row] = r3795;
    unsigned r3796 = stwo_m31_add(r3755, r1);
    lookup_words[339u * row_count + row] = r3796;
    unsigned r3797 = stwo_m31_add(r3763, r1);
    lookup_words[340u * row_count + row] = r3797;
    unsigned r3798 = stwo_m31_add(r3773, r1);
    sub_words[338u * row_count + row] = r3798;
    unsigned r3799 = stwo_m31_add(r3781, r1);
    sub_words[339u * row_count + row] = r3799;
    unsigned r3800 = stwo_m31_add(r3773, r1);
    lookup_words[342u * row_count + row] = r3800;
    unsigned r3801 = stwo_m31_add(r3781, r1);
    lookup_words[343u * row_count + row] = r3801;
    unsigned r3802 = (r3308 & 511u);
    unsigned r3803 = (r3308 >> 9u);
    unsigned r3804 = (r3803 & 511u);
    unsigned r3805 = (r3308 >> 18u);
    unsigned r3806 = (r3805 & 511u);
    unsigned r3807 = (r3309 & 511u);
    unsigned r3808 = (r3309 >> 9u);
    unsigned r3809 = (r3808 & 511u);
    unsigned r3810 = (r3309 >> 18u);
    unsigned r3811 = (r3810 & 511u);
    unsigned r3812 = (r3310 & 511u);
    unsigned r3813 = (r3310 >> 9u);
    unsigned r3814 = (r3813 & 511u);
    unsigned r3815 = (r3310 >> 18u);
    unsigned r3816 = (r3815 & 511u);
    unsigned r3817 = (r3311 & 511u);
    unsigned r3818 = (r3311 >> 9u);
    unsigned r3819 = (r3818 & 511u);
    unsigned r3820 = (r3311 >> 18u);
    unsigned r3821 = (r3820 & 511u);
    unsigned r3822 = (r3312 & 511u);
    unsigned r3823 = (r3312 >> 9u);
    unsigned r3824 = (r3823 & 511u);
    unsigned r3825 = (r3312 >> 18u);
    unsigned r3826 = (r3825 & 511u);
    unsigned r3827 = (r3313 & 511u);
    unsigned r3828 = (r3313 >> 9u);
    unsigned r3829 = (r3828 & 511u);
    unsigned r3830 = (r3313 >> 18u);
    unsigned r3831 = (r3830 & 511u);
    unsigned r3832 = (r3314 & 511u);
    unsigned r3833 = (r3314 >> 9u);
    unsigned r3834 = (r3833 & 511u);
    unsigned r3835 = (r3314 >> 18u);
    unsigned r3836 = (r3835 & 511u);
    unsigned r3837 = (r3315 & 511u);
    unsigned r3838 = (r3315 >> 9u);
    unsigned r3839 = (r3838 & 511u);
    unsigned r3840 = (r3315 >> 18u);
    unsigned r3841 = (r3840 & 511u);
    unsigned r3842 = (r3316 & 511u);
    unsigned r3843 = (r3316 >> 9u);
    unsigned r3844 = (r3843 & 511u);
    unsigned r3845 = (r3316 >> 18u);
    unsigned r3846 = (r3845 & 511u);
    unsigned r3847 = (r3317 & 511u);
    out_cols[224u][row] = r3317;
    lookup_words[320u * row_count + row] = r3317;
    const unsigned dargs63[56] = { r4, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r3802, r3804, r3806, r3807, r3809, r3811, r3812, r3814, r3816, r3817, r3819, r3821, r3822, r3824, r3826, r3827, r3829, r3831, r3832, r3834, r3836, r3837, r3839, r3841, r3842, r3844, r3846, r3847 };
    unsigned douts63[28];
    stwo_wit_deduce_felt_mul(dargs63, douts63);
    unsigned r3848 = douts63[0];
    unsigned r3849 = douts63[1];
    unsigned r3850 = douts63[2];
    unsigned r3851 = douts63[3];
    unsigned r3852 = douts63[4];
    unsigned r3853 = douts63[5];
    unsigned r3854 = douts63[6];
    unsigned r3855 = douts63[7];
    unsigned r3856 = douts63[8];
    unsigned r3857 = douts63[9];
    unsigned r3858 = douts63[10];
    unsigned r3859 = douts63[11];
    unsigned r3860 = douts63[12];
    unsigned r3861 = douts63[13];
    unsigned r3862 = douts63[14];
    unsigned r3863 = douts63[15];
    unsigned r3864 = douts63[16];
    unsigned r3865 = douts63[17];
    unsigned r3866 = douts63[18];
    unsigned r3867 = douts63[19];
    unsigned r3868 = douts63[20];
    unsigned r3869 = douts63[21];
    unsigned r3870 = douts63[22];
    unsigned r3871 = douts63[23];
    unsigned r3872 = douts63[24];
    unsigned r3873 = douts63[25];
    unsigned r3874 = douts63[26];
    unsigned r3875 = douts63[27];
    const unsigned dargs64[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r3848, r3849, r3850, r3851, r3852, r3853, r3854, r3855, r3856, r3857, r3858, r3859, r3860, r3861, r3862, r3863, r3864, r3865, r3866, r3867, r3868, r3869, r3870, r3871, r3872, r3873, r3874, r3875 };
    unsigned douts64[28];
    stwo_wit_deduce_felt_add(dargs64, douts64);
    unsigned r3876 = douts64[0];
    unsigned r3877 = douts64[1];
    unsigned r3878 = douts64[2];
    unsigned r3879 = douts64[3];
    unsigned r3880 = douts64[4];
    unsigned r3881 = douts64[5];
    unsigned r3882 = douts64[6];
    unsigned r3883 = douts64[7];
    unsigned r3884 = douts64[8];
    unsigned r3885 = douts64[9];
    unsigned r3886 = douts64[10];
    unsigned r3887 = douts64[11];
    unsigned r3888 = douts64[12];
    unsigned r3889 = douts64[13];
    unsigned r3890 = douts64[14];
    unsigned r3891 = douts64[15];
    unsigned r3892 = douts64[16];
    unsigned r3893 = douts64[17];
    unsigned r3894 = douts64[18];
    unsigned r3895 = douts64[19];
    unsigned r3896 = douts64[20];
    unsigned r3897 = douts64[21];
    unsigned r3898 = douts64[22];
    unsigned r3899 = douts64[23];
    unsigned r3900 = douts64[24];
    unsigned r3901 = douts64[25];
    unsigned r3902 = douts64[26];
    unsigned r3903 = douts64[27];
    unsigned r3904 = (r3318 & 511u);
    unsigned r3905 = (r3318 >> 9u);
    unsigned r3906 = (r3905 & 511u);
    unsigned r3907 = (r3318 >> 18u);
    unsigned r3908 = (r3907 & 511u);
    unsigned r3909 = (r3319 & 511u);
    unsigned r3910 = (r3319 >> 9u);
    unsigned r3911 = (r3910 & 511u);
    unsigned r3912 = (r3319 >> 18u);
    unsigned r3913 = (r3912 & 511u);
    unsigned r3914 = (r3320 & 511u);
    unsigned r3915 = (r3320 >> 9u);
    unsigned r3916 = (r3915 & 511u);
    unsigned r3917 = (r3320 >> 18u);
    unsigned r3918 = (r3917 & 511u);
    unsigned r3919 = (r3321 & 511u);
    unsigned r3920 = (r3321 >> 9u);
    unsigned r3921 = (r3920 & 511u);
    unsigned r3922 = (r3321 >> 18u);
    unsigned r3923 = (r3922 & 511u);
    unsigned r3924 = (r3322 & 511u);
    unsigned r3925 = (r3322 >> 9u);
    unsigned r3926 = (r3925 & 511u);
    unsigned r3927 = (r3322 >> 18u);
    unsigned r3928 = (r3927 & 511u);
    unsigned r3929 = (r3323 & 511u);
    unsigned r3930 = (r3323 >> 9u);
    unsigned r3931 = (r3930 & 511u);
    unsigned r3932 = (r3323 >> 18u);
    unsigned r3933 = (r3932 & 511u);
    unsigned r3934 = (r3324 & 511u);
    unsigned r3935 = (r3324 >> 9u);
    unsigned r3936 = (r3935 & 511u);
    unsigned r3937 = (r3324 >> 18u);
    unsigned r3938 = (r3937 & 511u);
    unsigned r3939 = (r3325 & 511u);
    unsigned r3940 = (r3325 >> 9u);
    unsigned r3941 = (r3940 & 511u);
    unsigned r3942 = (r3325 >> 18u);
    unsigned r3943 = (r3942 & 511u);
    unsigned r3944 = (r3326 & 511u);
    unsigned r3945 = (r3326 >> 9u);
    unsigned r3946 = (r3945 & 511u);
    unsigned r3947 = (r3326 >> 18u);
    unsigned r3948 = (r3947 & 511u);
    unsigned r3949 = (r3327 & 511u);
    const unsigned dargs65[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r3904, r3906, r3908, r3909, r3911, r3913, r3914, r3916, r3918, r3919, r3921, r3923, r3924, r3926, r3928, r3929, r3931, r3933, r3934, r3936, r3938, r3939, r3941, r3943, r3944, r3946, r3948, r3949 };
    unsigned douts65[28];
    stwo_wit_deduce_felt_mul(dargs65, douts65);
    unsigned r3950 = douts65[0];
    unsigned r3951 = douts65[1];
    unsigned r3952 = douts65[2];
    unsigned r3953 = douts65[3];
    unsigned r3954 = douts65[4];
    unsigned r3955 = douts65[5];
    unsigned r3956 = douts65[6];
    unsigned r3957 = douts65[7];
    unsigned r3958 = douts65[8];
    unsigned r3959 = douts65[9];
    unsigned r3960 = douts65[10];
    unsigned r3961 = douts65[11];
    unsigned r3962 = douts65[12];
    unsigned r3963 = douts65[13];
    unsigned r3964 = douts65[14];
    unsigned r3965 = douts65[15];
    unsigned r3966 = douts65[16];
    unsigned r3967 = douts65[17];
    unsigned r3968 = douts65[18];
    unsigned r3969 = douts65[19];
    unsigned r3970 = douts65[20];
    unsigned r3971 = douts65[21];
    unsigned r3972 = douts65[22];
    unsigned r3973 = douts65[23];
    unsigned r3974 = douts65[24];
    unsigned r3975 = douts65[25];
    unsigned r3976 = douts65[26];
    unsigned r3977 = douts65[27];
    const unsigned dargs66[56] = { r3876, r3877, r3878, r3879, r3880, r3881, r3882, r3883, r3884, r3885, r3886, r3887, r3888, r3889, r3890, r3891, r3892, r3893, r3894, r3895, r3896, r3897, r3898, r3899, r3900, r3901, r3902, r3903, r3950, r3951, r3952, r3953, r3954, r3955, r3956, r3957, r3958, r3959, r3960, r3961, r3962, r3963, r3964, r3965, r3966, r3967, r3968, r3969, r3970, r3971, r3972, r3973, r3974, r3975, r3976, r3977 };
    unsigned douts66[28];
    stwo_wit_deduce_felt_add(dargs66, douts66);
    unsigned r3978 = douts66[0];
    unsigned r3979 = douts66[1];
    unsigned r3980 = douts66[2];
    unsigned r3981 = douts66[3];
    unsigned r3982 = douts66[4];
    unsigned r3983 = douts66[5];
    unsigned r3984 = douts66[6];
    unsigned r3985 = douts66[7];
    unsigned r3986 = douts66[8];
    unsigned r3987 = douts66[9];
    unsigned r3988 = douts66[10];
    unsigned r3989 = douts66[11];
    unsigned r3990 = douts66[12];
    unsigned r3991 = douts66[13];
    unsigned r3992 = douts66[14];
    unsigned r3993 = douts66[15];
    unsigned r3994 = douts66[16];
    unsigned r3995 = douts66[17];
    unsigned r3996 = douts66[18];
    unsigned r3997 = douts66[19];
    unsigned r3998 = douts66[20];
    unsigned r3999 = douts66[21];
    unsigned r4000 = douts66[22];
    unsigned r4001 = douts66[23];
    unsigned r4002 = douts66[24];
    unsigned r4003 = douts66[25];
    unsigned r4004 = douts66[26];
    unsigned r4005 = douts66[27];
    unsigned r4006 = (r3665 & 511u);
    unsigned r4007 = (r3665 >> 9u);
    unsigned r4008 = (r4007 & 511u);
    unsigned r4009 = (r3665 >> 18u);
    unsigned r4010 = (r4009 & 511u);
    unsigned r4011 = (r3669 & 511u);
    unsigned r4012 = (r3669 >> 9u);
    unsigned r4013 = (r4012 & 511u);
    unsigned r4014 = (r3669 >> 18u);
    unsigned r4015 = (r4014 & 511u);
    unsigned r4016 = (r3673 & 511u);
    unsigned r4017 = (r3673 >> 9u);
    unsigned r4018 = (r4017 & 511u);
    unsigned r4019 = (r3673 >> 18u);
    unsigned r4020 = (r4019 & 511u);
    unsigned r4021 = (r3677 & 511u);
    unsigned r4022 = (r3677 >> 9u);
    unsigned r4023 = (r4022 & 511u);
    unsigned r4024 = (r3677 >> 18u);
    unsigned r4025 = (r4024 & 511u);
    unsigned r4026 = (r3681 & 511u);
    unsigned r4027 = (r3681 >> 9u);
    unsigned r4028 = (r4027 & 511u);
    unsigned r4029 = (r3681 >> 18u);
    unsigned r4030 = (r4029 & 511u);
    unsigned r4031 = (r3685 & 511u);
    unsigned r4032 = (r3685 >> 9u);
    unsigned r4033 = (r4032 & 511u);
    unsigned r4034 = (r3685 >> 18u);
    unsigned r4035 = (r4034 & 511u);
    unsigned r4036 = (r3689 & 511u);
    unsigned r4037 = (r3689 >> 9u);
    unsigned r4038 = (r4037 & 511u);
    unsigned r4039 = (r3689 >> 18u);
    unsigned r4040 = (r4039 & 511u);
    unsigned r4041 = (r3693 & 511u);
    unsigned r4042 = (r3693 >> 9u);
    unsigned r4043 = (r4042 & 511u);
    unsigned r4044 = (r3693 >> 18u);
    unsigned r4045 = (r4044 & 511u);
    unsigned r4046 = (r3697 & 511u);
    unsigned r4047 = (r3697 >> 9u);
    unsigned r4048 = (r4047 & 511u);
    unsigned r4049 = (r3697 >> 18u);
    unsigned r4050 = (r4049 & 511u);
    unsigned r4051 = (r3661 & 511u);
    const unsigned dargs67[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r4006, r4008, r4010, r4011, r4013, r4015, r4016, r4018, r4020, r4021, r4023, r4025, r4026, r4028, r4030, r4031, r4033, r4035, r4036, r4038, r4040, r4041, r4043, r4045, r4046, r4048, r4050, r4051 };
    unsigned douts67[28];
    lookup_words[92u * row_count + row] = r0;
    sub_words[7u * row_count + row] = r0;
    stwo_wit_deduce_felt_mul(dargs67, douts67);
    unsigned r4052 = douts67[0];
    unsigned r4053 = douts67[1];
    unsigned r4054 = douts67[2];
    unsigned r4055 = douts67[3];
    unsigned r4056 = douts67[4];
    unsigned r4057 = douts67[5];
    unsigned r4058 = douts67[6];
    unsigned r4059 = douts67[7];
    unsigned r4060 = douts67[8];
    unsigned r4061 = douts67[9];
    unsigned r4062 = douts67[10];
    unsigned r4063 = douts67[11];
    unsigned r4064 = douts67[12];
    unsigned r4065 = douts67[13];
    unsigned r4066 = douts67[14];
    unsigned r4067 = douts67[15];
    unsigned r4068 = douts67[16];
    unsigned r4069 = douts67[17];
    unsigned r4070 = douts67[18];
    unsigned r4071 = douts67[19];
    unsigned r4072 = douts67[20];
    unsigned r4073 = douts67[21];
    unsigned r4074 = douts67[22];
    unsigned r4075 = douts67[23];
    unsigned r4076 = douts67[24];
    unsigned r4077 = douts67[25];
    unsigned r4078 = douts67[26];
    unsigned r4079 = douts67[27];
    const unsigned dargs68[56] = { r3978, r3979, r3980, r3981, r3982, r3983, r3984, r3985, r3986, r3987, r3988, r3989, r3990, r3991, r3992, r3993, r3994, r3995, r3996, r3997, r3998, r3999, r4000, r4001, r4002, r4003, r4004, r4005, r4052, r4053, r4054, r4055, r4056, r4057, r4058, r4059, r4060, r4061, r4062, r4063, r4064, r4065, r4066, r4067, r4068, r4069, r4070, r4071, r4072, r4073, r4074, r4075, r4076, r4077, r4078, r4079 };
    unsigned douts68[28];
    stwo_wit_deduce_felt_add(dargs68, douts68);
    unsigned r4080 = douts68[0];
    unsigned r4081 = douts68[1];
    unsigned r4082 = douts68[2];
    unsigned r4083 = douts68[3];
    unsigned r4084 = douts68[4];
    unsigned r4085 = douts68[5];
    unsigned r4086 = douts68[6];
    unsigned r4087 = douts68[7];
    unsigned r4088 = douts68[8];
    unsigned r4089 = douts68[9];
    unsigned r4090 = douts68[10];
    unsigned r4091 = douts68[11];
    unsigned r4092 = douts68[12];
    unsigned r4093 = douts68[13];
    unsigned r4094 = douts68[14];
    unsigned r4095 = douts68[15];
    unsigned r4096 = douts68[16];
    unsigned r4097 = douts68[17];
    unsigned r4098 = douts68[18];
    unsigned r4099 = douts68[19];
    unsigned r4100 = douts68[20];
    unsigned r4101 = douts68[21];
    unsigned r4102 = douts68[22];
    unsigned r4103 = douts68[23];
    unsigned r4104 = douts68[24];
    unsigned r4105 = douts68[25];
    unsigned r4106 = douts68[26];
    unsigned r4107 = douts68[27];
    const unsigned dargs69[56] = { r4080, r4081, r4082, r4083, r4084, r4085, r4086, r4087, r4088, r4089, r4090, r4091, r4092, r4093, r4094, r4095, r4096, r4097, r4098, r4099, r4100, r4101, r4102, r4103, r4104, r4105, r4106, r4107, r101, r124, r84, r131, r166, r83, r41, r106, r98, r171, r110, r112, r49, r70, r115, r180, r19, r171, r125, r122, r62, r188, r33, r102, r61, r128, r46, r20 };
    unsigned douts69[28];
    sub_words[973u * row_count + row] = r19;
    sub_words[1015u * row_count + row] = r20;
    stwo_wit_deduce_felt_add(dargs69, douts69);
    unsigned r4108 = douts69[0];
    unsigned r4109 = douts69[1];
    unsigned r4110 = douts69[2];
    unsigned r4111 = douts69[3];
    unsigned r4112 = douts69[4];
    unsigned r4113 = douts69[5];
    unsigned r4114 = douts69[6];
    unsigned r4115 = douts69[7];
    unsigned r4116 = douts69[8];
    unsigned r4117 = douts69[9];
    unsigned r4118 = douts69[10];
    unsigned r4119 = douts69[11];
    unsigned r4120 = douts69[12];
    unsigned r4121 = douts69[13];
    unsigned r4122 = douts69[14];
    unsigned r4123 = douts69[15];
    unsigned r4124 = douts69[16];
    unsigned r4125 = douts69[17];
    unsigned r4126 = douts69[18];
    unsigned r4127 = douts69[19];
    unsigned r4128 = douts69[20];
    unsigned r4129 = douts69[21];
    unsigned r4130 = douts69[22];
    unsigned r4131 = douts69[23];
    unsigned r4132 = douts69[24];
    unsigned r4133 = douts69[25];
    unsigned r4134 = douts69[26];
    unsigned r4135 = douts69[27];
    unsigned r4136 = stwo_m31_mul(r4109, r191);
    unsigned r4137 = stwo_m31_add(r4108, r4136);
    unsigned r4138 = stwo_m31_mul(r4110, r193);
    unsigned r4139 = stwo_m31_add(r4137, r4138);
    unsigned r4140 = stwo_m31_mul(r4112, r191);
    unsigned r4141 = stwo_m31_add(r4111, r4140);
    unsigned r4142 = stwo_m31_mul(r4113, r193);
    unsigned r4143 = stwo_m31_add(r4141, r4142);
    unsigned r4144 = stwo_m31_mul(r4115, r191);
    unsigned r4145 = stwo_m31_add(r4114, r4144);
    unsigned r4146 = stwo_m31_mul(r4116, r193);
    unsigned r4147 = stwo_m31_add(r4145, r4146);
    unsigned r4148 = stwo_m31_mul(r4118, r191);
    unsigned r4149 = stwo_m31_add(r4117, r4148);
    unsigned r4150 = stwo_m31_mul(r4119, r193);
    unsigned r4151 = stwo_m31_add(r4149, r4150);
    unsigned r4152 = stwo_m31_mul(r4121, r191);
    unsigned r4153 = stwo_m31_add(r4120, r4152);
    unsigned r4154 = stwo_m31_mul(r4122, r193);
    unsigned r4155 = stwo_m31_add(r4153, r4154);
    unsigned r4156 = stwo_m31_mul(r4124, r191);
    unsigned r4157 = stwo_m31_add(r4123, r4156);
    unsigned r4158 = stwo_m31_mul(r4125, r193);
    unsigned r4159 = stwo_m31_add(r4157, r4158);
    unsigned r4160 = stwo_m31_mul(r4127, r191);
    unsigned r4161 = stwo_m31_add(r4126, r4160);
    unsigned r4162 = stwo_m31_mul(r4128, r193);
    unsigned r4163 = stwo_m31_add(r4161, r4162);
    unsigned r4164 = stwo_m31_mul(r4130, r191);
    unsigned r4165 = stwo_m31_add(r4129, r4164);
    unsigned r4166 = stwo_m31_mul(r4131, r193);
    unsigned r4167 = stwo_m31_add(r4165, r4166);
    unsigned r4168 = stwo_m31_mul(r4133, r191);
    unsigned r4169 = stwo_m31_add(r4132, r4168);
    unsigned r4170 = stwo_m31_mul(r4134, r193);
    unsigned r4171 = stwo_m31_add(r4169, r4170);
    unsigned r4172 = stwo_m31_mul(r4, r3308);
    unsigned r4173 = stwo_m31_mul(r2, r3318);
    unsigned r4174 = stwo_m31_add(r4172, r4173);
    unsigned r4175 = stwo_m31_add(r4174, r3665);
    unsigned r4176 = stwo_m31_add(r4175, r212);
    unsigned r4177 = stwo_m31_sub(r4176, r4139);
    unsigned r4178 = stwo_m31_add(r4177, r257);
    unsigned r4179 = (r4178 & 65535u);
    unsigned r4180 = (r4179 % STWO_M31_P);
    unsigned r4181 = stwo_m31_sub(r4180, r1);
    unsigned r4182 = stwo_m31_mul(r4, r3308);
    out_cols[215u][row] = r3308;
    lookup_words[311u * row_count + row] = r3308;
    unsigned r4183 = stwo_m31_mul(r2, r3318);
    unsigned r4184 = stwo_m31_add(r4182, r4183);
    unsigned r4185 = stwo_m31_add(r4184, r3665);
    unsigned r4186 = stwo_m31_add(r4185, r212);
    unsigned r4187 = stwo_m31_sub(r4186, r4139);
    unsigned r4188 = stwo_m31_sub(r4187, r4181);
    unsigned r4189 = stwo_m31_mul(r4188, r16);
    unsigned r4190 = stwo_m31_mul(r4, r3309);
    out_cols[216u][row] = r3309;
    lookup_words[312u * row_count + row] = r3309;
    unsigned r4191 = stwo_m31_add(r4189, r4190);
    unsigned r4192 = stwo_m31_mul(r2, r3319);
    unsigned r4193 = stwo_m31_add(r4191, r4192);
    unsigned r4194 = stwo_m31_add(r4193, r3669);
    unsigned r4195 = stwo_m31_add(r4194, r211);
    unsigned r4196 = stwo_m31_sub(r4195, r4143);
    unsigned r4197 = stwo_m31_mul(r4196, r16);
    unsigned r4198 = stwo_m31_mul(r4, r3310);
    out_cols[217u][row] = r3310;
    lookup_words[313u * row_count + row] = r3310;
    unsigned r4199 = stwo_m31_add(r4197, r4198);
    unsigned r4200 = stwo_m31_mul(r2, r3320);
    unsigned r4201 = stwo_m31_add(r4199, r4200);
    unsigned r4202 = stwo_m31_add(r4201, r3673);
    unsigned r4203 = stwo_m31_add(r4202, r220);
    unsigned r4204 = stwo_m31_sub(r4203, r4147);
    unsigned r4205 = stwo_m31_mul(r4204, r16);
    unsigned r4206 = stwo_m31_mul(r4, r3311);
    out_cols[218u][row] = r3311;
    lookup_words[314u * row_count + row] = r3311;
    unsigned r4207 = stwo_m31_add(r4205, r4206);
    unsigned r4208 = stwo_m31_mul(r2, r3321);
    unsigned r4209 = stwo_m31_add(r4207, r4208);
    unsigned r4210 = stwo_m31_add(r4209, r3677);
    unsigned r4211 = stwo_m31_add(r4210, r227);
    unsigned r4212 = stwo_m31_sub(r4211, r4151);
    unsigned r4213 = stwo_m31_mul(r4212, r16);
    unsigned r4214 = stwo_m31_mul(r4, r3312);
    out_cols[219u][row] = r3312;
    lookup_words[315u * row_count + row] = r3312;
    unsigned r4215 = stwo_m31_add(r4213, r4214);
    unsigned r4216 = stwo_m31_mul(r2, r3322);
    unsigned r4217 = stwo_m31_add(r4215, r4216);
    unsigned r4218 = stwo_m31_add(r4217, r3681);
    unsigned r4219 = stwo_m31_add(r4218, r228);
    unsigned r4220 = stwo_m31_sub(r4219, r4155);
    unsigned r4221 = stwo_m31_mul(r4220, r16);
    unsigned r4222 = stwo_m31_mul(r4, r3313);
    out_cols[220u][row] = r3313;
    lookup_words[316u * row_count + row] = r3313;
    unsigned r4223 = stwo_m31_add(r4221, r4222);
    unsigned r4224 = stwo_m31_mul(r2, r3323);
    unsigned r4225 = stwo_m31_add(r4223, r4224);
    unsigned r4226 = stwo_m31_add(r4225, r3685);
    unsigned r4227 = stwo_m31_add(r4226, r249);
    unsigned r4228 = stwo_m31_sub(r4227, r4159);
    unsigned r4229 = stwo_m31_mul(r4228, r16);
    unsigned r4230 = stwo_m31_mul(r4, r3314);
    out_cols[221u][row] = r3314;
    lookup_words[317u * row_count + row] = r3314;
    unsigned r4231 = stwo_m31_add(r4229, r4230);
    unsigned r4232 = stwo_m31_mul(r2, r3324);
    unsigned r4233 = stwo_m31_add(r4231, r4232);
    unsigned r4234 = stwo_m31_add(r4233, r3689);
    unsigned r4235 = stwo_m31_add(r4234, r202);
    unsigned r4236 = stwo_m31_sub(r4235, r4163);
    unsigned r4237 = stwo_m31_mul(r4236, r16);
    unsigned r4238 = stwo_m31_mul(r4, r3315);
    out_cols[222u][row] = r3315;
    lookup_words[318u * row_count + row] = r3315;
    unsigned r4239 = stwo_m31_add(r4237, r4238);
    unsigned r4240 = stwo_m31_mul(r2, r3325);
    unsigned r4241 = stwo_m31_add(r4239, r4240);
    unsigned r4242 = stwo_m31_add(r4241, r3693);
    unsigned r4243 = stwo_m31_add(r4242, r221);
    unsigned r4244 = stwo_m31_sub(r4243, r4167);
    unsigned r4245 = stwo_m31_mul(r4181, r67);
    unsigned r4246 = stwo_m31_sub(r4244, r4245);
    unsigned r4247 = stwo_m31_mul(r4246, r16);
    unsigned r4248 = stwo_m31_mul(r4, r3316);
    lookup_words[125u * row_count + row] = r4;
    lookup_words[247u * row_count + row] = r4;
    sub_words[343u * row_count + row] = r4;
    out_cols[223u][row] = r3316;
    lookup_words[319u * row_count + row] = r3316;
    unsigned r4249 = stwo_m31_add(r4247, r4248);
    unsigned r4250 = stwo_m31_mul(r2, r3326);
    sub_words[71u * row_count + row] = r2;
    unsigned r4251 = stwo_m31_add(r4249, r4250);
    unsigned r4252 = stwo_m31_add(r4251, r3697);
    unsigned r4253 = stwo_m31_add(r4252, r197);
    unsigned r4254 = stwo_m31_sub(r4253, r4171);
    unsigned r4255 = stwo_m31_mul(r4254, r16);
    sub_words[847u * row_count + row] = r16;
    unsigned r4256 = stwo_m31_add(r4181, r1);
    sub_words[328u * row_count + row] = r4256;
    unsigned r4257 = stwo_m31_add(r4189, r1);
    sub_words[329u * row_count + row] = r4257;
    unsigned r4258 = stwo_m31_add(r4197, r1);
    sub_words[330u * row_count + row] = r4258;
    unsigned r4259 = stwo_m31_add(r4205, r1);
    sub_words[331u * row_count + row] = r4259;
    unsigned r4260 = stwo_m31_add(r4181, r1);
    out_cols[256u][row] = r4181;
    lookup_words[345u * row_count + row] = r4260;
    unsigned r4261 = stwo_m31_add(r4189, r1);
    lookup_words[346u * row_count + row] = r4261;
    unsigned r4262 = stwo_m31_add(r4197, r1);
    lookup_words[347u * row_count + row] = r4262;
    unsigned r4263 = stwo_m31_add(r4205, r1);
    lookup_words[348u * row_count + row] = r4263;
    unsigned r4264 = stwo_m31_add(r4213, r1);
    sub_words[332u * row_count + row] = r4264;
    unsigned r4265 = stwo_m31_add(r4221, r1);
    sub_words[333u * row_count + row] = r4265;
    unsigned r4266 = stwo_m31_add(r4229, r1);
    sub_words[334u * row_count + row] = r4266;
    unsigned r4267 = stwo_m31_add(r4237, r1);
    sub_words[335u * row_count + row] = r4267;
    unsigned r4268 = stwo_m31_add(r4213, r1);
    lookup_words[350u * row_count + row] = r4268;
    unsigned r4269 = stwo_m31_add(r4221, r1);
    lookup_words[351u * row_count + row] = r4269;
    unsigned r4270 = stwo_m31_add(r4229, r1);
    lookup_words[352u * row_count + row] = r4270;
    unsigned r4271 = stwo_m31_add(r4237, r1);
    lookup_words[353u * row_count + row] = r4271;
    unsigned r4272 = stwo_m31_add(r4247, r1);
    sub_words[340u * row_count + row] = r4272;
    unsigned r4273 = stwo_m31_add(r4255, r1);
    sub_words[341u * row_count + row] = r4273;
    unsigned r4274 = stwo_m31_add(r4247, r1);
    lookup_words[355u * row_count + row] = r4274;
    unsigned r4275 = stwo_m31_add(r4255, r1);
    lookup_words[356u * row_count + row] = r4275;
    unsigned r4276 = stwo_m31_add(r1097, r1);
    lookup_words[91u * row_count + row] = r1097;
    sub_words[6u * row_count + row] = r1097;
    sub_words[38u * row_count + row] = r1097;
    sub_words[39u * row_count + row] = r1;
    sub_words[70u * row_count + row] = r1097;
    sub_words[102u * row_count + row] = r1097;
    lookup_words[124u * row_count + row] = r1097;
    lookup_words[520u * row_count + row] = r1;
    const unsigned dargs70[32] = { r4276, r31, r4139, r4143, r4147, r4151, r4155, r4159, r4163, r4167, r4171, r4135, r3665, r3669, r3673, r3677, r3681, r3685, r3689, r3693, r3697, r3661, r3318, r3319, r3320, r3321, r3322, r3323, r3324, r3325, r3326, r3327 };
    unsigned douts70[32];
    out_cols[225u][row] = r3318;
    out_cols[226u][row] = r3319;
    out_cols[227u][row] = r3320;
    out_cols[228u][row] = r3321;
    out_cols[229u][row] = r3322;
    out_cols[230u][row] = r3323;
    out_cols[231u][row] = r3324;
    out_cols[232u][row] = r3325;
    out_cols[233u][row] = r3326;
    out_cols[234u][row] = r3327;
    lookup_words[290u * row_count + row] = r31;
    lookup_words[321u * row_count + row] = r3318;
    lookup_words[322u * row_count + row] = r3319;
    lookup_words[323u * row_count + row] = r3320;
    lookup_words[324u * row_count + row] = r3321;
    lookup_words[325u * row_count + row] = r3322;
    lookup_words[326u * row_count + row] = r3323;
    lookup_words[327u * row_count + row] = r3324;
    lookup_words[328u * row_count + row] = r3325;
    lookup_words[329u * row_count + row] = r3326;
    lookup_words[330u * row_count + row] = r3327;
    out_cols[235u][row] = r3665;
    out_cols[236u][row] = r3669;
    out_cols[237u][row] = r3673;
    out_cols[238u][row] = r3677;
    out_cols[239u][row] = r3681;
    out_cols[240u][row] = r3685;
    out_cols[241u][row] = r3689;
    out_cols[242u][row] = r3693;
    out_cols[243u][row] = r3697;
    out_cols[244u][row] = r3661;
    out_cols[246u][row] = r4139;
    out_cols[247u][row] = r4143;
    out_cols[248u][row] = r4147;
    out_cols[249u][row] = r4151;
    out_cols[250u][row] = r4155;
    out_cols[251u][row] = r4159;
    out_cols[252u][row] = r4163;
    out_cols[253u][row] = r4167;
    out_cols[254u][row] = r4171;
    out_cols[255u][row] = r4135;
    lookup_words[359u * row_count + row] = r31;
    lookup_words[360u * row_count + row] = r4139;
    lookup_words[361u * row_count + row] = r4143;
    lookup_words[362u * row_count + row] = r4147;
    lookup_words[363u * row_count + row] = r4151;
    lookup_words[364u * row_count + row] = r4155;
    lookup_words[365u * row_count + row] = r4159;
    lookup_words[366u * row_count + row] = r4163;
    lookup_words[367u * row_count + row] = r4167;
    lookup_words[368u * row_count + row] = r4171;
    lookup_words[369u * row_count + row] = r4135;
    lookup_words[370u * row_count + row] = r3665;
    lookup_words[371u * row_count + row] = r3669;
    lookup_words[372u * row_count + row] = r3673;
    lookup_words[373u * row_count + row] = r3677;
    lookup_words[374u * row_count + row] = r3681;
    lookup_words[375u * row_count + row] = r3685;
    lookup_words[376u * row_count + row] = r3689;
    lookup_words[377u * row_count + row] = r3693;
    lookup_words[378u * row_count + row] = r3697;
    lookup_words[379u * row_count + row] = r3661;
    lookup_words[380u * row_count + row] = r3318;
    lookup_words[381u * row_count + row] = r3319;
    lookup_words[382u * row_count + row] = r3320;
    lookup_words[383u * row_count + row] = r3321;
    lookup_words[384u * row_count + row] = r3322;
    lookup_words[385u * row_count + row] = r3323;
    lookup_words[386u * row_count + row] = r3324;
    lookup_words[387u * row_count + row] = r3325;
    lookup_words[388u * row_count + row] = r3326;
    lookup_words[389u * row_count + row] = r3327;
    sub_words[135u * row_count + row] = r31;
    sub_words[136u * row_count + row] = r4139;
    sub_words[137u * row_count + row] = r4143;
    sub_words[138u * row_count + row] = r4147;
    sub_words[139u * row_count + row] = r4151;
    sub_words[140u * row_count + row] = r4155;
    sub_words[141u * row_count + row] = r4159;
    sub_words[142u * row_count + row] = r4163;
    sub_words[143u * row_count + row] = r4167;
    sub_words[144u * row_count + row] = r4171;
    sub_words[145u * row_count + row] = r4135;
    sub_words[146u * row_count + row] = r3665;
    sub_words[147u * row_count + row] = r3669;
    sub_words[148u * row_count + row] = r3673;
    sub_words[149u * row_count + row] = r3677;
    sub_words[150u * row_count + row] = r3681;
    sub_words[151u * row_count + row] = r3685;
    sub_words[152u * row_count + row] = r3689;
    sub_words[153u * row_count + row] = r3693;
    sub_words[154u * row_count + row] = r3697;
    sub_words[155u * row_count + row] = r3661;
    sub_words[156u * row_count + row] = r3318;
    sub_words[157u * row_count + row] = r3319;
    sub_words[158u * row_count + row] = r3320;
    sub_words[159u * row_count + row] = r3321;
    sub_words[160u * row_count + row] = r3322;
    sub_words[161u * row_count + row] = r3323;
    sub_words[162u * row_count + row] = r3324;
    sub_words[163u * row_count + row] = r3325;
    sub_words[164u * row_count + row] = r3326;
    sub_words[165u * row_count + row] = r3327;
    stwo_wit_deduce_poseidon_full_round_chain(dargs70, douts70);
    unsigned r4277 = douts70[0];
    unsigned r4278 = douts70[1];
    unsigned r4279 = douts70[2];
    unsigned r4280 = douts70[3];
    unsigned r4281 = douts70[4];
    unsigned r4282 = douts70[5];
    unsigned r4283 = douts70[6];
    unsigned r4284 = douts70[7];
    unsigned r4285 = douts70[8];
    unsigned r4286 = douts70[9];
    unsigned r4287 = douts70[10];
    unsigned r4288 = douts70[11];
    unsigned r4289 = douts70[12];
    unsigned r4290 = douts70[13];
    unsigned r4291 = douts70[14];
    unsigned r4292 = douts70[15];
    unsigned r4293 = douts70[16];
    unsigned r4294 = douts70[17];
    unsigned r4295 = douts70[18];
    unsigned r4296 = douts70[19];
    unsigned r4297 = douts70[20];
    unsigned r4298 = douts70[21];
    unsigned r4299 = douts70[22];
    unsigned r4300 = douts70[23];
    unsigned r4301 = douts70[24];
    unsigned r4302 = douts70[25];
    unsigned r4303 = douts70[26];
    unsigned r4304 = douts70[27];
    unsigned r4305 = douts70[28];
    unsigned r4306 = douts70[29];
    unsigned r4307 = douts70[30];
    unsigned r4308 = douts70[31];
    const unsigned dargs71[32] = { r4276, r32, r4279, r4280, r4281, r4282, r4283, r4284, r4285, r4286, r4287, r4288, r4289, r4290, r4291, r4292, r4293, r4294, r4295, r4296, r4297, r4298, r4299, r4300, r4301, r4302, r4303, r4304, r4305, r4306, r4307, r4308 };
    unsigned douts71[32];
    sub_words[167u * row_count + row] = r32;
    sub_words[168u * row_count + row] = r4279;
    sub_words[169u * row_count + row] = r4280;
    sub_words[170u * row_count + row] = r4281;
    sub_words[171u * row_count + row] = r4282;
    sub_words[172u * row_count + row] = r4283;
    sub_words[173u * row_count + row] = r4284;
    sub_words[174u * row_count + row] = r4285;
    sub_words[175u * row_count + row] = r4286;
    sub_words[176u * row_count + row] = r4287;
    sub_words[177u * row_count + row] = r4288;
    sub_words[178u * row_count + row] = r4289;
    sub_words[179u * row_count + row] = r4290;
    sub_words[180u * row_count + row] = r4291;
    sub_words[181u * row_count + row] = r4292;
    sub_words[182u * row_count + row] = r4293;
    sub_words[183u * row_count + row] = r4294;
    sub_words[184u * row_count + row] = r4295;
    sub_words[185u * row_count + row] = r4296;
    sub_words[186u * row_count + row] = r4297;
    sub_words[187u * row_count + row] = r4298;
    sub_words[188u * row_count + row] = r4299;
    sub_words[189u * row_count + row] = r4300;
    sub_words[190u * row_count + row] = r4301;
    sub_words[191u * row_count + row] = r4302;
    sub_words[192u * row_count + row] = r4303;
    sub_words[193u * row_count + row] = r4304;
    sub_words[194u * row_count + row] = r4305;
    sub_words[195u * row_count + row] = r4306;
    sub_words[196u * row_count + row] = r4307;
    sub_words[197u * row_count + row] = r4308;
    stwo_wit_deduce_poseidon_full_round_chain(dargs71, douts71);
    unsigned r4309 = douts71[0];
    unsigned r4310 = douts71[1];
    unsigned r4311 = douts71[2];
    unsigned r4312 = douts71[3];
    unsigned r4313 = douts71[4];
    unsigned r4314 = douts71[5];
    unsigned r4315 = douts71[6];
    unsigned r4316 = douts71[7];
    unsigned r4317 = douts71[8];
    unsigned r4318 = douts71[9];
    unsigned r4319 = douts71[10];
    unsigned r4320 = douts71[11];
    unsigned r4321 = douts71[12];
    unsigned r4322 = douts71[13];
    unsigned r4323 = douts71[14];
    unsigned r4324 = douts71[15];
    unsigned r4325 = douts71[16];
    unsigned r4326 = douts71[17];
    unsigned r4327 = douts71[18];
    unsigned r4328 = douts71[19];
    unsigned r4329 = douts71[20];
    unsigned r4330 = douts71[21];
    unsigned r4331 = douts71[22];
    unsigned r4332 = douts71[23];
    unsigned r4333 = douts71[24];
    unsigned r4334 = douts71[25];
    unsigned r4335 = douts71[26];
    unsigned r4336 = douts71[27];
    unsigned r4337 = douts71[28];
    unsigned r4338 = douts71[29];
    unsigned r4339 = douts71[30];
    unsigned r4340 = douts71[31];
    const unsigned dargs72[32] = { r4276, r33, r4311, r4312, r4313, r4314, r4315, r4316, r4317, r4318, r4319, r4320, r4321, r4322, r4323, r4324, r4325, r4326, r4327, r4328, r4329, r4330, r4331, r4332, r4333, r4334, r4335, r4336, r4337, r4338, r4339, r4340 };
    unsigned douts72[32];
    sub_words[199u * row_count + row] = r33;
    sub_words[200u * row_count + row] = r4311;
    sub_words[201u * row_count + row] = r4312;
    sub_words[202u * row_count + row] = r4313;
    sub_words[203u * row_count + row] = r4314;
    sub_words[204u * row_count + row] = r4315;
    sub_words[205u * row_count + row] = r4316;
    sub_words[206u * row_count + row] = r4317;
    sub_words[207u * row_count + row] = r4318;
    sub_words[208u * row_count + row] = r4319;
    sub_words[209u * row_count + row] = r4320;
    sub_words[210u * row_count + row] = r4321;
    sub_words[211u * row_count + row] = r4322;
    sub_words[212u * row_count + row] = r4323;
    sub_words[213u * row_count + row] = r4324;
    sub_words[214u * row_count + row] = r4325;
    sub_words[215u * row_count + row] = r4326;
    sub_words[216u * row_count + row] = r4327;
    sub_words[217u * row_count + row] = r4328;
    sub_words[218u * row_count + row] = r4329;
    sub_words[219u * row_count + row] = r4330;
    sub_words[220u * row_count + row] = r4331;
    sub_words[221u * row_count + row] = r4332;
    sub_words[222u * row_count + row] = r4333;
    sub_words[223u * row_count + row] = r4334;
    sub_words[224u * row_count + row] = r4335;
    sub_words[225u * row_count + row] = r4336;
    sub_words[226u * row_count + row] = r4337;
    sub_words[227u * row_count + row] = r4338;
    sub_words[228u * row_count + row] = r4339;
    sub_words[229u * row_count + row] = r4340;
    stwo_wit_deduce_poseidon_full_round_chain(dargs72, douts72);
    unsigned r4341 = douts72[0];
    unsigned r4342 = douts72[1];
    unsigned r4343 = douts72[2];
    unsigned r4344 = douts72[3];
    unsigned r4345 = douts72[4];
    unsigned r4346 = douts72[5];
    unsigned r4347 = douts72[6];
    unsigned r4348 = douts72[7];
    unsigned r4349 = douts72[8];
    unsigned r4350 = douts72[9];
    unsigned r4351 = douts72[10];
    unsigned r4352 = douts72[11];
    unsigned r4353 = douts72[12];
    unsigned r4354 = douts72[13];
    unsigned r4355 = douts72[14];
    unsigned r4356 = douts72[15];
    unsigned r4357 = douts72[16];
    unsigned r4358 = douts72[17];
    unsigned r4359 = douts72[18];
    unsigned r4360 = douts72[19];
    unsigned r4361 = douts72[20];
    unsigned r4362 = douts72[21];
    unsigned r4363 = douts72[22];
    unsigned r4364 = douts72[23];
    unsigned r4365 = douts72[24];
    unsigned r4366 = douts72[25];
    unsigned r4367 = douts72[26];
    unsigned r4368 = douts72[27];
    unsigned r4369 = douts72[28];
    unsigned r4370 = douts72[29];
    unsigned r4371 = douts72[30];
    unsigned r4372 = douts72[31];
    const unsigned dargs73[32] = { r4276, r34, r4343, r4344, r4345, r4346, r4347, r4348, r4349, r4350, r4351, r4352, r4353, r4354, r4355, r4356, r4357, r4358, r4359, r4360, r4361, r4362, r4363, r4364, r4365, r4366, r4367, r4368, r4369, r4370, r4371, r4372 };
    unsigned douts73[32];
    lookup_words[358u * row_count + row] = r4276;
    sub_words[134u * row_count + row] = r4276;
    sub_words[166u * row_count + row] = r4276;
    sub_words[198u * row_count + row] = r4276;
    sub_words[230u * row_count + row] = r4276;
    sub_words[231u * row_count + row] = r34;
    sub_words[232u * row_count + row] = r4343;
    sub_words[233u * row_count + row] = r4344;
    sub_words[234u * row_count + row] = r4345;
    sub_words[235u * row_count + row] = r4346;
    sub_words[236u * row_count + row] = r4347;
    sub_words[237u * row_count + row] = r4348;
    sub_words[238u * row_count + row] = r4349;
    sub_words[239u * row_count + row] = r4350;
    sub_words[240u * row_count + row] = r4351;
    sub_words[241u * row_count + row] = r4352;
    sub_words[242u * row_count + row] = r4353;
    sub_words[243u * row_count + row] = r4354;
    sub_words[244u * row_count + row] = r4355;
    sub_words[245u * row_count + row] = r4356;
    sub_words[246u * row_count + row] = r4357;
    sub_words[247u * row_count + row] = r4358;
    sub_words[248u * row_count + row] = r4359;
    sub_words[249u * row_count + row] = r4360;
    sub_words[250u * row_count + row] = r4361;
    sub_words[251u * row_count + row] = r4362;
    sub_words[252u * row_count + row] = r4363;
    sub_words[253u * row_count + row] = r4364;
    sub_words[254u * row_count + row] = r4365;
    sub_words[255u * row_count + row] = r4366;
    sub_words[256u * row_count + row] = r4367;
    sub_words[257u * row_count + row] = r4368;
    sub_words[258u * row_count + row] = r4369;
    sub_words[259u * row_count + row] = r4370;
    sub_words[260u * row_count + row] = r4371;
    sub_words[261u * row_count + row] = r4372;
    lookup_words[391u * row_count + row] = r4276;
    stwo_wit_deduce_poseidon_full_round_chain(dargs73, douts73);
    unsigned r4373 = douts73[0];
    unsigned r4374 = douts73[1];
    unsigned r4375 = douts73[2];
    unsigned r4376 = douts73[3];
    unsigned r4377 = douts73[4];
    unsigned r4378 = douts73[5];
    unsigned r4379 = douts73[6];
    unsigned r4380 = douts73[7];
    unsigned r4381 = douts73[8];
    unsigned r4382 = douts73[9];
    unsigned r4383 = douts73[10];
    unsigned r4384 = douts73[11];
    unsigned r4385 = douts73[12];
    unsigned r4386 = douts73[13];
    unsigned r4387 = douts73[14];
    unsigned r4388 = douts73[15];
    unsigned r4389 = douts73[16];
    unsigned r4390 = douts73[17];
    unsigned r4391 = douts73[18];
    unsigned r4392 = douts73[19];
    unsigned r4393 = douts73[20];
    unsigned r4394 = douts73[21];
    unsigned r4395 = douts73[22];
    unsigned r4396 = douts73[23];
    unsigned r4397 = douts73[24];
    unsigned r4398 = douts73[25];
    unsigned r4399 = douts73[26];
    unsigned r4400 = douts73[27];
    unsigned r4401 = douts73[28];
    unsigned r4402 = douts73[29];
    unsigned r4403 = douts73[30];
    unsigned r4404 = douts73[31];
    unsigned r4405 = (r4375 & 511u);
    unsigned r4406 = (r4375 >> 9u);
    unsigned r4407 = (r4406 & 511u);
    unsigned r4408 = (r4375 >> 18u);
    unsigned r4409 = (r4408 & 511u);
    unsigned r4410 = (r4376 & 511u);
    unsigned r4411 = (r4376 >> 9u);
    unsigned r4412 = (r4411 & 511u);
    unsigned r4413 = (r4376 >> 18u);
    unsigned r4414 = (r4413 & 511u);
    unsigned r4415 = (r4377 & 511u);
    unsigned r4416 = (r4377 >> 9u);
    unsigned r4417 = (r4416 & 511u);
    unsigned r4418 = (r4377 >> 18u);
    unsigned r4419 = (r4418 & 511u);
    unsigned r4420 = (r4378 & 511u);
    unsigned r4421 = (r4378 >> 9u);
    unsigned r4422 = (r4421 & 511u);
    unsigned r4423 = (r4378 >> 18u);
    unsigned r4424 = (r4423 & 511u);
    unsigned r4425 = (r4379 & 511u);
    unsigned r4426 = (r4379 >> 9u);
    unsigned r4427 = (r4426 & 511u);
    unsigned r4428 = (r4379 >> 18u);
    unsigned r4429 = (r4428 & 511u);
    unsigned r4430 = (r4380 & 511u);
    unsigned r4431 = (r4380 >> 9u);
    unsigned r4432 = (r4431 & 511u);
    unsigned r4433 = (r4380 >> 18u);
    unsigned r4434 = (r4433 & 511u);
    unsigned r4435 = (r4381 & 511u);
    unsigned r4436 = (r4381 >> 9u);
    unsigned r4437 = (r4436 & 511u);
    unsigned r4438 = (r4381 >> 18u);
    unsigned r4439 = (r4438 & 511u);
    unsigned r4440 = (r4382 & 511u);
    unsigned r4441 = (r4382 >> 9u);
    unsigned r4442 = (r4441 & 511u);
    unsigned r4443 = (r4382 >> 18u);
    unsigned r4444 = (r4443 & 511u);
    unsigned r4445 = (r4383 & 511u);
    unsigned r4446 = (r4383 >> 9u);
    unsigned r4447 = (r4446 & 511u);
    unsigned r4448 = (r4383 >> 18u);
    unsigned r4449 = (r4448 & 511u);
    unsigned r4450 = (r4384 & 511u);
    out_cols[266u][row] = r4384;
    lookup_words[402u * row_count + row] = r4384;
    lookup_words[452u * row_count + row] = r4384;
    unsigned r4451 = stwo_m31_sub(r4375, r4405);
    out_cols[257u][row] = r4375;
    lookup_words[393u * row_count + row] = r4375;
    out_cols[287u][row] = r4405;
    lookup_words[425u * row_count + row] = r4405;
    unsigned r4452 = stwo_m31_mul(r4407, r191);
    out_cols[288u][row] = r4407;
    lookup_words[426u * row_count + row] = r4407;
    unsigned r4453 = stwo_m31_sub(r4451, r4452);
    unsigned r4454 = stwo_m31_mul(r4453, r192);
    lookup_words[427u * row_count + row] = r4454;
    unsigned r4455 = stwo_m31_sub(r4376, r4410);
    out_cols[258u][row] = r4376;
    lookup_words[394u * row_count + row] = r4376;
    out_cols[289u][row] = r4410;
    lookup_words[428u * row_count + row] = r4410;
    unsigned r4456 = stwo_m31_mul(r4412, r191);
    out_cols[290u][row] = r4412;
    lookup_words[429u * row_count + row] = r4412;
    unsigned r4457 = stwo_m31_sub(r4455, r4456);
    unsigned r4458 = stwo_m31_mul(r4457, r192);
    lookup_words[430u * row_count + row] = r4458;
    unsigned r4459 = stwo_m31_sub(r4377, r4415);
    out_cols[259u][row] = r4377;
    lookup_words[395u * row_count + row] = r4377;
    out_cols[291u][row] = r4415;
    lookup_words[431u * row_count + row] = r4415;
    unsigned r4460 = stwo_m31_mul(r4417, r191);
    out_cols[292u][row] = r4417;
    lookup_words[432u * row_count + row] = r4417;
    unsigned r4461 = stwo_m31_sub(r4459, r4460);
    unsigned r4462 = stwo_m31_mul(r4461, r192);
    lookup_words[433u * row_count + row] = r4462;
    unsigned r4463 = stwo_m31_sub(r4378, r4420);
    out_cols[260u][row] = r4378;
    lookup_words[396u * row_count + row] = r4378;
    out_cols[293u][row] = r4420;
    lookup_words[434u * row_count + row] = r4420;
    unsigned r4464 = stwo_m31_mul(r4422, r191);
    out_cols[294u][row] = r4422;
    lookup_words[435u * row_count + row] = r4422;
    unsigned r4465 = stwo_m31_sub(r4463, r4464);
    unsigned r4466 = stwo_m31_mul(r4465, r192);
    lookup_words[436u * row_count + row] = r4466;
    unsigned r4467 = stwo_m31_sub(r4379, r4425);
    out_cols[261u][row] = r4379;
    lookup_words[397u * row_count + row] = r4379;
    out_cols[295u][row] = r4425;
    lookup_words[437u * row_count + row] = r4425;
    unsigned r4468 = stwo_m31_mul(r4427, r191);
    out_cols[296u][row] = r4427;
    lookup_words[438u * row_count + row] = r4427;
    unsigned r4469 = stwo_m31_sub(r4467, r4468);
    unsigned r4470 = stwo_m31_mul(r4469, r192);
    lookup_words[439u * row_count + row] = r4470;
    unsigned r4471 = stwo_m31_sub(r4380, r4430);
    out_cols[262u][row] = r4380;
    lookup_words[398u * row_count + row] = r4380;
    out_cols[297u][row] = r4430;
    lookup_words[440u * row_count + row] = r4430;
    unsigned r4472 = stwo_m31_mul(r4432, r191);
    out_cols[298u][row] = r4432;
    lookup_words[441u * row_count + row] = r4432;
    unsigned r4473 = stwo_m31_sub(r4471, r4472);
    unsigned r4474 = stwo_m31_mul(r4473, r192);
    lookup_words[442u * row_count + row] = r4474;
    unsigned r4475 = stwo_m31_sub(r4381, r4435);
    out_cols[263u][row] = r4381;
    lookup_words[399u * row_count + row] = r4381;
    out_cols[299u][row] = r4435;
    lookup_words[443u * row_count + row] = r4435;
    unsigned r4476 = stwo_m31_mul(r4437, r191);
    out_cols[300u][row] = r4437;
    lookup_words[444u * row_count + row] = r4437;
    unsigned r4477 = stwo_m31_sub(r4475, r4476);
    unsigned r4478 = stwo_m31_mul(r4477, r192);
    lookup_words[445u * row_count + row] = r4478;
    unsigned r4479 = stwo_m31_sub(r4382, r4440);
    out_cols[264u][row] = r4382;
    lookup_words[400u * row_count + row] = r4382;
    out_cols[301u][row] = r4440;
    lookup_words[446u * row_count + row] = r4440;
    unsigned r4480 = stwo_m31_mul(r4442, r191);
    out_cols[302u][row] = r4442;
    lookup_words[447u * row_count + row] = r4442;
    unsigned r4481 = stwo_m31_sub(r4479, r4480);
    unsigned r4482 = stwo_m31_mul(r4481, r192);
    lookup_words[448u * row_count + row] = r4482;
    unsigned r4483 = stwo_m31_sub(r4383, r4445);
    out_cols[265u][row] = r4383;
    lookup_words[401u * row_count + row] = r4383;
    out_cols[303u][row] = r4445;
    lookup_words[449u * row_count + row] = r4445;
    unsigned r4484 = stwo_m31_mul(r4447, r191);
    out_cols[304u][row] = r4447;
    lookup_words[450u * row_count + row] = r4447;
    unsigned r4485 = stwo_m31_sub(r4483, r4484);
    unsigned r4486 = stwo_m31_mul(r4485, r192);
    lookup_words[451u * row_count + row] = r4486;
    unsigned r4487 = (r4385 & 511u);
    unsigned r4488 = (r4385 >> 9u);
    unsigned r4489 = (r4488 & 511u);
    unsigned r4490 = (r4385 >> 18u);
    unsigned r4491 = (r4490 & 511u);
    unsigned r4492 = (r4386 & 511u);
    unsigned r4493 = (r4386 >> 9u);
    unsigned r4494 = (r4493 & 511u);
    unsigned r4495 = (r4386 >> 18u);
    unsigned r4496 = (r4495 & 511u);
    unsigned r4497 = (r4387 & 511u);
    unsigned r4498 = (r4387 >> 9u);
    unsigned r4499 = (r4498 & 511u);
    unsigned r4500 = (r4387 >> 18u);
    unsigned r4501 = (r4500 & 511u);
    unsigned r4502 = (r4388 & 511u);
    unsigned r4503 = (r4388 >> 9u);
    unsigned r4504 = (r4503 & 511u);
    unsigned r4505 = (r4388 >> 18u);
    unsigned r4506 = (r4505 & 511u);
    unsigned r4507 = (r4389 & 511u);
    unsigned r4508 = (r4389 >> 9u);
    unsigned r4509 = (r4508 & 511u);
    unsigned r4510 = (r4389 >> 18u);
    unsigned r4511 = (r4510 & 511u);
    unsigned r4512 = (r4390 & 511u);
    unsigned r4513 = (r4390 >> 9u);
    unsigned r4514 = (r4513 & 511u);
    unsigned r4515 = (r4390 >> 18u);
    unsigned r4516 = (r4515 & 511u);
    unsigned r4517 = (r4391 & 511u);
    unsigned r4518 = (r4391 >> 9u);
    unsigned r4519 = (r4518 & 511u);
    unsigned r4520 = (r4391 >> 18u);
    unsigned r4521 = (r4520 & 511u);
    unsigned r4522 = (r4392 & 511u);
    unsigned r4523 = (r4392 >> 9u);
    unsigned r4524 = (r4523 & 511u);
    unsigned r4525 = (r4392 >> 18u);
    unsigned r4526 = (r4525 & 511u);
    unsigned r4527 = (r4393 & 511u);
    unsigned r4528 = (r4393 >> 9u);
    unsigned r4529 = (r4528 & 511u);
    unsigned r4530 = (r4393 >> 18u);
    unsigned r4531 = (r4530 & 511u);
    unsigned r4532 = (r4394 & 511u);
    out_cols[276u][row] = r4394;
    lookup_words[412u * row_count + row] = r4394;
    lookup_words[482u * row_count + row] = r4394;
    unsigned r4533 = stwo_m31_sub(r4385, r4487);
    out_cols[267u][row] = r4385;
    lookup_words[403u * row_count + row] = r4385;
    out_cols[305u][row] = r4487;
    lookup_words[455u * row_count + row] = r4487;
    unsigned r4534 = stwo_m31_mul(r4489, r191);
    out_cols[306u][row] = r4489;
    lookup_words[456u * row_count + row] = r4489;
    unsigned r4535 = stwo_m31_sub(r4533, r4534);
    unsigned r4536 = stwo_m31_mul(r4535, r192);
    lookup_words[457u * row_count + row] = r4536;
    unsigned r4537 = stwo_m31_sub(r4386, r4492);
    out_cols[268u][row] = r4386;
    lookup_words[404u * row_count + row] = r4386;
    out_cols[307u][row] = r4492;
    lookup_words[458u * row_count + row] = r4492;
    unsigned r4538 = stwo_m31_mul(r4494, r191);
    out_cols[308u][row] = r4494;
    lookup_words[459u * row_count + row] = r4494;
    unsigned r4539 = stwo_m31_sub(r4537, r4538);
    unsigned r4540 = stwo_m31_mul(r4539, r192);
    lookup_words[460u * row_count + row] = r4540;
    unsigned r4541 = stwo_m31_sub(r4387, r4497);
    out_cols[269u][row] = r4387;
    lookup_words[405u * row_count + row] = r4387;
    out_cols[309u][row] = r4497;
    lookup_words[461u * row_count + row] = r4497;
    unsigned r4542 = stwo_m31_mul(r4499, r191);
    out_cols[310u][row] = r4499;
    lookup_words[462u * row_count + row] = r4499;
    unsigned r4543 = stwo_m31_sub(r4541, r4542);
    unsigned r4544 = stwo_m31_mul(r4543, r192);
    lookup_words[463u * row_count + row] = r4544;
    unsigned r4545 = stwo_m31_sub(r4388, r4502);
    out_cols[270u][row] = r4388;
    lookup_words[406u * row_count + row] = r4388;
    out_cols[311u][row] = r4502;
    lookup_words[464u * row_count + row] = r4502;
    unsigned r4546 = stwo_m31_mul(r4504, r191);
    out_cols[312u][row] = r4504;
    lookup_words[465u * row_count + row] = r4504;
    unsigned r4547 = stwo_m31_sub(r4545, r4546);
    unsigned r4548 = stwo_m31_mul(r4547, r192);
    lookup_words[466u * row_count + row] = r4548;
    unsigned r4549 = stwo_m31_sub(r4389, r4507);
    out_cols[271u][row] = r4389;
    lookup_words[407u * row_count + row] = r4389;
    out_cols[313u][row] = r4507;
    lookup_words[467u * row_count + row] = r4507;
    unsigned r4550 = stwo_m31_mul(r4509, r191);
    out_cols[314u][row] = r4509;
    lookup_words[468u * row_count + row] = r4509;
    unsigned r4551 = stwo_m31_sub(r4549, r4550);
    unsigned r4552 = stwo_m31_mul(r4551, r192);
    lookup_words[469u * row_count + row] = r4552;
    unsigned r4553 = stwo_m31_sub(r4390, r4512);
    out_cols[272u][row] = r4390;
    lookup_words[408u * row_count + row] = r4390;
    out_cols[315u][row] = r4512;
    lookup_words[470u * row_count + row] = r4512;
    unsigned r4554 = stwo_m31_mul(r4514, r191);
    out_cols[316u][row] = r4514;
    lookup_words[471u * row_count + row] = r4514;
    unsigned r4555 = stwo_m31_sub(r4553, r4554);
    unsigned r4556 = stwo_m31_mul(r4555, r192);
    lookup_words[472u * row_count + row] = r4556;
    unsigned r4557 = stwo_m31_sub(r4391, r4517);
    out_cols[273u][row] = r4391;
    lookup_words[409u * row_count + row] = r4391;
    out_cols[317u][row] = r4517;
    lookup_words[473u * row_count + row] = r4517;
    unsigned r4558 = stwo_m31_mul(r4519, r191);
    out_cols[318u][row] = r4519;
    lookup_words[474u * row_count + row] = r4519;
    unsigned r4559 = stwo_m31_sub(r4557, r4558);
    unsigned r4560 = stwo_m31_mul(r4559, r192);
    lookup_words[475u * row_count + row] = r4560;
    unsigned r4561 = stwo_m31_sub(r4392, r4522);
    out_cols[274u][row] = r4392;
    lookup_words[410u * row_count + row] = r4392;
    out_cols[319u][row] = r4522;
    lookup_words[476u * row_count + row] = r4522;
    unsigned r4562 = stwo_m31_mul(r4524, r191);
    out_cols[320u][row] = r4524;
    lookup_words[477u * row_count + row] = r4524;
    unsigned r4563 = stwo_m31_sub(r4561, r4562);
    unsigned r4564 = stwo_m31_mul(r4563, r192);
    lookup_words[478u * row_count + row] = r4564;
    unsigned r4565 = stwo_m31_sub(r4393, r4527);
    out_cols[275u][row] = r4393;
    lookup_words[411u * row_count + row] = r4393;
    out_cols[321u][row] = r4527;
    lookup_words[479u * row_count + row] = r4527;
    unsigned r4566 = stwo_m31_mul(r4529, r191);
    out_cols[322u][row] = r4529;
    lookup_words[480u * row_count + row] = r4529;
    unsigned r4567 = stwo_m31_sub(r4565, r4566);
    unsigned r4568 = stwo_m31_mul(r4567, r192);
    lookup_words[481u * row_count + row] = r4568;
    unsigned r4569 = (r4395 & 511u);
    unsigned r4570 = (r4395 >> 9u);
    unsigned r4571 = (r4570 & 511u);
    unsigned r4572 = (r4395 >> 18u);
    unsigned r4573 = (r4572 & 511u);
    unsigned r4574 = (r4396 & 511u);
    unsigned r4575 = (r4396 >> 9u);
    unsigned r4576 = (r4575 & 511u);
    unsigned r4577 = (r4396 >> 18u);
    unsigned r4578 = (r4577 & 511u);
    unsigned r4579 = (r4397 & 511u);
    unsigned r4580 = (r4397 >> 9u);
    unsigned r4581 = (r4580 & 511u);
    unsigned r4582 = (r4397 >> 18u);
    unsigned r4583 = (r4582 & 511u);
    unsigned r4584 = (r4398 & 511u);
    unsigned r4585 = (r4398 >> 9u);
    unsigned r4586 = (r4585 & 511u);
    unsigned r4587 = (r4398 >> 18u);
    unsigned r4588 = (r4587 & 511u);
    unsigned r4589 = (r4399 & 511u);
    unsigned r4590 = (r4399 >> 9u);
    unsigned r4591 = (r4590 & 511u);
    unsigned r4592 = (r4399 >> 18u);
    unsigned r4593 = (r4592 & 511u);
    unsigned r4594 = (r4400 & 511u);
    unsigned r4595 = (r4400 >> 9u);
    unsigned r4596 = (r4595 & 511u);
    unsigned r4597 = (r4400 >> 18u);
    unsigned r4598 = (r4597 & 511u);
    unsigned r4599 = (r4401 & 511u);
    unsigned r4600 = (r4401 >> 9u);
    unsigned r4601 = (r4600 & 511u);
    unsigned r4602 = (r4401 >> 18u);
    unsigned r4603 = (r4602 & 511u);
    unsigned r4604 = (r4402 & 511u);
    unsigned r4605 = (r4402 >> 9u);
    unsigned r4606 = (r4605 & 511u);
    unsigned r4607 = (r4402 >> 18u);
    unsigned r4608 = (r4607 & 511u);
    unsigned r4609 = (r4403 & 511u);
    unsigned r4610 = (r4403 >> 9u);
    unsigned r4611 = (r4610 & 511u);
    unsigned r4612 = (r4403 >> 18u);
    unsigned r4613 = (r4612 & 511u);
    unsigned r4614 = (r4404 & 511u);
    out_cols[286u][row] = r4404;
    lookup_words[422u * row_count + row] = r4404;
    lookup_words[512u * row_count + row] = r4404;
    unsigned r4615 = stwo_m31_sub(r4395, r4569);
    out_cols[277u][row] = r4395;
    lookup_words[413u * row_count + row] = r4395;
    out_cols[323u][row] = r4569;
    lookup_words[485u * row_count + row] = r4569;
    unsigned r4616 = stwo_m31_mul(r4571, r191);
    out_cols[324u][row] = r4571;
    lookup_words[486u * row_count + row] = r4571;
    unsigned r4617 = stwo_m31_sub(r4615, r4616);
    unsigned r4618 = stwo_m31_mul(r4617, r192);
    lookup_words[487u * row_count + row] = r4618;
    unsigned r4619 = stwo_m31_sub(r4396, r4574);
    out_cols[278u][row] = r4396;
    lookup_words[414u * row_count + row] = r4396;
    out_cols[325u][row] = r4574;
    lookup_words[488u * row_count + row] = r4574;
    unsigned r4620 = stwo_m31_mul(r4576, r191);
    out_cols[326u][row] = r4576;
    lookup_words[489u * row_count + row] = r4576;
    unsigned r4621 = stwo_m31_sub(r4619, r4620);
    unsigned r4622 = stwo_m31_mul(r4621, r192);
    lookup_words[490u * row_count + row] = r4622;
    unsigned r4623 = stwo_m31_sub(r4397, r4579);
    out_cols[279u][row] = r4397;
    lookup_words[415u * row_count + row] = r4397;
    out_cols[327u][row] = r4579;
    lookup_words[491u * row_count + row] = r4579;
    unsigned r4624 = stwo_m31_mul(r4581, r191);
    out_cols[328u][row] = r4581;
    lookup_words[492u * row_count + row] = r4581;
    unsigned r4625 = stwo_m31_sub(r4623, r4624);
    unsigned r4626 = stwo_m31_mul(r4625, r192);
    lookup_words[493u * row_count + row] = r4626;
    unsigned r4627 = stwo_m31_sub(r4398, r4584);
    out_cols[280u][row] = r4398;
    lookup_words[416u * row_count + row] = r4398;
    out_cols[329u][row] = r4584;
    lookup_words[494u * row_count + row] = r4584;
    unsigned r4628 = stwo_m31_mul(r4586, r191);
    out_cols[330u][row] = r4586;
    lookup_words[495u * row_count + row] = r4586;
    unsigned r4629 = stwo_m31_sub(r4627, r4628);
    unsigned r4630 = stwo_m31_mul(r4629, r192);
    lookup_words[496u * row_count + row] = r4630;
    unsigned r4631 = stwo_m31_sub(r4399, r4589);
    out_cols[281u][row] = r4399;
    lookup_words[417u * row_count + row] = r4399;
    out_cols[331u][row] = r4589;
    lookup_words[497u * row_count + row] = r4589;
    unsigned r4632 = stwo_m31_mul(r4591, r191);
    out_cols[332u][row] = r4591;
    lookup_words[498u * row_count + row] = r4591;
    unsigned r4633 = stwo_m31_sub(r4631, r4632);
    unsigned r4634 = stwo_m31_mul(r4633, r192);
    lookup_words[499u * row_count + row] = r4634;
    unsigned r4635 = stwo_m31_sub(r4400, r4594);
    out_cols[282u][row] = r4400;
    lookup_words[418u * row_count + row] = r4400;
    out_cols[333u][row] = r4594;
    lookup_words[500u * row_count + row] = r4594;
    unsigned r4636 = stwo_m31_mul(r4596, r191);
    out_cols[334u][row] = r4596;
    lookup_words[501u * row_count + row] = r4596;
    unsigned r4637 = stwo_m31_sub(r4635, r4636);
    unsigned r4638 = stwo_m31_mul(r4637, r192);
    lookup_words[502u * row_count + row] = r4638;
    unsigned r4639 = stwo_m31_sub(r4401, r4599);
    out_cols[283u][row] = r4401;
    lookup_words[419u * row_count + row] = r4401;
    out_cols[335u][row] = r4599;
    lookup_words[503u * row_count + row] = r4599;
    unsigned r4640 = stwo_m31_mul(r4601, r191);
    out_cols[336u][row] = r4601;
    lookup_words[504u * row_count + row] = r4601;
    unsigned r4641 = stwo_m31_sub(r4639, r4640);
    unsigned r4642 = stwo_m31_mul(r4641, r192);
    lookup_words[505u * row_count + row] = r4642;
    unsigned r4643 = stwo_m31_sub(r4402, r4604);
    out_cols[284u][row] = r4402;
    lookup_words[420u * row_count + row] = r4402;
    out_cols[337u][row] = r4604;
    lookup_words[506u * row_count + row] = r4604;
    unsigned r4644 = stwo_m31_mul(r4606, r191);
    out_cols[338u][row] = r4606;
    lookup_words[507u * row_count + row] = r4606;
    unsigned r4645 = stwo_m31_sub(r4643, r4644);
    unsigned r4646 = stwo_m31_mul(r4645, r192);
    lookup_words[508u * row_count + row] = r4646;
    unsigned r4647 = stwo_m31_sub(r4403, r4609);
    out_cols[285u][row] = r4403;
    lookup_words[421u * row_count + row] = r4403;
    out_cols[339u][row] = r4609;
    lookup_words[509u * row_count + row] = r4609;
    unsigned r4648 = stwo_m31_mul(r4611, r191);
    out_cols[340u][row] = r4611;
    lookup_words[510u * row_count + row] = r4611;
    unsigned r4649 = stwo_m31_sub(r4647, r4648);
    unsigned r4650 = stwo_m31_mul(r4649, r192);
    lookup_words[511u * row_count + row] = r4650;
    unsigned r4651 = input_cols[8u][row];
    out_cols[341u][row] = r4651;
    lookup_words[521u * row_count + row] = r4651;
}
