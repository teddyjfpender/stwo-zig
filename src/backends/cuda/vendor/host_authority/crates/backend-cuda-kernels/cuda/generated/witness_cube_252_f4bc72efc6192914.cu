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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_22ad07ddaf1c1605(
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

    unsigned r0 = 2u;
    unsigned r1 = 4u;
    unsigned r2 = 8u;
    unsigned r3 = 32u;
    unsigned r4 = 64u;
    unsigned r5 = 136u;
    unsigned r6 = 512u;
    unsigned r7 = 8192u;
    unsigned r8 = 65536u;
    unsigned r9 = 262144u;
    unsigned r10 = 524288u;
    unsigned r11 = 4194304u;
    unsigned r12 = 134217728u;
    unsigned r13 = 447122465u;
    lookup_words[97u * row_count + row] = r13;
    lookup_words[99u * row_count + row] = r13;
    lookup_words[101u * row_count + row] = r13;
    lookup_words[103u * row_count + row] = r13;
    lookup_words[105u * row_count + row] = r13;
    lookup_words[107u * row_count + row] = r13;
    unsigned r14 = 463900084u;
    lookup_words[109u * row_count + row] = r14;
    lookup_words[111u * row_count + row] = r14;
    lookup_words[113u * row_count + row] = r14;
    lookup_words[115u * row_count + row] = r14;
    lookup_words[117u * row_count + row] = r14;
    lookup_words[119u * row_count + row] = r14;
    unsigned r15 = 480677703u;
    lookup_words[69u * row_count + row] = r15;
    lookup_words[71u * row_count + row] = r15;
    lookup_words[73u * row_count + row] = r15;
    lookup_words[75u * row_count + row] = r15;
    lookup_words[77u * row_count + row] = r15;
    lookup_words[79u * row_count + row] = r15;
    lookup_words[81u * row_count + row] = r15;
    lookup_words[83u * row_count + row] = r15;
    unsigned r16 = 497455322u;
    lookup_words[85u * row_count + row] = r16;
    lookup_words[87u * row_count + row] = r16;
    lookup_words[89u * row_count + row] = r16;
    lookup_words[91u * row_count + row] = r16;
    lookup_words[93u * row_count + row] = r16;
    lookup_words[95u * row_count + row] = r16;
    unsigned r17 = 514232941u;
    lookup_words[37u * row_count + row] = r17;
    lookup_words[39u * row_count + row] = r17;
    lookup_words[41u * row_count + row] = r17;
    lookup_words[43u * row_count + row] = r17;
    lookup_words[45u * row_count + row] = r17;
    lookup_words[47u * row_count + row] = r17;
    lookup_words[49u * row_count + row] = r17;
    lookup_words[51u * row_count + row] = r17;
    unsigned r18 = 517791011u;
    lookup_words[133u * row_count + row] = r18;
    lookup_words[136u * row_count + row] = r18;
    lookup_words[139u * row_count + row] = r18;
    lookup_words[142u * row_count + row] = r18;
    lookup_words[145u * row_count + row] = r18;
    lookup_words[148u * row_count + row] = r18;
    unsigned r19 = 531010560u;
    lookup_words[53u * row_count + row] = r19;
    lookup_words[55u * row_count + row] = r19;
    lookup_words[57u * row_count + row] = r19;
    lookup_words[59u * row_count + row] = r19;
    lookup_words[61u * row_count + row] = r19;
    lookup_words[63u * row_count + row] = r19;
    lookup_words[65u * row_count + row] = r19;
    lookup_words[67u * row_count + row] = r19;
    unsigned r20 = 682009131u;
    lookup_words[121u * row_count + row] = r20;
    lookup_words[123u * row_count + row] = r20;
    lookup_words[125u * row_count + row] = r20;
    lookup_words[127u * row_count + row] = r20;
    lookup_words[129u * row_count + row] = r20;
    lookup_words[131u * row_count + row] = r20;
    unsigned r21 = 1410849886u;
    lookup_words[21u * row_count + row] = r21;
    lookup_words[23u * row_count + row] = r21;
    lookup_words[25u * row_count + row] = r21;
    lookup_words[27u * row_count + row] = r21;
    lookup_words[29u * row_count + row] = r21;
    lookup_words[31u * row_count + row] = r21;
    lookup_words[33u * row_count + row] = r21;
    lookup_words[35u * row_count + row] = r21;
    unsigned r22 = 1813904000u;
    lookup_words[241u * row_count + row] = r22;
    lookup_words[244u * row_count + row] = r22;
    lookup_words[247u * row_count + row] = r22;
    unsigned r23 = 1830681619u;
    lookup_words[223u * row_count + row] = r23;
    lookup_words[226u * row_count + row] = r23;
    lookup_words[229u * row_count + row] = r23;
    lookup_words[232u * row_count + row] = r23;
    lookup_words[235u * row_count + row] = r23;
    lookup_words[238u * row_count + row] = r23;
    unsigned r24 = 1847459238u;
    lookup_words[205u * row_count + row] = r24;
    lookup_words[208u * row_count + row] = r24;
    lookup_words[211u * row_count + row] = r24;
    lookup_words[214u * row_count + row] = r24;
    lookup_words[217u * row_count + row] = r24;
    lookup_words[220u * row_count + row] = r24;
    unsigned r25 = 1864236857u;
    lookup_words[187u * row_count + row] = r25;
    lookup_words[190u * row_count + row] = r25;
    lookup_words[193u * row_count + row] = r25;
    lookup_words[196u * row_count + row] = r25;
    lookup_words[199u * row_count + row] = r25;
    lookup_words[202u * row_count + row] = r25;
    unsigned r26 = 1881014476u;
    lookup_words[169u * row_count + row] = r26;
    lookup_words[172u * row_count + row] = r26;
    lookup_words[175u * row_count + row] = r26;
    lookup_words[178u * row_count + row] = r26;
    lookup_words[181u * row_count + row] = r26;
    lookup_words[184u * row_count + row] = r26;
    unsigned r27 = 1897792095u;
    lookup_words[151u * row_count + row] = r27;
    lookup_words[154u * row_count + row] = r27;
    lookup_words[157u * row_count + row] = r27;
    lookup_words[160u * row_count + row] = r27;
    lookup_words[163u * row_count + row] = r27;
    lookup_words[166u * row_count + row] = r27;
    unsigned r28 = 1987997202u;
    lookup_words[0u * row_count + row] = r28;
    unsigned r29 = 2065568285u;
    lookup_words[250u * row_count + row] = r29;
    lookup_words[253u * row_count + row] = r29;
    lookup_words[256u * row_count + row] = r29;
    unsigned r30 = input_cols[0u][row];
    unsigned r31 = input_cols[1u][row];
    unsigned r32 = input_cols[2u][row];
    unsigned r33 = input_cols[3u][row];
    unsigned r34 = input_cols[4u][row];
    unsigned r35 = input_cols[5u][row];
    unsigned r36 = input_cols[6u][row];
    unsigned r37 = input_cols[7u][row];
    unsigned r38 = input_cols[8u][row];
    unsigned r39 = input_cols[9u][row];
    unsigned r40 = input_cols[0u][row];
    unsigned r41 = input_cols[1u][row];
    unsigned r42 = input_cols[2u][row];
    unsigned r43 = input_cols[3u][row];
    unsigned r44 = input_cols[4u][row];
    unsigned r45 = input_cols[5u][row];
    unsigned r46 = input_cols[6u][row];
    unsigned r47 = input_cols[7u][row];
    unsigned r48 = input_cols[8u][row];
    unsigned r49 = input_cols[9u][row];
    unsigned r50 = input_cols[0u][row];
    unsigned r51 = input_cols[1u][row];
    unsigned r52 = input_cols[2u][row];
    unsigned r53 = input_cols[3u][row];
    unsigned r54 = input_cols[4u][row];
    unsigned r55 = input_cols[5u][row];
    unsigned r56 = input_cols[6u][row];
    unsigned r57 = input_cols[7u][row];
    unsigned r58 = input_cols[8u][row];
    unsigned r59 = input_cols[9u][row];
    unsigned r60 = input_cols[0u][row];
    unsigned r61 = input_cols[1u][row];
    unsigned r62 = input_cols[2u][row];
    unsigned r63 = input_cols[3u][row];
    unsigned r64 = input_cols[4u][row];
    unsigned r65 = input_cols[5u][row];
    unsigned r66 = input_cols[6u][row];
    unsigned r67 = input_cols[7u][row];
    unsigned r68 = input_cols[8u][row];
    unsigned r69 = input_cols[9u][row];
    unsigned r70 = input_cols[0u][row];
    unsigned r71 = input_cols[1u][row];
    unsigned r72 = input_cols[2u][row];
    unsigned r73 = input_cols[3u][row];
    unsigned r74 = input_cols[4u][row];
    unsigned r75 = input_cols[5u][row];
    unsigned r76 = input_cols[6u][row];
    unsigned r77 = input_cols[7u][row];
    unsigned r78 = input_cols[8u][row];
    unsigned r79 = input_cols[9u][row];
    unsigned r80 = input_cols[0u][row];
    unsigned r81 = input_cols[1u][row];
    unsigned r82 = input_cols[2u][row];
    unsigned r83 = input_cols[3u][row];
    unsigned r84 = input_cols[4u][row];
    unsigned r85 = input_cols[5u][row];
    unsigned r86 = input_cols[6u][row];
    unsigned r87 = input_cols[7u][row];
    unsigned r88 = input_cols[8u][row];
    unsigned r89 = input_cols[9u][row];
    unsigned r90 = input_cols[0u][row];
    unsigned r91 = input_cols[1u][row];
    unsigned r92 = input_cols[2u][row];
    unsigned r93 = input_cols[3u][row];
    unsigned r94 = input_cols[4u][row];
    unsigned r95 = input_cols[5u][row];
    unsigned r96 = input_cols[6u][row];
    unsigned r97 = input_cols[7u][row];
    unsigned r98 = input_cols[8u][row];
    unsigned r99 = input_cols[9u][row];
    unsigned r100 = input_cols[0u][row];
    unsigned r101 = input_cols[1u][row];
    unsigned r102 = input_cols[2u][row];
    unsigned r103 = input_cols[3u][row];
    unsigned r104 = input_cols[4u][row];
    unsigned r105 = input_cols[5u][row];
    unsigned r106 = input_cols[6u][row];
    unsigned r107 = input_cols[7u][row];
    unsigned r108 = input_cols[8u][row];
    unsigned r109 = input_cols[9u][row];
    unsigned r110 = input_cols[0u][row];
    unsigned r111 = input_cols[1u][row];
    unsigned r112 = input_cols[2u][row];
    unsigned r113 = input_cols[3u][row];
    unsigned r114 = input_cols[4u][row];
    unsigned r115 = input_cols[5u][row];
    unsigned r116 = input_cols[6u][row];
    unsigned r117 = input_cols[7u][row];
    unsigned r118 = input_cols[8u][row];
    unsigned r119 = input_cols[9u][row];
    unsigned r120 = input_cols[0u][row];
    unsigned r121 = input_cols[1u][row];
    unsigned r122 = input_cols[2u][row];
    unsigned r123 = input_cols[3u][row];
    unsigned r124 = input_cols[4u][row];
    unsigned r125 = input_cols[5u][row];
    unsigned r126 = input_cols[6u][row];
    unsigned r127 = input_cols[7u][row];
    unsigned r128 = input_cols[8u][row];
    unsigned r129 = input_cols[9u][row];
    unsigned r130 = input_cols[0u][row];
    unsigned r131 = input_cols[1u][row];
    unsigned r132 = input_cols[2u][row];
    unsigned r133 = input_cols[3u][row];
    unsigned r134 = input_cols[4u][row];
    unsigned r135 = input_cols[5u][row];
    unsigned r136 = input_cols[6u][row];
    unsigned r137 = input_cols[7u][row];
    unsigned r138 = input_cols[8u][row];
    unsigned r139 = input_cols[9u][row];
    unsigned r140 = (r130 & 511u);
    unsigned r141 = (r130 >> 9u);
    unsigned r142 = (r141 & 511u);
    unsigned r143 = (r130 >> 18u);
    unsigned r144 = (r143 & 511u);
    unsigned r145 = (r131 & 511u);
    unsigned r146 = (r131 >> 9u);
    unsigned r147 = (r146 & 511u);
    unsigned r148 = (r131 >> 18u);
    unsigned r149 = (r148 & 511u);
    unsigned r150 = (r132 & 511u);
    unsigned r151 = (r132 >> 9u);
    unsigned r152 = (r151 & 511u);
    unsigned r153 = (r132 >> 18u);
    unsigned r154 = (r153 & 511u);
    unsigned r155 = (r133 & 511u);
    unsigned r156 = (r133 >> 9u);
    unsigned r157 = (r156 & 511u);
    unsigned r158 = (r133 >> 18u);
    unsigned r159 = (r158 & 511u);
    unsigned r160 = (r134 & 511u);
    unsigned r161 = (r134 >> 9u);
    unsigned r162 = (r161 & 511u);
    unsigned r163 = (r134 >> 18u);
    unsigned r164 = (r163 & 511u);
    unsigned r165 = (r135 & 511u);
    unsigned r166 = (r135 >> 9u);
    unsigned r167 = (r166 & 511u);
    unsigned r168 = (r135 >> 18u);
    unsigned r169 = (r168 & 511u);
    unsigned r170 = (r136 & 511u);
    unsigned r171 = (r136 >> 9u);
    unsigned r172 = (r171 & 511u);
    unsigned r173 = (r136 >> 18u);
    unsigned r174 = (r173 & 511u);
    unsigned r175 = (r137 & 511u);
    unsigned r176 = (r137 >> 9u);
    unsigned r177 = (r176 & 511u);
    unsigned r178 = (r137 >> 18u);
    unsigned r179 = (r178 & 511u);
    unsigned r180 = (r138 & 511u);
    unsigned r181 = (r138 >> 9u);
    unsigned r182 = (r181 & 511u);
    unsigned r183 = (r138 >> 18u);
    unsigned r184 = (r183 & 511u);
    unsigned r185 = (r139 & 511u);
    unsigned r186 = stwo_m31_sub(r30, r140);
    out_cols[0u][row] = r30;
    lookup_words[1u * row_count + row] = r30;
    unsigned r187 = stwo_m31_mul(r142, r6);
    unsigned r188 = stwo_m31_sub(r186, r187);
    unsigned r189 = stwo_m31_mul(r188, r7);
    unsigned r190 = stwo_m31_sub(r41, r145);
    out_cols[1u][row] = r41;
    lookup_words[2u * row_count + row] = r41;
    unsigned r191 = stwo_m31_mul(r147, r6);
    unsigned r192 = stwo_m31_sub(r190, r191);
    unsigned r193 = stwo_m31_mul(r192, r7);
    unsigned r194 = stwo_m31_sub(r52, r150);
    out_cols[2u][row] = r52;
    lookup_words[3u * row_count + row] = r52;
    unsigned r195 = stwo_m31_mul(r152, r6);
    unsigned r196 = stwo_m31_sub(r194, r195);
    unsigned r197 = stwo_m31_mul(r196, r7);
    unsigned r198 = stwo_m31_sub(r63, r155);
    out_cols[3u][row] = r63;
    lookup_words[4u * row_count + row] = r63;
    unsigned r199 = stwo_m31_mul(r157, r6);
    unsigned r200 = stwo_m31_sub(r198, r199);
    unsigned r201 = stwo_m31_mul(r200, r7);
    unsigned r202 = stwo_m31_sub(r74, r160);
    out_cols[4u][row] = r74;
    lookup_words[5u * row_count + row] = r74;
    unsigned r203 = stwo_m31_mul(r162, r6);
    unsigned r204 = stwo_m31_sub(r202, r203);
    unsigned r205 = stwo_m31_mul(r204, r7);
    unsigned r206 = stwo_m31_sub(r85, r165);
    out_cols[5u][row] = r85;
    lookup_words[6u * row_count + row] = r85;
    unsigned r207 = stwo_m31_mul(r167, r6);
    unsigned r208 = stwo_m31_sub(r206, r207);
    unsigned r209 = stwo_m31_mul(r208, r7);
    unsigned r210 = stwo_m31_sub(r96, r170);
    out_cols[6u][row] = r96;
    lookup_words[7u * row_count + row] = r96;
    unsigned r211 = stwo_m31_mul(r172, r6);
    unsigned r212 = stwo_m31_sub(r210, r211);
    unsigned r213 = stwo_m31_mul(r212, r7);
    unsigned r214 = stwo_m31_sub(r107, r175);
    out_cols[7u][row] = r107;
    lookup_words[8u * row_count + row] = r107;
    unsigned r215 = stwo_m31_mul(r177, r6);
    unsigned r216 = stwo_m31_sub(r214, r215);
    unsigned r217 = stwo_m31_mul(r216, r7);
    unsigned r218 = stwo_m31_sub(r118, r180);
    out_cols[8u][row] = r118;
    lookup_words[9u * row_count + row] = r118;
    unsigned r219 = stwo_m31_mul(r182, r6);
    unsigned r220 = stwo_m31_sub(r218, r219);
    unsigned r221 = stwo_m31_mul(r220, r7);
    const unsigned dargs0[56] = { r140, r142, r189, r145, r147, r193, r150, r152, r197, r155, r157, r201, r160, r162, r205, r165, r167, r209, r170, r172, r213, r175, r177, r217, r180, r182, r221, r129, r140, r142, r189, r145, r147, r193, r150, r152, r197, r155, r157, r201, r160, r162, r205, r165, r167, r209, r170, r172, r213, r175, r177, r217, r180, r182, r221, r129 };
    unsigned douts0[28];
    stwo_wit_deduce_felt_mul(dargs0, douts0);
    unsigned r222 = douts0[0];
    unsigned r223 = douts0[1];
    unsigned r224 = douts0[2];
    unsigned r225 = douts0[3];
    unsigned r226 = douts0[4];
    unsigned r227 = douts0[5];
    unsigned r228 = douts0[6];
    unsigned r229 = douts0[7];
    unsigned r230 = douts0[8];
    unsigned r231 = douts0[9];
    unsigned r232 = douts0[10];
    unsigned r233 = douts0[11];
    unsigned r234 = douts0[12];
    unsigned r235 = douts0[13];
    unsigned r236 = douts0[14];
    unsigned r237 = douts0[15];
    unsigned r238 = douts0[16];
    unsigned r239 = douts0[17];
    unsigned r240 = douts0[18];
    unsigned r241 = douts0[19];
    unsigned r242 = douts0[20];
    unsigned r243 = douts0[21];
    unsigned r244 = douts0[22];
    unsigned r245 = douts0[23];
    unsigned r246 = douts0[24];
    unsigned r247 = douts0[25];
    unsigned r248 = douts0[26];
    unsigned r249 = douts0[27];
    unsigned r250 = stwo_m31_mul(r140, r140);
    unsigned r251 = stwo_m31_mul(r140, r142);
    unsigned r252 = stwo_m31_mul(r142, r140);
    unsigned r253 = stwo_m31_add(r251, r252);
    unsigned r254 = stwo_m31_mul(r140, r189);
    unsigned r255 = stwo_m31_mul(r142, r142);
    unsigned r256 = stwo_m31_add(r254, r255);
    unsigned r257 = stwo_m31_mul(r189, r140);
    unsigned r258 = stwo_m31_add(r256, r257);
    unsigned r259 = stwo_m31_mul(r140, r145);
    unsigned r260 = stwo_m31_mul(r142, r189);
    unsigned r261 = stwo_m31_add(r259, r260);
    unsigned r262 = stwo_m31_mul(r189, r142);
    unsigned r263 = stwo_m31_add(r261, r262);
    unsigned r264 = stwo_m31_mul(r145, r140);
    unsigned r265 = stwo_m31_add(r263, r264);
    unsigned r266 = stwo_m31_mul(r140, r147);
    unsigned r267 = stwo_m31_mul(r142, r145);
    unsigned r268 = stwo_m31_add(r266, r267);
    unsigned r269 = stwo_m31_mul(r189, r189);
    unsigned r270 = stwo_m31_add(r268, r269);
    unsigned r271 = stwo_m31_mul(r145, r142);
    unsigned r272 = stwo_m31_add(r270, r271);
    unsigned r273 = stwo_m31_mul(r147, r140);
    unsigned r274 = stwo_m31_add(r272, r273);
    unsigned r275 = stwo_m31_mul(r140, r193);
    unsigned r276 = stwo_m31_mul(r142, r147);
    unsigned r277 = stwo_m31_add(r275, r276);
    unsigned r278 = stwo_m31_mul(r189, r145);
    unsigned r279 = stwo_m31_add(r277, r278);
    unsigned r280 = stwo_m31_mul(r145, r189);
    unsigned r281 = stwo_m31_add(r279, r280);
    unsigned r282 = stwo_m31_mul(r147, r142);
    unsigned r283 = stwo_m31_add(r281, r282);
    unsigned r284 = stwo_m31_mul(r193, r140);
    unsigned r285 = stwo_m31_add(r283, r284);
    unsigned r286 = stwo_m31_mul(r140, r150);
    unsigned r287 = stwo_m31_mul(r142, r193);
    unsigned r288 = stwo_m31_add(r286, r287);
    unsigned r289 = stwo_m31_mul(r189, r147);
    unsigned r290 = stwo_m31_add(r288, r289);
    unsigned r291 = stwo_m31_mul(r145, r145);
    unsigned r292 = stwo_m31_add(r290, r291);
    unsigned r293 = stwo_m31_mul(r147, r189);
    unsigned r294 = stwo_m31_add(r292, r293);
    unsigned r295 = stwo_m31_mul(r193, r142);
    unsigned r296 = stwo_m31_add(r294, r295);
    unsigned r297 = stwo_m31_mul(r150, r140);
    unsigned r298 = stwo_m31_add(r296, r297);
    unsigned r299 = stwo_m31_mul(r142, r150);
    unsigned r300 = stwo_m31_mul(r189, r193);
    unsigned r301 = stwo_m31_add(r299, r300);
    unsigned r302 = stwo_m31_mul(r145, r147);
    unsigned r303 = stwo_m31_add(r301, r302);
    unsigned r304 = stwo_m31_mul(r147, r145);
    unsigned r305 = stwo_m31_add(r303, r304);
    unsigned r306 = stwo_m31_mul(r193, r189);
    unsigned r307 = stwo_m31_add(r305, r306);
    unsigned r308 = stwo_m31_mul(r150, r142);
    unsigned r309 = stwo_m31_add(r307, r308);
    unsigned r310 = stwo_m31_mul(r189, r150);
    unsigned r311 = stwo_m31_mul(r145, r193);
    unsigned r312 = stwo_m31_add(r310, r311);
    unsigned r313 = stwo_m31_mul(r147, r147);
    unsigned r314 = stwo_m31_add(r312, r313);
    unsigned r315 = stwo_m31_mul(r193, r145);
    unsigned r316 = stwo_m31_add(r314, r315);
    unsigned r317 = stwo_m31_mul(r150, r189);
    unsigned r318 = stwo_m31_add(r316, r317);
    unsigned r319 = stwo_m31_mul(r145, r150);
    unsigned r320 = stwo_m31_mul(r147, r193);
    unsigned r321 = stwo_m31_add(r319, r320);
    unsigned r322 = stwo_m31_mul(r193, r147);
    unsigned r323 = stwo_m31_add(r321, r322);
    unsigned r324 = stwo_m31_mul(r150, r145);
    unsigned r325 = stwo_m31_add(r323, r324);
    unsigned r326 = stwo_m31_mul(r147, r150);
    unsigned r327 = stwo_m31_mul(r193, r193);
    unsigned r328 = stwo_m31_add(r326, r327);
    unsigned r329 = stwo_m31_mul(r150, r147);
    unsigned r330 = stwo_m31_add(r328, r329);
    unsigned r331 = stwo_m31_mul(r193, r150);
    unsigned r332 = stwo_m31_mul(r150, r193);
    unsigned r333 = stwo_m31_add(r331, r332);
    unsigned r334 = stwo_m31_mul(r150, r150);
    unsigned r335 = stwo_m31_mul(r152, r152);
    unsigned r336 = stwo_m31_mul(r152, r197);
    unsigned r337 = stwo_m31_mul(r197, r152);
    unsigned r338 = stwo_m31_add(r336, r337);
    unsigned r339 = stwo_m31_mul(r152, r155);
    unsigned r340 = stwo_m31_mul(r197, r197);
    unsigned r341 = stwo_m31_add(r339, r340);
    unsigned r342 = stwo_m31_mul(r155, r152);
    unsigned r343 = stwo_m31_add(r341, r342);
    unsigned r344 = stwo_m31_mul(r152, r157);
    unsigned r345 = stwo_m31_mul(r197, r155);
    unsigned r346 = stwo_m31_add(r344, r345);
    unsigned r347 = stwo_m31_mul(r155, r197);
    unsigned r348 = stwo_m31_add(r346, r347);
    unsigned r349 = stwo_m31_mul(r157, r152);
    unsigned r350 = stwo_m31_add(r348, r349);
    unsigned r351 = stwo_m31_mul(r152, r201);
    unsigned r352 = stwo_m31_mul(r197, r157);
    unsigned r353 = stwo_m31_add(r351, r352);
    unsigned r354 = stwo_m31_mul(r155, r155);
    unsigned r355 = stwo_m31_add(r353, r354);
    unsigned r356 = stwo_m31_mul(r157, r197);
    unsigned r357 = stwo_m31_add(r355, r356);
    unsigned r358 = stwo_m31_mul(r201, r152);
    unsigned r359 = stwo_m31_add(r357, r358);
    unsigned r360 = stwo_m31_mul(r152, r160);
    unsigned r361 = stwo_m31_mul(r197, r201);
    unsigned r362 = stwo_m31_add(r360, r361);
    unsigned r363 = stwo_m31_mul(r155, r157);
    unsigned r364 = stwo_m31_add(r362, r363);
    unsigned r365 = stwo_m31_mul(r157, r155);
    unsigned r366 = stwo_m31_add(r364, r365);
    unsigned r367 = stwo_m31_mul(r201, r197);
    unsigned r368 = stwo_m31_add(r366, r367);
    unsigned r369 = stwo_m31_mul(r160, r152);
    unsigned r370 = stwo_m31_add(r368, r369);
    unsigned r371 = stwo_m31_mul(r152, r162);
    unsigned r372 = stwo_m31_mul(r197, r160);
    unsigned r373 = stwo_m31_add(r371, r372);
    unsigned r374 = stwo_m31_mul(r155, r201);
    unsigned r375 = stwo_m31_add(r373, r374);
    unsigned r376 = stwo_m31_mul(r157, r157);
    unsigned r377 = stwo_m31_add(r375, r376);
    unsigned r378 = stwo_m31_mul(r201, r155);
    unsigned r379 = stwo_m31_add(r377, r378);
    unsigned r380 = stwo_m31_mul(r160, r197);
    unsigned r381 = stwo_m31_add(r379, r380);
    unsigned r382 = stwo_m31_mul(r162, r152);
    unsigned r383 = stwo_m31_add(r381, r382);
    unsigned r384 = stwo_m31_mul(r197, r162);
    unsigned r385 = stwo_m31_mul(r155, r160);
    unsigned r386 = stwo_m31_add(r384, r385);
    unsigned r387 = stwo_m31_mul(r157, r201);
    unsigned r388 = stwo_m31_add(r386, r387);
    unsigned r389 = stwo_m31_mul(r201, r157);
    unsigned r390 = stwo_m31_add(r388, r389);
    unsigned r391 = stwo_m31_mul(r160, r155);
    unsigned r392 = stwo_m31_add(r390, r391);
    unsigned r393 = stwo_m31_mul(r162, r197);
    unsigned r394 = stwo_m31_add(r392, r393);
    unsigned r395 = stwo_m31_mul(r155, r162);
    unsigned r396 = stwo_m31_mul(r157, r160);
    unsigned r397 = stwo_m31_add(r395, r396);
    unsigned r398 = stwo_m31_mul(r201, r201);
    unsigned r399 = stwo_m31_add(r397, r398);
    unsigned r400 = stwo_m31_mul(r160, r157);
    unsigned r401 = stwo_m31_add(r399, r400);
    unsigned r402 = stwo_m31_mul(r162, r155);
    unsigned r403 = stwo_m31_add(r401, r402);
    unsigned r404 = stwo_m31_mul(r157, r162);
    unsigned r405 = stwo_m31_mul(r201, r160);
    unsigned r406 = stwo_m31_add(r404, r405);
    unsigned r407 = stwo_m31_mul(r160, r201);
    unsigned r408 = stwo_m31_add(r406, r407);
    unsigned r409 = stwo_m31_mul(r162, r157);
    unsigned r410 = stwo_m31_add(r408, r409);
    unsigned r411 = stwo_m31_mul(r201, r162);
    unsigned r412 = stwo_m31_mul(r160, r160);
    unsigned r413 = stwo_m31_add(r411, r412);
    unsigned r414 = stwo_m31_mul(r162, r201);
    unsigned r415 = stwo_m31_add(r413, r414);
    unsigned r416 = stwo_m31_mul(r160, r162);
    unsigned r417 = stwo_m31_mul(r162, r160);
    unsigned r418 = stwo_m31_add(r416, r417);
    unsigned r419 = stwo_m31_mul(r162, r162);
    unsigned r420 = stwo_m31_add(r140, r152);
    unsigned r421 = stwo_m31_add(r142, r197);
    unsigned r422 = stwo_m31_add(r189, r155);
    unsigned r423 = stwo_m31_add(r145, r157);
    unsigned r424 = stwo_m31_add(r147, r201);
    unsigned r425 = stwo_m31_add(r193, r160);
    unsigned r426 = stwo_m31_add(r150, r162);
    unsigned r427 = stwo_m31_add(r140, r152);
    unsigned r428 = stwo_m31_add(r142, r197);
    unsigned r429 = stwo_m31_add(r189, r155);
    unsigned r430 = stwo_m31_add(r145, r157);
    unsigned r431 = stwo_m31_add(r147, r201);
    unsigned r432 = stwo_m31_add(r193, r160);
    unsigned r433 = stwo_m31_add(r150, r162);
    unsigned r434 = stwo_m31_mul(r420, r427);
    unsigned r435 = stwo_m31_sub(r434, r250);
    unsigned r436 = stwo_m31_sub(r435, r335);
    unsigned r437 = stwo_m31_add(r309, r436);
    unsigned r438 = stwo_m31_mul(r420, r428);
    unsigned r439 = stwo_m31_mul(r421, r427);
    unsigned r440 = stwo_m31_add(r438, r439);
    unsigned r441 = stwo_m31_sub(r440, r253);
    unsigned r442 = stwo_m31_sub(r441, r338);
    unsigned r443 = stwo_m31_add(r318, r442);
    unsigned r444 = stwo_m31_mul(r420, r429);
    unsigned r445 = stwo_m31_mul(r421, r428);
    unsigned r446 = stwo_m31_add(r444, r445);
    unsigned r447 = stwo_m31_mul(r422, r427);
    unsigned r448 = stwo_m31_add(r446, r447);
    unsigned r449 = stwo_m31_sub(r448, r258);
    unsigned r450 = stwo_m31_sub(r449, r343);
    unsigned r451 = stwo_m31_add(r325, r450);
    unsigned r452 = stwo_m31_mul(r420, r430);
    unsigned r453 = stwo_m31_mul(r421, r429);
    unsigned r454 = stwo_m31_add(r452, r453);
    unsigned r455 = stwo_m31_mul(r422, r428);
    unsigned r456 = stwo_m31_add(r454, r455);
    unsigned r457 = stwo_m31_mul(r423, r427);
    unsigned r458 = stwo_m31_add(r456, r457);
    unsigned r459 = stwo_m31_sub(r458, r265);
    unsigned r460 = stwo_m31_sub(r459, r350);
    unsigned r461 = stwo_m31_add(r330, r460);
    unsigned r462 = stwo_m31_mul(r420, r431);
    unsigned r463 = stwo_m31_mul(r421, r430);
    unsigned r464 = stwo_m31_add(r462, r463);
    unsigned r465 = stwo_m31_mul(r422, r429);
    unsigned r466 = stwo_m31_add(r464, r465);
    unsigned r467 = stwo_m31_mul(r423, r428);
    unsigned r468 = stwo_m31_add(r466, r467);
    unsigned r469 = stwo_m31_mul(r424, r427);
    unsigned r470 = stwo_m31_add(r468, r469);
    unsigned r471 = stwo_m31_sub(r470, r274);
    unsigned r472 = stwo_m31_sub(r471, r359);
    unsigned r473 = stwo_m31_add(r333, r472);
    unsigned r474 = stwo_m31_mul(r420, r432);
    unsigned r475 = stwo_m31_mul(r421, r431);
    unsigned r476 = stwo_m31_add(r474, r475);
    unsigned r477 = stwo_m31_mul(r422, r430);
    unsigned r478 = stwo_m31_add(r476, r477);
    unsigned r479 = stwo_m31_mul(r423, r429);
    unsigned r480 = stwo_m31_add(r478, r479);
    unsigned r481 = stwo_m31_mul(r424, r428);
    unsigned r482 = stwo_m31_add(r480, r481);
    unsigned r483 = stwo_m31_mul(r425, r427);
    unsigned r484 = stwo_m31_add(r482, r483);
    unsigned r485 = stwo_m31_sub(r484, r285);
    unsigned r486 = stwo_m31_sub(r485, r370);
    unsigned r487 = stwo_m31_add(r334, r486);
    unsigned r488 = stwo_m31_mul(r420, r433);
    unsigned r489 = stwo_m31_mul(r421, r432);
    unsigned r490 = stwo_m31_add(r488, r489);
    unsigned r491 = stwo_m31_mul(r422, r431);
    unsigned r492 = stwo_m31_add(r490, r491);
    unsigned r493 = stwo_m31_mul(r423, r430);
    unsigned r494 = stwo_m31_add(r492, r493);
    unsigned r495 = stwo_m31_mul(r424, r429);
    unsigned r496 = stwo_m31_add(r494, r495);
    unsigned r497 = stwo_m31_mul(r425, r428);
    unsigned r498 = stwo_m31_add(r496, r497);
    unsigned r499 = stwo_m31_mul(r426, r427);
    unsigned r500 = stwo_m31_add(r498, r499);
    unsigned r501 = stwo_m31_sub(r500, r298);
    unsigned r502 = stwo_m31_sub(r501, r383);
    unsigned r503 = stwo_m31_mul(r421, r433);
    unsigned r504 = stwo_m31_mul(r422, r432);
    unsigned r505 = stwo_m31_add(r503, r504);
    unsigned r506 = stwo_m31_mul(r423, r431);
    unsigned r507 = stwo_m31_add(r505, r506);
    unsigned r508 = stwo_m31_mul(r424, r430);
    unsigned r509 = stwo_m31_add(r507, r508);
    unsigned r510 = stwo_m31_mul(r425, r429);
    unsigned r511 = stwo_m31_add(r509, r510);
    unsigned r512 = stwo_m31_mul(r426, r428);
    unsigned r513 = stwo_m31_add(r511, r512);
    unsigned r514 = stwo_m31_sub(r513, r309);
    unsigned r515 = stwo_m31_sub(r514, r394);
    unsigned r516 = stwo_m31_add(r335, r515);
    unsigned r517 = stwo_m31_mul(r422, r433);
    unsigned r518 = stwo_m31_mul(r423, r432);
    unsigned r519 = stwo_m31_add(r517, r518);
    unsigned r520 = stwo_m31_mul(r424, r431);
    unsigned r521 = stwo_m31_add(r519, r520);
    unsigned r522 = stwo_m31_mul(r425, r430);
    unsigned r523 = stwo_m31_add(r521, r522);
    unsigned r524 = stwo_m31_mul(r426, r429);
    unsigned r525 = stwo_m31_add(r523, r524);
    unsigned r526 = stwo_m31_sub(r525, r318);
    unsigned r527 = stwo_m31_sub(r526, r403);
    unsigned r528 = stwo_m31_add(r338, r527);
    unsigned r529 = stwo_m31_mul(r423, r433);
    unsigned r530 = stwo_m31_mul(r424, r432);
    unsigned r531 = stwo_m31_add(r529, r530);
    unsigned r532 = stwo_m31_mul(r425, r431);
    unsigned r533 = stwo_m31_add(r531, r532);
    unsigned r534 = stwo_m31_mul(r426, r430);
    unsigned r535 = stwo_m31_add(r533, r534);
    unsigned r536 = stwo_m31_sub(r535, r325);
    unsigned r537 = stwo_m31_sub(r536, r410);
    unsigned r538 = stwo_m31_add(r343, r537);
    unsigned r539 = stwo_m31_mul(r424, r433);
    unsigned r540 = stwo_m31_mul(r425, r432);
    unsigned r541 = stwo_m31_add(r539, r540);
    unsigned r542 = stwo_m31_mul(r426, r431);
    unsigned r543 = stwo_m31_add(r541, r542);
    unsigned r544 = stwo_m31_sub(r543, r330);
    unsigned r545 = stwo_m31_sub(r544, r415);
    unsigned r546 = stwo_m31_add(r350, r545);
    unsigned r547 = stwo_m31_mul(r425, r433);
    unsigned r548 = stwo_m31_mul(r426, r432);
    unsigned r549 = stwo_m31_add(r547, r548);
    unsigned r550 = stwo_m31_sub(r549, r333);
    unsigned r551 = stwo_m31_sub(r550, r418);
    unsigned r552 = stwo_m31_add(r359, r551);
    unsigned r553 = stwo_m31_mul(r426, r433);
    unsigned r554 = stwo_m31_sub(r553, r334);
    unsigned r555 = stwo_m31_sub(r554, r419);
    unsigned r556 = stwo_m31_add(r370, r555);
    unsigned r557 = stwo_m31_mul(r205, r205);
    unsigned r558 = stwo_m31_mul(r205, r165);
    unsigned r559 = stwo_m31_mul(r165, r205);
    unsigned r560 = stwo_m31_add(r558, r559);
    unsigned r561 = stwo_m31_mul(r205, r167);
    unsigned r562 = stwo_m31_mul(r165, r165);
    unsigned r563 = stwo_m31_add(r561, r562);
    unsigned r564 = stwo_m31_mul(r167, r205);
    unsigned r565 = stwo_m31_add(r563, r564);
    unsigned r566 = stwo_m31_mul(r205, r209);
    unsigned r567 = stwo_m31_mul(r165, r167);
    unsigned r568 = stwo_m31_add(r566, r567);
    unsigned r569 = stwo_m31_mul(r167, r165);
    unsigned r570 = stwo_m31_add(r568, r569);
    unsigned r571 = stwo_m31_mul(r209, r205);
    unsigned r572 = stwo_m31_add(r570, r571);
    unsigned r573 = stwo_m31_mul(r205, r170);
    unsigned r574 = stwo_m31_mul(r165, r209);
    unsigned r575 = stwo_m31_add(r573, r574);
    unsigned r576 = stwo_m31_mul(r167, r167);
    unsigned r577 = stwo_m31_add(r575, r576);
    unsigned r578 = stwo_m31_mul(r209, r165);
    unsigned r579 = stwo_m31_add(r577, r578);
    unsigned r580 = stwo_m31_mul(r170, r205);
    unsigned r581 = stwo_m31_add(r579, r580);
    unsigned r582 = stwo_m31_mul(r205, r172);
    unsigned r583 = stwo_m31_mul(r165, r170);
    unsigned r584 = stwo_m31_add(r582, r583);
    unsigned r585 = stwo_m31_mul(r167, r209);
    unsigned r586 = stwo_m31_add(r584, r585);
    unsigned r587 = stwo_m31_mul(r209, r167);
    unsigned r588 = stwo_m31_add(r586, r587);
    unsigned r589 = stwo_m31_mul(r170, r165);
    unsigned r590 = stwo_m31_add(r588, r589);
    unsigned r591 = stwo_m31_mul(r172, r205);
    unsigned r592 = stwo_m31_add(r590, r591);
    unsigned r593 = stwo_m31_mul(r205, r213);
    unsigned r594 = stwo_m31_mul(r165, r172);
    unsigned r595 = stwo_m31_add(r593, r594);
    unsigned r596 = stwo_m31_mul(r167, r170);
    unsigned r597 = stwo_m31_add(r595, r596);
    unsigned r598 = stwo_m31_mul(r209, r209);
    unsigned r599 = stwo_m31_add(r597, r598);
    unsigned r600 = stwo_m31_mul(r170, r167);
    unsigned r601 = stwo_m31_add(r599, r600);
    unsigned r602 = stwo_m31_mul(r172, r165);
    unsigned r603 = stwo_m31_add(r601, r602);
    unsigned r604 = stwo_m31_mul(r213, r205);
    unsigned r605 = stwo_m31_add(r603, r604);
    unsigned r606 = stwo_m31_mul(r165, r213);
    unsigned r607 = stwo_m31_mul(r167, r172);
    unsigned r608 = stwo_m31_add(r606, r607);
    unsigned r609 = stwo_m31_mul(r209, r170);
    unsigned r610 = stwo_m31_add(r608, r609);
    unsigned r611 = stwo_m31_mul(r170, r209);
    unsigned r612 = stwo_m31_add(r610, r611);
    unsigned r613 = stwo_m31_mul(r172, r167);
    unsigned r614 = stwo_m31_add(r612, r613);
    unsigned r615 = stwo_m31_mul(r213, r165);
    unsigned r616 = stwo_m31_add(r614, r615);
    unsigned r617 = stwo_m31_mul(r167, r213);
    unsigned r618 = stwo_m31_mul(r209, r172);
    unsigned r619 = stwo_m31_add(r617, r618);
    unsigned r620 = stwo_m31_mul(r170, r170);
    unsigned r621 = stwo_m31_add(r619, r620);
    unsigned r622 = stwo_m31_mul(r172, r209);
    unsigned r623 = stwo_m31_add(r621, r622);
    unsigned r624 = stwo_m31_mul(r213, r167);
    unsigned r625 = stwo_m31_add(r623, r624);
    unsigned r626 = stwo_m31_mul(r209, r213);
    unsigned r627 = stwo_m31_mul(r170, r172);
    unsigned r628 = stwo_m31_add(r626, r627);
    unsigned r629 = stwo_m31_mul(r172, r170);
    unsigned r630 = stwo_m31_add(r628, r629);
    unsigned r631 = stwo_m31_mul(r213, r209);
    unsigned r632 = stwo_m31_add(r630, r631);
    unsigned r633 = stwo_m31_mul(r170, r213);
    unsigned r634 = stwo_m31_mul(r172, r172);
    unsigned r635 = stwo_m31_add(r633, r634);
    unsigned r636 = stwo_m31_mul(r213, r170);
    unsigned r637 = stwo_m31_add(r635, r636);
    unsigned r638 = stwo_m31_mul(r172, r213);
    unsigned r639 = stwo_m31_mul(r213, r172);
    unsigned r640 = stwo_m31_add(r638, r639);
    unsigned r641 = stwo_m31_mul(r213, r213);
    unsigned r642 = stwo_m31_mul(r175, r175);
    unsigned r643 = stwo_m31_mul(r175, r177);
    unsigned r644 = stwo_m31_mul(r177, r175);
    unsigned r645 = stwo_m31_add(r643, r644);
    unsigned r646 = stwo_m31_mul(r175, r217);
    unsigned r647 = stwo_m31_mul(r177, r177);
    unsigned r648 = stwo_m31_add(r646, r647);
    unsigned r649 = stwo_m31_mul(r217, r175);
    unsigned r650 = stwo_m31_add(r648, r649);
    unsigned r651 = stwo_m31_mul(r175, r180);
    unsigned r652 = stwo_m31_mul(r177, r217);
    unsigned r653 = stwo_m31_add(r651, r652);
    unsigned r654 = stwo_m31_mul(r217, r177);
    unsigned r655 = stwo_m31_add(r653, r654);
    unsigned r656 = stwo_m31_mul(r180, r175);
    unsigned r657 = stwo_m31_add(r655, r656);
    unsigned r658 = stwo_m31_mul(r175, r182);
    unsigned r659 = stwo_m31_mul(r177, r180);
    unsigned r660 = stwo_m31_add(r658, r659);
    unsigned r661 = stwo_m31_mul(r217, r217);
    unsigned r662 = stwo_m31_add(r660, r661);
    unsigned r663 = stwo_m31_mul(r180, r177);
    unsigned r664 = stwo_m31_add(r662, r663);
    unsigned r665 = stwo_m31_mul(r182, r175);
    unsigned r666 = stwo_m31_add(r664, r665);
    unsigned r667 = stwo_m31_mul(r175, r221);
    unsigned r668 = stwo_m31_mul(r177, r182);
    unsigned r669 = stwo_m31_add(r667, r668);
    unsigned r670 = stwo_m31_mul(r217, r180);
    unsigned r671 = stwo_m31_add(r669, r670);
    unsigned r672 = stwo_m31_mul(r180, r217);
    unsigned r673 = stwo_m31_add(r671, r672);
    unsigned r674 = stwo_m31_mul(r182, r177);
    unsigned r675 = stwo_m31_add(r673, r674);
    unsigned r676 = stwo_m31_mul(r221, r175);
    unsigned r677 = stwo_m31_add(r675, r676);
    unsigned r678 = stwo_m31_mul(r175, r129);
    unsigned r679 = stwo_m31_mul(r177, r221);
    unsigned r680 = stwo_m31_add(r678, r679);
    unsigned r681 = stwo_m31_mul(r217, r182);
    unsigned r682 = stwo_m31_add(r680, r681);
    unsigned r683 = stwo_m31_mul(r180, r180);
    unsigned r684 = stwo_m31_add(r682, r683);
    unsigned r685 = stwo_m31_mul(r182, r217);
    unsigned r686 = stwo_m31_add(r684, r685);
    unsigned r687 = stwo_m31_mul(r221, r177);
    unsigned r688 = stwo_m31_add(r686, r687);
    unsigned r689 = stwo_m31_mul(r129, r175);
    unsigned r690 = stwo_m31_add(r688, r689);
    unsigned r691 = stwo_m31_mul(r177, r129);
    unsigned r692 = stwo_m31_mul(r217, r221);
    unsigned r693 = stwo_m31_add(r691, r692);
    unsigned r694 = stwo_m31_mul(r180, r182);
    unsigned r695 = stwo_m31_add(r693, r694);
    unsigned r696 = stwo_m31_mul(r182, r180);
    unsigned r697 = stwo_m31_add(r695, r696);
    unsigned r698 = stwo_m31_mul(r221, r217);
    unsigned r699 = stwo_m31_add(r697, r698);
    unsigned r700 = stwo_m31_mul(r129, r177);
    unsigned r701 = stwo_m31_add(r699, r700);
    unsigned r702 = stwo_m31_mul(r217, r129);
    unsigned r703 = stwo_m31_mul(r180, r221);
    unsigned r704 = stwo_m31_add(r702, r703);
    unsigned r705 = stwo_m31_mul(r182, r182);
    unsigned r706 = stwo_m31_add(r704, r705);
    unsigned r707 = stwo_m31_mul(r221, r180);
    unsigned r708 = stwo_m31_add(r706, r707);
    unsigned r709 = stwo_m31_mul(r129, r217);
    unsigned r710 = stwo_m31_add(r708, r709);
    unsigned r711 = stwo_m31_mul(r180, r129);
    unsigned r712 = stwo_m31_mul(r182, r221);
    unsigned r713 = stwo_m31_add(r711, r712);
    unsigned r714 = stwo_m31_mul(r221, r182);
    unsigned r715 = stwo_m31_add(r713, r714);
    unsigned r716 = stwo_m31_mul(r129, r180);
    unsigned r717 = stwo_m31_add(r715, r716);
    unsigned r718 = stwo_m31_mul(r182, r129);
    unsigned r719 = stwo_m31_mul(r221, r221);
    unsigned r720 = stwo_m31_add(r718, r719);
    unsigned r721 = stwo_m31_mul(r129, r182);
    unsigned r722 = stwo_m31_add(r720, r721);
    unsigned r723 = stwo_m31_mul(r221, r129);
    unsigned r724 = stwo_m31_mul(r129, r221);
    unsigned r725 = stwo_m31_add(r723, r724);
    unsigned r726 = stwo_m31_mul(r129, r129);
    unsigned r727 = stwo_m31_add(r205, r175);
    unsigned r728 = stwo_m31_add(r165, r177);
    unsigned r729 = stwo_m31_add(r167, r217);
    unsigned r730 = stwo_m31_add(r209, r180);
    unsigned r731 = stwo_m31_add(r170, r182);
    unsigned r732 = stwo_m31_add(r172, r221);
    unsigned r733 = stwo_m31_add(r213, r129);
    unsigned r734 = stwo_m31_add(r205, r175);
    unsigned r735 = stwo_m31_add(r165, r177);
    unsigned r736 = stwo_m31_add(r167, r217);
    unsigned r737 = stwo_m31_add(r209, r180);
    unsigned r738 = stwo_m31_add(r170, r182);
    unsigned r739 = stwo_m31_add(r172, r221);
    unsigned r740 = stwo_m31_add(r213, r129);
    unsigned r741 = stwo_m31_mul(r727, r734);
    unsigned r742 = stwo_m31_sub(r741, r557);
    unsigned r743 = stwo_m31_sub(r742, r642);
    unsigned r744 = stwo_m31_add(r616, r743);
    unsigned r745 = stwo_m31_mul(r727, r735);
    unsigned r746 = stwo_m31_mul(r728, r734);
    unsigned r747 = stwo_m31_add(r745, r746);
    unsigned r748 = stwo_m31_sub(r747, r560);
    unsigned r749 = stwo_m31_sub(r748, r645);
    unsigned r750 = stwo_m31_add(r625, r749);
    unsigned r751 = stwo_m31_mul(r727, r736);
    unsigned r752 = stwo_m31_mul(r728, r735);
    unsigned r753 = stwo_m31_add(r751, r752);
    unsigned r754 = stwo_m31_mul(r729, r734);
    unsigned r755 = stwo_m31_add(r753, r754);
    unsigned r756 = stwo_m31_sub(r755, r565);
    unsigned r757 = stwo_m31_sub(r756, r650);
    unsigned r758 = stwo_m31_add(r632, r757);
    unsigned r759 = stwo_m31_mul(r727, r737);
    unsigned r760 = stwo_m31_mul(r728, r736);
    unsigned r761 = stwo_m31_add(r759, r760);
    unsigned r762 = stwo_m31_mul(r729, r735);
    unsigned r763 = stwo_m31_add(r761, r762);
    unsigned r764 = stwo_m31_mul(r730, r734);
    unsigned r765 = stwo_m31_add(r763, r764);
    unsigned r766 = stwo_m31_sub(r765, r572);
    unsigned r767 = stwo_m31_sub(r766, r657);
    unsigned r768 = stwo_m31_add(r637, r767);
    unsigned r769 = stwo_m31_mul(r727, r738);
    unsigned r770 = stwo_m31_mul(r728, r737);
    unsigned r771 = stwo_m31_add(r769, r770);
    unsigned r772 = stwo_m31_mul(r729, r736);
    unsigned r773 = stwo_m31_add(r771, r772);
    unsigned r774 = stwo_m31_mul(r730, r735);
    unsigned r775 = stwo_m31_add(r773, r774);
    unsigned r776 = stwo_m31_mul(r731, r734);
    unsigned r777 = stwo_m31_add(r775, r776);
    unsigned r778 = stwo_m31_sub(r777, r581);
    unsigned r779 = stwo_m31_sub(r778, r666);
    unsigned r780 = stwo_m31_add(r640, r779);
    unsigned r781 = stwo_m31_mul(r727, r739);
    unsigned r782 = stwo_m31_mul(r728, r738);
    unsigned r783 = stwo_m31_add(r781, r782);
    unsigned r784 = stwo_m31_mul(r729, r737);
    unsigned r785 = stwo_m31_add(r783, r784);
    unsigned r786 = stwo_m31_mul(r730, r736);
    unsigned r787 = stwo_m31_add(r785, r786);
    unsigned r788 = stwo_m31_mul(r731, r735);
    unsigned r789 = stwo_m31_add(r787, r788);
    unsigned r790 = stwo_m31_mul(r732, r734);
    unsigned r791 = stwo_m31_add(r789, r790);
    unsigned r792 = stwo_m31_sub(r791, r592);
    unsigned r793 = stwo_m31_sub(r792, r677);
    unsigned r794 = stwo_m31_add(r641, r793);
    unsigned r795 = stwo_m31_mul(r727, r740);
    unsigned r796 = stwo_m31_mul(r728, r739);
    unsigned r797 = stwo_m31_add(r795, r796);
    unsigned r798 = stwo_m31_mul(r729, r738);
    unsigned r799 = stwo_m31_add(r797, r798);
    unsigned r800 = stwo_m31_mul(r730, r737);
    unsigned r801 = stwo_m31_add(r799, r800);
    unsigned r802 = stwo_m31_mul(r731, r736);
    unsigned r803 = stwo_m31_add(r801, r802);
    unsigned r804 = stwo_m31_mul(r732, r735);
    unsigned r805 = stwo_m31_add(r803, r804);
    unsigned r806 = stwo_m31_mul(r733, r734);
    unsigned r807 = stwo_m31_add(r805, r806);
    unsigned r808 = stwo_m31_sub(r807, r605);
    unsigned r809 = stwo_m31_sub(r808, r690);
    unsigned r810 = stwo_m31_mul(r728, r740);
    unsigned r811 = stwo_m31_mul(r729, r739);
    unsigned r812 = stwo_m31_add(r810, r811);
    unsigned r813 = stwo_m31_mul(r730, r738);
    unsigned r814 = stwo_m31_add(r812, r813);
    unsigned r815 = stwo_m31_mul(r731, r737);
    unsigned r816 = stwo_m31_add(r814, r815);
    unsigned r817 = stwo_m31_mul(r732, r736);
    unsigned r818 = stwo_m31_add(r816, r817);
    unsigned r819 = stwo_m31_mul(r733, r735);
    unsigned r820 = stwo_m31_add(r818, r819);
    unsigned r821 = stwo_m31_sub(r820, r616);
    unsigned r822 = stwo_m31_sub(r821, r701);
    unsigned r823 = stwo_m31_add(r642, r822);
    unsigned r824 = stwo_m31_mul(r729, r740);
    unsigned r825 = stwo_m31_mul(r730, r739);
    unsigned r826 = stwo_m31_add(r824, r825);
    unsigned r827 = stwo_m31_mul(r731, r738);
    unsigned r828 = stwo_m31_add(r826, r827);
    unsigned r829 = stwo_m31_mul(r732, r737);
    unsigned r830 = stwo_m31_add(r828, r829);
    unsigned r831 = stwo_m31_mul(r733, r736);
    unsigned r832 = stwo_m31_add(r830, r831);
    unsigned r833 = stwo_m31_sub(r832, r625);
    unsigned r834 = stwo_m31_sub(r833, r710);
    unsigned r835 = stwo_m31_add(r645, r834);
    unsigned r836 = stwo_m31_mul(r730, r740);
    unsigned r837 = stwo_m31_mul(r731, r739);
    unsigned r838 = stwo_m31_add(r836, r837);
    unsigned r839 = stwo_m31_mul(r732, r738);
    unsigned r840 = stwo_m31_add(r838, r839);
    unsigned r841 = stwo_m31_mul(r733, r737);
    unsigned r842 = stwo_m31_add(r840, r841);
    unsigned r843 = stwo_m31_sub(r842, r632);
    unsigned r844 = stwo_m31_sub(r843, r717);
    unsigned r845 = stwo_m31_add(r650, r844);
    unsigned r846 = stwo_m31_mul(r731, r740);
    unsigned r847 = stwo_m31_mul(r732, r739);
    unsigned r848 = stwo_m31_add(r846, r847);
    unsigned r849 = stwo_m31_mul(r733, r738);
    unsigned r850 = stwo_m31_add(r848, r849);
    unsigned r851 = stwo_m31_sub(r850, r637);
    unsigned r852 = stwo_m31_sub(r851, r722);
    unsigned r853 = stwo_m31_add(r657, r852);
    unsigned r854 = stwo_m31_mul(r732, r740);
    unsigned r855 = stwo_m31_mul(r733, r739);
    unsigned r856 = stwo_m31_add(r854, r855);
    unsigned r857 = stwo_m31_sub(r856, r640);
    unsigned r858 = stwo_m31_sub(r857, r725);
    unsigned r859 = stwo_m31_add(r666, r858);
    unsigned r860 = stwo_m31_mul(r733, r740);
    unsigned r861 = stwo_m31_sub(r860, r641);
    unsigned r862 = stwo_m31_sub(r861, r726);
    unsigned r863 = stwo_m31_add(r677, r862);
    unsigned r864 = stwo_m31_add(r140, r205);
    unsigned r865 = stwo_m31_add(r142, r165);
    unsigned r866 = stwo_m31_add(r189, r167);
    unsigned r867 = stwo_m31_add(r145, r209);
    unsigned r868 = stwo_m31_add(r147, r170);
    unsigned r869 = stwo_m31_add(r193, r172);
    unsigned r870 = stwo_m31_add(r150, r213);
    unsigned r871 = stwo_m31_add(r152, r175);
    unsigned r872 = stwo_m31_add(r197, r177);
    unsigned r873 = stwo_m31_add(r155, r217);
    unsigned r874 = stwo_m31_add(r157, r180);
    unsigned r875 = stwo_m31_add(r201, r182);
    unsigned r876 = stwo_m31_add(r160, r221);
    unsigned r877 = stwo_m31_add(r162, r129);
    unsigned r878 = stwo_m31_add(r140, r205);
    unsigned r879 = stwo_m31_add(r142, r165);
    unsigned r880 = stwo_m31_add(r189, r167);
    unsigned r881 = stwo_m31_add(r145, r209);
    unsigned r882 = stwo_m31_add(r147, r170);
    unsigned r883 = stwo_m31_add(r193, r172);
    unsigned r884 = stwo_m31_add(r150, r213);
    unsigned r885 = stwo_m31_add(r152, r175);
    unsigned r886 = stwo_m31_add(r197, r177);
    unsigned r887 = stwo_m31_add(r155, r217);
    unsigned r888 = stwo_m31_add(r157, r180);
    unsigned r889 = stwo_m31_add(r201, r182);
    unsigned r890 = stwo_m31_add(r160, r221);
    unsigned r891 = stwo_m31_add(r162, r129);
    unsigned r892 = stwo_m31_mul(r864, r878);
    unsigned r893 = stwo_m31_mul(r864, r879);
    unsigned r894 = stwo_m31_mul(r865, r878);
    unsigned r895 = stwo_m31_add(r893, r894);
    unsigned r896 = stwo_m31_mul(r864, r880);
    unsigned r897 = stwo_m31_mul(r865, r879);
    unsigned r898 = stwo_m31_add(r896, r897);
    unsigned r899 = stwo_m31_mul(r866, r878);
    unsigned r900 = stwo_m31_add(r898, r899);
    unsigned r901 = stwo_m31_mul(r864, r881);
    unsigned r902 = stwo_m31_mul(r865, r880);
    unsigned r903 = stwo_m31_add(r901, r902);
    unsigned r904 = stwo_m31_mul(r866, r879);
    unsigned r905 = stwo_m31_add(r903, r904);
    unsigned r906 = stwo_m31_mul(r867, r878);
    unsigned r907 = stwo_m31_add(r905, r906);
    unsigned r908 = stwo_m31_mul(r864, r882);
    unsigned r909 = stwo_m31_mul(r865, r881);
    unsigned r910 = stwo_m31_add(r908, r909);
    unsigned r911 = stwo_m31_mul(r866, r880);
    unsigned r912 = stwo_m31_add(r910, r911);
    unsigned r913 = stwo_m31_mul(r867, r879);
    unsigned r914 = stwo_m31_add(r912, r913);
    unsigned r915 = stwo_m31_mul(r868, r878);
    unsigned r916 = stwo_m31_add(r914, r915);
    unsigned r917 = stwo_m31_mul(r864, r883);
    unsigned r918 = stwo_m31_mul(r865, r882);
    unsigned r919 = stwo_m31_add(r917, r918);
    unsigned r920 = stwo_m31_mul(r866, r881);
    unsigned r921 = stwo_m31_add(r919, r920);
    unsigned r922 = stwo_m31_mul(r867, r880);
    unsigned r923 = stwo_m31_add(r921, r922);
    unsigned r924 = stwo_m31_mul(r868, r879);
    unsigned r925 = stwo_m31_add(r923, r924);
    unsigned r926 = stwo_m31_mul(r869, r878);
    unsigned r927 = stwo_m31_add(r925, r926);
    unsigned r928 = stwo_m31_mul(r864, r884);
    unsigned r929 = stwo_m31_mul(r865, r883);
    unsigned r930 = stwo_m31_add(r928, r929);
    unsigned r931 = stwo_m31_mul(r866, r882);
    unsigned r932 = stwo_m31_add(r930, r931);
    unsigned r933 = stwo_m31_mul(r867, r881);
    unsigned r934 = stwo_m31_add(r932, r933);
    unsigned r935 = stwo_m31_mul(r868, r880);
    unsigned r936 = stwo_m31_add(r934, r935);
    unsigned r937 = stwo_m31_mul(r869, r879);
    unsigned r938 = stwo_m31_add(r936, r937);
    unsigned r939 = stwo_m31_mul(r870, r878);
    unsigned r940 = stwo_m31_add(r938, r939);
    unsigned r941 = stwo_m31_mul(r865, r884);
    unsigned r942 = stwo_m31_mul(r866, r883);
    unsigned r943 = stwo_m31_add(r941, r942);
    unsigned r944 = stwo_m31_mul(r867, r882);
    unsigned r945 = stwo_m31_add(r943, r944);
    unsigned r946 = stwo_m31_mul(r868, r881);
    unsigned r947 = stwo_m31_add(r945, r946);
    unsigned r948 = stwo_m31_mul(r869, r880);
    unsigned r949 = stwo_m31_add(r947, r948);
    unsigned r950 = stwo_m31_mul(r870, r879);
    unsigned r951 = stwo_m31_add(r949, r950);
    unsigned r952 = stwo_m31_mul(r866, r884);
    unsigned r953 = stwo_m31_mul(r867, r883);
    unsigned r954 = stwo_m31_add(r952, r953);
    unsigned r955 = stwo_m31_mul(r868, r882);
    unsigned r956 = stwo_m31_add(r954, r955);
    unsigned r957 = stwo_m31_mul(r869, r881);
    unsigned r958 = stwo_m31_add(r956, r957);
    unsigned r959 = stwo_m31_mul(r870, r880);
    unsigned r960 = stwo_m31_add(r958, r959);
    unsigned r961 = stwo_m31_mul(r867, r884);
    unsigned r962 = stwo_m31_mul(r868, r883);
    unsigned r963 = stwo_m31_add(r961, r962);
    unsigned r964 = stwo_m31_mul(r869, r882);
    unsigned r965 = stwo_m31_add(r963, r964);
    unsigned r966 = stwo_m31_mul(r870, r881);
    unsigned r967 = stwo_m31_add(r965, r966);
    unsigned r968 = stwo_m31_mul(r868, r884);
    unsigned r969 = stwo_m31_mul(r869, r883);
    unsigned r970 = stwo_m31_add(r968, r969);
    unsigned r971 = stwo_m31_mul(r870, r882);
    unsigned r972 = stwo_m31_add(r970, r971);
    unsigned r973 = stwo_m31_mul(r869, r884);
    unsigned r974 = stwo_m31_mul(r870, r883);
    unsigned r975 = stwo_m31_add(r973, r974);
    unsigned r976 = stwo_m31_mul(r870, r884);
    unsigned r977 = stwo_m31_mul(r871, r885);
    unsigned r978 = stwo_m31_mul(r871, r886);
    unsigned r979 = stwo_m31_mul(r872, r885);
    unsigned r980 = stwo_m31_add(r978, r979);
    unsigned r981 = stwo_m31_mul(r871, r887);
    unsigned r982 = stwo_m31_mul(r872, r886);
    unsigned r983 = stwo_m31_add(r981, r982);
    unsigned r984 = stwo_m31_mul(r873, r885);
    unsigned r985 = stwo_m31_add(r983, r984);
    unsigned r986 = stwo_m31_mul(r871, r888);
    unsigned r987 = stwo_m31_mul(r872, r887);
    unsigned r988 = stwo_m31_add(r986, r987);
    unsigned r989 = stwo_m31_mul(r873, r886);
    unsigned r990 = stwo_m31_add(r988, r989);
    unsigned r991 = stwo_m31_mul(r874, r885);
    unsigned r992 = stwo_m31_add(r990, r991);
    unsigned r993 = stwo_m31_mul(r871, r889);
    unsigned r994 = stwo_m31_mul(r872, r888);
    unsigned r995 = stwo_m31_add(r993, r994);
    unsigned r996 = stwo_m31_mul(r873, r887);
    unsigned r997 = stwo_m31_add(r995, r996);
    unsigned r998 = stwo_m31_mul(r874, r886);
    unsigned r999 = stwo_m31_add(r997, r998);
    unsigned r1000 = stwo_m31_mul(r875, r885);
    unsigned r1001 = stwo_m31_add(r999, r1000);
    unsigned r1002 = stwo_m31_mul(r871, r890);
    unsigned r1003 = stwo_m31_mul(r872, r889);
    unsigned r1004 = stwo_m31_add(r1002, r1003);
    unsigned r1005 = stwo_m31_mul(r873, r888);
    unsigned r1006 = stwo_m31_add(r1004, r1005);
    unsigned r1007 = stwo_m31_mul(r874, r887);
    unsigned r1008 = stwo_m31_add(r1006, r1007);
    unsigned r1009 = stwo_m31_mul(r875, r886);
    unsigned r1010 = stwo_m31_add(r1008, r1009);
    unsigned r1011 = stwo_m31_mul(r876, r885);
    unsigned r1012 = stwo_m31_add(r1010, r1011);
    unsigned r1013 = stwo_m31_mul(r871, r891);
    unsigned r1014 = stwo_m31_mul(r872, r890);
    unsigned r1015 = stwo_m31_add(r1013, r1014);
    unsigned r1016 = stwo_m31_mul(r873, r889);
    unsigned r1017 = stwo_m31_add(r1015, r1016);
    unsigned r1018 = stwo_m31_mul(r874, r888);
    unsigned r1019 = stwo_m31_add(r1017, r1018);
    unsigned r1020 = stwo_m31_mul(r875, r887);
    unsigned r1021 = stwo_m31_add(r1019, r1020);
    unsigned r1022 = stwo_m31_mul(r876, r886);
    unsigned r1023 = stwo_m31_add(r1021, r1022);
    unsigned r1024 = stwo_m31_mul(r877, r885);
    unsigned r1025 = stwo_m31_add(r1023, r1024);
    unsigned r1026 = stwo_m31_mul(r872, r891);
    unsigned r1027 = stwo_m31_mul(r873, r890);
    unsigned r1028 = stwo_m31_add(r1026, r1027);
    unsigned r1029 = stwo_m31_mul(r874, r889);
    unsigned r1030 = stwo_m31_add(r1028, r1029);
    unsigned r1031 = stwo_m31_mul(r875, r888);
    unsigned r1032 = stwo_m31_add(r1030, r1031);
    unsigned r1033 = stwo_m31_mul(r876, r887);
    unsigned r1034 = stwo_m31_add(r1032, r1033);
    unsigned r1035 = stwo_m31_mul(r877, r886);
    unsigned r1036 = stwo_m31_add(r1034, r1035);
    unsigned r1037 = stwo_m31_mul(r873, r891);
    unsigned r1038 = stwo_m31_mul(r874, r890);
    unsigned r1039 = stwo_m31_add(r1037, r1038);
    unsigned r1040 = stwo_m31_mul(r875, r889);
    unsigned r1041 = stwo_m31_add(r1039, r1040);
    unsigned r1042 = stwo_m31_mul(r876, r888);
    unsigned r1043 = stwo_m31_add(r1041, r1042);
    unsigned r1044 = stwo_m31_mul(r877, r887);
    unsigned r1045 = stwo_m31_add(r1043, r1044);
    unsigned r1046 = stwo_m31_mul(r874, r891);
    unsigned r1047 = stwo_m31_mul(r875, r890);
    unsigned r1048 = stwo_m31_add(r1046, r1047);
    unsigned r1049 = stwo_m31_mul(r876, r889);
    unsigned r1050 = stwo_m31_add(r1048, r1049);
    unsigned r1051 = stwo_m31_mul(r877, r888);
    unsigned r1052 = stwo_m31_add(r1050, r1051);
    unsigned r1053 = stwo_m31_mul(r875, r891);
    unsigned r1054 = stwo_m31_mul(r876, r890);
    unsigned r1055 = stwo_m31_add(r1053, r1054);
    unsigned r1056 = stwo_m31_mul(r877, r889);
    unsigned r1057 = stwo_m31_add(r1055, r1056);
    unsigned r1058 = stwo_m31_mul(r876, r891);
    unsigned r1059 = stwo_m31_mul(r877, r890);
    unsigned r1060 = stwo_m31_add(r1058, r1059);
    unsigned r1061 = stwo_m31_mul(r877, r891);
    unsigned r1062 = stwo_m31_add(r864, r871);
    unsigned r1063 = stwo_m31_add(r865, r872);
    unsigned r1064 = stwo_m31_add(r866, r873);
    unsigned r1065 = stwo_m31_add(r867, r874);
    unsigned r1066 = stwo_m31_add(r868, r875);
    unsigned r1067 = stwo_m31_add(r869, r876);
    unsigned r1068 = stwo_m31_add(r870, r877);
    unsigned r1069 = stwo_m31_add(r878, r885);
    unsigned r1070 = stwo_m31_add(r879, r886);
    unsigned r1071 = stwo_m31_add(r880, r887);
    unsigned r1072 = stwo_m31_add(r881, r888);
    unsigned r1073 = stwo_m31_add(r882, r889);
    unsigned r1074 = stwo_m31_add(r883, r890);
    unsigned r1075 = stwo_m31_add(r884, r891);
    unsigned r1076 = stwo_m31_mul(r1062, r1069);
    unsigned r1077 = stwo_m31_sub(r1076, r892);
    unsigned r1078 = stwo_m31_sub(r1077, r977);
    unsigned r1079 = stwo_m31_add(r951, r1078);
    unsigned r1080 = stwo_m31_mul(r1062, r1070);
    unsigned r1081 = stwo_m31_mul(r1063, r1069);
    unsigned r1082 = stwo_m31_add(r1080, r1081);
    unsigned r1083 = stwo_m31_sub(r1082, r895);
    unsigned r1084 = stwo_m31_sub(r1083, r980);
    unsigned r1085 = stwo_m31_add(r960, r1084);
    unsigned r1086 = stwo_m31_mul(r1062, r1071);
    unsigned r1087 = stwo_m31_mul(r1063, r1070);
    unsigned r1088 = stwo_m31_add(r1086, r1087);
    unsigned r1089 = stwo_m31_mul(r1064, r1069);
    unsigned r1090 = stwo_m31_add(r1088, r1089);
    unsigned r1091 = stwo_m31_sub(r1090, r900);
    unsigned r1092 = stwo_m31_sub(r1091, r985);
    unsigned r1093 = stwo_m31_add(r967, r1092);
    unsigned r1094 = stwo_m31_mul(r1062, r1072);
    unsigned r1095 = stwo_m31_mul(r1063, r1071);
    unsigned r1096 = stwo_m31_add(r1094, r1095);
    unsigned r1097 = stwo_m31_mul(r1064, r1070);
    unsigned r1098 = stwo_m31_add(r1096, r1097);
    unsigned r1099 = stwo_m31_mul(r1065, r1069);
    unsigned r1100 = stwo_m31_add(r1098, r1099);
    unsigned r1101 = stwo_m31_sub(r1100, r907);
    unsigned r1102 = stwo_m31_sub(r1101, r992);
    unsigned r1103 = stwo_m31_add(r972, r1102);
    unsigned r1104 = stwo_m31_mul(r1062, r1073);
    unsigned r1105 = stwo_m31_mul(r1063, r1072);
    unsigned r1106 = stwo_m31_add(r1104, r1105);
    unsigned r1107 = stwo_m31_mul(r1064, r1071);
    unsigned r1108 = stwo_m31_add(r1106, r1107);
    unsigned r1109 = stwo_m31_mul(r1065, r1070);
    unsigned r1110 = stwo_m31_add(r1108, r1109);
    unsigned r1111 = stwo_m31_mul(r1066, r1069);
    unsigned r1112 = stwo_m31_add(r1110, r1111);
    unsigned r1113 = stwo_m31_sub(r1112, r916);
    unsigned r1114 = stwo_m31_sub(r1113, r1001);
    unsigned r1115 = stwo_m31_add(r975, r1114);
    unsigned r1116 = stwo_m31_mul(r1062, r1074);
    unsigned r1117 = stwo_m31_mul(r1063, r1073);
    unsigned r1118 = stwo_m31_add(r1116, r1117);
    unsigned r1119 = stwo_m31_mul(r1064, r1072);
    unsigned r1120 = stwo_m31_add(r1118, r1119);
    unsigned r1121 = stwo_m31_mul(r1065, r1071);
    unsigned r1122 = stwo_m31_add(r1120, r1121);
    unsigned r1123 = stwo_m31_mul(r1066, r1070);
    unsigned r1124 = stwo_m31_add(r1122, r1123);
    unsigned r1125 = stwo_m31_mul(r1067, r1069);
    unsigned r1126 = stwo_m31_add(r1124, r1125);
    unsigned r1127 = stwo_m31_sub(r1126, r927);
    unsigned r1128 = stwo_m31_sub(r1127, r1012);
    unsigned r1129 = stwo_m31_add(r976, r1128);
    unsigned r1130 = stwo_m31_mul(r1062, r1075);
    unsigned r1131 = stwo_m31_mul(r1063, r1074);
    unsigned r1132 = stwo_m31_add(r1130, r1131);
    unsigned r1133 = stwo_m31_mul(r1064, r1073);
    unsigned r1134 = stwo_m31_add(r1132, r1133);
    unsigned r1135 = stwo_m31_mul(r1065, r1072);
    unsigned r1136 = stwo_m31_add(r1134, r1135);
    unsigned r1137 = stwo_m31_mul(r1066, r1071);
    unsigned r1138 = stwo_m31_add(r1136, r1137);
    unsigned r1139 = stwo_m31_mul(r1067, r1070);
    unsigned r1140 = stwo_m31_add(r1138, r1139);
    unsigned r1141 = stwo_m31_mul(r1068, r1069);
    unsigned r1142 = stwo_m31_add(r1140, r1141);
    unsigned r1143 = stwo_m31_sub(r1142, r940);
    unsigned r1144 = stwo_m31_sub(r1143, r1025);
    unsigned r1145 = stwo_m31_mul(r1063, r1075);
    unsigned r1146 = stwo_m31_mul(r1064, r1074);
    unsigned r1147 = stwo_m31_add(r1145, r1146);
    unsigned r1148 = stwo_m31_mul(r1065, r1073);
    unsigned r1149 = stwo_m31_add(r1147, r1148);
    unsigned r1150 = stwo_m31_mul(r1066, r1072);
    unsigned r1151 = stwo_m31_add(r1149, r1150);
    unsigned r1152 = stwo_m31_mul(r1067, r1071);
    unsigned r1153 = stwo_m31_add(r1151, r1152);
    unsigned r1154 = stwo_m31_mul(r1068, r1070);
    unsigned r1155 = stwo_m31_add(r1153, r1154);
    unsigned r1156 = stwo_m31_sub(r1155, r951);
    unsigned r1157 = stwo_m31_sub(r1156, r1036);
    unsigned r1158 = stwo_m31_add(r977, r1157);
    unsigned r1159 = stwo_m31_mul(r1064, r1075);
    unsigned r1160 = stwo_m31_mul(r1065, r1074);
    unsigned r1161 = stwo_m31_add(r1159, r1160);
    unsigned r1162 = stwo_m31_mul(r1066, r1073);
    unsigned r1163 = stwo_m31_add(r1161, r1162);
    unsigned r1164 = stwo_m31_mul(r1067, r1072);
    unsigned r1165 = stwo_m31_add(r1163, r1164);
    unsigned r1166 = stwo_m31_mul(r1068, r1071);
    unsigned r1167 = stwo_m31_add(r1165, r1166);
    unsigned r1168 = stwo_m31_sub(r1167, r960);
    unsigned r1169 = stwo_m31_sub(r1168, r1045);
    unsigned r1170 = stwo_m31_add(r980, r1169);
    unsigned r1171 = stwo_m31_mul(r1065, r1075);
    unsigned r1172 = stwo_m31_mul(r1066, r1074);
    unsigned r1173 = stwo_m31_add(r1171, r1172);
    unsigned r1174 = stwo_m31_mul(r1067, r1073);
    unsigned r1175 = stwo_m31_add(r1173, r1174);
    unsigned r1176 = stwo_m31_mul(r1068, r1072);
    unsigned r1177 = stwo_m31_add(r1175, r1176);
    unsigned r1178 = stwo_m31_sub(r1177, r967);
    unsigned r1179 = stwo_m31_sub(r1178, r1052);
    unsigned r1180 = stwo_m31_add(r985, r1179);
    unsigned r1181 = stwo_m31_mul(r1066, r1075);
    unsigned r1182 = stwo_m31_mul(r1067, r1074);
    unsigned r1183 = stwo_m31_add(r1181, r1182);
    unsigned r1184 = stwo_m31_mul(r1068, r1073);
    unsigned r1185 = stwo_m31_add(r1183, r1184);
    unsigned r1186 = stwo_m31_sub(r1185, r972);
    unsigned r1187 = stwo_m31_sub(r1186, r1057);
    unsigned r1188 = stwo_m31_add(r992, r1187);
    unsigned r1189 = stwo_m31_mul(r1067, r1075);
    unsigned r1190 = stwo_m31_mul(r1068, r1074);
    unsigned r1191 = stwo_m31_add(r1189, r1190);
    unsigned r1192 = stwo_m31_sub(r1191, r975);
    unsigned r1193 = stwo_m31_sub(r1192, r1060);
    unsigned r1194 = stwo_m31_add(r1001, r1193);
    unsigned r1195 = stwo_m31_mul(r1068, r1075);
    unsigned r1196 = stwo_m31_sub(r1195, r976);
    unsigned r1197 = stwo_m31_sub(r1196, r1061);
    unsigned r1198 = stwo_m31_add(r1012, r1197);
    unsigned r1199 = stwo_m31_sub(r892, r250);
    unsigned r1200 = stwo_m31_sub(r1199, r557);
    unsigned r1201 = stwo_m31_add(r516, r1200);
    unsigned r1202 = stwo_m31_sub(r895, r253);
    unsigned r1203 = stwo_m31_sub(r1202, r560);
    unsigned r1204 = stwo_m31_add(r528, r1203);
    unsigned r1205 = stwo_m31_sub(r900, r258);
    unsigned r1206 = stwo_m31_sub(r1205, r565);
    unsigned r1207 = stwo_m31_add(r538, r1206);
    unsigned r1208 = stwo_m31_sub(r907, r265);
    unsigned r1209 = stwo_m31_sub(r1208, r572);
    unsigned r1210 = stwo_m31_add(r546, r1209);
    unsigned r1211 = stwo_m31_sub(r916, r274);
    unsigned r1212 = stwo_m31_sub(r1211, r581);
    unsigned r1213 = stwo_m31_add(r552, r1212);
    unsigned r1214 = stwo_m31_sub(r927, r285);
    unsigned r1215 = stwo_m31_sub(r1214, r592);
    unsigned r1216 = stwo_m31_add(r556, r1215);
    unsigned r1217 = stwo_m31_sub(r940, r298);
    unsigned r1218 = stwo_m31_sub(r1217, r605);
    unsigned r1219 = stwo_m31_add(r383, r1218);
    unsigned r1220 = stwo_m31_sub(r1079, r437);
    unsigned r1221 = stwo_m31_sub(r1220, r744);
    unsigned r1222 = stwo_m31_add(r394, r1221);
    unsigned r1223 = stwo_m31_sub(r1085, r443);
    unsigned r1224 = stwo_m31_sub(r1223, r750);
    unsigned r1225 = stwo_m31_add(r403, r1224);
    unsigned r1226 = stwo_m31_sub(r1093, r451);
    unsigned r1227 = stwo_m31_sub(r1226, r758);
    unsigned r1228 = stwo_m31_add(r410, r1227);
    unsigned r1229 = stwo_m31_sub(r1103, r461);
    unsigned r1230 = stwo_m31_sub(r1229, r768);
    unsigned r1231 = stwo_m31_add(r415, r1230);
    unsigned r1232 = stwo_m31_sub(r1115, r473);
    unsigned r1233 = stwo_m31_sub(r1232, r780);
    unsigned r1234 = stwo_m31_add(r418, r1233);
    unsigned r1235 = stwo_m31_sub(r1129, r487);
    unsigned r1236 = stwo_m31_sub(r1235, r794);
    unsigned r1237 = stwo_m31_add(r419, r1236);
    unsigned r1238 = stwo_m31_sub(r1144, r502);
    unsigned r1239 = stwo_m31_sub(r1238, r809);
    unsigned r1240 = stwo_m31_sub(r1158, r516);
    unsigned r1241 = stwo_m31_sub(r1240, r823);
    unsigned r1242 = stwo_m31_add(r557, r1241);
    unsigned r1243 = stwo_m31_sub(r1170, r528);
    unsigned r1244 = stwo_m31_sub(r1243, r835);
    unsigned r1245 = stwo_m31_add(r560, r1244);
    unsigned r1246 = stwo_m31_sub(r1180, r538);
    unsigned r1247 = stwo_m31_sub(r1246, r845);
    unsigned r1248 = stwo_m31_add(r565, r1247);
    unsigned r1249 = stwo_m31_sub(r1188, r546);
    unsigned r1250 = stwo_m31_sub(r1249, r853);
    unsigned r1251 = stwo_m31_add(r572, r1250);
    unsigned r1252 = stwo_m31_sub(r1194, r552);
    unsigned r1253 = stwo_m31_sub(r1252, r859);
    unsigned r1254 = stwo_m31_add(r581, r1253);
    unsigned r1255 = stwo_m31_sub(r1198, r556);
    unsigned r1256 = stwo_m31_sub(r1255, r863);
    unsigned r1257 = stwo_m31_add(r592, r1256);
    unsigned r1258 = stwo_m31_sub(r1025, r383);
    unsigned r1259 = stwo_m31_sub(r1258, r690);
    unsigned r1260 = stwo_m31_add(r605, r1259);
    unsigned r1261 = stwo_m31_sub(r1036, r394);
    unsigned r1262 = stwo_m31_sub(r1261, r701);
    unsigned r1263 = stwo_m31_add(r744, r1262);
    unsigned r1264 = stwo_m31_sub(r1045, r403);
    unsigned r1265 = stwo_m31_sub(r1264, r710);
    unsigned r1266 = stwo_m31_add(r750, r1265);
    unsigned r1267 = stwo_m31_sub(r1052, r410);
    unsigned r1268 = stwo_m31_sub(r1267, r717);
    unsigned r1269 = stwo_m31_add(r758, r1268);
    unsigned r1270 = stwo_m31_sub(r1057, r415);
    unsigned r1271 = stwo_m31_sub(r1270, r722);
    unsigned r1272 = stwo_m31_add(r768, r1271);
    unsigned r1273 = stwo_m31_sub(r1060, r418);
    unsigned r1274 = stwo_m31_sub(r1273, r725);
    unsigned r1275 = stwo_m31_add(r780, r1274);
    unsigned r1276 = stwo_m31_sub(r1061, r419);
    unsigned r1277 = stwo_m31_sub(r1276, r726);
    unsigned r1278 = stwo_m31_add(r794, r1277);
    unsigned r1279 = stwo_m31_sub(r250, r222);
    unsigned r1280 = stwo_m31_sub(r253, r223);
    unsigned r1281 = stwo_m31_sub(r258, r224);
    unsigned r1282 = stwo_m31_sub(r265, r225);
    unsigned r1283 = stwo_m31_sub(r274, r226);
    unsigned r1284 = stwo_m31_sub(r285, r227);
    unsigned r1285 = stwo_m31_sub(r298, r228);
    unsigned r1286 = stwo_m31_sub(r437, r229);
    unsigned r1287 = stwo_m31_sub(r443, r230);
    unsigned r1288 = stwo_m31_sub(r451, r231);
    unsigned r1289 = stwo_m31_sub(r461, r232);
    unsigned r1290 = stwo_m31_sub(r473, r233);
    unsigned r1291 = stwo_m31_sub(r487, r234);
    unsigned r1292 = stwo_m31_sub(r502, r235);
    unsigned r1293 = stwo_m31_sub(r1201, r236);
    unsigned r1294 = stwo_m31_sub(r1204, r237);
    unsigned r1295 = stwo_m31_sub(r1207, r238);
    unsigned r1296 = stwo_m31_sub(r1210, r239);
    unsigned r1297 = stwo_m31_sub(r1213, r240);
    unsigned r1298 = stwo_m31_sub(r1216, r241);
    unsigned r1299 = stwo_m31_sub(r1219, r242);
    unsigned r1300 = stwo_m31_sub(r1222, r243);
    unsigned r1301 = stwo_m31_sub(r1225, r244);
    unsigned r1302 = stwo_m31_sub(r1228, r245);
    unsigned r1303 = stwo_m31_sub(r1231, r246);
    unsigned r1304 = stwo_m31_sub(r1234, r247);
    unsigned r1305 = stwo_m31_sub(r1237, r248);
    unsigned r1306 = stwo_m31_sub(r1239, r249);
    unsigned r1307 = stwo_m31_mul(r3, r1279);
    unsigned r1308 = stwo_m31_mul(r1, r1300);
    unsigned r1309 = stwo_m31_sub(r1307, r1308);
    unsigned r1310 = stwo_m31_mul(r2, r701);
    unsigned r1311 = stwo_m31_add(r1309, r1310);
    unsigned r1312 = stwo_m31_mul(r3, r1280);
    unsigned r1313 = stwo_m31_add(r1279, r1312);
    unsigned r1314 = stwo_m31_mul(r1, r1301);
    unsigned r1315 = stwo_m31_sub(r1313, r1314);
    unsigned r1316 = stwo_m31_mul(r2, r710);
    unsigned r1317 = stwo_m31_add(r1315, r1316);
    unsigned r1318 = stwo_m31_mul(r3, r1281);
    unsigned r1319 = stwo_m31_add(r1280, r1318);
    unsigned r1320 = stwo_m31_mul(r1, r1302);
    unsigned r1321 = stwo_m31_sub(r1319, r1320);
    unsigned r1322 = stwo_m31_mul(r2, r717);
    unsigned r1323 = stwo_m31_add(r1321, r1322);
    unsigned r1324 = stwo_m31_mul(r3, r1282);
    unsigned r1325 = stwo_m31_add(r1281, r1324);
    unsigned r1326 = stwo_m31_mul(r1, r1303);
    unsigned r1327 = stwo_m31_sub(r1325, r1326);
    unsigned r1328 = stwo_m31_mul(r2, r722);
    unsigned r1329 = stwo_m31_add(r1327, r1328);
    unsigned r1330 = stwo_m31_mul(r3, r1283);
    unsigned r1331 = stwo_m31_add(r1282, r1330);
    unsigned r1332 = stwo_m31_mul(r1, r1304);
    unsigned r1333 = stwo_m31_sub(r1331, r1332);
    unsigned r1334 = stwo_m31_mul(r2, r725);
    unsigned r1335 = stwo_m31_add(r1333, r1334);
    unsigned r1336 = stwo_m31_mul(r3, r1284);
    unsigned r1337 = stwo_m31_add(r1283, r1336);
    unsigned r1338 = stwo_m31_mul(r1, r1305);
    unsigned r1339 = stwo_m31_sub(r1337, r1338);
    unsigned r1340 = stwo_m31_mul(r2, r726);
    unsigned r1341 = stwo_m31_add(r1339, r1340);
    unsigned r1342 = stwo_m31_mul(r3, r1285);
    unsigned r1343 = stwo_m31_add(r1284, r1342);
    unsigned r1344 = stwo_m31_mul(r1, r1306);
    unsigned r1345 = stwo_m31_sub(r1343, r1344);
    unsigned r1346 = stwo_m31_mul(r0, r1279);
    unsigned r1347 = stwo_m31_add(r1346, r1285);
    unsigned r1348 = stwo_m31_mul(r3, r1286);
    unsigned r1349 = stwo_m31_add(r1347, r1348);
    unsigned r1350 = stwo_m31_mul(r1, r1242);
    unsigned r1351 = stwo_m31_sub(r1349, r1350);
    unsigned r1352 = stwo_m31_mul(r0, r1280);
    unsigned r1353 = stwo_m31_add(r1352, r1286);
    unsigned r1354 = stwo_m31_mul(r3, r1287);
    unsigned r1355 = stwo_m31_add(r1353, r1354);
    unsigned r1356 = stwo_m31_mul(r1, r1245);
    unsigned r1357 = stwo_m31_sub(r1355, r1356);
    unsigned r1358 = stwo_m31_mul(r0, r1281);
    unsigned r1359 = stwo_m31_add(r1358, r1287);
    unsigned r1360 = stwo_m31_mul(r3, r1288);
    unsigned r1361 = stwo_m31_add(r1359, r1360);
    unsigned r1362 = stwo_m31_mul(r1, r1248);
    unsigned r1363 = stwo_m31_sub(r1361, r1362);
    unsigned r1364 = stwo_m31_mul(r0, r1282);
    unsigned r1365 = stwo_m31_add(r1364, r1288);
    unsigned r1366 = stwo_m31_mul(r3, r1289);
    unsigned r1367 = stwo_m31_add(r1365, r1366);
    unsigned r1368 = stwo_m31_mul(r1, r1251);
    unsigned r1369 = stwo_m31_sub(r1367, r1368);
    unsigned r1370 = stwo_m31_mul(r0, r1283);
    unsigned r1371 = stwo_m31_add(r1370, r1289);
    unsigned r1372 = stwo_m31_mul(r3, r1290);
    unsigned r1373 = stwo_m31_add(r1371, r1372);
    unsigned r1374 = stwo_m31_mul(r1, r1254);
    unsigned r1375 = stwo_m31_sub(r1373, r1374);
    unsigned r1376 = stwo_m31_mul(r0, r1284);
    unsigned r1377 = stwo_m31_add(r1376, r1290);
    unsigned r1378 = stwo_m31_mul(r3, r1291);
    unsigned r1379 = stwo_m31_add(r1377, r1378);
    unsigned r1380 = stwo_m31_mul(r1, r1257);
    unsigned r1381 = stwo_m31_sub(r1379, r1380);
    unsigned r1382 = stwo_m31_mul(r0, r1285);
    unsigned r1383 = stwo_m31_add(r1382, r1291);
    unsigned r1384 = stwo_m31_mul(r3, r1292);
    unsigned r1385 = stwo_m31_add(r1383, r1384);
    unsigned r1386 = stwo_m31_mul(r1, r1260);
    unsigned r1387 = stwo_m31_sub(r1385, r1386);
    unsigned r1388 = stwo_m31_mul(r0, r1286);
    unsigned r1389 = stwo_m31_add(r1388, r1292);
    unsigned r1390 = stwo_m31_mul(r3, r1293);
    unsigned r1391 = stwo_m31_add(r1389, r1390);
    unsigned r1392 = stwo_m31_mul(r1, r1263);
    unsigned r1393 = stwo_m31_sub(r1391, r1392);
    unsigned r1394 = stwo_m31_mul(r0, r1287);
    unsigned r1395 = stwo_m31_add(r1394, r1293);
    unsigned r1396 = stwo_m31_mul(r3, r1294);
    unsigned r1397 = stwo_m31_add(r1395, r1396);
    unsigned r1398 = stwo_m31_mul(r1, r1266);
    unsigned r1399 = stwo_m31_sub(r1397, r1398);
    unsigned r1400 = stwo_m31_mul(r0, r1288);
    unsigned r1401 = stwo_m31_add(r1400, r1294);
    unsigned r1402 = stwo_m31_mul(r3, r1295);
    unsigned r1403 = stwo_m31_add(r1401, r1402);
    unsigned r1404 = stwo_m31_mul(r1, r1269);
    unsigned r1405 = stwo_m31_sub(r1403, r1404);
    unsigned r1406 = stwo_m31_mul(r0, r1289);
    unsigned r1407 = stwo_m31_add(r1406, r1295);
    unsigned r1408 = stwo_m31_mul(r3, r1296);
    unsigned r1409 = stwo_m31_add(r1407, r1408);
    unsigned r1410 = stwo_m31_mul(r1, r1272);
    unsigned r1411 = stwo_m31_sub(r1409, r1410);
    unsigned r1412 = stwo_m31_mul(r0, r1290);
    unsigned r1413 = stwo_m31_add(r1412, r1296);
    unsigned r1414 = stwo_m31_mul(r3, r1297);
    unsigned r1415 = stwo_m31_add(r1413, r1414);
    unsigned r1416 = stwo_m31_mul(r1, r1275);
    unsigned r1417 = stwo_m31_sub(r1415, r1416);
    unsigned r1418 = stwo_m31_mul(r0, r1291);
    unsigned r1419 = stwo_m31_add(r1418, r1297);
    unsigned r1420 = stwo_m31_mul(r3, r1298);
    unsigned r1421 = stwo_m31_add(r1419, r1420);
    unsigned r1422 = stwo_m31_mul(r1, r1278);
    unsigned r1423 = stwo_m31_sub(r1421, r1422);
    unsigned r1424 = stwo_m31_mul(r0, r1292);
    unsigned r1425 = stwo_m31_add(r1424, r1298);
    unsigned r1426 = stwo_m31_mul(r3, r1299);
    unsigned r1427 = stwo_m31_add(r1425, r1426);
    unsigned r1428 = stwo_m31_mul(r1, r809);
    unsigned r1429 = stwo_m31_sub(r1427, r1428);
    unsigned r1430 = stwo_m31_mul(r0, r1293);
    unsigned r1431 = stwo_m31_add(r1430, r1299);
    unsigned r1432 = stwo_m31_mul(r1, r823);
    unsigned r1433 = stwo_m31_sub(r1431, r1432);
    unsigned r1434 = stwo_m31_mul(r4, r701);
    unsigned r1435 = stwo_m31_add(r1433, r1434);
    unsigned r1436 = stwo_m31_mul(r0, r1294);
    unsigned r1437 = stwo_m31_mul(r1, r835);
    unsigned r1438 = stwo_m31_sub(r1436, r1437);
    unsigned r1439 = stwo_m31_mul(r0, r701);
    unsigned r1440 = stwo_m31_add(r1438, r1439);
    unsigned r1441 = stwo_m31_mul(r4, r710);
    unsigned r1442 = stwo_m31_add(r1440, r1441);
    unsigned r1443 = stwo_m31_mul(r0, r1295);
    unsigned r1444 = stwo_m31_mul(r1, r845);
    unsigned r1445 = stwo_m31_sub(r1443, r1444);
    unsigned r1446 = stwo_m31_mul(r0, r710);
    unsigned r1447 = stwo_m31_add(r1445, r1446);
    unsigned r1448 = stwo_m31_mul(r4, r717);
    unsigned r1449 = stwo_m31_add(r1447, r1448);
    unsigned r1450 = stwo_m31_mul(r0, r1296);
    unsigned r1451 = stwo_m31_mul(r1, r853);
    unsigned r1452 = stwo_m31_sub(r1450, r1451);
    unsigned r1453 = stwo_m31_mul(r0, r717);
    unsigned r1454 = stwo_m31_add(r1452, r1453);
    unsigned r1455 = stwo_m31_mul(r4, r722);
    unsigned r1456 = stwo_m31_add(r1454, r1455);
    unsigned r1457 = stwo_m31_mul(r0, r1297);
    unsigned r1458 = stwo_m31_mul(r1, r859);
    unsigned r1459 = stwo_m31_sub(r1457, r1458);
    unsigned r1460 = stwo_m31_mul(r0, r722);
    unsigned r1461 = stwo_m31_add(r1459, r1460);
    unsigned r1462 = stwo_m31_mul(r4, r725);
    unsigned r1463 = stwo_m31_add(r1461, r1462);
    unsigned r1464 = stwo_m31_mul(r0, r1298);
    unsigned r1465 = stwo_m31_mul(r1, r863);
    unsigned r1466 = stwo_m31_sub(r1464, r1465);
    unsigned r1467 = stwo_m31_mul(r0, r725);
    unsigned r1468 = stwo_m31_add(r1466, r1467);
    unsigned r1469 = stwo_m31_mul(r4, r726);
    unsigned r1470 = stwo_m31_add(r1468, r1469);
    unsigned r1471 = stwo_m31_mul(r0, r1299);
    unsigned r1472 = stwo_m31_mul(r1, r690);
    unsigned r1473 = stwo_m31_sub(r1471, r1472);
    unsigned r1474 = stwo_m31_mul(r0, r726);
    unsigned r1475 = stwo_m31_add(r1473, r1474);
    unsigned r1476 = stwo_m31_add(r1311, r12);
    unsigned r1477 = stwo_m31_add(r1317, r12);
    unsigned r1478 = (r1477 & 511u);
    unsigned r1479 = (r1478 << 9u);
    unsigned r1480 = (r1476 + r1479);
    unsigned r1481 = 131072u;
    unsigned r1482 = (r1480 + r1481);
    unsigned r1483 = (r1482 & 262143u);
    unsigned r1484 = (r1483 & 65535u);
    unsigned r1485 = (r1484 % STWO_M31_P);
    unsigned r1486 = (r1483 >> 16u);
    unsigned r1487 = (r1486 % STWO_M31_P);
    unsigned r1488 = stwo_m31_sub(r1487, r0);
    unsigned r1489 = stwo_m31_mul(r1488, r8);
    unsigned r1490 = stwo_m31_add(r1485, r1489);
    unsigned r1491 = stwo_m31_add(r1490, r10);
    sub_words[84u * row_count + row] = r1491;
    unsigned r1492 = stwo_m31_add(r1490, r10);
    lookup_words[22u * row_count + row] = r1492;
    unsigned r1493 = stwo_m31_sub(r1311, r1490);
    unsigned r1494 = stwo_m31_mul(r1493, r11);
    unsigned r1495 = stwo_m31_add(r1494, r10);
    sub_words[92u * row_count + row] = r1495;
    unsigned r1496 = stwo_m31_add(r1494, r10);
    lookup_words[38u * row_count + row] = r1496;
    unsigned r1497 = stwo_m31_add(r1317, r1494);
    out_cols[57u][row] = r1494;
    unsigned r1498 = stwo_m31_mul(r1497, r11);
    unsigned r1499 = stwo_m31_add(r1498, r10);
    sub_words[100u * row_count + row] = r1499;
    unsigned r1500 = stwo_m31_add(r1498, r10);
    lookup_words[54u * row_count + row] = r1500;
    unsigned r1501 = stwo_m31_add(r1323, r1498);
    out_cols[58u][row] = r1498;
    unsigned r1502 = stwo_m31_mul(r1501, r11);
    unsigned r1503 = stwo_m31_add(r1502, r10);
    sub_words[108u * row_count + row] = r1503;
    unsigned r1504 = stwo_m31_add(r1502, r10);
    lookup_words[70u * row_count + row] = r1504;
    unsigned r1505 = stwo_m31_add(r1329, r1502);
    out_cols[59u][row] = r1502;
    unsigned r1506 = stwo_m31_mul(r1505, r11);
    unsigned r1507 = stwo_m31_add(r1506, r10);
    sub_words[116u * row_count + row] = r1507;
    unsigned r1508 = stwo_m31_add(r1506, r10);
    lookup_words[86u * row_count + row] = r1508;
    unsigned r1509 = stwo_m31_add(r1335, r1506);
    out_cols[60u][row] = r1506;
    unsigned r1510 = stwo_m31_mul(r1509, r11);
    unsigned r1511 = stwo_m31_add(r1510, r10);
    sub_words[122u * row_count + row] = r1511;
    unsigned r1512 = stwo_m31_add(r1510, r10);
    lookup_words[98u * row_count + row] = r1512;
    unsigned r1513 = stwo_m31_add(r1341, r1510);
    out_cols[61u][row] = r1510;
    unsigned r1514 = stwo_m31_mul(r1513, r11);
    unsigned r1515 = stwo_m31_add(r1514, r10);
    sub_words[128u * row_count + row] = r1515;
    unsigned r1516 = stwo_m31_add(r1514, r10);
    lookup_words[110u * row_count + row] = r1516;
    unsigned r1517 = stwo_m31_add(r1345, r1514);
    out_cols[62u][row] = r1514;
    unsigned r1518 = stwo_m31_mul(r1517, r11);
    unsigned r1519 = stwo_m31_add(r1518, r10);
    sub_words[134u * row_count + row] = r1519;
    unsigned r1520 = stwo_m31_add(r1518, r10);
    lookup_words[122u * row_count + row] = r1520;
    unsigned r1521 = stwo_m31_add(r1351, r1518);
    out_cols[63u][row] = r1518;
    unsigned r1522 = stwo_m31_mul(r1521, r11);
    unsigned r1523 = stwo_m31_add(r1522, r10);
    sub_words[85u * row_count + row] = r1523;
    unsigned r1524 = stwo_m31_add(r1522, r10);
    lookup_words[24u * row_count + row] = r1524;
    unsigned r1525 = stwo_m31_add(r1357, r1522);
    out_cols[64u][row] = r1522;
    unsigned r1526 = stwo_m31_mul(r1525, r11);
    unsigned r1527 = stwo_m31_add(r1526, r10);
    sub_words[93u * row_count + row] = r1527;
    unsigned r1528 = stwo_m31_add(r1526, r10);
    lookup_words[40u * row_count + row] = r1528;
    unsigned r1529 = stwo_m31_add(r1363, r1526);
    out_cols[65u][row] = r1526;
    unsigned r1530 = stwo_m31_mul(r1529, r11);
    unsigned r1531 = stwo_m31_add(r1530, r10);
    sub_words[101u * row_count + row] = r1531;
    unsigned r1532 = stwo_m31_add(r1530, r10);
    lookup_words[56u * row_count + row] = r1532;
    unsigned r1533 = stwo_m31_add(r1369, r1530);
    out_cols[66u][row] = r1530;
    unsigned r1534 = stwo_m31_mul(r1533, r11);
    unsigned r1535 = stwo_m31_add(r1534, r10);
    sub_words[109u * row_count + row] = r1535;
    unsigned r1536 = stwo_m31_add(r1534, r10);
    lookup_words[72u * row_count + row] = r1536;
    unsigned r1537 = stwo_m31_add(r1375, r1534);
    out_cols[67u][row] = r1534;
    unsigned r1538 = stwo_m31_mul(r1537, r11);
    unsigned r1539 = stwo_m31_add(r1538, r10);
    sub_words[117u * row_count + row] = r1539;
    unsigned r1540 = stwo_m31_add(r1538, r10);
    lookup_words[88u * row_count + row] = r1540;
    unsigned r1541 = stwo_m31_add(r1381, r1538);
    out_cols[68u][row] = r1538;
    unsigned r1542 = stwo_m31_mul(r1541, r11);
    unsigned r1543 = stwo_m31_add(r1542, r10);
    sub_words[123u * row_count + row] = r1543;
    unsigned r1544 = stwo_m31_add(r1542, r10);
    lookup_words[100u * row_count + row] = r1544;
    unsigned r1545 = stwo_m31_add(r1387, r1542);
    out_cols[69u][row] = r1542;
    unsigned r1546 = stwo_m31_mul(r1545, r11);
    unsigned r1547 = stwo_m31_add(r1546, r10);
    sub_words[129u * row_count + row] = r1547;
    unsigned r1548 = stwo_m31_add(r1546, r10);
    lookup_words[112u * row_count + row] = r1548;
    unsigned r1549 = stwo_m31_add(r1393, r1546);
    out_cols[70u][row] = r1546;
    unsigned r1550 = stwo_m31_mul(r1549, r11);
    unsigned r1551 = stwo_m31_add(r1550, r10);
    sub_words[135u * row_count + row] = r1551;
    unsigned r1552 = stwo_m31_add(r1550, r10);
    lookup_words[124u * row_count + row] = r1552;
    unsigned r1553 = stwo_m31_add(r1399, r1550);
    out_cols[71u][row] = r1550;
    unsigned r1554 = stwo_m31_mul(r1553, r11);
    unsigned r1555 = stwo_m31_add(r1554, r10);
    sub_words[86u * row_count + row] = r1555;
    unsigned r1556 = stwo_m31_add(r1554, r10);
    lookup_words[26u * row_count + row] = r1556;
    unsigned r1557 = stwo_m31_add(r1405, r1554);
    out_cols[72u][row] = r1554;
    unsigned r1558 = stwo_m31_mul(r1557, r11);
    unsigned r1559 = stwo_m31_add(r1558, r10);
    sub_words[94u * row_count + row] = r1559;
    unsigned r1560 = stwo_m31_add(r1558, r10);
    lookup_words[42u * row_count + row] = r1560;
    unsigned r1561 = stwo_m31_add(r1411, r1558);
    out_cols[73u][row] = r1558;
    unsigned r1562 = stwo_m31_mul(r1561, r11);
    unsigned r1563 = stwo_m31_add(r1562, r10);
    sub_words[102u * row_count + row] = r1563;
    unsigned r1564 = stwo_m31_add(r1562, r10);
    lookup_words[58u * row_count + row] = r1564;
    unsigned r1565 = stwo_m31_add(r1417, r1562);
    out_cols[74u][row] = r1562;
    unsigned r1566 = stwo_m31_mul(r1565, r11);
    unsigned r1567 = stwo_m31_add(r1566, r10);
    sub_words[110u * row_count + row] = r1567;
    unsigned r1568 = stwo_m31_add(r1566, r10);
    lookup_words[74u * row_count + row] = r1568;
    unsigned r1569 = stwo_m31_add(r1423, r1566);
    out_cols[75u][row] = r1566;
    unsigned r1570 = stwo_m31_mul(r1569, r11);
    unsigned r1571 = stwo_m31_add(r1570, r10);
    sub_words[118u * row_count + row] = r1571;
    unsigned r1572 = stwo_m31_add(r1570, r10);
    lookup_words[90u * row_count + row] = r1572;
    unsigned r1573 = stwo_m31_add(r1429, r1570);
    out_cols[76u][row] = r1570;
    unsigned r1574 = stwo_m31_mul(r1573, r11);
    unsigned r1575 = stwo_m31_add(r1574, r10);
    sub_words[124u * row_count + row] = r1575;
    unsigned r1576 = stwo_m31_add(r1574, r10);
    lookup_words[102u * row_count + row] = r1576;
    unsigned r1577 = stwo_m31_mul(r5, r1490);
    out_cols[56u][row] = r1490;
    unsigned r1578 = stwo_m31_sub(r1435, r1577);
    unsigned r1579 = stwo_m31_add(r1578, r1574);
    out_cols[77u][row] = r1574;
    unsigned r1580 = stwo_m31_mul(r1579, r11);
    unsigned r1581 = stwo_m31_add(r1580, r10);
    sub_words[130u * row_count + row] = r1581;
    unsigned r1582 = stwo_m31_add(r1580, r10);
    lookup_words[114u * row_count + row] = r1582;
    unsigned r1583 = stwo_m31_add(r1442, r1580);
    out_cols[78u][row] = r1580;
    unsigned r1584 = stwo_m31_mul(r1583, r11);
    unsigned r1585 = stwo_m31_add(r1584, r10);
    sub_words[136u * row_count + row] = r1585;
    unsigned r1586 = stwo_m31_add(r1584, r10);
    lookup_words[126u * row_count + row] = r1586;
    unsigned r1587 = stwo_m31_add(r1449, r1584);
    out_cols[79u][row] = r1584;
    unsigned r1588 = stwo_m31_mul(r1587, r11);
    unsigned r1589 = stwo_m31_add(r1588, r10);
    sub_words[87u * row_count + row] = r1589;
    unsigned r1590 = stwo_m31_add(r1588, r10);
    lookup_words[28u * row_count + row] = r1590;
    unsigned r1591 = stwo_m31_add(r1456, r1588);
    out_cols[80u][row] = r1588;
    unsigned r1592 = stwo_m31_mul(r1591, r11);
    unsigned r1593 = stwo_m31_add(r1592, r10);
    sub_words[95u * row_count + row] = r1593;
    unsigned r1594 = stwo_m31_add(r1592, r10);
    lookup_words[44u * row_count + row] = r1594;
    unsigned r1595 = stwo_m31_add(r1463, r1592);
    out_cols[81u][row] = r1592;
    unsigned r1596 = stwo_m31_mul(r1595, r11);
    unsigned r1597 = stwo_m31_add(r1596, r10);
    sub_words[103u * row_count + row] = r1597;
    unsigned r1598 = stwo_m31_add(r1596, r10);
    lookup_words[60u * row_count + row] = r1598;
    unsigned r1599 = stwo_m31_add(r1470, r1596);
    out_cols[82u][row] = r1596;
    unsigned r1600 = stwo_m31_mul(r1599, r11);
    unsigned r1601 = stwo_m31_add(r1600, r10);
    sub_words[111u * row_count + row] = r1601;
    unsigned r1602 = stwo_m31_add(r1600, r10);
    out_cols[83u][row] = r1600;
    lookup_words[76u * row_count + row] = r1602;
    const unsigned dargs1[56] = { r140, r142, r189, r145, r147, r193, r150, r152, r197, r155, r157, r201, r160, r162, r205, r165, r167, r209, r170, r172, r213, r175, r177, r217, r180, r182, r221, r129, r222, r223, r224, r225, r226, r227, r228, r229, r230, r231, r232, r233, r234, r235, r236, r237, r238, r239, r240, r241, r242, r243, r244, r245, r246, r247, r248, r249 };
    unsigned douts1[28];
    stwo_wit_deduce_felt_mul(dargs1, douts1);
    unsigned r1603 = douts1[0];
    unsigned r1604 = douts1[1];
    unsigned r1605 = douts1[2];
    unsigned r1606 = douts1[3];
    unsigned r1607 = douts1[4];
    unsigned r1608 = douts1[5];
    unsigned r1609 = douts1[6];
    unsigned r1610 = douts1[7];
    unsigned r1611 = douts1[8];
    unsigned r1612 = douts1[9];
    unsigned r1613 = douts1[10];
    unsigned r1614 = douts1[11];
    unsigned r1615 = douts1[12];
    unsigned r1616 = douts1[13];
    unsigned r1617 = douts1[14];
    unsigned r1618 = douts1[15];
    unsigned r1619 = douts1[16];
    unsigned r1620 = douts1[17];
    unsigned r1621 = douts1[18];
    unsigned r1622 = douts1[19];
    unsigned r1623 = douts1[20];
    unsigned r1624 = douts1[21];
    unsigned r1625 = douts1[22];
    unsigned r1626 = douts1[23];
    unsigned r1627 = douts1[24];
    unsigned r1628 = douts1[25];
    unsigned r1629 = douts1[26];
    unsigned r1630 = douts1[27];
    unsigned r1631 = stwo_m31_mul(r140, r222);
    unsigned r1632 = stwo_m31_mul(r140, r223);
    unsigned r1633 = stwo_m31_mul(r142, r222);
    unsigned r1634 = stwo_m31_add(r1632, r1633);
    unsigned r1635 = stwo_m31_mul(r140, r224);
    unsigned r1636 = stwo_m31_mul(r142, r223);
    unsigned r1637 = stwo_m31_add(r1635, r1636);
    unsigned r1638 = stwo_m31_mul(r189, r222);
    unsigned r1639 = stwo_m31_add(r1637, r1638);
    unsigned r1640 = stwo_m31_mul(r140, r225);
    unsigned r1641 = stwo_m31_mul(r142, r224);
    unsigned r1642 = stwo_m31_add(r1640, r1641);
    unsigned r1643 = stwo_m31_mul(r189, r223);
    unsigned r1644 = stwo_m31_add(r1642, r1643);
    unsigned r1645 = stwo_m31_mul(r145, r222);
    unsigned r1646 = stwo_m31_add(r1644, r1645);
    unsigned r1647 = stwo_m31_mul(r140, r226);
    unsigned r1648 = stwo_m31_mul(r142, r225);
    unsigned r1649 = stwo_m31_add(r1647, r1648);
    unsigned r1650 = stwo_m31_mul(r189, r224);
    unsigned r1651 = stwo_m31_add(r1649, r1650);
    unsigned r1652 = stwo_m31_mul(r145, r223);
    unsigned r1653 = stwo_m31_add(r1651, r1652);
    unsigned r1654 = stwo_m31_mul(r147, r222);
    unsigned r1655 = stwo_m31_add(r1653, r1654);
    unsigned r1656 = stwo_m31_mul(r140, r227);
    unsigned r1657 = stwo_m31_mul(r142, r226);
    unsigned r1658 = stwo_m31_add(r1656, r1657);
    unsigned r1659 = stwo_m31_mul(r189, r225);
    unsigned r1660 = stwo_m31_add(r1658, r1659);
    unsigned r1661 = stwo_m31_mul(r145, r224);
    unsigned r1662 = stwo_m31_add(r1660, r1661);
    unsigned r1663 = stwo_m31_mul(r147, r223);
    unsigned r1664 = stwo_m31_add(r1662, r1663);
    unsigned r1665 = stwo_m31_mul(r193, r222);
    unsigned r1666 = stwo_m31_add(r1664, r1665);
    unsigned r1667 = stwo_m31_mul(r140, r228);
    unsigned r1668 = stwo_m31_mul(r142, r227);
    unsigned r1669 = stwo_m31_add(r1667, r1668);
    unsigned r1670 = stwo_m31_mul(r189, r226);
    unsigned r1671 = stwo_m31_add(r1669, r1670);
    unsigned r1672 = stwo_m31_mul(r145, r225);
    unsigned r1673 = stwo_m31_add(r1671, r1672);
    unsigned r1674 = stwo_m31_mul(r147, r224);
    unsigned r1675 = stwo_m31_add(r1673, r1674);
    unsigned r1676 = stwo_m31_mul(r193, r223);
    unsigned r1677 = stwo_m31_add(r1675, r1676);
    unsigned r1678 = stwo_m31_mul(r150, r222);
    unsigned r1679 = stwo_m31_add(r1677, r1678);
    unsigned r1680 = stwo_m31_mul(r142, r228);
    unsigned r1681 = stwo_m31_mul(r189, r227);
    unsigned r1682 = stwo_m31_add(r1680, r1681);
    unsigned r1683 = stwo_m31_mul(r145, r226);
    unsigned r1684 = stwo_m31_add(r1682, r1683);
    unsigned r1685 = stwo_m31_mul(r147, r225);
    unsigned r1686 = stwo_m31_add(r1684, r1685);
    unsigned r1687 = stwo_m31_mul(r193, r224);
    unsigned r1688 = stwo_m31_add(r1686, r1687);
    unsigned r1689 = stwo_m31_mul(r150, r223);
    unsigned r1690 = stwo_m31_add(r1688, r1689);
    unsigned r1691 = stwo_m31_mul(r189, r228);
    unsigned r1692 = stwo_m31_mul(r145, r227);
    unsigned r1693 = stwo_m31_add(r1691, r1692);
    unsigned r1694 = stwo_m31_mul(r147, r226);
    unsigned r1695 = stwo_m31_add(r1693, r1694);
    unsigned r1696 = stwo_m31_mul(r193, r225);
    unsigned r1697 = stwo_m31_add(r1695, r1696);
    unsigned r1698 = stwo_m31_mul(r150, r224);
    unsigned r1699 = stwo_m31_add(r1697, r1698);
    unsigned r1700 = stwo_m31_mul(r145, r228);
    unsigned r1701 = stwo_m31_mul(r147, r227);
    unsigned r1702 = stwo_m31_add(r1700, r1701);
    unsigned r1703 = stwo_m31_mul(r193, r226);
    unsigned r1704 = stwo_m31_add(r1702, r1703);
    unsigned r1705 = stwo_m31_mul(r150, r225);
    unsigned r1706 = stwo_m31_add(r1704, r1705);
    unsigned r1707 = stwo_m31_mul(r147, r228);
    unsigned r1708 = stwo_m31_mul(r193, r227);
    unsigned r1709 = stwo_m31_add(r1707, r1708);
    unsigned r1710 = stwo_m31_mul(r150, r226);
    unsigned r1711 = stwo_m31_add(r1709, r1710);
    unsigned r1712 = stwo_m31_mul(r193, r228);
    unsigned r1713 = stwo_m31_mul(r150, r227);
    unsigned r1714 = stwo_m31_add(r1712, r1713);
    unsigned r1715 = stwo_m31_mul(r150, r228);
    unsigned r1716 = stwo_m31_mul(r152, r229);
    unsigned r1717 = stwo_m31_mul(r152, r230);
    unsigned r1718 = stwo_m31_mul(r197, r229);
    unsigned r1719 = stwo_m31_add(r1717, r1718);
    unsigned r1720 = stwo_m31_mul(r152, r231);
    unsigned r1721 = stwo_m31_mul(r197, r230);
    unsigned r1722 = stwo_m31_add(r1720, r1721);
    unsigned r1723 = stwo_m31_mul(r155, r229);
    unsigned r1724 = stwo_m31_add(r1722, r1723);
    unsigned r1725 = stwo_m31_mul(r152, r232);
    unsigned r1726 = stwo_m31_mul(r197, r231);
    unsigned r1727 = stwo_m31_add(r1725, r1726);
    unsigned r1728 = stwo_m31_mul(r155, r230);
    unsigned r1729 = stwo_m31_add(r1727, r1728);
    unsigned r1730 = stwo_m31_mul(r157, r229);
    unsigned r1731 = stwo_m31_add(r1729, r1730);
    unsigned r1732 = stwo_m31_mul(r152, r233);
    unsigned r1733 = stwo_m31_mul(r197, r232);
    unsigned r1734 = stwo_m31_add(r1732, r1733);
    unsigned r1735 = stwo_m31_mul(r155, r231);
    unsigned r1736 = stwo_m31_add(r1734, r1735);
    unsigned r1737 = stwo_m31_mul(r157, r230);
    unsigned r1738 = stwo_m31_add(r1736, r1737);
    unsigned r1739 = stwo_m31_mul(r201, r229);
    unsigned r1740 = stwo_m31_add(r1738, r1739);
    unsigned r1741 = stwo_m31_mul(r152, r234);
    unsigned r1742 = stwo_m31_mul(r197, r233);
    unsigned r1743 = stwo_m31_add(r1741, r1742);
    unsigned r1744 = stwo_m31_mul(r155, r232);
    unsigned r1745 = stwo_m31_add(r1743, r1744);
    unsigned r1746 = stwo_m31_mul(r157, r231);
    unsigned r1747 = stwo_m31_add(r1745, r1746);
    unsigned r1748 = stwo_m31_mul(r201, r230);
    unsigned r1749 = stwo_m31_add(r1747, r1748);
    unsigned r1750 = stwo_m31_mul(r160, r229);
    unsigned r1751 = stwo_m31_add(r1749, r1750);
    unsigned r1752 = stwo_m31_mul(r152, r235);
    unsigned r1753 = stwo_m31_mul(r197, r234);
    unsigned r1754 = stwo_m31_add(r1752, r1753);
    unsigned r1755 = stwo_m31_mul(r155, r233);
    unsigned r1756 = stwo_m31_add(r1754, r1755);
    unsigned r1757 = stwo_m31_mul(r157, r232);
    unsigned r1758 = stwo_m31_add(r1756, r1757);
    unsigned r1759 = stwo_m31_mul(r201, r231);
    unsigned r1760 = stwo_m31_add(r1758, r1759);
    unsigned r1761 = stwo_m31_mul(r160, r230);
    unsigned r1762 = stwo_m31_add(r1760, r1761);
    unsigned r1763 = stwo_m31_mul(r162, r229);
    unsigned r1764 = stwo_m31_add(r1762, r1763);
    unsigned r1765 = stwo_m31_mul(r197, r235);
    unsigned r1766 = stwo_m31_mul(r155, r234);
    unsigned r1767 = stwo_m31_add(r1765, r1766);
    unsigned r1768 = stwo_m31_mul(r157, r233);
    unsigned r1769 = stwo_m31_add(r1767, r1768);
    unsigned r1770 = stwo_m31_mul(r201, r232);
    unsigned r1771 = stwo_m31_add(r1769, r1770);
    unsigned r1772 = stwo_m31_mul(r160, r231);
    unsigned r1773 = stwo_m31_add(r1771, r1772);
    unsigned r1774 = stwo_m31_mul(r162, r230);
    unsigned r1775 = stwo_m31_add(r1773, r1774);
    unsigned r1776 = stwo_m31_mul(r155, r235);
    unsigned r1777 = stwo_m31_mul(r157, r234);
    unsigned r1778 = stwo_m31_add(r1776, r1777);
    unsigned r1779 = stwo_m31_mul(r201, r233);
    unsigned r1780 = stwo_m31_add(r1778, r1779);
    unsigned r1781 = stwo_m31_mul(r160, r232);
    unsigned r1782 = stwo_m31_add(r1780, r1781);
    unsigned r1783 = stwo_m31_mul(r162, r231);
    unsigned r1784 = stwo_m31_add(r1782, r1783);
    unsigned r1785 = stwo_m31_mul(r157, r235);
    unsigned r1786 = stwo_m31_mul(r201, r234);
    unsigned r1787 = stwo_m31_add(r1785, r1786);
    unsigned r1788 = stwo_m31_mul(r160, r233);
    unsigned r1789 = stwo_m31_add(r1787, r1788);
    unsigned r1790 = stwo_m31_mul(r162, r232);
    unsigned r1791 = stwo_m31_add(r1789, r1790);
    unsigned r1792 = stwo_m31_mul(r201, r235);
    unsigned r1793 = stwo_m31_mul(r160, r234);
    unsigned r1794 = stwo_m31_add(r1792, r1793);
    unsigned r1795 = stwo_m31_mul(r162, r233);
    unsigned r1796 = stwo_m31_add(r1794, r1795);
    unsigned r1797 = stwo_m31_mul(r160, r235);
    unsigned r1798 = stwo_m31_mul(r162, r234);
    unsigned r1799 = stwo_m31_add(r1797, r1798);
    unsigned r1800 = stwo_m31_mul(r162, r235);
    unsigned r1801 = stwo_m31_add(r140, r152);
    unsigned r1802 = stwo_m31_add(r142, r197);
    unsigned r1803 = stwo_m31_add(r189, r155);
    unsigned r1804 = stwo_m31_add(r145, r157);
    unsigned r1805 = stwo_m31_add(r147, r201);
    unsigned r1806 = stwo_m31_add(r193, r160);
    unsigned r1807 = stwo_m31_add(r150, r162);
    unsigned r1808 = stwo_m31_add(r222, r229);
    unsigned r1809 = stwo_m31_add(r223, r230);
    unsigned r1810 = stwo_m31_add(r224, r231);
    unsigned r1811 = stwo_m31_add(r225, r232);
    unsigned r1812 = stwo_m31_add(r226, r233);
    unsigned r1813 = stwo_m31_add(r227, r234);
    unsigned r1814 = stwo_m31_add(r228, r235);
    unsigned r1815 = stwo_m31_mul(r1801, r1808);
    unsigned r1816 = stwo_m31_sub(r1815, r1631);
    unsigned r1817 = stwo_m31_sub(r1816, r1716);
    unsigned r1818 = stwo_m31_add(r1690, r1817);
    unsigned r1819 = stwo_m31_mul(r1801, r1809);
    unsigned r1820 = stwo_m31_mul(r1802, r1808);
    unsigned r1821 = stwo_m31_add(r1819, r1820);
    unsigned r1822 = stwo_m31_sub(r1821, r1634);
    unsigned r1823 = stwo_m31_sub(r1822, r1719);
    unsigned r1824 = stwo_m31_add(r1699, r1823);
    unsigned r1825 = stwo_m31_mul(r1801, r1810);
    unsigned r1826 = stwo_m31_mul(r1802, r1809);
    unsigned r1827 = stwo_m31_add(r1825, r1826);
    unsigned r1828 = stwo_m31_mul(r1803, r1808);
    unsigned r1829 = stwo_m31_add(r1827, r1828);
    unsigned r1830 = stwo_m31_sub(r1829, r1639);
    unsigned r1831 = stwo_m31_sub(r1830, r1724);
    unsigned r1832 = stwo_m31_add(r1706, r1831);
    unsigned r1833 = stwo_m31_mul(r1801, r1811);
    unsigned r1834 = stwo_m31_mul(r1802, r1810);
    unsigned r1835 = stwo_m31_add(r1833, r1834);
    unsigned r1836 = stwo_m31_mul(r1803, r1809);
    unsigned r1837 = stwo_m31_add(r1835, r1836);
    unsigned r1838 = stwo_m31_mul(r1804, r1808);
    unsigned r1839 = stwo_m31_add(r1837, r1838);
    unsigned r1840 = stwo_m31_sub(r1839, r1646);
    unsigned r1841 = stwo_m31_sub(r1840, r1731);
    unsigned r1842 = stwo_m31_add(r1711, r1841);
    unsigned r1843 = stwo_m31_mul(r1801, r1812);
    unsigned r1844 = stwo_m31_mul(r1802, r1811);
    unsigned r1845 = stwo_m31_add(r1843, r1844);
    unsigned r1846 = stwo_m31_mul(r1803, r1810);
    unsigned r1847 = stwo_m31_add(r1845, r1846);
    unsigned r1848 = stwo_m31_mul(r1804, r1809);
    unsigned r1849 = stwo_m31_add(r1847, r1848);
    unsigned r1850 = stwo_m31_mul(r1805, r1808);
    unsigned r1851 = stwo_m31_add(r1849, r1850);
    unsigned r1852 = stwo_m31_sub(r1851, r1655);
    unsigned r1853 = stwo_m31_sub(r1852, r1740);
    unsigned r1854 = stwo_m31_add(r1714, r1853);
    unsigned r1855 = stwo_m31_mul(r1801, r1813);
    unsigned r1856 = stwo_m31_mul(r1802, r1812);
    unsigned r1857 = stwo_m31_add(r1855, r1856);
    unsigned r1858 = stwo_m31_mul(r1803, r1811);
    unsigned r1859 = stwo_m31_add(r1857, r1858);
    unsigned r1860 = stwo_m31_mul(r1804, r1810);
    unsigned r1861 = stwo_m31_add(r1859, r1860);
    unsigned r1862 = stwo_m31_mul(r1805, r1809);
    unsigned r1863 = stwo_m31_add(r1861, r1862);
    unsigned r1864 = stwo_m31_mul(r1806, r1808);
    unsigned r1865 = stwo_m31_add(r1863, r1864);
    unsigned r1866 = stwo_m31_sub(r1865, r1666);
    unsigned r1867 = stwo_m31_sub(r1866, r1751);
    unsigned r1868 = stwo_m31_add(r1715, r1867);
    unsigned r1869 = stwo_m31_mul(r1801, r1814);
    unsigned r1870 = stwo_m31_mul(r1802, r1813);
    unsigned r1871 = stwo_m31_add(r1869, r1870);
    unsigned r1872 = stwo_m31_mul(r1803, r1812);
    unsigned r1873 = stwo_m31_add(r1871, r1872);
    unsigned r1874 = stwo_m31_mul(r1804, r1811);
    unsigned r1875 = stwo_m31_add(r1873, r1874);
    unsigned r1876 = stwo_m31_mul(r1805, r1810);
    unsigned r1877 = stwo_m31_add(r1875, r1876);
    unsigned r1878 = stwo_m31_mul(r1806, r1809);
    unsigned r1879 = stwo_m31_add(r1877, r1878);
    unsigned r1880 = stwo_m31_mul(r1807, r1808);
    unsigned r1881 = stwo_m31_add(r1879, r1880);
    unsigned r1882 = stwo_m31_sub(r1881, r1679);
    unsigned r1883 = stwo_m31_sub(r1882, r1764);
    unsigned r1884 = stwo_m31_mul(r1802, r1814);
    unsigned r1885 = stwo_m31_mul(r1803, r1813);
    unsigned r1886 = stwo_m31_add(r1884, r1885);
    unsigned r1887 = stwo_m31_mul(r1804, r1812);
    unsigned r1888 = stwo_m31_add(r1886, r1887);
    unsigned r1889 = stwo_m31_mul(r1805, r1811);
    unsigned r1890 = stwo_m31_add(r1888, r1889);
    unsigned r1891 = stwo_m31_mul(r1806, r1810);
    unsigned r1892 = stwo_m31_add(r1890, r1891);
    unsigned r1893 = stwo_m31_mul(r1807, r1809);
    unsigned r1894 = stwo_m31_add(r1892, r1893);
    unsigned r1895 = stwo_m31_sub(r1894, r1690);
    unsigned r1896 = stwo_m31_sub(r1895, r1775);
    unsigned r1897 = stwo_m31_add(r1716, r1896);
    unsigned r1898 = stwo_m31_mul(r1803, r1814);
    unsigned r1899 = stwo_m31_mul(r1804, r1813);
    unsigned r1900 = stwo_m31_add(r1898, r1899);
    unsigned r1901 = stwo_m31_mul(r1805, r1812);
    unsigned r1902 = stwo_m31_add(r1900, r1901);
    unsigned r1903 = stwo_m31_mul(r1806, r1811);
    unsigned r1904 = stwo_m31_add(r1902, r1903);
    unsigned r1905 = stwo_m31_mul(r1807, r1810);
    unsigned r1906 = stwo_m31_add(r1904, r1905);
    unsigned r1907 = stwo_m31_sub(r1906, r1699);
    unsigned r1908 = stwo_m31_sub(r1907, r1784);
    unsigned r1909 = stwo_m31_add(r1719, r1908);
    unsigned r1910 = stwo_m31_mul(r1804, r1814);
    unsigned r1911 = stwo_m31_mul(r1805, r1813);
    unsigned r1912 = stwo_m31_add(r1910, r1911);
    unsigned r1913 = stwo_m31_mul(r1806, r1812);
    unsigned r1914 = stwo_m31_add(r1912, r1913);
    unsigned r1915 = stwo_m31_mul(r1807, r1811);
    unsigned r1916 = stwo_m31_add(r1914, r1915);
    unsigned r1917 = stwo_m31_sub(r1916, r1706);
    unsigned r1918 = stwo_m31_sub(r1917, r1791);
    unsigned r1919 = stwo_m31_add(r1724, r1918);
    unsigned r1920 = stwo_m31_mul(r1805, r1814);
    unsigned r1921 = stwo_m31_mul(r1806, r1813);
    unsigned r1922 = stwo_m31_add(r1920, r1921);
    unsigned r1923 = stwo_m31_mul(r1807, r1812);
    unsigned r1924 = stwo_m31_add(r1922, r1923);
    unsigned r1925 = stwo_m31_sub(r1924, r1711);
    unsigned r1926 = stwo_m31_sub(r1925, r1796);
    unsigned r1927 = stwo_m31_add(r1731, r1926);
    unsigned r1928 = stwo_m31_mul(r1806, r1814);
    unsigned r1929 = stwo_m31_mul(r1807, r1813);
    unsigned r1930 = stwo_m31_add(r1928, r1929);
    unsigned r1931 = stwo_m31_sub(r1930, r1714);
    unsigned r1932 = stwo_m31_sub(r1931, r1799);
    unsigned r1933 = stwo_m31_add(r1740, r1932);
    unsigned r1934 = stwo_m31_mul(r1807, r1814);
    unsigned r1935 = stwo_m31_sub(r1934, r1715);
    unsigned r1936 = stwo_m31_sub(r1935, r1800);
    unsigned r1937 = stwo_m31_add(r1751, r1936);
    unsigned r1938 = stwo_m31_mul(r205, r236);
    unsigned r1939 = stwo_m31_mul(r205, r237);
    unsigned r1940 = stwo_m31_mul(r165, r236);
    unsigned r1941 = stwo_m31_add(r1939, r1940);
    unsigned r1942 = stwo_m31_mul(r205, r238);
    unsigned r1943 = stwo_m31_mul(r165, r237);
    unsigned r1944 = stwo_m31_add(r1942, r1943);
    unsigned r1945 = stwo_m31_mul(r167, r236);
    unsigned r1946 = stwo_m31_add(r1944, r1945);
    unsigned r1947 = stwo_m31_mul(r205, r239);
    unsigned r1948 = stwo_m31_mul(r165, r238);
    unsigned r1949 = stwo_m31_add(r1947, r1948);
    unsigned r1950 = stwo_m31_mul(r167, r237);
    unsigned r1951 = stwo_m31_add(r1949, r1950);
    unsigned r1952 = stwo_m31_mul(r209, r236);
    unsigned r1953 = stwo_m31_add(r1951, r1952);
    unsigned r1954 = stwo_m31_mul(r205, r240);
    unsigned r1955 = stwo_m31_mul(r165, r239);
    unsigned r1956 = stwo_m31_add(r1954, r1955);
    unsigned r1957 = stwo_m31_mul(r167, r238);
    unsigned r1958 = stwo_m31_add(r1956, r1957);
    unsigned r1959 = stwo_m31_mul(r209, r237);
    unsigned r1960 = stwo_m31_add(r1958, r1959);
    unsigned r1961 = stwo_m31_mul(r170, r236);
    unsigned r1962 = stwo_m31_add(r1960, r1961);
    unsigned r1963 = stwo_m31_mul(r205, r241);
    unsigned r1964 = stwo_m31_mul(r165, r240);
    unsigned r1965 = stwo_m31_add(r1963, r1964);
    unsigned r1966 = stwo_m31_mul(r167, r239);
    unsigned r1967 = stwo_m31_add(r1965, r1966);
    unsigned r1968 = stwo_m31_mul(r209, r238);
    unsigned r1969 = stwo_m31_add(r1967, r1968);
    unsigned r1970 = stwo_m31_mul(r170, r237);
    unsigned r1971 = stwo_m31_add(r1969, r1970);
    unsigned r1972 = stwo_m31_mul(r172, r236);
    unsigned r1973 = stwo_m31_add(r1971, r1972);
    unsigned r1974 = stwo_m31_mul(r205, r242);
    unsigned r1975 = stwo_m31_mul(r165, r241);
    unsigned r1976 = stwo_m31_add(r1974, r1975);
    unsigned r1977 = stwo_m31_mul(r167, r240);
    unsigned r1978 = stwo_m31_add(r1976, r1977);
    unsigned r1979 = stwo_m31_mul(r209, r239);
    unsigned r1980 = stwo_m31_add(r1978, r1979);
    unsigned r1981 = stwo_m31_mul(r170, r238);
    unsigned r1982 = stwo_m31_add(r1980, r1981);
    unsigned r1983 = stwo_m31_mul(r172, r237);
    unsigned r1984 = stwo_m31_add(r1982, r1983);
    unsigned r1985 = stwo_m31_mul(r213, r236);
    unsigned r1986 = stwo_m31_add(r1984, r1985);
    unsigned r1987 = stwo_m31_mul(r165, r242);
    unsigned r1988 = stwo_m31_mul(r167, r241);
    unsigned r1989 = stwo_m31_add(r1987, r1988);
    unsigned r1990 = stwo_m31_mul(r209, r240);
    unsigned r1991 = stwo_m31_add(r1989, r1990);
    unsigned r1992 = stwo_m31_mul(r170, r239);
    unsigned r1993 = stwo_m31_add(r1991, r1992);
    unsigned r1994 = stwo_m31_mul(r172, r238);
    unsigned r1995 = stwo_m31_add(r1993, r1994);
    unsigned r1996 = stwo_m31_mul(r213, r237);
    unsigned r1997 = stwo_m31_add(r1995, r1996);
    unsigned r1998 = stwo_m31_mul(r167, r242);
    unsigned r1999 = stwo_m31_mul(r209, r241);
    unsigned r2000 = stwo_m31_add(r1998, r1999);
    unsigned r2001 = stwo_m31_mul(r170, r240);
    unsigned r2002 = stwo_m31_add(r2000, r2001);
    unsigned r2003 = stwo_m31_mul(r172, r239);
    unsigned r2004 = stwo_m31_add(r2002, r2003);
    unsigned r2005 = stwo_m31_mul(r213, r238);
    unsigned r2006 = stwo_m31_add(r2004, r2005);
    unsigned r2007 = stwo_m31_mul(r209, r242);
    unsigned r2008 = stwo_m31_mul(r170, r241);
    unsigned r2009 = stwo_m31_add(r2007, r2008);
    unsigned r2010 = stwo_m31_mul(r172, r240);
    unsigned r2011 = stwo_m31_add(r2009, r2010);
    unsigned r2012 = stwo_m31_mul(r213, r239);
    unsigned r2013 = stwo_m31_add(r2011, r2012);
    unsigned r2014 = stwo_m31_mul(r170, r242);
    unsigned r2015 = stwo_m31_mul(r172, r241);
    unsigned r2016 = stwo_m31_add(r2014, r2015);
    unsigned r2017 = stwo_m31_mul(r213, r240);
    unsigned r2018 = stwo_m31_add(r2016, r2017);
    unsigned r2019 = stwo_m31_mul(r172, r242);
    unsigned r2020 = stwo_m31_mul(r213, r241);
    unsigned r2021 = stwo_m31_add(r2019, r2020);
    unsigned r2022 = stwo_m31_mul(r213, r242);
    unsigned r2023 = stwo_m31_mul(r175, r243);
    unsigned r2024 = stwo_m31_mul(r175, r244);
    unsigned r2025 = stwo_m31_mul(r177, r243);
    unsigned r2026 = stwo_m31_add(r2024, r2025);
    unsigned r2027 = stwo_m31_mul(r175, r245);
    unsigned r2028 = stwo_m31_mul(r177, r244);
    unsigned r2029 = stwo_m31_add(r2027, r2028);
    unsigned r2030 = stwo_m31_mul(r217, r243);
    unsigned r2031 = stwo_m31_add(r2029, r2030);
    unsigned r2032 = stwo_m31_mul(r175, r246);
    unsigned r2033 = stwo_m31_mul(r177, r245);
    unsigned r2034 = stwo_m31_add(r2032, r2033);
    unsigned r2035 = stwo_m31_mul(r217, r244);
    unsigned r2036 = stwo_m31_add(r2034, r2035);
    unsigned r2037 = stwo_m31_mul(r180, r243);
    unsigned r2038 = stwo_m31_add(r2036, r2037);
    unsigned r2039 = stwo_m31_mul(r175, r247);
    unsigned r2040 = stwo_m31_mul(r177, r246);
    unsigned r2041 = stwo_m31_add(r2039, r2040);
    unsigned r2042 = stwo_m31_mul(r217, r245);
    unsigned r2043 = stwo_m31_add(r2041, r2042);
    unsigned r2044 = stwo_m31_mul(r180, r244);
    unsigned r2045 = stwo_m31_add(r2043, r2044);
    unsigned r2046 = stwo_m31_mul(r182, r243);
    unsigned r2047 = stwo_m31_add(r2045, r2046);
    unsigned r2048 = stwo_m31_mul(r175, r248);
    unsigned r2049 = stwo_m31_mul(r177, r247);
    unsigned r2050 = stwo_m31_add(r2048, r2049);
    unsigned r2051 = stwo_m31_mul(r217, r246);
    unsigned r2052 = stwo_m31_add(r2050, r2051);
    unsigned r2053 = stwo_m31_mul(r180, r245);
    unsigned r2054 = stwo_m31_add(r2052, r2053);
    unsigned r2055 = stwo_m31_mul(r182, r244);
    unsigned r2056 = stwo_m31_add(r2054, r2055);
    unsigned r2057 = stwo_m31_mul(r221, r243);
    unsigned r2058 = stwo_m31_add(r2056, r2057);
    unsigned r2059 = stwo_m31_mul(r175, r249);
    unsigned r2060 = stwo_m31_mul(r177, r248);
    unsigned r2061 = stwo_m31_add(r2059, r2060);
    unsigned r2062 = stwo_m31_mul(r217, r247);
    unsigned r2063 = stwo_m31_add(r2061, r2062);
    unsigned r2064 = stwo_m31_mul(r180, r246);
    unsigned r2065 = stwo_m31_add(r2063, r2064);
    unsigned r2066 = stwo_m31_mul(r182, r245);
    unsigned r2067 = stwo_m31_add(r2065, r2066);
    unsigned r2068 = stwo_m31_mul(r221, r244);
    unsigned r2069 = stwo_m31_add(r2067, r2068);
    unsigned r2070 = stwo_m31_mul(r129, r243);
    unsigned r2071 = stwo_m31_add(r2069, r2070);
    unsigned r2072 = stwo_m31_mul(r177, r249);
    unsigned r2073 = stwo_m31_mul(r217, r248);
    unsigned r2074 = stwo_m31_add(r2072, r2073);
    unsigned r2075 = stwo_m31_mul(r180, r247);
    unsigned r2076 = stwo_m31_add(r2074, r2075);
    unsigned r2077 = stwo_m31_mul(r182, r246);
    unsigned r2078 = stwo_m31_add(r2076, r2077);
    unsigned r2079 = stwo_m31_mul(r221, r245);
    unsigned r2080 = stwo_m31_add(r2078, r2079);
    unsigned r2081 = stwo_m31_mul(r129, r244);
    unsigned r2082 = stwo_m31_add(r2080, r2081);
    unsigned r2083 = stwo_m31_mul(r217, r249);
    unsigned r2084 = stwo_m31_mul(r180, r248);
    unsigned r2085 = stwo_m31_add(r2083, r2084);
    unsigned r2086 = stwo_m31_mul(r182, r247);
    unsigned r2087 = stwo_m31_add(r2085, r2086);
    unsigned r2088 = stwo_m31_mul(r221, r246);
    unsigned r2089 = stwo_m31_add(r2087, r2088);
    unsigned r2090 = stwo_m31_mul(r129, r245);
    unsigned r2091 = stwo_m31_add(r2089, r2090);
    unsigned r2092 = stwo_m31_mul(r180, r249);
    unsigned r2093 = stwo_m31_mul(r182, r248);
    unsigned r2094 = stwo_m31_add(r2092, r2093);
    unsigned r2095 = stwo_m31_mul(r221, r247);
    unsigned r2096 = stwo_m31_add(r2094, r2095);
    unsigned r2097 = stwo_m31_mul(r129, r246);
    unsigned r2098 = stwo_m31_add(r2096, r2097);
    unsigned r2099 = stwo_m31_mul(r182, r249);
    unsigned r2100 = stwo_m31_mul(r221, r248);
    unsigned r2101 = stwo_m31_add(r2099, r2100);
    unsigned r2102 = stwo_m31_mul(r129, r247);
    unsigned r2103 = stwo_m31_add(r2101, r2102);
    unsigned r2104 = stwo_m31_mul(r221, r249);
    unsigned r2105 = stwo_m31_mul(r129, r248);
    unsigned r2106 = stwo_m31_add(r2104, r2105);
    unsigned r2107 = stwo_m31_mul(r129, r249);
    unsigned r2108 = stwo_m31_add(r205, r175);
    unsigned r2109 = stwo_m31_add(r165, r177);
    unsigned r2110 = stwo_m31_add(r167, r217);
    unsigned r2111 = stwo_m31_add(r209, r180);
    unsigned r2112 = stwo_m31_add(r170, r182);
    unsigned r2113 = stwo_m31_add(r172, r221);
    unsigned r2114 = stwo_m31_add(r213, r129);
    unsigned r2115 = stwo_m31_add(r236, r243);
    unsigned r2116 = stwo_m31_add(r237, r244);
    unsigned r2117 = stwo_m31_add(r238, r245);
    unsigned r2118 = stwo_m31_add(r239, r246);
    unsigned r2119 = stwo_m31_add(r240, r247);
    unsigned r2120 = stwo_m31_add(r241, r248);
    unsigned r2121 = stwo_m31_add(r242, r249);
    unsigned r2122 = stwo_m31_mul(r2108, r2115);
    unsigned r2123 = stwo_m31_sub(r2122, r1938);
    unsigned r2124 = stwo_m31_sub(r2123, r2023);
    unsigned r2125 = stwo_m31_add(r1997, r2124);
    unsigned r2126 = stwo_m31_mul(r2108, r2116);
    unsigned r2127 = stwo_m31_mul(r2109, r2115);
    unsigned r2128 = stwo_m31_add(r2126, r2127);
    unsigned r2129 = stwo_m31_sub(r2128, r1941);
    unsigned r2130 = stwo_m31_sub(r2129, r2026);
    unsigned r2131 = stwo_m31_add(r2006, r2130);
    unsigned r2132 = stwo_m31_mul(r2108, r2117);
    unsigned r2133 = stwo_m31_mul(r2109, r2116);
    unsigned r2134 = stwo_m31_add(r2132, r2133);
    unsigned r2135 = stwo_m31_mul(r2110, r2115);
    unsigned r2136 = stwo_m31_add(r2134, r2135);
    unsigned r2137 = stwo_m31_sub(r2136, r1946);
    unsigned r2138 = stwo_m31_sub(r2137, r2031);
    unsigned r2139 = stwo_m31_add(r2013, r2138);
    unsigned r2140 = stwo_m31_mul(r2108, r2118);
    unsigned r2141 = stwo_m31_mul(r2109, r2117);
    unsigned r2142 = stwo_m31_add(r2140, r2141);
    unsigned r2143 = stwo_m31_mul(r2110, r2116);
    unsigned r2144 = stwo_m31_add(r2142, r2143);
    unsigned r2145 = stwo_m31_mul(r2111, r2115);
    unsigned r2146 = stwo_m31_add(r2144, r2145);
    unsigned r2147 = stwo_m31_sub(r2146, r1953);
    unsigned r2148 = stwo_m31_sub(r2147, r2038);
    unsigned r2149 = stwo_m31_add(r2018, r2148);
    unsigned r2150 = stwo_m31_mul(r2108, r2119);
    unsigned r2151 = stwo_m31_mul(r2109, r2118);
    unsigned r2152 = stwo_m31_add(r2150, r2151);
    unsigned r2153 = stwo_m31_mul(r2110, r2117);
    unsigned r2154 = stwo_m31_add(r2152, r2153);
    unsigned r2155 = stwo_m31_mul(r2111, r2116);
    unsigned r2156 = stwo_m31_add(r2154, r2155);
    unsigned r2157 = stwo_m31_mul(r2112, r2115);
    unsigned r2158 = stwo_m31_add(r2156, r2157);
    unsigned r2159 = stwo_m31_sub(r2158, r1962);
    unsigned r2160 = stwo_m31_sub(r2159, r2047);
    unsigned r2161 = stwo_m31_add(r2021, r2160);
    unsigned r2162 = stwo_m31_mul(r2108, r2120);
    unsigned r2163 = stwo_m31_mul(r2109, r2119);
    unsigned r2164 = stwo_m31_add(r2162, r2163);
    unsigned r2165 = stwo_m31_mul(r2110, r2118);
    unsigned r2166 = stwo_m31_add(r2164, r2165);
    unsigned r2167 = stwo_m31_mul(r2111, r2117);
    unsigned r2168 = stwo_m31_add(r2166, r2167);
    unsigned r2169 = stwo_m31_mul(r2112, r2116);
    unsigned r2170 = stwo_m31_add(r2168, r2169);
    unsigned r2171 = stwo_m31_mul(r2113, r2115);
    unsigned r2172 = stwo_m31_add(r2170, r2171);
    unsigned r2173 = stwo_m31_sub(r2172, r1973);
    unsigned r2174 = stwo_m31_sub(r2173, r2058);
    unsigned r2175 = stwo_m31_add(r2022, r2174);
    unsigned r2176 = stwo_m31_mul(r2108, r2121);
    unsigned r2177 = stwo_m31_mul(r2109, r2120);
    unsigned r2178 = stwo_m31_add(r2176, r2177);
    unsigned r2179 = stwo_m31_mul(r2110, r2119);
    unsigned r2180 = stwo_m31_add(r2178, r2179);
    unsigned r2181 = stwo_m31_mul(r2111, r2118);
    unsigned r2182 = stwo_m31_add(r2180, r2181);
    unsigned r2183 = stwo_m31_mul(r2112, r2117);
    unsigned r2184 = stwo_m31_add(r2182, r2183);
    unsigned r2185 = stwo_m31_mul(r2113, r2116);
    unsigned r2186 = stwo_m31_add(r2184, r2185);
    unsigned r2187 = stwo_m31_mul(r2114, r2115);
    unsigned r2188 = stwo_m31_add(r2186, r2187);
    unsigned r2189 = stwo_m31_sub(r2188, r1986);
    unsigned r2190 = stwo_m31_sub(r2189, r2071);
    unsigned r2191 = stwo_m31_mul(r2109, r2121);
    unsigned r2192 = stwo_m31_mul(r2110, r2120);
    unsigned r2193 = stwo_m31_add(r2191, r2192);
    unsigned r2194 = stwo_m31_mul(r2111, r2119);
    unsigned r2195 = stwo_m31_add(r2193, r2194);
    unsigned r2196 = stwo_m31_mul(r2112, r2118);
    unsigned r2197 = stwo_m31_add(r2195, r2196);
    unsigned r2198 = stwo_m31_mul(r2113, r2117);
    unsigned r2199 = stwo_m31_add(r2197, r2198);
    unsigned r2200 = stwo_m31_mul(r2114, r2116);
    unsigned r2201 = stwo_m31_add(r2199, r2200);
    unsigned r2202 = stwo_m31_sub(r2201, r1997);
    unsigned r2203 = stwo_m31_sub(r2202, r2082);
    unsigned r2204 = stwo_m31_add(r2023, r2203);
    unsigned r2205 = stwo_m31_mul(r2110, r2121);
    unsigned r2206 = stwo_m31_mul(r2111, r2120);
    unsigned r2207 = stwo_m31_add(r2205, r2206);
    unsigned r2208 = stwo_m31_mul(r2112, r2119);
    unsigned r2209 = stwo_m31_add(r2207, r2208);
    unsigned r2210 = stwo_m31_mul(r2113, r2118);
    unsigned r2211 = stwo_m31_add(r2209, r2210);
    unsigned r2212 = stwo_m31_mul(r2114, r2117);
    unsigned r2213 = stwo_m31_add(r2211, r2212);
    unsigned r2214 = stwo_m31_sub(r2213, r2006);
    unsigned r2215 = stwo_m31_sub(r2214, r2091);
    unsigned r2216 = stwo_m31_add(r2026, r2215);
    unsigned r2217 = stwo_m31_mul(r2111, r2121);
    unsigned r2218 = stwo_m31_mul(r2112, r2120);
    unsigned r2219 = stwo_m31_add(r2217, r2218);
    unsigned r2220 = stwo_m31_mul(r2113, r2119);
    unsigned r2221 = stwo_m31_add(r2219, r2220);
    unsigned r2222 = stwo_m31_mul(r2114, r2118);
    unsigned r2223 = stwo_m31_add(r2221, r2222);
    unsigned r2224 = stwo_m31_sub(r2223, r2013);
    unsigned r2225 = stwo_m31_sub(r2224, r2098);
    unsigned r2226 = stwo_m31_add(r2031, r2225);
    unsigned r2227 = stwo_m31_mul(r2112, r2121);
    unsigned r2228 = stwo_m31_mul(r2113, r2120);
    unsigned r2229 = stwo_m31_add(r2227, r2228);
    unsigned r2230 = stwo_m31_mul(r2114, r2119);
    unsigned r2231 = stwo_m31_add(r2229, r2230);
    unsigned r2232 = stwo_m31_sub(r2231, r2018);
    unsigned r2233 = stwo_m31_sub(r2232, r2103);
    unsigned r2234 = stwo_m31_add(r2038, r2233);
    unsigned r2235 = stwo_m31_mul(r2113, r2121);
    unsigned r2236 = stwo_m31_mul(r2114, r2120);
    unsigned r2237 = stwo_m31_add(r2235, r2236);
    unsigned r2238 = stwo_m31_sub(r2237, r2021);
    unsigned r2239 = stwo_m31_sub(r2238, r2106);
    unsigned r2240 = stwo_m31_add(r2047, r2239);
    unsigned r2241 = stwo_m31_mul(r2114, r2121);
    unsigned r2242 = stwo_m31_sub(r2241, r2022);
    unsigned r2243 = stwo_m31_sub(r2242, r2107);
    unsigned r2244 = stwo_m31_add(r2058, r2243);
    unsigned r2245 = stwo_m31_add(r140, r205);
    out_cols[10u][row] = r140;
    sub_words[0u * row_count + row] = r140;
    lookup_words[134u * row_count + row] = r140;
    sub_words[78u * row_count + row] = r205;
    lookup_words[251u * row_count + row] = r205;
    unsigned r2246 = stwo_m31_add(r142, r165);
    out_cols[11u][row] = r142;
    out_cols[20u][row] = r165;
    sub_words[1u * row_count + row] = r142;
    lookup_words[135u * row_count + row] = r142;
    sub_words[79u * row_count + row] = r165;
    lookup_words[252u * row_count + row] = r165;
    unsigned r2247 = stwo_m31_add(r189, r167);
    out_cols[21u][row] = r167;
    sub_words[12u * row_count + row] = r189;
    lookup_words[152u * row_count + row] = r189;
    sub_words[2u * row_count + row] = r167;
    lookup_words[137u * row_count + row] = r167;
    unsigned r2248 = stwo_m31_add(r145, r209);
    out_cols[12u][row] = r145;
    sub_words[13u * row_count + row] = r145;
    lookup_words[153u * row_count + row] = r145;
    sub_words[3u * row_count + row] = r209;
    lookup_words[138u * row_count + row] = r209;
    unsigned r2249 = stwo_m31_add(r147, r170);
    out_cols[13u][row] = r147;
    out_cols[22u][row] = r170;
    sub_words[24u * row_count + row] = r147;
    lookup_words[170u * row_count + row] = r147;
    sub_words[14u * row_count + row] = r170;
    lookup_words[155u * row_count + row] = r170;
    unsigned r2250 = stwo_m31_add(r193, r172);
    out_cols[23u][row] = r172;
    sub_words[25u * row_count + row] = r193;
    lookup_words[171u * row_count + row] = r193;
    sub_words[15u * row_count + row] = r172;
    lookup_words[156u * row_count + row] = r172;
    unsigned r2251 = stwo_m31_add(r150, r213);
    out_cols[14u][row] = r150;
    sub_words[36u * row_count + row] = r150;
    lookup_words[188u * row_count + row] = r150;
    sub_words[26u * row_count + row] = r213;
    lookup_words[173u * row_count + row] = r213;
    unsigned r2252 = stwo_m31_add(r152, r175);
    out_cols[15u][row] = r152;
    out_cols[24u][row] = r175;
    sub_words[37u * row_count + row] = r152;
    lookup_words[189u * row_count + row] = r152;
    sub_words[27u * row_count + row] = r175;
    lookup_words[174u * row_count + row] = r175;
    unsigned r2253 = stwo_m31_add(r197, r177);
    out_cols[25u][row] = r177;
    sub_words[48u * row_count + row] = r197;
    lookup_words[206u * row_count + row] = r197;
    sub_words[38u * row_count + row] = r177;
    lookup_words[191u * row_count + row] = r177;
    unsigned r2254 = stwo_m31_add(r155, r217);
    out_cols[16u][row] = r155;
    sub_words[49u * row_count + row] = r155;
    lookup_words[207u * row_count + row] = r155;
    sub_words[39u * row_count + row] = r217;
    lookup_words[192u * row_count + row] = r217;
    unsigned r2255 = stwo_m31_add(r157, r180);
    out_cols[17u][row] = r157;
    out_cols[26u][row] = r180;
    sub_words[60u * row_count + row] = r157;
    lookup_words[224u * row_count + row] = r157;
    sub_words[50u * row_count + row] = r180;
    lookup_words[209u * row_count + row] = r180;
    unsigned r2256 = stwo_m31_add(r201, r182);
    out_cols[27u][row] = r182;
    sub_words[61u * row_count + row] = r201;
    lookup_words[225u * row_count + row] = r201;
    sub_words[51u * row_count + row] = r182;
    lookup_words[210u * row_count + row] = r182;
    unsigned r2257 = stwo_m31_add(r160, r221);
    out_cols[18u][row] = r160;
    sub_words[72u * row_count + row] = r160;
    lookup_words[242u * row_count + row] = r160;
    sub_words[62u * row_count + row] = r221;
    lookup_words[227u * row_count + row] = r221;
    unsigned r2258 = stwo_m31_add(r162, r129);
    out_cols[9u][row] = r129;
    out_cols[19u][row] = r162;
    sub_words[73u * row_count + row] = r162;
    lookup_words[243u * row_count + row] = r162;
    sub_words[63u * row_count + row] = r129;
    lookup_words[228u * row_count + row] = r129;
    lookup_words[10u * row_count + row] = r129;
    unsigned r2259 = stwo_m31_add(r222, r236);
    out_cols[28u][row] = r222;
    out_cols[42u][row] = r236;
    sub_words[4u * row_count + row] = r222;
    lookup_words[140u * row_count + row] = r222;
    sub_words[80u * row_count + row] = r236;
    lookup_words[254u * row_count + row] = r236;
    unsigned r2260 = stwo_m31_add(r223, r237);
    out_cols[29u][row] = r223;
    out_cols[43u][row] = r237;
    sub_words[5u * row_count + row] = r223;
    lookup_words[141u * row_count + row] = r223;
    sub_words[81u * row_count + row] = r237;
    lookup_words[255u * row_count + row] = r237;
    unsigned r2261 = stwo_m31_add(r224, r238);
    out_cols[30u][row] = r224;
    out_cols[44u][row] = r238;
    sub_words[16u * row_count + row] = r224;
    lookup_words[158u * row_count + row] = r224;
    sub_words[6u * row_count + row] = r238;
    lookup_words[143u * row_count + row] = r238;
    unsigned r2262 = stwo_m31_add(r225, r239);
    out_cols[31u][row] = r225;
    out_cols[45u][row] = r239;
    sub_words[17u * row_count + row] = r225;
    lookup_words[159u * row_count + row] = r225;
    sub_words[7u * row_count + row] = r239;
    lookup_words[144u * row_count + row] = r239;
    unsigned r2263 = stwo_m31_add(r226, r240);
    out_cols[32u][row] = r226;
    out_cols[46u][row] = r240;
    sub_words[28u * row_count + row] = r226;
    lookup_words[176u * row_count + row] = r226;
    sub_words[18u * row_count + row] = r240;
    lookup_words[161u * row_count + row] = r240;
    unsigned r2264 = stwo_m31_add(r227, r241);
    out_cols[33u][row] = r227;
    out_cols[47u][row] = r241;
    sub_words[29u * row_count + row] = r227;
    lookup_words[177u * row_count + row] = r227;
    sub_words[19u * row_count + row] = r241;
    lookup_words[162u * row_count + row] = r241;
    unsigned r2265 = stwo_m31_add(r228, r242);
    out_cols[34u][row] = r228;
    out_cols[48u][row] = r242;
    sub_words[40u * row_count + row] = r228;
    lookup_words[194u * row_count + row] = r228;
    sub_words[30u * row_count + row] = r242;
    lookup_words[179u * row_count + row] = r242;
    unsigned r2266 = stwo_m31_add(r229, r243);
    out_cols[35u][row] = r229;
    out_cols[49u][row] = r243;
    sub_words[41u * row_count + row] = r229;
    lookup_words[195u * row_count + row] = r229;
    sub_words[31u * row_count + row] = r243;
    lookup_words[180u * row_count + row] = r243;
    unsigned r2267 = stwo_m31_add(r230, r244);
    out_cols[36u][row] = r230;
    out_cols[50u][row] = r244;
    sub_words[52u * row_count + row] = r230;
    lookup_words[212u * row_count + row] = r230;
    sub_words[42u * row_count + row] = r244;
    lookup_words[197u * row_count + row] = r244;
    unsigned r2268 = stwo_m31_add(r231, r245);
    out_cols[37u][row] = r231;
    out_cols[51u][row] = r245;
    sub_words[53u * row_count + row] = r231;
    lookup_words[213u * row_count + row] = r231;
    sub_words[43u * row_count + row] = r245;
    lookup_words[198u * row_count + row] = r245;
    unsigned r2269 = stwo_m31_add(r232, r246);
    out_cols[38u][row] = r232;
    out_cols[52u][row] = r246;
    sub_words[64u * row_count + row] = r232;
    lookup_words[230u * row_count + row] = r232;
    sub_words[54u * row_count + row] = r246;
    lookup_words[215u * row_count + row] = r246;
    unsigned r2270 = stwo_m31_add(r233, r247);
    out_cols[39u][row] = r233;
    out_cols[53u][row] = r247;
    sub_words[65u * row_count + row] = r233;
    lookup_words[231u * row_count + row] = r233;
    sub_words[55u * row_count + row] = r247;
    lookup_words[216u * row_count + row] = r247;
    unsigned r2271 = stwo_m31_add(r234, r248);
    out_cols[40u][row] = r234;
    out_cols[54u][row] = r248;
    sub_words[74u * row_count + row] = r234;
    lookup_words[245u * row_count + row] = r234;
    sub_words[66u * row_count + row] = r248;
    lookup_words[233u * row_count + row] = r248;
    unsigned r2272 = stwo_m31_add(r235, r249);
    out_cols[41u][row] = r235;
    out_cols[55u][row] = r249;
    sub_words[75u * row_count + row] = r235;
    lookup_words[246u * row_count + row] = r235;
    sub_words[67u * row_count + row] = r249;
    lookup_words[234u * row_count + row] = r249;
    unsigned r2273 = stwo_m31_mul(r2245, r2259);
    unsigned r2274 = stwo_m31_mul(r2245, r2260);
    unsigned r2275 = stwo_m31_mul(r2246, r2259);
    unsigned r2276 = stwo_m31_add(r2274, r2275);
    unsigned r2277 = stwo_m31_mul(r2245, r2261);
    unsigned r2278 = stwo_m31_mul(r2246, r2260);
    unsigned r2279 = stwo_m31_add(r2277, r2278);
    unsigned r2280 = stwo_m31_mul(r2247, r2259);
    unsigned r2281 = stwo_m31_add(r2279, r2280);
    unsigned r2282 = stwo_m31_mul(r2245, r2262);
    unsigned r2283 = stwo_m31_mul(r2246, r2261);
    unsigned r2284 = stwo_m31_add(r2282, r2283);
    unsigned r2285 = stwo_m31_mul(r2247, r2260);
    unsigned r2286 = stwo_m31_add(r2284, r2285);
    unsigned r2287 = stwo_m31_mul(r2248, r2259);
    unsigned r2288 = stwo_m31_add(r2286, r2287);
    unsigned r2289 = stwo_m31_mul(r2245, r2263);
    unsigned r2290 = stwo_m31_mul(r2246, r2262);
    unsigned r2291 = stwo_m31_add(r2289, r2290);
    unsigned r2292 = stwo_m31_mul(r2247, r2261);
    unsigned r2293 = stwo_m31_add(r2291, r2292);
    unsigned r2294 = stwo_m31_mul(r2248, r2260);
    unsigned r2295 = stwo_m31_add(r2293, r2294);
    unsigned r2296 = stwo_m31_mul(r2249, r2259);
    unsigned r2297 = stwo_m31_add(r2295, r2296);
    unsigned r2298 = stwo_m31_mul(r2245, r2264);
    unsigned r2299 = stwo_m31_mul(r2246, r2263);
    unsigned r2300 = stwo_m31_add(r2298, r2299);
    unsigned r2301 = stwo_m31_mul(r2247, r2262);
    unsigned r2302 = stwo_m31_add(r2300, r2301);
    unsigned r2303 = stwo_m31_mul(r2248, r2261);
    unsigned r2304 = stwo_m31_add(r2302, r2303);
    unsigned r2305 = stwo_m31_mul(r2249, r2260);
    unsigned r2306 = stwo_m31_add(r2304, r2305);
    unsigned r2307 = stwo_m31_mul(r2250, r2259);
    unsigned r2308 = stwo_m31_add(r2306, r2307);
    unsigned r2309 = stwo_m31_mul(r2245, r2265);
    unsigned r2310 = stwo_m31_mul(r2246, r2264);
    unsigned r2311 = stwo_m31_add(r2309, r2310);
    unsigned r2312 = stwo_m31_mul(r2247, r2263);
    unsigned r2313 = stwo_m31_add(r2311, r2312);
    unsigned r2314 = stwo_m31_mul(r2248, r2262);
    unsigned r2315 = stwo_m31_add(r2313, r2314);
    unsigned r2316 = stwo_m31_mul(r2249, r2261);
    unsigned r2317 = stwo_m31_add(r2315, r2316);
    unsigned r2318 = stwo_m31_mul(r2250, r2260);
    unsigned r2319 = stwo_m31_add(r2317, r2318);
    unsigned r2320 = stwo_m31_mul(r2251, r2259);
    unsigned r2321 = stwo_m31_add(r2319, r2320);
    unsigned r2322 = stwo_m31_mul(r2246, r2265);
    unsigned r2323 = stwo_m31_mul(r2247, r2264);
    unsigned r2324 = stwo_m31_add(r2322, r2323);
    unsigned r2325 = stwo_m31_mul(r2248, r2263);
    unsigned r2326 = stwo_m31_add(r2324, r2325);
    unsigned r2327 = stwo_m31_mul(r2249, r2262);
    unsigned r2328 = stwo_m31_add(r2326, r2327);
    unsigned r2329 = stwo_m31_mul(r2250, r2261);
    unsigned r2330 = stwo_m31_add(r2328, r2329);
    unsigned r2331 = stwo_m31_mul(r2251, r2260);
    unsigned r2332 = stwo_m31_add(r2330, r2331);
    unsigned r2333 = stwo_m31_mul(r2247, r2265);
    unsigned r2334 = stwo_m31_mul(r2248, r2264);
    unsigned r2335 = stwo_m31_add(r2333, r2334);
    unsigned r2336 = stwo_m31_mul(r2249, r2263);
    unsigned r2337 = stwo_m31_add(r2335, r2336);
    unsigned r2338 = stwo_m31_mul(r2250, r2262);
    unsigned r2339 = stwo_m31_add(r2337, r2338);
    unsigned r2340 = stwo_m31_mul(r2251, r2261);
    unsigned r2341 = stwo_m31_add(r2339, r2340);
    unsigned r2342 = stwo_m31_mul(r2248, r2265);
    unsigned r2343 = stwo_m31_mul(r2249, r2264);
    unsigned r2344 = stwo_m31_add(r2342, r2343);
    unsigned r2345 = stwo_m31_mul(r2250, r2263);
    unsigned r2346 = stwo_m31_add(r2344, r2345);
    unsigned r2347 = stwo_m31_mul(r2251, r2262);
    unsigned r2348 = stwo_m31_add(r2346, r2347);
    unsigned r2349 = stwo_m31_mul(r2249, r2265);
    unsigned r2350 = stwo_m31_mul(r2250, r2264);
    unsigned r2351 = stwo_m31_add(r2349, r2350);
    unsigned r2352 = stwo_m31_mul(r2251, r2263);
    unsigned r2353 = stwo_m31_add(r2351, r2352);
    unsigned r2354 = stwo_m31_mul(r2250, r2265);
    unsigned r2355 = stwo_m31_mul(r2251, r2264);
    unsigned r2356 = stwo_m31_add(r2354, r2355);
    unsigned r2357 = stwo_m31_mul(r2251, r2265);
    unsigned r2358 = stwo_m31_mul(r2252, r2266);
    unsigned r2359 = stwo_m31_mul(r2252, r2267);
    unsigned r2360 = stwo_m31_mul(r2253, r2266);
    unsigned r2361 = stwo_m31_add(r2359, r2360);
    unsigned r2362 = stwo_m31_mul(r2252, r2268);
    unsigned r2363 = stwo_m31_mul(r2253, r2267);
    unsigned r2364 = stwo_m31_add(r2362, r2363);
    unsigned r2365 = stwo_m31_mul(r2254, r2266);
    unsigned r2366 = stwo_m31_add(r2364, r2365);
    unsigned r2367 = stwo_m31_mul(r2252, r2269);
    unsigned r2368 = stwo_m31_mul(r2253, r2268);
    unsigned r2369 = stwo_m31_add(r2367, r2368);
    unsigned r2370 = stwo_m31_mul(r2254, r2267);
    unsigned r2371 = stwo_m31_add(r2369, r2370);
    unsigned r2372 = stwo_m31_mul(r2255, r2266);
    unsigned r2373 = stwo_m31_add(r2371, r2372);
    unsigned r2374 = stwo_m31_mul(r2252, r2270);
    unsigned r2375 = stwo_m31_mul(r2253, r2269);
    unsigned r2376 = stwo_m31_add(r2374, r2375);
    unsigned r2377 = stwo_m31_mul(r2254, r2268);
    unsigned r2378 = stwo_m31_add(r2376, r2377);
    unsigned r2379 = stwo_m31_mul(r2255, r2267);
    unsigned r2380 = stwo_m31_add(r2378, r2379);
    unsigned r2381 = stwo_m31_mul(r2256, r2266);
    unsigned r2382 = stwo_m31_add(r2380, r2381);
    unsigned r2383 = stwo_m31_mul(r2252, r2271);
    unsigned r2384 = stwo_m31_mul(r2253, r2270);
    unsigned r2385 = stwo_m31_add(r2383, r2384);
    unsigned r2386 = stwo_m31_mul(r2254, r2269);
    unsigned r2387 = stwo_m31_add(r2385, r2386);
    unsigned r2388 = stwo_m31_mul(r2255, r2268);
    unsigned r2389 = stwo_m31_add(r2387, r2388);
    unsigned r2390 = stwo_m31_mul(r2256, r2267);
    unsigned r2391 = stwo_m31_add(r2389, r2390);
    unsigned r2392 = stwo_m31_mul(r2257, r2266);
    unsigned r2393 = stwo_m31_add(r2391, r2392);
    unsigned r2394 = stwo_m31_mul(r2252, r2272);
    unsigned r2395 = stwo_m31_mul(r2253, r2271);
    unsigned r2396 = stwo_m31_add(r2394, r2395);
    unsigned r2397 = stwo_m31_mul(r2254, r2270);
    unsigned r2398 = stwo_m31_add(r2396, r2397);
    unsigned r2399 = stwo_m31_mul(r2255, r2269);
    unsigned r2400 = stwo_m31_add(r2398, r2399);
    unsigned r2401 = stwo_m31_mul(r2256, r2268);
    unsigned r2402 = stwo_m31_add(r2400, r2401);
    unsigned r2403 = stwo_m31_mul(r2257, r2267);
    unsigned r2404 = stwo_m31_add(r2402, r2403);
    unsigned r2405 = stwo_m31_mul(r2258, r2266);
    unsigned r2406 = stwo_m31_add(r2404, r2405);
    unsigned r2407 = stwo_m31_mul(r2253, r2272);
    unsigned r2408 = stwo_m31_mul(r2254, r2271);
    unsigned r2409 = stwo_m31_add(r2407, r2408);
    unsigned r2410 = stwo_m31_mul(r2255, r2270);
    unsigned r2411 = stwo_m31_add(r2409, r2410);
    unsigned r2412 = stwo_m31_mul(r2256, r2269);
    unsigned r2413 = stwo_m31_add(r2411, r2412);
    unsigned r2414 = stwo_m31_mul(r2257, r2268);
    unsigned r2415 = stwo_m31_add(r2413, r2414);
    unsigned r2416 = stwo_m31_mul(r2258, r2267);
    unsigned r2417 = stwo_m31_add(r2415, r2416);
    unsigned r2418 = stwo_m31_mul(r2254, r2272);
    unsigned r2419 = stwo_m31_mul(r2255, r2271);
    unsigned r2420 = stwo_m31_add(r2418, r2419);
    unsigned r2421 = stwo_m31_mul(r2256, r2270);
    unsigned r2422 = stwo_m31_add(r2420, r2421);
    unsigned r2423 = stwo_m31_mul(r2257, r2269);
    unsigned r2424 = stwo_m31_add(r2422, r2423);
    unsigned r2425 = stwo_m31_mul(r2258, r2268);
    unsigned r2426 = stwo_m31_add(r2424, r2425);
    unsigned r2427 = stwo_m31_mul(r2255, r2272);
    unsigned r2428 = stwo_m31_mul(r2256, r2271);
    unsigned r2429 = stwo_m31_add(r2427, r2428);
    unsigned r2430 = stwo_m31_mul(r2257, r2270);
    unsigned r2431 = stwo_m31_add(r2429, r2430);
    unsigned r2432 = stwo_m31_mul(r2258, r2269);
    unsigned r2433 = stwo_m31_add(r2431, r2432);
    unsigned r2434 = stwo_m31_mul(r2256, r2272);
    unsigned r2435 = stwo_m31_mul(r2257, r2271);
    unsigned r2436 = stwo_m31_add(r2434, r2435);
    unsigned r2437 = stwo_m31_mul(r2258, r2270);
    unsigned r2438 = stwo_m31_add(r2436, r2437);
    unsigned r2439 = stwo_m31_mul(r2257, r2272);
    unsigned r2440 = stwo_m31_mul(r2258, r2271);
    unsigned r2441 = stwo_m31_add(r2439, r2440);
    unsigned r2442 = stwo_m31_mul(r2258, r2272);
    unsigned r2443 = stwo_m31_add(r2245, r2252);
    unsigned r2444 = stwo_m31_add(r2246, r2253);
    unsigned r2445 = stwo_m31_add(r2247, r2254);
    unsigned r2446 = stwo_m31_add(r2248, r2255);
    unsigned r2447 = stwo_m31_add(r2249, r2256);
    unsigned r2448 = stwo_m31_add(r2250, r2257);
    unsigned r2449 = stwo_m31_add(r2251, r2258);
    unsigned r2450 = stwo_m31_add(r2259, r2266);
    unsigned r2451 = stwo_m31_add(r2260, r2267);
    unsigned r2452 = stwo_m31_add(r2261, r2268);
    unsigned r2453 = stwo_m31_add(r2262, r2269);
    unsigned r2454 = stwo_m31_add(r2263, r2270);
    unsigned r2455 = stwo_m31_add(r2264, r2271);
    unsigned r2456 = stwo_m31_add(r2265, r2272);
    unsigned r2457 = stwo_m31_mul(r2443, r2450);
    unsigned r2458 = stwo_m31_sub(r2457, r2273);
    unsigned r2459 = stwo_m31_sub(r2458, r2358);
    unsigned r2460 = stwo_m31_add(r2332, r2459);
    unsigned r2461 = stwo_m31_mul(r2443, r2451);
    unsigned r2462 = stwo_m31_mul(r2444, r2450);
    unsigned r2463 = stwo_m31_add(r2461, r2462);
    unsigned r2464 = stwo_m31_sub(r2463, r2276);
    unsigned r2465 = stwo_m31_sub(r2464, r2361);
    unsigned r2466 = stwo_m31_add(r2341, r2465);
    unsigned r2467 = stwo_m31_mul(r2443, r2452);
    unsigned r2468 = stwo_m31_mul(r2444, r2451);
    unsigned r2469 = stwo_m31_add(r2467, r2468);
    unsigned r2470 = stwo_m31_mul(r2445, r2450);
    unsigned r2471 = stwo_m31_add(r2469, r2470);
    unsigned r2472 = stwo_m31_sub(r2471, r2281);
    unsigned r2473 = stwo_m31_sub(r2472, r2366);
    unsigned r2474 = stwo_m31_add(r2348, r2473);
    unsigned r2475 = stwo_m31_mul(r2443, r2453);
    unsigned r2476 = stwo_m31_mul(r2444, r2452);
    unsigned r2477 = stwo_m31_add(r2475, r2476);
    unsigned r2478 = stwo_m31_mul(r2445, r2451);
    unsigned r2479 = stwo_m31_add(r2477, r2478);
    unsigned r2480 = stwo_m31_mul(r2446, r2450);
    unsigned r2481 = stwo_m31_add(r2479, r2480);
    unsigned r2482 = stwo_m31_sub(r2481, r2288);
    unsigned r2483 = stwo_m31_sub(r2482, r2373);
    unsigned r2484 = stwo_m31_add(r2353, r2483);
    unsigned r2485 = stwo_m31_mul(r2443, r2454);
    unsigned r2486 = stwo_m31_mul(r2444, r2453);
    unsigned r2487 = stwo_m31_add(r2485, r2486);
    unsigned r2488 = stwo_m31_mul(r2445, r2452);
    unsigned r2489 = stwo_m31_add(r2487, r2488);
    unsigned r2490 = stwo_m31_mul(r2446, r2451);
    unsigned r2491 = stwo_m31_add(r2489, r2490);
    unsigned r2492 = stwo_m31_mul(r2447, r2450);
    unsigned r2493 = stwo_m31_add(r2491, r2492);
    unsigned r2494 = stwo_m31_sub(r2493, r2297);
    unsigned r2495 = stwo_m31_sub(r2494, r2382);
    unsigned r2496 = stwo_m31_add(r2356, r2495);
    unsigned r2497 = stwo_m31_mul(r2443, r2455);
    unsigned r2498 = stwo_m31_mul(r2444, r2454);
    unsigned r2499 = stwo_m31_add(r2497, r2498);
    unsigned r2500 = stwo_m31_mul(r2445, r2453);
    unsigned r2501 = stwo_m31_add(r2499, r2500);
    unsigned r2502 = stwo_m31_mul(r2446, r2452);
    unsigned r2503 = stwo_m31_add(r2501, r2502);
    unsigned r2504 = stwo_m31_mul(r2447, r2451);
    unsigned r2505 = stwo_m31_add(r2503, r2504);
    unsigned r2506 = stwo_m31_mul(r2448, r2450);
    unsigned r2507 = stwo_m31_add(r2505, r2506);
    unsigned r2508 = stwo_m31_sub(r2507, r2308);
    unsigned r2509 = stwo_m31_sub(r2508, r2393);
    unsigned r2510 = stwo_m31_add(r2357, r2509);
    unsigned r2511 = stwo_m31_mul(r2443, r2456);
    unsigned r2512 = stwo_m31_mul(r2444, r2455);
    unsigned r2513 = stwo_m31_add(r2511, r2512);
    unsigned r2514 = stwo_m31_mul(r2445, r2454);
    unsigned r2515 = stwo_m31_add(r2513, r2514);
    unsigned r2516 = stwo_m31_mul(r2446, r2453);
    unsigned r2517 = stwo_m31_add(r2515, r2516);
    unsigned r2518 = stwo_m31_mul(r2447, r2452);
    unsigned r2519 = stwo_m31_add(r2517, r2518);
    unsigned r2520 = stwo_m31_mul(r2448, r2451);
    unsigned r2521 = stwo_m31_add(r2519, r2520);
    unsigned r2522 = stwo_m31_mul(r2449, r2450);
    unsigned r2523 = stwo_m31_add(r2521, r2522);
    unsigned r2524 = stwo_m31_sub(r2523, r2321);
    unsigned r2525 = stwo_m31_sub(r2524, r2406);
    unsigned r2526 = stwo_m31_mul(r2444, r2456);
    unsigned r2527 = stwo_m31_mul(r2445, r2455);
    unsigned r2528 = stwo_m31_add(r2526, r2527);
    unsigned r2529 = stwo_m31_mul(r2446, r2454);
    unsigned r2530 = stwo_m31_add(r2528, r2529);
    unsigned r2531 = stwo_m31_mul(r2447, r2453);
    unsigned r2532 = stwo_m31_add(r2530, r2531);
    unsigned r2533 = stwo_m31_mul(r2448, r2452);
    unsigned r2534 = stwo_m31_add(r2532, r2533);
    unsigned r2535 = stwo_m31_mul(r2449, r2451);
    unsigned r2536 = stwo_m31_add(r2534, r2535);
    unsigned r2537 = stwo_m31_sub(r2536, r2332);
    unsigned r2538 = stwo_m31_sub(r2537, r2417);
    unsigned r2539 = stwo_m31_add(r2358, r2538);
    unsigned r2540 = stwo_m31_mul(r2445, r2456);
    unsigned r2541 = stwo_m31_mul(r2446, r2455);
    unsigned r2542 = stwo_m31_add(r2540, r2541);
    unsigned r2543 = stwo_m31_mul(r2447, r2454);
    unsigned r2544 = stwo_m31_add(r2542, r2543);
    unsigned r2545 = stwo_m31_mul(r2448, r2453);
    unsigned r2546 = stwo_m31_add(r2544, r2545);
    unsigned r2547 = stwo_m31_mul(r2449, r2452);
    unsigned r2548 = stwo_m31_add(r2546, r2547);
    unsigned r2549 = stwo_m31_sub(r2548, r2341);
    unsigned r2550 = stwo_m31_sub(r2549, r2426);
    unsigned r2551 = stwo_m31_add(r2361, r2550);
    unsigned r2552 = stwo_m31_mul(r2446, r2456);
    unsigned r2553 = stwo_m31_mul(r2447, r2455);
    unsigned r2554 = stwo_m31_add(r2552, r2553);
    unsigned r2555 = stwo_m31_mul(r2448, r2454);
    unsigned r2556 = stwo_m31_add(r2554, r2555);
    unsigned r2557 = stwo_m31_mul(r2449, r2453);
    unsigned r2558 = stwo_m31_add(r2556, r2557);
    unsigned r2559 = stwo_m31_sub(r2558, r2348);
    unsigned r2560 = stwo_m31_sub(r2559, r2433);
    unsigned r2561 = stwo_m31_add(r2366, r2560);
    unsigned r2562 = stwo_m31_mul(r2447, r2456);
    unsigned r2563 = stwo_m31_mul(r2448, r2455);
    unsigned r2564 = stwo_m31_add(r2562, r2563);
    unsigned r2565 = stwo_m31_mul(r2449, r2454);
    unsigned r2566 = stwo_m31_add(r2564, r2565);
    unsigned r2567 = stwo_m31_sub(r2566, r2353);
    unsigned r2568 = stwo_m31_sub(r2567, r2438);
    unsigned r2569 = stwo_m31_add(r2373, r2568);
    unsigned r2570 = stwo_m31_mul(r2448, r2456);
    unsigned r2571 = stwo_m31_mul(r2449, r2455);
    unsigned r2572 = stwo_m31_add(r2570, r2571);
    unsigned r2573 = stwo_m31_sub(r2572, r2356);
    unsigned r2574 = stwo_m31_sub(r2573, r2441);
    unsigned r2575 = stwo_m31_add(r2382, r2574);
    unsigned r2576 = stwo_m31_mul(r2449, r2456);
    unsigned r2577 = stwo_m31_sub(r2576, r2357);
    unsigned r2578 = stwo_m31_sub(r2577, r2442);
    unsigned r2579 = stwo_m31_add(r2393, r2578);
    unsigned r2580 = stwo_m31_sub(r2273, r1631);
    unsigned r2581 = stwo_m31_sub(r2580, r1938);
    unsigned r2582 = stwo_m31_add(r1897, r2581);
    unsigned r2583 = stwo_m31_sub(r2276, r1634);
    unsigned r2584 = stwo_m31_sub(r2583, r1941);
    unsigned r2585 = stwo_m31_add(r1909, r2584);
    unsigned r2586 = stwo_m31_sub(r2281, r1639);
    unsigned r2587 = stwo_m31_sub(r2586, r1946);
    unsigned r2588 = stwo_m31_add(r1919, r2587);
    unsigned r2589 = stwo_m31_sub(r2288, r1646);
    unsigned r2590 = stwo_m31_sub(r2589, r1953);
    unsigned r2591 = stwo_m31_add(r1927, r2590);
    unsigned r2592 = stwo_m31_sub(r2297, r1655);
    unsigned r2593 = stwo_m31_sub(r2592, r1962);
    unsigned r2594 = stwo_m31_add(r1933, r2593);
    unsigned r2595 = stwo_m31_sub(r2308, r1666);
    unsigned r2596 = stwo_m31_sub(r2595, r1973);
    unsigned r2597 = stwo_m31_add(r1937, r2596);
    unsigned r2598 = stwo_m31_sub(r2321, r1679);
    unsigned r2599 = stwo_m31_sub(r2598, r1986);
    unsigned r2600 = stwo_m31_add(r1764, r2599);
    unsigned r2601 = stwo_m31_sub(r2460, r1818);
    unsigned r2602 = stwo_m31_sub(r2601, r2125);
    unsigned r2603 = stwo_m31_add(r1775, r2602);
    unsigned r2604 = stwo_m31_sub(r2466, r1824);
    unsigned r2605 = stwo_m31_sub(r2604, r2131);
    unsigned r2606 = stwo_m31_add(r1784, r2605);
    unsigned r2607 = stwo_m31_sub(r2474, r1832);
    unsigned r2608 = stwo_m31_sub(r2607, r2139);
    unsigned r2609 = stwo_m31_add(r1791, r2608);
    unsigned r2610 = stwo_m31_sub(r2484, r1842);
    unsigned r2611 = stwo_m31_sub(r2610, r2149);
    unsigned r2612 = stwo_m31_add(r1796, r2611);
    unsigned r2613 = stwo_m31_sub(r2496, r1854);
    unsigned r2614 = stwo_m31_sub(r2613, r2161);
    unsigned r2615 = stwo_m31_add(r1799, r2614);
    unsigned r2616 = stwo_m31_sub(r2510, r1868);
    unsigned r2617 = stwo_m31_sub(r2616, r2175);
    unsigned r2618 = stwo_m31_add(r1800, r2617);
    unsigned r2619 = stwo_m31_sub(r2525, r1883);
    unsigned r2620 = stwo_m31_sub(r2619, r2190);
    unsigned r2621 = stwo_m31_sub(r2539, r1897);
    unsigned r2622 = stwo_m31_sub(r2621, r2204);
    unsigned r2623 = stwo_m31_add(r1938, r2622);
    unsigned r2624 = stwo_m31_sub(r2551, r1909);
    unsigned r2625 = stwo_m31_sub(r2624, r2216);
    unsigned r2626 = stwo_m31_add(r1941, r2625);
    unsigned r2627 = stwo_m31_sub(r2561, r1919);
    unsigned r2628 = stwo_m31_sub(r2627, r2226);
    unsigned r2629 = stwo_m31_add(r1946, r2628);
    unsigned r2630 = stwo_m31_sub(r2569, r1927);
    unsigned r2631 = stwo_m31_sub(r2630, r2234);
    unsigned r2632 = stwo_m31_add(r1953, r2631);
    unsigned r2633 = stwo_m31_sub(r2575, r1933);
    unsigned r2634 = stwo_m31_sub(r2633, r2240);
    unsigned r2635 = stwo_m31_add(r1962, r2634);
    unsigned r2636 = stwo_m31_sub(r2579, r1937);
    unsigned r2637 = stwo_m31_sub(r2636, r2244);
    unsigned r2638 = stwo_m31_add(r1973, r2637);
    unsigned r2639 = stwo_m31_sub(r2406, r1764);
    unsigned r2640 = stwo_m31_sub(r2639, r2071);
    unsigned r2641 = stwo_m31_add(r1986, r2640);
    unsigned r2642 = stwo_m31_sub(r2417, r1775);
    unsigned r2643 = stwo_m31_sub(r2642, r2082);
    unsigned r2644 = stwo_m31_add(r2125, r2643);
    unsigned r2645 = stwo_m31_sub(r2426, r1784);
    unsigned r2646 = stwo_m31_sub(r2645, r2091);
    unsigned r2647 = stwo_m31_add(r2131, r2646);
    unsigned r2648 = stwo_m31_sub(r2433, r1791);
    unsigned r2649 = stwo_m31_sub(r2648, r2098);
    unsigned r2650 = stwo_m31_add(r2139, r2649);
    unsigned r2651 = stwo_m31_sub(r2438, r1796);
    unsigned r2652 = stwo_m31_sub(r2651, r2103);
    unsigned r2653 = stwo_m31_add(r2149, r2652);
    unsigned r2654 = stwo_m31_sub(r2441, r1799);
    unsigned r2655 = stwo_m31_sub(r2654, r2106);
    unsigned r2656 = stwo_m31_add(r2161, r2655);
    unsigned r2657 = stwo_m31_sub(r2442, r1800);
    unsigned r2658 = stwo_m31_sub(r2657, r2107);
    unsigned r2659 = stwo_m31_add(r2175, r2658);
    unsigned r2660 = stwo_m31_sub(r1631, r1603);
    unsigned r2661 = stwo_m31_sub(r1634, r1604);
    unsigned r2662 = stwo_m31_sub(r1639, r1605);
    unsigned r2663 = stwo_m31_sub(r1646, r1606);
    unsigned r2664 = stwo_m31_sub(r1655, r1607);
    unsigned r2665 = stwo_m31_sub(r1666, r1608);
    unsigned r2666 = stwo_m31_sub(r1679, r1609);
    unsigned r2667 = stwo_m31_sub(r1818, r1610);
    unsigned r2668 = stwo_m31_sub(r1824, r1611);
    unsigned r2669 = stwo_m31_sub(r1832, r1612);
    unsigned r2670 = stwo_m31_sub(r1842, r1613);
    unsigned r2671 = stwo_m31_sub(r1854, r1614);
    unsigned r2672 = stwo_m31_sub(r1868, r1615);
    unsigned r2673 = stwo_m31_sub(r1883, r1616);
    unsigned r2674 = stwo_m31_sub(r2582, r1617);
    unsigned r2675 = stwo_m31_sub(r2585, r1618);
    unsigned r2676 = stwo_m31_sub(r2588, r1619);
    unsigned r2677 = stwo_m31_sub(r2591, r1620);
    unsigned r2678 = stwo_m31_sub(r2594, r1621);
    unsigned r2679 = stwo_m31_sub(r2597, r1622);
    unsigned r2680 = stwo_m31_sub(r2600, r1623);
    unsigned r2681 = stwo_m31_sub(r2603, r1624);
    unsigned r2682 = stwo_m31_sub(r2606, r1625);
    unsigned r2683 = stwo_m31_sub(r2609, r1626);
    unsigned r2684 = stwo_m31_sub(r2612, r1627);
    unsigned r2685 = stwo_m31_sub(r2615, r1628);
    unsigned r2686 = stwo_m31_sub(r2618, r1629);
    unsigned r2687 = stwo_m31_sub(r2620, r1630);
    out_cols[111u][row] = r1630;
    sub_words[71u * row_count + row] = r1630;
    lookup_words[240u * row_count + row] = r1630;
    lookup_words[20u * row_count + row] = r1630;
    unsigned r2688 = stwo_m31_mul(r3, r2660);
    unsigned r2689 = stwo_m31_mul(r1, r2681);
    unsigned r2690 = stwo_m31_sub(r2688, r2689);
    unsigned r2691 = stwo_m31_mul(r2, r2082);
    unsigned r2692 = stwo_m31_add(r2690, r2691);
    unsigned r2693 = stwo_m31_mul(r3, r2661);
    unsigned r2694 = stwo_m31_add(r2660, r2693);
    unsigned r2695 = stwo_m31_mul(r1, r2682);
    unsigned r2696 = stwo_m31_sub(r2694, r2695);
    unsigned r2697 = stwo_m31_mul(r2, r2091);
    unsigned r2698 = stwo_m31_add(r2696, r2697);
    unsigned r2699 = stwo_m31_mul(r3, r2662);
    unsigned r2700 = stwo_m31_add(r2661, r2699);
    unsigned r2701 = stwo_m31_mul(r1, r2683);
    unsigned r2702 = stwo_m31_sub(r2700, r2701);
    unsigned r2703 = stwo_m31_mul(r2, r2098);
    unsigned r2704 = stwo_m31_add(r2702, r2703);
    unsigned r2705 = stwo_m31_mul(r3, r2663);
    unsigned r2706 = stwo_m31_add(r2662, r2705);
    unsigned r2707 = stwo_m31_mul(r1, r2684);
    unsigned r2708 = stwo_m31_sub(r2706, r2707);
    unsigned r2709 = stwo_m31_mul(r2, r2103);
    unsigned r2710 = stwo_m31_add(r2708, r2709);
    unsigned r2711 = stwo_m31_mul(r3, r2664);
    unsigned r2712 = stwo_m31_add(r2663, r2711);
    unsigned r2713 = stwo_m31_mul(r1, r2685);
    unsigned r2714 = stwo_m31_sub(r2712, r2713);
    unsigned r2715 = stwo_m31_mul(r2, r2106);
    unsigned r2716 = stwo_m31_add(r2714, r2715);
    unsigned r2717 = stwo_m31_mul(r3, r2665);
    unsigned r2718 = stwo_m31_add(r2664, r2717);
    unsigned r2719 = stwo_m31_mul(r1, r2686);
    unsigned r2720 = stwo_m31_sub(r2718, r2719);
    unsigned r2721 = stwo_m31_mul(r2, r2107);
    unsigned r2722 = stwo_m31_add(r2720, r2721);
    unsigned r2723 = stwo_m31_mul(r3, r2666);
    unsigned r2724 = stwo_m31_add(r2665, r2723);
    unsigned r2725 = stwo_m31_mul(r1, r2687);
    unsigned r2726 = stwo_m31_sub(r2724, r2725);
    unsigned r2727 = stwo_m31_mul(r0, r2660);
    unsigned r2728 = stwo_m31_add(r2727, r2666);
    unsigned r2729 = stwo_m31_mul(r3, r2667);
    unsigned r2730 = stwo_m31_add(r2728, r2729);
    unsigned r2731 = stwo_m31_mul(r1, r2623);
    unsigned r2732 = stwo_m31_sub(r2730, r2731);
    unsigned r2733 = stwo_m31_mul(r0, r2661);
    unsigned r2734 = stwo_m31_add(r2733, r2667);
    unsigned r2735 = stwo_m31_mul(r3, r2668);
    unsigned r2736 = stwo_m31_add(r2734, r2735);
    unsigned r2737 = stwo_m31_mul(r1, r2626);
    unsigned r2738 = stwo_m31_sub(r2736, r2737);
    unsigned r2739 = stwo_m31_mul(r0, r2662);
    unsigned r2740 = stwo_m31_add(r2739, r2668);
    unsigned r2741 = stwo_m31_mul(r3, r2669);
    unsigned r2742 = stwo_m31_add(r2740, r2741);
    unsigned r2743 = stwo_m31_mul(r1, r2629);
    unsigned r2744 = stwo_m31_sub(r2742, r2743);
    unsigned r2745 = stwo_m31_mul(r0, r2663);
    unsigned r2746 = stwo_m31_add(r2745, r2669);
    unsigned r2747 = stwo_m31_mul(r3, r2670);
    unsigned r2748 = stwo_m31_add(r2746, r2747);
    unsigned r2749 = stwo_m31_mul(r1, r2632);
    unsigned r2750 = stwo_m31_sub(r2748, r2749);
    unsigned r2751 = stwo_m31_mul(r0, r2664);
    unsigned r2752 = stwo_m31_add(r2751, r2670);
    unsigned r2753 = stwo_m31_mul(r3, r2671);
    unsigned r2754 = stwo_m31_add(r2752, r2753);
    unsigned r2755 = stwo_m31_mul(r1, r2635);
    unsigned r2756 = stwo_m31_sub(r2754, r2755);
    unsigned r2757 = stwo_m31_mul(r0, r2665);
    unsigned r2758 = stwo_m31_add(r2757, r2671);
    unsigned r2759 = stwo_m31_mul(r3, r2672);
    unsigned r2760 = stwo_m31_add(r2758, r2759);
    unsigned r2761 = stwo_m31_mul(r1, r2638);
    unsigned r2762 = stwo_m31_sub(r2760, r2761);
    unsigned r2763 = stwo_m31_mul(r0, r2666);
    unsigned r2764 = stwo_m31_add(r2763, r2672);
    unsigned r2765 = stwo_m31_mul(r3, r2673);
    unsigned r2766 = stwo_m31_add(r2764, r2765);
    unsigned r2767 = stwo_m31_mul(r1, r2641);
    unsigned r2768 = stwo_m31_sub(r2766, r2767);
    unsigned r2769 = stwo_m31_mul(r0, r2667);
    unsigned r2770 = stwo_m31_add(r2769, r2673);
    unsigned r2771 = stwo_m31_mul(r3, r2674);
    unsigned r2772 = stwo_m31_add(r2770, r2771);
    unsigned r2773 = stwo_m31_mul(r1, r2644);
    unsigned r2774 = stwo_m31_sub(r2772, r2773);
    unsigned r2775 = stwo_m31_mul(r0, r2668);
    unsigned r2776 = stwo_m31_add(r2775, r2674);
    unsigned r2777 = stwo_m31_mul(r3, r2675);
    unsigned r2778 = stwo_m31_add(r2776, r2777);
    unsigned r2779 = stwo_m31_mul(r1, r2647);
    unsigned r2780 = stwo_m31_sub(r2778, r2779);
    unsigned r2781 = stwo_m31_mul(r0, r2669);
    unsigned r2782 = stwo_m31_add(r2781, r2675);
    unsigned r2783 = stwo_m31_mul(r3, r2676);
    unsigned r2784 = stwo_m31_add(r2782, r2783);
    unsigned r2785 = stwo_m31_mul(r1, r2650);
    unsigned r2786 = stwo_m31_sub(r2784, r2785);
    unsigned r2787 = stwo_m31_mul(r0, r2670);
    unsigned r2788 = stwo_m31_add(r2787, r2676);
    unsigned r2789 = stwo_m31_mul(r3, r2677);
    unsigned r2790 = stwo_m31_add(r2788, r2789);
    unsigned r2791 = stwo_m31_mul(r1, r2653);
    unsigned r2792 = stwo_m31_sub(r2790, r2791);
    unsigned r2793 = stwo_m31_mul(r0, r2671);
    unsigned r2794 = stwo_m31_add(r2793, r2677);
    unsigned r2795 = stwo_m31_mul(r3, r2678);
    unsigned r2796 = stwo_m31_add(r2794, r2795);
    unsigned r2797 = stwo_m31_mul(r1, r2656);
    unsigned r2798 = stwo_m31_sub(r2796, r2797);
    unsigned r2799 = stwo_m31_mul(r0, r2672);
    unsigned r2800 = stwo_m31_add(r2799, r2678);
    unsigned r2801 = stwo_m31_mul(r3, r2679);
    unsigned r2802 = stwo_m31_add(r2800, r2801);
    unsigned r2803 = stwo_m31_mul(r1, r2659);
    unsigned r2804 = stwo_m31_sub(r2802, r2803);
    unsigned r2805 = stwo_m31_mul(r0, r2673);
    unsigned r2806 = stwo_m31_add(r2805, r2679);
    unsigned r2807 = stwo_m31_mul(r3, r2680);
    unsigned r2808 = stwo_m31_add(r2806, r2807);
    unsigned r2809 = stwo_m31_mul(r1, r2190);
    unsigned r2810 = stwo_m31_sub(r2808, r2809);
    unsigned r2811 = stwo_m31_mul(r0, r2674);
    unsigned r2812 = stwo_m31_add(r2811, r2680);
    unsigned r2813 = stwo_m31_mul(r1, r2204);
    unsigned r2814 = stwo_m31_sub(r2812, r2813);
    unsigned r2815 = stwo_m31_mul(r4, r2082);
    unsigned r2816 = stwo_m31_add(r2814, r2815);
    unsigned r2817 = stwo_m31_mul(r0, r2675);
    unsigned r2818 = stwo_m31_mul(r1, r2216);
    unsigned r2819 = stwo_m31_sub(r2817, r2818);
    unsigned r2820 = stwo_m31_mul(r0, r2082);
    unsigned r2821 = stwo_m31_add(r2819, r2820);
    unsigned r2822 = stwo_m31_mul(r4, r2091);
    unsigned r2823 = stwo_m31_add(r2821, r2822);
    unsigned r2824 = stwo_m31_mul(r0, r2676);
    unsigned r2825 = stwo_m31_mul(r1, r2226);
    unsigned r2826 = stwo_m31_sub(r2824, r2825);
    unsigned r2827 = stwo_m31_mul(r0, r2091);
    unsigned r2828 = stwo_m31_add(r2826, r2827);
    unsigned r2829 = stwo_m31_mul(r4, r2098);
    unsigned r2830 = stwo_m31_add(r2828, r2829);
    unsigned r2831 = stwo_m31_mul(r0, r2677);
    unsigned r2832 = stwo_m31_mul(r1, r2234);
    unsigned r2833 = stwo_m31_sub(r2831, r2832);
    unsigned r2834 = stwo_m31_mul(r0, r2098);
    unsigned r2835 = stwo_m31_add(r2833, r2834);
    unsigned r2836 = stwo_m31_mul(r4, r2103);
    unsigned r2837 = stwo_m31_add(r2835, r2836);
    unsigned r2838 = stwo_m31_mul(r0, r2678);
    unsigned r2839 = stwo_m31_mul(r1, r2240);
    unsigned r2840 = stwo_m31_sub(r2838, r2839);
    unsigned r2841 = stwo_m31_mul(r0, r2103);
    unsigned r2842 = stwo_m31_add(r2840, r2841);
    unsigned r2843 = stwo_m31_mul(r4, r2106);
    unsigned r2844 = stwo_m31_add(r2842, r2843);
    unsigned r2845 = stwo_m31_mul(r0, r2679);
    unsigned r2846 = stwo_m31_mul(r1, r2244);
    unsigned r2847 = stwo_m31_sub(r2845, r2846);
    unsigned r2848 = stwo_m31_mul(r0, r2106);
    unsigned r2849 = stwo_m31_add(r2847, r2848);
    unsigned r2850 = stwo_m31_mul(r4, r2107);
    unsigned r2851 = stwo_m31_add(r2849, r2850);
    unsigned r2852 = stwo_m31_mul(r0, r2680);
    unsigned r2853 = stwo_m31_mul(r1, r2071);
    unsigned r2854 = stwo_m31_sub(r2852, r2853);
    unsigned r2855 = stwo_m31_mul(r0, r2107);
    unsigned r2856 = stwo_m31_add(r2854, r2855);
    unsigned r2857 = stwo_m31_add(r2692, r12);
    unsigned r2858 = stwo_m31_add(r2698, r12);
    unsigned r2859 = (r2858 & 511u);
    unsigned r2860 = (r2859 << 9u);
    unsigned r2861 = (r2857 + r2860);
    unsigned r2862 = 131072u;
    unsigned r2863 = (r2861 + r2862);
    unsigned r2864 = (r2863 & 262143u);
    unsigned r2865 = (r2864 & 65535u);
    unsigned r2866 = (r2865 % STWO_M31_P);
    unsigned r2867 = (r2864 >> 16u);
    unsigned r2868 = (r2867 % STWO_M31_P);
    unsigned r2869 = stwo_m31_sub(r2868, r0);
    unsigned r2870 = stwo_m31_mul(r2869, r8);
    unsigned r2871 = stwo_m31_add(r2866, r2870);
    unsigned r2872 = stwo_m31_add(r2871, r10);
    sub_words[88u * row_count + row] = r2872;
    unsigned r2873 = stwo_m31_add(r2871, r10);
    lookup_words[30u * row_count + row] = r2873;
    unsigned r2874 = stwo_m31_sub(r2692, r2871);
    unsigned r2875 = stwo_m31_mul(r2874, r11);
    unsigned r2876 = stwo_m31_add(r2875, r10);
    sub_words[96u * row_count + row] = r2876;
    unsigned r2877 = stwo_m31_add(r2875, r10);
    lookup_words[46u * row_count + row] = r2877;
    unsigned r2878 = stwo_m31_add(r2698, r2875);
    out_cols[113u][row] = r2875;
    unsigned r2879 = stwo_m31_mul(r2878, r11);
    unsigned r2880 = stwo_m31_add(r2879, r10);
    sub_words[104u * row_count + row] = r2880;
    unsigned r2881 = stwo_m31_add(r2879, r10);
    lookup_words[62u * row_count + row] = r2881;
    unsigned r2882 = stwo_m31_add(r2704, r2879);
    out_cols[114u][row] = r2879;
    unsigned r2883 = stwo_m31_mul(r2882, r11);
    unsigned r2884 = stwo_m31_add(r2883, r10);
    sub_words[112u * row_count + row] = r2884;
    unsigned r2885 = stwo_m31_add(r2883, r10);
    lookup_words[78u * row_count + row] = r2885;
    unsigned r2886 = stwo_m31_add(r2710, r2883);
    out_cols[115u][row] = r2883;
    unsigned r2887 = stwo_m31_mul(r2886, r11);
    unsigned r2888 = stwo_m31_add(r2887, r10);
    sub_words[119u * row_count + row] = r2888;
    unsigned r2889 = stwo_m31_add(r2887, r10);
    lookup_words[92u * row_count + row] = r2889;
    unsigned r2890 = stwo_m31_add(r2716, r2887);
    out_cols[116u][row] = r2887;
    unsigned r2891 = stwo_m31_mul(r2890, r11);
    unsigned r2892 = stwo_m31_add(r2891, r10);
    sub_words[125u * row_count + row] = r2892;
    unsigned r2893 = stwo_m31_add(r2891, r10);
    lookup_words[104u * row_count + row] = r2893;
    unsigned r2894 = stwo_m31_add(r2722, r2891);
    out_cols[117u][row] = r2891;
    unsigned r2895 = stwo_m31_mul(r2894, r11);
    unsigned r2896 = stwo_m31_add(r2895, r10);
    sub_words[131u * row_count + row] = r2896;
    unsigned r2897 = stwo_m31_add(r2895, r10);
    lookup_words[116u * row_count + row] = r2897;
    unsigned r2898 = stwo_m31_add(r2726, r2895);
    out_cols[118u][row] = r2895;
    unsigned r2899 = stwo_m31_mul(r2898, r11);
    unsigned r2900 = stwo_m31_add(r2899, r10);
    sub_words[137u * row_count + row] = r2900;
    unsigned r2901 = stwo_m31_add(r2899, r10);
    lookup_words[128u * row_count + row] = r2901;
    unsigned r2902 = stwo_m31_add(r2732, r2899);
    out_cols[119u][row] = r2899;
    unsigned r2903 = stwo_m31_mul(r2902, r11);
    unsigned r2904 = stwo_m31_add(r2903, r10);
    sub_words[89u * row_count + row] = r2904;
    unsigned r2905 = stwo_m31_add(r2903, r10);
    lookup_words[32u * row_count + row] = r2905;
    unsigned r2906 = stwo_m31_add(r2738, r2903);
    out_cols[120u][row] = r2903;
    unsigned r2907 = stwo_m31_mul(r2906, r11);
    unsigned r2908 = stwo_m31_add(r2907, r10);
    sub_words[97u * row_count + row] = r2908;
    unsigned r2909 = stwo_m31_add(r2907, r10);
    lookup_words[48u * row_count + row] = r2909;
    unsigned r2910 = stwo_m31_add(r2744, r2907);
    out_cols[121u][row] = r2907;
    unsigned r2911 = stwo_m31_mul(r2910, r11);
    unsigned r2912 = stwo_m31_add(r2911, r10);
    sub_words[105u * row_count + row] = r2912;
    unsigned r2913 = stwo_m31_add(r2911, r10);
    lookup_words[64u * row_count + row] = r2913;
    unsigned r2914 = stwo_m31_add(r2750, r2911);
    out_cols[122u][row] = r2911;
    unsigned r2915 = stwo_m31_mul(r2914, r11);
    unsigned r2916 = stwo_m31_add(r2915, r10);
    sub_words[113u * row_count + row] = r2916;
    unsigned r2917 = stwo_m31_add(r2915, r10);
    lookup_words[80u * row_count + row] = r2917;
    unsigned r2918 = stwo_m31_add(r2756, r2915);
    out_cols[123u][row] = r2915;
    unsigned r2919 = stwo_m31_mul(r2918, r11);
    unsigned r2920 = stwo_m31_add(r2919, r10);
    sub_words[120u * row_count + row] = r2920;
    unsigned r2921 = stwo_m31_add(r2919, r10);
    lookup_words[94u * row_count + row] = r2921;
    unsigned r2922 = stwo_m31_add(r2762, r2919);
    out_cols[124u][row] = r2919;
    unsigned r2923 = stwo_m31_mul(r2922, r11);
    unsigned r2924 = stwo_m31_add(r2923, r10);
    sub_words[126u * row_count + row] = r2924;
    unsigned r2925 = stwo_m31_add(r2923, r10);
    lookup_words[106u * row_count + row] = r2925;
    unsigned r2926 = stwo_m31_add(r2768, r2923);
    out_cols[125u][row] = r2923;
    unsigned r2927 = stwo_m31_mul(r2926, r11);
    unsigned r2928 = stwo_m31_add(r2927, r10);
    sub_words[132u * row_count + row] = r2928;
    unsigned r2929 = stwo_m31_add(r2927, r10);
    lookup_words[118u * row_count + row] = r2929;
    unsigned r2930 = stwo_m31_add(r2774, r2927);
    out_cols[126u][row] = r2927;
    unsigned r2931 = stwo_m31_mul(r2930, r11);
    unsigned r2932 = stwo_m31_add(r2931, r10);
    sub_words[138u * row_count + row] = r2932;
    unsigned r2933 = stwo_m31_add(r2931, r10);
    lookup_words[130u * row_count + row] = r2933;
    unsigned r2934 = stwo_m31_add(r2780, r2931);
    out_cols[127u][row] = r2931;
    unsigned r2935 = stwo_m31_mul(r2934, r11);
    unsigned r2936 = stwo_m31_add(r2935, r10);
    sub_words[90u * row_count + row] = r2936;
    unsigned r2937 = stwo_m31_add(r2935, r10);
    lookup_words[34u * row_count + row] = r2937;
    unsigned r2938 = stwo_m31_add(r2786, r2935);
    out_cols[128u][row] = r2935;
    unsigned r2939 = stwo_m31_mul(r2938, r11);
    unsigned r2940 = stwo_m31_add(r2939, r10);
    sub_words[98u * row_count + row] = r2940;
    unsigned r2941 = stwo_m31_add(r2939, r10);
    lookup_words[50u * row_count + row] = r2941;
    unsigned r2942 = stwo_m31_add(r2792, r2939);
    out_cols[129u][row] = r2939;
    unsigned r2943 = stwo_m31_mul(r2942, r11);
    unsigned r2944 = stwo_m31_add(r2943, r10);
    sub_words[106u * row_count + row] = r2944;
    unsigned r2945 = stwo_m31_add(r2943, r10);
    lookup_words[66u * row_count + row] = r2945;
    unsigned r2946 = stwo_m31_add(r2798, r2943);
    out_cols[130u][row] = r2943;
    unsigned r2947 = stwo_m31_mul(r2946, r11);
    unsigned r2948 = stwo_m31_add(r2947, r10);
    sub_words[114u * row_count + row] = r2948;
    unsigned r2949 = stwo_m31_add(r2947, r10);
    lookup_words[82u * row_count + row] = r2949;
    unsigned r2950 = stwo_m31_add(r2804, r2947);
    out_cols[131u][row] = r2947;
    unsigned r2951 = stwo_m31_mul(r2950, r11);
    unsigned r2952 = stwo_m31_add(r2951, r10);
    sub_words[121u * row_count + row] = r2952;
    unsigned r2953 = stwo_m31_add(r2951, r10);
    lookup_words[96u * row_count + row] = r2953;
    unsigned r2954 = stwo_m31_add(r2810, r2951);
    out_cols[132u][row] = r2951;
    unsigned r2955 = stwo_m31_mul(r2954, r11);
    unsigned r2956 = stwo_m31_add(r2955, r10);
    sub_words[127u * row_count + row] = r2956;
    unsigned r2957 = stwo_m31_add(r2955, r10);
    lookup_words[108u * row_count + row] = r2957;
    unsigned r2958 = stwo_m31_mul(r5, r2871);
    out_cols[112u][row] = r2871;
    unsigned r2959 = stwo_m31_sub(r2816, r2958);
    unsigned r2960 = stwo_m31_add(r2959, r2955);
    out_cols[133u][row] = r2955;
    unsigned r2961 = stwo_m31_mul(r2960, r11);
    unsigned r2962 = stwo_m31_add(r2961, r10);
    sub_words[133u * row_count + row] = r2962;
    unsigned r2963 = stwo_m31_add(r2961, r10);
    lookup_words[120u * row_count + row] = r2963;
    unsigned r2964 = stwo_m31_add(r2823, r2961);
    out_cols[134u][row] = r2961;
    unsigned r2965 = stwo_m31_mul(r2964, r11);
    unsigned r2966 = stwo_m31_add(r2965, r10);
    sub_words[139u * row_count + row] = r2966;
    unsigned r2967 = stwo_m31_add(r2965, r10);
    lookup_words[132u * row_count + row] = r2967;
    unsigned r2968 = stwo_m31_add(r2830, r2965);
    out_cols[135u][row] = r2965;
    unsigned r2969 = stwo_m31_mul(r2968, r11);
    unsigned r2970 = stwo_m31_add(r2969, r10);
    sub_words[91u * row_count + row] = r2970;
    unsigned r2971 = stwo_m31_add(r2969, r10);
    lookup_words[36u * row_count + row] = r2971;
    unsigned r2972 = stwo_m31_add(r2837, r2969);
    out_cols[136u][row] = r2969;
    unsigned r2973 = stwo_m31_mul(r2972, r11);
    unsigned r2974 = stwo_m31_add(r2973, r10);
    sub_words[99u * row_count + row] = r2974;
    unsigned r2975 = stwo_m31_add(r2973, r10);
    lookup_words[52u * row_count + row] = r2975;
    unsigned r2976 = stwo_m31_add(r2844, r2973);
    out_cols[137u][row] = r2973;
    unsigned r2977 = stwo_m31_mul(r2976, r11);
    unsigned r2978 = stwo_m31_add(r2977, r10);
    sub_words[107u * row_count + row] = r2978;
    unsigned r2979 = stwo_m31_add(r2977, r10);
    lookup_words[68u * row_count + row] = r2979;
    unsigned r2980 = stwo_m31_add(r2851, r2977);
    out_cols[138u][row] = r2977;
    unsigned r2981 = stwo_m31_mul(r2980, r11);
    unsigned r2982 = stwo_m31_add(r2981, r10);
    sub_words[115u * row_count + row] = r2982;
    unsigned r2983 = stwo_m31_add(r2981, r10);
    out_cols[139u][row] = r2981;
    lookup_words[84u * row_count + row] = r2983;
    unsigned r2984 = stwo_m31_mul(r1604, r6);
    out_cols[85u][row] = r1604;
    sub_words[9u * row_count + row] = r1604;
    lookup_words[147u * row_count + row] = r1604;
    unsigned r2985 = stwo_m31_add(r1603, r2984);
    out_cols[84u][row] = r1603;
    sub_words[8u * row_count + row] = r1603;
    lookup_words[146u * row_count + row] = r1603;
    unsigned r2986 = stwo_m31_mul(r1605, r9);
    out_cols[86u][row] = r1605;
    sub_words[20u * row_count + row] = r1605;
    lookup_words[164u * row_count + row] = r1605;
    unsigned r2987 = stwo_m31_add(r2985, r2986);
    lookup_words[11u * row_count + row] = r2987;
    unsigned r2988 = stwo_m31_mul(r1607, r6);
    out_cols[88u][row] = r1607;
    sub_words[32u * row_count + row] = r1607;
    lookup_words[182u * row_count + row] = r1607;
    unsigned r2989 = stwo_m31_add(r1606, r2988);
    out_cols[87u][row] = r1606;
    sub_words[21u * row_count + row] = r1606;
    lookup_words[165u * row_count + row] = r1606;
    unsigned r2990 = stwo_m31_mul(r1608, r9);
    out_cols[89u][row] = r1608;
    sub_words[33u * row_count + row] = r1608;
    lookup_words[183u * row_count + row] = r1608;
    unsigned r2991 = stwo_m31_add(r2989, r2990);
    lookup_words[12u * row_count + row] = r2991;
    unsigned r2992 = stwo_m31_mul(r1610, r6);
    out_cols[91u][row] = r1610;
    sub_words[45u * row_count + row] = r1610;
    lookup_words[201u * row_count + row] = r1610;
    unsigned r2993 = stwo_m31_add(r1609, r2992);
    out_cols[90u][row] = r1609;
    sub_words[44u * row_count + row] = r1609;
    lookup_words[200u * row_count + row] = r1609;
    unsigned r2994 = stwo_m31_mul(r1611, r9);
    out_cols[92u][row] = r1611;
    sub_words[56u * row_count + row] = r1611;
    lookup_words[218u * row_count + row] = r1611;
    unsigned r2995 = stwo_m31_add(r2993, r2994);
    lookup_words[13u * row_count + row] = r2995;
    unsigned r2996 = stwo_m31_mul(r1613, r6);
    out_cols[94u][row] = r1613;
    sub_words[68u * row_count + row] = r1613;
    lookup_words[236u * row_count + row] = r1613;
    unsigned r2997 = stwo_m31_add(r1612, r2996);
    out_cols[93u][row] = r1612;
    sub_words[57u * row_count + row] = r1612;
    lookup_words[219u * row_count + row] = r1612;
    unsigned r2998 = stwo_m31_mul(r1614, r9);
    out_cols[95u][row] = r1614;
    sub_words[69u * row_count + row] = r1614;
    lookup_words[237u * row_count + row] = r1614;
    unsigned r2999 = stwo_m31_add(r2997, r2998);
    lookup_words[14u * row_count + row] = r2999;
    unsigned r3000 = stwo_m31_mul(r1616, r6);
    out_cols[97u][row] = r1616;
    sub_words[77u * row_count + row] = r1616;
    lookup_words[249u * row_count + row] = r1616;
    unsigned r3001 = stwo_m31_add(r1615, r3000);
    out_cols[96u][row] = r1615;
    sub_words[76u * row_count + row] = r1615;
    lookup_words[248u * row_count + row] = r1615;
    unsigned r3002 = stwo_m31_mul(r1617, r9);
    out_cols[98u][row] = r1617;
    sub_words[82u * row_count + row] = r1617;
    lookup_words[257u * row_count + row] = r1617;
    unsigned r3003 = stwo_m31_add(r3001, r3002);
    lookup_words[15u * row_count + row] = r3003;
    unsigned r3004 = stwo_m31_mul(r1619, r6);
    out_cols[100u][row] = r1619;
    sub_words[10u * row_count + row] = r1619;
    lookup_words[149u * row_count + row] = r1619;
    unsigned r3005 = stwo_m31_add(r1618, r3004);
    out_cols[99u][row] = r1618;
    sub_words[83u * row_count + row] = r1618;
    lookup_words[258u * row_count + row] = r1618;
    unsigned r3006 = stwo_m31_mul(r1620, r9);
    out_cols[101u][row] = r1620;
    sub_words[11u * row_count + row] = r1620;
    lookup_words[150u * row_count + row] = r1620;
    unsigned r3007 = stwo_m31_add(r3005, r3006);
    lookup_words[16u * row_count + row] = r3007;
    unsigned r3008 = stwo_m31_mul(r1622, r6);
    out_cols[103u][row] = r1622;
    sub_words[23u * row_count + row] = r1622;
    lookup_words[168u * row_count + row] = r1622;
    unsigned r3009 = stwo_m31_add(r1621, r3008);
    out_cols[102u][row] = r1621;
    sub_words[22u * row_count + row] = r1621;
    lookup_words[167u * row_count + row] = r1621;
    unsigned r3010 = stwo_m31_mul(r1623, r9);
    out_cols[104u][row] = r1623;
    sub_words[34u * row_count + row] = r1623;
    lookup_words[185u * row_count + row] = r1623;
    unsigned r3011 = stwo_m31_add(r3009, r3010);
    lookup_words[17u * row_count + row] = r3011;
    unsigned r3012 = stwo_m31_mul(r1625, r6);
    out_cols[106u][row] = r1625;
    sub_words[46u * row_count + row] = r1625;
    lookup_words[203u * row_count + row] = r1625;
    unsigned r3013 = stwo_m31_add(r1624, r3012);
    out_cols[105u][row] = r1624;
    sub_words[35u * row_count + row] = r1624;
    lookup_words[186u * row_count + row] = r1624;
    unsigned r3014 = stwo_m31_mul(r1626, r9);
    out_cols[107u][row] = r1626;
    sub_words[47u * row_count + row] = r1626;
    lookup_words[204u * row_count + row] = r1626;
    unsigned r3015 = stwo_m31_add(r3013, r3014);
    lookup_words[18u * row_count + row] = r3015;
    unsigned r3016 = stwo_m31_mul(r1628, r6);
    out_cols[109u][row] = r1628;
    sub_words[59u * row_count + row] = r1628;
    lookup_words[222u * row_count + row] = r1628;
    unsigned r3017 = stwo_m31_add(r1627, r3016);
    out_cols[108u][row] = r1627;
    sub_words[58u * row_count + row] = r1627;
    lookup_words[221u * row_count + row] = r1627;
    unsigned r3018 = stwo_m31_mul(r1629, r9);
    out_cols[110u][row] = r1629;
    sub_words[70u * row_count + row] = r1629;
    lookup_words[239u * row_count + row] = r1629;
    unsigned r3019 = stwo_m31_add(r3017, r3018);
    lookup_words[19u * row_count + row] = r3019;
    unsigned r3020 = input_cols[10u][row];
    out_cols[140u][row] = r3020;
}
