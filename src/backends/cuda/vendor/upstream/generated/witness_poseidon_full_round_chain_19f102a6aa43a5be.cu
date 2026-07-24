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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_752513a1a2621451(
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
    unsigned r4 = 16u;
    unsigned r5 = 136u;
    unsigned r6 = 512u;
    unsigned r7 = 262144u;
    unsigned r8 = 134217729u;
    unsigned r9 = 268435458u;
    unsigned r10 = 402653187u;
    unsigned r11 = 502259093u;
    lookup_words[95u * row_count + row] = r11;
    lookup_words[101u * row_count + row] = r11;
    lookup_words[107u * row_count + row] = r11;
    lookup_words[113u * row_count + row] = r11;
    lookup_words[119u * row_count + row] = r11;
    lookup_words[125u * row_count + row] = r11;
    unsigned r12 = 1024310512u;
    lookup_words[63u * row_count + row] = r12;
    unsigned r13 = 1480369132u;
    lookup_words[131u * row_count + row] = r13;
    lookup_words[164u * row_count + row] = r13;
    unsigned r14 = 1987997202u;
    lookup_words[0u * row_count + row] = r14;
    lookup_words[21u * row_count + row] = r14;
    lookup_words[42u * row_count + row] = r14;
    unsigned r15 = input_cols[0u][row];
    out_cols[0u][row] = r15;
    lookup_words[132u * row_count + row] = r15;
    lookup_words[165u * row_count + row] = r15;
    unsigned r16 = input_cols[1u][row];
    unsigned r17 = input_cols[2u][row];
    out_cols[2u][row] = r17;
    lookup_words[1u * row_count + row] = r17;
    lookup_words[134u * row_count + row] = r17;
    unsigned r18 = input_cols[3u][row];
    unsigned r19 = input_cols[4u][row];
    unsigned r20 = input_cols[5u][row];
    unsigned r21 = input_cols[6u][row];
    unsigned r22 = input_cols[7u][row];
    unsigned r23 = input_cols[8u][row];
    unsigned r24 = input_cols[9u][row];
    unsigned r25 = input_cols[10u][row];
    unsigned r26 = input_cols[11u][row];
    unsigned r27 = input_cols[2u][row];
    unsigned r28 = input_cols[3u][row];
    out_cols[3u][row] = r28;
    lookup_words[2u * row_count + row] = r28;
    lookup_words[135u * row_count + row] = r28;
    unsigned r29 = input_cols[4u][row];
    unsigned r30 = input_cols[5u][row];
    unsigned r31 = input_cols[6u][row];
    unsigned r32 = input_cols[7u][row];
    unsigned r33 = input_cols[8u][row];
    unsigned r34 = input_cols[9u][row];
    unsigned r35 = input_cols[10u][row];
    unsigned r36 = input_cols[11u][row];
    unsigned r37 = input_cols[2u][row];
    unsigned r38 = input_cols[3u][row];
    unsigned r39 = input_cols[4u][row];
    out_cols[4u][row] = r39;
    lookup_words[3u * row_count + row] = r39;
    lookup_words[136u * row_count + row] = r39;
    unsigned r40 = input_cols[5u][row];
    unsigned r41 = input_cols[6u][row];
    unsigned r42 = input_cols[7u][row];
    unsigned r43 = input_cols[8u][row];
    unsigned r44 = input_cols[9u][row];
    unsigned r45 = input_cols[10u][row];
    unsigned r46 = input_cols[11u][row];
    unsigned r47 = input_cols[2u][row];
    unsigned r48 = input_cols[3u][row];
    unsigned r49 = input_cols[4u][row];
    unsigned r50 = input_cols[5u][row];
    out_cols[5u][row] = r50;
    lookup_words[4u * row_count + row] = r50;
    lookup_words[137u * row_count + row] = r50;
    unsigned r51 = input_cols[6u][row];
    unsigned r52 = input_cols[7u][row];
    unsigned r53 = input_cols[8u][row];
    unsigned r54 = input_cols[9u][row];
    unsigned r55 = input_cols[10u][row];
    unsigned r56 = input_cols[11u][row];
    unsigned r57 = input_cols[2u][row];
    unsigned r58 = input_cols[3u][row];
    unsigned r59 = input_cols[4u][row];
    unsigned r60 = input_cols[5u][row];
    unsigned r61 = input_cols[6u][row];
    out_cols[6u][row] = r61;
    lookup_words[5u * row_count + row] = r61;
    lookup_words[138u * row_count + row] = r61;
    unsigned r62 = input_cols[7u][row];
    unsigned r63 = input_cols[8u][row];
    unsigned r64 = input_cols[9u][row];
    unsigned r65 = input_cols[10u][row];
    unsigned r66 = input_cols[11u][row];
    unsigned r67 = input_cols[2u][row];
    unsigned r68 = input_cols[3u][row];
    unsigned r69 = input_cols[4u][row];
    unsigned r70 = input_cols[5u][row];
    unsigned r71 = input_cols[6u][row];
    unsigned r72 = input_cols[7u][row];
    out_cols[7u][row] = r72;
    lookup_words[6u * row_count + row] = r72;
    lookup_words[139u * row_count + row] = r72;
    unsigned r73 = input_cols[8u][row];
    unsigned r74 = input_cols[9u][row];
    unsigned r75 = input_cols[10u][row];
    unsigned r76 = input_cols[11u][row];
    unsigned r77 = input_cols[2u][row];
    unsigned r78 = input_cols[3u][row];
    unsigned r79 = input_cols[4u][row];
    unsigned r80 = input_cols[5u][row];
    unsigned r81 = input_cols[6u][row];
    unsigned r82 = input_cols[7u][row];
    unsigned r83 = input_cols[8u][row];
    out_cols[8u][row] = r83;
    lookup_words[7u * row_count + row] = r83;
    lookup_words[140u * row_count + row] = r83;
    unsigned r84 = input_cols[9u][row];
    unsigned r85 = input_cols[10u][row];
    unsigned r86 = input_cols[11u][row];
    unsigned r87 = input_cols[2u][row];
    unsigned r88 = input_cols[3u][row];
    unsigned r89 = input_cols[4u][row];
    unsigned r90 = input_cols[5u][row];
    unsigned r91 = input_cols[6u][row];
    unsigned r92 = input_cols[7u][row];
    unsigned r93 = input_cols[8u][row];
    unsigned r94 = input_cols[9u][row];
    out_cols[9u][row] = r94;
    lookup_words[8u * row_count + row] = r94;
    lookup_words[141u * row_count + row] = r94;
    unsigned r95 = input_cols[10u][row];
    unsigned r96 = input_cols[11u][row];
    unsigned r97 = input_cols[2u][row];
    unsigned r98 = input_cols[3u][row];
    unsigned r99 = input_cols[4u][row];
    unsigned r100 = input_cols[5u][row];
    unsigned r101 = input_cols[6u][row];
    unsigned r102 = input_cols[7u][row];
    unsigned r103 = input_cols[8u][row];
    unsigned r104 = input_cols[9u][row];
    unsigned r105 = input_cols[10u][row];
    out_cols[10u][row] = r105;
    lookup_words[9u * row_count + row] = r105;
    lookup_words[142u * row_count + row] = r105;
    unsigned r106 = input_cols[11u][row];
    unsigned r107 = input_cols[2u][row];
    unsigned r108 = input_cols[3u][row];
    unsigned r109 = input_cols[4u][row];
    unsigned r110 = input_cols[5u][row];
    unsigned r111 = input_cols[6u][row];
    unsigned r112 = input_cols[7u][row];
    unsigned r113 = input_cols[8u][row];
    unsigned r114 = input_cols[9u][row];
    unsigned r115 = input_cols[10u][row];
    unsigned r116 = input_cols[11u][row];
    out_cols[11u][row] = r116;
    lookup_words[10u * row_count + row] = r116;
    lookup_words[143u * row_count + row] = r116;
    unsigned r117 = input_cols[12u][row];
    out_cols[12u][row] = r117;
    lookup_words[22u * row_count + row] = r117;
    lookup_words[144u * row_count + row] = r117;
    unsigned r118 = input_cols[13u][row];
    unsigned r119 = input_cols[14u][row];
    unsigned r120 = input_cols[15u][row];
    unsigned r121 = input_cols[16u][row];
    unsigned r122 = input_cols[17u][row];
    unsigned r123 = input_cols[18u][row];
    unsigned r124 = input_cols[19u][row];
    unsigned r125 = input_cols[20u][row];
    unsigned r126 = input_cols[21u][row];
    unsigned r127 = input_cols[12u][row];
    unsigned r128 = input_cols[13u][row];
    out_cols[13u][row] = r128;
    lookup_words[23u * row_count + row] = r128;
    lookup_words[145u * row_count + row] = r128;
    unsigned r129 = input_cols[14u][row];
    unsigned r130 = input_cols[15u][row];
    unsigned r131 = input_cols[16u][row];
    unsigned r132 = input_cols[17u][row];
    unsigned r133 = input_cols[18u][row];
    unsigned r134 = input_cols[19u][row];
    unsigned r135 = input_cols[20u][row];
    unsigned r136 = input_cols[21u][row];
    unsigned r137 = input_cols[12u][row];
    unsigned r138 = input_cols[13u][row];
    unsigned r139 = input_cols[14u][row];
    out_cols[14u][row] = r139;
    lookup_words[24u * row_count + row] = r139;
    lookup_words[146u * row_count + row] = r139;
    unsigned r140 = input_cols[15u][row];
    unsigned r141 = input_cols[16u][row];
    unsigned r142 = input_cols[17u][row];
    unsigned r143 = input_cols[18u][row];
    unsigned r144 = input_cols[19u][row];
    unsigned r145 = input_cols[20u][row];
    unsigned r146 = input_cols[21u][row];
    unsigned r147 = input_cols[12u][row];
    unsigned r148 = input_cols[13u][row];
    unsigned r149 = input_cols[14u][row];
    unsigned r150 = input_cols[15u][row];
    out_cols[15u][row] = r150;
    lookup_words[25u * row_count + row] = r150;
    lookup_words[147u * row_count + row] = r150;
    unsigned r151 = input_cols[16u][row];
    unsigned r152 = input_cols[17u][row];
    unsigned r153 = input_cols[18u][row];
    unsigned r154 = input_cols[19u][row];
    unsigned r155 = input_cols[20u][row];
    unsigned r156 = input_cols[21u][row];
    unsigned r157 = input_cols[12u][row];
    unsigned r158 = input_cols[13u][row];
    unsigned r159 = input_cols[14u][row];
    unsigned r160 = input_cols[15u][row];
    unsigned r161 = input_cols[16u][row];
    out_cols[16u][row] = r161;
    lookup_words[26u * row_count + row] = r161;
    lookup_words[148u * row_count + row] = r161;
    unsigned r162 = input_cols[17u][row];
    unsigned r163 = input_cols[18u][row];
    unsigned r164 = input_cols[19u][row];
    unsigned r165 = input_cols[20u][row];
    unsigned r166 = input_cols[21u][row];
    unsigned r167 = input_cols[12u][row];
    unsigned r168 = input_cols[13u][row];
    unsigned r169 = input_cols[14u][row];
    unsigned r170 = input_cols[15u][row];
    unsigned r171 = input_cols[16u][row];
    unsigned r172 = input_cols[17u][row];
    out_cols[17u][row] = r172;
    lookup_words[27u * row_count + row] = r172;
    lookup_words[149u * row_count + row] = r172;
    unsigned r173 = input_cols[18u][row];
    unsigned r174 = input_cols[19u][row];
    unsigned r175 = input_cols[20u][row];
    unsigned r176 = input_cols[21u][row];
    unsigned r177 = input_cols[12u][row];
    unsigned r178 = input_cols[13u][row];
    unsigned r179 = input_cols[14u][row];
    unsigned r180 = input_cols[15u][row];
    unsigned r181 = input_cols[16u][row];
    unsigned r182 = input_cols[17u][row];
    unsigned r183 = input_cols[18u][row];
    out_cols[18u][row] = r183;
    lookup_words[28u * row_count + row] = r183;
    lookup_words[150u * row_count + row] = r183;
    unsigned r184 = input_cols[19u][row];
    unsigned r185 = input_cols[20u][row];
    unsigned r186 = input_cols[21u][row];
    unsigned r187 = input_cols[12u][row];
    unsigned r188 = input_cols[13u][row];
    unsigned r189 = input_cols[14u][row];
    unsigned r190 = input_cols[15u][row];
    unsigned r191 = input_cols[16u][row];
    unsigned r192 = input_cols[17u][row];
    unsigned r193 = input_cols[18u][row];
    unsigned r194 = input_cols[19u][row];
    out_cols[19u][row] = r194;
    lookup_words[29u * row_count + row] = r194;
    lookup_words[151u * row_count + row] = r194;
    unsigned r195 = input_cols[20u][row];
    unsigned r196 = input_cols[21u][row];
    unsigned r197 = input_cols[12u][row];
    unsigned r198 = input_cols[13u][row];
    unsigned r199 = input_cols[14u][row];
    unsigned r200 = input_cols[15u][row];
    unsigned r201 = input_cols[16u][row];
    unsigned r202 = input_cols[17u][row];
    unsigned r203 = input_cols[18u][row];
    unsigned r204 = input_cols[19u][row];
    unsigned r205 = input_cols[20u][row];
    out_cols[20u][row] = r205;
    lookup_words[30u * row_count + row] = r205;
    lookup_words[152u * row_count + row] = r205;
    unsigned r206 = input_cols[21u][row];
    unsigned r207 = input_cols[12u][row];
    unsigned r208 = input_cols[13u][row];
    unsigned r209 = input_cols[14u][row];
    unsigned r210 = input_cols[15u][row];
    unsigned r211 = input_cols[16u][row];
    unsigned r212 = input_cols[17u][row];
    unsigned r213 = input_cols[18u][row];
    unsigned r214 = input_cols[19u][row];
    unsigned r215 = input_cols[20u][row];
    unsigned r216 = input_cols[21u][row];
    out_cols[21u][row] = r216;
    lookup_words[31u * row_count + row] = r216;
    lookup_words[153u * row_count + row] = r216;
    unsigned r217 = input_cols[22u][row];
    out_cols[22u][row] = r217;
    lookup_words[43u * row_count + row] = r217;
    lookup_words[154u * row_count + row] = r217;
    unsigned r218 = input_cols[23u][row];
    unsigned r219 = input_cols[24u][row];
    unsigned r220 = input_cols[25u][row];
    unsigned r221 = input_cols[26u][row];
    unsigned r222 = input_cols[27u][row];
    unsigned r223 = input_cols[28u][row];
    unsigned r224 = input_cols[29u][row];
    unsigned r225 = input_cols[30u][row];
    unsigned r226 = input_cols[31u][row];
    unsigned r227 = input_cols[22u][row];
    unsigned r228 = input_cols[23u][row];
    out_cols[23u][row] = r228;
    lookup_words[44u * row_count + row] = r228;
    lookup_words[155u * row_count + row] = r228;
    unsigned r229 = input_cols[24u][row];
    unsigned r230 = input_cols[25u][row];
    unsigned r231 = input_cols[26u][row];
    unsigned r232 = input_cols[27u][row];
    unsigned r233 = input_cols[28u][row];
    unsigned r234 = input_cols[29u][row];
    unsigned r235 = input_cols[30u][row];
    unsigned r236 = input_cols[31u][row];
    unsigned r237 = input_cols[22u][row];
    unsigned r238 = input_cols[23u][row];
    unsigned r239 = input_cols[24u][row];
    out_cols[24u][row] = r239;
    lookup_words[45u * row_count + row] = r239;
    lookup_words[156u * row_count + row] = r239;
    unsigned r240 = input_cols[25u][row];
    unsigned r241 = input_cols[26u][row];
    unsigned r242 = input_cols[27u][row];
    unsigned r243 = input_cols[28u][row];
    unsigned r244 = input_cols[29u][row];
    unsigned r245 = input_cols[30u][row];
    unsigned r246 = input_cols[31u][row];
    unsigned r247 = input_cols[22u][row];
    unsigned r248 = input_cols[23u][row];
    unsigned r249 = input_cols[24u][row];
    unsigned r250 = input_cols[25u][row];
    out_cols[25u][row] = r250;
    lookup_words[46u * row_count + row] = r250;
    lookup_words[157u * row_count + row] = r250;
    unsigned r251 = input_cols[26u][row];
    unsigned r252 = input_cols[27u][row];
    unsigned r253 = input_cols[28u][row];
    unsigned r254 = input_cols[29u][row];
    unsigned r255 = input_cols[30u][row];
    unsigned r256 = input_cols[31u][row];
    unsigned r257 = input_cols[22u][row];
    unsigned r258 = input_cols[23u][row];
    unsigned r259 = input_cols[24u][row];
    unsigned r260 = input_cols[25u][row];
    unsigned r261 = input_cols[26u][row];
    out_cols[26u][row] = r261;
    lookup_words[47u * row_count + row] = r261;
    lookup_words[158u * row_count + row] = r261;
    unsigned r262 = input_cols[27u][row];
    unsigned r263 = input_cols[28u][row];
    unsigned r264 = input_cols[29u][row];
    unsigned r265 = input_cols[30u][row];
    unsigned r266 = input_cols[31u][row];
    unsigned r267 = input_cols[22u][row];
    unsigned r268 = input_cols[23u][row];
    unsigned r269 = input_cols[24u][row];
    unsigned r270 = input_cols[25u][row];
    unsigned r271 = input_cols[26u][row];
    unsigned r272 = input_cols[27u][row];
    out_cols[27u][row] = r272;
    lookup_words[48u * row_count + row] = r272;
    lookup_words[159u * row_count + row] = r272;
    unsigned r273 = input_cols[28u][row];
    unsigned r274 = input_cols[29u][row];
    unsigned r275 = input_cols[30u][row];
    unsigned r276 = input_cols[31u][row];
    unsigned r277 = input_cols[22u][row];
    unsigned r278 = input_cols[23u][row];
    unsigned r279 = input_cols[24u][row];
    unsigned r280 = input_cols[25u][row];
    unsigned r281 = input_cols[26u][row];
    unsigned r282 = input_cols[27u][row];
    unsigned r283 = input_cols[28u][row];
    out_cols[28u][row] = r283;
    lookup_words[49u * row_count + row] = r283;
    lookup_words[160u * row_count + row] = r283;
    unsigned r284 = input_cols[29u][row];
    unsigned r285 = input_cols[30u][row];
    unsigned r286 = input_cols[31u][row];
    unsigned r287 = input_cols[22u][row];
    unsigned r288 = input_cols[23u][row];
    unsigned r289 = input_cols[24u][row];
    unsigned r290 = input_cols[25u][row];
    unsigned r291 = input_cols[26u][row];
    unsigned r292 = input_cols[27u][row];
    unsigned r293 = input_cols[28u][row];
    unsigned r294 = input_cols[29u][row];
    out_cols[29u][row] = r294;
    lookup_words[50u * row_count + row] = r294;
    lookup_words[161u * row_count + row] = r294;
    unsigned r295 = input_cols[30u][row];
    unsigned r296 = input_cols[31u][row];
    unsigned r297 = input_cols[22u][row];
    unsigned r298 = input_cols[23u][row];
    unsigned r299 = input_cols[24u][row];
    unsigned r300 = input_cols[25u][row];
    unsigned r301 = input_cols[26u][row];
    unsigned r302 = input_cols[27u][row];
    unsigned r303 = input_cols[28u][row];
    unsigned r304 = input_cols[29u][row];
    unsigned r305 = input_cols[30u][row];
    out_cols[30u][row] = r305;
    lookup_words[51u * row_count + row] = r305;
    lookup_words[162u * row_count + row] = r305;
    unsigned r306 = input_cols[31u][row];
    unsigned r307 = input_cols[22u][row];
    unsigned r308 = input_cols[23u][row];
    unsigned r309 = input_cols[24u][row];
    unsigned r310 = input_cols[25u][row];
    unsigned r311 = input_cols[26u][row];
    unsigned r312 = input_cols[27u][row];
    unsigned r313 = input_cols[28u][row];
    unsigned r314 = input_cols[29u][row];
    unsigned r315 = input_cols[30u][row];
    unsigned r316 = input_cols[31u][row];
    out_cols[31u][row] = r316;
    lookup_words[52u * row_count + row] = r316;
    lookup_words[163u * row_count + row] = r316;
    unsigned r317 = input_cols[2u][row];
    sub_words[0u * row_count + row] = r317;
    unsigned r318 = input_cols[3u][row];
    sub_words[1u * row_count + row] = r318;
    unsigned r319 = input_cols[4u][row];
    sub_words[2u * row_count + row] = r319;
    unsigned r320 = input_cols[5u][row];
    sub_words[3u * row_count + row] = r320;
    unsigned r321 = input_cols[6u][row];
    sub_words[4u * row_count + row] = r321;
    unsigned r322 = input_cols[7u][row];
    sub_words[5u * row_count + row] = r322;
    unsigned r323 = input_cols[8u][row];
    sub_words[6u * row_count + row] = r323;
    unsigned r324 = input_cols[9u][row];
    sub_words[7u * row_count + row] = r324;
    unsigned r325 = input_cols[10u][row];
    sub_words[8u * row_count + row] = r325;
    unsigned r326 = input_cols[11u][row];
    sub_words[9u * row_count + row] = r326;
    unsigned r327 = input_cols[2u][row];
    unsigned r328 = input_cols[3u][row];
    unsigned r329 = input_cols[4u][row];
    unsigned r330 = input_cols[5u][row];
    unsigned r331 = input_cols[6u][row];
    unsigned r332 = input_cols[7u][row];
    unsigned r333 = input_cols[8u][row];
    unsigned r334 = input_cols[9u][row];
    unsigned r335 = input_cols[10u][row];
    unsigned r336 = input_cols[11u][row];
    const unsigned dargs0[10] = { r327, r328, r329, r330, r331, r332, r333, r334, r335, r336 };
    unsigned douts0[10];
    stwo_wit_deduce_cube_252(dargs0, douts0);
    unsigned r337 = douts0[0];
    unsigned r338 = douts0[1];
    unsigned r339 = douts0[2];
    unsigned r340 = douts0[3];
    unsigned r341 = douts0[4];
    unsigned r342 = douts0[5];
    unsigned r343 = douts0[6];
    unsigned r344 = douts0[7];
    unsigned r345 = douts0[8];
    unsigned r346 = douts0[9];
    unsigned r347 = input_cols[12u][row];
    sub_words[10u * row_count + row] = r347;
    unsigned r348 = input_cols[13u][row];
    sub_words[11u * row_count + row] = r348;
    unsigned r349 = input_cols[14u][row];
    sub_words[12u * row_count + row] = r349;
    unsigned r350 = input_cols[15u][row];
    sub_words[13u * row_count + row] = r350;
    unsigned r351 = input_cols[16u][row];
    sub_words[14u * row_count + row] = r351;
    unsigned r352 = input_cols[17u][row];
    sub_words[15u * row_count + row] = r352;
    unsigned r353 = input_cols[18u][row];
    sub_words[16u * row_count + row] = r353;
    unsigned r354 = input_cols[19u][row];
    sub_words[17u * row_count + row] = r354;
    unsigned r355 = input_cols[20u][row];
    sub_words[18u * row_count + row] = r355;
    unsigned r356 = input_cols[21u][row];
    sub_words[19u * row_count + row] = r356;
    unsigned r357 = input_cols[12u][row];
    unsigned r358 = input_cols[13u][row];
    unsigned r359 = input_cols[14u][row];
    unsigned r360 = input_cols[15u][row];
    unsigned r361 = input_cols[16u][row];
    unsigned r362 = input_cols[17u][row];
    unsigned r363 = input_cols[18u][row];
    unsigned r364 = input_cols[19u][row];
    unsigned r365 = input_cols[20u][row];
    unsigned r366 = input_cols[21u][row];
    const unsigned dargs1[10] = { r357, r358, r359, r360, r361, r362, r363, r364, r365, r366 };
    unsigned douts1[10];
    stwo_wit_deduce_cube_252(dargs1, douts1);
    unsigned r367 = douts1[0];
    unsigned r368 = douts1[1];
    unsigned r369 = douts1[2];
    unsigned r370 = douts1[3];
    unsigned r371 = douts1[4];
    unsigned r372 = douts1[5];
    unsigned r373 = douts1[6];
    unsigned r374 = douts1[7];
    unsigned r375 = douts1[8];
    unsigned r376 = douts1[9];
    unsigned r377 = input_cols[22u][row];
    sub_words[20u * row_count + row] = r377;
    unsigned r378 = input_cols[23u][row];
    sub_words[21u * row_count + row] = r378;
    unsigned r379 = input_cols[24u][row];
    sub_words[22u * row_count + row] = r379;
    unsigned r380 = input_cols[25u][row];
    sub_words[23u * row_count + row] = r380;
    unsigned r381 = input_cols[26u][row];
    sub_words[24u * row_count + row] = r381;
    unsigned r382 = input_cols[27u][row];
    sub_words[25u * row_count + row] = r382;
    unsigned r383 = input_cols[28u][row];
    sub_words[26u * row_count + row] = r383;
    unsigned r384 = input_cols[29u][row];
    sub_words[27u * row_count + row] = r384;
    unsigned r385 = input_cols[30u][row];
    sub_words[28u * row_count + row] = r385;
    unsigned r386 = input_cols[31u][row];
    sub_words[29u * row_count + row] = r386;
    unsigned r387 = input_cols[22u][row];
    unsigned r388 = input_cols[23u][row];
    unsigned r389 = input_cols[24u][row];
    unsigned r390 = input_cols[25u][row];
    unsigned r391 = input_cols[26u][row];
    unsigned r392 = input_cols[27u][row];
    unsigned r393 = input_cols[28u][row];
    unsigned r394 = input_cols[29u][row];
    unsigned r395 = input_cols[30u][row];
    unsigned r396 = input_cols[31u][row];
    const unsigned dargs2[10] = { r387, r388, r389, r390, r391, r392, r393, r394, r395, r396 };
    unsigned douts2[10];
    stwo_wit_deduce_cube_252(dargs2, douts2);
    unsigned r397 = douts2[0];
    unsigned r398 = douts2[1];
    unsigned r399 = douts2[2];
    unsigned r400 = douts2[3];
    unsigned r401 = douts2[4];
    unsigned r402 = douts2[5];
    unsigned r403 = douts2[6];
    unsigned r404 = douts2[7];
    unsigned r405 = douts2[8];
    unsigned r406 = douts2[9];
    const unsigned dargs3[1] = { r16 };
    unsigned douts3[30];
    stwo_wit_deduce_poseidon_round_keys(dargs3, douts3);
    unsigned r407 = douts3[0];
    unsigned r408 = douts3[1];
    unsigned r409 = douts3[2];
    unsigned r410 = douts3[3];
    unsigned r411 = douts3[4];
    unsigned r412 = douts3[5];
    unsigned r413 = douts3[6];
    unsigned r414 = douts3[7];
    unsigned r415 = douts3[8];
    unsigned r416 = douts3[9];
    unsigned r417 = douts3[10];
    unsigned r418 = douts3[11];
    unsigned r419 = douts3[12];
    unsigned r420 = douts3[13];
    unsigned r421 = douts3[14];
    unsigned r422 = douts3[15];
    unsigned r423 = douts3[16];
    unsigned r424 = douts3[17];
    unsigned r425 = douts3[18];
    unsigned r426 = douts3[19];
    unsigned r427 = douts3[20];
    unsigned r428 = douts3[21];
    unsigned r429 = douts3[22];
    unsigned r430 = douts3[23];
    unsigned r431 = douts3[24];
    unsigned r432 = douts3[25];
    unsigned r433 = douts3[26];
    unsigned r434 = douts3[27];
    unsigned r435 = douts3[28];
    unsigned r436 = douts3[29];
    unsigned r437 = (r337 & 511u);
    unsigned r438 = (r337 >> 9u);
    unsigned r439 = (r438 & 511u);
    unsigned r440 = (r337 >> 18u);
    unsigned r441 = (r440 & 511u);
    unsigned r442 = (r338 & 511u);
    unsigned r443 = (r338 >> 9u);
    unsigned r444 = (r443 & 511u);
    unsigned r445 = (r338 >> 18u);
    unsigned r446 = (r445 & 511u);
    unsigned r447 = (r339 & 511u);
    unsigned r448 = (r339 >> 9u);
    unsigned r449 = (r448 & 511u);
    unsigned r450 = (r339 >> 18u);
    unsigned r451 = (r450 & 511u);
    unsigned r452 = (r340 & 511u);
    unsigned r453 = (r340 >> 9u);
    unsigned r454 = (r453 & 511u);
    unsigned r455 = (r340 >> 18u);
    unsigned r456 = (r455 & 511u);
    unsigned r457 = (r341 & 511u);
    unsigned r458 = (r341 >> 9u);
    unsigned r459 = (r458 & 511u);
    unsigned r460 = (r341 >> 18u);
    unsigned r461 = (r460 & 511u);
    unsigned r462 = (r342 & 511u);
    unsigned r463 = (r342 >> 9u);
    unsigned r464 = (r463 & 511u);
    unsigned r465 = (r342 >> 18u);
    unsigned r466 = (r465 & 511u);
    unsigned r467 = (r343 & 511u);
    unsigned r468 = (r343 >> 9u);
    unsigned r469 = (r468 & 511u);
    unsigned r470 = (r343 >> 18u);
    unsigned r471 = (r470 & 511u);
    unsigned r472 = (r344 & 511u);
    unsigned r473 = (r344 >> 9u);
    unsigned r474 = (r473 & 511u);
    unsigned r475 = (r344 >> 18u);
    unsigned r476 = (r475 & 511u);
    unsigned r477 = (r345 & 511u);
    unsigned r478 = (r345 >> 9u);
    unsigned r479 = (r478 & 511u);
    unsigned r480 = (r345 >> 18u);
    unsigned r481 = (r480 & 511u);
    unsigned r482 = (r346 & 511u);
    const unsigned dargs4[56] = { r3, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r437, r439, r441, r442, r444, r446, r447, r449, r451, r452, r454, r456, r457, r459, r461, r462, r464, r466, r467, r469, r471, r472, r474, r476, r477, r479, r481, r482 };
    unsigned douts4[28];
    stwo_wit_deduce_felt_mul(dargs4, douts4);
    unsigned r483 = douts4[0];
    unsigned r484 = douts4[1];
    unsigned r485 = douts4[2];
    unsigned r486 = douts4[3];
    unsigned r487 = douts4[4];
    unsigned r488 = douts4[5];
    unsigned r489 = douts4[6];
    unsigned r490 = douts4[7];
    unsigned r491 = douts4[8];
    unsigned r492 = douts4[9];
    unsigned r493 = douts4[10];
    unsigned r494 = douts4[11];
    unsigned r495 = douts4[12];
    unsigned r496 = douts4[13];
    unsigned r497 = douts4[14];
    unsigned r498 = douts4[15];
    unsigned r499 = douts4[16];
    unsigned r500 = douts4[17];
    unsigned r501 = douts4[18];
    unsigned r502 = douts4[19];
    unsigned r503 = douts4[20];
    unsigned r504 = douts4[21];
    unsigned r505 = douts4[22];
    unsigned r506 = douts4[23];
    unsigned r507 = douts4[24];
    unsigned r508 = douts4[25];
    unsigned r509 = douts4[26];
    unsigned r510 = douts4[27];
    const unsigned dargs5[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r483, r484, r485, r486, r487, r488, r489, r490, r491, r492, r493, r494, r495, r496, r497, r498, r499, r500, r501, r502, r503, r504, r505, r506, r507, r508, r509, r510 };
    unsigned douts5[28];
    stwo_wit_deduce_felt_add(dargs5, douts5);
    unsigned r511 = douts5[0];
    unsigned r512 = douts5[1];
    unsigned r513 = douts5[2];
    unsigned r514 = douts5[3];
    unsigned r515 = douts5[4];
    unsigned r516 = douts5[5];
    unsigned r517 = douts5[6];
    unsigned r518 = douts5[7];
    unsigned r519 = douts5[8];
    unsigned r520 = douts5[9];
    unsigned r521 = douts5[10];
    unsigned r522 = douts5[11];
    unsigned r523 = douts5[12];
    unsigned r524 = douts5[13];
    unsigned r525 = douts5[14];
    unsigned r526 = douts5[15];
    unsigned r527 = douts5[16];
    unsigned r528 = douts5[17];
    unsigned r529 = douts5[18];
    unsigned r530 = douts5[19];
    unsigned r531 = douts5[20];
    unsigned r532 = douts5[21];
    unsigned r533 = douts5[22];
    unsigned r534 = douts5[23];
    unsigned r535 = douts5[24];
    unsigned r536 = douts5[25];
    unsigned r537 = douts5[26];
    unsigned r538 = douts5[27];
    unsigned r539 = (r367 & 511u);
    unsigned r540 = (r367 >> 9u);
    unsigned r541 = (r540 & 511u);
    unsigned r542 = (r367 >> 18u);
    unsigned r543 = (r542 & 511u);
    unsigned r544 = (r368 & 511u);
    unsigned r545 = (r368 >> 9u);
    unsigned r546 = (r545 & 511u);
    unsigned r547 = (r368 >> 18u);
    unsigned r548 = (r547 & 511u);
    unsigned r549 = (r369 & 511u);
    unsigned r550 = (r369 >> 9u);
    unsigned r551 = (r550 & 511u);
    unsigned r552 = (r369 >> 18u);
    unsigned r553 = (r552 & 511u);
    unsigned r554 = (r370 & 511u);
    unsigned r555 = (r370 >> 9u);
    unsigned r556 = (r555 & 511u);
    unsigned r557 = (r370 >> 18u);
    unsigned r558 = (r557 & 511u);
    unsigned r559 = (r371 & 511u);
    unsigned r560 = (r371 >> 9u);
    unsigned r561 = (r560 & 511u);
    unsigned r562 = (r371 >> 18u);
    unsigned r563 = (r562 & 511u);
    unsigned r564 = (r372 & 511u);
    unsigned r565 = (r372 >> 9u);
    unsigned r566 = (r565 & 511u);
    unsigned r567 = (r372 >> 18u);
    unsigned r568 = (r567 & 511u);
    unsigned r569 = (r373 & 511u);
    unsigned r570 = (r373 >> 9u);
    unsigned r571 = (r570 & 511u);
    unsigned r572 = (r373 >> 18u);
    unsigned r573 = (r572 & 511u);
    unsigned r574 = (r374 & 511u);
    unsigned r575 = (r374 >> 9u);
    unsigned r576 = (r575 & 511u);
    unsigned r577 = (r374 >> 18u);
    unsigned r578 = (r577 & 511u);
    unsigned r579 = (r375 & 511u);
    unsigned r580 = (r375 >> 9u);
    unsigned r581 = (r580 & 511u);
    unsigned r582 = (r375 >> 18u);
    unsigned r583 = (r582 & 511u);
    unsigned r584 = (r376 & 511u);
    const unsigned dargs6[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r539, r541, r543, r544, r546, r548, r549, r551, r553, r554, r556, r558, r559, r561, r563, r564, r566, r568, r569, r571, r573, r574, r576, r578, r579, r581, r583, r584 };
    unsigned douts6[28];
    stwo_wit_deduce_felt_mul(dargs6, douts6);
    unsigned r585 = douts6[0];
    unsigned r586 = douts6[1];
    unsigned r587 = douts6[2];
    unsigned r588 = douts6[3];
    unsigned r589 = douts6[4];
    unsigned r590 = douts6[5];
    unsigned r591 = douts6[6];
    unsigned r592 = douts6[7];
    unsigned r593 = douts6[8];
    unsigned r594 = douts6[9];
    unsigned r595 = douts6[10];
    unsigned r596 = douts6[11];
    unsigned r597 = douts6[12];
    unsigned r598 = douts6[13];
    unsigned r599 = douts6[14];
    unsigned r600 = douts6[15];
    unsigned r601 = douts6[16];
    unsigned r602 = douts6[17];
    unsigned r603 = douts6[18];
    unsigned r604 = douts6[19];
    unsigned r605 = douts6[20];
    unsigned r606 = douts6[21];
    unsigned r607 = douts6[22];
    unsigned r608 = douts6[23];
    unsigned r609 = douts6[24];
    unsigned r610 = douts6[25];
    unsigned r611 = douts6[26];
    unsigned r612 = douts6[27];
    const unsigned dargs7[56] = { r511, r512, r513, r514, r515, r516, r517, r518, r519, r520, r521, r522, r523, r524, r525, r526, r527, r528, r529, r530, r531, r532, r533, r534, r535, r536, r537, r538, r585, r586, r587, r588, r589, r590, r591, r592, r593, r594, r595, r596, r597, r598, r599, r600, r601, r602, r603, r604, r605, r606, r607, r608, r609, r610, r611, r612 };
    unsigned douts7[28];
    stwo_wit_deduce_felt_add(dargs7, douts7);
    unsigned r613 = douts7[0];
    unsigned r614 = douts7[1];
    unsigned r615 = douts7[2];
    unsigned r616 = douts7[3];
    unsigned r617 = douts7[4];
    unsigned r618 = douts7[5];
    unsigned r619 = douts7[6];
    unsigned r620 = douts7[7];
    unsigned r621 = douts7[8];
    unsigned r622 = douts7[9];
    unsigned r623 = douts7[10];
    unsigned r624 = douts7[11];
    unsigned r625 = douts7[12];
    unsigned r626 = douts7[13];
    unsigned r627 = douts7[14];
    unsigned r628 = douts7[15];
    unsigned r629 = douts7[16];
    unsigned r630 = douts7[17];
    unsigned r631 = douts7[18];
    unsigned r632 = douts7[19];
    unsigned r633 = douts7[20];
    unsigned r634 = douts7[21];
    unsigned r635 = douts7[22];
    unsigned r636 = douts7[23];
    unsigned r637 = douts7[24];
    unsigned r638 = douts7[25];
    unsigned r639 = douts7[26];
    unsigned r640 = douts7[27];
    unsigned r641 = (r397 & 511u);
    unsigned r642 = (r397 >> 9u);
    unsigned r643 = (r642 & 511u);
    unsigned r644 = (r397 >> 18u);
    unsigned r645 = (r644 & 511u);
    unsigned r646 = (r398 & 511u);
    unsigned r647 = (r398 >> 9u);
    unsigned r648 = (r647 & 511u);
    unsigned r649 = (r398 >> 18u);
    unsigned r650 = (r649 & 511u);
    unsigned r651 = (r399 & 511u);
    unsigned r652 = (r399 >> 9u);
    unsigned r653 = (r652 & 511u);
    unsigned r654 = (r399 >> 18u);
    unsigned r655 = (r654 & 511u);
    unsigned r656 = (r400 & 511u);
    unsigned r657 = (r400 >> 9u);
    unsigned r658 = (r657 & 511u);
    unsigned r659 = (r400 >> 18u);
    unsigned r660 = (r659 & 511u);
    unsigned r661 = (r401 & 511u);
    unsigned r662 = (r401 >> 9u);
    unsigned r663 = (r662 & 511u);
    unsigned r664 = (r401 >> 18u);
    unsigned r665 = (r664 & 511u);
    unsigned r666 = (r402 & 511u);
    unsigned r667 = (r402 >> 9u);
    unsigned r668 = (r667 & 511u);
    unsigned r669 = (r402 >> 18u);
    unsigned r670 = (r669 & 511u);
    unsigned r671 = (r403 & 511u);
    unsigned r672 = (r403 >> 9u);
    unsigned r673 = (r672 & 511u);
    unsigned r674 = (r403 >> 18u);
    unsigned r675 = (r674 & 511u);
    unsigned r676 = (r404 & 511u);
    unsigned r677 = (r404 >> 9u);
    unsigned r678 = (r677 & 511u);
    unsigned r679 = (r404 >> 18u);
    unsigned r680 = (r679 & 511u);
    unsigned r681 = (r405 & 511u);
    unsigned r682 = (r405 >> 9u);
    unsigned r683 = (r682 & 511u);
    unsigned r684 = (r405 >> 18u);
    unsigned r685 = (r684 & 511u);
    unsigned r686 = (r406 & 511u);
    const unsigned dargs8[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r641, r643, r645, r646, r648, r650, r651, r653, r655, r656, r658, r660, r661, r663, r665, r666, r668, r670, r671, r673, r675, r676, r678, r680, r681, r683, r685, r686 };
    unsigned douts8[28];
    stwo_wit_deduce_felt_mul(dargs8, douts8);
    unsigned r687 = douts8[0];
    unsigned r688 = douts8[1];
    unsigned r689 = douts8[2];
    unsigned r690 = douts8[3];
    unsigned r691 = douts8[4];
    unsigned r692 = douts8[5];
    unsigned r693 = douts8[6];
    unsigned r694 = douts8[7];
    unsigned r695 = douts8[8];
    unsigned r696 = douts8[9];
    unsigned r697 = douts8[10];
    unsigned r698 = douts8[11];
    unsigned r699 = douts8[12];
    unsigned r700 = douts8[13];
    unsigned r701 = douts8[14];
    unsigned r702 = douts8[15];
    unsigned r703 = douts8[16];
    unsigned r704 = douts8[17];
    unsigned r705 = douts8[18];
    unsigned r706 = douts8[19];
    unsigned r707 = douts8[20];
    unsigned r708 = douts8[21];
    unsigned r709 = douts8[22];
    unsigned r710 = douts8[23];
    unsigned r711 = douts8[24];
    unsigned r712 = douts8[25];
    unsigned r713 = douts8[26];
    unsigned r714 = douts8[27];
    const unsigned dargs9[56] = { r613, r614, r615, r616, r617, r618, r619, r620, r621, r622, r623, r624, r625, r626, r627, r628, r629, r630, r631, r632, r633, r634, r635, r636, r637, r638, r639, r640, r687, r688, r689, r690, r691, r692, r693, r694, r695, r696, r697, r698, r699, r700, r701, r702, r703, r704, r705, r706, r707, r708, r709, r710, r711, r712, r713, r714 };
    unsigned douts9[28];
    stwo_wit_deduce_felt_add(dargs9, douts9);
    unsigned r715 = douts9[0];
    unsigned r716 = douts9[1];
    unsigned r717 = douts9[2];
    unsigned r718 = douts9[3];
    unsigned r719 = douts9[4];
    unsigned r720 = douts9[5];
    unsigned r721 = douts9[6];
    unsigned r722 = douts9[7];
    unsigned r723 = douts9[8];
    unsigned r724 = douts9[9];
    unsigned r725 = douts9[10];
    unsigned r726 = douts9[11];
    unsigned r727 = douts9[12];
    unsigned r728 = douts9[13];
    unsigned r729 = douts9[14];
    unsigned r730 = douts9[15];
    unsigned r731 = douts9[16];
    unsigned r732 = douts9[17];
    unsigned r733 = douts9[18];
    unsigned r734 = douts9[19];
    unsigned r735 = douts9[20];
    unsigned r736 = douts9[21];
    unsigned r737 = douts9[22];
    unsigned r738 = douts9[23];
    unsigned r739 = douts9[24];
    unsigned r740 = douts9[25];
    unsigned r741 = douts9[26];
    unsigned r742 = douts9[27];
    unsigned r743 = (r407 & 511u);
    unsigned r744 = (r407 >> 9u);
    unsigned r745 = (r744 & 511u);
    unsigned r746 = (r407 >> 18u);
    unsigned r747 = (r746 & 511u);
    unsigned r748 = (r408 & 511u);
    unsigned r749 = (r408 >> 9u);
    unsigned r750 = (r749 & 511u);
    unsigned r751 = (r408 >> 18u);
    unsigned r752 = (r751 & 511u);
    unsigned r753 = (r409 & 511u);
    unsigned r754 = (r409 >> 9u);
    unsigned r755 = (r754 & 511u);
    unsigned r756 = (r409 >> 18u);
    unsigned r757 = (r756 & 511u);
    unsigned r758 = (r410 & 511u);
    unsigned r759 = (r410 >> 9u);
    unsigned r760 = (r759 & 511u);
    unsigned r761 = (r410 >> 18u);
    unsigned r762 = (r761 & 511u);
    unsigned r763 = (r411 & 511u);
    unsigned r764 = (r411 >> 9u);
    unsigned r765 = (r764 & 511u);
    unsigned r766 = (r411 >> 18u);
    unsigned r767 = (r766 & 511u);
    unsigned r768 = (r412 & 511u);
    unsigned r769 = (r412 >> 9u);
    unsigned r770 = (r769 & 511u);
    unsigned r771 = (r412 >> 18u);
    unsigned r772 = (r771 & 511u);
    unsigned r773 = (r413 & 511u);
    unsigned r774 = (r413 >> 9u);
    unsigned r775 = (r774 & 511u);
    unsigned r776 = (r413 >> 18u);
    unsigned r777 = (r776 & 511u);
    unsigned r778 = (r414 & 511u);
    unsigned r779 = (r414 >> 9u);
    unsigned r780 = (r779 & 511u);
    unsigned r781 = (r414 >> 18u);
    unsigned r782 = (r781 & 511u);
    unsigned r783 = (r415 & 511u);
    unsigned r784 = (r415 >> 9u);
    unsigned r785 = (r784 & 511u);
    unsigned r786 = (r415 >> 18u);
    unsigned r787 = (r786 & 511u);
    unsigned r788 = (r416 & 511u);
    out_cols[71u][row] = r416;
    lookup_words[74u * row_count + row] = r416;
    const unsigned dargs10[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r743, r745, r747, r748, r750, r752, r753, r755, r757, r758, r760, r762, r763, r765, r767, r768, r770, r772, r773, r775, r777, r778, r780, r782, r783, r785, r787, r788 };
    unsigned douts10[28];
    stwo_wit_deduce_felt_mul(dargs10, douts10);
    unsigned r789 = douts10[0];
    unsigned r790 = douts10[1];
    unsigned r791 = douts10[2];
    unsigned r792 = douts10[3];
    unsigned r793 = douts10[4];
    unsigned r794 = douts10[5];
    unsigned r795 = douts10[6];
    unsigned r796 = douts10[7];
    unsigned r797 = douts10[8];
    unsigned r798 = douts10[9];
    unsigned r799 = douts10[10];
    unsigned r800 = douts10[11];
    unsigned r801 = douts10[12];
    unsigned r802 = douts10[13];
    unsigned r803 = douts10[14];
    unsigned r804 = douts10[15];
    unsigned r805 = douts10[16];
    unsigned r806 = douts10[17];
    unsigned r807 = douts10[18];
    unsigned r808 = douts10[19];
    unsigned r809 = douts10[20];
    unsigned r810 = douts10[21];
    unsigned r811 = douts10[22];
    unsigned r812 = douts10[23];
    unsigned r813 = douts10[24];
    unsigned r814 = douts10[25];
    unsigned r815 = douts10[26];
    unsigned r816 = douts10[27];
    const unsigned dargs11[56] = { r715, r716, r717, r718, r719, r720, r721, r722, r723, r724, r725, r726, r727, r728, r729, r730, r731, r732, r733, r734, r735, r736, r737, r738, r739, r740, r741, r742, r789, r790, r791, r792, r793, r794, r795, r796, r797, r798, r799, r800, r801, r802, r803, r804, r805, r806, r807, r808, r809, r810, r811, r812, r813, r814, r815, r816 };
    unsigned douts11[28];
    stwo_wit_deduce_felt_add(dargs11, douts11);
    unsigned r817 = douts11[0];
    unsigned r818 = douts11[1];
    unsigned r819 = douts11[2];
    unsigned r820 = douts11[3];
    unsigned r821 = douts11[4];
    unsigned r822 = douts11[5];
    unsigned r823 = douts11[6];
    unsigned r824 = douts11[7];
    unsigned r825 = douts11[8];
    unsigned r826 = douts11[9];
    unsigned r827 = douts11[10];
    unsigned r828 = douts11[11];
    unsigned r829 = douts11[12];
    unsigned r830 = douts11[13];
    unsigned r831 = douts11[14];
    unsigned r832 = douts11[15];
    unsigned r833 = douts11[16];
    unsigned r834 = douts11[17];
    unsigned r835 = douts11[18];
    unsigned r836 = douts11[19];
    unsigned r837 = douts11[20];
    unsigned r838 = douts11[21];
    unsigned r839 = douts11[22];
    unsigned r840 = douts11[23];
    unsigned r841 = douts11[24];
    unsigned r842 = douts11[25];
    unsigned r843 = douts11[26];
    unsigned r844 = douts11[27];
    out_cols[101u][row] = r844;
    lookup_words[176u * row_count + row] = r844;
    unsigned r845 = stwo_m31_mul(r818, r6);
    unsigned r846 = stwo_m31_add(r817, r845);
    unsigned r847 = stwo_m31_mul(r819, r7);
    unsigned r848 = stwo_m31_add(r846, r847);
    unsigned r849 = stwo_m31_mul(r821, r6);
    unsigned r850 = stwo_m31_add(r820, r849);
    unsigned r851 = stwo_m31_mul(r822, r7);
    unsigned r852 = stwo_m31_add(r850, r851);
    unsigned r853 = stwo_m31_mul(r824, r6);
    unsigned r854 = stwo_m31_add(r823, r853);
    unsigned r855 = stwo_m31_mul(r825, r7);
    unsigned r856 = stwo_m31_add(r854, r855);
    unsigned r857 = stwo_m31_mul(r827, r6);
    unsigned r858 = stwo_m31_add(r826, r857);
    unsigned r859 = stwo_m31_mul(r828, r7);
    unsigned r860 = stwo_m31_add(r858, r859);
    unsigned r861 = stwo_m31_mul(r830, r6);
    unsigned r862 = stwo_m31_add(r829, r861);
    unsigned r863 = stwo_m31_mul(r831, r7);
    unsigned r864 = stwo_m31_add(r862, r863);
    unsigned r865 = stwo_m31_mul(r833, r6);
    unsigned r866 = stwo_m31_add(r832, r865);
    unsigned r867 = stwo_m31_mul(r834, r7);
    unsigned r868 = stwo_m31_add(r866, r867);
    unsigned r869 = stwo_m31_mul(r836, r6);
    unsigned r870 = stwo_m31_add(r835, r869);
    unsigned r871 = stwo_m31_mul(r837, r7);
    unsigned r872 = stwo_m31_add(r870, r871);
    unsigned r873 = stwo_m31_mul(r839, r6);
    unsigned r874 = stwo_m31_add(r838, r873);
    unsigned r875 = stwo_m31_mul(r840, r7);
    unsigned r876 = stwo_m31_add(r874, r875);
    unsigned r877 = stwo_m31_mul(r842, r6);
    unsigned r878 = stwo_m31_add(r841, r877);
    unsigned r879 = stwo_m31_mul(r843, r7);
    unsigned r880 = stwo_m31_add(r878, r879);
    unsigned r881 = stwo_m31_mul(r3, r337);
    unsigned r882 = stwo_m31_add(r881, r367);
    unsigned r883 = stwo_m31_add(r882, r397);
    unsigned r884 = stwo_m31_add(r883, r407);
    unsigned r885 = stwo_m31_sub(r884, r848);
    unsigned r886 = stwo_m31_add(r885, r8);
    unsigned r887 = (r886 & 65535u);
    unsigned r888 = (r887 % STWO_M31_P);
    unsigned r889 = stwo_m31_sub(r888, r1);
    unsigned r890 = stwo_m31_mul(r3, r337);
    unsigned r891 = stwo_m31_add(r890, r367);
    unsigned r892 = stwo_m31_add(r891, r397);
    unsigned r893 = stwo_m31_add(r892, r407);
    out_cols[62u][row] = r407;
    lookup_words[65u * row_count + row] = r407;
    unsigned r894 = stwo_m31_sub(r893, r848);
    out_cols[92u][row] = r848;
    lookup_words[167u * row_count + row] = r848;
    unsigned r895 = stwo_m31_sub(r894, r889);
    unsigned r896 = stwo_m31_mul(r895, r4);
    unsigned r897 = stwo_m31_mul(r3, r338);
    unsigned r898 = stwo_m31_add(r896, r897);
    unsigned r899 = stwo_m31_add(r898, r368);
    unsigned r900 = stwo_m31_add(r899, r398);
    unsigned r901 = stwo_m31_add(r900, r408);
    out_cols[63u][row] = r408;
    lookup_words[66u * row_count + row] = r408;
    unsigned r902 = stwo_m31_sub(r901, r852);
    out_cols[93u][row] = r852;
    lookup_words[168u * row_count + row] = r852;
    unsigned r903 = stwo_m31_mul(r902, r4);
    unsigned r904 = stwo_m31_mul(r3, r339);
    unsigned r905 = stwo_m31_add(r903, r904);
    unsigned r906 = stwo_m31_add(r905, r369);
    unsigned r907 = stwo_m31_add(r906, r399);
    unsigned r908 = stwo_m31_add(r907, r409);
    out_cols[64u][row] = r409;
    lookup_words[67u * row_count + row] = r409;
    unsigned r909 = stwo_m31_sub(r908, r856);
    out_cols[94u][row] = r856;
    lookup_words[169u * row_count + row] = r856;
    unsigned r910 = stwo_m31_mul(r909, r4);
    unsigned r911 = stwo_m31_mul(r3, r340);
    unsigned r912 = stwo_m31_add(r910, r911);
    unsigned r913 = stwo_m31_add(r912, r370);
    unsigned r914 = stwo_m31_add(r913, r400);
    unsigned r915 = stwo_m31_add(r914, r410);
    out_cols[65u][row] = r410;
    lookup_words[68u * row_count + row] = r410;
    unsigned r916 = stwo_m31_sub(r915, r860);
    out_cols[95u][row] = r860;
    lookup_words[170u * row_count + row] = r860;
    unsigned r917 = stwo_m31_mul(r916, r4);
    unsigned r918 = stwo_m31_mul(r3, r341);
    unsigned r919 = stwo_m31_add(r917, r918);
    unsigned r920 = stwo_m31_add(r919, r371);
    unsigned r921 = stwo_m31_add(r920, r401);
    unsigned r922 = stwo_m31_add(r921, r411);
    out_cols[66u][row] = r411;
    lookup_words[69u * row_count + row] = r411;
    unsigned r923 = stwo_m31_sub(r922, r864);
    out_cols[96u][row] = r864;
    lookup_words[171u * row_count + row] = r864;
    unsigned r924 = stwo_m31_mul(r923, r4);
    unsigned r925 = stwo_m31_mul(r3, r342);
    unsigned r926 = stwo_m31_add(r924, r925);
    unsigned r927 = stwo_m31_add(r926, r372);
    unsigned r928 = stwo_m31_add(r927, r402);
    unsigned r929 = stwo_m31_add(r928, r412);
    out_cols[67u][row] = r412;
    lookup_words[70u * row_count + row] = r412;
    unsigned r930 = stwo_m31_sub(r929, r868);
    out_cols[97u][row] = r868;
    lookup_words[172u * row_count + row] = r868;
    unsigned r931 = stwo_m31_mul(r930, r4);
    unsigned r932 = stwo_m31_mul(r3, r343);
    unsigned r933 = stwo_m31_add(r931, r932);
    unsigned r934 = stwo_m31_add(r933, r373);
    unsigned r935 = stwo_m31_add(r934, r403);
    unsigned r936 = stwo_m31_add(r935, r413);
    out_cols[68u][row] = r413;
    lookup_words[71u * row_count + row] = r413;
    unsigned r937 = stwo_m31_sub(r936, r872);
    out_cols[98u][row] = r872;
    lookup_words[173u * row_count + row] = r872;
    unsigned r938 = stwo_m31_mul(r937, r4);
    unsigned r939 = stwo_m31_mul(r3, r344);
    unsigned r940 = stwo_m31_add(r938, r939);
    unsigned r941 = stwo_m31_add(r940, r374);
    unsigned r942 = stwo_m31_add(r941, r404);
    unsigned r943 = stwo_m31_add(r942, r414);
    out_cols[69u][row] = r414;
    lookup_words[72u * row_count + row] = r414;
    unsigned r944 = stwo_m31_sub(r943, r876);
    out_cols[99u][row] = r876;
    lookup_words[174u * row_count + row] = r876;
    unsigned r945 = stwo_m31_mul(r889, r5);
    unsigned r946 = stwo_m31_sub(r944, r945);
    unsigned r947 = stwo_m31_mul(r946, r4);
    unsigned r948 = stwo_m31_mul(r3, r345);
    unsigned r949 = stwo_m31_add(r947, r948);
    unsigned r950 = stwo_m31_add(r949, r375);
    unsigned r951 = stwo_m31_add(r950, r405);
    unsigned r952 = stwo_m31_add(r951, r415);
    out_cols[70u][row] = r415;
    lookup_words[73u * row_count + row] = r415;
    unsigned r953 = stwo_m31_sub(r952, r880);
    out_cols[100u][row] = r880;
    lookup_words[175u * row_count + row] = r880;
    unsigned r954 = stwo_m31_mul(r953, r4);
    unsigned r955 = stwo_m31_add(r889, r1);
    sub_words[31u * row_count + row] = r955;
    unsigned r956 = stwo_m31_add(r896, r1);
    sub_words[32u * row_count + row] = r956;
    unsigned r957 = stwo_m31_add(r903, r1);
    sub_words[33u * row_count + row] = r957;
    unsigned r958 = stwo_m31_add(r910, r1);
    sub_words[34u * row_count + row] = r958;
    unsigned r959 = stwo_m31_add(r917, r1);
    sub_words[35u * row_count + row] = r959;
    unsigned r960 = stwo_m31_add(r889, r1);
    out_cols[102u][row] = r889;
    lookup_words[96u * row_count + row] = r960;
    unsigned r961 = stwo_m31_add(r896, r1);
    lookup_words[97u * row_count + row] = r961;
    unsigned r962 = stwo_m31_add(r903, r1);
    lookup_words[98u * row_count + row] = r962;
    unsigned r963 = stwo_m31_add(r910, r1);
    lookup_words[99u * row_count + row] = r963;
    unsigned r964 = stwo_m31_add(r917, r1);
    lookup_words[100u * row_count + row] = r964;
    unsigned r965 = stwo_m31_add(r924, r1);
    sub_words[36u * row_count + row] = r965;
    unsigned r966 = stwo_m31_add(r931, r1);
    sub_words[37u * row_count + row] = r966;
    unsigned r967 = stwo_m31_add(r938, r1);
    sub_words[38u * row_count + row] = r967;
    unsigned r968 = stwo_m31_add(r947, r1);
    sub_words[39u * row_count + row] = r968;
    unsigned r969 = stwo_m31_add(r954, r1);
    sub_words[40u * row_count + row] = r969;
    unsigned r970 = stwo_m31_add(r924, r1);
    lookup_words[102u * row_count + row] = r970;
    unsigned r971 = stwo_m31_add(r931, r1);
    lookup_words[103u * row_count + row] = r971;
    unsigned r972 = stwo_m31_add(r938, r1);
    lookup_words[104u * row_count + row] = r972;
    unsigned r973 = stwo_m31_add(r947, r1);
    lookup_words[105u * row_count + row] = r973;
    unsigned r974 = stwo_m31_add(r954, r1);
    lookup_words[106u * row_count + row] = r974;
    unsigned r975 = (r337 & 511u);
    unsigned r976 = (r337 >> 9u);
    unsigned r977 = (r976 & 511u);
    unsigned r978 = (r337 >> 18u);
    unsigned r979 = (r978 & 511u);
    unsigned r980 = (r338 & 511u);
    unsigned r981 = (r338 >> 9u);
    unsigned r982 = (r981 & 511u);
    unsigned r983 = (r338 >> 18u);
    unsigned r984 = (r983 & 511u);
    unsigned r985 = (r339 & 511u);
    unsigned r986 = (r339 >> 9u);
    unsigned r987 = (r986 & 511u);
    unsigned r988 = (r339 >> 18u);
    unsigned r989 = (r988 & 511u);
    unsigned r990 = (r340 & 511u);
    unsigned r991 = (r340 >> 9u);
    unsigned r992 = (r991 & 511u);
    unsigned r993 = (r340 >> 18u);
    unsigned r994 = (r993 & 511u);
    unsigned r995 = (r341 & 511u);
    unsigned r996 = (r341 >> 9u);
    unsigned r997 = (r996 & 511u);
    unsigned r998 = (r341 >> 18u);
    unsigned r999 = (r998 & 511u);
    unsigned r1000 = (r342 & 511u);
    unsigned r1001 = (r342 >> 9u);
    unsigned r1002 = (r1001 & 511u);
    unsigned r1003 = (r342 >> 18u);
    unsigned r1004 = (r1003 & 511u);
    unsigned r1005 = (r343 & 511u);
    unsigned r1006 = (r343 >> 9u);
    unsigned r1007 = (r1006 & 511u);
    unsigned r1008 = (r343 >> 18u);
    unsigned r1009 = (r1008 & 511u);
    unsigned r1010 = (r344 & 511u);
    unsigned r1011 = (r344 >> 9u);
    unsigned r1012 = (r1011 & 511u);
    unsigned r1013 = (r344 >> 18u);
    unsigned r1014 = (r1013 & 511u);
    unsigned r1015 = (r345 & 511u);
    unsigned r1016 = (r345 >> 9u);
    unsigned r1017 = (r1016 & 511u);
    unsigned r1018 = (r345 >> 18u);
    unsigned r1019 = (r1018 & 511u);
    unsigned r1020 = (r346 & 511u);
    const unsigned dargs12[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r975, r977, r979, r980, r982, r984, r985, r987, r989, r990, r992, r994, r995, r997, r999, r1000, r1002, r1004, r1005, r1007, r1009, r1010, r1012, r1014, r1015, r1017, r1019, r1020 };
    unsigned douts12[28];
    stwo_wit_deduce_felt_mul(dargs12, douts12);
    unsigned r1021 = douts12[0];
    unsigned r1022 = douts12[1];
    unsigned r1023 = douts12[2];
    unsigned r1024 = douts12[3];
    unsigned r1025 = douts12[4];
    unsigned r1026 = douts12[5];
    unsigned r1027 = douts12[6];
    unsigned r1028 = douts12[7];
    unsigned r1029 = douts12[8];
    unsigned r1030 = douts12[9];
    unsigned r1031 = douts12[10];
    unsigned r1032 = douts12[11];
    unsigned r1033 = douts12[12];
    unsigned r1034 = douts12[13];
    unsigned r1035 = douts12[14];
    unsigned r1036 = douts12[15];
    unsigned r1037 = douts12[16];
    unsigned r1038 = douts12[17];
    unsigned r1039 = douts12[18];
    unsigned r1040 = douts12[19];
    unsigned r1041 = douts12[20];
    unsigned r1042 = douts12[21];
    unsigned r1043 = douts12[22];
    unsigned r1044 = douts12[23];
    unsigned r1045 = douts12[24];
    unsigned r1046 = douts12[25];
    unsigned r1047 = douts12[26];
    unsigned r1048 = douts12[27];
    const unsigned dargs13[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1021, r1022, r1023, r1024, r1025, r1026, r1027, r1028, r1029, r1030, r1031, r1032, r1033, r1034, r1035, r1036, r1037, r1038, r1039, r1040, r1041, r1042, r1043, r1044, r1045, r1046, r1047, r1048 };
    unsigned douts13[28];
    stwo_wit_deduce_felt_add(dargs13, douts13);
    unsigned r1049 = douts13[0];
    unsigned r1050 = douts13[1];
    unsigned r1051 = douts13[2];
    unsigned r1052 = douts13[3];
    unsigned r1053 = douts13[4];
    unsigned r1054 = douts13[5];
    unsigned r1055 = douts13[6];
    unsigned r1056 = douts13[7];
    unsigned r1057 = douts13[8];
    unsigned r1058 = douts13[9];
    unsigned r1059 = douts13[10];
    unsigned r1060 = douts13[11];
    unsigned r1061 = douts13[12];
    unsigned r1062 = douts13[13];
    unsigned r1063 = douts13[14];
    unsigned r1064 = douts13[15];
    unsigned r1065 = douts13[16];
    unsigned r1066 = douts13[17];
    unsigned r1067 = douts13[18];
    unsigned r1068 = douts13[19];
    unsigned r1069 = douts13[20];
    unsigned r1070 = douts13[21];
    unsigned r1071 = douts13[22];
    unsigned r1072 = douts13[23];
    unsigned r1073 = douts13[24];
    unsigned r1074 = douts13[25];
    unsigned r1075 = douts13[26];
    unsigned r1076 = douts13[27];
    unsigned r1077 = (r367 & 511u);
    unsigned r1078 = (r367 >> 9u);
    unsigned r1079 = (r1078 & 511u);
    unsigned r1080 = (r367 >> 18u);
    unsigned r1081 = (r1080 & 511u);
    unsigned r1082 = (r368 & 511u);
    unsigned r1083 = (r368 >> 9u);
    unsigned r1084 = (r1083 & 511u);
    unsigned r1085 = (r368 >> 18u);
    unsigned r1086 = (r1085 & 511u);
    unsigned r1087 = (r369 & 511u);
    unsigned r1088 = (r369 >> 9u);
    unsigned r1089 = (r1088 & 511u);
    unsigned r1090 = (r369 >> 18u);
    unsigned r1091 = (r1090 & 511u);
    unsigned r1092 = (r370 & 511u);
    unsigned r1093 = (r370 >> 9u);
    unsigned r1094 = (r1093 & 511u);
    unsigned r1095 = (r370 >> 18u);
    unsigned r1096 = (r1095 & 511u);
    unsigned r1097 = (r371 & 511u);
    unsigned r1098 = (r371 >> 9u);
    unsigned r1099 = (r1098 & 511u);
    unsigned r1100 = (r371 >> 18u);
    unsigned r1101 = (r1100 & 511u);
    unsigned r1102 = (r372 & 511u);
    unsigned r1103 = (r372 >> 9u);
    unsigned r1104 = (r1103 & 511u);
    unsigned r1105 = (r372 >> 18u);
    unsigned r1106 = (r1105 & 511u);
    unsigned r1107 = (r373 & 511u);
    unsigned r1108 = (r373 >> 9u);
    unsigned r1109 = (r1108 & 511u);
    unsigned r1110 = (r373 >> 18u);
    unsigned r1111 = (r1110 & 511u);
    unsigned r1112 = (r374 & 511u);
    unsigned r1113 = (r374 >> 9u);
    unsigned r1114 = (r1113 & 511u);
    unsigned r1115 = (r374 >> 18u);
    unsigned r1116 = (r1115 & 511u);
    unsigned r1117 = (r375 & 511u);
    unsigned r1118 = (r375 >> 9u);
    unsigned r1119 = (r1118 & 511u);
    unsigned r1120 = (r375 >> 18u);
    unsigned r1121 = (r1120 & 511u);
    unsigned r1122 = (r376 & 511u);
    const unsigned dargs14[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1077, r1079, r1081, r1082, r1084, r1086, r1087, r1089, r1091, r1092, r1094, r1096, r1097, r1099, r1101, r1102, r1104, r1106, r1107, r1109, r1111, r1112, r1114, r1116, r1117, r1119, r1121, r1122 };
    unsigned douts14[28];
    stwo_wit_deduce_felt_mul(dargs14, douts14);
    unsigned r1123 = douts14[0];
    unsigned r1124 = douts14[1];
    unsigned r1125 = douts14[2];
    unsigned r1126 = douts14[3];
    unsigned r1127 = douts14[4];
    unsigned r1128 = douts14[5];
    unsigned r1129 = douts14[6];
    unsigned r1130 = douts14[7];
    unsigned r1131 = douts14[8];
    unsigned r1132 = douts14[9];
    unsigned r1133 = douts14[10];
    unsigned r1134 = douts14[11];
    unsigned r1135 = douts14[12];
    unsigned r1136 = douts14[13];
    unsigned r1137 = douts14[14];
    unsigned r1138 = douts14[15];
    unsigned r1139 = douts14[16];
    unsigned r1140 = douts14[17];
    unsigned r1141 = douts14[18];
    unsigned r1142 = douts14[19];
    unsigned r1143 = douts14[20];
    unsigned r1144 = douts14[21];
    unsigned r1145 = douts14[22];
    unsigned r1146 = douts14[23];
    unsigned r1147 = douts14[24];
    unsigned r1148 = douts14[25];
    unsigned r1149 = douts14[26];
    unsigned r1150 = douts14[27];
    const unsigned dargs15[56] = { r1049, r1050, r1051, r1052, r1053, r1054, r1055, r1056, r1057, r1058, r1059, r1060, r1061, r1062, r1063, r1064, r1065, r1066, r1067, r1068, r1069, r1070, r1071, r1072, r1073, r1074, r1075, r1076, r1123, r1124, r1125, r1126, r1127, r1128, r1129, r1130, r1131, r1132, r1133, r1134, r1135, r1136, r1137, r1138, r1139, r1140, r1141, r1142, r1143, r1144, r1145, r1146, r1147, r1148, r1149, r1150 };
    unsigned douts15[28];
    stwo_wit_deduce_felt_sub(dargs15, douts15);
    unsigned r1151 = douts15[0];
    unsigned r1152 = douts15[1];
    unsigned r1153 = douts15[2];
    unsigned r1154 = douts15[3];
    unsigned r1155 = douts15[4];
    unsigned r1156 = douts15[5];
    unsigned r1157 = douts15[6];
    unsigned r1158 = douts15[7];
    unsigned r1159 = douts15[8];
    unsigned r1160 = douts15[9];
    unsigned r1161 = douts15[10];
    unsigned r1162 = douts15[11];
    unsigned r1163 = douts15[12];
    unsigned r1164 = douts15[13];
    unsigned r1165 = douts15[14];
    unsigned r1166 = douts15[15];
    unsigned r1167 = douts15[16];
    unsigned r1168 = douts15[17];
    unsigned r1169 = douts15[18];
    unsigned r1170 = douts15[19];
    unsigned r1171 = douts15[20];
    unsigned r1172 = douts15[21];
    unsigned r1173 = douts15[22];
    unsigned r1174 = douts15[23];
    unsigned r1175 = douts15[24];
    unsigned r1176 = douts15[25];
    unsigned r1177 = douts15[26];
    unsigned r1178 = douts15[27];
    unsigned r1179 = (r397 & 511u);
    unsigned r1180 = (r397 >> 9u);
    unsigned r1181 = (r1180 & 511u);
    unsigned r1182 = (r397 >> 18u);
    unsigned r1183 = (r1182 & 511u);
    unsigned r1184 = (r398 & 511u);
    unsigned r1185 = (r398 >> 9u);
    unsigned r1186 = (r1185 & 511u);
    unsigned r1187 = (r398 >> 18u);
    unsigned r1188 = (r1187 & 511u);
    unsigned r1189 = (r399 & 511u);
    unsigned r1190 = (r399 >> 9u);
    unsigned r1191 = (r1190 & 511u);
    unsigned r1192 = (r399 >> 18u);
    unsigned r1193 = (r1192 & 511u);
    unsigned r1194 = (r400 & 511u);
    unsigned r1195 = (r400 >> 9u);
    unsigned r1196 = (r1195 & 511u);
    unsigned r1197 = (r400 >> 18u);
    unsigned r1198 = (r1197 & 511u);
    unsigned r1199 = (r401 & 511u);
    unsigned r1200 = (r401 >> 9u);
    unsigned r1201 = (r1200 & 511u);
    unsigned r1202 = (r401 >> 18u);
    unsigned r1203 = (r1202 & 511u);
    unsigned r1204 = (r402 & 511u);
    unsigned r1205 = (r402 >> 9u);
    unsigned r1206 = (r1205 & 511u);
    unsigned r1207 = (r402 >> 18u);
    unsigned r1208 = (r1207 & 511u);
    unsigned r1209 = (r403 & 511u);
    unsigned r1210 = (r403 >> 9u);
    unsigned r1211 = (r1210 & 511u);
    unsigned r1212 = (r403 >> 18u);
    unsigned r1213 = (r1212 & 511u);
    unsigned r1214 = (r404 & 511u);
    unsigned r1215 = (r404 >> 9u);
    unsigned r1216 = (r1215 & 511u);
    unsigned r1217 = (r404 >> 18u);
    unsigned r1218 = (r1217 & 511u);
    unsigned r1219 = (r405 & 511u);
    unsigned r1220 = (r405 >> 9u);
    unsigned r1221 = (r1220 & 511u);
    unsigned r1222 = (r405 >> 18u);
    unsigned r1223 = (r1222 & 511u);
    unsigned r1224 = (r406 & 511u);
    const unsigned dargs16[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1179, r1181, r1183, r1184, r1186, r1188, r1189, r1191, r1193, r1194, r1196, r1198, r1199, r1201, r1203, r1204, r1206, r1208, r1209, r1211, r1213, r1214, r1216, r1218, r1219, r1221, r1223, r1224 };
    unsigned douts16[28];
    stwo_wit_deduce_felt_mul(dargs16, douts16);
    unsigned r1225 = douts16[0];
    unsigned r1226 = douts16[1];
    unsigned r1227 = douts16[2];
    unsigned r1228 = douts16[3];
    unsigned r1229 = douts16[4];
    unsigned r1230 = douts16[5];
    unsigned r1231 = douts16[6];
    unsigned r1232 = douts16[7];
    unsigned r1233 = douts16[8];
    unsigned r1234 = douts16[9];
    unsigned r1235 = douts16[10];
    unsigned r1236 = douts16[11];
    unsigned r1237 = douts16[12];
    unsigned r1238 = douts16[13];
    unsigned r1239 = douts16[14];
    unsigned r1240 = douts16[15];
    unsigned r1241 = douts16[16];
    unsigned r1242 = douts16[17];
    unsigned r1243 = douts16[18];
    unsigned r1244 = douts16[19];
    unsigned r1245 = douts16[20];
    unsigned r1246 = douts16[21];
    unsigned r1247 = douts16[22];
    unsigned r1248 = douts16[23];
    unsigned r1249 = douts16[24];
    unsigned r1250 = douts16[25];
    unsigned r1251 = douts16[26];
    unsigned r1252 = douts16[27];
    const unsigned dargs17[56] = { r1151, r1152, r1153, r1154, r1155, r1156, r1157, r1158, r1159, r1160, r1161, r1162, r1163, r1164, r1165, r1166, r1167, r1168, r1169, r1170, r1171, r1172, r1173, r1174, r1175, r1176, r1177, r1178, r1225, r1226, r1227, r1228, r1229, r1230, r1231, r1232, r1233, r1234, r1235, r1236, r1237, r1238, r1239, r1240, r1241, r1242, r1243, r1244, r1245, r1246, r1247, r1248, r1249, r1250, r1251, r1252 };
    unsigned douts17[28];
    stwo_wit_deduce_felt_add(dargs17, douts17);
    unsigned r1253 = douts17[0];
    unsigned r1254 = douts17[1];
    unsigned r1255 = douts17[2];
    unsigned r1256 = douts17[3];
    unsigned r1257 = douts17[4];
    unsigned r1258 = douts17[5];
    unsigned r1259 = douts17[6];
    unsigned r1260 = douts17[7];
    unsigned r1261 = douts17[8];
    unsigned r1262 = douts17[9];
    unsigned r1263 = douts17[10];
    unsigned r1264 = douts17[11];
    unsigned r1265 = douts17[12];
    unsigned r1266 = douts17[13];
    unsigned r1267 = douts17[14];
    unsigned r1268 = douts17[15];
    unsigned r1269 = douts17[16];
    unsigned r1270 = douts17[17];
    unsigned r1271 = douts17[18];
    unsigned r1272 = douts17[19];
    unsigned r1273 = douts17[20];
    unsigned r1274 = douts17[21];
    unsigned r1275 = douts17[22];
    unsigned r1276 = douts17[23];
    unsigned r1277 = douts17[24];
    unsigned r1278 = douts17[25];
    unsigned r1279 = douts17[26];
    unsigned r1280 = douts17[27];
    unsigned r1281 = (r417 & 511u);
    unsigned r1282 = (r417 >> 9u);
    unsigned r1283 = (r1282 & 511u);
    unsigned r1284 = (r417 >> 18u);
    unsigned r1285 = (r1284 & 511u);
    unsigned r1286 = (r418 & 511u);
    unsigned r1287 = (r418 >> 9u);
    unsigned r1288 = (r1287 & 511u);
    unsigned r1289 = (r418 >> 18u);
    unsigned r1290 = (r1289 & 511u);
    unsigned r1291 = (r419 & 511u);
    unsigned r1292 = (r419 >> 9u);
    unsigned r1293 = (r1292 & 511u);
    unsigned r1294 = (r419 >> 18u);
    unsigned r1295 = (r1294 & 511u);
    unsigned r1296 = (r420 & 511u);
    unsigned r1297 = (r420 >> 9u);
    unsigned r1298 = (r1297 & 511u);
    unsigned r1299 = (r420 >> 18u);
    unsigned r1300 = (r1299 & 511u);
    unsigned r1301 = (r421 & 511u);
    unsigned r1302 = (r421 >> 9u);
    unsigned r1303 = (r1302 & 511u);
    unsigned r1304 = (r421 >> 18u);
    unsigned r1305 = (r1304 & 511u);
    unsigned r1306 = (r422 & 511u);
    unsigned r1307 = (r422 >> 9u);
    unsigned r1308 = (r1307 & 511u);
    unsigned r1309 = (r422 >> 18u);
    unsigned r1310 = (r1309 & 511u);
    unsigned r1311 = (r423 & 511u);
    unsigned r1312 = (r423 >> 9u);
    unsigned r1313 = (r1312 & 511u);
    unsigned r1314 = (r423 >> 18u);
    unsigned r1315 = (r1314 & 511u);
    unsigned r1316 = (r424 & 511u);
    unsigned r1317 = (r424 >> 9u);
    unsigned r1318 = (r1317 & 511u);
    unsigned r1319 = (r424 >> 18u);
    unsigned r1320 = (r1319 & 511u);
    unsigned r1321 = (r425 & 511u);
    unsigned r1322 = (r425 >> 9u);
    unsigned r1323 = (r1322 & 511u);
    unsigned r1324 = (r425 >> 18u);
    unsigned r1325 = (r1324 & 511u);
    unsigned r1326 = (r426 & 511u);
    out_cols[81u][row] = r426;
    lookup_words[84u * row_count + row] = r426;
    const unsigned dargs18[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1281, r1283, r1285, r1286, r1288, r1290, r1291, r1293, r1295, r1296, r1298, r1300, r1301, r1303, r1305, r1306, r1308, r1310, r1311, r1313, r1315, r1316, r1318, r1320, r1321, r1323, r1325, r1326 };
    unsigned douts18[28];
    stwo_wit_deduce_felt_mul(dargs18, douts18);
    unsigned r1327 = douts18[0];
    unsigned r1328 = douts18[1];
    unsigned r1329 = douts18[2];
    unsigned r1330 = douts18[3];
    unsigned r1331 = douts18[4];
    unsigned r1332 = douts18[5];
    unsigned r1333 = douts18[6];
    unsigned r1334 = douts18[7];
    unsigned r1335 = douts18[8];
    unsigned r1336 = douts18[9];
    unsigned r1337 = douts18[10];
    unsigned r1338 = douts18[11];
    unsigned r1339 = douts18[12];
    unsigned r1340 = douts18[13];
    unsigned r1341 = douts18[14];
    unsigned r1342 = douts18[15];
    unsigned r1343 = douts18[16];
    unsigned r1344 = douts18[17];
    unsigned r1345 = douts18[18];
    unsigned r1346 = douts18[19];
    unsigned r1347 = douts18[20];
    unsigned r1348 = douts18[21];
    unsigned r1349 = douts18[22];
    unsigned r1350 = douts18[23];
    unsigned r1351 = douts18[24];
    unsigned r1352 = douts18[25];
    unsigned r1353 = douts18[26];
    unsigned r1354 = douts18[27];
    const unsigned dargs19[56] = { r1253, r1254, r1255, r1256, r1257, r1258, r1259, r1260, r1261, r1262, r1263, r1264, r1265, r1266, r1267, r1268, r1269, r1270, r1271, r1272, r1273, r1274, r1275, r1276, r1277, r1278, r1279, r1280, r1327, r1328, r1329, r1330, r1331, r1332, r1333, r1334, r1335, r1336, r1337, r1338, r1339, r1340, r1341, r1342, r1343, r1344, r1345, r1346, r1347, r1348, r1349, r1350, r1351, r1352, r1353, r1354 };
    unsigned douts19[28];
    stwo_wit_deduce_felt_add(dargs19, douts19);
    unsigned r1355 = douts19[0];
    unsigned r1356 = douts19[1];
    unsigned r1357 = douts19[2];
    unsigned r1358 = douts19[3];
    unsigned r1359 = douts19[4];
    unsigned r1360 = douts19[5];
    unsigned r1361 = douts19[6];
    unsigned r1362 = douts19[7];
    unsigned r1363 = douts19[8];
    unsigned r1364 = douts19[9];
    unsigned r1365 = douts19[10];
    unsigned r1366 = douts19[11];
    unsigned r1367 = douts19[12];
    unsigned r1368 = douts19[13];
    unsigned r1369 = douts19[14];
    unsigned r1370 = douts19[15];
    unsigned r1371 = douts19[16];
    unsigned r1372 = douts19[17];
    unsigned r1373 = douts19[18];
    unsigned r1374 = douts19[19];
    unsigned r1375 = douts19[20];
    unsigned r1376 = douts19[21];
    unsigned r1377 = douts19[22];
    unsigned r1378 = douts19[23];
    unsigned r1379 = douts19[24];
    unsigned r1380 = douts19[25];
    unsigned r1381 = douts19[26];
    unsigned r1382 = douts19[27];
    out_cols[112u][row] = r1382;
    lookup_words[186u * row_count + row] = r1382;
    unsigned r1383 = stwo_m31_mul(r1356, r6);
    unsigned r1384 = stwo_m31_add(r1355, r1383);
    unsigned r1385 = stwo_m31_mul(r1357, r7);
    unsigned r1386 = stwo_m31_add(r1384, r1385);
    unsigned r1387 = stwo_m31_mul(r1359, r6);
    unsigned r1388 = stwo_m31_add(r1358, r1387);
    unsigned r1389 = stwo_m31_mul(r1360, r7);
    unsigned r1390 = stwo_m31_add(r1388, r1389);
    unsigned r1391 = stwo_m31_mul(r1362, r6);
    unsigned r1392 = stwo_m31_add(r1361, r1391);
    unsigned r1393 = stwo_m31_mul(r1363, r7);
    unsigned r1394 = stwo_m31_add(r1392, r1393);
    unsigned r1395 = stwo_m31_mul(r1365, r6);
    unsigned r1396 = stwo_m31_add(r1364, r1395);
    unsigned r1397 = stwo_m31_mul(r1366, r7);
    unsigned r1398 = stwo_m31_add(r1396, r1397);
    unsigned r1399 = stwo_m31_mul(r1368, r6);
    unsigned r1400 = stwo_m31_add(r1367, r1399);
    unsigned r1401 = stwo_m31_mul(r1369, r7);
    unsigned r1402 = stwo_m31_add(r1400, r1401);
    unsigned r1403 = stwo_m31_mul(r1371, r6);
    unsigned r1404 = stwo_m31_add(r1370, r1403);
    unsigned r1405 = stwo_m31_mul(r1372, r7);
    unsigned r1406 = stwo_m31_add(r1404, r1405);
    unsigned r1407 = stwo_m31_mul(r1374, r6);
    unsigned r1408 = stwo_m31_add(r1373, r1407);
    unsigned r1409 = stwo_m31_mul(r1375, r7);
    unsigned r1410 = stwo_m31_add(r1408, r1409);
    unsigned r1411 = stwo_m31_mul(r1377, r6);
    unsigned r1412 = stwo_m31_add(r1376, r1411);
    unsigned r1413 = stwo_m31_mul(r1378, r7);
    unsigned r1414 = stwo_m31_add(r1412, r1413);
    unsigned r1415 = stwo_m31_mul(r1380, r6);
    unsigned r1416 = stwo_m31_add(r1379, r1415);
    unsigned r1417 = stwo_m31_mul(r1381, r7);
    unsigned r1418 = stwo_m31_add(r1416, r1417);
    unsigned r1419 = stwo_m31_sub(r337, r367);
    unsigned r1420 = stwo_m31_add(r1419, r397);
    unsigned r1421 = stwo_m31_add(r1420, r417);
    unsigned r1422 = stwo_m31_sub(r1421, r1386);
    unsigned r1423 = stwo_m31_add(r1422, r9);
    unsigned r1424 = (r1423 & 65535u);
    unsigned r1425 = (r1424 % STWO_M31_P);
    unsigned r1426 = stwo_m31_sub(r1425, r2);
    unsigned r1427 = stwo_m31_sub(r337, r367);
    unsigned r1428 = stwo_m31_add(r1427, r397);
    unsigned r1429 = stwo_m31_add(r1428, r417);
    out_cols[72u][row] = r417;
    lookup_words[75u * row_count + row] = r417;
    unsigned r1430 = stwo_m31_sub(r1429, r1386);
    out_cols[103u][row] = r1386;
    lookup_words[177u * row_count + row] = r1386;
    unsigned r1431 = stwo_m31_sub(r1430, r1426);
    unsigned r1432 = stwo_m31_mul(r1431, r4);
    unsigned r1433 = stwo_m31_add(r1432, r338);
    unsigned r1434 = stwo_m31_sub(r1433, r368);
    unsigned r1435 = stwo_m31_add(r1434, r398);
    unsigned r1436 = stwo_m31_add(r1435, r418);
    out_cols[73u][row] = r418;
    lookup_words[76u * row_count + row] = r418;
    unsigned r1437 = stwo_m31_sub(r1436, r1390);
    out_cols[104u][row] = r1390;
    lookup_words[178u * row_count + row] = r1390;
    unsigned r1438 = stwo_m31_mul(r1437, r4);
    unsigned r1439 = stwo_m31_add(r1438, r339);
    unsigned r1440 = stwo_m31_sub(r1439, r369);
    unsigned r1441 = stwo_m31_add(r1440, r399);
    unsigned r1442 = stwo_m31_add(r1441, r419);
    out_cols[74u][row] = r419;
    lookup_words[77u * row_count + row] = r419;
    unsigned r1443 = stwo_m31_sub(r1442, r1394);
    out_cols[105u][row] = r1394;
    lookup_words[179u * row_count + row] = r1394;
    unsigned r1444 = stwo_m31_mul(r1443, r4);
    unsigned r1445 = stwo_m31_add(r1444, r340);
    unsigned r1446 = stwo_m31_sub(r1445, r370);
    unsigned r1447 = stwo_m31_add(r1446, r400);
    unsigned r1448 = stwo_m31_add(r1447, r420);
    out_cols[75u][row] = r420;
    lookup_words[78u * row_count + row] = r420;
    unsigned r1449 = stwo_m31_sub(r1448, r1398);
    out_cols[106u][row] = r1398;
    lookup_words[180u * row_count + row] = r1398;
    unsigned r1450 = stwo_m31_mul(r1449, r4);
    unsigned r1451 = stwo_m31_add(r1450, r341);
    unsigned r1452 = stwo_m31_sub(r1451, r371);
    unsigned r1453 = stwo_m31_add(r1452, r401);
    unsigned r1454 = stwo_m31_add(r1453, r421);
    out_cols[76u][row] = r421;
    lookup_words[79u * row_count + row] = r421;
    unsigned r1455 = stwo_m31_sub(r1454, r1402);
    out_cols[107u][row] = r1402;
    lookup_words[181u * row_count + row] = r1402;
    unsigned r1456 = stwo_m31_mul(r1455, r4);
    unsigned r1457 = stwo_m31_add(r1456, r342);
    unsigned r1458 = stwo_m31_sub(r1457, r372);
    unsigned r1459 = stwo_m31_add(r1458, r402);
    unsigned r1460 = stwo_m31_add(r1459, r422);
    out_cols[77u][row] = r422;
    lookup_words[80u * row_count + row] = r422;
    unsigned r1461 = stwo_m31_sub(r1460, r1406);
    out_cols[108u][row] = r1406;
    lookup_words[182u * row_count + row] = r1406;
    unsigned r1462 = stwo_m31_mul(r1461, r4);
    unsigned r1463 = stwo_m31_add(r1462, r343);
    unsigned r1464 = stwo_m31_sub(r1463, r373);
    unsigned r1465 = stwo_m31_add(r1464, r403);
    unsigned r1466 = stwo_m31_add(r1465, r423);
    out_cols[78u][row] = r423;
    lookup_words[81u * row_count + row] = r423;
    unsigned r1467 = stwo_m31_sub(r1466, r1410);
    out_cols[109u][row] = r1410;
    lookup_words[183u * row_count + row] = r1410;
    unsigned r1468 = stwo_m31_mul(r1467, r4);
    unsigned r1469 = stwo_m31_add(r1468, r344);
    unsigned r1470 = stwo_m31_sub(r1469, r374);
    unsigned r1471 = stwo_m31_add(r1470, r404);
    unsigned r1472 = stwo_m31_add(r1471, r424);
    out_cols[79u][row] = r424;
    lookup_words[82u * row_count + row] = r424;
    unsigned r1473 = stwo_m31_sub(r1472, r1414);
    out_cols[110u][row] = r1414;
    lookup_words[184u * row_count + row] = r1414;
    unsigned r1474 = stwo_m31_mul(r1426, r5);
    unsigned r1475 = stwo_m31_sub(r1473, r1474);
    unsigned r1476 = stwo_m31_mul(r1475, r4);
    unsigned r1477 = stwo_m31_add(r1476, r345);
    unsigned r1478 = stwo_m31_sub(r1477, r375);
    unsigned r1479 = stwo_m31_add(r1478, r405);
    unsigned r1480 = stwo_m31_add(r1479, r425);
    out_cols[80u][row] = r425;
    lookup_words[83u * row_count + row] = r425;
    unsigned r1481 = stwo_m31_sub(r1480, r1418);
    out_cols[111u][row] = r1418;
    lookup_words[185u * row_count + row] = r1418;
    unsigned r1482 = stwo_m31_mul(r1481, r4);
    unsigned r1483 = stwo_m31_add(r1426, r2);
    sub_words[41u * row_count + row] = r1483;
    unsigned r1484 = stwo_m31_add(r1432, r2);
    sub_words[42u * row_count + row] = r1484;
    unsigned r1485 = stwo_m31_add(r1438, r2);
    sub_words[43u * row_count + row] = r1485;
    unsigned r1486 = stwo_m31_add(r1444, r2);
    sub_words[44u * row_count + row] = r1486;
    unsigned r1487 = stwo_m31_add(r1450, r2);
    sub_words[45u * row_count + row] = r1487;
    unsigned r1488 = stwo_m31_add(r1426, r2);
    out_cols[113u][row] = r1426;
    lookup_words[108u * row_count + row] = r1488;
    unsigned r1489 = stwo_m31_add(r1432, r2);
    lookup_words[109u * row_count + row] = r1489;
    unsigned r1490 = stwo_m31_add(r1438, r2);
    lookup_words[110u * row_count + row] = r1490;
    unsigned r1491 = stwo_m31_add(r1444, r2);
    lookup_words[111u * row_count + row] = r1491;
    unsigned r1492 = stwo_m31_add(r1450, r2);
    lookup_words[112u * row_count + row] = r1492;
    unsigned r1493 = stwo_m31_add(r1456, r2);
    sub_words[46u * row_count + row] = r1493;
    unsigned r1494 = stwo_m31_add(r1462, r2);
    sub_words[47u * row_count + row] = r1494;
    unsigned r1495 = stwo_m31_add(r1468, r2);
    sub_words[48u * row_count + row] = r1495;
    unsigned r1496 = stwo_m31_add(r1476, r2);
    sub_words[49u * row_count + row] = r1496;
    unsigned r1497 = stwo_m31_add(r1482, r2);
    sub_words[50u * row_count + row] = r1497;
    unsigned r1498 = stwo_m31_add(r1456, r2);
    lookup_words[114u * row_count + row] = r1498;
    unsigned r1499 = stwo_m31_add(r1462, r2);
    lookup_words[115u * row_count + row] = r1499;
    unsigned r1500 = stwo_m31_add(r1468, r2);
    lookup_words[116u * row_count + row] = r1500;
    unsigned r1501 = stwo_m31_add(r1476, r2);
    lookup_words[117u * row_count + row] = r1501;
    unsigned r1502 = stwo_m31_add(r1482, r2);
    lookup_words[118u * row_count + row] = r1502;
    unsigned r1503 = (r337 & 511u);
    unsigned r1504 = (r337 >> 9u);
    unsigned r1505 = (r1504 & 511u);
    unsigned r1506 = (r337 >> 18u);
    unsigned r1507 = (r1506 & 511u);
    unsigned r1508 = (r338 & 511u);
    unsigned r1509 = (r338 >> 9u);
    unsigned r1510 = (r1509 & 511u);
    unsigned r1511 = (r338 >> 18u);
    unsigned r1512 = (r1511 & 511u);
    unsigned r1513 = (r339 & 511u);
    unsigned r1514 = (r339 >> 9u);
    unsigned r1515 = (r1514 & 511u);
    unsigned r1516 = (r339 >> 18u);
    unsigned r1517 = (r1516 & 511u);
    unsigned r1518 = (r340 & 511u);
    unsigned r1519 = (r340 >> 9u);
    unsigned r1520 = (r1519 & 511u);
    unsigned r1521 = (r340 >> 18u);
    unsigned r1522 = (r1521 & 511u);
    unsigned r1523 = (r341 & 511u);
    unsigned r1524 = (r341 >> 9u);
    unsigned r1525 = (r1524 & 511u);
    unsigned r1526 = (r341 >> 18u);
    unsigned r1527 = (r1526 & 511u);
    unsigned r1528 = (r342 & 511u);
    unsigned r1529 = (r342 >> 9u);
    unsigned r1530 = (r1529 & 511u);
    unsigned r1531 = (r342 >> 18u);
    unsigned r1532 = (r1531 & 511u);
    unsigned r1533 = (r343 & 511u);
    unsigned r1534 = (r343 >> 9u);
    unsigned r1535 = (r1534 & 511u);
    unsigned r1536 = (r343 >> 18u);
    unsigned r1537 = (r1536 & 511u);
    unsigned r1538 = (r344 & 511u);
    unsigned r1539 = (r344 >> 9u);
    unsigned r1540 = (r1539 & 511u);
    unsigned r1541 = (r344 >> 18u);
    unsigned r1542 = (r1541 & 511u);
    unsigned r1543 = (r345 & 511u);
    unsigned r1544 = (r345 >> 9u);
    unsigned r1545 = (r1544 & 511u);
    unsigned r1546 = (r345 >> 18u);
    unsigned r1547 = (r1546 & 511u);
    unsigned r1548 = (r346 & 511u);
    out_cols[41u][row] = r346;
    lookup_words[20u * row_count + row] = r346;
    const unsigned dargs20[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1503, r1505, r1507, r1508, r1510, r1512, r1513, r1515, r1517, r1518, r1520, r1522, r1523, r1525, r1527, r1528, r1530, r1532, r1533, r1535, r1537, r1538, r1540, r1542, r1543, r1545, r1547, r1548 };
    unsigned douts20[28];
    stwo_wit_deduce_felt_mul(dargs20, douts20);
    unsigned r1549 = douts20[0];
    unsigned r1550 = douts20[1];
    unsigned r1551 = douts20[2];
    unsigned r1552 = douts20[3];
    unsigned r1553 = douts20[4];
    unsigned r1554 = douts20[5];
    unsigned r1555 = douts20[6];
    unsigned r1556 = douts20[7];
    unsigned r1557 = douts20[8];
    unsigned r1558 = douts20[9];
    unsigned r1559 = douts20[10];
    unsigned r1560 = douts20[11];
    unsigned r1561 = douts20[12];
    unsigned r1562 = douts20[13];
    unsigned r1563 = douts20[14];
    unsigned r1564 = douts20[15];
    unsigned r1565 = douts20[16];
    unsigned r1566 = douts20[17];
    unsigned r1567 = douts20[18];
    unsigned r1568 = douts20[19];
    unsigned r1569 = douts20[20];
    unsigned r1570 = douts20[21];
    unsigned r1571 = douts20[22];
    unsigned r1572 = douts20[23];
    unsigned r1573 = douts20[24];
    unsigned r1574 = douts20[25];
    unsigned r1575 = douts20[26];
    unsigned r1576 = douts20[27];
    const unsigned dargs21[56] = { r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1549, r1550, r1551, r1552, r1553, r1554, r1555, r1556, r1557, r1558, r1559, r1560, r1561, r1562, r1563, r1564, r1565, r1566, r1567, r1568, r1569, r1570, r1571, r1572, r1573, r1574, r1575, r1576 };
    unsigned douts21[28];
    stwo_wit_deduce_felt_add(dargs21, douts21);
    unsigned r1577 = douts21[0];
    unsigned r1578 = douts21[1];
    unsigned r1579 = douts21[2];
    unsigned r1580 = douts21[3];
    unsigned r1581 = douts21[4];
    unsigned r1582 = douts21[5];
    unsigned r1583 = douts21[6];
    unsigned r1584 = douts21[7];
    unsigned r1585 = douts21[8];
    unsigned r1586 = douts21[9];
    unsigned r1587 = douts21[10];
    unsigned r1588 = douts21[11];
    unsigned r1589 = douts21[12];
    unsigned r1590 = douts21[13];
    unsigned r1591 = douts21[14];
    unsigned r1592 = douts21[15];
    unsigned r1593 = douts21[16];
    unsigned r1594 = douts21[17];
    unsigned r1595 = douts21[18];
    unsigned r1596 = douts21[19];
    unsigned r1597 = douts21[20];
    unsigned r1598 = douts21[21];
    unsigned r1599 = douts21[22];
    unsigned r1600 = douts21[23];
    unsigned r1601 = douts21[24];
    unsigned r1602 = douts21[25];
    unsigned r1603 = douts21[26];
    unsigned r1604 = douts21[27];
    unsigned r1605 = (r367 & 511u);
    unsigned r1606 = (r367 >> 9u);
    unsigned r1607 = (r1606 & 511u);
    unsigned r1608 = (r367 >> 18u);
    unsigned r1609 = (r1608 & 511u);
    unsigned r1610 = (r368 & 511u);
    unsigned r1611 = (r368 >> 9u);
    unsigned r1612 = (r1611 & 511u);
    unsigned r1613 = (r368 >> 18u);
    unsigned r1614 = (r1613 & 511u);
    unsigned r1615 = (r369 & 511u);
    unsigned r1616 = (r369 >> 9u);
    unsigned r1617 = (r1616 & 511u);
    unsigned r1618 = (r369 >> 18u);
    unsigned r1619 = (r1618 & 511u);
    unsigned r1620 = (r370 & 511u);
    unsigned r1621 = (r370 >> 9u);
    unsigned r1622 = (r1621 & 511u);
    unsigned r1623 = (r370 >> 18u);
    unsigned r1624 = (r1623 & 511u);
    unsigned r1625 = (r371 & 511u);
    unsigned r1626 = (r371 >> 9u);
    unsigned r1627 = (r1626 & 511u);
    unsigned r1628 = (r371 >> 18u);
    unsigned r1629 = (r1628 & 511u);
    unsigned r1630 = (r372 & 511u);
    unsigned r1631 = (r372 >> 9u);
    unsigned r1632 = (r1631 & 511u);
    unsigned r1633 = (r372 >> 18u);
    unsigned r1634 = (r1633 & 511u);
    unsigned r1635 = (r373 & 511u);
    unsigned r1636 = (r373 >> 9u);
    unsigned r1637 = (r1636 & 511u);
    unsigned r1638 = (r373 >> 18u);
    unsigned r1639 = (r1638 & 511u);
    unsigned r1640 = (r374 & 511u);
    unsigned r1641 = (r374 >> 9u);
    unsigned r1642 = (r1641 & 511u);
    unsigned r1643 = (r374 >> 18u);
    unsigned r1644 = (r1643 & 511u);
    unsigned r1645 = (r375 & 511u);
    unsigned r1646 = (r375 >> 9u);
    unsigned r1647 = (r1646 & 511u);
    unsigned r1648 = (r375 >> 18u);
    unsigned r1649 = (r1648 & 511u);
    unsigned r1650 = (r376 & 511u);
    out_cols[51u][row] = r376;
    lookup_words[41u * row_count + row] = r376;
    const unsigned dargs22[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1605, r1607, r1609, r1610, r1612, r1614, r1615, r1617, r1619, r1620, r1622, r1624, r1625, r1627, r1629, r1630, r1632, r1634, r1635, r1637, r1639, r1640, r1642, r1644, r1645, r1647, r1649, r1650 };
    unsigned douts22[28];
    stwo_wit_deduce_felt_mul(dargs22, douts22);
    unsigned r1651 = douts22[0];
    unsigned r1652 = douts22[1];
    unsigned r1653 = douts22[2];
    unsigned r1654 = douts22[3];
    unsigned r1655 = douts22[4];
    unsigned r1656 = douts22[5];
    unsigned r1657 = douts22[6];
    unsigned r1658 = douts22[7];
    unsigned r1659 = douts22[8];
    unsigned r1660 = douts22[9];
    unsigned r1661 = douts22[10];
    unsigned r1662 = douts22[11];
    unsigned r1663 = douts22[12];
    unsigned r1664 = douts22[13];
    unsigned r1665 = douts22[14];
    unsigned r1666 = douts22[15];
    unsigned r1667 = douts22[16];
    unsigned r1668 = douts22[17];
    unsigned r1669 = douts22[18];
    unsigned r1670 = douts22[19];
    unsigned r1671 = douts22[20];
    unsigned r1672 = douts22[21];
    unsigned r1673 = douts22[22];
    unsigned r1674 = douts22[23];
    unsigned r1675 = douts22[24];
    unsigned r1676 = douts22[25];
    unsigned r1677 = douts22[26];
    unsigned r1678 = douts22[27];
    const unsigned dargs23[56] = { r1577, r1578, r1579, r1580, r1581, r1582, r1583, r1584, r1585, r1586, r1587, r1588, r1589, r1590, r1591, r1592, r1593, r1594, r1595, r1596, r1597, r1598, r1599, r1600, r1601, r1602, r1603, r1604, r1651, r1652, r1653, r1654, r1655, r1656, r1657, r1658, r1659, r1660, r1661, r1662, r1663, r1664, r1665, r1666, r1667, r1668, r1669, r1670, r1671, r1672, r1673, r1674, r1675, r1676, r1677, r1678 };
    unsigned douts23[28];
    stwo_wit_deduce_felt_add(dargs23, douts23);
    unsigned r1679 = douts23[0];
    unsigned r1680 = douts23[1];
    unsigned r1681 = douts23[2];
    unsigned r1682 = douts23[3];
    unsigned r1683 = douts23[4];
    unsigned r1684 = douts23[5];
    unsigned r1685 = douts23[6];
    unsigned r1686 = douts23[7];
    unsigned r1687 = douts23[8];
    unsigned r1688 = douts23[9];
    unsigned r1689 = douts23[10];
    unsigned r1690 = douts23[11];
    unsigned r1691 = douts23[12];
    unsigned r1692 = douts23[13];
    unsigned r1693 = douts23[14];
    unsigned r1694 = douts23[15];
    unsigned r1695 = douts23[16];
    unsigned r1696 = douts23[17];
    unsigned r1697 = douts23[18];
    unsigned r1698 = douts23[19];
    unsigned r1699 = douts23[20];
    unsigned r1700 = douts23[21];
    unsigned r1701 = douts23[22];
    unsigned r1702 = douts23[23];
    unsigned r1703 = douts23[24];
    unsigned r1704 = douts23[25];
    unsigned r1705 = douts23[26];
    unsigned r1706 = douts23[27];
    unsigned r1707 = (r397 & 511u);
    unsigned r1708 = (r397 >> 9u);
    unsigned r1709 = (r1708 & 511u);
    unsigned r1710 = (r397 >> 18u);
    unsigned r1711 = (r1710 & 511u);
    unsigned r1712 = (r398 & 511u);
    unsigned r1713 = (r398 >> 9u);
    unsigned r1714 = (r1713 & 511u);
    unsigned r1715 = (r398 >> 18u);
    unsigned r1716 = (r1715 & 511u);
    unsigned r1717 = (r399 & 511u);
    unsigned r1718 = (r399 >> 9u);
    unsigned r1719 = (r1718 & 511u);
    unsigned r1720 = (r399 >> 18u);
    unsigned r1721 = (r1720 & 511u);
    unsigned r1722 = (r400 & 511u);
    unsigned r1723 = (r400 >> 9u);
    unsigned r1724 = (r1723 & 511u);
    unsigned r1725 = (r400 >> 18u);
    unsigned r1726 = (r1725 & 511u);
    unsigned r1727 = (r401 & 511u);
    unsigned r1728 = (r401 >> 9u);
    unsigned r1729 = (r1728 & 511u);
    unsigned r1730 = (r401 >> 18u);
    unsigned r1731 = (r1730 & 511u);
    unsigned r1732 = (r402 & 511u);
    unsigned r1733 = (r402 >> 9u);
    unsigned r1734 = (r1733 & 511u);
    unsigned r1735 = (r402 >> 18u);
    unsigned r1736 = (r1735 & 511u);
    unsigned r1737 = (r403 & 511u);
    unsigned r1738 = (r403 >> 9u);
    unsigned r1739 = (r1738 & 511u);
    unsigned r1740 = (r403 >> 18u);
    unsigned r1741 = (r1740 & 511u);
    unsigned r1742 = (r404 & 511u);
    unsigned r1743 = (r404 >> 9u);
    unsigned r1744 = (r1743 & 511u);
    unsigned r1745 = (r404 >> 18u);
    unsigned r1746 = (r1745 & 511u);
    unsigned r1747 = (r405 & 511u);
    unsigned r1748 = (r405 >> 9u);
    unsigned r1749 = (r1748 & 511u);
    unsigned r1750 = (r405 >> 18u);
    unsigned r1751 = (r1750 & 511u);
    unsigned r1752 = (r406 & 511u);
    out_cols[61u][row] = r406;
    lookup_words[62u * row_count + row] = r406;
    const unsigned dargs24[56] = { r2, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1707, r1709, r1711, r1712, r1714, r1716, r1717, r1719, r1721, r1722, r1724, r1726, r1727, r1729, r1731, r1732, r1734, r1736, r1737, r1739, r1741, r1742, r1744, r1746, r1747, r1749, r1751, r1752 };
    unsigned douts24[28];
    stwo_wit_deduce_felt_mul(dargs24, douts24);
    unsigned r1753 = douts24[0];
    unsigned r1754 = douts24[1];
    unsigned r1755 = douts24[2];
    unsigned r1756 = douts24[3];
    unsigned r1757 = douts24[4];
    unsigned r1758 = douts24[5];
    unsigned r1759 = douts24[6];
    unsigned r1760 = douts24[7];
    unsigned r1761 = douts24[8];
    unsigned r1762 = douts24[9];
    unsigned r1763 = douts24[10];
    unsigned r1764 = douts24[11];
    unsigned r1765 = douts24[12];
    unsigned r1766 = douts24[13];
    unsigned r1767 = douts24[14];
    unsigned r1768 = douts24[15];
    unsigned r1769 = douts24[16];
    unsigned r1770 = douts24[17];
    unsigned r1771 = douts24[18];
    unsigned r1772 = douts24[19];
    unsigned r1773 = douts24[20];
    unsigned r1774 = douts24[21];
    unsigned r1775 = douts24[22];
    unsigned r1776 = douts24[23];
    unsigned r1777 = douts24[24];
    unsigned r1778 = douts24[25];
    unsigned r1779 = douts24[26];
    unsigned r1780 = douts24[27];
    const unsigned dargs25[56] = { r1679, r1680, r1681, r1682, r1683, r1684, r1685, r1686, r1687, r1688, r1689, r1690, r1691, r1692, r1693, r1694, r1695, r1696, r1697, r1698, r1699, r1700, r1701, r1702, r1703, r1704, r1705, r1706, r1753, r1754, r1755, r1756, r1757, r1758, r1759, r1760, r1761, r1762, r1763, r1764, r1765, r1766, r1767, r1768, r1769, r1770, r1771, r1772, r1773, r1774, r1775, r1776, r1777, r1778, r1779, r1780 };
    unsigned douts25[28];
    stwo_wit_deduce_felt_sub(dargs25, douts25);
    unsigned r1781 = douts25[0];
    unsigned r1782 = douts25[1];
    unsigned r1783 = douts25[2];
    unsigned r1784 = douts25[3];
    unsigned r1785 = douts25[4];
    unsigned r1786 = douts25[5];
    unsigned r1787 = douts25[6];
    unsigned r1788 = douts25[7];
    unsigned r1789 = douts25[8];
    unsigned r1790 = douts25[9];
    unsigned r1791 = douts25[10];
    unsigned r1792 = douts25[11];
    unsigned r1793 = douts25[12];
    unsigned r1794 = douts25[13];
    unsigned r1795 = douts25[14];
    unsigned r1796 = douts25[15];
    unsigned r1797 = douts25[16];
    unsigned r1798 = douts25[17];
    unsigned r1799 = douts25[18];
    unsigned r1800 = douts25[19];
    unsigned r1801 = douts25[20];
    unsigned r1802 = douts25[21];
    unsigned r1803 = douts25[22];
    unsigned r1804 = douts25[23];
    unsigned r1805 = douts25[24];
    unsigned r1806 = douts25[25];
    unsigned r1807 = douts25[26];
    unsigned r1808 = douts25[27];
    unsigned r1809 = (r427 & 511u);
    unsigned r1810 = (r427 >> 9u);
    unsigned r1811 = (r1810 & 511u);
    unsigned r1812 = (r427 >> 18u);
    unsigned r1813 = (r1812 & 511u);
    unsigned r1814 = (r428 & 511u);
    unsigned r1815 = (r428 >> 9u);
    unsigned r1816 = (r1815 & 511u);
    unsigned r1817 = (r428 >> 18u);
    unsigned r1818 = (r1817 & 511u);
    unsigned r1819 = (r429 & 511u);
    unsigned r1820 = (r429 >> 9u);
    unsigned r1821 = (r1820 & 511u);
    unsigned r1822 = (r429 >> 18u);
    unsigned r1823 = (r1822 & 511u);
    unsigned r1824 = (r430 & 511u);
    unsigned r1825 = (r430 >> 9u);
    unsigned r1826 = (r1825 & 511u);
    unsigned r1827 = (r430 >> 18u);
    unsigned r1828 = (r1827 & 511u);
    unsigned r1829 = (r431 & 511u);
    unsigned r1830 = (r431 >> 9u);
    unsigned r1831 = (r1830 & 511u);
    unsigned r1832 = (r431 >> 18u);
    unsigned r1833 = (r1832 & 511u);
    unsigned r1834 = (r432 & 511u);
    unsigned r1835 = (r432 >> 9u);
    unsigned r1836 = (r1835 & 511u);
    unsigned r1837 = (r432 >> 18u);
    unsigned r1838 = (r1837 & 511u);
    unsigned r1839 = (r433 & 511u);
    unsigned r1840 = (r433 >> 9u);
    unsigned r1841 = (r1840 & 511u);
    unsigned r1842 = (r433 >> 18u);
    unsigned r1843 = (r1842 & 511u);
    unsigned r1844 = (r434 & 511u);
    unsigned r1845 = (r434 >> 9u);
    unsigned r1846 = (r1845 & 511u);
    unsigned r1847 = (r434 >> 18u);
    unsigned r1848 = (r1847 & 511u);
    unsigned r1849 = (r435 & 511u);
    unsigned r1850 = (r435 >> 9u);
    unsigned r1851 = (r1850 & 511u);
    unsigned r1852 = (r435 >> 18u);
    unsigned r1853 = (r1852 & 511u);
    unsigned r1854 = (r436 & 511u);
    out_cols[91u][row] = r436;
    lookup_words[94u * row_count + row] = r436;
    const unsigned dargs26[56] = { r1, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r0, r1809, r1811, r1813, r1814, r1816, r1818, r1819, r1821, r1823, r1824, r1826, r1828, r1829, r1831, r1833, r1834, r1836, r1838, r1839, r1841, r1843, r1844, r1846, r1848, r1849, r1851, r1853, r1854 };
    unsigned douts26[28];
    stwo_wit_deduce_felt_mul(dargs26, douts26);
    unsigned r1855 = douts26[0];
    unsigned r1856 = douts26[1];
    unsigned r1857 = douts26[2];
    unsigned r1858 = douts26[3];
    unsigned r1859 = douts26[4];
    unsigned r1860 = douts26[5];
    unsigned r1861 = douts26[6];
    unsigned r1862 = douts26[7];
    unsigned r1863 = douts26[8];
    unsigned r1864 = douts26[9];
    unsigned r1865 = douts26[10];
    unsigned r1866 = douts26[11];
    unsigned r1867 = douts26[12];
    unsigned r1868 = douts26[13];
    unsigned r1869 = douts26[14];
    unsigned r1870 = douts26[15];
    unsigned r1871 = douts26[16];
    unsigned r1872 = douts26[17];
    unsigned r1873 = douts26[18];
    unsigned r1874 = douts26[19];
    unsigned r1875 = douts26[20];
    unsigned r1876 = douts26[21];
    unsigned r1877 = douts26[22];
    unsigned r1878 = douts26[23];
    unsigned r1879 = douts26[24];
    unsigned r1880 = douts26[25];
    unsigned r1881 = douts26[26];
    unsigned r1882 = douts26[27];
    const unsigned dargs27[56] = { r1781, r1782, r1783, r1784, r1785, r1786, r1787, r1788, r1789, r1790, r1791, r1792, r1793, r1794, r1795, r1796, r1797, r1798, r1799, r1800, r1801, r1802, r1803, r1804, r1805, r1806, r1807, r1808, r1855, r1856, r1857, r1858, r1859, r1860, r1861, r1862, r1863, r1864, r1865, r1866, r1867, r1868, r1869, r1870, r1871, r1872, r1873, r1874, r1875, r1876, r1877, r1878, r1879, r1880, r1881, r1882 };
    unsigned douts27[28];
    stwo_wit_deduce_felt_add(dargs27, douts27);
    unsigned r1883 = douts27[0];
    unsigned r1884 = douts27[1];
    unsigned r1885 = douts27[2];
    unsigned r1886 = douts27[3];
    unsigned r1887 = douts27[4];
    unsigned r1888 = douts27[5];
    unsigned r1889 = douts27[6];
    unsigned r1890 = douts27[7];
    unsigned r1891 = douts27[8];
    unsigned r1892 = douts27[9];
    unsigned r1893 = douts27[10];
    unsigned r1894 = douts27[11];
    unsigned r1895 = douts27[12];
    unsigned r1896 = douts27[13];
    unsigned r1897 = douts27[14];
    unsigned r1898 = douts27[15];
    unsigned r1899 = douts27[16];
    unsigned r1900 = douts27[17];
    unsigned r1901 = douts27[18];
    unsigned r1902 = douts27[19];
    unsigned r1903 = douts27[20];
    unsigned r1904 = douts27[21];
    unsigned r1905 = douts27[22];
    unsigned r1906 = douts27[23];
    unsigned r1907 = douts27[24];
    unsigned r1908 = douts27[25];
    unsigned r1909 = douts27[26];
    unsigned r1910 = douts27[27];
    out_cols[123u][row] = r1910;
    lookup_words[196u * row_count + row] = r1910;
    unsigned r1911 = stwo_m31_mul(r1884, r6);
    unsigned r1912 = stwo_m31_add(r1883, r1911);
    unsigned r1913 = stwo_m31_mul(r1885, r7);
    unsigned r1914 = stwo_m31_add(r1912, r1913);
    unsigned r1915 = stwo_m31_mul(r1887, r6);
    unsigned r1916 = stwo_m31_add(r1886, r1915);
    unsigned r1917 = stwo_m31_mul(r1888, r7);
    unsigned r1918 = stwo_m31_add(r1916, r1917);
    unsigned r1919 = stwo_m31_mul(r1890, r6);
    unsigned r1920 = stwo_m31_add(r1889, r1919);
    unsigned r1921 = stwo_m31_mul(r1891, r7);
    unsigned r1922 = stwo_m31_add(r1920, r1921);
    unsigned r1923 = stwo_m31_mul(r1893, r6);
    unsigned r1924 = stwo_m31_add(r1892, r1923);
    unsigned r1925 = stwo_m31_mul(r1894, r7);
    unsigned r1926 = stwo_m31_add(r1924, r1925);
    unsigned r1927 = stwo_m31_mul(r1896, r6);
    unsigned r1928 = stwo_m31_add(r1895, r1927);
    unsigned r1929 = stwo_m31_mul(r1897, r7);
    unsigned r1930 = stwo_m31_add(r1928, r1929);
    unsigned r1931 = stwo_m31_mul(r1899, r6);
    unsigned r1932 = stwo_m31_add(r1898, r1931);
    unsigned r1933 = stwo_m31_mul(r1900, r7);
    unsigned r1934 = stwo_m31_add(r1932, r1933);
    unsigned r1935 = stwo_m31_mul(r1902, r6);
    unsigned r1936 = stwo_m31_add(r1901, r1935);
    unsigned r1937 = stwo_m31_mul(r1903, r7);
    unsigned r1938 = stwo_m31_add(r1936, r1937);
    unsigned r1939 = stwo_m31_mul(r1905, r6);
    unsigned r1940 = stwo_m31_add(r1904, r1939);
    unsigned r1941 = stwo_m31_mul(r1906, r7);
    unsigned r1942 = stwo_m31_add(r1940, r1941);
    unsigned r1943 = stwo_m31_mul(r1908, r6);
    unsigned r1944 = stwo_m31_add(r1907, r1943);
    unsigned r1945 = stwo_m31_mul(r1909, r7);
    unsigned r1946 = stwo_m31_add(r1944, r1945);
    unsigned r1947 = stwo_m31_add(r337, r367);
    unsigned r1948 = stwo_m31_mul(r2, r397);
    unsigned r1949 = stwo_m31_sub(r1947, r1948);
    unsigned r1950 = stwo_m31_add(r1949, r427);
    unsigned r1951 = stwo_m31_sub(r1950, r1914);
    unsigned r1952 = stwo_m31_add(r1951, r10);
    unsigned r1953 = (r1952 & 65535u);
    unsigned r1954 = (r1953 % STWO_M31_P);
    unsigned r1955 = stwo_m31_sub(r1954, r3);
    unsigned r1956 = stwo_m31_add(r337, r367);
    out_cols[32u][row] = r337;
    lookup_words[11u * row_count + row] = r337;
    out_cols[42u][row] = r367;
    lookup_words[32u * row_count + row] = r367;
    unsigned r1957 = stwo_m31_mul(r2, r397);
    out_cols[52u][row] = r397;
    lookup_words[53u * row_count + row] = r397;
    unsigned r1958 = stwo_m31_sub(r1956, r1957);
    unsigned r1959 = stwo_m31_add(r1958, r427);
    out_cols[82u][row] = r427;
    lookup_words[85u * row_count + row] = r427;
    unsigned r1960 = stwo_m31_sub(r1959, r1914);
    out_cols[114u][row] = r1914;
    lookup_words[187u * row_count + row] = r1914;
    unsigned r1961 = stwo_m31_sub(r1960, r1955);
    unsigned r1962 = stwo_m31_mul(r1961, r4);
    unsigned r1963 = stwo_m31_add(r1962, r338);
    out_cols[33u][row] = r338;
    lookup_words[12u * row_count + row] = r338;
    unsigned r1964 = stwo_m31_add(r1963, r368);
    out_cols[43u][row] = r368;
    lookup_words[33u * row_count + row] = r368;
    unsigned r1965 = stwo_m31_mul(r2, r398);
    out_cols[53u][row] = r398;
    lookup_words[54u * row_count + row] = r398;
    unsigned r1966 = stwo_m31_sub(r1964, r1965);
    unsigned r1967 = stwo_m31_add(r1966, r428);
    out_cols[83u][row] = r428;
    lookup_words[86u * row_count + row] = r428;
    unsigned r1968 = stwo_m31_sub(r1967, r1918);
    out_cols[115u][row] = r1918;
    lookup_words[188u * row_count + row] = r1918;
    unsigned r1969 = stwo_m31_mul(r1968, r4);
    unsigned r1970 = stwo_m31_add(r1969, r339);
    out_cols[34u][row] = r339;
    lookup_words[13u * row_count + row] = r339;
    unsigned r1971 = stwo_m31_add(r1970, r369);
    out_cols[44u][row] = r369;
    lookup_words[34u * row_count + row] = r369;
    unsigned r1972 = stwo_m31_mul(r2, r399);
    out_cols[54u][row] = r399;
    lookup_words[55u * row_count + row] = r399;
    unsigned r1973 = stwo_m31_sub(r1971, r1972);
    unsigned r1974 = stwo_m31_add(r1973, r429);
    out_cols[84u][row] = r429;
    lookup_words[87u * row_count + row] = r429;
    unsigned r1975 = stwo_m31_sub(r1974, r1922);
    out_cols[116u][row] = r1922;
    lookup_words[189u * row_count + row] = r1922;
    unsigned r1976 = stwo_m31_mul(r1975, r4);
    unsigned r1977 = stwo_m31_add(r1976, r340);
    out_cols[35u][row] = r340;
    lookup_words[14u * row_count + row] = r340;
    unsigned r1978 = stwo_m31_add(r1977, r370);
    out_cols[45u][row] = r370;
    lookup_words[35u * row_count + row] = r370;
    unsigned r1979 = stwo_m31_mul(r2, r400);
    out_cols[55u][row] = r400;
    lookup_words[56u * row_count + row] = r400;
    unsigned r1980 = stwo_m31_sub(r1978, r1979);
    unsigned r1981 = stwo_m31_add(r1980, r430);
    out_cols[85u][row] = r430;
    lookup_words[88u * row_count + row] = r430;
    unsigned r1982 = stwo_m31_sub(r1981, r1926);
    out_cols[117u][row] = r1926;
    lookup_words[190u * row_count + row] = r1926;
    unsigned r1983 = stwo_m31_mul(r1982, r4);
    unsigned r1984 = stwo_m31_add(r1983, r341);
    out_cols[36u][row] = r341;
    lookup_words[15u * row_count + row] = r341;
    unsigned r1985 = stwo_m31_add(r1984, r371);
    out_cols[46u][row] = r371;
    lookup_words[36u * row_count + row] = r371;
    unsigned r1986 = stwo_m31_mul(r2, r401);
    out_cols[56u][row] = r401;
    lookup_words[57u * row_count + row] = r401;
    unsigned r1987 = stwo_m31_sub(r1985, r1986);
    unsigned r1988 = stwo_m31_add(r1987, r431);
    out_cols[86u][row] = r431;
    lookup_words[89u * row_count + row] = r431;
    unsigned r1989 = stwo_m31_sub(r1988, r1930);
    out_cols[118u][row] = r1930;
    lookup_words[191u * row_count + row] = r1930;
    unsigned r1990 = stwo_m31_mul(r1989, r4);
    unsigned r1991 = stwo_m31_add(r1990, r342);
    out_cols[37u][row] = r342;
    lookup_words[16u * row_count + row] = r342;
    unsigned r1992 = stwo_m31_add(r1991, r372);
    out_cols[47u][row] = r372;
    lookup_words[37u * row_count + row] = r372;
    unsigned r1993 = stwo_m31_mul(r2, r402);
    out_cols[57u][row] = r402;
    lookup_words[58u * row_count + row] = r402;
    unsigned r1994 = stwo_m31_sub(r1992, r1993);
    unsigned r1995 = stwo_m31_add(r1994, r432);
    out_cols[87u][row] = r432;
    lookup_words[90u * row_count + row] = r432;
    unsigned r1996 = stwo_m31_sub(r1995, r1934);
    out_cols[119u][row] = r1934;
    lookup_words[192u * row_count + row] = r1934;
    unsigned r1997 = stwo_m31_mul(r1996, r4);
    unsigned r1998 = stwo_m31_add(r1997, r343);
    out_cols[38u][row] = r343;
    lookup_words[17u * row_count + row] = r343;
    unsigned r1999 = stwo_m31_add(r1998, r373);
    out_cols[48u][row] = r373;
    lookup_words[38u * row_count + row] = r373;
    unsigned r2000 = stwo_m31_mul(r2, r403);
    out_cols[58u][row] = r403;
    lookup_words[59u * row_count + row] = r403;
    unsigned r2001 = stwo_m31_sub(r1999, r2000);
    unsigned r2002 = stwo_m31_add(r2001, r433);
    out_cols[88u][row] = r433;
    lookup_words[91u * row_count + row] = r433;
    unsigned r2003 = stwo_m31_sub(r2002, r1938);
    out_cols[120u][row] = r1938;
    lookup_words[193u * row_count + row] = r1938;
    unsigned r2004 = stwo_m31_mul(r2003, r4);
    unsigned r2005 = stwo_m31_add(r2004, r344);
    out_cols[39u][row] = r344;
    lookup_words[18u * row_count + row] = r344;
    unsigned r2006 = stwo_m31_add(r2005, r374);
    out_cols[49u][row] = r374;
    lookup_words[39u * row_count + row] = r374;
    unsigned r2007 = stwo_m31_mul(r2, r404);
    out_cols[59u][row] = r404;
    lookup_words[60u * row_count + row] = r404;
    unsigned r2008 = stwo_m31_sub(r2006, r2007);
    unsigned r2009 = stwo_m31_add(r2008, r434);
    out_cols[89u][row] = r434;
    lookup_words[92u * row_count + row] = r434;
    unsigned r2010 = stwo_m31_sub(r2009, r1942);
    out_cols[121u][row] = r1942;
    lookup_words[194u * row_count + row] = r1942;
    unsigned r2011 = stwo_m31_mul(r1955, r5);
    unsigned r2012 = stwo_m31_sub(r2010, r2011);
    unsigned r2013 = stwo_m31_mul(r2012, r4);
    unsigned r2014 = stwo_m31_add(r2013, r345);
    out_cols[40u][row] = r345;
    lookup_words[19u * row_count + row] = r345;
    unsigned r2015 = stwo_m31_add(r2014, r375);
    out_cols[50u][row] = r375;
    lookup_words[40u * row_count + row] = r375;
    unsigned r2016 = stwo_m31_mul(r2, r405);
    out_cols[60u][row] = r405;
    lookup_words[61u * row_count + row] = r405;
    unsigned r2017 = stwo_m31_sub(r2015, r2016);
    unsigned r2018 = stwo_m31_add(r2017, r435);
    out_cols[90u][row] = r435;
    lookup_words[93u * row_count + row] = r435;
    unsigned r2019 = stwo_m31_sub(r2018, r1946);
    out_cols[122u][row] = r1946;
    lookup_words[195u * row_count + row] = r1946;
    unsigned r2020 = stwo_m31_mul(r2019, r4);
    unsigned r2021 = stwo_m31_add(r1955, r3);
    sub_words[51u * row_count + row] = r2021;
    unsigned r2022 = stwo_m31_add(r1962, r3);
    sub_words[52u * row_count + row] = r2022;
    unsigned r2023 = stwo_m31_add(r1969, r3);
    sub_words[53u * row_count + row] = r2023;
    unsigned r2024 = stwo_m31_add(r1976, r3);
    sub_words[54u * row_count + row] = r2024;
    unsigned r2025 = stwo_m31_add(r1983, r3);
    sub_words[55u * row_count + row] = r2025;
    unsigned r2026 = stwo_m31_add(r1955, r3);
    out_cols[124u][row] = r1955;
    lookup_words[120u * row_count + row] = r2026;
    unsigned r2027 = stwo_m31_add(r1962, r3);
    lookup_words[121u * row_count + row] = r2027;
    unsigned r2028 = stwo_m31_add(r1969, r3);
    lookup_words[122u * row_count + row] = r2028;
    unsigned r2029 = stwo_m31_add(r1976, r3);
    lookup_words[123u * row_count + row] = r2029;
    unsigned r2030 = stwo_m31_add(r1983, r3);
    lookup_words[124u * row_count + row] = r2030;
    unsigned r2031 = stwo_m31_add(r1990, r3);
    sub_words[56u * row_count + row] = r2031;
    unsigned r2032 = stwo_m31_add(r1997, r3);
    sub_words[57u * row_count + row] = r2032;
    unsigned r2033 = stwo_m31_add(r2004, r3);
    sub_words[58u * row_count + row] = r2033;
    unsigned r2034 = stwo_m31_add(r2013, r3);
    sub_words[59u * row_count + row] = r2034;
    unsigned r2035 = stwo_m31_add(r2020, r3);
    sub_words[60u * row_count + row] = r2035;
    unsigned r2036 = stwo_m31_add(r1990, r3);
    lookup_words[126u * row_count + row] = r2036;
    unsigned r2037 = stwo_m31_add(r1997, r3);
    lookup_words[127u * row_count + row] = r2037;
    unsigned r2038 = stwo_m31_add(r2004, r3);
    lookup_words[128u * row_count + row] = r2038;
    unsigned r2039 = stwo_m31_add(r2013, r3);
    lookup_words[129u * row_count + row] = r2039;
    unsigned r2040 = stwo_m31_add(r2020, r3);
    lookup_words[130u * row_count + row] = r2040;
    unsigned r2041 = input_cols[32u][row];
    out_cols[125u][row] = r2041;
    lookup_words[198u * row_count + row] = r2041;
    unsigned r2042 = stwo_m31_add(r16, r1);
    out_cols[1u][row] = r16;
    sub_words[30u * row_count + row] = r16;
    lookup_words[64u * row_count + row] = r16;
    lookup_words[133u * row_count + row] = r16;
    lookup_words[166u * row_count + row] = r2042;
    lookup_words[197u * row_count + row] = r1;
}
