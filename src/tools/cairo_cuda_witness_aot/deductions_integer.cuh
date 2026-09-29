// Repository-owned canonical Cairo modulo deductions. Layout and algorithms
// match the CPU u384/u768 implementation and the Metal witness lane.
// Invalid zero divisors and oversized quotients fail the CUDA session.
typedef unsigned long long cuda_witness_u64;
#ifndef STWO_CUDA_DEDUCTION_INVALID
#define STWO_CUDA_DEDUCTION_INVALID() asm volatile("trap;")
#endif

static __device__ __forceinline__ void stwo_wit_decode_u384(const unsigned *input, unsigned *output) {
    for (unsigned i = 0u; i < 12u; ++i) output[i] = 0u;
    for (unsigned felt = 0u; felt < 4u; ++felt) {
        for (unsigned limb = 0u; limb < 11u; ++limb) {
            unsigned bit = limb * 9u;
            unsigned word = bit >> 5u;
            unsigned shift = bit & 31u;
            unsigned value = input[felt * 28u + limb] & 0x1ffu;
            output[felt * 3u + word] |= value << shift;
            if (shift > 23u && word + 1u < 3u)
                output[felt * 3u + word + 1u] |= value >> (32u - shift);
        }
    }
}

static __device__ __forceinline__ unsigned stwo_wit_add_u384(
    const unsigned *left,
    const unsigned *right,
    unsigned *output
) {
    cuda_witness_u64 carry = 0u;
    for (unsigned i = 0u; i < 12u; ++i) {
        cuda_witness_u64 value = cuda_witness_u64(left[i]) + cuda_witness_u64(right[i]) + carry;
        output[i] = unsigned(value);
        carry = value >> 32u;
    }
    return unsigned(carry);
}

static __device__ __forceinline__ unsigned stwo_wit_sub_words(
    const unsigned *left,
    const unsigned *right,
    unsigned *output,
    unsigned words
) {
    cuda_witness_u64 borrow = 0u;
    for (unsigned i = 0u; i < words; ++i) {
        cuda_witness_u64 subtrahend = cuda_witness_u64(right[i]) + borrow;
        output[i] = left[i] - unsigned(subtrahend);
        borrow = cuda_witness_u64(left[i]) < subtrahend;
    }
    return unsigned(borrow);
}

static __device__ __noinline__ void stwo_wit_deduce_add_mod_is_zero(const unsigned *input, unsigned *output) {
    unsigned a[12], b[12], c[12], sum[12], difference[12];
    stwo_wit_decode_u384(input, a);
    stwo_wit_decode_u384(input + 112u, b);
    stwo_wit_decode_u384(input + 224u, c);
    stwo_wit_add_u384(a, b, sum);
    stwo_wit_sub_words(sum, c, difference, 12u);
    unsigned combined = 0u;
    for (unsigned i = 0u; i < 12u; ++i) combined |= difference[i];
    output[0] = combined == 0u;
}

static __device__ __forceinline__ void stwo_wit_mul_u384(
    const unsigned *left,
    const unsigned *right,
    unsigned *output
) {
    for (unsigned i = 0u; i < 24u; ++i) output[i] = 0u;
    for (unsigned i = 0u; i < 12u; ++i) {
        cuda_witness_u64 carry = 0u;
        for (unsigned j = 0u; j < 12u; ++j) {
            cuda_witness_u64 value = cuda_witness_u64(left[i]) * cuda_witness_u64(right[j]) +
                cuda_witness_u64(output[i + j]) + carry;
            output[i + j] = unsigned(value);
            carry = value >> 32u;
        }
        unsigned cursor = i + 12u;
        while (carry != 0u && cursor < 24u) {
            cuda_witness_u64 value = cuda_witness_u64(output[cursor]) + carry;
            output[cursor] = unsigned(value);
            carry = value >> 32u;
            ++cursor;
        }
    }
}

static __device__ __forceinline__ bool stwo_wit_remainder_ge(
    const unsigned *remainder,
    const unsigned *divisor
) {
    if (remainder[12] != 0u) return true;
    for (int i = 11; i >= 0; --i) {
        if (remainder[i] != divisor[i]) return remainder[i] > divisor[i];
    }
    return true;
}

static __device__ __forceinline__ void stwo_wit_div_u768_u384(
    const unsigned *numerator,
    const unsigned *divisor,
    unsigned *quotient
) {
    unsigned divisor_nonzero = 0u;
    for (unsigned i = 0; i < 12; ++i) divisor_nonzero |= divisor[i];
    if (divisor_nonzero == 0u) { STWO_CUDA_DEDUCTION_INVALID(); return; }
    unsigned remainder[13];
    for (unsigned i = 0u; i < 13u; ++i) remainder[i] = 0u;
    for (unsigned i = 0u; i < 12u; ++i) quotient[i] = 0u;
    for (int bit = 767; bit >= 0; --bit) {
        unsigned carry = (numerator[unsigned(bit) >> 5u] >> (unsigned(bit) & 31u)) & 1u;
        for (unsigned i = 0u; i < 13u; ++i) {
            unsigned next = remainder[i] >> 31u;
            remainder[i] = (remainder[i] << 1u) | carry;
            carry = next;
        }
        if (stwo_wit_remainder_ge(remainder, divisor)) {
            cuda_witness_u64 borrow = 0u;
            for (unsigned i = 0u; i < 12u; ++i) {
                cuda_witness_u64 subtrahend = cuda_witness_u64(divisor[i]) + borrow;
                unsigned prior = remainder[i];
                remainder[i] = prior - unsigned(subtrahend);
                borrow = cuda_witness_u64(prior) < subtrahend;
            }
            remainder[12] -= unsigned(borrow);
            if (bit >= 384) { STWO_CUDA_DEDUCTION_INVALID(); return; }
            quotient[unsigned(bit) >> 5u] |= 1u << (unsigned(bit) & 31u);
        }
    }
}

static __device__ __noinline__ void stwo_wit_deduce_mul_mod_quotient(const unsigned *input, unsigned *output) {
    unsigned p[12], a[12], b[12], c[12], product[24], extended_c[24], numerator[24], quotient[12];
    stwo_wit_decode_u384(input, p);
    stwo_wit_decode_u384(input + 112u, a);
    stwo_wit_decode_u384(input + 224u, b);
    stwo_wit_decode_u384(input + 336u, c);
    stwo_wit_mul_u384(a, b, product);
    for (unsigned i = 0u; i < 24u; ++i) extended_c[i] = i < 12u ? c[i] : 0u;
    stwo_wit_sub_words(product, extended_c, numerator, 24u);
    stwo_wit_div_u768_u384(numerator, p, quotient);
    for (unsigned word = 0u; word < 32u; ++word) {
        unsigned bit = word * 12u;
        unsigned limb = bit >> 5u;
        unsigned shift = bit & 31u;
        unsigned value = quotient[limb] >> shift;
        if (shift > 20u && limb + 1u < 12u)
            value |= quotient[limb + 1u] << (32u - shift);
        output[word] = value & 0xfffu;
    }
}
