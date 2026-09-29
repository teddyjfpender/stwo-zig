#include <metal_stdlib>
using namespace metal;
constant uint prime = 0x7fffffffu;
inline uint add(uint a, uint b) { uint c = a + b; return c >= prime ? c - prime : c; }
inline uint wide(uint a, uint b) {
    ulong p = (ulong)a * b;
    ulong folded = (p & 0x7ffffffful) + (p >> 31u);
    uint c = (uint)folded;
    return c >= prime ? c - prime : c;
}
inline uint narrow_fold(uint a, uint b) {
    ulong p = (ulong)a * b;
    uint folded = ((uint)p & prime) + (uint)(p >> 31u);
    return folded >= prime ? folded - prime : folded;
}
inline uint split_product(uint a, uint b) {
    uint lo = a * b;
    uint hi = mulhi(a, b);
    uint folded = (lo & prime) + ((hi << 1u) | (lo >> 31u));
    return folded >= prime ? folded - prime : folded;
}
#define VARIANT(name, multiply) \
kernel void name(device const uint* a [[buffer(0)]], \
                 device const uint* b [[buffer(1)]], \
                 device uint* out [[buffer(2)]], \
                 constant uint& rounds [[buffer(3)]], \
                 uint row [[thread_position_in_grid]]) { \
    uint x = a[row], y = b[row]; \
    for (uint r = 0; r < rounds; ++r) { x = add(multiply(x, y), 43u); y = add(y, 97u); } \
    out[row] = x; \
}
VARIANT(wide_variant, wide)
VARIANT(narrow_fold_variant, narrow_fold)
VARIANT(split_product_variant, split_product)
