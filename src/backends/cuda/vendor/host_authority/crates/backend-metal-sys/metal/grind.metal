#include <metal_stdlib>
using namespace metal;

// Blake2s IV constants (duplicated from blake2s.metal to keep grind self-contained).
constant uint GRIND_BLAKE2S_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

constant uchar GRIND_BLAKE2S_SIGMA[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

static inline uint grind_rotr32(uint value, uint shift) {
    return (value >> shift) | (value << (32u - shift));
}

// Single Blake2s compression for grind: hash a 40-byte message (prefix_digest + nonce)
// in one block. Returns the first word of the hash output.
//
// The message is: [prefix_digest[0..8], nonce_lo, nonce_hi, 0, 0, 0, 0, 0, 0]
// Total bytes = 40 (32 prefix + 8 nonce).
// This is the finalization compression (last block flag set).
static inline uint grind_blake2s_hash_nonce(
    constant uint *prefix_digest,
    uint nonce_lo,
    uint nonce_hi
) {
    // Message block: 16 words
    uint m[16];
    m[0]  = prefix_digest[0];
    m[1]  = prefix_digest[1];
    m[2]  = prefix_digest[2];
    m[3]  = prefix_digest[3];
    m[4]  = prefix_digest[4];
    m[5]  = prefix_digest[5];
    m[6]  = prefix_digest[6];
    m[7]  = prefix_digest[7];
    m[8]  = nonce_lo;
    m[9]  = nonce_hi;
    m[10] = 0u;
    m[11] = 0u;
    m[12] = 0u;
    m[13] = 0u;
    m[14] = 0u;
    m[15] = 0u;

    // Initialize state from IV with parameter block (key=0, hashlen=32).
    uint v[16];
    v[0]  = GRIND_BLAKE2S_IV[0] ^ 0x01010020u;
    v[1]  = GRIND_BLAKE2S_IV[1];
    v[2]  = GRIND_BLAKE2S_IV[2];
    v[3]  = GRIND_BLAKE2S_IV[3];
    v[4]  = GRIND_BLAKE2S_IV[4];
    v[5]  = GRIND_BLAKE2S_IV[5];
    v[6]  = GRIND_BLAKE2S_IV[6];
    v[7]  = GRIND_BLAKE2S_IV[7];
    v[8]  = GRIND_BLAKE2S_IV[0];
    v[9]  = GRIND_BLAKE2S_IV[1];
    v[10] = GRIND_BLAKE2S_IV[2];
    v[11] = GRIND_BLAKE2S_IV[3];
    v[12] = GRIND_BLAKE2S_IV[4] ^ 40u;  // t_lo = 40 bytes total
    v[13] = GRIND_BLAKE2S_IV[5];        // t_hi = 0
    v[14] = GRIND_BLAKE2S_IV[6] ^ 0xFFFFFFFFu;  // last block flag
    v[15] = GRIND_BLAKE2S_IV[7];

    // 10 rounds of Blake2s mixing.
    for (uint round = 0u; round < 10u; ++round) {
        // Column step: G(0,4,8,12), G(1,5,9,13), G(2,6,10,14), G(3,7,11,15)
        v[0] = v[0] + v[4] + m[GRIND_BLAKE2S_SIGMA[round][0]];
        v[12] = grind_rotr32(v[12] ^ v[0], 16u);
        v[8] = v[8] + v[12];
        v[4] = grind_rotr32(v[4] ^ v[8], 12u);
        v[0] = v[0] + v[4] + m[GRIND_BLAKE2S_SIGMA[round][1]];
        v[12] = grind_rotr32(v[12] ^ v[0], 8u);
        v[8] = v[8] + v[12];
        v[4] = grind_rotr32(v[4] ^ v[8], 7u);

        v[1] = v[1] + v[5] + m[GRIND_BLAKE2S_SIGMA[round][2]];
        v[13] = grind_rotr32(v[13] ^ v[1], 16u);
        v[9] = v[9] + v[13];
        v[5] = grind_rotr32(v[5] ^ v[9], 12u);
        v[1] = v[1] + v[5] + m[GRIND_BLAKE2S_SIGMA[round][3]];
        v[13] = grind_rotr32(v[13] ^ v[1], 8u);
        v[9] = v[9] + v[13];
        v[5] = grind_rotr32(v[5] ^ v[9], 7u);

        v[2] = v[2] + v[6] + m[GRIND_BLAKE2S_SIGMA[round][4]];
        v[14] = grind_rotr32(v[14] ^ v[2], 16u);
        v[10] = v[10] + v[14];
        v[6] = grind_rotr32(v[6] ^ v[10], 12u);
        v[2] = v[2] + v[6] + m[GRIND_BLAKE2S_SIGMA[round][5]];
        v[14] = grind_rotr32(v[14] ^ v[2], 8u);
        v[10] = v[10] + v[14];
        v[6] = grind_rotr32(v[6] ^ v[10], 7u);

        v[3] = v[3] + v[7] + m[GRIND_BLAKE2S_SIGMA[round][6]];
        v[15] = grind_rotr32(v[15] ^ v[3], 16u);
        v[11] = v[11] + v[15];
        v[7] = grind_rotr32(v[7] ^ v[11], 12u);
        v[3] = v[3] + v[7] + m[GRIND_BLAKE2S_SIGMA[round][7]];
        v[15] = grind_rotr32(v[15] ^ v[3], 8u);
        v[11] = v[11] + v[15];
        v[7] = grind_rotr32(v[7] ^ v[11], 7u);

        // Diagonal step: G(0,5,10,15), G(1,6,11,12), G(2,7,8,13), G(3,4,9,14)
        v[0] = v[0] + v[5] + m[GRIND_BLAKE2S_SIGMA[round][8]];
        v[15] = grind_rotr32(v[15] ^ v[0], 16u);
        v[10] = v[10] + v[15];
        v[5] = grind_rotr32(v[5] ^ v[10], 12u);
        v[0] = v[0] + v[5] + m[GRIND_BLAKE2S_SIGMA[round][9]];
        v[15] = grind_rotr32(v[15] ^ v[0], 8u);
        v[10] = v[10] + v[15];
        v[5] = grind_rotr32(v[5] ^ v[10], 7u);

        v[1] = v[1] + v[6] + m[GRIND_BLAKE2S_SIGMA[round][10]];
        v[12] = grind_rotr32(v[12] ^ v[1], 16u);
        v[11] = v[11] + v[12];
        v[6] = grind_rotr32(v[6] ^ v[11], 12u);
        v[1] = v[1] + v[6] + m[GRIND_BLAKE2S_SIGMA[round][11]];
        v[12] = grind_rotr32(v[12] ^ v[1], 8u);
        v[11] = v[11] + v[12];
        v[6] = grind_rotr32(v[6] ^ v[11], 7u);

        v[2] = v[2] + v[7] + m[GRIND_BLAKE2S_SIGMA[round][12]];
        v[13] = grind_rotr32(v[13] ^ v[2], 16u);
        v[8] = v[8] + v[13];
        v[7] = grind_rotr32(v[7] ^ v[8], 12u);
        v[2] = v[2] + v[7] + m[GRIND_BLAKE2S_SIGMA[round][13]];
        v[13] = grind_rotr32(v[13] ^ v[2], 8u);
        v[8] = v[8] + v[13];
        v[7] = grind_rotr32(v[7] ^ v[8], 7u);

        v[3] = v[3] + v[4] + m[GRIND_BLAKE2S_SIGMA[round][14]];
        v[14] = grind_rotr32(v[14] ^ v[3], 16u);
        v[9] = v[9] + v[14];
        v[4] = grind_rotr32(v[4] ^ v[9], 12u);
        v[3] = v[3] + v[4] + m[GRIND_BLAKE2S_SIGMA[round][15]];
        v[14] = grind_rotr32(v[14] ^ v[3], 8u);
        v[9] = v[9] + v[14];
        v[4] = grind_rotr32(v[4] ^ v[9], 7u);
    }

    // Finalize: h[0] = IV[0] ^ param ^ v[0] ^ v[8]
    return (GRIND_BLAKE2S_IV[0] ^ 0x01010020u) ^ v[0] ^ v[8];
}

// GPU PoW grind kernel.
//
// Each thread checks one nonce = (nonce_hi << 32) | thread_id.
// If the hash has enough trailing zeros, atomically updates result_nonce_lo
// with the minimum successful nonce_lo.
//
// Buffer layout:
//   buffer(0): prefix_digest — 8 x uint32 (the Blake2s hash of the PoW prefix data)
//   buffer(1): params — [pow_bits, nonce_hi, 0, 0]
//   buffer(2): result — [found_nonce_lo (atomic_uint, init to 0xFFFFFFFF)]
kernel void blake2s_grind(
    constant uint *prefix_digest [[buffer(0)]],
    constant uint *params [[buffer(1)]],
    device atomic_uint *result [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    uint pow_bits = params[0];
    uint nonce_hi = params[1];
    uint nonce_lo = tid;

    // Early exit if a smaller nonce was already found.
    uint current_best = atomic_load_explicit(result, memory_order_relaxed);
    if (nonce_lo >= current_best) {
        return;
    }

    uint h0 = grind_blake2s_hash_nonce(prefix_digest, nonce_lo, nonce_hi);

    // Check trailing zeros.
    uint trailing = ctz(h0);
    if (trailing >= pow_bits) {
        // Atomically update with minimum nonce_lo.
        atomic_fetch_min_explicit(result, nonce_lo, memory_order_relaxed);
    }
}
