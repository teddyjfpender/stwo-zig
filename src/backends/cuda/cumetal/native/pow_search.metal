#include <metal_stdlib>

using namespace metal;

namespace {

constant uchar kSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

inline uint rotate_right(uint value, uint shift) {
    return (value >> shift) | (value << (32u - shift));
}

inline void mix(
    thread uint *work,
    thread const uint *message,
    uint round,
    uint index,
    uint a,
    uint b,
    uint c,
    uint d) {
    work[a] = work[a] + work[b] + message[kSigma[round][2u * index]];
    work[d] = rotate_right(work[d] ^ work[a], 16u);
    work[c] += work[d];
    work[b] = rotate_right(work[b] ^ work[c], 12u);
    work[a] =
        work[a] + work[b] + message[kSigma[round][2u * index + 1u]];
    work[d] = rotate_right(work[d] ^ work[a], 8u);
    work[c] += work[d];
    work[b] = rotate_right(work[b] ^ work[c], 7u);
}

inline uint candidate_hash_word(
    device const uint *prefix_digest,
    ulong nonce) {
    uint message[16] = {};
    for (uint word = 0; word < 8; ++word) {
        message[word] = prefix_digest[word];
    }
    message[8] = static_cast<uint>(nonce);
    message[9] = static_cast<uint>(nonce >> 32);

    uint work[16] = {
        0x6a09e667u ^ 0x01010020u,
        0xbb67ae85u,
        0x3c6ef372u,
        0xa54ff53au,
        0x510e527fu,
        0x9b05688cu,
        0x1f83d9abu,
        0x5be0cd19u,
        0x6a09e667u,
        0xbb67ae85u,
        0x3c6ef372u,
        0xa54ff53au,
        0x510e527fu ^ 40u,
        0x9b05688cu,
        0x1f83d9abu ^ 0xffffffffu,
        0x5be0cd19u,
    };

    for (uint round = 0; round < 10; ++round) {
        mix(work, message, round, 0, 0, 4, 8, 12);
        mix(work, message, round, 1, 1, 5, 9, 13);
        mix(work, message, round, 2, 2, 6, 10, 14);
        mix(work, message, round, 3, 3, 7, 11, 15);
        mix(work, message, round, 4, 0, 5, 10, 15);
        mix(work, message, round, 5, 1, 6, 11, 12);
        mix(work, message, round, 6, 2, 7, 8, 13);
        mix(work, message, round, 7, 3, 4, 9, 14);
    }
    return (0x6a09e667u ^ 0x01010020u) ^ work[0] ^ work[8];
}

inline ulong index_to_nonce(ulong index) {
    constexpr uint kLowBits = 20;
    constexpr ulong kLowMask = (1ull << kLowBits) - 1ull;
    return ((index >> kLowBits) << 32) | (index & kLowMask);
}

}  // namespace

kernel void stwo_cumetal_pow_search(
    device const uint *prefix_digest [[buffer(0)]],
    constant uint &pow_bits [[buffer(1)]],
    constant ulong &window_begin [[buffer(2)]],
    constant uint &window_size [[buffer(3)]],
    device ulong *best_nonce [[buffer(4)]],
    device uint *completed_blocks [[buffer(5)]],
    device uint *transcript_nonce [[buffer(6)]]) {
    for (uint offset = 0; offset < window_size; ++offset) {
        const ulong nonce = index_to_nonce(window_begin + offset);
        const uint hash_word = candidate_hash_word(prefix_digest, nonce);
        const uint trailing_zeros = hash_word == 0 ? 32u : ctz(hash_word);
        if (trailing_zeros >= pow_bits) {
            *best_nonce = nonce;
            *completed_blocks = 1;
            transcript_nonce[0] = static_cast<uint>(nonce);
            transcript_nonce[1] = static_cast<uint>(nonce >> 32);
            return;
        }
    }
    *completed_blocks = 1;
}
