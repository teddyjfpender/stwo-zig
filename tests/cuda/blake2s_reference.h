#ifndef STWO_ZIG_TEST_BLAKE2S_REFERENCE_H
#define STWO_ZIG_TEST_BLAKE2S_REFERENCE_H

#include <array>
#include <cstdint>
#include <vector>

namespace blake2s_reference {

struct alignas(32) Hash {
    std::uint32_t words[8];
};

constexpr std::array<std::uint32_t, 8> kIv = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

constexpr std::uint8_t kSigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

inline std::uint32_t rotate_right(std::uint32_t value, std::uint32_t shift) {
    return (value >> shift) | (value << (32u - shift));
}

inline void compress(
    std::uint32_t hash[8],
    const std::uint32_t message[16],
    std::uint64_t byte_count,
    std::uint32_t last_block) {
    std::uint32_t work[16];
    for (int index = 0; index < 8; ++index) {
        work[index] = hash[index];
        work[index + 8] = kIv[index];
    }
    work[12] ^= static_cast<std::uint32_t>(byte_count);
    work[13] ^= static_cast<std::uint32_t>(byte_count >> 32);
    work[14] ^= last_block;

    auto mix = [&](int round, int pair, int a, int b, int c, int d) {
        work[a] += work[b] + message[kSigma[round][2 * pair]];
        work[d] = rotate_right(work[d] ^ work[a], 16);
        work[c] += work[d];
        work[b] = rotate_right(work[b] ^ work[c], 12);
        work[a] += work[b] + message[kSigma[round][2 * pair + 1]];
        work[d] = rotate_right(work[d] ^ work[a], 8);
        work[c] += work[d];
        work[b] = rotate_right(work[b] ^ work[c], 7);
    };
    for (int round = 0; round < 10; ++round) {
        mix(round, 0, 0, 4, 8, 12);
        mix(round, 1, 1, 5, 9, 13);
        mix(round, 2, 2, 6, 10, 14);
        mix(round, 3, 3, 7, 11, 15);
        mix(round, 4, 0, 5, 10, 15);
        mix(round, 5, 1, 6, 11, 12);
        mix(round, 6, 2, 7, 8, 13);
        mix(round, 7, 3, 4, 9, 14);
    }
    for (int index = 0; index < 8; ++index) {
        hash[index] ^= work[index] ^ work[index + 8];
    }
}

inline Hash hash_prefixed_words(
    std::uint32_t tag,
    const std::vector<std::uint32_t> &words) {
    std::uint32_t hash[8];
    for (int index = 0; index < 8; ++index) hash[index] = kIv[index];
    hash[0] ^= 0x01010020u;
    std::uint32_t prefix[16] = {};
    prefix[0] = tag;
    if (words.empty()) {
        compress(hash, prefix, 64, 0xffffffffu);
        Hash result{};
        for (int index = 0; index < 8; ++index) {
            result.words[index] = hash[index];
        }
        return result;
    }
    compress(hash, prefix, 64, 0);

    const std::size_t full_blocks =
        words.empty() ? 0 : (words.size() - 1) / 16;
    for (std::size_t block = 0; block < full_blocks; ++block) {
        compress(hash, words.data() + block * 16, 64 + (block + 1) * 64, 0);
    }
    std::uint32_t final_block[16] = {};
    const std::size_t offset = full_blocks * 16;
    for (std::size_t index = offset; index < words.size(); ++index) {
        final_block[index - offset] = words[index];
    }
    compress(
        hash,
        final_block,
        64 + words.size() * sizeof(std::uint32_t),
        0xffffffffu);

    Hash result{};
    for (int index = 0; index < 8; ++index) result.words[index] = hash[index];
    return result;
}

inline Hash hash_words(const std::vector<std::uint32_t> &words) {
    std::uint32_t hash[8];
    for (int index = 0; index < 8; ++index) hash[index] = kIv[index];
    hash[0] ^= 0x01010020u;

    const std::size_t full_blocks =
        words.empty() ? 0 : (words.size() - 1) / 16;
    for (std::size_t block = 0; block < full_blocks; ++block) {
        compress(hash, words.data() + block * 16, (block + 1) * 64, 0);
    }
    std::uint32_t final_block[16] = {};
    const std::size_t offset = full_blocks * 16;
    for (std::size_t index = offset; index < words.size(); ++index) {
        final_block[index - offset] = words[index];
    }
    compress(
        hash,
        final_block,
        words.size() * sizeof(std::uint32_t),
        0xffffffffu);

    Hash result{};
    for (int index = 0; index < 8; ++index) result.words[index] = hash[index];
    return result;
}

inline Hash hash_leaf_words(const std::vector<std::uint32_t> &words) {
    return hash_prefixed_words(0x6661656cu, words);
}

inline Hash hash_children(const Hash &left, const Hash &right) {
    std::vector<std::uint32_t> words;
    words.insert(words.end(), left.words, left.words + 8);
    words.insert(words.end(), right.words, right.words + 8);
    return hash_prefixed_words(0x65646f6eu, words);
}

inline bool equal(const Hash &left, const Hash &right) {
    for (int index = 0; index < 8; ++index) {
        if (left.words[index] != right.words[index]) return false;
    }
    return true;
}

}  // namespace blake2s_reference

#endif
