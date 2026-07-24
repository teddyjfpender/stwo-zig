#ifndef STWO_ZIG_TEST_TRANSCRIPT_REFERENCE_H
#define STWO_ZIG_TEST_TRANSCRIPT_REFERENCE_H

#include "blake2s_reference.h"

#include <array>
#include <cstdint>
#include <vector>

namespace transcript_reference {

using Hash = blake2s_reference::Hash;

inline Hash hash_bytes(const std::vector<std::uint8_t> &bytes) {
    std::uint32_t hash[8];
    for (int index = 0; index < 8; ++index) {
        hash[index] = blake2s_reference::kIv[index];
    }
    hash[0] ^= 0x01010020u;

    const std::size_t full_blocks =
        bytes.empty() ? 0 : (bytes.size() - 1) / 64;
    for (std::size_t block = 0; block < full_blocks; ++block) {
        std::uint32_t words[16] = {};
        for (std::size_t byte = 0; byte < 64; ++byte) {
            words[byte / 4] |=
                std::uint32_t(bytes[block * 64 + byte]) << (8 * (byte % 4));
        }
        blake2s_reference::compress(
            hash, words, (block + 1) * 64, 0);
    }

    std::uint32_t final_words[16] = {};
    const std::size_t offset = full_blocks * 64;
    for (std::size_t byte = offset; byte < bytes.size(); ++byte) {
        const std::size_t relative = byte - offset;
        final_words[relative / 4] |=
            std::uint32_t(bytes[byte]) << (8 * (relative % 4));
    }
    blake2s_reference::compress(
        hash, final_words, bytes.size(), 0xffffffffu);

    Hash result{};
    for (int index = 0; index < 8; ++index) result.words[index] = hash[index];
    return result;
}

inline void append_word(
    std::vector<std::uint8_t> &bytes,
    std::uint32_t word) {
    for (std::uint32_t byte = 0; byte < 4; ++byte) {
        bytes.push_back(static_cast<std::uint8_t>(word >> (8 * byte)));
    }
}

class Channel {
  public:
    void mix(const std::vector<std::uint32_t> &words) {
        std::vector<std::uint32_t> message(digest_.words, digest_.words + 8);
        message.insert(message.end(), words.begin(), words.end());
        digest_ = blake2s_reference::hash_words(message);
        draws_ = 0;
    }

    std::array<std::uint32_t, 8> draw_words() {
        std::vector<std::uint8_t> message;
        message.reserve(37);
        for (std::uint32_t word : digest_.words) append_word(message, word);
        append_word(message, draws_);
        message.push_back(0);
        ++draws_;
        const Hash digest = hash_bytes(message);
        std::array<std::uint32_t, 8> result{};
        for (int index = 0; index < 8; ++index) {
            result[index] = digest.words[index];
        }
        return result;
    }

    std::vector<std::uint32_t> draw_secure(std::uint32_t secure_count) {
        constexpr std::uint32_t kPrime = 0x7fffffffu;
        std::vector<std::uint32_t> result;
        result.reserve(4 * secure_count);
        while (result.size() < 4 * secure_count) {
            const auto words = draw_words();
            bool accepted = true;
            for (std::uint32_t word : words) {
                if (word >= 2u * kPrime) accepted = false;
            }
            if (!accepted) continue;
            for (std::uint32_t word : words) {
                result.push_back(word >= kPrime ? word - kPrime : word);
                if (result.size() == 4 * secure_count) break;
            }
        }
        return result;
    }

    bool valid_pow(std::uint32_t bits, std::uint64_t nonce) const {
        std::vector<std::uint8_t> prefix;
        prefix.reserve(52);
        append_word(prefix, 0x12345678u);
        prefix.insert(prefix.end(), 12, 0);
        for (std::uint32_t word : digest_.words) append_word(prefix, word);
        append_word(prefix, bits);
        const Hash prefix_digest = hash_bytes(prefix);

        std::vector<std::uint8_t> message;
        message.reserve(40);
        for (std::uint32_t word : prefix_digest.words) {
            append_word(message, word);
        }
        append_word(message, static_cast<std::uint32_t>(nonce));
        append_word(message, static_cast<std::uint32_t>(nonce >> 32));
        const Hash result = hash_bytes(message);

        std::uint32_t zeros = 0;
        for (int word = 0; word < 4; ++word) {
            if (result.words[word] == 0) {
                zeros += 32;
            } else {
                zeros += static_cast<std::uint32_t>(
                    __builtin_ctz(result.words[word]));
                break;
            }
        }
        return zeros >= bits;
    }

    std::array<std::uint32_t, 16> state_words(
        std::uint32_t cursor,
        std::uint64_t chain) const {
        std::array<std::uint32_t, 16> result{};
        for (int index = 0; index < 8; ++index) {
            result[index] = digest_.words[index];
        }
        result[8] = draws_;
        result[9] = cursor;
        result[12] = static_cast<std::uint32_t>(chain);
        result[13] = static_cast<std::uint32_t>(chain >> 32);
        return result;
    }

  private:
    Hash digest_{};
    std::uint32_t draws_ = 0;
};

}  // namespace transcript_reference

#endif
