#pragma once
#include "../blake2s_reference.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>
// Independent host reference, also checked against Zig's real Om31Channel.
namespace rv64_channel_reference {
struct Channel {
  std::array<uint32_t, 8> digest{};
  uint32_t draws = 0;
  explicit Channel(const uint32_t *seed) {
    std::copy(seed, seed + 8, digest.begin());
    draws = seed[8];
  }
  void mix(const uint32_t *words, uint32_t count) {
    std::vector<uint32_t> input(digest.begin(), digest.end());
    if (count)
      input.insert(input.end(), words, words + count);
    const auto h = blake2s_reference::hash_words(input);
    std::copy(h.words, h.words + 8, digest.begin());
    draws = 0;
  }
  std::array<uint32_t, 8> draw() {
    uint32_t h[8], message[16]{};
    std::copy(blake2s_reference::kIv.begin(), blake2s_reference::kIv.end(), h);
    h[0] ^= 0x01010020u;
    std::copy(digest.begin(), digest.end(), message);
    message[8] = draws++;
    blake2s_reference::compress(h, message, 37, 0xffffffffu);
    std::array<uint32_t, 8> out;
    for (uint32_t i = 0; i < 8; ++i)
      out[i] = uint64_t(h[i]) % 2147483647u;
    return out;
  }
};
} // namespace rv64_channel_reference
