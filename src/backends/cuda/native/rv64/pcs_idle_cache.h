#pragma once
// Optional upper PCS cache policy. Freed blocks return to the existing context
// async pool; this does not trim that pool or promise physical memory release.
#include <cstdint>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <vector>
namespace rv64_pcs_idle_cache {
struct Limit { bool enabled = false; uint64_t bytes = 0; };
inline Limit parse(const char *text, uint64_t admitted_bytes) {
  if (!text) return {};
  if (!*text) throw std::runtime_error("empty STWO_RV64_PCS_IDLE_CACHE_BYTES");
  uint64_t value = 0;
  unsigned digits = 0;
  for (const char *p = text; *p; ++p) {
    if (++digits > 20 || *p < '0' || *p > '9' ||
        value > (UINT64_MAX - uint64_t(*p - '0')) / 10)
      throw std::runtime_error("invalid STWO_RV64_PCS_IDLE_CACHE_BYTES");
    value = value * 10 + uint64_t(*p - '0');
  }
  if (digits > 1 && *text == '0')
    throw std::runtime_error("noncanonical STWO_RV64_PCS_IDLE_CACHE_BYTES");
  if (value > admitted_bytes)
    throw std::runtime_error("PCS idle cache cap exceeds admitted device bytes");
  return {true, value};
}
struct Trim { uint64_t before = 0, after = 0; size_t released = 0; };
template <class Block, class Release>
Trim trim(Limit limit, std::vector<Block> &blocks, uint64_t &retained,
          Release release) {
  if (!limit.enabled) return {};
  static_assert(std::is_nothrow_move_assignable<Block>::value &&
                std::is_nothrow_destructible<Block>::value,
                "retired-block metadata removal must not fail after free");
  Trim result;
  for (const auto &block : blocks) if (!block.used) {
    if (!block.ptr || !block.words || block.words > UINT64_MAX / 4 ||
        result.before > UINT64_MAX - block.words * 4)
      throw std::runtime_error("invalid idle PCS block ledger");
    result.before += block.words * 4;
  }
  if (result.before > retained)
    throw std::runtime_error("idle PCS blocks exceed retained ledger");
  result.after = result.before;
  while (result.after > limit.bytes) {
    size_t largest = blocks.size();
    for (size_t i = 0; i < blocks.size(); ++i)
      if (!blocks[i].used &&
          (largest == blocks.size() || blocks[i].words > blocks[largest].words))
        largest = i; // Equal-size ties retain original vector order.
    if (largest == blocks.size())
      throw std::runtime_error("idle PCS trim made no progress");
    const uint64_t bytes = blocks[largest].words * 4;
    release(blocks[largest].ptr); // Failure must throw; ledger stays unchanged.
    retained -= bytes;
    result.after -= bytes;
    blocks.erase(blocks.begin() + largest); // Trivial, nonthrowing metadata.
    ++result.released;
  }
  return result;
}
} // namespace rv64_pcs_idle_cache
