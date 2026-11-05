#ifndef STWO_CUDA_RV64_PREFIX_BANKS_H
#define STWO_CUDA_RV64_PREFIX_BANKS_H
#include <cstdint>
namespace stwo::cuda::rv64 {
// One unfinalized Blake state per row. Nonfinal distinct heights alternate
// banks; each bank needs only its own largest write, not the other's maximum.
struct PrefixBanks {
  static constexpr uint64_t state_words = 24;
  uint32_t rows[2]{0, 0}, next = 0, previous = 0;
  bool addHeight(uint32_t size) {
    if (!size || (size & (size - 1)) || size > (1u << 28) || size < previous)
      return false;
    if (size == previous) return true;
    rows[next] = size;
    next ^= 1u;
    previous = size;
    return true;
  }
  uint64_t words() const { return (uint64_t(rows[0]) + rows[1]) * state_words; }
  uint64_t offset(uint32_t bank) const { return bank ? rows[0] : 0; }
};
} // namespace stwo::cuda::rv64
#endif
