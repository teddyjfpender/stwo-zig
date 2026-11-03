#include "prefix_banks.h"
#include <cassert>
#include <cstdint>
#include <vector>
using stwo::cuda::rv64::PrefixBanks;
int main() {
  // All subsets of 16 increasing heights: every written state fits one bank,
  // while the previous height occupies the other, disjoint bank.
  for (uint32_t mask = 0; mask < (1u << 16); ++mask) {
    PrefixBanks plan;
    std::vector<uint32_t> writes;
    for (uint32_t bit = 0; bit < 16; ++bit)
      if (mask & (1u << bit)) {
        const uint32_t rows = 1u << bit;
        assert(plan.addHeight(rows));
        const auto snapshot = plan;
        assert(plan.addHeight(rows)); // Equal-height slabs share one write.
        assert(plan.next == snapshot.next && plan.words() == snapshot.words());
        writes.push_back(rows);
      }
    for (uint32_t i = 0; i < writes.size(); ++i) {
      const uint32_t bank = i & 1;
      assert(writes[i] <= plan.rows[bank]);
      if (i) {
        const uint64_t a = plan.offset(bank), b = plan.offset(bank ^ 1);
        assert(a + writes[i] <= b || b + writes[i - 1] <= a);
      }
    }
    const uint64_t last = writes.empty() ? 0 : writes.back();
    const uint64_t prior = writes.size() < 2 ? 0 : writes[writes.size() - 2];
    assert(plan.words() == (last + prior) * 24);
    assert(plan.words() <= last * 48);
  }
  PrefixBanks largest;
  for (uint32_t log : {9, 15, 17, 19, 21, 22, 24})
    assert(largest.addHeight(1u << log));
  assert(largest.words() == ((uint64_t(1) << 24) + (1u << 22)) * 24);
  assert((uint64_t(1) << 24) * 48 - largest.words() == 301989888);
  const auto before = largest;
  for (uint32_t invalid : {0u, 3u, 1u << 23, 1u << 29}) {
    assert(!largest.addHeight(invalid));
    assert(largest.words() == before.words() && largest.next == before.next);
  }
}
