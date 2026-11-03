#include "prefix_banks.h"
#include "pcs_framing.h"
#include <cstdlib>
#include <cstdint>
#include <vector>
using stwo::cuda::rv64::PrefixBanks;
static void require(bool value) { if (!value) std::abort(); }
int main() {
  uint32_t header[28]{};
  header[0] = 0x52564d53; header[1] = 2; header[15] = 0xffffffff;
  stwo::cuda::rv64::PcsAggregateCounts totals{};
  require(stwo::cuda::rv64::decodePcsCounts(header, 24, &totals));
  require(totals.coefficients == 0xffffffffull);
  require(!stwo::cuda::rv64::decodePcsCounts(header, 28, &totals));
  header[1] = 3; header[16] = 17; header[25] = 1;
  require(stwo::cuda::rv64::decodePcsCounts(header, 28, &totals));
  require(totals.evaluations == (uint64_t(1) << 32) + 17);
  require(!stwo::cuda::rv64::decodePcsCounts(header, 24, &totals));
  require(!stwo::cuda::rv64::decodePcsCounts(header, 27, &totals));
  header[25] = 0xffffffff;
  require(!stwo::cuda::rv64::decodePcsCounts(header, 28, &totals));
  header[25] = 0; header[23] = 1;
  require(!stwo::cuda::rv64::decodePcsCounts(header, 28, &totals));
  // All subsets of 16 increasing heights: every written state fits one bank,
  // while the previous height occupies the other, disjoint bank.
  for (uint32_t mask = 0; mask < (1u << 16); ++mask) {
    PrefixBanks plan;
    std::vector<uint32_t> writes;
    for (uint32_t bit = 0; bit < 16; ++bit)
      if (mask & (1u << bit)) {
        const uint32_t rows = 1u << bit;
        require(plan.addHeight(rows));
        const auto snapshot = plan;
        require(plan.addHeight(rows)); // Equal-height slabs share one write.
        require(plan.next == snapshot.next && plan.words() == snapshot.words());
        writes.push_back(rows);
      }
    for (uint32_t i = 0; i < writes.size(); ++i) {
      const uint32_t bank = i & 1;
      require(writes[i] <= plan.rows[bank]);
      if (i) {
        const uint64_t a = plan.offset(bank), b = plan.offset(bank ^ 1);
        require(a + writes[i] <= b || b + writes[i - 1] <= a);
      }
    }
    const uint64_t last = writes.empty() ? 0 : writes.back();
    const uint64_t prior = writes.size() < 2 ? 0 : writes[writes.size() - 2];
    require(plan.words() == (last + prior) * 24);
    require(plan.words() <= last * 48);
  }
  PrefixBanks largest;
  for (uint32_t log : {9, 15, 17, 19, 21, 22, 24})
    require(largest.addHeight(1u << log));
  require(largest.words() == ((uint64_t(1) << 24) + (1u << 22)) * 24);
  require((uint64_t(1) << 24) * 48 - largest.words() == 301989888);
  const auto before = largest;
  for (uint32_t invalid : {0u, 3u, 1u << 23, 1u << 29}) {
    require(!largest.addHeight(invalid));
    require(largest.words() == before.words() && largest.next == before.next);
  }
}
