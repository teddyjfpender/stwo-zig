#ifndef STWO_CUDA_RV64_TRACE_STREAM_PLAN_H
#define STWO_CUDA_RV64_TRACE_STREAM_PLAN_H
// Chunked LDE -> Merkle streaming schedule; mirrors
// src/integrations/riscv_cuda/rv64/trace_stream_plan.zig. A lifted Merkle leaf
// is ONE Blake2s message over all columns in stable ascending-height order, so
// any column boundary may be carried by the unfinalized per-row state (24
// words). The root depends only on column values and order, never on chunks.
#include <cstdint>
#include <vector>
namespace stwo::cuda::rv64::stream {
constexpr uint64_t kStateWords = 24, kAlignWords = 64, kMaxSegments = 96;
constexpr uint64_t kDefaultChunkWords = uint64_t(1) << 27;
inline uint64_t alignUp(uint64_t w) { return (w + kAlignWords - 1) / kAlignWords * kAlignWords; }
inline uint64_t treeWords(uint32_t leaves) { return (uint64_t(2) * leaves - 1) * 8; }
struct Call {
  uint32_t first, end, size, absorbed, seed_size;
  int seed_bank; // -1: none
  uint32_t out_bank;
  bool final;
  uint64_t chunk_words;
};
struct Plan {
  std::vector<Call> calls;
  uint64_t chunk_words = 0, bank_words[2]{0, 0}, tree_words = 0;
  uint32_t leaves = 0;
  uint64_t scratchWords() const { return alignUp(chunk_words) + alignUp(bank_words[0]) + alignUp(bank_words[1]); }
  uint64_t bankOffset(uint32_t bank) const { return alignUp(chunk_words) + (bank ? alignUp(bank_words[0]) : 0); }
};
// rows: LDE rows per column, nondecreasing powers of two. leaves: Merkle leaf
// rows (>= the tallest column; 0 means the tallest column). Returns false on
// invalid geometry. A column taller than the budget is its own chunk.
inline bool plan(const std::vector<uint32_t> &rows, uint64_t budget, Plan *out,
                 uint32_t leaves = 0) {
  if (rows.empty() || rows.size() > 65535 || !budget || !out) return false;
  if (!leaves) leaves = rows.back();
  if (leaves < rows.back() || (leaves & (leaves - 1))) return false;
  uint32_t previous = 0;
  for (auto r : rows)
    if (r < 2 || (r & (r - 1)) || r < previous) return false;
    else previous = r;
  Plan p{};
  p.leaves = leaves;
  p.tree_words = treeWords(p.leaves);
  uint32_t first = 0, absorbed = 0;
  while (first < rows.size()) {
    uint32_t end = first;
    uint64_t words = 0, segments = 0;
    for (; end < rows.size(); ++end) {
      const bool fresh = end == first || rows[end] != rows[end - 1];
      if (end > first && (words + rows[end] > budget || (fresh && segments == kMaxSegments))) break;
      words += rows[end];
      segments += fresh;
    }
    const uint32_t index = uint32_t(p.calls.size());
    Call c{first, end, end == rows.size() ? leaves : rows[end - 1], absorbed,
           index ? p.calls.back().size : 0u,
           index ? int((index - 1) & 1u) : -1, index & 1u, end == rows.size(), words};
    p.calls.push_back(c);
    if (words > p.chunk_words) p.chunk_words = words;
    const uint64_t written = c.final ? p.tree_words : uint64_t(c.size) * kStateWords;
    if (written > p.bank_words[c.out_bank]) p.bank_words[c.out_bank] = written;
    absorbed += end - first;
    first = end;
  }
  *out = std::move(p);
  return true;
}
} // namespace stwo::cuda::rv64::stream
#endif
