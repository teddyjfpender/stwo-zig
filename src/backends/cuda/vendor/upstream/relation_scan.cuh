// Shared contract between the relation tail lanes.
//
// The segmented tail (relation_graph.cu: reduce + shift + 3-kernel block scan)
// and the single-pass decoupled-lookback tail (relation_scan.cu) scan exactly
// the same element sequence: `relation_coset_scan_row` is the one bijection
// from scan position to committed storage row, kept here so the lanes cannot
// drift. The partition-descriptor layout below is consumed only by the
// lookback lane, but it is sized host-side (relation_graph.rs mirrors the
// TICKET/STRIDE constants), so it is part of the fixed ABI.

#ifndef RELATION_SCAN_CUH
#define RELATION_SCAN_CUH

#include <cstdint>

// Partition-descriptor buffer layout (all u32 words, zeroed before launch):
//   [0 .. TICKET_WORDS)                       ticket counter (word 0) + pad
//   [TICKET_WORDS + tile*STRIDE + FLAG]       0 none / 1 aggregate / 2 prefix
//   [TICKET_WORDS + tile*STRIDE + AGGREGATE]  tile-local QM31 total
//   [TICKET_WORDS + tile*STRIDE + PREFIX]     inclusive QM31 prefix over the
//                                             instance's tiles [first, tile]
// The QM31 fields sit at 16-byte offsets from a 16-byte-aligned base; both
// are written exactly once, before their flag transition is published, so
// volatile word loads after a volatile flag read cannot tear.
constexpr uint32_t RELATION_SCAN_TICKET_WORDS = 4;
constexpr uint32_t RELATION_SCAN_DESC_STRIDE = 12;
constexpr uint32_t RELATION_SCAN_DESC_FLAG = 0;
constexpr uint32_t RELATION_SCAN_DESC_AGGREGATE = 4;
constexpr uint32_t RELATION_SCAN_DESC_PREFIX = 8;
constexpr uint32_t RELATION_SCAN_FLAG_NONE = 0;
constexpr uint32_t RELATION_SCAN_FLAG_AGGREGATE = 1;
constexpr uint32_t RELATION_SCAN_FLAG_PREFIX = 2;

// `inclusive_prefix_sum_prepared_on` scans relation evaluations in coset
// order: bit-reverse circle order, interleave the two circle-domain halves,
// scan, then undo both permutations. The resulting gather and scatter use
// this same bijection, so disjoint scan tiles can update the output in place.
__device__ __forceinline__ uint32_t relation_coset_scan_row(
    uint32_t scan_index, uint32_t rows) {
  uint32_t circle_index = (scan_index & 1u) == 0u
                              ? scan_index / 2u
                              : rows - 1u - scan_index / 2u;
  uint32_t bits = 31u - __clz(rows);
  return bits == 0u ? 0u : __brev(circle_index) >> (32u - bits);
}

#endif // RELATION_SCAN_CUH
