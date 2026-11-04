#pragma once
// Static per-device arena: pure host-side offset allocator (no CUDA calls).
//
// One contiguous device slab is carved once at start. This class only hands
// out offsets inside it. Policy (Airbender/ZisK style, M4 arena stream):
//   - three size/lifetime classes, so that a 10-20 GB composition request
//     still finds a contiguous hole after hours of small churn:
//       long   (immutable setup, cached domains): highest-address fit, carved
//              from the TOP of the hole, so long-lived pages pack at the top;
//       small  (< kSmallBytes): lowest-address first fit, carved from the
//              bottom, so descriptors/params pack at the bottom;
//       large  (everything else): best fit (smallest hole that holds it),
//              lowest address on ties; preserves the biggest holes.
//   - free extents coalesce eagerly with both neighbours;
//   - overrun returns false. The caller turns that into
//     cudaErrorMemoryAllocation; there is never a driver/pool fallback.
// Determinism: the same allocate/release sequence always yields the same
// offsets (std::map/std::set ordering only), so a run is reproducible.
#include <stdint.h>

#include <map>
#include <set>
#include <unordered_map>
#include <utility>

namespace stwo::cuda::runtime::arena {

enum class Class : uint8_t { small = 0, large = 1, long_lived = 2 };

struct Stats {
  uint64_t capacity = 0;
  uint64_t used = 0;               // live bytes (aligned)
  uint64_t used_class[3] = {0, 0, 0};
  uint64_t high_water = 0;         // max live bytes
  uint64_t high_water_class[3] = {0, 0, 0};
  uint64_t low_extent = 0;         // max end offset of any non-long allocation
  uint64_t high_extent = 0;        // max (capacity - start) of any long allocation
  uint64_t allocations = 0;
  uint64_t releases = 0;
  uint64_t failures = 0;
  uint64_t largest_failure = 0;    // bytes of the largest failed request
  uint64_t largest_free_at_failure = 0;
  uint64_t used_at_failure = 0;
};

class OffsetArena {
 public:
  static constexpr uint64_t kAlignment = 512;
  static constexpr uint64_t kSmallBytes = uint64_t(4) << 20;

  explicit OffsetArena(uint64_t capacity) {
    capacity_ = capacity & ~(kAlignment - 1);
    stats_.capacity = capacity_;
    if (capacity_) insert_free(0, capacity_);
  }

  static uint64_t aligned(uint64_t bytes) {
    if (bytes > UINT64_MAX - (kAlignment - 1)) return 0;
    return (bytes + kAlignment - 1) & ~(kAlignment - 1);
  }

  static Class classify(uint64_t bytes, bool long_lived) {
    if (long_lived) return Class::long_lived;
    return bytes < kSmallBytes ? Class::small : Class::large;
  }

  // Returns false (no state change except failure counters) on overrun.
  bool allocate(uint64_t bytes, bool long_lived, uint64_t *out_offset,
                uint64_t *out_aligned = nullptr) {
    const uint64_t need = aligned(bytes);
    if (!need || !out_offset) return false;
    const Class cls = classify(need, long_lived);
    uint64_t hole = 0, hole_bytes = 0;
    bool found = false;
    if (cls == Class::large) {
      auto it = by_size_.lower_bound({need, 0});
      if (it != by_size_.end()) {
        hole_bytes = it->first;
        hole = it->second;
        found = true;
      }
    } else if (cls == Class::small) {
      for (const auto &extent : by_offset_) {
        if (extent.second >= need) {
          hole = extent.first;
          hole_bytes = extent.second;
          found = true;
          break;
        }
      }
    } else {
      for (auto it = by_offset_.rbegin(); it != by_offset_.rend(); ++it) {
        if (it->second >= need) {
          hole = it->first;
          hole_bytes = it->second;
          found = true;
          break;
        }
      }
    }
    if (!found) {
      ++stats_.failures;
      if (need > stats_.largest_failure) {
        stats_.largest_failure = need;
        stats_.largest_free_at_failure = largest_free();
        stats_.used_at_failure = stats_.used;
      }
      return false;
    }
    erase_free(hole, hole_bytes);
    uint64_t offset = hole;
    if (cls == Class::long_lived) {
      offset = hole + hole_bytes - need;
      if (hole_bytes > need) insert_free(hole, hole_bytes - need);
    } else if (hole_bytes > need) {
      insert_free(hole + need, hole_bytes - need);
    }
    live_.emplace(offset, Live{need, cls});
    const unsigned c = static_cast<unsigned>(cls);
    stats_.used += need;
    stats_.used_class[c] += need;
    if (stats_.used > stats_.high_water) stats_.high_water = stats_.used;
    if (stats_.used_class[c] > stats_.high_water_class[c])
      stats_.high_water_class[c] = stats_.used_class[c];
    if (cls == Class::long_lived) {
      if (capacity_ - offset > stats_.high_extent) stats_.high_extent = capacity_ - offset;
    } else if (offset + need > stats_.low_extent) {
      stats_.low_extent = offset + need;
    }
    ++stats_.allocations;
    *out_offset = offset;
    if (out_aligned) *out_aligned = need;
    return true;
  }

  // Carve exactly [offset, offset + aligned(bytes)) out of a free extent.
  bool allocate_at(uint64_t offset, uint64_t bytes, bool long_lived) {
    const uint64_t need = aligned(bytes);
    if (!need || offset % kAlignment) return false;
    auto it = by_offset_.upper_bound(offset);
    if (it == by_offset_.begin()) return false;
    --it;
    const uint64_t hole = it->first, hole_bytes = it->second;
    if (offset < hole || offset + need > hole + hole_bytes) return false;
    erase_free(hole, hole_bytes);
    if (offset > hole) insert_free(hole, offset - hole);
    if (offset + need < hole + hole_bytes) insert_free(offset + need, hole + hole_bytes - offset - need);
    const Class cls = classify(need, long_lived);
    live_.emplace(offset, Live{need, cls});
    const unsigned c = static_cast<unsigned>(cls);
    stats_.used += need;
    stats_.used_class[c] += need;
    if (stats_.used > stats_.high_water) stats_.high_water = stats_.used;
    if (stats_.used_class[c] > stats_.high_water_class[c])
      stats_.high_water_class[c] = stats_.used_class[c];
    ++stats_.allocations;
    return true;
  }

  // Visit free extents in address order: f(offset, bytes).
  template <class F>
  void for_each_free(F f) const {
    for (const auto &extent : by_offset_) f(extent.first, extent.second);
  }

  // Returns false when offset is not a live allocation (no state change).
  bool release(uint64_t offset, uint64_t *out_bytes = nullptr) {
    auto it = live_.find(offset);
    if (it == live_.end()) return false;
    const uint64_t bytes = it->second.bytes;
    const unsigned c = static_cast<unsigned>(it->second.cls);
    live_.erase(it);
    stats_.used -= bytes;
    stats_.used_class[c] -= bytes;
    ++stats_.releases;
    uint64_t start = offset, length = bytes;
    auto next = by_offset_.lower_bound(offset);
    if (next != by_offset_.end() && next->first == offset + bytes) {
      length += next->second;
      const uint64_t next_offset = next->first, next_bytes = next->second;
      erase_free(next_offset, next_bytes);
    }
    auto after = by_offset_.lower_bound(offset);
    if (after != by_offset_.begin()) {
      auto previous = std::prev(after);
      if (previous->first + previous->second == offset) {
        start = previous->first;
        length += previous->second;
        const uint64_t prev_offset = previous->first, prev_bytes = previous->second;
        erase_free(prev_offset, prev_bytes);
      }
    }
    insert_free(start, length);
    if (out_bytes) *out_bytes = bytes;
    return true;
  }

  uint64_t largest_free() const {
    return by_size_.empty() ? 0 : by_size_.rbegin()->first;
  }
  uint64_t free_bytes() const { return capacity_ - stats_.used; }
  size_t free_extents() const { return by_offset_.size(); }
  size_t live_count() const { return live_.size(); }
  uint64_t capacity() const { return capacity_; }
  const Stats &stats() const { return stats_; }
  bool live_bytes(uint64_t offset, uint64_t *out) const {
    auto it = live_.find(offset);
    if (it == live_.end()) return false;
    *out = it->second.bytes;
    return true;
  }

  // Structural self-check for tests: free extents disjoint, coalesced, and
  // free + live == capacity.
  bool check() const {
    uint64_t free_total = 0, cursor = 0;
    bool first = true;
    for (const auto &extent : by_offset_) {
      if (!first && extent.first <= cursor) return false;  // overlap or touching
      if (by_size_.find({extent.second, extent.first}) == by_size_.end()) return false;
      cursor = extent.first + extent.second;
      free_total += extent.second;
      first = false;
    }
    if (by_size_.size() != by_offset_.size()) return false;
    uint64_t live_total = 0;
    for (const auto &entry : live_) live_total += entry.second.bytes;
    return free_total + live_total == capacity_ && live_total == stats_.used;
  }

 private:
  struct Live {
    uint64_t bytes;
    Class cls;
  };
  void insert_free(uint64_t offset, uint64_t bytes) {
    by_offset_.emplace(offset, bytes);
    by_size_.emplace(bytes, offset);
  }
  void erase_free(uint64_t offset, uint64_t bytes) {
    by_offset_.erase(offset);
    by_size_.erase({bytes, offset});
  }
  uint64_t capacity_ = 0;
  std::map<uint64_t, uint64_t> by_offset_;            // offset -> bytes
  std::set<std::pair<uint64_t, uint64_t>> by_size_;   // (bytes, offset)
  std::unordered_map<uint64_t, Live> live_;           // offset -> live
  Stats stats_;
};

}  // namespace stwo::cuda::runtime::arena
