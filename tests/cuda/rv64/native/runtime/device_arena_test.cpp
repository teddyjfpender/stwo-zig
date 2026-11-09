// Host-only tests for the static device arena core (no CUDA needed).
//   g++ -std=c++17 -O2 -Wall -Wextra -o /tmp/arena_test device_arena_test.cpp && /tmp/arena_test
#include "device_arena.h"

#include <stdio.h>
#include <stdlib.h>

#include <random>
#include <vector>

using stwo::cuda::runtime::arena::OffsetArena;

static int failures = 0;
#define EXPECT(cond)                                                    \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "%s:%d: EXPECT failed: %s\n", __FILE__, __LINE__, #cond); \
      ++failures;                                                       \
    }                                                                   \
  } while (0)

static void test_basic_and_coalesce() {
  OffsetArena a(1 << 20);
  uint64_t x = 0, y = 0, z = 0;
  EXPECT(a.allocate(1000, false, &x));
  EXPECT(a.allocate(1000, false, &y));
  EXPECT(a.allocate(1000, false, &z));
  EXPECT(x == 0 && y == 1024 && z == 2048);  // 512-aligned, small = bottom first fit
  EXPECT(a.check());
  EXPECT(a.release(y));
  EXPECT(!a.release(y));       // double free rejected
  EXPECT(!a.release(12345));   // unknown offset rejected
  EXPECT(a.release(x));
  EXPECT(a.release(z));
  EXPECT(a.check());
  EXPECT(a.free_extents() == 1 && a.largest_free() == (1u << 20));
  EXPECT(a.stats().high_water == 3072);
}

static void test_classes() {
  const uint64_t cap = uint64_t(64) << 20;
  OffsetArena a(cap);
  uint64_t lng = 0, small = 0, large = 0;
  EXPECT(a.allocate(8 << 20, true, &lng));
  EXPECT(lng == cap - (8 << 20));             // long packs at the top
  EXPECT(a.allocate(4096, false, &small));
  EXPECT(small == 0);                          // small packs at the bottom
  EXPECT(a.allocate(16 << 20, false, &large));
  EXPECT(large == 4096);                       // best fit: the only hole
  // Best fit prefers the smallest hole that holds the request.
  uint64_t gap_a = 0, sep = 0, gap_b = 0, sep2 = 0;
  EXPECT(a.allocate(10 << 20, false, &gap_a));
  EXPECT(a.allocate(4096, false, &sep));
  EXPECT(a.allocate(6 << 20, false, &gap_b));
  EXPECT(a.allocate(4096, false, &sep2));
  EXPECT(a.release(gap_a));
  EXPECT(a.release(gap_b));
  uint64_t fit = 0;
  EXPECT(a.allocate(5 << 20, false, &fit));
  EXPECT(fit == gap_b);                        // 6 MiB hole, not the 10 MiB one
  EXPECT(a.check());
  // Overrun is a clean failure with no state change.
  const uint64_t used = a.stats().used;
  uint64_t none = 0;
  EXPECT(!a.allocate(cap, false, &none));
  EXPECT(a.stats().used == used && a.stats().failures == 1);
  EXPECT(a.stats().largest_failure == cap);
  EXPECT(a.check());
}

// Randomized differential test against a byte map; also checks determinism.
static std::vector<uint64_t> fuzz(uint64_t seed, bool verify) {
  const uint64_t cap = uint64_t(256) << 20;
  OffsetArena a(cap);
  std::vector<uint8_t> owner(cap / OffsetArena::kAlignment, 0);
  std::mt19937_64 rng(seed);
  struct Live { uint64_t offset, bytes; };
  std::vector<Live> live;
  std::vector<uint64_t> trace;
  for (int step = 0; step < 20000; ++step) {
    const bool do_alloc = live.empty() || (rng() % 100) < 55;
    if (do_alloc) {
      uint64_t bytes;
      const unsigned kind = rng() % 10;
      if (kind < 6) bytes = 1 + rng() % 65536;                 // small
      else if (kind < 9) bytes = (uint64_t(4) << 20) + rng() % (uint64_t(24) << 20);  // large
      else bytes = 1 + rng() % (uint64_t(8) << 20);             // long-ish
      const bool long_lived = kind == 9;
      uint64_t offset = 0, aligned = 0;
      if (a.allocate(bytes, long_lived, &offset, &aligned)) {
        trace.push_back(offset);
        if (verify) {
          EXPECT(offset % OffsetArena::kAlignment == 0);
          EXPECT(aligned >= bytes && offset + aligned <= cap);
          for (uint64_t u = offset / OffsetArena::kAlignment;
               u < (offset + aligned) / OffsetArena::kAlignment; ++u) {
            if (owner[u]) { EXPECT(!"overlap"); break; }
            owner[u] = 1;
          }
        }
        live.push_back({offset, aligned});
      } else {
        trace.push_back(~uint64_t(0));
        if (verify) EXPECT(a.largest_free() < OffsetArena::aligned(bytes));
      }
    } else {
      const size_t i = rng() % live.size();
      EXPECT(a.release(live[i].offset));
      if (verify)
        for (uint64_t u = live[i].offset / OffsetArena::kAlignment;
             u < (live[i].offset + live[i].bytes) / OffsetArena::kAlignment; ++u)
          owner[u] = 0;
      live[i] = live.back();
      live.pop_back();
    }
    if (verify && step % 997 == 0) EXPECT(a.check());
  }
  if (verify) EXPECT(a.check());
  for (const auto &l : live) EXPECT(a.release(l.offset));
  if (verify) {
    EXPECT(a.check());
    EXPECT(a.free_extents() == 1 && a.stats().used == 0);
  }
  return trace;
}

static void test_allocate_at() {
  OffsetArena a(uint64_t(16) << 20);
  EXPECT(a.allocate_at(uint64_t(4) << 20, uint64_t(2) << 20, false));
  EXPECT(!a.allocate_at(uint64_t(5) << 20, 512, false));      // inside a live range
  EXPECT(!a.allocate_at(uint64_t(15) << 20, uint64_t(2) << 20, false));  // past the end
  EXPECT(a.free_extents() == 2 && a.check());
  int extents = 0;
  a.for_each_free([&](uint64_t, uint64_t) { ++extents; });
  EXPECT(extents == 2);
  EXPECT(a.release(uint64_t(4) << 20));
  EXPECT(a.free_extents() == 1 && a.check());
}

int main() {
  test_basic_and_coalesce();
  test_allocate_at();
  test_classes();
  for (uint64_t seed = 1; seed <= 4; ++seed) {
    const auto first = fuzz(seed, true);
    const auto second = fuzz(seed, false);
    EXPECT(first == second);  // same sequence -> same offsets
  }
  if (failures) {
    fprintf(stderr, "device_arena_test: %d failure(s)\n", failures);
    return 1;
  }
  printf("device_arena_test: ok\n");
  return 0;
}
