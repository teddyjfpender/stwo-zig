// Host-only test of the exact control flow called by context.cu.
#include "runtime/pool_trim_policy.h"
#include <cassert>
#include <vector>
struct Fake {
  int validation = 0, join_status = 0, trim_status = 0;
  bool capturing = false;
  unsigned live_words = 64, generation = 9, reserved = 1024;
  std::vector<int> calls;
  int run() {
    return stwo::cuda::runtime::trim_pool(
        [&] { calls.push_back(1); return validation; },
        [&] { calls.push_back(2); return capturing; },
        [&] { calls.push_back(3); return join_status; },
        [&] { calls.push_back(4); if (!trim_status) reserved = live_words;
               return trim_status; }, 99);
  }
};
int main() {
  for (int invalid : {17, 10}) { // wrong owner / wrong device
    Fake f; f.validation = invalid;
    assert(f.run() == invalid && f.calls == std::vector<int>{1});
    assert(f.live_words == 64 && f.reserved == 1024 && f.generation == 9);
  }
  { Fake f; f.capturing = true;
    assert(f.run() == 99 && f.calls == (std::vector<int>{1, 2}));
    assert(f.reserved == 1024); }
  { Fake f; f.join_status = 53;
    assert(f.run() == 53 && f.calls == (std::vector<int>{1, 2, 3}));
    assert(f.reserved == 1024); }
  { Fake f; f.trim_status = 2;
    assert(f.run() == 2 && f.calls == (std::vector<int>{1, 2, 3, 4}));
    assert(f.reserved == 1024 && f.live_words == 64 && f.generation == 9); }
  { Fake f;
    assert(f.run() == 0 && f.calls == (std::vector<int>{1, 2, 3, 4}));
    assert(f.reserved == 64 && f.live_words == 64 && f.generation == 9); }
}
