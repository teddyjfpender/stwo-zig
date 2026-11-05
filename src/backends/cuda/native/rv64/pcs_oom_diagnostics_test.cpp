#include "pcs_oom_diagnostics.h"
#include <cassert>
#include <cstdio>
int main() {
  unsigned calls = 0;
  auto good = rv64_pcs_oom_diagnostics::poolSnapshot([&](size_t*u,size_t*r) { ++calls; *u=12105697200ull; *r=33600000000ull; return 0; });
  assert(calls==1 && good.status==0 && good.used==12105697200ull && good.reserved==33600000000ull);
  auto bad = rv64_pcs_oom_diagnostics::poolSnapshot([&](size_t*u,size_t*r) { ++calls; *u=99; *r=123; return 17; });
  assert(calls==2 && bad.status==17 && bad.used==0 && bad.reserved==0);
  const int original_allocation_error = 2;
  (void)rv64_pcs_oom_diagnostics::poolSnapshot([](size_t*,size_t*) { return 77; });
  assert(original_allocation_error==2);
  unsigned get_calls = 0, attr_calls = 0;
  auto default_good = rv64_pcs_oom_diagnostics::defaultPoolSnapshot<int>(
    [&](int *handle) { ++get_calls; *handle = 7; return 0; },
    [&](int handle, size_t *used, size_t *reserved) { ++attr_calls; assert(handle == 7); *used = 11; *reserved = 22; return 0; });
  assert(get_calls == 1 && attr_calls == 1 && default_good.used == 11 && default_good.reserved == 22 && default_good.status == 0);
  auto no_handle = rv64_pcs_oom_diagnostics::defaultPoolSnapshot<int>(
    [&](int *handle) { ++get_calls; *handle = 9; return 13; },
    [&](int, size_t*, size_t*) { ++attr_calls; return 0; });
  assert(get_calls == 2 && attr_calls == 1 && no_handle.status == 13 && no_handle.used == 0 && no_handle.reserved == 0);
  auto failed_attributes = rv64_pcs_oom_diagnostics::defaultPoolSnapshot<int>(
    [&](int *handle) { ++get_calls; *handle = 7; return 0; },
    [&](int, size_t *used, size_t *reserved) { ++attr_calls; *used = 99; *reserved = 100; return 17; });
  assert(get_calls == 3 && attr_calls == 2 && failed_attributes.status == 17 && failed_attributes.used == 0 && failed_attributes.reserved == 0);
  std::puts("PCS OOM pool diagnostic host mocks PASS");
}
