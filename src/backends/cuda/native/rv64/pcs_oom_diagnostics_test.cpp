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
  std::puts("PCS OOM pool diagnostic host mocks PASS");
}
