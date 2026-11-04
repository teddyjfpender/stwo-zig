#pragma once
#include <cstddef>
namespace rv64_pcs_oom_diagnostics {
struct PoolSnapshot { size_t used = 0, reserved = 0; int status = 0; };
template<class Query> PoolSnapshot poolSnapshot(Query query) noexcept {
  PoolSnapshot result;
  size_t used = 0, reserved = 0;
  result.status = query(&used, &reserved);
  // Failed queries may partially write outputs; do not report those as valid.
  if (result.status == 0) { result.used = used; result.reserved = reserved; }
  return result;
}
}
