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
template<class Handle, class GetPool, class Query>
PoolSnapshot defaultPoolSnapshot(GetPool get_pool, Query query) noexcept {
  Handle pool{};
  const int status = get_pool(&pool);
  if (status != 0) return {0, 0, status};
  return poolSnapshot([&](size_t *used, size_t *reserved) {
    return query(pool, used, reserved);
  });
}
}
