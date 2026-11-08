#ifndef RV64_PROJECTION_FIXTURE_H
#define RV64_PROJECTION_FIXTURE_H
#include <cstdint>
struct Rv64ProjectionFixture {
  const uint32_t *fixed, *main, *public_values;
  const uint64_t *offsets;
  const uint32_t *parameters;
  uint32_t *n, *d, *status;
  uint32_t log, first, rows;
};
using Rv64ProjectionLaunch = int (*)(void *, const Rv64ProjectionFixture *);
#endif
