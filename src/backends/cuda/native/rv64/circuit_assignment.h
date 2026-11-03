#pragma once
#include <cstdint>
// Generation-only descriptors of the original circuit topology. They never
// replace, weaken or add to the independently verified circuit constraints.
struct StwoCircuitAssignmentTask { uint32_t kind, out, args[6]; };
struct StwoCircuitAssignmentSeed { uint32_t out, value[4]; };
struct StwoCircuitAssignmentJob {
  uint32_t *values;
  const void *records;
  const uint32_t *indices;
  uint32_t *status;
  uint32_t value_count,record_count,index_count,first,count,reserved;
};
static_assert(sizeof(StwoCircuitAssignmentTask)==32);
static_assert(sizeof(StwoCircuitAssignmentSeed)==20);
static_assert(sizeof(StwoCircuitAssignmentJob)==56);
extern "C" int stwo_circuit_assignment_seed_on(void*,uint32_t,const StwoCircuitAssignmentJob*);
extern "C" int stwo_circuit_assignment_level_on(void*,uint32_t,const StwoCircuitAssignmentJob*);
