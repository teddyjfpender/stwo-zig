#pragma once
#include "circuit_assignment.h"
// Exact chain-plan steps, in authenticated dependency order. kind0 = one wide
// level; kind1 = the existing bounded-width chain kernel. No new arithmetic.
struct StwoAssignmentGraphStep {
  uint32_t first, count, first_level, levels, kind;
};
static_assert(sizeof(StwoAssignmentGraphStep) == 20);
extern "C" int stwo_assignment_graph_create_v1(void*, uint32_t,
    const StwoCircuitAssignmentJob*, const StwoAssignmentGraphStep*, uint32_t,
    const uint32_t*, uint32_t, void**);
extern "C" int stwo_assignment_graph_launch_v1(void*, uint32_t, void*,
    const StwoCircuitAssignmentJob*, const uint32_t*, uint32_t);
extern "C" int stwo_assignment_graph_destroy_v1(void*, void*);
