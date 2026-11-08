#pragma once
#include <stdint.h>
// Receiver-owned class/program is selected by the exported callback symbol.
// This descriptor contains only checked source allocations and request geometry.
struct StwoRv64NativeGkrSource {
    const uint32_t *fixed;
    const uint32_t *main;
    const uint32_t *parameters; // compact program parameter order, AoS OM31
    uint32_t *status;           // sticky noncanonical/pole verdict
    uint64_t fixed_words;
    uint64_t main_words;
    uint32_t row_log;
    uint32_t kind;              // local/RAM/KIO/Wire, never a wire-selected class
    uint32_t reserved0;
    uint32_t reserved1;
};
static_assert(sizeof(StwoRv64NativeGkrSource)==64,"native GKR source ABI");
