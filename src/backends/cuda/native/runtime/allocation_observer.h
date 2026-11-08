#pragma once
#include <stdint.h>
// Opt-in diagnostic only: boundaries host-join all owner lanes. No admission,
// allocation, proof or transcript policy changes. Stage IDs match Zig adapter.
extern "C" int stwo_exec_context_allocation_observer_begin_v1(
    void *, const uint32_t key[8], uint32_t ordinal, uint32_t domain,
    uint32_t stage, uint32_t lane);
extern "C" int stwo_exec_context_allocation_observer_next_v1(void *, uint32_t stage, uint32_t lane);
extern "C" int stwo_exec_context_allocation_observer_end_v1(void *);
// Reassign the WHOLE existing reservation to the current node, with a possibly
// smaller active request. Zero makes it shared idle cache; never frees memory.
extern "C" int stwo_exec_context_allocation_observer_bind_v1(void *, const void *, uint64_t active_bytes);
extern "C" int stwo_exec_context_allocation_observer_capability_v1(void);
