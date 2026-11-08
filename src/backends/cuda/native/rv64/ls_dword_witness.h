#pragma once
#include <stdint.h>
// Fourteen words/event: A64, immediate64, B64, before64, before_epoch,
// epoch, before_tick, tick, rights, store. Derived after/C are not uploaded.
// MAIN is the native 39-column physical circle layout, including zero padding.
extern "C" int stwo_rv64_ls_dword_witness_on(void *, uint32_t, const uint32_t *,
                                             uint32_t, uint32_t, uint32_t *,
                                             uint32_t *);
