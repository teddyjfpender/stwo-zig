# Unverified work-in-progress patches (not applied)

`build.py` applies only `patches/*.patch`; files here are NOT applied, so the
verified client builds are unchanged.

- `0024-evmone-rv64-translated-segments.patch` (renumbered from wip/0023,
  which collided with the applied v3 modexp patch): interpreter pass 2
  checkpoint from `codex/rv64-guest-client-interpreter2` (pre-translated
  segments / threaded dispatch). Applies cleanly on the current stack but is
  slower: re-measured 2026-11-02, v3 scored 4.778 -> 5.063 instr/gas,
  candidate 3.394 -> 3.680 (dispatch -0.28/gas, translation +0.54/gas). Kept
  parked for reference; see `autoresearch/guest_efficiency/notes/client-pass2-20261102.md`.
