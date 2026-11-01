# Unverified work-in-progress patches (not applied)

`build.py` applies only `patches/*.patch`; files here are NOT applied, so the
verified client builds are unchanged.

- `0023-evmone-rv64-translated-segments.patch`: interpreter pass 2 checkpoint
  from `codex/rv64-guest-client-interpreter2` (pre-translated segments /
  threaded dispatch). UNVERIFIED. Its number collides with the applied
  `0023-evmone-v3-modexp-arith256-mod.patch`; renumber (e.g. 0024) when the
  track lands with verified basket and EEST results. See HANDOFF.md.
