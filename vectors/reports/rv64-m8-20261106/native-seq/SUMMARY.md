# M8 native-seq: measure step (skipped, blocked)

Head measured: `codex/rv64-m7-integrate` @ `b51a235ed` (code `914f4273c`).

## Verdict

**No A/B was run, and nothing was promoted.** The measure step needs `STWO_RV64_M8_JOBS=1`
to pass `rv64_gate.sh` on both dev blocks first. At the head it does not.

**Blocker.** `jobs/mod.zig` `provider()` still returns `error.M8RequestProviderNotLanded`, and
`jobs/provider.zig` does not exist. So the job runtime boots, but no request reaches a native or
outer job. The JOBS=1 gate fails closed on 26235156 and 24628607 (gate run
`/workspace/m3/runs/m8-native-review-fixes/g1`, on source 914f4273c, which is this head's tree
minus the receipts). Native-finish deliverables 2-4 are still unbuilt, and the JOBS=1 gate can only
pass once they land:

- the witness source without joins
- TruthJob
- `request.Provider`, wired from `provider()`

Cross-job retained device memory (Stage1 -> seal -> Stage2) also has to land before Stage2 can run
as a single real-block job. The interleaved runner (`scripts/rv64_m7_integration_stack.py`, 3+3
arms) was therefore not started, and no request, window, recursion, tail, GPU or launch numbers
are claimed.

## State at head [M] (from the landed receipts, not re-measured here)

| item | 26235156 | 24628607 |
|---|---|---|
| default gate, byte-identical to frozen D2 | PASS (5987d31c…) | PASS (bd6bc793…) |
| JOBS=1 gate | FAIL closed, M8RequestProviderNotLanded | same |
| composition through the Stage2 seam (native_global device claims) | 11/11 | 14/14 |
| global slots at a 20 GiB arena | 76/76 | 127/127 |
| binding / OODS+PCS parity (native-finish-p3) | 4/4, 11/11 | 7/7, 14/14 |

The pod was idle at check time: both GPUs at 0 % and 2 MiB, and no tmux sessions.

## Pod hygiene

Pruned by literal name (all superseded by the receipted runs):

- `m8-native-finish-p3/gate-1` and `gate-1.log` (superseded by `g2`)
- `m8-runtime-persist-p3/host-1.log` and `host-2.log` (superseded by `host-3.log`)
- `m8-runtime-persist-p3/parity-1.{err,json}` (superseded by `parity-2`)

`/workspace` has 17 GB free of 80 GB (80 % used).

## Next (sequential)

1. Cross-job retained device memory (runtime api), then one real-block Stage2 job against the legacy PCS proof.
2. Witness source without joins, then TruthJob, then `jobs/provider.zig`. Then gate JOBS=1 on both blocks.
3. Re-run this measure step: the 3+3 interleaved A/B with a quiet gate.
