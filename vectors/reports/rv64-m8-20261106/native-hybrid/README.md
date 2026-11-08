# native-hybrid (codex/rv64-m8-native-hybrid) — 2026-11-06

`STWO_RV64_M8_NATIVE_JOBS=1` (default off; unset = today's path) runs each CPU segment's proving as two jobs on the
persistent per-GPU workers inside today's legacy orchestration (legacy keeps admission, the global-chi barrier,
truths, recursion, publication):

* **Stage1Job** behind the legacy local-GKR `NumericalStage`: local GKR + Eq/prefix binding (one job, one wait).
  MAIN is copied into the job window; the binding output goes into a **request-retained region** (`jobs/retained.zig`).
* **Stage2Job** behind the one legacy hook (`coordinator.NativeStageTwo`): global interaction of every slot, INTER,
  device-drawn composition coefficient + composition with device claim slots, OODS, enqueue-only PCS, on one device
  transcript (one job, one wait). MAIN comes from the legacy owner (replay restore). Host: framing, PCS decode,
  publicClaims, engine OODS constraint check, `encodePhysical`.
* Per-job **arena windows** on parked workers (unpark to the declaration + outside allocations, park after).

Parity [M]: per-segment proof bytes and all gated artifacts byte-identical to the frozen D2 golden, cold + warm, on
26235156 (32/32) and 24628607 (39/39). Gates: default and `NATIVE_JOBS=1` PASS on both blocks (`gates.json`).

**Not a win yet [M, diagnostic]:** warm native window 26235156 2.92 s → 5.05 s, 24628607 4.03 s → 5.31 s. Stage2 GPU time
is ~0.23 s/segment, but host framing (0.3–1.2 s) and assembly (0.3–3.1 s) per segment, the legacy MAIN replay before
stage two and one window per GPU at a time dominate. Next levers: cache the class framing (Set, mask points,
PcsJob.prepare, composition/INTER plans), drop the second Components.Set in the OODS check, retain MAIN when memory
allows (24628607 OOMs a legacy truth lease with it today), overlap windows.
