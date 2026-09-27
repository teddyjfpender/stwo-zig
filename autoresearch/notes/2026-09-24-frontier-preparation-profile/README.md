# Preparation profile after native two-level sharing

The preceding goal turn made verified progress: native integration, matched 24.3%
fixture improvement, final-source focused qualification and archived evidence.
This follow-up profiles the frozen qualified binary without changing its source.

M5 Max, SMP allocator, eight CPU leaf workers, canonical q70/PoW26 throughout.
`STWO_RISCV_PARENT_PREPARATION_PROFILE=1`, with the same authenticated AOT bundle
as the native-two-level-frontier checkpoint. All seven checks and all three aggregate
verifications pass. Complete profiled fixture: 44.15 seconds (single diagnostic run,
not a matched speedup). Raw log and parsed six child preparations are retained.

The root's two independent child preparations spend 2.447 + 2.247 = 4.694 seconds
in paths, of which 2.186 + 1.988 = 4.174 seconds is live emission. Transcript planning
is about 7.7 ms per child; transcript emission is about 46 ms. This argues against
prioritizing transcript plan caching or transcript compaction for total latency.

Next experiment: admit one helper alongside the coordinator through a caller-owned
persistent pool, retain the shared allocator budget, join all helpers before returning
errors, and measure root preparation plus complete fixture and physical memory.
Do not assume parallel preparation wins: large column writes can contend for bandwidth.
Proof parameters, circuits, keys and artifact geometry must remain unchanged.
