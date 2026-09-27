# Canonical BLAKE3 parent stage profile

Same fixture, ReleaseFast, SMP allocator, 16 workers, 70 queries / 26 PoW bits
for leaf and parent. One cold profiled sample; fresh verification passes.
Total parent: 54.658032 s; its proving call: 44.996692 s.

| Proving stage | Seconds |
| --- | ---: |
| Main setup / lookup multiplicities | 13.8334 |
| Main commitment | 2.8792 |
| Interaction generation | 11.4153 |
| Interaction commitment | 2.8093 |
| Core STARK | 14.0425 |

Core STARK includes sampled-value evaluation 10.4896 s, composition evaluation
2.4816 s, FRI quotient/commitment 0.6728 s. These children are included in core,
not additive to it. Trace extraction is negligible. Preparation and key/worker
setup are outside the proving call; see the complete phase log.

Source: prior releasefast-e2e snapshot plus its parent-benchmark-source overlay,
then baseline-producer.zig at src/frontends/riscv/recursion/blake3_native_parent_producer.zig.
The baseline producer adds opt-in stage timing only. The full source archive is
in ../2026-09-23-blake3-releasefast-e2e. Baseline binary SHA is retained here.

First experiment: bounded, worker-private lookup counts with deterministic merge;
no circuit/parameter change. Same-binary serial override permits proof-byte and
full-phase comparison. Sampling/coefficient retention and interaction generation
remain separate measured targets. No tenfold improvement is claimed.

## Qualified experiment: bounded parallel lookup registration

Same-binary B,A,A,B order (parallel, serial, serial, parallel), two cold samples
per arm, no warmups. No compiler or other prover overlapped measured execution.
The first B log is from the focused build gate; its internal timer excludes
compilation. Remaining runs invoke that exact test executable directly.

| Metric | Serial median | Parallel median |
| --- | ---: | ---: |
| Lookup setup | 13.818882 s | 1.120735 s |
| Parent proving call | 45.329949 s | 32.710535 s |
| Complete parent from authenticated leaf | 55.068716 s | 42.495006 s |

**1.296x complete-parent speedup; 22.83% less time.** Lookup setup alone improved
12.33x; that is not the total speedup. All four proof BLAKE3 hashes match:
fd93fe9cceba1f7a3c275634647f7d6459b995f05aeb016e9f99892a6b300741.
All four freshly verified after worker and row destruction. This is local,
source-pinned research, not a judged result, full-tree result, or hash-migration
A/B. ECDSA was not remeasured and does not yet use this helper.

The implementation shares immutable authenticated plans and column views; each
worker owns its two lookup counters. A structured pool lease bounds helper
jobs. Small inputs or unavailable leases use the serial reference path. All
jobs join before errors return or storage is released, and destination counts
are merged only after every worker succeeds. Allocation uses the existing host
budget. Padding multiplicities remain on the original serial path. No AIR,
transcript, proof format, PCS parameter or commitment geometry changed.

The serial comparison switch is STWO_RISCV_SERIAL_PARENT_LOOKUPS=1. Stage profiling
is independently enabled by STWO_RISCV_RECURSIVE_PARENT_PROFILE=1. Neither changes
admission. Candidate source overlays are retained under candidate-source.
run_followups.py pins the local executable path; build the focused target first
and substitute its executable path when reproducing on another checkout.

Next: bounded parallel interaction generation and the coefficient-retention /
sampled-value evaluation tradeoff. The remaining approximately 11.5 s interaction
and 10.5 s opening phases now dominate the proving call. Preserve the complete
parent denominator and memory budget when judging those experiments. Persistent
plans, bounded preparation/proving overlap, wider PCS/DEEP fusion, direct final
layout generation, and the separately reviewed parameter experiment remain the
full objective; this improvement does not complete it or establish 10x.
