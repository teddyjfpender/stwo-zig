# Recovered scheduling and pipeline work

Original worktrees are unchanged. No perf2 producer/test processes remained at inventory time.

## Scheduling
- Clean commit `c4e6d1e07d8ee6386200c2a9c3ef3ced3b0fa6ad` on `codex/rv64-perf2-sched-sweep`, base `eac3b7c07`.
- Six files: service schedule/pipeline/options, process telemetry, schedule tests, sweep Python.
- `--proof-jobs` up to4, explicit lane budgets total<=32, estimated in-flight memory admission (oversized item runs alone), lane-specific CPU telemetry.
- Proof bytes unchanged by default and4x4 capped smoke, each fresh accepted: `/private/tmp/stwo-rv64-perf-runs/sched-sweep-smoke.receipt.json` has all_identical/all_verified=true. l2x8 wall32.15s vs capped4x4 34.23s: not a measured speedup. Memory cap uses8bytes/nativecell as heuristic, does not bound total process RSS or all retained state.
- Safe combined-services output `/private/tmp/claude-501/sched-combined.log` finished exit0,401suser/6m38s elapsed. Terminal/options and toolbuild also completed in agent trace.
- Review found shared mutableTimer.read race across lanes, and explicit single-lane workers ignored if callerpool larger; fixes being qualified in `/private/tmp/stwo-rv64-recovered-scheduling`, separate branch, original unchanged.
- Developer trace agent `a873b53da421ea002`; review trace `a90f87674f99f943f` ended without final review verdict. Root trace project41eff230-75ab-4f11-a53b-7db4dcd5a611.

## Composition queue
- Original `/private/tmp/stwo-rv64-perf2-composition-queue`, HEADstill eac3b7c07, dirty22tracked+2new: cooperative_queue.zig and air/component_queue_test.zig.
- Cooperative top-level components and row/column chunks share a leased workqueue, with soft expanded-memory admission. Compatibility switch `STWO_ZIG_COMPOSITION_SCHEDULER=legacy`; optional bytecap and timing.
- Prefix evidence: cq-s-l1/l2 composition5.244/5.429s versus cq-s-q1/q2 3.089/3.091s; wall30.59/31.90→29.65/29.07s, usercpu~3%higher. Unbudgeted queue increased footprint; budgeted cq-s-q1g/q2g reduced footprint~14.5→11.5–11.7GB but composition3.09→4.09/3.95s.
- Latest ABBA sequence cq-ab-l1/q1/q2/l2/l3 recorded wall24.78/23.77/21.98/23.54/23.95s and prove20.15/18.75/17.71/19.24/19.52s; q3 killed midway. Not a complete balanced timing qualification.
- Developer trace `a066c7e358ddb418b`; taskbs9q9xi1j.output killed midlatest ABBA. `zig build test-air` in src/prover and RV64ALUSafe exercised. Deliberate temporary failing canaries validated testdiscovery and were removed (none remain on inspected finalsource); do not misreport their expected failures as bugs.
- Need final sourcecommit, review queue liveness/failure cleanup, full Safe/Fast gates, exact checkpointprefix+fresh, honest memory/timing receipt before defaultadoption.

## Interaction generation
- Original `/private/tmp/stwo-rv64-perf2-interaction-gen`, WIPcommit09a48a6e0 plus13tracked+new shift_word_packed_table_interaction.zig.
- Dirty implementation adds line-complete scatter groups and parallel prefixwaves forCPU/LS/BINARY/SHIFT/MUL plus joined packedSHIFTtable generation, parity and allocationfailure tests.
- Real `ig-final-a` prefix hashes match baseline; separate receiveraccepted (trace). Freshmostsource includes tests added after some builds; rebuild qualification required.
- Added packedSHIFT serialoracle equality at1,3,8workers including interaction+dictionary and limitedOOM checks. Eight Safe suites launched: multiplication-degree3, word16-execution-source, word16-memory, word16-binary-native-fill, word16-ls-native-fill, word16-shift-weighted, word16-shift-native-fill, word16-global-execution. Individual completion evidence must still be extracted or rerun.
- FinalABBA stopped after ig-ab-base1; ig-ab-igb empty/incomplete. No finished timingclaim.
- Developertrace `a3460cb9c20d206ec`, scratchpad/ig/run4.sh + stages.py retain harness.
- Need final checkpointreview+tests+newprefix/fresh before runtimeintegration.

## Recovered trace extracts
`/tmp/rv64-recovery-a873b53da421ea002.commands.txt`, `/tmp/rv64-recovery-a90f87674f99f943f.commands.txt`, `/tmp/rv64-recovery-a066c7e358ddb418b.commands.txt`, `/tmp/rv64-recovery-a3460cb9c20d206ec.commands.txt` hold filtered historical commands. Parent is preserving raw traces and dirty source separately.
