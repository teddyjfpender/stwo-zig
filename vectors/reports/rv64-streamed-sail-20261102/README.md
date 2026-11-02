# Pinned Sail all-ISA qualification of streamed68 GKR

Source 48832ce0d is built in ReleaseFast using the existing `rv64-om-sail-qualification` tool. No source, Sail image, guest, oracle or reference download is changed. The continuous pinned RV64IM corpus retires 1,032,240 instructions over 12,903 cases and exercises all 63 ordinary opcodes. Native capture compares every retirement with the independently generated/pinned Sail RVFI stream before constructing the proving request.

| Profile | Whole proving | Numerical GKR | Physical proof bytes | Fresh receiver |
|---|---:|---:|---:|---|
| OM control: beta1/q70/P26/fold4 |3.418s |1.313s |569,304 |Pass |
| OM candidate: beta2/q256/P0/fold4 |4.315s |1.293s |1,903,064 |Pass |

Both producer processes select `STWO_ZIG_GKR_TREE_CHECKPOINTS=2` and `STWO_ZIG_GKR_STREAM_BOTTOM=1`. Diagnostic metrics report zero raw N/D input-plane bytes and an exact requested-byte child cap of 1,991,804,672 bytes. The numerical requested-byte peak is 671,192,744 bytes in each run. These counters are not physical backing-capacity or RSS measurements. Process peak RSS is 5,326,389,248 bytes for control and 6,017,531,904 bytes for candidate, including the allocator/cache/runtime owners; raw time output is retained. These are functional qualification observations, not a speedup or memory-improvement A/B against the older source.

The four authoritative files in each profile (`bundle.json`, `cells.bin`, `cpu-0.bin`, `stage-one.bin`) hash identically to the previously accepted non-streamed Sail run for that profile. Optional Rust numerical sidecars are outside this comparison. A separate fresh process with GKR operational selection flags removed verifies each bundle, binds the independent expected CPU/RAM endpoint and rejects a wrong final-register endpoint. Each cross-profile verification also rejects with `GlobalGkrManifestExecution`.

Proof bytes, counts, all 63 opcode histogram entries, image/program identities, configuration, frozen producer policy, hard admission cap, per-worker timing and fresh acceptance are retained in the receipt. No new production route or profile is selected. This proves functional compatibility of the streamed source path on this independent ISA workload; it does not certify whole-protocol 128-bit security, Rust PCS/execution verification, GPU execution or Ethereum service coverage.

The producer still has the existing 48 GiB shared requested-byte budget, separate 4 GiB recycler ceiling and eight 1 MiB worker stacks. Runs use the shared heavy lock with `lockf -k`; actual proofs followed the root Safe gate and other timed workload windows. Reproduction uses the existing pinned config under `/private/tmp/stwo-rv64-delivery/word16-independent-qualification-v1/sail/config.json` and refuses overwriting output directories.
