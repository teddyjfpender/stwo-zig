# Streamed raw inputs with dense upper GKR: pinned Sail qualification

The existing `rv64-om-sail-qualification` tool is built in ReleaseFast at source `c30c8f52e` (qualified source80 implementation `0825ec08b` plus parser cleanup). It consumes the existing pinned continuous Sail corpus: **1,032,240 retirements, 12,903 cases, all 63 ordinary RV64IM opcodes**. No guest, oracle, image or production source is changed.

| Profile | Whole proving | Numerical GKR | Proof bytes | Fresh acceptance |
|---|---:|---:|---:|---|
| Control: beta1/q70/P26/fold4 |2.890s |0.883s |569,304 |Pass |
| Candidate: beta2/q256/P0/fold4 |3.611s |0.877s |1,903,064 |Pass |

The producer environment is cleared of existing GKR selections, then sets only `STWO_ZIG_GKR_STREAM_BOTTOM=1` and diagnostic metrics. In particular, `TREE_CHECKPOINTS` and legacy admission overrides are absent. Metrics confirm stride 1, streamed raw input, zero planned/raw N/D input-plane bytes, and an exact child requested-byte cap of 2,342,558,720 bytes. The numerical requested-byte peak is 1,870,709,152 bytes in both profiles. These counters are not original backing-capacity/RSS measurements. Process peak RSS is 5,577,932,800 bytes for control and 5,990,285,312 bytes for candidate, including the separate 4 GiB cache ceiling and runtime owners.

All four authoritative files for each profile hash identically to its earlier accepted non-streamed proof: `bundle.json`, `cells.bin`, `cpu-0.bin` and `stage-one.bin`. Every captured retirement is compared to the pinned independent RVFI stream. Both flag-free fresh receivers bind the independently expected CPU/RAM endpoint and reject a wrong final-register endpoint; both cross-profile attempts reject with `GlobalGkrManifestExecution`.

The shared heavy lock (`lockf -k`) serializes actual runs after compilation. Results establish functional compatibility and current observations. They are not an isolated timing A/B against the earlier streamed-checkpoint source, a whole-protocol 128-bit certificate, Rust execution/PCS verification or GPU qualification. The existing 48 GiB shared requested-byte budget, separate 4 GiB recycler limit and eight 1 MiB worker stacks remain unchanged.

## CSP adapter audit

There is no existing generic CSP entry that selects this OM/GKR path. `rv64-word16-csp` calls `word16_qualification/csp_execution.zig::proveWithSuite`, which constructs the classic joined Word16 setup/source and invokes `word16_execution/execution.zig::provePreparedWithOptions`. It does not call the services OM coordinator, local GKR child, source reader or tree-policy parser. Setting the streaming environment flag on that CLI would therefore not qualify streamed GKR. Existing classic CSP results remain valid in their own route and are not relabeled here.

The current OM adapter is deliberately concrete to `sail_image.Owner`: it requires a pinned Sail revision, per-retirement RVFI agreement, the all 63 opcode/no-service gate and an independently expected full endpoint. CSP has a distinct receiver-owned 32-byte ABI (`csp_image.Owner`, pinned ELF/input, halt flag/output) and its own `csp_capture.Capture`. A real future OM CSP adapter must reuse those authorities and explicitly connect them to the combined coordinator and fresh receiver. It cannot reinterpret CSP as the 43-byte Ethereum ABI, fabricate a Sail oracle, or relax the existing all 63 gate merely to run software ECDSA. No new tool, VM profile or adapter is added in this scope. Full Ethereum and actual Sail are the current source80 execution gates.
