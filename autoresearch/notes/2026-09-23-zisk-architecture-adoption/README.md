# ZisK architecture adoption: CSP first, then recursion

User direction, 2026-09-23: adopt the relevant ZisK architecture improvements,
surpass the original Poseidon CSP baseline, then qualify efficient recursion.
Stwo superiority is a hypothesis to measure, not an assumed result. The original
persistent-plan / PCS-fusion / final-layout / parameter-research objective remains
active within this scope. Ethereum feature expansion stays deferred.

## Reference and problem matching

[ZisK v1.3.0-alpha](https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha),
release commit `02d2ae7`, describes packed/variable-height AIRs, fewer instances,
fused witness scatter, compiled AIR kernels, and pipelined GPU/recursive work.
Its BLAKE3 configuration is explicitly optional in this alpha. These release
claims guide inspection; they are not isolated measurements of the hash change.
Earlier source-pinned scheduler findings are in the architecture comparison.

| Reference mechanism | Local problem to address | Implementation and acceptance boundary |
| --- | --- | --- |
| Dense traces and instance selection | G/XOR/lookup domain sizes and width still dominate larger CSP cases | Census live and padded field counts, lookup events and LDE bytes per cohort. Evaluate packing against total columns, degree and lookup cost, not row count alone. Preserve full hash constraints and canonical settings. |
| Fused witness generation/scatter | Full logical rows, transpose passes and transient metadata remain | Emit into final committed columns with compact fixed metadata; reuse admitted plans and buffers. Preserve independent fixed preprocessing and prove fresh artifacts. |
| Compiled AIR execution | Core composition is a major remaining parent stage | Inspect per-component interpreter/device fallback costs and specialize measured hot AIRs. Compare CPU/Metal proof behavior and complete proof time. |
| Streaming and device prefetch | Host allocation/staging and synchronous commitment boundaries | Retain plans and device buffers, bound in-flight bytes, overlap only independent work. Measure peak physical footprint as well as tracked allocations. |
| Overlapping leaf and recursive proofs | Sequential preparation/proving within each worker | Add separately owned preparation slots and dependency-ready scheduling with cancellation, admission and memory accounting. Qualify parent-of-parent and complete trees, including uneven trees. |
| Fewer proof instances | More instances multiply verifier work and dependent tree levels | Sweep segment/parent sizes within fixed parameters; measure total work, root latency, throughput, occupancy and memory jointly. Larger circuits are not automatically better. |

Implementation order: resolve the shared CSP trace/proving costs first, carrying
shared changes into native recursion; then finish preparation/proving overlap and
whole-tree qualification. The immediate investigation is the G/XOR/lookup cost
census and final-layout emission path. Do not spend another campaign on isolated
single-digit-percent copy improvements without estimating the remaining gap.

## Completion gates

1. **CSP:** all 16 original workloads on CPU and Metal, unchanged authenticated
   guests/inputs, ECDSA precompile enabled, 70 queries / 26 PoW bits, blowup 1,
   fold step 1 and last-layer degree 0. Match the original execution+witness+prove
   metric and also publish admission, encoding, verification and full transaction.
   Use one warmup and ten verified samples for final qualification. Preserve the
   historical baseline and publish improvements per row, not only a suite average.
   Superseding it means a measured improvement across that basket, not recovery
   from an intermediate BLAKE3 regression.
2. **Memory:** report process-lifetime physical footprint separately from allocator
   peaks and device counters. A cache can improve time while increasing memory.
   Do not infer memory improvements from digest size or fewer logical rows.
3. **Recursion:** canonical native parent, parent-of-parent, CPU/Metal and complete
   dependency trees; independently verify roots and reject changed statement/key/
   transcript bindings. Report cold/warm latency, aggregate work, critical path,
   throughput and peak memory. Subsecond and 10x remain targets until measured.
4. **Cross-prover comparison:** equivalence/superiority requires matched programs,
   security accounting, hardware/resources and timing scope. ZisK GPU block times
   cannot be directly compared with our Apple CSP microbenchmarks. No security
   parameter reduction may be folded into a fixed-profile speed claim.

## Reproducible current gap census

`python3 autoresearch/notes/2026-09-23-zisk-architecture-adoption/compare.py`
recreates `csp-gap.json` from retained reports. It checks guest, input, output and
PCS settings, preserves report fingerprints and records missing subset rows.
The original report's raw output is hashed before comparing with the newer native
report's `output_sha256`. All eight available pairs pass these identity checks.

This is historical diagnostic evidence: original one warmup/ten samples versus
current zero/three, with different source snapshots and no interleaving. It is
not a new benchmark run or promotion. Native reports omit the worker count;
the retained experiment documents 16 workers. Current source includes later
changes which have not been requalified as a complete suite.

| Workload | CPU original → current mean prove seconds | Metal original → current mean prove seconds |
| --- | ---: | ---: |
| ECDSA precompile / 32 | 0.882 → 0.845 | 0.864 → 0.930 |
| SHA256 / 128 | 0.776 → 1.806 | 0.442 → 1.652 |
| SHA256 / 2048 | 0.672 → 3.297 | 0.460 → 3.088 |
| Keccak / 128 | 0.541 → 3.322 | 0.415 → 3.042 |

The memory direction is workload-dependent. Historical CPU physical-footprint
observations are 1.29 → 0.69 GiB for ECDSA but 1.29 → 5.01 GiB for Keccak/128.
These are not a controlled memory qualification, but they directly contradict
any blanket claim that BLAKE3 reduced the system's memory footprint.

Latest recursion evidence is the
[same-binary streaming comparison](../2026-09-23-parent-streaming-parity/README.md):
identical artifacts, recorded stages 59.84 → 47.61 seconds, approximately unchanged
15.0 GB tracked peak, two-worker CPU diagnostic. This is a BLAKE3 integration
improvement, not a Poseidon comparison or a production latency qualification.
