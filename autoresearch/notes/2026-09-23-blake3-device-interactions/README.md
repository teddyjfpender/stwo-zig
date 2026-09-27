# Authenticated BLAKE3 interaction generation on Metal

Previous goal turn: progress, with a qualified sparse-memory traversal change
and evidence identifying CPU hash interactions as a larger remaining cost.
This experiment follows the compiled-AIR/device-execution part of the ZisK
problem mapping. It does not change proof parameters, typed semantics or roots.

## Implementation

The maintained generator exports all eight canonical execution-commitment AIRs
through the existing authenticated direct/relation plans and interaction codegen.
Their eight fraction kernels and six common scan kernels join the native core
AOT inventory (191 native exports). The recursive extension reuses those common
scans instead of defining them again. Manifest source and ABI hashes and runtime
pipeline admission remain exact; no production runtime shader compilation was
introduced. The generator's default mode checks committed source/inventory bytes.

The new shared `generateColumnsInto` ingress borrows existing final-layout main
and fixed columns. It eliminates the older ingress's extra logical-row projection
and source-column allocation. The Metal bridge still stages host columns into
resident buffers and copies generated outputs back; full residency is unfinished.

Execution and extension proofs select device interaction generation only when
the backend advertises the exact generated program. Programs are cached in the
admitted column owner. Unsupported backends/programs use the existing CPU path.
`STWO_RISCV_CPU_HASH_INTERACTIONS=1` forces that path for same-binary controls.
The previous broad recursive-profile capability remains unchanged, so admitting
selected BLAKE3 kernels does not accidentally enable unsupported table kernels.

CPU workspace ownership is now tracked per component. A GPU component may precede
an unsupported CPU component; an initialized-prefix count was no longer valid.
Output allocation and transfer remain failure-atomic. The focused safety-enabled
check covers injected device failure, mixed execution, cleanup and CPU retry,
then verifies real CPU columns/interactions against the original typed oracle.
Mock device outputs are never used as proof witnesses.

## Qualification so far

- Focused ReleaseSafe execution-commitment integration passed.
- Maintained recursive and BLAKE3 AOT catalogs regenerate exactly.
- Native core metallib admission passed: 191 exports, no function constants,
  exact AOT/JIT kernel inventory parity.
- Six shader-authority tests passed, including declaration digests and fail-closed
  runtime pipeline initialization.
- Metal ReleaseFast product builds.
- One canonical ECDSA precompile proof used all eight GPU kernels, verified and
  matched the retained proof bytes. This diagnostic is not the comparison result.

The same-binary Metal comparison completed. It uses 16 workers, 70 queries,
26 PoW bits, three samples per block, zero warmups, and
control/candidate/candidate/control order for ECDSA, SHA256/128, SHA256/2048 and
Keccak/128. GPU dispatch logs must be present only in candidate blocks. Every
retained proof must match the earlier full-suite proof hash and freshly verify.

## Remaining scope

This wires ordinary and extension execution proof generation, covering the CSP
paths through their shared column owner. Native-parent interaction generation is
not switched yet: it retains compact fixed metadata and needs an appropriate
fixed-column/residency plan before using this ingress. Persistent device buffers,
preparation/proving overlap, broader PCS fusion, full CSP baseline recovery and
whole-tree recursion qualification remain unfinished. No new security-parameter
experiment or cross-prover superiority claim is part of this change.

## Measured Metal results

Six samples per arm from a control/candidate/candidate/control sequence of
three-sample blocks; medians below include the complete
transaction, including admission, encoding and fresh verification. The interaction
column measures the host-observed stage including staging and output copies, not
just GPU kernel time.

| Workload | Total CPU-interaction → GPU-interaction seconds | Hash-interaction stage seconds |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 0.991766 → 0.962908 | 0.035839 → 0.017439 |
| sha256-128 | 2.072203 → 1.875904 | 0.253611 → 0.078608 |
| sha256-2048 | 3.630096 → 3.242240 | 0.532077 → 0.144597 |
| keccak-128 | 3.583377 → 3.154529 | 0.543839 → 0.150033 |

All 48 timed proofs and 16 retained fresh verifications passed with unchanged
full-suite proof hashes. A separate smoke proof also passed, excluded from the
comparison. Source, binaries, AOT bundle, exact commands, raw profiles, artifacts
and receipts are retained. The result is a shared Metal improvement, not a new
CPU result, full-suite qualification or claimed recursion latency reduction.
Original SHA/Keccak baseline recovery remains unfinished.

Inspection identifies the next composition gap in
`runtime/base_polynomial_composition.zig`: core-profile execution explicitly
clears framework-polynomial partitions, retaining host evaluation for those AIRs.
The next experiment should extend authenticated composition-kernel coverage and
select supported programs by exact identity, without enabling unknown kernels or
weakening fallback/error policy. It should retain the current interaction result
as its control and qualify complete proofs, not only a composition microbenchmark.
