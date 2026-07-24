# Task 09: Sub-Second SN PIE Proving

Status: next phase after Native CUDA architecture closure
Priority: ahead of further RISC-V CUDA performance work
Correctness oracle: pinned Rust stwo-cairo

## Objective

Accept each canonical SN PIE as an ordinary Cairo proving request and reduce
the complete warm verified-request boundary below one second on the designated
CUDA judge host. The result must come from generally useful Cairo, PCS, and
CUDA architecture rather than fixture-specific kernels, cached proofs, omitted
components, or timing only the device kernel interval.

The measured boundary is:

```text
canonical PIE bytes available to the proving process
  -> decode and validate
  -> bind public statement
  -> construct all Cairo components and interactions
  -> compile or reuse ProofProgram/CudaPlan
  -> prove through the process-owned CUDA runtime
  -> encode the canonical proof
  -> independently verify
  -> publish the proof
```

The primary request clock starts after the complete canonical request payload
has reached process-owned host memory. PIE decoding, validation, host-to-device
ingress, and every subsequent step remain inside it. Filesystem and network
delivery are separately measured production boundaries because page-cache,
storage, and transport state must not decide the prover verdict. A file-to-proof
receipt is still required for the production CLI.

Cold process, cold input delivery, plan miss, and sustained queue boundaries
remain separate measurements. They must not be hidden inside warmup.

## Required Foundation

This task requires completion of the stwo-cairo-zig semantic port for every
component exercised by the PIE corpus. Cairo must emit the same backend-neutral
`ProofProgram` used by Native and RISC-V; it may not own a second CUDA runtime,
scheduler, PCS implementation, transcript, arena manager, or proof format.

The PIE is already the authenticated output of a Cairo execution. The prover
does not rerun the Cairo program merely to recreate that execution. "Full
Cairo frontend" here means the complete proving adapter: decode and validate
the PIE's memory and execution resources, derive every active claim and public
input, construct every source-derived base and interaction witness, evaluate
the complete pinned stwo-cairo AIR, and bind the resulting statement into the
proof transcript. Reusing proof-derived semantic packs, imported commitment
roots, or pre-existing proofs is never production-admissible.

The porting loop stays component-local:

1. run the pinned Rust component oracle;
2. run Zig CPU for the same inputs and challenges;
3. compare the cumulative interaction accumulator after each component;
4. compare commitment roots and transcript state at each barrier;
5. admit the component to CUDA only after CPU parity;
6. compare CPU and CUDA intermediate values before comparing final proofs.

An unsupported Cairo component is an explicit release blocker. It is never a
CPU fallback.

## Corpus And Throughput Target

The initial corpus is the four canonical inputs under `~/Downloads/SN-PIEs`.
Their current adapted-cycle scale is approximately:

| fixture | adapted cycles | one-second rate required |
| --- | ---: | ---: |
| SN PIE 1 | 14,915,645 | 14.92 MHz |
| SN PIE 2 | 7,977,397 | 7.98 MHz |
| SN PIE 3 | 14,345,552 | 14.35 MHz |
| SN PIE 4 | 14,328,780 | 14.33 MHz |

The current `memory.bin` payloads are 601,669,240, 330,648,840,
585,694,480, and 593,715,160 bytes respectively. Input handling is therefore a
first-class stage: parsing must be bounded and streaming or zero-copy where
possible, but the primary verdict may not depend on an already decoded witness.

Milestones apply to every corpus member, not just the median:

1. complete proof and oracle parity with full attribution;
2. fit the entire request within the accounted device-memory policy;
3. largest PIE below 3.0 seconds verified;
4. largest PIE below 2.0 seconds verified;
5. largest PIE below 1.5 seconds verified;
6. every PIE below 1.0 second verified.

Each milestone is accepted only when the class-equal Cairo portfolio improves
without a significant Native or RISC-V backend regression.

## General Architecture Requirements

- Decode PIE data into compact component inputs; do not materialize a single
  dense CPU-shaped mega-trace when component domains are smaller.
- Preserve distinct component heights and activate expensive tables only when
  the execution uses them.
- Cache immutable program, ROM, domain, twiddle, and lookup material under
  complete semantic and implementation identities.
- Generate witness columns directly into owned, page-aligned backing that CUDA
  can adopt without copyback.
- Keep main, interaction, quotient, and FRI working sets resident where
  lifetimes permit.
- Tile or stream data that cannot fit on a 24 GiB device while preserving one
  proof transcript and bounded peak memory.
- Fuse work only when it removes measured global passes, launches, or
  representation transforms across the corpus.
- Use authenticated per-SM AOT modules in production. JIT and compatibility
  paths are diagnostic-only and promotion-ineligible.
- Perform zero intermediate D2H transfers and exactly one terminal proof read.
- Reuse the process-owned runtime and bounded request service.

## Correctness And Soundness Gates

Every admitted PIE must pass:

1. exact repeated CUDA proof bytes;
2. exact Zig CPU/CUDA proof bytes where the protocol permits;
3. independent Zig verification;
4. pinned Rust stwo-cairo verification;
5. public statement and PIE identity binding;
6. component accumulator parity against Rust;
7. commitment-root and transcript-challenge parity;
8. controlled PIE, public-input, commitment, and proof mutation rejection;
9. zero CPU fallback attempts and completions;
10. exact authenticated AOT admission with zero JIT misses;
11. one terminal D2H operation;
12. zero live arena bytes after request teardown;
13. allocation-failure and device-error unwind coverage;
14. proof publication only after successful independent verification.

No performance result is headline-eligible until all gates pass for all four
fixtures.

## Measurement Contract

Retain, per fixture and repetition:

- source, binary, Rust oracle, PIE, statement, protocol, AOT pack, toolchain,
  driver, and device identities;
- PIE decode, statement binding, trace construction, interaction generation,
  commitment, OODS, quotient, FRI, PoW, decommitment, proof encoding,
  independent verification, publication, and teardown time;
- device critical path, kernel and graph launches, synchronizations, transfers,
  and CPU fallback counters;
- row/cycle MHz, committed cells per second, constraint evaluations per second,
  and hash throughput;
- host RSS, accounted device peak, pool high-water mark, and allocation churn;
- proof digest and size;
- cold process, first request, plan miss, plan hit, steady warm request, and a
  deterministic mixed-PIE queue.

Verdicts use immutable binaries, same-host counterbalanced rounds, at least ten
warmups and seven measured rounds, deterministic bootstrap confidence
intervals, and separate cold/warm boundaries.

## Profiling Order

1. Attribute end-to-end host and device stages.
2. Use Nsight Systems to find idle gaps, transfers, allocation, compilation,
   synchronization, and launch topology.
3. Use Nsight Compute only on the dominant kernels.
4. Quantify representation transformations and global memory passes.
5. Change architecture only from retained evidence.
6. Re-run all four PIEs and the broad Native CUDA portfolio after every
   accepted change.

## Exit Evidence

- Four corpus receipts with exact CPU/CUDA/Rust parity.
- Same-host performance table with total verified-request time and MHz.
- Stage and memory scaling report explaining the dominant remaining costs.
- Retained profiler captures for the dominant paths.
- Broad backend regression matrix.
- A frozen evidence package showing every PIE below one second, or an explicit
  evidence-backed account of the next physical bottleneck if the milestone is
  not yet reached.
