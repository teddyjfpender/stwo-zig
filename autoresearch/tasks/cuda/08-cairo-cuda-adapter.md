# Task 08: Cairo CUDA Adapter

Status: next frontend after Native CUDA architecture closure

## Objective

Emit stwo-cairo components as generic `ProofProgram` and execute them through
the same CUDA runtime/compiler without creating a Cairo-specific GPU prover.

## Deliverables

- Cairo trace, components, interaction claims, public inputs, quotient, and FRI
  semantics are represented generically.
- Program and immutable tables are cached only under complete statement
  identity.
- Starknet PIE and block-sized inputs use bounded accounted admission.
- AIR-specific code ships in authenticated program packs.
- Benchmark coverage includes varied Cairo functions and large SN PIEs.

## Gates

- Pinned Rust stwo-cairo is the final correctness oracle.
- Zig CPU/CUDA canonical proof and transcript parity.
- Component-by-component oracle comparison during porting.
- Public statement and PIE mutation rejection.
- Zero fallback/JIT and exactly one terminal D2H.
- Complete lifecycle, stage, memory, and resource telemetry.
- Sustained randomized block/PIE queue produces every proof in order.
- No separate Cairo runtime, scheduler, arena, PCS, or transcript.

## Exit Evidence

- Small function, complex function, SNOS-like, and large SN PIE receipts.
- CPU/CUDA and Rust-oracle parity matrix.
- Stage and memory scaling report.
- Separate Cairo CUDA board proposal only after locked-host A/A calibration.

## Follow-On Performance Target

Task `09-cairo-sn-pie-subsecond.md` makes the four canonical SN PIEs the next
system workload after this semantic adapter is correct. It requires full
input-to-verified-proof timing below one second, without fixture-specific
shortcuts or a separate Cairo CUDA runtime.
