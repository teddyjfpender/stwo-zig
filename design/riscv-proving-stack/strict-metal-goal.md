# Strict Metal proving and small-tree performance

Status: active. This preserves the complete objective accepted on 2026-09-09.
The endpoint is the existing complete four-segment RISC-V proof tree, followed by
controlled increases in instructions, memory and recursive depth. Ethereum-sized
runs are not the development loop.

## Required final state

1. **Enforced GPU execution.** Inventory native, wrapper and parent operations.
   Strict production must reject any unsupported bulk proving operation before
   host execution. Positive per-operation GPU evidence is required; zero fallback
   counters or a GPU dispatch elsewhere do not establish coverage. CPU control,
   serialization and independent verification remain separately measured.
2. **Complete GPU support.** Derive direct constraints and exact framework lookup
   recurrences from authenticated AIR plans; bind preprocessing, main columns,
   profile parameters, challenges and claims without another protocol definition.
   Authenticate generated kernels through AOT admission. Complete native, wrapper
   and parent production, including witness expansion, interactions, commitments,
   composition and FRI, must pass strict mode and freshly verify.
3. **Remove repeated work.** Reuse immutable circuit schedules and fixed
   preprocessing, retain useful device buffers, remove repeated graph construction,
   and measure allocations, execution and synchronization. Report cold and warm
   complete requests separately; cache hits never replace input/proof admission.
4. **Specialize leaf wrappers.** Apply demonstrated arithmetic and Poseidon
   reductions to the actual leaf-verifier work, with new AIR keys where required.
   Require improved complete CPU and Metal requests and independent verification.
5. **Harden and scale.** Establish local formal obligations for fusion wire
   preservation, compact Poseidon and lookup boundaries; harden malformed inputs,
   allocation bounds, cancellation and circuit admission. Complete a separate
   production-security argument. Increase instruction, address and tree-size
   workloads gradually with predictable resources and small retained regressions.

Consolidate ownership and delete superseded producers/preparation routes when
replacements pass the complete-proof gate. Keep supported legacy verifier
adapters only where retained artifacts require them. Do not weaken proof
parameters, substitute a smaller endpoint or classify local algebra tests as
whole-prover soundness. The existing q193 profile remains experimental.

## Current checkpoint

- Known host preparation paths now reject `STWO_ZIG_METAL_REQUIRE_GPU=1`.
  Invalid values reject instead of silently selecting hybrid mode. Composition
  guards cover capability-free and mixed host/device requests, and host component
  counts are distinct from legacy fallback counts.
- The shared typed backend program and callbacks export existing admitted direct
  and relation plans. Runtime profile words and challenges remain invocation
  inputs; the claim shift derives from the admitted trace size and claim.
- The generated framework kernel passes actual small Metal/CPU numeric parity.
  This is a test-only compiled library, not production AOT or complete coverage.
- Interaction proof-of-work in leaf wrappers and parents now shares the existing
  backend-aware PCS nonce search. Returned nonces are checked by the transcript.
- Local compact-S-box and recurrence Lean theorems pass with explicit source
  correspondence and axiom checks. Compiler refinement, normalized-denominator
  obligations and protocol security remain open.
- The current hybrid four-segment tree passes all 136 fresh positive/negative
  cases, with all 21 proof/key/claim artifacts identical to the retained baseline.
  Its single production observation is 65.035 seconds; this checkpoint does not
  establish a significant speedup. Strict leaf and parent requests reject before
  known host witness/preparation work.

The next implementation boundary is production AOT/resident dispatch for the
framework catalog, followed by provider/range coverage and bulk witness/lookup
work. The strict complete-tree positive gate is **not passed**. The accepted
hybrid route and retained negative strict requests are separate evidence.

See [the operation inventory and integration map](strict-metal-proving.md),
[formal scope](recursive-air-formal-checks.md), and
[checkpoint evidence](../../vectors/reports/riscv-proving-stack-reset-20260908/strict-metal-v1/).
