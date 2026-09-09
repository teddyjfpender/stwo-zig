# Strict Metal proving and small-tree performance

Status: paused at the user's request on 2026-09-09; objective remains incomplete.
See [the pause checkpoint](pause-checkpoint-20260909.md) for newer source work,
verified CPU results and the exact outstanding gates. This preserves the complete objective accepted on 2026-09-09.
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
- The recursive framework now executes through an admitted production AOT
  profile and proof-owned resident buffers. Its 51 generated kernels cover
  all 39 leaf-wrapper and 31 parent composition components, derived from the
  same shared AIR catalogs and native provider evaluators used by verification. Physical placement remains bound
  by each owned job; equation-identical placements reuse one kernel.
- The real resident AOT test matches the native arithmetic AIR on all 64
  coordinates and rejects six invalid binding/parameter cases. The complete
  four-segment CPU/GPU composition-parity run freshly verifies all 136 cases,
  retaining byte-identical output for all 21 proof/key/claim artifacts.
- Interaction proof-of-work in leaf wrappers and parents now shares the existing
  backend-aware PCS nonce search. Returned nonces are checked by the transcript.
- Local compact-S-box and recurrence Lean theorems pass with explicit source
  correspondence and axiom checks. Compiler refinement, normalized-denominator
  obligations and protocol security remain open.
- The provider-complete hybrid tree passes all 136 fresh positive/negative
  cases, with all 21 proof/key/claim artifacts identical to the retained baseline.
  Its unshadowed production observation is 61.206 seconds, versus 65.835 seconds
  on the original core route and 71.690 seconds on the intermediate partial GPU
  route. These are single observations, not paired medians.
- Root composition now takes 0.163565 seconds versus the original 0.993760
  seconds, with zero host composition components. The full root is 10.311
  seconds; preparation, main filling/closure and interaction filling dominate.
- Poseidon reuses its native direct/lookup DAGs. Range has an explicit
  independent-prefix layout, mapped preprocessing/main inputs, zero direct
  roots and raw per-batch claims. Existing same-row-prefix identities remain
  unchanged. Actual GPU parity includes multiple distinct claims/previous sums
  and non-Boolean off-domain selectors.

Next, move bulk witness/lookup work and the remaining native composition onto
Metal. Native composition still has nine host components (six tables, program,
Merkle and clock). Domain expansion still fills retained coefficient storage on
the host, with admission enforced in the shared scratch owner before allocation
for semantic, lookup and framework callers. The strict complete-tree positive gate is **not passed**; current
strict tree/parent requests still reject known witness/preparation work.

The immediate interaction opportunity is the parent's serial Poseidon writer:
the leaf already uses the existing chunked batch-inversion route. Measure that
replacement independently, then use claims-free admitted lookup programs to
implement GPU fraction evaluation, inversion, scan and scatter. Preserve raw
independent claims, framework mean-shift semantics, padding and denominator-zero
rejection. Reusable preparation must never manufacture admission with dummy
claims or bypass current input/proof boundaries.

See [the operation inventory and integration map](strict-metal-proving.md),
[formal scope](recursive-air-formal-checks.md), and
[resident AOT checkpoint evidence](../../vectors/reports/riscv-proving-stack-reset-20260908/provider-resident-v1/).
