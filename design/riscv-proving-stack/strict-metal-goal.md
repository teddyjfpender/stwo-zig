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
- The recursive framework now executes through an admitted production AOT
  profile and proof-owned resident buffers. Its 41 generated kernels cover
  37/39 leaf-wrapper and 29/31 parent components, derived from the same shared
  AIR catalogs used by native verification. Physical placement remains bound
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
- The current hybrid four-segment tree passes all 136 fresh positive/negative
  cases, with all 21 proof/key/claim artifacts identical to the retained baseline.
  The core-only checkpoint took 65.035 seconds; the new framework AOT route
  took 71.690 seconds without parity shadows. This is a coverage milestone,
  not a speedup or default-profile promotion. Strict requests with the new
  profile still reject known host witness/preparation work.
- The diagnostic root comparison identifies the mixed-route bottleneck:
  29 framework components take 125.927 ms enclosing device work (11.367 ms
  kernels), but the host Poseidon provider takes 2.208 seconds. Composition
  consequently takes 2.282 seconds versus 0.994 seconds on the retained core
  route. Finish this provider's GPU coverage next; do not bury the regression
  beneath faster individual kernels or parallel CPU tuning.

The next implementation boundary is provider/range coverage and bulk
witness/lookup work. The two remaining recursive composition providers use
independent per-batch running sums, unlike the framework's same-row-prefix
recurrence. Their GPU route must preserve those equations explicitly. Domain
expansion still fills retained coefficient storage on the host and remains
guarded in strict mode. The strict complete-tree positive gate is **not
passed**. The accepted hybrid route and retained negative strict requests are
separate evidence.

See [the operation inventory and integration map](strict-metal-proving.md),
[formal scope](recursive-air-formal-checks.md), and
[resident AOT checkpoint evidence](../../vectors/reports/riscv-proving-stack-reset-20260908/framework-resident-v1/).
