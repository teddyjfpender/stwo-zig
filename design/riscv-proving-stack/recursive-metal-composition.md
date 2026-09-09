# Recursive Metal composition admission

Status: **future work**, identified during the small q193 parent optimization
pass. The current pass optimizes preparation, exact lookup closure and shared
host composition, including row sharding. It does not implement GPU evaluation
of the recursive parent catalog.

## Evidence and present boundary

The retained [`parent-hotpath-second-metal-timing-0-after.json.producer.log`](../../vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/parent-hotpath-second-metal-timing-0-after.json.producer.log)
reports `completed=false scheduler=unresolved` after 10,917 ns, followed by
89 Metal dispatches and 10 Poseidon commitments. Those dispatches establish
backend use elsewhere in the request, not GPU composition.

[`base_polynomial_composition.zig`](../../src/backends/metal/runtime/base_polynomial_composition.zig)
returns `null` when `semantic_count + lookup_count == 0`, before scheduler,
residency or AOT preparation. This is the applicable decline condition:

- The 28 typed components in the [parent catalog](../../src/integrations/riscv_cpu/recursive_segment_v2_detached_parent_cohort.zig)
  install a prepared host evaluator through
  [the shared typed adapter](../../src/frontends/riscv/recursion/air/universal_typed_component_component_for_manifest.zig),
  but no `backend_composition_capability`.
- The [range-table component](../../src/frontends/riscv/air/lookups/tables/component.zig)
  also exports no such capability.
- The [shared Poseidon provider](../../src/frontends/riscv/recursion/air/universal_shared_provider.zig)
  uses `.universal`; [HashComponent](../../src/frontends/riscv/air/memory_commitment/hash_component.zig)
  exports a capability only for `.narrow_memory`.

The zero-eligible-components return does not increment the resident-decline
fallback counter. Consequently `cpu_fallbacks=0` cannot establish GPU composition;
this request proceeds through the generic host composition evaluator.

## Reuse and missing admission

The [backend polynomial IR](../../src/prover/air/component_programs.zig) and
[Metal base code generator](../../src/backends/metal/runtime/base_polynomial_codegen.zig)
already implement the requisite base-field arithmetic. Their capabilities bind
one contiguous main-column slab and one selector. Typed recursion also needs
arbitrary preprocessed columns and authenticated profile parameters.

The [V1](../../src/backends/metal/runtime/lookup_polynomial_codegen.zig) and [V2](../../src/backends/metal/runtime/lookup_polynomial_v2_codegen.zig) lookup
kernels implement an independent cross-row prefix per batch. The
[recursive framework](../../src/frontends/riscv/recursion/air/framework_interaction.zig)
uses same-row cumulative differences between adjacent columns, previous-row access only for the final batch, and only the final `claimed_sum / trace_size`
shift. Existing capability tags cannot be reused to describe those equations.

## Next implementation gate

1. Add an explicit framework-layout capability and column-source binding;
   derive exports from the same authenticated direct and relation plans used by
   native verification. Preserve roots, order, claims, profile and proof bytes.
2. Generate matching Metal kernels and pin their AOT identities. Retain the
   host route for unsupported capabilities; never substitute the narrow Poseidon
   shell for the universal provider.
3. Require complete component/range coverage and bit-exact CPU/GPU composition
   parity, including padding, final-prefix boundaries and changed claims. Then
   run the small q193 parent proof, serialize, destroy the producer, and freshly
   verify under the existing admitted key on both backends.
4. Measure complete-request time, live memory, GPU execution and waits separately;
   require positive composition-dispatch evidence before claiming GPU composition.
