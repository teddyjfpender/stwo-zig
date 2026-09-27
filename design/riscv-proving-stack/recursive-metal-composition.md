# Recursive Metal composition admission

Status: **implemented for the qualified typed recursive-parent profile**.
The earlier small-q193 report documented a historical host-only path that no
longer describes the implementation.

The [typed adapter](../../src/frontends/riscv/recursion/air/universal_typed_component_component_for_manifest.zig)
exports authenticated `.framework_polynomial_v1` capabilities. The
[shared provider](../../src/frontends/riscv/recursion/air/universal_shared_provider.zig)
also exports framework composition capability for the range provider.

The retained [Metal parent log](../../vectors/reports/recursive-product-20260921/speed-research-parent-baseline-v1/metal-0.log)
records positive composition execution evidence:

- Framework composition: 30 components, 13 groups, 8.125 ms GPU.
- Semantic composition: 4 components, 4 kernels, 7.267 ms GPU.
- Lookup composition: 1 component, 1 kernel, 0.423 ms GPU.
- Parent receipt: 30 framework dispatches and zero host composition components.

The same run records 29 typed interaction components and 116 interaction
dispatches. Interaction generation and composition are distinct stages.
`cpu_fallbacks=0` alone remains insufficient evidence of GPU composition;
the explicit coverage and dispatch records above establish execution.

The [baseline report](../../vectors/reports/recursive-product-20260921/speed-research-parent-baseline-v1/README.md)
includes independent verification and qualified artifact identity checks for all
six CPU/Metal runs. This is development-profile qualification, not a claim that
every recursive profile has device coverage.

See the [performance investigation](recursion-performance-investigation.md) for
current bottlenecks. Host preparation and tuple projection dominate this parent;
implementing GPU composition is no longer the next task.
