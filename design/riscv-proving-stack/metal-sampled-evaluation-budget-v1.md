# Metal sampled evaluation scratch admission

The existing sampled coefficient and barycentric production entrypoints now use
constructor-time shared external-byte admission. Nine device-free checks pass,
all eleven actual runtime/backend body wrappers compile into an object, and the
complete assembled Objective-C runtime passes syntax checking after the final
byte-threshold revision. All thirteen frozen source hashes match. Evidence is
retained in `cpu-performance-gates-v1/metal-sampled-evaluation-budget-qualified-v1.json`
under the Ethereum block delivery notes. No device execution, STARK generation or
speedup is claimed.

`sampled_dispatch_budget_v1.Scope` uses the existing generic external allocation
scope. A supplied `SharedHostBudget` is always charged against its synchronized
heap-plus-external limit, including when an ordinary compatibility entrypoint
selects `explicit_unbudgeted`. Exact allocator identity is retained through
prepared/output-array cleanup. General Metal callers with ordinary allocators
retain the explicit uncapped compatibility route. There is no CPU evaluation
fallback in these dispatch methods.

The new private budgeted coefficient, resident barycentric and host barycentric
symbols carry a typed constructor callback and an 88-byte allocation receipt.
Legacy public C symbols remain available. The actual runtime methods validate
joined completion, sticky admission failures, live-byte exhaustion and successful
command completion before promoting output samples. Failed or malformed
receipts cannot be retried into successful output admission.

## Constructor inventory

Every new numeric native payload and MTLBuffer constructor in
`runtime/polynomial_evaluation.m` passes admission before allocation.

| Route | Persistent device buffers | Native numeric payloads / per-run buffers |
| --- | --- | --- |
| Coefficient | Flat coefficient slab or streamed 4-byte placeholder; factors (4-byte dummy for a constant plan); evaluation tasks; basis tasks; basis values; output values | Counted run task payload; copied coefficient run or ordinary no-copy alias; copied run tasks |
| Barycentric | Optional bounded host staging slab; column offsets; output indices; domain values; numerators; weights; scale; partial reductions; invalid-point flags; output values | Column offsets; bounded resident-run roster; group-run offsets; written-output bitmap |

Existing borrowed PCS resident buffers are not new allocations and are not
charged again. Their existing runtime/tree/source-pointer matching remains in
force. The plan types do not carry authenticated source allocator metadata, so
this batch cannot independently establish the budget owner of an already
borrowed PCS input. The original PCS owners remain responsible for that custody.
In particular, shared-budget coefficient evaluation disables guessed zero-charge
host aliases and makes a charged device copy. Ordinary uncapped callers preserve
their existing aligned no-copy optimization. A future owner-bearing coefficient
plan may admit authenticated aliases without this copy; this batch does not
invent that authority.

## Joined-wave lifetime and bounds

Coefficient streaming groups contiguous columns up to 64 MiB per run. One larger
column is indivisible and is still subject to authoritative budget admission.
Before admitting the next run, the runtime joins the previous wave if its queued
source/task buffers plus the next run's temporary native task payload and device
copy would exceed 256 MiB, or if it already has 128 dispatches. These are scheduling
targets, not replacements for the shared cap. Persistent basis/output buffers
remain charged throughout; an oversized column can exceed the wave target.

Each run uses an inner autorelease pool. Numeric task metadata is destroyed after
being copied into its device task buffer. A completed wave drops command, encoder
and buffer references before reporting joined-byte release. Explicit retained
command/encoder factories prevent the enclosing autorelease pool from holding
completed waves alive. The first wave contains the basis producer; later waves
consume its completed buffer. Shader math, sampled points, task ordering and
transcripts are unchanged.

Host barycentric evaluation reuses its bounded 64 MiB staging slab only after
checked completion of each command that borrows it. Resident barycentric input
buffers remain borrowed through the synchronous epoch. Persistent scratch and
native rosters are released after the common routine's enclosing pool has drained,
including constructor failures, cancellation and active-pole rejection. A
zero-byte budget lease survives until runtime-owned prepared/output heap arrays
are freed by their original allocator.

Accounting covers requested numeric payload and private buffer extents. It does
not enforce whole-process RSS, allocator/framework rounding, Objective-C object
headers, command bookkeeping, stacks or unrelated libraries.

## Qualification entrypoints

`src/metal_sampled_budget_test_root.zig`, filter `sampled budget:`, contains nine
device-free fixtures covering persistent/wave overlap, partial factory rejection,
ordinary aliases versus strict source custody, original-owner release, sticky
failure and cancellation, malformed receipts, exact coefficient branches,
mathematical byte thresholds and the barycentric constructor inventory.

`src/metal_sampled_budget_codegen.zig` retains all four actual coefficient runtime
methods, the barycentric host/resident selector, and their six actual backend
entrypoints. Its exported function retains addresses without calling them. The
parent owns object compilation and full assembled Objective-C syntax checks.
