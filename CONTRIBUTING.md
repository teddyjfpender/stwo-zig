# Contributing

This repository treats engineering taste as an enforceable correctness and performance constraint.
It is a parity-driven cryptographic prover, a high-performance Zig system, and a Metal compute
runtime. A change is not complete merely because it produces the right output once. It must make
ownership, protocol semantics, resource use, synchronization, and performance behavior legible to
the next engineer.

The governing idea is simple:

> Zig gives the programmer control that other toolchains often reserve for the compiler or
> runtime. Exercise that control deliberately, prove the invariants it depends on, and measure the
> machine behavior it creates.

We optimize for:

- exact protocol and cross-backend parity;
- local reasoning and explicit ownership;
- deep, well-compartmentalized modules with narrow interfaces;
- data-oriented layouts and predictable memory traffic;
- SIMD and GPU parallelism that follows a written cost model;
- persistent, streaming execution rather than benchmark-only fast paths;
- deterministic, independently verified evidence;
- progressive disclosure: public intent first, machinery behind it;
- minimal incidental state, configuration, allocation, and synchronization;
- readable code whose performance properties can be explained from source.

Performance and clarity are not opposing goals here. Unclear ownership, hidden copies, diffuse
state, and accidental abstractions are frequent causes of both bugs and poor throughput.

---

## Contents

- [Priority order](#priority-order)
- [Repository architecture](#repository-architecture)
- [What changes we accept](#what-changes-we-accept)
- [Non-negotiables](#non-negotiables)
- [Design before implementation](#design-before-implementation)
- [Module and directory design](#module-and-directory-design)
- [Progressive disclosure and file size](#progressive-disclosure-and-file-size)
- [Zig engineering standard](#zig-engineering-standard)
- [Memory, ownership, and resources](#memory-ownership-and-resources)
- [Comptime, generics, and specialization](#comptime-generics-and-specialization)
- [Cryptographic and numerical correctness](#cryptographic-and-numerical-correctness)
- [SIMD engineering](#simd-engineering)
- [Metal GPU engineering](#metal-gpu-engineering)
- [High-performance computing discipline](#high-performance-computing-discipline)
- [Concurrency and streaming](#concurrency-and-streaming)
- [Testing and parity](#testing-and-parity)
- [Benchmarking and profiling](#benchmarking-and-profiling)
- [Documentation](#documentation)
- [Dependencies and generated code](#dependencies-and-generated-code)
- [Change workflow](#change-workflow)
- [Commit and PR standards](#commit-and-pr-standards)
- [Review standards](#review-standards)
- [Security](#security)
- [Contributor checklist](#contributor-checklist)
- [Taste canon](#taste-canon)

---

## Priority order

When requirements compete, use this order:

1. **Protocol correctness and soundness.** Transcript order, field semantics, statement binding,
   proof shape, and verification behavior are never traded for speed.
2. **Pinned Rust Stwo oracle parity.** For every protocol surface shared with Stwo, the Rust
   implementation pinned in `conformance/upstream.md` is the final correctness oracle.
   Agreement among Zig scalar, SIMD, and Metal implementations cannot overrule a Rust disagreement.
3. **Memory and resource safety.** Ownership, bounds, lifetimes, alignment, queue completion, and
   failure cleanup must be explicit and correct.
4. **Determinism and backend parity.** Equivalent inputs and protocol parameters must preserve the
   committed semantics across Zig scalar/SIMD, Rust references, and Metal.
5. **Sustained end-to-end throughput.** Optimize verified proofs delivered by the production
   pipeline, including queues and repeated heterogeneous workloads.
6. **Latency and footprint.** Minimize warm proof time, cold setup, high-water memory, transfers,
   compilation, and orchestration overhead without hiding any of them.
7. **Elegance and convenience.** API beauty matters, but it cannot conceal costs or weaken the
   stronger requirements above.

An optimization that changes proof semantics is a bug. An optimization that silently falls back
to a different backend is not an optimization result. A fast kernel that slows the verified block
pipeline is not a performance improvement.

---

## Repository architecture

The codebase is divided by responsibility, not by arbitrary file size or implementation language.
The intended dependency direction is:

```text
frontends/{cairo,riscv,sm83}  machine/program semantics, ingestion, AIR, witness
             |
             v
integrations                  explicit frontend/backend composition
             |
             v
prover + backend contracts    protocol orchestration and capability interfaces
             |
             v
core                           fields, transcript, proof types, verifier, protocol laws

concrete backends/{cpu,metal,cuda} implement contracts; core never imports them

interop / tools / scripts     boundary adapters, evidence generation, operational tooling
vectors / reports             immutable parity fixtures and bound benchmark evidence
docs                           architecture, protocols, performance claims, operations
```

### Directory responsibilities

- `src/core/`: backend-independent mathematics, protocol data, transcript logic, and verification.
  It must not depend on a frontend or concrete accelerator.
- `src/backend/`: small capability contracts and backend-neutral operation interfaces. Do not put
  a concrete device policy here.
- `src/prover/`: proof orchestration and backend-generic prover algorithms. It may consume backend
  capabilities but must not smuggle Metal-specific policy into generic APIs.
- `src/backends/cpu_scalar/`: portable scalar reference behavior and CPU-specific implementation.
- `src/backends/metal/`: Metal runtime, memory, pipeline, kernel, and prover integration. Objective-C
  and MSL details stop at this boundary.
- `src/backends/cuda/`: CUDA-specific resources and execution, isolated from Metal and core.
- `src/frontends/`: machine statements, adapters, AIR, witnesses, geometry, and proof-plan logic.
  Frontends must not select a concrete backend or embed application-specific content.
- `src/integrations/`: explicit frontend/backend composition. Integrations select concrete
  backends without duplicating frontend semantics or generic prover orchestration.
- `src/interop/`: versioned external representations and cross-language conversion.
- `src/bench/`: benchmark execution primitives, not production protocol logic.
- `scripts/`: orchestration and report tooling. Scripts must call stable program boundaries rather
  than duplicate proof semantics.
- `tools/`: independently buildable adapters and developer utilities.
- `vectors/`: committed conformance inputs, outputs, and machine-readable evidence.
- `conformance/`: machine-read pins, parity ledger, and the source baseline. Prose design history lives in the sibling `stwo-zig-og-docs` archive.

### Dependency rules

1. `core` may depend only on lower-level utilities and standard shims.
2. Frontends depend on `core` and prover interfaces; `core` never imports a frontend.
3. Concrete backends implement capabilities; generic prover code must not identify a backend by
   name and branch on it.
4. Metal runtime and shader details do not cross into Cairo or core types.
5. Benchmark/report code does not decide proof semantics or enable production behavior.
6. Cross-language formats are versioned at `interop`; raw internal layouts are not public formats.
7. A convenience import must not create a dependency cycle or make a private representation part
   of the effective API.

If a change violates this direction, stop and write a design note. Do not solve the problem with a
re-export, an `anyopaque` escape hatch, a global callback, or a backend-name conditional.

---

## What changes we accept

We welcome changes that:

- improve or complete parity with the pinned Stwo/Cairo behavior;
- make invariants executable through types, validation, and tests;
- reduce allocations, copies, dispatches, synchronization, or memory high-water marks;
- improve verified warm, cold, or sustained proving performance with reproducible evidence;
- deepen module boundaries and reduce the surface a caller must understand;
- replace special-case benchmark paths with general production paths;
- make queues, caches, and persistent sessions bounded and transactional;
- add scalar, SIMD, or independent-oracle tests for optimized code;
- expose profiling that is disabled or negligible in the normal path;
- simplify code while preserving semantics explicitly.

We are skeptical of changes that:

- add a public abstraction before two real callers need it;
- introduce hidden allocation, global state, implicit fallback, or implicit synchronization;
- optimize an isolated kernel without measuring its pipeline contribution;
- use `comptime` to build a private language that is harder to debug than direct Zig;
- add flags to compensate for mixed responsibilities;
- duplicate field, transcript, verifier, or proof-shape logic in a script or backend;
- add dependencies for functionality that Zig or a small local module already provides;
- increase a giant file because splitting it would require naming its responsibilities;
- report throughput from an unverified proof or an incomparable numerator.

---

## Non-negotiables

A change will be blocked when any of the following applies:

1. **No stated contract.** Inputs, outputs, invariants, failure modes, and ownership are unclear.
2. **No parity story.** A protocol or arithmetic change lacks a reference, oracle, or derivation.
3. **No test for changed behavior.** Bug fixes need regression tests; new behavior needs positive,
   boundary, and negative coverage.
4. **Hidden work.** A public operation allocates, copies, compiles, blocks, dispatches, or mutates
   global state without its contract or telemetry making that fact clear.
5. **Silent fallback.** A Metal/CUDA performance lane falls back to CPU or a legacy prover without
   failing closed or reporting the exact path.
6. **Unbounded state.** A cache, queue, arena, report, recursion, generated source, or retry policy
   has no explicit capacity and failure behavior.
7. **Unsafe code by assertion alone.** Pointer casts, alignment, aliasing, FFI lifetimes, or byte
   layouts are not supported by construction and focused tests.
8. **Benchmark without verification.** Every measured proof must pass the named verifier.
9. **Benchmark without provenance.** Workload, protocol, binary/source identity, environment,
   numerator, timing scope, and cold/warm state are missing.
10. **Performance by semantic drift.** Security parameters, trace shape, query count, PoW, folding,
    commitment scheme, or included phases change between compared lanes.
11. **Diffuse configuration.** Environment flags or booleans alter behavior in unrelated modules.
12. **Drive-by churn.** Unrelated formatting, renaming, generated outputs, or refactors obscure the
    behavior under review.
13. **No final Rust-oracle evidence.** A shared Stwo protocol change, optimized backend, or proof
    path lacks conformance against the exact Rust revision pinned in
    `conformance/upstream.md`. Zig-to-Zig agreement, including agreement between scalar, SIMD,
    Metal, and the Zig verifier, is necessary but not sufficient.

---

## Design before implementation

### Start with a written contract

Before non-trivial code, write down:

- the exact input and output types;
- which object owns every allocation and device resource;
- which values are borrowed and for how long;
- mathematical and protocol invariants;
- accepted and rejected states;
- error and cancellation behavior;
- expected data volume and asymptotic work;
- memory high-water estimate;
- CPU threads, GPU dispatches, copies, and synchronization points;
- cold initialization versus reusable state;
- scalar/reference behavior used to prove parity;
- the benchmark that can falsify the performance hypothesis.

Record substantial designs as dated notes in the `stwo-zig-og-docs` archive, or extend an existing normative
architecture document when the concern already has one. The document should be as short as the
problem permits, but long enough to remove ambiguity. Large architecture changes need a dataflow
diagram and an ownership/lifetime diagram.

### State the performance hypothesis

Performance changes require a prediction before implementation. At minimum:

```text
Current bottleneck:
Evidence:
Proposed mechanism:
Expected affected stages:
Expected unchanged stages:
Bytes/operations/dispatches removed:
Memory cost:
Correctness oracle:
Success threshold:
Rollback condition:
```

This prevents post-hoc stories around noisy measurements and keeps optimization work on the
critical path.

### Derive instead of patching

For field arithmetic, transcript state, AIR evaluation, memory geometry, and proof reconstruction:

- derive the representation from the protocol or pinned reference;
- name intermediate invariants;
- make each transformation checkable;
- preserve semantic order even when execution is fused or reordered;
- distinguish logical order from physical storage order explicitly;
- document what is deliberately not guaranteed.

When a transformation is subtle, comment the invariant or proof obligation, not a narration of the
syntax.

### Prefer one source of truth

Protocol constants, trace geometry, component identities, kernel schemas, and report schemas each
need one authoritative definition. Generate or derive secondary forms. If duplication is required
across languages, bind it with a digest, version, parity vector, and test.

---

## Module and directory design

### Deep modules, narrow surfaces

A good module exposes a small, stable contract and hides meaningful implementation complexity. A
wrapper that renames functions, re-exports internals, or passes a large context object unchanged is
not a useful module.

Modules should hide:

- representation and layout;
- allocation and pooling strategy;
- caching and eviction;
- concurrency and command encoding;
- backend-specific handles;
- generated kernel source;
- recovery and cleanup state;
- policy likely to change.

If callers can observe or depend on a detail, it is part of the compatibility burden.

### Organize by responsibility

Prefer nested directories when a subsystem has independent concepts. A mature Metal backend should
trend toward boundaries like:

```text
src/backends/metal/
|-- mod.zig                    public backend surface
|-- backend.zig                capability implementations
|-- runtime/
|   |-- mod.zig                narrow runtime API
|   |-- device.zig             device/queue ownership
|   |-- command.zig            command-buffer lifecycle
|   |-- pipeline_cache.zig     bounded semantic cache
|   `-- telemetry.zig          opt-in measurements
|-- memory/
|   |-- arena.zig              allocations and lifetime classes
|   |-- binding.zig            typed offsets and alignment
|   `-- transfer.zig           explicit shared/private movement
|-- prover/
|   |-- commitments.zig
|   |-- composition.zig
|   |-- oods.zig
|   |-- fri.zig
|   `-- session.zig
|-- codegen/
|   |-- air.zig
|   |-- witness.zig
|   `-- semantic_key.zig
`-- shaders/
    |-- field.metal
    |-- commitments.metal
    |-- composition.metal
    `-- fri.metal
```

This is a direction, not permission for a cosmetic rewrite. Split along ownership, dataflow, and
change boundaries. Each move must preserve build behavior and make the dependency graph simpler.

Apply the same principle to frontend subsystems. Cairo adaptation, geometry, witness construction,
statement binding, proof planning, and resident execution are separate concerns even when one
request traverses all of them.

### Module entry points

`mod.zig` files are maps, not warehouses. They should contain:

- the module's public types and small constructors when appropriate;
- explicit imports/re-exports of the intended surface;
- short module-level invariants;
- no large algorithm merely because every caller imports the module.

Avoid wildcard namespace injection and broad re-export trees. Import the defining module and use a
qualified name when it adds useful context.

The `src/` root may also contain a minimal build entry point when Zig's module-root semantics
require one. `src/std_shims_freestanding.zig` is the deliberate example: it establishes the
freestanding verifier import boundary and must not accumulate reusable implementation code.

### No junk drawers

Do not add `utils.zig`, `helpers.zig`, `common.zig`, or `manager.zig` unless the name describes a
genuinely cohesive domain already recognized by the codebase. Name a module after the invariant it
owns or operation it implements.

---

## Progressive disclosure and file size

Source should reveal intent in this order:

1. module purpose and invariants;
2. public types and contracts;
3. public operations and orchestration;
4. internal dataflow stages;
5. low-level helpers and representation details;
6. focused tests or adjacent mirrored tests.

A reader should not traverse allocator plumbing, FFI declarations, or generated constants before
finding the operation they came to understand.

### Soft size limits

These are review thresholds, not line-count games:

- **Routine leaf module:** target 250-500 lines.
- **Substantial algorithm or stateful resource module:** target 500-650 lines.
- **Cohesive HPC, FFI, or protocol module:** soft ceiling 850 lines.
- **Manually authored file above 850 lines:** requires a written decomposition plan and explicit
  explanation of why splitting now would weaken invariants or reviewability.
- **Generated file:** may exceed 850 lines only when its generator is authoritative, the file is
  marked generated, and reviewers do not hand-edit it.
- **Function:** target 20-60 lines; orchestration may reach roughly 100 when it reads as a linear
  sequence of named stages. Deeply nested functions should be smaller.
- **Shader kernel:** target one visible algorithmic phase. A longer fused kernel must justify the
  fusion boundary with measured traffic/dispatch savings and register/threadgroup-memory data.

### Ratchet rule for existing large files

The repository contains legacy files well above these limits. Do not launch a big-bang split solely
to satisfy a number. Instead:

- do not add a new independent responsibility to an oversized file;
- extract the responsibility touched by a change when a clean ownership boundary exists;
- keep moves separate from behavioral changes when practical;
- require net growth above 850 lines to include a decomposition issue or plan;
- leave the file easier to split than before.

Splitting one giant file into many shallow forwarding files is not progress. A successful split
reduces the number of concepts and internal symbols each reader must load.

### Control-flow depth

- Prefer guard clauses and named stages over pyramids of conditionals.
- Treat more than three nested control blocks as a design warning.
- Keep error cleanup close to acquisition with `defer` and `errdefer`.
- Avoid callbacks that obscure sequencing or ownership.
- Use tables and data transformation when they make policy visible; do not replace a clear switch
  with indirection for its own sake.

---

## Zig engineering standard

### The Zig control contract

Zig does not promise that a sophisticated optimizer will repair a poor layout, infer intended
aliasing, remove an accidental allocation, or turn fragmented orchestration into an ideal SIMD/GPU
pipeline. The author is responsible for:

- data representation and locality;
- allocation frequency and lifetime;
- alignment and aliasing facts;
- integer width and overflow semantics;
- vector width and tail behavior;
- copies and ownership transfer;
- error propagation and cleanup;
- compile-time versus runtime work;
- concurrency granularity;
- device residency and synchronization;
- the build mode used for measurements.

Do not write Rust-shaped Zig with hidden framework policy, object graphs, clone-like copying, and
allocator behavior spread through convenience methods. Use Zig's explicitness to make costs and
lifetimes visible.

### Formatting and naming

- `zig fmt` is canonical. Do not hand-align code against the formatter.
- Files and directories use `snake_case`.
- Types use `TitleCase`.
- Functions use `camelCase` unless matching a stable external ABI.
- Variables and fields use `snake_case`.
- Constants follow the prevailing Zig convention for their role; do not encode type information in
  names.
- Use domain terminology from Stwo, Cairo, FRI, PCS, and Metal consistently.
- Abbreviations are acceptable only when standard in the domain: `fri`, `pcs`, `air`, `oods`,
  `lde`, `simd`, `gpu`, `m31`, `qm31`.

### Mutability and scope

- Use `const` unless the binding itself must change.
- Keep mutable state in the narrowest scope that owns its invariant.
- Prefer constructing a valid value to constructing an invalid value and filling it later.
- Do not reuse a variable for conceptually different phases to save a name.
- Avoid global mutable state. Process-global caches or runtimes need a documented lifecycle,
  synchronization model, capacity, reset/test strategy, and failure semantics.

### Types and invariants

- Use distinct types for values with different units or domains: bytes, elements, rows, log sizes,
  offsets, device addresses, transcript ordinals, and component identifiers.
- Prefer enums and tagged unions over boolean mode combinations.
- Constructors validate external input; internal functions consume validated types.
- Use optionals for absence and error unions for failure. Do not use magic sentinel integers unless
  an external format requires them.
- Make illegal states unrepresentable when the resulting type remains understandable.
- Keep public structs minimal. Private fields are preferred when callers must not construct invalid
  combinations.
- Exhaustively switch on protocol and resource states. An `else` that hides a newly added state is
  usually wrong.

### Errors and assertions

- Return errors for malformed input, unavailable resources, capacity exhaustion, compilation
  failure, device failure, verification failure, and other runtime conditions.
- Use assertions for programmer invariants that cannot be caused by untrusted input.
- Error sets should communicate the boundary's real failure modes without leaking every internal
  error as public API.
- Add context at process/tool boundaries. Low-level hot functions should not format strings or log.
- A production prover fails closed. It never converts an internal GPU failure into a successful CPU
  proof unless the API explicitly requested a fallback policy and the report records it.

### Integer and byte correctness

- Treat every narrowing cast, signedness change, offset addition, multiplication, and byte-length
  calculation as a proof obligation.
- Use checked arithmetic at trust and allocation boundaries.
- State deliberate modular arithmetic explicitly; cryptographic field wrapping is not a generic
  excuse for unchecked host-size arithmetic.
- Keep endian conversion at representation boundaries.
- Never rely on struct padding as a wire or GPU ABI without compile-time size/alignment/offset
  checks.
- Validate that element counts converted to byte counts cannot overflow `usize`, Metal API sizes,
  or shader index widths.

### Imports and API surface

- Import the module, then qualify domain operations where qualification helps the reader.
- Avoid aliases that erase whether an operation is scalar, SIMD, host, device, or verifier-side.
- Every `pub` symbol is a long-term commitment. Default to private.
- Do not export raw pointers, device handles, allocator internals, or cache entries when a smaller
  capability can express the need.
- Avoid getters that merely expose representation. Expose the meaningful operation instead.

### Safety and optimization controls

- Do not scatter `@setRuntimeSafety(false)` through performance code. Isolate it to the smallest
  proven region, retain a safety-enabled test path, and document the bounds/alignment argument.
- `inline` is for enabling a required compile-time specialization or a measured call-boundary win.
  Blanket forced inlining can increase instruction-cache pressure and compile time.
- `noinline` and branch hints require profiler or code-layout evidence. They are not readability
  tools and must not encode an untested workload assumption.
- Prefer an explicit checked boundary feeding a lean internal loop over repeated unchecked casts.
- Use `@memcpy` only for non-overlapping ranges and make overlap policy clear when choosing a move.
- Inspect emitted optimized code for critical scalar/SIMD primitives after changes to types,
  generics, alignment, or build configuration. Source-level similarity is not codegen evidence.
- Never use an optimization builtin to suppress a correctness condition that external input can
  violate.

### Comments

Comments explain:

- a mathematical identity;
- a protocol ordering requirement;
- an ownership or lifetime invariant;
- why a layout/alignment fact is valid;
- why a synchronization point is necessary;
- why a measured fusion or specialization exists;
- why an apparently simpler implementation is incorrect.

Comments do not paraphrase syntax, preserve dead history, or excuse unclear names. Link to a
normative design or issue for reasoning too large to keep beside the code.

---

## Memory, ownership, and resources

Memory behavior is part of the API and performance contract.

### Allocation rules

- Accept an allocator explicitly at the boundary that owns dynamic memory.
- Document whether returned memory is owned, borrowed, arena-backed, mapped, shared, or device-only.
- The module that acquires a resource defines how it is released.
- Use `defer` immediately after acquisition and `errdefer` for partial construction.
- Do not allocate in an inner field, FFT, hash, Merkle, AIR-row, or shader-dispatch loop.
- Reuse scratch storage only when capacity, exclusivity, clearing, and high-water behavior are
  explicit.
- Caches and arenas require byte/entry limits and observable miss/eviction behavior.
- An arena is a lifetime mechanism, not permission to retain everything until process exit.
- Test allocation failure or capacity exhaustion for stateful constructors where practical.

### Ownership vocabulary

Use these terms consistently in APIs and docs:

- **owned:** the receiver must release or transfer the value;
- **borrowed:** the value remains owned elsewhere and cannot outlive that owner;
- **shared:** multiple readers use an immutable or synchronized lifetime;
- **transferred:** exactly one owner changes at a named commit point;
- **resident:** valid device/host backing persists across requests under a bounded cache key;
- **snapshot:** immutable restoration state with a declared consistency point;
- **view:** non-owning typed access into storage whose owner is named.

Shallow copies of owning structs are forbidden unless the type deliberately implements a linear
transfer protocol. A copied slice is not copied backing storage; code and review must distinguish
those facts.

### Alignment and aliasing

- Express required alignment in types, allocation, and assertions at the boundary.
- Every `@alignCast`, `@ptrCast`, `@bitCast`, or `anyopaque` crossing needs a nearby invariant that a
  reviewer can verify.
- Do not create overlapping mutable slices.
- Avoid integer-to-pointer reconstruction when an owning typed binding can preserve provenance.
- Metal buffer offsets must satisfy both host type alignment and kernel/Metal ABI requirements.
- FFI callbacks and no-copy buffers must retain backing storage until the device or foreign caller
  has completed, not merely until command submission.

### Stateful resources

Represent device sessions, command buffers, caches, queue entries, and artifact publication as
state machines. Define:

- legal transitions;
- the single owner of each state;
- cancellation and error transitions;
- when resources become reusable;
- what is invalidated after device or proof failure;
- whether retry is safe and idempotent;
- which telemetry proves cleanup completed.

Publish results transactionally: validate and verify first, then atomically make proof/report state
visible. Failed work must not leave a cache entry or artifact that later appears valid.

---

## Comptime, generics, and specialization

`comptime` is for moving known work out of runtime and expressing real specialization. It is not a
license to build an opaque meta-framework.

### Good uses

- field and extension degree;
- fixed column counts and AIR shapes;
- vector lane counts with scalar-tail support;
- backend capability selection;
- static shader schemas and argument layouts;
- compile-time size/alignment/offset verification;
- unrolling a small measured fixed loop;
- eliminating protocol branches known for an entire binary or kernel.

### Review warnings

- generated code or binaries grow disproportionately;
- compile time becomes a development bottleneck;
- error messages no longer point to understandable source;
- a generic function branches on specific type identities;
- many `anytype` parameters obscure the actual contract;
- specialization duplicates protocol logic across backends;
- runtime data is forced into `comptime` through code generation without a stable semantic key.

Prefer an explicit interface of operations and associated types over reflection on type names. A
generic algorithm must state the laws required from its backend, not just the methods needed to
compile.

Generated Metal kernels require a semantic cache key that binds every value affecting code or ABI.
A cache hit with incomplete identity is a correctness failure.

---

## Cryptographic and numerical correctness

### Rust Stwo is the final correctness oracle

For all behavior within the shared Stwo compatibility scope, the Rust implementation at the exact
commit recorded in `conformance/upstream.md` is authoritative. This is a release and review
gate, not an optional diagnostic.

The oracle hierarchy is:

1. Zig scalar/reference code provides the fastest local differential oracle while developing SIMD,
   Metal, and prover stages.
2. Zig verifier and component/checkpoint tests provide independent local defense and failure
   localization.
3. The pinned Rust Stwo implementation is the final correctness oracle for acceptance.

Consequences:

- If Zig scalar, Zig SIMD, Zig Metal, and the Zig verifier agree but pinned Rust disagrees, the Zig
  change is not correct and must not merge as parity-complete.
- A Rust proof for the same statement/configuration must verify through the Zig interoperability
  boundary, and a Zig proof must verify through the pinned Rust boundary.
- When proof generation is deterministic, require byte-for-byte proof parity. When byte identity is
  not a valid contract, compare canonical transcript checkpoints, commitments, sampled values,
  proof geometry, decommitments, and verifier result, and document why bytes may differ.
- An independently written Zig implementation of Rust behavior is valuable but does not replace the
  Rust oracle.
- Oracle evidence must identify the Rust source revision and the executable/artifact used. Do not
  compare different Rust revisions opportunistically.
- Upgrading the oracle is a controlled compatibility event: update
  `conformance/upstream.md`, regenerate bound vectors, rerun bidirectional interop and tamper
  gates, and document intentional semantic changes.
- A Zig-only protocol extension cannot be called Stwo-parity-complete until a Rust reference,
  verifier adapter, or other Rust-side oracle at the pinned boundary can validate its shared
  semantics. A design note must define the extension and the exact point at which Rust remains
  authoritative.

Performance evidence is accepted only after this oracle gate passes for the measured path. Faster
output that only the Zig prover/verifier pair accepts is not a valid result.

### Protocol invariants

Changes touching proofs must preserve and test, as applicable:

- transcript absorption and challenge order;
- commitment tree order and leaf representation;
- field and extension-field canonicalization;
- circle domain, bit-reversal, and twiddle conventions;
- FRI folding, query, decommitment, and PoW semantics;
- AIR component order, trace-log bounds, and claimed sums;
- statement, program, memory, and public-output binding;
- security parameters and proof configuration;
- proof serialization and independent verifier reconstruction.

Do not infer equivalence from similar output sizes or one accepted proof. Use byte parity where the
protocol is deterministic, otherwise compare canonical semantic checkpoints and verify both forms.

### Arithmetic

- Keep a clear scalar implementation of every optimized field operation.
- Test zero, one, modulus boundaries, maximum limb values, carries, reductions, and non-canonical
  input rejection.
- Document whether an intermediate is canonical, lazy-reduced, Montgomery-like, packed, or raw.
- Do not substitute floating-point arithmetic for exact field/integer work.
- Avoid signed overflow and implementation-dependent shifts. State wrapping intent.
- Batch inversion and similar transformations must define zero behavior explicitly.

### Independent verification

Every production proof path needs an independent verification boundary. For backend work:

1. compare relevant intermediates against the Zig scalar oracle for rapid localization;
2. compare cumulative/component checkpoints when localizing parity;
3. generate the complete proof;
4. verify with the Zig verifier as a local defense;
5. verify across the pinned Rust/Zig boundary, with pinned Rust as the final acceptance oracle;
6. compare deterministic proof bytes or the documented canonical semantic checkpoints;
7. add tamper tests that prove statement and proof fields are actually bound in both boundaries.

A prover accepting its own malformed representation is not evidence. A Zig prover and Zig verifier
agreeing with each other is still not final parity evidence without the pinned Rust oracle.

---

## SIMD engineering

SIMD work starts with layout and a scalar oracle, not intrinsics.

### Required development sequence

1. Write or identify a straightforward scalar implementation.
2. Add fixed-seed differential tests over edge and representative sizes.
3. Write a cost model: operations, bytes loaded/stored, alignment, and expected reuse.
4. Choose structure-of-arrays or array-of-structures based on measured access, not convenience.
5. Implement vector chunks with an explicit, tested tail path.
6. Inspect optimized code or profiles to confirm vector execution.
7. Benchmark the containing proof stage and full proof, not only the loop.
8. Keep the scalar path available as an oracle and portability baseline.

### Layout and vector width

- Prefer structure-of-arrays when lanes perform the same operation on independent field elements.
- Keep hot columns contiguous and iteration order linear where the protocol allows it.
- Separate metadata/control structures from bulk field data.
- Parameterize lane width at `comptime` when it produces a small, bounded set of useful variants.
- Use the target's suggested vector length as input, not as a universal truth; benchmark important
  Apple Silicon and CI targets.
- Do not assume row counts are vector multiples. Test lengths `0`, `1`, `lanes - 1`, `lanes`,
  `lanes + 1`, and several non-power-of-two tails.
- Avoid gather/scatter unless its cost is measured and superior to a layout change.
- Use Zig `@Vector` operations for algorithms that are genuinely lane-parallel. Keep vector types
  inside the optimized implementation boundary rather than leaking a hardware width into protocol
  APIs or persisted layouts.

### Loads, stores, and aliasing

- Prefer naturally aligned contiguous loads and stores.
- Prove alignment before using aligned vector pointers.
- Do not depend on the optimizer discovering non-aliasing that the types do not establish.
- Avoid repeated slice bounds and pointer reconstruction in the hot loop when a validated view can
  be built once outside it.
- Keep conversion between packed/vector and scalar representations at clear boundaries.
- Count temporary writes. A fused arithmetic expression can still spill or create extra passes.
- Check the generated loop for scalarization after introducing shuffles, casts, lane extraction, or
  helper calls. A value having `@Vector` type does not prove the resulting machine loop is good.

### Control flow

- Remove branches from hot vector loops only when the resulting dataflow is clearer or measured
  faster.
- Branchless code is not automatically fast; it may do more work or increase register pressure.
- Split exceptional/rare rows from the common path when semantics permit and the partition cost is
  measured.
- Never let a mask hide an out-of-bounds load. Masked arithmetic does not make an invalid pointer
  valid.

### Arithmetic specialization

- Unroll only small fixed loops where instruction-cache and register effects are understood.
- Track lazy-reduction ranges formally. A vector lane may not exceed the scalar representation's
  valid range between reductions.
- Avoid redundant canonicalization between trusted internal stages.
- Share constants read-only; do not rebuild vector splats inside the inner loop.
- Measure whether an operation is compute-, dependency-, or memory-bound before adding arithmetic
  tricks.

### SIMD acceptance evidence

A SIMD PR includes:

- scalar differential tests;
- supported targets and fallback behavior;
- vector and tail sizes tested;
- before/after stage and proof timings in `ReleaseFast`;
- proof verification and parity status;
- allocation/copy changes;
- optimized-code or profiler evidence that the intended loop vectorized;
- explanation of any target-specific code.

---

## Metal GPU engineering

The Metal backend is a proving service architecture, not a collection of accelerated functions.
The goal is to keep useful proof state resident, encode coarse command graphs, minimize traffic and
CPU intervention, and deliver verified proofs repeatedly.

### Layering

Keep these concerns distinct:

1. **Protocol semantics:** backend-independent inputs, outputs, and order.
2. **Execution plan:** typed stages, dependencies, bindings, and lifetimes.
3. **Resource plan:** buffers, offsets, storage modes, capacity, and reuse.
4. **Pipeline plan:** semantic shader identity, compilation, specialization, and caching.
5. **Command graph:** encoders, dispatches, blits, barriers, events, and completion.
6. **Kernel implementation:** per-thread/group arithmetic and memory access.
7. **Service lifecycle:** cold preparation, resident reuse, queues, recovery, and publication.
8. **Telemetry:** opt-in observations that do not redefine timing or semantics.

Do not let an Objective-C runtime helper decide protocol behavior. Do not let a frontend know which
Metal buffers or pipeline states implement its proof.

### Residency and transfers

- Identify which data is immutable by protocol/geometry, mutable per block, scratch per phase, and
  output per proof.
- Reuse immutable twiddles, fixed tables, compiled pipelines, and geometry only under complete,
  content-bound cache keys.
- Choose shared versus private storage from access and synchronization behavior on Apple unified
  memory, not discrete-GPU folklore.
- A private-buffer copy must pay for itself through reuse, GPU access behavior, or reduced CPU/GPU
  contention.
- Do not blit and wait per column, component, or small phase.
- Batch transfers and keep the producer-consumer chain on GPU when possible.
- No-copy/shared buffers must keep host backing alive through command completion.
- Track resident, used, reserved, and peak bytes. A fast path that risks memory pressure or swap is
  not production-ready.

### Command submission

- Encode the largest coherent command graph that preserves debuggability, resource lifetime, and
  useful overlap.
- Avoid synchronous waits inside proof stages. Wait at true host-observation or reuse boundaries.
- One command buffer per tiny operation is a design failure unless profiles prove otherwise.
- Use explicit dependencies and resource states. Do not rely on incidental submission order across
  queues.
- Check command-buffer completion status and device errors. Failure invalidates affected resources
  before reuse.
- Keep queue count deliberate. More queues can add hazards and contention rather than parallelism.
- Bound in-flight proofs by memory and device capacity.

### Kernel design

- Start from data layout and traffic. State bytes read/written per logical row or element.
- Map adjacent threads to adjacent addresses whenever possible.
- Make grid-stride loops and bounds guards explicit.
- Query or account for thread execution width, maximum threads, and threadgroup memory.
- Select threadgroup size from occupancy, register pressure, memory coalescing, and reduction shape;
  do not cargo-cult 256 threads.
- Use threadgroup memory only when reuse exceeds synchronization and occupancy cost.
- Barriers must be reached uniformly by all participating threads.
- Avoid divergent control in the common path; never move a required barrier into divergent flow.
- Keep field arithmetic unsigned and exact, with reduction ranges shared with the scalar oracle.
- Treat register spilling as global memory traffic. Inspect profiler/compiler data for large fused
  kernels.
- Specialization constants and generated kernels require bounded variant counts.
- Match MSL scalar widths and signedness to compile-time-checked host ABI types. Do not assume that
  `long`, `size_t`, or enum layout is interchangeable across the boundary.
- Use explicit MSL address spaces (`device`, `constant`, `threadgroup`, `thread`) and preserve their
  lifetime/aliasing meaning in generated source.
- Keep atomics rare and state their ordering/visibility requirement. Global atomics are not a
  substitute for partitioning output ownership.
- Fast-math options must not affect exact protocol arithmetic. Any floating-point support code must
  document why relaxed operations cannot alter a proof-relevant result.

### Hazards and synchronization

- Use Metal's tracked hazard behavior by default. Untracked resources require an explicit fence or
  event plan, a documented ownership transition, and focused stress tests.
- Distinguish encoder barriers, command-buffer ordering, shared-event dependencies, and CPU waits;
  they have different costs and guarantees.
- Do not use a CPU readback to establish GPU ordering when a GPU-side dependency suffices.
- Do not reuse, clear, remap, or free a buffer until every command that can access it has completed.
- Argument buffers are appropriate when they reduce real binding/encoding overhead and their ABI is
  generated and checked. They are not required merely because a kernel has many conceptual inputs.
- Pipeline lookup and binding validation belong in preparation or coarse stage setup, not inside a
  per-component dispatch loop.

### Fusion policy

Fusion is valuable when it removes materialized intermediates, dispatch overhead, or round trips.
It is harmful when it:

- creates excessive live state and register spills;
- reduces occupancy enough to offset traffic savings;
- combines stages with incompatible grids or reuse;
- expands compilation latency or cache cardinality without bound;
- makes parity localization impossible;
- serializes work that could overlap;
- turns one reusable kernel into many near-duplicate variants.

Every non-trivial fusion needs:

- before/after dispatch count;
- bytes of intermediate traffic removed;
- pipeline compile/cache impact;
- register/threadgroup-memory and occupancy evidence when available;
- kernel and full-proof measurements;
- unchanged scalar/component parity checkpoints.

Fuse semantic phases only after the command graph and memory plan expose a real boundary worth
removing. Kernel fusion is not a substitute for architectural residency.

### Pipeline compilation and caching

- Production paths must not repeatedly compile invariant shader source.
- Prefer ahead-of-time metallibs or persistent binary archives when the environment supports them.
- When runtime JIT is required, separate compilation from warm proving metrics and cache by a
  complete semantic digest.
- Pipeline cache entries are bounded and observable.
- Failed compilation never publishes a cache hit or silently selects a different kernel.
- Cache keys bind source/template version, constants, field/protocol shape, argument ABI, device
  compatibility, and any feature that changes generated behavior.
- Benchmark reports distinguish source-JIT, cached-JIT, binary-archive, and AOT paths.

### Objective-C and FFI boundary

- Keep Objective-C ownership and autorelease behavior inside the runtime boundary.
- Check every returned Metal object/error needed for correctness.
- Translate foreign failures into a small Zig error contract with diagnostics at the CLI/service
  boundary.
- Do not expose Objective-C objects or raw Metal handles to protocol modules.
- Use compile-time and runtime checks for shared struct sizes, alignments, field offsets, and buffer
  ranges.
- Completion handlers must not capture stack or arena storage that can expire first.
- Avoid exception-dependent control flow across the FFI boundary.

### Metal parity and acceptance

Every new GPU stage requires:

- a scalar or SIMD oracle;
- tiny, boundary, and realistic geometry cases;
- exact comparison in logical order, independent of physical layout;
- cumulative/component checkpoint comparison when used in AIR evaluation;
- a complete proof accepted by the canonical verifier;
- a failure test proving the production Metal lane does not silently fall back;
- cold and warm timing separation;
- resource high-water and dispatch/synchronization evidence.

---

## High-performance computing discipline

### Write a cost model

Before changing hot code, estimate:

- logical work units: cycles, rows, columns, constraints, hashes, or field operations;
- arithmetic operations and dependency chains;
- bytes read, written, copied, and materialized;
- expected cache or device reuse;
- allocations and frees;
- CPU tasks and synchronization points;
- GPU dispatches, encoders, command buffers, and waits;
- compile/setup work and how often it is amortized;
- peak and steady-state memory.

The estimate may be rough, but it must predict which resource limits performance. Use roofline-style
reasoning: a memory-bound stage will not be fixed by more arithmetic parallelism, and a launch-bound
stage will not be fixed by tuning one instruction.

### Optimize in this order

Usually prefer:

1. remove unnecessary work or change the algorithm;
2. avoid materialization and copies;
3. improve data layout and locality;
4. move invariant work to preparation/resident state;
5. batch and reduce synchronization/dispatch;
6. expose coarse parallelism;
7. vectorize or map to GPU;
8. specialize and fuse measured hot paths;
9. tune instructions last.

This order is not dogma, but departures need evidence.

### Hot-path rules

- No logging, formatting, filesystem access, environment lookup, dynamic dispatch, or allocation in
  a measured inner path.
- Parse configuration once at the boundary and pass typed policy inward.
- Precompute invariant constants and validate them once.
- Avoid redundant conversions between logical, packed, SIMD, and device representations.
- Keep phase boundaries visible enough to profile.
- Prefer bounded workspaces and stable addresses for repeated proofs.
- Do not trade an unbounded memory increase for a benchmark win.

### Build modes

- Use Debug and ReleaseSafe to expose correctness problems.
- Use `ReleaseFast` for authoritative performance comparisons.
- Never headline Debug timings.
- Record target CPU/device and relevant build options.
- Native tuning results must be labeled and compared against a portable baseline.
- Do not depend on assertions that disappear in the measured build for validation of untrusted
  inputs or resource bounds.

---

## Concurrency and streaming

The production unit is a queue of blocks/proofs, not an isolated function call.

### Concurrency rules

- Define the owner of every mutable object and which thread/queue may access it.
- Prefer partitioned ownership and message/dataflow boundaries over fine-grained shared mutation.
- Do not combine CPU thread pools and GPU queues without an oversubscription model.
- Bound worker counts and in-flight work.
- Avoid locks in field/hash inner loops; restructure ownership first.
- Document ordering, cancellation, shutdown, and failure propagation.
- Use deterministic scheduling for tests where output/order matters.
- Never hold a lock while waiting for a GPU command buffer or external process.

### Streaming prover requirements

A persistent prover must:

- accept typed block/PIE inputs through one production interface;
- execute/adapt, prove, verify, and publish without benchmark-only preconditions;
- reuse only state whose complete geometry/protocol/content identity matches;
- separate cold preparation, warm proof, verification, and service wall time;
- enforce queue and memory backpressure;
- recover cleanly from malformed input, compile failure, GPU failure, and verification failure;
- prevent failed requests from contaminating later cache/session state;
- support heterogeneous repeated inputs, not only one geometry in a loop;
- report sustained verified throughput over declared queue sequences.

Tests should include random fixed-seed sequences over representative SN PIEs, repeated geometries,
cold misses, warm hits, eviction, failure injection, and orderly shutdown.

---

## Testing and parity

### Test layers

Use the narrowest test that proves the invariant, then add integration evidence appropriate to the
blast radius:

1. **Unit tests:** arithmetic, layouts, state transitions, cache keys, parsers, and failure paths.
2. **Property/table tests:** algebraic laws, round trips, boundary lengths, deterministic random
   cases with fixed seeds.
3. **Differential tests:** scalar versus SIMD, host versus Metal, Zig versus pinned Rust.
4. **Component parity:** cumulative accumulators/checkpoints after each AIR component or proof stage.
5. **Protocol tests:** transcript, commitments, FRI, decommitment, proof shape, and tamper rejection.
6. **Integration tests:** complete frontend execution/adaptation through verified proof.
7. **Streaming tests:** repeated heterogeneous blocks, cache lifecycle, backpressure, and recovery.
8. **Performance tests:** only after correctness gates pass; every measured proof verifies.

### Test quality

- Tests are deterministic and independent of network services unless explicitly integration-only.
- Randomized tests use fixed seeds and print the seed on failure.
- Avoid sleeps as synchronization. Wait on an event/state with a timeout.
- Do not weaken assertions to accommodate nondeterminism introduced by a change.
- Test the failure before the fix when adding a regression.
- Negative tests must demonstrate that a corrupted statement/proof/resource identity is rejected for
  the intended reason.
- Hardware tests state requirements and skip visibly when unavailable; they do not silently pass by
  using another backend.
- Large tests are bounded and labeled so local development remains practical.

### Useful repository gates

Run the gates relevant to the change. The baseline is:

```bash
zig build fmt
zig build upstream-pins
zig build source-conformance
zig build test
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

For protocol/parity work:

```bash
zig build api-parity
zig build upstream-surface
zig build vectors
zig build interop
zig build prove-checkpoints
```

For any shared core/prover change or RISC-V frontend change, run the blocking
production proof smoke:

```bash
zig build test-riscv-cpu-product stwo-zig-riscv-cpu -Doptimize=ReleaseFast -j2
python3 scripts/riscv_pr_proof_smoke.py \
  --cli zig-out/bin/stwo-zig-riscv-cpu \
  --artifact-dir zig-out/riscv-pr-proof-smoke \
  --report-out zig-out/riscv-pr-proof-smoke.json
python3 scripts/riscv_trace_vectors.py
```

This gate must produce and independently verify the branch, memory,
cross-shard, and crypto proof corpus defined in
[`conformance/riscv-pr-proof-gate.md`](conformance/riscv-pr-proof-gate.md).
Unit tests and compilation do not waive it. Live comparison against the exact
pinned Sail and Spike executables, plus the applicable architectural-test
execute → prove → independent-verify audit, remains mandatory in the exhaustive
release gate. Changes that can alter what the committed Sail attestation means
additionally trigger the blocking hosted live differential defined in
[`conformance/riscv-sail-differential-gate.md`](conformance/riscv-sail-differential-gate.md);
run it locally with `python3 scripts/riscv_sail_gate.py run`.

For Metal work on a supported Mac:

```bash
zig build metal-test -Doptimize=ReleaseFast
```

For the final official Cairo correctness oracle:

```bash
cargo test --manifest-path tools/stwo-cairo-official-verifier-rs/Cargo.toml
```

`tools/stwo-cairo-verifier-rs` remains a legacy SN2 envelope adapter. Its
acceptance is not official Stwo-Cairo acceptance and cannot release a Cairo
product.

Release signoff uses the repository's documented release gates. Do not run expensive or thermal
stress workloads casually on a shared development machine; choose a bounded smoke first and keep
Metal jobs serial.

---

## Benchmarking and profiling

### A benchmark is an experiment

Every performance claim records:

- exact workload and input identity/hash;
- protocol/security configuration;
- logical numerator and its semantics;
- backend and whether it is pure or hybrid;
- source revision and executable hash;
- build mode and target tuning;
- host CPU, memory, OS, GPU, and relevant toolchain;
- thread-pool and GPU concurrency policy;
- warmups, samples, ordering, cooldown, and aggregation;
- included and excluded phases;
- cold setup, warm proof, verification, end-to-end, and sustained queue timing as applicable;
- proof size, verification result, and parity result;
- memory high-water and known limitations.

Do not compare Cairo VM-cycle MHz, RISC-V cycle MHz, raw trace-row MHz, constraints per second, and
Fib iterations per second as though they were the same unit.

### Measurement rules

- Use `ReleaseFast` for headline throughput.
- Measure backends sequentially when they contend for the same Apple Silicon CPU/memory/GPU system.
- Begin with the smallest workload that reproduces the hot path.
- Separate first-use compilation/cache construction from resident work.
- Use enough samples for the noise level; label one-shot diagnostics as such.
- Report median and range/quantiles, not only the best run.
- Reverse or randomize lane order to reduce systematic thermal/order bias.
- Record thermal pressure or abort when the host is in an invalid state.
- Do not leave large profiler captures or generated binaries in the repository.
- Store committed reports only when their schema, provenance, verifier evidence, and interpretation
  are stable.

### Profiling rules

- Profile the full proof/service before choosing a kernel.
- Attribute time to non-overlapping stages when possible.
- Use Metal System Trace, GPU counters, command-buffer timing, CPU sampling, allocation telemetry,
  and code inspection according to the hypothesis.
- Instrumentation must be opt-in and its overhead measured.
- Encoder counters and detailed traces are for bounded targeted runs, not headline throughput.
- Profiles guide a hypothesis; they are not proof that an unmeasured rewrite helps.
- After optimization, re-profile to confirm the expected stage changed and no other stage regressed.

### Acceptance template

```text
Correctness:
  verifier:
  proof parity/checkpoints:
  negative tests:

Environment:
  source/executable:
  host/device/toolchain:
  build/protocol:

Measurement:
  workload/numerator:
  cold/warm/sustained scope:
  warmups/samples/order:

Result:
  before:
  after:
  memory/dispatch/copy delta:
  confidence/limitations:
```

---

## Documentation

Documentation is part of correctness when it defines a protocol, cache identity, lifetime, benchmark
scope, or operational procedure.

Update documentation when a change affects:

- public or cross-module APIs;
- proof/protocol behavior;
- directory or ownership boundaries;
- cache keys, persistent state, or recovery;
- benchmark interpretation;
- build/runtime requirements;
- security assumptions;
- current architecture or handover state.

### Documentation standard

- Put normative behavior before historical narrative.
- State what is implemented, planned, diagnostic, superseded, or production-ready.
- Use exact units and define numerators.
- Link evidence and bind it with hashes when it supports a claim.
- Keep commands runnable and paths repository-relative unless an external artifact is intentionally
  machine-local.
- Use diagrams for ownership and dataflow when prose becomes ambiguous.
- Do not preserve obsolete benchmark headlines without a visible superseded label.
- Comments and docs must not promise stronger soundness, portability, or security than tests prove.

---

## Dependencies and generated code

### Dependencies

This repository deliberately has a small Zig dependency surface. A new dependency requires:

- the capability it supplies;
- why a local or standard-library solution is inadequate;
- license and maintenance assessment;
- build, target, and cross-compilation impact;
- allocation, threading, and initialization behavior;
- security/update policy;
- benchmark impact when it enters a hot path;
- a removal boundary so it does not leak through public APIs.

For core cryptographic or GPU execution logic, prefer small auditable implementations and pinned
references over large frameworks.

### Generated code and artifacts

- The generator, schema, and inputs are authoritative; generated output is not hand-edited.
- Generated files carry a header naming the generator and regeneration command.
- Generation is deterministic and tested in CI where practical.
- Semantic digests bind generated shader/AIR content used by caches or reports.
- Do not commit build directories, profiler captures, temporary proof output, Python bytecode, or
  machine-specific caches.
- Commit benchmark evidence only when it is intentionally curated and small enough to review.
- Large binary fixtures need a documented reason, hash, provenance, and retention policy.
- Do not delete working Rust, Lean, CUDA, or generated authority code merely to
  reduce repository size. Follow the immutable replacement and clean-room
  gates in `conformance/repository-production-scope.md`.
- Published Zig package closures must pass `zig build package-dist`; they may
  not acquire autoresearch, Rust, Lean, vector, or deferred CUDA inputs.

---

## Change workflow

Configure an attributable Git author before committing. The repository does not
rewrite existing history, but PR validation rejects new commits authored with
the fixture identity `Test <test@example.*>`. A GitHub noreply address keeps a
personal email private while preserving attribution:

```sh
git config --local user.name "Your Name"
git config --local user.email "<id>+<login>@users.noreply.github.com"
```

Use the repository entrypoints rather than reconstructing CI commands locally:

```sh
python3 scripts/install_hooks.py  # once per checkout
python3 scripts/dev_test.py       # narrowest package-owned tests for worktree changes
python3 scripts/dev_test.py --check path/to/file.zig  # incremental type-check, no codegen
python3 scripts/dev_test.py --watch path/to/file.zig  # persistent edit/save diagnostics
python3 scripts/ci.py --fast      # static validate-or-reject in seconds; no compilation
python3 scripts/ci.py             # same standard gate as hosted CI
python3 scripts/ci.py --strict    # release evidence gate
```

`dev_test.py` derives package ownership and broad fallbacks from each
`package.contract.json`. For field, crypto, FRI/PCS, prover AIR/poly/PCS,
RISC-V ISA/runner/AIR-semantics, and SM83 ISA/runner edits it selects smaller
Debug-mode test roots instead. Debug avoids LLVM optimization during the edit
loop; the standard gate remains the optimized authority. Pass paths explicitly
to preview a planned edit, or use `--dry-run` to inspect the commands. An
unowned path fails closed; the script never reports green for a change it
cannot route. Broad package fallbacks retain their declared ReleaseSafe command.

`--check` follows Zig's recommended incremental, no-binary path and skips test
execution; use it for compile errors while editing, then run the normal focused
test before committing. `--watch` keeps one focused package's compiler process
alive and rebuilds on each save. Unfocused package fallbacks still run their
complete declared test command rather than pretending to be check-only.

Run `--fast` first and often: it rejects formatting, pin drift, and source-conformance
breakage in seconds without a single `zig build`. That
compilation-free property is enforced by test, not convention — a compile-class
command entering the fast plan fails `scripts/tests/test_ci.py`. Only after fast
passes is the standard gate, including the complete script-contract suite, worth
its minutes.

For the RISC-V lane, `scripts/riscv_formal_tools.py`,
`scripts/riscv_trace_vectors.py`, and `scripts/riscv_arch_tests.py` own formal
correctness evidence. They fail closed on the exact Sail compiler/model, Spike,
and architectural-test revisions.
`autoresearch/benchmarks/riscv_stark_v_benchmark.py` remains
only a legacy performance/layout comparison; it is not an ISA correctness
authority or release substitute.

Both RISC-V harnesses embed a `host_environment` block (chip, cores, memory, OS,
toolchain) so every report says what machine produced it, and their committed
baselines live under `vectors/reports/riscv_baselines/` (the per-run
`vectors/reports/*.json` outputs are gitignored). Those baselines are the
reference the autoresearch harness measures against; see that directory's
README for the anchor-freeze linkage. The native board's tracked history is
`vectors/reports/benchmark_history/`.

`autoresearch/benchmarks/build_crypto_guests.py` vendors the compiled cryptographic guests
(SHA-256, Keccak, ECDSA from Stark-V's guest-lib as source provenance, plus the repo-owned
`vectors/riscv_guests/poseidon2_m31` guest) into `vectors/riscv_elfs/crypto/`
with a provenance record, and
`autoresearch/benchmarks/riscv_crypto_benchmark.py` benches them
on both lanes. Rows are either `proof` (SHA-256 all sizes, single-block Keccak)
or `execution` (ECDSA, Poseidon2-M31, multi-block Keccak — neither lane proves
these at the pinned config, so both only execute them). The legacy matched
benchmark matrix remains CPU-only. The separate `stwo-zig-riscv-metal` product
owns RISC-V Metal conformance and must fail instead of entering a CPU fallback.

Membership in `scripts/` is also enforced by test: every script must be
transitively reachable from a live entry point (build graph, hosted workflow,
conformance policy, hooks, docs) or declared with a purpose in
`scripts/tests/test_script_reachability.py`. A script nothing reaches fails the
suite — wire it into a gate, declare it, or delete it; history keeps deletions
cheap to reverse.

The pre-commit hook is intentionally limited to staged-diff hygiene, formatting, and source
conformance. The pre-push hook uses the generated product catalog and
`conformance/ci-touchpoints-v1.json` to run only gates owned by the exact commits being pushed.
It reuses product-scoped caches and writes timing receipts under `zig-out/ci/pre-push/`. A host
that cannot execute a selected Metal or Full-Xcode lane reports it as deferred to authoritative
hosted CI. Pull requests and pushes to `main` use the same fail-closed affected-product closure;
unknown paths still select every lane. The complete Python script-contract suite runs when scripts,
their workflows, or soundness contracts change. A nightly full hosted matrix catches selector drift
without putting unrelated products on every merge's critical path.
Neither hook runs hardware benchmarks, profiles, or large SN PIE workloads.
The RISC-V focused lane is a correctness workload exception: whenever selected,
it runs the bounded four-program production proof gate and retains independent
verifier receipts. It is neither a benchmark nor optional release evidence.

Git permits an emergency local bypass with `--no-verify`. That bypass skips feedback only; it does
not waive any repository requirement. Disclose its use in the PR, run the relevant focused gate
before requesting review, and record any gate that remains unavailable. Run `python3 scripts/ci.py`
for an explicit full release rehearsal. Hosted CI is authoritative and must not contain a
corresponding bypass path.

1. **Identify the contract.** Name the bug, feature, parity gap, architectural debt, or measured
   bottleneck.
2. **Inspect the existing path.** Trace real call sites, ownership, protocol order, and reports.
3. **Write the design/hypothesis.** Do this before a cross-layer or performance-heavy change.
4. **Build the oracle.** Add scalar, Rust, component, or verifier evidence first.
5. **Implement the smallest coherent slice.** Keep intermediate states valid and testable.
6. **Run focused correctness tests.** Include failures and boundary sizes.
7. **Measure only after parity.** Use a bounded run before large SN PIE or queue tests.
8. **Profile the new whole path.** Confirm the intended mechanism caused the result.
9. **Update architecture and evidence.** Distinguish diagnostic from authoritative results.
10. **Run relevant repository gates.** Record anything unavailable and why.
11. **Review the diff for complexity.** Remove flags, exports, indirection, duplication, and stale
    comments introduced during exploration.

For a large change, prefer a sequence such as:

```text
contract/types -> scalar/reference tests -> resource/dataflow boundary -> optimized backend
-> integration/parity -> benchmark evidence -> cleanup
```

Do not merge a temporary correctness bypass with a promise to repair it later.

---

## Commit and PR standards

### Commits

- Use imperative mood: `Add`, `Fix`, `Refactor`, `Remove`, `Document`.
- Keep one reviewable concept per commit when possible.
- Separate pure moves/formatting from behavior.
- Do not commit broken intermediate states to a shared branch.
- Do not include caches, local artifacts, unrelated changes, or secret material.

### PR size

Small PRs are preferred, but cryptographic/GPU slices sometimes cross layers. Optimize for coherent
review rather than an arbitrary diff count.

- Aim for at most roughly 400 changed lines and 10 files for routine work.
- Larger PRs need a review map and a reason they cannot be split without hiding an invariant.
- More than 1,000 substantive changed lines should normally be a stack or series.
- Generated files and bound vectors are counted separately but must be identified.
- A performance PR should not combine unrelated optimizations; attribution matters.

### PR description

Include:

- **Contract:** behavior, invariants, and failure modes.
- **Why:** bug, parity gap, architecture need, or profiler evidence.
- **Design:** module/ownership/dataflow changes.
- **Correctness:** oracle, parity, verifier, and negative tests.
- **Performance:** hypothesis, before/after, scope, memory, and limitations.
- **Review map:** recommended file/order and risky lines.
- **Tests:** commands and results, including unavailable gates.
- **Operational impact:** cache/version migration, flags, artifacts, and rollback.

### Required disclosure

Call out explicitly:

- new `pub` APIs;
- new allocation or retained memory;
- new global/process state;
- new threads, queues, locks, atomics, or waits;
- new Metal buffer/storage modes or shader variants;
- new `@ptrCast`, `@alignCast`, `anyopaque`, or FFI lifetime;
- changed protocol/security parameters;
- fallback behavior;
- files exceeding the soft size ceiling;
- benchmark methodology changes.

---

## Review standards

Review asks both "does it work?" and "does it belong?"

### Correctness review

- Can the protocol transformation be derived from the specification/reference?
- Are transcript and proof orders unchanged or deliberately versioned?
- Are bounds, overflows, alignment, and lifetimes established before unsafe operations?
- Does failure leave resources and persistent state valid?
- Do independent tests reject tampering and semantic drift?

### Architecture review

- Does each responsibility have one owner?
- Is the dependency direction preserved?
- Is the interface smaller than the implementation complexity it hides?
- Did policy leak into a frontend, backend contract, or script?
- Could fewer flags/types/modules express the same design?
- Does an oversized file improve under the ratchet rule?

### Performance review

- Is the bottleneck measured in the complete pipeline?
- Does the cost model predict the observed result?
- Are allocation, memory, copy, dispatch, wait, and compilation effects included?
- Is the comparison protocol- and workload-equivalent?
- Is the optimized path the production path?
- Did proof verification occur inside the accepted experiment?
- Is the result warm, cold, sustained, or an isolated kernel metric, and is it labeled correctly?

### Readability review

- Can a reviewer identify the contract and ownership before reading helpers?
- Do names expose units, domains, and host/device representation?
- Are comments about why and invariants?
- Is control flow linear enough to audit cleanup and protocol order?
- Is cleverness justified by measured benefit?

A request for simplification is part of correctness work, not optional polish.

---

## Security

This code processes untrusted program/block inputs and produces cryptographic proofs. Treat parsers,
sizes, offsets, proof reconstruction, generated kernels, FFI, caches, and artifact paths as security
boundaries.

- Validate before allocation and before pointer/device use.
- Bound input-driven memory, generated source, queue depth, retries, logs, and output size.
- Use private, permission-restricted temporary directories for verifier/interchange artifacts.
- Publish artifacts atomically and refuse unsafe replacement.
- Bind cached/prepared state to complete content and protocol identity.
- Do not log private witness values, secrets, raw memory, or sensitive paths.
- Avoid secret-dependent branches or memory access in reusable cryptographic primitives unless the
  threat model explicitly permits them and documentation says so.
- Do not claim zeroization unless the compiler/runtime/device behavior is actually established.
- Treat Metal shader source and binary archives as executable code with provenance requirements.
- Do not open a public issue for a suspected vulnerability. Follow
  `SECURITY.md` and use GitHub private vulnerability reporting.

---

## Contributor checklist

### Design

- [ ] The change has one stated purpose and a written contract.
- [ ] Ownership, lifetimes, failure modes, and resource bounds are explicit.
- [ ] Dependency direction and information hiding are preserved.
- [ ] New public APIs are minimal and document their laws.
- [ ] Oversized files follow the ratchet rule or include a decomposition plan.

### Correctness

- [ ] Scalar/reference behavior exists for optimized arithmetic or kernels.
- [ ] Boundary, failure, and fixed-seed differential tests are included.
- [ ] Protocol/security parameters are unchanged or deliberately versioned.
- [ ] The exact Rust Stwo revision and oracle artifact match `conformance/upstream.md`.
- [ ] Rust proofs verify in Zig and Zig proofs verify through the pinned Rust boundary.
- [ ] Deterministic proof bytes match Rust, or documented canonical semantic checkpoints explain and
      validate any permitted byte difference.
- [ ] Complete proofs pass the Zig verifier as defense in depth and pinned Rust as the final oracle.
- [ ] Tamper tests demonstrate statement/proof binding where relevant.

### Zig and memory

- [ ] Allocation is explicit and absent from hot inner loops.
- [ ] Every owned resource has visible cleanup on success and error.
- [ ] Casts, alignment, aliasing, byte sizes, and overflow are justified.
- [ ] Mutable/global state is minimized, bounded, and synchronized.
- [ ] Debug/ReleaseSafe validation does not disappear unsafely in ReleaseFast.

### SIMD

- [ ] Layout, vector width, alignment, and tail behavior are documented.
- [ ] Scalar versus SIMD differential tests pass.
- [ ] Optimized-code/profile evidence confirms the intended vector path.
- [ ] Full-stage and full-proof performance are reported, not only a microbenchmark.

### Metal

- [ ] Residency, buffers, storage modes, and lifetimes are explicit.
- [ ] Dispatch, transfer, command-buffer, and wait counts are measured.
- [ ] Shader semantic identity and pipeline caching are complete and bounded.
- [ ] No silent CPU/legacy fallback is possible in the measured lane.
- [ ] GPU failure invalidates resources safely and is tested.
- [ ] Kernel and end-to-end proof parity pass.

### Performance evidence

- [ ] A pre-change hypothesis and cost model exist.
- [ ] Comparisons use the same workload and protocol.
- [ ] Cold, warm, end-to-end, and sustained scopes are labeled correctly.
- [ ] Source/binary, host/device, build, thread, and sample provenance are recorded.
- [ ] Memory high-water and limitations are reported.
- [ ] Every measured proof verifies.

### Delivery

- [ ] `zig fmt` and relevant Zig tests pass.
- [ ] Python/Rust/tool tests relevant to the change pass.
- [ ] Docs, designs, and benchmark interpretation are current.
- [ ] The diff contains no cache, profiler, build, secret, or unrelated artifacts.
- [ ] The PR explains unavailable gates and residual risks.

---

## Taste canon

The contribution bar is shaped by a specific engineering tradition. Reading every source is not a
prerequisite, but changes should respect the constraints they imply.

### Zig and systems taste

- The Zig language reference and standard library: explicit allocation, error unions, optionals,
  compile-time specialization, and readable low-level control.
- Andrew Kelley's writing and talks on simple systems, data-oriented design, and avoiding hidden
  control flow.
- TigerBeetle's engineering discipline: assertions, static/resource bounds, deterministic tests,
  explicit state machines, and operational correctness.
- Casey Muratori's data-oriented and performance-aware programming work: understand generated work,
  memory movement, and machine behavior rather than relying on abstraction folklore.

### Module and API design

- David Parnas: information hiding and decomposition by likely change.
- John Ousterhout: deep modules and complexity as the central software cost.
- Butler Lampson: interface economy, naming, and systems design judgment.
- Kernighan and Pike: simple interfaces, direct code, and tool-assisted clarity.
- Moseley and Marks: state and control as primary sources of incidental complexity.

### Correctness and derivation

- Tony Hoare and Leslie Lamport: invariants, state transitions, and precise concurrent reasoning.
- Richard Bird and the functional pearl tradition: derive small compositional programs from laws.
- Philip Wadler and John Hughes: parametricity and composition as constraints on accidental
  behavior.

### Performance engineering

- Hennessy and Patterson: measure the hierarchy and reason from architecture.
- The Roofline model: relate arithmetic intensity to compute and bandwidth ceilings.
- Agner Fog and vendor optimization manuals: inspect real instruction and microarchitectural
  behavior, while treating target-specific advice as target-specific.
- Apple Metal documentation and profiling guidance: command submission, resource storage, pipeline
  compilation, occupancy, counters, and unified-memory behavior.

### Cryptographic implementation taste

- Exact arithmetic and explicit representations over clever shortcuts.
- Differential and independent verification over self-consistency.
- Fail-closed behavior over availability theater.
- Bound, reproducible evidence over benchmark anecdotes.

The resulting aesthetic is not minimal code at any cost. It is code with minimal hidden machinery:
small public surfaces, explicit resources, exact semantics, measured execution, and enough internal
structure that a reviewer can prove both what it computes and why it is fast.
