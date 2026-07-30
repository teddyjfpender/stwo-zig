# Zig build-monorepo delivery goal

**Status:** REPOSITORY COMPLETE; PROTECTED RELEASE ACTIVATION DEFERRED

**RISC-V authority notice (2026-07-26):** The pre-Sail Stark-V oracle,
receipt, bundle, and challenge portions below are historical. They are
superseded by
[`2026-07-26-riscv-sail-contract.md`](2026-07-26-riscv-sail-contract.md) and
cannot authorize a current release.

**Created:** 2026-07-19

**Authority:** This is the operative delivery contract for implementing
the accepted build-monorepo architecture (design narrative archived in `stwo-zig-og-docs/design/`).
The architecture document defines the intended design. This document defines
the work, gates, evidence, and release decision required to claim that design
has been delivered.

**Repository disposition (2026-07-19):** The revised repository-architecture
scope is complete at `68028a77`. Product construction, focused ownership,
correctness-only gates, and fail-closed release plumbing are integrated. The
protected cross-host authority cannot be activated on the current private
repository plan and remains an explicit external TODO governed by
the activation runbook (archived in `stwo-zig-og-docs/design/`).
That operational activation is not part of the revised repository-setup goal.

**Protected release decision:** NO-GO until every mandatory checkpoint in this document
passes on one identified commit from a clean checkout. A focused product
compiling locally, an aggregate test suite passing, or a source tree looking
better organized is useful progress but is not completion evidence.

**Protected release formula:**

```text
GO = BG-00..BG-15 PASS on one clean commit
   + all required Linux and macOS product receipts PASS
   + Native and RISC-V focused/aggregate behavior parity PASS
   + pinned Rust oracle evidence PASS for every changed shared proof boundary
   + zero new source-conformance debt
   + zero implicit backend selection or silent fallback
```

Every term is mandatory. A false, missing, stale, or skipped term makes the
protected release decision NO-GO. It does not reopen the completed repository
architecture scope.

### Scope amendment: performance is a separate goal

As of 2026-07-19, proving-speed parity, build-speed parity, memory-ratio
promotion, benchmark execution, and backend optimization are explicitly
deferred to a later autoresearch goal. They are not release criteria for this
build-monorepo delivery goal.

This amendment does not remove benchmark or profiler ownership from the
architecture. Focused benchmark commands, stable workload identities,
machine-readable schemas, historical ledgers, delta tooling, and profiler
entry points must remain constructible and correctly attributed. The current
release gate validates those interfaces without executing a performance
matrix or accepting a throughput promotion.

Correctness is not performance. Proof verification, pinned Rust-oracle parity,
explicit backend selection, and zero silent fallback remain mandatory. A
Metal-labelled product may be slower during this architecture transition; it
may not claim CPU work as Metal work.

## Goal identity

Deliver stwo-zig as a deliberately composed Zig build monorepo in which core,
generic proving, frontends, concrete backends, integrations, products,
benchmarks, and release gates have explicit owners and mechanically enforced
dependency direction.

The result must provide several independently constructible products from one
protocol implementation. A CPU product must not compile or link Metal merely
because it is built on macOS. A RISC-V product must not compile Native examples
or Cairo. A Metal product must not hide CPU fallback behind a device-labelled
command. The compatibility CLI may compose released products, but it must not
own protocol logic or weaken their capability contracts.

This is an architecture and productionization goal, not a cosmetic directory
rewrite. It is complete only when the narrower graphs are used by real CLI,
benchmark, CI, profiling, and release workflows and their receipts identify
exactly what was built and measured.

## Governing documents

The following documents are normative, in descending order:

1. [CONTRIBUTING.md](../CONTRIBUTING.md), including its Zig performance,
   SIMD, Metal, correctness-oracle, directory, and file-size requirements.
2. [upstream.md](upstream.md), which pins the final Rust correctness oracles.
3. This delivery goal.
4. [the performance baseline epoch 2 amendment](2026-07-19-build-monorepo-baseline-epoch-2-amendment.md),
   retained as the future autoresearch epoch contract but non-operative for
   this architecture release decision.
5. [the RISC-V release goal](2026-07-18-riscv-release-goal.md), for specialized
   RISC-V soundness, statement, artifact, oracle, and registry requirements.
6. the accepted architecture (archived in `stwo-zig-og-docs/design/`).
7. [decomposition-plan.md](decomposition-plan.md) and
   [source-baseline.json](source-baseline.json), which govern existing debt.
8. [divergence-log.md](divergence-log.md), for deliberate protocol differences.

When requirements appear to conflict, the stronger correctness, explicitness,
or fail-closed rule wins. An implementation discovery updates the relevant
document or ledger; it never becomes an oral exception.

## Scope

### Required

This goal includes all of the following:

- the target `build_support/` ownership structure;
- named Zig module construction for core, prover, backend contracts, concrete
  backends, frontends, integrations, and product roots;
- focused Core, Prover, Native CPU, RISC-V CPU, and explicit Metal products;
- a correctly deferred Cairo CPU/Metal product definition that cannot be
  mistaken for a released lane;
- explicit CUDA composition policy even when CUDA is not available in CI;
- a thin root `build.zig` dispatcher;
- an opt-in aggregate `stwo-zig` compatibility product;
- focused CLI, test, benchmark, profiler, and release-gate ownership;
- canonical product and build identity in binaries and machine evidence;
- import, compile, link, visible-capability, and behavioral closure gates;
- final Rust-oracle conformance for affected proof behavior;
- benchmark/profiler ownership, schema, identity, history, and delta-tool
  continuity without executing performance comparisons; and
- migration of operative documentation and source-debt ledgers.

### Deliberately deferred

The following work is not required to complete this architecture goal:

- completing stwo-cairo-zig semantic parity;
- enabling Cairo proving products for release;
- enabling the RISC-V autoresearch board;
- implementing RISC-V Metal proving;
- implementing new CUDA kernels;
- proving-speed, build-speed, binary-size, or peak-memory parity against any
  historical epoch;
- executing or promoting the epoch-two performance matrix;
- repairing or productionizing the deferred epoch-two capture controller;
- changing AIR semantics, proof security parameters, transcript order, proof
  wire format, or verifier policy; and
- optimizing prover kernels.

Deferred does not mean invisible. Each deferred product must exist in the
matrix with an explicit unavailable or experimental state and a tested reason.
No placeholder product may emit release-quality benchmarks or proofs.

## Non-negotiable architecture laws

### Product identity is not an executable name

Each product has one stable logical ID, such as `stwo-riscv-cpu`. Build step
names, installed executable names, and compatibility aliases are separate
fields. For example, the `stwo-riscv-cpu` product may install
`stwo-zig-riscv-cpu` without creating a second product identity.

Receipts, caches, registries, and benchmark histories use the stable logical
ID. Human-facing command names may evolve only through an explicit alias and
deprecation contract.

### One protocol implementation

Core field arithmetic, transcript logic, proof types, verifier logic, PCS,
FRI, and shared prover algorithms remain single sources of truth. Focused
products compose these modules; they do not copy them.

### Explicit dependency direction

The allowed high-level dependency direction is:

```text
core
  ^
backend contracts <- generic prover
  ^                    ^
concrete backend    frontend
       ^                ^
       +------ integration
                    ^
                 product
```

In particular:

- `core` imports no prover, frontend, integration, or concrete backend;
- generic `prover` imports no frontend and no Metal/CUDA runtime policy;
- backend contracts contain no concrete backend or frontend types;
- a concrete backend imports core, backend contracts, and its own backend-private
  implementation/runtime only; any shared prover primitive is a separately
  named, acyclic lower-level module rather than an import of generic prover;
- a frontend contains statement, trace, AIR, and witness policy, but no device
  selection or concrete runtime ownership;
- an integration is the only layer that combines one frontend and one concrete
  backend;
- a focused product imports only the modules named by its manifest; and
- the aggregate facade and CLI sit above focused products and are never imported
  by them.

Relative imports may organize one owner. They may not tunnel around a named
module boundary to reach a sibling owner.

### Explicit capability selection

Frontend, backend, role, target, and optional protocol capabilities are typed
build inputs. Host OS is a compatibility check, not a product selector.

- Metal is enabled only by constructing a Metal product.
- CUDA is enabled only by constructing a CUDA product.
- CPU products never link Metal, Foundation, Objective-C, CUDA, or C++ GPU
  runtimes.
- A Metal or CUDA product fails when its runtime is unavailable.
- No backend-labelled product silently falls back to CPU.
- Unsupported frontend/backend pairs fail during graph construction or CLI
  parsing before proof output is created.

### Deep owners, thin dispatchers

The root build file selects options and invokes graph owners. It does not own
product internals, test sequences, backend linkage, benchmark construction, or
release policy.

`mod.zig` files and facade roots are maps, not warehouses. Product files own
orchestration; reusable protocol logic remains below them.

Product construction must not mutate the global default install step unless
the caller explicitly selected that product. `zig build` is not shorthand for
installing every CLI, diagnostic, benchmark, shader tool, and backend.

### Final Rust authority

Refactoring a build graph must not change proof meaning. Zig focused/aggregate
agreement is necessary but not sufficient. The exact Rust Stwo or Stark-V
revision pinned in [upstream.md](upstream.md) remains the final correctness
oracle for every shared boundary affected by the migration.

## Required repository shape

The target ownership structure is:

```text
build.zig                         thin option and product dispatcher
build_support/
|-- graph/
|   |-- modules.zig              named module construction
|   |-- product.zig              typed frontend/backend/role capabilities
|   |-- identity.zig             canonical build and product identity
|   `-- install.zig              explicit install helpers
|-- products/
|   |-- core.zig
|   |-- prover.zig
|   |-- native_cpu.zig
|   |-- native_metal.zig
|   |-- native_cuda.zig
|   |-- riscv_cpu.zig
|   |-- riscv_metal.zig          explicit unavailable descriptor
|   |-- riscv_cuda.zig           explicit unavailable descriptor
|   |-- cairo_cpu.zig            disabled until its own release goal passes
|   |-- cairo_metal.zig          disabled until its own release goal passes
|   |-- cairo_cuda.zig           disabled until its own release goal passes
|   |-- aggregate_cli.zig
|   `-- interop.zig
|-- backends/
|   |-- metal.zig
|   `-- cuda.zig
|-- gates/
|   |-- architecture.zig
|   |-- native.zig
|   |-- riscv.zig
|   |-- metal.zig
|   `-- release.zig
`-- benchmarks/
    |-- native.zig
    |-- riscv.zig
    `-- metal.zig

src/
|-- core/
|-- backend/                     backend contracts only
|-- backends/                    concrete CPU, Metal, and CUDA owners
|-- prover/                      generic prover implementation
|-- frontends/                   Native, RISC-V, and Cairo owners
|-- integrations/               explicit frontend/backend compositions
|-- products/                    focused product CLI/library shells
|-- interop/
`-- stwo.zig                    opt-in aggregate SDK facade
```

Equivalent names are allowed only when they improve an established local
boundary and are recorded in the goal reconciliation. Collapsing these owners
back into one large build file is not equivalent.

Metal and CUDA product descriptors own frontend/backend composition and release
state. `build_support/backends/metal.zig` and `cuda.zig` own only backend module,
toolchain, linkage, code-generation, and runtime construction. They never select
a frontend. Repetitive disabled descriptors may be generated from the central
matrix, but the generated product IDs and owners remain inspectable gate input.

New product entry points live under `src/products/<product>/`. Do not add
another permanent root Zig entry point to avoid defining a module owner.
Existing root RISC-V tools and `metal_arena_plan_cli.zig` move when their new
owner lands, and their source-baseline entries shrink or disappear. Deferred
Cairo and SN-PIE sources are preserved until their separate work resumes.

### Size and disclosure requirements

- root `build.zig`: target at most 200 lines, review stop at 300;
- graph owner: target at most 350 lines;
- product/backend/gate/benchmark build owner: target at most 500 lines;
- ordinary implementation file: follow the 500-line target and 850-line review
  stop in `CONTRIBUTING.md`;
- long compatibility tables or generated manifests live in data or generated
  files, not control-flow modules; and
- every exception names its reason and next extraction in
  [decomposition-plan.md](decomposition-plan.md).

`build_support/verification_products.zig` is split by gate responsibility even
if it remains just below a numeric ceiling. A 400-line file that owns unrelated
Native, RISC-V, benchmark, and release chains still violates the target
ownership model.

Line counts are review signals, not permission to create shallow wrappers. A
split must improve ownership, information hiding, or change locality.

## Product contract

### Product matrix

| Product | Frontend | Backend | Required state at completion |
| --- | --- | --- | --- |
| `stwo-core` | none | none | buildable/testable library |
| `stwo-prover` | none | contracts | buildable/testable generic prover |
| `stwo-native-cpu` | Native | CPU scalar/SIMD | released, CLI/test/benchmark |
| `stwo-riscv-cpu` | Stark-V RV32IM | CPU scalar/SIMD | staged or released according to its own gate |
| `stwo-cairo-cpu` | Cairo | CPU scalar/SIMD | explicit disabled state with reason |
| `stwo-native-metal` | Native | Metal | explicit opt-in, parity-gated |
| `stwo-cairo-metal` | Cairo | Metal | explicit disabled/experimental state |
| `stwo-riscv-metal` | RISC-V | Metal | explicit experimental unavailable state |
| `stwo-native-cuda` | Native | CUDA | explicit opt-in experimental state |
| `stwo-cairo-cuda` | Cairo | CUDA | explicit disabled/experimental state |
| `stwo-riscv-cuda` | RISC-V | CUDA | explicit experimental unavailable state |
| `stwo-zig` | released selection | explicit selection | compatibility product |

The product matrix is data consumed by build construction, registries, help,
tests, and evidence. These surfaces must not maintain independent lists.

Every product descriptor declares:

- stable product ID and schema;
- frontend set, backend set, and role;
- target support and unavailable-host policy;
- protocol and security features;
- installed artifacts and compatibility aliases;
- focused tests and release gates; and
- benchmark and profiler owners.

### Normative names

Logical product IDs are the permanent evidence and history keys. The following
initial command and artifact names are normative; a rename requires an alias,
deprecation interval, and history migration rather than a second product ID.

| Logical product ID | Build step | Installed executable | Public Zig module |
| --- | --- | --- | --- |
| `stwo-core` | `stwo-core` | none | `stwo_core` |
| `stwo-prover` | `stwo-prover` | none | `stwo_prover` |
| `stwo-native-cpu` | `stwo-native-cpu` | `stwo-zig-native-cpu` | none |
| `stwo-riscv-cpu` | `stwo-zig-riscv-cpu` | `stwo-zig-riscv-cpu` | none |
| `stwo-native-metal` | `stwo-native-metal` | `stwo-zig-native-metal` | none |
| `stwo-zig` | `stwo-zig` | `stwo-zig` | `stwo` |

Disabled and experimental products use their logical IDs from the product
matrix. They do not install an executable until their release state permits it.
`stwo` remains the aggregate downstream compatibility import. `stwo_core` and
`stwo_prover` are the focused public imports added by this migration.

### Stable build surface

At minimum, the completed graph exposes focused equivalents of:

```sh
zig build stwo-core
zig build test-stwo-core
zig build stwo-prover
zig build test-stwo-prover

zig build stwo-native-cpu -Doptimize=ReleaseFast
zig build test-native-cpu-product -Doptimize=ReleaseFast
zig build benchmark-native-cpu -Doptimize=ReleaseFast

zig build stwo-zig-riscv-cpu -Doptimize=ReleaseFast
zig build stwo-zig-riscv-cpu-static
zig build test-riscv-cpu-product -Doptimize=ReleaseFast

zig build stwo-native-metal -Doptimize=ReleaseFast
zig build test-native-metal -Doptimize=ReleaseFast

zig build stwo-zig -Doptimize=ReleaseFast
zig build architecture-gate -Darchitecture-mode=host -Doptimize=ReleaseFast
```

Each required role has one unambiguous owner and the documented command above.
The default install step must not build every product, and a focused step must
not acquire artifacts merely because another owner registered them globally.
An install-manifest gate compares the exact files under `zig-out/` with the
selected product descriptor. Extra binaries, shader tools, diagnostics, or
backend libraries fail the gate.

### Focused CLI behavior

Each focused CLI must:

- expose only its compiled frontend and backend;
- require explicit backend selection when more than one backend exists;
- reject irrelevant flags rather than ignore them;
- reject unsupported artifacts before producing output;
- publish proof and report files atomically;
- verify every proof used for a benchmark;
- emit deterministic machine-readable registry and identity output; and
- keep help, registry, accepted flags, and actual linkage consistent.

The aggregate CLI must preserve released command and schema compatibility. It
may delegate to shared product application modules; it may not reimplement
their proving or verification lifecycle.

## Canonical product identity

Every product, proof report, benchmark row, cache record, profiler capture, and
gate receipt carries a versioned canonical identity. At minimum it binds:

- identity schema and product name;
- frontend set, backend set, and role;
- source repository, full commit, tree OID, and dirty state;
- a full dirty-content digest when a diagnostic dirty build is admitted;
- Zig version;
- target architecture, OS, ABI, CPU model, and enabled CPU features;
- optimization mode;
- enabled protocol/capability manifest and its digest;
- backend runtime or SDK identity when present;
- generated shader/archive semantic identity for Metal; and
- exact executable digest for executable evidence.

The canonical encoding and digest live in `build_support/graph/identity.zig` or
one equivalent authority. Product-specific code must not invent another digest
algorithm.

For a diagnostic dirty build, the dirty-content digest covers a canonical,
sorted sequence of repository-relative path, file mode, and content for every
tracked modification and untracked source input. Ignored build/cache outputs
are excluded by an explicit policy. `HEAD`, a tree OID, and `dirty=true` alone
are not a reproducible identity. Release products reject dirty state entirely.

Identity is embedded in the binary and exposed through machine JSON. A workflow
label or cache key that is not checked against the binary is not sufficient.
Proof artifacts may bind the executable digest rather than duplicate every
identity field, but the retained receipt must map that digest to the canonical
product identity and reject a mismatch.

Build identity does not enter Rust-compatible cryptographic proof bytes. It
lives in the artifact envelope, report, registry, and release receipt. This
keeps protocol parity separate from build provenance while binding both at the
publication boundary.

## Mechanical closure requirements

Every focused product must pass all four closure classes.

### Import and compile closure

The architecture gate resolves the transitive import graph from the actual
product roots, including named build imports and relative source imports. It
rejects every module outside the product manifest.

String searches over one facade file are not sufficient. The gate must account
for the build-owned module mapping and resolve the same paths the compiler can
reach. Generated imports are represented by an explicit generated manifest.

The compiler then builds the product in a clean environment where unrelated
SDKs and libraries are unavailable.

Graph tests also reject dependency cycles. Focused compile-surface tests force
public declarations through `refAllDecls` or an equivalent explicit surface so
Zig lazy analysis cannot make a forbidden import look absent merely because a
particular test did not instantiate it.

The root dispatcher constructs only the selected product or explicitly selected
gate scope. Registering inert top-level step descriptors is permitted when Zig
requires command discovery, but registration must not construct modules,
compile artifacts, libraries, system-link inputs, SDK probes, generated tools,
tests, or benchmarks for an unselected product. A configure-closure receipt
records every instantiated product, module root, external dependency, tool, and
runtime probe and compares that set with the selected manifest.

One common transitive closure implementation is authoritative for all products.
Product-specific marker scanners may remain only as defense-in-depth tests; they
cannot certify closure or diverge into product-specific interpretations.

### Link closure

Platform tools inspect the final binary:

- Linux CPU products: `readelf`/`ldd` or equivalent prove no Metal, CUDA,
  Objective-C, or unexpected dynamic runtime dependency;
- macOS CPU products: `otool -L` proves no Metal or Foundation linkage;
- Metal products: required Metal/Foundation linkage is present and CPU fallback
  is absent from the labelled execution path;
- static challenge products: ELF class, target machine, and lack of
  `PT_INTERP` match their manifest.

Binary string scanning is useful supporting evidence, not the only link gate.

### Visible capability closure

For every product, snapshots or structured assertions cover:

- `--help`;
- application/backend registry JSON;
- product identity JSON;
- accepted and rejected flags;
- unsupported frontend/backend combinations; and
- unavailable-runtime diagnostics.

Help or registry claims that differ from compiled behavior fail the gate.

### Behavioral closure

Each released focused product executes its real production path:

- Native CPU proves and independently verifies a bounded Native workload;
- RISC-V CPU executes, proves, and independently verifies a multi-shard ELF;
- Native Metal proves and verifies the same statement as Native CPU;
- deferred products fail before producing proof or benchmark artifacts; and
- aggregate and focused products agree after normalizing only documented
  executable/product provenance.

## Executive checkpoint matrix

| Checkpoint | Required result | Authoritative evidence | Decision while incomplete |
| --- | --- | --- | --- |
| BG-00 Baseline | Frozen commands, identities, dependency/link surfaces, proof outputs, and source-conformance state from the pre-migration commit | versioned architecture baseline receipt | NO-GO |
| BG-01 Typed graph | One typed product/capability model and named module factory own construction | graph unit tests and invalid-pair negatives | NO-GO |
| BG-02 Core/prover | Independently buildable core and generic prover with enforced purity | focused build/test/import receipts | NO-GO |
| BG-03 RISC-V CPU | Focused host/static product, CLI, diagnostic, tests, and fast challenge | product receipt and secure challenge receipt | NO-GO |
| BG-04 Native CPU | Focused CLI/test/benchmark graph with no other frontend/backend | product and parity receipt | NO-GO |
| BG-05 Metal | Explicit Metal owners/products; no host-selected linkage | macOS compile/link/parity receipt | NO-GO |
| BG-06 CUDA | Explicit opt-in construction and unavailable-runtime policy | graph and negative capability tests | NO-GO |
| BG-07 Cairo | Product ownership defined but release disabled with reason | disabled-state and negative-output tests | NO-GO if ambiguous or accidentally enabled |
| BG-08 Aggregate | Thin compatibility product assembled from focused components | CLI/schema/behavior compatibility receipt | NO-GO |
| BG-09 Root/build layout | Thin root and target `build_support` ownership reached | source-conformance and size receipt | NO-GO |
| BG-10 Identity | Canonical identity embedded and propagated to every evidence class | identity mutation and cross-surface tests | NO-GO |
| BG-11 Gates/caches | Focused gates and product-scoped trusted caches | CI contract and cache-domain tests | NO-GO |
| BG-12 Bench/profiler | Benchmarks and profiles use exact focused products and retain comparable history | benchmark schema/delta/profile receipts | NO-GO |
| BG-13 Correctness | Focused/aggregate parity and final pinned Rust oracle conformance | oracle and adversarial receipts | NO-GO |
| BG-14 Performance readiness | Focused benchmark/profiler interfaces and future epoch configuration remain attributable and fail closed | static contract, schema, history, and deferred-state tests | NO-GO if ambiguous, executable as a promotion gate, or able to fabricate performance evidence |
| BG-15 Final integration | One clean commit passes all required hosts with no skips or new debt | architecture release receipt | NO-GO |

## Detailed checkpoints

### BG-00: Freeze the baseline

Before removing compatibility wiring, record:

- exact source commit/tree and dirty state;
- Zig version and host identities;
- existing public build step names;
- aggregate CLI help, registry, success, and failure outputs;
- Native and RISC-V proof/verify artifacts and normalized digests;
- focused-product dependency and dynamic-link surfaces; and
- source-conformance baseline and file counts.

Existing performance history and comparator policy remain immutable inputs to
the separate future autoresearch goal. BG-00 neither regenerates nor evaluates
them, and their absence cannot block this architecture goal. No build timing,
binary-size measurement, benchmark row, throughput comparison, confidence
interval, or performance baseline capture is required here.

Each later work package records its pre-slice structural and behavioral state.
That evidence exists to detect ownership or correctness regressions, not to
score performance.

### BG-01: Typed graph and module factory

Deliver one authority for:

- frontend, backend, role, and product declarations;
- allowed and forbidden capability pairs;
- named module roots and dependencies;
- canonical identity construction;
- explicit installation; and
- introspection used by closure gates.

Tests must construct every valid matrix entry and reject invalid pairs,
including Metal on an unsupported target, Cairo release while disabled, a
frontend importing a concrete backend directly, and a backend-labelled product
without that backend.

### BG-02: Core and generic prover products

Core and generic prover modules build and test independently. Their graph does
not acquire a frontend or concrete backend through a convenience facade.

Required gates:

- core import-purity;
- generic prover import-purity;
- backend-contract purity;
- independent build and unit tests;
- no platform framework linkage; and
- API compatibility for the aggregate SDK facade.

The root build exports `stwo_core`, `stwo_prover`, and compatibility module
`stwo` through documented `b.addModule` contracts. A clean temporary downstream
consumer package, containing no repository-relative source imports, must depend
on the repository as a package, import each public module, compile, and execute
a bounded smoke test. An in-repository unit test is not a substitute for this
consumer contract.

### BG-03: Focused RISC-V CPU product

The RISC-V CPU graph contains only core, contracts, generic prover, CPU
scalar/SIMD, RISC-V frontend, RISC-V/CPU integration, artifact codec,
diagnostic, and focused CLI shell.

It must provide:

- host CLI and static `x86_64-linux-musl` challenge products;
- exact product identity;
- focused help and registry;
- prove, verify, and benchmark behavior;
- transitive import and binary closure;
- secure multi-shard proof verification; and
- use by the bounded RISC-V promotion challenge.

The pinned Stark-V oracle is final for RISC-V execution, trace, statement,
witness, and AIR/relation boundaries. The pinned Rust Stwo implementation is
separately final for the shared field, PCS, FRI, transcript primitive, proof,
and verifier behavior used by this product. The independent Zig verifier is
defense in depth and does not replace either Rust authority.

The known signed `MULH` limitation retains the exact
`FIX(stark-v-signed-mulh)` implementation marker and remains fail-closed until
the pin changes. This required marker records an inherited pinned-oracle defect;
it is not architecture debt and must not be deleted merely to satisfy a generic
TODO/FIX count.

The fast promotion challenge is a trusted challenge-response protocol, not an
abbreviated self-test:

- the controller fixes the candidate commit/tree, focused executable digest,
  product identity, repository, workflow run/attempt, and protocol manifest
  before issuing a fresh cryptographic server nonce;
- a domain-separated digest of that nonce and candidate identity selects the
  bounded program inputs and expected public statement;
- the focused candidate CLI executes that workload and returns its atomic proof
  artifact and report within the job deadline;
- a separately provisioned trusted verifier validates the proof, statement,
  product/artifact envelope, executable identity, and challenge provenance;
- the candidate cannot choose or rewrite the nonce, expected statement,
  verifier, pinned-oracle bundle, anchor receipt, or trusted cache; and
- replay, another candidate, malformed output, timeout, or any mismatch fails
  without a registry change or promotion receipt.

The commit-derived challenge input is ordinary public workload data and may
therefore affect the proof statement. Build/product identity itself remains in
the envelope and receipt and is not added to Rust-compatible proof transcript
encoding. This challenge is rapid candidate evidence, not proof that an
untrusted candidate could not outsource proving; trusted build provenance,
executable hashing, protected workflow ownership, and periodic exhaustive
oracle gates close that remaining trust boundary.

### BG-04: Focused Native CPU product

The Native CPU graph contains core, contracts, generic prover, CPU scalar/SIMD,
released Native AIRs, Native/CPU integration, artifact verification, and its
focused product shell.

It must not import RISC-V, Cairo, Metal, CUDA, aggregate dispatch, or unrelated
operational tools. Its benchmark step uses the same proving transaction as the
CLI, verifies every measured proof, and emits total proving time plus the
canonical numerator and product identity.

Focused and aggregate Native invocations must agree on statement, proof bytes
where determinism promises them, verification result, stage inclusion, and
machine schema. The pinned Rust Stwo implementation is the final protocol
oracle. Existing bidirectional proof/artifact interoperability and tamper tests
remain part of the compatibility surface.

### BG-05: Explicit Metal products

Move Metal build/link/runtime ownership under `build_support/backends/metal.zig`
and focused Metal product constructors.

Required outcomes:

- host OS never enables Metal by itself;
- CPU products on macOS contain no Metal/Foundation linkage;
- explicit Metal products fail clearly on unsupported hosts;
- existing AOT, shader, benchmark, and profiler steps retain stable owners;
- Metal runtime, generated shader, and AOT identities enter product identity;
- device-labelled paths cannot fall back to CPU;
- parity uses CPU and final Rust oracles as required; and
- historical Metal performance evidence retains stable product/workload keys
  and remains comparable later without being rerun by this goal.

This checkpoint includes build architecture, not deferred kernel optimization.

### BG-06: Explicit CUDA policy

Remove global booleans that inject CUDA into unrelated graphs. CUDA construction
is an explicit backend/product request with target, library, and runtime
requirements owned below `build_support/backends/cuda.zig`.

No CUDA owner contains a developer-local default such as `/Users/...` or an
assumed `/usr/local/cuda`. Paths come from the explicit CUDA product/toolchain
contract and fail validation before compilation when incomplete.

When CUDA is unavailable, graph and CLI tests prove a fail-closed unavailable
state. No CPU or Metal product gains CUDA link paths or flags.

### BG-07: Cairo ownership without premature release

Define Cairo CPU and Cairo Metal product ownership so future conformance work
has a correct graph. Do not resume semantic port work under this checkpoint.

Required behavior:

- Cairo products are absent from released registries or explicitly disabled;
- the reason is non-empty and tested;
- Native/RISC-V products cannot reach Cairo sources;
- Cairo source debt does not grow; and
- no Cairo benchmark can emit promotion-quality evidence until its separate
  Rust-oracle goal passes.

### BG-08: Aggregate compatibility product

`stwo-zig` becomes an explicit composition of released components. It retains
documented command, help, registry, JSON schema, publication, and verification
contracts.

The aggregate product may select a set of backends through explicit build
options. Its default is documented and platform-independent. Unsupported
requested capabilities fail graph construction; they do not disappear.

Tests compare focused and aggregate paths and prove that the aggregate layer
contains routing only, not duplicate proof logic.

Downstream `@import("stwo")` SDK compatibility is frozen before facade cleanup.
Intentional API changes require a versioned migration and deprecation window;
moving build ownership is not by itself permission to break downstream imports.

### BG-09: Thin root and complete ownership layout

Reduce `build.zig` to option parsing, target/optimization resolution, product
selection, and calls to owners. Move tests, gates, benchmarks, Metal, CUDA, and
interop construction under the target `build_support` directories.

Delete obsolete duplicate owners only after stable command compatibility is
covered. Update imports, source-conformance policies, decomposition ledger, and
documentation in the same focused changes.

Specifically migrate active root owners such as `src/riscv_*` entry points and
`src/metal_arena_plan_cli.zig` into their product or integration directories
when those owners land. Preserve deferred Cairo and SN-PIE sources. Update the
README in the final layout slice with the focused package, build, install, and
test commands plus the supported-host/product matrix.

### BG-10: Identity propagation

One mutation fleet changes each identity field independently and proves that:

- canonical digest changes;
- binary registry reports the actual value;
- proof/benchmark/gate receipt validation rejects mismatches;
- cache lookup cannot substitute another capability set;
- Metal shader/AOT substitution fails; and
- aggregate/focused evidence cannot be confused.

Dirty builds may run diagnostic commands but cannot issue release receipts.

### BG-11: CI, release gates, and caches

Split CI work by real product ownership:

- Linux Core/Prover;
- Linux Native CPU;
- Linux RISC-V CPU and challenge;
- macOS CPU no-Metal closure;
- macOS explicit Metal acceptance;
- CUDA unavailable or device acceptance where infrastructure exists; and
- aggregate compatibility.

Ordinary Core, Prover, Native CPU, and RISC-V CPU jobs do not checkout or build
stwo-cairo. Cairo pins remain validated by repository-wide policy, while Cairo
execution/build work belongs only to its disabled or dedicated future lane.

Cache keys bind the complete product identity domain and toolchain. Broad
restore prefixes are allowed only inside a trusted writer scope and must rely
on Zig's content validation; they never authorize correctness evidence.

The three-minute RISC-V challenge consumes a pinned, content-addressed,
CI-attested Stark-V/oracle/verifier bundle produced by a separate exhaustive
trusted workflow. It does not compile Rust or rebuild the oracle on its critical
path. Bundle provenance, exact pin, source/toolchain digest, binary digests,
corpus digest, expiry, and producer workflow are verified before challenge
issuance. A missing or invalid bundle fails the fast gate and schedules the
trusted producer; it never permits an unverified substitute. Candidate jobs
have read-only access and cannot publish trusted cache entries or anchors.

No focused promotion loop runs the aggregate strict suite. Periodic exhaustive
gates remain separate and reusable according to their own trust contracts.

### BG-12: Benchmark and profiler ownership

Every benchmark and profile names its focused product. Required metadata
includes workload, input dimensions, numerator, full timing scope, verified
proof status, protocol/security profile, cold/warm state, product identity,
binary digest, host/device, and source commit/tree.

The benchmark history and delta tooling remain continuous. A product rename or
graph move must map historical identity explicitly rather than orphan old rows.

CPU and Metal results are never compared when stage inclusion, security
parameters, trace shape, or verification policy differs.

### BG-13: Correctness and compatibility authority

Run:

- focused versus aggregate behavior parity;
- CPU scalar/SIMD parity for affected paths;
- Metal versus CPU statement/proof verification parity;
- Native versus pinned Rust Stwo parity;
- RISC-V versus pinned Rust Stark-V parity;
- malformed product identity and capability mutations; and
- unavailable-backend and no-output negative tests.

Any semantic difference introduced during restructuring is a blocker. It must
be reverted or moved into a separate design and oracle-gated goal.

Oracle authority is lane-specific and boundary-specific. Native/core/shared
Metal semantics use the pinned Rust Stwo authority. RISC-V execution, trace,
statement, witness, and AIR use pinned Stark-V, while its shared Stwo proof
machinery also uses pinned Rust Stwo. Evidence from one lane or boundary does
not certify another. Zig scalar and the Zig verifier remain fast differential
and defense-in-depth checks, not replacements for either relevant Rust pin.

### BG-14: Performance-harness readiness

This checkpoint is architectural. It proves that later autoresearch can measure
the focused products without changing product construction or losing history.
It does not execute benchmarks and it has no speed, build-time, memory, or
binary-size threshold.

Required static and bounded checks:

- each released focused product owns an explicit benchmark and profiler entry
  point built from the same production proving transaction as its CLI;
- benchmark help, workload registry, schema version, numerator definition,
  product identity, backend identity, and runtime identity are testable without
  running a benchmark matrix;
- benchmark history and delta tools retain stable product/workload keys and
  reject malformed, cross-product, or provenance-incomplete rows;
- the frozen epoch-two protocol and baseline artifacts remain immutable future
  inputs and are not regenerated from the candidate tree;
- the incomplete epoch-two capture controller is labelled deferred and cannot
  emit or be consumed as promotion-quality evidence;
- architecture CI contains no benchmark execution, MHz comparison, confidence
  interval, performance receipt, or performance-derived release verdict; and
- profiler and benchmark construction do not broaden a focused product's import
  or dynamic-link closure.

BG-14 fails if performance evidence can be fabricated, if a candidate can
silently promote itself, if historical keys are lost, or if the architecture
release gate depends on a missing performance artifact. A slow but correct and
honestly labelled focused product does not fail this checkpoint.

The later autoresearch goal must repair and independently audit the epoch-two
controller before use. Its throughput, build, memory, binary, host-calibration,
and complete-clock policies remain documented future requirements, not waived
or implicitly satisfied requirements of this goal.

### BG-15: Final integration receipt

From one clean commit:

1. produce a Linux host receipt from the clean commit;
2. produce a macOS host receipt from the same clean commit;
3. run every required focused product gate on its declared host;
4. run aggregate compatibility;
5. run Linux and macOS link-closure jobs;
6. run final Native and RISC-V Rust-oracle gates;
7. validate benchmark/profiler construction, schemas, history keys, delta
   tooling, and the explicit non-executable deferred performance state;
8. confirm no required test was skipped;
9. confirm the source baseline only shrank or stayed unchanged; and
10. have the trusted aggregate verifier emit one bounded release receipt.

Only this receipt may change the status of this document to COMPLETE.

## Machine authority

Implementation must provide one enforcing entry point, preferably:

```sh
zig build architecture-gate -Darchitecture-mode=host -Doptimize=ReleaseFast
zig build architecture-verify -- \
  --linux-receipt <linux.json> --macos-receipt <macos.json>
```

The first command is the host-local producer. It runs only the products and
gates assigned to that host and emits a signed or CI-attested host receipt. The
second command is the trusted aggregate verifier and is the sole GO authority.
There is one versioned receipt family and one verification implementation;
host jobs do not reproduce aggregate policy.

Both host receipts must bind the same clean repository commit and tree, product
schema digest, protocol manifest, workflow definition, repository, workflow
run/attempt, and trusted producer identity. The aggregate verifier accepts only
receipts downloaded through the trusted CI artifact channel from the same
authorized workflow run, or receipts carrying an equivalent repository release
attestation. A local unsigned receipt is diagnostic and cannot contribute to
GO. Receipt freshness, replay, host-role uniqueness, artifact digests, and
required product allocation are verified before checkpoint evaluation.

The host producer writes bounded `build-monorepo-host-receipt-v1` artifacts:

```text
zig-out/release-evidence/build-architecture/<commit>/<host>/<run-id>.json
```

The trusted verifier writes the `build-monorepo-receipt-v1` aggregate at:

```text
zig-out/release-evidence/build-architecture/<commit>/receipt.json
```

The receipt contains:

- candidate repository, commit, tree, and clean state;
- toolchain and host identities;
- checkpoint verdicts BG-00 through BG-15;
- product identities and executable digests;
- exact ordered commands, durations, exit codes, and skipped-test counts;
- import and link closure summaries;
- compatibility and oracle receipt digests;
- benchmark/profiler interface and deferred-epoch contract digests;
- source-debt before-and-after records; and
- final `PASS` only when every mandatory field passes.

The controller rejects duplicate JSON fields, unknown schemas, missing
commands, reordered mandatory phases, stale baselines, dirty trees, omitted
products, mismatched commits/trees/workflows, replayed or unauthorized host
receipts, and unsupported-host results presented as passes.

Development commands may be run independently. They do not replace the final
controller.

## Migration work packages

The implementation sequence is designed for parallel delivery without losing
reviewability.

| Work package | Outcome | Depends on | May run in parallel with |
| --- | --- | --- | --- |
| WP-00 | baseline and machine schema | none | documentation preparation |
| WP-01 | typed graph, identity, install helpers | WP-00 | closure-tool design |
| WP-02 | Core/Prover focused products | WP-01 | product CLI extraction |
| WP-03 | RISC-V CPU product and challenge consumer | WP-01 | WP-04 |
| WP-04 | Native CPU product/benchmarks | WP-01 | WP-03 |
| WP-05 | explicit Metal owners/products | WP-01 | WP-03, WP-04 |
| WP-06 | CUDA policy and Cairo disabled products | WP-01 | WP-03..WP-05 |
| WP-07 | aggregate compatibility composition | WP-02..WP-06 | gate extraction preparation |
| WP-08 | gates, benchmarks, caches, profiler ownership | WP-03..WP-07 | documentation reconciliation |
| WP-09 | thin root, obsolete-owner deletion, debt shrink | WP-07, WP-08 | final evidence preparation |
| WP-10 | full correctness parity, oracle, architecture, and release receipt | all prior | none |

### Increment rules

- Each commit has one architectural purpose and leaves its affected focused
  graph green.
- Compatibility shims are explicit and deleted by a named later package.
- Refactors and semantic changes do not share a commit.
- Product owners land before old ownership is removed.
- Large mechanical moves are separated from behavior changes.
- Each merged slice updates checkpoint evidence and the target layout ledger.
- Parallel branches rebase on the graph authority rather than invent local
  product identity or installation helpers.
- A legacy build-step alias remains until the focused replacement passes its
  parity gate; rollback is reverting the slice, never runtime fallback.

Velocity comes from parallel independent owners and focused gates, not from
skipping final integration.

## Required adversarial tests

At minimum, the architecture fleet attempts to:

- import Metal, CUDA, Cairo, or RISC-V through a CPU product facade;
- reach a forbidden sibling through a relative import;
- request Metal on Linux and observe CPU fallback;
- build a CPU product on macOS and detect host-selected Metal linkage;
- label a CPU binary or receipt as Metal;
- substitute product identity, executable, target, optimization, or feature
  digest in a proof/benchmark/gate receipt;
- reuse a cache across incompatible capability sets;
- expose an application or flag absent from the product manifest;
- omit a released application from aggregate compatibility;
- enable a deferred Cairo/RISC-V-Metal product;
- measure an unverified proof;
- compare benchmarks with different protocol settings; and
- grow the source-conformance baseline.

Every attempt must fail for the intended invariant, not because a fixture is
missing or a command crashes first.

## Rollback and failure policy

Rollback is mandatory when a slice:

- changes proof semantics without a separately accepted design;
- weakens final Rust-oracle evidence;
- introduces implicit backend selection or fallback;
- causes a focused product to import or link an unrelated capability;
- breaks aggregate compatibility without a versioned migration;
- loses benchmark history or comparable timing scope;
- executes or consumes deferred performance promotion evidence;
- grows source debt; or
- requires disabling a mandatory gate.

Temporary compatibility duplication is allowed only when bounded by an owner,
deletion checkpoint, and parity test. A TODO without a gate is not a bound.
No unresolved TODO remains inside the active Core, Prover, Native CPU, RISC-V
CPU, Native Metal, build-graph, gate, benchmark, or compatibility scope at
sign-off. Only the explicitly deferred Cairo, RISC-V Metal, and unavailable
CUDA work may remain. The sole active-scope exception is the mandatory,
gate-checked `FIX(stark-v-signed-mulh)` marker required by the pinned Stark-V
limitation and [divergence log](divergence-log.md); it may be removed only with
a new upstream pin and its own oracle-conformance evidence.

## Current reconciliation

At creation of this goal:

- the accepted architecture document exists;
- the repository still has a broad root build and broad `src/stwo.zig` facade;
- the focused RISC-V CPU product and bounded challenge have diagnostic green
  evidence on implementation branches but are not sufficient to complete the
  full architecture;
- shared graph identity and focused Native CPU work are in progress;
- Metal remains partly host-selected in the aggregate build;
- Core, Prover, Native CPU, CUDA policy, gate/benchmark ownership, thin root,
  and final machine receipt remain incomplete; and
- therefore BG-00 through BG-15 remain NO-GO until reconciled on one clean
  integrated commit.

## Repository completion evidence

The revised goal deliberately stops at a repository that is ready for a later,
independent autoresearch goal. It does not claim performance parity or a
protected production release receipt.

- the root `build.zig` is a six-line dispatcher into independently constructed
  product scopes;
- one typed catalog owns released and deferred product construction;
- configure-closure validation passes all 15 catalog scopes;
- focused Core, Prover, Native CPU, Native Metal, RISC-V CPU, and aggregate
  graphs construct without importing deferred Cairo/CUDA implementations;
- CPU and Metal aggregate correctness builds pass, and the Metal lifecycle is
  fail-closed against CPU fallback;
- source conformance reports no new violations;
- registry parity covers all six released Native AIRs;
- 93 focused authority/receipt boundary tests and workflow lint pass;
- performance execution and promotion are disabled and deferred; and
- protected BG-15 issuance remains disabled until the external controls in the
  activation runbook exist.

## Protected release activation checklist

- [ ] BG-00 immutable baseline is committed and validated.
- [ ] BG-01 typed graph and canonical identity are the only authorities.
- [ ] BG-02 Core and Prover focused products pass purity and behavior gates.
- [ ] BG-03 RISC-V CPU product and secure fast challenge pass.
- [ ] BG-04 Native CPU product, benchmark, and parity pass.
- [ ] BG-05 Metal is explicit and CPU products are Metal-free on macOS.
- [ ] BG-06 CUDA is explicit and fail-closed when unavailable.
- [ ] BG-07 Cairo products are correctly owned and disabled.
- [ ] BG-08 aggregate CLI compatibility passes without duplicate protocol logic.
- [ ] BG-09 root/build ownership and file-size targets pass.
- [ ] BG-10 identity propagation and mutation fleet pass.
- [ ] BG-11 focused CI, release, and trusted cache contracts pass.
- [ ] BG-12 benchmark/profiler identity and historical deltas pass.
- [ ] BG-13 focused/aggregate and final Rust-oracle correctness pass.
- [ ] BG-14 benchmark/profiler interfaces, history, and deferred performance
      state pass without executing a performance matrix.
- [ ] BG-15 one clean cross-host integration receipt passes with zero skips.
- [ ] `conformance/source-baseline.json` did not grow.
- [ ] `conformance/decomposition-plan.md` reflects every retained exception.
- [ ] No autoresearch lane was enabled by this architecture work.

These boxes govern a future protected production-release activation, not the
completed repository-layout goal. When every box is supported by the BG-15
receipt, record the exact candidate commit and receipt digest and change the
protected release decision to GO. Performance work remains a separate goal and
must name the exact product actually measured.
