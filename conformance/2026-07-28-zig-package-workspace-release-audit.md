# Zig package-workspace release audit

**Status:** PASS  
**Audit date:** 2026-07-28  
**Current branch:** `feat/architecture-hardening`
**Current base:** `78556fe7` (`Feed: refresh after recorded promotion`)
**Original package epoch:** `9e30e723` through the package-workspace merge

This audit closes the package-workspace sequence that followed the RISC-V
conformance work. It records the commit ordering, package graph, enforced
boundary invariants, and local release evidence needed to review the epoch
without reconstructing intent from the whole repository history.

This is a release audit for repository structure and package isolation. It does
not claim that the universal AIR-to-Sail refinement theorem has been completed,
or that the PCS/FRI/Fiat-Shamir security accounting has received an independent
external review. Those remain separate soundness objectives.

## Result

The requested sequence is complete:

1. The 17 RISC-V source-conformance findings were removed without changing a
   Cairo path.
2. The RISC-V and Cairo feature histories were integrated before packaging.
3. Packaging began in a separate epoch whose first commit is a direct child of
   the integrated merge.
4. Manifests were added at existing owner directories; there was no mass
   directory move.
5. Cross-owner source edges now use declared named imports, and a repository
   checker rejects relative-import or embedded-resource boundary bypasses.
6. The only package-epoch directory move is a later, mechanical, 100% rename of
   the proof-wire root.

The resulting workspace has 18 packages, 18 primary public modules, and 59
declared dependency edges. Every package's independent CI lane passes, the
downstream consumer smoke test passes, and the normal release gate passes.

The architecture-hardening follow-up adds an independent stable
`stwo_prover_api` package, renames the orchestration owner to
`stwo_prover_engine`, removes the Metal backend's concrete dependency on the
CPU backend, and upgrades every owner contract to
`stwo-zig-package-contract-v2`. The historical sequence evidence below remains
the record of the original 17-package introduction; the graph and enforcement
sections describe the current 18-package workspace.

## Sequence evidence

### 1. Clear the 17 RISC-V findings without touching Cairo

The cleanup starts after `a685d2c0` and ends at `65ef68c7`. Running the source
ratchet from the pre-cleanup snapshot reports exactly 17 findings:

- ten oversized RISC-V or RISC-V-support sources;
- six undeclared Python package-layer edges; and
- one root-level RISC-V Metal implementation source.

The cleanup is the following extraction-only series:

| Commit | Extraction |
| --- | --- |
| `1c197cb6` | shared RISC-V AIR contract library |
| `695ca298` | RISC-V Metal product modules |
| `60f65d59` | RISC-V equivalence wire contracts |
| `ad891bfd` | upstream-pin ledger model |
| `3c4c7da5` | trace-vector ELF builder |
| `c328ec42` | AIR uniqueness test contracts |
| `6947ce77` | malicious-witness rejection matrix |
| `fa40c865` | RISC-V artifact validation boundary |
| `2791275e` | AIR uniqueness solver execution |
| `bea3bbaa` | architecture-test adapter support |
| `5ecbf767` | lookup-table uniqueness certificate |
| `65ef68c7` | infrastructure uniqueness certificates |

`git diff --name-only a685d2c0..65ef68c7` contains no path matching `cairo`.
At `65ef68c7`, the ratchet reports five explained legacy findings and no new
violation. Those five are unrelated to this cleanup and are listed below.

### 2. Integrate feature histories first

`6ae02bf7` has these parents:

```text
65ef68c7  RISC-V cleanup tip
9a9639e6  origin/feature/cairo-frontend-completion
```

Both `feat/riscv-sail-frontend` and
`origin/feature/cairo-frontend-completion` are ancestors of the package branch.
The Cairo integration is therefore part of the branch history, not copied or
reimplemented during the package epoch.

The merge also follows the semantic-authority cleanup in `c80b17e9`. Active
RISC-V release admission is Sail-backed, with Spike as the independent
executor. The Rust Stark-V CP-11 producer and replay jobs are disabled and
fail closed. Retained Stark-V references are limited to archived receipt
forensics, optional performance comparison, guest-source provenance, and
legacy proof-layout lineage; they are not semantic or release authority.

### 3. Start a separate package epoch

The first packaging commit is:

```text
9e30e723 Add independent core prover package manifests
parent: 6ae02bf7
```

This gives the packaging work one reviewable epoch after feature integration.
No packaging commit is interleaved into either feature branch's pre-merge
history.

### 4. Add manifests at existing owner directories

Each owner directory carries:

- `build.zig`;
- `build.zig.zon`;
- `package.contract.json`; and
- one primary named public module.

The package graph is:

| Package | Owner | Direct package dependencies | CI host |
| --- | --- | --- | --- |
| `stwo_core` | protocol-core | none | Linux |
| `stwo_backend_contracts` | backend-contracts | core | Linux |
| `stwo_prover_api` | prover-api | core | Linux |
| `stwo_prover_engine` | prover-engine | core, backend contracts, prover API | Linux |
| `stwo_riscv_frontend` | riscv-frontend | core, prover API, prover engine | Linux |
| `stwo_cairo_frontend` | cairo-frontend | core, backend contracts, prover API, prover engine | Linux |
| `stwo_cpu_backend` | cpu-backend | core, backend contracts, prover engine | Linux |
| `stwo_cuda_backend` | cuda-backend | backend contracts | Linux |
| `stwo_metal_backend` | metal-backend | core, backend contracts, prover API, prover engine | macOS |
| `stwo_riscv_cpu_integration` | riscv-cpu-integration | core, RISC-V frontend, CPU backend, prover API, prover engine | Linux |
| `stwo_cairo_cpu_integration` | cairo-cpu-integration | core, Cairo frontend, CPU backend, prover API, prover engine | Linux |
| `stwo_riscv_metal_integration` | riscv-metal-integration | core, RISC-V frontend, Metal backend, prover API, prover engine | macOS |
| `stwo_cairo_metal_integration` | cairo-metal-integration | core, backend contracts, Cairo frontend, Metal backend, Metal session, prover engine | macOS |
| `stwo_metal_session` | metal-session | none | Linux |
| `stwo_proof_wire` | proof-wire | core | Linux |
| `stwo_native_examples` | native-examples | core, CPU backend, prover API, prover engine, proof wire | Linux |
| `stwo_native_cuda_integration` | native-cuda-integration | core, backend contracts, CUDA backend, Native examples, proof wire, prover engine | Linux |
| `stwo_cairo_cuda_integration` | cairo-cuda-integration | core, backend contracts, Cairo frontend, CUDA backend, Native CUDA integration, prover engine | Linux |

Root and internal aggregate manifests enumerate the same 18 packages. They
assemble products from the public modules; they do not replace the owner-local
manifests.

### 5. Convert cross-owner edges to named imports

`scripts/check_package_workspace.py` is the enforcing boundary, not merely an
inventory. It fails on:

- a manifest dependency not matching the package contract;
- an undeclared dependency in an owner-local `build.zig`;
- a dependency forbidden by the declared architectural layer;
- an undeclared or unknown named import;
- a dependency cycle;
- a relative Zig import that leaves an owner;
- any consumer relative import that enters another owner;
- an `@embedFile` that leaves or enters an owner;
- drift in a primary public API ledger;
- a missing, duplicated, unreachable, or renamed signature/invariant test;
- drift in the generated package-ownership projection;
- a missing focused-CI lane, host mismatch, command mismatch, or lane that is
  not selected by a change to its package;
- drift between package contracts and the two aggregate manifests; or
- a missing package build, manifest, public module, or declared dependency.

Every v2 contract declares one semantic layer, an independent version, the
exact public-module and dependency surface, at least one concrete signature
test, at least one behavioral invariant test, and one exact focused-CI
lane/host/command tuple. The checker resolves each named Zig test from the
package's public root, rather than accepting an arbitrary test elsewhere in the
repository.

The migration order remained incremental:

```text
core -> backend contracts -> prover
     -> RISC-V frontend -> Cairo frontend
     -> CPU -> Metal -> CUDA
     -> CPU integrations -> Metal integrations
     -> proof wire -> Native examples -> CUDA integrations
```

The aggregate build still exists as a product composer. It consumes named
modules from smaller packages and is no longer the only place capable of
constructing those closures. Direct protocol tests and one-shot CLI commands
also discover each selected module's source and exact dependency scope from
the authoritative package contracts; commit `36214c8b` removes the former
second, manually maintained copy of that graph.

The Cairo frontend's package tests intentionally consume authenticated
monorepo conformance vectors. Commit `87c8deda` binds both test runners to the
repository vector root explicitly, so the owner-local command and root
`--build-file` CI command have identical working-directory semantics.
Production Cairo modules do not acquire an undeclared source dependency from
that test-only resource boundary.

### 6. Move only later and mechanically

There is one rename in `6ae02bf7..HEAD`:

```text
src/interop/proof_wire.zig
  -> src/interop/proof_wire/mod.zig
```

Commit `f141dc4d` performs a 100% Git rename plus path-only reference updates:
38 insertions and 38 deletions. The proof-wire package is added in the
following commit, `10072fc1`. No other file is renamed or deleted in the
package epoch.

This establishes the intended policy for future moves: first make ownership
and dependencies explicit in place; then move a stable owner only when the
layout itself improves, in a commit with no semantic change.

## Enforced team boundary

For day-to-day work, a package owner can reason about four local artifacts:

1. the public module named in `package.contract.json`;
2. the exact dependency allowlist in that contract and `build.zig.zon`;
3. the owner-local build and tests; and
4. the focused CI lane selected by `conformance/ci-touchpoints-v1.json`.

A change to a shared package selects its transitive consumers. A change to one
frontend selects that frontend, its integrations, and its assembled products;
it does not make an unrelated frontend part of the source closure. Host-specific
integrations retain explicit Linux or macOS lanes, while host-neutral package
contracts run on either host.

This is the Zig equivalent of a Rust workspace or TypeScript monorepo package
graph: the compiler module graph is assembled by `build.zig`, and the
repository checker supplies the boundary rules that Zig's package manager does
not infer automatically.

The packages are intentionally monorepo-distributed rather than independently
published. The active version semantics, atomic product-release rule, and
admission requirements for any future external publishing are defined in
[`zig-package-release-policy.md`](zig-package-release-policy.md).

## Verification evidence

The following commands passed on the audited macOS host with Zig 0.15.2:

| Evidence | Result |
| --- | --- |
| `python3 scripts/check_package_workspace.py` | 18 packages, 18 public modules, 59 edges |
| all 18 package `zig build test --build-file ...` lanes | PASS |
| owner-local `src/frontends/cairo` package test | 38/38 tests |
| `python3 scripts/check_build_configure_closure.py` | 21 catalog scopes |
| `python3 scripts/check_registry_parity.py` | 6 Native AIRs |
| `python3 scripts/check_source_conformance.py` | 0 explained legacy findings, 0 new |
| `python3 scripts/check_api_parity.py` | PASS |
| `python3 scripts/ci.py --fast` | 1,064 tests, 2 intentional skips |
| `python3 scripts/zig_protocol_test.py src/stwo_deep.zig -OReleaseFast` | 112/112 tests |
| `zig build test-downstream-modules -Doptimize=ReleaseFast -j2` | PASS |
| `zig build test -Daggregate-metal=false -Doptimize=ReleaseFast -j2` | 422-source closure PASS |
| `zig build riscv-release-gate -Driscv-release-phase=promoted -Doptimize=ReleaseFast -j2` | promoted smoke and committed Sail evidence PASS |
| `zig build release-gate -Doptimize=ReleaseFast -j2` | PASS |

The normal release gate includes the RISC-V CPU/prover closures, the complete
17-family extraction differential, the 292-case operand-class sweep, positive
and negative trace-vector reproduction, protocol/interchange tests, and Native
Rust interoperability.

## Residual debt and non-blocking observations

The five inherited oversized sources have been decomposed and
`conformance/source-baseline.json` is empty. The former Rust verifier owners,
Cairo Metal arena binding, and Metal arena planner now have narrow facades and
responsibility-specific modules, each below the source ceiling. Future
oversized-file or package-layering findings fail immediately; there is no
remaining source-conformance waiver.

The open Cairo frontend work can proceed independently because its package and
integrations have explicit boundaries. It does not require a repository-wide
move or simultaneous changes to the RISC-V frontend, prover engine, or backend
implementations.

The static CI tier passes but currently takes about 253 seconds on the audit
host, above its advisory 60-second budget. This is CI-latency debt, not a
correctness waiver.

Strict device acceptance, live formal-tool regeneration, and external
proof-system security review remain environment- or reviewer-owned gates. They
are not replaced by the package-workspace release evidence above.
