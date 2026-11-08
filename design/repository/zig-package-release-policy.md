# Zig package versioning and distribution policy

**Status:** active monorepo policy  
**Applies to:** every owner with `package.contract.json`  
**Current distribution mode:** deterministic dependency-closed source archives

## Decision

The repository has independent engineering packages and publishes reviewed
source distributions for the supported Zig package surface.

Each of the 21 packages has its own owner directory, public module, manifest,
dependency allowlist, API contract, invariant suite, and focused CI lane. That
supports team ownership, isolated builds, and dependency auditing. Seventeen
packages are publishable in v1. The three CUDA packages remain source-retained
but distribution-deferred until current NVIDIA hardware validation and
generated-AOT extraction are complete. `stwo_metal_session` remains internal.

Repository releases remain atomic: one reviewed tag produces all publishable
archives from the same commit and tree. Each archive contains its target
package, its complete local-path dependency closure, the Apache license, and a
canonical `PACKAGE-RELEASE.json`. It deliberately contains no autoresearch,
Rust tooling, Lean workspaces, vectors, or deferred CUDA payload. Consumers can
therefore use a small Zig source closure without cloning the research and
conformance monorepo.

## Meaning of the current versions

Every package contract and matching `build.zig.zon` currently carries `0.1.0`.
The workspace checker requires those two declarations to agree.

While distribution mode is `dependency-closed-source-archives-v1`:

- the version is an externally visible incubating package identity;
- packages may evolve at different rates without artificial version bumps on
  untouched owners;
- a repository tag, commit, tree, and package graph identify the exact
  compatible set;
- release receipts identify the assembled product and implementation revision,
  while package manifests identify the independently downloadable source
  closure.

No package may advertise its current version as a stable external API. The
stable/experimental distinction is instead expressed by its public API ledger,
signature tests, behavioral invariant tests, and package layer.

## Source of truth

For each package:

1. `package.contract.json` is authoritative for package name, version, layer,
   owner, public module, direct dependencies, API tests, invariants, and CI
   lane.
2. `build.zig.zon` is the Zig package-manager projection of that contract.
3. `build.zig` constructs the public module and consumes exactly the declared
   direct dependencies.
4. The generated ownership projection, aggregate manifests, and focused-CI
   touchpoints must reconcile with those contracts.
5. `conformance/package-release-v1.json` is authoritative for whether a
   package is `published`, `deferred`, or `internal`.

`scripts/check_package_workspace.py` rejects drift among these views, boundary
escapes, cycles, forbidden layer edges, and untested public API declarations.

## Change and review policy

A package change is reviewed at the smallest owner that can express it.

- Internal implementation changes remain inside the owner and run its focused
  lane plus affected transitive consumers.
- Public API changes update the API ledger and the exact signature/invariant
  tests in the same commit.
- A new dependency updates the package contract first and must satisfy the
  layer policy; the manifest, build, ownership projection, and CI selection
  then reconcile to it.
- Cross-package policy or adaptation belongs in an integration package, not in
  a concrete backend or frontend.
- Product roots aggregate public package modules. They do not reach into owner
  internals or become alternate dependency authorities.

The Cairo frontend, RISC-V frontend, backends, and their integrations can
therefore advance on separate branches. A shared-package change deliberately
selects its consumers; an unrelated frontend change does not.

## Source archive contract

`python3 scripts/package_release.py` and `zig build package-dist` implement the
v1 publication contract. They first run the package-workspace audit, reject a
dirty source tree by default, compute dependency closures from package
contracts, select only Git-tracked owner files, normalize tar metadata, and
emit `index.json` plus `SHA256SUMS`. Repeating the command for the same tree is
byte-identical.

The manual-or-tag `Zig package release` workflow builds the complete atomic
set, tests representative portable archives on Linux and compiles the Metal
backend archive on macOS from empty extraction directories. A tag run stages
assets in a draft, refuses to replace existing assets, and publishes the draft
only after every upload succeeds.

The policy is fail-closed: a package absent from the registry, a published
package depending on a deferred package, any Rust source in a publishable
closure, or any autoresearch/formal/vector/tooling path in an archive is an
error. CUDA remains implemented in the monorepo and is not silently weakened;
only its distribution status is deferred.

## Future SemVer rule

When independent version trains are admitted, package versions become
independent:

- **major:** incompatible public API, invariant, proof-wire, or behavioral
  contract change;
- **minor:** backward-compatible public capability or API addition; and
- **patch:** compatible implementation, performance, documentation, or test
  correction.

Before 1.0, the publishing proposal must state whether a minor bump may carry
an incompatible change; this policy intentionally does not assume that rule.
Dependency constraints and release tooling must compute the transitive publish
order from the authoritative package graph.

## Product releases

Applications, CLIs, aggregate libraries, proof receipts, and benchmark
artifacts remain products rather than reusable packages. A product release
records:

- repository commit and tree;
- dirty-state policy;
- aggregate package graph;
- toolchain and platform;
- proof/protocol identifiers where applicable; and
- the normal release-gate evidence.

This separation lets package owners work independently without fragmenting the
security review or implying that arbitrary combinations of package versions
have been validated.
