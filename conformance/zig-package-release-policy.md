# Zig package versioning and distribution policy

**Status:** active monorepo policy  
**Applies to:** every owner with `package.contract.json`  
**Current distribution mode:** source-monorepo only

## Decision

The repository has independent **engineering packages**, but it does not yet
publish independent **distribution artifacts**.

Each of the 18 packages has its own owner directory, public module, manifest,
dependency allowlist, API contract, invariant suite, and focused CI lane. That
is enough for team ownership, parallel development, isolated builds, and
dependency auditing. It does not require consumers to resolve 18 separately
released archives.

Repository releases are therefore atomic for now. Internal dependencies remain
local path dependencies, and the aggregate products select exact source from
one repository revision. This avoids claiming a compatibility and supply-chain
contract that the project does not presently need.

## Meaning of the current versions

Every package contract and matching `build.zig.zon` currently carries `0.1.0`.
The workspace checker requires those two declarations to agree.

While distribution mode is `source-monorepo`:

- the version is an incubating package identity, not an externally supported
  compatibility range;
- packages may evolve at different rates without artificial version bumps on
  untouched owners;
- a repository commit, tree, and package graph identify the exact compatible
  set; and
- release receipts identify the assembled product and implementation revision,
  not an independently downloadable package archive.

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

## External publishing admission

Independent publishing may be introduced only by a separate reviewed proposal.
That proposal must define all of the following before the first package is
published:

1. the registry or archive transport and immutable package identity;
2. SemVer compatibility rules for Zig source APIs before 1.0 and after 1.0;
3. dependency version constraints replacing or supplementing local paths;
4. a reproducible source archive and an allowlist for generated, embedded, and
   platform-specific inputs;
5. Linux/macOS support claims, including how Metal and CUDA packages are
   represented;
6. release provenance, checksums, signing, and rollback/yank policy;
7. clean-room consumer tests using only published artifacts;
8. a release order for the dependency DAG and failure recovery for partial
   publication;
9. deprecation and support windows for public APIs; and
10. an explicit list of packages that are public, internal-only, or product
    assemblies.

Until those conditions are approved and enforced, changing `0.1.0` does not
publish anything and adding registry metadata opportunistically is out of
scope.

## Future SemVer rule

If external publishing is admitted, package versions become independent:

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
