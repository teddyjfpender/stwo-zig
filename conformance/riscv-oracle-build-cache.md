# RISC-V Oracle Build Cache

**Status:** ARCHIVED. This cache format is retained for old-bundle forensics
and optional benchmark tooling only. The CP-11 producer is retired, no active
workflow writes this release cache, and a cache hit is not release evidence.

The retired CP-11 path executed the pinned Rust Stark-V oracle at commit
`d478f783055aa0d73a93768a433a3c6c31c91d1c`. Recompiling the `cp11_dump`
adapter does not add evidence when every build input is unchanged, so the
historical release producer maintained a persistent content-addressed binary
cache.

The cache is an acceleration layer, not an oracle substitute. Every cache hit
still executes the complete Rust/Zig corpus and compares every CP-11 boundary.
The resulting receipt remains candidate-bound and expires under the existing
release-evidence contract.

## Identity

An entry key is the canonical SHA-256 digest of:

- the exact Stark-V repository URL and commit;
- the clean Git index tree digest;
- every recursively initialized submodule path and commit;
- the root `Cargo.lock` digest;
- the aggregate digest of all checked-in `cp11_dump` overlays and the reviewed
  temporary Cargo manifest transform;
- resolved `rustc --version --verbose` and `cargo --version --verbose` output;
- the executable Rust target, effective Cargo configuration digest, and
  build-affecting Rust/C environment variables;
- the locked release build command; and
- host operating-system and architecture families.

The identity resolves Cargo's effective target and records whether it uses the
host-default or target-qualified output layout; the build selects only
`--bin cp11_dump`. A dirty checkout, missing submodule, wrong commit, malformed
toolchain identity, or unexpected manifest shape aborts before lookup or build.

## Validation

Each entry contains only `manifest.json` and `cp11_dump`. A hit is accepted only
when the strict manifest schema, recomputed identity/key, regular-file status,
executable mode, byte length, and executable SHA-256 all agree. Invalid entries
are never executed; the producer rebuilds and atomically replaces them. The
receipt records hit/miss status, the content key, manifest digest, executable
digest, and the exact validation list for auditability.

The default location is the platform cache directory. Override it for CI or a
shared persistent volume with:

```sh
export STWO_ZIG_RISCV_ORACLE_CACHE_DIR=/persistent/stwo-zig/riscv-oracle
```

The CLI also accepts `--oracle-cache-dir`. Deleting the directory is always
safe; the next CP-11 producer run performs a locked rebuild.

GitHub Actions restores this directory using a pinned `actions/cache` revision.
After installing the pinned toolchains and recursively initializing Stark-V,
CI computes the outer key with the same resolver used by the inner lookup. The
outer digest covers the complete inner build identity, inner cache schema, and
entry contract. Any identity or schema change that would make a valid old entry
miss therefore selects a new outer Actions key. Integrity damage under an
otherwise matching key is still rejected by the inner validation and rebuilt
for the current producer. Because Actions keys are immutable, a persistently
damaged outer entry requires an explicit cache-schema/key rotation.

This is an **integrity-checked, trusted-writer-scoped cache**, not an
authenticated artifact. The workflow permits restore/save only in the
exhaustive producer job. Both the job admission and a pre-cache runtime guard
require the canonical repository, `workflow_dispatch` on `refs/heads/main`, and
numeric owner identity `92999717` for both the actor and triggering actor. Pull
requests, forks, pushes, and manually dispatched fast gates cannot write this
namespace, and no broad `restore-keys` fallback is allowed.

The exhaustive job also captures the release-policy content domain from its
trusted main workflow commit and requires the candidate's workflow, build
graph, scripts, conformance inventories, and tests to be byte-identical before
executing the candidate cache resolver or build adapter. A registry candidate
therefore cannot redefine the cache key, entry validator, or oracle overlay.

GitHub currently reports `main` as `.protected=false`. Enabling branch
protection and restricting workflow changes remains an administrator hardening
TODO; checked-in workflow code cannot establish that setting. Until then, the
numeric repository-owner dispatch check is the fail-closed trust root. The
digest checks detect content drift but do not prove authorship independently of
that trusted writer. A cache hit never replaces execution of the Rust/Zig
oracle comparison.
