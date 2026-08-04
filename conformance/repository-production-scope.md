# Production repository scope and extraction policy

**Status:** active

**Effective:** 2026-08-01

**Primary deliverable:** versioned Zig packages and CPU/Metal products

## Boundary

`stwo-zig` is a Zig proving system. The supported distribution surface is the
dependency-closed package set declared in
[`package-release-v1.json`](package-release-v1.json), not every file needed to
develop, reproduce, or independently audit the monorepo.

The repository currently retains three kinds of adjacent evidence:

- Rust interoperability and oracle tools under `tools/`, plus the pinned CUDA
  host-authority snapshot;
- Lean refinement work under `formal/`; and
- autoresearch harnesses, ledgers, reports, and optional workflow templates
  under `autoresearch/`.

None enters a published Zig package archive. None is linked into a portable
core, prover, frontend, or CPU package merely because it lives in this
repository.

## Preserve useful work

Cleanup is extraction-first, never deletion-first. Working code or evidence is
removed from `main` only after its replacement has all of:

1. an immutable upstream repository and revision;
2. a content digest and reproducible acquisition path;
3. a clean-room build or replay test;
4. a documented offline/failure mode; and
5. proof that every current consumer uses the replacement.

Git history or an untested archive branch alone is not an adequate replacement.
This rule intentionally keeps the current CUDA and Lean work intact.

## CI boundary

Hosted CI owns product correctness, package boundaries, formal claim gates, and
release evidence. It does not judge or publish autoresearch work. The optional
research workflows remain versioned in `autoresearch/workflows/` so the owner
can install and run them explicitly, but no autoresearch workflow is installed
under `.github/workflows/` and production CI imports no autoresearch tests.

This separation also prevents research ledger or dashboard changes from
becoming merge requirements for production code.

Branch protection requires the stable production `Select focused gates` check;
autoresearch judge and validation checks are not merge requirements.

## Rust extraction

Rust tools are compatibility authorities, fixture generators, and independent
oracles; they are not production Zig modules. Moving them safely requires a
companion tools repository with immutable release artifacts and the same pinned
acceptance behavior. Until that exists:

- Rust tools stay isolated under `tools/` and are invoked only by named oracle
  or conformance gates;
- published source archives reject every `.rs` file and the entire `tools/`
  tree; and
- no new production package may depend on Cargo.

The large Rust footprint below `src/backends/cuda/vendor/host_authority` is a
pinned backend authority snapshot. It follows the stricter CUDA extraction
gate below rather than being treated as ordinary application source.

## Lean extraction

Lean is proof evidence rather than runtime code. It may move to a formal
companion repository after source identities, generated Sail inputs, theorem
names, axiom audits, and release receipts can be consumed fail-closed from an
immutable revision. Until then it stays in-tree so a Zig semantic change cannot
silently retain a proof about an older AIR. Published packages exclude it.

## CUDA retention and future split

The functional CUDA implementation remains required work and is not deleted.
Its three packages are distribution-deferred because the repository cannot
currently requalify them on the target 5090-class host. In particular, the
generated Cairo AOT sources and the vendored host-authority snapshot remain on
`main` until all of the following pass:

- deterministic regeneration or an authenticated content-addressed bundle;
- manifest-complete source and symbol coverage;
- clean-room build from the external artifact;
- native and Cairo proof parity on current NVIDIA hardware; and
- negative tests for missing, stale, or partially fetched payloads.

After those gates pass, generated payloads may move to a dedicated immutable
CUDA artifact repository or branch while the handwritten Zig/CUDA runtime,
ABI, manifests, and fail-closed loader stay here. The split must reduce clone
and package size without weakening offline reproducibility.

The checked-in source populations have different migration rules:

- The 15 product-owned Native AOT sources (3,958 lines) are maintained kernel
  implementations, not disposable generated output. They remain until a
  reviewed source generator or ordinary maintained-kernel replacement exists.
- The 271 Cairo evaluation sources (159,806 lines) are reproducible from
  `vectors/cairo/sn_pie_2_composition.bin` and the Zig CUDA emitter. The CUDA
  builder must generate them into its cache and authenticate the emitted
  manifest before their checked-in copies are removed.
- The 33 recorded-witness sources comprise 26 exact authority copies and seven
  deterministic derivations (79,420 lines total). Their compact witness
  program and a Zig-owned CUDA emitter must replace the imported Rust emitter
  before source removal.
- The 340 copied authority AOT sources are reference-only and never enter the
  Native product. They move with the host authority after the external
  acquisition and parity gates above are complete.

The redundant `vendor/upstream` checkout was not an independent authority: it
was byte-identical to the CUDA subtree already present in
`vendor/host_authority`. It was collapsed into that retained subtree without
removing unique source or changing either closure identity.

## Release surface

`zig build package-dist` emits the complete v1 publishable set. Each archive
contains only its package and transitive Zig package dependencies, preserves
required Metal/C/assembly assets, normalizes archive metadata, and records
source commit/tree plus file digests. `SHA256SUMS` and `index.json` bind the
atomic set.

CUDA packages are retained but deferred, and the low-level Metal session owner
is internal. Package state changes are reviewed in
[`package-release-v1.json`](package-release-v1.json); they never happen because
a directory happened to be included by a broad archive command.
