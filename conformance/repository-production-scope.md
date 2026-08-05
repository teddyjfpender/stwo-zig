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

- Rust interoperability and oracle tools under `tools/`, plus immutable
  manifests and a fetch boundary for the external CUDA host authority;
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

The former 1,003-file CUDA Rust workspace is no longer tracked. Its exact
commit, Git trees, 1,003-file host manifest, 458-file kernel manifest, and
fetch/verify tool remain. The isolated Rust adapter materializes that authority
only when its explicit oracle step is requested; it is not an ordinary CI or
release dependency.

## Lean extraction

Lean is proof evidence rather than runtime code. It may move to a formal
companion repository after source identities, generated Sail inputs, theorem
names, axiom audits, and release receipts can be consumed fail-closed from an
immutable revision. Until then it stays in-tree so a Zig semantic change cannot
silently retain a proof about an older AIR. Published packages exclude it.

## CUDA retention and future split

The functional CUDA implementation remains required work and is not deleted.
Its packages are distribution-deferred because the repository cannot currently
requalify them on the target NVIDIA host. Extraction is now complete for the
bulk authority and generated-witness populations because the following local
gates are in place:

- deterministic Zig regeneration from authenticated compact witness IR;
- manifest-complete source, AOT, and ABI-symbol coverage;
- an immutable external fetch that reproduces both full closure hashes;
- a 28-file authenticated active source closure; and
- fail-closed checks for absent, stale, or mismatched inputs.

Native and Cairo proof parity on current NVIDIA hardware is still required for
production admission, but it no longer blocks repository cleanup. The
handwritten Zig/CUDA runtime, ABI, manifests, generators, active authority, and
fail-closed loader stay here. Full Rust/CUDA authority is materialized only for
explicit audit or adapter work.

The checked-in source populations have different migration rules:

- The 15 product-owned Native AOT sources (3,958 lines) are maintained kernel
  implementations, not disposable generated output. They remain until a
  reviewed source generator or ordinary maintained-kernel replacement exists.
- The 271 Cairo evaluation bodies (159,806 lines when materialized) are reproducible
  from `vectors/cairo/sn_pie_2_composition.bin` and the Zig CUDA emitter. They
  are generated into Zig's build cache, and the builder requires their emitted
  manifest to equal the checked-in authenticated manifest. Generated `.cu`
  copies do not belong in the source tree.
- The 33 recorded-witness sources comprised 26 exact authority copies and seven
  deterministic derivations (79,420 lines total). They are now emitted by Zig
  into the cache from the authenticated witness-program bundle and checked
  against their existing source hashes.
- The 340 copied authority AOT sources are reference-only, never enter a Native
  product, and now exist only behind the external authority boundary.

The earlier `vendor/upstream` and `vendor/host_authority` trees contained no
unique repository-owned source. Both full closure identities remain checked,
and `scripts/cuda_external_authority.py` reproduced them from the immutable
upstream revision before the tracked workspace was removed.

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
