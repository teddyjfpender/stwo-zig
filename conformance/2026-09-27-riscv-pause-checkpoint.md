# RISC-V checkpoint before Cairo completion

The RISC-V and Ethereum block architecture effort is paused at the user's
request. Its three engineering agents were stopped, and no proof or compiler
process was running at the pause. The next development priority is completion
of the Cairo frontend and backend support for Starknet block proving.

This commit preserves the accumulated BLAKE3, CSP, recursive proving, backend,
and block architecture work together with its source experiments and textual
benchmark evidence. It is a work-in-progress checkpoint, not qualification of
every accumulated change or of end-to-end Ethereum block proving.

The final read-only global staging work is unqualified. Its two focused test
attempts failed during compilation; neither executed tests. Other partially
assembled recursive memory, caller, global provider, and proof-file transport
changes also require qualification before any completion claim. The earlier
global read-only collection receipt reports 41 passing tests, but qualifies
that earlier source snapshot only. CUDA coverage remains limited to the
recorded local compile and focused checks, with full GPU runs deferred.

Useful continuation records are in
`autoresearch/notes/2026-09-24-ethereum-block-delivery/`, including
`block-v5-readonly-global-staging-v2.md` and `cpu-performance-gates-v1/`.
Benchmark measurements and their conditions remain in those records and in
`vectors/riscv_csp/README.md`; this checkpoint introduces no new measurement.

Generated proof files, executable binaries, GPU libraries, raw memory spools,
and source tarballs remain local and are excluded from this commit. They
include multi-gigabyte interrupted block-run artifacts. Textual receipts may
reference these local artifacts; their inclusion does not imply a complete
published proof bundle.

The existing Cairo CPU and Metal qualification records predate this
checkpoint. They must be checked against the current source before relying
on them for the new Cairo/Starknet work.

## Checkpoint checks

The pre-commit checks were run individually on September 27:

- Staged whitespace check: failed, including preserved experiment logs and
  source whitespace.
- Zig format check: failed; 88 paths were reported.
- Source conformance: failed with 143 reported errors.
- Source conformance checker unit tests: 31 passed.

Commit and push hooks were bypassed for this explicitly requested paused-work
checkpoint. The pre-push hook would otherwise start the broad affected-lane
build and qualification process. No full proof, build suite, or hosted CI
qualification was performed for this checkpoint.
