# Direct-original recursion checkpoint — 30 October 2026

This checkpoint preserves the lab's RISC-V proving architecture, CPU/CUDA work,
qualified direct-original recursion, benchmark collectors and research evidence.
The user requested stopping here and committing the work. The complete retained
139,214,856-instruction block root remains unfinished.

This is a checkpoint branch, not a main-branch merge. Repository-wide source
conformance still reports file-size/layout debt; its baseline was not changed.
The failure is recorded under `campaign/qualification/checkpoint-20261030/`.
Formatting, changed-Python syntax, diff whitespace and credential-pattern checks
passed. Commit/push hooks are overridden for this checkpoint: the commit gate
requires source conformance, and the push gate requires a clean tree despite the
large raw local artifacts intentionally being retained outside Git. No claim
that the entire repository test suite or publication gates pass is made.

## Qualified execution-to-root architecture

The new path verifies original execution, bridge and compact-memory STARKs in
one circuit, closes their exact endpoint/CPU/global relations, and reduces
window proofs through a homogeneous circuit fold. It does not produce or read
the former intermediate NativeParent window proofs. Canonical public metadata
comes directly from original bundles. The receiver independently reconstructs
expected keys, checks ordered coverage and CPU/snapshot adjacency, and selects
the initial-input and terminal-output policies from external pins.

Original opening arithmetic now groups structurally equal sample points while
preserving transcript order, response weights and nonzero constraints. This
changes the direct-original circuit key identity to version 2 with a GDP1 marker.
The older standalone PCS and NativeParent wrapper retain their original path.

## Measured results

All rows below use 70 queries and 26 PoW bits, CPU ReleaseSafe. They describe
different scopes and must not be added together or treated as full-block times.

| Scope | Workers | Production | Proving + serialization | Fresh verification | Memory |
| --- | ---: | ---: | ---: | ---: | ---: |
| Saved six-cycle SHA/Keccak mixed fixture, ungrouped | 1 | 139.907 s | 120.805 s | 16.817 s | 38.423 GB charged peak |
| Same saved fixture, grouped | 1 | 64.503 s | 57.312 s | 5.777 s | 20.790 GB charged peak |
| Actual retained 1,048,576-instruction window, 507 Keccak / 66 recovery calls | 16 | 34.276 s | 26.377 s | 5.393 s | 39.737 GB RSS |

The mixed-fixture pair is one diagnostic A/B, not a repeated median. Grouping
reduces its padded variables from 71,303,168 to 46,137,344 while leaving BLAKE3
G work unchanged. The actual retained window is interior and checkpoint-bound;
it proves neither the skipped prefix nor a whole block. Its saved-originals
gate took 43.50 s including loading, metadata, census and fresh verification.
Earlier execution and original proving are excluded from those production times.

The complete original-only driver also passed a seven-instruction fixture with
three initial/middle/terminal windows and two folds. It took 169.692 s from saved
originals to a freshly verified root; no original proofs were regenerated. That
fixture exercises the complete driver and boundary protocol, not block scale.

## Validation and artifacts

- Four grouped-DEEP gates compare native, original and grouped answers, strict
  QM31/NoValue topology and preprocessing, and malformed/degenerate inputs.
- The grouped mixed proof and original-only complete driver passed 15 tests,
  with five unrelated opt-in gates skipped.
- The actual retained window passed all eight tests in its focused gate.
- Proofs, stage profiles, hashes and reports are under
  `campaign/qualification/new-direct-original-window-grouped-q70-v1/`,
  `campaign/qualification/new-direct-original-block-driver-grouped-q70-v1/`, and
  `campaign/qualification/new-direct-original-retained-window4-q70-v1/`.
- `scripts/v8_direct_original_results.py` validates artifact structure and hashes
  and emits node/stage CSVs. It does not replace cryptographic verification.

Build the focused gates using the standard package identities:

```sh
python3 scripts/zig_serial_build.py \
  --lock /tmp/stwo-zig-integration-build.lock \
  --build-file build_riscv_circuit_recursion_v1.zig compile \
  -Dtest-root=src/riscv_circuit_originals_test_root.zig \
  '-Dtest-filter=RISC direct original' -Doptimize=ReleaseSafe -j1 \
  --prefix zig-out/riscv-direct-originals
```

The opt-in retained-window gate needs the externally pinned local corpus named
in `retained_qualification.zig`; enable it with
`STWO_RISCV_ORIGINALS_RETAINED_WINDOW_PROVE_Q70=1`. Choose a new empty output
directory with `STWO_RISCV_ORIGINALS_RETAINED_WINDOW_OUTPUT`. The large retained
execution checkpoints, full original corpus, build binaries and source archives
remain on disk rather than in this Git checkpoint. Compact evidence and small
qualification proofs are committed. No raw artifacts were deleted.

## Remaining work

The retained full-block harness is source-only and has not been compiled or run.
The old baseline stopped after 107 window roots and 25 of 106 folds; it has no
complete root. No full-block speedup or GPU result is claimed by these new gates.
Receiving still needs external checkpoints and instance-derived keys.

The next architectural issue is repeated key derivation: the current binary
107-window schedule implies 4,407 key constructions for 213 unique nodes,
including production and verification. This is a code-path count, not measured
runtime. An immutable, independently derived expected-key catalog would remove
repeated subtree compilation. Its implementation was not started before this
checkpoint.

The retained caller census identifies another large target: caller main and
arithmetic-interaction trees account for 85.5% of mixed columns and 91.1% of its
opening samples. Keccak rounds are already sequential; narrowing would require
lane/bit serialization with new state, lookup and call-boundary constraints.
Those are research directions, not implemented improvements. The Word16 work is
also local-algebra-only and is not integrated into the execution prover.
