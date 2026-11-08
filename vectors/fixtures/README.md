# Maintained RV64 validation fixtures

These are test inputs, not current performance receipts.

- `rv64-d2-composed-v1/` is the complete frozen D2 parity and composed-cell
  package. The proof gate, basket and composed-cell regressions share its
  location through `scripts/rv64_validation.py`.
- `rv64-jobs-memory-policy-v1.json` is the committed allocation-policy fixture.
  Its package-owned layout test fails if it is missing.

`rv64-validation-fixtures.json` records every original path, byte count,
SHA-256 and Git blob. All 175 files were matched to the published archive
`archive/consolidation-20261108/worktrees/rv64-m8-gn-bind`, commit
`4a4d01bd5999bd6489fe71062c9e46ccdbcd73bb`, and moved without changing bytes.
The archive retains historical provenance; restoring old report directories
is not required to run these maintained tests.

Changing fixture bytes or fingerprints requires an explicit authority review.
A new performance receipt cannot replace the frozen proof parity reference.
