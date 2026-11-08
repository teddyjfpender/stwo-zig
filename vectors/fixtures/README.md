# Maintained validation fixtures

These are test inputs, not current performance receipts.

- `rv64-d2-composed-v1/` is the complete frozen D2 parity and composed-cell
  package. The proof gate, basket and composed-cell regressions share its
  location through `scripts/rv64_validation.py`.
- `rv64-jobs-memory-policy-v1.json` is the committed allocation-policy fixture.
  Its package-owned layout test fails if it is missing.
- `recursive/` holds the two pinned SegmentV2 tree admissions and their complete
  key/expected-statement closure. The original relative layout is preserved so
  neither admission bytes nor their embedded artifact hashes change.
- `rv64-foundations-v1/` retains the execution baseline and four pinned
  foundations inputs named by `conformance/rv64im-foundations-v1.json`.
- `rv64-profile-comparison-v1.json` is the verified-work input for profile
  comparison regressions; it is not a fresh execution result.
- `rv64-m3-basket-v1.json` supplies the fixed 15-block regression basket.
- `cairo-rust-reference-v1/` holds the independently qualified Cairo reference
  digests and root receipt consumed by the resident pipeline checks.

`rv64-validation-fixtures.json` records every original path, byte count,
SHA-256 and Git blob. All 209 files were matched to the published archive
`archive/consolidation-20261108/worktrees/rv64-m8-gn-bind`, commit
`4a4d01bd5999bd6489fe71062c9e46ccdbcd73bb`, and moved without changing bytes.
The archive retains historical provenance; restoring old report directories
is not required to run these maintained tests.

Changing fixture bytes or fingerprints requires an explicit authority review.
A new performance receipt cannot replace the frozen proof parity reference.
