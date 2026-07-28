# Session 01: FRI inverse routing from the twiddle tower

## Why this remained distinct

The literature search suggested cache-hot fold-to-hash handoffs and batched
folding, but current main already contains broad FRI scheduling work. Source
inspection identified one repeated scalar preparation that remained: each
line-fold layer fills the same bit-reversed coset x-coordinates and computes
their inverses even though the twiddle source retains a canonical inverse tower
for the same circle-domain family.

The earlier candidate established the exact index relationship empirically:
for folded half-length `h`, the required inverse coordinates equal the tower
slice starting at `T - 2h` and ending at `T - h`. This removes a fill loop and
the serial dependency chain in batch inversion. The mechanism was replayed
onto the current frontier rather than trusting its old commit or measurement.

## Rejected broader changes

Reordering folds, changing Merkle handoff, or regenerating a specialized tower
were rejected because they increase proof and ownership risk. Copying the slice
was also rejected; the scheme already owns the tower for the full operation, so
a borrowed immutable slice is sufficient. The original fill-plus-inverse path
is retained as a fail-safe for callers without a matching tower.

## Correctness reasoning

The optional slice is threaded from the PCS scheme through lazy FRI commit into
`FoldLineWorkspace`. Each layer checks that the tower is long enough before
selecting its exact suffix-relative slice. All fold arithmetic, query order,
transcript operations, and allocations outside the eliminated workspace remain
unchanged. The old path remains executable with a null preset.

## Current state

The branch changes four allowed source files, is based on
`cfd47be98a10598b90a898e787e5cd1c674b09e7`, and passed local policy and
correctness checks. Historical notes reported byte-identical digests and a
small deep-proof gain, but those are not current-frontier evidence. Hosted
qualification awaits upstream PR 118; no record is claimed yet.
