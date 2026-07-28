# Session 01: fourfold extension layer skipping

## Mechanism selection

The broad FFT literature search surfaced batching and locality ideas, but most
general fusion was already represented in main. A narrower algebraic case
remained in coefficient extension: the code recognizes a twofold extension and
skips its one degenerate largest-block layer, but a fourfold extension still
materializes three zero quarters and executes two layers whose outputs are
known duplications.

This candidate replays the previously isolated fourfold mechanism onto the
current frontier. It was kept separate from batched radix-8 twiddle reuse so
each remote record has one interpretable cause and can be rejected
independently.

## Correctness reasoning

With only the first quarter populated, the largest-block butterfly sees a
nonzero lower half and zero upper half; the next layer repeats that structure
within both halves. Neither result depends on the skipped twiddles. Copying the
first quarter into the other three therefore produces the exact state that the
ordinary transform would have after two layers.

The implementation records `extension_layers` rather than a Boolean, selecting
the existing twofold path for one layer and the new fourfold path for two.
Grouped batches use the fast path only when every member has the same exact
geometry. Otherwise they explicitly zero the unwritten tail and run the
ordinary transform. Backends that require materialized extension zeros receive
the correct initialized length derived from the layer count.

## Falsifiers and current state

Randomized differential tests compare explicit zero padding with the new
scalar and batched paths across domain log sizes 5 through 12. Remaining
falsifiers are proof-byte drift, a failed Rust oracle, a resource regression,
or an insignificant whole-proof ratio.

The immutable branch touches three allowed source files, passes local preflight
and correctness tests, and is published on the participant fork. Hosted
qualification awaits upstream PR 118 because the canonical Ubuntu workflow
currently builds Metal before measurement. No benchmark or record is inferred
from the successful algebraic tests.
