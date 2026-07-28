# Session 01: batched radix-8 twiddle reuse

## Search rationale

Four Elicit searches were used as a discovery layer across FFT batching,
fixed-tree scheduling, FRI folding, and fine-grained parallel work. Primary
sources on FFT locality and fold-and-batch methods supported examining shared
schedule data, but the broad mechanisms were mostly already present on
canonical main. The surviving source-level gap was narrower: current
`evaluateBuffersTailLayers` loops over buffers and calls the same packed
three-layer forward kernel with identical domain geometry and twiddle slices.

## Alternatives and falsifiers

Changing radix, proof layout, inverse order, or transcript-visible data was
rejected because it would enlarge the proof-equivalence surface. A more general
multi-direction batch kernel was also rejected: inverse transforms have
different normalization and are not the measured duplication. The candidate
therefore hoists only the repeated forward twiddle loads and preserves each
buffer's existing butterfly sequence.

Falsifiers are any mismatch against independent transforms, changed proof
bytes, a regression guard above budget, or a paired result whose confidence
interval does not clear the significance rule.

## Implementation reasoning

For each fused three-layer group, the batch kernel loads the seven packed
twiddles once: one for the first stage, two for the second, and four for the
third. It then applies the unchanged tuple butterflies to every independent
buffer. The duplicated-half variant retains reverse group traversal and reads
the initialized lower half exactly as the prior per-buffer kernel did.
Randomized tests compare two distinct buffers at multiple stages and separately
check duplicated-half expansion.

## Current state

The immutable branch touches three allowed source files and passes ancestry,
mode, locked-tree, patch-size, and local correctness gates. It is published on
the participant fork. Hosted qualification has not run because the canonical
Ubuntu workflow currently builds the unrelated Metal group. Upstream PR 118
repairs that infrastructure. Until an attested paired S3 receipt exists, this
is a candidate mechanism, not a record.
