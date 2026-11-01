# Joined numerator and denominator folds

An owned generic LogUp layer previously folded its secure numerator and denominator through two separate joined row scheduler calls. The new helper gives both disjoint planes to one row partition. Every output still reads its own old prefix and immutable half-offset suffix, through the original packed fold and scalar tail authority. No numerator-sized buffer, cache, or change to the sumcheck transcript is introduced.

The helper validates equal nonzero power-of-two shapes and disjoint owned address ranges before mutation. Both-borrowed aliases retain the immutable allocating path. If either plane is borrowed, the existing separate fold path remains. Fully owned planes use one joined row wave followed by the original two shrink-or-copy finalizations. A failed fallback allocation leaves independently valid owners for abort cleanup; lengths may differ and owned prefixes may already have changed. Retry is not supported.

The first multiplicity fold is intentionally unchanged: a base numerator must become secure, and preserving borrowed input and failure-atomic ownership while folding an owned denominator needs a separate consuming API integration. This slice targets the repeated secure folds only.

Qualification includes independent Q/OM scalar oracles over multiple sizes, a three-worker pool and held-lease serial fallback, malformed shape and owner overlap refusal before mutation, borrowed aliases, all fallback allocation failures, and old-source proof/artifact/next-channel-draw parity with independent terminal MLE verification. The fold-only benchmark records scheduler call counts by construction, not inferred hardware GPU launches or a whole-proof speedup. A one-worker or small task may make no worker-pool lease at all.
