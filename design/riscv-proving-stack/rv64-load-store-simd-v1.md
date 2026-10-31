# Load/store domain SIMD

This changes only the experimental closed load/store component's domain evaluator.
Sixteen logical evaluation rows use PackedM31 arithmetic for base-field identities
and PackedQM31 for challenge-dependent lookup equations and random accumulation.
The existing generic arithmetic-lane authority emits every residual in its original
order. OODS evaluation remains QM31. Layouts, masks, degrees, public statements,
claims, transcript and physical witness columns do not change.

The packed kernel loads contiguous current-row columns and gathers only the prior
main and interaction columns declared by the existing mask authority. It supports
partial groups, arbitrary bounded row intervals, fresh output and addition into
existing composition buckets. It validates all column lengths, coefficient count,
row bounds and quotient denominator count before any output write.

The component uses the existing domain-transform and joined parallel-row helpers.
Each worker owns a disjoint output interval and private stack scratch; it borrows
immutable columns, claims and challenges. Every wave joins before evaluation
buffers are freed. The same component adapter supports a serial packed fallback.
Worker stack admission remains the shared 256 KiB minimum in optimized builds.
There is no new machine factory, protocol version or public representation mode.

Tests retain the independent scalar QM31 loop as an oracle for the complete packed
row kernel, including all three component kinds, previous-row wrap, denominator
halves, nonaligned tails and additive output. Existing arbitrary-QM31 cubic and
per-residual packed/scalar tests remain. The complete q70/P26 proof is compared
between serial and four-worker evaluation and against the retained scalar proof;
a separate receiving process verifies the durable artifact. These are functional
checks, not an isolated performance measurement. The component remains a closed
finite-image LS/RAM experiment with no CPU, service or Ethereum execution claim.
