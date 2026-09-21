# Streamed tuple projection qualification

Parent profiles identified source-tuple projection at 1.7–1.9 seconds per parent;
Poseidon/range interaction generation together took about 12 ms. This change
targets the measured projection cost.

The admitted relation evaluator now streams selected, nonzero tuples directly
to the ledger. It no longer materializes a full array of diagnostic entries or
zeros unused tuple tails before discarding inactive events. The diagnostic API
remains available, and the legacy audit helper delegates to the same owner.
Event order, signed weights, tuple arity, canonical SHA-256 grouping, domain
selection and allocation-failure handling are preserved.

Eight focused tests pass, including exact comparison with diagnostic entries
across all 29 parent AIRs, zero rows and domain masks, plus malformed range
requests, cancellation and sticky allocation errors. All 14 ownership checks pass.

Three alternating instrumented fresh-process samples per version over the same
admitted 16-address eight-segment root give median source projection
1.735211 -> 1.250026 seconds (28.0% lower), and complete parent process time
7.099727 -> 6.682932 seconds (5.9% lower). Every benchmark proof was freshly
verified and its key, claims and proof bytes equal the retained baseline.
The first new-process sample was slower overall; medians summarize the three
samples and are not a large statistical study. Raw logs and receipts are retained.

The separate uninstrumented complete four-segment CPU/Metal/AOT gates pass all
384 cases. All 21 serialized artifacts equal each other and the canonical
baseline. Single observations: CPU leaves/parents 33.806/31.664 seconds, peak
RSS 3.898 GB; Metal 26.050/21.859 seconds, peak RSS 4.393 GB. These production
times exclude compilation, lock waits and hostile verifier cases.

This qualifies the optimization on these development workloads. It does not
establish production security, Ethereum readiness or equivalent speedups for
unmeasured workloads. The source snapshot and patch bind the qualified revision
before subsequent documentation edits.
