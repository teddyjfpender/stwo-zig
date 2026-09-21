# Focused recursive-parent speed research: baseline

Three alternating CPU/Metal fresh-process samples use the exact producer binaries
from the qualified typed-recursion closure checkpoint. Each sample rebuilds only
the final parent of its retained eight-segment, 16-address tree. The producer
exits before standalone verification. All six key/claim/proof artifacts match the
archived qualification hashes. No production source or proof parameters changed.

Median instrumented process time: 9.754 seconds CPU, 6.782 seconds Metal.
Child PCS preparation: 2.311 / 2.328 seconds; authority construction accounts for
1.014 / 1.028 seconds and row construction for 0.837 / 0.841 seconds within it.
Tuple projection is 1.283 / 1.284 seconds. Typed interaction generation is
1.201 / 0.425 seconds. Nested timings must not be added together.

First research target: shared child PCS preparation. Inspect authority/profile
construction and selected-lane row materialization for repeated work. Preserve
independent child admission, canonical tuple/row ordering, rejection behavior and
owned lifetimes. Do not replace authenticated boundaries with unchecked getters
or introduce an unbounded/global cache.

Development loop: reuse pinned children and keys, build only the affected parent
producer, alternate baseline/candidate samples, and freshly verify identical
artifacts after every run. Run focused PCS/admission tests for a candidate; use
complete products and the ladder only when promoting a measured improvement.
This baseline is instrumented and has three samples per backend; it is not an
optimization result or a statistically established cross-backend speed claim.

`benchmark.py` records the local experiment recipe; it requires the retained
qualification binaries and child bundles named in `samples.json`. `samples.json`
contains exact commands, binary/log hashes and phase records. Per-sample verifier
receipts, raw logs and `phase-medians.json` are retained alongside it.
