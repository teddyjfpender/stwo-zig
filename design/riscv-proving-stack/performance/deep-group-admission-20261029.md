# Bounded DEEP grouping without a metadata cliff

Task: compute exactly the existing FRI quotient, including every physical sample weight, line term, periodicity correction and transcript order. No AIR or verifier change.

Measured source: immutable mixed421 binary 0aba83b8; 42.974s DEEP/FRI in the saved clean run. The diagnostic macOS sample at /tmp/v7-deep-profile-421-20261029/sample.txt starts 27s after launch and covers the full DEEP phase. It reports 27,361 top-of-stack samples in accumulateTile. atos inline frames place dominant addresses in accumulateLiftedRuns (lines 482–491), not coefficient folding (5 samples). This is attribution, not a clean timing result.

Canonical problem: grouped sparse weighted reduction followed by a repeated gather/broadcast. A group is exactly (sample batch, source domain, lift map). Field distributivity permits summing its members before broadcasting, without changing the quotient. Existing upstream Stwo numerator semantics: https://docs.rs/stwo/latest/stwo/core/pcs/quotients/fn.accumulate_row_partial_numerators.html . Local encoding research warns that cell savings alone do not predict time and recommends removing repeated memory/commitment work; its q8 results are not production qualification.

| Candidate | Relationship | Memory/work | Decision |
|---|---|---|---|
| Raise 1 MiB metadata cap | Same algorithm | More unbounded growth; cliff remains | Reject as the primary fix |
| Materialize every weighted group | Exact linear reduction | Potentially large additional domain planes | Defer until census supports a bounded cache |
| Indexed members plus partial admission by lifting reuse | Exact same grouping | 16 bytes/member instead of 32; retained metadata remains <=1 MiB | Select |
| Change encoding/FRI parameters | Different protocol | Requires new security qualification | Outside scope |

Selected transfer: replace duplicated source slices/coefficient copies with original immutable data pointers, one group-shared length, and checked u32 indices into existing contribution records. If the full group roster does not fit, increase the admitted minimum lift shift; columns below that threshold remain in the original direct path. Admission and direct exclusion use the same returned threshold. This preserves an exact partition, avoiding both omission and duplicate inclusion. Worker row ranges and bounded scratch stay unchanged, retaining existing four-worker execution.

Complexity: O(C*L) planning worst case for C contributions and at most L machine-domain levels; O(C) metadata bounded by the explicit cap. Group reduction arithmetic is unchanged, but repeated numerator writes scale with admitted groups instead of columns. The prediction is a substantial reduction on the measured cliff case; falsifier is unchanged dominant direct-column census or no complete-proof speedup. No speedup is claimed before measurement.

Tests: index/canonical range validation, exact membership and residual partition at budget boundaries, odd/tail lifted row comparisons, full original quotient differential tests and canonical complete-proof hash parity. All indexed storage borrows original plans until joined workers finish. Allocation remains charged to the request allocator. Open uncertainty: actual group distribution and how much work survives below the selected cutoff; record admitted threshold/counts before interpreting the final A/B.

Limit: partial admission is by complete lifting tier, not arbitrary individual terms. A single highest-reuse tier exceeding the indexed cap still uses the original direct fallback. The exact fallback remains correct; it is not a claim of a performance bound at every possible width.

Lifetime review rejected retaining an index into temporary flattened column headers: those headers are freed before lazy execution. The selected 16-byte member keeps the original borrowed data pointer and a coefficient index into the provider-owned sample plan; no extra header owner or uncharged retained allocation is introduced.

## Second measured step: exact member admission

The first canonical mixed421 candidate preserved the complete proof hash `c318d46ae02ac6b894c0353d9b6ea832d8ec8ddb3d9ad6aa245ed6c5507dafdd`. Its diagnostic census still showed 133,794 direct terms, with only 414,288 of 1,048,576 metadata bytes used: 25,781 grouped terms in 32 groups at minimum shift 11. The measured DEEP/FRI phase was 35.541 s against 42.974 s in the original control. Other simultaneously qualified source changes also improved the complete request, so its overall improvement is not attributed to this kernel alone.

Before implementation, the next selected algorithm was bounded sparse-group admission with an exact complementary index set. Admit groups in descending lift-reuse order, and admit a bounded prefix when the next group cannot fit. A contribution bitset is included in the same 1 MiB retained cap. During planning only, split each column's original contribution range into contiguous unselected runs. The existing tile workers then use those runs without a per-row selection check. All contribution occurrences remain either grouped or direct, exactly once. Canonical disjoint original ranges are checked explicitly to prevent a selection bit from collapsing duplicate occurrences.

This removes the whole-tier capacity cliff without increasing the cap or materializing extra domain planes. It keeps the earlier threshold implementation as a differential planning control. More compact structure-of-arrays member storage and weighted-domain caches remain alternatives; neither is needed to establish this exact partition and both require separate evidence about their memory/work tradeoff. New tests force partial admission within one group, noncontiguous direct runs from one column, malformed range rejection, and a 70,000-column bounded-versus-combined quotient comparison after temporary headers have died. Complete candidate speed and proof-byte parity remain pending for this second step.

## Explicit request metadata budgets (2026-10-30)

The next experiment keeps the existing 1 MiB default and exposes a finite CPU execution policy through `engine.pcs.DeepGroupBudget`: 1, 4 or 8 MiB. `CommitmentSchemeProver.deep_group_budget` passes the request's selection to lazy DEEP planning. Core PCS reads no environment variable for this policy and neither serializes it nor changes transcript/security parameters. Group members, group descriptors and the exact selected-contribution bitmap remain included in `retainedBytes()` and allocated through the original request allocator. This cap describes retained grouping metadata, not total proof memory or process RSS.

The existing 70,000-column differential gate now also requires the 4/8 MiB policies to admit every eligible term, remove their direct fallback and produce identical weighted quotient values to the combined oracle. The 1 MiB branch still checks exact partial admission. Default wrappers continue passing `one_mib` explicitly. The benchmark harness records the chosen policy separately; no default promotion or speed claim follows from increasing the budget alone. Complete same-workload proof-byte equality and controlled timings are required.
