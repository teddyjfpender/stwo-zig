# Release native commitment staging before core proving

Task: reduce live worker memory without changing proof arithmetic or ownership.
Canonical match: region lifetime shortening, a mechanical allocation-lifetime
change rather than a new proving algorithm. Current preparation hands off final
main columns; interaction outputs and lookup counters live in the request arena.

Source evidence: pcs/commit_ops.zig commit calls the borrowed column preparation
path, which duplicates column values into owned commitment storage. The universal
challenge bundle stores Elements inline (including alpha powers); providers and
components refer to that stack bundle, not temporary arena storage. After the
interaction commitment, no main/interaction descriptor or counter is read.

Transfer: reset request scratch at that last-use boundary while retaining the
exclusive workspace lease. Keep existing bounded idle retention and error cleanup.
Reject retaining commitment staging through core proving; it serves no remaining
consumer. Do not reset before commit or unlock the workspace early.

Prediction: lower arena capacity entering core proving, potentially lower worker
peak. Exact peak is conditional on commitment vs core phase maxima and allocator
capacity growth. This does not establish the cause of the earlier 100 MB delta.

Validation: measure arena capacity before/after commitment, test reset while leased
and reuse, then full diagnostic native proof/independent verifier, artifact/key
parity, two-request reuse and allocation ownership checks. No timing claim.
