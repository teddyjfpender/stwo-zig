# Native BLAKE3 query joins

Task: connect transcript query outputs, DEEP position/bit inputs and FRI query
bits/derived positions. Reuse canonical blake3_query_links and existing scalar
and field-byte AIRs, following the already-qualified fixture relation signs.
Exact role/index join, O(graph nodes + queries * (31 + layers)) work/storage.
Invariant: native transcript/plan query output schedules agree; operation domain
and ordered values match the DEEP position. All 31 bits match between graphs and
are Boolean. One canonical scalar position feeds DEEP and byte encoding; each
DEEP bit emits once for FRI in addition to arithmetic uses. Derived FRI positions
remain constrained by canonical FRI arithmetic. No values in fixed rows.
Qualification: real native capture, coordinate/value/multiplicity checks, missing
query output and altered query position rejection. Paths need extra direction
and projection reads before final parent materialization. No new algorithm,
cryptography or speedup claim.
