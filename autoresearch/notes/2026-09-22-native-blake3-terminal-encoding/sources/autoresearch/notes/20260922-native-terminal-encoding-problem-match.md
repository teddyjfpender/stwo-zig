# Native BLAKE3 terminal coefficient encoding

Task: authenticate FRI terminal coefficient inputs through their canonical
transcript payload. Reuse existing scalar producer, QM31 pack, field-byte AIRs
and graph use counts. Factor common scalar-to-payload row construction from the
native sample/claim adapter to avoid a second implementation. Exact coordinate
join, O(graph nodes + coefficients) work/storage, no new cryptography.
Invariants: canonical FRI coefficient bindings, exactly one matching trusted/live
payload receipt, correct operation/source/shape, equality of all four coordinates,
source emission=graph uses+1, exact transcript word multiplicities. Fixed schedule
contains no coefficient value. Missing/mutated payloads reject.
Qualification: real native capture plus altered coefficient and omitted receipt
negative checks; existing native payload tests exercise the shared row constructor.
Complete native parent and public-boundary/query/path joins remain outstanding.
