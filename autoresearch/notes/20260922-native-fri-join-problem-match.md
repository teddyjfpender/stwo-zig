# Native BLAKE3 FRI arithmetic and DEEP-answer join

Task: evaluate native BLAKE3 capture using canonical FRI arithmetic and route each
DEEP answer coordinate exactly once into FRI. Reuse existing FRI capture owner,
FRI graph, terminal binding join, scalar-wire AIR and graph use counts. No new
cryptography or arithmetic. Derive fold widths from configured degree transitions,
not proof-supplied widths; verify capture matches. Complexity: existing graph
compilation/evaluation plus linear graph scans and O(queries) route rows.
Invariants: concrete verified native capture, validated DEEP graph/evaluation,
matching query/blowup configuration, fixed fold schedule, exact coordinate
identity and equality, source weight=DEEP uses+1, FRI weight=FRI uses.
Qualification: actual native capture; changed DEEP answer and terminal coefficient
rejected by canonical FRI graph. Fixed rows exclude values. No speedup claim.
Remaining: transcript challenge/query links, terminal encodings, Merkle paths,
public-boundary authority and complete joined native parent proof.
