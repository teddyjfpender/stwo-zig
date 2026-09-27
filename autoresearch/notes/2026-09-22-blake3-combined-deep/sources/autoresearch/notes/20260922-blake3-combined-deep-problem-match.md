# Join canonical PCS DEEP arithmetic to the combined BLAKE3 FRI proof

Task: constrain the native PCS quotient/DEEP answers in the same outer proof as
FRI arithmetic, paths and the PCS transcript. Reuse pcs_deep_circuit and existing
arithmetic lowering. The standalone fixture used an arbitrary point and a zero
placeholder seed; replace both with an explicit consistent non-base-field seed
and its canonical point. This is still a fixture input, not a full STARK OODS draw.
Exact mapping: verified capture's sampled values, queried values, raw queries,
DEEP randomness and answers -> existing canonical PCS graph -> shared arithmetic
components. Fixed fixture geometry [6,4], current-point samples, 17 queries.
Use separate circuit namespaces; FRI and DEEP answer inputs share the same public
statement values. Trace openings remain public until authenticated paths join.
Validation: actual native proof capture, changed sampled-value rejection by DEEP,
all four lowering lanes, exact combined wire ledger and full core verification.
No new quotient arithmetic, production profile or protocol/key change.
