# Join sparse alias consistency into the parent

Continue the sparse read-only consistency design. Current authoritative source:
blake3_opening_inputs uses actual projected rows to choose canonical scalar IDs;
blake3_query_links exposes authenticated boolean DEEP query-bit endpoints.
Inspection also found blake3_byte_route already defines general fixed affine
4x8 routing equations, though its convenience API only exposes byte selection.
Reuse those equations through an explicitly validated affine constructor; no
new AIR identity, copy of arithmetic constraints, or independent index authority.

For each verifier-known distinct column log and raw query, pack four selected
query bits at a time using existing QM31 packing, then accumulate their weighted
contributions into four index bytes through existing affine routing. Preserve
raw bit zero; output bit i>0 reads raw bit lifting-column_log+i. Share the final
index port across all columns with that log. Fixed schedules/read counts depend
only on geometry, not query values. O(q * distinct_logs * log_domain) preparation
and rows, plus O(columns*q log q) host sorting and O(columns*q) consistency rows.
This avoids repeating projection work for every column and never reduces a full
u32 index modulo M31. Existing DEEP constraints prove the source bits boolean.
Unused slots in the final four-bit pack repeat bit zero with coefficient zero;
all consumed reads still get exact multiplicities.

Each opening scalar becomes an independent private producer feeding arithmetic,
leaf encoding and the read-only input adapter. Each column has fixed table/chain
namespaces and exactly q sorted rows, with fixed-rank zero sentinel. Remove the
canonical-value hash map only as this replacement is joined to the complete
parent. Keep host validation as early admission, not circuit authority.

Validate geometry parity against native projected positions, fixed invariance
under changed queries/alias patterns, mutation rejection, and full parent proof.
Run only focused gates. No end-to-end speedup or reusable-key claim follows until
remaining production capacity/backend/key obligations are qualified.
