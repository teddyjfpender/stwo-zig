# Native BLAKE3 opening scalar producers

Task: materialize scalar producer rows for every authenticated trace/FRI opening
input, joining arithmetic, canonical encoding and lifted alias consistency.
Canonical problem: exact set coverage of typed graph input roles. Derive eligible
DEEP queried-value and FRI authenticated-value nodes from validated graphs, then
consume every expected node exactly once from the path builder's source list.
O(graph nodes + openings) work/storage. Reuse scalar_wire_source and shared graph
use counts. Trace weight=arithmetic uses+encoding+readonly adapter; FRI weight=
arithmetic uses+QM31 packing. No new AIR, hashing or algorithm.
Validation: real capture, exact coverage and values, missing/duplicate/wrong-value
source rejection. Full native parent/root/nonce/public-boundary joins remain.
