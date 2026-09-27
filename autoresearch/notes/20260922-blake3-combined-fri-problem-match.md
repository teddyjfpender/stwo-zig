# Combined canonical FRI arithmetic and BLAKE3 paths

Task: prove all captured FRI opening values privately in the same outer proof as
canonical FRI arithmetic. Use the existing typed wire component's independent
constraint-enable and emission-weight fields: private producers emit main-column
values with fixed multiplicity and no public value anchor. Hash paths authenticate
these values; they are not unconstrained public claims or zero-knowledge claims.
Map each canonical FRI authenticated input to one producer with graph reads plus
one packing read. Join packing, canonical encoding, complete folding subtree and
upper path for every layer/raw query. Other FRI inputs remain public auxiliary
inputs until transcript/PCS DEEP are joined. Existing arithmetic AIRs unchanged.
Canonical problem: exact DAG composition with conserved wire multiplicities.
Reuse all existing components; no new AIR/digest. Test roster becomes generated
instead of a fixed enumeration ladder. Inputs: actual fold4 BLAKE3 capture,
17 queries, 2 layers. Typed subtree hashes O(groups * (leaves + path depth)).
Validation: independently rebuild fixed columns without FRI value bytes, closed
combined ledger and complete core verification; false public input PP rejected.
No production suite transition, speed or security claim.
