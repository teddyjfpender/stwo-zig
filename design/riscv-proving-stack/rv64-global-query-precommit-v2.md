# Global query precommit memory contract (design, inactive)

The qualified three-worker register-only fixture retains full CPU main PCS
owners until the complete Manifest seals. This is sound for that bounded toy
profile; it is **not a memory-bounded Ethereum worker fanout implementation**.
The proof-producing harness is one process and makes no scheduling speedup claim.

At about104 million padded CPU rows,44 main columns alone represent about18.3GB
of M31 source cells. A46-column profile is about19.1GB. Those figures omit PCS
coefficients, Merkle nodes, metadata, local tables, other providers, interaction
construction, FFT/composition scratch, and concurrent proof owners. Releasing the
original source matrix after commitment does not release the retained PCS tree.
Limiting active stage-two workers cannot solve stage-one residency: the barrier
requires every participating root before *any* shared challenge is available.

## Admission before a wider activation

A retained-owner implementation must admit the complete resident stage-one plan,
not just one job's source width. Its estimate and measured telemetry must cover
all CPU/query/provider owners, shared immutable trees counted once, actual cache
lifetimes, narrow witness storage, and one stage-two peak at the selected worker
limit. If the complete plan exceeds the host budget and no qualified spill or
reconstruction path exists, fail with an admission error rather than describe
queueing alone as bounded fanout. Actual whole-job measurements, disk work, and
all physical proof components must enter the cost comparison.

## Physical projection candidate

The global relation needs all query tuple coordinates AND their weights/counts
committed before its alpha. It does not require every unrelated execution/helper
column to be committed at that point.

An explicit future layout can split a CPU's physical main across a precommitted
query tree and a later execution tree. For FUNCTION13, the query projection has
payload13 plus its committed unit/Boolean weight. If the CPU reads these SAME
physical columns at the same row geometry, its execution equations can consume
them directly: there is no second operand copy and no host equality claim. The
remaining execution columns may commit later, before independent fresh local
challenges and constraint coefficients. Global claims must be computed from the
pre-alpha physical projection, never from unconstrained later copies.

If packed subtrees use different heights/order or live in separate physical
proofs, an actual fresh-challenge local lookup/permutation relation must join the
CPU-emitted tuples/weights to the precommitted projection. Both roots must enter
that local transcript before the join challenge. Root metadata equality,
native journals, or a claimed rational equality do not establish this join.
A standalone query proof must authenticate its own positive weights and close
all global physical claims. Extra duplicate tuples, prefixes, joins and padding
must be counted; a projection is not automatically a total-proof improvement.

Pure functional truth facts may be reused: their global op IDs and operand/
result coordinates define semantics without a CPU ordinal in every tuple.
Memory/delegation is different. Its projection must bind namespace, owner/time
origin, full addresses/values, rights and weights. Physically unique init AND
teardown, strict time/order and complete coverage remain necessary. Global RAM
and its64-bit timestamp schema are unsupported by the qualified execution
aggregate. Local register clocks still have their existing24-bit cap/reset rule.

The new unified FUNCTION challenge API must remain neutral about whether the
pre-alpha shared tree is the full main or a qualified projection. Its schema and
expected geometry identify the precommitted data; actual proof verification must
then enforce whichever physical split/join protocol that version specifies.
The API must not accept post-alpha CPU fields as global inputs merely because a
caller labels a root a projection. Oldv1 proof/tree layouts remain unchanged.

## Durable storage alternatives

A spill contract must retain enough canonical PCS material to restore the actual
precommitment and opening authority, with checked counts/bytes, durable identity,
ownership, and exact root verification before stage two. A native packet SHA is
corruption/job identity only. It cannot replace the precommitted PCS root.

A deterministic reconstruction contract could rebuild a projection from the
already captured immutable native advice and require the ACTUAL rebuilt root to
match the Manifest before interactions. This does not re-execute the VM, but it
repeats projection/FFT/Merkle work; that repeated work and IO must be measured.
Fresh worker challenges cannot authorize changing the precommitted tuples or
counts. Silent fallback to an arbitrary new root is forbidden.

Neither storage alternative is implemented or promoted by this document. Their
failure/retry barriers, disk corruption/size caps, challenge binding, source
lifetimes, and whole-job cost need dedicated qualification before production
activation. The existing root-chain prover remains the control.
