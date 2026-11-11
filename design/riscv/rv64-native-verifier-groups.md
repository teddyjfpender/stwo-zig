# Bounded native-verifier groups for OP CPU recursion

Status: first real execution-only grouped root and independent receiver pass.
A balanced nine-run controlled comparison is recorded. The existing leaf/fold transport remains
available and unchanged.

The current small OP execution root proves three native verifiers separately
and then proves a fourth circuit verifying their three outer proofs. That
last circuit repeats outer PCS, FRI and lookup verification. A group instead
appends the three existing native verifiers into one circuit context and makes
one outer proof. Native verification itself is not omitted or weakened.

## Authority and statement

A group admits at most four adjacent native workers. Its header contains the
16-byte `STWO/RV64/GROUP1` domain, first ordinal, member count, total execution
worker count, and each member's kind, ordinal, frame length and eight-word
frame digest. The digest wires are outputs computed by the corresponding
native verifier circuits, not independently guessed public words. The group
hash is the circuit's eight-word output.

A graph for a proper subrange is useful for experiments, but is not an execution
receiver. The current accepting grouped route requires first=0 and count=total
and refuses executions larger than four workers. It does not change the native
256-worker ceiling or pretend to support a large block via this path.

The receiver derives the complete native inventory, two-phase manifest, fixed
authority, member order, statement frames, numerical GKR receipt marginals and
RAM/KIO/Wire closure from its independently pinned request and native bundle.
It builds the group in trace-only mode, derives its own statement-specific
outer key, restores only an existing physical root, verifies it, and rechecks
closure. Missing proofs cannot trigger production. The new transport lives
under `recursion-group-v1`, separate from `recursion-om31/tree.json`.

This still needs the native bundle and statement-specific key reconstruction.
It is not portable constant-key admission, anchored derivation, an OD/OP join,
a checkpoint accumulator or a complete Solidity verifier. Security language
remains “128-bit target under documented assumptions”, with no certificate.

## Resource hypothesis

The real 120794432 D2 bundle's raw native-verifier rows are:

| Member | QM31 operations | Blake G gates |
| --- | ---: | ---: |
| CPU | 4,439,252 | 2,857,760 |
| Keccak | 4,085,155 | 2,283,120 |
| SHA-256 | 3,504,218 | 2,544,720 |
| Sum before group header | 12,028,625 | 7,685,600 |

The Blake component fits 2^23 rows, while the arithmetic component needs 2^24.
The actual combined graph may share constants and adds a small header hash;
only its measured geometry is authoritative. These counts do not establish
memory fit or wall time. Use the same live-budget admissions as the tree route,
record RSS independently, and keep the failed attempt if it cannot fit.

## Qualification gates

1. All native verifier types append into one context with original constraints.
2. Value and trace-only graphs agree exactly, with no receiver assignment.
3. Empty, oversized, skipped, duplicated, reordered and mixed-manifest groups
   reject; aggregate acceptance refuses incomplete execution coverage.
4. Complete real OP production, independently restarted receiver and exact
   expected 43-byte output.
5. Root corruption, changed native statements/claims, wrong profile and missing
   root reject without rewriting artifacts or generating a proof.
6. Measure complete recursion wall, user/system time, peak RSS, stages and proof
   bytes against the same native request and outer profile. Different group/tree
   proof bytes are expected because the verified statement and topology differ.

## Bounded composition review

- Coverage is receiver-derived: the accepting route fixes first=0 and count=total
  from the admitted complete inventory. A partial group graph has no acceptance
  API. No subset, reordered, duplicated or skipped worker can be substituted.
- A member digest is the output of the original CPU, Keccak or current V3 truth
  verifier. Those computed wires enter the group hash directly. Host-side frame
  hashing alone would be insufficient and is not the circuit construction.
- Every native proof is physically admitted under the same source-derived setup,
  profile, fixed authority and sealed two-phase manifest as the tree route.
- The root receiver authenticates canonical frame words and numerical receipt
  marginals, then closes RAM/KIO/Wire through the existing `services_root`
  authority. The CLI independently pins and checks the program's terminal output.
- The group domain, ordered member metadata and hash construction enter the
  receiver-derived circuit/key. No producer-supplied key or geometry is admitted.
- Fresh reception uses a trace-only graph with zero value-table capacity. Missing
  roots return before graph construction; no proving fallback or artifact write
  is available. A different outer profile derives a different authority/domain.
- Resource admissions remain the existing synchronized live budget and bounded
  recycler. Four members is a graph count limit, not an RSS promise. Large
  geometries may still fail cleanly, and executions above four workers are refused.
- Native and outer security constructions are unchanged. Fewer outer proofs do
  not by themselves certify a composed error bound. The larger arithmetic shape
  must remain within original field/mass/degree validation. Receipts continue
  to state the 128-bit target under documented assumptions and unqualified status.

First real qualification: 20.703 s complete recursion command, 2.926 s independent
fresh reception, 42,050,158,592-byte peak RSS and 783,396-byte root proof. Native
proving is additional. Both a modified physical root and a missing root reject;
the missing-root receiver does not create a proof. These are qualification
measurements; repeated balanced-order comparisons determine the performance claim.

Three cold trials per variant, balanced across run positions, give median
21.981 s grouped M7 versus 35.766 s M6 tree and 40.944 s compiled M7 tree.
Every fresh receiver accepts; all same-variant proofs match exactly. Peak RSS
increases to 39.16 GiB from M6's 27.34 GiB. Observable trial drift and the small
sample count remain explicit. Native proving is additional. The detailed
receipt is `vectors/reports/rv64-opstack-cpu-20261108/recursion-native-groups.json`.

## Optional GROUP2 arithmetic

The independently selected `structural-v1` policy has the `STWO/RV64/GROUP2`
header and separate `recursion-group-v2` transport. It specializes only immutable
zero wire identities. A guessed zero never selects a different topology. Full
OM31 multiplication uses four QM31 products, two additions and one fixed-u
product (seven rows), instead of native Karatsuba's nine circuit rows. Scalar
field arithmetic and the underlying QM31 gate constraints are unchanged.

The concrete lane policy is thread-local and scoped, with failure cleanup. The
legacy policy emits the original graphs and independently restores the existing
GROUP1 and M7 tree proofs. Real GROUP2 production and fresh reception pass;
10,757,366 active arithmetic rows still pad to 2^24, so no additional complete
wall-time gain is established. A bounded symbolic cache was tested and rejected
because its 5.87% hit rate did not change that geometry. It is retained as a patch
and receipt, rather than permanent cache machinery in the production lane.
