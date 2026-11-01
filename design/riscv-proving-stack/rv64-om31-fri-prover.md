# Actual OM31 FRI prover qualification

The owned CPU FRI route now commits, folds, opens and independently verifies
all eight coordinates of OM31. This is a numerical/protocol building block;
it does not select OM31 in the Ethereum driver or certify whole-protocol
128-bit security. Qualification receipts are in
`vectors/reports/rv64-word16-execution-20261101/om31-fri-prover-v1/`.

The explicit route is:

```
const F = prover.fri.ForField(OM31);
const Backend = cpu.Om31FriBackend;
const Prover = F.FriProver(Backend, Hasher, MerkleChannel);
const Column = prover.secure_column.SecureColumnByCoordsFor(OM31);
const Verifier = core.fri.ForField(OM31).FriVerifier(Hasher, MerkleChannel);
```

The existing QM31 public functions and types remain facades of the same
field-selected implementation. Backend line evaluation and host coordinate
planes select the field explicitly. Four consecutive secure evaluations form
one packed leaf for multi-fold rounds, so its coordinate width is 16 M31 words
for QM31 and 32 for OM31. Coordinate ordering is evaluation offset followed by
field coordinate, matching the core wide receiver.

The OM31 CPU adapter advertises the existing M31 Merkle operations and no
legacy QM31-specific fold hooks. Folding uses the core OM31 authority; a full
legacy CPU backend cannot be reinterpreted as an OM31 folding implementation.
The wide lazy-quotient route is a separate integration gate until its provider
is selected through the explicit PCS family. The owned route transfers its
input column to `commit`, and `decommit` consumes the committed prover.

Allocator-failure qualification found two inherited cleanup defects. A failed
first-layer commitment did not release its transferred input column. More
seriously, the multi-fold core could reallocate a buffer, then fail on a later
fold while its caller retained the original pointer. It now grows workspace
before mutation, folds into prefixes without intermediate reallocations, and
performs one final resize. Failure retains the original allocation and original
slice length for cleanup; contents may have been folded and must not be reused
as an unmodified input. This is ownership atomicity, not value rollback.

Tests exercise a nonconstant low-degree polynomial with all eight coordinates
nonzero under fold steps 1 and 4, fresh verifier replay, high-coordinate leaf
and terminal mutations, changed transcript, removed inner layers, and all
allocation failures. Existing QM31 native tests also pass. The captured
historical LS20/tail18 proof remains exactly 381,800 bytes with its previous
SHA-256 and is accepted by a separately launched native receiver.

The wider field alone does not address all soundness terms. The complete
migration must bind the field and channel identity through PCS, composition,
OODS/DEEP, every lookup relation, global memory and recursive verification,
with a reviewed whole-protocol budget. These tests make no speedup or whole
128-bit security claim.
