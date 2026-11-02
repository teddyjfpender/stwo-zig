# Bulk GKR: bounded weighted OWNER and custody review

Scope: native bulk-only services extension on PR308 snapshot
`4e94b9dfc6efbd844b39645ee344c17479ba9b40`, merged at `93b6c2928`.
This review closes the bulk worker gates; it does not admit SHA/arith/curve,
sponge, LS-D64, byte-pair CPU, throughput Keccak or log-23 GKR layouts.
The complete Ethereum v3 candidate still fails closed. This is an engineering
source review under documented assumptions, not independent certification.

## Protocol and receiver authority

The native worker roster and physical component plan now enumerate bulk kinds
from the admitted setup, in exactly the source column order. Each component
shares original MAIN, local Eq/prefix binding, and its own independently sized
RAM inverse/prefix trace. There is no additional proof per bulk role.

CPU statements append a domain-tagged projection of bulk geometry and request
counts only when bulk is present. The old v2 statement bytes stay unchanged.
The child uses the already qualified v3 tuple-origin and receipt domains.
Transport explicitly names `RV64-SERVICES-CPU-GKR-BULK-OM31-V3-1` and refuses
legacy-profile downgrade. The manifest still binds every independently derived
worker statement, fixed root, MAIN root and verified child receipt before the
shared RAM challenge. Individual valid components do not establish acceptance.

`execution.Inventory` retains the original independent program, image, rights,
public sorted/unique cells, initial registers/PC, epoch adjacency, exact step
coverage and terminal endpoint admission. The receiver reconstructs keys and
roles, verifies each physical proof, and only then sums physical RAM claims.
Changed declarations cannot silently rekey a proof. Unsupported new PR308 secp
row truths are rejected explicitly, including their `(log,0)` declaration.

## Weighted JUMPDEST support

OWNER19 has two disjoint tuple classes:

- Unit consistency: CPU/LS/service ownership and fixed bulk call/result tokens.
  Their signs are bounded separately below the M31 characteristic.
- Transition membership: first coordinate `TOKEN_JD_TABLE`, fixed support of
  33*256 = 8,448 transitions `(pending,byte,next,jumpdest)`. The jtab MAIN
  multiplicity is an arbitrary base-field weight; **its sum is not unit mass**.

The table tag is a fixed canonical value above 255, distinct from every other
bulk token (`bulk_memory/types.zig: TOKEN_*`). CPU operation values come from
the authenticated ROM (`word16_execution/tuples.zig:rom,owner`; local GKR
`fractions.zig:cpuFor`). Ordinary bulk tokens are fixed constants in
`bulk_memory/equations.zig:emitQueries`. The disjointness claim also relies on
the previously reviewed CPU/LS/service ownership authority; this is not a new
range-inheritance lemma for those components.

Every jscan table consumer has negative Boolean unit weight: `active` for
word zero, one of the seven constrained valid-word bits for the others
(`equations.zig:jscanValid,jscanConstraints`). MAIN checks continuation,
remaining words, pending-state adjacency and zero pending at each call start.
`tableTuple` fixes the tag. `source.zig:fixedFor` constructs table columns from
`types.zig:tableEntry,transition`, with padded rows repeating valid entry zero.
The fresh receiver's fixed-key construction authenticates those columns.

Consequently, an invalid transition tuple has only consumers with coefficient
`-k`, where `1 <= k <= consumer_mass < p`. No table multiplicity, however
chosen, can supply that tuple. Ordinary OWNER tuples cannot supply it either
because the tag classes are disjoint. After excluding tuple-compression
collisions, clearing the rational denominators gives a nonzero polynomial.
Its identity failure is covered by the existing random-challenge degree bound.
The argument needs no integer bound on the *sum* of provider multiplicities.

`source_bounds.CpuScope.owner_table` records that valid support and unit
consumer bound separately. Unit OWNER mass excludes the 64 transition queries
per scan row and excludes weighted jtab providers. All those denominators,
including padding, stay in `relations.owner.denominator_slots`. The existing
collision bound therefore includes cross-partition pairs; neither pole events
nor mixed-tag compression collisions disappear from the budget. A separate
partition counter with zero additional denominator slots avoids double-counting.

Physical source geometry is capped at log22 in this extension. Even the full
64*2^22 transition-consumer upper bound is below p; the combined scope is still
checked explicitly. The test rejects mass exactly p, checks 8,448 support
rather than padded table height, and verifies token-tag separation. Native
fixtures also pass the conditional lookup-only 128-bit source-budget check.
They use q12 correctness proofs: this is **not** a 128-bit PCS or composed-
security qualification, and `security_qualified` remains false.

## Retention and scheduling

Each current bulk Source copies the entire shard's call/word inventory.
`bulk_metadata.requestUpperBound` charges those copies per present role,
plus call-row and active-row maps and jscan pending bytes. JUMPDEST has at
most nine word records per scan row; unaligned copy's lead record is included
in `ucopy_rows`. Table-only metadata can all retire after the local child.

Phase-one-only fixed columns, U16/U8 histograms, and jtab multiplicity/inventory
are charged separately by `localUpperBound` and included in stage-one task
admission, also with deferred binding. They are not retained across the
manifest barrier. MAIN/coefficients and Merkle custody retain their existing
charges. Stage two needs only narrow durable RAM metadata and its bounded
inverse/prefix output and scratch. These are represented requested-byte bounds,
not whole-process RSS or allocator-capacity guarantees.

Tests compare every actual retired source payload to its request bound across
all nine kinds, reject a retained-byte cap before capture consumption, and
exercise every allocation failure in source construction followed by owned
MAIN transfer and idempotent retirement. Original source/capture inventories,
immutable setup and proof-engine scratch retain their separately documented
admission responsibilities.

## Qualification gates

The services workers prove all nine kinds through three complete two-shard
executions: aligned memcpy/memset+LS; unaligned memcpy/memcmp+LS; JUMPDEST whose
second epoch reads the first bitmap as code. Each uses parked MAIN, deferred
binding, two lanes and reversed stage-two order, then independent fresh keys
and a transport roundtrip. Receiver mutations cover changed RAM debt, swapped
shards, omitted bulk counts, profile downgrade and changed geometry/rekeying.

Three balanced attacks still produce individually valid component proofs:
forged copied data with a matching terminal word; stale source data with a
matching terminal word; and a falsified memset packet/fill. Every fresh
receiver rejects with `UnclosedGlobalGkrRam` after physical verification.
This is the required global-closure gate, not numerical claims alone.

The implementation remains subject to the repository's wider native security
assumptions and the separate full-v3 composed-budget review. Existing v2
compatibility, classic controls and PR308's own qualified paths must remain
part of integration checks. No GPU or recursion qualification is implied.
