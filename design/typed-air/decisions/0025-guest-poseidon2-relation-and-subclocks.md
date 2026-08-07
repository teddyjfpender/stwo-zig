# ADR-0025 — Guest Poseidon2 relation, multiplicity, and shared subclocks

**Status:** accepted
**Date:** 2026-08-06

## Context

[ADR-0024](0024-guest-poseidon2-custom0-abi.md) fixes one guest-visible
`CUSTOM-0` instruction. One successful retirement snapshots sixteen canonical
M31 words, evaluates `riscv.poseidon2_m31.permute.v1`, and replaces those words
in place. It also fixes one pointer-register access at access phase `.first`
and sixteen distinct memory-word transitions at phase `.second`.

C-002 must now decide how the core invocation and specialized provider are
connected. Reusing the existing `poseidon2_io` relation would be unsafe: that
domain belongs to sparse-Merkle infrastructure and an equal 32-field tuple must
not let a guest request cancel an unrelated commitment event. Adding mode,
version, or call-ID fields to that tuple would also exceed the production
lookup entry's current maximum arity of 32.

The production convention is already precise. Each relation has its own
independent `(z, alpha)` pair. For tuple `(v_0, ..., v_{n-1})`, the denominator
is

```text
v_0 + alpha*v_1 + ... + alpha^(n-1)*v_(n-1) - z.
```

Typed role-signed liveness gives `request` and `consume` negative numerators
and `emit` positive numerators. Inactive rows contribute zero. Relation names
are metadata rather than lookup keys, and access ordinals are construction
metadata rather than denominator fields.

The shared memory phase also needs a proof, not an assumption. The current
soundness account requires strictly increasing clocks for successive accesses
to one `(address_space, address)` key. A same-key, same-clock transition can
cancel as a detached self-loop. On the other hand, clocks are not global event
identifiers: two different keys may have the same clock because the key itself
is in the seven-field `memory_access` tuple. The guest operation has exactly
that shape if alignment, non-wrapping addresses, and lane distinctness are
proved.

Finally, current production capacity and admission rules are base-profile
rules. The base relation registry contains exactly twelve domains, transcript
claims contain exactly 28 components, the memory coefficient guard assumes at
most three access edges per opcode, and the generic per-row lookup list holds
25 events. A guest call has 17 access edges and substantially more than 25
relation events once word canonicality is proved. Those facts constrain the
extension design and must not be hidden by widening base hot-path structures.

The audited source anchors are the typed
[`relation.zig`](../../../src/frontends/riscv/air/lang/relation.zig) registry,
production [`entry.zig`](../../../src/frontends/riscv/air/lookups/entry.zig)
event convention,
[`relation_challenges.zig`](../../../src/frontends/riscv/air/relation_challenges.zig)
draw order, [`memory_logup.zig`](../../../src/frontends/riscv/air/memory_logup.zig)
transition tuple, [`state_chain.zig`](../../../src/frontends/riscv/runner/state_chain.zig)
per-address tracker, and
[`statement_validation.zig`](../../../src/frontends/riscv/prover/statement_validation.zig)
coefficient guards. The conditional graph argument remains scoped by
[`SAIL_AIR_COMPOSITION.md`](../../../soundness/SAIL_AIR_COMPOSITION.md); this
ADR does not turn its randomized-LogUp or proof-system premises into theorems.

## Decision

Define one guest-specific, versioned, arity-32 function relation. Every active
core call emits one unit request and every active specialized provider row
emits one unit supply. Calls and supplies are duplicate-preserving rows, not
aggregated multiplicities. The extension uses the existing three access phases,
with all sixteen data-word transitions sharing `.second` only because their
memory keys are pairwise distinct.

This ADR accepts the logical relation and shared-clock argument. It does not
claim that the currently shipped base statement, registry, or verifier already
implements them. The activation blockers below are normative fail-closed
requirements for C-003 through C-009.

### Relation schema

The schema is fixed as follows:

| Property | Value |
| --- | --- |
| logical domain | `guest_poseidon2_io` |
| stable global schema ID | 12 |
| schema name | `stwo.riscv.guest_poseidon2_io` |
| schema version | 1 |
| relation ABI label | `guest_poseidon2_io_v1` |
| arity | 32 |
| fields 0 through 15 | `.felt`, input lanes 0 through 15 |
| fields 16 through 31 | `.felt`, output lanes 0 through 15 |
| allowed roles | `request`, `emit` |
| caller role | `request` |
| provider role | `emit` |
| access ordinal | forbidden |
| challenge convention | `stark_v_alpha_powers_minus_z` |
| multiplicity policy | `role_signed_liveness` |
| padding policy | `inactive_zero` |
| public boundary | none |
| coefficient authority | `statement_all_source` |

Schema ID 12 follows the base IDs 0 through 11 but is admitted only by
`rv32im-zkvm-poseidon2-v1`. The base profile's registry view still ends at ID
11. A base program, statement, artifact, prover, or verifier presented with ID
12 rejects it as unknown.

The extension relation gets a thirteenth independent challenge pair
`(z_guest, alpha_guest)`, drawn after all twelve base pairs. There is no
relation-ID, version, mode, pointer, clock, or execution ordinal in the tuple.
Domain/version separation comes from the typed schema, its independent draw,
the extension manifest, and the statement profile. This preserves arity 32 and
makes cross-domain cancellation with `poseidon2_io@1` impossible under the
same randomized-LogUp assumptions as the base relations.

The base-profile challenge type and draw path remain byte- and
schedule-identical. The extension invokes that same base draw under its
distinct transcript prefix, so its challenge values are deliberately not
expected to equal a base proof's values, and then uses a composed view
equivalent to:

```text
Poseidon2V1Relations {
    base: BaseRelations,                 // existing twelve pairs
    guest_poseidon2_io: RelationElements(32),
}
```

Construction first invokes the existing twelve-pair draw unchanged and then
draws exactly two secure felts for the guest pair. It must not resize the base
bulk draw and then assume the old transcript prefix stayed equivalent.

### Exact caller and provider events

For one active call with input `x[0..16]`, output `y[0..16]`, and Boolean
liveness `a = 1`, the core call component contributes:

```text
role       request
numerator  -a
tuple      (x[0], ..., x[15], y[0], ..., y[15])
```

The specialized provider contributes:

```text
role       emit
numerator  +a
tuple      (x[0], ..., x[15], y[0], ..., y[15])
```

Thus the guest-domain contribution for one honest call is exactly

```text
-1 / D_guest(x, y) + 1 / D_guest(x, y) = 0.
```

The caller event is emitted exactly once by the row that also proves the
committed custom instruction, `pc/clock` retirement, pointer-register read,
sixteen memory transitions, word/field conversions, and address derivations.
It is not emitted by the runner call buffer as an uncommitted side channel.

The provider row uses the authenticated 445-main-column compatibility mapping
for the canonical permutation. On every active guest row its fixed modes are

```text
enabler = 1
io      = 1
wide    = 0
```

and its interaction program replaces the legacy full-IO event with the new
guest `emit` event. The inactive legacy narrow, wide, and Merkle-IO events have
zero numerator and cannot cancel any guest event. Reusing main-column formulas
does not authorize reusing a relation domain.

The provider's direct constraints must establish function uniqueness: all
sixteen outputs are the exact result of the pinned semantic program on all
sixteen inputs. The relation only connects caller and provider; it does not by
itself prove that the provider function is Poseidon2.

### Canonical word-to-field binding

Each relation field on the caller side is bound to one four-byte memory word,
not obtained by unchecked M31 reduction. For bytes `(b0,b1,b2,b3)` in
little-endian order, an active caller row must:

1. request `range_check_8_8(b0,b1)` and `range_check_8_8(b2,b3)`;
2. request `range_check_m31(0,b3)`, proving `b3 < 128`;
3. prove the word is not exactly
   `(255,255,255,127)`, the byte encoding of `p = 2^31-1`; and
4. constrain the relation field to
   `b0 + 2^8*b1 + 2^16*b2 + 2^24*b3`.

The canonical non-`p` gadget uses the fact that `p = 3 mod 4`, so `-1` is not
a square in M31. Define materialized values

```text
s0 = (b0 - 255)^2 + (b1 - 255)^2
s1 = (b2 - 255)^2 + (b3 - 127)^2
nz = s0^2 + s1^2
```

and an inverse witness `inv`. Gate each materialization equality by `a`, require
all materialization and inverse columns to be zero on padding, and constrain
`nz * inv = a`. The gated quadratic equalities have degree at most three, and
the final inverse constraint has degree two. Under the byte and high-bit
checks, `nz = 0` if and only if the word is `p`; hence every active word is in
`[0,p)`. The implementation must pin an executable finite-field certificate
for the non-square premise and negative tests at `p`, `p+1`, `2p`, and
`u32::max`; prose is not sufficient activation evidence.

The gadget is applied independently to all sixteen inputs and sixteen outputs.
It therefore contributes exactly 64 `range_check_8_8` requests and 32
`range_check_m31` requests per active call before pointer/address-specific
range requests. These counts are statement coefficient inputs, not optional
optimizations. A later lower-cost canonical conversion requires a new reviewed
component version and equal or stronger mutation evidence.

### Duplicate, order, and multiplicity policy

Each successful custom instruction appends one call-buffer record and produces
one active caller row and one active provider row. For statement call count
`n_guest`:

```text
custom retirements
  = frozen call-buffer length
  = active caller rows
  = active provider rows
  = n_guest.
```

Liveness is Boolean. Every active caller and provider row has magnitude-one
multiplicity; no row stores an arbitrary scalar or integral count. Repeated
identical calls remain repeated rows, each with multiplicity one. The frozen
call-buffer order from ADR-0024 is the canonical witness order for both
components. No sorting, hashing, deduplication, run-length encoding, or tuple
aggregation is permitted in v1.

The guest relation is a multiset argument, so provider order is not a
mathematical soundness condition and no execution ordinal is added to its
tuple. Core retirement order remains bound by `registers_state`, program, and
memory relations. Canonical provider order exists for deterministic witness and
proof construction, diagnostics, reproducible parallel partitioning, and
mutation attribution; it must not be misdescribed as relation-enforced order.

Because each side has exactly `n_guest` unit terms and statement admission
requires `n_guest < p`, equality in M31 cannot hide an integer coefficient of
`p` identical calls. This coefficient lift remains conditional on the usual
randomized reduction from one sampled LogUp identity to exact tuple-wise
multiset balance.

### Padding and zero-call behavior

Active rows are a contiguous logical prefix of length `n_guest`; all remaining
rows are inactive padding. Preprocessed activity columns derive this prefix
from the statement rather than trusting a witness selector. Direct constraints
bind the committed enabler to that activity.

For padding rows:

- enabler, modes, tuple fields, call metadata, materializations, and inverse
  witnesses are zero;
- relation numerators are zero;
- the interaction generator does not invert a padding denominator; and
- every cumulative interaction column repeats its preceding value.

An extension-profile statement with `n_guest = 0` still contains both extension
component descriptors. Each has `n_rows = 0`, `log_size = 4`, its fixed v1
column count, sixteen all-zero main rows, and all-zero interaction columns and
claims. The thirteenth challenge pair is still drawn. Dynamically omitting the
components or relation draw would create a second transcript schema for the
same machine profile and is forbidden.

Zero calls do not turn an extension statement into a base statement. Only
`rv32im-zkvm-v1` owes byte identity to the current base transcript and proof
protocol. `rv32im-zkvm-poseidon2-v1` always binds its distinct profile,
30-component claim, extension manifest, and thirteenth relation draw, including
when `n_guest = 0`. The zero-call extension cohort measures that deliberate
fixed overhead; it is never expected or permitted to be proof-byte-identical
to a base-profile cohort.

### Shared-subclock soundness

Let `c >= 1` be the instruction clock and

```text
A(c,i) = 4*(c-1) + i + 1,  i in {0,1,2}.
```

The custom instruction uses:

- pointer-register access group ordinal 1 at `.first`, clock `A(c,0)=4c-3`;
  and
- lane groups 0 through 15, each with access ordinal 2 at `.second`, clock
  `A(c,1)=4c-2`.

Each access group is an adjacent `memory_access@1/consume`,
`memory_access@1/emit`, and `range_check_20@1/request` triple with one shared
one-based access ordinal. The consume tuple has the previous clock and value;
the emit tuple has the derived current clock and next value; the range request
is `current_clock - previous_clock - 1`.

The sixteen data keys are pairwise distinct. ADR-0024 gives a four-byte-aligned,
non-wrapping 64-byte span, so addresses `ptr + 4*lane` differ as ordinary
integers for lanes 0 through 15. All have `address_space = 1`. The pointer key
has `address_space = 0`, so it is distinct from every data key even if the
numeric register index equals a data address.

For any one of these keys there is at most one real access in instruction `c`.
Its preceding real access occurred in an earlier instruction. The largest
possible clock in instruction `c-1` is

```text
A(c-1,2) = 4c-5,
```

which is strictly less than both `4c-3` and `4c-2`. A first access has public
or committed predecessor clock zero. Long gaps retain the existing per-key
synthetic bridge chain, whose final predecessor is still strictly below the
real access and whose residual shifted gap is in `range_check_20`.

Therefore every edge is strictly increasing for its own key. Sharing
`4c-2` across different keys cannot form the same-key self-loop excluded by
the offline memory-consistency lemma: address space and address are fields 0
and 1 of every seven-field denominator. No semantic order among the sixteen
lanes is claimed or needed; the direct component consumes all sixteen prior
values as one snapshot and proves all sixteen next values simultaneously.

This argument does not permit two accesses to one key at `.second`. The typed
effect-group validator must allow a repeated ordinal only for this statically
fixed lane group after proving address distinctness, and must reject duplicate
lane indices, misalignment, wrapped derivations, or an address mutation that
aliases two lanes. A generic relaxation from “ordinals are unique” to “ordinals
may repeat” is unsound.

The clock stride, maximum clock, predecessor decomposition, bridge step, and
reserved fourth residue do not change. The existing soundness text and
certificate that say every access in one instruction has a distinct clock must
be refined to the actual invariant: successive accesses to one key are
strictly ordered; a reviewed fixed group may share a phase only across proved
distinct keys. This certificate update is an activation blocker, not a reason
to weaken the relation.

### Coefficient and cardinality admission

The current memory all-source bound is insufficient for the extension. Let:

- `n_base` be active base-profile opcode rows;
- `n_guest` be active custom-call rows;
- `n_clock` be real synthetic clock-update rows;
- `n_memory[j]` be active RW-memory boundary rows in shard `j`; and
- `p = 2^31-1`.

Every base row contributes at most three access edges. Every guest row
contributes exactly seventeen: one register read and sixteen data transitions.
The extension statement must perform checked `u64` arithmetic and require

```text
3*n_base + 17*n_guest + n_clock + sum_j(n_memory[j]) + 2 < p.
```

Equivalently, because `total_steps = n_base + n_guest`, it may check

```text
3*total_steps + 14*n_guest + n_clock + sum_j(n_memory[j]) + 2 < p.
```

The final `2` retains the conservative public memory-tuple collision bound.
Using the base expression `3*total_steps + ...` for an extension statement is
an admission error.

The statement also requires:

```text
n_guest < p
```

for each side of the guest relation. For every fixed lookup-table domain `d`,
the authenticated call-component plan must pin an exact maximum `q_d` of live
requests per guest call, and admission must require

```text
base_source_bound[d] + q_d*n_guest < p.
```

This includes `q_range_check_20 = 17`, the canonical-word counts fixed above,
and all pointer/address requests fixed by the accepted call-component plan.
Counters currently accumulate modulo M31; a modular counter is not a substitute
for this checked ordinary-integer bound. Any missing `q_d`, arithmetic overflow,
or bound at or above `p` rejects the statement before the channel is touched.

### Statement and transcript binding

The base profile retains exactly its existing 28 component claims and twelve
relation pairs. The extension profile has an explicitly different statement
schema with these appended component slots:

| Index | Component |
| --- | --- |
| 0 through 27 | unchanged base component order |
| 28 | `stwo.riscv.guest_poseidon2_call.v1` |
| 29 | `stwo.riscv.guest_poseidon2_provider.compat-v1` |

The guest relation challenge is appended at relation index 12. No base index is
renumbered. A base statement uses the existing fixed-size claims and never
mixes extension zeroes; an extension statement uses a separately versioned
30-component claim.

Before any commitment, the extension transcript binds the machine profile,
extension-manifest digest, Poseidon semantic digest, relation schema ID and
version, component identities and versions, and statement schema version.
Before relation challenges are drawn, it also binds:

- `n_guest`;
- both extension descriptors' `n_rows`, `log_size`, and main/interaction column
  counts;
- total steps with `n_base + n_guest = total_steps`;
- the canonical active-prefix policy;
- the coefficient-bound certificate inputs and result; and
- the preprocessed and main commitments under that geometry.

The claim phase mixes one versioned 30-slot main claim in the order above, then
one extended shard manifest containing the base descriptors in their unchanged
order followed by the two extension descriptors, then the interaction proof of
work, the unchanged twelve base draws, and the guest draw. The interaction
claim lists the unchanged 28 base sums followed by caller and provider sums,
then binds all interaction-column log sizes before the interaction root. The
guest relation has no public compensation term; caller and provider must cancel
each other.

Prover and verifier independently reconstruct this data from the admitted
statement and allowlisted manifests. Artifact fields copied from the prover are
not authority. A profile, schema, component, count, log-size, column-count,
semantic-digest, challenge-order, or claim-order mismatch rejects before proof
composition.

### Fail-closed validation

Cold construction and statement validation reject at least:

- unknown or base-profile guest schema IDs;
- wrong schema version, arity, field type, role, access ordinal, or challenge
  convention;
- any caller role other than `request` or provider role other than `emit`;
- non-Boolean liveness, non-prefix activity, inactive real rows, or nonzero
  padding;
- a call count differing from custom retirements, frozen buffer length, caller
  rows, or provider rows;
- provider modes other than `(enabler,io,wide)=(1,1,0)` on active rows;
- a missing, duplicated, sorted-away, or aggregated call;
- noncanonical input or output bytes and any unchecked field reduction;
- aliased lane addresses, wrong lane stride, a pointer/value mismatch, a
  non-strict predecessor clock, or a wrong shared access phase;
- a missing relation challenge or denominator inversion failure on an active
  event;
- coefficient/cardinality overflow or a bound greater than or equal to `p`;
- component omission in a zero-call extension statement; and
- any statement, transcript, artifact, or product-capability identity mismatch.

Validation of static schema and event plans occurs once before row generation.
The hot witness and interaction loops consume authenticated numeric IDs, fixed
roles, fixed projections, and preplanned column offsets; they perform no name
lookup or dynamic schema dispatch.

## Unresolved implementation blockers

The decision is accepted, but production activation remains blocked by these
concrete source gaps:

1. The current registry and challenge structures are exactly twelve-domain
   base types. C-005/C-006 need profile-composed registry and challenge views
   while preserving the base types and draw path byte-for-byte.
2. Current statement and transcript claims contain 28 slots. A separately
   versioned 30-slot extension statement, artifact encoding, verifier
   reconstruction, and new-process validation do not yet exist.
3. `statement_validation.zig` still uses `3*total_steps` for memory coefficient
   lift. It must implement the 17-edge guest formula and per-fixed-table source
   bounds before admitting one guest call.
4. `lookup_entry.List` has capacity 25. A call row exceeds it even before all
   canonicality and address events are counted. The extension needs its own
   authenticated fixed event plan or a separately reviewed component split;
   globally enlarging the base stack object is not accepted.
5. The canonical word gadget, its materialized degree report, non-square
   certificate, and exact request-count manifest are specified here but not
   implemented or mutation-tested.
6. The production strict-clock certificate and composition document currently
   use a stronger blanket phrase requiring distinct clocks for all accesses in
   one instruction. They must encode and test the distinct-key phase-sharing
   rule, including a same-key counterexample and all sixteen honest lanes.
7. The ELF-derived RW interval policy used by ADR-0024 is not presently a field
   in the public statement. C-006 must either bind the admitted memory-layout
   identity or explicitly prove that committed-root membership is the complete
   verifier-visible policy. It may not claim interval enforcement that the
   verifier cannot reconstruct.

No blocker may be converted into a debug assertion, trusted call-buffer check,
prover-only validation, or silent fallback. If the component split needed by
blocker 4 changes relation events, row multiplicity, or statement geometry,
this ADR must be amended or superseded before implementation proceeds.

## Performance invariants and gates

- Base-profile registry, challenge draws, claims, decoder, proof geometry, and
  hot lookup-list capacity remain unchanged.
- The guest function relation adds exactly one logical term per active caller
  and provider row and one independent challenge pair. Version, mode, pointer,
  and ordinal do not inflate its arity beyond 32.
- The provider uses the authenticated 445-column compatibility layout until a
  separately accepted measured layout supersedes it. No placeholder or H-010
  proposal becomes authority through this ADR.
- Shared phases retain the four-wide access clock and avoid changing every base
  predecessor bound merely to allocate sixteen globally unique lane clocks.
- Stable call order permits contiguous, disjoint worker ranges after freeze.
  Parallel generation does not sort, deduplicate, atomically contend on rows,
  or create nested pools.
- The base `MAX_ENTRIES = 25` container is not widened. The guest interaction
  plan uses exact compile-time event and batch counts and writes directly into
  preallocated final columns.
- Padding never evaluates denominators. Active loops allocate nothing after
  prepared capacity is available and contain no string work or per-call timer.
- Zero-call overhead, caller main and interaction cells, provider cells, 17
  access edges, 17 clock-range requests, 64 byte-pair requests, 32 M31 high-bit
  requests, materialization columns, total work, wall time, and peak RSS are
  reported separately.
- Any component split is compared by complete main/interaction cells,
  constraint degree, commitment/LDE work, quotient work, and critical path;
  reducing stack size or one phase cannot hide higher proof cost.
- No proving-speed or crossover claim is made until C-013 verifies every
  measured proof under the exact extension identity.

## Required negative evidence

The relation and subclock fleet includes at least:

- a base-profile proof and decoder rejecting the exact custom word and schema
  ID 12;
- a guest tuple offered on legacy `poseidon2_io`, and a legacy tuple offered on
  the guest domain, both failing to cancel;
- changed schema version, challenge draw order, arity, caller/provider role,
  sign, lane order, one input lane, and one output lane;
- omission of one caller or provider row, duplication of only one side,
  multiplicity two in one row, deduplication of two identical calls, and a
  forged execution ordinal;
- two identical honest calls retained as two rows and closing successfully;
- active rows after padding, a hole in the active prefix, nonzero main padding,
  nonzero interaction padding, and an active zero denominator;
- zero calls with both canonical log-four components and the thirteenth draw,
  plus rejection when either component is omitted;
- all sixteen honest addresses at one `.second` clock, followed by mutations
  to lane index, `+4` stride, address space, alignment, pointer, and one address
  that aliases another lane;
- a same-key same-clock self-loop, previous clock equal to or greater than the
  current clock, wrapped address derivation, and a missing clock-gap request;
- long-gap bridge chains for multiple lanes sharing the final `.second` phase;
- canonical words 0, 1, and `p-1`, and rejection of `p`, `p+1`, `2p`, and
  `u32::max` on every input/output conversion path;
- coefficient guards at the largest accepted value, exactly `p`, above `p`,
  and checked-`u64` overflow, including the historical insufficient
  `3*total_steps` formula;
- changed call count, component row count, log size, column count, profile,
  manifest digest, semantic digest, and artifact statement; and
- an independently recomputed domain-wise closure showing only
  `guest_poseidon2_io_v1` fails for each focused guest-relation forgery.

These are committed-witness and verifier-bound mutations where applicable. A
runner or honest-prover rejection alone does not demonstrate that a forged
proof row is constrained.

## Consequences

- Guest calls cannot cancel sparse-Merkle Poseidon events even when all 32
  values match.
- Unit duplicate-preserving rows make call accounting simple, deterministic,
  and naturally parallel without putting host ordinals into the proof tuple.
- The in-place ABI retains sixteen memory transitions and the existing clock
  stride, while its per-key strictness argument remains compatible with the
  offline memory graph.
- Word/field conversion becomes an explicit proof obligation instead of
  relying on the runner's canonicality check.
- Extension statements require a thirteenth relation pair and two appended
  component claims, but base statements and their transcript remain unchanged.
- The stronger memory and lookup coefficient guards reduce the maximum
  admissible extension geometry when necessary; sound integer lifting takes
  precedence over accepting a nominal maximum trace.
- The specialized call bridge needs a dedicated prevalidated interaction plan.
  This is more code than reusing the base 25-entry list, but avoids inflating
  every base opcode row's stack and validation surface.
- Acceptance of this ADR completes the C-002 design decision only. It does not
  mark C-003 through C-013 implemented, verified, performant, or production
  admitted.

## Rejected alternatives

- **Reuse `poseidon2_io@1`:** rejected because guest and Merkle events could
  cancel across semantic domains.
- **Add a domain, version, mode, or call ID to the tuple:** rejected because
  the full input/output tuple already has arity 32 and a distinct challenge and
  manifest provide cleaner separation without widening global lookup capacity.
- **Give both sides role `request` and hand-author one positive numerator:**
  rejected because it violates typed role-signed liveness and makes sign drift
  possible. Caller is `request`; provider is `emit`.
- **Aggregate duplicate tuples into scalar multiplicities:** rejected because
  it adds integer-range and overflow obligations, loses execution-local
  diagnostics, and complicates parallel ownership before evidence shows a
  benefit.
- **Sort or deduplicate the frozen buffer:** rejected because ADR-0024 fixes
  stable retirement order and duplicates are semantic multiplicity.
- **Put an execution ordinal in the relation:** rejected because deterministic
  function soundness needs tuple multiplicity, not provider ordering; the
  ordinal would increase arity and protocol cost.
- **Allocate seventeen unique subclocks:** rejected because it would change the
  global stride, predecessor decomposition, public clock validation, every base
  AIR family, and existing transcript evidence. The keys are distinct, so that
  cost supplies no memory-consistency benefit.
- **Allow arbitrary repeated access ordinals:** rejected because same-key
  same-clock edges admit the historical detached self-loop. Sharing is allowed
  only for the proved sixteen-address group.
- **Use one unchecked bulk-memory relation instead of sixteen
  `memory_access` transitions:** rejected because it would bypass the existing
  committed RW state chain and require a second memory-consistency proof.
- **Raise the base `MAX_ENTRIES` until the call fits:** rejected because it
  bloats every base row's hot stack/container for one extension component and
  still leaves physical interaction cost unaudited.
- **Omit zero-call components or the guest challenge:** rejected because it
  creates witness-dependent transcript schemas and ambiguous artifact identity.
- **Trust runner validation for canonical words:** rejected because a malicious
  prover controls committed field and memory values. The AIR must prove the
  injective word/field boundary.
- **Use the placeholder/example Poseidon implementation:** rejected because
  relation closure would then prove a function other than the semantic digest
  admitted by ADR-0024.
- **Treat one sampled LogUp equality as deterministic exact multiset balance:**
  rejected as an overclaim. The standard randomized-reduction assumption and
  coefficient/cardinality bounds remain explicit.

## Revisit when

Revisit this decision if the shared-key certificate finds an alias not covered
by the proof above, if the extension-specific call plan cannot fit accepted
degree or memory bounds, if C-013 shows relation or conversion overhead
dominates verified proving time, if a lower-cost canonical M31 conversion has
equivalent proof and mutation evidence, or if recursion introduces a reviewed
cross-proof relation summary.

Any change to domain ID, version, tuple order, roles, challenge order,
multiplicity, padding, zero-call geometry, or shared-subclock rule requires a
new extension statement and artifact version. An already admitted v1 proof or
binary must never be reinterpreted.
