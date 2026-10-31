# State-derived byte canonicality: design review

Existing default profiles retain these ranges. The minimal opt-in v3 candidate
below has focused AIR and strong joined-proof qualification; signed-load
representation changes remain design-only. Native host checks and a successful
execution are not an argument for omitting a constraint.

## Conditional canonicality lemma

Treat the closed state relation as an integer multiset equality:

    event BEFORE + terminal sinks = event AFTER + initial sources.

All tuples include space, the complete byte address, clock, eight value bytes,
and R/W rights. Each enabled CPU/service event has unit weight; all enables are
Boolean. Initial register sources are receiver-owned canonical u64 values.
Initial RAM sources must come from the authenticated private CellTable/root
argument, not a host-computed rational target. Tuple compression and LogUp give
this equality with their usual soundness error, not deterministic equality of
one evaluated rational function. Fresh padded mass bounds below M31 are needed
so signed integer multiplicities cannot disappear modulo the characteristic.

For any event with after time T, the CPU equations reconstruct previous time P
and gap G from three BYTE-checked bytes each and require P+G+1=T. Both inputs are
below 2^24, so the sum is at most 2^25-1, below M31. The bounded native after time
is below 2^24. Consequently this is ordinary integer equality and P<T. See
`air/encoding.zig` wideClocks and `air/range/constraints.zig` clockRanges.
Service bridges must establish the same strict inequality for every RAM lane,
with their tick bound to the CPU service slot, rather than only a host clock.

Induct on event AFTER time T. Its BEFORE tuple has clock P<T. On the negative
side of the equality, this BEFORE occurrence must match either an initial
source at time zero, or an AFTER occurrence at P. Both have canonical value
bytes: the first by authenticated initialization, the second by induction.
Terminal sinks are on the same side as BEFORE and cannot supply a value.
For a read event, AFTER copies BEFORE. For a write event, its new value must
have a separate canonicality proof. CPU register writes retain result-byte
ranges; stores copy canonical B bytes and preserved BEFORE bytes under Boolean,
one-hot byte offsets. Keccak/secp outputs retain their own bit/byte proofs.
Thus all event BEFORE and AFTER value bytes are canonical. The argument does
not require unique AFTER timestamps, although uniqueness/alias rules remain
necessary for architectural execution semantics.

The lemma can remove redundant value-range checks only. It cannot justify
omitting canonical addresses, bounded clocks, output ranges, memory policy,
unit weights, state closure, root authentication, or disabled-word zero gates.
A Boolean ROM opcode selects canonical B or a ROM immediate for RHS; this is
an additional argument, not a consequence of the state tuple alone.

## Required authority and admission gates

1. Exact global closure includes CPU, every enabled service bridge, private RAM
   CellTable, and the independently expected register delta. No private host RAM
   target is accepted. All absent roster claims are constrained to zero.
2. Initial CellTable values reach the before root through unit-flow chunk/node
   buses: bounded descending heights, canonical child positions, unconditional
   before output for every reused side digest, no free multiplicities, and
   fresh mass below M31. An orphan before side cannot mint an after source.
3. Every event producer proves P<T, including all 25 Keccak lanes and secp
   packet lanes. Check inactive padding, max ticks, repeated/aliased reads,
   services sharing slot3, and clocks rebased at batch boundaries.
4. Initial values are independently derived from expected ELF/input/zero RAM;
   preceding batches' accepted after root becomes the next before root.
5. Register result, service result, address and carry ranges remain anchors.
   All word-disabled zero identities remain. One-hot selectors and offsets
   remain proved, including selectors forbidden by the public opcode policy.
6. A new profile/version selects changed columns, queries, constraints and
   degree bounds equally at domain/OODS. No claim of polynomial/proof-byte
   equivalence to the old range-complete profile is made.

## Mandatory counterexamples

* Two unrooted transitions (t1,x)->(t2,y), (t2,y)->(t1,x) close as multisets
  with unique after times. They can carry nonbytes. Strict order rejects one.
* A self-loop cancels itself. Strict P+G+1=T rejects it.
* Without gap ranges, P=2,T=1,G=p-2 satisfies the field equation. It is not a
  predecessor relation. Gap and previous byte ranges must remain.
* Disabled words can hold arbitrary field elements without a state event;
  retain their zero constraints even if enabled values are inferred canonical.
* Removing output ranges together with input ranges is circular. A byte-add
  equation can use result=p-256 and carry=1 for zero operands; retain independent
  write anchors even if a later transition returns a canonical value.
* An unopened initial side, free provider multiplicity, or mass equal to p can
  create sources with no authenticated initialization. Root coverage and
  characteristic admission are part of this lemma, not optional optimizations.
* Fractional selectors can mix canonical words into nonbytes. Preserve Boolean
  selectors/ROM membership and one-hot offset proofs.

## Representation opportunities

Inventory must use the immutable admitted opcode policy, not observed execution
counts. In byteOperations, A is already excluded from BYTE queries whenever
shifts are present; A and RHS are excluded whenever byte bitwise operations are
present. Their canonicality inference therefore does not necessarily remove
any query. B, previous_rd, and memory_after are direct eight-byte words with no
bit consumers, giving 24 redundant BYTE entries for an opcode policy supporting
all three. This removes eight three-byte inverse batches (32 interaction base
columns), provided query regrouping is explicitly versioned.

Signed-load equations currently retain memory_before bit decompositions for
all potentially referenced offsets. With LB admitted this means eight bytes
represented by 64 bits. State-derived canonicality alone does not provide a
sign bit: replacing these by eight direct value fields plus one selected sign
would save 55 main fields, but requires a new signed-load authority. One possible
proof uses a Boolean sign s, selected canonical result byte b, and a BYTE query
for 2*(b-128*s); this forces the chosen sign. It needs separate degree analysis,
all signed widths/offsets, malformed-selector tests, and a full-Q authority.
Do not remove the old bits while retaining equations that read them as zeros.

The two opportunities together suggest 87 fewer committed CPU fields at a
policy where these consumers are present. This is a source-cell model, not a
performance or peak-memory prediction. No pruning is implemented here.

## Inspected service anchors and minimal v3 implementation

The new opt-in `cyclic_canonical_v3` uses the existing twelve-column state
relation, with a distinct version-three challenge tag. Its only omission is
B/previous_rd/memory_after from the CPU BYTE query list. All main columns,
bit decompositions, disabled-word identities and service constraints remain.
It is not selected by the Ethereum request defaults or chain driver here.

Keccak bridge `layout.RANGE_COLUMNS` includes both BEFORE8 and AFTER8,
TICK_BYTES3, PREVIOUS_BYTES3 and GAP3. Its `equations.emit` reconstructs both
clocks and enforces active*(tick-previous-1-gap)=0. The CPU `cpu_bus.evaluate`
header binds the bridge tick to 4*index+4; Bus.validate bounds steps below
2^22. The 25 immutable lane positions are distinct, with a full-width address
carry chain and pointer alignment. Its writes remain independently byte checked
in the bridge as well as bound to the permutation output by the typed IO bus.

Secp bridge `layout.RANGE_COLUMNS` includes TICK_BYTES3 and all four predecessor
and gap triples. Its `equations.emit` reconstructs the clocks and enforces the
same strict inequality separately for all four RAM lanes. `cpu_bus.evaluate`
binds tick to 4*index+4. Input-coordinate rows require AFTER=BEFORE. Output rows
bind AFTER through `wireTuple` to arithmetic result bytes. Both product and
linear `equations.byte` include their lhs/rhs/result arrays in the BYTE bus;
packet format only selects a fixed byte permutation. Aligned coordinate bases
and the four offsets 0/8/16/24 give distinct aligned lane addresses. All these
ranges, typed wire/IO closures and immutable lane schedules are retained.

The actual 52-op immutable policy was measured from
`interop_artifacts/rv64-ethereum-block-24628607/batch-000005.json`, with source SHA
and complete mask in `rv64-state-range-model.json`. Its physical logical main is
284 columns, unchanged by v3. Queries are B8/result7/previous_rd8/memory_after8/
address7/difference8/clocks24 =70; v3 retains46. BYTE batch inverses fall24 to16,
removing32 base interaction columns. No performance claim follows from this
cell count. Signed-load bit replacement remains design-only and is excluded
from the implemented v3 candidate.

## Candidate qualification

ReleaseSafe AIR passed the exact query inventory/restoration, distinct state
challenge schemas, canonical-boundary ghost rejection, future-before and
self-loop attacks, disabled-word ghost rejection, independently sealed BYTE
write-range closure, and dense-QM31 degree-four checks for every actual52 CPU
residual. ReleaseSafe authenticated execution passed both ABIs and PC encodings
with owned/arena proof-byte parity and fresh receivers, cross-state downgrade
rejection, and balanced forged state/hash/service claims. These are small
complete fixtures; they are not a claim of a v3 full Ethereum block run.

The independent CPU native16 gather path also matches the retained untiled
serial proof reference at 3/8/16 workers in both PC encodings. Native tile scratch
is 39,104 bytes per worker for this v2 CPU geometry, 37,056 for v3. Component
telemetry remains private until workers join; the joined-profile tests check
all88 component stage leaves remain root siblings and check partial adoption
allocation failure/retry ownership. Telemetry and gathering do not change the
AIR or transcript. No speedup is inferred from these functional gates.
