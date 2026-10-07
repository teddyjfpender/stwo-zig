# Direct RISC-V leaf wrapper: proof-complete target

## Why the 47-row diagnostic is not publishable

The real q193 native fixture generates all 47 rows of the V4 direct wrapper,
and its first relation audit had nonzero `range_check_8_8`,
`recursion_transcript_frame_word`, `recursion_verifier_input_word`, and
`recursion_statement_word` totals. Versioned row-35 and row-4 providers now
close the first two domains on that same real fixture; verifier-input and
statement/public authority remain open. An independently reviewed source audit also
found that row 40 consumes 24 local authority, wire, and receipt identity
tuples with no producer in that roster. Its row-42 ProgramV2 hash currently
reads leaf-dependent preprocessing rather than words proved equal to the
native verifier's executed program. Zeroing totals with host-computed values
would not establish those equalities. V4 remains a diagnostic witness and all
publication entry points stay disabled.

## Versioned 50-row candidate

Retain rows 0–46 as the native verifier, global link, arithmetic, ProgramV2,
Tree0, metadata, and link components, with these **versioned replacements**:

| Row | Change and proof obligation |
| --- | --- |
| 4 | Export the eight Tree0 frame words from the actual transcript-word values with the extra lookup multiplicity required by row 44. |
| 5 | Export the 16 committed `u16` halves of the eight native wire-ID words. The row-42 bridge must prove canonical 32-bit recomposition before ProgramV2 hashing. |
| 34 | Commit one ordered Poseidon provider over six call ranges: native verifier, metadata, link, ProgramV2, local authority, local receipt. |
| 35 | Recompute byte-table multiplicities including authenticated row-41 arithmetic requests. |
| 36 | Version the Statement source to emit one additional use at the exact 56 `S2WR`/`S2CX` words routed into local identities. |
| 42 | Replace the self-consistent word source with the versioned `NPV2`-consuming bridge. |
| 47 | Route native statement/context words to local authority, wire, and receipt identities through the existing typed child-field router. |
| 48–49 | Hash the authority and receipt preimages with typed `vm_public_claim_hash` AIR; produce the exact `LAI1` and `LRI1` tuples consumed by row 40. |

Rows 47–49 now have a typed PlanV5 layout and VPR6/VPK6 namespace. A
diagnostic 50-row cohort now writes all three trees and accounts for all 50
claims on a real q193 native leaf. This is not a wrapper proof: the real-leaf
relation audit still has nonzero verifier-input, statement, and local
public-claim-word domains (25, 29, and 30). The router/hash AIR defines
their tuple equations and the manifest pins geometry, schedule ID, semantic
digests, and six ordered call counts. Row 47 must receive `S2WR`/`S2CX` values from
the *checked native base AIR*. Row 40's 24 `LAI1`/`LWI1`/`LRI1` consumers
must close exactly with the router and hash rows. No second table of host
labels counts as proof authority.
The dormant router also forwards eight Tree0 words to `PPR1`. Direct V4
already emits those words in row 39 and consumes them through row 44, so the
V5 schedule must disable exactly those eight router forwards. Keeping them
would over-emit `PPR1` even if the new identity tuples close.
The versioned Statement source has a fourth fixed preprocessing column for
the 56 extra-use selectors (the old row had three). Its semantic identity and
geometry must be in VPR6/VPK6; the original V2 row 36 remains unchanged.

## Fixed-key and public boundary policy

The V4 ProgramV2 preprocessed words contain per-leaf wire and statement
identities, so its Tree0 root and VPK5 key change with each leaf. The target
is a fixed-key verifier template per admitted shape: opcode schedule, PCS
profile, geometry, and true constants remain in preprocessing; proof roots,
statement identities, and other leaf-dependent values are committed main or
authenticated public data. A template key must be reconstructed or looked up
by the detached verifier and checked by the parent. Accepting a child-carried
key as public input is unsound. Moving values to main alone is insufficient:
the `NPV2` relation must connect row 42's canonical words to the native
verifier components that actually execute them. The canonical ProgramV2 word
coverage audit must fail closed until every active index has exactly one
trusted origin or a semantically constrained fixed value.
PlanV5/VPR6 currently inherit V4's leaf-specific V2 `base_manifest_seal`.
Consequently VPR6 itself varies across honest leaves, before considering the
preprocessed root. The present VPK6 is only a versioned diagnostic key, not
the fixed-key template described here. Its replacement must derive protocol
identity from shape and AIR semantics alone, with every removed authority
field moved into a proof-visible main/public relation. Omitting leaf fields
from a hash without those joins would create an arbitrary-program verifier.
The staged native source currently covers 14 words from actual row-5 values
(wire identity and selected PCS payloads). A dormant row-42 bridge constrains
nine fixed format/PCS words in AIR under the pinned profile. On the focused
fixture, its machine-readable coverage audit still reports 46 unlinked words,
including instruction descriptors and identity fields, and `requireComplete()`
rejects it. Neither staged module is selected by the direct cohort yet.
The real q193 V6 audit exposed an additional representation boundary: the
native transcript writes each 32-bit wire-ID word as two 16-bit field payloads.
The first eight row-5 payloads are therefore **not** the eight canonical
ProgramV2 wire words. The V6 eight-row direct export intentionally rejects
this capture. A versioned proof-visible bridge must consume all 16 committed
half-word payloads, range-constrain each half, and prove the eight 32-bit
recompositions in row 42 before either the tuple ledger or a fixed key can be
admitted. Host recomposition is only a diagnostic and does not close this
soundness obligation.
The V7 bridge now implements those AIR equations, with 24 row-35 byte-table
requests and a canonical-gap check that rejects field-modulus aliases. On one
real q193 native capture, the diagnostic ledger closed all 24,336 selected
lookup contributions: zero unmatched tuples in domains 25, 29, and 30. This
uses a shape-compiled fixed schedule for 3,194 ProgramV2 words and leaves
only 16 identity words dynamic. It is **not** a physical 50-row proof: the
physical claims still come from the older V5 cohort and remain nonzero until
the new AIRs, row-35 provider, and verifier-owned fixed columns are installed
in the committed trees and checked by a fresh verifier.
The real capture also exposed a fixed-column bug: constant transcript
payloads such as PCS settings had been reconstructed with value zero. The
V7 row-5 writer now derives these values from admitted PCS, geometry, and
lookup descriptors. All 4,700 row-5 fixed rows match the q193 native source.
The V7 candidate template independently rebuilds this complete padded row-5
table and the row-42 ProgramV2 table, sizes row 5 for its actual cardinality,
and seals both AIR identities, fixed-column digests, and all 50 placements.
The V7 roster and candidate protocol ID now derive from that verifier-owned
template rather than a leaf-specific V2 manifest. Distinct leaves with the
same admitted shape get the same candidate key. No verification key is
admitted until the remaining base fixed tables and a fresh detached proof
transaction are qualified.
The first physical V7 bridge also runs on the real q193 capture: row 5 writes
4,700 rows, row 42 writes a 4,096-row padded table, and the versioned row-35
counter includes exactly 24 wire-byte requests. Its row-5/row-42 NPH2
interaction claims cancel under the shared relation draw. This is a scoped
physical claim check. The verifier-owned V7 key now also binds row 39's
corrected direct-source AIR and every padded fixed column. Substituting the
new physical row-5/35/39/42 audits into the real 50-row cohort closes the
complete domain-25 and domain-30 residuals exactly; both are regression
gates, not just printed diagnostics. Domain 29 remains nonzero because its
statement source still uses the diagnostic V5 cohort. Neither the scoped
check nor these two domain gates creates a proof.
The real q193 diagnostic now also replaces the V5 row-36 claim with the
physical V8 claim and charges the 412 verifier-owned G3S1 global statement
words through their public boundary. The complete 50-row diagnostic has zero
residual in all 47 relation domains and in the framework sum under one dummy
relation draw. The focused test fails if either total reopens. This is an
algebraic source-and-claim check, **not** a committed V8 cohort, a detached
verification, or a proof. In particular, the old V5 plan still supplies the
other rows; it does not bind a complete V8 roster or fixed Tree0.
Row 36 cannot simply be moved into the present fixed key: two valid SegmentV2
statement wires with 664 and 668 words share the same 1,024-row geometry but
require different fixed scope/index columns. The focused counterexample gate
rejects deriving that key from padded size or the separate 128-word native
transcript. A sound replacement must either admit the exact statement length
as independently verified key shape, or constrain variable active/index/use
columns in a versioned proof-visible AIR.
The bounded V8 row-36 AIR candidate implements the second option for a
1,024-row schedule with 664–887 wire words. One verifier-owned ordinal column
is constant across lengths; committed phase and bounded-distance columns
constrain the exact wire/context/padding order, derive scope and index, and
limit extra use to 0–2. Focused tests evaluate every row at 664, 668, and 887
words and reject forged phase, ordinal, count, and fan-out. It remains dormant
until the public parameter and physical row are admitted by a detached V7
verifier and the complete statement relation closes.
The verifier-side parameter source now derives the exact count from an
authenticated canonical SegmentV2 public wire and independently admitted
source manifest. A dormant V8 physical writer re-derives that count, checks
all wire values and the V6 fan-out schedule, and writes complete fixed, main,
and interaction columns under one ordinal key; focused Debug and ReleaseSafe
tests cover distinct wire lengths and hostile mutations. On the real q193
leaf it accepted the 784-word canonical wire and produced 1,024 physical
rows. Replacing only the V5 row-36 audit left domain 29 residual
`(88766749,1708476026,1322968230,1106752563)`; the omitted G3S1 public
boundary accounts for that residual exactly. Both the physical statement
claim and the boundary still need admission under one roster and a fresh
detached proof transaction.
The proof-inactive V8 candidate template and roster now replace row 36's
placement, seal its fixed ordinal column and AIR identity, and specify a
verifier-derived public wire-count parameter. The same candidate key covers
valid 664- and 668-word statements; focused tests reject altered source,
manifest, geometry, and parameter contracts. This seals one row's contract,
not the complete Tree0 or a publishable wrapper key.
The V8 candidate transcript prefix also commits the verifier-derived exact
statement count and the expected G3S1 words before relation challenges, then
the challenge-dependent G3S1 claim afterward. The real-leaf diagnostic
exercises this ordering but still evaluates its relations under a dummy draw;
the final detached proof must use the resulting Fiat–Shamir draw.
For the V6 base fixed schedule, rows 15 and 16 are deliberately unqualified.
Their Tree0 columns include the exact dense input-use multiplicities of the
native-public-sum arithmetic graph. Section lengths alone do not determine
that graph: merging the four sorted sparse-memory address lists changes the
input wiring, and the completion path can add a program-access term. A
per-leaf graph digest or use-count array cannot be imported into a reusable
fixed key. A proof-inactive V8 candidate now recompiles the exact public
claim/logup graphs from verifier-selected capacity and claimed-sum count,
seals both graph identities and all padded fixed columns, and matches the
native row-15/16 witness writer cellwise in focused tests. The complete
roster must still seal this profile together with graph-lowering rows 30–32;
the existing production writer rejects these rows before Tree0 publication.
The current legacy-zero machine-I/O graph is consistent with q193's admitted
zero-state policy; nonzero machine I/O needs a separately versioned graph and
statement relation.
Independent shape-derived writers now cover rows 11, 13, 14, 18, 19, and 22;
rows 11, 18, and 19 have not yet been admitted into the complete template
key. The row-13/14 writer covers the public authority hash and seal, with
physical fixed-column parity against the native graph and mutation gates.
Row 22 rebuilds the core Merkle-root schedule from verifier-owned query,
tree, and FRI counts. An isolated rows-23/24 ambiguity test shows why the
remaining coarse counts are insufficient: two ordered tree-column layouts
produce different row-23 fixed keys, and two PCS sample-layout orders with
equal counts produce different row-24 circuit identities. A later template
must select the ordered per-tree column logs, sample-layout tags and mask logs,
PCS graph/bindings/use counts, and both complete fixed digests before accepting
a child. The captured leaf must not choose these verifier-key inputs.
An isolated proof-inactive V11 row-23 writer now takes caller-selected ordered
VM/recursion column logs, copies them into owned storage, rebuilds the exact
trace-Merkle schedule, and hashes every padded fixed cell. Focused tests match
the native writer cell by cell and distinguish a 20/21 column permutation at
identical geometry. The real q193 diagnostic now also matches every row-23
Tree0 cell and pins the observed ordered-layout digest
`7f2265220644e9bde63d10ef1286b6b4ddf3360186e01b1246b0a0239e8e54e1`.
This is a fixture guard: the diagnostic obtains the layout from a verified
capture, so it is not yet an independently selected production key. A separate
V11 builder now derives ordered Trees 0–2 from the admitted statement, pinned
lookup manifest and validated bridge geometry; Tree 3 remains an explicit
verifier-selected parameter. Focused tests compare those outputs with the
native verifier's column ordering.
An isolated V11 row-24 writer recompiles the PCS graph from ordered tree
logs, exact sample-point tags and physical mask logs. Focused tests match all
native fixed cells and reject a sample-tag permutation with the same aggregate
sample count. The real q193 Tree0 comparison also matches every row-24 fixed
cell and its captured PCS circuit identity, now pinned as fixture vector
`01ffe0f7672b593a694f67bb5855c7b11773bbab76e4b2c9b02e2c25a8287f2e`.
The diagnostic still reads the PCS profile from the verified capture; a
production V11 key must select or derive the exact profile before the leaf.
The verifier-owned FRI leaf and node fixed schedules for rows 25 and 26 now
have an independent writer. Its complete committed-order columns, including
padding, match the native witness writer in focused tests and the real q193
Tree0 source. These rows are qualified as standalone fixed-column sources;
they are not yet admitted into the complete V7 fixed key.
An isolated V8 row-28 FRI-control writer now derives its entire padded fixed
table from verifier-owned VM/recursion plans and CoreProfileV6. Its committed
cells match the native writer, including padding, in Debug and ReleaseSafe
tests; altered plan, profile, geometry, and destination aliasing fail before
writes. The V8 template does not yet seal the recursion plan's authority
digest, so row 28 deliberately fails template admission.
The V9 candidate template closes that isolated admission gap: it recompiles
both VM and recursion schedules from one verifier-selected transcript shape,
seals the recursion schedule digest and every padded row-28 fixed cell, and
admits a physical writer only when its live plans and fixed table match.
Distinct admitted shapes yield distinct keys; resealed digest and shape
mutations fail. This does not seal the other missing Tree0 rows.
On the real q193 leaf, the V8 roster admits the authenticated 784-word
statement parameter. Independent writers for rows 27 and 29 now rebuild the
complete padded FRI-Merkle anchor and FRI-circuit input fixed columns. The
real q193 Tree0 comparison checks rows 27, 28, and 29 cell by cell; the
row-29 comparison caught a mistaken binary-outer circuit-ID namespace, now
corrected to the direct-leaf IDs 301–303. A proof-inactive V10 template seals
and admits the exact row-27/29 fixed digests and placements on top of V9's
row-28 key. This still does not admit the complete 50-row Tree0 or create a
wrapper proof.
The proof-inactive V11 candidate extends that key with exact padded row-23
trace-Merkle and row-24 PCS-DEEP fixed tables. It seals their ordered trace
layout, PCS sample/mask profile, arithmetic circuit identity, fixed digests,
and corrected placements. A real q193 diagnostic checks every Tree0 cell of
both writers against the native source, then admits both writers to a V11 key;
that profile is still read from a freshly verified capture, not selected by a
production verifier before the child arrives. The candidate explicitly
rejects complete preprocessing and proof activation.
For shared graph-lowering rows 30–32, a separate V8 candidate seals the
statement, claim, and public-LogUp contribution from verifier-selected
capacity and schedule. It matches an independently prepared outer source,
but intentionally does not claim full row fixed IDs. The proposed direct
segment-transcript wrapper has seven ordered arithmetic lanes: VM AIR,
statement, claim, public LogUp, PCS, FRI, and VM binary. Its candidate key
checks that exact lane order and rejects the current q193 SegmentV2 cohort,
which instead has five lanes including native-public-sum. The direct key
requires a verifier-selected VM graph pin before accepting the leaf. An
isolated compiler reconstructs that graph from admitted public statement
geometry and the lookup manifest. In a real q193 differential, its 14,729-node
graph, reference, schedule, profile and circuit IDs match the freshly verified
capture, with the expected IDs pinned as test vectors. The test's statement
admission callback still obtains those IDs from the producer before proof
generation; a production verifier key must select them independently before
the leaf arrives. Neither candidate has been connected to a complete fixed
Tree0 or a detached wrapper proof.
A further dormant row-4 profile can export kind and eight split argument limbs
for instructions with an actual payload row, using that row's existing
transcript-payload relation. Its coverage audit rejects duplicate origins and
records instructions with no payload row. Verifier sequence and sub-index are
absent from row 4, so the profile deliberately does not claim complete
instruction authority. A versioned descriptor owner is required for those
fields and zero-payload instructions.
The fail-closed instruction-owner contract checks row-3 call geometry and
enumerates the missing AIR equations. It emits no `NPV2` tuples: row 3 lacks
the raw descriptor and ordinal, and the required one-per-instruction
selector cannot be inferred from current coalesced calls. A host copy of
ProgramV2 cannot fill this gap.

The verifier-owned 24-word `LAS2` boundary consumes row 40's public link,
ProgramV2, and Tree0 words and mixes its expected values and claimed sum
into the transcript on both prover and fresh verifier. Its expected values
must come from admission, never the artifact. The existing V2 public-wire
boundary remains separate. A future public-I/O byte relation (issue #228)
must bind actual guest input/output bytes before an application claim is
published.

## Activation gates

1. A real native q193/PCS-PoW16/interaction-PoW10 proof feeds a complete
   V8 50-row cohort. Every direct AIR constraint and all 47 relation domains
   close, including the V2 wire, LAS2, and G3S1 boundaries, with one shared
   transcript-derived challenge draw and no free residual. The current
   diagnostic closure uses a dummy draw and V5 rows outside the physical
   V7/V8 replacements; it does not satisfy this gate.
2. A canonical 50-row proof is produced, serialized, producer state is
   destroyed, and a separately reconstructed verifier checks its fixed key,
   Tree0, transcript, all claims, and proof bytes. Mutations to each native
   identity, ProgramV2 word class, call range, public boundary, child order,
   position, and completion must fail.
3. A temporal parent recursively verifies two such leaves under an admitted
   key family, constrains adjacent spans and state/sparse-memory joins, and
   yields one freshly verified root. The gate then crosses 2^24 aggregate
   cycles with each leaf under its local cap.

Measure native proof, wrapper witness, wrapper prove/fresh-verify, parent
prove/fresh-verify, proof sizes, and peak resident/device memory separately.
The q193 native-to-39-row outer result is only a redundant diagnostic
baseline; it is not a stage in this direct pipeline.
