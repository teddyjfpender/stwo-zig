# BLAKE3 prover migration

Status, 2026-09-22: priority work; native CPU protocol foundation, a complete
compression proof and fixed-length full BLAKE3 hash proofs are implemented and tested. Production RISC-V leaf/parent proofs still use their
existing Poseidon suite. No BLAKE3 recursion, Metal proof or new production key is
qualified yet. The fused PCS prototype and prior scheduling work are retained.

## Evidence and upstream scope

The inspected [ZisK alpha release](https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha)
is commit `02d2ae7b711454ce4574d852f8bfbddbfcbb1d67`. Its release notes describe an
optional BLAKE3 recursive configuration and a seven-round compression precompile.
They also describe scheduling and witness-generation changes. This is evidence
for the architecture, not a controlled measurement of the hash change alone.
The earlier research checkout's tag resolved to
`5c5f81c96929abed88894473ec6060b1b545b5c5`; preserve both identities rather than
silently attributing earlier source inspection to the later release.

Release Cargo.lock uses `proofman-fields` 1.3.0-alpha, checksum
`eb8d460b2e0e01f448eb78bd5486877239130674572be8f5c334bc86948cd65b`.
Inspected reference implementation: Proofman
`d485fac207679076958b502554fb595568c2f954`,
`fields/src/blake3_core.rs` and `fields/src/blake3_transcript.rs`.
That commit is not asserted identical to the published crate. The transferable
idea is using the full BLAKE3 construction with a compression backend, rather
than replacing a Poseidon permutation inside its existing sponge. Goldilocks
transcript word reduction is not directly reusable over M31.

## Implemented reference protocol

`src/core/channel/blake3.zig` and
`src/core/vcs_lifted/blake3_merkle.zig` export an explicit experimental suite.
They reuse the existing std-backed `Blake3Hasher`; no new production dependency
or default-suite change. Protocol identifier: `stwo.blake3.experimental.v1`.
Every hash starts with that exact ASCII string and one operation byte:

| Tag | Encoding after protocol prefix and tag |
| --- | --- |
| 0, initial state | empty |
| 1, mix words | previous digest, u64 word count, u32 words |
| 2, mix QM31 | previous digest, u64 QM31 count, four u32 coordinates per value |
| 3, mix integer | previous digest, u64 value |
| 4, mix root | previous digest, full 32-byte root |
| 5, draw | current digest, u64 draw index |
| 6, PoW | current digest, u32 difficulty, u64 nonce |
| 7, leaf | concatenated canonical M31 values, each encoded as u32 |
| 8, node | full left digest, full right digest |

`src/core/channel/blake3_frame.zig` is now the sole protocol-byte author. Native
channel/Merkle hashing and recursive witness messages share its streaming writer;
materializing a frame is optional and is not done by the native hot path. The
original independent protocol-vector pins still pass. A complete CPU STARK also
verifies a canonically framed Merkle node against the native hasher, with public
child digests. See [framing evidence](../../autoresearch/notes/2026-09-21-blake3-framing/README.md).

All integers are little endian. Absorption updates the digest and resets the
draw index. Draws increment a checked counter without updating the digest.
For base-field sampling, reject an eight-word draw if any word is >= 2p,
then reduce each accepted word modulo p = 2^31-1. Each output has exactly two
preimages. Single-QM31 draws consume one block and use its first four words;
bulk draws consume up to two QM31 per block, matching the existing PCS API's
consumption convention. PoW checks trailing zero bits in the first little-endian
u32 and rejects difficulty above 32. The initial state is pinned against an
independent oracle because Zig 0.15.2's BLAKE3 implementation fails to evaluate
this short input at comptime; runtime hashing is tested.

Digests remain `[32]u8`. There is no M31 digest reduction and no device-family ID
advertised by this new hasher. This protocol has not received cryptographic
review; the identifier deliberately says experimental. The primitive's digest
size alone does not establish 128-bit soundness for the entire M31/QM31 proof.

## Migration boundaries and implementation order

| Boundary | Existing implementation | Required migration |
| --- | --- | --- |
| Native commitments/channel | Core BLAKE2 paths; recursion `poseidon2_channel.zig` | BLAKE3 suite is now a CPU oracle; qualify generic proving and serialization before selecting it |
| Scheduled Fiat–Shamir | `native_scheduled_channel.zig`, transcript witness and verifier schedule | Constrain identical byte framing, draw indices, field rejection, roots and PoW |
| Recursive hash provider | Typed Poseidon components, `detached_parent_catalog_v1.zig` | Typed BLAKE3 compression plus framing/chaining constraints; exact lookup closure |
| Trace/FRI authentication | Merkle witness components and `fixed_wire_adapter.zig` | Lossless digest limbs, BLAKE3 path verification, all child roots authenticated |
| Program/memory statements | `air/memory_commitment`, segment statement wire | New commitment suite and statement version, recomputed roots and empty-tree hashes |
| Keys/proof identities | `engine_protocol.zig`, protocol identities, canonical proof identity, trusted artifacts | Bind family and full protocol definition into trusted key and wire admission; reject mismatches before interpretation |
| Metal | `hash_domain.zig`, runtime ABI, commitment/FRI kernels, typed AOT | New explicit family, BLAKE3 kernels and generated recursive evaluator, CPU parity and actual dispatch evidence |
| Product defaults | RISC-V leaf, parent, CSP scripts and docs | Switch together after end-to-end qualification; retire old prover selection and redundant code |

The shared seven-round compression schedule and typed degree-two G arithmetic
reference are now implemented; see
[compression evidence](../../autoresearch/notes/2026-09-21-blake3-compression/README.md).
Four focused tests pass, including complete witness-coordinate mutation and
standard hash parity across chunk boundaries. This is not a qualified recursive
provider: the reference has 704 Boolean columns per G and no authenticated
inter-call relations. A compact typed G now uses 124 columns, 80 degree-two
equations and 56 requests to existing byte-pair/bitwise schemas. Its three
focused tests cover equivalence, mutation and table membership; see
[compact component evidence](../../autoresearch/notes/2026-09-21-blake3-packed/README.md).
Typed G and feedforward XOR call components now compile through the canonical
relation binding, with a fixed 272-wire compression plan and a writer for all
72 rows. Exact signed multiset tests close both wires and canonical production
lookup-counter rows; see [wiring evidence](../../autoresearch/notes/2026-09-21-blake3-wiring/README.md).
A standalone CPU compression STARK now commits the G, XOR and public-boundary
components together with the production bitwise and byte-pair tables. The core
verifier accepts it using independently reconstructed preprocessing and matching
BLAKE3 transcript draws. Substituted preprocessing roots and changed public
outputs fail root admission. The test uses eight queries and zero PoW solely to
keep integration checks short; it is not a production-security performance result.
See [committed proof evidence](../../autoresearch/notes/2026-09-21-blake3-committed/README.md).

A canonical full-hash DAG now expands fixed public message lengths into the same
G/XOR wire circuit. It handles empty input, zero-padded partial blocks, chunk
counters, CHUNK_START/END, left-complete chunk trees, PARENT and ROOT. Chaining
values share wires across compression calls; they are private intermediates,
not additional public claims or values recomputed by the verifier. The first
eight words of the root output form the ordinary 32-byte digest. Keyed hashing
and XOF are outside the current unkeyed protocol suite.

`test-blake3-hash` checks standard-library parity across 18 lengths up to 8193
bytes, exact global wire closure, mutations and allocation failures.
`test-blake3-proof` now verifies full hash STARKs for 0, 65 and 2049 bytes, covering
empty/partial blocks and an unbalanced three-chunk tree. It rebuilds fixed
columns from public message/digest and length-owned topology without computing
the private rounds. See [full-hash evidence](../../autoresearch/notes/2026-09-21-blake3-full-hash/README.md).

These are public-message hash proof gates. A typed private-input bridge now
copies complete caller word tuples into the hash graph and constrains unused
partial-word bytes to zero. Its trusted preprocessing receives length and caller
wire range, never message bytes. Compiler/export and exact global wire tests pass,
including rejection of missing caller emissions and changed endpoints. See
[private-input evidence](../../autoresearch/notes/2026-09-21-blake3-private-input/README.md).
The bridge now also passes a complete CPU STARK for H(H(message)): the first
hash's digest is omitted from the public statement and its output wires feed the
second hash through the bridge. Trusted preprocessing uses only original message,
final digest and canonical schedules. This is witness-only composition, not a
zero-knowledge claim. See [private composition evidence](../../autoresearch/notes/2026-09-21-blake3-private-proof/README.md).
Typed byte routing now also assembles canonical Merkle frames from authenticated
child digest words at unaligned offsets. Symbolic digest callbacks in the shared
frame writer derive the routing, and producer use counts reflect every consumer.
A complete CPU proof composes two native-framed leaf hashes with their parent;
the intermediate leaf digests are witness-only and its final root matches the
native commitment hasher. See [byte-routing evidence](../../autoresearch/notes/2026-09-21-blake3-byte-routing/README.md).

Binary Merkle paths now also have a sibling-free preprocessing builder and a
typed bounded private-word source. Native four-leaf paths match at all positions;
complete CPU STARKs verify depth zero and depth two with private siblings. Their
index and depth are public statement coordinates in this gate. See
[path evidence](../../autoresearch/notes/2026-09-22-blake3-merkle-path/README.md).
Production recursion must still bind query indices to constrained Fiat–Shamir
challenges and account for lifted PCS/FRI path geometry and batching.

Typed challenge extraction now proves the native eight-word rejection predicate
and reduction to M31, including rejection in an unused half-block. A complete
CPU STARK binds a canonical draw frame to all eight scalar outputs with real
range providers and trusted preprocessing. See
[challenge evidence](../../autoresearch/notes/2026-09-22-blake3-challenge/README.md).
The frame's state and start index remain public. Ordered rejection retries now
have a reusable builder: consecutive counters, rejected intermediate attempts,
and one accepted final attempt. The complete draw proof uses this builder; a
skip past an accepted attempt fails its status constraints. See
[ordered-draw evidence](../../autoresearch/notes/2026-09-22-blake3-ordered-draw/README.md).
Single-QM31 consumption is also supported: check all eight words, emit four,
discard the upper half and advance the draw counter. Consecutive single calls
match the native channel, and complete CPU proofs cover both consumption modes.
See [consumption evidence](../../autoresearch/notes/2026-09-22-blake3-single-draw/README.md).
A shared digest-role router now supports state/root inputs for draw, integer
absorption, root absorption and PoW frames, using the native frame writer and
existing typed byte-selection AIR. Merkle routing delegates to this same path.
Missing, duplicate and unused digest bindings are rejected. See
[frame-routing evidence](../../autoresearch/notes/2026-09-22-blake3-frame-routing/README.md).
A reusable routed-frame witness now replaces message-input boundaries with
authenticated routes. A complete CPU proof verifies two native integer
absorptions with a private intermediate state; independently reconstructed fixed
columns do not depend on that state's bytes. See
[private-transition evidence](../../autoresearch/notes/2026-09-22-blake3-private-transition/README.md).
Ordered draws now accept authenticated private state and sum its routed consumer
counts across attempts. A complete CPU STARK proves native absorption followed
by a single secure challenge, without exposing the intermediate state. See
[private-draw evidence](../../autoresearch/notes/2026-09-22-blake3-private-draw/README.md).
Integer absorption and secure draws now share a sequence builder that derives
state links and draw counters from operation order, including absorption resets.
A complete CPU proof covers absorb/draw/draw/absorb/draw with private states.
See [sequence evidence](../../autoresearch/notes/2026-09-22-blake3-transcript-sequence/README.md).
The same builder now supports all native absorption variants: integer, words,
secure fields and roots. An eleven-operation CPU proof matches six native
challenges across those transitions; empty word/field arrays are also checked.
Payloads are public in this gate and intermediate states are private. See
[absorption evidence](../../autoresearch/notes/2026-09-22-blake3-all-absorption/README.md).
Raw query masking now has a typed bytewise-AND component and a complete CPU
proof binding a canonical draw to eight query indices. Packed bytes preserve
31-bit index values without M31 aliasing; field rejection is not applied.
See [query evidence](../../autoresearch/notes/2026-09-22-blake3-query-mask/README.md).
Private-state query batching now preserves native raw order, duplicates, partial
blocks and counter consumption. A complete CPU proof derives nine indices from
an absorption-produced private state; unit cases cover zero through three blocks.
See [batch evidence](../../autoresearch/notes/2026-09-22-blake3-query-batch/README.md).
Raw query batches now participate in the same transcript sequence as secure
draws and all absorption types. A sixteen-operation CPU proof checks shared
counter advancement, partial batches, absorption reset and empty batches across
six AIR components. See
[mixed-sequence evidence](../../autoresearch/notes/2026-09-22-blake3-mixed-query-sequence/README.md).
PoW verification is now part of the sequence: the native low-bit hash predicate
preserves state/counter, and nonce absorption remains explicit. A twenty-operation
CPU proof includes a native-generated 8-bit nonce, a subsequent draw, nonce
absorption and another draw. Boundary tests cover zero difficulty, invalid
nonces, full 32-bit masking and unsupported difficulty. See
[PoW evidence](../../autoresearch/notes/2026-09-22-blake3-pow-sequence/README.md).
Canonical query-to-path admission now reuses native sorting/deduplication/folding
and checks exact path lists. A complete CPU proof constrains nine raw queries
and their two unique private-sibling paths together. Folded mapping has unit
coverage; the proof uses unfolded depth-one paths and public auxiliary query
coordinates. See
[path-admission evidence](../../autoresearch/notes/2026-09-22-blake3-query-path/README.md).
Lifted leaf geometry now matches real native BLAKE3 commitments/decommitments:
parity-preserving column projection, ascending column size and stable equal-size
order. A complete typed depth-three path proof authenticates a native captured
opening to its real root. See
[lifted-path evidence](../../autoresearch/notes/2026-09-22-blake3-lifted-path/README.md).
A typed canonical QM31-to-byte encoder now connects arithmetic wires to packed
hash words, excluding both the modulus encoding and high-bit aliases. A complete
CPU proof verifies source tuple → canonical bytes → BLAKE3 hash using the private
input bridge. See
[field-encoding evidence](../../autoresearch/notes/2026-09-22-blake3-field-encoding/README.md).
Indexed word payload routing now shares native frame serialization for leaves,
secure fields and raw words. The canonical field proof now hashes a framed leaf
through authenticated payload wires, and trusted fixed columns are independent
of payload bytes. Native protocol vectors remain unchanged. See
[private-framing evidence](../../autoresearch/notes/2026-09-22-blake3-private-payload-framing/README.md).
Lifted opening batches now have shape/range and repeated-projected-row
consistency checks, using one reusable map across columns. Real native
mixed-size openings pass; conflicting short-column values are rejected before
leaf construction in the integration fixture. See
[opening-admission evidence](../../autoresearch/notes/2026-09-22-blake3-lifted-query-admission/README.md).
Actual successful CPU PCS captures now feed typed trace and FRI path preparation,
including mixed column sizes, raw duplicate queries and fold schedules 1, 2 and
4. FRI capture paths begin above the folding subtree; the adapter reconstructs
intra-subtree siblings with native leaf packing before passing an original leaf
path to the typed witness. One captured packed FRI path also verifies in a
complete CPU outer proof. This does not yet bind sibling-leaf values to recursive
FRI arithmetic. See
[PCS capture evidence](../../autoresearch/notes/2026-09-22-blake3-pcs-capture/README.md).
The next gate closes that sibling-value gap for a complete folding group: every
QM31 tuple feeds a canonical field-byte encoder, every packed leaf is hashed in
typed constraints, and shared internal nodes feed the upper path. A real fold4
group (16 QM31 values, four packed leaves) verifies in one six-component CPU
proof; changing a source tuple in the last leaf invalidates the statement.
Native captures for fold1/2/4 and tail layers agree with the complete typed tree.
The source tuples are still public auxiliary fixture inputs; replacing those
sources with authenticated production FRI arithmetic/transcript wiring remains.
See [complete-group evidence](../../autoresearch/notes/2026-09-22-blake3-fri-group/README.md).
A hash-independent owned arithmetic capture adapter now checks routing and
canonical field inputs against a supplied FRI profile. Actual BLAKE3 captures for
fold1/2/4 satisfy the existing canonical recursive FRI graph, and every arithmetic
input coordinate matches its captured hash value. Mutated DEEP answers and
misrouted positions are rejected. This is host evaluation of the full arithmetic
graph, not yet a combined outer proof with the hash components; the scalar
FRI-value relation must still be connected to the QM31 encoding source.
See [arithmetic capture evidence](../../autoresearch/notes/2026-09-22-blake3-fri-arithmetic/README.md).
A typed scalar-to-QM31 repacking component now consumes the four scalar wires
identified by canonical FRI graph bindings and emits the tuple used by the hash
encoder. The complete group gate includes that connection in its seven-component
proof. Scalar source boundaries remain public fixture inputs; full arithmetic
operation rows and their additional producer counts are not yet part of this
outer proof. See [scalar-wire evidence](../../autoresearch/notes/2026-09-22-fri-scalar-pack/README.md).
Canonical FRI hash wiring is now reusable: schedules and sorted extra reads are
derived from the authenticated graph bindings. The existing arithmetic lowering
accepts these exports, counts each extra read and generates operation invocations
for segment and binary modes. This removes the fixture-only node map, but those
arithmetic operation rows are still outside the complete hash-group proof.
See [wire-plan evidence](../../autoresearch/notes/2026-09-22-fri-hash-wire-plan/README.md).
The arithmetic rows now pass a separate complete CPU STARK gate using the
existing multiply, inverse and linear AIRs with explicit proof-kind parameters.
It covers the canonical fold4 FRI circuit for all 17 queries of a real BLAKE3 PCS
capture, with graph-derived constants, inputs and zero-output anchors. This
advances beyond host-only evaluation. The arithmetic gate still has public
inputs; combining it with all authenticated hash paths and private shared
producers remains unfinished. See
[complete arithmetic proof](../../autoresearch/notes/2026-09-22-fri-arithmetic-proof/README.md).
A combined ten-component proof now joins canonical FRI arithmetic and ALL captured
FRI paths: 17 queries across two layers, 34 folding groups and 1,224 shared
private scalar coordinates. The public FRI-value anchors are removed. Hash paths
and arithmetic consume the same producers with exact graph-plus-hash counts;
trusted fixed columns contain neither private value nor digest bytes. An exact
wire ledger also detects a changed private scalar emission. This closes the
separate-proof gap for the FRI subsystem. Transcript and PCS DEEP/trace admission
remain public-input boundaries, and production CPU/Metal migration is unfinished.
See [combined FRI proof](../../autoresearch/notes/2026-09-22-blake3-combined-fri/README.md).
The combined proof now also constrains the actual standalone PCS transcript:
trace roots, sampled values, DEEP and FRI draws, terminal coefficients, PoW,
nonce absorption and raw queries. Twelve components share the same public
statement for transcript outputs/arithmetic/path indices; FRI opening values
remain private. The replay adapter preserves caller state on mismatches and
allocation failures and accepts an existing operation prefix. Full outer-STARK
prefix/composition/OODS admission and PCS DEEP/trace proof constraints remain.
See [PCS transcript evidence](../../autoresearch/notes/2026-09-22-blake3-pcs-transcript/README.md).
The canonical PCS DEEP quotient circuit now participates in the same outer
proof, sharing public answer values with FRI and reusing existing arithmetic
components. The standalone fixture's OODS point/seed are now consistent, and an
altered sampled value is rejected. Trace queried values remain public inputs;
their authentication paths must still be joined. The fixture seed is explicitly
not a full STARK transcript draw. See
[combined DEEP evidence](../../autoresearch/notes/2026-09-22-blake3-combined-deep/README.md).
The trace paths are now joined: all 17 paths for the mixed [6,4] columns reach
the public trace root and feed private base-field values into DEEP arithmetic.
Canonical scalar producers enforce literal zero extension coordinates, and
query-specific routes share producers for repeated projected column rows.
The thirteen-component proof and exact wire ledger pass, including changed
trace/FRI value audits. This closes the public trace-value boundary in the
standalone PCS fixture. Full outer-STARK transcript/composition/OODS admission
and production CPU/Metal/key qualification remain. See
[trace-join evidence](../../autoresearch/notes/2026-09-22-blake3-trace-join/README.md).
A real full-STARK capture now qualifies the complete verifier transcript prefix:
composition randomness, composition commitment and OODS seed precede PCS opening
operations. The combined PCS proof supplies that capture after native verification;
a second typed proof verifies its entire transcript. Composition-root substitution
is rejected. This is full-STARK transcript qualification, not recursive proof of
its composition/OODS algebra or parent-of-parent qualification. See
[full-STARK prefix evidence](../../autoresearch/notes/2026-09-22-blake3-stark-prefix/README.md).
The real capture now also qualifies its complete composition/OODS equation in a
separate typed arithmetic proof: all thirteen typed AIRs, both lookup tables,
claim balance, OODS circle mapping and split composition reconstruction. Existing
recorders and generic table equations remain the arithmetic authorities. The
combined gate verifies three complete proofs in 14 seconds on this host; this is
qualification runtime, not production recursion latency. Composition and transcript
still use separate public fixture statements. Joining them with the actual
full-STARK PCS into one parent remains required. See
[composition proof evidence](../../autoresearch/notes/2026-09-22-blake3-composition-proof/README.md).
The actual four-tree STARK capture now supplies DEEP and FRI arithmetic alongside
composition in one typed arithmetic proof. Column degrees, ordered sample masks
and FRI schedule come from admitted components/configuration and are checked
against capture data. The owned DEEP adapter rejects shape, sample-order and
encoding mutations and preserves its data after source mutation. This removes the
standalone two-column restriction from arithmetic qualification. All three graphs
still use public fixture input boundaries; the full transcript and authentication
paths must join that same parent before recursive verification is complete. See
[full-STARK arithmetic evidence](../../autoresearch/notes/2026-09-22-blake3-full-stark-arithmetic/README.md).
The full-STARK transcript now joins those three arithmetic graphs in the same
parent fixture. The transcript-only proof wrapper was removed; live and trusted
transcript rows feed the common typed roster with disjoint namespaces. The
combined gate now verifies two proofs and passes in 12 seconds / 1 GiB on this
host. This is test runtime, not qualified production recursion latency. Full
captured trace/FRI authentication paths are still absent from this parent, and
public fixture inputs have not become production private-input admission. See
[transcript/arithmetic join evidence](../../autoresearch/notes/2026-09-22-blake3-transcript-arithmetic-join/README.md).
All four captured trace trees and every complete FRI folding group now join the
same parent fixture. Native query projection, lifted-column ordering and repeated
row consistency are checked; every prepared root matches its captured commitment.
The parent includes transcript, composition/OODS, DEEP, FRI and authentication
paths with public leaf values and private sibling words. Its combined gate passes
in 28 seconds / 6 GiB, reflecting the added hash work; these are fixture costs,
not production recursion performance. Fixed reusable keys, private child-proof
input admission, CPU/Metal and parent-of-parent qualification are still required.
See [full parent path evidence](../../autoresearch/notes/2026-09-22-blake3-parent-paths/README.md).
A preprocessing audit identified the remaining child-dependent boundaries.
The transcript compiler now supports externally routed raw words and canonical
field encodings, with owned per-operation read multiplicities and namespace alias
rejection. Changed absorbed values retain identical fixed columns; a complete
proof with private input producers and a constrained native challenge passes.
The full parent still uses its public absorption operations pending shared-source
integration. Reusable keys additionally require dynamic query/path routing and
fixed-capacity rejection handling; this stage does not qualify a reusable key.
See [private absorption evidence and dependency inventory](../../autoresearch/notes/2026-09-22-blake3-routed-transcript-inputs/README.md).
The parent now integrates routed claim and sample absorption. Canonical field
encoders read the same composition input wires, with exact additional consumer
counts. Claim producers are private and shared between composition and transcript;
sampled values retain public arithmetic anchors until DEEP's scalar inputs are
joined. The full eleven-AIR parent and the single-graph regression pass. Direct
claim anchors are removed, but other per-proof public outputs still prevent a
reusable production key. See
[shared parent input evidence](../../autoresearch/notes/2026-09-22-blake3-parent-routed-inputs/README.md).
Sample values now share private sources across DEEP, composition and transcript.
The canonical DEEP input bindings select four scalar nodes per sample; weighted
instances of the existing packing AIR supply the sole secure tuple producer for
composition and the encoder. Both sets of public sample anchors are removed.
No AIR equations or semantic digest changed. Weighted tuple/mapping tests, the
full twelve-AIR parent and the shared arithmetic regression pass. Queried trace
and FRI opening values remain public; reusable-key and scheduling work remains.
See [private sample evidence](../../autoresearch/notes/2026-09-22-blake3-private-parent-samples/README.md).
Queried trace and FRI opening values now share private sources with authentication.
Trace rows use canonical lifted-row producers and query-specific scalar routes;
FRI coordinates use existing packing and canonical field-byte encoding. Both the
leaf payload anchors and corresponding arithmetic anchors are removed. The full
thirteen-AIR parent and arithmetic regression pass. No AIR equations or identities
changed. Public challenge/query/root/terminal inputs and dynamic schedule handling
still prevent reusable production keys. See
[private opening evidence](../../autoresearch/notes/2026-09-22-blake3-private-opening-inputs/README.md).
DEEP answers now feed FRI through private scalar routes, and FRI terminal
coefficients feed transcript absorption through private packing and encoding.
Their public arithmetic and absorption anchors are removed. Owned canonical input
mappings reject missing/duplicate coordinates, and the full parent, regression and
mapping/packing unit pass. No AIR identity changed. Public challenge, commitment,
query and nonce boundaries plus dynamic scheduling remain before key reuse. See
[private terminal-input evidence](../../autoresearch/notes/2026-09-22-blake3-private-terminal-inputs/README.md).

Every secure challenge in the joined parent now comes directly from a constrained
BLAKE3 transcript output: universal relation draws, composition randomness, OODS
seed, DEEP randomness, and each FRI alpha. Protocol roles identify outputs;
canonical graph bindings identify consumers. Existing scalar routes and weighted
packing distribute each accepted coordinate, including the OODS seed shared by
composition and DEEP. Both transcript and arithmetic public challenge anchors
are removed, without changing AIR equations or semantic identities. The focused
mapping, routed/public transcript, and complete parent gates pass (six tests).
Commitments, query routing, nonces and per-capture rejection/schedule geometry
still block reusable production qualification. See
[private challenge evidence](../../autoresearch/notes/2026-09-22-blake3-private-challenges/README.md).

Trace and FRI commitment roots now share canonical eight-word sources between
transcript absorption and all complete authentication paths. Existing byte-route
constraints bind computed root bytes to these sources using negative output
multiplicity. The preprocessed-tree root retains its public trusted-key anchor;
other roots use bounded private-word producers. Public root values are removed
from the non-key fixed columns without changing AIR equations or identities.
Seven focused tests pass, including public API regression proofs and the joined
parent proof. See
[shared root evidence](../../autoresearch/notes/2026-09-22-blake3-private-roots/README.md).

Transcript query outputs now feed DEEP positions through constrained canonical
field encodings. DEEP query bits share scalar sources with FRI and the new typed
Merkle word selector. That selector authenticates the direction bit and orders
both child words without direction-dependent fixed columns. Trace projection
preserves raw bit zero; FRI consumes the appropriate consecutive folded bits.
FRI positions and offsets are private and checked by its arithmetic. The joined
parent now uses fourteen AIRs. Nine distinct focused tests pass, including the
new selector's typed identity/export/mutation checks, a native lifted-projection
oracle, and the complete parent proof. See
[private query evidence](../../autoresearch/notes/2026-09-22-blake3-private-queries/README.md).

PoW and subsequent nonce absorption now share two bounded private-word sources.
Canonical framing exposes the u64 as two little-endian words without changing
serialized bytes or the protocol identity. The parent combines exact read counts
from both operations; nonce values are removed from fixed columns. No AIR changed.
Six focused tests pass, including a proof with nonzero PoW and nonzero upper
nonce bits, manual frame-byte parity, public transcript regressions, and the
complete parent. See
[private nonce evidence](../../autoresearch/notes/2026-09-22-blake3-private-nonce/README.md).

The retry path now has a genuine native regression fixture: absorbing integer
418109725 produces a first raw word of 0xffffffff, rejecting the first block;
the second block accepts. Its state and three raw blocks are pinned. Both native
bulk extraction and a complete transcript proof exercise this retry and subsequent
counter/reset behavior. All four focused tests pass. See
[real rejection evidence](../../autoresearch/notes/2026-09-22-blake3-real-rejection/README.md).

A typed first-acceptance controller now consumes all candidate statuses, emits
only the first accepted challenge, and authenticates the consumed attempt ordinal.
A complete hash/controller proof covers reject/accept/accept and discards the
third candidate; all short acceptance patterns and legacy draw behavior are tested.
The new raw-attempt export API shares existing draw/hash witness code. Its physical
batch counter is explicitly distinct from the selected native counter. Four
focused tests pass. See
[retry controller evidence](../../autoresearch/notes/2026-09-22-blake3-retry-controller/README.md).

Checked private u64 advancement is now implemented and joined to bounded retries.
Byte carry/range constraints reject overflow and freeze the counter after the
first acceptance. Draw-index bytes feed hashing through authenticated payload
routes. Native comparisons cover real rejection, cross-word carries and padding
at u64-max; a complete bounded hash/controller/counter proof passes. Eight distinct
focused tests pass. See
[private counter evidence](../../autoresearch/notes/2026-09-22-blake3-private-counters/README.md).
Bounded retries now feed the complete transcript and joined parent fixture.
The verifier supplies a capacity of three in this fixture; recorded attempt counts
have no fixed-column authority. Private counter ports chain between secure draws
and raw query batches. Absorption resets the counter to constrained zero; PoW and
empty queries preserve it. Raw query extraction never rejection-samples. The parent
roster includes retry-control and checked counter-step AIRs alongside its existing
hash, arithmetic, private inputs, query and Merkle path components.

Five distinct focused tests pass, including the joined parent. The strengthened
bounded-transcript test produces two complete CPU proofs: genuine rejection plus
consecutive single/bulk draws and resets, and independent raw 0xffffffff extraction
followed by a secure draw. Zeroed attempt metadata preserves live rows and trusted
preprocessing. Capacity errors and wrong public challenge preprocessing are tested.
See [bounded transcript evidence](../../autoresearch/notes/2026-09-22-blake3-bounded-transcript/README.md).
These are qualification fixtures; their timings do not establish an end-to-end
BLAKE3 speedup. Fixed capacity adds recursive hash work that must be included in
subsequent comparisons.

A sparse read-only consistency replacement is now qualified as a separate proof
fragment. Sorted u32 index/value rows enforce integer order and equal values at
equal indices, using the existing multiset and byte-range providers. An input
adapter binds independent bounded index and scalar-value ports. Three focused
tests pass, including a complete joined input-adapter/table CPU proof with
unsorted duplicates and u32 boundary cases. See
[read-only consistency evidence](../../autoresearch/notes/2026-09-22-readonly-consistency/README.md).
The read-only components are now joined to the complete parent fixture. Shared
projected index bytes come from authenticated DEEP bits through existing packing
and affine-routing constraints. Independent private opening-value producers feed
arithmetic, leaf encoding and read-only input adapters. Per-column sorted tables
use fixed row counts and ranks. The previous capture-dependent canonical scalar
map and its alias-derived IDs/multiplicities have been removed.

The projection regression proves fixed wiring invariance under changed queries
and duplicate patterns, including 31-bit projection boundaries. The complete
18-AIR parent gate passes with the new connections; its 32-second test runtime is
qualification evidence, not a matched performance result. See
[parent alias-join evidence](../../autoresearch/notes/2026-09-22-parent-alias-join/README.md).

A reusable bounded transcript plan now retains trusted preprocessing and binds
capacity, protocol/AIR identities, fixed rows and semantic export/read mappings
into a structural fingerprint. It accepts changed private routed inputs and ignores
recorded attempt counts, while rejecting public shape/role changes and explicit
capacity exhaustion. Transcript proofs and the parent prefix consume this plan;
the parent fixture passes capacity explicitly and safely transfers preprocessing
ownership before adding its separate key-root boundaries. Three distinct focused
tests pass, including allocation-failure/arena-growth checks and complete proofs.
See [transcript-plan evidence](../../autoresearch/notes/2026-09-22-transcript-plan/README.md).
The fingerprint is not a PCS root or full parent key. The parent fixture still
constructs a plan per invocation; production caching remains unfinished.

The normal native V2 RISC-V pipeline now produces and independently verifies
BLAKE3 nonfinal/final segment proofs through an explicit generic-engine selection.
The engine and recursive fixtures share coherent protocol aliases. The same
engine-parameterized test also verifies the default Blake2s path; a BLAKE3 proof
is rejected under the default suite's preprocessing root. Actual runner snapshot
identities replace stale placeholder memory digests in these tests, without
weakening statement admission. All three focused tests pass, including the
existing rebased leaf-local V3 default-suite proof.

See [native BLAKE3 segment evidence](../../autoresearch/notes/2026-09-22-native-blake3-segment/README.md).
This one-query, zero-PoW diagnostic was slower with BLAKE3 than Blake2s and establishes
no speedup. It preserves existing V2 program/state/sparse-memory and guest Poseidon
semantics; only the proof suite is selected. The native V2 capture now has an owning transcript adapter that reuses canonical
physical-manifest encoders and matches the independently verified native channel
across 227 operations, all 12 relation pairs, and the final draw counter. Changed
interaction claims are rejected. Its native relation exports have a distinct role
and cannot silently enter fixture universal-relation links. See
[native transcript evidence](../../autoresearch/notes/2026-09-22-native-blake3-transcript/README.md).
This qualifies transcript witness preparation, not a complete recursive parent.
The real BLAKE3 capture also satisfies the native composition recorder (13,929
nodes, 29 zero outputs), and 104 scalar challenge routes now connect transcript
roles to its authenticated input bindings. See
[native composition evidence](../../autoresearch/notes/2026-09-22-native-blake3-composition-links/README.md).
These routes are prepared but not yet proved inside a complete native parent.
Native claim/sample encoding rows are now prepared for 28 canonical aggregates
and 705 samples (733 secure values, 2,932 scalar connections), with exact
transcript read multiplicities and mutation rejection. See
[native payload evidence](../../autoresearch/notes/2026-09-22-native-blake3-payload-links/README.md).
Native PCS/DEEP preparation now evaluates the real capture with its authenticated
geometry (16,069 nodes, 34 zero outputs). All 705 samples have 2,820 explicit
shared scalar routes between composition, encoding and DEEP; the source rows
carry exact additional consumption counts. An arena ownership leak exposed by
the larger capture was fixed and covered by an allocation-growth regression. See
[native DEEP evidence](../../autoresearch/notes/2026-09-22-native-blake3-deep-join/README.md).
Native FRI preparation also evaluates the real capture (3,684 nodes, 94 zero
outputs) and constructs explicit DEEP-answer scalar routes, rejecting changed
answers and terminal coefficients. See
[native FRI evidence](../../autoresearch/notes/2026-09-22-native-blake3-fri-join/README.md).
Native transcript challenge routes now cover DEEP and FRI: 88 scalar connections
in this gate, including four shared OODS coordinates with exact additional
consumption counts. Missing FRI draws and altered DEEP randomness reject. See
[native PCS challenge evidence](../../autoresearch/notes/2026-09-22-native-blake3-pcs-challenges/README.md).
Native terminal coefficients now have canonical transcript encoding rows, using
the same scalar/pack/byte constructor as claims and samples. Missing receipts
and changed coefficient payloads reject. See
[native terminal evidence](../../autoresearch/notes/2026-09-22-native-blake3-terminal-encoding/README.md).
Native query preparation now connects transcript position bytes, all 31 shared
DEEP/FRI query bits, and FRI derived positions/offsets (104 scalar rows in the
one-query gate). Missing outputs and changed query values reject. See
[native query evidence](../../autoresearch/notes/2026-09-22-native-blake3-query-join/README.md).
All native trace/FRI paths now use the canonical shared builder, with 39,816 G
rows, 2,352 selector rows and 781 opening sources in the gate. Query rows account
for path/projection reads; successful replanning replaces counts and failures
restore them. The existing joined FRI fixture proof also passes the shared code.
See [native path evidence](../../autoresearch/notes/2026-09-22-native-blake3-paths/README.md).
All 781 native opening sources now have scalar producer rows with exact
arithmetic, encoding/packing and readonly-adapter use counts. The adapter derives
the required inventory from typed graph roles and rejects missing, duplicate or
changed sources. See
[native opening evidence](../../autoresearch/notes/2026-09-22-native-blake3-opening-producers/README.md).
Native root/nonce source rows now cover all transcript/path reads: 188 private
words and eight fixed preprocessing-key boundary words. The key root is checked
with the native statement-derived verifier; each nonce requires both its PoW
and absorption receipts. Changed roots/nonces and missing receipts reject. See
[native root/nonce evidence](../../autoresearch/notes/2026-09-22-native-blake3-root-nonce/README.md).
The native public-boundary graph now evaluates the verified BLAKE3 capture
through the existing canonical authority (4,351 nodes, 1,332 inputs, 21 zero
outputs). A changed published sum rejects. See
[native public-boundary evidence](../../autoresearch/notes/2026-09-22-native-blake3-public-boundary/README.md).
Public-boundary challenge sharing now routes 32 coordinates from the native
composition sources. A 116-input arithmetic graph enforces component aggregate
plus public-total cancellation with four independent zero outputs. Mutated
aggregate values, role mappings and stored boundary evaluations reject. See
[native public-link evidence](../../autoresearch/notes/2026-09-22-native-blake3-public-links/README.md).
Public wire/byte/selector source closure now emits 1,280 public coordinate rows
and sixteen private published-sum producers. Alongside the 32 challenge and four
total routes, these cover all 1,332 public-boundary inputs. The canonical native
statement encoder determines the exact transcript prefix positions and contents;
changed statement words reject. See
[native public-source evidence](../../autoresearch/notes/2026-09-22-native-blake3-public-sources/README.md).
The complete experimental native-child parent now proves and independently
verifies all five graphs (VM composition, DEEP, FRI, public boundary, aggregate
cancellation) through the eighteen typed AIR components. Exact producer admission
covers 8,376 arithmetic inputs and rejects duplicate/missing opening producers;
all three activation selectors are fixed to one. The joined witness has 86,464
BLAKE3 G rows, 7,093 scalar rows and 29,488 arithmetic rows. See
[native parent evidence](../../autoresearch/notes/2026-09-22-native-blake3-parent/README.md).
This gate uses an inner q1/PoW0 native proof and an outer q8/PoW0 parent proof.
Public statement operands still specialize preprocessing. The parent now has a distinct key-admission transcript binding its suite,
profile, child statement/configuration, five graphs, transcript plan, typed
roster/registry and fixed preprocessing root. A verifier-owned expected key
identity is mandatory. Wrong pins, versions, configurations, graph identities,
lifting presence and root substitutions reject; the full parent verifies under
this transcript. See
[native parent admission evidence](../../autoresearch/notes/2026-09-22-native-blake3-parent-admission/README.md).
The canonical in-memory artifact owner and witness-independent verifier are now
implemented. The verifier rebuilds typed components and column geometry from
the pinned key, consumes proofs on all paths, and returns an owned verified
capture. Compensated claim tampering passes cancellation admission but rejects
in core verification. Parent-specific claim absorption explicitly advances the
protocol to version 2 and rejects version-1 keys. See
[native parent verifier evidence](../../autoresearch/notes/2026-09-22-native-blake3-parent-verifier/README.md).
The bounded external codec now round-trips the real parent artifact
byte-for-byte (111,428 bytes) and feeds independent verification. Its fixed
372-byte header and body preflight enforce the verifier pin, canonical claims,
exact lengths, protocol configuration and allocation geometry before proof
decoding. Preflight and verification share one component owner. Malformed
headers, lengths, claims, configurations and commitment-count prefixes reject.
See [native parent codec evidence](../../autoresearch/notes/2026-09-22-native-blake3-parent-codec/README.md).
The standalone backend-injected producer now retains authenticated definitions,
relation plans, compiled component templates and fixed columns in a stable
per-key plan. Request metadata is checked before proving; scratch and proof
ownership are separate. The real artifact verifies after plan destruction, with
no allocator leaks and no plan-arena growth during the request. Shared row
projection has one canonical implementation. See
[native parent producer evidence](../../autoresearch/notes/2026-09-22-native-blake3-parent-producer/README.md).
Fixed host columns are reused; commitment-tree reuse and scheduler integration
remain pending. Admission permits only the diagnostic profile. A canonical
capture-preparation coordinator and production security-profile qualification
remain unfinished; this is not a production migration or statement-independent
key. Production defaults remain unchanged.

Remaining work: production capacity classes and overflow admission; production
child-proof source and reusable-key/artifact qualification; Metal support; and
CPU/Metal parent-of-parent qualification. Removing this specific source of
query-dependent preprocessing does not establish a complete reusable key.
Production recursion still uses Poseidon. New protocol/key/artifact identities must be admitted
explicitly; equal digest lengths do not authorize interpreting new proof bytes under
old keys.

The compact provider uses four bounded bytes per 32-bit word, preserving every
bit. Additions use bounded byte carries; XOR and rotations use canonical bitwise
and byte-pair tables. The shared typed arithmetic and relation compiler remain
the only constraint authors. Full construction reference:
[BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).

Retain guest-visible Poseidon precompile semantics when a program explicitly
requests Poseidon. Ethereum Keccak and structural SHA-256 artifact pins are
separate obligations. Migrating the prover's commitments does not authorize
changing the guest's program or making existing artifact identifiers ambiguous.

## Qualification and performance

The focused gate is `test-blake3-protocol` in the RISC-V CPU integration build.
It covers official primitive vectors across block/chunk boundaries, streaming,
independent protocol vectors, rejection boundaries, domain separation, a
nonconstant CPU PCS/FRI proof, tampered sampled-value rejection, every root byte's
high-bit mutation, wrong BLAKE2 family rejection, and matching final transcripts.
This target is PCS/FRI qualification. `test-blake3-framework` adds typed boundary,
export and padded interaction checks; `test-blake3-proof` produces and verifies a
compression and full-hash STARKs. None is a complete RISC-V or recursive parent proof.

Native diagnostic on M5 Max / 64 GiB, Zig 0.15.2 ReleaseSafe, six alternating
pairs, 2048 hashes per sample:

| Operation | Poseidon median ns/hash | BLAKE3 median ns/hash | Median paired speedup |
| --- | ---: | ---: | ---: |
| Leaf, 16 M31 words | 1786.45 | 204.56 | 8.76x |
| Leaf, 256 M31 words | 19687.54 | 1826.48 | 10.79x |
| Leaf, 4096 M31 words | 305724.42 | 27860.52 | 10.99x |
| Internal node | 595.38 | 160.38 | 3.70x |

These are single-message native API timings, not optimized batch/device paths,
not a profile-weighted workload, and not proof speedups. They include each
suite's own domain framing. Both use the same M31 leaf inputs; repeated nodes
use each suite's own digest chain. No build/proof work ran concurrently.
Samples and source pins are in
[`../../autoresearch/notes/2026-09-21-blake3-migration/README.md`](../../autoresearch/notes/2026-09-21-blake3-migration/README.md).

The next performance acceptance measure is complete same-statement,
same-security-profile leaf/parent/tree wall time with independently verified
outputs, including recursive witness generation, interaction work, commitments,
PoW, admission and bounded scheduling. Native savings must exceed the added
recursive bitwise constraints and lookup traffic. Do not claim the earlier
5.54-second Poseidon parent timing is now a BLAKE3 result.

Security parameter changes remain a separate experiment. Keep original
q193/16+10 recursive measurements distinct from canonical CSP 70-query/26-bit
results. No query or PoW reduction accompanies this foundation.
