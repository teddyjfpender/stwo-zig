# Direct provider verification before recursive closure

Task: verify every original provider proof once inside a bounded parent, without
first generating and then verifying an individual recursive wrapper. Preserve
the exact typed physical claims, source seal, first roots, independent template
selection and complete family/index roster. This is dependency-graph contraction,
not a replacement of proof verification by a host receipt.

Inputs are genuine original RAM-lane, range16, ROM and six-table lookup captures.
The retained Ethereum census has 622 base files. Native direct aggregation has
already removed one redundant layer; providers must use the same topology.
The existing provider adapters supply transcript, Merkle, FRI, DEEP and AIR
equations plus public wire schedules. Namespaces must be rebased disjointly
before joining their rows. The budget covers all live preparations and joined
columns; no per-provider recursive proof is created.

| Candidate | Relationship | Cost and risk |
|---|---|---|
| Existing wrapper forest | Reference implementation | Two proof layers for each base provider; large hash amplification |
| Direct heterogeneous base batch | Exact graph contraction | Original verifier equations once; sum of original work plus one aggregate proof; namespace/typed roster custody is critical |
| Omit source obligations after summing claims | Not equivalent | Unsound: terminal ROM, register windows and initial/final RAM sources require independent authentication |

Selected: direct heterogeneous base batch, then attach the complete global
closure equations and source proofs. [ZisK's independently instantiated AIRs](https://github.com/0xPolygonHermez/zisk/blob/1e22630bb7e143c30705a1603ed87cfd3da8c6ec/pil/zisk.pil)
provide an architectural analogy for sizing providers separately; no code or
speed ratio is transferred. The existing native-batch implementation is the
exact local row-joining precedent.

Prediction (hypothesis): remove one standalone wrapper proof per provider and
its subsequent verifier rows. This does not remove original provider-verifier
work. A complete bundle/root measurement, not a synthetic claim list, must
establish the benefit. Same seal and security are required across children;
family/index order is strict; omission, duplicate and family substitution are
rejected against an independently supplied expected roster. Child equations
continue to absorb every physical claim before interaction commitment.

Qualification: compile and unit checks for typed schedule/roster admission;
real mixed-family base proofs through the combined parent; changed claims,
roots, family, child order, source seal and proof bytes rejected. Independent
expected key selection remains mandatory. Test exact namespace ownership and
allocation failure cleanup. No benchmark runs while another lane compiles.

Outstanding complete-root obligations are explicitly in scope: the NativeV3
joint relation adapter; caller arithmetic/fused verification; terminal ROM
boundary; register window compensation; authenticated request census;
initial/final RAM source authentication; and final public job identity. The
existing V5 semantic join records these as pending. The direct provider batch
must remain typed as OPEN until the actual equations and source receivers are
attached and verified without external base proof files. An empty obligation
list or a supplied success boolean cannot issue standalone-root authority.

## Complete root checklist: original obligations and intended authority

The final artifact is one verifier STARK plus bounded public metadata. Checking
cheap algebra on ROOT-PUBLIC values in the standalone verifier is sufficient;
it need not be another recursive arithmetic graph. Every such value must be
bound to an actual included child-verifier equation. A producer-generated
receipt, unkeyed digest or success boolean is not a substitute. Metadata scales
with the exact proof roster and cannot be advertised as constant-size.

| Obligation | Existing authoritative check | Planned final root binding/check | Status |
|---|---|---|---|
| Exact source seal and all-family roster, including typed absence | `block_v5_source_seal_v1.zig:seal/Sealed.require`, `block_v5_global_receiver_impl_v1.zig:Pins.validate` | Root-public job/seal, exact family/index/roots/template roster; independently derive family counts and require every original proof or explicitly versioned replacement exactly once | Provider-batch subset implemented; full roster pending |
| Security and expected verifier programs | Original per-family recursive admissions and expected-key factories | Standalone policy chooses each source/template and config independently; received proof/metadata cannot choose an arbitrary expected recursive key | Batch explicit key/roster check implemented; complete independent root factory pending |
| Native instruction semantics and all physical lookup claims | NativeV3 plus fused companion verification in `block_v5_program_native_batch_common_v1.zig`; replacement B6JP-v3 | One joint child binds exact partition layout, direct opcode/clock equations, integer/byte memory bridge and physical claims; derive accounting exports only from that child | B6JP-v3 agent lane; integration pending |
| Per-execution state closure | `block_v5_native_table_join_impl_v1.zig:finish`, `Algebra.states` | Native state/compensation plus caller state close separately for EACH execution; no cancellation across executions | Pending joint/caller export mapping |
| Local register windows and compensation | `block_v5_register_windows_v1.zig`, table join `requireRegisterWindowsClosed` | Root-public ordered register endpoint windows, independently derived compensation using exact original global challenge epoch; each window closes independently | Pending |
| Six lookup kinds and exact requester group coverage | Table join `finish`, `block_v5_global_join_algebra_v1.zig:lookupGroup` | Six provider claims authenticated by lookup child; joint/caller requests and byte claims selected by independent `first_execution/execution_count` plan; close each kind in each group | Provider claim binding implemented; complete requester mapping pending |
| Ordinary and precompile RAM accesses, byte requests and exact census | `block_v5_word_memory_join_impl_v1.zig:finish`, table join byte-demand check | Original frame/index/event counts, integer/byte partition totals from joint/caller child; enforce exact `sidecarMemoryDemand` count and one inclusion per request | Pending |
| Sorted RAM transition/link, initial/final source sums and range groups | `block_v5_ram_lanes_receiver_v1.zig`, `block_v5_memory_source_page_join_owner_v1.zig:verify` | RAM child exposes all sums and counts. Range children close the exact planned instance slices. PAGE/source child authenticates initial/final sums; require predecessor/link zero and source signs separately | Direct RAM/range binding implemented; source and range-closure wiring pending |
| Complete ELF ROM and terminal unretired fetch | `block_v5_program_boundary_v1.zig:deriveFromPinnedNativePublic`, original program receiver | ROM child binds complete program root and fetch census; root-public native/caller program claims plus independently derived boundary fetch term close against it | ROM child binding implemented; terminal/requester mapping pending |
| Ordered execution/PC/clock coverage | `block_v5_pc_clock_span_v1.zig:leaf/merge`, global receiver `blockSpan` | Root-public spans and counts reconstructed from independent execution admission; contiguous coverage, correct initial/final PC and no null padding | Existing native-batch edge equations; joint root mapping pending |
| ELF/input admission, initial RAM and public output | `block_v5_rw_endpoint_sources_v1.zig:check`, `block_v5_memory_source_page_join_owner_v1.zig`, original public-data admission | Independent expected job binds ELF/input/program and initial/final root/output contract; included PAGE/FOLD source-verifier equations authenticate source and endpoint data; root checks same epoch and source identity | Pending; do not use host `Sources.check` result as a recursive source proof |
| Caller/precompile arithmetic, physical claims and register/RAM coupling | `block_v5_precompile_family_proof_v1.zig`, caller fused recursive admission/bus | Include genuine caller arithmetic and fused bridge verifier equations directly, preserving per-call identity, program/state/table/memory claims and event/frame counts | Existing original adapters; direct inclusion pending |
| Final residual accounting | `block_v5_global_receiver_impl_v1.zig:verifyFreshSelected`, `Algebra.residual` | Original signed accounting over authenticated root-public values ONLY after every scoped bus/census/source check; native+caller+program+table+memory opposites−aux clock+register compensation+bytes = 0 | Pending; aggregate zero alone never suffices |
| No detached base-file dependency | Current `VerifiedNativeBatchBundle` still freshly loads all globals | Final `verifyRoot` consumes root proof, independent expected policy and public metadata only; remove/alter every base file after proving and verify cold successfully | Pending; current provider receiver is deliberately an OPEN batch |

Source PAGE uses the original word-memory challenge prefix and its authenticated
extension epoch. Reusing an older source-auth challenge epoch would not close
the RAM equations. Source-only PAGE forest summaries should be combined with
the direct RAM/range verifier rows; using the old source+RAM forest AND direct
RAM/range rows would duplicate proofs again. Final closure must account for
this explicitly rather than stacking both architectures.

## Implementation evidence and failures uncovered

The four-family direct batch exports prepared rows, typed public wires and
claims; callers can join these before proving, so its standalone batch proof
is a qualification option, not an architectural requirement. The auxiliary
direct preparation does the same for original caller arithmetic, caller fused,
raw PAGE and fold PAGE. It retains original owned public frames and PAGE's
eight-root grammar instead of coercing them into the provider two-root schema.
Both are OPEN equations until the final root authenticates the complete roster
and runs every scoped check above. Auxiliary index/template labels alone do
not replace reconstruction of original public statements by root policy.

The first real range16 + ROM mixed proof exposed two original defects before
batching could qualify: empty-tree Merkle captures returned uninitialized
storage, and recursive DEEP rejected every zero-column tree although the
original complete-ROM proof has a valid empty main tree. The capture fix
preserves the original empty-tree verifier convention (which does not itself
check an empty root); the ROM admission independently recomputes its fixed and
empty main roots. Recursive geometry must keep that empty tree's transcript
slot while producing zero opening/hash work and zero path-root multiplicity.
It must not fabricate a main column or omit the root's transcript absorption.

The PAGE live path emitter also still accepted only four/five commitments,
despite PAGE fixed setup and hash layout admitting ten. The explicit live PAGE
entrypoint is selected from the original admitted child type and requires
exactly ten, leaving generic native entrypoints unchanged. These fixes remain
qualification work until the real mixed proofs pass; no speed result is
inferred from compilation or from synthetic public metadata.

### Direct mixed assembly (implementation, qualification pending)

`block_v6_mixed_direct_prepare_v1.prepareDraining` composes the partitioned
native verifier, direct global-provider batch and caller/PAGE verifier rows
before any intermediate wrapper proof. The exact flattened typed roster,
original public supplies and all namespaces remain distinct. Preparation clones
public frames and drains wide row columns into one owned aggregate. All input
owners must still be destroyed after success or failure; the result is independent
of their lifetimes. Preparation requires at least two pieces; callers already
holding one complete piece do not need this joining API.

The mixed protocol authenticates open original equations. Its independently
admitted key binds the complete roster and public wire schedule. It does not
claim that authenticated open scalars constitute a closed block. The final
receiver must reconstruct every original statement and close the checklist above,
including source PAGE equations and all per-scope/census conditions, before
publishing block authority. This metadata is O(roster), not constant-size.

The four-provider direct proof gate now passes in ReleaseSafe with diagnostic
q8/PoW0 configuration: actual range16, sorted RAM lanes, ROM and native lookup
base proofs become one parent proof with no intermediate family wrappers.
Original captures and admissions are destroyed before parent proving; fresh
verification rejects a missing child, wrong expected key and modified range
claim. This qualifies that direct assembly mechanism, not complete block closure
or canonical-security performance. The mixed typed-roster/schedule negative gate
also passes. The actual PAGE-to-mixed-parent gate subsequently passed in both Debug and
clean stripped ReleaseSafe (all six tests; details below).

The first PAGE test build revealed a development-loop bottleneck outside the
prover: LLVM spent its sampled time generating DWARF variable histories for the
expanded verifier. Correctness builds can retain ReleaseSafe checks and use
`-fstrip` to omit debug metadata. This does not change the proof protocol; it
reduces compiler work and sacrifices symbolized diagnostic stacks for that run.

The genuine source gate found two producer defects, rather than an invalid
recursive profile. PAGE's OODS adapter expected nine trace-tree sample lists,
while the shared verifier passes those nine plus the composition-tree samples.
It now accepts and checks the exact composition-column shape without treating
those samples as child masks. FOLD table multiplicities were copied in logical
tuple order although fixed and interaction columns use committed circle order.
The FOLD collector now calls the same `committedColumn` conversion as the working
RAW producer. No constraint, transcript challenge or security parameter changed.
The focused regression exercises actual padded and nonempty FOLD collections,
requires a nonuniform multiplicity moved by the permutation, and rejects the old
logical-order column mutation. All three tests pass. The original RAW and FOLD
proofs now pass publication's encode/decode and independent original verifier;
the full source-to-parent gate also passes all six tests in Debug. It
reconstructs the original source algebra, rejects a missing page and changed
claim, prepares both original verifier row sets, and joins them before a single
parent proof. The original decoded base proofs and captures are destroyed and
the proof files deleted before that parent proof is created. The encoded parent
is decoded and independently verified; changing the source public statement
rejects it. This fixture has an empty source but real padded SHA streams, the
root FOLD and all ten original tree commitments. It does not exercise a complete
Ethereum execution, and q8/PoW0 remains diagnostic security. After removing all temporary production diagnostics, the clean stripped
ReleaseSafe build also passes all six tests. The separate original PAGE
shape/codec/allocation suite passes all twenty tests in ReleaseSafe.

The source-only parent test retains cloned canonical public values from the
original independent PAGE admissions. It does not yet round-trip PAGE claim
metadata through the detached mixed codec and reconstruct those admissions from
an external job manifest. The codec already has all-family malformed/allocation
tests and a genuine four-provider round trip; the full assembled block gate
must jointly exercise PAGE claim decoding, independent source context and rows,
all provider families and final global closure. This source gate is not a
substitute for that complete detached receiver qualification.

### PAGE admission and collection for the complete mixed root

`block_v6_source_recursive_admissions_v1.Owner` now owns the independent source
context, deep-copied fold descriptors/recipes and fresh immutable original AIR
setups. Its `create` entrypoint needs only normative context and descriptor
metadata; it retains no producer job or proof. `createFromJob` is a bounded
migration helper: it loads original fold operand files against their exact
stored pin, derives only the original recipe scheduler's public metadata and
checks the independently selected page inventory digest and geometry. It does
not rebuild wide hash witnesses or treat operand hashes as proof authority.

`block_v6_source_recursive_collection_v1.collect` strictly decodes and freshly
captures every RAW/FOLD proof in that independent roster, then prepares original
recursive verifier rows without proving wrappers. Each page becomes one owned
auxiliary piece and one canonical claim record; base proofs and captures are
released page by page. The helper caps source pages at the mixed-root limit of
64, bounds metadata, setup, capture and aggregate collection memory, and never
truncates a roster. The root coordinator must additionally count all native,
provider and caller children against that same 64-child limit. Independent
admission ownership and collected rows have separate lifetimes so the producer
job can be destroyed before detached verification.

### Independent PAGE and caller-fused fixed setup

The PAGE fixed roster now retains a namespace plan derived from its original
immutable arithmetic lowering before those graph owners are released. This
includes the legacy inverse/linear circuit identifiers stored in MAIN; a
fixed-column-only scan would omit them. The shared auxiliary singleton adapter
replays the exact first namespace relocation, wire schedule and auxiliary
context transcript, and exports the resulting complete identifier set for the
outer mixed relocation. It accepts no manufactured private witness or capture.

The caller-fused compiler independently reconstructs the original component
masks, symbolic composition equations, DEEP and FRI graphs, arithmetic lowering,
original transcript grammar, all five commitment PCS paths, source ports, public
schedule and fixed row roster. Its auxiliary adapter shares the PAGE transform.
Typed `validateLive` compares every fixed row, wire, context and namespace domain
against actual independently verified preparations. Both complete code paths
pass semantic compilation; their end-to-end fixed/live equality remains an
explicit qualification gate. These compilers do not grant block authority or
remove the final mixed key's independent factory obligation.

Actual collection can additionally compare cold and live fixed preparation with
`STWO_BLOCK_V6_QUALIFY_FIXED_PARITY=1`. The check uses the real decoded child and
its independent admission; it adds no wrapper proof. PAGE and caller-fused hooks
compare all fixed rows, typed wires, context identities and namespace domains.
It is off by default, rejects unknown option values, and cannot turn a failed
comparison into proof authority. Cold-factory source and collector hooks pass
forced semantic analysis; actual equality is reported only by successful live
comparison receipts, not compilation.

A collection parameter named `row_capacity` was also found to feed transcript
rejection-attempt capacity, rather than trace-row capacity. Its default of
`1 << 23` was therefore inappropriate. The coordinator changed it to the explicit
`circuit_capacity = 2`, matching the existing native/PAGE and focused provider
routes. Trace-memory and row-count limits remain separate. No end-to-end speedup
is claimed from this correction without a matched completed run.

### Exact capture geometry units

The genuine mixed run exposed a unit mismatch in original caller capture
validation: manifest logs describe raw trace domains, while the PCS capture
records FRI-extended evaluation domains. Arithmetic, fused and readonly caller
captures now share an exact checked `raw_log + configured_blowup` comparison,
retaining each route's original error and exact column count. A broader audit
found the same mismatch in incremental native capture and corrected its
configuration forwarding. Already extended PAGE, partitioned, capacity-fused
and incremental Ethereum checks were not extended twice.

Two focused ReleaseSafe regressions pass: one obtains captured geometry from
an actual PCS verifier commit and rejects raw, truncated, changed and
arithmetic-overflow logs; the other exercises incremental-native validation
and rejects raw logs independently in every trace tree, a truncated tree
roster and an empty composition tree. These are shape-validation corrections,
not changes to AIR equations, transcript binding or verification authority.

### Fixed-root verification lifetime

The real two-segment fixture published and freshly verified both nonempty RAW
pages and both nonempty FOLD pages. Both RAW pages also matched the independent
cold fixed compiler exactly. The subsequent FOLD recursive preparation reached
an allocation limit; full mixed-root qualification remained pending at this
checkpoint. PAGE capture now reports its own budget exhaustion separately from
backing allocator exhaustion, and the collector identifies the failed family
and phase.

Independent fixed-root checking no longer retains all temporary evaluation trees
simultaneously. It checks each original pinned root and destroys that temporary
PCS scheme before the next group, preserving the original channel mix order.
This helper is explicitly the legacy Blake3 suite: its roots do not depend on
commitment ordinal, unlike revision profiles with index-specific lifting. A
ReleaseSafe regression compares every root and the complete channel against the
previous grouped implementation, verifies lower charged peak memory, and rejects
changed roots and roster length. Real PAGE verification uses the same checker;
no fixed commitment check is skipped or replaced by a host receipt.

The next diagnostic isolated the FOLD preparation allocation failure to the
public-claim validation path, not the capture or collector cap. PAGE validation
was reconstructing its wide original graph and fixed columns through the
admission metadata allocator (320 MiB in this fixture). The shared public-value
constructor now supplies its bounded live-work allocator to PAGE's explicit
validation hook. Metadata ownership and every original admission/root/equation
check remain intact. Other family policies retain their existing signature.
A genuine PAGE regression clamps the admission allocator to its measured
metadata-validation peak and reconstructs actual claims through a separate live
budget; this is invoked by the real source-direct fixture and passes forced
semantic compilation pending its next actual execution.

The subsequent genuine mixed fixture passes all four PAGE cold/live comparisons:
RAW indices 0/1 and nonempty FOLD indices 0/1. It also passes the actual FOLD
constrained-admission scratch regression before proceeding to native/provider
preparation. Capture, per-page preparation and collection caps remain unchanged
at 512 MiB, 4 GiB and 8 GiB. The public-claim path now retains only one original
wide recipe at a time, with explicit nonnull composition admission; captured
frames still undergo their full independent geometry/log/constraint comparison.
This qualifies those PAGE paths, not the later complete mixed root, which is
reported separately by the assembled integration result.

### Caller-fused original mask geometry

A focused original SHA1/Keccak1 component fixture exposed two recursive shape
assumptions before another complete run. The shared caller root-owner uses
current/+27 openings at the composition-domain step; a separate physical-step
Keccak family already existed. They now have distinct layout tags (7 and 6),
exact independently derived mask logs, and separate strict capture checks.
The original component masks select the cold verifier graph; received sample
points cannot select their own layout.

The same original roster contains committed columns with no openings at log13,
while the largest sampled trace is log7. Core PCS deliberately ignores empty
masks when computing FRI lifting. Recursive DEEP now preserves these committed
columns while permitting a wider domain only for `.none` layouts; sampled
columns remain bounded by lifting. Native quotient/DEEP differential tests cover
both Keccak layouts with an unused wider column and reject changed samples,
wrong steps, invalid domains and changing the unused column into a sampled one.
The exact original-mask and independent cold-shape fixture passes (4 tests).

That small fixture's census is 10,799 sampled columns / 307,752 raw cells and
4,340 unsampled columns / 103,062 raw cells, with FRI blowup log1. Thus unsampled
columns account for 25.09% of this fixture's committed raw cells, not an order of
magnitude. This is a structural census, not a performance measurement or
permission to remove them from the original commitment protocol.

## Tall committed trees above the sampled lifting domain

The actual caller-fused preparation reached a further original-geometry gap:
some committed columns have no OODS samples and are taller than the FRI lifting
domain. Native PCS still authenticates their Merkle openings, expanding the
query index as `(position >> 1) << (tree_log - lifting + 1) | (position & 1)`.
The recursive query linker previously rejected this valid case.

The shared `blake3_query_links.traceBit` now supplies that exact map to trace
Merkle directions, live projected-index columns and independent fixed PCS
ports. Inserted low coset bits consume the DEEP query bit at `lifting`; the
DEEP graph now constrains this anchor to zero only for independently admitted
profiles containing a taller committed column. A free Boolean bit is not
sufficient. Legacy profiles without tall columns keep their existing graph.
Frontier multiplicities follow the actual mapped top direction too.

Focused ReleaseSafe evidence: exhaustive query-map equality against native PCS
for lifting logs 1–8, tree heights 0–10 and every raw position; exact live/cold
projection rows, ports and use counts including taller trees; legacy packing
regression (three tests). The separate DEEP gate mutates the zero anchor to one
and recomputes the arithmetic witness, then observes the constraint failure.
The real all-provider capture/preparation gate subsequently passed all 12 tests:
two native executions, all four provider families and both caller families,
including exact caller-fused cold/live fixed parity. This exercises genuine
original proofs and captures, not synthetic success receipts. Its 33.06-second
duration includes independent setup checks and is diagnostic, not production
throughput. The complete block-root proof gate remains separate and pending.
