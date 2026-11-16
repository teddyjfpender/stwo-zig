# RFC draft: origin-specific waist error codes at real boundaries

Status: the exact first-consumer transaction was approved by the coordinating
implementation delegate under the user-directed D2 scope: [decision](https://github.com/teddyjfpender/stwo-zig/issues/360#issuecomment-6750967254).
This records a delegate decision, not a new owner/user signature. Full D2 remains
incomplete; all remaining coverage obligations below are retained. Slice: [#359](https://github.com/teddyjfpender/stwo-zig/issues/359).
RFC: [#360](https://github.com/teddyjfpender/stwo-zig/issues/360).
Census source: `27ed1d34894c554fcdaf91af3c4eae331ea242ac`.
Owners for the first transaction: `protocol-core`, `circuit-recursion` and
`circuit-cpu-integration`, with the Cairo recursion CPU product owner.
Named accountable owner: `@teddyjfpender`. A coordinating delegate's review is
recorded as a delegate decision, never as a new owner/user signature.

## Full D2 destination and first transaction

The destination remains plan section 7.3: stable u16 code tables owned by all
five waist packages, used at their actual process and wire boundaries; an
append-only meaning/class/since ledger and executable consumer contracts.
Existing internal errors are not all converted into one global error union.
Public `Error` aliases for the declared coded boundaries remain a completion
obligation; no partial alias is advertised as all possible package failures.

The first proposed transaction introduces two codes at one existing decoder
origin and carries them to its existing verification verdict and CLI. It is a
necessary stage, not completion or redefinition of D2. No unused provider table
is published for a package merely to mark a checklist complete.

## Source census and origin ambiguity

The comment-stripped literal census below counts `error{...}` declarations and
inline signatures. It does not expand imported aliases, generic instantiations,
allocator/I/O errors or inferred error unions. Counts of unique literal tags
are per package, not a disjoint global taxonomy.

| Waist package | Literal sets | Unique literal tags | Existing exported/reachable authorities |
| --- | --- | --- | --- |
| core | 33 | 77 | `verifier_types.VerificationError` (14 own tags plus FRI7 and lifted-Merkle5); field, shape, AIR/constraint, domain and PCS errors |
| backend | 6 | 42 | arena-plan12, recovery6, proof-program16, native-AIR6, line-evaluation2, secure-column1; tag overlaps reduce the union |
| prover_api | 2 | 7 | `QuotientOpsError`3 and work-profile4; inferred task reservation/lifetime errors are additional |
| proof_wire | 1 | 5 | `ForField/ForHasher.CodecError`; JSON parser, FRI config and allocator errors also escape decode |
| recursion_wire | 9 | 24 | circuit binary decode/shape/config, felt stream, JSON, registry/query, packed node, decimal felt and postcard preflight |

For example `ShapeMismatch` belongs to core verification, quotient geometry and
circuit encoding; `ValueOutOfRange` occurs in different codecs. The same Zig
error tag does not establish the same owner, stage, class or recovery action.
`@intFromError`, an alphabetically generated ordinal and a global `anyerror`
switch are forbidden as stable wire identities.

Source anchors at the census revision:

- `core/verifier_types.zig:41`, `core/fri/config.zig:114` and
  `core/vcs_lifted/verifier.zig:8` define the verification union.
- `backend/{arena_plan,recovery,proof_program,proof_program_native_air}.zig`
  declare independent planner, storage and proof-program contracts.
- `prover_api/column.zig:6` defines quotient errors; `engine.zig:86` retains the
  first diagnostic cause, and `task_profile.zig:125` retains `error_name` plus
  cancellation winner/reason and cleanup status.
- `proof_wire/family.zig:75` declares five codec tags. Its JSON decoder uses
  strict unknown-field parsing; its binary decoder rejects trailing data.
- `recursion_wire/circuit_serialize.zig:162` explicitly returns
  `DecodeError || ConfigError || Allocator.Error`; decoded proofs keep existing
  ownership and consumed-byte semantics, including permitted trailing bytes.

## Exact first mapping and public provider ledger

Reserve the documented code bands below; reservations do not create runtime
exports or promise coverage. Code0 and all unallocated codes have no meaning.

| Owner | Band | First-transaction state |
| --- | --- | --- |
| core | `0x1000..0x1fff` | shared metadata types only, immediately consumed below; core error mappings pending |
| backend | `0x2000..0x2fff` | no table/API added; mappings pending actual origin capture |
| prover_api | `0x3000..0x3fff` | no table/API added; mappings pending origin and cancellation contracts |
| proof_wire | `0x4000..0x4fff` | no table/API added; codec/parser/allocation origins remain pending |
| recursion_wire | `0x5000..0x5fff` | only the two circuit binary decode entries below |

| Provider and exact origin | Original error retained | Code u16 | Class | Since |
| --- | --- | --- | --- | --- |
| recursion wire, `circuit_serialize.deserializeProof` | `NotEnoughData` | `0x5001` (20481) | `invalid_input` | `0.2.0` |
| recursion wire, `circuit_serialize.deserializeProof` | `ValueOutOfRange` | `0x5002` (20482) | `invalid_input` | `0.2.0` |

Add exactly one root export `error_codes` to core and recursion wire; retain
all existing exports and signatures. Core's new `error_codes.zig` provides:

- `Class = enum { invalid_input, verification_failed, resource_exhausted,
  unsupported, internal }`, serialized by these strings, never enum ordinals;
- `Entry = struct { tag: []const u8, code: u16, class: Class, since: []const u8 }`.

Recursion wire's new `error_codes.zig` provides immutable `table` with exactly
the two rows, `fromCircuitDecode(circuit_serialize.DecodeError) Entry` and
`lookup(u16) ?Entry`. It uses core's metadata types through the existing core
dependency. It does not accept arbitrary `anyerror`, parse an error-name string,
map JSON/shape errors or invent a numeric fallback. Existing binary decoder
signatures and their errors remain untouched.

Codes and meanings/classes are append-only and never reused. A deprecated
meaning retains its tombstone for archived diagnostics. `since` is the package
version first declaring the mapping in repository history, not a claim of
qualified publication. A new mapped meaning is additive; changing or reusing a
meaning/class requires the normal breaking-contract review, not a table edit.

## Actual boundary consumers and exact process behavior

`src/integrations/circuit_cpu/verify.zig:54` already consumes this decoder.
It returns `Allocator.Error!Verdict`, with rejection `stage` and original
`reason`. Only allocation failure is a thrown error. Propose one additive
optional `wire_failure: ?core.error_codes.Entry = null` field on the rejected
payload. Populate it only at the existing `deserializeProof` catch for the two
typed decode tags. Preserve `stage=.deserialize`, the original reason, every
allocation/deinit path, and the existing `OutOfMemory` propagation.

Do not populate it in the generic `reject(stage, reason)` helper. The subsequent
`verifier_proof.circuitVerifierValues` catch can have the same stage/tag from a
different origin and must remain unmapped. Config/shape/layout/build/circuit
rejections remain unchanged and explicitly outside these two code entries.

`src/products/cairo/recursion/cpu/app.zig:764` is the existing process consumer.
Keep its current accepted/rejected stdout bytes and return verdict. Add one
bounded stderr JSON line only when the verdict carries the owned mapping:

```json
{"schema":"circuit_decode_rejection_v1","provider":"stwo_circuit_recursion_wire","origin":"circuit_serialize.deserializeProof","code":20481,"class":"invalid_input"}
```

This is a scoped diagnostic receipt, not a proof-wire envelope or global process
error ABI. No new flag, launcher, environment reader, install boundary or
stdout framing is introduced. No in-repository parser of this new stderr line
currently exists; none is fabricated to claim consumer coverage. Its actual
consumer integration is the CLI's use of the owned verdict metadata, exercised
through existing product tests and a bounded process contract.

The existing exit matrix stays exact: success0, CLI usage2, execution/allocation
error1, rejected verification3. A class alone does not choose an exit: malformed
proof bytes remain rejected verification3, while a malformed CLI request stays
usage2. Diagnostic formatting uses bounded storage without allocation. A failure
to write optional diagnostic stderr must not replace the primary rejection or
turn it into an accepted proof; stdout/error and exit behavior remain authoritative.

Unknown code lookup returns null, including0, another package band and65535.
No caller may infer a class or retry policy from an unknown number. A future
receipt reader must reject contradictory provider/origin/code/class pairs as
unsupported diagnostics while retaining the original failure. In this stage
unmapped rejections retain their existing text and exit with no fabricated code;
absence of a coded receipt is not success or evidence of D2 coverage.

## Five-package coverage ledger and remaining actual consumers

| Provider boundary | Real existing consumer/serializer | First-stage coverage | Remaining D2 obligation |
| --- | --- | --- | --- |
| core verifier/FRI/Merkle | Native artifact verifier dispatch; CPU RISC-V full-width verifier; circuit verification/build | none | capture exact call origin and preserve cryptographic vs structural refusal classes before assigning table entries |
| core field/AIR/domain/shape | backend/frontend/engine callers; circuit proof config | none | distinguish internal contract defects from caller input at the boundary; do not global-map shared tags |
| backend arena/recovery/native-AIR | `backends/metal/arena_plan.zig`, `protocol_recipes.zig`, backend/engine proof-program callers | none | carry planner/storage origin through real failure diagnostics; preserve resource cleanup and avoid adding codes solely for unused capability declarations |
| prover API quotient geometry | `engine/prover/pcs/quotient_column_geometry.zig` and quotient planning/providers | none | preserve first cause/subphase; no exception-to-success or retry conversion |
| prover API task/work/lifetime | `engine/prover/task_graph_profile.zig:430` writes task `error_name`; recursive CSP producer failure report | none | preserve cancellation winner/reason, generations and cleanup; version profile/attempt readers together before changing structured fields |
| proof wire JSON/binary/family | Native artifact verifier, Native interop command, circuit/RISC-V consumers | none | five explicit tags plus parser/config/allocation origins need actual consumer-driven mappings; unchanged valid and negative bytes |
| recursion circuit binary decode | circuit CPU `verifyProofBytes` -> Cairo recursion CLI verify | two typed decoder tags | shape/config, allocation and other deserialize origins remain unmapped |
| recursion felt/JSON/registry/request/postcard | Cairo recursion product; RISC-V recursion/circuit input adapters | none | retain their different consumed-byte/trailing-byte, nullable JSON and resource-bound refusals; no accidental format normalization |

The existing `rv64-ethereum-rejected-batch-v1` serializer writes a free-text
failure; the recursive CSP attempt serializer writes `stage/error_name` and its
Python `canonical_producer.py` reader validates exact failure keys. They are
real later process consumers, not edited in this first transaction. Structured
field changes there need a versioned producer/reader transaction. Likewise
existing Native/RISC-V successful verify receipts are not converted into a
new shared failure ABI.

D2 is complete only when the declared live process/wire boundaries for all five
providers have reviewed mappings, aliases/table ownership, unknown-code and
resource/cancellation behavior, their actual consumers, and required contract
tests. Unmapped boundaries stay visible in this ledger. D3 CDC infrastructure,
D5 budgets and final Phase1 exit are independent obligations.

## Versions and D1 sequencing

D1 PR #356 is a prepared, unmerged/unpublished RC candidate. Per the coordinator's
sequencing decision, first review/land necessary additive D2 providers on current
0.x versions, then amend RFC #355 and refresh the RC freeze to the resulting
actual ledgers. Keep #355's old hashes as historical proposal evidence.

The exact first-stage version transaction would be core `0.1.0 -> 0.2.0`,
recursion wire `0.1.0 -> 0.2.0`, and circuit CPU integration `0.2.0 -> 0.3.0`
(the public Verdict payload gains an optional field). Their manifest/README facts
must match. Core's ledger29 ->30, recursion wire11 ->12; the integration still
exports the same nine root names, but its nested additive API is versioned.
Backend/prover API/proof-wire versions and ledgers are unchanged in this stage.
All dependency paths, injections, distribution statuses and wire revisions stay
exact. No `1.1` detour, silent patch bump or final1.0 declaration is proposed.
Additional provider mappings need their own exact subsequent version transaction.

## Tests first, budget and rollback

Before implementation, add provider goldens for every code/tag/class/since row,
uniqueness and band membership; validate unknown and foreign codes return null.
Add signature checks for the typed mapper and shared metadata. Prove that a
same-named error from an unowned catch is not annotated. Keep the existing
malformed/truncated/noncanonical decode and allocation-failure corpus unchanged.

Consumer tests must pin stage/reason and metadata for both coded errors, and
prove config/shape/other-origin/OOM behavior remains exact. Product tests pin
stdout, stderr JSON fields and exit0/1/2/3; accepted proofs emit no rejection
receipt. Check optional diagnostic output failure retains the primary verdict.
Existing proof/transcript/serde golden bytes and cleanup/cancellation tests stay
mandatory. Run hosted Debug/ReleaseFast provider and CPU product gates; no GPU or
heavy laptop compilation. A source/model test is not a process receipt.

This preparation deliverable changes documentation only: code0,flags/scripts0.
Proposed first implementation allowance: <=320 net Zig/table/test lines, with
runtime/table plumbing<=100; remaining growth owns exact provider/consumer and
negative contracts. Configuration/version/ledger/budget facts and documentation
are measured separately. No top-level launcher or general schema registry.
If the reviewed design cannot fit, stop and revise its scope/budget before code.
Before publication revert the first transaction as one unit. After publication
preserve assigned code tombstones; never recycle a code, alter an error meaning,
relax a decoder or remove a negative test to make a mapping pass.

## 2026-11-13 bounded origin transactions

The standing owner instruction authorizes necessary bounded amendments. The
implementation delegate recorded exact additions in RFC #360 before editing;
this is delegated authorization, not an independent owner/security signature.
The older first-transaction tables above remain historical scope, not a claim
that the later origins are unimplemented.

| Provider / actual origin | Stable meanings | Live consumer wiring | Executed evidence |
| --- | --- | --- | --- |
| Core `FriConfig.init` | `0x1001` invalid last-layer bound; `0x1002` invalid blowup; both invalid_input, since rc.2 | Native interop `pcsConfigFromCli` exact typed catch rethrows original error and optionally emits bounded stderr | Three direct metadata/config tests in Debug and ReleaseFast; whole Native process remains pending |
| Backend `arena_plan.build` | `0x2001`–`0x200c` twelve arena structural errors; `0x200d` allocator failure, since rc.2; budget/OOM resource_exhausted | Metal arena-plan runner exact build catch emits optional stderr, then the original failure JSON writer and return | Entire 26-test Backend provider and private formatter both modes; full Metal process remains pending |
| Prover API quotient admission | `0x3001` shape, `0x3002` column log, `0x3003` column length, invalid_input, since rc.2 | Existing QM31 and OM31 lazy-provider checks annotate a borrowed per-attempt sink on the consumed PCS scheme; diagnosed proving retains nullable `ProveDiagnostic.code` | Ten direct API/first-cause tests and actual two-field consumer test (plus its two discovered anonymous checks), both modes; complete Engine/product process remains pending |
| Proof wire JSON/binary | Five literal codec meanings `0x4001`–`0x4005`, since rc.2 | Native artifact decoder exact owned diagnostic catch | Canonical package 21/21 tests in each mode, including physical binary mutation/OOM; whole Native process pending |
| Recursion circuit binary | `0x5001` NotEnoughData and `0x5002` ValueOutOfRange, since 0.2.0 | Existing circuit CPU verdict and Cairo recursion CLI | Previously retained provider/consumer evidence; canonical hosted lane qualification is a separate gate |

Core, Backend and Prover API additions advance their unpublished candidate
versions from `1.0.0-rc.1` to `1.0.0-rc.2`. Backend and API each add one root
export, `error_codes`; Core already exports that module. The diagnostic field
is host observability metadata, not a new proof/transcript/wire member. No
ColumnEvaluation layout, validation pass or recorder mutation was added.
Original constructor wrappers remain and pass a null sink for ordinary proving.
Only exact owned checks write a code; generic component/backend errors and OOM
in quotient construction stay unmapped. The Native private formatter extraction
retains existing proof-wire stderr bytes and has no public helper ABI.

Local receipts record explicit optimization for every Zig module. Provider and
consumer execution is not inferred from import declarations or compile-only
success. Guard peaks were below 400 MiB, with no GPU use. The runtime receipts
and raw logs are retained outside the repository under `/tmp/stwo-d2-*.json`
and `/tmp/stwo-backend-d2-*.log`; they are local evidence, not portable artifacts.
The canonical hosted five-provider graph and real process receipts still have
to qualify the committed source.

At the rc.2 checkpoint, remaining full-D2 coverage included Core verification/FRI/Merkle failures,
backend recovery/native-AIR, prover work/task/lifetime failures, JSON parser and
configuration/allocator decode origins, and recursion felt/postcard/request/
registry/config origins. In particular, no global `anyerror` mapper was added
and no same-named caller error is reclassified. The optional versioned CSP stderr/sidecar framing is now implemented. Primary
v3 structured failure payloads remain unchanged; adding codes there still
requires a versioned framing decision. These boundaries are not waived by five nonempty code bands.

## Core verification continuation after checkpoint 204639fff

The delegated RFC #360 continuation adds `PcsVerificationError`, the exact typed
`VerificationError || Allocator.Error` boundary of PCS verification. Codes
`0x1101`–`0x111a` pin the existing verifier/FRI/lifted-Merkle meanings; `0x111b`
pins PCS allocation failure. The candidate Core version advances to rc.3 and
Native examples to 0.2.0 for nested additive methods. The rc.2 configuration
entries retain their original codes and since values; no root export names,
dependencies, proof/config wire fields or transcript draws change.

Opt-in `verifyDiagnosed`/`verifyExDiagnosed` annotate exact typed PCS catches and
explicit Core-owned structure/OODS checks. Their shared implementation leaves
caller component mask/evaluation callbacks untouched. A same-tag callback error
therefore remains unmapped; this is executed behavior, not an error-name rule.
Legacy entrypoints pass a null output and retain ownership/capture behavior.
Native XOR forwards diagnostics from the actual receiver and its interop branch
uses bounded optional stderr, retaining the original error. Earlier Native
statement/preprocessed-root failures remain unmapped and clear stale metadata.

Local focused Debug and ReleaseFast checks execute all four metadata tests and
12 verifier/capture cases, including owned structure/OODS, identical-tag custom
callback refusal, typed PCS shape refusal and a physically absent FRI-layer
refusal. Existing Merkle capture and every-allocation-failure cases also pass.
The actual Native receiver executes both rejection origins in each mode using
its real fixed preprocessed commitment, without constructing a STARK proof.
Peak guarded RSS is below 800 MiB. Full prover-dependent successful roundtrip
and FRI-mutation additions remain unrun under the local compilation boundary;
they are not counted as qualification evidence. The original revision-target grinding
case separately reached SIGXCPU; the broader unfiltered diagnostic-root crash
remains unclassified. Neither is established as an arithmetic/compiler defect.

These checks qualify the declared typed verification origin, not all Core
arithmetic/input-decode origins or every product consumer. Remaining full-D2
work still includes backend recovery/native-AIR, prover work/task/lifetime,
other parser/resource and recursion framing boundaries. Component callback
errors deliberately remain unclassified by Core.


## Postcard preflight continuation after checkpoint 0534f6b46

RFC #360 issue #359 delegates this bounded origin-owned addition under the
owner's standing approval: at most 500 net source/test lines, targeting below
250, with no new flags, scripts, runtime dependencies or public root names.
The recursion-wire candidate advances rc.1 to rc.2. Existing binary codes
0x5001/0x5002 and their since values remain unchanged. Postcard's ten exact
preflight errors receive append-only codes 0x5101–0x510a in declaration order;
only ProofResourceLimitExceeded is resource_exhausted, the others invalid_input.

The parser belongs to a separately named canonical interop_postcard module.
Importing its source again from recursion-wire would violate Zig module
ownership. The approved alternative is an explicit structural ten-tag error
contract in error_codes, with an exact-type comptime equality check against the
actual parser Error at the real consumer catch. Adding or removing a parser tag
fails closed. This is a typed ABI projection, not an anyerror/name classifier;
no parser algorithm, new injected module or helper ABI is duplicated.

The live RISC-V artifact verifier applies this projection only around its
allocation-free, callback-free preflight immediately before allocating decode.
It writes optional bounded recursion_postcard_rejection_v1 stderr with provider,
origin, code and class, then returns the original error. Writer failure cannot
replace or classify the parser error. Provenance, framing and downstream
verification errors remain unmapped. Proof bytes, parser acceptance, primary
receipts, stdout, exit causes and transcripts are unchanged.

The actual consumer executes a public-serializer positive fixture, every
truncation of that fixture, physical examples of all ten errors, byte-preserving
success and a same-tag diagnostic-writer failure. Debug and ReleaseFast both
pass the two cases through actual SDK/provider namespaces under 295 MB guarded
aggregate RSS. The serializer fixture is not claimed to be a valid STARK proof.
The existing canonical adapter test root explicitly collects these cases and
its minimum test floor rises from five to seven; no new launcher is introduced.
Full proof construction and native process verification remain outside this
small local check, and other recursion parser/registry/framing origins still
need typed coverage.


## Seven recursion JSON input origins after c0fb190d8

The next delegated RFC #360 / #359 tranche has a pre-edit ceiling of 700 net
source/test lines, targeting below 450. Its finite live scope is registry,
verify request, leaf input, leaf manifest, registry definition, prover parameters
and FRI configuration in the existing circuit-recursion CPU command. There is
no new module, launcher, runtime flag or public facade helper. The existing
private product diagnostic owner selects these seven parsers at comptime;
callers cannot inject a callback or parser into the classification boundary.
The original application stays below its 850-line limit.

Recursion-wire rc.3 appends codes 0x5201 InvalidJson, 0x5202 MissingField,
0x5203 InvalidValue, 0x5204 OutOfMemory and 0x5205 EmptyTraceRange. Only allocation
failure is resource_exhausted; the others are invalid_input. The first four
accept exactly json_text.ReadError; definition admission additionally accepts
its owned EmptyTraceRange. Existing 0x5001/0x5002 and 0x5101–0x510a meanings and
since values remain unchanged. The old binary diagnostic writer now refuses
other valid provider code bands, avoiding incorrect circuit-decode origins.

All twelve live parser call sites across the seven families route through the
closed input owner, immediately around their actual parser operations. Input
file reading remains outside these catches. Returned value/arena ownership,
original parser errors, standard output, receipts and successful bytes remain
unchanged; optional recursion_input_rejection_v1 stderr binds the selected
origin. Writer failure returns the original parser error, including allocation
failure, without broad error-name classification.

Local bounded tests execute all seven real operations with retained fixtures
and public-codec-generated leaf input, silent byte-preserving success, public
writer/reparse/rewrite identity for registry/request/leaf/FRI, every allocation
failure cleanup, all three JSON refusal classes at each operation, empty-range
refusal, and diagnostic-writer failure. Exact JSON frames assert origin/code and
class. Code-table tests pin exact typed signatures, tags, class, version and
unknown refusal. Full process execution and proof construction are not inferred
from these operation tests. Registry query, packed-tree, felt framing and other
owned failure origins still require their own typed consumer coverage.


## Backend proof-program and Native AIR admission after 23e1f06f0

The delegated RFC #360 / #359 batch has a pre-edit ceiling of 700 net source
and test lines (target below 400), with no flags, scripts, dependencies or root
exports. Backend advances rc.2 to rc.3 and CUDA 0.1 to 0.2 for additive nested
opt-in methods. Codes 0x2201–0x2210 pin the sixteen exact proof_program.Error
meanings, and 0x2301–0x2306 pin the six exact Native AIR contract errors, all
invalid_input since rc.3. Existing arena codes and since values remain unchanged.

ProofProgram.validateDiagnosed shares the released validator body. Its exact
native-contract catch records that owned cause before returning the existing
InvalidNativeAir wrapper; other program validator failures receive the exact
program code. Native AIR mismatch checks in the program validator remain the
program-owned InvalidNativeAir origin. No callback or arbitrary error-name
classifier exists. Legacy validate passes null. Every diagnosed admission
clears stale output first and does not change the program or its digests.

The actual CUDA host execution-plan compiler exposes compileDiagnosed over the
same compilation body. Its pure program admission forwards this origin data;
subsequent compile-target, planner and allocator failures stay unmapped. The
legacy compile entrypoint passes null. This CPU-only planning operation does
not initialize a CUDA context, execute a kernel or establish GPU qualification.

Tests-first physical cases execute all sixteen program failures and all six
native sub-contract failures through the actual CUDA module. Successful legacy
and diagnosed plans match cache keys, schedules, prediction and arena geometry.
A later target failure clears stale metadata, and every allocation failure
preserves cleanup without falsely assigning a backend program code. Provider
goldens pin exact typed signatures, meanings, class, since values and unknown
refusal. Debug/ReleaseFast execute the three consumer cases and 27 provider
cases under 385 MB guarded aggregate RSS; no full proof or GPU claim follows.
Recovery callback/I/O and prover task/lifetime boundaries remain separate work.


## Task reservation, publication and capture lifetime after 50eea5dd

RFC #360 / #359 delegates a 700-net-line ceiling (target below 500) to the
callback-free task-recorder lifecycle: twelve recorder errors, eleven semantic
contribution errors and allocator failure. API rc.3 appends literal codes
0x3101–0x3118 while retaining the three existing column codes. Exact
ReservationError, PendingError, PublicationError and SnapshotError signatures
are compiler-enforced; their union is limited to these owned task operations.
Counter/identity exhaustion and allocation failure are resource_exhausted;
shape, ownership, range and lifecycle misuse are invalid_input.

The actual stage recorder's diagnosed reservation/publication/snapshot calls
project only these concrete recorder operations. Sinks are per call, never
stored in a Recorder. The actual Engine Capture's opt-in initDiagnosed clears
stale output before earlier attribution and clock operations, and borrows the
sink only until coordinator publication/join and Capture.deinit. Workers never
write it. No ownership transfer or concurrent write path is introduced. Legacy
entrypoints pass null. Exact PendingGraph.abortDiagnosed can clear a prior
failure on explicit successful abort; ordinary cleanup/deinit uses the legacy
null path and cannot erase the primary capture diagnostic.

The existing monotonic clock, callback transport and atomic failure-precedence
implementation move together into one private clock owner; original public
names and function types remain available. This keeps the Capture owner below
850 lines. The clock algorithm, proof/transcript/schema bytes and callback
rejection semantics do not change. A foreign clock callback returning the same
tag as an owned reservation failure remains unmapped, as do earlier engine
attribution/allocation failures outside the selected recorder operation.

Bounded Debug and ReleaseFast execution passes 26 actual engine capture/clock
cases and 14 API lifecycle/property cases each, below 391 MB aggregate RSS.
Physical diagnostic cases cover all eleven contribution errors, reservation
shape/generation limits, active/wrong/stale/storage capability rejection,
joined-summary refusal, snapshot exclusion, explicit abort/success/reset and
every allocation failure cleanup. Process-global recorder-identity exhaustion,
u64 task-count overflow on this 64-bit host and an impossible scheduler enum
are typed golden cases only, not physical execution claims. Full proof/process
and cross-host qualification remain separate. Work-profile validation and
backend recovery callback/I/O origins remain open.

## Logical-work operation origins after dee870158

RFC360 decision6922612001 adds four exact API-owned meanings at0x3201–0x3204,
with APIrc.4 and Engine0.3 reexport metadata. Per-call record/snapshot wrappers
call the existing authorities and preserve their errors, locks, arithmetic and
serialized profile digest. No output pointer is stored. Disabled capabilities
retain zero state and no counter work. CounterOverflow is resource exhaustion;
invalid counter grouping, producer coverage and profile authentication are input
failures. The actual Engine stage consumer physically exercises allfour causes,
snapshot equality, failure atomicity, stale reset and disabled behavior. Each
mode passes one named consumer case plus the root container and27 API target
cases (transitive cases included), peak315MB. This does not qualify a complete
proof, command-level error report or device execution.


## Concrete byte-input and root admission matrix after dee870158

RFC #360 / #359 delegates at most 1200 net source/test lines to the finite
matrix below, with no new flags, launchers or dependencies. ProofWire rc.3 and
RecursionWire rc.4 expose additive nested ledger functions; Circuit CPU moves
0.4 to 0.5 for verifyProofBytesDiagnosed. Root facade names remain unchanged.
Unallocated 0x5502 stays reserved for a future encoder transaction; an encoder
helper without a live consumer is not declared covered by this batch.

| Concrete operation | Actual consumer | Local executed qualification |
| --- | --- | --- |
| Canonical QM31/OM31 JSON and binary proof bytes | Native verifier's existing diagnosed decoder; Native interop framing | Full codec suite, public roundtrips, malformed JSON/config, every allocator failure, actual CLI frame |
| Circuit binary decode/config/resource catch | Circuit CPU receiver and Cairo CPU verify command | Actual public decoder InvalidProofShape and physical allocation failure, typed receiver rejection, foreign same-tag build refusal |
| Registry config/leaf/multiverifier lookup | Circuit CPU canonical and leaf admission | Actual retained registry, positive lookups, three physical failures, optional writer failure |
| Packed root JSON/depth | RV64 fold_root receiver | Public codec roundtrip, maximum-depth refusal, every allocation failure, writer failure |
| Fold checkpoint JSON | Cairo CPU stage loader | Actual public checkpoint writer/parser, roundtrip and all allocation failures via closed input owner |
| Registry JSON before CUDA asset selection | Cairo CUDA canonical_paths | Actual byte parser success/refusal and optional writer failure; no device execution |

ProofWire appends literal std.json.ParseError(Scanner) codes 0x4101–0x410e and
native FRI config codes 0x4201/0x4202, retaining all 0x400x meanings. This is a
complete-buffer operation, not arbitrary reader I/O. ForHasher already rejects
all fields except exact Core QM31/OM31; expanded annotation additionally requires
primitive canonical hash arrays. A permitted custom 32-byte Hash struct's
jsonParse can return the same SyntaxError: physical tests show it remains
unmapped. No foreign callback name is assigned a code. Typed scanner/schema
cases that cannot occur for complete buffers/plain schema stay golden-only.

Recursion adds QueryError four-tag meanings 0x5301–0x5304, TooDeep 0x5401,
InvalidProofShape 0x5501 and binary-owned OutOfMemory 0x5503. The maximum-leaf
query has direct public-query qualification only; it is not called a live
process path. Existing JSON resource metadata is reused only by the exact
packed/checkpoint/registry parser operations. Binary allocator failure has its
own distinct origin and resource class. Optional diagnostics cannot replace a
primary failure. File I/O and later circuit/statement/verification errors remain
outside these narrow parser catches, preserving original causes and cleanup.

The legacy circuit verifier delegates to the same implementation with a null
sink. The CPU command uses the diagnosed form for binary allocator failure;
old stdout/exit and rejection verdict behavior remain. Invalid binary config
is now coded at its exact decoder catch; the binary-only diagnostic writer
still refuses unrelated postcard/JSON/query code bands. Callback supplied
writers are not assigned decoder codes.

Local Debug/ReleaseFast run the full 24-case proof codec suite and seven real
consumer/provider roots under the existing 1 GiB guard (peak below 616 MB).
These are operation/receiver-catch qualifications, not full proof construction,
whole CLI input loading, GPU execution or the full native root proof. Remaining
families include generic felt/postcard transports, standalone encoding/shape,
Core setup, backend recovery and device admission; they are not waived by this
finite matrix or its table counts.


## Joined custody, pure device admission and revision configuration after 9b6450a9c

The delegated RFC #360 / #359 batch is bounded at 1200 net source/test lines,
targeting 650. API rc.5 adds joined-custody codes 0x3401–0x3403 and pure device
admission codes 0x3501–0x3508. Core rc.4 adds exact V2 configuration meanings
0x1201 InvalidTreeHeight and 0x1202 InvalidLiftingLogSize. Engine 0.4 exposes
additive diagnosed replay/revision operations. Existing column, task, work and
verification meanings remain unchanged. No flags, scripts or dependencies are
introduced; the existing shape code 0x5501 is not duplicated.

| Origin | Actual consumer | Local exercised scope |
| --- | --- | --- |
| Joined stage custody, exact JoinedError | RV64 component profile Group.join | Active/self refusal, success, ownership preservation and every allocation failure |
| TraceColumnError and RetirementScopeError | RISC-V CUDA trace admission and joined-input retirement | Pure header validation, scope failure and identical-tag foreign retirement callback |
| ReplayError four-tag set | Actual PCS Scheme.refreshDeviceOm31MainDiagnosed | All four typed refusals, identical-tag pre-validator Engine refusal, accepted header replacement |
| CompositionTreeError two-tag set | Engine resident evaluator after callback join | Both typed refusals, success and identical-tag callback failure after prior owned failure |
| PcsConfigV2.Error two-tag set | Engine revision lifting and mask-size admission | Both typed config failures, success/reset and identical-tag backend callback refusal |

The existing legacy operations delegate to the same algorithms or retain their
bodies and pass null outputs. Exact typed validators precede their projections;
callback invocation is outside these catches. The diagnostic origin slots are
per proof and coordinator-owned. Deferred commit workers join before lifting
and append; resident evaluation returns before the coordinator validates its
descriptors. Forwarding into ProveDiagnostic requires the captured typed cause
to equal the primary failure. No arbitrary outer error-name classifier exists.

TraceCommitRequest's approved default-null diagnostic field is borrowed only
for the synchronous operation. It is never retained by returned column/tree
owners or written by workers. Two distinct sink addresses preserve the actual
authenticated Scope and column headers. This in-memory request has no separate
serialized identity function; native queue/commit identities are selected from
explicit scope/geometry fields, not raw struct bytes. No GPU identity/timing
qualification is inferred from these host checks. Integration-owned protocol
refusals before the selected pure validators remain unmapped even when their
tags coincide. Earlier/later device and backend callbacks also remain unmapped.

The actual Engine collector explicitly includes its existing device-composition
owner, so the callback discrimination case is executed rather than merely
registered. Final bounded Debug/ReleaseFast run 5 Engine cases, 13 API cases,
1 Core golden, 2 actual Group cases and 1 actual trace-header case each under
315 MB aggregate RSS. Descriptor pointers are never dereferenced as device
memory; the backend callback fixture exercises provenance only. Full prove and
CUDA Context execution, hardware qualification and byte-parity proof runs remain
unrun. Constructor-only InvalidFoldStep stays typed library behavior without
an invented process path. Other Core setup/arithmetic helpers retain their
owned typed contracts; this matrix does not create a code for every helper.

## Recovery operations and focused discovery after9b6450a9c

RFC360 decision6923691634 adds six exact RecoveryError meanings at0x2401–2406
under Backendrc.4. A singleton compile-time cause is recorded only where an
owned check returns it; no outer anyerror mapper exists. Actual engine methods
share the arena hook bodies and retain no output pointer. File reads/writes,
allocations and buffer/recipe/group callbacks remain unannotated at this origin.
Real spill files cover unmaterialized, missing, size and checksum failure; short
reads retain EndOfStream with no fabricated recovery code. Actual Cairo column
recipes preserve successful results and keep a same-tag callback failure foreign.

Tests first exposed a genuine empty-registry slice panic; a bounded loop guard
now admits an actual resident-only plan without any recovery storage access.
An anonymous Backend collector makes filtered child tests reachable while the
original named collector and canonical module list remain. #383 decision
6923868302 is bounded to30net source. Actual old metadata28cases is preserved
in the new33-case executed inventory; all33 pass each mode under389MB. The
identical focused command changes from zero discovered cases to two passing
cases (collector+intended test). Existing inferred error sets are compared by
resolved members, not deferred type identity. Earlier panic, zero-case and
signature-identity diagnostic evidence remains retained. No complete process,
proof or GPU qualification is inferred.
