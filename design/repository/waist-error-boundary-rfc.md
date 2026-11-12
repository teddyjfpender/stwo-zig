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
