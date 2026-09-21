# Recursive verifier: live investigation and implementation

Latest checkpoint (2026-09-07): schema7 raw clocks and program-bound key admission passed the complete native-assisted wrapper lifecycle (3/3) and separate-process replay (1/1). Standalone root/global admission and the real block route remain unfinished. CSP functional A/B passed 128 reports; performance promotion still needs a quiet host. See the [current progress record](progress.md#2026-09-07-schema7-complete-proof-and-separate-process-replay-pass); older observations below retain their historical scope.

Reference checkout: `starkware-libs/proving`, commit
`cd7bc5f4697fb188a27e09f9242f1dd76df8afdc` (2026-09-05 retrieval).
The former `stwo-circuits` README directs current development to this repository.

The useful reference is `crates/stark_verifier/src/verify.rs`: it constrains the
Fiat-Shamir transcript, public LogUp sum, composition evaluation, openings,
FRI, query selection, statement claim and relation-use bounds in one circuit.
`crates/circuit_verifier/src/components/qm31_ops.rs` uses a 12-column arithmetic
AIR and an eight-column interaction trace to connect circuit wires. This
supports reusing our existing arithmetic and permutation providers; it does
not establish that adding a new RISC-V instruction is necessary.

## Committed prefix proof verified; payload extension under verification

`recursive_common_fold_secure_cohort_v2.zig` has passed a full bootstrap proof
with components 0--4 and 6--9 in the actual proof trees, including producer
destruction and fresh cold reopening (11 minutes, 9G peak RSS). Those components
have physical writers, parameters, interactions, claims and domain audits.
The current extension activates row 5 for roots, physical claimed sums, sampled
values and final FRI coefficients; its focused source gate passes (59164 exact contributions, altered payload and
randomness rejected). Its full proof and fresh cold reopening also pass
(11 minutes, 9G peak RSS), together with both field-public boundary tests.
Rows 10--17 remain inactive. The shared provider now includes both transcript lanes, the 116
field-public calls and the verifier-core suffix, with exact complete geometry.

The native boundary no longer compensates challenges or randomness: an exact
2396-contribution tuple test closes those AIR joins and rejects a changed
randomness output. Native control, verifier-input, statement and transcript
payload boundaries still remain. The nine-component full proof is recorded
in the [committed-prefix receipt](evidence/recursive-transcript-committed-prefix-progress.json).
This bootstrap proof still relies on native boundaries and does not establish
an independently verifiable root.

The existing Ethereum role-0 wrapper has a recorded transcript and typed row
writers, but the common-fold child verifier had only native channel replay.
The secure engine now shares a single replay implementation between native and
recording channels. `recordVerifiedReplayWithCohort` records the exact mixes,
PoW frames and draws, partitioned by typed context. Native protocol bytes stay
unchanged. Raw recordings remain witness data, not admission capabilities.

The existing row-1 witness builder now converts validated raw transcripts into
rows without minting the legacy schedule-authenticated batch. Ethereum's
role-0 row writer reuses the same call conversion. The complete proof test
checks native/recorded replay equality, both PoW sites, all 193 query words,
every 32-lane Poseidon request and within-frame state-tuple cancellation.

## Program-derived transcript AIR rows

`recursive_secure_transcript_rows_v1.zig` now builds universal rows 0--4 and
6--9 from the admitted program and recording. The role-0 Ethereum writer shares
its frame constructors. The new row source owns all arrays; it borrows no
recording word/call storage after construction. PoW frames use the existing
control tags 6/20 and fixed program difficulty, and relation/randomness rows
consume the exact atomic draw tuples emitted by the state rows.

Tests evaluate the actual typed AIR constraints and use the existing tuple
ledger to close every internal relation. Explicit native boundary oracles cover
only the permutation provider, payload inputs and semantic challenge consumers.
They reject altered initial state, payload, randomness, PoW word and a jointly
weakened PoW check/frame. Preprocessing stays identical for different valid
canonical children. That initial witness-only milestone preceded the committed-prefix proof above.

## Retained canonical-child transcript handoff

The canonical cold owner now retains its recorded replay on the heap. Graph,
claims and query authority are derived from that same replay and prepared cohort;
the constructor no longer creates a second cohort merely to replay the transcript.
The existing ingress and worker child handoff borrow the retained recording.
Process-local token snapshots pin its program/recording identities and owned
allocations. Preparing rows validates the recording contents and needs no new
PCS verification, native interaction reconstruction or graph recording.

This initial handoff preceded common-fold activation. The subsequent common-fold
retention preserves the fused cold-verification/replay path; adding another full
replay would undo the existing preparation saving.

## Shared common-fold transcript retention

The native engine can now record an already verified cold replay while reusing
its generated interactions, claims and audit. Relation challenges are redrawn
and compared exactly, and the finished replay must match the retained replay.
The existing full reconstruction/validation entry points keep their checks.
The new path checks the exact prepared cohort/session before reuse and avoids
another preprocessing-root lookup or interaction-tree reconstruction.

The canonical complete-proof test matches the retained recording exactly and
rejects altered prepared-cohort identity and relation challenges. Its recorded
pass took 70.6 ms. Common-fold bootstrap and backend cold owners now retain that
recording, with process-local storage pinning and an ingress transcript view.
The full common-fold proof/cold-open test passed in 12 minutes / 10G RSS;
its recording and program identities survive producer destruction and fresh
verification. Concrete backend function compilation and all three child gates
also pass. That compile gate exposed and now guards two repaired pointer/slice
type errors in the previously uncompiled production backend path. Runtime
production geometry/parity admission remains unavailable. Details and scope are
in [the shared-recording receipt](evidence/recursive-shared-transcript-progress.json).

## Parent source now owns both transcript lanes

The fixed common-fold source consumes the retained canonical/common-fold views
and owns prepared logical rows for both verifier lanes. Raw frame rows are freed
one lane at a time. The shared physical writers have passed exact main/PP row,
padding, alias and undersized-destination checks through the actual parent
source. A new focused gate takes 14 seconds / 1G RSS and checks late allocation
failure cleanup. The complete fold/cold-open rerun is pending in the
[parent-source receipt](evidence/recursive-transcript-parent-source-progress.json).
This does not yet activate the committed prefix or append its provider calls.

## Suffix control binding under verification

The current source extends committed row 0 with the authenticated recursion
schedule's composition instructions/assertion, trace/FRI opening steps, deep
quotient evaluation, FRI folds and last-layer verification. It reuses
`control_witness.rowForVerifierStep`; steps come from the validated program,
not from a consumer ledger. The constructor prepares the extension before
changing the retained owner. Native boundary schema 3 removes `recursion_step`
and keeps only verifier-input, statement and transcript-payload obligations.

The focused test compares these row-0 producers with the actual control
relation events of rows 19, 23, 27 and 28. All 70044 contributions close, and
changed control, payload and randomness inputs are rejected (17s / 1G RSS).
The concrete cohort compiles and both field-public tests pass. The latter
needed its mutation changed from the removed control domain to the remaining
statement domain. The full control proof exposed a stale ordinal mapping in `domainIndex`;
that duplicate table has now been replaced by a lookup in `DOMAINS`, and its
regression test is part of the existing field-public gate. The repaired full
control transaction still needs a pass. See `evidence/recursive-transcript-control-progress.json`.

## Fixed transcript metadata binding under verification

Row 5 now fixes the manifest header/seal, registry seal, authority/session
headers, claim count and claim coordinates. The native channel and program
builder share header definitions. Program constants come from the admitted
manifest and protocol configuration; none are copied from the recorded witness.
Dynamic session/claim SHA seals and public-statement payloads remain native.

The canonical proof guard retains SHA-256
`23da5f591218aab54cf8f04f646e045195349d9b1674e641c5b80f702419f468`.
The direct AIR test rejects a changed constant payload value. All 13 build
steps and five tests pass: the source join (70044 contributions), canonical
proof, field-public checks and boundary-index regression. The concrete cohort
also compiles. The combined full proof is building; see
`evidence/recursive-transcript-constant-progress.json`.

## Required next integration

1. Complete the running full proof and fresh reopening with payload, control
   and fixed-metadata binding. Keep each receipt tied to its tested source hashes.
2. Complete the remaining payload and public-statement bindings. Session
   identity and claim-vector SHA seals are witness-dependent values; they
   cannot become verifier-key constants. Remove native boundaries only after
   their AIR producers and consumers are constrained.
3. Constrain field-public continuation and output publication. Keep fixed
   verifier-key/program authority separate from witness-dependent preprocessing
   and local custody.
4. Prove a parent from real complete Ethereum leaves, destroy every child and
   producer owner, then verify the root using only its bytes, public statement
   and pinned verifier key. Only that gate supports production activation and
   the equivalent final-proof comparison.

These remain completion requirements. Active transcript commitment alone does
not establish complete recursive Ethereum block verification.

### Statement integration update (2026-09-06)

The earlier combined transcript-control/fixed-metadata full proof passed (12m, 10G RSS). A subsequent profile now commits the canonical field-statement bridge at row 12 and its 2,700 signed range requests at row 35, removing the native statement-word boundary. It passes 11/11 source/field/canonical build steps and 6/6 tests; the full proof for this newer profile is running separately. This still leaves native auxiliary verifier inputs and dynamic SHA payloads, field-public hash/fold semantics, the real Ethereum leaf/bundle path, and final independent-root verification unfinished. See `evidence/recursive-field-statement-integrated-progress.json`.

### Owned continuation circuit update (2026-09-06)

The degree-four statement-bridge attempt failed during proving because its extra polynomial extension needed released coefficients. The newer bridge uses the already-active statement mask directly and stays cubic. The common fold now joins the existing pinned continuation circuit through rows 10/11, duplicate child statement emissions and the authenticated shared arithmetic lane; its source join passes with 6,896 contributions. Full proof/fresh verification of this newer profile remains pending. The field-public hash calls and dynamic SHA/auxiliary verifier inputs still rely on native boundaries, so this is not yet an independently verifiable root.

### Public hash binding update (2026-09-06)

The owned statement-fold full proof passed (12m, 9G), resolving the earlier degree-four extension failure. The next profile replaces native field-public permutation compensation with four committed hash AIR instances plus a word router. Its public-output boundary is derived solely from published node words and verifier challenges. Focused source/routing/public-boundary checks pass; full proof/fresh verification is running. Native auxiliary verifier inputs and dynamic SHA transcript seals remain unresolved, and fresh root verification still needs to be decoupled from native child-verifier custody. See `evidence/recursive-field-public-hash-progress.json`.

### Common-fold provider subclaims (verification pending)

Common-fold schema 6 now absorbs both audited Poseidon provider subclaims before the composition challenge. The transcript payload AIR emits claim coordinates 39 and 40; only common-fold child lanes remove the corresponding native verifier-input compensation. Canonical child transcript identities remain unchanged, and their legacy subclaims retain native custody. The full transcript gate checks the actual AIR tuple join against cold composition inputs and rejects equal-and-opposite changes that preserve the provider total. The source development gate now constructs all 36 components, catching parameter admission errors without a full STARK. Checks are queued in `evidence/recursive-provider-partial-check.log`; no new proof pass is claimed.

### Public-hash proof verified

The schema-5 public-hash profile with corrected inactive-row parameter admission passed the complete proof, producer-destruction and fresh-verification gate: 4/4 build steps, 1/1 test, 12m and 10G peak RSS (compile 1m, 4G). Its rerecorded transcript has 182 operations, 184 frames, 1,765 permutations and 193 queries. This resolves the earlier `ParameterMismatch`; it predates the schema-6 provider-subclaim binding now under test. Source provenance and scope are preserved in `evidence/recursive-field-public-hash-retry.json`.

The current composition recorders also specialize graph constants to child session statement words and native boundary sums: `recursive_common_fold_composition_capture_v2.zig:620` and `recursive_common_canonical_empty_composition_capture_v2.zig:597`. Claim padding is already constrained by the recorded claim policy, but its lookup boundary is still supplied natively. A fixed-key independent root requires these instance-dependent graph constants and remaining native boundary authority to be replaced by constrained or independently available public inputs; a passing cold-owner proof does not establish that property.

### Statement inputs without graph literals (verification pending)

The canonical/common-fold composition capture schemas advance to 2. Their recorders no longer accept the session or add 412 equal-to-instance-literal statement constraints. Statement input slots remain in the graph ABI and in every row-18 schedule, including zero-use inputs; row 18 consumes each word from the committed transcript/statement bridge independently of arithmetic use count. A source regression mutates a composition-side statement input while retaining the transcript and requires `FieldStatementJoinMismatch`. Native boundary constants remain unchanged pending an explicit constrained replacement. The source/canonical/concrete-backend checks are queued in `evidence/recursive-statement-input-check.log`; no proof or performance improvement is claimed yet.

The statement-input source/canonical/backend checks pass: 10/10 build steps, 2/2 tests. All 824 statement input rows remain and have zero arithmetic uses; changing a composition-side word is rejected by the AIR lookup. Canonical proof SHA remains `23da5f591218aab54cf8f04f646e045195349d9b1674e641c5b80f702419f468`; the versioned composition capture identity changes. Source runtime/RSS remains 48s / 5G, so no measured memory improvement is claimed. The corrected provider-subclaim tuple helper passes its small check (4/4 field tests, 673ms / 3M; compile 9s / 733M), including equal-and-opposite subclaim tampering. The full proof for these combined changes is running separately in `evidence/recursive-statement-input-proof.log`.

### Combined statement and provider-subclaim proof passed

The capture-schema-2/common-fold-schema-6 proof passed all four steps and its complete test: 12m / 9G RSS, compile 1m / 5G. Logs explicitly confirm producer destruction, fresh verification and rejection of equal-and-opposite provider-subclaim tampering. The recording has 183 operations, 185 frames, 1,768 permutations and 193 queries. This resolves the earlier diagnostic sign error. Source hashes and scope are in `evidence/recursive-statement-input-proof-progress.json`.

### Claim values and canonical key binding under test

Common-fold schema 7 omits the redundant SHA claim receipt from the Fiat-Shamir transcript while directly absorbing every validated roster claim. The default manifest API retains its previous seal suffix; canonical and CSP paths keep that form. Session SHA remains because its key/provenance fields need explicit replacements. Separately, the canonical-empty preprocessing root is pinned from the frozen provider-only key in the existing payload AIR, with root inputs still emitted to the verifier lookup. The native canonical proof gate recomputes and checks this root; a changed capture root and changed AIR value must be rejected. Constants can now hold full M31 words as well as the existing split-u32 metadata. Checks are running in `evidence/recursive-claim-values-check.log`; this newer profile has no full proof pass yet.

The schema-7 checks pass after fixing an undersized provider log in the claim-format test setup. The field gate is 4/4 tests (275ms / 3M, compile 9s / 732M): all 36 individual claim mutations change the digest, invalid/missing claims fail before channel mutation, and appending the original SHA suffix exactly recovers the legacy transcript. The source gate passes (48s / 5G) and the concrete backend compiles. The canonical full proof remains byte-identical (11s / 87M); its preprocessing root is recomputed, wrong-key capture admission is rejected, and eight root words are fixed in the AIR while retaining their lookup uses. The full schema-7 proof is running in `evidence/recursive-claim-values-proof.log` (session 12805).

### Canonical child boundary transcript join (schema 8, verification pending)

The canonical cohort validates a fixed five-u32 boundary header and a zero
verifier-input boundary. Its native public request still depends on the exact
113 public-hash Poseidon calls. Preserve that semantic calculation and the
composition graph constraint; dropping them would not finish recursion.

The new common-fold profile uses the existing transcript payload AIR to bind
the canonical wire-boundary QM31 to the composition verifier's four inputs at
`claimed_sum` index 41. The five-u32 header is fixed in preprocessing.
The native suffix no longer compensates those matched verifier-input and
transcript-payload tuples. Common-fold children retain their native boundary
path. The source gate mutates an actual canonical composition boundary input
and requires the transcript/composition tuple join to fail.

This removes a native copy-binding obligation, not the public hash semantics
or the instance-dependent graph constants. Session SHA, canonical claim SHA,
auxiliary inputs, common-fold boundary derivation and fixed-key admission
remain. Targeted check: `evidence/recursive-canonical-wire-check.log`.


Follow-up candidate, not implemented: the common-fold native arithmetic wire
boundary is already enumerated by
`air/verifier_arithmetic_lowering_plan.zig::Plan.public_terms`. Investigate
emitting those exact fixed constant/output-anchor tuples inside the AIR (the
common-fold row 10 is currently inactive), instead of carrying their aggregate
as a native boundary. Preserve each authenticated value and multiplicity;
zeroing the boundary without its producer would weaken verification. This may
remove a substantial native boundary dependency while reusing the existing
lowering plan. It does not automatically make instance-dependent composition
graph constants or the common-fold preprocessing key fixed.

### Fixed-wire anchors integrated in common-fold schema 9

Common-fold row 10 now emits 33,377 exact binary graph constants and signed output anchors from the authenticated lowering plan. The legacy global-closure envelope retains independently derived wire evidence as an audit cross-check, but common-fold closure no longer adds that contribution externally. The boundary transcript omits it, and composition capture schema 3 constrains its former external wire input to zero. The frozen default universal catalog is unchanged.

Field checks pass (4/4 tests); source integration passes (4/4 steps, 1/1 test, 47s/5G; compile 1m/4G). Actual graph tuple joins reject a missing anchor and changed coordinate, owner validation rejects mutation, all 36 components construct, and global closure verifies before a full STARK. Exact source provenance is in `evidence/recursive-fixed-wire-integration-progress.json`. Full proof/fresh verification is pending. Native auxiliary boundaries, session seals and fixed-key admission remain; this is not an independent root.

### Protocol zero inputs moved into the fixed-value AIR (schema 10 under test)

A second independently weighted lookup in the existing fixed-wire AIR supplies claim-padding words 36..38 and, for common-fold children only, zero external wire input 41. Each lookup reuses the fixed coordinate columns; the interaction width remains four columns and preprocessing adds one column. Owner rows and suffix exclusion are derived from the exact protocol policy, not an observed residual. Canonical wire boundary 41 and provider subclaims 39/40 are excluded from that policy.

The field gate passes 4/4 tests (289ms/3M; compile 10s/749M). It used the existing small-build `--no-lock` option alongside the earlier schema-9 full proof, so overlapping timing is not performance evidence. The source gate is queued under the serial lock at session 61184, with actual padding-consumer mutation and missing fixed-producer checks. Schema-9 full proof session 70019 remains a separate compiled snapshot. Source hashes, scope and status are in `evidence/recursive-fixed-zero-progress.json`.

Next closure issue: local suffix evidence and the frozen V2 global closure envelope both require nonzero tuple counts. Once common-fold child verifier-input obligations are fully matched, support an actual empty boundary in the common-fold route. Do not invent dummy tuples or relax the CSP boundary contract. Native seals, remaining boundary semantics and independent key admission still block a standalone root.

### Schema-9 fixed-wire proof verified

Session 70019 passed all 8 build steps and both tests. The complete common-fold proof passed producer destruction and fresh verification, then retained node `b49bb17032b1531c9ed4b85598c46742f7d1f1df064487c4658ef2fd04f47a45` in the existing CAS. The canonical proof identity guard passed unchanged. Fold runtime/RSS: 8m/10G; compile 1m/5G. The fold recording contains 182 operations, 184 frames, 1,761 permutations and 193 queries. Small field checks overlapped this run, so these observations establish verification, not a performance comparison.

This proves the schema-9 anchor integration only; the newer schema-10 zero-input source gate is running separately. Source provenance and the full log remain under `evidence/recursive-fixed-wire-integration-progress.json`. Independent root, complete Ethereum leaf/block and CSP promotion remain unverified.

The schema-10 source gate passes against two canonical children (70,108 closed semantic contributions; wrong padding input and missing producer rejected). Its common-fold-only zero wire input 41 currently has policy and typed-row fixture coverage, not a real folded-child source test. Full proof session 34223 is running.

For empty-boundary support, both `DomainEvidenceV2.validate` and the accumulator finalizer in `recursive_common_fold_suffix_input_boundary_v2.zig` reject zero tuples; the finalizer also requires an observed row mask. The frozen global V2 boundary source/claim constructors independently reject zero counts. A common-fold-specific closure input can reuse `binary_global_closure_outer_source_public_boundary_claim_v2.zig::preflightInputs` for exact row/provider validation, retain the internal wire-anchor evidence as an audit, and take the actual remaining verifier-input contribution from the suffix evidence. Export/reuse that preflight helper rather than duplicating its validation. Keep default global/CSP constructors strict. No empty-boundary implementation is included yet.

### Common-fold empty native boundaries (schema 11 under test)

The local common-fold closure input now reuses the existing shared row/provider preflight and retains wire-anchor evidence as an internal audit. It no longer constructs the frozen global V2 two-boundary envelope. Every actual suffix contribution, including verifier-input terms, is added exactly once. Empty domain evidence requires zero tuple count, zero claim, zero observed row mask and a provenance digest. The frozen global/CSP boundary constructors are unchanged.

The focused gate passes 4/4 tests (292ms/3M; compile 10s/766M). It closes a fixture with genuinely empty suffix domains and rejects an unmatched verifier input, malformed row total and duplicate row; the original global constructor still rejects zero tuples. An initial fixture accidentally requested an empty leaf inside a 210-segment execution and failed `InteriorEmptySpan`; corrected to padding index 210. Source/full-proof verification remains pending in `evidence/recursive-empty-boundary-progress.json`. Native child custody, dynamic transcript seals, remaining boundary semantics and independent key admission still block a standalone root.

### Schema-10 claim-padding proof verified

Session 34223 passed 4/4 build steps and its full proof test, including producer destruction, fresh verification and retained node `4516699ccfb78a32ffd0e1fc422c446e7e12362e0c0a2edb1d350664a0bbd8bf`. Runtime/RSS: 8m/10G; compile 1m/4G. Recording: 182 operations, 184 frames, 1,762 permutations and 193 queries. Small empty-boundary field checks overlapped, so this is verification evidence rather than a performance comparison. The newer schema-11 empty-boundary source gate (63711) remains separate and pending. Native custody and independent-root gaps remain.

### Next session binding investigation (not implemented)

The existing SHA pair AIR candidate (`frontends/riscv/air/guest_precompile/sha256_pair_direct_candidate_v1.zig`) handles fixed 64-byte inputs, has 2,162 main columns, and lacks production dispatch/memory integration; it is not a drop-in session-seal verifier. Common-fold bootstrap and production manifest authorities derive verification-key, next-parent-key and AIR-program IDs from the same `domainIdentityForManifest` functions and log sizes. The production methods first validate registry/parity custody but return the same manifest-derived identity values.

Investigate a versioned common-fold session transcript with the existing protocol header and three explicitly absorbed key digests. `Program.init` can derive those key words from its authenticated manifest and pin them as constant payloads without accepting proof values. Replace the three native engine `session.mixInto` call sites through one flavor helper; leave canonical/CSP session mixing unchanged. Retain native session validation and audit metadata, prove that all semantic public words already enter the authority transcript/AIR, and explicitly account for every omitted session identity preimage before dropping the redundant SHA receipt. Fixed preprocessing-root admission and remaining native boundary semantics still need separate work.

### Common-fold session preimage accounting (schema 12 under test)

The new common-fold session transcript absorbs a distinct CFS2 protocol header and all 24 words of verification-key, next-parent-key and AIR-program IDs. `Program.init` derives those IDs from the validated common-fold manifest/log sizes and pins 48 split-u32 limbs in the existing constant payload AIR. This is an explicit versioned semantic transcript; native session receipts remain validated and serialized as custody metadata. Canonical/CSP mixing keeps the legacy session header and SHA seal.

| Old session identity input | Binding in the versioned route |
| --- | --- |
| Format/schema | Explicit session header; common-fold authority schema 12 separates the profile. |
| Source kind | CFS2 domain and the method's required common-fold source kind. |
| Activation/reserved | Native session validation requires their fixed inactive/zero values; they are not free semantic inputs. |
| Protocol identity | Exact secure protocol admission and fixed program/header parameters; verifier configuration remains separately checked. |
| Parent statement words | The preceding cohort authority absorbs all 450 NodePublic words; statement and public-hash AIR joins remain required. |
| Parent statement SHA | Native validation recomputes it; the same statement words are already semantic inputs. |
| Profile identity | The next-parent key ID derives from the exact manifest/log-size profile. |
| Parent manifest identity | The manifest prefix and contract-derived key ID bind the selected manifest; native session/cohort equality remains. |
| Verification, next-parent and AIR-program IDs | All three are explicitly absorbed and manifest-derived program literals. |
| Ingress and child-composition receipt identities | Continue to identify and validate the native capture custody in admission/audits. Their raw receipt bytes are not semantic public inputs of this field session. Child proof data and public outputs still require all AIR verification obligations. |

These key IDs do not substitute for the independently admitted preprocessing commitment. Dynamic graph constants, remaining native boundaries and canonical child seals are still unresolved; there is no standalone-root claim. The three engine session call sites share one flavor helper. Field checks pass (4/4; 675ms/3M, compile 10s/787M), covering 24 key mutations, stale-session rejection before channel mutation, exact legacy encoding and manifest-derived literals. Source and replay compilation are queued in `evidence/recursive-session-key-source-check.log`; the full proof's new helper must verify the actual 48 AIR limbs and reject a changed value.

### Schema-11 empty-boundary proof verified

Session 62385 passed 4/4 build steps and its full proof test, including producer destruction, fresh verification and retained node `d2be24c35bfb24717be449bb46e59f5c155925415f438ae0ed072cff329c8ac9`. Runtime/RSS: 8m/10G; compile 1m/5G. Recording: 182 operations, 184 frames, 1,762 permutations and 193 queries. Small session-key field compilation overlapped; no performance comparison is claimed. The newer schema-12 session-key source/replay gate remains separate. Independent-root and real Ethereum proof requirements remain incomplete.

### Recorded public-output boundary (schema 13 under test)

Composition capture schema 4 now records the 450-term public-output LogUp boundary using the existing QM31 arithmetic recorder. The 412 body words reuse the existing statement inputs; only 38 header/digest inputs are appended. An append-only source tag maps those words into the existing statement lookup namespace. Common-fold transcript rows emit the exact extra multiplicities through the unchanged field-statement AIR. Default profiles have zero extra inputs; default source tags, indices and profile hashes retain their old encodings. No new AIR component or wider AIR is introduced.

The native public-output sum is removed from the graph literal, but the remaining suffix-domain sum is still native. The focused recorded-graph check rejects all 450 individual word changes, both relation-challenge changes, an altered claim, and a zero denominator. Complete capture/AIR source joins and proof verification are pending. Native suffix boundary semantics, canonical seals, independently trusted preprocessing keys, actual folded-child coverage, and complete Ethereum proofs remain required.

### Canonical boundary no longer a native graph literal

The canonical composition recorder now takes only manifest/layout/components, not a native replay receipt. Published node words drive 113 symbolic Poseidon permutations, four digest equalities, empty-leaf header/body/coordinate equations, and the IO LogUp sum. That sum is constrained equal to transcript input 41; the mandatory zero verifier-input boundary is omitted from the arithmetic total. Source/cold tests pass and two distinct child indices produce the same graph identity. Full parent proof is pending. The generic helper lives in the existing Poseidon AIR runtime owner to preserve the manual-source ceiling; native hashing paths are unchanged.

Next semantic gaps: canonical session and claim SHA seals remain unbound dynamic transcript payloads. Common-fold boundary receipts also retain native diagnostic payloads, including a redundant published-output sum and duplicated verifier-input evidence. Their removal or constrained replacement must preserve complete transcript/public-key binding; do not accept free compensating boundary claims. After internal lookup closure, independently verify preprocessing-key identity and open a root without native child custody. Actual folded-child and Ethereum leaf coverage remain required.

### Direct field transcripts and zero native suffix admission (schema 15)

Canonical field profile 2 uses a distinct CES2 header, three manifest-derived key IDs, direct physical claims and both provider subclaims. Legacy SessionV1.mixInto remains unchanged; the field flavor explicitly chooses mixFieldInto. The canonical output already binds its statement, coordinate and public hashes in AIR. Common-fold diagnostic boundary metadata is removed from the semantic transcript; it is retained only as native audit evidence. Secure-cohort admission now requires zero tuples and zero claimed sum in both suffix domains. Composition capture schema 5 no longer accepts a native replay argument or inserts its suffix claim as a graph literal.

The first canonical proof passed; parent source closure exposed an audit classifier still treating canonical provider partials as external. The classifier now matches the actual row-5 producers. Focused checks pass; the corrected parent source integration and full proof are separate gates. No standalone root is claimed. Next: independently admit the actual preprocessing root and component parameters, serialize the physical claims and provider partials needed by the verifier, and verify from public node, proof and trusted key without rebuilding child witness cohorts. Existing component adapters and the core STARK verifier should be reused. An actual folded child still needs a real geometry/profile and sibling proofs; the bootstrap's sentinel registry cannot be promoted into production authority.

The strict gate also exposed PoW nonce payloads as external inputs. They now use row 12 with its statement-output mask disabled, preserving the complete u32 range in each half while range-checking both u16 limbs through the existing byte table. Published statement rows retain canonical M31 checks. No new columns or components. Source/canonical gate 12793 passes: both suffix domains are empty and global closure verifies. This closes the tested canonical-child lookup boundaries; it does not admit a preprocessing key or remove child custody from the native root verifier. Full schema-15 parent proof is running separately.

### Explicit-key verifier passes saved-proof replay

The new verifier reconstructs the field session directly from the manifest and published node, absorbs 36 physical claims and both provider partials, checks total claims plus the public-output boundary, and invokes the existing STARK verifier over pinned AIR definitions. It takes no native closure receipt or child cohort. Replay 55062 passes against the schema-15 checkpoint; final transcript equals the native verifier and changed root/claim/provider-partial cases reject. One call took 330,749,500ns.

The key remains an explicitly trusted caller input (manifest, preprocessing commitment, component parameters and provider row count). The test extracts these from an already verified cohort and destroys that temporary cohort before verification. This is not independent key admission. Next, freeze/admit the exact key independently of a proof instance, make claims/key transport durable, and run verification in a process that has no child artifacts. Also require a real common-fold child and the production Ethereum role; the canonical-child bootstrap's sentinel registry remains non-routable.

### Durable fresh-process verifier passed

The runner now accepts a versioned key JSON plus separately trusted expected SHA-256, versioned public-input JSON, and a size/hash-bound binary proof. Session 65826 exported the verified bootstrap inputs; a fresh process verified copied inputs with reads of the original local Ethereum store denied by macOS sandbox. Wrong key hash, stale schema and proof-byte mutation reject. One process measured 119.6ms verification, 122.0ms request handling, 0.79s total launch-to-exit and 17.0MiB maximum RSS. Transport hashes protect the supplied files; they do not independently admit the circuit key.

Build from repository root:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu build-recursive-common-fold-verifier-v2 -Doptimize=ReleaseSafe
```

Run the exported bootstrap fixture with the expected identity recorded by its verified setup:

```sh
src/integrations/riscv_cpu/zig-out/bin/recursive-common-fold-verify-v2 \
  .git/local-ethereum/detached-verifier-v2/key.json \
  d851a6465f6edb02cbeb8a3bc8173b40b86ad6642e07b791478e8b08975a9b37 \
  .git/local-ethereum/detached-verifier-v2/inputs.json \
  .git/local-ethereum/detached-verifier-v2/proof.bin
```

This pin is for the recorded nonproduction bootstrap fixture. Do not replace independent key admission by hashing a key received alongside an untrusted proof. The remaining work includes independent setup, actual nested common-fold children, the real Ethereum leaf/block profile, and the CSP regression gate.

### Rebuilt setup matches across independent child statements

`test-recursive-common-fold-setup-v2` passed 4/4 build steps and its test (46s/6G; compile 1m/4G). It freshly proves and cold-verifies canonical children 212/213, assembles parent coordinate 1/106, regenerates preprocessing through the existing commitment engine and snapshots component parameters. No parent proof or parent capture supplies this setup. The full serialized key hash equals the separately saved 210/211, parent 1/105 baseline: `d851a6465f6edb02cbeb8a3bc8173b40b86ad6642e07b791478e8b08975a9b37`.

The regression target uses a literal baseline hash and requires no local checkpoint files. Existing bootstrap modes retain their original coordinates. All compiled source hashes match `evidence/recursive-setup-progress.json`; conformance remains at 94 existing findings. This is two-case key invariance, not general setup admission, an actual nested fold or an Ethereum root. The latter requirements and current-tree CSP promotion remain outstanding.

Run: `python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-common-fold-setup-v2 -Doptimize=ReleaseSafe --summary all`.

### Detached capture and sibling-proof preparation

The existing detached verifier now optionally returns the core verifier's actual opening/FRI capture. The CLI accepts a final optional `SHAPE_JSON` path and writes diagnostic shape transport only after successful verification. The shape includes the independently supplied key hash and verified proof hash; reading this JSON does not admit a live child or a production key.

Build 3985 passed 6/6 steps and the transport test (644ms/2M; executable compile 44s/2G). Native comparison 12683 passed 4/4 steps and its saved-proof replay (4m/6G; compile 1m/5G). The detached capture identity equals the existing cold verifier's full capture identity. A separate sandboxed process with original-store reads denied passed capture verification in 127,465,959ns (request 130,866,375ns; maximum RSS 20,332,544 bytes; process wall 0.772s). Plain verification reaches the same final transcript. Altering a proof byte and updating its transport hash still fails core verification (`ProofOfWork`) and emits no shape file. These are single verification observations, not Ethereum proving or optimization claims.

The authenticated common-fold output wire is 4 commitments, 36 claims, 2,520 sampled values, 457,796 queried values, 772 trace paths, 193 queries, 6 FRI layers, maximum fold width 16, one final coefficient, and maximum Merkle depth 22. FRI widths are `[16,16,16,16,16,2]`; depths are `[18,14,10,6,2,1]`. This differs from the canonical child's four-layer/depth-17 input selector. Exact data and provenance: `evidence/recursive-verifier-capture-shape.json`, `recursive-verifier-capture-progress.json` and adjacent logs.

Bootstrap statement selection now accepts `STWO_RECURSION_BOOTSTRAP_LEFT_INDEX` for even padding indices 210 through 254. Default input stays 210/211; the independent setup test remains fixed at 212/213. Checkpoint replay obtains the leaf pair from the saved node's validated height-one coordinate, then independently verifies the proof as before. The input helper holds the moved checkpoint-reference parser too; the bootstrap test file shrinks to 833 lines. Input gate 3840 passed 3/3 steps and its test (260ms/1M; compile 3s/397M). Both conformance runs retain 94 existing findings.

Serial process 10817 is producing sibling folds 1/106 and 1/107 from 212/213 and 214/215, saving each to the shared CAS and exporting detached inputs under `.git/local-ethereum/recursion-siblings/{106,107}`. They can feed parent 2/53. Their proof results are pending in `evidence/recursive-nested-siblings-progress.json`; do not treat a started process as a verified sibling or nested parent. The capture-regression executable predates the input-helper changes; its frozen source hashes remain separate. The sibling process verifies its own source snapshot before launch.

Next implementation: connect actual fold children using their authenticated output dimensions and transcript/recorded composition. The shared fixed-source owner currently extracts transcript views through the production child's `payload` union; other live adapters need a typed transcript accessor when their real child route is integrated. The detached capture can supply geometry without rebuilding grandchildren, but transcript and composition preparation still need an equivalent path before claiming an independent nested child. No production key admission, Ethereum leaf/block/root, or current-tree CSP promotion is claimed.

### Detached transcript witness and common child key binding

Sibling 1/106 passed its full proof, producer destruction, fresh verification and detached capture checks (4/4 steps, 1/1 test; 10m/10G; compile 1m/5G). Checkpoint `11e3235eb7d4dec23d89ab0973c12bfd0e4b40a2f3b7581a740d04a3c8771ec6`; exported key remains `d851a6465f6edb02cbeb8a3bc8173b40b86ad6642e07b791478e8b08975a9b37`. Serial process 10817 is now proving sibling 1/107. Both complete siblings and their nested parent remain unverified until those respective checks finish.

`recursive_common_fold_detached_transcript_v2.zig` verifies a supplied keyed proof, obtains the genuine core capture, then executes the existing value-independent transcript program through the existing recording channel. It reconstructs all 94 relation challenge draws and 193 full query words, checks every captured challenge and projected query, validates the complete recording, and requires the native verifier's terminal transcript. Input byte buffers can be destroyed before preparing the transcript AIR rows. Initial check 86580 passed 3/3 steps and its test in 1s/34M (compile 45s/2G); log retained as `evidence/recursive-detached-transcript-initial-check.log`.

A required nesting fix was found during this work: canonical child tree-0 roots were fixed in preprocessing, while common-fold roots were ordinary witness payloads. A new append-only source tag, `common_preprocessed_root`, makes the already verified common child key root a constant payload and retains its commitment lookup producer. The initial check validates all eight constants and rejects an altered root witness through the actual transcript AIR constraints. It also rejects changed program constants and recording data. Native transcript bytes and the canonical-child bootstrap's proving path are unchanged; the common-child witness program identity changes intentionally. Caller key authenticity and the parent circuit key still require admission; this does not create production authority.

The composition extension is newer than that passing check. The existing common-fold `recordProgram` and public-input writer were lifted out of the cohort-specific generic, retaining the same constraint program and introducing one actual second caller. The detached path rebuilds the 34 logical definitions plus Poseidon/range adapters from the key, uses the shared recorder, fills public inputs from the verified node/claims/challenges, and evaluates the circuit. Standalone check 2314 and native-equivalence replay 37922 are queued behind sibling proving. The native check uses the saved 1/106 node, also exercising automatic checkpoint-coordinate recovery, and compares program/execution identities, challenges, query words, composition circuit/layout/bindings and every input/evaluation value. These newer checks have not passed yet. Current source hashes and scopes are in `evidence/recursive-detached-transcript-progress.json`; conformance remains at 94 existing findings.

Source timing matters: sibling 106 compiled before these edits. Sibling 107's compilation overlapped later development; its result alone must not be used as provenance for all current edits. The separately queued final standalone/native checks cover the frozen final source snapshot. No cross-snapshot performance comparison is claimed.

Next actual parent integration can use two detached owners and their recorded compositions, with the authenticated six-layer/depth-22 wire. Reuse `fixed_wire.TypesForLive`, `CohortForLiveV2`, and the existing secure kernel; do not fabricate three-role registry parity. The fixed source needs a typed transcript accessor in place of its production-union switch. A minimal live projection needs capture, claims, interaction nonce, full query words and graph/bindings/evaluation; its public schedule must derive parent 2/53 from children 1/106 and 1/107. Retain trusted child-key roots in parent preprocessing. The secure Ethereum leaf/block/root and current-tree CSP promotion remain required.

### Nested parent source now passes

Both saved fold siblings and the detached/native transcript-plus-composition equivalence checks passed. The explicit-key parent adapter passes complete universal-36 source admission and global closure, with zero native suffix inputs, from real fold children 1/106 and 1/107. Full parent 2/53 proving and verification after producer/child destruction is running in session 83622. See `progress.md` and `evidence/recursive-detached-parent-progress.json` for commands, provenance and pending results. Independent parent key admission, Ethereum leaf/block/root and CSP promotion are not established by the source gate.

### Nested proof passed; Ethereum role remains the next integration gap

Parent 2/53 now proves two actual fold children and verifies after all child/producer state is destroyed. Fresh-process verification also passes with the original artifact store denied. The root uses the explicitly supplied, cohort-derived `c9d86ae5...5474ef` key; independent admission of that key and the production Ethereum role remain required. The current one-worker test takes 113.4s proving and 289.3s through its full replay/export/detached checks, at 8G reported peak RSS; isolated verification is 128.8ms at 20.3MB RSS. These measurements concern a padding fixture only. Full evidence and scope are in `progress.md` and `evidence/recursive-detached-parent-progress.json`.

The real-leaf wrapper currently uses its older native session/claim/boundary transcript (`ethereum_incremental_leaf_wrapper_v4`), while the new value-independent secure transcript program supports canonical-empty and common-fold kinds. Campaign pre-final adapters also lack a real typed transcript view and retain an older manifest-policy signature. Integrating the Ethereum child requires binding its actual public/profile/provider semantics in AIR; importing a native receipt or merely adding a role tag is insufficient. Current genuine-wrapper compilation passes; the bounded two-segment proof fixture is running in session 28006.


### 2026-09-06 continuation and native transcript follow-up

The saved-child zero-I/O mismatch is resolved through an explicit SegmentV2
claim constructor, retaining legacy rejection and typed statement relation
consumers. The next failure exposed label-based fixture I/O commitments; those
original proofs are preserved as negative regressions. Fresh canonical-I/O
children cold-verify and pass VM/FRI materialization. Their hashes and commands
are recorded in `progress.md` and `autoresearch/benchmarks/ETHEREUM_BLOCK.md`.

The new focused transcript replay exposed and now passes the paired-draw
geometry mismatch (25 native operations, 50 QM31 values). The row writer retains
both values per challenge, and post-tree1 profile routing admits the actual
76-mix sequence. Native plan construction is shared with the replay; transcript
preflight now precedes large wrapper allocation. The complete wrapper still
requires a passing proof transaction; see the live checkpoint rather than
interpreting focused replay success as an Ethereum root.

Two saved stack samples demonstrate repeated deep validation in geometry and
identity getters, with a sampled peak footprint of 16.4G. Only duplicate checks
already performed by the immediately called authenticated getter were removed.
Independent root/key admission, real0 statement/boundary bindings, global-clock
AIR, campaign-owned claim capacity, and the latest CSP A/B gate remain open.


### P0 admission and ownership follow-up (2026-09-06)

The retained campaign membership replay passes both cold child verifications,
positive membership, rejected witness/schedule/campaign mutations, and allocator
cleanup. The full wrapper remains a separate gate. Its legacy materialize-only
flag now fails explicitly with `ProofGateCannotStopAfterMaterialize`.

Current circuit/profile classification, from the live source:

| Value | Required authority | Current Ethereum gap |
| --- | --- | --- |
| PCS parameters, role selectors, AIR definitions, provider windows and circuit shape | Independently admitted profile and shared native/typed-AIR plans | Profile admission must precede proof-dependent construction; observed geometry alone is insufficient. |
| Child statement words and continuation | AIR relations to the verified child/public output | `composition_capture_owner_v4.zig::recordProgram` still constrains words to `session.parent_statement_words` literals. |
| Public-wire and verifier-input boundary sums | Derive from authenticated public inputs and relation challenges in AIR | The same recorder inserts `replay.audited` boundary sums as literals. The common-fold recorder already derives its public output sum from inputs and requires its native suffix boundary to be zero; reuse that approach where Ethereum's actual relations permit it. |
| Sampled values, claims, nonces, roots, transcript draws and query words | Witness inputs joined to transcript/PCS/FRI relations | Existing classifiers cover several families. The default `.constant` payload and non-statement portions of the pre-tree-0 wire still require explicit classification. |
| Child preprocessing root | Trusted child key admitted independently of the child proof | A root supplied with its proof does not establish key admission. |
| Process-local receipt hashes, allocation addresses, diagnostic counters | Local custody checks only | They must not stand in for a semantic AIR relation or independent proof verification. |

The acceptance gate for removing proof-dependent literals must compare circuit
and key identities across two different admitted statements/boundaries, exercise
mutations through the real AIR, and verify a serialized proof in a process that
cannot access the producer or child state. Do not delete the existing constraints
until their authenticated input relations replace them.

Campaign ownership is now immutable: runtime counts and identities live behind
opaque storage with const views, and materializers own their campaign snapshots.
The real saved-proof gate validates after destroying the caller campaign. Several
upper owners still borrow graph/witness preparation and expose mutable native-core
access. A pointer/digest token cannot make those remaining allocations immutable. Separate builder finalization from a privately owned read-only state,
then make cheap accessors available only on that state. The campaign constructor's
failure-path transfer is now repaired: it restores the input if preparation fails
after Base consumes it. The genuine saved-pair gate injects OOM at allocation
18,377, then validates the restored input and empty allocation tracker.

The next measured validation reduction removes reconstruction of the full
expected field schedule: compare the authenticated retained I/O prefix and
regenerate the fixed 125-call suffix in bounded stack storage. Construction and
validation share that suffix writer. This edit postdates the stopped full-wrapper binary and passes both the 39-case
focused suite and genuine custody/rollback gate. The complete wrapper remains
unverified.


### Claim authentication and clock routing prerequisites (2026-09-06, complete proof pending)

The byte-routing checkpoint closes all 256 register-byte arithmetic inputs on the
retained genuine pair, but the complete wrapper still fails before PCS. Its
latest measured residuals are recorded in `statement_byte_routing`; the following
source changes and findings have not yet produced a new complete-cohort result.

Extension detailed claims already have native transcript authority:
`src/frontends/riscv/prover/guest_precompile/ethereum_types.zig::ExtensionClaim.mixInto`
and `mixComponent` mix each detailed batch array before its aggregate. Ethereum
transcript-program schema 4 now classifies 12 such recorded frames through
`consumeDetailedClaims` in
`src/integrations/riscv_cpu/recursive_common_ethereum_incremental_leaf_transcript_program_v4_support.zig`.
It checks the exact native payload and ordered VM input coordinates, then routes
source kind 12 through the existing typed transcript AIR with Ethereum-specific
witness admission. The route and its aggregate-preserving mutation test are
implemented and pass in the 44-case focused suite (37s/3G compile; 832ms/64M
run; `evidence/detailed-claim-routing-tests.log`). The singleton chi-table, xor5-table and
bridge detailed-input aliases remain incomplete. Do not infer complete claim
closure from this partial route.

The base path has a different unresolved boundary. In
`src/frontends/riscv/air/lang/lookup_physical_manifest_v2.zig::AuthenticatedStatement.mixInteractionClaim`,
the channel receives the canonical aggregate vector.
`src/frontends/riscv/prover/base_component_assembly.zig` constructs components
that consume the detailed claims, and
`src/frontends/riscv/recursion/vm_air_composition_circuit_graph_build.zig`
uses them in individually weighted composition constraints while also enforcing
aggregate equality. Source/algebra inspection therefore identifies a gap in the
argument that each detailed claim is fixed before the verifier draws composition
randomness and its OODS point. No adversarial proof has been executed, and this
note does not claim a demonstrated proof forgery. Required next evidence is a
focused native proof-level check, followed by an explicit shared protocol/admission
decision. Aggregate equality is insufficient justification to make these inputs
private or suppress their unmatched authentication lookups. Existing CSP protocol
identities must remain preserved unless an explicit separately versioned route
is adopted and validated.

The proposed register-clock mapping is exact: native V2 public-wire indices
516..643 correspond to public-sum graph inputs 413..540 (128 u16 inputs).
`classifyPreTree0` currently marks only the 412-word embedded statement span as
dynamic, leaving clock words and other raw-wire values as constants. A prospective
Ethereum row-5 variant can emit the existing statement-word relation under a new
admitted scope, with row 11 applying integer checks and wire emissions. The
existing shared statement-routing plan should own all 128 destinations and use
counts. This is still a design, requiring AIR mutation/closure checks and a
versioned catalog/profile before admission.

`src/frontends/riscv/air/public_data_v2.zig::mixInto` also absorbs `wire_id` before
the complete raw wire. Moving clocks out of preprocessing is not the whole
boundary fix: that wire identity and all other proof-dependent raw words still
require authenticated relations or fixed profile classification. A transcript
program authority whose identity includes native/replay custody cannot serve as
a statement-independent circuit key. The acceptance criterion remains key and
circuit invariance across different admitted statements, real AIR tamper
rejection and independent verification of a complete serialized proof.

The disk replay path is now present in source as `test-ethereum-wrapper-replay`,
with `STWO_ETHEREUM_WRAPPER_REPLAY_DIR` selecting `leaf-0.bin`, `leaf-1.bin` and
`wrapper.bin`. Export identity includes the ordered hashes of all three files;
existing bytes are compared in bounded memory and mismatches reject. Those
storage checks pass in the focused suite; independent replay compilation and an
actual retained wrapper verification remain pending. Export occurs after the
proving API's internal verification and initial cold-open return, so failures
inside those earlier steps are not yet retained. Reusing an admitted cohort for
the kernel's internal verification does not satisfy producer destruction; the
separate saved-input rebuild and wrapper reopen remain mandatory.


The subsequent shared-claim/storage focused suite passes 45/45, and the saved
wrapper replay target compiles. An intermediate full cohort reduces verifier
input residuals to 152 (27,813 unmatched total), but its wrapper still fails
before PCS. That executable predates the final consolidation and resource
telemetry edits. Its evidence is separate from the pending latest-source replay;
see the intermediate receipt in `progress.md`. There is still no Ethereum
wrapper available for the disk replay command.


The final shared-claim source snapshot now reproduces 152 verifier-input
residuals and 27,813 unmatched tuples in the complete cohort. The 1/2 gate still
fails before PCS; it does not produce a serialized Ethereum wrapper. Final
request: 250,374,128,333 ns, 38,638,547,360 bytes process lifetime peak footprint,
one worker. The exact current source/log hashes, 15 resource markers and 15
sampled unmatched tuples are in `shared_claim_routing_and_resource_checkpoint`.
This final receipt supersedes the intermediate executable for current-source
claims; neither is a completed proving benchmark.

The memory markers locate the peak increase in native tuple append, after the
prefix/suffix ledger contains only 1,129,391 records. Final ledger capacity is
90,811,043 records at 136 bytes each (12,350,301,848 bytes), with 68,827,570 active
records (9,360,549,520 bytes). The lifetime peak rises from 17,837,127,360 to
38,638,547,360 bytes during native append. This establishes the next allocation
boundary to instrument; it does not identify live memory or prove that array
resizing alone accounts for the peak. Preserve exact tuples/closure and measure
native row temporaries, retained trees and growth overlap before changing the
storage route. Ethereum-only telemetry leaves CSP execution and identities
unchanged. The complete disk replay command in `progress.md` compiles, but still
has no genuine Ethereum wrapper available to verify.


## Verified native schema-3 boundary; wrapper admission still open

The new schema-3 native pair passes serialization, complete producer destruction
and independent verification of both SHA-pinned disk files (1/1; 125.139s;
1,179,403,824-byte lifetime peak; one worker). See
[evidence/ethereum-base-bound-producer.log](evidence/ethereum-base-bound-producer.log)
and the `base_bound_native_schema3_checkpoint` JSON object. This is a native
fixture milestone, not a recursive wrapper or whole-block proof. The prior
27,813-unmatched wrapper failure remains historical evidence for its recorded
source snapshot.

New wrapper admission must require detailed-base schema 3. Retained schema-2
native fixtures remain explicit legacy regressions. The intermediate focused
52/53 result exposed a four-host-word/eight-recorded-limb header mismatch; its
fix and the new public cancellation endpoint await the next combined gate.
Remaining program/statement admission and exact role-I/O routing must close
before a wrapper can be promoted as independently verifiable.

## Bounded program/publication checkpoint; fixed admission remains open

The later publication integration batch passes 65/65; whole-ELF admission passes
4/4. The frontend publication preparation receipt is 43/43 before prototype
removal. These replace the earlier focused failures for their tested batches,
but do not validate the later schema-4 source or a complete wrapper. The native
schema-3 producer remains the earlier 1/1 lifecycle receipt. See
`bounded_admission_and_publication_checkpoint` in the JSON evidence file.

The first admitted program route covers the entire ELF and constrains completion
PC/raw/decoded values against its full executable table, bounded to 64 rows.
Role capacity is at most 32; completion uses an explicit nonfinal profile. This
is a complete-fixture development profile and cannot be described as a mainnet
block benchmark.

Native schema 4 has an opt-in shared tagged frame emitter that removes custody
SHA values from transcript framing and explicitly absorbs role IO/completion.
Its five tests, including exact legacy recorded-frame preservation and real
profile/helper invocation, await execution. Schema-2/3 regression interpretation
is retained. Raw V2 exhaustive classification has a retained initial compiler
failure; its rerun and authenticated AIR closure remain pending. Current
schema-3 cohort replay is running without a terminal receipt at this checkpoint.

Fresh wrapper reopening still loads and verifies both native proofs to rebuild
verifier preparation before checking the wrapper. Producer destruction and
independent reopening establish a lifecycle boundary, not a succinct endpoint.
Fixed admission must separate all statement-dependent preprocessing from circuit
structure. Root-only verification additionally needs actual child verification
in AIR with only the public statement, admitted ELF/profile and root artifact at
the external verifier. No independently verified wrapper or root is recorded.

## Shared final-claim boundary and 458-residual diagnosis

Current focused checks pass frontend 41/41, integration 79/79 and native V2 layout
18/18. Schema-4 tagged emission and frame-plan tests now pass; their integration
into the active recursive admission remains unfinished. Native, recursive and
prover-hook final claims now use `AuthorityV4.mixFinalClaims`, preventing the
observed recursive omission of schema-3 selected-base frames. Exact legacy
schema-2/3 framing and schema-2/3/4 interaction ordering are regression checked.

The retained real cohort failure has 458 unmatched tuples over 68,814,696
contributions (255.244s; 38,094,647,232-byte lifetime peak). The 450 duplicate
public-boundary emissions and eight inherited claim-hash digest consumers are
identified. Current source removes both redundant paths, including actual child
hash provider calls, and keeps the semantic, role and IO checks. Complete-proof
session 19754 subsequently passed exact closure and failed during STARK proving;
see the terminal receipt below.

A historical independent input reconstruction receipt passed 1/1 after producer
allocations reached zero, but explicitly verified no wrapper. Its source head
and exact executable snapshot are unknown; it is not a current-tree result or
part of the current 41/79/18 batch. The active route still needs native
proof bytes and host native verification. It cannot be promoted as a fixed,
independently verifiable root. The tested schema-4 frame plan and exhaustive raw
V2 classification need authenticated circuit integration; the bounded fixture
is not a mainnet Ethereum benchmark. All receipts and scopes are in
`shared_final_claims_and_boundary_closure_checkpoint`.


## Exact cohort closure and the remaining proving failure

Session 19754 (`test-ethereum-complete-proof`) passed 2/3 tests and failed the
genuine saved-pair wrapper request at `prove.stark` with `InvalidProofShape`.
Before that failure, the exact tuple ledger classified and released all
68,788,872 contributions without mismatch. The redundant boundary and inherited
claim-hash routes are therefore closed for this actual cohort. No wrapper was
serialized or independently verified.

The request took 597.676632792s. Ledger classification reached a process lifetime
peak of 27,332,448,608 bytes; later proving raised the overall peak to
45,273,744,552 bytes. The historical 458-residual run peaked at 38,094,647,232
bytes. The lower ledger high-water is not a whole-request memory improvement or
a live-owner measurement. Full telemetry and the uniquely retained terminal log
are recorded in `complete_proof_boundary_v4_checkpoint` in the PR198 JSON receipt.

Focused schedule admission now passes 15/15 and native V2 layout 20/20. The
proving-policy correction being implemented after the failure is unverified at
the complete-proof level. Schema-4 FramePlan integration, authenticated raw V2
AIR routing, and the complete serialization/destruction/verification lifecycle
remain prerequisites. The active bounded fixture route is native-assisted, not
a root-only or mainnet block endpoint. The historical source-unknown input
reconstruction receipt remains separate from current gates.


The subsequent focused gates pass integration 83/83, native V2 layout 20/20,
schedule admission 15/15 and quotient domains 6/6. Their logs are retained in
`retained_coefficients_retry_checkpoint`. Coefficient-retention retry session
1030 has returned with a later finalization failure, recorded below. Fixed recursive admission and root-only verification remain open.


## Retained-coefficient terminal receipt

Retry 1030 passed 2/3 tests: all 68,788,872 exact tuple contributions closed,
then finalization rejected with `ConstraintsNotSatisfied`. The former
`InvalidProofShape` is no longer this run's stopping point, but no wrapper was
serialized or independently verified. The full request took 814.173816291s with
a 59,835,018,536-byte process lifetime peak. Finalization/OODS debugging and a
later focused 87-test gate are pending; no successful outcome is inferred.

The actual resource plan has `blowup_log=1` (LDE factor 2). Native-sized retained
coefficients total 10,908,653,376 bytes, half the LDE storage; the earlier guessed
1/16 ratio does not apply. The PCS minimum estimate is 32,725,960,128 bytes,
excluding Merkle, witness and composition owners, and is distinct from the
measured process peak. The uniquely retained terminal log and hashes are in
`retained_coefficients_terminal_checkpoint`. The active route still needs fixed
recursive admission and a complete wrapper lifecycle; native-assisted reopening
is not root-only verification or a mainnet block benchmark.


## Verified coefficient recovery and bounded preflight

Quotient recovery now passes 8/8 after fixing packed radix-8 indexing for a
larger twiddle tower. Exact-size indexing remains unchanged. The independent
1/1 kernel regression covers forward, inverse, normalized inverse and
duplicated-half expansion with 1x/2x/4x table sizes. Missing coefficients are
recovered from the complete committed LDE inside the existing quotient buffer;
nonzero coefficients above native degree reject before truncation. Genuine
nonconstant polynomial parity passes at native logs 2/4/6/7/8. No additional
whole source coefficient set is retained; quotient buffers remain live.

Integration passes 89/89 and static AIR preflight 2/2. The genuine first-18
component preflight passes 1/1, checking direct roots, adapter parameters and
padding (93.695878083s, 17,835,849,240-byte lifetime peak). Its receipt explicitly
excludes the full cohort and wrapper verification. Exact logs and source-batch
limitations are in `quotient_recovery_and_preflight_checkpoint`. The full
schema-3 native-assisted wrapper still fails OODS finalization with
`ConstraintsNotSatisfied`; no root-only verification or Ethereum block proof
is established. Fixed schema-4 admission and raw V2 AIR integration remain open.


## Normalized mixed-quotient admission checkpoint

The production-geometry fixture exposed a q1/q2 lifting mismatch (3/4 tests
passed). Ethereum wrapper admission v1 now selects split two for every component:
q1 callbacks use the existing polynomial extension; q2 callbacks change only
the split declaration. Both prover/verifier handle sets are normalized before
gate sealing. Wrapper manifest schema 13 binds this policy into the contract
identity; native schema-3 leaf fixtures and default CSP geometry stay unchanged.

Admitted geometry passes 5/5, core split-only behavior 3/3, and explicit wrapper
capture admission 3/3. Capture reconstruction uses normalized `max(trace+2)`
and requires split two only through the Ethereum wrapper constructor; legacy
constructors still reject it. The first-34 genuine AIR preflight passes 1/1
(101.466684791s, 17,835,931,208-byte lifetime peak), excluding provider rows and
wrapper verification. The small proof executable passes 2/2 but its target's
count guard failed; the aggregate remains 95/96 until corrected retry 40794
finishes. These results are retained in `normalized_wrapper_geometry_checkpoint`.

No new full wrapper receipt exists: the last complete request failed OODS
finalization. The current native-assisted diagnostic is not root-only
verification or an Ethereum block benchmark. PCS resource estimates exclude
additional quotient-extension/composition buffers.


## 2026-09-06: corrected combined gate passes 101/101

Combined session 40794 passed **101/101 tests and 8/8 build steps**, including
both exact-count guards: small composition proof **2/2** (19s/1G compile,
304ms/4M run) and integration **99/99** (1m/5G compile, 1s/69M run). This
supersedes the earlier fixture-count and test-count-guard failures; their logs
remain retained as historical regression evidence. The new immutable receipt is
`ethereum-composition-admission-combined-101-passed.log` in the PR198 evidence
directory, with its SHA-256 and source-batch scope in `combined_pass_checkpoint`.

Complete-wrapper and failed-proof replay compile checks are running in session
41064; no terminal result is recorded here. The latest full wrapper result
remains the retained `ConstraintsNotSatisfied` failure. These focused successes
do not establish wrapper serialization/fresh verification, a root-only endpoint,
a full Ethereum block benchmark or CSP promotion.


## 2026-09-07: STARK succeeds; cold geometry rejects the split-two capture

The complete-wrapper retry used frozen source snapshot
`237f9cdea71e6ee2db29808e4d8f0c73f5bc6ffe`, source SHA-256
`fa69c65fba207556e7f88c151d28d47d1bf74ada4e5b07e35f4c5e1be2522ddd`.
STARK generation succeeded in **433.091515875 s**, and native STARK verification
returned successfully. The later `ColdGeometry` admission still expected eight
composition columns from the global split-one default; this wrapper explicitly
admits split two and has sixteen. It rejected the capture with
`InvalidEthereumIncrementalColdGeometryV4`.

The complete gate therefore **failed: 2/3 tests passed, 1/4 build steps passed**.
The whole request took **1348.869591958 s**, with a process-lifetime physical
footprint peak of **52,615,273,088 bytes** (52.62 GB). The earlier retained-
coefficients attempt peaked at 59,835,018,536 bytes and failed OODS finalization;
these runs reached different phases and outcomes. Their peaks are descriptive
observations, not a matched memory or speed comparison.

This is not the first independently verified wrapper lifecycle: cold admission
failed before returning the completed owner, and the final producer-destruction
and independent-verification gate was not reached. No canonical wrapper proof
candidate was retained because its persistence hook followed successful cold
opening. The full log, progress log, live cold-validation sample and source
receipt are retained in
[evidence/2026-09-07-normalized-q2-cold-geometry-failure](evidence/2026-09-07-normalized-q2-cold-geometry-failure),
with hashes and exact scope in `normalized_q2_cold_geometry_checkpoint`.

The next changes address this shared-admission mismatch and retain proof bytes
before cold admission. Later validation changes are not part of the measured
snapshot. Root-only verification, fixed schema-4 admission, whole-block proving
and latest-source CSP promotion remain unfinished. The CSP comparison is
prepared but has not run; its candidate must be refreshed after source changes
stabilize.


## 2026-09-07: first independent wrapper lifecycle passes

Frozen snapshot `804799bc288f8f41904edec7f5a17db22a65b3af` (source SHA-256
`1ad0fdb5e8329f497860389af2003dce61b0773bb27a7f1b4daf5d8b87215939`)
passed the complete lifecycle: **3/3 tests**, canonical serialization, producer
allocator drained to zero, fresh verifier reconstruction, successful cold
verification and all postprocessing/mutation checks. The canonical proof is
3,019,076 bytes, SHA-256
`f404b395543ba08d5b2d0014ef5a71d7653e925b335b0bc5632e3ea179f6ecf3`.
The focused preflight had passed 106 admission/routing tests plus two complete
mixed-degree STARK tests.

This is the small genuine **native-assisted wrapper**, not a whole Ethereum
block or a root-only recursive proof. Active native child admission remains
selected-detailed schema3; field-authority schema4 and parent Ethereum transcript
publication remain unselected. No new CSP promotion or CPU/Metal A/B is claimed.

Measured request: 7,493.155262042 seconds (124.89 minutes), of which
434.685765000 seconds were STARK construction, 1,279.436158666 seconds were the
wrapper prove/cold-open phase, 376.380326416 seconds were independent reopening,
and **5,728.522278083 seconds (95.48 minutes) were postprocessing**. Peak physical
footprint was 52,615,223,816 bytes; peak tracked allocations were 43,963,032,188
bytes. Final tracked ownership was zero. The retained native input proving is
excluded. These are diagnostic timings, not an Ethereum block benchmark.

The proof and logs now allow subsequent verification/ownership changes to be
checked without reproving. Opaque cold-owner and new transcript-route edits
made after the frozen binary launched are a separate, initially unverified
source batch. Evidence: [checkpoint](evidence/2026-09-07-first-independent-wrapper/checkpoint.json)
and [complete log](evidence/2026-09-07-first-independent-wrapper/complete-proof.log).

## 2026-09-07: retained wrapper replay passes

The private-owner replay passed fresh verification and publication/mutation checks in 618.19 s; postprocessing fell from 5,728.52 s to 188.76 s. This remains a native-assisted small wrapper. The checked-view follow-up passed: postprocessing is now 55.86 s and complete retained replay 479.72 s, with additional child-alias regressions. Root-only field admission remains pending; current CSP preservation is running. See [the authoritative progress checkpoint](progress.md#2026-09-07-retained-wrapper-independently-replays-after-ownership-fix) and its linked evidence.
