# Local Ethereum engineering progress — 2026-09-05

Active source: PR #198, `autoresearch/metal-ecdsa-subsecond-20260829`, base
`6b7f08af51204dc8e96252879c772a8bed874748`. The [unified goal](unified-goal.md)
governs implementation order. This record is a work log, not block-proof or performance-promotion evidence.

## Native campaign checkpoint — 2026-09-08, 20 accepted leaves

Accepted unique segments now comprise **0–18 and 120: 20/121**. Newly accepted
17 and 18 were rehashed against their canonical metadata and successful separate
verifier receipts; their proofs are 60,403,484 and 61,514,273 bytes. Fresh verifier
times were 48.39 and 48.86 seconds respectively, including the verifier's admitted
native route rather than an isolated STARK-kernel measurement. Controller35106
continues unchanged; real19 production has completed and its separate verifier
is waiting behind wrapper2. Whole-block verification remains pending.
[New acceptance evidence](evidence/2026-09-08-keccak-campaign-boundary/real17-18-native-campaign-acceptance-v1.json).

## Current wrapper delivery blocker — 2026-09-08

The repaired real wrapper2 v7 run has acquired the shared lock after 529 seconds
and is executing as testPID40352 (session71193, launcher39991). Its initial native
cold-open phase completed in 100.18 seconds. This is a running real proof attempt,
not wrapper acceptance. Native19 production separately completed in 544.14 seconds
with internal cold verification and a 31,859,924,488-byte lifetime peak; its fresh
standalone verifier is waiting behind the wrapper, so accepted count remains20.
[Actual retry start and terminal authority](evidence/2026-09-08-wrapper-file-backed-pcs/real-wrapper-v7-started.json).

Live observation at approximately 31 minutes of test runtime confirms ongoing
suffix preparation after geometry and prefix rows. The last reported lifetime
peak is 31,979,626,568 bytes (29.8 GiB). A one-second sample places all 84 main
thread samples in suffix statement/campaign validation, including continuation
compensation field inversions. This is a narrow sample, not a complete-request
cost attribution or resource failure. Keep this optimization deferred and let
the changed real proof run complete. No new wrapper or parent was accepted at
this checkpoint; native acceptance remains 20/121.
[Live process, phase snapshot and retained sample](evidence/2026-09-08-wrapper-file-backed-pcs/real-wrapper-v7-preparation-observation-v1.json).

At approximately 45 minutes of runtime, the same process has passed exact closure
of 166,400,671 tuple contributions and released the ledger. Its lifetime peak is
56,226,636,864 bytes (52.4 GiB). A subsequent live sample confirms execution has
advanced to fixed Tree0 preparation (`fillBaseTree`), where nested structure,
transcript and campaign validation still consume time. This remains deferred
performance evidence; the run is unchanged and no wrapper is accepted yet.
[Post-ledger live sample](evidence/2026-09-08-wrapper-file-backed-pcs/real-wrapper-v7-post-ledger-sample.txt).

The initial Tree0 CPU commitment subsequently completed in 471.36 seconds;
the containing preparation phase took 654.77 seconds. Its file-backed allocator
reported 15,264,661,504 total mapped bytes and zero remaining mapped bytes at
release. This does not yet exercise the repaired full-prover main-tree path.
The same process remains live; full wrapper and independent verification remain
pending, with native acceptance still 20/121.
[Tree0 phase records and live-process observation](evidence/2026-09-08-wrapper-file-backed-pcs/real-wrapper-v7-tree0-completion-v1.json).

At about 61 minutes the process remains live in
`EngineKernelForManifest.validateSessionAgainstCohort`, following the completed
Tree0 preparation. The one-second sample contains cohort/geometry/native-provider
validation and shared Poseidon schedule hashing. Attribute this interval to
session preparation, not Tree0 commitment or final STARK verification. It remains
a deferred optimization observation, not permission to restart the proof.
[Session-validation sample](evidence/2026-09-08-wrapper-file-backed-pcs/real-wrapper-v7-session-validation-sample.txt).

Full-prover preprocessing passed in 290.76 seconds. The selected mapped main
arena (11,824,971,072 source bytes) then allocated in 31.61 seconds, with sampled
current footprint increasing only 5,792,024 bytes to 34,294,854,656. This is an
allocation-phase observation, not a whole-proof memory saving: filling will
touch the mapped pages, and main commitment remains pending. The process is
still live; no real wrapper is accepted yet.
[Full preprocessing and main allocation records](evidence/2026-09-08-wrapper-file-backed-pcs/real-wrapper-v7-main-allocation-v1.json).

**The repaired main-tree commitment has passed on the real wrapper.** Main fill
took 250.19 seconds and commitment 196.27 seconds; allocation/fill/commit together
took 478.07 seconds. Current footprint after commitment was 36,449,212,680 bytes;
lifetime peak remains the earlier 56,226,636,864-byte preparation peak. This run
has completed the stage that the prior v4 attempt did not complete. Remaining
interaction, composition, FRI, serialization and independent verification are
still required; no wrapper is accepted yet. During commitment one process sample
reached 1193.9% CPU, so the configured one-worker policy must not be described as
single-core execution. This sample is not a phase-average parallelism measurement.
[Main-phase records and live-process observation](evidence/2026-09-08-wrapper-file-backed-pcs/real-wrapper-v7-main-commitment-v1.json).

A live sample during the subsequent interaction phase places execution in
`fillInteractionInto → validateGenerated → auditAndClose`, including nested
transcript/program/input validation. It establishes the active work at that
instant, not the entire interaction-phase cost or a completed closure check.
The same process remains live at approximately 88 minutes; no wrapper acceptance
or additional native acceptance has occurred.
[Interaction closure-validation sample](evidence/2026-09-08-wrapper-file-backed-pcs/real-wrapper-v7-interaction-closure-sample.txt).

The file-backed v4 real wrapper2 attempt is terminal **failed, signal 9**, with
no accepted proof. Its command took 4,377.70 seconds including queue and compile.
Full-prover preprocessing completed, including Tree0 commitment and admitted-root
comparison; the failure followed during main-tree allocation/fill/commit, which
the old phase telemetry cannot distinguish. Lifetime peak footprint was
56,226,604,168 bytes and the final sampled current footprint was 34,289,685,368
bytes. Signal 9 alone does not establish a memory-kill cause.

Reassessment after the two failed real attempts found that retained-LDE mapping
still left a whole-source-tree detach in both shared and borrowed PCS ingestion.
The main source arena is 11,824,971,072 bytes. The bounded repair uses mapped
source arenas and bounded source/LDE batches, and adds separate main allocation,
fill and commitment measurements. This is not a third speedup project: acceptance
requires the small complete proof with actual mapped source ingestion, focused
PCS ownership/parity checks, then the real wrapper2 and separate-process verify.
Frozen ordinary source v7 (`cc4df4adc3913b0a68dc975dbc4f06afebcb03b912865e1901f636448819067f`)
passes all **13 PCS storage tests**, all **3 small complete-STARK tests**, and the
complete-wrapper compilation gate. The tests exercise actual mapped source
allocation, bounded shared/borrowed ingestion, canonical proof parity, scratch
and producer destruction, fresh verification, and allocation-failure cleanup.
The retained failure exposed duplicate cleanup ownership in FFT preparation;
the narrow repair passes exhaustive allocation-failure injection. All 5,756
source pins were rechecked after validation; exactly seven files differ from
ordinary v4, and no Initial38 changes enter this candidate.

The changed real wrapper2 v7 retry has now launched with a separate corpus and
scratch directory. **No real proof is accepted yet**; completion and a separate
process's pinned root verification remain required. Earlier diagnostic wrappers
do not meet the active field-profile/campaign admission and cannot substitute.
[Storage recovery gates, seven-file pins and retained failing case](evidence/2026-09-08-wrapper-file-backed-pcs/checkpoint-v2.json).
[Retained terminal logs, source pin and repair criterion](evidence/2026-09-08-wrapper-file-backed-pcs/real-wrapper-failure-analysis-v4.json).

The standalone ordinary-root verifier build has passed from frozen v4 source;
binary SHA256 `77120ae24d5ef2846cd743baa447bdf7cf5f2641961413db326bd64a89d36907`.
This establishes verifier availability, not wrapper acceptance. Native campaign
production continues independently under the shared heavy-job lock.

The existing `scripts/ethereum_wrapper_root_check.py` now accepts only explicit
semantic rejection errors for its deliberate mutations. An OOM, I/O error,
timeout, crash or unknown error cannot masquerade as rejection. It uses the
shared job lock and records queue time separately from verifier process time.
Explicit `--initial-v1` additionally checks both Initial38 claims and the valid
alternate public node retained by the complete initial producer. Four process
gate regression tests pass; their mock subprocesses are not proof evidence.
The tested checker and lock helper are frozen in
`.git/local-ethereum/wrapper-root-check-v2/`, manifest
`e2c43db846afb5de399dc188a4dc3d5f40d363a2dfb06cfb6784f1beaaa1e8f4`,
ready to consume the real wrapper candidate after its producer terminates.
[Checker tests and limits](evidence/2026-09-08-wrapper-file-backed-pcs/root-check-process-tests-v2.json).

### Immediate consumers of wrapper2

Wrapper3's geometry-only request is frozen at
`.git/local-ethereum/real-wrapper-segment3-geometry-v2/request.json`, source manifest
`0c59cb6ef39b87b9f50935119b64bc5c9299e7cd97c28ffe6b1c8e27b59af84e`.
It requires wrapper2's independently accepted key, admits it through the shared
key/child-shape owner, and compares all ten wire dimensions against actual context
3/4 before wrapper3 production. Both guarded test names now live directly in the
test root, eliminating imported-test discovery uncertainty. Syntax checks pass;
semantic compilation and actual compatibility are unverified. No job was queued.
[Frozen geometry request](evidence/2026-09-08-wrapper3-geometry/request-v2.json).

Wrapper3's production template is also prepared at
`.git/local-ethereum/real-wrapper-segment3-file-backed-v7/request-template.json`,
SHA256 `8af5a9e11f97526d8a281d054ecbbff4c59bfd9f8e78dd2e7e36144d80f48a95`.
It reuses the ordinary v7 source/build and its already-passed storage gates, with
context3/4, pair slot0 and separate corpus/scratch directories. All five context
file identities and the retained failing input were checked. It deliberately has
no launch argv: first record wrapper2's independent acceptance and the successful
geometry-v2 receipt, then create the actual request. No wrapper3 job was queued.
[Pinned production template and launch conditions](evidence/2026-09-08-wrapper3-geometry/wrapper3-production-template-v1.json).

The next actual sibling-parent route is frozen at
`.git/local-ethereum/saved-real-parent-source-v1/`, manifest
`a2912e320765a948de4abaf989cdbd3ef50f71ed1a6d552441198f8bef2afdf5`.
It derives from the ordinary v7 source with only two parent test files and their
build-step insertion; no Initial38 work enters this consumer. The acceptance
test now distinguishes a malformed public node from a well-formed changed source
commitment using shared hash helpers, and accepts only specific cryptographic
rejections for the latter. Reversed/duplicate children require their exact error.
The existing resource estimate runs before full parent PCS allocation, but after
independent Tree0 key admission; the common-fold route does not use the leaf
scratch allocator. This is an unmeasured resource risk, not a demonstrated failure
or an authorized third optimization. All 5,758 frozen source pins and syntax
checks pass; semantic compilation, actual parent proof and separate-process
verification remain pending. The request cannot be filled until both wrappers
have independent acceptance receipts.
[Parent request, three-file pins and acceptance limits](evidence/2026-09-08-saved-real-parent/preparation-v1.json).

## Initial root lifecycle integration — 2026-09-08

- The full complete-proof lifecycle **compiles both ordinary and Initial38
  assemblies and kernels**: 2/2 steps, compiler 2 minutes / MaxRSS 5G, frozen v4
  manifest `181a588f6aab4c9526b50338f01c6ca701da06f14fabac546d4458858d186357`.
  This includes canonical serialization, producer destruction and the selected
  fresh verifier calls; it is compilation evidence, not a completed real proof.
- Focused preparation/admission checks pass **8/8**, and initial/ordinary root
  admission passes **16/16**, frozen v5 manifest
  `dfc3b0b8eb70b25f67c3858545ed2ee51eeb50737776ce53fc5106e9e21fd180`.
  The only code change after the full compile was a fixture repair: boolean
  profile fields are toggled, while numeric fields are incremented. Genuine
  initial lane/packet column writers and exact 38-component per-domain closure
  checks pass **2/2**, with explicit test discovery in frozen v6. Earlier queued
  validation entries are superseded; all these gates are terminal.
  [Commands, source pins, retained logs and acceptance limits](evidence/2026-09-08-initial38-assembly/receipt-v2.json).
- Explicit Initial38 selection now joins the ordinary row owners with input
  lane36 and packet37 before shared range construction and exact tuple closure.
  All38 claims enter the proof gate and common per-domain cancellation check;
  the external statement marker is38. Initial source rows remain immutable and
  are protected against destination aliasing. Ordinary36 remains the default
  API and retains its identity hashing and component placement.
- Initial fixed circuit identity binds admitted geometry and arithmetic without
  per-capture custody hashes. The complete-proof route requires a retained
  corpus, destroys producer owners, then opens serialized key/public/proof
  inputs through the Initial38 verifier and compares the expected public node.
  Wrong-key, changed-public-node and corrupt-proof cases are retained. The old36
  cold-capture path rejects initial inputs explicitly. Actual initial recursive
  child publication into the detached fold remains unfinished.
- Initial0/1 input readiness is recorded under
  `.git/local-ethereum/initial-terminal-wrapper-readiness-v1/`:149 retained source
  and receipt records matched their hashes/sizes, which is byte authentication
  rather than a new STARK verification. Initial0 has an exact request and a
  separate corpus seeded with the genuine retained failure case `c86f6acd…`.
  No real initial wrapper has been proved and freshly accepted yet.
- Terminal120's native proof is retained; adjacent context119/120 still needs
  native119. The running controller snapshots its reusable inventory at startup,
  so copying a119 proof into live output would not prevent reproving it. Use the
  [restart/import fallback](evidence/2026-09-08-keccak-campaign-boundary/terminal119-reuse-fallback-v1.md)
  only if terminal admission becomes the next blocked proof before119 completes
  naturally.
- Ordinary wrapper2, compatible wrapper3 and their actual parent remain the
  immediate recursive artifact sequence. The v4 wrapper2 attempt failed as
  recorded above; no unchanged retry is authorized by this checkpoint. Named
  `check-ethereum-saved-real-parent` and `test-ethereum-saved-real-parent`
  commands exist, but their actual child-dependent gate remains pending accepted
  wrappers. The independent ordinary verifier product is available; availability
  alone establishes no wrapper or parent acceptance.

Initial38 detached transcript/composition selection is now implemented in the
active tree with explicit versioned policy. It shares the existing operation
builder and recording path, preserves the 41-slot ABI, keeps physical claims
36/37 dynamic, constrains slot38 to zero, and retains provider slots39/40.
Focused frame, row, policy, descriptor and mutation tests have been added.
Formatting and AST checks pass; semantic execution and retained initial-proof
replay remain pending behind the ordinary proof route. This does not activate
the heterogeneous initial0/ordinary1 fold or establish an initial proof.
[Transcript source and exact commands](evidence/2026-09-08-initial38-assembly/transcript-selection-source-v2.json),
[composition source and exact commands](evidence/2026-09-08-initial38-assembly/composition-source-ready-v1.json).

## Real wrapper storage recovery — 2026-09-08

- Added explicit file-backed retained PCS column storage after the real segment-2
  resource failure. It reserves disk space before shared mapping, unlinks scratch
  files immediately, moves/frees one completed column at a time, and keeps ordinary
  allocation as the default. It changes storage, not the AIR, transcript or keys.
  The opt-in is `STWO_ETHEREUM_PCS_SCRATCH_DIR`; current and peak physical footprint
  are now distinct phase measurements. Memory fit for the real wrapper is unproven.
- Allocator checks pass **3/3**. The complete small heterogeneous STARK gate passes
  **3/3**, including identical canonical bytes with mapped storage and independent
  verification after scratch/producer destruction. Focused PCS checks pass **8/8**
  including discovery, complete mapped PCS proof parity and allocation-failure
  cleanup. The broader PCS suite is not green: its FRI work-counter mismatch and
  test-only checked integer overflow both reproduce on the pre-change frozen v2.
- The real segment-2 complete proof retry is launched from frozen source manifest
  `8fbdbfe38e4c167cb769ab34255f0f614ad9029c240216e64058a38b00bcf0a9`
  (5,756 files), using the same native pair and circuit, a separate corpus and
  file-backed retained columns. Session `51199` owns its execution; the receipt at
  `.git/local-ethereum/real-wrapper-segment2-file-backed-v4/execution.json` is the
  terminal authority. This launch is not real wrapper/root acceptance.
  [Commands, gates and retained baseline failures](evidence/2026-09-08-wrapper-file-backed-pcs/checkpoint-v1.json).
- A two-second live sample of the retry at roughly28 minutes shows cohort
  initialization and transcript-state sealing, with reported physical footprint
  29.3G. This is not STARK verifier timing, a complete profile, or evidence that
  later PCS storage fits. The run remains unchanged; the sample is retained for
  post-delivery investigation.
  [Sample and interpretation limits](evidence/2026-09-08-wrapper-file-backed-pcs/live-sample-v1.json).
- Initial/ordinary root admission previously passed **15/15**, and compact initial
  policy passed **13/13**. Selected Initial38 complete cohort assembly now compiles
  and its focused gates pass as recorded above; a real segment-0 wrapper remains
  unaccepted.

## Delivery recovery checkpoint — 2026-09-08

- The actual segment-2 complete wrapper run is terminal **failed (signal 9)**,
  not an accepted proof. It completed exact tuple classification (166,400,671
  contributions), released the ledger and committed Tree0; its last phase report
  was preprocessing. Reported lifetime peak footprint was 57,180,776,232 bytes
  (53.25 GiB), and the three retained PCS trees alone were estimated at
  47,559,075,456 bytes (44.29 GiB), excluding witness/Merkle/composition storage.
  The signal alone does not establish its cause. This measured resource obstacle
  requires a bounded storage fix before repeating the real wrapper; no additional
  speedup search is opened. Command wall time was 4,292.86 seconds including queue
  and compilation. No real wrapper, parent or block root is accepted.
  [Terminal receipt and retained logs](evidence/2026-09-08-native-root-routing/real-pair2-complete-proof-failure-v2.json).
- The initial manifest gate passed **5/5**, compact initial claim policy **2/2**,
  and the initial/ordinary root-admission gate now passes **15/15** after fixing
  selected catalog row typing. The latter includes component ordering, independently
  pinned key transport, explicit initial-profile selection and child geometry.
  These are focused admission checks; initial cohort assembly and a complete
  initial proof remain outstanding. The compact row-owner gate subsequently passed 13/13 after repairing
  a missing optional argument in a legacy test fixture.
- Native recovery passed real Metal segment 11 and resumed production: **18 unique
  native leaves are accepted (0–16 and terminal 120)**. Segment 11’s 5,509 Keccak calls use canonical
  log17 under explicit Ethereum maximum18; legacy/CSP maximum16 is unchanged.
  Producer request: 278.10 seconds, proving: 175.55 seconds, peak footprint:
  17,901,762,264 bytes (16.67 GiB). After producer destruction, a separate verifier
  accepted the serialized 60,940,314-byte proof in 48.39 seconds (44.96-second
  verification, 1,034,028,328-byte peak). Proof SHA256:
  `4aab103858d9bd1d9ad254427c8c8c48d7442536dadbd56cbda7391d05fb5722`.
  The stopped synthetic context gate was a two-cycle fixture claiming 9,828
  external calls; correcting its authenticated span makes live and frozen gates
  pass 2/2. Replacement Metal product passes 3/3 tests; both products are built
  from source manifest `3b9ab4c9b99a6de7de90d49168d898c6e4dad4cb35d26fe49888b05ba3c3a6ec`.
- The explicitly migrated Metal campaign is running as PID 35106 / session 30220
  in `.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907/metal-field5-block-v2`.
  Imports 0–11 and 120 preserve original proof bytes, producer identities and
  timing receipts; the new controller freshly verifies each without reproving it,
  then continues without restarting. Segment 12, the first newly produced leaf
  after migration, has now independently passed: 193.779-second producer request,
  64.106-second proof, 9,950,109,928-byte peak; fresh verification request 47.871
  seconds (44.396-second verification), 981,910,728-byte peak. Its proof is
  60,605,324 bytes, SHA256
  `6d0317c5490f72e2120e6643b0cbc8459e9106c3b85756f84c73ffa2250c48ea`.
  Segments 13–15 also passed separate verification, bringing the campaign to
  17 unique accepted leaves; their producer requests were 151.91/154.30/156.43
  seconds, with 27.24/27.27/27.35 seconds proving. Independent verifier requests
  were 48.34/49.17/49.64 seconds.
  [Retained segment-13–15 receipts](evidence/2026-09-08-keccak-campaign-boundary/real13-15-native-campaign-acceptance-v1.json).
  Segment 16 also independently passed, bringing the current count to 18;
  [its exact proof and process receipts are retained](evidence/2026-09-08-keccak-campaign-boundary/real16-native-campaign-acceptance-v1.json).
  Controller production continues unchanged at 17. Queue waits (4,353 seconds before its
  producer and 53 seconds before its verifier) are separate from these process
  timings. [Retained segment-12 acceptance](evidence/2026-09-08-keccak-campaign-boundary/real12-native-campaign-acceptance-v1.json).
  Plan SHA256:
  `1928f72ed715f6ac4086d8c6ff033bcb42fcff377dba121e4d45aa0a3650d833`.
  One child runs under the shared lock at a time. Complete 121-segment coverage
  and independent bundle continuation verification remain outstanding. On real11,
  composition evaluation took 124.75 seconds (71.1% of proving); this is retained
  bottleneck evidence for later optimization, not another interruption to delivery.
  [Acceptance, pinned receipts and migration evidence](evidence/2026-09-08-keccak-campaign-boundary/real11-native-recovery-acceptance-v1.json).

- Read-only final-bundle readiness audit found the accepting integration already
  connected: after all 121 leaves, the controller calls the pinned
  `verify-bundle-fixed-program-v5` endpoint with independent manifest and
  materialization hashes, checks exact receipt/count/worker identity, and retains
  its terminal result. Shared coverage checks bind order, clock continuity, CPU
  and memory boundaries, complete initial/final state and the intended job; each
  proof is then freshly verified with one live capture. The historical genuine
  pair and rejection gate passed; its bundle body is unchanged in the frozen
  verifier, but that dedicated gate has not been rerun against all newer native
  dependencies. Full121 acceptance is still required.
  [Pinned command, limits, negative-gate evidence and remaining checks](evidence/2026-09-08-keccak-campaign-boundary/whole-bundle-readiness-v1.json).

## Continuation-root integration checkpoint — 2026-09-08

- The Metal controller accepted segments 0–10 plus retained terminal 120, then
  stopped on segment 11 with Keccak `CallRangeTooLarge` before proving
  (91.503-second failed producer request). Its terminal receipt confirms exit 1;
  production recovery is the native track's next blocker. It freshly reverified
  imported segment 9 in 54.210 seconds without reproving it. These are 12 accepted
  records, not whole-block acceptance. CPU production remains stopped at its retained
  safe boundary; its pending successful candidate must be recovered on resume.
  The bounded recovery now threads explicit Ethereum schema5 Keccak geometry
  through native and integration admission, retaining legacy/CSP log16 entrypoints.
  Its focused geometry gate and frozen replacement products are queued; segment11
  proof/fresh verification must pass before an explicit campaign migration.
  [Retained production failure](evidence/2026-09-08-keccak-campaign-boundary/checkpoint.json).
- Native continuation roots now route in a separate statement namespace from
  snapshot digests. Canonical raw-limb joins publish exact counts derived from
  the admitted public-sum, VM-composition and transcript-frame consumers.
  The joint focused gate passes 8/8, including distinct snapshot/root values,
  missing/duplicate/miscounted uses, source substitution and canonicality checks.
  Frozen source manifest SHA256 is
  `004f181199b663e94641a5674914c569a03af62a21f602b2dec871324b4447ea`;
  compile 11 seconds / 986 MB, tests 298 milliseconds / 5 MB.
- The first real context-2/3 AIR run passed VM materialization, then failed claim
  semantics on the same obsolete equality between scalar roots and snapshot
  digests. Request 557.26 seconds, peak 5,733,766,448 bytes. A focused replay of
  the retained real leaf isolates that failure in nine seconds and now accepts
  the explicit native-root policy with unchanged snapshot words; changed roots
  reject. Actual row11/row15 wire-closure tests and legacy policy checks pass.
  [Failure, repair and phase evidence](evidence/2026-09-08-native-root-routing/real-claim-repair-v1.json)
  retains the exact input and shows that these are not wrapper proof acceptance.
- `test-ethereum-air-preflight` passed against real context 2/3 after
  all focused gates passed from source manifest
  `cafe4e94959879fd3b8d4afcd48804842885d69bce06188748251e05f2f5d417`.
  Its one real test checks direct roots, adapter parameters and padding for 34
  components; request 1,599.38 seconds, peak 31,978,725,256 bytes. Provider rows
  and exact lookup closure are not covered by this diagnostic. The same frozen
  source's `test-ethereum-complete-proof` subsequently failed with signal 9; see
  the terminal checkpoint above. No real wrapper or parent proof is accepted.
  [AIR verdict, measured child dimensions and next execution](evidence/2026-09-08-native-root-routing/real-pair2-air-acceptance-v2.json).
  Two bounded live samples show repeated public-logup validation during statement
  row construction; the later sample reports a 28.4 GiB peak physical footprint.
  These are phase samples, not total-time attribution or a failed resource gate.
  [Live observation and samples](evidence/2026-09-08-native-root-routing/real-pair2-v2-live-observation.json).
- The native resumed-clock validator separately passes the original genuine
  proof/verification gate and rebased local proof/lease mutations (2/2). It now
  checks the authenticated executed span; CSP defaults and identities remain
  unchanged. Evidence is retained in `evidence/2026-09-08-native-v2-clock-boundary`.
- The isolated initial-input lane passes its genuine execution/mutation gate
  (3/3) and sealed-shape gate (2/2 including discovery). The authenticated packet
  bridge also passes its two focused lane/graph binding tests. Compact policy and
  active segment-0 wrapper integration remain pending; these checks alone do not
  establish large-input wrapper admission.
  The explicit initial job admission, compact claim/public-sums selections and
  initial lane/packet row owner are written with syntax checks; their semantic
  gates are queued. Producer and fresh-verifier replay each reopen the pinned
  initial admission and retain a private copy. The new initial manifest appends
  rows36/37 while preserving ordinary placements, and shares ordered claim/gate
  implementation with the existing manifest. Its new and legacy protocol tests
  remain pending; selected cohort assembly and a real initial proof are unfinished.
  [Initial manifest implementation checkpoint](evidence/2026-09-08-initial-manifest/checkpoint-v1.json).

## Delivery checkpoint: optimized block campaign launched

- The optimized real CPU segment-9 proof passed a separate-process five-case gate.
  The explicit schema5 whole-directory verifier also verified the retained genuine
  pair and rejected missing, duplicate, reordered, broken-memory-boundary and
  incorrect initial/terminal/cycle claims. Its frozen executable is
  `9cbd5efedf164eb232a721e0cefa6b420a32083890e47df989aaae587bafabd3`.
- The 121-segment CPU controller accepted segments 0 through 5 after separate-process
  verification in `cpu-field5-block-v1`. Segment 6 finished production and awaits
  independent verification. The controller stopped at a confirmed zero-child
  boundary to prioritize the faster Metal campaign; no proof process was killed.
  `controller-scheduling-stop-v1.json` retains the exact resume arguments and
  segment 6's successful execution receipt. PID 18484 is terminal. A stopped
  `flock` waiter must not remain suspended and potentially acquire the shared lock.
  Existing segment 9
  is retained for independent re-verification rather than duplicate proving.
  Segment 0's producer request took 1,557.73 seconds; the additional independent
  verifier took 90.88 seconds. Proof SHA256 is
  `d52e9577b23b79b16afc9da1c6c55b324d8872c3f447deab18e0b3a439a2d532`,
  41,293,029 bytes. Whole-block acceptance remains outstanding.
- Segment 1's complete producer request took 739.24 seconds; its independent
  verifier request took 66.77 seconds. Its proof is 45,392,055 bytes, SHA256
  `1b397d9acde09d4e35db11bd3923fd004e59571fe1c804321f1a36016f639666`.
  The first real adjacent pair's proof, metadata and successful verification pins
  are retained in `cpu-field5-block-first-pair-v1.json` at the campaign root for
  real-program wrapper admission. This receipt does not claim recursive acceptance.
- Segment 0 has 4,318,234 remaining Poseidon calls, versus segment 9's 478,450.
  Its retained LDE preflight is 24,512,287,728 bytes. The producer's reported
  lifetime peak is 34,836,719,344 bytes, matching the observer's sampled producer
  peak. These are distinct from the admission budget and from controller-plus-
  producer summed footprint. Receipt and 815 samples are retained in the campaign's
  `cpu-field5-block-v1/leaf0-observer-v1` directory.
- The optimized small wrapper passed the complete three-case lifecycle and
  five separate-process root checks with no native inputs. See
  [complete-proof evidence](evidence/2026-09-07-real-campaign-v1/fixed-program-wrapper-complete-v1.json)
  and [independent-root evidence](evidence/2026-09-07-real-campaign-v1/fixed-program-wrapper-root-independent-v1.json).
  This is not a real-program wrapper or a block root. Replacing bounded 64-row
  completion interpolation is the next real-wrapper admission blocker.
- The accepted optimized wrapper also passed the detached replay gate: input
  buffers destroyed, independently admitted capture shape, 193 queries, typed
  transcript AIR checks, actual wire-input mutation rejection and native OODS/q2
  composition parity. [Replay evidence](evidence/2026-09-07-real-campaign-v1/fixed-program-wrapper-detached-replay-v1.json)
  retains the failed direct-helper build and the successful existing-target run.
  No parent proof was produced; `fold_admitted=false` remains explicit.
- Fixed a fold replay integration mismatch: an explicitly admitted Ethereum fold
  used its own native session identifiers, but engine replay still reconstructed
  legacy identifiers. The actual engine selector now consumes the admitted fold
  key, preserves the legacy path when that admission is absent, and propagates
  invalid-key/cohort errors. The [seven-case namespace gate](evidence/2026-09-07-real-campaign-v1/fold-engine-namespace-v1.json)
  passes. This removes a two-child replay blocker; it does not establish a parent
  proof or activate fold admission.
- The controller now supports a dedicated Metal producer with explicit AOT pins,
  without a CPU-reference proof requirement. Its 16 custody/routing tests pass;
  [these are mocked controller checks](evidence/2026-09-07-real-campaign-v1/fixed-program-block-controller-v2.json),
  not a Metal production proof. The corrected matched Metal5 run published the
  exact CPU segment-9 proof bytes and passed separate-process verification
  (54.36-second request, 50.91-second inner verification, 956,974,256-byte peak).
  The corrected dedicated product also proved terminal segment120: 216.46-second
  complete producer request, 60.15-second proving phase and 12,430,042,208-byte
  peak, with 91 device dispatches and 3 reported host fallbacks. Its additional
  [separate-process verification](evidence/2026-09-07-real-campaign-v1/real-terminal-metal-field5-fresh-v1.json)
  passed in 102.77 seconds, including 99.33 seconds native verification, peak
  1,260,144,032 bytes. The 100,960,686-byte proof is retained.
  The [Metal campaign](evidence/2026-09-07-real-campaign-v1/metal-field5-campaign-v2.json)
  launched with corrected productv3 and all 11 controller imports frozen in
  `controller-source-v2`; segment0 passed production and separate-process
  verification, and segment1 is running. Segment0's proof matches CPU bytes;
  complete producer request459.65 seconds, proving282.44 seconds, lifetime
  peak38,800,103,144 bytes, additional independent verification90.80 seconds.
  [Actual receipts and phase measurements](evidence/2026-09-07-real-campaign-v1/real-metal-campaign-leaf0-v1.json)
  retain the scope and resource observations. Imported accepted9/120 retain
  original timing receipts and remain subject to controller re-verification.
  Whole-block verification and CSP promotion remain pending.
- Controller recovery now reuses a successful producer candidate after interruption
  or failed fresh verification. It checks campaign and proof identities before
  new production, then requires fresh verification before publishing acceptance.
  The [19-case controller gate](evidence/2026-09-07-real-campaign-v1/fixed-program-block-controller-v3.json)
  includes interruption before proof publication, repeated verifier failures and
  corrupt/mismatched candidate rejection. These are custody tests with mocked
  children. The stopped CPU invocation used the preceding source; its next resume
  must use the recovery change. The active Metal snapshot includes it.
- The dedicated terminal-120 trial exposed a small-circle Metal fallback bug
  before proving: owned arena adoption intentionally aliases source and coefficient
  buffers, but the fallback unconditionally used `@memcpy`. The retained failure
  is `metal-field5-segment120-production-v1` (169.65 seconds, 2,581,056,464-byte
  peak, no proof artifact). The bounded fix validates shapes, accepts exact alias
  and rejects partial overlap. Small-log polynomial parity tests, product rebuild
  and terminal production/fresh verification subsequently passed. Prepared launchv1
  remains superseded; active launchv2 pins the corrected binary. This was neither terminal AIR
  rejection nor a memory-budget failure. CPU segment 3 continued running; the
  attempted between-worker scheduling pause left it untouched when a worker was
  found.
- Full-program completion openings passed the actual nonfinal exact-closure
  gate: 36 components, 68,619,086 contributions, 412.67 seconds and
  29,179,975,328-byte peak. This predates the terminal selector edits and is not
  a wrapper proof. The next actual real-program gate uses independently verified
  pair1/2, both with zero public input/output words, retaining their real global
  positions and pinned materialization/ELF. Segment0 carries 675,173 input words:
  the current 32-tuple role-binding and 1,024-word claim defaults cannot admit it.
  The limits stay unchanged while a scalable, authenticated input-binding route
  is developed; segment0 remains mandatory for the block root.
- Native contexts2/3 and3/4 are retained in `real-program-wrapper-pair-2-3-v1`
  and `real-program-wrapper-pair-3-4-v1`, with source proof, original fresh receipt,
  metadata, materialization and ELF identities checked. They prepare wrappers2/3
  for the first real binary parent. The existing fold requires sibling alignment
  (`left.index == parent.index * 2`), so adjacent wrappers1/2 cannot form that
  parent. No wrapper or parent acceptance is implied by these retained inputs.
- The first real-program wrapper preflight passed full-ELF opening, native proof
  verification and global campaign admission, then failed at materialization:
  `VM_COMPOSITION_UNSAT output=43/44 node=615848`, `UnsatisfiedCircuit`.
  `/tmp/ethereum-real-program-wrapper-air-v2.log` retains the 636.40-second failed
  request (325.24 seconds campaign admission, 1,763,100,688-byte peak). The final
  composition equality on the actual native claims is the next wrapper blocker;
  no real wrapper or block root is accepted yet.
- A [matched native/recursive diagnostic](evidence/2026-09-08-real-wrapper-bridge/receipt.json)
  narrowed that failure to the six-constraint incremental bridge: all108 base and
  all14 Ethereum component cumulative values match exactly, and the composition
  sample equals the native final value. Only the bridge accumulation differs.
  The failed real input, full diagnostic log, comparison script and values are
  retained. Request322.23 seconds, peak1,763,117,096 bytes; no wrapper proof was
  produced. This is the specific next fix, not a broader component rewrite.
- The existing common-fold verifier now has explicit `--ethereum-v1` transport
  and publication through `writeEthereumBundle`, reusing its public-input layout.
  [Build and retained-proof checks](evidence/2026-09-07-real-campaign-v1/fold-verifier-command-v1.json)
  passed6/6 build steps, the transport test, and four separate-process cases:
  retained legacy proof acceptance, wrong pin, wrong transport namespace and a
  resealed Ethereum-key namespace applied to the legacy proof. This prepares
  independent parent verification; it does not establish an Ethereum parent.

## Open TODO: investigate native STARK verification latency

Execution order and completion criteria are maintained in the [unified goal](unified-goal.md).

- [ ] Investigate the real segment-9 independent verifier's **69.184 s request /
  69.109 s `verify_ns`**, one worker, 1.030 GB peak. The inner timer covers
  `FreshInputV4.coldOpen` (including native proof verification) and global metadata
  admission; it is **not an isolated STARK/PCS timer**. File reads, retained
  materialization admission and initial proof-identity checks precede that timer.
  Retain the current [actual Metal proof verification receipt](evidence/2026-09-07-real-campaign-v1/real-selected-metal-fresh-v1-receipt.json)
  as the regression input. First separate decoding/authentication, fixed circuit
  and Tree0 preparation, repeated validation, transcript/composition checks,
  Merkle openings and FRI verification, recording phase time, work counts and
  allocations. Check whether the cause overlaps the slow CSP verification
  reported during [precompile autoresearch](../2026-08-29-metal-ecdsa-subsecond/note.md);
  do not assume a shared cause. Compare cold admission with reuse of an
  independently authenticated immutable verifier profile, preserving fresh
  process verification and every proof check. Keep the complete-request timing
  visible; rerun the retained hostile inputs and CSP preservation gates for any
  shared verifier changes.

## Phase 1 repairs

- Gave the benchmark resource report one owner in prover measurement; CPU,
  Metal and aggregate adapters reuse that module. Report fields and sampling
  behavior are unchanged.
- Restored legacy completion encoding: a segment-only unretired fetch cannot
  be serialized under the ordinary CSP artifact schema.
- Bounded controller CAS cache-hit reads by the authenticated object's length,
  instead of requesting a 128 GiB allocation for every object. Existing length,
  immutable-file and digest checks remain enforced.
- Restored direct oracle dependency closure for the artifact-store package.
- Reconciled package API/dependency ledgers with actual exports; experimental
  Ethereum and recursive exports remain explicitly experimental.
- Removed five redundant root CLI forwarding files. Their existing tool-owned
  entrypoints now own the executable roots and appear in the build catalog.
- Replaced the Metal CLI's duplicated registry serializer with the existing
  CPU/Metal shared registry. The duplicate incorrectly emitted registry schema 2,
  so the normal CSP admission parser rejected it before proving.

## Verified checks

- CPU ReleaseFast CLI and trace dumper compile.
- Metal ReleaseFast CLI compiles with an authenticated, locally generated core AOT bundle.
- Prover measurement: 8 Zig tests passed.
- Adapter wire-arena filtered ReleaseSafe suite passed, including segment-only
  completion rejection and allocation cleanup.
- Controller control-plane/campaign tests: 24 passed.
- Package-release and direct-oracle command tests: 13 passed.
- Revm observer's relocated standalone semantic tests: 3 passed.
- Package workspace: 23 packages, 23 public modules, 76 dependency edges pass.
- CLI admission tests: 9 passed. `git diff --check` passed.
- Complete build configure closure passed: 21 catalog scopes, aggregate CPU
  and aggregate Metal install/registry/linkage exercises, and negative scope checks.
  The aggregate adapter now receives the same owned prover module as the focused products.

## Local artifact custody

Development host: Apple M4 Max, 14 CPUs, 36 GiB; Zig 0.15.2; full Xcode/Metal
compiler available. Artifacts live under `.git/local-ethereum/`, outside the
versioned source inventory and outside temporary-directory cleanup.

The existing CSP snapshot helper created clean source snapshots and retained
receipts binding them to the active dirty tree; no clean-provenance override
was used and no active branch commit was made.

- `baseline-source`: `e965bd9930a9cdb96edef17b8515d8f4dc162613`.
- `baseline-source-v2`: `8ecfd1dba5b43adaf6e79a4a50b00b70703227d0`;
  source digest `70242c002322f26385fd85dd70048394eb1747e3b269e7cef72294f71c256bf2`.
  Includes the shared Metal registry fix. CPU, trace and Metal rebuilds passed.
- `aot-m4`: authenticated core AOT bundle generated on this machine.
- `upstream/mainnet_24628607_66_7_zec_reth.bin`: 2,718,960 bytes,
  SHA-256 `e1c6d4e06a87649da68e461a91465e4123b990f531e68581ee1750599ff12376`.
- `upstream/zec-reth.elf`: 5,556,232 bytes,
  SHA-256 `213206cfde4b3e27114406c10ab529bd6a15579443d2f134c3c51d9554b96494`.
  Both were retrieved from zisk-eth-client commit
  `0887d43621931faba8cdf8da70402091bbe620ff`, at the manifest's exact paths.

The first clean CPU SHA-256/128 smoke executed, proved and independently
verified. Its single measured sample reported 1.080 s proving, 0.126 s
verification, 816.9 KiB proof and 1.26 GiB RSS. This is a functionality
observation, not a speed claim: the harness observed Battery Power and marked
it non-publishable. Other host activity was present. The repeated
CPU/Metal A/B regression gate has not passed yet.

## Outstanding

The complete CPU integration test graph still exposes the unfinished ContextV2
publication-provider migration. The old provider fixes 21 detailed claims;
the new context authenticates physical lookup geometry and instance custody.
An unsafe cast or a count-only projection is not an acceptable repair.

Source conformance initially reported 89 file-size violations, five misplaced
CLI roots and six H-009/H-010 production-authority references. The follow-up checker confirms the five root CLI placement failures are gone.
The remaining 89 size and six authority failures require actual ownership
and source decomposition work, not relaxed ceilings or allowlists. Formal
source-binding/coverage gates and full native-oracle validation remain pending.

The RV32 guest overlay, canonical projected input and historical execution
artifacts have not yet been recovered. Recover or reproducibly rebuild those
before advancing the real Ethereum proof. Commitment security, global clocks,
portable scheduling, complete provider joins and sound recursion remain open.
No CSP protocol identity, worker policy or RV32 execution semantics has been
changed by these repairs.

## Complete CSP diagnostic matrix

Both CPU and Metal completed all 16 canonical cases, one warm-up plus one sample
per case, with the existing sanitized 16-worker policy and secure PCS settings.
Every output matched, every proof freshly verified, every negative fixture was
rejected, and every case retained peak-memory evidence. All 16 CPU/Metal pairs
have **byte-identical proof hashes**, statement hashes, public-value hashes,
guest hashes and input hashes. Recursion and precompiles remained disabled.

Retained full reports:
[CPU](evidence/cpu-v2-full16.json), [Metal](evidence/metal-v2-full16.json),
[per-case parity and memory](evidence/cpu-metal-parity.json), and
[source snapshot receipt](evidence/source-snapshot.json).
These reports are both `power-condition-non-publishable`; they establish
functionality/parity and diagnostic memory observations, not a performance
non-regression claim or a Zisk comparison.

The diagnostic ECDSA case used 8.54 GiB peak on CPU and 4.71 GiB on Metal.
The smaller cases used 1.26–1.85 GiB on CPU and 1.64–1.93 GiB on Metal.
These are process-lifetime physical-footprint peaks including self-verification,
not estimates of complete Ethereum leaves.

The authenticated Zisk input was also replayed through the existing framing
validator: both length-prefixed bincode payload hashes and alignment passed.
The pinned stateless-validator source is now checked out locally at its exact
manifest commit, but its Stwo overlay is still missing.

Additional developer checks: 35 build/CI contract tests and 21 CSP snapshot/A/B
contract tests passed. Temporary snapshot-test repositories now disable signing
locally, so a user's global GPG setting cannot break their test loop.

## ContextV2 provider and laptop development loop

The publication provider now consumes authenticated ContextV2 directly. Source
format 3 and authority format 2 bind its dynamic geometry and reject earlier
receipts. The 21-claim fixture remains supported; the retained segment geometry
has 88 claims, 407 logical provider rows and a 512-row trace. The typed AIR
semantic identity remains unchanged. The integration owner, manifest builder,
component adapter and cold audit rebuild now carry that geometry explicitly.
These are synthetic geometry/custody tests, not a real Ethereum proof.

Public authority, public wire, verified receipt and native-public-sums identities
must match between capture and context. Borrowed claims are immutable during
materialization and are rechecked before writes. Workspace allocation failures
release every allocation. Aliased staging, output, source and verification
buffers are rejected before reconstruction can overwrite evidence. Hot prepare
still allocates zero times; cold trace verification owns a temporary rebuild slab.

Removed the leaf adapter's duplicate legacy claim projection and opcode/infra
switches: ContextV2 already authenticates the selected physical claim projection.
The integration outer cohort compiles in ReleaseSafe. The direct native leaf
preparation target still fails at its old composition constructor accepting
Context rather than ContextV2. Do not cast or project it to the old physical
layout. The next repair must use the selected-lookup V2 composition sources and
verifier-derived inputs, including exact base-versus-full capture geometry.

The serial build wrapper defaults to one job and a scheduler budget of two-thirds
of physical RAM, capped at 24 GiB (8 GiB fallback). Both settings propagate to
focused child builds. Zig's maxrss is a scheduler budget for declared step
estimates, not an OS memory cap; it does not change proof-worker policy. Runtime
arguments after `--` are preserved. Wrapper and actual nested-build tests pass
(4 tests), including low-memory host budgets, invalid options and child flags.

The non-core audit test facade had silently failed to import its two test
shards. It now imports them explicitly. Focused provider and audit targets have
filters plus test-count floors (10 and 5). ReleaseSafe passes all 15 tests;
provider compile reported 11 seconds / 855 MiB MaxRSS, audit compile 25 seconds /
about 1 GiB. These are one-run development observations. Four ContextV2 tests,
344 profile tests (one skip), and 312 manifest tests (one skip) also pass.

Evidence: [receipt](evidence/context-provider-progress.json),
[provider/audit tests](evidence/provider-custody-tests.log),
[context/profile tests](evidence/context-profile-tests.log),
[build-wrapper tests](evidence/laptop-build-tests.log), and
[outer-cohort compile](evidence/outer-cohort-compile.log).
The earlier broad non-core target's single import test is superseded by the
five-test focused result; it was not evidence that the audit cases had run.

The CSP reports above remain the earlier retained snapshot's diagnostic baseline.
No later source revision has passed the repeated performance A/B promotion gate.
No CSP protocol, worker policy or RV32 execution path was widened or changed by
this ContextV2 provider work. All six engineering phases remain active; complete
leaf/block proofs, secure Ethereum commitments/clocks, guest recovery and sound
recursive child verification still require work.

## Base VM composition handoff (follow-up)

The direct SegmentV2 leaf preparation target now compiles in ReleaseSafe.
A separate ContextV2 preparation entry reuses the selected physical lookup
compiler and the existing base AIR recorder. It reconstructs the statement,
revalidates the physical profile, checks exact commitment logs and OODS masks,
and obtains every dynamic graph input from the authenticated native capture.
It rejects an extended Ethereum capture rather than silently truncating it to a
base profile. The full Ethereum compiler remains a separate route.

The first real native fixture was proved, postcard-decoded and natively verified;
its new composition replay then passed after correcting full-degree versus
split-domain composition reconstruction. Its later transcript assertion was
stale: the physical lookup activation adds 15 permutations (3 for the header,
4 for each of three digest frames), giving 900 transcript and 1,208 complete
provider calls for that fixture. These pins were updated from their legacy
values. The complete handoff/mutation rerun is still pending below.

A rejected fresh circuit exposed double cleanup of its graph and evaluation
storage. The shared constructor now keeps exactly one error-cleanup owner for
each allocation. An allocation-failure sweep and an unsatisfied-circuit test
pass with the testing allocator. The native fixture also now moves capture
ownership only after successful leaf construction, preventing a failure leak.

[The focused profile suite](evidence/base-v2-profile-tests.log) passes all 14
intended tests, including the existing Ethereum compiler and field-authority
checks, capture geometry rejection, and cleanup failure injection. Its test
runtime was 5 seconds and reported 77 MiB MaxRSS. Cold ReleaseSafe compilation
still took 6 minutes and roughly 6 GiB; filtering reduced the inventory but did
not make that optimized compiler loop fast. The superseded broad compile was
explicitly terminated before completion and is not a passing test receipt.
[The direct leaf compile](evidence/base-v2-leaf-compile.log) also passes.

This is a real small native-segment ingress test, not the Ethereum block or a
recursive STARK proof. Ethereum guest recovery, secure commitments/global clocks,
full core-plus-provider fresh-process proof measurements, the block bundle and
actual child-proof recursion remain open. CSP runtime defaults remain untouched;
the earlier CSP diagnostic snapshot is still not a post-change A/B promotion.

The complete native handoff rerun now passes:
[evidence](evidence/base-v2-native-ingress.log). It exercises native proving,
postcard decoding/native verification, ContextV2 composition preparation,
core/non-core source regeneration and the existing mutation fleet. Fixture:
one executed cycle, 24,255 proof bytes, 900 transcript calls, 14 authority
calls, 294 core calls, 1,208 complete provider calls. The executable reports
4,457 ms native proving and 902 ms verification; total run 7 seconds / about
1 GiB MaxRSS, cold compile 1 minute / about 6 GiB. These are single-run test
observations using the fixture's **one-query, zero-PoW test PCS**, not
production-security timings or evidence of Ethereum-block performance.

The same 14-test inventory also passes in Debug: 10-second cold compile / about
1 GiB, 55-second test runtime / 81 MiB. This is the measured default development
loop for this laptop; ReleaseSafe remains the optimized correctness check.
[Debug evidence](evidence/base-v2-debug-loop.log). The next phase-one priority
is durable reconstruction of the missing Ethereum guest and canonical input,
then the secure Ethereum commitment/global-clock/resource profile; these native
handoff repairs do not replace those requirements.

## Recovered canonical input and rebuilt full-block guest

The pinned Zisk fixture now has a retained host converter in
`autoresearch/benchmarks/guest_runtime/projection`. It uses Alloy 2.0 and the
pinned upstream stateless SSZ types, checks both framed records, recovers and
compares all 66 transaction public keys, and roundtrips the canonical input.
The resulting canonical and runner input hashes exactly match the historical
manifest. `host_validation` freshly executes that input and reproduces the
pinned successful 43-byte output. Both tools retain Cargo locks and run with
one compiler job; warm compile/revalidation is below one second per tool on
this host, an observed development-loop result, not proving latency.

The original codec decodes BPO1 at 1765290071 and BPO2 at 1767747671. The
manifest and comparison validator previously mislabeled the latter as BPO1;
that metadata and its documentation are corrected without changing any input
or expected output bytes. The comparison/corpus/matrix/protocol suite passes
41 tests. One Rust parser check covers framing truncation, padding, overflow
and changed fixture rejection.

A new independent guest crate in `guest_runtime/ethereum` builds the unmodified
stateless-validator source at a134a621, installs the native Alloy signer
provider directly, and reuses the retained exact-layout allocator and word
Keccak wrapper. Revm and supplied-key verification keep software semantics.
The target emits RV32IM and supplies four single-thread LLVM atomic libcalls;
their direct arithmetic/CAS test passes. The guest's crate does not modify
CSP guests or their protocol configuration. See its README for the locked,
one-job build.

The new ELF is 3412588 bytes with SHA-256
`f3657d077b88da313369ff002aafbe8b6bf4912e8fd1ef1d1b76a6dc0f1d40a7`.
It is a new artifact, not the missing old ELF. The bounded admission run
retained one 65536-cycle segment (intentional partial exit 75). The complete
run then finished through the existing controller and freshly validated its
journal: **61 segments, 253646998 cycles, 253614097 core rows, 32835 native
Keccak calls, 66 native signer-recovery calls**, no stderr, and the exact
expected output hash. The retained trace dumper comes from clean snapshot
8ecfd1dba5b43adaf6e79a4a50b00b70703227d0, not the later dirty tree.

These receipts establish execution, not proof. The V4 capture explicitly
reports `segment_statement_v2_admissible=false`. No historical guest product
or final comparison activation is promoted. The 2^24 global-clock cap, scalar
memory/program roots, secure leaf handoff and portable resource profile remain
next. The lower cycle count alone does not justify attributing a speedup to a
particular optimization or comparing proving time against Zisk.

Durable inputs live in `.git/local-ethereum/projected-input-recheck`, the ELF
and source receipt in `rebuilt-guest-v1`, and the execution in
`rebuilt-guest-full-block`. Evidence copies, tool/source hashes, Cargo-lock
identities, tests and the complete journal are in `evidence/input-recovery-progress.json`
and `evidence/rebuilt-guest-progress.json` with their referenced sibling logs.

## Secure-profile investigation after the rebuilt execution

The new 253646998-cycle execution still exceeds V2's 2^24 global cap. It would
fit below M31 after multiplying its cycle counter by four, but that does not
authorize widening the shared V2 limit or solve larger corpus blocks. The
existing leaf-local V3 authority explicitly remains native statement custody;
its 64-bit global span still requires AIR binding.

The existing Poseidon2 AIR already supports atomic input/output tuples of all
16 lanes through `poseidon2_io`. Its 445-column permutation and typed provider
can therefore be reused for a stronger commitment construction; the current
narrow Merkle path consumes only output lane zero. The existing recursion
sponge has 8 M31 capacity lanes and an 8-lane digest, so its generic collision
ceiling is about 124 bits. It cannot silently become a 128-bit commitment.
A 128-bit commitment design using this width would need at least nine M31
capacity lanes and nine digest lanes, with rate seven and a second squeeze
permutation to obtain the final two digest lanes. Reading capacity lanes as
extra digest output is not the standard sponge construction. This is design
investigation, not an activated or security-reviewed profile.

Primary references checked: Poseidon2 paper https://eprint.iacr.org/2023/323.pdf
(capacity bound); Plonky3 `poseidon2/src/round_numbers.rs` (31-bit, width-16,
degree-five, eight full/fourteen partial round selection); and the newer
cryptanalysis https://eprint.iacr.org/2026/306. The latter improves attack
bounds without asserting that its discussed parameters fall below their
claimed levels. Specific parameter and complete proof-system soundness budgets
still need evaluation; a hash-width change alone establishes neither.

## Ethereum binary-node caller AIR foundation

`air/memory_commitment/ethereum_node_v1.zig` now implements a separate node
sponge with rate seven, capacity nine, nine digest lanes, explicit memory vs
program domains, schema/height binding, ordered children and padding. It uses
three absorption permutations and a fourth squeeze permutation. The existing
Poseidon AIR's full atomic-I/O mode can authenticate those four tuples. Its
79 caller equations bind every input state and every retained digest word;
kind and height bits are constrained. Tree position and depth semantics remain
the future tree component's responsibility.

The focused `test-ethereum-commitment-v1` target passes 2/2 tests in Debug
and ReleaseSafe: native witness, caller equations over M31 and QM31, full
permutation AIR equations, and changed digest/input/domain/height/child-order
rejection. Debug compile was about one second / 332 MiB; ReleaseSafe about
four seconds / 383 MiB; both test runs under one second. Final compile-time
shape assertions were followed by another passing Debug run.

This module is not exported into the active proof path. Its full provider
LogUp connection, Merkle tree, leaf encoding, statement roots, codecs and
continuation binding are still outstanding. It is neither a commitment proof
nor a complete 128-bit security claim. No scalar CSP construction was changed.
The package inventory names the two new tests and its floor increases by two.
Source conformance remains at the same 89 size and six authority violations.

## Joint Ethereum node/provider proof and bounded development commands

The node caller now has the full four-request atomic-I/O LogUp connection and
a real PCS component. Its physical shape is 161 main columns, eight interaction
columns and 82 constraints. The component reuses existing sampling, polynomial
extension ownership, quotient and accumulation helpers. It is exported only
through the testing/development surface; the CSP execution path is unchanged.

The new `run-ethereum-node-proof-v1` commands in the CPU and Metal integration
packages prove two callers plus all eight full Poseidon permutations. They
serialize four LogUp claims and the actual proof, destroy the producer's
witness/pool/scheme/in-memory proof owners, and freshly verify from bytes. The
verifier reconstructs canonical activity/first-row preprocessing and redraws
the transcript. This is a fresh verifier in the same process, not yet a
fresh-process worker protocol. Both backends produce exactly 24798 bytes with
SHA-256 `bb5d6da5cbce1a85bebe70341370e3e8f791a684b700256135a4c5c2cc6eff69`.

The checks reject a forged second squeeze/digest through provider-bus closure,
a nonboolean height with balanced provider claims through the actual prover
AIR check, changed claims, and corrupted proof bytes. The expected corrupted
proof produces a labeled Merkle-error log line. An initial joint-proof failure
found a coset-to-circle placement omission in the new harness. It now uses the
existing `BitReversalTable`; the unit interaction test uses three distinct
active rows so constant cumulative padding cannot mask that mistake.

All four focused tests pass in Debug and ReleaseSafe. The lean CPU executable
passes in both modes; Metal passes with the recovered authenticated AOT bundle.
The final ReleaseSafe Metal exercise reports 40 device dispatches and zero
reported CPU fallbacks, including the deliberate negative cases. ReleaseSafe
compile work was 19 seconds CPU / 24 seconds Metal, about 1 GiB peak each;
the complete diagnostic exercises used 4 MiB / 35 MiB reported peak RSS.
Single-run production-plus-encoding times were 3.30 ms CPU / 12.42 ms Metal and
fresh verification 0.73 ms / 1.05 ms. These are tiny diagnostic measurements:
PCS uses zero PoW bits and three queries, allocators differ, and this is not a
repeated performance comparison or an Ethereum leaf measurement.

The oversized CPU proof-build file now delegates the existing Ethereum leaf
and provider commands to `build_ethereum_leaf_steps.zig`, keeping command names,
test filters and guards intact. Its size falls from 1127 to 666 lines. The
source-conformance debt falls from 95 to 94 findings (88 size, six authority).
Broader script validation found and fixed stale 22-package/73-edge CI graph
pins and redundant artifact-store lane selection. The actual 23-package,
76-edge graph is pinned, with an explicit artifact-store consumer-closure
check. All 102 selected script tests and all 21 configure scopes pass.

The node proof does not yet authenticate a Merkle topology, a public root, or
an Ethereum statement. Production commitment/security admission, the V3 clock
join, full leaf proving and worker/root recursion remain open. Current-source
CSP performance promotion also remains open; the retained full16 reports are
still the earlier diagnostic snapshot, not a later repeated A/B pass. Detailed
receipts and commands are in `evidence/ethereum-node-proof-v1-progress.json`
and its sibling logs.

## Public Merkle path proof and verification in a separate process

The Ethereum development proof now covers a 30-level binary path and all 120
Poseidon permutations. Verifier-reconstructed selectors bind the public index,
memory/program domain and height at every row. All nine leaf and root lanes
and every adjacent path link are constrained. This supersedes the earlier
two-node development fixture without changing CSP defaults or worker policy.

CPU and Metal produced identical 31,000-byte proofs with SHA-256
`10bdc30e0dcd2bf6aec985d51fbac3758db6b591170c33be9c533d6a1b7274a3`.
A completed Metal process saved the artifact; a later CPU process read only its
bytes and independently verified it. The Metal producer reported 22 dispatches
and zero fallbacks. Both Debug and ReleaseSafe focused targets passed 5/5 tests.
AIR checks reject a broken path link and a changed ninth root lane even with
balanced permutation claims. The harness also rejects altered claims and proof
bytes. Separate `produce PATH` and `verify PATH` commands are documented in the
frontend README.

This is digest membership under diagnostic PCS (zero PoW, three FRI queries),
not a secure Ethereum leaf proof. VM leaf encoding, execution linkage, complete
commitment-profile security and global-clock binding remain open. CPU/Metal
single-run timings are development diagnostics, not performance claims.
Evidence: [path receipt](evidence/ethereum-path-proof-v1-progress.json).

## Paired CSP preservation rerun

Clean source snapshot `39b798168af607c0da2e108d94b96a4d7fba8126` rebuilt all
three products (CPU, Metal, trace diagnostic), using serial compilation with
reported peaks of 3-4 GiB. Compared with restored baseline
`8ecfd1dba5b43adaf6e79a4a50b00b70703227d0`, both CPU and Metal completed
all 16 cases in two alternating-order rounds: 128 launches, one warm-up and
five measured samples each, 640 measured samples total. Secure PCS, 16-worker
policy, native execution and Metal dispatch admission remained unchanged.
Every proof, statement, guest, input and output identity matched across arms
and backends. Raw public-values JSON includes each source commit, so those
hashes match within each arm, not across different commits.

Across the 32 backend/case comparisons, per-case cohort-median proving changes
ranged from -1.73% to +1.47% and peak-memory changes from -0.67% to +0.34%.
No case increased by more than 5% in both paired rounds. This threshold is a
diagnostic investigation trigger, not a statistical non-regression certificate.
Power/host interference was captured and promotion remains false. The existing
normative A/B gate has not been weakened.

The note-local `csp_paired_rerun.py` reuses the canonical workload, alternating
schedule, production harness and statistical helpers. Its runnable check rejects
changed worker/PCS/native policy, invalid verification custody and Metal decline.
Raw reports and host samples remain under `.git/local-ethereum/csp-path-paired-v2/`.
[Per-case report](evidence/csp-path-paired-report.json),
[receipt](evidence/csp-path-preservation-progress.json),
[source snapshot](evidence/csp-path-source-snapshot.json).

## Program-image word proof on CPU and Metal

The nine-lane Ethereum path now has a word-addressed tree builder and actual
ELF consumer. Four little-endian bytes are injected into the digest without
field reduction; absent words mean zero. Memory/program domains and all tree
heights remain separated. Construction compacts one sorted frontier in place
and retains only the selected path, rather than a full tree witness. RV32
execution and CSP types remain unchanged.

Both backends proved word `0x02000197` at byte address `0x400` in the rebuilt
Ethereum guest (ELF SHA-256 `f3657d077b88da313369ff002aafbe8b6bf4912e8fd1ef1d1b76a6dc0f1d40a7`).
Their 31,045-byte artifacts have identical SHA-256
`9a80f89311b432b570dc70af6df1582fd5071cd4044839dee16329b2e4a906d5`.
After the Metal producer exited, a separate CPU process independently reloaded
the ELF, recomputed the declared-program root and verified the proof. It rejected
a different requested address and a separate ELF with one changed program byte.

Single-run request observations, including file IO and complete program-tree
preparation: CPU 2.051 seconds / 53 MiB reported peak RSS; Metal 2.072 seconds /
83 MiB; separate CPU verification 2.047 seconds / 53 MiB. Runtime initialization
is outside the internal timer. Metal reported 22 dispatches and no fallbacks.
These are diagnostic membership proofs with zero PoW and three FRI queries, not
Ethereum execution proofs, security-admitted timings or a Zisk comparison.

The new file decoder now reuses the existing allocation-free Postcard preflight.
A hostile commitment count fails before the first allocation. The universal
provider never consumed its extra activity selector; removing that unused column
keeps strict preflight intact and reduces the synthetic path artifact from
31,000 to 30,692 bytes. The development transcript revision is now 2; earlier
receipts retain the earlier geometry and hashes. Both CPU and Metal complete the
positive/adversarial exercise. Focused tests pass 6/6 in Debug and ReleaseSafe.
Source conformance remains at the pre-existing 94 failures, with no new waiver.

[Program-word receipt and logs](evidence/ethereum-program-word-proof-progress.json).
These follow-up source changes are confined to Ethereum diagnostics and their
test inventory; the CSP production code measured in snapshot `39b798168af607c0da2e108d94b96a4d7fba8126`
was not changed afterward. Next, bind the nine-lane commitment to VM memory and
program lookup/continuation semantics under a separate Ethereum profile. The
existing scalar roots and eight-lane recursive statements cannot be silently
reinterpreted as this root. Global-clock joining, a real complete execution leaf,
the full-block bundle and child-verifying succinct recursion remain unfinished.

## Recursive child transcript recording and Debug stack repair

The common-fold investigation located a concrete missing AIR link: rows 0--17
are inactive, while a native suffix boundary supplies challenges, statement
words and verifier control. Its provider schedule currently requires zero
transcript calls. This prevents interpreting the existing q193 common-fold
transaction as an independently verifiable recursive root.

The secure verifier now uses one replay implementation with either the native
or recording channel. The new `recordVerifiedReplayWithCohort` entry point
records exact protocol operations without changing transcript bytes. A
cold-opened canonical-empty q193 proof generated 174 operations, 176 frames,
1,649 Poseidon permutations and all 193 query words. Native and recorded
claims, relations, terminal digest and draw count match. The existing row-1 AIR
witness conversion checks every 32-lane provider request and each within-frame
state-tuple link. The Ethereum role-0 writer now shares that conversion.

Debug exposed stack exhaustion in the canonical-empty component constructor.
Its large logical component roster now has one heap owner instead of stack
copies. The same complete proof test passes on the normal 8176 KiB stack,
including allocator leak checking: Debug compile 14s/2 GiB and test about
1 minute/80 MiB; final ReleaseSafe test 6s/69 MiB. The final ReleaseSafe run
passed all 32 selected checks (31 Ethereum role-0 structural checks and the
q193 cold-reopen/recording gate). These are development test measurements,
not Ethereum block performance. CSP protocol/default/worker policy is untouched.

This completes the recording-to-row witness bridge, not the transcript AIR
closure or child-verifying recursion. The next work is a verifier-owned
common-fold transcript program, activation of the existing transcript rows and
provider calls, and replacement of native boundary compensation by constrained
relation producers. Real Ethereum leaf ingress and a root verifier without
child witnesses remain required. Reference paths and the exact gap are in
[recursion-verifier-gap.md](recursion-verifier-gap.md); measurements and hashes
are in [the receipt](evidence/recursive-secure-transcript-progress.json).

## Value-independent recursive transcript program

The secure recording path now owns a protocol-derived transcript program for
canonical-empty and common-fold children. Operation order, frame sizes, mandatory
padding, relation/FRI/query draws and both PoW sites are derived from the manifest
and admitted capture geometry, independently of the recording's values. The
native engine shares the program's context tags and checks each recording
against that program before returning it. This program is not a serializable
child-admission capability or proof of AIR closure.

The canonical-empty test now proves two different public statements, destroys
each producer and cold-opens both artifacts. The session and claim-vector SHA
values change, while the program's identity and operations remain identical.
Altered geometry and altered payload metadata are rejected. ReleaseSafe passes
in 9 seconds / 86 MiB reported RSS and Debug in about 2 minutes / 108 MiB on the
normal stack. The existing canonical artifact SHA remains
`23da5f591218aab54cf8f04f646e045195349d9b1674e641c5b80f702419f468`.

The first common-fold run successfully compared 188 operations, 190 frames,
1,681 permutations and all 193 query words. Adding that replay inside the old
test changed its expected cache counters and failed the cache lifecycle check.
The recording exercise now has its own focused target,
`test-recursive-common-fold-transcript-program-v1`, sharing the same real proof
and cold-open setup. The original branch retains its exact cache assertions and
eight-round reuse benchmark. The standalone focused run passes 1/1 in 14 minutes / 10G reported peak RSS;
its compile took about one minute / 4G. The original branch's compile check also passes (one minute / 4G); its
eight-round benchmark has not been rerun. The isolated transcript test does not
replace that benchmark or its original cache lifecycle assertions.

Three short runtime samples observed native preprocessing reconstruction and
interaction/audit reconstruction; the largest reported physical-footprint peak
was 13.1G. They are diagnostic snapshots, not a complete timing profile. The
native replay constructs an audit and then calls a validator that reconstructs
interactions again; avoiding redundant preparation is a candidate for further
review, not an optimization applied in this change.

Session identity and claim-vector seals remain dynamic SHA payloads requiring
binding constraints. Next work remains activation of transcript AIR rows and
provider calls, constrained payload/statement/continuation relations, and a root
verifier that needs no child witnesses. Ethereum profile, full leaf/block proofs
and CSP promotion remain open. No CSP protocol/default/worker policy changed.
Source conformance still reports 94 errors; no waiver was added.

[Program progress receipt](evidence/recursive-secure-transcript-program-progress.json).

## Transcript AIR rows and retained canonical-child handoff

The program-derived witness now covers universal rows 0--4 and 6--9, including
both PoW sites, relation challenges and verifier randomness. Tests execute the
actual typed AIR constraints and close every internal lookup tuple. Native
oracles remain explicitly limited to payload inputs, permutation-provider calls
and semantic challenge consumers. Altered initial state, payload, randomness,
PoW words and jointly weakened PoW check/frame witnesses fail. Different valid
canonical children produce identical preprocessing. The common-fold proof and
cold-open transcript exercise passed 1/1 in 14 minutes / 10G peak RSS, checking
188 operations, 190 frames, 1,681 permutations and 193 queries. That run preceded
the subsequent retained-child handoff changes below.

The canonical cold owner now retains the exact recorded replay used for its
claims, query authority and composition graph. It uses the already prepared
cohort instead of constructing a second cohort for replay. Existing ingress and
worker handoffs carry the recording by reference; the owning proof releases it.
The process-local token pins program/recording identities and exact allocations.
The row constructor still validates all recording contents before reading them.
This witness is not a durable admission capability.

The proof test destroys the producer, cold-opens its bytes, prepares both lanes
from the retained recording, and checks unchanged native replay/graph counters.
A different child's recording and replacement recording allocations are rejected.
ReleaseSafe passed in 10 seconds / 87 MiB and Debug in about 2 minutes / 108 MiB
on the normal stack. Both retain the canonical proof SHA
`23da5f591218aab54cf8f04f646e045195349d9b1674e641c5b80f702419f468`.

The new ownership fields initially exceeded the canonical module's source-line
ceiling. Identical query-log validation from that module and the role-neutral
child module now lives in the existing common wrapper authority. Callers retain
their original error mappings, and a malformed composition degree/path is
rejected. No source waiver was added; conformance is back to the same 94 errors.

The common-fold cohort still commits an inactive transcript prefix. Its source,
provider schedule, parameters/log sizes and claim closure must consume the new
rows together. Dynamic session/claim SHA payloads, row-5 semantic binding,
field-public continuation and a root verifier without child witnesses remain
open. Common-fold child retention must reuse its fused verification/replay path;
it must not add another expensive interaction reconstruction. The original
common-fold eight-round reuse benchmark and latest-tree CSP promotion suite have
not been rerun. No CSP protocol/default/worker policy was changed.

Final ReleaseSafe validation passed 4/4 tests and the common-fold bootstrap
compile check after the shared query-geometry extraction. Debug ownership checks
preceded that extraction. See [the handoff receipt](evidence/recursive-transcript-child-handoff-progress.json)
for source hashes, validation scope and unfinished completion gates.

## Shared common-fold transcript recording and concrete backend checks

`recordColdReplayWithCohort` now reuses the generated interactions, claims and
audited closure from the exact cold-verified cohort. It redraws the challenges,
checks them against the retained relations and requires exact final replay
identity. The existing full reconstruction and validation entry points retain
their checks. The canonical equivalence/mutation gate passes in 10 seconds /
87 MiB; recording the shared transaction takes about 71 ms and adds no
preprocessed-cache lookup. These are development diagnostics, not block timings.

Both bootstrap and concrete common-fold backend cold owners retain transcript
recordings, pin their storage in process-local tokens, and release all owned
arrays. The backend's child ingress carries a dimension-independent transcript
view. The full isolated common-fold proof test passes in 12 minutes / 10G RSS:
producer destruction and fresh cold-open reproduce the program and recording
identities, all 193 queries and the actual typed transcript row checks. A changed
retained recording seal fails token validation. Preparing rows adds no owner
replay/graph work. This isolated proof still requires live children; it is not an
independently verifiable recursive root.

The child gate now compiles the actual backend proving, cold-open, full-audit and
handoff functions. That found two older errors hidden by structural-only tests:
registry pointers were addressed a second time, and the audit passed a pointer
to a byte slice. All affected common-fold projection callers now pass the
existing registry pointer, and the audit passes the slice. The final gate passes
3/3 in 590 ms / 1 MiB, with 45 seconds / 2G compilation. The original bootstrap
compile gate passes too; its eight-round runtime benchmark has not been rerun.
Production geometry/parity activation remains unavailable and unclaimed.

Source conformance remains at the same 94 failing files; the existing oversized
bootstrap and native-engine modules grew. No waiver was added. CSP defaults,
protocol and worker policy remain unchanged, but latest-source CSP promotion is
still unverified. Next: consume the retained recordings in the parent source,
commit transcript AIR rows/provider calls/claims together, and complete semantic
payload, statement and continuation binding. See [the shared-recording receipt](evidence/recursive-shared-transcript-progress.json).

## Parent-owned transcript rows and a focused source development gate

The common-fold fixed source now consumes both cold child transcript views and
owns their prepared logical AIR rows (0--4 and 6--9) and permutation calls.
Temporary raw rows are released after each child lane. Logical conversion is
shared with the existing constraint/lookup tests. Main and preprocessing writers
reuse the Ethereum wrapper's physical writer, preflight every destination and
protected buffer before writing, and reject an undersized late component before
touching earlier columns. Source custody pins the prepared row identity.

The focused `test-recursive-common-fold-transcript-source-v1` target constructs
real cold canonical children and the actual parent source without proving a
common fold. ReleaseSafe passes 1/1 in 14 seconds / 1G peak RSS, including both
lanes, nine physical components, 3,298 permutation calls, zero padding, alias and
undersized-destination rejection, changed-call rejection, and an injected late
allocation failure. Constructor cleanup now guards the uninitialized source and
has exactly one owner for the storage allocation. The first fault-injection run
counted later validation allocations as well; its unexpected-success leak was
in the test. The final test snapshots the constructor count immediately and
cleans up unexpected success before reporting failure.

The canonical proof/recording/row test passed in 11 seconds / 87M with unchanged
proof SHA, before the final helper extraction. Concrete backend compilation and
three child tests, and the original bootstrap compile gate, also passed before
the cleanup follow-up. The full common-fold proof/cold-open rerun is now live;
its handle and log are in the progress receipt. No full-proof result is claimed
until that process exits successfully. Source conformance still reports the
same 94 failing files; two existing oversized modules grew, with no waiver.

This is parent-source integration, not committed prefix activation. The provider
schedule still includes only the field-public boundary and verifier suffix. Next
connect prefix component parameters/log sizes, physical interactions and claims,
append the transcript calls to the same provider, and replace native semantic
boundaries with constrained payload/challenge/statement/continuation relations.
The independent root, Ethereum leaf/block proofs and latest-tree CSP promotion
remain unfinished. See [the parent-source receipt](evidence/recursive-transcript-parent-source-progress.json).

## Committed transcript prefix and exact suffix joins

The prior parent-source ownership snapshot completed its full common-fold proof,
producer destruction and fresh cold-open gate in 12 minutes / 10G peak RSS.
That receipt now records completion against its original source hashes; it does
not certify the committed-prefix changes described below.

The common-fold cohort now writes transcript components 0--4 and 6--9 into the
actual preprocessing, main and interaction trees, derives their component
parameters from the prepared rows, binds their claims and audits their domains.
Its schema is now 2. The source appends all transcript calls before the 116
field-public calls, and the shared bundle appends verifier-core calls. Nonempty
transcript layouts use schema 2; the old zero-transcript layout retains its
encoding. Bootstrap manifest construction now receives the complete bundle's
actual log sizes rather than estimating its provider size from the core alone.

The field-public audit consumes only its statement-authority range. The native
boundary now has four explicit domains: suffix control, verifier inputs,
statement words and transcript payload words. It no longer compensates relation
challenges or verifier randomness. Payload values still come from authenticated
native child custody; this is an explicit unfinished AIR binding, not a root
verifier independent of child witnesses.

The focused source gate checks the exact typed tuple producers from transcript
rows 8/9 against real composition, query, PCS and FRI consumers. All 2,396
contributions cancel, with zero unmatched challenge or randomness tuples. A
changed randomness output produces two unmatched tuples and is rejected. The
final source gate passes in 16 seconds / 1G RSS. Two field-public tests pass in
260 ms, checking unchanged statement-only compensation with an added transcript
prefix, a complete schedule, range-gap/schema-downgrade rejection, and rejection
of an empty verifier core. The concrete bootstrap/cohort compile gate also
passes. Initial compile errors from a tuple-valued test argument and stale
boundary-contract assertions are preserved in logs and superseded by passing
checks. The new four-domain boundary and schema are intentional common-fold
changes; CSP defaults, protocol identities and worker policy are untouched.

The first full proof with this active prefix is running. Its source hashes,
process handle and log are in [the committed-prefix receipt](evidence/recursive-transcript-committed-prefix-progress.json).
No successful committed-prefix proof is claimed yet. Source conformance still
reports 94 failing files, without a waiver. Remaining work includes row-5
semantic payload binding (including dynamic session/claim SHA seals), constrained
public statement/continuation, fixed verifier-key authority, and an independent
root over genuine Ethereum leaves. Ethereum profile/leaf/block and CSP promotion
gates remain open.

## Proof payload now joins the committed transcript

The nine-component committed-prefix full proof passed with producer destruction
and fresh cold reopening: 11 minutes and 9G peak RSS. Its earlier source hashes
remain in `evidence/recursive-transcript-committed-prefix-progress.json`.

The current extension activates row 5 using the existing typed AIR. It binds
commitments, physical claims 0--35, sampled values, FRI roots and final-layer
coefficients to the exact values absorbed by Fiat-Shamir. The existing shared
composition vector also has auxiliary claims; those are explicitly outside the
serialized physical-claim range and retain native custody. No unmatched sum is
used to manufacture a binding.

The focused source test passes in 16s / 1G RSS, with 59164 exact contributions
and zero unmatched proof-input, challenge or randomness tuples. Changing a
payload value or randomness output causes two unmatched tuples and rejection.
The original bootstrap's concrete cohort also compiles (6/6 build steps).
The full ten-component proof is running; its pending handle and source hashes
are in `evidence/recursive-transcript-payload-progress.json`.

Remaining native obligations include suffix control, auxiliary claim inputs,
statement words, dynamic SHA seals and public-hash callers. This milestone is
not a complete recursive verifier, Ethereum leaf, block bundle or CSP promotion.

## Payload proof verified; control binding under verification

The ten-component payload proof passed its complete bootstrap transaction,
producer destruction and fresh cold reopening in 11m / 9G peak RSS. Both
field-public tests also passed (7/7 build steps, 3/3 tests). The receipt
`evidence/recursive-transcript-payload-progress.json` retains the tested source
hashes; those precede the control extension below.

Current row 0 additionally emits composition, Merkle-opening and FRI control
steps from the authenticated verifier schedule. Native boundary schema 3
removes `recursion_step`, leaving three native domains. The source test now
checks these exact producers against rows 19, 23, 27 and 28 and alters a control
argument. Its build is running; no pass is claimed yet. The existing 94
conformance findings remain across 93 files, with no newly failing files.

The control source check now passes in 17s / 1G RSS: 70044 contributions close
and mutated control, payload and randomness inputs are each rejected. Concrete
cohort compilation also passes. The field-public negative test was still
mutating the removed control domain; after changing it to the remaining
statement domain, both tests pass in 649ms. The full proof with control binding
is building under handle 13802; only its source/compile checks are verified so far.

## Fixed metadata and boundary-index repair

The full control proof exposed a second, stale domain-to-ordinal table. That
table is removed: `domainIndex` now searches the authoritative `DOMAINS` list.
The existing field-public target also runs the boundary regression test,
including every domain index and rejection of the removed control domain.

Row 5 additionally fixes protocol/manifest headers, static manifest/registry
seals, the claim count and claim coordinates. Native replay and program
construction share the header definitions. These constants are derived from
configuration and manifest geometry, never recorded witness values. Dynamic
SHA seals and public statements still need constraints.

All 13 build steps and five tests pass. Source joins close 70044 contributions
and reject changed payload, randomness and control inputs (17s / 1G RSS).
The constant-payload direct constraint rejects mutation. The canonical proof
still hashes to `23da5f591218aab54cf8f04f646e045195349d9b1674e641c5b80f702419f468`
(11s / 87M RSS). Three field/boundary tests pass in 276ms, and the concrete
cohort compiles. The combined full proof is building, with source hashes in
`evidence/recursive-transcript-constant-progress.json`. Conformance remains
at 94 findings across 93 files with no newly failing files.

## Combined transcript/control/fixed-metadata proof verified

The combined full proof passed after the domain-index repair: 4/4 build steps,
1/1 test, 12m runtime and 10G peak RSS, including producer destruction and fresh
cold reopening. Its source hashes and log are retained in
`evidence/recursive-transcript-constant-progress.json`. This proves the current
bootstrap with the remaining native statement/SHA boundaries, not an independent
recursive root.

A separate `field_statement_word_v3` AIR is under development for canonical
recombination of transcript u16 limbs. It has not been installed in the frozen
universal roster or the common-fold proving profile. Its tests include field
modulus aliases and the modular-inverse-of-two byte-range trap.

### Common-fold statement AIR integration (2026-09-06)

The separate common-fold catalog now installs `field_statement_word_v3` at row 12. Both child transcripts produce 900 canonical words and 2,700 range requests; the existing row-35 provider commits their signed multiplicities and interaction claim. The native statement-word boundary has been removed, leaving auxiliary verifier inputs and dynamic payloads. Common manifest/cohort/boundary schemas advance independently; the frozen universal catalog is unchanged.

The initial integrated source/compile check passed 6/6 steps (source test 17s, 1G RSS). The final source/field/canonical check is pending after correcting the degree-four batched relation bound and adding range-storage alias protection. The full proof with this integration has not yet passed. Conformance remains 94 findings across 93 files with no newly failing file. See `evidence/recursive-field-statement-integrated-progress.json` for source hashes and pending handles.

Final integration checks passed 11/11 steps and 6/6 tests: source 17s/1G, field/profile isolation 267ms/2M, canonical proof 11s/87M. Full integrated proof launched separately; success is still pending.

The statement-bridge-only full proof terminated with `InvalidProofShape` in `engine.prove`. Inspection found the new degree-four evaluator requires coefficients that this profile deliberately releases after commitment. The subsequent profile removes the redundant row-mask factor (the verifier-owned statement mask already includes activation), returning the batched lookup to degree three without widening PCS defaults. The existing statement-fold circuit is also being connected through rows 10/11 and the shared arithmetic lane. These newer changes are under source/build verification, not yet full-proof verified.

### Statement fold and cubic bridge (2026-09-06)

The common fold now owns the existing pinned statement-semantics circuit, feeds its parent words through row 10 and all its inputs through row 11, and lends its authenticated graph/evaluation to the shared rows-30--32 arithmetic lowering. Row 12 emits each child body word twice to serve composition and continuation checks. The owned graph, evaluation, rows and source identities are validated and destroyed together. The statement bridge removes a redundant preprocessing mask factor, restoring degree three; its new semantic digest is `b2befb25386395106050de88684f519c637477304505732a4a25900121253ac6`. Coefficient retention and frozen CSP defaults are unchanged.

The source/field/concrete compilation gate passed 9/9 steps and 5/5 tests (source 17s/1G, field 602ms/2M). The exact statement join now closes 6,896 contributions across child and parent scopes. Full proof plus canonical compatibility are running under the handles recorded in `evidence/recursive-statement-fold-progress.json`. The prior degree-four snapshot failed; neither it nor this current snapshot is being reported as a verified independent root.

### Parent public hashes and published-output binding (2026-09-06)

The previous statement-fold snapshot passed its full proof and fresh cold verification after producer destruction: 12m, 9G peak RSS, 3,564 range requests. Canonical proof bytes remain `23da5f591218aab54cf8f04f646e045195349d9b1674e641c5b80f702419f468`. Its receipt retains that earlier source snapshot.

The newer profile now installs the existing VM public-claim hash AIR at rows 13--16 with separate phase parameters and disjoint sponge state-step ranges. Row 17 routes child digests and parent words into all four native-compatible hash preimages and digest comparisons. Parent statement words now come from that router, leaving row 10 inactive. The 116 hash requests are matched by the committed provider rather than a native compensation claim. A new public-output boundary can be derived from the published NodePublicV2 and verifier challenges alone, without child proofs or producer buffers.

Source/field/concrete compilation passed 9/9 steps and 5/5 tests (17s/1G source). The statement join closes 7,860 contributions; the hash-internal join closes 2,336 contributions, and a changed parent word is rejected. A separate 3/3-step, 4/4-test check verifies that the public-output boundary cancels exactly the AIR public emissions and rejects a mutated claim. Conformance remains 94 findings/93 files, with no new failing file. The full proof of this new profile is pending at `evidence/recursive-field-public-hash-progress.json`; independent root/Ethereum/CSP promotion claims remain false.

### Public-hash component setup correction

The full public-hash proof attempt failed at `prove.components` with `ParameterMismatch`. The reserved inactive statement-input row 10 was sent to parameter extraction despite having no rows. Component initialization now retains its zero parameters and rejects nonempty rows for that reserved component; active components retain strict extraction. The canonical-empty identity guard passed unchanged. A full proof rerun is pending in `evidence/recursive-field-public-hash-proof-2.log` (session 83413); no new proof success is claimed.

### Common-fold provider subclaims (verification pending)

Common-fold schema 6 now absorbs both audited Poseidon provider subclaims before the composition challenge. The transcript payload AIR emits claim coordinates 39 and 40; only common-fold child lanes remove the corresponding native verifier-input compensation. Canonical child transcript identities remain unchanged, and their legacy subclaims retain native custody. The full transcript gate checks the actual AIR tuple join against cold composition inputs and rejects equal-and-opposite changes that preserve the provider total. The source development gate now constructs all 36 components, catching parameter admission errors without a full STARK. Checks are queued in `evidence/recursive-provider-partial-check.log`; no new proof pass is claimed.

### Public-hash proof verified

The schema-5 public-hash profile with corrected inactive-row parameter admission passed the complete proof, producer-destruction and fresh-verification gate: 4/4 build steps, 1/1 test, 12m and 10G peak RSS (compile 1m, 4G). Its rerecorded transcript has 182 operations, 184 frames, 1,765 permutations and 193 queries. This resolves the earlier `ParameterMismatch`; it predates the schema-6 provider-subclaim binding now under test. Source provenance and scope are preserved in `evidence/recursive-field-public-hash-retry.json`.

The subclaim source/concrete-backend check passed: 6/6 steps, 1/1 test. The expanded source gate now takes 48s / 5G RSS (previous structural-only source gate: 17s / 1G); the additional cost constructs interactions and all 36 actual components but avoids the 12-minute STARK. Concrete backend compilation passes at 1m / 5G. The new full proof plus canonical identity guard is launched separately; the provider-subclaim tuple mutation check runs in that full-proof gate and remains pending.

### Statement inputs without graph literals (verification pending)

The canonical/common-fold composition capture schemas advance to 2. Their recorders no longer accept the session or add 412 equal-to-instance-literal statement constraints. Statement input slots remain in the graph ABI and in every row-18 schedule, including zero-use inputs; row 18 consumes each word from the committed transcript/statement bridge independently of arithmetic use count. A source regression mutates a composition-side statement input while retaining the transcript and requires `FieldStatementJoinMismatch`. Native boundary constants remain unchanged pending an explicit constrained replacement. The source/canonical/concrete-backend checks are queued in `evidence/recursive-statement-input-check.log`; no proof or performance improvement is claimed yet.

The provider-subclaim full gate failed in the new diagnostic path; its helper incorrectly passed a positive signed weight for an external consumer to `TupleLedger.append`. That helper is corrected and now has a small fixture in the existing field-public gate. The full proof gate remains unverified until rerun. Explicit fresh-verification and causal transcript/partial stage logs now distinguish future proof failures from post-verification diagnostic failures. The unchanged canonical proof guard passed (11s / 87M).

The statement-input source/canonical/backend checks pass: 10/10 build steps, 2/2 tests. All 824 statement input rows remain and have zero arithmetic uses; changing a composition-side word is rejected by the AIR lookup. Canonical proof SHA remains `23da5f591218aab54cf8f04f646e045195349d9b1674e641c5b80f702419f468`; the versioned composition capture identity changes. Source runtime/RSS remains 48s / 5G, so no measured memory improvement is claimed. The corrected provider-subclaim tuple helper passes its small check (4/4 field tests, 673ms / 3M; compile 9s / 733M), including equal-and-opposite subclaim tampering. The full proof for these combined changes is running separately in `evidence/recursive-statement-input-proof.log`.

### Combined statement and provider-subclaim proof passed

The capture-schema-2/common-fold-schema-6 proof passed all four steps and its complete test: 12m / 9G RSS, compile 1m / 5G. Logs explicitly confirm producer destruction, fresh verification and rejection of equal-and-opposite provider-subclaim tampering. The recording has 183 operations, 185 frames, 1,768 permutations and 193 queries. This resolves the earlier diagnostic sign error. Source hashes and scope are in `evidence/recursive-statement-input-proof-progress.json`.

### Claim values and canonical key binding under test

Common-fold schema 7 omits the redundant SHA claim receipt from the Fiat-Shamir transcript while directly absorbing every validated roster claim. The default manifest API retains its previous seal suffix; canonical and CSP paths keep that form. Session SHA remains because its key/provenance fields need explicit replacements. Separately, the canonical-empty preprocessing root is pinned from the frozen provider-only key in the existing payload AIR, with root inputs still emitted to the verifier lookup. The native canonical proof gate recomputes and checks this root; a changed capture root and changed AIR value must be rejected. Constants can now hold full M31 words as well as the existing split-u32 metadata. Checks are running in `evidence/recursive-claim-values-check.log`; this newer profile has no full proof pass yet.

The schema-7 checks pass after fixing an undersized provider log in the claim-format test setup. The field gate is 4/4 tests (275ms / 3M, compile 9s / 732M): all 36 individual claim mutations change the digest, invalid/missing claims fail before channel mutation, and appending the original SHA suffix exactly recovers the legacy transcript. The source gate passes (48s / 5G) and the concrete backend compiles. The canonical full proof remains byte-identical (11s / 87M); its preprocessing root is recomputed, wrong-key capture admission is rejected, and eight root words are fixed in the AIR while retaining their lookup uses. The full schema-7 proof is running in `evidence/recursive-claim-values-proof.log` (session 12805).

### Claim-value transcript and canonical-key full proof verified

Session 12805 completed successfully: 4/4 build steps, 1/1 test, 12m test time with 9G MaxRSS (compile 1m/5G). Producer destruction and fresh verification passed, all eight canonical preprocessing-root words are pinned in AIR, and a provider-subclaim mutation preserving the total was rejected. Common-fold schema 7 uses 182 operations, 184 frames and 1764 permutations for 193 queries. The exact tested source hashes remain in `evidence/recursive-claim-values-proof-progress.json`. This is a recursive bootstrap proof, not a full Ethereum block or standalone root.

Checkpoint/replay development is in progress: retain completed proofs in the existing CAS before test-only diagnostics, then run the same transcript AIR checks through a separate current cold verifier without another common-fold proving pass. Compilation session 34998 follows the completed proof under the existing serial build lock.

### Canonical child boundary join and durable replay development

Common-fold schema 8 uses the existing payload AIR to join the canonical wire boundary to composition claim input 41, and pins the canonical boundary header. The first source test caught a wrong VM-versus-recursion claim tag; corrected source verification passes with 70,060 joined contributions and zero unmatched inputs. Changing an actual boundary input produces two unmatched tuples and is rejected. Full 36-component admission passes. Source test: 48s/5G; canonical proof identity guard: 11s/87M, unchanged native proof and capture bytes. The native boundary semantic calculation remains required.

The separate checkpoint replay target compiled and rejected missing node, malformed node and missing store. The full schema-8 proof is launched with CAS retention enabled; exact source hashes and status are in `evidence/recursive-canonical-wire-checkpoint-proof-progress.json`. A successful saved-proof replay is still pending. Default full proving remains fresh; no CSP promotion or standalone root is claimed.

### Durable replay verified and retained-row hashing accelerated

The schema-8 full proof and separate-process retained-proof replay both passed. The replay initially spent 263.137s in its measured checks. Profiling identified per-word SHA update overhead while validating retained rows; a contiguous byte update preserves the exact digest on supported little-endian layouts, with the scalar fallback retained. The digest compatibility check covers 131 storage lengths, malformed backing words and changed-word rejection; the restored row-18 custody test also passes.

Replaying the same saved proof after the change passed all four build steps and its test, with checks at 162.568s (38.2% lower in this single before/after run), 6G peak RSS, and a separate 1m/5G compile. No content validation is skipped. This is a development replay measurement, not fresh proving or an Ethereum benchmark. Exact evidence is in `evidence/recursive-retained-digest-progress.json`. The fixed-wire AIR unit checks pass, but common-fold integration remains pending. Native child checks remain required; independent root, complete Ethereum leaf/block and current-tree CSP promotion remain unverified.

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

The schema-10 source gate passed: 4/4 steps, 1/1 test, 48s/5G (compile 1m/4G). All 70,108 semantic contributions close. A changed padding consumer produces two unmatched tuples; removing its AIR producer leaves one unmatched tuple. All 33,401 fixed rows and all 36 components validate; global closure passes. Full schema-10 proof remains pending.

### Common-fold empty native boundaries (schema 11 under test)

The local common-fold closure input now reuses the existing shared row/provider preflight and retains wire-anchor evidence as an internal audit. It no longer constructs the frozen global V2 two-boundary envelope. Every actual suffix contribution, including verifier-input terms, is added exactly once. Empty domain evidence requires zero tuple count, zero claim, zero observed row mask and a provenance digest. The frozen global/CSP boundary constructors are unchanged.

The focused gate passes 4/4 tests (292ms/3M; compile 10s/766M). It closes a fixture with genuinely empty suffix domains and rejects an unmatched verifier input, malformed row total and duplicate row; the original global constructor still rejects zero tuples. An initial fixture accidentally requested an empty leaf inside a 210-segment execution and failed `InteriorEmptySpan`; corrected to padding index 210. Source/full-proof verification remains pending in `evidence/recursive-empty-boundary-progress.json`. Native child custody, dynamic transcript seals, remaining boundary semantics and independent key admission still block a standalone root.

### Schema-10 claim-padding proof verified

Session 34223 passed 4/4 build steps and its full proof test, including producer destruction, fresh verification and retained node `4516699ccfb78a32ffd0e1fc422c446e7e12362e0c0a2edb1d350664a0bbd8bf`. Runtime/RSS: 8m/10G; compile 1m/4G. Recording: 182 operations, 184 frames, 1,762 permutations and 193 queries. Small empty-boundary field checks overlapped, so this is verification evidence rather than a performance comparison. The newer schema-11 empty-boundary source gate (63711) remains separate and pending. Native custody and independent-root gaps remain.

The schema-11 source gate passed: 4/4 steps, 1/1 test, 48s/5G (compile 1m/4G). All 36 components construct, 70,108 semantic contributions close, and existing input/control/randomness mutations remain rejected. Full proof is queued separately in `evidence/recursive-empty-boundary-proof.log`.

### Direct common-fold session key binding (schema 12 under test)

The common-fold session now explicitly absorbs three manifest-derived key IDs through a distinct field-session header. The program fixes their 48 split limbs in the existing constant-payload AIR; native session validation and the canonical/CSP encoding remain. All 24 key-word mutations change the transcript, a stale session is rejected before mixing, and the legacy encoding matches exactly. Field gate: 4/4 tests, 675ms/3M (compile 10s/787M). Source and replay compilation are queued; full AIR/proof verification remains pending. Preimage-by-preimage scope is recorded in `recursion-verifier-gap.md`; independent preprocessing-key admission and native boundary gaps remain.

### Schema-11 empty-boundary proof verified

Session 62385 passed 4/4 build steps and its full proof test, including producer destruction, fresh verification and retained node `d2be24c35bfb24717be449bb46e59f5c155925415f438ae0ed072cff329c8ac9`. Runtime/RSS: 8m/10G; compile 1m/5G. Recording: 182 operations, 184 frames, 1,762 permutations and 193 queries. Small session-key field compilation overlapped; no performance comparison is claimed. The newer schema-12 session-key source/replay gate remains separate. Independent-root and real Ethereum proof requirements remain incomplete.

The schema-12 source/replay compilation gate passed: 6/6 steps, 1/1 source test, 49s/5G (source and replay compilation each 1m/4G). The full proof and canonical identity guard are launched separately in `evidence/recursive-session-key-proof.log`; the actual 48-limb common-fold session-key AIR mutation check remains pending there.

### Schema-12 direct session-key proof verified

Session 37715 passed all 8 build steps and both tests: full bootstrap proof, producer destruction, fresh verification, 48-limb session-key AIR mutation rejection, and unchanged canonical identity guard. Retained checkpoint `bfa98d12c9b0b05739f813d2339ef96f5c45e29ecc1bef275a404bb9051faddb`. Fold runtime/RSS: 8m/10G; compile 1m/5G. Recording: 184 operations, 186 frames, 1770 permutations, 193 queries. This is the compiled schema-12 snapshot in `evidence/recursive-session-key-progress.json`, not the newer public-boundary work or an independent root.

### Public-output boundary recorded in arithmetic (schema 13 under test)

Composition capture schema 4 derives the 450-word public-output boundary in its arithmetic graph. The existing 412 statement slots are used directly, with 38 appended header/digest inputs bound through the unchanged word-routing AIR. No new AIR columns or components. Focused field check passed 4/4 tests (714ms/3M; compile 10s/795M), rejecting 453 individual word/challenge/claim mutations and a zero denominator. Shared ABI/recorder checks passed 372 tests with one skipped. The source check caught an inactive-row preprocessing count change; the legacy count was restored and the check is rerunning. Extended writer alias/shape tests and the complete proof are queued separately. Scope and source hashes are in `evidence/recursive-public-boundary-progress.json`. Remaining suffix sums are still native; no independent root, Ethereum proof, or CSP promotion is claimed.

The schema-13 source gate passed after restoring the inactive-row encoding: 4/4 steps, 1/1 test, 48s/5G (compile 1m/4G). All 36 components admit, 70,108 semantic contributions close, and existing changed-input/missing-producer mutations are rejected. The source gate still uses canonical children; the common-fold public-boundary graph and its 38 new input joins are checked by the separately queued full proof (74775).

The extended V3 writer check passed: 346 tests passed, one skipped, 923ms/16M (compile 2m/6G). The appended values preserve the entire legacy prefix; missing or aliased extra inputs reject before destination mutation. Full proof session 74775 acquired the serial lock; all recorded source hashes still match the current tree.

### Schema-13 public-boundary proof verified

Session 74775 passed all 8 build steps and both tests. The real cold composition capture binds all 450 public words, including the 38 appended inputs; the source join closes and changed public inputs fail the arithmetic graph. Producer destruction and fresh verification pass. Saved checkpoint `9aaa562a0cd212bb6b413cbb8d72cb9a40191ee312f5acdc14918485a0ed41c1`. Runtime/RSS: 8m/10G, compile 1m/5G. Recording: 184 operations, 186 frames, 1770 permutations, 193 queries. Canonical proof identity guard remains unchanged (11s/87M). A small canonical-boundary field check overlapped, so these are verification observations, not a speed comparison. Exact compiled-source provenance remains in `evidence/recursive-public-boundary-progress.json`; the newer canonical-boundary capture is a separate unverified integration.

### Canonical public-hash boundary constrained (schema 14 under test)

Canonical composition capture schema 3 now derives all four public hashes and the 113-call Poseidon IO boundary from published word inputs. It constrains empty-body tags/zero tail, height-zero coordinates, matching ordinal/index, the exact padding-index range, and every published hash digest. Both native boundary literals are removed. The new symbolic permutation uses the pinned AIR matrices and constants through the existing runtime owner; native scalar/SIMD hashing is unchanged. Both child kinds use the existing field-word AIR to route their 38 header/digest inputs.

The focused field check passed 4/4 tests (819ms/28M; compile 11s/818M), comparing all 113 permutations to native execution and rejecting 16 word/challenge/claim mutations plus a zero denominator. The recorded reference contains 232,753 arithmetic nodes. The canonical cold proof and complete parent source gate passed (8/8 steps, 2/2 tests; canonical 11s/95M, parent source 1m/5G). Independently verified canonical children at indices 211 and 212 have identical composition graph identities. All 36 components admit and global closure passes. Full parent proof 88365 is running separately; exact source provenance and the helper-ownership move caveat are in `evidence/recursive-canonical-boundary-progress.json`. Native SHA seals and independent key admission still prevent a standalone root.

### Schema-14 canonical boundary parent proof verified

Session 88365 completed successfully: 4/4 build steps, 1/1 test, producer destruction and fresh verification, retained checkpoint `5647cd56784964516e4720709d463b9c19d5c9cc39a55a2e82dc15d412595905`. Runtime/RSS: 10m/9G, compile 1m/5G. Public-word, key-limb and provider-partial mutation checks pass. This is the previously captured schema-14 snapshot, not the newer field-session or suffix-closure changes. Small checks overlapped; no performance comparison or independent-root claim.

### Closed child lookup boundaries (schema 15 under test)

Canonical field profile 2 absorbs manifest key IDs, claims and both provider partials directly through existing AIR payload rows. Common-fold removes diagnostic native boundary payloads, requires both suffix domains to have zero tuples and zero sum, and drops the native suffix-sum literal from composition capture schema 5. The record function no longer receives native replay evidence. Legacy transcript paths and CSP defaults remain. Source and canonical cold proof check 88714 is running; source hashes are in `evidence/recursive-closed-boundary-progress.json`. No nested-fold or independently keyed root verification is claimed.

The provider-classification fix closed all 70,140 semantic contributions, but strict admission still rejected a native payload boundary (direct diagnostic: CommonFoldAuditMismatch). The remaining payloads are the two four-limb PoW nonces per child. Row 12 now supplies them through its existing byte-range provider: two u32 halves per nonce, four additional rows per child, no new columns/components. Published statement rows retain M31 canonicality through their fixed output mask; nonce rows preserve all 64 bits. Field checks pass 4/4 (764ms/28M, compile 11s/857M), including u32 values 0, modulus, 0x80000000 and 0xffffffff and altered-limb rejection. Source/canonical integration is running separately in `evidence/recursive-nonce-source-check.log`. Full proof and independent-root requirements remain pending.

### Schema-15 child boundaries close in the source gate

Session 12793 passed all 8 build steps and both tests. The canonical cold proof passes (11s/95M), and the parent source check passes (1m/5G). All 36 components admit, both native suffix domains have zero tuples and zero claimed sum, and global closure verifies. The field-word join covers 900 canonical words and 16 nonce limbs (8,012 contributions); altered public input and existing missing-producer mutations still reject. The proof-input/control/randomness join closes 70,140 contributions. All source hashes match the recorded snapshot; conformance remains at 94 pre-existing findings. The full fold proof is running separately in `evidence/recursive-closed-boundary-proof.log`. This establishes lookup closure for canonical children; an actual folded child and an independently keyed root remain unverified.

### Verification with an explicit key (implementation under test)

The new common-fold verifier accepts only a public key (manifest, preprocessing root and component parameters), public node, 36 claims, two provider partials, interaction nonce and canonical proof bytes. It rebuilds pinned AIR definitions and invokes the existing core STARK verifier. Global lookup closure is computed from public output plus physical claims; no child cohort, native closure receipt, replay or session-custody seal enters its API. The canonical decoder is shared with the existing secure engine through a protocol-only helper.

The replay test snapshots setup data from an already verified cohort, destroys that temporary cohort, compares final transcript identity, and tests changed root/claim/provider partial rejection. Key admission is still caller-owned and not independently demonstrated by this test. Compile check 42894 is queued behind the separate schema-15 full proof 9562. Exact new-source hashes are recorded in `evidence/recursive-detached-verifier-progress.json`. No new verifier pass or standalone-root claim yet.

### Schema-15 full fold proof verified

Session 9562 passed 4/4 build steps and its full proof test, including producer destruction and fresh verification. Checkpoint `63240a089f9d6d8829c6a4b9481b952982af46b1a429059dccce7e444fd93f47`. Runtime/RSS: 10m/9G; compile 1m/5G. Recording: 178 operations, 180 frames, 1756 permutations and 193 queries. Key-limb, provider-partial and public-word mutation checks pass. Range requests are 3588, including the 24 new nonce byte-pair requests. This is the captured schema-15 snapshot; the explicit-key verifier was added after compilation and is not covered by this result. Its compile check 42894 acquired the serial lock after the proof finished.

### Saved proof verifies without a child-cohort argument

Replay session 55062 passed 4/4 steps and its test against checkpoint `63240a089f9d6d8829c6a4b9481b952982af46b1a429059dccce7e444fd93f47`. The explicit-key verifier completes in 330,749,500ns and matches the native verifier's final transcript. Changed preprocessing root, changed claim total and opposite provider-partial changes preserving the total are rejected. All compiled source hashes match. The complete replay harness takes 4m/6G; that RSS includes native cold-open, graph/custody tests and test-only key extraction, so it is not the detached verifier's memory figure.

This is verification of a real saved bootstrap fold proof with a caller-supplied key. The temporary setup cohort is destroyed before the new verify call, whose API accepts no child state; however, this test obtains its key from a previously verified cohort. Independent key admission, durable claim/key input transport and a fresh-process verifier remain outstanding, as do actual nested common-fold children and complete Ethereum proving. No CSP promotion or Zisk comparison is claimed.

### Durable verifier command (fresh-process check pending)

The installed `recursive-common-fold-verify-v2` command reads only an explicitly authenticated key JSON, public-input JSON and binary proof. The caller supplies the expected key SHA-256 separately. Both JSON formats require explicit format/schema versions and use bounded parsing; proof size and SHA-256 bind the separate binary. Build/test session 80827 passed 6/6 steps and its transport test (639ms/2M, compile 6s/581M); the 4MiB executable compiled in 43s/2G. Wrong key digest, stale/missing version and u64-max nonce round trip are covered.

Saved-proof export 65826 is running against checkpoint `63240a089f9d6d8829c6a4b9481b952982af46b1a429059dccce7e444fd93f47`. Its key is still extracted from verified bootstrap setup; the new hash parameter does not by itself establish independent circuit admission. Fresh-process verification and isolated memory measurements remain pending in `evidence/recursive-verifier-command-progress.json`. Conformance remains at 94 existing findings.

### Fresh-process verification with original-store access denied

Export session 65826 passed 4/4 steps and its saved-proof replay (4m/6G). It wrote `key.json`, `inputs.json` and the 2,886,425-byte proof under `.git/local-ethereum/detached-verifier-v2`; exported key SHA-256 is `d851a6465f6edb02cbeb8a3bc8173b40b86ad6642e07b791478e8b08975a9b37`. This identity comes from the verified bootstrap setup, not an independent circuit admission.

A separate installed verifier process ran with copies of only those three files in a temporary working directory. A macOS sandbox denied reads of the entire original `.git/local-ethereum` store; a failed `cat` probe confirmed the denial. Verification passed, and separate invocations rejected the wrong expected key hash, a stale schema and a changed proof byte. One measured process: 119,576,334ns verification, 121,977,667ns request handling including input cleanup, 0.792958792s total subprocess wall time, 17,776,640 bytes maximum RSS and 15,401,656 bytes peak memory footprint. This is a bootstrap-fold verification measurement, not an Ethereum proving or Zisk comparison. Exact stdout, `/usr/bin/time -l` output, executable SHA and scope are in `evidence/recursive-verifier-fresh-process.json`.

The new runner removes child artifacts from the verification process. Independent key admission remains: audit and freeze setup independently of a proof instance, compare setup across independent child statements, and require actual common-fold children and the Ethereum role before claiming the requested root. CSP promotion remains unverified.

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

### Actual common-fold siblings feed the nested parent source

Both sibling proofs completed: 1/106 (10m/10G) and 1/107 (11m/10G), each with producer destruction, fresh verification and detached capture checks. Their exported keys match the recorded bootstrap pin. The standalone detached composition test passed 3/3 steps and its test (1s/34M; compile 48s/2G). Native replay 37922 passed 4/4 steps and its test (4m/6G; compile 1m/5G), comparing transcript/program identities, relation challenges, query words, circuit/layout/bindings, every public input and every graph evaluation. These are recursion test fixtures, not Ethereum leaves.

The new `recursive_common_fold_detached_parent_v2.zig` uses opaque verified child owners, their actual six-layer/depth-22 captures and the shared composition recorder. It derives parent 2/53 from saved children 1/106 and 1/107, checks sibling order/continuation and pins the supplied child roots in transcript preprocessing. It reuses the existing fixed-wire owner, universal-36 cohort and secure kernel. No registry sentinel is minted. The bootstrap manifest policy was moved into the existing manifest owner with its historical identity domain unchanged; the fixed source now obtains a transcript view through its live policy.

Source check 68070 passed 3/3 steps and its test (30s/5G; compile 1m/4G): all 36 components are admitted, global closure passes and both native suffix boundaries have zero tuples and zero sums. Reversed and duplicate children reject. An initial compile caught a missing role projection and was corrected. This gate precedes the full-proof test addition and formatting; it is not evidence of a completed nested proof.

Full-proof session 83622 is running `test-recursive-common-fold-detached-parent-proof-v2` with one worker. It will export `.git/local-ethereum/recursion-nested-parent/53`, destroy producer and child owners, and verify only the retained key/node/claims/nonce/proof. Its result is pending in `evidence/recursive-detached-parent-progress.json`; the exact current source snapshot and build log are retained there. Parent setup is extracted from the verified cohort for this test, so independent production key admission remains outstanding. The Ethereum profile/leaf/block/root and current-tree CSP A/B promotion remain unfinished.

### Reproducible verification without original artifact access

`autoresearch/benchmarks/recursive_fold_verify_fresh.py` repeats the previously manual macOS check: copy only the key, public inputs and binary proof into a temporary directory; deny reads of the original store; verify the copied proof; reject an incorrect expected key digest; and mutate a proof byte while updating the transport digest, requiring rejection and no capture output. A real bootstrap run passed, with the changed proof failing PCS Merkle verification (`RootMismatch`). The report includes the executable/key digests, verifier receipt, authenticated shape, native process RSS and raw timing/rejection output. It remains benchmark diagnostics, outside the production `scripts/` boundary.

Run with the independently recorded expected key digest, never a digest accepted from an untrusted bundle:

```sh
python3 autoresearch/benchmarks/recursive_fold_verify_fresh.py \
  --binary src/integrations/riscv_cpu/zig-out/bin/recursive-common-fold-verify-v2 \
  --bundle .git/local-ethereum/detached-verifier-v2 \
  --expected-key-sha256 d851a6465f6edb02cbeb8a3bc8173b40b86ad6642e07b791478e8b08975a9b37 \
  --deny-store .git/local-ethereum \
  --out autoresearch/notes/2026-09-05-pr198-local-ethereum-plan/evidence/recursive-fresh-verifier-script-check.json
```

That check verifies the existing bootstrap fixture, not the still-running nested parent. Its timing is a single observation while another proof was running, not a performance comparison. The latest source-conformance check has 93 existing findings (previously 94); extracting the shared manifest policy removes the bootstrap owner's manual-source ceiling violation. Bootstrap setup recheck 76970 is queued behind nested proof 83622 to confirm the historical key pin after this refactor.

### Actual nested fold proof and isolated root verification passed

Session 83622 passed 3/3 build steps and its full test (4m/8G; compile 1m/4G). Parent 2/53 proves the two actual common-fold children 1/106 and 1/107. It exports a 2,899,529-byte proof, destroys both child owners and the parent producer/cohort/capture, then verifies solely from the retained key, public node, 36 physical claims, both provider subclaims, nonce and proof. The final transcript matches, and changing the parent output digest rejects. All frozen proof source hashes still match `evidence/recursive-detached-parent-progress.json`.

Measured intervals in this one-worker test: preparation 10,142,128,958ns; proving 113,439,612,208ns; native cold verification/reconstruction 75,230,811,875ns; complete test request through detached verification 289,347,905,125ns. The request loads already-proved children and includes extra replay/export/cleanup diagnostics. It is neither a complete Ethereum request nor an A/B optimization result.

Exported parent key SHA-256: `c9d86ae57770878eec3078e5f912822f3159717930d6aa224672d8b2455474ef`. A separate installed verifier process passed with only copied key/input/proof files and original-store reads denied. Verification took 128,788,167ns (request 132,100,416ns), maximum RSS 20,332,544 bytes. Wrong expected key and altered proof with updated transport hash reject; the altered proof fails `RootMismatch` and produces no shape. Exact evidence: `evidence/recursive-detached-parent-fresh-process.json`. The executable is the previously measured detached verifier with its SHA recorded, not a newly rebuilt binary.

The nested output retains the bootstrap's ten fixed-wire dimensions and tree column counts (q193, six FRI layers, depth 22); table layout and key differ. This is evidence for this nesting step, not a general fixed-point or multi-level campaign admission.

Bootstrap setup recheck 76970 passed 4/4 steps and its test (46s/6G; compile 1m/4G). Rebuilding setup from canonical children 212/213 still yields the pinned `d851a646...a9b37` key after the shared manifest-policy refactor. Independent admission of the new nested parent key remains open: it was extracted from the verified cohort. This root covers the padding test fixture, not Ethereum leaves. The Ethereum security/global-clock profile, complete CPU/Metal leaf and block, production root and CSP A/B gate remain unfinished.

The existing genuine Ethereum role-0 wrapper target compiles at the current tree (14250: 2/2 steps, 11s/2G). Its full two-segment fixture test is now running in session 28006 with one worker and the existing 8GiB declared host budget; log `evidence/recursive-ethereum-role0-current-proof.log`. This exercises actual core/precompile proof machinery on a small fixture, not the mainnet block. Its result is pending.

### Ethereum fixture exposed a diagnostic allocation ceiling

Baseline session 28006 terminated with signal 6 during role-0 materialization. It had already produced two native Stage101 proofs (79.4s) and cold-opened both (46.7s), with about 1.15GB measured lifetime peak footprint. The failure was `record-capacity-exceeded`: the diagnostic `TrackedSmpAllocatorV4` had exactly 4096 live records and 4,277,308 tracked bytes. The build summary's `1/1 tests passed` is not a successful test: the run failed and the wrapper proof did not execute. Full log and frozen baseline sources remain in `evidence/recursive-ethereum-role0-current-progress.json`.

The tracker now uses the standard unmanaged hash map, allocated through the backing SMP allocator. It retains exact pointer/size checks, serializes address reuse and accounting, reserves metadata before a remap can move memory, returns allocation failure on metadata OOM, and releases metadata when the last tracked allocation is freed. Failure reports show at most 16 allocations plus the omitted count. The owner shrinks from roughly 737 to 355 lines. No production allocator, CSP worker policy or protocol default changes.

The existing focused runtime check now keeps 8193 live allocations, checks exact byte totals after resizing all of them, releases every allocation, and then exercises its existing four-thread realloc/free workload. Focused session 94142 is queued; its result and the full fixture rerun are not yet verified.

Separately, the nested-parent test no longer asks for a second reconstruction of state already computed during cold verification. A sibling engine API returns the exact verified replay using `verifyBytesImpl`'s existing output; the old entry point still selects no retained replay. Full proof check 59791 is running and pins the previously verified parent key `c9d86ae5...5474ef`; it still destroys all producer/child state before the final detached verifier. This optimization is pending validation, not a claimed speedup. Baseline remains 289.3s through the complete diagnostic request. Source hashes and scope are in `evidence/recursive-detached-parent-shared-replay-progress.json`.

### Shared verifier replay passes with identical proof bytes

Session 59791 passed 3/3 steps and its full parent test (3m/9G; compile 1m/4G). The key, public-input JSON and binary proof are byte-identical to the earlier 2/53 output; proof SHA-256 remains `51c4bd779ea63901e986f1d31ece2862c29832c7d924296e6522fd977162ccf7`. The test still destroys every child/producer owner before final detached verification. The complete request measured 228,642,898,667ns versus the earlier 289,347,905,125ns, about 21% lower in this single observation. Proving itself was essentially unchanged at 112,996,035,333ns. Cold verification now includes retained-replay finalization, so its 98,013,846,875ns is not the same interval as the earlier 75.2s. Reported MaxRSS increased from 8G to 9G; these rounded single-run figures do not establish a memory improvement or a promotion benchmark. Exact source and evidence are in `evidence/recursive-detached-parent-shared-replay-progress.json`.

The allocator correction passed the existing field/public/materializer suite: 94142, 4/4 steps, 31/31 tests (597ms/3M; compile 29s/3G). That includes the 8193-live-allocation regression, exact shrink accounting, complete release and concurrent reallocation. All frozen allocator source hashes match. Conformance remains at 93 findings with no added finding categories. The full Ethereum role-0 fixture is rerunning in `evidence/recursive-role0-allocator-full-proof.log`; its proof result remains pending. Neither this small fixture nor the successful padding root completes the requested mainnet block benchmark or CSP promotion gate.

### Ethereum fixture advances past allocator capacity and exposes a circuit mismatch

Full fixture session 32395 is terminal: exit 1, 1/4 build steps, 0/1 tests. Both Stage101 proofs completed (79.36s), both cold opens completed (46.79s), and campaign preparation completed (1.49s). Materialization then returned `UnsatisfiedCircuit`; the former 4096-record allocation panic did not recur. Peak physical footprint reported before materialization was 1,154,680,152 bytes, not a complete-request memory measurement. The full wrapper remains unproved.

The genuine fixture now prints an available Zig error-return stack and its already-collected partial materialization metrics on failure. Session 8767 reruns the unchanged proof checks with these diagnostics; exact sources and pending result are recorded in `evidence/recursive-role0-materialization-trace-progress.json`. This identifies the failing phase before changing circuit semantics. No Ethereum success, CSP promotion or security admission is claimed.

The diagnostic run 8767 also failed (exit 1, 0/1 tests), now locating the failure in VM composition preparation: public witnesses, transcript replay and program compilation completed; composition preparation and FRI capture did not. The graph has 540,232 nodes and 44 outputs (43 transcript-claim aggregate joins plus the composition equality). No Zig error-return trace was available in this build; partial metrics supplied the phase evidence.

The shared fresh VM composition constructor now prints only the first unsatisfied output index/node/value on rejection, preserving the error and existing cleanup. Session 43491 reruns the same genuine fixture to locate that output. The fixture also optionally exports already cold-verified Stage101 artifacts under their SHA-256 filenames, so subsequent recursion debugging can retain the actual child proofs despite a downstream failure. This run selects `.git/local-ethereum/role0-genuine-stage101`; exports and final result remain pending in `evidence/recursive-role0-composition-output-progress.json`. No child-proof cache substitutes for proving in this full fixture.

### Shorter saved-child composition replay loop

A separate `test-ethereum-incremental-leaf-materialize-v4-replay` target requires `STWO_ROLE0_STAGE101_REPLAY_PATH` and `STWO_ROLE0_STAGE101_REPLAY_SHA256`, bounds the input size, checks its expected digest, cold-verifies leaf 0 and materializes/audits the actual VM composition. It never substitutes cached children into the full proving fixture. Its compile-only counterpart is queued in session 51860, behind full diagnostic fixture 21762. Both results are pending. The full fixture's source snapshot predates this new test/target; the replay snapshot is recorded separately in `evidence/recursive-role0-saved-composition-progress.json`.

The full diagnostic run required moving the optional artifact export into a typed helper after two compile errors in the direct test-body error-return expression (43491 and 29355). Current full run 21762 has compiled and is executing; exact evidence and retained earlier failures are in `evidence/recursive-role0-composition-output-progress.json`.

### Exact saved-child reproducer and split-domain correction

Full diagnostic session 21762 exported both native cold-verified Stage101 proofs and failed only output 43/44, node 540231, in the VM composition graph. All 43 transcript-claim aggregate joins pass. Exported first-child SHA-256 is `c86f6acde3d4ab6b148f5a02abe37fe0d7af7d1d96f0fffca26c42c2502538cf` (8,641,480 bytes); second-child SHA-256 is `45dc05384de0b1b55b765a8a3d80a90e3c631b940a533370dd6c8e8c27f93cbc` (8,955,531 bytes). Both on-disk hashes were checked independently. They remain small-fixture proofs, not mainnet leaves.

Saved-child replay compilation 51860 passed 2/2 steps (3m/5G). Replay 37235 independently cold-verified the pinned first child and reproduced the exact failed node/value; materialization failed at 582ms, with the cached test compile taking 52ms. That interval excludes child verification and is not an end-to-end proving benchmark. Conformance still has 93 errors, unchanged in count.

The concrete discrepancy is the quotient evaluation domain: native verification uses `composition_log_size - composition_log_split` (`src/core/verifier.zig:167`), while both Ethereum graph compilers passed the full composition bound. The V2 and incremental V4 callers now derive the split domain, and the shared extension recorder receives it explicitly for Keccak, tables and secp providers. The bridge uses the same domain as the base/providers. Composition reconstruction and native proof parameters retain the full degree bound. Correction replay 70201 is running; `evidence/recursive-role0-split-domain-progress.json` pins its source and input. No passing corrected replay or outer proof is claimed yet.

The split-domain-only replay 70201 remained a failure (0/1 tests): final output 43 is still nonzero, now node 540226. This corrects a native/recorded discrepancy but does not by itself establish an evaluated Ethereum composition. A second concrete mismatch was found in memory semantics: native `assembleIntoAuthenticatedLookupV2WithIncrementalBoundaryV3` selects `full_state_split_multiplicity_v3`, whereas the shared base recorder always selected legacy `memory_interaction.evaluateGeneric`.

The recorder now takes the existing native `MemoryBoundaryPolicy` at compile time and calls the corresponding production evaluator. Incremental V4 selects the split policy; Ethereum V2 and base VM preparation explicitly retain the legacy policy. No arithmetic implementation was duplicated. Replay 89489 tests both corrections against the same pinned genuine child; its result is pending in `evidence/recursive-role0-memory-policy-progress.json`. The saved-child hash rejection was also exercised using the baseline executable: a wrong expected digest rejects before cold verification/materialization (`recursive-role0-saved-digest-rejection.json`).


### Native policy consolidation and the next genuine capture failure

Both the native prover/verifier and Ethereum graph compilers now derive the
composition mask domain with `core.verifier_types.compositionMaskLogSize`.
Native and recorded memory constraints dispatch through the same
`MemoryBoundaryPolicy.evaluateGeneric` implementation. The domain check passed;
the first attempted integration test selection passed 31 tests but correctly
failed its count guard because a dependency module's memory test was not
collected. The test now runs through the frontend-owned focused root.

The consolidated saved-proof replay (90584) evaluated the actual VM composition
in 57ms, then rejected `SamplePointLayoutMismatch` during captured PCS setup.
Native Ethereum Keccak state uses `[0,-2,-1,1,2,27]`; signer-recovery main columns
use `[0,-1,1]`. The capture bridge previously admitted only singleton and two-point
masks. The native components now publish their existing offset arrays; recursive
layout classification and DEEP batching consume those exact arrays. Existing
enum tags, default memory policy and two-point periodicity remain unchanged.

`test-recursion-native-parity` passed 8/8 tests (session 75839): ReleaseSafe compile
7s/648M, run 270ms/2M. It covers pinned legacy profile/circuit identities, the
native memory-policy default, both Ethereum layouts against native `friAnswers`,
and rejection of point-order, point-value and every sampled-value mutation.
A first build attempt caught a duplicate target name; the existing protocol root
was preserved and extended with the new focused target. No duplicate target
remains. Saved-proof replay 46207 is compiling with Zig's time report; actual
Ethereum capture success remains pending. Sources and input identity are pinned
in `evidence/recursive-ethereum-mask-progress.json`. Practical commands are in
`autoresearch/benchmarks/ETHEREUM_BLOCK.md` under focused recursion regression.


### Actual saved Ethereum child capture now passes; compile cost measured

Replay 46207 completed 4/4 steps and 1/1 test successfully. The actual pinned
child cold-verifies and its VM composition and FRI/DEEP capture evaluate/audit.
The test took 28s/1G rounded peak RSS; materialization was 4,622,428,375ns,
including 3,997,109,291ns captured FRI/DEEP work. This is a capture replay, not a
recursive wrapper proof or mainnet leaf. The profiling web server was stopped
only after the successful build summary, so the wrapper process subsequently
returned exit 1 from SIGINT; that exit is not a test failure.

Zig's raw time report and decoded JSON are retained in evidence. Compile wall
time was 239,541,544,500ns, of which LLVM emission was 232,850,305,458ns. The
AArch64 assembly printer alone took 172.09s. A stripped ReleaseSafe build then
passed the identical saved-proof test (49845): compile 46s/2G versus 3m/5G,
run 28s/1G, materialization 4,750,831,417ns. This single comparison supports a
faster edit loop; it does not establish a runtime improvement or CSP promotion.
`-Dethereum-proof-strip=true` now opts into this mode for the saved replay and
genuine proof tests, retaining ReleaseSafe checks; debug symbols remain the
default when the option is omitted. The duplicate genuine compile/run module
and test definitions were removed: both targets now share one compile artifact.

The focused parity gate passed again with an 8-test floor (68449): cached compile
43ms, run 5ms. Conformance still reports 93 errors. Full genuine two-leaf wrapper
89370 now runs with the same fix and stripped ReleaseSafe build; its outcome is
pending in `evidence/recursive-role0-after-mask-fix-progress.json`.


### Full genuine fixture advances to wrapper graph construction

89370 finished with `OutputLimitExceeded` at `role0_prove`. Both native proofs
were regenerated and cold-verified with exactly the original bytes/hashes.
This run used the host-derived 14 workers, so its Stage101 wall time (64.05s)
is not an A/B comparison with the earlier one-worker fixture. Cold opens took
46.96s; the complete materialization phase took 6.03s with a cumulative process
peak footprint of 1,957,726,656 bytes. Its retained tracked allocations were
856,163,262 bytes, with no untracked allocations.

An independent graph-construction check found that the public-sum graph's
conservative `3 * input_count` reservation exceeded its default output limit
for 1,024/2,048 tuple capacities before graph emission. This was not yet a
confirmed explanation of the genuine wrapper failure. Allocation hints are now capped
at the existing limits; the builder still rejects actual graphs exceeding those
limits. A new graph-construction regression for 1,024/2,048 tuple capacities then
exposed an unused fifth radix multiplication overflowing `u64`. It now stops
updating the radix after the fourth limb, as the existing native sum authority
does. The first run panicked; after both fixes, 64869 passed 32/32 focused tests
(29s compile, 675ms/44M run), validating that both graphs fit the unchanged limits.

The genuine test now shares its entire wrapper transaction with a separate
`test-ethereum-incremental-leaf-wrapper-v4-replay` target. The latter reads both
pinned SHA-named inputs from `STWO_ROLE0_STAGE101_REPLAY_DIR`, checks each digest,
cold-verifies both, and prints that Stage101 proving is excluded. The full fixture
still regenerates its native proofs. Saved-pair run 58444 is pending with one
worker and stripped ReleaseSafe compilation; see
`evidence/recursive-role0-saved-wrapper-progress.json`.


### Default claim shape reproduces the wrapper output limit

Saved-pair 58444 still rejected `OutputLimitExceeded`. A diagnostic replay
73322 emitted no public-sum failure diagnostic, ruling that builder out as the
remaining error source. The wrapper constructs `ClaimReference` with the frozen
default shape (1,024 input words, 1,025 output words); prior semantics tests use
only two slots. A focused test of that exact default shape reproduced
`OutputLimitExceeded` (46223; direct binary log confirms the error name).

The claim graph now caps output storage at its existing node budget instead of
the generic 65,536-output limit. Generic arithmetic defaults, input/node limits,
claim shape, graph operations, public identities and worker policy are unchanged.
All byte/range constraints remain present. The default graph builds and validates,
and the test asserts that its outputs exceed the old cap under the same node
budget: 23578 passed 33/33 tests (30s compile, 433ms/64M run). The small native
parity target now also runs existing honest-claim and algebraic mutation checks;
13556 passed 10/10 (8s/656M compile, 280ms/4M run).

27120 reruns the actual pinned pair with this claim-graph bound. Success is not
yet claimed; source and scope are in `evidence/recursive-role0-claim-budget-progress.json`.


### Next binding mismatch is genuine V2 continuation I/O state

27120 now gets past the default claim graph's output bound, then fails with
`SemanticConstraintViolation`: output 86, node 11108, value
`1991068772/0/0/0`. This is the first entry-state `public_io_state` limb.
`vm_public_semantics_circuit_contract.constrainMachineBoundary` requires all
16 entry/exit I/O-state limbs to be zero for the legacy V1 claim. The retained
native SegmentV2 statement instead contains the fixture's authenticated
`role0-genuine-io-entry/shared/exit` digests. The source statement treats these
as continuation commitments; this failure is not evidence that they already
prove the complete application's I/O semantics.

The failing inputs remain unchanged. A legacy regression now independently
rejects nonzero entry and exit I/O-state limbs using the observed value. It
passes in the native-parity suite (88035, 10/10); this prevents a future V4 fix
from silently relaxing legacy semantics. The next integration task is to trace
and bind the SegmentV2 I/O-state policy through the actual statement/transcript
AIR, under an explicit V4 profile. Do not zero the fixture's digests, remove the
legacy guard, or replace the binding with a host-only assertion.

Final source conformance still reports 93 errors; formatting and
`git diff --check` pass. No complete Ethereum wrapper/root, secure mainnet block
proof, or current-tree CSP promotion is claimed. The active goal remains open.


## SegmentV2 continuation, real input regressions, and transcript consolidation — 2026-09-06

The V4 claim owner now selects `ClaimReference.initForSegmentV2`; the legacy
constructor still enforces zero continuation I/O. The SegmentV2 graph keeps
all statement-word consumers on row 15, with a distinct graph seal. Tests cover
all 16 boundary I/O limbs crossing the row-10/15 relation, plus every internal
I/O limb in both native folding and row-11 AIR. This authenticates continuation
commitments; it does not by itself establish application I/O semantics.

The transcript router also used statement item 2 while row 10 consumes item 0.
A failing 412-word regression exposed this; the router now uses the shared AIR
constant. The initial new wrapper replay passed the old output-86 failure and
stopped at output 13497, node 42044, value 939440486: the original fixture's input
edge was a label hash, not the canonical public-input projection hash.

The original native proof remains unchanged and now has a dedicated rejection
replay: its hash and exact observed digest difference are pinned, native cold
verification succeeds, and recursive claim semantics must reject it. That gate
passed in 24s / 260M rounded RSS after a 36s stripped ReleaseSafe compile.
The two- and three-leaf generators now use the existing native input/output
projection digest helpers with the fixture's default claim capacity.

Fresh canonical-I/O native children were proved and cold-verified before export:

- leaf 0: `fb15a6064ae68884f64ef138987b0f5053f18df708162b29336091e14db94e6b`, 8,637,263 bytes;
- leaf 1: `8759e365005142eaa6b4311271b18e07939da50ad351d313d5e76beff849e0d2`, 8,960,088 bytes.

They live in `.git/local-ethereum/role0-genuine-stage101-canonical-io`; the old
pair stays in `role0-genuine-stage101`. The full genuine run measured 79.421s
native build, 47.157s cold verification, and 6.054s materialization with worker
setting 1. It then failed at `EthereumIncrementalTranscriptGeometryMismatchV4`.
The attempted stop signal arrived after the test had already exited; this was
a real failure, not an interrupted result.

Two one-second `sample` traces caught repeated deep validation through geometry
and identity getters before proving. The first reported a 16.4G peak physical
footprint. Duplicate immediate owner/view validations have been removed only
where the following getter already runs those checks; the geometry getter path
still authenticates all retained owners. Rejection propagation is tested.
No whole-run speedup or lower peak-memory claim has been established yet.

The native core and focused replay now share `buildPlans`. The new transcript
replay reproduced the geometry failure without constructing the multi-GiB
wrapper. The actual recording has 25 relation draw operations containing 50
QM31 values, not 50 separate operations. Geometry, typed program classification,
and row construction now share the challenge count and retain both `(z, alpha)`
values from each native draw. A native-recording test covers all 25 rows and
rejects duplicate/missing challenges. The V4 post-tree1 profile also contains
76 separate mix operations; the router now retains this sequence and rejects
unexpected draws instead of requiring a single mix.

Current focused checks: 37 integration checks and 12 native/recursive parity
checks pass. The canonical-I/O transcript replay passes in 28s / 1G rounded RSS,
after a 46s stripped ReleaseSafe compile. Early transcript geometry/program
validation now runs before native wrapper-row allocation and is checked again
against the native owner's plans. The saved-pair wrapper rerun is tracked in
`evidence/recursive-role0-preflight-wrapper-replay.log` and the current checkpoint
`evidence/recursive-segment-v2-io-progress.json`.

CSP's latest-tree 16-case A/B gate remains outstanding; no promotion is claimed.
The mainnet materializer's execution-sized claim capacity still needs admission
by the V4 recursive profile. There is no independently verified Ethereum root,
secure mainnet leaf CPU/Metal benchmark, or equivalent Zisk final-proof comparison.


The first saved-pair preflight rerun failed at context 7 (interaction claims)
before large allocation. The router used the compatibility canonical claim
and its full backing array of log sizes, whereas the native transcript uses
`authenticated.canonicalInteractionClaim(...).view()` and active physical log
sizes. It also omitted the Ethereum extension's domain/count header. Those
routes now share the native projection and retain that header.

The follow-up `recursive-role0-native-claims-wrapper-replay.log` run (session
59671) has passed transcript preflight and is constructing rows 10--34. A saved
sample still reports 16.4G peak footprint and nested getter-triggered validation.
It is not a passing proof transaction yet. The next preparation cleanup should
batch fresh validated geometry/identity reads within a phase rather than
revalidate an entire ownership hierarchy for every getter. Final conformance
still reports 93 existing errors; `git diff --check` passes. No promotion.

### Geometry read consolidation — 2026-09-06

The canonical-I/O wrapper passed every transcript program preflight and reached the complete cohort constructor. A further one-second sample (`evidence/stwo-role0-before-geometry-batching.sample.txt`) again found repeated geometry/suffix/child validation, with 16.4 GiB peak physical footprint. This run was intentionally stopped after about 16 minutes of test execution; it is not a completed baseline or wrapper proof.

Suffix and universal geometry owners now expose one fully validated read-only metadata view per preparation phase. Their consumers reuse freshly validated identities for private identity hashing. The complete and secure cohort validators use those views and keep native finalization and complete-state checks. No snapshot is reused across native finalization. Hash field order and protocol identities are unchanged by construction; the pinned proof replay must verify the change. Current replay: session 27951, `evidence/recursive-role0-geometry-batching-wrapper-replay.log`. No speedup or proof success claimed while it runs.

The consolidated wrapper compiled successfully (binary `.zig-cache/o/67a3159854fbc1112c00d6fbba0f6f20/test`, PID 46796). The replay is still running; a post-change one-second sample remains in suffix geometry validation and reports the same 16.4G peak physical footprint. This is not a completed A/B. The 37-case integration gate is queued under the shared lock (session 55154, `evidence/recursive-geometry-batching-integration.log`). Scoped formatting and whitespace checks pass; source conformance has the exact same 93 errors as the preceding checkpoint.

### Closure baseline prepared during wrapper replay

The existing `row == 10 && !claim.isZero()` check was moved, without changing rejection behavior, into a private row-audit validator alongside row34/35 domain restrictions. A new focused test derives a claim from the authenticated shared statement-input AIR and requires it to be admitted as a component contribution; it also checks claim mutations and restricted provider domains. This baseline has not executed yet and is expected to expose the existing individual-zero check. The queued integration gate now contains 38 tests. Do not report it passing or remove the guard without inspecting the baseline. The running wrapper binary predates this behavior-preserving extraction.

### P0 priority: validation ownership and circuit/profile admission

User updated the active goal to the five P0 foundations in attachment `4ab28984-4721-46d4-8c89-cd586c1eddd0/pasted-text-1.txt`. The Ethereum end state and CSP preservation remain required. The geometry-batching wrapper failed naturally with `InvalidTraceRow`; the attempted SIGTERM arrived after exit. The queued integration baseline passed 37/38 and rejected an authenticated nonzero row10 claim. Removing that individual-zero condition gives 38/38 passing (33s compile, 815ms run, 64M rounded RSS), with negative checks for claim corruption, restricted provider domains, nonzero aggregate sum, and cross-domain cancellation.

Geometry now owns its transcript plans at stable addresses and constructs its transcript rows before the large native suffix. Insertion checks use the same typed AIR logical writers as the cohort, so malformed source metadata fails at admission. Resource cleanup is explicit per successful construction stage; no cached validated bit was added. Replay session 68534 is running (`evidence/recursive-role0-transcript-owned-preflight-retry.log`); the first compile exposed an error-set omission, repaired before this retry. Do not report the ownership change verified until its replay result is inspected.

### Shared recorded-frame admission verified

Early source admission identified the exact first failing payload row: recorded frame offset 8 versus legacy offset 16. The next replay passed all 157,446 active payload rows and exposed the first inactive recursion-lane row, which correctly retains the legacy layout. The V4 adapter now selects the checked writer from its authenticated lane; both insertion and cohort construction use that adapter. Fixed profile words normalize unused semantic input coordinates.

The common-fold route now uses the same checked recorded-frame writer instead of manually concatenating logical inputs. Its real source gate exposed the fixed tree0 commitment policy (constant value 954990678, item0, input multiplicity1); the shared recorded layout explicitly admits that policy while retaining default legacy restrictions. Logical row bytes are preserved for this common-fold path. Exact source metadata failures are retained in focused regression checks.

Validation: 39/39 V4 integration gates (34s compile, 808ms run, 64M); genuine common-fold transcript source/36-component closure 1/1 (1m compile, 1m run, rounded 5G runtime RSS); native recursion parity 12/12 (cached compile, 29ms run). Full Ethereum wrapper replay is running as session45275, `evidence/recursive-role0-shared-frame-wrapper-replay.log`. Failure paths now report total request usage after teardown, so failed preparation also has complete timing/peak-footprint evidence.

This is partial P0 progress: the materialized campaign remains borrowed, so scoped reads do not establish fully immutable campaign custody. Witness-independent Ethereum circuit/key admission, the complete wrapper, fresh independent root verification, and the current-tree CSP A/B gate remain unfinished.


### P0 retained campaign custody and failure-path ownership

The old shared-frame wrapper replay (45275/PID 47863) was intentionally stopped
with SIGTERM after preserving a sample showing 16.5G peak physical footprint
and campaign witness reconstruction nested beneath rows-10-34 validation.
The retained-membership replacement passes the genuine two-child custody gate
(1/1, 47s compile, 54s request), including index, witness, schedule and campaign
mutations and zero tracked allocations after cleanup. It also passes all 39
focused V4 integration tests (33s compile, 801ms run). Fixed/runtime campaign
membership now uses the same checks. No validation flag was introduced.

The full proof target explicitly rejects its former materialize-only setting;
the cached executable returned `ProofGateCannotStopAfterMaterialize` as required.
The separate custody target documents its smaller scope in ETHEREUM_BLOCK.md.

A new full wrapper replay is running in session 84735, PID 48193, binary
`f30f28077f81c21310e17f279a71dbc9/test`. Its sample still peaks at 16.5G; this is
not a measured full-request speed or memory improvement. Source changes after
its compilation remove full expected-schedule allocation by sharing the fixed
125-call suffix writer, and repair campaign-constructor rollback after Base
consumes its input. The genuine custody gate now injects failure at the last
allocation and requires the original input to remain valid. These newer edits
have only formatting/syntax checks so far; integration and custody gates are
queued under the serial lock. Exact source hashes are in
`evidence/recursive-segment-v2-io-progress.json`.

The materializer's former O(1) validation comment was corrected: source
validation still scans authenticated input. Campaign immutability and removal
of proof-dependent statement/boundary constants remain open. The current
classification and acceptance criteria are recorded in recursion-verifier-gap.md.


### P0 focused checks complete; large replay remains diagnostic

The bounded schedule/rollback source passes all 39 integration tests (33s
compile, 823ms run). The genuine saved-pair custody gate also passes (47s
compile, 64.717s measured gate interval, 1,960,626,624 bytes peak footprint).
It cold-verifies both pinned children, checks retained membership/mutations,
releases materialization, rebuilds it with an allocation counter, injects OOM
at allocation 18,377, and confirms that rollback restores the original valid
FreshInput with zero tracked allocations. The initial new test compile caught
a parameter shadowing the existing `input` helper; renaming it resolved that
compile error. Logs: `recursive-bounded-schedule-integration.log` and
`recursive-bounded-schedule-custody-retry.log`.

The full wrapper replay (84735/PID 48193) was intentionally terminated with
SIGTERM after roughly 11 minutes of preparation. The retained late sample
shows all 844 samples under rows-10-34 identity computation calling native
validation, then native identity computation/provider geometry calling full
core/graph validation. Peak physical footprint is still 16.5G. This run has
no completed proof result and predates the bounded-schedule/rollback changes.
Do not keep rerunning that large route unchanged: the next P0 step is the
ownership/validation boundary demonstrated by this sample, alongside admitted
profile inputs replacing proof-dependent constants. No heavy process remains
from these checks. The current CSP promotion gate is still outstanding.

Final source cleanup keeps optional artifact export with the existing genuine
runtime I/O policy, leaving the proof test responsible for proof/custody checks.
The final custody gate passes again (48s compile, 65.300s gate interval,
1,960,692,208 bytes peak footprint; rollback and empty allocator pass). Log:
`evidence/recursive-p0-custody-final.log`. Final source conformance reports 92
existing errors, one fewer than the preceding P0 checkpoint; it is not clean.
No new source ceiling violation remains. Formatting and whitespace checks pass.


### P0 immutable campaign ownership verified

Runtime campaign observations now live behind opaque private storage and expose
only const count/identity slices. Fixed-count audit receipts keep their explicit
mutable test surface. The materializer owns a separate campaign snapshot and
releases it during normal destruction or error rollback; it no longer borrows
the caller's campaign allocation. Existing identity preimages/hash algorithms
are retained. The worker's custody comparison uses the validated authority
identity, since equivalent owned snapshots intentionally have distinct addresses.

All 40 focused V4 tests pass (32s compile, 433ms run). The real saved-pair replay
also passes after destroying the caller campaign before revalidating materializer
membership; it additionally injects failure at allocation 18,381 and validates
the restored input and empty tracker. Runtime is 64.628s after a 46s compile;
the retained campaign costs 320 bytes and four allocations for this two-leaf
fixture. This is lifetime/custody evidence, not a full-wrapper performance gain.
The complete genuine Ethereum wrapper compiles (2m/5G); it was not rerun through
the already measured repeated graph-validation bottleneck.

The worker gate first exposed two remaining campaign field accesses, now migrated
to the immutable view. It then reached the missing `FixedPolicyV2.transcriptView`
interface in the pre-final common-fold adapter. This is not repaired by a stub:
`taggedTranscriptView` already explicitly lacks Ethereum support, and the shared
value-independent transcript program currently supports only canonical-empty and
common-fold field sessions. The Ethereum wrapper still uses its older session
and boundary protocol. Implementing its authenticated transcript and AIR input
bindings is part of P0 circuit/profile admission; the worker gate remains failed.
Exact outcomes and source hashes are in `evidence/recursive-segment-v2-io-progress.json`.

The raw-observation mint is private to the owned campaign module; its synthetic
entrypoint exists only in test executables. Runtime callers must cold-admit
actual inputs or clone an existing immutable owner. The final 40-case check
passes again (32s compile, 829ms run). This last change only restricts the
synthetic entrypoint; the full genuine body compiled before that restriction.
The worker gate remains failed at the authenticated transcript-view integration,
not hidden behind a compatibility stub. No heavy process remains running.


### P0 PCS graph ownership and native-core encapsulation

The captured PCS graph now uses a private `pcs_deep_circuit.Prepared` owner.
Its constructor builds and validates the graph internally and copies the caller's
profile arrays; it never accepts a mutable Circuit with potentially retained
aliases. Graph, profile and binding projections contain const slices. Explicit
full audits remain available. Mutable evaluations still replay every non-input
node and zero output, but no longer rehash this privately owned graph on each
`validateAgainst` call. The mutable Circuit API retains its original full checks.
This establishes graph integrity, not independent Ethereum circuit/key admission.

The 14-case native-parity gate passes (10s compile, 295ms run), covering pinned
legacy identities, caller-profile mutation, active native PCS answer parity,
changed evaluations and identities, and every construction allocation failure.
The real saved-pair custody/OOM replay also passes (46s compile, 63.308s gate
interval; materialization 4.906s). The materialized state retains 856,163,806
bytes in 58 allocations: 224 bytes and one allocation above the immutable
campaign checkpoint. Late allocation failure at index 18,382 restores a valid
input and leaves the allocator empty.

A bounded full-wrapper diagnostic compiled and ran for 182 seconds before an
intentional SIGTERM. The early sample shows native trace preparation; the next
sample shows repeated owner identity/geometry validation. PCS evaluation replay
replaces the former PCS graph hashing, while VM prepared graphs and provider
schedules are still repeatedly validated. Peak footprint is still 16.5G. The
wrapper has not completed proof generation or independent verification; its
termination is not a proof pass, regardless of the build tool's test-count line.

The Ethereum native owner also no longer exports `nativeCore`/`nativeCoreConst`
pointers, which exposed mutable inner slices even through a const pointer.
Consumers now request complete-state and generated-interaction validation from
the owner. The complete genuine wrapper compiles after this encapsulation
(2m/5G). Other borrowed preparation and component views still require audit;
this does not claim full immutable preparation. Source conformance remains at
92 existing errors. Common-fold source/closure and focused integration outcomes
are recorded separately in the machine-readable checkpoint.

Next: privately own the accepted evaluation buffers, then continue through the
remaining captured FRI/VM graphs and provider schedule ownership. Replace the
Ethereum statement/boundary constants with authenticated AIR input relations
and complete its actual child transcript integration. Complete wrapper proof,
serialization/fresh verification, and current-tree CSP CPU/Metal A/B remain
required. Do not repeat the large wrapper unchanged through the same validation
hierarchy.

Final checks for this change: common-fold transcript source and all 36 component
closure pass (1m compile/4G, 59s run/5G); all 40 focused Ethereum integration
checks pass (33s compile/3G, 796ms run/64M). `git diff --check` and focused format
checks pass. No heavy process remains running. These results do not establish
an Ethereum root, a wrapper end-to-end speedup, or current-tree CSP promotion.


### P0 immutable accepted PCS evaluations

Accepted PCS evaluations now have opaque private storage alongside the already
private graph owner. `Prepared.evaluateFrozen` computes and checks every graph
value before retaining the evaluation; no mutable evaluation or existing value
alias is accepted. Only const values and copied identity metadata escape.
Routine validation checks the immutable graph identity and shape. Explicit
`auditAgainst` still performs full graph/evaluation replay. Mutable evaluation
APIs retain their replay checks. Both paths share canonical base-field input
copying, including bounds and canonicality checks.

All 15 native-parity checks pass (10s compile/824M, 308ms run/5M), including
active native answer parity, invalid-witness rejection, caller-witness and
separate-mutable-evaluation changes, destruction of the original graph followed
by admission against a freshly constructed equivalent graph, rejection of a
different profile, and every immutable-evaluation allocation failure.

The genuine saved-pair custody/rollback gate passes (46s compile/2G, 62.807s gate
interval). Materialization is 4.804s. Retained state is 856,163,870 bytes in 59
allocations: 64 bytes and one allocation above the private-graph checkpoint.
Late failure at allocation 18,383 restores a valid input and leaves the allocator
empty. These timings are diagnostics, not a controlled end-to-end speedup.

The full wrapper compiled (1m/4G) and ran for 201 seconds before intentional
SIGTERM. Two samples show no PCS evaluation replay in the sampled validation
path. The remaining work is repeated VM graph/evaluation/schedule and provider
call validation; the late sample is in complete-cohort initialization. Peak
footprint remains 16.5G. No complete wrapper proof or independent verification
pass is claimed. Source conformance remains at 92 existing errors.

Next ownership consolidation: VM `Prepared` borrows graph arrays from a separate,
publicly mutable Ethereum composition program. Retain that program and its
preparation under one immutable authority before removing its nested checks.
`Prepared.validate` also currently calls `Circuit.validate` both directly and
through `validateEvaluation`, and `Circuit.validate` hashes its graph both
directly and through `reference`; consolidate those explicit checks without
weakening graph, binding, schedule, input or output validation. Provider inputs
and mutable provider finalization still need separate ownership. Ethereum
statement/boundary AIR bindings, child transcript integration, independent root
verification and current-tree CSP A/B remain unfinished.

Final shared-path checks pass: the genuine common-fold source verifies closure
across all 36 components (1m compile/4G, 1m run/5G); all 40 focused Ethereum
integration checks pass (32s compile/3G, 1s run/64M). Formatting and
`git diff --check` pass. No heavy test/build process remains running. Full
Ethereum wrapper proof, independent verification and CSP A/B are still pending.


## Boundary design takes precedence over wrapper optimization

User steering: repair the ownership/protocol boundaries before continuing the
broader Ethereum benchmark goal. The running wrapper diagnostic was stopped
with SIGTERM; its compiler succeeded (1m/4G), but it is not a proof pass.

The Ethereum composition handoff now has a private compiled owner and a distinct
finalized owner. Graph construction happens inside the boundary. Finalization
consumes compilation on success/error, computes and checks all witness values,
and retains the original graph and schedule. The materializer no longer exposes
Program plus a separately mutable borrowed Prepared. Recursive consumers use a
single Source contract with const projections. Legacy V2 inputs explicitly use
its borrowed variant and retain full mutation-sensitive validation.

The small ownership target passes (4 tests, including the root harness): 6s
compile/526M, 276ms runtime/1M. It exercises all allocation failures, rejection
cleanup, alias isolation, mutable-witness rejection, identical circuit metadata
and exact emitted-column parity. An initial unfiltered run also passed 319 tests
with one skip (1m compile/4G, 706ms/14M); keeping that dependency test suite out of
the routine target produced a much smaller measured development loop.

The genuine saved-pair cold-open/materialization/rollback gate passes: 45s
compile/2G, 62.582s gate interval, 4.652s materialization phase, 1,959,545,208-byte
peak physical footprint. Retained state is 856,164,910 bytes in 60 allocations:
1,040 bytes and one allocation above the previous owner. Schedule compiles=1,
graph copies=0. Failure index 18,384 restores a valid input and frees everything.
This is preparation/ownership evidence, not a complete wrapper proof or a
controlled end-to-end speedup measurement.

Contract and commands: src/frontends/riscv/recursion/COMPOSITION_PREPARATION.md.
The full recursive consumer build is being checked after migrating the remaining
session/cohort metadata reads. Universal circuit/profile admission is still
unfinished: V4 embeds bridge roots and other statement-dependent constants.
Dynamic authenticated AIR inputs and shared transcript/continuation definitions
remain ahead of broader wrapper optimization. Independent Ethereum root
verification and current-tree CSP A/B remain mandatory, uncompleted gates.

Final boundary checks: the genuine full Ethereum consumer compiles in 2m/5G;
all 11 legacy V2 handoff checks pass (15s compile/2G, 637ms runtime/1M).
The old program header now accurately identifies statement-specialized bridge
roots rather than claiming proof-independent circuit admission. Formatting and
diff checks pass. No heavy test/build processes remain. This ownership boundary
is integrated; broader wrapper optimization remains paused behind the remaining
protocol/profile and independent-proof boundaries listed above.


## Opt-in statement-root graph and shared field encoding

The new compiler input separates geometry from bridge-root values. Schema 2
appends two canonical VM statement-word inputs and evaluates the native bridge
AIR over those inputs. The default schema-1 wrapper and CSP profiles remain on
their existing route. Root coordinates and the optional profile hash extension
have one definition in vm_statement_roots.zig; legacy zero-count preimages and
source tags are unchanged.

The pinned genuine Stage101 native proof cold-verifies and its full composition
replays under the new graph. Changing either root by one is rejected by the
final composition constraint under the same graph identity. Exact proof hash,
root values, mutations and graph identity are retained in
`evidence/ethereum-statement-root-regression.json`. The gate passed with a 45s/2G
compile and 27s/1G runtime. It does not establish outer provider closure: two new
statement-word consumers need authenticated provider multiplicities.

Two duplicated V1 field-binding encoders now use vm_binding_field_encoding_v1.
All seven legacy word encodings are pinned; the new statement-root profile is
rejected before emitting words until its field admission is versioned.
Seven focused preparation/transport/encoding checks pass (6s/557M compile,
265ms/1M runtime), and 311 legacy VM checks pass with one existing skip.

The 15 actual VM/provider field-compatibility checks pass. The symbol-rich
baseline completed successfully in 6m/6G, with 6s/77M runtime. Sampling found LLVM
debug-history generation in function emission. The same tests with the opt-in
`-Dprofile-test-strip=true` compiled in 25s/1G and ran in the same 6s/77M.
ReleaseSafe checks remain enabled and debug symbols remain the default. The
original process finished before an attempted stop; it was not terminated.

The full default Ethereum consumer also compiles (2m/5G). Formatting and diff
checks pass; no heavy process remains. Next is the shared statement provider
use-count/routing plan and exact closure of the new inputs, followed by versioned
field admission and the remaining recursive statement/boundary inputs. Broader
wrapper optimization, independent Ethereum root claims and CSP promotion remain
behind their outstanding gates.

## 2026-09-06: shared statement-root routing and genuine closure gate

Implemented the opt-in `recursion.statement_input.roots.v3` provider with the
same AIR builder as V2. The fixed schedule adds one segment-scope use at each
canonical root coordinate. V2 defaults, semantic identity and static profile
remain unchanged. V3 has eight preprocessing columns; its fifteenth logical
input follows the V2 parameters. Static analysis measures interaction degree
four, so physical admission must derive the correct quotient geometry.

The new routing audit compiles entries from the actual provider, canonical
statement-semantics circuit, and VM input AIR. All 412 segment-scope words
close. Missing exit, duplicate entry, and individually altered entry/exit
consumers fail, including when replaying the retained cold-verified native
proof. These failing cases are pinned in the existing regression JSON.

Validation: `test-recursion-preparation` passes 15 tests (including all six
legacy statement-provider checks), 12s compile/916M, 290ms run/3M. The genuine
`test-ethereum-statement-root-replay` passes with four routing and two
composition rejections, 47s compile/2G, 27s run/1G. Evidence lives in
`evidence/statement-root-routing-focused.log` and
`evidence/statement-root-routing-genuine.log`. Format and diff checks pass.

Prerequisite 1 is still incomplete at the proof boundary: V3 preprocessing
must be admitted and committed by the outer component, followed by closure
of every remaining scope/relation. Next are the shared versioned admission
for all statement/boundary inputs and the complete-proof command that destroys
producer state before independent verification. Block proving remains paused;
no complete Ethereum root or current-tree CSP performance promotion is claimed.

## 2026-09-06: physical statement-provider admission and native/recursive parity

Corrected the opt-in V3 logical layout to match physical adapters: main,
preprocessing, parameters. Its extra use-count input is now logical slot 9,
not the former tail slot 14. The V3 candidate semantic seal is now
`3b632ab5b96cdbc56fbcf28c5e10b45db8a6ff933c227d400ad3e75ef44481f2`.
V2's layout and identities are unchanged. Both versions use one parameter
helper; V3 writes all eight preprocessed columns through the existing direct
executor with shape/alias checks and exact padding.

The shared composition-profile module now selects row 10 through
`StatementRootOuterCatalog`. Manifest geometry is compiler-derived and all
other component geometries remain unchanged. The physical diagnostic feeds
real column samples through the native point callback, records that same
component once, and compares recursive evaluation on both valid and mutated
samples. Altering the extra-use column makes constraints nonzero. This uses
fixed diagnostic challenges and is not evidence of a complete outer STARK.

Validation: 17 focused tests pass, including legacy V2 tests and full catalog
geometry (14s compile/1G; 289ms run/3M). Genuine saved-leaf replay passes the
physical checks plus four routing and two composition negatives (49s
compile/2G; 27s run/1G). Logs: `evidence/statement-root-physical-focused.log`
and `evidence/statement-root-physical-genuine.log`. Formatting/diff checks pass.

The three prerequisites remain open. Next, the outer cohort must consume
this catalog/writer, admit and commit V3 preprocessing and establish full
closure. Shared versioned admission for the remaining statement/boundary
inputs and the serialize/destroy/freshly-verify command follow. Block proving
and CSP benchmark promotion remain paused. No heavy processes remain live.

## 2026-09-06: live Ethereum root profile and complete-cohort failure

The existing Ethereum materializer now uses the schema-2 dynamic-root graph.
Its outer manifest is schema 4 with 571 preprocessing columns, and row 10 uses
the shared V3 AIR in both logical rows and physical components. The default
RV32/CSP catalog and V2 provider remain unchanged. Genuine root replay passes;
40 focused integration checks and 17 final preparation checks pass.

The complete 36-component cohort now has a dedicated replay before PCS. It
retains all 66,568,919 actual contributions: the statement-word domain closes
across all scopes. Full closure fails with 115,664 unmatched tuples in five
domains: Poseidon I/O 131, arithmetic wires 81,371, verifier inputs 6,832,
public-claim words 10,506, and public-claim bytes 16,824. Bounded samples from
each domain are retained with exact component/event origins in the checkpoint.
Samples show row-15 circuit-40 wires without consumers, row-18 kind-12 inputs
without publishers, and row-12 public-logup words/bytes without consumers.
These observations must guide the shared admission/routing fix; no balancing
terms or relaxed closure checks were introduced.

Preparation now validates one borrowed read view, hoists source geometry out
of the eight-component loop, and removes duplicate parent traversals where
children already perform them. It adds no cached validation flag. The same
failure and counts recur in 244.0s versus 354.7s before the final hoist (402.9s
before the initial view change). Peak physical footprint remains 35.8 GiB.
These are sequential local development measurements, not proving speed or a
CSP promotion. Memory and deeper ownership consolidation remain unresolved.

Evidence: `evidence/statement-root-complete-cohort-{first-failure,diagnostic,hoisted}.log`,
`evidence/statement-root-live-{materializer-replay,field-public,preparation}.log`,
and `evidence/statement-root-cohort-preparation.sample.txt`.

All three user prerequisites remain binding: complete shared routing closure,
versioned admission of remaining statement/boundary inputs, and a complete
serialize/destroy/independently-verify proof command with retained failures.
The existing wrapper replay still reuses its materializer when cold-opening;
it does not yet satisfy producer destruction. Block proving, independently
verified root claims, and current-head CSP promotion remain paused.

## 2026-09-06: admit the missing statement/public-claim arithmetic

The Ethereum native core omitted the arithmetic graphs whose inputs rows 11
and 15 emitted. The new `ethereum_statement_arithmetic_v4.Prepared` owns both
converted graphs and evaluations in private storage. It validates every node,
reconstructs the expected claim circuit from capacity and the fixed statement-I/O
policy, and rejects a self-consistent legacy zero-I/O graph. Internal views are
deeply const. Admission schema 1 binds the fixed circuit structure independently
of witness values; the native core binds it conditionally, leaving the legacy
null identity preimage unchanged. The shared lowering and arithmetic evaluation
path consumes both graphs. The Ethereum owner releases them after its native core.

Validation: 18 focused preparation tests pass (15s/1G compile; 1s/9M run).
The new case covers stale evaluations, wrong I/O policy, every allocation failure,
source mutation and reads after all source state is destroyed. Full wrapper
consumers compile (2m/5G); final canonical-policy admission also compiles and runs
in the genuine complete-cohort replay.

Latest genuine replay: 68,820,208 contributions, 34,892 unmatched tuples.
Arithmetic-wire residuals fall from 81,371 to 599. The statement domain remains
closed. Other residuals are unchanged: Poseidon I/O 131, verifier inputs 6,832,
public-claim words 10,506 and public-claim bytes 16,824. This fails before PCS,
with clean ownership teardown, in 246.5s and 36.0 GiB peak physical footprint.
It is not a completed proving benchmark. Exact samples and inputs are retained
in `statement_arithmetic_admission` in the checkpoint and its evidence logs.

The remaining wire samples point to public-sum circuit 42. Its row-16 source
currently projects only the selector and 32 relation-challenge words. The actual
graph also reads statement words, register clocks/bytes, role-I/O words, tuple
selectors and published values. Those inputs require authenticated AIR joins
and shared routing; removing unmatched provider emissions without establishing
those joins would not complete the protocol.

All three prerequisites still gate block proving. No complete serialized wrapper
has been independently verified after destroying all producer state, no recursive
root is claimed, and no current-head CSP performance promotion is claimed.


## 2026-09-06: shared statement routes and independent input reconstruction

The row-16 owner now retains a copied statement-routing plan from the admitted
public-sum graph. The same plan drives row-10 multiplicities and row-11 wire
sources, reusing the typed statement AIR and its integer range checks. Every
used statement input consumes one authenticated tuple and emits its exact graph
fan-out. Unused inputs add no rows. Ethereum manifest schema 5 and row-16 owner
schema 4 bind the new route; legacy AIR seals, CSP defaults and worker policy
remain unchanged. Geometry derives the extra row count in the existing validated
read, without adding another parent validation traversal.

The 41-case focused suite passes, including actual AIR closure and missing,
duplicate or shifted routing failures. The plan owns its schedule after source
graph destruction; statement values remain outside that fixed plan identity.
The real 36-component cohort closes 143 formerly missing arithmetic wires:
599 -> 456. Statement and range domains remain closed. Both the dedicated
cohort and complete-proof command report 68,820,634 contributions and 34,749
unmatched tuples. Other residuals remain Poseidon I/O 131, verifier input words
6,832, claim words 10,506 and claim bytes 16,824. The dedicated replay takes
249.1s and peaks at 36.0 GiB; this is a failing diagnostic, not a proving benchmark.

`test-ethereum-complete-proof` is now the combined development acceptance gate.
With `STWO_ETHEREUM_PROOF_CORPUS` pointing to the retained corpus, it runs the
real label-input commitment rejection case and the wrapper lifecycle. It cannot
pass on materialization alone. The wrapper's fresh-verification path now destroys
all producer captures, campaign and materializer before rebuilding verifier inputs
from serialized native proofs. The separate reconstruction test passes in 105.9s
at 1.8 GiB peak physical footprint and records zero live producer runtime
allocations before rebuilding. It explicitly does not produce a wrapper proof.

The complete command compiles and runs: 1/2 tests pass. The retained failure is
correctly rejected; the wrapper fails during proving at exact tuple closure,
before serialization or independent wrapper verification can be reached. The
wrapper request takes 247.8s with a 36.0 GiB peak. The three prerequisites remain
binding; full admission, complete closure and a passing proof lifecycle are still
unfinished. Block proving has not resumed. No recursive root or CSP performance
promotion is claimed. See `statement_routing_and_proof_lifecycle` in the JSON
checkpoint and `COMPOSITION_PREPARATION.md` for the single command and evidence.

Legacy VM profile/provider compatibility: 15/15 pass (26s/1G compile;
6s/77M runtime). This does not replace the current-head CPU/Metal A/B.


## 2026-09-06: authenticate register-byte routing through the shared statement AIR

The shared statement-routing plan is now schema 2. It admits the canonical
256 register-byte input coordinates and owns their exact graph destinations and
use counts. Row 10 derives statement-provider multiplicity from this plan;
row 11 emits both the used statement word and its required bytes. The new
Ethereum-only `recursion.statement_semantics.bytes.v2` AIR reuses the legacy
integer decomposition constraint and `(8,8)` range lookup. It adds four fixed
preprocessing columns and two byte-wire events, with no new main trace columns.
The byte values remain witnesses authenticated by the statement relation and
range/decomposition constraints; they are not circuit constants.

Native adapters and recursive recording select the same AIR through manifest
schema 6: 575 preprocessing columns, 1,044 main columns, 564 interaction columns
and 1,313 constraints. The legacy default and root-only catalogs remain intact.
The 42-case focused suite passes (35s/3G compile; 843ms/64M run), including byte
values/destinations/use counts, decomposition tampering, AIR seal mutation,
misordered byte sources and the existing exact statement-routing checks. The
preparation suite now includes eight existing legacy row-11 cases and passes
26/26 (15s/1G compile; 592ms/9M run).

The complete-proof command closes all 256 formerly missing register-byte wires:
arithmetic residuals fall from 456 to 200. Across 68,820,890 contributions,
34,493 tuples remain unmatched. Statement and range domains stay closed. Other
residuals remain Poseidon I/O 131, verifier input words 6,832, public-claim words
10,506 and public-claim bytes 16,824. The retained tiny genuine leaf pair is a
development fixture, not a mainnet block. The failing wrapper request takes
248,004,827,916 ns (248.0s), with 38,638,498,160 bytes (36.0 GiB) peak physical
footprint and one worker.

The combined gate remains 1/2: the retained genuine label-input commitment
rejection passes, while the wrapper fails at `role0_prove` with
`EthereumIncrementalTupleNotClosedV4` before PCS. Wrapper serialization,
producer destruction and independent wrapper verification are not reached.
Remaining clock limbs, role-I/O inputs, selectors, published values and other
lookup domains still need authenticated routing and shared circuit admission.
No wrapper/root or Ethereum proving benchmark is claimed. All three prerequisites
still gate block proving; current-head CPU/Metal CSP A/B remains required.

Evidence: `evidence/statement-byte-routing-tests.log`,
`evidence/statement-byte-complete-proof.log`,
`evidence/statement-byte-compatibility.log`, and the `statement_byte_routing`
checkpoint with source/log hashes and sampled unmatched tuple provenance.


## 2026-09-06: bounded admission findings and replay retention (complete proof pending)

The next prerequisite work is split between existing transcript sources, native
claim authentication and clock routing. The changes below postdate the passing
byte-routing checkpoint; they do not update its measured closure counts or prove
that the full wrapper passes.

The Ethereum transcript-program schema is now 4 in source. Its new detailed-claim
payload class routes the 12 extension component batch frames already mixed by the
native Ethereum transcript into verifier-input source kind 12. Classification
requires exact agreement with the recorded native array and the VM graph's
ordered claim coordinates. The route uses an Ethereum-specific payload adapter;
legacy entrypoints continue to reject kind 12. The accompanying test covers
exact typed-AIR routing and an aggregate-preserving change to the detailed array,
and the focused suite passes 44/44 (37s/3G compile; 832ms/64M run). The two
singleton Keccak table claims and bridge claim
still need aliases to their detailed-input coordinates. This is a partial route,
not evidence that the 6,832 verifier-input residuals have closed.

A separate source/algebra review found that base RV32 claim mixing passes the
canonical aggregate claim vector to the transcript, while the composition path
uses the detailed per-component/per-batch claims with individual weights. The
recursive graph also constrains detailed sums to the canonical aggregates.
That aggregate equality alone does not establish that each detailed value was
fixed before composition randomness and the OODS point. No adversarial proof
has been executed; the finding requires a focused native proof-level check and
an explicit protocol decision. It does not authorize privatizing unmatched
claims, deleting their lookup consumers, or silently changing CSP identities.

The proposed clock route maps 128 native public-wire words (516 through 643) to
public-sum graph inputs 413 through 540. The existing `statement_span` transcript
classification keeps these words outside its dynamic span and therefore in
preprocessing constants. The proposed Ethereum-only row-5 route emits the
existing statement lookup under a distinct admitted scope; row 11 checks the
u16 limbs and emits their graph wires, with counts owned by the shared routing
plan. This is a design pending implementation and validation. Making those
128 words dynamic does not by itself admit the native `wire_id` or the remaining
raw-wire values: those still need their own shared commitment/transcript binding.
A program identity containing native or replay identities is a custody identity,
not a proof-independent circuit key.

Replay retention has also changed in source. Export directories now derive from
the ordered hashes of both native inputs and wrapper bytes. Existing files are
compared in bounded memory; mismatched content is rejected instead of replacing
a retained regression. `test-ethereum-wrapper-replay` reads that triplet from
`STWO_ETHEREUM_WRAPPER_REPLAY_DIR`, reconstructs verifier inputs from disk, then
cold-verifies the wrapper with no live producer owner. Storage checks pass in
the 44-case focused suite; standalone replay compilation and a genuine saved
wrapper result remain pending. Export still occurs only after the proving API
returns successfully: a failure during its internal proof verification or
initial cold-open/capture can still discard newly encoded wrapper bytes. The
later producer-destroyed verification failure is the failure this export can
currently retain.

The prover now reuses its already admitted cohort through the kernel's checked
entrypoint. That internal verification still uses producer preparation; the
public cold-open constructs a new cohort, and the development gate separately
destroys producer state before rebuilding from native bytes. This reduces
repeated preparation without substituting internal verification for the required
independent lifecycle. No performance improvement is claimed before measurement.
The focused log is retained as `evidence/detailed-claim-routing-tests.log`.
An obsolete rejection-path debug print was removed afterward; the complete-proof
replay is running against the subsequent source and has no result yet. All three
prerequisites, a complete Ethereum proof and the current-head CSP latency/memory
gate remain open.


## 2026-09-06: shared claim gate and intermediate cohort receipt

The consolidated claim/storage focused gate passes 45/45 (38s/3G compile;
824ms/64M run). `check-ethereum-wrapper-replay` also compiles (1m/4G), but this
is a compile-only result: no retained Ethereum wrapper exists to verify.
Evidence: `evidence/shared-claim-gates.log`.

An intermediate complete-proof executable closes 6,680 extension detailed-claim
inputs: verifier-input residuals fall from 6,832 to 152. It reports 68,827,570
contributions and 27,813 unmatched tuples. Other residuals are unchanged:
arithmetic wires 200, Poseidon I/O 131, public-claim words 10,506 and public-claim
bytes 16,824. Statement and range relations remain closed. The combined gate
still passes only the retained rejection case (1/2); the wrapper fails with
`EthereumIncrementalTupleNotClosedV4` in `role0_prove` before PCS. Its request
is 250,610,395,416 ns with 38,638,580,128 bytes peak physical footprint, one worker.
This is a failing development replay, not a proving benchmark.

This executable predates the final shared-claim consolidation and new Ethereum
cohort resource telemetry: those sources changed while it ran. Its receipt is
retained as `evidence/detailed-claim-complete-proof-intermediate.log` and must not
be attributed to the latest source snapshot. A subsequent complete-proof replay
is compiling; its outcome and source-hash checkpoint remain pending. All three
prerequisites continue to gate block proving and CSP promotion.


## 2026-09-06: final shared-claim replay and measured cohort allocation boundary

The final source snapshot reproduces the extension routing improvement:
68,827,570 contributions, 27,813 unmatched tuples, with verifier-input residuals
reduced by 6,680 to 152. Arithmetic wires remain 200, Poseidon I/O 131,
public-claim words 10,506 and public-claim bytes 16,824. Statement and range
relations remain closed. The shared classifier now owns Ethereum recorded-frame
admission and physical layout; the integration consumes that one definition.
The Ethereum transcript program is schema 4, manifest schema 6, statement-routing
plan schema 2. Default payload paths retain their existing rejection rules.

The final complete-proof gate is 1/2: the genuine label-input commitment
rejection passes, while the wrapper fails at exact closure before PCS. Its
request takes 250,374,128,333 ns (250.374s) at 38,638,547,360 bytes (36.0 GiB)
process lifetime peak footprint, with one worker. Compilation is 1m/4G.
This is a failing development replay, not an Ethereum proving benchmark.
No wrapper serialization or independent wrapper verification was reached.
The focused 45/45 result and compile-only standalone verifier result remain
separate evidence; no genuine wrapper exists for the latter.

New Ethereum-local telemetry narrows the memory investigation. The process
lifetime peak is already 17,837,127,360 bytes on entry to complete-cohort
preparation and remains there through prefix and suffix tuple append. It rises
to 38,638,547,360 bytes during native tuple append. At that marker the ledger
contains 68,827,554 records; range-provider output adds only 16. Final ledger
length is 68,827,570, capacity 90,811,043 and measured record size 136 bytes:
9,360,549,520 bytes used, 12,350,301,848 capacity, 2,989,752,328 unused capacity.
These are exact ledger byte calculations. The process peak is not live memory;
it cannot by itself separate array growth/copy overlap from temporary native
logical rows and already retained preprocessing/main/interaction trees.

Measured intervals include geometry reads/validation 23.221s, prefix-component
preparation 8.038s, prefix logical rows 4.190s, suffix rows 33.753s, provider
finalization 1.931s, native tuple append 30.484s and classification 27.394s.
Ledger release is observed; the lifetime peak correctly does not fall afterward.
Sorting and diagnostic printing remain allocation-free. The next memory work is
bounded allocation measurement within native tuple append, followed by an
Ethereum-local reservation or row-projection change justified by those numbers.
No ledger representation change, heuristic reservation or CSP path change is
included in this checkpoint.

The independent disk replay command is available below. Replace both placeholder
values with a retained corpus path and exported triplet identity:

```sh
STWO_ETHEREUM_WRAPPER_REPLAY_DIR="<corpus>/wrapper-replays/<triplet-sha256>" \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-wrapper-replay -Doptimize=ReleaseSafe \
  -Dethereum-proof-strip=true --summary all
```

This command is compile-verified only (1m/4G). Export retains both ordered native
inputs and wrapper bytes, preserves mismatched existing files by rejecting, and
publishes the wrapper last. It can retain a failure during the later independent
rebuild/reopen. Failures inside the proving API's internal verification or initial
cold-open still occur before export and may discard encoded proof bytes.
Internal verification with the reused admitted cohort is distinct from this
producer-destroyed verification boundary.

Evidence: `evidence/shared-claim-gates.log`,
`evidence/shared-claim-complete-proof.log`, and
`shared_claim_routing_and_resource_checkpoint` in the JSON checkpoint. That
checkpoint records every resource marker, unmatched tuple sample, input pin,
source hash and the separately scoped intermediate receipt. Remaining base
claim authentication, singleton aliases, clock/IO/publication routing and
statement-independent admission remain prerequisites. All three user gates,
a complete Ethereum proof/root and current-head CPU/Metal CSP A/B remain open.


## 2026-09-06: schema-3 native pair crosses the independent disk boundary

The explicit detailed-base Ethereum native profile now passes its producer-only
lifecycle gate: **1/1**, two genuine q193 native leaf proofs serialized to disk,
all producer allocations destroyed, then both SHA-pinned files opened and
verified afresh. The request took 125.139s (78.367s production/export/destruction,
46.772s fresh disk verification), at 1,179,403,824 bytes process lifetime peak
physical footprint and one configured worker. Compile summary: 1m/3G;
run summary: 2m/1G. These measurements cover the tiny two-leaf native fixture,
not an Ethereum block or recursive wrapper.

The command, from repository root, is:

```sh
STWO_ETHEREUM_PROOF_CORPUS="$PWD/.git/local-ethereum" \
STWO_ROLE0_GENUINE_WORKER_COUNT=1 \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-native-base-bound-producer -Doptimize=ReleaseSafe \
  -Dethereum-proof-strip=true --summary all
```

Its exact test filter is `role0 schema3 native pair serializes destroys producer
and freshly verifies`. The native full-leaf profile is schema 3; the unchanged
artifact container is schema 2. The schema is already serialized, hashed and
mixed into the native transcript. Existing schema-2 constructors and retained
SHA fixtures keep their original interpretation. New admission adds the selected
physical base claims before the bridge claim and Tree 2; native and recursive
extraction consume one selected-claim layout.

The new directory is `.git/local-ethereum/base-bound-v3`. Artifact hashes and
sizes were independently rechecked from disk at this checkpoint:

| Leaf | SHA-256 | Bytes |
| --- | --- | ---: |
| 0 | `7984f63fe4e285cdfb6a59ca877435edadade565de3540c5c73dc019a85af559` | 8,649,106 |
| 1 | `9fe54ac33fa51210fa82974f339de5b2ec8df35e4916a05b8ea6351eb0a82088` | 8,954,248 |

The saved complete-proof route now selects this new pair. The label-input
regression and earlier canonical-IO files remain retained. There is no new
wrapper result: the previous 250.374s/38,638,547,360-byte failure and 27,813
unmatched tuples are a **historical source snapshot**, before subsequent clock,
singleton, reservation and public-cancellation changes. They are not current-head
wrapper performance or current closure counts.

Intermediate checks remain explicitly incomplete: frontend validation was
32/35 (the VM context subgate passed 5/5; three new row-12 seal/route tests failed),
then the integration clock/alias probe was 47/50. A later focused run reached
52/53, with clock checks passing and only the schema-3 header classifier failing.
The classifier incorrectly expected four host words where `mixU32s` records eight
u16 field words. That exact representation fix is implemented; a fresh combined
rerun is pending. Public-sum schema 4 now removes twenty redundant published-value
inputs and constrains public boundary plus all 43 canonical claims to zero;
row-16 schema 6 projects their 172 limbs. Those later changes have no complete
proof result at this checkpoint.

Evidence is retained in `evidence/ethereum-base-bound-producer.log`, the four
`*-intermediate.log` files added alongside it, and
`base_bound_native_schema3_checkpoint` in the JSON receipt. Source hashes there
are documentation-time hashes, not a claim that later saved-pair edits were
included in the producer executable. No Ethereum wrapper, whole block or root is
proven, and no current-head 16-case CPU/Metal CSP benchmark result is claimed.

## 2026-09-06: bounded admission and publication gates

Three focused receipts now pass at their recorded source batches:

| Gate | Result | Compile | Run |
| --- | ---: | --- | --- |
| Frontend publication preparation | 43/43 | 18s, MaxRSS 1G | 990ms, MaxRSS 9M |
| Whole-program admission | 4/4 | 4s, MaxRSS 420M | 269ms, MaxRSS 3M |
| Publication integration | 65/65 | 44s, MaxRSS 4G | 880ms, MaxRSS 65M |

The frontend receipt precedes subsequent prototype removal. The integration
receipt precedes the new schema-4 tests; neither receipt validates later edits.
Logs are retained as `evidence/ethereum-publication-air-tests.log`,
`evidence/ethereum-program-admission-tests.log` and
`evidence/ethereum-integration-publication-tests.log`. The earlier schema-3
native producer result remains **1/1, 125.139s, 1,179,403,824 bytes lifetime peak**;
it was not rerun by these focused gates.

Whole-program admission now owns the complete ELF, its native commitment, and
all declared supported executable completion rows. The admitted completion
polynomials constrain PC, raw instruction limbs and all four decoded fields;
proof values do not choose a smaller table. The first development profile
explicitly admits at most **64 executable rows**, at most **32 role tuples**,
and the version-1 **nonfinal** completion policy. These bounds describe the
small complete-fixture route, not a mainnet Ethereum block profile. The program
file retained beside the schema-3 pair is 1,048 bytes with SHA-256
`ecfd324f8088f9c985210b728d91851fb1144254f0bb6d52aa3d7ed0e3625f55`;
its disk hash was checked for this checkpoint.

The explicit native schema-4 route is implemented but **not yet test-passed**.
Its shared tagged emitter removes custody-only boundary/profile SHA frames from
Fiat–Shamir while retaining those hashes in input validation. It replaces the
public-boundary SHA with explicit role input/output words and completion,
classifies coordinate values separately from admitted geometry, and leaves
schema-2/3 constructors and transcript branches intact. Five tests under
`Ethereum schema4` include genuine fixture preparation and exact comparison
against retained historical schema-2/3 recorded frames, returning before proof
production. Recursive schema-4 consumption and fixed admission are still open.

The exhaustive raw V2 layout helper is a separate prerequisite. Its first
`test-segment-statement-v2` compile failed on a local `section` capture shadowing
the method of that name; the failure is retained in
`evidence/ethereum-native-layout-tests.log`. A correction and rerun still need a
receipt here. Layout classification alone does not establish lookup closure for
raw lineage, snapshot, memory-clock, completion and variable-section words.

A fresh schema-3 cohort run has started in
`/tmp/ethereum-base-bound-cohort-replay.log` (session 18608); this checkpoint has
**no terminal result** for it. The earlier 27,813-unmatched result remains
historical evidence and must not be reported as the new run's closure count.
There is still no independently verified Ethereum wrapper, whole block or root.

The replay storage contract now includes four files: `leaf-0.bin`, `leaf-1.bin`,
`program.elf` and `wrapper.bin`; the directory identity binds their ordered
content hashes. Fresh reopening rebuilds preparation from both native proof
files and the independently pinned ELF, then cold-verifies the wrapper. It is
independent of producer state, but still performs native proof verification in
the host. It is **not root-only verification** from a public statement, admitted
ELF/profile and root proof. No current-head 16-case CPU/Metal CSP promotion result
is claimed. Exact receipts and documentation-time source hashes are in
`bounded_admission_and_publication_checkpoint` in the JSON evidence file.

## 2026-09-06: shared final claims and the remaining closure routes

The latest bounded gates pass: frontend preparation **41/41** (17s/1G compile,
1s/9M run), integration **79/79** (58s/4G compile, 1s/66M run), and native V2 layout
**18/18** (6s/468M compile, 420ms/2M run). The integration gate includes schema-4
frame encoding, real admitted schema-2/3 frame preservation, schema-2/3/4 final
claim ordering and the new frame-plan classification tests. The earlier
schema-4 pending-test status is superseded for these focused checks. This does
not mean the schema-4 frame plan has been integrated into recursive admission.

The real schema-3 replay exposed another parallel transcript description: the
recursive path mixed the existing extension claims and bridge but omitted the
new selected-base claims. `AuthorityV4.mixFinalClaims` now supplies one shared
selected-base-then-bridge sequence to the native prover hook, native verifier and
recursive replay. The extension prefix remains unchanged, and schema 2 keeps
its exact legacy sequence. The real preparation fixture checks recorded
operations, payloads and final channel digests without generating another proof.

A **historical** independent input reconstruction receipt passed **1/1**:
105.891s request, 1,958,037,904 bytes lifetime peak, one worker. Its source commit
and exact executable source snapshot are unknown; it is not part of the current
41/79/18 batch and has not been verified against the current tree. The original
log's observed filesystem modification timestamp is 2026-09-06 14:40:22 UTC;
that timestamp is not an execution-time or commit attestation. All tracked producer allocations
and bytes reach zero before reconstruction from the two native proof files and
pinned ELF. Its receipt explicitly records `wrapper_verified=false`; this is a
working development boundary, not a wrapper verification result.

The next real cohort reached **68,814,696 contributions and 458 unmatched
tuples**, down from the historical 27,813 residuals. Its request was
255,244,400,250 ns with 38,094,647,232 bytes lifetime peak, one worker, and failed
0/1 at closure. Exactly 450 residuals were duplicate public-boundary emissions
at scope 4; the other eight were inherited legacy VM-claim-digest consumers at
verifier 0, kind 11. Ethereum's native transcript has no such digest input.
Current source removes the duplicate emitter and the redundant child-claim hash
rows, allocations and actual provider calls. Claim semantics, role sources and
input/output hashes remain; no invented digest emitter closes the obligation.
The Ethereum row-12 variant omits that hash fanout while preserving the legacy
CSP semantic seal. These changes have focused checks. The subsequent terminal receipt below
confirms exact tuple closure, followed by a STARK proving failure.

The full `test-ethereum-complete-proof` rerun in session 19754 has now returned;
its terminal result is recorded below. The 458-unmatched log is retained as
`evidence/ethereum-base-bound-cohort-458-unmatched.log`; it describes the source
before these removals, not the new run. Further receipts are
`evidence/ethereum-publication-air-tests-v2.log`,
`evidence/ethereum-integration-boundary-tests.log`,
`evidence/ethereum-native-layout-tests-18-passed.log` and
`evidence/ethereum-independent-inputs-replay.log`.

P0 fixed circuit admission remains open: the tested schema-4 `FramePlan` is not
integrated into the active recursive route, and unresolved raw V2 values still
need authenticated AIR endpoints. The current native-assisted wrapper route is
diagnostic. It still needs native proof bytes for fresh preparation, whereas a
succinct root verifier must use only the public statement, admitted ELF/profile
and root proof. The 64-executable-row, 32-role-tuple, nonfinal fixture bounds
remain explicit. No independently verified wrapper, full Ethereum block,
succinct root or current-head CPU/Metal CSP promotion receipt exists. Detailed
scope and source hashes are in `shared_final_claims_and_boundary_closure_checkpoint`.


## 2026-09-06: exact lookup closure reached; STARK proving still fails

The complete-proof target returned **2/3 tests passed, one failed**. The genuine
schema-3 saved-pair request classified and released **68,788,872 exact lookup
contributions without a mismatch**, then failed with `InvalidProofShape` at
`prove.stark`. The previous 450 duplicate boundary emissions and eight inherited
claim-hash consumers no longer block this cohort. This is a closure milestone,
not a produced or independently verified wrapper: serialization and fresh wrapper
verification were not reached.

The request took **597.676632792 seconds** with one worker and an overall lifetime
peak of **45,273,744,552 bytes**. Native leaf production is excluded. During ledger
classification the process high-water footprint was **27,332,448,608 bytes**,
below the historical 458-residual run's 38,094,647,232 bytes. Later proving raised
this run's overall peak above that historical receipt. These are process lifetime
high-water samples, not live allocation measurements or a whole-request memory
improvement. The ledger held 9,355,286,592 bytes of records; its once-reserved
capacity was 147,272,324 records (20,029,036,064 bytes), leaving 78,483,452 unused
records. Reserved capacity must not be equated with resident memory.

The immutable terminal log is
`evidence/ethereum-complete-proof-boundary-v4-invalid-proof-shape.log` (8,852 bytes;
SHA-256 `fc7f3efe2dced2bc95f873711009b13074eb4ae9a074b9476c4d54a1f831edee`).
It records the executable, seed, program ELF identity and phase telemetry.
Compilation reports 1m/4G. Exact parsed receipts and documentation-time source
hashes are in `complete_proof_boundary_v4_checkpoint`; those hashes are not an
attestation of an exact committed executable source snapshot.

Additional retained focused checks pass schedule admission **15/15**
(7s/581M compile, 346ms/4M run) and native V2 layout **20/20**
(6s/479M compile, 634ms/2M run). The parent reported an intermediate integration
**80/80** result (55s/4G compile, 1s/66M run), but its temporary log was overwritten
by a pending rerun before this checkpoint retained it; it is a parent-reported
receipt, separate from the retained 79/79 log. The parent has identified missing
retained polynomial coefficients under the current preparation policy as the
`InvalidProofShape` cause and is implementing an Ethereum-local policy correction;
that correction has no complete-proof result here.

P0 still requires the complete wrapper lifecycle and fixed circuit admission.
Schema-4 FramePlan integration and authenticated raw V2 AIR sources remain open;
fresh native-assisted reconstruction is not root-only verification. The bounded
64-program-row, 32-role-tuple, nonfinal fixture is not a mainnet block benchmark.
No wrapper, whole-block, succinct-root or current-head CSP promotion result is
claimed. Historical independent input reconstruction remains source-unknown and
is not grouped with current-tree gates.


## 2026-09-06: retained-coefficient retry and focused development gates

The latest integration receipt is retained before its temporary log can be
overwritten: **83/83** (56s/4G compile, rounded 1s/66M run). Native V2 layout
passes **20/20** (6s/479M, 634ms/2M), schedule admission **15/15**
(7s/581M, 346ms/4M), and typed quotient domains **6/6**
(9s/785M, 281ms/2M). Logs and SHA-256 identities are recorded in
`retained_coefficients_retry_checkpoint`. These are separate source batches;
documentation-time source hashes do not attest each executable's exact snapshot.
The retained 83/83 log supersedes the parent-reported intermediate 80/80 receipt
for this later integration gate.

Two focused commands are available from the repository root:

```sh
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv test-recursion-schedule-admission -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/frontends/riscv test-recursion-quotient-domains -Doptimize=ReleaseSafe --summary all
```

The coefficient-retention complete-proof retry in session 1030 has returned;
its terminal receipt follows. Focused passes do not establish a produced wrapper,
fresh verification or fixed root admission.


## 2026-09-06: retained coefficients reach finalization; constraint check fails

Retry 1030 returned **2/3 tests passed, one failed**. It again classified and
released **68,788,872 exact tuple contributions without mismatch**. Retaining
coefficients gets this route past the earlier `InvalidProofShape`, but finalization
now rejects with **`ConstraintsNotSatisfied`** (`subphase=none`, `evaluation=null`).
The log does not identify the offending constraint. The parent is investigating
the OODS mismatch; no diagnosis or correction has a passing full-proof receipt
here. No wrapper was serialized or freshly verified.

The request took **814.173816291s**, one worker, with **59,835,018,536 bytes**
process lifetime peak. Native leaf production is excluded. Ledger classification
reached 27,332,432,152 bytes, then wrapper commitment phases raised the high-water
to 32,168,320,736 bytes after preprocessing, 46,255,146,608 after main commitment,
and 55,535,755,512 after interaction commitment. These are lifetime high-water
samples, not isolated live-owner allocations.

The resource plan corrects the earlier guessed PCS geometry: **`blowup_log=1`**,
so the LDE factor is **2**, not 16. The three trees retain **10,908,653,376 bytes**
of native-sized coefficients, equal to **one half of LDE storage**, not one
sixteenth. Coefficients plus LDE storage yield a **32,725,960,128-byte minimum**
PCS resident estimate, excluding Merkle, witness and composition owners. This
planned minimum is separate from the measured 59.84GB process peak.

Evidence is retained as
`evidence/ethereum-complete-proof-retained-coefficients-constraints-not-satisfied.log`
(10,105 bytes; SHA-256
`801f68d7260bdd887aeef62bc20cdcad50b8cc5bd9be755814a518708f601a67`).
The executable, seed, exact phase/resource plan and documentation-time source
hashes are in `retained_coefficients_terminal_checkpoint`. Source hashes do not
attest the failing executable's exact source snapshot; later debugging can change
the shared tree. Compilation reports 1m/4G. A subsequent focused 87-test gate is
pending at this checkpoint. Fixed circuit admission, full wrapper lifecycle,
root-only verification, Ethereum block proving and CSP promotion remain open.


## 2026-09-06: bounded coefficient recovery and the FFT tower regression

The coefficient recovery test retained a real failure before correction: 7/8
passed, with native log 6 / committed log 7 / quotient log 8 rejecting after
interpolation. Coefficient 16 was 1,999,441,802 instead of 311, despite valid
domain membership in the twiddle tower. The packed radix-8 path indexed from
`values.len / 2` even when the caller supplied a larger twiddle table. Scalar
stages indexed from the table's end. The shared packed kernel now uses
`twiddles.len`; exact-size indexing is unchanged. The deterministic nonconstant
polynomial and original failing log are retained as regressions.

The corrected quotient gate passes **8/8** (10s/778M compile, 687ms/2M run),
including retained/recovered polynomial parity at native logs 2, 4, 6, 7 and 8,
immutable source values, same-domain borrowing and rejection of nonzero high
coefficients. Recovery uses the existing quotient output buffer: copy and
interpolate the entire committed LDE, reject coefficients above the native
degree, then pad and evaluate. Missing sources wider than the quotient remain
unsupported. Per-component quotient buffers still remain live; this is not
streaming row evaluation or a measured whole-request speedup.

The standalone **1/1** packed radix-8 test also passes: forward, inverse,
normalized inverse and duplicated-half expansion match scalar stages for
1x, 2x and 4x twiddle tables. It ran through `scripts/zig_protocol_test.py` while
holding `/tmp/stwo-zig-build.lock`. The timed complete command took 1.75s with
375,652,352-byte maximum RSS; compilation is included, so this is not an isolated
kernel benchmark. Native Poseidon/range provider quotient domains match the
actual PCS `trace_log + 1`; typed adapters have an extension floor of one. That
compatibility finding is code inspection, not a successful full proof with
coefficient retention disabled.

Further retained checks pass integration **89/89** (57s/4G compile, 1s/66M run),
static AIR preflight **2/2** (20s/1G, 282ms/3M), and genuine first-18-component
preflight **1/1** (1m/3G compile). The genuine preflight checks direct roots,
adapter parameters and padding in 93.695878083s with a 17,835,849,240-byte
lifetime peak. It explicitly records `full_cohort=false` and
`wrapper_verified=false`. Remaining components and full OODS composition are
not established by this result.

Unique logs, hashes, commands and source-snapshot limitations are in
`quotient_recovery_and_preflight_checkpoint`. The latest full wrapper still
fails finalization with `ConstraintsNotSatisfied`; its native schema-3 route
is diagnostic and requires host native verification. No wrapper serialization,
fresh wrapper verification, root-only endpoint, full Ethereum block or CSP
promotion is claimed. Fixed schema-4 admission and raw V2 AIR integration remain
separate P0 work.


## 2026-09-06: normalized wrapper composition and explicit capture admission

The genuine AIR preflight now passes **1/1 over the first 34 components**:
101.466684791s, 17,835,931,208-byte lifetime peak, one worker. It checks direct
roots, adapter parameters and padding; its receipt explicitly records
`provider_rows_checked=false` and `wrapper_verified=false`. This expands the
earlier first-18 check without claiming the complete proof works.

A tiny production-geometry regression failed **3/4** at row 17's point/domain
comparison. That AIR uses quotient `trace_log + 2`, while ordinary components
use `trace_log + 1`; the wrapper's legacy split-one geometry made PCS trace
lifting disagree with quotient accumulation lifting. The versioned Ethereum
wrapper admission now normalizes every component to `trace_log + 2`, with shared
split two on both prover and verifier handles. Existing q1 polynomial extension
handles ordinary rows and native providers; q2 rows use a split-only override.
The admitted-geometry gate passes **5/5** (23s/1G compile, 787ms/4M run).

The core split-only gate passes **3/3**, including two discovery roots. Direct,
parallel and prepared callbacks do not enable extension for delta zero; the
existing delta-one polynomial-parity check remains. The complete test command
took 2.29s with 503,414,784-byte maximum RSS. A prior wrong-module-root invocation
failed before testing and is retained separately. Null/default behavior and
existing candidate extension behavior remain unchanged.

Wrapper manifest **schema 13** hashes composition admission version 1 and split
2 into its contract identity, which feeds program/profile/session identities.
Retained native **schema-3 leaf fixtures remain unchanged**. The subsequent
wrapper capture path explicitly admits split two and normalized `max(trace+2)`
from the wrapper contract. It does not infer admission from a proof's chunk
count. Legacy/native capture constructors still require split one. Capture
regression **3/3** passes (two discovery roots; 12.06s complete command,
2,307,735,552-byte maximum RSS), including old/new split rejection and altered
composition-column logs. These command measurements include compilation.

The small mixed-composition proof executable passed **2/2 tests** (19s/1G
compile, 305ms/4M run), but its enclosing exact-count guard failed because it
expected one compiled test. This is not a passing target receipt. The aggregate
also remains **95/96**, failing a completion-publication fixture count
(`expected 1, found 7`). The parent reports both guard/fixture corrections;
combined retry 40794 is running without a terminal result here.

Logs, hashes, exact scopes and source-batch limitations are in
`normalized_wrapper_geometry_checkpoint`. The PCS resident estimate still
excludes additional q1 polynomial-extension/composition buffers. The latest
full wrapper receipt remains `ConstraintsNotSatisfied`; normalized geometry
has not yet produced or independently verified a wrapper. Native-assisted
reopening remains diagnostic, and fixed native schema-4/raw V2 AIR admission,
root-only verification, full Ethereum block proving and CSP promotion remain
separate unfinished work.


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

## 2026-09-07: retained wrapper independently replays after ownership fix

Frozen source `2943a7b5cb2b2a422ce89d59a4c503bfd4c67355` passed the retained-candidate gate (1/1). It reconstructs verifier inputs from the pinned native pair and ELF, verifies the saved wrapper, checks recursive publication and node serialization, and rejects query/sample mutations. Tracked allocator ownership returned to zero. No producer is constructed.

Postprocessing fell from 5,728.52 s to 188.76 s; full replay took 618.19 s. Cold source validation fell from 38.76 s to 4.12 s. The replay's lifetime peak was 32,160,915,096 bytes; this excludes proving and is not directly comparable to the full lifecycle's peak. Requested materialization/proving workers were one; verifier Merkle scheduling remained separate.

The fix retains full closure admission, then checks current mutable capture/source bindings against a private value-only replay. A compile-time pointer-free guard protects that ownership assumption. Exact borrowed-view checks and shared routing passed 114 integration/small-proof cases and five raw transcript checks. The explicit field-program constructor also passed using genuinely verified metadata; this is not a field-profile proof.

The checked-view follow-up also passed (source `0b6c919c820ca6965fe4a83e227d341b294a4194`, 114/114 focused gates and 1/1 genuine replay). Every adapter acquisition now accepts current mutable sources once, then projects its exact borrowed views locally. Actual child graph metadata, equal-content foreign output buffers, and a copied manifest are rejected. Postprocessing is now 55.86 s, including the additional mutations; complete replay is 479.72 s. See [final checked-view receipt](evidence/2026-09-07-retained-wrapper-validation/checked-views-replay.json). Root-only field-profile admission, raw clock semantics and real campaign geometry remain unfinished. The frozen CPU/Metal CSP A/B build and run are in progress; no promotion is claimed. See [run receipt](evidence/2026-09-07-retained-wrapper-validation/passed-replay.json), [complete replay log](evidence/2026-09-07-retained-wrapper-validation/passed-replay.log), [raw admission obligations](evidence/2026-09-07-raw-clock-admission.md), and [real leaf readiness](evidence/2026-09-07-real-leaf-readiness.md).


## 2026-09-07: frozen checked-view CSP comparison completed

Source `0b6c919c820ca6965fe4a83e227d341b294a4194` completed all 128 CPU/Metal A/B reports and 640 measured samples across the unchanged 16 cases and 16-worker secure policy. All reports passed verification and exact CPU/Metal/A/B proof and statement identity checks. All 128 quiet-host gates failed; a separate project CPU job was active and was not paused without permission. This is functional preservation evidence, not latency/memory promotion.

Per-case proving median changes ranged from -2.90% to +6.14%, verification -2.47% to +6.86%, end-to-end -2.64% to +2.48%, and memory -0.29% to +0.62%. No case triggered the diagnostic repeated-over-5% proof/memory flag, but all positive changes repeated in both rounds remain recorded for quiet-host investigation; 5% is not an allowed regression. See [complete per-case review and retained evidence](evidence/2026-09-07-checked-views-csp/review.json). This frozen source predates the subsequent raw-clock schema7 work.


## 2026-09-07: raw clocks and program-bound key admission

The existing public-sums program now uses schema7. Its 1,739 private Boolean witnesses are constrained to the same 128 raw clock limbs used by memory lookups. It checks canonical encodings, zero-aware native access-clock bounds, full native-u64 span joins, positive checked cycle length/end≤2^24, and entry≤exit. Existing CSP defaults and the RV32 path are unchanged. The 2^24 limit applies to the native statement frame; retained real leaves already normalize that frame, and global block positions remain a separate u64 authority.

The Ethereum cohort now derives contract, program, profile, layouts, verification keys and preprocessing cache identity from the independently built immutable public-sums program identity, so arithmetic changes cannot preserve the admitted key merely by fitting the same padded geometry. The native local projection and existing leaf-link AIR schedule also consume one versioned canonical-word map. That consolidation does not activate global-link AIR in the current wrapper.

Validation: five raw-clock gates passed; seven selected existing/new leaf-local tests passed; the combined integration/prepared/small-proof run passed 121/121 tests (113 +6 +2). A complete genuine wrapper run on this new admission is next; the earlier successful wrapper and CSP receipts predate schema7. See [gate evidence](evidence/2026-09-07-raw-clock-program-admission/admission-gates.log).


## 2026-09-07: schema7 complete proof and separate-process replay pass

Frozen source `7757605cee19a6d01918a3a6de7fff366fabd634` (source SHA-256 `3aec645118afe63470202ef424b3e352352000ff0621e176d6af368b3256b1f0`) passed the complete genuine wrapper gate **3/3** and a separate-process candidate replay **1/1**. The 3,026,589-byte proof has SHA-256 `76ce3cdd4cc269b5d6bcffcd0a3d9a45d4861fc3566ab27870ada277d15a6dc3`. Both producer and final tracked allocations drained to zero; serialization, independent verification, publication and mutation checks passed. Exact closure accounts for 68,882,155 contributions.

The complete request took 1,757.015380500 s (29.28 min), including 468.966286542 s of STARK work and 55.709469291 s of postprocessing. Lifetime peak footprint was 52,620,991,008 bytes (49.01 GiB). Separate-process replay reconstructed the preprocessing authority without producer-process cache state and passed in 477.487553667 s (7.96 min), peak 32,167,861,792 bytes (29.96 GiB), with no producer construction. These are diagnostic wrapper measurements, excluding native input proving, not an Ethereum block/Zisk final-proof comparison.

Evidence: [complete lifecycle](evidence/2026-09-07-raw-clock-program-admission/complete-proof.json), [separate-process replay](evidence/2026-09-07-raw-clock-program-admission/fresh-process-replay.json), and [worker-policy findings](evidence/2026-09-07-raw-clock-program-admission/worker-policy.md). Remaining correctness work is the explicit field profile and full dynamic public/global-continuation admission for a standalone root. Real campaign geometry, CPU/Metal leaf/block reproduction and uncontended CSP performance evidence also remain. After the proof passed, seven unused geometry-only identity/key helpers and their private derivation helper were removed (79 lines). The active cohort already used the program-bound path. Post-cleanup validation passed 121/121 tests and compiled both complete-proof and candidate-replay commands; the proof receipts remain pinned to the source above. See [post-cleanup gates](evidence/2026-09-07-raw-clock-program-admission/post-cleanup-gates.log).

Post-cleanup source pin: `0fc5cc644869db6f5fcb8dbaa8da6387daaaa48f`, source SHA-256 `2daf2b7d37ab7bef5eca16c77df3f8a2e2b1b9f5d87b56b964ab0a78904266e8`. This pin covers the 79-line unused-helper deletion and the final 121-test/compile checks. Complete proving and separate-process replay were run on the preceding `7757605` source; no proving logic changed in the cleanup.

### 2026-09-08 DevEx detour: first executed gates

The frozen wrapper2 v7 attempt passed main commitment and interaction (1605.680 seconds), then reached PCS sampled-value evaluation. It was deliberately cancelled for the user-directed DevEx priority; no complete proof was accepted. All completed phase logs and the final sample are retained in `evidence/2026-09-08-validation-ownership/`. This is a cancellation, not an OOM or proof rejection.

The opt-in bounded selected-leaf verifier lane freshly accepted native0 while that wrapper was running: 87.195 seconds monitored request, 2,390,526,184 bytes reported peak, below the explicit 3 GiB child budget. Accepted campaign coverage remains 20 unique leaves (0–18 and120); resume rechecks are not new proofs. The controller keeps the existing proof-verification policy and the heavy producer lock. Exact concurrent evidence is under `evidence/2026-09-08-bounded-native-verifier/`.

The focused `test-ethereum-validation-ownership` gate passed 5/5 tests: compile16s / 1G MaxRSS; tests266ms / 1M MaxRSS. It covers opaque prefix/suffix access, fused generation versus canonical columns and independent cold sums, allocation failures, immutable campaign cloning and API integration. Full proof compile and real-input replay remain pending; this does not establish complete-proof parity or a measured end-to-end speedup.

### 2026-09-08 DevEx detour: consolidated boundary and real replay

An additional 20 tests passed on the first ownership revision: small complete composition3/3 (936ms, compile20s), prepared wrapper8/8 (263ms, compile6s), symbolic public boundary9/9 (272ms, compile9s). The complete-proof target compiled2/2 in2m /5G MaxRSS. Exact logs are retained under `evidence/2026-09-08-validation-ownership/`; these gates precede the later six-file boundary consolidation.

The first real no-PCS replay failed compilation in10.821s because the standard JSON decoder rejects the ordinary Generated.initial_claims void field. A replay-only reflected decoder and required malformed-field/profile regression fix that without changing protocol structures. The corrected frozen source-v3 is `c2afa2b712c36dd7ccd396c8ca7675c69e8d8cbde2126bd59045901894aa07d3`; `.git/local-ethereum/devex-real-cohort-replay-v2` is the running before-consolidation measurement. It has passed cold opening85.092s, campaign150.792s and materialization133.191s and reached real preparation. No terminal result or real-wrapper proof acceptance yet.

The newer Complete/Secure boundary validates shared Geometry once and checks privately owned prefix/native preparation locally. Native.Storage.validate source-level calls per secure closure check fall4→1, full TranscriptRows.validate3→0 (prepared-row validation remains), Complete.validateStructure2→1. These are static counts excluding deeper generic/Initial38 work, not measured speedups. No validation flag or trusted caller receipt was introduced. Frozen source-v4 correctness/complete-compile gates are queued behind the before-consolidation real replay.

Bounded verifier lane closeout:15 successful request receipts (0–14),14 controller progress lines (0–13), then a confirmed childless SIGTERM pause; all20 accepted proofs and candidate19 rehashed unchanged. The15 receipts are repeated verification, not new block coverage. Native production remains paused for the user-directed detour.

Final bounded delta in this pass removes upstream audits from Geometry.rows10Through34Mutable and Rows10_34.nativeCoreMutable; they return borrowed opaque handles and the actual Native finalizer still validates before writing. This removes one Geometry, two Rows10_34 and two Native validation invocations per Complete initialization. Frozen after-source is `dd88e4828e9ad646b29829bf461fcf2823e197751f364360d3560c9f4f3d7409` (source-v5), seven files different from the running before-source-v3. Queued source-v4 gates were cancelled while confirmed childless, without running a compiler, and replaced by source-v5 gates. No more code changes are planned before these measurements.

To avoid duplicating the expensive cold half on superseded code, the before-source-v3 run will deliberately stop only after the live `producer_destroyed=true serialized_bytes=` marker. The monitor verifies test48195's full frozen-source ancestry before signaling that test alone. This is a before-production timing run, not an accepted complete replay. Source-v5 will perform full serialization/destruction/independent Tree2 reconstruction and cold closure after its queued25-test/full-compile gates pass. Its unlaunched request is `.git/local-ethereum/devex-real-cohort-replay-v3/request.json`. Current before-run phases: complete-cohort geometry-ready305.984s, prefix26.207s, suffix231.014s; these follow initial Geometry construction and are not the duration of Geometry.init itself. Source-v5 gates session11804 wait on the same heavy lock; native campaign remains safely paused.


### 2026-09-08 DevEx detour: final boundary gates pass; corrected full replay running

Source-v5 (`dd88e4828e9ad646b29829bf461fcf2823e197751f364360d3560c9f4f3d7409`) passed all25 focused tests and the full-proof compilation gate. Tests took265ms (ownership5),741ms (small composition3),265ms (prepared boundary8), and274ms (symbolic boundary9); full-proof compilation reported2m /5G MaxRSS. These executed results cover the seven-file validation boundary/getter consolidation. See `evidence/2026-09-08-validation-ownership/consolidated-boundary-executed-gates-v2.json`.

The before replay completed exact source tuple closure for166,400,671 contributions, preparation1795.987s, Tree2 generation170.699s, and producer destruction14.593s. Serialized transport was87,326bytes, final producer allocations zero. Lifetime physical footprint was56,225,850,168bytes; tracked allocation peak74,801,485,871bytes. After the destruction marker, only the frozen test received SIGTERM as planned. This is a producer-half measurement, not a complete replay pass. Full evidence is `evidence/2026-09-08-devex-before-production/before-production-measurement-v1.json`.

The baseline also exposed a separate real codec regression: Zig omits void struct fields, while the local decoder expected explicit null. An isolated run of the existing frozen binary confirmed failure without compilation or real replay. The decoder now accepts exactly the non-void fields, initializes void internally and rejects a supplied void key. Both ordinary and initial transport cases, null/numeric injected void, missing and unknown fields are covered in the cheap ownership gate. It passed6/6 in264ms after17s compilation. The retained original reproducer and corrected receipt are in `evidence/2026-09-08-validation-ownership/`.

Frozen source-v6 (`c6652c850b088bf75ef3fb0d750218b9c99f1fab473b545304c2a1532bbba3c1`) differs from source-v5 only in this replay decoder and its cheap-test wiring. The full real-input replay launched at07:15:12UTC in `.git/local-ethereum/devex-real-cohort-replay-v3`, request SHA-256 `0905cd4d9221279cf9c02ffa59d3b24e14217e7726140d8a66cb26c7bd842836`. All5774 source files and the materialization pin were checked before launch. It must complete producer destruction, independently rebuild every native audit/Tree2 value, compare the full Generated result and pass cold prefix/suffix closure. No measured after-speedup, complete replay, STARK or block acceptance is claimed yet. Native production remains paused; no further source changes are planned ahead of this measurement.


### 2026-09-08 DevEx detour: consuming proof and one-candidate acceptance prepared

The source-v6 real replay remains live. Completed ingress times are85.283s cold opening,151.335s campaign setup and133.828s materialization, each within0.5% of its before measurement. Geometry construction is in progress; one second of sampling shows full source admission through transcript-program derivation and native continuation-sum inversions. This is construction evidence, not a completed phase timing or proof that every remaining audit is redundant. The source-pinned sample and limited interpretation are retained in `evidence/2026-09-08-validation-ownership/after-consolidation-geometry-observation-v1.json`.

The next real segment2 complete-proof request is `.git/local-ethereum/real-wrapper-segment2-devex-v1/request.json` (SHA-256 `dc9fef6647d976c32b8abb6f5ce750795c0721db2d077435706e2c60c3984d03`). All5774 frozen source files and eight durable input/verifier pins were checked. The genuine failing input has been copied and rehashed into its fresh corpus; no proof was launched. The request preserves pair2/3, one worker, fixed-program admission and mapped PCS policy, and requires the current replay's terminal acceptance first.

A separate Python-only extraction makes the controller's leaf-receipt predicate callable by a verification-only operation. The shared boundary now also requires canonical equality between the published leaf record and the exact metadata bytes hashed by the receipt, rejecting extra fields and Boolean/float substitutions. All46 active and38 frozen Python tests pass. Frozen bounded-verifier source-v5 manifest is `e892cf0ba3523ca0afd5bfb6c06f870c3d120d5a17edab7d7affe7775c87538c`. This does not alter the running Zig replay snapshot or CSP/default scheduling.

The pending native19 proof can now be freshly verified and accepted without restarting production or walking leaves0–18. Its prepared command is `.git/local-ethereum/native19-verification-only-v1/command.json`; request SHA-256 `f280392c76c47a860f10a6326a6665ea9d1311eb40b7f0900354b79492f31073`. The operation pins proof, metadata, successful producer, plan, verifier, materialization, policy, source and helper; uses the controller lock, existing bounded lane and shared publication helper; and launches no producer. It remains unlaunched while the controlled replay runs. Accepted inventory remains20 leaves(0–18,120). Evidence is under `evidence/2026-09-08-native19-verification-only/`.


### 2026-09-08 DevEx detour: measured residual ownership work and next frozen revision

The source-v6 producer preparation completed in1623.176s versus1795.987s before: **9.62% less wall time**, not the70% reduction seen in the inner Complete geometry-validation span(305.984s→91.608s). Tuple contributions remained166,400,671; reported peak56,225,833,760bytes is effectively unchanged. Ledger destruction was105.897s versus60.295s, so the inner validation improvement does not equal complete-request savings. Producer serialization/destruction completed with87,326bytes and zero tracked producer allocations; independent cold preparation is running. The phase comparison is `evidence/2026-09-08-validation-ownership/preparation-comparison-v1.json` and is explicitly partial, source-v6 only.

The call trace exposed at least30 full FreshInput/capture validations in Geometry's own program/rows path alone, plus validating child getters. This is the original P0 boundary problem, so the getter revision is not being treated as the finished detour. The exact paths and source-seal fix are retained in `source-seal-admission-v1.json`.

Residual fixes now frozen: schema3 sealing reuses schema2's complete input admission; transcript program and rows finalize their newly generated owned state without repeating source derivation; ChildPublic privately deep-owns public I/O arrays and copies all source/admission values, with a compile-time guard against future shallow pointers; ChildStatement owns its source identity/statement words and local circuit/row state. Full public validation still admits mutable input and compares it with the owned snapshot. Nested mutable witness views retain local checks. Native construction/full validation now explicitly admit the child and statement before reading their metadata. Existing hash domains and identity input ordering are preserved in source; proof verification remains pending. Both child constructors also repair late-error cleanup ownership.

Source-v7 manifest SHA-256 is `6b29fb27217ddf51ac81011e522b04d1715e59aa02bc987f5bed290a14cc4ba8`,5775files,12 changed/added relative to source-v6(including the separately tested Python receipt extraction). Its32-test/full-proof-compile gate is queued behind the live replay: session48892, `.git/local-ethereum/devex-owned-source-boundary-gates-v1.log`. This includes source snapshot mutations, exposed prepared-row mutations, allocation-failure cleanup, schema3 source fixtures, and the existing complete small proofs. Formatting/AST and diff checks passed; no semantic success is claimed for source-v7 yet.

The consuming real segment2 proof request is now `.git/local-ethereum/real-wrapper-segment2-devex-v2/request.json`, SHA-256 `2b87b4bbc58048262ab8380563d0340b8f169753066b455e4d8ce8f4da9351d7`. It supersedes the unlaunched source-v6 wrapper request, uses frozen source-v7, and has its genuine failing input seeded. All5775 source files and eight durable input/verifier pins were rechecked. Require the source-v6 diagnostic replay to finish and source-v7 correctness gates to pass before this actual complete-proof lifecycle. Its preparation/closure timings and independent proof acceptance must validate the new ownership changes; the running source-v6 replay cannot do so. No additional broad redesign or unrelated optimization is queued. Native19's separate verification-only request remains prepared, not launched; block inventory remains20 leaves.


### 2026-09-08 08:27 UTC — complete DevEx baseline accepted; larger preparation refactor

Frozen source-v6 real replay finished exit0, all2 guarded tests passed. Producer serialized87326 bytes and was destroyed; fresh Tree2 exactly matched the entire decoded Generated value, then independent cold closure passed and verifier ownership returned to zero. Producer preparation1623.176s, cold preparation1642.702s, cold Tree2216.934s, cold closure120.658s. Whole command4357.108s including compilation; lifetime peak footprint56226325544 bytes. This is development closure acceptance, not a STARK/wrapper/root proof. Evidence: `evidence/2026-09-08-validation-ownership/replay-v6-accepted-v1.json`.

User authorized larger changes targeting seconds: source-v8 consolidates pending deep-owned source boundaries, direct surviving public sums with canceled-denominator rejection, compact streaming tuple closure, and constructor-local finalization. v7 queued build was confirmed childless and superseded before compilation; no v7 acceptance claimed. v8 compact-ledger5/5 tests passed in5.18s including compile. Direct arithmetic command exposed an incorrect module root, before semantic test execution; adding frontend-root entrypoint. v8 complete boundary/proof compile is running. No speed claim for the new production path yet.

## 2026-09-08: native19 accepted through the bounded verification-only route

After the controlled v6 cohort replay passed, the pinned source-v5 one-candidate operation freshly verified and published native19. Exit0; accepted coverage is now **21/121 leaves (0–19 and120)**. No earlier leaves were re-verified, and no controller or native producer was launched. Request63.780496s, verifier field60.346030s, reported peak1,321,354,800bytes; monitored envelope passed at63.879298s and1,312,998,936bytes peak. These are complete native verifier request measurements, not isolated STARK-kernel timings.

All12 custody prerequisites and16 frozen Python source files were checked before launch, and all pinned prerequisites rehashed unchanged afterward. Source manifest remains `e892cf0ba3523ca0afd5bfb6c06f870c3d120d5a17edab7d7affe7775c87538c`; request remains `f280392c76c47a860f10a6326a6665ea9d1311eb40b7f0900354b79492f31073`. Exact proof, metadata, accepted leaf, verification and scheduling receipts are retained under `evidence/2026-09-08-native19-verification-only/operation-accepted.json` and sibling files. Remaining native production stays paused.


### 2026-09-08 08:41 UTC — preparation gates pass; consuming real wrapper launched

All20 ownership tests pass on frozen source-v11 (f0b4b269026f21062492162828f4a3dfe9b952dc4467aa48744e8b89b27fbd5a). Compact closure7/7 and public-sum arithmetic4/4 pass; small complete composition3/3, prepared boundary8/8, symbolic boundary9/9 and full wrapper compile passed on the same production implementation before test-only corrections. Retained failure logs identify test module-root/discovery and precise expected circuit-error corrections; no failing input was admitted to make a test pass.

The expanded4096-word public-sum fixture measured scalar10.812042ms versus surviving0.395958ms median over3 rounds (27.31x). Setup excluded; this is not a real-block speedup. New closure uses canonical range histograms and canonical hash balances, preserving exact signed counts/provider identity, with no per-contribution record reservation or sort. Geometry construction removes redundant synchronous whole-source audits; external borrowed-source checks remain.

Actual ordinary wrapper2 launched at08:41:42UTC from `.git/local-ethereum/real-wrapper-segment2-devex-v3/request.json`, request fdbb6c7a8cbd6975f1c6e13309e7a8be28507018c6a286792fd9f81d2953b247; all5779 source and8 input/verifier pins rehashed, new corpus seeded and new PCS scratch empty. Supervisor54872/child54873; native production remains paused. This replaces unlaunched devex-v1/v2. Required finish remains guarded3/3 actual proof acceptance, producer destruction, independent root verification, then separate pinned verifier using the trusted admitted key. No new actual wrapper/root accepted yet. Native19 independently accepted via bounded lane: coverage21/121 (0–19,120); no whole-block bundle.


### 2026-09-08 — consuming wrapper closes real tuples with lower setup cost

Actual v11 wrapper test55152 is live (supervisor54872, session20872), now inside CPU Poseidon2 streaming Tree0 commitment; a one-second process sample confirms the active stack. Native cold-open59.920s, campaign67.294s, materialization60.110s. Geometry subphases: admission3.913s, plans/prefix2.590s, program31.911s, transcript rows11.392s, suffix99.688s, manifest projection16.448s, local finalization6.157s.

The new real ledger closes exactly166400671 contributions, matching baseline count. Total ledger ingestion/range/classification/release414.026s→81.030s (80.43% lower); old reserved record capacity43,108,562,464B versus estimated compact retained3,928,074,992B. This estimate includes map metadata per slot but excludes allocator headers/alignment. Peak live map entries14,331,501; capacity80,154,096; range source events only9443, so savings are chiefly generic aggregation/sort removal rather than avoiding millions of range hashes. Suffix-row preparation234.298s→1.949s; Complete geometry entry91.608s→26.240s. Source-phase peak footprint56,225,833,760B→38,002,389,432B is not the final proof peak. Baseline is development replay; after is its consuming actual wrapper on the same real inputs/profile. No complete-request speedup or STARK acceptance claimed. Exact phase evidence: `real-compact-ledger-comparison-v1.json`.

Measured native cold-open sampling also exposed test DebugAllocator growth/free overhead in lifted Merkle verification. Prepared source-v12 moves the existing tracked SMP lifetime before .prove native captures (fresh reconstruction included), and shared lifted verifier now frees only initialized dedup columns and reuses row scratch. OOM/duplicate regressions and all5 core verifier tests are prepared; no semantic claim yet. v12 manifest b7f1e875529734b0a8373b641417d26b6b54ed8021576e6b70a39b9fb4747a9b,5780files,exact3changed/added paths. Gate requests at `.git/local-ethereum/devex-preparation-gates-v12` are NOT launched/queued: current v11 proof and its independent verifier come first, then lifted5/smallcomplete3/nativeABBA. Root verification preparation is `.git/local-ethereum/real-wrapper-segment2-devex-v3/independent-verification-preparation-v1/plan.json`; trust key only from successful admitted-run emission, require expected height0/index2 and exact statement/output custody before existing5case checker.

Milestones unchanged: native21/121 (0–19,120); no whole-block bundle; no newly accepted real wrapper/root. Detour remains active until consuming complete proof acceptance and measured request, then resume native campaign/wrapper3/actual parent.


### 2026-09-08 09:12 UTC — actual wrapper reaches interactions; residual validation confirmed

Frozen v11 test55152 remains live. Tree0 admission completed in536.314s (commit485.293s); the actual proof subsequently filled/committed its preprocessed tree in193.165s. Main allocation27.866s, fill107.618s, commitment188.761s; complete main phase324.245s. Lifetime peak reported40,051,685,088B so far, not a final proof peak.

A retained two-second sample after main commitment shows1503/1633 main-thread samples in Geometry.validatePrepared,1499 through ProgramAuthority.validateAgainstPreparedSource, descending through derive, transcript replay and recorded Poseidon execution validation. This confirms residual P0 ownership work inside the interaction writer; it does not establish the time of the entire interaction phase. Evidence: `evidence/2026-09-08-validation-ownership/wrapper-v11-after-main-observation-v1.json` and associated sample. A bounded ownership audit is checking whether the synchronous engine transaction can avoid these repeated audits without trusting mutable borrowed state. No new production change or job was launched; current proof and independent acceptance retain priority. Native inventory remains21/121; no whole-block bundle or newly accepted real wrapper/root.

Follow-up: interaction generation/closure/commitment completed in265.852s; peak footprint so far42,620,401,128B. The live run has entered the STARK phase. Wrapper3 geometry request is ready against the same v11 source, SHA25681183a236ede6637f5bb653e04d6d72ee6201b897ac8f33fa8d2bf1f1627c6a2; its expected key remains unset until wrapper2 independently accepts. It checks10 wire dimensions, not complete key equality or parent acceptance.

09:17 UTC: a one-second sample confirms actual `proveDiagnosedRetainingFailure → computeCompositionEvaluationSequential → ethereum_transcript_payload_raw_v1.prepareDomainEvaluator`, including column copies/interpolation in `evaluationValues`. This is actual quotient work, distinct from the earlier preparation validation. Raw sample retained as `wrapper-v11-sample-stark-entry.txt`; no new optimization queued from this sample.


### 2026-09-08 09:18 UTC — wrapper2 failed during quotient; low swap confirmed

Frozen v11 actual wrapper2 terminated signal9; execution exit1 after2205.910s including compilation. macOS kernel at13:18:27.395 local explicitly reports low swap and killing largest compressed process55152(test), reported45266MB. Last resource marker was interaction complete265.852s, peak42,620,401,128B; the final sample was actual quotient preparation for ethereum_transcript_payload_raw_v1. Retained exact kernel output, command, request, execution, full log and sample in `evidence/2026-09-08-wrapper2-quotient-memory-failure/failure.json`. No wrapper/root accepted. The build's3/3 tests passed text cannot override signal9 and lifecycle guard failure. No independent candidate verifier or wrapper3 launch is permitted.

Next repair is bounded to this failed wrapper's quotient memory, specifically temporary evaluation column ownership/lifetimes. Do not repeat the unchanged run. Pending v12 lifted verifier/small-composition/native allocator gates released under the existing serial lock. The validation audit found that captured.validate does not deeply validate replay execution; globally removing support.derive's replay check would weaken Program.init and Rows.validate. Sources were left unchanged. A lexical synchronous call alone is not immutable custody over the existing borrowed materialization.


### 2026-09-08 — bounded quotient storage repair and passed v12 gates

Root cause model: row5 payload_raw has37 source columns at trace log24/committed log25/quotient log26. Its owned quotient extensions allocate9,932,111,872B on the ordinary heap before evaluation, plus about256MiB twiddles and then a1GiB output bucket. Row34 uses quotient log23 equal to its committed LDE and borrows454 columns; it does not allocate the same expansion. These are static allocation sizes, not a full peak model.

The repair adds optional execution-only quotient value storage to Scheme→Trace→typed evaluator. Only Ethereum's explicit scratch path selects its existing file-backed owner. Metadata, twiddles and output keep their ordinary allocator; value cleanup retains the matching selected allocator on both success and failure. No changes to polynomial degree checks, recovered coefficients, commitment/transcript identities or CSP policy. New tests exercise exact heap/mapped quotient parity, source immutability, value/metadata allocation failures, and real scheme allocator propagation/default/reset. Source-v13 first gate caught a test constructor missing allocator/try; retained failure and corrected that one test line. Frozen v14 manifest67b81a1cef1d88e2360863d61d072429654c668ecc784f785dc0990d6f4e488d has5780 files; production bytes equal v13. PCS retained, typed quotient and small complete-proof gates are running serially before retry. Evidence: `2026-09-08-wrapper2-quotient-memory-failure/repair-v1.json`.

V12 prerequisites passed: all5 requested lifted-verifier tests plus one imported backend test(6/6), small complete-composition3/3, real native allocator ABBA1/1 with4 samples and exact native identities/zero surviving owners. Testing allocator59.648696/59.447153s versus trackedSMP57.307168/57.144478s; mean reduction3.90%, not an order-of-magnitude gain. The long test process retains lifetime peaks, so these are not independent per-allocator peak measurements. This acceptance does not cover the later quotient source changes.


### 2026-09-08 09:38 UTC — quotient repair gates passed; real wrapper2 retry launched

Frozen v15 PCS retained storage14/14 passed(exit0,16.225s including12s compilation); typed quotient9/9 passed(exit0,14.000s including10s compilation); small complete composition3/3 passed(exit0,23.136s). Gates include selected/default/reset allocator routing through committed scheme→trace, exact mapped/heap quotient parity, source immutability, value/metadata failure cleanup, recovered high-degree rejection, serialized proof-byte parity, destruction and fresh verification. The v14 regression initially read its deferred first commitment before flushing and panicked; the test now resolves that existing deferred operation. Only test corrections separate v13→v15; production storage repair is unchanged. Both failed gate outputs are retained.

Actual wrapper2 retry `.git/local-ethereum/real-wrapper-segment2-devex-v4` launched09:38:46UTC, supervisor58710/child58711, session40903. Source-v15 manifest3583e75812dadd63810e902d2e3565b35240eb7233432e35dec8d6518666a7c4, requestd7d1a1ca8d7e0600a860fff932c3e3885df058403f5a95ac81fc4617e19da117. All5780 files,8 durable input/verifier pins and the new hostile seed rehashed; each required gate's source/request/log/execution pinned in launch-preflight.json. New corpus/scratch, same pair2/3/global2/profile/worker policy, shared heavy lock; native production paused. The actual consuming proof and separate independent root verifier remain required. Native21/121; no whole-block bundle, newly accepted real wrapper, parent or final root.


### 2026-09-08 10:10 UTC — real retry reaches interactions; complete-proof rejection gate extended

Actual source-v15 test58861 remains live; main commitment completed189.565s, whole main phase328.960s. Preprocessed commitment184.385s. A one-second retained sample (`.git/local-ethereum/real-wrapper-segment2-devex-v4/interaction-sample.txt`) shows actual transcript interaction arithmetic, after the entry checks. This does not negate the previously measured repeated upstream validation. A lightweight five-second libproc observer is attached to this same PID with birth-identity checking, recording footprint/RSS/pageins and the last completed phase; its sampled maximum is not the process lifetime peak. No other heavy job was launched and the frozen source remains unchanged. Quotient repair and complete proof acceptance remain unproven until this run completes.

Review of the separate root gate found missing same-proof statement, boundary, position and profile cases. The new Zig exporter derives canonical mutations through shared SpanStatement, NodePublic, fixed-circuit and protocol definitions; it never regenerates the proof. The Python checker now admits an independently pinned five-case fixture manifest tied to the original proof/key/inputs, preserves claims/nonce for node cases, and uses explicitly test-only alternate pins for protocol/circuit cases. Together with the existing genuine and four negative cases this gives ten process cases for an ordinary interior wrapper. It requires the specific semantic rejection for each case; OOM, crashes, timeouts or unrelated admission errors fail the gate. Seven Python process-boundary tests pass in0.139s, including malformed-fixture rejection before starting any process. These use mocked processes, not STARK proofs. Zig exporter semantic compilation/tests and real ten-case execution are still pending the live heavy job; initial/terminal position coverage is not claimed. Existing five-case launch preparation is retained and must be superseded explicitly before claiming the expanded acceptance gate.


### 2026-09-08 10:18 UTC — mapped quotient retry passes previous failing component

Live source-v15 test58861 reached native `qm31_mul_full.runPreparedDomain` during sequential composition evaluation. Component ordering places transcript payload before the native cohort, so this is evidence that the run progressed beyond v11's fatal payload-quotient preparation. It is not acceptance of the entire memory repair or proof. Interaction phase242.082s; latest sampled footprint about40.6GB. Exact sample and source-order reasoning retained in `evidence/2026-09-08-wrapper2-quotient-retry-v4/passed-failing-stage-v1.json`.

Independent rejection tools are frozen separately: exporter source `dc36811033574594f3ded87a3628f1c8a086530bd4c4c163f480044a28ae6281` is v15 plus only the new exporter and nine build-wiring lines; the working transcript ownership refactor is excluded. Checker closure `a940c1d152e3bdc3f10eb461a65a06ccc016c84f1ffc9e48c05e8cb7f7679af6` passes7 process tests using the explicitly pinned Python3.14 interpreter. An unqualified Python from the frozen directory lacked hashlib.file_digest; that environment failure is retained and the launch plan already pins Python3.14. Exporter now rejects unsupported initial/terminal position fixtures before creating output, rather than publishing an incomplete five-case manifest. Zig semantic/build gates remain unlaunched behind the live proof.


### 2026-09-08 10:34 UTC — actual STARK phase completes; fresh verification still running

Source-v15 actual wrapper2 completed the STARK phase in1,053.957s. Reported lifetime peak footprint44,929,895,816B; current footprint31,904,915,840B at phase end. PCS reports83,441,664,000B cumulatively mapped and zero remaining mappings. This passes the previously failing composition/quotient resource stage but does not yet accept the complete wrapper. Native-aware cold verification is rebuilding Generated interactions; a retained sample (`.git/local-ethereum/real-wrapper-segment2-devex-v4/after-stark-sample.txt`) identifies repeated shared Poseidon call-layout hashing under Core.validateCoreReady as another remaining ownership cost. No root candidate or independent acceptance has been claimed.

Working-source transcript change now copies complete verifier plans and pointer-free admission/terminal metadata into the opaque row owner. Operational row checks do not read mutable execution; explicit cold validation still reconstructs it. Complete fill entry points consume this operational route. The retained mutation regression hashes actual row contents before/after, avoiding aliased-view equality; its measured diagnostic time is separated from preparation timing. Semantic tests remain pending behind the current proof. Native migration is independently reviewed and in progress: use a separately owned small input/root/identity projection, eliminate the discarded legacy input-wire calculation only in a distinct native result path, retain full legacy claims and explicit cold audits. Further owner-local call-layout hashing removal is being reviewed against actual custody. Test-only deep-audit counters will report attempted/completed work per replay phase rather than infer it from samples alone.

If the frozen v15 wrapper completes all internal and independent gates, retain it as accepted wrapper2. Subsequent ownership changes require their focused and retained-input gates and an actual consuming proof; advance to compatible wrapper3 on the repaired source rather than regenerate an already accepted wrapper2 solely because preparation changed. Protocol/key compatibility and exact wire geometry must still be checked before that production.

### 2026-09-08 11:14 UTC — cold verification completed; ownership source frozen for tests

Source-v15 test58861 remains live after roughly93 minutes. It retained a3,028,338-byte root proof candidate; candidate existence is not acceptance. Cold cohort reconstruction took865.181s, including534.102s of Tree0 preparation, and the `cold.verify` phase took623.473s. A subsequent two-second sample shows `coldOpenAtTarget → initComponents → validateGenerated → auditPreparedClaims`, dominated by field batch inversion in the transcript interaction audit. This is additional recursive-publication work after the reported verification phase. Retained sample: `.git/local-ethereum/real-wrapper-segment2-devex-v4/after-cold-verify-sample.txt`. Terminal lifecycle guards and the separate verifier remain pending; no new accepted wrapper or block root.

Ownership refactor source-v16 is frozen at manifest `de8de3c8fd4e9347f49389ad48dac8ed748628a66435401250d527254fb35dda`. Native preparation privately owns input/root projections and moves Poseidon call/output allocations into its opaque owner; full cold checks retain source and layout audits. Transcript rows own both verifier schedules and admission metadata. Native interaction generation omits the discarded legacy input-wire calculation while preserving the legacy route. Test-only counters and mutation/parity/allocation-failure checks accompany these changes. None is semantically accepted yet. Prepared gate order is ownership21, small-composition3, complete-proof compilation, then retained real-cohort replay2; `.git/local-ethereum/devex-preparation-gates-v16/plan.json` records the commands.

The separate checker now accepts real key transports up to the verifier's64MiB limit; the candidate's20,912,431-byte key exposed the old16MiB checker limit. Eight mocked-process tests pass; real-proof checks remain pending. Frozen checker-v4 and the five canonical rejection exports are pinned by `post-publication-rejection-plan-v2/plan.json`. README now documents the retained-proof command with serialization, independent key admission, fresh verifier processes and canonical negative cases. These checks precede the v16 gates; no concurrent heavy job has been queued.

### 2026-09-08 11:27 UTC — real wrapper2 complete lifecycle passed

Frozen v15 terminal exit0, guarded3/3 passed,6484.285s including compilation. The exact global2 wrapper serialized, destroyed all producer state, independently verified its root without native inputs, rebuilt and freshly verified the wrapper, passed recursive publication and mutation checks, and ended with zero tracked allocations/bytes/untracked allocations. Trusted terminal ROOT_CANDIDATE emission admits key `0bfb07fadf11dbce2f21c96bc440efec779cf790443aa43eccdcf03db5989357`; proof `0c772d96071c75d5975e779b922319641f450a0c31ce371b20c4da3ecd00e480` is3,028,338B. All5780 source files, original8 input/verifier pins, hostile seed and compiled binary rehashed unchanged. Evidence: `evidence/2026-09-08-wrapper2-complete-lifecycle/result.json`.

The internal detached-root verifier took119.195ms,209.692ms for its complete request. In contrast cold reopening for recursive publication took2074.345s, including865.181s cohort reconstruction,623.473s cold verification and510.401s composition-graph construction. Publication and hostile checks added500.911s. These nested timings must not be summed indiscriminately or called standalone STARK-verifier latency. Peak footprint44,929,895,816B. Separate ten-case verification still pending; no whole-block bundle/parent/root accepted.

One remaining constructor boundary was demonstrated during this run: five generated audits and two temporary Tree2 regenerations inside composition capture. A one-file working repair copies pointer-free replay/admission metadata, keeps one complete numerical admission, and finalizes owned graph state locally; external full validation remains. It is under review and semantically untested, separate from frozen v16. The rejection exporter focused compile caught a comptime branch inferring a nonoptional slice; explicit optional type repairs that line. Failed source1 log is retained and a source2 focused gate is running before any real export. This does not change the accepted proof or its verifier.

### 2026-09-08 — real wrapper2 independently accepted; next consumer unblocked

The separate pinned verifier passed all10 cases in2.166s total: genuine, wrong key pin, changed claim, nonce, proof, canonical statement, boundary, position, protocol and circuit parameter. Genuine verification took110.779ms; verifier request198.666ms; fresh subprocess517.236ms including process startup. It used no native inputs and matched the independently admitted key, exact public coordinate/statement/output and original proof hash. All source, binary, candidate and fixture pins remained unchanged. Exporter source2 guarded1/1 and build passed first; only an explicit optional slice annotation differs from failed source1. Final acceptance is `evidence/2026-09-08-wrapper2-complete-lifecycle/acceptance.json`.

Checkpoint: native21/121, no complete native bundle; accepted real ordinary wrapper2; no actual recursive parent or whole-block root. Next: current ownership gates, segment3 compatible geometry and consuming proof, then their actual parent. Retain accepted2; do not reprove it merely to test preparation changes.

Constructor review caught an important distinction: complete generated validation checks native audit consistency but does not independently regenerate all native audits. The working constructor repair therefore retains one full ingress replay admission on copied inputs, including Tree2 regeneration; it removes only the redundant full exit admission. Revised static reduction is5→3 generated audits and2→1 Tree2 regenerations, not the initially proposed5→1/2→0. The untested shortcut was corrected before any build or proof used it. No protocol hash was duplicated to manufacture a resealed test case. Latest source will receive the unlaunched focused gates; the opt-in constructor parity/rejection diagnostic belongs on its next consuming proof.

### 2026-09-08 11:46 UTC — ownership gates passed; measured real replay launched

Source-v17 ownership compilation exposed two type errors before tests executed: `std.mem.eql` cannot compare M31 structs, and a native/legacy conditional needed its named NativeInteractionClaims result type. Failed7.852s execution and source pins are retained. Source-v18 contains only those fixes across transcript rows and existing outer-module type wiring; its manifest is `e0bb141158bf666065ee78f2739f253324fb4c1becb44ba2472bd13741d24552`.

V18 passed ownership21/21 in59.379s, small complete proofs3/3 in20.953s, and complete wrapper compilation in140.531s. Each gate rehashed all5781 source files and request pins before/after; no runtime failure occurred in these gates. Results: `.git/local-ethereum/devex-preparation-gates-v18/results.json`, SHA256 `89aa60e6fd9a5967ff34a528c0ee64b9c375b418001439187109fda330fc7172`.

Retained real-cohort replay `.git/local-ethereum/devex-real-cohort-replay-v7` launched11:46:50UTC, supervisor67019/serial child67020/session34978. Request `afb1e450e440044b03d7962743361fc84e15879a5dd7f9a2ef7fc4dd28457e37` pins the same real pair2/3, six inputs, profile and worker1. It requires native/legacy numerical parity, source-mutation isolation and cold rejection, actual deep-audit counters, full Generated serialization, producer destruction and exact fresh reconstruction. It does not reprove accepted wrapper2 or claim an additional root. The next actual wrapper3 must exercise the composition-admission diagnostic as well as its complete lifecycle; this cohort replay cannot cover composition capture. No other heavy job is active.

### 2026-09-08 11:54 UTC — real geometry caught input snapshot ordering error

V18 real-cohort replay exited1 after434.441s including compilation,330.106s runtime. It failed with V2CoreCohortMismatch before the suffix preparation marker; native/legacy parity and independent closure were not reached. Source and all input pins remained unchanged. Evidence: `evidence/2026-09-08-prepared-input-row-order/failure.json`.

PreparedInputsV4 copied a prefix of the committed Tree1 value column into its private snapshot. The production ColumnBuffer.scatter writes logical rows at `framework.committedRow`, while snapshot validation and native input generation index logical preprocessing rows. Suffix constructor final validation calls Native.validate→core.validateCoreReady→PreparedInputs.validateSource and rejects that permutation. Two independent source traces matched this path to the observed failing stage; no moved-buffer count/identity discrepancy was found. Repair is limited to gathering logical values through the shared row mapping, with a regression using actual scatter and nontrivial padded geometry. Keep the full cold check that caught it. No retry has run; accepted wrapper2 is unchanged.

### 2026-09-08 12:10 UTC — row-order repair gates passed; real replay retry launched

Frozen source-v19 manifest `e5467995260207c8e168aaf749aec5379fdf2b45ce1c88adf25d5a7688a34499` changes only recursive_fri_outer_part_03.zig from v18. Prepared input values are gathered in logical order through shared `framework.committedRow` into one allocation. The existing ownership/OOM regression now scatters seven unique logical values into a padded16-row production ColumnBuffer, proves a raw-prefix copy is wrong, checks exact gathered values and mutation isolation, and exercises all allocation failures. The existing optional stage diagnostic distinguishes prepared-input-source failures; full cold source validation remains.

V19 gates passed: ownership21/21 in59.216s, small complete proofs3/3 in20.794s, full wrapper compilation134.404s. All5781 source files and request pins remained unchanged before/after every gate. Results SHA256 `a30bfff680ca9fe6bfb6a9a65507586a91dd337c0c5073a097eb0229704cbcf8` in `.git/local-ethereum/devex-preparation-gates-v19/results.json`.

Real-cohort replay v8 launched12:10:00UTC, supervisor67753/serial child67754/session87257. Request `be0071a0aabc301df3e2d3340ccccadc2ed4e6102cbc189abde02c920725d6f4` retains the same six inputs, real pair2/3, profile and worker1. Only the progress destination and existing closure diagnostic environment differ from failed v7. The launch receipt pins prior failure, accepted wrapper2 and all new prerequisite results. Completion still requires guarded2/2, numerical parity, source-mutation checks, producer destruction and exact independent Generated reconstruction. No new proof or speedup is claimed at launch.

### 2026-09-08 — live replay passes repaired preparation and native parity

Source-v19 real replay v8 passed the previous suffix admission failure and closed all166,400,671 lookup contributions. Preparation completed in305.264s including9.461s of mutation diagnostics, versus1623.176s in retained v3 (source-v6):81.19% less elapsed preparation. Peak footprint through preparation was38,002,339,992B versus56,225,833,760B. This compares cumulative v6→v19 changes on the retained pair/profile/worker1, not an isolated-change A/B or a completed replay; cold reconstruction is still pending.

The real native prepared-input regression passed in79.790s. Legacy generation35.424s and native generation32.854s produced identical17 claims, audits, Poseidon partials, public boundaries and Tree2 digest `f6e116e96a4366444cc9bb87286958d383119a0cf14a99c5f18dc08b1776a6d3`. Private input/root reads remained stable under source mutation with no additional deep FRI/PCS audits, full cold validation rejected both source changes, and the active recursion-wire pole was rejected. Tracked live allocation bytes were identical before/after; retained input projection890,372B. The mutation diagnostic's full cold checks are separate from the zero-deep-work operational-read window. No additional wrapper is accepted by this closure test.

Read-only parent-consumer review confirms accepted wrapper2's detached key/inputs/proof bundle is the actual saved-parent input contract; its ten geometry dimensions match the parent. Native-aware wrapper publication artifacts are not consumed there. A bounded root-production mode is being added to share full canonical proof production, mandatory durable root retention, trusted key emission, tracked producer destruction and exact detached verification, then hand the saved bundle to the actual parent. Existing complete-proof/publication diagnostics remain. V15's2074.345s cold reopening and500.911s postprocessing would be excluded from this endpoint (42.92min phase-removal estimate, not a measured speedup). The changed legacy composition-capture constructor still requires its retained-candidate regression; the detached endpoint does not validate that unused constructor.

The next-action decision supersedes that pending constructor validation: restore the legacy capture file byte-for-byte to accepted v15 (`bbb8ec0f49640ab0ea02561a2b526e0cc96a52bed7642033d24c87777d22d64f`) and defer its optional optimization. Its patch and exact required acceptance are retained in `evidence/2026-09-08-deferred-legacy-capture/`. Neither `Proof.proveCanonical` nor the actual detached parent calls that constructor; retaining an unvalidated optimization would impose a45–60+min legacy replay unrelated to the next consuming artifact. No full-check shortcut is retained there and no constructor speedup is claimed. The live frozen v19 replay is unchanged; its active ownership/closure code is unchanged by this restoration. Source-v20 will contain the root helper/build addition and this restoration, with compile and real wrapper3 acceptance still required.

### 2026-09-08 12:30 UTC — real ownership/closure replay accepted

V8 terminated exit0, guarded2/2, all required markers present, all5781 source and six input pins unchanged. The complete Generated publication serialized to87,326B, destroyed the producer owner to zero tracked bytes, rebuilt every claim and audit independently, matched exactly, passed the separate row closure audit, and destroyed the verifier owner to zero. Mutation, pole and native/legacy parity checks passed. This is complete preparation/closure transport acceptance, not an additional STARK wrapper. Evidence: `evidence/2026-09-08-preparation-real-replay-v8/result.json`, SHA256 `00154d30fb2917ad010ee0990b3d33e0832c76a5649ed82650c17dd2d682835d`.

Against v3's same retained pair/profile/worker1, preparation1623.176→305.264s (81.19%), cold preparation1642.702→292.678s (82.18%), Tree2 generation217.860→84.048s (61.42%), complete runtime4253.301→1098.931s (74.16%). Current cold Tree2 regeneration85.094s, cold closure54.036s. Complete request including compilation1204.295s versus4357.108s; compilation remains roughly105s and has not materially improved. Peak footprint56,226,325,544→42,358,046,016B (24.67%). Current runtime includes79.790s of additional real native parity/mutation diagnostics and9.461s transcript mutation diagnostics; these are not production speedup claims. This is cumulative v6→v19 improvement, not an isolated-change or CSP A/B.

Source-v20 manifest `e934e28a8e59eb1a4c7445e548dd939777fd6892778fa4814458d56f73683544` has exactly three changes from v19: root-production helper/build wiring and restoration of the unused legacy capture implementation. The active preparation owners are identical. Next lane: compile `check-ethereum-root-production`, run wrapper3 geometry against the admitted wrapper2 key, then `test-ethereum-root-production` and ten-case fresh acceptance for actual3. Actual parent follows. A separate parent-test-only change now checks canonical state/clock/coverage mutations and derives its hostile parent from a changed saved child source; formatting/AST pass, semantic and actual parent execution remain pending.

Checkpoint: native21/121 accepted, no native block bundle; real ordinary wrapper2 accepted, no wrapper3 or actual parent, no complete block root. The detour's consuming-proof gate remains open until wrapper3 passes on the repaired active preparation route. No native campaign or additional heavy job runs alongside its reserved compilation/proof lane.

### 2026-09-08 12:45 UTC — compatible wrapper3 proof launched

V20 root-production compilation passed exit0 in134.088s,2/2 build steps, no tests executed. Its receipt is `9d3f307c6ea2556420e973e7936ec45f32d6923f64e40a6907af84b25f094238`. Actual global3 geometry v5 then passed guarded2/2 exit0 in416.278s including compilation (334.007s runtime), with30,183,479,712B peak footprint. All ten dimensions match the independently admitted wrapper2 key: commitments4, claims36, sampled values2453, queried values444865, trace paths772, FRI layers6, queries193, fold width16, last-layer coefficients1, maximum Merkle depth25. All source, six inputs, trusted key and prerequisite pins remained unchanged. Geometry receipt `b7a71a6a65068ae42c9b302e0187b1cc133b9d8a0fa9da5931b8ba9fbd9f3220`; evidence retained in `evidence/2026-09-08-wrapper3-geometry-v5/`. Equal dimensions are necessary compatibility, not proof or parent acceptance.

Actual wrapper3 root production launched12:44:55UTC on frozen v20, session98893, supervisor69799/serial child69800/test69809. Request `fd97cb0098014c204ba682cb8ef3d027dac20419c1992863a7420c184f0c129a` in `.git/local-ethereum/real-wrapper-segment3-root-v1/` pins native3/4, global3/pairslot0, all5781 source files, six inputs, the genuine retained label failure, and downstream verifier/exporter/checker. Launch receipt `78b450416e123f22d66d6cbb0f854fa679a1f58dd2ef43665970f21b1a125234` binds accepted compile/geometry/closure evidence. Test binary14,252,776B SHA256 `80f9a8cd1c77315ab22f1f045e03911ba4add3a97948f11a6e7daa6915482a88`.

The root command reuses full canonical proof production, mandatory durable root retention, trusted key emission, tracked producer destruction and exact independent public-input verification. It omits the unused legacy publication replay; that implementation was restored to its accepted version. This job can only reach `lifecycle_passed_pending_fresh_process_checks`; actual wrapper3 acceptance additionally requires the pinned ten-case fresh verifier gate. Its key must come from this successful admitted lifecycle, not reuse wrapper2's key merely because dimensions match. Do not restart the live job on an observation timeout. Next accepted artifact is wrapper3, then their actual parent; no further optimization precedes them.

### 2026-09-08 12:56 UTC — wrapper3 hashing; parent handoff prepared

Actual test69809 remains live. Native reopening39.388s and campaign admission70.562s passed; geometry and exact lookup closure completed with160,647,908 contributions. A one-second sample at12:56UTC (`.git/local-ethereum/real-wrapper-segment3-root-v1/commitment-sample.txt`) found all853 samples under PCS `commitStreamingWithBacking→finalizeBoundedTailRangeReusing`:757 in CPU Poseidon permutation/matrix code and96 in the streaming loop. No validation stack appeared in this window. These are numerical Merkle commitment hashes, not execution of a Poseidon AIR precompile. This bounded sample explains the current wait; it is not an entire-request profile or a reason to interrupt the consuming proof for another optimization.

Frozen parent source-v21 manifest `eb921183d51c32c72c535d6ecce2ab0dd7088cbb8364ca57c845c971567dd14d` differs from v20 only in the parent gate. It includes canonical state/clock/coverage rejection checks, a parent public-input mutation derived from an altered actual child source, and decoding the serialized parent key through the consumer before proving. Formatting/AST pass; semantic and actual parent proof checks remain unexecuted. `.git/local-ethereum/saved-real-parent-v2/sequence-plan.json` prepares parent compilation, a standalone verifier build from this same source, actual2/3 parent production, then separate fresh-process verification. The older verifier binary lacks sufficient source provenance and is not an acceptance dependency. Wrapper3 pins stay unset until its real lifecycle and ten-case gate pass.

The parent currently selects common_fold_field_v2, which does not enable the Ethereum-wrapper retained-column/quotient scratch allocator in the shared engine. Its request must report actual in-memory storage and its existing pre-proof PCS resource plan; setting the wrapper scratch variable would not establish mapped parent storage. No storage change or parent workload has been launched. The prepared wrapper3 `run-independent.py` checks the terminal lifecycle, all original pins, canonical rejection fixtures and exact public fields before creating acceptance; it has only passed syntax/read-only preflight and correctly refuses the still-live producer.

At about13:02UTC, wrapper3 Tree0 completed: CPU PCS commitment471.428s, total Tree0 PCS preparation508.296s. Its15,264,169,984B cumulative temporary file mappings were all released. Lifetime peak footprint at this boundary39,530,618,552B; the actual producer remains live and no root candidate is accepted. Together with the retained sample, this separates the residual numerical commitment cost from the real replay's validated ownership improvement. Continue this same run through proving and fresh acceptance; no hash/backend change is queued ahead of the actual parent.

### 2026-09-08 13:15 UTC — wrapper3 enters final STARK phase

Same actual test69809/session98893 remains live after about30 minutes. Preprocessed phase145.305s; main allocation25.791s, fill91.649s, commitment178.050s, full main phase295.495s. Interaction phase224.002s completed with42,058,478,216B lifetime peak footprint and38,160,823,184B current footprint. The mapped column-storage plan totals47,558,223,488B excluding Merkle/witness/composition storage; this is a storage estimate, not measured physical memory. Native/kernel worker settings are unchanged; process CPU time shows internal parallel work in commitment phases. These are current wrapper3 phase measurements, not an A/B claim against the different wrapper2 input.

No additional proof is accepted at this checkpoint. Native21/121 and wrapper2 acceptance remain unchanged; no native bundle, parent or complete root. Next action after successful terminal lifecycle is the prepared `run-independent.py` ten-case gate, then fill actual wrapper3 pins in the v21 parent request and execute its prepared build/proof/fresh-verification sequence. No other heavy job is running or queued.

### 2026-09-08 — wrapper3 accepted; checkpoint before proving-stack reset

Actual ordinary wrapper3 passed guarded3/3, serialized its root bundle, destroyed all tracked producer allocations, and passed exact detached verification. The separate fresh-process gate passed all10 genuine/tampered cases; acceptance SHA256 f86f60c9225e22fa093bf466c15c752a6c243264867a6fe95b86b480b9bb5538. Complete production request3323.982s; final STARK phase1034.602s; fresh independent verification111.248ms. Peak footprint44,456,659,856bytes. Evidence: `evidence/2026-09-08-wrapper3-complete-lifecycle/`.

Accepted state: Metal native21/121, ordinary wrappers2/3. No complete native block bundle, actual recursive parent, whole-block root or completed current CSP16CPU/Metal A/B promotion gate. Prepared actual-parent request remains unlaunched. Native and recursive production are paused for the user-authorized bounded proving-stack/DevEx reset. This checkpoint preserves working artifacts and incomplete work; it is not a release or a performance-promotion claim. Large proof bundles and frozen build trees remain in `.git/local-ethereum`; committed receipts pin their exact identities.
