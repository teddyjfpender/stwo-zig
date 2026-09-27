# Delivery checkpoint

The active nine-hour goal remains **incomplete**. This turn made implementation
progress; do not mark complete from these subsystem gates.

## Implemented and verified

- `recursion/blake3_stream_frontier.zig`: concrete verified-Node frontier retains
  one subtree per height, requires contiguous same-job slots, checks each folded
  parent against the expected Span, and commits carry-chain ownership only after
  all folds succeed. Explicit verified padding is required.
- `recursion/blake3_stream_prover.zig`: bounded preparation plus persistent
  worker, independent key derivation, same-security-profile child admission,
  consuming source rows, independent verification of each returned parent.
- Worker convenience `proveAdmittedConsuming` now acquires a lease and preserves
  consume-on-all-paths behavior; this also fixes the canonical tree test helper
  that had referenced this missing convenience method.
- Three focused frontier tests pass (`test-frontier-final.log`): padding,
  carry rollback at both merge depths, wrong order/job/returned parent.
- Real four-leaf recursive stream test passes (`test-stream-proof-retry.log`,
  7 tests including imported roots). Uses diagnostic q8/PoW0; this is an
  ownership/cryptographic integration gate, not canonical block qualification.
  The final root remains valid after destroying its persistent worker.

## Real block fixtures restored

Pinned ZisK input downloaded from commit 0887d436 and SHA256 checked:
`e1c6d4e06a87649da68e461a91465e4123b990f531e68581ee1750599ff12376`.
`prepare_block_fixture.py` rebuilt the retained converter and reproduced exact
2,700,688-byte canonical SSZ / 2,700,692-byte runner transport for 66 transactions.
The previous `.git/local-ethereum` artifacts are not present on this host.
Nightly-2026-08-08 plus rust-src installed for reproducible guest compilation.

## Earlier process (completed)

`build_block_guest.py` completed successfully; former unified exec
session **10683**. Log: `build-block-guest.log`. It compiles the pinned host
validator, checks the canonical output hash, builds the RV32 guest and retains
`ethereum-block.elf` plus `block-artifacts.json`. Poll this exact live handle or
inspect authoritative process state; do not restart just because of a timeout.
The script creates expected-output.bin once, so resume a later failed guest
build directly rather than replaying successful host-output creation blindly.

## Next engineering work

Connect a full-guest segmented producer/verifier to the new frontier. Current
`ethereum_auth_benchmark.zig` only supports one segment and a 72-byte synthetic
output. The full validator emits 43 bytes; source/image/input identities and
complete-job endpoint admission must come from real execution, not that harness.
`blake3_segment_statement.initJob` needs first and last endpoints to bind total
segments/cycles. Use bounded preflight/replay or retained segment descriptors;
never retain the entire execution trace. Tree Span folds require equal-height
slots; implement authenticated empty padding for non-power-of-two segment counts.
Then integrate SHA compression and full Ethereum precompile semantics through
CPU dispatch, memory/caller/AIR/lookup and guest providers. Existing SHA candidate
is explicitly inactive, and signer recovery only authenticates successful calls
(not EVM ECRECOVER invalid-result semantics).

## Peer research

ZisK commit 5c5f81c96929abed88894473ec6060b1b545b5c5 available at
`/tmp/stwo-recursion-peer-research-20260921/zisk`.
CuMetal cloned to `/tmp/stwo-cuda-metal-20260924`, commit
`e74b377942f9d2db0f2dde14c5a1b51a9c678692`. README and known-gaps reviewed:
source recompilation supports a tested CUDA subset, not arbitrary CUDA binaries;
cooperative grid sync, inline assembly, pointer semantics and field arithmetic
need per-kernel qualification. No CUDA/Metal port or GPU performance claim yet.

See PLAN.md for the unchanged full completion contract and nine-hour window.


## Second goal turn — authoritative latest checkpoint

This turn made implementation and measurement progress. Full goal remains active.

### Completed

- Full guest rebuilt and host oracle verified; exact hashes in block-artifacts.json.
- `ethereum_block_execution.zig` executes the full 66-tx validator with bounded
  segment-owned traces, strict halt completion and exact oracle comparison.
  Real run: 253,646,998 cycles; 32,835 Keccak; 66 signer recovery; 80.17s process;
  281,571,760-byte process footprint. All recorded in execution*.json/log.
- `runner/balanced_schedule.zig` partitions known cycles into nonempty balanced
  binary leaf counts. This permits exact replay without fabricated empty proofs.
  Does not itself prove execution or admit preflight metadata.
- PUBLIC SUBTREE CUSTODY IS NOW THE SHARED PRODUCTION PATH, not merely proposed.
  `blake3_public_subtrees.zig` derives a gap-free dyadic cover with old/new hashes
  computed from admitted public words. 675,173-word structural test: 17 ranges,
  640 path hashes vs 40,510,380 previously.
  `blake3_public_subtree_path.zig` proves above that public subtree using existing
  typed BLAKE3 AIRs. `blake3_public_subtree_chain.zig` creates sequential range
  roots, validates old subtree, merges sorted edits in linear time, and shares
  private sibling producers across old/new paths.
  Custody, execution-span binding and parent custody append now use new chain.
  `custody.admit` independently recomputes all range hashes from expected public
  words. Its memory-boundary lookup is now binary search over the admitted sorted
  schedule. Generic private-word update chain remains for its distinct use.
- `test-subtree-integration.log`: 222 checks passed including real STARK false-root
  rejection and public-I/O custody admission. Earlier test-subtree-proof.log only
  failed an expected error name, corrected in source and passing integration.
- New canonical 64 authentication recursive proof VERIFIED at 16.6929 GiB process,
  17,823,198,543 worker bytes, 4,291,050,424 retained preparation bytes, 45.6917s
  process, 13.3335s parent. Previous balanced 64 was55.42 GiB and143.31s (earlier
  timing had archive interference). New evidence auth-64-subtrees.*. Same q70/26.
- README.md records new measurements and boundaries. Full goal still unfinished.

### Current live work

`ethereum_block_leaf.zig`: first real full-validator segment proving driver,
q70/PoW26,16 workers,48GiB TOTAL allocator budget, encoded/decoded independent
leaf capture verification. No block-proof claim. Build succeeded (`build-leaf.log`).

First 1,048,576-cycle segment FAILED `CommitmentTraceTooLarge` in witness prep,
4.4s and~0.41GiB. Log first-leaf.log. This is ordinary leaf hash commitment domain
geometry (logs cap24), NOT recursive-parent memory or a proven block.

Smaller 262,144-cycle first segment FAILED `UnclosedExecutionRelations` after
71.85s, at 33,151,315,208 bytes process footprint (30.88 GiB). Session 85393 has
finished; do not poll or describe it as live. Log leaf-262k.log. Partial public
input consumption is an investigation hypothesis, not an established cause.

Follow-up memory qualification: same auth-host binary verified batch16 at
16.14 GiB /36.21s, batch32 at16.82 GiB /41.07s, alongside batch64 at16.69 GiB.
All q70/PoW26; manifests and memory-scaling-summary.json record identities.
Frontier ownership checks through4096 segments passed (26 focused tests total).
These are not cryptographic proofs with4096 leaves. No benchmark remains running.

### Next technical actions

1. Resolve real leaf domain/memory geometry from the running262k proof. If needed,
   report `blake3_commitment_columns.rowCounts` before logsForCounts rejects>24,
   and partition ordinary leaf hash cohorts as done for parent, or size segments
   by measured working set. Do not just raise memory or security limits.
2. Finish full-block segmented producer/verifier using execution preflight and
   balanced schedules. Need compact first/last endpoint summaries to construct
   JobContext without keeping all traces. Current segment_statement.initJob takes
   first/last segments+public data; full first/last roots and app I/O can be retained
   independently. Repeat execution deterministically with the chosen budgets.
3. Persistent stream folder currently returns verified Node, not encoded proof.
   Add retained final artifact/admission/statement delivery, then standalone root
   verification against externally pinned admission. Never trust keys from received
   proof bytes. Existing Node.verifyOwned consumes artifact and transfers allocator
   budget custody to its verified capture; this lifetime is already tested.
4. SHA precompile integration still REQUIRED, untouched so far. Existing fixed-pair
   direct candidate is2162cols/128rows, inactive, no CPU dispatch/memory linkage.
   Prefer compression-level general SHA operation like ZisK; add correct guest,
   typed AIR and authenticated caller/memory linkage. EVM ECRECOVER invalid semantics
   and other Ethereum precompile inventory still required.
5. Program hashing is ALREADY optimized: `blake3_commitment_shared_emit.zig` uses
   admitted `blake3_public_program` fixed rows for full decoded ROM. Do not reinvent
   program hash elimination; the remaining leaf geometry is ordinary memory hashes.
6. GPU/CUDA work remains deferred until CPU closure; CuMetal reference audited only.

Source runtime changes after balanced memory campaign require new keys. The current
subtree path uses existing AIR types but changed fixed data/context IDs; statement
full-memory semantics and q70/26 unchanged. Do not overwrite historical baseline
artifacts or their checksums. Full new campaign archive/checksums still pending.


## Shared partial-input closure and leaf column lifetime

- Confirmed a shared closure bug: ordinary memory omits untouched public-input
  exits, while legacy public compensation emitted every input. New scheduled
  compensation emits only inputs with verifier-admitted final boundaries.
  The native verifier and symbolic recursive composition use the same generic
  arithmetic. It iterates sparse boundaries, avoiding inversions/circuit rows
  for all unread public input words. Public custody continues restoring omitted
  words from independently admitted public input into full continuation roots.
- Admission rejects initial public-input boundaries and clock-zero final input
  boundaries. All base/compact/extension key transcripts bind B3PI version1,
  so old keys/artifacts are not claimed compatible with this closure authority.
- Proof source hash columns are released after fixed/main commitment, interaction
  generation and closure. Typed component metadata and PCS evaluations survive;
  deinit remains safe and attempted source reuse is rejected. Both base and
  extension leaf paths share this lifetime improvement.
- test-partial-input-consuming.log:10 passed, including actual compact proofs
  reading a nonzero/zero input word while leaving the other untouched, independent
  capture verification, symbolic recursive closure, missing-provider residual,
  source release and rejected reuse. The unused-input regression demonstrates
  the old all-input compensation disagrees with the correctly closed sum.
- test-partial-input-before.log is an initial fixture setup failure (InputTooLarge),
  NOT evidence of a cryptographic rejection; fixture symbols were corrected.
  test-partial-input-after.log qualifies the unused-input closure; proof.log
  qualifies partial proofs before adding consuming-column lifetime checks.
- Rebuilding block-leaf-inputfix with build_leaf_inputfix.py (session46540).
  Next run is run_leaf_inputfix.py; historical block-leaf and failed run retained.
  Full block and the remaining efficient SHA/other precompile requirements remain
  unfinished; no completion claim.


Real leaf follow-up SUCCEEDED: leaf-262k-inputfix.json/proof, q70/PoW26,
262144 cycles, independent decode/verify,112.05s process,38.66GiB processpeak,
41550136518 trackedpeak. Session23365 terminalexit0. This establishes the first
real block segment only, not full block proof. Source closure fix is confirmed.

Next memory change releases hash interaction source columns after commitment,
retaining claims for the proof artifact. It is implemented in both leaf paths.
Focused partial proof test running session16139; release binary build queued
session78131. After they pass, run run_leaf_release.py for canonical comparison.


## Leaf interaction storage qualification completed

`leaf-262k-release.*`: canonical first full-validator leaf independently verifies,
262144 cycles,70 queries/26 PoW bits. Process footprint **36.53 GiB**, down from
38.66 GiB after the initial closure fix. Tracked peak39,267,758,574 bytes. Process
wall111.90s, prover67.39s. The proof is byte-for-byte identical to inputfix.proof:
SHA2564095aca10ee204276015887e842413663420b17859c113875e46f152349230d0.

`test-partial-input-release-all.log`:10 focused checks passed with source fixed,
main and interaction column release. `block-leaf-release-source.tar.gz` freezes
all Zig sources used by the direct build; `leaf-release-SHA256SUMS` pins archive,
binary, guest, input, verified proof, report and logs. No heavy jobs remain live:
sessions16139,78131,69553 all completed successfully.

Next scaling implementation is specified in MEMORY-NEXT.md: coupled entry/exit
multiproofs with shared unchanged frontier producers, and only accessed word
lookup boundaries. Current later segments classify the whole initial input as
ordinary memory; shrinking cycle budgets alone does not remove that cost.
This next change is **not implemented**. Full block aggregation and efficient
SHA/other precompile integration also remain unfinished. Goal remains active.


## Paired ordinary-memory multiproof implemented

- `blake3_commitment_witness.build` now schedules word providers only when their
  leaf-local final_clock is nonzero, retaining complete ordinary root snapshots.
- `blake3_commitment_shared_emit` merges the admitted initial/final address union;
  missing public-custody sides get fixed-zero word providers.
- `blake3_shared_path_emit.emitPair` forces both paths onto the same topology and
  frontier source identities. The first side emits private/fixed digest producers
  with doubled fanout; the other side consumes those same words. Host preparation
  additionally rejects changed frontier values early. The wire constraints, not
  that host check, enforce unchanged subtrees inside the proof.
- Empty boundary schedules require equal roots. Commitment plan identity is now
  v5.paired-memory, invalidating old key admission for this new fixed geometry.
- `test-paired-memory.log`:12 focused checks passed. Actual compact resumed proofs
  with16-byte and4096-byte untouched input have identical hash row counts; both
  independently verify and their symbolic recursive closure validates. Changed
  unaccessed memory and changed empty-schedule roots are rejected. Prior partial
  public-input zero/nonzero and source-column consuming checks also pass.
- Driver accepts optional target segment index, freeing prior trace/snapshot
  before resuming. `build-leaf-paired.log` succeeded (session23169 completed).
- Actual four-leaf streaming tree test currently compiling/running session28419.
  Paired block leaf sweep0/1/15/63 queued behind it via session55133; scripts
  test_stream_proof.py and run_paired_scaling.py. Do not start duplicate runs.

Full Ethereum block root, efficient SHA integration and other broader completion
requirements remain unfinished. This is concrete progress, not goal completion.


## Paired memory and ROM cache checkpoint — all jobs terminal

- Paired memory is implemented and actual four-leaf stream root passes7 tests.
  Core/column/census integration passes5 updated tests. Partial/resumed/negative
  proof checks pass12; cache mutation/eviction checks pass2.
- Real262k leaf0 passes35.21GiB/108.80s. Real262k leaf1 fails trace domain cap
  before large allocation; run_paired_scaling stopped there (session55133 exit1).
- Bounded32k windows at globalcycles1,262145,3932161,16515073 all q70/26 verified.
  Footprints9.09/9.09/9.13/1.25GiB; wall43.79/44.40/46.05/38.76s. These are
  sampled windows with unproved warm-up execution, NOT a complete block root.
  run_paired_windows session52333 finishedexit0; paired-window-summary.json records.
- Canonicalauth64 root passes16.74GiB/58.22s (auth-64-paired.*). Earlier45.69s
  subtree run is faster; do not claim a speed win here. Paired missing-side leaves
  currently hash fixed zero words and dense known-zero subtrees unnecessarily.
- Bounded ROM root cache is WIRED into Plan.validate. Cache key includes current
  root and all current leaf bytes; only fully validated keys inserted, no pointers
  or caller-supplied validity flags. Eight entries, mutex-protected, no protocol
  change. Actual first32k window is2.50x faster43.79→17.51s, trackedpeak identical,
  proof byte-for-byte identical. cachetest40038, build16212, run55778 terminalexit0.
- All other build/test/proof handles from this turn are terminal (68927,23169,
  28419,12396,63737,83235,93805). No job remains live.

Next concrete actions:
1. Remove known-zero excluded-side hash work without changing memory roots: mark
   missing-side Input as fixed zero; fold only nodes whose BOTH children are
   computed-known-zero (not frontier nodes), publish required constant digest
   wires. Do not emit now-unused word/bridge providers. By refusing to fold across
   frontier children, both paths continue consuming every shared frontier with
   the current doubled fanout. Census and fixed/live emission must agree; replay
   partial/resumed tests and canonicalauth64 to quantify the actual effect.
2. Core node Frame is108 bytes with44-byte domain header, hence2 BLAKE3
   compressions per internal memory node. A versioned keyed-domain64-byte frame
   could reduce this, but IS NOT IMPLEMENTED and requires explicit keyed hash DAG,
   witness, fixed metadata, domains and full root/protocol qualification. Do not
   remove domain separation or just hash untagged bytes.
3. Finish streamed block driver/root artifact delivery and efficient SHA256
   compression precompile integration; full block root is still unproven. Existing
   Keccak and successful signer recovery remain; invalid EVM recovery and other
   required precompiles remain separate incomplete integration work.

Goal remains active; this turn made concrete implementation and proof progress.


## Known-zero folding and memory priority checkpoint

- Previous pending jobs finished: known-zero dense proofs12passed, assembly5passed,
  saved stream-root artifact test7passed. Canonicalauth64constant verified46.83s,
  18,052,367,832B process peak. See README and auth-64-constant artifacts.
- Current source releases each consumed parent row cohort immediately after its
  interaction generation, rather than retaining all cohorts until the loop ends.
  This changes lifetimes only; borrowed/reusable preparations retain ownership.
  releaseCohort is idempotent; releaseRows safely cleans partially consumed rows.
- build-auth-cohort.log completed successfully (session10588 exit0).
- test-stream-cohort.log: actual four-leaf root and artifact reverification passed
  all7 tests (session10693 exit0).
- Canonical16/32/64 sweep currently running serialized as session79535,
  run_cohort_scaling.py. Do not restart or overwrite existing output artifacts.
- Ownership test queued session6892, test-cohort-storage.log.
- Run summarize_cohort.py after the sweep; it checks verification/security and
  requires the64-transaction proof to remain byte-identical to auth-64-constant.

Immediate user priority remains memory footprint at16and beyond. Full block
proof and SHA integration remain unfinished; goal is active, not complete.


## Cohort checkpoint — all current jobs terminal

- Sweep79535 exit0: canonical16/32/64 verified, process15.75/16.59/16.47GiB;
  worker allocation peaks16.02/16.59/16.60GiB.64proof byte-identical to constant
  baseline. See cohort-scaling-summary.json. No major worker peak improvement.
- Initial ownership test6892 selected0tests. Added focused parent-storage root;
  corrected test9142 passed1actual test. Actual recursive test10693 passed7.
- Source release is production consuming-parent behavior across backends; no
  security profile or proof format change. Known-zero planv6 was earlier change.
- No current build/proof/test remains running. Source snapshot and hashes retained
  as cohort-source.tar.gz and cohort-SHA256SUMS.
- Remaining memory work: later core proving/commitments dominate single-parent
  allocation peaks; stream worker also retains its prior authenticated plan while
  building a replacement to preserve failure atomicity. Measure/design these
  carefully rather than claiming per-cohort freeing solved the entire peak.
- Full block streamed proof driver and efficient SHA integration remain incomplete.
  Active nine-hour goal is not complete; preserve the original full scope.


## Streaming command checkpoint — live jobs, do not restart

Previous goal turn was progress (qualified cohort lifetime changes and memory
scaling). Current turn implemented full bounded preflight/replay/root-delivery
command and compact endpoint claims. Old initJob now delegates to the same endpoint
constructor. Folder.provePrepared handles both leaf and aggregate preparations,
consuming rows on every path and retaining only complete verified root bytes.

Terminal evidence:
- build_stream first failed on runner.result namespace; fixed direct result import.
  build-stream-retry succeeded, session23865 exit0.
- test_stream_endpoints session36406 exit0:8actual tests, including Ethereum
  adjacent segments and endpoint wrong-side/count/program rejection.
- stream-auth1-diagnostic-4096:8leaves,21,635cycles,64.26s flow,4.05GiBtracked,
  saved root decoded/reverified. Session42297 exit0.
- stream-auth1-canonical-16384:2leaves,70.35s flow,19.77GiBtracked,15.53GiBprocess,
  q70/PoW26 through all layers, saved root decoded/reverified. Session10373 exit0.
- execution profiler build72728 exit0; optional PC counts cover all baseinstructions
  and validate count+Keccak+recovery==cycles. Symbolizer retains ELF identity.

CURRENT LIVE JOBS:
1. session76963: run_stream_smoke.py --profile canonical --limit2048,
   run-stream-canonical-16.log and stream-auth1-canonical-2048.*.
   Actual process13504 was confirmed live and loghad2/16leaves proved,
   ~19.14GiBtrackedpeak. This is a real16-leaf cryptographic tree, not16transactions.
   Poll the exact session/process. Do not restart due to observation timeout.
2. session82760: run_execution_profile.py queued under shared build lock behind
   canonical16. Writes execution-profile.*, execution-pc-counts.json. Full actual
   mainnet block execution with oracle verification, not a proof.
   After completion run symbolize_execution.py to produce execution-function-profile.json.

Next: finish/inspect16-leaf proof; inspect actual hotfunctions before deciding SHA/
other-precompile integration priority. Then archive current sources and all terminal
artifacts (do not compress archives during timed proof runs). Latest stream sources
are NOT in the earlier cohort archive. Current binary/source hashes retained in
stream-current-SHA256SUMS; full archive pending terminal runs.

Full block proof and efficient SHA/otherprecompile integration remain incomplete.
Keep the full nine-hour objective active; do not mark complete or blocked.


## Memory/profile/SHA foundation checkpoint — all jobs terminal

This turn is PROGRESS: real16-leaf canonical root verified, entire block profiled,
shared ROM root computation implemented/qualified, SHA semantics consolidated and
verified, direct leaf pairing measured then kept opt-in for memory priority.

Completed:
-76963: canonical16leaf unpaired root:618.47s,19.49GiBtracked,15.33GiBprocess.
  All21,635cycles of complete1transaction guest, q70/26 at every layer; final
  artifact decoded and independently verified. stream-auth1-canonical-2048.*.
-82760: full mainnetblock execution profiling exit0; oracle exact,253,646,998cycles
  fully accounted for. execution-function-profile.json: k25640.85%, memcpy18.96%,
  SHA4.48%. Symbol-entry visits66native txrecover,0supplied-key verify callback,
  12softwareRevm ecrecover. See EVM-RECOVERY-NEXT.md for careful next design.
-33595: generalSHA compression tests2passed; arbitrary chaining states and
  padding-boundary messages match independent standardlibrary. Shared oldpair
  logic now imports it;93409 fixedpairAIR/caller regressions25passed. Production
  SHA remains inactive: no new CPU dispatch, efficient typed AIR or memory linkage.
-65043 root cache3tests passed. Cache MOVED from prover/blake3_program_validation_cache
  to air/program/blake3_root_cache.zig; no duplicate oldfile. Both program build
  and Plan.validate share bounded content-derived results; claimed roots still
  compared.95367 buildexit0.66678 same-binary realblockleaf comparison passed:
  16.57→15.45s,9.19GiBtracked unchanged, proofBYTEIDENTICAL. Env research control
  STWO_RISCV_UNCACHED_PROGRAM_ROOT affects computation reuse only.
-3247 build direct-pair driver exit0;25636 canonical2leafpaired root exit0:
  59.12s vs70.35s oldunpaired, BUT30.52GiBtracked/29.62GiBprocess vs19.77/15.53.
  Exact same complete-execution statement; different legitimate parent key/proof.
-Therefore paired mode is OPT-IN via optional final 'paired' CLI argument.
  One unified driver supports bounded batch1(default) orbatch2. Both preserve every
  independently verified execution proof and all Span/custody checks. Pairmode
  uses existing Pipeline.preparePairOwnedWithPool, so16leaves require15recursive
  proofjobs ratherthan31, but large memorytradeoff forbids claiming a default win.
-75881 built final policybinary;58669 canonical2leaf default regression exit0:
  69.06s,15.53GiBprocess, proofBYTEIDENTICAL to originalunpaired. Current driver
  frees runner snapshots after constructing owning witnesses, before nextsegment.
-Current builds: build_stream_policy.py→block-stream-policy and
  run_stream_policy.py; preserves earlier unpaired/paired binaries/artifacts.
-9713 unpaired sourcearchive finished and exact driver source hash restored.
  New complete sourcearchive/hashes: stream-memory-profile-source.tar.gz and
  stream-memory-profile-SHA256SUMS. No build/test/proof remains running.

Next substantial work:
1. Implement correct EVM recovery acceleration. Success-only native opcode cannot
   represent invalidEVM results. EVM-RECOVERY-NEXT.md details a feasible untrusted
   success-hint bridge (actual successful native result remains proved; software
   fallback preserves invalid and unhinted cases) plus required negative tests.
   No such guest changes have yet been made. Guest SSZ/oracle source stays pinned.
2. Bulkcopy measured19% and efficientSHA measured4.48% remain required; SHA-NEXT.md
   has packed typedAIR direction (not implemented). Do not activate2162column
   fixed-paircandidate as final efficient solution.
3. Fullblock streamed proof has NOT completed. Existing16leafqualification is the
   small authentication guest. Do not conflate16leaves with16transactions.
4. Full original9hour goal inclprecompiles/GPU-readiness stays active, incomplete.

## Immediate memory-priority turn — qualification in progress

User explicitly prioritized memory at16and beyond. EVM collector/native guest
builds finished; host recovery/memcpy tests5passed. Collector execution and native
proof qualification have NOT run. Prior EVM-RECOVERY-NEXT status is stale: bridge
source now exists, but is not yet integration-qualified. Full goal stays active.

Memory baseline instrumentation completed: auth16-memory-stages verifies the
same q70/26 recursive proof. Before core proof16,435,928,547worker bytes live;
composition peak17,196,556,091. Most live storage is retained commitments.

New code, awaiting qualification:
- Native parent plan stores23internalBLAKE3fixed-metadata digests and lengths,
  avoiding persistent duplicate fixed rows. Source rows remain owned by current
  preparation until final interaction reader. Independently admitted fixed
  commitment remains unchanged. Row mutations/lengths still checked.
- Core deep composition splits release obsolete evaluation/pair storage before
  commitment only when chunks own independent coefficient copies. Borrowed
  in-place CPU/Metal coefficient storage stays alive until copies exist.
- Stream folder evicts an incompatible cached worker before creating replacement,
  avoiding overlap of old/new fixed commitments. Same-structure reuse retained.
  General Worker.proveAdmitted retains its existing failure-atomic contract.
- Opt-in STWO_HOST_MEMORY_PROFILE stage snapshots use recognized budget vtable.

Current jobs: final authbuild72459; qualification driver34546 waits under shared
buildlock, then16/32/64authsweep, streambuild, focusedproof/mutationtests, actual
canonical16leafroot. Do not restart or overwrite artifacts. Earlier builds48056
and14092terminalsuccess. Final build was explicitly rerun after correcting
borrowed composition lifetime; only its binary should be measured.

Auth final build72459terminalsuccess.16/32/64qualification allverified,
proofbyteidentical: worker14.5237/15.0952/15.0952GiB, process14.7599/15.5042/
15.3551GiB. Summary andREADMEupdated. Timing~2sregression, notspeedwin.
Qualification34546nowstreambuild/testphase; compositionownershiptest88915queued.
StreamsourcealsoevictsobsoleteworkerBEFOREderiveKey, because keyderivation
constructsatemporaryfixedcommitmenttoo. run_stream_memory_lifetimes.py rebuilds
finalsourcesagainbeforetimedrun; do not use initialstreambinaryforclaim.

## Memory lifetime checkpoint — all jobs terminal

This is verified progress on the active goal, not completion of the full block
proving system. The user's immediate memory priority was measured at 16/32/64
transaction authentications and in a complete 16-leaf recursive tree.

- Qualification driver 34546 exited successfully. Final stream binary was rebuilt
  after the pre-key-derivation eviction change; all subsequent runs use it.
- Auth worker peaks: 16.02/16.59/16.60 → 14.52/15.10/15.10 GiB.
  Physical process peaks: 14.76/15.50/15.36 GiB. All three q70/PoW26 proofs
  independently verify and are byte-identical to earlier cohort baselines.
- Complete canonical 16-leaf stream: tracked peak 19.49 → 18.06 GiB;
  physical peak 15.33 → 14.40 GiB; time 618.47 → 678.91 s.
  Saved root decoded and independently verified, byte-identical to old root.
  This proves all 21,635 cycles of the one-transaction authentication guest;
  it is not a full Ethereum block proof.
- Focused recursive integration test passes, including changed/truncated fixed
  metadata rejection and verification after worker destruction. The separate
  composition ownership test (88915, exit0) passes every allocation failure.
- Formatting checks passed for all five changed production/test Zig files.
- Artifacts: memory-lifetimes-summary.json, stream-lifetimes-summary.json,
  memory-lifetimes-source-overlay.tar.gz, memory-lifetimes-SHA256SUMS.json.
  Overlay applies to stream-memory-profile-source.tar.gz plus the archived guest
  base. Current Rust guest sources are included; their integration remains pending.
- No build, proof, or test from this turn remains running.

The retained commitment floor is still substantial: these changes do not claim
minimum possible memory. See MEMORY-LIFETIMES.md for ownership and remaining
representation/AIR-width bottlenecks. There is a measured timing regression,
not a speed improvement. Full block proof, production SHA integration, new EVM
collector execution/native qualification, and GPU work remain incomplete.
Continue the original nine-hour goal; do not mark complete or blocked.


## EVM execution and real recovery leaf checkpoint — all jobs terminal

This goal turn is verified progress. The full objective remains incomplete.

- Collector78320 exit0: all66transactions execute and exact43byteoracle matches.
  It observed12successfulEVMrecoveries and wrote the untrusted STWECR01footer.
- Fastguestbuild59834 exit0; variants44995 exit0. NativeEVM alone reduced cycles
  253,646,998→141,105,392; native+memcpy139,213,662. Both exactoracleverified.
- Corrected memcpy's C ABI to c_void pointers, eliminating runtime-symbol lint.
  Finalbuild94735 and finalexecution71686 exit0. Finalguest139,213,662cycles,
  39.92sexecution,32,835Keccak and78native recovery calls (66tx+12EVM).
  This is execution, not full block proving. ELFsymbolcheck confirms replacement
  of compiler-builtins memcpy; shared implementation uses normal RV32 operations.
- Recoverylocationsbuild83023/run30578 exit0. The first EVM native call (ordinal67)
  is at globalcycle55,074,081; canonical32kproofwindow is segment1680.
- Leafbuild84141/run87996 exit0: real segment1680proved, encoded/decoded and
  independently verified at q70/PoW26. Contains1recovery+7Keccak;3.83GiBtracked
  peak. Replay83.87s, witness5.72s, proving5.78s. This is NOT a complete block.
- New execution instrumentation reports optional native call locations via
  STWO_ETHEREUM_RECOVERY_LOCATIONS. Leafreport includes precompile call counts.
- No job from this turn remains running. Canonical SSZ prefix and43byteoutput
  remain pinned; augmentedtransportinput and eachELF have manifests.

Next required work: recursive admission/wrapping of the real accelerated EVM
segment, then efficient production SHA compression AIR/dispatch/memory/caller
integration. Full block root and GPU qualification remain undone. Existing SHA
semantic module tests passed previously, but production precompile is inactive.
Do not mark the original nine-hour goal complete or blocked.


## Recursive capture / packed SHA checkpoint — all jobs terminal

Verified progress; full nine-hour objective remains active and incomplete.

- New generic research helper blake3_recursive_capture_qualification.zig accepts
  an independently admitted canonical execution capture, prepares bounded parent
  rows, proves with a bounded worker, destroys worker, encodes/decodes and verifies.
  It explicitly reports span_custody_attached=false and block_verified=false.
  ethereum_block_leaf optional ninth arg 'recursive' invokes it. Scoped pool
  bindings are released/reacquired explicitly; no nested binding remains.
- Initial build70477 and final build71978 succeeded. Final run85127 exited0:
  real EVM segment1680, one recovery/sevenKeccak, child q70/26 and parent q70/26.
  Parent preparation11.25s, proving16.30s, worker14.38GiB; artifact983225bytes.
  See evm-recursive-summary.json. This is recursive capture qualification, not
  a complete block or a new Span-custody-root qualification.
- New SHA word author, packed typed arithmetic and witness writer, tests and root.
  Arithmetic geometries164/88/16 columns; direct constraints40/28/4; lookup events
  126/60/8. Build validates pinned geometry and semantic digest. Production=false.
- SHA initial test94851 and diagnostic5140 failed an over-strong mutation test:
  c bits masked by Maj may change while preserving outputs. No arithmetic equation
  was weakened. Corrected accepted-input tests against scalar expected outputs;
  all scratch modifications and byte-range violations still reject.
- Qualified90006, pinned44708 and final actual-table-membership2465 all exited0.
  Final log test-sha-packed-tables.log has2substantive tests, including full
  compression round/expansion coverage. No SHA STARK/dispatch claim yet.
- Formatting passed. No current build/proof/test remains running.

Next large engineering step: complete SHA graph/constant/state/message wiring,
then CPU/memory/caller integration with the canonical profile and guest provider.
Full block root and GPU/CuMetal work remain unfinished. Preserve original goal.
For subsequent real-window qualifications use larger warmup strides where the
same global start is divisible (55,050,240 =105*524,288), to avoid the slow1680
small-snapshot replay loop. Existing invocation manifests record exact old runs.


## Active memory priority: wider lookup experiment

SHA compression graph and canonical standalone SHA STARK passed; CPU/memory
SHA dispatch remains inactive. User immediately prioritizes memory at16andabove.
The batch-four experiment halves BLAKE3 G interaction width80to40; direct AIR
and byte/range/wire semantics remain unchanged. Initial full proof and small
compression rejected ConstraintsNotSatisfied. A two-event control with enlarged
quotient domain also failed. The cause is heterogeneous quotient geometry:
all proof components need a common composition split and polynomial extension
of the smaller quotient domains. Using the existing reviewed q1-to-q2 handle
extension on both prover and verifier passed the small compression STARK.
This is not yet an accepted large-memory result. Native parent normalized build
is underway. No full-block or GPU qualification is claimed.


Memory experiment checkpoint: the execution leaf retains its qualified two-event
G layout. blake3_g_call_wide.zig reuses that exact arithmetic/witness author for
a four-event recursive-parent layout. Parent-only normalization passed a real
canonical16tx proof (57.76s,29,783,152,680workerbytes), but eager quotient
preparation retained all four enlarged G evaluation slabs simultaneously.

A general CpuCompositionPreparation.streamed policy now prepares, executes,
joins and releases one component at a time; each component can still use the
bounded worker pool. The same power schedule and q1-to-q2 interpolation are
preserved. Canonical16tx passed at58.31s,18,000,079,016workerbytes; proof bytes
are identical to eager wide layout. This is still above the previous15.59GB
worker peak and is not yet accepted as an overall memory improvement.

10focused prepared-composition tests passed, including1/2/4workers, exact powers,
finite budgets, live preparation count4to1, every allocation failure, execution
failure cleanup, and existing eager scheduling regression cases. 3wide-layout
focused tests also passed. The eight-shard candidate is currently measuring.

## Coefficient residency experiment

Restored the cubic/four-G-shard roster after wide batching saved little memory and slowed proving. Streamed preparation alone preserved the 16-transaction proof (40.30s, 15,594,615,680 worker bytes).

Implemented coefficient-backed host PCS storage: compact after commitment; expand one component for AIR evaluation; fold native coefficients before DEEP quotient FFT; regenerate one column at a time for queried Merkle leaf blocks. First canonical 16/32 transaction proofs verify and match previous proof hashes exactly. See `coefficient-storage-first-summary.json`. Stage profiling places the remaining peak in interaction commitment (both coefficient and LDE sets coexist before hashing).

Next experiment hashes every incoming column batch before freeing its LDE. A capped Merkle-only BLAKE3 state retains four CVs instead of the general hash's 54, while reusing standard BLAKE3 update/finalization. Full leaf byte lengths are preflighted; the general hash function is unchanged. Eight focused tests pass, including every admitted width, exact roots/openings, quotient equality, shared storage, and allocation-failure cleanup. Canonical benchmark qualification is pending. Feature remains opt-in.

## Compact storage and assembly lifetime qualification

Coefficient-backed storage, incremental BLAKE3 commitment, coset composition, and bounded parallel opening batches passed 16/32/64-transaction canonical proof equality. Worker peaks are 9.281/9.584/9.584 GiB; totals 43.534/48.021/54.043s. The 16-transaction reference is 14.524GiB /40.012s.

Releasing independent fusion scratch before column projection reduced the 16-transaction process peak from 13,812,495,008 to 11,570,735,880 bytes, preserving the proof. The next candidate finishes direct cohorts before lowering, releases copied execution transcript/path sources, and applies the same ownership path to recursive aggregation nodes. CPU native-parent polynomial residency is now the default; the explicit materialized flag is a research oracle. Canonical transaction and complete 16/32-leaf qualification are queued/running. See MEMORY-POLYNOMIALS.md and per-run artifacts; no deeper result is claimed yet.

## Full 16-leaf qualification and 32-leaf boundary correction

The complete 16-leaf/31-recursive-job authentication proof verifies and is byte-identical to the prior root. Tracked peak 19,389,625,682 -> 10,834,475,354 bytes; physical peak 15,461,261,384 -> 9,988,894,080 bytes; total 678.914 -> 794.598s. See assembly-release-tree16-summary.json.

The 32-leaf attempt initially failed in counting preflight with OutputAddressNotAccessed (0.02s, before any proof). Counting chunks need not match final proof boundaries. Added execution-only output-access collection, application I/O claim hashing with structural validation, and terminal-aware bounded scheduling. Strict proof replay keeps all output access-clock checks. The actual guest passes strict replay at 16 and32leaves; publication needs349cycles, versus final leaves1352/676. The32-leaf full proof is running with the corrected preflight. New scheduler/output-shape tests pass; the tiny replay fixture is being corrected to use the same release-ABI halt setting as production. A final test rerun is queued behind the timed proof.

## Memory scaling qualified: 16 and 32 actual leaves

The full 32-leaf/63-recursive-job tree freshly verifies at canonical q70/26. Tracked peak 10,835,151,220 bytes (10.091 GiB), physical peak 9,955,517,688 bytes (9.272 GiB), total 1562.102575916s. The complete execution identity matches the 16-leaf run; tracked peak increases only 675,866 bytes /0.00624% for the extra level. The 16-leaf baseline comparison remains a 44.1% tracked and35.4% physical memory reduction, with17.0% more CPU time. These are single CPU qualification observations, not medians or full block/GPU results.

Terminal/public-data regression gate: all15tests passed in test-terminal-planning-5.log. The last fixture repair supplied the actual declared program and memory roots before calling the fully validating output identity function; production runtime code was unchanged. Strict execution replay at64leaves also passed with a349-cycle final leaf; this is not a64-leaf proof. Final report: MEMORY-POLYNOMIALS.md; reproducible artifact checks: summarize_memory_scaling.py; structured results: memory-scaling-qualified-summary.json. Final source archive and manifest preserve provenance. No full test-suite rerun or further proof rerun was needed after test-only edits.

## SHA native transaction and typed memory caller

Provider emission now owns only four final batch arrays and uses no per-round heap scratch. Canonical compression proof and all allocation failures passed (test-sha-provider-1.log). The two-pointer native compression transaction, full typed caller/memory/SHA graph closure, upper address boundary and prior typed memory/retirement compatibility pass all 17 focused tests (test-sha-memory-12.log). See SHA-MEMORY.md for exact scope. Production remains inactive: the universal component compiler must support the closed machine expressions and program-bound PC before roster/profile/guest activation. No full block or new SHA VM proof is claimed.

## 64-leaf memory qualification underway

The canonical 64-leaf / 127-job tree was launched on AC power using the pinned terminal-planning binary, with the same fixture and security parameters as 16/32 leaves. Terminal replay reserves 349 cycles. Results remain pending in stream-terminal-planning-auth1-canonical-512.*; no 64-leaf proof or peak claim is made until completion. Run summarize_memory_scaling.py --include-64 after success; it requires exact leaf counts, verified roots, matching complete statements and proof artifact hashes. Existing 16/32 artifacts were revalidated successfully.

## SHA shared compiler proof checkpoint

Closed machine-expression compilation and program-bound PC admission passed all 18 focused tests. The standalone canonical SHA memory-call STARK freshly verified in 30.576s (test-sha-memory-stark-2.log), including a changed public output boundary rejection. Production SHA dispatch remains inactive; profile/session/leaf roster/guest integration is still required. See SHA-MEMORY.md. This source postdates the saved memory qualification binary.

## SHA tape/preprocessing integration candidate (validation queued)

The reusable five-cohort SHA row owner now reads the native execution tape directly, validates instruction/register/clock agreement and owns exactly five final row arrays. Provider emission accepts a borrowed view, avoiding a second call-record array. Independent preprocessing emits final fixed columns from a single compression topology instead of allocating full placeholder witness rows. The canonical compression and memory-call proof fixtures now use this path.

SHA relation binding preserves shared VM program/state/memory/range challenges but draws a distinct internal wire challenge after the main commitment. This avoids sharing BLAKE3 internal wire namespaces when the components are joined. The memory-call proof gate replays that draw on prover and verifier. Program-bound PC admission also follows derived expressions transitively; new negative tests cover wrong/duplicate PC declarations and malformed retirement liveness.

These edits are not yet qualified. test-sha-memory-stark-3.log, test-sha-provider-2.log and test-sha-compiler-5.log are queued behind the complete 64-leaf measurement. At 03:40 UTC its live process 45200 had finished 16/64 leaves, retained one frontier node and observed 10,639,480,840 tracked bytes. This is an intermediate peak, not the final result. Production SHA profile/session/guest activation remains outstanding.

The SHA candidate now also supports zero-call segments with inactive padded cohorts. Its canonical memory-call fixture invokes the native recorded-clock transaction, checks exact memory/PC/retirement results, and proves the resulting tape. Candidate source archive and unqualified status are preserved in sha-memory-integration-candidate.json.

## Guest SHA framing and canonical component profile (queued qualification)

Added autoresearch/benchmarks/guest_runtime/sha256_precompile_v1.rs: allocation-free full-message SHA-256 framing, direct aligned input blocks, one four-byte-aligned scratch block for unaligned input/padding, and an explicitly selected RV32 native instruction at 0x0c62800b (t0/t1). The pattern follows pinned ZisK ziskos/entrypoint/src/zisklib/lib/sha256.rs while retaining our two-pointer/four-byte ABI. It does not activate a legacy ELF profile or replace the Ethereum guest's default SHA implementation yet.

The dedicated host crate checks every length 0..130, larger block boundaries, eight alignments, exact call counts/direct-buffer reuse, standard messages and a million-byte input against sha2 0.10.9. test_sha_guest.py also compiles the native RV32 library and checks emitted instruction sites. This gate is queued behind the 64-leaf run; no result is claimed yet (test-sha-guest-1.log).

sha256_component_profile.zig now owns the five-component geometry/order and semantic identities; the row owner and preprocessing share it. The memory-call proof transcript binds the canonical profile and uses protocol format 2 for the isolated SHA wire draw. New profile tests reject modified geometry/identity and placement overflow. Zero-call checks evaluate all five AIRs and require every nonzero padding request to belong to a valid shared lookup table. These latest changes postdate sha-memory-integration-candidate-source.tar.gz and remain unqualified pending the queued gates.

At 03:59 UTC the live complete-tree process had reached 39/64 leaves with tracked peak 10,640,925,735 bytes. The host remained on AC power.

## Complete 64-leaf root qualified

The 64-leaf/127-job canonical tree completed and its root freshly verified. Tracked peak 10,835,361,718 bytes, physical peak 9,962,792,544 bytes, total 3137.641386333s. Root SHA-256 8283d466fa752e00de4490f53c0b85212c0ace28a28ce3f095edfcf58c2f42cb. Artifact validator confirmed canonical q70/26, exit zero, proof bytes/hash, exact expected leaf/job counts, and matching complete execution statement/ELF/input/output versus 16/32 leaves. Tracked peak growth is 886,364 bytes /0.00818% from 16 leaves. Full result is now recorded in MEMORY-POLYNOMIALS.md, README.md and memory-scaling-qualified-summary.json. The saved binary predates current SHA/compiler source.

## Qualified SHA integration foundation (2026-09-25)

The current focused gates pass: 11 memory-call/provider tests, 19 shared compiler
and typed-effect tests, six compression/provider tests, and three Rust guest
framing tests. The memory-call STARK freshly verifies at canonical q70/26 in
25.513 seconds; the compression STARK verifies in 4.856 seconds. These are single
qualification observations, not comparable end-to-end guest benchmarks.
Evidence: `test-sha-memory-stark-3.log`, `test-sha-compiler-5.log`,
`test-sha-provider-2.log`, and `test-sha-guest-2.log`.

The provider borrows native execution tape and owns only five final row arrays.
Independent preprocessing emits final fixed columns directly, removing full
placeholder witness arrays: at 64 calls, 4,993,024 placeholder bytes disappear
and 632,832 fixed-value bytes remain. This is an 8.89x reduction in those value
buffers, not in whole-prover memory. Allocation-failure and zero-call padding
checks pass. Lookup registration validates before mutation; verifier-derived
multiplicity bounds count 26 memory accesses per polarity per SHA call, with
23 extra accesses beyond the native retirement allowance. SHA internal wires
use independent transcript challenges while retaining shared VM memory and
lookup buses. A canonical component profile binds geometry and semantic digests;
a shared component owner keeps relation challenges alive after AST teardown.

The Rust SDK implements complete SHA-256 framing with aligned direct block reads
and bounded scratch. Host checks cover padding/alignment boundaries, standard
vectors and a million-byte input against the independent sha2 implementation.
The RV32 build emits the exact instruction 0x0c62800b; see
`sha-guest-qualification.json`. This qualifies framing and ABI compilation,
not a production guest execution or proof.

Production SHA dispatch remains inactive. Combined profile/program admission,
session tape plumbing, production leaf roster/admission and guest-provider
activation still require integration and a fresh recursive guest proof. The
memory-scaling measurements use the separately archived earlier binary; they do
not measure the current SHA/compiler source snapshot.

## Combined SHA execution session (2026-09-25)

`runner/guest_precompile/ethereum_sha.zig` now owns Keccak, recovery and SHA tapes
with checked aggregate counts and one external-retirement origin. The existing
Ethereum dispatcher delegates through an aggregate-count entry point; its old
profile behavior is preserved. The combined session enforces one total call
budget before mutation. It remains outside ELF admission pending the matching
production proof roster.

The native-call input to the canonical standalone SHA STARK now executes through
this combined session. It freshly verified at q70/26 in 24.772 seconds (single
observation, `test-sha-memory-stark-4.log`, all 11 selected tests passed).
`test-sha-combined-session-3.log` passes the SHA → Keccak → SHA sequence,
including shared memory-clock transitions, rejecting stale per-tape retirement
counts without mutation, rejecting total-budget overflow and releasing every
injected allocation failure. The first stricter test expected the wrong error
name; the trace correctly returns ProfileClockCountMismatch. No runtime change
was needed for that expectation correction.

This is execution-session integration and a standalone proof, not yet an
admitted SHA guest or a combined SHA/Keccak production leaf proof. Next: connect
combined session ownership to segmented results, declared-program admission and
the production leaf witness/statement, then qualify recursive guest proving.

## Combined ownership, admission and transcript integration

The SHA tape now freezes without allocation or copying. The combined session
validates cumulative trace counts minus the segment origin before moving any
of its five tape buffers; an invalid count leaves all ownership unchanged.
`EthereumShaSegmentResult` supplies the owned segment wrapper for subsequent
session plumbing. The canonical standalone SHA proof now consumes frozen tape
records. `test-sha-memory-stark-5.log` passes all 14 selected tests, including
mixed SHA/Keccak execution, allocation failures, frozen-pointer identity and
combined challenge replay. The q70/26 memory-call proof verifies in 24.896s
(single observation).

Combined verifier admission adds SHA's exact public fixed-table bounds and
23 additional memory terms per call, and validates the aggregate native external
retirement count. Zero-call SHA cohorts still contribute fixed padding demand.
The existing Ethereum admission path retains its previous bounds and identity.
The new `blake3_ethereum_sha_statement.zig` binds the Ethereum manifest, canonical
SHA component profile and combined certificate under the distinct B3ES/version-1
transcript frame. Altered SHA semantics and memory bounds are rejected.
`test-sha-combined-admission-2.log` passes all nine selected tests through the
existing Ethereum witness census, including zero/nonzero SHA admission deltas,
wrong aggregate counts and transcript separation. This is statement/admission
qualification, not a combined production proof.

`ethereum_sha_relations.zig` draws the existing 26 Ethereum challenges followed
by SHA's framed independent wire pair, retaining exactly the shared native VM
buses. Capture/replay and prover/verifier transcript agreement pass. The focused
admission script now delegates to the common SHA Zig harness rather than copying
its build command.

Remaining production work: connect the new owned result to segmented execution,
add the declared SHA-capable executable identity and program fetch authority,
join the SHA witness/interactions/components with the Ethereum leaf pipeline,
encode/decode the combined proof artifact, activate the guest SHA provider,
and freshly verify the resulting guest through recursion. Full Ethereum-block
root and GPU qualification also remain outstanding.

## SHA-capable ELF and segmented execution qualification

The explicit `rv32im-zkvm-ethereum-sha-v1` profile now uses ELF profile ID 4,
capability bits 14 and ABI version 1. Its execution semantic identity is the
SHA-256 of `riscv.ethereum.keccakf_1600.secp256k1_recover.sha256_compress.v1`.
Prior profile IDs, metadata and decoding remain unchanged. The shared CUSTOM-0
decoder admits both SHA pointer registers; declared and fetched program words
project to `{50, 0, rs1, rs2}`, matching the typed SHA caller. Old Ethereum
execution still rejects SHA. Wrong capabilities, ABI and digest are rejected
before loading. The old unknown-profile test now uses 0xffff because ID 4 has
an assigned identity.

The canonical ExecutionSession now selects the combined SHA state and returns
owned SHA-capable segment/run results. A seven-instruction ELF executes
SHA → Keccak → SHA through both global and leaf-local segmented clocks and the
same one-shot loop. The first segment is freed before resuming. Segment freezing
uses the extracted trace's local count; cumulative freezing remains a separate
entry point. This fixes the observed double-subtraction of the prior external
origin. Leaf-local tests explicitly select segment-owned trace retention, as
required by the existing bounded-memory session contract. Diagnostics has a
third external family for SHA; the old Ethereum minimal replay path explicitly
rejects the new opcode.

`test-sha-profile-5.log`: all 20 focused tests pass, covering the new admission,
all 1024 SHA operand pairs, both segmented clock modes, one-shot execution,
legacy rejection, mixed-session ownership/allocation failures, existing ELF
malformation/truncation tests and old CUSTOM-0/profile identities.
`test-sha-profile-regression-1.log` also passes the existing nine-test Ethereum
witness/admission census after introducing the profile.

Execution admission is now enabled for this explicit profile. End-to-end proof
activation remains incomplete: wire frozen SHA records into the combined native
leaf witness/program fetch census, register shared lookup demand before table
commitment, append SHA interactions/components and proof artifact encoding, and
qualify the admitted guest through recursion. The full Rust SHA SDK framing is
qualified separately; its Ethereum guest provider selection remains pending.
The earlier standalone SHA memory-call proof is not evidence of this combined
production guest proof. Full Ethereum-block root and GPU qualification remain
outstanding.


## Combined SHA witness and profile-aware boundary qualification

The shared Ethereum witness owner now supports the explicit SHA profile without
forking native trace construction. SHA records contribute program fetches,
external retirement counts, shared lookup demand and five owned AIR row arrays.
Lookup demand is registered before fixed tables are committed. Cross-family
retirement clocks cannot alias. Interaction columns retain their actual backing
blocks; cleanup no longer attempts to free individual column views.

`test-sha-combined-witness-5.log`: all 11 focused tests passed. The complete
SHA → Keccak → SHA execution and both leaf-local segments close all shared LogUp
relations, including a segment with no Keccak calls. The first segment is released
before resuming. Allocation-failure cleanup is qualified. These checks are
witness/relation evidence, not a combined SHA production STARK.

This exposed a general segment boundary issue: public program compensation used
the base ISA decoder even when the next, unexecuted instruction was an admitted
precompile. Public compensation now accepts the execution profile; native leaf
assembly, prepared verification and the recursive composition recorder supply
their authenticated protocol's profile. Legacy base entry points retain their
base semantics.

`test-precompile-boundary-root-2.log`: all 8 tests passed. Two real Ethereum
segments split immediately before Keccak were proved, recursively aggregated,
serialized and independently verified with full memory custody after releasing
witnesses and the worker. This development gate uses **8 queries / 0 PoW bits**;
it is not canonical performance evidence. Root artifact: 156,037 bytes; tracked
worker peak: 4,775,791,376 bytes. The initial `-1.log` selected the wrong test root
and ran only two import tests; it is explicitly not qualification evidence.

Remaining SHA production work: append SHA components and claims to the canonical
leaf assembly/artifact, verify that artifact, wire the combined recursive capture,
and activate the Ethereum guest SDK provider. Full block root qualification is
still outstanding. The current full-block guest uses ordinary RV32 memory-copy
instructions and the existing Ethereum profile; it does not require the private
bulk-memory candidate opcode.


## Qualified stage measurement check

The new CPU measurement path passed on the existing authentication fixture:
21,635 executed cycles, one execution leaf and its recursive wrapper, canonical
70 queries / 26 PoW bits, AC power before and after. This is **not a full Ethereum
block benchmark**. The root was freshly verified and every workload/artifact
hash matched the invocation.

| Metric | Measurement |
| --- | ---: |
| Process wall | 41.912504 s |
| Prover pipeline | 41.205360 s |
| Tracked allocation peak | 10,010,117,687 bytes (9.323 GiB) |
| OS physical footprint peak | 10,138,544,520 bytes (9.442 GiB) |
| Proof size | 981,446 bytes |

| Stage | Wall time |
| --- | ---: |
| preflight | 0.009538 s |
| replay execution | 0.003700 s |
| witness preparation | 1.512627 s |
| verifier preparation | 0.669343 s |
| leaf proof and recursive witness | 17.040524 s |
| recursive proving and aggregation | 21.952648 s |
| final root verification | 0.015759 s |

Evidence: [measurement.json](measurements-auth1-canonical-stages/measurement.json),
[proof report](measurements-auth1-canonical-stages/proof-report.json), and
[process log](measurements-auth1-canonical-stages/run.log). No speedup is claimed
from this instrumentation run. Transaction/gas throughput for the mainnet block
will be derived only after its complete root is verified.


## Combined SHA production assembly qualification

The Ethereum prefix and five SHA components now have one combined component
owner for both proving and verification. It owns its relation copy and stable
component owners, validates the combined admission certificate, and derives SHA
column/constraint offsets from the actual preceding components. The original
Ethereum assembly shares the same checked compact-provider offset calculation.
It retains its original two-family admission path and transcript.

Combined Tree-0 generation uses verifier-derived SHA topology. Main columns reuse
the existing Ethereum views and project SHA rows directly to final columns.
Interaction output concatenates column descriptors without cloning their field
storage; each producer retains responsibility for its own backing allocations.
Cleanup releases these owners in reverse order.

The combined claim type binds all fourteen existing Ethereum claims and five SHA
claims with explicit framing and order. Zero SHA calls do not force its padded
lookup claims to zero. The strict claim codec retains the existing detailed
Ethereum claims, uses a distinct combined magic/component count, and rejects
noncanonical field limbs and truncation.

`test-sha-combined-assembly-2.log`: all 12 focused tests passed. The actual
SHA → Keccak → SHA witness closes every shared relation. Both prover and verifier
assemblies agree on placement; all three generated column trees end at the
expected offsets. Claims round-trip and reproduce the transcript. Leaf-local
splits before the first SHA instruction and before Keccak both pass after freeing
the preceding segment, including zero-SHA/zero-Ethereum padding. Existing Ethereum
witness census and SHA interaction allocation-failure cleanup also pass.

This is assembly/claims/witness qualification, **not yet a combined SHA leaf
STARK or recursive root**. Next integration batch: expose the combined profile
through the shared extension proof/prepared/manifest API; pass the existing
allocator into SHA coefficient admission instead of introducing an untracked
allocator; route full VM relations to SHA while preserving Ethereum's draw order;
add combined statement metadata encoding; prove, serialize and freshly verify the
combined leaf. Then wire its recursive capture and activate the guest SDK. Full
mainnet-block root remains pending.

## SHA leaf integration — recursion handoff details

The shared leaf pipeline now has an allocator-aware profile adapter, a B3ES
prepared-key identity, fixed-size SHA statement metadata, and a SHA profile
specialization. The full-width artifact/source API accepts the explicit SHA ELF
profile and has a disjoint B3SVART1 envelope. Canonical proof qualification is
being run before declaring these paths complete.

The next recursion batch must handle the following together:

- Add the SHA capture to the closed execution-profile mapping. Its geometry has
  nineteen extension components, not the fourteen Ethereum components or the
  guest-Poseidon pair.
- Replay extension challenges through the profile adapter. SHA's independent wire
  pair is preceded by SHAW framing; drawing 28 raw felts would omit that transcript
  operation and is not equivalent.
- Reconstruct verifier component ownership with full VM relations using the new
  adapter's replay method and pass the profile to native public compensation.
- Record the fourteen Ethereum equations using the combined certificate's
  independently admitted prefix geometry, then the five typed SHA AIRs with their
  isolated wire relation and shared native/table relations. Bind their scalar
  claims in the exact order used by the new claim transcript.
- Update recursive source/claim routing and profile-aware closure, then prove and
  freshly verify a canonical recursive root. Merely recognizing the capture type
  or replaying its transcript is not recursive proof qualification.

The Ethereum SDK provider remains inactive until the combined proof/recursion
path is qualified. Full mainnet-block root and GPU qualification remain pending.

Recorder implementation notes from the current sources: SHA can reuse the typed
`recordComponent` loop already used for BLAKE3 and compact-range AIRs. Copy the
universal symbolic draw array, replace only `recursion_wire` with extension draw
pair 13, and construct the SHA `ChallengeSet` from that array. The Ethereum prefix
uses draw pairs 0..13 and its own detailed-claim prefix; the five SHA claims follow
as scalars. Derive the SHA placements from its stable owner. The existing final
constraint-count check must cover all nineteen extension components. Ethereum
prefix geometry needs an admitted combined-profile entry point; passing the
combined certificate through the existing two-family validator is invalid.


## Canonical combined SHA leaf and source artifact qualified

`test-sha-combined-leaf-5.log`: all nine focused tests pass. Both full-table and
compact-provider versions of the admitted SHA → Keccak → SHA guest produce a
canonical **70-query / 26-PoW** STARK through the shared extension pipeline.
The original witness and prepared key are released before verification. The
strict combined proof codec round-trips; a modified SHA claim is rejected.
A separate key is derived from decoded metadata. The full source-bound artifact
then independently authenticates the supplied ELF/input, decodes its manifest,
derives another key and freshly verifies the proof.

| Provider mode | Inner proof bytes | Qualification elapsed |
| --- | ---: | ---: |
| Full tables | 4,108,400 | 4.647371334 s |
| Compact | 4,031,494 | 2.980226500 s |

These timings include witness/key preparation, artifact serialization, negative
claim verification and repeated positive verification. They are correctness-gate
timings, not an isolated prover benchmark or a full Ethereum block measurement.

The new B3ES profile uses allocator-aware admission and prepared-key identity,
832-byte extension metadata that binds all five SHA semantic/geometry descriptors,
and a disjoint B3SVART1 source envelope. SHA coefficient derivation is charged to
the caller's allocator. Compact transcript mixing now completes allocating
admission once before changing the channel; a capped allocator test verifies that
mixing does not allocate a second admission pass after channel mutation.

Existing Ethereum and guest-Poseidon full proofs, outer artifacts and recursive
replay checks passed in `test-sha-combined-leaf-4.log`. That entire invocation
failed because its SHA fixture lacked release ABI symbols. The production source
validator correctly rejected it; the fixture now uses the complete release ABI.
`-5.log` qualifies the corrected SHA fixtures. The earlier challenge-adapter type
mismatch was fixed by retaining each profile's fixed draw count at replay.

Source archive and exact hashes: `sha-combined-leaf-qualification.json` and
`sha-combined-leaf-source.tar.gz`. Combined SHA recursion remains unqualified;
the Ethereum guest SHA SDK provider, full mainnet block root, and GPU qualification
remain pending. The recursion handoff above lists the required symbolic challenge,
claim routing and geometry changes.


## SHA recursion, custody and default EVM provider qualification

Canonical combined SHA recursion is now qualified. The closed capture mapping,
profile-aware transcript replay, native public compensation and DEEP geometry
support the explicit SHA profile. Challenge replay retains the SHAW domain frame;
only SHA's internal wire relation is replaced with its separate symbolic pair.
The recursive composition recorder replays the fourteen Ethereum components and
all five SHA typed AIRs using the native verifier's authenticated programs. Its
constraint census covers all nineteen components. SHA claims remain circuit
inputs bound to the transcript, and changed claims are rejected.

`test-sha-recursive-parent-1.log`: all eight tests pass. A canonical SHA/Keccak
leaf produced a canonical recursive parent, serialized it, released the worker
and rows, and freshly verified the parent. Parent path: 48.822127125 seconds,
including 8.880612500 seconds preparation and 33.239605583 seconds proving;
979,542-byte parent artifact; tracked worker peak 9,818,400,272 bytes.
This worker peak excludes separately retained preparation allocations.

`test-sha-recursive-segments-1.log`: all eleven tests pass. Two adjacent SHA-profile
segments (SHA, then Keccak/SHA) prove full memory custody, aggregate, serialize,
and freshly verify a complete root at **70 queries / 26 PoW bits**. Elapsed:
121.026120416 seconds; parent artifact: 1,015,674 bytes; tracked worker peak:
19,183,383,520 bytes, excluding 9,104,411,864 retained preparation bytes. This is
a paired two-leaf qualification fixture, not a mainnet block timing or a claim
that the earlier unpaired streaming footprint increased. Existing Ethereum
boundary aggregation and guest-Poseidon proof/replay regressions also pass.

The shared segment-pair API now selects base, Ethereum or Ethereum/SHA by explicit
execution profile. The block stream and bounded preflight use that same profile
selection. There is no alternate SHA proof engine. The ISA activation marker is
true for this explicit capability; runner markers reference that single constant.
Older executable profiles continue to reject the SHA instruction.

The Rust Ethereum guest now defaults to a `sha256-precompile` feature and overrides
revm's `Crypto::sha256` through the shared allocation-free SDK. Its ELF note selects
profile 4 / capabilities 14 / ABI 1 at the same time. `--no-default-features` retains
the prior explicit profile for comparisons. Other SHA2 uses outside that EVM
provider are not automatically redirected. All three independent host framing
and alignment tests pass, and the default RV32 guest builds. A build-time check
now compares the emitted capability note with the canonical semantic digest.
The initial guest artifact was correctly rejected for a mis-transcribed digest;
`ethereum-block-sha-default-v2.elf` contains the corrected, checked note. Earlier
failed build/execution logs are retained as failed attempts.

The corrected guest executes mainnet block 24,628,607 (66 transactions) and matches
the existing expected output: 139,214,856 cycles, 32,835 Keccak calls, 78 recoveries,
**zero EVM SHA compression calls**, 40.089439375 seconds runner elapsed,
40.156780125 seconds process wall, and 256,713,536 bytes peak physical footprint.
This establishes guest integration compatibility, not a SHA speedup or native SDK
runtime-vector coverage. The previous guest executed 139,213,662 cycles in
39.916791458 seconds; these single runs are not a controlled performance comparison.

A full canonical block proof has started in
`measurements-mainnet-24628607-sha-canonical-4194304`, using the new profile-aware
stream binary and a 4,194,304-cycle upper bound. Its successful root has **not**
yet been observed. Power status is recorded by the measurement harness; this run
started on battery at 100%. Full block proof and GPU qualification remain pending.
The next SDK gate should execute native Rust SHA framing against known vectors;
the chosen mainnet fixture does not exercise that callback.

Exact sources and hashes: `sha-recursive-delivery-qualification.json` and
`sha-recursive-delivery-source.tar.gz`.


### SHA preflight profile correction

The initial full block proof attempt above **failed** after 1.23 seconds with
`InvalidPrecompileEncoding`; no proof was produced. Preflight execution selected
the SHA profile correctly, but its program commitment still used the old Ethereum
decode authority. That authority is now passed through both endpoint commitments.
The strict replay check supports the same two explicitly admitted profiles.
The terminal-publication regression now runs for both profiles, including an
unexecuted SHA instruction in the declared program, and all 15 focused checks pass.
Source archive and hashes: `sha-preflight-profile-fix-qualification.json`.
The failed run and its measurement are retained. Full block proof timing and memory
remain unqualified until a successful independently verified root is produced.


### Native Rust SHA SDK execution qualified

`sha-native-vectors-v1/qualification.json` records 44 native RV32 digest vectors:
offsets 0–3 and lengths 0, 1, 55, 56, 63, 64, 65, 127, 128, 129 and 1024 bytes.
All outputs match independent Python hashlib SHA-256, with exactly 148 admitted
compression instructions, 38,367 guest cycles, and no Keccak or recovery calls.
This covers padding boundaries and the direct aligned / copied unaligned block
paths using the actual SDK assembly instruction. It is an execution qualification,
not a proof timing. The test executable and Ethereum guest share the capability
note in `ethereum_admission_v1.rs`; the duplicate note was removed from main.rs.
`sha-native-sdk-vectors-source.tar.gz` preserves the sources. This closes the native
SDK vector gap above; the pinned mainnet fixture itself still has zero SHA calls.


### Full block proof partition qualification remains pending

The corrected preflight completes all 139,214,856 cycles in 10.049406584 seconds
with the 4,194,304-cycle counting limit, checks the expected output, and plans 64
leaves. The first witness then fails `CommitmentTraceTooLarge`: the supported
commitment AIR log-size cap is 24. This cap was retained. Failed invocation:
`measurements-mainnet-24628607-sha-canonical-4194304-v2/measurement.json`.
A smaller 262,144-cycle partition is now under measurement with witness-stage
profiling enabled. There is still no successful full-block root or block proof
throughput claim. The repeated SHA guest build after extracting the shared ELF
note passes (`build-sha-ethereum-guest-v3.log`, ELF/build manifest v3).


The 262144-limit mainnet run has proved and recursively verified its first of 1024 leaves: 143.936252875 seconds including 41.585451125 seconds preflight; tracked peak 20,064,043,363 bytes. First native proof stage total 27.322755 seconds. Partial observations only; full root and OS peak remain pending. Live process 61230 / tool session 21937. Shared Rust ELF-note refactor v3 is byte-identical to v2. Current summary: block-delivery-current-status.json.


GPU/precompile source audit completed without competing builds or GPU runs. Inspected clean pinned Proofman streamed-commit implementation, matched bounded slot/chunk ideas to existing Metal streaming leaves, and recorded field/serialization incompatibilities and the separate pinned CuMetal provider revision. RISC-V CUDA provider still has zero authenticated AOT entries. Added GPU-READINESS.md, PRECOMPILE-INVENTORY.md and source-hash manifest gpu-precompile-source-audit.json. Full block run remains live; latest verified progress is captured in block-delivery-current-status.json. No full block or GPU completion claim.

Added and attached sample_block_memory.py to verified-live PID61230 (sampler tool session50035). Five-second RSS samples pin process start/executable identity, follow new log bytes, correlate completed leaf count, and end on exit or PID reuse without touching the prover. Initial records parse and report positive RSS. Samples exclude startup and are not exact peaks or physical footprint. Attachment manifest: rss-sampling-attachment.json. Prover session21937 remains live; five leaves verified at538.413614083 seconds, peaktracked21,393,851,929bytes.


Standalone root receiver source added: src/frontends/riscv/ethereum_block_verify.zig. It enforces a separately supplied 32-byte key pin before proof I/O, canonical q70/26, bounded JSON/proof input and a 1GiB host-allocation budget, then uses existing RootArtifact.verify and Node.root. Report success/timing/hash fields are ignored as authority. Formatting passes. qualify_block_receiver.py is queued (session16783) behind the live proof lock: retained canonical root, bad key before missing-proof open, malformed pin, changed security, truncated proof, corrupted proof. It has NOT built or passed runtime qualification yet. Pending source hashes: block-receiver-pending.json. Mainnet stream remains live, eight leaves and their aggregate verified with unchanged tracked peak21,393,851,929bytes.


Normal-product wiring added for stwo-ethereum-block-stream and stwo-ethereum-block-verify, sharing the exact direct-source roots and canonical protocol/postcard/backend imports. Both targets are in the root build catalog. Formatting passes; batched normal build session40380 is queued behind the live proof. No product-build success claim yet. COMMANDS.md documents arguments, canonical profile, output creation, optional pairing and independent receiver pin requirements. Source hashes/status: canonical-block-products-pending.json.

Verified wait: original proof session21937 and PID61230 remain live, advanced to14/1024 proved and recursively verified leaves at1444.227165750s. Tracked peak21,568,911,347bytes (~20.09GiB), increased175,059,418bytes from the earlier plateau. This is partial full-block evidence, not a completed benchmark. Receiver and normal builds remain queued. Power observed battery79%; user asked asynchronously to reconnect, proof continues.


Verified wait reached the first16-leaf mainnet prefix and its recursive aggregate:31recursivejobs completed, frontier contracted to1node, elapsed1691.919184958s, peaktracked21,568,911,347bytes (20.0876GiB), unchanged through the carry chain. This is a prefix of the1024-leaf job, not a16-leaf complete job or a completed block. Observation: mainnet-prefix-16-observation.json. Log comparison also shows aggregate witness arithmetic~233krows versus~1.5Mrows in execution-leaf wrappers; no timing speedup is inferred from row counts alone. Originalproofsession21937 remains live.

User reports power reconnected and explicitly requests no further power prompts. Preserve this preference across continuations; proof work continues.

## Segment sizing correction

Stopped the conservative 1024-leaf mainnet run deliberately after 20 verified leaves (20.09 GiB tracked peak). It has no completed block root. The 64-leaf configuration failed the log-24 commitment trace bound, but 128/256/512 were not screened before this run. New admission-only sizing uses actual preflight-balanced segments and the production commitment row census without allocating fixed/main proving columns. Candidates that fit still require canonical native and full-custody recursive qualification; geometry alone is not a proof or speedup.

## Log-25 experiment result

The 512-leaf terminal segment was admitted at log 25 but failed with OutOfMemory after 167.892 seconds under the unchanged 48 GiB overall budget. No proof or speedup resulted. Evidence: `segment-proof-sizing-log25-v1/results.json` and `512-511.log`. Raising the cap alone is not a sufficient solution. A full 512-leaf admission census is now running with JSONL records and final completeness/output checks, while selected-leaf diagnostics were expanded to localize future allocation failures.

## Work-based schedule implementation

Added explicit, borrowed cycle budgets to the existing schedule, with power-of-two slot-count, nonzero/max-capacity, exact total and terminal-publication validation. The stream and geometry tool share the schedule-file parser and validate against independent full execution preflight. Stream replay retains exact cycle and completion checks; root and full-custody verification are unchanged. New geometry `all` mode checks every leaf and emits a final coverage summary. The row-density planner creates proposals only from a complete census. A queued qualification job builds the updated geometry tool and independently scans the 256-leaf proposal, falling back to 512 if any commitment component exceeds log 24. These are candidates, not proof-qualified schedules. Tests/builds are queued under the existing serialization lock.


## Component commitment barrier

Extracted the real fixed/main PCS stage from the production extension pipeline.
Added bounded census/discard/replay and rejection of changed roots before lookup
interaction generation; temporary extension main columns now release after the
commit. Canonical ordinary/compact SHA+Keccak leaf fixtures freshly verify,
including source artifacts and independent verifier replay (nine tests passed,
`test-first-round-pcs-v2.log`). Added a versioned ordered component-root manifest
with exact work coverage, security and admitted identity binding, plus five
focused ReleaseSafe tests including planner tests. This manifest is not yet
production shared-randomness or recursive-memory proof support. The separate
memory AIR, shared native/recursive challenge path and global closure remain
required. No full-block proof or architecture speedup is claimed.


## Global sorted-memory contract primitives

Added checked projection of actual tracker accesses into a common 64-bit block
clock for both leaf-local and global-continuous segment frames, with canonical
17-byte event records. Added a typed, identity-pinned sorted-memory adjacency
gadget proving address/clock order and same-address value continuity with byte
range checks; no M31/64-bit wrap. Five focused tests passed. The remaining
required work is a proof-enforced execution/precompile-to-sorted-memory
permutation, authenticated first-value initialization, constrained row linkage
and cross-instance continuation, and native/recursive global relation closure.
No memory hash reduction or complete block proof is yet claimed.


## Bounded memory-event transport

Added a disk-backed external event sorter with bounded event chunks and eight-run
merge fanout. It accepts real runner access slices under segment clock authority,
checks canonical events and strict sorted order, and detects duplicate key/clock
pairs. Focused multi-pass and cross-segment tests pass. The sorter is not yet
connected to the block proof; no performance or proof security claim follows
until the typed permutation, initialization and recursive closure are wired.

## Joint-manifest native and recursive qualification

Two real adjacent compact SHA execution leaves now seal one ordered fixed/main
PCS manifest, draw identical canonical q70/PoW26 relations, serialize and freshly
verify through a two-pass bounded receiver. Missing, reordered and duplicate
proof files are rejected (`test-sha-joint-segments-v3.log`). The native recursive
recorder pins the roster digest and main root into fixed parent rows while routing
both initial PCS roots to Merkle checks. A one-leaf canonical recursive proof
freshly verifies (`test-sha-joint-parent-v3.log`): parent wall time 50.84 s,
tracked worker peak 9.94 GB. This is a qualified fixture, not an Ethereum block
proof or evidence of global memory closure. The adjacent two-leaf manifest
aggregate also freshly verifies with full existing custody
(`test-sha-joint-pair-v2.log`): 120.01 s total, 19.18 GB tracked worker peak.
Component identities/geometry in this fixture are placeholders derived from
execution keys in the initial test. They are now independently derived from
the prepared profile/key/three-tree geometry and authenticated span/cycle
coverage, and checked again by the pair aggregator. Canonical requalification
passes (`test-sha-joint-pair-admission-v3.log`): 120.97 s, 19.18 GB tracked
worker peak. The block-stream CLI has an opt-in `paired joint` route for exactly
two segments; its normal build has passed. The sorted-memory AIR/permutation
and block-wide schedule remain to be integrated before the intended full CPU
block measurement.

The installed stream and receiver builds completed. The `paired joint` product
proved all 21,635 cycles of the existing two-segment authentication fixture,
then a fresh receiver verified its persisted canonical root with a pinned key
(`joint-two-segment-root-v1/qualification.json`). Producer time 76.87 s,
tracked peak 18.76 GB; the fixture uses 70 queries/26 PoW bits and the existing
full-memory custody. This is not the mainnet block or separate sorted-memory AIR.

The sorted event transport now emits explicit before/after transitions across
writes and requires an independently admitted initial value on a new address.
Its reader poisons itself after an initial-value failure. Three focused tests
pass (`test-block-memory-transition-v3.log`). It is not yet proof authority.

Four selected canonical full-custody proofs in the explicit 256-leaf mainnet
schedule pass: terminal #255 (94,180 cycles, 163.56 s, 37.37 GB tracked peak),
peak BLAKE3 #53 (233,639 cycles, 195.98 s, 38.60 GB), peak other precompile
rows #244 (159,229 cycles, 160.88 s, 37.32 GB), and longest #50
(4,194,304 cycles, 87.53 s, 17.42 GB). Corresponding `*-256-proof-v1` JSON
records pin commands, security, stage times and inputs. This proves neither
the remaining 252 leaves nor the block root; the separate sorted-memory AIR
and non-rounded recursive count are still the architectural gate.

The sorted-memory transport now buffers 1,024 records per run read instead of
issuing one positional read per 17-byte event, and admits each run only when
its file length exactly matches the declared event count. A streaming memory
instance partitioner emits the exact number of real rows (no instance-count
rounding), carries predecessor links across instance boundaries, and rejects
both truncated and surplus event streams before completion. All 33 focused
block-memory tests pass, including multi-run buffer-boundary and census cases.
This is still witness transport: PCS admission, execution-to-memory permutation,
authenticated first values and recursive relation closure remain to be built.

## Exact-count and separate-memory implementation in progress

The block stream now has an opt-in `exact` route that schedules the actual
segment count, retains an independently verifiable dyadic proof forest without
dummy leaves, and publishes a versioned roster with an external digest pin.
This is a proof forest, not one recursive root, and each execution leaf still
uses its existing full memory custody. A complete 256-leaf geometry census
produced a conservative 218-segment candidate by merging adjacent work-balanced
leaves under log24 row and 2^22-cycle bounds. The merged schedule is a proposal
until every actual merged segment passes geometry admission and canonical proof.

The `exact-three-segment-v1` canonical qualification now passes: 21,635 cycles
in the explicit unequal schedule `[7000,7000,7635]`, two verified forest proof
files for three actual segments, q70/PoW26, and a fresh-process receiver with a
development roster pin. Producer time was 103.26 s (107.31 s wrapper wall),
tracked peak 18.76 GB, proof bytes 1,998,097; fresh receiver time was 40.05 ms
with 7.30 MB tracked peak. The host-only sorted witness had 51,929 real memory
events in one planned memory instance. Its 4,747 first-touch keys split into 31
registers, 4,683 ordinary RW, 33 public-input words (also covered by the
continuation RW root), and zero program words. `qualification.json` hashes the
binaries, inputs, schedule, bundle and report. This still uses old per-leaf
memory custody and is not a mainnet or separate-memory block proof.

The same block stream can spool actual register/RW accesses across all segments,
sort them on a 64-bit global clock, partition exact memory row counts, and report
first-touch source counts. Its first-segment replay image now distinguishes
public registers, RW memory, public input and program words. A host admission
guard reconstructs the **continuation** initial RW root, including public input,
and compares it to the block job; this is not itself a proof. Forty focused
ReleaseFast replay/import tests pass. Public register first values have a
deterministic 32-bit use-mask provider and a focused tuple test; the mask and
positive relation sum still require block-v2 transcript/closure integration.

The new typed sorted-memory AIR has fixed row selectors, exact census,
cross-instance predecessor pins, 64-bit ordering and value continuity. Its
block-v2 transition/link/initial requests and 35 byte-range effects are
translated to native and sampled quotient constraints. A shared 8x8 range table
commits its multiplicity before the sealed challenge draw and closes 18 batched
range claims. Fixed linear link selectors reduced the memory quotient degree,
so the memory AIR and range table now prove in one STARK. The canonical
q70/PoW26 small fixture passed fresh verification: 10.717 s proving,
29.8 ms verification and 254,058 Postcard proof bytes. This exercises two
active transitions at log8 plus the 65,536-row byte table; it is not a block
measurement. A versioned SourceSeal v2 binds the public register mask and
ordered provider roster before the universal challenge draw. An initial RW
provider based on the shared BLAKE3 sparse multiproof is being integrated.
The execution-side transition emitter, authenticated provider closure, full
instance roster/global closure, one complete-block recursive root and mainnet
CPU measurement remain unqualified. No full block proof or memory/speed
improvement is claimed here.

A fast host-only roster replay exactly reproduces the qualified three-segment
proof run's 51,929 events and 4,747 first-touch keys without rerunning any
proof. Its 47,470-byte `exact-three-segment-v1/memory-first-touch.bin` uses
10-byte sorted records `(space,address LE4,initial value LE4,source)` and hashes
to `c76b0c8dcf41bde037ea735441b18857df4fcaf43eb1b9853b0df60ae79636db`.
This supplies real 4,716-key RW-root addresses for a bounded two-chunk shared
path census; it is still a planning witness, not a proof.

That real roster contains only 34 nonzero initial values: 2 registers,
30 public-input words and 2 ordinary RW words. A shared-path census for all
4,716 RW-root keys would emit 1,454,288 hash rows across 9,531 computed nodes.
Sparse initialization is therefore a core architecture problem: the default-zero
first touches need proof against the pinned initial root without independently
hashing a path per zero address. The current roster classification is host-only.
The complete fixture continuation snapshot contains 150 nonzero RW/input words
(`exact-three-snapshot-v3/report.json`), and its regenerated first-touch roster
hashes exactly to the earlier qualified roster. A complete sparse-tree proof
over those 150 nonzero leaves, with forced public empty siblings and a proved
sorted join to first touches, is the current replacement design. It has not yet
been qualified as a full provider proof.
On the real 150-leaf fixture roster, a shared-path witness census emits 55,600
hash rows over 348 computed nodes, versus 1,454,288 rows when opening all
4,716 RW-root first-touch keys. This is a 26.16x row reduction at the witness
topology level; it is not yet a qualified complete-sparse AIR proof.

An experimental joint provider PCS proof now includes the positive 9-byte
initial-bus quotient, typed BLAKE3 hash/range/wire effects, and a versioned
complete-sparse mode with fixed public empty-subtree siblings. The latter
now binds both first-round roots into SourceSeal v3 before drawing the 47
universal and block-only challenges, then fresh-verifies at q70/PoW26. The
latest complete-sparse fixture sample took 1.165 s to prove and 0.854 s to
verify, with 403,385 Postcard bytes. Zero first-touch absence plus global
initial-bus closure remain unproved, so this is a positive source proof, not
complete production initial-state authority.

The full 218-segment exact proposal now passes an actual admission replay
(`exact-schedule-geometry-v1/qualification.json`): all 139,214,856 cycles and
all 218 segment records completed with the expected output, and every component
fits log24. The largest component has 16,492,000 rows versus the 16,777,216
limit. Geometry took 286.74 s with 1.075 GB tracked peak. This replaces the
additive-bound scheduling estimate with measured geometry, but still proves no
execution leaf or full block under the new architecture.
It measures the **old full-custody** leaf geometry; once block-wide memory
replaces per-leaf custody, execution component rows change and the optimal
exact segment count must be recomputed rather than hard-coded to 218.

A two-instance typed memory proof test now streams 3 sorted events into 2+1
real rows, proves each instance and fresh-verifies both under one SourceSeal.
Receipt admission accepts the exact ordered roster and rejects omission,
reordering, a changed seal, and unbalanced cross-instance links. The execution
transition emitter and initial-value closure are still required for block-wide
proof authority.

An isolated canonical q70/PoW26 proof of the real three-segment fixture's
51,929 sorted events now passes fresh verification in one log16 memory
instance. Replay took 42.8 ms, first-round commitment 109.1 ms, PCS proving
1.213 s (1.275 s on one repeat), and verification 46.9 ms. The Postcard proof
is 264,044 bytes and tracked peak is 438,123,168 bytes. The execution and
initial-state relation claims remain open, so this timing is **not** a complete
fixture/block proof. The source-hashed record is
`exact-three-segment-v1/memory-proof-v2-q70-pow26.json`.
PoW timing can vary substantially between single runs.

The complete 218-segment mainnet **host-only** sorted-memory replay also passed
(`exact-schedule-memory-roster-v1/qualification.json`): 356,303,914 real
events, 3,142,932 first touches (31 registers, 2,467,724 ordinary RW,
675,177 public input, no program), 74.49 s wall and 1.075 GB tracked peak.
Only 913 ordinary RW first touches begin nonzero; the other 2,466,811 begin
zero. The complete initial continuation snapshot has 666,708 nonzero RW/input
leaves, of which 657,509 are in the input address region. These are planning
counts, not STARK evidence. At a 2^20-row memory cap the raw event count
requires 340 independently sized memory instances before any proof overhead.
The exact nonempty 30-level tree topology has 676,082 internal nodes over all
666,708 nonzero leaves. Excluding the observed public-input address interval
leaves 9,199 nonzero words and 9,708 internal nodes. This is host-only topology;
any verifier-known-input shortcut needs an explicit versioned verifier input
contract, because the current detached receiver accepts only a proof bundle
and digest pin, not the raw 2.7 MB input.

One shared 8x8 byte-range table per **bounded shard** is the intended large-block
layout. The 35 requests per memory row imply a maximum of 61,356,675 real
events per shard before an M31 multiplicity could wrap. The exact mainnet
roster (339 full log20 instances plus 836,650 rows) partitions into six
contiguous shards, each below that limit. The shard planner binds its exact
intervals/census in a digest and rejects tampering. A separate table PCS proof
and fresh verifier pass a focused q8/PoW0 test; the canonical request-only
memory-instance and shared-table path is qualified below.
The bound SourceSeal v3 table proof also passes fresh verification at canonical
q70/PoW26 with a nonzero multiplicity: first-round commitment 0.180 s,
proof 48.706 s, verification 0.208 s, and 211,935 Postcard bytes. This is one
sample under concurrent host work, not a stable table-speed comparison.
The production SourceSeal extension now absorbs both the exact shard-plan
digest and the ordered fixed/main first-round root roster digest before the
47 universal challenge draws. It binds distinct exact execution and memory
instance counts. The old v1 manifest digest stays unchanged;
the final batch verifier must require the bound form and recompute those
digests from trusted admissions.
The disk-backed sorted spool can now reopen its admitted final run. A bounded
producer can commit each memory instance once to collect fixed/main roots and
shard counters, release that trace/PCS state, seal the complete roster, then
reopen the same sorted events and re-commit each instance against its sealed
roots before serial proving. This is the intended two-pass lifetime for 340
mainnet memory instances; focused replay tests are being qualified.
The reopen path passed all 40 focused ReleaseFast replay/import tests, including
a second read of the exact admitted sorted stream and reconstructed transitions.

The request-only sorted-memory instance and shared 8x8 table now prove together
under one bound SourceSeal v3 at canonical q70/PoW26. Fresh verifiers accept
both artifacts and the exact link/range claims close. On a two-event fixture,
the combined first rounds took 0.207 s, proving 33.985 s and verification
0.258 s; memory/table Postcard payloads were 79,016/212,016 bytes. These are
small-fixture correctness measurements with substantial fixed table/PoW work,
not mainnet row-throughput estimates.

The batch receiver now parses bounded serialized memory-request and table
proofs, fresh-verifies them against pinned roots and SourceSeal v3, admits the
exact memory/link roster, and closes the shared byte-range claims in a focused
q8/PoW0 test. Tampered claims, digests, counts and truncated proofs fail. Its
complete-block result remains an explicit error until execution and initial
source verifiers are wired.

One **full log20 mainnet sorted-memory instance** then passed a request-only
q70/PoW26 CPU proof and fresh verification: 1,048,576 rows, 2.278 s fixed/main
commitment, 22.645 s proving, 0.381 s verification, 406,342 Postcard proof
bytes, and 6,463,831,637 tracked peak bytes (6.02 GiB). Replaying/sorting all
218 execution segments before extracting this first sorted instance took
63.492 s. This is one sample of one of 340 planned instances and excludes
the shared table, execution transition and initial-value proofs; it cannot be
multiplied into a qualified full-block timing. Exact source/input hashes and
measurements are in
`exact-schedule-memory-roster-v1/first-log20-memory-proof-v2-q70-pow26.json`.

The public initial-RW fallback was measured against the full 218-segment
mainnet first-touch roster. An independently derived ELF/input entry root
matches the complete 666,708-word nonzero image. Streaming all 3,142,932
first touches checks 3,142,901 RW/input values, 2,484,479 implicit zeros,
31 pinned initial registers and zero program touches; it computes positive
initial-bus claims in 0.226 s with 118,930,376 tracked peak bytes. Fresh
session/root setup adds 0.250 s. `public-rw-fallback-v2.json` records roots,
claims, timings and SHA256 pins. The scoped receiver also passes a real 2+1
memory/table serialized-proof fresh-verification test before initial claim
closure. This is not complete-block authority: execution transition proofs
and independently pinned production SourceSeal first-round roots remain to be
integrated.

The block-v3 receiver now fresh-verifies native Ethereum-SHA execution, its
same-root typed access sidecar, independently sized sorted memory, separate
execution and memory byte tables, and the public initial-image claim before
issuing a scoped `VerifiedBlockCore`. A coherent single-segment SHA-profile
fixture with base instructions only passed q8/PoW0 across all these proof
families (`block_memory_core_sha_fixture_test.zig`, 8/8 focused tests). The
unmodified six-step SHA/Keccak/SHA fixture exposed a genuine coverage gap:
the opcode sidecar proves 5 accesses while the runner records 108. The
remaining 103 are exactly two 26-access SHA calls and one 51-access Keccak
call. Full transition closure must wait for typed extension-access emitters;
the test never filters those events. The final complete-block receiver also
requires freshly linked recursive leaves and an independently pinned outer
key/forest roster. See [BLOCK-ARCHITECTURE-V3.md](BLOCK-ARCHITECTURE-V3.md)
and [exact-root-v2.md](exact-root-v2.md) for that authority boundary.

A later artifact audit corrected the NOP/x0 attribution: the genuine
three-NOP segmented fixture has 11 runner accesses, 11 typed accesses and an
11-event packaged opcode sidecar. All three `ADDI x0,x0,0` rows are present.
The earlier 11-versus-5 comparison mixed this fixture with the unmodified
SHA/Keccak workload, whose 5 opcode accesses require 103 separate precompile
accesses. The typed extension sidecars now cover that latter workload; see
[BLOCK-ARCHITECTURE-V3.md](BLOCK-ARCHITECTURE-V3.md).

The production-facing one-segment CPU block-v4 assembler now passes a focused
real public-I/O and Keccak run at diagnostic q8/PoW0. The exact 70-event
execution/sorted-memory relation, initial source, and separate byte tables
close under fresh core verification. The run measured 5.416 s wall time,
520,385,073 tracked peak bytes, and 1,651,532 STARK/native-artifact payload
bytes; verifier-visible nonzero image and first-touch files were 2,040 and
590 bytes. The image includes initialized Keccak state. This is core proof
qualification only; recursion and canonical q70/PoW26 are excluded. The first
real-I/O attempt exposed a typed load/store sidecar address-unit error: its
native selectors were already byte addresses, while the sidecar multiplied
them by four as word indices. The fixed family-specific bridge now binds the
byte address in its witness and quotient, while external caller word indices
retain the original conversion. Exact scope and source hashes are in
`block-v4-cpu-real-io-small-q8.json`. A subsequent focused hardening keeps
typed byte addresses below the native AIR's 2^30 bound, rejecting unaligned
and high-bit tampering; 4/4 narrow ReleaseFast tests pass. The complete core
benchmark was not repeated after this non-fixture-path bound refinement.

The bounded two-segment CPU assembler now passes a real public-I/O fixture
with a zero-call first leaf and a Keccak terminal leaf. Its q8/PoW0 core
verification closes 70 total events and 51 external events in 8.467 s with
819,815,347 tracked peak bytes; this still excludes recursion. A separate
two-pass streaming producer replays one segment at a time and stages hashed
proof files. Its corresponding q8 fixture passes with the same first-round
digest and SourceSeal; the measured 7.442 s is **producer-only**, before the
fresh-verifier callback. A private incremental core receiver has also passed
the two-segment q8 real-I/O fixture while loading one staged execution proof
at a time. It reconstructs native verifier shape through a third pinned
public replay, so its memory is bounded but verification is not succinct.
At this point the streaming complete recursive receiver and production CLI
integration remained to qualify. No full 218-segment proof or end-to-end block
time/memory claim follows from these fixtures.

The joined two-segment real-I/O diagnostic q8 complete receiver has now
passed with two recursive leaves, a dyadic parent, an exact outer root,
wrong-pin rejections and clean allocator teardown. Its staged producer took
7.627 s, recursive proof generation 33.908 s, and fresh complete receiver
5.180 s; [the result](block-v4-cpu-streaming-complete-real-io-q8.json) scopes
the partial receiver peak. This fixture still generates recursive proofs from
a bounded in-memory assembly. A separate real two-segment observer gate now
proves and hash-stages both leaves during the incremental replay and closes
the 70-event core with zero live receiver allocations; it does not yet stage
or verify the dyadic/outer forest. The canonical q70 joined receiver and
production bundle/CLI remain pending.

A read-only 218-segment candidate native-key replay under the proposed exact
schedule reached segment 29 and failed in `PreparedVerifier.initCompact` with
`OutOfMemory` at a 16 GiB tracked limit. It ran 538.98 s and reached a
16,591,749,120-byte resident peak; no candidate manifest was published.
[The scoped failure record](block-v4-candidate-roster-218-baseline-failure.json)
pins the source files and schedule. Subsequent probes separated the large
segment witness from native key preparation and found no large per-key
retention. This scan contains no proof or merged first-round geometry authority.

The follow-up 30-key prefix with chunked host preflight and an owned verifier-input
snapshot completed under the same 16 GiB limit. The snapshot releases each
segment witness before native key preparation; at index 29 tracked peak was
9,748,075,183 bytes, resident peak 9,774,448,640 bytes, and live memory
returned to 46,792,290 bytes after the segment. Wall time was 616.77 s.
[The scoped prefix record](block-v4-candidate-roster-snapshot-30-probe.json)
contains the exact source hashes and stage measurements. This intentionally
published no candidate manifest. The proposed 4,194,304-cycle leaf at index 48
still requires a separate sizing check before a full 218-key replay.

That targeted sizing check passed: the proposed maximum 4,194,304-cycle
segment at index 48 prepared its native key with 4,255,910,637 tracked peak
bytes, 3,896,033,280 resident bytes, and 115.42 s wall time. It replayed
preceding segments without preparing their keys, stopped immediately after
index 48, and published no manifest. [The target record](block-v4-candidate-roster-target48-probe.json)
keeps this host sizing result distinct from proof or geometry admission.

The full read-only candidate replay then completed all 218 proposed leaves and
139,214,856 cycles. Its candidate manifest hashes to
`a8ba6144b6897afa1724e611af7c1ccd7c133ce24fe067855d819794bb1fb749`;
all 218 native key IDs are distinct under the current leaf-specific key
identity. Work elapsed 4,592.790813291 s (process wall 4,592.79 s), with
10,212,395,984 tracked peak bytes and 10,053,238,784 maximum resident bytes.
[The complete scoped result](block-v4-candidate-roster-218-snapshot-result.json),
[candidate manifest](candidate-native-key-roster-v1/candidate-trusted-v1.json),
and [run log](block-v4-candidate-roster-218-snapshot.log) are retained with
source hashes. The outer key and forest digest in this manifest are provisional
zeros; no STARK proof, merged first-round admission, or complete mainnet block
verification occurred. Under the revised architecture priority, this candidate
result is retained as sizing evidence; the former geometry/producer pipeline
was not launched after it.
