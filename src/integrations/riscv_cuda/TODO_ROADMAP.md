# RV64 GPU consolidation, productionisation and performance roadmap

Status snapshot: 2026-11-08. This is a delivery plan, not a qualification receipt.
The merge checkpoint and the later hygiene backup are different source trees.
Merging the correctness checkpoint does **not** qualify GPU-native promotion.

## 1. Source boundaries and the immediate handoff

| Source boundary | Status | What a reviewer may conclude |
|---|---|---|
| `51897dc265593df7580c4abf0b232909fc105e34` | MERGE CHECKPOINT | Recorded default/native correctness on 24628607; GPU-native remains default-off |
| PR314 plus this roadmap/merge receipt | REQUESTED MERGE | Merge the checkpoint and evidence documentation; no later allocator/setup/default-flip changes are implied |
| `codex/rv64-gpu-hygiene-local` | UNMERGED BACKUP | Later preservation, ownership, setup and harness work; qualification remains incomplete |
| `e4c4a9da65700da47af40a0b6e9bb7ecc1014571` | BACKUP AUDIT SNAPSHOT | Earlier static/flag inventory and the failed CI run below |
| `357e5d23010dff22bbdd1fe8afaf25082644bb2d` | LATER UNMERGED BACKUP | Test/fixture owners and AOT collision repair; full hardware qualification remains pending |

The published backup was independently verified at `0fd4c01b25b38be507165645366ba71a3d3b9b55`.
Refresh the backup ref after committing later coherent batches; never infer its head from a local branch name.
The remote backup was re-read and verified at `357e5d23010dff22bbdd1fe8afaf25082644bb2d` before this handoff.
The earlier hygiene remote checkpoint was `51897dc265593df7580c4abf0b232909fc105e34`.
Preservation of a later commit is not evidence that it passes the checkpoint's GPU gates.

- [ ] Merge only the agreed PR314 checkpoint, this roadmap and the compact merge validation receipt.
- [ ] Verify the resulting merge commit and its exact source relationship to 51897.
- [ ] Keep the later backup reachable while planning its application in coherent batches.
- [ ] Re-inventory the canonical checkout after the merge; do not open component worktrees.
- [ ] Commit or explicitly preserve every pending local edit before further retirement.
- [ ] Keep PR322 outside this merge and hygiene scope.

Related PR boundaries: PR316 and PR320 are already exact ancestors of this checkpoint.
PR299 is separate circuit-CUDA FRI work and is not required for PR314.
PR270 has conflicting capture-hardening changes and needs an independent reconciliation.
PR306 remains draft/outside this merge; PR322 is explicitly excluded.

## 2. Binding contracts and evidence vocabulary

The [delivery contract](../../../design/riscv/rv64-gpu-hygiene.md)
defines promotion order, subtraction budgets, ownership and completion requirements.
The [handoff](../../../design/riscv/rv64-m8-handoff.md)
contains historical results and the architectural work queue; its estimates are not promises.
The [current receipt](../../../vectors/reports/rv64-productionisation/current.json)
records the evidence belonging to its own source revision.
Its 51897-prefix version has stale last-qualified metadata; use the compact
[51897 merge validation](../../../vectors/reports/rv64-productionisation/merge-validation-51897.json)
for the separately preserved gate receipts and their retention limitations.
The [archive index](../../../design/riscv/rv64-archive-index.md)
records recoverable history and the custody process.

Use these labels in every follow-up receipt:

- **HOST / FAKE DEVICE:** executable ownership, allocation and failure models.
- **BUILD:** a specified source/binary configuration compiled successfully.
- **HARDWARE CORRECTNESS:** real GPU outputs passed the stated acceptance scope.
- **SAMPLED PHYSICAL OBSERVATION:** observed whole-device usage at discrete sample times.
- **ENFORCED CEILING:** physical availability was constrained; the peak was not measured.
- **QUALIFIED TIMING:** matched canonical runs passed quiet, identity and acceptance gates.
- **ESTIMATE:** an architectural or capacity prediction awaiting measurement.
- **PENDING / FAILED / RESOURCE LIMITED:** open work, never interchangeable with PASS.

Do not turn a warm request, component test, source merge or successful backup into a release verdict.

## 3. Developer interface: exactly three normal entrypoints

The maintained instructions are in [rv64/jobs/README.md](rv64/jobs/README.md).
Run these commands from the canonical repository root:

```sh
python3 scripts/dev_test.py <changed-paths>
bash scripts/rv64_gate.sh --stream m8-gn-bind --out <new-receipt-dir> --source-commit <sha> --runtime <pinned-runtime.json>
python3 scripts/rv64_m8_bench15.py run --assets <pinned-assets.json> --out <new-basket-dir> --arms gpu-native
```

- [ ] Extend these entrypoints and their actual shared libraries.
- [ ] Do not introduce another top-level developer launcher.
- [ ] Keep `dev_test.py --dry-run` useful for the actual no-argument worktree scope.
- [ ] Use `--optimize ReleaseFast` when reproducing an optimized CI failure.
- [ ] Route changed live fixtures to their owning validators and package tests.
- [ ] Reject nonexistent Python typos and genuinely unowned source paths.
- [ ] Keep check-only planning distinct from executed tests.
- [ ] Run the default gate before each qualified deletion batch and every push required by the contract.
- [ ] If hardware is unavailable, record the gate as pending instead of silently substituting host tests.

## 4. What is already established, and what is only in the backup

The 51897 checkpoint preserves the first subtractive delivery and its recorded correctness gates.
On 24628607, default and explicit GPU-native each have cold/warm frozen-payload parity,
two fresh isolated CPU accepts and the selected 19-case semantic-negative corpus.
Those receipts do not establish the median block comparison, new-block latency or the native basket.
The correctness pairs were not matched quiet 3+3 timing experiments.
The merge validation must retain exact source/binary pins and SHA-256s of the original external receipts.

The following later work must be reviewed and applied from the backup; it is not merged by this handoff:

- Maintained fixture separation and retirement of 7,004 historical report files.
- Quiescent setup-miss construction, array ownership and separate setup timing.
- Truth coefficient-prefix lifetime corrections and source-derived immutable warming bounds.
- Separate immutable warming, persistent census, bounded probing and final admission.
- The installation resource Owner split and its partial-failure cleanup.
- Shared resource-test ownership and the eight Metal resource roots plus AOT pair.
- Focused developer routing and the explicit typo/deleted-owner classification repairs.
- Concurrent fresh CPU receivers with independent output directories and quarantine lifetime.
- Guarded sampled-memory evidence linkage and per-GPU aggregation.
- Subsequent driver/capture test-owner splits, which need their own final committed validation state.

Do not copy a later `current.json` over the merge checkpoint and imply that its evidence has landed.

## 5. CI and broad-suite truthfulness

[CI run 42494574484](https://github.com/teddyjfpender/stwo-zig/actions/runs/42494574484)
belongs to backup snapshot `e4c4a9da65700da47af40a0b6e9bb7ecc1014571`.
It was in progress when queried and subsequently completed **FAIL**; exact final job counts were still being collected.
Hosted CI exposed an AOT name collision; the later backup repairs it with zero net code growth.
A repeat CI result is pending. Neither the old run nor the repair is an all-suite PASS.
These backup results are not results for the 51897-plus-documentation merge candidate.

An older broad Python snapshot ran 2,135 tests with 47 failures, 49 errors and 61 skips.
Those are historical counts; the current full-suite result is unknown until rerun on pinned source.
Later focused successes do not erase that missing full-suite result.

- [ ] Save the terminal result and failed-job logs of run 42494574484.
- [ ] Run the appropriate CI scope again for the actual merge/hygiene candidate.
- [ ] Resolve product-closure fixture publication leakage instead of baselining it.
- [ ] Resolve CUDA runtime-source roster and broad environment-reader ownership mismatches.
- [ ] Preserve existing test discovery, negative classifications and source identity checks.
- [ ] Distinguish intentional skips from missing execution of required GPU tests.
- [ ] Keep bounded laptop checks bounded; do not retry a resource-cap kill as if it were a pass.
- [ ] Save stopped compiler/test receipts and the resource limit that caused the stop.
- [ ] Run large compiler and complete-block work on a funded, frozen pod source snapshot.
- [ ] Update the current receipt only with results that match the new source hash.

Recent backup host checks include an eight-test Arena pass and focused driver passes.
The later driver-owner check passed 42 host entries; all 30 bodies were preserved and 29 were selected.
Focused developer-routing checks passed 29 tests on that later source.
A capture-fixture check was killed at its RSS cap; it remains unvalidated.
Its observed group RSS reached 872,272 KiB; no completed capture compile is claimed.
These counts overlap other host suites and are not additive qualification totals.

## 6. Static gate: latest 118 diagnostics across 117 paths

The e4c4 read-only inventory reported **120 diagnostics / 119 distinct paths**.
That older breakdown was 112 manual-source, three build-support and five command/test-owner ceilings.
After the later fixture/test-owner work, the reported backup count is **118 diagnostics / 117 paths**.
Neither number is a newly measured static result for the merge prefix.
Refresh the literal inventory and category breakdown at the final chosen backup commit.
Recompute this inventory after applying pending test-owner splits and after every completed batch.

- [ ] Bring the static gate to zero findings without adding baselines.
- [ ] Do not increase any source, build-support or command-owner ceiling.
- [ ] Delete proven unreachable implementations only after preserving their unique work.
- [ ] Split live code by acquisition/lifetime responsibility, not arbitrary line ranges.
- [ ] Keep ordinary public package APIs and backend layering intact during moves.
- [ ] Retain all tests protecting behavior that remains live.
- [ ] Do not replace test bodies with forwarding roots or empty discovery success.
- [ ] Record the before/after diagnostic set, not just the total.

Representative live boundaries needing owner work include:

| Family | Concrete owners | Required direction |
|---|---|---|
| CUDA runtime | `src/backends/cuda/runtime/context.zig`, native runtime context/arena | Separate context, allocation observation and lifecycle responsibilities |
| Metal runtime | `src/backends/metal/runtime.m`, runtime bindings and operation files | Keep source identity and Objective-C linkage with the actual operation owners |
| Frontend proving | RISC-V orchestration/provider files | Separate immutable authority, execution state and proof publication |
| CPU recursion | `rv64_recursion/om31_native/execution_wrap.zig` | Separate schedule, framing/cache lifetime and publication; preserve CPU products |
| GPU integration | resident, recursion builder and job-runtime files | Keep setup, requests and teardown explicitly owned |
| Command tests | large driver/capture test owners | Real fixture/scenario owners, preserved bodies and mandatory discovery |

The full literal path inventory is in the optional local audit described in section 19.

## 7. Flag arithmetic: a registry is not retirement

The [flag registry](../../../conformance/rv64-flags.json) currently declares 297 names.
Of these, **260 are live**: 135 runtime, 28 qualification, three frozen and 94 scheduled after promotion.
The remaining declarations are 34 constants and three reference-only names.
The strict target is **fewer than 60 live flags**, with no pending M7/M8 switch.

At least **201 actual reader removals** are necessary: `260 - 201 = 59`.
Removing only the scheduled 94 leaves **166**, requiring at least **107 further removals**.
Changing a registry status, hiding a scan path or renaming an environment variable does not count.

| Reader-backed additional bundle | Flags | Required owner work |
|---|---:|---|
| Legacy CUDA execution and installation controls | 44 | Replace live template bootstrap, retire callbacks/selectors and bind pinned installation data |
| Capture-policy controls | 25 | Promote one authenticated capture policy; derive bounded workers/windows from its owner |
| CPU recursion schedules and caches | 11 | Retire duplicate control readers while preserving CPU proof/receiver products |
| Qualification inputs | 28 | Retain artifact security, GPU-required failures and fixture discovery through owned test interfaces |
| Additional candidates | 108 | Projects 58 remaining only after all those real changes |

The 108 are a dependency plan, not a claim that 108 flags are dead.
The retained remainder also needs review; it is not an endorsement of every permanent knob.
Hybrid helper controls still required by the complete legacy sweep must not be forgotten.

Four narrow pre-promotion candidates were identified:

- ~~`STWO_RV64_GLOBAL_ADMISSION` and its host-policy/runtime selectors~~ (deleted with the admission ledger; Footprint lives in `rv64/footprint_types.zig`).
- `STWO_RV64_HARNESS_ALLOW_BLOCKS`, which duplicates existing `--allow-block`.

Preserve generic Footprint, capacity, ticket, cancellation, physical guard and runtime-observation APIs.
The flag name alone is not evidence that those APIs may be deleted.
Qualification output-directory flags can select a stronger proof profile; they are not just optional printing.
`M8_REQUIRE_GPU` currently turns a missing device into failure; preserve that invariant before removing its reader.

## 8. Native immutable construction is a retirement prerequisite

The current native installer still builds recursion templates through legacy execution.
See [native_recursion_install.zig](rv64/native_recursion_install.zig)
and [outer_job_factory.zig](rv64/outer_job_factory.zig).
`Owner.prepare` calls `resident_batch.runCombined`, then harvests `Outer.NodeClasses` templates.
Its installation environment deliberately selects legacy GN_NODE/OUTER paths; `STWO_RV64_M8_GN_INSTALL=1` is now the only selector of outer node jobs.
Native request-only reachability is therefore insufficient to prove the old stack dead.

- [ ] Build immutable class geometry from admitted source/capture authorities directly.
- [ ] Give FIXED, twiddles, programs, descriptors and encoders a native installation owner.
- [ ] Preserve authority identities, output bytes and checked allocation schedules.
- [ ] Remove the temporary proving/recording path only after equivalent construction is accepted.
- [ ] Preserve unknown-block rejection and explicit new-block setup accounting.
- [ ] Replace environment-selected internal transitions with typed owner calls, not new aliases.
- [ ] Keep library/runtime paths bound to the existing pinned asset manifest.
- [x] Inventory every consumer before removing feeder/provider symbols (feeder, provider and both hybrid request modes deleted).
- [ ] Inventory every consumer before removing owner-callback symbols.
- [ ] Delete retired code and its retired tests together; retain all live lifecycle tests.

The later installation Owner is backup-only:
[driver_install.zig at the published backup](https://github.com/teddyjfpender/stwo-zig/blob/0fd4c01b25b38be507165645366ba71a3d3b9b55/src/integrations/riscv_cuda/rv64/jobs/driver_install.zig).
Do not add a broken relative link to it or assume the merge prefix contains that file.

## 9. Apply backup work as coherent, reviewable batches

Use one canonical checkout and compare the backup against the actual merged 51897 prefix.
Do not transplant the backup's prepared default-on setting into the merge checkpoint.

1. Apply maintained fixture relocation with byte hashes, provenance and consumer updates together.
2. Apply historical report retirement with its published archive, literal deletion list and completion ledger.
3. Apply developer routing and mandatory test-owner wiring together with their preserved test bodies.
4. Apply setup-miss ownership, capacity-array ownership and partial-failure rules as one reviewed transaction.
5. Apply the immutable-warm/probe split with truth prefix-layout/resource changes and all failure tests.
6. Apply the installed-resource Owner migration with every runtime consumer and cleanup path.
7. Apply fresh CPU receiver concurrency with output isolation and quarantine-drain tests.
8. Apply sampled-memory collection, shared validation and all gate/basket consumers together.
9. Apply later driver/capture test-owner edits only after their exact final host result is known.
10. Re-pin source, binaries, runtime and workload before any new hardware claim.

Each batch needs an explicit subtraction budget, source-diff review and appropriate tests.
Do not cherry-pick only the success path of an allocator, cancellation or test-discovery change.
If overlapping commits cannot be applied cleanly, reconstruct the final owned change and remeasure its cost.
Keep the source backup ref until every unique change is either accepted or explicitly archived.
The latest reported cumulative backup code delta is net **−66,991 lines**, with no new flags or scripts.
That is a backup accounting result, not deletion credit for code merged in the 51897 prefix.

## 10. Installation, request and failure ownership checklist

The public contracts remain [gpu_native.zig](rv64/jobs/gpu_native.zig)
and [api.zig](rv64/jobs/api.zig); resource units live in [resources.zig](rv64/jobs/resources.zig).

- [ ] Installation owns classes, capture capacity, slabs, event pools and immutable resources.
- [ ] The service owns copied worker/capacity arrays; borrowed workers/ops/factories outlive it.
- [ ] Immutable warming uses its own actual footprint, not a padded request estimate.
- [ ] Existing persistent resources and known future class reservations count before warm allocation.
- [ ] Retire old temporary arenas before observing free capacity or starting probes.
- [ ] Probe capacity respects configured caps, reserves, graph allowance and resident ownership.
- [ ] Fixed-pool capacity excludes the small slab and outside `cudaMemGetInfo` headroom.
- [ ] Growing-pool accounting never credits already-owned memory as reusable workspace.
- [ ] Both placement probes complete before measured peaks replace request padding.
- [ ] Final admission uses the updated class peaks and the actual persistent census.
- [ ] A rejected preflight preserves the existing usable service.
- [ ] A failure after old-runtime retirement leaves an explicit terminal service.
- [ ] Every partial acquisition has one owner and reverse-order cleanup.
- [ ] Drain all dependent futures, callbacks, streams and requests before releasing their storage.
- [ ] Preserve logical allocation peaks separately from physical observations and enforced capacity.

## 11. GPU work is deferred until funding and preservation checks pass

The last recorded pod is `cps13bvat3xhdo`, stopped with its 80GB pod volume preserved.
That volume is **not** an independently retained network volume.
Compute was stopped after prepaid credit exhausted; no top-up, paid restart or replacement pod is implied.
Stopped storage can still accrue charges; preserve the volume without presenting it as permanent custody.

- [ ] Obtain explicit funding/restart direction before paid work.
- [ ] Rediscover the endpoint; historical SSH coordinates are not durable identifiers.
- [ ] Read the preserved build/runtime manifests and verify all required asset hashes.
- [ ] Copy missing raw evidence to the user-approved local laptop archive before new runs.
- [ ] Verify archive bytes before clearing any evidence or changing the pod.
- [ ] Preserve the active source/cache relationships; do not delete a cache while a compiler uses it.
- [ ] Check the filesystem that actually holds benchmark outputs before claiming free-space recovery.
- [ ] Acquire build locks; let hardware harnesses acquire their own GPU lock.
- [ ] Freeze source throughout builds, gates and measurements.
- [ ] Stop on the first failed acceptance gate; preserve the exact failure instead of retrying through it.

## 12. Ordered GPU-native promotion gates

The 51897 merge checkpoint keeps **`STWO_RV64_M8_GPU_NATIVE=0` by default**.
Explicit native qualification uses `GPU_NATIVE=1` with the required jobs/runtime bindings.
The later backup prepared default-on source; treat that setting as an unqualified candidate, not permission to publish it.

1. Rebuild and pass the current-source guarded default/native correctness gate.
2. Run the canonical quiet interleaved **3+3 on 24628607** against the preserved default.
3. Run the same canonical **3+3 on 26235168**, the median-sized basket block.
4. Pass a genuine same-service new-block setup miss, including the **4-segment to 7-segment** transition.
5. Pass the complete **15-block GPU-native basket**, with every block and both cold/warm proofs.
6. Review all proof, semantic-negative, identity, resource and timing evidence.
7. Flip the default in one source/validation/registry/documentation change and rerun its gate.
8. Retire legacy paths only after the promoted replacement scope is complete.

The setup-miss implementation can land before its hardware gate, but remains explicitly unqualified.
Keep source identity stable within a comparison; never combine results from different allocator candidates.
Never lower a ceiling, profile, corpus, fixture pin or test floor to obtain acceptance.

## 13. Setup-miss and complete-basket acceptance

The service boundary is [driver_serve.zig](rv64/jobs/driver_serve.zig).
Request execution remains [driver_request.zig](rv64/jobs/driver_request.zig).

- [ ] Warm the initial admitted block, then submit a different admitted block to the same process.
- [ ] Drain both request parities before replacing setup-owned resources.
- [ ] Exercise the actual 26235156-to-24628607 growth case where the workload permits the recorded 4-to-7 geometry.
- [ ] Include median-block geometry and a further same-service request after the miss.
- [ ] Refuse a block outside the pinned manifest without hidden fallback.
- [ ] Report `setup_ns`, request wall and setup-plus-request separately from queue/drain/client latency.
- [ ] Verify cold/warm payload parity and source-authority pins after the setup transaction.
- [ ] Use all 15 maintained basket entries; diagnostic subsets are not a regression-set pass.
- [ ] Require 30 fresh CPU accepts for a one-round native cold/warm basket.
- [ ] Keep artifact-store deletion/quarantine and CUDA-disabled receiver isolation effective.
- [ ] Maintain independent receiver output roots and deterministic verdict order.
- [ ] On receiver failure, drain all verification work before restoring quarantined storage.
- [ ] Preserve the selected semantic-negative corpus; resource failures do not count as semantic rejection.
- [ ] Record missing/failed arms and stop the qualification path rather than tolerating them.

## 14. Physical memory: the ceiling is not the observed peak

The guard [rv64_m7_gpu_budget_guard.cpp](../../../scripts/rv64/rv64_m7_gpu_budget_guard.cpp)
constrains physical availability; its successful lifecycle does not measure a process peak.
Allocator high-water logs cover their allocator scope, not all CUDA modules, stacks and contexts.
The process observer's default-pool high-water is also not total process residency.

The backup adds evidence plumbing through the existing DeviceMonitor and shared validation:

- Monotonic service/request boundaries tied to actual request IDs and proof paths.
- Explicit guard-held bounds; samples freeze before guard release.
- Per-GPU ordinal/UUID identity, counts, first/last samples and maximum gaps.
- An immutable `resource-final.json` hash linked into service and acceptance receipts.
- Separate measurement and cleanup failures, with guaranteed guard-release attempts and lease cleanup.
- Historical evidence marked unavailable; new native acceptance fails closed if required coverage is missing.

Label these results **whole-device sampled observed maxima INCLUDING guard memory**.
The target sample interval is 200ms; timestamps mark observation of the `nvidia-smi` result.
They are not exact hardware instants, exact peaks, process-exclusive peaks or SM occupancy.
Do not subtract guard bytes outside a verified held interval; the current plan reports them separately.
No current-source physical observation is qualified until a funded accepted run actually produces it.

## 15. Preserve recovery data without overstating what is local

The user accepts the laptop as the archive/raw-evidence destination; no cloud upload is required.
Local custody is under `ge-artifacts/rv64-gpu-hygiene-20261108/consolidation` outside the repository.
That path is machine-specific and is not a portable test input or CI dependency.

Verified locally: 338 recovery payloads, **21,557,449 bytes**, with all manifest hashes matching.
The separate manifest is 54,614 bytes; its SHA is `8e6a206805e9b9281663368a5c240e95cd5e109e9c0b6f2b0575e903ad4994d7`.
The 164 tarballs contain 1,478 members / 65,609,983 unpacked bytes; no unsafe entries were found.
No secret-pattern indicators were found; this is not a comprehensive guarantee against sensitive data.
Working patches, personal paths, branch identities and recovery topology remain sensitive categories.

Fifteen targeted local terminal/receipt files were hash-inventoried, totaling 6,243,002 bytes.
The production26 terminal tar is verified, but contains only five files, not a complete service archive.
Accepted 51897 default/native gate metadata is local; four fresh accepts and parity are recorded.
That does **not** prove that every corresponding payload, receiver log or capture is local.

Of the frozen 39 payload artifacts, only three binding JSON artifacts / 716,668 bytes were verified local.
The other **36 binary/proof artifacts / 83,973,536 bytes** were absent from the targeted local fixture and archive-object paths.
Keep their hashes and pod references; do not claim byte recovery from a manifest or public ref alone.
Raw accepted-service producer/receiver logs, timelines and installation captures also remain incompletely copied.
The stopped pod's current filesystem contents have not been reverified.

- [ ] Preserve the volume until the specific missing evidence is retrieved or explicitly accounted for.
- [ ] Hash every recovered file against the recorded pin before counting it as local.
- [ ] Keep failed terminal evidence; do not rewrite historical verdicts.
- [ ] Update the archive index with actual custody locations and remaining gaps.

## 16. Tagged archives and historical report retirement

Published recovery refs include `archive/consolidation-20261108/recovery-index-v1`.
The historical receipt snapshot is `archive/receipts-20261108/pre-retirement-v1` at `7c0686ae7c21be9bd5675f3d7b8f2b8439a07713`.
The later safety recheck verified 242 distinct archive tags and 484 tag/peeled records.
Those later audit facts must not be mistaken for a claim that the merge checkpoint's index was rewritten.

The backup retired 7,004 report files / 1,570,076,423 bytes after preservation and a literal-list audit.
It moved 34 live fixtures byte-identically; those moves receive no code-removal credit.
This report/fixture retirement is **not merged by the 51897-plus-roadmap handoff**.
Apply its full archive/provenance/consumer closure, not only its deletions.

- [ ] Keep current receipts and live site/benchmark history until their owners migrate them.
- [ ] Use literal written names and expected-head checks for any future branch retirement.
- [ ] Verify remote tag objects and peeled commits before retiring source refs.
- [ ] Never delete evidence merely because it is old, large or on a stopped pod.

## 17. Performance work after promotion: feeding, then architecture

The first target is measured late feeding, not a smaller FFT or Merkle kernel.
The reported diagnostic counters were about **9.65s enqueue** and **5s gated per GPU**.
They are attribution clues, not qualified latency measurements for the current candidate.

- [ ] Use existing native ranges to identify capture-streaming and host-prestage waits.
- [ ] Separate host enqueue ranges from projected GPU execution and transfer activity.
- [ ] Account for peer-copy host staging separately from ordinary proof-result D2H.
- [ ] Finish whole-node graph replay only with address/epoch invalidation and teardown tests.
- [ ] Measure per-request uploads and enforce the intended resident-class boundary.
- [ ] Charge cold/new-block class construction, rather than hiding it before the timing window.

Then follow [handoff section 5](../../../design/riscv/rv64-m8-handoff.md#5-take-large-architectural-steps-not-small-kernel-tweaks):

1. Complete GPU-native ownership and retire hybrids/legacy callbacks.
2. Finish packed residency, device geometry, copy-lane ownership and P1 memory work.
3. Evaluate equal-height commitments/column stacking with a proof-format and soundness note.
4. Evaluate native GKR for the remaining lookup-column scope.
5. Consider larger segments and fan-in changes only after their memory gates pass.
6. Evaluate recursion diet choices with independently checked security parameters.
7. Make class shapes stable enough to remove production new-block setup from the hot path.
8. Treat MLE/GKR+WHIR or wider GPU placement as separate architectural proposals.

Each step needs its own whole-system falsifier, acceptance scope and before/after evidence.
No 4–6 second result is promised for 24628607 or for the median/large blocks.
Report median, tail/large-block and full-basket behavior; do not use the small dev block as the headline.

## 18. Batch budgets and definition of done

Before editing, record code added/removed/net, flags added/removed/live and scripts added/removed.
Record documentation, configuration and receipt changes separately.
File moves, archived source snapshots and wrappers do not count as production-code deletion.
The default cleanup budget is subtractive; positive code growth needs an explicit owner/invariant justification.

A hygiene batch is complete only when:

- [ ] Its literal scope, preserved source and subtraction budget are recorded.
- [ ] Live tests and package/default developer routing still discover the real bodies.
- [ ] Relevant host checks pass on the final source, with resource-limited checks kept open.
- [ ] The required default hardware gate passes, or delivery is explicitly pending hardware.
- [ ] Static findings decrease without new baselines or ceiling changes.
- [ ] Flags actually lose their readers and consumers before registry deletion.
- [ ] Source, binaries, runtime and workload identities match the receipts being cited.
- [ ] Failures, cancellations and partial teardown retain their original guarantees.
- [ ] Reviewers can distinguish merged, backup-only and pending changes without reconstructing chat history.

The entire phase is complete only after static green, the strict flag target, ordered promotion,
the complete legacy sweep, current-source CPU/corpus acceptance and the qualified benchmark set.
Neither merging PR314 nor finishing this document closes those remaining obligations.

## 19. Optional local audit pointers and portable history

The following machine-local receipts help reconstruct this snapshot; none is required by CI:

- `consolidation/remaining-hygiene-current-inventory-v1.json`: earlier literal 120/119 inventory; refresh for the later 118/117 state.
- `consolidation/live-flag-removal-readonly-plan-v1.json`: all 260 names, actual consumer lines and the 108-candidate plan.
- `consolidation/local-recovery-evidence-audit-v1.json`: recovery hashes, sensitive categories and missing raw evidence.
- `consolidation/installation-owner-checkpoint-recovery.json`: source bundle custody, explicitly unqualified.
- `consolidation/install-phase-final-cost-and-validation.json`: bounded host evidence and outstanding full-runtime/hardware checks.
- `consolidation/metal-resource-roots-ownership-v1-preservation.json`: 80 preserved named test bodies and owner wiring.
- `consolidation/native-polynomial-aot-owner-v1-preservation.json`: exporter CLI and four preserved authority test bodies.
- `consolidation/driver-test-owner-bounded-all.json`: fake-device driver evidence only.
- `consolidation/capture-fixture-bounded-host.json`: the resource-cap stop, not a pass.

Use the published archive refs and source commit IDs above for portable history.
For backup-only implementation, compare the complete committed batch against the merge prefix before applying it.
On every revision, refresh status fields from actual receipts and keep older measurements explicitly historical.
