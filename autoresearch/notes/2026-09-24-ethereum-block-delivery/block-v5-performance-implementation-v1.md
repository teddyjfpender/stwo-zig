# Performance implementation and evidence ledger

This retains all 22 requirements in [the original roadmap](block-v5-performance-roadmap-v1.md), corresponding to the user's 17 grouped priorities. The full goal remains active. Source implementation, focused qualification and measured complete-block performance are distinct. The stopped 67-segment mainnet-v3 run has not been restarted; no segment proof runs are authorized by this engineering batch.

## Current implementation

- Production defaults select execution-local register custody for native and caller accesses. Sorted RAM contains only writable-memory accesses. Ordered windows, exact register clocks, native/caller projections and independently pinned endpoints must close per window. Zero requester census produces genuinely absent RAM/range families. Unit custody/cancellation/source gates pass; a real complete mixed/zero-RAM bundle is still unqualified.
- Ordinary-memory, native lookup and external caller quotient evaluation share bounded immutable column recovery. Exact domains, policy, full degree bounds, concurrent reuse and bounded fallback are checked. A genuine conditional load/store filtering bug was fixed in the canonical typed projection.
- One sealed range16 inverse table is shared by every memory instance and range provider. Exhaustive 65,536-value parity, active/unused poles and challenge mismatch checks pass. Fresh memory/range proof verification passes with production provider reuse.
- Word protocol v4 uses 12 fixed, 27 main and 68 interaction columns, 63 constraints and degree four. Predecessors use nine authenticated shifted main columns plus independently pinned public boundaries. Packed u64 ordinal selectors use four16-bit limbs. Global first/last selectors derive from pinned claim geometry. Fresh memory/range/global endpoint proof verification and full-u64 fixed-selector parity pass. The prior v3 stage used22 fixed columns; stored timing evidence identifies its source snapshot.
- Word quotient rows use packed QM31 and disjoint shared-worker tiles; claim normalization and public endpoint constants are prepared once. Scalar OODS and packed equations agree. Production driver and pool callbacks compiled after witness source/direct-recursion integration. Latest v4 quotient rows measured55.897ms scalar versus14.351ms with three workers,3.895x; this remains an isolated row kernel.
- Replay uses bounded262,144-event chunks, stable radix sorting and32-way heap merging. Singleton groups carry their files without rewriting. Exact read/write traffic and heap-buffer statistics are reported. Adversarial ordering, duplicates, unsigned radix boundaries and33-run/two-pass tests pass. The planned57.9M-event RW workload would require221 initial runs/two merges; this is not a new mainnet measurement.
- Production collection stages canonical native/caller main cells while the first guest witness is live. Later native loading rebuilds main aliases/counters, recommits against retained roots and moves that PCS into the producer. Caller reconstruction restores all19 typed blocks, private tables, SHA metadata and counters, then reuses its mandatory recommit through the original warm proof transaction. The driver no longer opens a second runner pass. All native/caller custody, root/counter, mapped-codec and lifetime checks pass. The driver compiled without executing segment proofs; the latest narrowed-layout kernel/codegen gate also passed. No segment proof has been run.
- Leaf publication feeds ready parents to the exact incremental forest. Borrowed policies remain alive through worker joins; every driver allocation is charged to a synchronized40GiB aggregate heap budget. Thread stacks and RSS are separate. Readiness/abort gates pass, but real assembled forest overlap/setup reuse remains unqualified.
- Direct arithmetic cohorts3/4/5 passed legacy-column/fixed-field and ownership parity. Direct emission now also covers source cohorts6/8/9/10/13–17 and native PCS output cohorts12/18/19; their legacy parity/admission/ownership checks pass. No fresh recursive proof with these changes has been run.
- Four-lane CPU BLAKE3 batches canonical framed nodes and PoW final compressions. Seven independent compression/chunk/frame/tree/nonce parity checks pass. Short kernel samples favor batching but vary; they cannot establish a whole-proof speedup. Four-leaf direct/packed commitment hooks now handle complete BLAKE3 message trees through shared dispatch;9 focused leaf checks and8 node/PoW/compact regression checks pass. Uniform columns allocate no packing scratch; mixed columns use bounded four-leaf scratch. A16384-leaf equal-work builder diagnostic measured2.338x at170 uniform columns and1.924x at92 mixed columns. Streaming state and variable transcript frames retain their existing paths; complete prover timing is still unmeasured.
- Canonical native local fusion now uses version2: program, table/state/register/clock projections and ordinary packed access share one interaction tree, composition and FRI. Fresh native base verification remains separate. Assembly binds both exact rosters, native/access roots and Frame; independent transport bounds both claim arrays and selects the exact three/four-trace-tree grammar. Program/global joins consume the same scoped fresh receipts without loading separate request/projection/opcode artifacts. Zero RW uses a real projection proof with typed memory absence; both-empty loads only genuine native. Equation/mask/absence codegen passed 11/11; transport/custody/API gates passed 15/15. No joint STARK or complete bundle has been run.
- Independent caller, sorted memory/range, ROM and lookup jobs now run through a bounded admission queue after the common seal. Jobs share the aggregate 40 GiB heap limit and the driver's helper pool, including recursive leaf workers and incremental forest lanes. Errors cancel queued work and propagate at owned proof boundaries; all jobs join before manifest publication or owner destruction. The actual driver and report CLI bodies generated without being called; shared-binding/concurrent-allocation/reservation/failure/abort gates passed 19/19. Reservations are admission estimates, not measured per-job heap peaks. Complete proof overlap, resource sizing and performance remain unqualified.

- Caller projection/access fusion has an isolated five-commitment producer and fresh receiver. Eleven nonproving equation/mask/admission/API checks pass across all caller types. Canonical pipeline, independently bounded file transport and scoped global joins are wired; focused integration15/15 and actual driver/CLI body generation13/13 pass. No complete fused proof is qualified. Subsequent two-event RAM integration changes those shared consumers and requires its own gate.
- The earlier four-program word/range GPU snapshot passed seven CPU parity/schema checks. The new canonical six-program word/range/lane catalog passes five lane equation/fraction/ownership checks and six strict source-product admission checks. A real Metal library, actual native bridge and production quotient/PCS dispatch bodies compile; CUDA source and actual NativeSession compile, and all13 source kernels pass production admission. Exact receipts are in `cpu-performance-gates-v1/ram-lanes-gpu-*`. No GPU execution or throughput has been measured. Canonical lane device witness/interaction producer integration is now wired. Its CPU metadata/census/claim/alignment gate passes4/4, and actual collection/replay/requester/range-provider/original-STARK producer bodies compile together with the regenerated real Metal library. Shared heap/external admission and teardown passed16 device-free checks; updated RAM metadata4/4 plus actual Metal RAM/quotient/PCS production body and real library compilation also pass. Generic FRI ownership, inverse leases/LRU, quotient private constructors and generic PCS LDE scratch now pass their scoped device-free/body gates. Other constructor families, hardware execution and full downstream residency remain unqualified.
- Two-event strict-RAM source preserves degree four with 170 cells per physical row:85/event versus107 at full occupancy. It uses117 equations per row:58.5/event versus63. Six focused nonproving checks now pass, including actual degree4, masks/domain/OODS and streaming2051-event odd-tail parity. The real proof/planner/receiver and canonical mode1 integration are now source-complete. The assembled lifecycle/production gate passed25/25 after correcting clock fixtures, physical FRI preflight geometry, early proof/resource caps and exact provider-roster bounds. It includes genuine empty source closure without proof-loader calls and real producer/driver/store/global body generation. Replay now delegates its phase budget checks to the same Proof.Limits authority instead of duplicating those calculations; this subsequent cleanup is format-checked and needs the next focused producer gate. The recorded57,876,727 writable-memory events plan as7 lane instances versus14 word instances at physical rowlog22. A same32768-event CPU comparison passes exact aggregate bus/counter parity: interaction median32.327ms word versus21.500ms lanes; trace/interaction value arrays14,024,704 versus11,141,120bytes. These exclude commitment/STARK/FRI/recursion, shared inverse setup and process peak memory. Actual fresh lane proof and complete canonical bundle remain unqualified.

## All requirements and remaining acceptance

| ID | Requirement | Evidence and remaining work |
|---|---|---|
| 1 | Execution-local register custody | Canonical source and unit/source closure gates pass. Genuine mixed caller and zero-RAM complete detached proofs remain unqualified. |
| 2 | Constant/immutable specialization | Explicit authenticated native local-zero recipe passes12 focused checks, including a genuine three-instruction CPU fixture and full-degree LDE recovery; explicit caller recipes initially passed4, including genuinely derived SHA identity; the expanded explicit profile/component/mask/domain/window/tracker/staged-counter gate now passes13 checks. Native GPU capability namespaces7/8 are distinct from retained provider caches, and actual exporters now cover all17 local-zero direct/lookup families in the authenticated kernel inventory;6 source admission checks pass. Canonical caller profile/witness/window/tracker migration is active and x0 elision remains disabled. Isolated authenticated input classification now passes14 focused checks plus the Debug census gate, including actual producer and internally fresh native/caller receiver bodies. Additive immutable Selection and late actual-source Proposal binding now pass20 focused checks, including tiny CPU borrowed-prefix/classifier commitment replay and allocation failures. Caller source-field fusion now passes11 focused checks including authentic source/mask/OODS parity, immutable write rejection, exact provider census/caps/allocation rollback and actual producer/fresh receiver/warm body compilation. Canonical fusion, transport and mutable-RAM reduction remain incomplete. |
| 3 | Shared column recovery | Exact-domain, full-degree, concurrency and bounded fallback gates pass; conditional RW projection gates pass. Complete production performance/closure remains unmeasured. |
| 4 | SIMD and parallel quotient | Equation/row/lease gates pass; isolated v3 row kernel was3.82x scalar with three workers. V4 row kernel measured3.895x with three workers. Complete proof time remains outstanding. Typed GPU equation/fraction programs now compile into a real Metal AOT library; hardware execution remains outstanding. |
| 5 | Narrow memory/range width | Canonical v4 fixed12/main27/range17/interaction68 implemented; fixed/u64/mask/fresh proof gates pass. Complete block/resource qualification remains outstanding. |
| 6 | Same-root proof fusion | V2 native projections plus ordinary-memory four-tree source, typed absence, canonical seal/transport/driver/global consumer wiring implemented.11 equation/mask/API and15 transport/custody checks pass. Genuine joint proof, complete bundle and performance remain unqualified; caller fusion has11 passing isolated checks and canonical15-test/codegen13-test gates. Subsequent lane migration still needs qualification. |
| 7 | Multiple operations per row | Existing word representation packing remains. Two-event strict RAM equations/masks/domain/streaming gate6/6 passes; canonical integration and focused admission/body gate25/25 are qualified at their recorded source snapshot; actual fresh proof remains outstanding. Multiple execution lanes and ordered equal-value pairing remain incomplete. |
| 8 | Capacity selection after narrowing | Resource-aware RAM sizing minimizes exact instance count then committed row area, without widening independent limits;6 focused checks pass. The canonical capacity producer/receiver bodies compile and16 product checks pass. Whole-PCS peak memory, larger real proof geometry and complete-block performance remain unqualified. |
| 9 | Generate guest witness once | Native/caller staging and production source replacement implemented in source. Root/counter/lifetime and genuine SHA/Keccak/signer reconstruction gates pass; real complete proof acceptance remains outstanding. |
| 10 | Independent-family pipeline | Bounded caller/memory/ROM/lookup coordinators, reservation admission, one shared aggregate heap/helper pool, cooperative failure boundaries and joined publication are wired.19 queue/binding/driver/CLI codegen checks pass. Real proof overlap/resource qualification remains outstanding. |
| 11 | Incremental recursive forest | Stream and production publication source wired; readiness/abort/caps pass. Fresh odd/exact complete forest overlap qualification remains outstanding. |
| 12 | Capacity-based native setup | Distinct B5CT/v1 dynamic-activity protocol, exact prefix-count equations, capacity-only fixed rows, late admission and actual producer/fresh receiver bodies pass13 focused nonproving checks after correcting canonical count-column placement. Actual one-entry fixed-commitment reuse now passes9 checks, including tiny CPU shared-buffer/coefficient, cold/warm transcript, owner-before-lease and allocation-failure parity. Distinct capacity catalog/owned wire and real owned/borrowed capture bodies now pass10 scoped checks. Actual-policy capacity durable publication, owned loaders and shared non-overwrite file I/O now pass11 focused checks with literal artifacts. Capacity recursive equations/public counts/independent admission/ownership now pass10 nonproving checks plus actual producer/fresh receiver/cache/normalization body compilation. Typed capacity exact forest/staging/detached manifest now share the existing topology and pass7 focused metadata/early-load checks plus actual dual default/capacity body compilation. Shared real NativeV3/capacity ROM and caller closure, plus one independent admitRoster preflight, now compile as an actual dual-body object without being called. Typed shared Memory/Table/Global/Complete/Detached contracts now pass12 focused checks plus actual dual default/capacity body compilation. Capacity fused equations/source/selector/wire/ownership and actual producer/fresh receiver/stage/store bodies now pass 24 focused nonproving checks, including shared runtime lookup-OOM parity/recovery. Native/fused durable stores share one implementation and pass21 focused ownership/transport/body checks. Canonical producer/receiver now select the genuine capacity stack and16 nonproving product/body checks pass. The shared authenticated cache passes17 checks including configured-cap cold fallback and malformed-source/OOM rejection. Successful fresh complete proof and performance qualification remain outstanding. |
| 13 | Authenticated parent setup/worker reuse | Bounded authenticated setup cache and dynamic admission rebind implemented. Canonical recursive leaf/forest coordinators now borrow the driver's helper pool; identical binding reuse and different-pool rejection pass. The canonical native cache now reuses one lazily started request thread and joins it before teardown;6 focused concurrency/lifetime/actual-body checks pass. Capacity callbacks now feed one bounded ordered capture coordinator;10 ownership/backpressure/failure/join/body checks pass and the actual canonical driver bodies compile. Real cache-hit/overlap detached forest qualification remains outstanding. |
| 14 | Direct recursive columns | Arithmetic direct-column parity/ownership passed. Opening/PCS/public-source direct emitters and parity/ownership gates pass; Pack cohort11 emits directly and inventory borrows committed columns; boundary2 initial rows release before matcher scratch, then public terms append directly. Selector-use scratch is reused and freed before the audit; audit masks/counts now actually free before arithmetic construction. Native PCS matching stores only real candidates and reuses one cold plan across counting/emission. Twelve parity/ownership/allocation/mutation checks pass including a65,536-node graph. Assembled native/execution and owned/borrowed parent bodies compile without being called (2-test gate). Scalar12 and upstream execution sample columns are now canonical; the focused12-test parity/mutation/allocation-failure/actual-parent-body gate passes after fixing partial owner publication; The subsequent canonical claim/challenge/terminal/public-route migration passes18 focused upstream+prior parity/mutation/allocation/actual-parent-body checks. Canonical FRI answer/query/opening sources now emit direct columns and release graph-sized expected/use scratch before publication;24 focused PCS+prior source/ownership/actual-parent-body checks pass. Canonical path/projection/opening/public-coordinate/root/nonce source owners and boundary2/route7 assembly now pass32 focused parity/mutation/allocation-failure/actual-parent-body checks. Canonical bounded transcript and upstream Merkle nonhash materializers now emit directly;39 focused source/ownership/actual-parent-body checks pass with72 matched source hashes. Noncanonical dense parity and original standalone routes remain. Fresh recursive proof qualification remains outstanding. |
| 15 | Batched CPU BLAKE3 | Production node/PoW and shared direct/packed four-leaf batches are wired. Nine leaf tree/framing/mixed-lifting/tail/ownership/actual-root checks and eight existing node/PoW/compact regression checks pass. Uniform170-column16384-leaf builder median18.453ms versus7.891ms (2.338x); mixed92-column10.367ms versus5.387ms (1.924x). No whole-proof inference; retained streaming/transcript batching and complete prover performance remain outstanding. |
| 16 | Resident GPU proving | Typed word/range parity7/7 and real Metal AOT/bridge compilation pass. CUDA runtime contracts6/6, actual NativeSession object compilation, product admission4/4 and real11-entry source staging pass; no CUDA binary or hardware execution is qualified. The actual Metal secure quotient/PCS seam now compiles and six-program word/range/lane exports pass5 CPU parity/ownership checks; strict catalog6/6 and actual13-entry CUDA source admission pass. Canonical lane resident witness/interaction producer is wired with4 passing CPU ownership/census tests and actual original-STARK production body/offline Metal library compilation. Shared heap/external RAM/quotient accounting passes16 device-free contracts,4 RAM metadata checks and actual Metal producer/quotient/PCS body/library compilation. Native GPU inventory now exports actual legacy/local-zero capabilities, rejects duplicate cache IDs and validates each authority before deduplicating executable DAGs;6 source admission checks pass and the real94-kernel Metal library compiles offline. Generic device FRI/cache/shared-arena ownership now passes16 device-free checks, actual Metal factory/fold/cascade/fused-quotient/drain/deinit body compilation and Objective-C syntax. Ordinary allocator compatibility now passes23 device-free strict/uncapped ownership/failure checks and actual ordinary/strict fold/cascade/fused/shutdown body compilation; supplied shared budgets remain strict, ordinary inverses ephemeral. Backend shutdown drains joined FRI/composition caches. Immutable inverse leases now pass11 same-budget reader/proposal/factory/completion concurrency checks plus23 ownership regressions and actual bank/fold/cascade/fused/shutdown body compilation; global locks no longer span factories or GPU waits. Bounded multi-geometry inverse reuse also passes18 lease/LRU plus23 ownership checks. Generic PCS LDE private copies now reserve at7 constructors and follow actual queued/joined receipts, with7 device-free contracts and full generic PCS body compilation. Sampled coefficient/OODS and host/resident barycentric scratch now pass9 device-free budget/wave/receipt checks plus actual runtime/backend body compilation and full Objective-C syntax. Shared-budget coefficient ingress uses charged copies rather than unauthenticated borrowed aliases;64 MiB runs and256 MiB joined waves bound streaming targets. Executed proofs, hardware overlap, producer-specific teardown and scheduling remain unqualified. Hardware parity, full downstream residency and other family coverage remain incomplete; CPU/compile gates do not prove GPU acceleration. |
| 17 | GPU prefetch/completion/batching | Dependency-aware persistent GPU scheduling remains incomplete. |
| 18 | Multi-GPU graph execution | Work/VRAM balancing and hardware acceptance remain incomplete; no NVIDIA benchmark host currently exists. |
| 19 | Reduce capture/staging repetition | Duplicate file-pin storage removed; staged native/caller PCS reuse source implemented. Core borrowed capture gate passes6/6: actual successful literal PCS ownership/owned-path/transcript parity, unchanged capture after original input poisoning/free, every allocation failure, early/late rejection and multi-step FRI scratch cleanup. Existing FRI allocation-error mapping, sparse double ownership and folding leaks were fixed. Native recursive leaf source removes its redundant encode/decode cycle while retaining fresh verification and independently owned capture; actual native borrowed verifier and leaf callback body generation now passes4 focused checks without calling either function. Successful full-STARK capture and complete bundle qualification remain pending. Canonical native serialization now writes directly into one capped envelope, removes the temporary postcard copy and preserves exact NativeV3 bytes; literal wire/deep ownership/allocation-failure tests pass within the10-check capacity transport gate. Wider capture repetition remains incomplete. |
| 20 | Recursive closure of all globals | Genuine range16, strict RAM-lanes, ROM and complete six-table lookup verifier/public-bus/transcript/admission source has 41 distinct focused checks across pinned snapshots. Full native-capacity fused recursion now passes19 scoped checks with actual capture/publication/cache/receiver LLVM bodies; native/caller fused transport and protocol share one implementation. Caller-fused original equations/transcript/admission/ownership pass the full retained-body batch plus a fixture-only correction; current assembled semantics also compile. Exact heterogeneous coverage metadata passes6 checks, but metadata is not cryptographic coverage. Complete streaming memory-source equations pass12 checks (SHA/BLAKE3, complete images, full u64 clocks, symbolic/zero/fault checks); actual source proofs/aggregation are still pending. Shared scalar/symbolic global joins pass4 checks and actual canonical producer/receiver semantics compile. Both initial caller-arithmetic custom-runner attempts executed zero tests and are explicitly disqualified; both corrected policies retain genuine full verifier/publication bodies and pass their narrow true-log18/policy correction (12 distinct checks per pinned combined snapshot). The original caller producer now has a recursive pipeline with one fused proof owner and capture release between parent builds;15 scoped ownership/admission/body checks pass. Source first-round lifecycle passes8 checks; actual typed execution/caller recursive file transport passes11 scoped checks with all three real typed receiver/publication bodies retained. Fresh all-family recursion, authenticated source aggregation and complete global closure remain incomplete. Complete detached verification remains mandatory. |
| 21 | Shared range16 inverse table | Exhaustive all-value, zero-pole/mismatch and real shared memory/range proof gates pass. Complete-block timing remains outstanding. |
| 22 | Reduce replay/sort traffic | Register filtering, larger bounded chunks, radix and32-way singleton-preserving heap merge implemented; adversarial/statistics gates pass. Full-block traffic/resource measurement remains outstanding. |

## Persisted qualification and measurements

Evidence is retained in [cpu-performance-gates-v1](cpu-performance-gates-v1/). Full logs define their scope; test counts include transitive tests where present.

- Initial inverse/packed/worker gate:32/32 passed. Initial memory proof:1/1. These precede protocolv3/v4.
- Word36 production-driver/row-kernel gate:16/16.32768 rows: scalar60.369ms, packed44.951ms, three workers15.716ms. It excludes recovery, commitments, FRI, PoW and recursion.
- Transport/cache/register/direct-column gate:25/25; no execution segment proving.
- Word27 v3 driver/kernel gate:19/19.32768 rows: scalar54.278ms, packed40.063ms, three workers14.214ms. Median of three; all outputs agreed. These measurements predate the previous-opening mask and fixed12 changes.
- Word27 v3 fresh proof:2/2. Masked fresh proof:2/2. Explicit mask/OODS/full-gather parity:2/2.
- Word v4 fixed12/mask/fresh proof gate:5/5. Canonical equations are verified under diagnostic8-query/zero-PoW security in this focused proof; it is not a full canonical-security block result.
- Native program/lookup/state/register/clock fusion:7/7 nonproving masks, OODS/domain equation parity and concrete producer/fresh-receiver code generation. Genuine fused proof and production transport/global consumer integration remain unqualified.
- BLAKE3 compression/frame/chunk/tree/nonce gate:7/7. Bounded node/PoW kernel diagnostic:1/1; raw four-sample ABBA timings and equal-output checks are retained, with no complete-prover extrapolation.
- Witness/direct custody:27/27 passed, including genuine SHA/Keccak and active signer/secp reconstruction, original physical roots, signed counters, complete SHA main/fixed rows, mapped multi-buffer codec, negative admission/root/cap cases, and direct column transfer/release. Debug multi-buffer gate:2/2.
- The driver compile-only test passed inside the preceding19-test gate whose two fixture/codec failures were subsequently corrected and qualified above. Latest v4 driver/kernel gate:13/13 passed, including actual driver body generation without calling it.32768 rows: scalar55.897ms, packed40.516ms, three workers14.351ms. These are not whole-block timings.
- Full native/access fusion V2:11/11 nonproving equations/masks/identities/typed-absence/codegen. Independent-family driver/CLI and queue/shared-pool custody:19/19. Full-fusion transport/policy/global API and durable file custody:15/15, including independently capped secondary claims rejected before proof parsing or allocation. Passed logs and 30 source hashes are retained in `fusion-pipeline-qualified-source-manifest.json`; the manifest states the exact separate gate scopes. No execution, STARK or recursive proof was run for these gates.

Latest GPU schema evidence is retained in `word-gpu-schema-codegen-v2.log` and `word-gpu-schema-qualified-source-manifest-v2.json`; offline Metal compilation receipts are in `word-gpu-aot-metal-v2/artifact_manifest.json`. Caller isolated11-test evidence is retained separately from its unfinished canonical integration.

Direct recursive pack/boundary and RAM two-event evidence are retained in `direct-recursive-inventory-columns.log` and `ram-two-event-equations-codegen.log`, each with source hashes and explicit scope.

CUDA word/range runtime and offline source evidence is retained in `cuda-word-resident-contract.log`, `word-gpu-cuda-source-native-codegen.log`, `cuda-secure-product-admission.log`, and the exact source/product directories. Latest sparse recursive matcher parity and allocation-failure evidence is in `direct-recursive-sparse-pcs-columns.log`. Assembled direct parent phase-scratch/body evidence is in `direct-recursive-parent-phase-scratch-codegen.log`. These are implementation gates, not complete proof measurements.

Direct scalar/sample column evidence is retained in `direct-recursive-scalar-source-columns-v1.log` and `direct-recursive-scalar-source-columns-qualified-v1.json`; no recursive proof or performance result is established.

Immutable core capture ownership evidence is retained in `borrowed-proof-capture-ownership-v1.log` and `borrowed-proof-capture-ownership-qualified-source-v1.json`; this malformed-proof gate does not qualify successful capture or native callback wiring.

Current two-event RAM assembled evidence is retained in `ram-lanes-assembled-canonical-custody-codegen-v1.log` and `ram-lanes-assembled-qualified-source-v1.json`. GPU schema/library/backend/source-product evidence is retained in `ram-lanes-gpu-qualified-source-v1.json` and its linked logs/receipts. The assembled25-test gate includes12 named behavioral/body checks and13 import tests. These snapshots precede the next resident producer changes.

No full-block speedup, order-of-magnitude result or GPU throughput has been established. Final acceptance still requires unchanged program/input,70 queries/26 PoW bits, complete independent verification, exact base/recursive counts, isolated proof time and process/device peak memory. Segment runs remain stopped.

Successful immutable PCS capture and owned-path parity are retained in `borrowed-proof-capture-success-ownership-v2.log` and `borrowed-proof-capture-success-qualified-source-v2.json`; no prover or segment was run.

Resident lane producer metadata/ownership evidence4/4, actual production body object and regenerated Metal library are retained in `ram-lanes-resident-producer-qualified-source-v1.json`, its linked logs and `ram-lanes-resident-producer-metal-aot-v1/`. This scope excludes device execution, shared external-device charging and end-to-end performance.

Four-leaf BLAKE3 builder evidence and complete raw ABBA samples are retained in `blake3-four-leaf-builder-v1.log`, `blake3-four-leaf-node-pow-regression-v1.log`, `blake3-four-leaf-builder-qualified-source-v1.json` and [the scoped measurement note](block-v5-blake3-four-leaf-builder-v1.md).

Canonical upstream direct-column source and actual-parent-body evidence18/18 is retained in `direct-recursive-upstream-source-columns-v1.log`, `direct-recursive-upstream-source-columns-qualified-v1.json` and [the remaining-materializer audit](block-v5-recursive-upstream-source-columns-v1.md).

Shared heap/external reservations and actual canonical RAM/quotient body/library evidence are retained in `shared-external-memory-device-free-qualified-source-v1.json`, `ram-lanes-shared-external-budget-qualified-source-v1.json` and `ram-lanes-shared-budget-metal-aot-v1/`. Logical allocation limits exclude framework/stack overhead and remaining generic FRI allocations; they are not a whole-process RSS limit.

Explicit local-zero source recipe evidence is retained in `x0-local-native-source-qualified-v1.json` (12 checks, tiny three-instruction CPU fixture) and `x0-local-caller-source-qualified-v1.json` (4 checks); canonical activation remains disabled. Native immutable verifier/leaf callback body evidence4/4 is retained separately in `borrowed-native-capture-production-body-qualified-v1.json`.

Canonical FRI answer/query/opening direct source evidence24/24 is retained in `direct-recursive-pcs-source-columns-v1.log`, `direct-recursive-pcs-source-columns-qualified-v1.json` and [the exact remaining scope/storage note](block-v5-recursive-pcs-source-columns-v1.md).

Native local-zero GPU inventory evidence6/6 (4 named admission checks plus2 imports), exact32-source hashes and safe-math offline94-kernel Metal compilation are retained in `native-x0-polynomial-inventory-qualified-v1.json`, `native-x0-polynomial-inventory-v1.log` and `native-x0-polynomial-metal-aot-v2/`. See [the source/namespace inventory note](block-v5-native-x0-gpu-inventory-v1.md). Canonical activation, GPU execution and complete proof performance remain unqualified.

Budgeted FRI/cascade/inverse-cache ownership16/16 and actual production body object/syntax evidence are retained in `metal-fri-shared-budget-qualified-source-v1.json` and linked logs. Ordinary unbudgeted Metal entrypoint compatibility, producer cache drain and broader commitment/OODS scratch remain explicitly unqualified.

Direct recursive path/public/root source owners and assembled parent bodies pass32/32, recorded in `direct-recursive-path-source-columns-qualified-v1.json`, its log and [the remaining-materializer inventory](block-v5-recursive-path-source-columns-v1.md). This does not establish a recursive proof speedup.

Expanded explicit local-zero caller integration passes13/13 (10 named+3 imports), with source hashes and exact SHA recipe retained in `x0-local-caller-integration-qualified-v2.json` and its log. Canonical protocol/profile remains2, elision disabled; matched collection/driver policy integration and fresh complete proof remain pending.

Shared composition/BLAKE3 scratch accounting passes4 device-free ownership/rollback/eviction/lifetime checks and actual producer/streaming/shutdown body compilation, recorded in `metal-composition-shared-pool-qualified-v1.json` and [the scoped pool note](block-v5-composition-shared-pool-v1.md). Cached resident buffers retain their budget charge; this is not whole-process RSS or device execution qualification.

Ordinary Metal FRI compatibility passes23 focused contracts and actual strict/ordinary/fused/shutdown body compilation, retained in `metal-fri-ordinary-compatibility-qualified-source-v2.json`. Factory-failure rollback now publishes optional owners only after successful construction. No device or STARK was run; budgeted cache global-lock serialization remains a known concurrency gap.

Generic direct and fused opening-quotient private buffer admission now passes8 device-free cap/ownership/rollback/concurrency checks, six real dispatch-body compilation and Objective-C syntax. All25 private constructor sites plus the parent seed reserve before allocation; no-copy aliases retain their original ownership. The returned hash arena keeps its charge in the actual Tree. Exact source and artifact evidence is `metal-quotient-allocation-budget-qualified-v1.json`; this does not establish device execution, RSS or a proof speedup.

Budgeted FRI inverse leases now pass11 device-free same-budget overlap/reader/replacement/proposal/failure/cap checks and23 ownership regressions, plus actual production body compilation. Bank/cache locks no longer span factories or checked completion. Evidence is `metal-fri-inverse-leases-qualified-source-v1.json`. This supersedes the earlier global-lock gap, but does not establish hardware concurrency or full-block speedup; bounded multi-geometry idle reuse now passes18 lease/LRU plus23 ownership checks and actual production body compilation.

Ordinary lazy quotient BLAKE3 routing now uses typed direct parameters instead of the unsupported staged-state interface, with exact zero-seed/prefix admission. Ten allocation/framing/admission checks and actual BLAKE3 backend lazy commitment plus six dispatch bodies compile, recorded in `metal-quotient-direct-blake3-qualified-v1.json`. This removes a source routing gap; hardware parity and actual proof performance remain unqualified.

Canonical bounded transcript and Merkle nonhash direct columns pass39/39 focused source checks, including six new parity/mutation/allocation-failure fixtures and actual parent body generation. All72 frozen source hashes match `direct-recursive-nonhash-source-columns-qualified-v1.json`. ID14 canonical source emission is qualified at this scope; no new recursive STARK, total peak-memory or speed result is established.

Quotient result ownership now passes6/6 device-free rejection/adoption/lifetime checks and real full lazy FRI engine body compilation, recorded in `metal-quotient-result-ownership-qualified-v1.json`. Rejected execution receipts destroy every published tree; failed first/middle tree adoption transfers raw ownership before consuming constructors, preventing double destruction and abandoned tails. Temporary shared-budget leases keep raw result arrays alive through cleanup. No device or proof was executed.

Cohesive execution recipes now pass17/17 source checks each for explicit local-zero profile3 and retained canonical profile2, with independent runner-selected policy assertions and actual cold/warm driver, codec, producer/global receiver bodies generated without calling them. Receipt `x0-cohesive-production-recipes-qualified-v1.json` pins33 sources and both logs. Canonical recipe0/protocol2 remains selected; this is not fresh fused-proof or complete-bundle qualification. Input bytes are already authenticated by generic RAM but remain legally writable; immutable specialization must prove classification and unchanged values before generic-RAM subtraction.

Bounded eight-entry inverse LRU passes18 lease/LRU and23 strict/ordinary ownership regressions plus actual production body compilation (`metal-fri-inverse-lru-qualified-v1.json`). Different completed circle/line geometries remain reusable up to min(256MiB, owner cap/8) per bank. Pressure can permanently evict idle entries; live readers remain immutable and charged. These are device-free resource-policy checks, not measured GPU overlap or block speedup.

Generic PCS circle LDE now initializes its actual batch with the producer allocator. All7 private LDE constructor sites admit before allocation; exact runtime/allocator matching prevents foreign/shared owner reuse. Actual C queued-operation receipts keep genuinely buffered scratch charged until batch completion/cancellation and release synchronously destroyed groups immediately. Legacy ordinary entrypoints retain uncapped compatibility and reject supplied shared-budget bypass. Seven device-free lifetime/cap/wave checks, actual full generic PCS/batched/standalone body object and literal assembled Objective-C runtime prefix pass (`metal-circle-lde-budget-qualified-v1.json`). No GPU, STARK, guest, segment or speed run occurred.

Persistent canonical native recursive request-lane source evidence6/6 is retained
in `native-recursive-request-lane-production-v2.log` and
`native-recursive-request-lane-qualified-v1.json`; actual cached/consuming/destruction
bodies compile without invocation. The lane completes19 fixture callbacks with
one thread. This is not a proof throughput or cache-hit measurement.

Capacity-native B5CT/v1 evidence13/13 is retained in
`native-capacity-production-v4.log` and `native-capacity-templates-qualified-v1.json`.
The corrected count-column witness uses the authentic execution circle ordering;
all six frozen source hashes match. This qualifies equations, custody and actual
producer/receiver compilation, not a fresh STARK, cached fixed tree or canonical
block migration.

Sampled coefficient/OODS and barycentric scratch evidence9/9, actual eleven
production body wrappers and full assembled Objective-C syntax are retained in
`metal-sampled-evaluation-budget-qualified-v1.json` and its linked evidence.
All thirteen frozen source hashes match; hardware execution, source-input budget
provenance and end-to-end peak memory remain separate acceptance work.

Authenticated readonly input classification source evidence14/14 (seven named
contracts plus imports), actual producer/fresh native/caller receiver body
compilation and corrected Debug census2/2 are retained in
`readonly-input-source-qualified-v1.json`. All eight frozen code hashes match.
Canonical input remains writable unless an independently admitted subset policy
is selected; this isolated batch does not filter canonical RAM events.

Actual immutable capacity fixed reuse evidence9/9 and10 matched snapshot source
hashes is retained in `native-capacity-fixed-basis-qualified-v1.json`. Four lease
checks commit only tiny CPU fixed/main trees with hard trace_log<=3; this is real
buffer/coefficient sharing, not a complete proof or throughput measurement.

Distinct capacity catalog/artifact/fresh-capture source and canonical single-buffer
native encoding evidence10/10 is retained in
`native-capacity-transport-capture-qualified-v1.json` and
[native-capacity-transport-v2.log](cpu-performance-gates-v1/native-capacity-transport-v2.log).
The actual catalog producer, independent artifact receiver and owned/borrowed
capture bodies compile without invocation. Literal envelopes, exact old-byte
parity, independent decoded ownership and every allocation failure are qualified;
fresh captured STARKs and complete block performance remain unqualified.

Readonly Selection/Proposal two-pass seam evidence20/20 (six new named
contracts, seven prior classifier contracts and seven import checks) is retained
in `readonly-input-two-pass-proposal-qualified-v1.json` and
[readonly-input-two-pass-proposal-v1.log](cpu-performance-gates-v1/readonly-input-two-pass-proposal-v1.log).
Twelve code snapshots cover actual immutable selection, actual late source
binding, tiny CPU borrowed-prefix/classifier commitment replay and exhaustive
allocation failures. Canonical fusion, RAM filtering and complete proof
qualification remain outstanding; no segment, STARK, device or benchmark ran.

Capacity durable transport evidence11/11 is retained in
`native-capacity-store-qualified-v1.json` and
[native-capacity-store-production-v2.log](cpu-performance-gates-v1/native-capacity-store-production-v2.log).
Genuine common-seal/catalog policy admits keys, counts and roots independently
of file bytes. Literal postcard publication/loading, failure ownership,
exclusive non-overwrite, tamper checks, bounded streaming manifest and exhaustive
allocation failures pass. The actual fresh-capture loader body compiles without
invocation. Shared I/O replaces duplicate legacy store publication/read code.
Canonical capacity/fused driver activation and complete proof remain unqualified.

Capacity recursion source evidence10/10 plus actual object body compilation is
retained in `native-capacity-recursion-qualified-v1.json` and
[native-capacity-recursion-production-v3.log](cpu-performance-gates-v1/native-capacity-recursion-production-v3.log).
All21 frozen candidate/dependency hashes matched before documentation changed.
Mixed-domain original arithmetic and prefix count equations match the actual
CPU composite evaluator; changing 5/7 and empty frame3/7 counts reuse one graph,
mutations fail, 257-wide public count supply and allocation cleanup pass.
Actual recursive publication, fresh receiver, cache and normalization bodies
compile without being called. No STARK/segment/device/performance run occurred.

Canonical legacy manifest publication now shares the same exclusive durable
I/O. Its prior manifest regression and actual instantiated ROM put/take bodies
pass the6-check followup recorded in `native-capacity-store-qualified-v1.json`
and `native-capacity-store-legacy-body-v1.log`; the earlier11-check baseline and
its source snapshots are retained separately.

Typed capacity Exact/Stream/Manifest evidence7/7 plus actual dual object body
compilation is retained in `native-capacity-exact-qualified-v1.json` and
[native-capacity-exact-production-v1.log](cpu-performance-gates-v1/native-capacity-exact-production-v1.log).
All15 candidate source snapshots matched before documentation changed. One
shared implementation retains genuine distinct capacity public/claim frames,
wide schedules, independent early metadata security/census, bounded topology
and detached outer/file pins. Default NativeV3 public APIs stay typed. Actual
forest execution, Global/driver activation and full block performance remain
unqualified; no proof/segment/device was run.

Actual default/capacity program/provider fresh closure object compilation is
retained in `native-capacity-program-body-qualified-v1.json` and
`native-capacity-program-body-v1.log`. One shared loop preserves actual fresh
native/fused/caller verification and ROM provider closure. Its independent
`admitRoster` now runs before file callbacks and is reused by the typed Global
receiver; it does not grant cryptographic acceptance. This is compilation-only,
not a successful fresh proof, complete bundle or canonical capacity activation.

Caller readonly fusion source evidence11/11 (seven named+four imports) is
retained in `caller-readonly-qualified-v1.json` and
`caller-readonly-unit-v2.log`. Authentic source fields are reused; all-RW
universal/byte requests remain, while mutable and immutable transition
requests have separate exact census. This does not enable canonical RAM
subtraction or establish a fresh composite STARK or complete block proof.

Typed capacity/default shared complete-receiver evidence12/12 plus actual
Global/Complete/Detached object compilation is retained in
`native-capacity-global-qualified-v1.json`, `native-capacity-global-unit-v2.log`
and `native-capacity-global-body-v1.log`. These contracts retain actual empty
frame PC/register/auxiliary obligations, reject legacy separate-loader routing,
and independently rebuild capacity recursive policy. The fresh verification
bodies compile under stable B5CF revision3 dependencies; no fresh complete
proof or canonical capacity collector/driver activation is established.

Distinct capacity memory fusion source, equations and transport evidence24/24
(17 named+7 imports) is retained in `native-capacity-fused-qualified-v1.json`
and `native-capacity-fused-unit-v3.log`. Shared runtime extraction now
propagates allocator failure before symbolic naming/graph publication; all
lookup-family successful DAG/event parity and exhaustive selected direct/lookup
factory failure checks pass. Actual native/fused fresh acceptance remains
unqualified; literal artifacts are ownership fixtures.

The duplicate native/fused durable store bodies are replaced by typed adapters
to one bounded kernel, qualified21/21 (14 named+7 imports) in
`native-capacity-shared-store-qualified-v1.json` and
`native-capacity-shared-store-v1.log`. Family-specific codec, independent policy,
fresh verification, filename/magic/error boundaries remain distinct. Canonical
capacity driver activation, real complete bundle and speed/RSS remain pending.


Capacity witness-once staging is qualified10/10 (five named+five imports), plus
actual legacy/capacity staging and commit/bind CPU object bodies compiled, in
`native-capacity-staged-columns-qualified-v1.json`. Exact span/catalog metadata,
original main-column reconstruction, ownership under all allocation failures,
and the unchanged old API pass without committing/proving or executing a guest.
The capacity collector, shared driver, bundle storage and fresh detached loader
are now source-integrated. Their assembled qualification is in progress; initial
compiler failures (ambiguous factory aliases and a legacy-only loader callback)
are retained with source snapshots and corrected before any proof run. Segment
proving remains stopped. No end-to-end speed, complete proof or default capacity
activation claim follows from this source integration.


Shared capacity/default collection and assembly now qualify16/16 (six named,
ten imports) in `native-capacity-collection-assembly-qualified-v1.json`, including
actual complete producer bodies retained without invocation. Real B5CF identities,
ROM census parity, late independent entry binding, sparse roster bounds and
exhaustive allocation cleanup pass. Factory bodies moved into shared impl modules
while legacy modules remain typed adapters; the failed initial compile snapshot
is retained.

Capacity complete bundle qualifies13/13 (six named, seven imports) in
`capacity-complete-bundle-qualified-v1.json`. Genuine B5CTART1/B5CFART1 codec
ownership, separate B5CFILE1/policy identities, independent caps and both actual
complete detached consumer bodies are qualified without proof execution. The
capacity memory loader has its genuine context-only contract; no legacy opcode
receipt adaptation is used. Actual fresh complete proof/default driver activation
and performance remain outstanding. Segment proving is stopped.


The complete shared CPU driver now qualifies seven policy/type checks and actual
legacy/capacity `Driver.run` object bodies under a stable63-source assembled
snapshot in `native-capacity-assembled-driver-qualified-v1.json`. The object
contains both real run symbols and retains the old sorted-memory store API;
both drivers publish genuine shared typed RAM sinks. Collection, staging,
fused/native recursive publication, bounded queues/shared budget, incremental
exact forest and fresh detached verification compile as one path. Initial
legacy-store nominal mismatch and corrected source snapshots/logs are retained.
No run body was invoked. Canonical capacity CLI selection, fresh complete proof,
block time and peak RSS remain unqualified; segments stay stopped.

The next cohesive source integration selects one capacity stack for both installed
CPU producer and fresh detached receiver, retains canonical70-query/26-bit security,
and identifies it with report version2. Collection and staged replay share an
authenticated fixed-basis cache with configured-cap cold fallback and explicit
leases spanning moved PCS lifetime. Resource-aware RAM planning intersects each
component's limits and minimizes exact instance count before committed row area.

Capacity native callbacks now enqueue genuinely verified owned captures into one
ordered recursive coordinator. The default is one waiting capture plus one active
worker. It borrows neither native proof nor replay/PCS; backpressure precedes
capture allocation. Driver teardown joins it before family/cache/metadata/pool
destruction. Success still requires exact leaf completeness, all base families,
forest publication and the fresh all-family detached receiver. Queue counts are
reported as queue-owned captures, not estimated RSS or proof throughput.

The genuine range16 recursive adapter is source-complete and separately staged
for focused qualification. It does not finish RAM/provider aggregation or global
recursive closure. Fixed-cache, RAM resource selection, queue ownership, range
equations and canonical installed-body gates are being qualified under the new
`capacity-canonical-integration-*` source snapshots/results. Earlier receipts
retain their original sources and do not qualify these later changes.

The measurement-report guard passes three pure Python regressions, rejecting
legacy grammar, downgraded security and incomplete/nonfresh reports. The shared
CPU argument builder passes19 pure Python contracts and scopes optimization/CPU
flags to every Zig module; its receipt is
`protocol-cpu-runner-argv-qualified-v1.json`. This does not change historical
measurement settings or establish a speedup. No segment, guest, STARK, benchmark
or device run is authorized by these focused gates; segment proving stays stopped.

Focused capacity integration results now pass17 cache checks,6 RAM sizing checks,10 queue ownership/body checks and16 canonical product/actual entry checks at their recorded snapshots. Range16 passes6 equation/admission/transcript/security/allocation checks after fixing shared recorder error propagation: the first typed error stays sticky and is returned unchanged, so OutOfMemory is not concealed by GraphConstructionFailed. Updated full installed-entry semantic compilation passes without repeating full LLVM generation. The actual range capture/all-cohort/publication/fresh receiver object is retained separately; no body was invoked. Failed candidates and all source snapshots remain in capacity-canonical-integration-* receipts. These55 checks include imports and are not successful STARKs, complete block proofs or performance measurements.

Original native-fused/caller capture evidence is retained in `cpu-performance-gates-v1/fused-capture-cohesive-qualified-v1.json`; all 18 scoped checks pass, and the real owned/borrowed verifier bodies were emitted without successful STARK invocation. Exact coverage metadata evidence is retained in `cpu-performance-gates-v1/recursive-coverage-metadata-focused-v1-result.json`: all six tests pass with no changed source pins. The coverage descriptors retain explicit missing adapters and ten source-authentication obligations. Neither gate qualifies complete recursive closure or block performance; shared typed adapter changes after these snapshots require separate qualification. Segment, STARK and device runs remain stopped.


Caller arithmetic's corrected policy runners execute the executable root's actual
test list and reject zero discovered tests. The original focused-v1 success exits
with zero tests are explicitly disqualified by
`cpu-performance-gates-v1/caller-arithmetic-policy-runner-audit-v1.json`. Both
corrected focused-v2 binaries exercised all12 checks and retained genuine original
verifier/publication bodies; their sole failure was a fixture using4519 Keccak
calls where9039 are required for true log18. The fixture now derives the threshold
from canonical29-row/two-operation geometry. Each independent policy passes its
three-check narrow correction, recorded in the legacy/selected
`caller-arithmetic-*-qualified-v1.json` combined receipts. This combines the
recorded full-body snapshot and justified fixture correction; it is not a new
full-suite run or a successful STARK.

Native full-capacity fused recursion passes19 checks with actual producer, cache
and fresh-leaf bodies retained in
`native-capacity-fused-recursion-qualified-v1.json`. Caller-fused recursion has
its scoped full-body/corrective receipt in `caller-fused-recursion-qualified-v1.json`.
Shared global-join equations pass four independent cancellation/sign/accounting
checks, and actual canonical installed producer/detached-receiver bodies analyze
with those delegates in `global-join-canonical-product-integration-qualified-v1.json`.
The joins preserve per-execution state, per-window register custody, per-provider
group/kind lookup closure, one byte partition and the original auxiliary-clock
minus/register-compensation plus signs. Counts, fresh admissions and exact source
coverage remain separate obligations.

Memory source cryptographic equations pass12 focused checks after fixing real
carry/output aliasing and SHA state-update ownership. B5SC first-round lifecycle
passes eight further checks in `memory-source-first-round-qualified-v1.json`: exact
physical census, full-clock private input columns, original word challenge parity,
source-root ordering, bounded owners and allocation cleanup. Actual commitment,
fixed recommit and shared-tree lease bodies are retained without being invoked.
These are equation and lifecycle qualifications. Same-original-main arithmetic
input binding, actual source proofs and complete aggregate closure remain pending.
The bit-graph oracle does122E BLAKE3 compressions and is not a fast hash-proving
architecture. Reusing the existing packed SHA/BLAKE3 cores still requires source
schedules, full frames and separately authenticated routing/range providers.

The caller recursive pipeline now has a real source implementation over the
original staged/live caller producer. Exactly one owned fused base proof waits
for its arithmetic companion. Original arithmetic verification occurs once; its
recursive child is published and its capture is released before original fused
verification and parent construction. Both recursive children precede forwarding
the original base proofs. Every sink retains ownership on errors, and incomplete
or partial publication cannot claim a complete bundle. The original witness/PCS
never escapes its segment lifetime. Source analysis and15 focused ownership, admission/fault/import checks pass; the
12.6MiB binary retains actual staged/live caller and both parent publisher bodies
without invocation. Evidence is `caller-recursive-pipeline-qualified-v1.json`. Canonical
driver activation, typed durable transport and final all-family closure remain
pending. No segment, STARK, benchmark or device run has been started.


Typed execution recursive file envelopes (`B5EXLF01`) cover caller arithmetic,
caller fused and full-capacity native fused while retaining the provider
`B5PVLF01` grammar. Exact independently pinned Prepared/template policy controls
the key, source instance/index and schedule. Public claims are bounded JSON
proposals; only actual original `Leaf.verify` can return an open equation.
Publication shares the existing exclusive/synced multi-span file I/O, retaining
proof bytes without a full envelope copy. Loading bounds length and SHA first,
then requires distinct fresh typed proof verification. Eleven nonproving checks
pass; three actual original encode/decode/publication/fresh-load routes are
retained in the5.48MiB binary. `recursive-execution-leaf-files-qualified-v1.json`
records the exact scope. Initial provider32KiB metadata limits correctly rejected
complete caller claims; explicit execution limits now permit4MiB encoded/32MiB
owned metadata while reusing checked extent arithmetic. Successful cryptographic
loads, native-fused behavioral metadata roundtrip and exact complete manifest/driver
activation remain unqualified.


The actual heterogeneous child/source-pairing parent and optional original
scoped global-join parent now pass source analysis after narrow generic RAM
transcript corrections. `RAM.Claim.mix`, its event helper and `RAM.mixClaims`
accept the original transcript collector as well as BLAKE3 channels; their
framing bodies are unchanged. Both independent focused equation/fault/body
gates pass16 checks with unchanged source pins; exact scoped receipts are
`heterogeneous-open-recursion-legacy-qualified-v1.json` and
`global-join-recursion-qualified-v1.json`. These parents remain OPEN:
mapping topology/census alone does not prove
that every semantic source/global term is present. Deterministic mapping from
original authenticated field/word frames, full endpoint/source obligations and
genuine hierarchy beyond32 native spans remain being implemented.

A further source-architecture cost is now explicit: current `Stream.census` uses
`E = input_words + rw_words + endpoints`, with `DEPTH * E` internal node steps.
Initial image insertions as well as endpoint edits each repeat a full Merkle
path; the122E compression count is not just executed RAM accesses. A new sorted
full-image/endpoint merge and sparse batch-tree fold is prioritized to reuse
unique internal nodes while preserving original BLAKE3 tree framing, untouched
leaves, before-value/source joins and independently pinned initial/final roots.
This is an engineering target. It has not replaced the current authenticated
path, qualified a source proof, or established a measured speedup.


Original-main source binding and bounded durable replay now pass11 focused
checks plus actual point/domain/recommit source analysis, recorded in
`memory-source-original-main-binding-qualified-v1.json`. Four physical trees
retain the original fixed/private source columns, independently reconstructed
circuit/node/use routing and interaction columns. Dedicated wire randomness
follows both supplier and requesting arithmetic commitments. Scalar and SIMD
equations agree, mutation/degree/census/mask/epoch and allocation/lifecycle
checks pass. Wide1728-column source compilation exposed two unnecessary inline
mask loops in the shared word quotient adapter; ordinary loops retain the exact
mask relations and avoid compile-time branch-budget/code-generation expansion.
No actual PCS or source STARK ran; complete source/hierarchy/semantic closure
and block performance remain unqualified. The new batch-tree path remains
separate engineering under review.

The same mixed-family source/pairing equations also pass16 selected-policy
checks with the actual root test list and unchanged source pins, recorded in
`heterogeneous-open-recursion-selected-qualified-v1.json`. Both independent
policy paths are now qualified within this nonproving scope. No successful
recursive STARK, complete hierarchy/bundle or performance claim follows.


Seven typed recursive families now share one exact durable store kernel;
provider store framing/public APIs/error domains are preserved, while caller
indices follow the original sparse precompile roster rather than ordinal zero
through file count. Native full-capacity fusion requires the original execution
roster. Binary policy lookup, exact slot/file caps, exclusive synced publication,
borrowed metadata/proof spans, failure ownership, single fresh load and sticky
failed loads are shared. All20 focused transport/ownership/fault/import checks
pass with the genuine original seven loader/publication bodies retained; exact
scope is `recursive-leaf-store-qualified-v1.json`. A real index2 caller among
three native executions qualifies sparse publication and rejects index0, missing
files, duplicates, nonproof acceptance and reloading failed files. Source policy
and template borrows must outlive joined readers. Driver/hierarchy activation,
complete manifest/source accounting and successful proofs remain unqualified.


Deterministic semantic mapping now passes17 focused checks and actual
derive/record/same-parent attach source analysis. Original field and word-limb
claims are selected by normative typed slot ordinals, including identical zero
payloads; every role/slot/coordinate/group/obligation/source mutation is checked
against an independently re-derived recipe rather than a received digest. The
initial full fixture run failed one reset missing its mutation seal; the sole
fixture correction restores the intended algebraic rejection and full v2passes.
`global-join-semantic-mapping-qualified-v1.json` preserves the exact open scope.

The original-byte forwarding hierarchy passes15 legacy-policy checks and real
producer/fresh-receiver source compilation. Its75-leaf fixture uses67 genuine
native span descriptors plus providers and no rounded proof count. Every
forwarded byte is linked to lower authenticated public bytes, and native
index/count, PC and clock adjacency have explicit constrained equations.
Whole-policy source/export caps bound current O(n log²n) retained transcripts;
this is closure engineering, not the intended compact performance architecture.
`heterogeneous-hierarchy-legacy-qualified-v1.json` records scope and pending
source/global authority. A new compact scoped-summary hierarchy will retain
only unresolved typed claim scopes/pairing endpoints and verify actual lower
parents without replaying full descendant public transcripts. Neither hierarchy
has produced a successful recursive proof or complete block measurement.


The seven-family split loader now passes21 focused checks, with actual original
publication and fresh-receiver bodies retained; the exact scope is
`recursive-leaf-store-split-qualified-v1.json`. Header, metadata and proof have
separate bounded ownership. The transport fixture fits exactly the metadata and
proof payload allocation budget and transfers the proof allocation without
copying the full envelope. A proof-byte loader supports later fresh hierarchy
verification without conferring verified state itself. This is an I/O allocation
qualification, not a whole-prover peak-memory measurement. The earlier failed
fixture exposed transport hash rejection precedence; bounded stack hashing now
preserves that behavior without allocation from an untrusted header.

The canonical source writer already emits four raw record files. The new
batch-tree route removes the old per-edit opening callback and redundant
stream materialization; it does not claim to remove openings from those files.
Initial public-input authentication also does not make a touched RAM word
immutable: the batch equations preserve the original mutable final word.


The new simultaneous memory tree batch now passes17 focused nonproving checks,
recorded in `memory-source-batch-qualified-v1.json`. The dense full-image fixture
retains both original roots and reduces compression count by more than16x
against its old per-edit oracle; this is a work-count check, not proof timing.
Exact ordinal joins, untouched leaves, mutable touched input, full-width clocks,
all default heights, actual packed G/XOR constraints and graph ownership
mutations are covered. Two failed allocation fixtures were corrected to let
evaluation scratch OOM propagate to fault injection while retaining mutation
rejection; production equations were unchanged. Source SHA/page proofs, later
challenge-epoch wire interactions, fresh recursive authority and canonical
driver activation remain outstanding. No segment or STARK was run.


The first forwarding hierarchy also passes all15 focused checks under the
independently selected execution recipe, with unchanged source pins and actual
root test discovery. `heterogeneous-hierarchy-selected-qualified-v1.json`
records this additional policy qualification. This does not qualify the new
compact hierarchy, prove source/global closure, activate the canonical driver,
or establish a complete recursive proof or end-to-end performance.


Caller policies now have stable original arithmetic/fused admission-pair
ownership and an exact sparse catalog. Original private sessions and new
borrowed staged/live sessions retain pointers to the same immutable policies;
session teardown releases its lease without invalidating later file/hierarchy
readers. Catalog creation uses the real assembled optional caller roster and
source-seal indices. Source and receiver geometry still use the original typed
admission factories. The catalog must outlive joined durable/hierarchy readers.

All21 focused source checks pass, recorded in
`caller-admission-ownership-qualified-v1.json`, including10 named behavioral
checks, actual borrowed producer bodies retained only, sparse index2 custody,
lease/resource/security/mutation/order/sink-failure checks and selected new
allocation boundaries. An intentionally stopped first attempt redundantly
walked every upstream typed AIR allocation; the actual one-second profile
confirmed repeated AIR construction. The stopped result and reason are retained.
The revised gate checks owner/partial-owner/final-validation boundaries rather
than claiming new exhaustive coverage of all upstream allocations. Earlier
exhaustive admission evidence is retained for its historical snapshot. Driver
activation, complete compact/source/global authority and proof performance
remain unqualified; no segment or STARK ran.


SHA public admission now reuses one immutable typed-effect setup census per
executable recipe across the existing production `deriveForRecipe` API. The
cache contains only original per-AIR live-pattern and zero-padding coefficient
weights, derived from actual typed AIR effects. Every caller still checks
count-dependent geometry, padding, signed memory demand and field-safe bounds.
No witness, challenge, root or accepted proof is cached. Failed initialization
leaves the cache empty; successful setup retains no allocator-backed graph.

The six focused checks pass in `sha-admission-setup-cache-qualified-v1.json`,
including the original uncached effect-by-effect oracle on ten boundary counts
for both recipes, allocation-free warm reuse, failure/retry and concurrent
single publication. This removes observed repeated AIR setup in caller
admission throughout the existing API; no whole-proof speedup is inferred.

Actual original staged/live caller bodies also compile against the cached
SHA setup API, recorded in `caller-admission-cached-setup-integration-v1.json`.
The current cache6/6 gate and prior ownership21/21 gate retain distinct exact
source snapshots; there was no redundant full ownership rerun or proving run.

Compact-hierarchy review exposed an additional semantic seam: the legacy
Global.Plan scope/hash admission did not independently select normative claim
coordinates. The compact implementation is being corrected to derive those
selectors from the qualified typed semantic map and reject re-sealed arbitrary
recipes. Unsupported program/register/source compensation remains explicit
OPEN pending integration with genuine public/source export equations. This
is outstanding engineering, not a qualified complete block architecture.


The compact scoped hierarchy now passes22 focused source checks under each
legacy and selected execution recipe, with unchanged1721 source pins per gate.
The semantic admission fix derives exact selectors from the original typed
semantic map; re-sealed selectors, signs and terms are rejected. Byte-lifted
QM31 claims, same-parent tuple closure, exact LCA routing, provider absence,
75-leaf carried tails and allocation ownership are covered. Actual original
producer and fresh-receiver bodies compile but were not invoked. Receipts:
`heterogeneous-scoped-legacy-qualified-v1.json` and
`heterogeneous-scoped-selected-qualified-v1.json`.

The current inherited six-word span bus safely rejects cycles at or above
2^30; a full-u64 constrained bus is needed for larger jobs. Immutable compact
setup ownership, complete public/source/global compensation, canonical driver
activation and genuine proof performance remain open. Segment runs remain
stopped, and no recursive or block proof timing is claimed.


The genuine global public-export extension now passes17 focused nonproving
checks (eight named behavioral checks plus actual body retention/imports),
semantic analysis and emitted original stage/cache/fresh-receiver object with
the exported body marker. Exact B5PD fields, full-word register compensation,
canonical completion decoding, full-u64 byte carries, tuple signs, shared input
borrowing and allocation/mutation rejection are covered. Root corrected two
new native-relation call interfaces to use the original fixed-arity native
RelationElements from exact shared draws; equation arithmetic was unchanged.
The failed first semantic attempt and immutable v2 snapshots are retained in
`global-public-exports-qualified-v1.json`. This qualifies that source snapshot,
not complete source authority or a successful root proof.

The current followup implements durable independently expected public policy
ownership with one shared input, and compact setup ownership to avoid repeating
whole-job semantic derivation at every fold. These are not yet qualified. The
full-u64 original-child/higher-parent bus integration remains mandatory.


Native legacy/capacity PCS geometry now shares one independently validated
span cursor. Every returned log array uses exactly one allocation; capacity
main construction writes original native columns and activity tails directly,
without allocating/copying an intermediate native array. Capacity Prepared
validation checks the same exact geometry without its three temporary arrays.
Source review also found legacy NativeV3 Prepared omitted retained-log checks;
its independent validation now rejects changed or truncated masks without
scratch allocation. Initialization admits authority before allocating logs.

The19-check nonproving qualification passes with unchanged1717 pins, including
actual public parent/publisher/cache/fresh receiver bodies, denied-allocation
legacy/capacity admission, exact empty frames, maximum shard census, altered
columns and rollback. `native-column-log-layout-qualified-v1.json` retains
initial18-check and final19-check snapshots separately. These are setup/mask
ownership improvements; no block proof, speedup or RSS measurement is inferred.


The durable native-fused store now has an additive independently typed optional
selection. The old dense default is unchanged. All original native admissions
are bound to the exact source roster; both original projection and memory
inventories must be empty before omitting a fused companion. Each selected
policy borrows the same admitted native owner. Received indices cannot mint
absence, and publication or an empty verified file census grants no equation.

The15-check focused source gate passes with1656 unchanged pins (eight named
behavioral checks plus imports). Actual two-execution q70/pow26 metadata selects
required index1 after genuinely empty index0; omissions, relabels, native owner
reordering, geometry/security mutations, lookalike ownership, resource limits,
selection allocation rollback and original caller/split-file behavior are
covered. `native-fused-selection-qualified-v1.json` retains the original failed
fixture-enum semantic attempt and successful corrected semantic snapshot.
Canonical driver activation and complete source/global authority remain open;
no segment, STARK, device, proof-speed or peak-RSS measurement ran.


Expected public job custody and the distinct lazy new-public-root source now
pass22 focused nonproving checks with1723 unchanged pins (13 named behavioral
checks, one actual body-retention marker and imports). The file retains exactly
one independently expected input vector; every public field is compared before
binding the original typed policy. Retained allocator/owner lifetime, genuine
large-input serializer descriptors beyond the old one-million-cell grammar,
binary lazy cell lookup, exact original child frame identity and complete
allocation rollback are covered. Root factored the original fresh verification
kernel so owned reception reconstructs public fields once for verification and
normalization. Actual publisher/fresh verifier/normalizer bodies are emitted in
the focused binary with the retained exported marker, never invoked.

`global-expected-public-owner-qualified-v1.json` records the corrected source
snapshot separately from the immutable authored candidate and first semantic
snapshot. The new public protocol remains OPEN: complete memory/source join,
the additive wide original-child ingress, higher-parent closure and canonical
driver activation still require engineering. No segment, STARK, device, proof
timing or peak-RSS measurement ran.


Public export normalization now derives the exact original transcript prefix
once, then uses checked direct coordinates for each window instead of
revalidating and rescanning the complete public input per window. Original
field ordering and invalid-window error priority remain unchanged. Independent
sequential-counter parity through 4096 windows, bounds and overflow checks plus
the owned-public regression fixtures pass 24 focused nonproving checks with 1724
unchanged source pins. `global-export-layout-qualified-v1.json` records the
semantic and focused source snapshots. Actual production bodies are retained,
never invoked. No block proof, speedup or peak-RSS measurement is inferred.


The additive packed BLAKE page column owner now regenerates original G/Xor
matrices directly from bounded fold operands, with 192-byte compression
captures instead of 1536 Boolean capture cells. Original canonical defaults
and common before/after frames retain explicit recipe obligations; host
geometry and native digest checks convey no proof authority. Four focused
nonproving checks pass with 1686 unchanged source pins, including actual
regeneration against the original full-row projection for shared/default/
changed leaves and a two-compression shared branch, exact signed table
counters with padded rows, byte capture mapping, resource limits and corrupted
digest cleanup. `memory-source-packed-blake-columns-qualified-v1.json` records
this scoped column-owner result. Exhaustive allocation faults, unified PAGE
proof integration and cross-page source closure remain open. No proof timing
or peak-RSS measurement is inferred.


The compact job setup owner legacy-policy source now passes all 16 focused
nonproving checks with 1725 unchanged source pins: eight named behavioral
checks, actual body retention and imports. Independent job pins, copied
proposal storage, exact local selector fingerprints, bounded retained leases,
allocation rollback, full-u64 scalar carry equations and original typed/generic
row parity are covered. The first focused attempt correctly rejected an
uninitialized fixture wire schedule; the fixture now explicitly initializes
that schedule without changing production admission. Both attempts are kept
in `heterogeneous-scoped-owned-legacy-qualified-v1.json`. Selected-policy
qualification, full source/global closure and canonical activation remain
open. No segment, STARK, device, proof timing or peak-RSS measurement ran.


The compact setup owner also passes the selected local-zero policy source
gate: all 16 focused nonproving checks and actual producer/fresh-receiver
body retention, with 1725 unchanged pins. This separately qualifies the
selected recipe snapshot; its byte grammar and original admission remain
unchanged. `heterogeneous-scoped-owned-selected-qualified-v1.json` records
semantic and focused results. Canonical driver activation and complete
source/global authority remain open; no proof timing or RSS claim is made.


The additive full-u64 original-child bridge now passes 15 focused nonproving
checks with 1721 unchanged pins. Exact original channel bytes remain unchanged;
a separate typed parent binds genuine original public digest coordinates and
proves first + (clock - 1) = last with explicit carries across all u64 limbs.
Legacy six-word span limits remain rejected. Coordinate/digest/count/overflow
mutations and allocation rollback are covered, and actual original fresh
verifier/State.plan plus genuine new-parent producer/receiver bodies are
emitted and retained, never invoked. Root fixed a shadowed graph identifier
and compared the native/capacity original span using their genuine differing
optional/nonoptional types. All failed semantic attempts and the corrected
snapshot are retained in `wide-original-child-bridge-qualified-v1.json`.
Multiwindow public integration, complete source/global authority and canonical
activation remain open. No segment, STARK, device, proof timing or RSS ran.


Packed SHA and BLAKE pages now have an additive shared per-job immutable
typed AIR/setup owner. Each page borrows exact authenticated definitions and
relation plans under an atomic retained lease, while geometry, columns,
counters, captures, challenges and source admission stay page-local. The
original cold constructors use the same kernels. SHA columns also retain
the aggregate allocator explicitly. All 9 focused nonproving checks pass
with 1688 unchanged source pins, covering genuine SHA padding-edge/cold
parity, BLAKE original row/table/capture parity, coordinator and allocator
release before page teardown, and every cached page allocation failure.
These faults target new page ownership instead of repeatedly rebuilding
upstream typed AIR graphs. `packed-hash-shared-setup-qualified-v1.json`
records the snapshot. Actual unified PAGE job use and canonical activation
remain pending; no block proof, timing or RSS claim is made.


The packed original SHA PAGE source snapshot passes all 22 focused nonproving
checks with 1714 unchanged source pins. Padding-edge, scalar/SIMD, original
full-row/table, compact operand, durable replay and allocation-failure parity
are covered; genuine PAGE producer/fresh receiver and eight-tree codec bodies
are retained without invoking a STARK. The first semantic failures and six
compile repairs are retained alongside the passing snapshot in
`memory-source-packed-page-qualified-v1.json`. Subsequent cached Stage and
ComponentOwner overloads require their separate gate. Unified raw/fold PAGE
authority, complete source/global closure and canonical activation remain open.
No segment, STARK, device, proof timing or peak-RSS measurement ran.


The actual cached SHA Stage and component construction snapshot now passes
all 11 focused nonproving checks with 1693 unchanged source pins. Real CPU
collection, persistence and replay preserve the exact six original roots;
copied component programs, column logs and masks survive source-page release.
The actual SHA producer reuses already-authenticated page AIR definitions.
The first focused gate exposed a cross-budget tree-promotion error: shared raw
storage was being released through the destination allocator. The additive
`Shared.copyWithSourceAllocator` preserves the original storage allocator while
allowing separate destination descriptors. The unchanged fixture passes after
that repair. Both attempts are retained in
`packed-hash-shared-stage-qualified-v1.json`. Unified raw/fold PAGE proving,
complete source/global closure and canonical activation remain open. No segment,
STARK, device, proof timing or peak-RSS measurement ran.


Fresh arithmetic fixed reconstruction now uses the same admitted fusion walk
as legacy rows and direct producer columns. `materializeFixed` accepts only
the independently admitted lowering plan, graph reference and proof kind; no
private evaluations, invocation buffers, inverse computation or main columns
are reconstructed. Exact compact dot4/FMA/inverse/linear metadata, counts, logs
and committed fixed columns match the original producer in both modes. All
14 focused nonproving checks pass with 675 unchanged source pins, including
every fixed-owner allocation failure, canonical empty padding and unchanged
original degree, scalar-coordinate and wire-boundary regressions. Both failed
attempts and the passing source snapshot are retained in
`arithmetic-fixed-columns-qualified-v1.json`. The unified PAGE receiver and
complete source/global closure still require integration; no STARK, segment,
device, proof timing or peak-RSS measurement ran.


Actual capacity CPU driver optional seven-family publication now passes all
19 focused nonproving checks in both original execution recipe sources, with
1843 unchanged pins per gate (ReleaseFast legacy; Debug selected). Real dual
driver, producer, fresh original capture, independently row-derived key and
standalone supplemental leaf receiver bodies are emitted and retained, never
invoked. Sparse roster binding, exact source pointer identity, schedule custody,
transport corruption and allocation rollback are covered. Root fixed only
public visibility on imported body marker exports. All attempts and exact
source snapshots are retained in `cpu-recursive-publication-qualified-v1.json`.
Publication remains optional: native-fused pairing, scoped/public compensation,
source/global closure, canonical activation and a genuine complete block proof
remain open. No segment, STARK, device, proof timing or peak-RSS measurement ran.


Bounded wide public-window integration now passes 17 focused nonproving
checks with 1740 unchanged pins. Exact contiguous fan-in1..4, original global
indices, full-u64 compensation/count/carry/adjacency, million-word input frame
bounds, independently held cached input expectation and allocation rollback
are covered. Actual genuine parent producer, fresh receiver, higher source
and default shared-row bodies are emitted and retained without invocation.
The initial namespace/shadow failures and corrected snapshot are retained in
`wide-public-windows-qualified-v1.json`. Original child channel bytes remain
unchanged. The new input root is policy custody only: the in-circuit original
B5PD/input-root bridge, reusable job-wide tail carrier, source/global closure
and canonical activation remain open. No STARK, segment, device, proof timing
or peak-RSS measurement ran.


Original framed BLAKE3 input-tail reuse now passes all 10 focused nonproving
checks with 639 unchanged source pins. Standard BLAKE3 parity covers the
authoritative 68-byte header, 956-byte first input region, exact-full-chunk
ROOT handling and absolute tail counters. Original joined hash equations
share the tail once across four original frames plus an independent input
root, with source/claim mutations and allocation/retained-budget rollback
covered. The incorrect hand-counted framing assertion and comptime standard
hash narrowing failure are retained alongside their repairs in
`original-words-tail-qualified-v1.json`. Genuine job-wide carrier placement,
complete source/global closure and canonical activation remain open. No
segment, STARK, device, proof timing or peak-RSS measurement ran.


The actual optional CPU scoped-job callback and standalone independent
receiver snapshot now pass all 22 focused nonproving checks under both
original execution recipes, with 1869 unchanged pins per gate. Nine authored
behavioral checks cover exact eight-family sparse nonrounded coverage, source
and event mutations, roster and reader allocation rollback, context binder
parity, canonical summary limbs and fail-closed inherited clock bounds. Real
dual driver, authentic key reconstruction, bounded fresh folds and one-time
JobSetup transfer bodies are emitted and retained, never invoked. Typed family
switches, original Open proposal coercion and a test FilePin alias were fixed;
attempts are retained in `cpu-scoped-job-qualified-v1.json`. Positive complete
JobSetup transfer, shared input-tail/public compensation integration and
complete source/global closure remain open. No segment, STARK, device, proof
timing or peak-RSS measurement ran.


The actual compact/public compensation parent snapshot now passes all 15
focused nonproving checks under both original execution recipes, with 1750
unchanged pins per gate. Seven behavioral checks cover scalar original signed
accounting and field mutations, independent per-window register closure,
exactly-once native compensation, full output/carry bounds, distinct typed
parent identity, receiver framing guards and transferred-buffer rollback.
Genuine two-child verifier rows, shared graph attachment, parent production
and independent fresh receiver bodies are emitted and retained, never invoked.
One shadowed parameter was renamed; failed/passing attempts are retained in
`scoped-public-compensation-qualified-v1.json`. Original roster/clock limits,
wide shared-tail integration, complete source/global closure and canonical
activation remain open. No segment, STARK, device, proof timing or peak-RSS
measurement ran.


The standalone scoped receiver now checks bounded pinned manifest framing,
indices and individual/aggregate byte limits before reconstructing any
original sources or consuming base proofs. All 13 focused nonproving checks
pass with 1847 unchanged pins; four behavioral fixtures demonstrate actual
early failures using deliberately uninitialized authority pointers and cover
manifest allocation rollback. Actual receiver/transfer bodies also compile
under the selected recipe; the genuine-input positive transfer harness is
retained but not invoked. Root also shares a private original normalization
kernel within Full.Policy.validate: successful K-leaf batches check the whole
coverage roster on entry and exit rather than 1+K times. Public normalize and
verify boundaries and original typed leaf validation remain intact. This is
a code-path work reduction, not a timing claim; positive full-policy runtime
parity remains pending. Exact shared revision and source snapshots are retained
in `cpu-scoped-receive-guard-qualified-v1.json`. Complete source/global
recursive closure remains open. No segment, STARK, device, proof timing or
peak-RSS measurement ran.


The unified raw SHA/fold BLAKE memory-source PAGE snapshot now passes all 20
focused nonproving checks with 1717 unchanged source pins. Actual producer and
fresh independent ten-tree receiver bodies compile and are retained, never
invoked. Fixtures cover original byte framing and all capture boundaries, exact
input routing and arithmetic reconstruction, separate local claim closures,
shared masks, scalar/off-domain equations, independent fold fixed metadata,
strict codec bounds and allocation rollback. Cohesive ownership, original AIR
build arguments and proof-kind padding integration repairs and all failed
attempts are retained in memory-source-unified-page-qualified-v1.json. PAGE
job publication, fresh PAGE/lane/range join qualification and final recursive
source/global/public closure remain open. No segment, STARK, device, proof
timing or peak-RSS measurement ran.


The new original memory-source PAGE/lane/range join now passes all seven
focused nonproving checks under each execution recipe, with 1722 unchanged
pins per gate. Five behavioral fixtures cover independent source authority,
canonical fields, separate indexed/fold/predecessor/initial/final closure signs,
exact root census and consuming lifecycle/resource guards. Actual bounded
owner/setup and original PAGE/lane/range receiver bodies are retained, never
proof-invoked. The initial missing recipe-runner attempt and both passing
snapshots are preserved in memory-source-page-join-qualified-v1.json. Genuine
proof execution, transition/public/global final recursive integration and
canonical activation remain open. No segments, STARKs, devices or performance
measurements ran.


The original input-tail provider and bounded original Frame.words/B5PD
consumer snapshot now passes all 14 focused nonproving checks with 1729
unchanged pins. Ten authored checks cover exact original CV placement and
seven-round uses plus one export, scalar and fixed routing parity, byte
multisets and mutations, unchanged original B5PD digest, allocation rollback
and backing-owner lifetime. Actual provider publication, fresh receiver,
nested capture and bounded column bodies compile and are retained, never
proof-invoked. Two fixture assumptions were repaired against independently
counted original DAG edges and the actual affine destination, with a new
nonempty-frontier conservation check; failed and passing evidence is retained
in input-tail-provider-qualified-v1.json. Active native/public normalization
and routing are not switched. Distinct v2 window activation and exact
common-ancestor links, complete closure and canonical proof remain open. No
segments, STARKs, devices or performance measurements ran.


Actual source PAGE join verification now uses consuming exact-roster batches
with a private genuine verification kernel. Full original SOURCE/Word roster
reconstruction occurs at each kind batch entry and exit plus the join entry: a
successful join changes from 1 + raw_pages + fold_pages reconstructions to five.
Every original per-page pin, descriptor, fixed-root, transcript, AIR and FRI
check remains; the public single-page API still reconstructs its full epoch and
consumes rejected proof ownership. No public skip flag or reusable admission
token exists. Accumulations are provisional until batch/whole-join success.
All eight focused nonproving checks pass under both original execution recipes,
with 1722 unchanged pins each, including a new no-proof-take resource guard;
actual batch and fresh receiver bodies are retained. Evidence and changed
source hashes are retained in memory-source-page-roster-batch-qualified-v1.json.
This is a code-path work-count reduction, not a measured speedup. Genuine
positive PAGE proof batches, source driver activation and final recursive
closure remain open; no segment, STARK, device or performance run occurred.


The actual bounded source-PAGE job snapshot now passes all ten focused
nonproving checks with 1716 unchanged pins. Seven authored checks exercise
shared-budget constructor and parent/setup leases, aggregate metadata/disk
bounds and overflow, failed/live phase guards, genuine original SHA/fold claim
proposal graph parity and mutations, four initial constructor allocation
failures and every detached fold-inventory allocation failure. Real collection,
persistence, complete ordered seal, replay, proving, strict encode/decode, fresh
verification and synced publication bodies compile and are retained, never
proof-invoked. One nested digest loop syntax repair and both failed/passing
source attempts are retained in memory-source-page-job-qualified-v1.json.
Production ownership releases producer proof and PCS page before decode/fresh
verification, retaining only encoded bytes and bounded public fold recipes.
Driver selection/durable fresh artifact loader and final recursive closure
remain open. No segment, STARK, device or performance measurement ran.


Nested retained PAGE join/transition allocations now use additive
SharedHostBudget.createRetainingParent. An identifiable backing shared budget
is retained until the nested allocator and control object have been destroyed;
original create retains its borrowed-allocator contract. All seven focused
allocator checks pass, including original owner release, descendant/external
leases, exact budget/accounting boundaries and every allocation failure of
the new ownership path. Evidence is preserved in
shared-host-budget-backing-qualified-v1.json. Actual receiver proof execution,
canonical driver activation and process peak memory remain unqualified.


The actual PAGE source-to-original capacity native/caller transition receiver
snapshot passes all 14 focused nonproving checks under both execution recipes,
with 1769 unchanged pins each. Six authored behavioral checks cover exact
pinned memory/source/seal/limit identities, original caller all-RW event census
and overflow, missing/duplicate hook order, exact event count/transition signs,
resource guards and retained-output allocation rollback. Genuine new PAGE/lane/
range and original native/caller/fused/ROM receiver and hook bodies are retained,
never proof-invoked. The unchanged Memory.admitPins extraction preserves old
canonical init verification, while the new wrapper consumes genuine fresh
source proofs internally before supplying the original transition equations.
Independent setup leases and nested fold-descriptor release compile in this
snapshot, and nested backing owners use the qualified retained-parent budget.
Evidence/source hashes are retained in memory-source-page-transition-qualified-v1.json.
Actual proof execution, replacing duplicated detached loops, remaining global/
public/final recursive closure and canonical activation remain open. No segment,
STARK, device or performance measurement ran.


The actual opted-in CPU source PAGE driver snapshot passes all 17 focused
nonproving checks with 1918 unchanged source pins. Four authored behavioral
checks exercise option/resource guards, exact positional source-file lengths
and offsets, durable fold inventory allocation rollback, independent census
and compact file corruption rejection. Actual collection, durable publication,
source transition and CPU driver bodies compile and are retained, never invoked.
PAGE artifact counts/bytes are included in reports; publication timing covers
replay, proving, encoding and initial verification, rather than isolated proving.
Evidence is retained in cpu-source-page-driver-qualified-v1.json. Removing
repeated Fold construction and old detached verification, standalone durable
admission, final recursive closure and canonical activation remain open.
No segment, STARK, device or performance run occurred.


Durable source transition loading now admits one original Bundle.Store reader
under JobBudget for the whole synchronous receiver lifetime. takeWithAllocator
preserves original SHA-pinned file read, strict original decoders and consuming
failed-attempt state while separating bounded proof ownership from retained
metadata. Canonical sparse family/index lookup uses binary search after original
strict roster admission. All eight focused nonproving checks pass with1763
unchanged pins, including exhaustive proof allocation rollback, denial of all
post-admission metadata allocation and decoded proof lifetime beyond Store
release. The actual connected source PAGE driver/Loader bodies also pass
semantic analysis with1920 unchanged pins. Evidence is retained in
bundle-reader-reuse-qualified-v1.json. No actual proof verification, speed or
peak-memory claim is made.

The actual CPU source collection path now traverses original Fold.Cursor once
and commits replayed canonical operands through Job.collectWithOperations.
All five focused nonproving checks pass with1807 unchanged pins: dense64-leaf
full-tree operation parity across more than128 records, resource/identity/order/
footer/SHA/truncation rejection and preallocation Job admission guards. Spool
records use the original250-byte operation encoding with a64-record16000-byte
buffer. Footer/hash completion is required before job sealing, and spool bytes
are charged to the aggregate operand limit. Evidence is retained in
memory-source-fold-spool-qualified-v1.json. This removes the second original
tree traversal in this code path, but adds spool IO alongside per-page operand
files; range-based loading to remove that duplication remains open. No segment,
STARK, device, end-to-end speed or peak-memory run occurred.


Selected v2 bounded public windows and the original input-tail carrier ancestor
snapshot now pass all31 focused nonproving checks with1779 unchanged pins.
Five new byte-equation/layout/OOM checks run alongside ten original wide-window
and ten original tail-provider checks, plus retained genuine publisher/fresh
receiver/ancestor bodies. Root repaired an inputFrontier declaration shadow
and an actual graph-construction ABI error: all source input nodes must precede
all equality operation nodes. Pair/source ordering and equality math are
unchanged; no test expectation was weakened. Failed and passing attempts are
preserved in tail-linked-public-qualified-v1.json. Actual selected <=4-window
and one-carrier/<=3-consumer ancestor production bodies compile, never
proof-invoked. Larger-forest placement/multiplicity, canonical selection, global
source closure and final recursive authority remain open. Source-derived keys
require rederivation after shared factory extraction. No segment, STARK, device,
end-to-end speed or peak-memory measurement ran.


The explicit CPU/capacity PAGE source path now selects genuine PAGE/lane/range
verification inside the original private global kernel. Native/caller/fused/ROM
verification remains one original loop with both memory and table hooks; table,
register, byte, provider and final accounting equations are unchanged. Complete
detached source selection shares original native forest preparation/verification
and one DetachedTransport implementation. Metadata guards are extracted
unchanged, and external public input length/SHA remain independently checked
before source consumption. All16 focused nonproving checks pass with1782
unchanged pins; actual legacy/capacity/default/PAGE-selected global and complete
detached bodies are retained, never invoked. Evidence is retained in
page-global-receive-qualified-v1.json. Standalone durable policy and actual
Driver replacement, positive proofs, canonical activation and final global
recursive closure remain open. No performance claim is made.

Store.withProofAllocator now supplies the original typed callbacks from a stable
borrowed ProofReader adapter, sharing default loader factories and the same
consuming Store session. This separates retained metadata ownership from fresh
proof deallocation without rebuilding reader state. All eight focused
nonproving checks pass with1823 unchanged pins, including actual literal native
callback decode and exhaustive allocation failure/lifetime checks. Evidence
is retained in bundle-reader-adapter-qualified-v1.json; positive all-family
transport/proof verification and standalone global execution remain open.


The actual opted-in source controller now selects exact-roster Job.publishAll.
Its original proving/codec/fresh-verification pipeline reconstructs the complete
context at raw/fold roster entry and exit: five redraws per PAGE become four
per publication job. Every original per-PAGE replay, fixed root, arithmetic/core/
table claim, mask, strict decode, PCS and FRI check remains. Proposal-only codec
APIs mint no authority; public single-operation APIs retain full checking.
Durable JobLoader uses decodeProposal beneath genuine Join roster entry/exit
checks, retaining the five join redraws independent of PAGE count. Producer
proof/PCS owners are released before nested decoding. Failed batches poison
partial publication; callbacks are provisional until batch completion. All12
focused nonproving checks pass with1817 unchanged pins. The earlier passing
tests with one drifting source pin were rejected and preserved, then rerun
against frozen production sources. Evidence is retained in
memory-source-page-publisher-qualified-v1.json. Positive actual PAGE proofs,
standalone durable policy/Driver replacement and final recursive closure remain
open. The redraw counts are code-path counts, not measured speed or peak memory.
No segment, STARK or device run occurred.


The explicit capacity source PAGE driver now publishes original PAGE artifacts
and a length/SHA-pinned normative policy, then destroys its complete producer
Job before cold standalone complete verification. Independent original Metadata
reconstructs Globals; durable PAGE policy rebuilds original Source/Batch/Context
admissions without transported VerifiedPage claims. All original native/caller/
ROM/lookup/forest verification shares one original PAGE-backed complete receiver;
the prior extra transition plus old detached pass is absent in this selection.
One retained consuming Bundle.Store and independently retained pointer-bearing
policies supply original typed callbacks under the proof allocator. Producer and
durable loaders now share original Fold inventory reconstruction and ownership.
Both actual legacy and capacity Driver bodies compile and are retained, never
invoked here. All13 durable and18 source/Driver nonproving focused checks pass
with1823 and1936 unchanged literal source pins respectively. The initial two
compile-time ABI hashing quota failures are retained; a local1M branch quota
preserves the exact digest. Evidence is retained in
cpu-source-page-durable-driver-qualified-v1.json. Observational report scope is
explicitly complete_bundle, with the independent PAGE policy pin returned.
Positive complete-admission policy transport, genuine positive complete proof
execution, canonical activation and final recursive global compensation remain
open. Source selection remains optional/null by default. No segment, STARK,
device, end-to-end performance or peak-memory run occurred.


Actual raw/fold original PAGE recursive capture, full verifier Bus preparation,
Parent publication and fresh Leaf receiver bodies now compile and are retained,
never proof-invoked. Both legacy and selected roots pass15 focused nonproving
checks each with1736 unchanged literal pins. Eight behavioral fixtures cover
exact4/5/10 composition/FRI suffix slots, original full Fold scalar/symbolic
quotient parity at arbitrary OODS samples and input mutation, union-mask/log/count
rejection, original allocated-proof owned/borrowed failure custody and exhaustive
frame clone allocation rollback. The generic five-commitment access-capture
composition/FRI slot selection is corrected; legacy recorder admission remains
strict. Root repaired immutable setup pointer qualifiers in the fixture and
preserved its failed semantic attempt. Evidence is retained in
memory-source-page-recursion-qualified-v1.json. Raw equation parity behavior,
positive original/recursive PAGE proofs, exact recursive PAGE source-root
assembly and final caller/RAM/ROM/lookup compensation remain open. No segment,
STARK, device, end-to-end speed or peak-memory run occurred.


The genuine fan-in4 input-request forest now retains actual bounded publisher,
runner, same-parent graph and fresh root receiver bodies. Its exact original
window/count/leaf/full-u64 coverage and unique carrier have18 focused checks;
44 cohesive forest/window/tail/provider checks and12 original global public
export checks pass. Allocation-failure testing caught a real returned stack
arena allocator-control lifetime crash. One stable_graph_arena_v1 owner now
serves forest, ancestor, shared Wide/v2 and global public-export graphs, retaining
original equation/transcript/graph identities. Original packed configuration
framing now has its missing mixFelts method plus exact canonical/extended
word tests. Minimum-count planning carries short remainders forward:19 checks
prove ceil((leaves-1)/3) merge nodes plus one carrier for16 sizes1..257, exact
once custody, no unary merge and no rounded count. The17-leaf/65-window example
needs7 total nodes rather than9; this is a routing count, not a timed proof.
Failed semantic/allocator-crash attempts are retained in
input-request-forest-qualified-v1.json.

Positive normative PAGE metadata transport now passes5 checks with1785
unchanged literal pins. Original Source/Batch/plans/B5SS/Context admissions and
one real raw/fold six-tree CPU premix construction feed Export.write->Policy.read
independent reconstruction, ownership, complete allocation faults and independent
pin/Global/config/plan/seal tampering. The fixture has5 original empty-stream
SHA padding compressions and2 Fold empty/root operations; fixed tables retain
log16. Commits occur once outside the OOM sweep. Native/ROM/provider roots and
absent artifact pins remain explicit UNVERIFIED metadata proposals; no proof
receiver runs. Evidence:memory-source-page-policy-positive-qualified-v1.json.

Actual original input-request Snapshot/key/schedule ownership and typed CPU
publish/reconstruct bodies now compile and are retained. All17 focused contracts
pass with1886 unchanged literal pins: original full clocks/output/coverage copy,
shared input alias, schedule coordinate/sign/part/uses custody, resource caps and
complete allocation rollback/retained-parent destruction. The real last fresh
root is transferred with its stable owner in the publisher body. Evidence:
input-request-policy-owner-qualified-v1.json. Positive full Snapshot/proof
execution, canonical caller installation and final compensation remain open.

Architecture audit found an additional concrete scaling obligation: original
scoped_child_verifier_rows.collect emits child_term inputs for every inherited
packed public supply; forest Source exports the entire node schedule. Descendant
terms therefore grow with subtree size despite compact summary/replay fields
and fan-in4. A bounded lookup cache cannot remove this equation/grammar cost.
The next version must close internal recursive-wire suppliers in the same
genuine node proof, exporting only authenticated compact summary fields.
Instance-pinned fixed boundary AIR suppliers are a genuine closure seam, but
independent expected-key reconstruction and reusable setup/self-contained final
verification remain explicit obligations. No host-computed supply scalar or
closure flag substitutes for those equations. All segment/STARK/device runs
remain stopped; no complete block time or peak-memory result exists.


New closed-node supply recipes have an additive version2 streaming BLAKE3
identity and immutable lookup session. Explicit domains/counts and fixed
little-endian records are streamed in64-record buffers (3072 record bytes),
replacing per-tuple Channel framing for this new version only. Existing proof
transcripts and normative version1 digests are unchanged. Six behavioral
fixtures plus their root import pass7/7 with1824 unchanged pins: independent
one-shot byte oracle at chunk/buffer boundaries, every schedule field/value/
count binding, malformed geometry rejected before policy access, poison on
failed/partial/excess append, exactly one original admission at entry/exit,
and borrowed mutation rejection. Initial semantic fixture-shadow failure is
retained. Evidence:public-supply-streaming-v2-qualified-v1.json. Production
closed-node integration/body qualification, independently reconstructed keys
and all final block obligations remain open. No segment, proof, device or
performance run occurred; buffering is an implemented structural improvement,
not a measured end-to-end speedup.


The new version5 closed input-request node path now retains actual independent
Setup.derive, genuine full child verifier Rows, Stage.publish, fresh Receiver
and zero-term Source bodies. Semantic and focused qualification pass with1884
unchanged pins;16 total selected checks include10 behavioral fixtures, a body
marker and unnamed imports. Fixtures verify original enabled four-coordinate
boundary equations, real original framework interaction sum/sign/multiplicity
parity, committed-row preservation, allocation rollback, exact allocator
custody, mutation guards, canonical config framing and minimum fan-in4 topology.
Original child AIR/DEEP/FRI/PoW/transcripts remain unchanged. Version5 suppliers
close inside actual node AIR; its exported schedule/Source.terms are empty,
node child_term rejects and per-wire lookup constructs no descendant Owner.
Streaming sessionv2 is integrated and source-authority-pinned. Evidence:
closed-input-request-forest-qualified-v2.json. These are equation/ownership and
actual-body qualifications, not positive proof execution or measured speed.
The instance-pinned key still depends on genuine captures, so standalone final
expected-key reconstruction and reusable geometry remain open; new v5 durable
owner/CPU selection and complete global compensation also remain open. Oldv4
routes/defaults are untouched. No segment, STARK or device run occurred.


Original Raw PAGE full accumulated quotient parity now joins the prior Fold
qualification. An independent new fixture constructs original raw admissions,
semantic/fixed SHA/arithmetic setup and original nine-tree Components.Owner;
actual maskPoints/evaluateConstraintQuotientsAtPoint match unchanged symbolic
Recorded.record(.raw) at chosen arbitrary current/previous OODS samples, and
mutating an original main sample yields UnsatisfiedCircuit. Semantic and5 total
focused checks pass with1722/1724 unchanged source pins; two are behavioral
parity/mutation tests, others unnamed imports. This compares the full weighted
accumulator, not independently instrumented individual constraint terms.
Evidence:memory-source-page-raw-parity-qualified-v1.json. Proposed pins/claims
do not mint proof authority. Positive PAGE/recursive proofs, assembled source
root/join and final standalone closure remain open. No PCS, segment, STARK,
device or end-to-end speed/peak-memory run occurred.


New version5 durable request Owner and typed CPU Selection now qualify actual
publish/reconstruct/original native+carrier+WM/closed-node/fresh-root/read/
teardown bodies. Semantic and14 focused checks pass with1898 unchanged pins;
eight behavioral fixtures cover exact minimum window/node census, allocation
rollback, owned explicitly unadmitted future slots, separate b5ir5/WM transport
namespace, zero node schedule, retaining-parent metadata budget and unfinished
owner rejection. Real original children derive every expected topological key
before parent acceptance; last fresh root transfers with stable owner. Evidence:
closed-input-request-policy-owner-qualified-v2.json. No proof was executed or
admitted by these fixtures. Driver/canonical activation, independently derived
shape-only setup/final standalone key, all global compensation and end-to-end
measurements remain open. Audit no longer assumes rejection attempts or Merkle
query dedup are capture-dependent fixed data: existing bounded retries, ordinal
root sharing and private constrained directions may already support independent
shape derivation, which needs exact source evidence and implementation. Segment,
STARK and device runs remain stopped.


Actual raw/fold PAGE recursion now has a closed minimum-count fan-in4 forest.
Semantic and22 focused checks each for legacy/local-zero recipes pass with
1849/1851 unchanged pins. Sixteen behavioral checks cover exact physical leaf
census, no rounded proof count, every small roster minimal merges, original
22-Q scalar/symbolic claim merge and original PAGE/Fold root closure, mutated
exports/sign/count/source roots, invocation/slice ownership/canonicality/OOM,
empty external schedule, original full Raw quotient parity, checked u32 offsets
and cached/uncached compiled recipe parity. Original leaf/full child verifier,
fixed-template, parent publisher and fresh receiver/Source bodies are retained
only. Root corrected alias/capture names and checked offset typing; all failed
semantic attempts including its intermediate text replacement fault are kept.
Compiled recipe authority is cached once through the independently qualified
thread-safe static helper; helper/protocol bytes are pinned, dynamic policies
and proof checks are never cached. Evidence:memory-source-page-forest-qualified-v1.json and
static-source-authority-cache-qualified-v1.json. PAGE node suppliers
close with original Boundary AIR and export no descendant terms. Initial/
endpoint remain OPEN for sorted RAM; all native/caller/register/ROM/lookup/
accounting and final standalone authority remain OPEN. A genuine on-demand
durable catalogue/forest owner is still under construction. No segment, STARK,
device, e2e performance or peak-memory run occurred.


The real PAGE-root/sorted RAM/range small-instance recursive join now qualifies
original fresh leaf Sources, same-parent verifier rows/equation graph, version18
producer/codec and fresh Receiver bodies. Semantic and14 focused checks pass
with1854 unchanged pins; nine behavioral fixtures cover original PAGE.Join
scalar signs, all source/RAM closed coordinate mutations, all17 range planes,
separate opposite-deficit shards (no pooling), mandatory zero-RAM source
closure,49-input symbolic parity/mutation, complete graph/transcript allocation
failures, original RAM90/range claim-coordinate reconstruction and hard cap
rejection before authority access. Root fixed one reader capture shadow error
and retained the failed attempt. Direct parents accept at most4 real verifiers
INCLUDING PAGE root, regardless of enlarged caller resource limits. This is
a qualified small-instance equation/body path, not a scalable block assembly:
a new independently conserved shard forest is required and under construction.
Native/caller transition stays exported OPEN; every wider register/state/public/
ROM/table/lookup/accounting and final expected-key obligation is OPEN. Evidence:
memory-recursive-source-ram-range-join-qualified-v1.json. No positive proof
execution, segment, STARK, device, e2e performance or RSS run occurred.


Canonical fold operand publication/loading now streams unchanged normative
bytes in64-record/16000-byte buffers through the original atomic publication
semantics. Publication needs no allocator; loading retains only decoded
operations, removing a1024096-byte encoded-page heap allocation at4096 records
from each path. Six focused transport checks (five behavioral plus root) and
five original spool/consumer checks (three behavioral, retained real collect/
Job bodies and root) pass with1723/1821 unchanged pins. Byte/pin oracle covers
1/63/64/65/129/4096 records; tests cover bounded allocation, full allocation
rollback, late encoder cleanup, digest-before-proposal guards, truncation,
overflow/caps and exclusive publication/temp ownership. Initial semantic
shared-composition loop parser failure is retained and repaired by its owner.
Evidence:fold-operand-streaming-qualified-v1.json. No proof, segment, device,
speed or process-peak-memory run occurred. Full census spool and individual
PAGE operand files still duplicate durable record storage/IO; eliminating that
requires a separately authenticated slice/index migration, not a speed claim
from this bounded heap staging improvement. Final recursive/global closure
and canonical end-to-end qualification remain OPEN.


Partial capture-free recursive parent setup pieces now pass semantic analysis
and11 focused checks with1892 stable pins: five behavioral original component
column/mask/degree parity, independent mutation-seal rejection, exact resource
policy/absence of verifier authority, retained allocator custody and original
bounded native transcript/fixed-plan parity checks, plus actual-body marker
and unnamed imports. Actual single original composition, DEEP/FRI, transcript,
query/trusted path/fixed-arithmetic pieces and original live verifier/publisher
bodies are retained only. Root stopped the unnecessarily broad OOM fixture
at90.78s; it rebuilt the old component factory at every failure point. New
geometry/independent seal/teardown failures are still exhaustive, while original
full component parity runs separately once; complete revised gate18.97s. All
failed/interrupted attempts are preserved. Evidence:
recursive-parent-fixed-pieces-qualified-v1.json. Complete fixed key/standalone
expected key is NOT implemented; original opening-input/link/fusion/fixed
roster/G partition/PCS assembly remains open. Public boundary values still
need authenticated MAIN suppliers for keys reusable across instances. No
proof, segment, device or performance run occurred; canonical70/26 unchanged.


Actual on-demand durable PAGE leaf/closed-parent owner and typed CPU selection
now qualify independently reconstructed original setup/capture, publication,
standalone file reconstruction, summary-only genuine Parent receiver/Source
and root teardown bodies. Semantic analysis and21 focused checks for EACH
legacy/local-zero recipe pass with1899 stable pins:14 behavioral checks, real
body retention, independent recipe assertion and unnamed imports. <=4 direct
leaf inventories are scoped on demand; receiving lower closed parents needs
no descendant descriptor leases. Idle Prepared slots reject original proof
acceptance. Root repaired mutable Dir/typed optional root and consolidated
~8KB duplicated Source code into one statically selected ForReceiver body;
public alias ambiguity failure is retained/fixed. Audit found the8GiB live
lane incorrectly nested below1GiB metadata; producer loops now use retained
aggregate backing independently, matching existing request owners. New tests
verify scratch above metadata cap, both local caps, original aggregate cap,
escaping summary allocator custody and all allocation rollback. Evidence:
memory-source-page-forest-owned-qualified-v1.json. Actual bodies retained only;
no positive PAGE or recursive proof ran. Expected keys still reconstruct from
genuine original PAGE artifacts, not standalone reusable setup. Full source/
RAM/native/caller/register/ROM/lookup/accounting closure, canonical activation,
e2e proving time and measured peak memory remain OPEN. Segments remain stopped.


The scalable minimum fan-in4 RAM/range shard forest and final PAGE-root/compact
memory join now pass semantic analysis and16 focused checks with1913 stable
pins. Eleven behavioral topology/u64-census/resource/mutation/17-plane local
closure/final signs/scalar-symbolic/new graph/ownership/OOM fixtures plus real
original producer/strict codec/fresh receiver/Source/body retention, root and
three unnamed imports execute no proofs. Root repaired node declaration
shadows and the actual RAM graph fixture caught BuilderAlreadyActive; BOTH
real RAM forest and final PAGE+RAM graph now deactivate before finish. Failed
semantic/focused attempts are retained. Per-shard range providers cannot pool
opposite deficits, upper nodes accept only locally closed shard roots, and
all physical proof counts remain exact/minimal. Final source/RAM endpoint and
range equations close while native/caller packed transition is deliberately
exported OPEN. Evidence:ram-range-shard-forest-qualified-v1.json. Durable spec
catalogue/manifest/typed job owner is next. Scalable global connection must
retain requester-only packed transition before the old scoped root zeroes its
combined requester/provider sum; no interim all-RAM-verification bridge is
being substituted. Full original public/register/state/ROM/lookup/accounting,
standalone/reusable expected setup, canonical driver and positive e2e proof/
measurements remain OPEN. No segment, STARK or device run occurred.


Requester-only extraction, direct public compensation and final two-root join
now have focused NONPROVING qualifications. Requester summary passes14 checks
in Debug with1919 stable pins (six behavioral guards plus body/import checks);
the earlier ReleaseFast attempt is preserved separately. PUBLIC21 passes12
checks with1849 stable pins (four behavioral guards plus body/import checks).
It implements original public/register/state/program/accounting equations
against retained requester claims and forwards packed transition T without
verifying RAM descendants. Independently admitted public metadata remains
public; it is not a private decoder/hash proof. Source admission compares
validated compact seal/ref, allowing stable metadata to outlive the earlier
requester capture after actual verifier rows have been copied. The final
VERSION22 join passes13 checks with1937 stable pins (five behavioral guards
plus body/import checks): original requester T plus memory T, same base seal,
source endpoints/census, exact security and closed supplier schedule. Genuine
child preparation, producers and fresh receivers are compiled/retained only.
No positive same-parent graph, recursive proof or end-to-end run is claimed.
Evidence:requester-summary-qualified-v1.json, requester-public-qualified-v1.json
and requester-memory-join-qualified-v1.json. Canonical70 queries/26 PoW unchanged.

The durable RAM/range forest catalogue, manifest and typed owner now pass
semantic analysis and18 checks for EACH legacy/local-zero recipe with1919
stable pins (12 behavioral checks plus retained bodies/recipe/import checks).
Root shortened real preparation lifetimes: original leaf/node captures are
released after independently owned verifier rows are prepared; those rows
and temporary public owners are released before fresh receiving; publication
uses the existing consuming worker. Escaping PAGE/memory summary roots keep
retained aggregate scratch-budget leases. This is source-level lifetime
engineering, not measured peak RSS or positive proof custody qualification.
Manifest proposals are compared only after original expected keys are rebuilt.
Expected setup still depends on original artifacts and is not a reusable key.
Evidence:ram-range-forest-owned-qualified-v1.json.

The complete original ONE-CHILD lower fixed roster now passes semantic
analysis and15 checks with1898 stable pins: original opening encoding,
fusion, G partition and PCS matching parity/guards plus retained factory
bodies. Complete standalone closed setup remains OPEN. Exact fixed namespace
work found an important remaining port: inactive arithmetic rows do not let
the AIR infer MAIN circuit identifiers from fixed schedules. Original emitter
identifiers must be admitted explicitly; unsupported cases fail closed.
Evidence:recursive-parent-fixed-roster-qualified-v1.json.

Capacity/native-fused/caller/caller-fused/ROM/six-table source adapters already
exist in actual typed admission. The old kind-only pendingAdapters report is
conservative/stale; legacy native_fused_v2 remains unsupported. The next
cohort is one statically selected bounded requester fold, a durable final
requester-public/memory root assembler, exact fixed attachment ports and safe
independent setup. Current optional driver selection is NOT canonical default.
Full source/global closure, complete block receipt, reusable setup, canonical
activation, positive e2e proving time and measured peak memory remain OPEN.
Segments, STARK/device/benchmark runs remain stopped.


All eight original native/capacity/open-parent/range/RAM/ROM/caller/lookup
public schedule digest paths now share allocation-free bounded duplicate
detection. Sorted schedules require O(n) comparisons; arbitrary legacy order
retains exact acceptance and transcript framing using O(n log n) deterministic
heap sort of private u16 indices. The schedule itself is never reordered.
Largest caller scratch is65,792 bytes; open-parent scratch8,192 bytes.
Original circuit+wire identity, resource/coordinate/field bounds and errors
remain enforced. Five behavioral fixtures plus root pass6/6 in1.63s Debug
with1724 stable pins: independent original framing for all eight families,
nonadjacent metadata-different duplicate rejection, original bounds, maximum
caller schedule/full-u32 key parity, exhaustive small tuple parity. Initial
fixture narrow-field casts failed semantic analysis and were repaired; failed
attempt preserved. Evidence:public-wire-uniqueness-qualified-v1.json.
This removes repeated quadratic metadata work; no proving speedup, proof,
segment, benchmark/device or process-peak measurement is claimed.


The actual CPU requester job now qualifies14/14 Debug checks with1906 stable
pins (six behavioral plus retained bodies/imports). One statically selected
fold implementation supports complete/requesters; the requester path retains
its already-fresh root plus the actual allocator lease, avoiding a second
root verification. Real child captures die immediately after original verifier
rows own their inputs; consuming workers release source columns at last use,
and rows/producer/workspace die before independent Fresh receiving. Exact
subtype reporting recognizes supported capacity/fused/caller adapters while
legacy fusion remains unsupported. No new source authority is granted.
Evidence:cpu-requester-job-qualified-v1.json.

Durable PUBLIC21 and FINAL22 final assembly passes20/20 Debug checks for EACH
independently selected legacy/local-zero recipe with1950 stable pins. Twelve
behavioral manifest/source/key/transport/resource/lifetime/window-copy/OOM
checks plus body/import retention execute no proofs. PUBLIC21 preparation
owns all genuine verifier rows before the optional requester capture-release
callback; stable normative catalogue/source metadata remains. Expected keys
and schedules derive before manifest proposals are accepted. Memory/PAGE
ownership transfers only after successful actual FINAL22 fresh receiving.
Evidence:cpu-final-job-qualified-v1.json.

The selected four-stage CPU completion is connected to the real capacity
Driver and installed producer entry via optional --recursive-completion.
Original canonical product collection/profile/store stay independently
selected. Required recursive families/source PAGE/register windows and exact
original RAM proof/plan limits are checked before collection; old scoped_job
selection is mutually exclusive. One retained aggregate allocator covers all
stages. Driver/JSON report selected completion stage ns (setup/proving/file
staging/fresh receive, NOT isolated STARK), proof counts/bytes, final manifest
pin and allocator peak. Current source qualification passes20/20 Debug checks
with2039 stable pins (seven behavioral plus installed entry, both original
Driver, genuine completion/producer/receiver body and import retention).
Evidence:cpu-recursive-completion-qualified-v2.json; historical v1 preserved.
Actual path is compiled/retained ONLY: no guest, proof, segment or device ran.

Failure/retry review found incomplete published-file cleanup. Both canonical
fold recipes now use one exclusive prefix tracker; successful file inventory
advances BEFORE observational callbacks and disarms only after setup.finish.
Seven filesystem callback/later-failure/collision/private-inode/resource/
commit/reconstruct fixtures plus genuine retained fold/Job bodies pass15/15
Debug with1906 stable pins. Cross-stage completion tracks successfully created
PAGE/RAM/public/final roots/manifests and removes only those files if a later
stage fails; original inputs/pre-existing destinations/other recipes survive.
Two stage-handoff filesystem guards are included in the assembled20-check
gate. Evidence:cpu-scoped-publication-qualified-v1.json.

Exact <=4 recursive fixed attachments and original MAIN identifier emission
now pass22/22 Debug checks with2004 stable pins (eight new attachment and six
original fixed-roster behaviors plus body/import retention). Both arithmetic
selected modes reconstruct actual inactive identifiers via the original
emitter; fixed AIR alone is never assumed to authenticate them. Shared
ForAdmission/ForPieces factories preserve one original compiler body/default
APIs. Initial source gate caught ambiguous inner/top-level aliases and a
supplier fixture passed the wrong wrapper type; repaired with Self/explicit
AdmissionLimits and original row storage, failed immutable attempt retained.
Evidence:recursive-fixed-attachments-qualified-v1.json. Genuine bottom
RAM/range/PAGE shapes, requester packed/public tuple/B5SS fixed source ports,
exact family context/preprocessed keys and complete reusable setup remain OPEN.

The complete global/source closure audit, final standalone receiver, accepted
CompleteBlock authority, canonical default activation, positive e2e proving
with isolated time/process peak memory and resident GPU/device qualification
remain OPEN. Existing full detached bundle receiving still runs on selected
completion. No speed/memory measurement is inferred from these source checks.
Segments and proving runs remain stopped. Next cohorts are genuine native
family shapes and independently admitted public setup ports, alongside an
allocation-free exact-frame comparator that preserves original validation.


Scaling review found a real PUBLIC21 frame rejection: the shared Builder's
32 native root-offset inventory capped aggregate public statements even
though all root steps/words had independent bounded storage. PUBLIC21 mixes
one B5PD source root per window plus protocol/root bindings, so67 windows
would exceed that bookkeeping cap. Builder now exposes explicit optional
root-offset tracking: native callers keep defaulttrue and their original32
guard/exact offsets; PUBLIC21 recording explicitly disables only unused
offset inventory, preserving all root words/steps/count and limits. Four pure
framing/original digest/transition/bounds/OOM behaviors plus root pass5/5 Debug
in1.58s with1849 stable pins, including32/67/4096 window-sized root streams.
Initial fixture used a nonexistent QM31 constructor; repaired with original
fromBase and failed attempt retained. Evidence:recursive-frame-scaling-qualified-v1.json.
This is legal aggregate framing support, not a real4096-window proof, a
row/span limit lift or measured proving improvement. No proof/guest/segment/
benchmark/device ran. Global/source closure and reusable fixed setup OPEN.


Allocation-free exact statement comparator qualifies9/9 Debug checks (eight
behavioral plus root),1933 stable source pins. It replays ORIGINAL authority
mix calls against the complete original operation grammar, full root/integer/
word values and canonical field limbs; rejects regrouping, truncation, trailing
inventories, altered auxiliary coordinates and all limit violations. No
allocator or fixed root-offset array is used. Original Builder and PUBLIC21/
V20 recordFrame/transition-coordinate oracles agree; denial allocator and80
root-operation fixtures pass. Evidence:recursive-statement-compare-qualified-v1.json.
The first attempt stopped on upstream shared extraction syntax (unused PAGE
captures and ambiguous public-kernel type aliases); narrow repairs passed
without equation changes. Failed immutable attempt retained. Original Source.validate
integration remains OPEN and is the next cohort; original Fresh/admission/term
checks must stay unchanged. No proof, segment, benchmark/device, proving time
or process peak memory is claimed.


Native RAM/range fixed transcript now compiles without a proof capture. A
shared original prefix body selects either live value/challenge emission or
routing-only fixed emission, and Word.Challenges.drawWith shares exact
universal47 -> word-v4 tag -> five-pair ordering. One fixed PCS operation
schema now serves original parent and native families. Existing trusted bounded
Plan remains the only fixed emitter; no nonce, claim, challenge assignments or
MAIN columns are constructed on the fixed production path. Six independent
framing/channel/draw/fixed-plan/geometry/OOM/bound behaviors plus retained
original live/policy derivation bodies/root pass8/8 Debug with1730 stable pins.
Evidence:word-fixed-transcript-qualified-v1.json. Native source/path/context
assembly and complete family expected keys remain OPEN.

Actual PUBLIC21 and V20 Source.validate now avoid repeated frame reconstruction
and allocator use. Original Fresh/authority/term/Admission checks remain direct;
exact original nonempty/felt count/final-singleton/transition coordinate guards
stay in one per-source frame kernel. Five new integration and eight original
comparator behaviors, original Source/Admission body retention/root/imports
pass21/21 Debug with1937 stable pins. Evidence:recursive-source-frame-check-qualified-v1.json.
No accepted proof fixture was synthesized.

Genuine native RAM/range and raw/fold PAGE static shape/equation/DEEP/FRI
compiler pieces pass15/15 Debug with1915 stable pins: nine mathematical,
original full PAGE mask/graph identity, mutation, custody and new OOM behaviors
plus retained actual original/static bodies/root/imports. Original RAM24
geometry ceiling was checked against the existing Proof guards and preserved.
Initial unused fixture local was repaired; failed immutable attempt retained.
Evidence:native-bottom-recursive-fixed-qualified-v1.json. Read-only arithmetic
review confirmed original externalInputs only marks input inventory; it does
not change the original six Lower.Lane Reference/Plan. Independently supplied
public sources and complete native path/context/key rosters remain OPEN.

Requester/PUBLIC21 fixed ports pass22/22 Debug for EACH independently selected
legacy/local-zero source recipe with1925 stable pins (13behavioral plus
marker/recipe/root/imports). One static tuple+B5SS kernel shares every original
validation/lowering/source/identity/order check between live and fixed output;
packed scalar/four-coordinate port factories preserve default rejection.
Source audit caught PUBLIC21 setup routing's interleaved coordinate bug before
qualification: setup now records through original no-offset Builder and ONE
original Statement.recordAt body (generic recorder signature only), preserving
flattened words-first/felt-tail coordinates at67/4096root counts. Initial
shadowed local/static compile quota issues repaired; failed attempt retained.
Evidence:requester-public-fixed-ports-qualified-v1.json. CompletePUBLIC21
fixed namespace/context/key assembly remains OPEN.

Original parent deriveKeyWithProfile now delegates ONE fixed-only key
commitment primitive after its existing partitionHashRows. Additive
Parent.ForBackend.deriveKeyFromFixed takes only independently compiled fixed
rows/context/profile, preserving exact projection/lookup order, existing
joined shard geometry, streaming root-only commitment and coefficient-never
policy; no MAIN/capture is needed. Three pure geometry/context/early allocator
rejection behaviors plus original/fixed CPU body retention/root pass5/5 Debug
with1728 stable pins. No PCS commitment was invoked. Evidence:parent-fixed-key-qualified-v1.json.
Initial fixture slice-construction syntax was repaired; failed attempt retained.
This primitive does not authenticate a caller's family/statement.

All above receipts name immutable source snapshots, including older checkpoints
before later coordinated changes. Source qualification is not a positive proof,
complete family key, CompleteBlock acceptance or measured speedup. Segment,
guest, STARK, fullDriver/forest/benchmark/device runs remain stopped. The full
17-group/22-item objective, complete global/source closure, default activation,
positive e2e time/process peak memory and resident GPU work remain OPEN.
Next engineering: native count4/count10 path/query/opening ports, complete
PUBLIC21 fixed assembly/context and source draft-page transport that removes
spool/page duplicate encoding/write while preserving original detached bytes.


Native original four/ten-tree PCS fixed path/query/projection/opening ports pass
10/10 Debug with1916 stable pins (six behavioral groups plus actual original
factory body retention/import roots). Typed RAM/range derivation validates
independent native/transcript owners before and after; actual raw/fold PAGE
geometry uses ten roots and original column ordering, with missing original
prefix/public/context setup explicitly fail-closed. Evidence:
native-recursive-fixed-pcs-qualified-v1.json. No PCS/proof invocation.

Single-write fold draft transport passes11/11 Debug with1731 stable pins
(nine behavioral groups, body retention and root). Original Cursor two-pass
replay and Store.publish/load exact bytes/hash agree; same-inode exclusive
promotion, corruption/OOM cleanup and retained aggregate budget pass. Payload
encoding/writes now target250E bytes; final storage250E+96P vs prior500E+96P+208,
with192P header write bytes and promotion read/hash still present. Controller/
Job selection remains OPEN until next cohort. Initial Zig runtime-selected
format string repaired into two literal-format branches, names unchanged;
failed immutable snapshot preserved. Evidence:
memory-source-fold-draft-page-transport-qualified-v1.json. No measured time/RSS.

CompletePUBLIC21 fixed family assembly passes19/19 Debug for EACH independently
selected register recipe with1930 stable pins (ten behavior groups plus original
fixed/live key/producer/receiver body retention and imports). Actual requester
packed roster, original tuple/B5SS fixed rows, independently lowered MAIN
identifiers, two exact namespaces, child-then-tuple join, final G partition,
five original context channels and external schedule share canonical original
helpers. Runtime whole-family parity and actual fixed PCS commitment still
require genuine independent Public.Owner/live Prepared; none fabricated.
Initial namespace fixture omitted empty cohorts' original physical MAIN column
arrays; fixed by original Direct emitter for all23 cohorts, then replacing four
arithmetic lanes with original Fusion rows. Production unchanged by repair;
failed immutable attempt retained. Evidence:
requester-public-fixed-assembly-qualified-v1.json. Lower requester catalogue
independence, independent native memory/V20 expected setup, completeFINAL22
fixed assembly/default activation, full global/source closure, standalone
CompleteBlock receiver and positive e2e measurement remain OPEN. Segments,
STARK, benchmark/device/fullDriver/forest runs remain stopped; whole17group/
22item objective remains ACTIVE.


Native RAM/range external supplier routing now shares ONE original live/fixed
emitter. Original live public-value equality checks remain direct before shared
routing, initial key/main roots retain original query multiplicities, public
receipt words/graph inputs retain exact original order and coordinates. Typed
fixed owners require original native admission+transcript before/after and cold
rebuild schedules. Four independent routing/original digest/span/ordinal/OOM
behaviors plus actual original/typed bodies/root/imports pass9/9 Debug5.48s,
1904 stable pins. Mutation fixture originally attempted to mutate immutable
receipt storage; repaired into borrowed mutable receipt copies, never minting
an admission and preserving original Plan custody. Failed attempt retained.
Evidence:word-fixed-public-qualified-v1.json. This check precedes later root
private-supplier/full-roster source factoring; historical pins are immutable.

Root engineering batch now adds typed original native private supplier routing
and complete Word fixed-roster/context/expected-key construction. ONE original
parent private source emitter selects original47pairs/default roots or native
52pairs/external first-two roots; old packed/public rejection remains. ONE old
append/fusion/partition recipe and active-selector supplier body is shared by
old parent and native roster, avoiding duplicate row recipes. New native roster
retains compact fixed rows/public schedule only, not another projected column
inventory; the one fixed-key commitment helper handles projection when needed.
Current batch is authored/fmt-clean but UNQUALIFIED; original/full native body
retention and original mathematical routing/partition/fusion fixtures next.
Actual complete native fixed/live parity, expected root commitment, default
production selection and positive final proof remain OPEN. No source-only
check implies whole-block acceptance or measured end-to-end benefit.

Canonical Controller/Job draft collection integration now passes23/23 focused
Debug checks with1839 stable source pins. Default collection selects one-write
drafts; original Job admission/source-seal bodies retained, bounded ownership
rollback and original transport/loader/accounting regressions pass. This
supersedes the prior OPEN Controller/Job selection entry. Actual admitted
complete production invocation and time/RSS remain OPEN. Evidence:
memory-source-fold-draft-collection-qualified-v1.json.

Native RAM/range private suppliers and complete fixed-roster kernel pass7/7
Debug checks with1920 stable pins, including actual old default full roster API
body retention alongside new typed native context/key/live-validation bodies.
Compiler-only static expansion quotas increased; runtime geometry and equations
unchanged. Actual positive fixed/live/commitment-root parity, production expected
key integration and complete global closure remain OPEN. Evidence:
word-native-fixed-roster-qualified-v2.json. No proving/device/segment run.

FINAL22 requester/memory fixed assembly passes16/16 focused Debug checks for
EACH original register recipe,2020 stable source pins. Original signed closure,
two-child namespace, fixed tuple schedule, exact context and bounded ownership
fixtures pass; actual expected-key/producer/admission bodies retained. Initial
negative fixture expected evaluate success for altered memory; corrected to
expect original UnsatisfiedCircuit while retaining nonzero scalar residual
check. Original compiler-only23-component expansion quota increased. Lower
V20 expected setup still explicitly uses original admitted PAGE/RAM capture;
MissingIndependentMemoryRootFixedSetup remains closed. Independent PAGE memory
setup, actual full parity/commitment/default activation and standalone positive
block proof remain OPEN. Evidence:requester-memory-fixed-assembly-qualified-v1.json.

Original PAGE fixed transcript and typed ten-tree PCS setup pass9/9 focused
Debug checks with1921 stable pins. Five independent original raw/fold byte
framing/count-layout/bounds/OOM/lease groups pass; genuine admitted factory
and original live bodies retained but not invoked. Repairs confined to fixture
original config/row-log limits and compiler-only body retention quota. Missing
PAGE public/private suppliers, exact context/full roster and independent memory
root setup remain fail-closed. No positive proof/segment/commitment/device run
or time/RSS claim. Evidence:page-recursive-fixed-transcript-qualified-v1.json.

Canonical native expected setup is now selected in CPU supplemental receive
and RAM/range forest leaf publication/reconstruction. Original admitted policy
produces fixed setup without a proof/capture; direct internal owner/key factory
avoids second full cold roster; bounded one-entry family cache retains only
key/public schedule and revalidates actual admission on each hit. Fixed setup
dies before original decode; original proofs still freshly verified. Original
live G partition precedes exact context/log/schedule parity and producer fixed
root admission.33/33 Debug checks pass with2053 stable source pins, retaining
actual cache/factory/default full receiver+forest bodies without invocation.
First passing snapshot preceded source-review partition correction; immutable
v2 snapshot is authoritative. Cold/hit/live expected commitment parity and
positive proof/time/RSS remain OPEN. Evidence:word-expected-setup-qualified-v1.json.

Full original PAGE raw/fold public/private suppliers, context/fixed roster and
independent expected-key factory now implemented.18/18 cohesive PAGE Debug
checks pass with1929 stable source pins:five full roster/schedule/source/limit/
OOM/lifetime groups plus five original transcript byte-framing groups, retaining
actual genuine factory/key/live/default/native/caller bodies. Original live
public-value equality checks remain before shared emitter; all eight initial
PAGE roots remain external and original47 relation draws unchanged. Actual
positive full fixed/live expected root parity, PAGE forest key composition and
complete source/global block authority remain OPEN. Evidence:
page-recursive-fixed-roster-qualified-v1.json. No commitment/proof/segment/device run.

Default draft replay/promotion now reuses one owner-budgeted buffer capped at
4096 original records/page capacity. Unpublished replay removes unused full
envelope SHA; exact bound checked inventory avoids duplicate promotion decode
only after all current bytes rehashed.21/21 Debug transport checks pass with
1737 stable pins, five new buffered byte/order/request/corruption/OOM groups
plus14 original transport/rollback/custody regressions and actual body/root.
Observed fixtures use up to128-record PAGEs; full4096 PAGE64-to1 pread formula
needs separate actual cardinality qualification. Physical payload bytes still
read twice, with three vs four payload SHA passes including canonical envelope.
Evidence:memory-source-fold-draft-buffer-qualified-v1.json. No proof/commitment/
segment/device run, no end-to-end time/RSS claim.

Full4096-record original PAGE transport now qualified2/2 Debug1.757s with
1731 stable pins. Actual original 2048-leaf source yields a full PAGE plus tail;
observed replay AND promotion payload preadAll requests are64 versus1 for
64-record versus4096-record buffer, with exact Store.publish bytes/pins, original
Store.load operations and published Reader corruption rejection. This replaces
prior formula-only full-PAGE cardinality evidence. Counts exclude header/tail and
possible short-read syscalls; no end-to-end speed/RSS/proof claim. Evidence:
memory-source-fold-full-page-transport-qualified-v1.json.
Previous goal turn classified PROGRESS: canonical CPU PAGE policy export now
passes pre-proof Job semantic claims into v2 independent policy, no capture-derived
fallback. That integration remains source-only pending cohesive qualification.

Default memory completion now selects independent PAGE16/RAM19 catalogues,
authenticated borrowed V20 expected setup, and direct PUBLIC21/FINAL22 factories.
Root44/44 focused Debug checks pass153.578s with2141 stable pins; actual full
CPU capacity Driver, Session create/deinit, supplemental receiver, RAM forest
and final job publish/reconstruct bodies retained without invocation. Native
RAM/range publication now retains expected metadata and original persistent
workers borrowing driver pool, checks independent expected IDs before proving,
and consumes cold source rows early. Reconstruct leaf/node/join/public/final
paths omit private witness construction solely for key recovery. Original
producer fixed-root admission and fresh cryptographic receives remain mandatory.
Sibling fixed-live budget bug corrected; transcript capacity mismatch rejects
before collection/proving. Failed v3 local-shadow and v4 compiler-quota attempts
retained; v5 authoritative with PAGE type-expansion-only quota repair. Full
fixed/live/commitment parity, positive assembled proof/global block closure and
time/RSS remain OPEN. PAGE semantic-policy and both-recipe catalogue focused
qualifications follow independently. Evidence:
word-independent-memory-pipeline-qualified-v1.json. No PCS/STARK/segment/device run.

PAGE default independent leaf/node integration and semantic-policy v2 now
pass23/23 selected Debug checks37.568s with2032 stable pins. Seven new coordinate/
claim/version/routing/context/ownership groups plus original durable transport,
consuming cache lifetime and independent expected-ID guards pass. Actual Job/
export/CPU caller/typed raw-fold fullfactory/default forest and fresh verifier
bodies retained without invocation. Original proposed claims recorded BEFORE
proving and compared to actual original verification; expected v2 policy pin
supplies canonical constants, old absent-claim records cannot nominate setup.
Fixed PAGE16 catalogue uses aggregate sibling live lane and authenticates selected
node inventory; reconstruct omits private rows. No positive fixed/live key-root
parity, source/global block proof or time/RSS qualification. Evidence:
page-independent-default-setup-qualified-v1.json. No PCS/STARK/segment/device run.

RAM19/PAGE16 compact fixed catalogues, authenticated V20 borrowed setup and
direct PUBLIC21/FINAL22 factory assembly pass21/21 selected Debug checks for
each custody_v2 and local_zero_v1 recipe,35.754s and36.050s with2062 stable
pins each. Twelve behavioral mutation/budget/OOM/custody groups plus genuine
factory body retention, recipe assertion and import bookkeeping; no PCS
commitments or proof invocation. Prior missing-runner v1 attempt preserved.
Positive fixed/live key-root parity, full source/global closure and time/RSS
remain OPEN. Evidence:source-ram-forest-join-fixed-qualified-v1.json.

Supplemental CPU Session failure rollback now connected after joined workers/
readers and before Store destruction. Only successful original writer pins and
this Session's successfully published OPEN manifest are removed; pending/
preexisting destinations and reader inventories survive. Cleanup allocates no
memory, clears successful/missing pins, retains failed-deletion pins and reports
cleanup failures. Four real transport groups across all seven typed families
plus one byte/file overflow boundary group pass with prior integration checks:
49/49 selected Debug153.534s,2143 stable source pins. Driver/Session/Completion
actual production bodies retained without invocation. Aggregate report arithmetic
moved into Completion's existing rollback scope after review found a post-success
overflow could strand outputs. No positive complete proof or time/RSS claims;
no PCS/STARK/segment/device run. Evidence:
word-independent-memory-pipeline-qualified-v2.json. Previous v1/v5 receipts
remain historical; v2/v6 qualifies the newly frozen pipeline source.

The next CPU source batch wires original persistent caches for all seven
supplemental families, rather than just RAM/range, and exposes actual per-family
setup hits/misses, request-lane starts/completions and scoped allocator peaks.
Five original stages now use joined cache preflight admission and release
captures/cold plans/workspaces after their final consumers. Source formatting
and the canonical command graph's15 command-only Python tests pass; cohesive
CPU lifetime/production-body qualification now passes in the combined41/41
Debug assembly gate described below. No warm-cache proof or speed claim follows
from this batch.

Explicit immutable-input integration now has source collection/replay census,
late binding to actual initial-source pins, typed native/caller file policies
and loaders, and genuine native classifier publication in the original warm
segment callback. Borrowed bindings cannot destroy their owning public Plan.
Default input remains mutable. Driver preflight rejects readonly with legacy
register mode, PAGE/source completion or supplemental recursive grammars that
do not carry those original proof families. Focused collection and actual-body
checks pass in the combined41/41 gate; complete detached classifier acceptance
and recursive grammar integration remain separate obligations.

CUDA original scheduling admission now passes7/7 selected Debug checks1.514s
with494 stable source pins. Actual direct/capture/replay production and session
admission bodies emit a2,875,880-byte object with499 stable pins in0.639s;
all three exported production markers are present. The object is never linked
or executed. Unsupported lanes and node/schedule/geometry/target drift reject
before original dispatch, graph capture or cached replay. Only lane0 is
supported; real stream/event overlap, per-device ownership, AOT launch binding
and concurrent arenas remain unfinished. Qualification also fixed an illegal
CUDA sibling import by moving unchanged shared circle quotient geometry to
the core package, preserving the Metal forwarding API. Exact evidence:
cuda-scheduled-admission-qualified-v1.json. The failed first import attempt is
preserved. No PCS/STARK/segment/device run or end-to-end speed measurement.

The all-seven cache review found and fixed a real fused-family lifetime defect:
a retained Plan held prior dynamic public-array borrows after the consuming row
owner freed them. Scoped producer Plans now retain value-only template identity,
validate current admission, and clear current public-array borrows before lease
release. Original compatibility APIs remain available.

Canonical immutable-input collection now commits its allocation-free exact
readonly roster before shared challenges. Nonzero readonly_roster_digest selects
source-seal version3 and binds original Plan/selection, native classifier roots,
geometry and dense/sparse census in both B5SS and native-roster channels.
Independent detached policy reconstructs the inventory before RAM subtraction;
zero preserves original writable transcript bytes. Old isolated B5IR trusted-root
APIs remain compatibility surfaces, not canonical subtraction authority.

The cohesive CPU batch passes41/41 selected Debug checks in68.868s with2189
unchanged pins. Actual cache/stage/driver/CLI/independent receiver production bodies
are retained; current admission, roster mutation, worker/OOM custody and early
missing-grammar rejection are exercised without PCS or proof calls. Evidence:
cpu-performance-gates-v1/cpu-performance-assembly-qualified-v1.json. This is a
frozen integration snapshot; subsequent recursive/global-provider edits require
new qualification. Genuine assembled proof acceptance and time/RSS remain OPEN.

CUDA owned-context lane/event prerequisites pass7/7 host metadata checks in1.115s
with304 stable pins. Actual selected-device construction, dependency, teardown,
legacy and guard Zig bodies emit a1,809,104-byte object in0.423s with299 stable
pins; all five exported markers are retained. Native .cu/.h source pins are
separately checked, but native C++ was not compiled and no GPU was executed.
Compiled proof routing remains lane0 only. Real AOT launch binding, Session owned
construction outcomes, dispatcher/event routing, concurrent arenas and per-device
admission remain OPEN. Evidence:cuda-lane-context-qualified-v1.json. Earlier
illegal runtime thread-default attempt is preserved as failed-v1 evidence.

Next coherent CPU architecture batch replaces repeated per-source readonly
interval-provider arrays with versioned shared global-provider proofs. Collect
original counters once, bind source/provider/range roots before shared draws,
and close original request claims through genuine integer-mass/provider AIR and
recursive joins. The existing bounded standalone adapter is an oracle, not the
large-block endpoint. Source, provider and orchestration work is divided across
the existing agents; no new block proof or speed/RSS claim follows yet.

The shared global-provider collection snapshot now passes41/41 selected Debug
checks in69.522s with2204 unchanged source pins. It covers field-safe whole-source
grouping with a4.8-billion-event integer census, bounded exclusive counter-file
staging and shard reading, roster/root/policy mutations, allocation rollback,
scalar/SIMD equations and genuine native/provider/range and canonical CLI body
retention. Five actual production exports are present in the compiled binary.
Evidence: [global-readonly-collection-qualified-v1.json](cpu-performance-gates-v1/global-readonly-collection-qualified-v1.json).
The original per-source histogram collection is still used by this qualified
snapshot. It does not qualify the subsequent streaming witness path.

Newer source now includes owner/generation-bound streaming observation tokens,
one reused group counter vector, native live-row collection, caller observation
seams and typed fresh source-claim receipts. Counter grammar is explicitly
versioned and included in roster binding. Native/caller/provider recursive
adapters and group joins are being assembled. These changes are not yet a frozen
qualified cohort and are not selected by the complete canonical driver. Remaining
integration includes provider first-round staging, proof-file codecs/loaders,
the complete detached receiver and recursive closure. Original mutable RAM,
program, ROM, lookup, byte and register obligations remain required.

CUDA selected Session/runtime ownership now passes8/8 host checks in1.221s.
Six genuine selected-construction, cleanup and compatibility bodies emit a
2,081,144-byte object in0.443s. Typed construction outcomes retain partial
Context/AOT ownership and the original runtime registry lease after cleanup
failure. Independent selected ordinal/UUID and original provider/platform/AOT
guards remain enforced. Evidence: [cuda-selected-session-qualified-v1.json](cpu-performance-gates-v1/cuda-selected-session-qualified-v1.json).
Native C++ was not compiled, no GPU ran, and proof routing still supports only
lane0; this is not multi-device or resident throughput qualification.

Segments remain stopped. None of these new checks invokes PCS commitments,
STARK proving, guest execution, forest proving or benchmarks. Fresh complete
bundle acceptance, canonical recursive closure, block proving time and peak RSS
remain OPEN. No end-to-end speedup is established by the source snapshots.
