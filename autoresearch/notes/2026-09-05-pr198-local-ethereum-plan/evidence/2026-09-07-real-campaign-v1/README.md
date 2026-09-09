# Real retained Ethereum campaign, 2026-09-07

The real guest now has an explicit retained V4 route within the existing wire
limit: `--campaign-geometry authenticated-v1` admits count and budget from the
authenticated source request. Default admission remains the historical 210
segments. The new campaign uses 121 segments at 2^21 cycles each. No CSP guest,
execution policy, shared RV32 memory type, or protocol identity changed here.

The original rebuilt guest executed all 253,646,998 cycles and materialized
sources in 135.69 seconds, but fresh V4 capture rejected it with
`MemoryClockMissing`. Its linker declared only static data as RW while the
allocator used the heap beyond that range. The first missing word was
`0x0200e630`, immediately above declared data end `0x0200e628`: instruction
`0x00b52023` at PC `0x1b30`, instruction clock 12373/access clock 49491, stores 1
over 0. The old ELF, source campaign, and exact failing input remain durable.
That source-materialization timing is **not a valid proving baseline**.

The guest-only linker fix makes `__data_len` include the declared heap while
preserving static-data end and heap start. The new ELF SHA-256 is
`f81e30505c2ae1ab16e693933bef65f6fbae94ca6e04b4bc66688a068cddce16`.
Every executable PT_LOAD byte and address matches the old ELF. A build script
now tracks linker.ld so edits cause relinking; the cached guest rebuild took
15.33 seconds.

The corrected guest completed all 121 source segments in **406.42 seconds**
(391.64 user / 7.03 system), with peak footprint **850,740,328 bytes** and maximum
RSS 851,345,408 bytes. Snapshot hashing used one synchronous worker, avoiding
queued projections. It retained exactly 253,614,097 core rows and 32,901 external
rows, with unchanged 43-byte output digest
`730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5`.
This is complete execution/source preparation, not STWIEF04 proving.

The focused genuine first-segment gate passed **2/2**: new heap-admitted source
accepted, old ELF rejected at the exact retained heap store (12-second compile,
2-second run, 501 MB test RSS). The separate campaign/claim CLI gate passed
**5/5**. Its claim selector preserves `legacy_aggregate_v2` by default and
explicitly admits `selected_detailed_v3` or `field_authority_v4`; CPU and Metal
share that selection through the actual profile-minting path. The explicit-claim CPU product compiled successfully (5 minutes, 8 GB compiler
peak), SHA-256 `f5190ecf77206697160a364a85571170891fe612de9705a4347ee34dc5a5f8a1`.
This predates the optional global-metadata sidecar; a real field-profile proof
remains a separate gate.

Durable corrected artifacts are under
`.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907/`.
`authority/materialization-v2.json` has SHA-256
`e9d9ba5619d5780155bf7f23e3475a1af0aae85ec74a0660b837c0cdbb237f4e`.
Its source request has SHA-256
`bcd8a5568b6cdfd59a3eb6105528ede2f71825615c0106a44ce4f10ce76978c2`.
All command lines, executable/input hashes, source manifests and timing output
are retained in the campaign. Source files outside materialization changed
during the product compile; before/after inventories make that limitation
explicit. The running capture uses the already compiled binary.

The next selected proof leaf is **segment 9**: 2,096,404 core rows, 682 Keccak
calls and 66 signer recoveries, totaling 2^21 execution cycles. Raw compact/public
wire capture used `--cold-workers 1`; no completed V4 publication,
real STWIEF04 proof, CPU/Metal timing comparison, full block proof, or succinct
root is claimed yet.

A one-second raw-capture sample observed duplicate wire authentication inside
`validateWireAgainstRetainedMetadata`: an explicit retained-root authentication
is followed by `public_wire.metadata()`, which authenticates again. All 56
sampled stacks were in that function, with 48 under freshView/canonical hashing.
This identifies a bounded validation-consolidation opportunity; it is not a
wall-time percentage or measured optimization result.

The optional global-metadata sidecar and explicit field4 PCS preflight passed
**6/6 focused tests** (4-second compile, 264 ms run). Preflight uses the native
Tree0/Tree1/authenticated Tree2 layouts plus the bridge, before Engine creation.
Its retained-evaluation lower bound excludes Merkle nodes, FRI, quotient work,
twiddles and witness owners; passing it is not a process-memory guarantee.
The prepared CPU route now prints all existing transaction phase timings and
producer/fresh-verifier/full-request resource receipts. Reported footprints
are process lifetime peaks, not isolated phase allocations.

A fresh Metal AOT bundle passed the authenticated runtime probe: **166 exact
kernel exports**, zero function constants and AOT/JIT parity. The retained
bundle receipt pins manifest and metallib hashes. This is backend admission
evidence, not a real Ethereum Metal proof. The explicit V2 benchmark tuple
keeps the old Stage101 pins unchanged and will name the actual freshly
CPU-verified reference artifact once produced.

The V2 Metal tuple, retained V1 pins and existing Stage101 contracts passed
**13/13 tests** (8-second compile, 352 ms run). The actual Metal command also
compiled (1 minute, 5 GB compiler peak). The CPU v2 command with PCS preflight,
metadata sidecar and request receipts compiled (5 minutes, 8 GB compiler peak).
Both executable hashes are retained; neither compile result establishes a
real leaf proof.

All **121 compact tapes and 121 public wires** were retained, but final receipt
sealing failed with `NonCanonicalAscii` after **2714.24 seconds** (2667.15 user,
12.21 system), peak footprint **770,233,312 bytes**. The raw and ordinary capture
observers both retained borrowed compact-artifact path slices after freeing
the callback storage. A shared owned append/deinit now fixes both; a focused
regression destroys the caller storage before reading the retained path.
Bounded diagnostics identify artifact index, path byte index and byte value.
No ASCII/metadata validation was relaxed. Recovery uses the existing
reopen-unsealed route against all surviving pairs, without Ethereum
reexecution. The recovery was deliberately stopped after 664.17 seconds
(660.04 user / 1.87 system), peak footprint 563,069,936 bytes, after
opening roughly 17 leaves. All 121 retained pairs remain intact.

The shared compact-path ownership regression and the six existing campaign
checks passed **7/7** (4-second compile, 267 ms run). The stopped recovery
binary predates that fix but used the raw-recovery path, which never invokes
either capture observer. A sample identified repeated authentication of
canonical public wires.


The explicit selected-leaf route now avoids reopening unrelated campaign
leaves. Its option/identity gate passed **7/7**; the shared postprocess gate
passed **5/5**, including minting a genuine nonzero-index fixture from its
admitted entry state, cold publication, absence of campaign seals, and rejection
of a changed entry word. Controller custody checks passed **7/7**, including
one immutable admission directory per index across retries and rejection of
changing that directory during resume. These focused checks do not establish
that the real segment 9 proof works. The narrow prepared CPU executable is
being compiled before that measured request.


The narrow prepared CPU worker compiled in **1 minute / 5 GB** (broad product:
5 minutes / 8 GB). Its first real segment 9 request successfully published
selected-leaf admission, then aborted in changed-only sparse transition witness
construction, before the PCS preflight or proving. The retained attempt took
**79.67 seconds** (77.94 user / 0.82 system), peak footprint **692,814,904 bytes**.
No proof or metadata sidecar was produced. The measured request used one worker,
16 GiB composition budget and a sampled 32 GiB process-footprint stop; it did
not reach either budget check. The actual pair and selected admission remain
available for a focused replay. Investigation found a next-level array reserve
assuming every changed byte has a changed sibling; sparse changed bytes can
require one parent per input, rather than half that count. A regression is
being run before the bounded allocation fix.


Both versions of sparse transition construction reproduced the capacity error
in focused cases before the fix: 64 adjacent words with one changed byte for
V2, and 64 spaced words for V1. The corrected reserve uses the proven maximum
of one parent per current child. The full transition root then passed **247
tests, 1 skipped, 0 failures**, including these new cases, root parity against
full-tree construction and Merkle/Poseidon lookup cancellation. This changes
allocation capacity, not witness contents, protocol identities or worker
policy. No CSP benchmark promotion is claimed. The corrected narrow worker
build is queued; real segment 9 has not passed proving.


The corrected real replay reached full prepared geometry and rejected the
initial PCS check after **46.00 seconds**, peak footprint **2,186,676,552 bytes**.
The exact retained-LDE requirement is **20,550,093,056 bytes**, across 16,894
columns; source columns total 10,275,046,528 bytes. Component decomposition
confirmed the same totals on a second retained replay (46.54 seconds).
Native Poseidon accounts for **15,267,266,560 bytes**: 3,396,146 calls padded to
log22. Of those, 478,450 concern the transition and **2,917,696 = 4×729,419+20**
are fixed program authentication (85.91% of these calls). The prepared witness
appends every program call in
[`commitment_witness.zig`](../../../../../src/frontends/riscv/prover/commitment_witness.zig:485);
`real-selected-component-geometry.json` retains the measured native descriptors.
This is AIR provider work, separate from PCS Merkle hashing. Same-root CPU
Merkle reuse therefore cannot remove it. Reusing program witness preparation would
not remove those AIR rows. A separate authenticated program-proof design is
future work, not a shortcut taken in this benchmark.

The initial check incorrectly reused the CPU composition allocator's 16 GiB
budget as a ceiling for retained PCS columns, although those columns live
outside that allocator. The execution-only CLI now exposes
`--pcs-retained-byte-budget` separately; prepared routes otherwise use their
explicit host admission limit for this lower-bound check. The next request
selects **24 GiB PCS / 16 GiB composition / 32 GiB sampled process stop**.
CPU commitment streams 64 columns and drops coefficients with `.never`, so
all source columns are not added to the final retained-LDE total at once.
The working model includes a maximum 1 GiB source batch, approximately 1.5 GiB
for three maximum-height source Merkle trees, and the earlier observed
2.19 GB preparation peak. Composition/FRI/twiddle/allocator costs remain
additional; this model is not a measured whole-request peak or allocation
safety guarantee. No real leaf proof has yet been published.

The separate-budget focused gate passed **7/7**, and the prepared CPU v6
product compiled in about one minute (5 GB compiler peak). Controller tests
also passed **7/7**. The next actual request is retained in
`cpu-field4-segment9-selected-v4`; it failed after **50.85 seconds** at a second,
legacy Tree1 budget check (peak **2,765,540,160 bytes**). The outer 24 GiB
preflight passed, but Tree1 still used the 16 GiB composition budget and
assumed retained coefficients while the actual scheme selected `.never`.
The explicit execution request now reaches the shared Tree1 estimate with
the actual scheme retention policy. The focused gate passed **9/9**, including real geometry policy rejection and
actual explicit-one-worker binding. Product v7 compiled; its first combined
gate found only eight of nine expected tests, then moving the pool test into
the integration root made the exact nine-test gate pass.
The request also exposed the explicit-one-worker pool early return, which
left commitment helpers unbound; the fix binds the existing one-worker pool
while preserving the unspecified policy. The v4 timings therefore cannot be
reported as an enforced one-thread baseline. No proof was published.

The next measured request is `cpu-field4-segment9-selected-v5` with the same
24/16/32 GiB limits and actual scoped one-worker commitment execution. Its
terminal result is pending. The actual deeper Tree1 check passed with
**17,253,064,448 bytes**, 8,458 columns and the scheme's actual `.never`
policy against 24 GiB. The retained one-second Tree0 sample shows only the
main thread during streaming Poseidon Merkle leaf finalization; it is a
phase sample, not a wall-time percentage.


The real CPU segment9 full leaf now **passes**: field-authority schema4,
core plus every provider, serialization, producer destruction and fresh native
verification. See `real-selected-cpu-success-receipt.json`,
`real-selected-cpu-success-plan.json`, `real-selected-cpu-success-phases.json`
and the retained log/samples. The complete request took **1,191.75 seconds**
externally (**1,190.960 seconds** inside the command), with a **26,345,901,712
byte** process-lifetime peak (24.54 GiB). The sampled32 GiB stop did not trigger.
The proof is **62,552,044 bytes**, SHA256
`43aa15db272bfb6fdac201c5bf682dbc0887444ada440d9721afe5d099a2c2d8`.
The LeafV1 metadata sidecar is16,650bytes, SHA256
`3d0775148bd5055e6d22c9cafabd3f6bd0a82086bf8d18456bf222b6e4c67bc8`.

Producer time was1,100.106seconds; fresh verification53.148seconds. The
remaining37.707seconds belong to other complete-request work; producer
cleanup is included but has no separate timer. Native proof work was dominated
by three Merkle commitments557.564seconds, FRI quotient construction/commit
244.896seconds, composition148.237seconds and sampled-value evaluation
51.016seconds. The receipt retains ordered nested phases and aggregates only
depth2, avoiding double-counting. This binary did not enable the later CPU
Merkle-tail reuse option. Fresh separate-process selected verification subsequently passed; the matched
Metal full-leaf request hit its measured process-memory stop (details below).


`real-selected-cpu-success-column-histograms.json` derives each committed tree's
column-height distribution from the pinned successful transport and retained
admitted component geometry, cross-checking the actual Tree1 and total PCS
counts. Tree0 has200columns/289,772,032LDEbytes; Tree1 has8,458columns/
17,253,064,448bytes; Tree2 has8,236columns/3,007,256,576bytes. Their largest
source-log22 groups contain4,455and20columns respectively (LDElog23).
Tree1's455 comprise445Poseidon and10Merkle columns. The extractor is diagnostic;
it does not replace native verification or mint a new admission.


The same real CPU artifact also passed **independent fresh-process verification**
after the cold immutable admission cleanup: request 70.718 seconds, native
verification 70.638 seconds, peak 1.030 GB, worker 1. See
[the separate verifier receipt and provenance](real-selected-cpu-fresh-v2.json).
This process independently pinned the materialization and selected metadata;
it received no producer state or retained admission lease.

The frozen matched Metal field4 attempt **did not produce a proof**. It
passed both explicit PCS preflights, then the 32 GiB sampled process monitor
stopped it at 69.18 seconds, with process-lifetime peak 37,972,405,608 bytes.
The 2-second monitor is a fallback and permits overshoot; it is not an
allocation guarantee. The retained `real-selected-metal-memory-stop-v1-*`
files preserve the successful CPU oracle, authenticated AOT and executable
pins, exact command, limits, logs and samples. Source ownership work on
Metal coefficient storage is a follow-up, not a successful baseline result.

A separate Ethereum-only narrow Poseidon component now passes an isolated
complete CPU STARK gate: **6/6**, including the test-root sentinel, native
permutation/lookup parity, every-column mutation and padding checks, declared
degree checks, complete proof serialization, producer destruction, independent
selector-root reconstruction, fresh verification and changed-claim rejection.
See `narrow-poseidon-complete-component-v1.log`. Its geometry is 287 main,
2 preprocessed, 8 interaction columns and 288 constraints at degree 3, q1, split1,
PCS blowup 1. The ungated permutation constraints require valid computed
padding; only lookup multiplicities use the Boolean activity enabler.
This test has a public provider claim and does not establish caller closure,
the combined native profile, real-leaf runtime, or CSP benchmark preservation.

The combined fixed-program/narrow-provider LDE estimate is a model pending
actual profile geometry: starting 20,550,093,056 bytes, remove the
455 Poseidon + 24 Merkle columns' log22→19 height difference and add six fixed
program preprocessed columns at log20. This gives 6,536,923,392 bytes; replacing
445 main Poseidon columns with 287 at log19 gives 5,874,223,360 bytes. Neither
number is a measured process peak or runtime.

The subsequent selected-route gate passes **7/7** (including the root sentinel):
[narrow component receipt](narrow-poseidon-selected-component-v1.json). It adds
central-profile width admission/rejection and byte parity between the planned
row writer and serial materialization, including computed padding. Both native
prover and verifier assembly use the same explicit selected component. Existing
constructors continue to select the legacy layout. The seven-test gate includes
the complete isolated proof again; whole-leaf integration remains pending.


The second matched Metal attempt passed native cryptographic verification and
produced exactly the CPU artifact bytes (SHA256 `43aa15db…a2c2d8`), but the
benchmark release check withheld publication: its historical tiny-fixture
placement expected three CPU small-circle operations, while this real leaf
performed zero. All other CPU fallback counters were also zero. This is a
retained **publication failure**, not a published Metal benchmark artifact.
See [the phase and failure analysis](real-selected-metal-release-failure-v2-phase-and-failure-analysis.json).

The request lasted 252.60 seconds and peaked at 29,376,648,744 bytes; the
32 GiB sampled stop did not trigger. Native proof work took 152.039 seconds
versus the CPU baseline's 1,089.657 seconds; this 7.167× ratio describes the
proof phase only. Fresh native verification took 52.112 seconds. Exclusive
depth2 scopes record three Merkle commits totaling 31.907 seconds, composition
46.901 seconds, FRI construction/commit 27.930 seconds and sampled values
0.277 seconds. Source packing cost 2.954 seconds and is separately scoped.

The frozen v4 executable SHA and build log are retained. No complete source
snapshot was retained for that binary, despite the coordinated source freeze;
the changed current checkout cannot substitute for it. It predates two later
lifted-Merkle allocation-failure cleanup fixes. The next retry uses an immutable
source snapshot and explicitly pins zero small-circle placements in the
benchmark admission. Existing requests default to the historical exact three;
all nonpermitted CPU fallback work remains rejected.


The corrected matched Metal request now **passes and publishes**, followed by
**independent fresh-process verification of the saved Metal artifact**.
[Complete CPU/Metal phase comparison](real-selected-metal-success-v3-phase-comparison.json)
and [independent Metal verifier receipt](real-selected-metal-fresh-v1.json)
retain the exact executable, source snapshot, input, output and AOT pins.

| Complete prepared-leaf request | CPU | Authenticated AOT Metal |
| --- | ---: | ---: |
| External elapsed | 1,191.75 s | 247.37 s |
| Native proof stage | 1,089.657 s | 147.071 s |
| In-request fresh native verification | 53.148 s | 52.259 s |
| Process-lifetime peak | 26.346 GB | 29.375 GB |

This is **one paired observation**, about **4.82× faster** for the complete
prepared-leaf request. Both routes use field-authority schema4, the same real
segment9 of121, 2,097,152 cycles, worker1, composition16GiB, PCS24GiB and a
32GiB sampled process stop. Both publish the same62,552,044-byte proof and
16,650-byte global metadata, byte-for-byte. Guest building, full-campaign
execution/capture, compilation and AOT generation are excluded from both
prepared-leaf requests. The Metal request includes cold runtime initialization.
This does not establish full-block proving, a final succinct root comparison,
a stable multi-run speedup, or the required16-case CSP promotion suite.

The separate Metal verifier then reopened the actual published Metal paths
using the independently pinned materialization and a frozen native verifier.
It destroyed the retained admission before proof cold-open, passed in
69.184seconds (69.109seconds native verification), peaked at1,029,866,504bytes
and confirmed every input/executable hash remained unchanged.

### Explicit narrow-Poseidon Metal admission

The new Ethereum provider has a separate AOT profile, `ethereum_fixed_program_narrow_v1`. Its five generated kernels extend the authenticated inventory to 171 exports. The core/CSP inventory remains 166 exports with the previously measured source SHA256 `c2daaaf7dab998e6c542651dec73323973eafceee6ccf9d56fce6094ccac2786`; its default manifest encoding and CLI selection remain unchanged. The authority gate passed 7/7, and the backend-neutral native/DAG gate passed 8/8.

The new bundle is `.git/local-ethereum/ethereum-fixed-program-narrow-aot-v1/bundle`, manifest SHA256 `320f1b944927e173c5d2972ab0cb69f68129d135f40838976c2cde653bf180c3`. The source is 1,621,173 bytes and the linked metallib is 2,885,498 bytes. Tool test/build plus actual Metal compilation took 13.625 seconds; this is a build measurement, not proving throughput.

An actual isolated Metal component proof passed with all five admitted pipelines loaded, one direct batch and one lookup batch dispatched, and exactly the same 26,812 serialized proof bytes as CPU. All producer state was destroyed before fresh CPU verification. The GPU fixture uses trace log 15 / quotient log 16 to reach the existing measured mixed-component dispatch threshold; the everyday CPU component fixture remains log 4. The earlier log 4 GPU assertion was a test-geometry mismatch: the existing backend intentionally ran it on CPU, and the proof bytes already matched. No dispatch policy was relaxed. The first real pipeline failure is retained: the runtime originally initialized only the legacy polynomial list. The new initializer receives the additional names from the admitted profile and resolves every pipeline before publishing the runtime, with no source-JIT fallback.

The repeatable GPU proof gate is:

```sh
python3 scripts/ethereum_narrow_metal_proof.py \
  --bundle .git/local-ethereum/ethereum-fixed-program-narrow-aot-v1/bundle \
  --manifest-sha256 320f1b944927e173c5d2972ab0cb69f68129d135f40838976c2cde653bf180c3
```

The shared `metal-core-aot` tool builds this explicit profile with `build --output-dir DIR --profile ethereum-fixed-program-narrow-v1`. Omitting `--profile` retains the core profile. The source regeneration/check command is:

```sh
STWO_ETHEREUM_NARROW_AOT_GENERATE=src/backends/metal/shaders \
  python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/ethereum_narrow_aot_generator_test.zig \
  -O ReleaseSafe -fstrip --test-filter 'Ethereum narrow AOT extension'
```

Omit the environment variable to check the retained generated source against the production DAG builders. The new component capability is now selected for the explicit narrow component; the final activated CPU/GPU regression batch passed 19/19 (8 CPU/DAG, 1 generated-source, 9 authority/default-initializer, 1 actual GPU proof), retained in `ethereum-narrow-activation-v1.json` and its log. This component proof does not establish full-leaf schema 5 performance, whole-block coverage, or CSP benchmark promotion.

### Matched schema5 full-leaf result

`real-selected-metal-field5-v2.json` records the accepted matched run on real segment 9 of 121. CPU and authenticated Metal publish exactly the same 62,271,644-byte proof (SHA256 `5c102cc46a993393409a9a0a9074f1c21817fb235402af6b94d38985aec3ce27`) and global metadata. Both use the explicit fixed-program/narrow-Poseidon profile, worker 1 and the same composition/PCS/process-monitor settings.

| Complete prepared-leaf measurement | CPU schema5 | Metal schema5 |
| --- | ---: | ---: |
| External request | 373.36 s | 145.78 s |
| Proving | 292.049 s | 63.517 s |
| In-request fresh native verification | 33.954 s | 33.718 s |
| Process-lifetime peak | 9.052 GB | 9.873 GB |

This is one paired observation, approximately 2.56× for the complete request. Metal used the independently authenticated 171-export AOT bundle, with zero fallback and zero runtime compilation recorded. Its exclusive depth-2 stages include 7.950 s across three Merkle commits, 35.399 s composition, and 0.374 s FRI quotient construction/commitment. The receipt retains the hierarchy rather than adding nested stages. Build/execution/capture and AOT generation are excluded from both requests; runtime startup, serialization, producer destruction and fresh native verification are included.

The additional separate-process check passed on the actual Metal paths: 54.356 s request, 50.914 s native verification, and 956,974,256 bytes peak footprint. It independently pinned the retained materialization and reconstructed the ELF admission, destroyed the retained input authority before proof cold-open, and rechecked every input and executable hash. See `real-selected-metal-field5-fresh-v1.json`.

The preceding release failure is retained in `real-selected-metal-field5-release-failure-v1.json`. Native proof, exact CPU-reference equality and fresh verification had passed; the benchmark still expected legacy preparation counts. Schema5's measured provider inventory adds two owner validations and one borrow. The corrected benchmark admits 5/3 only for schema5 and retains 3/2 for legacy profiles; it now prints the complete counters before release checks. The corrected build passed 21/21 focused tests (18 benchmark, 3 production-entry).

A dedicated `ethereum-prepared-leaf-metal-v1` entry reuses the shared serialization/destruction/fresh-verification transaction without requiring a CPU reference. Its additional required options are `--aot-bundle PATH --aot-manifest-sha256 HEX`; the other options match the prepared CPU command. The first actual terminal segment 120 trial passed input admission, then aborted in the small-circle LDE fallback on an exact source/coefficient alias; `real-terminal-metal-field5-alias-failure-v1.json` retains the input and stack. A bounded ownership fix and small-polynomial parity gate precede the retry. The retry samples process memory observationally, keeping composition/PCS/host admission limits separate from any process cap. These selected-leaf results establish neither whole-block coverage nor the CSP 16-case promotion gate.

The corrected production command has now proved and published actual terminal segment120 without a CPU reference: 216.46 s complete request, 60.152 s proving, 65.971 s in-request fresh verification and 12.430 GB peak. The receipt records91 device dispatches and aggregate host fallback3; it does not identify fallback subtypes. Separate-process verification also passed in102.768 s (99.335 s native verification, 1.260 GB peak), with all artifact, materialization and executable hashes unchanged. See `real-terminal-metal-field5-v2.json` and `real-terminal-metal-field5-fresh-v1.json`.

The serial121-leaf Metal campaign has started from a frozen11-module recovery-controller snapshot and frozen production-v3 executable. Accepted leaves9/120 are imported with their original executable identities and362.24 s producer plus157.124 s external-verifier accounting retained. Each imported leaf is verified again before full-bundle acceptance; only one heavy child holds the shared lock. The CPU controller was stopped at an idle boundary with its successful segment6 candidate retained separately. `metal-field5-campaign-v2.json` records the exact launch. Full-block coverage and independent bundle verification remain pending.

The first campaign-produced Metal leaf0 is now accepted after separate-process verification. Its heavier geometry used24.512 GB of retained LDE and reached38.800 GB actual lifetime footprint; the admission budget was not treated as a process cap. Complete producer request was459.654 s (282.437 s proving,77.781 s in-request verification), followed by90.802 s separate-process verification. It recorded102 device dispatches and aggregate fallback3. The41,293,029-byte proof and exact request, source, phase and verification receipts are retained in `real-metal-campaign-leaf0-v1.json`. The controller continued to leaf1; full121-leaf bundle acceptance is still pending.
