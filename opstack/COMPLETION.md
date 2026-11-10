# OP Stack CPU delivery gates

Updated 2026-11-09. This is the completion checklist for PR #322, not a claim
that the unchecked gates already work. Receipts, source and fresh receivers
are the authority. Historical plans in `DESIGN.md` and the feasibility study
predate the anchored transition implementation.

The functional comparison is ZisK's OP flow: execution ranges, authenticated
L1 derivation, execution/derivation binding, an accumulating recursive proof,
and settlement. Its dashboard describes a SNARK wrap. Our chosen settlement
route remains a direct STARK verifier. CPU qualification comes first; GPU
latency figures are not CPU acceptance criteria.

| Gate | Current qualification | Required closure |
| --- | --- | --- |
| Kona execution | Three complete local native execution bundles, including selected heavy block 121065789 with 91 CPU and 24 service proofs; fresh receivers and physical corruption rejection | Extend representative execution coverage without weakening expected-output binding |
| Anchored derivation | Historical native/RV64 transition and new159321793→159321794 independently native-accepted; canonical authenticated input retained in-repo; actual anchor/root/blob/proof mutations reject | Complete physical derivation STARK with independently pinned OD output; new witness has not run under RV64 |
| Capacity and continuity | Fastest retained anchored replay needs at least 733 CPU proofs before services; native cap is 256 | Reviewed versioned segmentation binding PC, registers, clocks, memory, services and final output; no blind cap increase |
| Recursive closure | Complete small grouped roots plus original B2 heavy root (126 leaves/64 folds) and selected D2 heavy root (115 leaves/58 folds); final executable accepts both and rejects physical attacks | Reduce heavy latency; extend closure to an actual anchored derivation proof |
| Joined statement | Receiver-side OD/OP join and synthetic ordered folds exist | Actual recursive root authenticating both matching programs, exact outputs, order and complete native closure |
| Accumulator | No complete running OP checkpoint accumulator receipt | Adjacent checkpoint folds rejecting gaps, overlaps, swapped branches and substituted anchors |
| Settlement | Packed pinned AIR 637,484 gas; full native worker PCS remains about 1.724 billion gas | Complete authorized checkpoint verifier under actual transaction constraints |
| Security | 128-bit security target under documented assumptions; `security_qualified=false` | Bounded composed accounting for the concrete derivation, segmentation, recursive and settlement construction; no certification claim |
| Regression hygiene | Fixed-source geometry repair; both heavy profiles accepted by final executable; 24 settlement tests pass, three external-fixture skips | Keep formats/defaults stable; resolve outstanding broader CI failures and qualify new shared changes independently |

## Current optimization branch: explicit pure-P2 execution

The CPU continuation is developing a separate construction rather than silently
replacing the qualified execution controls above. Its records are in
[`rv64-opstack-cpu-20261109`](../vectors/reports/rv64-opstack-cpu-20261109/) and
[`rv64-opstack-performance-20261109`](../vectors/reports/rv64-opstack-performance-20261109/).

| New construction gate | Established evidence | Still required |
| --- | --- | --- |
| Selected OP guest | Three real blocks agree with independent execution; heavy block runs 238,226,172 instructions, down from 380,167,068 | Complete native and recursive proofs of that selected heavy execution |
| Compact native route | Actual block 120794432, CPU + Keccak + SHA, exact 43-byte result; retained 7,048,980-byte bundle and fresh receiver | Complete selected heavy execution; do not substitute preparation or replay for proving |
| Bounded immutable setup | Two fresh heavy captures reuse all 36 setup classes with no new misses; all roots, public cells and final states match; 28.068 GB peak requested memory under 32 GiB; final heap/external counters zero | Uninterrupted warm end-to-end proving measurements; both preparation timers were interrupted |
| R5 portable root-only handoff | Actual small block: three physical leaves, two folds, 667,304-byte root; fresh receiver derives source authority and verifies only the root | Practical performance: 305.567 seconds additional recursion remains too slow; not a default promotion |
| R6 independent OM31 multiplication | Actual small execution closes all three leaves and two folds: 687,908-byte root: original Safe run 198.102 seconds; subsequent Fast run 138.898 seconds with every node/root/sidecar byte-identical and fresh source-only acceptance; native production is additional | Actual full-height heavy classes and complete heavy native-plus-root performance; no extrapolation from the small block |
| Service-local GKR | Actual Kona120794432 completes native suite3 and a 683,432-byte R6 root, with separate source-only acceptance and policy/output refusal; explicit suite3 additionally closes a complete synthetic CPU + Miller native bundle, two recursive leaves and one fold, with physical adversaries | The full-height synthetic log15 Miller fixture now passes native and complete R7 root qualification with 1,023 actual VM calls; actual heavy integration and performance remain open. The small Kona block has zero Miller calls; capacity fixtures are not Kona blocks or heavy performance results |
| Bounded truth planning | Source-derived checkpoint/whole-worker estimator refuses heavy log18 Keccak and admits log16/4,518-permutation shards under the declared 8 GiB worker limit | Resource-derived shard-plan integration is present; physical heavy qualification remains open. Estimates are requested bytes, not measured RSS |
| Retained source custody | Small native bundle remains byte-identical with CPU advice parking and post-seal LS/SHIFT auxiliary retirement; witness-free ledger reproduces capture and event payloads exactly | Model excludes scratch/mappings; 27.46 GB CPU seal payload is not whole-worker admission or measured RSS |
| Detached sponge and CPU frontier | Actual selected796k guest and alternate1.317M guest complete fresh native proof production and independent receivers, with global closure and all typed callbacks. Selected guest includes CPU, detached sponge, local Keccak and classic SHA | Production source-suite admission remains closed; representative heavy/resource and broader regression qualification still required |
| Native recursive dot product | Complete actual Kona120794432 R7 root,680,116bytes, fresh source-only receiver and full execution/terminal/global admission; CPU217,378,816cells versus R6 264,302,592 | All-fresh and matched timing;164.625s incremental qualification reuses one verified CPU leaf and uses classic truths, so it is not comparable to the local-GKR R6 control |
| Direct native groups | Selected small execution closes four native members in one group; R6 and R7 final-only B2 proofs and two-group/one-fold roots freshly verify without native proof files | Resource-derived heavy group sizing and controlled performance. Larger groups trade peak memory against additional folds; existing defaults remain unchanged |
| Immutable outer Miller setup | Bounded producer and independent verifier caches reproduce/accept the same physical root with cached and forced-fallback keys; class barrier, request binding, adversarial checks and zero final heap | Repeated-class complete-execution performance; no process-global cache or unbudgeted retention |
| Complete heavy performance | Matched D2 native + M6 root baseline 3,328.446 seconds | At most 332.845 seconds for the same heavy block, through a complete recursive root; **not achieved** |

R5's source-only receiver loads source declarations and public cells, not native
proof bytes. It retains exact expected program/image/output, terminal and global
closure checks; a small final proof does not eliminate cold source-key setup.
R6's receiver additionally discards prover-only FIXED buffers after independently
constructing each source key. This is a retention improvement, not avoidance of
the initial commitment or a certified security claim.

The current `rv64-op-native` and `rv64-op-root` commands expose only their explicit
experimental route; they do not switch the historical Ethereum driver or its
profiles. Admission of service-local GKR requires the receiver's independent
protocol selection and complete physical gates. The production security label
remains **128-bit security target under documented assumptions** with
`security_qualified=false`.

The [complete Miller fixture](../vectors/reports/rv64-opstack-performance-20261109/source-suite/complete-recursive-fixture-v1.json)
is a one-retirement test program with an actual Miller service packet. Its
693,812-byte root covers two leaves and one fold; recursive production took
45.630 seconds in one qualification run, additional to native proof production.
A separate process reconstructs code, input, CPU/Miller keys and outer authority
without `native-op.bin`. It rejects physical corruption, a valid wrong-key proof,
missing/duplicated/reordered leaves, changed suite policy, balanced forged Wire
claims, a substituted late Miller receipt and coherently changed terminal state.
This closes whole-root fixture framing and closure, not anchored derivation or
the heavy-block tenfold performance target.

The [actual suite3 Kona qualification](../vectors/reports/rv64-opstack-performance-20261109/source-suite/kona-small-complete-v1.json)
also completes block120794432: 796,406 instructions, CPU + Keccak + SHA, a
5,553,784-byte native bundle and a 683,432-byte three-leaf/two-fold root.
Native production records15.873 seconds before its receipt; recursion takes
140.855 seconds additional. The separate source-only receiver records32.020
seconds of cold source construction and27.057 milliseconds of root verification,
with zero final heap/external retention. Dropping the independent suite policy
or changing the externally expected output rejects. These are qualification
runs during concurrent engineering, not a controlled speed comparison.

## Latest bounded qualifications

The current eight-role R7 heavy source model uses321,908,736 cells versus
415,756,288 for each of two retained source classes (22.57% fewer). This
supersedes the historical seven-role projection: it includes the genuine QM31
input producer required for physical source closure. No heavy proof was rerun.
See the [current source model](../vectors/reports/rv64-opstack-cpu-20261109/native-dot/heavy-class-source-v2.json)
and [actual small leaf](../vectors/reports/rv64-opstack-cpu-20261109/native-dot/actual-small-cpu-physical-v2.json).
Pending recursive parents prove their independently admitted children, but do
not yet establish complete execution inventory or anchored OP validity.

The default-off producer Miller setup cache is now integrated through an
explicit proving-capability barrier. Cached and forced-fallback runs reproduce
the same complete693,812-byte CPU+Miller fixture root, all recursive nodes and
sidecars. A separate source-only receiver accepts with physical native proof
bytes absent and rejects the retained adversarial cases. This fixture contains
only one Miller leaf, so it establishes ownership and parity, not amortized
setup savings. See [producer cache qualification](../vectors/reports/rv64-opstack-performance-20261109/miller-local-gkr/producer-cache-root-v1.json).

Authenticated capture of recent transition159321793→159321794 is complete.
The own native client accepts both original and pruned witnesses with the exact
43-byte OD result. The canonical13,882,081-byte input is retained once, as a
hash-pinned deterministic gzip in `tests/fixtures/transition-159321794/`.
All15 sidecars pass standard C-KZG. Actual native anchor/root/blob/proof/order
negative controls reject. Fresh native replay from the in-repo fixture takes
0.211seconds; this is native host execution, **not RV64 or STARK proving**.
The historical input remains unavailable. See the [complete receipt](../vectors/reports/rv64-opstack-performance-20261109/transition-recent-mainnet-complete-v1.json).

The direct four-member group proves the exact canonical root previously
established by four wrapped native proofs plus three folds. Its source-derived
cell count is3.059x smaller; requested peak9.297GB under32GiB and final live
allocation zero.44.984seconds excludes12.920seconds cold producer setup and
11.440seconds independently rebuilt receiver setup. The old156.261second node
sum comes from an earlier concurrent qualification, **not a quiet matched A/B**.
No heavy proving was rerun. See the [physical group receipt](../vectors/reports/rv64-opstack-cpu-20261109/direct-native-group4-physical-v1.json).

The detached source inventory now owns its exact lookup/GKR/PCS/global security
ledger; source-derived preflight runs before wide keys and exact checks remain
mandatory afterwards. The security label remains a target under documented
assumptions, not certification. The complete selected-small detached native runtime gate passes;
production source-suite admission remains closed.

## Working rules

The [CPU continuation receipt](../vectors/reports/rv64-opstack-cpu-20261108/README.md)
reproduces complete execution bundles for 120794432 and 121057303 with fresh
receivers and both corruption controls. The synthetic OD/OP child/parent fold
also completes with physical STARK verification. These close the local execution
reproduction and synthetic-fold checks. The follow-up [real recursion receipt](../vectors/reports/rv64-opstack-cpu-20261108/real-recursion.json)
also closes an execution-only Mainnet root: three wrapped leaves and two folds,
accepted in a separate receiver process. The [heavy execution root](../vectors/reports/rv64-opstack-cpu-20261108/heavy-recursion-ternary.json)
also closes block 121065789 with 126 leaves and 64 ternary folds, independent
strict acceptance and physical corruption/missing-node rejection. Its 42.3-minute
recursion is a functionality and memory milestone, not a speed target. The
strict receiver still needs all native and recursive proofs. Anchored transition,
joined checkpoint, accumulation and settlement acceptance remain open.
The [selected guest and bounded schedule](../vectors/reports/rv64-opstack-cpu-20261108/heavy-cpu-scheduling-and-guest.json)
also complete the heavy block's native proof with 91 CPU and 24 service proofs.
The subsequent [capture/packed-accumulation qualification](../vectors/reports/rv64-opstack-cpu-20261108/capture-and-packed-accumulation.json)
reduces native production to **1,222.972 s**, with **32.358 s** fresh reception
and byte identity for all preceding proof/statement artifacts. This excludes
recursion. The [selected D2 heavy root](../vectors/reports/rv64-opstack-cpu-20261108/heavy-d2-recursion-comparison.json)
also closes all 115 native members and 173 recursive nodes in **1,781.674 s**,
additional to **1,586.092 s** D2 native production. D2 reduces native proof bytes
and increases native time; it is an explicit profile, not a default speedup.
The matched CPU recursion fanout experiment is removed after no heavy-block
gain and higher memory. Its patch and refusal selector remain documented in
[CPU tuning](CPU_TUNING.md).

The [fixed-source repair](../design/riscv-proving-stack/rv64-fixed-source-geometry.md)
checks ordered native column geometry as well as the lifted source root before
reusing a fixed binding. Complete heavy native acceptance works with both
committed-source and identity-only independently derived setup. This closes a
real cache alias; no transcript or admission guard was weakened.

The [packed Solidity arithmetic](../settlement/PACKED_AIR.md) reduces the pinned
177-node AIR to **637,484 gas**, while the full worker PCS remains around
1.724 billion gas. Component gas improvements do not close settlement.

- Replay is not a proof. A native bundle is not a recursive root. A receiver-side
  join is not an in-circuit join. A PCS replay is not a complete checkpoint verifier.
- Do not raise the 256-proof, trace-log or characteristic limits to bypass
  admission. A changed construction needs its own identity and bounded review.
- Canonical anchor/finality selection remains external verifier policy; the
  derivation guest proves ancestry from that independently selected anchor.
- Keep OP changes under `opstack/` and `settlement/` where possible. Shared
  fixes must justify their Ethereum impact and retain protocol parity evidence.
- Measure complete CPU requests separately from compile time. Record geometry,
  profiles, workers, wall/user/system time, per-child peak RSS and failure status.
  RSS uses Darwin bytes or Linux KiB converted to bytes. Requested-live budgets
  are admissions, not RSS caps; retained immutable setup is accounted separately.
- Retain exact ELF/input identities and portable reproduction instructions.
  Scratch paths in old receipts do not establish that the files still exist.

## Reproduction inputs

The execution corpus is publicly retrievable with the hash-pinned
`mainnet.py` importer. The anchored transition archives named in `TRANSITION.md`
are not in Git and were not found in this checkout or local artifact store.
Their location is needed for physical replay of the same transition. Until
recovered, keep the transition gate open; do not replace it with a synthetic
case or call an execution-only proof an OP validity proof.


## Complete grouped small execution

The selected 796,406-instruction Kona execution closes CPU/frontier, detached
sponge, local Keccak and classic SHA through one physical root. Native bundle
identity is unchanged across these terminal experiments. Source-only reception
with `detached-op.bin` absent accepts; physical corruption, source/output,
coverage/order and balanced-debt attacks reject. Original native production is
additional to every row below.

| Terminal construction | Groups / folds | Node proof time | Producer total | Peak requested memory | Root bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| R6, Poseidon2 B4 | 1 / 0 | 93.373 s | 121.133 s | 18.885 GB | 750,068 |
| R6, Poseidon2 B2 | 1 / 0 | 46.589 s | 62.630 s | 13.313 GB | 1,341,688 |
| R7, Poseidon2 B2 | 1 / 0 | 37.757 s | 51.743 s | 8.965 GB | 1,324,724 |
| R6, Poseidon2 B2 | 2 / 1 | 76.210 s summed | 100.110 s | 10.071 GB | 1,228,888 |
| R7, Poseidon2 B2 | 2 / 1 | 80.099 s summed | 106.125 s | 7.413 GB | 1,211,984 |
| R6, terminal Blake experiment | 1 / 0 | 19.078 s | 37.097 s | 12.983 GB | 1,278,096 |
| R7, terminal Blake experiment | 1 / 0 | 15.647 s | 31.552 s | 8.667 GB | 1,263,064 |

These are qualification observations during engineering, **not quiet matched
A/B runs**. Producer totals include native fresh verification and cold source
setup. The Blake row includes both genuine Poseidon2 FIXED construction and
separate Blake FIXED construction; neither is hidden. Its fresh source receiver
needs 15.377 s for source and both setups, then 9.489 ms for root read/verify.
All paths finish with zero retained heap/external custody.

R7 reduces the direct-group source model from 830,730,240 to 643,035,136 cells.
This does not guarantee an improvement for every group: the CPU+sponge subgroup
pads worse in R7. The two-group results demonstrate a real memory/latency trade,
not a universal reason to use smaller groups or R7 everywhere.

Final-only B2 uses an independently pinned outer profile; native B4 proofs are
unchanged. The shared OM31 compact-domain host-view repair has compact/full
storage byte-parity controls for both B2 and the original B4 path.

The terminal Blake route remains test-only with distinct identity, domain and
wire magic. Valid same-output Poseidon2 and Blake roots reject under the other's
format. It has **no production or settlement admission**. Its hash/Fiat-Shamir
union accounting must be reviewed before promotion; the label remains
“128-bit security target under documented assumptions,” not certification.

Receipts: [R6 B2](../vectors/reports/rv64-opstack-cpu-20261109/grouped-terminal-b2-actual-small-v1.json),
[R7 B2](../vectors/reports/rv64-opstack-cpu-20261109/grouped-r7-terminal-b2-actual-small-v1.json),
[R6 two groups](../vectors/reports/rv64-opstack-cpu-20261109/grouped-max2-terminal-b2-actual-small-v1.json),
[R7 two groups](../vectors/reports/rv64-opstack-cpu-20261109/grouped-r7-max2-terminal-b2-actual-small-v1.json),
[R6 terminal Blake](../vectors/reports/rv64-opstack-cpu-20261109/terminal-blake-actual-selected-small-v1.json),
and [R7 terminal Blake](../vectors/reports/rv64-opstack-cpu-20261109/terminal-blake-r7-actual-selected-small-v1.json).

## Anchored guest work and its limits

The new retained transition has independently accepted native replay and
negative controls; **no complete new RV64 transition or physical derivation
STARK exists yet**. Canonical Fr255, lazy Brotli allocation and bulk-memory
forwarding remain explicit guest candidates, with selected ELF/defaults unchanged.

- Canonical Fr255 removes repeated representation conversions through the
  existing arith256 service. The dense diagnostic drops 2,650,944 to 2,375,230
  instructions with independent Unicorn agreement. This is not a block timing.
- Brotli demand allocation initializes only requested cells under the original
  per-type live caps. A tiny golden diagnostic finishes in 48,493 instructions
  while the eager control is unfinished at four million. Bulk forwarding brings
  it to 39,112 instructions. These setup-heavy probes are not full-transition
  speedups; actual-channel four-million-step prefixes remain unfinished.
- Raw-container conversion preserves the exact claim and witness body, and the
  independent native host accepts it. The historical fastest 3.072-billion-step
  replay already used uncompressed input, so raw conversion is not an additional
  saving against that baseline.

The heavy complete-root target remains **unachieved** and was not rerun.

## Latest one-process small-block qualification (November 10)

The explicit R7 terminal Blake test harness now supports `MODE=from-guest`.
It starts from the selected ELF and input, executes the actual guest, produces
the native proofs, releases their wide owners, freshly verifies them, constructs
both source-derived FIXED keys, and proves and self-verifies the grouped root
in one process. Explicit `config.workers` is honored; the fallback remains eight.

| Actual block 120794432, 796,406 instructions, ReleaseFast, 16 workers | Time |
| --- | ---: |
| Guest execution and native proof production | 11.410 s |
| Fresh native verification, cold source setup and root production | 18.156 s |
| Total producer | **29.566 s** |
| Root proving alone, included above | 9.319 s |
| Additional independent source-only receiver, including nine controls | 7.914 s |

Peak requested memory is 8.667 GB under the unchanged 32 GiB cap; final heap
and external counters are zero. All native proofs and the 1,263,064-byte root,
metadata and templates match retained controls byte for byte. This is one
qualification observation, not a quiet repeated performance claim. The final
receiver reads no native proof bytes. The experiment retains the documented
security assumptions and has no production or settlement admission.

The subsequent packed-P2-tail run reproduces every native/root/sidecar byte at
**25.624 seconds total**: 9.159 seconds native and 16.465 seconds root producer.
Requested peak remains 8.667 GB. Its separate source-only receiver passes all
nine controls in 6.580 seconds (4.556 seconds setup, 9.293 ms root read/verify).
These are single observations; terminal Blake root proving itself did not speed
up in this run. See the [post-fix complete small-block receipt](../vectors/reports/rv64-opstack-performance-20261110/selected-from-guest-r7-p2-tail-v1.json).

The separate actual-heavy first-four-million-instruction conditional fragment
identified commitment hashing as 59.34 of 74.73 seconds. Packed Poseidon2
bounded-tail dispatch and lifted-prefix reuse now reduce the same fragment's
seal plus complete time to **23.93 seconds (3.12×)**. MAIN Merkle falls
39.25→5.79 seconds and INTER Merkle 20.10→3.83 seconds. Both PCS and GKR
proofs are byte-identical, independent verification passes, requested peak is
exactly unchanged at 10,093,072,140 bytes, and no major faults occur.
Outstanding aggregate RAM/Wire obligations remain explicit. This is not a
complete block/root or a controlled repeated benchmark; the heavy tenfold
end-to-end target remains open.

Receipts: [one-process small block](../vectors/reports/rv64-opstack-performance-20261110/selected-from-guest-r7-terminal-blake-v1.json),
[bounded-tail microprobe](../vectors/reports/rv64-opstack-performance-20261110/p2-bounded-tail-packed-reuse-micro-v1.json),
[actual heavy fragment parity and timing](../vectors/reports/rv64-opstack-cpu-20261109/heavy-conditional-prefix-p2-tail-v1.json).

The separate dense BN254 reuse experiment illustrates why guest instruction
count alone is insufficient. Square+multiply drops 19,344 to 8,988 instructions
with independent native/VM/Unicorn agreement, but active field cells rise
53,220 to 88,632. Conditional heavy padding saves only about 10.3% field cells
and doubles Miller leaf count. It stays opt-in; a dedicated fused tower provider
is the next experiment. See the [full cost review](../design/riscv-proving-stack/op-bn254-dense-reuse-cost.md).


## Fused pairing foundation

The immutable G2 doubling/addition source now has complete physical BYTE/SSA
fixtures with independently pinned expected input/export authority. All writers
are canonical, the complete equations have degree at most three, and both local
relations close independently. Eleven source/public-key attacks per class reject;
coherent internal result+p retains local lookup closure but fails the physical
proof. These small correctness fixtures use deliberately input-specific FIXED
keys and do not admit a reusable production provider.

The complete 87-line preparation now has a physical BYTE/SSA proof, including
source-owned Frobenius corrections and all line exports. Exact non-infinity G2
curve/subgroup checking and a positive pairing residue certificate have separate
physical proofs as well. Each uses an independently reconstructed receiver and
adversarial source/statement controls; coherent noncanonical writers and an
unrestricted inverse-scale residue attack reject.

| Conditional arithmetic gate | Native + child bytes | Requested peak | Remaining authority |
| --- | ---: | ---: | --- |
| All 87 G2 preparation lines | 186,188 | 59.54 MB | Variable-input Wire/RAM and reusable setup |
| Exact G2 curve/subgroup | 146,656 | 114.17 MB | Infinity handling and composite pairing linkage |
| Positive pairing residue | 253,004 | 36.93 MB | Bind z to the complete shared Miller computation |

These are small q12 correctness fixtures with input-specific FIXED authority,
not production security or performance qualifications. The private residue
hints are canonical, and its scale is constrained to Fp6; they are not free
host validity claims. The next engineering gate is the source-owned shared
Miller accumulation, then one authenticated composite provider, variable-input
Wire/RAM closure and recursive reception. No new VM tag or default is admitted.

Evidence: [preparation](../vectors/reports/rv64-opstack-performance-20261109/guest/g2-preparation-physical-v1.json),
[subgroup](../vectors/reports/rv64-opstack-cpu-20261110/g2-exact-subgroup-physical-v1.json),
[residue](../vectors/reports/rv64-opstack-performance-20261109/guest/positive-residue-physical-v1.json).
