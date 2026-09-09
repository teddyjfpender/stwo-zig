# Small detached recursion: work in progress

Starting checkpoint: `51646b44`. This directory retains failures as well as
passing gates. The corrected version-2 development route proves two different
x7 statements under one identical serialized key and freshly verifies both.
The original version-1 admission failure remains retained below.

## Admission and dynamic register inputs

`detached-admission-first.log`: all nine guarded tests passed. The three groups
exercise the witness-free 39-component factory, expected-public statement claim,
and explicit detached development transcript. The factory's first compilation
took 46 seconds; public-input and transcript checks took six and five seconds.
Runtime was below 300 ms per group. These are construction/semantic checks,
not recursive-proof acceptance.

`dynamic-register-focused-gates.log`: all 20 tests passed, including test-root
declarations. The named gates cover row11 byte decomposition/export, native-sum
graph equality across changed register values, and row15's exact consumption of
those bytes. Native/CSP proof parameters and defaults are unchanged. The outer
statement/public-source identities are versioned for the added lookup events.

The focused frontend commands now filter their own cases and enforce minimum
test counts. The broad test inventory still owns transitive coverage. Compilation
fell from approximately 60/21/20 seconds to 13/6/6 seconds for these three gates;
each focused runtime was at most 500 ms. These are observations from one build
of each version, not repeated benchmark medians.

Retained failures explain the subsequent edits:

- `row11-semantic-gate-first.log`: enum arithmetic inferred a one-bit result.
- `row11-semantic-gate-second.log`: the intentionally old AIR digest rejected
  the new event structure; the measured digest was then pinned.
- `dynamic-register-semantic-gates.log` and the two `*-semantic-direct.log`
  files: an obsolete seven-event compatibility guard rejected the nine-event
  AIR, and the new graph regression omitted the required binary capacity lane.
  The direct retained test binaries identified the exact errors without a new
  compilation. Both causes are repaired by the passing focused run above.

## First detached artifact and retained failures

`candidate-x7-a-verifier.log` records a real 91,035-byte recursive proof accepted
in a separate process with no native inputs. Verification took 15.919 ms and the
verifier request took 17.151 ms in this single observation. The producer reports
403.233 ms detached preparation and 863.204 ms detached proving, in addition to
its existing native-assisted parity route. These are development-profile
measurements, not a production-security or optimized full-request benchmark.

`candidate-x7-a-hostile-replay.json` records 12 fresh-process cases: genuine
acceptance and rejection of changed claims, balanced claim/provider tampering,
malformed proof encoding, changed proof data, a wrong key pin, and a different
canonical expected statement. The maintained command is
`scripts/riscv_segment_v2_detached_gate.py`; retained binaries and source snapshots
pin this historical version.

`candidate-x7-b-producer.log` rejects a different x7 value under the same key.
`candidate-x7-fixed-circuit-diff.json` localizes the mismatch to row13's
preprocessed statement-hash call words; other preprocessing rows and graph
structure agree. The correction moves those words into committed witness data
and binds each indexed group to expected calls derived by the shared native
authority-preimage emitter. `row13-dynamic-fourth.log` passes both focused tests;
the corrected real-proof result is recorded below.

The memory audit also found that Span memory digest fields were not equated to
the actual sparse-snapshot digest fields. Canonical admission and 16 independent
AIR graph equalities now implement that binding. `memory-binding-semantic-v1.log`
passes 42 tests, including every one-sided digest mutation. The detached transcript is
version 2; the retained first artifact uses version 1 and must be replayed with
its pinned historical verifier.

## Corrected same-key complete proofs

`same-key-v2.json` records two distinct expected statements and proofs with the
same serialized key, SHA256
`0c8de0d9530af6194acbb40e7657ce4b115cf33bb2603958b7ca69b97eb30c85`.
Both fresh verifier processes accepted without native inputs. The x7-a proof
has 93,420 bytes and verified in 17.069 ms; x7-b verified in 15.183 ms.
These are individual observations, not medians. The producer still runs the
native-assisted parity oracle before producing the additional detached proof.

`candidate-v2-x7-a-hostile-replay.json` passes all 12 fresh-process cases,
including the other canonical expected statement. This checks a fixed tiny
fixture profile across changed register values; arbitrary sparse topology or
production security is not implied. The source-pinned rebuilt verifier also
passes the 12 retained cases in `same-key-v2-current-hostile-replay.json`.

`detached-v2-gates-first.log` passes all 12 guarded integration tests and builds
the standalone verifier. `core-geometry-oom-focused-v4.log` passes both named
tests, including exhaustive allocation-failure sweeps for column concatenation
and both mask-construction modes. `detached-boundary-review.md` records the
separate code review and its practical limits.

## Two actual children on CPU and Metal

`two-child-cpu-1/` and `two-child-metal-1/` retain both actual proofs for the
same completed 98-instruction memory workload. Child 0 covers cycles [0,64),
child 1 covers [64,98). Native prover output is destroyed before fresh native
decoding; each outer candidate and preparation owner is destroyed before the
next child. The producer process exits before detached bundle verification.

Both backends produce byte-identical per-child keys, expected wires and outer
proofs. Each backend passes 17 fresh-process cases, including complete-job
coverage, sparse snapshots, boundary clocks and lineage, plus rejection of
swapped, duplicated and missing children. See the two
`two-child-*-1-hostile-pair-replay.json` files. This is a verified two-proof
bundle; it is not a succinct recursive parent proof.

Individual producer-process observations: CPU 7.91 seconds, Metal 6.55 seconds.
Child outer proofs have 93,479 and 92,901 bytes. CPU fresh per-child verification
took 16.261 and 15.603 ms. CPU maximum RSS was 1,070,563,328 bytes; Metal maximum
RSS was 591,003,648 bytes. The OS separately reported Metal peak memory footprint
of 1,418,905,472 bytes: RSS must not be substituted for total device-related
footprint. Raw `/usr/bin/time -l` output is retained. These are development-profile
observations, not repeated performance benchmarks.

`detached-child-recording-second.log` passes all five guarded tests: the factory
records all 39 AIRs with 41 symbolic claim inputs, and a retained real child
survives input destruction, transcript/capture replay and tamper rejection. Its
recording contains 100 operations, 1,484 Poseidon calls, 2,276 sampled values,
6,348 queried values, 16 FRI layers and three queries. That gate precedes actual
composition evaluation and parent AIR admission; it does not replace either.

`detached-child-composition-first.log` then passes actual composition evaluation
against that genuine proof. The graph has 10,072 inputs, 39,769 nodes and 52
outputs. Every one of the 41 claim inputs and all four limbs of a composition
sample are independently mutated and rejected. The combined real-child replay
and composition gate runs in about one second with 18 MiB reported RSS, after a
57-second focused compilation. Parent authentication of the graph's dynamic
public-boundary input remains required.

## Required complete-proof checks still pending

`detached-child-prefix-third.log` passes the genuine-child gate with actual
typed transcript-prefix rows: 60 operations, 247 Poseidon calls, 54 fixed and
984 dynamic payload words, 1,000 declared input uses and two public-boundary
challenge exports. The gate checks lookup tuples and multiplicities, keeps
dynamic values out of preprocessing, and checks the exact transition to the
captured PCS suffix. It runs alongside composition and fresh verification in
one second with 18 MiB reported RSS (57-second compilation). Parent activation
remains false until consuming arithmetic, provider closure and a parent proof
pass. The first two attempts retain compile failures, corrected by explicit
coordinate narrowing and matching the existing infallible row constructor.

`sparse-specialization-before-first.log` retains the no-proof reproduction:
values 13 and 14 have identical address topology and 2,255 graph nodes but
different constant anchors; value 269 adds a seventh continuation term and
changes the graph to 2,263 nodes. The 12-test gate takes 450 ms after seven
seconds of compilation. Its exact pre-fix test is retained in
`sparse-specialization-before.patch`; this is the retained pre-fix defect. The dynamic-memory results below establish
the subsequent fix for an explicitly admitted address topology.

The single-command lifecycle gate now also passes 17 fresh-process cases on
both backends. `lifecycle-cpu-1-process.json` and
`lifecycle-metal-1-process.json` retain exact commands and wall times of 8.076
and 6.282 seconds. Producer processes exit before verification; caller allocator
payload is zero before each native decode and after each outer producer is
destroyed. The gate checks the independent key pins and expected inputs, actual
Metal dispatch, and unchanged artifact hashes. `lifecycle-guard-checks.json`
retains rejection of invalid lifecycle metadata and output reuse. Runnable
instructions are in the small-recursive benchmark document. Verifier-only
replays do not hold the heavy-job lock.

The maintained candidate producer and detached verifier share one explicit
transcript definition. A candidate is not a verifier receipt. The corrected
same-key check has fresh-process evidence. Its fixed projection includes the exact Tree0
root and active lowering anchors; dimension equality alone is insufficient.

The next milestone is the actual recursive parent: bind the
detached transcript's dynamic public inputs, context/hash boundaries, claims and
captured openings into its active AIR. No recursive parent, 2/4/8-segment ladder,
or production-security result is claimed yet.

The earlier CSP diagnostic's quiet-host admission remains unmet. New outer
admission changes do not establish CSP performance promotion.


## Dynamic memory and parent preparation, 2026-09-08

The row11 memory source now exports constrained bytes and nonzero selectors;
row15 relays them into the shared native-sum graph. All scheduled continuation
terms remain in the graph, including zero-byte slots. Values13,14,269 under the
same address topology now share one graph and per-child key. The focused
row11/native-sum/public-source gates passed23 tests. The pre-fix reproducer is
retained above; no CSP execution or protocol default was changed by this fix.

The real98-instruction memory fixture executes64+34 instructions, starting with
13,14 or269 at address1048832. Every seed produced two CPU and two Metal child
proofs; corresponding proof, key, claim and expected-input bytes agree across
backends. Each of the six pairs passed17 fresh-process acceptance/rejection
cases, including adjacent coverage and continuation. Independently reviewed
expected wires and key pins live in `dynamic-memory-v3-admission/`; the
`dynamic-memory-v3[-metal]-seed*-accepted.json` files contain fresh receipts.
Those results cover changing values within the admitted topology, not arbitrary
memory membership or an independently proved recursive parent.

The maintained lifecycle command was also rerun with seed13 on both backends:
`dynamic-memory-v3-lifecycle-cpu-1.json` and
`dynamic-memory-v3-lifecycle-metal-1.json` both pass17 cases, including producer
process exit before fresh verification. Producer wall time was7.747s CPU and
6.031s Metal; individual detached wrapper verification was15.4/15.1ms. These are
single development-profile observations, not production-security benchmarks.

`dynamic-memory-v3-child-pcs-first.log` passed the genuine child gate with shared
PCS transcript scheduling, actual PCS/FRI arithmetic and altered DEEP-answer
rejection. Runtime was about1s at27MiB RSS after a61s compilation. The shared PCS
suffix has40 operations,1,242 Poseidon calls and9,148 sampled field words. This
check precedes the subsequent full Merkle/query row assembly and continuation
root changes; those require their own acceptance records.

`dynamic-memory-v3-parent-boundary-first.log` passed both focused arithmetic
gates: canonical boundary hashes/identities/sections rejected34 mutations per
fixture; the parent folds the two actual seed13 child projections, publishes412
words, and rejects21 arithmetic mutations. Boundary owners were destroyed before
parent checks. Runtime was352/315ms; compilation6/7s. Native identity golden
checks then passed21/21 (`segment-statement-identity-goldens-v2.log`). These are
preparation checks, explicitly not a parent STARK proof.

The active work is exact cross-circuit input routing, provider closure and one
parent STARK with a fresh independent verifier. The2/4/8 ladder and separately
admitted production-security profile remain pending.


## First independently verified two-child parent, 2026-09-09

The actual parent now proves the child transcript, composition, PCS/FRI openings,
boundary hashes, sparse memory and clocks, and complete root statement in its
active typed AIR. Producer state is destroyed before serialized artifact custody;
the standalone verifier consumes only the admitted key, expected root, claims and
proof. Expected roots are separately derived from reviewed child public wires.

The first full-row closure exposed a real query-randomness mismatch: the transcript
published full field draws while query mapping consumed masked indices. The shared
owned transcript now projects the original draw words; the existing query AIR
proves reduction to indices. The failing sixth assembly log remains retained.
The seventh gate closes1,383,808 contributions across47 domains with no residuals,
preparing in388ms (2s complete check,507MiB RSS).

`detached-parent-v1-{cpu,metal}-seed{13,14,269}-first-accepted.json` all pass21
fresh-process cases (126 total), including altered canonical root, balanced claims,
balanced provider partials, inactive claims, malformed proof and key/profile changes.
All runs share the independently retained tiny-memory-v1 parent key; corresponding
CPU/Metal-origin parent artifacts match exactly. The parent backend is CPU in all
six runs. The producer's initial key is explicitly recorded as bootstrap fixture
admission, then independently pinned for all subsequent changing-value runs.
No general circuit admission or production security is implied.

`detached-parent-v1-measurements.json` records3.87–4.06s parent request,
9.7–11.8ms core fresh verification, roughly655–656MiB maximum RSS, and
92,779–96,390 proof bytes. Native child production is outside those timings.
`detached-parent-v1-lifecycle-cpu-seed13.json` exercises the maintained one-command
producer-destruction/fresh-verification gate. Five additional ingress cases reject
swapped/duplicate children and swapped/duplicate expected inputs before proof output.

Current shared semantic checks pass: genuine child PCS replay, boundary arithmetic,
parent arithmetic, routing/export compatibility, and21 native identity goldens.
Additional explicit clock and command checks are recorded separately. The full
4/8-segment recursive tree, production-security profile and quiet-host16-case CSP
performance admission remain open. The next tree needs authenticated intermediate
endpoint lineage and a parent-proof capture consumer; a flat bundle is not that tree.


## Parent proof as the next recursive input, 2026-09-09

The ordinary parent verifier and its recording/capture variant now execute one
shared implementation. Leaf and parent capture share the draw-to-capture mapping;
recording freshness belongs to the channel. No parent witness reconstruction is
used to obtain native verification acceptance.

The shared composition recorder now advances through the manifest's active roster,
while retaining physical claim/sample coordinates. The previous contiguous-row
assumption could not consume this parent (30 active rows,36 physical claim slots).
Capture geometry likewise checks provider membership rather than treating physical
row34 as active ordinal34. A distinct detached-parent manifest family prevents
substitution with the legacy universal or Ethereum family.

`detached-parent-capture-first.log` passes the genuine parent and original child
replays. The parent check destroys its input arena, authenticates the complete
recording, records38,076 composition graph nodes from2,149 sampled values, rejects
all45 claim/sample mutations, and checks the shared PCS/FRI circuit. Runtime882ms,
17MiB RSS; compilation46s. The original child remains1s/30MiB after a1min build.
This is a verified parent and checked consuming arithmetic, not another parent
STARK or a4/8-segment tree.

Rebuilt standalone producers/verifiers then passed both maintained complete gates
(`detached-parent-capture-lifecycle-{cpu,metal}.json`,42 fresh-process cases).
All four resulting artifact files match the earlier seed13 parent byte for byte,
including the key and proof. Build receipts record unchanged source through the
build and binary hashes. Unused parent-inactive flags were removed; semantic-only
checks now correctly report that they did not verify a parent proof themselves.


## Version2 continuation publication, 2026-09-09

The supported parent profile now publishes436 words: the existing412-word Span,
then session, entry lineage and exit lineage (8 words each). The shared frontend
`span_continuation_v1` defines native and AIR endpoint propagation/join checks.
The key's explicit root/intermediate mode participates in its identity and the
transcript. Root mode retains the shared complete-job checks. This is a new
version2 admission; version1 keys are not silently accepted by the new verifier.

The first producer exposed a412-word publication-counter assumption. Its retained
failure is `detached-parent-continuation-v2-cpu-seed13.log`. The counter now derives
its length from the shared publication type. A separate mutation-helper bound
was repaired and all24 new public words have direct AIR mutation coverage.
The third preparation gate passes3 tests, exact closure and394ms preparation;
full preparation/closure remains2s at507MiB RSS. The initial missing-fixture
invocation and compile failures remain retained rather than reported as passes.

Six actual version2 root proofs cover seeds13/14/269 and both native child
backends. Their25-case fresh-process gates all pass (150 cases) under one root key,
and corresponding artifacts are byte-identical across child backends. The
separately admitted intermediate mode also proves and passes25 cases on this same
full two-segment fixture. This tests mode admission/publication, not a partial
four-segment subtree. Mode tampering, session and both lineage changes reject.
The new root's genuine consuming capture passes in943ms at17MiB RSS, including
45 claim/sample mutations and PCS/FRI replay after caller-input destruction.

Current admission and source/binary pins are in `detached-parent-v2-admission/`
and `detached-parent-v2-third-binary-pins.json`. Current observations are in
`detached-parent-v2-measurements.json`. The actual4/8-segment tree, production
security measurement and formal CSP performance preservation remain open.

## Actual segment ladder and partial recursive layer, 2026-09-09

One shared materializer, statement admission and child prover now handle2/4/8
segments. The two-segment CLI alias retains the same implementation and all eight
reference artifact files are byte-identical. Independent expected wires come
from the execution-only workload runner; review files record explicit development
key admission plus independently modeled positions, sparse values and clocks.

The first ladder execution failed at the genuine1→2 boundary with SlotsMisaligned.
Both source and canonical-wire adjacency had incorrectly required binary sibling
alignment. They now use the existing shared executed-span join; recursive folds
retain slot alignment. The nine-case2/4/8×1/4/16-address ladder checks both sides
of this distinction and passes in0.78s/about5MiB RSS. Its separate executable
compiles in7s/614MiB; the full prover builds still take minutes/about7GiB. Frontend
V2 checks and identities pass23 cases in706ms after6s compilation.

All14 CPU and14 Metal child wrappers freshly verify through336 mutation/acceptance
cases. Metal reuses independently pinned CPU keys and produces identical bytes.
Production observations are7.73/15.24/30.45s CPU and6.95/12.17/24.93s Metal for
2/4/8 children, excluding aggregation. Native ingress remains the largest portion:
CPU19.63s of30.45s for eight children, Metal13.92s of24.93s. Child wrapper proving
adds about7.7–7.8s and preparation about3.1s. Resource and phase details are in
segment-ladder-measurements.json; these are single development observations.

Six actual partial parents cover the first recursive layer of the4/8-segment jobs.
An explicit continuation profile admits retained entry clocks on both children
of later pairs. All150 fresh parent cases pass, including rejection of attempts
to publish a partial span as a whole root. The maintained producer-exit gate also
passes25 cases on a Metal-origin later pair under the CPU-origin parent key;
all four artifact files match. Parent requests are3.85–3.90s, preparation379–388ms,
RSS655–656MiB and core fresh verification10–11ms. The command/parser gate passes
four cases. Root proofs consuming these intermediate STARKs, production-security
measurements and formal CSP preservation remain open.

The genuine later partial parent also passes the next-consumer capture gate:
994ms/17MiB,38,076 composition nodes,2,149 samples and45 rejected claim/sample
mutations after input destruction. Compilation took47s/2GiB. This checks the
consuming arithmetic and PCS replay, not a next-layer STARK.

## Complete four/eight-segment recursive roots

Actual4→2→1 and8→4→2→1 trees now have one independently verified root each.
The parent consumer uses the shared immutable capture owner, composition and PCS
path. Transcript payload markers originate in the same admitted protocol used
by the standalone verifier. Its active boundary reconstructs436 public words
from872 split-u16 transcript limbs, proves canonical encoding and derives the
complete public lookup claim. Shared continuation checks authenticate span,
session and endpoint lineage at every recursive level.

The four-segment final assembly closes1,437,799 tuple contributions with no
unmatched tuples in any of47 domains. Its first loader compile failure is retained
in `parent-consumer-assembly-first.log`; the repaired assembly passes in
`parent-consumer-assembly-second.log`. The final preparation/statement checks
also reject45 coherent mutations against the same parent-of-parent AIR, including
swaps, duplication, gaps, incomplete root coverage and state drift, bypassing
host admission. Native first-layer statement checks still pass228 raw-boundary
mutations and the same45 shared statement mutations.

`parent-consumer-final-checks-first.log` covers the actual eight-segment root:
436 coherent public-word changes, the noncanonical encoding of zero,45
composition mutations, all872 dynamic transcript limbs, PCS and caller input
destruction. The capture check runs in1s/36MiB after50s/2GiB compilation. Existing
leaf capture still passes, and all four transport checks pass.

The four/eight-segment roots take3.91/3.92s for final aggregation, produce
90,169/85,923-byte proofs and freshly verify in12.38/9.78ms. Peak parent RSS stays
about656MiB. See `segment-ladder-root-measurements.json`; its stage sums combine
separate observations and are not single end-to-end controller measurements.

The seed14 four-segment job reuses every seed13 key: four native-child wrappers,
two intermediate parents and the final root. All48 child and75 parent fresh
cases pass with changed public memory values. The full eight-segment tree also
replays from actual Metal-origin children through seven CPU parent producers;
all175 cases pass under the CPU-admitted keys and all parent artifact bytes are
identical. Each maintained gate waits for producer exit before verification.
The four initial new parent proofs add100 fresh acceptance/rejection cases.

Keys in `segment-ladder-{4,8}-admission/` remain explicitly reviewed bootstrap
development admissions. No candidate self-admits in the pinned lifecycle runs.
Production-security measurements, formal quiet-host CSP preservation and
optimization of the measured whole tree remain open. The new route does not
change shared RV32 types, CSP protocol identities or backend worker policy.

## Measured parent opening optimization

The existing stage recorder is available through
`STWO_RISCV_RECURSIVE_PARENT_PROFILE=1`, with task capture disabled. It covers
fixed preprocessing, main columns, exact closure, interaction generation and
commitments, then the shared engine composition/PCS stages. The ordinary route
allocates no recorder nodes. Profiling on/off preserves exact key/proof bytes
and passes50 fresh cases.

The first profile attributed1.373s to sampled-value evaluation,743ms to exact
lookup closure and389ms to composition. The small parent had explicitly
discarded coefficients already computed for commitments. Retaining them reduced
sampled-value evaluation to16.96ms, about98.8%. Three alternating A/B rounds on
the same eight-segment final root reduced median request time from3.8748s to
2.5528s (34.1%), while peak RSS rose from655.6MiB to703.5MiB. All175 fresh cases
pass and key, claims, proof and expected-word bytes remain identical. This uses
the established PCS retention policy only in the small detached parent; CSP
and native-child defaults are unchanged. Detailed source/binary pins, phase
profiles, process memory and all rounds are in `parent-coefficients-ab.json`
and the adjacent build/patch records.

The remaining dominant measured phase is exact tuple closure, approximately
749ms, followed by composition at394ms. Further work should optimize that actual
finalization boundary without replacing authenticated ownership with a cached
validation flag. The complete tree now works; production-security measurements
and formal CSP promotion are still outstanding.

The retained-coefficient producer also passes25 fresh cases on the original
two-native-child parent with Metal-produced inputs, under the original admitted
key and with byte-identical artifacts (`parent-retained-coefficients-metal-two-accepted.json`).

## Shared compact closure and range-column finalization

The small parent now reuses the existing compact exact tuple ledger. The owner
is consolidated in `recursive_compact_tuple_ledger_v1.zig`; Ethereum consumers
use the same implementation. The ordinary diagnostic ledger used by CSP keeps
its existing behavior. Both ledgers group non-range tuples by the same canonical
SHA-256 digest; compact range entries use exact canonical table indices and
preserve malformed-input and allocation-failure rejection before cancellation.
No protocol, AIR constraint, key identity or worker policy changed.

A focused `test-recursive-compact-tuple-ledger` command now runs all seven existing
parity/provider-phase/allocation-failure checks, using the previously unwired
small test root. Initial compilation took6s/538MiB, execution267ms/4MiB; the later
cached run took23ms. The genuine parent preparation gate retains identical exact
closure of1,437,799 contributions, while its process peak fell511→356MiB.

Three alternating complete-root A/B rounds show median request2.573→2.253s
(12.4%); peak RSS703.5→693.0MiB. Closure itself was406ms, down from749ms. Every
proof/key byte matches the original independently admitted root and all175 fresh
cases pass. The first compact round was slower at2.838s; subsequent rounds were
2.243s and2.253s. These local observations are retained in `parent-ledger-ab.json`
and do not establish quiet-host or CSP performance promotion.

The finalization regression additionally exposed that the old audit read the
range provider's retained counter without comparing its generated main column.
Changing the actual multiplicity still reported closure; the failing run is in
`parent-range-main-regression-first.log`. The fix compares every physical range
multiplicity with the owned counter before allocating the ledger. The fixed
regression and all ledger checks pass in `parent-range-main-regression-fixed.log`.
This is an audit-boundary defect, not evidence of a forged STARK being accepted.
The final producer is checked with both native-child and recursive-parent-child
Metal-origin inputs, using the existing keys and independent verifier.

The first two measured optimizations are now implemented. The next critical
milestones are the separately admitted production-security route and formal CSP
preservation, before further scale or broad optimization.

## Stronger native profile through the active small ingress

The CPU/Metal driver now accepts an explicit native-ingress-only profile check.
The existing one-query development selection remains the default for complete
wrappers. The additive `protocol_v1` selection uses the existing frozen protocol
parameters at every native boundary: proving, serialized-wire shape preflight,
fresh CPU verification, captured FRI and owned recursive preparation. It does
not emit or claim a stronger recursive root.

Both native backends pass on the first64-instruction segment of the same real
98-instruction one-address memory fixture. Native producer allocations are
empty before fresh decoding. CPU stronger-profile ingress is4.48s, including
2.28s proving,0.45s verification and0.99s recursive preparation. Metal is3.38s,
including1.07s proving,0.47s verification and1.01s preparation. CPU process RSS
is1008MiB; Metal is531MiB, excluding a separate device-footprint measurement.
These single observations are not CSP/performance promotion.

The193-query/fold-four native proof is1,323,023bytes and produces58,865
verifier-core Poseidon calls, compared with29,002bytes and315calls for the
one-query/fold-two development proof. Recursive preparation therefore scales
much more than native proving in this small example. Its next complete wrapper
must authenticate the larger input, with an explicitly versioned stronger outer
profile, interaction PoW in the AIR and rejection of weaker child admissions.
Production-security recursion and formal CSP preservation remain open.

Five invalid profile/workload combinations reject before proving. The complete
existing development route is additionally checked against its retained proof
bytes and independent admitted keys using the maintained producer-exit gate.
CPU and Metal builds complete in163s/177s (about7GiB/6GiB compiler RSS). The
runtime check is small; compilation of the shared full driver remains minutes.
See `native-security-ingress-measurements.json` and the adjacent source/binary
pins, proof receipts and logs.

Both complete development replays pass32 fresh cases in total, and all16
artifact files are byte-identical to the admitted baseline; see
`native-profile-default-parity.json`.

## Complete q193 child wrappers on CPU and Metal

A separate `recursive_q193_v1` key profile now admits the existing frozen PCS
parameters for both native child and detached wrapper: 193 queries, fold four,
PCS PoW 16 and interaction PoW 10. The native producer rejects weaker PCS input
before cohort allocation. Key validation rejects a weaker native query schedule.
The shared detached transcript requires and checks its interaction nonce before
relation draws. Default q3 keys, claims and proof bytes remain unchanged.
The q193 profile remains experimental pending its consuming parent AIR and root.

Two actual adjacent CPU-origin child wrappers freshly verify after producer
exit. Their 98-instruction memory job takes 33.13s to produce: 9.73/10.19s outer
proving, plus 2.66/2.62s cohort/key preparation and native ingress. The first
2,487,266-byte wrapper verifies in 83.6ms. Peak RSS is 2.43GiB. Input-column
estimates report 540,806,144 bytes before the three tree allocations and explicitly
exclude expansion, commitments and metadata. Sampling found the known discarded-
coefficient opening path; it does not yet give a whole-phase time attribution.

Changing initial memory from 13 to 14 reuses both complete key files and freshly
verifies against independent expected wires. Actual Metal native proofs also
produce identical wrapper/key/claim/statement bytes under the same keys, with
32.88s production and approximately 83.3ms first-wrapper verification. Outer
proving and fresh verification remain CPU operations. RSS is separate from any
Metal device footprint; these runs are not quiet-host performance promotion.

The stronger runs pass 92 fresh acceptance/rejection cases; the development
CPU/Metal replays add 34 cases and preserve every baseline artifact byte. Eight
focused protocol/transport checks pass, including legacy claim encoding, nonce
zero versus absence, profile drift, invalid/missing work and unexpected work on
the development transcript. Evidence and parity hashes are indexed in
`q193-child-measurements.json`; `q193-child-admission/review.json` records the
bootstrap pins, cross-statement reuse and remaining admission requirements.

Next: extend the shared detached prefix to carry the interaction PoW through
its existing typed pow-check/frame/nonce rows, then admit and prove the stronger
two-child parent and final root. The current prefix still assumes single-frame
mix/draw operations, so its q3 success does not establish this q193 consumer.
Production-security root, larger strong-profile trees and formal CSP preservation
remain open. Do not replace those gates with these independently verified leaves.

## Independently verified q193 two-child root

The separately admitted `recursive_q193_v1` parent now verifies both real q193
child wrappers inside its AIR and yields one freshly verified root. Interaction
PoW shares its claim encoding and transcript step between leaf and parent; the
prefix carries its temporary draw, work check, frame and nonce through the
existing typed AIR rows. A genuine invalid-work mutation keeps the word/bit
decomposition consistent and is rejected by the direct AIR constraints. The
original prefix failure remains in `q193-parent-prepare-before-pow.log`.

The first parent process takes29.05s, including6.16s preparation,3.69s fixed-key
preparation and18.15s subsequent proving/serialization. Its2,563,834-byte root
verifies in73.3ms, with6.24GiB peak producer RSS. These are single local
observations, not performance promotion. Stage profiling assigns5.09s to exact
lookup closure,3.29s main commitment,2.01s interaction filling,2.08s interaction
commitment and3.54s composition. Sampled-value evaluation is246ms; the previous
coefficient-retention improvement remains active. Preparation and closure are
separate measured phases; do not conflate either with STARK verification.

A different initial memory value (13→14) produces a different accepted proof
under the identical complete parent key. Actual Metal-origin native children
also produce identical parent proof/key/claim/publication bytes, with27.73s
parent production and79.0ms fresh verification. All aggregation remains CPU.
These three strong runs pass81 fresh-process cases. The default q3 replay adds
26 cases and preserves every old artifact byte. A real weak-child invocation
rejects in41ms before output creation and before parent AIR preparation.

The next recursive consumer also passes its genuine capture, shared prefix,
composition and PCS checks after input destruction:436 coherent public-word
mutations, noncanonical zero and45 claim/sample mutations reject. This focused
check runs in3s, with49s compilation. The combined child/command/producer/verifier
build takes221s; its real stronger-child replay runs in16s and the four command
checks in255ms. Four shared transcript checks and the parent capture add five
more passing focused tests. See `q193-parent-measurements.json`, admission review,
complete-proof gate reports and retained build/source/binary identities.

This completes the first q193 two-child root, not the whole goal. Formal
production-security admission and CSP preservation remain open; no stronger
four/eight-segment root or Ethereum block benchmark is claimed. The next backend
milestone is full Metal proving of leaves, wrappers and every parent level under
the same admitted protocol, with fresh independent CPU verification and actual
per-proof GPU dispatch evidence. Then finish the stronger2/4/8-tree measurements
and optimize the largest remaining measured costs.

## Actual Metal parent proving

The parent proof transaction now takes an engine at its backend boundary. CPU
remains the default; the Metal runner uses the same AIR, transcript, parameters,
key admission and serialization. Its authenticated core AOT runtime must dispatch
Metal work and Poseidon commitments, release all call leases and shut down before
reporting success. The independent CPU verifier and admitted CPU keys are reused.

Both q3 and q193 parent proofs pass their fresh-process gates (26+27 cases), with
all four artifact files byte-identical to their CPU baselines. The q193 parent
process takes23.36s, versus the earlier29.05s CPU observation, and verifies in
77.7ms. Its RSS is5.61GiB, separate from device footprint. Telemetry records95
Metal dispatches and10 Poseidon commitments. No CPU fallback counter is recorded;
this does not mean scheduled host work disappears. Combined fixed/main/interaction
commitment phases fall from9.06s to3.66s. Exact closure remains5.02s and composition
3.69s. These are single observations, not a controlled performance promotion.

The default CPU producer is rebuilt through the same generic transaction, freshly
verified and byte-identical to its old output; four command checks pass. Metal
compilation is100s; the CPU producer plus command checks take98s. Evidence is
indexed in `metal-parent-measurements.json` and the adjacent complete-proof reports.
The maintained Metal target is `build-recursive-segment-v2-detached-parent-producer`
in `src/integrations/riscv_metal`. The shared complete-proof gate accepts explicit
`--metal-aot-bundle` and `--metal-aot-manifest-sha256` with its normal producer/key/
expected-statement pins, and checks dispatch/shutdown evidence before verification.

Full Metal trees remain unfinished: native children and recursive parents now
run on Metal, but the detached child wrappers still use CPU. Next pass the same
backend engine through their existing producer transaction, retain per-wrapper
GPU evidence, prove and freshly verify a complete two-segment Metal tree, then
run the actual2/4/8 ladders. Expand telemetry to attribute composition's remaining
host/device work before claiming further GPU speedups. Production-security
admission and the formal CSP preservation gate remain open.
