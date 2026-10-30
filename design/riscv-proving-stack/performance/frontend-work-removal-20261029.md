# Block-scale RISC-V work removal

The target is the retained 139,214,856-instruction Ethereum block, including
every provider and one independently verified root. A small native proof or
recursive parent is a correctness gate, not completion of this target. The
previous 1–3 hour H200 estimate is a speculative planning range; neither a
block measurement nor a calibrated architectural model supports it.

The active sequence is now **CPU architecture and scaling qualification first**.
The GPU design brief below is a later implementation constraint; no GPU work
is required or being run for this CPU campaign.

## CPU implementation and scale checkpoint

The [CPU campaign](../../../vectors/reports/riscv-cpu-architecture-20261029/recursive-window-times.csv)
now contains genuine 1,048,576-instruction continuations of the retained guest
at q70/PoW26. Both comparisons use exactly the same externally selected complete
incoming/outgoing state, ELF, eight CPU workers and original theorem. Neither
proves the skipped prefix or a complete Ethereum block. Each observation is one
diagnostic run, not a repeated ranked median.

| Partition | Original STARKs | Source excluding recursion | Recursion | Request to verified root | Charged peak | Process RSS peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Four 262,144-step segments | 7 | 23.13 s | 115.67 s | 142.88 s | 36.64 GB | 36.70 GB |
| One 1,048,576-step segment | 4 | 23.21 s | 85.01 s | 112.24 s | 29.67 GB | 29.73 GB |

The row-fused producer also independently closes 131,072, 524,288 and 1,048,576
instructions in 57.67, 66.80 and 110.13 seconds, with charged peaks of 20.37,
19.59 and 29.67 GB respectively. At 1M, its complete root bytes match the legacy
producer exactly. Native proving changes from 8.26 to 7.92 seconds and total
time from 112.24 to 110.13 seconds in single observations: **no substantial or
statistically established performance gain**. It remains opt-in. This is useful
negative evidence against spending another campaign on row-recipe construction.

The [recursive stage CSV](../../../vectors/reports/riscv-cpu-architecture-20261029/recursive-parent-stages.csv)
retains inclusive parent/child timings with indexed paths. Do not add a stage
to its children. The next architecture round must join the nonterminal window
memory theorem into the shared original-PCS union before recursive verification;
reducing original producer overhead alone cannot meet the goal.

Both roots passed detached verification after original proof/witness owners and
checkpoints were destroyed. Saved root bytes are hashed and rechecked by the
CSV collector. The one-segment root SHA256 is
`4a2e01c7ef0eb6d73c2206987b63a5a5d545984080d4e6160e6daa09f290134a`.
This establishes a 1.27× request-time improvement from consolidation on actual
Ethereum execution, **not another 10×**. Recursion is still 75.74% of request
time. Native original proving in the four-segment run takes 8.03 seconds;
optimizing that phase alone cannot deliver the required end-to-end gain.

The first attempt spent 145.04 seconds and reached a 36.70 GB RSS peak before
the detached receiver rejected `V7MemoryResourceLimit`: the benchmark admitted
larger source RAM geometry but passed default small receiver limits. A shared,
externally selected benchmark resource policy now feeds source generation and
all direct/shared/bounded receivers. It changes resource admission only, not
constraints, transcript, count bounds or production defaults. The failed
attempt and its parent-stage profile remain recorded separately.

Two encoding/producer changes are implemented separately from those baseline
measurements:

* `block_execution_compact_ram_bridge_v1.zig` uses 29 instead of 48 physical
  integer witness columns for explicitly admitted RAM-only, 32-bit-clock spans.
  It reconstructs high bytes and constant carries as polynomials and evaluates
  every original integer equation, plus a RAM-space constraint. It preserves
  all 21 transition limbs. It passed 150 imported ReleaseSafe tests, followed
  by five focused tests covering byte-address inputs, inactive rows, extension
  points, altered cells, out-of-range clocks and statement identity. **It is
  not selected by a product or recursively qualified yet.**
* `block_v7_native_projection_batch_v1.zig` constructs each component's typed
  lookup entries once per row rather than once per physical projection. It
  emits the same ordered claims and prefix columns, uses bounded row tiles and
  exclusive group ownership across CPU workers, and transfers output ownership
  without copying columns. All seventeen opcode families, clock entries and
  q2/q3 rosters match the legacy generator. A genuine native+access proof gate
  independently verifies both paths and compares complete proof bytes and every
  claim after producer destruction. The unchanged protocol keeps the legacy
  path selectable; the new path remains opt-in pending larger canonical runs.

The architectural priority remains shared original PCS/FRI and smaller
recursive verification, including nonterminal window support in the finite
union path. The compact bridge and row-fused producer must not be substituted
for that larger goal.

### Shared-PCS window memory port

`block_v7_union_memory_family_v1.zig` now supplies both terminal and explicit
nonterminal union contexts. The old terminal module is a compatibility facade;
there is one ownership implementation. Both contexts reuse the original
memory mode's RAM specification and AIR owner, so nonterminal contexts retain
all 31 interaction planes, the state-delta relation and nonhalt constants.
They do not synthesize terminal reads or reinterpret terminal claims.

The initial context gates passed 12 ReleaseSafe tests. The assembled streaming
producer now goes further: one genuine nonterminal union STARK closes every
provider, matches all physical claims from the separate-original oracle, and
passes fresh serialized verification after producer destruction (13 tests,
including sparse initialization). The terminal all-provider oracle remains
green (11 tests). See the assembled qualification record below.

The remaining join is recursive: compile the shared original into an
independently derived recursive key, authenticate the complete window/public
relation in-circuit, and close multiple joined chunks in one root. Canonical
128K/512K/1M original-union measurements precede larger chunk sizing. The first
128K canonical attempt rejected an unsupported q1-to-q3 heterogeneous lift;
the lower-level evaluator already supports genuine two-step extension, and
the placement adapter is being qualified against that workload. This failed
attempt is retained and is not an accepted benchmark.

The compact RAM bridge is another explicit layout migration: any integration
must derive byte-range requests from the expanded witness and preserve their
original obligations. Nineteen fewer witness columns do not authorize silently
dropping range claims, changing natural counts or accepting a legacy key.

## Complete-block encoding census

The [ledger](../../../vectors/reports/riscv-frontend-work-ledger-20261029/ledger.json)
combines all 266 execution-census segments with widths exported from the
current typed authorities. The [family CSV](../../../vectors/reports/riscv-frontend-work-ledger-20261029/native-families.csv)
retains the complete distribution. This is a deterministic encoding model,
not a recorded full-block proof layout. It excludes V7 physical projection and
access interactions, clock infrastructure, providers, PCS expansion and
recursion. In particular, compatibility interaction columns must not be added
to a V7 total as though they were its actual physical layout.

| Native encoding work | Count |
| --- | ---: |
| Main cells at present widths and 65,536-row shards | 6,625,111,062 |
| Main cells without padding | 5,838,661,634 |
| Typed component shards across execution partitions | 5,465 |
| Ordered compatibility lookup requests | 2,206,968,341 |
| Load/store main cells | 2,933,593,600 (44.28%) |
| Basic immediate ALU main cells | 1,121,003,520 (16.92%) |
| Basic register ALU main cells | 790,982,080 (11.94%) |

These three families account for 73.14% of native main area. The raw main
values alone represent 26.50 GB of aggregate block work, **not peak memory**.
Removing register events from global RAM proving does not remove the register
values, prior clocks, byte bounds and access projections still carried by
opcode rows. This distinguishes the next encoding problem from the already
modeled 10.14× global-memory-area improvement.

Two tempting changes have limited or adverse modeled effects:

* Raising the shard cap to 524,288 without coalescing executions increases main
  area from 6.63 to 7.90 billion cells. Fewer components can cost more work.
* Coalescing four original partitions at the existing cap reduces shards from
  5,465 to 2,846 and main cells to 6.16 billion. Sixteen partitions give 2,287
  shards and 5.94 billion cells. The whole-block grouping reaches 5.85 billion,
  but requires 2,133 native components in one partition, exceeding the present
  256-component admission limit. These are counterfactuals, not admitted proofs.

Existing register-read and load/store selector alias candidates would save
453,220,112 main cells (6.84%) at the original partition. They are explicitly
non-production programs. Integrating those candidates is useful but cannot be
represented as the next 10× architecture.

## Selected architectural work

1. **Replace repeated register access representation.** Design one register
   relation whose constrained read/write tuples carry the required value and
   clock semantics once. Opcode semantic rows reference this relation rather
   than repeatedly materializing equivalent before/after byte arrays and
   re-proving their integer interpretation in companion access rows. Preserve
   x0, aliased operands, conditional writes, all 32 endpoint values, ordered
   subclocks and segment continuity. A value-only multiset is insufficient.
   Compare total main, witness, interaction and quotient cells plus recursive
   openings; moving columns between AIRs is not a saving.
2. **Share one PCS for compatible relations before recursion.** Independent
   component heights remain independent. Native, access and caller equations
   should share commitments/composition/FRI where their commitment phases and
   public challenge schedule permit it. V7 already has joint-original and
   union implementations; finish those joins rather than adding a wrapper per
   proof family. Count every committed tree, physical claim, OODS value and
   Merkle path, not just proof files. Avoid padding proof counts.
3. **Close terminal execution without re-proving VM memory images.** The V7
   ELF-initialization/sorted-RAM/terminal-output theorem is the selected route;
   it must retain all native and precompile transition bindings. Its removal
   of the old RAW/FOLD memory-image work must reach the actual block root.
   In the older complete fixture those children accounted for 75.68% of
   recursive arithmetic rows. This is not a new saving to multiply again if
   a V7 benchmark already excludes them. Retain the old checkpoint theorem as
   a different statement, not a mode that silently drops its roots.
4. **Use larger proved operations where the execution actually spends work.**
   Keccak and secp256k1 recovery are already precompiled: this block contains
   32,835 and 78 calls respectively. Merely enabling those precompiles again
   cannot explain a new gain. Attribute their memory bridge, range requests,
   arithmetic witness and recursive verification separately. Candidate bulk
   copy/zero/word operations require an authenticated instruction sequence and
   exact RAM effects, or a separately versioned guest/statement. Never replace
   arbitrary guest loops with unchecked host results.
5. **Retain physical plans and construct wide witnesses once.** V7 already
   durably stages first rounds; verify the current restore/prove path before
   reusing a V5 duplicate-work diagnosis. Reuse immutable code/layout state
   across distinct requests, while retaining request-specific statement,
   transcript and witness identity. All proof numerical stages stay on GPU.

Bounds matter at block scale: the combined lookup count is above the M31
characteristic, but belongs to different relations. Establish each relation's
natural-count bound separately; neither treating all requests as one relation
nor relying on modular cancellation is valid.

## Concrete runtime change in this pass

The CPU access generator already batch-inverts denominators, while
`resident_native_access_interaction_v1.cuh` performed seventeen QM31 inversions
per active row. Its CUDA row body now uses inclusive products and a backward
pass: **one inversion and 48 QM31 multiplications**, with the same existing
seventeen-element local array. The denominator input is reread during the
backward pass. No arena plane, allocation, launch, transcript datum or host
numerical work is added. Canonical checks, active zero-denominator rejection,
inactive zero semantics and sticky errors remain.

The actual row body passes 950 CPU arithmetic differential cases under address
and undefined-behavior sanitizers, including every denominator/limb mutation,
active/inactive zero denominators, malformed activity, output guards and launch
tails. The scalar oracle uses the backend's original field inverse. This
qualifies arithmetic parity only. **No CUDA timing, occupancy improvement,
full proof parity or block speedup is claimed.** Device register/local-memory
cost and unchanged whole-proof bytes remain required acceptance gates.

## GPU execution design brief

* Families/device: all native opcodes and infrastructure, RAM, program/lookup,
  Keccak/recovery callers and recursive closure; H200 for block qualification.
* Oracle/boundary: independently pinned original statement and verifier; raw
  admitted records to one terminal proof, followed by separately timed fresh
  verification. No numerical CPU fallback or intermediate readback.
* Barriers: all first commitments precede global challenge derivation; each
  physical interaction claim is absorbed before the corresponding interaction
  commitment. Composition, OODS, DEEP and FRI retain their actual dependencies.
* Lifetimes: immutable modules/tables are runtime-owned; raw input, witness and
  transcript are request-owned; interaction scratch is reused only after its
  last consumer. The inversion change adds no arena resource and no stream.
* Cache identity: existing exact emitted-code identity is separate from full
  statement identity. New encoding/PCS protocols require new admitted keys.
* Passes/transfers: the inversion change trades one reread of 16 denominator
  values per active row for 16 fewer inversions; no new GPU transfer or kernel.
* Scheduling: parallel first rounds and component work across GPUs, a narrow
  authenticated global barrier, then batched recursive reduction. Do not
  divide full latency by GPU count without measuring this critical path.
* Failure: any malformed input, wrong code/key, count overflow, missing
  provider or nonzero closure residual rejects; no compatibility fallback.
* Acceptance: exact scalar/typed parity first, then GPU original verification
  and byte parity, then idle-host repeated full-family and block measurements.

The decisive artifact is one block-wide work ledger containing **actual**
component/tree geometries, all provider work, commitment passes, recursive
rows, device peaks and critical-path times. Until that exists, neither these
cell counts nor isolated kernel factors justify a seconds-per-block claim.

## Reproduction

Export metadata with `STWO_RISCV_ENCODING_CENSUS_OUTPUT` set to a new file:

```sh
python3 scripts/zig_protocol_test.py src/riscv_frontend_encoding_census.zig \
  -OReleaseSafe --test-filter 'export typed RISC-V encoding work metadata'
python3 scripts/riscv_frontend_work_ledger.py \
  --census vectors/reports/v7-runpod-gpu-20261029/full-execution-census \
  --metadata "$STWO_RISCV_ENCODING_CENSUS_OUTPUT" --output /path/to/new-ledger
python3 -m unittest scripts.tests.test_riscv_frontend_work_ledger \
  scripts.tests.test_riscv_native_access_batch_inverse
```

The output preserves the compiled encoding metadata and hashes its census
inputs. It needs no GPU and never admits or verifies a proof.

## Shared original window proof: first assembled qualification (2026-10-29)

The streaming window driver now exposes its complete first-round epoch before
separate original proofs are generated. `block_v7_window_union_producer_v1`
restores those staged native/caller commitments and joins them with the live
ROM, compact lookup, and state-delta memory providers in one original STARK.
It adopts the committed private trees; it does not first create and then
combine separately proved source artifacts. The old publication path remains
available as an independent oracle.

Window scope and terminal scope use the same implementations with distinct
protocol tags and wire magic (`B7WUN001` versus unchanged `B7MUN001`). The
window scope independently clones the externally admitted endpoints, derives
initialization from the selected complete incoming state, and closes the
nonterminal state delta. It cannot be reinterpreted as terminal execution.
Every original physical claim is still absorbed into the transcript.

ReleaseSafe qualification: the initial assembled window test passed 12 tests.
The stronger detached gate passed 13 tests, including genuine native/Keccak
execution, sparse initialization, identical physical claims and verified
summary against the separate-original oracle, serialized-byte verification
after the producer proof was destroyed, rejection of a truncated artifact and
a changed envelope, and a compensated pair of forged RAM claims. The existing
terminal multi-union all-provider oracle passed 11 tests. These are tiny
correctness fixtures, not throughput evidence.

Remaining: a complete recursive adapter and closure for the joined original
proof. Canonical retained-window measurements and detached metadata loading
are now recorded below.
A successful original union is not yet a complete recursive root or a full
Ethereum block proof. Its end-to-end gain is not assumed from the reduction
in the number of original STARKs.

### Canonical shared-original measurements

Saved proof bytes and the checked invocation reports are indexed in
`vectors/reports/riscv-cpu-architecture-20261029/shared-original-window-times.csv`.
All observations below use eight CPU workers, q70/PoW26, independently pinned
complete endpoints and sparse initialization. Each is a single diagnostic,
not a ranked median. These are **original proofs, not recursive roots**.

| Instructions | Native layout | Request through fresh verification | Charged peak | Original STARKs |
| ---: | --- | ---: | ---: | ---: |
| 131,072 | q3 canonical | 6.94 s | 2.20 GB | 1 |
| 1,048,576 | q3 canonical | 23.65 s | 6.68 GB | 1 |
| 1,048,576 | degree-bounded q2 | 21.66 s | 5.88 GB | 1 |
| 4,194,304 | degree-bounded q2 | 101.95 s | 20.43 GB | 1 |

Original proving throughput has not improved by an order of magnitude: the
prior 1M source phase already took about 23 seconds. The key architectural
change is that recursion can now verify **one** original rather than four.
That recursive reduction is still being assembled and must be measured
before claiming an end-to-end speedup over the old 110–112 second root.

The 1M q2 shared-original core takes 5.21 seconds, including 4.01 seconds of
composition evaluation. Preparing provider interactions takes 3.56 seconds;
memory alone is 2.05 seconds. These inclusive stage times are in the saved
`native-stage-profile.json`; do not add parents to children. Fresh detached
verification takes 3.33 seconds. Larger source chunks and smaller recursive
verification remain the priority, rather than optimizing a small FRI stage.

The joined recursion adapter now has independent multi-tree PCS geometry,
owned verifier captures, bounded public metadata transport and an exact
epoch/union transcript recorder under qualification. The original union
uses two hash streams; the existing constrained reset opcode preserves both
without changing the original proof protocol. The native/caller/PAGE APIs
keep their old fixed-count gates; separate bounded union APIs are explicit.
The joined composition graph now passes genuine native RAM, Keccak and sparse
Keccak fixtures using the original equation kernels and a single Horner
accumulator. The 14-test all-family qualification log and frozen source manifest
are retained under the campaign's `qualification/` directory. Public wire
closure and independently compiled parent keys remain required before any
recursive union proof is publishable.

The 4M original saves 7,734,614 proof bytes and 5,981,134 public metadata bytes.
Its producer proof and metadata are destroyed before reconstruction and fresh
verification. A separate process reloads these artifacts using only the pinned
ELF and complete endpoint snapshots: 10.44 seconds total, 10.38 seconds fresh
verification, 1.90 GB peak process footprint (2.18 GB charged allocation peak).
This is verification-only evidence, not another proving measurement. The
successful original proof hash is
`3a994d006561f62197c47f38ad961ab151e9982cd31dc2bdaa5e6b2efdac353e`.

At 4M, source collection costs 12.61 seconds, provider first commitments 36.54
seconds, and the shared proof consumer 41.61 seconds. These are inclusive
instrumented stages; the full 101.95-second request also includes setup,
transport, reconstruction and verification. Provider construction and repeated
physical memory work therefore remain architectural targets. No complete
Ethereum block or skipped execution prefix has been proved by this window.


### Shared recursive root: first canonical end-to-end result

`native-131072-window-union-recursive` proves a genuine 131,072-instruction
Ethereum window using one original shared STARK and one recursive STARK at
q70/PoW26, eight CPU workers. The original proof, verified capture and parent
rows are destroyed before the fresh receiver reconstructs its own fixed key,
verifies the root bytes and closes all public execution relations. Root SHA256:
`20e37f8d6d0f487a12c9c940a0055f571f8b41ca22df5ade502f1c32eb3c24e7`.
The 938,880-byte root requires the public metadata and finite physical-claim
sidecar; it is not a standalone full-Ethereum-block theorem. The skipped prefix
remains unproved.

| Measured stage | Seconds |
| --- | ---: |
| Source collection and original shared STARK | 4.88 |
| Recursive fixed compiler | 15.92 |
| Fixed commitment | 1.07 |
| Recursive witness preparation | 18.74 |
| Recursive STARK proof | 9.21 |
| Fresh recursive verification including independent key reconstruction | 22.68 |
| Full request through fresh verification | 76.29 |

Charged allocation peak is 5.77 GB; process peak footprint is 5.25 GB. Raw
nanoseconds and proof hash are in `shared-recursive-window-times.csv`. This is a
single diagnostic observation, not a median or a full-block extrapolation.

The earlier separate-original 131K root spent 27.90 seconds in its recursive
STARK proof and retained 5.10 GB of parent rows, versus 9.21 seconds and 1.92 GB
with the shared original. Its full request was 57.67 seconds, but its final
verification used the independently constructed expected key rather than
rebuilding that key a second time. The new 76.29-second request includes 22.68
seconds of fresh key reconstruction and verification. These full timings have
different setup boundaries; the new path is not an end-to-end speedup yet.
Native q3/row-fused and q2 layouts also differ between these diagnostic cases.

The next architectural change is an immutable admitted compiler owner. It
reconstructs source policy once and reuses exact composition, DEEP, FRI and
arithmetic programs through fixed setup and live preparation. The receiver
still creates its own admitted compiler from external metadata and claims.
Reference row/key/proof parity and hostile compensated physical claims are
required gates; a cached digest alone must never nominate a verifier key.

### Full-block memory work-removal census

The actual retained 139,214,856-instruction execution has 57,876,727 RAM accesses.
Only 214,658 hit non-writable ELF segments and 2,162,853 hit the input region;
these account for about 4.1% of RAM accesses. There were no observed store
instructions into either candidate region. ELF flags are not current machine
permissions, so these counts do not authorize dropping events from a proof.
Stack accesses account for 24,306,967 events (42.0%).

Grouping exact touched addresses into 4M-instruction cohorts gives 5,444,030
address/cohort pairs, or 10.63x fewer records than per-access global memory.
8M cohorts give 5,255,628 pairs (11.01x fewer); the whole execution touches
3,142,901 distinct addresses. This motivates a local-RAM-chain protocol with
unique, ordered per-cohort endpoints and globally linked values. Native and
caller consume/emit tuples, byte bounds, strict clock advancement, exact
address classification, cohort identity and no duplicate/forked endpoint rows
must all remain constrained. No product route currently selects that new
protocol, and these counts are not measured proof speedups.

The census is execution-only, with independently pinned ELF/input/output and
the complete expected 139,214,856 cycles. Compilation ran concurrently with
some census observations; their wall times are diagnostic, not isolated proving
benchmarks. Raw per-segment records and invocation provenance are retained in
`full-execution-memory-classes` and `full-execution-memory-cohorts`. The latter's
`unique_ram_keys_segment=0` field is an instrumentation error (the map was
transferred into the session); only its separately collected 4M/8M/full-block
sets are used above. A corrected census is being collected separately.


### Qualified compiler reuse and increasing-window closure

The immutable compiler capsule now passes complete recursive proof-byte parity
against the reconstructing reference, including rejection of compensated forged
physical memory claims. The fresh receiver independently reconstructs its own
compiler and key. No caller-supplied compiler digest acts as an admission key.

| Declared window | Full request / fresh verification (s) | Recursive STARK (s) | Charged peak (GB) |
| --- | ---: | ---: | ---: |
| 131,072, reconstructing compiler | 76.288 | 9.206 | 5.772 |
| 131,072, admitted compiler capsule | 40.883 | 9.151 | 5.697 |
| 1,048,576, admitted compiler capsule | 75.064 | 15.716 | 8.987 |
| 4,194,304, four native components | 207.849 | 34.490 | 19.459 |
| 4,194,304, one native component | 193.256 | 25.659 | 20.832 |

These are single isolated observations, not ranked medians. All use canonical
70 queries / 26 PoW bits and eight CPU workers. All are declared nonterminal
windows with independently pinned complete snapshots, not complete blocks or
proofs of the skipped prefix. Full request includes original proving, recursive
setup and proving, and fresh key reconstruction and verification. Actual STARK
phase time is reported separately so setup removal cannot masquerade as faster
STARK arithmetic.

The 4M RAM planner changes 53 components into four: 11,236 RAM opening columns
become 848, at about 7.2% more padded RAM rows. This required implementing the
nonterminal tiled RAM quotient with both state-delta planes. Random scalar /
packed folded-equation parity covers all 163 constraints; the canonical 4M
original and recursive proofs also pass fresh verification. The earlier 4M
out-of-memory and unsupported-tile attempts remain recorded as failures.

Coalescing four native components into one reduces recursive STARK time by
25.6%, but reduces the full request only 7.0% and increases charged peak. This
is evidence against treating native coalescing alone as the next order-of-
magnitude improvement. Provider preparation remains about 37 seconds, and the
original source phase becomes slightly slower with one large native component.

The corrected full-block execution census is in
`full-execution-memory-cohorts-stream`: the sum of unique RAM keys per 524K
segment is 6,288,382. Its independent 4M/8M/full-execution sets reproduce the
counts above. It records all 266 execution segments and the expected final
output, but it is not a proof. Endpoint-only RAM remains an inactive prototype:
its component equations and tuple/range constraints are being qualified before
any source/global relation integration or performance claim.

The machine-readable raw stage data and artifact hashes are in
`vectors/reports/riscv-cpu-architecture-20261029/shared-recursive-window-times.csv`.


The genuine 131,072-instruction Keccak-heavy window (890 calls, one native and
one batched caller) also reaches a fresh recursive root at canonical security:
105.070 seconds full request, 30.865 seconds source phase,
25.563 seconds recursive STARK,
14.769 GB charged peak. The original proof and public metadata are persisted
before recursive preparation. Root SHA-256:
`3438f2a60434e888740bde94905dcc88ca1acab5f1981185199e8108d20574cc`.


### Memory generation and quadratic census diagnosis

The batched independent-plane interaction generator preserves the complete
4M source proof and recursive root bytes (root `313bb0cd...728f37`). Its isolated
whole request is 203.808 s versus 207.849 s; source consumer time falls from
36.441 s to 30.567 s. This is a modest whole-path observation, not a claimed
order-of-magnitude improvement. Exact committed matrices/physical sums match
the scalar reference across chunk boundaries and singular denominators remain
rejected. Existing root/capsule parity gates also pass.

The new provider clocks isolate 35.913 s in `Witness.Owner.init`, out of
36.760 s for memory first-round preparation. Fixed and main commitments take
0.108 s and 0.294 s respectively. The main cause under test is an accidental
quadratic census: after binary lookup of the owning initial interval, each
first-touch row linearly searched all intervals for that same index. Saved 4M
selection implies 128,014,534,808 equality comparisons. Returning the binary
lookup index removes that scan; the binary comparison upper bound is 9,613,392.
Those are implied operation counts, not measured speedups. The same candidate
hoists repeated window-policy validation and reuses already retained fixed
polynomials for the merged commitment, while preserving exact roots and
resource leases. The isolated end-to-end measurement is pending.

Private source trees were already adopted without recommitment. Eliminating
repeated private-tree FFTs is therefore not an additional opportunity in this
path. A future unified-first-commit protocol can reduce root/path multiplicity,
but it must bind a new descriptor roster and column offsets explicitly; its
benefit must not be estimated by multiplying root-count reduction alone.


The indexed census + validation-hoist candidate is now canonical-proof-qualified
at 4M: 169.920 s full request, 48.945 s source phase, 19.507 GB charged peak.
Witness initialization falls from 35.913 s to 2.641 s (13.60x), with exact original
and recursive proof bytes preserved. Consumer time is 30.245 s and recursive
production remains 85.906 s. This is 1.20x end-to-end versus the batched reference,
not a 13.6x whole-prover speedup.

The fixed reuse helper's live telemetry reports `fixed_polynomials_reused=false`:
legacy native checkpoints intentionally discard coefficients. Thus the measured
candidate gain must NOT be attributed to successful merged-fixed reuse. A bounded
resident source path is being developed instead of misreporting fallback as reuse.

New inactive endpoint components now have real original-STARK evidence: a native
store/load example proves direct typed AIR and the complete restored RAM-clock
projection roster without the legacy WORD access sidecar, destroys producer data,
and passes fresh fixed-key verification. The endpoint collector/range provider,
caller RAM projection and exact finite descriptor have separate focused gates.
The no-sidecar proof is OPEN until endpoint AIR, range, ROM, tables and global
coarse transitions are joined. It is not a complete window or block proof.


### Clean endpoint original: real 4M window

The new native-only endpoint path now proves the genuine 4,194,304-instruction
window at canonical 70-query / 26-PoW security with eight CPU workers. It
constructs no per-access WORD witness or legacy checkpoint, releases the runner
before proving, and joins native execution, all endpoint/range constraints, ROM,
lookups and global sorted RAM into one original STARK. Per-access halt guards
remain in the native AIR: endpoint equality alone would permit an intermediate
halt write followed by clearing it.

| Boundary | Seconds |
| --- | ---: |
| Original STARK production, including commitments/interactions/admission | 24.989 |
| Core STARK within original production | 15.078 |
| Source driver before its fresh typed verification | 30.120 |
| Source driver including fresh typed verification | 36.152 |
| Full diagnostic including publication and a second fresh byte verification | 44.923 |

Charged peak is 16.907 GB; the proof envelope is 2,978,836 bytes. Logical RAM
accesses fall from 1,710,496 events to 505,967 per-address endpoints. Global RAM
uses 262,144 packed rows. The reported native main census remains 212,813,416
cells, so native frontend cost is now a major remaining architectural target.
This census precedes the small halt-guard tail; it is not a complete all-tree
cell count.

The original proof is destroyed before byte-level metadata admission and fresh
verification. The published envelope SHA-256 is
`a2a0fc02064c7abfa063188fb5de6834f7a9b792bce49811c2f9b418f972f79f`.
The frozen executable and unchanged-source manifest are retained in the external
artifact store; the observation records their hashes. The raw conservative
`semantics_qualified=false` marker is preserved unchanged, despite the separately
qualified mandatory native halt guard. It must not be silently rewritten into
a broader qualification claim.

This is an ORIGINAL proof of a declared nonterminal window, not an Ethereum
block or skipped-prefix proof. The 44.923-second diagnostic is not comparable
to the older 169.920-second original-plus-recursive-root request. For the source
phase alone, 48.945 versus 30.120 seconds is approximately 1.63x, not 10x.

The new endpoint recursive path has separately passed canonical original-plus-
parent qualification on a four-instruction example: complete local/global
ledger closure is inside the parent composition DAG, with original proof and
metadata erased before an independently reconstructed receiving key verifies
the root. That small gate establishes equations/ownership, not 4M performance.
Its canonical artifacts live under `qualification/new-endpoint-recursion-q70`.

The production architecture being assembled separates local cohort proving
from a late narrow global-memory bridge. Cohorts retain the exact 23-column
endpoint main commitment; the bridge reopens that commitment under one shared
global challenge. Thus local proofs can run independently without carrying full
intermediate RAM snapshots or proving the wide execution witness again. Local
endpoint claims drawn under different epochs cannot simply be added together.

### CPU architecture campaign continuation, 2026-10-30

The late-memory architecture has now qualified original bundles at 4M, 8M and
16M real Ethereum instruction windows. The 16M/32-cohort compact-global run takes
182.233 seconds including fresh original verification and peaks at 3.738 GB
charged memory. Independent disk-only receiving after producer destruction
reconstructs and verifies all 34 originals using externally pinned snapshots.

A bounded two-job CPU pipeline then proves the same 4M compact-global window in
34.385 seconds versus 48.066 seconds sequentially, using 4.737 rather than 2.933
GB. Every one of the ten original proof files is byte-identical between runs.
The measured original-production gain composes with the earlier compact-global
memory reduction; it is not a complete-block or complete-recursive-root result.

The first complete single-DAG recursive root joins Local11 verifier bodies, the
late bridge and Compact7 global RAM inside one STARK, with PC/register adjacency,
endpoint-root identity and global-transition closure constrained in the graph.
Canonical q70/PoW26 qualification and independent byte-only receiving pass for
an eight-instruction fixture; production defaults remain disabled. The next
qualification target is the saved real 4M bundle, without repeating execution
or source proving.

Sparse ELF-authenticated ROM has also passed canonical full-local original
qualification and legacy joint-regression tests. The retained 146-PC cohort
needs 256 ROM rows versus 1,048,576 in the legacy complete table. Actual producer
integration and real-window timings are required before claiming a full-stack
speedup from that row reduction.

See `endpoint-cohort-late-bridge-20261030.md` for the explicit proof boundaries,
measurement table, qualification artifacts, memory accounting and remaining
caller/terminal/block obligations. Machine-readable results live in
`vectors/reports/riscv-cpu-architecture-20261029/local-global-window-times.csv`.

### Current qualified boundary and dominant remaining cost

The actual saved 4M/eight-local sparse-ROM bundle now closes in one q70/26 root,
with independently rebuilt receiving keys and zero snapshot-delta public ports.
Saved-original-to-root time is 290.826 seconds, including 186.964 seconds parent
proving and 27.575 seconds fresh receiving; charged peak is 49.241 decimal GB,
under the unchanged 48 GiB budget. The 4M original bundle separately takes
23.224 seconds, so their arithmetic sum is 314.050 seconds, not a single measured
invocation. The 16M/80.865-second observation still covers originals only.

Actual caller-containing execution is qualified through a 131,072-instruction
window with 890 real Keccak calls: one mixed original verifies at q70/26 in
21.311 seconds complete and 3.009 GB charged peak. Global RAM/root remain open
for that benchmark. Small mixed originals have also closed through the same late
bridge and compact global memory with file-only receiving. A genuine recovery
write-one/clear-zero halt attack is rejected by the original AIR despite zero
initial/final halt endpoints; the ordinary-RAM control proves successfully.

The largest next architectural bets are bounded shared-provider group originals
(reduce the original-proof roster before recursion) and DirectRAMclockV3 larger
single originals (remove RAM clock filler rows while preserving order, register
custody and per-access halt constraints). Proof-count reductions are not claimed
as equal reductions in Merkle input bytes or end-to-end latency.

For unambiguous timing boundaries, allocator/thread policies, scopes and the
current table, see `vectors/reports/riscv-cpu-architecture-20261029/MEASUREMENTS.md`.
