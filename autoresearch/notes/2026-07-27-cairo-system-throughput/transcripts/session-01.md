# Session 01: portfolio baseline and stage-placement diagnosis

## Request

Apply the repository's high-performance engineering and autoresearch process to
raise Zig SIMD and Zig Metal Cairo proof performance across a broad collection
of real programs. Retain notes and transcripts, and reject benchmark-specific
fast paths.

## Initial decision

The current autoresearch manifest explicitly says Cairo is a future frontend
and excludes Cairo frontend paths from its editable surface. Treating a Cairo
change as a Native-board promotion would be false evidence. This effort
therefore uses the same profiling, paired-comparison, oracle, transcript, and
portfolio disciplines on a dependent research branch, but does not claim a
current ledger promotion.

The objective is the seven-workload geometric mean, not the fastest individual
row. All-opcodes, Poseidon, Pedersen, arithmetic, memory, and recurrence-heavy
programs exercise different component mixes. Each row remains a regression
guard even if only the aggregate objective improves.

## Existing evidence

The pinned three-way baseline uses three measured samples per lane in rotated
order. Every Zig CPU/Metal proof is byte-identical and independently accepted
by the pinned Rust verifier. The raw result digest is
`22c5e2aa4f1414b2eabeb3ff38c282beb8ba3132f95457c7f62e69e36c97584f`.

The large Metal arithmetic sample attributes substantially more host samples to
AIR quotient evaluation, interaction collection, packed QM31 multiplication,
Blake2s, Pedersen table work, and witness execution than to Metal driver waits.
The product capability contract independently states the same architecture:
execution is a Cairo VM sidecar, witness is host, AIR constraint evaluation is
host SIMD, and only commitment/LDE/quotient/FRI is Metal.

This falsifies the tempting first hypothesis that another isolated PCS shader
fusion should be the primary Cairo optimization. The first architecture target
must instead be shared witness/AIR work and the ownership boundary that prevents
those stages from becoming resident. Metal kernel tuning remains valid only
after device work becomes a material fraction of full request latency.

## Landed predecessor improvements

Commit `40d01353` changed the Rust VM adapter from pretty, effectively
unbuffered JSON output to compact JSON through a 4 MiB buffered writer with
explicit flush and sync. A 285 MB handoff fell from roughly 142 seconds to
0.88 seconds with unchanged proof bytes.

Commit `b891c65b` executes recorded witness component row ranges through the
existing prover pool with disjoint output ownership and worker-local scratch.
Admission depends on semantic operations rather than workload identity.
Interleaved three-sample A/B evidence showed Pedersen at `0.671x`, Poseidon at
`0.988x`, and all-opcodes at `0.999x`, with exact proof parity.

## Next hypothesis

Break the large CPU and Metal profiles down by common component family and
full-trace pass. Look first for:

1. redundant initialization or materialization in recorded witness programs;
2. serial interaction/table passes with independent row ranges;
3. repeated packed-field conversions or collector capture passes in host AIR
   evaluation;
4. immutable preprocessed tables reconstructed for every proof; and
5. an existing generic backend contract that can carry structurally admitted
   witness/AIR work onto Metal without introducing benchmark-specific kernels.

Any candidate must predict which portfolio rows move and why before it is
implemented.

## Hypothesis 1: transfer base-column ownership

Inspection found that `component_executor` allocates and fills canonical `u32`
output columns. `base_trace.Collector.capture` then allocates the same number
of `M31` values, converts every canonical word, and leaves the executor buffers
to be freed immediately after the observer returns. `M31` is exactly one
canonical `u32` with identical size and alignment.

The candidate allocates witness output columns independently and transfers
their ownership into `ColumnEvaluation` at the observer boundary. This retains
the commitment scheme's existing per-column ownership model while deleting one
full base-trace allocation, traversal, conversion, and free cycle.

Prediction:

- arithmetic-2m and memory-7m should improve most because their live base trees
  contain the most generated cells;
- recurrence workloads should improve modestly;
- small hash/opcode workloads may be neutral because fixed tables and proof
  setup dominate;
- both CPU and Metal should move in the same direction because this boundary
  precedes backend commitment; and
- proof bytes, geometry, producer words, lookup words, interaction traces, and
  backend telemetry must remain unchanged.

Falsifiers are a proof mismatch, any ownership/leak failure, a portfolio
regression outside noise, or a Metal-only result that indicates accidental
coupling rather than shared handoff removal.

### Result: rejected

The focused frontend gate passed and all compared proof hashes remained exact.
Interleaved A-B-B-A proof timings were:

- arithmetic-2m baseline `9329.312 / 9162.745 ms`, candidate
  `9176.001 / 9127.432 ms`;
- memory-7m baseline `21006.991 / 21125.206 ms`, candidate
  `21003.949 / 20947.448 ms`; and
- an all-opcodes smoke was also effectively neutral.

An outer process measurement on arithmetic-2m reported baseline and candidate
maximum RSS of `5,299,159,040` and `5,298,880,512` bytes respectively. Later
prover stages dominate the lifetime peak, so the candidate did not materially
improve either time or memory. The implementation was completely removed.

## Hypothesis 2: parallel interaction inversion batches

The large profile attributes roughly as many host samples to interaction
collection as to AIR evaluation. Production construction calls
`recorded_interaction.materializeTrace` independently for each component. Each
component processes fixed 32K-row batches serially. A batch performs relation
word construction, a large batch inversion, cumulative-column writes, and a
local claimed-sum reduction.

Those batches have disjoint destination rows and independent inversion scratch.
Only their claimed sums must be combined. The candidate uses the existing
bounded prover pool, assigns contiguous groups of complete 32K batches, creates
worker-local `Reference` scratch, and reduces worker sums in worker-index order.
The final circle-order LogUp prefix scan remains serial because it has a true
cross-row dependency.

Prediction:

- memory-7m and arithmetic-2m should move materially because they contain the
  largest interaction domains;
- recurrence cases should move when their dominant components exceed one
  batch;
- fixed small hash/opcode programs should remain neutral;
- CPU and Metal should improve similarly because the interaction trace is
  currently a host stage in both products; and
- exact proof bytes and claimed sums must remain unchanged.

The implementation is generic over authenticated relation descriptors and
source views. It has no workload, component-name, or size-specific semantic
path; the row threshold only amortizes scheduling and scratch allocation.

### CPU result: accepted for Metal evaluation

The focused Cairo frontend gate passed before measurement. A-B-B-A runs used
separate baseline and candidate `ReleaseFast` binaries, sequential execution,
the same canonical-small parameters, in-process verification, and no discarded
samples.

| Workload | Baseline mean ms | Candidate mean ms | Ratio | Speedup |
| --- | ---: | ---: | ---: | ---: |
| all-opcodes | 3,965.944 | 3,051.751 | 0.769489 | 1.300x |
| arithmetic 2m | 9,322.759 | 7,033.067 | 0.754398 | 1.326x |
| memory 7m | 21,297.286 | 15,355.970 | 0.721029 | 1.387x |
| Poseidon aggregator | 2,646.140 | 2,208.967 | 0.834788 | 1.198x |
| Pedersen aggregator | 5,035.496 | 4,592.651 | 0.912055 | 1.096x |
| Fibonacci 100k | 3,483.555 | 2,597.287 | 0.745585 | 1.341x |
| Factorial 100k | 5,317.483 | 4,326.557 | 0.813648 | 1.229x |

The seven-workload geometric-mean ratio is `0.790753`, or `1.265x` faster.
Every workload wins. The prediction that fixed hash/opcode cases would remain
neutral was wrong: those statements commit large implicit lookup tables even
when their VM execution is short, so their interaction domains also benefit.
Pedersen improves least because its separately optimized witness generation
and fixed-table work leave a smaller interaction share.

All four proof files for each A-B-B-A row were byte-identical:

- all-opcodes:
  `79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`;
- arithmetic 2m:
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`;
- memory 7m:
  `e3317e55a5db5a4251e04827b3d4f2ccaeb801feb6a9d2848e71ef23daced994`;
- Poseidon:
  `354eb34dcb2eafa77be3c581e91bce752eb348a22cfefa45e2841783cb431ce8`;
- Pedersen:
  `99ce64aac8281e6bcda5f9039da8b192c048ad7fba67fbe037dbd7b312c8e9ac`;
- Fibonacci 100k:
  `84215f82b4083523c0cf59d9abbfb4ef7e16f0af12f65d6451ce082b6728e746`;
- Factorial 100k:
  `1e90d44933c53ef3674dbb7b4b08e824bcd7862a30b4f8164f8df0e23838fd54`.

This is CPU evidence only. The candidate proceeds to a Metal portfolio check
and a new stage profile; it is not accepted until zero-fallback Metal behavior
and the next bottleneck are observed.

### Metal result: accepted

Metal A-B-B-A measurements retained the same authenticated AOT identity and
reported 73 to 79 dispatches with zero CPU fallbacks. All proofs matched the
CPU hashes above exactly.

| Workload | Baseline mean ms | Candidate mean ms | Ratio | Speedup |
| --- | ---: | ---: | ---: | ---: |
| all-opcodes | 7,811.286 | 6,880.365 | 0.880824 | 1.135x |
| arithmetic 2m | 10,097.585 | 8,017.695 | 0.794021 | 1.259x |
| memory 7m | 28,839.752 | 18,887.984 | 0.654929 | 1.527x |
| Poseidon aggregator | 5,697.769 | 5,039.839 | 0.884529 | 1.131x |
| Pedersen aggregator | 8,100.378 | 7,494.764 | 0.925236 | 1.081x |
| Fibonacci 100k | 4,042.069 | 3,045.920 | 0.753555 | 1.327x |
| Factorial 100k | 6,344.914 | 5,766.681 | 0.908867 | 1.100x |

The Metal geometric-mean ratio is `0.823459`, or `1.214x` faster. The long
memory row showed thermal drift in both directions, so this paired result is
diagnostic rather than a release-judge confidence interval. Its exact parity,
zero-fallback telemetry, and consistent direction across all seven rows are
sufficient to retain the structural change while later final evidence uses a
fresh controlled portfolio run.

The post-change Metal sample is
`/private/tmp/stwo-cairo-arithmetic-2m.interaction-parallel.metal.sample.txt`.
Interaction construction is now distributed across pool workers and consumes
far less calling-thread time. The dominant remaining prover stacks are Cairo
AIR domain evaluation, packed QM31 multiplication, witness execution, Blake2s,
Pedersen table construction, and the residual parallel inversion work. Metal
command-buffer waits remain a very small sampled share.

## Hypothesis 3: retain packed AIR evaluations through accumulation

The Cairo AIR interpreter evaluates four rows at a time as four coordinate
vectors. It then reconstructs four scalar `QM31` values lane by lane and calls
the scalar accumulator, which immediately decomposes each value back into the
same four coordinate columns. This representation round trip sits inside every
AIR row group and blocks direct vector stores/additions.

Add a four-lane accumulator operation to the backend-neutral host accumulator.
The fresh-column path stores each coordinate vector directly; subsequent AIR
parts load, add, and store coordinate vectors directly. The scalar operation
and all existing callers remain unchanged.

Prediction:

- AIR-heavy rows should improve on CPU and Metal;
- the gain should be broader than a single Cairo program because every
  captured Cairo AIR component uses this evaluator;
- exact proof bytes and coefficient order must remain unchanged; and
- workloads dominated by witness generation or interaction inversion may move
  less.

The candidate is rejected if the generic accumulator semantics differ between
its fresh-store and additive paths, if any proof changes, or if the portfolio
does not show a repeatable aggregate gain.

### Result: rejected

The full focused Cairo frontend gate and exact-proof checks passed. A-B-B-A
CPU screening against the committed interaction-only binary measured:

- all-opcodes baseline `4,356.036 / 4,599.830 ms`, candidate
  `4,386.058 / 4,870.662 ms`;
- arithmetic-2m baseline `9,871.079 / 9,650.907 ms`, candidate
  `9,999.498 / 10,818.389 ms`; and
- memory-7m baseline `21,633.985 / 21,723.759 ms`, candidate
  `21,672.043 / 21,962.808 ms`.

The largest row was neutral and the smaller AIR-heavier rows regressed. The
representation round trip was visible in source but was not the limiting
operation; packed QM31 multiplication remained dominant, while the generic
vector load/store path worsened the surrounding generated code. The new API
and caller were removed completely.

## Hypothesis 4: Karatsuba packed QM31 multiplication

The post-change profile names `PackedQm31.mul` as the hottest leaf in Cairo AIR
evaluation. Source comparison found a concrete algorithmic mismatch: scalar
`QM31.mul` uses Karatsuba over `CM31` and needs nine base-field products, while
the Cairo four-row SIMD implementation expands the same multiplication into
sixteen vector base-field products.

Implement the identical tower-field calculation over four-row vectors:

1. Karatsuba complex multiplication uses three vector products.
2. Quadratic-extension Karatsuba uses three complex products.
3. Multiplication by the fixed `R = 2 + i` uses additions/subtractions only.

This reduces every full packed secure-field multiplication from sixteen to
nine AdvSIMD M31 multiplies without changing the evaluator, trace layout,
accumulator, AIR program, or scheduling architecture.

Prediction:

- AIR-heavy all-opcodes and arithmetic rows should improve materially;
- memory may improve less because witness and interaction work dominate;
- the win must apply to every Cairo AIR program with secure multiplication,
  with no workload selector; and
- a table of scalar-oracle products, complete proof hashes, and the frontend
  gate must remain exact.

A neutral result would mean instruction dispatch or trace reads dominate despite
the leaf profile. Any parity difference rejects the implementation immediately.

### Result: rejected

Every proof remained exact, but A-B-B-A CPU measurements were:

- all-opcodes baseline `2,963.648 / 3,017.260 ms`, candidate
  `2,996.911 / 2,975.673 ms`;
- arithmetic-2m baseline `7,163.900 / 7,150.078 ms`, candidate
  `7,252.442 / 7,376.884 ms`; and
- memory-7m baseline `15,615.988 / 15,281.980 ms`, candidate
  `15,256.207 / 15,034.647 ms`.

All-opcodes was neutral, arithmetic regressed about 2.2%, and memory improved
about 2.0%. The reduced multiply count did not reduce the complete portfolio:
the added modular add/sub dependency chains offset the saved M5 AdvSIMD
multiplies. The schoolbook implementation was restored exactly.

## Hypothesis 5: increase interaction batch concurrency

The accepted interaction scheduler retained the pre-existing 32K-row memory
batch as its scheduling grain. That makes allocation simple, but on an
18-thread M5 a 64K interaction component exposes only two jobs and a 32K
component remains serial. The post-change sample still shows inversion workers
as a large aggregate stack while many pool threads wait.

Reduce the fixed inversion batch to 8K rows. This is a structural scheduling
parameter, not a workload selector. It exposes four jobs for 32K components and
eight for 64K components, reduces each worker's inversion scratch, and retains
contiguous ranges, deterministic reduction order, disjoint output ownership,
and the same final prefix scan.

Prediction:

- fixed-table-heavy all-opcodes, Poseidon, and Pedersen should benefit from
  better medium-component utilization;
- large arithmetic and memory components should be neutral or improve
  modestly;
- peak temporary interaction memory should not increase because per-job
  scratch falls with the batch size; and
- exact proof bytes must remain unchanged.

The candidate is rejected if added allocation/loop overhead regresses the
portfolio or if smaller batches expose allocator contention.

### Result: rejected

Exact proofs held. A-B-B-A CPU screening measured:

- all-opcodes baseline `2,782.247 / 2,810.404 ms`, candidate
  `2,765.613 / 2,762.766 ms`;
- arithmetic-2m baseline `6,871.652 / 7,087.500 ms`, candidate
  `6,762.062 / 6,921.876 ms`; and
- memory-7m baseline `15,113.611 / 21,132.169 ms`, candidate
  `17,943.271 / 20,888.614 ms`.

The medium rows improved only 1-2%. The long row's strong thermal drift makes
its exact ratio noisy, but the candidate occupied more of the middle ABBA
schedule and provided no evidence of a system win. Extra small-batch allocator
and scheduling pressure is not justified by the minor medium-case gain. The
32K grain was restored.

## Hypothesis 6: packed QM31 batch inversion

Interaction traces batch-invert millions of full secure-field denominators.
The generic striped inversion advances independent chains, but each `QM31`
multiply still executes scalar field operations. The existing CM31 path in
`fields/mod.zig` already demonstrates the correct architecture: transpose
several field elements into AdvSIMD coordinate vectors and advance four
independent chains per vector multiplication.

Add the corresponding QM31 path for AArch64. Four adjacent secure-field values
become four coordinate vectors. QM31 Karatsuba then performs nine vector M31
products for four independent multiplications, instead of thirty-six scalar
products. Reuse the existing 8/16/32-chain Montgomery schedule and keep the
generic implementation as the fallback on every other architecture and
non-aligned length.

Prediction:

- every large Cairo interaction component should improve on CPU and Metal;
- larger arithmetic and memory traces should benefit most;
- the optimization is core field infrastructure and is not selected by
  frontend, workload, label, or benchmark size;
- the only algorithmic change is exact field multiplication inside
  Montgomery's batch-inversion identity; and
- randomized scalar differential tests plus exact complete proofs must pass.

The candidate is rejected for any scalar differential mismatch, proof change,
or portfolio regression.

### CPU result: accepted for width tuning and Metal evaluation

The 64-value randomized scalar differential and all existing field tests pass.
Every complete proof remained exact. A-B-B-A CPU results against the accepted
interaction-only binary were:

| Workload | Baseline mean ms | Candidate mean ms | Ratio | Speedup |
| --- | ---: | ---: | ---: | ---: |
| all-opcodes | 3,870.323 | 3,842.918 | 0.992919 | 1.007x |
| arithmetic 2m | 8,822.687 | 7,976.707 | 0.904113 | 1.106x |
| memory 7m | 21,926.993 | 21,767.215 | 0.992713 | 1.007x |
| Poseidon aggregator | 3,509.893 | 3,446.339 | 0.981893 | 1.018x |
| Pedersen aggregator | 6,341.817 | 6,265.120 | 0.987906 | 1.012x |
| Fibonacci 100k | 3,796.953 | 3,734.332 | 0.983508 | 1.017x |
| Factorial 100k | 6,561.622 | 6,563.989 | 1.000361 | 1.000x |

The geometric-mean ratio is `0.977133`, or `1.023x` faster. No row regresses
outside sub-per-mille noise, and arithmetic improves materially. The candidate
is retained provisionally because it accelerates a generic core primitive, but
the secure-field chain width was inherited from CM31 rather than measured for
QM31.

## Hypothesis 7: tune packed QM31 chain width independently

The initial implementation selects 32 independent chains whenever the input
allows it, copying the measured CM31 policy. A QM31 packed multiply carries
twice as many coordinate vectors and substantially more temporaries than a
CM31 multiply. Eight packed groups at width 32 may therefore spill registers
and erase the arithmetic win.

Compare a width-8-only candidate against the preserved width-32 executable.
No field logic, fallback, batch geometry, or proof data changes.

Prediction: if register pressure dominates, width 8 should improve the
interaction-heavy arithmetic row without regressing the broader screen. If
multiply latency dominates, width 32 will remain faster and the inherited
policy stays.

### Result: rejected

Exactness held, but the width-8 A-B-B-A screen was neutral/noisy on
all-opcodes and arithmetic and roughly 7% slower on memory-7m after pairing the
outer samples. Independent chains are still needed to cover the longer QM31
multiply latency; register pressure did not dominate. The 32/16/8 selection
order was restored.

## Revised objective: architectural Cairo throughput

The accepted interaction batching and packed QM31 inversion improve the
seven-workload portfolio, but their cumulative gain remains well below the
product objective:

- accepted CPU geometric-mean speedup: approximately `1.27x`;
- accepted Metal geometric-mean speedup: approximately `1.21x`;
- minimum useful system objective: `2x` across the portfolio; and
- aspirational objective: `4-5x` without workload-specific dispatch.

The post-change sample identifies host AIR evaluation and host witness
execution as the remaining dominant stages. Metal command-buffer waits are not
the bottleneck. The official Cairo Metal product is therefore still a hybrid
prover: it constructs the witness and interprets the captured AIR on the CPU,
then accelerates commitment, quotient, and FRI work.

Further field-level tuning cannot plausibly close the remaining gap. The next
accepted architecture must remove interpreted host work:

1. expose domain-parallel AIR execution as a generic scheduler contract;
2. specialize authenticated Cairo AIR programs ahead of repeated row
   execution on CPU;
3. lower the same authenticated programs to the existing Metal code generator
   and resident arena; and
4. move witness recipes through the same CPU/Metal specialization boundary.

Every step must preserve exact CPU/Metal proof bytes and official Rust
verification. No implementation may dispatch on benchmark name, corpus path,
input digest, or measured size.

## Hypothesis 8: split the dominant AIR component by domain

The generic AIR scheduler currently creates one job per component. Cairo
components have highly unequal domains, so the largest component leaves most
workers idle at the end of composition evaluation. Blindly spawning nested
jobs inside every component can deadlock the bounded global pool.

Add an explicit optional parallel-domain evaluator to the prover component
contract. The scheduler selects at most one eligible dominant component,
executes it on the caller, and lets that evaluator partition disjoint row
ranges through the shared pool while the ordinary component jobs drain. This
preserves coefficient ownership, component ordering, and one accumulator per
component. It also establishes the row-range boundary required by subsequent
AOT CPU and resident Metal evaluators.

Prediction:

- AIR-heavy large rows improve without changing witness or PCS behavior;
- smaller components retain the existing component-level scheduler;
- exact proof bytes remain unchanged; and
- the abstraction is frontend-neutral and opt-in, not Cairo- or
  benchmark-shaped.

Reject the change if it regresses the portfolio, changes proof bytes, or
creates recursive pool waits.

### CPU result: accepted

All focused proofs remained exact. A-B-B-A screening against the accepted
interaction plus packed-QM31 executable measured:

| Workload | Baseline mean ms | Candidate mean ms | Ratio | Speedup |
| --- | ---: | ---: | ---: | ---: |
| all-opcodes | 3,244.142 | 2,786.726 | 0.859002 | 1.164x |
| arithmetic 2m | 7,400.133 | 5,425.809 | 0.733204 | 1.364x |
| memory 7m | 15,185.605 | 11,834.597 | 0.779330 | 1.283x |

The result validates the load-imbalance diagnosis: the largest AIR domain was
serializing the end of the component schedule. The generic contract is
retained because it is opt-in, selects by structural domain size, and permits
only the caller-owned component to subdivide through the bounded pool.

Evidence is stored in `/private/tmp/cairo-domain-parallel-ab-v1/result.json`.

## Hypothesis 9: bind trace geometry and shifted rows once

Every interpreted trace-read instruction currently repeats three kinds of work
that are invariant for the entire component:

- resolving component-local columns through preprocessed indices or trace
  spans;
- validating committed-column shape and lifting geometry; and
- converting nonzero circle-domain offsets through two bit reversals for every
  SIMD lane.

Bind the three interaction column sets once before evaluation and validate each
bound polynomial once. Materialize one compact `u32` row map for each distinct
nonzero offset used by the authenticated component programs. Hot reads then
perform only a local-column lookup, mapped-row load, and the already-defined
lifting-index projection.

The maps are derived solely from authenticated program instructions and domain
geometry, owned by the component evaluation, and freed before the next proving
stage. Offset zero remains allocation-free.

Prediction:

- AIR-heavy workloads improve most;
- proof bytes remain exact because this caches the existing index function;
- map construction remains a small fraction of the repeated interpreted reads;
  and
- peak memory increases only by four bytes per row and distinct nonzero offset
  for concurrently evaluated components.

Reject on any proof mismatch, portfolio regression, or unbounded map lifetime.

### Result: rejected

Exact proofs held, but one paired screen was neutral:

| Workload | Baseline ms | Candidate ms | Ratio |
| --- | ---: | ---: | ---: |
| all-opcodes | 2,347.566 | 2,330.548 | 0.992751 |
| arithmetic 2m | 4,867.969 | 4,868.591 | 1.000128 |
| memory 7m | 11,302.199 | 11,280.455 | 0.998076 |

The one-time full-domain offset-map construction consumed essentially the same
time removed from interpreted trace reads. The binding and maps were removed
in full; the result reinforces that eliminating interpretation, rather than
rearranging its address arithmetic, is the required next step.

## Hypothesis 10: execute lane-independent witness bytecode with AdvSIMD

The witness executor currently interprets one recorded instruction for one row
at a time. Most Cairo witness programs contain only lane-independent integer
and M31 operations, column reads/writes, fixed-table reads, and lookup-word
emission. Four adjacent rows can therefore share one opcode dispatch while
their values execute in native four-lane vectors.

Add a structurally admitted packed interpreter:

- inspect the authenticated opcode stream, never the workload label;
- retain scalar execution for deductions and multiplicity mutations;
- execute four rows per dispatch for all remaining opcodes;
- keep scalar prefix/tail handling for arbitrary worker ranges; and
- differential-test every output class against the scalar interpreter.

Prediction:

- arithmetic, memory, and opcode rows improve broadly;
- expensive Pedersen/Poseidon deductions remain neutral;
- CPU and Metal both benefit because the current official Metal product builds
  its witness on the host; and
- proof bytes and all witness columns remain exact.

Reject if any recorded opcode lacks exact packed semantics or if the portfolio
does not improve.

### Result: rejected

Exact proofs held, but one paired screen measured:

| Workload | Baseline ms | Candidate ms | Ratio |
| --- | ---: | ---: | ---: |
| all-opcodes | 2,332.864 | 2,348.666 | 1.006774 |
| arithmetic 2m | 4,824.407 | 4,804.358 | 0.995845 |
| memory 7m | 11,237.726 | 11,066.315 | 0.984747 |

Sharing one dispatch across four rows does not remove enough work. The simple
programs are already parallel, while deductions remain scalar and the packed
path retains runtime opcode dispatch and indirect table semantics. The entire
candidate was removed. Further interpreter variants are out of scope; the
remaining CPU route is authenticated AOT specialization.

## Hypothesis 11: specialize authenticated AIR bytecode ahead of time

The Cairo AIR bundle contains immutable evaluator topology, but the SIMD
evaluator still switches on every base and extension instruction for every
four rows. Generate direct Zig evaluators for each unique structural program
in the three official AIR bundles. Admit a generated evaluator by a BLAKE3
identity over its full instruction/dataflow shape while leaving live constants
and parameters bound from the authenticated runtime program. Unknown shapes
must retain the generic interpreter.

The first monolithic generation attempt was stopped after approximately 3.5
minutes when the Zig compiler exceeded 11.6 GiB RSS. Splitting each evaluator
into `noinline` chunks of at most 192 instructions reduced the clean product
build to 57.73 seconds and 3.20 GiB peak RSS. That made the experiment
measurable, but it still produced a 5.9 MiB executable versus the accepted 1.8
MiB executable.

### Result: rejected

All proofs were byte-identical and verified, but the A-B-B-A sentinel screen
did not justify the build and binary cost:

| Workload | Baseline mean ms | AOT mean ms | Ratio | Speedup |
| --- | ---: | ---: | ---: | ---: |
| all-opcodes | 2,662.590 | 2,644.339 | 0.993146 | 1.007x |
| arithmetic 2m | 5,583.545 | 5,335.989 | 0.955664 | 1.046x |
| memory 7m | 12,703.411 | 12,732.594 | 1.002297 | 0.998x |

The geometric-mean ratio is approximately `0.9836`, only a `1.017x` gain.
Direct instruction specialization therefore cannot supply the missing system
factor after domain parallelism. The generated source, dispatcher, structural
identity, and product step were removed in full. Evidence is retained in
`/private/tmp/cairo-aot-ab-v1`.

The next candidate must change the amount or placement of work: fuse AIR
evaluation with quotient accumulation, move the authenticated evaluator onto
Metal, or eliminate witness materialization. Further host interpreter tuning
is below the admission threshold.

## Measurement increment: expose Cairo stage profiles

The generic prover already records PCS sub-stages, but the official Cairo
products always passed a null recorder. Add one backend-neutral
`--stage-profile-out` option to `prove` and `run-and-prove`, carry the recorder
through both focused backend bindings, and bracket the Cairo-only stages:

- preprocessed planning and materialize/commit;
- base-trace construction;
- AIR-template instantiation;
- main-trace commit;
- interaction-trace construction and commit; and
- the existing composition, sampling, FRI, PoW, and decommit stages.

Profiling is opt-in, produces a separate machine-readable artifact, and does
not alter the normal report or proof boundary. CPU and Metal produced the same
arithmetic-2m proof SHA-256
`25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`;
Metal reported 74 dispatches and zero CPU fallbacks.

### Arithmetic-2m attribution

| Stage | CPU s | Metal s | CPU share | Metal share |
| --- | ---: | ---: | ---: | ---: |
| base trace build | 1.507 | 1.550 | 31.3% | 29.0% |
| preprocessed materialize + commit | 0.400 | 0.344 | 8.3% | 6.4% |
| main trace commit | 0.459 | 0.165 | 9.5% | 3.1% |
| interaction trace build | 0.342 | 0.336 | 7.1% | 6.3% |
| interaction trace commit | 0.320 | 0.136 | 6.7% | 2.5% |
| composition evaluation | 0.397 | 0.414 | 8.3% | 7.7% |
| FRI quotient build + commit | 0.262 | 1.350 | 5.5% | 25.2% |
| proof of work | 0.587 | 0.595 | 12.2% | 11.1% |
| complete proof transaction | 4.812 | 5.351 | 100% | 100% |

These are one-run diagnostic profiles, not promotion evidence. They disprove
the idea that the accepted Metal backend is broadly limited by command
submission: the dominant Metal-specific loss is concentrated in FRI quotient
build/commit, which is `5.15x` the CPU stage on this workload. The shared
host-side base trace is the largest individual CPU stage and remains the
largest shared CPU/Metal cost.

The next research round should therefore:

1. use Metal System Trace and device counters inside
   `fri_quotient_build_and_commit` to separate kernel time, waits, residency
   conversion, and commit time;
2. profile live base-trace construction by witness operation, bytes written,
   allocation, and output-column pass count;
3. treat PoW as an independent 11-12% floor and test a protocol-identical
   accelerated implementation; and
4. only then move host composition and interaction work to the resident
   backend.

The two largest measured changes have enough combined headroom to matter:
making Metal FRI merely match CPU saves about 1.09 seconds, and halving base
trace construction saves about 0.78 seconds. Together they would move this
Metal row from 5.35 seconds toward 3.49 seconds before PoW or resident AIR
work, approximately `1.53x`.
