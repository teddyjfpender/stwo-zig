# Admission for the owned stride-two GKR producer

This is an operational resource bound, not a security theorem or RSS promise.
Dense/default admission remains unchanged. The lower plan is selected only for
fused stride-two product construction, consuming input ownership, the qualified
owned denominator fold, and metadata-only terminal binding. The coordinator
snapshots that choice once, uses it for admission and passes the same Boolean to
every CPU worker. A worker cannot silently fall back to dense after admission.
Invalid nonempty environment selections fail before worker/source allocation.

For an instance with N facts, the freshly allocated canonical input planes are
4N bytes of M31 numerators and32N bytes of OM31 denominators. The producer never
charges a smaller physical input backing merely because a logical MLE shrinks.
Every checkpoint plane is likewise charged at its original creation length until
its owner is freed. Freed allocations can enter the separate bounded recycler
cache; they are not live task payload or an additional free memory allowance.

Let S=32 and h be the common tree height above original inputs currently being
consumed by the top-down batch. Each local instance uses the same h while active.
The original input capacity is charged throughout as an upper bound. Additional
retained even checkpoints at heights2,4,... below h have capacity
2SN*(1/4+1/16+...) < (2/3)SN. When h is odd, the regenerated layer has capacity
2SN/2^h. Its first fold may temporarily allocate one secure half-plane when the
allocator refuses resize. No task writes or frees a lower checkpoint while its
regenerated view is being used; every pool job is joined first.

The worst odd height is h=1: lower retained secure checkpoints are absent,
regeneration costs SN, a resize/copy fallback costs at most SN/4, and the shared
Eq table plus its construction overlap is conservatively at most SN/4 at that
height. This totals at most1.5SN beyond the original inputs. Higher odd heights
have geometrically smaller regeneration/Eq costs; adding their lower retained
checkpoints stays below the same envelope. At even h>=2 the current layer was
already counted as a checkpoint, and its resize/copy overlap plus Eq is smaller.
At h=0, the original denominator backing is already counted; the secure numerator
lift, optional denominator copy-half fallback and Eq fit the same1.5SN envelope.
Grand-product/single-denominator kernels have fewer planes. Mixed-height Eq uses
one shared table bounded by the largest participating instance, so replacing
that largest N by sum(N_i) is conservative. Proof/mask/owner metadata keeps the
existing checked4096*((I+1)*(V+1)+(V+1)^2) reserve without reduction.

The implemented working reserve deliberately uses2SN+4N, leaving an extra half
secure value plus a base value per fact beyond the phase envelope. Thus numeric
admission is104 bytes per production multiplicity fact plus unchanged metadata,
versus136 in the default conservative plan. All arithmetic is checked before
input allocation. The terminal-binding phase has no raw N/D planes: its separate
bound is64 bytes per row, output headers, retained proof metadata, and the maximum
prepared-projection allocation derived from the actual Entry layout and the
central maximum tuple arity. The final plan takes the maximum of these phases.
The child hard requested-byte allocator uses this derived plan as its cap; the
configured GKR budget is an upper admission limit, not permission to exceed the
smaller admitted task reserve.

The complete task estimate still separately counts MAIN coefficients, binding,
global metadata/output, retained inventory and existing PCS floors. Immutable
setup, original capture/advice, thread stacks, allocator metadata/rounding, kernel
pages and free recycler capacity are outside the numerical bound. Consequently
the scheduler cap is represented payload admission, not a hard process-RSS cap.
Two-lane host measurements must report these distinctions and actual RSS/swap.
No default promotion follows from a resource estimate or artifact-byte parity.

## Explicit tighter dense admission

`STWO_ZIG_GKR_TIGHT_ADMISSION=1` selects the same104B/fact reserve while keeping
the original dense numerical prover and matrix-based terminal binding. This is
orthogonal to the checkpoint option; unset or0 preserves the old dense136B plan.
Other nonempty values fail closed. The coordinator snapshots both choices once;
the child hard requested-byte cap and scheduling derive from that same policy.
No proof/profile/configuration bytes contain these operational choices.

For dense production multiplicity inputs, at a common active tree height h>=1,
raw input capacity is36*sum(N). All retained lower/current secure planes cost at
most64*sum(N)*(1-2^-h). Shared Eq construction overlap is at most12*Nmax/2^h and
one-plane resize/copy fallback at most16*Nmax/2^h. Since Nmax<=sum(N), their sum is
strictly below100*sum(N). At h=0 the borrowed raw inputs plus newly lifted secure
fold planes cost68*sum(N); Eq and the next copy-half fallback contribute at most
8*Nmax each, for at most84*sum(N). Matrix binding retains the original raw36N
plus64 bytes per row, bounded by100N because every row has at least one fact.
The104 reserve leaves4 bytes per fact beyond the larger dense phase. The existing
metadata envelope, output headers and all checked arithmetic remain unchanged.
This is a production multiplicity bound, not a claim about arbitrary external
layer representations or arbitrary allocator backing over-allocation.

Independent test allocators stress both refusal of every resize/remap and
successful logical resize that retains original physical payload capacity until
free. Exact-cap numerical children and independent pending receivers pass. In
the larger test, requested peak13,111,104B and original-capacity peak13,112,672B
are below the15,024,128B admitted cap; the one-fact-per-row binding case also
passes. Tracking-map bytes, allocator pages/free cache and stacks are explicitly
outside that payload measurement. Dense104 is opt-in until separate actual
concurrency/throughput evidence and review justify changing the default.

A first real prefix of two ordinary CPU shards (8,388,606 steps), fully parked,
cache1GiB and2x8 worker lanes under36GiB scheduler admission, fresh-verifies in both
modes. All five authoritative artifacts are byte-identical. The owned checkpoint
plan admits16.312+15.809GB task leases concurrently; stage1 overlaps for6.521s.
Proving is14.479s with23.763GB peak RSS. The original dense136 plan serializes
stage1 under the same cap, taking18.048s. This is one non-quiet pair, not a qualified
speed multiplier. It demonstrates admission/concurrency, not physical inability
of dense proofs to fit; the explicit tighter dense104 control is measured next.

The subsequent same-binary prefix2 triplet uses211fe2272 plus the qualified lazy
oracle, the same2x8/cap36GiB/cache1GiB/parked configuration and independently fresh
receivers. All fifteen authoritative artifact hashes match across all modes.

| Prefix2 measure | Original dense136 | Explicit dense104 | Lazy checkpoint104 |
|---|---:|---:|---:|
| Source+prove |20.134s |16.229s |16.714s |

Tight dense admission enables two stage1 jobs without recomputing tree levels.
These are single runs on a shared host, not full-block throughput qualification
or a reason to change the default. The committed receipt includes actual stage
intervals, live-admission traces, numerical caps, processRSS and every artifact
hash. A lower per-job memory requirement may intentionally increase whole-host
RSS when it permits more jobs to run together.

## Streamed-bottom reserve

Only the frozen policy with `stream_bottom=true`, checkpoint storage and tight
admission selects this lower bound. Dense136 and nonstreamed104 are unchanged.
The opaque source supplies canonical raw facts through bounded64-fact callbacks;
no full raw M31-numerator/OM31-denominator owners exist. Their admitted input-byte
count is therefore0. All already-created secure checkpoint/fold owners are still
charged at their original creation capacities until freed, regardless of logical
resize. The public opaque-oracle clone API can materialize a complete raw matrix;
that API is explicitly excluded from the production source path, which transfers
oracles into `sumcheck.proveBatchOwned` and never clones them.

The geometric even checkpoint bank has at most64*sum(N)/3 bytes. An odd terminal height can add one constant-size terminal pair (at most64 bytes per instance); the unchanged checked metadata reserve covers this separately. At common
height h>=2, geometric lower checkpoints, a current folded-half owner, shared Eq
and one resize/copy fallback stay below that bank plus another16*sum(N), which is
below68*sum(N). At h=1 there is no lower secure checkpoint; bounded source reads
produce only the already-folded secure half (16*sum(N)), plus the smaller Eq and
fallback. At h=0 all secure checkpoint owners have been consumed and destroyed.
The first raw-source fold creates two secure half owners,32*sum(N) bytes total.
Retaining these original capacities through inner folds plus shared Eq
construction (conservatively12*Nmax) and one copy-half fallback (16*Nmax) is at
most60*sum(N). The implemented working reserve is68*sum(N), leaving8 bytes per
fact beyond this larger phase. Mixed dimensions can only reduce the simultaneous
plane sizes; replacing Nmax by sum(N) is conservative. The original metadata
reserve is unchanged and covers bounded source/reader/header descriptors.

The binding-phase maximum is still64 bytes per row plus output headers, retained
proof metadata and the actual-layout prepared-projection scratch bound. There
are no raw planes in that phase. The final plan takes the maximum of numeric and
binding phases and enforces it with the child's exact requested-byte cap. Free
recycler cache, allocator rounding/bookkeeping, stacks, capture/setup and PCS
scratch remain separately admitted and must not be presented as a process-RSS
limit. Tests exercise original-capacity retention, compulsory allocation/copy
fallbacks, many mixed instance sizes and synchronized equal-size first folds,
with independent pending verification. No default promotion or unchecked clone
fallback is introduced.

## Reproducible policy and requested-byte observations

The coordinator optionally writes `observed_tree_policy` from the same single
frozen environment read used for admission and each worker. CPU timing records
also expose numerical and including-binding requested peaks, admitted GKR peak,
and the actual hard allocator limit. These are allocator-request observations,
not RSS or retained-backing measurements; they do not enter the proof transcript.

`rv64-om-retention-plan BUNDLE ROM_LOG BLOWUP [GLOBAL_BYTES]` uses that same
frozen policy and the production `taskEstimates` authority. GLOBAL_BYTES defaults
to8GiB. With no memory policy selected every pre-existing report field matches
the earlier default136 report exactly. The full30-worker roster at ROMlog20 and
beta1 yields maximum adjacent CPU stage-one payload leases54.722GiB (default136),
43.300GiB (dense104), and30.450GiB (stream68). This predicts admission, not runtime
overlap or a host-memory guarantee; capture, setup, PCS, allocator and kernel
owners remain outside those task leases.

The initial source push ran the repository pre-push lanes. Cairo Metal failed
because `STWO_METAL_CORE_AOT_BUNDLE` was unavailable. The already-authorized
hook exception was used after the focused RV64 Safe/Fast gates passed.

## Streamed bottom, dense upper storage: independent operational choice

`STWO_ZIG_GKR_STREAM_BOTTOM=1` also works with checkpoint policy unset. This
streams raw facts, stores every secure upper tree level, and replays metadata
for terminal binding. It automatically selects tight admission. Explicit
checkpoint2 plus stream1 retains the existing stride-two source path and68N
bound. Materialized default136 and tight dense104 controls remain unchanged.
Invalid nonempty policies fail before worker admission; there is no fallback.

The source-dense numerical payload reserve is80N plus the unchanged checked
metadata. All original secure upper creation capacities total64*sum(N_i−1),
less than64N, even if allocators retain backing after shrink. At common outer
height h>=1, shared Eq construction is at most max(32,12Nmax/2^h) (<=6Nmax for production Frame N>=32; the scalar constant/header allowance is also covered by metadata), and one
copy-half resize fallback is at most16Nmax/2^h (<=8Nmax). Instance folds and
plane finalizers are sequential; parallel row jobs join before return. Thus
these phases are below78N without assuming any bank-retirement discount.
At bottom h0 every earlier upper oracle has been destroyed; source first folds
own32N and Eq/copy transients are at most12Nmax+16Nmax, giving60N. Choose80N
with metadata separately charged, and take the maximum with actual metadata-
projection/binding scratch. No dense raw N/D planes exist. Explicit public
opaque cloning/materialization is excluded from this production path.

This bounds requested and original live payload capacities, not free recycler
cache, allocator rounding, stacks, MAIN/PCS/setup/capture owners or RSS. The same
frozen policy selects the scheduler retention estimate and hard child limit.

The source-dense implementation is qualified in `0825ec08b`: QM31/OM31 mixed
and tiny source proofs, artifacts and next draws match materialized dense;
fresh terminal verification, pole behavior, callback errors, all allocation
failures, joined workers and immutable held-lease fallback pass Safe/Fast.
Production Child lifecycles and real CPU service proofs pass both modes. Exact
caps cover mixed12 and synchronized16 instances with retaining/no-resize allocators.
AIR independent code/resource review found no blocker.

Same-binary prefix measurements are in
`vectors/reports/rv64-gkr-stream-dense-upper-20261102/matched-prefix-receipt.json`.
CPU0 ABCCBA and two-CPU ABBA produced44 identical authoritative artifact hashes
and10 accepted fresh receivers. CPU0 numerical requested peak fell12.616GB to
8.074GB (1.56x), while RSS fell16.388GB to11.849GB (1.38x); source-checkpoint68
reached2.691GB numerical and8.543GB RSS. Two-CPU source-dense RSS fell30.657GB
to21.833GB (1.40x) at the same two8-worker lanes. Mean proving times were9.655s
vs9.768s for CPU0, and15.775s vs15.931s for two CPUs: these approximately1%
differences are below the visible host variation, not evidence of a speedup.
CPU0 checkpoint68 averaged10.030s. Numerical reductions still cost more under
streaming; dense uppers remove checkpoint recomputation, not metadata replay.

No host-wide quiet was established. A2-second own planner compilation overlapped
the first source-dense CPU0 sample and is flagged; other agent compilation was
active during parts of the sweep. Default controls remain unchanged. A complete
matched block remains required before operational-policy promotion. The pure
full-roster source80 plan places the heaviest adjacent CPU tasks at34.733GiB,
below the36GiB payload admission cap, while preserving the physical-memory caveats.
