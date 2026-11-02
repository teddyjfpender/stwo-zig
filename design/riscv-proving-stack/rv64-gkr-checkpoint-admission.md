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
