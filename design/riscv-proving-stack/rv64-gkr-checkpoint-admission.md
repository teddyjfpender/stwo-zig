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
