# Resident sumcheck tail design

The current large-input pipeline distributes raw terms over many blocks, then
launches round control and a half-split fold. Once at most256 fraction rows
remain, the working set fits in 16 KiB shared memory. Repeated global table
traffic and kernel dispatch become removable costs, while one block can still
parallelize independent terms and rows. This policy is opt-in until hardware
measurements establish a crossover; small shared working sets do not establish
a latency win by themselves.

## Ownership and order

A launch accepts one to eight independent host metadata descriptors, copied
by value into a bounded kernel argument packet. Device pointers remain borrowed
from one execution context and explicit lane. Every range in every descriptor
is validated before any dispatch; cross-job read/write aliases are rejected.
Read-only point/Eq/lambda sharing is permitted. No device descriptor upload,
allocation, event creation or graph-cache ownership is added.

One block owns one job. All input rows load into a column-major shared table with a block-private XOR row swizzle;
base numerators are extended exactly once. At each remaining round, parallel
raw-term evaluation and a deterministic block reduction precede thread-zero
transcript advancement. A barrier publishes the new challenge; threads fold
unique half-split rows in place. Each output overwrites only its own first-half
source, and every second-half source lies beyond all outputs. A second barrier
separates this fold from the next round's sum. No global block barrier is
needed; independent transcripts never wait for each other.

The cursor/geometry relation is exact: `first + log2(count) - 1 == variables`.
The caller has already initialized state and Eq and scoped/authenticated the
seed. Every remaining record is cleared before attempted advancement, including
when an earlier round poisoned the job. State and the current record also stay in shared memory; compact records are emitted each round and state once at exit. The final two rows are written to
explicit secure output planes and the existing32-word compact mask. Sticky
status and the fresh native verifier remain publication gates.

## Integration and evidence gates

The typed sumcheck controller can switch to the tail at a configured power-of-
two threshold in 4..256. It primes/uses large reductions normally above that
threshold. The existing arena is sufficient; output-plane selection keeps the terminal fraction API and selects a bank disjoint from the tail input. The batch launch is numerical execution only, not
mixed-instance GKR batching and not a multi-device worker pool. Device credit
and lifetime remain charged until joined success/abort.

Required evidence: complete polynomial/challenge/state/terminal native parity,
interior handoff and minimum geometry, distinct output canaries, cross-job alias
rejection before mutation, sticky-failure isolation, sm89/sm120 compile/resource
inspection, and real-driver sanitizer/timing sweeps for batch sizes1/2/4/8.
Host arithmetic replay cannot validate shared-memory barriers or actual GPU
throughput. No production/security gate opens from this optimization.


## Cost model

From 256 secure rows there are seven rounds. The separate baseline needs 21
sum/round/fold dispatches plus one mask gather; a tail uses one dispatch. The
fold/sum-fused baseline needs 16 dispatches including initial sum and mask,
versus one tail. These counts exclude shared initialization/Eq work before
handoff, and assume single-block sum stages at these sizes. The tail reads
its source fractions once and writes two final rows, rather than repeatedly
reading/writing intermediate global fraction tables. It still emits every
proof record, reads Eq/point/lambda and publishes final state. Fewer dispatches
are structural savings, not measured throughput or GPU utilization.

The kernel uses 64 threads/block and 16,848 shared bytes, including its
shared state/record/reduction storage. Compile-time hash tables reduce control
register pressure. Use compiler logs for architecture-specific register/stack
counts. A shape policy must account for registers, available concurrent jobs,
shared capacity and latency. Independent-job batching exposes more schedulable
blocks; it does not make one small tail saturate a whole GPU.
