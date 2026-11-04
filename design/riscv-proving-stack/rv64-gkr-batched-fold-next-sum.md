# Experimental batched fold and next-round sum

The mixed persistent-tail experiment removed 12.9% of GKR launches, but did not
reduce adapter wall time in its single cold/warm full-block comparison. Warm
CUDA traversal fell from 627.0 to 602.0ms while adapter wall rose from 861.4 to
869.6ms. The full native proving delta was 680.7ms; the summed local-GKR stage
delta was only 12.6ms. Those measurements do not attribute the whole-block
difference to the tail. CPU-only qualification also overlapped. The event spans
include enqueue gaps, so wall minus summed event spans is not a pure CPU timer.

The persistent tail uses one CTA for the entire mixed batch, processing up to 64
oracles through eight warps. The established batched sum and fold distribute
oracles over independent grid rows. Reduced launch count therefore does not by
itself establish lower numerical cost or preserve that parallelism.

This new candidate keeps the multi-CTA grid. After the shared round-r challenge
has been drawn, one kernel folds its active fractions and computes their raw
sum for round r+1 from the folded values in registers. It reuses the existing
qualified `fold_sum_tile` algebra and the existing batch reduction kernel. It
removes the logical reread of the just-produced fractions; register pressure
and actual device traffic still need measurement.

Mixed heights require an explicit readiness rule. Previously active oracles
have a prefetched sum. Newly waking oracles have not folded and receive the
ordinary sum kernel. A shared round consumes both sets before drawing its one
challenge. A zero-length ordinary batch is skipped. The terminal count 4 fold
uses the established route because no next sum is needed. No future challenge,
round polynomial or field value comes back to the host.

Global input/bank/scratch admission still precedes mutation. The optional native
entry independently validates all input/output spans before its first launch.
The next-round correction, sleeping claims, oracle weights and transcript
transition remain with the original shared batch-round implementation.

The option is OFF by default. `STWO_RV64_GKR_BATCH_FOLD_SUM=1` requires the new
optional symbol and batched oracles; 0 disables it. Other values reject. The
persistent-tail option cannot be enabled simultaneously. Older images retain
the established path. No active production runtime was replaced for this work.

Host scheduling/ownership tests, the full production semantic check and offline
SM120 compilation pass. The mock checks every active raw sum is ready before
every shared draw, including newly waking base-numerator oracles, count 8 to
count 4, terminal folding, missing capability and poisoning.

The optional numerical route subsequently passed its one guarded GPU invocation
on a 5090: nine native GKR goldens, nine GKR poison cases, eleven binding poison
cases, and 178 metadata/witness checks. Positive route counters confirmed 578
fused calls and 578 kernel launches across that entire tiny-fixture invocation.
Those are not launch counts per production segment or block. Native transcript,
mask and compact-artifact parity passed. The helper process took 3.277 seconds,
including initialization; that is not a kernel benchmark or a speedup claim.

Representative full-block qualification, new-kernel sanitizer checks and
performance remain pending. The option remains OFF and no active production
runtime was replaced. See the separate source-checkpoint and numerical-gate
receipts for their precise qualification scopes.
