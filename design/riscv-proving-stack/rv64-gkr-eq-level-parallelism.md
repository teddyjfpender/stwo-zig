# Bounded GKR Eq-level scaling

The packed GKR slice already pools `nextGrandProductLayer` and `nextLogupLayer`, as well as oracle reductions and MLE folds. This follow-up changes only the remaining serial packed scaling loop at each Eq-table level to the existing bounded `row_work.fill` scheduler.

Every task borrows an immutable previous level and writes its own index interval in both halves of the existing new output level. The pool joins before the previous level can be deinitialized. Packed arithmetic, scalar tails, index ordering, recursive allocation ownership and numerical results are unchanged. There are no new matrices, scratch allocations, pools, global caches or transcript operations. The usual nonblocking scoped-pool/cooperative fallback and minimum grain apply.

Safe/Fast ownership and exhaustive allocation-failure gates pass. The actual pinned171de6ab8 source comparison passes41tests, including complete Q/OM four-gate mixed-height proof bytes, next transcript draws and independent fresh terminal binding under1/2/4/8worker schedules. New direct tensor-product tests check Eq ordering for0/1/5/17variables under a four-worker pool with1MiB stacks.

A shared-host three-iteration20-variable Eq-only micro measured Q10.49ms→5.03ms and OM35.91ms→12.90ms from one to four workers. This supports the local scheduling change; it is not a projection for the4.28s total GKR numerical stage or full block. Raw logs and reproduction commands live in `vectors/reports/rv64-gkr-eq-levels-20261101/`.
