# Task 03: CUDA Scheduler And Graphs

Status: stage graphs implemented; persistent service remains single-lane until
overlap evidence justifies additional physical streams

## Objective

Compile the proof dependency DAG into the smallest evidenced critical path using
lane streams and cached graph regions where they reduce verified-request time.

## Deliverables

- One coordination stream and a bounded runtime-owned lane pool.
- Explicit event edges for cross-stream dependencies.
- Scheduler model for independent components, commitments, quotient chunks,
  Merkle subtrees, and within-round FRI work.
- Saturation model prevents useless concurrency.
- Stable graph regions with validated parameter updates and direct fallback for
  differential tests only.
- Graph cache identity is the complete plan cache key.
- Report includes lane, event, graph instantiate/update/launch/miss counters.

## Gates

- Direct and scheduled paths are byte-identical.
- Direct and graph paths are byte-identical.
- Transcript-visible operations preserve exact order.
- Nsight Systems demonstrates the predicted overlap or launch-gap reduction.
- Graph setup is excluded only from warm requests where it is genuinely cached;
  cold and first-shape boundaries retain it.
- No new device-wide synchronization or intermediate D2H.
- Peak accounted memory includes all concurrent lanes and graph resources.
- Structural screen has no row above its regression ceiling.

## Exit Evidence

- Before/after dependency diagram and timeline capture.
- One-stream versus scheduled ABBA.
- Direct versus graph ABBA.
- Rejection note for every stream/graph experiment that did not shrink the
  complete critical path.
