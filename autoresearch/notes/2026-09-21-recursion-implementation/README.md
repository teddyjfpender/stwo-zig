# Recursion implementation goal — active

The attached objective carries four requirements. None is narrowed to this
checkpoint. The preceding investigation was progress: pinned source inspection
and concurrent-proof evidence changed the implementation priorities.

| Requirement | Current evidence | Remaining completion evidence |
| --- | --- | --- |
| Persistent proving plans and bounded scheduling | Bounded parent DAG replay implemented; eight scheduler tests and two seven-parent replays pass | Persistent authenticated plans and buffers in maintained producers, preparation/proving overlap, actual aggregate-memory measurement, cold and warm whole-product qualification |
| Fused PCS/DEEP components beyond muladd/dot4 | Prior row census and source comparison identify target | Implemented component, binding and rejection tests, new identities, CPU/Metal parity and complete-proof improvement |
| Direct witness generation into final layout | Prior batch emits selected PCS/FRI logical lanes | Remaining authority/materialization removal, final-layout integration and measured end-to-end benefit |
| Separate recursion parameter experiment | Existing frontier model and upstream parameter differences inspected | Versioned experimental profiles, explicit security comparison/review, fresh complete proofs and domain/query tradeoff measurements |

## First scheduling checkpoint

`scripts/recursive_proof_scheduler.py` executes ready DAG nodes with worker and
caller-estimated memory reservations. It prefers deeper ready nodes, preserves
stable tie ordering, and starts a dependent only after producer exit, standalone
verification and artifact admission. Failures/timeouts terminate and reap active
process groups. Dependency cycles and oversized jobs fail before execution.
Memory reservations are not an OS memory limit or measured peak aggregate RSS.

`autoresearch/benchmarks/recursion/tree_replay.py` connects this executor to admitted
parent receipts. It retains the leaves, replaces parent-child paths with fresh
outputs, checks producer identity and artifact pins, verifies inputs remain
unchanged, and records commands, logs, timings and acceptance. The repository
build lock is held once across the whole replay, excluding builds without
serializing its internal producers. Existing qualification gates are unchanged.

This is the process-scheduling layer, not a persistent worker or a finished
production tree pipeline. Fresh processes still repeat runtime and plan setup.
The next implementation boundary is immutable authenticated plan ownership in the
Zig producer, followed by reuse across requests without caching witness values.

On Apple M5 Max/64 GiB, with the previously qualified optimized Metal binary:

| Replay | Workers | Parent nodes | Wall seconds including fresh verification |
| --- | ---: | ---: | ---: |
| Bounded DAG | 2 | 7 | 30.111784083 |
| Serial DAG | 1 | 7 | 39.672668959 |

Both runs reserve 8 GB per admitted job against a 16 GB budget. All 14 newly
produced proofs independently verified and matched their qualified key, claims
and proof bytes. This is a single diagnostic pair, approximately 1.32x, with
retained leaf inputs; it is not full-program production or a statistically
qualified speedup. The serial run overlapped brief Python scheduler unit tests;
no compilation or second proof benchmark ran alongside either replay. Repeat
controlled alternating measurements before promoting a performance claim.

Eight focused tests pass: verification/admission dependency barriers, memory
admission, cyclic/oversized input rejection, failed verifier handling, cancellation
and reaping of another running job, timeout, eager ready-parent dispatch without
a level barrier, and admission callback rejection. Command:

```sh
python3 -m unittest discover -s scripts -p test_recursive_proof_scheduler.py
```

Reports and complete producer/verifier logs are under `evidence/{bounded,serial}`.
Measured scheduler/driver snapshots and test source are retained alongside them.
Full proof bundles remain at `/tmp/stwo-recursion-{bounded,serial}-tree-20260921-v1`.
Reports pin all input files, binaries and the scheduler/driver sources. No proof
parameters or proving implementation changed in this checkpoint. The full goal
remains active, including all four requirements above.
