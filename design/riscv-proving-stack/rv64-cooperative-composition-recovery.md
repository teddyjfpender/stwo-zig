# Recovered cooperative composition queue

Recovered from `recovery/rv64-wave2-20261101/composition-queue` at
`0ea417bcc`. This is an optional host scheduling path; it changes neither AIR
constraints nor the proof transcript. Production automatic selection keeps the
established scheduler. `STWO_ZIG_COMPOSITION_SCHEDULER=queue` opts into the
experiment; `legacy` explicitly selects the control path.

The recovered implementation lets one pool wave drain component work and
cooperative column/row batches. Non-cooperative exclusive components retain a
separate full-pool phase. Power ranges and accumulation order remain bound to
component identity, independent of completion order.

## Safety and limits

- Each published batch lives until every claimed callback has returned. Its
  publisher waits for completion even when a callback records an error.
- Callbacks from the audited row kernels evaluate equations only; callbacks
  from the column transform use the serial FFT. These are leaves and do not
  acquire another pool lease or publish further queue batches.
- Every admitted component is joined before its error is returned. An error
  stops new admissions after that component finishes; already running work
  drains. This is failure cleanup, not a new external cancellation API.
- One wave lease is returned before the non-cooperative exclusive phase.
- The admission byte limit is a **soft working-set estimate**, not a hard
  allocator limit. It counts expanded columns and an output bucket, but a
  component larger than the limit may run alone. Completed accumulator
  outputs remain live for the final merge after active admission is released.
  Other proof stages, retained coefficients, fixed setup and allocator caches
  are outside this estimate. It cannot be used as GPU memory admission.
- `STWO_ZIG_COMPOSITION_QUEUE_BYTES` sets the estimate's concurrency limit.
  Promotion needs a complete allocation-lifetime ledger and full-block
  memory/performance measurements. Queue enablement alone is not a proven
  wall-time improvement.
- Temporary failing test-discovery canaries from the interrupted work were
  removed before recovery. They are absent from this checkpoint.

## Qualification

`src/prover: zig build test-air` passes all 152 tests in ReleaseSafe and
ReleaseFast. This includes mixed-component parity across 1/2/3/8 workers,
soft-cap variants, component-error joining, allocation-failure cleanup,
exclusive-component isolation, and queue callback coverage. The recovery adds
an explicit regression that cooperative capability does not enable the queue
by default.

Native RV64 qualification and same-binary prefix evidence are recorded in the
accompanying receipt after those gates finish. No full-block performance claim
or default queue promotion follows from these focused tests.

The recovery's Safe native driver, Word16 ALU/shared-provider suite and RV64
AIR suite pass. Both modes prove the real 4-CPU/3-truth prefix, and separate
fresh receivers accept. All seven proofs, bundle, cells, cost and roster are
byte-identical between modes and to the frozen schema5 baseline. The queue
actually executes four CPU waves on eight threads. With the explicit 1 GiB
soft cap the largest estimated active component is 3,154,116,608 bytes, using
the documented oversized-component exception.

The single engineering pair is slower with the queue (34.51 -> 40.08 seconds
wall; 28.18 -> 32.81 seconds proving), while capture/setup also slow and a
fresh receiver overlaps the queue run. This establishes neither a controlled
speedup nor a regression attribution. Default enablement remains withheld.
See `vectors/reports/rv64-word16-execution-20261101/cooperative-composition-recovery-v1.json`.
