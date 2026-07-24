# Session 04: Persistent Request Service

## Decision

The process service remains deliberately single-lane. The current CUDA context
reports one physical execution lane, and retained profiling does not establish
that a second proof or stream would shorten the complete critical path.
Queueing and runtime reuse are therefore implemented independently of GPU
overlap.

The backend-neutral service and its public contract are:

`src/prover/execution/request_service.zig`

`src/prover/execution/request_service_types.zig`

CUDA supplies the process runtime and a frontend-owned workload dispatcher.
The service itself contains no AIR, frontend, CUDA handle, kernel, or proof
format knowledge.

## Ownership And State

```text
new runtime
    |
  ready -- submit --> bounded FIFO -- pumpOne --> one active proof
    |                                      |             |
    |                                      | success     | recoverable failure
    |                                      v             v
    |                               ordered result    ordered failure
    |
    +-- fatal/uncertain failure --> abort runtime --> poisoned
                                                |
                           publish failure/cancellations
                                                |
                                      install new runtime
                                                |
                                              ready
```

- The service owns one already-open process runtime.
- The runtime must report exactly one execution lane. More lanes fail closed;
  this slice does not fabricate stream concurrency.
- Producers may submit through the bounded host queue while the owner thread is
  executing a proof. Only that owner thread may execute, cancel, publish,
  reset, or close the CUDA runtime.
- A request moves into service ownership only after admission succeeds.
- The workload destroys each accepted request exactly once.
- A completed proof remains service-owned until FIFO publication transfers it
  to the caller.
- Recoverable errors continue only when the workload classifies the error as
  request-local and the runtime independently reports ready.
- Every other error aborts the runtime, cancels unstarted requests, and retains
  ordered failure/cancellation publications.
- Reset requires the poisoned generation to have no active or unpublished
  tickets and accepts a newly opened runtime as an explicit ownership transfer.
- Graceful close requires an empty service. Destructive abort destroys queued
  requests and unpublished proofs before relinquishing the process runtime.

## Admission Bounds

Admission has separate, explicit outcomes for:

- a running service that disallows concurrent enqueue;
- queue-slot exhaustion;
- one proof exceeding the device-memory policy;
- retained queued inputs exceeding their host-memory policy;
- poisoned and stopped services.

With the enforced one-proof execution policy, peak admitted device demand is:

```text
process persistent resources
+ prepared-plan cache resources
+ max_request_device_bytes
```

Queued requests consume no device arena. Their retained host inputs are bounded
by `max_queued_input_bytes`, and the number of unpublished tickets is bounded
by `max_pending`. CUDA's existing four-entry execution cache separately owns
fixed-address plan arenas and refuses eviction while an arena is leased.

## Ordering And Telemetry

Tickets increase monotonically. Execution selects the oldest queued ticket,
and publication can move only the oldest unpublished ticket. A later proof may
finish only after the prior proof leaves the sole execution lane, but it still
cannot be published ahead of an earlier unconsumed result.

Every receipt records:

- runtime generation and exact shape key;
- predicted device and retained-input bytes;
- admission queue depth;
- admission, start, and finish timestamps;
- queue wait and complete service time;
- first-request cold status;
- authoritative prepared-shape cache hit before execution;
- shape retention after execution;
- runtime-poison disposition.

Aggregate telemetry records admissions and each rejection class, queue and
input-byte high-water marks, cold and total service time, shape hits/misses,
completion/failure/cancellation/publication counts, and runtime poison count.
Each receipt binds its generation's runtime initialization time, while
aggregate telemetry retains both the current and cumulative initialization
cost. The caller supplies that measured boundary; the service does not infer
or hide it.

## Host-Independent Evidence

Validated on the implementation commit's source:

```text
zig test src/prover/execution/request_service_test.zig -O ReleaseSafe
# 8/8 passed

zig build test-stwo-prover -Doptimize=ReleaseSafe
# PASS, 181-source transitive prover closure

zig build test -Doptimize=ReleaseSafe
# PASS, 388-source transitive repository closure

zig build test-cuda-runtime-contract -Doptimize=ReleaseSafe
# PASS

zig build test-cuda-build-plan
# PASS, 34/34 tooling tests

zig build cuda-source-closure
# PASS

zig build source-conformance
# PASS, no new violations
```

The focused tests cover mixed shapes (`A, B, A`), cold/miss/hit attribution,
FIFO output, every admission capacity, host enqueue during an active proof
without GPU overlap, explicit busy policy, queued cancellation, recoverable
request failure, fatal runtime poison, queued cancellation after poison,
generation reset, failure-timing ownership cleanup, destructor balance, and
rejection of an unmeasured multi-lane runtime.

## Hardware Evidence Still Required

This host-independent slice does not claim CUDA overlap or sustained GPU
throughput. A locked CUDA host must still run a real Native mixed-family queue
through a frontend workload dispatcher and retain:

1. exact proof bytes and independent Rust-oracle receipts per request;
2. queue/service/cold/shape-hit receipts from the service;
3. zero CPU fallbacks and one terminal proof read per request;
4. bounded plan-cache and device-memory high-water evidence;
5. Nsight Systems confirmation that warm requests contain no context creation,
   module load, compilation, or unexpected allocation;
6. a one-lane versus any proposed multi-lane ABBA result before changing the
   physical execution policy.

Until that evidence exists, the architecture supports deterministic persistent
service execution but makes no multi-stream or service-throughput promotion
claim.
