# Wrapper worker and memory scope — 2026-09-07

Bounded read-only source review plus a retained runtime sample. No worker sweep,
code change, build, or additional proving workload was performed for this note.
The terminal proof receipt and source snapshot are maintained separately.

## Measured sample

`raw-clock-stark.sample.txt` preserves `/tmp/ethereum-raw-clock-stark.sample.txt`
verbatim: 36,113 bytes, SHA-256
`f552d621c7c55521457648fbdd0d772cfad8edf897dc971c9ee87aacea170dfa`.
The sample identifies PID 87343, timestamp 2026-09-07 13:35:54.204 +0400,
macOS 15.3.1, and 46.8G current/peak physical footprint as printed by `sample`.
It contains 32 thread entries. All 90 main-thread stack observations are inside
wrapper STARK commitment construction; most descend into batched Merkle leaf
hashing and Poseidon permutation. Many other threads are parked.
This is a bounded stack observation, not total phase attribution or a worker4
measurement. Existing thread count also does not equal active proving workers.

## What the requested budget controls

`STWO_ROLE0_GENUINE_HOST_BYTE_BUDGET` becomes `WorkerPolicyV4.host_byte_budget`
and is forwarded by `cpuRequest()` to the Stage101 CPU composition request.
That request can constrain its composition allocations; it does not cap wrapper
proving, Merkle/FFT storage, materialization, or process footprint.
Wrapper `ExecutionOptions` currently contains worker count only, and the
wrapper invokes `Engine.proveDiagnosedRetainingFailure` with default options.
Its composition compatibility budget is `maxInt`, not the logged Stage101
budget. A phase record carrying `host_byte_budget` must not be presented as an
enforced memory ceiling for that phase.

`STWO_ROLE0_GENUINE_WORKER_COUNT=1` scopes fixture/materialization and wrapper
proving workers. Independent cold verification has separate scheduling and can
use parallel Merkle pools; it is not a single-thread verifier guarantee. The
earlier 1265% CPU observation during cold verification is documented in
`../2026-09-07-real-leaf-readiness.md`.

## Why four workers are not yet recommended

The public-input agent's source review found the following allocation changes.
These byte counts are code-derived estimates, not measured resident memory:

- Materialization helper threads share sources/evaluations/output; projection
  uses 4096-row chunks without per-worker graph copies
  (`vm_air_composition_circuit_parallel_v4.zig:36–62`).
- Merkle leaves share output and allocate 1024 hashers per worker. Three extra
  workers add 216 KiB on this 64-bit Poseidon layout; Poseidon has no packed-byte
  scratch allocation (`src/prover/vcs_lifted/leaves.zig:316–339`).
- Three additional proof-pool helper stacks reserve 48 MiB total (16 MiB each),
  plus bookkeeping. Reservation is not measured residency
  (`recursive_binary_outer_support.zig:89`, `src/prover/work_pool.zig`).
- The decisive unpriced difference is composition: the parallel path allocates
  a worker/evaluator/accumulator for **every component before dispatch**, then
  retains them until joined cleanup (`src/prover/air/component_parallel.zig:267–327`).
  The current serial path evaluates components consecutively. The additional
  live storage has not been measured for this wrapper.

There is no demonstrated environment-only way to obtain just the inexpensive
parallelism. Batched Merkle leaves use the proof pool; the separate Merkle
override does not independently increase those leaves. Explicitly requesting
one composition worker still selects the prepared task path and does not
preserve current serial allocation lifetimes. Keep one leaf in flight and the
current requested proving worker count of one. A bounded Merkle-only pool or a
serial-composition option preserving lifetimes requires implementation and
measurement before a four-worker recommendation. Preserve the independent
16-case CPU/Metal CSP gate; Ethereum timing cannot conceal a CSP regression.

## Next bounded development-loop opportunity

`universal_proof_v4_core.proveAtTarget` already calls the kernel's native
prove-and-verify route, encodes and retains canonical candidate bytes, then
calls `coldOpenAtTarget` to build a complete wrapper cold owner.
The genuine `runWrapper` subsequently copies those bytes, destroys all producer
state, rebuilds verifier inputs, and calls `Proof.coldOpen` again.

The first complete wrapper cold-open is redundant for that lifecycle command:
extract the existing canonical-byte production block behind one shared core
helper, retain native verification and candidate publication, then let the
lifecycle destroy producer state before its single independently reconstructed
wrapper cold-open. Keep `proveAndColdVerify` as the convenience API over the
same helper. This preserves the required verification boundary while avoiding
duplicated recursive capture/preparation work. It is a proposed bounded change;
no implementation or speedup is claimed here.
