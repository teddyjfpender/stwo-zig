# RV64 CUDA numerical qualification

These tests are based on PR310's native OM31/GKR construction. They do not
produce an Ethereum execution proof, a recursion root or a security certificate.
The production proof receiver and its fail-closed admission are unchanged.

## Host numerical checks

`independent_field.py` compiles the actual CUDA arithmetic header on the host
and checks basis, edge and random products against an independent schoolbook
Python polynomial tower. The host shim declares no CUDA driver functions and
cannot execute a GPU path.

```sh
python3 tests/cuda/rv64/independent_field.py
zig build test test-rv64-numerical --build-file src/integrations/riscv_cuda/build.zig -Doptimize=ReleaseSafe -j2
zig build test test-rv64-numerical --build-file src/integrations/riscv_cuda/build.zig -Doptimize=ReleaseFast -j2
```

The Zig/C++ bridge checks full-coordinate multiplication and fractions against
native OM31, and the raw sumcheck arithmetic against the actual native GKR
polynomial for base and secure numerators at sizes 4, 8, 16, 256 and 1024.
These are numerical host checks, not device parity or the final pinned Rust
protocol oracle gate. That gate and full receiver parity remain pending.

## Compile and run on NVIDIA hardware

Use CUDA >=12.8 with support for `sm_89` and `sm_120`. Match toolkit headers,
compiler and libraries; install NVTX3 headers for the existing context runtime.
`CUDA_HOME` and `NVTX_INCLUDE` below are explicit toolchain locations.

```sh
"$CUDA_HOME/bin/nvcc" -O3 -std=c++17 \
  -gencode arch=compute_89,code=sm_89 \
  -gencode arch=compute_120,code=sm_120 \
  -Isrc/backends/cuda/native -I"$NVTX_INCLUDE" \
  src/backends/cuda/native/rv64/gkr.cu \
  src/backends/cuda/native/runtime/context.cu \
  tests/cuda/rv64/resident_smoke.cu \
  -Xcompiler=-pthread -ldl -o /tmp/rv64-resident-smoke

/tmp/rv64-resident-smoke 2 20
/tmp/rv64-resident-smoke 4 20
compute-sanitizer --tool memcheck /tmp/rv64-resident-smoke 2 10
compute-sanitizer --tool racecheck /tmp/rv64-resident-smoke 2 10
compute-sanitizer --tool synccheck /tmp/rv64-resident-smoke 2 10
```

Run sizes log2=2,3,4,8,9,10,16,20,22 to cover tiny/tail/multi-level reductions.
The harness uses the real existing context, async allocation registry, ingress
and compute streams, event dependency and joined teardown. One owner thread per
requested device enqueues independent work concurrently. A missing driver/device
exits **77 (skipped)**; an insufficient requested device count fails. No fallback.

Every device run checks projection, EqEvals, one/two-level trees, raw sumcheck
and half-split folding, both base and secure numerator paths, plus overlap,
lane, geometry, canonicality and sticky-pole rejection. Host reference evaluation
and readbacks are outside the timed region. Hot waves reuse every allocation
and transfer no host data; setup transfers and validation readbacks still occur.
Timings are median CUDA-event durations of 11 waves after 3 warmups. Each wave
contains projection, trees, Eq construction, sumcheck and folding; it is not a
single GKR proof, a throughput score or complete-block latency. Output records
explicitly set `full_block_verified=false`.

Before comparing 2/4x4090 against 2/4x5090, record UUIDs, GPU clocks/power,
PCIe topology, free/reserved/peak memory, driver/toolkit, source/binary digests,
CPU/NUMA placement, device timings and process wall time. Use Nsight Systems
to verify overlap and zero hot-loop copies, and Nsight Compute for achieved
occupancy, memory throughput, spills and launch distribution. Compilation's
register count alone is not a utilization measurement.

Custody checks can also run without a driver, using toolkit enum declarations:

```sh
g++ -std=c++17 -O2 -Wall -Wextra -Werror \
  -I"$CUDA_HOME/include" -Isrc/backends/cuda/native \
  tests/cuda/rv64/custody_test.cpp -o /tmp/rv64-custody-test
/tmp/rv64-custody-test
```

This intentionally mocks only the registry/stream boundary to exercise byte
units, bounds, overlap and error propagation. It does not authenticate real
CUDA allocation ownership; the hardware test exercises the actual registry.

## Resident sumcheck feedback and verifier adapter

The second slice enqueues a complete **single LogUp oracle's sumcheck** using
`rv64.sumcheck.enqueue`. Interpolation, coefficient trimming, ordinary-Blake
absorption, raw-mod-OM31 draws, updated claims and all folds stay on the GPU.
Only the compact round records, final state and terminal mask are read back
for assembly. The caller supplies the already scoped native transcript seed;
this helper does not authenticate a seed or replace full GKR/PCS binding.

`rv64.assembly.verifyReadback` converts that compact format to the existing
native sumcheck proof, invokes the native verifier and LogUp gate relation,
and checks challenges, digest/draw counter, final claim, Eq correction and
terminal mask. Numerical acceptance remains separate from physical binding.

Compile the host oracle separately with the numerical shim, then link the real
CUDA driver harness. Do not compile the oracle as a device translation unit:

```sh
g++ -O3 -std=c++17 -Itests/cuda/rv64/host_include \
  -Isrc/backends/cuda/native -c tests/cuda/rv64/numerical_bridge.cpp \
  -o /tmp/rv64-round-oracle.o

"$CUDA_HOME/bin/nvcc" -O3 -std=c++17 \
  -gencode arch=compute_89,code=sm_89 \
  -gencode arch=compute_120,code=sm_120 \
  -Isrc/backends/cuda/native -I"$NVTX_INCLUDE" \
  src/backends/cuda/native/rv64/gkr.cu \
  src/backends/cuda/native/rv64/round.cu \
  src/backends/cuda/native/rv64/tail.cu \
  src/backends/cuda/native/runtime/context.cu \
  tests/cuda/rv64/sumcheck_smoke.cu /tmp/rv64-round-oracle.o \
  -Xcompiler=-pthread -ldl -o /tmp/rv64-sumcheck-smoke

/tmp/rv64-sumcheck-smoke 2 16
/tmp/rv64-sumcheck-smoke 4 16
compute-sanitizer --tool memcheck /tmp/rv64-sumcheck-smoke 2 10
compute-sanitizer --tool initcheck /tmp/rv64-sumcheck-smoke 2 10
compute-sanitizer --tool racecheck /tmp/rv64-sumcheck-smoke 2 10
compute-sanitizer --tool synccheck /tmp/rv64-sumcheck-smoke 2 10
```

This compares every round record, challenge, final state and mask against the
separate host oracle, for both base and secure numerators, and checks poisoned
rounds clear challenges before downstream folds. The host oracle's result is
independently matched to the existing native prover/verifier in Zig tests.
The real-context Zig FFI controller is also compile-checked without CUDA via
the `check-rv64-native-bindings` target, included in the default focused test.

The harness reports combined and split secure-reduction timings separately.
The split route doubles first-stage block parallelism and reduces register
pressure, but rereads first-half values: measure before selecting it. Default
commands retain the combined route; set `split_secure_sum=true` explicitly to
qualify the alternative. Each route uses three warmups and eleven full-round
runs with zero intermediate host transfers. No complete-block timing is implied.

The sumcheck harness packs the terminal mask on-device and reads only32 mask
words,40 state words and 44 words per round. It never downloads a fold bank.
Run sanitizer initcheck as well: after a device-side pole, every already
queued round must emit a defined neutral challenge and an invalid record
ordinal, while the sticky failure prevents admission.

## Eq-table launch/traffic fusion

Set `NativeCommands.fused_eq=true` to use up to four expansion levels per
launch. The baseline remains the default. A 21-variable Eq table takes6
launches instead of21. Each tile performs the same30 OM31 multiplications
as four separate binary expansions, but keeps intermediate levels in registers.
Eq-buffer traffic per old prefix drops from 1440 to 544 bytes (point loads and
cache effects excluded). This is a structural count, not a bandwidth timing.

The hardware harness now checks/times eight strategies: four combinations of baseline/fused
Eq and combined/split secure reductions, plus fold/sum fusion with baseline/fused Eq and 64/256-row shared tails, comparing complete round records and
terminal masks. Fusion increases registers (four levels use128 on sm120) and
reduces thread count, so fewer launches alone do not establish higher GPU
utilization or lower latency. Use the full-round timings and Nsight to select.


## Fold and next-round sum fusion

Set `NativeCommands.fused_fold_sum=true` to fold nonterminal rounds and form
next-round raw sums in one first-stage kernel. The first round still primes
sums normally and the last uses the standalone terminal fold. This flag is
independent of `fused_eq`; `split_secure_sum` affects the priming sum only when
fold/sum fusion is enabled. Baseline remains default pending device profiling.

Each thread owns four folded fraction rows and immediately consumes their
register values for the next raw term. All eight source rows are read once;
the folded table is still written for the following fold, but never reread
by a separate sum kernel. No inter-block dependency, atomics, additional
workspace or host round feedback is introduced. Reduction tails use the same
deterministic multi-block reducer as the baseline. Every write reservation is
checked against all inputs/outputs before the first dispatch.

For an initial power-of-two count `n>=4`, this eliminates `log2(n)-2` launches
and `64*(n-4)` bytes of logical fraction-table reads across the job, excluding
cache effects, Eq/parameter reads and scratch reduction traffic. At `n=2^22`,
that is20 launches and 268,435,200 bytes (256 MiB minus256 bytes). Secure-input
fold + next-sum fraction traffic per eight-row tile falls from 1024 to 768 bytes.
The fused first stage uses 128 registers/thread and 256 shared bytes on sm89 and
sm120, with no compiler-reported spills or stack frame. Fewer threads and
higher work per thread may offset traffic savings; these are structural counts,
not measured bandwidth or speedups.

The numerical host test runs the exact tile helper on padded, disjoint SoA
planes and compares complete records/state/terminal values with the baseline
and native prover (14 cases,62 rounds, including zero polynomials, count4
terminal-only and count8 minimum fused paths). This does not execute CUDA.
The real-driver harness adds `fold_sum_ms` and `all_fused_ms` timings to the
existing four variants and checks failed-round propagation through fused folds.
Run shapes through `log_count=20`, including small tails, on each target GPU
count; use Compute Sanitizer/Nsight before enabling a policy.


A separate host replay checks 22 size/base combinations under ASan/UBSan:

```sh
g++ -O1 -g -std=c++17 -fsanitize=address,undefined -fno-omit-frame-pointer \
  -Itests/cuda/rv64/host_include -Isrc/backends/cuda/native \
  tests/cuda/rv64/numerical_bridge.cpp tests/cuda/rv64/host_replay_test.cpp \
  -o /tmp/rv64-host-replay-sanitize
ASAN_OPTIONS=detect_leaks=0 /tmp/rv64-host-replay-sanitize
```

Leak scanning is disabled because this runner cannot inspect `/proc` thread
state; address and undefined-behavior instrumentation remain enabled. This
checks host memory safety only. GPU memcheck/racecheck/synccheck are pending.


## Shared tails and independent-job batches

Set `NativeCommands.tail_count` to a power of two in 4..256 to complete the
small end of sumcheck in one block; zero (default) disables the policy. The
controller checks this policy before any mutation and avoids forming unused
next sums before a tail handoff. It chooses a terminal bank disjoint from the
input, so its terminal pointer may differ from the baseline's parity choice.
Every proof value stays on device. `tailBatch` accepts1..8 independent ready
jobs with heterogeneous counts/cursors; all must use the same context/lane,
with disjoint mutable ranges. This batches independent transcripts, not a
mixed-instance GKR claim or a multi-device runtime pool.

The block owns256 shared numerator/denominator slots, one state and one
record. A prefix-preserving XOR row permutation avoids adjacent-pair bank
conflicts in the32-bank/u32 model. All64 threads enter each reduction/barrier;
thread zero updates the native transcript, then parallel in-place folds own
unique rows. Compact records are emitted each round and state once at exit.
No intermediate global fold table is emitted. From 256 rows,22 baseline
launches (or16 with fold/sum fusion) become one, excluding prior init/Eq work.
Runtime crossover, occupancy and speedup still require hardware measurements.

The shared Blake2s schedule is now compile-time immutable under native CUDA;
CuMetal retains its existing declaration. Standard hash comparisons cover129
suffix lengths across block boundaries. The kernel resource report distinguishes
actual round/tail counts from the isolated hash's48-register result.

Build the additional harness with the same CUDA architecture/include flags as
`sumcheck-smoke`, including `src/backends/cuda/native/rv64/tail.cu` in both commands
and replacing the harness source with `tests/cuda/rv64/tail_smoke.cu` for the
batch driver. Both use the separately compiled `numerical_bridge.cpp` object.

```sh
/tmp/rv64-tail-smoke 2
/tmp/rv64-tail-smoke 4
compute-sanitizer --tool memcheck /tmp/rv64-tail-smoke 2
compute-sanitizer --tool racecheck /tmp/rv64-tail-smoke 2
compute-sanitizer --tool synccheck /tmp/rv64-tail-smoke 2
compute-sanitizer --tool initcheck /tmp/rv64-tail-smoke 2
```

The batch driver sweeps 1/2/4/8 independent tails of varied shapes, compares
all records/state/masks, checks padded planes and guard words, rejects a
cross-job alias before mutation and poisons one job while its peers complete.
It times sequential tail launches against one batched launch; reset is outside
the CUDA-event interval. Setup arrays remain owned through synchronization.
The full-round driver adds `tail64_ms`/`tail256_ms` and tests interior handoff.
Both return77 when no NVIDIA device/driver is available.

The actual native packet preflight also runs without a device. Its registry
and lane are mocked and every call is rejected before launch, including the
80th range alias and out-of-allocation address:

```sh
nvcc -O2 -std=c++17 -Isrc/backends/cuda/native \
  src/backends/cuda/native/rv64/tail.cu tests/cuda/rv64/tail_preflight_test.cu \
  -o /tmp/rv64-tail-preflight
/tmp/rv64-tail-preflight
```

ASan/UBSan host replay now also compares five tail thresholds for every size;
this validates shared-table arithmetic helpers, not GPU barriers or races.
See the [design](../../../design/riscv-proving-stack/rv64-cuda-tail.md) and
[pinned ZisK review](../../../design/riscv-proving-stack/rv64-cuda-zisk-review.md).


The harness `Owner` copies setup ingress into owned staging retained until
join, including exception paths. It is noncopyable/nonmovable; an unrecoverable
teardown join failure terminates the test before borrowed host memory can be
freed. This setup-only CPU copy is outside timing intervals. Its deferred-read
mock verifies temporary upload arguments and exception teardown under ASan/UBSan:

```sh
nvcc -O1 -g -std=c++17 -Isrc/backends/cuda/native \
  -Xcompiler=-fsanitize=address -Xcompiler=-fsanitize=undefined \
  -Xcompiler=-fno-omit-frame-pointer tests/cuda/rv64/context_owner_test.cpp \
  -o /tmp/rv64-owner-sanitize
ASAN_OPTIONS=detect_leaks=0 /tmp/rv64-owner-sanitize
```
