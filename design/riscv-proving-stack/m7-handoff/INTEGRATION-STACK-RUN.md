# One canonical M7 stack

The runner uses the canonical integration source and one immutable driver,
receiver, a25 image, Sparse library and observer library for every arm. No
proof-size candidate is included. The preset is `integration-stack-preset.json`.
Runtime hooks must be built successfully before preparing an executable manifest.
Independent full captured-value diagnostic SHA256 is ON and required for correctness smoke, OFF in both headline/profile arms. The required R1 private capture seal remains included in production. The instrumentation matrix is stored in the preset and experiment receipt.
The final fullstack also selects EARLY_NATIVE_SEGMENTS=1 and FIRST_PASS_RAM=1; baseline explicitly selects both0. Old CPU0_PRESTAGE and EARLY_NATIVE_MAIN stay0 in both arms. R1 is therefore measured as part of the single combined stack, with no per-feature experiment.

The small-block correctness gate runs a lane1 baseline and two lane2 fullstack
services using source-implemented seeded ready admission (17 and29). Each serves
one cold and one warm request. The gate compares captured-input SHA256, every
native binary, bundle.json, ordered tree.json, and every leaf/fold/root proof.
It requires activation logs for each seed. Fresh GPU-disabled CPU receivers run
only after every service has exited. No timing JSON participates in byte parity.

The headline experiment runs six isolated, UNPROFILED services in the fixed order
baseline/fullstack/baseline/fullstack/baseline/fullstack. Each service gets one
cold warmup and one timed warm request. Primary medians include exactly three
warm requests per arm. With `--ownership-profile-pair`, one baseline/fullstack
Nsight pair follows all six primary services; its walls are excluded from
headline medians. CUPTI GPU-seconds are computed separately after fresh receivers.

Correctness smoke records load/steal/GPU inventory once and explicitly labels its walls UNQUALIFIED. It does not wait for benchmark quiet conditions.
Before each headline request, the runner requires five consecutive samples with zero pod cgroup CPU PSI some/full-total deltas, zero nr_throttled/throttled_usec deltas, CPU steal<=1%, and no active compiler/receiver or foreign GPU process. Host load is recorded but does not gate; it spans other cgroups on the shared192core host. The current pod quota is40.8cores. Pressure/throttling snapshots are also recorded immediately before and after each request. A busy pod fails after300s;
it is never relabelled quiet. Fresh receivers cannot contaminate primary timings.

Only the fullstack arm holds the physical CUDA budget guard under the same GPU lease, from
before prover startup through prover exit. Guard ready records, binary SHA256,
PID, terminal status and exact per-device held bytes are preserved. A watchdog
kills the prover process group if the guard exits early. On the current5090s,
held5,681,184,768B enforces prover physical availability<=27,998,552,064B per GPU.
The baseline keeps its original auto arena without a canary; it has no28GBclaim. Applying a canary to baseline would alter the control arena and was stopped before the first request.
This is an enforced upper bound, NOT an exact observed peak. Device-wide NVML
samples include the canary and are labelled accordingly. Host/RSS is observed;
the GPU-only admission policy does not certify a host/RSS bound.

Prepare after the ONE combined build (replace uppercase paths/checkpoints):

```sh
python3 SOURCE/scripts/rv64_m7_integration_stack.py prepare \
  --source-root SOURCE --source-commit FINAL \
  --driver DRIVER --receiver RECEIVER --library A25 \
  --sparse SPARSE --observer OBSERVER \
  --process-budget-guard /workspace/m3/build/m7-rc-sparse/gpu-budget-guard \
  --native-hooks-commit NATIVE --device-hooks-commit DEVICE \
  --block 26235156 --out SMALL-MANIFEST.json
python3 SOURCE/scripts/rv64_m7_integration_stack.py run \
  --manifest SMALL-MANIFEST.json --out SMALL-SMOKE --smoke
```

Prepare another manifest with `--block 24628607`, then run `run --manifest HEAD-MANIFEST.json --out HEAD-EXPERIMENT
--ownership-profile-pair`. Do not execute until Root approves the combined
source/build and first-class coverage. The runner stops on the first missing
class, byte mismatch, receiver rejection, guard failure or quiet-gate failure.
