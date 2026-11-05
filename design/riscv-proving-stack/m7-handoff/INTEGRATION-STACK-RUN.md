# One canonical M7 stack

The runner uses the canonical integration source and one immutable driver,
receiver, a25 image, Sparse library and observer library for every arm. No
proof-size candidate is included. The preset is `integration-stack-preset.json`.
Runtime hooks must be built successfully before preparing an executable manifest.

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

Before each request, the runner requires five consecutive samples with load1m<8,
CPU steal<=1%, and no active compiler/receiver process. A busy pod fails after300s;
it is never relabelled quiet. Fresh receivers cannot contaminate primary timings.

Both arms hold the physical CUDA budget guard under the same GPU lease, from
before prover startup through prover exit. Guard ready records, binary SHA256,
PID, terminal status and exact per-device held bytes are preserved. A watchdog
kills the prover process group if the guard exits early. On the current5090s,
held5,681,184,768B enforces prover physical availability<=27,998,552,064B per GPU.
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

Prepare another manifest with `--block24628607` (with a space between the flag
and value), then run `run --manifest HEAD-MANIFEST.json --out HEAD-EXPERIMENT
--ownership-profile-pair`. Do not execute until Root approves the combined
source/build and first-class coverage. The runner stops on the first missing
class, byte mismatch, receiver rejection, guard failure or quiet-gate failure.
