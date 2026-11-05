# One measurement contract for the Ethereum basket

`scripts/rv64_ethereum_basket.py` plans or runs the fifteen blocks pinned by
`autoresearch/guest_efficiency/basket.json`. It invokes the real candidate
producer and a separate native receiver. It does not build a second prover.
Execution is opt-in; the default writes a plan with missing inputs explicitly
listed for each block.

The current default is `conjectured128_b2_q108_p20_fold4`. Select
`--profile proven_beta2_q256_p0_fold4` for the documented-assumption control.
The harness does not normalize measurements between those constructions.

An input manifest has this shape (paths are relative to the manifest or may
use environment variables):

```json
{
  "schema": "rv64-ethereum-basket-inputs/v1",
  "cpu_driver": "${CPU_DRIVER}",
  "receiver": "${CPU_DRIVER}",
  "resources": {
    "gkr_bytes": 34359738368,
    "global_bytes": 8589934592,
    "retained_frontend_bytes": 21474836480,
    "disk_bytes": 137438953472,
    "park_main": true,
    "fixed_setup_bytes": 12884901888,
    "schedule": {"lanes": 2, "workers_per_lane": 8, "memory_cap_bytes": 38654705664}
  },
  "blocks": {
    "24628607": {
      "request": "${ARTIFACTS}/native-v3-24628607/request.json",
      "jobs": "${ARTIFACTS}/native-v3-24628607/jobs"
    }
  }
}
```

Supply one request/input identity per block; the harness verifies ELF and input
hashes and checks that the expected output begins with that basket block's
payload request root. The guest tooling's `bench.py prepare` and client adapter
produce inputs; old guest instruction-count records are not fresh proving
baselines. Optional `historical_receipt` entries remain explicitly historical.

```
python3 scripts/rv64_ethereum_basket.py --manifest INPUTS.json --output RUN
python3 scripts/rv64_ethereum_basket.py --manifest INPUTS.json --output RUN \
  --blocks 24628607 --execute
```

Use `"jobs": "-"` with the direct-capture CLI to include execution in the
producer process. The cached-jobs route measures replay/import, setup and
proving and explicitly reports `execution_included=false`; it does not quietly
exclude nine seconds from an alleged end-to-end number. Direct capture exposes
its checkpoint/execution/join statistics. Resources are written to a JSON file
and passed with the existing CLI's actual file argument contract.

For N local GPUs, provide `gpu_driver`, `gpu_workers` (distinct device ordinals
and `capacity_bytes` after the device reserve), `host_capacity_bytes`, and each
block's `resident_bytes` and `host_bytes` requirements. The dispatcher grants
one process slot per device and retains both host/device byte credits until the
process and fresh verifier have joined. For example, four GPU slots do not
permit four 20 GB CPU handoff buffers on a 48 GB admitted host budget. This is
whole-block scheduling; splitting one block's physical workers belongs to the
prover's existing coordinator, not this harness.

`--backend gpu` fails closed until a GPU driver is configured. It also requires
the driver's `report.json` to include `gpu.kernel_launches > 0` and
`gpu.device_ms >= 0`; an ordinary CPU driver cannot silently become a GPU
baseline. These are instrumentation checks, not cryptographic attestation of
GPU origin or residency. Optional driver `native_cells` and `cell_scope`
enable ns/cell; absent cells remain null, never a guessed denominator.
`--nsys /path/to/nsys` profiles the exact producer command and labels the
result as profiled rather than comparing it with an unprofiled latency run.

Every accepted result records per-child wall/user/system time, peak RSS, minor
and major faults, capture/setup/prove durations, CPU/truth proof counts,
native cell scope when available, top-level worker stage totals and artifact
hashes. Worker stage sums can overlap and are not relabeled as block wall time.
An optional `reference_directory` enforces matching report context and exact
proof/bundle bytes before publication. Eight fast harness tests cover command
framing, hash binding, receiver failure, CPU fallback, per-child usage and
host/device admission; they do not assert that fixture subprocesses are proofs.
