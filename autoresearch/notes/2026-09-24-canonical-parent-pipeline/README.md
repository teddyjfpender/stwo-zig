# Canonical typed execution-parent pipeline — 2026-09-24

## Implemented

`blake3_execution_parent_pipeline.zig` connects typed full-width execution captures
to the existing shared bounded parent runner. It adds no second scheduler. Jobs
carry explicit child verifier/capture types, pinned child identity, independently
admitted parent key and retry capacity. Preparation owns a shared allocation budget
which survives with its returned rows; queue byte admission includes that ownership.
Preparation and proving both check the job context, and the worker uses its existing
admitted-key proof/rekey path. The API is exported as
`blake3_execution_parent_proof.execution_pipeline`.

One preparation producer overlaps one persistent proving worker through the existing
one-item owned handoff. Both output proofs retain allocator leases and survive worker
destruction. The existing native-child and tree-pair adapters remain intact. Their
local qualification policy was extracted into a shared test helper, with no policy
semantics changed. No production scheduling defaults or cryptographic parameters changed.

A named `test-blake3-native-parent-pipeline-aot` target now explicitly qualifies
this path; it clears the serial-control environment variable. The ordinary parent
qualification retains its single-parent behavior unless explicitly opted into the
pipeline. Benchmark worker counts and SMP allocation are explicit test-only options.

## Qualification and boundaries

`qualified.log`: testing allocator, **7/7 tests passed**. `production-qualified.log`:
SMP allocator through the new named target, **7/7 tests passed**. `build-help.log`
confirms the final target wiring, including its serial-control exclusion.
The qualification exercises:

- q70/PoW26 for both the real CPU child capture and both Metal parent outputs.
- Two jobs sharing one fixed plan and worker pool; exact plan/column identities
  remain stable, and both outputs verify after worker destruction.
- Original proofs and freshly decoded codec copies independently verify.
- Rejection of excessive CPU/memory reservations, a one-byte preparation budget,
  and a corrupt independently pinned parent key before publishing output.
- Positive measured preparation/proving overlap; serial control has zero overlap.

All timed and qualified outputs retain parent SHA-256
`87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b`,
857,591 parent bytes and 483,375 child bytes. This is **two repeated jobs for one
canonical child fixture**, not distinct Ethereum blocks or a full recursive tree.
The existing four-leaf tree test still uses diagnostic q8/PoW0 and was not rerun.

The initial compile had ambiguous nested type names. The first runtime qualification
then exposed a test-harness ownership mistake: verification consumes the original
artifact, so encoding must precede it. That ordering was fixed. `parent.log`,
`parent-final.log`, and `diagnostic.log` retain those failures; they are excluded
from measurements. These were not accepted as successful qualification.

## Matched experiments

M5 Max, ReleaseFast, authenticated AOT bundle, **eight proving workers plus one
preparation worker**. The worker count was a candidate from the preceding noisy
worker sweep, not an autotuned production default. Both arms retain the same worker,
inputs, keys and configured limits. Each serial control drains a one-job call before
starting another; the overlap arm submits a two-job batch. Serial therefore includes
an extra preparation-thread/handoff setup. The configuration reserves 12 GiB for
preparation, 24 GiB for worker-routed allocations, retained-row bytes plus 64 MiB per
queued item, and 12 GiB for external allocations, under a 60 GiB local policy.

Admission reserves about 56.524 GB. This is not an enforced whole-process RSS cap:
backend allocations, allocator overhead and external owners require the caller's
reservation. The tracked worker peak is about 11.994 GB and remains below its 24 GiB
cap. OS physical peaks are reported separately below.

For each allocator: one frozen binary, serial/overlapped/overlapped/serial order,
two processes per arm, compilation excluded. Sixteen timed parent outputs across
the eight processes each pass original and fresh-codec verification.

| Allocator | Mode | Two-job window median (s) | Complete fixture median (s) | Overlap median (s) | Physical peak maximum (GB) |
|---|---|---:|---:|---:|---:|
| Testing | serial | 22.391 | 35.443 | 0.000 | 30.135 |
| Testing | overlapped | 21.514 | 35.000 | 8.080 | 33.114 |
| SMP | serial | 21.049 | 32.923 | 0.000 | 30.144 |
| SMP | overlapped | 19.894 | 36.709 | 5.662 | 32.768 |

The testing-allocator window is 3.9% lower with overlap; the SMP window is 5.5%
lower. **Neither establishes a reliable end-to-end speedup.** Timing drift is large:
SMP serial windows range 16.941–25.156 s, while overlap windows are 19.741–20.047 s.
The SMP complete fixture median is actually 11.5% higher with overlap. Physical peak
rises about 2.62 GB with SMP (2.98 GB with testing allocation). All observations
are retained. No samples were removed to improve the result.

Timestamps demonstrate real overlap, but concurrent preparation also takes longer
in several runs, and proving stages slow even after preparation has finished.
Contention and host timing drift are plausible contributors; these experiments do
not isolate a root cause. SMP allocation does not resolve the variability. Do not
attribute all of it to allocator locks, thermal limits, or a particular background
application without stronger evidence.

The two-job window excludes initial child proving, seed preparation, parent key and
worker construction, negative checks, and final independent verification. The full
fixture includes those costs. It is neither a production root-latency measurement
nor an ordinary CSP result. The prototype overlap path is explicitly opted into;
there is no blanket production-default recommendation from these measurements.

## Reproduce

```sh
# Default testing allocator; override worker count deliberately if desired.
STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-pipeline-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
# Production allocator qualification, with the same limits and checks.
STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-pipeline-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-canonical-parent-pipeline/measure.py
python3 autoresearch/notes/2026-09-24-canonical-parent-pipeline/production/measure.py
```

`binary.json` and `production-binary.json` pin the respective executables. Both use
`core`. `testing-source` records the first qualified helper/adapter sources;
`candidate-source` records the final sources, including SMP selection and the build
target. Its final build-only change clears the serial-control variable, which was
absent during the successful qualification. `control-source` snapshots pre-adapter
recursion/prover sources and the earlier build wiring. `changes.patch` is the delta.
The worktree is dirty; HEAD alone does not reproduce the binaries. Drivers, raw
profiles, spans, per-process memory and summaries are retained and checksummed.

## Remaining work

Canonical single-level overlap and ownership now have executable evidence. Reliable
throughput benefit, scheduling dependent tree levels, canonical full-tree qualification,
and persistent reuse across heterogeneous jobs remain broader acceptance work.
Preparation-stage profiling and resource-aware scheduling should precede any blanket
overlap rollout. Deeper PCS/DEEP fusion, remaining full-row transcript preprocessing,
full CPU/Metal CSP recovery, and the separately reviewed parameter experiment remain
open. Neither subsecond recursion, an order-of-magnitude total improvement, nor
cross-prover superiority is established by this checkpoint.
