# Resident basket measurement contract

`scripts/rv64_resident_basket.py` wraps the existing production `resident-batch`
entry. It does not add a numerical pipeline or launch remote jobs. The matrix is
all 15 entries in `autoresearch/guest_efficiency/basket.json`, on 1, 2 and 4
physically identified RTX 5090s. Missing cases remain visible. A failed case
cannot become an accepted timing, and a partial matrix is never complete.

Example on the GPU host, with existing adapted requests:

```sh
python3 scripts/rv64_resident_basket.py plan \
  --inputs /workspace/rv64-gpu-session/basket/manifest-resident.json \
  --driver /workspace/rv64-gpu-session/build/rv64-ethereum-fully-resident \
  --receiver /workspace/rv64-gpu-session/build/rv64-ethereum-fully-resident \
  --library /workspace/rv64-gpu-session/build/resident-oom-trim/libstwo-rv64-native-6d9a8d6188fb6df6.so \
  --devices 0,1,2,3 --counts 1,2,4 --output /workspace/resident-matrix
```

Change `plan` to `run` to execute. Use only the physical devices available on that
host; `--counts 1` supports a one-GPU host. `--keep-going` records unsupported
cases and proceeds, but returns failure if any case failed. Without it, execution
stops at the first failure. `report` regenerates the Markdown and JSON summary
from the same pinned plan and retained results without running a prover. Existing
case directories are never overwritten or silently resumed. To select a newly
qualified native image, supply its exact `--library-sha256` explicitly.

The input manifest uses `rv64-ethereum-basket-inputs/v1`: `blocks` contains each
request and independently measured `expected_cpu_segments`; `resources` supplies
explicit byte budgets and the CPU capture/prover schedule. The harness forces
full direct capture, no parked MAIN and uniform-r27 Keccak geometry. Optional
`resident_environment` pins explicit production policy switches, such as a
qualified device replay mode. Other inherited `STWO_RV64_*` settings are removed.
The pinned guest, actual input bytes, receiver, producer, runtime and byte budgets
are held constant across device counts. The manifest must provide an explicit
coordinator schedule. Each configuration exposes at least one coordinator lane
per GPU, redistributing the same total CPU worker budget when more lanes are
needed. For example, two lanes of four workers become four lanes of two on four
GPUs; the one-GPU control schedule stays unchanged. An insufficient worker budget
fails planning instead of silently oversubscribing the host. The exact schedule
is retained in the plan, result and report. Existing host/device byte admission
still controls actual concurrency; lane count alone does not establish memory fit
or device utilization. The chosen GPU cap defaults to 28 GiB per
device. Device count does not establish that all stage-one MAIN coefficients fit;
production byte admission remains authoritative. No host spill is substituted.

Every block/configuration starts a fresh producer process that executes the same
request twice using one persistent pool. Trial zero is cold; trial one is warm.
A fresh receiver accepts the full cold proof and checks the expected output. Warm
acceptance is inherited only after exact proof-file and bundle SHA parity; it
avoids reconstructing the same receiver key a second time. If a matching accepted
one-GPU result exists, other device counts must match its proof bytes as well.
The profile is `conjectured128_b2_q108_p20_fold4`: a 128-bit target under documented
assumptions, not a certified whole-protocol security bound. Recursion is excluded.

`result.json` retains request wall, capture, setup, proving, native verification,
worker timings, fresh receiver cost, actual GPU telemetry, proof hashes, page
faults, process RSS and whole-device VRAM samples. Request wall includes execution,
capture, setup, proving and native verification. It excludes initial pool creation;
whole producer-process wall includes that startup and teardown. The difference is
reported separately, never presented as an exact cold-request startup allocation.
RSS and physical VRAM cover both requests together, not an isolated warm peak.
CUDA-event spans may overlap or include enqueue gaps; they are not block wall.
Wide-transfer absence is a strict production-path contract, not a CUPTI trace.

The current historical CPU receipt has six fresh accepted blocks out of fifteen,
on ELF `718186e58cc2b228734810fe629daf20f26e0024e93f4d3928821b94814dc903`.
It is an older producer/geometry checkpoint, not a completed matched CPU basket
or a valid denominator for fresh GPU speedup claims. No CPU basket is launched by
this harness.

## Separate GPU production from independent CPU qualification

`produce` runs the same producer as `run`, then writes `produced.json` and a
result with `status: produced_pending_verification`, `accepted: false`. It pins
every native artifact, recursive proof, tree and producer log to the original
plan. Run `qualify` with the same arguments and output directory to freshly
verify those existing artifacts. Changed inputs, assets, proof bytes or trees
are rejected before verification. Both receivers run with
`CUDA_VISIBLE_DEVICES=''`, no GPU library selection and the PCS helper set to
`/bin/false`. Recursive admission additionally requires all nodes restored,
zero newly proved nodes, and unchanged physical proof/tree hashes. Only this
phase can change the result to `accepted`.

The split lets the GPU produce successive cases without waiting for CPU-only
receivers. `run` preserves the original sequential behavior. Relocating a run
requires preserving pinned authority/assets and paths; the harness never
silently rebases or substitutes them. Pending cases stay incomplete in JSON
and Markdown reports.

`--strict-recursive-receiver` selects `verify-recursion-candidate`: one CPU
process derives native keys and fixed authority once, verifies the native bundle,
then verifies every existing recursive node using trace-only graphs. It must
return both native acceptance and complete restored-root acceptance, with no
proof generation. The original separate native + resume receiver path stays a
control. A deferred `qualify` may explicitly upgrade only its receiver binaries
and this verification strategy: the original `plan.json` and pending provenance
remain unchanged, and the new pins are recorded in `qualification-plan.json`.
Changing guest, profile, prover, runtime, request, resources or physical artifacts
is rejected. The strict process usage is shared by native and root acceptance;
it must not be counted twice when aggregating receiver time.
