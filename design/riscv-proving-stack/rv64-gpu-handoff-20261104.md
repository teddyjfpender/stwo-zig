# RV64 GPU handoff — November 4, 2026

The branch is `codex/rv64-cuda-ethereum`, PR314. PR316 closure tests and PR320
setup/cache/direct-capture changes are integrated. This handoff checkpoints
completed engineering; the optimized full15 two-GPU matrix remains incomplete.

The accepted test-block measurements include fresh native proofs and recursion:

| Block24628607 | Request | Recursion | Independent CPU receiver |
|---|---:|---:|---|
|2GPU, CPU FIXED commitment|147.555s|110.880s|Accepted|
|2GPU, GPU FIXED commitment|98.924s|63.621s|Accepted|
|1GPU, GPU FIXED commitment|136.901s|99.897s|Accepted|

These are single ordered observations, not medians. The same-binary1/2GPU pair
scales1.384× in request wall. All native, leaf, fold, root and tree bytes match
the earlier accepted control. These measurements predate the options below.
Security is a128-bit target under documented assumptions, not certification.

This round includes three options that remain OFF by default:

| Option | Intended effect | Qualification at handoff |
|---|---|---|
|`STWO_RV64_PCS_IDLE_CACHE_BYTES`|Bound unused upper PCS cache;0 releases all unused blocks|8,881 host checks; tiny composite cap0/2GiB exercised on both GPUs, but composite error recovery is not production-qualified|
|`STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS=1`|Group at most256 narrow dependency levels in a256-thread CTA|Six host tests and emitted narrow driver; real GPU narrow execution remains open|
|`STWO_RV64_COMPOSITION_POOL_TRIM=1`|Owner/device-checked joined trim before N2B for arenas at least12GiB|Host control-flow/opt-in tests; GPU phase-trim qualification remains open|

Failure-only private/default pool and device diagnostics are included. Missing
optional runtime APIs reject explicit opt-ins; no default selects a candidate
image or silently falls back. Current host integration passes32 GKR-plan tests,
25 recursion-ready tests,68 Python harness tests, the idle-cache host target,
C++ OOM/trim policy mocks and combined semantic checks. The immutable established
runtime remains the reference for accepted block results.

The largest basket block26235159 requires49CPU+26truth proofs and149recursive
nodes. V1 rejected retained-memory admission because its manifest omitted the
original compact replay environment. V2 restored that environment without
raising caps, completed native proving, then failed a16.844GB outer allocation.
V3 recovered an allocation but later reported N2B status2. Its experimental
composite links a second static CUDA runtime, so stale error-state interaction
is a confounder. No V1/V2/V3 root acceptance is claimed; partial files match the
accepted originals and all failed attempts are preserved. Do not promote the
composite as an OOM-recovery solution.

A clean single-image rebuild was attempted with the original generated AOT
catalogues, idle-cache/narrow code, pool diagnostics and the new public trim API.
Native syntax pilots passed. Core case43 exceeded the180s compiler deadline;
there is no finished monolithic candidate image. The completed256 objects are
preserved, alongside all sources, manifests and failure logs. Resume requires
bounded regrouping of only cases43/44 and reuse of the cache, rather than a cold
rebuild. Exact commands and prepared regrouped inputs are in the durable README.

Remote cache archive:
`/workspace/rv64-monolithic-partial-cache-20261104.tar.zst`

Verified durable local copy:
`/Users/theodorepender/code/cryptography/rv64-proof-artifacts/20261104/build-checkpoints/rv64-monolithic-partial-cache-20261104.tar.zst`

Archive SHA256:
`0a92af98bfeb58efae297d4ef8dfc5be9020693bca9c86d0a5f44af0312977e7`

The two RTX5090s remain running on pod `cps13bvat3xhdo`. No pod stop or deletion
was performed for this handoff. Producer queues, receivers, compiler jobs and
the assistant's automatic stop watchdog are stopped. The local lease is marked
handed to the user; it no longer authorizes new automated GPU jobs. Use
`runpodctl ssh info cps13bvat3xhdo` for the current SSH endpoint.

Further GPU work requires coordination with the user, who is taking over the
host. Before a new benchmark, finish the single-runtime build, qualify both-device
custody/numerical paths, then retry the largest case with exact artifact parity
and a fresh cache-disabled CPU receiver. Only afterward continue the full15
matrix. The4GPU matrix is also open.
