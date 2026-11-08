# GPU hygiene delivery audit

This audit applies to the user brief and the eight completion gates in
`design/riscv-proving-stack/rv64-gpu-hygiene.md`. It is a progress audit, not
a completion certificate. The hardware gate snapshot is
`b2da53a24965226b7e29e45d1635932c37267cce9c484733367d50b90129fa5f`.
The final snapshot is
`41239ee7365ece49b2e4cc86a62fcbc5895dbbe552364198bded2434c13bf34f`:
only trailing blank lines in two Python files changed after the gates. The
original bytes, before/after hashes and AST equality are preserved in
checkpoint 7. All other source files, including prover and validation code,
remain byte-identical; the full 178-test Python gate was rerun successfully
on the final pod snapshot and production asset pins were rechecked.

| Gate | Current evidence | Status |
|---|---|---|
| 1. Executable resource/readback contract | `jobs/resources.zig` owns checked sizing and readback policy; worker staging and native node publication consume it. Boundary tests plus the native 24628607 gate and CUDA census cover real use. | PASS for the installed native path |
| 2. Shared allocation/budget schedule | `OuterNodeJob.heldBufferWords` drives both budgeting and allocation. `memory_plan.zig::MainCursor` is used by the pure planner and actual MAIN placement; overflowing reservations refuse before allocation. | PASS |
| 3. Installation/request boundary and legacy retirement | `jobs/README.md` traces the real dispatch, install, begin, finish and publication owners. Installed timing spans are borrowed by request-slot parity. The unreachable `jobs.serve` scaffold is removed. Hybrid class construction and the reference path retain live owners; broader replacement qualification remains incomplete, so they are retained explicitly. | PASS for this cleanup; no production replacement claim |
| 4. Shared validation authority | Gate, canonical runner, basket and activity analyzer use `scripts/rv64_validation.py`. Tests cover pins, effective library overrides, artifact completeness, fresh CPU isolation and error-backed negative-corpus classification. Only PASS exits zero. | PASS |
| 5. Native ranges and actual CUDA census | Both profiled native 24628607 requests have 48 complete ranges covering native/truth stages, seal and leaf/fold/root nodes. CUDA and complete driver receipts agree on two final readbacks, zero private job-slab readbacks, seven capture-release callbacks and zero request event creations. Peer transport remains separately counted. | PASS; shared analyzer finished with fresh-accepted references |
| 6. Focused developer workflow | Existing `dev_test.py` routes resource, runtime, node, native, truth, outer and CPU publication owners to their package tests. Pod check-only and publication execution receipts are in checkpoint 4; current gate units pass 1,392 Zig tests (16 skipped) and 178 Python tests. | PASS |
| 7. Static checks, host tests and bounded proof regressions | All four default/native gates pass frozen cold/warm parity, two fresh CPU accepts each and all 19 selected corpus cases each. The source snapshot remained unchanged throughout. Global formatting passes; full static checks remain non-green on inherited provenance, 139 source-conformance paths and 150 unreachable scripts. No checks or baselines were relaxed. | INCOMPLETE |
| 8. Owner docs, compact evidence and committed delivery | Current owner documentation, checkpoints and the static audit exist. All native gates and activity analysis pass. The commit containing this audit is the reviewable delivery unit; its remote ancestry must be checked through Git. The full static gate remains unresolved. | Owner docs and evidence PASS; verify Git delivery |

The readback comparison is a mechanism observation against the retained
profile, not a controlled latency comparison. Host NVTX durations are enqueue
time, not GPU time. The broader 105 pending catalog cases are outside the
selected 19-case corpus gate. No new speedup, physical peak, new-block latency,
default promotion or complete production qualification is established.

The latest compact evidence is [checkpoint 7](checkpoint-7.json); the final
static recheck is recorded in [static-audit.json](static-audit.json). Raw
proofs, traces and logs remain outside the repository and are referenced by
path and SHA-256. The full objective remains active while these completion
items are unresolved.


## Owner-boundary follow-up

[Checkpoint 8](checkpoint-8.json) records the uncommitted follow-up to the
landed `4a4d01bd5` checkpoint. The installed recursion registry and request-job
owner now fit the existing ceiling, and two demonstrated lifetime/failure
regressions have fixes with focused and broader host evidence. This does not
extend checkpoint 7's hardware qualification to the new code. The full static
gate remains open (138 failing paths), hosted CI has unresolved failures, and
full-proof acceptance plus committed delivery of the follow-up remain pending.
