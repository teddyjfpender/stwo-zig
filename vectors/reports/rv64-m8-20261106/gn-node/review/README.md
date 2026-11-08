# gn-node review (2026-11-07)

Review of `codex/rv64-m8-gn-node` @ 5420efb23 (device seed fill, device statement/FIXED mix, seed_tape / child_binding, production NodeJob). Labels: [M] measured, [D] derived, [E] estimate.

## Findings, verified against the code

| # | finding | verdict | fix |
|---|---|---|---|
| 1 | `outer_device.Recursion.node` freed **every** NodeJob of the previous request on the first `node()` of a new request id. `driver_request.Driver.begin` keeps two requests in flight (slab parities), so request N+1 makes its jobs while N's batches still enqueue or finish. The result is a use-after-free of N's NodeJob and its made OuterNodeJob (and `Recursion.end` was never called by the driver). | CONFIRMED (driver_request.zig `in_flight[2]`, `begin` → `make` → `node`) | 383e51e6d: every job carries its `request` and a `settled` flag (release-stored after `finish`/`abort` return; the worker never touches a job after that). `node()` reclaims settled jobs only, `end(request)` frees that request's jobs, and `deinit` frees the rest. Host test: a pipelined request's `node()` keeps the earlier job alive (`heldJobs` 2), and the settled job is reclaimed later. cb410ff73: `request` defaults to 0 for the standalone check-mode `GnJob`. |
| 2 | `outer_seed.cu` `seed_caps` indexes fixed arrays: shared `at_of[1024]` / `nodes[1024][8]` per query, the 64-bit cap coverage mask + `layer[64]` (cap log ≤ 6), and the FRI coset `level[16]`. The program builder never checked them, so a profile with more than 1024 queries, a cap log above 6, or an unpacked fold step above 4 would write out of bounds on the device instead of failing. | CONFIRMED (robustness; today's profiles are inside the bounds) | 383e51e6d: `outer_seed_device.finish` refuses such a cap at warm time (`error.GnSeedProgramKernelBounds`, `capFitsKernel`), with a unit test. Every real class program on both blocks passes it (the job/check arms below build all of them). |
| 3 | The receipt's "NodeJob host 36–105 us/node" column covers only the seed fill and verdict launches. The body's own stage and enqueue are separate: every body graph was **captured** (never replayed), so the host still issued every body kernel into the capture. | CONFIRMED (measurement scope) | README wording fixed (1688baaae). Body numbers on 25d0e62f are below. |
| 4 | The builder's evidence ran on the frozen a25 base, not 25d0e62f. | CONFIRMED (acceptance gap) | Re-run on 25d0e62f (below). |

Checked and not a defect:
- **Stream order.** The fill's custody stream (lane 0 of `e.ctx()`) is the worker's exec stream, so the peer copy, the fill and the body are ordered on one stream.
- **Seed `dst` bounds.** The `dst` + seeds-per-unit of each op stays within `n_seeds` by construction (`finish`: constants + tape == vars). The kernel checks every gather source against its area length.
- **Soundness.** The fill assembles the recursion circuit's witness. The om31 node re-verifies the child proof in-circuit (transcript, Merkle, FRI), so the device checks are fail-closed diligence, not the soundness argument. A forged child image gives a node proof that does not verify.
- **The `pcs_native.zig` recorder hook** is env-gated (one getenv per native proof) and proof-neutral.

## Re-run on the 25d0e62f base (this review)

Image `/workspace/m3/build/m8-opt-combined/img` (lib 25d0e62f…). The jobs addon and outer-fs addon were rebuilt from this tree against that base (`/workspace/m3/build/m8-gn-node/rev-addon-1`, jobs sha256 0290cb91…, outer-fs 9f1dd752…; recipe as in gn-bind addon-3). The driver was built at cb410ff73.

- [M] **Default gate**, `rv64_gate.sh --stream m8-gn-node --runtime <opt-combined runtime.json>`, 26235156 at cb410ff73: **PASS**. It covers build, Zig + Python unit tests, cold + warm 32/32 + 32/32 byte-identical to the frozen D2 golden, 2/2 fresh CPU receivers and the 19-case corpus (`gate-default-26235156-25d0e62f.json`; run `/workspace/m3/runs/m8-gn-node/rev3/gate-rv3-26235156`).
- [M] **Production NodeJob** (`GN_NODE=job`, `OUTER_JOBS=1 OUTER_DEVICE_CHECKS=1 OUTER_GRAPH_THRESHOLD=1`, proof-only runner `pod/gn_prove.py` with `GN_RUNTIME`):

| block | node jobs (cold + warm) | device bytes == host bytes | image tail identical | 7/7 verdicts accepted | requests vs frozen D2 | NodeJob seed+verdict host / node (min / med / max) | body stage / node | body enqueue / node (graph captured) | body GPU wait / node |
|---|---|---|---|---|---|---|---|---|---|
| 24628607 | 38 (28 leaves) | 38/38 | 38/38 | 38/38 | **39/39 + 39/39** | 37 / 47 / 119 us | 28 / 122 / 313 ms | 6 / 29 / 108 ms | 64 / 350 / 468 ms |
| 26235156 | 30 (22 leaves) | 30/30 | 30/30 | 30/30 | **32/32 + 32/32** | 38 / 49 / 127 us | 22 / 96 / 271 ms | 10 / 23 / 1129 ms | 63 / 357 / 465 ms |

  The timings are host timers (`std.time.Timer`) around the job phases. "Body GPU wait" is the host wait on the body's completion, not a CUDA-event kernel time. The 1129 ms enqueue maximum on 26235156 is a single outlier (not investigated). Host launches per node: 6 NodeJob launches + 1 body graph launch. Graph outcome: `captured` on every node (no replay across requests in the hybrid window).
- [M] **Check mode** (`GN_NODE=check`), 24628607: 38/38 node proofs from device-filled seeds/checkpoint/outputs, outputs and checkpoints identical 38/38, verdicts accepted 38/38, requests 39/39 + 39/39 byte-identical. Seed-fill GPU time 33.8 ms over 38 nodes (CUDA events).
- [M] **Negative**, `FAULT_INJECTION=1 GN_NODE_FAULT_ORDINAL=4`, 24628607: `seed_tape=0x3050006` on fold 4, which gives `GnNodeDeviceRejected`, and the request is refused, as intended.
- [M] Host tests (laptop, memguard 6 GB): `test-rv64-jobs-outer` 112 passed / 1 skipped, including the new lifetime and kernel-bound tests.

Raw files (pod, not in git): `/workspace/m3/runs/m8-gn-node/rev2/` (arm-j-24628607 proof.json sha256 5368a003…, arm-g 3a6e68e6…, arm-n b5db55af…) and `/workspace/m3/runs/m8-gn-node/rev3/` (arm-jr3-26235156 proof.json b80d944c…). producer.stderr sha256: 26f700e3… (24628607 job) and 18d58e31… (26235156 job). Summaries: `job-24628607-25d0e62f.json`, `job-26235156-25d0e62f.json`.

## Still open (unchanged by this review; owners named in the main README)
- Leaf statement tail + outputs + Blake sample tape still come from host values. Native Stage 2 / TruthJob must write them.
- The template seeds section is still packed and uploaded per node (the `device_inputs` flag, `outer_job.zig`/`outer_staged.zig`, not this stream's files).
- Graph replay across requests is unproven. It needs the GPU-native install's stable arena; every node above was captured, which is where the body's enqueue cost sits.
- The check-mode `GnJob` sets the class template's FIXED raw evaluations per node. That is a shared-template mutation, fine for the serial check mode, but the GPU-native install must not run two nodes of one class concurrently on that path (it uses persistent class regions instead).
