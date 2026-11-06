# gpu-recursion: class plans + first device check (recursion stream, M8 GPU-native)

Branch `codex/rv64-m8-gpu-recursion` @ 534c2638c (on the contract 065e248e6). Labels [M]/[D]/[E].

## Landed (default off, no proof byte depends on it)
- `jobs/outer_class_plan.zig`: one `Slot` per cached class. The first node builds the plan under the slot lock and every later node borrows it. A different process signature (stream knobs, compact mode, PCS framing version, symbol addresses) never reuses a plan.
- `STWO_RV64_M8_OUTER_CLASS_PLAN=1` (H18–H20):
  - Leaf statics are cached by authority identity (identity binds the FIXED root, component logs and output count). Fold statics were already cached this way.
  - initWhole's stream schedules, composition commit stream and PCS framing (`PcsJob.prepare` at the placeholder point) become a class `WholePlan`.
  - Nodes borrow the plan. The PCS clone shares the template's 17 immutable sections and owns only its column table, which `bindColumn` writes per node.
  - Host budget is `STWO_RV64_M8_OUTER_CLASS_PLAN_HOST_MB` (default 64 GiB; the pod has 377 GB RAM [M]).
- `jobs/outer_device.zig`: `RecursionFactory.warm` / `class_of` run over a class registry (`register(id, key, info)`), with one `ClassEntry` per class. A sealed cache refuses new classes. `truth` and `node` still fail closed.
- `STWO_RV64_M8_OUTER_DEVICE_CHECKS=1` adds `NAT/rv64/jobs/outer_checks.cu`, the `lookup_sum` kernel (Check 0x0302):
  - It computes the om31 LogUp closure from the section's claims, z and alpha plus the staged expected outputs.
  - It runs at the end of every whole-node body, inside the captured graph.
  - It writes a Verdict word and a per-node tag into the job slab.
  - finish requires the device verdict and the host reference to agree.
  - `STWO_RV64_M8_OUTER_CHECK_FAULT_ORDINAL=n` is the negative test: node n gets one corrupted public limb on the device side only.

## Evidence
- [M] Local `zig build test-rv64-jobs-outer`: 98/98 under memguard. This covers slot build-once, concurrent first nodes, signature bypass, the budget, factory warm and seal, and verdict tag/stale/unset handling.
- [M] Pod builds: zig driver and receiver (ReleaseFast), plus addon `jobs-addon-b4/libstwo-rv64-jobs.so` sha256 5d7065c7…3828.
- [M] Pod unit suite (the gate's unit-zig set plus test-rv64-jobs-outer): 827/832 passed, 5 skipped.
- GPU gates: **NOT RUN.**
  - Both GPUs have been held since 19:27Z by pid 3302210. It is the idle orphan combined-serve from m8-native-hybrid (30.1 GB per GPU [M]). This stream does not own it and did not touch it.
  - Pipeline `/workspace/m3/runs/m8-gpu-recursion/g1` (tmux `rec-gates1`, `gates.sh 534c2638c g1 b4 ...`) waits until both GPUs are under 2 GB. Then it runs these arms in order:
    - default 26235156;
    - hybrids + new flags on 24628607;
    - hybrids baseline on 24628607 (the A/B);
    - JOBS=1 + new flags on 24628607 and 26235156;
    - the negative fault arm on 26235156 node 4 (expected FAIL with OuterDeviceLookupSumRejected);
    - hybrids + new flags on 26235156.

## Baseline being attacked
Feeder gate-c 24628607, warm request [M] (`runs/m8-feeder/daemon-24628607-r2-gate-gate-c-24628607-00-baseline/producer.stderr`, GPU_M8_OUTER_NODE_HOST):
- prestage: 0.18–0.34 s per leaf;
- init: 0.09–0.57 s per node, 1.87 s once;
- stage: 0.03–0.19 s;
- direct enqueue: 0.07–0.16 s.

Every node ran `outcome=direct`. Per-node GPU time is 0.07–0.51 s (CUDA events). Expected with the class plan [E]: prestage ≈ 0 and init a few ms on warm nodes, which removes about 0.4–0.9 s of host time per node from each lane. Unverified until g1 runs.
