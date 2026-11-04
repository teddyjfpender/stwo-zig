# Progress ledger and receipt schema (owned by stream `measure`)

Every performance commit in M4–M8 appends **one JSON line per measured run** to
`vectors/reports/progress/<stream>.jsonl` and commits the receipt it came from. One file per stream, append-only:
never edit history, append a corrected row with a `notes` entry instead. `PROGRESS.md` is generated, never hand-edited.

```sh
# on the pod, after a harness run (bench writes receipt.json and receipt-v2.json)
python3 scripts/rv64_m3_pod.py bench 24628607 --stream m4-<s> --tag x --counters --smaps \
    --reference vectors/reports/rv64-m3-20261104/integrate/scale/24628607.json
# laptop: copy the receipt back, then append + render
~/Coding/ge-ops/bin/podget /workspace/m3/runs/m4-<s>/24628607-2gpu-x/receipt-v2.json vectors/reports/rv64-m4-20261104/<s>/24628607-x.json
python3 scripts/rv64_progress.py append vectors/reports/rv64-m4-20261104/<s>/24628607-x.json --stream <s> --milestone M4 --notes "what changed"
python3 scripts/rv64_progress.py render     # rewrites PROGRESS.md from every ledger
python3 scripts/rv64_progress.py check      # validates every row (run before committing)
```

## Row schema (`rv64-progress-row/v1`)

Required: `date` (YYYY-MM-DD), `commit` (source commit the binaries were built from), `stream`, `milestone`
(`v7`, `M3`, `M4.0`, `M4`, … `M8`), `block`, `gpus`, `label` (`M` measured with a receipt, `D` derived from
measured numbers, `E` estimate; never put an `E` in a measured column without the label).

Columns (number or absent; seconds unless noted). Definitions are the receipt-v2 stage boundaries below.

| key | definition |
|---|---|
| `request_s` | request accepted → final proof bytes written |
| `capture_s` | input → last segment's compact records ready |
| `setup_s` | native setup on the request path (cold service unless `config` says warm) |
| `native_s` | native prove (stage 1 + barrier + stage 2; projection/widening count here) |
| `recursion_s` | recursion stage wall (last native proof → final proof today) |
| `verifier_s` | fresh, separate, cache-disabled receiver process wall, per block |
| `rss_peak_gib` | producer whole-process peak RSS (getrusage; = daemon metric once a daemon exists) |
| `rss_request_private_gib` | private non-file-backed RSS at the sampled peak (`--smaps`) |
| `device_peak_gb` | max over GPUs of NVML-sampled used bytes / 1e9 |
| `proof_bytes` | final proof bytes (root today; compress2 from M7) |
| `native_verify_s` | native verify on the critical path (0 when overlapped) |
| `fold_tail_s` | recursion DAG wall after the last leaf finished |
| `syncs`, `launches`, `pool_mallocs`, `library_loads`, `pageable_copies` | per-request CUDA driver-API counts from the counter shim (`--counters`): stream+ctx+event synchronize; cuLaunchKernel(Ex); cuMemAllocFromPoolAsync+cuMemAllocAsync; cuLibraryLoadData+cuModuleLoad*; H2D/D2H copies touching unregistered host memory |
| `loadavg_1m` | pod 1-minute load average at producer start (timing hygiene: quote only quiet runs, < 8) |
| `instructions_m`, `nodes` | executed instructions (millions), recursion node count |

Text: `byte_identical_to` (name of the reference receipt whose every proof hash matches: the strongest
correctness check for scheduling-only changes), `receiver_accepted` (true/false), `config`, `notes`, `receipt`
(repo path of the committed receipt), `run` (pod run dir).

## Receipt schema v2 (`rv64-m4-receipt/v2`, plan §8.1)

Written by the harness as `run/receipt-v2.json` (`scripts/rv64_measure.py build_v2`; also
`python3 scripts/rv64_measure.py receipt-v2 RUN [--reference R]` for any old run). Fixed stage boundaries — no column
can be "won" by moving work into another:

| field | definition |
|---|---|
| `stages.request_s` | request accepted → final proof bytes written |
| `stages.capture_s` / `capture_critical_s` | input → last segment compact records ready / part not overlapped by native work (equal in M3) |
| `stages.setup_s` = `setup_cold_service_s` \| `setup_warm_s`; `setup_install_s` | SetupCache miss / hit; one-time install reported, never hidden (null until it exists) |
| `stages.native_s`, `stage1_s`, `stage2_s` | native prove; schedule.json phase walls. Projection and widening count here, never under capture |
| `stages.native_verify_on_critical_path_s` | 0 when the side thread is joined without waiting |
| `stages.recursion_wall_s`, `recursion_tail_s`, `fold_tail_after_last_leaf_s`, `compress_s` | recursion wall; last native proof → final proof; DAG wall after the last leaf; compress layers (0 before M7) |
| `verifier.verify_per_block_s`, `derive_vk_tables_once_s` | fresh receiver wall; one-time VK derivation (null before M5) |
| `ram.rss_peak_daemon_gib`, `rss_peak_request_private_gib`, `smaps_peak_census` | both RAM metrics (plan R11) + census by mapping category at peak |
| `device_memory.device_peak_gb[gpu]` | NVML sampled |
| `proof_size.proof_bytes_final`, `proof_bytes_root` | |
| `loadavg.start/end`, `host` | timing hygiene |
| `counters` | shim totals per request, per thread, and per recursion node (device-stage window on its lane thread): syncs, launches, pool mallocs, library loads, pageable copies, with API seconds |
| `gpu.nvml_kernel_activity`, `gpu.nsys` | NVML kernel-active %; with `--nsys`: kernel-busy GPU-s (union) vs kernel-sum vs first-to-last span per device and per node kind |
| `correctness` | parity vs accepted v7, receiver verdict, `fingerprint_vs_reference` (every proof hash vs a named receipt) |

Changing a definition requires a new schema name and a note here; old rows keep their meaning.

## Tools

- `tools/rv64-cuda-counters/` — LD_PRELOAD driver-API counter shim (interposes `dlsym` → `cuGetProcAddress`, so it
  works with the statically linked cudart in `libstwo-rv64-native.so`). Pass-through only: it never changes
  arguments or results. Self-test: `selftest.cu` (expected 5 syncs, 5 launches, 3 pageable + 2 pinned copies).
- `scripts/rv64_measure.py` — receipt v2, `fingerprint A B` (proof-fingerprint diff), `nsys RUN` (per-phase/per-node
  extractor), `smaps PID`.
- `scripts/rv64_progress.py` — this ledger.
