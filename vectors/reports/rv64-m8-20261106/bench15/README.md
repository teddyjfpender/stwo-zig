# bench15: the 15-block M3 basket on the final M8 path (prepared, smoke only)

Branch `codex/rv64-m8-bench15` from `codex/rv64-m7-integrate @ c72b51646`. Script: `scripts/rv64_m8_bench15.py`
(tests: `scripts/tests/test_rv64_m8_bench15.py`). Labels: [M] measured, [D] derived, [E] estimate.

## What it does

One command over the 15 M3 blocks (`vectors/reports/rv64-m3-20261104/summary.json`, M3 sum 1,843 s [M]). It runs them in
ascending M3 request time and stops on the first proof, parity or receiver failure. Each block:

1. **Headline services.** Arms are interleaved (`A B C A B C`, `--rounds 3`). Each service is a fresh `combined-serve`
   with a cold and a warm request. It is built by `rv64_m7_integration_stack.command` (the canonical runner's service
   command, the same one `rv64_gate.py` uses): the frozen preset's `baseline` arm plus an `STWO_RV64_M8_*` overlay.
   The quiet gate is enforced. A quiet-gate timeout is retried (`--quiet-retries`) and is never counted as a proof
   failure.
2. **Byte parity.** Every request of every arm must equal the block's first proof. On the two dev blocks, every
   request must also equal the frozen D2 golden (`rv64_gate.frozen_parity`).
3. **Fresh CPU receivers** run after all timing, on the retained reference proofs (or `--receivers per-arm`).
4. **Profiled service** (`--profile warm`): one Nsight service per arm for kernel GPU-seconds (`rv64_m7_gpu_seconds.py`,
   CUPTI union) and Nsight launch/sync counts. These services are never in the headline medians.
5. **Pruning.** Proof payloads and Nsight files are deleted once checked, and `producer.stderr` is gzipped. A service
   keeps about 300 KB, and a block needs about one service of proof disk at a time. The run refuses to start a service
   below `--min-free-gb`.

Resumable: rerun the same command and it skips finished blocks and services. If the configuration or assets changed,
it refuses to resume.

It does not start if `gpu.lock` is held when it starts (`--wait-for-gpu` overrides). It never takes the lock itself; the
harness takes it per service.

| arm | overlay |
|---|---|
| `default` | none (legacy owner path) |
| `outer` | `STWO_RV64_M8_OUTER_JOBS=1` + addon + outer-fs + pinned 2365587456 (the outer-fold gate env) |
| `native` | `STWO_RV64_M8_NATIVE_JOBS=1` + addon (the native-hybrid gate env) |
| `hybrid` | outer + native |
| `jobs` | `STWO_RV64_M8_JOBS=1` (fails closed today: `M8RequestProviderNotLanded`) |

Blocks with ≥ 40 CPU segments also get `STWO_RV64_PCS_IDLE_CACHE_BYTES=0`. This is the proof-neutral M3 fix, used from
25229951 onward.

Per block and arm the output reports:
- proving time: the service request wall, from input bytes through capture (witness generation), native and recursion
  to the root. This is the Ethproofs boundary: no fetch, no submit;
- client request time;
- capture, setup, native window, recursion after native, and the tail [D];
- kernel GPU-s and GPU busy [D];
- sampled device peak, and per-node job-arena peak [D];
- launches and syncs per node: [M] job receipts where the arm runs OuterNodeJobs, otherwise Nsight counts / nodes [D].

The M3 and M7 baselines are shown alongside. The output is `bench15.json`, schema `rv64-m8-bench15/v1`, plus
`bench15.md`.

```
# on the pod, from /workspace/m3/src/m8-bench15 (never inside flock gpu.lock)
python3 scripts/rv64_m8_bench15.py pin --driver ... --receiver ... --addon ... --outer-fs ... \
    --source-commit <sha> --copy-to /workspace/m3/build/m8-bench15/pinned-<sha> --out /workspace/m3/runs/m8-bench15/assets-<sha>.json
python3 scripts/rv64_m8_bench15.py check --assets <assets.json>
python3 scripts/rv64_m8_bench15.py estimate --arms default,outer,native,hybrid
python3 scripts/rv64_m8_bench15.py run --smoke --arms default --assets <assets.json> --out /workspace/m3/runs/m8-bench15/<name>
python3 scripts/rv64_m8_bench15.py run --arms default,hybrid --assets <assets.json> --out /workspace/m3/runs/m8-bench15/<name>  # in tmux
```

Harness change in `rv64_m4_resident.py`:
- `--bench-basket-block` admits exactly one M3-basket block per service, with `--repeat` ≤ 2. The owner's one-block-at-
  a-time rule stays enforced by the bench's ascending, stop-on-first-failure order.
- `parity_vs_m3` is now informational when the M3 receipt is missing (25229951 has only a diagnostic M3 run).

## (b) Inputs check [M] (`check-c72b51646.json`): READY, nothing missing

- **Every block's inputs are present:** `inputs/requests/<b>.json` and `inputs/<b>.bin`. The input SHA-256 matches each
  request, the `guest.elf` SHA-256 matches, and the plan-template job and segment count match. The sizes range from
  1.74 MB (26235156) to 14.7 MB (24628611).
- **Witness:** it is not stored. Capture regenerates it from the input bytes inside every request.
- **Golden:** a frozen D2 golden exists only for the dev blocks 26235156 and 24628607, and both are present. The other 13
  blocks use cross-arm and cold/warm byte parity plus fresh CPU receivers.
- **Regenerating inputs:** `python3 scripts/rv64_m3_pod.py inputs` copies them from the read-only originals
  (`/workspace/rv64-gpu-session/two-gpu-ready-fixed-full15`, present). The golden is the committed
  `rv64-m7-20261105/d2-composed` package.
- **The only gap is informational:** 25229951 has no `runs/integrate/25229951-2gpu-scale` M3 receipt, so its M3 parity
  is recorded as unavailable.
- **Assets (`assets-c72b51646.json`):** pinned copies under `/workspace/m3/build/m8-bench15/pinned-c72b51646/` (139 MB).
  The driver `1d5cb14a…` and receiver `fa5ee44b…` are the outer-fold-review gate builds (1148a45da; c72b51646 adds
  receipts only). The addon is `12a3a079…` and outer-fs is `166556d1…`. The frozen CUDA runtime is `p0-runtime.json`.
  The `native`/`hybrid` arms need the integrated addon and driver once native-hybrid lands, so re-pin then.

## (c) Smoke [M] (`smoke-1-bench15.*`): 26235156, default arm, 1 round + 1 profiled service, diagnostic quiet

| | cold | warm | capture | native window | recursion after native | kernel GPU-s | GPU busy [D] | launches/node [D] | syncs/node [D] |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 26235156 default | 23.33 s | 10.28 s | 1.78 | 3.36 | 5.00 | 8.16 | 38% | 2789 | 121 |

- 4/4 requests byte-identical to the block reference and to the frozen D2 golden.
- 2/2 fresh CPU receivers accepted (30.2 s and 30.1 s).
- The profiled warm request (10.60 s) was byte-identical to the fresh-accepted reference.
- The walls are unqualified (diagnostic quiet mode).

Pod receipts:

| receipt | path (under `/workspace/m3/runs/m8-bench15/`) | sha256 |
|---|---|---|
| block state | `smoke-1/blocks/26235156.json` | `23b3c6d8…` |
| headline service | `daemon-26235156-r2-smoke-1-26235156-default-h0-a1-00-baseline/receipt.json` | `6791af5b…` |
| profiled service | `daemon-26235156-r2-smoke-1-26235156-default-p0-a11-00-baseline/receipt.json` | `daac7459…` |

## Wall-time estimate [E] (`estimate.json`)

Method: cold and warm walls are linear in M3 request seconds through the two dev-block calibration points. Calibration:

- default: 24.0/10.45 s on 26235156 (gate) and 29.8/12.8 s on 24628607 (M7 p1 headline);
- outer: 40.7/16.65 s and 50.0/20.1 s (outer-fold-review gates);
- native: default + 2.5/1.7 s (native-hybrid diagnostic).

Each service adds about 20 s of overhead. Each arm runs 3 headline rounds plus 1 profiled service at 1.5×.

| arm | GPU wall, 15 blocks | 26235159 cold / warm |
|---|---:|---:|
| default | 1.8 h | 99 / 41 s |
| outer | 2.7 h | 160 / 61 s |
| native | 1.9 h | 101 / 42 s |
| hybrid | ~2.3 h | ~119 / 48 s |
| jobs | (fails closed today) | – |

- Fresh CPU receivers add about 1.0 h in total.
- All five arms together come to about 12 h; default + hybrid is about 5.2 h.
- The longest single service (lock hold) is about 6 min, under the 15-minute rule.
- The big-block numbers are extrapolations. At M8 no block beyond 24628607 has run on the D2 profile (M7 ran 24697070
  cold once), so a big-block OOM is the main risk. The run stops on it.
