# M4 stream `resident`: receipts (2026-11-04)

These receipts are for 2x RTX 5090 on the shared pod. **Every number is a single observation [M].**

- **Load:** the 1-min load average was 21–60 during these runs, against the protocol's quiet-host bar of 8. Other M4 streams were building and proving at the same time. Each receipt records `load_avg_before` and `load_avg_after`.
- **Parity:** every proof here was compared, file for file, with the M3 integrate scale receipt for its block (`/workspace/m3/runs/integrate/<block>-2gpu-scale/receipt.json`). That covers native bins, the bundle, every recursive proof and the tree. **All 34 served requests are byte-identical.**
- **Acceptance:** the receiver is fresh, separate and CPU-only. It ran with `CUDA_VISIBLE_DEVICES=""`, the setup cache unset, the class store unset and the fold class cache set to 0. **The ArtifactStore directory was renamed out of existence for the whole receive.** All 12 receiver runs accepted.

## Headline: `daemon-warmboot-r7.json`

| block | M3 baseline request | M4 resident request, 1st / 2nd | capture | setup | native | recursion |
|---|---:|---:|---:|---:|---:|---:|
| 26235156 | 34.28 s | **24.68 / 23.94 s** | 2.57 | **0.137** | 5.15 | 16.65 |
| 24628607 | 51.11 s | **35.71 / 37.07 s** | 3.15 | **0.165** | 6.52 | 25.58 |

- **Service:** the driver is `combined-serve` (d6af8aae, commit fe2c2754e). One process serves [26235156, 24628607] × 2 through the spool.
- **Service start: 13.49 s [M], reported here and never in a request.** It covers process start, both CUDA contexts, 683 EAGER library loads (3.05 s per r8), the pool, the session pre-warm from the store (3.2 s + 4.2 s setup-only) and the class preload (11 templates, 0.93 s).
- **Service stop:** 2.44 s.
- **Speedup vs M3 [D]:** 1.39x on 26235156 and 1.43x on 24628607. Setup went from 12.55 s to 0.165 s on 24628607 (76x).

## Gates (stream prompt)

| gate | result | evidence |
|---|---|---|
| cold-service setup ≤ 1.0 s | **met.** 0.93 s (156) and 0.92 s (607) with the store loaded lazily; 0.137 / 0.165 s with `--warm` boot | `daemon-coldservice-r5`, `daemon-warmboot-r7` |
| 2nd request = 1st ±10% | **met with `--warm` + class preload:** 156 is +3.1% (24.68 vs 23.94), 607 is −3.7% (35.71 vs 37.07). Without `--warm` it is **not met** on 156: +12.3% (28.62 vs 25.48, r5) | r7, r5, r6 |
| ≤ 20 `cuLibraryLoadData` per request | **met: 0 per request.** All 683 loads happen before the first request (EAGER, at service start) | `daemon-26235156-eager-nsys-r8` (`cuda_api.per_request`) |
| byte-identical proofs | **met** on all 34 requests | `parity_vs_m3` in every receipt |
| fresh receiver accepts, store deleted | **met** on 12 of 12 | `receivers[*]` in r5, r7, seed1, warmstore1 |
| catalogue drift gate | **met.** catalogues-v3 is byte-equal to regeneration (6 families); v2 fails exactly on the 2 `global` boundary kernels that caused 24628590 | `catalogue-gate-v3.json`, `catalogue-gate-v2-negative.json` |

## Lazy module loading (`daemon-26235156-lazy-nsys1.json`)

`CUDA_MODULE_LOADING=LAZY` gave these results:
- service start 2.19 s, against 4.56 s for EAGER on the same driver (`smoke1`);
- 409 of 686 libraries actually loaded (`cuLibraryUnload` = 409);
- proofs byte-identical.

LAZY is **not** the default:
- LAZY loads go through cudart internally, are not traced as `cuLibraryLoadData`, and cannot be attributed to a request.
- A November 3 native failure listed lazy module allocation under pool pressure as an open hypothesis.

The service keeps EAGER at start, so per-request loads are 0 by construction.

## Other receipts

| receipt | what |
|---|---|
| `serve-integrate-seed1` / `serve-integrate-warmstore1` | M3 integrate binaries and harness only (`combined-batch` as the service, store fresh then reused). Gives cold-service setup 1.01 / 0.72 s with the unchanged binary. |
| `daemon-26235156-smoke1` | first `combined-serve` smoke test, with the setup validation catalogue: warm setup 0.131 s |
| `daemon-seed-r3`, `daemon-coldservice-r5` | class store (no preload) |
| `daemon-warmboot-r6` | `--warm` without class preload: 156 still +10.9% |
| `daemon-seed-r7` | seeds the store for driver d6af8aae |

## Incidents (measured, shared pod)

- **OOM kill:** the r4 run (`--nsys`, 4 requests) was SIGKILLed during its 4th request. The cause was the container cgroup: `memory.max` = 93 GB, shared by all streams, with `oom_kill` = 1. No receipt exists for r4.
- **Disk full:** the first r7 seed hit ENOSPC on `/workspace`, which was at 94%. The failed store write killed the service. Fixed after the measurements: store persistence failures are now logged, not fatal. The commit after fe2c2754e has this fix; it compiles but has not been run on a GPU. Old store namespaces were pruned.

## Adversarial check (2026-11-04, 26235156 only, single observations [M], load avg 39-58)

| run | driver | store | request 1 / 2 (s) | setup 1 / 2 (s) | parity vs M3 | receiver |
|---|---|---|---|---|---|---|
| adv1 (independent re-run of the headline) | d6af8aae | reuse + warm | 25.07 / 25.13 | 0.137 / 0.134 | 35/35 proof files sha-equal, both requests | 2/2 accepted |
| adv2 (fixed driver) | 3b7cdb28 | fresh | 31.52 / 25.05 | 4.86 / 0.124 | identical | 1/1 accepted |
| adv3 (fixed driver, tampered) | 3b7cdb28 | reuse + warm, class 122489c6 seed_vars[0]^=1 | 25.75 / 24.20 | 0.125 / 0.130 | identical | 1/1 accepted |

The parity check was redone outside the harness: sha256 over the sorted list of every `*.bin`,
`*.proof` and `bundle.json` in each proof tree gave `2abc5797...` for both requests and for the M3
integrate tree.

Fixes in this commit, all for liveness: none of them changes a proof byte or the receiver.
- A disk-loaded fold-class template that fails a use-time check (capability, shape or
  `PlanClassSeedLayout`) failed the whole request before. It is now a logged miss
  (`store_reject_on_use`) and that class is rebuilt fresh. `seed_vars`/`n_*` sit outside the stored
  identity digest, so a file corrupted there passed load and then broke the request. adv3 shows the
  rejection followed by byte-identical proofs.
- `STWO_RV64_OUTER_PLAN_CLASS_CACHE=check` now also loads from the store. That makes it possible to
  check a persisted store against fresh plans, which could not be done before.
- Serve loop admission: before this fix, a malformed request, an unknown block or a reused request
  name killed the service, and the file stayed in `inbox/` and killed the restart as well. Such a
  request now gets `done/<stem>.json {"ok":false,...}` and is removed. adv3 injected two of them after
  READY, the service kept going, and both real requests were served.
- Class-store temp files now use a random suffix and are opened exclusive, matching `setup_cache`.
  Two services built from the same driver share one store namespace.
