# RTX PRO 6000 Blackwell: autoresearch rounds 5 and 6

These rounds extend [rounds 1–2](../2026-10-13-rtx6000-pro-two-rounds/README.md) and [rounds 3–4](../2026-10-13-rtx6000-pro-rounds-3-4/README.md). The objective was to make large one-block Starknet PIEs, leaf wrapping, and recursive folds faster while establishing which PIE geometries can actually fit on an RTX PRO 6000 Blackwell Server Edition. Measurements used one otherwise idle 96 GB nominal card, CUDA 12.8, an SM 120 ReleaseFast build, the production circuit registry (70 queries, 26 PoW bits), four real one-block adapted CPI inputs, and contiguous, verified settlement leaves. The final executable SHA-256 was `61d17917bac386b645c914aaaf5621ffbf47263b139e3120a392409e08fc0ef1`. The fixed coefficient artifact SHA-256 was `4d4fda06dfa3bca19554510a158f6c50abad06a74d29c17885ed4cbb88ada34d`.

These are direct, local diagnostics, not ranked challenge receipts. Every successful `leaf-wrap` and `fold-tree` command completed the product's exact verification before publishing its proof. Candidate proof SHA-256 values were compared with saved reference proofs or their paired control. The receipt's `source_commit` field says `rounds-5-6-final-uncommitted` because the measured source had not yet been committed; the checked-in changes and report are the measured candidate. Inputs and proof objects remain in the local proving-service cache rather than Git.

## Round 5: avoid a redundant 16.3 GB managed-memory round trip

The prior saturated-PIE path explicitly migrated both the 31.87 GB lookup slab and the 16.30 GB main coefficient slab to host and back. The latter is needed again for AIR constraints, OODS, and opening work. We kept the proof-preserving lookup migration but removed the explicit coefficient round trip. `STWO_CUDA_MANAGED_PREFETCH=1` now selects lookup-only migration; `=full` retains the older policy for A/B experiments. The change affects placement, not the statement or transcript.

| Saturated `16309799_16309799` | Old full policy, two runs | New lookup-only policy, two runs | Change |
|---|---:|---:|---:|
| Median complete `leaf-wrap` command | 29.16 s | 22.11 s | 24.2% faster |
| Median Cairo proof and decode | 20.64 s | 16.41 s | 20.5% faster |
| Explicit managed movement, **each direction** | 48.17 GB | 31.87 GB | 33.8% less |
| Sampled whole-device peak | 97,249 MiB | 97,249 MiB | unchanged |

The full command trials were 31.51 and 26.82 seconds with the old policy, versus 20.13 and 24.09 seconds with the new one. The first old-policy run also had a cold 7.57-second ingress, versus roughly 2.2–2.6 seconds afterward; proof/decode is the cleaner comparison. All four produced the identical proof SHA-256 `c2579a0435e8e7e7ef3300c82675808b1e9e6937bd1ba686308f0cd59ca1d54e`. The final rebuilt binary, using the public `=1` default, completed the same saturated leaf in **24.03 seconds** (2.53 seconds ingress, 18.13 seconds Cairo proof/decode, 1.29 seconds wrap) with that same proof hash. The smaller oversubscribed `16309286_16309286` also proved in **12.74 seconds** with the saved reference hash. These managed proofs reached only **4 MiB sampled free** and require a dedicated card; a 200 ms sampler can miss a shorter physical peak.

## Round 6: overlap independent host construction with device proof work

The fold tree had been building the next multiverifier value table only after the previous sibling's GPU proof completed. It now prepares one independent next sibling on a CPU worker while the device proves the current one. Proof submission, verification, and output ordering remain canonical, with one device arena and at most one extra prepared table. `STWO_CIRCUIT_DEVICE_FOLD_LOOKAHEAD=0` restores serial preparation. The initial worker-budget hypothesis failed (`InvalidWorkerBudget` on this host); capping that job to eight workers resolved it before the qualified A/B runs.

| Verified contiguous tree | Serial preparation | One-pair lookahead | Proof SHA-256 / sampled device peak |
|---|---:|---:|---|
| 16 leaves, two runs each | 9.41, 9.11 s | **6.95, 6.95 s** | Identical `998f7b4323d9…`; 27,481 MiB |
| 5 leaves, one run each | 3.48 s | **3.25 s** | Identical `c85a17b8cde…`; 27,481 MiB |

The 16-leaf median complete command fell **25.0%**. Five leaves exercises the odd-leaf carry path. The `leaf-wrap` command also now prepares its proof-independent verified session while Cairo proves. With `STWO_CIRCUIT_LEAF_PREPARE_ASYNC=0` as control, two paired fitting-PIE trials were 5.86 and 5.63 seconds serial versus **5.63 and 5.39 seconds** overlapped (4.1% median improvement). All four leaf proofs were byte-identical to saved H200 and RTX references, SHA-256 `d85db1e1f5fdf6b956a69154092fe52e2293fef65cbe3ab006c33aeb409ebf44`, with about 90,875 MiB sampled device peak. This modest wrap gain is a full-command result; the approximately 1.2-second wrap proof itself did not become faster.

## Exact one-block capacity boundary

The geometry inspector now accepts `--registry` and constructs the same production leaf lane, blowup, and combined arena as `leaf-wrap`. Previously, inspecting a CPI without this lane understated the saturated combined arena by roughly 10 GB. It also reports both the allocated arena and a lower bound: the sum of **simultaneously live** resident slots at each proof phase. The latter cannot be fixed by a different packing order alone.

| One-block PIE | OS steps | EC-OP | Pedersen | Peak simultaneously live | Allocated combined arena | Current result |
|---|---:|---:|---:|---:|---:|---|
| `16309292_16309292` | 20.93M | 360 | 131,671 | 92.215 GB | 93.940 GB | Strict proof, 5.39–5.86 s in wrap A/B |
| `16309353_16309353` | 23.18M | 642 | 150,218 | 95.620 GB | 97.920 GB | Strict proof, 7.04 s in round 3 |
| `16309286_16309286` | 23.21M | 282 | 138,271 | 101.699 GB | 103.123 GB | Managed proof, 12.74 s |
| `16309799_16309799` | 24.39M | 732 | 185,316 | **118.815 GB** | **118.891 GB** | Managed proof, 24.03 s |

CUDA reports 101.976 GB total. With the existing 256 MiB admission reserve, the near-boundary PIE has only 8.8 MB theoretical live-set headroom, before runtime and other allocations. The saturated PIE exceeds that safe physical bound by **17.108 GB**; its planner gap is only **0.076 GB**. Strict allocation rejects it in 2.42 seconds with `InsufficientDeviceMemory`. The resulting boundary is empirical: these two smaller geometries fit strictly on this otherwise idle card, and these two larger geometries do not. It is not a universal OS-step cutoff. In the saturated case, `partial_ec_mul_window_bits_18` doubles its padded rows from 4.19M to 8.39M versus the fitting example, and the Pedersen aggregator doubles from 131,072 to 262,144 rows. Geometry, not merely block count or OS steps, controls capacity.

The peak is at OODS. Saturated main and interaction evaluations occupy 32.61 and 26.95 GB; their coefficients occupy 16.30 and 13.48 GB, with multiple Merkle buffers and fixed columns also live. The 31.87 GB lookup slab is already dead and aliased by that phase, so moving it alone cannot make strict allocation fit. A full strict-memory solution must shorten one or more evaluation/coefficient/Merkle lifetimes or tile/recompute their late OODS and decommit consumers, while preserving the commitment, openings, and proof bytes. The round-3 cold-evaluation eviction experiment slowed the proof because those consumers still needed the data. Kernel tuning or a CUDA DSL may improve fitting-case compute, but neither removes this 17.1 GB live-set deficit without a storage/schedule change. We therefore do **not** claim that the saturated PIE now fits strict device memory or has a lower physical peak; the accepted round-5 change reduces transfer traffic and time while managed oversubscription remains necessary.

The complete per-case geometry is in [geometry_summary.csv](geometry_summary.csv), [boundary.csv](boundary.csv), [phase_live.csv](phase_live.csv), [slot_inventory.csv](slot_inventory.csv), [extents.csv](extents.csv), [trees.csv](trees.csv), [trace_components.csv](trace_components.csv), and [lookup_components.csv](lookup_components.csv). Measured commands, stage times, proof hashes, and sampled device peaks are in [runs.csv](runs.csv), [cairo_stages.csv](cairo_stages.csv), and [proof_checks.csv](proof_checks.csv). [Raw receipts](raw-receipts.tar.gz) contain logs, per-sample device memory, and JSON Cairo reports. No private CPI or proof object is included.

To repeat the geometry screen, build `cairo-trace-geometry` in ReleaseFast and run `cairo-trace-geometry --memory-breakdown --registry vectors/circuit/official/registries/production.json <adapted-input.cpi>`. To repeat a proof trial, build `circuit-recursion-cuda-resident` for `sm_120`, use the same registry and exact CPI, and run [the measurement harness](../../experiments/rtx6000-pro/measure.py). Set `STWO_CUDA_MANAGED_OVERSUBSCRIBE=1 STWO_CUDA_MANAGED_PREFETCH=1` only for admitted oversubscribed inputs. The final CUDA build, local CPU product build, geometry build, 31 focused source-conformance tests, Zig formatting, and whitespace checks passed. The RTX pod was deleted after receipts and selected proof objects were saved.
