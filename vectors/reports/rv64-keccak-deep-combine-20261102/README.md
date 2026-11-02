# Keccak truth DEEP quotient at blowup 2: root cause and fix

Block 24,628,607, 4-packet prefix, V3 GKR route (`rv64-word16-ethereum-gkr
--security-profile P produce-candidate`), evmone v3 client, jobs and
`request.json`/`resources.json` from `../rv64-gkr-route-speedups-20261102/`
(`run.sh` here is the exact runner). 14-core M4 Max, AC power, memguard (22 GB
reservation; one heavy job at a time). Base binary: merged `16f9fc378`
(the `gkrmain` build used for the #313 receipts). Fix binary: this branch,
ReleaseFast. `STWO_ZIG_PROFILE_OM_DOMAIN=1`, `profile_stages=true`.

## Root cause

The Keccak truth (log 18 trace, 1,923 MAIN + 1,560 INTER columns, compact
coefficient storage) builds its DEEP numerators in
`pcs/quotients/combined_setup_family.zig` `combine`: 10,063 (column, sample
batch) members are folded into 11 OM31 aggregate views (8 coordinate planes
each), then FFT'd. `STWO_ZIG_PROFILE_WIDE_QUOTIENT=1` and `/usr/bin/sample`
(`baseline-b2-keccak-quotient.sample-top.txt`) put almost all of the stage in
`CombineContext.run`; the row loop, FFT and FRI layers are small.

The work is identical at both blowups (same 10,063 members, 2,762,211,328
source rows, same 11 views); only the view length changes (2^19 vs 2^20).
The old schedule accumulated every member directly into the view planes.
All 7 views of the large class are separate power-of-two allocations
(2 MiB per plane at blowup 2), so for one chunk the 56 destination planes and the
source chunk all land in the same L1 sets and thrash. That this is set conflict, not
arithmetic or bandwidth, is supported by: identical work at both blowups with a 5x
time difference; the large run-to-run spread at blowup 2 on identical inputs
(Keccak quotient 13.8 to 27.8 core-s, which tracks allocation placement); and the
layout-only fix below removing it. Why the 4 MiB planes at blowup 4 escape it was
not isolated further. This is not lazy per-query recomputation, a domain fast path
or sampled-point batching. Those are blowup-invariant here.

`numerator_combine` for the Keccak truth (wall, `combine-phase-lines.txt`):

| | blowup 2 (conjectured128) | blowup 4 (proven) |
|---|---:|---:|
| base | 2.458 s, 2.271 s | 0.491 s, 0.490 s |
| fix (64 KiB tile) | 0.518 s | 0.535 s |
| fix variant 32 KiB / 128 KiB tile | 0.693 / 0.488 s | 0.733 / 0.510 s |

## Fix

Each combine task now accumulates into one contiguous per-task tile on the
stack (all views x coordinates of the height class, at most 64 KiB, as many rows
as fit, a multiple of the vector width). It walks the members in the same
column-outer order and copies the tile into the view planes once. A class too
wide to tile (fewer than 32 rows fit) keeps the old in-place schedule. M31
addition and multiplication are exact and canonical, so every view value is the
same field element. Proof bytes are unchanged.

## Measurements (clean runs, no wide-quotient timers)

| conjectured128, 4 packets | base run 1 | base run 2 | fix run 1 | fix run 2 |
|---|---:|---:|---:|---:|
| Prove (wall) | 47.16 s | 48.64 s | 46.41 s | 45.88 s |
| Recorded stage core-s | 372.4 | 383.0 | 362.1 | 363.1 |
| DEEP quotients + FRI commit, all proofs (core-s) | 51.8 | 58.6 | 41.2 | 41.0 |
| Keccak truth `fri_quotient_build_and_commit` wall / core-s | 1.79 / 13.8 | 2.38 / 18.6 | 0.73 / 5.4 | 0.72 / 5.3 |
| Keccak truth proof wall (critical path) | 20.45 s | 21.13 s | 19.03 s | 19.01 s |
| Process wall / user-s | 53.96 / 437.5 | 55.56 / 448.6 | 53.55 / 428.0 | 52.82 / 428.6 |

The #313 receipt had 27.8 core-s for the base Keccak quotient. The four profiled
base runs here measured 20.9, 23.6, 19.4 and 13.8 to 18.6 core-s. The fix measured
5.3 to 6.8 core-s in every blowup-2 run, at or below blowup 4's 6.4 to 7.2. The
CPU proofs' combine also gets faster (0.27-0.45 s down to 0.20-0.26 s each at blowup 2). At
blowup 4 the Keccak quotient stage reads 6.4-7.2 (base) and 6.6-8.4 core-s (fix)
across 3+4 single runs; its combine moves 0.49 to 0.51-0.53 s, within noise.
Single runs; wall deltas below ~5% are noise.

## Byte identity

`sha-list-digests.txt`: the digest of the sorted `sha256` list of every artifact
(`bundle.json`, `cells.bin`, 4 CPU + 8 truth proofs, `stage-one.bin`) per run.
All 11 blowup-2 runs (base and fix, with and without timers, three tile sizes)
equal `b2.sha256`, and that file equals the #313 `cj4.sha256`. All 7 blowup-4
runs equal `b4.sha256`, whose proof files equal the #313 `pv4.sha256`.

Unit test: `coefficient storage tiled combine matches the scalar column-serial
reference` (`test-stwo-prover-coefficient-storage`) checks tiled classes with a
tail tile, a class too wide to tile (direct path), a class smaller than one tile,
sources shorter than the view, odd lengths, and an untouched view with no members
against the scalar formula. It was confirmed to run by forcing it to fail once.
