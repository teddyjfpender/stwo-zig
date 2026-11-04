# GKR route: in-process direct capture (plan phase P2, plus P4)

Block 24,628,607 (26,894,777 steps, 7 segments), V3 GKR route (`rv64-word16-ethereum-gkr`),
evmone v3 client, default `conjectured128_b2_q108_p20_fold4` profile. Plan:
`design/riscv-proving-stack/rv64-block-to-inputs-plan.md`. Base: main `89f607a22`.

## What changed

- **Reused from #314** (cherry-picked `460cc14a2`, kept as its own commit): `JOBS=-` selects
  `direct.zig` (in-process walk → `Packet.fromNative` → `captureOne` → ordered ledger) in
  `produce-candidate` / `produce-control` / `plan` / `capture`, and
  `capture_options.execution_workers` selects the fast first pass plus parallel segment walks.
  No packet files, no SHA-256, no fsync, no Poseidon frontier graph, no terminal RAM proof on
  this route (none carries authority on the GKR route, `packet.zig:1-3`).
- **New here:**
  1. Execution starts **before** expected-image/program init (`direct.Started.start`; the
     CLI parses resources first). Admission is unchanged: every batch still passes
     `Packet.fromNative` against the receiver-side image, in index order.
  2. The in-process walk no longer builds the legacy Poseidon chunk512 sparse cache of the
     initial image (`Request.Options.poseidon_initial_cache = false`, ≈137 ms of a 218 ms
     `Request.init` in the profile). The walk never read it. Durable collection
     (`nativeprepare`) still builds it (tested).
  3. The capture window is now 1..16 on both routes (it was capped at 2, `capture_options.zig:11`).
  4. Ledger: one hash lookup per LS event plus a per-shard capacity hint. Contents are
     unchanged and boundaries are sorted (ledger 0.46 → 0.40 s).
  5. `block_to_inputs` in the capture/report JSON gives init, T_first (segment 0 captured and
     its ledger shard built), the last segment, all inputs, and the ledger total and finish. It
     is measured the same way on both routes (`Capture.Ordered`).
  6. **P4:** `Image.Owner` reads inputs up to `INPUT_CAPACITY_MAX - 4` (the same bound as
     `Request.init`) instead of 4 MiB, in producer and receiver. Inputs stay SHA-256 pinned.

## Block-to-inputs, 24,628,607 (AC power, `capture` mode, 3 runs each, `capture-timings-ac.json`)

"Before" = main: a separate `nativeprepare` process (4.13 s, measured by the coordinator on
main `89f607a22`: traced walk, Poseidon graph, packet SHA, write and fsync, 1.69 GB) and
then the packet import in the GKR CLI.

| Route | init | T_first (segment 0 inputs ready) | T_all (all segment inputs ready) |
|---|---:|---:|---:|
| main, packets (`nativeprepare` 4.13 s + import, inflight 2) | 0.14 s | ≈4.13 + 0.70 = **≈4.8 s** ¹ | 4.13 + 2.03/2.08/2.10 = **≈6.2 s** |
| #314 as-is (direct, 7 workers, inflight 2) | — | — ² | 1.81 / 1.85 / 1.90 |
| **this branch, direct, 7 workers, inflight 7** | 0.22 (overlapped) | **0.93 / 0.96 / 0.97 s** | **1.30 / 1.33 / 1.35 s** |

¹ T_first on main from this branch's packet route (same import code; 0.69 / 0.70 / 0.71 s from
CLI start), with all packets already written. ² Not instrumented in #314.

Sweep (one run each, s): w7i2 1.47 / T_first 0.88; w4i4 1.33 / 0.91; w3i3 1.42 / 0.90;
w7i16 1.35 / 0.98; w14i16 1.35 / 0.98; serial walk (w0i2) 1.95 / 0.94.

Segment 0's critical path (w7i7): batch ready 0.21 s after capture starts (the walk started
0.22 s earlier, overlapping init), admission 0.03 s, `captureOne` ≈0.32 s, ledger shard 0
≈0.15 s (first-touch inserts). T_first ≈0.9 s is the floor for P2 at the fixed 4,194,303-step
batch. Going below it needs P3 (chunked parallel replay inside a segment and a parallel
ledger). The serial ledger (0.40 s total) is the main tail in T_all.

## Gates

| Gate | Result |
|---|---|
| 4-packet prefix, direct (`d4`) | `bundle.json` + 13 `*.bin` byte-identical to `../rv64-gkr-memory-20261102/proof-files.sha256`; fresh `verify-prefix-candidate` accepts |
| 4-packet prefix, packet route, new binary (`p4`) | byte-identical (same file); fresh receiver accepts |
| complete block, direct (`dfull`) | `bundle.json` + 20 `*.bin` byte-identical to main `89f607a22` `fbmain`; fresh `verify-candidate` accepts, `completed_ethereum_block: true`; peak RSS 15.5 GB (main fbmain 17.5 GB) |
| suites (ReleaseSafe) | truth-gkr, services-gkr-local, keccak-throughput, word16-v3-services, word16-combined-services, word16-execution, capture-prefetch all rc=0 (`suites-summary.txt`; word16-v3-services was memguard-killed at the 8 GB reservation, RSS 10.5 GB, and passed when rerun at `--gb 14`) |

Producer runs: `run.sh BIN OUT PREFIX JOBS RESOURCES` (JOBS `-` = direct) with
`resources-direct.json`. Proof runs were on battery, so their prove times are not quoted.
Hashes are in `proof-files.sha256`; per-run summaries are in `*.summary.json`.

## P4: basket inputs over 4 MiB (`basket-summary.txt`, `basket.sh`)

Adapted inputs (evmone v3 adapter): 10 of 15 are over 4 MiB. The main binary fails all 10 in
`Image.Owner.init` with `FileTooBig`. The other 5 get past image load, then stop at the new
resource field, which the main binary does not know. With this branch, **all 15 blocks**
admit and capture a 1-packet prefix. **8 blocks capture end to end**, all with
`final_pc = terminal_pc`: 26235156 (15.3 M steps), 24628607, 24647140, 25229957, 24628608
(38.6 M), and three that were over the cap: 24626900 (49.1 M), 24697070 (57.8 M) and
24697073 (60.4 M). Peak RSS was 4.0–8.6 GB (4 workers, inflight 4). The 7 largest blocks
(91–184 M steps est.) were not captured end to end on this shared 36 GB host. Capture
retains about 140 B/step, so those need about 13–26 GB. They are not proven here.

## Not done / open

- T_first ≤ 30 ms and T_all ≤ 0.3 s need P3 (minimal trace, parallel chunk replay, parallel ledger).
- The walk's request and `Image.Owner` still load and authorise the image twice (now
  concurrently). Sharing one image would save about 0.08 s of CPU but couples
  producer and receiver ownership.
- Proving still starts only after all segment inputs are ready. Streaming segment 0 into
  the prover is outside P2.
