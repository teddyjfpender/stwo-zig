# Large guest end-to-end campaign — 2026-09-24

The selected fixture is **4,096 sequential SHA-256 hashes**, starting from 32 zero bytes, with the final 32-byte digest committed as public output. This is a real software guest proof: 14,905,704 retired RV32IM instructions. Input is a little-endian u32 iteration count. Both guest sources use sha2 0.10.9, with matching loop, initial value, bound and digest. Our statement authenticates the four-byte iteration-count input; the final peer guest additionally commits that count after the digest (36 public application bytes), so both proofs bind the same logical `(count, digest)` claim. Platform-specific I/O encodings differ. This is a research workload, not an official CSP result.

The implementation follows ZisK's checked-in `examples/sha-hasher` computation. Our peer wrapper omits that example's magic-number metadata and printing, and commits the digest plus the iteration count required to match our authenticated input binding. This is the software lane; it does not establish performance of accelerated SHA precompile guests.

## Local calibration

Fresh-process, single-sample CPU measurements on battery, ReleaseFast; BLAKE3, 70 queries, 26 PoW bits, blowup 2. `STWO_ZIG_WORKERS=16` and `STWO_ZIG_MERKLE_WORKERS=16` were supplied; the current full-width report emits `workers: null`, so these are requested limits rather than independently measured active worker counts. No competing build or timing run was active for these samples.

| SHA iterations | Instructions | Execution | Witness | Proving | Fresh verification | Full transaction | Peak physical footprint |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 128 | 466,152 | 0.023 s | 0.130 s | 0.740 s | 0.114 s | 1.113 s | 1.39 GiB |
| 1,024 | 3,726,696 | 0.165 s | 0.309 s | 3.582 s | 0.149 s | 4.342 s | 4.87 GiB |
| 2,048 | 7,453,032 | 0.341 s | 0.530 s | 6.643 s | 0.208 s | 7.915 s | 7.52 GiB |
| **4,096** | **14,905,704** | **0.679 s** | **0.978 s** | **13.010 s** | **0.299 s** | **15.243 s** | **14.17 GiB** |

Full transaction also includes admission and artifact encoding; process startup/teardown are measured separately in fixture JSON. These are calibration observations, not repeated-run medians or head-to-head speed ratios. The selected size is in the requested approximately-20-second class; it is frozen independently of peer timing. The smaller two samples precede the runtime roster fix; the larger two follow it. Execution+witness+proving for the selected case is 14.667 s.

The 4,096 case spends about 85% of the transaction in proof generation. Guest execution alone is not the dominant cost. Half-size is qualified; doubling above 4,096 requires a new guest bound and checking the existing per-proof execution/component capacity, then segmented/recursive execution as needed. That doubling is not yet measured.

## Scaling defect found and fixed

At 2,048 hashes the old prover failed with `Overflow` before proof production. `overflow-trace.log` pins the failure to `universal_component_roster.Manifest.placement`: appending the hash components overflowed an 8-bit claimed-sum index after the native execution shards.

The shared runtime roster now uses u32 placement indices; native component offsets and compact-range end placement use the same width. `PlacementFor` keeps the legacy fixed-roster manifest's u8 field and seal encoding unchanged. The fix is shared across typed assemblies, not selected by guest or benchmark. The 2,048- and 4,096-hash proofs now verify with unchanged cryptographic settings.

207 focused ReleaseSafe tests pass, including crossing indices 255–257, rejecting actual u32 overflow, typed provider checks, and fixed manifest checks. The first broader run exposed a pre-existing public-data test expecting transcript version 2 while production already uses 3; the stale test literal was corrected, without changing production transcript bytes. Both logs are retained. A fresh 1,024-iteration proof matches the pre-fix statement, transcript, output and proof SHA-256 exactly (`small-proof-compatibility.json`).

## Verified native-system observations

The final **unsampled** peer run (`peer-4096-bound.json`) produced a complete aggregated proof, verified it against the guest's BLAKE3 program key, and checked its public count and digest. An independent Python SHA-256 oracle agrees with both systems (`same-statement-qualification.json`).

| Metric | STWO-Zig | ZisK |
|---|---:|---:|
| Proving transaction plus final verification | 15.243 s | 263.348 s |
| Separate peer context/ROM setup | included in local transaction where applicable | 3.645 s |
| Process wall time | 15.293 s | 268.186 s |
| Peak physical footprint | 14.168 GiB | 46.429 GiB |
| Proof artifact bytes | 7,007,552 | 831,536 |
| Guest/VM instructions (different ISAs; not comparable counts) | 14,905,704 RV32IM | 9,818,886 ZisK internal |
| Proof structure | single execution STARK | AIR proofs + recursive aggregation + final STARK |
| Native security configuration | 70 queries / 26 PoW / blowup 2 | Main AIR: 211 / 24 / blowup 2; final: 106 / 24 / blowup 4 |

**Single-run native profiles, not security-normalized speed ratios.** Same host on battery; no concurrent build, proof, or sampling in the final runs. The peer uses Goldilocks and a different FRI schedule/security analysis; matching query counts alone would not establish equal soundness. Explicit peer setup is excluded from its proving interval. Peer proving already includes internal proof checks; its additional program-key-bound verification takes 0.0187 s. Local full transaction includes fresh serialized-artifact verification. Peak footprint includes each process's setup and retained proving resources.

Native peer timing: contribution calculation 10.294 s; **combined base proving and inner recursive aggregation 242.924 s**; final outer proof 9.929 s; internal final verification 0.090 s. The combined timer joins recursive workers too, so it cannot be reported as base proving alone. A finer base/recursion split remains to be instrumented.

The earlier digest-only peer diagnostic (`peer-4096.json`) took 300.457 s proving plus 57.762 s first-time setup and included one second of sampling. It did not commit the iteration count. It is retained as diagnostic evidence only, not pooled with the final input-bound result. Sampling showed active polynomial evaluation (`evmap`), NTT and field/expression work; it did not indicate a stalled scheduler. These are leads for component benchmarks, not a complete time attribution.

### Peer setup provenance

- ZisK checkout `5c5f81c96929abed88894473ec6060b1b545b5c5` remains clean. Host uses locked crates.io proofman 1.3.0-alpha packages, distinct from the earlier standalone proofman source compilation.
- Official BLAKE3 proving key: 6,460,671,142-byte archive, 19,549,200,731 extracted bytes before generated constant trees. Published MD5 verified; SHA-256 recorded in `peer-key.json`. Installed under `/tmp/stwo-zisk-guest-e2e-20260924`; existing installed keys were retained.
- CPU build uses the earlier pinned nlohmann/json.hpp through CPATH and isolated protoc 31.1. No peer source patches were needed.
- Guest uses pinned ZisK 4.0.0 (`rustc 1.94.0-dev`), isolated and linked as `stwo-zisk-peer-4`.
- Requested RAYON_NUM_THREADS=16 and OMP_NUM_THREADS=16. Peer logs confirm 16 process workers and a separate eight-thread recursive witness setting; this is not a claim that every internal pool shares a strict global 16-thread cap.
- Final host and guest binaries, dependency locks, proof artifacts, parameters, raw logs, power readings and checksums are retained locally.

Next: instrument base and inner recursive proving separately, then run the doubled workload through our segmented/recursive path. The current native comparison does not establish superiority on larger recursive programs or other hardware.

## Reproduction

Local product: `python3 scripts/zig_serial_build.py stwo-zig-riscv-cpu -Doptimize=ReleaseFast`.

Guest: in `guest-stwo`, run `cargo build --release --locked`. From the repository root, run `python3 autoresearch/notes/2026-09-24-zisk-guest-e2e/calibrate.py 4096 repeat-1`. Use a new label for each retained run. The script refuses to overwrite existing results and checks successful proof verification, expected output digest, ELF/input hashes and 70/26 settings before recording qualification. `calibrate.py` accepts an optional second positional run label to retain additional samples without overwriting artifacts. `test_roster.py` runs the focused regression gates. `build_peer.py` serializes the peer CPU build.

The initial `sha256-16384` attempt records that the existing CSP ELF rejects inputs beyond its declared 4 KB region; it is not a timing result for this chain. Original overflow diagnostics remain in `overflow-trace.log`. Files called `.proof.json` are binary B3RVART1 proof artifacts, as emitted by the full-width product.

The peer benchmark host requests a complete aggregated proof, verifies it against the guest verification key under BLAKE3, and compares the proof-derived public digest against an independent host SHA-256 chain. It separates context/ROM setup, proving, and final verification; per-AIR and recursion phases remain in the native log. The initial key/constant-tree preparation is not counted as guest proving.

Peer reproduction: `build_peer.py`, `build_peer_guest.py`, `build_peer_host.py`, then `run_peer.py 4096 new-label`, all from this directory via Python (or repository-relative script paths). The documented isolated toolchain, key and protoc paths must exist. `run_peer.py` limits the whole subprocess group to 600 seconds and checks the final public count/digest independently.
