# RV64 GKR route: block_to_inputs report (P0) and setup cache (P1)

Plan: `design/riscv-proving-stack/rv64-block-to-inputs-plan.md` (PR #318), phases P0 and P1.
Block 24,628,607 (26.89 M steps, 7 CPU + 11 truth proofs), V3 GKR route
(`rv64-word16-ethereum-gkr produce-candidate`), default `conjectured128_b2_q108_p20_fold4`,
evmone v3 client, jobs `~/Coding/ge-cache/gkrperf/native/jobs`, `request.json`/`resources.json`
of `../rv64-gkr-memory-20261102/` (2 lanes x 8 workers, park MAIN, 12 GiB fixed setup).
14-core M4 Max, 36 GB, memguard. Branch `codex/rv64-setup-cache`, base main `89f607a22`.
`run.sh` is the exact proof driver (the 20261102 driver, run in this stream's directory, plus
`VERIFY_ENV` for the fresh receiver). `blocks.json` is the input of `scripts/rv64_block_to_inputs.py`.

## Summary

- **Setup per block, complete block (producer):** 6.97 s on main -> **0.26-0.28 s** from the
  on-disk cache (3 warm runs), **0.2-0.4 ms** when resident in the same process, 4.8-5.0 s
  cold (no artifact yet; identity-only CPU sources). Target was ~0 resident, <= 0.25 s cold
  load: the resident target is met, the cold load (0.26 s) is just above it.
- **Fresh verifier, complete block (`load_and_setup_ns`):** 7.05 / 7.03 s on main -> **0.372 /
  0.372 s** warm, 4.78 s cold. A tampered artifact is rejected (fail closed).
- **Proof bytes:** `bundle.json` and every `*.bin` are byte-identical to main for the 4-packet
  prefix and the complete block, with a cold cache and with a warm cache.
- **T_first** (block in -> CPU segment 0 inputs ready, in `produce-candidate`): 8.36 s cold ->
  **3.71 s** warm, of which capture + import is 1.99 s and segment 0's source build 1.15 s
  (main has no harness; ~10.2 s derived from its `fbmain` report: init ~0.12 + capture/import 1.96 +
  setup 6.97 + admission ~0.13 + segment-0 source 1.05).
- All 5 local suites pass (two needed `--gb 12`: memguard killed them at 10.4 GB).

## Results (AC power)

Timing batch (`timing.sh`, `timing-ac.txt`): quiet host, AC, one job at a time, same binary as
the gates (branch head source, `bin=4ba1dc9f...`). Main binary:
`~/Coding/ge-cache/fullblock/bin/bin/rv64-word16-ethereum-gkr` (89f607a22).

| Complete block 24,628,607 | main | this branch |
|---|---:|---:|
| Producer setup, no cache dir (`inputs-candidate`, `block_to_inputs.stages.setup_ns`) | 6.97 s (`fbmain` produce) | 4.77 s (keys 0.54 + FixedSet 4.23) |
| Same, identity-only CPU off (`STWO_ZIG_RV64_SETUP_IDENTITY_ONLY_CPU=0`) | | 5.65 s (keys 1.43 + FixedSet 4.22) |
| Producer setup, cold cache (builds + later stores 18 artifacts, 1.34 GB) | | 4.85 s |
| Producer setup, warm cache (runs 1-3; resident in the same process) | | **0.265 / 0.276 / 0.263 s**; 0.20-0.38 ms |
| Fresh verifier `load_and_setup`, no dir / cold / warm x2 | 7.046 / 7.031 s | 4.777 / 4.781 / **0.372 / 0.372 s** |
| Fresh verifier `verify_ns` | 0.853 s | 0.852-0.864 s |
| T_first, `inputs-candidate` (sequential sources), cold / warm | | 8.00 / 3.30 s |

| 4-packet prefix | main | this branch |
|---|---:|---:|
| Producer setup, no dir / identity-only off | 4.74 s (20261102 receipt, 19f228d37) | 3.28 / 4.08 s |
| Producer setup, warm cache (3 runs) | | **0.182 / 0.176 / 0.171 s** |

Gate runs (`gates.sh`, `gates-proofs.txt`, `runs-block-to-inputs.json`): AC, but the host was
shared with another stream's test suites, so treat their prove times as noisy.

| Run | setup_ns | T_first | T_all (CPU / all) | prove | fresh receiver load_and_setup | bytes vs main |
|---|---:|---:|---:|---:|---:|---|
| prefix cold (`p4c`) | 3.513 s | 6.139 s | 16.03 / 25.33 s | 53.97 s | 3.523 s (cold) | identical |
| prefix warm (`p4w`) | **0.197 s** | **2.800 s** | 13.28 / 22.23 s | 52.96 s | 0.301 s (prover-written), 0.329 s (verifier-written) | identical |
| complete cold (`fbc`) | 5.031 s | 8.360 s | 33.46 / 41.81 s | 81.98 s | 5.026 s (cold) | identical |
| complete warm (`fbw`) | **0.310 s** | **3.708 s** | 28.53 / 37.18 s | 80.61 s | 0.405 s (prover-written), 0.384 s (verifier-written) | identical |

(`setup_ns` is the historical report field: plan + setup + bundle directory; the
`block_to_inputs` stage `setup_ns` excludes plan, e.g. 0.268 s for `fbw`.) T_all is measured
inside the scheduled prove, so it includes waiting for lane slots: it is not an inputs-only
critical path. Peak RSS 12.3-16.2 GB (main `fbmain` 17.5 GB).

Hashes: `prefix-proof-files.sha256` equals `../rv64-gkr-memory-20261102/proof-files.sha256`
(= keccak-deep `b2.sha256` set, digest of the sorted list `044a9355...`);
`fullblock-proof-files.sha256` equals main's `fbmain` run (digest `4d7b53d0...`). All four runs
match.

## Gates

| Gate | Result |
|---|---|
| Byte identity, 4-packet prefix, cold cache / warm cache | identical / identical |
| Byte identity, complete block, cold cache / warm cache | identical / identical |
| Fresh receiver, cold cache (empty dir) prefix / complete | accepted / accepted |
| Fresh receiver, warm cache, prover-written prefix / complete | accepted / accepted |
| Fresh receiver, warm cache, verifier-written prefix / complete | accepted / accepted |
| Tampered VK byte, fresh receiver | rc=1 `error: SetupCacheArtifactRejected` |
| Tampered bulk byte, prover (`inputs-candidate`) | rc=1 `error: SetupCacheArtifactRejected` |
| `truth-gkr`, `services-gkr-local`, `keccak-throughput` | rc=0 |
| `word16-v3-services`, `word16-combined-services` | rc=0 with `--gb 12` (rc=137 at `--gb 8`: memguard RSS cap 10.4 GB, peak 10.5 GB; the other stream hit the same) |
| `test-riscv64-wide-fixed-setup` (new cache tests), `word16-fixed-native-cache`, `test-cairo-preprocessed-cache` | rc=0 (the new tests were confirmed to run by forcing one to fail once) |

New tests (`ethereum/setup_cache_test.zig`, run by `wide-fixed-setup` and `truth-gkr`):
identity-only coefficients equal the committed ones and give the same candidate identity, root
and appended-transcript digest; prover and verifier round trips; flips of the component key,
a header length, the VK source root, the structure, a coefficient and a Merkle node are rejected
(VK-only reads ignore bulk flips by design); truncation and an artifact renamed to another
component's key are rejected; a different rung misses; exactly one seal per component.


## What changed

**P0, `block_to_inputs`.** `produce-candidate` writes `report.json.block_to_inputs`: one
monotonic clock from `gkr_main` entry; `init_done_at_ns`, `capture_done_at_ns` (packet import +
capture), `plan_done_at_ns`, `keys_done_at_ns`, `setup_done_at_ns`, `coordinator_admitted_at_ns`,
per-worker `source_begin/ready_at_ns` (recorded inside the scheduled stage one), `t_first_ns`
(worker 0, i.e. CPU segment 0, inputs ready), `t_first_any_ns`, `t_all_cpu_ns`, `t_all_ns`
(truth sources included), stage durations and the setup-cache counters. New diagnostic mode
`inputs-candidate CONFIG JOBS PREFIX RESOURCES` runs exactly the same pipeline up to every
worker's source build (sequential, each source dropped), then stops: a few GB, ~10-20 s, no
proof. It also re-runs Keys + FixedSet once more in the same process (the setup of a next block
with the same rungs) and reports `resident_next_block_setup_ns`.
`scripts/rv64_block_to_inputs.py` runs either mode over a blocks file (optional `nativeprepare`
for missing jobs, `--setup-cache`, `--repeat` for cold/warm). Proof bytes do not change.

**P1(a), setup cache (`ethereum/setup_cache.zig`).** Setup is a pure function of receiver-owned
identity; each component (one CPU geometry rung, one truth setup) is keyed by SHA-256 over
(SHA-256 of the running executable, pinned ELF SHA-256 + the request fields that shape program
authority [CPU only], native suite identity, candidate rate, component kind and canonical
geometry/bridges/log parameters, format version). Components are:
- resident in-process (`Keys.initResident` borrows them; a second block with the same rungs hits
  all of them and FixedSet hits by source tag: ~0.3-0.5 ms);
- persisted per component in `$STWO_ZIG_RV64_SETUP_CACHE/<key>.rv64-setup` (written atomically
  via tmp + rename, after the proof/verification and outside every timing);
- restored without either commit: the source key becomes root-only (suite, column heights,
  root), the candidate fixed key is restored with its exact coefficients and retained Merkle
  layers (prover) or root-only (verifier), adopted into `Fixed.Cache` under its source tag.
- built in parallel (8 threads, `STWO_ZIG_RV64_SETUP_BUILD_THREADS`); the artifact's bulk part
  loads on a helper thread while the component builds.

**P1(b), redundant first commit.** In candidate mode the CPU source key is identity-only
(`Key.identityOnly`): its columns are interpolated exactly (the polynomials a commit retains), and
no LDE/Merkle commit is made; its "root" is a domain-separated chunked SHA-256 over suite, shape
and coefficients, used only as identity (never mixed into a transcript). This is allowed because
no CPU statement binds the CPU source root (`cpu_worker.zig cpuStatement`, the expected-worker
root is `binding.root()`); fixed identity/root are unchanged, as the byte-identical proofs show.
Truth source commits are NOT removed on a cold build: `truth_worker.zig:40` and
`truth_v3_worker.zig:31` bind `truth.key().root` (the production-suite root) into the truth
statement, so removing them would change proof bytes. The warm cache path skips them too, since
the artifact carries that root.

**P1(c), verifier.** `verify-candidate`/`verify-prefix-candidate` use the same cache in verifier
mode: they read only header + VK (~1 KiB per component) and restore root-only keys
(`root_only` keys refuse PCS append and `requireSource`). Any mismatch is a hard error
(`error.SetupCacheArtifactRejected`), never a silent fallback; a missing artifact is a miss (the
receiver builds and then stores it).

## Integrity and why the prover does not re-hash the 266.8 M coefficient cells

- Header (256 B): magic, version, flags, component key, code identity, section lengths, VK
  SHA-256, bulk chunked-SHA-256, chunk size; SHA-256 over the header. A file under another
  component's name, a different executable, a truncated or flipped file are all rejected.
- VK section: suite identity, source column heights and root, candidate rate, identity, root,
  cells and heights: every value a receiver statement or transcript binds
  (`fixed_authority.zig` statement/begin: fixed identity/root; truth statements: source root).
  The verifier trusts exactly these, and checks only them (SHA-256 over ~1 KiB).
- Bulk section (prover only): column descriptors, per-column native-sharing digests, the
  coefficients and the retained Merkle layers, bound by one chunked parallel SHA-256
  (`engine.chunked_sha256`, moved unchanged from the Cairo tree-digest cache).

The prover skips the two serial hashes the cold path does per key (fixed identity = SHA-256 over
all 266.8 M cells, and the native-sharing digest): both are replaced by authenticated stored
values. This is sound because prover-side bytes cannot change what is accepted: a wrong
coefficient or node yields a transcript that an independent receiver (which binds only its own
VK roots) does not reproduce. The one load-time hash left on the prover is the parallel bulk
digest, kept so corruption fails at load instead of at the receiver; it is availability, not
soundness. Native sharing uses the stored digest only as a lookup hint: every hit still compares
the actual values. Trust boundary: the cache directory. A party who can rewrite an artifact
consistently (header, VK and digests) can equally replace the receiver binary, which is why the
code identity is the SHA-256 of the running executable.

## Not done / unresolved

- **Truth source commits on a cold build** stay (they are bound by truth statements, see P1(b));
  removing them needs a statement change and a fresh receiver. Warm builds skip them.
- **Cold FixedSet** (candidate commits, ~4-4.6 s for the complete block) is unchanged. A
  parallel pre-seal of the candidate keys was tried (4 concurrent seals, sealing outside the
  Fixed.Cache mutex): prefix 2.9 -> 2.2 s but complete block 4.6 -> 5.2 s on battery and a
  4.3 GB fixed-budget peak (was 1.2 GB), so it was reverted.
- **Warm critical path** is now component construction itself: CPU materials
  (`Program.fixedFromEntries`, ~45-90 ms per CPU rung, rebuilt per rung) and the Keccak
  chi/xor5 tables (`tables.Trace.buildPolicy`, ~0.19 s). Persisting those (or sharing the ROM
  part across rungs) is the next step below ~0.25 s.
- **Disk dedupe**: each artifact carries its own coefficients, so the 7 CPU rungs store the
  shared ROM columns 7 times (1.34 GB on disk and read per warm load, 231 MB unique after the
  in-memory native dedupe). Content-addressed payloads would cut cold-disk I/O ~5x.
- **In-process residency across different blocks** is implemented (resident map, source-tag
  hits) and measured only as "same rungs again in one process" (`inputs-candidate`'s second
  pass); there is no multi-block `produce` driver yet, and other basket blocks were not run
  (no native jobs prepared here). The basket's union of rungs is therefore not precomputed.
- The code identity is the executable's SHA-256, so every rebuild is a cold cache by design.
- `Program`/Keccak-table construction runs once per process even when every key loads; the
  verifier pays it too (warm verifier ~0.3-0.4 s, of which image + bundle read is part).
