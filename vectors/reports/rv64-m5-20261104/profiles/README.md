# Stream profiles, M5: review 2, negative corpus v3, format-version registry (2026-11-04)

This change touches notes, the corpus harness and the off-by-default registry. It changes no prover or receiver behaviour, and no proof is re-proven:
- Every case runs against the accepted M3 cold proofs in `/workspace/m3/runs/integrate/<block>-2gpu-cold1`.
- M4 is byte-identical to those proofs.
- The admitted profiles, identities and default are untouched.

## What is here

| file | what |
|---|---|
| `{26235156,24628607}-negative-corpus-v3.json` | [M] Full runnable corpus v3 against the **M4 integrate receiver** (`1af34c0b…`, `/workspace/m3/build/m4-integrate`). Fresh, separate, GPU-disabled, cache-disabled process per case. |
| `{26235156,24628607}-negative-corpus-v3-recsize-receiver.json` | [M] The outer-profile cases against a receiver built from `codex/rv64-m4-recsize-port` @ `d4cdf05fa` (`588791b7…`). It is the first receiver that reads `STWO_RV64_OUTER_PROFILE`; canon-vk merged the same code. |
| `coverage-<stream>-<sha>.json` (5 files) | `coverage` of the latest pushed M5 branches: the U/W-tier hooks (zig tests named `corpus <ID>`) that exist. |
| `candidate-tests-releasesafe-review2.log` | [M] `zig test -OReleaseSafe` of the candidate registry: 23/24 pass (9 new). The failure is the pre-existing `LOCAL_RELATIONS` 9-vs-10 roster test (`rv64-m7-profiles.md` §2.1). The new M5 roster test pins 10 and passes. |
| `mass-census.json` | [D] cross-proof LogUp mass of both dev blocks from their accepted `bundle.json` (`scripts/rv64_m5_mass_census.py`). ram is 2^23.9 / 2^24.6, leaving a 7.1 / 6.4-bit margin to p. **One global RAM relation caps a block at about 2 G instructions** [E, linear]. This applies to today's receiver as well (binding §10.2). |
| `recsize-receiver-build.log` | build exit status of the recsize receiver (CPU only, build lock held) |

Notes: `design/riscv-proving-stack/rv64-m5-binding.md` §10 (review 2) and `rv64-m7-profiles.md` §8 (format versions).

## Corpus v3 results [M]

| block | receiver | ran | passed | crashes | unsupported (capability missing) | control wall | load 1m start → end |
|---|---|---:|---:|---|---|---:|---|
| 26235156 | M4 integrate `1af34c0b` | 37 | **37** | none | V07 (no same-tree donor); P02/P02b/P03/C01 (no outer-profile env) | 42.1 s | 16 → 26 |
| 24628607 | M4 integrate `1af34c0b` | 38 | **38** | none | P02/P02b/P03/C01 | 63.4 s | 26 → 23 |
| 26235156 | recsize-port `588791b7` | 9 | 8 | **P03** | — | 46.2 s | 28 |
| 24628607 | recsize-port `588791b7` | 9 | 8 | **P03** | — | 67.9 s | 30 |

| 26235156 | **canon-vk `59e774b9e`** `9d2344ca` | 43 | 42 | **P03** | V07 | 45.4 s | 31 → 49 |
| 24628607 | **canon-vk `59e774b9e`** `9d2344ca` | 44 | 43 | **P03** | — | 80.8 s | 49 → 39 |

The pod was shared with other streams (load 16–49), so **no wall in this table is a quiet-host timing**.

**Corpus on the pushed canon-vk branch** (`59e774b9e`: k-ary pipelined executor, VK tables, recsize port; receiver built CPU-only by profiles). Every runnable case gives the same verdict as on the M4 receiver, with the same first error class. That covers V06 and V07 (`RecursiveReceiverArtifactMismatch`, `Om31CircuitWireAuthority`) and P02/P02b (`Om31CircuitWireProfile`). The only failure is the P03 abort. So no rejection regressed with k-ary support on the r1 default.

### New runnable cases

| case | 26235156 | 24628607 | what it shows |
|---|---|---|---|
| `V06` coherent cross-block root that passes the size cap | reject, `RecursiveReceiverArtifactMismatch` (42.8 s) | reject, `RecursiveReceiverArtifactMismatch` (67.4 s) | closes review 1's open item: `V04` on 24628607 was stopped only by `FileTooBig`. The root donor of 24628607 is the accepted M3 proof of 25229957 (root 700,952 B ≤ 706,424 B, same 38-file tree), only read, never proven or measured. |
| `V07` whole recursion tree of another block | unsupported (no same-shape donor) | reject, `Om31CircuitWireAuthority` (19.2 s) | a fully coherent foreign tree fails at the first leaf authority |
| `P02` outer `m3_b4_q51` + binary folds, r1 proofs | reject, `Om31CircuitWireProfile` | reject, `Om31CircuitWireProfile` | the outer profile domain is bound (semantic), the P02 open item |
| `P02b` outer `m3_b8_q34` + binary folds | reject, `Om31CircuitWireProfile` | same | |
| `P02d` outer m3 at its default arity 4 | reject, `MissingRecursiveNodeProof` (missing) | same | without `STWO_RV64_FOLD_ARITY=2` the plan differs first: weaker, kept as a variant |
| `P04` r1 receiver planning 4-ary folds | reject, `MissingRecursiveNodeProof` (missing) | same | |
| `P03` unknown outer profile name | **crash (abort, exit −6)** | **crash (abort, exit −6)** | **finding**: `protocol.zig active()` panics on an unknown `STWO_RV64_OUTER_PROFILE`. It fails closed but crashes; the corpus never counts a crash as a pass. Fix owner: canon-vk (CV1). |
| `C01` explicit r1 | accept, same statement | accept, same statement | the recsize-port receiver accepts M3/M4 r1 proofs on both dev blocks [M]. This is receiver-side compatibility only; the port's GPU byte parity is still unverified. |

The M4 receiver rejects the remaining 34 (26235156) and 35 (24628607) cases with the same first errors as corpus v2. `X06` is still rejected by `InvalidSumcheck` on both blocks.

### Pending cases (spec only): 61, each with a tier and an owner

`python3 scripts/rv64_m5_negative_corpus.py spec` prints them. They are published per owner in `/workspace/m3/M5-INTERFACES.md`, section "profiles".

| tier | m5 | m7 |
|---|---:|---:|
| R (fresh receiver process; `run --format m5-root`) | 7 (`RR01`–`RR07`) | 1 (`M03`) |
| U (statement-check unit test) | 7 | 3 |
| W (circuit witness mutation) | 29 | 14 |

**Hook coverage** (`coverage-<stream>-<sha>.json`, re-run on the latest pushes):

| stream | commit | own hooks |
|---|---|---|
| blake-gadget | `0ac650b69` | **8/8** (BG01–BG08) |
| outer-gkr | `0e609b431` | **7/7** (M01, M02, M05–M08, M10) |
| canon-vk | `2ac415114` | 0/22 (G03, G05 and Z08 exist in substance in `vk_table.zig`, not named) |
| canon-native | `529a2d925` | 0/8 |
| rootverify | `92cda862e` | 0/6 U tier (its own RV R-tier corpus, 51/51) |
| profiles | this branch | 1/1 (M09) |

### Root-only format dry run (`--format m5-root`, today's M4 receiver) [M]

This checks that the harness's M5 root-only mode works before the format exists. It also records the baseline for the M5 gate "root tamper rejected first, ≤ 1.5 s". Receipts: `*-negative-corpus-v3-m5root-dryrun.json`. 7/7 cases pass on each block.

| case | 26235156 | 24628607 |
|---|---|---|
| `RR01` root flip | reject `RecursiveReceiverArtifactMismatch` **50.7 s** | reject, **73.2 s** |
| `RR02` root + 32 B | reject `FileTooBig` (resource: the size cap is exact) | same |
| `RR03` VK / table files planted in the proof directory | accepted with the control statement (never read) | same |
| `RR05` producer sidecar JSON counts edited | reject `RecursiveReceiverArtifactMismatch` | same |
| `S09`, `X06` under the relaxed root-only expectation | reject (today's receiver still reads natives and cells) | same |

Today a root tamper is found only after the full re-derivation: 50.7 / 73.2 s on a loaded pod, against the M5 gate of ≤ 1.5 s.

### Cross-block roots against the pushed root-only receiver (rootverify `92cda862e`, binary `f5f7ec5e`) [M]

The receiver is rootverify's `verify-root-candidate`, run with its own receiver-derived table `vk-both.json`, through `--format m5-root --receiver-argv`. Receipts: `*-negative-corpus-v3-rootverify-receiver.json`. 5/5 and 6/6 pass.

| case | 26235156 | 24628607 |
|---|---|---|
| C00 control | accept, 12.4 s | accept, 17.9 s |
| V04 cross-block root | reject `Om31CircuitWireAuthority` | reject `Om31CircuitWireAuthority` (**semantic now**, `FileTooBig` before) |
| V06 same-size cross-block root | reject `Om31CircuitWireAuthority` | reject `Om31CircuitWireAuthority` |
| V07 whole foreign tree | — (no same-tree donor) | reject `Om31CircuitWireAuthority` |
| RR01 root flip | reject `RootMismatch` (12.6 s) | reject `RootMismatch` (18.1 s) |
| T01 wrong expected output | reject `GlobalGkrManifestExecution` | same |

rootverify also ran this corpus v3 in `m5-root` mode against its receiver itself: 40/40 on each block (`/workspace/m3/runs/m5-rootverify/profiles-v3-m5root-*.json`). It ran without `--root-donor`, so V06 and V07 were reported as unsupported there; they are measured here.

## Review 2 in one paragraph

Review 2 signs off F3–F12, re-opens F1 and F2 with corrections, and finds two new blocking gaps:
- **F1 correction.** The cross-proof mass vector is exactly `{ram, kio, wire}` from `mass_authority.zig`. range16, range8 and AND are per-proof relations. The counters are per-family call and truth counters, plus sponge and CPU ordinal.
- **F13 (blocking).** The χ chain must bind the local GKR receipt and terminal marginals, as today's manifest does. canon-native's `rho()` already does.
- **F14 (blocking).** The halt flag and the output are terminal memory, not machine state, and need an `NS.out` field written by `mb` leaves.

Mass bounds are re-derived from the code (§10.2). The two receiver mass accountings differ on sponge kio, and the M5 one (`mass_authority`) is the stricter.

On the pushed M5 branches:
- canon-vk's `T_rec` holds compress kinds, so folds must constrain the child kind (new case `G06`).
- `DEPTH` 6 overflows at 4 rungs × 17 families.
- `T_nat` has two different encodings in M5-INTERFACES (canon-native §3 vs canon-vk CV2), and must have one.

## Reproduce (pod)

```sh
cd /workspace/m3/src/m5-profiles
I=/workspace/m3/runs/integrate
python3 scripts/rv64_m5_negative_corpus.py run --run $I/24628607-2gpu-cold1 --donor $I/26235156-2gpu-cold1 \
  --root-donor $I/25229957-2gpu-scale --receiver /workspace/m3/build/m4-integrate/zig-out/bin/rv64-word16-ethereum-recursion-receiver \
  --jobs 3 --work /workspace/m3/scratch/m5-profiles/corpus --out OUT.json
python3 scripts/rv64_m5_negative_corpus.py coverage --src src          # U/W hooks per owner
ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global /workspace/zig/zig test -OReleaseSafe --dep stwo_core \
  -Mroot=src/integrations/riscv_cpu/rv64_om31_security_candidate_test_root.zig -Mstwo_core=src/core/mod.zig
```
