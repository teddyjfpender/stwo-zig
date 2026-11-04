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
| `coverage-canon-vk-59e774b9e.json`, `coverage-canon-native-e3fdff934.json` | `coverage` of the pushed M5 branches: the U/W-tier hooks (zig tests named `corpus <ID>`) that exist. |
| `candidate-tests-releasesafe-review2.log` | [M] `zig test -OReleaseSafe` of the candidate registry: 21/22 pass. The failure is the pre-existing `LOCAL_RELATIONS` 9-vs-10 roster test (`rv64-m7-profiles.md` §2.1). The new M5 roster test pins 10 and passes. |
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

The pod was shared with other streams (load 16–30), so **no wall in this table is a quiet-host timing**.

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

**Hook coverage today: 0 of 53 U/W hooks** on both canon-vk `59e774b9e` and canon-native `e3fdff934`. canon-vk's `vk_table.zig` tests cover G03, G05 and Z08 in substance, but they are not named `corpus <ID>`. The profiles tree has 1 hook (`M09`).

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
