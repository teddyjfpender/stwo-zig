# Stream profiles: M5/M7 gating notes, negative corpus v1, M7 candidate registry (2026-11-04)

This change adds notes, a corpus and a registry. It changes no proof, prover or receiver behaviour.
- The admitted profiles and identities are untouched.
- The new registry entries are off by default and can be selected by no path.
- The proofs under test are the M3 baseline proofs, not re-proven.

## What is here

| file | what |
|---|---|
| `26235156-negative-corpus.json`, `24628607-negative-corpus.json` | [M] 35 runnable cases each. Every case runs in a fresh, separate, GPU-disabled, cache-disabled receiver process (the M3 integrate receiver, sha256 `7b823d49…`, built from `d6f7b2b5e`) against the accepted M3 cold proofs in `/workspace/m3/runs/integrate/<block>-2gpu-cold1`. The donor is the other dev block. The 15 pending M5/M7 cases are listed with the spec. |
| `candidate-tests-releasesafe.log` | [M] `zig test -OReleaseSafe` of `rv64_om31_security_candidate_test_root.zig`: 12 pass, 1 fails. The failure is pre-existing (see below); the 3 new M7 tests pass. |

## Corpus result

| block | ran | passed | unexpected accepts | control receiver wall | corpus wall (2 jobs) | load 1m start → end |
|---|---:|---:|---|---:|---:|---|
| 26235156 | 35 | **35** | none | 47.4 s | 280 s | 46 → 75 |
| 24628607 | 35 | **35** | none | 68.2 s | 389 s | 75 → 45 |

The pod was busy with other streams during these runs, so the walls are not quiet-host timings.

- The control is accepted, and its statement (output, root digest, root authority, manifest, profiles) equals that of the original accepted receipt.
- `K02` (producer `report.json` cpu_proofs − 1) is accepted with an **identical statement**. The receiver re-derives the count and does not read that field, so this counts as a pass under the `reject_or_same_statement` rule.
- Every other case is rejected. The first error of each is in the receipt.
- Byte-level native mutations stop at the bundle file hashes (`WideBundleFileChanged`). The **coherent** variants rewrite `bundle.json` consistently and reach semantic checks:
  - `InvalidServicesWireRequest` or `InvalidServicesWireBoundary` for permuted, dropped or duplicated segments;
  - `InvalidCombinedTruthSpan` for permuted truth shards;
  - `RootMismatch` or `GlobalGkrPhysicalRootMismatch` for native bit flips;
  - `CircuitCheckFailure` or `UntrustedGlobalMemoryInitialization` for stage-one or cells flips.
- Root-proof mutations (`R04`, `R05`, `V04`) are only rejected at the end of the full re-derivation, about 48 s on 26235156, or by a size cap (`FileTooBig` on 24628607). In M5 the root check comes first (`rv64-m5-binding.md` §5).

## Adversarial review 1 (2026-11-04): corpus v2 [M]

The harness is now `rv64-m5-negative-corpus/v2`, with two changes.
- **Verdict rule.** A `reject` now passes only as a *clean* rejection: exit code > 0 and no crash marker (signal, panic, unreachable, segfault, timeout). Before, any failing exit counted, so a receiver that crashed on every mutated input would have passed the whole corpus.
- **Classification.** Each rejection is classed as `semantic`, `resource` or `missing`. The receipt lists the non-semantic ones.

New runnable case `X06-coherent-terminal-value`: it flips the value of the middle **terminal** RAM cell in `cells.bin` and rehashes `bundle.json`. Rights, epoch and tick stay canonical, so only the RAM teardown closure can reject it. This is the M3 analogue of review finding F2.

There are 12 new pending cases, `Z01`–`Z12` (`rv64-m5-binding.md` §9).

| block | ran | passed | crashes | non-semantic rejects | X06 | control receiver wall | corpus wall (2 jobs) | load 1m start → end |
|---|---:|---:|---|---|---|---:|---:|---|
| 26235156 | 36 | **36** | none | S01, S02 missing | rejected, `InvalidSumcheck` | 46.5 s | 271 s | 28 → 74 |
| 24628607 | 36 | **36** | none | S01, S02 missing; V04 resource (`FileTooBig`) | rejected, `InvalidSumcheck` | 69.3 s | 390 s | 74 → 34 |

Receipts: `{26235156,24628607}-negative-corpus-v2.json`. The receiver is the same M3 integrate build (`7b823d49`), run on the same accepted cold proofs, with nothing re-proven. The walls come from a loaded pod.

What this shows:
- `V04` on 24628607 is rejected by a **size cap**, not cryptographically. The M5 corpus should add a coherent cross-block root case of the right size.
- `S01` and `S02` add nothing beyond the coherent `S09`.

Candidate tests: `candidate-tests-releasesafe-review1.log` gives 13/14 pass. The new characteristic-bound test passes, and the one failure is the same pre-existing `LOCAL_RELATIONS` failure.

## Pre-existing test failure (not caused by this change)

The test "candidate local relation roster matches production raw fraction authority" fails at baseline `bcd401ce4`: `expected 9, found 10`.

The cause is that `fractions.zig` gained `byte_pair` (`63728c3f8`). Fixing it means changing an identity that is mixed into native proofs, so it is deferred to the next native format bump; see `rv64-m7-profiles.md` §2.1.

## Reproduce (pod)

```sh
cd /workspace/m3/src/m4-profiles
python3 scripts/rv64_m5_negative_corpus.py run --run /workspace/m3/runs/integrate/26235156-2gpu-cold1 \
  --donor /workspace/m3/runs/integrate/24628607-2gpu-cold1 --out OUT.json --jobs 2
python3 scripts/rv64_m5_negative_corpus.py spec   # full spec, including pending cases
ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global /workspace/zig/zig test -OReleaseSafe --dep stwo_core \
  -Mroot=src/integrations/riscv_cpu/rv64_om31_security_candidate_test_root.zig -Mstwo_core=src/core/mod.zig
```
