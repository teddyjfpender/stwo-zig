# Adversarial review: m9-poseidon2-leaves (2026-11-07)

Scope: commits 2bacd44f0..1782dec9b on `codex/rv64-m9-poseidon2-leaves`.
Labels: [M] measured, [D] derived, [E] estimate.
GPU use: one `gpu.lock` hold of 28 s, standalone kernels only, on an idle GPU. No request-level runs.

## Corrected headline [E] (`model.json` v2-reviewed; design doc §1, §6)

As built (sponge node, today's P2 kernel, one-thread P2 transcript), **the lever is a net loss**:

| | p50 (29.1 M gas) | p95 (55.8 M gas) | 24628607 |
|---|---:|---:|---:|
| builder's central | −4.4 GPU-s | −8.0 | −1.4 |
| **as built, reviewed** | **+8.7** | **+16.8** | **+2.2** (request wall up to +2.3 s) |
| 2-to-1 node | +5.6 | +11.0 | +1.3 |
| 2-to-1 + P2 kernels ×0.6 | ≈0 | +0.5 | −0.4 |
| engineered target (above + transcript ≤ ×3 Blake) | **−6.2 (−20%)** | **−11.4 (−20%)** | −2.0 (wall −2.0 s upper bound) |
| pessimistic | +16.1 | +30.7 | +4.4 |

Signs are + for more GPU-s and − for a cut.

## Findings

| # | finding | status | effect |
|---|---|---|---|
| 1 | **m (Merkle share of recursion kernel time) was 0.18, scaled from the request-wide share.** Native hashing is only ~0.12 GPU-s of the request's 1.520 GPU-s of Merkle kernels (`opt-combined/ab8-kernels.json`) [M], so recursion's own share is 1.40 / (0.573 × 8.478) = **0.29** (0.28–0.33) [D] | confirmed, fixed in model and doc | break-even k falls from 15–18 to **11.8**; measured k is 9.95; the p50 recursion cut falls from 6.4 to 2.3 GPU-s |
| 2 | **The native delta was taken at M6 log blowup 1.** The production default is D2 `d2_native_b4_q54_p20_fold4`, at log blowup 2 (`om31_security_candidate.zig:438`; the opt-combined gates are byte-identical to the D2 golden) | confirmed, fixed (×2 [E] in the central rows) | native +2.1 → +4.1 GPU-s at p50 |
| 3 | **The serial device transcript was missing.** `channel_mix<<<1,1>>>` costs 0.0775 GPU-s over 363 calls [M] and sits on every proof's Fiat–Shamir path. A one-thread P2 sponge is **×23.9** slower per mix: 12.9 µs per permutation against 0.72 µs per Blake2s compression, for 8–4,096 words (`serial-mix.jsonl`) [M]. It cannot stay on Blake, because the in-circuit channel would then pay ~22.7k cells per compression | confirmed, measured, added to model and doc §8 step 5 | +1.78 GPU-s on 24628607, +6.8 at p50, all serial |
| 4 | **The GPU parent layer (`stwo_p2m31_parent_layer_on`) was never compared with the reference.** Parity checked leaves only, and bench roots were printed but never checked | confirmed, fixed: the emitter writes `N`/`T` records and the gate checks them | re-run [M]: **336/336**, 2,688 parents and 46 full roots match the Zig `hashParent` |
| 5 | The "pinned fingerprint" test compared `columnWord(1,2,3)` with itself | confirmed, fixed: pins 1026837563 and a `hashParent` vector; the CUDA host pins the same value | — |
| 6 | No seeded chain split fell on an exact rate boundary (absorbed % 12 == 0, at = 0 after the eager permute) | confirmed gap, fixed: a new Zig test (4 shapes) and 3 GPU chain cases | all pass; zig 90/90 [M] |
| 7 | "2-to-1 node: −28% of P2 native permutations" (§9) | wrong, fixed | it is −14%: nodes are 28% of permutations and halve. The +0.452 GPU-s figure was already right |
| 8 | §1 said the whole-leaf model range was ×0.24–0.31; `model.json` gives 0.206–0.308 | fixed | — |
| 9 | Savings were stated in GPU-s only, never on the critical path | added: phase-wall scaling at constant busy for 24628607 (an upper bound) | as built +2.27 s request wall; engineered target −2.0 s |

## What held up

- Leaf parity, re-run on the review binary `526aad18…` [M].
- The builder's model is internally consistent: its central rows reproduce at −4.36 / −8.02 / −1.41 GPU-s.
- Gas percentiles: p50 29.11 M and p95 55.82 M over 2,901 blocks, re-computed.
- The [D] per-decommitment rows: FIXED 817k/46.7k ×17.5, MAIN 5.65M/257k ×22.0 and composition 545k/35.6k ×15.3 re-derived by hand. Census ×0.192, a non-hash part of 82.05 M and 28.2k cells per compression all re-derived.
- Security arithmetic:
  - p − 1 = 2·3²·7·11·31·151·331, so gcd(5, p − 1) = 1;
  - capacity 372 bits; the 9-limb digest gives 139.5-bit generic collision resistance;
  - leaf and node are domain-separated at state[23];
  - 10*-style padding is injective at fixed widths.
- The 2-to-1 node is correctly flagged as unqualified.

## Still open (not fixed here)

- The single-shape and chain bench [M] numbers were not re-run. The builder's re-check on its final binary agreed within 2%.
- k in-request is unmeasured. If in-request Blake runs below its standalone HBM roofline, the effective k is lower, which helps the lever.
- Recursion GPU-s are assumed proportional to committed cells.
- The `status` contract leaves bad rows unwritten, so integration must check `status` before using a root.
- Go/no-go order before any integration:
  1. P2 kernel at ≥ ×1.7;
  2. 2-to-1 node security note;
  3. a parallel P2 transcript at ≤ ×3 Blake;
  4. only then the native A/B.
