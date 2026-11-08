# M7 compress profiles: C1 / C2, FRI arity, Merkle caps, multiproof (stream profiles, M6 prep)

Stream `profiles`, branch `codex/rv64-m6-profiles`, 2026-11-05. This note gives M7's compress stream everything it needs
to start building:
- named profiles with conjectured-128 arithmetic;
- a calibrated proof-size model;
- the soundness argument for every framing lever;
- the corrections to plan §5 that the model forces.

It extends `rv64-m7-profiles.md` (§1 profile table, §3 first size model, §5 statement passthrough). Where the two differ,
this note supersedes §3 of that one.

Labels: **[M]** measured, **[D]** arithmetic or model on measured numbers, **[E]** estimate.

**Registry:** `om31_security_candidate.zig` `CandidateProfile` / `candidateSpec`, with tests in
`om31_security_candidate_test.zig`. All entries are OFF BY DEFAULT. None is in `Profile`, `PROFILES` or
`protocol.Profile`; `requireCandidateNotAdmitted` holds, and the candidate identity domain is `…candidate-profile/v2`
(it hashes the framing fields).

**Model:** `scripts/rv64_m7_compress_model.py table`. The receipt is
`vectors/reports/rv64-m6-20261105/profiles/m7-compress-model.json`.

---

## 1. Profiles (conjectured-128 arithmetic, all pinned by tests)

Conjectured bits are `log_b · q + pow` (ethSTARK, the same rule as every admitted profile). The Johnson column is
`q · log_b + 2·pow`, doubled to stay an integer. It is an upper bound used for ranking only (`rv64-m7-profiles.md` [R1]).

| entry | layer | log b | q | pow | log₂ FRI arity | last layer | conj. bits | Johnson ×2 | status |
|---|---|---:|---:|---:|---:|---:|---|---:|---|
| `c1_b8_q36_p20_fold4` | C1 | 3 | 36 | 20 | 4 | 2^0 | 3·36 + 20 = 128 | 148 | registered (M5) |
| `c1_b16_q27_p20_fold4` | C1 | 4 | 27 | 20 | 4 | 2^0 | 4·27 + 20 = 128 | 148 | **new (M6)**: fewer queries for C2 to verify |
| `c2_b16_q27_p20_fold3` | C2 | 4 | 27 | 20 | 3 | 2^3 | 4·27 + 20 = 128 | 148 | registered; last layer 2^3 added |
| `c2_b16_q27_p20_fold4` | C2 | 4 | 27 | 20 | 4 | 2^3 | 128 | 148 | registered; last layer 2^3 added |
| `c2_b64_q18_p20_fold3` | C2 | 6 | 18 | 20 | 3 | 2^3 | 6·18 + 20 = 128 | 148 | **new (M6)**: the size pick of §3 |

Every entry is exactly 128 conjectured bits. None is below today's native default under Johnson: 148, which equals the
admitted b2 q108 p20. b64 is inside the core FRI range (`LOG_MAX_BLOWUP_FACTOR = 16`).

There is no `b32` entry. At exactly 128 bits it would be `b32 q22 p18`, whose Johnson ×2 is 22·5 + 36 = 146 < 148. That
violates the "never weaker than today" rule, and §3 shows it does not win on size anyway.

---

## 2. Soundness of each framing lever

The query term binds every layer: about 60 bits above the algebraic union (`rv64-m7-profiles.md` §2). So a lever is
admissible when it leaves the query term at 128 and adds at most negligible algebraic weight.

1. **FRI arity 8 (`fold_step` 3) or 16 (4).**
   - Query term: unchanged. The ethSTARK count is per query, not per layer.
   - Commit phase: a fold of `2^s` cosets with powers of one α is a degree ≤ 2^s − 1 polynomial in α per layer. Its error
     is at most `2^s · |D| / |F|`. At `2^3 · 2^24 / 2^243.3` that is ≈ 2^-216 per layer [D], against a 2^-128 budget.
   - `fold_step` is hashed into the identity, so case **M03 / CP04** (proven at 3, verified at 4) must reject.
2. **Pruned last layer (`log_last_layer` 3).**
   - The prover sends the 8 coefficients of the last-layer polynomial (core already sends the last layer as
     coefficients). The verifier checks the degree bound by construction, with `last_layer_poly.len() ≤ 2^log_last`
     (`fri_family.zig`).
   - The proximity claim is about the same code, so the conjectured bound is unchanged.
   - Case **CP03**: a coefficient at index ≥ 2^3 must be refused.
3. **Multiproof (batched decommitment).** This is **already the core default.**
   - `vcs_lifted/verifier.zig` sends a sibling only when it is not itself on a path. It rejects witnesses that are too
     short or too long (`WitnessTooShort`, `WitnessTooLong`) and leftover deduplicated values.
   - So the wire set is canonical and binding is the ordinary Merkle collision bound.
   - Today's 706 KB root **already includes it** [M + D: the model below reproduces 706 KB to 9% with multiproof,
     whereas the M5 note's per-path model was 1.16× high].
   - Case **CP01**: an extra, reordered or duplicated sibling is refused. This is a property of the existing verifier, so
     the hook can be written now against any proof.
4. **Merkle caps.**
   - Sound: the 2^c cap nodes are mixed into the transcript in place of the root, and each path stops at the cap. The
     binding is the same collision bound per node.
   - **Not used.** Under the multiproof, the top ~log₂(q) levels are already nearly free, while a cap costs 2^c·32 B per
     tree. A 16-node cap is a net **loss** of 3.4–3.9 KB at C1 and C2 [D, §3].
   - The `merkle_cap_log` field stays in the registry (hashed, 0 everywhere), so a later cap is a new identity.
   - Case **CP02** stays in the corpus for the case that one is ever used.
5. **Duplicate queries at low counts.** With q = 18 positions on a 2^23 line domain, P[some duplicate] ≈ q²/2^24 ≈
   2^-15.7. The error is E[ρ^{distinct}] ≤ ρ^18 · (1 + 2^-15.7 · ρ^-1) = ρ^18 · (1 + 2^-9.7) at ρ = 2^-6. That is a
   relative loss of 0.002 bit [D]. It is negligible, but it is why b64 is not pushed further, to q ≤ 12.
6. **Merkle arity 4 (plan §5 lever "arity-4 Merkle in C2 only"). Rejected for size.**
   - Per 2 binary levels a multiproof path sends 2 siblings. One 4-ary level sends 3.
   - With 32-byte Blake2s digests, 4-ary paths are about 1.5× **larger**, and the hashing cost per path is equal: one
     64 B compression per binary node against two per 4-ary node.
   - It would also need a new hasher and profile id (`merkle_arity_log` stays 1). Removed from the M7 lever list.
7. **Digest truncation:** not admissible. Merkle binding needs collision resistance, and 256-bit digests are the 128-bit
   collision level.

C1 and C2 statement passthrough, the T_rec exclusion of compress VKs (G06) and M03/M04 are as in `rv64-m7-profiles.md` §5.

---

## 3. Size model, calibrated on the measured root [D]

**Model** (`scripts/rv64_m7_compress_model.py`):
- trace trees: for each unique line position, the conjugate pair of leaves, every opened column at 4 B, and **exact**
  multiproof siblings (Monte Carlo over query sets, using the vcs_lifted rule);
- FRI line layers after the circle fold: 2^s − 1 OM31 siblings per unique coset, plus that layer's multiproof;
- fixed: commitments, last layer, OODS samples (columns × 2 × 32 B) and the PoW nonce.

**Calibration:** the model gives 773 KB raw for the M5 default root (r1 b2 q108, 2^23 rows, 311 opened columns
[M, diet census `parent_side.today_columns`], 4 trees, fold 4), against **706,424 B measured** [M]. All rows below are
scaled by 0.913.

Byte split of that root [D]:

| part | KB |
|---|---:|
| opened values | 245 |
| trace-tree paths | 194 |
| FRI values | 177 |
| FRI paths | 71 |

### 3.1 C2 grid (FRI arity 8, last layer 2^3)

| C2 rows | b, q | 150 cols, 3 trees | 215 cols, 3 trees | 215 cols, 4 trees | 311 cols, 4 trees | LDE (215 cols) |
|---|---|---:|---:|---:|---:|---:|
| 2^18 | b16 q27 | 125.7 KB | 142.4 | 154.6 | 179.1 | 3.6 GB |
| 2^18 | b32 q22 | 110.8 | 125.0 | 135.8 | 156.8 | 7.2 GB |
| 2^18 | **b64 q18** | **97.6** | 109.9 | 119.4 | 137.6 | 14.4 GB |
| 2^19 | b16 q27 | 134.2 | 150.8 | 163.8 | 188.3 | 7.2 GB |
| 2^19 | b64 q18 | 103.3 | 115.7 | 125.7 | 143.9 | 28.9 GB ✗ |
| 2^20 | b16 q27 | 142.7 | 159.3 | 173.1 | 197.6 | 14.4 GB |
| 2^20 | b64 q18 | 110.2 | 122.5 | 133.0 | 151.3 | 57.7 GB ✗ |

Further rows [D]:
- **Arity 8 vs 16:** 2^16 b16 q27 311 cols gives 165.0 KB at s3 and 171.9 KB at s4. Arity 8 stays the optimum, as the M5
  note found.
- **Last layer 2^3:** −2.6 KB.
- **Caps (16 nodes):** +3.4 KB at C2, +3.5 KB at C1.
- **Width is the dominant lever.** A fused-Blake k = 1 row layout (6,189 opened columns per row-shape, census) costs
  **1,677 KB** at C2 2^17. The k = 10 layout (1,072 columns) costs 368 KB. **The C2 circuit must not use the fused
  Blake2s gadget.** Its rows are 3–60× wider than the G-gate, and the opened-value term scales with total width.
- **The outer GKR section is 69.8 KB per proof** [M, M5 outer-gkr]. C2 must use classic interaction, not outer GKR.
  The section alone would be 70% of a 100 KB budget. C1 may use either, since its size is not shipped. Its *width*
  drives C2's leaf hashing, though (§4).

### 3.2 Conclusions

- **Tree count.** Classic interaction needs its own commitment round (PP, main, interaction, composition), so a C2 with
  lookups has **4 trees**. "3 trees" in the grid means a lookup-free C2 AIR. The G-gate uses XOR lookups, so that is a
  research item, not an option.
- **≤ 100 KB is reachable only at the edge.** At `c2_b64_q18_p20_fold3` and 2^18 rows [D]:

  | columns | 4 trees | 3 trees |
  |---:|---:|---:|
  | 128 | 102.9 KB | |
  | 150 | 107.1 KB | 97.6 KB |
  | 192 | 115.1 KB | 105.6 KB |

  So ≤ 100 KB needs a 4-tree C2 with ≤ ~120 opened columns, or a lookup-free 3-tree C2 with ≤ ~150 columns.
  2^19 rows add about 6 KB, and at 150 columns the LDE is already 20 GB.
- **The realistic M7 band is 103–115 KB** [D for size; the row count is §4 E].
- **`c2_b16_q27_*` (the plan's C2) cannot reach 100 KB at any height or width in this grid.** Its best is 2^18 / 150
  columns at 125.7 KB.
- **The plan's ≤ 75 KB stretch is not reachable** with Blake2s-256 Merkle and ≥ 128 columns.

---

## 4. Can C2 be ≤ 2^18 rows? The in-circuit hashing budget [E]

C2 verifies one C1 proof. Its cost is dominated by Blake2s compressions. For C1 = `c1_b8_q36` at 2^20 rows, 311
columns, 4 trees, fold 4 (eval 2^23, 5 FRI layers), the count is about 7,800 compressions [E]:

| work | compressions |
|---|---:|
| leaf hashing: 72 leaves × 311 cols × 4 B / 64 B | ~1,700 |
| trace-path nodes: 4 × ~700 distinct | ~2,800 |
| FRI cosets: 5 layers × 36 × (8 leaf blocks + path) | ~3,200 |

At today's G-gate cost of 8,672 cells per compression [M, census `per_compression.today`], that is ≈ 68 M cells
for hashing alone. Folding arithmetic and OODS come on top: the census puts hashing at about 2/3 of a verifier, so the
total is ~100 M cells.

A 2^18 × 128-column C2 holds 34 M cells. **So the plan's two stages land C2 at 2^19.6–2^20 rows, and a two-stage
chain gives ≈ 110–125 KB [D/E].**

Ways to the ≤ 100 KB region, in order of risk:
1. **Narrow C1.** C1's width and query count drive C2's work, while C1's own size is irrelevant. With `c1_b16_q27`
   (27 queries, −22% compressions) and a ~150-column C1, leaf hashing drops by half. The total is then ~5,000
   compressions, about 43 M hash cells and ~65 M overall [E]. That is still about 2^19.
2. **A third, tiny stage C3** at `b64 q18` and 2^18 rows. It verifies C2, which itself uses `b64 q18`: about 18 queries ×
   (depth ~24 + 4 FRI layers), roughly 3,500 compressions, ~30 M hash cells and ~45 M overall [E]. Borderline at 2^18 ×
   150 columns, and it fits at 2^18 × 192 columns.
   - It costs one more small proof on the request tail [E: 0.1–0.3 s on the GPU at 2^18].
   - C3 is the same circuit family as C2 with a constant inner VK, so statement passthrough (§5 of the M7 note) applies
     verbatim.
   - At 4 trees and the 192 columns that fit, it gives ≈ 115 KB. At ≤ 128 columns it gives 103 KB, but then the circuit
     does not fit 2^18.
   - **Recommended as the M7 fallback for size *robustness*, not as a route under 100 KB.** It is registered by reusing `c2_b64_q18_p20_fold3` for both C2 and C3, with
     distinct circuit VKs. Its identity is the circuit, not the PCS: the C3 VK must not be in `T_rec`, exactly like C1
     and C2.
3. **A cheaper narrow in-circuit Blake2s**, at ≤ ~4,500 cells per compression **at ≤ ~128 columns of width.** The fused
   gadget reaches 6,080 cells per compression, but only at 6,125 columns, so it does not help C2.

**What M7 compress must measure first** (one CPU run each, no GPU):
- (a) the exact compression count of the C2 verifier circuit for a real C1 proof;
- (b) C2's total columns with the minimal component roster;
- (c) then pick between "C1 narrow + C2 at 2^19 (≈ 113 KB at 150 columns, 4 trees)" and "C3 at 2^18 (≈ 103–115 KB)".
  Report to the owner that the plan's ≤ 100 KB gate needs ≤ ~120 opened columns in the last stage.

The model reproduces any (rows, b, q, cols, trees) point in under a second.

---

## 5. Hand-off to M7 (what is frozen now)

- **Names, domains and arithmetic:** §1. Use `c2_b64_q18_p20_fold3` for the shipped compact proof and `c1_b16_q27_p20_fold4`
  or `c1_b8_q36_p20_fold4` for C1. Ask profiles for any other point. Do not invent one.
- **Framing:**
  - no caps;
  - multiproof is the core;
  - FRI arity 8;
  - last layer 2^3 on C2;
  - binary Blake2s-256 Merkle;
  - classic interaction in C2, with no outer GKR section;
  - no fused Blake2s gadget in C2.
- **Corpus:** CP01–CP04, M03 and M04 (`scripts/rv64/rv64_m5_negative_corpus.py` v4, owner compress). CP01 can be hooked
  against today's vcs_lifted verifier immediately.
- **Corrections to plan §5 (M7 row "two-stage compress"):**
  - "multiproof dedup" is already in today's 706 KB;
  - "Merkle caps (16-node cut)" is net negative;
  - "arity-4 Merkle in C2" is larger, not smaller;
  - the C2 of the plan (`b16 q27`) bottoms out at ≈ 126 KB;
  - ≤ 100 KB needs `b64 q18` at ≤ 2^18 rows with ≤ ~120 opened columns (4 trees). [D/E] says the realistic band is
    103–115 KB;
  - ≤ 75 KB is out of reach with 32-byte digests.

**Where the bytes are, at the edge point** (2^18, b64 q18, 128 columns, 4 trees: 103.0 KB) [D]:

| part | KB |
|---|---:|
| trace-tree paths | 37.8 |
| FRI paths | 24.1 |
| opened values | 16.8 |
| FRI values | 16.3 |
| fixed (OODS samples, commitments, last layer, PoW) | ~8 |

Each commitment round is its own tree, so the same 18 positions pay one multiproof per tree. Two ways would cut the
37.8 KB:
- fewer rounds, for example a preprocessed-free C2 whose constants are wired as main constraints;
- a smaller query count at a higher blowup (b128 q15 p20 = 7·15 + 20 = 125, not 128).

Both are M7 research items, not registered profiles.
