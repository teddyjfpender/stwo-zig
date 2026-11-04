# M7 profile notes: D2 native, recsize outer, C1/C2 compress, outer LogUp-GKR

Stream `profiles`, branch `codex/rv64-m4-profiles`, 2026-11-04. This note gates the M7 soundness obligations in plan §5:
- C1 and C2 entries with conjectured-128 arithmetic;
- the outer GKR note;
- the D2 profile;
- the k-ary binding, which is in `rv64-m5-binding.md` §4.3.

Labels: **[M]** measured, **[D]** arithmetic on measured or pinned numbers, **[E]** estimate.

**Registry.** The entries live in `src/integrations/riscv_cpu/word16_execution/om31_security_candidate.zig`, after the comment "M7 candidate profiles": `CandidateProfile`, `CANDIDATE_PROFILES`, `candidateSpec/Config/Identity`, `OuterGkrFacts`, `requireOuterGkrBits*`. Tests are in `om31_security_candidate_test.zig`.

**Every entry is OFF BY DEFAULT.**
- None is a member of `Profile`, `PROFILES`, `Profile.parse` or the outer `protocol.Profile`.
- `profileFor` rejects each candidate config, and a test pins that.
- No CLI flag, environment variable or proof byte can select one.
- Admitted bytes, identities and the default (`conjectured128_b2_q108_p20_fold4`) are unchanged.

---

## 1. Profile table

Conjectured bits are `log_blowup · queries + pow` (the ethSTARK conjecture, the same rule as the accepted native and r1 outer profiles). Johnson bits are `queries · log_blowup / 2 + pow`, the provable regime with per-query error about √ρ.

| entry | layer | log b | q | pow | log₂ FRI arity | conj. bits | Johnson bits | identity domain |
|---|---|---:|---:|---:|---:|---:|---:|---|
| `conjectured128_b2_q108_p20_fold4` (admitted, today) | native | 1 | 108 | 20 | 4 | 128 | 74 | `…CONJECTURED-ethstark/v2` |
| `d2_native_b4_q54_p20_fold4` | native (D2) | 2 | 54 | 20 | 4 | 128 | 74 | `rv64-om31-native-d2-b4-q54-p20-fold4/CANDIDATE-v1` |
| `m3_outer_b4_q51_p26_fold4` | leaf/fold/root | 2 | 51 | 26 | 4 | 128 | 77 | `stwo/circuit/native-om31/m3-b4-q51-p26-fold4/lens-v1` (= recsize `5d68d0f01`) |
| `c1_b8_q36_p20_fold4` | compress 1 | 3 | 36 | 20 | 4 | 128 | 74 | `…/c1-b8-q36-p20-fold4/lens-v1` |
| `c2_b16_q27_p20_fold3` | compress 2, arity 8 | 4 | 27 | 20 | 3 | 128 | 74 | `…/c2-b16-q27-p20-fold3/lens-v1` |
| `c2_b16_q27_p20_fold4` | compress 2, arity 16 | 4 | 27 | 20 | 4 | 128 | 74 | `…/c2-b16-q27-p20-fold4/lens-v1` |

The tests pin four properties:
- every candidate is exactly 128 conjectured bits;
- no candidate falls below today's native default under Johnson (2× bits ≥ 148);
- identities are pairwise distinct and distinct from both admitted identities;
- each config's fold step is the declared one.

**No layer drops below the 128 label under the conjecture, and none drops below today's Johnson-regime level either.**

PoW is checked after the last FRI commitment and before queries are derived (`core/pcs/verifier_family.zig`), as for the accepted profiles. So it counts toward the query phase. The grind cost is 2^20 per C1/C2/D2 proof. C1 and C2 run once per request, so their grind is negligible. D2 grinds once per native segment.

### 1.1 Correction to the plan: "FRI fold 8/16" and `fold_step`

`fold_step` is the **log₂ folding arity per FRI layer**:
- `core/fri_family.zig` folds `positions >>= fold_step`;
- `foldToLineWithStep` removes `fold_step` degree halvings.

Today's "fold4" profiles therefore **already fold 16-to-1 per layer**. Plan §5's "FRI fold 8/16" for C2 means `fold_step` 3 or 4, not 8 or 16. A `fold_step` of 8 (arity 256) would open 255 sibling OM31 values per query per layer, about 8 KB, and is strictly worse for size (§3).

The registry carries both C2 arities. §3 recommends arity 8.

---

## 2. Algebraic terms vs blowup

The same conditional root-count model is used as in the native ledger (`ledger`):
- OODS and DEEP: c·samples·32·N;
- FRI envelope: (c+1)·65536·N_eval·(v+1);
- raw-modulo point probability 3^8/2^256.

Every outer/compress challenge is OM31: in-circuit lanes are 8-coordinate (`om31_native/common.zig`), with μ = 2^-243.3.

Raising the blowup from 2 to 16 grows the evaluation domain by 8× and loses 3 bits on the FRI/DEEP terms. The OODS term does not change.

With c = 512 columns, 8 samples per column and v = 30 [D, conservative]:

| layer | trace log | bits per proof (algebraic union) |
|---|---:|---:|
| outer r1 b2 | 22 | 190 |
| m3 b4 | 22 | 189 |
| C1 b8 | 20 | 190 |
| C2 b16 | 18 | 191 |
| D2 native b4 (per proof, before the κ union) | 22 | 189 |

The algebraic terms are 60+ bits below the 2^-128 query term at every layer. **The query term binds, and it is pinned at 128 in §1.**

**D2 promotion obligation.** `ledger()` takes `n = 2^max_trace_log` and folds the domain factor into the 65536 envelope at blowup 2. At promotion it must take `log_blowup` explicitly, adding +1 bit of weight for b4. It must also re-run `requireConditionalRomBudget` with the result. The margin is about 60 bits, so the outcome is not in doubt, but the arithmetic must be the receiver's.

### 2.1 Drift found: `LOCAL_RELATIONS` = 9, production has 10 [M]

The pre-existing test "candidate local relation roster matches production raw fraction authority" **fails at baseline**. It reports `expected 9, found 10`. The failure reproduces on an unmodified `bcd401ce4` tree on the pod, so these changes did not cause it.

The cause is the production `gkr_local/fractions.zig` `Relation` enum. It gained `byte_pair` in `63728c3f8`, "paired-byte local GKR projection".

**Ledger effect.** `ledger()` multiplies `p · LOCAL_RELATIONS` in four terms, so it undercounts those terms by 10/9. That is about +0.15 bit of weight inside a 60-bit margin. It is not a soundness problem.

**Why it is not fixed here.** `LOCAL_RELATIONS` is hashed into `identity()` and `profileIdentity()`, and those are mixed into the native channel. Changing it changes every native proof byte. This iteration must keep proofs byte-identical.

**Fix:** bump the native candidate identity (`…/v3`) with `LOCAL_RELATIONS = 10` at the next native format change. That is either the D2 promotion or the M5 native χ-chain version (`rv64-m5-binding.md` §3.3), whichever comes first. Until then, the failing test is the open marker.

---

## 3. Proof-size model for C2 (why arity 8, and what ≤ 100 KB needs) [E]

**Model.** Per query, for each tree, there are two parts:
- openings: about 200 base columns at 4 B, plus one Merkle path per tree;
- per FRI layer: (2^s − 1) sibling OM31 values at 32 B, plus the path in that layer.

Hashes are 32 B, OM31 values are 32 B, there are 4 trees, and the last layer is degree 0. "Caps + dedup" removes 4 path levels (a 16-node cap) and about log₂(q) levels of shared multiproof prefix per path.

**Calibration.** The model gives 870 KB for today's root (b2, q108, 2^22) against **748 KB measured** [M]. It overestimates by about 1.16×.

| C2 trace | log₂ arity 2 | **3 (arity 8)** | 4 (arity 16) | 5 |
|---|---:|---:|---:|---:|
| 2^16, raw | 190 KB | 175 | 179 | 204 |
| 2^16, caps + dedup | 106 | **108** | 124 | 150 |
| 2^18, caps + dedup | 126 | **126** | 138 | 166 |
| 2^20, caps + dedup | 147 | **143** | 160 | 197 |

Raw model numbers; divide by about 1.16 for the calibrated value [E].

What follows:
- **Arity 8 (`c2_b16_q27_p20_fold3`) is the size optimum, or within 2% of it, at every height.** Arity 16 costs 8–15% more.
- **≤ 100 KB needs a C2 trace of about 2^16 to 2^17, plus caps and dedup.** The calibrated value is 93 KB at 2^16 and 108 KB at 2^18.
- A 2^20 C2 lands at about 125 KB calibrated. So the compress chain must narrow:
  - C1 at about 2^20 (`b8_q36`, calibrated about 175 KB);
  - then C2 at 2^16 to 2^17.
- That is the two-stage shape of plan §5, now with a height target for C2. The C2 circuit must verify one C1 proof at 36 queries in ≤ 2^17 rows. That requires the fused Blake gadget (blake-gadget stream) and is the M7 risk to watch.
- The plan's ≤ 75 KB stretch needs both arity-4 Merkle in C2 and a smaller column count. Arity-4 Merkle is a hasher change: it needs a new profile id with a Merkle-arity field, which this registry does not have yet.

---

## 4. Outer LogUp-GKR soundness (M7 outer-gkr stream)

### 4.1 What changes

Today every outer proof commits its LogUp interaction columns: they are 50% of cells [M]. Outer GKR replaces those columns with a batched LogUp-GKR, using the fraction-sum layers of Papini–Haböck. The circuit then verifies a sumcheck per layer in-circuit, using OM31 operations and no hashes beyond the transcript.

### 4.2 Error terms

Model: one outer proof, `i` batched instances, the largest instance of `2^v` rows (so v layers), round degree d = 3, and tuple arity a. It is implemented as `outerGkrLedger`.

| term | degree weight | source |
|---|---|---|
| sumcheck rounds | i · d · v(v+1)/2 | layer k has k rounds of degree d; no credit for batching |
| instance mix | (2i + 2) · v | random combination of numerators and denominators per layer |
| layer binding | 2 i v | reducing two claims to one per layer (line restriction) |
| tuple compression | i · a · 2^v | distinct tuples colliding under α-compression |
| pole events | 2 i · 2^v | z hitting a compressed tuple, or the cleared rational identity |

The union over outer proofs multiplies these by `p`. Per-challenge error is degree × μ, by Schwartz–Zippel with the raw-modulo point probability μ = 3^8/2^256.

**Results** [D, from `zig test`; the arithmetic is pinned by tests]:

| facts | OM31 challenges | QM31 challenges (if drawn from p⁴) |
|---|---:|---:|
| caps: p = 256, i = 128, v = 30, a = 128 | **191.3 bits** (≥ 128 + 2 + 21 reserve) | 72.0 bits |
| realistic M7: p = 40, i = 16, v = 24, a = 8 | **206.7 bits** | 87.4 bits |
| GKR-specific terms only (sumcheck + mix + binding), caps | 217.8 bits | 98.4 bits |

**Findings:**
1. **The outer GKR must draw its challenges in OM31.** Our in-circuit lanes already do. With QM31 challenges, the tuple-compression term alone gives 72–87 bits, below 128. The plan's "about 2^-110 to 2^-115" was a QM31 sumcheck-only estimate. It left out the tuple term, which is not GKR-specific and is present for committed LogUp as well.
2. With OM31, GKR adds weight of about 2^25 to a union dominated by the 2^52 tuple term. Its marginal cost is under 0.001 bit. **Outer GKR is not a soundness risk under this model.** The obligations are completeness and binding, below.
3. **Binding (as native `gkr_late_binding`, basis `binding_theorem_required`).**
   - The GKR claims must be mixed into the outer transcript before the challenges that consume them.
   - The final layer's evaluation claims must be checked against the committed base columns through the outer PCS (OODS), not taken from the prover.
   - Each instance's (relation, component) tag must be inside the mixed instance list.
   - The reviewer checks these three points against the code. The corpus cases are `M01` (round tamper) and `M02` (final-claim tamper).
4. **The in-circuit verifier must use constant round counts per class.** `v` per instance is a function of `S_out` (`rv64-m5-binding.md` §1). The sumcheck length is therefore a constant and is never muxed. This is the same rule as for log sizes.

### 4.3 Obligations before the outer-gkr stream merges

- A CPU reference verifier, plus a tamper corpus: every round coefficient, every claim, instance order.
- `M01` and `M02` rejected by a fresh receiver.
- The `OuterGkrFacts` of the real circuit, read from the class constants, pass `requireOuterGkrBits(·, 151)`.
- The kill rule of plan §5 (25% of leaf cells) is measured by outer-gkr, not here.

---

## 5. C1 and C2: statement passthrough and binding

- C1 verifies exactly one top-level node proof, a fold or leaf with outputs `NS`, under a VK it checks for membership in `T_rec`. This is `rv64-m5-binding.md` §4.1(2) with k = 1. C1 outputs `NS` unchanged.
- C2 verifies exactly one C1 proof, against a C1 VK that is a constant of C2. That is allowed because C1 is not self-recursive. C2 outputs `NS` unchanged.
- The receiver verifies C2 under its derived C2 VK and applies the root checks of `rv64-m5-binding.md` §5 to the passed-through `NS`.
- The domain strings in §1 are hashed into authority identity, wire header, outer transcript and in-circuit transcript, exactly as recsize does for `m3`. A C2 proof therefore cannot verify under C1 parameters, which is case `M03`.
- C1 and C2 each add one outer attempt to the union in `rv64-m5-binding.md` §6. That costs no bits beyond the per-attempt 2^-128.

---

## 6. D2 (native b4_q54_p20): what it trades

- **Soundness:** identical labels to today (128 conjectured, 74 Johnson). §2 shows a 1-bit algebraic loss inside a 60-bit margin.
- **Cost [E]:**
  - The native LDE doubles: +30–40% native prove, and more device memory per segment. Plan §2.5 says to pick at most two of {2^24 segments, b4, concurrency}.
  - In-circuit query work halves: 54 instead of 108 queries for every leaf's FRI and Merkle decommitment verification.
  - Plan M4.0 deliverable 6 decides whether D2 is net positive. This note does not.
- **Format:**
  - A new native protocol identity (`CANDIDATE-v1` domain).
  - The FIXED commitment is sealed at the profile's blowup, so FIXED roots, AOT catalogues and every native VK in `T_nat` change.
  - `gkr_main.zig` `candidateLabel` and the `--security-profile` usage must gain the entry at promotion. That file belongs to canon-vk (integration note).

---

## 7. Promotion checklist (any entry)

1. Move the entry into the admitted registry: `Profile` plus `PROFILES` for native, `protocol.Profile` for outer/compress, owned by canon-vk/compress. Keep its name and domain string.
2. Run the identity regression test: the admitted identities for existing profiles must stay byte-identical.
3. Run the corpus `P01`/`P02`-style profile mismatch against a fresh receiver.
4. Get fresh-receiver acceptance on 26235156 and 24628607 under the new profile, with receipts.
5. For D2: re-run the ledger with `log_blowup` (§2). For C2 with arity-4 Merkle: assign a new id.
6. `security_qualified` stays false. No entry creates a certificate (`requireWholeProtocolPromotion` still returns `NoReviewedWholeProtocol128Certificate`).
