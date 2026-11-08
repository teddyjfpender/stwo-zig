# LogUp-GKR prototype: LS scalar-range lookups with committed-column binding

Status: the original STEP 1 design below was written against `eac3b7c07`.
The recovered implementation now has an explicitly selected experimental
mini-AIR/tool for STEP 2a and Safe/Fast adversarial tests. It has not joined
the production LS owner/RAM protocol (STEP 2b), and has no recursive receiver.
The default Word16 protocol and receivers remain unchanged. The build catalog
now exposes the prototype and its dedicated test suite; implementation and
resource limitations are documented in
`src/integrations/riscv_cpu/logup_gkr/README.md`. Estimates below are historical
design hypotheses, not measured speedups.

Upstream reference, read only and not executed: starkware-libs/stwo at
`826591c6c` (2026-08-13), `crates/stwo/src/prover/lookups/*` and
`crates/examples/src/xor/gkr_lookups/{mle_eval.rs,accumulation.rs}`. The
binding method is the univariate IOP for multilinear evaluation from
Papini and Haböck, *Improving logarithmic derivative lookups using GKR*
(eprint 2023/1284, Section 5.1). Upstream marks `mle_eval` as `dead_code`, has
a lifted-protocol TODO, and never wires it end to end into an AIR. We adapt
the method. We do not port the upstream code line for line.

## 1. The gap this closes

`src/prover/lookups/gkr_verifier.zig:partiallyVerifyBatch` returns
`GkrArtifact{ood_point, claims_to_verify_by_instance, n_variables_by_instance}`.
These are multilinear evaluation claims about the GKR *input layer* at a random
point. Today's tests check them against arrays they hold in memory. A receiver
holds only commitments. It must show that the input layer is the committed
execution witness, put through the numerator and denominator expressions the
AIR defines. It must also take the shape from its own geometry, never from the
proof. Without this, GKR proves a sum over arrays the prover chose freely.

## 2. Family choice: LS U16/U8 range lookups

Cells come from the baseline prefix4 `roster.json`
(`/private/tmp/stwo-rv64-perf-runs/perf2-baseline-prefix4`).

| batch | LS log / tail log | INTER cells (all) | LS+tail range pair cells | share of INTER |
|---|---|---:|---:|---:|
| 0 | 20 / 18 | 325,585,792 | 41,943,040 | 12.9 % |
| 1 | 19 / 16 | 283,889,152 | 18,874,368 | 6.6 % |
| 2 | 19 / 15 | 281,792,000 | 17,825,792 | 6.3 % |
| 3 | 19 / 18 | 335,688,960 | 25,165,824 | 7.5 % |
| prefix4 | | 1,226,955,904 | 103,809,024 | 8.5 % |

The LS layout is `load_store_v2/layout.zig`. INTER has 48 columns:

- 8 RAM columns: an inverse and the RAM prefix.
- 9 paired-inverse QM31 columns, holding 36 base columns.
- One local prefix, holding 4 base columns.

There are 18 local fractions. One is OWNER, 12 are U16 (`LOGICAL_U16`), 4 are
U8 (`LOGICAL_U8`) and one is SELECTION. Pairs 0 and 8 mix OWNER and SELECTION
with range lanes. Moving the 16 range lanes to GKR leaves OWNER and SELECTION
in one pair, so 8 pair columns (32 base columns) disappear.

Why this family:

1. **It closes inside one proof.** range16 and range8 are local tables, recommitted
   for each proof. `sources.zig:validateOpenForGlobalRam` requires every
   non-RAM relation to close inside the proof. Neither family nor table crosses a shard.
2. **It has 16 unconditional singles per row, exactly 2^4 lanes.** Every
   numerator is 1 (`LogUpSingles`). Each denominator is affine in one physical
   MAIN column: `z16 - c16*m` or `z8 - m`. `projection.zig` stores all 16 query
   columns physically. None is an affine virtual column.
3. **It is GKR's best case per row.** The binding costs one eq column per
   component size. 16 fractions per row amortise it best. If GKR loses here, it
   loses on every thinner family.
4. **It exercises the batch path.** LS and LS_tail have different sizes, and both
   are present in batch 0. This tests the multi-size batch GKR, which has no
   test today.

Considered and not chosen:

- **CPU range.** This is 3 U16 and 3 U8 per row at log22. The range share is 3
  whole QM31 columns (12 base columns, 50.3 M cells per proof, 15-18 % of
  INTER) plus half of the OWNER pair. It is larger in absolute terms. But 6 is
  not a power of two, so it needs zero-numerator padding lanes and a generic
  numerator. Net saving is at most 8 of 12 columns. It is the natural second
  target once LS is measured.
- **BINARY AND.** binary plus binary_tail INTER is about 19 M cells in batch 0.
  The share is too small to be informative.

The real volume is the whole U16/U8 family across CPU, ALU, SHIFT, LS,
INITIAL and the tails. Section 9 covers extending to it.

## 3. Protocol: experimental variant `WGKR-LS-RANGE-v0`

This is a separate variant chosen by receiver configuration. It has its own
transcript tag and its own component shapes. LS and LS_tail INTER widths change,
and `mixMaterials` already mixes every shape width. The default `SCHEMA = 5`
transcript is unchanged byte for byte.

Transcript order. The existing `execution.zig` and `stage1_worker.zig` sequence
is in plain text. The **NEW** steps are added.

1. `P.mix(setup, request, image)`, which includes shapes. **NEW:** mix
   `(0x57474b52 'WGKR', revision 0, n_instances, n_vars[i], lane-map id)`.
2. Commit FIXED (the retained root).
3. Commit MAIN. The root is mixed. In the global lane this is followed by the
   stage-one barrier and the manifest.
4. Draw all relation challenges with `P.draw` or `drawWithSharedRam`, unchanged.
   This includes `range16 = (z16, c16)` and `range8 = (z8, 1)`.
5. **NEW: GKR batch** on the same channel, over instances LS and LS_tail when
   present. Instances run in decreasing size (`n = log + 4`). For each layer:
   - mix the active claims, starting with the output claims `(n_root, d_root)`;
   - draw `alpha` and `lambda`;
   - run the sumcheck, mixing each round polynomial and drawing a challenge;
   - check the circuit;
   - mix the masks, then draw the fold challenge.

   Output: the terminal point `r` (MSB-first, length 24 for LS) and per-instance
   terminal claims `(nu_i, delta_i)` at the suffix `r[n_unused_i..]`.
6. **NEW: receiver-side scalar checks.** These are listed in section 7.
7. Generate interaction for all classic relations, unchanged except LS and
   LS_tail. Those keep RAM, the OWNER-SELECTION pair, the eq column `c_i` and
   the MLE prefix `S_i` (v0).
8. Mix claims, with LS and LS_tail `range16` and `range8` ledgers fixed to zero.
9. v1 only: draw `gamma` and build the merged prefix (section 5.4).
10. Commit INTER, then composition, OODS, FRI, PoW and queries, all unchanged.
    The LS variant adds the constraints of section 5.

**Commitment before challenge.** The GKR input layer is
`V(p, j) = D_j(p)`. Its values come from MAIN trace values and from `(z, c)`.

- The MAIN root is mixed before step 4.
- `(z, c)` are drawn before any GKR message.
- Every GKR challenge comes after the claims it constrains: output claims are
  mixed before `alpha` and `lambda`, each round polynomial before its challenge,
  and the masks before the fold challenge.
- `r` is therefore fixed only after `V` is fixed. The eq column depends on `r`,
  so it is committed in INTER, after `r`. This mirrors classic LogUp, where the
  inverse columns depend on `z` and are committed after `z`.
- In v1, `gamma` is drawn after `nu`, `delta` and every classic claim are mixed.

**List decoding.** The MAIN commitment binds a codeword only up to the FRI list.
The prover can choose among list members after seeing `r`, exactly as it can
after seeing `z`. The existing `z` analysis already pays this with a union
bound over the list size `L`. The `r` draw pays the same factor (section 6).
This adds no new assumption.

## 4. Index conventions (the main correctness risk)

- **GKR leaf index:** `idx = (p << 4) | j`.
  - `p` is the **storage** row position (bit-reversed circle-domain order), the
    `R.trace.physical(logical, log)` used for LS INTER writes.
  - `j` is the lane: 0-11 are the U16 lanes in `LOGICAL_U16` order, 12-15 the
    U8 lanes in `LOGICAL_U8` order.
- **Point layout.** The circuit pairs `(2i, 2i+1)`, folding the least
  significant bit first. `Mle.fixFirstVariable` and the `ood_point` append order
  are MSB-first. So `r = (r_row[0..log], r_lane[0..4])`:
  - `r_row` is MSB-first over the bits of `p`;
  - `r_lane = r[log..log+4]`.

  The tail instance takes the suffix `r[2..24]` when its log is 18. Its lane
  part is the same `r[20..24]`, so LS and the tail share the lane weights.
- **Why this order.** The bottom four GKR layers fold the 16 lanes inside one
  row, which is what makes streaming possible (section 8). The eq column is
  `c(p) = eq(bits(p), r_row)` at storage index `p`. That is exactly upstream's
  convention: `c(D[b0..]) = eq(b, r)` on a `BitReversedOrder` column.
  `bits(0) = 0^n` sits at coset index 0, and `bits(N-1) = 1^n` at coset index 1.
- **Who defines the leaf set.** The receiver defines it through the binding
  expression, not the prover. A bad index map can only break completeness. It
  cannot make the GKR sum cover a different multiset than the one the AIR
  authenticates. So index bugs show up as failed honest proofs, and the tests in
  section 10 target them.

## 5. Binding terminal claims to committed columns

### 5.1 Reducing to one weighted row sum

The lane weights `w_j = eq(bits(j), r_lane)` are verifier constants. Write
`E(p)` for the weighted denominator of row `p`. Because `D_j` is affine:

```
E(p) = sum_j w_j * D_j(p) = K - sum_j u_j * m_j(p)
K    = z16 * sum_{j<12} w_j + z8 * sum_{j>=12} w_j
u_j  = w_j * c16   (j < 12),   u_j = w_j   (j >= 12)
```

The denominator claim is then a single row sum:

```
delta = Dtilde(r) = sum_p eq(bits(p), r_row) * E(p)
```

The numerator claim needs no binding, because singles have numerator 1
everywhere. Its multilinear extension at any point equals
`sum eq(r, idx) * 1 = 1`, so the receiver checks `nu == 1` exactly. This check
is load-bearing. Without it, the prover can choose the last mask's numerators,
which amounts to choosing arbitrary multiplicities.

For a future family with non-constant numerators `N_j`, draw `beta` after
`(nu, delta)`. Bind `nu + beta*delta` with `E'(p) = sum_j w_j (N_j + beta D_j)`.
Nothing requires `E` to be linear. It is evaluated row by row inside a
constraint, so quadratic denominators also work, at degree `1 + deg(D)`.

### 5.2 The eq column

`c` is a committed QM31 column, so 4 base columns. Its constraints are ported
from upstream `eval_eq_constraints`, `eval_carry_quotient_col` and
`eval_step_selector`:

- **C1 (anchors):** `(c - eq(0^n, r_row)) * is_first + (c - eq(1^n, r_row)) * is_second = 0`.
- **C2 (recurrence):** `c(x) - c(x + 2*step) * q(x) = 0`, where `q` is the
  succinct carry-quotient polynomial. The verifier evaluates `q` at the OODS
  point in O(n^2) QM31 operations. The prover interpolates and extends `q` once,
  as an uncommitted QM31 column.

C2 relates each half coset cyclically. With `q != 0` on the trace and C1
anchoring both half cosets, `c` is uniquely determined. That needs every
`r_row[k]` outside `{0, 1}` (section 7, R5).

### 5.3 The weighted-sum prefix (v0: own column)

`S` is a committed QM31 column, so 4 base columns. Its constraint is cyclic, in
coset order, with mask `[0, -1]`:

```
S(x) - S(x - step) - c(x) * E(x) + delta / N = 0
```

Summing over the trace domain gives `sum_p c(p) E(p) = delta`. This is the same
kind of statement as a classic LogUp claimed sum. All new constraints have
degree 2, so they fit the existing 2n native domain. LS's max degree stays 3.

### 5.4 Merging into the LS local prefix (v1: saves 4 columns)

The local prefix authenticates `A`, the sum of OWNER and SELECTION fractions,
against the claim `S_A`. In v1 its row term becomes:

```
A-terms + gamma * c(x) * E(x) - (S_A + gamma * delta) / N
```

`S_A` (mixed in step 8) and `delta` (step 5) are both fixed before `gamma`. So
`A + gamma*B = S_A + gamma*delta` with `(A, B) != (S_A, delta)` holds with
probability at most `1/|F|`.

v1 is only sound with this ordering. Merging is unsound if `gamma` is drawn
before `S_A` is fixed: the prover then sets `S_A := A + gamma*(B - delta)`.

## 6. Soundness

**Lemma.** Assume the following.

- (i) The MAIN root and `(z, c)` are fixed before any GKR challenge.
- (ii) The GKR verifier accepts the receiver-fixed shape, giving outputs
  `(n_i, d_i)` and terminal claims `(nu_i, delta_i)`.
- (iii) Every `d_i != 0` and every `nu_i == 1`.
- (iv) The STARK accepts C1, C2 and the prefix constraint at the receiver-computed
  `eq(0^n, r)`, `eq(1^n, r)`, `q`, `w_j`, `K`, `u_j` and `delta_i`.

Then, except with probability `eps_GKR + eps_STARK` (times the list factor `L`):

```
n_i / d_i = sum_{p, j} 1 / D_j(p)    over the committed MAIN trace of instance i
d_i       = prod_{p, j} D_j(p)       which is nonzero, so every leaf is defined
```

*Proof sketch.*

1. By (iv), C1 and C2 force `c = eq(., r_row)`. The prefix forces
   `delta_i = Vtilde_i(r)`, the true input-layer multilinear extension.
2. By (iii), `nu_i = 1tilde(r)`. So both terminal claims are true.
3. GKR soundness runs backward through the layers. At each layer the sumcheck
   round polynomials have degree at most 3, and the mask fold is exact for a
   multilinear function. Hence the output claim is the true projective sum of
   `V_i`, which is fixed before `r` by (i). Any false output claim survives to a
   true terminal claim only with probability `eps_GKR`.
4. `d_i != 0` makes `n_i / d_i` well defined.

The closure then sums `sum(classic claims) + sum_i n_i/d_i` (minus the RAM part
in the global lane) and requires 0. Haböck's LogUp lemma gives multiset
inclusion of the LS range queries in `[0, 2^16)` and `[0, 2^8)`, with error at
most `M / |F|`. This is the existing argument. GKR only replaces how the LS
range part of the sum is authenticated.

**Error budget.** `|F| = |QM31| ≈ 2^124`.

| Term | Count | Bound |
|---|---|---|
| GKR, LS `n = 24` | per layer k: `3k` sumcheck, `+1` lambda, `+1` alpha, `+1` fold | `sum_{k<24} (3k + 3) = 900`, so `<= 2^-114` |
| eq-point abort | `2 * 20` | `<= 2^-118`, completeness only |
| v1 gamma merge | 1 | `2^-124` |
| LogUp identity (unchanged) | `M ≈ 1.5e8` range fractions | `<= 2^-96.8` |

The protocol's nominal level remains the q70/PoW26 FRI bound (blowup 2, about
96 bits nominal). GKR is not the weakest term.

Round-by-round error is `3/|F|` per round. The Fiat-Shamir loss is therefore
about 122 bits per hash query, above the nominal level. Grinding `z` or `r` by
recommitting MAIN is the same attack as classic LogUp's.

**Self-attack (what fails if a check is dropped).**

- `nu == 1` dropped: the prover chooses the numerators, i.e. forges multiplicities. **Fatal.**
- Shape taken from the proof: an extra layer moves the terminal point off the
  eq column's dimension, and the `n_variables_by_instance` returned today comes
  from the proof's mask count. **The receiver must compare it to geometry.**
- `d_root != 0` dropped: the sum is undefined. Leaves with a zero denominator
  would be accepted.
- Eq column generated by the recurrence instead of independently: a wrong `q`
  port would pass tests while binding a non-eq vector. **The prover must build
  `c` from `gen_eq_evals`.** Tests compare the AIR-determined column to
  `gen_eq_evals` (section 10).
- GKR run on a separate channel or before step 4: `V` is not fixed before `r`. **Fatal.**
- v1 with `gamma` drawn before the claims are mixed: see section 5.4.
- Non-canonical QM31 on the wire: transcript malleability. Decode must reject
  values `>= p`.
- Variable-length round polynomials: not a soundness bug, but they break a
  fixed-shape recursive verifier. The wire must use exactly 4 coefficients
  (3 once compressed).

## 7. What the receiver checks (fresh process)

- **R1. Shape from geometry.**
  - Instances are LS, plus LS_tail when `ls_tail_log` is set.
  - `n_vars = log + 4`.
  - `sumcheck_proofs.len == max n`; layer k has exactly `k - n_unused` rounds,
    each with 4 coefficients.
  - Masks are 2 columns of 2 values.
  - Limits apply: at most 32 layers and at most 4 instances.
- **R2. Output claims.** Canonical, with `d_i != 0`.
- **R3.** `partiallyVerifyBatch` with gate `LogUp`.
- **R4.** `nu_i == 1`.
- **R5.** `r_row` coordinates for each instance are outside `{0, 1}`.
- **R6. Closure.** `sum(claims.values())` with the LS and LS_tail `range16` and
  `range8` ledgers forced to zero, plus `sum_i n_i * d_i^-1`, minus the RAM part
  in global mode, equals 0.
- **R7.** STARK verification with the LS-GKR components. The verifier computes
  `eq0`, `eq1`, `q(OODS)`, `is_first`, `is_second`, `w_j`, `K`, `u_j`, `delta_i/N`.
- **R8.** The variant comes from receiver configuration only. Tag, shapes and the
  fixed root are mixed as in step 1.

## 8. Memory plan

The current `gkr_prover.proveBatch` calls `buildLayers` and materialises every
layer.

- LS (`n = 24`):
  - singles input layer: `2^24 × 16 B = 256 MiB`;
  - generic layers: `sum_{k<24} 2^k × 32 B ≈ 512 MiB`;
  - oracle clones, `fixFirstVariable` halves and `EqEvals` (64 MiB at k = 23);
  - peak about **1.2-1.4 GiB**, plus about 25 % for the tail.

Bounded plan (v1 prover):

1. **No leaf table.** `D_j(p)` is computed on demand from the retained LS
   metadata (u16/u8 per lane, 32 MiB). It needs one QM31 multiply-subtract per
   leaf. The `dict16` and `dict8` inverse tables are not used.
2. **Lane layers are row-local.** Layers 24 to 21 fold the 16 lanes inside a row.
   Layer 20 (one fraction per row, 32 MiB) and everything above (32 MiB) are
   stored. Layers 21-24 are recomputed when needed.
3. **Streamed first round.** For the sumcheck of a lane layer, round 1 streams
   from the metadata. Only the half table after the first fix is materialised:
   input layer denominators `2^23 × 16 B = 128 MiB`, with the numerators kept
   symbolically constant at 1; layer 23 `2^22 × 32 B = 128 MiB`.
4. **Split EqEvals.** Represent EqEvals as `eq(y_hi) ⊗ eq(y_lo)`, two tables of
   about `2^12`, instead of `2^(k-1)`.

Target peak: **≤ 256 MiB for each instance alive at the same time.** The classic
path for the same columns holds 32 base columns at log20: 128 MiB of trace plus
256 MiB of 2n LDE (plus coefficients if retained). The variant adds eq and `S`:
8 base columns, about 48 MiB with LDE.

A materialise-everything v0 is acceptable as a correctness gate, provided its
peak is recorded honestly.

## 9. Expected costs (estimates, replaced by STEP 3 measurement)

**Cells.**

- Removed: LS and LS_tail drop 32 base columns each.
- Added: v0 adds 8 (eq + `S`); v1 adds 4 (eq only).
- Prefix4 totals:
  - v0 net: −77.9 M INTER cells (−6.3 %);
  - v1 net: −90.8 M (−7.4 %);
  - batch 0, v1: −36.7 M (−11.3 % INTER, −5.0 % MAIN+INTER).
- Table side (range16/range8, log16 and log8) is unchanged.

**Prover work.**

- GKR sumcheck is about 30 QM31 multiplies per leaf: roughly `5e8` for LS
  batch 0. That is about 2-5 core-s in today's scalar, allocation-per-round Zig,
  and about 0.3-0.6 core-s once packed and chunked across the work pool.
- Removed classic work for 32 columns at log20:
  - interaction fill: cheap dictionary products, about 0.1 core-s;
  - IFFT/FFT, Merkle and LDE: 256 MiB of Blake2s input;
  - 8 degree-3 pair constraints at 2^21 points;
  - DEEP quotients;
  - roughly 1.5-2 core-s in total.
- Verdict before measuring: **plausibly neutral to slightly positive in CPU
  seconds, and only after the sumcheck is parallelised.** The unoptimised GKR
  will probably lose. Because two proofs run concurrently, the wall effect is
  smaller still.

**Proof bytes.**

- GKR proof, LS plus tail: 276 rounds × 4 × 16 B = 17.7 KB, masks 46 × 64 B =
  2.9 KB, outputs 64 B. Total about **20.7 KB** (16.3 KB with compressed rounds).
- Removed queried values for about 48-56 base columns: 70 queries × 1-2
  positions × 4 B is −13 to −31 KB. OODS changes by less than 1 KB.
- Net is **−15 to +8 KB** on 0.8-1.2 MB CPU proofs: about neutral.

**Native verifier.**

- GKR costs about 1,000 Blake2s compressions:
  - per layer: claim mix 2, alpha and lambda 2, mask mix 3, fold 1;
  - per round: 2 to mix + 1 to draw;
  - plus about 4k QM31 operations.
- The eq and `q` evaluation costs about 3k QM31 operations.
- Fewer queried columns save about 500 compressions.
- Net is +0.1-0.3 ms against about 38 ms per proof today.

**Recursive verifier.** Net is about +500 compressions and −12k QM31
operations. Against the leaf's about 3.1 M Blake G gates (about 39k
compressions), that is **about +1.5 %**.

- It needs new circuit gadgets: sumcheck round check, eq, fraction gate,
  carry-quotient evaluation.
- That gadget work is not part of this prototype. STEP 3 reports operation
  counts from a counting channel.

**Scaling beyond LS.** The same batch can take every U16/U8 consumer, CPU
included, as further instances. Each component pays 4 base columns at its own
size. That only pays when a component has at least 3-4 range fractions per row.
The table side can also move to GKR (`LogUpMultiplicities`) with a
preprocessed-value binding. It is not worth it at log16.

## 10. STEP 2 and STEP 3 plan, and the adversarial suite

**2a. Real-witness family proof (correctness gate).**

- An experimental mini-AIR with three components:
  - an LS-range consumer whose MAIN holds the 16 range columns of a real LS
    trace, taken from a prefix-batch source or the existing LS native fixtures;
  - range16;
  - range8.
- The same witness is proved two ways: classic paired LogUp, and GKR with the
  eq/`S` binding.
- A fresh-process receiver verifies each.

**2b. Word16 integration.** The LS and LS_tail variant inside the execution
transcript, behind the variant tag. Measured on prefix4 batch 0 against the
baseline, with heavy runs under the heavy lock.

**Unit tests** (wired into an existing lookups or Word16 test root):

- `gen_eq_evals` against the AIR-determined `c` at every storage index, for log
  2-12 and random `r`.
- C1/C2 vanish for the honest `c`, and any single-cell mutation violates them.
- `q(OODS)` succinct against interpolated.
- Two-instance GKR with different sizes, prove and verify (no test today).
- The singles `nu == 1` path.
- Wire canonicality and fixed shape.

**Adversarial tests.** Each must be rejected, and at the stated check.

| Attack | Rejected at |
|---|---|
| Tampered GKR round-polynomial coefficient | R3 `InvalidSumcheck` |
| Tampered layer mask (GKR re-run consistently) | R3 `CircuitCheckFailure` |
| Wrong terminal claim, AIR shift using `delta + 1` | R7 OODS mismatch |
| Last mask numerators ≠ 1 (forged multiplicity) | R4 |
| Extra layer or shape change | R1 |
| `d_root = 0` | R2 |
| Mutated committed LS range column after GKR | R7 |
| Same mutation applied to GKR too | R6 closure |
| Unbalanced lookup: value outside `[0, 2^16)` proved honestly through GKR | R6 |
| Eq-column cell flip | R7 |
| Synthetic `r_row[k] ∈ {0, 1}` | R5 |

**STEP 3 compares** prover wall and per-stage seconds (from
`physical-*.stages.json`), user and sys time, faults, peak RSS, proof bytes,
fresh verifier time, INTER cells removed, and counted hashes and field
operations for the native verifier and a recursion estimate. Classic and GKR
use the same witness. Each result is reported as it comes out, including a loss.
