# Outer LogUp-GKR, profile `outer_gkr_om31_strict_v1` (stream outer-gkr, M5 iteration of the M7 lever)

*2026-11-04, branch `codex/rv64-m5-outer-gkr`. This is the soundness/binding section the profiles note
(`rv64-m7-profiles.md` §4.3) asks the outer-gkr stream for. It extends §4 of that note; the profiles stream
owns that file, so this argument lives here and is linked from the M5 interface contract. Labels: **[M]** measured
(receipt in `vectors/reports/rv64-m5-20261104/outer-gkr/`), **[D]** arithmetic on measured numbers, **[E]** model.*

**Status: OFF BY DEFAULT.** No outer prover, circuit or receiver selects the profile. The flag-gated hook is specified
in `/workspace/m3/M5-INTERFACES.md` (section `outer-gkr`) for canon-vk, which owns the outer circuit files.

## 1. What the profile fixes

| item | value | where |
|---|---|---|
| name / identity domain | `outer_gkr_om31_strict_v1` / `stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v1` (SHA-256 into 8 words) | `outer_gkr/profile.zig` |
| field of challenges | OM31 (degree 8), raw-Blake OM31 channel = the outer transcript | profiles note §4.2 finding 1 |
| draw rule | **strict**: a draw is admissible only if all 8 raw words are `< 2p`; otherwise the section is rejected (never redrawn) | `section.zig StrictChannel`, `circuit.zig requireAdmissible` |
| instance roster per class | constant list of (component, lane group, row_log, lane_log), strictly ordered | `Class`, `instancesFor` |
| hybrid rule | a component goes to the GKR only if its classic OM31 interaction (2 × QM31-counted facts) is wider than its 16 binding columns: `triple_xor` (48), `m_31_to_u_32` (24), `blake_g_gate` (104), `verify_bitwise_xor_12` (64). Others stay classic LogUp. | `gkrBound` |
| lane groups | binary decomposition of a component's lookups (blake 26 = 16+8+2; triple 12 = 8+4; m31 5 = 4+1; xor12 16) — no padding waste beyond the power-of-two lanes of each group, and the leaf fits one 32 GB GPU | `instancesFor` |
| layout | index = lane · 2^row_log + row (lanes are the most significant variables) | §5 |
| round polynomials | exactly 4 coefficients, leading coefficient nonzero | `checkShape` |
| transcript | `mixU32s(header)`, `mixFelts([salt])`, then the batched GKR of the shared `verifier_kernel` | `section.verify`, `circuit.verify` |
| header | identity[8], magic, version, class id, n, one word per instance `(component<<24 | group<<16 | row_log<<8 | lane_log)` | `Class.header` |
| wire | `[magic, version, class, n, L] salt[8] roots[16n]`, per layer `rounds[depth][4][8]`, masks of the active instances (class order) | `encode/decode` |

Real classes (24628607): `leaf-cpu-24628607` (census-v2 nodes 0,1,3,4,7,8) and `fold-24628607` (node 20 and its
row-geometry class): 8 instances, **L = 27 layers, 351 sumcheck rounds**, 432 draws, section **69,812 B** / 69,300 B.

## 2. Error terms (sumcheck error and the rest)

Per outer proof with `i` instances, `v = L` layers, round degree `d = 3`, tuple arity `a`, instance size `2^v`
(the profiles ledger `outerGkrLedger`, conservative: no batching credit). Leaf/fold class, `i = 8`, `v = 27`,
`a = 32`, union over `p = 40` outer proofs per request (24628607 has 33):

| term | degree weight per proof | × p = 40 |
|---|---:|---:|
| sumcheck rounds `i·d·v(v+1)/2` | 9,072 | 2^18.5 |
| instance mix `(2i+2)·v` | 486 | 2^14.2 |
| layer binding `2·i·v` | 432 | 2^14.1 |
| tuple compression `i·a·2^v` | 2^35 | 2^40.3 |
| pole events `2·i·2^v` | 2^31 | 2^36.3 |
| **total** | | **≈ 2^40.4** |

Per-challenge point probability:
- registry model (raw-modulo, `requireOuterGkrBits`): μ = 3^8/2^256 = 2^-243.3 → **≥ 202 bits** for the union;
- strict draws: conditioned on admission each coordinate is uniform on M31 (each value has exactly 2 preimages in
  [0, 2p)), so μ = p^-8 ≈ 2^-248 → ≥ 207 bits.

The **sumcheck error proper** of the actual batched protocol is Σ rounds · d / |F| = 351 · 3 / 2^248 ≈ 2^-237.9 per
proof (plus one degree-1 line reduction and two batching combinations per layer: 27 · 3 more terms of degree ≤ max
instance count). GKR-specific terms are 2^-224 even with the registry's conservative per-instance overcount; the
union is dominated by the tuple term, which is not GKR-specific (committed LogUp has it too).

`P.requireSecurity(class, 40)` pins `requireOuterGkrBits(·, 151)` and the characteristic bound for both real classes
(test "outer GKR profile"); with QM31 challenges the same facts fail at 124 bits (pinned in the same test).

## 3. Strict draws: why rejection, why it is sound, what it costs

- **Rule.** Every GKR draw reads the 8 raw Blake words; if any word is `≥ 2p` the section is invalid. In circuit,
  each word's 16-bit limbs give `t = hi − 0xffff`, `s = (lo − 0xfffe)(lo − 0xffff)`; `word ≥ 2p ⇔ t = s = 0`; since
  `p ≡ 3 (mod 4)`, `t² + s² = 0 ⇔ t = s = 0` over M31, and the 8 factors of a draw are multiplied and shown
  nonzero with one guessed inverse (constraint, not a branch). Test: `0xfffffffe` and `0xffffffff` make the graph
  unsatisfiable; `0xfffffffd`, `0xfffeffff`, `0xffff0000` do not.
- **Same values as the existing provers.** On admitted draws `w mod p` equals the raw-mod channel's value, so the CPU
  prover (`gkr_prover`) and the CUDA traversal (device raw-Blake channel) are reused unchanged; the receiver adds only
  the predicate. Measured: the GPU section is **byte-identical** to the CPU reference section (test-small class).
- **Soundness.** Rejection removes transcripts and never adds one; challenges of admitted transcripts are uniform.
  The salt is a free Fiat–Shamir nonce mixed before the first draw: choosing among salts is the same as making more
  random-oracle queries, already covered by the query budget of the FS argument (error ≤ Q · ε).
- **Completeness.** Pr[a section hits a rejected draw] ≤ 432 · 8 · 2^-31 ≈ 2^-19.2 for the real classes. The prover
  replays the receiver and re-salts (`proveCpu`, `gpu_class.sh`): expected attempts 1 + 2^-19.
- This closes the open item of `rv64-gkr-circuit-cost-gate.md` / diet README §4 ("in-circuit `drawSecureFelt` does not
  reject raw words ≥ 2p") **for the outer GKR section**. The other in-circuit channels are unchanged (not this
  stream's files).

## 4. Binding obligations (profiles note §4.2 item 3) — status

| obligation | how | status |
|---|---|---|
| GKR claims mixed before the challenges that consume them | header + salt mixed first; roots mixed at layer 0 before α, λ (shared kernel) | done, tested |
| each instance's (relation/component, group) tag inside the mixed list | one header word per instance, class-constant order | done; corpus G03/G04/G13 |
| constant round counts per class, never muxed | class constants; strict shape; 4 coefficients per round | done; corpus G05/G10/G15/G16 |
| root closure | `Σ n_root/d_root` (each `d_root ≠ 0`) + classic claimed sums + public bus term = 0, checked by the outer verifier | section exposes `root_sum`; CPU G17, circuit closure test |
| final-layer claims bound to committed columns via the outer PCS | **hook obligation** (§5): eq + weighted-prefix binding columns opened at OODS | `requireTerminal` CPU + circuit (M02 rejected); AIR side not built (canon-vk) |
| characteristic bound | conservative use mass `Σ lanes · 2^row` = 2^27.9 (leaf) < p; assumes uses carry ±1 | **canon-vk to confirm on the outer AIR** |

## 5. Lane-major layout and the binding columns

The GKR point convention: instance `g` with `n_g = r_g + l_g` variables reads the last `n_g` coordinates of the batch
point `z`, most significant first. With index = lane · 2^r + row, the row bits are the low `r` bits, i.e. the last
`r` coordinates `z[L−r..L]`, **independent of the lane count**. So every lane group of a component (same `r`) shares
the row point, and one **eq column** `E(x) = eq(z_row, x)` per component serves all its groups. The lane point of
group `g` is `z[L−n_g .. L−r]`; its lane weights `w_g(lane) = eq(z_lane,g, lane)` are verifier-computed constants.

The **weighted prefix column** `Pre` (one per component) accumulates, row by row,
`Pre(x+1) − Pre(x) = E(x) · Σ_g ρ_g Σ_lane w_g(lane) · (n_g[lane, x] + γ · d_g[lane, x])`, where `n_g`, `d_g` are the
LogUp numerator/denominator expressions of the main row (degree 1 in main for this AIR), and `ρ_g`, `γ` are drawn after
the GKR section. The final value must equal `Σ_g ρ_g (claim_n,g + γ claim_d,g)`. Both columns are OM31 (16 base
columns). This is the native "late binding" construction (`gkr_late_binding`, `binding_theorem_required`): it needs
the same review as the native one (open item 1).

## 6. Measured (24628607, 2× RTX 5090 pod, one GPU per run)

| | leaf-cpu (node 0) | fold (node 20) |
|---|---:|---:|
| committed cells today (PP + main + OM31 interaction) [M] | 1,940.0 M | 1,715.0 M |
| committed cells with outer GKR (own) [D] | 1,101.1 M (**×0.568**) | 901.3 M (**×0.526**) |
| interaction share today | 60.8 % | 61.8 % |
| GKR fractions | 257.9 M | 246.4 M |
| GPU GKR prover, plain route (tree + traversal, CUDA events) [M] | 182.3 ms (28.0 + 154.3) | 174.9 ms (26.7 + 148.2) |
| GPU GKR prover, fused fold+next-sum route, byte-identical [M] | **148.2 ms** | **143.2 ms** |
| device bytes [M] | 26.9 GB | 25.8 GB |
| in-circuit verifier gates [M, valid circuit on the GPU proof] | G 195,200; qm31 223,203; m31→u32 20,360; triple-XOR 19,520; eq 1,581 | G 193,600; qm31 219,570; m31→u32 20,168; triple-XOR 19,360 |
| in-circuit verifier cells per verified child [D] | 40.9 M (2.1 % of a leaf; kill line 25 %) | 40.5 M |
| section bytes [M] | 69,812 | 69,300 |
| fresh receiver (transcript + strict draws + shape + terminal vs recomputed inputs) [M] | accepted, 3.3 ms verify + 53 s terminal MLE | accepted |

Tree (33 nodes, 32 child verifications) [D]: 53.39 G → **30.0–30.3 G committed cells (×0.56–0.57)** including
the in-circuit verifier and the narrower children (176 fewer columns per opened child). GPU [D]: GKR 4.8 GPU-s (fold-sum route; 5.9 plain)
added vs 11.2 GPU-s of committed-cell kernel work removed at the M4.0 all-in rate 0.235 ns per LDE cell (b2) —
net ≈ −6.4 GPU-s of today's 25.1 recursion kernel GPU-s. Not measured: an end-to-end recursion run (needs the hook).

## 7. Open items

1. Review of the late-binding columns (§5) against `binding_theorem_required` — same reviewer as native.
2. canon-vk: confirm use multiplicities are ±1 in the outer AIR (characteristic bound, §4).
3. Hook (interfaces file): outer AIR drops the classic interaction of the four components and gains eq + prefix
   columns; the outer prover runs the GKR after MAIN commit; the outer verifier/circuit call `verify` +
   `requireTerminal` + closure; parents verify the child's section with `circuit.verify`.
4. GPU memory: the unfused traversal materializes all 258 M input fractions (26.9 GB). Production should project
   tuples → fractions inside the first tree/sum kernels (as the native GKR stage does from MAIN), cutting ~9 GB.
5. Proof size: the section sends 4 coefficients per round; deriving c0 from the claim would save 25 % of round bytes
   (a kernel and format change, version 2).
