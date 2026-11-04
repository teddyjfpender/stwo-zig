# Native LogUp-GKR v1: `rv64-m5-native-gkr/v1` (stream native-gkr, M5)

*2026-11-04, branch `codex/rv64-m5-native-gkr`. The soundness/binding section of the native GKR protocol that the
profiles note (`rv64-m7-profiles.md`) should register. It extends §4 of that note (outer GKR) to native proofs; the
profiles stream owns that file, so the argument lives here. Labels: **[M]** measured (receipts in
`vectors/reports/rv64-m5-20261104/native-gkr/`), **[D]** arithmetic on measured numbers, **[E]** model.*

**Status: OFF BY DEFAULT, reference level.** What exists: the census (§2), the v1 roster, section transcript, CPU
reference prover and verifier, wire codec, binding-column reference, and the NG tamper corpus at the section level
(`services/native_gkr/`, step `test-riscv64-native-gkr`). What does not exist yet: the native AIR change (binding
constraints that read global fractions), the GPU fused projection in lane-major order, the receiver and chain wiring,
and the leaf hook. No production prover, receiver or leaf selects v1. §8 lists exactly what is left.

## 1. What changes, in one paragraph

M4 native proofs (`RV64-SERVICES-CPU-GKR-TRUTH-CLASSIC-OM31-V3`) run a stage-one **local** LogUp-GKR per CPU proof
and commit, per component, one eq + prefix binding pair (16 M31 columns). They still commit **classic** LogUp columns
for the three global relations (RAM, KIO, Wire), and truth proofs are classic for everything. v1 runs **one batched
LogUp-GKR per native proof in stage two** (after `chi` fixes the shared RAM/KIO/Wire challenges) that carries every
fraction of the proof: local and global, CPU and truth. Each component keeps exactly one binding pair; the global
groups of a component share it, so global relations stop costing any committed column. The proof's global claims
become GKR roots that the execution receiver closes across proofs exactly as it closes today's classic claimed sums.

## 2. Census [M] and prediction [D] (full tables: `native-gkr/CENSUS.md`)

| | 24628607 | 26235156 |
|---|---:|---:|
| native INTER today [M] (equals measured tree=2 words for every proof) | 1,854.1 M | 1,350.1 M |
| of which truth proofs (all classic) | 838.5 M | 701.5 M |
| of which CPU global RAM/KIO/Wire (classic) | 256.5 M | 179.4 M |
| of which local-GKR binding pairs | 759.1 M | 469.1 M |
| INTER bits/gas own height / LDE b2 [M] | 7,796 / 15,592 | 7,688 / 15,377 |
| **v1 INTER [D]** | **903.4 M (x0.487)** | **611.7 M (x0.453)** |
| v1 INTER bits/gas own / LDE [D] | 3,798 / 7,597 | 3,484 / 6,967 |
| MAIN + INTER [M] -> v1 [D] | 4,557 -> 3,606 M (x0.791) | 3,174 -> 2,436 M (x0.767) |
| ZisK INTER (`committed-work-comparison-v1.json`) | 28.3k LDE bits/gas | |

The 73k figure that motivated this stream is the pre-local-GKR q70 protocol of 2026-11-01. Today's native
interaction is already 1.8x below ZisK per gas; v1 makes it 3.7x below.

## 3. The protocol

### 3.1 Roster (`roster.zig`)
- Components in receiver order: CPU roles, bridges, bulk, sponge, dword (exactly `cpu_components.Plan` order), and the
  truth parts (`keccak`, `chi`, `xor5`; one v3 component per v3 truth).
- Per component the fractions are split by relation kind into groups `local, ram, kio, wire` (Kind order); a group
  exists iff its term count is nonzero; `lane_log = ceil(log2 terms)`; padded lanes carry exactly `(n, d) = (0, 1)`.
- The roster, the term counts and the row logs are functions of receiver-derived geometry: sumcheck lengths, mask
  counts and root counts are class constants, never proof values (profiles finding 4.2(4)).
- Strict canonical order `(component, kind)`; any reordering or relabelling is refused (`NativeGkrRosterOrder/Shape`).
- Bounds: 64 instances (CUDA `batch_max_oracles`; must rise to 128 for production, §8), 28 variables, lane log 10.

### 3.2 Layout
Lane-major, `index = lane * 2^row_log + row` (outer-gkr convention). With the GKR point convention (instance `g` reads
the last `n_g` coordinates of the batch point, MSB first), the row bits of every group of a component are the last
`row_log` coordinates, whatever its lane count. **Lemma (shared row point):** all groups of a component have the same
`z_row`. This is what lets one eq column serve the local and the global groups. M4's local GKR is row-major; v1 changes
the projection order (GPU fused projection kernel, §8) but not the traversal kernels.

### 3.3 Transcript (`section.zig`)
Continuing the native proof's raw-Blake OM31 channel at the point where M4 draws its classic interaction elements
(after MAIN, after the stage-two shared draw from `chi`):
1. `mixU32s(identity[8])`, identity = SHA-256(`stwo/rv64/native-gkr/om31-strict-draw/lane-major/v1`);
2. `mixU32s([MAGIC, VERSION, ordinal])`, then statement, FIXED root, MAIN root and the 32-byte shared seed `chi`;
3. `mixU32s(roster.header)` (every component's origin, row log and four term counts; every instance's
   `(component, kind, lane_log)`), then `mixFelts([salt])`;
4. the batched LogUp-GKR of the shared engine verifier kernel (roots mixed at layer 0 before any layer challenge);
5. `gamma`, then `rho_g` for every instance (late binding), then the INTER commitment (binding pairs only).
All draws are **strict** (outer-gkr §3: a draw with any raw word `>= 2p` rejects the section; the prover re-salts).

### 3.4 Closure
- **Local:** the projective sum of the local roots is zero (`n/d` with every root `d != 0`; `NativeGkrLocalUnclosed`,
  `NativeGkrRootPole`).
- **Global:** for each relation `r` in {ram, kio, wire}, `c_r = sum over the proof's r-groups of n_root/d_root`
  (every `d_root != 0`). `c_r` replaces M4's classic claimed sum of relation `r` for this proof. The execution receiver
  closes `sum_k c_{k,r} + public_r = 0` per relation, unchanged, and keeps the characteristic bound
  (`GlobalRamCharacteristicBound`, `CombinedLookupMassExceeded`): v1 does not change any multiplicity.

### 3.5 Binding (terminal claims -> committed MAIN)
Per component with row log `r`: `E(x) = eq(z_row, x)`, and the weighted prefix
`Pre(x+1) - Pre(x) = E(x) * sum_g rho_g sum_lane w_g(lane) (n_g[lane, x] + gamma d_g[lane, x])`, `Pre(0) = 0`,
boundary `Pre(2^r) = sum_g rho_g (claim_n,g + gamma claim_d,g)`, where `w_g(lane) = eq(z_lane,g, lane)` are verifier
constants, `n_g, d_g` are the relation's numerator/denominator expressions evaluated on the MAIN row (the same emitters
as today: `fractions.zig`, `global_cpu.queriesFor`, the truth equations), padded lanes contribute the constant
`gamma * w_g(lane)`, and the eq recurrence is today's (`binding.zig` constraints 1-2). This is the M4 native
`gkr_late_binding` construction with several groups per component, i.e. outer-gkr `binding.zig` on the native roster.

## 4. Soundness argument

**Setting.** Field OM31 (|F| = p^8 ≈ 2^248), strict draws (each admitted challenge uniform on F, outer-gkr §3).
Per native proof: `i` instances (≤ 64), `L` layers (≤ 28), round degree 3, tuple arity `a` (≤ 58 for RAM, ≤ 50 KIO),
largest instance `2^L` facts. Union over `P` native proofs per block (P = 17 on 24628607; caps P = 1,024).

| term | weight per proof | caps union (P = 1,024, i = 64, L = 28) |
|---|---|---:|
| sumcheck rounds `i·3·L(L+1)/2` | 2^17.4 | 2^27.4 |
| instance mix `(2i+2)·L` | 2^11.8 | 2^21.8 |
| layer binding `2·i·L` | 2^11.8 | 2^21.8 |
| binding columns (rho/gamma Schwartz-Zippel, `deg ≤ 2` in `(rho, gamma)` per component) | 2^7 | 2^17 |
| tuple compression `i·a·2^L` (not GKR-specific; classic LogUp has it) | 2^39.9 | 2^49.9 |
| pole events `2·i·2^L` | 2^35 | 2^45 |
| **total** | | **≈ 2^50.0** |

With μ = p^-8 ≈ 2^-248 per admitted challenge (or 3^8/2^256 = 2^-243.3 under the registry's raw-modulo model) the
union error is ≤ 2^-193 (2^-198 strict). GKR-specific terms add under 0.001 bit to a union dominated by the tuple term,
which M4's classic global LogUp already carries. **v1 is not a field-size risk.** The obligations are binding and
statement placement:

1. **Claims before consumers.** The roots are mixed at layer 0 before the first layer challenge; `gamma, rho` are drawn
   after the whole section; the INTER commitment follows them. An adversary fixes every terminal claim before seeing
   `rho, gamma`.
2. **Binding theorem (per component).** Suppose the committed MAIN rows define fractions `n_g, d_g` and the prover's
   terminal claims are `(N_g, D_g)`. Summing the prefix recurrence over the 2^r rows (cyclic, `Pre(0) = 0`) and the eq
   identity `sum_x eq(z_row, x) f(x, lane) = f~(z_row, lane)` give
   `sum_g rho_g (MLE(n_g)(z_g) + gamma MLE(d_g)(z_g)) = sum_g rho_g (N_g + gamma D_g)`. If any `(N_g, D_g)` differs from
   the MLE of the committed fractions, the left minus right is a nonzero polynomial of degree ≤ 2 in `(rho, gamma)`
   fixed before they are drawn: it vanishes with probability ≤ 2/|F|. The eq column itself is pinned by its recurrence
   and its two endpoint constraints (unchanged from M4). Cross-group cancellation inside one component is exactly what
   `rho` separates (test NG06); cross-component cancellation is impossible because every component has its own
   boundary constraint.
3. **The GKR then reduces the roots to those terminal claims** (standard batched LogUp-GKR, the shared verifier
   kernel). So each root is the true fraction sum of its group, except with the sumcheck error above.
4. **Local closure** = M4's local closure (now over v1's local groups). **Global claims** are, with the same
   probability, the true per-proof sums of the global fractions: exactly what M4's classic claimed sum asserts. The
   cross-proof closure, the characteristic bound and the INIT/TERM anchors are therefore unchanged arguments.
5. **Padding.** Padded lanes are not prover inputs: the AIR adds the constant `gamma * sum_{padded} w_g(lane)`. A
   prover that runs the GKR on different padded leaves fails the binding (test NG05).
6. **Statement placement.** The scope (statement, FIXED, MAIN, ordinal, `chi`) and the full roster header are mixed
   before any GKR draw. A section from another proof, ordinal, block, roster or relation labelling is refused
   (tests NG03 and the transcript test). Constant shape: rounds `= depth`, 4 coefficients with nonzero leading
   coefficient, masks `= variables`, 2 roots per instance (`checkShape`, NG01/NG02).
7. **Chain consequence (canon-native).** M4 binds the stage-one local GKR receipt `lambda_k` into `rho_k` (review-2 F13).
   In v1 there is no stage-one GKR: `rho_k` = stage-one commitments only (MAIN, FIXED), and the section is part of the
   stage-two proof transcript that the native verifier (and the leaf) replays. That needs a canon-native `/v2` chain
   tag (`rho` without `lambda`), requested in M5-INTERFACES.

**Completeness.** Pr[a section hits a rejected draw] ≤ draws · 8 · 2^-31; draws ≈ L(L+1)/2 + 2L + i + 1 ≈ 520 for a
CPU proof: 2^-19. The prover re-salts (`proveCpu`, at most 64 salts).

## 5. Leaf side

The recursion leaf verifies one native proof. Under v1 it verifies the native GKR section in-circuit with outer-gkr's
gadget (`outer_gkr/circuit.zig`: strict in-circuit draws, constant-shape sumchecks, `requireClosure`,
`requireTerminal`), with the native roster as class constants, and the binding boundary per component through the
native OODS values of the binding columns. The leaf already verifies M4's local GKR in-circuit, so for CPU proofs the
change is more instances (global groups) on the same layer count; truth leaves gain a GKR they do not have today.

**Leaf-cell delta model [E]** (`native-gkr/<block>-leaf-model.json`): opened native columns fall by 37,176 over the 17
proofs of 24628607 (2,008 -> 608 INTER columns on CPU-0; 5,128 -> 16 on each secp-add truth). At q = 108, 80 G rows per
compression and today's leaf row widths: **-3.41 G leaf cells on 24628607 (-6.4 % of the 53.4 G tree) and -1.81 G on
26235156**; added in-circuit GKR work is +0.16 G / +0.11 G inside those nets. Hook request to canon-vk in
M5-INTERFACES (section native-gkr).

## 6. Prover cost [D]
- Committed native cells: -951 M (24628607) / -738 M (26235156) INTER own-height cells; at M4.0's native all-in rate
  (≤ 0.341 ns per LDE cell, b2) that is ≤ 0.65 / 0.50 GPU-s of commit + quotient work removed per request.
- GKR work: CPU proofs +10-30 % facts (85-160 M per proof vs 102-152 M measured); truth proofs gain 2^24-2^27 facts
  (Keccak log 18: lane log 9). At the measured fold-sum route rate (outer-gkr: 148 ms for 258 M fractions) about
  +0.4 GPU-s per 24628607 request. Net prover effect is small and positive; the large effects are the leaf (§5) and the
  stage-one critical path (the local GKR leaves stage one).
- Composition: the per-component binding constraints read more fraction expressions (global tuples), the classic
  global constraints disappear; constraint count per component falls (one prefix residual instead of
  `ceil(q/2) + 2` per relation).

## 7. v2 lever (not built)
After v1 the remaining INTER is binding: 903 M on 24628607, of which the `cpu` component (16 columns at its row log, 7 CPU proofs) is 436 M. Sharing
one eq column per row log across components (components of one row log are on one trace domain) and combining their
prefixes with `rho` would take INTER to about 8 columns per component plus 8 per distinct row log (≈ 0.5 G). It needs
cross-component constraints in the native AIR framework.

## 8. Implementation status and what is left
Done (this branch, tests `test-riscv64-native-gkr`): roster + header + cost (`roster.zig`); transcript, strict draws
(outer-gkr `StrictChannel`), CPU reference prover with re-salt, verifier with local closure and exposed global claims,
binding reference (`bindingColumns`, `expectedBoundary`, `requireBinding`), strict codec (`section.zig`); NG corpus
(`tests.zig`): NG01 every single word of an encoded section, NG02 codec, NG03 relabelled relation, NG04 unclosed local,
NG05 padded-lane forgery vs MAIN, NG06 rho separation; census tool `rv64-native-gkr-census`.

Left, in order:
1. Native AIR: per-component binding residual over all groups (`role.zig`/truth roles), drop `global_cpu.emitFor` and
   the truth classic columns; AOT composition catalogue regeneration.
2. Prover: stage-two section (projection of global + local fractions in lane-major order straight from MAIN on the
   GPU, fused into the first traversal layers, reusing the outer-gkr fold-sum route), CUDA `batch_max_oracles` 64 -> 128.
3. Receiver: global claims from roots; canon-native chain `/v2`; profiles registry entry and identity bump.
4. Leaf hook (canon-vk) with outer-gkr's gadget.
5. Fresh-receiver acceptance and the NG corpus at tier R on real proofs of the two dev blocks.
