# M9 canon-leaf: canonical leaf classes (the shape catalog)

Stream `m9-canon-leaf`, branch `codex/rv64-m9-canon-leaf` (cut from `codex/rv64-m7-integrate` @ 95e3d7e15), 2026-11-07.
This is M9/M10 preparation. It runs in parallel with the GPU-native landing and touches nothing that stream owns.
Labels: **[M]** measured, **[D]** arithmetic on measured data, **[E]** estimate or model.

Artifacts:
- **Catalog builder:** `scripts/rv64_m9_canon_leaf_catalog.py`. It reuses `rv64_m5_canon_rungs.py` and `rv64_m5_canon_native_ref.py`.
- **Prototype:** `src/integrations/riscv_cpu/rv64_recursion/canon_leaf.zig`, with the generated table `canon_leaf_catalog.zig` and the tests in `canon_leaf_test.zig`. The flag is `STWO_RV64_M9_CANON_LEAF` (default off). Nothing reads the flag yet.
- **Test suite:** `zig build test-riscv64-m9-canon-leaf -Doptimize=ReleaseSafe`, 6 tests, PASS [M].
- **Receipts:** `vectors/reports/rv64-m9-prep/canon-leaf/`:
  - `segment-shapes-15.json`: the 579 leaf declarations of the 15 accepted M3 basket bundles;
  - `catalog-r4.json`: the R = 1..8 sweep and leave-one-block-out (LOBO) coverage;
  - `catalog-r8.json`.

## 0. Result in one table

| | today (exact) | frozen canon-native v1 (R=4) | **this catalog, R=4** | this catalog, R=8 |
|---|---:|---:|---:|---:|
| leaf classes needed for the 15 blocks [D] | **389** (336 CPU + 53 truth) | 46 | **72 in catalog / 53 used** | 101 / 82 |
| basket leaves without a class (strict roster) [D] | 0 (every leaf is its own class) | **3 / 579** | **0 / 579** | 0 / 579 |
| leave-one-block-out misses (an unseen block) [D] | n/a | n/a | **1 / 579** | 1 / 579 |
| new leaf classes per block in a different-blocks service [D] | 60–75 % of leaves, every block | – | 0 if the catalog is installed | 0 |
| native CPU cells tax, basket [D] | 0 | +35.9 % (canon-native) | +32.1 % | +18.2 % |
| native CPU cells tax, 24628607 / 26235156 / 26235168 [D] | 0 | – | +15.6 / +16.5 / +48.1 % | +9.6 / +9.0 / +29.5 % |
| truth rows tax [D] | 0 | – | +2.0 % | +0.01 % |
| host packed class store [D] | per block | – | ≈1.7 GB | ≈2.4 GB |

The Zig tests check the R=4 column against the Python receipt. They map every one of the 579 basket leaves onto the
catalog: 53 classes used, 389 exact classes today. They show that the frozen v1 table misses exactly 3 leaves (blocks
24628595, 25229951 and 26235168). They also check that one class gives the same key in more than 250 cross-block
recurrences.

## 1. What a leaf class is today, and why it changes every block

The statement is **already** witness. The M5 binding work made every per-request scalar a guessed public frame word,
hashed into the leaf output and checked by the receiver or fold. The canon-native review spelled this out as
"Native input is witness assignment only … none becomes a circuit constant".

| leaf | per-request values: guessed frame words | circuit constants |
|---|---|---|
| CPU leaf (`om31_native/cpu_leaf.zig` 69–190) | ordinal, statement, manifest, claims, steps, epoch, initial/final pc, 32 registers, register clocks, sponge first id, and per slot rows/calls/first id with an in-circuit `nonempty` flag | `setup` (geometry logs, tails, bridges, layout flags), the slot roster and local-GKR instance roster derived from it, the native FIXED root (`requireDigest`, :87), the binding (profile, fixed identity, root; `frame.zig mixWorkerBegin` :111), the PCS config, `wide_clock(cpu_log)` |
| native-GKR CPU leaf (`native_gkr_cpu_leaf.zig` 32–60) | the same, plus the compact metadata and inputs | the compact header (domain, `class_key = structure(f, r)`, program, config identity, fixed identity, root; :46). It **already requires a strict rung** (`NativeChainNotStrict`, :36–37) |
| truth leaf (`truth_leaf.zig` 85–99) | ordinal, first id, calls, statement, manifest, claim | family, log, profile word, FIXED root `truth.key().root` (:97) |

So the leaf topology, and with it the PP, FIXED root and outer authority identity, is a function of the declaration
plus the native FIXED binding, the config and the outer profile and shape. That is the rootverify `leafKey` premise
(`rv64-m5-rootverify.md` §3.1). The producer's class key is `SHA-256(authority identity ‖ prepared identity)`
(`outer_job_prestage.zig` 587–593). It inherits that dependence.

The declaration is fitted exactly to each segment's counts:
- 336 of the 347 CPU leaves of the basket have distinct declarations [D].
- The E8 topology census measured every leaf as its own gate graph: 10/10 on 26235156 and 16/16 on 24628607 [M,
  `rv64-m5-canon-vk.md` README E8].
- Interned constants (the FIXED root words) shift var ids. Two leaves of different classes therefore differ in their
  constant tables even at an equal size. This is the "six classes of identical size have different keys" observation
  (`rv64-m9-io-streaming.md` §1.4).

**Different-blocks service [D]** (`catalog-r4.json` `exact.service`). One service sees each basket block once, in
bench15 order, with an unbounded class store. A block still brings new leaf classes for 60–75 % of its leaves:
- 24628607: 12 new of 17;
- 26235168: 33 of 49;
- 25229955: 34 of 49;
- 26235159: 50 of 75, after 14 other blocks.

So outside the same-block benchmark the class store almost never hits. The M8 rule that a class miss is an error
(`GpuNativeClassNotWarmed`, `rv64-m8-gpu-native.md` l.32/83) cannot hold for exact leaves.

## 2. The canonical leaf class: what moves where

A canonical leaf class is `c = (kind, native family f, catalog rung r)`, plus the Keccak profile word for truths.
- f is canon-native's family: `cpu_first`, `cpu_middle`, `cpu_last` or `cpu_single`, `truth_<family>`, `mb`.
- r indexes the family's catalog list.

The segment's declaration is replaced by the rung's component vector under the strict roster (`rv64-m6-native/v2`). The
leaf circuit, called R_leaf[c], is then a function of c and of nothing per segment.

| field | today | canonical | checked by |
|---|---|---|---|
| component logs (rows capacity) | circuit constant, exact per segment | class constant = the rung's logs | strict fit (`plan.zig canonFitStrict`); the AIR's `nonempty` and count columns |
| actual row and call counts per slot | guessed frame words (already) | unchanged: witness | leaf `flag()` (nonempty), boundary/global closure at the receiver |
| component presence (slot roster, local-GKR instances) | circuit constant: present iff count > 0 | **class constant**. Use is a witness flag: an absent use is an all-padding instance with count 0 | v2 one-sided presence (`presenceAdmitted`), the AIR `nonempty` prefix (`rv64-m6-native-v2.md` §2) |
| `cpu_log` | circuit constant | class constant. Rungs are keyed by `cpu_log`; `cpu_last` gets a ladder 16..22; a final segment below 2^16 rows is padded to 2^16 at capture | strict fit (equality) |
| layout flags (`omit_empty_division`, …) | circuit constant | class constant (`CPU_LAYOUT_FLAGS`: v2 never omits division) | structure v2 digest |
| native FIXED root / identity | circuit constant | **Option A (proposed for M9):** class constant. Measured block-independent: the 8 (f, r) classes shared by 607 and 156 have identical vkhashes (`rv64-m6-native-v2.md` §5, `class-independence.json`) [M]. **Option B (M10):** guessed, plus T_nat membership at the constant index `index(c)` (`vk_table.verifyMembership`) | A: `requireDigest` against the constant. B: Merkle path to T_nat (canon-vk G01/G03) |
| truth log | circuit constant | the rung log (`plan.zig canonicalTruths`) | truth AIR padding |
| truth calls, first id | guessed (already) | unchanged | receiver |
| statement scalars (ordinal … claims, chi) | guessed (already) | unchanged | receiver / fold chain |
| outer padding target | f(leaf graph) | f(c) under `set-v2` or `uniform-v1`; exact also becomes f(c), because the graph is f(c) | the outer authority |

Nothing per-segment remains a constant under Option A. Option B goes further: it makes R_leaf independent of the
program image, so a guest upgrade does not change the leaf VKs. It is not needed for cross-block recurrence, so it is
deferred to fold v3 / M10.

The class key (`canon_leaf.zig classKey`, host-only: an ArtifactStore / `ClassCache` key, never in a proof):

```
native = canon-native ClassKey(f, r, native_profile, image, rung_table_id(catalog))      (canon_native.zig ClassKey)
key    = H("rv64-m9-canon-leaf-class/v1", [kind, f, aux, r, index] || native || pcs_config || outer_domain || outer_shape)
```

- H is canon-native's word rule.
- `rung_table_id` binds every class of the catalog, over structure v2 (`rungTableId`). A key from another catalog cannot
  collide; the test checks that it differs from the v1 table's.
- `index` is the class position in canonical order: CPU families ascending, rungs ascending, then truths by (family,
  aux). It is the circuit-constant table index of R_leaf[c] for T_nat / T_rec membership.
- 72 classes fit a depth-7 table; T_nat DEPTH 6 (64 slots) is too small at R=4 and must grow to 7.

## 3. The catalog for the 15-block basket

### 3.1 Construction (`rv64_m9_canon_leaf_catalog.py`)

- **CPU.** Proofs are grouped by (family, cpu_log), because cpu_log is fixed by capture and strict fit requires it to
  be equal. Each group gets canon-native's contiguous DP on strict-roster cells, giving R rungs, the group max vectors.
  Then the envelopes:
  - per (family, cpu_log), one roster-complete envelope: every component at max(family max + 1, all-family max),
    capped at 23 (the largest admitted log in the basket);
  - an unseen component gets 12 [E];
  - `boundary_log` stays 5 and zbb stays absent.
- **cpu_last.** It also gets envelopes at every cpu_log 16..22.
- **Truth.** Per (family, profile word): DP rungs on rows, plus max + 1.
- **Order.** Rungs are ordered by (cpu_log, cells), so "first fitting rung" is the cheapest admissible class. This is
  the same rule as production `canonicalCpuForSegment`, which takes the table as `anytype`, so the generated table plugs
  in unchanged.

### 3.2 Numbers [D]

| R | catalog classes | used | CPU cells tax | CPU main tax (GKR route) | truth rows tax | presence-preserving classes | LOBO misses |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 35 | 16 | +134 % | +113 % | +57 % | 165 | 1 |
| 2 | 50 | 31 | +53.0 % | +46.9 % | +15.1 % | 186 | 1 |
| 3 | 63 | 44 | +38.3 % | +34.8 % | +5.4 % | 193 | 1 |
| **4** | **72** | **53** | **+32.1 %** | +29.6 % | +2.0 % | 211 | 1 |
| 6 | 88 | 69 | +22.6 % | +21.0 % | +0.2 % | 225 | 1 |
| 8 | 101 | 82 | +18.2 % | +17.3 % | +0.01 % | 240 | 1 |

R=4, by family:
- `cpu_first`: 5 rungs;
- `cpu_middle`: 5;
- `cpu_last`: 18 (cpu_log groups 17/20/21/22 plus the 16..22 ladder);
- truth: 44.

The "presence-preserving classes" column is what the class count would be if presence stayed a circuit constant
(canon-native v1 mode): 211 instead of 53. So presence is the field that must move. Rung padding alone is not enough.

**Frozen canon-native v1 table under the strict roster: 3 misses [D, Zig test].**
- 24628595 `cpu_last`: a terminal_log above every cpu_log-20 rung.
- 25229951 `cpu_first`: jalr, initial and sponge.perm exceed the rungs. 25229951 was not in the 14 blocks v1 was fitted on.
- 26235168 `cpu_last`: cpu_log 17 has no rung.
- The v1 DP pooled cpu_log values within a rung. Under v2-strict this would be `RV64_CANON_STRICT_NOFIT` →
  `NativeChainNotStrict` on 3 of 15 blocks.

### 3.3 Coverage of unseen blocks and the miss path

**LOBO [D].** Build the catalog from 14 blocks and map the 15th. At every R, 578 of 579 leaves fit. The one miss is
26235159 segment 34, a bn254-heavy middle segment: bn254_g1_add 15 against a 14-block max of 13, so the envelope at 14
is short.

**Policy.**
- `STWO_RV64_M9_CANON_LEAF=on` refuses a miss with `CanonLeafNoClass`. This is the M8 contract: a refused request plus
  a warm hint, never a silent slow path.
- `audit` keeps exact classes and logs the canonical class next to them. It is the rollout mode.
- An unseen-block miss rate around 0.2 % of leaves (1/579, the bn254 case) argues for one of two fixes: an explicit
  exact-class fallback, kept as a separately named class, never silently mixed; or an envelope sized from roster MAX_LOG
  instead of the basket max. The second makes the catalog complete by construction, at extra tax only for the outlier.
- Which of the two is a policy decision; E8 on a wider block sample decides.

**Production truth families.** Production runs the D2 coalesced-truth profile, which has one truth per family per
block. Its truth logs are larger than the M3 truths used here, and 9/15 blocks are currently refused at plan time
(bench15). The truth half of the catalog must be regenerated from D2 declarations once the round-3 p-truth-split
lands. The builder takes any `segment-shapes` file. The CPU half is unaffected, because CPU segmentation is the same.

## 4. Soundness argument

Claim: under `on`, the set of statements a receiver accepts is unchanged, and per-proof security bits are unchanged.

1. **Padding is an admitted geometry.** A rung vector is an ordinary native geometry; canon-native §7 and v2 §2 prove
   padded declarations under the unchanged native AIR.
   - Padding rows are the AIR's own padding: the enabler and `nonempty` prefix, with multiplicity 0 in every LogUp sum.
   - The real counts are public guessed words, bound into the leaf output and checked by the receiver against its own
     inventory.
   - A larger capacity adds no accepted execution: the count words, not the capacity, define what is claimed.
2. **Presence relaxation is one-sided.** This is the v2-strict argument (`rv64-m6-native-v2.md` §2 points 1–2, tamper
   suite in `rv64-m6-20261105/native-format/`).
   - An absent component with nonzero calls or rows is still refused (`presenceAdmitted`).
   - A present, all-padding instance has count 0, so its `nonempty` flag is 0 and its LogUp contribution is 0.
3. **The class is receiver-derived, never producer-chosen at the receiver.**
   - The receiver computes c from its own inventory with the same strict fit, and then the leaf authority as R_leaf[c].
   - A proof made for c' ≠ c fails the authority check today. Under fold v3 it fails the T_rec membership at the
     constant index(c) (canon-vk G01).
   - The producer does choose the rung (first fit). Any admissible rung is sound by point 1, so the receiver only needs
     a deterministic rule for its own derivation. The rule: the first fitting rung on its counts, the same function
     `canonicalCpuForSegment` runs with the receiver's counts.
4. **Constants are class functions (Option A).** R_leaf[c]'s constants are the rung vector, the layout flags, the native
   FIXED root/identity of c, the config and the profile.
   - The FIXED root is block-independent per class [M, 2 blocks, 8 shared classes].
   - The catalog builder's install step must still assert it on every class it builds: derive the FIXED of c twice from
     different synthetic declarations and require equality, like `VkLeafClassMismatch`.
   - If it failed, the result is a completeness failure (honest roots reject), not a soundness one. That is the
     rootverify §3.1 argument.
5. **Option B (M10).** A guessed native VK plus Merkle membership in T_nat at a constant index is sound under Blake2s
   collision resistance. Leaf, empty and node tags are distinct, and the index is range-checked by boolean path bits
   (canon-vk §4).
6. **Union bound.** The tree has the same number of leaf and fold proofs, so the union bound is unchanged.
   - Per-proof bits are unchanged: same native and outer profiles. A larger native trace only changes the degree bound
     that FRI tests, which the conjecture covers at any size.
   - Larger native traces raise the leaf's Merkle depth by at most `log` levels per opening. That changes cost, not bits.
7. **Key collisions are host-only.** The class key never enters a transcript, so a collision can only make the cache
   hand out a wrong template.
   - The PP-cache `check` mode (`STWO_RV64_OUTER_PP_CLASS_CACHE=check`) and the authority comparison on a hit are the
     audit.
   - A wrong template yields a different authority, so the result fails closed.

## 5. Verifier and receiver changes

- **Inventory** (`execution.zig Inventory` / `gkr_local/chain.zig`). It already derives (f, r) under v2. It must derive
  them against **this catalog**, not the frozen v1 table:
  - `native_gkr/canonical_rungs.zig cpuRung` and `ethereum/canon_native_rungs.zig` gain a catalog variant selected by
    the flag;
  - `strictRung` equality on the declared vector is unchanged.
- **Leaf authority.** It becomes R_leaf[c], derived once per (catalog, image, profile) and not per request.
  - `derive-vk-tables` can emit every leaf VK from the catalog alone, with no block. That removes rootverify's leaf
    premise and its `VkLeafClassMismatch` derive-time check becomes a build-time check.
  - The leaf table key changes from `leafKey(declaration JSON …)` to `classKey(c, …)`.
- **Root-only receiver.** The table header gains the catalog's `rung_table_id`. A table from another catalog is
  refused, like `VkTableNotDerivedByThisReceiver`.
- **Refusals.** A declaration ≠ its class rung vector is refused (`NativeChainNotStrict`). A class index outside the
  catalog is refused (`CanonLeafNoClass`).
- **Proof bytes change** (circuit change). The D2 golden must be re-frozen under the new format. Producer and receiver
  must share `STWO_RV64_M9_CANON_LEAF`; add it to `FORMAT_ENV_KEYS` in `rv64_m3_pod.py`.

## 6. What it saves, and what it costs [D/E]

**Host class build.** A cold request on 24628607 spends 13.2 CPU-s on plan builds and 2.72 CPU-s on PP packs for 19
classes, leaf and fold mixed (`rv64-m9-io-streaming.md` §1.4) [M]. That is **0.838 CPU-s per class** [D].
- New exact leaf classes per block in a different-blocks service (§1) [D]: 607 12, 26235168 33, 25229955 34,
  26235159 50.
- Removed host class-build work per new block [E]: ≈10.1 / 27.7 / 28.5 / 41.9 CPU-s. This assumes a leaf costs the
  mixed mean; leaves are the bigger circuits, so it is likely an underestimate.
- With the catalog installed, this is 0 on 578/579 leaves.
- Hits still pay the host unpack, 3.70 CPU-s per warm request [M], until L1b keeps the packed classes resident.

**Wall time.**
- The bench15 cold − warm gap on 24628607 is 29.01 − 11.77 = 17.2 s [M]. It is the upper bound on what any class or
  setup caching can recover for a new block.
- Leaf host prep is 2.0–3.0 s per leaf class [M, canon-vk §7]. It is the first-leaf critical path.
- Estimate for a new block on a warm service: canonical leaves recover **3–17 s per block on 24628607** [E].
- Canonical native classes also make the native FIXED setup cache hit across blocks [M block-independence]. That share
  is inside the same gap.
- E8 (different-blocks warm, `rv64-m9-io-streaming.md` §6) is the measurement that fixes this number. It is a GPU
  request-level run, so it is not done here (stream guardrail).

**It also unblocks the following.**
- M8 `ClassCache` consistency: `GpuNativeClassNotWarmed` becomes true for leaves, not an error on most requests.
- L1b residency: 53 used classes × 24 MB packed ≈ 1.3 GB packed, ≈0.6 GB per GPU [D from 0.455 GB per 19].
- Install-time preinstall: 72 × 0.838 ≈ 60 CPU-s of host build [D], plus native setup per class.

**Cost: padding tax [D] and its time [E].**
- Native CPU cells tax at R=4:
  - +15.6 % on 607 and +16.5 % on 156;
  - basket +32 %, worst block +48 % (26235168).
- At R=8 the same figures are +9.6 %, +9.0 %, +18 % and +29.5 %.
- At the M8 warm 607 native window of 3.82 s [M], R=4 adds ≈ +0.6 s and R=8 ≈ +0.37 s [E, time ∝ cells].
- The recursion side is worse than cells suggest. Strict presence adds committed columns, and leaf verifier work grows
  with the column count. The M6 v2-strict measurement on 607 (one-shot, pod load 27–43, single runs) went from native
  8.16 to 9.84 s and recursion 23.9 to 29.6 s [M, noisy].
  - That makes ≈ +1–1.5 s an upper-bound guess for the warm 607 recursion [E].
- **Net.** On the same-block warm benchmark, canonical leaves are a loss: +1–2 s on 607 [E]. On the production shape,
  where every block is new, they win whenever the E8 miss penalty is above that. The one-shot/cold evidence (17 s gap)
  says it is, but E8 must confirm.
- **Recommendation.** **R=8** (101 classes, depth-7 tables, ≈2.4 GB host store). Classes cost install time and host
  memory, not request time, so the M5 kill rule's R ≤ 4 bias no longer applies. Revisit R once v2-gkr removes the
  classic interaction columns, which cuts the padding cost of INTER roughly in half (`rv64-m6-native-v2.md` §5).

## 7. Integration steps after GPU-native lands

1. **Rebase.** Rebase `codex/rv64-m9-canon-leaf` on the post-GPU-native integrate. Regenerate the catalog from the D2
   declarations once round-3 p-truth-split proves all 15 blocks:
   `rv64_m9_canon_leaf_catalog.py --shapes <D2 shapes> --rungs 8 --zig …`. Update the expected counts in
   `canon_leaf_test.zig` to the receipt.
2. **Native side, producer** (`gkr_main.zig` ~746, `early_segments`/`early_cpu0` `canonical_rungs`). Under
   `STWO_RV64_M9_CANON_LEAF=on`, force the strict roster with `table = canon_leaf.Catalog` in
   `Plan.canonicalCpusMode` / `canonicalTruths`. Both are `anytype` tables, so there is no code change in plan.zig.
   Capture pads a final segment below 2^16 rows to 2^16.
3. **Native side, receiver and leaf.** Add the catalog variant of `canonical_rungs.zig cpuRung` / `cpuStructure` used
   by `native_gkr_cpu_leaf.zig` :35–38 and by `Inventory`. The version identity (`versionIdentityV2`) must bind
   `rung_table_id`, so v1-table and catalog proofs never cross-verify.
4. **Outer producer key.** Under the flag, `outer_job_prestage.zig` 587–593 sets `class_key = canon_leaf.classKey(…)`
   for leaves. Folds keep `om31_outer.classKey`. Keep the authority-equality assertion on every hit (`check` mode in
   CI).
5. **Install / warm.** For every catalog class, build the trace-only leaf graph from a synthetic declaration equal to
   the rung vector. Fill the M8 `ClassCache` (FIXED, plans, tapes, PP), assert FIXED block-independence (§4.4), then
   seal. Requests never build leaf classes.
6. **Receiver.**
   - Leaf VK table entries keyed by `classKey` and emitted by `derive-vk-tables` from the catalog.
   - The header binds `rung_table_id`.
   - `CanonLeafNoClass` / `NativeChainNotStrict` refusals.
   - Add `STWO_RV64_M9_CANON_LEAF` to `FORMAT_ENV_KEYS`.
7. **Gates.**
   - Re-freeze the D2 golden under the new format; on the dev blocks, 2/2 fresh receivers.
   - Negative corpus plus new cases: rung relabel, wrong cpu_log class, all-padding instance with calls,
     cross-catalog table. Reuse `rv64_m6_native_v2_tamper.py`.
   - E8 different-blocks warm on the basket, then choose R from the measured miss penalty against the tax.
8. **Later (M10).** Option B: guessed native VK plus T_nat membership in the leaf, which makes R_leaf image-independent.
   Fold v3 then carries index(c) as the leaf constant.

## 8. Not done here (precise)

- **No GPU run.** That includes no E8 and no measured tax on the M8 binaries. Every time figure in §6 is [E] from the
  measurements cited there.
- **No producer or receiver wiring.** The flag is parsed and nothing reads it.
- **Strict fit is computed from declarations.** The pair counts are bounded by the declaration's own capacity, which is
  conservative (it may pick a larger rung than production). The production path passes real counts through the same
  table.
- **The truth half is from M3 truths**, not the D2 coalesced truths.
- **The envelope cap (23) and the unseen-component log (12) are [E] choices.** They are not roster MAX_LOG; making the
  envelope roster-complete is the open completeness lever (§3.3).
