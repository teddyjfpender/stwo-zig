# Native protocol `rv64-m6-native/v2` (stream native-format, M6)

*2026-11-05, branch `codex/rv64-m6-native-format`. Interface: `/workspace/m3/M6-INTERFACES.md` section native-format
(NF0-NF5). Bases: canon-native `rv64-m5-native-chi-chain/v1` (`rv64-m5-canon-native.md`, 3ab539067) and native-gkr
`rv64-m5-native-gkr/v1` (`rv64-native-gkr.md`, 2fc4b878b), both merged here at cac9012e3. Labels: [M] measured,
[D] arithmetic on measured numbers, [E] model.*

## 1. Profiles and selection

| profile | version identity `H("rv64-m6-native-chi-chain/v2", [2, 10, 3, R=4, 32, 1, mode])` | status |
|---|---|---|
| `v2-strict` (mode 0) | strict roster + canonical chi chain; native AIR unchanged (stage-one local GKR, classic global LogUp) | implemented, selectable |
| `v2-gkr` (mode 1) | strict roster + chain + one stage-two batched native LogUp-GKR per proof, no classic LogUp columns | specified (NF4); selector refused (`NativeVersionNotImplemented`) |

Selector: `STWO_RV64_NATIVE_VERSION` = `m6-native-v2-strict` for producer AND receiver
(`word16_execution/native_policy.zig`). Unset / `v1-flat` = the M5 default bytes; `m5-chi-chain-v1` stays selectable;
any other value is a clean error (exit 1). Profiles registry names: `m6_native_v2_b2_q108_p20_fold4` (= v2-strict) and
`m6_native_v2_gkr_b2_q108_p20_fold4` (= v2-gkr); the component string is `rv64-m6-native-chi-chain/v2`, which is also
the version tag above.

## 2. The strict roster (closes canon-native review A1)

**Rule.** Every native segment k has a class (f_k, r_k). Its declared component vector (the 41 CPU logs of
`canon_native.zig CPU_COMPONENTS`, 0 = absent; a truth's `(log, aux)`) **equals** the rung vector of (f_k, r_k) in
`ethereum/canon_native_rungs.zig`. The producer (`plan.zig canonicalCpusMode(strict)`) writes the rung vector into the
declaration. Rung components that the segment does not use are committed as **all-padding instances** (zero calls or
zero rows). The division component is never omitted under v2 (`omit_empty_division = false`; it is committed at the rung
log). A segment that no rung holds is an error (`NativeChainNotStrict`); there is no UNCLASSED segment under v2.

**Receiver.** `chain.assign` derives `r_k` as the unique rung with vector equality (`Canon.strictRung`) and refuses
anything else, including a set `omit_empty_division`. The receiver plans its own declarations from its own capture with
the same code, so the declaration is receiver-derived. Producer bytes never select the class.

**Admission relaxation (policy-gated).** Under v2 only, "present iff it has rows" becomes "absent implies no rows" for
the bridges (12 families), the bulk kinds, the sponge kinds, the LS-D64 head and tail, and the LS32 tail
(`protocol.zig presenceAdmitted`, `types.zig dwordCounts`, `geometry.zig lsCounts`). The ALU, BINARY and SHIFT tails
already admit empty instances (their claims are prover-computed and close through FUNCTION). Outside v2 the old rule
is unchanged, byte for byte.

**Why the relaxation is sound.**
1. *Presence is a class constant.* Under v2 the receiver fixes the component set from (f, r) alone, so the prover cannot
   choose presence to hide or add a relation. The old rule tied presence to counts because presence was otherwise free.
2. *An empty instance proves nothing extra.* An all-padding instance is the same AIR as a populated one, with the
   receiver-derived public counts set to 0: 0 calls, `first_id` continuing the family span, and claims derived from 0
   calls. Every relation it touches (RAM, KIO, Wire, FUNCTION, range, AND) is closed by the same global and local
   closure as before. A prover that fills the "empty" instance with active rows must balance their lookups against
   receiver-derived claims of 0 calls, exactly as when it pads a populated instance with fake rows. The argument for
   padding rows is the existing one: padding rows have multiplicity 0 under the component's own constraints.
3. *Masses.* Every mass bound uses the instance log (`2^log` rows, padding included), so a present-empty instance is
   already counted at full size by `CombinedRangeMassExceeded`, `CombinedLookupMassExceeded` and the per-component
   `validateGeometry` bounds. Nothing new escapes the characteristic bound.
4. *Chain.* The class vector that the chain hashes is the declaration, so `structure` in the chain is the T_nat structure.

**Structure v2.** `structure_v2(f, r) = H("rv64-m6-native-structure/v2", [f, r, n, (id, log)*n, flags])`. The flags word
packs the geometry layout flags (omit_empty_division, cpu_fused_tail, cpu_u8_pairs, cpu_compact_decode, mul_u8_pairs,
ls_fused_pairs, alu_fused_tail, ls_dword_fused_pairs; bit i in this order). v1 hashed logs only, so two declarations
with equal logs and different layouts (an omitted division of log 5 against a real one of log 5) shared a structure.
Under v2 they cannot.

**vkhash v2 (closes A3).** `vkhash = H(native-vk, [f, r, suite(8), fixed_identity(8), fixed_root(8), profile_identity(8),
structure_v2(8)])` with `suite = Suite.identity()`. The fixed authority is **required**: no fixed set, or a binding
without a named profile, is `NativeChainFixedAuthorityMissing`.

**Policy, not data (closes A4).** `manifest.chainDigestFor(version, ...)`: a chained policy refuses any entry without
chain fields (`NativeChainMissing`); a flat policy never reads them.

**Consequence: block-independent native classes.** The native class set and every FIXED artifact are functions of
(image, profile, f, r). Setup can therefore install all classes once, and the vkhash of a class is the same in every
block's chain. That is what the native VK table needs (fold-v3 / rootverify; NF2). Measured check: the chain logs
`RV64_NATIVE_CHAIN` (ordinal, f, r, vkhash) on both dev blocks, and every (f, r) that occurs in both has an equal
vkhash (receipts, section 5).

**Cost.** The strict-roster cells tax on the 15-block basket is +35.9 % at R = 4, against +25.5 % presence-preserving
(canon-native `rung-tax-cells.json`, [D]). The dev-block deltas are measured in section 5. The strict roster is the
price of a constant native VK; native GKR (v2-gkr) is the lever that pays it back (INTER x0.49 [D]).

## 3. Chain (unchanged encodings)
`m_{k+1} = H(seg, [m_k, k, f, r, vkhash, stmt_k, s_in, s_out, rho_k])`, `chi = H(chi, [stmt, m_kappa])`, IV over the v2
version identity. Under v2-gkr, rho_k is the v1 rho with local absent (no stage-one GKR).

## 4. v2-gkr: what is specified and what is open
NF4 fixes the section: native-gkr v1 plus every open review item resolved:
- identity `.../lane-major/v2`;
- local lookup elements drawn strictly right after the salt, inside the section;
- roster from the emitters, with term-count assertions;
- `requireNativeGkrSecurity`, which checks the per-relation M4 source-bound mass against p and requires union bits >= 128;
- 128 instances.

It is **not built**: the native AIR change, GPU lane-major projection, receiver global claims from roots, and the leaf hook
are open. See the receipts and the stream report for what was measured.

## 5. Measured (2026-11-05, binaries of 715aa3f9e; pod load 27-43, single observations, not quiet-quotable)

Receipts: `vectors/reports/rv64-m6-20261105/native-format/` and `vectors/reports/progress/native-format.jsonl`.

**Switched on [M].** Both dev blocks prove under v2-strict in the production GPU prover. The harness is a one-shot bench,
`--env STWO_RV64_NATIVE_VERSION=m6-native-v2-strict` (runs `26235156-2gpu-v2s-r5` and `24628607-2gpu-v2s-r6`). A fresh,
separate, cache-disabled, GPU-disabled receiver accepts both (receiver 001bf1d9).
The control is the M5 default flat format on the **same** binaries. Its root sha is b424203b (156) and 2feed86a (607),
equal to the M5 default, so it is byte-identical.

| 24628607 / 26235156 | flat control | v2-strict | ratio |
|---|---:|---:|---:|
| native MAIN words | 2,703.0 M / 1,823.9 M | 3,133.2 M / 2,078.3 M | x1.159 / x1.140 |
| native INTER words (census reconciles exactly with GPU_TRACE_OWNERSHIP tree=2) | 1,854.1 M / 1,350.1 M | 2,270.7 M / 1,517.4 M | x1.225 / x1.124 |
| request (one-shot) s | 48.8 / 34.4 | 55.5 / 36.2 | |
| native prove s | 8.16 / 5.31 | 9.84 / 5.64 | |
| recursion s | 23.9 / 17.3 | 29.6 / 20.9 | |
| setup s (one-shot, cold) | 13.6 / 9.1 | 12.9 / 7.0 | |
| root proof bytes | 706,424 / 748,536 | 715,064 / 750,456 | |
| device peak (sampled) GB | 31.5 | 31.5 | |

**Where the tax comes from [M], from per-component census diffs of the same runs:**
- *Strict-roster-specific:* components that were absent and are now committed as padding. 92.8 M cells on 607 and
  29.3 M on 156, of which dword tail 37 M, LS32 tail 33 M and empty bridges about 20 M.
- *Canonical rung-log padding:* the same as canon-native v1 presence-preserving mode. 610.6 M on 607 and 363.6 M on 156:
  terminal +220 M (607), dword tail, bulk copy/set/ucopy, initial, sponge perm.

The strict roster itself therefore costs about 2 % of committed native cells. The rest is the R = 4 canonical table that
any constant native VK pays. A finer table (T_nat has 18 spare slots at DEPTH 6) is the lever if it matters before v2-gkr.

**Block independence [M].** RV64_NATIVE_CHAIN over both blocks gives 14 distinct (f, r) classes, each with exactly one
vkhash. The 8 classes that occur in both blocks have identical vkhashes (`class-independence.json`). The native VK table
can therefore be derived once.

**v2-gkr on the strict classes [D].** The census on the v2-strict bundles predicts native INTER 2,270.7 M -> 1,124.2 M on
607 (x0.495 vs v2-strict, x0.606 vs the M5 flat 1,854 M), and 1,517.4 M -> 705.8 M on 156 (x0.465 / x0.523). Keccak truth
INTER is 742.8 M -> 110.4 M on 607 (classic local 575.7 M + KIO 167.1 M become GKR). It is the largest single item and is
unaffected by the strict roster.

**Negative evidence [M].** NV03 tier R, fresh receivers (`26235156-nv03-cross-version.json`):
- v2 proof under the flat, v1-chain, v2-gkr and unknown selectors: rejected, exit 1, `InvalidServicesWireRequest`, at
  wire admission;
- flat proof under v2: rejected (`NativeChainNotStrict`).

The negative corpus v3 results on both v2 blocks are in `corpus-*.json`.
