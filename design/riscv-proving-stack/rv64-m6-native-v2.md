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

## 5. Measured
See `vectors/reports/rv64-m6-20261105/native-format/` and `vectors/reports/progress/native-format.jsonl`.
