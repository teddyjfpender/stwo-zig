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
anything else, including a set `omit_empty_division`.

*Correction (adversarial review, 2026-11-05).* An earlier draft said here that the receiver plans its own declarations
from its own capture. It does not. `verify-recursion-candidate` never captures: it reads the declarations and the
request counts from the producer's `bundle.json` (`gkr_main.zig` verify branch: `W.read`, then
`Keys.initWithSuiteAndCaches(loaded.cpu_declarations, ...)`). So **the producer chooses the class**: any rung of the
segment's family whose vector it declares exactly. The receiver only checks that the declaration *is* some rung
(`NativeChainNotStrict` otherwise), and every key, FIXED root and vkhash follows from that declaration. This is still
sound: the rung set is finite and public, and each rung is an ordinary admitted geometry with its own VK. But the
soundness of the admission relaxation cannot rest on "the prover cannot choose presence". See point 1 below.

**Admission relaxation (policy-gated).** Under v2 only, "present iff it has rows" becomes "absent implies no rows" for
the bridges (12 families), the bulk kinds, the sponge kinds, the LS-D64 head and tail, and the LS32 tail
(`protocol.zig presenceAdmitted`, `types.zig dwordCounts`, `geometry.zig lsCounts`). The ALU, BINARY and SHIFT tails
already admit empty instances on the receiver side (their claims are prover-computed and close through FUNCTION). The
`geometry.zig factCounts` relaxation is used only by producer witness planning (`provider_tails.zig`, via
`sources.zig`/`device_headers.zig`), not by admission. Outside v2 the old rule
is unchanged, byte for byte.

**Why the relaxation is sound.**
1. *Presence is the producer's choice of rung, and that choice cannot hide calls.* The producer picks the rung, so it
   does choose presence (see the correction above). Two rules make that harmless:
   - The relaxation is one-sided. `presenceAdmitted` still refuses an *absent* component with non-zero calls or rows, and
     absent claims must be zero (`NonzeroAbsentServiceClaim`). A rung choice can therefore only *add* instances; it
     can never drop a component that has work.
   - An added instance is all padding by its own AIR. Every optional CPU-proof component (bridges, bulk, sponge, LS-D64,
     LS32 tail) forces `active` to be a prefix whose first row equals `nonempty = (count != 0)`. With count 0 that gives
     row 0 inactive, every later active row needs an active predecessor, padding forces every other MAIN column to
     zero, and every lookup numerator is gated by `active`. In the native verifier, `nonempty` is computed from the
     receiver-admitted count (`qFor(count != 0)`). In the OM31 leaf it is the `is_nonzero` gadget of
     `om31_native/cpu_leaf.zig flag()`: boolean, `count * (1 - nz) = 0` and `count * inv = nz`. The prover cannot
     set it.
   Measured in the tamper suite of this review (fresh receivers, `rv64-m6-20261105/native-format/review-tamper-26235156.json`):
   activating a present-empty instance (NVT05), a non-zero global claim on a present-empty bridge or LS32 tail
   (NVT06/07), and an admissible relabel to another rung (NVT02b) are all rejected.
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
Under v2 they cannot. The production v3 layout (`Plan.CpuLayout.forGkrProfile`) gives flags = **0x0E** (cpu_fused_tail, cpu_u8_pairs,
cpu_compact_decode), as measured in the v2 bundles. Golden vectors for the version identities and all 46 class structures:
`vectors/rv64-m6/native-v2-vectors.json`, generated by `scripts/rv64_m6_native_v2_ref.py` and pinned by
`corpus NV01 golden`.

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

**Ledger at the NF4 bounds [D] (profiles NV-R3).** Inputs: 256 proofs, 128 instances, 28 variables, round degree 3, tuple
arity 58, N = 2^28.

| term | value |
|---|---|
| sumcheck rounds | 256 * 128 * 3 * 28 * 29 / 2 = 2^25.3 |
| instance mix | 256 * 258 * 28 = 2^20.8 |
| layer binding | 256 * 128 * 2 * 28 = 2^20.8 |
| tuple compression | 256 * 128 * 58 * 2^28 = 2^48.9 |
| poles | 256 * 128 * 2 * 2^28 = 2^44 |
| **total** | **about 2^48.9** |

At the raw-modulo OM31 point probability 3^8 / 2^256 the union is 2^-194, which clears the 151-bit target. The test
`native GKR v2 bits ledger at the NF4 caps` pins 190 bits as passing and 200 as failing. The *conservative* characteristic
mass at the caps, 128 * 2^28 = 2^35, is >= p. So `requireNativeGkrSecurity` takes the receiver's per-relation source-bound
masses (`RelationMasses`) and has no conservative fallback; the test pins this too.

**Version binding before stage one (profiles NV-R2).** The v2 version identity enters only the chain IV, hence chi. It
does not enter the stage-one transcript (MAIN commitment, the stage-one local GKR of v2-strict, FIXED). Why that is
harmless:
- (i) every stage-one object is bound to its own statement, FIXED root and ordinal, exactly as under v1. It proves only
  proof-local facts (local relation closure), and no stage-one fact depends on the protocol version.
- (ii) under v2 the receiver derives a *different declaration*: the strict rung vector, with a different FIXED and
  structure. So a v1 stage-one transcript of the same segment does not even exist for the same FIXED.
- (iii) every draw that touches a cross-proof relation (RAM/KIO/Wire challenges and everything in stage two) comes from
  `drawShared(chi)`, and chi hashes the v2 version through the IV. A v1 or flat proof therefore meets different global
  challenges under a v2 receiver; NV03 confirms this ([M], five of five rejected).

Mixing the version at the native channel start would change every stage-one byte. It is the cleaner rule for v2-gkr,
which changes stage one anyway (no stage-one GKR): v2-gkr mixes `version_v2(mode=1)` as the first channel word.

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

**Negative corpus v3 [M]** (`rv64_m5_negative_corpus.py run`, fresh receivers with the v2 policy): 42/42 on 26235156 and
42/42 on 24628607. No unexpected accepts and no crashes (`corpus-<block>-v2-strict.json`).

**v2-gkr roster bound [D]** (`v2gkr-roster-caps.json`, from the strict-class census): the CPU rosters reach **68
instances** (cpu-5 on 607, cpu-1/2 on 156), above v1's 64 (`rv64-native-gkr-tool shape` refuses them with
`NativeGkrRosterShape`). The maximum is 27 variables and lane log 11. That is why v2 sets 128 instances and why CUDA
`batch_max_oracles` 64 -> 128 is a hard prerequisite. The flat classes peak at exactly 64.

**CUDA `batch_max_oracles` 128: attempted, not landed [M].** The attempt is saved as
`batch-oracles-128-attempt.patch`. It changes:
- `batch.h` (cap 128; state words `61 + 33 * cap` = 4,285);
- `gkr_loop.h` and `riscv_cuda/rv64/abi.zig` (GkrState 2,580 words; offsets 280/288/296/308/2,356);
- the launch-metadata bounds (`Roots` 6 KiB, `BatchJobs` 3,080 B, `BatchTailPacket` above 4 KiB, all by-value kernel
  parameters within the CUDA 12.1+ 32,764 B limit).

Every TU compiles: `batch_tail` uses 41,904 B smem, 255 registers and a 208 B stack. The zig driver builds against the new
ABI. But the `-rdc` device link of the resident image (`nvcc -shared`) **segfaults deterministically** (exit 139 after
33.7 s, reproduced twice). The likely trigger is the by-value packets that now exceed 4 KiB in relocatable device code
(unverified). The fix for v2-gkr is to move the per-oracle job arrays (`SumPacket`/`FoldPacket`/`FoldSumPacket`,
`BatchTailPacket`, `Roots`) from kernel parameters into a device-side job buffer, written once per batch. That also fits
the enqueue-only contract better than 30 KiB parameter blocks per launch. The production tree keeps 64, so its bytes are
unchanged.

*Review note on the segfault diagnosis (unverified either way).* hint-tape reported in M6-INTERFACES (about 23:00 pod time)
that the pod's 30 GB root overlay (`/`, where nvcc's default TMPDIR lives) reached 100 % and that an **nvcc link
segfaulted** at that time. During this review `/` was at 91 %. Before anyone redesigns the kernel parameters on the strength
of "deterministic exit 139", re-run the 128-oracle device link once with `TMPDIR=/workspace/...` and enough free space.

## 6. Adversarial review of v2-strict (2026-11-05, reviewer, head 902284701)

Scope: forging native proofs under `STWO_RV64_NATIVE_VERSION=m6-native-v2-strict` with fresh, separate, cache-disabled,
GPU-disabled receivers (b4, 001bf1d9) on the accepted 26235156 pair. Script `scripts/rv64_m6_native_v2_tamper.py`.
Receipt `vectors/reports/rv64-m6-20261105/native-format/review-tamper-26235156.json`. Every mutation is coherent:
`bundle.json` is rewritten with matching file hashes, so `WideBundleFileChanged` cannot be what rejects.

**Result [M]: 15/15 as expected. No unexpected accepts, no crashes.**

| id | forgery attempt | rejected by |
|---|---|---|
| NVT00 | control (unmodified) | accepted (49.1 s wall at load ~23) |
| NVT01 | cpu-1 sha256 log 8 -> 9 (no rung equals it) | `NativeChainNotStrict` |
| NVT02 | cpu-1 relabelled as cpu_middle rung 0 (capacities too small) | `InvalidServicesWireRequest` (admission) |
| NVT02b | cpu-1 relabelled rung 1 -> rung 2: the counts fit, 4 curve bridges become present-empty with zero claims; strict check passes | `GlobalGkrManifestExecution` (keys and FIXED of rung 2 do not match the rung-1 proof) |
| NVT03 | cpu-3 `omit_empty_division = true` | `NativeChainNotStrict` |
| NVT04 | cpu-0 `cpu_compact_decode = false` (same rung vector, different flags word) | `GlobalGkrManifestExecution` |
| NVT05 | present-empty arith256_mod in cpu-0 claims 1 call (cpu-1 12 -> 11, so the truth span still adds up) | `InvalidSumcheck` |
| NVT06 | non-zero global RAM claim on cpu-0's present-empty arith256_mod | `OodsNotMatching` |
| NVT07 | non-zero global RAM claim on cpu-1's present-empty LS32 tail | `OodsNotMatching` |
| NVT08 | cpu-0's present-empty arith256_mod made absent (legal under the old rule) and its claims dropped | `NativeChainNotStrict` |
| NVT09 | 24628607's cpu-0 (same class, same vkhash 35369d4f, same initial state) replayed as 26235156's cpu-0 | `InvalidCombinedTruthSpan` |
| NVT09b | NVT09 with the truth spans re-aligned to the donor's counts | `InvalidKeccakComponentGeometry` |
| NVT10 | cpu-1 <-> cpu-2 (same class 21f356a4), epochs rewritten to the ordinals | `NonAdjacentEthereumCpu` |
| NVT11 | truth-1 <-> truth-2 proofs and claims (same keccak class 2457324e), spans kept | `GlobalGkrPhysicalRootMismatch` |
| NVT12 | truth-1 keccak log 14 -> 16 (another strict rung) | `GlobalGkrManifestExecution` |

**Completeness [M].** A fresh v2 receiver run of this review accepted the v2-strict 24628607 bundle
(`24628607-2gpu-v2s-r6`): `accepted` and `completed_ethereum_block` true, 7 CPU + 10 truth proofs, setup 10.76 s, native
verify 1.62 s, recursion verify 61.6 s. This is a single observation at load ~20, on a CPU-only receiver. NVT00 is the
26235156 control.

**Findings.**
1. *(Fixed in this note.)* Sec. 2 said that the receiver derives the declarations from its own capture. It reads them
   from the producer's bundle, so the producer chooses the rung. The relaxation is still sound, for the reasons now
   given in sec. 2 point 1: one-sided presence, plus the AIR's `nonempty` prefix with a receiver-computed or
   gadget-constrained flag. NVT02b shows that an admissible relabel is caught by the keys and FIXED.
2. *(Open; completeness, fails closed.)* v2-strict is not total. `canonFitStrict` requires `cpu_log` (and `boundary_log`)
   to equal the rung exactly. The table has no `cpu_single` family at all, and `cpu_last` only has `cpu_log` 20, 21 and 22.
   `cpu_log` is fixed by the step count of the capture-time source. So a block that fits in one segment (fewer than
   about 4.19 M steps), or whose last segment has fewer than 2^19 steps, gets `NativeChainNotStrict` and cannot be
   proven under v2. That is [E] at least 1 in 8 multi-segment blocks, plus every single-segment block. The real share is higher, because
the only cpu_log-20 rung (cpu_last rung 0) has no Keccak bridge. Both dev blocks fit:
   their last segments have cpu_log 22 and 21. Before v2-strict becomes the default, add `cpu_single` rungs and cpu_last
   rungs down to the smallest cpu_log, or pad the last segment's cpu_log up to a rung. Either is a rung-table change.
3. *(Open, low.)* The version identity binds R = 4 but not the contents of the rung table. A re-generated table with the
   same R keeps the same version identity, although (f, r) then names different vectors. vkhash and structure_v2 still
   differ, so this is not a forgery. Bind a rung-table digest (NF2 `rung_table_id`) into `versionIdentityV2` before the
   first table change.
4. *(Open, low, v2-gkr reference only.)* `v2.proveCpu` may try `MAX_SALT_ATTEMPTS = 64` salts, which is 6 bits of grinding
   over the local elements. The NF4 ledger (2^-194) does not list it. The margin covers it (188 >= 151), but the ledger
   should carry the term. `v2.verify` returns the global group sums unbound. NF4's "global claims = GKR roots" and the
   MAIN binding residual are not built. As the status says, nothing in v2.zig is a receiver yet.
