# 128-bit security target under documented assumptions

Status: **bounded engineering review complete**, 2026-11-02. This is the agreed native GPU-handoff standard. It is not an independent security audit, formal proof, or certified whole-protocol128 claim. The native candidate is described as **“128-bit security target under documented assumptions.”** The stronger certificate gate remains closed; `security_qualified=false` retains its existing meaning.

Assumption identity: `rv64-native-om31-beta2-q256-p0-fold4-assumptions-20261102-v1`. Construction identity, field, sampler, transcript, parameters and proof encoding are unchanged. The reporting label is not a new proof protocol or acceptance authority.

## Reviewed scope and conclusion

The reviewed native construction is OM31/raw-Blake, beta2,256 queries, zero query-PoW, fold4. Its measured execution is block24,628,607:104,253,913 instructions,25 CPU proofs and5 service truth proofs. The final combined run proves in292.261s, reproduces all33 authoritative artifacts and is accepted by the unchanged fresh receiver. Recursion is excluded.

The exact-rational [composed model](../../vectors/reports/rv64-composed-security-20261102/model.py) was rerun against that run's fresh receiver-derived shape. The whole-roster query term is about2^-159.56; the conditional algebraic union is about2^-196.07. With explicit adaptive/scoped ROM assumptions its conservative formula is

`eps(T) <= (T+2^22)*E +169*(T^2+1)/2^256`.

It bounds success per query below2^-128.596 uniformly for1<=T<=2^120 under the stated premises. This is **not** failure probability2^-128 for a2^120-query adversary. Beyond the audited work range,256-bit hashes are treated conventionally as a128-bit generic collision target; the displayed reduction does not establish an exact unrestricted128-bit finite-security inequality. This distinction is accepted explicitly, rather than hidden by rounding or extra query-PoW credit.

## Assumptions accepted for this engineering target

| Assumption | Meaning and boundary |
|---|---|
| Classical ideal-hash model | Raw Blake2s256 transcript/commitment hashing and SHA256 identity hashing act as their modeled ideal authorities. This is not post-quantum security. Conventional128-bit collision strength is a target, not a theorem that removes finite reduction constants. |
| Applicable source-specific PCS reduction | The documented circle/line, conjugate DEEP, quotient-only degree correction, degree15 macro-FRI and unique-decoding correspondences apply to this implementation. The engineering review checks source consistency; it does not replace a formal theorem proof. |
| Scoped adaptive Fiat–Shamir reduction | The documented reduction applies across local GKR, native PCS and manifest scopes with their explicit domain separation, message ordering, round and hash-event budgets. The conservative169 coefficient is retained. |
| Source algebra and AIR premises | Sealed MAIN fixes tuples before relation challenges; valid support, unit stateful weights, canonical values and characteristic bounds make a false relation a nonzero polynomial. Integer semantic correctness is a reviewed engineering premise, not supplied by a larger extension field. |
| Receiver-owned scope | Trusted image/setup, ordered manifests, coverage, adjacency, physical binding and global closure are checked by the actual receiver. Producer metadata cannot authorize a security claim. The numerical budget applies to the reviewed30-proof roster, not every shape below generic parser caps. |

No extra security is credited to query PoW: this candidate hasP0. The legacyq70/P26 control remains a nominal96-bit PCS benchmark. Increasing its queries/grinding alone would not strengthen all earlier algebraic challenges. OM31 is retained for the stronger native target.

## Bounded source review performed

Review base: `03dbf1aac9bfe1573a3f8a6bb8a4c44fd5552e99`. The review receipt records current file hashes and comparisons with the original security snapshot.

| Check | Source/evidence and result |
|---|---|
| Parameters and raw sampler | `word16_execution/om31_security_candidate.zig` pinsOM31,beta2,q256,P0,fold4; `core/channel/raw_mod_m31.zig` supplies the actual sampler. The model retains exact maximum point mass6561/2^256, never uniform1/OM31 by substitution. |
| Challenge placement and namespaces | `services/gkr_local/child.zig:begin/verifyPending` binds statement,FIXED,MAIN,ordinal and ordered instances before local challenges. `challenges.zig:draw` separates relations and draws independent tuple coefficients; the scalar byte relation is injective with coefficient1. |
| Terminal authentication | `child.zig:verifyPending` reconstructs checked marginals before drawingeta. `binding.zig` uses the same row tuple emitter and authenticated Eq/cyclic-prefix constraints; `role_oods.zig` derives auxiliaries from the physical evaluation point. A numerical child remains pending until physical binding. Existing balanced-corrupt-projection proofs fail fresh verification. |
| Global challenge authority | `manifest.zig:verifyAndSeal/drawShared` seals the ordered expected roster, MAIN roots and checked local marginals before RAM14/KIO11/Wire35 challenges. Physical-root checks and aggregate claim closure remain required. |
| Canonicality and characteristic | `source_bounds.zig:derive` checks independently derived shape and ordinary signed global mass againstM31; the LS joint-write induction and52-writer audit includeLUI/AUIPC. Stateful OWNER/RAM weights are unit/Boolean; weighted reusable membership support is treated separately. These are source-level engineering arguments, not machine-checked semantic proofs. |
| PCS/FRI source drift | Of33 original snapshot files,28 match exactly. Five differ: public coordinate-walker export/forwarder, fresh-zero FRI fold hook and profiling scopes. No verifier/transcript change is introduced. Actual native proof parity, Safe/Fast scalar-oracle/allocation tests and the unchanged fresh receiver cover the optimized prover path. |
| Composition and scope accounting | The corrected exact model uses strict unique-regime agreement41/64, the DEEP domain factor, degree15 fold4 and conservativeR=2^22. Older candidate helpers using5/8 andR=2^20 remain engineering preflights, not this composed model or a qualification authority. |

The [full composed analysis](rv64-composed-security-analysis-20261102.md) contains the theorem anchors and detailed correspondence argument. Its remaining formal/independent-review obligations are retained as assumptions here, not marked proven. Primary references and accessed revisions are pinned in `vectors/reports/rv64-composed-security-20261102/primary-sources.json`.

## Handoff and enforcement

Integration checkpoint: the admitted evmone v2 guest now has a separate complete-block receiver/model receipt in `vectors/reports/rv64-pr308-evmone-v2-gkr-20261102/`. It uses15native proofs (11CPU+4truth). The optional `model.py --reviewed-v2-envelope` path permits only a monotone subset of this review's30-proof v2 envelope, including explicit shape/support/product-row bounds and exclusion of v3 families, throughput Keccak and paired/fused CPU layouts. The default pinned-roster model is unchanged. This is an execution-budget recalculation under the same assumptions, not a v3 security promotion.

The CLI reports the128-bit target and assumption identity separately from certification. Existing receiver parameter, geometry, mass, manifest and physical-binding validation remains unchanged. The certificate registry stays closed; this decision does not make caller-supplied review booleans authoritative.

Guest or geometry changes must regenerate the receiver-derived roster/mass and exact model before carrying forward the numerical bound. The executable model deliberately rejects unreviewed rosters. GPU implementations must preserve the same authority, field, sampler and transcript and pass proof/fresh-receiver parity; no GPU qualification is claimed here.

An OM31/GKR recursive root still needs a compatible outer construction and separate error/topology budget. Independent cryptographic audit and formalization remain valuable follow-up assurance, but are not prerequisites for using this explicitly assumption-qualified native target in GPU development.
