# Whole-protocol 128-bit security: architecture and fail-closed accounting

Status: additive policy foundation, not an implemented128-bit proof suite. Current q70/P26 benchmark proofs, transcript and receivers are unchanged. The new `word16_execution/security_policy.zig` cannot authorize any whole-protocol128 claim: its receiver-owned certificate registry has no such entry. Numeric budgets, wider-field labels, repetition flags and query counts cannot manufacture that authority.

The target needs a precise classical computational/ROM work-factor definition, including allowed adversarial hash queries and applicable conjectures. It is not simply a per-proof probability of2^-128, and it is not a post-quantum target. The dyadic budget helper checks a necessary union-bound bookkeeping condition only; it does not implement a concrete ROM security estimator.

## Actual authorities at e70b35c31

| Path / role | Commitment authority | Fiat–Shamir / challenges | Current parameters and limits |
|---|---|---|---|
| Native Word16 CPU and mixed-service truth proofs | `rv64/air/protocol.zig`: prefixed raw256-bit Blake2s Merkle | Raw `Blake2sChannel`; QM31=p^4, p=2^31−1 | q70, blowup2, query PoW26, fold1; explicit fold4 experiment |
| Global services manifest | Native raw Blake channel over sealed fixed+MAIN roots and receiver-bound roster | `word16_global_execution/services/protocol.zig:shared`: RAM14, KIO11, Wire35 shared QM31 challenges | Characteristic/mass and aggregate closure checks are essential; global relations are not replaced by local GKR |
| Local CPU/provider lookups | Same native PCS | `word16_execution` and family AIR challenge authority | REG, ROM, OWNER, FUNCTION, byte/range/table debts and all physical claims need coverage |
| Keccak and secp truth | Same native PCS | Keccak chi/xor lookup challenges; secp polynomial/byte challenge plus global Wire35 | Tiny/provider-specific degrees and roster multiplicity count toward whole-block error |
| Standalone GKR mini-AIR | Same native raw Blake PCS | `logup_gkr/protocol.zig`; `lookups/gkr_verifier.zig`, `sumcheck.zig` | Experimental only; production local binding and recursive circuit unimplemented |
| Actual RV64 leaf wraps and internal circuit folds | **Plain unreduced256-bit Blake2s Merkle**, not an M31-reduced commitment | `circuit_cpu.prove.Internal`: `Blake2sM31Channel`, eight reduced M31 words in the FS state; QM31 arithmetic | Official production registry: q70/P26, fold4; shared target includes log23 QM31 and Blake-G chips |
| Actual final root circuit proof | Same plain raw256-bit Blake2s Merkle | `circuit_cpu.prove.Root`: raw `Blake2sChannel` | Registry-selected circuit suite; outer proof cannot retroactively remove inner argument errors |
| Alternate RV32 recursion/Poseidon substrate | Pinned width16 Poseidon2-M31, rate8/capacity8, digest8M31 | `riscv/recursion/poseidon2_channel.zig` and `recursion/protocol.zig` | Exists separately; **not the actual RV64 leaf/wrap/fold hash path** |

The critical distinction is in `core/vcs_lifted/channel_profile.zig`: **both** internal and root profiles set `MerkleHasher=Blake2sPlainMerkleHasher` and `Hasher=Blake2sHasher`; only `Channel` differs. `integrations/circuit_cpu/mod.zig` tests the equality. A channel class name is not evidence that its Merkle roots are reduced.

Eight M31 words encode fewer than248 bits, giving a generic state/digest collision ceiling just below124 bits. For an actual Poseidon commitment this is a binding concern. For reduced Blake FS state it is an **unresolved concrete ROM accounting issue**, not a demonstrated124-bit end-to-end attack and not a conclusion that the hash must be migrated. The policy distinguishes `CommitmentCollisionCeilingBelowTarget` from `UnreviewedReducedTranscriptBound`. The latter blocks a security claim pending an applicable analysis; it does not reject existing proofs or prescribe a replacement.

Native raw-channel sampling is important: `core/channel/blake2s.zig:drawBaseFelts` rejects all words >=2p before reducing, producing uniform base coordinates under the ideal hash model. The reduced FS channel first runs `vcs/blake2_hash.zig:reduceToM31`, so the rejection sees canonical words. Residues0/1 have three raw32-bit preimages and the others two. A generic four-coordinate maximum-density upper bound relative to uniform is at most(3/2)^4, about5.0625. A concrete bound must account for this sampler difference. This is not a practical attack claim.

## Error ledger: no omitted terms

The typed `Argument` set requires an entry for every category below. A budget entry is either unknown, not used, or an asserted total dyadic error bound. “Not used” is meaningful only under a reviewed receiver-owned protocol identity. The final certificate gate remains closed even if a caller supplies an unrealistically strong bound for every entry.

| Category | What the final bound must include |
|---|---|
| Tuple fingerprinting | Coordinate compression collisions, all bus arities and independent challenges; source fields, challenge distributions and admitted mass |
| Local LogUp | Rational-identity degree/support/multiplicity bounds, poles and exact signed local closure; all participating instances |
| Global RAM LogUp | Every CPU/bridge/boundary participant, characteristic bound, INIT/TEARDOWN authority and execution-wide sum |
| Service IO LogUp | Keccak IO, secp Wire and local truth byte/chi/xor relations; count/degrees across the entire roster |
| GKR and input binding | Every sumcheck degree/round, instance RLC, gate and row/lane folding, multilinear-to-univariate binding and late N/D combination |
| Composition | Random constraint mixing, multi-domain list sizes, table heights/degrees, weighted quotient and split selection |
| OODS identity | Bad point/denominator sets, list sizes, circle seed-to-point map and every masked offset |
| DEEP batching | Random combination degree, samples and periodicity terms, lifting semantics and all domains |
| FRI folding / queries | Applicable circle-FRI theorem/regime, list/line assumptions, all round losses and query error |
| FS and commitments | Actual ROM reduction, adversarial work/query count, raw Merkle binding, reduced transcript distribution/state and domain separation |
| Recursive verifier / outer proofs | Inner acceptance error plus all leaf/fold/root proof errors, transcript authority and topology/statement binding |

A single random-field root-count estimate scales with its degree/numerator over the challenge field. QM31 has fewer than124 bits, before these degree/list/round losses. For example, a crude M/|QM31| estimate at M≈2^27 leaves approximately97 bits, not128; this is an illustration of a missing certificate, not the final exact LogUp bound. Characteristic constraints cannot be fixed by a larger extension because characteristic stays p.

The current `PcsConfig.securityBits()` is `pow_bits + log_blowup*n_queries`: it reports96 at q70/P26. It does **not** include the ledger above. Raising it to128 by q102/P26 does not qualify the whole protocol. Source order in `core/verifier.zig` and `core/pcs/verifier.zig` draws composition randomness, OODS seed, DEEP randomness and FRI folding challenges **before** checking query PoW. That late grind is not automatically extra security for earlier algebraic errors.

## Candidate architectures and equal-security comparison

These are architecture alternatives to be formally analyzed, not admitted profiles.

| Candidate | Shared work and cost | Open security / recursion obligations |
|---|---|---|
| Wider secure field, e.g. degree8 over M31 | Base MAIN can remain M31. Secure INTER, binding/composition coordinate columns and secure wire sizes grow roughly2×; tower arithmetic is more expensive | New irreducible extension, samplers, evaluators, PCS/FRI and circuit support everywhere. Re-budget all degrees/list losses; unchanged characteristic limits. Secure-field enlargement alone does not resolve reduced FS analysis |
| Independent whole-algebraic repetitions, shared MAIN | Reuse program/setup and one commitment to the same MAIN. Separate lookup, composition, OODS/DEEP/FRI challenge schedules and dependency branches; MAIN openings may be deduplicated across query sets | Conditional soundness after shared MAIN must be proved; one weak unrepeated argument remains a bottleneck. Combining repetitions into one single-QM31 sumcheck/FRI introduces a new single-field batching error, so “batched FRI” is a theorem obligation, not a free optimization |
| Phase-specific PoW before each covered challenge | Keep existing field and narrow proofs; prover pays real grinding work. Verifier checks bounded nonces and all dependency framing | Apply a concrete FS/ROM theorem to each phase. Need transcript placement/nonce inclusion before the challenge, distinct framing, and coverage of every earlier error. Query-only PoW is insufficient; do not add its bits indiscriminately |

Compare **equally secure** variants. A twice-repeated GKR candidate cannot be compared against a once-executed96-control baseline as a production verdict. Likewise an improved128-target GKR leaf must be compared with the128-target classic-LogUp leaf, including the same outer recursion target and all scope/error bounds.

The preserved q70 source model gives all-local GKR46,725 added Blake compressions over25 CPU leaves, versus74,620 removed trace-leaf blocks and approximately3,996 removed OODS transcript blocks. A conditional fully independent two-copy construction approximately doubles the GKR transcript cost to93,450, **but also approximately doubles the classic INTER/opening work against which it is compared**. Thus doubling only GKR and holding the96 baseline fixed is not an equal-security comparison. Shared MAIN roots, different query sets, leaf rounding and recursion arithmetic prevent blindly multiplying the final wall-time difference by two.

For a degree8 variant retaining the literal Blake protocol framing, with S=6,800 active instance-layers, R=8,125 sumcheck rounds and L-sum650, claims/masks/round polynomials cost2/3/3 Blake compressions and each secure draw at least one32-byte hash block: a lower-level framing model gives `5S+4R+3L=68,450`, versus46,725 at degree4. It excludes any extra sampler squeezing/FS framing and changed binding/root mix. The equally widened classic control also has wider interaction columns/openings. These counts establish a cost question, not a winner. There is no measured accepting production GKR circuit.

An algebraic GKR-only subtranscript may reduce expensive Blake-G gates without replacing the PCS. Existing Poseidon width16/rate8/digest8 is not a qualified128-bit profile; capacity/output/framing need their own review. Raw-operation counts are not circuit proving measurements. Any nested transcript must injectively seed raw u32 parent state, bind protocol/scope/geometry/repetition identities and roots, and mix terminal digest/claims back into the parent before dependent commitments. It also leaves all non-GKR error terms to solve.

## Implemented boundary and qualification

`security_policy.zig` is an additive typed claim-accounting API. `benchmarkControl()` pins the current nominal control. `requireClaim(...,.whole_protocol_128)` always fails: structural failures have specific errors and otherwise the registry returns `NoReviewedWholeProtocol128Certificate`. It has no dependency on proof decoding and does not alter verification acceptance. `Budget.requireUnionBound` checks a conservative dyadic union budget without floating point: with k applicable terms, require each claimed exponent at least target+ceil(log2 k). This is deliberately insufficient for certification, and numeric claims never bypass the registry.

Production completion requires choosing a concrete security model and formally budgeted architecture, implementing its transcript/dependencies, pinning complete receiver authority, qualifying adversarial and mutation tests, building the matching recursion verifier, and publishing an equally secure complete-block performance comparison. This policy does not claim any of those gates completed.

## Primary references consulted

- [Logarithmic derivative lookups, Haböck (2022/1530)](https://eprint.iacr.org/2022/1530): rational identities, multiplicities, vector lookups and a dedicated soundness analysis. Its parameter-specific bound must be instantiated; the simple M/field illustration above is not a substitute.
- [LogUp-GKR, Papini–Haböck (2023/1284)](https://eprint.iacr.org/2023/1284): fractional-sum GKR and the univariate/multilinear bridge. It motivates the mechanism but does not certify this implementation's receiver/binding or whole-block security.
- [Circle STARKs, Haböck–Levit–Papini (2024/278)](https://eprint.iacr.org/2024/278) and [official Stwo whitepaper summary](https://github.com/starkware-libs/stwo/blob/dev/.agents/papers/llm/Stwo_Whitepaper.llm.md): circle coding and multi-domain soundness must use applicable degree/domain conditions. The summary distinguishes proven and conjectural parameter regimes and a ROM error bound dependent on adversarial queries, per-round errors and hash collisions. No formal whole-protocol parameter certificate was derived in this task.
- [DEEP-FRI, Ben-Sasson et al. (2019/336)](https://eprint.iacr.org/2019/336): outside-domain sampling improves proximity reductions under explicit list-decoding assumptions; it does not eliminate finite-field error terms.
- [Cryptographic sponge functions, Bertoni et al.](https://keccak.team/files/CSF-0.1.pdf), sections5–6: generic sponge/output collision analysis depends on capacity and output size. The existing eight-word Poseidon output's cardinality is a source-derived ceiling, not a review of its permutation security.
