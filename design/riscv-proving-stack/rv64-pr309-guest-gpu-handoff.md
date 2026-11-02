# PR309 handoff: native GKR qualification and security boundaries

Current engineering classification: **128-bit security target under documented assumptions**. The [bounded review](rv64-native-128-assumptions-review.md) is complete for the pinned native construction. Certification and recursion remain separate; the historical analysis and fail-closed certificate policy below are preserved.

This closes the current CPU implementation slice. Guest integration and GPU execution are subsequent work. Do not infer a security promotion from proof acceptance, a wider field, or faster kernels.

## What is implemented

The services route authenticates local GKR claims against committed MAIN on the lifted domain. Register, owner, function, ROM and local tables already use GKR; RAM14, Keccak IO and secp Wire remain transcript-bound global classic arguments. Complete reception closes these obligations and checks the initial image, coverage, adjacency and terminal output.

Streamed numerical input, bounded checkpoint storage, optional deferred binding, owned witness retirement and bounded parked MAIN are qualified. The final CPU kernel slice adds packed/pooled OM31 FRI, actual owned-column zero-top dyadic LDE, and blocked DEEP finalization. The dyadic worker path joins every job and propagates errors before publishing output. Proof parameters, transcript order and accepted statement authority do not change in this kernel slice.

Per-slice Safe/Fast numerical, allocation-failure and physical-proof tests accompany the changes. The final combined build and full-block receipt are under `vectors/reports/rv64-pr309-final-20261102/`. Timings there cover pinned block 24,628,607, 104,253,913 guest instructions, 25 CPU plus five truth proofs, without recursion. The fresh receiver is the separately frozen pre-kernel binary; all 33 authoritative artifacts are compared with the prior same-profile/same-geometry run.

## Security classification

| Profile | Purpose | Qualification |
|---|---|---|
| QM31 q70/P26 control | Historical nominal96-bit PCS benchmark | Not a whole-protocol128 claim |
| OM31 q70/P26 control | Matched field/GKR engineering comparison | Functional qualification; no reviewed whole-protocol certificate |
| OM31 beta2/q256/P0/fold4 candidate | Stronger native engineering candidate | Full-block functional qualification and conditional composed analysis; `security_qualified=false` |
| Recursive outer proof | Future current-profile root | Existing QM31 wrap/fold does not qualify OM31/GKR |

The [composed analysis](rv64-composed-security-analysis-20261102.md) and exact-rational model include raw challenge bias, lookup identities, GKR/binding, DEEP/OODS, degree15 macro-FRI and multi-scope transcript terms. Their bounded-work result depends on explicit theorem-to-source and adaptive random-oracle premises. It is neither a statistical failure probability of 2^-128 nor an unrestricted certified128-bit guarantee. The certificate registry remains fail-closed.

Before promotion: independently review those premises and the scoped Fiat–Shamir reduction; select the concrete security/work definition and hash constants; validate the budget for the new execution's receiver-derived roster. Recursion requires its own analysis. No additional query or grinding setting silently supplies these missing proofs.

## Guest merge gate

1. Integrate the completed guest separately; regenerate ABI symbols, heap/input bounds and ELF identity from that ELF.
2. Re-run independent execution/oracle agreement and complete native proof/fresh verification. Preserve expected state/output and explicit global service closure.
3. Recompute the receiver-owned shape, lookup mass and composed model for the new guest. This document's 30-proof budget is not reusable for arbitrary inventories.
4. Benchmark source construction and proving separately using the same schedule and security profile. Do not compare a one-batch control to a full block or include recursion in only one side.

## GPU and recursion gate

Carry the native field, sampler, canonical encoding, transcript, fixed-key authority and global claims unchanged into the device design. Keep requested allocation, retained capacity, scratch and process RSS distinct. The final CPU kernels remove avoidable work; they do not qualify device custody or numerical parity.

An OM31/GKR recursive leaf still needs eight-coordinate PCS/FRI, terminal binding, manifest/adjacency and global closure. Measure complete root verification work, not just proof-file size. A same-security GKR-over-classic wall-time win and the two-second stretch target remain unestablished.

GPU provisioning/execution is deferred by user instruction. The PR records the independent inherited circuit-provenance CI failure; focused local qualification is not a claim that repository-wide CI is green.
