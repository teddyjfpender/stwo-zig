# OM/GKR GPU and 128-target readiness audit

Pinned source: `6091851f7`, with the shared worker configuration guard added by this slice. This is a source authority audit and a bounded admission fix. It does not qualify whole-protocol 128-bit security or a GPU prover.

## What the current receiver actually accepts

`services/gkr_local/worker_protocol.zig:16` instantiates the CPU backend explicitly. The supported physical protocol remains OM31, raw-modulo Blake challenges, prefixed Blake2s Merkle trees, beta1, last-layer log0 and fold1 or fold4. Query count and PoW are independent receiver inputs, bound into each worker transcript (`worker_protocol.zig:36`) and execution identity (`execution.zig:112`). The benchmark's q70/P26/fold4 configuration is preserved. Successful acceptance has no security certificate field.

`execution.zig:34` first applies shared configuration and native image/request admission, then derives each worker's ordered roster, statement, fixed root, global relation presence and characteristic mass. The stage-one manifest authenticates every CPU GKR child and every truth MAIN root before drawing global challenges. Physical CPU/truth proofs must match those roots. `execution.zig:147` separately verifies every physical proof and closes RAM, KIO and Wire before returning an execution result. The Ethereum adapter separately distinguishes a prefix from completion and authenticates the 43-byte terminal result. These obligations must remain intact through device and recursion work.

This audit found an admission mismatch: whole-execution admission allowed PoW through64, while the selected raw channel delegates to the Blake2s canonical grinder whose maximum is32 (`core/channel/blake2s_pow_order.zig:45`). Standalone worker entrypoints also lacked the same configuration check. The bounded fix moves the supported construction check to `worker_protocol.validateConfig`, calls it before CPU/truth producer and fresh-receiver allocations, and makes whole-execution admission delegate to it. Out-of-range PoW fails as an error before mining, rather than reaching a panic. This does not change admitted control transcripts, query schedules or security parameters.

## Beta2 authority: implemented helper versus missing integration

`word16_execution/fixed_setup.zig:31` hashes the explicit rate, ordered coefficient geometry and canonical coefficient contents. Its bounded immutable cache produces a distinct beta2 tree from trusted retained M31 coefficients, without re-materializing fixed rows. `WideFixedKey.require` (`:88`) checks independently expected descriptor, identity and root; `append` (`:95`) also checks the exact receiver-admitted PCS configuration and initial append phase. Existing tests cover independent reconstruction, ownership after cache teardown, all allocation failures, stale roots/identities, and beta1 transcript parity.

Actual services admission still chooses `setup.key.root` and `truth.key().root` (`gkr_local/execution.zig:58,76`), and actual worker append still consumes those legacy suite keys (`worker_protocol.zig:46`). The cache is not a beta2 production switch. Current shared configuration deliberately rejects beta2.

A coherent next beta2 slice needs all of the following together:

1. A receiver-owned fixed-authority context per admitted worker: exact coefficient identity, descriptor and independently reconstructed root, held by an immutable cache lease. Its lifetime must cover all physical proof references; there is no producer-selected root or rate fallback.
2. Inventory, CPU/truth statement identities, stage-one manifest, producer append and fresh receiver must all use that same admitted authority. Fixed column order and logs remain derived from the original trusted setup. Changing only append would break the receiver/manifest binding.
3. Separate explicit candidate protocol admission and transcript identity. Preserve the benchmark control. Require beta2 configuration and candidate caps before key/proof allocation; do not silently broaden the beta1 profile.
4. Actual CPU and all K/ADD/DOUBLE physical proofs at beta2, decoded fresh receiver, immutable-key reuse, stale-rate/root/identity/config mutations and allocation-failure cleanup. Then whole-execution closure and real block qualification under a bounded setup plan.

This is the setup/transport engineering gate, not the security theorem gate.

## GPU work that is still required

| Area | Reusable authority | Missing resident implementation/gate |
|---|---|---|
| M31 witnesses and commitments | Column-major MAIN, owned commitments, immutable setup identity, prepared public projections | Device-owned MAIN/FIXED/INTER lifetime, fixed-tree upload once per identity, actual transfer/peak-VRAM accounting |
| Composition | Shared MAIN, local GKR Eq/prefix and global classic polynomial authorities; packed base-field rows | Generated device kernels for the actual complete CPU and truth roles, including all eight secure coordinates, independent native/OODS parity |
| Numerical GKR | Typed OM31/M31 layers, shared verifier kernel, deterministic scoped CPU reductions | Resident M31 numerator/OM denominator layers, product tree and sumcheck folding/reduction, bounded workspace, identical challenge and proof bytes |
| DEEP/FRI | Shared M31 aggregate combination/FFT, checked scratch plan, exact wide quotient law | OM31 finalizer and FRI folding, resident mixed-height sampling/openings, backend-owned allocation and readback; wide raw backend currently fails explicitly (`quotient_field.zig:96`) |
| Scheduling/custody | Two-phase manifest, N-lane admission, durable full MAIN parking | Explicit GPU slot/stream leases, VRAM plan including product tree/binding/FFT/commit buffers; host retention estimates and file parking are not a VRAM budget |
| Receiver | Fresh native proofs, authenticated manifest and separate global closure | Device-produced full proof accepted by independent CPU receiver, failures/OOM/cancellation, complete block, and matched secure baseline |

The CPU pool kernels are useful algebra and layout references, not GPU qualification. The actual GKR input matrices, product tree and Eq/prefix binding remain material owners. Reducing host requested bytes cannot be reported as the same reduction in device peak or traffic. Keep local M31 numerators in base form, avoid a new process-global cache, and preserve the existing bounded producer ownership interfaces.

## Recursion is not connected to this execution profile

`logup_gkr/om31_circuit_verifier.zig:112` instantiates the same numerical verifier kernel in a circuit and returns a pending GKR artifact. Its header explicitly says no production receiver selects it. Its caller must still authenticate terminal input marginals against the physical MAIN expressions, rather than treating guessed MLE inputs as authority. The OM MAIN/global circuit residual tests establish arithmetic parity, not a recursive Ethereum execution proof.

The current production-style RV64 leaf/closure/fold path still uses QM31 (`rv64_recursion/leaf_statement.zig:17`, `closure.zig:16`, `fold_root.zig:18`). Its admitted topology and layout hashes do not automatically admit the new OM/GKR manifest or eight-coordinate physical proofs.

The smallest coherent recursive gate is a receiver-owned new leaf topology that verifies one actual OM physical worker plus its actual local GKR child (when required), derives the same scope/transcript, authenticates the terminal binding and exposes only verified RAM/KIO/Wire debts and statement/manifest identities. All truth relations must remain closed under the explicit classic-truth profile. A subsequent parent/root must bind the complete ordered manifest, program/image/endpoints, adjacency/coverage and separate global closure. Run actual service-rich leaves, folds and a fresh root receiver with omission/reorder/root/claim/candidate/layout mutations. Only then compare proof-to-fold architecture and complete recursive cost.

Outer circuit proof security is independent: retaining a QM31 outer proof does not inherit the native OM31 candidate's algebraic error. Redesign or independently qualify the outer field/channel/error budget before a whole-protocol claim.

## Construction and 128-target blockers

`word16_execution/om31_security_candidate.zig:200` intentionally refuses whole-protocol promotion even with every review flag set. Do not remove that gate because engineering tests pass. The existing candidate ledger lists the actual missing reductions:

- Source-derived signed/count/canonical-writer and characteristic mass arguments, including weighted facts and cross-worker grouping.
- Exact univariate-to-multilinear Eq/prefix binding and the adaptive raw-modulo GKR transcript reduction, including poles and all local namespaces.
- Applicable mixed-height circle OODS/DEEP/FRI theorem and instantiated query/list/round constants; the current engineering envelope is not a theorem.
- Stated classical-work/security convention and adaptive random-oracle bound over the claimed work range; the current bounded120-range conditional audit is not unrestricted128 certification.
- Every recursive layer's algebraic/transcript error and topology/statement binding, unioned with native/global errors.
- A final receiver-owned reviewed certificate registry entry, independent of all producer-supplied files and numeric labels.

PR309 can accurately report the implemented native experimental route, measured controls/regressions, bounded ownership and completed engineering gates. It must retain these separate native-beta2, theorem/security, recursion and resident-GPU gates until each has its own source and qualification evidence.
