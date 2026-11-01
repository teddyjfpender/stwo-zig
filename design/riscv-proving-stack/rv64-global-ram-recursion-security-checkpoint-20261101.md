# RV64 global RAM, complete Word16 recursion, and 128-bit security — 2026-11-01

**Status:** scoped research and executable *preflight/reference* implementation. This is **not** activation of global RAM, a new accepting recursive Word16 root, or a qualified 128-bit proof system.

**Base:** `codex/rv64-arith-memory` at `423a135cbcbe7400af238ebb586fbb145c4ea1c5`. Review `rv64-global-memory-argument.md`, `rv64-word16-recursion-readiness.md`, `rv64-optimization-goal-20261101.md` and `rv64-whole-protocol-security-policy.md` alongside this checkpoint. These files describe different, strictly scoped obligations.

## 1. Measured control and why this matters

The controlled native Word16 Ethereum guest executes **104,253,913 instructions**, producing **25 CPU and 5 service proofs**; the independent receiver accepts all 30 and the terminal output. The three repeated current schema-6, q70/P26, two-lane/eight-worker CPU runs took **148.14 / 156.99 / 159.97 s**. The median is **156.99 s**, not a projected single-proof latency. Their proof artifacts were identical. The later schema-7 LS32 fixture independently verifies the complete block and 17 CSP cases, but its source/geometry differs and it has **no controlled whole-block speedup** claim. The current proof set is a **native multi-proof certificate**, not one recursive root.

Source measurements: `vectors/reports/rv64-word16-execution-20261101/optimization-current-baseline-v1.json`, `vectors/reports/rv64-ls32-qualified-20261101/receipt.json` and `design/riscv-proving-stack/rv64-ls32-qualification.md`.

The CPU still pays for authenticated **batch-local Poseidon RAM**, the associated sequential root chain, duplicate PC/CPU state admission across native proof files and nontrivial recursive verifier work. A global-memory substitution is only useful if its *entire* source/receiver/circuit cost wins. It must not trade the existing root chain for host-only trusted metadata.

## 2. Executable result in this change

`word16_execution/memory/global_manifest.zig` retains the previously qualified **two-boundary physical** diagnostic and its existing root/claim checks. The new `validateStagedExecutionPlan` is an **independent expected-inventory preflight** for a proposed full-execution manifest. The accepting `Manifest.init` still returns `UnqualifiedGlobalExecution` for that scope.

The staged format fixes: INIT is zero-step at epoch 0; CPU participants occupy epochs 1..N and each retire **1..(2^22−1)** steps; TEARDOWN is zero-step at epoch N. Ordinals, roles, epoch numbers, continuous first-step offsets, expected PC/register-digest adjacency, and independently anchored genesis/final PC/register digests are checked before allocating. Expected fixed/MAIN log sizes are bounded to the currently admitted 5..22 range, and three distinct nominal positive-mass ledgers are added with checked arithmetic and strict **sum below 2^31−1**. All missing, duplicated, re-ordered, empty or oversized shards reject. **These mass fields are still metadata**; no claim about a physically proven positive event count is made.

`word16_execution/memory/global_flow_model.zig` is a bounded (64 words / 256 events), allocation-free, quadratic **independent reference** for the intended cross-epoch memory flow. It starts at an independently supplied canonical INIT, follows strict lexicographic predecessor chains, enforces unique `(address, epoch, tick)` after-times, checks before-values, immutable rights and exact TEARDOWN. Simultaneous Keccak/service accesses to **different** addresses at one epoch/tick are allowed; repeated writes to the **same** address/time reject. Malicious future predecessors, forks, stale data, unanchored addresses and wrong terminal words are tested. The model is intentionally not a verifier: changing an event's `origin` or `origin_ordinal` still passes when the data flow is otherwise honest. This explicit negative boundary demonstrates the need to bind events to physical CPU and service rows.

## 3. Global RAM protocol that is still missing

The selected 14-coordinate tuple is:

```
(space=1, addr_u16[4], epoch_u16, tick_u16, tick_u8,
 value_u16[4], readable_bit, writable_bit)
```

The required signed multiset identity is **BEFORE + TEARDOWN = AFTER + INIT**, under one manifest-derived QM31 challenge. Every after-time must descend strictly to exactly one independently authenticated INIT; the last time/value must be exactly TEARDOWN. Inactive rows produce zero mass. The "unique" key is **(address, epoch, tick)**, not `tick` alone. Overlapping service pointers require coalescing to one transition or a separately proved subclock. Unknown zero-default memory must prove absence from the nonzero expected image; policy-region membership alone does not prove zero.

The physical phase barrier must:
1. Seal the exact **memory-query columns and active weights** before drawing any global RAM challenge. A metadata receipt of a later witness is not a precommitment. If there is a separate query subtree, prove the physical join to the CPU/service committed row, with roots bound before the join challenge.
2. Check a receiver-owned complete, ordered manifest of **actual** fixed and query-tree PCS roots, geometry, shape identities, source/program/image/policy identities, service-call ranges, and *physically constrained* relation-mass ceilings. Compute the seal and RAM14 challenge only after all stage-one roots are present.
3. Prove each worker with that same challenge and a rechecked local root. The fresh receiver verifies **each entire STARK and its local claims** before summing the typed RAM claims. It must not accept cancellation between unrelated relations or take an expected root from proof metadata.
4. Prove sorted unique INIT/TEARDOWN with independently expected pristine image and terminal ABI values, verify all CPU/service event source joins, all epoch/time strictness and every active weight. Require one complete aggregate receiver rejection suite (omission, double emission, permutation, stale/root substitutions, incorrect zero defaults, mass overflow, service alias and terminal replacement).
5. Demonstrate a **bounded** stage-one source/PCS lifetime. All shards cannot simply retain every wide MAIN tree until the barrier. Measure committed projection storage, spill/reconstruction, failed admission and cleanup. Preserve the existing private-root receiver until the replacement passes all gates.

The previously drafted `global_ram_v1/` prototype tree referenced in older documents is **not present at this branch head**. Do not count its design as implemented code. The current working proof of boundary correctness is `memory/global_boundary_proof.zig`, with two actual native proofs, and not an execution-proof input bridge.

## 4. Complete Word16 recursive root: exact acceptance contract

The existing RV64 native-protocol recursion has verified **two/four legacy batches**, including independent topology and native fixed-root admission. **It does not verify the current Word16 + service proof format.** Reusing a legacy recursion receipt or a host-verified list of native proofs as a purported in-circuit Word16 verifier would be unsound.

A minimal authentic end-to-end progression:

1. **Typed real Word16 leaf:** implement a single circuit-point authority for every currently selected CPU, ROM, ALU/BINARY/SHIFT, JALR, MUL/DIV, LS/INIT/TERM, and service role. Source the equations from the actual native AIR, preserving ordered physical claims, FRI/PCS masks, every challenge draw and absent-role zero rules. Independently reconstruct the fixed root/key **before reading a child proof**. Complete a real native STARK-in-circuit leaf, fresh circuit verification, and hostile claim/root/sample substitutions.
2. **Global-closure fold:** introduce typed accumulator/public inputs for CPU/ROM/FUNCTION/local register debts, RAM14, Keccak IO11, secp Wire35, native program/ABI identity, service-call ordinals and first/last CPU states. The fold verifies child proofs *inside the parent circuit*, binds ordered non-overlapping spans and preserves every relation type. A field-sum over unverified host claims is not a recursive proof.
3. **Root:** the independently admitted root verifies all **25 CPU + 5 service** children and whichever INIT/TEARDOWN proofs the selected RAM version actually requires; binds the actual expected execution identity, the genesis image, complete CPU/PC/register adjacency, service call inventory, all global zero sums, 104,253,913 accepted retirements, terminal PC, halt, and independently expected **43-byte** result. Reject incomplete/missing/swapped children and arbitrary claimed root statements. Only then measure root proving, root verification, bytes, and peak memory.
4. **Version isolation:** changes to global RAM or core schema change native statements, physical claim rosters, transcript identity, fixed roots and recursive keys. Preserve native multi-proof proof acceptance while new identity/key/receipt migration is under test. Legacy RV64 recursive receipts never grant Word16 authority.

A root over the 25 CPU files while separately "trusting" the five service files or terminal state does **not** meet this contract. The CPU source/receiver in `word16_global_execution/services/` and `ethereum/receiver.zig` is the reference acceptance authority.

## 5. Exact 128-bit whole-protocol target

The existing q70/P26/fold1 benchmark control is **not** certified as 128-bit whole-protocol security. For `p = 2^31−1`, a single uniform QM31 challenge has `|F|=p^4 < 2^124`. Even a nonzero **degree-one** identity's Schwartz-Zippel upper bound `1/|F|` does **not** give a 128-bit guarantee. More queries and query-time proof-of-work do not make that earlier algebraic challenge larger.

`security_policy.requireSingleDrawAlgebraicBudget` now performs the exact integer necessary single-draw field-size comparison `degree × 2^required_bits <= p^extension_degree`. Its tests reject QM31 even for one degree-one identity at 124 or 128 bits, while accepting a degree-eight **arithmetic-only candidate** for a bounded degree at 132 bits. This is an **individual polynomial bound**, not an estimator of FRI, pre-challenge grinding, GKR, recursive composition, commitment attacks, or adaptive Fiat-Shamir queries.

To call the *whole protocol* 128-bit requires reviewed identities, field algebra/degree accounting, union/multi-instance bounds, FRI/PCS and hash/transcript ROM assumptions, recursive proof nesting, and an actual independently verified receiver at the selected parameters. The existing fail-closed `Certificate` registry must remain empty until a reviewed security argument and independent artifacts exist. Two "independent" FS repetitions do not automatically multiply security without an adaptive-independence proof. A 256-bit digest's **generic birthday collision ceiling** is only 128 bits before a multi-target accounting margin; do not silently treat it as a full-system 128-bit certificate.

## 6. Verification and promotion rules

Focused commands for this PR:

```sh
zig build test-riscv64-word16-global-memory -Doptimize=ReleaseSafe -j2
zig build test-riscv64-word16-global-memory -Doptimize=ReleaseFast -j2
zig build test-riscv64-security-policy -Doptimize=ReleaseSafe -j2
zig build test-riscv64-security-policy -Doptimize=ReleaseFast -j2
```

This branch's test assertions are **not yet a clean-host CI receipt**. No Zig toolchain is available in the analysis environment, so a passing test may not be asserted without actual runner output. Any source/format gate failure remains open until the exact head is compiled. The changes leave native proof formats, FS transcript order, hardware backend and production selection unchanged.

Next engineering milestone should be **one real CPU shard + one physical global RAM INIT/TEARDOWN pair** under the shared precommitment, with fresh receiver checks and a hostile CPU event-origin substitution. This will determine whether the tuple projection/bridge is economical before migrating the 30-proof whole-block driver. The user-requested GPU work remains deferred; only after full CPU/security acceptance should a device prove/verify campaign be treated as a performance qualification.
