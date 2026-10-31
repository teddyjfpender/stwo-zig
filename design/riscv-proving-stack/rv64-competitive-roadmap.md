# RV64 proving: the road to the Zisk and Airbender frontier

Status: roadmap, 2026-10-31. It orders the remaining engineering by the
leverage each item has on block-scale proving time and cost, against the
frontier as publicly reported this month. Every competitor figure below is
vendor-reported unless marked otherwise and must be re-checked on EthProofs
before it is quoted externally.

## 1. The frontier, October 2026

| System | Reported result | Hardware | Proof system | Notes |
| --- | --- | --- | --- | --- |
| Airbender Prime (ZKsync, 13 Oct 2026) | 99% of 7,200 consecutive mainnet blocks under 10 s each, including witness preparation; worst 12 s | one RTX PRO 6000 Blackwell | hash-based STARK: GKR sumcheck for constraints, WHIR commitment, Blake2s; L1 proofs planned with Keccak-256 commitments, no pairing wrap | RV32, delegation circuits, degree-2 lookups, shuffle RAM with lazy init |
| Zisk v1.1.0-alpha (Aug 2026) | p99 9.62 s, 99.7% of tested blocks under 10 s | four RTX 5090 | Goldilocks STARK (pil2-proofman), fixed per-AIR instances, minimal trace | RV64IMA, Binary and Arith state machines, Keccak, SHA-256 and arith256 precompiles; block range and methodology not published |
| Zisk, EthProofs Nov 2025 | 99.74% under 12 s, 6.56 s mean | 24 RTX 5090 | | independently listed |

The working standard the field uses: at least 99 percent of mainnet blocks
proven inside 10 seconds, witness included, on hardware that costs cents
per proof. The leader does this on one GPU. Our stated target of a 2 to 5x
gap on four 5090s therefore has to be read as the first milestone, not the
destination: parity means one or two GPUs under 10 s p99.

## 2. Where we are, measured

Block 24,628,607, lean guest (104.3M retirements), legacy byte CPU:

| Quantity | Value |
| --- | ---: |
| Batches of 2^22 - 1 steps | 36 (CPU proofs, 16 workers, M5 Max) |
| Plain batch prove | 16 to 22 s; service batches 2 to 4x more |
| Cells per retirement | 533 main + interaction, quotient on 4n |
| Main columns per batch, of which private RAM providers | 1188, of which 712 |
| Proof per batch | about 1 MB (3.7 MB with services) |
| Recursion | 2 and 4 batches to one root on CPU: wrap 9 s, fold 10 s per pair; circuit proofs under 1 s each on an RTX PRO 6000 (team measurement) |
| GPU batch proving | none for RV64 yet (CUDA runtime exists for Cairo and the circuit prover) |

Against the frontier the gap decomposes into five factors, roughly
multiplicative:

1. Arithmetization: 533 cells per retirement on 4n, against a few dozen
   columns per lane for Zisk's main machine and degree-2 lookup rows for
   Airbender. This is the largest factor, about 3 to 5x.
2. Memory argument: 712 of 1188 main columns and the whole Poseidon2 chunk
   tree exist only to prove RAM; both competitors use a permutation or
   lookup memory argument with no hashing. About 1.5 to 2x on columns, and
   it removes the serial root chain.
3. Proof system work per cell: quotient composition on a coset domain plus
   Merkle-committed FRI with 70 queries, against sumcheck-based constraint
   checking (no composition polynomial) and WHIR (far fewer hashes) in
   Airbender Prime. About 2x in GPU time at equal cells, and the dominant
   factor once 1 and 2 are done.
4. Hardware: CPU today, GPU required. The CUDA port is designed
   (`rv64-cuda-port.md`); it is a port, not research.
5. Guest and witness: 104M retirements is competitive after the lean-guest
   rounds, but execution, trace capture and witness are not yet streamed
   into the prover, and recursion is not yet overlapped with batch proving.

## 3. Required work, in leverage order

Each item names its design, its gate, and what it is worth. Items in the
same tier are independent and can run in parallel.

### Tier 1: arithmetization and memory (the 3 to 8x)

1. **Thin Word16 CPU on 2n with family chips and fixed geometry**
   (`rv64-word16-cpu-2n.md`). 533 to about 271 cells per retirement, every
   cell on 2n instead of 4n, opcode selectors replaced by ROM-authenticated
   features, one typed bus tuple, fixed log per chip. Gate: full block with
   fresh receiver, statement parity, CI target. Worth about 3x on the CPU
   component alone.
2. **Global memory argument** (`rv64-global-memory-argument.md`). LogUp
   RAM relation across batches with epoch ordering, sparse INIT/TEARDOWN,
   two-phase manifest, no Poseidon2 RAM tree. Removes 712 main columns per
   batch, the RAM witness (28.8 s per block), and the serial root chain, so
   batches prove in any order and in parallel. Gate: the thirteen-item
   attack list and a full block through the aggregate receiver.
3. **Delegations at Zisk's granularity.** Present: Keccak-f, secp ADD and
   DOUBLE. Missing against Zisk and Airbender: full ecrecover (one call, not
   44.9k bus crossings), SHA-256 compression (11.2M guest instructions
   today), arith256 and modular arithmetic (secp field inversion and sqrt
   hints), a memcpy/memset/memcmp DMA machine (15.3M instructions), and a
   frequent-operation table. Each is a fixed-shape provider with a typed bus
   and a lookup-mass admission. Worth about 1.5x on guest instructions and
   more on service batches.
4. **Fixed geometry per protocol version.** Every chip and provider at a
   fixed log size per 2^22 batch, padded instances rather than variable
   logs. This is what makes one verifying key per AIR, one recursion
   topology, and prover-side memory planning possible. It is a prerequisite
   for Tier 3 and Tier 4, not an optimization.

### Tier 2: proof system per cell (the 2x after Tier 1)

5. **Sumcheck-based constraint checking.** Airbender Prime's step from
   quotient-and-FRI to GKR sumcheck removes the composition polynomial and
   its coset evaluation (287 s of the 36-batch run) and shrinks the per-cell
   GPU work to multilinear evaluations. For us this is a new prover lane in
   `src/prover`, not a change to the AIRs: constraints stay as they are;
   the lane evaluates them under sumcheck randomness instead of on 2n
   cosets. Gate: a batch proof of the Word16 lane under the new lane,
   byte-pinned verifier, security analysis signed off.
6. **Commitment with fewer hashes.** WHIR or a comparable
   proximity-test-based commitment cuts Merkle hashing by a large constant
   against lifted-tree FRI at fold step 1, and makes recursion leaves
   smaller (the current leaf spends two-thirds of its hashing in FRI).
   Short of a new commitment: fold step 4, plain hasher, fewer queries with
   a matching proof of work. Gate: parameters at the same security claim
   competitors make, written down with the conjecture they rely on.
7. **Degree discipline.** Degree 2 lookups only, as Airbender does, instead
   of degree 3 pair batching, halves the sumcheck or quotient work per
   lookup row. This is a Word16 chip design choice to take now, not later.

### Tier 3: GPU (the 10x that turns seconds-per-batch into real time)

8. **CUDA resident batch prover** (`rv64-cuda-port.md`). Witness kernels
   from the tape, FFT and LDE, generated constraint kernels from the typed
   DAG via a symbolic lane (the lane contract now exists), LogUp, Merkle,
   FRI, DEEP, host transcript. Memory plan 5 GB per 2^22 batch on the
   Word16 shape, so two batches in flight per 32 GB device. Gate: proof
   byte-identical to the CPU proof of the same batch, then four GPUs on a
   block with fresh receiver and p50/p99 over a block range.
9. **Executor-to-prover streaming.** Minimal trace (checkpoint every 2^18
   steps plus memory-read values, as Zisk), parallel replay to witness in
   pinned device buffers, no files between execution and proving, batches
   proven as the executor emits them. Gate: witness generation hidden under
   proving for every batch but the last.
10. **Recursion on the device and overlapped.** Wraps start as batches
    finish; folds run on whichever GPU is free; the root receiver runs on
    the host. With circuit proofs under one second the critical path after
    the last batch is one wrap plus six folds. Gate: end-to-end root on the
    same machine, measured p50/p99 over a block range.

### Tier 4: recursion and settlement

11. **One leaf topology.** Follows from fixed geometry; until then the root
    receiver binds each leaf to its admitted layout hash.
12. **Batch protocol tightened for recursion.** Fold step 4 and the plain
    hasher in the batch PCS, Word16 column counts: the leaf drops from
    about 3.1M to under 1M Blake G gates, enough for a dedicated RV64
    registry with a cheaper fold fixpoint than the production one.
13. **In-circuit adjacency.** A fold statement that opens both children's
    statement words and checks pc, registers, RAM root and call-id
    continuity, so the root carries the whole chain and the receiver checks
    one digest.
14. **Settlement wrap.** Either a pairing-based wrap of the root for today's
    L1 verifiers, or the route Airbender announced, Keccak-256 commitments
    verified directly on L1. Decide with the security review; both are
    downstream of a fixed root shape.

### Tier 5: engineering standards that make the above safe and measurable

15. **An EthProofs-grade harness.** Prove 7,200 consecutive mainnet blocks,
    record p50/p99 wall time including witness, GPU count, energy and cost
    per proof, and publish receipts in the repository as the Starknet lane
    does. Without this no comparison with Zisk or Airbender is honest.
16. **RV64 in CI.** Today no CI workflow, `ci.py` plan or release gate runs
    the RV64 lane. Add the focused test roots, the fresh-receiver block
    test on a committed small fixture, the recursion tests, and a perf
    ratchet on the per-batch stage profile.
17. **One verifying key per AIR and one receiver.** Fixed shapes, pinned
    registries, and a receiver that is a key plus a proof, with the
    adversarial lists of every design document promoted to committed tests.
18. **Security.** Independent review of the lookup-mass bounds, the global
    memory argument and the recursion statement; a written statement of the
    security level and the conjectures it rests on, matching how the
    competitors state theirs; formal verification of the receiver's
    adjacency and closure rules is the next step the field is moving to.
19. **Separation of pinned surfaces.** The StarkWare-parity circuit surface
    is pinned (`circuit-starkware-pin`); the same discipline applies to the
    RV64 receiver key and registries once fixed.

## 4. Phases and what each buys

| Phase | Work | Expected per-block result | Milestone |
| --- | --- | --- | --- |
| A (CPU, now) | Tier 1 items 1, 2, 4; Tier 5 items 16, 17 | 36 batches at 5 to 7 s each on the M5 Max; recursion ready | the architecture is final |
| B (GPU) | Tier 3 items 8, 9, 10; Tier 1 item 3 | 0.3 to 0.6 s per batch per 5090; four 5090s 8 to 12 s p50 end to end | within 2x of Zisk on the same four GPUs |
| C (proof system) | Tier 2 items 5, 6, 7; Tier 4 items 11 to 13 | about 2x less GPU work per cell; one or two GPUs under 10 s p99 | Airbender Prime class |
| D (settlement) | Tier 4 item 14; Tier 5 items 15, 18 | published 7,200-block receipts and L1 proofs | listed on EthProofs |

Phases A and B are engineering with designs in hand. Phase C is the one
place where the field's frontier moved past the current proof system; it is
a new prover lane, and the AIRs, memory argument, delegations and recursion
built in A and B carry over unchanged.

## 5. Sources for the frontier figures

Vendor announcements and secondary coverage, as of 2026-10-31; verify on
ethproofs.org before external use.

- ZKsync Airbender Prime announcement coverage: single RTX PRO 6000, 99% of
  7,200 blocks under 10 s, GKR sumcheck and WHIR, Keccak-256 L1 commitments.
- ZisK v1.1.0-alpha coverage: p99 9.62 s on four RTX 5090; EthProofs
  November 2025 listing at 24 RTX 5090.
