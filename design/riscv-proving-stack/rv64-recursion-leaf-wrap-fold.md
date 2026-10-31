# RV64 recursion: leaf wrap, fold, root

Status: implemented and exercised on two real Ethereum batches
(2026-10-31, branch `codex/rv64-guest-secp-lean`). This document is the
reasoning behind the design, what was built, the measured shape and time
of the first leaves, and the path to a block-scale root. It supersedes the
aggregation sketch in `rv64-aggregation.md`, which assumed a Poseidon2
Merkle switch that is neither available in-circuit nor necessary.

## 1. The problem as found

A block is 36 batch proofs of 2^22 - 1 retirements each. Every batch proof
is a native `stwo_7b211ed` proof: Blake2s channel, domain-prefixed lifted
Blake2s Merkle trees, 4 trees (fixed, main, interaction, composition) all
at height 23, FRI with fold step 1 (22 layers), 70 queries, 26-bit PoW,
composition split 2 (16 columns), and about 15 lookup relations each with
its own tagged challenge draw and its claim closed by the receiver outside
the AIR. The batch receiver chains batches natively (pc, registers, RAM
root, call ids).

The repository's recursion stage for Starknet is a circuit lane: an M31
circuit builder, an 11-component circuit AIR, a circuit prover on CPU,
Metal and CUDA, an in-circuit STARK verifier (`stark_verifier/`), a
multiverifier that folds two child circuit proofs, a registry of fixed
shapes, a topology cache and a tree driver. That in-circuit verifier is
hard-wired to the `proving@5a7c5ed` protocol: Blake2s-M31 channel, plain
Merkle, fold step 4, one lookup pair, pair-batched cumulative-sum LogUp
with claimed sums, 8 composition columns, all trees at one lifting height.
Neither side bends with a flag.

## 2. Decision: verify the native protocol in-circuit

Two routes were open.

- Re-target the batch prover to the circuit protocol. Every relation would
  move to the standard cumulative-sum layout under one challenge pair, the
  composition split would drop to 1 (degree 3, so Word16 only), claims
  would become u32 groups, and the transcript would adopt lifting heights.
  Recursion would then wait on the Word16 rewrite and re-qualification of
  all sixteen components.
- Write an in-circuit verifier for the native protocol family on the same
  builder, reusing the builder gadgets, prover, fold tree and registry.

The second was chosen. It wraps today's proofs unchanged, it is a sibling
of the existing verifier rather than a fork of it, and its protocol knobs
(hasher prefix, fold step, tree heights, composition split) are parameters
of a `Shape`, so the later protocol tightening is a shape change rather than
a rewrite. The leaf pads to the production registry's shared target, so the
fold tree, canonical multiverifier, topology cache and the Metal and CUDA
circuit provers are reused as they are.

## 3. What was built

### 3.1 In-circuit native verifier (`src/frontends/circuit/native_verifier/`)

`verify(V, ctx, shape, proof_wires, statement)` replays the native
transcript: the statement mixes its public words, the first two roots are
mixed, the statement draws its challenges and mixes its claims, the
interaction root, composition randomness, composition root, OODS seed and
point, the statement's composition value against the reconstructed
composition sample (split per shape), all sampled values, DEEP randomness,
FRI roots and alphas, PoW, the query draw, Merkle decommitments, DEEP
quotients and the FRI decommitment. Prefixed hashes start from the constant
chaining state after the 64-byte domain prefix, so a prefixed node costs
one compression. The fixed-width witness is converted from the native
verifier's proof capture (per raw query paths, cosets and answers).
Parity tests: identical final digest, challenges, OODS point, FRI alphas,
query positions and DEEP answers on a real proof; each single flipped value
invalidates the circuit; topology is value-independent. 154 tests.

### 3.2 Lane-generic constraint evaluation (RV64 frontend and integration)

Every component of a batch roster evaluates its constraints at a point over
an external lane `F` (`air/lane.zig` contract: QM31-shaped, with
challenges, claims and public scalars supplied as lane values through flat
layouts in draw order, mix order and a documented publics order). The
circuit lane (`rv64_recursion/circuit_lane.zig`) is a wire with a bound
context, so the leaf's constraint set is the batch's own constraint code,
not a transcription. `rv64_point_evaluation.zig` reproduces
`evalCompositionPolynomialAtPoint` over the roster and describes the proof
shape (column logs, mask offsets, global log, split).

### 3.3 Leaf statement (`src/integrations/riscv_cpu/rv64_recursion/`)

- `transcript_walk.zig` is the single definition of the public words,
  tagged draws and claim felts, driven through a sink. The native replay
  sink proves parity against the real receiver (both batches: 255 free
  words, 269 challenge draws, 97 claim felts, equal digests at every phase).
  The circuit sink makes layout words constants and free words guessed
  wires; registers and pcs are guessed as bytes and range-checked.
- `closure.zig` is the receiver's claim closure over wires: omitted rosters
  are zero, the RAM Poseidon, policy and graph sums close (with the two node
  tuples of the before and after roots), and the state effect equals the
  boundary target of the public registers under the state challenges.
- The eight circuit outputs are Blake2s of the free words, so a leaf's
  output digest commits to its public statement and nothing else.
- `leaf_wrap.zig` verifies natively with capture, builds, pads to the shared
  target, proves with the circuit prover and serializes; `fold_root.zig`
  folds with the existing tree and verifies a root: root circuit proof,
  packed-tree digest recomputation, every leaf's circuit hash, every leaf
  digest against its revealed statement words, and the batch chain
  adjacency from the independently derived initial state to the final pc.
- Tool `rv64-recursion` with `check-transcript`, `wrap`, `fold`,
  `verify-root`; tests `test-riscv64-recursion` and
  `test-riscv64-recursion-circuit`.

## 4. Measured, batch 0 of block 24,628,607 (4,194,303 steps, no services)

| Quantity | Value |
| --- | ---: |
| Native verify with capture | 20 ms |
| Circuit build (verifier + constraints + closure + digest) | 268 ms |
| Pad to shared target | 419 ms |
| Preprocess | 366 ms |
| Prove, CPU, ReleaseSafe | 10.3 s |
| Raw gates: blake_g | 3,082,960 |
| Raw gates: qm31_ops | 1,841,020 |
| Raw gates: m31_to_u32 | 544,512 |
| Raw gates: triple_xor | 308,296 |
| Raw gates: eq | 19,275 |
| Padded witness | 45,088,768 variables |
| Leaf proof | 545,896 bytes |

The raw leaf is about 37 percent of the production target (blake_g 2^23,
qm31_ops 2^23), so it pads to the same shape as a Starknet leaf wrap and
proves in the same time. A service batch (batch 3 of the four-batch run,
with Keccak and secp rosters, 3.7 MB batch proof) roughly doubles the raw
leaf (blake_g 6,344,480, qm31_ops 4,955,445, m31_to_u32 1,197,618) and still
fits the same target; its wrap took the same 9.1 s.

### 4.1 Two batches to a root (ReleaseFast, CPU, M5 Max)

| Stage | Wall | Peak RSS |
| --- | ---: | ---: |
| Wrap batch 1 (prove 7.3 s) | 9.6 s | 15.1 GB |
| Fold 2 leaves, 1 reduction | 10.0 s | 13.8 GB |
| Root receiver (root proof 1.5 s, chain 1.7 s) | 3.7 s | 3.3 GB |

Root receiver output: proof verified, 2 leaf digests recomputed, 2
statements chained to pc 0x13c3fc after 8,388,606 steps (the batch
driver's final pc). Tamper checks, each rejected with its own error: a
statement word of leaf 1 flipped (`LeafStatementWordsMismatch`), one byte of
the root proof flipped (`RootProofRejected`), the two leaf files swapped
(`LeafCircuitHashMismatch`).

### 4.2 Four batches to a root, two parallel reductions

| Stage | Wall | Peak RSS |
| --- | ---: | ---: |
| Wrap batches 0-3, serial (prove 8.7 / 9.5 / 9.0 / 9.1 s) | 41.9 s | 15.1 GB |
| Fold 4 leaves, 3 reductions over 2 layers, 2 jobs | 24.7 s | 24.3 GB |
| Root receiver | 3.3 s | 3.3 GB |

Root receiver output: proof verified, 4 leaf digests recomputed, 4
statements chained to pc 0x20e3c4 after 16,777,212 steps. With two jobs
the first layer's two reductions ran concurrently (about 12 s for the pair
against 10 s for one alone), then the root reduction. Root proofs are
545,896 bytes regardless of leaf count, and the root receiver's cost is
independent of the block size except for the native chain walk.

## 5. Where the leaf's cost comes from, and the knobs

Per batch, in Blake2s compressions (each is 80 G gates):

| Source | Compressions | Why |
| --- | ---: | --- |
| FRI, 22 layers, fold step 1 | ~20,800 | two leaves and a path of depth 22 - i per layer per query |
| Trace leaves, 1933 columns | ~8,800 | 70 queries x (8 + 76 + 39 + 2) column blocks |
| Trace paths, 4 trees x 23 | ~6,400 | one compression per prefixed node |
| Channel, statement, claims | ~2,000 | |

Three protocol-level changes, each a shape parameter of the new verifier:

1. Fold step 4 in the batch FRI config: 6 layers instead of 22, cosets of
   16 packed four per leaf; FRI falls to roughly 6,000 compressions.
2. Plain lifted hasher (`Blake2sPlainMerkleHasher`): removes the constant
   prefix block; no in-circuit saving beyond one interned constant, but it
   aligns the batch protocol with the circuit lane for a later merge.
3. Word16 columns (`rv64-word16-cpu-2n.md`): 1933 to about 700 columns per
   leaf hash, trace leaves fall to about 3,200 compressions.

Together the leaf drops to roughly 12,000 compressions, below 2^20 G gates,
small enough for a dedicated RV64 registry target with a cheaper
multiverifier fixpoint than the production one.

## 6. Parallelism and the block-scale schedule

- Wraps are independent: each needs one batch proof and the ELF authority.
  They start as batches finish and run on any device; a wrap is one
  canonical-shape circuit proof.
- Folds pair adjacent leaves left to right with the odd one carried up; the
  tree driver already runs sibling reductions concurrently and the Metal and
  CUDA provers plug in through `Fold.provers`.
- For 36 batches the tree has depth 6. The critical path after the last
  batch proof is one wrap plus six folds. With the resident CUDA circuit
  prover at under one second per canonical proof on an RTX 6000 Pro (as
  measured by the team), the recursion stage adds well under ten seconds of
  wall time and a few GPU-seconds of total work; it is not on the
  real-time critical path once batch proving is.
- The root receiver is native and cheap: one circuit proof verification,
  a digest recomputation over 36 leaves, and the existing chain adjacency.

## 7. Separation from the StarkWare-parity circuits

The Starknet pipeline's circuits are pinned to `proving@5a7c5ed` byte for
byte, and nothing RV64 does may move them. The boundary is enforced three
ways:

- The native-protocol verifier is a sibling module (`native_verifier/`)
  with its own copies of the FRI folding helpers (`fold_helpers.zig`); it
  imports the pinned verifier's circle and query gadgets read-only and
  changes nothing under `stark_verifier/`, `statements/`, `air_eval/`,
  `common/` or `builder/`.
- Any RV64-specific fold statement, registry target or evaluator goes in a
  new module or a new registry file, never in `multiverifier.zig`,
  `canonical.zig` or the committed registries. Until then the RV64 leaf
  pads to the production target and the production multiverifier folds it
  unchanged.
- `zig build circuit-starkware-pin` (first rung of `circuit-parity-local`)
  checks one SHA-256 over the whole pinned surface against
  `vectors/circuit/official/starkware_surface_pin.txt`. A StarkWare-side
  change re-runs the parity ladder and updates the pin in the same commit;
  an accidental edit from another lane fails loudly.

## 8. Gates before this is production

1. A topology per layout. Component log sizes, rosters and RAM counts are
   circuit constants, so every distinct batch layout is a distinct leaf
   circuit hash. Fixed geometry per protocol version (already required by
   the Word16 and global-memory designs) collapses this to one hash per
   ELF class; until then the root receiver checks each leaf hash against
   the set of admitted layouts rather than a single value.
2. Promote the probe into tests: a leaf wrap of a committed small batch
   fixture, a two-leaf fold and root receipt, and the adversarial list
   (tampered proof byte, wrong public word, wrong claim, swapped leaf
   order, foreign leaf circuit hash, truncated packed tree).
3. In-circuit adjacency in the fold (a derived multiverifier statement that
   opens both children's statement words and checks pc, registers, RAM root
   and call-id continuity) once the public-word layout is frozen; today the
   root receiver does it natively from the revealed preimages.
4. Device wraps: route `leaf_wrap` through `circuit_metal.provers` and the
   CUDA resident source as the Cairo lane does; nothing in the leaf is
   CPU-specific.
