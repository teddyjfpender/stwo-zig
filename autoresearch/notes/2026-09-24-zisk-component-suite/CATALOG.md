# ZisK comparison inventory

This is the function-family inventory for the shared RISC-V/CSP and recursive-STARK
critical path. It is not a claim that every ZisK utility, guest syscall, elliptic
curve, or end-to-end proof has been timed. **The full campaign is not complete.**

Sources pinned to ZisK `5c5f81c96929abed88894473ec6060b1b545b5c5` and its inspected
Proofman checkout `d485fac207679076958b502554fb595568c2f954`. Source names below are
relative to those repositories. `GL` means Goldilocks, `Q` means QM31.

| Family / peer entry points | Local counterpart / measurement boundary | Status |
|---|---|---|
| `pil2-stark/src/goldilocks/src/blake3_core.hpp`: `hash_le64`, `Hasher::absorb`, `finalize_xof`, `permute8` | std BLAKE3 with the same canonical-word encoding and XOF output | Measured: chunk edges, short/long messages; exact parity |
| same: `compress_xof` | `core/crypto/blake3_compression.compress` | Measured: identical full compression outputs |
| ZisK `precompiles/helpers/src/blake3/blake3f`: `blake3_f` | same local compression; adapter supplies identical initialization/feed-forward | Measured: actual Rust guest helper; exact parity |
| `blake3_goldilocks.cpp`: `linearHash`, `permuteTrunc` | `vcs_lifted/blake3_merkle` leaf and node authors | Measured: different native framing; equal payload byte counts |
| same: `merkletree` | research tree loop over std BLAKE3 using **ZisK's** protocol | Measured: identical full roots; 1K/16K/256K leaves, 64/512-byte leaves |
| same: `merkletreeReduce`; `MerkleTreeGL::merkelize`, `getGroupProof`, root verification | production tiled commitments, decommitment paths, verifier | Reduction is exercised by tree build; production wrapper/opening/verification timings still required |
| `TranscriptGL::put`, `getField` | native BLAKE3 `Channel.mixU32s`, `drawSecureFelt` | Measured in four separately labelled battery cases; AC repeat outstanding. Different protocols |
| `TranscriptGL::getState`, `getPermutations` | native transcript state/query sampling | Inventory only; not covered by `getField` timing |
| `Blake3Goldilocks::grinding`, `permute8` nonce loop | production four-lane `blake3_pow_batch.firstWords` and scalar nonce verifier | Measured fixed-candidate throughput on battery; minimum-nonce and scalar/batch qualifications passed. AC repeat outstanding. Candidate protocol/output widths differ |
| `Goldilocks::{add,mul,inv}` | M31 equivalents | Measured; separate field oracles, dependent chains |
| `Goldilocks::batchInverse` | `fields.batchInverseInPlace(M31)` | Measured at 1K/16K/256K; different fields/representation/allocation |
| `Goldilocks3::{add,mul,inv}` | QM31 equivalents | Measured; independent polynomial/tower arithmetic oracle |
| `NTT_Goldilocks::{NTT,INTT}` | circle evaluate/interpolate with cached twiddles | Measured at 2^10/14/18; exact round trips per field |
| `NTT_Goldilocks::LDE` | interpolate, zero-pad, circle evaluate | Measured at the same sizes, 2x expansion; distinct domains. Peer LDE includes its internal extension-plan allocation |
| `FRI<GL>::fold` | `core.fri.foldLineInPlaceNWithWorkspace` (CPU backend's implementation), one fold | Measured at 2^10/14/18; constant-polynomial qualification; different fields/domains/normalization |
| `FRI::{merkelize,proveQueries,proveFRIQueries,verify_fold,setFinalPol}` | FRI commit, decommit, verifier | Full stage fixture still required; primitive fold/tree timings do not cover these |
| `gate_bands_blake3.hpp`: `expand_lane` | typed `blake3_compression_witness.prepare` | Measured diagnostic; outputs match but trace/routing/lookup/checksum work differs |
| same: `expand_boundary_columns`, `expand_one_lane`, `expand_block`; CPU `expand_all`, `write_multiplicities` | full framed-hash witness, final-layout columns, private lookup count/reduction | **Not yet separately timed**. Required to turn the diagnostic into a fair complete witness-stage comparison |
| ZisK `precompiles/blake3/src/blake3.rs`: `process_input`, `compute_witness` | guest hash precompile witness/proof | Generated PIL row types, tables, and a matched workload fixture required; helper timing is not this stage |
| ZisK core `tiny_keccak::keccakf` execution path | admitted `keccakf_authority.permute` | Measured; identical full 1600-bit outputs |
| ZisK core SHA2 0.10.9 dependency | std SHA256 whole-message hash | Measured at 64/1024/65536 bytes; host library workload only, not guest/precompile proof |
| ZisK `core/helpers.rs::sha256f` compression syscall | SHA-256 compression / guest execution path | Raw compression and proof-stage fixture remain; whole-hash timing above does not substitute |
| ZisK `precompiles/keccakf` witness/caches, bit-state helper, tables | paired sliced Keccak witness and compact lookup tables | Full witness and cache hit/miss fixture required; bit-state helper compiled but not reported as an execution comparison |
| ZisK `precompiles/helpers/src/arith_eq/secp256k1.rs`, `arith_eq` witness, `zisklib` ECDSA | admitted secp256k1/ECDSA guest precompile and CSP workload | Matching arithmetic/validation, point encoding, batch size and witness fixtures required; existing CSP number is not a peer comparison |
| `Starks::calculateImPolsExpressions`, `calculateQuotientPolynomial`; expression kernels | typed AIR evaluation, interaction construction, segmented quotient evaluation | Same constraint-operation fixture / generated evaluator required |
| `Starks::calculateFRIPolynomial` / `fri_expression` | PCS opening/DEEP quotient and combination | Matched degree/column/query fixture required; extension multiply/fold timings alone do not cover it |
| `Starks::{extendAndMerkelize,commitStage}`; packed/indexed trace decode | fused LDE/commit, column packing, residency plans | Complete layout/commit fixture required; separate transform/tree figures cannot be added to claim pipeline time |
| Proofman `recursion.rs::{gen_witness_recursive,gen_witness_aggregation,generate_recursive_proof,aggregate_worker_proofs}` | native typed verifier planning/emission, segmented recursive tree | Matched child proof/profile and generated recursion proving keys required |
| Proofman `generate_air_proof`, `generate_proof`, verify path | proof creation, encoding, independent verification | Full hash-AIR and recursion proof campaign still required |
| Proofman scheduler/thread tokens, scratch pools, worker proof queue | work pool, retained buffers, bounded witness/proof overlap | Concurrency/peak-memory/throughput experiment required; single-thread timings cannot establish this |
| NVIDIA CUDA hash/NTT/expression/FRI/trace kernels | Metal equivalents and CUDA backend | Cannot measure peer CUDA on this Apple host; requires a CUDA host and a separately labelled hardware comparison |

## Required next stage fixtures

1. Complete BLAKE3 witness pipeline: same compressions and flags, report interior,
   boundary, lookup counting/reduction, final column bytes, and peak allocation.
2. Hash-AIR proof: setup from `examples/hashes/README.md`, pin generated PIL,
   proving/verifying keys, blowup, queries, PoW and proof format. The peer checkout
   has no generated `examples/hashes/build/provingKey` in this campaign. Its
   example's BLAKE3 blowup is 4x; ours must not be called equivalent merely because
   both use BLAKE3. Measure verified proof creation, not witness-only work.
3. Matched AIR/DEEP/FRI/opening workloads, followed by complete recursion levels
   with 1/2/4/8 workers and memory residency. Record single-proof latency and steady
   throughput separately. A 90x scalar fold ratio is not a recursion speedup.
4. CSP SHA/Keccak/ECDSA proof workloads with agreed semantics and parameters.
   Run ZisK's optimized x86/CUDA implementations on supported hardware before
   drawing claims about their production throughput.

Poseidon prover internals are excluded from this BLAKE3 campaign. Retained guest
Poseidon semantics, BN254/BLS/bigint precompiles, SNARK wrapping, network/RPC,
serialization utilities and EVM/block execution are outside the immediate shared
CSP/recursion comparison; add them only for a named matching workload.


## Subsequent stage campaign

[2026-09-24-zisk-system-stages](../2026-09-24-zisk-system-stages/README.md)
now measures actual LDE plus production commitment APIs with explicit one-worker
controls and stage breakdowns; local complete Keccak witness/validation/counting;
and a complete independently verified local BLAKE3 Keccak proof at 70 queries,
26 PoW bits and 16 scoped workers. It retains the Keccak and framing improvements
and records the remaining narrow-commitment/small-transcript gaps. It does not yet
supply a peer full-proof or complete peer witness-stage comparison.
