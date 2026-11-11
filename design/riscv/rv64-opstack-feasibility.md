# RV64 frontend for the OP Stack in place of SP1: feasibility study

**Implementation update (2026-11-06):** the execution spike is now implemented in
[`opstack/`](../../opstack/README.md), with pinned historical OP Mainnet fixtures,
independent RV64/Unicorn checks and physical native CPU STARK production/fresh
reception for blocks 120794432 and 121057303. The Sepolia corpus remains a regression preset.
See [the implementation contract](rv64-opstack-implementation.md) and the dated
[mainnet benchmark report](../../vectors/reports/rv64-opstack-mainnet-20261106/README.md). The historical source census below remains pinned to Nov 4;
its original runtime estimates are superseded by measured results. L1 derivation,
physical OP GPU proofs and settlement are still open. Settlement stays pure
STARK, as the owner decided: no SNARK wrapping.


Date: 2026-11-04. Tags:
- **[verified-source]**: read in the code at the pinned SHA.
- **[measured]**: run here.
- **[estimate]**: my judgement.
- **[published]**: a vendor or documentation claim.

Pinned sources:
- **stwo-zig worktree:** `~/Coding/ge-wt/rv64-m4-integrate` @ `bcd401ce447af9f34b7461c11fd92a7b52e104f5`.
- **op-succinct:** @ `1e01cf0504c9306331641e37599cebe4e46fa635` (https://github.com/succinctlabs/op-succinct/tree/1e01cf0504c9306331641e37599cebe4e46fa635).
- **Kona and op-revm:** optimism tag `kona-client/v1.8.0`, commit `3c8b1aea1e738595fc2588693fa5aa9ba09f1dcd`. The shipped ELF was built from optimism checkout `a271fd6`.
- **op-rs/kona:** archived, @ `2586fc56ea0b0f17a8b47c44196012e33a321ea7`.
- **SP1:** `v6.10.0` @ `d83ed91f9670`.
- **sp1-contracts:** @ `d3629729c3216eb51bd4859d027a8eb729399fa4`.
- **optimism (ZKDisputeGame):** @ `507993910a36c153a3dad1ee0742a60687f1cd0f`.

Scratch work is in `/Users/theodorepender/Coding/ge-cache/rv64-opstack/{src,scratch,taskB,taskD}`. No GPU or pod was used. Nothing was proven or run on our RV64 executor. The only measurements are ELF disassembly and an instruction census.

---

## 1. Answer in three sentences

1. **Can we?** Yes. OP Succinct's range program already compiles to plain RV64IM, which is the instruction set we prove [measured]. Every gap is in the runtime and proof plumbing around it, so the right approach is to rebuild the Kona crates against our own guest interface and services, as we did with evmone, rather than emulate SP1.
2. **Current implementation.** A separate no_std Kona execution guest now runs real OP blocks on our RV64 executor, reusing constrained crypto services and retaining trie state across a range. Instruction counts and independent execution checks are measured; they do not establish a proof-time advantage over SP1.
3. **Remaining scope.** Complete Kona L1 derivation/KZG, bind derivation and execution in recursion, qualify physical GPU proofs and implement direct STARK settlement behind a vendor-neutral verifier adapter. No SNARK wrapper is part of this plan. The old engineering estimates below describe the original study, not a delivery commitment.

---

## 2. How OP Succinct uses SP1 and Kona today

### The range ELF
- **File:** `elf/range-elf-embedded`, sha256 `223b0bb8…69bc4`, 7.47 MB with 3.3 MB of `.text`. It has the same SHA that our `rv64/README.md:158-163` pins.
- **Format:**
  - ELF64 RISC-V, arch attribute `rv64i2p1_m2p0_zmmul1p0`.
  - Three LOAD segments at 0x78000000 (R / RX / RW); entry point 0x782a83f0.
  - Built with `rustc 1.96.0-dev` and LLD 22.1.2. [measured]
- **Instruction set** (`llvm-objdump --mattr=+m,+a,+c`):
  - 75 distinct mnemonics, all RV64IM, plus `fence` ×19, `ecall` ×40 and `unimp` ×82 (panic paths).
  - No compressed, atomic, floating-point or CSR instructions. [measured]
- **Build:** SP1 compiles for `riscv64im-succinct-zkvm-elf` with `-C passes=lower-atomic` (`crates/build/src/lib.rs:17-35`). [verified-source]
- **Fences:** all 19 are `0x0100000f` (`fence w,0`, fm=0). Our decoder admits FENCE when `f3==0 && word>>28==0` (`decode.zig:323`) and runs it as a no-op, so these pass. [measured + verified-source]

### What the range program does
The program is `programs/range/ethereum/src/main.rs` [verified-source]:
1. Starts with `sp1_zkvm::entrypoint!`, then `kona_proof::block_on`.
2. Reads one input with `io::read_vec()`: an rkyv-encoded `DefaultWitnessData { preimage_store: HashMap<PreimageKey, Vec<u8>>, blob_data }`.
3. Runs `check_preimages()`, which re-hashes every Keccak and SHA-256 key up front.
   - `Local` and `GlobalGeneric` keys are not checked. They are bound through the committed BootInfo.
   - `Precompile` keys are `unimplemented!`. Precompiles run inside the guest, not through the fault-proof VM's preimage oracle.
4. Checks blobs with `kzg_rs::verify_blob_kzg_proof_batch`.
5. Kona's `OraclePipeline` and `Driver` derive L2 blocks from L1 data. That data covers receipts, batches, brotli/zlib channels and span batches. The blocks are then executed with op-revm (`revm 42.0.1`) over a lazily loaded `TrieDB`.
6. Commits `BootInfoStruct { l1Head, l2PreRoot, l2PostRoot, l2BlockNumber, rollupConfigHash = sha256(serde_json-pretty RollupConfig) }`. The runtime hashes the public values with SHA-256, and eight COMMIT calls write the digest.

**Why we can't reuse the stock Kona fault-proof binary.** The Asterisc `kona-client` targets `riscv64imac`. It uses Linux-style read/write/mmap/exit system calls and sends precompiles to the host oracle. What we would reuse is the Kona *crates* (`kona-proof`, `-driver`, `-derive`, `-mpt`, `-executor`), which are `no_std + alloc`. [verified-source]

### SP1 system calls the range ELF uses
I read these from the `t0` value at each `ecall` site [measured]:

| Group | Calls |
|---|---|
| Control | HALT, WRITE |
| Unconstrained mode | ENTER_UNCONSTRAINED / EXIT_UNCONSTRAINED (10 call sites, all inverse/square-root hints) |
| Output | COMMIT ×8, COMMIT_DEFERRED_PROOFS ×8 |
| Input | HINT_LEN, HINT_READ |
| Hashing | SHA_EXTEND, SHA_COMPRESS, KECCAK_PERMUTE |
| secp256k1 / secp256r1 | SECP256K1_ADD/DOUBLE, SECP256R1_ADD/DOUBLE |
| BN254 | Fp add/sub/mul, Fp2 mul |
| BLS12-381 | ADD/DOUBLE, Fp add/sub/mul, Fp2 mul |
| Big integer | UINT256_MULMOD |

- The aggregation ELF also uses VERIFY_SP1_PROOF.
- Crypto acceleration comes from SP1's patched forks ("sp1-patches") of sha2, sha3/tiny-keccak, k256, p256 and substrate-bn, plus kzg-rs → `sp1_bls12_381`.
- EIP-2537 BLS (ark-bls12-381), modexp and ripemd are *unpatched*: they run in software on SP1 too. [verified-source: Cargo.toml:237-261, Cargo.lock]

### Aggregation and L1 settlement
- **Aggregation program** (`programs/aggregation/src/main.rs:18-100`) [verified-source]:
  - Chains the BootInfos: `postRoot[i] == preRoot[i+1]`, with the same `rollupConfigHash` throughout.
  - For each range, calls `verify_sp1_proof(multi_block_vkey, sha256(bincode(boot_info)))`, which is a deferred proof.
  - Walks the L1 header chain with Keccak back from `latest_l1_checkpoint_head`, covering every `l1Head`.
  - Commits ABI-encoded `AggregationOutputs`, including `multiBlockVKey` and `proverAddress`.
- **Proof modes:** range proofs are Compressed; the aggregation proof is Plonk or Groth16.
- **On-chain verification:**
  - `OPSuccinctL2OutputOracle.sol:403` calls `ISP1Verifier(verifier).verifyProof(aggregationVkey, abi.encode(publicValues), proof)`. The owner can swap `verifier`.
  - `OPSuccinctFaultDisputeGame` stores the verifier and vkeys as immutables, so changing them means deploying a new game implementation.
  - The Optimism monorepo now ships a generic `ZKDisputeGame` that calls `IZKVerifier.verify(programId, publicValues, proof)`. Its doc comment names "SP1, Risc0, etc." as implementers, and the only adapter today is `SP1PlonkAdapter`.
  - The matching guests (`rust/kona/sp1/programs/{super-range,super-aggregation,log-commitment}`) are marked experimental. [verified-source @`50799391`]

### Published SP1 costs
These are SP1 RV32IM figures from Dec 2024. No breakdown has been published for the current Hypercube prover. [published]

**World Chain, 101 blocks** (`book/quick-start/cost-estimator.md` @ `op-succinct-v1.0.0-rc1` `f28db3cf`):

| Item | Cycles per gas | Million cycles per L2 block |
|---|---:|---:|
| Total | 36.1 | |
| Execution | 28.3 | |
| — BN254 (World ID Groth16) | 18.0 | |
| — execution without precompiles | ≈10.1 | |
| Derivation | | 24.0 |
| Oracle checks | | 15.5 |
| Blob / KZG checks | | 6.7 |

**Other figures:**
- OP Sepolia sample: about 21 cycles per gas.
- Launch post (https://blog.succinct.xyz/op-succinct/): 62¢ per Base block, 21¢ per OP Mainnet block.
- Mantle claims "as low as $0.002/tx" (https://blog.succinct.xyz/mantle/).

---

## 3. Gap table

| Component | SP1 / OP Succinct | Ours (`bcd401ce4`) | Work | Effort [estimate] | Risk |
|---|---|---|---|---|---|
| **Instruction set** | RV64IM, atomics lowered | RV64IM with 63 variants; FENCE (fm=0) is a no-op; a Zbb subset in reserve | none | 0 | Low [measured on the ELF] |
| **Toolchain / build target** | `riscv64im-succinct-zkvm-elf`, std-capable | `riscv64i-stwo.json`, `+m,+forced-atomics`, no_std | Port op-succinct's glue code (std HashMap, Arc, println) to hashbrown/no_std or add a std shim; make the ELF reproducible | 3–5 d | Low |
| **Entry point, allocator, I/O** | SP1 `entrypoint!`, embedded allocator, HINT_LEN/READ, WRITE, HALT | `__input_start` window, `__output_data`, `__output_len=43`, `__halt_flag` | Replace `sp1_zkvm::io` with our interface; use a bump allocator | 1 wk | Low |
| **Running the stock SP1 ELF unchanged** | native | none (`profile.sp1_abi_supported=false`) | Dispatch on `t0`, write results back to registers, provable HINT_READ, two-pointer argument packets, unconstrained execution with rollback, all in the AIR | 2–4 mo | **Not recommended** |
| **Private witness input** | hint stream, never public | The input SHA-256 is in the work-packet header, and the verifier rebuilds memory from public bytes (`rv64_work_packet_header.zig:80-103`, `expected_image.zig:20-30`) | Committed-input mode: initial memory becomes a prover commitment; change the memory-root and initial-image AIRs; soundness review | 4–6 wk | **High** (changes what the proof states) |
| **Memory and witness size** | 2^48 address space | 256 MiB mapped, 16 MiB input cap, `MAX_LEAVES=65536*8`, `MAX_REGIONS=256` | Either cap ranges at 5–30 blocks, or raise the limits and requalify the memory AIR and continuations at 10–100× | 1–3 wk / 4–8 wk | **High** |
| **Keccak** | KECCAK_PERMUTE | Keccak-f and sponge services, plus a `native-keccak` hook | reuse | ~0 | Low |
| **SHA-256** | extend + compress | compress service, `vendor/sha2-rv64` | reuse | ~0 | Low |
| **ecrecover (k256 0.13.4)** | secp256k1 add/double + hooks | `vendor/k256` patched onto our service (GLV) | reuse | ~0 | Low |
| **BN254 precompiles (0x06–0x08)** | Fp/Fp2 calls via substrate-bn | G1 add/double, Fp2 mul and 256-bit modular arithmetic, connected only through C++ glue | Patch `substrate-bn 0.6` onto our services | 2–4 wk | Medium (World Chain is the stress case) |
| **BLS12-381 / KZG** (blob check, precompile 0x0a) | `sp1_bls12_381` calls | G1 add/double, Fp2 mul and 384-bit Montgomery multiply (`arith384_mont`); C++ glue only; no G2, Fp6 or Fp12 in Rust | Patch kzg-rs; implement the 4096-point evaluation, batch inversion and 2-pairing check; differential tests | 4–7 wk | Medium–High (runs per blob) |
| **EIP-2537 BLS** (Isthmus+) | unpatched | software | none at first | 0 | Same cost cliff as SP1 |
| **P256VERIFY** (RIP-7212) | secp256r1 add/double | **none** [verified-source, grep] | Software over 256-bit modular arithmetic, or a new AIR | 3 d–3 wk | Low while usage is rare |
| **modexp, ripemd, blake2f, brotli** | software / UINT256 | arith256_mod + software | revm modexp hook; profile brotli | 3–5 d | Low |
| **Inverse / square-root hints** | unconstrained mode | none | Hint-then-check service | 1–2 wk | Medium (an unchecked hint is a forgery vector) |
| **Public output** | COMMIT of sha256(BootInfo) | fixed 43 bytes (`terminal_air.zig:10`) | Put the BootInfo digest in the 32-byte root slot; define the 253-bit mask rule | 1–2 d | Low |
| **Continuations / recursion** | SP1 shards + recursion | `rv64_recursion/` folds 17 leaves into a 708 KB root; verification takes 61.9 s and 7.2 GB [measured]. README:15 still says "no continuation, recursive composition" | Fix the README; test at Kona range sizes | 2–4 wk | Medium |
| **Proof aggregation in the guest** (`verify_sp1_proof`) | VERIFY_SP1_PROOF | none [verified-source] | Add a deferred-statement mechanism plus OP aggregation logic | 5–9 wk | Medium |
| **Program identity (vkeys)** | SP1 vkey format | the fold hashes identity and fixed roots | `programId = H(domain, ELF commitment, recursion VK root)` | 1–2 wk | Low |
| **Fixed-key root proof** | constant-VK recursion | The verifier rebuilds child authorities and checks adjacency/coverage off-circuit (`om31_outer.zig:1-16`) | Move those checks into the circuit | 3–6 wk | Medium–High |
| **Proof verifiable on L1** | Groth16 ~270k gas, PLONK ~300k gas | direct STARK settlement remains open | STARK compression + EVM-friendly final hash profile + Solidity STARK verifier/adapters; no SNARK wrap | requires new estimate | **Highest** |
| **Host / proposer** | `sp1_sdk`, `ProofProvider` | none | `ProofProvider::StwoZig`, input conversion, range sizing for our limits | 3–6 wk | Low–Medium |
| **Security level** | ~100-bit, conjectured | 96-bit nominal, not composed-proven (`rv64-composed-security-analysis-20261102.md:15`) | Composed soundness analysis | weeks + review | High for L1 |

---

## 4. Guest cost

### Our measured baselines [in-repo reports]

| Guest | Instructions per gas |
|---|---:|
| Rust revm guest | 13.88 → 13.18 |
| evmone v2 | 7.14 |
| evmone v3 | **3.130** (31,667 bits/gas) |

- evmone's interpreter costs about 1.8 instructions per gas, against revm's 4.8.
- Where the revm guest spends its time: interpreter 36%, allocator 18%, Merkle-Patricia trie and RLP 18%, secp glue 11%, SHA 11%, Keccak glue 4%.

### Projected cost of Kona on our RV64 [estimate]
Assumption: one SP1 cycle ≈ one of our instructions, ±30%.

| Configuration | Execution, instr/gas | Fixed cost per L2 block | Base-like block (24 Mgas) | OP Mainnet-like block (5.7 Mgas) |
|---|---:|---:|---:|---:|
| P0: Kona as-is, crypto on our services | 10–13 | 40–60 M | **12–15/gas (~290–360 M instructions)** | 18–23/gas |
| P1: lean Rust (zero-copy, decode trie nodes once, bump allocator) | 8–10 | 20–30 M | 9–11/gas | 12–15/gas |
| P2: evmone with OP rules + slim Rust derivation | 3.1–3.6 | 10–15 M (20–40 M for short ranges) | **3.6–4.2/gas (~96 M instructions)** | 5–6/gas (~31 M instructions) |

The "fixed cost per L2 block" column covers derivation, oracle and blob checks, i.e. work that doesn't scale with gas. Brotli/zlib channel decoding has no service and probably costs 15–30 M instructions per Base block, so profile it first.

### Optimisation levers, following the evmone campaign
1. **Execution client: evmone with OP rules.** This is the biggest lever, about 2.5–3× on execution. It needs:
   - deposit transactions (type 0x7E);
   - the L1 data fee, including a FastLZ estimate per transaction;
   - the operator fee;
   - the OP-specific receipt fields and Isthmus withdrawals root;
   - P256VERIFY and the Granite and Isthmus precompile limits.

   The catch: this is a permanent fork of OP execution rules. It takes 6–10 wk, plus a differential test harness over ≥10⁵ blocks, plus about 0.3 FTE per hardfork.
2. **Lean Kona:**
   - a zero-copy trie node table that hashes each node once (our `witness_trie.cpp` gave −40% on trie work);
   - stop cloning a Vec on every `oracle.get()` (`chain_provider.rs:171-187`);
   - use a bump allocator.
3. **Crypto delegation onto existing services.** KZG maps to the BLS services; P-256 can run over 256-bit modular arithmetic.
4. **Split derivation from execution into separate proofs.** This parallelises proving, but the binding fix from advisory GHSA-5jh4-3p33-85xc has to survive the split.
5. **Not worth doing:** zero-parse layouts (≤4–6% gain) and memoising Keccak results.

**Recommendation:** stop at P1 (unforked op-revm, about 8–11 instructions per gas) until a customer pays for P2.

### Implied proving time per L2 block on 2× RTX 5090 [estimate, ±50% because the instruction mix differs from L1 blocks]
- **Today:** 1.09–1.5 s per million instructions [measured on L1 blocks].
- **After the 10x plan:** 0.12 s per million instructions as the target, with a realistic band of 0.073–0.107.

| Configuration | Today | 10x target | 10x realistic band |
|---|---:|---:|---:|
| P2, Base-like (96 M instructions) | ~105 s | ~11.5 s | 7–10 s |
| P1, Base-like (~240 M) | ~260 s | ~29 s | 18–26 s |
| P0, Base-like (~325 M) | ~355 s | ~39 s | 24–35 s |
| P2, OP Mainnet-like (~31 M) | ~34 s | ~3.8 s | ~6 s floor, so batch blocks |

**Throughput needed to keep up:**
- **Base:** at 12 Mgas/s (the Dec-2024 rate; re-check, it is higher now) and 4 instructions per gas, Base needs about 48 M instructions/s. That is about 4–6 nodes after the 10x plan, versus about 50 nodes today.
- **OP Mainnet:** 1–2 nodes after the 10x plan.

### Compared with SP1
- **Instructions:** P2 would run about 2.5–3.5× fewer instructions per gas than SP1's Dec-2024 figures, and probably 1.5–2.5× fewer than current Hypercube. P1 is roughly at parity.
- **What that doesn't show:** instruction counts are not proof cost. There is no like-for-like cost-per-gas comparison against Hypercube yet, so we should claim nothing on cost until the spike and a matched-hardware comparison exist.

---

## 5. Settlement path

> **Owner decision (2026-11-04): no SNARK wrap.** The OP Stack path stays pure Stwo STARK. The final proof is the 10x plan's M7 two-stage compressed proof (≤100 KB target), with an EVM-friendly (Keccak) last layer as a new named STARK profile and the M5 constant recursion VK. It is verified directly by a Solidity Circle-STARK verifier behind `IZKVerifier` / `ISP1Verifier`-shaped adapters. Options A and B below (BN254 PLONK/Groth16 wraps) are superseded. Option C is the chosen route; the calldata figures quoted for C are for today's 708 KB proof, not the compressed one. The P3 checklist on PR #322 is authoritative.


| Option | How | L1 cost | Verdict |
|---|---|---|---|
| **A. Shrink + PLONK/Groth16 over BN254** (the pattern SP1, RISC Zero and OpenVM use) | Fixed-key root → one more recursion layer using a BN254-friendly hash (Poseidon2) → a gnark PLONK circuit exposing `programId` and `sha256(pv)&(2^253−1)` | ~270–300k gas | **Recommended** |
| B. Wrap the current Blake2s root directly in gnark | Use HerodotusDev/stwo-gnark-verifier @`dd44a6f6` as a reference (unaudited, test fixture uses 1 query) | ~10⁹ constraints | Reuse its gadgets only |
| C. Solidity Circle STARK verifier | Port the verifier directly | 11–28 M gas for calldata alone | Not competitive |
| D. Cairo → Stone → SHARP | Settle through StarkWare's verifier | ~5.8 M gas | Starknet only, not OP |

**Where to plug in:**
- **Primary target:** OP's `ZKDisputeGame`, through our own `IZKVerifier` adapter. Registering it is a per-chain governance action.
- **Easier first customer:** op-succinct's L2 output oracle, through an `ISP1Verifier`-shaped contract set via `updateVerifier`. Don't go through Succinct's gateway.
- **Trusted setup:** PLONK on the Aztec Ignition setup, so no ceremony is needed.
- **Choose one statement up front.** op-succinct's BootInfo and OP's super-root programs are different statements, and targeting one then switching means designing twice.
- **Effort:** 8–12 engineer-months plus audit [estimate].
- **Licences:** everything involved is MIT or Apache.
- **Competition:**
  - Optimism named Succinct its preferred provider in Feb 2026, but `IZKVerifier` is open to multiple vendors.
  - RISC Zero's Kailua is archived.
  - I found no public ZisK, OpenVM or Pico OP integration.

---

## 6. Phased plan with gates

**P0: Kona range program running on our emulator, with instruction counts.** CPU only, under memguard; 3–4 wk.
- **Steps:**
  1. Build the Kona crates plus op-succinct's range glue for `riscv64i-stwo.json`, behind a no_std shim, with our I/O interface and a bump allocator. Start with software crypto, then switch in our hooks.
  2. Generate witnesses with op-succinct's host.
  3. Run 1, 5 and 30 Base blocks, plus 5 World Chain blocks.
- **Deliverables:**
  - BootInfo byte-identical to native Kona;
  - instructions per gas broken down by bucket;
  - peak memory;
  - witness bytes per L2 block and per L1 origin block.
- **Kill or defer if any of these holds:**
  - more than ~20 instructions per gas on Base;
  - KZG plus derivation fixed cost above ~60 M per L2 block at 30-block ranges;
  - a 30-block witness above ~128 MiB.

**P1: native proofs of one L2 block range.** 3–5 mo.
- **Work:**
  - committed private-input mode, including review;
  - memory/continuation requalification, or a short-range policy;
  - crypto wiring: BN254, BLS/KZG pairing, P-256, checked hints;
  - lean-Rust optimisations;
  - BootInfo digest in the root slot;
  - fix the stale README.
- **Gate:** a verified native proof of a real 5–30-block range, and projected cost per Mgas at least 1.5× below Hypercube.

**P2: aggregation and statement binding.** 2–3 mo.
- **Work:**
  - deferred-statement mechanism;
  - aggregation guest: BootInfo chaining, config hash, L1 header walk, `proverAddress`;
  - `programId` scheme;
  - fixed-key root;
  - proposer adapter.
- **Gate:** a root proof that verifies from public values and a constant verifying key alone, plus a passed design review.

**P3: pure-STARK compression and on-chain verification.** Replaces the original wrap proposal; requires a new estimate and audit.
- **Work:**
  - two-stage STARK compression and a named EVM-friendly final hash profile;
  - direct Solidity Circle-STARK verification;
  - Solidity adapters with Foundry tests;
  - composed soundness case;
  - external audit.
- **Gate:** independent acceptance of the compressed STARK and on-chain verification with measured gas, calldata and composed soundness. No SNARK wrapper.

**Optional after P1, if a customer pays:** P2-level guest cost (evmone with OP rules) and the derivation/execution split.

**Original total estimate:** 18–26 engineer-months plus audit included the now-rejected wrapper and must be re-estimated for the selected pure-STARK route.

---

## 7. Risks and open questions

**Unmeasured basics (P0 answers these)**
1. Kona's instructions per gas on our machine are not measured; every cost figure above is extrapolated.
2. Witness size is not measured. It is likely hundreds of MB to over 1 GB at the default 1800-block range, against our 16 MiB input and 256 MiB address space.

**Scale and statement design**
3. **Scale.** A full 1800-block range is about 0.5 trillion instructions, roughly 2,500× our largest tested run (205 M instructions; verification already uses 7.2 GB). Short ranges avoid this but shift cost into aggregation and per-range derivation.
4. **Private input.** Adding private input changes the memory AIRs, so it needs the same soundness bar as any AIR change.

**Soundness**
5. **Open soundness items:**
   - `Local` and `GlobalGeneric` preimage keys are unchecked; each use must be bound by committed fields.
   - `rollupConfigHash` is computed over pretty-printed serde_json, a canonicalisation hazard.
   - Hint results must be checked in the guest.
   - The GHSA-5jh4 binding must survive any split.
   - Our 96-bit security level is nominal, not composed-proven.

**Maintenance**
6. **Maintenance forks:**
   - sp1-patches crates re-pointed at our services: about 0.25 FTE.
   - evmone with OP rules: about 0.3 FTE per hardfork, and a new class of consensus-divergence bugs.

**Statement and ecosystem**
7. **Moving target.** OP is shifting from BootInfo to super-root programs. Which one does the first customer need?
8. **Governance.** Succinct is the preferred provider, and each chain must register a new verifier through governance. Our realistic pitch is a second `verifierType` built on diversity and cost.

**Cost and docs**
9. **Cost transfer.** Our proving rate (s/M instructions) was measured on L1 evmone blocks, so it carries ±50% for Kona. No normalised comparison with Hypercube exists, and Base's gas rate needs re-checking.
10. **Stale docs.** `rv64/README.md:15` says there is no recursion, while `rv64_recursion/` produces 708 KB roots. Fix this before anyone relies on it externally.

**Already settled**
11. **Confirmed non-issues:**
    - The instruction set (RV64IM, no A/C/F) [measured].
    - All 19 fences are `fence w,0` and pass `decode.zig:323` [measured + verified-source].
    - revm 42, k256 0.13.4 and our Keccak/SHA services can be reused as-is [verified-source].
---

## 8. Frontier reference: ZisK proving OP Mainnet live (op.zisk.build), and what it changes for us

*Added 2026-11-05.* Source: the live dashboard [op.zisk.build](https://op.zisk.build/). Its data was read through the page's own `config.js` and `data.js` and the `api/v1/client` and `api/v1/query_range` endpoints it uses. A compact snapshot is committed at `vectors/reports/rv64-opstack-20261105/zisk-op-mainnet-snapshot.json`: 500 range proofs (≈83 min of chain) and 64 batches, captured 2026-11-05T13:41Z.

These are third-party live metrics that we read but did not reproduce, labelled **[M-ext]**. The page publishes no proof system parameters, security level, GPU kernel details or repository links, so anything about ZisK internals below that is not on the page is labelled **[inferred]**.

### 8.1 What it is

- **Chain:** OP Mainnet (`config.js`: `{"name": "OP Mainnet", "genesisL2Block": 105235063, "blockTime": 2}`), proven continuously, "every block as it is made".
- **Hardware:** **one host with 4 NVIDIA RTX 5090 workers** (`coordinator_workers_connected = 4`, cluster label `workers-1-4`, host `worker-1`) [M-ext]. That matches our 4-GPU standard.
- **The pipeline, in the page's own words.** "We prove the blocks in ranges as soon as they exist." The chain posts a batch to Ethereum every few minutes. "From the moment the batch is on Ethereum, the clock runs until its validity proof is done." Closing a batch is three jobs:
  - **Derive** ("proving the batch is exactly what [the chain] posted to Ethereum");
  - **Bind** ("tying the block proofs and the derivation into one proof");
  - **SNARK** ("wrapping it into the compact form Ethereum verifies cheaply").

  Range proofs are "aggregated as they come": folded range by range into one running proof of the batch.

### 8.2 Measured numbers [M-ext]

| Metric | Value |
|---|---|
| Execution range size | **5 L2 blocks** in every proof (10 s of chain) |
| Execution range proof time (`zc_recent_proof_prover_seconds`, n = 500) | min 2.70 s, **median 3.41 s**, p90 4.29 s, max 9.83 s |
| Transactions per 5-block range | min 73, **median 105**, p90 176, max 890 |
| Per-GPU phases of the last proof (10-min window, 4 workers) | phase 1 median 0.71 s (max 1.19); phase 2 median 2.19 s (max 3.40). All 4 GPUs work on each range. |
| Implied GPU duty cycle [D] | 3.41 s of proving per 10 s of chain, ≈ **34%**; the page says "the cluster has room to spare" |
| Blocks per L1 batch (n = 64) | min 16, **median 176**, p90 281, max 329 |
| Execution proofs per batch | median 36, p90 57, max 66 |
| **L1 batch timestamp → validity proof** | min 8.71 s, **median 10.38 s**, p90 11.76 s, max 19.0 s |
| Batch first seen by their node → validity proof | median 7.22 s, p90 7.45 s |
| Close-out steps, seconds (median / p90 / max) | **channel (derive) 2.83 / 3.02 / 3.57**; **final (bind) 2.44 / 2.48 / 2.56**; **wrap (SNARK) 1.71 / 1.72 / 1.74** |
| Queueing before each step (`step_waited_seconds`) | ≈0 (channel max 5.2 s once) |

So:
- The roughly 3 s gap between L1 inclusion and "seen" is L1 sync and download.
- The rest is a **fixed, batch-size-independent** close-out of about 7 s: derive, bind, wrap.
- Execution proving is entirely off the latency path.

### 8.3 What we take from it

1. **Prove execution apart from derivation.** This is the biggest structural lesson.
   - ZisK proves L2 *execution* in short ranges from the sequencer's blocks, before the batch reaches L1 [inferred from "as soon as they exist" and the Witness/Derive split]. After L1 inclusion it proves only that the posted batch derives to exactly those blocks, then binds the two.
   - OP Succinct's range program, which our P0 currently ports, does derivation **and** execution inside one guest per range. That puts L1 sync, blob/KZG work and derivation on every range proof's critical path.
   - Splitting them means:
     - **Execution proofs reuse our L1 pipeline almost unchanged.** OP execution is EVM plus deposit transactions (0x7E), the L1 data fee (FastLZ), the operator fee and OP precompile limits. That's our evmone RV64 guest with OP rules, on the same GPU prover, recursion and campaign as #314. The study's "optional" evmone-with-OP-rules item (≈2.5–3× cheaper execution than Kona-as-is) becomes the main path.
     - **Derivation becomes a small, separate guest:** L1 header/receipt walk → blob or calldata → channel frames → (span) batches → a commitment to each L2 block's transaction list and attributes. Blob/KZG and brotli costs land only there.
     - **Latency becomes a fixed close-out cost**, independent of batch size.
   - **Soundness:** the bind step must enforce exactly what the monolithic range program enforced, including the fix for advisory **GHSA-5jh4-3p33-85xc**. Each executed block's inputs (transactions, deposits, L1 attributes, timestamps, parent hash, and the L1 origin's hash and number) must equal what derivation produced, and the state roots must chain. Write this as a named binding note with a tamper corpus before any split proof ships.
2. **Aggregate as you go.**
   - Range proofs are folded into one running proof per batch as they finish (`zc_recent_proof_folded_timestamp_seconds`), so closing a batch is one bind step, not a tree.
   - This is the comb / running-accumulator topology in the 4-GPU design doc (`codex/rv64-4gpu-realtime-design`, `design/riscv-proving-stack/rv64-4gpu-realtime.md` §6 g).
   - For us it requires a constant fold VK (M5 canonical / set-v2) and a fold that accepts {accumulator, new range proof}.
3. **Small ranges keep latency down.** Five blocks keeps each proof near 3.4 s and the backlog near zero. On a light chain, choose range size for latency and queue depth, not for amortised cost. Our earlier "5–30-block ranges" sizing was cost-driven. Re-evaluate it once P0 measures our per-range fixed cost.
4. **Four GPUs keep up with OP Mainnet with headroom.**
   - About 21 transactions per 2 s block on average (105 per 5 blocks) [M-ext].
   - We have not measured OP block cost on our prover, so we do not claim parity.
   - The comparison to make in P1: ZisK's **3.41 s median per 5 OP Mainnet blocks on 4×5090**, and **≈10.4 s median from L1 inclusion to validity proof**.
5. **Use their user-facing metric.** For a rollup the number that matters is **"L1 batch inclusion → validity proof"**, with a p99. Adopt it, plus "range proof seconds per N blocks" and GPU duty cycle, as the headline metrics of this PR. Their bar is median 10.4 s, p90 11.8 s.
6. **Wrap vs pure STARK.**
   - ZisK spends 1.71 s on a SNARK wrap.
   - The owner decision for us is a pure Stwo STARK, verified directly (P3), so that slot is our two-stage compression instead: C1/C2 from the 10x plan's M7, with a ≤1.5 s budget in the 4-GPU doc.
   - The target close-out (derive + bind + compress) should therefore be comparable, about 7 s.
7. **Unsafe-head reorgs** [inferred requirement]. Proving ahead on blocks that are not yet on L1 means a sequencer reorg, or an unsafe block that differs from the derived one, invalidates range proofs. The coordinator must:
   - key range proofs by (block hash, parent hash);
   - have bind reject any mismatch;
   - re-prove from the fork point.

   Test it with a reorg injection harness.
8. **Copy the observability model.**
   - Their page is driven by Prometheus ring buffers:
     - per proof: first and last block, prover seconds, transactions, ended and folded timestamps;
     - per batch: L1 block and timestamp, seen time, execution-proof count, and seconds and waited seconds per step;
     - coordinator: connected workers, per-worker phase seconds, recent jobs.
   - Any past moment can be replayed (`?since=`).
   - We should emit the same series from our resident service, which is a cleaner public form of our progress ledger.

### 8.4 Consequences for the phased plan (supersedes §6 where they differ)

- **P0 is re-cut into two measurements:**
  - **P0a, execution:** OP Mainnet and Base blocks through **evmone with OP rules** on our RV64 emulator, plus a Kona-executor baseline for comparison. Report instructions per gas, and the differential against op-reth over ≥10³ blocks to start.
  - **P0b, derivation:** a minimal derivation guest (L1 receipts/blobs → frames → channels → batches → per-block input commitments). Report instructions per L1 batch, blob/KZG cost and witness bytes.
  - Kill criteria carry over per part.
- **P1:** native proofs of (a) a 5-block execution range on GPU and (b) one batch derivation. Gates:
  - range-proof seconds per 5 OP Mainnet blocks on 4×5090, compared with ZisK's 3.41 s median;
  - derivation-proof seconds per batch, compared with their 2.83 s.
- **P2:** a bind circuit (per-block input equality, root chaining, L1 origin binding, the GHSA-5jh4 case), a running-accumulator fold with a constant VK, a reorg-aware coordinator, and the Prometheus series above. Gate: **L1 inclusion → root proof** measured on live OP Mainnet in shadow mode, against ZisK's median 10.4 s.
- **P3:** unchanged (pure STARK, two-stage compression, Solidity verifier). The compress step replaces ZisK's 1.71 s wrap in the close-out budget.
