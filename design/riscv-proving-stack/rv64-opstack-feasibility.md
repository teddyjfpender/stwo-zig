# RV64 frontend for the OP Stack in place of SP1: feasibility study



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
2. **How hard?** About 3–4 weeks of CPU-only work gets real instructions-per-gas numbers, and about 6–9 engineer-months gets native proofs of OP block ranges with aggregation and statement binding. Replacing SP1 *on L1* also needs a SNARK wrap that we don't have. That brings the total to about **18–26 engineer-months plus 3–6 months of external audit**, with a first mainnet settlement about 12–18 months out [estimate].
3. **What we think.** Run the measurement spike now: it is cheap and it settles the cost question. Pitch the result as a *second `verifierType`* for OP's multi-proof Stage 2 (Optimism's `IZKVerifier` interface is already vendor-neutral), not as a replacement for SP1. Don't commit to the wrap until the spike shows we are clearly cheaper (≥1.5×) than current SP1 Hypercube.

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
| **Proof verifiable on L1** | Groth16 ~270k gas, PLONK ~300k gas | none; a SNARK wrap is explicitly "out of scope" (`rv64-aggregation.md:98`) | Shrink layer + gnark PLONK wrap + Solidity adapters | 8–12 eng-mo | **Highest** |
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

**P3: SNARK wrap and on-chain verification.** 8–12 eng-mo plus audit.
- **Work:**
  - BN254-friendly hashing in prover, verifier and recursion;
  - gnark PLONK wrap;
  - Solidity adapters with Foundry tests;
  - composed soundness case;
  - external audit.
- **Gate:** the owner funds it as a separate track, or a customer accepts off-chain verification in the meantime.

**Optional after P1, if a customer pays:** P2-level guest cost (evmone with OP rules) and the derivation/execution split.

**Total to an L1-verifiable replacement:** about 18–26 engineer-months plus audit [estimate].

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