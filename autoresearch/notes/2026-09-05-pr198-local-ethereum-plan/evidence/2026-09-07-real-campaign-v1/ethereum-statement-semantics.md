# Retained Ethereum statement semantics

This is a source/custody audit, not a whole-block verification receipt. Exact absolute source paths, sizes and SHA256 values are in [ethereum-statement-semantics-pins.json](ethereum-statement-semantics-pins.json). The active campaign has 121 segments; terminal native proof and final whole-bundle verification remain required.

The retained ELF SHA is `f81e30505c2ae1ab16e693933bef65f6fbae94ca6e04b4bc66688a068cddce16`. Its build receipt pins the current guest source and Cargo lock; the executable segment matches the preceding guest, with the full heap newly included in declared RW memory. The tracked stateless dependency files are unchanged at `a134a621bad7229ff7f980e42dfca8e22d101491` (only Cargo's untracked `.cargo-ok` marker exists).

The actual 43-byte expected output (SHA `730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5`) decodes as payload-request SSZ root `e63d2797ca5c6f826a32d20c41ba552d25777533ab295f9d232560b014d09030`, success 1, chain 1, schema 5121/BPO2. It is not block hash `d6edeb114882eb19af618789a4ebd5f84984e7d340d54459d1b2d9d7c1ed99a9`.

| Claim | Source relation |
| --- | --- |
| Prestate | stateless `validation.rs:274–285` checks parent ancestry, then initializes the trie from the parent header's state root; `tries/src/zeth.rs:116–133` hashes witness nodes/code and opens that root. |
| Execution/poststate | `validation.rs:287–345` executes the EVM, applies state changes, computes the root and compares it with the block header. |
| Transactions/withdrawals | Reth consensus common `validation.rs:141–190` recomputes body commitments; payload conversion reconstructs header fields. |
| Receipts/gas/requests | Reth Ethereum consensus `validation.rs:58–106` checks actual gas, receipt root/log bloom and execution-request hash. |
| Block identity | Reth payload `validator.rs:76–85` recomputes the header hash and compares it with the payload's block hash. That payload is committed by the returned SSZ request root. |
| Fork rules | stateless guest `convert.rs:50–103` constructs chain1 with forks through selected BPO2 active. This does not prove canonical-chain selection or independently reproduce the historical mainnet fork schedule. |
| Success/output | repo `guest_runtime/ethereum/src/main.rs:165–181` calls the pinned validator, requires success, writes all output bytes, then writes the halt flag. Panic executes an illegal instruction. Native transaction recovery is successful-only; Revm's EVM precompiles retain software semantics. |

RV32 memory/continuation roots are not Ethereum state roots. Ethereum meaning follows from execution of the admitted guest over the authenticated input and output. The independently pinned materialization SHA is `e9d9ba5619d5780155bf7f23e3475a1af0aae85ec74a0660b837c0cdbb237f4e`; its source request pins the ELF, runner input SHA `faaf02583929396faed177914da27b4a493766993001357bd1720340ca1ddabb`, and output. The retained journal terminates after 253,646,998 cycles with `halt_flag` and that exact output; its own claim is execution-only, not a proof.

Native terminal support exists: `segment_leaf_local_authority_v3.zig:147–153` requires completion on the last leaf, `incremental_public_logup_v4.zig:192–205` preserves it, and `public_logup.zig:170–179` consumes the halt memory tuple. The completed bundle uses `RootStatement.init` and exact adjacency/coverage. This distinguishes supported terminal semantics from a still-pending actual leaf120 proof. The recursive nonfinal-only program profile is a different layer.

Whole-block acceptance still requires all native leaves plus independent terminal bundle verification. Cross-system comparison additionally needs a normalized benchmark binding: the ZisK expected output is a 256-byte length-prefixed block hash, while ours is the 43-byte SSZ validation result. `ethereum_block_benchmark_statement.py:103–131` deliberately retains `matched_guest_statement_reproduced=false`. Normalization of pinned input/header/output statements does not by itself establish equivalent guest execution, ZisK proof verification, finality, or performance equivalence.

## Pinned normalization follow-up

The new benchmark-layer checker passed against the actual retained files. [statement-normalization-v1.json](statement-normalization-v1.json) seals the decoded 13-field header, parent state root, recomputed payload-request root, benchmark statement SHA, independent materialization SHA and its complete job/source-request custody. The recovered parent state root is `ab6d9cef65166d92ff4507a3ed09ac786cb5a0a9f598ca46f79621c95c7de186`. It checks exact ELF/input/output identity equality across the materialization source request, and requires strict completion. The final native verifier separately enforces the materialization's actual JobContext; this receipt does not verify native proofs or replace that verifier.

The existing upstream-codec Rust projection recomputes the exact canonical input from the pinned ZisK input, now emits the actual decoded header and recomputed SSZ request root, and checks the parent header relation. Python reuses the existing frame and Stwo projection authorities, compares every header field with the independent benchmark manifest, and joins the computed request root to the 43-byte output. It reconstructs **expected** ZisK output framing from that block hash and verifies the already-pinned 256-byte output SHA; it does not claim to have rerun ZisK or newly observed its output artifact.

Validation: Rust 1/1, Python 6/6 (including mutations of every header field, result root/success/chain/fork, output confusion, and job-source identity), and actual retained normalization PASS. Six additional actual-file/authority mutations reject: materialization, ZisK input, runner input, output, ELF pin and projection executable pin. Logs, [mutation results](statement-normalization-mutations-v1.json), and [source/executable pins](statement-normalization-source-pins.json) are adjacent. The checker is `python -m autoresearch.benchmarks.ethereum_block_statement_normalization`; it requires independently supplied materialization, ELF and projection-executable SHA pins and creates its output receipt exclusively.

`matched_guest_statement_reproduced`, `zisk_execution_reproduced`, and `whole_block_proof_verified` remain false. Existing benchmark manifests and comparison flags were not promoted. This establishes a concrete normalization/binding artifact while preserving the separate complete-bundle and cross-guest acceptance requirements.
