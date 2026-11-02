# RV64 Ethereum guest: instruction counts vs ZisK on the same mainnet blocks

Date: 2026-11-01. Execution only. Nothing here was proved. Receipt:
`vectors/reports/rv64-ethereum-20261101/guest-steps-comparison-v1.json`.

## What was run

- **Blocks.** These are the 15 mainnet blocks that ZisK publishes as `zisk-eth-client` reth fixtures
  (`bin/guests/stateless-validator-reth/inputs/*.bin`, commit `dfa27ff2e`). The range is 24,626,900 to 26,235,168,
  with 60 to 641 txs and 5.4 to 58.9 Mgas. Our pinned block 24,628,607 is one of them.
- **Inputs.** Our canonical SSZ inputs come from those same fixtures. The converter is the existing
  `autoresearch/benchmarks/guest_runtime/projection`, with its single-fixture pins removed. No RPC was needed.
  For 24,628,607 the converter reproduces the pinned `canonical-input.ssz` byte for byte. All 15 blocks are BPO2,
  and all have empty execution requests.
- **Our guest.** We use the round-5 lean services ELF (`8acf8385…`) with `rv64-ethereum-execution`
  (`ethereum_services_v2`). The run checks the 43-byte output (payload-request root, success flag, chain id and
  fork id). For 24,628,607 it reproduces **104,253,913** instructions.
  - The pinned ELF has a 4 MiB input window, so only 5 of the 15 blocks fit.
  - For the other 10, the same branch source was relinked with a 16 MiB input window, and a scratch copy of the
    executor was set to `INPUT_CAPACITY` = 16 MiB.
  - On the 5 blocks that fit, the relinked guest is within 0.08% of the pinned ELF. Rebuilding from the branch is
    not byte-identical, and the data addresses shift.
- **ZisK.** We built `ziskemu` from source at v1.4.0-alpha (`64a1f166`) and ran `ziskemu -X` with ZisK's own
  `zec-reth.elf` on all 15 blocks. We also ran `zec-ziskethone.elf` (C++/evmone) on the 3 blocks that ZisK ships
  ethone inputs for. Every ZisK run returned the correct block hash.

## Results

| block | txs | gas | ours (RV64IM instr) | ours / gas | ZisK reth steps | ZisK ethone steps | ours / reth | ours / ethone |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 24,626,900 | 221 | 16,338,083 | 217,574,707 | 13.3 | 104,851,202 | | 2.08 | |
| 24,628,590 | 478 | 49,134,719 | 629,126,569 | 12.8 | 318,012,180 | | 1.98 | |
| 24,628,595 | 641 | 54,230,474 | 710,501,452 | 13.1 | 346,436,700 | | 2.05 | |
| 24,628,607 | 66 | 7,372,614 | 104,253,913 | 14.1 | 60,289,420 | | 1.73 | |
| 24,628,608 | 146 | 12,907,474 | 151,203,451 | 11.7 | 81,410,395 | | 1.86 | |
| 24,628,611 | 627 | 58,862,996 | 778,082,522 | 13.2 | 370,532,834 | | 2.10 | |
| 24,647,140 | 60 | 7,704,951 | 109,139,374 | 14.2 | 58,141,998 | | 1.88 | |
| 24,697,070 | 270 | 17,435,221 | 261,016,581 | 15.0 | 118,573,137 | | 2.20 | |
| 24,697,073 | 308 | 22,277,128 | 305,609,769 | 13.7 | 110,032,109 | | 2.78 | |
| 25,229,951 | 420 | 57,944,048 | 618,896,990 | 10.7 | 315,700,337 | | 1.96 | |
| 25,229,955 | 305 | 39,102,791 | 517,378,514 | 13.2 | 232,207,462 | | 2.23 | |
| 25,229,957 | 107 | 9,768,139 | 123,511,251 | 12.6 | 61,829,664 | | 2.00 | |
| 26,235,156 | 91 | 5,443,474 | 79,595,147 | 14.6 | 35,721,945 | 10,011,348 | 2.23 | 7.95 |
| 26,235,159 | 532 | 57,734,946 | 879,612,412 | 15.2 | 361,332,170 | 117,222,289 | 2.43 | 7.50 |
| 26,235,168 | 260 | 29,142,059 | 510,264,082 | 17.5 | 189,873,711 | 59,225,558 | 2.69 | 8.62 |

Notes on the table:
- **Aggregate.** Across 445.4 Mgas, ours runs **13.46 instr/gas**. ZisK reth runs **6.21 steps/gas**, so ours is
  **2.17x** the reth guest. On the 3 shared blocks, ziskethone runs **2.02 steps/gas** and ours is **7.9x** it.
- **Block sources.** Rows with an input under 4 MiB (24,628,607 / 24,628,608 / 24,647,140 / 25,229,957 / 26,235,156)
  use the pinned ELF. All other rows use the wide-input relink.
- **Precompile calls match closely.** On 24,628,607 we run 32,835 keccak-f against ZisK reth's 32,396. We run
  11,496 secp add / 9,768 double against ZisK's 10,086 / 9,838. So the gap is software instructions, not
  precompile usage.

ZisK's own eight-block set from `ziskethone/docs/perf-notes.md` (`data_20260808`, starting at 25,701,329):
- Totals are 1,676,971,663 steps with evmone and 1,433,274,221 with `-mzisk-dma`.
- The PC histogram for block 25,701,329 sums to 234,838,799 steps.
- Only 25,701,329 and 25,708,403 are named. The other six block numbers, all gas figures, and the inputs are not
  published.
- The ~490 M-step "cold-account" heavy blocks come from the 200M-gas killer set, and their block numbers are not
  listed.
- So none of these can be run here. See "Blocked" below.

## Where our 104.25 M instructions go (24,628,607)

These are self counts from the PC histogram, bucketed by symbol name. Inlined code is counted under its caller.

| bucket | instr | share |
|---|---:|---:|
| EVM interpreter (revm handler/instructions, bytecode analysis) | 36.05 M | 34.6% |
| memcpy/memmove/memset/memcmp + alloc | 21.66 M | 20.8% |
| MPT / RLP (zeth-mpt resolve, decode, encode, drop) | 16.61 M | 15.9% |
| sha256 compress (software; SSZ request root) | 11.29 M | 10.8% |
| secp/ECDSA glue around the add/double service (field square, inversion, decompress, recover) | 11.21 M | 10.7% |
| keccak sponge glue around the keccak-f service | 3.54 M | 3.4% |
| SSZ input decode | 1.14 M | 1.1% |
| other | 2.75 M | 2.6% |

Precompile-call setup is about 14% of instructions: 10.7% secp glue plus 3.4% keccak glue. EVM execution proper
is about 35%. The remaining half is state and witness plumbing: MPT, memcpy and the SSZ statement hash.

## Caveats

- **Different clients.** Ours is reth stateless-validator + revm built for plain RV64IM. ZisK reth is
  reth/revm built for ZisK. ziskethone is C++ evmone with a hand-tuned MPT. The blocks and witness are the same.
  The ~4x gap between the two ZisK guests shows how much the client choice matters.
- **Steps are not RV instructions.** ZisK counts ZisK ops after transpilation, and its guests are built with
  Zbb/bitmanip (`rev8`, `andn`, `sh3add`, …) and DMA `memcpy/memset/memcmp` ops.
  - One ZisK step can replace several RV64IM instructions. This matters most here, because a fifth of our count is
    mem* and alloc.
  - Mapping is mostly 1:1 otherwise, but atomics expand to several steps.
- **Work the ZisK guests do not do.** Our guest computes the SSZ `new_payload_request` root with software sha256,
  about 11% of the count. The ZisK guests commit the block hash instead.
- **Steps are only a proxy for proving cost.** ZisK prices MAIN at 68 per step plus memory, opcode and precompile
  areas. Our cost per retirement depends on the Word16 AIR shape.
- **Input conversion assumptions.** Converted inputs assume BPO2 and empty execution requests. A block with
  deposits, withdrawal requests or consolidations needs its requests, which the RethInput fixture does not carry.
  It also needs the converter extended.

## Blocked / what is needed

1. **No RPC endpoint is configured** in the repo or the environment. To produce canonical inputs for arbitrary
   blocks, such as ZisK's eight `data_20260808` blocks or the ~490 M-step heavy blocks:
   - We need an archive-capable reth node (or a provider) that serves `debug_executionWitness(block)` and
     `eth_getBlockByNumber(block, true)`, plus the execution requests for post-Prague blocks.
   - Expect roughly 2-15 MB of witness per block at 5-60 Mgas.
   - ZisK's `input-gen rpc -u <URL> -b <N>` writes the RethInput `.bin` that our generalized converter consumes.
2. **We need ZisK's block list.** The six unnamed `data_20260808` block numbers and the heavy-block numbers would
   have to come from ZisK.
3. **Pinned ELF input window.** The pinned round-5 ELF only accepts inputs up to 4 MiB. Promoting a wide-input
   layout would need a new pinned ELF and a matching change to the executor contract.

Before anyone relies on these numbers, a reviewer should check the figures against the receipt.
