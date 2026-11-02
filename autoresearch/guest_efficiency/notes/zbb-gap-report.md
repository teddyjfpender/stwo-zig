# Zbb/Zba gap report (Move D, candidate first)

Date 2026-11-01, branch `codex/rv64-guest-candidate-isa`, executor commit
`b68291571`. Execution only; nothing here is promotable. Data:
`notes/candidate-isa-results-20261101.json`, ledger lines tagged `D_isa`.

**Answer.** Zba + Zbb take the evmone-class client from 5.653 to 5.343
instructions/gas (scored, -5.5%) and the Rust guest from 9.825 to 9.282
(-5.5%). On the three blocks where ziskethone has published step counts, they
close **0.32 of the 4.86 instructions/gas gap to 2.02 (about 6.5%)**. The ISA is
not what separates us from ziskethone. Missing services (BLS12-381 and BN254)
account for about 40% of the gap and client code for about 50%.

## Method

1. **Profile.** `ethereum_services_v3_candidate_isa` is the candidate services
   plus the 32 CONTEXT.md instructions (`src/frontends/riscv/rv64/candidate_isa.zig`).
   - Each instruction retires as one instruction and is counted per op (`candidate_isa_counts`).
   - The admitted decoder is unchanged.
   - Negative check: the Zbb ELF traps `IllegalInstruction` under plain `_v3_candidate`.
2. **Builds.** Three variants per client, all with exact outputs on all 15 blocks and guards G1-G6 passing:
   - Client: `client_evmone/build.py --profile candidate --isa {zba,zbb,zba_zbb}`, which sets `-mcpu=generic_rv64+m+zba+zbb`. Zbb builds also set `ZEG_BSWAP_BUILTIN`, ziskethone's own default.
   - Rust guest: the `ethereum-services-v2-lean` build plus `candidate-services`, with `RUSTFLAGS += -C target-feature=+zba,+zbb`. The target JSON base features `+m,+forced-atomics` accept them, and build-std rebuilds `core` and `alloc` with them.
   - The compiler emits the instructions. Static counts in `.text`: client 1,671 Zba / 3,168 Zbb sites; Rust 8,200 Zba / 5,013 Zbb.
3. **Price.** Each retirement costs (CPU row + ROM share + one family fact), minus the 154.81 cells the proxy already charges, plus any width added to an existing chip. Costs are in `proposals/candidate-isa-costs.json` (low / nominal / high); bits/gas below are nominal.

## Results (`--set all`, all guards pass)

Columns: I/gas scored, holdout and all are instructions per gas on the scored, holdout and full sets. Bits/gas is scored committed bits per gas at low / nominal / high ISA cost. Retired is the count of candidate instructions retired.

| variant | I/gas scored | I/gas holdout | I/gas all | bits/gas low / nominal / high | retired |
|---|---:|---:|---:|---:|---:|
| evmone RV64IM | 5.653 | 4.844 | 5.494 | 78,849 | 0 |
| evmone +Zba | 5.580 | 4.778 | 5.421 | 78,101 / 78,192 / 79,027 | 32.6M |
| evmone +Zbb | 5.414 | 4.638 | 5.261 | 76,602 / 76,704 / 77,078 | 13.9M |
| evmone +Zba+Zbb | **5.343** | 4.573 | 5.191 | 75,803 / **75,960** / 77,076 | 45.6M |
| Rust RV64IM | 9.825 | 8.307 | 9.525 | 125,990 | 0 |
| Rust +Zba | 9.675 | 8.171 | 9.378 | 124,408 / 124,606 / 126,155 | 79.1M |
| Rust +Zbb | 9.433 | 7.982 | 9.147 | 122,338 / 122,516 / 123,167 | 22.8M |
| Rust +Zba+Zbb | **9.282** | 7.847 | 8.999 | 120,620 / **120,936** / 122,980 | 101.4M |

On the scored set, both extensions together give -5.5% instructions on both
clients. Committed bits fall by -3.7% (client) and -4.0% (Rust) at nominal
cost, and by -2.2% / -2.4% at high cost.

### Saving per retired candidate instruction

| | Zba | Zbb |
|---|---:|---:|
| evmone (all blocks) | 32.5M saved / 32.6M retired = 1.0 | 103.8M / 13.9M = 7.5 |
| Rust (all blocks) | 65.5M / 79.1M = 0.83 | 168M / 22.8M = 7.4 |

- **Zba** saves exactly what its definition says: one shift-add pair becomes one instruction.
- **Zbb** saves 7-8 per retirement because `rev8` stands in for byte-assembled big-endian loads, and the client's sources switch to Zbb code paths:
  - intx stops using its byte-wise big-endian path;
  - `zeg::bswap64` becomes `__builtin_bswap64`;
  - `count_nonzero_bytes` uses `orc.b` + `cpop`.

### Retired candidate ops (all blocks, both extensions)

- **evmone:** sh3add 29.1M, rev8 8.7M, andn 2.1M, sh1add 1.5M, orn 0.8M, cpop 0.8M, add.uw 0.8M, maxu 0.6M, clz 0.3M, minu 0.3M, orc.b 0.2M, everything else under 0.2M. Rotates: 32.
- **Rust:** sh1add 39.3M, sh3add 35.3M, rev8 9.0M, maxu 4.8M, andn 3.6M, add.uw 2.7M, minu 2.0M, ctz 1.6M, clz 0.8M, sext.b 0.4M, roriw 0.36M.

Rotates are almost unused because Keccak-f and SHA-256 compression are already
services. The client's SHA-256 glue uses duplicated-word rotations.

## Per bucket, before and after (instructions/gas, all 15 blocks)

evmone client:

| bucket | RV64IM | +Zba | +Zbb | +both | change |
|---|---:|---:|---:|---:|---:|
| evm_interpreter | 1.862 | 1.809 | 1.710 | 1.659 | -0.203 |
| witness_trie_mpt | 0.825 | 0.823 | 0.818 | 0.816 | -0.009 |
| state_tables_host | 0.569 | 0.566 | 0.516 | 0.512 | -0.057 |
| precompile_bls_kzg | 0.460 | 0.458 | 0.458 | 0.455 | -0.005 |
| keccak_glue | 0.432 | 0.430 | 0.431 | 0.430 | -0.002 |
| precompile_bn254 | 0.300 | 0.299 | 0.298 | 0.298 | -0.002 |
| evm_jumpdest_analysis | 0.299 | 0.296 | 0.299 | 0.296 | -0.003 |
| mem_alloc | 0.263 | 0.261 | 0.258 | 0.257 | -0.006 |
| secp_ecdsa_glue | 0.222 | 0.219 | 0.222 | 0.219 | -0.003 |
| other | 0.179 | 0.179 | 0.170 | 0.170 | -0.009 |
| ssz_statement_sha256 | 0.064 | 0.063 | 0.063 | 0.063 | -0.001 |
| input_ssz | 0.019 | 0.017 | 0.019 | 0.017 | -0.002 |
| **total** | 5.494 | 5.421 | 5.261 | 5.191 | -0.303 |

- The interpreter takes 67% of the saving: the `dispatch_cgoto` jump-table index (sh3add) and U256 big-endian conversion (rev8).
- The state tables take 19%: sload / hash-table probe, rev8 and andn.
- The crypto glue barely moves: Keccak, BLS and BN254 do not change.

Rust guest:

| bucket | RV64IM | +Zba | +Zbb | +both | change |
|---|---:|---:|---:|---:|---:|
| evm_interpreter | 3.677 | 3.585 | 3.469 | 3.377 | -0.300 |
| mpt_rlp | 1.823 | 1.821 | 1.724 | 1.720 | -0.103 |
| secp_ecdsa_glue | 1.721 | 1.685 | 1.709 | 1.672 | -0.049 |
| other_crypto | 1.130 | 1.120 | 1.130 | 1.120 | -0.010 |
| mem_alloc | 0.492 | 0.488 | 0.483 | 0.479 | -0.013 |
| keccak_glue | 0.359 | 0.358 | 0.344 | 0.343 | -0.016 |
| ssz_input | 0.162 | 0.161 | 0.147 | 0.146 | -0.016 |
| other | 0.122 | 0.121 | 0.106 | 0.105 | -0.017 |
| ssz_statement_sha256 | 0.038 | 0.038 | 0.036 | 0.036 | -0.002 |
| **total** | 9.525 | 9.378 | 9.147 | 8.999 | -0.526 |

- The largest single function saving is revm `mload`: 0.226 to 0.140/gas with Zbb (U256 from big-endian bytes).
- In MPT, `resolve_digests` and `decode_into` gain from rev8, clz/ctz and minu.
- With Zba, `FieldElement::square` in k256 loses 0.024/gas.

## Static check: RV64IM idioms vs measured saving

`idioms.py` (scratch) scans the RV64IM ELFs for each idiom and weights every
site by its PC-histogram executions.

| idiom (instructions saved) | evmone dynamic saved | Rust dynamic saved |
|---|---:|---:|
| slli 1-3 + add -> shNadd (1) | 24.5M | 33.2M |
| not + and/or -> andn/orn (1) | 2.2M | 3.1M |
| xor + not -> xnor (1) | 0 | 2.9M |
| slli 32 + srli 32 -> zext.w (1) | 0.9M | 0.4M |
| slli/srai 48/56 -> sext.b/h (1) | 0.03M | 0.4M |
| rotate (slli + srli + or) -> rori (2) | 0 (0 sites executed) | 0.015M (7,280 executions; measured rori: 7,292) |
| shift/or byte-swap windows -> rev8 | 1.2M | 4.3M |
| **total, fraction of instructions** | 28.9M, 1.18% | 44.4M, 1.05% |
| **measured saving, both extensions** | **134.9M, 5.5%** | **234.3M, 5.5%** |

### How the static counts line up with the measurement

**Shift-add and rotates are where they should be.** Static shift-add explains
75% of the client's measured Zba saving (24.5M of 32.5M) and 51% of Rust's
(33.2M of 65.5M). The remainder comes from the compiler using sh*add in
address arithmetic, where the RV64IM code reuses the shifted value, so the
local matcher skips it. Rotates match their measurement: about 7k executions
statically, 7,292 `rori` retired.

**Byte swap is the big miss: the static count finds 1-2% where Zbb measures
4.2%.** On RV64IM, a big-endian load from possibly unaligned bytes is a chain
of byte loads with shift/or, not a shift-mask bswap of a register.
Misalignment traps here, so the compiler cannot use `ld` + bswap. The client
also switches source paths on `__riscv_zbb`:
- intx `INTX_BE_BYTEWISE`;
- `zeg/bswap.hpp`;
- `zeg/intrinsic_gas.hpp` (`orc.b` + `cpop`).

The saving therefore sits in the interpreter's U256 load/store and in key
handling, with no fixed idiom to find. The rest of Zbb (`maxu`/`minu` instead
of branch + move, `clz`/`ctz` instead of compiler-rt calls) has no static idiom
in the scanner.

## The remaining gap to ziskethone's 2.02

ziskethone was measured by ZisK on 3 of our 15 blocks: 26235156, 26235159 and
26235168 (`vectors/reports/rv64-ethereum-20261101/guest-steps-comparison-v1.json`).
Its total is 186.5M steps over 92.3M gas = 2.02. Our evmone client on the same
blocks runs 6.882 instructions/gas on RV64IM and 6.566 with Zba + Zbb. The gap
is 4.86, of which 0.32 is ISA.

**Caveat on the ziskethone shares.** ziskethone's per-bucket figures come from
`docs/perf-notes.md` (block 25701329, which is not in our basket; self steps
in ZisK ops, 234.8M total), scaled to 2.02 steps/gas. They are estimates (est.).

| bucket (ours, 3 blocks, +Zba+Zbb) | ours | ziskethone est. | gap | what closes it |
|---|---:|---:|---:|---|
| precompile_bls_kzg | 1.300 | ~0.05 | 1.25 | **service**: BLS12-381 ops (ZisK precompiles) |
| precompile_bn254 | 0.758 | ~0.05 | 0.71 | **service**: BN254 add/dbl/pairing ops. ZisK also issues `arith256` 31.9k and `arith256_mod` 24.7k calls on 26235159; we issue 0 and 173.8k, because our ModArith goes through `arith256_mod` |
| evm_interpreter + jumpdest | 2.076 | ~0.8 (dispatch 15.9% + check_requirements 7.5% + SWAP 3.5% + PUSH 2.2% + other opcodes) | 1.28 | **client**: RV64IM-tuned interpreter (track in progress), advanced-mode block checks |
| witness_trie_mpt | 0.788 | ~0.28 (build/reduce/eval/pack, 14%) | 0.51 | **client**: trie/state port |
| state_tables_host | 0.497 | ~0.19 (hash lookups 4.9% + variant 4.5%) | 0.31 | **client** |
| keccak_glue (sponge) | 0.415 | ~0.14 (7.1%) | 0.27 | **service/client**: a sponge or `dma_xor`-style absorb (sibling track), aligned absorb |
| mem_alloc | 0.256 | small (DMA) | ~0.2 | **ISA/DMA**: ZisK `-mzisk-dma` turns every compiler copy of 16 bytes or more into one op (2.71M `dma_xmemcpy` on 26235159 vs our 0.42M candidate memcpy calls) |
| secp_ecdsa_glue | 0.213 | ~0.1 | ~0.1 | client |
| ssz statement + input | 0.083 | 0 | 0.08 | statement: ZisK commits the block hash, not the SSZ root |
| other | 0.180 | ~0.1 | ~0.1 | client |
| **total** | **6.566** | **2.02** | **4.55** | |

### How the 4.86 instructions/gas splits

| part | instructions/gas | share | basis |
|---|---:|---:|---|
| ISA (Zba + Zbb, measured) | 0.32 | 6.5% | measured |
| ISA-like DMA lowering of compiler copies | ~0.2 | ~4% | est. |
| Services ZisK has and we do not (BLS12-381, BN254; Keccak absorb) | ~2.0 + ~0.15 | ~44% | est. |
| Client code (interpreter, MPT, state tables, glue) | ~2.2 | ~45% | est. |
| Statement difference (SSZ root) | 0.08 | ~2% | est. |

### Applying this to the whole basket

On the full basket, BLS/KZG plus BN254 is 0.75/gas, so the 3-block split
overstates services for the average block. Over all 15 blocks, ISA is 0.30 of
a 3.47 gap: 5.49 all-blocks against 2.02, about 9%.

The PATH-TO-BIG-JUMP estimate puts the client at about 3-3.5 instructions/gas
after services and client work. That estimate implicitly assumed Zbb would
close most of the remaining distance to 2.02. The measurement says otherwise:
expect about 3.0-3.3 with Zba + Zbb. Below that requires closing the
interpreter and MPT gap in client code, plus ZisK-style DMA for small copies.

## Caveats

- **ZisK steps are not RISC-V instructions.** The transpiler can expand or fuse instructions, and `rev8` was 13 ops before it became 1. The ziskethone build flags behind the published ELF (`-mzisk-dma` or not) are not recorded in our comparison.
- **ziskethone bucket shares come from a different block** and are estimates (est.).
- **The bits/gas proxy is linear.** Candidate costs are estimates in `proposals/candidate-isa-costs.json`, not a qualified AIR. Instruction-mix effects (the replaced shift/or instructions are cheap ALU rows that cost less than 154.8) are not modelled, so the bits saving is somewhat overstated at every cost level.
- **The idiom scanner is heuristic.** It uses a local window and a register-redefinition check; the byte-swap detection is a crude window heuristic.
- **No per-family build exists.** LLVM cannot enable a Zbb subset, so the per-family split of the Zbb saving is not measured. Per-op retirements are measured.
