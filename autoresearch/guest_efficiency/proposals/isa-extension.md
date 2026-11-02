# Proposal: admit a Zbb/Zba subset in the Word16 CPU AIR

Status: group 1 partly built on `codex/rv64-ge-zbb` (2026-11-02): admitted-ISA decoder and
executor profile `ethereum_services_v3_zbb`, static ISA audit, `rev8` client build
(-4.1% instr/gas vs the same-tree v3 client), Zbb BINARY chip with a chip-level STARK fixture.
CPU-lane ROM/role integration and a program proof are not done. See
`notes/zbb-binary-admitted-20261102.md`. Earlier status: candidate-measured, not built. Evidence: `notes/zbb-gap-report.md`,
`notes/candidate-isa-results-20261101.json`, costs in
`proposals/candidate-isa-costs.json` (estimates).

## Recommendation

| Order | Group | Instructions | AIR change | Measured value | Verdict |
|---|---|---|---|---|---|
| 1 | **BINARY extension** | `rev8`, `andn`, `orn`, `xnor`, `sext.b`, `sext.h`, `zext.h` | +6 selectors on BINARY, no new lookups | Most of the Zbb saving: `rev8` 8.7-9.0M and `andn`/`orn` 3-4M retirements; Zbb overall -4.2% instructions on both clients | **Build first.** Cheapest change, and it carries the big Zbb effect. |
| 2 | **Compare-select** | `max`, `maxu`, `min`, `minu` | Small new chip, or +5 ALU columns | Rust 6.9M retirements (each replaces a branch + move); client 0.95M | Build with group 1 if it is cheap to share the ALU's borrow chain; otherwise later. |
| 3 | **Bit count** | `clz[w]`, `ctz[w]`, `cpop[w]`, `orc.b` | New chip + 2^8-row byte table | Rust 2.4M (`clz`/`ctz` replace compiler-rt calls); client 1.3M (`cpop`/`orc.b` in calldata gas counting) | Defer. Most new AIR and least certain cost; the value is mostly inside the Zbb total. |
| 4 | **Shift-add (Zba)** | `sh{1,2,3}add[.uw]`, `add.uw` | New SHADD chip | -1.3% (client), -1.5% (Rust) instructions; 1.0 and 0.83 instructions saved per retirement | Marginal. A whole new chip plus recursion support for about 1.5%. Revisit after the interpreter port, which changes the address arithmetic mix. |
| — | **Rotates** | `rol[w]`, `ror[w]`, `rori[w]`, `slli.uw` | +5 SHIFT selectors | About 0.4M retirements: Keccak and SHA-256 are services, and the client's SHA glue uses duplicated-word rotations | **Do not build.** Per retirement they cost more than the row they replace (nominal +44 cells over the proxy). |

Groups 1-3 together are the "Zbb" build the compiler targets: LLVM cannot
enable a Zbb subset. Admitting only group 1 therefore needs one of these:

- a compiler subset: `+zbkb` gives `andn`, `orn`, `xnor`, `rev8` and rotates, but also brings in `pack`, `packh`, `brev8`, `zip` and `unzip`;
- or a guest build that uses `rev8`/`andn` through intrinsics only, with no `-march` Zbb.

**The decision to make first:** full Zbb (groups 1-3 plus the rotates the
compiler will emit) or Zbkb (`rev8`, `andn`, `orn`, `xnor`, rotates, `pack*`).
Measure Zbkb with the same candidate method before building any AIR. It needs
`pack`/`packh`/`packw`/`brev8` added to `candidate_isa.zig`, about 30 lines.

## Expected value (scored set, nominal cost)

| Client | Instr/gas, RV64IM | Instr/gas, +Zba+Zbb | Committed bits/gas, RV64IM | Committed bits/gas, +Zba+Zbb | Bits/gas, Zbb only |
|---|---:|---:|---:|---:|---:|
| evmone (candidate services) | 5.653 | 5.343 (-5.5%) | 78,849 | 75,960 (-3.7%) | 76,704 (-2.7%) |
| Rust guest | 9.825 | 9.282 (-5.5%) | 125,990 | 120,936 (-4.0%) | 122,516 (-2.8%) |

At high cost, the bits/gas gain from both extensions shrinks to -2.2% (client)
and -2.4% (Rust). ISA closes about 6.5% of the gap to ziskethone's 2.02. The
rest is services (BLS12-381, BN254; about 44%) and client code (about 45%);
see the gap report.

## CPU AIR changes

**CPU row: none.** Candidate ops use the existing FUNCTION13 tuple
`(op, A_eff, B_eff|IMM, C)` with new global op IDs (`word16_execution/features.zig`)
and ROM entries. The unary ops leave `rs2` unread; `enabled=0` then forces
`B=0`. No new CPU columns or interactions. The CPU row stays 47 main + 40
interaction cells.

**Group 1: extend BINARY** (`word16_v1/binary.zig`). It is 29 main + 24
interaction today: 8 byte-AND lookups of `(a_i, b_i, T_i)`. Per byte, with
`T = a & b` already looked up:

| Op | Output | How |
|---|---|---|
| `andn` | `a - T` | |
| `orn` | `255 - b + T` | |
| `xnor` | `255 - (a + b - 2T)` | |
| `rev8` | `c_i = a_{7-i}` | Selector-weighted permutation of the looked-up `a` bytes. `B = 0`; the AND lookups still range-check the bytes. |
| `sext.b`, `sext.h` | `c = low byte(s)` + `sign·0xff` fill | ROM immediate `0x80` / `0x8000` makes `T` of the top byte equal `128·sign`. |
| `zext.h` | | Existing AND with ROM immediate `0xffff`; a decode-level mapping, no new selector. |

All outputs are affine in `(a, b, T)` per selector, which keeps the derived C
at degree 2.

**Group 2: compare-select chip.**
- **Columns:** `A[4]`, `B[4]`, difference limbs, borrow chain and sign bits, as the ALU proves SLT/SLTU (`word16_v1/alu.zig` 114-139).
- **Selection:** `choose = s_min·sl + s_max·(1-sl) + s_minu·b3 + s_maxu·(1-b3)`, then `C_i = (Σs)·B_i + choose·(A_i - B_i)`. Degree 2.
- **Size:** about 31 main + 20 interaction.

**Group 3: bit-count chip.**
- **Byte table:** 2^8 rows, byte -> `(popcount, nonzero, clz8, ctz8)`, fixed.
- **Row:** 8 byte queries, which also range-check the bytes against A's limbs. Two prefix chains of "all bytes zero so far", one from each end, select the first non-zero byte for clz/ctz.
- **Other ops:** `cpop` = Σ popcount; `orc.b` byte i = `255·nonzero_i`. The w forms restrict to bytes 0-3.
- **Size:** about 34 main + 24 interaction.

**Group 4: SHADD chip.**
- **Main columns:** `A[4]`, `B[4]`, `C[4]`, carries `< 2^4`, one-hot `k` (1, 2, 3), `.uw` flag.
- **Interaction:** C limbs range16, carries small-range.
- Kept out of the ALU: adding 16 columns to every ALU row would cost about 1.75 cells per instruction overall.

## Cost per row (`candidate-isa-costs.json`)

Total cost = CPU row 87.5 + ROM 2.26 + one fact.

| Group | Fact (cells, padded) | Total vs proxy 154.81 | Width on existing chip (cells per instruction) |
|---|---:|---:|---:|
| BINARY extension | 61 (53-75) | -4 (-12..+10) | 0.45 |
| Compare-select | 75 (66-92) | +10 (+1..+27) | 0 (0.55 if in ALU) |
| Bit count | 70 (55-120) | +5 (-10..+55) | 0 |
| SHADD | 60 (48-90) | -5 (-17..+25) | 0 (1.75 if in ALU) |
| Rotates in SHIFT | 109 (100-125) | +44 (+35..+60) | 0.29 |

Each Zbb retirement removes about 7.5 RV64IM instructions (measured). So every
Zbb group pays at any point in its cost range. Zba removes about 1.0 per
retirement, so it pays only while its row costs less than about 2× the
instruction it replaces. It does, but the absolute gain is small.

## Soundness

- **Decode.** Each new op ID must be bound by the immutable ROM tuple, as the existing ops are. The decoder qualification must show:
  - every candidate encoding maps to exactly one op;
  - nothing else maps to a candidate op: near misses such as `packw` with `rs2 != 0`, the RV32 `rev8` encoding `0x698`, and the excluded Zbs/Zbc encodings stay illegal.

  The execution-tool tests (`candidate_isa_test.zig`) already pin the encodings against LLVM's assembler. They need porting to the ROM builder.
- **Facts.** Each new chip needs complete constraints:
  - `rev8`: the permutation must be over range-checked bytes that recompose A's limbs.
  - Bit count: each prefix chain must be Boolean and monotone, and exactly one first-non-zero byte must be selected when `A ≠ 0`. `clz(0) = 64` and `clzw(0) = 32` need explicit cases.
  - Compare-select: the result must equal one of the two operands, and the sign/borrow bits must be the ALU's proven ones.
- **Adversarial tests.** Same as the services lane: per-op tampering of C, of the selectors and of the multiplicities.
- **Statement.** Admitting instructions changes the ISA in the statement. The `execution_profile` and compact tape need a new admitted profile; the existing `ethereum_services_v2` guests are unchanged.

## Recursion impact

| Group | Cost in the recursion circuits |
|---|---|
| 1 | Nothing new: the BINARY component gains columns and constraints, so the verifier circuit's BINARY evaluation grows by about 6 selector terms. Smallest impact. |
| 2-4 | Each new chip is a new component: a new tree, plus OOD/FRI queries over its columns and a new LogUp sum term. |

Expect each new chip to cost a fixed number of recursion-circuit constraints,
similar to the existing JALR composite. That cost has to be built and qualified
in the native-protocol in-circuit verifier.

## Next steps

1. Implement Zbkb `pack`/`packh`/`packw`/`brev8` in the candidate executor. Measure `-march=..._zbkb` against `_zbb` on both clients; this decides whether group 1 alone is reachable from the compiler.
2. Re-run this measurement on the RV64IM-tuned interpreter (`codex/rv64-guest-client-interpreter`) when it lands. The interpreter is 67% of the Zbb saving.
3. Then the group 1 AIR, a fixture proof and a fresh receiver, following the services-lane gates in PATH-TO-BIG-JUMP.md.

Review before reliance: all cell figures are estimates, from chip widths read
out of the source and the block 24,628,607 roster. None is a qualified AIR.
