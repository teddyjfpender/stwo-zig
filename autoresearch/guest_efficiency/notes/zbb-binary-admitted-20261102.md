# Zbb BINARY subset: admitted-ISA executor, client and chip (2026-11-02)

Branch `codex/rv64-ge-zbb`. Proposal: `proposals/isa-extension.md` group 1.

## What exists

- **ISA option.** `decode.Isa.rv64im_zbb_binary` = RV64IM + `andn orn xnor rev8 sext.b sext.h zext.h`
  (standard RV64 encodings, `decode.decodeZbbBinary`). New profile
  `execution_profile.Profile.ethereum_services_v3_zbb` (v3 services, this ISA);
  every older profile decodes exactly RV64IM. Opcodes are appended to `decode.Opcode`;
  identities that enumerate opcodes use `decode.baseOpcodes()` (unchanged domain).
- **Executor.** `rv64-ethereum-execution` profile `ethereum_services_v3_zbb`; per-op
  retirements in `zbb_binary_counts`. `opcode_counts` keeps the 65-entry RV64IM schema.
- **Static audit.** `rv64-isa-audit [--require-subset] ELF...` (`src/frontends/riscv/rv64/isa_audit.zig`)
  decodes every word of every executable section with the same decoders and fails on any
  Zbb/Zba/Zbkb encoding outside the subset, or any undecodable word other than `unimp`/0.
- **Client.** `client_evmone/build.py --profile v3 --isa zbb_binary --isa-audit <tool>`.
  LLVM cannot enable a Zbb subset (measured: a `+zbb` build has 730 non-admitted sites
  — clz 73, cpop 63, min/max 232, rori/roriw 344, orc.b 1 — in almost every TU; `+zbkb`
  emits pack/packh for constants and 839 rotates). So the compiler stays RV64IM and every
  byte swap is one `rev8` issued as a raw `.insn` (`glue/stwo_zbb_binary.h`, intx patch 0024).
  The linked ELF passes the audit: 744 `rev8`, 0 other bit-manip, 2 trap words.
  The other six admitted ops are not emitted by this build (no compiler support).
- **AIR.** `air/word16_v1/binary_zbb.zig`: BINARY-shaped row (+3 selectors, 31 local main,
  same 8 byte-AND requests against the same table, same 24 interaction columns), FUNCTION ids
  19..24, B pinned for sext.b/sext.h, soundness argument in the file header.
  `binary_lookup.emitOf`/`binary_component.Kind.binary_zbb` reuse the BINARY lookup and
  component; `word16/binary_fixture.zig` is generic (`FixtureSet`), `binary_fixture.zbb`
  proves the chip.

## Measured (basket `--set all`, all 15 blocks exact output, G1-G5 pass)

Baseline is this tree's own `--profile v3 --isa im` client (sha, arith, aligned mem), the
same v3 set as the zbb build. G6 fails for the zbb run only because
`ethereum_services_v3_zbb` is not yet in `targets.json` (locked).

| client | instr/gas scored | holdout | all | committed bits/gas scored (proxy) |
|---|---:|---:|---:|---:|
| v3 RV64IM (own build, b9378915) | 4.778 | 4.061 | 4.636 | 67,192 |
| v3 zbb_binary, rev8 everywhere (5fe20aa7, default) | **4.582 (-4.1%)** | 3.884 | 4.444 | **65,229 (-2.9%)** |
| v3 zbb_binary, rev8 in intx kernel only (`--zbb-kernel-only`) | 4.588 | 3.888 | 4.450 | 65,289 |

Per block: -2.3% .. -5.5% instructions. Block 24,628,607: 143,784 `rev8` retired,
1.70 M instructions saved = 11.8 per `rev8` (each replaces the 13-instruction mask swap).

Bits/gas estimate: the proxy charges every retirement 154.8 cells. A rev8 row is the CPU
row (87.5) + ROM + one Zbb BINARY fact (32 main + 24 interaction, ~56 cells), i.e. close to
the proxy. The removed instructions are mask/shift ALU rows (~124 cells, not 154.8), so the
real saving is about 0.8x the proxy saving: **~65,600 bits/gas (-2.3%)** is the honest
estimate; 65,229 is the proxy number.

## Not done

- CPU-lane integration: ROM mapping of the new opcodes (`word16_execution/features.zig`
  still rejects them), BINARY_ZBB role in sources/prepared/protocol/wire/GKR-local,
  a program fixture proof through the services lane with a fresh receiver, recursion.
  Until then `prepared.zig` rejects `ethereum_services_v3_zbb` tapes (fails closed).
- `targets.json` needs `ethereum_services_v3_zbb` in `allowed_execution_profiles` once
  the CPU lane admits it.
