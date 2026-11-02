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

## Measured after merging origin/codex/rv64-guest-efficiency bf59d0334 (umem default)

Same method; v3 default set is now sha,arith,mem,umem. Executor rebuilt from the merged tree.

| client | instr/gas scored | holdout | all | committed bits/gas scored (proxy) |
|---|---:|---:|---:|---:|
| v3 RV64IM (541968b6) | 4.447 | 3.761 | 4.311 | 63,851 |
| v3 zbb_binary (db44755d, 744 rev8, audit clean) | **4.251 (-4.4%)** | 3.584 | 4.119 | **61,887 (-3.1%)** |

Estimated with the cheaper mask-row cost (0.8x proxy saving): ~62,280 bits/gas (-2.5%).

## Measured before the merge (basket `--set all`, all 15 blocks exact output, G1-G5 pass)

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

## CPU-lane integration (2026-11-02, branch head after d46c8e017)

Provable in the Word16 v3 services lane under `ethereum_services_v3_zbb` with a
fresh receiver (`zig build test-riscv64-word16-zbb-services`): two shards with
all seven instructions plus SHA-256, arith256_mod, memset, memcpy, SD/LD of a
rev8 result. ROM: andn/orn/xnor -> FUNCTION 19/20/21; rev8/sext.b/sext.h ->
22/23/24 with the B operand pinned by the ROM immediate (0/0x80/0x8000);
zext.h -> BINARY AND (16) with immediate 0xffff. One Zbb component (2 fixed,
32 MAIN, 24 interaction columns, rows = distinct Zbb facts) per shard; its
byte-AND requests join the core AND table. Absent component => no column,
claim, transcript or wire byte (v2 golden and v3 sha256/all bundles
byte-identical, verified after the final merges).

Fail closed: GKR-local lane, v3 truth-leaf recursion tool, legacy full AIR
(opcode policy / Plan.allows), non-Zbb ROMs (no Zbb component key), and the
Ethereum block driver: its native batch is built on the legacy byte ROM
authority, which has no Zbb rows, so a v3_zbb request stops with
`UnsupportedRv64ServiceExecutionProfile` before capture. Driver support needs
a Zbb-aware native batch/work packet authority (not done). Hence
`ethereum_services_v3_zbb` is NOT added to targets.json G6.

### Measured (merged head ff2381db6 + fused-tail 584ddea61, executor and both clients rebuilt from this tree)

Basket `--set all`, 15/15 exact outputs, G1-G5 pass (G6 fails for zbb: profile not allowed):

| client | scored instr/gas | holdout | all | scored bits/gas (proxy) |
|---|---:|---:|---:|---:|
| v3 RV64IM (this tree, default v3 set) | 4.060 | 3.440 | 3.937 | 54,544 |
| v3 zbb_binary (744 rev8, audit clean) | **3.864 (-4.8%)** | 3.263 | 3.745 | **53,067 (-2.7%)** |

The proxy charges 154.8 cells per retirement and does not see the Zbb
component; its real cost is below.

Block 24,628,607 (`zbb_shard_steps` = 4,194,303 executor diagnostic): 30,719,275
-> 29,016,151 instructions (-1,703,124, -5.5%; 143,784 rev8, 11.85 saved per
rev8); distinct Zbb facts per shard [2317, 3280, 3771, 3120, 3619, 2594, 7] ->
component logs 12 x6 and 5 -> 1,378,048 committed (MAIN+INTERACTION) cells
= 56 x (6 x 4096 + 32), i.e. +0.047 cells per instruction, +12.1 bits/gas on
this block (64.80 bits per committed cell, gas 7,372,614).
On the reference roster (9 CPU proofs at log 22, 36,659,069 instructions): at
most 9 x 4096 x 56 = 2,064,384 cells = +0.056 cells/instruction, against
-0.0554 instructions per instruction x 158.6 committed cells = -8.79
cells/instruction (lower bound with the CPU row only, 89.6 cells: -4.96), net
about -8.7 cells per original instruction (-5.5%); about -2,360 bits/gas on
block 24,628,607 (-1,330 with the CPU-row-only bound).

## Ethereum driver + real prefix proof (2026-11-02, branch `codex/rv64-ge-zbb2`)

`codex/rv64-ge-zbb` merged onto PR head 2490495dd. The Zbb component is the last
CPU-local block (after LS-D64) in columns, fixed, logs, sources, handles,
claims transcript and wire; `admitZbb` also counts the CPU byte-pair AND mass.

- **Layouts.** v3_zbb now takes the v3 default CPU layout (fused tail + U8
  pairs + LS-D64, `Plan.CpuLayout.forProfile` via `isV3`), the v3 Keccak truth
  policy, and `admitProfile` admits it like v3 (the Zbb component stays rejected
  under every other profile). The zbb services fixture proves and fresh-verifies
  on BOTH the historical and the v3 default layout, and the forged sext.b /
  zext.h results are rejected on both (`test-riscv64-word16-zbb-services`, 4 tests).
- **Native batch / packet authority.** The legacy native statement stays the
  v2-decoded byte-ROM statement (as for v3 tapes); `ProgramAuthority` gains
  `rom_profile` (= `profile` except on the Zbb route: v2 statement, v3_zbb
  execution ROM, `Request.romProfile`). `Authority.instructionAt(pc)` returns the
  legacy row when valid and, only under the Zbb ROM, the Zbb BINARY decode of a
  row the legacy ROM keeps invalid (base opcodes on invalid rows, invalid words,
  unmapped/misaligned PCs fail closed). Used by `Batch.init/observe` and the
  packet admission walk. `tapeAdmits(tape, statement, rom)` is `tapeMatches`
  without a separate ROM and admits exactly v3_zbb tapes on the Zbb route
  (`tapeMatches` itself is unchanged, so a v3_zbb tape still never matches a
  v2 Word16 ROM). The packet program key binds `rom_profile` on the Zbb route
  only (all other keys byte-identical). The Word16 program is built from
  `rom_profile`. The legacy packet reader / worker does not re-derive the
  execution ROM and rejects Zbb packets (`InvalidWorkPacketBoundary`); the
  legacy prover already rejects every non-v2 request. Tests:
  `test-riscv64-work-packet` (+3: decode/pairing/key/tape truth table, batch with
  Zbb rows + forged opcodes + v2 ROM, admission walk counts + legacy reader and
  v2-ROM rejection).
- **Real prefix proof (block 24,628,607, 4 packets, 16,777,212 instructions).**
  Client `build.py --profile v3 --isa zbb_binary --isa-audit rv64-isa-audit`
  (default v3 set; sha256 f44278ad..., 744 rev8, audit clean; terminal_pc
  489124 = the `j .` in stwo_guest_main), adapted input e549944d.
  `nativeprepare` (max_batches 4): 4 packets, 6 s. `produce ... prefix4 4`
  (memguard --gb 15): accepted in-process, 36.9 s wall, prove 31.9 s, max RSS
  20.4 GB (/usr/bin/time; footprint 13.8 GB). Every CPU proof: fused tail, U8
  pairs, LS-D64 (logs 20/19), Zbb log 12 (distinct facts 2,637 / 3,934 / 3,740
  / 3,401). Fresh `verify-prefix`: accepted (2.5 s). Adversarial on the real
  bundle: a v3 request rejects it (`UnadmittedZbbBinaryComponent`), a +1 Zbb
  FUNCTION claim fails (`OodsNotMatching`), dropping the Zbb component fails
  (`GlobalExecutionInventoryMismatch`).
  Exact cells: Zbb components 917,504 MAIN+INTERACTION over the prefix =
  0.0547 cells/instruction (calibration `zbb_binary_cells_per_instruction`);
  CPU proofs 2,347,412,768 MAIN+INTERACTION (139.9/instruction; the zbb prefix
  covers 66.6% of the block's 25.19 M instructions, the v3 prefix 62.4% of
  26.89 M, so per-instruction figures of the two prefixes are not comparable).
- **Basket** (this tree's executor, host and both clients; `--set all`, 15/15
  exact, G1-G6 PASS, promotable):

| client | scored instr/gas | holdout | all | scored bits/gas |
|---|---:|---:|---:|---:|
| v3 RV64IM (4e7a2684) | 3.283 | 2.853 | 3.198 | 40,336 |
| v3 zbb_binary (f44278ad) | **3.087 (-6.0%)** | 2.676 | 3.006 | **38,736 (-4.0%)** |

  Per block -4.0% .. -7.0% instructions (24,628,607: 26,894,760 -> 25,191,636).
  bench.py now scores v3_zbb rows with every `_v3` coefficient plus the measured
  Zbb component (`V3_PROFILES`, required coefficient); no other row changes.

### How to select it

```sh
python3 client_evmone/build.py --out OUT --cache ~/Coding/ge-cache/evmsrc --profile v3 \
  --isa zbb_binary --isa-audit <rv64-isa-audit from src/frontends/riscv/rv64>
# bench: --elf OUT/client-evmone-v3-zbb_binary.elf --profile ethereum_services_v3_zbb
# prover request.json: "execution_profile": "ethereum_services_v3_zbb", terminal_pc of that ELF
```

Not made the build.py default: `--isa zbb_binary` needs the audit tool path,
and the complete-block proof of the zbb client (coordinator-scheduled) has not
been run; the 4-packet prefix is the evidence so far.
