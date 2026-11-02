# LS-D64: an aligned LD/SD fast row beside LS32

Status: implemented on `codex/rv64-ge-ls64` (frontend chip, services-lane
wiring, Ethereum planner default for `ethereum_services_v3`). Round-1 design
"LS-D64" (`~/Coding/ge-ops/round1-designs.json`, design 0). Paths: `air/` =
`src/frontends/riscv/rv64/air/`, `svc/` =
`src/integrations/riscv_cpu/word16_global_execution/services/`.

## 1. Why

83.2% of evmone v3 loads/stores are naturally aligned 8-byte LD/SD (77.9% on
block 24,628,607; `notes/ls-width-histogram-v3.json` on `codex/rv64-ge-cells`).
Every access paid for the full LS32 row (`air/memory/load_store_v2`): MAIN70 +
INTER32 = 102 cells. An LD/SD never uses the byte/half/word flags, the seven
non-zero offsets, the selection lookup or the b_low/b_high byte split.

## 2. Layout (MAIN39 + INTER28 = 67 cells)

Committed (`air/memory/load_store_dword/layout.zig::STORED`), as V1 logical
coordinates: RAM transition 27 of 28 (active, write=store, same, address limbs
1..3, before/after epoch, before/after tick lo/hi, before[4], after[4], R, W,
epoch_gap, gap_lo, gap_hi, carry), A[4] (28..31), B[4] (36..39), quotient (68),
address carries[4] (75..78).

Virtual (`expandFor`, affine, no products):

| Logical | Value |
|---|---|
| 3 owner tick | after_lo + 65536 after_hi |
| 4 address limb 0 | 8 q |
| 44..47 EA | address limbs (offset 0) |
| 32..35 immediate | EA_c + 65536 carry_c - A_c - carry_{c-1} |
| 40..43 C | after - B |
| flags | LD = active - store, SD = store, other nine 0 |
| 48 opcode | LD_op (active - store) + SD_op store |
| 60..67 offsets | offset0 = active, others 0 |
| 69 selected limb | before[3] |
| 73 b_low | B[0]; 70, 71, 72, 74 are 0 |

INTER: RAM inverse + prefix (8, unchanged LS32 authority), four strict local
pair inverses over seven fractions (16): (OWNER19 weighted by `active`, U16
after_lo), (U16 epoch_gap, U16 gap_lo), (U16 q, U8 after_hi), (U8 gap_hi
single), and one local prefix (4). 255 constraints, degree 3.

## 3. Soundness

1. **Restriction of an audited row.** The unchanged
   `load_store_v1/equations.zig::emitLocalWithPublicFor` and
   `closed_ram/equations.zig::transitionRamFor` run on the expansion. A dword
   row therefore satisfies exactly the V1 constraints of an LS32 row whose
   flags are LD/SD at offset 0; the extra constraints are identities on the
   virtual coordinates. Degree stays <= 3 because every virtual coordinate is
   affine.
2. **Dropped lookups.** Selection and b_low/b_high only constrain
   selected_byte, signs and the B bytes; LD/SD never read them (their V1 uses
   are multiplied by the zero flags) and their virtual values are constants or
   affine in committed columns. Retained: after clock split (U16/U8), strict
   gaps (U16, U16, U8), address quotient (U16).
3. **Address and alignment.** addr0 = EA0 = 8q with q U16, the LS32 bounded
   quotient argument (no inverse-of-eight compensation: test "misaligned
   address claimed aligned" includes the field-inverse attempt and an
   exhaustive q/carry search). The immediate is the exact field residue of
   the committed addition, and OWNER binds it to the CPU's canonical ROM
   immediate, so `A + I + c_in = EA + 65536 c_out` holds limbwise as with the
   committed immediate. Address canonicality still comes from RAM chronology
   and receiver-validated aligned INIT coverage.
4. **OWNER is one-to-one.** Both LS components consume the same per-CPU
   OWNER19 relation (same challenge), the tuple carries the tick, CPU OWNER
   weight is Boolean and active-gated, and the dword OWNER weight is the RAM
   `active` of the same row. The dword opcode is virtual and can only be 0,
   LD or SD; any other CPU tuple cannot be consumed by a dword row. The
   routing choice is the prover's (it cannot change acceptance: both
   components enforce LD/SD semantics). The dword shares join the CPU-local
   closure (`svc/statement.zig::CpuClaims.local`), never summed across CPUs.
5. **RAM** stays one global multiset: the dword RAM claim is an additive
   share in `CpuClaims.ram`, with its own inverse/prefix like LS32.
6. **Padding.** `(1 - active) v = 0` over every committed column zeroes every
   virtual coordinate; Boolean(store) and Boolean(active - store) give
   store <= active; one inactive terminal row per present instance.
7. **Joint REG/RAM write induction**: section 12 of
   [rv64-ls-joint-write-induction.md](rv64-ls-joint-write-induction.md). No new
   writer case: dword LD is the LS32 LD case (after = before, C = before),
   dword SD the LS32 SD case (after = B).

## 4. Integration (selected per CPU proof by geometry)

* Roster: `svc/types.zig::Logs.ls_dword` and `ls_dword_tail` (head/tail, the
  LS32 ladder rule; tail present iff it has rows). Present => every LD/SD of
  that CPU proof is a dword row, in tape order (`svc/pipeline.zig::splitEvents`);
  `memory.ls_count` is then the LS32 share and `Request.ls_dword` the dword
  total. Components follow the sponge block (`svc/roster.zig::dwordOffset`).
* Transcript: mixed only when present (`svc/protocol.zig::beginCpu`: tag
  `0x4c534436`, LS32 and dword counts, both instance logs, widths, the dword
  encoding identity), and claims mixed after the sponge claims
  (`CpuClaims.mix`). Absent: every v2/v3 transcript, wire and bundle byte is
  unchanged (`Logs`, `CompactRequest` and `WireClaims` omit the fields).
* Admission: presence iff rows, canonical head/tail split, U16/U8 mass of
  every physical row, RAM 2 per row, service count bound
  (`svc/protocol.zig::admitDword`, repeated natively in `svc/wire.zig::validate`).
* Ethereum driver: `ethereum/plan.zig::cpusWithLsDword` sizes LS32 on the
  non-LD/SD remainder and the dword ladder on the LD/SD count; the default for
  `execution_profile == ethereum_services_v3` (`--no-ls-dword` opts out);
  `ethereum/main.zig::admitProfile` rejects the component for v2 requests.
  `role_cost.zig` reports `ls_dword` and `ls_dword_tail` rows.

## 5. Measurements

See the commit messages for the exact runs. Layout tier: 102 -> 67 committed
cells per LD/SD row. Block 24,628,607 roster (9 CPU proofs, 36,659,069
instructions, exact per-proof RAM events from
`vectors/reports/rv64-ethereum-20261101/evmone-v3-block-24628607-v1.json`,
block LD/SD share 0.778869 applied uniformly, planner ladder rule):
`notes/ls_dword_cells.py` gives LS 38.11 -> 27.12 cells/instruction (111.1 ->
79.1 per access), -10.99 cells/instruction, about -2,890 bits/gas at 4.060
instr/gas (sensitivity +-0.03 share: -10.3 to -10.6). This is a layout-tier
model of the exact roster, not a complete-block proof (the coordinator
schedules those).

## 6. Not done / risks

* No recursion support (the dword component is native-lane only; v3 services
  recursion is unfinished anyway).
* A bespoke non-projection AIR could drop the four B columns (step 2 of the
  round-1 design, about -1.2 cells/instruction more).
* The dword interaction generator is serial per instance (the LS32 one is
  parallel); prover wall time on 2^20-row instances is not yet measured.
