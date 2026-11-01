# RV64 Keccak and memory committed-cell reduction

Design proposal, 2026-11-01; no prover code changed. Receipt:
`vectors/reports/rv64-ethereum-20261101/keccak-memory-cost-model-v1.json`. Paths
are under `src/frontends/riscv/rv64/air/` unless noted. **Measured** = read from
`/tmp/rv64-ls32-qualified-complete-v1/{cost,roster}.json` (block 24,628,607,
schema 7, 7,372,614 gas). **Estimated** = derived from column counts here,
unqualified. Proxy: 62 bits/cell, +4.51 % composition, fixed excluded.

## 1. Keccak-f cost today (measured)

Geometry: `delegations/keccak/layout.zig:3-22`.
- Each cell holds `a+8b`, two permutations' bits (`packed_row.zig:1-2`).
- A slot is 29 rows: 2 input, 25 state groups, 2 output (`guest_precompile/keccakf_authority.zig:56-61`).
- MAIN is 1923 columns: 1600 state, 320 parity, 3 header.
- Each round row makes 1600 chi lookups (one output each) and 320 xor5 lookups. Tuples: `guest_precompile/keccakf_lookup_tuples.zig:4-36`.
- Lookups are cleared three per degree-4 batch: 640 batches plus 9 IO11 batches, 2596 interaction columns (`layout.zig:15-19`, `equations.zig:107-131`).
- Tables are 2^13 chi and 2^10 xor5. Each has 7 fixed, 1 main and 4 interaction columns (`tables.zig:44-58`).

| per Keccak-f call | cells | basis |
|---|---:|---|
| main (1923 cols) | 30,705 | measured |
| interaction (2596 cols) | 41,451 | measured |
| chi + xor5 tables | 2.8 | measured |
| **truth total** | **72,159** | measured; = calibration |
| of which power-of-two padding | 6,631 (9.2 %) | measured: 476,122 rows used of 2×2^18 |
| fixed (not in proxy) | 515 | measured |
| Word16 bridge (66 + 116 cols × 25 rows) | 6,164 | measured; 35 % padding rows |
| **all-in per call** | **78,323** | measured |

- LogUp interaction is 57.4 % of truth cells (57.9 % with bridge); 82 % of the 1945 fractions/row are chi.
- The bridge (`word16_bridge/layout.zig:3-19`: interaction RAM 8, OWNER 8, IO 8, 22 U16 → 48, 19 U8 → 44) is charged inside the CPU coefficient (1.94 of 154.8 cells/instr).
- Density: 4.454 calls/kgas measured; the stated 290 cells/gas implies 4.02, used below. Charging the bridge per call puts today's model at 83,070 vs the stated 82,204 bits/gas.

**ZisK** (`zisk-src/precompiles/keccakf/pil/NUMBERS.md`, as reported, not re-run): same paired `a+8b` construction (`keccakf_authority.zig:8-12`), 27 rows × 2611 columns per slot, 35,249 Goldilocks cells/Keccak-f unpadded = **2.26 Mbit**. Ours: 72,159 M31 cells = **2.24 Mbit** (2.03 unpadded): bit parity. ZisK has half our cells because of 5-output chi and 3-position xor5 lookups (`keccakf.pil:245-305`): stage 2 is 682 columns vs our 2596.

## 2. Keccak design alternatives (all estimated)

**(a) Throughput lookup tables. Recommended.**
- One chi lookup proves a 5-lane row (2^21 table); one xor5 lookup proves 3 positions (2^16). The authority exists on the RV32 path, unwired in RV64 (`guest_precompile/keccakf_authority.zig:66-79`, `keccakf_throughput_tables_v1.zig:1-27`, `keccakf_throughput_interaction_plan_v1.zig:1-23`).
- Lookups/round row 1920 → 427; triple batching → 152 batches, 608 interaction columns; MAIN unchanged; degree 4.
- 36,700 nominal, ~40,400 padded, +659 tables → **41,071/call** (−43 %).
- Soundness: audited tuple semantics; packed keys affine, 28^5 < p (`keccakf_authority.zig:71-74`); re-derive the LogUp mass bound. The 2^21 table adds 7 × 2^21 fixed cells per proof (outside the proxy, real work).

**(b) Slot geometry.**
- (b1) A 27-row slot: read op-B input and output as `(v−a)/8` on round 0 and round 24, as `keccakf.pil:195-216` does. That is −6.9 %. Booleanity becomes `8b(8−8b)`, degree 2.
- (b2) Three permutations per cell (`a+8b+64c`), compact chi (2^19 table): 48,272/call, worse than (a); 5-output chi on 3 slices needs 2^31 rows.
- (b3) Two rounds per row: same lookups per round; no gain.
- Padding ladder: power-of-two proof splits at 97 % fill instead of 90.8 %: −6.4 %, no AIR change.

**(c) Word16 limbs at the IO boundary only.**
- Inside the permutation: not viable (16-bit 2-input tables are 2^32).
- At IO: replace bit→byte packing (`equations.zig:67-78`) and the bridge's byte columns/recomposition (`word16_bridge/equations.zig:18-25,50-53`) with four u16 limbs of 16 already-boolean bits (`equations.zig:181-184`). Drop 16 MAIN columns, 16 U8 and 8 value U16 queries: before-values are canonical by RAM induction (as LS32, `memory/load_store_v2/layout.zig:18-23`), after-values by the bits.
- Row 182 → 118: **6,164 → ~4,000/call**. Risk low–medium (IO11 changes both sides).

**(d) Bridge IO in the global RAM argument.** Per-lane chronology (25 × ~6 columns, +17 batches) in a ~2,500-column row used on 4 of 29 rows: ~3,481/call vs ~4,000 for (c). Marginal, duplicates OWNER binding, high risk. Dominated: the narrow bridge is the cheapest home for per-lane chronology.

**(e) Sponge-level service (absorb inside the AIR).**
- Glue is 107.7 instructions/call, measured on the baseline guest (`keccak_glue`, `autoresearch/guest_efficiency/notes/baseline-attribution-24628607.json`); unmeasured on the 5.88 guest.
- State stays in the AIR; the bridge reads 17 rate lanes per block and writes the digest once. One extra row/slot holds message bits; absorb `v_in = v_out + m − 2·v_out·m` is degree 2.
- Saves ~90 instructions/call and bridge 6,164 → ~2,400. Soundness: bind length and pad10*1 in-AIR; 8-byte-aligned input; new ECALL ABI.

**(f) LogUp-GKR for the Keccak lookups.**
- Removes all interaction columns (~12 eq/binding columns remain); with (b1) + ladder **26,933/call**.
- Keccak is GKR's best case (1945 fractions/row vs 16 in the LS prototype, `rv64-logup-gkr-prototype.md` §2), but services GKR is still `Pending` (`rv64-services-local-gkr-custody.md`), the isolated-family recursion result was negative (`rv64-gkr-circuit-cost-gate.md`:30), and whole-protocol security is unreviewed.

Not re-verified: Plonky3/SP1 keccak-air is ~2.6k columns × 24 rows, no lookups (~63k BabyBear cells; recalled figure, verify before quoting). Stwo-Cairo's Keccak was not inspected.

## 3. Memory accesses (measured attribution)

From `roster.json`:
- 33,457,230 LS rows (= `ram_events`; 32.1 % of instructions); LS + LS_tail = **112.2 cells/access** (102 nominal × 1.10 padding).
- Every instruction pays the CPU row, 47 + 40 = **87.5** (`word16_execution/layout.zig:4-48`).
- **Load/store ≈ 200 cells; non-LS ≈ 124** (87.5 + 36 family facts); ~5 cells/instr ROM/table/boundary overhead is uniform. This does not reproduce the sibling 289 vs 91.

The LS row (`memory/load_store_v2/projection.zig:5-8`, `layout.zig:6-31`, `local_lookup.zig:11-29`):
- MAIN 70 = RAM14 transition 25 (`closed_ram/layout.zig:2-23`) + A/IMM/B/C OWNER duplicate 16 + flags 11 + offsets 8 + quotient 1 + selection 4 + b_high 1 + carries 4.
- Interaction 32 = RAM 8 + 5 pairs + prefix over OWNER19, 4 U16 (tick lo, epoch gap, gap lo, quotient), 4 U8 (tick hi, gap hi, b bytes), SELECTION (`load_store_v1/equations.zig:21-34,62-78`).

Designs (estimates):
- **M1 aligned-dword chip.** Route naturally aligned LD/SD to a narrow chip. It drops the offsets, selection, b bytes and 9 flags, and aliases B or C onto the RAM value columns through a degree-2 OWNER projection. That is about 39 MAIN + 28 interaction = **68 columns** against 102. Sub-word accesses stay on LS v2.
  - The aligned share is **unmeasured**; the model assumes 60 %.
  - Risk: low, since it is a subset of the qualified authority with a disjoint opcode whitelist.
- **M3 range trims under canonical induction.**
  - Put the scalar after-tick into RAM14. It is CPU-derived through OWNER and needs no lo/hi split ranges.
  - Drop the quotient by relying on receiver-validated aligned INIT addresses (`load_store_v2/equations.zig:33-40`).
  - Result: dword rows 58 columns, sub-word rows 96.
  - Risk: medium. RAM14 changes globally (LS, bridges, INIT/TEARDOWN), and LS32 deliberately kept these queries (`load_store_v2/layout.zig:23`).
- **M2 fused dword LS+CPU.** Aligned LD/SD do not emit a CPU row. The LS row carries PC, ROM and two REG accesses: about 89 columns against 87.5 + 63.8. That halves a dword access, from 200 to about 98.
  - It needs a PC/tick continuity mechanism for the rows skipped in the CPU trace, about +2.2 cells on the remaining CPU rows.
  - Risk: high. Tick uniqueness and the PC chain are both soundness-critical (`word16_execution/README.md`, "Derived predecessor clocks").

Halving every access (−32 cells/instr) would need M2 on sub-word accesses too.

## 4. Results table (5.88 and 3.0 instr/gas, 4.02 calls/kgas)

CPU column excludes the bridge; the Keccak column includes it. Everything other than "today" is estimated.

| design | CPU cells/instr | Keccak cells/call | bits/gas @5.88 | bits/gas @3.0 |
|---|---:|---:|---:|---:|
| today (measured coefficients) | 152.9 | 78,323 | 83,070 | 54,541 |
| K1 padding ladder | 152.9 | 73,719 | 81,870 | 53,342 |
| K3 (a) throughput tables | 152.9 | 47,235 | 74,974 | 46,445 |
| K3 + B1 (c) u16 IO | 152.9 | 45,067 | 74,409 | 45,880 |
| K4 (a)+(b1)+ladder + B1 | 152.9 | 39,880 | 73,058 | 44,529 |
| K5 (b2) 3 perms/cell + B1 | 152.9 | 52,269 | 76,285 | 47,756 |
| K6 (f) GKR+(b1)+ladder + B1 | 152.9 | 30,930 | 70,727 | 42,198 |
| K4 + (e) sponge¹ | 152.9 | 39,678 | 69,423 | 40,894 |
| M1 dword chip² | 145.7 | 78,323 | 80,326 | 53,141 |
| M1+M3 | 142.7 | 78,323 | 79,196 | 52,564 |
| M1+M2+M3 | 133.9 | 78,323 | 75,847 | 50,856 |
| bound: every access halved | 120.8 | 78,323 | 70,861 | 48,312 |
| K4+B1 + M1+M3 | 142.7 | 39,880 | 69,185 | 42,553 |
| K4+(e) + M1+M3¹ | 142.7 | 39,678 | 65,788 | 39,156 |
| everything (K6+(e)+M1+M2+M3)¹ | 133.9 | 30,396 | 60,227 | 35,236 |

¹ Also removes about 90 glue instructions per call, which is −0.36 instr/gas (estimate from the baseline guest).
² Assumes 60 % of accesses are aligned dwords.

**No design reaches 30,000 bits/gas at 3.0 instr/gas.** Today's CPU coefficient alone is 29,700 bits/gas there, secp ~4,400. Reaching 30,000 needs CPU **≤ 91 cells/instr** (Keccak ~30k/call) or ≤ 83 (36k); ≤ 131.6 even with free Keccak. The CPU row (87.5) and family facts are the binding constraint; that needs its own brief.

## 5. Ranking (bits/gas saved at 5.88 per engineering week)

Weeks are rough estimates.

| # | design | Δ bits/gas | weeks | per week | soundness risk |
|---|---|---:|---:|---:|---|
| 1 | (a) throughput tables | −8,100 | 2.5 | 3,240 | low–med: mass bound, table identity binding |
| 2 | ladder (proof split) | −1,200 | 1 | 1,200 | none (scheduler); more truth proofs |
| 3 | (e) sponge service | −3,600 | 4 | 900 | med: padding/length binding, new ABI; glue saving unverified on the 5.88 guest |
| 4 | M1 dword chip | −2,700 | 3.5 | 780 | low; depends on unmeasured dword share |
| 5 | M3 range trims | −1,100 | 2 | 570 | med: global RAM14 schema, INIT alignment argument |
| 6 | M2 fused LS/CPU | −3,300 | 7 | 480 | high: PC/tick continuity |
| 7 | (c) u16 bridge IO | −570 | 1.5 | 380 | low–med: induction argument as in LS32 |
| 8 | (b1) 27-row slot | −740 | 2.5 | 300 | med: op-B boundary encoding |
| 9 | (f) Keccak GKR | −2,300 | 8 | 290 | high: protocol pending, recursion cost |
| — | (b2), (d) | dominated | | | |

## 6. Minimal prototype for (a)

1. In `delegations/keccak/`, add an RV64 throughput component next to the compact one. Use the same MAIN and row filler. Tuples and tables come from `keccakf_throughput_tables_v1.zig`. Use triple batching (`equations.zig:107-131` pattern) with 143 + 9 batches, so 608 interaction columns. Mix a distinct profile identity before roots, as `batch_policy.zig:27-31` does.
2. Use 2^21 chi and 2^16 xor5 table components (7 fixed, 1 main, 4 interaction). Re-derive `lookupMass`/`admitRoster` (`layout.zig:37-60`) for the 5-output and 3-position buses.
3. Fixture: a log-18 truth proof over real block calls, 18,078 calls. Pass criteria:
   - the proof verifies;
   - IO11 is unchanged against the existing bridge;
   - measured cells/call ≤ 42,000.
4. Adversarial tests: wrong chi output in each of the 5 lanes, wrong iota round, a corrupted parity triple, and a table-multiplicity overflow.
5. Record 2^21-table commit time, peak memory and prove-time delta (cells are not time).
6. In parallel: log the executor's load/store width/alignment histogram to settle the M1/M2 dword share.

These are design estimates for prover engineering. Any soundness claim in this doc needs independent review before adoption.
