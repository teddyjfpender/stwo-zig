# Native interaction census (stream native-gkr, M5, 2026-11-04)

**What this is.** Every committed native INTER (interaction-tree) cell of the M4 production native protocol
`RV64-SERVICES-CPU-GKR-TRUTH-CLASSIC-OM31-V3` (profile `conjectured128_b2_q108_p20_fold4`), split per physical
component and relation, for the two dev blocks, plus the cells the new native protocol `rv64-m5-native-gkr/v1`
(`design/riscv-proving-stack/rv64-native-gkr.md`) would commit.

**Labels.** Today's cells are **[M]**: the declaration census (`rv64-native-gkr-census`, built from the production
roster code `cpu_components.Plan`, `global_cpu.layout`, `truth_components`, `truth_v3_catalog`, ROM log 18) equals the
measured `GPU_TRACE_OWNERSHIP tree=2 coefficient_words` of every native proof of the M4 integrate runs
(`/workspace/m3/runs/m4-integrate/<block>-2gpu-g5-counters`), 11/11 on 26235156 and 17/17 on 24628607, exactly
(multiset equality, `reconciled_with_measured_tree2: true`). The 24628607 total, 1,854.05 M, is the M4.0 item-8 number.
v1 cells are **[D]** (the v1 rule applied to the same rosters: one 16-column eq+prefix binding pair per component
that has any LogUp fraction; no other INTER column). Bits/gas = cells × 31 / gas (own height); the LDE (b2) figure
doubles it.

**Headline.**
- Native INTER today is **1.854 G cells on 24628607 = 7,796 bits/gas own height = 15,592 LDE bits/gas** (1.350 G /
  15,377 on 26235156). The 73k "interaction bits/gas" of `committed-work-comparison-v1.json` is the 2026-11-01 classic
  q70 protocol (before local GKR); it is stale. ZisK, same file: 1.698e12 LDE bits / 59.98 M gas = **28.3k LDE bits/gas**.
  On the interaction column we are already **1.8x below ZisK**; v1 takes it to **7.6k (3.7x below)**.
- **What is still committed:** (1) every truth proof (Keccak, secp add/double, sha256, arith256) is entirely classic
  LogUp: 838 M cells on 24628607 (45 %), Keccak alone 743 M; (2) CPU global RAM/KIO/Wire classic columns: 257 M (14 %);
  (3) the local-GKR binding pairs (eq + prefix, 16 columns per component): 759 M (41 %).
- **v1 removes (1) and (2) completely** and keeps one binding pair per component: INTER 1,854 -> **903 M (x0.487)**
  on 24628607, 1,350 -> **612 M (x0.453)** on 26235156; MAIN+INTER x0.791 / x0.767.
- What v1 cannot remove is the binding itself (cpu_word16_exec 507 M is all binding: CPU 2^22 x 16). The next lever is
  sharing eq/prefix columns across components of one row log (v2, section 7 of the design note).

**Families.** cpu_word16_exec = cpu, boundary, selection, alu(+tail), binary(+tail), shift(+tail), jalr; rom; memory_ls =
ls(+tail), initial, terminal, LS-D64 dword; range_u8_u16_tables = range16, range8, and_table, shift_table; deleg_* =
in-CPU bridges (keccak bridge + sponge call/perm, secp add/double, sha256, arith256); bulk_memory_jumpdest = the nine bulk
components; truth_* = the separate truth proofs. REG has no separate AIR (registers are in the CPU AIR's local
relations); there is no FUNCTION/OWNER component in either block's roster.

### 24628607 (gas 7,372,614, 17 native proofs; declared == measured tree=2 words for every proof: True)

| family | relations today | INTER today (M) | local-GKR binding | global RAM | global KIO | global Wire | classic local | INTER bits/gas | v1 INTER (M) | saving (M) | v1 bits/gas |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| truth_keccak | all classic (truth) | 742.8 | 0.0 | 0.0 | 167.1 | 0.0 | 575.7 | 3,123 | 110.4 | 632.4 | 464 |
| cpu_word16_exec | local GKR only | 507.3 | 507.3 | 0.0 | 0.0 | 0.0 | 0.0 | 2,133 | 507.3 | 0.0 | 2,133 |
| memory_ls | local GKR + classic global | 364.2 | 165.3 | 198.9 | 0.0 | 0.0 | 0.0 | 1,531 | 198.9 | 165.3 | 836 |
| truth_add | all classic (truth) | 53.8 | 0.0 | 0.0 | 0.0 | 0.3 | 53.6 | 226 | 0.2 | 53.7 | 1 |
| bulk_memory_jumpdest | local GKR + classic global | 52.0 | 22.6 | 29.4 | 0.0 | 0.0 | 0.0 | 218 | 22.6 | 29.4 | 95 |
| truth_double | all classic (truth) | 41.3 | 0.0 | 0.0 | 0.0 | 0.2 | 41.1 | 174 | 0.2 | 41.1 | 1 |
| rom | local GKR only | 29.4 | 29.4 | 0.0 | 0.0 | 0.0 | 0.0 | 124 | 29.4 | 0.0 | 124 |
| deleg_keccak_bridge | local GKR + classic global | 22.7 | 1.9 | 9.4 | 11.4 | 0.0 | 0.0 | 95 | 1.9 | 20.8 | 8 |
| range_u8_u16_tables | local GKR only | 22.0 | 22.0 | 0.0 | 0.0 | 0.0 | 0.0 | 93 | 22.0 | 0.0 | 93 |
| deleg_mul | local GKR only | 8.4 | 8.4 | 0.0 | 0.0 | 0.0 | 0.0 | 35 | 8.4 | 0.0 | 35 |
| deleg_secp_bridge | local GKR + classic global | 8.3 | 1.8 | 4.6 | 0.0 | 1.8 | 0.0 | 35 | 1.8 | 6.5 | 8 |
| deleg_sha256_bridge | local GKR + classic global | 1.2 | 0.3 | 0.7 | 0.0 | 0.3 | 0.0 | 5 | 0.3 | 0.9 | 1 |
| truth_arith256_mod | all classic (truth) | 0.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.5 | 2 | 0.0 | 0.5 | 0 |
| deleg_arith256_bridge | local GKR + classic global | 0.2 | 0.0 | 0.1 | 0.0 | 0.0 | 0.0 | 1 | 0.0 | 0.1 | 0 |
| deleg_div | local GKR only | 0.1 | 0.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0.1 | 0.0 | 0 |
| truth_sha256 | all classic (truth) | 0.1 | 0.0 | 0.0 | 0.0 | 0.1 | 0.0 | 0 | 0.1 | 0.0 | 0 |
| **total** | | **1,854.1** | | | | | | **7,796** | **903.4** | **950.7** | **3,798** |

MAIN 2,703.0 M; MAIN+INTER 4,557.1 M -> 3,606.4 M (x0.791); INTER x0.487; INTER LDE bits/gas (b2, the unit of the 73k figure) 15,592 -> 7,597.

### 26235156 (gas 5,443,474, 11 native proofs; declared == measured tree=2 words for every proof: True)

| family | relations today | INTER today (M) | local-GKR binding | global RAM | global KIO | global Wire | classic local | INTER bits/gas | v1 INTER (M) | saving (M) | v1 bits/gas |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| truth_keccak | all classic (truth) | 551.1 | 0.0 | 0.0 | 117.0 | 0.0 | 434.1 | 3,138 | 108.4 | 442.7 | 617 |
| cpu_word16_exec | local GKR only | 312.3 | 312.3 | 0.0 | 0.0 | 0.0 | 0.0 | 1,779 | 312.3 | 0.0 | 1,779 |
| memory_ls | local GKR + classic global | 230.7 | 98.6 | 132.1 | 0.0 | 0.0 | 0.0 | 1,314 | 132.1 | 98.6 | 752 |
| truth_add | all classic (truth) | 84.0 | 0.0 | 0.0 | 0.0 | 0.4 | 83.6 | 478 | 0.3 | 83.8 | 2 |
| truth_double | all classic (truth) | 66.1 | 0.0 | 0.0 | 0.0 | 0.3 | 65.8 | 376 | 0.3 | 65.8 | 2 |
| bulk_memory_jumpdest | local GKR + classic global | 34.2 | 14.9 | 19.3 | 0.0 | 0.0 | 0.0 | 195 | 14.9 | 19.3 | 85 |
| rom | local GKR only | 16.8 | 16.8 | 0.0 | 0.0 | 0.0 | 0.0 | 96 | 16.8 | 0.0 | 96 |
| deleg_secp_bridge | local GKR + classic global | 16.6 | 3.7 | 9.2 | 0.0 | 3.7 | 0.0 | 94 | 3.7 | 12.9 | 21 |
| deleg_keccak_bridge | local GKR + classic global | 15.8 | 1.6 | 6.5 | 7.7 | 0.0 | 0.0 | 90 | 1.6 | 14.2 | 9 |
| range_u8_u16_tables | local GKR only | 12.6 | 12.6 | 0.0 | 0.0 | 0.0 | 0.0 | 72 | 12.6 | 0.0 | 72 |
| deleg_mul | local GKR only | 8.4 | 8.4 | 0.0 | 0.0 | 0.0 | 0.0 | 48 | 8.4 | 0.0 | 48 |
| deleg_sha256_bridge | local GKR + classic global | 1.2 | 0.3 | 0.7 | 0.0 | 0.3 | 0.0 | 7 | 0.3 | 0.9 | 2 |
| truth_arith256_mod | all classic (truth) | 0.2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2 | 1 | 0.0 | 0.2 | 0 |
| deleg_div | local GKR only | 0.1 | 0.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0.1 | 0.0 | 0 |
| truth_sha256 | all classic (truth) | 0.1 | 0.0 | 0.0 | 0.0 | 0.1 | 0.0 | 0 | 0.1 | 0.0 | 0 |
| deleg_arith256_bridge | local GKR + classic global | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0.0 | 0.0 | 0 |
| **total** | | **1,350.1** | | | | | | **7,688** | **611.7** | **738.4** | **3,484** |

MAIN 1,823.9 M; MAIN+INTER 3,173.9 M -> 2,435.6 M (x0.767); INTER x0.453; INTER LDE bits/gas (b2, the unit of the 73k figure) 15,377 -> 6,967.

**Biggest single items (24628607).** Keccak truth `keccak` component, log 18/17/14: 1,152 classic local + 408 KIO
columns (1,560 OM31-coordinate columns) per row; chi table log 21 and xor5 log 16 add 16 local columns each. secp
add/double truths: 5,104 / 4,016 classic local columns at log 13 (they would be 1 binding pair). CPU `initial`
(log 20) and `dword.0` (log 20) RAM columns are the largest CPU global items.

**v1 GKR work [D].** CPU proofs: 40-64 instances per proof (local + one group per global relation), largest instance
2^26 facts, 85-160 M facts per proof vs 102-152 M measured today (`GPU_GKR facts=`): about +10-30 % GKR traversal work
(today 0.14-0.24 s per proof on one 5090). Truth Keccak: 2^27 facts for the log-18 proof (lane log 9: 429 local + KIO
fractions per row). One CPU proof of 24628607 reaches 64 instances = the CUDA `batch_max_oracles` limit; v1 needs that
limit raised to 128 (one constant in the shared traversal; the CPU reference has no limit below 64 and refuses above).

**Leaf-cell delta [E]** (`*-leaf-model.json`, `scripts/rv64_native_gkr_leaf_model.py`, calibrated like the outer-gkr
census): a leaf opens fewer native columns (-37,176 columns over the 17 proofs of 24628607) and verifies more GKR
instances: **-3.41 G leaf cells on 24628607 (-6.4 % of the 53.4 G tree), -1.81 G on 26235156**; secp truth leaves gain
most (-480 M each). Unmeasured until canon-vk wires the leaf hook.

Files: `<block>-census.json` (families, totals, reconciliation, measured words), `<block>-census-declared.json` (raw
per-component census), `<block>-leaf-model.json`. Reproduce on the pod:
`rv64-native-gkr-census <bundle.json> 18 > c.json && python3 -I scripts/rv64_native_gkr_census.py --census c.json --stderr <producer.stderr> --gas <gas> --block <b> --out r.json`.
