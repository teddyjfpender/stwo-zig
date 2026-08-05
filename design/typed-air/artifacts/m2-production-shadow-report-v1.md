# M2 production shadow report

Generated deterministically from the complete production symbolic builder. Counts are per independently compiled opcode family.

| Family | Main cols | DAG source → typed | Merges | Direct | Lookups / batches / interaction cols | Degree D / N / Den / I | Expansion D / I | Relation dependencies |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `base_alu_reg` | 35 | 160 → 160 | 0 | 22 | 18 / 9 / 36 | 3 / 1 / 1 / 3 | 1 / 1 | `registers_state`×2, `memory_access`×6, `program_access`×1, `bitwise`×4, `range_check_20`×3, `range_check_8_8`×2 |
| `base_alu_imm` | 35 | 145 → 145 | 0 | 22 | 16 / 8 / 32 | 3 / 1 / 1 / 3 | 1 / 1 | `registers_state`×2, `memory_access`×4, `program_access`×1, `bitwise`×4, `range_check_20`×2, `range_check_8_11`×1, `range_check_8_8`×2 |
| `shifts_reg` | 60 | 362 → 362 | 0 | 70 | 20 / 10 / 40 | 3 / 1 / 1 / 3 | 1 / 1 | `registers_state`×2, `memory_access`×6, `program_access`×1, `range_check_20`×4, `range_check_8_8`×6, `range_check_m31`×1 |
| `shifts_imm` | 51 | 341 → 341 | 0 | 67 | 16 / 8 / 32 | 3 / 1 / 1 / 3 | 1 / 1 | `registers_state`×2, `memory_access`×4, `program_access`×1, `range_check_20`×2, `range_check_8_8`×6, `range_check_m31`×1 |
| `lt_reg` | 44 | 167 → 167 | 0 | 36 | 14 / 7 / 28 | 3 / 1 / 1 / 3 | 1 / 1 | `registers_state`×2, `memory_access`×6, `program_access`×1, `range_check_20`×4, `range_check_8_8`×1 |
| `lt_imm` | 37 | 163 → 163 | 0 | 33 | 11 / 6 / 24 | 3 / 1 / 1 / 3 | 1 / 1 | `registers_state`×2, `memory_access`×4, `program_access`×1, `range_check_20`×3, `range_check_8_8_4`×1 |
| `branch_eq` | 30 | 102 → 102 | 0 | 18 | 9 / 5 / 20 | 3 / 1 / 2 / 3 | 1 / 1 | `registers_state`×2, `memory_access`×4, `program_access`×1, `range_check_20`×2 |
| `branch_lt` | 37 | 161 → 161 | 0 | 33 | 11 / 6 / 24 | 3 / 1 / 1 / 3 | 1 / 1 | `registers_state`×2, `memory_access`×4, `program_access`×1, `range_check_20`×3, `range_check_8_8`×1 |
| `lui` | 18 | 55 → 55 | 0 | 9 | 7 / 4 / 16 | 2 / 1 / 1 / 3 | 0 / 1 | `registers_state`×2, `memory_access`×2, `program_access`×1, `range_check_20`×1, `range_check_8_8_4`×1 |
| `auipc` | 29 | 108 → 108 | 0 | 17 | 12 / 6 / 24 | 2 / 1 / 1 / 3 | 0 / 1 | `registers_state`×2, `memory_access`×2, `program_access`×1, `range_check_20`×1, `range_check_8_8`×4, `range_check_m31`×2 |
| `jalr` | 41 | 153 → 153 | 0 | 23 | 18 / 9 / 36 | 2 / 1 / 1 / 3 | 0 / 1 | `registers_state`×2, `memory_access`×4, `program_access`×1, `range_check_20`×3, `range_check_8_8_4`×1, `range_check_8_8`×5, `range_check_m31`×2 |
| `jal` | 20 | 60 → 60 | 0 | 10 | 8 / 4 / 16 | 2 / 1 / 1 / 3 | 0 / 1 | `registers_state`×2, `memory_access`×2, `program_access`×1, `range_check_20`×1, `range_check_8_8`×1, `range_check_m31`×1 |
| `load_store` | 48 | 304 → 302 | 2 | 63 | 16 / 8 / 32 | 3 / 1 / 1 / 3 | 1 / 1 | `registers_state`×2, `memory_access`×6, `program_access`×1, `range_check_20`×4, `range_check_m31`×3 |
| `mul` | 39 | 121 → 121 | 0 | 17 | 16 / 16 / 64 | 2 / 1 / 2 / 3 | 0 / 1 | `registers_state`×2, `memory_access`×6, `program_access`×1, `range_check_20`×3, `range_check_8_11`×4 |
| `mulh` | 47 | 210 → 210 | 0 | 24 | 22 / 22 / 88 | 2 / 1 / 2 / 3 | 0 / 1 | `registers_state`×2, `memory_access`×6, `program_access`×1, `range_check_20`×3, `range_check_8_11`×8, `range_check_m31`×2 |
| `div` | 67 | 423 → 423 | 0 | 79 | 25 / 25 / 100 | 3 / 2 / 2 / 3 | 1 / 1 | `registers_state`×2, `memory_access`×6, `program_access`×1, `range_check_20`×4, `range_check_8_11`×8, `range_check_8_8`×3, `range_check_m31`×1 |
| `fence` | 6 | 16 → 16 | 0 | 2 | 3 / 2 / 8 | 2 / 1 / 1 / 3 | 0 / 1 | `registers_state`×2, `program_access`×1 |
| **Independent-family sum / maximum** | **644** | **3051 → 3049** | **2** | **545** | **242 / 155 / 620** | **3 / 2 / 2 / 3** | **1 / 1** | — |

Degree columns are: direct constraint, lookup numerator, relation denominator, and final interaction recurrence. Expansion is the additional log-degree capacity required after division by the trace-domain vanishing polynomial. Shifted-row masks remain degree one; `is_first` is the degree-one boundary selector.

This is a compatibility report, not a production activation receipt. The typed logical manifest does not yet identify the external lookup record or physical layout.
