# P-002 native typed-family static profiles

> Shadow/profile evidence only. This report does not activate a typed definition in the production prover, alter a proof statement, or contain runtime performance telemetry.

## Identity and authority

| Field | Value |
| --- | --- |
| Schema | `stwo.typed-air.native-family-static-profile.v1` v1 |
| Report SHA-256 | `0dd67acd8705f77a5c482a8d3706b38929d799091b3971e995b20dcc44f56772` |
| Families | 17, in production protocol enum order |
| Native program authority | `native_typed_definition` |
| Production activation | `not_assessed` |
| Lookup geometry authority | `current_audited_protocol` |

## Aggregate static facts

| Coordinate | Sum or maximum |
| --- | ---: |
| Physical main columns | 644 |
| Logical input nodes | 677 |
| Direct constraint roots | 545 |
| Typed effects / lookup events | 242 / 242 |
| Lookup batches / interaction coordinates | 155 / 620 |
| Expression DAG nodes / edges / shared nodes | 3079 / 4370 / 649 |
| Reachable / outside-closure nodes | 3034 / 45 |
| Maximum degree: direct / numerator / denominator / interaction | 3 / 2 / 2 / 3 |

## Family profiles

Degree columns are logical value, direct constraint, lookup numerator, lookup denominator, and modeled interaction degree. DAG columns are nodes, edges, structurally shared nodes, and nodes outside the constraint/effect closure.

| # | Family | Native definition | Program SHA-256 | Main / inputs | Roots | Lookups / batch / batches / interaction | Degrees V/C/N/Den/I | DAG N/E/S/O |
| ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 0 | `base_alu_reg` | `typed_base_alu_reg` | `f8cf9c0b60b41fc948ec7c5efd61caf5abf96ec30f242c6a375845ab905e61c5` | 35 / 36 | 22 | 18 / 2 / 9 / 36 | 3/3/1/1/3 | 154/214/32/0 |
| 1 | `base_alu_imm` | `typed_addi` | `77cac74f85ee61abc8aa1ab97ee37c3f1fddb61eda7c9c982f166c75122908a6` | 35 / 36 | 22 | 16 / 2 / 8 / 32 | 3/3/1/1/3 | 147/186/26/0 |
| 2 | `shifts_reg` | `typed_shifts_reg` | `c40d1f981405a9108fe64ca3a4ec0037aa6c006733e9edd0ceb4787a4687ae09` | 60 / 65 | 70 | 20 / 2 / 10 / 40 | 3/3/1/1/3 | 369/566/68/6 |
| 3 | `shifts_imm` | `typed_shifts_imm` | `6eda0a9643861c820271cde92eb3c8f5ac99c7efbffd5a25ef0865a249e454df` | 51 / 56 | 67 | 16 / 2 / 8 / 32 | 3/3/1/1/3 | 347/540/65/5 |
| 4 | `lt_reg` | `typed_lt_reg` | `e28ede4abf49917335d8ecec6e4f5c6bfdea3e4e8f967501313a95dad4d703b0` | 44 / 45 | 36 | 14 / 2 / 7 / 28 | 3/3/1/1/3 | 168/224/41/4 |
| 5 | `lt_imm` | `typed_lt_imm` | `21a4a1214f2ed1e8cb6cc311434a6114d5faf3c3e91dff3229835b1316084551` | 37 / 38 | 33 | 11 / 2 / 6 / 24 | 3/3/1/1/3 | 163/224/41/4 |
| 6 | `branch_eq` | `typed_branch_eq` | `4b7ac248bf672d93a01cbd659e59a7a98f1ec81ab5b50dd29090ca8816e49b09` | 30 / 31 | 18 | 9 / 2 / 5 / 20 | 3/3/1/2/3 | 100/123/23/1 |
| 7 | `branch_lt` | `typed_branch_lt` | `262eae1d57530034e41143c0c5961e3c7826d0e5c3af69a0b656ede2d0eeeded` | 37 / 40 | 33 | 11 / 2 / 6 / 24 | 3/3/1/1/3 | 164/223/42/3 |
| 8 | `lui` | `typed_lui` | `3f69a47662e9216f86c03bba257b52fb280542af610972a4c98cf7630252fd68` | 18 / 19 | 9 | 7 / 2 / 4 / 16 | 2/2/1/1/3 | 51/50/9/0 |
| 9 | `auipc` | `typed_auipc` | `b65eb0279c680db06f9fe36f4bbf3db1f1c99d913afb5e0a0e00e3a1b0f9abfe` | 29 / 31 | 17 | 12 / 2 / 6 / 24 | 2/2/1/1/3 | 106/132/25/1 |
| 10 | `jalr` | `typed_jalr` | `9e374e33bcc65926240d5181eac52bad8b57b699097a211425715ba372a86f28` | 41 / 43 | 23 | 18 / 2 / 9 / 36 | 2/2/1/1/3 | 159/197/37/2 |
| 11 | `jal` | `typed_jal` | `0677d8ecf741d37f938ae0f77e647e782952fbec11a8f07702e62d6980735dc5` | 20 / 22 | 10 | 8 / 2 / 4 / 16 | 2/2/1/1/3 | 59/61/12/1 |
| 12 | `load_store` | `typed_load_store` | `ec8aefea7299e84a480524c3848c1ccc73241caea4e89f983f7c2605e6b04e90` | 48 / 52 | 63 | 16 / 2 / 8 / 32 | 3/3/1/1/3 | 312/476/73/9 |
| 13 | `mul` | `typed_mul` | `0d93e601535fa7ec6cb6c744afbf72418f12ca68cbbd16dc18a9fea4b33bfce4` | 39 / 40 | 17 | 16 / 1 / 16 / 64 | 2/2/1/2/3 | 119/142/22/1 |
| 14 | `mulh` | `typed_mulh` | `00d717cfbaa5ba3f82604ce9fdedd1e3f4de1ede56d3fe09ddd835d3118c0e7b` | 47 / 48 | 24 | 22 / 1 / 22 / 88 | 2/2/1/2/3 | 214/306/44/3 |
| 15 | `div` | `typed_div` | `a33fd73890a391f954566eac75c54111c3ab5da54f20554ce095f7083b9e3ec2` | 67 / 68 | 79 | 25 / 1 / 25 / 100 | 3/3/2/2/3 | 433/698/88/5 |
| 16 | `fence` | `typed_fence` | `ed5fd16042ad5918b843e6afd45393d527b0dfb3dfba2dcf29fe93caf041d3f2` | 6 / 7 | 2 | 3 / 2 / 2 / 8 | 2/2/1/1/3 | 14/8/1/0 |

The machine TSV carries every field in the complete P-001 static-profile schema. `null` materialization and source-CSE coordinates mean that no materialization plan or pre-interning provenance was supplied; they do not mean zero work. Layout, batching, batch count, interaction-column count, and degree coordinates are regenerated against the audited production shadow report before reviewed artifact bytes are admitted.
