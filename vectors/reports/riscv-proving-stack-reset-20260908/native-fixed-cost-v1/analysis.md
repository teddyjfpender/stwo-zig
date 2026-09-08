# Native fixed-cost attribution: 64-step ADDI/BNE fixture

The retained CPU and Metal profiles measure the same 64 retired instructions (43 ADDI, 21 BNE), with a separately checked 16-step continuation. Native proof size is 27,068 bytes on both backends. These are diagnostic observations, not repeated-run medians or production-security claims: native q1, outer q3, PoW0 are unchanged development parameters.

Inputs: `baseline-cpu-profile.json`, `baseline-metal-profile.json`, `baseline-cpu-build-profile-03.log`, and `baseline-metal-build-profile.log`. The logs also contain later fresh native verification and CPU outer proving; this analysis uses only the first native producer section and its JSON snapshot.

## Registry and measured component work

`src/frontends/riscv/prover/base_component_assembly.zig:447` emits semantic then physical lookup adapters for each opcode family. `opcode_manifest.zig` maps ADDI to `base_alu_imm` and BNE to `branch_eq`. `statement_geometry.zig:270` appends program, optional memory, Merkle, Poseidon2, clock, then the fixed tables in `air/component_order.zig`. This fixture has no memory boundary shard, so there is no memory component between program and Merkle. These are physical registry indices, not canonical transcript claim-slot indices.

| Index | Shared AIR owner | Evaluation rows | CPU task run ms | Metal host task run ms |
| --- | --- | ---: | ---: | ---: |
| 0 | base_alu_imm semantic | 128 | 0.147584 | device partition |
| 1 | base_alu_imm physical lookup | 128 | 0.356292 | device partition |
| 2 | branch_eq semantic | 64 | 0.092792 | device partition |
| 3 | branch_eq physical lookup | 64 | 0.208958 | device partition |
| 4 | program commitment | 16 | 0.161833 | 0.108833 |
| 5 | memory Merkle-node AIR | 512 | 0.591042 | 0.466209 |
| 6 | Poseidon2 AIR | 512 | 3.115375 | 3.097584 |
| 7 | clock update | 32 | 0.155041 | 0.060875 |
| 8 | bitwise table | 524,288 | 3.388792 | 3.319458 |
| 9 | range_check_20 table | 2,097,152 | 36.038041 | 29.711292 |
| 10 | range_check_8_11 table | 1,048,576 | 15.763500 | 20.276875 |
| 11 | range_check_8_8_4 table | 2,097,152 | 11.964875 | 11.930709 |
| 12 | range_check_8_8 table | 131,072 | 2.766166 | 2.336125 |
| 13 | range_check_m31 table | 65,536 | 0.488000 | 0.485250 |

Each event owns one component's contribution; exclusive contribution ownership does not mean exclusive wall time. The fixed-table event intervals happen to be disjoint in both profiles, totaling 70.409374 ms CPU and 68.059709 ms Metal. Other host tasks overlap each other. Summing every task's run gives 75.238291 / 71.793210 ms, while the union of all host run intervals is 73.524749 / 71.157293 ms. Graph wall is 73.550292 / 71.181750 ms. Thus task-run sums must not be added to graph wall or used as a wall-time partition.

Both task snapshots explicitly request and admit 14 workers. The outer receipt's `workers=1` does not establish a one-worker native graph. In `metal/runtime/base_polynomial_composition.zig:436`, enabling structured profiling prepares and drains the host graph before synchronous device dispatch; its schedule differs from ordinary overlapping execution. Missing Metal host events 0–3 identify the device partition, not zero work. No per-component device duration is present in these task snapshots.

## Wall stages and the remaining measurement gap

| Producer interval | CPU ms | Metal ms |
| --- | ---: | ---: |
| Whole native prove call | 5,174.579 | 847.722 |
| Preprocessed stage | 29.392 | 29.209 |
| Main commit stage | 1,316.572 | 335.595 |
| Interaction generation plus commit | 2,600.134 | 146.972 |
| Composition evaluation | 159.904 | 142.283 |
| Composition host graph (nested) | 73.550292 | 71.181750 |
| Composition stage outside graph | 86.353708 | 71.101250 |
| Composition interpolation/split | 5.131 | 2.348 |
| Composition commit | 494.198 | 25.347 |
| Sampled-value evaluation | 42.047 | 22.177 |
| FRI quotient build/commit | 447.281 | 103.172 |

The CPU composition residual remains **86.353708 ms of unattributed preparation/cleanup and other enclosing work**. This is only 1.67% of the 5.175-second native prove call, so resolving it is not the dominant CPU opportunity. The JSON task snapshot alone leaves the Metal residual unresolved, but the retained raw Metal log already supplies a complete disjoint breakdown:

| Metal composition wall phase | ms |
| --- | ---: |
| preparation | 6.411833 |
| host_launch_or_inline | 71.226667 |
| device_preparation | 0.131333 |
| semantic_dispatch | 0.734625 |
| lookup_dispatch | 3.272417 |
| scratch_release | 3.030250 |
| host_wait | 0.021667 |
| partition_parity | 0.044166 |
| device_merge | 0.006334 |
| work_receipt | 0.007500 |
| accumulation | 54.707250 |
| full_parity | 0.042666 |
| publication | 0.006542 |
| cleanup | 2.583000 |
| Sum | 142.226250 |

Every phase starts at the preceding phase's end, and each `wall_ns` equals `end_ns - start_ns`; the sum exactly matches the logged wall total. The enclosing composition stage is 142.283 ms, leaving only 0.056750 ms outside this recorder at the printed stage precision. Host launch/drain encloses the 71.181750-ms task graph with 0.044917 ms of surrounding work. The original 71.101250-ms stage-minus-graph difference therefore reconciles as 70.999583 ms of other recorded phases + 0.044917 ms of host-phase overhead + 0.056750 ms outside the recorder. **Accumulation alone is 54.707250 ms**, the largest non-host-graph phase; it is no longer an unattributed gap. Dispatch values here are host wall intervals, not device kernel times. Per-component host spans are nested inside host launch/drain and must not be added again.

Nested stage children are not additional work: main-stage Merkle commit is 1,294.946 / 309.017 ms; interaction-stage Merkle commit is 2,521.278 / 70.499 ms. Table interaction generation is 56.737 / 55.886 ms inside the interaction stage. Opcode generation's infrastructure child is explicitly overlapped. Deferred Tree0 preparation/commit spans can overlap caller work, and the preprocessed stage can return before its worker finishes; the log labels those worker spans `worker_span_may_overlap=true`. Do not add deferred worker durations to caller stages. Likewise the later ~1-second CPU native verifier has its own Tree0 reconstruction, outside native proving.

The larger native-cost comparison is clear without proportional guesses: lookup interaction generation costs 56.737 ms CPU / 55.886 ms Metal, and the CPU deferred fixed Tree0 worker records 37.728958 ms of preparation (including FFT work, not an exclusive FFT-only timer). CPU main and interaction Merkle children together cost **3,816.224 ms**, versus **379.516 ms** on Metal; these are whole-tree measurements, not table-only hashing measurements. Native Metal completes in 847.722 ms. Fixed lookup generation and CPU generic-composition residuals are much smaller than the measured CPU commitment work. These observations are baseline attribution only; subsequent optimization results belong in their own comparison.

The root-level stage durations sum to 5,132.018 / 814.321 ms, versus enclosing native calls of 5,174.579 / 847.722 ms. Differences are 42.561 / 33.401 ms at the printed precision; these are uncovered caller time, not a measured per-component allocation. Parent/child stage values and worker events must remain separate views.

## Source-derived fixed-table column payload

The six table schemas (`air/lookups/tables/schema.zig`) specify fixed log sizes and arities. `tables/component.zig:51` declares `(1 + arity)` preprocessed columns, one main multiplicity column, and `tables/interaction.zig:16` declares four M31 interaction coordinates. Each M31 occupies four bytes. With the admitted blowup log of 1, dense retained evaluation buffers contain twice the base-row payload. These are payload calculations, not sampled process memory.

| Table | Base log | Tree0 source bytes | Tree1 source bytes | Tree2 source bytes | Dense retained LDE bytes, all three trees |
| --- | ---: | ---: | ---: | ---: | ---: |
| bitwise | 18 | 5,242,880 | 1,048,576 | 4,194,304 | 20,971,520 |
| range_check_20 | 20 | 8,388,608 | 4,194,304 | 16,777,216 | 58,720,256 |
| range_check_8_11 | 19 | 6,291,456 | 2,097,152 | 8,388,608 | 33,554,432 |
| range_check_8_8_4 | 20 | 16,777,216 | 4,194,304 | 16,777,216 | 75,497,472 |
| range_check_8_8 | 16 | 786,432 | 262,144 | 1,048,576 | 4,194,304 |
| range_check_m31 | 15 | 393,216 | 131,072 | 524,288 | 2,097,152 |
| Total | | 37,879,808 | 11,927,552 | 47,710,208 | 195,035,136 |

The fixed tables contribute 97,517,568 bytes (93 MiB) of base-row values and 195,035,136 bytes (186 MiB) of dense LDE values. The default scheme retains coefficients (`pcs/scheme.zig:114`, policy `.always`), so the corresponding coefficient-plus-LDE payload model is 292,552,704 bytes (279 MiB). This excludes metadata, Merkle layers, temporary FFT/composition/FRI allocations, worker stacks, and device storage. Original source buffers need not remain live alongside coefficients; do not add another 93 MiB without a lifetime measurement.

This table subtotal is independently derived, not apportioned from whole-tree sizes. For example, the native Tree0 log reports 37,884,864 source bytes and 75,769,728 LDE bytes for all 32 columns; fixed tables account for 37,879,808 and 75,759,616 bytes respectively, leaving 5,056 / 10,112 bytes for the non-table prefix. The source-census records explicitly say `payload_is_allocator_live=false`; they describe logical payload, not simultaneously live allocations. The separate native caller-allocator peak of 459,292,864 bytes likewise excludes size-routed mmap and device allocations and is not a table-only measurement.

This establishes fixed lookup domains as a substantial retained-memory floor and measured host-composition cost. It does not justify multiplying table-byte fractions by whole-tree Merkle duration: shared tree hashing, unequal column heights, preparation, and scheduling prevent that attribution without a direct measurement.


## Selected optimization and attribution check

The selected change batches four independent Poseidon states using canonical M31 SIMD arithmetic. Its three ownership layers are the shared [canonical `permute4`](../../../../src/frontends/riscv/air/memory_commitment/poseidon2.zig), the [recursive Merkle leaf/node hooks](../../../../src/frontends/riscv/recursion/poseidon2_channel.zig), and generic PCS consumers ([streaming leaves](../../../../src/prover/vcs_lifted/leaves.zig), [node layers](../../../../src/prover/vcs_lifted/layers.zig)). `permute4` consumes the existing round constants and matrices; the hooks retain existing leaf/node framing and digest extraction. The generic consumers select supported hooks and retain scalar remainders. No AIR constraints, transcript ordering, commitment parameters, or proof query counts changed.

The first native producer in `optimized-cpu-build-profile-02.log` and `optimized-cpu-profile.json` can be compared with the baseline producer above:

| CPU measured interval | Baseline ms | Optimized ms | Difference ms |
| --- | ---: | ---: | ---: |
| Main-stage Merkle child | 1,294.946 | 554.930 | -740.016 |
| Interaction-stage Merkle child | 2,521.278 | 903.883 | -1,617.395 |
| These two disjoint children combined | 3,816.224 | 1,458.813 | -2,357.411 |
| Deferred Tree0 worker preparation | 37.728958 | 36.072666 | -1.656292 |
| Deferred Tree0 worker Merkle admission | 1,051.805750 | 368.554000 | -683.251750 |
| Composition evaluation | 159.904 | 161.109 | +1.205 |
| Enclosing native prove call | 5,174.579 | 2,385.549 | -2,789.030 |

Main/interaction Merkle children shrink by **61.77%**, removing 2.357 seconds from those measured intervals. Deferred Tree0 Merkle admission separately shrinks by **64.96%** while its preparation remains approximately 36–38 ms. **Do not add that 683-ms worker reduction to the 2.357-second child reduction**: deferred Tree0 overlaps caller work and can be paid inside another stage's wait. Its second worker record belongs to the later fresh CPU verifier and is excluded here. Composition evaluation is essentially unchanged in this observation, supporting commitment hashing as the measured optimization target rather than assigning the benefit to AIR evaluation.

These are single profiled observations with diagnostics and the structured host scheduler enabled, not medians. The unprofiled 64-step CPU native medians are 5,267.121 → 2,418.518 ms (54.08% reduction); full-request medians are 8.963 → 5.340 seconds. The complete median comparison is retained in `results.md`/`summary.json`. Host-side SIMD also benefits fresh CPU verification and the CPU outer proof when native proving uses Metal; it does not establish an improvement in Metal device kernel time.
