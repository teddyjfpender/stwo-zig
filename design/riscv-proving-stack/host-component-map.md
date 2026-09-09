# Native19 host composition owner map

Read-only map for the instrumented `fixed_program_narrow_v5` native19 run, PID **75019**. No source edits or additional proof/sample jobs. Binary SHA256 is `b8d1f63e594262b5e86e393bebde90f99e68e8d0749b57a202cd9ec176eaefea`; addresses below apply only to this executable and process. Use the component index plus adapter symbol; a generic adapter address alone cannot distinguish two instances or opcode families.

## Assembly order

`src/frontends/riscv/prover/incremental_ethereum_orchestration_v3.zig:569` assembles the base, then Ethereum extension, then incremental bridge; its final `assembly.active()` goes directly to `Engine.prove`. Despite the filename, this is the shared orchestration consumed by the V4 integration.

Let **S** be actual opcode shard descriptors (`statement.n_components`), **M** be RW memory shards, and **B = 2S + M + 10**. Do not replace S by the 17-family count: zero-count families are omitted, and a populated family can have multiple shards (`statement_geometry.zig:295`). Indices are zero-based **prover adapter indices**, not canonical transcript claim ordinals.

| Component index | Owner |
|---|---|
| `2j`, `2j+1`, `0 <= j < S` | Opcode descriptor j: semantic AIR, then opcode lookup AIR |
| `2S` | Program/fixed-program fetch component |
| `2S+1 .. 2S+M` | RW memory shard components |
| `2S+M+1` | Merkle-node component |
| `2S+M+2` | **Narrow degree-3 Poseidon2 component**, selected by this profile |
| `2S+M+3` | Unified clock update |
| `2S+M+4 .. 2S+M+9` | bitwise, range_check_20, range_check_8_11, range_check_8_8_4, range_check_8_8, range_check_m31 |
| `B .. B+13` | Keccak, chi table, xor5 table, secp product-base, product-scalar, linear-base, linear-scalar, point, split, scalar-program, signed-table, recovery, byte-table, recovery-caller |
| `B+14` | Incremental changed-memory bridge |

Source authorities: `base_component_assembly.zig:448` interleaves the semantic/lookup pair, `:529` walks infrastructure; `:547` selects narrow Poseidon; `guest_precompile/ethereum_assembly.zig:222` appends the exact 14 Ethereum handles; `incremental_ethereum_orchestration_v3.zig:591` appends the bridge. All under `src/frontends/riscv/prover/`. Fixed-program preprocessing adds columns but does not insert a new component handle.

A host row is emitted only for an **unaccelerated whole component**. `component_index` retains its original full-roster index, even though host workers are stored densely. Semantic/lookup GPU partition counts are dispatch partition counts and cannot be used to reconstruct S or B. `eval_log` is the evaluation bound, not necessarily the witness trace log.

## Exact adapter addresses for the live process

The existing one-second sample's Binary Images section gives runtime image base **0x10034c000**. `otool -l` gives linked `__TEXT` vmaddr **0x100000000**. Therefore ASLR slide is **0x34c000**. This table was obtained by read-only `nm -n` on the pinned binary; no execution/build was needed.

| Emitted runtime evaluator | Linked address | AIR adapter owner |
|---|---|---|
| `0x1006b2e80` | `0x100366e80` | `air.guest_precompile.keccakf_component.KeccakShardComponent` |
| `0x1006b3b98` | `0x100367b98` | `air.guest_precompile.keccakf_table_component.KeccakTableComponent` |
| `0x1006b4cc8` | `0x100368cc8` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.Product(.base))` |
| `0x1006b5b54` | `0x100369b54` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.Product(.scalar))` |
| `0x1006b69e0` | `0x10036a9e0` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.Linear(.base))` |
| `0x1006b7848` | `0x10036b848` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.Linear(.scalar))` |
| `0x1006b86b0` | `0x10036c6b0` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.basic("secp256k1_point"[0..15],air.guest_precompile.secp256k1_point_direct,523,416,12,0,air.guest_precompile.secp256k1_component_config.Point__struct_8037))` |
| `0x1006b953c` | `0x10036d53c` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.basic("secp256k1_split"[0..15],air.guest_precompile.secp256k1_split_direct,227,131,3,0,air.guest_precompile.secp256k1_component_config.Split__struct_8070))` |
| `0x1006baa18` | `0x10036ea18` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.basic("secp256k1_scalar_program"[0..24],air.guest_precompile.secp256k1_scalar_direct,1124,1134,7,32,air.guest_precompile.secp256k1_component_config.ScalarProgram__struct_8125))` |
| `0x1006bb8a8` | `0x10036f8a8` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.basic("secp256k1_signed_table"[0..22],air.guest_precompile.secp256k1_table_direct,284,479,3,0,air.guest_precompile.secp256k1_component_config.Table__struct_8159))` |
| `0x1006bcd9c` | `0x100370d9c` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.basic("secp256k1_recovery_v1"[0..21],air.guest_precompile.secp256k1_recovery_direct,517,37,6,81,air.guest_precompile.secp256k1_component_config.Recovery__struct_8252))` |
| `0x1006bdc28` | `0x100371c28` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.ByteTable)` |
| `0x1006bf270` | `0x100373270` | `air.guest_precompile.secp256k1_component.Component(air.guest_precompile.secp256k1_component_config.basic("secp256k1_recovery_caller_v1"[0..28],air.guest_precompile.secp256k1_recovery_caller,292,302,68,0,air.guest_precompile.secp256k1_component_config.RecoveryCaller__struct_7854))` |
| `0x1006c00fc` | `0x1003740fc` | `air.memory_commitment.incremental_bridge_component_v2.IncrementalBridgeComponentV2` |
| `0x1007419fc` | `0x1003f59fc` | `air.semantic_component.SemanticComponent` |
| `0x100757b80` | `0x10040bb80` | `air.lookups.opcode_component.OpcodeLookupComponent` |
| `0x10076b000` | `0x10041f000` | `air.memory_commitment.poseidon2_narrow_component_v1.Component` |
| `0x10076ce7c` | `0x100420e7c` | `air.memory_commitment.hash_component.HashComponent` |
| `0x10076e734` | `0x100422734` | `air.lookups.tables.component.LookupTableComponent` |
| `0x100770394` | `0x100424394` | `air.clock_update_component.ClockUpdateComponent` |
| `0x100771e94` | `0x100425e94` | `air.component.RiscVTraceComponent` |

The logger records the serial vtable adapter address even when `mode=parallel`; it is an owner identity, not necessarily the currently executing parallel entrypoint. For a sampled program counter use `atos` directly:

```sh
xcrun atos -arch arm64 \
  -o .git/local-ethereum/native19-stack-reset-v1/product/bin/ethereum-prepared-leaf-metal-v1 \
  -l 0x10034c000 0xRUNTIME_ADDRESS
```

A future process requires its own image load address. Do not reuse this slide after restart. If a binary is stripped, use the source-order formulas above; never label from the numerically nearest unrelated symbol without an actual symbol range.

## Reading the timing report

Rank `metal composition host` rows by `wall_ns`, join the exact evaluator address against the table, then use component index to distinguish repeated instances. For `scheduler=inline_host`, those calls occur within `host_launch_or_inline`; for `scheduler=pool`, host spans may overlap device preparation and synchronous dispatch. Never add host durations or GPU `gpu_ms` to the phase sum. Device times are existing Metal command timers; phase times are caller wall durations.

The report must have `completed=true` and exact `phase_sum_ns == wall_ns`. Accepted proof identity and fresh verifier results are separate requirements; timing evidence alone is not acceptance. Original composition was 259.335809 s, versus 104.976 ms total semantic+lookup device time. No attribution of that gap is assumed before this run emits its measurements.

## Live Keccak sample: capability and scaling

The retained `composition-host-sample.txt` identifies `KeccakShardComponent.PreparedDomainState.run` under ordinary `Worker.runLegacy`. This is the existing Ethereum Keccak precompile AIR; it is not fallback execution of Keccak guest instructions. Its `asProverComponent` (`air/guest_precompile/keccakf_component.zig:179`) sets only `prepare_domain_evaluator`. It leaves `backend_composition_capability` and `domain_parallel_evaluator` null. Thus the Metal partition selector (`base_polynomial_composition.zig:1237`) sends the complete component to the host regardless of its size. Enabling a GPU flag cannot dispatch a capability that has not been implemented/exported.

The prepared evaluator (`keccakf_component.zig:576`) serially visits every evaluation row. Each row executes the direct constraints, reconstructs `rowPairsBase`, then folds **1,041 secure-field LogUp pair constraints**. The compact plan has **2,082 lookup events and 4,164 interaction columns** (`keccakf_interaction_plan.zig:1,214`). It reduced fixed table universes about 230-fold for latency-oriented shards, but its per-row work scales with the Ethereum shard's evaluation domain. `fixed_program_narrow_v1` raises the admitted Keccak maximum trace log from16 to18 (`prover/ethereum_circuit_profile_v1.zig:22`) without adding a Keccak backend capability. The profiler's `eval_log` implies `1041 * 2^eval_log` pair-constraint evaluations; this is an exact loop count, not a measured time or a proposed new protocol.

The protected canonical RV CSP suite is a different route: `vectors/riscv_csp/manifest-v2.json` records `uses_precompile=false` for Keccak and secp256k1, and `scripts/riscv_csp_benchmark_lib/contract.py:651` rejects any other value. Those guest-crypto workloads use ordinary RV opcode AIRs. They do not exercise this Ethereum Keccak adapter. Separate precompile/autoresearch experiments may show speedups elsewhere; they do not establish a GPU Keccak composition path here.

Wait for terminal per-component timings before attributing the complete259s baseline gap to this sampled component. No kernel, AIR, scheduling, or protocol change is proposed by this read-only map.

## Measured native19 result

The producer completed successfully. This section attributes its actual timing; fresh standalone verification remains a separate acceptance step. Evidence: `.git/local-ethereum/native19-stack-reset-v1/candidate/stderr-and-time.log` and the retained composition sample. No before/after speedup is claimed: this is the first instrumented attribution, and request phases differ from the older baseline.

| Measured region | Wall time |
|---|---:|
| Complete instrumented composition runtime, including cleanup | 311.785765875 s |
| **Keccak index 112**, 7,215 constraints, evaluation log 19 | **278.718263250 s** |
| Other host components combined | about 13.478 s |
| Host launch/inline region | 292.196325958 s |
| Semantic synchronous Metal dispatch | 13.579494833 s |
| Lookup synchronous Metal dispatch | 4.705508708 s |
| Host join | 0.000008459 s |
| Accumulation/finalization | 1.193919917 s |
| Complete prove phase | 410.729736333 s |

Keccak accounts for **89.394% of composition** and **67.859% of proving** in this run. It is the dominant measured work. Even hypothetical elimination of all of this Keccak time alone would cap this prove-phase speedup at about 3.11x; it cannot honestly establish 90% or 99% end-to-end improvement by itself.

GPU device timers are **101.008625 ms semantic** and **21.244625 ms lookup** (122.253250 ms total). They are nested within the synchronous wall calls and are not additive wall phases. Their large difference from synchronous dispatch wall is a separate measured issue; the present sample does not identify which transfer/driver work causes it.

`scheduler=pool` describes a non-null global pool object, not active helper threads. `work_pool.zig:221` returns early for `worker_count == 1` without initializing its thread pool. `WorkPool.spawnWg:275` then calls each worker directly with `@call`. Therefore all host spans are sequential on the caller before AOT/device dispatch, exactly as the timestamps show. This is the unchanged requested worker 1 policy, not a new scheduling regression. The 8.459 microsecond join is consistent with no pending worker jobs.

The measured roster resolves **S=45 opcode shards, M=12 memory shards, B=112 base handles**: program90; memory91–102; Merkle103; narrow Poseidon 104; clock105; lookup tables106–111; Keccak112; chi113; xor5114; secp115–125; bridge126. Narrow Poseidon 104 is absent from the host list because it is accelerated. The sampled dominant work is Keccak's secure-field LogUp loop, not the Poseidon host fallback.

### Keccak geometry-derived column memory (estimate, not measured process memory)

The component's compile-time geometry is 31 preprocessed columns and 2,204 main columns (`keccakf_trace.zig:280`), plus 4,164 base-field interaction coordinate columns (`keccakf_interaction_plan.zig:214`). Measured evaluation log 19 implies trace log 18 through `maxConstraintLogDegreeBound = claim.log_size + 1`. The padded source domain therefore has 262,144 rows and evaluation/LDE domain 524,288 rows. Each M31 value is 4 bytes.

| Column group | Columns | Padded trace payload, bytes | Retained evaluation payload, bytes |
|---|---:|---:|---:|
| Preprocessed | 31 | 32,505,856 | 65,011,712 |
| Main | 2,204 | 2,311,061,504 | 4,622,123,008 |
| Interaction coordinates | 4,164 | 4,366,270,464 | 8,732,540,928 |
| Total | **6,399** | **6,709,837,824 (6.249GiB)** | **13,419,675,648 (12.498GiB)** |

These are exact column-width/domain arithmetic estimates for one component, excluding Merkle trees, metadata, other AIRs, FRI, twiddles, row stack, and allocator overhead. Do not add the trace and LDE totals and call that a simultaneous live allocation. The request reports blowup_log=1 and coefficient retention never. Keccak preparation borrows already matching log 19 `poly.values` (`hash_component_prepared_support.zig:94`); with no retained coefficients, a mismatching source would have failed admission. Thus the successful route does **not** imply another 12.498 GiB copy is allocated by this evaluator. Its secure accumulator output alone is 8,388,608 bytes; source descriptor/state metadata and its 512 KiB certified row stack are additional small owners.

The loop performs 545,783,808 LogUp pair-constraint evaluations and **3,236,954,112** direct-constraint evaluations (`6,174 * 524,288`); all 7,215 constraints total **3,782,737,920**. These are loop-count estimates, not hardware operation counts. The process lifetime peak actually reported was 31,878,078,080 bytes, while current footprint at the host-phase boundary was 26,979,045,464 bytes. Neither is a per-Keccak peak measurement.
