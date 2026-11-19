# RV64 flag lifecycle review

Issue [#332](https://github.com/starknet-innovation/stwo-zig/issues/332). This inventories the 99 live names before this slice; thirty-six genuine removals leave 63. It is not a declaration that the `<60` promotion gate passes. Constants and historical reference-only symbols are excluded from the starting 99.

The existing registry owns exact source paths, absence defaults, expiry and generated reference sets. No second configuration registry or launcher is introduced. All full names below have prefix `STWO_RV64_`.

## Landed subtraction

- Division and multiplication reference evaluators now execute unconditionally alongside optimized evaluators in the existing physical proof and rejection cases. Division uses artifact-selected production parameters for both; only optimized artifacts are published. Physical proof reruns are **UNRUN** locally; syntax, metadata and Python conformance checks pass.
- The harness environment block allowlist duplicated the existing repeated `--allow-block` option. The environment reader is removed. Its retired-input negative test proves that an inherited value cannot authorize a block; explicit CLI authorization and service/repeat restrictions remain. Focused gate and registry tests pass.

- The GPU GKR parity harness now requires separate, fold/sum-fused and small-tail-fused execution on every invocation. Every variant retains the full positive and poison matrix, independent expected artifacts, and route-use assertions. CUDA compilation and hardware replay remain **UNRUN**.
- Recorded fold children now derive from unique predecessor FIXED+MAIN root pairs in the parent seed tape, with ambiguity, duplicate, missing and geometry refusals. The external tree override is removed; existing host/device seed, output and checkpoint comparisons remain. Actual real-record replay remains **UNRUN**.

- Standalone outer recursion now uses the existing `GPU_DEVICES` list selector, requiring exactly one ID through the shared parser; the duplicate singular selector is removed. Default ordinal0 and device budget are unchanged. Its entrypoint tests are registered; full entrypoint execution remains **UNRUN** locally.

## Remaining dependency

26 names are frozen behind ordered GPU-native promotion. Eleven stronger physical-artifact consumers remain protected under one common run-root selector, with fixed provider directories. Reaching 59 now requires **4 more genuine reductions** from the remaining 63 controls. Changing live controls to reference-only, renaming them, moving independent choices into one JSON switch, selecting an unqualified GPU path by default, or deleting negative coverage does not meet that requirement.

The inventory does **not** establish a mathematical minimum of 60. Several controls can eventually disappear through compulsory test variants, deterministic ownership decisions, or qualified native-default retirement. Those replacements require engineering and qualification; a missing maintained literal setter is not proof that a runtime branch is dead.

The eleven integration-preset optimization switches are particularly concrete blockers to immediate default-hardcoding: seed tape, packed fold cache, compact CPU ingress, sampled-Blake prefill, CPU replay, narrow runs, assignment graph, owner controller, rolling beta-2 PCS, phase cache trim, and packed class ingress. Their native/job route gates remain protected separately. Presets select those non-default paths; deleting them loses maintained coverage, while selecting them unconditionally promotes an unqualified GPU route. They are not asserted to be eleven logically independent protocol requirements.

## Next coherent reductions

1. Qualify the mandatory three-variant GPU parity harness and recorded-root association against retained real recordings on an authorized GPU. The stricter source is implemented; hardware acceptance is not claimed.
2. Consolidate duplicate legacy standalone and resident resource admission through the existing typed request owner. Establish equivalence for device selection, capacity, workers, scopes and cache reservation before removing environment overrides. Merely moving their independent choices into a manifest is not a reduction.
3. Keep recorded fixture association bound to actual source roots. Missing, ambiguous, duplicate or non-predecessor child matches fail closed; no neighbouring tree-file heuristic is used.
4. Retire measured losing optimization variants with matching full-path evidence. PACK_FOLD_CACHE was active; its input has now been replaced with deterministic byte-cost selection while both raw and compressed representations remain.

## Complete starting inventory

| Suffix | Purpose and disposition | Owner | Preset values |
|---|---|---|---|
| `ALLOCATION_OBSERVER` | Opt-in actual CUDA allocation accounting; node-observer qualification explicitly enables it. | [device_arena_runtime.cuh](../../src/backends/cuda/native/runtime/device_arena_runtime.cuh) | none in maintained presets |
| `ARITH_NONE_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_arithmetic_roster_test.zig](../../src/integrations/riscv_cpu/tests/rv64_arithmetic_roster_test.zig) | none in maintained presets |
| `BLAKE_SAMPLE_PREFILL` | Capture sampled-value Blake inputs and prefill/elide GPU numerical GG tasks; native install explicitly disables it. | [blake_sample_capture.zig](../../src/integrations/riscv_cpu/rv64_recursion/om31_native/blake_sample_capture.zig) | 1 |
| `CPU_COMPACT_INGRESS` | Choose compact capture transfer and GPU unpack, versus expanded host ingress. | [cpu_projection.zig](../../src/integrations/riscv_cuda/rv64/cpu_projection.zig) | 1 |
| `DEVICE_ARENA` | Set global native allocator admission/physical memory policy; frozen admission requires explicit arena. | [device_arena_runtime.cuh](../../src/backends/cuda/native/runtime/device_arena_runtime.cuh) | auto, auto |
| `DIVISION_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_division_proof_test.zig](../../src/integrations/riscv_cpu/tests/rv64_division_proof_test.zig) | none in maintained presets |
| `DIVISION_REFERENCE` | Select reference rather than optimized division evaluator; now both run unconditionally. **Retired in this slice.** | [rv64_division_proof_test.zig](../../src/integrations/riscv_cpu/tests/rv64_division_proof_test.zig) | none in maintained presets |
| `ETH_CPU_V1_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_ethereum_cpu_proof_test.zig](../../src/products/ethereum/statement/cpu/tests/rv64_ethereum_cpu_proof_test.zig) | none in maintained presets |
| `ETH_CPU_V2_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_ethereum_cpu_proof_test.zig](../../src/products/ethereum/statement/cpu/tests/rv64_ethereum_cpu_proof_test.zig) | none in maintained presets |
| `FOLD_ARITY` | Choose producer/receiver fold topology; profile mismatches and malformed overrides are negative-corpus cases. | [ready_dag.zig](../../src/integrations/riscv_cpu/rv64_recursion/om31_native/ready_dag.zig) | none in maintained presets |
| `FOLD_CLASS_CACHE` | Choose fold topology/key caching; repeated-job and negative-corpus controls explicitly set it. | [execution_wrap_ownership.zig](../../src/integrations/riscv_cpu/rv64_recursion/om31_native/execution_wrap_ownership.zig) | none in maintained presets |
| `GPU_BYTE_CAP` | Set legacy single-device/hybrid allocation ceiling; basket derives its value from worker capacity. | [rv64_hybrid_ethereum_main.zig](../../src/products/ethereum/statement/cuda/rv64_hybrid_ethereum_main.zig) | none in maintained presets |
| `GPU_COMPOSITION_HELPER` | Select optional subprocess composition offload; no maintained setter found, but live route remains. | [rv64_hybrid_ethereum_main.zig](../../src/products/ethereum/statement/cuda/rv64_hybrid_ethereum_main.zig) | none in maintained presets |
| `GPU_CPU_REPLAY` | Choose retained device-ledger CPU replay; rejects unless device trace and binding are selected. | [resident_pool.zig](../../src/products/ethereum/statement/cuda/rv64/resident_pool.zig) | 1 |
| `GPU_DEVICE` | Duplicate standalone selector removed; existing GPU_DEVICES parser requires exactly one ordinal. **Retired in this slice.** | [rv64_outer_recursion_main.zig](../../src/products/ethereum/statement/cuda/rv64_outer_recursion_main.zig) | none in maintained presets |
| `GPU_DEVICES` | Select one or more resident-worker CUDA ordinals; basket supplies routed worker devices. | [mod.zig](../../src/integrations/riscv_cuda/rv64/jobs/mod.zig) | none in maintained presets |
| `GPU_DEVICE_BINDING` | Select device binding stage; fully resident and replay modes require its presence. | [resident_batch.zig](../../src/products/ethereum/statement/cuda/rv64/resident_batch.zig) | none in maintained presets |
| `GPU_DEVICE_CAPS` | Per-device admission ceilings; validated against router and combined-recursion geometry. | [resident_batch.zig](../../src/products/ethereum/statement/cuda/rv64/resident_batch.zig) | none in maintained presets |
| `GPU_DEVICE_TRACE` | Select device trace generation; fully resident and replay modes require its presence. | [resident_batch.zig](../../src/products/ethereum/statement/cuda/rv64/resident_batch.zig) | none in maintained presets |
| `GPU_HOST_RETAINED` | Select legacy host-retained comparison; fully resident entrypoints explicitly reject presence. | [resident_batch.zig](../../src/products/ethereum/statement/cuda/rv64/resident_batch.zig) | none in maintained presets |
| `GPU_LIBRARY` | Select native base shared library; missing library prevents native/resident route setup. | [rv64_combined_ethereum_main.zig](../../src/products/ethereum/statement/cuda/rv64_combined_ethereum_main.zig) | none in maintained presets |
| `GPU_PCS_HELPER` | Select legacy subprocess PCS executable; required in hybrid helper route. | [rv64_hybrid_ethereum_main.zig](../../src/products/ethereum/statement/cuda/rv64_hybrid_ethereum_main.zig) | none in maintained presets |
| `GPU_PLANNED_CPU_WORKERS` | Declare legacy combined worker admission; batch manifest instead owns worker schedule. | [rv64_combined_ethereum_main.zig](../../src/products/ethereum/statement/cuda/rv64_combined_ethereum_main.zig) | none in maintained presets |
| `GPU_RETAINED_SCOPES` | Bound simultaneous retained router scopes per device, validated against requested CPU workers. | [resident_router.zig](../../src/integrations/riscv_cuda/rv64/resident_router.zig) | none in maintained presets |
| `GPU_WORKDIR` | Select legacy helper export/job directory; required for its file-based handoff. | [rv64_hybrid_ethereum_main.zig](../../src/products/ethereum/statement/cuda/rv64_hybrid_ethereum_main.zig) | none in maintained presets |
| `HARNESS_ALLOW_BLOCKS` | Duplicate explicit block-owner authorization; removed, existing repeated --allow-block CLI retained. **Retired in this slice.** | [rv64_m4_resident.py](../../scripts/rv64/rv64_m4_resident.py) | none in maintained presets |
| `KECCAK_CPU_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_keccak_cpu_proof_test.zig](../../src/integrations/riscv_cpu/tests/rv64_keccak_cpu_proof_test.zig) | none in maintained presets |
| `KECCAK_CPU_CYCLIC_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_keccak_cpu_proof_test.zig](../../src/integrations/riscv_cpu/tests/rv64_keccak_cpu_proof_test.zig) | none in maintained presets |
| `KECCAK_CPU_NONE_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_keccak_roster_test.zig](../../src/integrations/riscv_cpu/tests/rv64_keccak_roster_test.zig) | none in maintained presets |
| `LEAF_SEED_TAPE` | Choose off/on/check leaf seed cache; check compares every seed against full graph. | [leaf_tape.zig](../../src/integrations/riscv_cpu/rv64_recursion/om31_native/leaf_tape.zig) | 1 |
| `LEAN_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_lean_proof_test.zig](../../src/integrations/riscv_cpu/tests/rv64_lean_proof_test.zig) | none in maintained presets |
| `M8_AOT_REGISTER_SCHEDULE` | Native-default retirement gate: aot register schedule; retain until ordered promotion gates pass. | [rv64_m8_aot_register_relink.py](../../scripts/rv64/rv64_m8_aot_register_relink.py) | none in maintained presets |
| `M8_DEEP_LEGACY` | Native-default retirement gate: deep legacy; retain until ordered promotion gates pass. | [deep.cu](../../src/backends/cuda/native/rv64/deep.cu) | none in maintained presets |
| `M8_FAULT_INJECTION` | Native-default retirement gate: fault injection; retain until ordered promotion gates pass. | [outer_checks.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_checks.zig) | none in maintained presets |
| `M8_GN_INSTALL` | Native-default retirement gate: gn install; retain until ordered promotion gates pass. | [outer_node_prover.zig](../../src/integrations/riscv_cuda/rv64/outer_node_prover.zig) | none in maintained presets |
| `M8_GN_NODE` | Native-default retirement gate: gn node; retain until ordered promotion gates pass. | [outer_seed_record.zig](../../src/integrations/riscv_cuda/rv64/outer_seed_record.zig) | none in maintained presets |
| `M8_GN_NODE_FAULT_ORDINAL` | Native-default retirement gate: gn node fault ordinal; retain until ordered promotion gates pass. | [outer_node_checks.zig](../../src/integrations/riscv_cuda/rv64/outer_node_checks.zig) | none in maintained presets |
| `M8_GN_NODE_RECORD` | Native-default retirement gate: gn node record; retain until ordered promotion gates pass. | [outer_seed_record.zig](../../src/integrations/riscv_cuda/rv64/outer_seed_record.zig) | none in maintained presets |
| `M8_GN_NODE_RECORDS` | Select recorded real-node fixture directory; absence skips the piece-only node harness. | [outer_seed_harness_test.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_seed_harness_test.zig) | none in maintained presets |
| `M8_GN_NODE_TREE` | External recursion-tree override removed; ordered children derive from recorded root pairs. **Retired in this slice.** | [outer_seed_harness_test.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_seed_harness_test.zig) | none in maintained presets |
| `M8_GN_PACK_RECORD` | Native-default retirement gate: gn pack record; retain until ordered promotion gates pass. | [gn_pack_record.zig](../../src/integrations/riscv_cuda/rv64/gn_pack_record.zig) | none in maintained presets |
| `M8_GN_PACK_RECORDS` | Select one or more real segment recording directories for GPU pack parity harness. | [native_pack_gpu_test.zig](../../src/integrations/riscv_cuda/rv64/jobs/native_pack_gpu_test.zig) | none in maintained presets |
| `M8_GN_PACK_RECORD_MAIN` | Native-default retirement gate: gn pack record main; retain until ordered promotion gates pass. | [gn_pack_record.zig](../../src/integrations/riscv_cuda/rv64/gn_pack_record.zig) | none in maintained presets |
| `M8_GN_SHAPE_MISS_BLOCK` | Native-default retirement gate: gn shape miss block; retain until ordered promotion gates pass. | [rv64_resident_class_setup_parity_main.zig](../../src/products/ethereum/statement/cuda/rv64_resident_class_setup_parity_main.zig) | none in maintained presets |
| `M8_GN_SHAPE_MISS_REQUEST` | Native-default retirement gate: gn shape miss request; retain until ordered promotion gates pass. | [rv64_resident_class_setup_parity_main.zig](../../src/products/ethereum/statement/cuda/rv64_resident_class_setup_parity_main.zig) | none in maintained presets |
| `M8_GPU_BASE` | Uses the existing GPU_LIBRARY base-ABI selector; JOBS_LIBRARY remains separate. **Retired in the next tranche.** | [native_gpu_support_test.zig](../../src/integrations/riscv_cuda/rv64/jobs/native_gpu_support_test.zig) | none in maintained presets |
| `M8_GPU_NATIVE` | Native-default retirement gate: gpu native; retain until ordered promotion gates pass. | [driver.zig](../../src/integrations/riscv_cuda/rv64/jobs/driver.zig) | 1 |
| `M8_GPU_NATIVE_REUSE` | Native-default retirement gate: gpu native reuse; retain until ordered promotion gates pass. | [driver_ge.zig](../../src/products/ethereum/statement/cuda/rv64/jobs/driver_ge.zig) | 1 |
| `M8_JOBS` | Native-default retirement gate: jobs; retain until ordered promotion gates pass. | [mod.zig](../../src/integrations/riscv_cuda/rv64/jobs/mod.zig) | 1 |
| `M8_JOBS_ARENA_BYTES` | Native-default retirement gate: jobs arena bytes; retain until ordered promotion gates pass. | [mod.zig](../../src/integrations/riscv_cuda/rv64/jobs/mod.zig) | none in maintained presets |
| `M8_JOBS_LIBRARY` | Native-default retirement gate: jobs library; retain until ordered promotion gates pass. | [driver_ge.zig](../../src/products/ethereum/statement/cuda/rv64/jobs/driver_ge.zig) | /workspace/m3/build/m8-gn-codec/addon-5/libstwo-rv64-jobs.so, a8691a96b4192036147e9810e0ab4a5ada929cb55726d2d876a047774c9cfebb |
| `M8_JOBS_PINNED_BYTES` | Native-default retirement gate: jobs pinned bytes; retain until ordered promotion gates pass. | [mod.zig](../../src/integrations/riscv_cuda/rv64/jobs/mod.zig) | 2365587456 |
| `M8_JOBS_PLAN` | Native-default retirement gate: jobs plan; retain until ordered promotion gates pass. | [plan.zig](../../src/integrations/riscv_cuda/rv64/jobs/plan.zig) | none in maintained presets |
| `M8_JOBS_PLAN_DIR` | Retired destination: explicit parity fixtures publish final plans to their typed OUT/class-plans. | [plan.zig](../../src/integrations/riscv_cuda/rv64/jobs/plan.zig) | none in maintained presets |
| `M8_OUTER_CHECK_FAULT_ORDINAL` | Native-default retirement gate: outer check fault ordinal; retain until ordered promotion gates pass. | [outer_checks.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_checks.zig) | none in maintained presets |
| `M8_OUTER_CLASS_PLAN` | Native-default retirement gate: outer class plan; retain until ordered promotion gates pass. | [outer_class_plan.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_class_plan.zig) | none in maintained presets |
| `M8_OUTER_DECLARE_WORDS` | Native-default retirement gate: outer declare words; retain until ordered promotion gates pass. | [outer_job.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_job.zig) | none in maintained presets |
| `M8_OUTER_DEVICE_CHECKS` | Native-default retirement gate: outer device checks; retain until ordered promotion gates pass. | [outer_checks.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_checks.zig) | none in maintained presets |
| `M8_OUTER_DEVICE_ENCODE` | Native-default retirement gate: outer device encode; retain until ordered promotion gates pass. | [outer_encode.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_encode.zig) | none in maintained presets |
| `M8_OUTER_ENCODE_FAULT_ORDINAL` | Native-default retirement gate: outer encode fault ordinal; retain until ordered promotion gates pass. | [outer_encode.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_encode.zig) | none in maintained presets |
| `M8_OUTER_FAULT_ORDINAL` | Native-default retirement gate: outer fault ordinal; retain until ordered promotion gates pass. | [outer_hybrid_owner.zig](../../src/integrations/riscv_cuda/rv64/outer_hybrid_owner.zig) | none in maintained presets |
| `M8_OUTER_FS_LIBRARY` | Native-default retirement gate: outer fs library; retain until ordered promotion gates pass. | [native_recursion_install.zig](../../src/products/ethereum/statement/cuda/rv64/native_recursion_install.zig) | /workspace/m3/build/m8-gn-bind/addon-4/libstwo-rv64-outer-fs-ops.so, ba6ffb21ab246b72ab3d23950d20c24f14039cc9d3f54d07ed6e3129cc5f4677 |
| `M8_OUTER_OODS_FAULT_ORDINAL` | Native-default retirement gate: outer oods fault ordinal; retain until ordered promotion gates pass. | [outer_encode.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_encode.zig) | none in maintained presets |
| `M8_OUTER_OODS_POINT_FAULT_ORDINAL` | Native-default retirement gate: outer oods point fault ordinal; retain until ordered promotion gates pass. | [outer_encode.zig](../../src/integrations/riscv_cuda/rv64/jobs/outer_encode.zig) | none in maintained presets |
| `M8_PARITY_COMPOSITION` | Native-default retirement gate: parity composition; retain until ordered promotion gates pass. | [rv64_native_producer_parity_main.zig](../../src/products/ethereum/statement/cuda/rv64_native_producer_parity_main.zig) | none in maintained presets |
| `M8_PARITY_DEVICE` | Native-default retirement gate: parity device; retain until ordered promotion gates pass. | [rv64_resident_class_setup_parity_main.zig](../../src/products/ethereum/statement/cuda/rv64_resident_class_setup_parity_main.zig) | none in maintained presets |
| `M8_PARITY_DEVICE_CLAIMS` | Native-default retirement gate: parity device claims; retain until ordered promotion gates pass. | [rv64_native_producer_parity_main.zig](../../src/products/ethereum/statement/cuda/rv64_native_producer_parity_main.zig) | none in maintained presets |
| `M8_PARITY_ONLY` | Native-default retirement gate: parity only; retain until ordered promotion gates pass. | [rv64_native_producer_parity_main.zig](../../src/products/ethereum/statement/cuda/rv64_native_producer_parity_main.zig) | none in maintained presets |
| `M8_PARITY_PCS` | Native-default retirement gate: parity pcs; retain until ordered promotion gates pass. | [rv64_native_producer_parity_main.zig](../../src/products/ethereum/statement/cuda/rv64_native_producer_parity_main.zig) | none in maintained presets |
| `M8_PARITY_SOURCE_DEVICE` | Native-default retirement gate: parity source device; retain until ordered promotion gates pass. | [rv64_resident_stage_two_parity_main.zig](../../src/products/ethereum/statement/cuda/rv64_resident_stage_two_parity_main.zig) | none in maintained presets |
| `M8_PCS_SCALE` | Opt into native-segment-sized GPU PCS scale parity, skipped otherwise. | [native_pcs_scale_test.zig](../../src/integrations/riscv_cuda/rv64/jobs/native_pcs_scale_test.zig) | none in maintained presets |
| `M8_REQUIRE_GPU` | Make missing GPU libraries a failure instead of an optional test skip; receipt integrity guard. | [native_gpu_support_test.zig](../../src/integrations/riscv_cuda/rv64/jobs/native_gpu_support_test.zig) | none in maintained presets |
| `M8_SAMPLE_LEGACY` | Native-default retirement gate: sample legacy; retain until ordered promotion gates pass. | [samples.cu](../../src/backends/cuda/native/rv64/samples.cu) | none in maintained presets |
| `M8_TAIL_POW_BITS` | Tail parity now obligatorily exercises pow0 and pow20; q8 remains diagnostic. **Retired in the next tranche.** | [native_tail_test.zig](../../src/integrations/riscv_cuda/rv64/jobs/native_tail_test.zig) | none in maintained presets |
| `M8_TRUTH_SPLIT` | Native-default retirement gate: truth split; retain until ordered promotion gates pass. | [truth_plan.zig](../../src/products/ethereum/statement/cpu/word16_global_execution/ethereum/truth_plan.zig) | none in maintained presets |
| `M9_CLASS_PACKED_INGRESS` | Choose compressed class upload/device unpack and matching resource prewarm. | [driver_ge.zig](../../src/products/ethereum/statement/cuda/rv64/jobs/driver_ge.zig) | 1 |
| `MULTIPLICATION_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_multiplication_proof_test.zig](../../src/integrations/riscv_cpu/tests/rv64_multiplication_proof_test.zig) | none in maintained presets |
| `MULTIPLICATION_REFERENCE` | Select reference rather than optimized MUL evaluator; now both run unconditionally. **Retired in this slice.** | [rv64_multiplication_proof_test.zig](../../src/integrations/riscv_cpu/tests/rv64_multiplication_proof_test.zig) | none in maintained presets |
| `MUL_CPU_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_keccak_cpu_proof_test.zig](../../src/integrations/riscv_cpu/tests/rv64_keccak_cpu_proof_test.zig) | none in maintained presets |
| `NATIVE_VERSION` | Select distinct native manifest/roster protocol; unknown or unimplemented versions fail closed. | [native_policy.zig](../../src/integrations/riscv_cpu/word16_execution/native_policy.zig) | v1-flat |
| `NVTX` | Opt into CUDA profiling annotation; integration preset enables it. | [pcs_pipeline.cuh](../../src/backends/cuda/native/rv64/pcs_pipeline.cuh) | 1 |
| `OUTER_ASSIGNMENT_GRAPH` | Choose cached numerical CUDA graph execution; missing API and invalid lease refusals are live. | [assignment_graphs.zig](../../src/integrations/riscv_cuda/rv64/assignment_graphs.zig) | 1 |
| `OUTER_ASSIGNMENT_NARROW_RUNS` | Choose narrow-run grouping when chain scheduling does not take precedence. | [outer_assignment.zig](../../src/integrations/riscv_cuda/rv64/outer_assignment.zig) | 1 |
| `OUTER_OWNER_CONTROLLER` | Route complete outer operation through session owner controller with pool/TLS restoration. | [outer_source.zig](../../src/integrations/riscv_cuda/rv64/outer_source.zig) | 1 |
| `OUTER_PLAN_CLASS_STORE` | Select durable class-plan cache directory, identity-bound and corruption-tested. | [outer_assignment.zig](../../src/integrations/riscv_cuda/rv64/outer_assignment.zig) | none in maintained presets |
| `OUTER_PROFILE` | Select outer proof/security profile shared by producer and receiver; wrong-profile corpus retained. | [protocol.zig](../../src/integrations/circuit_cpu/om31/protocol.zig) | m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1 |
| `OUTER_SHAPE` | Select diagnostic exact/uniform/set-v2 geometry subject to canonical-profile restrictions. | [outer_wrap.zig](../../src/integrations/riscv_cpu/rv64_recursion/om31_native/outer_wrap.zig) | none in maintained presets |
| `PACKED_FULL_ARTIFACT_DIR` | Select artifact publication and/or stronger physical-proof qualification; explicitly protected from cleanup. | [rv64_packed_full_proof_test.zig](../../src/integrations/riscv_cpu/tests/rv64_packed_full_proof_test.zig) | none in maintained presets |
| `PACK_FOLD_CACHE` | Raw/encoded retention derives from actual requested retained bytes, including owner metadata. **Retired in the next tranche.** | [cache_pack.zig](../../src/integrations/circuit_cpu/om31/cache_pack.zig) | 1 |
| `PCS_IDLE_CACHE_BYTES` | Bound native idle cache retention; zero used for phase-bound retirement qualification. | [pcs_native.cu](../../src/backends/cuda/native/rv64/pcs_native.cu) | none in maintained presets |
| `PCS_ROLLING_BETA2` | Choose beta-2 rolling PCS schedule; affects actual memory plan and execution path. | [pcs_enqueue.cu](../../src/backends/cuda/native/rv64/jobs/pcs_enqueue.cu) | 1 |
| `PHASE_CACHE_TRIM` | Choose release of idle device cache at stage boundary, trading residency against reuse. | [pcs_native.zig](../../src/integrations/riscv_cuda/rv64/pcs_native.zig) | 1 |
| `PINNED_STAGING` | Choose pinned staging allocator path; default true, node-observer smoke exercises override. | [device_arena_runtime.cuh](../../src/backends/cuda/native/runtime/device_arena_runtime.cuh) | none in maintained presets |
| `PROCESS_MEMORY_OBSERVE` | Choose process/host memory observation; integration preset enables it. | [process_memory_observer.cu](../../tests/cuda/rv64/native/rv64/process_memory_observer.cu) | 1 |
| `RECURSION_HOST_BYTES` | Bound host reservation for legacy combined recursion, batch manifest has separate owned budget. | [rv64_combined_ethereum_main.zig](../../src/products/ethereum/statement/cuda/rv64_combined_ethereum_main.zig) | none in maintained presets |
| `SERVICE_GEOMETRY_ELF` | Select executable ELF for immutable service geometry diagnostic; absent does not run it. | [rv64_service_geometry_test.zig](../../src/integrations/riscv_cpu/tests/rv64_service_geometry_test.zig) | none in maintained presets |
| `SERVICE_GEOMETRY_OUTPUT` | Canonical geometry JSON goes to stdout; no second destination input. **Retired in the next tranche.** | [rv64_service_geometry_test.zig](../../src/integrations/riscv_cpu/tests/rv64_service_geometry_test.zig) | none in maintained presets |
| `TEST_BATCH_FOLD_SUM` | Fold/sum fusion is now compulsory alongside separate and small-tail variants. **Retired in this slice.** | [gkr_loop_smoke.cu](../../tests/cuda/rv64/gkr_loop_smoke.cu) | none in maintained presets |
| `TEST_BATCH_TAIL` | Small-tail fusion is now compulsory alongside separate and fold/sum variants. **Retired in this slice.** | [gkr_loop_smoke.cu](../../tests/cuda/rv64/gkr_loop_smoke.cu) | none in maintained presets |

The source reference scanner also includes maintained shell/Python setters, native code, workflow references and both active preset files. Keyword setters and named-helper readers must be followed through their owning function; simple getenv counts undercount those cases. The temporary operator inventory includes every literal occurrence with source context; the canonical registry reference arrays remain the maintained path inventory.

## Other repository-owned namespaces

The same registry and source gate now cover every literal `STWO_*` name in the
maintained source scan, including Objective-C `.m`/`.mm` and C++ `.cc` owners.
The historical registry/schema/CLI names remain compatible. No runtime controls
or defaults were added by recording existing controls.

The additional 561 names comprise 234 runtime controls, 79 qualification
controls, 238 compile-time constants/macros/domain tags and 10 fixture/reference
names. They are not all counted as runtime flags. Existing RV64 promotion and
package-budget flag counters still count only `STWO_RV64_*` names; the RV64
under-60 target remains open.

Every new live entry records its real owner, absence default, status, review
date, expiry and exact source evidence. Indirect constant-key/helper controls
can additionally pin actual getter/default consumers through
`default_evidence.readers`, including consumers in a different module. Changing
those pinned expressions fails source conformance. Reference refresh cannot
invent declarations, change defaults or renew expired controls. Objective-C and
Rust environment readers cannot be reclassified as constants to escape the
live inventory. This is source/configuration enforcement; runtime unknown-env
rejection and full application-path execution are not implied.

Before implementation, four focused tests failed: another namespace was
ignored, its metadata was invalid, its live names spent the RV64 promotion
budget, and its entries inflated a package's RV64 flag counter. The existing
checker and budget owner were corrected. The combined registry/budget/source-conformance suite now passes 60 cases,
including typed-reader source drift, status, expiry and unknown-name refusals. No GPU execution was performed.

## Deterministic host-cache representation tranche

Four more controls are retired: tail parity runs both pow0 and pow20, the
geometry diagnostic writes JSON to stdout, piece-only GPU tests use the existing
base-library selector, and cache representation follows actual retained bytes.
The pow20 tail uses a diagnostic q8 fixture; it does not establish production
whole-protocol security. GPU and physical tail execution remain unrun locally.

PP caches retain the existing raw owner when encoding plus its metadata is no
smaller, and retain the encoded owner otherwise. Requested-byte admission now
includes PP and assignment-template headers. Both decoders remain. The
non-pipelined PP consumer now uses the existing acquire/Lease contract, which
can return either a borrowed raw PP or an owned reconstructed PP; cleanup and
independent receiver authority remain explicit.

The externally retained CPU cost receipt measures median3 on synthetic
512KiB payloads. Structured columns retained
214234 bytes (59.1% less), and structured eight-field task records retained
131072 bytes (75% less). Packing cost 178us/99us and decoding cost 120us/91us,
versus raw cold-copy cost 39us/34us. Random payloads retained the raw owner;
the unsuccessful cold packing attempt cost 574us/537us, while the warm raw
owner requires no decode. This records the CPU/storage tradeoff without a
prover-speedup claim. Linux native-LZ4 and full cache/proof integration remain
qualification gates.

## Common qualification artifact destination (2026-11-16)

Owner decision [#332](https://github.com/starknet-innovation/stwo-zig/issues/332#issuecomment-6920870578) consolidates eleven independent destinations into the existing `STWO_RV64_LEAN_ARTIFACT_DIR` run root. It preserves every physical proof case and all stronger parameter selection; no production parameter is weakened. The complete starting inventory above is historical, not a list of remaining controls.

Each provider writes beneath its fixed subdirectory: `arith_none`, `division`, `keccak_cpu`, `keccak_cpu_cyclic`, `keccak_cpu_none`, `lean`, `multiplication`, `mul_cpu`, `packed_full`, `ethereum_cpu_v1`, or `ethereum_cpu_v2`. Existing file names and paired-C0 nesting are unchanged. Operators must read LEAN output from `<root>/lean` instead of directly from `<root>`. No maintained downstream reader depended on the old direct-root layout.

An absent common root preserves no-output behavior. An empty root is rejected; allocation and environment errors propagate instead of silently selecting weaker test parameters. Each owner retains its original stronger-configuration expression and all publication/receiver/mutation bodies. An independent whole-source ledger checks all eight owners and all 38 writer expressions after normalizing only the exact getter and private import. Tiny path tests cover all eleven mappings, allocation failures and positive/absent environment ownership. Full physical proof publication is not re-run locally.

The filtered recorded-node GPU harness also honors the existing required-GPU policy for either missing library. Optional mode may retain its host-only arm; required mode cannot claim GPU coverage after skipping that arm. A pure eight-case missing-base/addon/required matrix checks that policy without executing a GPU.

## Binding and parity ownership (2026-11-16)

Decision [#332](https://github.com/starknet-innovation/stwo-zig/issues/332#issuecomment-6921667442) removes three duplicate controls without promoting a GPU execution route. The proposed capacity consolidation is deferred: silently ignoring an inherited scalar cap could exceed the operator’s requested limit. Both scalar capacity consumers retain their original defaults and explicit-cap semantics.

The existing `GPU_DEVICE_TRACE` opt-in owns both device trace and mandatory binding construction. Previously valid configurations were00 and11; independent binding had no usable mode. Binding-provider failures remain terminal, and host-retained comparison mode still rejects device trace custody. The retired binding acknowledgement is ignored: a raw legacy binding-only environment now selects default hybrid mode instead of the former marker-combination refusal. It cannot enable residency; this is an explicit compatibility change, unlike ignoring a requested resource cap. The independent reviewer checks every former binding reader and setter; no missing-provider rejection is replaced by a success.

The existing native parity `.all` mode now always compares compositions and PCS proofs, while the respective focused modes preserve their independent comparisons. Separate switches cannot silently omit those checks. Production kernels/defaults are unchanged; this strengthens qualification coverage, not a GPU qualification claim. Actual GPU parity execution remains **UNRUN** locally.

## Typed fault ownership and complete physical test selection (2026-11-16)

Decisions [6922138831](https://github.com/starknet-innovation/stwo-zig/issues/332#issuecomment-6922138831) and [6922293884](https://github.com/starknet-innovation/stwo-zig/issues/332#issuecomment-6922293884) migrate four production sabotage selectors to executable typed qualification cases. Actual Driver/Worker publication rejects real host encoder, seed-program and rational-closure verdicts atomically; same-worker retries and cancellation/lifetime tests execute. The independent tuple oracle is separately compared with canonical CPU `Witness.outputTerm` and its actual relation/U constants in both modes. PCS mutation is test-only and refuses execution in a production build. All nine recorded GN physical cases remain, with an additional exact offset-zero MAIN-path case. Production-record/GPU replay and full encoded-node execution remain **UNRUN**; these tests do not newly qualify concrete CircuitCPU prepared-input teardown.

The two OODS fault selectors and their arm remain live. There is no small existing host OODS interpreter; inventing another authority solely for a flag count would increase soundness risk. Their retirement needs an executable real acceptance fixture.

The former plural recorded-node input selector now shares the existing singular producer directory authority with identical file layout. Independently, the real-scale PCS comparison runs whenever its existing GPU-library admission succeeds, without an extra selector. The unread raw MAIN dump option is retired while mandatory per-column SHA artifacts and every maintained replay consumer remain; existing raw files are not deleted. These changes leave 68 live RV64 controls, so the `<60` gate remains open.

## One native selection and producer-owned scratch (2026-11-16)

Decision [6923663392](https://github.com/starknet-innovation/stwo-zig/issues/332#issuecomment-6923663392) retires two redundant process controls. `GPU_NATIVE` is the sole explicit native-driver selector; its invalid values still reject, and shipped addon/FS assets remain hash-pinned. Compatibility is explicit: native1 without the former JOBS acknowledgement now selects native, JOBS-only now selects the unchanged default reference route, and obsolete acknowledgement values are ignored. The acknowledgement cannot inject shipped assets. Default native selection remains off; this does not promote a GPU backend.

Subprocess scratch derives from the existing producer CLI OUT as `OUT/.gpu-hybrid`. Only the CPU dispatcher claims OUT. The wrapper creates no early directories and leaves invalid, nonproducer and profile admission to the CPU owner. Request callbacks create only the scratch child, exclusively claim their fixed-role request/output files, and clean those owned files after success or failure. A collision refuses without deleting foreign files. PCS and composition names are disjoint; composition’s existing keep-jobs behavior remains. Fresh receivers retain their empty CUDA visibility and false PCS helper, and need no scratch destination override. Private path, collision, allocation-failure and mode tests execute without a prover. Full subprocess proof production remains **UNRUN** locally. The current live count is66; seven further genuine retirements are required.

## Immutable kernels and typed physical comparison (2026-11-16)

Decision [6927542834](https://github.com/starknet-innovation/stwo-zig/issues/332#issuecomment-6927542834) removes three process variant selectors. Public DEEP and SAMPLE C entrypoints call their unchanged current default path with `legacy=false`. Hidden internal C++ launch functions retain both algorithms, with typed true/false calls from the existing statically linked physical benchmark. They add no public C ABI export. Tests pin every normalized launch-body token, all physical benchmark cases/poison/status comparisons and timing boundaries, plus real public structure layouts and hidden C++ header signatures. CUDA translation and execution remain **UNRUN**; source preservation and host header compilation are not GPU qualification.

AOT register scheduling uses the existing immutable replacement build path. The compatibility `--replace` spelling is accepted as a no-op, not another selector. Original baseline objects/artifacts remain the independent physical oracle; generated kernel bodies/reports and catalogue identities match the former explicit replacement path. Existing physical before/after benchmark sources are preserved. Runtime rollback now means choosing the original baseline artifact, rather than switching catalogues within an admitted artifact. No artifact is re-pinned and no currently-disabled GPU feature is promoted. The live RV64 count is63; the strict `<60` gate still requires four genuine retirements.

## Request-owned recording datasets (host qualified)

The three NODE/PACK recording selectors are retired into the existing
`STWO_RV64_LEAN_ARTIFACT_DIR` policy. Combined with typed final-plan publication,
this leaves **59 live RV64 controls**. The numeric `<60` gate is met; ordered
GPU-native promotion and physical record/replay qualification remain separate.
No runtime control is hidden in a JSON menu, role option or thread-local ID.

With the root absent, capture is disabled. Selecting it now opts into every
available pack and node capture as well as the existing CPU artifact writers.
Capture downloads, serialization, hashing and disk I/O consume extra resources;
these runs are instrumented and must not be presented as clean production
proving timings. Capture failures never replace the underlying proof verdict.
An unsuccessful proof, failed capture or live borrow cannot publish completion.

Each actual execution attempt owns one explicit Dataset under
`ROOT/recordings/executions/<identity>/`, with fixed `pack` and `nodes` roles.
The immutable manifest binds execution and attempt identities, purpose,
request bytes and freshly computed program/input hashes checked against their
request pins. Completion binds the exact independent role inventory, file sizes
and hashes. Exclusive admission refuses identity conflicts; identical node/PCS
publication is serialized and conflicting contents refuse. A node ordinal alone
never selects a dataset.

The lifecycle is concrete:

- `resident_batch.requestOne` shares one owner across its Native contexts and
  closes it after `hybrid.endRequest` quiescence and slot detachment.
- Native `beginBlock` checks the installed execution binding; `endBlock`
  releases its slot after the existing lease audit. Context destruction releases
  remaining capture ownership only after the native C owner joins callbacks.
- Direct combined, hybrid and standalone recursion entries own explicit sessions.
  The latter includes both `recurse-candidate` and `resume-recursion-candidate`;
  receiver-only commands do not enable capture.
- Source assembly and each in-flight pack recording borrow the same owner;
  every source-build error aborts the capture and releases its recording lease.
  PCS and node serializers retain synchronous borrows through publication.
- Hybrid node provers receive the matching Native slot. Ambiguous duplicate
  device contexts disable capture and mark it incomplete; no first-match guess
  or new service-count ceiling chooses a foreign execution.
- Class installation calls `runCombinedForInstall` explicitly. Each one-block,
  repeat-one installation invocation gets a fresh `.class_install` attempt.
  `NodeClasses.installNode` refuses a different class at the same ordinal;
  its installed inventory is dense and global to that invocation. Classes do
  not reset node ordinals inside one warm execution, so child PCS records stay
  together instead of being split into incomplete per-class datasets.

Replay visits every complete modern dataset independently and deterministically.
Historical colon-separated pack roots migrate one-for-one, with unchanged
payloads or directory links, into
`ROOT/recordings/historical/pack/<family>/`; historical node roots use
`historical/nodes/<family>/`. Never flatten families, select the first old root
as a writer, or join child roots across datasets. All explicitly imported
historical families are passed to the unchanged per-family harness. An absent
role skips; incomplete or corrupt provided data rejects. A modern nodes role
containing only auxiliary PCS images does not claim node replay coverage.

Host tests exercise simultaneous contexts, ordinal-zero reuse in independent
executions/installations, actual file-pin checks, exclusive/content conflicts,
abort/retry, live-borrow destruction refusal, post-completion write refusal and
manifest corruption/inventory mismatch. The actual Session consumer executes
against the real `Native.Context.recording` type and its admission refusal,
without GPU initialization. All nine original GN negatives plus the exact
first MAIN-path-word case, every pack SHA comparison and complete per-family
replay bodies remain intact. Full Native/Outer/CLI typing and actual retained
GPU record/replay remain **UNRUN**; host filesystem tests do not qualify them.

`PLAN_DIR` retirement is implemented by two explicit nested Worker methods.
`quiesce` closes admission, drains accepted jobs and serializes the worker join;
repeated and concurrent external calls join once. `destroyWithPlan(OUT)` first
quiesces, writes the unchanged v2 schema to `OUT/class-plans`, then releases the
worker. Its self-thread refusal retains ownership; after successful quiescence,
path, allocation and write failures consume the worker. Ordinary `destroy` has
no diagnostic environment lookup or output side effect.

The four existing native, truth, class-build and GN-S2 parity tools use their
existing typed OUT. The sweep collects that `class-plans` subdirectory, avoiding
proof JSON. Final snapshots retain the exact post-join/pre-metadata-release
point: shutdown statistics and class, region and retained records remain alive
until writing finishes. The original parse-back case is retained. Four host
cases cover final parsed counters, concurrent joins, self-thread refusal,
post-quiescence admission refusal, foreign-path failure and allocation failure;
all 18 discovered cases pass in Debug and ReleaseFast under the 1 GiB cap.
These are real Worker/FakeOps lifecycle checks, not GPU execution qualification.
Keep `M8_JOBS_PLAN` independent: it changes actual class admission/peak policy.
