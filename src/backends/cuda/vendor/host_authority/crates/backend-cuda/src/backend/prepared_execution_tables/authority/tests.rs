use core::ffi::c_void;

use super::*;
use crate::backend::prepared_witness_input::static_build::{
    binding_for_test, validate_binding_for_test,
};

fn requirements() -> ExecutionTablesWorkspaceRequirements {
    execution_tables_workspace_requirements(19, 17, 5).unwrap()
}

fn contract() -> ExecutionTablesContract {
    ExecutionTablesContract::compile(&requirements()).unwrap()
}

#[test]
fn contract_seals_host_ingress_stage_order_and_exact_raw_abis() {
    type RawSplit = unsafe extern "C" fn(*const u32, u32, u32, *const *mut u32, *mut c_void) -> i32;
    let _: RawSplit = stwo_backend_cuda_kernels::raw::memory_limb_split_big_columns_on;
    let _: RawSplit = stwo_backend_cuda_kernels::raw::memory_limb_split_small_columns_on;

    let contract = contract();
    contract.validate().unwrap();
    assert_eq!(
        contract,
        ExecutionTablesContract::compile(&requirements()).unwrap()
    );
    assert_eq!(
        contract.host_ingress(),
        &ExecutionTablesHostIngressGeometry {
            fields: [
                ExecutionTablesHostIngressField {
                    role: ExecutionTablesHostIngressRole::RawAddressToId,
                    encoding: ExecutionTablesHostIngressEncoding::RawU32,
                    rows: 19,
                    words_per_row: 1,
                    copied_words: 19,
                    arena_words: 19,
                },
                ExecutionTablesHostIngressField {
                    role: ExecutionTablesHostIngressRole::F252Values,
                    encoding: ExecutionTablesHostIngressEncoding::F252LittleEndianU32x8,
                    rows: 17,
                    words_per_row: 8,
                    copied_words: 136,
                    arena_words: 136,
                },
                ExecutionTablesHostIngressField {
                    role: ExecutionTablesHostIngressRole::SmallValues,
                    encoding: ExecutionTablesHostIngressEncoding::SmallU128LittleEndianU32x4,
                    rows: 5,
                    words_per_row: 4,
                    copied_words: 20,
                    arena_words: 20,
                },
            ],
        }
    );
    assert_eq!(
        EXECUTION_TABLES_STAGE_ORDER,
        [ExecutionTablesStage::Big, ExecutionTablesStage::Small]
    );
    assert_eq!(
        EXECUTION_TABLES_FIXED_ORDER,
        [
            ExecutionTablesFixedField::BigStage,
            ExecutionTablesFixedField::BigInputWords,
            ExecutionTablesFixedField::BigOutputLimbs,
            ExecutionTablesFixedField::SmallStage,
            ExecutionTablesFixedField::SmallInputWords,
            ExecutionTablesFixedField::SmallOutputLimbs,
            ExecutionTablesFixedField::LimbBits,
            ExecutionTablesFixedField::BlockThreads,
        ]
    );
    assert_eq!(contract.fixed_words(), &[1, 8, 28, 2, 4, 8, 9, 256]);

    let stages = contract.stages();
    assert_eq!(
        stages.each_ref().map(|stage| stage.stage()),
        EXECUTION_TABLES_STAGE_ORDER
    );
    assert_eq!(
        stages.each_ref().map(|stage| stage.abi().entry_symbol()),
        [
            "memory_limb_split_big_columns_on",
            "memory_limb_split_small_columns_on",
        ]
    );
    for abi in stages.each_ref().map(|stage| stage.abi()) {
        assert_eq!(
            abi.arguments(),
            &[
                argument(
                    0,
                    "values",
                    ExecutionTablesAbiArgumentKind::OptionalDeviceConstPointerU32,
                    ExecutionTablesAbiAccess::ReadValuesWhenNonEmpty,
                ),
                argument(
                    1,
                    "n_values",
                    ExecutionTablesAbiArgumentKind::U32,
                    ExecutionTablesAbiAccess::RealRowCount,
                ),
                argument(
                    2,
                    "column_length",
                    ExecutionTablesAbiArgumentKind::U32,
                    ExecutionTablesAbiAccess::ColumnRowCount,
                ),
                argument(
                    3,
                    "limb_cols_host",
                    ExecutionTablesAbiArgumentKind::HostConstPointerTableDeviceMutU32,
                    ExecutionTablesAbiAccess::ReadHostPointersWriteDeviceColumns,
                ),
                argument(
                    4,
                    "stream",
                    ExecutionTablesAbiArgumentKind::CudaStream,
                    ExecutionTablesAbiAccess::OrderedExecutionStream,
                ),
            ],
        );
    }
}

#[test]
fn effects_seal_low_bits_full_column_writes_and_zero_padding() {
    let contract = contract();
    let [big, small] = contract.stages();
    assert_eq!(
        big.effect(),
        ExecutionTablesEffectAbi::ReadLeWordsWriteLowNineBitLimbsZeroPadV1
    );
    assert_eq!(
        big.row_domain(),
        ExecutionTablesRowDomain::RealPrefixThenZeroPaddingV1
    );
    assert_eq!(
        big.effect_geometry(),
        &ExecutionTablesStageEffect {
            stage: ExecutionTablesStage::Big,
            source_start_word: 0,
            source_read_words: 136,
            input_words_per_row: 8,
            real_rows: 17,
            column_rows: 32,
            emitted_low_bits: 252,
            ignored_high_bits: 4,
            zero_padding_start_row: 17,
            zero_padding_rows: 15,
            output_writes: (0..28)
                .map(|column_ordinal| ExecutionTablesColumnEffect {
                    column_ordinal,
                    write_start_word: 0,
                    written_words: 32,
                })
                .collect(),
        }
    );
    assert_eq!(
        small.effect_geometry(),
        &ExecutionTablesStageEffect {
            stage: ExecutionTablesStage::Small,
            source_start_word: 0,
            source_read_words: 20,
            input_words_per_row: 4,
            real_rows: 5,
            column_rows: 16,
            emitted_low_bits: 72,
            ignored_high_bits: 56,
            zero_padding_start_row: 5,
            zero_padding_rows: 11,
            output_writes: (0..8)
                .map(|column_ordinal| ExecutionTablesColumnEffect {
                    column_ordinal,
                    write_start_word: 0,
                    written_words: 16,
                })
                .collect(),
        }
    );
    assert_eq!(
        big.launch(),
        ExecutionTablesKernelLaunch {
            stage: ExecutionTablesStage::Big,
            grid: [1, 1, 1],
            block: [256, 1, 1],
            dynamic_shared_bytes: 0,
            cooperative: false,
            cluster: None,
        }
    );
    assert_eq!(
        [big.launch().symbol(), small.launch().symbol(),],
        [
            "memory_limb_split_into_kernel<8, 28>",
            "memory_limb_split_into_kernel<4, 8>",
        ]
    );

    // Address IDs are host-ingested consumer data, never an output of either split.
    assert_eq!(
        contract.host_ingress().fields[0].role,
        ExecutionTablesHostIngressRole::RawAddressToId
    );
    assert_eq!(
        big.effect_geometry().output_writes.len() + small.effect_geometry().output_writes.len(),
        36
    );

    let binder = include_str!("../../prepared_execution_tables.rs");
    let big_call = binder
        .find("raw::memory_limb_split_big_columns_on(")
        .unwrap();
    let small_call = binder
        .find("raw::memory_limb_split_small_columns_on(")
        .unwrap();
    assert!(
        big_call < small_call,
        "split stages must remain Big then Small"
    );
}

#[test]
fn launch_grid_is_checked_at_the_largest_canonical_u32_column() {
    let rows = 1usize << 31;
    let requirements = execution_tables_workspace_requirements(0, rows, 0).unwrap();
    let contract = ExecutionTablesContract::compile(&requirements).unwrap();
    let launch = contract.stages()[0].launch();
    assert_eq!(launch.grid, [8_388_608, 1, 1]);
    assert_eq!(launch.grid[0], 1 + ((1u32 << 31) - 1) / BLOCK_THREADS);

    let too_wide = execution_tables_workspace_requirements(u32::MAX as usize + 1, 0, 0).unwrap();
    assert_eq!(
        ExecutionTablesContract::compile(&too_wide),
        Err(ExecutionTablesAuthorityError::SizeOverflow)
    );
}

#[test]
fn empty_tables_have_no_source_read_and_the_wrapper_accepts_null_exactly_then() {
    let requirements = execution_tables_workspace_requirements(0, 0, 0).unwrap();
    let contract = ExecutionTablesContract::compile(&requirements).unwrap();
    assert_eq!(
        ExecutionTablesAbiArgumentKind::OptionalDeviceConstPointerU32 as u8,
        5
    );
    assert_eq!(
        ExecutionTablesAbiAccess::ReadValuesWhenNonEmpty as u8,
        6
    );
    for stage in contract.stages() {
        assert_eq!(stage.effect_geometry().real_rows, 0);
        assert_eq!(stage.effect_geometry().source_read_words, 0);
        assert_eq!(
            stage.abi().arguments()[0],
            argument(
                0,
                "values",
                ExecutionTablesAbiArgumentKind::OptionalDeviceConstPointerU32,
                ExecutionTablesAbiAccess::ReadValuesWhenNonEmpty,
            )
        );
    }
    let source = include_str!("../../../../../backend-cuda-kernels/cuda/memory_witness.cu");
    assert!(source.contains("(n_values != 0 && values == nullptr)"));
}

#[test]
fn canonical_and_derived_mutations_fail_closed() {
    let baseline = requirements();
    let mut mutations = Vec::new();
    let mut changed = baseline.clone();
    changed.n_big += 1;
    mutations.push(changed);
    let mut changed = baseline.clone();
    changed.raw_f252_words += 1;
    mutations.push(changed);
    let mut changed = baseline.clone();
    changed.small_column_words *= 2;
    mutations.push(changed);
    let mut changed = baseline;
    changed.table_stride_words += 1;
    mutations.push(changed);
    for mutation in mutations {
        assert_eq!(
            ExecutionTablesContract::compile(&mutation),
            Err(ExecutionTablesAuthorityError::InvalidCanonicalRequirements)
        );
    }

    macro_rules! rejects {
        ($field:ident, $change:expr) => {{
            let mut changed = contract();
            $change(&mut changed.$field);
            assert_eq!(
                changed.validate(),
                Err(ExecutionTablesAuthorityError::InvalidCanonicalRequirements),
                stringify!($field),
            );
        }};
    }
    rejects!(
        requirements,
        |value: &mut ExecutionTablesWorkspaceRequirements| value.n_small += 1
    );
    rejects!(
        host_ingress,
        |value: &mut ExecutionTablesHostIngressGeometry| {
            value.fields[0].encoding = ExecutionTablesHostIngressEncoding::F252LittleEndianU32x8
        }
    );
    rejects!(fixed_words, |value: &mut [u32; 8]| value[1] ^= 1);
    rejects!(stages, |value: &mut [ExecutionTablesStageContract; 2]| {
        value.swap(0, 1)
    });
    rejects!(stages, |value: &mut [ExecutionTablesStageContract; 2]| {
        value[0].effect_geometry.ignored_high_bits += 1
    });
    rejects!(stages, |value: &mut [ExecutionTablesStageContract; 2]| {
        value[1].launch.grid[0] += 1
    });
    rejects!(static_source_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(wrapper_source_identity, |value: &mut [u8; 32]| value[0] ^=
        1);
    rejects!(source_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(requirements_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(host_ingress_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(fixed_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(abi_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(effect_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(launch_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(identity, |value: &mut [u8; 32]| value[0] ^= 1);
}

#[test]
fn source_closure_and_target_sm_build_are_identity_bearing() {
    let source = include_str!("../../../../../backend-cuda-kernels/cuda/memory_witness.cu");
    for required in [
        "__global__ void memory_limb_split_into_kernel(",
        "uint32_t words[N_WORDS] = {0};",
        "if (row < n_values)",
        "extern \"C\" int memory_limb_split_big_columns_on(",
        "extern \"C\" int memory_limb_split_small_columns_on(",
        "memory_limb_split_columns_on_impl<8, 28>",
        "memory_limb_split_columns_on_impl<4, 8>",
        "(n_values != 0 && values == nullptr)",
        "n_values > column_length",
    ] {
        assert!(
            source.contains(required),
            "missing source authority: {required}"
        );
    }
    let semantic = contract();
    for identity in [
        semantic.static_source_identity(),
        semantic.wrapper_source_identity(),
        semantic.source_identity(),
        semantic.requirements_identity(),
        semantic.host_ingress_identity(),
        semantic.fixed_identity(),
        semantic.abi_identity(),
        semantic.effect_identity(),
        semantic.launch_identity(),
        semantic.identity(),
    ] {
        assert_ne!(identity, ZERO_IDENTITY);
    }
    assert_eq!(
        semantic.wrapper_source_identity(),
        digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE)
    );

    let binding = binding_for_test(
        STATIC_BUILD_DOMAIN,
        semantic.identity(),
        [0x61; 32],
        [0x61; 32],
        &[86, 89],
        89,
    )
    .unwrap();
    validate_binding_for_test(
        &binding,
        STATIC_BUILD_DOMAIN,
        semantic.identity(),
        [0x61; 32],
        [0x61; 32],
        &[86, 89],
        89,
    )
    .unwrap();
    let linked = linked_contract(semantic.identity(), binding);
    assert_eq!(linked.contract_identity(), semantic.identity());
    assert_eq!(linked.module_build_identity(), [0x61; 32]);
    assert_ne!(linked.static_build_source_identity(), ZERO_IDENTITY);
    assert_ne!(linked.static_build_identity(), ZERO_IDENTITY);
    assert_eq!(linked.target_sm(), 89);
    assert_ne!(linked.sm_identity(), ZERO_IDENTITY);
    assert_ne!(linked.identity(), ZERO_IDENTITY);

    for changed in [
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x62; 32],
            [0x62; 32],
            &[86, 89],
            89,
        )
        .unwrap(),
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x61; 32],
            [0x61; 32],
            &[86, 89],
            86,
        )
        .unwrap(),
    ] {
        assert_ne!(
            linked.identity(),
            linked_contract(semantic.identity(), changed).identity()
        );
    }
    let mut changed_source = binding;
    changed_source.static_build_source_identity[0] ^= 1;
    assert_eq!(
        validate_binding_for_test(
            &changed_source,
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x61; 32],
            [0x61; 32],
            &[86, 89],
            89,
        ),
        Err(StaticBuildBindError::InconsistentBuildMetadata)
    );
    let mut changed_aggregate = binding;
    changed_aggregate.identity[0] ^= 1;
    assert_eq!(
        validate_binding_for_test(
            &changed_aggregate,
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x61; 32],
            [0x61; 32],
            &[86, 89],
            89,
        ),
        Err(StaticBuildBindError::InconsistentBuildMetadata)
    );
    assert_eq!(
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x61; 32],
            [0x61; 32],
            &[86, 89],
            90,
        ),
        Err(StaticBuildBindError::UnsupportedTargetSm(90))
    );

    if stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        let target = stwo_backend_cuda_kernels::static_cuda_module_target_sms()[0];
        semantic
            .bind_static_build(target)
            .unwrap()
            .unwrap()
            .validate(&semantic)
            .unwrap();
    } else {
        assert_eq!(semantic.bind_static_build(89).unwrap(), None);
    }
}
