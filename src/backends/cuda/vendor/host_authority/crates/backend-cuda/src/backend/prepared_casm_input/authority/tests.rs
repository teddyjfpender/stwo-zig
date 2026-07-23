use core::ffi::c_void;

use super::*;
use crate::backend::prepared_witness_input::static_build::{
    binding_for_test, validate_binding_for_test,
};

fn contract(include_iota: bool) -> WitnessCasmInputContract {
    WitnessCasmInputContract::compile(&witness_casm_input_requirements(17, include_iota).unwrap())
        .unwrap()
}

#[test]
fn contract_seals_exact_raw_abi_effect_and_launch() {
    type RawCasmInput = unsafe extern "C" fn(
        *const u32,
        u32,
        u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut c_void,
    ) -> i32;
    let _: RawCasmInput = stwo_backend_cuda_kernels::raw::stwo_witness_casm_input_scatter_on;

    let contract = contract(false);
    assert_eq!(
        contract
            .abi()
            .arguments()
            .iter()
            .map(|argument| (
                argument.ordinal,
                argument.name,
                argument.kind,
                argument.access,
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                0,
                "rows_dev",
                WitnessCasmInputAbiArgumentKind::DeviceConstPointerU32,
                WitnessCasmInputAbiAccess::ReadRowMajorStates,
            ),
            (
                1,
                "n_real",
                WitnessCasmInputAbiArgumentKind::U32,
                WitnessCasmInputAbiAccess::RealRowCount,
            ),
            (
                2,
                "consumer_rows",
                WitnessCasmInputAbiArgumentKind::U32,
                WitnessCasmInputAbiAccess::ConsumerRowCount,
            ),
            (
                3,
                "pc_dev",
                WitnessCasmInputAbiArgumentKind::DeviceMutPointerU32,
                WitnessCasmInputAbiAccess::WritePc,
            ),
            (
                4,
                "ap_dev",
                WitnessCasmInputAbiArgumentKind::DeviceMutPointerU32,
                WitnessCasmInputAbiAccess::WriteAp,
            ),
            (
                5,
                "fp_dev",
                WitnessCasmInputAbiArgumentKind::DeviceMutPointerU32,
                WitnessCasmInputAbiAccess::WriteFp,
            ),
            (
                6,
                "enabler_dev",
                WitnessCasmInputAbiArgumentKind::DeviceMutPointerU32,
                WitnessCasmInputAbiAccess::WriteEnabler,
            ),
            (
                7,
                "iota_dev",
                WitnessCasmInputAbiArgumentKind::OptionalDeviceMutPointerU32,
                WitnessCasmInputAbiAccess::WriteOptionalIota,
            ),
            (
                8,
                "stream",
                WitnessCasmInputAbiArgumentKind::CudaStream,
                WitnessCasmInputAbiAccess::OrderedExecutionStream,
            ),
        ]
    );
    assert_eq!(
        WITNESS_CASM_INPUT_FIXED_ORDER,
        [
            WitnessCasmInputFixedField::StateWords,
            WitnessCasmInputFixedField::RealRows,
            WitnessCasmInputFixedField::ConsumerRows,
            WitnessCasmInputFixedField::IncludeIota,
        ]
    );
    assert_eq!(contract.fixed_words(), &[3, 17, 32, 0]);
    assert_eq!(
        contract.effect_geometry(),
        &WitnessCasmInputEffectGeometry {
            source_start_word: 0,
            source_rows: 17,
            state_words_per_row: 3,
            consumer_rows: 32,
            output_columns: vec![
                WitnessCasmInputColumnEffect {
                    column_ordinal: 0,
                    value: WitnessCasmInputColumnValue::StateWord(0),
                    written_words: 32,
                },
                WitnessCasmInputColumnEffect {
                    column_ordinal: 1,
                    value: WitnessCasmInputColumnValue::StateWord(1),
                    written_words: 32,
                },
                WitnessCasmInputColumnEffect {
                    column_ordinal: 2,
                    value: WitnessCasmInputColumnValue::StateWord(2),
                    written_words: 32,
                },
                WitnessCasmInputColumnEffect {
                    column_ordinal: 3,
                    value: WitnessCasmInputColumnValue::Enabler,
                    written_words: 32,
                },
            ],
        }
    );
    assert_eq!(
        contract.launch(),
        WitnessCasmInputKernelLaunch {
            grid: [1, 1, 1],
            block: [256, 1, 1],
            dynamic_shared_bytes: 0,
            cooperative: false,
            cluster: None,
        }
    );
    assert_eq!(
        contract.abi().entry_symbol(),
        "stwo_witness_casm_input_scatter_on"
    );
    assert_eq!(
        contract.launch().symbol(),
        "witness_casm_input_scatter_kernel"
    );
    contract.validate().unwrap();
    for identity in [
        contract.static_source_identity(),
        contract.wrapper_source_identity(),
        contract.source_identity(),
        contract.requirements_identity(),
        contract.fixed_identity(),
        contract.abi_identity(),
        contract.effect_identity(),
        contract.launch_identity(),
        contract.identity(),
    ] {
        assert_ne!(identity, ZERO_IDENTITY);
    }
}

#[test]
fn iota_contract_has_exact_fifth_output() {
    let requirements = witness_casm_input_requirements(257, true).unwrap();
    let contract = WitnessCasmInputContract::compile(&requirements).unwrap();

    assert_eq!(contract.fixed_words(), &[3, 257, 512, 1]);
    assert_eq!(contract.launch().grid, [2, 1, 1]);
    assert_eq!(contract.effect_geometry().output_columns.len(), 5);
    assert_eq!(
        contract.effect_geometry().output_columns[4],
        WitnessCasmInputColumnEffect {
            column_ordinal: 4,
            value: WitnessCasmInputColumnValue::Iota,
            written_words: 512,
        }
    );
}

#[test]
fn canonical_requirement_and_contract_mutations_fail_closed() {
    let baseline = witness_casm_input_requirements(17, true).unwrap();
    let mut mutations = Vec::new();
    let mut changed = baseline.clone();
    changed.n_real_rows += 1;
    mutations.push(changed);
    let mut changed = baseline.clone();
    changed.consumer_rows = 64;
    mutations.push(changed);
    let mut changed = baseline.clone();
    changed.include_iota = false;
    mutations.push(changed);
    let mut changed = baseline.clone();
    changed.staging_words += 1;
    mutations.push(changed);
    let mut changed = baseline.clone();
    changed.consumer_input_column_words[0] -= 1;
    mutations.push(changed);
    let mut changed = baseline;
    changed.consumer_input_column_words.swap_remove(4);
    mutations.push(changed);
    for requirements in mutations {
        assert_eq!(
            WitnessCasmInputContract::compile(&requirements),
            Err(WitnessCasmInputAuthorityError::InvalidCanonicalRequirements)
        );
    }

    macro_rules! rejects {
        ($field:ident, $change:expr) => {{
            let mut changed = contract(true);
            $change(&mut changed.$field);
            assert_eq!(
                changed.validate(),
                Err(WitnessCasmInputAuthorityError::InvalidCanonicalRequirements),
                stringify!($field),
            );
        }};
    }
    rejects!(requirements, |value: &mut WitnessCasmInputRequirements| {
        value.n_real_rows += 1
    });
    rejects!(fixed_words, |value: &mut [u32; 4]| value[0] ^= 1);
    rejects!(
        effect_geometry,
        |value: &mut WitnessCasmInputEffectGeometry| value.consumer_rows += 1
    );
    rejects!(launch, |value: &mut WitnessCasmInputKernelLaunch| value
        .grid[0] +=
        1);
    rejects!(static_source_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(wrapper_source_identity, |value: &mut [u8; 32]| value[0] ^=
        1);
    rejects!(source_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(requirements_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(fixed_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(abi_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(effect_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(launch_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(identity, |value: &mut [u8; 32]| value[0] ^= 1);
}

#[test]
fn contract_identity_changes_with_iota_and_shape() {
    let plain = contract(false);
    let iota = contract(true);
    let other =
        WitnessCasmInputContract::compile(&witness_casm_input_requirements(33, false).unwrap())
            .unwrap();

    assert_ne!(plain.identity(), iota.identity());
    assert_ne!(plain.identity(), other.identity());
    assert_ne!(plain.effect_identity(), iota.effect_identity());
    assert_ne!(plain.requirements_identity(), other.requirements_identity());
}

#[test]
fn upper_canonical_row_geometry_uses_overflow_safe_grid() {
    let n_real_rows = (1usize << 30) + 1;
    let requirements = witness_casm_input_requirements(n_real_rows, false).unwrap();
    let contract = WitnessCasmInputContract::compile(&requirements).unwrap();
    let consumer_rows = 1u32 << 31;
    assert_eq!(requirements.consumer_rows, consumer_rows as usize);
    assert_eq!(
        contract.launch().grid,
        [1 + (consumer_rows - 1) / BLOCK_THREADS, 1, 1]
    );
}

#[test]
fn source_closure_and_linked_build_fields_are_identity_bearing() {
    let source = include_str!("../../../../../backend-cuda-kernels/cuda/witness_casm_input.cu");
    for required in [
        "__global__ void witness_casm_input_scatter_kernel(",
        "uint32_t source_row = row < n_real ? row : 0;",
        "enabler[row] = row < n_real;",
        "iota[row] = row;",
        "extern \"C\" int stwo_witness_casm_input_scatter_on(",
        "const uint32_t block = 256;",
        "witness_casm_input_scatter_kernel<<<grid, block, 0, stream>>>",
    ] {
        assert!(
            source.contains(required),
            "missing source authority: {required}"
        );
    }

    let semantic = contract(true);
    assert_eq!(
        semantic.wrapper_source_identity(),
        digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE)
    );
    let binding = binding_for_test(
        STATIC_BUILD_DOMAIN,
        semantic.identity(),
        [0x41; 32],
        [0x41; 32],
        &[86, 89],
        89,
    )
    .unwrap();
    validate_binding_for_test(
        &binding,
        STATIC_BUILD_DOMAIN,
        semantic.identity(),
        [0x41; 32],
        [0x41; 32],
        &[86, 89],
        89,
    )
    .unwrap();
    let linked = linked_contract(semantic.identity(), binding);
    assert_eq!(linked.contract_identity(), semantic.identity());
    assert_eq!(linked.module_build_identity(), [0x41; 32]);
    assert_ne!(linked.static_build_source_identity(), ZERO_IDENTITY);
    assert_ne!(linked.static_build_identity(), ZERO_IDENTITY);
    assert_eq!(linked.target_sm(), 89);
    assert_ne!(linked.sm_identity(), ZERO_IDENTITY);
    assert_ne!(linked.identity(), ZERO_IDENTITY);

    let changed_build = binding_for_test(
        STATIC_BUILD_DOMAIN,
        semantic.identity(),
        [0x42; 32],
        [0x42; 32],
        &[86, 89],
        89,
    )
    .unwrap();
    assert_ne!(
        linked.identity(),
        linked_contract(semantic.identity(), changed_build).identity()
    );
    let changed_sm = binding_for_test(
        STATIC_BUILD_DOMAIN,
        semantic.identity(),
        [0x41; 32],
        [0x41; 32],
        &[86, 89],
        86,
    )
    .unwrap();
    assert_ne!(
        linked.identity(),
        linked_contract(semantic.identity(), changed_sm).identity()
    );
    for mutate in [0usize, 1] {
        let mut changed = binding;
        if mutate == 0 {
            changed.static_build_source_identity[0] ^= 1;
        } else {
            changed.identity[0] ^= 1;
        }
        assert_eq!(
            validate_binding_for_test(
                &changed,
                STATIC_BUILD_DOMAIN,
                semantic.identity(),
                [0x41; 32],
                [0x41; 32],
                &[86, 89],
                89,
            ),
            Err(StaticBuildBindError::InconsistentBuildMetadata)
        );
        assert_ne!(
            linked.identity(),
            linked_contract(semantic.identity(), changed).identity()
        );
    }
    for rejected in [
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x41; 32],
            [0x42; 32],
            &[86, 89],
            89,
        ),
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x41; 32],
            [0x41; 32],
            &[89, 86],
            89,
        ),
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x41; 32],
            [0x41; 32],
            &[86, 89],
            90,
        ),
    ] {
        assert!(rejected.is_err());
    }

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
