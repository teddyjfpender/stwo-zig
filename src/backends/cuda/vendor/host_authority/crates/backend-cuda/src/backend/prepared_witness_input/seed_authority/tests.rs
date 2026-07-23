use core::ffi::c_void;

use super::*;
use crate::backend::prepared_witness_input::static_build::{
    binding_for_test, validate_binding_for_test,
};

fn requirements() -> WitnessInputSeedRequirements {
    witness_input_seed_requirements(2, 497, 512, true, true).unwrap()
}

fn contract() -> WitnessInputSeedContract {
    WitnessInputSeedContract::compile(&requirements()).unwrap()
}

#[test]
fn upper_u32_row_geometry_matches_the_overflow_safe_wrapper_grid() {
    let consumer_rows = u32::MAX - 15;
    let requirements =
        witness_input_seed_requirements(1, 1, consumer_rows as usize, false, false).unwrap();
    let contract = WitnessInputSeedContract::compile(&requirements).unwrap();
    assert_eq!(
        contract.launch().grid,
        [consumer_rows.div_ceil(BLOCK_THREADS), 1, 1]
    );
    assert_eq!(
        1u32 + (consumer_rows - 1) / BLOCK_THREADS,
        contract.launch().grid[0]
    );
}

#[test]
fn contract_seals_exact_abi_effect_constants_and_launch() {
    type RawSeed = unsafe extern "C" fn(
        *const u32,
        u32,
        u32,
        u32,
        *const *mut u32,
        u32,
        u32,
        *mut c_void,
    ) -> i32;
    let _: RawSeed = stwo_backend_cuda_kernels::raw::stwo_witness_input_seed_on;

    let contract = contract();
    contract.validate().unwrap();
    assert_eq!(
        contract,
        WitnessInputSeedContract::compile(&requirements()).unwrap()
    );
    assert_eq!(contract.abi().entry_symbol(), "stwo_witness_input_seed_on");
    assert_eq!(
        contract
            .abi()
            .arguments()
            .iter()
            .map(|argument| (
                argument.ordinal,
                argument.name,
                argument.kind,
                argument.access
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                0,
                "scalars_dev",
                WitnessInputSeedAbiArgumentKind::DeviceConstPointerU32,
                WitnessInputSeedAbiAccess::ReadScalarWords
            ),
            (
                1,
                "n_scalars",
                WitnessInputSeedAbiArgumentKind::U32,
                WitnessInputSeedAbiAccess::ScalarWordCount
            ),
            (
                2,
                "n_real_rows",
                WitnessInputSeedAbiArgumentKind::U32,
                WitnessInputSeedAbiAccess::RealRowCount
            ),
            (
                3,
                "consumer_rows",
                WitnessInputSeedAbiArgumentKind::U32,
                WitnessInputSeedAbiAccess::ConsumerRowCount
            ),
            (
                4,
                "consumer_cols_dev",
                WitnessInputSeedAbiArgumentKind::DeviceMutPointerTableU32,
                WitnessInputSeedAbiAccess::WriteConsumerColumns
            ),
            (
                5,
                "include_enabler",
                WitnessInputSeedAbiArgumentKind::U32,
                WitnessInputSeedAbiAccess::IncludeEnabler
            ),
            (
                6,
                "include_iota",
                WitnessInputSeedAbiArgumentKind::U32,
                WitnessInputSeedAbiAccess::IncludeIota
            ),
            (
                7,
                "stream",
                WitnessInputSeedAbiArgumentKind::CudaStream,
                WitnessInputSeedAbiAccess::OrderedExecutionStream
            ),
        ],
    );
    assert_eq!(
        WITNESS_INPUT_SEED_FIXED_ORDER,
        [
            WitnessInputSeedFixedField::ScalarWords,
            WitnessInputSeedFixedField::RealRows,
            WitnessInputSeedFixedField::ConsumerRows,
            WitnessInputSeedFixedField::IncludeEnabler,
            WitnessInputSeedFixedField::IncludeIota,
        ]
    );
    assert_eq!(contract.fixed_words(), &[2, 497, 512, 1, 1]);
    assert_eq!(
        contract.effect_geometry(),
        &WitnessInputSeedEffectGeometry {
            scalar_source_start_word: 0,
            scalar_source_words: 2,
            real_rows: 497,
            consumer_rows: 512,
            output_columns: vec![
                WitnessInputSeedColumnEffect {
                    column_ordinal: 0,
                    value: WitnessInputSeedColumnValue::RepeatedScalar(0),
                    written_words: 512,
                },
                WitnessInputSeedColumnEffect {
                    column_ordinal: 1,
                    value: WitnessInputSeedColumnValue::RepeatedScalar(1),
                    written_words: 512,
                },
                WitnessInputSeedColumnEffect {
                    column_ordinal: 2,
                    value: WitnessInputSeedColumnValue::Enabler,
                    written_words: 512,
                },
                WitnessInputSeedColumnEffect {
                    column_ordinal: 3,
                    value: WitnessInputSeedColumnValue::Iota,
                    written_words: 512,
                },
            ],
        }
    );
    assert_eq!(
        contract.launch(),
        WitnessInputSeedKernelLaunch {
            grid: [2, 1, 1],
            block: [256, 1, 1],
            dynamic_shared_bytes: 0,
            cooperative: false,
            cluster: None,
        }
    );
    assert_eq!(contract.launch().symbol(), "witness_input_seed_kernel");
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
fn canonical_requirement_and_contract_mutations_fail_closed() {
    let baseline = requirements();
    let mut mutations = Vec::new();
    let mut changed = baseline.clone();
    changed.scalar_words += 1;
    mutations.push(changed);
    let mut changed = baseline.clone();
    changed.consumer_rows *= 2;
    mutations.push(changed);
    let mut changed = baseline.clone();
    changed.include_enabler = false;
    mutations.push(changed);
    let mut changed = baseline.clone();
    changed.include_iota = false;
    mutations.push(changed);
    let mut changed = baseline.clone();
    changed.consumer_input_column_words[0] -= 1;
    mutations.push(changed);
    let mut changed = baseline;
    changed.output_pointer_words += 1;
    mutations.push(changed);
    for mutation in mutations {
        assert_eq!(
            WitnessInputSeedContract::compile(&mutation),
            Err(WitnessInputSeedAuthorityError::InvalidCanonicalRequirements)
        );
    }
    let alternate = WitnessInputSeedContract::compile(
        &witness_input_seed_requirements(2, 496, 512, true, true).unwrap(),
    )
    .unwrap();
    assert_ne!(
        contract().requirements_identity(),
        alternate.requirements_identity()
    );
    assert_ne!(contract().fixed_identity(), alternate.fixed_identity());
    assert_ne!(contract().effect_identity(), alternate.effect_identity());
    assert_ne!(contract().identity(), alternate.identity());

    macro_rules! rejects {
        ($field:ident, $change:expr) => {{
            let mut changed = contract();
            $change(&mut changed.$field);
            assert_eq!(
                changed.validate(),
                Err(WitnessInputSeedAuthorityError::InvalidCanonicalRequirements),
                stringify!($field),
            );
        }};
    }
    rejects!(fixed_words, |value: &mut [u32; 5]| value[0] ^= 1);
    rejects!(
        effect_geometry,
        |value: &mut WitnessInputSeedEffectGeometry| value.consumer_rows += 1
    );
    rejects!(launch, |value: &mut WitnessInputSeedKernelLaunch| value
        .grid[0] +=
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
fn source_closure_and_linked_build_fields_are_all_identity_bearing() {
    let source = include_str!("../../../../../backend-cuda-kernels/cuda/witness_edge_gather.cu");
    for required in [
        "__global__ void witness_input_seed_kernel(",
        "extern \"C\" int stwo_witness_input_seed_on(",
        "const uint32_t block = 256;",
        "uint32_t grid = 1u + (consumer_rows - 1u) / block;",
        "witness_input_seed_kernel<<<grid, block, 0, (cudaStream_t)stream>>>",
    ] {
        assert!(
            source.contains(required),
            "missing source authority: {required}"
        );
    }
    assert_eq!(
        contract().wrapper_source_identity(),
        digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE)
    );

    let semantic = contract();
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
    assert_ne!(
        linked.identity(),
        linked_contract(
            semantic.identity(),
            binding_for_test(
                STATIC_BUILD_DOMAIN,
                semantic.identity(),
                [0x42; 32],
                [0x42; 32],
                &[86, 89],
                89,
            )
            .unwrap(),
        )
        .identity()
    );
    let mut changed_source = binding;
    changed_source.static_build_source_identity[0] ^= 1;
    assert_eq!(
        validate_binding_for_test(
            &changed_source,
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
        linked_contract(semantic.identity(), changed_source).identity()
    );
    let mut changed_aggregate = binding;
    changed_aggregate.identity[0] ^= 1;
    assert_eq!(
        validate_binding_for_test(
            &changed_aggregate,
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
        linked_contract(semantic.identity(), changed_aggregate).identity()
    );
    assert_ne!(
        linked.identity(),
        linked_contract(
            semantic.identity(),
            binding_for_test(
                STATIC_BUILD_DOMAIN,
                semantic.identity(),
                [0x41; 32],
                [0x41; 32],
                &[86, 89],
                86,
            )
            .unwrap(),
        )
        .identity()
    );
    assert_eq!(
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x41; 32],
            [0x41; 32],
            &[86, 89],
            90,
        ),
        Err(StaticBuildBindError::UnsupportedTargetSm(90))
    );
    assert_eq!(
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x41; 32],
            [0x42; 32],
            &[86, 89],
            89,
        ),
        Err(StaticBuildBindError::InconsistentBuildMetadata)
    );
    assert_eq!(
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            semantic.identity(),
            [0x41; 32],
            [0x41; 32],
            &[89, 86],
            89,
        ),
        Err(StaticBuildBindError::InconsistentBuildMetadata)
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
