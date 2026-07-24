use core::ffi::c_void;

use super::*;
use crate::backend::prepared_witness_input::static_build::{
    binding_for_test, validate_binding_for_test,
};
use crate::backend::prepared_witness_input::{
    WitnessInputCompactLayout, WitnessInputGatherDescriptorField, WitnessInputGatherEdge,
};

fn edges() -> [WitnessInputGatherEdge; 2] {
    [
        WitnessInputGatherEdge {
            producer_rows: 32,
            word_base: 2,
            words_per_instance: 3,
            n_instances: 2,
        },
        WitnessInputGatherEdge {
            producer_rows: 16,
            word_base: 4,
            words_per_instance: 3,
            n_instances: 1,
        },
    ]
}

fn layout() -> WitnessInputCompactLayout {
    WitnessInputCompactLayout {
        tuple_words: 3,
        key_words: 2,
        consumer_input_count: 6,
        enabler_slot: Some(3),
        iota_slot: Some(4),
        multiplicity_slot: 5,
    }
}

fn requirements() -> WitnessInputCompactRequirements {
    witness_input_compact_requirements(&edges(), layout(), 64).unwrap()
}

fn contract() -> WitnessInputCompactContract {
    WitnessInputCompactContract::compile(&requirements()).unwrap()
}

unsafe extern "C" fn failed_temp_query(_rows: u32, _out_bytes: *mut usize) -> i32 {
    719
}

unsafe extern "C" fn zero_temp_query(_rows: u32, _out_bytes: *mut usize) -> i32 {
    0
}

#[test]
fn scratch_query_failures_map_into_authority_errors() {
    assert_eq!(
        checked_witness_input_compact_temp_bytes(failed_temp_query, 64)
            .map_err(WitnessInputCompactAuthorityError::SortScratchQueryFailed),
        Err(WitnessInputCompactAuthorityError::SortScratchQueryFailed(
            719
        ))
    );
    assert_eq!(
        checked_witness_input_compact_temp_bytes(zero_temp_query, 64)
            .map_err(WitnessInputCompactAuthorityError::ScanScratchQueryFailed),
        Err(WitnessInputCompactAuthorityError::ScanScratchQueryFailed(0))
    );
}

#[test]
fn current_device_sm_provenance_is_exact_and_fail_closed() {
    let sm89 = crate::backend::exec_context::CudaDeviceSnapshot {
        count: 2,
        current: 1,
        sm_major: 8,
        sm_minor: 9,
    };
    assert_eq!(current_target_sm(sm89), Ok(89));
    assert_eq!(require_current_target_sm(89, sm89), Ok(()));
    assert_eq!(
        require_current_target_sm(86, sm89),
        Err(
            WitnessInputCompactAuthorityError::CurrentDeviceTargetSmMismatch {
                requested: 86,
                actual: 89,
            }
        )
    );
    for snapshot in [
        crate::backend::exec_context::CudaDeviceSnapshot::default(),
        crate::backend::exec_context::CudaDeviceSnapshot {
            count: 1,
            current: 1,
            sm_major: 8,
            sm_minor: 9,
        },
        crate::backend::exec_context::CudaDeviceSnapshot {
            count: 1,
            current: 0,
            sm_major: 8,
            sm_minor: 10,
        },
        crate::backend::exec_context::CudaDeviceSnapshot {
            count: 1,
            current: 0,
            sm_major: u32::MAX,
            sm_minor: 0,
        },
    ] {
        assert_eq!(
            current_target_sm(snapshot),
            Err(WitnessInputCompactAuthorityError::CurrentDeviceUnavailable)
        );
    }
}

#[test]
fn exact_composite_abi_descriptors_effects_and_sequence_are_sealed() {
    type RawTempBytesQuery = unsafe extern "C" fn(u32, *mut usize) -> i32;
    type RawCompact = unsafe extern "C" fn(
        *const *const u32,
        *const u32,
        u32,
        u32,
        u32,
        u32,
        u32,
        u32,
        u32,
        *const *mut u32,
        u32,
        u32,
        u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut c_void,
        usize,
        *mut c_void,
        usize,
        *mut c_void,
    ) -> i32;
    let _: RawTempBytesQuery =
        stwo_backend_cuda_kernels::raw::stwo_witness_input_compact_sort_temp_bytes;
    let _: RawTempBytesQuery =
        stwo_backend_cuda_kernels::raw::stwo_witness_input_compact_scan_temp_bytes;
    let _: RawCompact = stwo_backend_cuda_kernels::raw::stwo_witness_input_compact_on;

    let contract = contract();
    contract.validate().unwrap();
    assert_eq!(
        contract.abi().entry_symbol(),
        "stwo_witness_input_compact_on"
    );
    assert_eq!(contract.abi().arguments().len(), 26);
    assert_eq!(
        contract
            .abi()
            .arguments()
            .iter()
            .map(|argument| argument.ordinal)
            .collect::<Vec<_>>(),
        (0..26).collect::<Vec<_>>()
    );
    assert_eq!(
        contract
            .abi()
            .arguments()
            .iter()
            .map(|argument| argument.name)
            .collect::<Vec<_>>(),
        [
            "producer_subs_dev",
            "edge_descs_dev",
            "n_edges",
            "tuple_words",
            "key_words",
            "total_rows",
            "sort_rows",
            "consumer_rows",
            "n_inputs",
            "consumer_cols_dev",
            "enabler_slot",
            "iota_slot",
            "multiplicity_slot",
            "tuples_dev",
            "keys_a_dev",
            "keys_b_dev",
            "indices_a_dev",
            "indices_b_dev",
            "heads_dev",
            "positions_dev",
            "n_unique_dev",
            "sort_temp_dev",
            "sort_temp_bytes",
            "scan_temp_dev",
            "scan_temp_bytes",
            "stream",
        ]
    );
    assert_eq!(
        WITNESS_INPUT_GATHER_DESCRIPTOR_ORDER,
        [
            WitnessInputGatherDescriptorField::ProducerRows,
            WitnessInputGatherDescriptorField::WordBase,
            WitnessInputGatherDescriptorField::WordsPerInstance,
            WitnessInputGatherDescriptorField::InstanceCount,
            WitnessInputGatherDescriptorField::DestinationRowOffset,
        ]
    );
    assert_eq!(
        contract.descriptor_words(),
        &[32, 2, 3, 2, 0, 16, 4, 3, 1, 64]
    );
    assert_eq!(
        WITNESS_INPUT_COMPACT_FIXED_ORDER,
        [
            WitnessInputCompactFixedField::EdgeCount,
            WitnessInputCompactFixedField::TupleWords,
            WitnessInputCompactFixedField::KeyWords,
            WitnessInputCompactFixedField::TotalRows,
            WitnessInputCompactFixedField::SortRows,
            WitnessInputCompactFixedField::ConsumerRows,
            WitnessInputCompactFixedField::ConsumerInputCount,
            WitnessInputCompactFixedField::EnablerSlot,
            WitnessInputCompactFixedField::IotaSlot,
            WitnessInputCompactFixedField::MultiplicitySlot,
        ]
    );
    assert_eq!(contract.fixed_words(), &[2, 3, 2, 80, 128, 64, 6, 3, 4, 5]);
    let without_enabler = WitnessInputCompactContract::compile(
        &witness_input_compact_requirements(
            &edges(),
            WitnessInputCompactLayout {
                tuple_words: 3,
                key_words: 2,
                consumer_input_count: 5,
                enabler_slot: None,
                iota_slot: Some(3),
                multiplicity_slot: 4,
            },
            64,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(without_enabler.fixed_words()[7], u32::MAX);

    let geometry = contract.effect_geometry();
    assert_eq!(
        geometry.sources,
        vec![
            WitnessInputCompactSourceEffect {
                source_ordinal: 0,
                read_start_words: 64,
                read_len_words: 192,
            },
            WitnessInputCompactSourceEffect {
                source_ordinal: 1,
                read_start_words: 64,
                read_len_words: 48,
            },
        ]
    );
    assert_eq!(geometry.descriptor_read_start_words, 0);
    assert_eq!(geometry.descriptor_read_len_words, 10);
    assert!(geometry.rejects_equal_key_distinct_tuple);
    assert_eq!(geometry.padding_source_unique_row, 0);
    assert_eq!(geometry.padding_multiplicity, 0);
    assert_eq!(
        geometry.outputs,
        (0..6)
            .map(|output_ordinal| WitnessInputCompactOutputEffect {
                output_ordinal,
                write_start_words: 0,
                write_len_words: 64,
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        geometry.scratch,
        WitnessInputCompactScratchEffect {
            tuple_words: 384,
            sort_key_words_each: 128,
            sort_index_words_each: 128,
            run_words_each: 128,
            unique_count_words: 1,
            sort_temp_capacity_words: 5120,
            scan_temp_capacity_words: 1280,
        }
    );

    let stages = contract.stages();
    assert_eq!(stages.len(), 12);
    assert_eq!(
        stages.iter().map(|stage| stage.ordinal).collect::<Vec<_>>(),
        (0..12).collect::<Vec<_>>()
    );
    assert!(matches!(
        stages[0].execution,
        WitnessInputCompactExecution::Kernel {
            stage: WitnessInputCompactKernelStage::Gather,
            ..
        }
    ));
    for (offset, (word, from, to)) in [
        (
            2,
            WitnessInputCompactIndexBuffer::A,
            WitnessInputCompactIndexBuffer::B,
        ),
        (
            1,
            WitnessInputCompactIndexBuffer::B,
            WitnessInputCompactIndexBuffer::A,
        ),
        (
            0,
            WitnessInputCompactIndexBuffer::A,
            WitnessInputCompactIndexBuffer::B,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let key = 1 + offset * 2;
        assert!(matches!(
            stages[key].execution,
            WitnessInputCompactExecution::Kernel {
                stage: WitnessInputCompactKernelStage::ExtractKey {
                    word: actual,
                    indices,
                },
                ..
            } if actual == word && indices == from
        ));
        assert!(matches!(
            stages[key + 1].execution,
            WitnessInputCompactExecution::Cub {
                stage: WitnessInputCompactCubStage::StableRadixSortPairs {
                    word: actual,
                    keys_from: WitnessInputCompactKeyBuffer::A,
                    keys_to: WitnessInputCompactKeyBuffer::B,
                    indices_from,
                    indices_to,
                    begin_bit: 0,
                    end_bit: 32,
                },
                library_managed_launch_geometry: true,
                ordered_on_wrapper_stream: true,
            } if actual == word && indices_from == from && indices_to == to
        ));
    }
    assert!(matches!(
        stages[7].execution,
        WitnessInputCompactExecution::Kernel {
            stage: WitnessInputCompactKernelStage::Heads {
                indices: WitnessInputCompactIndexBuffer::B
            },
            ..
        }
    ));
    assert!(matches!(
        stages[8].execution,
        WitnessInputCompactExecution::Cub {
            stage: WitnessInputCompactCubStage::InclusiveSum,
            ..
        }
    ));
    assert!(matches!(
        stages[9].execution,
        WitnessInputCompactExecution::Kernel {
            stage: WitnessInputCompactKernelStage::ClearOutput,
            ..
        }
    ));
    assert!(matches!(
        stages[10].execution,
        WitnessInputCompactExecution::Kernel {
            stage: WitnessInputCompactKernelStage::Scatter {
                indices: WitnessInputCompactIndexBuffer::B
            },
            ..
        }
    ));
    assert!(matches!(
        stages[11].execution,
        WitnessInputCompactExecution::Kernel {
            stage: WitnessInputCompactKernelStage::Finalize,
            ..
        }
    ));
    assert_eq!(contract.final_indices(), WitnessInputCompactIndexBuffer::B);
    for stage in stages {
        if let WitnessInputCompactExecution::Kernel { launch, .. } = stage.execution {
            assert_eq!(launch.block, [256, 1, 1]);
            assert_eq!(launch.dynamic_shared_bytes, 0);
            assert!(!launch.cooperative);
            assert_eq!(launch.cluster, None);
        }
    }
}

#[test]
fn identities_and_mutations_cover_the_complete_semantic_contract() {
    let baseline = contract();
    for identity in [
        baseline.static_source_identity(),
        baseline.wrapper_source_identity(),
        baseline.source_identity(),
        baseline.requirements_identity(),
        baseline.descriptor_identity(),
        baseline.fixed_identity(),
        baseline.abi_identity(),
        baseline.effect_identity(),
        baseline.launch_identity(),
        baseline.identity(),
    ] {
        assert_ne!(identity, ZERO_IDENTITY);
    }
    let mut requirement_mutations = Vec::new();
    let mut changed = requirements();
    changed.edges[0].edge.word_base += 1;
    requirement_mutations.push(changed);
    let mut changed = requirements();
    changed.total_input_rows += 1;
    requirement_mutations.push(changed);
    let mut changed = requirements();
    changed.sort_rows *= 2;
    requirement_mutations.push(changed);
    let mut changed = requirements();
    changed.consumer_rows *= 2;
    requirement_mutations.push(changed);
    let mut changed = requirements();
    changed.consumer_input_column_words[0] += 1;
    requirement_mutations.push(changed);
    let mut changed = requirements();
    changed.descriptor_words += 1;
    requirement_mutations.push(changed);
    let mut changed = requirements();
    changed.tuple_scratch_words += 1;
    requirement_mutations.push(changed);
    let mut changed = requirements();
    changed.sort_temp_words += 1;
    requirement_mutations.push(changed);
    for mutation in requirement_mutations {
        assert!(WitnessInputCompactContract::compile(&mutation).is_err());
    }
    let mut alternate_layout = layout();
    alternate_layout.key_words = 1;
    let alternate = WitnessInputCompactContract::compile(
        &witness_input_compact_requirements(&edges(), alternate_layout, 64).unwrap(),
    )
    .unwrap();
    assert_ne!(
        baseline.requirements_identity(),
        alternate.requirements_identity()
    );
    assert_ne!(baseline.fixed_identity(), alternate.fixed_identity());
    assert_ne!(baseline.effect_identity(), alternate.effect_identity());
    assert_ne!(baseline.identity(), alternate.identity());

    macro_rules! rejects {
        ($field:ident, $change:expr) => {{
            let mut changed = contract();
            $change(&mut changed.$field);
            assert_eq!(
                changed.validate(),
                Err(WitnessInputCompactAuthorityError::InvalidCanonicalRequirements),
                stringify!($field),
            );
        }};
    }
    rejects!(descriptor_words, |value: &mut Box<[u32]>| value[0] ^= 1);
    rejects!(fixed_words, |value: &mut [u32; 10]| value[0] ^= 1);
    rejects!(
        effect_geometry,
        |value: &mut WitnessInputCompactEffectGeometry| value.total_rows += 1
    );
    rejects!(stages, |value: &mut Box<[WitnessInputCompactStage]>| {
        value[0].ordinal += 1
    });
    rejects!(
        final_indices,
        |value: &mut WitnessInputCompactIndexBuffer| { *value = WitnessInputCompactIndexBuffer::A }
    );
    rejects!(source_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(requirements_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(descriptor_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(fixed_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(abi_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(effect_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(launch_identity, |value: &mut [u8; 32]| value[0] ^= 1);
    rejects!(identity, |value: &mut [u8; 32]| value[0] ^= 1);
}

#[test]
fn source_order_build_sm_and_runtime_scratch_fail_closed() {
    let source = include_str!("../../../../../backend-cuda-kernels/cuda/witness_edge_gather.cu");
    for declaration in [
        "extern \"C\" int stwo_witness_input_compact_sort_temp_bytes(",
        "extern \"C\" int stwo_witness_input_compact_scan_temp_bytes(",
    ] {
        assert!(
            source.contains(declaration),
            "missing checked compact scratch query: {declaration}"
        );
    }
    for invariant in [
        "if (out_bytes == nullptr) {",
        "*out_bytes = 0;",
        "if (rows == 0) {",
        "if (bytes == 0) {",
        "return (int)error;",
        "*out_bytes = bytes;",
    ] {
        assert_eq!(
            source.matches(invariant).count(),
            2,
            "both compact scratch queries must enforce: {invariant}"
        );
    }
    assert_eq!(
        source.matches("return (int)cudaErrorInvalidValue;").count(),
        6
    );
    assert_eq!(source.matches("return (int)cudaSuccess;").count(), 2);
    let ordered = [
        "witness_input_compact_gather_kernel<<<",
        "for (uint32_t word = tuple_words; word-- > 0;)",
        "witness_input_compact_key_kernel<<<",
        "cub::DeviceRadixSort::SortPairs(",
        "witness_input_compact_heads_kernel<<<",
        "cub::DeviceScan::InclusiveSum(",
        "witness_input_compact_clear_output_kernel<<<",
        "witness_input_compact_scatter_kernel<<<",
        "witness_input_compact_finalize_kernel<<<",
    ];
    let mut cursor = 0;
    for needle in ordered {
        let found = source[cursor..]
            .find(needle)
            .unwrap_or_else(|| panic!("missing or misordered source authority: {needle}"));
        cursor += found + needle.len();
    }
    for invariant in [
        "same %u-word key, different %u-word tuple",
        "consumer_cols[word][row] = consumer_cols[word][0];",
        "consumer_cols[multiplicity_slot][row] = 0u;",
    ] {
        assert!(
            source.contains(invariant),
            "missing compact semantic authority: {invariant}"
        );
    }
    let contract = contract();
    assert_eq!(
        contract.wrapper_source_identity(),
        digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE)
    );
    let binding = binding_for_test(
        STATIC_BUILD_DOMAIN,
        contract.identity(),
        [0x51; 32],
        [0x51; 32],
        &[86, 89],
        89,
    )
    .unwrap();
    let linked = linked_contract(&contract, binding, 2048, 1024).unwrap();
    assert_eq!(linked.contract_identity(), contract.identity());
    assert_eq!(linked.module_build_identity(), [0x51; 32]);
    assert_ne!(linked.static_build_source_identity(), ZERO_IDENTITY);
    assert_ne!(linked.static_build_identity(), ZERO_IDENTITY);
    assert_eq!(linked.target_sm(), 89);
    assert_eq!(linked.sort_temp_bytes(), 2048);
    assert_eq!(linked.scan_temp_bytes(), 1024);
    assert_ne!(linked.runtime_scratch_identity(), ZERO_IDENTITY);
    assert_ne!(linked.identity(), ZERO_IDENTITY);

    let changed_build = binding_for_test(
        STATIC_BUILD_DOMAIN,
        contract.identity(),
        [0x52; 32],
        [0x52; 32],
        &[86, 89],
        89,
    )
    .unwrap();
    assert_ne!(
        linked.identity(),
        linked_contract(&contract, changed_build, 2048, 1024)
            .unwrap()
            .identity()
    );
    let mut changed_source = binding;
    changed_source.static_build_source_identity[0] ^= 1;
    assert_eq!(
        validate_binding_for_test(
            &changed_source,
            STATIC_BUILD_DOMAIN,
            contract.identity(),
            [0x51; 32],
            [0x51; 32],
            &[86, 89],
            89,
        ),
        Err(StaticBuildBindError::InconsistentBuildMetadata)
    );
    assert_ne!(
        linked.identity(),
        linked_contract(&contract, changed_source, 2048, 1024)
            .unwrap()
            .identity()
    );
    let mut changed_aggregate = binding;
    changed_aggregate.identity[0] ^= 1;
    assert_eq!(
        validate_binding_for_test(
            &changed_aggregate,
            STATIC_BUILD_DOMAIN,
            contract.identity(),
            [0x51; 32],
            [0x51; 32],
            &[86, 89],
            89,
        ),
        Err(StaticBuildBindError::InconsistentBuildMetadata)
    );
    assert_ne!(
        linked.identity(),
        linked_contract(&contract, changed_aggregate, 2048, 1024)
            .unwrap()
            .identity()
    );
    assert_ne!(
        linked.identity(),
        linked_contract(&contract, binding, 2049, 1024)
            .unwrap()
            .identity()
    );
    assert_eq!(
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            contract.identity(),
            [0x51; 32],
            [0x50; 32],
            &[86, 89],
            89,
        ),
        Err(StaticBuildBindError::InconsistentBuildMetadata)
    );
    assert_eq!(
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            contract.identity(),
            [0x51; 32],
            [0x51; 32],
            &[89, 86],
            89,
        ),
        Err(StaticBuildBindError::InconsistentBuildMetadata)
    );
    assert_eq!(
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            contract.identity(),
            [0x51; 32],
            [0x51; 32],
            &[86, 89],
            90,
        ),
        Err(StaticBuildBindError::UnsupportedTargetSm(90))
    );
    assert_eq!(
        linked_contract(&contract, binding, 0, 1024),
        Err(WitnessInputCompactAuthorityError::InvalidRuntimeScratch)
    );
    assert_eq!(
        linked_contract(
            &contract,
            binding,
            contract.requirements().sort_temp_words * 4 + 1,
            1024,
        ),
        Err(WitnessInputCompactAuthorityError::InvalidRuntimeScratch)
    );

    if stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        let target =
            current_target_sm(crate::backend::exec_context::cuda_device_snapshot().unwrap())
                .unwrap();
        assert!(stwo_backend_cuda_kernels::static_cuda_module_target_sms().contains(&target));
        contract
            .bind_static_build(target)
            .unwrap()
            .unwrap()
            .validate(&contract)
            .unwrap();
    } else {
        assert_eq!(contract.bind_static_build(89).unwrap(), None);
    }
}
