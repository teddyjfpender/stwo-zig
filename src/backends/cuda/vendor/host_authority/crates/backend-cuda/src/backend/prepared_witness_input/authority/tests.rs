use core::ffi::c_void;

use super::super::WitnessInputGatherEdge;
use super::*;
use crate::backend::prepared_witness_input::static_build::{
    binding_for_test, validate_binding_for_test, StaticBuildBindError, StaticBuildBinding,
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

fn requirements() -> WitnessInputGatherRequirements {
    witness_input_gather_requirements(&edges(), true, true).unwrap()
}

fn contract() -> WitnessInputGatherContract {
    WitnessInputGatherContract::compile(&requirements()).unwrap()
}

#[test]
fn exact_contract_is_deterministic_complete_and_address_free() {
    type RawGather = unsafe extern "C" fn(
        *const *const u32,
        *const u32,
        u32,
        u32,
        u32,
        u32,
        *const *mut u32,
        u32,
        u32,
        *mut c_void,
    ) -> i32;
    let _: RawGather = stwo_backend_cuda_kernels::raw::stwo_witness_input_gather_on;

    let baseline = contract();
    assert_eq!(baseline, contract());
    baseline.validate().unwrap();
    assert_eq!(baseline.abi(), WitnessInputGatherAbi::PackedEdgesV1);
    assert_eq!(
        baseline.effect(),
        WitnessInputGatherEffectAbi::ReadPackedEdgesWritePaddedColumnsV1
    );
    assert_eq!(
        baseline.row_domain(),
        WitnessInputGatherRowDomain::StackedPackedEdgesRepeatFirstPackedRowV1
    );
    assert_eq!(
        baseline.abi().entry_symbol(),
        "stwo_witness_input_gather_on"
    );
    assert_eq!(baseline.abi().arguments().len(), 10);
    assert_eq!(
        baseline
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
                "producer_subs_dev",
                WitnessInputGatherAbiArgumentKind::DeviceConstPointerTableU32,
                WitnessInputGatherAbiAccess::ReadPackedProducerColumns,
            ),
            (
                1,
                "edge_descs_dev",
                WitnessInputGatherAbiArgumentKind::DeviceConstPointerU32,
                WitnessInputGatherAbiAccess::ReadCanonicalEdgeDescriptors,
            ),
            (
                2,
                "n_edges",
                WitnessInputGatherAbiArgumentKind::U32,
                WitnessInputGatherAbiAccess::EdgeCount,
            ),
            (
                3,
                "input_width",
                WitnessInputGatherAbiArgumentKind::U32,
                WitnessInputGatherAbiAccess::InputWidth,
            ),
            (
                4,
                "total_real_rows",
                WitnessInputGatherAbiArgumentKind::U32,
                WitnessInputGatherAbiAccess::TotalRealRows,
            ),
            (
                5,
                "consumer_rows",
                WitnessInputGatherAbiArgumentKind::U32,
                WitnessInputGatherAbiAccess::ConsumerRows,
            ),
            (
                6,
                "consumer_cols_dev",
                WitnessInputGatherAbiArgumentKind::DeviceMutPointerTableU32,
                WitnessInputGatherAbiAccess::WriteConsumerColumns,
            ),
            (
                7,
                "include_enabler",
                WitnessInputGatherAbiArgumentKind::U32,
                WitnessInputGatherAbiAccess::IncludeEnabler,
            ),
            (
                8,
                "include_iota",
                WitnessInputGatherAbiArgumentKind::U32,
                WitnessInputGatherAbiAccess::IncludeIota,
            ),
            (
                9,
                "stream",
                WitnessInputGatherAbiArgumentKind::CudaStream,
                WitnessInputGatherAbiAccess::OrderedExecutionStream,
            ),
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
        baseline.descriptor_words(),
        &[32, 2, 3, 2, 0, 16, 4, 3, 1, 64]
    );
    assert_eq!(baseline.requirements(), &requirements());

    let effect = baseline.effect_geometry();
    assert_eq!(
        effect.edges,
        vec![
            WitnessInputGatherPackedEdgeEffect {
                source_ordinal: 0,
                source_start_words: 64,
                source_len_words: 192,
                destination_row_offset: 0,
                destination_rows: 64,
            },
            WitnessInputGatherPackedEdgeEffect {
                source_ordinal: 1,
                source_start_words: 64,
                source_len_words: 48,
                destination_row_offset: 64,
                destination_rows: 16,
            },
        ]
    );
    assert_eq!(effect.descriptor_read_start_words, 0);
    assert_eq!(effect.descriptor_read_len_words, 10);
    assert_eq!(
        effect.output_writes,
        (0..5)
            .map(|output_ordinal| WitnessInputGatherOutputEffect {
                output_ordinal,
                write_start_words: 0,
                write_len_words: 128,
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(effect.packed_lanes, 16);
    assert_eq!(effect.input_columns, 3);
    assert_eq!(effect.output_columns, 5);
    assert_eq!(effect.total_real_rows, 80);
    assert_eq!(effect.consumer_rows, 128);
    assert!(effect.include_enabler);
    assert!(effect.include_iota);
    assert_eq!(effect.padding_source_edge, 0);
    assert_eq!(effect.padding_source_rows, 16);

    let launch = baseline.wrapper_launch();
    assert_eq!(
        launch.audited_internal_kernel_symbol(),
        "witness_input_gather_kernel"
    );
    assert_eq!(launch.grid, [1, 1, 1]);
    assert_eq!(launch.block, [256, 1, 1]);
    assert_eq!(launch.dynamic_shared_bytes, 0);
    assert!(!launch.cooperative);
    for identity in [
        baseline.static_source_identity(),
        baseline.wrapper_source_identity(),
        baseline.source_identity(),
        baseline.requirements_identity(),
        baseline.descriptor_identity(),
        baseline.abi_identity(),
        baseline.effect_identity(),
        baseline.launch_identity(),
        baseline.identity(),
    ] {
        assert_ne!(identity, ZERO_IDENTITY);
    }
}

#[test]
fn source_closure_seals_exact_wrapper_kernel_descriptor_and_stream_launch() {
    let source = include_str!("../../../../../backend-cuda-kernels/cuda/witness_edge_gather.cu");
    for required in [
        "#define WIG_DESC_STRIDE 5u",
        "[producer_rows, word_base, words_per_instance, n_instances, destination_row_offset]",
        "__global__ void witness_input_gather_kernel(",
        "extern \"C\" int stwo_witness_input_gather_on(",
        "const uint32_t block = 256;",
        "uint32_t grid = 1u + (consumer_rows - 1u) / block;",
        "witness_input_gather_kernel<<<grid, block, 0, (cudaStream_t)stream>>>",
        "uint32_t source_global_row = row < total_real_rows ? row : (row & 15u);",
    ] {
        assert!(
            source.contains(required),
            "missing source authority: {required}"
        );
    }

    let static_source = [0x11; 32];
    let wrapper_source = [0x22; 32];
    let baseline = source_identity_from(
        static_source,
        wrapper_source,
        BINDER_SOURCE,
        AUTHORITY_SOURCE,
        LINKED_SOURCE,
    );
    let mut changed_static = static_source;
    changed_static[0] ^= 1;
    assert_ne!(
        baseline,
        source_identity_from(
            changed_static,
            wrapper_source,
            BINDER_SOURCE,
            AUTHORITY_SOURCE,
            LINKED_SOURCE,
        )
    );
    let mut changed_wrapper = wrapper_source;
    changed_wrapper[0] ^= 1;
    assert_ne!(
        baseline,
        source_identity_from(
            static_source,
            changed_wrapper,
            BINDER_SOURCE,
            AUTHORITY_SOURCE,
            LINKED_SOURCE,
        )
    );
    for changed_index in 0..3 {
        let mut sources = [
            BINDER_SOURCE.to_vec(),
            AUTHORITY_SOURCE.to_vec(),
            LINKED_SOURCE.to_vec(),
        ];
        sources[changed_index][0] ^= 1;
        assert_ne!(
            baseline,
            source_identity_from(
                static_source,
                wrapper_source,
                &sources[0],
                &sources[1],
                &sources[2],
            ),
            "source {changed_index} was not sealed",
        );
    }
    assert_eq!(
        contract().wrapper_source_identity(),
        digest(WRAPPER_SOURCE_DOMAIN, source.as_bytes())
    );
}

#[test]
fn linked_build_authority_seals_contract_module_source_target_and_sm() {
    let semantic = contract();
    let binding = binding_for_test(
        linked::STATIC_BUILD_DOMAIN,
        semantic.identity(),
        [0x41; 32],
        [0x41; 32],
        &[86, 89],
        89,
    )
    .unwrap();
    validate_binding_for_test(
        &binding,
        linked::STATIC_BUILD_DOMAIN,
        semantic.identity(),
        [0x41; 32],
        [0x41; 32],
        &[86, 89],
        89,
    )
    .unwrap();
    let linked = linked::linked_contract(semantic.identity(), binding);
    assert_eq!(linked.contract_identity(), semantic.identity());
    assert_eq!(linked.module_build_identity(), [0x41; 32]);
    assert_ne!(linked.static_build_source_identity(), ZERO_IDENTITY);
    assert_ne!(linked.static_build_identity(), ZERO_IDENTITY);
    assert_eq!(linked.target_sm(), 89);
    assert_ne!(linked.sm_identity(), ZERO_IDENTITY);
    assert_ne!(linked.identity(), ZERO_IDENTITY);

    let changed_contract = linked::linked_contract([0x77; 32], binding);
    assert_ne!(linked.identity(), changed_contract.identity());

    let changed_build = binding_for_test(
        linked::STATIC_BUILD_DOMAIN,
        semantic.identity(),
        [0x42; 32],
        [0x42; 32],
        &[86, 89],
        89,
    )
    .unwrap();
    assert_ne!(
        linked.identity(),
        linked::linked_contract(semantic.identity(), changed_build).identity()
    );

    let changed_sm = binding_for_test(
        linked::STATIC_BUILD_DOMAIN,
        semantic.identity(),
        [0x41; 32],
        [0x41; 32],
        &[86, 89],
        86,
    )
    .unwrap();
    assert_ne!(
        linked.identity(),
        linked::linked_contract(semantic.identity(), changed_sm).identity()
    );

    let mutations: [fn(&mut StaticBuildBinding); 5] = [
        |changed| changed.module_build_identity[0] ^= 1,
        |changed| changed.static_build_source_identity[0] ^= 1,
        |changed| changed.target_sm ^= 1,
        |changed| changed.sm_identity[0] ^= 1,
        |changed| changed.identity[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = binding;
        mutate(&mut changed);
        assert_eq!(
            validate_binding_for_test(
                &changed,
                linked::STATIC_BUILD_DOMAIN,
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
            linked::linked_contract(semantic.identity(), changed).identity()
        );
    }

    assert_eq!(
        binding_for_test(
            linked::STATIC_BUILD_DOMAIN,
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
            linked::STATIC_BUILD_DOMAIN,
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
            linked::STATIC_BUILD_DOMAIN,
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

#[test]
fn every_requirements_shape_drift_is_rejected() {
    let mutations: [fn(&mut WitnessInputGatherRequirements); 22] = [
        |changed| {
            changed.edges.swap(0, 1);
        },
        |changed| {
            changed.edges.pop();
        },
        |changed| changed.edges.clear(),
        |changed| changed.edges.push(changed.edges[0]),
        |changed| changed.edges[0].edge.producer_rows += 16,
        |changed| changed.edges[0].edge.word_base += 1,
        |changed| changed.edges[0].edge.words_per_instance += 1,
        |changed| changed.edges[0].edge.n_instances += 1,
        |changed| changed.edges[0].destination_row_offset += 16,
        |changed| changed.edges[0].destination_rows += 16,
        |changed| changed.edges[0].required_source_words += 1,
        |changed| changed.input_width += 1,
        |changed| changed.total_real_rows += 16,
        |changed| changed.consumer_rows *= 2,
        |changed| changed.include_enabler = false,
        |changed| changed.include_iota = false,
        |changed| changed.consumer_input_column_words[0] -= 1,
        |changed| {
            changed.consumer_input_column_words.pop();
        },
        |changed| {
            changed
                .consumer_input_column_words
                .push(changed.consumer_rows)
        },
        |changed| changed.source_pointer_words += 1,
        |changed| changed.descriptor_words += 1,
        |changed| changed.output_pointer_words += 1,
    ];
    for mutate in mutations {
        let mut changed = requirements();
        mutate(&mut changed);
        assert_eq!(
            WitnessInputGatherContract::compile(&changed),
            Err(WitnessInputGatherAuthorityError::InvalidCanonicalRequirements)
        );
    }
}

#[test]
fn all_representable_overflow_frontiers_fail_closed() {
    let Some(too_large_u32) = (u32::MAX as usize).checked_add(1) else {
        return;
    };
    let mut cases = Vec::new();
    let mut changed = requirements();
    changed.edges[0].edge.producer_rows = too_large_u32;
    cases.push(changed);
    let mut changed = requirements();
    changed.edges[0].edge.word_base = too_large_u32;
    cases.push(changed);
    let mut changed = requirements();
    changed.edges[0].edge.words_per_instance = too_large_u32;
    cases.push(changed);
    let mut changed = requirements();
    changed.edges[0].edge.n_instances = too_large_u32;
    cases.push(changed);
    let mut changed = requirements();
    changed.edges[0].edge.producer_rows = 1 << 16;
    changed.edges[0].edge.n_instances = 1 << 16;
    cases.push(changed);
    for changed in cases {
        assert_eq!(
            WitnessInputGatherContract::compile(&changed),
            Err(WitnessInputGatherAuthorityError::SizeOverflow)
        );
    }
}

#[test]
fn canonical_geometry_changes_only_the_appropriate_identities() {
    let baseline = contract();
    let without_tail = WitnessInputGatherContract::compile(
        &witness_input_gather_requirements(&edges(), false, false).unwrap(),
    )
    .unwrap();
    assert_eq!(
        baseline.static_source_identity(),
        without_tail.static_source_identity()
    );
    assert_eq!(
        baseline.wrapper_source_identity(),
        without_tail.wrapper_source_identity()
    );
    assert_eq!(baseline.source_identity(), without_tail.source_identity());
    assert_eq!(baseline.abi_identity(), without_tail.abi_identity());
    assert_eq!(
        baseline.descriptor_identity(),
        without_tail.descriptor_identity()
    );
    assert_eq!(baseline.launch_identity(), without_tail.launch_identity());
    assert_ne!(
        baseline.requirements_identity(),
        without_tail.requirements_identity()
    );
    assert_ne!(baseline.effect_identity(), without_tail.effect_identity());
    assert_ne!(baseline.identity(), without_tail.identity());

    let mut larger_edges = edges();
    larger_edges[0].n_instances = 9;
    let larger = WitnessInputGatherContract::compile(
        &witness_input_gather_requirements(&larger_edges, true, true).unwrap(),
    )
    .unwrap();
    assert_ne!(baseline.descriptor_identity(), larger.descriptor_identity());
    assert_ne!(baseline.effect_identity(), larger.effect_identity());
    assert_ne!(baseline.launch_identity(), larger.launch_identity());
    assert_ne!(baseline.identity(), larger.identity());
    assert_eq!(larger.wrapper_launch().grid, [2, 1, 1]);
}

#[test]
fn every_stored_authority_mutation_fails_revalidation() {
    let mutations: [fn(&mut WitnessInputGatherContract); 39] = [
        |changed| changed.requirements.total_real_rows += 16,
        |changed| changed.descriptor_words[0] ^= 1,
        |changed| {
            changed.descriptor_words =
                changed.descriptor_words[..changed.descriptor_words.len() - 1].into()
        },
        |changed| {
            changed.effect_geometry.edges.pop();
        },
        |changed| changed.effect_geometry.edges[0].source_ordinal += 1,
        |changed| changed.effect_geometry.edges[0].source_start_words += 1,
        |changed| changed.effect_geometry.edges[0].source_len_words += 1,
        |changed| changed.effect_geometry.edges[0].destination_row_offset += 1,
        |changed| changed.effect_geometry.edges[0].destination_rows += 1,
        |changed| changed.effect_geometry.descriptor_read_start_words += 1,
        |changed| changed.effect_geometry.descriptor_read_len_words -= 1,
        |changed| {
            changed.effect_geometry.output_writes.pop();
        },
        |changed| changed.effect_geometry.output_writes[0].output_ordinal += 1,
        |changed| changed.effect_geometry.output_writes[0].write_start_words += 1,
        |changed| changed.effect_geometry.output_writes[0].write_len_words -= 1,
        |changed| changed.effect_geometry.packed_lanes += 1,
        |changed| changed.effect_geometry.input_columns += 1,
        |changed| changed.effect_geometry.output_columns += 1,
        |changed| changed.effect_geometry.total_real_rows += 1,
        |changed| changed.effect_geometry.consumer_rows += 1,
        |changed| changed.effect_geometry.include_enabler = false,
        |changed| changed.effect_geometry.include_iota = false,
        |changed| changed.effect_geometry.padding_source_edge += 1,
        |changed| changed.effect_geometry.padding_source_rows -= 1,
        |changed| changed.wrapper_launch.grid[0] += 1,
        |changed| changed.wrapper_launch.grid[1] += 1,
        |changed| changed.wrapper_launch.block[0] -= 1,
        |changed| changed.wrapper_launch.block[1] += 1,
        |changed| changed.wrapper_launch.dynamic_shared_bytes += 1,
        |changed| changed.wrapper_launch.cooperative = true,
        |changed| changed.static_source_identity[0] ^= 1,
        |changed| changed.wrapper_source_identity[0] ^= 1,
        |changed| changed.source_identity[0] ^= 1,
        |changed| changed.requirements_identity[0] ^= 1,
        |changed| changed.descriptor_identity[0] ^= 1,
        |changed| changed.abi_identity[0] ^= 1,
        |changed| changed.effect_identity[0] ^= 1,
        |changed| changed.launch_identity[0] ^= 1,
        |changed| changed.identity[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = contract();
        mutate(&mut changed);
        assert!(changed.validate().is_err());
    }
}
