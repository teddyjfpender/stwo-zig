use super::super::WITNESS_FEED_NO_LUT;
use super::*;
use crate::backend::prepared_witness_input::static_build::binding_for_test;

const BUILD: [u8; 32] = [7; 32];
const SMS: [u32; 2] = [89, 90];

fn fold_descriptor(
    word_base: u32,
    bits: &[u32],
    relation: u32,
    table_size: u32,
    lut: u32,
    destination: u32,
) -> [u32; WITNESS_FEED_DESCRIPTOR_WORDS] {
    let mut entry = [0; WITNESS_FEED_DESCRIPTOR_WORDS];
    entry[0] = word_base;
    entry[1] = bits.len() as u32;
    entry[2..2 + bits.len()].copy_from_slice(bits);
    entry[7] = relation;
    entry[8] = table_size;
    entry[9] = lut;
    entry[10] = destination;
    entry
}

fn fixture() -> (WitnessFeedWorkspaceRequirements, Vec<u32>, Vec<Vec<u32>>) {
    let mut descriptors = Vec::new();
    descriptors.extend(fold_descriptor(0, &[2, 2], 1, 16, 0, 0));

    let mut memory = fold_descriptor(2, &[31], 1, 8, WITNESS_FEED_NO_LUT, 1);
    memory[11] = WitnessFeedDescriptorKind::MemoryIdDecode as u32;
    memory[12] = 4;
    memory[13] = 2;
    descriptors.extend(memory);

    let mut xor4 = fold_descriptor(3, &[4, 4, 4], 0, 1 << 8, 1, 3);
    xor4[11] = WitnessFeedDescriptorKind::DependentXor as u32;
    descriptors.extend(xor4);

    let mut xor12 = fold_descriptor(6, &[12, 12, 12], 0, 1 << 20, WITNESS_FEED_NO_LUT, 4);
    xor12[11] = WitnessFeedDescriptorKind::Xor12 as u32;
    descriptors.extend(xor12);

    let luts = vec![(0..16).rev().collect(), (0..256).rev().collect()];
    let requirements = witness_feed_workspace_requirements(
        32,
        9,
        &descriptors,
        &luts,
        &[32, 16, 8, 256, 16 << 20],
    )
    .unwrap();
    (requirements, descriptors, luts)
}

fn contract(mode: WitnessFeedLaunchMode) -> WitnessFeedContract {
    let (requirements, descriptors, luts) = fixture();
    WitnessFeedContract::compile(&requirements, &descriptors, &luts, mode).unwrap()
}

#[test]
fn contract_seals_content_full_transitions_and_exact_may_write_ranges() {
    let contract = contract(WitnessFeedLaunchMode::GlobalAtomics);
    assert_eq!(contract.abi().entry_symbol(), "stwo_witness_feed_counts_on");
    assert_eq!(contract.abi().arguments().len(), 7);
    assert_eq!(
        contract.descriptor_kinds(),
        [
            WitnessFeedDescriptorKind::Fold,
            WitnessFeedDescriptorKind::MemoryIdDecode,
            WitnessFeedDescriptorKind::DependentXor,
            WitnessFeedDescriptorKind::Xor12,
        ]
    );
    assert_eq!(
        contract.effect_geometry().row_domain,
        WitnessFeedRowDomain {
            row_count: 32,
            sub_words_per_row: 9,
            source_words: 288,
        }
    );
    assert_eq!(
        contract.effect_geometry().source,
        WitnessFeedSourceRead {
            read_start_words: 0,
            read_len_words: 288,
        }
    );
    assert_eq!(contract.effect_geometry().descriptor_words, 56);
    assert_eq!(
        contract
            .effect_geometry()
            .lut_reads
            .iter()
            .map(|read| (read.lut_ordinal, read.read_len_words))
            .collect::<Vec<_>>(),
        [(0, 16), (1, 256)]
    );
    assert_eq!(
        contract
            .effect_geometry()
            .destinations
            .iter()
            .map(|destination| (
                destination.destination_ordinal,
                destination.atomic_len_words,
                destination.may_write_ranges.as_slice(),
            ))
            .collect::<Vec<_>>(),
        [
            (
                0,
                32,
                &[WitnessFeedDestinationRange {
                    start_words: 16,
                    len_words: 16,
                }][..],
            ),
            (
                1,
                16,
                &[WitnessFeedDestinationRange {
                    start_words: 8,
                    len_words: 8,
                }][..],
            ),
            (
                2,
                8,
                &[WitnessFeedDestinationRange {
                    start_words: 4,
                    len_words: 4,
                }][..],
            ),
            (
                3,
                256,
                &[WitnessFeedDestinationRange {
                    start_words: 0,
                    len_words: 256,
                }][..],
            ),
            (
                4,
                16 << 20,
                &[WitnessFeedDestinationRange {
                    start_words: 0,
                    len_words: 16 << 20,
                }][..],
            ),
        ]
    );
    assert!(contract
        .effect_geometry()
        .destinations
        .iter()
        .all(|destination| destination.atomic_start_words == 0));
    assert_eq!(contract.launch().grid, [1, 1, 1]);
    assert_eq!(contract.launch().block, [256, 1, 1]);
    assert_eq!(contract.launch().static_shared_bytes, 0);
    assert_eq!(contract.launch().symbol(), "witness_feed_counts_kernel");
    contract.validate().unwrap();
    for identity in [
        contract.static_source_identity(),
        contract.wrapper_source_identity(),
        contract.source_identity(),
        contract.requirements_identity(),
        contract.descriptor_identity(),
        contract.lut_identity(),
        contract.content_identity(),
        contract.abi_identity(),
        contract.effect_identity(),
        contract.launch_identity(),
        contract.identity(),
    ] {
        assert_ne!(identity, [0; 32]);
    }
}

#[test]
fn adjacent_descriptor_ranges_merge_without_claiming_the_unused_tail() {
    let mut descriptors = Vec::new();
    descriptors.extend(fold_descriptor(0, &[4], 0, 16, WITNESS_FEED_NO_LUT, 0));
    descriptors.extend(fold_descriptor(1, &[4], 1, 16, WITNESS_FEED_NO_LUT, 0));
    let requirements = witness_feed_workspace_requirements(2, 2, &descriptors, &[], &[64]).unwrap();
    let contract = WitnessFeedContract::compile(
        &requirements,
        &descriptors,
        &[],
        WitnessFeedLaunchMode::GlobalAtomics,
    )
    .unwrap();
    assert_eq!(
        contract.effect_geometry().destinations[0].may_write_ranges,
        [WitnessFeedDestinationRange {
            start_words: 0,
            len_words: 32,
        }]
    );
    assert_eq!(
        contract.effect_geometry().destinations[0].atomic_len_words,
        64,
        "the in-place semantic transition carries the untouched tail through"
    );
}

#[test]
fn launch_modes_seal_distinct_symbols_resources_and_identities() {
    let global = contract(WitnessFeedLaunchMode::GlobalAtomics);
    let privatized = contract(WitnessFeedLaunchMode::Privatized);
    assert_eq!(
        privatized.abi().entry_symbol(),
        "stwo_witness_feed_counts_privatized_on"
    );
    assert_eq!(
        privatized.launch().symbol(),
        "witness_feed_counts_privatized_kernel"
    );
    assert_eq!(
        privatized.launch().static_shared_bytes,
        WITNESS_FEED_PRIVATIZED_SHARED_BYTES as u32
    );
    assert_eq!(global.effect_geometry(), privatized.effect_geometry());
    assert_ne!(global.abi_identity(), privatized.abi_identity());
    assert_ne!(global.launch_identity(), privatized.launch_identity());
    assert_ne!(global.identity(), privatized.identity());
}

#[test]
fn raw_wrapper_abis_and_overflow_safe_grids_match_the_contract() {
    type Entry = unsafe extern "C" fn(
        *const u32,
        u32,
        *const u32,
        u32,
        *const *const u32,
        *const *mut u32,
        *mut core::ffi::c_void,
    ) -> i32;
    let _: Entry = stwo_backend_cuda_kernels::raw::stwo_witness_feed_counts_on;
    let _: Entry = stwo_backend_cuda_kernels::raw::stwo_witness_feed_counts_privatized_on;

    let descriptor = fold_descriptor(0, &[31], 0, u32::MAX, WITNESS_FEED_NO_LUT, 0);
    let requirements = witness_feed_workspace_requirements(
        u32::MAX as usize,
        1,
        &descriptor,
        &[],
        &[u32::MAX as usize],
    )
    .unwrap();
    for mode in [
        WitnessFeedLaunchMode::GlobalAtomics,
        WitnessFeedLaunchMode::Privatized,
    ] {
        let contract = WitnessFeedContract::compile(&requirements, &descriptor, &[], mode).unwrap();
        assert_eq!(contract.launch().grid, [16_777_216, 1, 1]);
    }
    let wrapper = include_str!("../../../../backend-cuda-kernels/cuda/witness_feed_counts.cu");
    assert_eq!(
        wrapper
            .matches("uint32_t grid = 1u + (column_length - 1u) / block;")
            .count(),
        2
    );
}

#[test]
fn requirements_content_and_retained_contracts_fail_closed() {
    let (requirements, descriptors, luts) = fixture();
    let mut malformed = requirements.clone();
    malformed.descriptor_count -= 1;
    assert_eq!(
        WitnessFeedContract::compile(
            &malformed,
            &descriptors,
            &luts,
            WitnessFeedLaunchMode::GlobalAtomics,
        )
        .unwrap_err(),
        WitnessFeedAuthorityError::InvalidCanonicalRequirements
    );

    let baseline = contract(WitnessFeedLaunchMode::GlobalAtomics);
    let mutations: [fn(&mut WitnessFeedContract); 6] = [
        |contract| contract.source_identity[0] ^= 1,
        |contract| contract.abi_identity[0] ^= 1,
        |contract| contract.descriptor_kinds[0] = WitnessFeedDescriptorKind::Xor12,
        |contract| contract.effect_geometry.destinations[0].may_write_ranges[0].len_words -= 1,
        |contract| contract.launch.grid[0] += 1,
        |contract| contract.identity[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = baseline.clone();
        mutate(&mut changed);
        assert!(changed.validate().is_err());
    }

    let mut changed_luts = luts.clone();
    changed_luts[0].swap(0, 1);
    assert_ne!(
        WitnessFeedContract::compile(
            &requirements,
            &descriptors,
            &changed_luts,
            WitnessFeedLaunchMode::GlobalAtomics,
        )
        .unwrap()
        .identity(),
        baseline.identity()
    );
    let mut changed_descriptors = descriptors.clone();
    changed_descriptors[12] = 1;
    assert_ne!(
        WitnessFeedContract::compile(
            &requirements,
            &changed_descriptors,
            &luts,
            WitnessFeedLaunchMode::GlobalAtomics,
        )
        .unwrap()
        .identity(),
        baseline.identity()
    );
}

#[test]
fn linked_receipt_binds_contract_archive_and_target() {
    let contract = contract(WitnessFeedLaunchMode::GlobalAtomics);
    let binding = binding_for_test(
        STATIC_BUILD_DOMAIN,
        contract.identity(),
        BUILD,
        BUILD,
        &SMS,
        89,
    )
    .unwrap();
    let linked = linked_contract(contract.identity(), binding);
    assert_eq!(linked.contract_identity(), contract.identity());
    assert_eq!(linked.module_build_identity(), BUILD);
    assert_eq!(linked.target_sm(), 89);
    for identity in [
        linked.static_build_source_identity(),
        linked.static_build_identity(),
        linked.sm_identity(),
        linked.identity(),
    ] {
        assert_ne!(identity, [0; 32]);
    }
    let mut corrupted = linked;
    corrupted.contract_identity[0] ^= 1;
    assert_eq!(
        corrupted.validate(&contract).unwrap_err(),
        WitnessFeedAuthorityError::StaticBuildMismatch
    );
}
