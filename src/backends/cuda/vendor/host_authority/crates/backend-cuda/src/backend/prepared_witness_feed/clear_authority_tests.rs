use super::*;
use crate::backend::prepared_witness_input::static_build::{
    binding_for_test, validate_binding_for_test,
};

const BUILD: [u8; 32] = [7; 32];
const SMS: [u32; 2] = [89, 90];

fn contract() -> WitnessFeedClearContract {
    let requirements = witness_feed_clear_workspace_requirements(&[8192, 64, 1024, 256]).unwrap();
    WitnessFeedClearContract::compile(&requirements).unwrap()
}

#[test]
fn exact_clear_contract_seals_abi_effect_launch_and_sources() {
    let contract = contract();
    assert_eq!(contract.abi().entry_symbol(), "stwo_witness_feed_clear_on");
    assert_eq!(contract.abi().arguments().len(), 5);
    assert_eq!(
        contract.effect_geometry().destination_lengths,
        [8192, 64, 1024, 256]
    );
    assert_eq!(
        contract
            .effect_geometry()
            .destinations
            .iter()
            .map(|destination| destination.write_len_words)
            .collect::<Vec<_>>(),
        [8192, 64, 1024, 256]
    );
    assert_eq!(contract.launch().grid, [32, 4, 1]);
    assert_eq!(contract.launch().block, [256, 1, 1]);
    assert_eq!(contract.launch().symbol(), "witness_feed_clear_kernel");
    assert!(contract.validate().is_ok());
    for identity in [
        contract.static_source_identity(),
        contract.wrapper_source_identity(),
        contract.source_identity(),
        contract.requirements_identity(),
        contract.abi_identity(),
        contract.effect_identity(),
        contract.launch_identity(),
        contract.identity(),
    ] {
        assert_ne!(identity, [0; 32]);
    }
}

#[test]
fn raw_wrapper_abi_and_zero_effect_match_the_contract() {
    let _: unsafe extern "C" fn(
        *const *mut u32,
        *const u32,
        u32,
        u32,
        *mut core::ffi::c_void,
    ) -> i32 = stwo_backend_cuda_kernels::raw::stwo_witness_feed_clear_on;
    let source = include_str!("../../../../backend-cuda-kernels/cuda/witness_feed_counts.cu");
    assert!(source.contains("uint32_t destination = blockIdx.y;"));
    assert!(source.contains("if (word < lengths[destination])"));
    assert!(source.contains("destinations[destination][word] = 0;"));
}

#[test]
fn canonical_geometry_and_upper_launch_boundary_fail_closed() {
    let upper = witness_feed_clear_workspace_requirements(&[u32::MAX as usize]).unwrap();
    let upper = WitnessFeedClearContract::compile(&upper).unwrap();
    assert_eq!(upper.launch().grid, [16_777_216, 1, 1]);

    if let Ok(oversized_words) = usize::try_from(u64::from(u32::MAX) + 1) {
        let oversized = WitnessFeedClearWorkspaceRequirements {
            destination_words: vec![oversized_words],
            destination_pointer_words: 2,
            destination_length_words: 1,
            max_destination_words: oversized_words,
        };
        assert_eq!(
            WitnessFeedClearContract::compile(&oversized).unwrap_err(),
            WitnessFeedClearAuthorityError::SizeOverflow
        );
    }

    let mut malformed = witness_feed_clear_workspace_requirements(&[16, 32]).unwrap();
    malformed.max_destination_words = 16;
    assert_eq!(
        WitnessFeedClearContract::compile(&malformed).unwrap_err(),
        WitnessFeedClearAuthorityError::InvalidCanonicalRequirements
    );

    for zero in [
        WitnessFeedClearWorkspaceRequirements {
            destination_words: Vec::new(),
            destination_pointer_words: 0,
            destination_length_words: 0,
            max_destination_words: 0,
        },
        WitnessFeedClearWorkspaceRequirements {
            destination_words: vec![0],
            destination_pointer_words: 2,
            destination_length_words: 1,
            max_destination_words: 0,
        },
    ] {
        assert_eq!(
            WitnessFeedClearContract::compile(&zero).unwrap_err(),
            WitnessFeedClearAuthorityError::InvalidCanonicalRequirements
        );
    }
}

#[test]
fn contract_identity_changes_with_destination_order_and_extent() {
    let baseline = contract();
    for words in [
        vec![64, 8192, 1024, 256],
        vec![8192, 64, 1024, 255],
        vec![8192, 64, 1024, 256, 1],
    ] {
        let requirements = witness_feed_clear_workspace_requirements(&words).unwrap();
        assert_ne!(
            WitnessFeedClearContract::compile(&requirements)
                .unwrap()
                .identity(),
            baseline.identity()
        );
    }
}

#[test]
fn retained_contract_rejects_identity_and_launch_drift() {
    let baseline = contract();
    let mutations: [fn(&mut WitnessFeedClearContract); 5] = [
        |contract: &mut WitnessFeedClearContract| contract.source_identity[0] ^= 1,
        |contract: &mut WitnessFeedClearContract| contract.abi_identity[0] ^= 1,
        |contract: &mut WitnessFeedClearContract| contract.effect_identity[0] ^= 1,
        |contract: &mut WitnessFeedClearContract| contract.launch.grid[0] += 1,
        |contract: &mut WitnessFeedClearContract| contract.identity[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = baseline.clone();
        mutate(&mut changed);
        assert!(changed.validate().is_err());
    }
}

#[test]
fn linked_build_binds_contract_target_and_archive() {
    let contract = contract();
    let binding = binding_for_test(
        STATIC_BUILD_DOMAIN,
        contract.identity(),
        BUILD,
        BUILD,
        &SMS,
        89,
    )
    .unwrap();
    validate_binding_for_test(
        &binding,
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

    assert!(binding_for_test(
        STATIC_BUILD_DOMAIN,
        contract.identity(),
        BUILD,
        [8; 32],
        &SMS,
        89,
    )
    .is_err());
    assert!(binding_for_test(
        STATIC_BUILD_DOMAIN,
        contract.identity(),
        BUILD,
        BUILD,
        &SMS,
        80,
    )
    .is_err());

    if stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        let target = stwo_backend_cuda_kernels::static_cuda_module_target_sms()[0];
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

#[test]
fn authority_sources_cover_the_real_wrapper_and_overflow_safe_grid() {
    let wrapper = include_str!("../../../../backend-cuda-kernels/cuda/witness_feed_counts.cu");
    let authority = include_str!("clear_authority.rs");
    assert!(wrapper.contains("extern \"C\" int stwo_witness_feed_clear_on("));
    assert!(wrapper.contains("witness_feed_clear_kernel<<<grid, block, 0"));
    assert!(wrapper.contains("dim3 grid(1u + (max_words - 1u) / block, n_destinations, 1);"));
    assert!(authority.contains("Ok(1 + (value - 1) / divisor)"));
}
