use super::*;

fn identity(mode: PreparedWitnessMode) -> WitnessKernelIdentity {
    WitnessKernelIdentity {
        label: "strict-test".to_string(),
        kernel_name: "witness_strict_test".to_string(),
        semantic_hash: 17,
        cache_key: 23,
        aot_manifest_identity: [9; 32],
        aot_manifest_hash: 9,
        mode,
    }
}

fn snapshot() -> CudaDeviceSnapshot {
    CudaDeviceSnapshot {
        count: 1,
        current: 0,
        sm_major: 8,
        sm_minor: 9,
    }
}

fn authority() -> AuthorityFacts {
    AuthorityFacts {
        source_identity: [1; 32],
        kernel_symbol: "witness_strict_test",
        semantic_hash: 17,
        cache_key: 23,
        target_sm: 89,
        cubin_identity: [2; 32],
        abi_schema: Some(AotKernelAbiSchema::RecordedWitnessV1),
        abi_schema_identity: AotKernelAbiSchema::RecordedWitnessV1.identity(),
        program_identity: [3; 32],
        authority_identity: [4; 32],
        schema_scope: AotKernelSchemaScope::StructuredAbi,
        module_globals: AotKernelModuleGlobals::None,
    }
}

fn launch() -> InstalledAotLaunchFacts {
    InstalledAotLaunchFacts::new([2, 1, 1], [256, 1, 1], 0).unwrap()
}

fn receipt() -> ReceiptFacts {
    let authority = authority();
    ReceiptFacts {
        manifest_identity: [9; 32],
        source_identity: authority.source_identity,
        cubin_identity: authority.cubin_identity,
        program_identity: authority.program_identity,
        abi_schema_identity: authority.abi_schema_identity,
        authority_identity: authority.authority_identity,
        kernel_symbol: authority.kernel_symbol,
        semantic_hash: authority.semantic_hash,
        cache_key: authority.cache_key,
        target_sm: authority.target_sm,
        abi_schema: AotKernelAbiSchema::RecordedWitnessV1,
        module_globals: authority.module_globals,
        ownership_is_borrowed: true,
        launch: launch(),
        device_ordinal: 0,
        exec_context_token: 11,
        driver_context_token: 12,
        module_token: 13,
        function_token: 14,
        stream_token: 15,
        has_pedersen_publication: false,
        publication: FunctionPublicationFacts {
            manifest_identity: [9; 32],
            source_identity: authority.source_identity,
            cubin_identity: authority.cubin_identity,
            program_identity: authority.program_identity,
            abi_schema_identity: authority.abi_schema_identity,
            authority_identity: authority.authority_identity,
            kernel_symbol: authority.kernel_symbol,
            semantic_hash: authority.semantic_hash,
            cache_key: authority.cache_key,
            target_sm: authority.target_sm,
            device_ordinal: 0,
            driver_context_token: 12,
            module_token: 13,
            function_token: 14,
        },
    }
}

fn authority_error(field: &'static str) -> PreparedWitnessError {
    PreparedWitnessError::StrictAotAuthorityMismatch {
        identity: identity(PreparedWitnessMode::RequireEmbeddedAot),
        field,
    }
}

fn receipt_error(field: &'static str) -> PreparedWitnessError {
    PreparedWitnessError::StrictAotReceiptMismatch {
        identity: identity(PreparedWitnessMode::RequireEmbeddedAot),
        field,
    }
}

#[test]
fn retained_handle_borrows_the_graph_context_and_never_launches_eagerly() {
    type Install = for<'a, 'identity, 'program> fn(
        &'a CudaExecContext,
        &'identity WitnessKernelIdentity,
        &'program WitnessProgram,
        usize,
    ) -> Result<
        Option<InstalledAotFunction<'a>>,
        PreparedWitnessError,
    >;
    let _: Install = install;

    let source = include_str!("../installed_aot.rs");
    assert!(source.contains("InstalledAotFunction::install"));
    assert!(!source.contains("launch_raw"));
    assert!(!source.contains("stwo_installed_aot_function_launch"));
}

#[test]
fn recorded_launch_geometry_matches_the_legacy_wrapper_exactly() {
    let native = include_str!("../../../../../backend-cuda-kernels/cuda/runtime_jit.cu");
    assert!(native
        .contains("constexpr uint32_t ceil_div_nonzero_u32(uint32_t value, uint32_t divisor)"));
    assert!(native.contains(
        "const unsigned block = 256;  // must match the generated kernel's __launch_bounds__"
    ));
    assert!(native.contains("ceil_div_nonzero_u32(kU32Max, 256u) == 16777216u"));
    assert!(!native.contains("(row_count + block - 1) / block"));
    assert_eq!(
        native
            .matches("const unsigned grid = ceil_div_nonzero_u32(row_count, block);")
            .count(),
        4
    );
    assert_eq!(
        native
            .matches("const unsigned grid = ceil_div_nonzero_u32(shard_rows, block);")
            .count(),
        1
    );

    for (rows, grid) in [
        (1usize, 1u32),
        (255, 1),
        (256, 1),
        (257, 2),
        (u32::MAX as usize, u32::MAX.div_ceil(256)),
    ] {
        let facts = recorded_launch_facts(rows).unwrap();
        assert_eq!(facts.grid(), [grid, 1, 1]);
        assert_eq!(facts.block(), [256, 1, 1]);
        assert_eq!(facts.dynamic_shared_bytes(), 0);
    }
    assert_eq!(
        recorded_launch_facts(0).unwrap_err(),
        PreparedWitnessError::ZeroRows
    );
    if let Some(too_many_rows) = (u32::MAX as usize).checked_add(1) {
        assert_eq!(
            recorded_launch_facts(too_many_rows).unwrap_err(),
            PreparedWitnessError::RowCountOverflow
        );
    }
}

#[test]
fn mode_is_total_and_strict_cannot_omit_the_authority_or_retained_handle() {
    let pre_resolved = identity(PreparedWitnessMode::PreResolved);
    assert_eq!(
        admit_authority(&pre_resolved, [0; 32], [0; 32], snapshot(), None).unwrap(),
        None
    );
    assert_eq!(validate_retention_mode(&pre_resolved, false), Ok(()));

    let strict = identity(PreparedWitnessMode::RequireEmbeddedAot);
    assert_eq!(
        admit_authority(&strict, [3; 32], [9; 32], snapshot(), None).unwrap_err(),
        PreparedWitnessError::StrictAotAuthorityMissing(strict.clone())
    );
    assert_eq!(
        validate_retention_mode(&strict, false).unwrap_err(),
        receipt_error("retention_mode")
    );
    assert_eq!(validate_retention_mode(&strict, true), Ok(()));
}

#[test]
fn every_authority_axis_is_cross_checked_before_install() {
    let strict = identity(PreparedWitnessMode::RequireEmbeddedAot);
    let validate = |facts| admit_authority(&strict, [3; 32], [9; 32], snapshot(), Some(facts));
    assert_eq!(validate(authority()), Ok(Some(authority())));

    macro_rules! rejects {
        ($field:ident, $value:expr, $name:literal) => {{
            let mut changed = authority();
            changed.$field = $value;
            assert_eq!(validate(changed).unwrap_err(), authority_error($name));
        }};
    }
    rejects!(source_identity, ZERO_IDENTITY, "source_identity");
    rejects!(kernel_symbol, "wrong", "kernel_symbol");
    rejects!(semantic_hash, 18, "semantic_hash");
    rejects!(cache_key, 24, "cache_key");
    rejects!(target_sm, 90, "target_sm");
    rejects!(cubin_identity, ZERO_IDENTITY, "cubin_identity");
    rejects!(
        abi_schema,
        Some(AotKernelAbiSchema::OrdinaryConstraintV1),
        "abi_schema"
    );
    rejects!(abi_schema_identity, [8; 32], "abi_schema_identity");
    rejects!(program_identity, [8; 32], "program_identity");
    rejects!(authority_identity, ZERO_IDENTITY, "authority_identity");
    rejects!(
        schema_scope,
        AotKernelSchemaScope::ExportedSymbolOnly,
        "schema_scope"
    );
    rejects!(
        module_globals,
        AotKernelModuleGlobals::Unspecified,
        "module_globals"
    );
    assert_eq!(
        admit_authority(&strict, [3; 32], [8; 32], snapshot(), Some(authority())).unwrap_err(),
        authority_error("manifest_identity")
    );
    let mut bad_device = snapshot();
    bad_device.current = bad_device.count;
    assert_eq!(
        admit_authority(&strict, [3; 32], [9; 32], bad_device, Some(authority())).unwrap_err(),
        authority_error("device")
    );
}

#[test]
fn every_retained_receipt_axis_is_cross_checked() {
    let strict = identity(PreparedWitnessMode::RequireEmbeddedAot);
    let validate = |facts| {
        validate_receipt(
            &strict,
            authority(),
            [9; 32],
            snapshot(),
            launch(),
            11,
            15,
            facts,
        )
    };
    assert_eq!(validate(receipt()), Ok(()));

    macro_rules! rejects {
        ($field:ident, $value:expr, $name:literal) => {{
            let mut changed = receipt();
            changed.$field = $value;
            assert_eq!(validate(changed).unwrap_err(), receipt_error($name));
        }};
    }
    rejects!(manifest_identity, [8; 32], "manifest_identity");
    rejects!(source_identity, [8; 32], "source_identity");
    rejects!(cubin_identity, [8; 32], "cubin_identity");
    rejects!(program_identity, [8; 32], "program_identity");
    rejects!(abi_schema_identity, [8; 32], "abi_schema_identity");
    rejects!(authority_identity, [8; 32], "authority_identity");
    rejects!(kernel_symbol, "wrong", "kernel_symbol");
    rejects!(semantic_hash, 18, "semantic_hash");
    rejects!(cache_key, 24, "cache_key");
    rejects!(target_sm, 90, "target_sm");
    rejects!(
        abi_schema,
        AotKernelAbiSchema::OrdinaryConstraintV1,
        "abi_schema"
    );
    rejects!(
        module_globals,
        AotKernelModuleGlobals::WitnessPedersenV1,
        "module_globals"
    );
    rejects!(ownership_is_borrowed, false, "ownership");
    rejects!(
        launch,
        InstalledAotLaunchFacts::new([3, 1, 1], [256, 1, 1], 0).unwrap(),
        "launch"
    );
    rejects!(device_ordinal, 1, "device_ordinal");
    rejects!(exec_context_token, 0, "exec_context_token");
    rejects!(driver_context_token, 0, "driver_context_token");
    rejects!(module_token, 0, "module_token");
    rejects!(function_token, 0, "function_token");
    rejects!(stream_token, 0, "stream_token");
    rejects!(has_pedersen_publication, true, "pedersen_publication");

    let mut changed = receipt();
    changed.publication.function_token = 0;
    assert_eq!(
        validate(changed).unwrap_err(),
        receipt_error("publication_function_token")
    );
    let mut changed = receipt();
    changed.publication.authority_identity = [8; 32];
    assert_eq!(
        validate(changed).unwrap_err(),
        receipt_error("publication_authority_identity")
    );
}
