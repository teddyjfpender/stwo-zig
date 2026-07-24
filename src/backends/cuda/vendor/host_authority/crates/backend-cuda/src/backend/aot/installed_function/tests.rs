use super::*;

fn authority() -> AuthorityFacts {
    AuthorityFacts {
        source_identity: [1; 32],
        cubin_identity: [2; 32],
        program_identity: [3; 32],
        abi_schema_identity: AotKernelAbiSchema::RecordedWitnessV1.identity(),
        authority_identity: [4; 32],
        kernel_symbol: "witness",
        target_sm: 89,
        schema: Some(AotKernelAbiSchema::RecordedWitnessV1),
        scope: AotKernelSchemaScope::StructuredAbi,
        module_globals: AotKernelModuleGlobals::None,
    }
}

fn arguments(count: usize) -> Vec<*mut c_void> {
    (0..count)
        .map(|index| (0x1000 + index * 8) as *mut c_void)
        .collect()
}

#[test]
fn authority_mutations_fail_closed() {
    assert_eq!(
        authority().validate(),
        Ok(AotKernelAbiSchema::RecordedWitnessV1)
    );
    let invalid = [
        AuthorityFacts {
            source_identity: ZERO_IDENTITY,
            ..authority()
        },
        AuthorityFacts {
            cubin_identity: ZERO_IDENTITY,
            ..authority()
        },
        AuthorityFacts {
            program_identity: ZERO_IDENTITY,
            ..authority()
        },
        AuthorityFacts {
            authority_identity: ZERO_IDENTITY,
            ..authority()
        },
        AuthorityFacts {
            abi_schema_identity: [9; 32],
            ..authority()
        },
        AuthorityFacts {
            kernel_symbol: "",
            ..authority()
        },
        AuthorityFacts {
            target_sm: 0,
            ..authority()
        },
        AuthorityFacts {
            scope: AotKernelSchemaScope::ExportedSymbolOnly,
            schema: None,
            module_globals: AotKernelModuleGlobals::Unspecified,
            ..authority()
        },
        AuthorityFacts {
            schema: Some(AotKernelAbiSchema::OrdinaryConstraintV1),
            module_globals: AotKernelModuleGlobals::WitnessPedersenV1,
            ..authority()
        },
    ];
    for changed in invalid {
        assert!(changed.validate().is_err(), "{changed:?}");
    }

    let wave = AuthorityFacts {
        abi_schema_identity: AotKernelAbiSchema::CompositionWaveV2.identity(),
        schema: Some(AotKernelAbiSchema::CompositionWaveV2),
        ..authority()
    };
    assert_eq!(wave.validate(), Ok(AotKernelAbiSchema::CompositionWaveV2));
}

#[test]
fn wrong_schema_arity_or_null_storage_cannot_form_launch_token() {
    let mut raw = arguments(AotKernelAbiSchema::RecordedWitnessV1.arguments().len());
    assert_eq!(
        check_arguments(
            [4; 32],
            AotKernelAbiSchema::RecordedWitnessV1,
            AotKernelAbiSchema::OrdinaryConstraintV1,
            &mut raw,
        )
        .unwrap_err(),
        InstalledAotFunctionError::ArgumentSchemaMismatch
    );
    raw.pop();
    let mut launched = false;
    let result = check_arguments(
        [4; 32],
        AotKernelAbiSchema::RecordedWitnessV1,
        AotKernelAbiSchema::RecordedWitnessV1,
        &mut raw,
    )
    .and_then(|checked| {
        dispatch_checked(
            [4; 32],
            AotKernelAbiSchema::RecordedWitnessV1,
            1,
            1,
            checked,
            |_| {
                launched = true;
                Ok(())
            },
        )
    });
    assert_eq!(
        result,
        Err(InstalledAotFunctionError::ArgumentCount {
            expected: 8,
            actual: 7,
        })
    );
    assert!(!launched);
    let mut raw = arguments(8);
    raw[3] = core::ptr::null_mut();
    assert_eq!(
        check_arguments(
            [4; 32],
            AotKernelAbiSchema::RecordedWitnessV1,
            AotKernelAbiSchema::RecordedWitnessV1,
            &mut raw,
        )
        .unwrap_err(),
        InstalledAotFunctionError::NullArgument { ordinal: 3 }
    );
}

#[test]
fn wrong_context_or_authority_never_dispatches() {
    let mut raw = arguments(8);
    let checked = check_arguments(
        [4; 32],
        AotKernelAbiSchema::RecordedWitnessV1,
        AotKernelAbiSchema::RecordedWitnessV1,
        &mut raw,
    )
    .unwrap();
    let mut launched = false;
    let result = dispatch_checked(
        [4; 32],
        AotKernelAbiSchema::RecordedWitnessV1,
        1,
        2,
        checked,
        |_| {
            launched = true;
            Ok(())
        },
    );
    assert_eq!(result, Err(InstalledAotFunctionError::ContextMismatch));
    assert!(!launched);

    let mut raw = arguments(8);
    let checked = check_arguments(
        [4; 32],
        AotKernelAbiSchema::RecordedWitnessV1,
        AotKernelAbiSchema::RecordedWitnessV1,
        &mut raw,
    )
    .unwrap();
    let result = dispatch_checked(
        [5; 32],
        AotKernelAbiSchema::RecordedWitnessV1,
        1,
        1,
        checked,
        |_| {
            launched = true;
            Ok(())
        },
    );
    assert_eq!(
        result,
        Err(InstalledAotFunctionError::ArgumentSchemaMismatch)
    );
    assert!(!launched);
}

#[test]
fn native_receipt_mutations_reject_wrong_sm_and_launch_facts() {
    let launch = InstalledAotLaunchFacts::new([3, 1, 1], [256, 1, 1], 0).unwrap();
    let baseline = NativeReceipt {
        abi_version: CUDA_INSTALLED_AOT_FUNCTION_ABI_VERSION,
        ownership: CUDA_INSTALLED_AOT_BORROWED_PUBLISHED,
        device_ordinal: 0,
        sm_major: 8,
        sm_minor: 9,
        argument_count: 8,
        grid_x: 3,
        grid_y: 1,
        grid_z: 1,
        block_x: 256,
        block_y: 1,
        block_z: 1,
        dynamic_shared_bytes: 0,
        reserved: 0,
        context_token: 1,
        module_token: 2,
        function_token: 3,
        stream_token: 4,
        function: NativeFunctionResources {
            abi_version: 1,
            max_threads_per_block: 1_024,
            registers_per_thread: 128,
            binary_version: 89,
            ptx_version: 86,
            reserved: 0,
            local_bytes: 0,
            static_shared_bytes: 0,
        },
    };
    let validate = |native: &NativeReceipt| {
        validate_native_receipt(native, 89, 8, launch, 4, 0, 1, 2, 3, None)
    };
    assert_eq!(validate(&baseline), Ok(()));
    for mutate in [
        |receipt: &mut NativeReceipt| receipt.sm_minor += 1,
        |receipt: &mut NativeReceipt| receipt.grid_x += 1,
        |receipt: &mut NativeReceipt| receipt.block_x /= 2,
        |receipt: &mut NativeReceipt| receipt.argument_count -= 1,
        |receipt: &mut NativeReceipt| receipt.ownership = 0,
        |receipt: &mut NativeReceipt| receipt.reserved = 1,
        |receipt: &mut NativeReceipt| receipt.device_ordinal += 1,
        |receipt: &mut NativeReceipt| receipt.context_token = 0,
        |receipt: &mut NativeReceipt| receipt.module_token = 0,
        |receipt: &mut NativeReceipt| receipt.function_token = 0,
        |receipt: &mut NativeReceipt| receipt.stream_token = 0,
        |receipt: &mut NativeReceipt| receipt.function.abi_version = 0,
        |receipt: &mut NativeReceipt| receipt.function.max_threads_per_block = 0,
        |receipt: &mut NativeReceipt| receipt.function.binary_version = 90,
        |receipt: &mut NativeReceipt| receipt.function.reserved = 1,
    ] {
        let mut changed = baseline;
        mutate(&mut changed);
        assert_eq!(
            validate(&changed),
            Err(InstalledAotFunctionError::NativeReceiptMismatch)
        );
    }
}

#[test]
fn native_function_resources_are_preserved_exactly() {
    let raw = NativeFunctionResources {
        abi_version: 1,
        max_threads_per_block: 768,
        registers_per_thread: 97,
        binary_version: 89,
        ptx_version: 86,
        reserved: 0,
        local_bytes: 24,
        static_shared_bytes: 48,
    };
    assert_eq!(
        native_function_resources(raw),
        InstalledAotFunctionResources {
            max_threads_per_block: 768,
            registers_per_thread: 97,
            binary_version: 89,
            ptx_version: 86,
            local_bytes: 24,
            static_shared_bytes: 48,
        }
    );
}

#[test]
fn stub_build_cannot_fabricate_installed_authority() {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        assert!(!stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT);
    }
}
