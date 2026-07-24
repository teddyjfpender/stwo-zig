use core::ffi::c_void;

use super::*;

fn exact_program() -> ProgramMetadata<'static> {
    ProgramMetadata {
        label: "blake_g",
        identity: BG_FUSED_PROGRAM_IDENTITY,
        semantic_hash: BG_FUSED_SEMANTIC_HASH,
        n_inputs: BG_N_RECORDED_INPUTS as u32,
        n_cols: BG_N_TRACE as u32,
        n_mult_tables: 0,
        n_lookup_words: BG_N_LOOKUP_WORDS as u32,
        n_sub_words: BG_N_SUB_WORDS as u32,
    }
}

fn contract(n_real_rows: usize, padded_rows: usize) -> BlakeGDirectCompositeContract {
    BlakeGDirectCompositeContract::compile_admitted(exact_program(), n_real_rows, padded_rows)
        .unwrap()
}

#[test]
fn exact_contract_is_deterministic_and_complete() {
    type RawDirect = unsafe extern "C" fn(
        *const *const u32,
        u32,
        u32,
        *const *mut u32,
        *const *const u32,
        *const *mut u32,
        *mut c_void,
    ) -> i32;
    let _: RawDirect = stwo_backend_cuda_kernels::raw::blake_g_write_trace_fused_direct_into_on;

    let baseline = contract(777, 1024);
    assert_eq!(baseline, contract(777, 1024));
    assert_eq!(
        baseline.abi().entry_symbol(),
        "blake_g_write_trace_fused_direct_into_on"
    );
    assert_eq!(baseline.abi().arguments(), &ARGUMENTS);
    assert_eq!(baseline.program_identity(), BG_FUSED_PROGRAM_IDENTITY);
    assert_eq!(baseline.n_real_rows(), 777);
    assert_eq!(baseline.padded_rows(), 1024);
    assert_eq!(baseline.input_column_words(), &[1024; 6]);
    assert_eq!(baseline.trace_column_words(), &[1024; 53]);
    assert_eq!(baseline.lut_words(), BLAKE_G_DIRECT_LUT_WORDS);
    assert_eq!(baseline.lut_order(), BLAKE_G_DIRECT_LUT_ORDER);
    assert_eq!(baseline.count_words(), BLAKE_G_DIRECT_COUNT_WORDS);
    assert_eq!(baseline.count_order(), BLAKE_G_DIRECT_COUNT_ORDER);
    assert_eq!(
        baseline.row_domain(),
        BlakeGDirectRowDomain::MonolithicFullPaddedRowsV1
    );
    assert_eq!(baseline.wrapper_launch().grid, [4, 1, 1]);
    assert_eq!(baseline.wrapper_launch().block, [256, 1, 1]);
    assert_eq!(baseline.wrapper_launch().dynamic_shared_bytes, 0);
    assert!(!baseline.wrapper_launch().cooperative);
    for identity in [
        baseline.source_identity(),
        baseline.abi_identity(),
        baseline.effect_identity(),
        baseline.launch_identity(),
        baseline.identity(),
    ] {
        assert_ne!(identity, ZERO_IDENTITY);
    }
}

#[test]
fn source_closure_proves_direct_wrapper_launch_and_effect_shape() {
    let wrapper = include_str!("../../../../../backend-cuda-kernels/cuda/blake_witness.cu");
    let scalar = include_str!("../../../../../backend-cuda-kernels/cuda/blake_g_fused_scalar.cuh");
    let evaluator =
        include_str!("../../../../../backend-cuda-kernels/cuda/blake_g_row_evaluator.cuh");
    for required in [
        "constexpr uint32_t BG_BLOCK = 256;",
        "extern \"C\" int blake_g_write_trace_fused_direct_into_on(",
        "blake_g_write_trace_fused_scalar_kernel<<<blocks, BG_BLOCK, 0, stream>>>",
    ] {
        assert!(
            wrapper.contains(required),
            "missing source authority: {required}"
        );
    }
    assert!(scalar.contains("__global__ void blake_g_write_trace_fused_scalar_kernel("));
    assert_eq!(
        evaluator.matches("sink.template trace<").count(),
        BG_N_TRACE
    );
    assert_eq!(evaluator.matches("sink.template count_lut<").count(), 14);
    assert_eq!(evaluator.matches("sink.count_xor12(").count(), 2);
    assert!(evaluator.contains("const uint32_t enabler = row < n_rows ? 1u : 0u;"));
    assert!(evaluator.contains("sink.template trace<52>(enabler);"));

    let compact = wrapper.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(compact.contains("trace_cols_host, nullptr, nullptr, luts_host, counts_host, stream"));

    let manifest =
        include_str!("../../../../../backend-cuda-kernels/cuda/generated/aot_manifest.json");
    assert!(manifest.contains(
        "\"program_identity\": \"aaf9afa6c30d514b412d651f915d3b9056ac079fe686d8bac596e99b26247163\""
    ));

    let prepared_feed = core::str::from_utf8(PREPARED_FEED_SOURCE).unwrap();
    assert!(prepared_feed.contains("BlakeGDirectLutContentIdentity::from_host_words(luts_host)?"));
    assert!(prepared_feed.contains("upload(arena, *slice, host)?"));
    assert!(prepared_feed.contains("lut_content_identity: BlakeGDirectLutContentIdentity"));

    let lut_content = core::str::from_utf8(LUT_CONTENT_SOURCE).unwrap();
    assert!(lut_content.contains("for word in words"));
    assert!(lut_content.contains("hasher.update(&word.to_le_bytes())"));
    assert!(lut_content.contains("There is deliberately"));
    assert!(lut_content.contains("no constructor from digest bytes"));
}

#[test]
fn every_correctness_critical_source_changes_the_direct_identity() {
    let cuda_identity = [0x11; 32];
    let sources = [
        BINDER_SOURCE,
        AUTHORITY_SOURCE,
        PREPARED_FEED_SOURCE,
        LUT_CONTENT_SOURCE,
    ];
    let baseline = source_identity_from(
        cuda_identity,
        sources[0],
        sources[1],
        sources[2],
        sources[3],
    );

    let mut changed_cuda = cuda_identity;
    changed_cuda[0] ^= 1;
    assert_ne!(
        source_identity_from(changed_cuda, sources[0], sources[1], sources[2], sources[3],),
        baseline
    );
    for changed_index in 0..sources.len() {
        let mut changed = sources.map(<[u8]>::to_vec);
        changed[changed_index][0] ^= 1;
        assert_ne!(
            source_identity_from(
                cuda_identity,
                &changed[0],
                &changed[1],
                &changed[2],
                &changed[3],
            ),
            baseline,
            "source {changed_index} was not sealed",
        );
    }
}

#[test]
fn every_program_authority_mutation_is_rejected() {
    let mutations: [fn(&mut ProgramMetadata<'static>); 8] = [
        |program| program.label = "blake_g_mutated",
        |program| program.identity[0] ^= 1,
        |program| program.semantic_hash ^= 1,
        |program| program.n_inputs += 1,
        |program| program.n_cols += 1,
        |program| program.n_mult_tables += 1,
        |program| program.n_lookup_words += 1,
        |program| program.n_sub_words += 1,
    ];
    for mutate in mutations {
        let mut program = exact_program();
        mutate(&mut program);
        assert_eq!(
            BlakeGDirectCompositeContract::compile_admitted(program, 31, 32),
            Err(BlakeGDirectAuthorityError::ProgramIdentityMismatch)
        );
    }
}

#[test]
fn geometry_mutations_fail_closed_or_change_identity() {
    assert_eq!(
        BlakeGDirectCompositeContract::compile_admitted(exact_program(), 0, 0),
        Err(BlakeGDirectAuthorityError::ZeroPaddedRows)
    );
    assert_eq!(
        BlakeGDirectCompositeContract::compile_admitted(exact_program(), 33, 32),
        Err(BlakeGDirectAuthorityError::RealRowsExceedPadded {
            n_real_rows: 33,
            padded_rows: 32,
        })
    );
    let baseline = contract(31, 32);
    assert_ne!(baseline.identity(), contract(30, 32).identity());
    assert_ne!(baseline.identity(), contract(31, 64).identity());
    assert_ne!(
        baseline.launch_identity(),
        contract(31, 257).launch_identity()
    );
    assert_eq!(
        baseline.launch_identity(),
        contract(30, 32).launch_identity()
    );
    assert_eq!(
        baseline.validate_bound_geometry(31, 32, &[32; 6], &[32; 53]),
        Ok(())
    );
    for drift in [
        baseline.validate_bound_geometry(30, 32, &[32; 6], &[32; 53]),
        baseline.validate_bound_geometry(31, 64, &[32; 6], &[32; 53]),
        baseline.validate_bound_geometry(31, 32, &[32; 5], &[32; 53]),
        baseline.validate_bound_geometry(31, 32, &[31; 6], &[32; 53]),
        baseline.validate_bound_geometry(31, 32, &[32; 6], &[32; 52]),
        baseline.validate_bound_geometry(31, 32, &[32; 6], &[31; 53]),
    ] {
        assert_eq!(
            drift,
            Err(BlakeGDirectAuthorityError::BindingGeometryMismatch)
        );
    }
    if usize::BITS > 32 {
        assert_eq!(
            BlakeGDirectCompositeContract::compile_admitted(
                exact_program(),
                u32::MAX as usize + 1,
                u32::MAX as usize + 1,
            ),
            Err(BlakeGDirectAuthorityError::SizeOverflow)
        );
    }
}
