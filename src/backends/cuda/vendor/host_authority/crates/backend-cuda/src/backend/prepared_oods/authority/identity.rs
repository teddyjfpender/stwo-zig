use super::compiler::CompiledOodsContract;
use super::*;

const WRAPPER_SOURCE_DOMAIN: &[u8] = b"stwo-cuda-oods-wrapper-source-v1\0";
const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-oods-execution-source-v1\0";
const FIXED_DOMAIN: &[u8] = b"stwo-cuda-oods-execution-fixed-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-oods-execution-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-oods-execution-effect-v1\0";
const HOST_CALL_DOMAIN: &[u8] = b"stwo-cuda-oods-execution-host-call-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-oods-execution-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-oods-execution-contract-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-oods-execution-linked-v1\0";

const BINDER_SOURCE: &[u8] = include_bytes!("../../prepared_oods.rs");
const PASS_COLLAPSE_SOURCE: &[u8] = include_bytes!("../pass_collapse.rs");
const EVALUATION_LAUNCH_SOURCE: &[u8] = include_bytes!("../evaluation_launch.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("../authority.rs");
const COMPILER_SOURCE: &[u8] = include_bytes!("compiler.rs");
const IDENTITY_SOURCE: &[u8] = include_bytes!("identity.rs");
const RAW_FFI_SOURCE: &[u8] = include_bytes!("../../../../../backend-cuda-kernels/src/raw.rs");
const OODS_SOURCE: &[u8] = include_bytes!("../../../../../backend-cuda-kernels/cuda/oods.cu");
const COLLAPSED_SOURCE: &[u8] =
    include_bytes!("../../../../../backend-cuda-kernels/cuda/oods_collapsed.cu");
const OODS_HEADER: &[u8] = include_bytes!("../../../../../backend-cuda-kernels/cuda/oods.cuh");
const INVERSE_HEADER: &[u8] =
    include_bytes!("../../../../../backend-cuda-kernels/cuda/batch_inverse.cuh");
const FIELDS_HEADER: &[u8] = include_bytes!("../../../../../backend-cuda-kernels/cuda/fields.cuh");

pub(super) fn wrapper_source_identity() -> [u8; 32] {
    digest_many(
        WRAPPER_SOURCE_DOMAIN,
        &[
            OODS_SOURCE,
            COLLAPSED_SOURCE,
            OODS_HEADER,
            INVERSE_HEADER,
            FIELDS_HEADER,
        ],
    )
}

pub(super) fn source_identity(
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&static_source_identity);
    hasher.update(&wrapper_source_identity);
    for source in [
        BINDER_SOURCE,
        PASS_COLLAPSE_SOURCE,
        EVALUATION_LAUNCH_SOURCE,
        AUTHORITY_SOURCE,
        COMPILER_SOURCE,
        IDENTITY_SOURCE,
        RAW_FFI_SOURCE,
    ] {
        hash_bytes(&mut hasher, source);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn validate_static_symbols() -> Result<(), OodsExecutionAuthorityError> {
    for (symbol, source) in [
        ("pub fn launch", BINDER_SOURCE),
        ("stwo_oods_derive_points_on", OODS_SOURCE),
        ("derive_points_kernel", OODS_SOURCE),
        ("stwo_oods_eval_first_on", OODS_SOURCE),
        ("eval_first_kernel", OODS_SOURCE),
        ("stwo_oods_eval_reduce_on", OODS_SOURCE),
        ("eval_reduce_kernel", OODS_SOURCE),
        ("stwo_oods_store_results_on", OODS_SOURCE),
        ("store_results_kernel", OODS_SOURCE),
        (
            "stwo_oods_barycentric_weights_collapsed_cohort_on",
            COLLAPSED_SOURCE,
        ),
        (
            "barycentric_weights_collapsed_small_kernel",
            COLLAPSED_SOURCE,
        ),
        (
            "barycentric_weights_collapsed_1024_kernel",
            COLLAPSED_SOURCE,
        ),
        ("stwo_oods_barycentric_eval_many_on", OODS_SOURCE),
        ("barycentric_eval_many_kernel", OODS_SOURCE),
        ("barycentric_reduce_rows_kernel", OODS_SOURCE),
        ("stwo_oods_derive_points_on", RAW_FFI_SOURCE),
        ("stwo_oods_eval_first_on", RAW_FFI_SOURCE),
        ("stwo_oods_eval_reduce_on", RAW_FFI_SOURCE),
        ("stwo_oods_store_results_on", RAW_FFI_SOURCE),
        (
            "stwo_oods_barycentric_weights_collapsed_cohort_on",
            RAW_FFI_SOURCE,
        ),
        ("stwo_oods_barycentric_eval_many_on", RAW_FFI_SOURCE),
    ] {
        if !contains(source, symbol.as_bytes()) {
            return Err(OodsExecutionAuthorityError::MissingStaticSymbol(symbol));
        }
    }
    Ok(())
}

pub(super) fn fixed_identity(
    compiled: &CompiledOodsContract,
) -> Result<[u8; 32], OodsExecutionAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FIXED_DOMAIN);
    hash_size(&mut hasher, compiled.columns.len())?;
    for column in &compiled.columns {
        hash_u32s(
            &mut hasher,
            &[column.source_log_size, column.evaluation_log_size],
        );
        hasher.update(&[source_kind(column.source_kind)]);
        hash_size(&mut hasher, column.offset_points.len())?;
        for point in &column.offset_points {
            hash_u32s(&mut hasher, &[point.x.0, point.y.0]);
        }
    }
    for words in [
        &compiled.fixed_offset_words,
        &compiled.fixed_fold_words,
        &compiled.fixed_output_index_words,
        &compiled.fixed_descriptor_offset_words,
    ] {
        hash_words(&mut hasher, words)?;
    }
    hash_size(&mut hasher, compiled.values.len())?;
    for value in &compiled.values {
        hash_role(&mut hasher, value.role);
        hash_size(&mut hasher, value.words)?;
        hash_size(&mut hasher, value.alignment_words)?;
        hasher.update(&[value.ownership as u8]);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn abi_identity(invocation: &OodsExecutionInvocation) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ABI_DOMAIN);
    hasher.update(&[invocation.abi as u8]);
    hash_bytes(&mut hasher, invocation.abi.wrapper_symbol().as_bytes());
    for argument in invocation.abi.arguments() {
        hasher.update(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
        hash_bytes(&mut hasher, argument.name.as_bytes());
    }
    for argument in &invocation.arguments {
        hasher.update(&[argument.ordinal]);
        hash_bytes(&mut hasher, argument.name.as_bytes());
        match argument.value {
            OodsExecutionInvocationValue::Role(role) => {
                hasher.update(&[1]);
                hash_role(&mut hasher, role);
            }
            OodsExecutionInvocationValue::OrderedStream => {
                hasher.update(&[2]);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn effect_identity(
    accesses: &[OodsExecutionAccess],
) -> Result<[u8; 32], OodsExecutionAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hash_size(&mut hasher, accesses.len())?;
    for access in accesses {
        hash_role(&mut hasher, access.role);
        hasher.update(&[access.kind as u8]);
        hash_size(&mut hasher, access.start_word)?;
        hash_size(&mut hasher, access.words)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn host_call_identity(
    call: &OodsExecutionHostCall,
) -> Result<[u8; 32], OodsExecutionAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HOST_CALL_DOMAIN);
    hasher.update(&call.ordinal.to_le_bytes());
    hash_bytes(&mut hasher, call.wrapper_symbol.as_bytes());
    hash_host_call_kind(&mut hasher, &call.kind)?;
    hash_size(&mut hasher, call.children.len())?;
    for child in &call.children {
        hash_child_launch(&mut hasher, child);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn launch_identity(
    calls: &[OodsExecutionHostCall],
) -> Result<[u8; 32], OodsExecutionAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LAUNCH_DOMAIN);
    hash_size(&mut hasher, calls.len())?;
    for call in calls {
        let identity = host_call_identity(call)?;
        if identity == ZERO_IDENTITY || identity != call.identity {
            return Err(OodsExecutionAuthorityError::ContractMismatch);
        }
        hasher.update(&identity);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn contract_identity(fields: [[u8; 32]; 5]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTRACT_DOMAIN);
    for field in fields {
        hasher.update(&field);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn linked_authority(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> OodsExecutionLinkedAuthority {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&contract_identity);
    hasher.update(&binding.identity);
    hasher.update(&binding.module_build_identity);
    hasher.update(&binding.static_build_source_identity);
    hasher.update(&binding.target_sm.to_le_bytes());
    hasher.update(&binding.sm_identity);
    OodsExecutionLinkedAuthority {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity: *hasher.finalize().as_bytes(),
    }
}

fn hash_host_call_kind(
    hasher: &mut blake3::Hasher,
    kind: &OodsExecutionHostCallKind,
) -> Result<(), OodsExecutionAuthorityError> {
    match kind {
        OodsExecutionHostCallKind::DeriveCoefficient { group } => {
            hash_u32s(hasher, &[1, *group]);
        }
        OodsExecutionHostCallKind::EvaluateFirst { group } => {
            hash_u32s(hasher, &[2, *group]);
        }
        OodsExecutionHostCallKind::EvaluateReduce {
            group,
            pass,
            input_size,
            input_stride,
            factor_index,
            output_stride,
            input,
            output,
        } => {
            hash_u32s(
                hasher,
                &[
                    3,
                    *group,
                    *pass,
                    *input_size,
                    *input_stride,
                    *factor_index,
                    *output_stride,
                    *input as u32,
                    *output as u32,
                ],
            );
        }
        OodsExecutionHostCallKind::StoreCoefficient {
            group,
            reduced_stride,
            reduced,
        } => hash_u32s(hasher, &[4, *group, *reduced_stride, *reduced as u32]),
        OodsExecutionHostCallKind::DeriveEvaluation { group } => {
            hash_u32s(hasher, &[5, *group]);
        }
        OodsExecutionHostCallKind::CollapsedWeights {
            cohort,
            batch,
            first_group,
            group_count,
        } => hash_u32s(hasher, &[6, *cohort, *batch, *first_group, *group_count]),
        OodsExecutionHostCallKind::EvaluateMany {
            group,
            cohort,
            batch,
            local_group,
            weight_offset_words,
        } => {
            hash_u32s(hasher, &[7, *group, *cohort, *batch, *local_group]);
            hash_size(hasher, *weight_offset_words)?;
        }
    }
    Ok(())
}

fn hash_child_launch(hasher: &mut blake3::Hasher, launch: &OodsExecutionKernelLaunch) {
    hash_bytes(hasher, launch.symbol.as_bytes());
    hash_u32s(hasher, &launch.grid);
    hash_u32s(hasher, &launch.block);
    hasher.update(&launch.dynamic_shared_bytes.to_le_bytes());
    hasher.update(&[
        u8::from(launch.cooperative),
        u8::from(launch.cluster.is_some()),
    ]);
    if let Some(cluster) = launch.cluster {
        hash_u32s(hasher, &cluster);
    }
}

fn hash_role(hasher: &mut blake3::Hasher, role: OodsExecutionValueRole) {
    match role {
        OodsExecutionValueRole::SourcePointers => hash_u32s(hasher, &[1]),
        OodsExecutionValueRole::Source { column } => hash_u32s(hasher, &[2, column]),
        OodsExecutionValueRole::PointParameter => hash_u32s(hasher, &[3]),
        OodsExecutionValueRole::OffsetPoints => hash_u32s(hasher, &[4]),
        OodsExecutionValueRole::FoldCounts => hash_u32s(hasher, &[5]),
        OodsExecutionValueRole::OutputIndices => hash_u32s(hasher, &[6]),
        OodsExecutionValueRole::CollapsedDescriptorOffsets => hash_u32s(hasher, &[7]),
        OodsExecutionValueRole::FoldingFactors => hash_u32s(hasher, &[8]),
        OodsExecutionValueRole::ScratchA => hash_u32s(hasher, &[9]),
        OodsExecutionValueRole::ScratchB => hash_u32s(hasher, &[10]),
        OodsExecutionValueRole::SamplePoints => hash_u32s(hasher, &[11]),
        OodsExecutionValueRole::SampledValues => hash_u32s(hasher, &[12]),
        OodsExecutionValueRole::EvaluationPoints => hash_u32s(hasher, &[13]),
        OodsExecutionValueRole::BarycentricNumerators => hash_u32s(hasher, &[14]),
        OodsExecutionValueRole::BarycentricWeights => hash_u32s(hasher, &[15]),
        OodsExecutionValueRole::BarycentricPartials => hash_u32s(hasher, &[16]),
    }
}

fn source_kind(kind: OodsSourceKind) -> u8 {
    match kind {
        OodsSourceKind::Coefficients => 1,
        OodsSourceKind::Evaluations => 2,
    }
}

fn digest_many(domain: &[u8], sources: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for source in sources {
        hash_bytes(&mut hasher, source);
    }
    *hasher.finalize().as_bytes()
}

fn hash_words(
    hasher: &mut blake3::Hasher,
    words: &[u32],
) -> Result<(), OodsExecutionAuthorityError> {
    hash_size(hasher, words.len())?;
    hash_u32s(hasher, words);
    Ok(())
}

fn hash_u32s(hasher: &mut blake3::Hasher, values: &[u32]) {
    for value in values {
        hasher.update(&value.to_le_bytes());
    }
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_size(hasher: &mut blake3::Hasher, value: usize) -> Result<(), OodsExecutionAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| OodsExecutionAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn contains(source: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && source.windows(needle.len()).any(|window| window == needle)
}
