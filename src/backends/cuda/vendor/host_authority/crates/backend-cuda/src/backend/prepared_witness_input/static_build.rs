//! Shared binding of a pure witness-input contract to the linked static CUDA build.

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const STATIC_BUILD_SOURCE: &[u8] = include_bytes!("static_build.rs");
const STATIC_BUILD_SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-input-static-build-source-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StaticBuildBinding {
    pub(crate) module_build_identity: [u8; 32],
    pub(crate) static_build_source_identity: [u8; 32],
    pub(crate) target_sm: u32,
    pub(crate) sm_identity: [u8; 32],
    pub(crate) identity: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StaticBuildBindError {
    InconsistentBuildMetadata,
    BuildReceiptUnavailable,
    BuildReceiptMismatch,
    UnsupportedTargetSm(u32),
}

pub(crate) fn bind_static_build(
    domain: &[u8],
    contract_identity: [u8; 32],
    target_sm: u32,
) -> Result<Option<StaticBuildBinding>, StaticBuildBindError> {
    let expected = stwo_backend_cuda_kernels::expected_static_cuda_module_build_identity();
    let target_sms = stwo_backend_cuda_kernels::static_cuda_module_target_sms();
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return if expected == ZERO_IDENTITY && target_sms.is_empty() {
            Ok(None)
        } else {
            Err(StaticBuildBindError::InconsistentBuildMetadata)
        };
    }
    let actual =
        stwo_backend_cuda_kernels::static_cuda_module_build_identity().map_err(|error| {
            use stwo_backend_cuda_kernels::StaticCudaModuleBuildIdentityError;
            match error {
                StaticCudaModuleBuildIdentityError::Unavailable(_) => {
                    StaticBuildBindError::BuildReceiptUnavailable
                }
                StaticCudaModuleBuildIdentityError::ReceiptMismatch { .. } => {
                    StaticBuildBindError::BuildReceiptMismatch
                }
            }
        })?;
    binding_from_fields(
        domain,
        contract_identity,
        actual,
        expected,
        target_sms,
        target_sm,
    )
    .map(Some)
}

fn binding_from_fields(
    domain: &[u8],
    contract_identity: [u8; 32],
    actual_build_identity: [u8; 32],
    expected_build_identity: [u8; 32],
    target_sms: &[u32],
    target_sm: u32,
) -> Result<StaticBuildBinding, StaticBuildBindError> {
    let static_build_source_identity = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(STATIC_BUILD_SOURCE_DOMAIN);
        hasher.update(
            &u64::try_from(STATIC_BUILD_SOURCE.len())
                .map_err(|_| StaticBuildBindError::InconsistentBuildMetadata)?
                .to_le_bytes(),
        );
        hasher.update(STATIC_BUILD_SOURCE);
        *hasher.finalize().as_bytes()
    };
    if contract_identity == ZERO_IDENTITY
        || actual_build_identity == ZERO_IDENTITY
        || expected_build_identity == ZERO_IDENTITY
        || actual_build_identity != expected_build_identity
        || static_build_source_identity == ZERO_IDENTITY
        || target_sms.is_empty()
        || target_sm == 0
        || !target_sms.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(StaticBuildBindError::InconsistentBuildMetadata);
    }
    if !target_sms.contains(&target_sm) {
        return Err(StaticBuildBindError::UnsupportedTargetSm(target_sm));
    }
    let mut sm_hasher = blake3::Hasher::new();
    sm_hasher.update(domain);
    sm_hasher.update(b"sm-v1\0");
    sm_hasher.update(
        &u64::try_from(target_sms.len())
            .map_err(|_| StaticBuildBindError::InconsistentBuildMetadata)?
            .to_le_bytes(),
    );
    for sm in target_sms {
        sm_hasher.update(&sm.to_le_bytes());
    }
    sm_hasher.update(&target_sm.to_le_bytes());
    let sm_identity = *sm_hasher.finalize().as_bytes();

    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(b"binding-v1\0");
    hasher.update(&contract_identity);
    hasher.update(&actual_build_identity);
    hasher.update(&static_build_source_identity);
    hasher.update(&sm_identity);
    let identity = *hasher.finalize().as_bytes();
    Ok(StaticBuildBinding {
        module_build_identity: actual_build_identity,
        static_build_source_identity,
        target_sm,
        sm_identity,
        identity,
    })
}

#[cfg(test)]
pub(crate) fn binding_for_test(
    domain: &[u8],
    contract_identity: [u8; 32],
    actual_build_identity: [u8; 32],
    expected_build_identity: [u8; 32],
    target_sms: &[u32],
    target_sm: u32,
) -> Result<StaticBuildBinding, StaticBuildBindError> {
    binding_from_fields(
        domain,
        contract_identity,
        actual_build_identity,
        expected_build_identity,
        target_sms,
        target_sm,
    )
}

#[cfg(test)]
pub(crate) fn validate_binding_for_test(
    binding: &StaticBuildBinding,
    domain: &[u8],
    contract_identity: [u8; 32],
    actual_build_identity: [u8; 32],
    expected_build_identity: [u8; 32],
    target_sms: &[u32],
    target_sm: u32,
) -> Result<(), StaticBuildBindError> {
    let expected = binding_from_fields(
        domain,
        contract_identity,
        actual_build_identity,
        expected_build_identity,
        target_sms,
        target_sm,
    )?;
    if *binding == expected {
        Ok(())
    } else {
        Err(StaticBuildBindError::InconsistentBuildMetadata)
    }
}
