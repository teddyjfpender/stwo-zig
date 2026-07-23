//! Read-only authority for the exact function retained by `runtime_jit.cu`.
//!
//! The legacy launch wrappers resolve this same `(cache_key, CUcontext)` cache
//! entry. Retaining its module/function tokens therefore names the function
//! that unchanged witness and constraint dispatch will actually enqueue.

use std::ffi::CString;

use stwo_backend_cuda_kernels::raw::{
    CudaAotFunctionPublication as NativePublication, CUDA_AOT_FUNCTION_PUBLICATION_ABI_VERSION,
    CUDA_AOT_FUNCTION_PUBLICATION_AOT,
};

use super::{
    loaded_kernel_authority, loaded_manifest_identity, AotKernelAuthority, AotKernelSchemaScope,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedAotFunctionPublication {
    manifest_identity: [u8; 32],
    source_identity: [u8; 32],
    cubin_identity: [u8; 32],
    program_identity: [u8; 32],
    abi_schema_identity: [u8; 32],
    kernel_authority_identity: [u8; 32],
    kernel_symbol: &'static str,
    semantic_hash: u64,
    cache_key: u64,
    target_sm: u32,
    device_ordinal: u32,
    driver_context_token: u64,
    module_token: u64,
    function_token: u64,
}

impl LoadedAotFunctionPublication {
    pub const fn manifest_identity(&self) -> [u8; 32] {
        self.manifest_identity
    }

    pub const fn source_identity(&self) -> [u8; 32] {
        self.source_identity
    }

    pub const fn cubin_identity(&self) -> [u8; 32] {
        self.cubin_identity
    }

    pub const fn program_identity(&self) -> [u8; 32] {
        self.program_identity
    }

    pub const fn abi_schema_identity(&self) -> [u8; 32] {
        self.abi_schema_identity
    }

    pub const fn kernel_authority_identity(&self) -> [u8; 32] {
        self.kernel_authority_identity
    }

    pub const fn kernel_symbol(&self) -> &'static str {
        self.kernel_symbol
    }

    pub const fn semantic_hash(&self) -> u64 {
        self.semantic_hash
    }

    pub const fn cache_key(&self) -> u64 {
        self.cache_key
    }

    pub const fn target_sm(&self) -> u32 {
        self.target_sm
    }

    pub const fn device_ordinal(&self) -> u32 {
        self.device_ordinal
    }

    pub const fn driver_context_token(&self) -> u64 {
        self.driver_context_token
    }

    pub const fn module_token(&self) -> u64 {
        self.module_token
    }

    pub const fn function_token(&self) -> u64 {
        self.function_token
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoadedAotFunctionPublicationError {
    CudaUnavailable,
    MissingManifestAuthority,
    InvalidAuthority,
    AuthorityMismatch,
    InvalidKernelSymbol,
    NativePublicationUnavailable,
    NativePublicationMismatch,
}

impl core::fmt::Display for LoadedAotFunctionPublicationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CudaUnavailable => formatter.write_str("CUDA kernels are unavailable"),
            Self::MissingManifestAuthority => {
                formatter.write_str("loaded AOT manifest authority is missing")
            }
            Self::InvalidAuthority => formatter.write_str("AOT function authority is invalid"),
            Self::AuthorityMismatch => {
                formatter.write_str("AOT function authority mismatched the embedded index")
            }
            Self::InvalidKernelSymbol => formatter.write_str("AOT kernel symbol contains NUL"),
            Self::NativePublicationUnavailable => {
                formatter.write_str("loaded AOT function publication is unavailable")
            }
            Self::NativePublicationMismatch => {
                formatter.write_str("loaded AOT function publication mismatched authority")
            }
        }
    }
}

impl std::error::Error for LoadedAotFunctionPublicationError {}

/// Publish the current-context cache entry after an exact successful AOT
/// precompile. A cache miss is an error; this read-only operation never invokes
/// NVRTC, loads a module, or changes cache state.
pub fn loaded_aot_function_publication(
    authority: AotKernelAuthority,
) -> Result<LoadedAotFunctionPublication, LoadedAotFunctionPublicationError> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(LoadedAotFunctionPublicationError::CudaUnavailable);
    }
    let manifest_identity = loaded_manifest_identity();
    if manifest_identity == ZERO_IDENTITY {
        return Err(LoadedAotFunctionPublicationError::MissingManifestAuthority);
    }
    if authority.schema_scope() != AotKernelSchemaScope::StructuredAbi
        || authority.abi_schema().is_none()
        || authority.kernel_symbol().is_empty()
        || authority.source_identity() == ZERO_IDENTITY
        || authority.cubin_identity() == ZERO_IDENTITY
        || authority.program_identity() == ZERO_IDENTITY
        || authority.abi_schema_identity() == ZERO_IDENTITY
        || authority.identity() == ZERO_IDENTITY
        || authority.target_sm() < 10
    {
        return Err(LoadedAotFunctionPublicationError::InvalidAuthority);
    }
    let sm_major = authority.target_sm() / 10;
    let sm_minor = authority.target_sm() % 10;
    if loaded_kernel_authority(authority.cache_key(), sm_major, sm_minor) != Some(authority) {
        return Err(LoadedAotFunctionPublicationError::AuthorityMismatch);
    }
    let kernel_name = CString::new(authority.kernel_symbol())
        .map_err(|_| LoadedAotFunctionPublicationError::InvalidKernelSymbol)?;
    let mut native = NativePublication::default();
    let available = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_cuda_jit_get_aot_function_publication(
            kernel_name.as_ptr(),
            authority.cache_key(),
            &mut native,
        )
    };
    if !available {
        return Err(LoadedAotFunctionPublicationError::NativePublicationUnavailable);
    }
    validate_native(&native, authority.cache_key(), authority.target_sm())?;

    Ok(LoadedAotFunctionPublication {
        manifest_identity,
        source_identity: authority.source_identity(),
        cubin_identity: authority.cubin_identity(),
        program_identity: authority.program_identity(),
        abi_schema_identity: authority.abi_schema_identity(),
        kernel_authority_identity: authority.identity(),
        kernel_symbol: authority.kernel_symbol(),
        semantic_hash: authority.semantic_hash(),
        cache_key: authority.cache_key(),
        target_sm: authority.target_sm(),
        device_ordinal: native.device_ordinal,
        driver_context_token: native.context_token,
        module_token: native.module_token,
        function_token: native.function_token,
    })
}

fn validate_native(
    native: &NativePublication,
    cache_key: u64,
    target_sm: u32,
) -> Result<(), LoadedAotFunctionPublicationError> {
    if native.abi_version != CUDA_AOT_FUNCTION_PUBLICATION_ABI_VERSION
        || native.flags != CUDA_AOT_FUNCTION_PUBLICATION_AOT
        || native.reserved != 0
        || native.cache_key != cache_key
        || native.sm_minor > 9
        || native
            .sm_major
            .checked_mul(10)
            .and_then(|major| major.checked_add(native.sm_minor))
            != Some(target_sm)
        || native.context_token == 0
        || native.module_token == 0
        || native.function_token == 0
    {
        return Err(LoadedAotFunctionPublicationError::NativePublicationMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native() -> NativePublication {
        NativePublication {
            abi_version: CUDA_AOT_FUNCTION_PUBLICATION_ABI_VERSION,
            flags: CUDA_AOT_FUNCTION_PUBLICATION_AOT,
            device_ordinal: 0,
            sm_major: 8,
            sm_minor: 9,
            reserved: 0,
            cache_key: 17,
            context_token: 0x100,
            module_token: 0x200,
            function_token: 0x300,
        }
    }

    #[test]
    fn native_publication_mutations_fail_closed_before_install() {
        assert_eq!(validate_native(&native(), 17, 89), Ok(()));
        for mutate in [
            |receipt: &mut NativePublication| receipt.abi_version += 1,
            |receipt: &mut NativePublication| receipt.flags = 0,
            |receipt: &mut NativePublication| receipt.reserved = 1,
            |receipt: &mut NativePublication| receipt.sm_minor += 1,
            |receipt: &mut NativePublication| receipt.cache_key += 1,
            |receipt: &mut NativePublication| receipt.context_token = 0,
            |receipt: &mut NativePublication| receipt.module_token = 0,
            |receipt: &mut NativePublication| receipt.function_token = 0,
        ] {
            let mut changed = native();
            mutate(&mut changed);
            assert_eq!(
                validate_native(&changed, 17, 89),
                Err(LoadedAotFunctionPublicationError::NativePublicationMismatch)
            );
        }
    }
}
