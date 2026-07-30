//! Context-bound ownership and launch authority for one embedded AOT function.
//!
//! Every function borrows the exact entry retained by `runtime_jit.cu`, which
//! is also what the unchanged prover launch wrappers resolve. A witness module
//! carrying Pedersen globals additionally requires the live table/global
//! publication. This seam is eager-only; graph ownership remains separate.

use core::ffi::c_void;
use core::ptr::NonNull;
use std::ffi::CString;

use stwo_backend_cuda_kernels::raw::{
    CudaFunctionAttributes as NativeFunctionResources,
    CudaInstalledAotFunctionReceipt as NativeReceipt, CUDA_INSTALLED_AOT_BORROWED_PUBLISHED,
    CUDA_INSTALLED_AOT_FUNCTION_ABI_VERSION,
};

use super::{
    loaded_aot_function_publication, AotKernelAbiSchema, AotKernelAuthority,
    AotKernelModuleGlobals, AotKernelSchemaScope, LoadedAotFunctionPublication,
    LoadedAotFunctionPublicationError,
};
use crate::backend::exec_context::CudaExecContext;
use crate::backend::pedersen_module_publication::{
    loaded_aot_pedersen_module_publication, PedersenModulePublicationError,
    PedersenModulePublicationReceipt,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const CUDA_SUCCESS: i32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledAotLaunchFacts {
    grid: [u32; 3],
    block: [u32; 3],
    dynamic_shared_bytes: u32,
}

impl InstalledAotLaunchFacts {
    pub fn new(
        grid: [u32; 3],
        block: [u32; 3],
        dynamic_shared_bytes: u32,
    ) -> Result<Self, InstalledAotFunctionError> {
        if grid.contains(&0)
            || block.contains(&0)
            || block
                .into_iter()
                .try_fold(1u64, |product, value| product.checked_mul(u64::from(value)))
                .is_none()
        {
            return Err(InstalledAotFunctionError::InvalidLaunchFacts);
        }
        Ok(Self {
            grid,
            block,
            dynamic_shared_bytes,
        })
    }

    pub const fn grid(self) -> [u32; 3] {
        self.grid
    }

    pub const fn block(self) -> [u32; 3] {
        self.block
    }

    pub const fn dynamic_shared_bytes(self) -> u32 {
        self.dynamic_shared_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledAotFunctionOwnership {
    BorrowedPublished,
}

/// Resources reported by CUDA for the exact loaded function in this receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledAotFunctionResources {
    pub max_threads_per_block: u32,
    pub registers_per_thread: u32,
    pub binary_version: u32,
    pub ptx_version: u32,
    pub local_bytes: u64,
    pub static_shared_bytes: u64,
}

/// Semantic and process-local receipt for one installed function.
///
/// Pointer-shaped tokens are equality facts for this process only. They never
/// enter the program, proof, or artifact identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledAotFunctionReceipt {
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
    abi_schema: AotKernelAbiSchema,
    module_globals: AotKernelModuleGlobals,
    ownership: InstalledAotFunctionOwnership,
    launch: InstalledAotLaunchFacts,
    device_ordinal: u32,
    exec_context_token: u64,
    driver_context_token: u64,
    module_token: u64,
    function_token: u64,
    stream_token: u64,
    resources: InstalledAotFunctionResources,
    function_publication: LoadedAotFunctionPublication,
    pedersen_publication: Option<PedersenModulePublicationReceipt>,
}

impl InstalledAotFunctionReceipt {
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

    pub const fn abi_schema(&self) -> AotKernelAbiSchema {
        self.abi_schema
    }

    pub const fn module_globals(&self) -> AotKernelModuleGlobals {
        self.module_globals
    }

    pub const fn ownership(&self) -> InstalledAotFunctionOwnership {
        self.ownership
    }

    pub const fn launch(&self) -> InstalledAotLaunchFacts {
        self.launch
    }

    pub const fn device_ordinal(&self) -> u32 {
        self.device_ordinal
    }

    pub const fn exec_context_token(&self) -> u64 {
        self.exec_context_token
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

    pub const fn stream_token(&self) -> u64 {
        self.stream_token
    }

    pub const fn resources(&self) -> InstalledAotFunctionResources {
        self.resources
    }

    pub const fn function_publication(&self) -> &LoadedAotFunctionPublication {
        &self.function_publication
    }

    pub fn pedersen_publication(&self) -> Option<&PedersenModulePublicationReceipt> {
        self.pedersen_publication.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstalledAotFunctionError {
    AuthorityMismatch,
    InvalidAuthority,
    SymbolOnlyAuthority,
    UnspecifiedModuleGlobals,
    InvalidKernelSymbol,
    InvalidLaunchFacts,
    FunctionPublication(LoadedAotFunctionPublicationError),
    PedersenPublication(PedersenModulePublicationError),
    Native { operation: &'static str, code: i32 },
    NullNativeHandle,
    NativeReceiptMismatch,
    ContextMismatch,
    ArgumentSchemaMismatch,
    ArgumentCount { expected: usize, actual: usize },
    NullArgument { ordinal: usize },
}

impl core::fmt::Display for InstalledAotFunctionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AuthorityMismatch => {
                formatter.write_str("AOT authority does not match the embedded index")
            }
            Self::InvalidAuthority => formatter.write_str("AOT authority is invalid"),
            Self::SymbolOnlyAuthority => {
                formatter.write_str("symbol-only AOT authority is not installable")
            }
            Self::UnspecifiedModuleGlobals => {
                formatter.write_str("AOT module-global contract is unspecified")
            }
            Self::InvalidKernelSymbol => formatter.write_str("AOT kernel symbol contains NUL"),
            Self::InvalidLaunchFacts => formatter.write_str("invalid AOT launch facts"),
            Self::FunctionPublication(error) => {
                write!(formatter, "loaded AOT function publication failed: {error}")
            }
            Self::PedersenPublication(error) => {
                write!(formatter, "Pedersen module publication failed: {error}")
            }
            Self::Native { operation, code } => {
                write!(
                    formatter,
                    "native AOT {operation} failed with status {code}"
                )
            }
            Self::NullNativeHandle => {
                formatter.write_str("native AOT install returned a null handle")
            }
            Self::NativeReceiptMismatch => {
                formatter.write_str("native AOT install receipt mismatched authority")
            }
            Self::ContextMismatch => formatter.write_str("CUDA context identity mismatch"),
            Self::ArgumentSchemaMismatch => formatter.write_str("AOT argument schema mismatch"),
            Self::ArgumentCount { expected, actual } => {
                write!(
                    formatter,
                    "AOT argument count mismatch: expected {expected}, got {actual}"
                )
            }
            Self::NullArgument { ordinal } => {
                write!(
                    formatter,
                    "AOT argument {ordinal} has a null storage pointer"
                )
            }
        }
    }
}

impl std::error::Error for InstalledAotFunctionError {}

impl From<PedersenModulePublicationError> for InstalledAotFunctionError {
    fn from(value: PedersenModulePublicationError) -> Self {
        Self::PedersenPublication(value)
    }
}

impl From<LoadedAotFunctionPublicationError> for InstalledAotFunctionError {
    fn from(value: LoadedAotFunctionPublicationError) -> Self {
        Self::FunctionPublication(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorityFacts {
    source_identity: [u8; 32],
    cubin_identity: [u8; 32],
    program_identity: [u8; 32],
    abi_schema_identity: [u8; 32],
    authority_identity: [u8; 32],
    kernel_symbol: &'static str,
    target_sm: u32,
    schema: Option<AotKernelAbiSchema>,
    scope: AotKernelSchemaScope,
    module_globals: AotKernelModuleGlobals,
}

impl From<AotKernelAuthority> for AuthorityFacts {
    fn from(authority: AotKernelAuthority) -> Self {
        Self {
            source_identity: authority.source_identity(),
            cubin_identity: authority.cubin_identity(),
            program_identity: authority.program_identity(),
            abi_schema_identity: authority.abi_schema_identity(),
            authority_identity: authority.identity(),
            kernel_symbol: authority.kernel_symbol(),
            target_sm: authority.target_sm(),
            schema: authority.abi_schema(),
            scope: authority.schema_scope(),
            module_globals: authority.module_globals(),
        }
    }
}

impl AuthorityFacts {
    fn validate(self) -> Result<AotKernelAbiSchema, InstalledAotFunctionError> {
        if self.scope != AotKernelSchemaScope::StructuredAbi {
            return Err(InstalledAotFunctionError::SymbolOnlyAuthority);
        }
        let schema = self
            .schema
            .ok_or(InstalledAotFunctionError::SymbolOnlyAuthority)?;
        let globals_valid = matches!(
            (schema, self.module_globals),
            (
                AotKernelAbiSchema::RecordedWitnessV1,
                AotKernelModuleGlobals::None | AotKernelModuleGlobals::WitnessPedersenV1
            ) | (
                AotKernelAbiSchema::OrdinaryConstraintV1,
                AotKernelModuleGlobals::None
            ) | (
                AotKernelAbiSchema::CompositionWaveV2,
                AotKernelModuleGlobals::None
            )
        );
        if self.kernel_symbol.is_empty()
            || self.source_identity == ZERO_IDENTITY
            || self.cubin_identity == ZERO_IDENTITY
            || self.program_identity == ZERO_IDENTITY
            || self.authority_identity == ZERO_IDENTITY
            || self.abi_schema_identity != schema.identity()
            || self.target_sm < 10
            || !globals_valid
        {
            return Err(InstalledAotFunctionError::InvalidAuthority);
        }
        Ok(schema)
    }
}

#[derive(Debug)]
pub struct CheckedAotArguments<'arguments> {
    authority_identity: [u8; 32],
    schema: AotKernelAbiSchema,
    arguments: &'arguments mut [*mut c_void],
}

/// One installed AOT function. The legacy cache retains the module; this handle
/// revalidates the exact published function before every enqueue.
///
/// Installation is a post-precompile admission step: the existing strict-AOT
/// precompile path must first populate this exact cache entry successfully on
/// the proof's CUDA context. Install it after that success and before
/// `PreparedWitnessGraph` runtime admission; it never compiles or self-heals a
/// missing entry.
pub struct InstalledAotFunction<'context> {
    handle: NonNull<c_void>,
    context: &'context CudaExecContext,
    receipt: InstalledAotFunctionReceipt,
}

impl<'context> InstalledAotFunction<'context> {
    pub fn install(
        context: &'context CudaExecContext,
        authority: AotKernelAuthority,
        launch: InstalledAotLaunchFacts,
    ) -> Result<Self, InstalledAotFunctionError> {
        let facts = AuthorityFacts::from(authority);
        let schema = facts.validate()?;
        let sm_major = authority.target_sm() / 10;
        let sm_minor = authority.target_sm() % 10;
        let kernel_name = CString::new(authority.kernel_symbol())
            .map_err(|_| InstalledAotFunctionError::InvalidKernelSymbol)?;
        let argument_count = u32::try_from(schema.arguments().len())
            .map_err(|_| InstalledAotFunctionError::InvalidAuthority)?;
        let function_publication = loaded_aot_function_publication(authority)?;
        let manifest_identity = function_publication.manifest_identity();
        let pedersen_publication = match authority.module_globals() {
            AotKernelModuleGlobals::None => None,
            AotKernelModuleGlobals::WitnessPedersenV1 => {
                let publication = loaded_aot_pedersen_module_publication(
                    authority.cache_key(),
                    sm_major,
                    sm_minor,
                )?;
                validate_pedersen_publication(&publication, &function_publication, authority)?;
                Some(publication)
            }
            _ => return Err(InstalledAotFunctionError::UnspecifiedModuleGlobals),
        };

        let mut raw_handle = core::ptr::null_mut();
        let mut native = NativeReceipt::default();
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_installed_aot_function_borrow_published_create(
                context.identity_token().as_ptr(),
                kernel_name.as_ptr(),
                authority.cache_key(),
                authority.target_sm(),
                function_publication.module_token(),
                function_publication.function_token(),
                function_publication.driver_context_token(),
                argument_count,
                launch.grid[0],
                launch.grid[1],
                launch.grid[2],
                launch.block[0],
                launch.block[1],
                launch.block[2],
                launch.dynamic_shared_bytes,
                &mut raw_handle,
                &mut native,
            )
        };
        if code != CUDA_SUCCESS {
            if let Some(handle) = NonNull::new(raw_handle) {
                unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_installed_aot_function_destroy(
                        handle.as_ptr(),
                    );
                }
            }
            return Err(InstalledAotFunctionError::Native {
                operation: "install",
                code,
            });
        }
        let handle = NonNull::new(raw_handle).ok_or(InstalledAotFunctionError::NullNativeHandle)?;
        if validate_native_receipt(
            &native,
            authority.target_sm(),
            argument_count,
            launch,
            context.stream_raw().as_ptr() as usize as u64,
            function_publication.device_ordinal(),
            function_publication.driver_context_token(),
            function_publication.module_token(),
            function_publication.function_token(),
            pedersen_publication.as_ref(),
        )
        .is_err()
        {
            unsafe {
                stwo_backend_cuda_kernels::raw::stwo_installed_aot_function_destroy(
                    handle.as_ptr(),
                );
            }
            return Err(InstalledAotFunctionError::NativeReceiptMismatch);
        }

        Ok(Self {
            handle,
            context,
            receipt: InstalledAotFunctionReceipt {
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
                abi_schema: schema,
                module_globals: authority.module_globals(),
                ownership: InstalledAotFunctionOwnership::BorrowedPublished,
                launch,
                device_ordinal: native.device_ordinal,
                exec_context_token: context.identity_token().as_ptr() as usize as u64,
                driver_context_token: native.context_token,
                module_token: native.module_token,
                function_token: native.function_token,
                stream_token: native.stream_token,
                resources: native_function_resources(native.function),
                function_publication,
                pedersen_publication,
            },
        })
    }

    pub fn receipt(&self) -> &InstalledAotFunctionReceipt {
        &self.receipt
    }

    pub fn belongs_to(&self, context: &CudaExecContext) -> bool {
        self.context.identity_token() == context.identity_token()
    }

    pub fn check_arguments<'arguments>(
        &self,
        schema: AotKernelAbiSchema,
        arguments: &'arguments mut [*mut c_void],
    ) -> Result<CheckedAotArguments<'arguments>, InstalledAotFunctionError> {
        check_arguments(
            self.receipt.kernel_authority_identity,
            self.receipt.abi_schema,
            schema,
            arguments,
        )
    }

    /// Enqueue this function with the immutable launch facts sealed at install.
    ///
    /// # Safety
    ///
    /// Every pointer in `arguments` must address host storage containing one
    /// parameter value with the checked schema's exact kind. Device pointers
    /// and all referenced extents must belong to `context`, satisfy the access
    /// contract, and remain live until its stream passes the launch.
    pub unsafe fn launch_raw(
        &self,
        context: &CudaExecContext,
        arguments: CheckedAotArguments<'_>,
    ) -> Result<(), InstalledAotFunctionError> {
        dispatch_checked(
            self.receipt.kernel_authority_identity,
            self.receipt.abi_schema,
            self.context.identity_token().as_ptr() as usize,
            context.identity_token().as_ptr() as usize,
            arguments,
            |raw| {
                let argument_count = u32::try_from(raw.len())
                    .map_err(|_| InstalledAotFunctionError::InvalidAuthority)?;
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_installed_aot_function_launch(
                        self.handle.as_ptr(),
                        context.identity_token().as_ptr(),
                        raw.as_mut_ptr(),
                        argument_count,
                    )
                };
                if code == CUDA_SUCCESS {
                    Ok(())
                } else {
                    Err(InstalledAotFunctionError::Native {
                        operation: "launch",
                        code,
                    })
                }
            },
        )
    }
}

impl Drop for InstalledAotFunction<'_> {
    fn drop(&mut self) {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_installed_aot_function_destroy(
                self.handle.as_ptr(),
            )
        };
        if code != CUDA_SUCCESS && !std::thread::panicking() {
            eprintln!("stwo-backend-cuda: installed AOT destroy failed with status {code}");
        }
    }
}

fn validate_pedersen_publication(
    publication: &PedersenModulePublicationReceipt,
    function: &LoadedAotFunctionPublication,
    authority: AotKernelAuthority,
) -> Result<(), InstalledAotFunctionError> {
    if publication.manifest_identity() != function.manifest_identity()
        || publication.source_identity() != authority.source_identity()
        || publication.cubin_identity() != authority.cubin_identity()
        || publication.program_identity() != authority.program_identity()
        || publication.abi_schema_identity() != authority.abi_schema_identity()
        || publication.kernel_authority_identity() != authority.identity()
        || publication.kernel_symbol() != authority.kernel_symbol()
        || publication.semantic_hash() != authority.semantic_hash()
        || publication.semantic_hash() != function.semantic_hash()
        || publication.cache_key() != authority.cache_key()
        || publication.target_sm() != authority.target_sm()
        || publication.device_ordinal() != function.device_ordinal()
        || publication.module_token() != function.module_token()
        || publication.function_token() != function.function_token()
        || publication.context_token() != function.driver_context_token()
    {
        return Err(InstalledAotFunctionError::AuthorityMismatch);
    }
    Ok(())
}

fn validate_native_receipt(
    native: &NativeReceipt,
    target_sm: u32,
    argument_count: u32,
    launch: InstalledAotLaunchFacts,
    stream_token: u64,
    device_ordinal: u32,
    context_token: u64,
    module_token: u64,
    function_token: u64,
    pedersen: Option<&PedersenModulePublicationReceipt>,
) -> Result<(), InstalledAotFunctionError> {
    if native.abi_version != CUDA_INSTALLED_AOT_FUNCTION_ABI_VERSION
        || native.ownership != CUDA_INSTALLED_AOT_BORROWED_PUBLISHED
        || native.sm_minor > 9
        || native
            .sm_major
            .checked_mul(10)
            .and_then(|major| major.checked_add(native.sm_minor))
            != Some(target_sm)
        || native.argument_count != argument_count
        || [native.grid_x, native.grid_y, native.grid_z] != launch.grid
        || [native.block_x, native.block_y, native.block_z] != launch.block
        || native.dynamic_shared_bytes != launch.dynamic_shared_bytes
        || native.reserved != 0
        || native.device_ordinal != device_ordinal
        || native.context_token != context_token
        || native.module_token != module_token
        || native.function_token != function_token
        || native.stream_token != stream_token
        || !native_function_resources_valid(native.function, target_sm)
    {
        return Err(InstalledAotFunctionError::NativeReceiptMismatch);
    }
    if let Some(publication) = pedersen {
        if native.device_ordinal != publication.device_ordinal()
            || native.context_token != publication.context_token()
            || native.module_token != publication.module_token()
            || native.function_token != publication.function_token()
        {
            return Err(InstalledAotFunctionError::NativeReceiptMismatch);
        }
    }
    Ok(())
}

fn native_function_resources_valid(resources: NativeFunctionResources, target_sm: u32) -> bool {
    resources.abi_version == 1
        && resources.reserved == 0
        && resources.max_threads_per_block != 0
        && resources.binary_version == target_sm
}

fn native_function_resources(resources: NativeFunctionResources) -> InstalledAotFunctionResources {
    InstalledAotFunctionResources {
        max_threads_per_block: resources.max_threads_per_block,
        registers_per_thread: resources.registers_per_thread,
        binary_version: resources.binary_version,
        ptx_version: resources.ptx_version,
        local_bytes: resources.local_bytes,
        static_shared_bytes: resources.static_shared_bytes,
    }
}

fn check_arguments<'arguments>(
    authority_identity: [u8; 32],
    expected_schema: AotKernelAbiSchema,
    actual_schema: AotKernelAbiSchema,
    arguments: &'arguments mut [*mut c_void],
) -> Result<CheckedAotArguments<'arguments>, InstalledAotFunctionError> {
    if actual_schema != expected_schema {
        return Err(InstalledAotFunctionError::ArgumentSchemaMismatch);
    }
    let expected = expected_schema.arguments().len();
    if arguments.len() != expected {
        return Err(InstalledAotFunctionError::ArgumentCount {
            expected,
            actual: arguments.len(),
        });
    }
    if let Some(ordinal) = arguments.iter().position(|argument| argument.is_null()) {
        return Err(InstalledAotFunctionError::NullArgument { ordinal });
    }
    Ok(CheckedAotArguments {
        authority_identity,
        schema: expected_schema,
        arguments,
    })
}

fn dispatch_checked<T>(
    expected_authority: [u8; 32],
    expected_schema: AotKernelAbiSchema,
    expected_context: usize,
    actual_context: usize,
    mut checked: CheckedAotArguments<'_>,
    dispatch: impl FnOnce(&mut [*mut c_void]) -> Result<T, InstalledAotFunctionError>,
) -> Result<T, InstalledAotFunctionError> {
    if expected_context != actual_context {
        return Err(InstalledAotFunctionError::ContextMismatch);
    }
    if checked.authority_identity != expected_authority || checked.schema != expected_schema {
        return Err(InstalledAotFunctionError::ArgumentSchemaMismatch);
    }
    dispatch(&mut checked.arguments)
}

#[cfg(test)]
mod tests;
