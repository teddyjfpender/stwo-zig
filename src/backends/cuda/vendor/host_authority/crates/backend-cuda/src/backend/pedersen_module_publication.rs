//! Fail-closed composition of a live CUmodule publication with semantic authority.
//!
//! Native code proves process-local facts: the exact current module/context,
//! symbols, ordered pointer values, readback, and completion event. This layer
//! separately binds those addresses to the process-lifetime registered table and
//! the collision-resistant embedded AOT identities. The table digest identifies
//! exactly what this process registered; it does not by itself assert canonical
//! Cairo Pedersen content. That comparison belongs at the stwo-cairo authority
//! gate. Process addresses never enter a semantic hash.

use std::ffi::CString;

use stwo_backend_cuda_kernels::raw::{
    CudaPedersenModulePublication, CUDA_PEDERSEN_GLOBALS_PRESENT,
    CUDA_PEDERSEN_PUBLICATION_ABI_VERSION, CUDA_PEDERSEN_PUBLICATION_REQUIRED_FLAGS,
};

use super::aot::{
    self, AotKernelAbiSchema, AotKernelAuthority, AotKernelModuleGlobals, AotKernelSchemaScope,
};
use super::pedersen_table::{
    registered_borrowed_pedersen_table, PedersenTableContentDigest, RegisteredPedersenTable,
    RegisteredPedersenTableError, PEDERSEN_TABLE_N_COLUMNS, PEDERSEN_TABLE_REGISTRATION_GENERATION,
};

const PEDERSEN_COLUMNS_SYMBOL_BYTES: u32 = 56 * 8;
const PEDERSEN_ROWS_SYMBOL_BYTES: u32 = 4;

/// Exact semantic and process-local authority for one live AOT module.
///
/// The address tokens are diagnostic/equality fields only. They are deliberately
/// private and must never be folded into a program, proof, or artifact identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PedersenModulePublicationReceipt {
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
    table_content_digest: PedersenTableContentDigest,
    table_source_rows: usize,
    table_padded_rows: usize,
    table_registration_generation: u64,
    device_ordinal: u32,
    module_token: u64,
    function_token: u64,
    context_token: u64,
    columns_symbol_token: u64,
    rows_symbol_token: u64,
    completion_event_token: u64,
    column_pointers: [u64; PEDERSEN_TABLE_N_COLUMNS],
}

impl PedersenModulePublicationReceipt {
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

    pub const fn table_content_digest(&self) -> PedersenTableContentDigest {
        self.table_content_digest
    }

    pub const fn table_source_rows(&self) -> usize {
        self.table_source_rows
    }

    pub const fn table_padded_rows(&self) -> usize {
        self.table_padded_rows
    }

    pub const fn table_registration_generation(&self) -> u64 {
        self.table_registration_generation
    }

    pub const fn device_ordinal(&self) -> u32 {
        self.device_ordinal
    }

    /// Process-local equality token, never a semantic identity.
    pub const fn module_token(&self) -> u64 {
        self.module_token
    }

    /// Process-local equality token for the exact exported function.
    pub const fn function_token(&self) -> u64 {
        self.function_token
    }

    /// Process-local equality token, never a semantic identity.
    pub const fn context_token(&self) -> u64 {
        self.context_token
    }

    /// Process-local address of the exact 448-byte, 8-byte-aligned pointer symbol.
    pub const fn columns_symbol_token(&self) -> u64 {
        self.columns_symbol_token
    }

    pub const fn columns_symbol_bytes(&self) -> u32 {
        PEDERSEN_COLUMNS_SYMBOL_BYTES
    }

    /// Process-local address of the exact 4-byte, 4-byte-aligned row-count symbol.
    pub const fn rows_symbol_token(&self) -> u64 {
        self.rows_symbol_token
    }

    pub const fn rows_symbol_bytes(&self) -> u32 {
        PEDERSEN_ROWS_SYMBOL_BYTES
    }

    /// Process-local equality token for the synchronized initialization event.
    pub const fn completion_event_token(&self) -> u64 {
        self.completion_event_token
    }

    pub const fn column_pointers(&self) -> [u64; PEDERSEN_TABLE_N_COLUMNS] {
        self.column_pointers
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PedersenModulePublicationError {
    CudaUnavailable,
    InvalidArchitecture,
    MissingManifestAuthority,
    MissingKernelAuthority,
    InvalidKernelAuthority,
    InvalidKernelSymbol,
    RegisteredTableUnavailable,
    RegisteredTable(RegisteredPedersenTableError),
    AddressOverflow,
    NativePublicationUnavailable,
    NativePublicationMismatch,
}

impl core::fmt::Display for PedersenModulePublicationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CudaUnavailable => formatter.write_str("CUDA kernels are unavailable"),
            Self::InvalidArchitecture => formatter.write_str("invalid CUDA SM architecture"),
            Self::MissingManifestAuthority => {
                formatter.write_str("loaded AOT manifest authority is missing")
            }
            Self::MissingKernelAuthority => {
                formatter.write_str("loaded AOT kernel authority is missing")
            }
            Self::InvalidKernelAuthority => {
                formatter.write_str("loaded AOT kernel authority is invalid")
            }
            Self::InvalidKernelSymbol => formatter.write_str("AOT kernel symbol contains NUL"),
            Self::RegisteredTableUnavailable => {
                formatter.write_str("registered Pedersen table is unavailable")
            }
            Self::RegisteredTable(error) => {
                write!(formatter, "registered Pedersen table is invalid: {error:?}")
            }
            Self::AddressOverflow => formatter.write_str("device address does not fit u64"),
            Self::NativePublicationUnavailable => {
                formatter.write_str("live AOT Pedersen module publication is unavailable")
            }
            Self::NativePublicationMismatch => {
                formatter.write_str("live AOT Pedersen module publication mismatched authority")
            }
        }
    }
}

impl std::error::Error for PedersenModulePublicationError {}

impl From<RegisteredPedersenTableError> for PedersenModulePublicationError {
    fn from(value: RegisteredPedersenTableError) -> Self {
        Self::RegisteredTable(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegisteredTableFields {
    content_digest: PedersenTableContentDigest,
    source_rows: usize,
    padded_rows: usize,
    registration_generation: u64,
    column_pointers: [u64; PEDERSEN_TABLE_N_COLUMNS],
}

impl RegisteredTableFields {
    fn from_registered(
        table: RegisteredPedersenTable,
    ) -> Result<Self, PedersenModulePublicationError> {
        table.validate_exact_registration_geometry(
            table.content_digest(),
            table.source_n_rows(),
            table.n_rows(),
        )?;
        let mut column_pointers = [0; PEDERSEN_TABLE_N_COLUMNS];
        for (index, column) in table.columns().into_iter().enumerate() {
            column_pointers[index] = u64::try_from(column.as_u32_ptr() as usize)
                .map_err(|_| PedersenModulePublicationError::AddressOverflow)?;
        }
        Ok(Self {
            content_digest: table.content_digest(),
            source_rows: table.source_n_rows(),
            padded_rows: table.n_rows(),
            registration_generation: table.registration_generation(),
            column_pointers,
        })
    }
}

fn target_sm(sm_major: u32, sm_minor: u32) -> Option<u32> {
    (sm_minor < 10)
        .then_some(())
        .and_then(|()| sm_major.checked_mul(10))
        .and_then(|major| major.checked_add(sm_minor))
}

fn validate_kernel_authority(
    authority: AotKernelAuthority,
    cache_key: u64,
    expected_target_sm: u32,
) -> Result<(), PedersenModulePublicationError> {
    if authority.cache_key() != cache_key
        || authority.target_sm() != expected_target_sm
        || authority.abi_schema() != Some(AotKernelAbiSchema::RecordedWitnessV1)
        || authority.schema_scope() != AotKernelSchemaScope::StructuredAbi
        || authority.module_globals() != AotKernelModuleGlobals::WitnessPedersenV1
        || authority.kernel_symbol().is_empty()
        || authority.source_identity() == [0; 32]
        || authority.cubin_identity() == [0; 32]
        || authority.program_identity() == [0; 32]
        || authority.abi_schema_identity() != AotKernelAbiSchema::RecordedWitnessV1.identity()
        || authority.identity() == [0; 32]
    {
        return Err(PedersenModulePublicationError::InvalidKernelAuthority);
    }
    Ok(())
}

fn validate_native_publication(
    native: &CudaPedersenModulePublication,
    kernel_cache_key: u64,
    sm_major: u32,
    sm_minor: u32,
    table: &RegisteredTableFields,
) -> Result<(), PedersenModulePublicationError> {
    let expected_rows = u32::try_from(table.padded_rows)
        .map_err(|_| PedersenModulePublicationError::NativePublicationMismatch)?;
    if native.abi_version != CUDA_PEDERSEN_PUBLICATION_ABI_VERSION
        || native.flags != CUDA_PEDERSEN_PUBLICATION_REQUIRED_FLAGS
        || native.globals_state != CUDA_PEDERSEN_GLOBALS_PRESENT
        || native.sm_major != sm_major
        || native.sm_minor != sm_minor
        || native.pointer_count != PEDERSEN_TABLE_N_COLUMNS as u32
        || native.columns_symbol_bytes != PEDERSEN_COLUMNS_SYMBOL_BYTES
        || native.rows_symbol_bytes != PEDERSEN_ROWS_SYMBOL_BYTES
        || native.n_rows != expected_rows
        || native.cache_key != kernel_cache_key
        || native.module_token == 0
        || native.function_token == 0
        || native.context_token == 0
        || native.columns_symbol_token == 0
        || native.rows_symbol_token == 0
        || native.completion_event_token == 0
        || native.columns_symbol_token % 8 != 0
        || native.rows_symbol_token % 4 != 0
        || table.registration_generation != PEDERSEN_TABLE_REGISTRATION_GENERATION
        || native.column_pointers != table.column_pointers
        || native
            .column_pointers
            .iter()
            .any(|pointer| *pointer == 0 || pointer % 4 != 0)
    {
        return Err(PedersenModulePublicationError::NativePublicationMismatch);
    }
    Ok(())
}

/// Require one exact live AOT module publication on the current CUDA context.
///
/// This is a cold setup/admission operation. It must complete before dependent
/// graph instantiation; hot launches continue to use the unchanged launch ABI.
/// It relies on the formal table's one-shot `OnceLock` registration and retained
/// allocations for the process/context lifetime. A replaceable table or context
/// teardown requires a new generation and an owning installed-program abstraction.
pub fn loaded_aot_pedersen_module_publication(
    cache_key: u64,
    sm_major: u32,
    sm_minor: u32,
) -> Result<PedersenModulePublicationReceipt, PedersenModulePublicationError> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(PedersenModulePublicationError::CudaUnavailable);
    }
    let target_sm =
        target_sm(sm_major, sm_minor).ok_or(PedersenModulePublicationError::InvalidArchitecture)?;
    let manifest_identity = aot::loaded_manifest_identity();
    if manifest_identity == [0; 32] {
        return Err(PedersenModulePublicationError::MissingManifestAuthority);
    }
    let authority = aot::loaded_kernel_authority(cache_key, sm_major, sm_minor)
        .ok_or(PedersenModulePublicationError::MissingKernelAuthority)?;
    validate_kernel_authority(authority, cache_key, target_sm)?;
    let kernel_name = CString::new(authority.kernel_symbol())
        .map_err(|_| PedersenModulePublicationError::InvalidKernelSymbol)?;

    let table = registered_borrowed_pedersen_table()
        .ok_or(PedersenModulePublicationError::RegisteredTableUnavailable)?;
    let table = RegisteredTableFields::from_registered(table)?;
    let mut native = CudaPedersenModulePublication::default();
    let available = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_cuda_jit_get_pedersen_module_publication(
            kernel_name.as_ptr(),
            cache_key,
            &mut native,
        )
    };
    if !available {
        return Err(PedersenModulePublicationError::NativePublicationUnavailable);
    }
    validate_native_publication(&native, cache_key, sm_major, sm_minor, &table)?;

    Ok(PedersenModulePublicationReceipt {
        manifest_identity,
        source_identity: authority.source_identity(),
        cubin_identity: authority.cubin_identity(),
        program_identity: authority.program_identity(),
        abi_schema_identity: authority.abi_schema_identity(),
        kernel_authority_identity: authority.identity(),
        kernel_symbol: authority.kernel_symbol(),
        semantic_hash: authority.semantic_hash(),
        cache_key,
        target_sm,
        table_content_digest: table.content_digest,
        table_source_rows: table.source_rows,
        table_padded_rows: table.padded_rows,
        table_registration_generation: table.registration_generation,
        device_ordinal: native.device_ordinal,
        module_token: native.module_token,
        function_token: native.function_token,
        context_token: native.context_token,
        columns_symbol_token: native.columns_symbol_token,
        rows_symbol_token: native.rows_symbol_token,
        completion_event_token: native.completion_event_token,
        column_pointers: native.column_pointers,
    })
}

#[cfg(test)]
mod tests {
    use stwo_backend_cuda_kernels::raw::CUDA_PEDERSEN_PUBLICATION_EVENT_COMPLETE;

    use super::*;

    fn table() -> RegisteredTableFields {
        RegisteredTableFields {
            content_digest: PedersenTableContentDigest::new([7; 32]),
            source_rows: 7,
            padded_rows: 8,
            registration_generation: PEDERSEN_TABLE_REGISTRATION_GENERATION,
            column_pointers: std::array::from_fn(|index| 0x1000 + index as u64 * 0x100),
        }
    }

    fn native() -> CudaPedersenModulePublication {
        let table = table();
        CudaPedersenModulePublication {
            abi_version: CUDA_PEDERSEN_PUBLICATION_ABI_VERSION,
            flags: CUDA_PEDERSEN_PUBLICATION_REQUIRED_FLAGS,
            device_ordinal: 0,
            sm_major: 8,
            sm_minor: 9,
            pointer_count: PEDERSEN_TABLE_N_COLUMNS as u32,
            columns_symbol_bytes: PEDERSEN_COLUMNS_SYMBOL_BYTES,
            rows_symbol_bytes: PEDERSEN_ROWS_SYMBOL_BYTES,
            n_rows: table.padded_rows as u32,
            globals_state: CUDA_PEDERSEN_GLOBALS_PRESENT,
            cache_key: 17,
            module_token: 0x100,
            function_token: 0x200,
            context_token: 0x300,
            columns_symbol_token: 0x400,
            rows_symbol_token: 0x500,
            completion_event_token: 0x600,
            column_pointers: table.column_pointers,
        }
    }

    #[test]
    fn exact_native_publication_is_accepted() {
        validate_native_publication(&native(), 17, 8, 9, &table()).unwrap();
    }

    #[test]
    fn absent_globals_cannot_fabricate_a_present_publication() {
        let mut absent = native();
        absent.globals_state = stwo_backend_cuda_kernels::raw::CUDA_PEDERSEN_GLOBALS_ABSENT;
        absent.flags = 1;
        absent.completion_event_token = 0;
        assert_eq!(
            validate_native_publication(&absent, 17, 8, 9, &table()),
            Err(PedersenModulePublicationError::NativePublicationMismatch)
        );
    }

    #[test]
    fn every_native_authority_class_fails_closed() {
        let cases: &[fn(&mut CudaPedersenModulePublication)] = &[
            |receipt| receipt.abi_version += 1,
            |receipt| receipt.flags ^= CUDA_PEDERSEN_PUBLICATION_EVENT_COMPLETE,
            |receipt| receipt.globals_state = 0,
            |receipt| receipt.sm_major += 1,
            |receipt| receipt.sm_minor += 1,
            |receipt| receipt.pointer_count -= 1,
            |receipt| receipt.columns_symbol_bytes -= 1,
            |receipt| receipt.rows_symbol_bytes += 1,
            |receipt| receipt.n_rows *= 2,
            |receipt| receipt.cache_key += 1,
            |receipt| receipt.module_token = 0,
            |receipt| receipt.function_token = 0,
            |receipt| receipt.context_token = 0,
            |receipt| receipt.columns_symbol_token += 1,
            |receipt| receipt.rows_symbol_token += 1,
            |receipt| receipt.completion_event_token = 0,
            |receipt| receipt.column_pointers.swap(0, 1),
            |receipt| receipt.column_pointers[55] = 0,
        ];
        for mutate in cases {
            let mut changed = native();
            mutate(&mut changed);
            assert_eq!(
                validate_native_publication(&changed, 17, 8, 9, &table()),
                Err(PedersenModulePublicationError::NativePublicationMismatch)
            );
        }

        let mut stale_table = table();
        stale_table.registration_generation = 0;
        assert_eq!(
            validate_native_publication(&native(), 17, 8, 9, &stale_table),
            Err(PedersenModulePublicationError::NativePublicationMismatch)
        );
    }

    #[test]
    fn invalid_architecture_is_rejected() {
        assert_eq!(target_sm(8, 10), None);
        assert_eq!(target_sm(u32::MAX, 0), None);
        assert_eq!(target_sm(8, 9), Some(89));
    }

    #[test]
    fn stub_build_cannot_fabricate_a_live_publication() {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            assert_eq!(
                loaded_aot_pedersen_module_publication(17, 8, 9),
                Err(PedersenModulePublicationError::CudaUnavailable)
            );
        }
    }
}
