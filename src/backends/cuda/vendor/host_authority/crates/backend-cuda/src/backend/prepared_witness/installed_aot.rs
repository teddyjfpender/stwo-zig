//! Strict-AOT ownership for one prepared recorded-witness graph.
//!
//! The graph still launches through the capture-safe legacy wrapper. This
//! module retains and rechecks the exact cache-owned AOT function that wrapper
//! resolves, without enqueueing through the eager-only installed handle.

use super::{PreparedWitnessError, PreparedWitnessMode, WitnessKernelIdentity};
use crate::backend::aot::{
    self, AotKernelAbiSchema, AotKernelAuthority, AotKernelModuleGlobals, AotKernelSchemaScope,
    InstalledAotFunction, InstalledAotFunctionOwnership, InstalledAotFunctionReceipt,
    InstalledAotLaunchFacts,
};
use crate::backend::exec_context::{cuda_device_snapshot, CudaDeviceSnapshot, CudaExecContext};
use crate::backend::jit_witness::isa::WitnessProgram;

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const RECORDED_WITNESS_BLOCK_THREADS: u32 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorityFacts {
    source_identity: [u8; 32],
    kernel_symbol: &'static str,
    semantic_hash: u64,
    cache_key: u64,
    target_sm: u32,
    cubin_identity: [u8; 32],
    abi_schema: Option<AotKernelAbiSchema>,
    abi_schema_identity: [u8; 32],
    program_identity: [u8; 32],
    authority_identity: [u8; 32],
    schema_scope: AotKernelSchemaScope,
    module_globals: AotKernelModuleGlobals,
}

impl From<AotKernelAuthority> for AuthorityFacts {
    fn from(authority: AotKernelAuthority) -> Self {
        Self {
            source_identity: authority.source_identity(),
            kernel_symbol: authority.kernel_symbol(),
            semantic_hash: authority.semantic_hash(),
            cache_key: authority.cache_key(),
            target_sm: authority.target_sm(),
            cubin_identity: authority.cubin_identity(),
            abi_schema: authority.abi_schema(),
            abi_schema_identity: authority.abi_schema_identity(),
            program_identity: authority.program_identity(),
            authority_identity: authority.identity(),
            schema_scope: authority.schema_scope(),
            module_globals: authority.module_globals(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptFacts {
    manifest_identity: [u8; 32],
    source_identity: [u8; 32],
    cubin_identity: [u8; 32],
    program_identity: [u8; 32],
    abi_schema_identity: [u8; 32],
    authority_identity: [u8; 32],
    kernel_symbol: &'static str,
    semantic_hash: u64,
    cache_key: u64,
    target_sm: u32,
    abi_schema: AotKernelAbiSchema,
    module_globals: AotKernelModuleGlobals,
    ownership_is_borrowed: bool,
    launch: InstalledAotLaunchFacts,
    device_ordinal: u32,
    exec_context_token: u64,
    driver_context_token: u64,
    module_token: u64,
    function_token: u64,
    stream_token: u64,
    has_pedersen_publication: bool,
    publication: FunctionPublicationFacts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FunctionPublicationFacts {
    manifest_identity: [u8; 32],
    source_identity: [u8; 32],
    cubin_identity: [u8; 32],
    program_identity: [u8; 32],
    abi_schema_identity: [u8; 32],
    authority_identity: [u8; 32],
    kernel_symbol: &'static str,
    semantic_hash: u64,
    cache_key: u64,
    target_sm: u32,
    device_ordinal: u32,
    driver_context_token: u64,
    module_token: u64,
    function_token: u64,
}

impl From<&InstalledAotFunctionReceipt> for ReceiptFacts {
    fn from(receipt: &InstalledAotFunctionReceipt) -> Self {
        let publication = receipt.function_publication();
        Self {
            manifest_identity: receipt.manifest_identity(),
            source_identity: receipt.source_identity(),
            cubin_identity: receipt.cubin_identity(),
            program_identity: receipt.program_identity(),
            abi_schema_identity: receipt.abi_schema_identity(),
            authority_identity: receipt.kernel_authority_identity(),
            kernel_symbol: receipt.kernel_symbol(),
            semantic_hash: receipt.semantic_hash(),
            cache_key: receipt.cache_key(),
            target_sm: receipt.target_sm(),
            abi_schema: receipt.abi_schema(),
            module_globals: receipt.module_globals(),
            ownership_is_borrowed: receipt.ownership()
                == InstalledAotFunctionOwnership::BorrowedPublished,
            launch: receipt.launch(),
            device_ordinal: receipt.device_ordinal(),
            exec_context_token: receipt.exec_context_token(),
            driver_context_token: receipt.driver_context_token(),
            module_token: receipt.module_token(),
            function_token: receipt.function_token(),
            stream_token: receipt.stream_token(),
            has_pedersen_publication: receipt.pedersen_publication().is_some(),
            publication: FunctionPublicationFacts {
                manifest_identity: publication.manifest_identity(),
                source_identity: publication.source_identity(),
                cubin_identity: publication.cubin_identity(),
                program_identity: publication.program_identity(),
                abi_schema_identity: publication.abi_schema_identity(),
                authority_identity: publication.kernel_authority_identity(),
                kernel_symbol: publication.kernel_symbol(),
                semantic_hash: publication.semantic_hash(),
                cache_key: publication.cache_key(),
                target_sm: publication.target_sm(),
                device_ordinal: publication.device_ordinal(),
                driver_context_token: publication.driver_context_token(),
                module_token: publication.module_token(),
                function_token: publication.function_token(),
            },
        }
    }
}

pub(super) fn install<'a>(
    context: &'a CudaExecContext,
    identity: &WitnessKernelIdentity,
    program: &WitnessProgram,
    row_count: usize,
) -> Result<Option<InstalledAotFunction<'a>>, PreparedWitnessError> {
    if identity.mode == PreparedWitnessMode::PreResolved {
        validate_retention_mode(identity, false)?;
        return Ok(None);
    }

    let snapshot = cuda_device_snapshot()?;
    let manifest_identity = aot::loaded_manifest_identity();
    let target_sm = target_sm(snapshot).ok_or_else(|| authority_mismatch(identity, "device"))?;
    let authority =
        aot::loaded_kernel_authority(identity.cache_key, target_sm / 10, target_sm % 10);
    let admitted = admit_authority(
        identity,
        program.semantic_identity(),
        manifest_identity,
        snapshot,
        authority.map(AuthorityFacts::from),
    )?
    .ok_or_else(|| PreparedWitnessError::StrictAotAuthorityMissing(identity.clone()))?;
    let authority = authority
        .ok_or_else(|| PreparedWitnessError::StrictAotAuthorityMissing(identity.clone()))?;

    let launch = recorded_launch_facts(row_count)?;
    let installed = InstalledAotFunction::install(context, authority, launch).map_err(|error| {
        PreparedWitnessError::StrictAotInstall {
            identity: identity.clone(),
            error,
        }
    })?;
    validate_receipt(
        identity,
        admitted,
        manifest_identity,
        snapshot,
        launch,
        context.identity_token().as_ptr() as usize as u64,
        context.stream_raw().as_ptr() as usize as u64,
        installed.receipt().into(),
    )?;
    validate_retention_mode(identity, true)?;
    Ok(Some(installed))
}

fn recorded_launch_facts(
    row_count: usize,
) -> Result<InstalledAotLaunchFacts, PreparedWitnessError> {
    if row_count == 0 {
        return Err(PreparedWitnessError::ZeroRows);
    }
    let rows = u32::try_from(row_count).map_err(|_| PreparedWitnessError::RowCountOverflow)?;
    InstalledAotLaunchFacts::new(
        [rows.div_ceil(RECORDED_WITNESS_BLOCK_THREADS), 1, 1],
        [RECORDED_WITNESS_BLOCK_THREADS, 1, 1],
        0,
    )
    .map_err(|_| PreparedWitnessError::SizeOverflow)
}

fn target_sm(snapshot: CudaDeviceSnapshot) -> Option<u32> {
    (snapshot.count != 0
        && snapshot.current < snapshot.count
        && snapshot.sm_major != 0
        && snapshot.sm_minor <= 9)
        .then_some(())
        .and_then(|()| snapshot.sm_major.checked_mul(10))
        .and_then(|major| major.checked_add(snapshot.sm_minor))
}

fn admit_authority(
    identity: &WitnessKernelIdentity,
    program_identity: [u8; 32],
    manifest_identity: [u8; 32],
    snapshot: CudaDeviceSnapshot,
    authority: Option<AuthorityFacts>,
) -> Result<Option<AuthorityFacts>, PreparedWitnessError> {
    if identity.mode == PreparedWitnessMode::PreResolved {
        return Ok(None);
    }
    let authority = authority
        .ok_or_else(|| PreparedWitnessError::StrictAotAuthorityMissing(identity.clone()))?;
    let target_sm = target_sm(snapshot).ok_or_else(|| authority_mismatch(identity, "device"))?;
    let expected_schema = AotKernelAbiSchema::RecordedWitnessV1;
    let globals_valid = matches!(
        authority.module_globals,
        AotKernelModuleGlobals::None | AotKernelModuleGlobals::WitnessPedersenV1
    );
    for (matches, field) in [
        (
            manifest_identity != ZERO_IDENTITY
                && identity.aot_manifest_identity == manifest_identity,
            "manifest_identity",
        ),
        (
            authority.source_identity != ZERO_IDENTITY,
            "source_identity",
        ),
        (
            authority.kernel_symbol == identity.kernel_name,
            "kernel_symbol",
        ),
        (
            authority.semantic_hash == identity.semantic_hash,
            "semantic_hash",
        ),
        (authority.cache_key == identity.cache_key, "cache_key"),
        (authority.target_sm == target_sm, "target_sm"),
        (authority.cubin_identity != ZERO_IDENTITY, "cubin_identity"),
        (authority.abi_schema == Some(expected_schema), "abi_schema"),
        (
            authority.abi_schema_identity == expected_schema.identity(),
            "abi_schema_identity",
        ),
        (
            authority.program_identity == program_identity && program_identity != ZERO_IDENTITY,
            "program_identity",
        ),
        (
            authority.authority_identity != ZERO_IDENTITY,
            "authority_identity",
        ),
        (
            authority.schema_scope == AotKernelSchemaScope::StructuredAbi,
            "schema_scope",
        ),
        (globals_valid, "module_globals"),
    ] {
        if !matches {
            return Err(authority_mismatch(identity, field));
        }
    }
    Ok(Some(authority))
}

#[allow(clippy::too_many_arguments)]
fn validate_receipt(
    identity: &WitnessKernelIdentity,
    authority: AuthorityFacts,
    manifest_identity: [u8; 32],
    snapshot: CudaDeviceSnapshot,
    launch: InstalledAotLaunchFacts,
    exec_context_token: u64,
    stream_token: u64,
    receipt: ReceiptFacts,
) -> Result<(), PreparedWitnessError> {
    let pedersen_expected = authority.module_globals == AotKernelModuleGlobals::WitnessPedersenV1;
    let publication = receipt.publication;
    for (matches, field) in [
        (
            publication.manifest_identity == manifest_identity,
            "publication_manifest_identity",
        ),
        (
            publication.source_identity == authority.source_identity,
            "publication_source_identity",
        ),
        (
            publication.cubin_identity == authority.cubin_identity,
            "publication_cubin_identity",
        ),
        (
            publication.program_identity == authority.program_identity,
            "publication_program_identity",
        ),
        (
            publication.abi_schema_identity == authority.abi_schema_identity,
            "publication_abi_schema_identity",
        ),
        (
            publication.authority_identity == authority.authority_identity,
            "publication_authority_identity",
        ),
        (
            publication.kernel_symbol == authority.kernel_symbol,
            "publication_kernel_symbol",
        ),
        (
            publication.semantic_hash == authority.semantic_hash,
            "publication_semantic_hash",
        ),
        (
            publication.cache_key == authority.cache_key,
            "publication_cache_key",
        ),
        (
            publication.target_sm == authority.target_sm,
            "publication_target_sm",
        ),
        (
            publication.device_ordinal == snapshot.current,
            "publication_device_ordinal",
        ),
        (
            publication.driver_context_token != 0,
            "publication_driver_context_token",
        ),
        (publication.module_token != 0, "publication_module_token"),
        (
            publication.function_token != 0,
            "publication_function_token",
        ),
    ] {
        if !matches {
            return Err(receipt_mismatch(identity, field));
        }
    }
    for (matches, field) in [
        (
            receipt.manifest_identity == manifest_identity,
            "manifest_identity",
        ),
        (
            receipt.source_identity == authority.source_identity,
            "source_identity",
        ),
        (
            receipt.cubin_identity == authority.cubin_identity,
            "cubin_identity",
        ),
        (
            receipt.program_identity == authority.program_identity,
            "program_identity",
        ),
        (
            receipt.abi_schema_identity == authority.abi_schema_identity,
            "abi_schema_identity",
        ),
        (
            receipt.authority_identity == authority.authority_identity,
            "authority_identity",
        ),
        (
            receipt.kernel_symbol == authority.kernel_symbol,
            "kernel_symbol",
        ),
        (
            receipt.semantic_hash == authority.semantic_hash,
            "semantic_hash",
        ),
        (receipt.cache_key == authority.cache_key, "cache_key"),
        (receipt.target_sm == authority.target_sm, "target_sm"),
        (
            receipt.abi_schema == AotKernelAbiSchema::RecordedWitnessV1,
            "abi_schema",
        ),
        (
            receipt.module_globals == authority.module_globals,
            "module_globals",
        ),
        (receipt.ownership_is_borrowed, "ownership"),
        (receipt.launch == launch, "launch"),
        (receipt.device_ordinal == snapshot.current, "device_ordinal"),
        (
            receipt.exec_context_token == exec_context_token && exec_context_token != 0,
            "exec_context_token",
        ),
        (
            receipt.driver_context_token == publication.driver_context_token,
            "driver_context_token",
        ),
        (
            receipt.module_token == publication.module_token,
            "module_token",
        ),
        (
            receipt.function_token == publication.function_token,
            "function_token",
        ),
        (
            receipt.stream_token == stream_token && stream_token != 0,
            "stream_token",
        ),
        (
            receipt.has_pedersen_publication == pedersen_expected,
            "pedersen_publication",
        ),
    ] {
        if !matches {
            return Err(receipt_mismatch(identity, field));
        }
    }
    Ok(())
}

fn validate_retention_mode(
    identity: &WitnessKernelIdentity,
    retained: bool,
) -> Result<(), PreparedWitnessError> {
    match (identity.mode, retained) {
        (PreparedWitnessMode::PreResolved, false)
        | (PreparedWitnessMode::RequireEmbeddedAot, true) => Ok(()),
        _ => Err(receipt_mismatch(identity, "retention_mode")),
    }
}

fn authority_mismatch(
    identity: &WitnessKernelIdentity,
    field: &'static str,
) -> PreparedWitnessError {
    PreparedWitnessError::StrictAotAuthorityMismatch {
        identity: identity.clone(),
        field,
    }
}

fn receipt_mismatch(identity: &WitnessKernelIdentity, field: &'static str) -> PreparedWitnessError {
    PreparedWitnessError::StrictAotReceiptMismatch {
        identity: identity.clone(),
        field,
    }
}

#[cfg(test)]
mod tests;
