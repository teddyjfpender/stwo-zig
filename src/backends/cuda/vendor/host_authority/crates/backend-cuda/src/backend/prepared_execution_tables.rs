//! Arena-backed Cairo execution tables for resident witness replay.
//!
//! Compact host tables are ingested into stable raw slots during setup. The hot
//! launch only splits big and small values into their stable limb columns on the
//! arena stream. Pointer and stride descriptors are uploaded once and then shared
//! by every prepared witness graph through [`PreparedExecutionTablesView`].

use core::cell::Cell;
use core::ffi::c_void;
use std::collections::BTreeSet;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaLaunchContext, CudaRuntimeError,
    DeviceArena,
};

mod authority;
mod ingest_receipt;

pub use authority::{
    ExecutionTablesAbi, ExecutionTablesAbiAccess, ExecutionTablesAbiArgument,
    ExecutionTablesAbiArgumentKind, ExecutionTablesAuthorityError, ExecutionTablesColumnEffect,
    ExecutionTablesContract, ExecutionTablesEffectAbi, ExecutionTablesFixedField,
    ExecutionTablesHostIngressEncoding, ExecutionTablesHostIngressField,
    ExecutionTablesHostIngressGeometry, ExecutionTablesHostIngressRole,
    ExecutionTablesKernelLaunch, ExecutionTablesLinkedContract, ExecutionTablesRowDomain,
    ExecutionTablesStage, ExecutionTablesStageContract, ExecutionTablesStageEffect,
    EXECUTION_TABLES_FIXED_ORDER, EXECUTION_TABLES_STAGE_ORDER,
};
pub use ingest_receipt::ExecutionTablesIngestReceipt;

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const F252_WORDS: usize = 8;
const SMALL_WORDS: usize = 4;
pub const EXECUTION_TABLE_BIG_LIMBS: usize = 28;
pub const EXECUTION_TABLE_SMALL_LIMBS: usize = 8;
pub const EXECUTION_TABLE_POINTERS: usize =
    1 + EXECUTION_TABLE_BIG_LIMBS + EXECUTION_TABLE_SMALL_LIMBS;
pub const EXECUTION_TABLE_STRIDES: usize = 3;
pub const EXECUTION_TABLE_POINTER_ALIGNMENT_WORDS: usize =
    core::mem::align_of::<*mut u32>() / WORD_BYTES;
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);
const MIN_COLUMN_WORDS: usize = 16;

/// Pure arena geometry for one fixed execution-table shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTablesWorkspaceRequirements {
    pub n_addrs: usize,
    pub n_big: usize,
    pub n_small: usize,
    pub raw_addr_to_id_words: usize,
    pub raw_f252_words: usize,
    pub raw_small_words: usize,
    pub big_column_words: usize,
    pub small_column_words: usize,
    pub table_pointer_words: usize,
    pub table_stride_words: usize,
}

/// One requirement for merging execution tables into the proof-wide arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionTablesArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

/// Stable logical slots used by the prepared execution tables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTablesWorkspaceSlots {
    pub raw_addr_to_id: ArenaSlotId,
    pub raw_f252_words: ArenaSlotId,
    pub raw_small_words: ArenaSlotId,
    pub big_limbs: Vec<ArenaSlotId>,
    pub small_limbs: Vec<ArenaSlotId>,
    pub table_pointers: ArenaSlotId,
    pub table_strides: ArenaSlotId,
}

impl ExecutionTablesWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &ExecutionTablesWorkspaceSlots,
    ) -> Result<Vec<ExecutionTablesArenaSlotRequirement>, PreparedExecutionTablesError> {
        if slots.big_limbs.len() != EXECUTION_TABLE_BIG_LIMBS {
            return Err(PreparedExecutionTablesError::SlotShapeMismatch {
                role: "big_limbs",
                expected: EXECUTION_TABLE_BIG_LIMBS,
                actual: slots.big_limbs.len(),
            });
        }
        if slots.small_limbs.len() != EXECUTION_TABLE_SMALL_LIMBS {
            return Err(PreparedExecutionTablesError::SlotShapeMismatch {
                role: "small_limbs",
                expected: EXECUTION_TABLE_SMALL_LIMBS,
                actual: slots.small_limbs.len(),
            });
        }
        let mut ids = vec![
            slots.raw_addr_to_id,
            slots.raw_f252_words,
            slots.raw_small_words,
            slots.table_pointers,
            slots.table_strides,
        ];
        ids.extend(slots.big_limbs.iter().copied());
        ids.extend(slots.small_limbs.iter().copied());
        ensure_distinct(&ids)?;

        let mut output = vec![
            words(slots.raw_addr_to_id, self.raw_addr_to_id_words),
            words(slots.raw_f252_words, self.raw_f252_words),
            words(slots.raw_small_words, self.raw_small_words),
        ];
        output.extend(
            slots
                .big_limbs
                .iter()
                .map(|&id| words(id, self.big_column_words)),
        );
        output.extend(
            slots
                .small_limbs
                .iter()
                .map(|&id| words(id, self.small_column_words)),
        );
        output.push(ExecutionTablesArenaSlotRequirement {
            id: slots.table_pointers,
            len_words: self.table_pointer_words,
            alignment_words: EXECUTION_TABLE_POINTER_ALIGNMENT_WORDS,
        });
        output.push(words(slots.table_strides, self.table_stride_words));
        Ok(output)
    }
}

fn words(id: ArenaSlotId, len_words: usize) -> ExecutionTablesArenaSlotRequirement {
    ExecutionTablesArenaSlotRequirement {
        id,
        len_words,
        alignment_words: 1,
    }
}

/// Compute the exact stable-slot geometry without touching CUDA.
pub fn execution_tables_workspace_requirements(
    n_addrs: usize,
    n_big: usize,
    n_small: usize,
) -> Result<ExecutionTablesWorkspaceRequirements, PreparedExecutionTablesError> {
    let raw_f252_words = n_big
        .checked_mul(F252_WORDS)
        .ok_or(PreparedExecutionTablesError::SizeOverflow)?
        .max(1);
    let raw_small_words = n_small
        .checked_mul(SMALL_WORDS)
        .ok_or(PreparedExecutionTablesError::SizeOverflow)?
        .max(1);
    let big_column_words = padded_column_words(n_big)?;
    let small_column_words = padded_column_words(n_small)?;
    let table_pointer_words = EXECUTION_TABLE_POINTERS
        .checked_mul(POINTER_WORDS)
        .ok_or(PreparedExecutionTablesError::SizeOverflow)?;
    Ok(ExecutionTablesWorkspaceRequirements {
        n_addrs,
        n_big,
        n_small,
        raw_addr_to_id_words: n_addrs.max(1),
        raw_f252_words,
        raw_small_words,
        big_column_words,
        small_column_words,
        table_pointer_words,
        table_stride_words: EXECUTION_TABLE_STRIDES,
    })
}

fn padded_column_words(n: usize) -> Result<usize, PreparedExecutionTablesError> {
    n.max(1)
        .checked_next_power_of_two()
        .map(|words| words.max(MIN_COLUMN_WORDS))
        .ok_or(PreparedExecutionTablesError::SizeOverflow)
}

/// Compact host data copied into the arena at the setup boundary.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionTablesHostData<'a> {
    pub addr_to_id: &'a [u32],
    pub f252_values: &'a [[u32; F252_WORDS]],
    pub small_values: &'a [u128],
}

/// Auditable work performed by one setup ingest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedExecutionTablesIngestTelemetry {
    pub compact_h2d_bytes: u64,
    pub compact_h2d_copies: u64,
    pub descriptor_h2d_bytes: u64,
    pub descriptor_h2d_copies: u64,
    pub sync_calls: u64,
}

/// Exact work submitted by one hot execution-table launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedExecutionTablesLaunchTelemetry {
    pub kernel_launches: u64,
    pub allocations: u64,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub d2d_bytes: u64,
    pub sync_calls: u64,
}

impl PreparedExecutionTablesLaunchTelemetry {
    const TWO_SPLITS: Self = Self {
        kernel_launches: 2,
        allocations: 0,
        h2d_bytes: 0,
        d2h_bytes: 0,
        d2d_bytes: 0,
        sync_calls: 0,
    };
}

/// Rejected geometry or CUDA boundary operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedExecutionTablesError {
    CudaUnavailable,
    SizeOverflow,
    InvalidRequirements,
    SlotShapeMismatch {
        role: &'static str,
        expected: usize,
        actual: usize,
    },
    DuplicateSlot(ArenaSlotId),
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    SlotMisaligned(ArenaSlotId),
    HostShapeMismatch {
        role: &'static str,
        expected: usize,
        actual: usize,
    },
    IngestGenerationOverflow,
    NotIngested,
    Authority(ExecutionTablesAuthorityError),
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedExecutionTablesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "prepared execution tables rejected: {self:?}")
    }
}

impl std::error::Error for PreparedExecutionTablesError {}

impl From<ArenaError> for PreparedExecutionTablesError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedExecutionTablesError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

impl From<ExecutionTablesAuthorityError> for PreparedExecutionTablesError {
    fn from(value: ExecutionTablesAuthorityError) -> Self {
        Self::Authority(value)
    }
}

/// Copyable descriptor view shared with prepared witness launches. All pointed-to
/// storage is owned by the borrowed arena, not by a process-global cache.
#[derive(Clone, Copy)]
pub struct PreparedExecutionTablesView<'a> {
    arena: &'a DeviceArena,
    table_pointers: ArenaSlice,
    table_strides: ArenaSlice,
    table_data: [ArenaSlice; EXECUTION_TABLE_POINTERS],
    n_addrs: usize,
    n_big: usize,
    n_small: usize,
}

impl PreparedExecutionTablesView<'_> {
    pub fn table_pointers(self) -> ArenaSlice {
        self.table_pointers
    }

    pub fn table_strides(self) -> ArenaSlice {
        self.table_strides
    }

    /// Exact data ranges dereferenced through `table_pointers` by every witness
    /// launch. Admission uses this inventory to reject stale arena reuse masks.
    pub(crate) fn table_data(self) -> [ArenaSlice; EXECUTION_TABLE_POINTERS] {
        self.table_data
    }

    pub fn shape(self) -> (usize, usize, usize) {
        (self.n_addrs, self.n_big, self.n_small)
    }

    pub fn belongs_to(self, arena: &DeviceArena) -> bool {
        core::ptr::eq(self.arena, arena)
            && self.table_pointers.context_token() == arena.context().identity_token()
            && self.table_strides.context_token() == arena.context().identity_token()
            && self
                .table_data
                .iter()
                .all(|slice| slice.context_token() == arena.context().identity_token())
    }
}

/// Stable arena binding for execution tables. The first ingest also uploads the
/// immutable descriptors; later ingests update only compact contents of the same
/// shape. [`Self::launch`] performs only two explicit-stream kernel enqueues.
pub struct PreparedExecutionTablesGraph<'a> {
    arena: &'a DeviceArena,
    contract: ExecutionTablesContract,
    raw_addr_to_id: ArenaSlice,
    raw_f252_words: ArenaSlice,
    raw_small_words: ArenaSlice,
    big_limbs: Vec<ArenaSlice>,
    small_limbs: Vec<ArenaSlice>,
    table_pointers: ArenaSlice,
    table_strides: ArenaSlice,
    descriptor_pointers: Vec<usize>,
    descriptor_strides: [u32; EXECUTION_TABLE_STRIDES],
    big_output_pointers: Vec<*mut u32>,
    small_output_pointers: Vec<*mut u32>,
    initialized: Cell<bool>,
    ingest_state: ingest_receipt::ExecutionTablesIngestState,
}

impl<'a> PreparedExecutionTablesGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        requirements: &ExecutionTablesWorkspaceRequirements,
        slots: &ExecutionTablesWorkspaceSlots,
    ) -> Result<Self, PreparedExecutionTablesError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedExecutionTablesError::CudaUnavailable);
        }
        if execution_tables_workspace_requirements(
            requirements.n_addrs,
            requirements.n_big,
            requirements.n_small,
        )? != *requirements
        {
            return Err(PreparedExecutionTablesError::InvalidRequirements);
        }
        let contract = ExecutionTablesContract::compile(requirements)?;
        requirements.arena_slot_requirements(slots)?;
        let raw_addr_to_id = bind_slot(
            arena,
            slots.raw_addr_to_id,
            requirements.raw_addr_to_id_words,
            1,
        )?;
        let raw_f252_words =
            bind_slot(arena, slots.raw_f252_words, requirements.raw_f252_words, 1)?;
        let raw_small_words = bind_slot(
            arena,
            slots.raw_small_words,
            requirements.raw_small_words,
            1,
        )?;
        let big_limbs = bind_many(arena, &slots.big_limbs, requirements.big_column_words)?;
        let small_limbs = bind_many(arena, &slots.small_limbs, requirements.small_column_words)?;
        let table_pointers = bind_slot(
            arena,
            slots.table_pointers,
            requirements.table_pointer_words,
            EXECUTION_TABLE_POINTER_ALIGNMENT_WORDS,
        )?;
        let table_strides = bind_slot(
            arena,
            slots.table_strides,
            requirements.table_stride_words,
            1,
        )?;

        let mut descriptor_pointers = Vec::with_capacity(EXECUTION_TABLE_POINTERS);
        descriptor_pointers.push(raw_addr_to_id.as_u32_ptr() as usize);
        descriptor_pointers.extend(big_limbs.iter().map(|column| column.as_u32_ptr() as usize));
        descriptor_pointers.extend(
            small_limbs
                .iter()
                .map(|column| column.as_u32_ptr() as usize),
        );
        debug_assert_eq!(descriptor_pointers.len(), EXECUTION_TABLE_POINTERS);
        let descriptor_strides = [
            u32::try_from(requirements.n_addrs)
                .map_err(|_| PreparedExecutionTablesError::SizeOverflow)?,
            u32::try_from(requirements.n_big)
                .map_err(|_| PreparedExecutionTablesError::SizeOverflow)?,
            u32::try_from(requirements.n_small)
                .map_err(|_| PreparedExecutionTablesError::SizeOverflow)?,
        ];
        let big_output_pointers = big_limbs.iter().map(|column| column.as_u32_ptr()).collect();
        let small_output_pointers = small_limbs
            .iter()
            .map(|column| column.as_u32_ptr())
            .collect();

        Ok(Self {
            arena,
            contract,
            raw_addr_to_id,
            raw_f252_words,
            raw_small_words,
            big_limbs,
            small_limbs,
            table_pointers,
            table_strides,
            descriptor_pointers,
            descriptor_strides,
            big_output_pointers,
            small_output_pointers,
            initialized: Cell::new(false),
            ingest_state: ingest_receipt::ExecutionTablesIngestState::new(),
        })
    }

    /// Upload one same-shape compact table set and fence setup exactly once.
    pub fn ingest(
        &self,
        host: ExecutionTablesHostData<'_>,
    ) -> Result<PreparedExecutionTablesIngestTelemetry, PreparedExecutionTablesError> {
        let requirements = self.contract.requirements();
        let generation = self.ingest_state.next_generation()?;
        let binding = ingest_receipt::ExecutionTablesIngestBinding::new(
            self.arena,
            &self.contract,
            self.raw_addr_to_id,
            self.raw_f252_words,
            self.raw_small_words,
        );
        let receipt =
            ExecutionTablesIngestReceipt::prepare(binding, &self.contract, host, generation)?;

        // Keep the explicit little-endian representation used by the legacy path;
        // the setup-only temporary remains alive through the single fence below.
        let small_words = host
            .small_values
            .iter()
            .flat_map(|&value| {
                [
                    value as u32,
                    (value >> 32) as u32,
                    (value >> 64) as u32,
                    (value >> 96) as u32,
                ]
            })
            .collect::<Vec<_>>();
        let first_ingest = !self.initialized.get();
        let compact_bytes = requirements
            .n_addrs
            .checked_add(
                requirements
                    .n_big
                    .checked_mul(F252_WORDS)
                    .ok_or(PreparedExecutionTablesError::SizeOverflow)?,
            )
            .and_then(|words| {
                requirements
                    .n_small
                    .checked_mul(SMALL_WORDS)
                    .and_then(|small| words.checked_add(small))
            })
            .and_then(|words| words.checked_mul(WORD_BYTES))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(PreparedExecutionTablesError::SizeOverflow)?;
        let descriptor_bytes = if first_ingest {
            requirements
                .table_pointer_words
                .checked_add(requirements.table_stride_words)
                .and_then(|words| words.checked_mul(WORD_BYTES))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(PreparedExecutionTablesError::SizeOverflow)?
        } else {
            0
        };

        // No earlier receipt may attest potentially changed device bytes once
        // a fully validated attempt can begin. Failed attempts consume their
        // generation and leave no current receipt.
        self.ingest_state.begin(receipt);
        let upload_result = (|| {
            if first_ingest {
                upload(self.arena, self.table_pointers, &self.descriptor_pointers)?;
                upload(self.arena, self.table_strides, &self.descriptor_strides)?;
            }
            upload(self.arena, self.raw_addr_to_id, host.addr_to_id)?;
            upload(self.arena, self.raw_f252_words, host.f252_values)?;
            upload(self.arena, self.raw_small_words, &small_words)
        })();
        // Drain even if a later enqueue failed, so no borrowed host source can
        // escape this method while an earlier asynchronous copy is still live.
        let sync_result = self.arena.context().sync();
        upload_result?;
        sync_result?;
        self.initialized.set(true);
        self.ingest_state.publish(receipt);
        Ok(PreparedExecutionTablesIngestTelemetry {
            compact_h2d_bytes: compact_bytes,
            compact_h2d_copies: [
                requirements.n_addrs,
                requirements.n_big,
                requirements.n_small,
            ]
            .into_iter()
            .filter(|&len| len != 0)
            .count() as u64,
            descriptor_h2d_bytes: descriptor_bytes,
            descriptor_h2d_copies: if first_ingest { 2 } else { 0 },
            sync_calls: 1,
        })
    }

    /// Split compact values into the stable limb columns on the arena stream.
    /// No allocation, transfer, synchronization, or host-lifetime handoff occurs.
    pub fn launch(
        &self,
    ) -> Result<PreparedExecutionTablesLaunchTelemetry, PreparedExecutionTablesError> {
        self.launch_on(self.arena.context().launch_context())
    }

    pub fn launch_on(
        &self,
        launch: CudaLaunchContext,
    ) -> Result<PreparedExecutionTablesLaunchTelemetry, PreparedExecutionTablesError> {
        if !self.initialized.get() || self.ingest_state.receipt().is_none() {
            return Err(PreparedExecutionTablesError::NotIngested);
        }
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        let requirements = self.contract.requirements();
        let stream = launch.stream_raw().as_ptr();
        let big = unsafe {
            stwo_backend_cuda_kernels::raw::memory_limb_split_big_columns_on(
                self.raw_f252_words.as_u32_ptr(),
                requirements.n_big as u32,
                requirements.big_column_words as u32,
                self.big_output_pointers.as_ptr(),
                stream,
            )
        };
        check_cuda("memory_limb_split_big_columns_on", big)?;
        let small = unsafe {
            stwo_backend_cuda_kernels::raw::memory_limb_split_small_columns_on(
                self.raw_small_words.as_u32_ptr(),
                requirements.n_small as u32,
                requirements.small_column_words as u32,
                self.small_output_pointers.as_ptr(),
                stream,
            )
        };
        check_cuda("memory_limb_split_small_columns_on", small)?;
        Ok(PreparedExecutionTablesLaunchTelemetry::TWO_SPLITS)
    }

    pub fn view(&self) -> Result<PreparedExecutionTablesView<'a>, PreparedExecutionTablesError> {
        if !self.initialized.get() || self.ingest_state.receipt().is_none() {
            return Err(PreparedExecutionTablesError::NotIngested);
        }
        let table_data: [ArenaSlice; EXECUTION_TABLE_POINTERS] =
            core::iter::once(self.raw_addr_to_id)
                .chain(self.big_limbs.iter().copied())
                .chain(self.small_limbs.iter().copied())
                .collect::<Vec<_>>()
                .try_into()
                .expect("execution-table pointer geometry is fixed");
        let requirements = self.contract.requirements();
        Ok(PreparedExecutionTablesView {
            arena: self.arena,
            table_pointers: self.table_pointers,
            table_strides: self.table_strides,
            table_data,
            n_addrs: requirements.n_addrs,
            n_big: requirements.n_big,
            n_small: requirements.n_small,
        })
    }

    pub fn contract(&self) -> &ExecutionTablesContract {
        &self.contract
    }

    pub fn belongs_to(&self, arena: &DeviceArena) -> bool {
        core::ptr::eq(self.arena, arena)
            && std::iter::once(self.raw_addr_to_id)
                .chain([self.raw_f252_words, self.raw_small_words])
                .chain(self.big_limbs.iter().copied())
                .chain(self.small_limbs.iter().copied())
                .chain([self.table_pointers, self.table_strides])
                .all(|slice| slice.belongs_to(arena.context()))
    }

    pub fn raw_addr_to_id(&self) -> ArenaSlice {
        self.raw_addr_to_id
    }

    pub fn raw_f252_words(&self) -> ArenaSlice {
        self.raw_f252_words
    }

    pub fn raw_small_words(&self) -> ArenaSlice {
        self.raw_small_words
    }

    pub fn big_limbs(&self) -> &[ArenaSlice] {
        &self.big_limbs
    }

    pub fn small_limbs(&self) -> &[ArenaSlice] {
        &self.small_limbs
    }

    pub fn table_pointers(&self) -> ArenaSlice {
        self.table_pointers
    }

    pub fn table_strides(&self) -> ArenaSlice {
        self.table_strides
    }

    pub fn ingest_receipt(&self) -> Option<ExecutionTablesIngestReceipt> {
        self.ingest_state.receipt()
    }

    pub fn ingest_is_current(&self, receipt: &ExecutionTablesIngestReceipt) -> bool {
        let binding = ingest_receipt::ExecutionTablesIngestBinding::new(
            self.arena,
            &self.contract,
            self.raw_addr_to_id,
            self.raw_f252_words,
            self.raw_small_words,
        );
        self.ingest_state.is_current(receipt, binding)
    }

    pub fn requirements(&self) -> &ExecutionTablesWorkspaceRequirements {
        self.contract.requirements()
    }
}

fn bind_many(
    arena: &DeviceArena,
    ids: &[ArenaSlotId],
    required_words: usize,
) -> Result<Vec<ArenaSlice>, PreparedExecutionTablesError> {
    ids.iter()
        .map(|&id| bind_slot(arena, id, required_words, 1))
        .collect()
}

fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedExecutionTablesError> {
    let slice = arena.bind(id)?;
    if slice.len_words() < required_words {
        return Err(PreparedExecutionTablesError::SlotTooSmall {
            slot: id,
            required_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedExecutionTablesError::SlotMisaligned(id));
    }
    // Pooled slots may be larger than any single logical buffer; expose only
    // the logical extent so no consumer derives sizes from the pooled surplus.
    Ok(slice.truncated(required_words))
}

fn upload<T: Copy>(
    arena: &DeviceArena,
    destination: ArenaSlice,
    values: &[T],
) -> Result<(), PreparedExecutionTablesError> {
    let bytes = core::mem::size_of_val(values);
    if bytes == 0 {
        return Ok(());
    }
    if bytes > destination.len_bytes() {
        return Err(PreparedExecutionTablesError::SlotTooSmall {
            slot: destination.id(),
            required_words: bytes.div_ceil(WORD_BYTES),
            actual_words: destination.len_words(),
        });
    }
    unsafe {
        arena.context().memcpy_h2d_async(
            destination.as_void_ptr(),
            values.as_ptr().cast::<c_void>(),
            bytes,
        )?;
    }
    Ok(())
}

fn ensure_distinct(ids: &[ArenaSlotId]) -> Result<(), PreparedExecutionTablesError> {
    let mut seen = BTreeSet::new();
    for &id in ids {
        if !seen.insert(id) {
            return Err(PreparedExecutionTablesError::DuplicateSlot(id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
