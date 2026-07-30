//! Prepared fixed-table BaseTrace and LookupInputs materialization.
//!
//! Setup binds and uploads stable descriptor/pointer tables once.
//! [`PreparedFixedTableGraph::launch`] is exactly one explicit-stream kernel enqueue and performs
//! no allocation, transfer, synchronization, or default-stream work.

use core::ffi::c_void;
use std::collections::BTreeSet;

use super::exec_context::{
    ArenaError, ArenaSlice, ArenaSlotId, CudaLaunchContext, CudaRuntimeError, DeviceArena,
};
use super::pedersen_table::RegisteredPedersenColumn;

mod authority;

pub use authority::{
    FixedTableMaterializerAbi, FixedTableMaterializerAbiAccess, FixedTableMaterializerAbiArgument,
    FixedTableMaterializerAbiArgumentKind, FixedTableMaterializerAuthorityError,
    FixedTableMaterializerContract, FixedTableMaterializerKernelLaunch,
    FixedTableMaterializerLinkedContract,
};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);
const M31_MODULUS: u32 = (1 << 31) - 1;

pub const FIXED_TABLE_LOOKUP_DESCRIPTOR_WORDS: usize = 4;
pub const FIXED_TABLE_POINTER_ALIGNMENT_WORDS: usize =
    core::mem::align_of::<*mut u32>() / WORD_BYTES;

/// Immutable source for one fixed-table word column.
///
/// Most sources are arena-owned. Pedersen-18 is special: its already-registered
/// process-lifetime table is the sole evaluation owner, so resident graphs borrow
/// those columns instead of retaining a second 1.75-GiB arena copy.
#[derive(Clone, Copy, Debug)]
pub enum FixedTableSourceColumn {
    Arena(ArenaSlice),
    RegisteredPedersen(RegisteredPedersenColumn),
}

impl FixedTableSourceColumn {
    pub fn as_u32_ptr(self) -> *mut u32 {
        match self {
            Self::Arena(slice) => slice.as_u32_ptr(),
            Self::RegisteredPedersen(column) => column.as_u32_ptr(),
        }
    }

    pub fn len_words(self) -> usize {
        match self {
            Self::Arena(slice) => slice.len_words(),
            Self::RegisteredPedersen(column) => column.len_words(),
        }
    }

    pub fn arena_slot(self) -> Option<ArenaSlotId> {
        match self {
            Self::Arena(slice) => Some(slice.id()),
            Self::RegisteredPedersen(_) => None,
        }
    }

    pub const fn registered_pedersen_index(self) -> Option<usize> {
        match self {
            Self::Arena(_) => None,
            Self::RegisteredPedersen(column) => Some(column.index()),
        }
    }
}

impl From<ArenaSlice> for FixedTableSourceColumn {
    fn from(value: ArenaSlice) -> Self {
        Self::Arena(value)
    }
}

impl From<RegisteredPedersenColumn> for FixedTableSourceColumn {
    fn from(value: RegisteredPedersenColumn) -> Self {
        Self::RegisteredPedersen(value)
    }
}

/// One word-major LookupInputs source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedTableLookupSource {
    Constant(u32),
    SourceColumn(u32),
    MultiplicityColumn(u32),
    ExpandedXorA {
        multiplicity_column: u32,
        limb_bits: u32,
        expand_bits: u32,
    },
    ExpandedXorB {
        multiplicity_column: u32,
        limb_bits: u32,
        expand_bits: u32,
    },
    ExpandedXor {
        multiplicity_column: u32,
        limb_bits: u32,
        expand_bits: u32,
    },
}

impl FixedTableLookupSource {
    fn descriptor(self) -> [u32; FIXED_TABLE_LOOKUP_DESCRIPTOR_WORDS] {
        match self {
            Self::Constant(value) => [0, value, 0, 0],
            Self::SourceColumn(column) => [1, column, 0, 0],
            Self::MultiplicityColumn(column) => [2, column, 0, 0],
            Self::ExpandedXorA {
                multiplicity_column,
                limb_bits,
                expand_bits,
            } => [3, multiplicity_column, limb_bits, expand_bits],
            Self::ExpandedXorB {
                multiplicity_column,
                limb_bits,
                expand_bits,
            } => [4, multiplicity_column, limb_bits, expand_bits],
            Self::ExpandedXor {
                multiplicity_column,
                limb_bits,
                expand_bits,
            } => [5, multiplicity_column, limb_bits, expand_bits],
        }
    }
}

/// Pure launch semantics for one fixed-table component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedTableMaterializationConfig {
    pub row_count: usize,
    pub source_column_count: usize,
    /// For each BaseTrace output, the source multiplicity-column index.
    pub trace_multiplicity_columns: Vec<u32>,
    pub multiplicity_column_count: usize,
    /// One descriptor per flattened word-major LookupInputs output.
    pub lookup_sources: Vec<FixedTableLookupSource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedTableArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedTableWorkspaceRequirements {
    pub row_count: usize,
    pub source_column_count: usize,
    pub multiplicity_column_count: usize,
    pub trace_output_count: usize,
    pub lookup_output_count: usize,
    pub source_pointer_words: usize,
    pub multiplicity_pointer_words: usize,
    pub trace_mapping_words: usize,
    pub trace_pointer_words: usize,
    pub lookup_descriptor_words: usize,
    pub lookup_pointer_words: usize,
    trace_multiplicity_columns: Vec<u32>,
    lookup_descriptors: Vec<u32>,
}

/// Arena identities owned by one materializer. Source and multiplicity columns
/// are borrowed separately because they are produced elsewhere in the proof DAG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedTableWorkspaceSlots {
    /// Absent exactly when `source_column_count == 0`.
    pub source_pointers: Option<ArenaSlotId>,
    pub multiplicity_pointers: ArenaSlotId,
    pub trace_multiplicity_columns: ArenaSlotId,
    pub trace_outputs: Vec<ArenaSlotId>,
    pub trace_output_pointers: ArenaSlotId,
    pub lookup_descriptors: ArenaSlotId,
    pub lookup_outputs: Vec<ArenaSlotId>,
    pub lookup_output_pointers: ArenaSlotId,
}

/// Arena identities for the resident Cairo layout. Multiplicities and flattened
/// `LookupInputs` are each one contiguous word-major range; trace columns retain
/// their existing per-column arena identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedTableContiguousWorkspaceSlots {
    /// Absent exactly when `source_column_count == 0`.
    pub source_pointers: Option<ArenaSlotId>,
    pub multiplicity_pointers: ArenaSlotId,
    pub trace_multiplicity_columns: ArenaSlotId,
    pub trace_outputs: Vec<ArenaSlotId>,
    pub trace_output_pointers: ArenaSlotId,
    pub lookup_descriptors: ArenaSlotId,
    pub lookup_output: ArenaSlotId,
    pub lookup_output_pointers: ArenaSlotId,
}

impl FixedTableWorkspaceRequirements {
    pub fn trace_multiplicity_columns(&self) -> &[u32] {
        &self.trace_multiplicity_columns
    }

    pub fn lookup_descriptors(&self) -> &[u32] {
        &self.lookup_descriptors
    }

    pub fn arena_slot_requirements(
        &self,
        slots: &FixedTableWorkspaceSlots,
    ) -> Result<Vec<FixedTableArenaSlotRequirement>, PreparedFixedTableError> {
        require_count(
            "trace_outputs",
            self.trace_output_count,
            slots.trace_outputs.len(),
        )?;
        require_count(
            "lookup_outputs",
            self.lookup_output_count,
            slots.lookup_outputs.len(),
        )?;
        match (self.source_pointer_words, slots.source_pointers) {
            (0, None) => {}
            (0, Some(_)) => return Err(PreparedFixedTableError::UnexpectedSourcePointerSlot),
            (_, None) => return Err(PreparedFixedTableError::MissingSourcePointerSlot),
            (_, Some(_)) => {}
        }

        let mut result = Vec::with_capacity(
            6 + usize::from(slots.source_pointers.is_some())
                + slots.trace_outputs.len()
                + slots.lookup_outputs.len(),
        );
        if let Some(id) = slots.source_pointers {
            result.push(pointers(id, self.source_pointer_words));
        }
        result.extend([
            pointers(slots.multiplicity_pointers, self.multiplicity_pointer_words),
            words(slots.trace_multiplicity_columns, self.trace_mapping_words),
            pointers(slots.trace_output_pointers, self.trace_pointer_words),
            words(slots.lookup_descriptors, self.lookup_descriptor_words),
            pointers(slots.lookup_output_pointers, self.lookup_pointer_words),
        ]);
        result.extend(
            slots
                .trace_outputs
                .iter()
                .map(|&id| words(id, self.row_count)),
        );
        result.extend(
            slots
                .lookup_outputs
                .iter()
                .map(|&id| words(id, self.row_count)),
        );
        ensure_distinct(result.iter().map(|requirement| requirement.id))?;
        Ok(result)
    }

    pub fn arena_slot_requirements_contiguous(
        &self,
        slots: &FixedTableContiguousWorkspaceSlots,
    ) -> Result<Vec<FixedTableArenaSlotRequirement>, PreparedFixedTableError> {
        require_count(
            "trace_outputs",
            self.trace_output_count,
            slots.trace_outputs.len(),
        )?;
        match (self.source_pointer_words, slots.source_pointers) {
            (0, None) => {}
            (0, Some(_)) => return Err(PreparedFixedTableError::UnexpectedSourcePointerSlot),
            (_, None) => return Err(PreparedFixedTableError::MissingSourcePointerSlot),
            (_, Some(_)) => {}
        }
        let lookup_words = self
            .row_count
            .checked_mul(self.lookup_output_count)
            .ok_or(PreparedFixedTableError::LaunchGeometryOverflow)?;
        let mut result = Vec::with_capacity(
            6 + usize::from(slots.source_pointers.is_some()) + slots.trace_outputs.len(),
        );
        if let Some(id) = slots.source_pointers {
            result.push(pointers(id, self.source_pointer_words));
        }
        result.extend([
            pointers(slots.multiplicity_pointers, self.multiplicity_pointer_words),
            words(slots.trace_multiplicity_columns, self.trace_mapping_words),
            pointers(slots.trace_output_pointers, self.trace_pointer_words),
            words(slots.lookup_descriptors, self.lookup_descriptor_words),
            words(slots.lookup_output, lookup_words),
            pointers(slots.lookup_output_pointers, self.lookup_pointer_words),
        ]);
        result.extend(
            slots
                .trace_outputs
                .iter()
                .map(|&id| words(id, self.row_count)),
        );
        ensure_distinct(result.iter().map(|requirement| requirement.id))?;
        Ok(result)
    }
}

fn words(id: ArenaSlotId, len_words: usize) -> FixedTableArenaSlotRequirement {
    FixedTableArenaSlotRequirement {
        id,
        len_words,
        alignment_words: 1,
    }
}

fn pointers(id: ArenaSlotId, len_words: usize) -> FixedTableArenaSlotRequirement {
    FixedTableArenaSlotRequirement {
        id,
        len_words,
        alignment_words: FIXED_TABLE_POINTER_ALIGNMENT_WORDS,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedFixedTableError {
    CudaUnavailable,
    ZeroRows,
    RowCountOverflow,
    NoMultiplicities,
    MultiplicityCountOverflow,
    SourceCountOverflow,
    NoTraceOutputs,
    TraceCountOverflow,
    NoLookupOutputs,
    LookupCountOverflow,
    LaunchGeometryOverflow,
    InvalidConstant {
        word: usize,
        value: u32,
    },
    SourceIndexOutOfRange {
        word: usize,
        index: u32,
        count: usize,
    },
    MultiplicityIndexOutOfRange {
        output: &'static str,
        index: usize,
        column: u32,
        count: usize,
    },
    InvalidExpandedXorGeometry {
        word: usize,
        limb_bits: u32,
        expand_bits: u32,
    },
    CountMismatch {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    MissingSourcePointerSlot,
    UnexpectedSourcePointerSlot,
    DuplicateSlot(ArenaSlotId),
    DuplicateSourcePointer(usize),
    InputAliasesWorkspace(ArenaSlotId),
    SourceSizeMismatch {
        source: usize,
        expected_words: usize,
        actual_words: usize,
    },
    SlotSizeMismatch {
        slot: ArenaSlotId,
        expected_words: usize,
        actual_words: usize,
    },
    SlotMisaligned(ArenaSlotId),
    ContextMismatch(ArenaSlotId),
    KernelLaunchFailed,
    InvalidAuthority,
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedFixedTableError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "prepared fixed table rejected: {self:?}")
    }
}

impl std::error::Error for PreparedFixedTableError {}

impl From<ArenaError> for PreparedFixedTableError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedFixedTableError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

pub fn fixed_table_workspace_requirements(
    config: &FixedTableMaterializationConfig,
) -> Result<FixedTableWorkspaceRequirements, PreparedFixedTableError> {
    if config.row_count == 0 {
        return Err(PreparedFixedTableError::ZeroRows);
    }
    u32::try_from(config.row_count).map_err(|_| PreparedFixedTableError::RowCountOverflow)?;
    if config.multiplicity_column_count == 0 {
        return Err(PreparedFixedTableError::NoMultiplicities);
    }
    u32::try_from(config.multiplicity_column_count)
        .map_err(|_| PreparedFixedTableError::MultiplicityCountOverflow)?;
    u32::try_from(config.source_column_count)
        .map_err(|_| PreparedFixedTableError::SourceCountOverflow)?;
    if config.trace_multiplicity_columns.is_empty() {
        return Err(PreparedFixedTableError::NoTraceOutputs);
    }
    u32::try_from(config.trace_multiplicity_columns.len())
        .map_err(|_| PreparedFixedTableError::TraceCountOverflow)?;
    if config.lookup_sources.is_empty() {
        return Err(PreparedFixedTableError::NoLookupOutputs);
    }
    u32::try_from(config.lookup_sources.len())
        .map_err(|_| PreparedFixedTableError::LookupCountOverflow)?;
    let output_count = config
        .trace_multiplicity_columns
        .len()
        .checked_add(config.lookup_sources.len())
        .and_then(|outputs| u32::try_from(outputs).ok())
        .ok_or(PreparedFixedTableError::LaunchGeometryOverflow)?;
    if output_count > u16::MAX.into() {
        return Err(PreparedFixedTableError::LaunchGeometryOverflow);
    }

    for (index, &column) in config.trace_multiplicity_columns.iter().enumerate() {
        if column as usize >= config.multiplicity_column_count {
            return Err(PreparedFixedTableError::MultiplicityIndexOutOfRange {
                output: "trace",
                index,
                column,
                count: config.multiplicity_column_count,
            });
        }
    }
    let mut lookup_descriptors =
        Vec::with_capacity(config.lookup_sources.len() * FIXED_TABLE_LOOKUP_DESCRIPTOR_WORDS);
    for (word, source) in config.lookup_sources.iter().copied().enumerate() {
        match source {
            FixedTableLookupSource::Constant(value) if value >= M31_MODULUS => {
                return Err(PreparedFixedTableError::InvalidConstant { word, value });
            }
            FixedTableLookupSource::SourceColumn(index)
                if index as usize >= config.source_column_count =>
            {
                return Err(PreparedFixedTableError::SourceIndexOutOfRange {
                    word,
                    index,
                    count: config.source_column_count,
                });
            }
            FixedTableLookupSource::MultiplicityColumn(column)
                if column as usize >= config.multiplicity_column_count =>
            {
                return Err(PreparedFixedTableError::MultiplicityIndexOutOfRange {
                    output: "lookup",
                    index: word,
                    column,
                    count: config.multiplicity_column_count,
                });
            }
            FixedTableLookupSource::ExpandedXorA {
                multiplicity_column,
                limb_bits,
                expand_bits,
            }
            | FixedTableLookupSource::ExpandedXorB {
                multiplicity_column,
                limb_bits,
                expand_bits,
            }
            | FixedTableLookupSource::ExpandedXor {
                multiplicity_column,
                limb_bits,
                expand_bits,
            } => {
                if multiplicity_column as usize >= config.multiplicity_column_count {
                    return Err(PreparedFixedTableError::MultiplicityIndexOutOfRange {
                        output: "expanded xor",
                        index: word,
                        column: multiplicity_column,
                        count: config.multiplicity_column_count,
                    });
                }
                let rows = limb_bits
                    .checked_mul(2)
                    .and_then(|bits| 1usize.checked_shl(bits));
                let columns = expand_bits
                    .checked_mul(2)
                    .and_then(|bits| 1usize.checked_shl(bits));
                if limb_bits == 0
                    || expand_bits == 0
                    || rows != Some(config.row_count)
                    || columns != Some(config.multiplicity_column_count)
                {
                    return Err(PreparedFixedTableError::InvalidExpandedXorGeometry {
                        word,
                        limb_bits,
                        expand_bits,
                    });
                }
            }
            FixedTableLookupSource::Constant(_)
            | FixedTableLookupSource::SourceColumn(_)
            | FixedTableLookupSource::MultiplicityColumn(_) => {}
        }
        lookup_descriptors.extend(source.descriptor());
    }

    let trace_output_count = config.trace_multiplicity_columns.len();
    let lookup_output_count = config.lookup_sources.len();
    Ok(FixedTableWorkspaceRequirements {
        row_count: config.row_count,
        source_column_count: config.source_column_count,
        multiplicity_column_count: config.multiplicity_column_count,
        trace_output_count,
        lookup_output_count,
        source_pointer_words: pointer_words(config.source_column_count)?,
        multiplicity_pointer_words: pointer_words(config.multiplicity_column_count)?,
        trace_mapping_words: trace_output_count,
        trace_pointer_words: pointer_words(trace_output_count)?,
        lookup_descriptor_words: lookup_descriptors.len(),
        lookup_pointer_words: pointer_words(lookup_output_count)?,
        trace_multiplicity_columns: config.trace_multiplicity_columns.clone(),
        lookup_descriptors,
    })
}

fn pointer_words(count: usize) -> Result<usize, PreparedFixedTableError> {
    count
        .checked_mul(POINTER_WORDS)
        .ok_or(PreparedFixedTableError::LaunchGeometryOverflow)
}

pub struct PreparedFixedTableGraph<'a> {
    arena: &'a DeviceArena,
    contract: FixedTableMaterializerContract,
    requirements: FixedTableWorkspaceRequirements,
    source_columns: Vec<FixedTableSourceColumn>,
    multiplicity_columns: Vec<ArenaSlice>,
    multiplicity_slab: Option<ArenaSlice>,
    source_pointers: Option<ArenaSlice>,
    multiplicity_pointers: ArenaSlice,
    trace_multiplicity_columns: ArenaSlice,
    trace_outputs: Vec<ArenaSlice>,
    trace_output_pointers: ArenaSlice,
    lookup_descriptors: ArenaSlice,
    lookup_outputs: Vec<ArenaSlice>,
    lookup_output_slab: Option<ArenaSlice>,
    lookup_output_pointers: ArenaSlice,
}

impl<'a> PreparedFixedTableGraph<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        arena: &'a DeviceArena,
        config: &FixedTableMaterializationConfig,
        source_columns: &[FixedTableSourceColumn],
        multiplicity_columns: &[ArenaSlice],
        slots: &FixedTableWorkspaceSlots,
    ) -> Result<Self, PreparedFixedTableError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedFixedTableError::CudaUnavailable);
        }
        let contract = FixedTableMaterializerContract::compile(config)
            .map_err(|_| PreparedFixedTableError::InvalidAuthority)?;
        let requirements = contract.requirements().clone();
        requirements.arena_slot_requirements(slots)?;
        require_count(
            "source_columns",
            requirements.source_column_count,
            source_columns.len(),
        )?;
        require_count(
            "multiplicity_columns",
            requirements.multiplicity_column_count,
            multiplicity_columns.len(),
        )?;
        validate_source_inputs(arena, source_columns, requirements.row_count)?;
        validate_inputs(arena, multiplicity_columns, requirements.row_count)?;

        let source_pointers = match slots.source_pointers {
            Some(id) => Some(bind_min(
                arena,
                id,
                requirements.source_pointer_words,
                FIXED_TABLE_POINTER_ALIGNMENT_WORDS,
            )?),
            None => None,
        };
        let multiplicity_pointers = bind_min(
            arena,
            slots.multiplicity_pointers,
            requirements.multiplicity_pointer_words,
            FIXED_TABLE_POINTER_ALIGNMENT_WORDS,
        )?;
        let trace_multiplicity_columns = bind_min(
            arena,
            slots.trace_multiplicity_columns,
            requirements.trace_mapping_words,
            1,
        )?;
        let trace_outputs =
            bind_many_exact(arena, &slots.trace_outputs, requirements.row_count, 1)?;
        let trace_output_pointers = bind_min(
            arena,
            slots.trace_output_pointers,
            requirements.trace_pointer_words,
            FIXED_TABLE_POINTER_ALIGNMENT_WORDS,
        )?;
        let lookup_descriptors = bind_min(
            arena,
            slots.lookup_descriptors,
            requirements.lookup_descriptor_words,
            1,
        )?;
        let lookup_outputs =
            bind_many_exact(arena, &slots.lookup_outputs, requirements.row_count, 1)?;
        let lookup_output_pointers = bind_min(
            arena,
            slots.lookup_output_pointers,
            requirements.lookup_pointer_words,
            FIXED_TABLE_POINTER_ALIGNMENT_WORDS,
        )?;

        let workspace_ids = source_pointers
            .iter()
            .map(|slice| slice.id())
            .chain([
                multiplicity_pointers.id(),
                trace_multiplicity_columns.id(),
                trace_output_pointers.id(),
                lookup_descriptors.id(),
                lookup_output_pointers.id(),
            ])
            .chain(trace_outputs.iter().map(|slice| slice.id()))
            .chain(lookup_outputs.iter().map(|slice| slice.id()))
            .collect::<BTreeSet<_>>();
        let mut input_ids = BTreeSet::new();
        let mut input_pointers = BTreeSet::new();
        for &input in source_columns {
            if !input_pointers.insert(input.as_u32_ptr() as usize) {
                return Err(PreparedFixedTableError::DuplicateSourcePointer(
                    input.as_u32_ptr() as usize,
                ));
            }
            if let Some(id) = input.arena_slot() {
                if !input_ids.insert(id) {
                    return Err(PreparedFixedTableError::DuplicateSlot(id));
                }
                if workspace_ids.contains(&id) {
                    return Err(PreparedFixedTableError::InputAliasesWorkspace(id));
                }
            }
        }
        for &input in multiplicity_columns {
            if !input_ids.insert(input.id()) {
                return Err(PreparedFixedTableError::DuplicateSlot(input.id()));
            }
            if workspace_ids.contains(&input.id()) {
                return Err(PreparedFixedTableError::InputAliasesWorkspace(input.id()));
            }
        }

        if let Some(destination) = source_pointers {
            upload(arena, destination, &source_pointer_values(source_columns))?;
        }
        upload(
            arena,
            multiplicity_pointers,
            &pointer_values(multiplicity_columns),
        )?;
        upload(
            arena,
            trace_multiplicity_columns,
            requirements.trace_multiplicity_columns(),
        )?;
        upload(
            arena,
            trace_output_pointers,
            &pointer_values(&trace_outputs),
        )?;
        upload(arena, lookup_descriptors, requirements.lookup_descriptors())?;
        upload(
            arena,
            lookup_output_pointers,
            &pointer_values(&lookup_outputs),
        )?;
        arena.context().sync()?;

        Ok(Self {
            arena,
            contract,
            requirements,
            source_columns: source_columns.to_vec(),
            multiplicity_columns: multiplicity_columns.to_vec(),
            multiplicity_slab: None,
            source_pointers,
            multiplicity_pointers,
            trace_multiplicity_columns,
            trace_outputs,
            trace_output_pointers,
            lookup_descriptors,
            lookup_outputs,
            lookup_output_slab: None,
            lookup_output_pointers,
        })
    }

    /// Bind the Cairo resident layout without splitting its multiplicity or
    /// flattened `LookupInputs` ranges into hundreds of synthetic arena slots.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_contiguous(
        arena: &'a DeviceArena,
        config: &FixedTableMaterializationConfig,
        source_columns: &[FixedTableSourceColumn],
        multiplicity_slab: ArenaSlice,
        slots: &FixedTableContiguousWorkspaceSlots,
    ) -> Result<Self, PreparedFixedTableError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedFixedTableError::CudaUnavailable);
        }
        let contract = FixedTableMaterializerContract::compile(config)
            .map_err(|_| PreparedFixedTableError::InvalidAuthority)?;
        let requirements = contract.requirements().clone();
        requirements.arena_slot_requirements_contiguous(slots)?;
        require_count(
            "source_columns",
            requirements.source_column_count,
            source_columns.len(),
        )?;
        validate_source_inputs(arena, source_columns, requirements.row_count)?;
        require_context(arena, multiplicity_slab)?;
        let multiplicity_words = requirements
            .row_count
            .checked_mul(requirements.multiplicity_column_count)
            .ok_or(PreparedFixedTableError::LaunchGeometryOverflow)?;
        if multiplicity_slab.len_words() < multiplicity_words {
            return Err(PreparedFixedTableError::SlotSizeMismatch {
                slot: multiplicity_slab.id(),
                expected_words: multiplicity_words,
                actual_words: multiplicity_slab.len_words(),
            });
        }

        let source_pointers = match slots.source_pointers {
            Some(id) => Some(bind_min(
                arena,
                id,
                requirements.source_pointer_words,
                FIXED_TABLE_POINTER_ALIGNMENT_WORDS,
            )?),
            None => None,
        };
        let multiplicity_pointers = bind_min(
            arena,
            slots.multiplicity_pointers,
            requirements.multiplicity_pointer_words,
            FIXED_TABLE_POINTER_ALIGNMENT_WORDS,
        )?;
        let trace_multiplicity_columns = bind_min(
            arena,
            slots.trace_multiplicity_columns,
            requirements.trace_mapping_words,
            1,
        )?;
        let trace_outputs =
            bind_many_exact(arena, &slots.trace_outputs, requirements.row_count, 1)?;
        let trace_output_pointers = bind_min(
            arena,
            slots.trace_output_pointers,
            requirements.trace_pointer_words,
            FIXED_TABLE_POINTER_ALIGNMENT_WORDS,
        )?;
        let lookup_descriptors = bind_min(
            arena,
            slots.lookup_descriptors,
            requirements.lookup_descriptor_words,
            1,
        )?;
        let lookup_words = requirements
            .row_count
            .checked_mul(requirements.lookup_output_count)
            .ok_or(PreparedFixedTableError::LaunchGeometryOverflow)?;
        let lookup_output_slab = bind_min(arena, slots.lookup_output, lookup_words, 1)?;
        let lookup_output_pointers = bind_min(
            arena,
            slots.lookup_output_pointers,
            requirements.lookup_pointer_words,
            FIXED_TABLE_POINTER_ALIGNMENT_WORDS,
        )?;

        let workspace_ids = source_pointers
            .iter()
            .map(|slice| slice.id())
            .chain([
                multiplicity_pointers.id(),
                trace_multiplicity_columns.id(),
                trace_output_pointers.id(),
                lookup_descriptors.id(),
                lookup_output_slab.id(),
                lookup_output_pointers.id(),
            ])
            .chain(trace_outputs.iter().map(|slice| slice.id()))
            .collect::<BTreeSet<_>>();
        let mut input_ids = BTreeSet::new();
        let mut input_pointers = BTreeSet::new();
        for &input in source_columns {
            if !input_pointers.insert(input.as_u32_ptr() as usize) {
                return Err(PreparedFixedTableError::DuplicateSourcePointer(
                    input.as_u32_ptr() as usize,
                ));
            }
            if let Some(id) = input.arena_slot() {
                if !input_ids.insert(id) {
                    return Err(PreparedFixedTableError::DuplicateSlot(id));
                }
                if workspace_ids.contains(&id) {
                    return Err(PreparedFixedTableError::InputAliasesWorkspace(id));
                }
            }
        }
        if !input_ids.insert(multiplicity_slab.id()) {
            return Err(PreparedFixedTableError::DuplicateSlot(
                multiplicity_slab.id(),
            ));
        }
        if workspace_ids.contains(&multiplicity_slab.id()) {
            return Err(PreparedFixedTableError::InputAliasesWorkspace(
                multiplicity_slab.id(),
            ));
        }

        if let Some(destination) = source_pointers {
            upload(arena, destination, &source_pointer_values(source_columns))?;
        }
        upload(
            arena,
            multiplicity_pointers,
            &contiguous_pointer_values(
                multiplicity_slab,
                requirements.multiplicity_column_count,
                requirements.row_count,
            ),
        )?;
        upload(
            arena,
            trace_multiplicity_columns,
            requirements.trace_multiplicity_columns(),
        )?;
        upload(
            arena,
            trace_output_pointers,
            &pointer_values(&trace_outputs),
        )?;
        upload(arena, lookup_descriptors, requirements.lookup_descriptors())?;
        upload(
            arena,
            lookup_output_pointers,
            &contiguous_pointer_values(
                lookup_output_slab,
                requirements.lookup_output_count,
                requirements.row_count,
            ),
        )?;
        arena.context().sync()?;

        Ok(Self {
            arena,
            contract,
            requirements,
            source_columns: source_columns.to_vec(),
            multiplicity_columns: Vec::new(),
            multiplicity_slab: Some(multiplicity_slab),
            source_pointers,
            multiplicity_pointers,
            trace_multiplicity_columns,
            trace_outputs,
            trace_output_pointers,
            lookup_descriptors,
            lookup_outputs: Vec::new(),
            lookup_output_slab: Some(lookup_output_slab),
            lookup_output_pointers,
        })
    }

    /// Enqueue one allocation/copy/sync-free materialization kernel.
    pub fn launch(&self) -> Result<(), PreparedFixedTableError> {
        self.launch_on(self.arena.context().launch_context())
    }

    pub fn launch_on(&self, launch: CudaLaunchContext) -> Result<(), PreparedFixedTableError> {
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        let source_pointers = self
            .source_pointers
            .map_or(core::ptr::null_mut(), |slice| slice.as_u32_ptr().cast());
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_fixed_table_materialize_on(
                source_pointers,
                self.multiplicity_pointers.as_u32_ptr().cast(),
                self.trace_multiplicity_columns.as_u32_ptr().cast_const(),
                self.trace_output_pointers.as_u32_ptr().cast(),
                self.requirements.trace_output_count as u32,
                self.lookup_descriptors.as_u32_ptr().cast_const(),
                self.lookup_output_pointers.as_u32_ptr().cast(),
                self.requirements.lookup_output_count as u32,
                self.requirements.row_count as u32,
                launch.stream_raw().as_ptr(),
            )
        };
        if code == 0 {
            Ok(())
        } else {
            Err(PreparedFixedTableError::KernelLaunchFailed)
        }
    }

    pub fn requirements(&self) -> &FixedTableWorkspaceRequirements {
        &self.requirements
    }

    pub fn contract(&self) -> &FixedTableMaterializerContract {
        &self.contract
    }

    pub fn belongs_to(&self, arena: &DeviceArena) -> bool {
        core::ptr::eq(self.arena, arena)
    }

    pub fn source_columns(&self) -> &[FixedTableSourceColumn] {
        &self.source_columns
    }

    pub fn multiplicity_columns(&self) -> &[ArenaSlice] {
        &self.multiplicity_columns
    }

    pub fn multiplicity_slab(&self) -> Option<ArenaSlice> {
        self.multiplicity_slab
    }

    pub fn source_pointers(&self) -> Option<ArenaSlice> {
        self.source_pointers
    }

    pub fn multiplicity_pointers(&self) -> ArenaSlice {
        self.multiplicity_pointers
    }

    pub fn trace_multiplicity_columns(&self) -> ArenaSlice {
        self.trace_multiplicity_columns
    }

    pub fn trace_outputs(&self) -> &[ArenaSlice] {
        &self.trace_outputs
    }

    pub fn trace_output_pointers(&self) -> ArenaSlice {
        self.trace_output_pointers
    }

    pub fn lookup_descriptors(&self) -> ArenaSlice {
        self.lookup_descriptors
    }

    pub fn lookup_outputs(&self) -> &[ArenaSlice] {
        &self.lookup_outputs
    }

    pub fn lookup_output_slab(&self) -> Option<ArenaSlice> {
        self.lookup_output_slab
    }

    pub fn lookup_output_pointers(&self) -> ArenaSlice {
        self.lookup_output_pointers
    }
}

fn validate_inputs(
    arena: &DeviceArena,
    columns: &[ArenaSlice],
    row_count: usize,
) -> Result<(), PreparedFixedTableError> {
    for &column in columns {
        require_context(arena, column)?;
        if column.len_words() != row_count {
            return Err(PreparedFixedTableError::SlotSizeMismatch {
                slot: column.id(),
                expected_words: row_count,
                actual_words: column.len_words(),
            });
        }
    }
    Ok(())
}

fn validate_source_inputs(
    arena: &DeviceArena,
    columns: &[FixedTableSourceColumn],
    row_count: usize,
) -> Result<(), PreparedFixedTableError> {
    for (source, &column) in columns.iter().enumerate() {
        if let FixedTableSourceColumn::Arena(slice) = column {
            require_context(arena, slice)?;
        }
        if column.len_words() != row_count {
            return Err(PreparedFixedTableError::SourceSizeMismatch {
                source,
                expected_words: row_count,
                actual_words: column.len_words(),
            });
        }
    }
    Ok(())
}

fn pointer_values(slices: &[ArenaSlice]) -> Vec<usize> {
    slices
        .iter()
        .map(|slice| slice.as_u32_ptr() as usize)
        .collect()
}

fn source_pointer_values(slices: &[FixedTableSourceColumn]) -> Vec<usize> {
    slices
        .iter()
        .map(|slice| slice.as_u32_ptr() as usize)
        .collect()
}

fn contiguous_pointer_values(slab: ArenaSlice, count: usize, stride_words: usize) -> Vec<usize> {
    (0..count)
        .map(|index| unsafe { slab.as_u32_ptr().add(index * stride_words) as usize })
        .collect()
}

fn upload<T: Copy>(
    arena: &DeviceArena,
    destination: ArenaSlice,
    values: &[T],
) -> Result<(), PreparedFixedTableError> {
    let bytes = core::mem::size_of_val(values);
    if bytes > destination.len_bytes() {
        return Err(PreparedFixedTableError::SlotSizeMismatch {
            slot: destination.id(),
            expected_words: bytes.div_ceil(WORD_BYTES),
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

fn bind_many_exact(
    arena: &DeviceArena,
    ids: &[ArenaSlotId],
    expected_words: usize,
    alignment_words: usize,
) -> Result<Vec<ArenaSlice>, PreparedFixedTableError> {
    ids.iter()
        .map(|&id| bind_min(arena, id, expected_words, alignment_words))
        .collect()
}

// Pooled arena slots are sized to the largest disjoint-lifetime sharer, so a
// requirement is a lower bound on physical capacity. The returned slice is
// truncated to exactly `expected_words`, making `len_words()` the logical
// requirement everywhere downstream (same contract as
// prepared_witness_input's bind_min; undersized, misaligned, or
// foreign-context slots still fail closed).
fn bind_min(
    arena: &DeviceArena,
    id: ArenaSlotId,
    expected_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedFixedTableError> {
    let slice = arena.bind(id)?;
    require_context(arena, slice)?;
    truncate_bound_slot(slice, expected_words, alignment_words)
}

/// Validate one bound slot's capacity and alignment, then truncate it to the
/// logical requirement so `len_words()` never exposes the pooled surplus.
fn truncate_bound_slot(
    slice: ArenaSlice,
    expected_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedFixedTableError> {
    if slice.len_words() < expected_words {
        return Err(PreparedFixedTableError::SlotSizeMismatch {
            slot: slice.id(),
            expected_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedFixedTableError::SlotMisaligned(slice.id()));
    }
    Ok(slice.truncated(expected_words))
}

fn require_context(arena: &DeviceArena, slice: ArenaSlice) -> Result<(), PreparedFixedTableError> {
    if slice.context_token() == arena.context().identity_token() {
        Ok(())
    } else {
        Err(PreparedFixedTableError::ContextMismatch(slice.id()))
    }
}

fn require_count(
    field: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), PreparedFixedTableError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PreparedFixedTableError::CountMismatch {
            field,
            expected,
            actual,
        })
    }
}

fn ensure_distinct(
    ids: impl IntoIterator<Item = ArenaSlotId>,
) -> Result<(), PreparedFixedTableError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(PreparedFixedTableError::DuplicateSlot(id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRAPPER_SOURCE: &str =
        include_str!("../../../backend-cuda-kernels/cuda/fixed_table_materializer.cu");

    fn mutate_materializer_entry(old: &str, new: &str) -> String {
        let entry = WRAPPER_SOURCE
            .find("extern \"C\" int stwo_fixed_table_materialize_on")
            .unwrap();
        let relative = WRAPPER_SOURCE[entry..].find(old).unwrap();
        let start = entry + relative;
        let mut mutation = WRAPPER_SOURCE.to_owned();
        mutation.replace_range(start..start + old.len(), new);
        mutation
    }

    fn materializer_entry_header() -> &'static str {
        let start = WRAPPER_SOURCE
            .find("extern \"C\" int stwo_fixed_table_materialize_on")
            .unwrap();
        let end = start + WRAPPER_SOURCE[start..].find('{').unwrap();
        &WRAPPER_SOURCE[start..end]
    }

    #[test]
    fn materializer_authority_requires_the_exact_wrapper_entry_abi() {
        let abi = FixedTableMaterializerAbi::MaterializeV1;
        assert!(abi.source_declares_entry(WRAPPER_SOURCE.as_bytes()));

        let mutations = [
            mutate_materializer_entry(
                "extern \"C\" int stwo_fixed_table_materialize_on",
                "extern \"C\" void stwo_fixed_table_materialize_on",
            ),
            mutate_materializer_entry(
                "const uint32_t *const *source_columns_dev",
                "uint32_t *const *source_columns_dev",
            ),
            mutate_materializer_entry(
                "const uint32_t *const *multiplicity_columns_dev",
                "const uint32_t *const *wrong_multiplicity_columns_dev",
            ),
            mutate_materializer_entry(
                "const uint32_t *trace_multiplicity_columns_dev",
                "const uint32_t **trace_multiplicity_columns_dev",
            ),
            mutate_materializer_entry(
                "uint32_t *const *trace_outputs_dev",
                "const uint32_t *const *trace_outputs_dev",
            ),
            mutate_materializer_entry("uint32_t n_trace_outputs", "size_t n_trace_outputs"),
            mutate_materializer_entry(
                "const uint32_t *lookup_descriptors_dev",
                "uint32_t *lookup_descriptors_dev",
            ),
            mutate_materializer_entry(
                "uint32_t *const *lookup_outputs_dev",
                "uint32_t **lookup_outputs_dev",
            ),
            mutate_materializer_entry(
                "uint32_t n_lookup_outputs",
                "uint64_t n_lookup_outputs",
            ),
            mutate_materializer_entry("uint32_t row_count", "uint32_t rows"),
            mutate_materializer_entry("void *stream", "cudaStream_t stream"),
            mutate_materializer_entry(
                "const uint32_t *const *source_columns_dev,\n    const uint32_t *const *multiplicity_columns_dev",
                "const uint32_t *const *multiplicity_columns_dev,\n    const uint32_t *const *source_columns_dev",
            ),
        ];
        for (ordinal, mutation) in mutations.iter().enumerate() {
            assert!(
                !abi.source_declares_entry(mutation.as_bytes()),
                "accepted fixed-table ABI mutation {ordinal}"
            );
        }

        let header = materializer_entry_header();
        let mutated_definition =
            mutate_materializer_entry("uint32_t row_count", "uint32_t wrong_row_count");
        let comment_decoy = format!("/* {header} */\n{mutated_definition}");
        assert!(!abi.source_declares_entry(comment_decoy.as_bytes()));

        let escaped_header = header
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        let string_decoy =
            format!("const char *decoy = \"{escaped_header}\";\n{mutated_definition}");
        assert!(!abi.source_declares_entry(string_decoy.as_bytes()));

        let prototype_decoy = format!("{header};\n{mutated_definition}");
        assert!(!abi.source_declares_entry(prototype_decoy.as_bytes()));

        let exact_prototype = format!("{header};");
        assert!(!abi.source_declares_entry(exact_prototype.as_bytes()));

        let duplicate_declaration = format!("{header};\n{WRAPPER_SOURCE}");
        assert!(!abi.source_declares_entry(duplicate_declaration.as_bytes()));

        let duplicate_definition = format!("{WRAPPER_SOURCE}\n{header} {{ return 0; }}");
        assert!(!abi.source_declares_entry(duplicate_definition.as_bytes()));
    }

    #[test]
    fn bound_slots_truncate_pooled_surplus_to_the_logical_requirement() {
        // Pooled physical slots are sized to the LARGEST epoch-disjoint
        // sharer; the binder must expose only the logical extent so kernel
        // extents derived from `len_words()` never see the surplus.
        let oversized = ArenaSlice::dangling_for_test(4, 768);
        let bound = truncate_bound_slot(oversized, 256, 1).unwrap();
        assert_eq!(bound.len_words(), 256);
        assert_eq!(bound.id(), oversized.id());
        assert_eq!(bound.as_u32_ptr(), oversized.as_u32_ptr());
        // Undersized slots still fail closed.
        assert!(matches!(
            truncate_bound_slot(ArenaSlice::dangling_for_test(4, 128), 256, 1),
            Err(PreparedFixedTableError::SlotSizeMismatch { .. })
        ));
    }

    #[test]
    fn requirements_lower_all_source_kinds_to_the_stable_abi() {
        let config = FixedTableMaterializationConfig {
            row_count: 16,
            source_column_count: 1,
            trace_multiplicity_columns: vec![1, 0],
            multiplicity_column_count: 4,
            lookup_sources: vec![
                FixedTableLookupSource::Constant(7),
                FixedTableLookupSource::SourceColumn(0),
                FixedTableLookupSource::MultiplicityColumn(3),
                FixedTableLookupSource::ExpandedXorA {
                    multiplicity_column: 2,
                    limb_bits: 2,
                    expand_bits: 1,
                },
                FixedTableLookupSource::ExpandedXorB {
                    multiplicity_column: 2,
                    limb_bits: 2,
                    expand_bits: 1,
                },
                FixedTableLookupSource::ExpandedXor {
                    multiplicity_column: 2,
                    limb_bits: 2,
                    expand_bits: 1,
                },
            ],
        };
        let requirements = fixed_table_workspace_requirements(&config).unwrap();
        assert_eq!(requirements.trace_multiplicity_columns(), [1, 0]);
        assert_eq!(requirements.lookup_descriptors().len(), 6 * 4);
        assert_eq!(
            &requirements.lookup_descriptors()[..12],
            &[0, 7, 0, 0, 1, 0, 0, 0, 2, 3, 0, 0]
        );
        assert_eq!(
            &requirements.lookup_descriptors()[12..],
            &[3, 2, 2, 1, 4, 2, 2, 1, 5, 2, 2, 1]
        );
    }

    #[test]
    fn all_source_kind_authority_is_deterministic_sensitive_and_exact() {
        let config = FixedTableMaterializationConfig {
            row_count: 16,
            source_column_count: 1,
            trace_multiplicity_columns: vec![1, 0],
            multiplicity_column_count: 4,
            lookup_sources: vec![
                FixedTableLookupSource::Constant(7),
                FixedTableLookupSource::SourceColumn(0),
                FixedTableLookupSource::MultiplicityColumn(3),
                FixedTableLookupSource::ExpandedXorA {
                    multiplicity_column: 2,
                    limb_bits: 2,
                    expand_bits: 1,
                },
                FixedTableLookupSource::ExpandedXorB {
                    multiplicity_column: 2,
                    limb_bits: 2,
                    expand_bits: 1,
                },
                FixedTableLookupSource::ExpandedXor {
                    multiplicity_column: 2,
                    limb_bits: 2,
                    expand_bits: 1,
                },
            ],
        };
        let contract = FixedTableMaterializerContract::compile(&config).unwrap();
        let repeated = FixedTableMaterializerContract::compile(&config).unwrap();
        contract.validate().unwrap();
        repeated.validate().unwrap();
        assert_eq!(contract, repeated);

        let identities = [
            contract.source_identity(),
            contract.config_identity(),
            contract.abi_identity(),
            contract.effect_identity(),
            contract.launch_identity(),
            contract.identity(),
        ];
        assert!(identities.iter().all(|identity| *identity != [0; 32]));
        assert_eq!(identities.into_iter().collect::<BTreeSet<_>>().len(), 6);

        let arguments = contract.abi().arguments();
        assert_eq!(arguments.len(), 10);
        assert!(arguments
            .iter()
            .enumerate()
            .all(|(ordinal, argument)| argument.ordinal as usize == ordinal));
        assert_eq!(
            contract.launch(),
            FixedTableMaterializerKernelLaunch {
                grid: [1, 8, 1],
                block: [256, 1, 1],
                dynamic_shared_bytes: 0,
                cooperative: false,
                cluster: None,
            }
        );

        let mut changed_config = config;
        changed_config.lookup_sources[0] = FixedTableLookupSource::Constant(8);
        let changed = FixedTableMaterializerContract::compile(&changed_config).unwrap();
        changed.validate().unwrap();
        assert_eq!(contract.source_identity(), changed.source_identity());
        assert_eq!(contract.abi_identity(), changed.abi_identity());
        assert_eq!(contract.launch_identity(), changed.launch_identity());
        assert_ne!(contract.config_identity(), changed.config_identity());
        assert_ne!(contract.effect_identity(), changed.effect_identity());
        assert_ne!(contract.identity(), changed.identity());

        if stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            let target_sm = *stwo_backend_cuda_kernels::static_cuda_module_target_sms()
                .first()
                .expect("built static CUDA module must name a target SM");
            let linked = contract
                .bind_static_build(target_sm)
                .unwrap()
                .expect("built static CUDA module must bind");
            linked.validate(&contract).unwrap();
            assert_eq!(linked.contract_identity(), contract.identity());
            assert!(linked.validate(&changed).is_err());
        } else {
            assert_eq!(contract.bind_static_build(89).unwrap(), None);
        }
    }

    #[test]
    fn invalid_indices_and_xor_geometry_fail_closed() {
        let mut config = FixedTableMaterializationConfig {
            row_count: 8,
            source_column_count: 0,
            trace_multiplicity_columns: vec![0],
            multiplicity_column_count: 1,
            lookup_sources: vec![FixedTableLookupSource::SourceColumn(0)],
        };
        assert!(matches!(
            fixed_table_workspace_requirements(&config),
            Err(PreparedFixedTableError::SourceIndexOutOfRange { .. })
        ));
        config.lookup_sources = vec![FixedTableLookupSource::ExpandedXor {
            multiplicity_column: 0,
            limb_bits: 2,
            expand_bits: 1,
        }];
        assert!(matches!(
            fixed_table_workspace_requirements(&config),
            Err(PreparedFixedTableError::InvalidExpandedXorGeometry { .. })
        ));
    }

    #[test]
    fn contiguous_layout_keeps_flat_lookup_range_whole() {
        let config = FixedTableMaterializationConfig {
            row_count: 16,
            source_column_count: 0,
            trace_multiplicity_columns: vec![1, 0],
            multiplicity_column_count: 2,
            lookup_sources: vec![
                FixedTableLookupSource::MultiplicityColumn(0),
                FixedTableLookupSource::MultiplicityColumn(1),
            ],
        };
        let requirements = fixed_table_workspace_requirements(&config).unwrap();
        let slots = FixedTableContiguousWorkspaceSlots {
            source_pointers: None,
            multiplicity_pointers: ArenaSlotId(1),
            trace_multiplicity_columns: ArenaSlotId(2),
            trace_outputs: vec![ArenaSlotId(3), ArenaSlotId(4)],
            trace_output_pointers: ArenaSlotId(5),
            lookup_descriptors: ArenaSlotId(6),
            lookup_output: ArenaSlotId(7),
            lookup_output_pointers: ArenaSlotId(8),
        };
        let requests = requirements
            .arena_slot_requirements_contiguous(&slots)
            .unwrap();
        assert_eq!(
            requests
                .iter()
                .find(|request| request.id == slots.lookup_output)
                .unwrap()
                .len_words,
            32
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.len_words == 16)
                .count(),
            2,
            "only the existing BaseTrace columns remain split",
        );
    }
}
