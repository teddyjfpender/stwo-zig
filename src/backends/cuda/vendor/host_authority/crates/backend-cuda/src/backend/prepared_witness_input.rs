//! Prepared device edges from resident producer sub-inputs to consumer inputs.
//!
//! Canonical edge order determines contiguous destination row ranges. Setup
//! uploads the stable source/descriptors/output pointer ABI once; launch is one
//! explicit-stream kernel with no allocation, transfer, or synchronization.

use core::cell::Cell;
use core::ffi::c_void;
use std::collections::BTreeSet;

use super::exec_context::{
    ArenaError, ArenaSlice, ArenaSlotId, CudaLaunchContext, CudaRuntimeError, DeviceArena,
};

mod authority;
mod compact_authority;
mod seed_authority;
pub(crate) mod static_build;

pub use authority::{
    WitnessInputGatherAbi, WitnessInputGatherAbiAccess, WitnessInputGatherAbiArgument,
    WitnessInputGatherAbiArgumentKind, WitnessInputGatherAuthorityError,
    WitnessInputGatherContract, WitnessInputGatherDescriptorField, WitnessInputGatherEffectAbi,
    WitnessInputGatherEffectGeometry, WitnessInputGatherLinkedContract,
    WitnessInputGatherOutputEffect, WitnessInputGatherPackedEdgeEffect,
    WitnessInputGatherRowDomain, WitnessInputGatherWrapperLaunch,
    WITNESS_INPUT_GATHER_DESCRIPTOR_ORDER,
};
pub use compact_authority::{
    WitnessInputCompactAbi, WitnessInputCompactAbiAccess, WitnessInputCompactAbiArgument,
    WitnessInputCompactAbiArgumentKind, WitnessInputCompactAuthorityError,
    WitnessInputCompactContract, WitnessInputCompactCubStage, WitnessInputCompactEffectAbi,
    WitnessInputCompactEffectGeometry, WitnessInputCompactExecution, WitnessInputCompactFixedField,
    WitnessInputCompactIndexBuffer, WitnessInputCompactKernelLaunch,
    WitnessInputCompactKernelStage, WitnessInputCompactKeyBuffer,
    WitnessInputCompactLinkedContract, WitnessInputCompactOutputEffect,
    WitnessInputCompactRowDomain, WitnessInputCompactScratchEffect,
    WitnessInputCompactSourceEffect, WitnessInputCompactStage, WITNESS_INPUT_COMPACT_FIXED_ORDER,
};
pub use seed_authority::{
    WitnessInputSeedAbi, WitnessInputSeedAbiAccess, WitnessInputSeedAbiArgument,
    WitnessInputSeedAbiArgumentKind, WitnessInputSeedAuthorityError, WitnessInputSeedColumnEffect,
    WitnessInputSeedColumnValue, WitnessInputSeedContract, WitnessInputSeedEffectAbi,
    WitnessInputSeedEffectGeometry, WitnessInputSeedFixedField, WitnessInputSeedKernelLaunch,
    WitnessInputSeedLinkedContract, WitnessInputSeedRowDomain, WITNESS_INPUT_SEED_FIXED_ORDER,
};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);

pub const WITNESS_INPUT_GATHER_DESCRIPTOR_WORDS: usize = 5;
pub const WITNESS_INPUT_GATHER_PACKED_LANES: usize = 16;
pub const WITNESS_INPUT_GATHER_POINTER_ALIGNMENT_WORDS: usize =
    core::mem::align_of::<*mut u32>() / WORD_BYTES;
const WITNESS_INPUT_COMPACT_SORT_OVERHEAD_WORDS: usize = 4096;
const WITNESS_INPUT_COMPACT_SCAN_OVERHEAD_WORDS: usize = 1024;
const WITNESS_INPUT_COMPACT_NO_SLOT: u32 = u32::MAX;

type WitnessInputCompactTempBytesQuery = unsafe extern "C" fn(u32, *mut usize) -> i32;

fn checked_witness_input_compact_temp_bytes(
    query: WitnessInputCompactTempBytesQuery,
    rows: u32,
) -> Result<usize, i32> {
    let mut bytes = 0;
    let status = unsafe { query(rows, &mut bytes) };
    if status != 0 || bytes == 0 {
        Err(status)
    } else {
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherEdge {
    pub producer_rows: usize,
    pub word_base: usize,
    pub words_per_instance: usize,
    pub n_instances: usize,
}

/// Validated source range and derived destination row range for one edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherEdgePlan {
    pub edge: WitnessInputGatherEdge,
    pub destination_row_offset: usize,
    pub destination_rows: usize,
    pub required_source_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherRequirements {
    pub edges: Vec<WitnessInputGatherEdgePlan>,
    pub input_width: usize,
    pub total_real_rows: usize,
    pub consumer_rows: usize,
    pub include_enabler: bool,
    pub include_iota: bool,
    pub consumer_input_column_words: Vec<usize>,
    pub source_pointer_words: usize,
    pub descriptor_words: usize,
    pub output_pointer_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherSlots {
    pub source_pointers: ArenaSlotId,
    pub descriptors: ArenaSlotId,
    /// Existing input-column slots owned by the prepared consumer writer.
    pub consumer_input_columns: Vec<ArenaSlotId>,
    pub output_pointers: ArenaSlotId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputSeedRequirements {
    pub scalar_words: usize,
    pub n_real_rows: usize,
    pub consumer_rows: usize,
    pub include_enabler: bool,
    pub include_iota: bool,
    pub consumer_input_column_words: Vec<usize>,
    pub output_pointer_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputSeedSlots {
    pub scalar_values: ArenaSlotId,
    /// Existing input-column slots owned by the prepared consumer writer.
    pub consumer_input_columns: Vec<ArenaSlotId>,
    pub output_pointers: ArenaSlotId,
}

/// Recorder ABI for a canonical multiset consumer. Tuple words always occupy
/// the leading slots. The tail slots are explicit because generated writers
/// reserve enabler/iota before their multiplicity input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactLayout {
    pub tuple_words: usize,
    /// Prefix used by the host writer's canonical sort. A distinct suffix for
    /// the same key is rejected on device, eliminating DashMap-order drift.
    pub key_words: usize,
    pub consumer_input_count: usize,
    pub enabler_slot: Option<usize>,
    pub iota_slot: Option<usize>,
    pub multiplicity_slot: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactRequirements {
    pub edges: Vec<WitnessInputGatherEdgePlan>,
    pub layout: WitnessInputCompactLayout,
    pub total_input_rows: usize,
    pub sort_rows: usize,
    /// Exact padded row count already committed by the proof shape. Launch
    /// traps unless the device-born unique count pads to this extent.
    pub consumer_rows: usize,
    pub consumer_input_column_words: Vec<usize>,
    pub source_pointer_words: usize,
    pub descriptor_words: usize,
    pub output_pointer_words: usize,
    pub tuple_scratch_words: usize,
    pub sort_key_words: usize,
    pub sort_index_words: usize,
    pub run_words: usize,
    /// Conservative CUB capacity; prepare checks the exact native query.
    pub sort_temp_words: usize,
    /// Conservative CUB capacity; prepare checks the exact native query.
    pub scan_temp_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactSlots {
    pub source_pointers: ArenaSlotId,
    pub descriptors: ArenaSlotId,
    /// Existing stable recorder input-column slots.
    pub consumer_input_columns: Vec<ArenaSlotId>,
    pub output_pointers: ArenaSlotId,
    pub tuple_scratch: ArenaSlotId,
    pub sort_keys_a: ArenaSlotId,
    pub sort_keys_b: ArenaSlotId,
    pub sort_indices_a: ArenaSlotId,
    pub sort_indices_b: ArenaSlotId,
    pub run_heads: ArenaSlotId,
    pub run_positions: ArenaSlotId,
    pub n_unique: ArenaSlotId,
    pub sort_temp: ArenaSlotId,
    pub scan_temp: ArenaSlotId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

impl WitnessInputGatherRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &WitnessInputGatherSlots,
    ) -> Result<Vec<WitnessInputGatherArenaSlotRequirement>, PreparedWitnessInputGatherError> {
        if slots.consumer_input_columns.len() != self.consumer_input_column_words.len() {
            return Err(
                PreparedWitnessInputGatherError::ConsumerColumnCountMismatch {
                    expected: self.consumer_input_column_words.len(),
                    actual: slots.consumer_input_columns.len(),
                },
            );
        }
        let mut result = vec![
            pointer_requirement(slots.source_pointers, self.source_pointer_words),
            word_requirement(slots.descriptors, self.descriptor_words),
            pointer_requirement(slots.output_pointers, self.output_pointer_words),
        ];
        result.extend(
            slots
                .consumer_input_columns
                .iter()
                .zip(&self.consumer_input_column_words)
                .map(|(&id, &len_words)| word_requirement(id, len_words)),
        );
        ensure_distinct(result.iter().map(|entry| entry.id))?;
        Ok(result)
    }
}

fn word_requirement(id: ArenaSlotId, len_words: usize) -> WitnessInputGatherArenaSlotRequirement {
    WitnessInputGatherArenaSlotRequirement {
        id,
        len_words,
        alignment_words: 1,
    }
}

fn pointer_requirement(
    id: ArenaSlotId,
    len_words: usize,
) -> WitnessInputGatherArenaSlotRequirement {
    WitnessInputGatherArenaSlotRequirement {
        id,
        len_words,
        alignment_words: WITNESS_INPUT_GATHER_POINTER_ALIGNMENT_WORDS,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedWitnessInputGatherError {
    CudaUnavailable,
    NoEdges,
    ZeroProducerRows(usize),
    ProducerRowsNotPacked {
        edge: usize,
        rows: usize,
    },
    ProducerRowsOverflow(usize),
    ZeroInputWidth(usize),
    InputWidthOverflow(usize),
    WordBaseOverflow(usize),
    ZeroInstances(usize),
    InstanceCountOverflow(usize),
    InputWidthMismatch {
        edge: usize,
        expected: usize,
        actual: usize,
    },
    SizeOverflow,
    TotalRowsOverflow,
    SourceCountMismatch {
        expected: usize,
        actual: usize,
    },
    SourceRowsMismatch {
        edge: usize,
        source_words: usize,
        producer_rows: usize,
    },
    SourceTooSmall {
        edge: usize,
        required_words: usize,
        actual_words: usize,
    },
    ConsumerColumnCountMismatch {
        expected: usize,
        actual: usize,
    },
    DuplicateSlot(ArenaSlotId),
    SourceAliasesWorkspace(ArenaSlotId),
    SlotSizeMismatch {
        slot: ArenaSlotId,
        expected_words: usize,
        actual_words: usize,
    },
    SlotMisaligned(ArenaSlotId),
    ContextMismatch(ArenaSlotId),
    KernelLaunchFailed,
    ZeroSeedScalars,
    InvalidSeedRows {
        n_real_rows: usize,
        consumer_rows: usize,
    },
    HostSeedScalarCountMismatch {
        expected: usize,
        actual: usize,
    },
    SeedNotIngested,
    InvalidCompactLayout,
    InvalidCompactConsumerRows(usize),
    SortScratchTooSmall {
        required_bytes: usize,
        actual_bytes: usize,
    },
    ScanScratchTooSmall {
        required_bytes: usize,
        actual_bytes: usize,
    },
    SortScratchQueryFailed(i32),
    ScanScratchQueryFailed(i32),
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

pub fn witness_input_seed_requirements(
    scalar_words: usize,
    n_real_rows: usize,
    consumer_rows: usize,
    include_enabler: bool,
    include_iota: bool,
) -> Result<WitnessInputSeedRequirements, PreparedWitnessInputGatherError> {
    if scalar_words == 0 {
        return Err(PreparedWitnessInputGatherError::ZeroSeedScalars);
    }
    if n_real_rows == 0
        || n_real_rows > consumer_rows
        || consumer_rows % WITNESS_INPUT_GATHER_PACKED_LANES != 0
    {
        return Err(PreparedWitnessInputGatherError::InvalidSeedRows {
            n_real_rows,
            consumer_rows,
        });
    }
    u32::try_from(scalar_words).map_err(|_| PreparedWitnessInputGatherError::SizeOverflow)?;
    u32::try_from(n_real_rows).map_err(|_| PreparedWitnessInputGatherError::TotalRowsOverflow)?;
    u32::try_from(consumer_rows).map_err(|_| PreparedWitnessInputGatherError::TotalRowsOverflow)?;
    let output_columns = scalar_words
        .checked_add(usize::from(include_enabler))
        .and_then(|count| count.checked_add(usize::from(include_iota)))
        .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
    Ok(WitnessInputSeedRequirements {
        scalar_words,
        n_real_rows,
        consumer_rows,
        include_enabler,
        include_iota,
        consumer_input_column_words: vec![consumer_rows; output_columns],
        output_pointer_words: pointer_words(output_columns)?,
    })
}

impl WitnessInputSeedRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &WitnessInputSeedSlots,
    ) -> Result<Vec<WitnessInputGatherArenaSlotRequirement>, PreparedWitnessInputGatherError> {
        if slots.consumer_input_columns.len() != self.consumer_input_column_words.len() {
            return Err(
                PreparedWitnessInputGatherError::ConsumerColumnCountMismatch {
                    expected: self.consumer_input_column_words.len(),
                    actual: slots.consumer_input_columns.len(),
                },
            );
        }
        let mut result = vec![
            word_requirement(slots.scalar_values, self.scalar_words),
            pointer_requirement(slots.output_pointers, self.output_pointer_words),
        ];
        result.extend(
            slots
                .consumer_input_columns
                .iter()
                .zip(&self.consumer_input_column_words)
                .map(|(&id, &len_words)| word_requirement(id, len_words)),
        );
        ensure_distinct(result.iter().map(|entry| entry.id))?;
        Ok(result)
    }
}

impl WitnessInputCompactRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &WitnessInputCompactSlots,
    ) -> Result<Vec<WitnessInputGatherArenaSlotRequirement>, PreparedWitnessInputGatherError> {
        if slots.consumer_input_columns.len() != self.consumer_input_column_words.len() {
            return Err(
                PreparedWitnessInputGatherError::ConsumerColumnCountMismatch {
                    expected: self.consumer_input_column_words.len(),
                    actual: slots.consumer_input_columns.len(),
                },
            );
        }
        let mut result = vec![
            pointer_requirement(slots.source_pointers, self.source_pointer_words),
            word_requirement(slots.descriptors, self.descriptor_words),
            pointer_requirement(slots.output_pointers, self.output_pointer_words),
            word_requirement(slots.tuple_scratch, self.tuple_scratch_words),
            word_requirement(slots.sort_keys_a, self.sort_key_words),
            word_requirement(slots.sort_keys_b, self.sort_key_words),
            word_requirement(slots.sort_indices_a, self.sort_index_words),
            word_requirement(slots.sort_indices_b, self.sort_index_words),
            word_requirement(slots.run_heads, self.run_words),
            word_requirement(slots.run_positions, self.run_words),
            word_requirement(slots.n_unique, 1),
            word_requirement(slots.sort_temp, self.sort_temp_words),
            word_requirement(slots.scan_temp, self.scan_temp_words),
        ];
        result.extend(
            slots
                .consumer_input_columns
                .iter()
                .zip(&self.consumer_input_column_words)
                .map(|(&id, &len_words)| word_requirement(id, len_words)),
        );
        ensure_distinct(result.iter().map(|entry| entry.id))?;
        Ok(result)
    }
}

impl core::fmt::Display for PreparedWitnessInputGatherError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "prepared witness input gather rejected: {self:?}")
    }
}

impl std::error::Error for PreparedWitnessInputGatherError {}

impl From<ArenaError> for PreparedWitnessInputGatherError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedWitnessInputGatherError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

/// Pure canonical edge plan. Each producer contributes complete packed-16 rows;
/// the consumer is padded to the next packed-row power of two.
pub fn witness_input_gather_requirements(
    edges: &[WitnessInputGatherEdge],
    include_enabler: bool,
    include_iota: bool,
) -> Result<WitnessInputGatherRequirements, PreparedWitnessInputGatherError> {
    let Some(first) = edges.first() else {
        return Err(PreparedWitnessInputGatherError::NoEdges);
    };
    u32::try_from(edges.len()).map_err(|_| PreparedWitnessInputGatherError::SizeOverflow)?;
    if first.words_per_instance == 0 {
        return Err(PreparedWitnessInputGatherError::ZeroInputWidth(0));
    }
    u32::try_from(first.words_per_instance)
        .map_err(|_| PreparedWitnessInputGatherError::InputWidthOverflow(0))?;
    let input_width = first.words_per_instance;
    let mut destination_row_offset = 0usize;
    let mut plans = Vec::with_capacity(edges.len());
    for (index, &edge) in edges.iter().enumerate() {
        if edge.producer_rows == 0 {
            return Err(PreparedWitnessInputGatherError::ZeroProducerRows(index));
        }
        if edge.producer_rows % WITNESS_INPUT_GATHER_PACKED_LANES != 0 {
            return Err(PreparedWitnessInputGatherError::ProducerRowsNotPacked {
                edge: index,
                rows: edge.producer_rows,
            });
        }
        u32::try_from(edge.producer_rows)
            .map_err(|_| PreparedWitnessInputGatherError::ProducerRowsOverflow(index))?;
        if edge.words_per_instance == 0 {
            return Err(PreparedWitnessInputGatherError::ZeroInputWidth(index));
        }
        u32::try_from(edge.words_per_instance)
            .map_err(|_| PreparedWitnessInputGatherError::InputWidthOverflow(index))?;
        if edge.words_per_instance != input_width {
            return Err(PreparedWitnessInputGatherError::InputWidthMismatch {
                edge: index,
                expected: input_width,
                actual: edge.words_per_instance,
            });
        }
        u32::try_from(edge.word_base)
            .map_err(|_| PreparedWitnessInputGatherError::WordBaseOverflow(index))?;
        if edge.n_instances == 0 {
            return Err(PreparedWitnessInputGatherError::ZeroInstances(index));
        }
        u32::try_from(edge.n_instances)
            .map_err(|_| PreparedWitnessInputGatherError::InstanceCountOverflow(index))?;

        let destination_rows = edge
            .producer_rows
            .checked_mul(edge.n_instances)
            .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
        let source_word_end = edge
            .words_per_instance
            .checked_mul(edge.n_instances)
            .and_then(|words| edge.word_base.checked_add(words))
            .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
        let required_source_words = source_word_end
            .checked_mul(edge.producer_rows)
            .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
        u32::try_from(destination_rows)
            .map_err(|_| PreparedWitnessInputGatherError::TotalRowsOverflow)?;
        u32::try_from(destination_row_offset)
            .map_err(|_| PreparedWitnessInputGatherError::TotalRowsOverflow)?;
        plans.push(WitnessInputGatherEdgePlan {
            edge,
            destination_row_offset,
            destination_rows,
            required_source_words,
        });
        destination_row_offset = destination_row_offset
            .checked_add(destination_rows)
            .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
    }
    let total_real_rows = destination_row_offset;
    u32::try_from(total_real_rows)
        .map_err(|_| PreparedWitnessInputGatherError::TotalRowsOverflow)?;
    let packed_rows = total_real_rows / WITNESS_INPUT_GATHER_PACKED_LANES;
    let padded_packed_rows = packed_rows
        .checked_next_power_of_two()
        .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
    let consumer_rows = padded_packed_rows
        .checked_mul(WITNESS_INPUT_GATHER_PACKED_LANES)
        .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
    u32::try_from(consumer_rows).map_err(|_| PreparedWitnessInputGatherError::TotalRowsOverflow)?;
    let output_columns = input_width
        .checked_add(usize::from(include_enabler))
        .and_then(|width| width.checked_add(usize::from(include_iota)))
        .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
    u32::try_from(output_columns).map_err(|_| PreparedWitnessInputGatherError::SizeOverflow)?;

    Ok(WitnessInputGatherRequirements {
        edges: plans,
        input_width,
        total_real_rows,
        consumer_rows,
        include_enabler,
        include_iota,
        consumer_input_column_words: vec![consumer_rows; output_columns],
        source_pointer_words: pointer_words(edges.len())?,
        descriptor_words: edges
            .len()
            .checked_mul(WITNESS_INPUT_GATHER_DESCRIPTOR_WORDS)
            .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?,
        output_pointer_words: pointer_words(output_columns)?,
    })
}

/// Pure arena geometry for device-born canonical multiset compaction. Source
/// order is the schedule's producer-edge order; equal tuples are RLE-counted,
/// sorted lexicographically, and padded by repeating row zero with multiplicity
/// zero exactly like the host claim generators.
pub fn witness_input_compact_requirements(
    edges: &[WitnessInputGatherEdge],
    layout: WitnessInputCompactLayout,
    consumer_rows: usize,
) -> Result<WitnessInputCompactRequirements, PreparedWitnessInputGatherError> {
    if layout.tuple_words == 0
        || layout.key_words == 0
        || layout.key_words > layout.tuple_words
        || layout.consumer_input_count == 0
        || layout.multiplicity_slot >= layout.consumer_input_count
        || layout.tuple_words > layout.consumer_input_count
        || layout
            .enabler_slot
            .is_some_and(|slot| slot >= layout.consumer_input_count)
        || layout
            .iota_slot
            .is_some_and(|slot| slot >= layout.consumer_input_count)
    {
        return Err(PreparedWitnessInputGatherError::InvalidCompactLayout);
    }
    let mut occupied = (0..layout.tuple_words).collect::<BTreeSet<_>>();
    for slot in [layout.enabler_slot, layout.iota_slot]
        .into_iter()
        .flatten()
    {
        if !occupied.insert(slot) {
            return Err(PreparedWitnessInputGatherError::InvalidCompactLayout);
        }
    }
    if !occupied.insert(layout.multiplicity_slot) || occupied.len() != layout.consumer_input_count {
        return Err(PreparedWitnessInputGatherError::InvalidCompactLayout);
    }
    if consumer_rows < WITNESS_INPUT_GATHER_PACKED_LANES
        || !consumer_rows.is_power_of_two()
        || consumer_rows % WITNESS_INPUT_GATHER_PACKED_LANES != 0
    {
        return Err(PreparedWitnessInputGatherError::InvalidCompactConsumerRows(
            consumer_rows,
        ));
    }
    u32::try_from(layout.tuple_words)
        .and_then(|_| u32::try_from(layout.key_words))
        .and_then(|_| u32::try_from(layout.consumer_input_count))
        .and_then(|_| u32::try_from(layout.multiplicity_slot))
        .map_err(|_| PreparedWitnessInputGatherError::SizeOverflow)?;
    for slot in [layout.enabler_slot, layout.iota_slot]
        .into_iter()
        .flatten()
    {
        u32::try_from(slot).map_err(|_| PreparedWitnessInputGatherError::SizeOverflow)?;
    }
    u32::try_from(consumer_rows).map_err(|_| PreparedWitnessInputGatherError::TotalRowsOverflow)?;

    let gathered = witness_input_gather_requirements(edges, false, false)?;
    if gathered.input_width != layout.tuple_words {
        return Err(PreparedWitnessInputGatherError::InputWidthMismatch {
            edge: 0,
            expected: layout.tuple_words,
            actual: gathered.input_width,
        });
    }
    let sort_rows = gathered
        .total_real_rows
        .checked_next_power_of_two()
        .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
    u32::try_from(sort_rows).map_err(|_| PreparedWitnessInputGatherError::TotalRowsOverflow)?;
    let tuple_scratch_words = sort_rows
        .checked_mul(layout.tuple_words)
        .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
    let sort_temp_words = sort_rows
        .checked_mul(8)
        .and_then(|words| words.checked_add(WITNESS_INPUT_COMPACT_SORT_OVERHEAD_WORDS))
        .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
    let scan_temp_words = sort_rows
        .checked_mul(2)
        .and_then(|words| words.checked_add(WITNESS_INPUT_COMPACT_SCAN_OVERHEAD_WORDS))
        .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?;
    Ok(WitnessInputCompactRequirements {
        edges: gathered.edges,
        layout,
        total_input_rows: gathered.total_real_rows,
        sort_rows,
        consumer_rows,
        consumer_input_column_words: vec![consumer_rows; layout.consumer_input_count],
        source_pointer_words: pointer_words(edges.len())?,
        descriptor_words: edges
            .len()
            .checked_mul(WITNESS_INPUT_GATHER_DESCRIPTOR_WORDS)
            .ok_or(PreparedWitnessInputGatherError::SizeOverflow)?,
        output_pointer_words: pointer_words(layout.consumer_input_count)?,
        tuple_scratch_words,
        sort_key_words: sort_rows,
        sort_index_words: sort_rows,
        run_words: sort_rows,
        sort_temp_words,
        scan_temp_words,
    })
}

fn pointer_words(count: usize) -> Result<usize, PreparedWitnessInputGatherError> {
    count
        .checked_mul(POINTER_WORDS)
        .ok_or(PreparedWitnessInputGatherError::SizeOverflow)
}

pub struct PreparedWitnessInputGatherGraph<'a> {
    arena: &'a DeviceArena,
    requirements: WitnessInputGatherRequirements,
    sources: Vec<ArenaSlice>,
    source_pointers: ArenaSlice,
    descriptors: ArenaSlice,
    consumer_input_columns: Vec<ArenaSlice>,
    output_pointers: ArenaSlice,
}

/// Capture-safe canonical sort/RLE replacement for host DashMap claim
/// generators. Every pointer and CUB scratch range is arena-bound at prepare;
/// launch performs no allocation, transfer, or synchronization.
pub struct PreparedWitnessInputCompactGraph<'a> {
    arena: &'a DeviceArena,
    requirements: WitnessInputCompactRequirements,
    sources: Vec<ArenaSlice>,
    source_pointers: ArenaSlice,
    descriptors: ArenaSlice,
    consumer_input_columns: Vec<ArenaSlice>,
    output_pointers: ArenaSlice,
    tuple_scratch: ArenaSlice,
    sort_keys_a: ArenaSlice,
    sort_keys_b: ArenaSlice,
    sort_indices_a: ArenaSlice,
    sort_indices_b: ArenaSlice,
    run_heads: ArenaSlice,
    run_positions: ArenaSlice,
    n_unique: ArenaSlice,
    sort_temp: ArenaSlice,
    scan_temp: ArenaSlice,
    sort_temp_bytes: usize,
    scan_temp_bytes: usize,
}

impl<'a> PreparedWitnessInputCompactGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        sources: &[ArenaSlice],
        requirements: &WitnessInputCompactRequirements,
        slots: &WitnessInputCompactSlots,
    ) -> Result<Self, PreparedWitnessInputGatherError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedWitnessInputGatherError::CudaUnavailable);
        }
        let raw_edges = requirements
            .edges
            .iter()
            .map(|edge| edge.edge)
            .collect::<Vec<_>>();
        if witness_input_compact_requirements(
            &raw_edges,
            requirements.layout,
            requirements.consumer_rows,
        )? != *requirements
        {
            return Err(PreparedWitnessInputGatherError::InvalidCompactLayout);
        }
        requirements.arena_slot_requirements(slots)?;
        if sources.len() != requirements.edges.len() {
            return Err(PreparedWitnessInputGatherError::SourceCountMismatch {
                expected: requirements.edges.len(),
                actual: sources.len(),
            });
        }
        for (index, (&source, plan)) in sources.iter().zip(&requirements.edges).enumerate() {
            require_context(arena, source)?;
            if source.len_words() % plan.edge.producer_rows != 0 {
                return Err(PreparedWitnessInputGatherError::SourceRowsMismatch {
                    edge: index,
                    source_words: source.len_words(),
                    producer_rows: plan.edge.producer_rows,
                });
            }
            if source.len_words() < plan.required_source_words {
                return Err(PreparedWitnessInputGatherError::SourceTooSmall {
                    edge: index,
                    required_words: plan.required_source_words,
                    actual_words: source.len_words(),
                });
            }
        }

        let source_pointers = bind_min(
            arena,
            slots.source_pointers,
            requirements.source_pointer_words,
            WITNESS_INPUT_GATHER_POINTER_ALIGNMENT_WORDS,
        )?;
        let descriptors = bind_min(arena, slots.descriptors, requirements.descriptor_words, 1)?;
        let consumer_input_columns = bind_many_min(
            arena,
            &slots.consumer_input_columns,
            &requirements.consumer_input_column_words,
            1,
        )?;
        let output_pointers = bind_min(
            arena,
            slots.output_pointers,
            requirements.output_pointer_words,
            WITNESS_INPUT_GATHER_POINTER_ALIGNMENT_WORDS,
        )?;
        let tuple_scratch = bind_min(
            arena,
            slots.tuple_scratch,
            requirements.tuple_scratch_words,
            1,
        )?;
        let sort_keys_a = bind_min(arena, slots.sort_keys_a, requirements.sort_key_words, 1)?;
        let sort_keys_b = bind_min(arena, slots.sort_keys_b, requirements.sort_key_words, 1)?;
        let sort_indices_a = bind_min(
            arena,
            slots.sort_indices_a,
            requirements.sort_index_words,
            1,
        )?;
        let sort_indices_b = bind_min(
            arena,
            slots.sort_indices_b,
            requirements.sort_index_words,
            1,
        )?;
        let run_heads = bind_min(arena, slots.run_heads, requirements.run_words, 1)?;
        let run_positions = bind_min(arena, slots.run_positions, requirements.run_words, 1)?;
        let n_unique = bind_min(arena, slots.n_unique, 1, 1)?;
        let sort_temp = bind_min(arena, slots.sort_temp, requirements.sort_temp_words, 1)?;
        let scan_temp = bind_min(arena, slots.scan_temp, requirements.scan_temp_words, 1)?;
        let workspace_ids = std::iter::once(source_pointers.id())
            .chain(std::iter::once(descriptors.id()))
            .chain(consumer_input_columns.iter().map(|slice| slice.id()))
            .chain(
                [
                    output_pointers,
                    tuple_scratch,
                    sort_keys_a,
                    sort_keys_b,
                    sort_indices_a,
                    sort_indices_b,
                    run_heads,
                    run_positions,
                    n_unique,
                    sort_temp,
                    scan_temp,
                ]
                .into_iter()
                .map(|slice| slice.id()),
            )
            .collect::<BTreeSet<_>>();
        for source in sources {
            if workspace_ids.contains(&source.id()) {
                return Err(PreparedWitnessInputGatherError::SourceAliasesWorkspace(
                    source.id(),
                ));
            }
        }

        let sort_temp_bytes = checked_witness_input_compact_temp_bytes(
            stwo_backend_cuda_kernels::raw::stwo_witness_input_compact_sort_temp_bytes,
            requirements.sort_rows as u32,
        )
        .map_err(PreparedWitnessInputGatherError::SortScratchQueryFailed)?;
        if sort_temp_bytes > sort_temp.len_bytes() {
            return Err(PreparedWitnessInputGatherError::SortScratchTooSmall {
                required_bytes: sort_temp_bytes,
                actual_bytes: sort_temp.len_bytes(),
            });
        }
        let scan_temp_bytes = checked_witness_input_compact_temp_bytes(
            stwo_backend_cuda_kernels::raw::stwo_witness_input_compact_scan_temp_bytes,
            requirements.sort_rows as u32,
        )
        .map_err(PreparedWitnessInputGatherError::ScanScratchQueryFailed)?;
        if scan_temp_bytes > scan_temp.len_bytes() {
            return Err(PreparedWitnessInputGatherError::ScanScratchTooSmall {
                required_bytes: scan_temp_bytes,
                actual_bytes: scan_temp.len_bytes(),
            });
        }

        upload(arena, source_pointers, &pointer_values(sources))?;
        let descriptor_values = requirements
            .edges
            .iter()
            .flat_map(|plan| {
                [
                    plan.edge.producer_rows as u32,
                    plan.edge.word_base as u32,
                    plan.edge.words_per_instance as u32,
                    plan.edge.n_instances as u32,
                    plan.destination_row_offset as u32,
                ]
            })
            .collect::<Vec<_>>();
        upload(arena, descriptors, &descriptor_values)?;
        upload(
            arena,
            output_pointers,
            &pointer_values(&consumer_input_columns),
        )?;
        arena.context().sync()?;

        Ok(Self {
            arena,
            requirements: requirements.clone(),
            sources: sources.to_vec(),
            source_pointers,
            descriptors,
            consumer_input_columns,
            output_pointers,
            tuple_scratch,
            sort_keys_a,
            sort_keys_b,
            sort_indices_a,
            sort_indices_b,
            run_heads,
            run_positions,
            n_unique,
            sort_temp,
            scan_temp,
            sort_temp_bytes,
            scan_temp_bytes,
        })
    }

    pub fn launch(&self) -> Result<(), PreparedWitnessInputGatherError> {
        self.launch_on(self.arena.context().launch_context())
    }

    pub fn launch_on(
        &self,
        launch: CudaLaunchContext,
    ) -> Result<(), PreparedWitnessInputGatherError> {
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        let layout = self.requirements.layout;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_witness_input_compact_on(
                self.source_pointers.as_u32_ptr().cast(),
                self.descriptors.as_u32_ptr().cast_const(),
                self.requirements.edges.len() as u32,
                layout.tuple_words as u32,
                layout.key_words as u32,
                self.requirements.total_input_rows as u32,
                self.requirements.sort_rows as u32,
                self.requirements.consumer_rows as u32,
                layout.consumer_input_count as u32,
                self.output_pointers.as_u32_ptr().cast(),
                layout
                    .enabler_slot
                    .map_or(WITNESS_INPUT_COMPACT_NO_SLOT, |slot| slot as u32),
                layout
                    .iota_slot
                    .map_or(WITNESS_INPUT_COMPACT_NO_SLOT, |slot| slot as u32),
                layout.multiplicity_slot as u32,
                self.tuple_scratch.as_u32_ptr(),
                self.sort_keys_a.as_u32_ptr(),
                self.sort_keys_b.as_u32_ptr(),
                self.sort_indices_a.as_u32_ptr(),
                self.sort_indices_b.as_u32_ptr(),
                self.run_heads.as_u32_ptr(),
                self.run_positions.as_u32_ptr(),
                self.n_unique.as_u32_ptr(),
                self.sort_temp.as_void_ptr(),
                self.sort_temp_bytes,
                self.scan_temp.as_void_ptr(),
                self.scan_temp_bytes,
                launch.stream_raw().as_ptr(),
            )
        };
        if code == 0 {
            Ok(())
        } else {
            Err(PreparedWitnessInputGatherError::KernelLaunchFailed)
        }
    }

    pub fn requirements(&self) -> &WitnessInputCompactRequirements {
        &self.requirements
    }

    pub fn sources(&self) -> &[ArenaSlice] {
        &self.sources
    }

    pub fn consumer_input_columns(&self) -> &[ArenaSlice] {
        &self.consumer_input_columns
    }

    pub fn n_unique(&self) -> ArenaSlice {
        self.n_unique
    }

    pub fn descriptor_slices(&self) -> [ArenaSlice; 3] {
        [self.source_pointers, self.descriptors, self.output_pointers]
    }

    pub fn scratch_slices(&self) -> [ArenaSlice; 10] {
        [
            self.tuple_scratch,
            self.sort_keys_a,
            self.sort_keys_b,
            self.sort_indices_a,
            self.sort_indices_b,
            self.run_heads,
            self.run_positions,
            self.n_unique,
            self.sort_temp,
            self.scan_temp,
        ]
    }
}

impl<'a> PreparedWitnessInputGatherGraph<'a> {
    /// Bind borrowed producer/consumer slices and drain immutable setup uploads.
    pub fn prepare(
        arena: &'a DeviceArena,
        sources: &[ArenaSlice],
        edges: &[WitnessInputGatherEdge],
        include_enabler: bool,
        include_iota: bool,
        slots: &WitnessInputGatherSlots,
    ) -> Result<Self, PreparedWitnessInputGatherError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedWitnessInputGatherError::CudaUnavailable);
        }
        let requirements = witness_input_gather_requirements(edges, include_enabler, include_iota)?;
        requirements.arena_slot_requirements(slots)?;
        if sources.len() != requirements.edges.len() {
            return Err(PreparedWitnessInputGatherError::SourceCountMismatch {
                expected: requirements.edges.len(),
                actual: sources.len(),
            });
        }
        for (index, (&source, plan)) in sources.iter().zip(&requirements.edges).enumerate() {
            require_context(arena, source)?;
            if source.len_words() % plan.edge.producer_rows != 0 {
                return Err(PreparedWitnessInputGatherError::SourceRowsMismatch {
                    edge: index,
                    source_words: source.len_words(),
                    producer_rows: plan.edge.producer_rows,
                });
            }
            if source.len_words() < plan.required_source_words {
                return Err(PreparedWitnessInputGatherError::SourceTooSmall {
                    edge: index,
                    required_words: plan.required_source_words,
                    actual_words: source.len_words(),
                });
            }
        }

        let source_pointers = bind_min(
            arena,
            slots.source_pointers,
            requirements.source_pointer_words,
            WITNESS_INPUT_GATHER_POINTER_ALIGNMENT_WORDS,
        )?;
        let descriptors = bind_min(arena, slots.descriptors, requirements.descriptor_words, 1)?;
        let consumer_input_columns = bind_many_min(
            arena,
            &slots.consumer_input_columns,
            &requirements.consumer_input_column_words,
            1,
        )?;
        let output_pointers = bind_min(
            arena,
            slots.output_pointers,
            requirements.output_pointer_words,
            WITNESS_INPUT_GATHER_POINTER_ALIGNMENT_WORDS,
        )?;
        let workspace_ids = std::iter::once(source_pointers.id())
            .chain(std::iter::once(descriptors.id()))
            .chain(consumer_input_columns.iter().map(|slice| slice.id()))
            .chain(std::iter::once(output_pointers.id()))
            .collect::<BTreeSet<_>>();
        for source in sources {
            if workspace_ids.contains(&source.id()) {
                return Err(PreparedWitnessInputGatherError::SourceAliasesWorkspace(
                    source.id(),
                ));
            }
        }

        let source_pointer_values = pointer_values(sources);
        let output_pointer_values = pointer_values(&consumer_input_columns);
        upload(arena, source_pointers, &source_pointer_values)?;
        let descriptor_values = requirements
            .edges
            .iter()
            .flat_map(|plan| {
                [
                    plan.edge.producer_rows as u32,
                    plan.edge.word_base as u32,
                    plan.edge.words_per_instance as u32,
                    plan.edge.n_instances as u32,
                    plan.destination_row_offset as u32,
                ]
            })
            .collect::<Vec<_>>();
        upload(arena, descriptors, &descriptor_values)?;
        upload(arena, output_pointers, &output_pointer_values)?;
        arena.context().sync()?;

        Ok(Self {
            arena,
            requirements,
            sources: sources.to_vec(),
            source_pointers,
            descriptors,
            consumer_input_columns,
            output_pointers,
        })
    }

    /// Enqueue exactly one multi-producer gather on the arena stream.
    pub fn launch(&self) -> Result<(), PreparedWitnessInputGatherError> {
        self.launch_on(self.arena.context().launch_context())
    }

    pub fn launch_on(
        &self,
        launch: CudaLaunchContext,
    ) -> Result<(), PreparedWitnessInputGatherError> {
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_witness_input_gather_on(
                self.source_pointers.as_u32_ptr().cast(),
                self.descriptors.as_u32_ptr().cast_const(),
                self.requirements.edges.len() as u32,
                self.requirements.input_width as u32,
                self.requirements.total_real_rows as u32,
                self.requirements.consumer_rows as u32,
                self.output_pointers.as_u32_ptr().cast(),
                u32::from(self.requirements.include_enabler),
                u32::from(self.requirements.include_iota),
                launch.stream_raw().as_ptr(),
            )
        };
        if code == 0 {
            Ok(())
        } else {
            Err(PreparedWitnessInputGatherError::KernelLaunchFailed)
        }
    }

    pub fn requirements(&self) -> &WitnessInputGatherRequirements {
        &self.requirements
    }

    pub fn sources(&self) -> &[ArenaSlice] {
        &self.sources
    }

    pub fn consumer_input_columns(&self) -> &[ArenaSlice] {
        &self.consumer_input_columns
    }

    pub fn descriptor_slices(&self) -> [ArenaSlice; 3] {
        [self.source_pointers, self.descriptors, self.output_pointers]
    }
}

/// Capture-safe expansion of compact statement metadata into the recorder's
/// stable input columns. Preparation uploads only immutable pointer metadata;
/// each proof ingests O(number-of-scalars) words before graph capture/replay.
pub struct PreparedWitnessInputSeedGraph<'a> {
    arena: &'a DeviceArena,
    requirements: WitnessInputSeedRequirements,
    scalar_values: ArenaSlice,
    consumer_input_columns: Vec<ArenaSlice>,
    output_pointers: ArenaSlice,
    ingested: Cell<bool>,
}

impl<'a> PreparedWitnessInputSeedGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        requirements: &WitnessInputSeedRequirements,
        slots: &WitnessInputSeedSlots,
    ) -> Result<Self, PreparedWitnessInputGatherError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedWitnessInputGatherError::CudaUnavailable);
        }
        if witness_input_seed_requirements(
            requirements.scalar_words,
            requirements.n_real_rows,
            requirements.consumer_rows,
            requirements.include_enabler,
            requirements.include_iota,
        )? != *requirements
        {
            return Err(PreparedWitnessInputGatherError::SizeOverflow);
        }
        requirements.arena_slot_requirements(slots)?;
        let scalar_values = bind_min(arena, slots.scalar_values, requirements.scalar_words, 1)?;
        let consumer_input_columns = bind_many_min(
            arena,
            &slots.consumer_input_columns,
            &requirements.consumer_input_column_words,
            1,
        )?;
        let output_pointers = bind_min(
            arena,
            slots.output_pointers,
            requirements.output_pointer_words,
            WITNESS_INPUT_GATHER_POINTER_ALIGNMENT_WORDS,
        )?;
        upload(
            arena,
            output_pointers,
            &pointer_values(&consumer_input_columns),
        )?;
        arena.context().sync()?;
        Ok(Self {
            arena,
            requirements: requirements.clone(),
            scalar_values,
            consumer_input_columns,
            output_pointers,
            ingested: Cell::new(false),
        })
    }

    /// Enqueue the compact scalar upload. The caller owns the setup fence so
    /// multiple prepared writers share one synchronization.
    pub fn ingest_scalars(&self, values: &[u32]) -> Result<(), PreparedWitnessInputGatherError> {
        if values.len() != self.requirements.scalar_words {
            return Err(
                PreparedWitnessInputGatherError::HostSeedScalarCountMismatch {
                    expected: self.requirements.scalar_words,
                    actual: values.len(),
                },
            );
        }
        upload(self.arena, self.scalar_values, values)?;
        self.ingested.set(true);
        Ok(())
    }

    pub fn launch(&self) -> Result<(), PreparedWitnessInputGatherError> {
        self.launch_on(self.arena.context().launch_context())
    }

    pub fn launch_on(
        &self,
        launch: CudaLaunchContext,
    ) -> Result<(), PreparedWitnessInputGatherError> {
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        if !self.ingested.get() {
            return Err(PreparedWitnessInputGatherError::SeedNotIngested);
        }
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_witness_input_seed_on(
                self.scalar_values.as_u32_ptr().cast_const(),
                self.requirements.scalar_words as u32,
                self.requirements.n_real_rows as u32,
                self.requirements.consumer_rows as u32,
                self.output_pointers.as_u32_ptr().cast(),
                u32::from(self.requirements.include_enabler),
                u32::from(self.requirements.include_iota),
                launch.stream_raw().as_ptr(),
            )
        };
        if code == 0 {
            Ok(())
        } else {
            Err(PreparedWitnessInputGatherError::KernelLaunchFailed)
        }
    }

    pub fn requirements(&self) -> &WitnessInputSeedRequirements {
        &self.requirements
    }

    pub fn consumer_input_columns(&self) -> &[ArenaSlice] {
        &self.consumer_input_columns
    }

    pub fn descriptor_slices(&self) -> [ArenaSlice; 2] {
        [self.scalar_values, self.output_pointers]
    }
}

fn pointer_values(slices: &[ArenaSlice]) -> Vec<usize> {
    slices
        .iter()
        .map(|slice| slice.as_u32_ptr() as usize)
        .collect()
}

fn upload<T: Copy>(
    arena: &DeviceArena,
    destination: ArenaSlice,
    values: &[T],
) -> Result<(), PreparedWitnessInputGatherError> {
    // Capacity contract (see `bind_min`): the destination is a whole arena
    // slot that may be pooled larger than this payload. Exactly `values` is
    // uploaded and exactly `values` is later read back by the kernels, so a
    // larger backing slot is unobservable; a smaller one fails closed here.
    let bytes = core::mem::size_of_val(values);
    if bytes > destination.len_bytes() {
        return Err(PreparedWitnessInputGatherError::SlotSizeMismatch {
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

fn bind_many_min(
    arena: &DeviceArena,
    ids: &[ArenaSlotId],
    lengths: &[usize],
    alignment_words: usize,
) -> Result<Vec<ArenaSlice>, PreparedWitnessInputGatherError> {
    ids.iter()
        .zip(lengths)
        .map(|(&id, &len_words)| bind_min(arena, id, len_words, alignment_words))
        .collect()
}

/// Bind one arena slot, require the kernel-ABI capacity, and return a slice
/// truncated to exactly that requirement.
///
/// `required_words` is a LOWER bound on the physical capacity: the arena plan
/// pools logical buffers with disjoint proof-epoch lifetimes into one physical
/// slot sized to the largest sharer, and `DeviceArena::bind` always returns
/// the whole slot. The returned slice is truncated to `required_words`, so
/// `len_words()` IS the logical requirement everywhere downstream and the
/// pooled surplus is invisible; an undersized or misaligned slot still fails
/// closed before any launch.
fn bind_min(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedWitnessInputGatherError> {
    let slice = arena.bind(id)?;
    require_context(arena, slice)?;
    truncate_bound_slot(slice, required_words, alignment_words)
}

/// Validate one bound slot's capacity and alignment, then truncate it to the
/// logical requirement so `len_words()` never exposes the pooled surplus.
fn truncate_bound_slot(
    slice: ArenaSlice,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedWitnessInputGatherError> {
    if slice.len_words() < required_words {
        return Err(PreparedWitnessInputGatherError::SlotSizeMismatch {
            slot: slice.id(),
            expected_words: required_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedWitnessInputGatherError::SlotMisaligned(slice.id()));
    }
    Ok(slice.truncated(required_words))
}

fn require_context(
    arena: &DeviceArena,
    slice: ArenaSlice,
) -> Result<(), PreparedWitnessInputGatherError> {
    if slice.context_token() == arena.context().identity_token() {
        Ok(())
    } else {
        Err(PreparedWitnessInputGatherError::ContextMismatch(slice.id()))
    }
}

fn ensure_distinct(
    ids: impl IntoIterator<Item = ArenaSlotId>,
) -> Result<(), PreparedWitnessInputGatherError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(PreparedWitnessInputGatherError::DuplicateSlot(id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn successful_temp_query(rows: u32, out_bytes: *mut usize) -> i32 {
        assert_eq!(rows, 64);
        unsafe { out_bytes.write(2048) };
        0
    }

    unsafe extern "C" fn failed_temp_query(_rows: u32, out_bytes: *mut usize) -> i32 {
        unsafe { out_bytes.write(2048) };
        719
    }

    unsafe extern "C" fn zero_temp_query(_rows: u32, _out_bytes: *mut usize) -> i32 {
        0
    }

    fn edges() -> [WitnessInputGatherEdge; 2] {
        [
            WitnessInputGatherEdge {
                producer_rows: 16,
                word_base: 1,
                words_per_instance: 3,
                n_instances: 2,
            },
            WitnessInputGatherEdge {
                producer_rows: 16,
                word_base: 2,
                words_per_instance: 3,
                n_instances: 1,
            },
        ]
    }

    #[test]
    fn bound_slots_truncate_pooled_surplus_to_the_logical_requirement() {
        // Pooled physical slots are sized to the LARGEST epoch-disjoint
        // sharer; the binder must expose only the logical extent so kernel
        // extents derived from `len_words()` never see the surplus.
        let oversized = ArenaSlice::dangling_for_test(9, 512);
        let bound = truncate_bound_slot(oversized, 112, 1).unwrap();
        assert_eq!(bound.len_words(), 112);
        assert_eq!(bound.id(), oversized.id());
        assert_eq!(bound.as_u32_ptr(), oversized.as_u32_ptr());
        // Undersized slots still fail closed.
        assert!(matches!(
            truncate_bound_slot(ArenaSlice::dangling_for_test(9, 64), 112, 1),
            Err(PreparedWitnessInputGatherError::SlotSizeMismatch { .. })
        ));
    }

    #[test]
    fn compact_temp_queries_require_success_and_nonzero_bytes() {
        assert_eq!(
            checked_witness_input_compact_temp_bytes(successful_temp_query, 64),
            Ok(2048)
        );
        assert_eq!(
            checked_witness_input_compact_temp_bytes(failed_temp_query, 64),
            Err(719)
        );
        assert_eq!(
            checked_witness_input_compact_temp_bytes(zero_temp_query, 64),
            Err(0)
        );
    }

    #[test]
    fn canonical_plan_computes_offsets_padding_tail_and_source_ranges() {
        let requirements = witness_input_gather_requirements(&edges(), true, true).unwrap();
        assert_eq!(requirements.input_width, 3);
        assert_eq!(requirements.total_real_rows, 48);
        assert_eq!(requirements.consumer_rows, 64);
        assert_eq!(requirements.consumer_input_column_words, [64; 5]);
        assert_eq!(requirements.edges[0].destination_row_offset, 0);
        assert_eq!(requirements.edges[0].destination_rows, 32);
        assert_eq!(requirements.edges[0].required_source_words, 112);
        assert_eq!(requirements.edges[1].destination_row_offset, 32);
        assert_eq!(requirements.edges[1].destination_rows, 16);
        assert_eq!(requirements.edges[1].required_source_words, 80);
        assert_eq!(requirements.descriptor_words, 10);
        assert_eq!(requirements.source_pointer_words, 2 * POINTER_WORDS);
        assert_eq!(requirements.output_pointer_words, 5 * POINTER_WORDS);
    }

    #[test]
    fn compact_seed_plan_is_exact_and_alias_checked() {
        let requirements = witness_input_seed_requirements(1, 48, 64, true, true).unwrap();
        assert_eq!(requirements.scalar_words, 1);
        assert_eq!(requirements.consumer_input_column_words, [64; 3]);
        assert_eq!(requirements.output_pointer_words, 3 * POINTER_WORDS);
        let slots = WitnessInputSeedSlots {
            scalar_values: ArenaSlotId(1),
            consumer_input_columns: vec![ArenaSlotId(2), ArenaSlotId(3), ArenaSlotId(4)],
            output_pointers: ArenaSlotId(5),
        };
        assert_eq!(
            requirements.arena_slot_requirements(&slots).unwrap().len(),
            5
        );
        assert!(matches!(
            witness_input_seed_requirements(0, 48, 64, true, true),
            Err(PreparedWitnessInputGatherError::ZeroSeedScalars)
        ));
        assert!(matches!(
            witness_input_seed_requirements(1, 65, 64, true, true),
            Err(PreparedWitnessInputGatherError::InvalidSeedRows { .. })
        ));
    }

    #[test]
    fn canonical_compact_plan_exposes_tuple_key_and_recorder_tail() {
        let layout = WitnessInputCompactLayout {
            tuple_words: 3,
            key_words: 2,
            consumer_input_count: 6,
            enabler_slot: Some(3),
            iota_slot: Some(4),
            multiplicity_slot: 5,
        };
        let requirements = witness_input_compact_requirements(&edges(), layout, 32).unwrap();
        assert_eq!(requirements.layout.tuple_words, 3);
        assert_eq!(requirements.layout.key_words, 2);
        assert_eq!(requirements.total_input_rows, 48);
        assert_eq!(requirements.sort_rows, 64);
        assert_eq!(requirements.consumer_rows, 32);
        assert_eq!(requirements.consumer_input_column_words, [32; 6]);
        assert_eq!(requirements.tuple_scratch_words, 64 * 3);
        assert_eq!(requirements.sort_key_words, 64);
        assert_eq!(requirements.run_words, 64);
        let slots = WitnessInputCompactSlots {
            source_pointers: ArenaSlotId(1),
            descriptors: ArenaSlotId(2),
            consumer_input_columns: (3..9).map(ArenaSlotId).collect(),
            output_pointers: ArenaSlotId(9),
            tuple_scratch: ArenaSlotId(10),
            sort_keys_a: ArenaSlotId(11),
            sort_keys_b: ArenaSlotId(12),
            sort_indices_a: ArenaSlotId(13),
            sort_indices_b: ArenaSlotId(14),
            run_heads: ArenaSlotId(15),
            run_positions: ArenaSlotId(16),
            n_unique: ArenaSlotId(17),
            sort_temp: ArenaSlotId(18),
            scan_temp: ArenaSlotId(19),
        };
        assert_eq!(
            requirements.arena_slot_requirements(&slots).unwrap().len(),
            19
        );

        let mut invalid = layout;
        invalid.multiplicity_slot = 4;
        assert_eq!(
            witness_input_compact_requirements(&edges(), invalid, 32).unwrap_err(),
            PreparedWitnessInputGatherError::InvalidCompactLayout
        );
        assert!(matches!(
            witness_input_compact_requirements(&edges(), layout, 48),
            Err(PreparedWitnessInputGatherError::InvalidCompactConsumerRows(
                48
            ))
        ));
    }

    #[test]
    fn invalid_edges_and_slot_aliases_fail_closed() {
        let mut invalid = edges();
        invalid[1].words_per_instance = 2;
        assert_eq!(
            witness_input_gather_requirements(&invalid, false, false).unwrap_err(),
            PreparedWitnessInputGatherError::InputWidthMismatch {
                edge: 1,
                expected: 3,
                actual: 2,
            }
        );
        invalid = edges();
        invalid[0].producer_rows = 15;
        assert!(matches!(
            witness_input_gather_requirements(&invalid, false, false),
            Err(PreparedWitnessInputGatherError::ProducerRowsNotPacked { .. })
        ));

        let requirements = witness_input_gather_requirements(&edges(), false, true).unwrap();
        let duplicate = ArenaSlotId(1);
        let slots = WitnessInputGatherSlots {
            source_pointers: duplicate,
            descriptors: duplicate,
            consumer_input_columns: vec![
                ArenaSlotId(3),
                ArenaSlotId(4),
                ArenaSlotId(5),
                ArenaSlotId(6),
            ],
            output_pointers: ArenaSlotId(7),
        };
        assert_eq!(
            requirements.arena_slot_requirements(&slots).unwrap_err(),
            PreparedWitnessInputGatherError::DuplicateSlot(duplicate)
        );
    }
}
