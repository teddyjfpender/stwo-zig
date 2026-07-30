//! Prepared multiplicity feeds from a recorded witness's resident sub-input buffer.
//!
//! Setup validates the flat descriptor ABI, binds every arena address, and uploads
//! descriptors, LUTs, and pointer tables once. [`PreparedWitnessFeedGraph::launch`]
//! is one explicit-stream kernel enqueue with no allocation, copy, or synchronization.

use core::ffi::c_void;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use super::exec_context::{
    ArenaError, ArenaSlice, ArenaSlotId, CudaLaunchContext, CudaRuntimeError, DeviceArena,
};
use super::prepared_witness::{BLAKE_G_DIRECT_COUNT_WORDS, BLAKE_G_DIRECT_LUT_WORDS};

mod authority;
mod blake_g_lut_content;
mod clear_authority;
mod source_upload;
pub use authority::{
    WitnessFeedAbi, WitnessFeedAbiAccess, WitnessFeedAbiArgument, WitnessFeedAbiArgumentKind,
    WitnessFeedAuthorityError, WitnessFeedContract, WitnessFeedDescriptorField,
    WitnessFeedDescriptorKind, WitnessFeedDestinationEffect, WitnessFeedDestinationRange,
    WitnessFeedEffectAbi, WitnessFeedEffectGeometry, WitnessFeedKernelLaunch,
    WitnessFeedLinkedContract, WitnessFeedLutRead, WitnessFeedRowDomain, WitnessFeedSourceRead,
    WITNESS_FEED_DESCRIPTOR_FIELD_ORDER,
};
pub use blake_g_lut_content::{BlakeGDirectLutContentError, BlakeGDirectLutContentIdentity};
pub use clear_authority::{
    WitnessFeedClearAbi, WitnessFeedClearAbiAccess, WitnessFeedClearAbiArgument,
    WitnessFeedClearAbiArgumentKind, WitnessFeedClearAuthorityError, WitnessFeedClearContract,
    WitnessFeedClearDestinationEffect, WitnessFeedClearEffectAbi, WitnessFeedClearEffectGeometry,
    WitnessFeedClearKernelLaunch, WitnessFeedClearLinkedContract,
};
pub use source_upload::WitnessFeedSourceUploadReceipt;

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);

pub const WITNESS_FEED_DESCRIPTOR_WORDS: usize = 14;
pub const WITNESS_FEED_MAX_TUPLE_WORDS: usize = 5;
pub const WITNESS_FEED_NO_LUT: u32 = u32::MAX;
pub const WITNESS_FEED_POINTER_ALIGNMENT_WORDS: usize =
    core::mem::align_of::<*mut u32>() / WORD_BYTES;

/// Static shared-memory budget of the privatized count kernel (see
/// `WFC_PRIV_SHARED_BYTES` in witness_feed_counts.cu — the two constants must
/// stay equal).
pub const WITNESS_FEED_PRIVATIZED_SHARED_BYTES: usize = 48 * 1024;
pub const WITNESS_FEED_PRIVATIZED_SHARED_WORDS: usize =
    WITNESS_FEED_PRIVATIZED_SHARED_BYTES / WORD_BYTES;

/// Selects which count-feed kernel [`PreparedWitnessFeedGraph::launch`]
/// submits. Chosen once at [`PreparedWitnessFeedGraph::prepare`] (from the
/// process-global `STWO_CUDA_FEED_PRIVATIZED` switch), so eager runs, capture
/// and replay of one graph all observe one mode.
///
/// Byte-identity: every count is a u32 sum of `+1` increments merged with
/// wrapping atomic adds. Privatization only reassociates that sum — per-block
/// shared-memory partials, then one unconditional (branchless) atomicAdd per
/// covered word into the same global slab — and wrapping u32 addition is
/// commutative and associative, so both modes produce byte-identical count
/// slabs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessFeedLaunchMode {
    /// Direct global atomicAdd scatter (default; the proven fallback).
    GlobalAtomics,
    /// Per-block shared-memory histograms for descriptors whose touched
    /// counter footprint fits the 48KB static shared budget; oversized
    /// families keep the global-atomic path inside the same launch. Opt-in
    /// via `STWO_CUDA_FEED_PRIVATIZED=1`.
    Privatized,
}

/// Touched counter words for one descriptor — the shared-memory words the
/// privatized kernel must cover: table words per relation column times the
/// number of relation columns the descriptor writes. Mirrors
/// `wfc_privatized_footprint_words` in witness_feed_counts.cu exactly.
pub fn witness_feed_privatized_footprint_words(
    entry: &[u32; WITNESS_FEED_DESCRIPTOR_WORDS],
) -> u64 {
    let table_size = u64::from(entry[8]);
    match entry[11] {
        // MEM-ID DECODE writes one big relation column (table_size words) and
        // one small relation column (entry[12] words).
        1 => table_size + u64::from(entry[12]),
        // xor12 addresses all sixteen expanded multiplicity columns.
        3 => 16 * table_size,
        // FOLD / dependent-XOR write one relation column of the table.
        _ => table_size,
    }
}

/// Per-descriptor privatization decision of the kernel: footprint x 4B must
/// fit the 48KB static shared budget. Pure host math for unit tests and
/// planning; the device kernel makes the identical decision per descriptor.
pub fn witness_feed_descriptor_fits_shared(entry: &[u32; WITNESS_FEED_DESCRIPTOR_WORDS]) -> bool {
    witness_feed_privatized_footprint_words(entry) <= WITNESS_FEED_PRIVATIZED_SHARED_WORDS as u64
}

/// Pure `STWO_CUDA_FEED_PRIVATIZED` parse, unit-testable without an
/// environment: only the literal `"1"` opts into the privatized lane.
fn feed_privatized_flag_from(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// `STWO_CUDA_FEED_PRIVATIZED=1` opts newly prepared feed graphs into the
/// privatized kernel. Read once per process (`OnceLock`). Default OFF: the
/// global-atomic scatter stays the proven fallback.
fn feed_privatized_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        feed_privatized_flag_from(std::env::var("STWO_CUDA_FEED_PRIVATIZED").ok().as_deref())
    })
}

fn witness_feed_mode_from_env() -> WitnessFeedLaunchMode {
    if feed_privatized_enabled() {
        WitnessFeedLaunchMode::Privatized
    } else {
        WitnessFeedLaunchMode::GlobalAtomics
    }
}

/// One slot request for merging a feed graph into the proof-wide arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessFeedArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

/// Pure, exact geometry for one prepared feed launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessFeedWorkspaceRequirements {
    pub row_count: usize,
    pub sub_words_per_row: usize,
    pub source_words: usize,
    pub descriptor_words: usize,
    pub descriptor_count: usize,
    pub lut_words: Vec<usize>,
    pub lut_pointer_words: usize,
    pub multiplicity_words: Vec<usize>,
    pub multiplicity_pointer_words: usize,
}

/// Arena identities used by one feed graph. Multiplicity slots are supplied by
/// the caller so several producer graphs can accumulate into the same targets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessFeedWorkspaceSlots {
    pub descriptors: ArenaSlotId,
    pub lut_tables: Vec<ArenaSlotId>,
    pub lut_pointers: ArenaSlotId,
    pub multiplicity_destinations: Vec<ArenaSlotId>,
    pub multiplicity_pointers: ArenaSlotId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessFeedClearWorkspaceRequirements {
    pub destination_words: Vec<usize>,
    pub destination_pointer_words: usize,
    pub destination_length_words: usize,
    pub max_destination_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessFeedClearWorkspaceSlots {
    pub destination_pointers: ArenaSlotId,
    pub destination_lengths: ArenaSlotId,
}

impl WitnessFeedClearWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: WitnessFeedClearWorkspaceSlots,
    ) -> Result<[WitnessFeedArenaSlotRequirement; 2], PreparedWitnessFeedError> {
        if slots.destination_pointers == slots.destination_lengths {
            return Err(PreparedWitnessFeedError::DuplicateSlot(
                slots.destination_pointers,
            ));
        }
        Ok([
            pointers(slots.destination_pointers, self.destination_pointer_words),
            words(slots.destination_lengths, self.destination_length_words),
        ])
    }
}

impl WitnessFeedWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &WitnessFeedWorkspaceSlots,
    ) -> Result<Vec<WitnessFeedArenaSlotRequirement>, PreparedWitnessFeedError> {
        check_count("lut_tables", self.lut_words.len(), slots.lut_tables.len())?;
        check_count(
            "multiplicity_destinations",
            self.multiplicity_words.len(),
            slots.multiplicity_destinations.len(),
        )?;
        let mut result = vec![
            words(slots.descriptors, self.descriptor_words),
            pointers(slots.lut_pointers, self.lut_pointer_words),
            pointers(slots.multiplicity_pointers, self.multiplicity_pointer_words),
        ];
        result.extend(
            slots
                .lut_tables
                .iter()
                .zip(&self.lut_words)
                .map(|(&id, &len_words)| words(id, len_words)),
        );
        result.extend(
            slots
                .multiplicity_destinations
                .iter()
                .zip(&self.multiplicity_words)
                .map(|(&id, &len_words)| words(id, len_words)),
        );
        ensure_distinct(result.iter().map(|entry| entry.id))?;
        Ok(result)
    }
}

fn words(id: ArenaSlotId, len_words: usize) -> WitnessFeedArenaSlotRequirement {
    WitnessFeedArenaSlotRequirement {
        id,
        len_words,
        alignment_words: 1,
    }
}

fn pointers(id: ArenaSlotId, len_words: usize) -> WitnessFeedArenaSlotRequirement {
    WitnessFeedArenaSlotRequirement {
        id,
        len_words,
        alignment_words: WITNESS_FEED_POINTER_ALIGNMENT_WORDS,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedWitnessFeedError {
    CudaUnavailable,
    ZeroRows,
    ZeroSubWords,
    RowCountOverflow,
    SizeOverflow,
    NoDescriptors,
    DescriptorStrideMismatch(usize),
    NoMultiplicityDestinations,
    EmptyLut(usize),
    EmptyMultiplicityDestination(usize),
    InvalidDescriptorKind {
        descriptor: usize,
        kind: u32,
    },
    InvalidTupleWidth {
        descriptor: usize,
        width: u32,
    },
    InvalidTupleBitWidth {
        descriptor: usize,
        word: usize,
        bits: u32,
    },
    NonzeroUnusedTupleBit {
        descriptor: usize,
        word: usize,
        bits: u32,
    },
    NonzeroUnusedDescriptorWord {
        descriptor: usize,
        word: usize,
        value: u32,
    },
    SourceRangeOverflow {
        descriptor: usize,
    },
    SourceRangeOutOfBounds {
        descriptor: usize,
        end_word: usize,
        sub_words_per_row: usize,
    },
    EmptyTable {
        descriptor: usize,
    },
    DestinationIndexOutOfRange {
        descriptor: usize,
        index: u32,
        count: usize,
    },
    DestinationTooSmall {
        descriptor: usize,
        index: usize,
        required_words: usize,
        actual_words: usize,
    },
    DestinationLengthNotMultiple {
        descriptor: usize,
        index: usize,
        destination_words: usize,
        table_size: usize,
    },
    DestinationTableSizeMismatch {
        descriptor: usize,
        index: usize,
        expected_table_size: usize,
        actual_table_size: usize,
    },
    UnusedDestination(usize),
    LutIndexOutOfRange {
        descriptor: usize,
        index: u32,
        count: usize,
    },
    LutSizeMismatch {
        descriptor: usize,
        index: usize,
        expected_words: usize,
        actual_words: usize,
    },
    LutValueOutOfRange {
        descriptor: usize,
        index: usize,
        offset: usize,
        value: u32,
        table_size: usize,
    },
    UnusedLut(usize),
    /// A dependent tuple such as `(a, b, a ^ b)` cannot be represented by the
    /// current fold ABI. Silently bounding its 24-bit fold to an xor8 LUT would
    /// discard valid rows.
    UnsupportedDependentTupleMapping {
        descriptor: usize,
        tuple_bits: u32,
        lut_words: usize,
    },
    InvalidMemoryDescriptor {
        descriptor: usize,
    },
    InvalidXorDescriptor {
        descriptor: usize,
        kind: u32,
    },
    AliasedMemoryDestinations {
        descriptor: usize,
        index: u32,
    },
    SlotShapeMismatch {
        role: &'static str,
        expected: usize,
        actual: usize,
    },
    DuplicateSlot(ArenaSlotId),
    SlotSizeMismatch {
        slot: ArenaSlotId,
        expected_words: usize,
        actual_words: usize,
    },
    SlotMisaligned(ArenaSlotId),
    ContextMismatch(ArenaSlotId),
    ConflictingDestination(ArenaSlotId),
    BlakeGFusionShape(&'static str),
    BlakeGDirectLutContent(BlakeGDirectLutContentError),
    FeedAuthority(WitnessFeedAuthorityError),
    ClearAuthority(WitnessFeedClearAuthorityError),
    SourceUploadGenerationOverflow,
    KernelLaunchFailed,
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedWitnessFeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "prepared witness feed rejected: {self:?}")
    }
}

impl std::error::Error for PreparedWitnessFeedError {}

impl From<ArenaError> for PreparedWitnessFeedError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedWitnessFeedError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

impl From<BlakeGDirectLutContentError> for PreparedWitnessFeedError {
    fn from(value: BlakeGDirectLutContentError) -> Self {
        Self::BlakeGDirectLutContent(value)
    }
}

impl From<WitnessFeedAuthorityError> for PreparedWitnessFeedError {
    fn from(value: WitnessFeedAuthorityError) -> Self {
        Self::FeedAuthority(value)
    }
}

impl From<WitnessFeedClearAuthorityError> for PreparedWitnessFeedError {
    fn from(value: WitnessFeedClearAuthorityError) -> Self {
        Self::ClearAuthority(value)
    }
}

/// Validate the complete descriptor/LUT/destination ABI without requiring CUDA.
pub fn witness_feed_workspace_requirements(
    row_count: usize,
    sub_words_per_row: usize,
    descriptors: &[u32],
    luts: &[Vec<u32>],
    multiplicity_words: &[usize],
) -> Result<WitnessFeedWorkspaceRequirements, PreparedWitnessFeedError> {
    if row_count == 0 {
        return Err(PreparedWitnessFeedError::ZeroRows);
    }
    u32::try_from(row_count).map_err(|_| PreparedWitnessFeedError::RowCountOverflow)?;
    if sub_words_per_row == 0 {
        return Err(PreparedWitnessFeedError::ZeroSubWords);
    }
    let source_words = row_count
        .checked_mul(sub_words_per_row)
        .ok_or(PreparedWitnessFeedError::SizeOverflow)?;
    if descriptors.is_empty() {
        return Err(PreparedWitnessFeedError::NoDescriptors);
    }
    if !descriptors
        .len()
        .is_multiple_of(WITNESS_FEED_DESCRIPTOR_WORDS)
    {
        return Err(PreparedWitnessFeedError::DescriptorStrideMismatch(
            descriptors.len(),
        ));
    }
    u32::try_from(descriptors.len() / WITNESS_FEED_DESCRIPTOR_WORDS)
        .map_err(|_| PreparedWitnessFeedError::SizeOverflow)?;
    if multiplicity_words.is_empty() {
        return Err(PreparedWitnessFeedError::NoMultiplicityDestinations);
    }
    if let Some(index) = luts.iter().position(Vec::is_empty) {
        return Err(PreparedWitnessFeedError::EmptyLut(index));
    }
    if let Some(index) = multiplicity_words.iter().position(|&words| words == 0) {
        return Err(PreparedWitnessFeedError::EmptyMultiplicityDestination(
            index,
        ));
    }

    let mut used_luts = vec![false; luts.len()];
    let mut used_destinations = vec![false; multiplicity_words.len()];
    let mut destination_table_sizes = vec![None; multiplicity_words.len()];
    for (descriptor, entry) in descriptors
        .chunks_exact(WITNESS_FEED_DESCRIPTOR_WORDS)
        .enumerate()
    {
        validate_descriptor(
            descriptor,
            entry,
            sub_words_per_row,
            luts,
            multiplicity_words,
            &mut used_luts,
            &mut used_destinations,
            &mut destination_table_sizes,
        )?;
    }
    if let Some(index) = used_luts.iter().position(|&used| !used) {
        return Err(PreparedWitnessFeedError::UnusedLut(index));
    }
    if let Some(index) = used_destinations.iter().position(|&used| !used) {
        return Err(PreparedWitnessFeedError::UnusedDestination(index));
    }

    Ok(WitnessFeedWorkspaceRequirements {
        row_count,
        sub_words_per_row,
        source_words,
        descriptor_words: descriptors.len(),
        descriptor_count: descriptors.len() / WITNESS_FEED_DESCRIPTOR_WORDS,
        lut_words: luts.iter().map(Vec::len).collect(),
        lut_pointer_words: pointer_words(luts.len())?,
        multiplicity_words: multiplicity_words.to_vec(),
        multiplicity_pointer_words: pointer_words(multiplicity_words.len())?,
    })
}

pub fn witness_feed_clear_workspace_requirements(
    destination_words: &[usize],
) -> Result<WitnessFeedClearWorkspaceRequirements, PreparedWitnessFeedError> {
    if destination_words.is_empty() {
        return Err(PreparedWitnessFeedError::NoMultiplicityDestinations);
    }
    if let Some(index) = destination_words.iter().position(|&words| words == 0) {
        return Err(PreparedWitnessFeedError::EmptyMultiplicityDestination(
            index,
        ));
    }
    let max_destination_words = *destination_words.iter().max().unwrap();
    u32::try_from(destination_words.len()).map_err(|_| PreparedWitnessFeedError::SizeOverflow)?;
    if destination_words.len() > u16::MAX as usize {
        return Err(PreparedWitnessFeedError::SizeOverflow);
    }
    u32::try_from(max_destination_words).map_err(|_| PreparedWitnessFeedError::SizeOverflow)?;
    Ok(WitnessFeedClearWorkspaceRequirements {
        destination_words: destination_words.to_vec(),
        destination_pointer_words: pointer_words(destination_words.len())?,
        destination_length_words: destination_words.len(),
        max_destination_words,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_descriptor(
    descriptor: usize,
    entry: &[u32],
    sub_words_per_row: usize,
    luts: &[Vec<u32>],
    multiplicity_words: &[usize],
    used_luts: &mut [bool],
    used_destinations: &mut [bool],
    destination_table_sizes: &mut [Option<usize>],
) -> Result<(), PreparedWitnessFeedError> {
    let width = entry[1];
    if !(1..=WITNESS_FEED_MAX_TUPLE_WORDS as u32).contains(&width) {
        return Err(PreparedWitnessFeedError::InvalidTupleWidth { descriptor, width });
    }
    let word_base = entry[0] as usize;
    let end_word = word_base
        .checked_add(width as usize)
        .ok_or(PreparedWitnessFeedError::SourceRangeOverflow { descriptor })?;
    if end_word > sub_words_per_row {
        return Err(PreparedWitnessFeedError::SourceRangeOutOfBounds {
            descriptor,
            end_word,
            sub_words_per_row,
        });
    }
    let table_size = entry[8] as usize;
    if table_size == 0 {
        return Err(PreparedWitnessFeedError::EmptyTable { descriptor });
    }
    match entry[11] {
        0 => validate_fold_descriptor(
            descriptor,
            entry,
            width as usize,
            table_size,
            luts,
            multiplicity_words,
            used_luts,
            used_destinations,
            destination_table_sizes,
        ),
        1 => validate_memory_descriptor(
            descriptor,
            entry,
            width as usize,
            table_size,
            multiplicity_words,
            used_destinations,
            destination_table_sizes,
        ),
        2 => validate_xor_lut_descriptor(
            descriptor,
            entry,
            width as usize,
            table_size,
            luts,
            multiplicity_words,
            used_luts,
            used_destinations,
            destination_table_sizes,
        ),
        3 => validate_xor12_descriptor(
            descriptor,
            entry,
            width as usize,
            table_size,
            multiplicity_words,
            used_destinations,
            destination_table_sizes,
        ),
        kind => Err(PreparedWitnessFeedError::InvalidDescriptorKind { descriptor, kind }),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_xor_lut_descriptor(
    descriptor: usize,
    entry: &[u32],
    width: usize,
    table_size: usize,
    luts: &[Vec<u32>],
    multiplicity_words: &[usize],
    used_luts: &mut [bool],
    used_destinations: &mut [bool],
    destination_table_sizes: &mut [Option<usize>],
) -> Result<(), PreparedWitnessFeedError> {
    let bits = entry[2];
    if width != 3
        || !(1..16).contains(&bits)
        || entry[3] != bits
        || entry[4] != bits
        || entry[5..7].iter().any(|&value| value != 0)
        || entry[9] == WITNESS_FEED_NO_LUT
        || entry[12] != 0
        || entry[13] != 0
        || (1usize << (2 * bits)) != table_size
    {
        return Err(PreparedWitnessFeedError::InvalidXorDescriptor {
            descriptor,
            kind: 2,
        });
    }
    validate_destination(
        descriptor,
        entry[10],
        entry[7],
        table_size,
        multiplicity_words,
        used_destinations,
        destination_table_sizes,
    )?;
    let lut_index = entry[9] as usize;
    let Some(lut) = luts.get(lut_index) else {
        return Err(PreparedWitnessFeedError::LutIndexOutOfRange {
            descriptor,
            index: entry[9],
            count: luts.len(),
        });
    };
    if lut.len() != table_size {
        return Err(PreparedWitnessFeedError::LutSizeMismatch {
            descriptor,
            index: lut_index,
            expected_words: table_size,
            actual_words: lut.len(),
        });
    }
    if let Some((offset, &value)) = lut
        .iter()
        .enumerate()
        .find(|(_, value)| **value as usize >= table_size)
    {
        return Err(PreparedWitnessFeedError::LutValueOutOfRange {
            descriptor,
            index: lut_index,
            offset,
            value,
            table_size,
        });
    }
    used_luts[lut_index] = true;
    Ok(())
}

fn validate_xor12_descriptor(
    descriptor: usize,
    entry: &[u32],
    width: usize,
    table_size: usize,
    multiplicity_words: &[usize],
    used_destinations: &mut [bool],
    destination_table_sizes: &mut [Option<usize>],
) -> Result<(), PreparedWitnessFeedError> {
    if width != 3
        || entry[2..5] != [12, 12, 12]
        || entry[5..7].iter().any(|&value| value != 0)
        || entry[7] != 0
        || table_size != (1 << 20)
        || entry[9] != WITNESS_FEED_NO_LUT
        || entry[12] != 0
        || entry[13] != 0
    {
        return Err(PreparedWitnessFeedError::InvalidXorDescriptor {
            descriptor,
            kind: 3,
        });
    }
    // The derived high limbs address all sixteen columns, regardless of the
    // recorded relation_index (which is canonically zero for xor12).
    validate_destination(
        descriptor,
        entry[10],
        15,
        table_size,
        multiplicity_words,
        used_destinations,
        destination_table_sizes,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_fold_descriptor(
    descriptor: usize,
    entry: &[u32],
    width: usize,
    table_size: usize,
    luts: &[Vec<u32>],
    multiplicity_words: &[usize],
    used_luts: &mut [bool],
    used_destinations: &mut [bool],
    destination_table_sizes: &mut [Option<usize>],
) -> Result<(), PreparedWitnessFeedError> {
    if entry[13] != 0 {
        return Err(PreparedWitnessFeedError::NonzeroUnusedDescriptorWord {
            descriptor,
            word: 13,
            value: entry[13],
        });
    }
    let mut tuple_bits = 0u32;
    for word in 0..WITNESS_FEED_MAX_TUPLE_WORDS {
        let bits = entry[2 + word];
        if word < width {
            if !(1..32).contains(&bits) {
                return Err(PreparedWitnessFeedError::InvalidTupleBitWidth {
                    descriptor,
                    word,
                    bits,
                });
            }
            tuple_bits = tuple_bits
                .checked_add(bits)
                .ok_or(PreparedWitnessFeedError::SizeOverflow)?;
            if tuple_bits > 32 {
                return Err(PreparedWitnessFeedError::InvalidTupleBitWidth {
                    descriptor,
                    word,
                    bits,
                });
            }
        } else if bits != 0 {
            return Err(PreparedWitnessFeedError::NonzeroUnusedTupleBit {
                descriptor,
                word,
                bits,
            });
        }
    }

    validate_destination(
        descriptor,
        entry[10],
        entry[7],
        table_size,
        multiplicity_words,
        used_destinations,
        destination_table_sizes,
    )?;
    if entry[9] == WITNESS_FEED_NO_LUT {
        return Ok(());
    }
    let lut_index = entry[9] as usize;
    let Some(lut) = luts.get(lut_index) else {
        return Err(PreparedWitnessFeedError::LutIndexOutOfRange {
            descriptor,
            index: entry[9],
            count: luts.len(),
        });
    };
    if lut.len() != table_size {
        return Err(PreparedWitnessFeedError::LutSizeMismatch {
            descriptor,
            index: lut_index,
            expected_words: table_size,
            actual_words: lut.len(),
        });
    }
    // A LUT-addressed fold must cover its complete tuple domain. This rejects
    // triple-xor's `(a,b,a^b)` width instead of silently dropping most rows.
    if tuple_bits >= usize::BITS || (1usize << tuple_bits) > lut.len() {
        return Err(PreparedWitnessFeedError::UnsupportedDependentTupleMapping {
            descriptor,
            tuple_bits,
            lut_words: lut.len(),
        });
    }
    if let Some((offset, &value)) = lut
        .iter()
        .enumerate()
        .find(|(_, value)| **value as usize >= table_size)
    {
        return Err(PreparedWitnessFeedError::LutValueOutOfRange {
            descriptor,
            index: lut_index,
            offset,
            value,
            table_size,
        });
    }
    used_luts[lut_index] = true;
    Ok(())
}

fn validate_memory_descriptor(
    descriptor: usize,
    entry: &[u32],
    width: usize,
    big_table_size: usize,
    multiplicity_words: &[usize],
    used_destinations: &mut [bool],
    destination_table_sizes: &mut [Option<usize>],
) -> Result<(), PreparedWitnessFeedError> {
    if width != 1
        || entry[2] != 31
        || entry[3..7].iter().any(|&bits| bits != 0)
        || entry[9] != WITNESS_FEED_NO_LUT
        || entry[12] == 0
    {
        return Err(PreparedWitnessFeedError::InvalidMemoryDescriptor { descriptor });
    }
    if entry[10] == entry[13] {
        return Err(PreparedWitnessFeedError::AliasedMemoryDestinations {
            descriptor,
            index: entry[10],
        });
    }
    validate_destination(
        descriptor,
        entry[10],
        entry[7],
        big_table_size,
        multiplicity_words,
        used_destinations,
        destination_table_sizes,
    )?;
    validate_destination(
        descriptor,
        entry[13],
        entry[7],
        entry[12] as usize,
        multiplicity_words,
        used_destinations,
        destination_table_sizes,
    )
}

fn validate_destination(
    descriptor: usize,
    raw_index: u32,
    relation_index: u32,
    table_size: usize,
    multiplicity_words: &[usize],
    used_destinations: &mut [bool],
    destination_table_sizes: &mut [Option<usize>],
) -> Result<(), PreparedWitnessFeedError> {
    let index = raw_index as usize;
    let Some(&actual_words) = multiplicity_words.get(index) else {
        return Err(PreparedWitnessFeedError::DestinationIndexOutOfRange {
            descriptor,
            index: raw_index,
            count: multiplicity_words.len(),
        });
    };
    let required_words = (relation_index as usize + 1)
        .checked_mul(table_size)
        .ok_or(PreparedWitnessFeedError::SizeOverflow)?;
    if required_words > actual_words {
        return Err(PreparedWitnessFeedError::DestinationTooSmall {
            descriptor,
            index,
            required_words,
            actual_words,
        });
    }
    if actual_words % table_size != 0 {
        return Err(PreparedWitnessFeedError::DestinationLengthNotMultiple {
            descriptor,
            index,
            destination_words: actual_words,
            table_size,
        });
    }
    match destination_table_sizes[index] {
        Some(expected_table_size) if expected_table_size != table_size => {
            return Err(PreparedWitnessFeedError::DestinationTableSizeMismatch {
                descriptor,
                index,
                expected_table_size,
                actual_table_size: table_size,
            });
        }
        None => destination_table_sizes[index] = Some(table_size),
        _ => {}
    }
    used_destinations[index] = true;
    Ok(())
}

fn pointer_words(count: usize) -> Result<usize, PreparedWitnessFeedError> {
    count
        .max(1)
        .checked_mul(POINTER_WORDS)
        .ok_or(PreparedWitnessFeedError::SizeOverflow)
}

/// One allocation-free, capture-safe feed launch.
pub struct PreparedWitnessFeedGraph<'a> {
    arena: &'a DeviceArena,
    contract: WitnessFeedContract,
    source: ArenaSlice,
    descriptors: ArenaSlice,
    lut_tables: Vec<ArenaSlice>,
    lut_pointers: ArenaSlice,
    multiplicity_destinations: Vec<ArenaSlice>,
    multiplicity_pointers: ArenaSlice,
    source_upload_generation: Cell<u64>,
    source_upload_receipt: Cell<Option<WitnessFeedSourceUploadReceipt>>,
}

/// Source-free prepared binding for the exact Blake-G producer/feed fusion.
/// It borrows only the canonical LUTs and shared count destinations; there is
/// no SubcomponentInputs slab, descriptor upload, pointer table, or feed launch.
pub struct PreparedBlakeGFusedFeed<'a> {
    arena: &'a DeviceArena,
    luts: [ArenaSlice; 4],
    counts: [ArenaSlice; 5],
    lut_content_identity: BlakeGDirectLutContentIdentity,
}

impl<'a> PreparedBlakeGFusedFeed<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        luts: [ArenaSlice; 4],
        luts_host: [&[u32]; 4],
        counts: [ArenaSlice; 5],
    ) -> Result<Self, PreparedWitnessFeedError> {
        if luts
            .iter()
            .zip(BLAKE_G_DIRECT_LUT_WORDS)
            .any(|(slice, words)| !slice.belongs_to(arena.context()) || slice.len_words() != words)
            || counts
                .iter()
                .zip(BLAKE_G_DIRECT_COUNT_WORDS)
                .any(|(slice, words)| {
                    !slice.belongs_to(arena.context()) || slice.len_words() != words
                })
        {
            return Err(PreparedWitnessFeedError::BlakeGFusionShape(
                "canonical LUT/count geometry drifted",
            ));
        }
        let lut_content_identity = BlakeGDirectLutContentIdentity::from_host_words(luts_host)?;
        for (slice, host) in luts.iter().zip(luts_host) {
            upload(arena, *slice, host)?;
        }
        ensure_distinct(luts.iter().chain(&counts).map(|slice| slice.id()))?;
        arena.context().sync()?;
        Ok(Self {
            arena,
            luts,
            counts,
            lut_content_identity,
        })
    }

    pub fn belongs_to(&self, arena: &DeviceArena) -> bool {
        core::ptr::eq(self.arena, arena)
    }

    pub fn luts(&self) -> [ArenaSlice; 4] {
        self.luts
    }

    pub fn counts(&self) -> [ArenaSlice; 5] {
        self.counts
    }

    /// Backend-computed identity of every uploaded LUT word in canonical Direct
    /// role order. Mutable count destinations are deliberately excluded: their
    /// zero-before-producer authority belongs to the prepared clear graph.
    pub const fn lut_content_identity(&self) -> &BlakeGDirectLutContentIdentity {
        &self.lut_content_identity
    }
}

/// One launch clears the exact ordered destination list supplied at prepare.
///
/// Proof-wide union completeness belongs to the producer catalog that binds
/// this graph; the backend contract deliberately does not infer semantic roles.
pub struct PreparedWitnessFeedClearGraph<'a> {
    arena: &'a DeviceArena,
    contract: WitnessFeedClearContract,
    destinations: Vec<ArenaSlice>,
    destination_pointers: ArenaSlice,
    destination_lengths: ArenaSlice,
}

impl<'a> PreparedWitnessFeedClearGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        destinations: &[ArenaSlice],
        slots: WitnessFeedClearWorkspaceSlots,
    ) -> Result<Self, PreparedWitnessFeedError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedWitnessFeedError::CudaUnavailable);
        }
        let requirements = witness_feed_clear_workspace_requirements(
            &destinations
                .iter()
                .map(|destination| destination.len_words())
                .collect::<Vec<_>>(),
        )?;
        let contract = WitnessFeedClearContract::compile(&requirements)?;
        requirements.arena_slot_requirements(slots)?;
        let destination_pointers = bind_min(
            arena,
            slots.destination_pointers,
            requirements.destination_pointer_words,
            WITNESS_FEED_POINTER_ALIGNMENT_WORDS,
        )?;
        let destination_lengths = bind_min(
            arena,
            slots.destination_lengths,
            requirements.destination_length_words,
            1,
        )?;
        ensure_distinct(
            destinations
                .iter()
                .map(|destination| destination.id())
                .chain([destination_pointers.id(), destination_lengths.id()]),
        )?;
        let destinations = destinations
            .iter()
            .zip(&requirements.destination_words)
            .map(|(&destination, &expected_words)| {
                bind_external_min(arena, destination, expected_words)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pointers = pointer_values(&destinations);
        let lengths = requirements
            .destination_words
            .iter()
            .map(|&words| u32::try_from(words).map_err(|_| PreparedWitnessFeedError::SizeOverflow))
            .collect::<Result<Vec<_>, _>>()?;
        let upload_result = (|| {
            upload(arena, destination_pointers, &pointers)?;
            upload(arena, destination_lengths, &lengths)
        })();
        // Always drain a possibly enqueued earlier copy before the borrowed
        // pointer/length vectors can be dropped.
        let sync_result = arena.context().sync();
        upload_result?;
        sync_result?;
        Ok(Self {
            arena,
            contract,
            destinations,
            destination_pointers,
            destination_lengths,
        })
    }

    pub fn launch(&self) -> Result<(), PreparedWitnessFeedError> {
        self.launch_on(self.arena.context().launch_context())
    }

    pub fn launch_on(&self, launch: CudaLaunchContext) -> Result<(), PreparedWitnessFeedError> {
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        let requirements = self.contract.requirements();
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_witness_feed_clear_on(
                self.destination_pointers.as_u32_ptr().cast(),
                self.destination_lengths.as_u32_ptr().cast_const(),
                requirements.destination_words.len() as u32,
                requirements.max_destination_words as u32,
                launch.stream_raw().as_ptr(),
            )
        };
        if code == 0 {
            Ok(())
        } else {
            Err(PreparedWitnessFeedError::KernelLaunchFailed)
        }
    }

    pub fn destinations(&self) -> &[ArenaSlice] {
        &self.destinations
    }

    pub fn belongs_to(&self, arena: &DeviceArena) -> bool {
        core::ptr::eq(self.arena, arena)
            && self
                .destinations
                .iter()
                .copied()
                .chain([self.destination_pointers, self.destination_lengths])
                .all(|slice| slice.belongs_to(arena.context()))
    }

    pub fn destination_pointers(&self) -> ArenaSlice {
        self.destination_pointers
    }

    pub fn destination_lengths(&self) -> ArenaSlice {
        self.destination_lengths
    }

    pub fn requirements(&self) -> &WitnessFeedClearWorkspaceRequirements {
        self.contract.requirements()
    }

    pub fn contract(&self) -> &WitnessFeedClearContract {
        &self.contract
    }
}

impl<'a> PreparedWitnessFeedGraph<'a> {
    /// Bind exact geometry, upload immutable launch data once, and drain setup
    /// before any graph capture begins. The kernel symbol is selected here
    /// from `STWO_CUDA_FEED_PRIVATIZED` (default OFF: global atomics).
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        arena: &'a DeviceArena,
        source: ArenaSlice,
        row_count: usize,
        sub_words_per_row: usize,
        descriptors_host: &[u32],
        luts_host: &[Vec<u32>],
        multiplicity_words: &[usize],
        slots: &WitnessFeedWorkspaceSlots,
    ) -> Result<Self, PreparedWitnessFeedError> {
        Self::prepare_with_mode(
            arena,
            source,
            row_count,
            sub_words_per_row,
            descriptors_host,
            luts_host,
            multiplicity_words,
            slots,
            witness_feed_mode_from_env(),
        )
    }

    /// [`Self::prepare`] with an explicit kernel selection. This constructor
    /// never reads `STWO_CUDA_FEED_PRIVATIZED`; immutable runtime generations
    /// use it to pin [`WitnessFeedLaunchMode::GlobalAtomics`], while native
    /// parity tests can select either mode on identical inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_mode(
        arena: &'a DeviceArena,
        source: ArenaSlice,
        row_count: usize,
        sub_words_per_row: usize,
        descriptors_host: &[u32],
        luts_host: &[Vec<u32>],
        multiplicity_words: &[usize],
        slots: &WitnessFeedWorkspaceSlots,
        mode: WitnessFeedLaunchMode,
    ) -> Result<Self, PreparedWitnessFeedError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedWitnessFeedError::CudaUnavailable);
        }
        let requirements = witness_feed_workspace_requirements(
            row_count,
            sub_words_per_row,
            descriptors_host,
            luts_host,
            multiplicity_words,
        )?;
        let contract =
            WitnessFeedContract::compile(&requirements, descriptors_host, luts_host, mode)?;
        requirements.arena_slot_requirements(slots)?;
        let source = bind_external_min(arena, source, requirements.source_words)?;

        let descriptors = bind_min(arena, slots.descriptors, requirements.descriptor_words, 1)?;
        let lut_tables = bind_many_exact(arena, &slots.lut_tables, &requirements.lut_words, 1)?;
        let lut_pointers = bind_min(
            arena,
            slots.lut_pointers,
            requirements.lut_pointer_words,
            WITNESS_FEED_POINTER_ALIGNMENT_WORDS,
        )?;
        let multiplicity_destinations = bind_many_exact(
            arena,
            &slots.multiplicity_destinations,
            &requirements.multiplicity_words,
            1,
        )?;
        let multiplicity_pointers = bind_min(
            arena,
            slots.multiplicity_pointers,
            requirements.multiplicity_pointer_words,
            WITNESS_FEED_POINTER_ALIGNMENT_WORDS,
        )?;
        ensure_distinct(
            std::iter::once(source.id())
                .chain(std::iter::once(descriptors.id()))
                .chain(lut_tables.iter().map(|slice| slice.id()))
                .chain(std::iter::once(lut_pointers.id()))
                .chain(multiplicity_destinations.iter().map(|slice| slice.id()))
                .chain(std::iter::once(multiplicity_pointers.id())),
        )?;

        let lut_pointer_values = if lut_tables.is_empty() {
            vec![0usize]
        } else {
            pointer_values(&lut_tables)
        };
        let multiplicity_pointer_values = pointer_values(&multiplicity_destinations);
        let upload_result = (|| {
            upload(arena, descriptors, descriptors_host)?;
            for (destination, lut) in lut_tables.iter().copied().zip(luts_host) {
                upload(arena, destination, lut)?;
            }
            upload(arena, lut_pointers, &lut_pointer_values)?;
            upload(arena, multiplicity_pointers, &multiplicity_pointer_values)
        })();
        // Drain after any enqueue failure so all borrowed host descriptors,
        // LUTs, and pointer tables remain live through the last possible copy.
        let sync_result = arena.context().sync();
        upload_result?;
        sync_result?;

        Ok(Self {
            arena,
            contract,
            source,
            descriptors,
            lut_tables,
            lut_pointers,
            multiplicity_destinations,
            multiplicity_pointers,
            source_upload_generation: Cell::new(0),
            source_upload_receipt: Cell::new(None),
        })
    }

    /// Enqueue only the prepared feed-count kernel on the proof stream.
    pub fn launch(&self) -> Result<(), PreparedWitnessFeedError> {
        self.launch_on(self.arena.context().launch_context())
    }

    pub fn launch_on(&self, launch: CudaLaunchContext) -> Result<(), PreparedWitnessFeedError> {
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        let requirements = self.contract.requirements();
        let code = unsafe {
            match self.contract.launch_mode() {
                WitnessFeedLaunchMode::GlobalAtomics => {
                    stwo_backend_cuda_kernels::raw::stwo_witness_feed_counts_on(
                        self.source.as_u32_ptr().cast_const(),
                        requirements.row_count as u32,
                        self.descriptors.as_u32_ptr().cast_const(),
                        requirements.descriptor_count as u32,
                        self.lut_pointers.as_u32_ptr().cast(),
                        self.multiplicity_pointers.as_u32_ptr().cast(),
                        launch.stream_raw().as_ptr(),
                    )
                }
                WitnessFeedLaunchMode::Privatized => {
                    stwo_backend_cuda_kernels::raw::stwo_witness_feed_counts_privatized_on(
                        self.source.as_u32_ptr().cast_const(),
                        requirements.row_count as u32,
                        self.descriptors.as_u32_ptr().cast_const(),
                        requirements.descriptor_count as u32,
                        self.lut_pointers.as_u32_ptr().cast(),
                        self.multiplicity_pointers.as_u32_ptr().cast(),
                        launch.stream_raw().as_ptr(),
                    )
                }
            }
        };
        if code == 0 {
            Ok(())
        } else {
            Err(PreparedWitnessFeedError::KernelLaunchFailed)
        }
    }

    /// Kernel selection sealed at prepare.
    pub fn launch_mode(&self) -> WitnessFeedLaunchMode {
        self.contract.launch_mode()
    }

    pub fn requirements(&self) -> &WitnessFeedWorkspaceRequirements {
        self.contract.requirements()
    }

    pub fn contract(&self) -> &WitnessFeedContract {
        &self.contract
    }

    pub fn source(&self) -> ArenaSlice {
        self.source
    }

    pub fn belongs_to(&self, arena: &DeviceArena) -> bool {
        core::ptr::eq(self.arena, arena)
            && std::iter::once(self.source)
                .chain(std::iter::once(self.descriptors))
                .chain(self.lut_tables.iter().copied())
                .chain(std::iter::once(self.lut_pointers))
                .chain(self.multiplicity_destinations.iter().copied())
                .chain(std::iter::once(self.multiplicity_pointers))
                .all(|slice| slice.belongs_to(arena.context()))
    }

    /// Upload or refresh the statement-varying word-major source before graph
    /// capture and publish the only current receipt after the copy is fenced.
    pub fn upload_source(
        &self,
        words: &[u32],
    ) -> Result<WitnessFeedSourceUploadReceipt, PreparedWitnessFeedError> {
        if words.len() != self.contract.requirements().source_words {
            return Err(PreparedWitnessFeedError::SlotSizeMismatch {
                slot: self.source.id(),
                expected_words: self.contract.requirements().source_words,
                actual_words: words.len(),
            });
        }
        let generation =
            source_upload::next_source_upload_generation(self.source_upload_generation.get())?;
        let binding = source_upload::WitnessFeedSourceUploadBinding::new(
            self.arena,
            &self.contract,
            self.source,
        );
        let receipt = WitnessFeedSourceUploadReceipt::prepare(binding, words, generation)?;

        // Once a valid attempt begins, no earlier receipt may attest the
        // potentially changed device bytes. Advance independently so a failed
        // attempt cannot reuse its generation on a later retry.
        self.source_upload_generation.set(generation);
        self.source_upload_receipt.set(None);
        let upload_result = upload(self.arena, self.source, words);
        // Drain even after an enqueue error: an earlier or partial async copy
        // may still reference the borrowed host words.
        let sync_result = self.arena.context().sync();
        upload_result?;
        sync_result?;

        self.source_upload_receipt.set(Some(receipt));
        Ok(receipt)
    }

    pub fn source_upload_receipt(&self) -> Option<WitnessFeedSourceUploadReceipt> {
        self.source_upload_receipt.get()
    }

    pub fn source_upload_is_current(&self, receipt: &WitnessFeedSourceUploadReceipt) -> bool {
        let binding = source_upload::WitnessFeedSourceUploadBinding::new(
            self.arena,
            &self.contract,
            self.source,
        );
        self.source_upload_receipt.get() == Some(*receipt)
            && receipt.matches(binding, self.source_upload_generation.get())
    }

    pub fn multiplicity_destinations(&self) -> &[ArenaSlice] {
        &self.multiplicity_destinations
    }

    pub fn lut_tables(&self) -> &[ArenaSlice] {
        &self.lut_tables
    }

    pub fn descriptors(&self) -> ArenaSlice {
        self.descriptors
    }

    pub fn lut_pointers(&self) -> ArenaSlice {
        self.lut_pointers
    }

    pub fn multiplicity_pointers(&self) -> ArenaSlice {
        self.multiplicity_pointers
    }

    /// Immutable descriptor storage sealed into the captured kernel arguments.
    pub fn descriptor_slices(&self) -> Vec<ArenaSlice> {
        let mut result = Vec::with_capacity(self.lut_tables.len() + 3);
        result.push(self.descriptors);
        result.extend(self.lut_tables.iter().copied());
        result.extend([self.lut_pointers, self.multiplicity_pointers]);
        result
    }
}

/// Clear the union of all feed destinations exactly once per arena slot. Call
/// this once before every set of producer feed launches; duplicate slices from
/// graphs sharing a target are intentionally coalesced.
pub fn clear_witness_feed_destinations_once(
    arena: &DeviceArena,
    destinations: &[ArenaSlice],
) -> Result<u64, PreparedWitnessFeedError> {
    let mut unique = BTreeMap::<ArenaSlotId, ArenaSlice>::new();
    for &destination in destinations {
        bind_external_min(arena, destination, destination.len_words())?;
        if let Some(previous) = unique.insert(destination.id(), destination) {
            if previous.as_u32_ptr() != destination.as_u32_ptr()
                || previous.len_words() != destination.len_words()
            {
                return Err(PreparedWitnessFeedError::ConflictingDestination(
                    destination.id(),
                ));
            }
        }
    }
    let mut bytes = 0usize;
    for destination in unique.into_values() {
        bytes = bytes
            .checked_add(destination.len_bytes())
            .ok_or(PreparedWitnessFeedError::SizeOverflow)?;
        unsafe {
            arena
                .context()
                .memset_async(destination.as_void_ptr(), 0, destination.len_bytes())?;
        }
    }
    u64::try_from(bytes).map_err(|_| PreparedWitnessFeedError::SizeOverflow)
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
) -> Result<(), PreparedWitnessFeedError> {
    let bytes = core::mem::size_of_val(values);
    if bytes > destination.len_bytes() {
        return Err(PreparedWitnessFeedError::SlotSizeMismatch {
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
    lengths: &[usize],
    alignment_words: usize,
) -> Result<Vec<ArenaSlice>, PreparedWitnessFeedError> {
    ids.iter()
        .zip(lengths)
        .map(|(&id, &words)| bind_min(arena, id, words, alignment_words))
        .collect()
}

fn bind_min(
    arena: &DeviceArena,
    id: ArenaSlotId,
    expected_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedWitnessFeedError> {
    let slice = arena.bind(id)?;
    let truncated = bind_external_min(arena, slice, expected_words)?;
    if (truncated.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedWitnessFeedError::SlotMisaligned(id));
    }
    Ok(truncated)
}

// Pooled arena slots are sized to the largest disjoint-lifetime sharer, so a
// requirement is a lower bound on physical capacity. The returned slice is
// truncated to exactly `expected_words`, making `len_words()` the logical
// requirement everywhere downstream — clears and launches must never observe
// the pooled surplus (same contract as prepared_witness_input's bind_min;
// undersized, misaligned, or foreign-context slots still fail closed).
// Callers must store and use the RETURNED slice, never the argument.
fn bind_external_min(
    arena: &DeviceArena,
    slice: ArenaSlice,
    expected_words: usize,
) -> Result<ArenaSlice, PreparedWitnessFeedError> {
    if slice.context_token() != arena.context().identity_token() {
        return Err(PreparedWitnessFeedError::ContextMismatch(slice.id()));
    }
    truncate_bound_slot(slice, expected_words)
}

/// Validate one slice's capacity and truncate it to the logical requirement
/// so `len_words()` never exposes the pooled surplus to clears or launches.
fn truncate_bound_slot(
    slice: ArenaSlice,
    expected_words: usize,
) -> Result<ArenaSlice, PreparedWitnessFeedError> {
    if slice.len_words() < expected_words {
        return Err(PreparedWitnessFeedError::SlotSizeMismatch {
            slot: slice.id(),
            expected_words,
            actual_words: slice.len_words(),
        });
    }
    Ok(slice.truncated(expected_words))
}

fn check_count(
    role: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), PreparedWitnessFeedError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PreparedWitnessFeedError::SlotShapeMismatch {
            role,
            expected,
            actual,
        })
    }
}

fn ensure_distinct(
    ids: impl IntoIterator<Item = ArenaSlotId>,
) -> Result<(), PreparedWitnessFeedError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(PreparedWitnessFeedError::DuplicateSlot(id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_slots_truncate_pooled_surplus_to_the_logical_requirement() {
        // Pooled physical slots are sized to the LARGEST epoch-disjoint
        // sharer; the multiplicity clear graph derives its per-destination
        // clear extents from `len_words()`, so the binder must expose only
        // the logical extent — clearing a whole pooled slot clobbers
        // cohabitants of the other epoch.
        let oversized = ArenaSlice::dangling_for_test(5, 1024);
        let bound = truncate_bound_slot(oversized, 320).unwrap();
        assert_eq!(bound.len_words(), 320);
        assert_eq!(bound.id(), oversized.id());
        assert_eq!(bound.as_u32_ptr(), oversized.as_u32_ptr());
        // Undersized slots still fail closed.
        assert!(matches!(
            truncate_bound_slot(ArenaSlice::dangling_for_test(5, 64), 320),
            Err(PreparedWitnessFeedError::SlotSizeMismatch { .. })
        ));
    }

    fn fold_descriptor(
        word_base: u32,
        bits: &[u32],
        relation: u32,
        table_size: u32,
        lut: u32,
        destination: u32,
    ) -> [u32; WITNESS_FEED_DESCRIPTOR_WORDS] {
        let mut entry = [0u32; WITNESS_FEED_DESCRIPTOR_WORDS];
        entry[0] = word_base;
        entry[1] = bits.len() as u32;
        entry[2..2 + bits.len()].copy_from_slice(bits);
        entry[7] = relation;
        entry[8] = table_size;
        entry[9] = lut;
        entry[10] = destination;
        entry
    }

    fn memory_descriptor() -> [u32; WITNESS_FEED_DESCRIPTOR_WORDS] {
        let mut entry = [0u32; WITNESS_FEED_DESCRIPTOR_WORDS];
        entry[0] = 7;
        entry[1] = 1;
        entry[2] = 31;
        entry[8] = 8;
        entry[9] = WITNESS_FEED_NO_LUT;
        entry[10] = 2;
        entry[11] = 1;
        entry[12] = 4;
        entry[13] = 3;
        entry
    }

    fn valid_geometry() -> (Vec<u32>, Vec<Vec<u32>>, Vec<usize>) {
        let mut descriptors = Vec::new();
        descriptors.extend(fold_descriptor(0, &[2, 2], 1, 16, 0, 0));
        descriptors.extend(fold_descriptor(
            2,
            &[1, 1, 1, 1, 1],
            0,
            32,
            WITNESS_FEED_NO_LUT,
            1,
        ));
        descriptors.extend(memory_descriptor());
        (
            descriptors,
            vec![(0..16).rev().collect()],
            vec![32, 32, 8, 4],
        )
    }

    #[test]
    fn pure_requirements_cover_descriptors_luts_and_destinations() {
        let (descriptors, luts, destinations) = valid_geometry();
        let requirements =
            witness_feed_workspace_requirements(32, 8, &descriptors, &luts, &destinations).unwrap();
        assert_eq!(requirements.source_words, 256);
        assert_eq!(requirements.descriptor_count, 3);
        assert_eq!(requirements.descriptor_words, 42);
        assert_eq!(requirements.lut_words, [16]);
        assert_eq!(requirements.multiplicity_words, [32, 32, 8, 4]);
        assert_eq!(requirements.lut_pointer_words, POINTER_WORDS);
        assert_eq!(requirements.multiplicity_pointer_words, 4 * POINTER_WORDS);

        let slots = WitnessFeedWorkspaceSlots {
            descriptors: ArenaSlotId(1),
            lut_tables: vec![ArenaSlotId(2)],
            lut_pointers: ArenaSlotId(3),
            multiplicity_destinations: vec![
                ArenaSlotId(4),
                ArenaSlotId(5),
                ArenaSlotId(6),
                ArenaSlotId(7),
            ],
            multiplicity_pointers: ArenaSlotId(8),
        };
        assert_eq!(
            requirements.arena_slot_requirements(&slots).unwrap().len(),
            8
        );
    }

    #[test]
    fn xor_tuple_geometry_is_explicit_and_malformed_kinds_fail_closed() {
        let mut triple_xor = fold_descriptor(0, &[8, 8, 8], 0, 1 << 16, 0, 0);
        triple_xor[11] = 2;
        let requirements = witness_feed_workspace_requirements(
            32,
            3,
            &triple_xor,
            &[vec![0; 1 << 16]],
            &[1 << 16],
        )
        .unwrap();
        assert_eq!(requirements.descriptor_count, 1);

        triple_xor[11] = 9;
        assert!(matches!(
            witness_feed_workspace_requirements(
                32,
                3,
                &triple_xor,
                &[vec![0; 1 << 16]],
                &[1 << 16]
            ),
            Err(PreparedWitnessFeedError::InvalidDescriptorKind { .. })
        ));

        triple_xor[11] = 2;
        triple_xor[4] = 7;
        assert!(matches!(
            witness_feed_workspace_requirements(
                32,
                3,
                &triple_xor,
                &[vec![0; 1 << 16]],
                &[1 << 16]
            ),
            Err(PreparedWitnessFeedError::InvalidXorDescriptor { kind: 2, .. })
        ));

        let mut xor12 = fold_descriptor(0, &[12, 12, 12], 0, 1 << 20, WITNESS_FEED_NO_LUT, 0);
        xor12[11] = 3;
        assert!(
            witness_feed_workspace_requirements(32, 3, &xor12, &[], &[16 * (1 << 20)],).is_ok()
        );

        let (descriptors, luts, destinations) = valid_geometry();
        let requirements =
            witness_feed_workspace_requirements(32, 8, &descriptors, &luts, &destinations).unwrap();
        let duplicate = ArenaSlotId(1);
        let slots = WitnessFeedWorkspaceSlots {
            descriptors: duplicate,
            lut_tables: vec![duplicate],
            lut_pointers: ArenaSlotId(3),
            multiplicity_destinations: vec![
                ArenaSlotId(4),
                ArenaSlotId(5),
                ArenaSlotId(6),
                ArenaSlotId(7),
            ],
            multiplicity_pointers: ArenaSlotId(8),
        };
        assert_eq!(
            requirements.arena_slot_requirements(&slots).unwrap_err(),
            PreparedWitnessFeedError::DuplicateSlot(duplicate)
        );
    }

    #[test]
    fn privatized_footprint_counts_touched_relation_columns() {
        // FOLD / dependent-XOR: one relation column of table_size words,
        // regardless of the relation index or LUT.
        let fold = fold_descriptor(0, &[2, 2], 3, 16, WITNESS_FEED_NO_LUT, 0);
        assert_eq!(witness_feed_privatized_footprint_words(&fold), 16);
        let mut xor4 = fold_descriptor(0, &[4, 4, 4], 0, 1 << 8, 0, 0);
        xor4[11] = 2;
        assert_eq!(witness_feed_privatized_footprint_words(&xor4), 1 << 8);

        // MEM-ID DECODE: big column plus small column.
        let memory = memory_descriptor();
        assert_eq!(
            witness_feed_privatized_footprint_words(&memory),
            8 + 4,
            "memory feeds cover the big and the small relation column"
        );

        // xor12 addresses all sixteen expanded multiplicity columns.
        let mut xor12 = fold_descriptor(0, &[12, 12, 12], 0, 1 << 20, WITNESS_FEED_NO_LUT, 0);
        xor12[11] = 3;
        assert_eq!(
            witness_feed_privatized_footprint_words(&xor12),
            16 * (1 << 20)
        );
    }

    #[test]
    fn shared_budget_boundary_is_exact_at_48kb() {
        assert_eq!(WITNESS_FEED_PRIVATIZED_SHARED_BYTES, 48 * 1024);
        assert_eq!(WITNESS_FEED_PRIVATIZED_SHARED_WORDS, 12288);

        // table_size * 4B == 48KB fits exactly; one more word does not.
        let at_budget = fold_descriptor(0, &[14], 0, 12288, WITNESS_FEED_NO_LUT, 0);
        assert!(witness_feed_descriptor_fits_shared(&at_budget));
        let over_budget = fold_descriptor(0, &[14], 0, 12289, WITNESS_FEED_NO_LUT, 0);
        assert!(!witness_feed_descriptor_fits_shared(&over_budget));

        // The memory split counts BOTH columns against the budget.
        let mut memory = memory_descriptor();
        memory[8] = 12280;
        memory[12] = 8;
        assert!(witness_feed_descriptor_fits_shared(&memory));
        memory[12] = 9;
        assert!(!witness_feed_descriptor_fits_shared(&memory));

        // xor12's validated 2^20 table can never privatize.
        let mut xor12 = fold_descriptor(0, &[12, 12, 12], 0, 1 << 20, WITNESS_FEED_NO_LUT, 0);
        xor12[11] = 3;
        assert!(!witness_feed_descriptor_fits_shared(&xor12));

        // Footprints larger than u32::MAX words must not wrap into "fits".
        let mut huge = fold_descriptor(0, &[12, 12, 12], 0, u32::MAX, WITNESS_FEED_NO_LUT, 0);
        huge[11] = 3;
        assert_eq!(
            witness_feed_privatized_footprint_words(&huge),
            16 * u64::from(u32::MAX)
        );
        assert!(!witness_feed_descriptor_fits_shared(&huge));
    }

    #[test]
    fn privatized_flag_requires_literal_one() {
        assert!(feed_privatized_flag_from(Some("1")));
        for raw in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("2"),
            Some("01"),
        ] {
            assert!(!feed_privatized_flag_from(raw), "{raw:?} must stay OFF");
        }
    }

    #[test]
    fn explicit_mode_constructor_is_host_visible() {
        let _constructor = PreparedWitnessFeedGraph::prepare_with_mode;
    }

    #[test]
    fn batched_clear_plans_one_pointer_and_length_table() {
        let requirements = witness_feed_clear_workspace_requirements(&[16, 32, 8]).unwrap();
        assert_eq!(requirements.destination_words, [16, 32, 8]);
        assert_eq!(requirements.max_destination_words, 32);
        assert_eq!(requirements.destination_length_words, 3);
        let slots = WitnessFeedClearWorkspaceSlots {
            destination_pointers: ArenaSlotId(70),
            destination_lengths: ArenaSlotId(71),
        };
        let requests = requirements.arena_slot_requirements(slots).unwrap();
        assert_eq!(requests[0].len_words, 3 * POINTER_WORDS);
        assert_eq!(requests[1].len_words, 3);
    }
}
