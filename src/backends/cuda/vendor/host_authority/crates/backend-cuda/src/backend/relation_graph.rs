//! Prepared, arena-backed CommonLookupElements execution.
//!
//! Static relation descriptors plus source/output pointer tables are uploaded once in
//! [`PreparedRelationGraph::prepare`]. [`PreparedRelationGraph::launch`] is the
//! single eager/capture sequence: proof-wide ragged pair generation, inverse and
//! fraction chaining, then segmented reduction, shift and prefix scans. It
//! allocates, transfers, and synchronizes nothing.

use core::ffi::c_void;
use std::collections::BTreeSet;

use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};

mod authority;
pub use authority::challenge::*;
pub use authority::*;

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const POINTER_WORDS: usize = core::mem::size_of::<*const u32>().div_ceil(WORD_BYTES);
const DESCRIPTOR_WORDS: usize = 16;
const USE_WORDS: usize = 7;
const REDUCTION_BLOCK: usize = 256;
const SECURE_FIELD_WORDS: usize = 4;
const INSTANCE_POINTER_TABLES: usize = 5;
const INSTANCE_GEOMETRY_WORDS: usize = 11;
const FRACTION_INVERSE_BLOCK_VALUES: usize = 1024;
const M31_MODULUS: u64 = 0x7fff_ffff;
const LARGE_MEMORY_VALUE_ID_BASE: u32 = 0x4000_0000;
const BLAKE_G_INPUT_COLUMNS: u32 = 6;
const BLAKE_G_LOGUP_COLUMNS: usize = 9;
const BLAKE_G_RELATION_IDS: [u32; 17] = [
    112_558_620,
    112_558_620,
    521_092_554,
    521_092_554,
    648_362_599,
    45_448_144,
    648_362_599,
    45_448_144,
    112_558_620,
    112_558_620,
    521_092_554,
    521_092_554,
    62_225_763,
    95_781_001,
    62_225_763,
    95_781_001,
    1_139_985_212,
];
/// Mirror of `RELATION_SCAN_TICKET_WORDS` in `relation_scan.cuh`: the ticket
/// counter (word 0) plus padding to keep the descriptor QM31 fields 16-byte
/// aligned.
const SCAN_TICKET_WORDS: usize = 4;
/// Mirror of `RELATION_SCAN_DESC_STRIDE` in `relation_scan.cuh`: one
/// partition descriptor = flag word (+3 pad) + aggregate QM31 + prefix QM31.
const SCAN_DESC_STRIDE_WORDS: usize = 12;
const XOR12_ROWS: u32 = 1 << 20;
pub const RELATION_POINTER_ALIGNMENT_WORDS: usize =
    core::mem::align_of::<*const u32>() / WORD_BYTES;

/// Width of the fused-lane eligibility bitmask passed by value into
/// `stwo_relation_fused_on` (must match `RELATION_FUSED_MASK_WORDS` in
/// `relation_fused.cuh`). 8 words = 256 instance bits.
pub const RELATION_FUSED_MASK_WORDS: usize = 8;
/// Proofs with more relation instances than mask bits fail closed to the
/// 3-stage lane as a whole.
pub const RELATION_FUSED_MAX_INSTANCES: usize = RELATION_FUSED_MASK_WORDS * 32;
/// Original two-pass fused lane bound. Every fused batch at or below this
/// tuple width uses suffix/recompute; wider admitted tuples use one-read.
const RELATION_FUSED_NARROW_MAX_TUPLE_WORDS: u32 = 32;
/// Audited one-read wide-lane tuple bound. This covers every generated Cairo
/// relation width (33, 36, 43, 58, 73, 87 and 126) without turning an arbitrary
/// future relation into an unmeasured fused launch.
pub const RELATION_FUSED_MAX_TUPLE_WORDS: u32 = 126;
/// The one-read lane batches at most 512 fractions in shared memory. Every
/// generated Cairo relation batch fits this column bound; larger admitted
/// batches retain the suffix/recompute fallback below.
const RELATION_FUSED_ONE_READ_MAX_COLUMNS: usize = 512;
/// Defensive fused-lane bound on chain length. Running state stays three
/// QM31 registers regardless of column count; this only guards pathological
/// programs whose per-thread column walk would dominate a single launch.
pub const RELATION_FUSED_MAX_COLUMNS: usize = 1024;

/// Selects which kernel pipeline [`PreparedRelationGraph::launch_with_mode`]
/// submits. Both modes produce byte-identical committed columns and claimed
/// sums. `Fused` is selected either by a mode-sealed compact preparation or,
/// for a full preparation, by `STWO_CUDA_RELATION_FUSED=1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationLaunchMode {
    /// pairs -> ragged batch inverse -> global fraction chain (default).
    ThreeStage,
    /// One fused kernel that never materializes the denominator slab;
    /// fused-ineligible instances still run per-instance 3-stage kernels.
    Fused,
}

/// Test-only selector for the same-binary adaptive relation differential.
/// Neither variant participates in [`PreparedRelationGraph::launch`].
#[cfg(feature = "test-only-relation-ab")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RelationFusedTestStrategy {
    Adaptive = 0,
    /// Exact pre-change selector: every fused batch with at most 512 columns
    /// takes the one-read lane, independent of tuple width.
    AllOneReadBaseline = 1,
}

/// Exact CUDA-loaded function facts used by the relation A/B receipt.
#[cfg(feature = "test-only-relation-ab")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationFusedTestFunctionResources {
    pub abi_version: u32,
    pub max_threads_per_block: u32,
    pub registers_per_thread: u32,
    pub binary_version: u32,
    pub ptx_version: u32,
    pub reserved: u32,
    pub local_bytes: u64,
    pub static_shared_bytes: u64,
}

/// Selects which tail sequence follows the pipeline body. Both tails scan
/// exactly the same element sequence (the last interaction column in coset
/// scan order) and produce byte-identical committed columns and claimed sums;
/// `Scan` is opt-in via `STWO_CUDA_RELATION_SCAN_TAIL=1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationTailMode {
    /// Segmented reduce + shift + 3-kernel block scan (default; 5 kernels).
    Segmented,
    /// Single-pass decoupled-lookback scan folding reduce/claimed-sum into
    /// the same pass, plus a shift fixup (memset + 2 kernels).
    Scan,
}

fn relation_batch_max_tuple_words(batch: &RelationBatchProgram) -> u32 {
    batch
        .columns
        .iter()
        .flat_map(|column| &column.uses)
        .map(|relation_use| relation_use.tuple_words)
        .max()
        .unwrap_or(0)
}

/// Static admissibility for the one-read shared Montgomery lane. Runtime
/// selection still keeps <=32-word tuples on suffix/recompute; this predicate
/// proves that wider tuples fit the 512-fraction tile and audited width.
pub fn relation_batch_one_read_eligible(batch: &RelationBatchProgram) -> bool {
    batch.columns.len() <= RELATION_FUSED_ONE_READ_MAX_COLUMNS
        && relation_batch_max_tuple_words(batch) <= RELATION_FUSED_MAX_TUPLE_WORDS
}

fn relation_batch_prefers_one_read(batch: &RelationBatchProgram) -> bool {
    relation_batch_max_tuple_words(batch) > RELATION_FUSED_NARROW_MAX_TUPLE_WORDS
        && relation_batch_one_read_eligible(batch)
}

/// Static fused-lane eligibility of every instance of `batch`. Tuples of at
/// most 32 words use suffix/recompute through 1024 columns. Wider tuples use
/// one-read only when they fit its 512-fraction tile and 126-word audited
/// width. Anything outside either envelope keeps the proven 3-stage path.
pub fn relation_batch_fused_eligible(batch: &RelationBatchProgram) -> bool {
    if batch.columns.len() > RELATION_FUSED_MAX_COLUMNS {
        return false;
    }
    relation_batch_prefers_one_read(batch)
        || relation_batch_max_tuple_words(batch) <= RELATION_FUSED_NARROW_MAX_TUPLE_WORDS
}

/// Pack per-instance eligibility flags into the device kernel's by-value
/// mask. `None` means the proof cannot use the fused lane at all (more
/// instances than mask bits) and must fail closed to the 3-stage path.
fn fused_eligibility_mask(eligible: &[bool]) -> Option<[u32; RELATION_FUSED_MASK_WORDS]> {
    if eligible.len() > RELATION_FUSED_MAX_INSTANCES {
        return None;
    }
    let mut mask = [0u32; RELATION_FUSED_MASK_WORDS];
    for (instance, &flag) in eligible.iter().enumerate() {
        if flag {
            mask[instance / 32] |= 1u32 << (instance % 32);
        }
    }
    Some(mask)
}

/// `STWO_CUDA_RELATION_FUSED=1` opts the default [`PreparedRelationGraph::launch`]
/// into the fused lane. Read once per process so eager runs, capture and
/// replay all observe one mode.
fn fused_launch_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("STWO_CUDA_RELATION_FUSED").as_deref() == Ok("1"))
}

/// `STWO_CUDA_RELATION_SCAN_TAIL=1` opts every implicit-tail launch into the
/// decoupled-lookback scan tail. Read once per process so eager runs, capture
/// and replay all observe one mode. Default OFF: the segmented tail stays the
/// proven fallback.
fn scan_tail_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("STWO_CUDA_RELATION_SCAN_TAIL").as_deref() == Ok("1"))
}

fn validate_prepared_launch_mode(
    prepared: RelationLaunchMode,
    requested: RelationLaunchMode,
) -> Result<(), RelationGraphError> {
    if prepared == RelationLaunchMode::Fused && requested != RelationLaunchMode::Fused {
        return Err(RelationGraphError::CompactFusedLaunchModeMismatch { requested });
    }
    Ok(())
}

fn implicit_launch_mode(prepared: RelationLaunchMode) -> RelationLaunchMode {
    if prepared == RelationLaunchMode::Fused || fused_launch_enabled() {
        RelationLaunchMode::Fused
    } else {
        RelationLaunchMode::ThreeStage
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RelationTupleKind {
    LookupWords = 0,
    MemoryAddressChunk = 1,
    MemoryBigLimbs = 2,
    MemoryBigValue = 3,
    MemorySmallLimbs = 4,
    MemorySmallValue = 5,
    BitwiseXor12 = 6,
    /// One source-table pointer per tuple operand. Tuple word zero remains the
    /// descriptor's sealed relation id, so no constants are materialized.
    ProjectedColumns = 7,
    /// Exact Blake-G row reconstruction from six uncommitted input columns.
    /// Only the isolated fused kernel may execute this descriptor kind.
    BlakeGInputs = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RelationMultiplicityKind {
    One = 0,
    Enabler = 1,
    LookupWord = 2,
    MemoryAddressChunk = 3,
    MemoryBig = 4,
    MemorySmall = 5,
    BitwiseXor12 = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationUseDescriptor {
    pub tuple_kind: RelationTupleKind,
    pub tuple_arg: u32,
    pub tuple_words: u32,
    pub relation_id: u32,
    pub multiplicity_kind: RelationMultiplicityKind,
    pub multiplicity_arg: u32,
    pub negative: bool,
}

impl RelationUseDescriptor {
    fn to_words(self) -> [u32; USE_WORDS] {
        [
            self.tuple_kind as u32,
            self.tuple_arg,
            self.tuple_words,
            self.relation_id,
            self.multiplicity_kind as u32,
            self.multiplicity_arg,
            self.negative as u32,
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationColumnDescriptor {
    pub uses: Vec<RelationUseDescriptor>,
}

impl RelationColumnDescriptor {
    fn to_words(&self) -> Result<[u32; DESCRIPTOR_WORDS], RelationGraphError> {
        if !(1..=2).contains(&self.uses.len()) {
            return Err(RelationGraphError::InvalidColumnArity(self.uses.len()));
        }
        let mut output = [0u32; DESCRIPTOR_WORDS];
        output[0] = self.uses.len() as u32;
        for (index, relation_use) in self.uses.iter().enumerate() {
            let start = 1 + index * USE_WORDS;
            output[start..start + USE_WORDS].copy_from_slice(&relation_use.to_words());
        }
        Ok(output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationSourceLayout {
    /// One contiguous word-major lookup buffer.
    LookupWords { words: u32 },
    /// One column pointer per tuple operand; relation ids and standard
    /// multiplicities stay in their existing descriptors.
    ProjectedColumns { columns: u32 },
    /// Six canonical Blake-G raw input columns. The relation kernel derives
    /// every operand and the real-row enabler without an intermediate slab.
    BlakeGInputs,
    /// `[id0, mult0, id1, mult1, ...]` column pointers.
    MemoryAddress { chunks: u32 },
    /// `[value limbs..., multiplicity]` column pointers.
    MemoryBig { value_words: u32 },
    /// `[value limbs..., multiplicity]` column pointers.
    MemorySmall { value_words: u32 },
    /// One multiplicity column pointer per expanded high-bit pair.
    BitwiseXor12 { multiplicity_columns: u32 },
}

impl RelationSourceLayout {
    pub fn pointer_count(self) -> Result<usize, RelationGraphError> {
        let count = match self {
            Self::LookupWords { .. } => 1,
            Self::ProjectedColumns { columns } => columns,
            Self::BlakeGInputs => BLAKE_G_INPUT_COLUMNS,
            Self::MemoryAddress { chunks } => chunks
                .checked_mul(2)
                .ok_or(RelationGraphError::SizeOverflow)?,
            Self::MemoryBig { value_words } | Self::MemorySmall { value_words } => value_words
                .checked_add(1)
                .ok_or(RelationGraphError::SizeOverflow)?,
            Self::BitwiseXor12 {
                multiplicity_columns,
            } => multiplicity_columns,
        };
        usize::try_from(count).map_err(|_| RelationGraphError::SizeOverflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationRowExtent {
    Exact {
        n_real_rows: u32,
        padded_rows: u32,
        /// Added to derived memory ids. Zero for every non-big-memory source.
        source_offset_rows: u32,
    },
    Bounded {
        observed_rows: u32,
        max_rows: u32,
        padded_capacity: u32,
    },
}

impl RelationRowExtent {
    pub fn capacity_rows(self) -> u32 {
        match self {
            Self::Exact { padded_rows, .. } => padded_rows,
            Self::Bounded {
                padded_capacity, ..
            } => padded_capacity,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationBatchProgram {
    pub source_layout: RelationSourceLayout,
    pub columns: Vec<RelationColumnDescriptor>,
    /// Empty for an absent component. Memory-big templates may have many.
    pub instances: Vec<RelationRowExtent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationKernelProgram {
    pub relation_graph_hash: u64,
    pub template_use_count: usize,
    pub max_alpha_powers: u32,
    pub batches: Vec<RelationBatchProgram>,
}

/// Admission gate for the isolated six-input Blake-G relation kernel. The
/// descriptor order is part of its ABI: eight paired XOR columns followed by
/// one negative, enabler-gated Blake-G column.
pub fn blake_g_inputs_batch_is_exact(batch: &RelationBatchProgram) -> bool {
    if batch.source_layout != RelationSourceLayout::BlakeGInputs
        || batch.columns.len() != BLAKE_G_LOGUP_COLUMNS
        || batch.columns[..8]
            .iter()
            .any(|column| column.uses.len() != 2)
        || batch.columns[8].uses.len() != 1
    {
        return false;
    }
    batch
        .columns
        .iter()
        .flat_map(|column| &column.uses)
        .enumerate()
        .all(|(index, relation_use)| {
            let final_use = index + 1 == BLAKE_G_RELATION_IDS.len();
            relation_use.tuple_kind == RelationTupleKind::BlakeGInputs
                && relation_use.tuple_arg == index as u32
                && relation_use.tuple_words == if final_use { 21 } else { 4 }
                && relation_use.relation_id == BLAKE_G_RELATION_IDS[index]
                && relation_use.multiplicity_kind
                    == if final_use {
                        RelationMultiplicityKind::Enabler
                    } else {
                        RelationMultiplicityKind::One
                    }
                && relation_use.multiplicity_arg == 0
                && relation_use.negative == final_use
        })
}

impl RelationKernelProgram {
    pub fn validate(&self) -> Result<(), RelationGraphError> {
        if self.relation_graph_hash == 0 {
            return Err(RelationGraphError::InvalidGraphHash);
        }
        if self.max_alpha_powers == 0 {
            return Err(RelationGraphError::MissingAlphaPowers);
        }
        let mut use_count = 0usize;
        for (batch_index, batch) in self.batches.iter().enumerate() {
            if batch.columns.is_empty() {
                return Err(RelationGraphError::EmptyBatch(batch_index));
            }
            let _ = batch.source_layout.pointer_count()?;
            if matches!(batch.source_layout, RelationSourceLayout::BlakeGInputs)
                && !blake_g_inputs_batch_is_exact(batch)
            {
                return Err(RelationGraphError::InvalidBlakeGInputsBatch);
            }
            for column in &batch.columns {
                let _ = column.to_words()?;
                use_count = use_count
                    .checked_add(column.uses.len())
                    .ok_or(RelationGraphError::SizeOverflow)?;
                for relation_use in &column.uses {
                    validate_use(batch.source_layout, *relation_use)?;
                    if relation_use.tuple_words == 0
                        || relation_use.tuple_words > self.max_alpha_powers
                    {
                        return Err(RelationGraphError::TupleWidthOutOfBounds {
                            width: relation_use.tuple_words,
                            max: self.max_alpha_powers,
                        });
                    }
                    if relation_use.relation_id == 0 || relation_use.relation_id >= 0x7fff_ffff {
                        return Err(RelationGraphError::InvalidRelationId(
                            relation_use.relation_id,
                        ));
                    }
                }
            }
            let columns =
                u32::try_from(batch.columns.len()).map_err(|_| RelationGraphError::SizeOverflow)?;
            for extent in &batch.instances {
                validate_extent(batch.source_layout, *extent)?;
                let rows = extent.capacity_rows();
                if u64::from(rows) * u64::from(columns) > i32::MAX as u64 {
                    return Err(RelationGraphError::FractionChainTooLarge { rows, columns });
                }
            }
            if matches!(batch.source_layout, RelationSourceLayout::MemoryBig { .. }) {
                let mut expected_offset = 0u32;
                for extent in &batch.instances {
                    if let RelationRowExtent::Exact {
                        padded_rows,
                        source_offset_rows,
                        ..
                    } = *extent
                    {
                        if source_offset_rows != expected_offset {
                            return Err(RelationGraphError::InvalidRowExtent);
                        }
                        expected_offset = expected_offset
                            .checked_add(padded_rows)
                            .ok_or(RelationGraphError::SizeOverflow)?;
                    }
                }
            }
        }
        if use_count != self.template_use_count {
            return Err(RelationGraphError::UseCoverageMismatch {
                expected: self.template_use_count,
                actual: use_count,
            });
        }
        Ok(())
    }

    pub fn requirements(&self) -> Result<RelationGraphRequirements, RelationGraphError> {
        relation_graph_requirements(self)
    }

    /// Exact arena requirements for `mode`. The fused layout keeps full
    /// denominator slabs only for instances that must use the 3-stage
    /// fallback; eligible instances receive one aligned sentinel word because
    /// the fused kernel never dereferences their denominator pointer.
    pub fn requirements_for_mode(
        &self,
        mode: RelationLaunchMode,
    ) -> Result<RelationGraphRequirements, RelationGraphError> {
        relation_graph_requirements_for_mode(self, mode)
    }

    fn descriptor_words(&self) -> Result<Vec<u32>, RelationGraphError> {
        let mut output = Vec::new();
        for batch in &self.batches {
            for column in &batch.columns {
                output.extend(column.to_words()?);
            }
        }
        Ok(output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationInstanceRequirement {
    pub batch_index: usize,
    pub instance_index: usize,
    pub row_capacity: u32,
    pub source_pointer_words: usize,
    pub output_pointer_words: usize,
    pub output_coordinate_count: usize,
    pub output_coordinate_words: usize,
    /// Aggregate words across every output coordinate.
    pub output_words: usize,
    /// Full QM31 slab in 3-stage mode and for fused fallbacks; one aligned,
    /// intentionally untouched sentinel word for fused-eligible instances in
    /// a fused-mode preparation.
    pub denominator_words: usize,
    pub claimed_sum_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationGraphRequirements {
    pub descriptor_words: usize,
    pub alpha_words: usize,
    pub z_words: usize,
    pub inverse_words: usize,
    pub reduction_words: usize,
    pub scan_eval_words: usize,
    /// One-word compatibility sentinel; the proof-wide scan no longer uses CUB.
    pub scan_temp_words: usize,
    /// Ticket counter + one partition descriptor per row block, consumed by
    /// the decoupled-lookback scan tail (zeroed on-stream before each scan).
    pub scan_descriptor_words: usize,
    pub fraction_pointer_words: usize,
    pub fraction_geometry_words: usize,
    pub pair_blocks: u32,
    pub fraction_inverse_blocks: u32,
    pub fraction_chain_blocks: u32,
    pub instances: Vec<RelationInstanceRequirement>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationInstanceSlots {
    pub source_pointers: ArenaSlotId,
    pub output_pointers: ArenaSlotId,
    /// Exactly `4 * logup_columns` commit-source slots in interaction-column,
    /// secure-coordinate order. Numerators are fraction-chained in place.
    pub output_coordinates: Vec<ArenaSlotId>,
    pub denominators: ArenaSlotId,
    pub claimed_sum: ArenaSlotId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationGraphSlots {
    pub descriptors: ArenaSlotId,
    pub alphas: ArenaSlotId,
    pub z: ArenaSlotId,
    pub inverse_scratch: ArenaSlotId,
    pub reduction_a: ArenaSlotId,
    pub reduction_b: ArenaSlotId,
    pub scan_eval_scratch: ArenaSlotId,
    pub scan_temp_scratch: ArenaSlotId,
    /// Partition descriptors (ticket + flag/aggregate/prefix per row block)
    /// for the decoupled-lookback scan tail.
    pub scan_descriptors: ArenaSlotId,
    /// Proof-wide dispatch pointer tables in source, descriptor, output,
    /// denominator and claimed-sum order, followed by immutable ragged geometry.
    pub fraction_pointers: ArenaSlotId,
    pub fraction_geometry: ArenaSlotId,
    /// Active instances in deterministic `(batch, instance)` order.
    pub instances: Vec<RelationInstanceSlots>,
}

impl RelationGraphRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &RelationGraphSlots,
    ) -> Result<Vec<RelationArenaSlotRequirement>, RelationGraphError> {
        if slots.instances.len() != self.instances.len() {
            return Err(RelationGraphError::SlotShapeMismatch {
                expected: self.instances.len(),
                actual: slots.instances.len(),
            });
        }
        let mut output = vec![
            slot_requirement(slots.descriptors, self.descriptor_words, 1),
            slot_requirement(slots.alphas, self.alpha_words, 1),
            slot_requirement(slots.z, self.z_words, 1),
            slot_requirement(
                slots.inverse_scratch,
                self.inverse_words,
                SECURE_FIELD_WORDS,
            ),
            slot_requirement(slots.reduction_a, self.reduction_words, SECURE_FIELD_WORDS),
            slot_requirement(slots.reduction_b, self.reduction_words, SECURE_FIELD_WORDS),
            slot_requirement(slots.scan_eval_scratch, self.scan_eval_words, 1),
            slot_requirement(slots.scan_temp_scratch, self.scan_temp_words, 1),
            slot_requirement(
                slots.scan_descriptors,
                self.scan_descriptor_words,
                SECURE_FIELD_WORDS,
            ),
            slot_requirement(
                slots.fraction_pointers,
                self.fraction_pointer_words,
                RELATION_POINTER_ALIGNMENT_WORDS,
            ),
            slot_requirement(slots.fraction_geometry, self.fraction_geometry_words, 1),
        ];
        for (requirement, instance_slots) in self.instances.iter().zip(&slots.instances) {
            if instance_slots.output_coordinates.len() != requirement.output_coordinate_count {
                return Err(RelationGraphError::SlotShapeMismatch {
                    expected: requirement.output_coordinate_count,
                    actual: instance_slots.output_coordinates.len(),
                });
            }
            output.push(slot_requirement(
                instance_slots.source_pointers,
                requirement.source_pointer_words,
                RELATION_POINTER_ALIGNMENT_WORDS,
            ));
            output.push(slot_requirement(
                instance_slots.output_pointers,
                requirement.output_pointer_words,
                RELATION_POINTER_ALIGNMENT_WORDS,
            ));
            output.extend(
                instance_slots
                    .output_coordinates
                    .iter()
                    .map(|&id| slot_requirement(id, requirement.output_coordinate_words, 1)),
            );
            output.extend([
                slot_requirement(
                    instance_slots.denominators,
                    requirement.denominator_words,
                    SECURE_FIELD_WORDS,
                ),
                slot_requirement(
                    instance_slots.claimed_sum,
                    requirement.claimed_sum_words,
                    SECURE_FIELD_WORDS,
                ),
            ]);
        }
        let mut seen = BTreeSet::new();
        for requirement in &output {
            if !seen.insert(requirement.id) {
                return Err(RelationGraphError::DuplicateSlot(requirement.id));
            }
        }
        Ok(output)
    }
}

fn slot_requirement(
    id: ArenaSlotId,
    len_words: usize,
    alignment_words: usize,
) -> RelationArenaSlotRequirement {
    RelationArenaSlotRequirement {
        id,
        len_words: len_words.max(1),
        alignment_words,
    }
}

pub fn relation_graph_requirements(
    program: &RelationKernelProgram,
) -> Result<RelationGraphRequirements, RelationGraphError> {
    relation_graph_requirements_for_mode(program, RelationLaunchMode::ThreeStage)
}

pub fn relation_graph_requirements_for_mode(
    program: &RelationKernelProgram,
    mode: RelationLaunchMode,
) -> Result<RelationGraphRequirements, RelationGraphError> {
    program.validate()?;
    if mode != RelationLaunchMode::Fused
        && program
            .batches
            .iter()
            .any(|batch| matches!(batch.source_layout, RelationSourceLayout::BlakeGInputs))
    {
        return Err(RelationGraphError::BlakeGInputsRequireFused);
    }
    let instance_count = program.batches.iter().try_fold(0usize, |count, batch| {
        count
            .checked_add(batch.instances.len())
            .ok_or(RelationGraphError::SizeOverflow)
    })?;
    if mode == RelationLaunchMode::Fused && instance_count > RELATION_FUSED_MAX_INSTANCES {
        return Err(RelationGraphError::FusedInstanceCapacityExceeded {
            instances: instance_count,
            max: RELATION_FUSED_MAX_INSTANCES,
        });
    }
    let descriptor_words = program
        .batches
        .iter()
        .map(|batch| batch.columns.len())
        .sum::<usize>()
        .checked_mul(DESCRIPTOR_WORDS)
        .ok_or(RelationGraphError::SizeOverflow)?;
    let alpha_words = usize::try_from(program.max_alpha_powers)
        .map_err(|_| RelationGraphError::SizeOverflow)?
        .checked_mul(SECURE_FIELD_WORDS)
        .ok_or(RelationGraphError::SizeOverflow)?;
    let mut pair_blocks = 0usize;
    let mut fraction_inverse_blocks = 0usize;
    let mut fraction_chain_blocks = 0usize;
    let mut instances = Vec::new();
    for (batch_index, batch) in program.batches.iter().enumerate() {
        for (instance_index, extent) in batch.instances.iter().enumerate() {
            let rows = usize::try_from(extent.capacity_rows())
                .map_err(|_| RelationGraphError::SizeOverflow)?;
            let columns = batch.columns.len();
            let values = rows
                .checked_mul(columns)
                .ok_or(RelationGraphError::SizeOverflow)?;
            let inverse_blocks = if rows >= FRACTION_INVERSE_BLOCK_VALUES {
                debug_assert_eq!(rows % FRACTION_INVERSE_BLOCK_VALUES, 0);
                values / FRACTION_INVERSE_BLOCK_VALUES
            } else {
                values.div_ceil(FRACTION_INVERSE_BLOCK_VALUES)
            };
            fraction_inverse_blocks = fraction_inverse_blocks
                .checked_add(inverse_blocks)
                .ok_or(RelationGraphError::SizeOverflow)?;
            let row_blocks = rows.div_ceil(REDUCTION_BLOCK);
            let instance_pair_blocks = row_blocks
                .checked_mul(columns)
                .ok_or(RelationGraphError::SizeOverflow)?;
            pair_blocks = pair_blocks
                .checked_add(instance_pair_blocks)
                .ok_or(RelationGraphError::SizeOverflow)?;
            fraction_chain_blocks = fraction_chain_blocks
                .checked_add(row_blocks)
                .ok_or(RelationGraphError::SizeOverflow)?;
            let coordinate_words = columns
                .checked_mul(SECURE_FIELD_WORDS)
                .and_then(|value| value.checked_mul(rows))
                .ok_or(RelationGraphError::SizeOverflow)?;
            instances.push(RelationInstanceRequirement {
                batch_index,
                instance_index,
                row_capacity: extent.capacity_rows(),
                source_pointer_words: batch
                    .source_layout
                    .pointer_count()?
                    .checked_mul(POINTER_WORDS)
                    .ok_or(RelationGraphError::SizeOverflow)?,
                output_pointer_words: columns
                    .checked_mul(SECURE_FIELD_WORDS)
                    .and_then(|count| count.checked_mul(POINTER_WORDS))
                    .ok_or(RelationGraphError::SizeOverflow)?,
                output_coordinate_count: columns
                    .checked_mul(SECURE_FIELD_WORDS)
                    .ok_or(RelationGraphError::SizeOverflow)?,
                output_coordinate_words: rows,
                output_words: coordinate_words,
                denominator_words: if mode == RelationLaunchMode::Fused
                    && relation_batch_fused_eligible(batch)
                {
                    1
                } else {
                    coordinate_words
                },
                claimed_sum_words: SECURE_FIELD_WORDS,
            });
        }
    }
    let reduction_words = fraction_chain_blocks
        .max(1)
        .checked_mul(SECURE_FIELD_WORDS)
        .ok_or(RelationGraphError::SizeOverflow)?;
    let pair_blocks = u32::try_from(pair_blocks).map_err(|_| RelationGraphError::SizeOverflow)?;
    let fraction_chain_blocks =
        u32::try_from(fraction_chain_blocks).map_err(|_| RelationGraphError::SizeOverflow)?;
    fraction_chain_blocks
        .checked_mul(SECURE_FIELD_WORDS as u32)
        .ok_or(RelationGraphError::SizeOverflow)?;
    u32::try_from(instances.len())
        .map_err(|_| RelationGraphError::SizeOverflow)?
        .checked_mul(SECURE_FIELD_WORDS as u32)
        .ok_or(RelationGraphError::SizeOverflow)?;
    Ok(RelationGraphRequirements {
        descriptor_words,
        alpha_words,
        z_words: SECURE_FIELD_WORDS,
        // The ragged inverse operates in-place in each denominator slab.
        inverse_words: 1,
        reduction_words,
        // Custom segmented scans reuse reduction_b for their tile totals.
        scan_eval_words: 1,
        scan_temp_words: 1,
        scan_descriptor_words: scan_descriptor_words(fraction_chain_blocks as usize)?,
        fraction_pointer_words: instances
            .len()
            .checked_mul(INSTANCE_POINTER_TABLES)
            .and_then(|pointers| pointers.checked_mul(POINTER_WORDS))
            .ok_or(RelationGraphError::SizeOverflow)?,
        fraction_geometry_words: instances
            .len()
            .checked_mul(INSTANCE_GEOMETRY_WORDS)
            .ok_or(RelationGraphError::SizeOverflow)?,
        pair_blocks,
        fraction_inverse_blocks: u32::try_from(fraction_inverse_blocks)
            .map_err(|_| RelationGraphError::SizeOverflow)?,
        fraction_chain_blocks,
        instances,
    })
}

/// Ticket counter plus one lookback partition descriptor per row block.
/// Mirrors the buffer contract validated by `stwo_relation_scan_tail_on`.
fn scan_descriptor_words(total_row_blocks: usize) -> Result<usize, RelationGraphError> {
    total_row_blocks
        .checked_mul(SCAN_DESC_STRIDE_WORDS)
        .and_then(|words| words.checked_add(SCAN_TICKET_WORDS))
        .ok_or(RelationGraphError::SizeOverflow)
}

fn relation_instance_geometry(
    pair_first: u32,
    inverse_first: u32,
    row_first: u32,
    rows: u32,
    columns: u32,
    n_real_rows: u32,
    source_offset_rows: u32,
) -> Result<([u32; INSTANCE_GEOMETRY_WORDS], u32, u32, u32), RelationGraphError> {
    let values = rows
        .checked_mul(columns)
        .ok_or(RelationGraphError::SizeOverflow)?;
    let inverse_blocks = if rows as usize >= FRACTION_INVERSE_BLOCK_VALUES {
        values / FRACTION_INVERSE_BLOCK_VALUES as u32
    } else {
        values.div_ceil(FRACTION_INVERSE_BLOCK_VALUES as u32)
    };
    let row_blocks = rows.div_ceil(REDUCTION_BLOCK as u32);
    let pair_blocks = row_blocks
        .checked_mul(columns)
        .ok_or(RelationGraphError::SizeOverflow)?;
    let geometry = [
        pair_first,
        pair_blocks,
        inverse_first,
        inverse_blocks,
        row_first,
        row_blocks,
        rows,
        columns,
        n_real_rows,
        source_offset_rows,
        M31::from_u32_unchecked(rows).inverse().0,
    ];
    Ok((
        geometry,
        pair_first
            .checked_add(pair_blocks)
            .ok_or(RelationGraphError::SizeOverflow)?,
        inverse_first
            .checked_add(inverse_blocks)
            .ok_or(RelationGraphError::SizeOverflow)?,
        row_first
            .checked_add(row_blocks)
            .ok_or(RelationGraphError::SizeOverflow)?,
    ))
}

fn relation_source_word_extents(
    layout: RelationSourceLayout,
    rows: u32,
) -> Result<Vec<usize>, RelationGraphError> {
    let rows = usize::try_from(rows).map_err(|_| RelationGraphError::SizeOverflow)?;
    let pointers = layout.pointer_count()?;
    match layout {
        RelationSourceLayout::LookupWords { words } => Ok(vec![usize::try_from(words)
            .map_err(|_| RelationGraphError::SizeOverflow)?
            .checked_mul(rows)
            .ok_or(RelationGraphError::SizeOverflow)?]),
        _ => Ok(vec![rows; pointers]),
    }
}

fn validate_extent(
    layout: RelationSourceLayout,
    extent: RelationRowExtent,
) -> Result<(), RelationGraphError> {
    match extent {
        RelationRowExtent::Exact {
            n_real_rows,
            padded_rows,
            source_offset_rows,
        } => {
            if n_real_rows == 0
                || n_real_rows > padded_rows
                || !padded_rows.is_power_of_two()
                || u64::from(padded_rows) >= M31_MODULUS
            {
                return Err(RelationGraphError::InvalidRowExtent);
            }
            let layout_valid = match layout {
                RelationSourceLayout::MemoryBig { .. } => source_offset_rows
                    .checked_add(padded_rows)
                    .is_some_and(|end| end <= LARGE_MEMORY_VALUE_ID_BASE),
                RelationSourceLayout::MemoryAddress { chunks } => {
                    source_offset_rows == 0
                        && u64::from(chunks) * u64::from(padded_rows) < M31_MODULUS
                }
                RelationSourceLayout::BitwiseXor12 { .. } => {
                    source_offset_rows == 0
                        && n_real_rows == XOR12_ROWS
                        && padded_rows == XOR12_ROWS
                }
                _ => source_offset_rows == 0,
            };
            if !layout_valid {
                return Err(RelationGraphError::InvalidRowExtent);
            }
        }
        RelationRowExtent::Bounded {
            observed_rows,
            max_rows,
            padded_capacity,
        } => {
            if max_rows == 0
                || observed_rows > max_rows
                || max_rows > padded_capacity
                || !padded_capacity.is_power_of_two()
                || u64::from(padded_capacity) >= M31_MODULUS
            {
                return Err(RelationGraphError::InvalidRowExtent);
            }
            let layout_valid = match layout {
                RelationSourceLayout::MemoryAddress { chunks } => {
                    u64::from(chunks) * u64::from(padded_capacity) < M31_MODULUS
                }
                RelationSourceLayout::BitwiseXor12 { .. } => padded_capacity == XOR12_ROWS,
                _ => true,
            };
            if !layout_valid {
                return Err(RelationGraphError::InvalidRowExtent);
            }
        }
    }
    Ok(())
}

fn validate_use(
    layout: RelationSourceLayout,
    relation_use: RelationUseDescriptor,
) -> Result<(), RelationGraphError> {
    let tuple_valid = match (layout, relation_use.tuple_kind) {
        (RelationSourceLayout::LookupWords { words }, RelationTupleKind::LookupWords) => {
            relation_use
                .tuple_arg
                .checked_add(relation_use.tuple_words)
                .is_some_and(|end| end <= words)
        }
        (
            RelationSourceLayout::ProjectedColumns { columns },
            RelationTupleKind::ProjectedColumns,
        ) => relation_use
            .tuple_words
            .checked_sub(1)
            .and_then(|operand_words| relation_use.tuple_arg.checked_add(operand_words))
            .is_some_and(|end| end <= columns),
        (RelationSourceLayout::BlakeGInputs, RelationTupleKind::BlakeGInputs) => {
            relation_use.tuple_arg < BLAKE_G_RELATION_IDS.len() as u32
                && relation_use.tuple_words
                    == if relation_use.tuple_arg + 1 == BLAKE_G_RELATION_IDS.len() as u32 {
                        21
                    } else {
                        4
                    }
        }
        (RelationSourceLayout::MemoryAddress { chunks }, RelationTupleKind::MemoryAddressChunk) => {
            relation_use.tuple_arg < chunks && relation_use.tuple_words == 3
        }
        (RelationSourceLayout::MemoryBig { value_words }, RelationTupleKind::MemoryBigLimbs)
        | (
            RelationSourceLayout::MemorySmall { value_words },
            RelationTupleKind::MemorySmallLimbs,
        ) => {
            relation_use.tuple_words == 3
                && relation_use
                    .tuple_arg
                    .checked_add(2)
                    .is_some_and(|end| end <= value_words)
        }
        (RelationSourceLayout::MemoryBig { value_words }, RelationTupleKind::MemoryBigValue)
        | (
            RelationSourceLayout::MemorySmall { value_words },
            RelationTupleKind::MemorySmallValue,
        ) => {
            relation_use.tuple_arg == 0
                && value_words
                    .checked_add(2)
                    .is_some_and(|width| relation_use.tuple_words == width)
        }
        (
            RelationSourceLayout::BitwiseXor12 {
                multiplicity_columns,
            },
            RelationTupleKind::BitwiseXor12,
        ) => relation_use.tuple_arg < multiplicity_columns && relation_use.tuple_words == 4,
        _ => false,
    };
    let multiplicity_valid = match relation_use.multiplicity_kind {
        RelationMultiplicityKind::One | RelationMultiplicityKind::Enabler => {
            relation_use.multiplicity_arg == 0
        }
        RelationMultiplicityKind::LookupWord => matches!(
            layout,
            RelationSourceLayout::LookupWords { words }
                if relation_use.multiplicity_arg < words
        ),
        RelationMultiplicityKind::MemoryAddressChunk => matches!(
            layout,
            RelationSourceLayout::MemoryAddress { chunks }
                if relation_use.multiplicity_arg < chunks
        ),
        RelationMultiplicityKind::MemoryBig => matches!(
            layout,
            RelationSourceLayout::MemoryBig { value_words }
                if relation_use.multiplicity_arg == value_words
        ),
        RelationMultiplicityKind::MemorySmall => matches!(
            layout,
            RelationSourceLayout::MemorySmall { value_words }
                if relation_use.multiplicity_arg == value_words
        ),
        RelationMultiplicityKind::BitwiseXor12 => matches!(
            layout,
            RelationSourceLayout::BitwiseXor12 { multiplicity_columns }
                if relation_use.multiplicity_arg < multiplicity_columns
        ),
    };
    if !tuple_valid || !multiplicity_valid {
        return Err(RelationGraphError::SourceLayoutMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelationGraphError {
    InvalidGraphHash,
    InvalidBlakeGInputsBatch,
    BlakeGInputsRequireFused,
    MissingAlphaPowers,
    EmptyBatch(usize),
    InvalidColumnArity(usize),
    InvalidRelationId(u32),
    TupleWidthOutOfBounds {
        width: u32,
        max: u32,
    },
    UseCoverageMismatch {
        expected: usize,
        actual: usize,
    },
    SourceLayoutMismatch,
    InvalidRowExtent,
    SizeOverflow,
    SlotShapeMismatch {
        expected: usize,
        actual: usize,
    },
    DuplicateSlot(ArenaSlotId),
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
    ContextMismatch(ArenaSlotId),
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    MisalignedSlot(ArenaSlotId),
    SourceCountMismatch {
        expected: usize,
        actual: usize,
    },
    SourceTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    UnresolvedBoundedRows {
        batch: usize,
        instance: usize,
    },
    ChallengeWidthMismatch {
        expected: usize,
        actual: usize,
    },
    ScanScratchTooSmall {
        required_bytes: usize,
        actual_bytes: usize,
    },
    FractionChainTooLarge {
        rows: u32,
        columns: u32,
    },
    FusedInstanceCapacityExceeded {
        instances: usize,
        max: usize,
    },
    CompactFusedLaunchModeMismatch {
        requested: RelationLaunchMode,
    },
}

impl core::fmt::Display for RelationGraphError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RelationGraphError {}

impl From<ArenaError> for RelationGraphError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for RelationGraphError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

pub struct RelationChallenges<'a> {
    pub alpha_powers: &'a [SecureField],
    pub z: SecureField,
}

#[derive(Clone, Debug)]
pub struct RelationInstanceSources {
    /// Layout-defined source columns. `LookupWords` uses one contiguous
    /// word-major buffer; computed and projected layouts use one pointer per
    /// source column.
    pub columns: Vec<ArenaSlice>,
}

#[derive(Clone, Debug)]
pub struct PreparedRelationOutput {
    pub batch_index: usize,
    pub instance_index: usize,
    pub rows: u32,
    pub columns: u32,
    /// Exact commit-source slices in interaction-column, secure-coordinate order.
    pub coordinates: Vec<ArenaSlice>,
    pub claimed_sum: ArenaSlice,
}

impl PreparedRelationOutput {
    /// Number of coordinate pointers in the output table consumed by kernels.
    ///
    /// This is four times the logical LogUp column count for QM31 outputs.
    fn n_coordinate_pointers(&self) -> Result<u32, RelationGraphError> {
        u32::try_from(self.coordinates.len()).map_err(|_| RelationGraphError::SizeOverflow)
    }
}

struct PreparedInstance {
    output: PreparedRelationOutput,
    descriptor_ptr: *const u32,
    source_pointers: ArenaSlice,
    output_pointers: ArenaSlice,
    denominators: ArenaSlice,
    n_real_rows: u32,
    source_offset_rows: u32,
    /// Pointer count in `source_pointers`, for the per-instance fallback lane.
    n_source_pointers: u32,
    /// Static fused-lane eligibility (see [`relation_batch_fused_eligible`]).
    fused_eligible: bool,
    /// Isolated six-input Blake-G body. It is deliberately excluded from the
    /// generic fused mask so its register allocation cannot affect other AIRs.
    blake_g_inputs: bool,
}

/// Descriptor-complete executable relation graph. The arena borrow makes every
/// captured pointer and every claimed-sum boundary buffer structurally live.
pub struct PreparedRelationGraph<'a> {
    arena: &'a DeviceArena,
    alphas: ArenaSlice,
    z: ArenaSlice,
    inverse_scratch: ArenaSlice,
    reduction_a: ArenaSlice,
    reduction_b: ArenaSlice,
    scan_descriptors: ArenaSlice,
    fraction_pointers: ArenaSlice,
    fraction_geometry: ArenaSlice,
    pair_blocks: u32,
    fraction_inverse_blocks: u32,
    fraction_chain_blocks: u32,
    prepared_mode: RelationLaunchMode,
    instances: Vec<PreparedInstance>,
}

impl<'a> PreparedRelationGraph<'a> {
    /// Bind all caller-owned slots and source buffers, upload immutable
    /// descriptors/pointer tables plus the first challenge values, then perform
    /// the sole setup drain. No setup transfer is captured by `launch`.
    pub fn prepare(
        arena: &'a DeviceArena,
        program: &RelationKernelProgram,
        slots: &RelationGraphSlots,
        sources: &[RelationInstanceSources],
        challenges: RelationChallenges<'_>,
    ) -> Result<Self, RelationGraphError> {
        Self::prepare_with_mode(
            arena,
            program,
            RelationLaunchMode::ThreeStage,
            slots,
            sources,
            challenges,
        )
    }

    /// Prepare a mode-sealed relation graph. `Fused` compacts eligible
    /// denominator slabs to one-word sentinels, so that prepared layout may
    /// never be launched through the proof-wide 3-stage body.
    pub fn prepare_with_mode(
        arena: &'a DeviceArena,
        program: &RelationKernelProgram,
        mode: RelationLaunchMode,
        slots: &RelationGraphSlots,
        sources: &[RelationInstanceSources],
        challenges: RelationChallenges<'_>,
    ) -> Result<Self, RelationGraphError> {
        program.validate()?;
        let requirements = program.requirements_for_mode(mode)?;
        requirements.arena_slot_requirements(slots)?;
        if sources.len() != requirements.instances.len() {
            return Err(RelationGraphError::SourceCountMismatch {
                expected: requirements.instances.len(),
                actual: sources.len(),
            });
        }
        if challenges.alpha_powers.len() < program.max_alpha_powers as usize {
            return Err(RelationGraphError::ChallengeWidthMismatch {
                expected: program.max_alpha_powers as usize,
                actual: challenges.alpha_powers.len(),
            });
        }
        for requirement in &requirements.instances {
            if matches!(
                program.batches[requirement.batch_index].instances[requirement.instance_index],
                RelationRowExtent::Bounded { .. }
            ) {
                return Err(RelationGraphError::UnresolvedBoundedRows {
                    batch: requirement.batch_index,
                    instance: requirement.instance_index,
                });
            }
        }

        let descriptors = bind_slot(arena, slots.descriptors, requirements.descriptor_words, 1)?;
        let alphas = bind_slot(arena, slots.alphas, requirements.alpha_words, 1)?;
        let z = bind_slot(arena, slots.z, requirements.z_words, 1)?;
        // Kept bound (not just validated): the fused lane's per-instance
        // fallback drives `stwo_relation_fraction_chain_on`, whose ABI still
        // carries this legacy one-word scratch slot.
        let inverse_scratch = bind_slot(
            arena,
            slots.inverse_scratch,
            requirements.inverse_words,
            SECURE_FIELD_WORDS,
        )?;
        let reduction_a = bind_slot(
            arena,
            slots.reduction_a,
            requirements.reduction_words,
            SECURE_FIELD_WORDS,
        )?;
        let reduction_b = bind_slot(
            arena,
            slots.reduction_b,
            requirements.reduction_words,
            SECURE_FIELD_WORDS,
        )?;
        let _scan_eval_scratch = bind_slot(
            arena,
            slots.scan_eval_scratch,
            requirements.scan_eval_words,
            1,
        )?;
        let _scan_temp_scratch = bind_slot(
            arena,
            slots.scan_temp_scratch,
            requirements.scan_temp_words,
            1,
        )?;
        let scan_descriptors = bind_slot(
            arena,
            slots.scan_descriptors,
            requirements.scan_descriptor_words,
            SECURE_FIELD_WORDS,
        )?;
        let fraction_pointers = bind_slot(
            arena,
            slots.fraction_pointers,
            requirements.fraction_pointer_words,
            RELATION_POINTER_ALIGNMENT_WORDS,
        )?;
        let fraction_geometry = bind_slot(
            arena,
            slots.fraction_geometry,
            requirements.fraction_geometry_words,
            1,
        )?;
        let descriptor_words = program.descriptor_words()?;
        let alpha_words =
            secure_words(&challenges.alpha_powers[..program.max_alpha_powers as usize]);
        let z_words = secure_words(core::slice::from_ref(&challenges.z));
        let mut uploads = vec![
            PendingUpload::u32(descriptors, descriptor_words),
            PendingUpload::u32(alphas, alpha_words),
            PendingUpload::u32(z, z_words),
        ];

        let context_token = arena.context().identity_token();
        let mut prepared = Vec::with_capacity(requirements.instances.len());
        let mut descriptor_column_offset = Vec::with_capacity(program.batches.len());
        let mut column_offset = 0usize;
        for batch in &program.batches {
            descriptor_column_offset.push(column_offset);
            column_offset = column_offset
                .checked_add(batch.columns.len())
                .ok_or(RelationGraphError::SizeOverflow)?;
        }
        for ((requirement, instance_slots), source) in requirements
            .instances
            .iter()
            .zip(&slots.instances)
            .zip(sources)
        {
            let batch = &program.batches[requirement.batch_index];
            let RelationRowExtent::Exact {
                n_real_rows,
                padded_rows,
                source_offset_rows,
            } = batch.instances[requirement.instance_index]
            else {
                unreachable!("bounded extents rejected")
            };
            let expected_sources = batch.source_layout.pointer_count()?;
            if source.columns.len() != expected_sources {
                return Err(RelationGraphError::SourceCountMismatch {
                    expected: expected_sources,
                    actual: source.columns.len(),
                });
            }
            validate_sources(batch.source_layout, source, padded_rows, context_token)?;
            let source_pointers = bind_slot(
                arena,
                instance_slots.source_pointers,
                requirement.source_pointer_words,
                RELATION_POINTER_ALIGNMENT_WORDS,
            )?;
            let output_pointers = bind_slot(
                arena,
                instance_slots.output_pointers,
                requirement.output_pointer_words,
                RELATION_POINTER_ALIGNMENT_WORDS,
            )?;
            let output_coordinates = instance_slots
                .output_coordinates
                .iter()
                .map(|&id| bind_slot(arena, id, requirement.output_coordinate_words, 1))
                .collect::<Result<Vec<_>, _>>()?;
            let denominators = bind_slot(
                arena,
                instance_slots.denominators,
                requirement.denominator_words,
                SECURE_FIELD_WORDS,
            )?;
            let claimed_sum = bind_slot(
                arena,
                instance_slots.claimed_sum,
                requirement.claimed_sum_words,
                SECURE_FIELD_WORDS,
            )?;
            uploads.push(PendingUpload::pointers(
                source_pointers,
                source
                    .columns
                    .iter()
                    .map(|column| column.as_u32_ptr() as usize)
                    .collect(),
            ));
            uploads.push(PendingUpload::pointers(
                output_pointers,
                output_coordinates
                    .iter()
                    .map(|column| column.as_u32_ptr() as usize)
                    .collect(),
            ));
            let descriptor_word_offset = descriptor_column_offset[requirement.batch_index]
                .checked_mul(DESCRIPTOR_WORDS)
                .ok_or(RelationGraphError::SizeOverflow)?;
            let descriptor_ptr = unsafe {
                descriptors
                    .as_u32_ptr()
                    .add(descriptor_word_offset)
                    .cast_const()
            };
            prepared.push(PreparedInstance {
                output: PreparedRelationOutput {
                    batch_index: requirement.batch_index,
                    instance_index: requirement.instance_index,
                    rows: padded_rows,
                    columns: u32::try_from(batch.columns.len())
                        .map_err(|_| RelationGraphError::SizeOverflow)?,
                    coordinates: output_coordinates,
                    claimed_sum,
                },
                descriptor_ptr,
                source_pointers,
                output_pointers,
                denominators,
                n_real_rows,
                source_offset_rows,
                n_source_pointers: u32::try_from(expected_sources)
                    .map_err(|_| RelationGraphError::SizeOverflow)?,
                fused_eligible: relation_batch_fused_eligible(batch),
                blake_g_inputs: matches!(batch.source_layout, RelationSourceLayout::BlakeGInputs),
            });
        }

        if !prepared.is_empty() {
            let mut pointers = prepared
                .iter()
                .map(|instance| instance.source_pointers.as_u32_ptr() as usize)
                .collect::<Vec<_>>();
            pointers.extend(
                prepared
                    .iter()
                    .map(|instance| instance.descriptor_ptr as usize),
            );
            pointers.extend(
                prepared
                    .iter()
                    .map(|instance| instance.output_pointers.as_u32_ptr() as usize),
            );
            pointers.extend(
                prepared
                    .iter()
                    .map(|instance| instance.denominators.as_u32_ptr() as usize),
            );
            pointers.extend(
                prepared
                    .iter()
                    .map(|instance| instance.output.claimed_sum.as_u32_ptr() as usize),
            );
            let mut geometry = Vec::with_capacity(
                prepared
                    .len()
                    .checked_mul(INSTANCE_GEOMETRY_WORDS)
                    .ok_or(RelationGraphError::SizeOverflow)?,
            );
            let mut pair_first = 0u32;
            let mut inverse_first = 0u32;
            let mut row_first = 0u32;
            for instance in &prepared {
                let (record, next_pair, next_inverse, next_row) = relation_instance_geometry(
                    pair_first,
                    inverse_first,
                    row_first,
                    instance.output.rows,
                    instance.output.columns,
                    instance.n_real_rows,
                    instance.source_offset_rows,
                )?;
                geometry.extend(record);
                pair_first = next_pair;
                inverse_first = next_inverse;
                row_first = next_row;
            }
            if pair_first != requirements.pair_blocks
                || inverse_first != requirements.fraction_inverse_blocks
                || row_first != requirements.fraction_chain_blocks
            {
                return Err(RelationGraphError::SizeOverflow);
            }
            uploads.push(PendingUpload::pointers(fraction_pointers, pointers));
            uploads.push(PendingUpload::u32(fraction_geometry, geometry));
        }

        upload_and_sync(arena, &uploads)?;
        Ok(Self {
            arena,
            alphas,
            z,
            inverse_scratch,
            reduction_a,
            reduction_b,
            scan_descriptors,
            fraction_pointers,
            fraction_geometry,
            pair_blocks: requirements.pair_blocks,
            fraction_inverse_blocks: requirements.fraction_inverse_blocks,
            fraction_chain_blocks: requirements.fraction_chain_blocks,
            prepared_mode: mode,
            instances: prepared,
        })
    }

    /// Allocation/copy/sync/default-stream-free sequence shared by eager mode and
    /// graph capture. A compact fused preparation is permanently fused;
    /// otherwise the pipeline defaults to the proven 3-stage lane and
    /// `STWO_CUDA_RELATION_FUSED=1` opts into fused execution. The tail remains
    /// independently selected by `STWO_CUDA_RELATION_SCAN_TAIL=1`.
    pub fn launch(&self) -> Result<(), RelationGraphError> {
        self.launch_with_mode(implicit_launch_mode(self.prepared_mode))
    }

    fn tail_mode_from_env() -> RelationTailMode {
        if scan_tail_enabled() {
            RelationTailMode::Scan
        } else {
            RelationTailMode::Segmented
        }
    }

    /// The fused lane: one kernel replaces pairs + ragged inverse + global
    /// fraction chain and never touches the denominator slots or
    /// `inverse_scratch` for eligible instances. Mode-aware preparations bind
    /// one-word denominator sentinels for those instances; fused-ineligible
    /// instances retain full slabs and run the existing per-instance pairs +
    /// inverse + chain kernels.
    pub fn launch_fused(&self) -> Result<(), RelationGraphError> {
        self.launch_with_mode(RelationLaunchMode::Fused)
    }

    /// Explicit-body-mode launch; the tail follows the process-wide env gate.
    pub fn launch_with_mode(&self, mode: RelationLaunchMode) -> Result<(), RelationGraphError> {
        self.launch_with_modes(mode, Self::tail_mode_from_env())
    }

    /// Fully explicit launch used by the parity tests: any body lane may be
    /// combined with any tail lane; all four combinations are byte-identical.
    pub fn launch_with_modes(
        &self,
        mode: RelationLaunchMode,
        tail: RelationTailMode,
    ) -> Result<(), RelationGraphError> {
        validate_prepared_launch_mode(self.prepared_mode, mode)?;
        if self.instances.is_empty() {
            return Ok(());
        }
        let generic_eligibility = self
            .instances
            .iter()
            .map(|instance| instance.fused_eligible && !instance.blake_g_inputs)
            .collect::<Vec<_>>();
        let has_blake_g_inputs = self
            .instances
            .iter()
            .any(|instance| instance.blake_g_inputs);
        // Fail closed: proofs beyond the mask capacity, or with no eligible
        // instance, run the whole 3-stage lane even when fused was requested.
        let fused_mask = match mode {
            RelationLaunchMode::Fused
                if generic_eligibility.contains(&true) || has_blake_g_inputs =>
            {
                fused_eligibility_mask(&generic_eligibility)
            }
            RelationLaunchMode::ThreeStage => None,
            RelationLaunchMode::Fused => None,
        };
        match fused_mask {
            Some(mask) => self.launch_fused_body(&mask),
            None => self.launch_three_stage_body(),
        }?;
        match tail {
            RelationTailMode::Segmented => self.launch_segmented_tail(),
            RelationTailMode::Scan => self.launch_scan_tail(),
        }
    }

    /// Launch one dormant selector strategy for a same-process native A/B.
    /// The production [`Self::launch`] path never calls this method.
    #[cfg(feature = "test-only-relation-ab")]
    #[doc(hidden)]
    pub fn launch_fused_test_strategy(
        &self,
        strategy: RelationFusedTestStrategy,
        tail: RelationTailMode,
    ) -> Result<(), RelationGraphError> {
        validate_prepared_launch_mode(self.prepared_mode, RelationLaunchMode::Fused)?;
        if self.instances.is_empty() {
            return Ok(());
        }
        let generic_eligibility = self
            .instances
            .iter()
            .map(|instance| instance.fused_eligible && !instance.blake_g_inputs)
            .collect::<Vec<_>>();
        let has_blake_g_inputs = self
            .instances
            .iter()
            .any(|instance| instance.blake_g_inputs);
        let fused_mask = if generic_eligibility.contains(&true) || has_blake_g_inputs {
            fused_eligibility_mask(&generic_eligibility)
        } else {
            None
        };
        match (fused_mask, strategy) {
            (Some(mask), RelationFusedTestStrategy::Adaptive) => self.launch_fused_body(&mask),
            (Some(mask), RelationFusedTestStrategy::AllOneReadBaseline) => {
                self.launch_fused_all_one_read_test_body(&mask)
            }
            (None, _) => self.launch_three_stage_body(),
        }?;
        match tail {
            RelationTailMode::Segmented => self.launch_segmented_tail(),
            RelationTailMode::Scan => self.launch_scan_tail(),
        }
    }

    /// Query the exact CUDA function loaded on the current device. Static
    /// source/module identities are reported separately by the kernel crate.
    #[cfg(feature = "test-only-relation-ab")]
    #[doc(hidden)]
    pub fn fused_test_function_resources(
        strategy: RelationFusedTestStrategy,
    ) -> Result<RelationFusedTestFunctionResources, RelationGraphError> {
        let mut attributes = stwo_backend_cuda_kernels::raw::CudaFunctionAttributes::default();
        check_cuda("relation_fused_test_function_attributes", unsafe {
            stwo_backend_cuda_kernels::raw::stwo_relation_fused_test_function_attributes(
                strategy as u32,
                &mut attributes,
            )
        })?;
        Ok(RelationFusedTestFunctionResources {
            abi_version: attributes.abi_version,
            max_threads_per_block: attributes.max_threads_per_block,
            registers_per_thread: attributes.registers_per_thread,
            binary_version: attributes.binary_version,
            ptx_version: attributes.ptx_version,
            reserved: attributes.reserved,
            local_bytes: attributes.local_bytes,
            static_shared_bytes: attributes.static_shared_bytes,
        })
    }

    fn pointer_table(&self, index: usize) -> Result<*mut u32, RelationGraphError> {
        let offset = self
            .instances
            .len()
            .checked_mul(POINTER_WORDS)
            .and_then(|table_words| table_words.checked_mul(index))
            .ok_or(RelationGraphError::SizeOverflow)?;
        Ok(unsafe { self.fraction_pointers.as_u32_ptr().add(offset) })
    }

    fn n_instances(&self) -> Result<u32, RelationGraphError> {
        u32::try_from(self.instances.len()).map_err(|_| RelationGraphError::SizeOverflow)
    }

    fn n_alpha_powers(&self) -> Result<u32, RelationGraphError> {
        u32::try_from(self.alphas.len_words() / SECURE_FIELD_WORDS)
            .map_err(|_| RelationGraphError::SizeOverflow)
    }

    fn launch_three_stage_body(&self) -> Result<(), RelationGraphError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        let geometry = self.fraction_geometry.as_u32_ptr().cast_const();
        check_cuda("relation_pairs_global_on", unsafe {
            stwo_backend_cuda_kernels::raw::stwo_relation_pairs_global_on(
                self.pointer_table(0)?.cast(),
                self.pointer_table(1)?.cast(),
                self.pointer_table(2)?.cast(),
                self.pointer_table(3)?.cast(),
                geometry,
                self.n_instances()?,
                self.pair_blocks,
                self.alphas.as_u32_ptr().cast_const(),
                self.n_alpha_powers()?,
                self.z.as_u32_ptr().cast_const(),
                stream,
            )
        })?;
        check_cuda("relation_fraction_chain_global_on", unsafe {
            stwo_backend_cuda_kernels::raw::stwo_relation_fraction_chain_global_on(
                self.pointer_table(2)?.cast(),
                self.pointer_table(3)?.cast(),
                geometry,
                self.n_instances()?,
                self.fraction_inverse_blocks,
                self.fraction_chain_blocks,
                stream,
            )
        })?;
        Ok(())
    }

    fn launch_fused_body(
        &self,
        mask: &[u32; RELATION_FUSED_MASK_WORDS],
    ) -> Result<(), RelationGraphError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        let geometry = self.fraction_geometry.as_u32_ptr().cast_const();
        if mask.iter().any(|&word| word != 0) {
            check_cuda("relation_fused_on", unsafe {
                stwo_backend_cuda_kernels::raw::stwo_relation_fused_on(
                    self.pointer_table(0)?.cast(),
                    self.pointer_table(1)?.cast(),
                    self.pointer_table(2)?.cast(),
                    geometry,
                    self.n_instances()?,
                    self.fraction_chain_blocks,
                    self.alphas.as_u32_ptr().cast_const(),
                    self.n_alpha_powers()?,
                    self.z.as_u32_ptr().cast_const(),
                    mask.as_ptr(),
                    stream,
                )
            })?;
        }
        for instance in self
            .instances
            .iter()
            .filter(|instance| instance.blake_g_inputs)
        {
            check_cuda("relation_blake_g_inputs_on", unsafe {
                stwo_backend_cuda_kernels::raw::stwo_relation_blake_g_inputs_on(
                    instance.source_pointers.as_u32_ptr().cast_const().cast(),
                    instance.n_source_pointers,
                    instance.output.rows,
                    instance.n_real_rows,
                    self.alphas.as_u32_ptr().cast_const(),
                    self.n_alpha_powers()?,
                    self.z.as_u32_ptr().cast_const(),
                    instance.output_pointers.as_u32_ptr().cast_const().cast(),
                    instance.output.n_coordinate_pointers()?,
                    stream,
                )
            })?;
        }
        // Statically ineligible instances keep the exact per-instance 3-stage
        // sequence (pairs, then in-place slab inverse + fraction chain).
        for instance in self
            .instances
            .iter()
            .filter(|instance| !instance.fused_eligible && !instance.blake_g_inputs)
        {
            check_cuda("relation_pairs_on", unsafe {
                stwo_backend_cuda_kernels::raw::stwo_relation_pairs_on(
                    instance.source_pointers.as_u32_ptr().cast_const().cast(),
                    instance.n_source_pointers,
                    instance.output.rows,
                    instance.n_real_rows,
                    instance.source_offset_rows,
                    instance.descriptor_ptr,
                    instance.output.columns,
                    self.alphas.as_u32_ptr().cast_const(),
                    self.n_alpha_powers()?,
                    self.z.as_u32_ptr().cast_const(),
                    instance.output_pointers.as_u32_ptr().cast_const().cast(),
                    instance.denominators.as_u32_ptr(),
                    stream,
                )
            })?;
            check_cuda("relation_fraction_chain_on", unsafe {
                stwo_backend_cuda_kernels::raw::stwo_relation_fraction_chain_on(
                    instance.output_pointers.as_u32_ptr().cast_const().cast(),
                    instance.denominators.as_u32_ptr(),
                    self.inverse_scratch.as_u32_ptr(),
                    instance.output.rows,
                    instance.output.columns,
                    stream,
                )
            })?;
        }
        Ok(())
    }

    #[cfg(feature = "test-only-relation-ab")]
    fn launch_fused_all_one_read_test_body(
        &self,
        mask: &[u32; RELATION_FUSED_MASK_WORDS],
    ) -> Result<(), RelationGraphError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        let geometry = self.fraction_geometry.as_u32_ptr().cast_const();
        if mask.iter().any(|&word| word != 0) {
            check_cuda("relation_fused_all_one_read_test_on", unsafe {
                stwo_backend_cuda_kernels::raw::stwo_relation_fused_all_one_read_test_on(
                    self.pointer_table(0)?.cast(),
                    self.pointer_table(1)?.cast(),
                    self.pointer_table(2)?.cast(),
                    geometry,
                    self.n_instances()?,
                    self.fraction_chain_blocks,
                    self.alphas.as_u32_ptr().cast_const(),
                    self.n_alpha_powers()?,
                    self.z.as_u32_ptr().cast_const(),
                    mask.as_ptr(),
                    stream,
                )
            })?;
        }
        self.launch_fused_test_fallbacks()
    }

    #[cfg(feature = "test-only-relation-ab")]
    fn launch_fused_test_fallbacks(&self) -> Result<(), RelationGraphError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        for instance in self
            .instances
            .iter()
            .filter(|instance| instance.blake_g_inputs)
        {
            check_cuda("relation_blake_g_inputs_on", unsafe {
                stwo_backend_cuda_kernels::raw::stwo_relation_blake_g_inputs_on(
                    instance.source_pointers.as_u32_ptr().cast_const().cast(),
                    instance.n_source_pointers,
                    instance.output.rows,
                    instance.n_real_rows,
                    self.alphas.as_u32_ptr().cast_const(),
                    self.n_alpha_powers()?,
                    self.z.as_u32_ptr().cast_const(),
                    instance.output_pointers.as_u32_ptr().cast_const().cast(),
                    instance.output.n_coordinate_pointers()?,
                    stream,
                )
            })?;
        }
        // Statically ineligible instances keep the exact per-instance 3-stage
        // sequence (pairs, then in-place slab inverse + fraction chain).
        for instance in self
            .instances
            .iter()
            .filter(|instance| !instance.fused_eligible && !instance.blake_g_inputs)
        {
            check_cuda("relation_pairs_on", unsafe {
                stwo_backend_cuda_kernels::raw::stwo_relation_pairs_on(
                    instance.source_pointers.as_u32_ptr().cast_const().cast(),
                    instance.n_source_pointers,
                    instance.output.rows,
                    instance.n_real_rows,
                    instance.source_offset_rows,
                    instance.descriptor_ptr,
                    instance.output.columns,
                    self.alphas.as_u32_ptr().cast_const(),
                    self.n_alpha_powers()?,
                    self.z.as_u32_ptr().cast_const(),
                    instance.output_pointers.as_u32_ptr().cast_const().cast(),
                    instance.denominators.as_u32_ptr(),
                    stream,
                )
            })?;
            check_cuda("relation_fraction_chain_on", unsafe {
                stwo_backend_cuda_kernels::raw::stwo_relation_fraction_chain_on(
                    instance.output_pointers.as_u32_ptr().cast_const().cast(),
                    instance.denominators.as_u32_ptr(),
                    self.inverse_scratch.as_u32_ptr(),
                    instance.output.rows,
                    instance.output.columns,
                    stream,
                )
            })?;
        }
        Ok(())
    }

    /// Segmented reduction, claimed sums, shift and prefix scans — identical
    /// in both body lanes.
    fn launch_segmented_tail(&self) -> Result<(), RelationGraphError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        let geometry = self.fraction_geometry.as_u32_ptr().cast_const();
        check_cuda("relation_tail_global_on", unsafe {
            stwo_backend_cuda_kernels::raw::stwo_relation_tail_global_on(
                self.pointer_table(2)?.cast(),
                self.pointer_table(4)?.cast(),
                geometry,
                self.n_instances()?,
                self.fraction_chain_blocks,
                self.reduction_a.as_u32_ptr(),
                u32::try_from(self.reduction_a.len_words() / SECURE_FIELD_WORDS)
                    .map_err(|_| RelationGraphError::SizeOverflow)?,
                self.reduction_b.as_u32_ptr(),
                u32::try_from(self.reduction_b.len_words())
                    .map_err(|_| RelationGraphError::SizeOverflow)?,
                stream,
            )
        })?;
        Ok(())
    }

    /// Decoupled-lookback tail: one ragged single-pass scan over every
    /// instance (claimed sums fold into the same pass) plus a shift fixup,
    /// preceded by an on-stream memset of the partition descriptors. Byte
    /// identical to the segmented tail and equally capture-safe.
    fn launch_scan_tail(&self) -> Result<(), RelationGraphError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        let geometry = self.fraction_geometry.as_u32_ptr().cast_const();
        check_cuda("relation_scan_tail_on", unsafe {
            stwo_backend_cuda_kernels::raw::stwo_relation_scan_tail_on(
                self.pointer_table(2)?.cast(),
                self.pointer_table(4)?.cast(),
                geometry,
                self.n_instances()?,
                self.fraction_chain_blocks,
                self.scan_descriptors.as_u32_ptr(),
                u32::try_from(self.scan_descriptors.len_words())
                    .map_err(|_| RelationGraphError::SizeOverflow)?,
                stream,
            )
        })?;
        Ok(())
    }

    pub fn outputs(&self) -> impl ExactSizeIterator<Item = &PreparedRelationOutput> + '_ {
        self.instances.iter().map(|instance| &instance.output)
    }

    /// Stable relation challenge slice consumed directly by resident
    /// composition parameter materialization.
    pub const fn z_source(&self) -> ArenaSlice {
        self.z
    }

    /// Stable alpha-power table consumed directly by resident composition
    /// parameter materialization.
    pub const fn alpha_powers_source(&self) -> ArenaSlice {
        self.alphas
    }

    /// Expand the device transcript's exact `LookupElements::draw` output
    /// (`[z, alpha]`, two consecutive QM31 values) directly into the persistent
    /// z/alpha-power slots used by [`Self::launch`]. This is allocation-free,
    /// transfer-free and capture-safe on the arena's explicit stream.
    pub fn expand_challenges_from_transcript(
        &self,
        drawn_z_alpha: ArenaSlice,
    ) -> Result<(), RelationGraphError> {
        if drawn_z_alpha.context_token() != self.arena.context().identity_token() {
            return Err(RelationGraphError::ContextMismatch(drawn_z_alpha.id()));
        }
        let required_words = 2 * SECURE_FIELD_WORDS;
        if drawn_z_alpha.len_words() < required_words {
            return Err(RelationGraphError::SlotTooSmall {
                slot: drawn_z_alpha.id(),
                required_words,
                actual_words: drawn_z_alpha.len_words(),
            });
        }
        let n_alpha_powers = u32::try_from(self.alphas.len_words() / SECURE_FIELD_WORDS)
            .map_err(|_| RelationGraphError::SizeOverflow)?;
        check_cuda("relation_expand_challenges_on", unsafe {
            stwo_backend_cuda_kernels::raw::stwo_relation_expand_challenges_on(
                drawn_z_alpha.as_u32_ptr().cast_const(),
                self.alphas.as_u32_ptr(),
                n_alpha_powers,
                self.z.as_u32_ptr(),
                self.arena.context().stream_raw().as_ptr(),
            )
        })?;
        Ok(())
    }

    /// Update only transcript-derived challenge words between proof replays. This
    /// boundary is deliberately outside `launch` and must complete before capture
    /// or graph replay begins.
    pub fn upload_challenges_at_transcript_boundary(
        &self,
        challenges: RelationChallenges<'_>,
    ) -> Result<(), RelationGraphError> {
        let expected = self.alphas.len_words() / SECURE_FIELD_WORDS;
        if challenges.alpha_powers.len() < expected {
            return Err(RelationGraphError::ChallengeWidthMismatch {
                expected,
                actual: challenges.alpha_powers.len(),
            });
        }
        let uploads = [
            PendingUpload::u32(
                self.alphas,
                secure_words(&challenges.alpha_powers[..expected]),
            ),
            PendingUpload::u32(self.z, secure_words(core::slice::from_ref(&challenges.z))),
        ];
        upload_and_sync(self.arena, &uploads)
    }

    /// The only relation-side D2H: four words per active trace, immediately when
    /// the corresponding interaction claims must be mixed into the transcript.
    pub fn read_claimed_sums_at_transcript_boundary(
        &self,
    ) -> Result<Vec<SecureField>, RelationGraphError> {
        let mut words = vec![[0u32; SECURE_FIELD_WORDS]; self.instances.len()];
        for (instance, output) in self.instances.iter().zip(&mut words) {
            unsafe {
                self.arena.context().memcpy_d2h_async(
                    output.as_mut_ptr().cast(),
                    instance.output.claimed_sum.as_void_ptr().cast_const(),
                    SECURE_FIELD_WORDS * WORD_BYTES,
                )?;
            }
        }
        self.arena.context().sync()?;
        Ok(words
            .into_iter()
            .map(|coordinates| {
                SecureField::from_m31_array(coordinates.map(M31::from_u32_unchecked))
            })
            .collect())
    }
}

enum HostDescriptor {
    U32(Vec<u32>),
    Pointers(Vec<usize>),
}

struct PendingUpload {
    destination: ArenaSlice,
    descriptor: HostDescriptor,
}

impl PendingUpload {
    fn u32(destination: ArenaSlice, values: Vec<u32>) -> Self {
        Self {
            destination,
            descriptor: HostDescriptor::U32(values),
        }
    }

    fn pointers(destination: ArenaSlice, values: Vec<usize>) -> Self {
        Self {
            destination,
            descriptor: HostDescriptor::Pointers(values),
        }
    }

    fn bytes(&self) -> (*const c_void, usize) {
        match &self.descriptor {
            HostDescriptor::U32(values) => (
                values.as_ptr().cast(),
                values.len().saturating_mul(WORD_BYTES),
            ),
            HostDescriptor::Pointers(values) => (
                values.as_ptr().cast(),
                values.len().saturating_mul(core::mem::size_of::<usize>()),
            ),
        }
    }
}

fn secure_words(values: &[SecureField]) -> Vec<u32> {
    values
        .iter()
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}

fn upload_and_sync(
    arena: &DeviceArena,
    uploads: &[PendingUpload],
) -> Result<(), RelationGraphError> {
    for upload in uploads {
        let (source, bytes) = upload.bytes();
        unsafe {
            arena
                .context()
                .memcpy_h2d_async(upload.destination.as_void_ptr(), source, bytes)?;
        }
    }
    arena.context().sync()?;
    Ok(())
}

fn validate_sources(
    layout: RelationSourceLayout,
    sources: &RelationInstanceSources,
    rows: u32,
    context_token: core::ptr::NonNull<c_void>,
) -> Result<(), RelationGraphError> {
    for source in &sources.columns {
        if source.context_token() != context_token {
            return Err(RelationGraphError::ContextMismatch(source.id()));
        }
    }
    for (source, required_words) in sources
        .columns
        .iter()
        .zip(relation_source_word_extents(layout, rows)?)
    {
        if source.len_words() < required_words {
            return Err(RelationGraphError::SourceTooSmall {
                slot: source.id(),
                required_words,
                actual_words: source.len_words(),
            });
        }
    }
    Ok(())
}

fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, RelationGraphError> {
    truncate_bound_slot(arena.bind(id)?, required_words, alignment_words)
}

/// Validate one bound slot's capacity and alignment, then truncate it to the
/// logical requirement. Pooled slots may be larger than any single logical
/// buffer; only the logical extent is exposed. Alpha-power counts,
/// scan-descriptor counts, and reduction capacities are all derived from
/// `len_words()` downstream and must never observe the pooled surplus.
fn truncate_bound_slot(
    slice: ArenaSlice,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, RelationGraphError> {
    if slice.len_words() < required_words.max(1) {
        return Err(RelationGraphError::SlotTooSmall {
            slot: slice.id(),
            required_words: required_words.max(1),
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(RelationGraphError::MisalignedSlot(slice.id()));
    }
    Ok(slice.truncated(required_words.max(1)))
}

#[cfg(test)]
#[path = "relation_graph_wide_tests.rs"]
mod wide_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_slots_truncate_pooled_surplus_to_the_logical_requirement() {
        // Pooled physical slots are sized to the LARGEST epoch-disjoint
        // sharer; the binder must expose only the logical extent so
        // alpha-power and scan-descriptor counts never see the surplus.
        let oversized = ArenaSlice::dangling_for_test(3, 512);
        let bound = truncate_bound_slot(oversized, 96, 1).unwrap();
        assert_eq!(bound.len_words(), 96);
        assert_eq!(bound.id(), oversized.id());
        assert_eq!(bound.as_u32_ptr(), oversized.as_u32_ptr());
        // Zero-word requirements keep one addressable word (legacy scratch ABI).
        assert_eq!(truncate_bound_slot(oversized, 0, 1).unwrap().len_words(), 1);
        // Undersized slots still fail closed.
        assert!(matches!(
            truncate_bound_slot(ArenaSlice::dangling_for_test(3, 64), 96, 1),
            Err(RelationGraphError::SlotTooSmall { .. })
        ));
    }

    fn lookup_use(tuple_arg: u32, tuple_words: u32) -> RelationUseDescriptor {
        RelationUseDescriptor {
            tuple_kind: RelationTupleKind::LookupWords,
            tuple_arg,
            tuple_words,
            relation_id: 1,
            multiplicity_kind: RelationMultiplicityKind::One,
            multiplicity_arg: 0,
            negative: false,
        }
    }

    fn sample_program() -> RelationKernelProgram {
        RelationKernelProgram {
            relation_graph_hash: 1,
            template_use_count: 3,
            max_alpha_powers: 6,
            batches: vec![
                RelationBatchProgram {
                    source_layout: RelationSourceLayout::LookupWords { words: 8 },
                    columns: vec![RelationColumnDescriptor {
                        uses: vec![lookup_use(0, 3), lookup_use(3, 2)],
                    }],
                    instances: vec![RelationRowExtent::Exact {
                        n_real_rows: 6,
                        padded_rows: 8,
                        source_offset_rows: 0,
                    }],
                },
                RelationBatchProgram {
                    source_layout: RelationSourceLayout::MemoryBig { value_words: 4 },
                    columns: vec![RelationColumnDescriptor {
                        uses: vec![RelationUseDescriptor {
                            tuple_kind: RelationTupleKind::MemoryBigValue,
                            tuple_arg: 0,
                            tuple_words: 6,
                            relation_id: 2,
                            multiplicity_kind: RelationMultiplicityKind::MemoryBig,
                            multiplicity_arg: 4,
                            negative: true,
                        }],
                    }],
                    instances: vec![RelationRowExtent::Bounded {
                        observed_rows: 3,
                        max_rows: 7,
                        padded_capacity: 8,
                    }],
                },
            ],
        }
    }

    fn blake_g_inputs_batch() -> RelationBatchProgram {
        let mut use_index = 0usize;
        let columns = (0..BLAKE_G_LOGUP_COLUMNS)
            .map(|column| {
                let arity = if column < 8 { 2 } else { 1 };
                let uses = (0..arity)
                    .map(|_| {
                        let final_use = use_index + 1 == BLAKE_G_RELATION_IDS.len();
                        let relation_use = RelationUseDescriptor {
                            tuple_kind: RelationTupleKind::BlakeGInputs,
                            tuple_arg: use_index as u32,
                            tuple_words: if final_use { 21 } else { 4 },
                            relation_id: BLAKE_G_RELATION_IDS[use_index],
                            multiplicity_kind: if final_use {
                                RelationMultiplicityKind::Enabler
                            } else {
                                RelationMultiplicityKind::One
                            },
                            multiplicity_arg: 0,
                            negative: final_use,
                        };
                        use_index += 1;
                        relation_use
                    })
                    .collect();
                RelationColumnDescriptor { uses }
            })
            .collect();
        assert_eq!(use_index, BLAKE_G_RELATION_IDS.len());
        RelationBatchProgram {
            source_layout: RelationSourceLayout::BlakeGInputs,
            columns,
            instances: vec![RelationRowExtent::Exact {
                n_real_rows: 6,
                padded_rows: 8,
                source_offset_rows: 0,
            }],
        }
    }

    fn blake_g_inputs_program() -> RelationKernelProgram {
        RelationKernelProgram {
            relation_graph_hash: 0xb1a6_e601,
            template_use_count: BLAKE_G_RELATION_IDS.len(),
            max_alpha_powers: 21,
            batches: vec![blake_g_inputs_batch()],
        }
    }

    fn sample_slots() -> RelationGraphSlots {
        let mut next = 0u32;
        let mut id = || {
            let result = ArenaSlotId(next);
            next += 1;
            result
        };
        RelationGraphSlots {
            descriptors: id(),
            alphas: id(),
            z: id(),
            inverse_scratch: id(),
            reduction_a: id(),
            reduction_b: id(),
            scan_eval_scratch: id(),
            scan_temp_scratch: id(),
            scan_descriptors: id(),
            fraction_pointers: id(),
            fraction_geometry: id(),
            instances: (0..2)
                .map(|_| RelationInstanceSlots {
                    source_pointers: id(),
                    output_pointers: id(),
                    output_coordinates: (0..4).map(|_| id()).collect(),
                    denominators: id(),
                    claimed_sum: id(),
                })
                .collect(),
        }
    }

    #[test]
    fn requirements_cover_every_arena_buffer_without_cuda() {
        let requirements = relation_graph_requirements(&sample_program()).unwrap();
        assert_eq!(requirements.descriptor_words, 2 * DESCRIPTOR_WORDS);
        assert_eq!(requirements.alpha_words, 6 * SECURE_FIELD_WORDS);
        assert_eq!(requirements.z_words, SECURE_FIELD_WORDS);
        assert_eq!(requirements.inverse_words, 1);
        assert_eq!(requirements.reduction_words, 2 * SECURE_FIELD_WORDS);
        assert_eq!(requirements.scan_eval_words, 1);
        assert_eq!(requirements.scan_temp_words, 1);
        assert_eq!(
            requirements.scan_descriptor_words,
            SCAN_TICKET_WORDS + 2 * SCAN_DESC_STRIDE_WORDS
        );
        assert_eq!(
            requirements.fraction_pointer_words,
            2 * INSTANCE_POINTER_TABLES * POINTER_WORDS
        );
        assert_eq!(
            requirements.fraction_geometry_words,
            2 * INSTANCE_GEOMETRY_WORDS
        );
        assert_eq!(requirements.pair_blocks, 2);
        assert_eq!(requirements.fraction_inverse_blocks, 2);
        assert_eq!(requirements.fraction_chain_blocks, 2);
        assert_eq!(requirements.instances.len(), 2);
        assert_eq!(
            requirements.instances[0].output_words,
            8 * SECURE_FIELD_WORDS
        );
        assert_eq!(requirements.instances[0].output_coordinate_count, 4);
        assert_eq!(requirements.instances[0].output_coordinate_words, 8);
        assert_eq!(
            requirements.instances[0].output_pointer_words,
            4 * POINTER_WORDS
        );
        assert_eq!(
            requirements.instances[1].source_pointer_words,
            5 * POINTER_WORDS
        );
        assert_eq!(
            requirements.instances[0].denominator_words,
            8 * SECURE_FIELD_WORDS
        );
        assert_eq!(
            requirements.instances[1].denominator_words,
            8 * SECURE_FIELD_WORDS
        );

        let slots = sample_slots();
        let slot_requirements = requirements.arena_slot_requirements(&slots).unwrap();
        assert_eq!(slot_requirements.len(), 11 + 2 * 8);
        assert_eq!(
            slot_requirements[11].alignment_words,
            RELATION_POINTER_ALIGNMENT_WORDS
        );
    }

    #[test]
    fn exact_blake_g_inputs_descriptor_is_fused_only_and_six_source() {
        let program = blake_g_inputs_program();
        let batch = &program.batches[0];
        assert!(blake_g_inputs_batch_is_exact(batch));
        assert_eq!(batch.source_layout.pointer_count().unwrap(), 6);
        assert!(program.validate().is_ok());
        assert_eq!(
            program.requirements_for_mode(RelationLaunchMode::ThreeStage),
            Err(RelationGraphError::BlakeGInputsRequireFused)
        );
        let requirements = program
            .requirements_for_mode(RelationLaunchMode::Fused)
            .unwrap();
        assert_eq!(requirements.instances.len(), 1);
        assert_eq!(
            requirements.instances[0].source_pointer_words,
            6 * POINTER_WORDS
        );
        assert_eq!(requirements.instances[0].output_coordinate_count, 36);
        assert_eq!(
            requirements.instances[0].output_words,
            8 * 9 * SECURE_FIELD_WORDS
        );
        assert_eq!(requirements.instances[0].denominator_words, 1);
        assert_eq!(
            requirements.instances[0].claimed_sum_words,
            SECURE_FIELD_WORDS
        );
    }

    #[test]
    fn blake_g_launch_counts_coordinate_pointers_not_logical_columns() {
        let slice = ArenaSlice::dangling_for_test(1, 8);
        let output = PreparedRelationOutput {
            batch_index: 0,
            instance_index: 0,
            rows: 8,
            columns: BLAKE_G_LOGUP_COLUMNS as u32,
            coordinates: vec![slice; BLAKE_G_LOGUP_COLUMNS * SECURE_FIELD_WORDS],
            claimed_sum: slice,
        };

        assert_eq!(output.columns, 9);
        assert_eq!(output.n_coordinate_pointers().unwrap(), 36);
    }

    #[test]
    fn blake_g_inputs_descriptor_mutations_fail_closed() {
        fn rejected(
            mut batch: RelationBatchProgram,
            mutate: impl FnOnce(&mut RelationBatchProgram),
        ) {
            mutate(&mut batch);
            assert!(!blake_g_inputs_batch_is_exact(&batch));
            let mut program = blake_g_inputs_program();
            program.batches[0] = batch;
            assert_eq!(
                program.validate(),
                Err(RelationGraphError::InvalidBlakeGInputsBatch)
            );
        }

        let canonical = blake_g_inputs_batch();
        rejected(canonical.clone(), |batch| {
            batch.columns.pop().map(drop).unwrap()
        });
        rejected(canonical.clone(), |batch| {
            batch.columns[0].uses.pop().map(drop).unwrap()
        });
        rejected(canonical.clone(), |batch| {
            batch.columns[0].uses[0].tuple_kind = RelationTupleKind::LookupWords
        });
        rejected(canonical.clone(), |batch| {
            batch.columns[0].uses[0].tuple_arg = 1
        });
        rejected(canonical.clone(), |batch| {
            batch.columns[0].uses[0].tuple_words = 5
        });
        rejected(canonical.clone(), |batch| {
            batch.columns[0].uses[0].relation_id ^= 1
        });
        rejected(canonical.clone(), |batch| {
            batch.columns[0].uses[0].multiplicity_kind = RelationMultiplicityKind::Enabler
        });
        rejected(canonical.clone(), |batch| {
            batch.columns[0].uses[0].multiplicity_arg = 1
        });
        rejected(canonical.clone(), |batch| {
            batch.columns[0].uses[0].negative = true
        });
        rejected(canonical.clone(), |batch| {
            batch.columns[8].uses[0].negative = false
        });
        rejected(canonical, |batch| {
            batch.columns[8].uses[0].multiplicity_kind = RelationMultiplicityKind::One
        });
    }

    #[test]
    fn fused_requirements_compact_only_eligible_denominators() {
        let mut program = sample_program();
        program.max_alpha_powers = RELATION_FUSED_MAX_TUPLE_WORDS + 1;
        program.batches[0].source_layout = RelationSourceLayout::LookupWords {
            words: RELATION_FUSED_MAX_TUPLE_WORDS + 2,
        };
        program.batches[0].columns[0].uses[0].tuple_words = RELATION_FUSED_MAX_TUPLE_WORDS + 1;
        assert!(!relation_batch_fused_eligible(&program.batches[0]));
        assert!(relation_batch_fused_eligible(&program.batches[1]));

        let full = program.requirements().unwrap();
        assert_eq!(
            full,
            program
                .requirements_for_mode(RelationLaunchMode::ThreeStage)
                .unwrap()
        );
        assert_eq!(full.instances[0].denominator_words, 8 * SECURE_FIELD_WORDS);
        assert_eq!(full.instances[1].denominator_words, 8 * SECURE_FIELD_WORDS);

        let fused = program
            .requirements_for_mode(RelationLaunchMode::Fused)
            .unwrap();
        assert_eq!(fused.instances[0].denominator_words, 8 * SECURE_FIELD_WORDS);
        assert_eq!(fused.instances[1].denominator_words, 1);
        assert_eq!(
            fused.instances[0].output_words,
            full.instances[0].output_words
        );
        assert_eq!(
            fused.instances[1].output_words,
            full.instances[1].output_words
        );

        let slots = sample_slots();
        let slot_requirements = fused.arena_slot_requirements(&slots).unwrap();
        let compact = slot_requirements
            .iter()
            .find(|requirement| requirement.id == slots.instances[1].denominators)
            .unwrap();
        assert_eq!(compact.len_words, 1);
        assert_eq!(compact.alignment_words, SECURE_FIELD_WORDS);
    }

    #[test]
    fn compact_fused_requirements_and_launch_modes_fail_closed() {
        let mut program = sample_program();
        let extent = program.batches[0].instances[0];
        program.batches[0].instances = vec![extent; RELATION_FUSED_MAX_INSTANCES + 1];
        program.batches[1].instances.clear();
        assert_eq!(
            program.requirements_for_mode(RelationLaunchMode::Fused),
            Err(RelationGraphError::FusedInstanceCapacityExceeded {
                instances: RELATION_FUSED_MAX_INSTANCES + 1,
                max: RELATION_FUSED_MAX_INSTANCES,
            })
        );
        assert!(program
            .requirements_for_mode(RelationLaunchMode::ThreeStage)
            .is_ok());

        assert_eq!(
            validate_prepared_launch_mode(
                RelationLaunchMode::Fused,
                RelationLaunchMode::ThreeStage
            ),
            Err(RelationGraphError::CompactFusedLaunchModeMismatch {
                requested: RelationLaunchMode::ThreeStage,
            })
        );
        assert!(validate_prepared_launch_mode(
            RelationLaunchMode::Fused,
            RelationLaunchMode::Fused
        )
        .is_ok());
        assert!(validate_prepared_launch_mode(
            RelationLaunchMode::ThreeStage,
            RelationLaunchMode::Fused
        )
        .is_ok());
        assert_eq!(
            implicit_launch_mode(RelationLaunchMode::Fused),
            RelationLaunchMode::Fused,
            "compact preparation must force implicit launch onto the fused body"
        );
    }

    #[test]
    fn graph_coverage_and_source_bounds_fail_closed() {
        let mut program = sample_program();
        program.template_use_count += 1;
        assert_eq!(
            program.validate(),
            Err(RelationGraphError::UseCoverageMismatch {
                expected: 4,
                actual: 3,
            })
        );

        assert_eq!(
            validate_use(
                RelationSourceLayout::LookupWords { words: 8 },
                lookup_use(7, 2),
            ),
            Err(RelationGraphError::SourceLayoutMismatch)
        );
        let big = RelationUseDescriptor {
            tuple_kind: RelationTupleKind::MemoryBigLimbs,
            tuple_arg: 3,
            tuple_words: 3,
            relation_id: 1,
            multiplicity_kind: RelationMultiplicityKind::One,
            multiplicity_arg: 0,
            negative: false,
        };
        assert_eq!(
            validate_use(RelationSourceLayout::MemoryBig { value_words: 4 }, big),
            Err(RelationGraphError::SourceLayoutMismatch)
        );
        assert_eq!(
            validate_use(
                RelationSourceLayout::BitwiseXor12 {
                    multiplicity_columns: 16,
                },
                RelationUseDescriptor {
                    tuple_kind: RelationTupleKind::BitwiseXor12,
                    tuple_arg: 16,
                    tuple_words: 4,
                    multiplicity_kind: RelationMultiplicityKind::BitwiseXor12,
                    multiplicity_arg: 16,
                    ..big
                },
            ),
            Err(RelationGraphError::SourceLayoutMismatch)
        );

        let projected = RelationUseDescriptor {
            tuple_kind: RelationTupleKind::ProjectedColumns,
            tuple_arg: 5,
            tuple_words: 4,
            relation_id: 1,
            multiplicity_kind: RelationMultiplicityKind::One,
            multiplicity_arg: 0,
            negative: false,
        };
        assert!(validate_use(
            RelationSourceLayout::ProjectedColumns { columns: 8 },
            projected,
        )
        .is_ok());
        assert_eq!(
            validate_use(
                RelationSourceLayout::ProjectedColumns { columns: 7 },
                projected,
            ),
            Err(RelationGraphError::SourceLayoutMismatch)
        );
        assert_eq!(
            validate_use(RelationSourceLayout::LookupWords { words: 8 }, projected),
            Err(RelationGraphError::SourceLayoutMismatch)
        );
        assert_eq!(
            validate_use(
                RelationSourceLayout::ProjectedColumns { columns: 8 },
                RelationUseDescriptor {
                    tuple_words: 0,
                    ..projected
                },
            ),
            Err(RelationGraphError::SourceLayoutMismatch)
        );
    }

    #[test]
    fn oversized_fraction_batch_fails_before_cuda() {
        let mut program = sample_program();
        let repeated = program.batches[0].columns[0].clone();
        program.template_use_count += repeated.uses.len();
        program.batches[0].columns.push(repeated);
        program.batches[0].instances[0] = RelationRowExtent::Exact {
            n_real_rows: 1,
            padded_rows: 1 << 30,
            source_offset_rows: 0,
        };

        assert_eq!(
            program.validate(),
            Err(RelationGraphError::FractionChainTooLarge {
                rows: 1 << 30,
                columns: 2,
            })
        );
    }

    #[test]
    fn fused_eligibility_classifies_tuple_width_and_column_count() {
        let program = sample_program();
        // Both sample batches sit well inside the fused envelope.
        assert!(relation_batch_fused_eligible(&program.batches[0]));
        assert!(relation_batch_fused_eligible(&program.batches[1]));
        assert!(relation_batch_one_read_eligible(&program.batches[0]));
        assert!(relation_batch_one_read_eligible(&program.batches[1]));
        assert!(!relation_batch_prefers_one_read(&program.batches[0]));
        assert!(!relation_batch_prefers_one_read(&program.batches[1]));

        // One use wider than the tuple-word cap routes the batch to the
        // 3-stage lane.
        let mut wide = program.batches[0].clone();
        wide.columns[0].uses[0].tuple_words = RELATION_FUSED_MAX_TUPLE_WORDS + 1;
        assert!(!relation_batch_fused_eligible(&wide));
        assert!(!relation_batch_one_read_eligible(&wide));
        assert!(!relation_batch_prefers_one_read(&wide));
        wide.columns[0].uses[0].tuple_words = RELATION_FUSED_MAX_TUPLE_WORDS;
        assert!(relation_batch_fused_eligible(&wide));
        assert!(relation_batch_one_read_eligible(&wide));
        assert!(relation_batch_prefers_one_read(&wide));

        // Every generated wide Cairo tuple is explicitly inside the one-read
        // lane, while the original <=32-word lane remains independently
        // bounded by the larger defensive chain limit.
        for width in [33, 36, 43, 58, 73, 87, 126] {
            wide.columns[0].uses[0].tuple_words = width;
            assert!(relation_batch_fused_eligible(&wide), "width {width}");
            assert!(relation_batch_one_read_eligible(&wide), "width {width}");
            assert!(relation_batch_prefers_one_read(&wide), "width {width}");
        }
        let column = wide.columns[0].clone();
        wide.columns = vec![column.clone(); RELATION_FUSED_ONE_READ_MAX_COLUMNS];
        assert!(relation_batch_fused_eligible(&wide));
        assert!(relation_batch_one_read_eligible(&wide));
        assert!(relation_batch_prefers_one_read(&wide));

        wide.columns.push(column.clone());
        assert!(
            !relation_batch_fused_eligible(&wide),
            "a wide row must fit the 512-fraction shared tile"
        );
        assert!(!relation_batch_one_read_eligible(&wide));
        assert!(!relation_batch_prefers_one_read(&wide));
        for relation_use in &mut wide.columns[0].uses {
            relation_use.tuple_words = RELATION_FUSED_NARROW_MAX_TUPLE_WORDS;
        }
        for relation_column in &mut wide.columns[1..] {
            for relation_use in &mut relation_column.uses {
                relation_use.tuple_words = RELATION_FUSED_NARROW_MAX_TUPLE_WORDS;
            }
        }
        assert!(
            relation_batch_fused_eligible(&wide),
            "the existing narrow lane retains its 1024-column envelope"
        );
        assert!(!relation_batch_one_read_eligible(&wide));

        wide.columns = vec![column; RELATION_FUSED_MAX_COLUMNS];
        for relation_column in &mut wide.columns {
            for relation_use in &mut relation_column.uses {
                relation_use.tuple_words = RELATION_FUSED_NARROW_MAX_TUPLE_WORDS;
            }
        }
        assert!(relation_batch_fused_eligible(&wide));
        assert!(!relation_batch_one_read_eligible(&wide));
        assert!(!relation_batch_prefers_one_read(&wide));

        // A pathological chain length also fails closed.
        let mut long = program.batches[0].clone();
        let column = long.columns[0].clone();
        long.columns = vec![column; RELATION_FUSED_MAX_COLUMNS + 1];
        assert!(!relation_batch_fused_eligible(&long));
        assert!(!relation_batch_prefers_one_read(&long));
        long.columns.pop();
        assert!(relation_batch_fused_eligible(&long));
        assert!(!relation_batch_prefers_one_read(&long));
    }

    #[test]
    fn fused_eligibility_mask_packs_bits_and_fails_closed() {
        assert_eq!(
            fused_eligibility_mask(&[]),
            Some([0u32; RELATION_FUSED_MASK_WORDS])
        );

        let mut flags = vec![false; 200];
        flags[0] = true;
        flags[31] = true;
        flags[32] = true;
        flags[68] = true;
        flags[199] = true;
        let mask = fused_eligibility_mask(&flags).unwrap();
        assert_eq!(mask[0], (1 << 0) | (1 << 31));
        assert_eq!(mask[1], 1 << 0);
        assert_eq!(mask[2], 1 << (68 - 64));
        assert_eq!(mask[6], 1 << (199 - 192));
        assert_eq!(mask[3], 0);
        assert_eq!(mask[7], 0);

        // Exactly at capacity: every bit set.
        let full = fused_eligibility_mask(&vec![true; RELATION_FUSED_MAX_INSTANCES]).unwrap();
        assert_eq!(full, [u32::MAX; RELATION_FUSED_MASK_WORDS]);

        // One instance beyond the mask capacity fails closed for the proof.
        assert_eq!(
            fused_eligibility_mask(&vec![true; RELATION_FUSED_MAX_INSTANCES + 1]),
            None
        );
    }

    #[test]
    fn duplicate_caller_slots_are_rejected() {
        let requirements = sample_program().requirements().unwrap();
        let mut slots = sample_slots();
        slots.instances[1].output_coordinates[0] = slots.instances[0].output_coordinates[0];
        assert!(matches!(
            requirements.arena_slot_requirements(&slots),
            Err(RelationGraphError::DuplicateSlot(_))
        ));
    }

    #[test]
    fn scan_partitions_cover_row_blocks_without_crossing_instances() {
        let requirements = relation_graph_requirements(&sample_program()).unwrap();
        // Instance row tiles are laid out contiguously: every instance's first
        // tile index is the running row-block total, which is exactly where a
        // lookback chain must restart with an identity prefix.
        let mut row_first = 0u32;
        for instance in &requirements.instances {
            let row_blocks = instance.row_capacity.div_ceil(REDUCTION_BLOCK as u32);
            assert!(row_blocks >= 1);
            row_first = row_first.checked_add(row_blocks).unwrap();
        }
        assert_eq!(row_first, requirements.fraction_chain_blocks);
        // One descriptor per tile plus the ticket words, matching the device
        // buffer contract validated by `stwo_relation_scan_tail_on`.
        assert_eq!(
            requirements.scan_descriptor_words,
            SCAN_TICKET_WORDS
                + requirements.fraction_chain_blocks as usize * SCAN_DESC_STRIDE_WORDS
        );
        assert_eq!(
            scan_descriptor_words(usize::MAX),
            Err(RelationGraphError::SizeOverflow)
        );
    }

    /// Host mirror of `relation_coset_scan_row` (relation_scan.cuh).
    fn coset_scan_row(scan_index: u32, rows: u32) -> u32 {
        let circle_index = if scan_index % 2 == 0 {
            scan_index / 2
        } else {
            rows - 1 - scan_index / 2
        };
        let bits = 31 - rows.leading_zeros();
        if bits == 0 {
            0
        } else {
            circle_index.reverse_bits() >> (32 - bits)
        }
    }

    #[test]
    fn scan_order_matches_circle_domain_prefix_sum_reference() {
        use num_traits::Zero;
        use stwo::core::utils::{bit_reverse, coset_order_to_circle_domain_order};

        // The oracle the parity tests compare against: bit-reverse circle
        // order, interleave the two circle-domain halves, inclusive scan, and
        // undo both permutations.
        fn reference(mut values: Vec<SecureField>) -> Vec<SecureField> {
            bit_reverse(&mut values);
            let mut coset = Vec::with_capacity(values.len());
            for index in 0..values.len() / 2 {
                coset.extend([values[index], values[values.len() - 1 - index]]);
            }
            let mut sum = SecureField::zero();
            for value in &mut coset {
                sum += *value;
                *value = sum;
            }
            let mut output = coset_order_to_circle_domain_order(&coset);
            bit_reverse(&mut output);
            output
        }

        for log_rows in 1..=9u32 {
            let rows = 1u32 << log_rows;
            let values = (0..rows)
                .map(|row| {
                    SecureField::from_u32_unchecked(
                        (7 + 13 * row) % 1009,
                        (3 + 29 * row) % 2027,
                        (11 + 31 * row) % 4093,
                        (5 + 37 * row) % 8191,
                    )
                })
                .collect::<Vec<_>>();

            // The device lanes walk scan positions through the storage-row
            // bijection and update in place; both tails share this mapping.
            let mut sequential = values.clone();
            let mut positions_seen = vec![false; rows as usize];
            let mut inclusive = SecureField::zero();
            for scan_index in 0..rows {
                let row = coset_scan_row(scan_index, rows) as usize;
                assert!(!positions_seen[row], "scan order must be a bijection");
                positions_seen[row] = true;
                inclusive += values[row];
                sequential[row] = inclusive;
            }
            assert_eq!(sequential, reference(values.clone()));

            // The claimed sum is the final inclusive value — the same total
            // the segmented reduce tree produces.
            assert_eq!(inclusive, values.iter().copied().sum::<SecureField>());
        }
        assert_eq!(coset_scan_row(0, 1), 0);
    }
}
