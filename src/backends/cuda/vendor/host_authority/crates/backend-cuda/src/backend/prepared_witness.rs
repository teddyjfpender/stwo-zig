//! Prepared, arena-backed recorded witness execution.
//!
//! Setup resolves the recorded kernel, binds every source/destination, and uploads
//! immutable pointer tables once. [`PreparedWitnessGraph::launch`] is then a single
//! explicit-stream cached-kernel enqueue: it allocates, transfers, and synchronizes
//! nothing, so the exact same method is safe during CUDA graph capture.

use core::ffi::c_void;
use std::collections::BTreeSet;
use std::ffi::CString;

use super::blake_witness::{
    BG_FUSED_PROGRAM_IDENTITY, BG_FUSED_SEMANTIC_HASH, BG_N_DATA_INPUTS, BG_N_LOOKUP_WORDS,
    BG_N_RECORDED_INPUTS, BG_N_SUB_WORDS, BG_N_TRACE,
};
use super::exec_context::{
    ArenaError, ArenaSlice, ArenaSlotId, CudaLaunchContext, CudaRuntimeError, DeviceArena,
};
use super::exec_tables::{witness_table_pointers, DeviceExecutionTables};
use super::jit_witness::isa::{WitnessOp, WitnessProgram};
use super::prepared_execution_tables::PreparedExecutionTablesView;
use super::{aot, jit_witness};

mod blake_g_direct_authority;
mod installed_aot;
mod phase_program;
pub use blake_g_direct_authority::{
    BlakeGDirectAbiAccess, BlakeGDirectAbiArgument, BlakeGDirectAbiArgumentKind,
    BlakeGDirectAuthorityError, BlakeGDirectCompositeAbi, BlakeGDirectCompositeContract,
    BlakeGDirectCountDestination, BlakeGDirectEffectAbi, BlakeGDirectLut, BlakeGDirectRowDomain,
    BlakeGDirectWrapperLaunch, BLAKE_G_DIRECT_BLOCK_THREADS, BLAKE_G_DIRECT_COUNT_ORDER,
    BLAKE_G_DIRECT_COUNT_WORDS, BLAKE_G_DIRECT_LUT_ORDER, BLAKE_G_DIRECT_LUT_WORDS,
};
pub use phase_program::{phase_scratch_words, PreparedWitnessPhaseProgram};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);
const EXECUTION_TABLE_POINTERS: usize = 37;
const EXECUTION_TABLE_STRIDES: usize = 3;

pub const WITNESS_POINTER_ALIGNMENT_WORDS: usize = core::mem::align_of::<*mut u32>() / WORD_BYTES;

/// Kernel-admission policy selected during setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedWitnessMode {
    /// Resolve the kernel before capture, allowing the existing runtime compiler on
    /// an embedded-pack miss. Launch still performs no compilation.
    PreResolved,
    /// Permanently enable AOT-only lookup and reject this graph unless its exact
    /// semantic key is present in the embedded pack for the active GPU.
    RequireEmbeddedAot,
}

/// Immutable identity sealed into one prepared launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessKernelIdentity {
    pub label: String,
    pub kernel_name: String,
    pub semantic_hash: u64,
    pub cache_key: u64,
    /// Collision-resistant identity for the exact embedded AOT pack. The
    /// source/effect contract remains a separate authority frontier.
    pub aot_manifest_identity: [u8; 32],
    /// Non-authoritative compatibility/telemetry projection of
    /// `aot_manifest_identity`.
    pub aot_manifest_hash: u64,
    pub mode: PreparedWitnessMode,
}

struct WitnessKernelMaterial {
    identity: WitnessKernelIdentity,
    /// Strict AOT preparation deliberately carries no CUDA source. The embedded
    /// cubin is resolved by semantic key, so materializing the (potentially very
    /// large) source translation unit on every warm proof would be pure overhead.
    source: Option<String>,
}

#[derive(Clone, Copy)]
struct AotManifestBinding {
    identity: [u8; 32],
    telemetry_tag: u64,
}

fn witness_kernel_material(
    program: &WitnessProgram,
    mode: PreparedWitnessMode,
    manifest: AotManifestBinding,
) -> Result<WitnessKernelMaterial, PreparedWitnessError> {
    witness_kernel_material_with(program, mode, manifest, aot::witness_kernel_source)
}

fn witness_kernel_material_with<F>(
    program: &WitnessProgram,
    mode: PreparedWitnessMode,
    manifest: AotManifestBinding,
    emit_source: F,
) -> Result<WitnessKernelMaterial, PreparedWitnessError>
where
    F: FnOnce(&WitnessProgram) -> Option<aot::EmittedKernel>,
{
    let (kernel_name, semantic_hash, cache_key, source) = match mode {
        PreparedWitnessMode::RequireEmbeddedAot => {
            let semantic_hash = program.semantic_hash();
            (
                jit_witness::codegen::witness_kernel_name(semantic_hash),
                semantic_hash,
                jit_witness::codegen::witness_jit_cache_key(semantic_hash),
                None,
            )
        }
        PreparedWitnessMode::PreResolved => {
            let emitted = emit_source(program)
                .ok_or_else(|| PreparedWitnessError::CodegenFailed(program.label.clone()))?;
            (
                emitted.kernel_name,
                emitted.semantic_hash,
                emitted.cache_key,
                Some(emitted.source),
            )
        }
    };
    Ok(WitnessKernelMaterial {
        identity: WitnessKernelIdentity {
            label: program.label.clone(),
            kernel_name,
            semantic_hash,
            cache_key,
            aot_manifest_identity: manifest.identity,
            aot_manifest_hash: manifest.telemetry_tag,
            mode,
        },
        source,
    })
}

fn enable_strict_aot(identity: &WitnessKernelIdentity) -> Result<(), PreparedWitnessError> {
    if identity.aot_manifest_identity == [0; 32] {
        return Err(PreparedWitnessError::EmptyAotManifest);
    }
    // Strictness is process-wide and monotonic. The source-free precompile below
    // therefore performs exactly runtime_jit's tier-0 `(cache_key, active SM)`
    // embedded-pack lookup and cannot fall through to disk PTX or NVRTC.
    aot::require_loaded_kernels();
    Ok(())
}

fn classify_kernel_preparation(
    identity: &WitnessKernelIdentity,
    prepared: bool,
) -> Result<(), PreparedWitnessError> {
    if prepared {
        Ok(())
    } else {
        Err(match identity.mode {
            PreparedWitnessMode::RequireEmbeddedAot => {
                PreparedWitnessError::StrictAotUnavailable(identity.clone())
            }
            PreparedWitnessMode::PreResolved => {
                PreparedWitnessError::KernelPreparationFailed(identity.clone())
            }
        })
    }
}

fn witness_precompile_relax_opt_with<F>(
    mode: PreparedWitnessMode,
    n_instrs: usize,
    prove_max_instrs: F,
) -> bool
where
    F: FnOnce() -> usize,
{
    match mode {
        // The embedded artifact was already admitted by its semantic key. Its build
        // optimization is sealed into that artifact, so runtime policy must not
        // influence (or even be observed by) this lane.
        PreparedWitnessMode::RequireEmbeddedAot => false,
        PreparedWitnessMode::PreResolved => n_instrs > prove_max_instrs(),
    }
}

fn witness_precompile_relax_opt(mode: PreparedWitnessMode, n_instrs: usize) -> bool {
    witness_precompile_relax_opt_with(mode, n_instrs, jit_witness::witness_prove_max_instrs)
}

/// Exact work submitted by one hot-path [`PreparedWitnessGraph::launch`].
///
/// The CUDA execution context cannot see driver-API launches made by the generated
/// kernel shim, so the prepared primitive exposes this static one-kernel contract for
/// the resident runtime's aggregate telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedWitnessLaunchTelemetry {
    pub kernel_launches: u64,
    pub allocations: u64,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub d2d_bytes: u64,
    pub sync_calls: u64,
    pub memset_bytes: u64,
}

impl PreparedWitnessLaunchTelemetry {
    const KERNEL: Self = Self {
        kernel_launches: 1,
        allocations: 0,
        h2d_bytes: 0,
        d2h_bytes: 0,
        d2d_bytes: 0,
        sync_calls: 0,
        memset_bytes: 0,
    };

    const PHASE_PAIR: Self = Self {
        kernel_launches: 2,
        ..Self::KERNEL
    };

    fn clear(bytes: u64) -> Self {
        Self {
            kernel_launches: 0,
            memset_bytes: bytes,
            ..Self::KERNEL
        }
    }
}

/// Exact pure sizing for one recorded program at one row extent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessWorkspaceRequirements {
    pub row_count: usize,
    pub input_column_words: Vec<usize>,
    pub input_pointer_words: usize,
    pub execution_table_pointer_words: usize,
    pub execution_table_stride_words: usize,
    pub output_column_words: Vec<usize>,
    pub output_pointer_words: usize,
    pub multiplicity_column_words: Vec<usize>,
    pub multiplicity_pointer_words: usize,
    pub multiplicity_dummy_words: Option<usize>,
    pub lookup_words: usize,
    pub sub_words: usize,
}

/// One slot request for merging this graph into the proof-wide arena layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

/// Logical slots consumed by one prepared witness graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessWorkspaceSlots {
    pub input_columns: Vec<ArenaSlotId>,
    pub input_pointers: ArenaSlotId,
    pub execution_table_pointers: ArenaSlotId,
    pub execution_table_strides: ArenaSlotId,
    pub output_columns: Vec<ArenaSlotId>,
    pub output_pointers: ArenaSlotId,
    pub multiplicity_columns: Vec<ArenaSlotId>,
    pub multiplicity_pointers: ArenaSlotId,
    pub multiplicity_dummy: Option<ArenaSlotId>,
    pub lookup_words: ArenaSlotId,
    pub sub_words: ArenaSlotId,
}

impl WitnessWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &WitnessWorkspaceSlots,
    ) -> Result<Vec<WitnessArenaSlotRequirement>, PreparedWitnessError> {
        self.arena_slot_requirements_inner(slots, true, true, true, self.input_column_words.len())
    }

    /// Arena requirements when the execution-table descriptor pair is supplied
    /// by a shared [`PreparedExecutionTablesView`]. The two per-writer descriptor
    /// fields in `slots` are ignored and need not exist in the arena layout.
    pub fn arena_slot_requirements_with_prepared_execution_tables(
        &self,
        slots: &WitnessWorkspaceSlots,
    ) -> Result<Vec<WitnessArenaSlotRequirement>, PreparedWitnessError> {
        self.arena_slot_requirements_inner(slots, false, true, true, self.input_column_words.len())
    }

    /// Exact native Blake-G contract: the fused producer never executes the
    /// recorded writer's `SubWord` instructions, so its sub destination aliases
    /// the existing one-word multiplicity dummy and contributes no arena slab.
    pub fn arena_slot_requirements_for_blake_g_fusion_with_prepared_execution_tables(
        &self,
        slots: &WitnessWorkspaceSlots,
    ) -> Result<Vec<WitnessArenaSlotRequirement>, PreparedWitnessError> {
        if slots.multiplicity_dummy != Some(slots.sub_words) {
            return Err(PreparedWitnessError::BlakeGFusionShape(
                "retired sub destination must alias the existing dummy",
            ));
        }
        self.arena_slot_requirements_inner(slots, false, true, false, self.input_column_words.len())
    }

    /// Replacement Blake-G contract: six raw inputs stay live, while the
    /// enabler is synthesized from `row < n_real` and both flattened writer
    /// tails are absent. Their logical slot IDs must all name the existing
    /// one-word multiplicity dummy, making accidental materialization fail
    /// before arena construction.
    pub fn arena_slot_requirements_for_blake_g_direct_with_prepared_execution_tables(
        &self,
        slots: &WitnessWorkspaceSlots,
    ) -> Result<Vec<WitnessArenaSlotRequirement>, PreparedWitnessError> {
        let canonical = self.row_count > 0
            && self.input_column_words.len() == BG_N_RECORDED_INPUTS
            && self
                .input_column_words
                .iter()
                .all(|&words| words == self.row_count)
            && self.input_pointer_words == pointer_words(BG_N_RECORDED_INPUTS)?
            && self.output_column_words.len() == BG_N_TRACE
            && self
                .output_column_words
                .iter()
                .all(|&words| words == self.row_count)
            && self.output_pointer_words == pointer_words(BG_N_TRACE)?
            && self.multiplicity_column_words.is_empty()
            && self.multiplicity_pointer_words == POINTER_WORDS
            && self.multiplicity_dummy_words == Some(1)
            && self.lookup_words
                == self
                    .row_count
                    .checked_mul(BG_N_LOOKUP_WORDS)
                    .ok_or(PreparedWitnessError::SizeOverflow)?
            && self.sub_words
                == self
                    .row_count
                    .checked_mul(BG_N_SUB_WORDS)
                    .ok_or(PreparedWitnessError::SizeOverflow)?;
        if !canonical {
            return Err(PreparedWitnessError::BlakeGFusionShape(
                "direct blake_g workspace geometry drifted",
            ));
        }
        if slots.multiplicity_dummy != Some(slots.lookup_words)
            || slots.multiplicity_dummy != Some(slots.sub_words)
        {
            return Err(PreparedWitnessError::BlakeGFusionShape(
                "retired lookup and sub destinations must alias the existing dummy",
            ));
        }
        self.arena_slot_requirements_inner(slots, false, false, false, BG_N_DATA_INPUTS)
    }

    fn arena_slot_requirements_inner(
        &self,
        slots: &WitnessWorkspaceSlots,
        include_execution_tables: bool,
        include_lookup_words: bool,
        include_sub_words: bool,
        input_columns: usize,
    ) -> Result<Vec<WitnessArenaSlotRequirement>, PreparedWitnessError> {
        validate_slot_shape(self, slots, input_columns)?;
        let mut result = Vec::new();
        result.extend(
            slots
                .input_columns
                .iter()
                .zip(&self.input_column_words[..input_columns])
                .map(|(&id, &len_words)| words(id, len_words)),
        );
        result.push(pointers(
            slots.input_pointers,
            pointer_words(input_columns)?,
        ));
        if include_execution_tables {
            result.extend([
                pointers(
                    slots.execution_table_pointers,
                    self.execution_table_pointer_words,
                ),
                words(
                    slots.execution_table_strides,
                    self.execution_table_stride_words,
                ),
            ]);
        }
        result.extend(
            slots
                .output_columns
                .iter()
                .zip(&self.output_column_words)
                .map(|(&id, &len_words)| words(id, len_words)),
        );
        result.push(pointers(slots.output_pointers, self.output_pointer_words));
        result.extend(
            slots
                .multiplicity_columns
                .iter()
                .zip(&self.multiplicity_column_words)
                .map(|(&id, &len_words)| words(id, len_words)),
        );
        result.push(pointers(
            slots.multiplicity_pointers,
            self.multiplicity_pointer_words,
        ));
        if let (Some(id), Some(len_words)) =
            (slots.multiplicity_dummy, self.multiplicity_dummy_words)
        {
            result.push(words(id, len_words));
        }
        if include_lookup_words {
            result.push(words(slots.lookup_words, self.lookup_words));
        }
        if include_sub_words {
            result.push(words(slots.sub_words, self.sub_words));
        }
        ensure_distinct(&result.iter().map(|entry| entry.id).collect::<Vec<_>>())?;
        Ok(result)
    }
}

fn words(id: ArenaSlotId, len_words: usize) -> WitnessArenaSlotRequirement {
    WitnessArenaSlotRequirement {
        id,
        len_words,
        alignment_words: 1,
    }
}

fn pointers(id: ArenaSlotId, len_words: usize) -> WitnessArenaSlotRequirement {
    WitnessArenaSlotRequirement {
        id,
        len_words,
        alignment_words: WITNESS_POINTER_ALIGNMENT_WORDS,
    }
}

/// Pure workspace pass. Multiplicity lengths are destination-table extents in the
/// recorder's compact table-index order.
pub fn witness_workspace_requirements(
    program: &WitnessProgram,
    row_count: usize,
    multiplicity_words: &[usize],
) -> Result<WitnessWorkspaceRequirements, PreparedWitnessError> {
    if row_count == 0 {
        return Err(PreparedWitnessError::ZeroRows);
    }
    u32::try_from(row_count).map_err(|_| PreparedWitnessError::RowCountOverflow)?;
    validate_program_outputs(program)?;
    let n_inputs =
        usize::try_from(program.n_inputs).map_err(|_| PreparedWitnessError::SizeOverflow)?;
    let n_outputs =
        usize::try_from(program.n_cols).map_err(|_| PreparedWitnessError::SizeOverflow)?;
    let n_mult =
        usize::try_from(program.n_mult_tables).map_err(|_| PreparedWitnessError::SizeOverflow)?;
    if multiplicity_words.len() != n_mult {
        return Err(PreparedWitnessError::MultiplicityCountMismatch {
            expected: n_mult,
            actual: multiplicity_words.len(),
        });
    }
    if let Some(index) = multiplicity_words.iter().position(|&len| len == 0) {
        return Err(PreparedWitnessError::EmptyMultiplicity(index));
    }
    let flat_words = |words_per_row: u32| {
        usize::try_from(words_per_row)
            .ok()
            .and_then(|words| words.checked_mul(row_count))
            .map(|words| words.max(1))
            .ok_or(PreparedWitnessError::SizeOverflow)
    };
    Ok(WitnessWorkspaceRequirements {
        row_count,
        input_column_words: vec![row_count; n_inputs],
        input_pointer_words: pointer_words(n_inputs)?,
        execution_table_pointer_words: pointer_words(EXECUTION_TABLE_POINTERS)?,
        execution_table_stride_words: EXECUTION_TABLE_STRIDES,
        output_column_words: vec![row_count; n_outputs],
        output_pointer_words: pointer_words(n_outputs)?,
        multiplicity_column_words: multiplicity_words.to_vec(),
        multiplicity_pointer_words: pointer_words(n_mult)?,
        multiplicity_dummy_words: (n_mult == 0).then_some(1),
        lookup_words: flat_words(program.n_lookup_words)?,
        sub_words: flat_words(program.n_sub_words)?,
    })
}

fn pointer_words(count: usize) -> Result<usize, PreparedWitnessError> {
    count
        .max(1)
        .checked_mul(POINTER_WORDS)
        .ok_or(PreparedWitnessError::SizeOverflow)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedWitnessError {
    CudaUnavailable,
    ZeroRows,
    RowCountOverflow,
    SizeOverflow,
    MultiplicityCountMismatch {
        expected: usize,
        actual: usize,
    },
    EmptyMultiplicity(usize),
    InvalidOpcode {
        instruction: usize,
        opcode: u8,
    },
    ProgramIndexOutOfRange {
        instruction: usize,
        role: &'static str,
        index: u32,
        count: u32,
    },
    SlotShapeMismatch {
        role: &'static str,
        expected: usize,
        actual: usize,
    },
    DuplicateSlot(ArenaSlotId),
    PhysicalAlias {
        first: ArenaSlotId,
        second: ArenaSlotId,
    },
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    SlotMisaligned(ArenaSlotId),
    ExecutionTableShapeMismatch,
    ExecutionTableContextMismatch,
    RecordingMissing(String),
    InvalidIsa(String),
    CodegenFailed(String),
    InvalidKernelString,
    EmptyAotManifest,
    PhasePlanMismatch,
    PhaseProgramMismatch,
    PhaseRequiresStrictAot,
    PhaseScratchMissing {
        required_words: usize,
    },
    PhaseScratchUnexpected(ArenaSlotId),
    PhaseAotPreparationFailed([WitnessKernelIdentity; 2]),
    PhaseKernelLaunchFailed([WitnessKernelIdentity; 2]),
    StrictAotUnavailable(WitnessKernelIdentity),
    StrictAotAuthorityMissing(WitnessKernelIdentity),
    StrictAotAuthorityMismatch {
        identity: WitnessKernelIdentity,
        field: &'static str,
    },
    StrictAotInstall {
        identity: WitnessKernelIdentity,
        error: aot::InstalledAotFunctionError,
    },
    StrictAotReceiptMismatch {
        identity: WitnessKernelIdentity,
        field: &'static str,
    },
    KernelPreparationFailed(WitnessKernelIdentity),
    KernelLaunchFailed(WitnessKernelIdentity),
    BlakeGDirectAuthority(BlakeGDirectAuthorityError),
    BlakeGFusionShape(&'static str),
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedWitnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "prepared witness graph rejected: {self:?}")
    }
}

impl std::error::Error for PreparedWitnessError {}

impl From<ArenaError> for PreparedWitnessError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedWitnessError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

impl From<BlakeGDirectAuthorityError> for PreparedWitnessError {
    fn from(value: BlakeGDirectAuthorityError) -> Self {
        Self::BlakeGDirectAuthority(value)
    }
}

/// Allocation-free prepared witness launch. The borrowed tables and arena make every
/// address captured by the kernel structurally outlive this plan.
#[derive(Clone, Copy)]
enum WitnessExecutionTables<'a> {
    Legacy(&'a DeviceExecutionTables),
    Prepared(PreparedExecutionTablesView<'a>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WitnessLaunchContract {
    Recorded,
    BlakeGFused,
    BlakeGDirect,
}

/// Fail-closed identity gate for the hand-lowered Blake-G implementation.
/// Geometry alone is insufficient: a regenerated row body must fall back to
/// the recorded writer until the native lowering is re-proven and re-pinned.
pub fn blake_g_fusion_program_is_exact(program: &WitnessProgram) -> bool {
    program.label == "blake_g"
        && program.semantic_identity() == BG_FUSED_PROGRAM_IDENTITY
        && program.semantic_hash() == BG_FUSED_SEMANTIC_HASH
        && program.n_inputs as usize == BG_N_RECORDED_INPUTS
        && program.n_cols as usize == BG_N_TRACE
        && program.n_lookup_words as usize == BG_N_LOOKUP_WORDS
        && program.n_sub_words as usize == BG_N_SUB_WORDS
        && program.n_mult_tables == 0
}

pub struct PreparedWitnessGraph<'a> {
    arena: &'a DeviceArena,
    _tables: WitnessExecutionTables<'a>,
    identity: WitnessKernelIdentity,
    installed_aot: Option<aot::InstalledAotFunction<'a>>,
    source: Option<CString>,
    kernel_name: CString,
    row_count: u32,
    instruction_count: u32,
    input_columns: Vec<ArenaSlice>,
    output_columns: Vec<ArenaSlice>,
    multiplicity_columns: Vec<ArenaSlice>,
    input_pointers: ArenaSlice,
    execution_table_pointers: ArenaSlice,
    execution_table_strides: ArenaSlice,
    output_pointers: ArenaSlice,
    multiplicity_pointers: ArenaSlice,
    multiplicity_dummy: Option<ArenaSlice>,
    lookup_words: ArenaSlice,
    sub_words: ArenaSlice,
    launch_contract: WitnessLaunchContract,
    blake_g_direct_contract: Option<BlakeGDirectCompositeContract>,
}

impl<'a> PreparedWitnessGraph<'a> {
    /// Resolve a program from the shared recording registry and prepare it.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_registered(
        arena: &'a DeviceArena,
        label: &str,
        row_count: usize,
        multiplicity_words: &[usize],
        tables: &'a DeviceExecutionTables,
        slots: &WitnessWorkspaceSlots,
        mode: PreparedWitnessMode,
    ) -> Result<Self, PreparedWitnessError> {
        let program = jit_witness::recorded_program(label)
            .ok_or_else(|| PreparedWitnessError::RecordingMissing(label.to_string()))?;
        Self::prepare(
            arena,
            program,
            row_count,
            multiplicity_words,
            tables,
            slots,
            mode,
        )
    }

    /// Prepared-table counterpart of [`Self::prepare_registered`]. The shared
    /// descriptor view points exclusively into this proof arena.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_registered_with_execution_tables(
        arena: &'a DeviceArena,
        label: &str,
        row_count: usize,
        multiplicity_words: &[usize],
        tables: PreparedExecutionTablesView<'a>,
        slots: &WitnessWorkspaceSlots,
        mode: PreparedWitnessMode,
    ) -> Result<Self, PreparedWitnessError> {
        let program = jit_witness::recorded_program(label)
            .ok_or_else(|| PreparedWitnessError::RecordingMissing(label.to_string()))?;
        Self::prepare_with_execution_tables(
            arena,
            program,
            row_count,
            multiplicity_words,
            tables,
            slots,
            mode,
        )
    }

    /// Bind all slots, pre-resolve the generated kernel, upload immutable pointer
    /// descriptors, and drain setup once before graph capture.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        arena: &'a DeviceArena,
        program: &WitnessProgram,
        row_count: usize,
        multiplicity_words: &[usize],
        tables: &'a DeviceExecutionTables,
        slots: &WitnessWorkspaceSlots,
        mode: PreparedWitnessMode,
    ) -> Result<Self, PreparedWitnessError> {
        Self::prepare_inner(
            arena,
            program,
            row_count,
            multiplicity_words,
            WitnessExecutionTables::Legacy(tables),
            slots,
            mode,
            WitnessLaunchContract::Recorded,
        )
    }

    /// Bind a prepared arena-owned execution-table view. This path performs no
    /// legacy-stream handoff and never copies table descriptors into per-writer
    /// slots; every writer shares the immutable workspace-owned descriptor pair.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_execution_tables(
        arena: &'a DeviceArena,
        program: &WitnessProgram,
        row_count: usize,
        multiplicity_words: &[usize],
        tables: PreparedExecutionTablesView<'a>,
        slots: &WitnessWorkspaceSlots,
        mode: PreparedWitnessMode,
    ) -> Result<Self, PreparedWitnessError> {
        Self::prepare_inner(
            arena,
            program,
            row_count,
            multiplicity_words,
            WitnessExecutionTables::Prepared(tables),
            slots,
            mode,
            WitnessLaunchContract::Recorded,
        )
    }

    /// Prepare the exact native Blake-G producer/feed replacement. The generic
    /// recorded writer remains pre-resolved for identity admission, but its
    /// multi-gigabyte sub destination is structurally absent and generic launch
    /// is forbidden on the resulting graph.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_blake_g_fused_with_execution_tables(
        arena: &'a DeviceArena,
        program: &WitnessProgram,
        row_count: usize,
        tables: PreparedExecutionTablesView<'a>,
        slots: &WitnessWorkspaceSlots,
        mode: PreparedWitnessMode,
    ) -> Result<Self, PreparedWitnessError> {
        Self::prepare_inner(
            arena,
            program,
            row_count,
            &[],
            WitnessExecutionTables::Prepared(tables),
            slots,
            mode,
            WitnessLaunchContract::BlakeGFused,
        )
    }

    /// Prepare the replacement Blake-G producer/feed body. Only the six raw
    /// data inputs and 53 committed trace columns are retained; the recorded
    /// enabler input, lookup slab, and sub slab are structurally absent.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_blake_g_direct_with_execution_tables(
        arena: &'a DeviceArena,
        program: &WitnessProgram,
        n_real_rows: usize,
        row_count: usize,
        tables: PreparedExecutionTablesView<'a>,
        slots: &WitnessWorkspaceSlots,
        mode: PreparedWitnessMode,
    ) -> Result<Self, PreparedWitnessError> {
        let contract = BlakeGDirectCompositeContract::compile(program, n_real_rows, row_count)?;
        let mut prepared = Self::prepare_inner(
            arena,
            program,
            row_count,
            &[],
            WitnessExecutionTables::Prepared(tables),
            slots,
            mode,
            WitnessLaunchContract::BlakeGDirect,
        )?;
        prepared.blake_g_direct_contract = Some(contract);
        Ok(prepared)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_inner(
        arena: &'a DeviceArena,
        program: &WitnessProgram,
        row_count: usize,
        multiplicity_words: &[usize],
        tables: WitnessExecutionTables<'a>,
        slots: &WitnessWorkspaceSlots,
        mode: PreparedWitnessMode,
        launch_contract: WitnessLaunchContract,
    ) -> Result<Self, PreparedWitnessError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedWitnessError::CudaUnavailable);
        }
        jit_witness::isa::validate_isa_layout().map_err(PreparedWitnessError::InvalidIsa)?;
        let requirements = witness_workspace_requirements(program, row_count, multiplicity_words)?;
        if matches!(
            launch_contract,
            WitnessLaunchContract::BlakeGFused | WitnessLaunchContract::BlakeGDirect
        ) && !blake_g_fusion_program_is_exact(program)
        {
            return Err(PreparedWitnessError::BlakeGFusionShape(
                "recorded blake_g program identity drifted",
            ));
        }
        match (tables, launch_contract) {
            (WitnessExecutionTables::Legacy(_), WitnessLaunchContract::Recorded) => {
                requirements.arena_slot_requirements(slots)?
            }
            (WitnessExecutionTables::Prepared(_), WitnessLaunchContract::Recorded) => {
                requirements.arena_slot_requirements_with_prepared_execution_tables(slots)?
            }
            (WitnessExecutionTables::Prepared(_), WitnessLaunchContract::BlakeGFused) => {
                requirements
                    .arena_slot_requirements_for_blake_g_fusion_with_prepared_execution_tables(
                        slots,
                    )?
            }
            (WitnessExecutionTables::Prepared(_), WitnessLaunchContract::BlakeGDirect) => {
                requirements
                    .arena_slot_requirements_for_blake_g_direct_with_prepared_execution_tables(
                        slots,
                    )?
            }
            (
                WitnessExecutionTables::Legacy(_),
                WitnessLaunchContract::BlakeGFused | WitnessLaunchContract::BlakeGDirect,
            ) => {
                return Err(PreparedWitnessError::BlakeGFusionShape(
                    "fused blake_g requires prepared execution tables",
                ));
            }
        };

        let direct_blake_g = launch_contract == WitnessLaunchContract::BlakeGDirect;
        let input_column_words = if direct_blake_g {
            &requirements.input_column_words[..BG_N_DATA_INPUTS]
        } else {
            &requirements.input_column_words
        };
        let input_columns = bind_many(arena, &slots.input_columns, input_column_words, 1)?;
        let output_columns = bind_many(
            arena,
            &slots.output_columns,
            &requirements.output_column_words,
            1,
        )?;
        let multiplicity_columns = bind_many(
            arena,
            &slots.multiplicity_columns,
            &requirements.multiplicity_column_words,
            1,
        )?;
        let input_pointers = bind_slot(
            arena,
            slots.input_pointers,
            pointer_words(input_column_words.len())?,
            WITNESS_POINTER_ALIGNMENT_WORDS,
        )?;
        let (execution_table_pointers, execution_table_strides) = match tables {
            WitnessExecutionTables::Legacy(_) => (
                bind_slot(
                    arena,
                    slots.execution_table_pointers,
                    requirements.execution_table_pointer_words,
                    WITNESS_POINTER_ALIGNMENT_WORDS,
                )?,
                bind_slot(
                    arena,
                    slots.execution_table_strides,
                    requirements.execution_table_stride_words,
                    1,
                )?,
            ),
            WitnessExecutionTables::Prepared(view) => {
                if !view.belongs_to(arena) {
                    return Err(PreparedWitnessError::ExecutionTableContextMismatch);
                }
                (view.table_pointers(), view.table_strides())
            }
        };
        let output_pointers = bind_slot(
            arena,
            slots.output_pointers,
            requirements.output_pointer_words,
            WITNESS_POINTER_ALIGNMENT_WORDS,
        )?;
        let multiplicity_pointers = bind_slot(
            arena,
            slots.multiplicity_pointers,
            requirements.multiplicity_pointer_words,
            WITNESS_POINTER_ALIGNMENT_WORDS,
        )?;
        let multiplicity_dummy = match (
            slots.multiplicity_dummy,
            requirements.multiplicity_dummy_words,
        ) {
            (Some(id), Some(len_words)) => Some(bind_slot(arena, id, len_words, 1)?),
            (None, None) => None,
            _ => unreachable!("slot shape validated"),
        };
        let lookup_words = if direct_blake_g {
            multiplicity_dummy.ok_or(PreparedWitnessError::BlakeGFusionShape(
                "direct blake_g is missing its one-word dummy",
            ))?
        } else {
            bind_slot(arena, slots.lookup_words, requirements.lookup_words, 1)?
        };
        let sub_words = match launch_contract {
            WitnessLaunchContract::Recorded => {
                bind_slot(arena, slots.sub_words, requirements.sub_words, 1)?
            }
            WitnessLaunchContract::BlakeGFused | WitnessLaunchContract::BlakeGDirect => {
                multiplicity_dummy.ok_or(PreparedWitnessError::BlakeGFusionShape(
                    "fused blake_g is missing its one-word dummy",
                ))?
            }
        };
        let prepared_table_data = match tables {
            WitnessExecutionTables::Legacy(_) => None,
            WitnessExecutionTables::Prepared(view) => Some(view.table_data()),
        };

        // `ArenaLayout::new_reused` proves only the caller-declared epoch masks.
        // Re-establish the stronger kernel-local fact after binding: every range
        // observed by this prepared launch is physically disjoint. This makes a
        // stale or incomplete lifetime mask fail closed before descriptor upload
        // or graph capture. Blake-G's retired sub destination is the one exact
        // authorized alias; it is represented by `multiplicity_dummy` only once.
        let bound_ranges = input_columns
            .iter()
            .copied()
            .chain(output_columns.iter().copied())
            .chain(multiplicity_columns.iter().copied())
            .chain([
                input_pointers,
                execution_table_pointers,
                execution_table_strides,
                output_pointers,
                multiplicity_pointers,
            ])
            .chain((!direct_blake_g).then_some(lookup_words))
            .chain(multiplicity_dummy)
            .chain((launch_contract == WitnessLaunchContract::Recorded).then_some(sub_words))
            .chain(prepared_table_data.into_iter().flatten());
        ensure_physically_disjoint(bound_ranges)?;

        let manifest = AotManifestBinding {
            identity: aot::loaded_manifest_identity(),
            telemetry_tag: aot::loaded_manifest_hash(),
        };
        let material = witness_kernel_material(program, mode, manifest)?;
        let identity = material.identity;
        if mode == PreparedWitnessMode::RequireEmbeddedAot {
            enable_strict_aot(&identity)?;
        }
        let source = material
            .source
            .map(CString::new)
            .transpose()
            .map_err(|_| PreparedWitnessError::InvalidKernelString)?;
        let kernel_name = CString::new(identity.kernel_name.clone())
            .map_err(|_| PreparedWitnessError::InvalidKernelString)?;
        let relax_opt = witness_precompile_relax_opt(mode, program.n_instrs());
        let source_ptr = source
            .as_ref()
            .map_or(core::ptr::null(), |source| source.as_ptr());
        let prepared = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_cuda_jit_precompile(
                source_ptr,
                kernel_name.as_ptr(),
                identity.cache_key,
                relax_opt,
            )
        };
        classify_kernel_preparation(&identity, prepared)?;
        let installed_aot = installed_aot::install(arena.context(), &identity, program, row_count)?;

        let input_values = pointer_values(&input_columns);
        let output_values = pointer_values(&output_columns);
        let multiplicity_values = if multiplicity_columns.is_empty() {
            vec![multiplicity_dummy
                .expect("slot shape validated")
                .as_u32_ptr() as usize]
        } else {
            pointer_values(&multiplicity_columns)
        };
        upload_descriptor(arena, input_pointers, &input_values)?;
        if let WitnessExecutionTables::Legacy(legacy) = tables {
            let (table_pointers, table_strides) = witness_table_pointers(legacy);
            if table_pointers.len() != EXECUTION_TABLE_POINTERS
                || table_strides.len() != EXECUTION_TABLE_STRIDES
            {
                return Err(PreparedWitnessError::ExecutionTableShapeMismatch);
            }
            let table_values: Vec<usize> = table_pointers
                .into_iter()
                .map(|pointer| pointer as usize)
                .collect();
            // The compatibility tables are still born on the legacy stream.
            crate::synchronize_legacy_stream_for_arena_handoff();
            upload_descriptor(arena, execution_table_pointers, &table_values)?;
            upload_descriptor(arena, execution_table_strides, &table_strides)?;
        }
        upload_descriptor(arena, output_pointers, &output_values)?;
        upload_descriptor(arena, multiplicity_pointers, &multiplicity_values)?;
        arena.context().sync()?;

        Ok(Self {
            arena,
            _tables: tables,
            identity,
            installed_aot,
            source,
            kernel_name,
            row_count: u32::try_from(row_count).expect("requirements validated row count"),
            instruction_count: u32::try_from(program.n_instrs())
                .map_err(|_| PreparedWitnessError::SizeOverflow)?,
            input_columns,
            output_columns,
            multiplicity_columns,
            input_pointers,
            execution_table_pointers,
            execution_table_strides,
            output_pointers,
            multiplicity_pointers,
            multiplicity_dummy,
            lookup_words,
            sub_words,
            launch_contract,
            blake_g_direct_contract: None,
        })
    }

    /// Enqueue the already-resolved kernel on the proof arena's explicit stream.
    /// No allocation, transfer, synchronization, or runtime compilation occurs here.
    pub fn launch(&self) -> Result<PreparedWitnessLaunchTelemetry, PreparedWitnessError> {
        self.launch_on(self.arena.context().launch_context())
    }

    /// Enqueue on one proof-owned component lane. The lane must belong to the
    /// arena's execution context, so captured pointers cannot cross proof owners.
    pub fn launch_on(
        &self,
        launch: CudaLaunchContext,
    ) -> Result<PreparedWitnessLaunchTelemetry, PreparedWitnessError> {
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        if self.launch_contract != WitnessLaunchContract::Recorded {
            return Err(PreparedWitnessError::BlakeGFusionShape(
                "generic recorded launch is forbidden without a sub slab",
            ));
        }
        let ok = unsafe {
            let source_ptr = self
                .source
                .as_ref()
                .map_or(core::ptr::null(), |source| source.as_ptr());
            stwo_backend_cuda_kernels::raw::stwo_cuda_jit_witness_launch(
                source_ptr,
                self.kernel_name.as_ptr(),
                self.identity.cache_key,
                self.input_pointers.as_u32_ptr().cast(),
                self.execution_table_pointers.as_u32_ptr().cast(),
                self.execution_table_strides.as_u32_ptr(),
                self.output_pointers.as_u32_ptr().cast(),
                self.multiplicity_pointers.as_u32_ptr().cast(),
                self.lookup_words.as_u32_ptr(),
                self.sub_words.as_u32_ptr(),
                self.row_count,
                false,
                launch.stream_raw().as_ptr(),
            )
        };
        if ok {
            Ok(PreparedWitnessLaunchTelemetry::KERNEL)
        } else {
            Err(PreparedWitnessError::KernelLaunchFailed(
                self.identity.clone(),
            ))
        }
    }

    /// Replace the recorded blake_g writer plus its generic 48-word feed pass
    /// with the native one-pass producer. Every pointer is an already-bound
    /// arena address; this method performs no allocation, copy, or sync and is
    /// safe in the same eager/capture positions as [`Self::launch_on`].
    pub fn launch_blake_g_fused_on(
        &self,
        launch: CudaLaunchContext,
        n_real_rows: usize,
        luts: [ArenaSlice; 4],
        counts: [ArenaSlice; 5],
    ) -> Result<PreparedWitnessLaunchTelemetry, PreparedWitnessError> {
        self.launch_blake_g_native_on(
            launch,
            n_real_rows,
            luts,
            counts,
            WitnessLaunchContract::BlakeGFused,
        )
    }

    /// Launch the replacement producer/feed body without materializing either
    /// writer tail. The six input slices remain available to the isolated
    /// direct relation body after this launch.
    pub fn launch_blake_g_direct_on(
        &self,
        launch: CudaLaunchContext,
        n_real_rows: usize,
        luts: [ArenaSlice; 4],
        counts: [ArenaSlice; 5],
    ) -> Result<PreparedWitnessLaunchTelemetry, PreparedWitnessError> {
        self.launch_blake_g_native_on(
            launch,
            n_real_rows,
            luts,
            counts,
            WitnessLaunchContract::BlakeGDirect,
        )
    }

    fn launch_blake_g_native_on(
        &self,
        launch: CudaLaunchContext,
        n_real_rows: usize,
        luts: [ArenaSlice; 4],
        counts: [ArenaSlice; 5],
        contract: WitnessLaunchContract,
    ) -> Result<PreparedWitnessLaunchTelemetry, PreparedWitnessError> {
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        if self.launch_contract != contract
            || self.identity.label != "blake_g"
            || self.input_columns.len()
                != if contract == WitnessLaunchContract::BlakeGDirect {
                    BG_N_DATA_INPUTS
                } else {
                    BG_N_RECORDED_INPUTS
                }
            || self.output_columns.len() != BG_N_TRACE
            || (contract == WitnessLaunchContract::BlakeGFused
                && self.lookup_words.len_words() < BG_N_LOOKUP_WORDS * self.row_count as usize)
            || n_real_rows > self.row_count as usize
        {
            return Err(PreparedWitnessError::BlakeGFusionShape(
                "recorded blake_g witness geometry drifted",
            ));
        }
        let direct_authority = if contract == WitnessLaunchContract::BlakeGDirect {
            let authority = self.blake_g_direct_contract.as_ref().ok_or(
                PreparedWitnessError::BlakeGFusionShape("direct blake_g authority is missing"),
            )?;
            let input_words: [usize; BG_N_DATA_INPUTS] =
                std::array::from_fn(|index| self.input_columns[index].len_words());
            let trace_words: [usize; BG_N_TRACE] =
                std::array::from_fn(|index| self.output_columns[index].len_words());
            authority.validate_bound_geometry(
                n_real_rows,
                self.row_count as usize,
                &input_words,
                &trace_words,
            )?;
            Some(*authority)
        } else {
            None
        };
        let lut_words = direct_authority
            .map(BlakeGDirectCompositeContract::lut_words)
            .unwrap_or(BLAKE_G_DIRECT_LUT_WORDS);
        let count_words = direct_authority
            .map(BlakeGDirectCompositeContract::count_words)
            .unwrap_or(BLAKE_G_DIRECT_COUNT_WORDS);
        if luts.iter().zip(lut_words).any(|(slice, words)| {
            !slice.belongs_to(self.arena.context()) || slice.len_words() != words
        }) || counts.iter().zip(count_words).any(|(slice, words)| {
            !slice.belongs_to(self.arena.context()) || slice.len_words() != words
        }) {
            return Err(PreparedWitnessError::BlakeGFusionShape(
                "canonical xor LUT/count geometry drifted",
            ));
        }
        // Every operand is live for the entire launch. Reject a bad arena
        // coloring by bound address range, not merely logical slot identity:
        // epoch-disjoint IDs may still have been assigned overlapping bytes.
        let live_slices = self
            .input_columns
            .iter()
            .copied()
            .chain(self.output_columns.iter().copied())
            .chain((contract == WitnessLaunchContract::BlakeGFused).then_some(self.lookup_words))
            .chain(luts)
            .chain(counts);
        ensure_physically_disjoint(live_slices)?;

        let inputs: [*const u32; BG_N_DATA_INPUTS] =
            std::array::from_fn(|column| self.input_columns[column].as_u32_ptr().cast_const());
        let outputs: [*mut u32; BG_N_TRACE] =
            std::array::from_fn(|column| self.output_columns[column].as_u32_ptr());
        let lut_ptrs = luts.map(|slice| slice.as_u32_ptr().cast_const());
        let count_ptrs = counts.map(ArenaSlice::as_u32_ptr);
        let n_real_rows =
            u32::try_from(n_real_rows).map_err(|_| PreparedWitnessError::SizeOverflow)?;
        let code = unsafe {
            match contract {
                WitnessLaunchContract::BlakeGFused => {
                    stwo_backend_cuda_kernels::raw::blake_g_write_trace_fused_into_on(
                        inputs.as_ptr(),
                        n_real_rows,
                        self.row_count,
                        outputs.as_ptr(),
                        self.lookup_words.as_u32_ptr(),
                        lut_ptrs.as_ptr(),
                        count_ptrs.as_ptr(),
                        launch.stream_raw().as_ptr(),
                    )
                }
                WitnessLaunchContract::BlakeGDirect => {
                    stwo_backend_cuda_kernels::raw::blake_g_write_trace_fused_direct_into_on(
                        inputs.as_ptr(),
                        n_real_rows,
                        self.row_count,
                        outputs.as_ptr(),
                        lut_ptrs.as_ptr(),
                        count_ptrs.as_ptr(),
                        launch.stream_raw().as_ptr(),
                    )
                }
                WitnessLaunchContract::Recorded => unreachable!("native contract selected above"),
            }
        };
        if code == 0 {
            Ok(PreparedWitnessLaunchTelemetry::KERNEL)
        } else {
            Err(PreparedWitnessError::KernelLaunchFailed(
                self.identity.clone(),
            ))
        }
    }

    /// Capture-safe zeroing for multiplicity destinations. Call once before all
    /// producers that accumulate into a shared destination, not once per producer.
    pub fn clear_multiplicities(
        &self,
    ) -> Result<PreparedWitnessLaunchTelemetry, PreparedWitnessError> {
        let bytes = self
            .multiplicity_columns
            .iter()
            .try_fold(0usize, |total, destination| {
                total.checked_add(destination.len_bytes())
            })
            .ok_or(PreparedWitnessError::SizeOverflow)?;
        for destination in &self.multiplicity_columns {
            unsafe {
                self.arena.context().memset_async(
                    destination.as_void_ptr(),
                    0,
                    destination.len_bytes(),
                )?;
            }
        }
        Ok(PreparedWitnessLaunchTelemetry::clear(
            u64::try_from(bytes).map_err(|_| PreparedWitnessError::SizeOverflow)?,
        ))
    }

    pub fn kernel_identity(&self) -> &WitnessKernelIdentity {
        &self.identity
    }

    /// Immutable authority and live-function receipt retained by a strict-AOT
    /// graph. Pre-resolved graphs deliberately return `None`.
    pub fn installed_aot_receipt(&self) -> Option<&aot::InstalledAotFunctionReceipt> {
        self.installed_aot
            .as_ref()
            .map(aot::InstalledAotFunction::receipt)
    }

    pub fn row_count(&self) -> usize {
        self.row_count as usize
    }

    /// Prepared writers are arena-instance capabilities, not merely bindings
    /// to slot ids in a compatible CUDA context.
    pub fn belongs_to(&self, arena: &DeviceArena) -> bool {
        core::ptr::eq(self.arena, arena)
    }

    /// Stable setup-only weight used for deterministic component-lane packing.
    pub fn estimated_work(&self) -> u64 {
        u64::from(self.row_count) * u64::from(self.instruction_count.max(1))
    }

    pub fn input_columns(&self) -> &[ArenaSlice] {
        &self.input_columns
    }

    pub fn output_columns(&self) -> &[ArenaSlice] {
        &self.output_columns
    }

    pub fn multiplicity_columns(&self) -> &[ArenaSlice] {
        &self.multiplicity_columns
    }

    pub fn lookup_words(&self) -> ArenaSlice {
        self.lookup_words
    }

    pub fn sub_words(&self) -> ArenaSlice {
        self.sub_words
    }

    pub fn is_blake_g_fused(&self) -> bool {
        matches!(
            self.launch_contract,
            WitnessLaunchContract::BlakeGFused | WitnessLaunchContract::BlakeGDirect
        )
    }

    pub fn is_blake_g_direct(&self) -> bool {
        self.launch_contract == WitnessLaunchContract::BlakeGDirect
    }

    pub const fn blake_g_direct_contract(&self) -> Option<&BlakeGDirectCompositeContract> {
        self.blake_g_direct_contract.as_ref()
    }

    /// Immutable descriptor slices, useful to seal the exact Graph-A ABI during
    /// session construction.
    pub fn descriptor_slices(&self) -> [ArenaSlice; 5] {
        [
            self.input_pointers,
            self.execution_table_pointers,
            self.execution_table_strides,
            self.output_pointers,
            self.multiplicity_pointers,
        ]
    }

    pub fn multiplicity_dummy(&self) -> Option<ArenaSlice> {
        self.multiplicity_dummy
    }
}

fn pointer_values(slices: &[ArenaSlice]) -> Vec<usize> {
    slices
        .iter()
        .map(|slice| slice.as_u32_ptr() as usize)
        .collect()
}

fn upload_descriptor<T: Copy>(
    arena: &DeviceArena,
    destination: ArenaSlice,
    values: &[T],
) -> Result<(), PreparedWitnessError> {
    let bytes = core::mem::size_of_val(values);
    if bytes > destination.len_bytes() {
        return Err(PreparedWitnessError::SlotTooSmall {
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

fn bind_many(
    arena: &DeviceArena,
    ids: &[ArenaSlotId],
    lengths: &[usize],
    alignment_words: usize,
) -> Result<Vec<ArenaSlice>, PreparedWitnessError> {
    ids.iter()
        .zip(lengths)
        .map(|(&id, &len)| bind_slot(arena, id, len, alignment_words))
        .collect()
}

fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedWitnessError> {
    truncate_bound_slot(arena.bind(id)?, required_words, alignment_words)
}

/// Validate one bound slot's capacity and alignment, then truncate it to the
/// logical requirement. Pooled slots may be larger than any single logical
/// buffer; `clear_multiplicities` memsets `len_bytes()` per column and must
/// never clear a cohabitant's words in the pooled surplus.
fn truncate_bound_slot(
    slice: ArenaSlice,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedWitnessError> {
    if slice.len_words() < required_words {
        return Err(PreparedWitnessError::SlotTooSmall {
            slot: slice.id(),
            required_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedWitnessError::SlotMisaligned(slice.id()));
    }
    Ok(slice.truncated(required_words))
}

fn validate_slot_shape(
    requirements: &WitnessWorkspaceRequirements,
    slots: &WitnessWorkspaceSlots,
    input_columns: usize,
) -> Result<(), PreparedWitnessError> {
    check_count("input_columns", input_columns, slots.input_columns.len())?;
    check_count(
        "output_columns",
        requirements.output_column_words.len(),
        slots.output_columns.len(),
    )?;
    check_count(
        "multiplicity_columns",
        requirements.multiplicity_column_words.len(),
        slots.multiplicity_columns.len(),
    )?;
    check_count(
        "multiplicity_dummy",
        usize::from(requirements.multiplicity_dummy_words.is_some()),
        usize::from(slots.multiplicity_dummy.is_some()),
    )
}

fn validate_program_outputs(program: &WitnessProgram) -> Result<(), PreparedWitnessError> {
    for (instruction, inst) in program.insts.iter().enumerate() {
        let Some(op) = WitnessOp::from_raw(inst.op) else {
            return Err(PreparedWitnessError::InvalidOpcode {
                instruction,
                opcode: inst.op,
            });
        };
        let (role, index, count) = match op {
            WitnessOp::Input => ("input", inst.a, program.n_inputs),
            WitnessOp::ColWrite => ("output", inst.imm, program.n_cols),
            WitnessOp::MultPush => ("multiplicity", inst.imm, program.n_mult_tables),
            WitnessOp::LookupWord => ("lookup", inst.imm, program.n_lookup_words),
            WitnessOp::SubWord => ("sub", inst.imm, program.n_sub_words),
            WitnessOp::TableLimb => ("execution_table", inst.b, 2),
            _ => continue,
        };
        if index >= count {
            return Err(PreparedWitnessError::ProgramIndexOutOfRange {
                instruction,
                role,
                index,
                count,
            });
        }
    }
    Ok(())
}

fn check_count(
    role: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), PreparedWitnessError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PreparedWitnessError::SlotShapeMismatch {
            role,
            expected,
            actual,
        })
    }
}

fn ensure_distinct(ids: &[ArenaSlotId]) -> Result<(), PreparedWitnessError> {
    let mut seen = BTreeSet::new();
    for &id in ids {
        if !seen.insert(id) {
            return Err(PreparedWitnessError::DuplicateSlot(id));
        }
    }
    Ok(())
}

/// Reject overlap by bound device address, independently of logical slot IDs.
///
/// The check is setup-only. Sorting makes the admission O(n log n), while the
/// captured launch retains no range metadata or runtime branch.
fn ensure_physically_disjoint(
    slices: impl IntoIterator<Item = ArenaSlice>,
) -> Result<(), PreparedWitnessError> {
    let mut ranges = slices
        .into_iter()
        .map(|slice| {
            let start = slice.as_u32_ptr() as usize;
            let end = start
                .checked_add(slice.len_bytes())
                .ok_or(PreparedWitnessError::SizeOverflow)?;
            Ok((start, end, slice.id()))
        })
        .collect::<Result<Vec<_>, PreparedWitnessError>>()?;
    ranges.sort_unstable_by_key(|&(start, end, id)| (start, end, id));
    for pair in ranges.windows(2) {
        let (_, first_end, first) = pair[0];
        let (second_start, _, second) = pair[1];
        if second_start < first_end {
            return Err(PreparedWitnessError::PhysicalAlias { first, second });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::exec_context::{ArenaLayout, ArenaRangeSpec, ArenaSlotSpec};
    use super::super::jit_witness::recording::WitnessRecorder;
    use super::*;

    fn test_manifest() -> AotManifestBinding {
        AotManifestBinding {
            identity: [0x12; 32],
            telemetry_tag: 0x1234,
        }
    }

    #[test]
    fn bound_slots_truncate_pooled_surplus_to_the_logical_requirement() {
        // Pooled physical slots are sized to the LARGEST epoch-disjoint
        // sharer; multiplicity clears memset `len_bytes()` per column, so the
        // binder must expose only the logical extent.
        let oversized = ArenaSlice::dangling_for_test(8, 256);
        let bound = truncate_bound_slot(oversized, 64, 1).unwrap();
        assert_eq!(bound.len_words(), 64);
        assert_eq!(bound.id(), oversized.id());
        assert_eq!(bound.as_u32_ptr(), oversized.as_u32_ptr());
        // Undersized slots still fail closed.
        assert!(matches!(
            truncate_bound_slot(ArenaSlice::dangling_for_test(8, 32), 64, 1),
            Err(PreparedWitnessError::SlotTooSmall { .. })
        ));
    }

    #[test]
    fn reused_layout_cannot_hide_a_bound_physical_alias() {
        const FIRST: ArenaSlotId = ArenaSlotId(41);
        const SECOND: ArenaSlotId = ArenaSlotId(42);
        let reused = [
            ArenaRangeSpec {
                slot: ArenaSlotSpec {
                    id: FIRST,
                    offset_words: 0,
                    len_words: 32,
                    alignment_words: 1,
                },
                live_mask: 0b01,
            },
            ArenaRangeSpec {
                slot: ArenaSlotSpec {
                    id: SECOND,
                    offset_words: 16,
                    len_words: 32,
                    alignment_words: 1,
                },
                live_mask: 0b10,
            },
        ];
        // The generic reuse contract admits these distinct declared epochs.
        let layout = unsafe { ArenaLayout::new_reused(64, &reused) }.unwrap();
        let slices = [FIRST, SECOND].map(|id| {
            let spec = layout.slot(id).unwrap();
            ArenaSlice::dangling_at_for_test(id.0, spec.offset_words, spec.len_words)
        });
        // A prepared witness launch observes both ranges simultaneously and
        // therefore rejects the stale epoch coloring by physical address.
        assert_eq!(
            ensure_physically_disjoint(slices).unwrap_err(),
            PreparedWitnessError::PhysicalAlias {
                first: FIRST,
                second: SECOND,
            }
        );
    }

    #[test]
    fn execution_table_data_cannot_alias_a_witness_destination() {
        const OUTPUT: ArenaSlotId = ArenaSlotId(51);
        const TABLE_DATA: ArenaSlotId = ArenaSlotId(52);
        let output = ArenaSlice::dangling_at_for_test(OUTPUT.0, 0, 64);
        let table_data = ArenaSlice::dangling_at_for_test(TABLE_DATA.0, 32, 64);
        assert_eq!(
            ensure_physically_disjoint([output, table_data]).unwrap_err(),
            PreparedWitnessError::PhysicalAlias {
                first: OUTPUT,
                second: TABLE_DATA,
            }
        );
    }

    fn program() -> WitnessProgram {
        let mut recorder = WitnessRecorder::new("prepared_witness_pure");
        let a = recorder.input(0);
        let b = recorder.input(1);
        let sum = recorder.m31_add(a, b);
        recorder.col_write(0, sum);
        recorder.mult_push(0, a);
        recorder.lookup_word(0, sum);
        recorder.sub_word(0, b);
        recorder.finish()
    }

    fn slots(requirements: &WitnessWorkspaceRequirements) -> WitnessWorkspaceSlots {
        let mut next = 1u32;
        let mut id = || {
            let result = ArenaSlotId(next);
            next += 1;
            result
        };
        WitnessWorkspaceSlots {
            input_columns: requirements
                .input_column_words
                .iter()
                .map(|_| id())
                .collect(),
            input_pointers: id(),
            execution_table_pointers: id(),
            execution_table_strides: id(),
            output_columns: requirements
                .output_column_words
                .iter()
                .map(|_| id())
                .collect(),
            output_pointers: id(),
            multiplicity_columns: requirements
                .multiplicity_column_words
                .iter()
                .map(|_| id())
                .collect(),
            multiplicity_pointers: id(),
            multiplicity_dummy: requirements.multiplicity_dummy_words.map(|_| id()),
            lookup_words: id(),
            sub_words: id(),
        }
    }

    #[test]
    fn strict_kernel_material_skips_source_codegen() {
        let program = program();
        let strict = witness_kernel_material_with(
            &program,
            PreparedWitnessMode::RequireEmbeddedAot,
            test_manifest(),
            |_| panic!("strict preparation invoked witness source codegen"),
        )
        .unwrap();
        assert!(strict.source.is_none());
        assert_eq!(strict.identity.semantic_hash, program.semantic_hash());
        assert_eq!(
            strict.identity.kernel_name,
            jit_witness::codegen::witness_kernel_name(program.semantic_hash())
        );
        assert_eq!(
            strict.identity.cache_key,
            jit_witness::codegen::witness_jit_cache_key(program.semantic_hash())
        );

        // The non-strict lane still takes the exact existing source-emission path.
        let emitted = core::cell::Cell::new(false);
        let pre_resolved = witness_kernel_material_with(
            &program,
            PreparedWitnessMode::PreResolved,
            test_manifest(),
            |program| {
                emitted.set(true);
                aot::witness_kernel_source(program)
            },
        )
        .unwrap();
        assert!(emitted.get());
        assert!(pre_resolved.source.is_some());
        assert_eq!(pre_resolved.identity.cache_key, strict.identity.cache_key);
    }

    #[test]
    fn strict_kernel_admission_rejects_missing_embedded_entry() {
        let identity = witness_kernel_material_with(
            &program(),
            PreparedWitnessMode::RequireEmbeddedAot,
            test_manifest(),
            |_| panic!("strict preparation invoked witness source codegen"),
        )
        .unwrap()
        .identity;
        assert_eq!(
            classify_kernel_preparation(&identity, false).unwrap_err(),
            PreparedWitnessError::StrictAotUnavailable(identity)
        );
    }

    #[test]
    fn strict_precompile_selection_does_not_read_runtime_policy() {
        let runtime_reads = core::cell::Cell::new(0);
        let strict_relax_opt = witness_precompile_relax_opt_with(
            PreparedWitnessMode::RequireEmbeddedAot,
            usize::MAX,
            || {
                runtime_reads.set(runtime_reads.get() + 1);
                0
            },
        );
        assert!(!strict_relax_opt);
        assert_eq!(runtime_reads.get(), 0);

        let pre_resolved_relax_opt =
            witness_precompile_relax_opt_with(PreparedWitnessMode::PreResolved, 3, || {
                runtime_reads.set(runtime_reads.get() + 1);
                2
            });
        assert!(pre_resolved_relax_opt);
        assert_eq!(runtime_reads.get(), 1);
    }

    #[test]
    fn pure_requirements_are_exact() {
        let requirements = witness_workspace_requirements(&program(), 32, &[8]).unwrap();
        assert_eq!(requirements.input_column_words, [32, 32]);
        assert_eq!(requirements.output_column_words, [32]);
        assert_eq!(requirements.multiplicity_column_words, [8]);
        assert_eq!(requirements.lookup_words, 32);
        assert_eq!(requirements.sub_words, 32);
        assert_eq!(
            requirements.execution_table_pointer_words,
            37 * POINTER_WORDS
        );
        assert_eq!(requirements.execution_table_stride_words, 3);
        assert_eq!(requirements.multiplicity_dummy_words, None);
        let full_slots = slots(&requirements);
        let full = requirements.arena_slot_requirements(&full_slots).unwrap();
        let mut shared_slots = full_slots;
        shared_slots.execution_table_pointers = shared_slots.input_columns[0];
        shared_slots.execution_table_strides = shared_slots.input_columns[0];
        let shared = requirements
            .arena_slot_requirements_with_prepared_execution_tables(&shared_slots)
            .unwrap();
        assert_eq!(shared.len() + 2, full.len());

        let mut no_mult_recorder = WitnessRecorder::new("no_mult");
        let input = no_mult_recorder.input(0);
        no_mult_recorder.col_write(0, input);
        let no_mult_program = no_mult_recorder.finish();
        let no_mult = witness_workspace_requirements(&no_mult_program, 32, &[]).unwrap();
        assert_eq!(no_mult.multiplicity_pointer_words, POINTER_WORDS);
        assert_eq!(no_mult.multiplicity_dummy_words, Some(1));
    }

    #[test]
    fn fused_blake_contract_physically_omits_the_sub_slab() {
        let mut recorder = WitnessRecorder::new("blake_g");
        let input = recorder.input(0);
        recorder.col_write(0, input);
        recorder.lookup_word(0, input);
        recorder.sub_word(0, input);
        let requirements =
            witness_workspace_requirements(&recorder.finish(), 1 << 20, &[]).unwrap();
        let mut slots = slots(&requirements);
        slots.sub_words = slots.multiplicity_dummy.unwrap();
        let fused = requirements
            .arena_slot_requirements_for_blake_g_fusion_with_prepared_execution_tables(&slots)
            .unwrap();
        assert!(fused
            .iter()
            .any(|entry| entry.id == slots.sub_words && entry.len_words == 1));
        assert!(!fused
            .iter()
            .any(|entry| entry.id == slots.sub_words && entry.len_words == requirements.sub_words));

        let mut invalid = slots;
        invalid.sub_words = invalid.lookup_words;
        assert!(matches!(
            requirements.arena_slot_requirements_for_blake_g_fusion_with_prepared_execution_tables(
                &invalid
            ),
            Err(PreparedWitnessError::BlakeGFusionShape(_))
        ));
    }

    #[test]
    fn direct_blake_contract_retains_six_inputs_and_omits_both_writer_tails() {
        let rows = 1 << 20;
        let requirements = WitnessWorkspaceRequirements {
            row_count: rows,
            input_column_words: vec![rows; BG_N_RECORDED_INPUTS],
            input_pointer_words: pointer_words(BG_N_RECORDED_INPUTS).unwrap(),
            execution_table_pointer_words: pointer_words(EXECUTION_TABLE_POINTERS).unwrap(),
            execution_table_stride_words: EXECUTION_TABLE_STRIDES,
            output_column_words: vec![rows; BG_N_TRACE],
            output_pointer_words: pointer_words(BG_N_TRACE).unwrap(),
            multiplicity_column_words: vec![],
            multiplicity_pointer_words: POINTER_WORDS,
            multiplicity_dummy_words: Some(1),
            lookup_words: rows * BG_N_LOOKUP_WORDS,
            sub_words: rows * BG_N_SUB_WORDS,
        };
        let mut slots = slots(&requirements);
        let retired_enabler = slots.input_columns.pop().unwrap();
        let dummy = slots.multiplicity_dummy.unwrap();
        slots.lookup_words = dummy;
        slots.sub_words = dummy;

        let direct = requirements
            .arena_slot_requirements_for_blake_g_direct_with_prepared_execution_tables(&slots)
            .unwrap();
        assert_eq!(
            direct
                .iter()
                .find(|entry| entry.id == slots.input_pointers)
                .unwrap()
                .len_words,
            pointer_words(BG_N_DATA_INPUTS).unwrap()
        );
        assert_eq!(
            direct
                .iter()
                .filter(|entry| slots.input_columns.contains(&entry.id))
                .count(),
            BG_N_DATA_INPUTS
        );
        assert!(!direct.iter().any(|entry| entry.id == retired_enabler));
        assert_eq!(
            direct.iter().filter(|entry| entry.id == dummy).count(),
            1,
            "lookup/sub aliases must produce one addressable sentinel"
        );
        assert!(!direct.iter().any(|entry| {
            entry.len_words == requirements.lookup_words
                || entry.len_words == requirements.sub_words
        }));

        let mut materialized_lookup = slots.clone();
        materialized_lookup.lookup_words = retired_enabler;
        assert!(matches!(
            requirements.arena_slot_requirements_for_blake_g_direct_with_prepared_execution_tables(
                &materialized_lookup
            ),
            Err(PreparedWitnessError::BlakeGFusionShape(_))
        ));
        let mut seventh_input = slots;
        seventh_input.input_columns.push(retired_enabler);
        assert_eq!(
            requirements
                .arena_slot_requirements_for_blake_g_direct_with_prepared_execution_tables(
                    &seventh_input
                )
                .unwrap_err(),
            PreparedWitnessError::SlotShapeMismatch {
                role: "input_columns",
                expected: BG_N_DATA_INPUTS,
                actual: BG_N_RECORDED_INPUTS,
            }
        );
    }

    #[test]
    fn pure_requirements_reject_invalid_extents() {
        assert_eq!(
            witness_workspace_requirements(&program(), 0, &[8]).unwrap_err(),
            PreparedWitnessError::ZeroRows
        );
        assert!(matches!(
            witness_workspace_requirements(&program(), 32, &[]),
            Err(PreparedWitnessError::MultiplicityCountMismatch { .. })
        ));
        assert_eq!(
            witness_workspace_requirements(&program(), 32, &[0]).unwrap_err(),
            PreparedWitnessError::EmptyMultiplicity(0)
        );
        let mut invalid = program();
        invalid.n_mult_tables = 0;
        assert!(matches!(
            witness_workspace_requirements(&invalid, 32, &[]),
            Err(PreparedWitnessError::ProgramIndexOutOfRange {
                role: "multiplicity",
                ..
            })
        ));
    }

    #[test]
    fn slot_aliases_and_shape_drift_fail_closed() {
        let requirements = witness_workspace_requirements(&program(), 32, &[8]).unwrap();
        let mut bound = slots(&requirements);
        bound.output_columns[0] = bound.input_columns[0];
        assert_eq!(
            requirements.arena_slot_requirements(&bound).unwrap_err(),
            PreparedWitnessError::DuplicateSlot(bound.input_columns[0])
        );

        let mut bound = slots(&requirements);
        bound.input_columns.pop();
        assert!(matches!(
            requirements.arena_slot_requirements(&bound),
            Err(PreparedWitnessError::SlotShapeMismatch {
                role: "input_columns",
                ..
            })
        ));
    }
}
