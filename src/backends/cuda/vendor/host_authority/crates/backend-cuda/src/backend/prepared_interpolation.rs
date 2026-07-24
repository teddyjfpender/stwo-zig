//! Allocation-free, explicit-stream interpolation from resident evaluations.
//!
//! Relation kernels may retain their canonical evaluation columns for AIR
//! consumers while PCS stages consume a distinct coefficient representation.
//! Columns with no later evaluation consumer may instead alias that storage
//! exactly in either launch mode. Setup binds and uploads immutable input/output
//! pointer tables once. Replay uses one sealed launch mode: the proven
//! copy-then-in-place path, or the opt-in stage-fused path. Both run on the
//! proof-owned stream. Prepared interpolation supports domain logs 3 through
//! 30; smaller domains require the legacy backend's CPU fallback.

use core::ffi::c_void;
use std::collections::BTreeSet;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};

mod authority;
pub use authority::{
    InterpolationAbiAccess, InterpolationAbiArgument, InterpolationAbiArgumentKind,
    InterpolationAuthorityError, InterpolationBatchAuthority, InterpolationEffectAbi,
    InterpolationPrimitiveAbi, InterpolationPrimitiveAuthority,
};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);

pub const INTERPOLATION_POINTER_ALIGNMENT_WORDS: usize =
    core::mem::align_of::<*mut u32>() / WORD_BYTES;
pub const INTERPOLATION_MAX_BATCH_COLUMNS: usize = 65_535;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum InterpolationLaunchMode {
    StageWiseCopyThenInPlace = 0,
    StageFusedOutOfPlace = 1,
}

impl InterpolationLaunchMode {
    pub fn from_env() -> Self {
        static MODE: std::sync::OnceLock<InterpolationLaunchMode> = std::sync::OnceLock::new();
        *MODE.get_or_init(|| {
            if std::env::var("STWO_CUDA_B2N_STAGE_FUSED").as_deref() == Ok("1") {
                Self::StageFusedOutOfPlace
            } else {
                Self::StageWiseCopyThenInPlace
            }
        })
    }
}

/// Audited stage intervals mirrored by `LAUNCH_B2N_CONFIG_*` in `ifft.cuh`.
/// Logs outside the fused range deliberately use one interval per stage.
pub fn b2n_stage_intervals(log_n: u32) -> Option<Vec<u32>> {
    if !is_supported_interpolation_log_size(log_n) {
        return None;
    }
    let intervals = match log_n {
        13 => vec![7, 6],
        14 => vec![8, 6],
        15 => vec![7, 8],
        16 => vec![8, 8],
        17 => vec![9, 8],
        18 => vec![10, 8],
        19 => vec![7, 6, 6],
        20 => vec![8, 6, 6],
        21 => vec![7, 6, 8],
        22 => vec![8, 6, 8],
        23 => vec![7, 8, 8],
        24 => vec![8, 8, 8],
        25 => vec![7, 6, 6, 6],
        26 => vec![8, 6, 6, 6],
        27 => vec![7, 8, 6, 6],
        28 => vec![8, 8, 6, 6],
        29 => vec![7, 8, 8, 6],
        3..=12 | 30 => vec![1; log_n as usize],
        _ => unreachable!("supported interpolation log has a stage partition"),
    };
    Some(intervals)
}

pub(super) const fn is_supported_interpolation_log_size(log_size: u32) -> bool {
    matches!(log_size, 3..=30)
}

fn validate_interpolation_log_size(
    batch: usize,
    log_size: u32,
) -> Result<(), PreparedInterpolationError> {
    if is_supported_interpolation_log_size(log_size) {
        Ok(())
    } else {
        Err(PreparedInterpolationError::InvalidLogSize { batch, log_size })
    }
}

pub fn b2n_chunk_ranges(column_count: usize) -> Vec<core::ops::Range<usize>> {
    (0..column_count)
        .step_by(INTERPOLATION_MAX_BATCH_COLUMNS)
        .map(|start| start..(start + INTERPOLATION_MAX_BATCH_COLUMNS).min(column_count))
        .collect()
}

/// One evaluation/coefficient pair. The slices may alias exactly in either
/// launch mode when the evaluation is dead after interpolation. Partial and
/// cross-column aliases are rejected.
#[derive(Clone, Copy, Debug)]
pub struct InterpolationColumn {
    pub evaluations: ArenaSlice,
    pub coefficients: ArenaSlice,
    pub log_size: u32,
}

/// One same-log inverse-NTT batch and its stable device pointer table.
#[derive(Clone, Debug)]
pub struct InterpolationBatch {
    pub columns: Vec<InterpolationColumn>,
    pub input_pointers: ArenaSlotId,
    pub output_pointers: ArenaSlotId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedInterpolationError {
    EmptyBatches,
    EmptyBatch(usize),
    InvalidLogSize {
        batch: usize,
        log_size: u32,
    },
    MixedLogSizes {
        batch: usize,
        column: usize,
        expected: u32,
        actual: u32,
    },
    ContextMismatch(ArenaSlotId),
    EvaluationAliasesCoefficient(ArenaSlotId),
    DuplicateEvaluation(ArenaSlotId),
    DuplicateCoefficient(ArenaSlotId),
    DuplicatePointerTable(ArenaSlotId),
    PointerTablesAlias(ArenaSlotId),
    PointerTableAliasesValue(ArenaSlotId),
    PointerTableAliasesTwiddles(ArenaSlotId),
    TwiddlesAliasValue(ArenaSlotId),
    ColumnTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    PointerTableTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    MisalignedPointerTable(ArenaSlotId),
    TwiddlesTooSmall {
        required_words: usize,
        actual_words: usize,
    },
    SizeOverflow,
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedInterpolationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid prepared CUDA interpolation: {self:?}")
    }
}

impl std::error::Error for PreparedInterpolationError {}

impl From<ArenaError> for PreparedInterpolationError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedInterpolationError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

#[derive(Clone, Debug)]
struct PreparedBatch {
    columns: Vec<InterpolationColumn>,
    input_pointers: ArenaSlice,
    output_pointers: ArenaSlice,
    log_size: u32,
}

/// Prepared resident interpolation.  Setup may synchronize after uploading
/// immutable pointer descriptors; launch never allocates, synchronizes, or uses
/// the legacy/default CUDA stream.
pub struct PreparedInterpolationGraph<'a> {
    arena: &'a DeviceArena,
    inverse_twiddles: ArenaSlice,
    batches: Vec<PreparedBatch>,
    mode: InterpolationLaunchMode,
}

impl<'a> PreparedInterpolationGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        batches: &[InterpolationBatch],
        inverse_twiddles: ArenaSlice,
        mode: InterpolationLaunchMode,
    ) -> Result<Self, PreparedInterpolationError> {
        let pointer_tables = validate_batches(arena, batches, inverse_twiddles, mode)?;

        let mut prepared = Vec::with_capacity(batches.len());
        let mut pointer_uploads = Vec::with_capacity(batches.len());
        for (batch, (input_pointers, output_pointers)) in batches.iter().zip(pointer_tables) {
            let inputs: Vec<usize> = batch
                .columns
                .iter()
                .map(|column| column.evaluations.as_u32_ptr() as usize)
                .collect();
            let outputs: Vec<usize> = batch
                .columns
                .iter()
                .map(|column| column.coefficients.as_u32_ptr() as usize)
                .collect();
            let bytes = inputs
                .len()
                .checked_mul(core::mem::size_of::<usize>())
                .ok_or(PreparedInterpolationError::SizeOverflow)?;
            pointer_uploads.push((input_pointers, inputs, bytes));
            pointer_uploads.push((output_pointers, outputs, bytes));
            prepared.push(PreparedBatch {
                columns: batch.columns.clone(),
                input_pointers,
                output_pointers,
                log_size: batch.columns[0].log_size,
            });
        }
        for (destination, pointers, bytes) in &pointer_uploads {
            // SAFETY: pointer-table capacity/alignment were validated, and all
            // host vectors remain owned by `pointer_uploads` until the setup
            // stream synchronization below completes.
            unsafe {
                arena.context().memcpy_h2d_async(
                    destination.as_void_ptr(),
                    pointers.as_ptr().cast::<c_void>(),
                    *bytes,
                )?;
            }
        }
        arena.context().sync()?;

        Ok(Self {
            arena,
            inverse_twiddles,
            batches: prepared,
            mode,
        })
    }

    /// Copy each distinct canonical evaluation to its coefficient slot, then
    /// interpolate all coefficient slots in same-log batches on the arena
    /// stream. Exact in-place columns skip the identity copy.
    pub fn launch(&self) -> Result<(), PreparedInterpolationError> {
        let twiddle_words = u32::try_from(self.inverse_twiddles.len_words())
            .map_err(|_| PreparedInterpolationError::SizeOverflow)?;
        let stream = self.arena.context().stream_raw().as_ptr();

        for batch in &self.batches {
            match self.mode {
                InterpolationLaunchMode::StageWiseCopyThenInPlace => {
                    let bytes = pow2(batch.log_size)?
                        .checked_mul(WORD_BYTES)
                        .ok_or(PreparedInterpolationError::SizeOverflow)?;
                    for column in &batch.columns {
                        if is_exact_in_place(*column) {
                            continue;
                        }
                        unsafe {
                            self.arena.context().memcpy_d2d_async(
                                column.coefficients.as_void_ptr(),
                                column.evaluations.as_void_ptr().cast_const(),
                                bytes,
                            )?;
                        }
                    }
                }
                InterpolationLaunchMode::StageFusedOutOfPlace => {}
            }

            let column_count = u32::try_from(batch.columns.len())
                .map_err(|_| PreparedInterpolationError::SizeOverflow)?;
            let eval_domain_size = 1u32
                .checked_shl(batch.log_size - 1)
                .ok_or(PreparedInterpolationError::SizeOverflow)?;
            let code = unsafe {
                match self.mode {
                    InterpolationLaunchMode::StageWiseCopyThenInPlace => {
                        stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_columns_on(
                            batch.output_pointers.as_u32_ptr().cast::<*mut u32>(),
                            batch.log_size,
                            column_count,
                            self.inverse_twiddles.as_u32_ptr(),
                            twiddle_words,
                            eval_domain_size,
                            stream,
                        )
                    }
                    InterpolationLaunchMode::StageFusedOutOfPlace => {
                        stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_columns_out_of_place_on(
                            batch.input_pointers.as_u32_ptr().cast::<*const u32>(),
                            batch.output_pointers.as_u32_ptr().cast::<*mut u32>(),
                            batch.log_size,
                            column_count,
                            self.inverse_twiddles.as_u32_ptr(),
                            twiddle_words,
                            eval_domain_size,
                            stream,
                        )
                    }
                }
            };
            check_cuda("prepared_interpolation", code)?;
        }
        Ok(())
    }

    pub fn batch_count(&self) -> usize {
        self.batches.len()
    }

    pub fn column_count(&self) -> usize {
        self.batches.iter().map(|batch| batch.columns.len()).sum()
    }
}

fn validate_batches(
    arena: &DeviceArena,
    batches: &[InterpolationBatch],
    inverse_twiddles: ArenaSlice,
    mode: InterpolationLaunchMode,
) -> Result<Vec<(ArenaSlice, ArenaSlice)>, PreparedInterpolationError> {
    if batches.is_empty() {
        return Err(PreparedInterpolationError::EmptyBatches);
    }
    let context = arena.context().identity_token();
    if inverse_twiddles.context_token() != context {
        return Err(PreparedInterpolationError::ContextMismatch(
            inverse_twiddles.id(),
        ));
    }

    let mut evaluations = BTreeSet::new();
    let mut coefficients = BTreeSet::new();
    let mut pointer_ids = BTreeSet::new();
    let mut value_ranges = Vec::new();
    let mut pointer_ranges = Vec::new();
    let mut max_twiddle_words = 0usize;
    let mut pointer_tables = Vec::with_capacity(batches.len());

    for (batch_index, batch) in batches.iter().enumerate() {
        let Some(first) = batch.columns.first() else {
            return Err(PreparedInterpolationError::EmptyBatch(batch_index));
        };
        validate_interpolation_log_size(batch_index, first.log_size)?;
        let required_words = pow2(first.log_size)?;
        max_twiddle_words = max_twiddle_words.max(required_words / 2);

        for id in [batch.input_pointers, batch.output_pointers] {
            if !pointer_ids.insert(id) {
                return Err(PreparedInterpolationError::DuplicatePointerTable(id));
            }
        }
        let pointer_words = batch
            .columns
            .len()
            .checked_mul(POINTER_WORDS)
            .ok_or(PreparedInterpolationError::SizeOverflow)?;
        let mut bind_table = |id| -> Result<ArenaSlice, PreparedInterpolationError> {
            let table = arena.bind(id)?;
            if table.len_words() < pointer_words {
                return Err(PreparedInterpolationError::PointerTableTooSmall {
                    slot: id,
                    required_words: pointer_words,
                    actual_words: table.len_words(),
                });
            }
            if (table.as_u32_ptr() as usize) % (INTERPOLATION_POINTER_ALIGNMENT_WORDS * WORD_BYTES)
                != 0
            {
                return Err(PreparedInterpolationError::MisalignedPointerTable(id));
            }
            let table = table.truncated(pointer_words);
            pointer_ranges.push(address_range(table, pointer_words)?);
            Ok(table)
        };
        let input_table = bind_table(batch.input_pointers)?;
        let output_table = bind_table(batch.output_pointers)?;
        if ranges_overlap(
            address_range(input_table, pointer_words)?,
            address_range(output_table, pointer_words)?,
        ) {
            return Err(PreparedInterpolationError::PointerTablesAlias(
                batch.input_pointers,
            ));
        }
        pointer_tables.push((input_table, output_table));

        for (column_index, column) in batch.columns.iter().enumerate() {
            if column.log_size != first.log_size {
                return Err(PreparedInterpolationError::MixedLogSizes {
                    batch: batch_index,
                    column: column_index,
                    expected: first.log_size,
                    actual: column.log_size,
                });
            }
            for value in [column.evaluations, column.coefficients] {
                if value.context_token() != context {
                    return Err(PreparedInterpolationError::ContextMismatch(value.id()));
                }
                if value.len_words() < required_words {
                    return Err(PreparedInterpolationError::ColumnTooSmall {
                        slot: value.id(),
                        required_words,
                        actual_words: value.len_words(),
                    });
                }
            }
            let in_place =
                insert_value_identities(&mut evaluations, &mut coefficients, *column, mode)?;
            let evaluation_range = address_range(column.evaluations, required_words)?;
            value_ranges.push((column.evaluations.id(), in_place, evaluation_range));
            if !in_place {
                value_ranges.push((
                    column.coefficients.id(),
                    true,
                    address_range(column.coefficients, required_words)?,
                ));
            }
        }
    }

    if let Some(id) = pointer_ids
        .iter()
        .find(|id| evaluations.contains(id) || coefficients.contains(id))
    {
        return Err(PreparedInterpolationError::PointerTableAliasesValue(*id));
    }
    if pointer_ids.contains(&inverse_twiddles.id()) {
        return Err(PreparedInterpolationError::PointerTableAliasesTwiddles(
            inverse_twiddles.id(),
        ));
    }
    if twiddles_alias_value_identity(&evaluations, &coefficients, inverse_twiddles.id()) {
        return Err(PreparedInterpolationError::TwiddlesAliasValue(
            inverse_twiddles.id(),
        ));
    }
    if inverse_twiddles.len_words() < max_twiddle_words {
        return Err(PreparedInterpolationError::TwiddlesTooSmall {
            required_words: max_twiddle_words,
            actual_words: inverse_twiddles.len_words(),
        });
    }
    let twiddle_range = address_range(inverse_twiddles, inverse_twiddles.len_words())?;
    if let Some(id) = twiddles_overlapping_value(&value_ranges, twiddle_range) {
        return Err(PreparedInterpolationError::TwiddlesAliasValue(id));
    }
    for (index, &(id, writable, range)) in value_ranges.iter().enumerate() {
        for &(other_id, _, other) in &value_ranges[index + 1..] {
            if ranges_overlap(range, other) {
                return Err(PreparedInterpolationError::EvaluationAliasesCoefficient(
                    if writable { id } else { other_id },
                ));
            }
        }
        if pointer_ranges
            .iter()
            .any(|&table| ranges_overlap(range, table))
        {
            return Err(PreparedInterpolationError::PointerTableAliasesValue(id));
        }
    }
    if pointer_ranges
        .iter()
        .any(|&table| ranges_overlap(table, twiddle_range))
    {
        return Err(PreparedInterpolationError::PointerTableAliasesTwiddles(
            inverse_twiddles.id(),
        ));
    }
    for (index, &range) in pointer_ranges.iter().enumerate() {
        if pointer_ranges[index + 1..]
            .iter()
            .any(|&other| ranges_overlap(range, other))
        {
            return Err(PreparedInterpolationError::PointerTablesAlias(
                batches[0].input_pointers,
            ));
        }
    }
    Ok(pointer_tables)
}

fn address_range(
    slice: ArenaSlice,
    words: usize,
) -> Result<(usize, usize), PreparedInterpolationError> {
    let start = slice.as_u32_ptr() as usize;
    let bytes = words
        .checked_mul(WORD_BYTES)
        .ok_or(PreparedInterpolationError::SizeOverflow)?;
    let end = start
        .checked_add(bytes)
        .ok_or(PreparedInterpolationError::SizeOverflow)?;
    Ok((start, end))
}

const fn ranges_overlap(left: (usize, usize), right: (usize, usize)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

fn twiddles_alias_value_identity(
    evaluations: &BTreeSet<ArenaSlotId>,
    coefficients: &BTreeSet<ArenaSlotId>,
    twiddles: ArenaSlotId,
) -> bool {
    evaluations.contains(&twiddles) || coefficients.contains(&twiddles)
}

fn twiddles_overlapping_value(
    value_ranges: &[(ArenaSlotId, bool, (usize, usize))],
    twiddle_range: (usize, usize),
) -> Option<ArenaSlotId> {
    value_ranges
        .iter()
        .find_map(|&(id, _, range)| ranges_overlap(range, twiddle_range).then_some(id))
}

fn insert_value_identities(
    evaluations: &mut BTreeSet<ArenaSlotId>,
    coefficients: &mut BTreeSet<ArenaSlotId>,
    column: InterpolationColumn,
    _mode: InterpolationLaunchMode,
) -> Result<bool, PreparedInterpolationError> {
    let evaluation = column.evaluations.id();
    let coefficient = column.coefficients.id();
    let in_place = is_exact_in_place(column);
    if in_place {
        if evaluations.contains(&evaluation) || coefficients.contains(&coefficient) {
            return Err(PreparedInterpolationError::EvaluationAliasesCoefficient(
                evaluation,
            ));
        }
        evaluations.insert(evaluation);
        coefficients.insert(coefficient);
        return Ok(true);
    }
    if coefficients.contains(&evaluation) {
        return Err(PreparedInterpolationError::EvaluationAliasesCoefficient(
            evaluation,
        ));
    }
    if evaluations.contains(&coefficient) {
        return Err(PreparedInterpolationError::EvaluationAliasesCoefficient(
            coefficient,
        ));
    }
    if !evaluations.insert(evaluation) {
        return Err(PreparedInterpolationError::DuplicateEvaluation(evaluation));
    }
    if !coefficients.insert(coefficient) {
        return Err(PreparedInterpolationError::DuplicateCoefficient(
            coefficient,
        ));
    }
    Ok(false)
}

fn is_exact_in_place(column: InterpolationColumn) -> bool {
    column.evaluations.id() == column.coefficients.id()
}

fn pow2(log_size: u32) -> Result<usize, PreparedInterpolationError> {
    1usize
        .checked_shl(log_size)
        .ok_or(PreparedInterpolationError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(evaluations: u32, coefficients: u32, log_size: u32) -> InterpolationColumn {
        InterpolationColumn {
            evaluations: ArenaSlice::dangling_for_test(evaluations, 1 << log_size),
            coefficients: ArenaSlice::dangling_for_test(coefficients, 1 << log_size),
            log_size,
        }
    }

    #[test]
    fn stagewise_mode_allows_only_exact_per_column_aliases() {
        let mut evaluations = BTreeSet::new();
        let mut coefficients = BTreeSet::new();
        assert!(!insert_value_identities(
            &mut evaluations,
            &mut coefficients,
            column(1, 2, 5),
            InterpolationLaunchMode::StageWiseCopyThenInPlace,
        )
        .unwrap());
        assert!(insert_value_identities(
            &mut evaluations,
            &mut coefficients,
            column(4, 4, 5),
            InterpolationLaunchMode::StageWiseCopyThenInPlace,
        )
        .unwrap());
        assert_eq!(
            insert_value_identities(
                &mut evaluations,
                &mut coefficients,
                column(3, 1, 5),
                InterpolationLaunchMode::StageWiseCopyThenInPlace,
            ),
            Err(PreparedInterpolationError::EvaluationAliasesCoefficient(
                ArenaSlotId(1)
            ))
        );
        assert_eq!(
            insert_value_identities(
                &mut evaluations,
                &mut coefficients,
                column(5, 4, 5),
                InterpolationLaunchMode::StageWiseCopyThenInPlace,
            ),
            Err(PreparedInterpolationError::EvaluationAliasesCoefficient(
                ArenaSlotId(4)
            ))
        );
    }

    #[test]
    fn fused_mode_accepts_exact_alias_and_copy_predicate_matches_identity() {
        let aliased = column(4, 4, 5);
        let distinct = column(4, 5, 5);
        assert!(is_exact_in_place(aliased));
        assert!(!is_exact_in_place(distinct));
        assert!(insert_value_identities(
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
            aliased,
            InterpolationLaunchMode::StageFusedOutOfPlace,
        )
        .unwrap());
    }

    #[test]
    fn batches_preserve_caller_column_order() {
        let batch = InterpolationBatch {
            columns: vec![column(7, 17, 6), column(4, 14, 6), column(9, 19, 6)],
            input_pointers: ArenaSlotId(30),
            output_pointers: ArenaSlotId(31),
        };
        assert_eq!(
            batch
                .columns
                .iter()
                .map(|column| (column.evaluations.id(), column.coefficients.id()))
                .collect::<Vec<_>>(),
            [
                (ArenaSlotId(7), ArenaSlotId(17)),
                (ArenaSlotId(4), ArenaSlotId(14)),
                (ArenaSlotId(9), ArenaSlotId(19)),
            ]
        );
    }

    #[test]
    fn prepared_log_size_boundary_is_fail_closed() {
        for log_size in [3, 30] {
            assert_eq!(validate_interpolation_log_size(7, log_size), Ok(()));
            assert!(b2n_stage_intervals(log_size).is_some());
        }
        for log_size in [0, 1, 2, 31] {
            assert_eq!(
                validate_interpolation_log_size(7, log_size),
                Err(PreparedInterpolationError::InvalidLogSize { batch: 7, log_size })
            );
            assert_eq!(b2n_stage_intervals(log_size), None);
        }
    }

    #[test]
    fn fused_stage_intervals_cover_every_supported_stage_once_and_rescale_once() {
        for log_n in 3..=30 {
            let intervals = b2n_stage_intervals(log_n).unwrap();
            assert_eq!(intervals.iter().sum::<u32>(), log_n);
            let mut next = 1;
            let mut final_intervals = 0;
            for stages in intervals {
                let end = next + stages - 1;
                assert!(end <= log_n);
                final_intervals += usize::from(end == log_n);
                next = end + 1;
            }
            assert_eq!(next, log_n + 1);
            assert_eq!(final_intervals, 1);
        }
    }

    #[test]
    fn fused_logs_17_and_18_select_block_warp_init_intervals() {
        assert_eq!(b2n_stage_intervals(17), Some(vec![9, 8]));
        assert_eq!(b2n_stage_intervals(18), Some(vec![10, 8]));
    }

    #[test]
    fn address_range_overlap_is_global_not_slot_id_based() {
        assert!(ranges_overlap((100, 200), (150, 250)));
        assert!(ranges_overlap((150, 250), (100, 200)));
        assert!(!ranges_overlap((100, 200), (200, 300)));
        assert!(!ranges_overlap((200, 300), (100, 200)));
    }

    #[test]
    fn evaluation_identity_must_not_alias_inverse_twiddles() {
        let evaluations = BTreeSet::from([ArenaSlotId(7)]);
        let coefficients = BTreeSet::from([ArenaSlotId(17)]);
        assert!(twiddles_alias_value_identity(
            &evaluations,
            &coefficients,
            ArenaSlotId(7)
        ));
        assert!(twiddles_alias_value_identity(
            &evaluations,
            &coefficients,
            ArenaSlotId(17)
        ));
        assert!(!twiddles_alias_value_identity(
            &evaluations,
            &coefficients,
            ArenaSlotId(27)
        ));
    }

    #[test]
    fn evaluation_partial_range_must_not_overlap_inverse_twiddles() {
        let values = [(ArenaSlotId(7), false, (100, 200))];
        assert_eq!(
            twiddles_overlapping_value(&values, (150, 250)),
            Some(ArenaSlotId(7))
        );
        assert_eq!(twiddles_overlapping_value(&values, (200, 250)), None);
    }

    #[test]
    fn pointer_table_chunks_match_cuda_grid_boundaries() {
        assert!(b2n_chunk_ranges(0).is_empty());
        assert_eq!(b2n_chunk_ranges(65_535), [0..65_535]);
        assert_eq!(b2n_chunk_ranges(65_536), [0..65_535, 65_535..65_536]);
        assert_eq!(b2n_chunk_ranges(131_070), [0..65_535, 65_535..131_070]);
    }

    #[test]
    fn launch_modes_have_distinct_cache_discriminants() {
        assert_ne!(
            InterpolationLaunchMode::StageWiseCopyThenInPlace as u8,
            InterpolationLaunchMode::StageFusedOutOfPlace as u8
        );
    }
}
