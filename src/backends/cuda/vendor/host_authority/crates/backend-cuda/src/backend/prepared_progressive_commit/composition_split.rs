//! Direct Composition accumulator decomposition into retained evaluations.
//!
//! The production lane is deliberately narrow: four coordinate evaluations at
//! log 24 or 25 become eight canonical retained columns.  The CUDA operator
//! either uses the qualified terminal split or fuses the final inverse interval,
//! coefficient-half split, zero-extension duplication, and first forward
//! interval.  This module seals the shape, traffic contract, and independent
//! CPU oracle; unsupported schedules and launch modes fail closed.

use core::ffi::c_void;

use stwo::core::fields::m31::{BaseField, P};
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;

use super::{bind_slot, CommitArenaSlotRequirement, POINTER_WORDS};
use crate::backend::exec_context::{
    check_cuda, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};
use crate::backend::prepared_commit::PreparedCommitError;

pub const COMPOSITION_SOURCE_COORDINATES: usize = 4;
pub const COMPOSITION_RETAINED_COLUMNS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionSplitSchedule {
    pub evaluation_log_size: u32,
    pub inverse_intervals: u32,
    pub final_inverse_first_stage: u32,
    pub final_inverse_stages: u32,
    pub first_forward_first_stage: u32,
    pub first_forward_stages: u32,
    pub remaining_forward_intervals: u32,
    pub shared_min_stride_log: u32,
}

impl CompositionSplitSchedule {
    pub const fn for_production_log(log_size: u32) -> Option<Self> {
        match log_size {
            24 => Some(Self {
                evaluation_log_size: 24,
                inverse_intervals: 3,
                final_inverse_first_stage: 19,
                final_inverse_stages: 6,
                first_forward_first_stage: 2,
                first_forward_stages: 5,
                remaining_forward_intervals: 2,
                shared_min_stride_log: 18,
            }),
            25 => Some(Self {
                evaluation_log_size: 25,
                inverse_intervals: 4,
                final_inverse_first_stage: 20,
                final_inverse_stages: 6,
                first_forward_first_stage: 2,
                first_forward_stages: 5,
                remaining_forward_intervals: 2,
                shared_min_stride_log: 19,
            }),
            _ => None,
        }
    }

    pub const fn first_unfused_forward_stage(self) -> u32 {
        self.first_forward_first_stage + self.first_forward_stages
    }

    pub const fn is_exact(self) -> bool {
        let final_inverse_end = match self
            .final_inverse_first_stage
            .checked_add(self.final_inverse_stages)
        {
            Some(end) => match end.checked_sub(1) {
                Some(end) => end,
                None => return false,
            },
            None => return false,
        };
        let first_forward_end = match self
            .first_forward_first_stage
            .checked_add(self.first_forward_stages)
        {
            Some(end) => match end.checked_sub(1) {
                Some(end) => end,
                None => return false,
            },
            None => return false,
        };
        let Some(shared_min_stride_log) = self.evaluation_log_size.checked_sub(first_forward_end)
        else {
            return false;
        };
        final_inverse_end == self.evaluation_log_size
            && self.first_forward_first_stage == 2
            && self.shared_min_stride_log == shared_min_stride_log
            && self.remaining_forward_intervals == 2
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionSplitTraffic {
    pub source_image_bytes: u64,
    pub retained_image_bytes: u64,
    pub current_logical_bytes: u64,
    pub terminal_fallback_logical_bytes: u64,
    pub fused_logical_bytes: u64,
    pub current_kernel_launches: u32,
    pub terminal_fallback_kernel_launches: u32,
    pub fused_kernel_launches: u32,
    pub current_d2d_nodes: u32,
    pub fused_d2d_nodes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionSplitOracle {
    /// Canonical retained column order: left coordinates 0..4, then right 0..4.
    pub retained_evaluations: [Vec<u32>; COMPOSITION_RETAINED_COLUMNS],
}

#[derive(Clone, Copy, Debug)]
pub struct CompositionSplitColumns {
    pub source_evaluations: [ArenaSlice; COMPOSITION_SOURCE_COORDINATES],
    pub retained_evaluations: [ArenaSlice; COMPOSITION_RETAINED_COLUMNS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionSplitPointerSlots {
    pub source_pointers: ArenaSlotId,
    pub retained_pointers: ArenaSlotId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionSplitLaunchMode {
    FusedFirstForward,
    TerminalFallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionSplitProgram {
    schedule: CompositionSplitSchedule,
    traffic: CompositionSplitTraffic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositionSplitError {
    UnsupportedProductionLog(u32),
    UnsupportedLaunchMode {
        evaluation_log_size: u32,
        mode: CompositionSplitLaunchMode,
    },
    InvalidSchedule,
    SourceColumnCount {
        expected: usize,
        actual: usize,
    },
    SourceLength {
        coordinate: usize,
        expected: usize,
        actual: usize,
    },
    NonCanonicalWord {
        coordinate: usize,
        row: usize,
        word: u32,
    },
    ContextMismatch(ArenaSlotId),
    SourceTooSmall {
        coordinate: usize,
        required_words: usize,
        actual_words: usize,
    },
    RetainedOutputTooSmall {
        canonical_column: usize,
        required_words: usize,
        actual_words: usize,
    },
    TwiddlesTooSmall {
        required_words: usize,
        actual_words: usize,
    },
    InvalidAlias {
        first: ArenaSlotId,
        second: ArenaSlotId,
    },
    SizeOverflow,
    Prepared(PreparedCommitError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for CompositionSplitError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid Composition evaluation split: {self:?}")
    }
}

impl std::error::Error for CompositionSplitError {}

impl From<PreparedCommitError> for CompositionSplitError {
    fn from(value: PreparedCommitError) -> Self {
        Self::Prepared(value)
    }
}

impl From<CudaRuntimeError> for CompositionSplitError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

impl CompositionSplitProgram {
    pub fn compile(evaluation_log_size: u32) -> Result<Self, CompositionSplitError> {
        let schedule = CompositionSplitSchedule::for_production_log(evaluation_log_size).ok_or(
            CompositionSplitError::UnsupportedProductionLog(evaluation_log_size),
        )?;
        if !schedule.is_exact() {
            return Err(CompositionSplitError::InvalidSchedule);
        }
        Ok(Self {
            schedule,
            traffic: traffic(schedule)?,
        })
    }

    pub const fn schedule(self) -> CompositionSplitSchedule {
        self.schedule
    }

    pub const fn traffic(self) -> CompositionSplitTraffic {
        self.traffic
    }

    /// Both registered shapes use the spill-free 256-thread LOG3 fused boundary.
    /// Log 24 reaches it through the exact 10+8+6 inverse partition; log 25 uses
    /// the ordinary 7+6+6+6 partition.
    pub const fn admits_launch_mode(self, mode: CompositionSplitLaunchMode) -> bool {
        matches!(
            (self.schedule.evaluation_log_size, mode),
            (
                24 | 25,
                CompositionSplitLaunchMode::TerminalFallback
                    | CompositionSplitLaunchMode::FusedFirstForward
            )
        )
    }

    pub fn arena_slot_requirements(
        self,
        slots: CompositionSplitPointerSlots,
    ) -> Result<[CommitArenaSlotRequirement; 2], CompositionSplitError> {
        if slots.source_pointers == slots.retained_pointers {
            return Err(CompositionSplitError::InvalidAlias {
                first: slots.source_pointers,
                second: slots.retained_pointers,
            });
        }
        Ok([
            CommitArenaSlotRequirement {
                id: slots.source_pointers,
                len_words: COMPOSITION_SOURCE_COORDINATES
                    .checked_mul(POINTER_WORDS)
                    .ok_or(CompositionSplitError::SizeOverflow)?,
                alignment_words: POINTER_WORDS,
            },
            CommitArenaSlotRequirement {
                id: slots.retained_pointers,
                len_words: COMPOSITION_RETAINED_COLUMNS
                    .checked_mul(POINTER_WORDS)
                    .ok_or(CompositionSplitError::SizeOverflow)?,
                alignment_words: POINTER_WORDS,
            },
        ])
    }

    /// Independent reference for the exact committed bytes. This supports all
    /// CPU-manageable logs; production admission remains restricted to 24/25.
    pub fn oracle(
        evaluation_log_size: u32,
        source_evaluations: &[Vec<u32>],
    ) -> Result<CompositionSplitOracle, CompositionSplitError> {
        if source_evaluations.len() != COMPOSITION_SOURCE_COORDINATES {
            return Err(CompositionSplitError::SourceColumnCount {
                expected: COMPOSITION_SOURCE_COORDINATES,
                actual: source_evaluations.len(),
            });
        }
        let rows = words(evaluation_log_size)?;
        if !(3..=30).contains(&evaluation_log_size) {
            return Err(CompositionSplitError::UnsupportedProductionLog(
                evaluation_log_size,
            ));
        }
        for (coordinate, source) in source_evaluations.iter().enumerate() {
            if source.len() != rows {
                return Err(CompositionSplitError::SourceLength {
                    coordinate,
                    expected: rows,
                    actual: source.len(),
                });
            }
            if let Some((row, &word)) = source.iter().enumerate().find(|(_, word)| **word >= P) {
                return Err(CompositionSplitError::NonCanonicalWord {
                    coordinate,
                    row,
                    word,
                });
            }
        }

        let domain = CanonicCoset::new(evaluation_log_size).circle_domain();
        let twiddles = CpuBackend::precompute_twiddles(domain.half_coset);
        let mut outputs: [Vec<u32>; COMPOSITION_RETAINED_COLUMNS] =
            std::array::from_fn(|_| Vec::new());
        for coordinate in 0..COMPOSITION_SOURCE_COORDINATES {
            let evaluation = CircleEvaluation::<CpuBackend, BaseField, BitReversedOrder>::new(
                domain,
                source_evaluations[coordinate]
                    .iter()
                    .copied()
                    .map(BaseField::from_u32_unchecked)
                    .collect(),
            );
            let coefficients = evaluation.interpolate_with_twiddles(&twiddles);
            let (left, right) = coefficients.split_at_mid();
            outputs[coordinate] = left
                .evaluate_with_twiddles(domain, &twiddles)
                .values
                .into_iter()
                .map(|value| value.0)
                .collect();
            outputs[COMPOSITION_SOURCE_COORDINATES + coordinate] = right
                .evaluate_with_twiddles(domain, &twiddles)
                .values
                .into_iter()
                .map(|value| value.0)
                .collect();
        }
        Ok(CompositionSplitOracle {
            retained_evaluations: outputs,
        })
    }
}

pub struct PreparedCompositionSplitGraph<'a> {
    arena: &'a DeviceArena,
    program: CompositionSplitProgram,
    mode: CompositionSplitLaunchMode,
    source_pointers: ArenaSlice,
    retained_pointers: ArenaSlice,
    inverse_twiddles: ArenaSlice,
    inverse_twiddle_words: u32,
    forward_twiddles: ArenaSlice,
    forward_twiddle_words: u32,
    retained_evaluations: [ArenaSlice; COMPOSITION_RETAINED_COLUMNS],
}

impl<'a> PreparedCompositionSplitGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        program: CompositionSplitProgram,
        mode: CompositionSplitLaunchMode,
        slots: CompositionSplitPointerSlots,
        columns: CompositionSplitColumns,
        inverse_twiddles: ArenaSlice,
        forward_twiddles: ArenaSlice,
    ) -> Result<Self, CompositionSplitError> {
        if !program.admits_launch_mode(mode) {
            return Err(CompositionSplitError::UnsupportedLaunchMode {
                evaluation_log_size: program.schedule.evaluation_log_size,
                mode,
            });
        }
        let context = arena.context();
        let rows = words(program.schedule.evaluation_log_size)?;
        let twiddle_words = rows / 2;
        let sources = bind_values(context, columns.source_evaluations, rows, true)?;
        let retained_evaluations = bind_values(context, columns.retained_evaluations, rows, false)?;
        let inverse_twiddle_words = bind_twiddles(context, inverse_twiddles, twiddle_words)?;
        let forward_twiddle_words = bind_twiddles(context, forward_twiddles, twiddle_words)?;

        let requirements = program.arena_slot_requirements(slots)?;
        let source_pointers = bind_slot(
            arena,
            slots.source_pointers,
            requirements[0].len_words,
            POINTER_WORDS,
        )?;
        let retained_pointers = bind_slot(
            arena,
            slots.retained_pointers,
            requirements[1].len_words,
            POINTER_WORDS,
        )?;
        validate_disjoint(
            &sources,
            &retained_evaluations,
            [source_pointers, retained_pointers],
            [inverse_twiddles, forward_twiddles],
        )?;

        upload_pointers(arena, source_pointers, &sources)?;
        upload_pointers(arena, retained_pointers, &retained_evaluations)?;
        arena.context().sync()?;

        Ok(Self {
            arena,
            program,
            mode,
            source_pointers,
            retained_pointers,
            inverse_twiddles,
            inverse_twiddle_words,
            forward_twiddles,
            forward_twiddle_words,
            retained_evaluations,
        })
    }

    pub fn launch(&self) -> Result<(), CompositionSplitError> {
        let log_size = self.program.schedule.evaluation_log_size;
        let eval_domain_size = 1u32
            .checked_shl(log_size - 1)
            .ok_or(CompositionSplitError::SizeOverflow)?;
        let stream = self.arena.context().stream_raw().as_ptr();
        match self.mode {
            CompositionSplitLaunchMode::FusedFirstForward => {
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_composition_fused_first_forward_on(
                        self.source_pointers.as_u32_ptr().cast(),
                        self.retained_pointers.as_u32_ptr().cast(),
                        log_size,
                        self.inverse_twiddles.as_u32_ptr(),
                        self.inverse_twiddle_words,
                        self.forward_twiddles.as_u32_ptr(),
                        self.forward_twiddle_words,
                        eval_domain_size,
                        stream,
                    )
                };
                check_cuda("composition_split_fused_first_forward", code)?;
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::
                        stwo_ntt_n2b_columns_after_first_stage_two_interval_on(
                            self.retained_pointers.as_u32_ptr().cast(),
                            log_size,
                            COMPOSITION_RETAINED_COLUMNS as u32,
                            self.forward_twiddles.as_u32_ptr(),
                            self.forward_twiddle_words,
                            eval_domain_size,
                            stream,
                        )
                };
                check_cuda("composition_split_remaining_forward", code)?;
            }
            CompositionSplitLaunchMode::TerminalFallback => {
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_composition_to_retained_on(
                        self.source_pointers.as_u32_ptr().cast(),
                        self.retained_pointers.as_u32_ptr().cast(),
                        log_size,
                        self.inverse_twiddles.as_u32_ptr(),
                        self.inverse_twiddle_words,
                        eval_domain_size,
                        stream,
                    )
                };
                check_cuda("composition_split_terminal_fallback", code)?;
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_ntt_n2b_columns_from_stage_two_on(
                        self.retained_pointers.as_u32_ptr().cast(),
                        log_size,
                        COMPOSITION_RETAINED_COLUMNS as u32,
                        self.forward_twiddles.as_u32_ptr(),
                        self.forward_twiddle_words,
                        eval_domain_size,
                        stream,
                    )
                };
                check_cuda("composition_split_fallback_forward", code)?;
            }
        }
        Ok(())
    }

    pub const fn mode(&self) -> CompositionSplitLaunchMode {
        self.mode
    }

    pub const fn traffic(&self) -> CompositionSplitTraffic {
        self.program.traffic
    }

    pub fn retained_evaluations(&self) -> &[ArenaSlice; COMPOSITION_RETAINED_COLUMNS] {
        &self.retained_evaluations
    }
}

fn bind_values<const N: usize>(
    context: &crate::backend::exec_context::CudaExecContext,
    values: [ArenaSlice; N],
    required_words: usize,
    sources: bool,
) -> Result<[ArenaSlice; N], CompositionSplitError> {
    let mut output = values;
    for (index, value) in output.iter_mut().enumerate() {
        if !value.belongs_to(context) {
            return Err(CompositionSplitError::ContextMismatch(value.id()));
        }
        if value.len_words() < required_words {
            return Err(if sources {
                CompositionSplitError::SourceTooSmall {
                    coordinate: index,
                    required_words,
                    actual_words: value.len_words(),
                }
            } else {
                CompositionSplitError::RetainedOutputTooSmall {
                    canonical_column: index,
                    required_words,
                    actual_words: value.len_words(),
                }
            });
        }
        *value = value.truncated(required_words);
    }
    Ok(output)
}

fn bind_twiddles(
    context: &crate::backend::exec_context::CudaExecContext,
    twiddles: ArenaSlice,
    required_words: usize,
) -> Result<u32, CompositionSplitError> {
    if !twiddles.belongs_to(context) {
        return Err(CompositionSplitError::ContextMismatch(twiddles.id()));
    }
    if twiddles.len_words() < required_words {
        return Err(CompositionSplitError::TwiddlesTooSmall {
            required_words,
            actual_words: twiddles.len_words(),
        });
    }
    u32::try_from(twiddles.len_words()).map_err(|_| CompositionSplitError::SizeOverflow)
}

fn upload_pointers<const N: usize>(
    arena: &DeviceArena,
    destination: ArenaSlice,
    values: &[ArenaSlice; N],
) -> Result<(), CompositionSplitError> {
    let addresses = values
        .iter()
        .map(|value| value.as_u32_ptr() as usize)
        .collect::<Vec<_>>();
    let bytes = addresses
        .len()
        .checked_mul(core::mem::size_of::<usize>())
        .ok_or(CompositionSplitError::SizeOverflow)?;
    unsafe {
        arena.context().memcpy_h2d_async(
            destination.as_void_ptr(),
            addresses.as_ptr().cast::<c_void>(),
            bytes,
        )?;
    }
    Ok(())
}

fn validate_disjoint(
    sources: &[ArenaSlice; COMPOSITION_SOURCE_COORDINATES],
    retained: &[ArenaSlice; COMPOSITION_RETAINED_COLUMNS],
    pointers: [ArenaSlice; 2],
    twiddles: [ArenaSlice; 2],
) -> Result<(), CompositionSplitError> {
    let values = sources
        .iter()
        .chain(retained)
        .chain(&pointers)
        .chain(&twiddles)
        .copied()
        .map(|value| Ok((value.id(), address_range(value)?)))
        .collect::<Result<Vec<_>, CompositionSplitError>>()?;
    validate_address_ranges(&values)
}

fn validate_address_ranges(
    values: &[(ArenaSlotId, (usize, usize))],
) -> Result<(), CompositionSplitError> {
    for (index, &(id, range)) in values.iter().enumerate() {
        for &(other_id, other_range) in &values[index + 1..] {
            if ranges_overlap(range, other_range) {
                return Err(CompositionSplitError::InvalidAlias {
                    first: id,
                    second: other_id,
                });
            }
        }
    }
    Ok(())
}

fn address_range(slice: ArenaSlice) -> Result<(usize, usize), CompositionSplitError> {
    let start = slice.as_u32_ptr() as usize;
    let bytes = slice
        .len_words()
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(CompositionSplitError::SizeOverflow)?;
    Ok((
        start,
        start
            .checked_add(bytes)
            .ok_or(CompositionSplitError::SizeOverflow)?,
    ))
}

const fn ranges_overlap(left: (usize, usize), right: (usize, usize)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

fn traffic(
    schedule: CompositionSplitSchedule,
) -> Result<CompositionSplitTraffic, CompositionSplitError> {
    let rows = 1u64
        .checked_shl(schedule.evaluation_log_size)
        .ok_or(CompositionSplitError::SizeOverflow)?;
    let source_image_bytes = rows
        .checked_mul(COMPOSITION_SOURCE_COORDINATES as u64)
        .and_then(|words| words.checked_mul(core::mem::size_of::<u32>() as u64))
        .ok_or(CompositionSplitError::SizeOverflow)?;
    let retained_image_bytes = source_image_bytes
        .checked_mul(2)
        .ok_or(CompositionSplitError::SizeOverflow)?;
    let k = u64::from(schedule.inverse_intervals);
    let scale = |passes: u64| {
        source_image_bytes
            .checked_mul(passes)
            .ok_or(CompositionSplitError::SizeOverflow)
    };
    Ok(CompositionSplitTraffic {
        source_image_bytes,
        retained_image_bytes,
        current_logical_bytes: scale(2 * k + 17)?,
        terminal_fallback_logical_bytes: scale(2 * k + 13)?,
        fused_logical_bytes: scale(2 * k + 9)?,
        current_kernel_launches: schedule.inverse_intervals + 4,
        terminal_fallback_kernel_launches: schedule.inverse_intervals + 3,
        fused_kernel_launches: schedule.inverse_intervals + 2,
        current_d2d_nodes: COMPOSITION_RETAINED_COLUMNS as u32,
        fused_d2d_nodes: 0,
    })
}

fn words(log_size: u32) -> Result<usize, CompositionSplitError> {
    1usize
        .checked_shl(log_size)
        .ok_or(CompositionSplitError::SizeOverflow)
}

#[path = "composition_split_tests.rs"]
#[cfg(test)]
mod tests;
