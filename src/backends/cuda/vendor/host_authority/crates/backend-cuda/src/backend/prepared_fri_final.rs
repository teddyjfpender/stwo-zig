//! Resident final-layer FRI interpolation and transcript staging.
//!
//! The final line evaluation remains coordinate-major and bit-reversed after
//! folding. This graph reproduces `FriProver::commit_last_layer` entirely on the
//! proof stream: naturalize, line-IFFT, normalize, enforce the degree bound,
//! truncate in natural order, and write the retained `LinePoly` storage order
//! directly to the typed transcript input.

use std::collections::BTreeSet;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};
use super::prepared_fri::{fri_workspace_requirements, FriWorkspaceConfig, PreparedFriEvaluation};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const SECURE_COORDINATES: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriFinalWorkspaceRequirements {
    pub config: FriWorkspaceConfig,
    pub evaluation_log_size: u32,
    pub evaluation_words: usize,
    pub coefficient_words: usize,
    pub transcript_words: usize,
    pub inverse_twiddle_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriFinalWorkspaceSlots {
    pub coefficients: ArenaSlotId,
    pub degree_error: ArenaSlotId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriFinalArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedFriFinalError {
    SizeOverflow,
    FinalEvaluationLogMismatch {
        expected: u32,
        actual: u32,
    },
    ContextMismatch(ArenaSlotId),
    AliasedSlot(ArenaSlotId),
    EvaluationStrideTooSmall {
        required: usize,
        actual: usize,
    },
    EvaluationTooSmall {
        required: usize,
        actual: usize,
    },
    InverseTwiddlesTooSmall {
        required: usize,
        actual: usize,
    },
    TranscriptInputTooSmall {
        required: usize,
        actual: usize,
    },
    SlotTooSmall {
        slot: ArenaSlotId,
        required: usize,
        actual: usize,
    },
    Arena(ArenaError),
    Fri(super::prepared_fri::PreparedFriError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedFriFinalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid prepared CUDA final FRI graph: {self:?}")
    }
}

impl std::error::Error for PreparedFriFinalError {}

impl From<ArenaError> for PreparedFriFinalError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<super::prepared_fri::PreparedFriError> for PreparedFriFinalError {
    fn from(value: super::prepared_fri::PreparedFriError) -> Self {
        Self::Fri(value)
    }
}

impl From<CudaRuntimeError> for PreparedFriFinalError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

pub fn fri_final_workspace_requirements(
    config: FriWorkspaceConfig,
) -> Result<FriFinalWorkspaceRequirements, PreparedFriFinalError> {
    let fri = fri_workspace_requirements(config)?;
    let evaluation_words = secure_words(fri.last_layer_log_size)?;
    let transcript_words = secure_words(config.fri.log_last_layer_degree_bound)?;
    Ok(FriFinalWorkspaceRequirements {
        config,
        evaluation_log_size: fri.last_layer_log_size,
        evaluation_words,
        coefficient_words: evaluation_words,
        transcript_words,
        inverse_twiddle_words: pow2(config.twiddle_log_size)?,
    })
}

impl FriFinalWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: FriFinalWorkspaceSlots,
    ) -> Result<[FriFinalArenaSlotRequirement; 2], PreparedFriFinalError> {
        if slots.coefficients == slots.degree_error {
            return Err(PreparedFriFinalError::AliasedSlot(slots.coefficients));
        }
        Ok([
            FriFinalArenaSlotRequirement {
                id: slots.coefficients,
                len_words: self.coefficient_words,
                alignment_words: 1,
            },
            FriFinalArenaSlotRequirement {
                id: slots.degree_error,
                len_words: 1,
                alignment_words: 1,
            },
        ])
    }
}

/// Allocation-free final FRI launch graph. A nonzero discarded coefficient
/// writes the non-canonical word `P` into the transcript input; the following
/// typed `MixFelts` operation records `STATUS_INVALID_FIELD` and cannot advance.
pub struct PreparedFriFinalGraph<'a> {
    arena: &'a DeviceArena,
    requirements: FriFinalWorkspaceRequirements,
    evaluation: PreparedFriEvaluation,
    inverse_twiddles: ArenaSlice,
    coefficients: ArenaSlice,
    degree_error: ArenaSlice,
    transcript_coefficients: ArenaSlice,
}

impl<'a> PreparedFriFinalGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        config: FriWorkspaceConfig,
        evaluation: PreparedFriEvaluation,
        inverse_twiddles: ArenaSlice,
        transcript_coefficients: ArenaSlice,
        slots: FriFinalWorkspaceSlots,
    ) -> Result<Self, PreparedFriFinalError> {
        let requirements = fri_final_workspace_requirements(config)?;
        if evaluation.log_size != requirements.evaluation_log_size {
            return Err(PreparedFriFinalError::FinalEvaluationLogMismatch {
                expected: requirements.evaluation_log_size,
                actual: evaluation.log_size,
            });
        }
        let evaluation_size = pow2(evaluation.log_size)?;
        if evaluation.coordinate_stride < evaluation_size {
            return Err(PreparedFriFinalError::EvaluationStrideTooSmall {
                required: evaluation_size,
                actual: evaluation.coordinate_stride,
            });
        }
        let required_evaluation_capacity = evaluation
            .coordinate_stride
            .checked_mul(SECURE_COORDINATES)
            .ok_or(PreparedFriFinalError::SizeOverflow)?;
        if evaluation.values.len_words() < required_evaluation_capacity {
            return Err(PreparedFriFinalError::EvaluationTooSmall {
                required: required_evaluation_capacity,
                actual: evaluation.values.len_words(),
            });
        }
        if inverse_twiddles.len_words() < requirements.inverse_twiddle_words {
            return Err(PreparedFriFinalError::InverseTwiddlesTooSmall {
                required: requirements.inverse_twiddle_words,
                actual: inverse_twiddles.len_words(),
            });
        }
        if transcript_coefficients.len_words() < requirements.transcript_words {
            return Err(PreparedFriFinalError::TranscriptInputTooSmall {
                required: requirements.transcript_words,
                actual: transcript_coefficients.len_words(),
            });
        }

        let slot_requirements = requirements.arena_slot_requirements(slots)?;
        let coefficients = bind_slot(arena, slot_requirements[0])?;
        let degree_error = bind_slot(arena, slot_requirements[1])?;
        let sources = [
            evaluation.values,
            inverse_twiddles,
            transcript_coefficients,
            coefficients,
            degree_error,
        ];
        let context = arena.context().identity_token();
        for source in sources {
            if source.context_token() != context {
                return Err(PreparedFriFinalError::ContextMismatch(source.id()));
            }
        }
        let mut ids = BTreeSet::new();
        for source in sources {
            if !ids.insert(source.id()) {
                return Err(PreparedFriFinalError::AliasedSlot(source.id()));
            }
        }

        Ok(Self {
            arena,
            requirements,
            evaluation,
            inverse_twiddles,
            coefficients,
            degree_error,
            transcript_coefficients,
        })
    }

    pub fn requirements(&self) -> &FriFinalWorkspaceRequirements {
        &self.requirements
    }

    pub fn transcript_destination(&self) -> ArenaSlice {
        self.transcript_coefficients
    }

    pub fn degree_error(&self) -> ArenaSlice {
        self.degree_error
    }

    /// Enqueue only stream-owned memset and kernels; safe in eager mode and
    /// graph capture, with no allocation, transfer, synchronization, or default
    /// stream dependency.
    pub fn launch(&self) -> Result<(), PreparedFriFinalError> {
        unsafe {
            self.arena
                .context()
                .memset_async(self.degree_error.as_void_ptr(), 0, WORD_BYTES)?;
        }
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_fri_last_layer_on(
                self.evaluation.values.as_u32_ptr().cast_const(),
                u32::try_from(self.evaluation.coordinate_stride)
                    .map_err(|_| PreparedFriFinalError::SizeOverflow)?,
                self.evaluation.log_size,
                self.inverse_twiddles.as_u32_ptr().cast_const(),
                u32::try_from(self.requirements.inverse_twiddle_words)
                    .map_err(|_| PreparedFriFinalError::SizeOverflow)?,
                self.requirements.config.fri.log_last_layer_degree_bound,
                self.coefficients.as_u32_ptr(),
                self.degree_error.as_u32_ptr(),
                self.transcript_coefficients.as_u32_ptr(),
                self.arena.context().stream_raw().as_ptr(),
            )
        };
        check_cuda("prepared_fri_final", code)?;
        Ok(())
    }
}

fn bind_slot(
    arena: &DeviceArena,
    requirement: FriFinalArenaSlotRequirement,
) -> Result<ArenaSlice, PreparedFriFinalError> {
    let slice = arena.bind(requirement.id)?;
    if slice.len_words() < requirement.len_words {
        return Err(PreparedFriFinalError::SlotTooSmall {
            slot: requirement.id,
            required: requirement.len_words,
            actual: slice.len_words(),
        });
    }
    // Pooled slots may be larger than any single logical buffer; expose only
    // the logical extent so no consumer derives sizes from the pooled surplus.
    Ok(slice.truncated(requirement.len_words))
}

fn pow2(log_size: u32) -> Result<usize, PreparedFriFinalError> {
    1usize
        .checked_shl(log_size)
        .ok_or(PreparedFriFinalError::SizeOverflow)
}

fn secure_words(log_size: u32) -> Result<usize, PreparedFriFinalError> {
    pow2(log_size)?
        .checked_mul(SECURE_COORDINATES)
        .ok_or(PreparedFriFinalError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;
    use stwo::core::circle::Coset;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::fri::FriConfig;
    use stwo::core::poly::line::{LineDomain, LinePoly};
    use stwo::core::utils::{bit_reverse, bit_reverse_index};
    use stwo::prover::backend::cpu::circle::slow_precompute_twiddles;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::line::LineEvaluation;
    use stwo::prover::secure_column::SecureColumnByCoords;

    use super::*;

    fn config() -> FriWorkspaceConfig {
        FriWorkspaceConfig {
            fri: FriConfig::new(2, 1, 16, 4),
            circle_log_size: 11,
            twiddle_log_size: 10,
        }
    }

    #[test]
    fn exact_workspace_and_transcript_shape() {
        let requirements = fri_final_workspace_requirements(config()).unwrap();
        assert_eq!(requirements.evaluation_log_size, 3);
        assert_eq!(requirements.evaluation_words, 4 * 8);
        assert_eq!(requirements.coefficient_words, 4 * 8);
        assert_eq!(requirements.transcript_words, 4 * 4);
        assert_eq!(requirements.inverse_twiddle_words, 1 << 10);

        let slots = FriFinalWorkspaceSlots {
            coefficients: ArenaSlotId(1),
            degree_error: ArenaSlotId(2),
        };
        assert_eq!(
            requirements.arena_slot_requirements(slots).unwrap(),
            [
                FriFinalArenaSlotRequirement {
                    id: ArenaSlotId(1),
                    len_words: 32,
                    alignment_words: 1,
                },
                FriFinalArenaSlotRequirement {
                    id: ArenaSlotId(2),
                    len_words: 1,
                    alignment_words: 1,
                },
            ]
        );
    }

    #[test]
    fn tree_offsets_recover_natural_line_ifft_twiddles() {
        let root = Coset::half_odds(10);
        let final_domain = LineDomain::new(root.repeated_double(7));
        let twiddles = slow_precompute_twiddles(root);
        let inverse: Vec<_> = twiddles.into_iter().map(|value| value.inverse()).collect();
        let total = inverse.len();

        let mut domain = final_domain;
        while domain.size() > 1 {
            let domain_size = domain.size();
            let stored = &inverse[total - domain_size..total - domain_size / 2];
            for (natural_index, point) in domain.iter().take(domain_size / 2).enumerate() {
                assert_eq!(
                    stored[bit_reverse_index(natural_index, domain.log_size().saturating_sub(1))],
                    point.inverse()
                );
            }
            domain = domain.double();
        }
    }

    #[test]
    fn reference_commit_last_layer_order_and_degree_split() {
        let log_size = 3;
        let domain = LineDomain::new(Coset::half_odds(log_size));
        let ordered = vec![
            SecureField::from_u32_unchecked(3, 5, 7, 11),
            SecureField::from_u32_unchecked(13, 17, 19, 23),
            SecureField::from_u32_unchecked(29, 31, 37, 41),
            SecureField::from_u32_unchecked(43, 47, 53, 59),
            SecureField::zero(),
            SecureField::zero(),
            SecureField::zero(),
            SecureField::zero(),
        ];
        let polynomial = LinePoly::from_ordered_coefficients(ordered.clone());
        let values: Vec<_> = (0..domain.size())
            .map(|index| {
                polynomial.eval_at_point(domain.at(bit_reverse_index(index, log_size)).into())
            })
            .collect();
        let evaluation = LineEvaluation::<CpuBackend>::new(
            domain,
            values.into_iter().collect::<SecureColumnByCoords<_>>(),
        );
        let mut recovered = evaluation.interpolate().into_ordered_coefficients();
        let high = recovered.split_off(1 << 2);
        assert_eq!(recovered, ordered[..4]);
        assert!(high.iter().all(SecureField::is_zero));

        let transcript_order = LinePoly::from_ordered_coefficients(recovered.clone()).to_vec();
        assert_eq!(
            transcript_order,
            vec![ordered[0], ordered[2], ordered[1], ordered[3]]
        );

        let mut bit_reversed = ordered.clone();
        bit_reverse(&mut bit_reversed);
        for index in 0..ordered.len() {
            assert_eq!(
                bit_reversed[bit_reverse_index(index, log_size)],
                ordered[index]
            );
        }
    }
}
