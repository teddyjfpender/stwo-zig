//! Prepared arena-native quotient combination and LDE into FRI input layout.
//!
//! The caller computes partial-numerator coordinate columns and supplies exact
//! OODS constants. Setup uploads stable pointer/log descriptors once;
//! [`PreparedQuotientGraph::launch`] combines on the quotient subdomain,
//! interpolates four M31 coordinates in place, and evaluates them directly into
//! the contiguous full-domain layout consumed by prepared FRI.

use core::ffi::c_void;
use std::collections::BTreeSet;

use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;

use super::exec_context::{
    check_cuda, cuda_device_snapshot, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError,
    DeviceArena,
};
use super::prepared_interpolation::is_supported_interpolation_log_size;
use super::quotient_producer_b2n::{
    QuotientProducerB2nAttestationError, QuotientProducerB2nFunctionAttributes,
    QuotientProducerB2nKernelRole, QuotientProducerB2nLaunchAttestation,
    QuotientProducerB2nProgram, QuotientProducerB2nReceipt, QuotientProducerB2nRuntimeAttestation,
    QUOTIENT_PRODUCER_B2N_CONTINUATION_THREADS, QUOTIENT_PRODUCER_B2N_LAUNCH_THREADS,
};
use crate::columns::bindings::{CirclePointSecureField, CudaSecureField};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const SECURE_COORDINATES: usize = 4;
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);

pub const QUOTIENT_POINTER_ALIGNMENT_WORDS: usize = core::mem::align_of::<*mut u32>() / WORD_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientWorkspaceConfig {
    pub lifting_log_size: u32,
    pub log_blowup_factor: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientWorkspaceRequirements {
    pub config: QuotientWorkspaceConfig,
    pub subdomain_log_size: u32,
    pub sample_count: usize,
    pub sample_point_words: usize,
    pub first_linear_term_words: usize,
    pub partial_log_size_words: usize,
    pub partial_pointer_words: usize,
    pub coordinate_pointer_words: usize,
    pub coefficient_size_words: usize,
    pub subdomain_value_words: usize,
    pub output_value_words: usize,
    pub combine_pass_bytes: QuotientCombinePassBytes,
    pub forward_twiddle_words: usize,
    pub inverse_twiddle_words: usize,
    pub half_coset_initial_index: u32,
    pub half_coset_step_size: u32,
}

/// Exact logical pass/byte model for quotient combination. These values describe
/// explicit kernel requests, not cache behavior or measured HBM traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientCombinePassBytes {
    pub rows: usize,
    pub samples: usize,
    pub denominator_inversions: usize,
    /// Bytes occupied by the retired global `cm31[row][sample]` slab.
    pub eliminated_scratch_bytes: usize,
    /// One retired global write plus one retired global read per denominator.
    pub eliminated_logical_traffic_bytes: usize,
    pub denominator_global_passes: usize,
    /// One canonical QM31 output write per row.
    pub output_write_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientWorkspaceSlots {
    pub sample_points: ArenaSlotId,
    pub first_linear_terms: ArenaSlotId,
    pub partial_log_sizes: ArenaSlotId,
    pub partial_coordinate_ptrs: ArenaSlotId,
    pub subdomain_coordinate_ptrs: ArenaSlotId,
    pub output_coordinate_ptrs: ArenaSlotId,
    pub coefficient_sizes: ArenaSlotId,
    pub subdomain_values: ArenaSlotId,
    pub output_values: ArenaSlotId,
}

#[derive(Clone, Copy, Debug)]
pub struct QuotientSampleConstants {
    pub sample_point: CirclePoint<SecureField>,
    pub first_linear_term_acc: SecureField,
}

#[derive(Clone, Copy, Debug)]
pub struct QuotientNumeratorSource {
    pub constants: QuotientSampleConstants,
    pub log_size: u32,
    /// M31 coordinate columns in canonical QM31 order.
    pub coordinates: [ArenaSlice; SECURE_COORDINATES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedQuotientError {
    InvalidLiftingLogSize(u32),
    InvalidBlowup {
        lifting_log_size: u32,
        log_blowup_factor: u32,
    },
    UnsupportedNativeInterpolationLogSize(u32),
    EmptySources,
    TooManySources(usize),
    PartialLogSizeTooLarge {
        source: usize,
        log_size: u32,
        subdomain_log_size: u32,
    },
    ConstantsCountMismatch {
        expected: usize,
        actual: usize,
    },
    ProducerB2nProgramMismatch,
    ProducerB2nAttestation(QuotientProducerB2nAttestationError),
    DuplicateSlot(ArenaSlotId),
    ContextMismatch(ArenaSlotId),
    SourceAliasesWorkspace(ArenaSlotId),
    AliasedTwiddles(ArenaSlotId),
    AliasedSourceSlot(ArenaSlotId),
    SourceTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    MisalignedSlot {
        slot: ArenaSlotId,
        alignment_words: usize,
    },
    ForwardTwiddlesTooSmall {
        required_words: usize,
        actual_words: usize,
    },
    InverseTwiddlesTooSmall {
        required_words: usize,
        actual_words: usize,
    },
    SizeOverflow,
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedQuotientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid prepared CUDA quotient workspace: {self:?}")
    }
}

impl std::error::Error for PreparedQuotientError {}

impl From<ArenaError> for PreparedQuotientError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedQuotientError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

impl From<QuotientProducerB2nAttestationError> for PreparedQuotientError {
    fn from(value: QuotientProducerB2nAttestationError) -> Self {
        Self::ProducerB2nAttestation(value)
    }
}

pub fn quotient_workspace_requirements(
    config: QuotientWorkspaceConfig,
    partial_log_sizes: &[u32],
) -> Result<QuotientWorkspaceRequirements, PreparedQuotientError> {
    if !(2..=30).contains(&config.lifting_log_size) {
        return Err(PreparedQuotientError::InvalidLiftingLogSize(
            config.lifting_log_size,
        ));
    }
    if config.log_blowup_factor == 0 || config.log_blowup_factor >= config.lifting_log_size {
        return Err(PreparedQuotientError::InvalidBlowup {
            lifting_log_size: config.lifting_log_size,
            log_blowup_factor: config.log_blowup_factor,
        });
    }
    let subdomain_log_size = config.lifting_log_size - config.log_blowup_factor;
    if !is_supported_interpolation_log_size(subdomain_log_size) {
        return Err(
            PreparedQuotientError::UnsupportedNativeInterpolationLogSize(subdomain_log_size),
        );
    }
    if partial_log_sizes.is_empty() {
        return Err(PreparedQuotientError::EmptySources);
    }
    let sample_count = partial_log_sizes.len();
    let _ = u32::try_from(sample_count)
        .map_err(|_| PreparedQuotientError::TooManySources(sample_count))?;
    for (source, &log_size) in partial_log_sizes.iter().enumerate() {
        if log_size > subdomain_log_size {
            return Err(PreparedQuotientError::PartialLogSizeTooLarge {
                source,
                log_size,
                subdomain_log_size,
            });
        }
    }

    let full_domain = pow2(config.lifting_log_size)?;
    let subdomain = pow2(subdomain_log_size)?;
    let denominator_inversions = subdomain
        .checked_mul(sample_count)
        .ok_or(PreparedQuotientError::SizeOverflow)?;
    let eliminated_scratch_bytes = denominator_inversions
        .checked_mul(core::mem::size_of::<[u32; 2]>())
        .ok_or(PreparedQuotientError::SizeOverflow)?;
    let eval_domain = CanonicCoset::new(config.lifting_log_size).circle_domain();
    let (quotient_domain, _) = eval_domain.split(config.log_blowup_factor);
    Ok(QuotientWorkspaceRequirements {
        config,
        subdomain_log_size,
        sample_count,
        sample_point_words: typed_words::<CirclePointSecureField>(sample_count)?,
        first_linear_term_words: typed_words::<CudaSecureField>(sample_count)?,
        partial_log_size_words: sample_count,
        partial_pointer_words: sample_count
            .checked_mul(SECURE_COORDINATES)
            .and_then(|count| count.checked_mul(POINTER_WORDS))
            .ok_or(PreparedQuotientError::SizeOverflow)?,
        coordinate_pointer_words: SECURE_COORDINATES
            .checked_mul(POINTER_WORDS)
            .ok_or(PreparedQuotientError::SizeOverflow)?,
        coefficient_size_words: SECURE_COORDINATES,
        subdomain_value_words: subdomain
            .checked_mul(SECURE_COORDINATES)
            .ok_or(PreparedQuotientError::SizeOverflow)?,
        output_value_words: full_domain
            .checked_mul(SECURE_COORDINATES)
            .ok_or(PreparedQuotientError::SizeOverflow)?,
        combine_pass_bytes: QuotientCombinePassBytes {
            rows: subdomain,
            samples: sample_count,
            denominator_inversions,
            eliminated_scratch_bytes,
            eliminated_logical_traffic_bytes: eliminated_scratch_bytes
                .checked_mul(2)
                .ok_or(PreparedQuotientError::SizeOverflow)?,
            denominator_global_passes: 0,
            output_write_bytes: subdomain
                .checked_mul(core::mem::size_of::<[u32; SECURE_COORDINATES]>())
                .ok_or(PreparedQuotientError::SizeOverflow)?,
        },
        forward_twiddle_words: pow2(config.lifting_log_size - 1)?,
        inverse_twiddle_words: pow2(subdomain_log_size - 1)?,
        half_coset_initial_index: quotient_domain.half_coset.initial_index.0 as u32,
        half_coset_step_size: quotient_domain.half_coset.step_size.0 as u32,
    })
}

impl QuotientWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &QuotientWorkspaceSlots,
    ) -> Result<Vec<QuotientArenaSlotRequirement>, PreparedQuotientError> {
        let requirements = vec![
            slot(slots.sample_points, self.sample_point_words, 1),
            slot(slots.first_linear_terms, self.first_linear_term_words, 1),
            slot(slots.partial_log_sizes, self.partial_log_size_words, 1),
            slot(
                slots.partial_coordinate_ptrs,
                self.partial_pointer_words,
                QUOTIENT_POINTER_ALIGNMENT_WORDS,
            ),
            slot(
                slots.subdomain_coordinate_ptrs,
                self.coordinate_pointer_words,
                QUOTIENT_POINTER_ALIGNMENT_WORDS,
            ),
            slot(
                slots.output_coordinate_ptrs,
                self.coordinate_pointer_words,
                QUOTIENT_POINTER_ALIGNMENT_WORDS,
            ),
            slot(slots.coefficient_sizes, self.coefficient_size_words, 1),
            slot(slots.subdomain_values, self.subdomain_value_words, 1),
            slot(slots.output_values, self.output_value_words, 1),
        ];
        let mut seen = BTreeSet::new();
        for requirement in &requirements {
            if !seen.insert(requirement.id) {
                return Err(PreparedQuotientError::DuplicateSlot(requirement.id));
            }
        }
        Ok(requirements)
    }
}

fn slot(id: ArenaSlotId, len_words: usize, alignment_words: usize) -> QuotientArenaSlotRequirement {
    QuotientArenaSlotRequirement {
        id,
        len_words,
        alignment_words,
    }
}

enum HostDescriptor {
    U32(Vec<u32>),
    Pointers(Vec<usize>),
    Points(Vec<CirclePointSecureField>),
    Secure(Vec<CudaSecureField>),
}

impl HostDescriptor {
    fn bytes(&self) -> (*const c_void, usize) {
        match self {
            Self::U32(values) => typed_bytes(values),
            Self::Pointers(values) => typed_bytes(values),
            Self::Points(values) => typed_bytes(values),
            Self::Secure(values) => typed_bytes(values),
        }
    }
}

struct PendingUpload {
    destination: ArenaSlice,
    descriptor: HostDescriptor,
}

/// Stable quotient-to-FRI launch object. Launch never allocates, uploads, frees,
/// synchronizes, or touches the default stream.
pub struct PreparedQuotientGraph<'a> {
    arena: &'a DeviceArena,
    requirements: QuotientWorkspaceRequirements,
    sample_points: ArenaSlice,
    first_linear_terms: ArenaSlice,
    partial_log_sizes: ArenaSlice,
    partial_coordinate_ptrs: ArenaSlice,
    subdomain_coordinate_ptrs: ArenaSlice,
    output_coordinate_ptrs: ArenaSlice,
    coefficient_sizes: ArenaSlice,
    subdomain_values: ArenaSlice,
    output_values: ArenaSlice,
    forward_twiddles: ArenaSlice,
    inverse_twiddles: ArenaSlice,
    producer_b2n: Option<QuotientProducerB2nProgram>,
    producer_b2n_attestation: Option<QuotientProducerB2nRuntimeAttestation>,
}

impl<'a> PreparedQuotientGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        config: QuotientWorkspaceConfig,
        sources: &[QuotientNumeratorSource],
        forward_twiddles: ArenaSlice,
        inverse_subdomain_twiddles: ArenaSlice,
        slots: &QuotientWorkspaceSlots,
    ) -> Result<Self, PreparedQuotientError> {
        Self::prepare_inner(
            arena,
            config,
            sources,
            forward_twiddles,
            inverse_subdomain_twiddles,
            slots,
            None,
        )
    }

    /// Prepare the exact-shape producer-owned inverse boundary. The ordinary
    /// [`Self::prepare`] constructor remains the byte-identical fallback.
    pub fn prepare_with_producer_b2n(
        arena: &'a DeviceArena,
        config: QuotientWorkspaceConfig,
        sources: &[QuotientNumeratorSource],
        forward_twiddles: ArenaSlice,
        inverse_subdomain_twiddles: ArenaSlice,
        slots: &QuotientWorkspaceSlots,
        program: QuotientProducerB2nProgram,
    ) -> Result<Self, PreparedQuotientError> {
        Self::prepare_inner(
            arena,
            config,
            sources,
            forward_twiddles,
            inverse_subdomain_twiddles,
            slots,
            Some(program),
        )
    }

    fn prepare_inner(
        arena: &'a DeviceArena,
        config: QuotientWorkspaceConfig,
        sources: &[QuotientNumeratorSource],
        forward_twiddles: ArenaSlice,
        inverse_subdomain_twiddles: ArenaSlice,
        slots: &QuotientWorkspaceSlots,
        producer_b2n: Option<QuotientProducerB2nProgram>,
    ) -> Result<Self, PreparedQuotientError> {
        let logs: Vec<_> = sources.iter().map(|source| source.log_size).collect();
        if producer_b2n
            .as_ref()
            .is_some_and(|program| !program.matches(config, &logs))
        {
            return Err(PreparedQuotientError::ProducerB2nProgramMismatch);
        }
        let producer_b2n_attestation = producer_b2n
            .as_ref()
            .map(query_producer_b2n_attestation)
            .transpose()?;
        let requirements = quotient_workspace_requirements(config, &logs)?;
        let slot_requirements = requirements.arena_slot_requirements(slots)?;
        let workspace_ids: BTreeSet<_> = slot_requirements.iter().map(|entry| entry.id).collect();
        let context_token = arena.context().identity_token();

        if forward_twiddles.id() == inverse_subdomain_twiddles.id() {
            return Err(PreparedQuotientError::AliasedTwiddles(
                forward_twiddles.id(),
            ));
        }
        let mut source_ids =
            BTreeSet::from([forward_twiddles.id(), inverse_subdomain_twiddles.id()]);
        for source in [forward_twiddles, inverse_subdomain_twiddles]
            .into_iter()
            .chain(sources.iter().flat_map(|source| source.coordinates))
        {
            if source.context_token() != context_token {
                return Err(PreparedQuotientError::ContextMismatch(source.id()));
            }
            if workspace_ids.contains(&source.id()) {
                return Err(PreparedQuotientError::SourceAliasesWorkspace(source.id()));
            }
            if source.id() != forward_twiddles.id()
                && source.id() != inverse_subdomain_twiddles.id()
                && !source_ids.insert(source.id())
            {
                return Err(PreparedQuotientError::AliasedSourceSlot(source.id()));
            }
        }
        if forward_twiddles.len_words() < requirements.forward_twiddle_words {
            return Err(PreparedQuotientError::ForwardTwiddlesTooSmall {
                required_words: requirements.forward_twiddle_words,
                actual_words: forward_twiddles.len_words(),
            });
        }
        if inverse_subdomain_twiddles.len_words() < requirements.inverse_twiddle_words {
            return Err(PreparedQuotientError::InverseTwiddlesTooSmall {
                required_words: requirements.inverse_twiddle_words,
                actual_words: inverse_subdomain_twiddles.len_words(),
            });
        }
        for source in sources {
            let required_words = pow2(source.log_size)?;
            for coordinate in source.coordinates {
                if coordinate.len_words() < required_words {
                    return Err(PreparedQuotientError::SourceTooSmall {
                        slot: coordinate.id(),
                        required_words,
                        actual_words: coordinate.len_words(),
                    });
                }
            }
        }

        let sample_points = bind_slot(
            arena,
            slots.sample_points,
            requirements.sample_point_words,
            1,
        )?;
        let first_linear_terms = bind_slot(
            arena,
            slots.first_linear_terms,
            requirements.first_linear_term_words,
            1,
        )?;
        let partial_log_sizes = bind_slot(
            arena,
            slots.partial_log_sizes,
            requirements.partial_log_size_words,
            1,
        )?;
        let partial_coordinate_ptrs = bind_slot(
            arena,
            slots.partial_coordinate_ptrs,
            requirements.partial_pointer_words,
            QUOTIENT_POINTER_ALIGNMENT_WORDS,
        )?;
        let subdomain_coordinate_ptrs = bind_slot(
            arena,
            slots.subdomain_coordinate_ptrs,
            requirements.coordinate_pointer_words,
            QUOTIENT_POINTER_ALIGNMENT_WORDS,
        )?;
        let output_coordinate_ptrs = bind_slot(
            arena,
            slots.output_coordinate_ptrs,
            requirements.coordinate_pointer_words,
            QUOTIENT_POINTER_ALIGNMENT_WORDS,
        )?;
        let coefficient_sizes = bind_slot(
            arena,
            slots.coefficient_sizes,
            requirements.coefficient_size_words,
            1,
        )?;
        let subdomain_values = bind_slot(
            arena,
            slots.subdomain_values,
            requirements.subdomain_value_words,
            1,
        )?;
        let output_values = bind_slot(
            arena,
            slots.output_values,
            requirements.output_value_words,
            1,
        )?;
        let subdomain_stride = pow2(requirements.subdomain_log_size)?;
        let output_stride = pow2(requirements.config.lifting_log_size)?;
        let partial_pointers = (0..SECURE_COORDINATES)
            .flat_map(|coordinate| {
                sources
                    .iter()
                    .map(move |source| source.coordinates[coordinate].as_u32_ptr() as usize)
            })
            .collect();
        let subdomain_pointers = coordinate_pointers(subdomain_values, subdomain_stride);
        let output_pointers = coordinate_pointers(output_values, output_stride);
        let constants: Vec<_> = sources.iter().map(|source| source.constants).collect();
        let uploads = vec![
            points_upload(sample_points, &constants),
            secure_upload(first_linear_terms, &constants),
            PendingUpload {
                destination: partial_log_sizes,
                descriptor: HostDescriptor::U32(logs),
            },
            PendingUpload {
                destination: partial_coordinate_ptrs,
                descriptor: HostDescriptor::Pointers(partial_pointers),
            },
            PendingUpload {
                destination: subdomain_coordinate_ptrs,
                descriptor: HostDescriptor::Pointers(subdomain_pointers),
            },
            PendingUpload {
                destination: output_coordinate_ptrs,
                descriptor: HostDescriptor::Pointers(output_pointers),
            },
            PendingUpload {
                destination: coefficient_sizes,
                descriptor: HostDescriptor::U32(vec![
                    u32::try_from(subdomain_stride).map_err(
                        |_| PreparedQuotientError::SizeOverflow
                    )?;
                    SECURE_COORDINATES
                ]),
            },
        ];
        upload_and_sync(arena, &uploads)?;

        Ok(Self {
            arena,
            requirements,
            sample_points,
            first_linear_terms,
            partial_log_sizes,
            partial_coordinate_ptrs,
            subdomain_coordinate_ptrs,
            output_coordinate_ptrs,
            coefficient_sizes,
            subdomain_values,
            output_values,
            forward_twiddles,
            inverse_twiddles: inverse_subdomain_twiddles,
            producer_b2n,
            producer_b2n_attestation,
        })
    }

    pub fn requirements(&self) -> &QuotientWorkspaceRequirements {
        &self.requirements
    }

    /// Device destination for the canonical sample-point array. A prepared OODS
    /// producer writes this slice on the arena stream before [`Self::launch`].
    pub const fn sample_points_destination(&self) -> ArenaSlice {
        self.sample_points
    }

    /// Device destination for the accumulated first line coefficients. A
    /// prepared numerator producer writes this slice before [`Self::launch`].
    pub const fn first_linear_terms_destination(&self) -> ArenaSlice {
        self.first_linear_terms
    }

    /// Update only transcript-derived constants between graph replays.
    pub fn upload_constants_at_transcript_boundary(
        &self,
        constants: &[QuotientSampleConstants],
    ) -> Result<(), PreparedQuotientError> {
        if constants.len() != self.requirements.sample_count {
            return Err(PreparedQuotientError::ConstantsCountMismatch {
                expected: self.requirements.sample_count,
                actual: constants.len(),
            });
        }
        upload_and_sync(
            self.arena,
            &[
                points_upload(self.sample_points, constants),
                secure_upload(self.first_linear_terms, constants),
            ],
        )
    }

    /// Combine, interpolate, and evaluate using only the arena's explicit stream.
    pub fn launch(&self) -> Result<(), PreparedQuotientError> {
        let sample_count = u32::try_from(self.requirements.sample_count)
            .map_err(|_| PreparedQuotientError::SizeOverflow)?;
        let subdomain_size = u32::try_from(pow2(self.requirements.subdomain_log_size)?)
            .map_err(|_| PreparedQuotientError::SizeOverflow)?;
        let partial_ptrs = self
            .partial_coordinate_ptrs
            .as_u32_ptr()
            .cast::<*const u32>();
        let subdomain_ptrs = self
            .subdomain_coordinate_ptrs
            .as_u32_ptr()
            .cast::<*mut u32>();
        let output_ptrs = self.output_coordinate_ptrs.as_u32_ptr().cast::<*mut u32>();
        let stream = self.arena.context().stream_raw().as_ptr();
        let partials = |coordinate: usize| unsafe {
            partial_ptrs.add(coordinate * self.requirements.sample_count)
        };
        let subdomain_coordinate = |coordinate: usize| unsafe {
            self.subdomain_values
                .as_u32_ptr()
                .add(coordinate * subdomain_size as usize)
        };

        let inverse_words = u32::try_from(self.inverse_twiddles.len_words())
            .map_err(|_| PreparedQuotientError::SizeOverflow)?;
        let inverse_domain_size = 1u32 << (self.requirements.subdomain_log_size - 1);
        if self.producer_b2n.is_some() {
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_combine_quotients_b2n_init7_on(
                    self.requirements.half_coset_initial_index,
                    self.requirements.half_coset_step_size,
                    subdomain_size,
                    self.requirements.subdomain_log_size,
                    self.sample_points.as_u32_ptr().cast_const(),
                    sample_count,
                    self.first_linear_terms.as_u32_ptr().cast(),
                    self.partial_log_sizes.as_u32_ptr().cast_const(),
                    partials(0),
                    partials(1),
                    partials(2),
                    partials(3),
                    subdomain_coordinate(0),
                    subdomain_coordinate(1),
                    subdomain_coordinate(2),
                    subdomain_coordinate(3),
                    self.inverse_twiddles.as_u32_ptr(),
                    inverse_words,
                    inverse_domain_size,
                    stream,
                )
            };
            check_cuda("prepared_quotient_producer_b2n_init7", code)?;
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_columns_after_first_seven_on(
                    subdomain_ptrs,
                    self.requirements.subdomain_log_size,
                    SECURE_COORDINATES as u32,
                    self.inverse_twiddles.as_u32_ptr(),
                    inverse_words,
                    inverse_domain_size,
                    stream,
                )
            };
            check_cuda("prepared_quotient_b2n_continuation", code)?;
        } else {
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_combine_quotients_from_numerators_on(
                    self.requirements.half_coset_initial_index,
                    self.requirements.half_coset_step_size,
                    subdomain_size,
                    self.requirements.subdomain_log_size,
                    self.sample_points.as_u32_ptr().cast_const(),
                    sample_count,
                    self.first_linear_terms.as_u32_ptr().cast(),
                    self.partial_log_sizes.as_u32_ptr().cast_const(),
                    partials(0),
                    partials(1),
                    partials(2),
                    partials(3),
                    subdomain_coordinate(0),
                    subdomain_coordinate(1),
                    subdomain_coordinate(2),
                    subdomain_coordinate(3),
                    stream,
                )
            };
            check_cuda("prepared_quotient_combine", code)?;
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_columns_on(
                    subdomain_ptrs,
                    self.requirements.subdomain_log_size,
                    SECURE_COORDINATES as u32,
                    self.inverse_twiddles.as_u32_ptr(),
                    inverse_words,
                    inverse_domain_size,
                    stream,
                )
            };
            check_cuda("prepared_quotient_interpolate", code)?;
        }

        let forward_words = u32::try_from(self.forward_twiddles.len_words())
            .map_err(|_| PreparedQuotientError::SizeOverflow)?;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_lde_n2b_columns_on(
                subdomain_ptrs.cast::<*const u32>(),
                self.coefficient_sizes.as_u32_ptr().cast_const(),
                output_ptrs,
                self.requirements.config.lifting_log_size,
                SECURE_COORDINATES as u32,
                self.forward_twiddles.as_u32_ptr(),
                forward_words,
                1u32 << (self.requirements.config.lifting_log_size - 1),
                stream,
            )
        };
        check_cuda("prepared_quotient_evaluate", code)?;
        Ok(())
    }

    /// Contiguous `[coord0 | coord1 | coord2 | coord3]` full-domain evaluation.
    pub const fn output_evaluation(&self) -> ArenaSlice {
        self.output_values
    }

    pub fn producer_b2n_receipt(&self) -> Option<QuotientProducerB2nReceipt> {
        self.producer_b2n.as_ref().map(|program| program.receipt())
    }

    /// Current-device and loaded-function facts qualified before preparation.
    /// `None` is the unchanged ordinary/legacy path.
    pub const fn producer_b2n_runtime_attestation(
        &self,
    ) -> Option<QuotientProducerB2nRuntimeAttestation> {
        self.producer_b2n_attestation
    }
}

fn query_producer_b2n_attestation(
    program: &QuotientProducerB2nProgram,
) -> Result<QuotientProducerB2nRuntimeAttestation, PreparedQuotientError> {
    let device = cuda_device_snapshot()?;
    let sm_arch = device
        .sm_major
        .checked_mul(10)
        .and_then(|major| major.checked_add(device.sm_minor))
        .ok_or(PreparedQuotientError::SizeOverflow)?;

    let mut raw_producer = stwo_backend_cuda_kernels::raw::CudaFunctionAttributes::default();
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_combine_quotients_b2n_init7_function_attributes(
            &mut raw_producer,
        )
    };
    check_cuda("quotient_producer_b2n_function_attributes", code)?;
    let producer_function =
        function_attributes(QuotientProducerB2nKernelRole::Producer, raw_producer)?;

    let continuations: [Result<_, PreparedQuotientError>; 2] =
        [(0, 8), (1, 16)].map(|(ordinal, start_stage)| {
            let mut raw = stwo_backend_cuda_kernels::raw::CudaFunctionAttributes::default();
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_after_first_seven_function_attributes(
                    start_stage,
                    8,
                    &mut raw,
                )
            };
            check_cuda(
                "quotient_producer_b2n_continuation_function_attributes",
                code,
            )?;
            Ok(QuotientProducerB2nLaunchAttestation {
                role: QuotientProducerB2nKernelRole::Continuation,
                ordinal,
                start_stage,
                stages: 8,
                launch_threads: QUOTIENT_PRODUCER_B2N_CONTINUATION_THREADS,
                function: function_attributes(QuotientProducerB2nKernelRole::Continuation, raw)?,
            })
        });
    let [continuation_0, continuation_1] = continuations;
    let attestation = QuotientProducerB2nRuntimeAttestation {
        device_count: device.count,
        current_device: device.current,
        sm_arch,
        producer: QuotientProducerB2nLaunchAttestation {
            role: QuotientProducerB2nKernelRole::Producer,
            ordinal: 0,
            start_stage: 1,
            stages: 7,
            launch_threads: QUOTIENT_PRODUCER_B2N_LAUNCH_THREADS,
            function: producer_function,
        },
        continuations: [continuation_0?, continuation_1?],
    };
    program.qualify_runtime_attestation(&attestation)?;
    Ok(attestation)
}

fn function_attributes(
    role: QuotientProducerB2nKernelRole,
    raw: stwo_backend_cuda_kernels::raw::CudaFunctionAttributes,
) -> Result<QuotientProducerB2nFunctionAttributes, QuotientProducerB2nAttestationError> {
    if raw.reserved != 0 {
        return Err(QuotientProducerB2nAttestationError::FunctionAbiReserved {
            role,
            actual: raw.reserved,
        });
    }
    Ok(QuotientProducerB2nFunctionAttributes {
        abi_version: raw.abi_version,
        max_threads_per_block: raw.max_threads_per_block,
        registers_per_thread: raw.registers_per_thread,
        binary_version: raw.binary_version,
        ptx_version: raw.ptx_version,
        local_bytes: raw.local_bytes,
        static_shared_bytes: raw.static_shared_bytes,
    })
}

fn points_upload(destination: ArenaSlice, constants: &[QuotientSampleConstants]) -> PendingUpload {
    PendingUpload {
        destination,
        descriptor: HostDescriptor::Points(
            constants
                .iter()
                .map(|value| CirclePointSecureField::from(value.sample_point))
                .collect(),
        ),
    }
}

fn secure_upload(destination: ArenaSlice, constants: &[QuotientSampleConstants]) -> PendingUpload {
    PendingUpload {
        destination,
        descriptor: HostDescriptor::Secure(
            constants
                .iter()
                .map(|value| CudaSecureField::from(value.first_linear_term_acc))
                .collect(),
        ),
    }
}

fn coordinate_pointers(values: ArenaSlice, stride: usize) -> Vec<usize> {
    (0..SECURE_COORDINATES)
        .map(|coordinate| unsafe { values.as_u32_ptr().add(coordinate * stride) as usize })
        .collect()
}

fn typed_words<T>(count: usize) -> Result<usize, PreparedQuotientError> {
    core::mem::size_of::<T>()
        .checked_mul(count)
        .and_then(|bytes| bytes.checked_add(WORD_BYTES - 1))
        .map(|bytes| bytes / WORD_BYTES)
        .ok_or(PreparedQuotientError::SizeOverflow)
}

fn pow2(log_size: u32) -> Result<usize, PreparedQuotientError> {
    1usize
        .checked_shl(log_size)
        .ok_or(PreparedQuotientError::SizeOverflow)
}

fn typed_bytes<T>(values: &[T]) -> (*const c_void, usize) {
    (
        values.as_ptr().cast(),
        values.len().saturating_mul(core::mem::size_of::<T>()),
    )
}

fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedQuotientError> {
    truncate_bound_slot(arena.bind(id)?, required_words, alignment_words)
}

/// Validate one bound slot's capacity and alignment, then truncate it to the
/// logical requirement. Pooled slots may be larger than any single logical
/// buffer; END-relative twiddle bases derive from `len_words()` and must
/// never observe the pooled surplus.
fn truncate_bound_slot(
    slice: ArenaSlice,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedQuotientError> {
    if slice.len_words() < required_words {
        return Err(PreparedQuotientError::SlotTooSmall {
            slot: slice.id(),
            required_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedQuotientError::MisalignedSlot {
            slot: slice.id(),
            alignment_words,
        });
    }
    Ok(slice.truncated(required_words))
}

fn upload_and_sync(
    arena: &DeviceArena,
    uploads: &[PendingUpload],
) -> Result<(), PreparedQuotientError> {
    for upload in uploads {
        let (source, bytes) = upload.descriptor.bytes();
        unsafe {
            arena
                .context()
                .memcpy_h2d_async(upload.destination.as_void_ptr(), source, bytes)?;
        }
    }
    arena.context().sync()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use num_traits::{One, Zero};
    use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;
    use stwo::core::fields::cm31::CM31;
    use stwo::core::fields::FieldExpOps;
    use stwo::core::pcs::quotients::denominator_inverses;

    use super::*;

    #[test]
    fn function_attribute_abi_mapping_is_exact_and_reserved_words_fail_closed() {
        let raw = stwo_backend_cuda_kernels::raw::CudaFunctionAttributes {
            abi_version: 1,
            max_threads_per_block: 1_024,
            registers_per_thread: 96,
            binary_version: 90,
            ptx_version: 80,
            reserved: 0,
            local_bytes: 0,
            static_shared_bytes: 33_920,
        };
        assert_eq!(
            function_attributes(QuotientProducerB2nKernelRole::Continuation, raw).unwrap(),
            QuotientProducerB2nFunctionAttributes {
                abi_version: 1,
                max_threads_per_block: 1_024,
                registers_per_thread: 96,
                binary_version: 90,
                ptx_version: 80,
                local_bytes: 0,
                static_shared_bytes: 33_920,
            }
        );
        assert!(matches!(
            function_attributes(
                QuotientProducerB2nKernelRole::Continuation,
                stwo_backend_cuda_kernels::raw::CudaFunctionAttributes { reserved: 1, ..raw }
            ),
            Err(QuotientProducerB2nAttestationError::FunctionAbiReserved { .. })
        ));
    }

    #[test]
    fn bound_slots_truncate_pooled_surplus_to_the_logical_requirement() {
        // Pooled physical slots are sized to the LARGEST epoch-disjoint
        // sharer; the binder must expose only the logical extent so
        // END-relative twiddle bases never shift into the surplus.
        let oversized = ArenaSlice::dangling_for_test(2, 4096);
        let bound = truncate_bound_slot(oversized, 1024, 1).unwrap();
        assert_eq!(bound.len_words(), 1024);
        assert_eq!(bound.id(), oversized.id());
        assert_eq!(bound.as_u32_ptr(), oversized.as_u32_ptr());
        // Undersized slots still fail closed.
        assert!(matches!(
            truncate_bound_slot(ArenaSlice::dangling_for_test(2, 512), 1024, 1),
            Err(PreparedQuotientError::SlotTooSmall { .. })
        ));
    }

    fn config() -> QuotientWorkspaceConfig {
        QuotientWorkspaceConfig {
            lifting_log_size: 8,
            log_blowup_factor: 2,
        }
    }

    fn slots() -> QuotientWorkspaceSlots {
        let mut next = 1u32;
        let mut id = || {
            let value = ArenaSlotId(next);
            next += 1;
            value
        };
        QuotientWorkspaceSlots {
            sample_points: id(),
            first_linear_terms: id(),
            partial_log_sizes: id(),
            partial_coordinate_ptrs: id(),
            subdomain_coordinate_ptrs: id(),
            output_coordinate_ptrs: id(),
            coefficient_sizes: id(),
            subdomain_values: id(),
            output_values: id(),
        }
    }

    #[test]
    fn requirements_match_exact_combine_interpolate_and_fri_layout() {
        let requirements = quotient_workspace_requirements(config(), &[6, 5]).unwrap();
        assert_eq!(requirements.subdomain_log_size, 6);
        assert_eq!(requirements.sample_point_words, 16);
        assert_eq!(requirements.first_linear_term_words, 8);
        assert_eq!(requirements.partial_pointer_words, 8 * POINTER_WORDS);
        assert_eq!(requirements.subdomain_value_words, 4 * 64);
        assert_eq!(requirements.output_value_words, 4 * 256);
        assert_eq!(
            requirements.combine_pass_bytes,
            QuotientCombinePassBytes {
                rows: 64,
                samples: 2,
                denominator_inversions: 128,
                eliminated_scratch_bytes: 1024,
                eliminated_logical_traffic_bytes: 2048,
                denominator_global_passes: 0,
                output_write_bytes: 1024,
            }
        );
        assert_eq!(requirements.forward_twiddle_words, 128);
        assert_eq!(requirements.inverse_twiddle_words, 32);
        assert_eq!(
            requirements
                .arena_slot_requirements(&slots())
                .unwrap()
                .len(),
            9
        );
    }

    #[test]
    fn immediate_denominators_match_materialized_reference_in_canonical_order() {
        let domain = CanonicCoset::new(8).circle_domain();
        let zero = SecureField::from_u32_unchecked(0, 0, 0, 0);
        let mut seed = 0x243f_6a88u32;
        for case in 0..128usize {
            let sample_count = case % 8 + 1;
            let points = (0..sample_count)
                .map(|sample| SECURE_FIELD_CIRCLE_GEN.mul((case + sample + 1) as u128))
                .collect::<Vec<_>>();
            let numerators = (0..sample_count)
                .map(|_| {
                    let mut next = || {
                        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                        seed & 0x3fff_ffff
                    };
                    SecureField::from_u32_unchecked(next(), next(), next(), next())
                })
                .collect::<Vec<_>>();
            let domain_point = domain.at((case * 37) % domain.size());
            let materialized = denominator_inverses(&points, domain_point);
            let expected = numerators
                .iter()
                .zip(materialized)
                .fold(zero, |sum, (numerator, inverse)| {
                    sum + numerator.mul_cm31(inverse)
                });
            let immediate = points
                .iter()
                .zip(&numerators)
                .fold(zero, |sum, (point, numerator)| {
                    let inverse =
                        denominator_inverses(core::slice::from_ref(point), domain_point)[0];
                    sum + numerator.mul_cm31(inverse)
                });
            assert_eq!(immediate, expected, "case {case}");
        }
    }

    fn zero_safe_inverse(value: CM31) -> CM31 {
        if value.is_zero() {
            CM31::zero()
        } else {
            value.inverse()
        }
    }

    fn chunk_batch_inverse(values: &[CM31], chunk_size: usize) -> Vec<CM31> {
        assert!(chunk_size > 0);
        values
            .chunks(chunk_size)
            .flat_map(|chunk| {
                let mut prefixes = vec![CM31::one(); chunk_size];
                for offset in 0..chunk_size {
                    let value = chunk.get(offset).copied().unwrap_or_else(CM31::one);
                    let value = if value.is_zero() { CM31::one() } else { value };
                    prefixes[offset] = if offset == 0 {
                        value
                    } else {
                        prefixes[offset - 1] * value
                    };
                }

                let mut inverse_product = prefixes[chunk_size - 1].inverse();
                for offset in (1..chunk_size).rev() {
                    let value = chunk.get(offset).copied().unwrap_or_else(CM31::one);
                    let normalized = if value.is_zero() { CM31::one() } else { value };
                    let inverse = inverse_product * prefixes[offset - 1];
                    inverse_product *= normalized;
                    prefixes[offset] = if value.is_zero() {
                        CM31::zero()
                    } else {
                        inverse
                    };
                }
                prefixes[0] = if chunk[0].is_zero() {
                    CM31::zero()
                } else {
                    inverse_product
                };
                prefixes.truncate(chunk.len());
                prefixes
            })
            .collect()
    }

    #[test]
    fn chunk_batch_inverse_matches_independent_elementwise_oracle() {
        let mut state = 0x9e37_79b9u32;
        for len in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 19, 31, 32, 33] {
            for case in 0..128usize {
                let values = (0..len)
                    .map(|sample| {
                        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                        let a = state & 0x7fff_ffff;
                        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                        let b = state & 0x7fff_ffff;
                        if (case + sample) % 17 == 0 {
                            CM31::zero()
                        } else {
                            CM31::from_u32_unchecked(a, b)
                        }
                    })
                    .collect::<Vec<_>>();
                let expected = values
                    .iter()
                    .copied()
                    .map(zero_safe_inverse)
                    .collect::<Vec<_>>();
                for chunk_size in [4, 8, 16] {
                    assert_eq!(
                        chunk_batch_inverse(&values, chunk_size),
                        expected,
                        "len {len}, chunk {chunk_size}, case {case}"
                    );
                }
            }
        }
    }

    #[test]
    fn chunk_batched_quotients_preserve_each_rows_canonical_sample_order() {
        let mut state = 0x243f_6a88u32;
        let mut next_u31 = || {
            state = state.wrapping_mul(22_695_477).wrapping_add(1);
            state & 0x3fff_ffff
        };
        for rows in [1, 3, 8, 17] {
            for samples in [1, 3, 4, 5, 8, 9, 19, 32] {
                let denominators = (0..samples)
                    .map(|sample| {
                        (0..rows)
                            .map(|row| {
                                if (sample * rows + row) % 29 == 0 {
                                    CM31::zero()
                                } else {
                                    CM31::from_u32_unchecked(next_u31(), next_u31())
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let numerators = (0..rows)
                    .map(|_| {
                        (0..samples)
                            .map(|_| {
                                SecureField::from_u32_unchecked(
                                    next_u31(),
                                    next_u31(),
                                    next_u31(),
                                    next_u31(),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let batch_coefficients = (0..samples)
                    .map(|_| {
                        SecureField::from_u32_unchecked(
                            next_u31(),
                            next_u31(),
                            next_u31(),
                            next_u31(),
                        )
                    })
                    .collect::<Vec<_>>();
                for chunk_size in [4, 8] {
                    let batched = (0..rows)
                        .map(|row| {
                            let row_denominators = denominators
                                .iter()
                                .map(|column| column[row])
                                .collect::<Vec<_>>();
                            chunk_batch_inverse(&row_denominators, chunk_size)
                        })
                        .collect::<Vec<_>>();

                    for row in 0..rows {
                        let direct_sum = (0..samples).fold(SecureField::zero(), |sum, sample| {
                            sum + numerators[row][sample]
                                .mul_cm31(zero_safe_inverse(denominators[sample][row]))
                        });
                        let batched_sum = (0..samples).fold(SecureField::zero(), |sum, sample| {
                            sum + numerators[row][sample].mul_cm31(batched[row][sample])
                        });
                        assert_eq!(
                            batched_sum, direct_sum,
                            "sum rows {rows}, samples {samples}, chunk {chunk_size}, row {row}"
                        );

                        let direct_horner =
                            (0..samples).fold(SecureField::zero(), |acc, sample| {
                                acc * batch_coefficients[sample]
                                    + numerators[row][sample]
                                        .mul_cm31(zero_safe_inverse(denominators[sample][row]))
                            });
                        let batched_horner =
                            (0..samples).fold(SecureField::zero(), |acc, sample| {
                                acc * batch_coefficients[sample]
                                    + numerators[row][sample].mul_cm31(batched[row][sample])
                            });
                        assert_eq!(
                            batched_horner, direct_horner,
                            "horner rows {rows}, samples {samples}, chunk {chunk_size}, row {row}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn requirements_reject_missing_or_out_of_domain_numerators() {
        assert_eq!(
            quotient_workspace_requirements(config(), &[]).unwrap_err(),
            PreparedQuotientError::EmptySources
        );
        assert_eq!(
            quotient_workspace_requirements(config(), &[7]).unwrap_err(),
            PreparedQuotientError::PartialLogSizeTooLarge {
                source: 0,
                log_size: 7,
                subdomain_log_size: 6
            }
        );
    }

    #[test]
    fn requirements_reject_subdomains_unsupported_by_native_interpolation() {
        for (lifting_log_size, log_blowup_factor, subdomain_log_size) in
            [(2, 1, 1), (3, 1, 2), (4, 2, 2)]
        {
            assert_eq!(
                quotient_workspace_requirements(
                    QuotientWorkspaceConfig {
                        lifting_log_size,
                        log_blowup_factor,
                    },
                    &[1],
                ),
                Err(
                    PreparedQuotientError::UnsupportedNativeInterpolationLogSize(
                        subdomain_log_size,
                    )
                )
            );
        }

        let requirements = quotient_workspace_requirements(
            QuotientWorkspaceConfig {
                lifting_log_size: 4,
                log_blowup_factor: 1,
            },
            &[3],
        )
        .unwrap();
        assert_eq!(requirements.subdomain_log_size, 3);
    }

    #[test]
    fn slot_plan_rejects_aliases() {
        let requirements = quotient_workspace_requirements(config(), &[6]).unwrap();
        let mut slots = slots();
        slots.output_values = slots.subdomain_values;
        assert!(matches!(
            requirements.arena_slot_requirements(&slots),
            Err(PreparedQuotientError::DuplicateSlot(_))
        ));
    }
}
