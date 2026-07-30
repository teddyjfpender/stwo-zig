//! Compiled quotient-producer to inverse-NTT boundary.
//!
//! SN2 combines on a log-23 subdomain. The legacy prepared path writes that
//! image and then rereads and rewrites it once per B2N stage. This program owns
//! stages 1..7 in the producer CTA and completes the transform as two 8-stage
//! intervals. Compilation is pure and exact-shape; runtime never probes policy.

use num_traits::Zero;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::denominator_inverses;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::poly::twiddles::TwiddleBuffer;

use super::prepared_quotient::{QuotientSampleConstants, QuotientWorkspaceConfig};

pub const QUOTIENT_PRODUCER_B2N_FIRST_STAGES: u32 = 7;
pub const QUOTIENT_PRODUCER_B2N_LAUNCH_THREADS: u32 = 128;
pub const QUOTIENT_PRODUCER_BATCH_INVERSE_CHUNK: u32 = 8;
pub const QUOTIENT_PRODUCER_B2N_CONTINUATION_THREADS: u32 = 512;
pub const QUOTIENT_PRODUCER_B2N_REQUIRED_SM_ARCH: u32 = 90;
pub const QUOTIENT_PRODUCER_B2N_CONTINUATION_SHARED_CAP: u64 = 34 * 1024;
// Architectural admission policy after the exact current-device SM90 and
// loaded binaryVersion=90 gates pass; this is not observed telemetry.
const SM90_REGISTER_FILE_POLICY: u32 = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientProducerB2nSchedule {
    pub lifting_log_size: u32,
    pub subdomain_log_size: u32,
    pub sample_count: usize,
    pub producer_stages: u32,
    pub continuation_intervals: [u32; 2],
}

impl QuotientProducerB2nSchedule {
    pub const fn is_exact(self) -> bool {
        (self.lifting_log_size == 24 || self.lifting_log_size == 25)
            && self.subdomain_log_size == 23
            && self.sample_count > 0
            && self.producer_stages == QUOTIENT_PRODUCER_B2N_FIRST_STAGES
            && self.continuation_intervals[0] == 8
            && self.continuation_intervals[1] == 8
            && self.producer_stages
                + self.continuation_intervals[0]
                + self.continuation_intervals[1]
                == self.subdomain_log_size
    }
}

/// A fail-closed limit for one exact launch shape. These are admission limits,
/// never claims about what ptxas or the loaded function actually produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientProducerB2nKernelResourcePolicy {
    pub launch_threads: u32,
    pub required_blocks_per_sm: u32,
    pub max_registers_per_thread: u32,
    pub max_local_bytes: u64,
    pub max_static_shared_bytes: u64,
}

/// Exact SM90 policy qualified against runtime-loaded CUDA functions during
/// prepared-graph construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientProducerB2nResourcePolicy {
    pub required_sm_arch: u32,
    pub registers_per_sm: u32,
    pub producer: QuotientProducerB2nKernelResourcePolicy,
    pub continuation: QuotientProducerB2nKernelResourcePolicy,
}

/// Compatibility name for callers that treated this as a policy type. The
/// former observed-looking ptxas/toolkit fields intentionally no longer exist.
pub type QuotientProducerB2nResourceContract = QuotientProducerB2nResourcePolicy;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientProducerB2nFunctionAttributes {
    pub abi_version: u32,
    pub max_threads_per_block: u32,
    pub registers_per_thread: u32,
    pub binary_version: u32,
    pub ptx_version: u32,
    pub local_bytes: u64,
    pub static_shared_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientProducerB2nKernelRole {
    Producer,
    Continuation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientProducerB2nLaunchAttestation {
    pub role: QuotientProducerB2nKernelRole,
    pub ordinal: u32,
    pub start_stage: u32,
    pub stages: u32,
    pub launch_threads: u32,
    pub function: QuotientProducerB2nFunctionAttributes,
}

/// Runtime facts observed from the current device and the three exact launches
/// selected by the production program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientProducerB2nRuntimeAttestation {
    pub device_count: u32,
    pub current_device: u32,
    pub sm_arch: u32,
    pub producer: QuotientProducerB2nLaunchAttestation,
    pub continuations: [QuotientProducerB2nLaunchAttestation; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientProducerB2nAttestationError {
    InvalidDeviceSelection {
        device_count: u32,
        current_device: u32,
    },
    DeviceSmMismatch {
        required: u32,
        actual: u32,
    },
    LaunchMetadataMismatch {
        role: QuotientProducerB2nKernelRole,
        ordinal: u32,
    },
    FunctionAbiVersion {
        role: QuotientProducerB2nKernelRole,
        expected: u32,
        actual: u32,
    },
    FunctionAbiReserved {
        role: QuotientProducerB2nKernelRole,
        actual: u32,
    },
    BinaryVersion {
        role: QuotientProducerB2nKernelRole,
        expected: u32,
        actual: u32,
    },
    MissingPtxVersion {
        role: QuotientProducerB2nKernelRole,
    },
    MaxThreadsPerBlock {
        role: QuotientProducerB2nKernelRole,
        required: u32,
        actual: u32,
    },
    RegistersPerThread {
        role: QuotientProducerB2nKernelRole,
        limit: u32,
        actual: u32,
    },
    LocalMemory {
        role: QuotientProducerB2nKernelRole,
        limit: u64,
        actual: u64,
    },
    StaticSharedMemory {
        role: QuotientProducerB2nKernelRole,
        limit: u64,
        actual: u64,
    },
    ContinuationFunctionsDiffer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientProducerB2nTraffic {
    pub coordinate_image_bytes: u64,
    pub unchanged_partial_read_bytes: u64,
    pub denominator_factors: u64,
    pub batch_inverse_calls: u64,
    pub fallback_logical_bytes: u64,
    pub fused_logical_bytes: u64,
    pub eliminated_logical_bytes: u64,
    pub fallback_kernel_launches: u32,
    pub fused_kernel_launches: u32,
    pub eliminated_kernel_launches: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientProducerB2nReceipt {
    pub schedule: QuotientProducerB2nSchedule,
    pub resources: QuotientProducerB2nResourcePolicy,
    pub traffic: QuotientProducerB2nTraffic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientProducerB2nProgram {
    receipt: QuotientProducerB2nReceipt,
    partial_log_sizes: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotientProducerB2nError {
    UnsupportedShape(QuotientWorkspaceConfig),
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
    PartialLength {
        source: usize,
        expected: usize,
        actual: usize,
    },
    InvalidSchedule,
    SizeOverflow,
}

impl core::fmt::Display for QuotientProducerB2nError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid quotient producer/B2N program: {self:?}")
    }
}

impl std::error::Error for QuotientProducerB2nError {}

impl core::fmt::Display for QuotientProducerB2nAttestationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "unqualified quotient producer/B2N runtime: {self:?}"
        )
    }
}

impl std::error::Error for QuotientProducerB2nAttestationError {}

impl QuotientProducerB2nProgram {
    pub fn compile(
        config: QuotientWorkspaceConfig,
        partial_log_sizes: &[u32],
    ) -> Result<Self, QuotientProducerB2nError> {
        let subdomain_log_size = match (config.lifting_log_size, config.log_blowup_factor) {
            (24, 1) | (25, 2) => 23,
            _ => return Err(QuotientProducerB2nError::UnsupportedShape(config)),
        };
        validate_sources(subdomain_log_size, partial_log_sizes)?;
        let schedule = QuotientProducerB2nSchedule {
            lifting_log_size: config.lifting_log_size,
            subdomain_log_size,
            sample_count: partial_log_sizes.len(),
            producer_stages: QUOTIENT_PRODUCER_B2N_FIRST_STAGES,
            continuation_intervals: [8, 8],
        };
        if !schedule.is_exact() {
            return Err(QuotientProducerB2nError::InvalidSchedule);
        }
        Ok(Self {
            receipt: QuotientProducerB2nReceipt {
                schedule,
                resources: QuotientProducerB2nResourcePolicy {
                    required_sm_arch: QUOTIENT_PRODUCER_B2N_REQUIRED_SM_ARCH,
                    registers_per_sm: SM90_REGISTER_FILE_POLICY,
                    producer: QuotientProducerB2nKernelResourcePolicy {
                        launch_threads: QUOTIENT_PRODUCER_B2N_LAUNCH_THREADS,
                        required_blocks_per_sm: 4,
                        max_registers_per_thread: 128,
                        max_local_bytes: 0,
                        max_static_shared_bytes: 4
                            * u64::from(QUOTIENT_PRODUCER_B2N_LAUNCH_THREADS)
                            * core::mem::size_of::<u32>() as u64,
                    },
                    continuation: QuotientProducerB2nKernelResourcePolicy {
                        launch_threads: QUOTIENT_PRODUCER_B2N_CONTINUATION_THREADS,
                        required_blocks_per_sm: 1,
                        max_registers_per_thread: 128,
                        max_local_bytes: 0,
                        max_static_shared_bytes: QUOTIENT_PRODUCER_B2N_CONTINUATION_SHARED_CAP,
                    },
                },
                traffic: traffic(schedule)?,
            },
            partial_log_sizes: partial_log_sizes.to_vec(),
        })
    }

    pub const fn receipt(&self) -> QuotientProducerB2nReceipt {
        self.receipt
    }

    pub fn matches(&self, config: QuotientWorkspaceConfig, partial_log_sizes: &[u32]) -> bool {
        config.lifting_log_size == self.receipt.schedule.lifting_log_size
            && config.log_blowup_factor
                == self.receipt.schedule.lifting_log_size - self.receipt.schedule.subdomain_log_size
            && partial_log_sizes == self.partial_log_sizes
    }

    /// Validate current-device and loaded-function facts before any prepared
    /// graph upload or launch can select this program.
    pub fn qualify_runtime_attestation(
        &self,
        attestation: &QuotientProducerB2nRuntimeAttestation,
    ) -> Result<(), QuotientProducerB2nAttestationError> {
        let policy = self.receipt.resources;
        if attestation.device_count == 0 || attestation.current_device >= attestation.device_count {
            return Err(
                QuotientProducerB2nAttestationError::InvalidDeviceSelection {
                    device_count: attestation.device_count,
                    current_device: attestation.current_device,
                },
            );
        }
        if attestation.sm_arch != policy.required_sm_arch {
            return Err(QuotientProducerB2nAttestationError::DeviceSmMismatch {
                required: policy.required_sm_arch,
                actual: attestation.sm_arch,
            });
        }

        validate_launch_metadata(
            attestation.producer,
            QuotientProducerB2nKernelRole::Producer,
            0,
            1,
            self.receipt.schedule.producer_stages,
            policy.producer.launch_threads,
        )?;
        validate_function(
            attestation.producer,
            policy.producer,
            policy.required_sm_arch,
            policy.registers_per_sm,
        )?;

        let mut start_stage = self.receipt.schedule.producer_stages + 1;
        for (ordinal, continuation) in attestation.continuations.iter().copied().enumerate() {
            let stages = self.receipt.schedule.continuation_intervals[ordinal];
            validate_launch_metadata(
                continuation,
                QuotientProducerB2nKernelRole::Continuation,
                ordinal as u32,
                start_stage,
                stages,
                policy.continuation.launch_threads,
            )?;
            validate_function(
                continuation,
                policy.continuation,
                policy.required_sm_arch,
                policy.registers_per_sm,
            )?;
            start_stage += stages;
        }
        if attestation.continuations[0].function != attestation.continuations[1].function {
            return Err(QuotientProducerB2nAttestationError::ContinuationFunctionsDiffer);
        }
        Ok(())
    }
}

fn validate_launch_metadata(
    launch: QuotientProducerB2nLaunchAttestation,
    role: QuotientProducerB2nKernelRole,
    ordinal: u32,
    start_stage: u32,
    stages: u32,
    launch_threads: u32,
) -> Result<(), QuotientProducerB2nAttestationError> {
    if launch.role != role
        || launch.ordinal != ordinal
        || launch.start_stage != start_stage
        || launch.stages != stages
        || launch.launch_threads != launch_threads
    {
        return Err(QuotientProducerB2nAttestationError::LaunchMetadataMismatch { role, ordinal });
    }
    Ok(())
}

fn validate_function(
    launch: QuotientProducerB2nLaunchAttestation,
    policy: QuotientProducerB2nKernelResourcePolicy,
    required_binary_version: u32,
    registers_per_sm: u32,
) -> Result<(), QuotientProducerB2nAttestationError> {
    let role = launch.role;
    let function = launch.function;
    if function.abi_version != 1 {
        return Err(QuotientProducerB2nAttestationError::FunctionAbiVersion {
            role,
            expected: 1,
            actual: function.abi_version,
        });
    }
    if function.binary_version != required_binary_version {
        return Err(QuotientProducerB2nAttestationError::BinaryVersion {
            role,
            expected: required_binary_version,
            actual: function.binary_version,
        });
    }
    if function.ptx_version == 0 {
        return Err(QuotientProducerB2nAttestationError::MissingPtxVersion { role });
    }
    if function.max_threads_per_block < policy.launch_threads {
        return Err(QuotientProducerB2nAttestationError::MaxThreadsPerBlock {
            role,
            required: policy.launch_threads,
            actual: function.max_threads_per_block,
        });
    }
    let threads_at_required_occupancy = policy
        .launch_threads
        .checked_mul(policy.required_blocks_per_sm)
        .unwrap_or(u32::MAX);
    let register_envelope_limit = registers_per_sm / threads_at_required_occupancy;
    let register_limit = policy.max_registers_per_thread.min(register_envelope_limit);
    if function.registers_per_thread > register_limit {
        return Err(QuotientProducerB2nAttestationError::RegistersPerThread {
            role,
            limit: register_limit,
            actual: function.registers_per_thread,
        });
    }
    if function.local_bytes > policy.max_local_bytes {
        return Err(QuotientProducerB2nAttestationError::LocalMemory {
            role,
            limit: policy.max_local_bytes,
            actual: function.local_bytes,
        });
    }
    if function.static_shared_bytes > policy.max_static_shared_bytes {
        return Err(QuotientProducerB2nAttestationError::StaticSharedMemory {
            role,
            limit: policy.max_static_shared_bytes,
            actual: function.static_shared_bytes,
        });
    }
    Ok(())
}

fn traffic(
    schedule: QuotientProducerB2nSchedule,
) -> Result<QuotientProducerB2nTraffic, QuotientProducerB2nError> {
    let rows = 1u64
        .checked_shl(schedule.subdomain_log_size)
        .ok_or(QuotientProducerB2nError::SizeOverflow)?;
    let image = rows
        .checked_mul(4)
        .and_then(|words| words.checked_mul(core::mem::size_of::<u32>() as u64))
        .ok_or(QuotientProducerB2nError::SizeOverflow)?;
    let fallback_passes = 1 + 2 * u64::from(schedule.subdomain_log_size);
    let fused_passes = 1 + 2 * schedule.continuation_intervals.len() as u64;
    let fallback_logical_bytes = image
        .checked_mul(fallback_passes)
        .ok_or(QuotientProducerB2nError::SizeOverflow)?;
    let fused_logical_bytes = image
        .checked_mul(fused_passes)
        .ok_or(QuotientProducerB2nError::SizeOverflow)?;
    let fallback_kernel_launches = 1 + schedule.subdomain_log_size;
    let fused_kernel_launches = 1 + schedule.continuation_intervals.len() as u32;
    Ok(QuotientProducerB2nTraffic {
        coordinate_image_bytes: image,
        unchanged_partial_read_bytes: rows
            .checked_mul(schedule.sample_count as u64)
            .and_then(|values| values.checked_mul(4 * core::mem::size_of::<u32>() as u64))
            .ok_or(QuotientProducerB2nError::SizeOverflow)?,
        denominator_factors: rows
            .checked_mul(schedule.sample_count as u64)
            .ok_or(QuotientProducerB2nError::SizeOverflow)?,
        batch_inverse_calls: rows
            .checked_mul(
                (schedule.sample_count as u64)
                    .div_ceil(u64::from(QUOTIENT_PRODUCER_BATCH_INVERSE_CHUNK)),
            )
            .ok_or(QuotientProducerB2nError::SizeOverflow)?,
        fallback_logical_bytes,
        fused_logical_bytes,
        eliminated_logical_bytes: fallback_logical_bytes - fused_logical_bytes,
        fallback_kernel_launches,
        fused_kernel_launches,
        eliminated_kernel_launches: fallback_kernel_launches - fused_kernel_launches,
    })
}

fn validate_sources(
    subdomain_log_size: u32,
    partial_log_sizes: &[u32],
) -> Result<(), QuotientProducerB2nError> {
    if partial_log_sizes.is_empty() {
        return Err(QuotientProducerB2nError::EmptySources);
    }
    u32::try_from(partial_log_sizes.len())
        .map_err(|_| QuotientProducerB2nError::TooManySources(partial_log_sizes.len()))?;
    for (source, &log_size) in partial_log_sizes.iter().enumerate() {
        if log_size > subdomain_log_size {
            return Err(QuotientProducerB2nError::PartialLogSizeTooLarge {
                source,
                log_size,
                subdomain_log_size,
            });
        }
    }
    Ok(())
}

/// Independent scalar oracle for the exact producer boundary. It covers the
/// bit-reversed quotient-domain row, lifted low-log numerator indexing, sample
/// order, and all seven inverse-NTT stages without sharing device code.
pub fn quotient_producer_b2n_oracle(
    config: QuotientWorkspaceConfig,
    constants: &[QuotientSampleConstants],
    partials: &[Vec<SecureField>],
) -> Result<[Vec<u32>; 4], QuotientProducerB2nError> {
    let subdomain_log_size = config
        .lifting_log_size
        .checked_sub(config.log_blowup_factor)
        .ok_or(QuotientProducerB2nError::UnsupportedShape(config))?;
    if subdomain_log_size < QUOTIENT_PRODUCER_B2N_FIRST_STAGES {
        return Err(QuotientProducerB2nError::UnsupportedShape(config));
    }
    let mut logs = Vec::with_capacity(partials.len());
    for (source, values) in partials.iter().enumerate() {
        if values.is_empty() {
            return Err(QuotientProducerB2nError::PartialLength {
                source,
                expected: 1,
                actual: 0,
            });
        }
        logs.push(values.len().ilog2());
    }
    validate_sources(subdomain_log_size, &logs)?;
    if constants.len() != partials.len() {
        return Err(QuotientProducerB2nError::ConstantsCountMismatch {
            expected: partials.len(),
            actual: constants.len(),
        });
    }
    for (source, (values, &log_size)) in partials.iter().zip(&logs).enumerate() {
        let expected = 1usize
            .checked_shl(log_size)
            .ok_or(QuotientProducerB2nError::SizeOverflow)?;
        if values.len() != expected {
            return Err(QuotientProducerB2nError::PartialLength {
                source,
                expected,
                actual: values.len(),
            });
        }
    }

    let eval_domain = CanonicCoset::new(config.lifting_log_size).circle_domain();
    let (domain, _) = eval_domain.split(config.log_blowup_factor);
    let rows = domain.size();
    let sample_points = constants
        .iter()
        .map(|value| value.sample_point)
        .collect::<Vec<CirclePoint<SecureField>>>();
    let mut coordinates: [Vec<BaseField>; 4] = std::array::from_fn(|_| Vec::with_capacity(rows));
    for row in 0..rows {
        let point = domain.at(bit_reverse_index(row, subdomain_log_size));
        let inverses = denominator_inverses(&sample_points, point);
        let quotient = constants
            .iter()
            .zip(partials)
            .zip(&logs)
            .zip(inverses)
            .fold(
                SecureField::zero(),
                |sum, (((constants, partial), &log_size), inverse)| {
                    let ratio = subdomain_log_size - log_size;
                    let lifted = (row >> (ratio + 1) << 1) + (row & 1);
                    let numerator = partial[lifted] - constants.first_linear_term_acc * point.y;
                    sum + numerator.mul_cm31(inverse)
                },
            );
        for (coordinate, value) in quotient.to_m31_array().into_iter().enumerate() {
            coordinates[coordinate].push(value);
        }
    }

    let twiddles = CpuBackend::precompute_twiddles(eval_domain.half_coset)
        .itwiddles
        .extract_subdomain_twiddles(config.lifting_log_size, subdomain_log_size);
    producer_b2n_first_seven_cuda_layout(&mut coordinates, &twiddles);
    Ok(coordinates.map(|values| values.into_iter().map(|value| value.0).collect()))
}

fn producer_b2n_first_seven_cuda_layout(
    coordinates: &mut [Vec<BaseField>; 4],
    twiddles: &[BaseField],
) {
    let rows = coordinates[0].len();
    debug_assert!(coordinates.iter().all(|values| values.len() == rows));
    debug_assert_eq!(rows % QUOTIENT_PRODUCER_B2N_LAUNCH_THREADS as usize, 0);
    let tile_rows = QUOTIENT_PRODUCER_B2N_LAUNCH_THREADS as usize;
    let active_threads = tile_rows / 2;
    let mut layer_size = rows / 2;
    let mut layer_offset = 0usize;
    for stage in 1..=QUOTIENT_PRODUCER_B2N_FIRST_STAGES {
        let stride = 1usize << (stage - 1);
        for tile in 0..rows / tile_rows {
            for local_thread in 0..active_threads {
                let group = local_thread & (stride - 1);
                let pair_in_tile = local_thread >> (stage - 1);
                let left = tile * tile_rows + group + pair_in_tile * 2 * stride;
                let right = left + stride;
                let pair = (tile * active_threads + local_thread) >> (stage - 1);
                let twiddle = if stage == 1 {
                    circle_twiddle(twiddles, pair)
                } else {
                    twiddles[layer_offset + pair]
                };
                for values in &mut *coordinates {
                    let left_value = values[left];
                    let right_value = values[right];
                    values[left] = left_value + right_value;
                    values[right] = (left_value - right_value) * twiddle;
                }
            }
        }
        if stage >= 2 {
            layer_size /= 2;
            layer_offset += layer_size;
        }
    }
}

fn circle_twiddle(twiddles: &[BaseField], index: usize) -> BaseField {
    let pair = index / 4;
    match index % 4 {
        0 => twiddles[2 * pair + 1],
        1 => -twiddles[2 * pair + 1],
        2 => -twiddles[2 * pair],
        _ => twiddles[2 * pair],
    }
}

#[cfg(test)]
mod tests {
    use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;
    use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
    use stwo::prover::poly::BitReversedOrder;

    use super::*;
    use crate::backend::prepared_quotient::quotient_workspace_requirements;

    #[test]
    fn exact_sn2_receipt_removes_twenty_one_launches_and_5_637_gb() {
        let configs = [
            QuotientWorkspaceConfig {
                lifting_log_size: 24,
                log_blowup_factor: 1,
            },
            QuotientWorkspaceConfig {
                lifting_log_size: 25,
                log_blowup_factor: 2,
            },
        ];
        let requirements =
            configs.map(|config| quotient_workspace_requirements(config, &[23; 19]).unwrap());
        assert_eq!(requirements[0].subdomain_log_size, 23);
        assert_ne!(
            requirements[0].half_coset_initial_index,
            requirements[1].half_coset_initial_index
        );
        assert_eq!(
            requirements[0].half_coset_step_size,
            requirements[1].half_coset_step_size
        );
        assert_eq!(
            requirements[0].inverse_twiddle_words,
            requirements[1].inverse_twiddle_words
        );

        let programs =
            configs.map(|config| QuotientProducerB2nProgram::compile(config, &[23; 19]).unwrap());
        let receipt = programs[0].receipt();
        assert!(receipt.schedule.is_exact());
        assert_eq!(receipt.schedule.lifting_log_size, 24);
        assert_eq!(receipt.schedule.subdomain_log_size, 23);
        assert_eq!(programs[1].receipt().schedule.lifting_log_size, 25);
        assert_eq!(programs[1].receipt().traffic, receipt.traffic);
        assert_eq!(programs[1].receipt().resources, receipt.resources);
        assert_eq!(receipt.traffic.coordinate_image_bytes, 134_217_728);
        assert_eq!(receipt.traffic.denominator_factors, 159_383_552);
        assert_eq!(receipt.traffic.batch_inverse_calls, 25_165_824);
        assert_eq!(receipt.traffic.unchanged_partial_read_bytes, 2_550_136_832);
        assert_eq!(receipt.traffic.fallback_logical_bytes, 6_308_233_216);
        assert_eq!(receipt.traffic.fused_logical_bytes, 671_088_640);
        assert_eq!(receipt.traffic.eliminated_logical_bytes, 5_637_144_576);
        assert_eq!(
            (
                receipt.traffic.fallback_kernel_launches,
                receipt.traffic.fused_kernel_launches,
                receipt.traffic.eliminated_kernel_launches,
            ),
            (24, 3, 21)
        );
        assert_eq!(receipt.resources.required_sm_arch, 90);
        assert_eq!(receipt.resources.registers_per_sm, 65_536);
        assert_eq!(receipt.resources.producer.launch_threads, 128);
        assert_eq!(receipt.resources.producer.required_blocks_per_sm, 4);
        assert_eq!(receipt.resources.producer.max_registers_per_thread, 128);
        assert_eq!(receipt.resources.producer.max_static_shared_bytes, 2_048);
        assert_eq!(receipt.resources.continuation.launch_threads, 512);
        assert_eq!(
            receipt.resources.continuation.max_static_shared_bytes,
            34_816
        );
    }

    fn exact_program() -> QuotientProducerB2nProgram {
        QuotientProducerB2nProgram::compile(
            QuotientWorkspaceConfig {
                lifting_log_size: 25,
                log_blowup_factor: 2,
            },
            &[23],
        )
        .unwrap()
    }

    fn function(
        max_threads_per_block: u32,
        registers_per_thread: u32,
        static_shared_bytes: u64,
    ) -> QuotientProducerB2nFunctionAttributes {
        QuotientProducerB2nFunctionAttributes {
            abi_version: 1,
            max_threads_per_block,
            registers_per_thread,
            binary_version: 90,
            ptx_version: 80,
            local_bytes: 0,
            static_shared_bytes,
        }
    }

    fn valid_attestation() -> QuotientProducerB2nRuntimeAttestation {
        let continuation_function = function(1_024, 96, 33_920);
        QuotientProducerB2nRuntimeAttestation {
            device_count: 1,
            current_device: 0,
            sm_arch: 90,
            producer: QuotientProducerB2nLaunchAttestation {
                role: QuotientProducerB2nKernelRole::Producer,
                ordinal: 0,
                start_stage: 1,
                stages: 7,
                launch_threads: 128,
                function: function(128, 98, 2_048),
            },
            continuations: [
                QuotientProducerB2nLaunchAttestation {
                    role: QuotientProducerB2nKernelRole::Continuation,
                    ordinal: 0,
                    start_stage: 8,
                    stages: 8,
                    launch_threads: 512,
                    function: continuation_function,
                },
                QuotientProducerB2nLaunchAttestation {
                    role: QuotientProducerB2nKernelRole::Continuation,
                    ordinal: 1,
                    start_stage: 16,
                    stages: 8,
                    launch_threads: 512,
                    function: continuation_function,
                },
            ],
        }
    }

    fn rejected(
        mutate: impl FnOnce(&mut QuotientProducerB2nRuntimeAttestation),
    ) -> QuotientProducerB2nAttestationError {
        let mut attestation = valid_attestation();
        mutate(&mut attestation);
        exact_program()
            .qualify_runtime_attestation(&attestation)
            .unwrap_err()
    }

    #[test]
    fn exact_runtime_attestation_is_qualified() {
        exact_program()
            .qualify_runtime_attestation(&valid_attestation())
            .unwrap();
    }

    #[test]
    fn runtime_attestation_rejects_device_and_launch_metadata_mutations() {
        for error in [
            rejected(|value| value.device_count = 0),
            rejected(|value| value.current_device = value.device_count),
        ] {
            assert!(matches!(
                error,
                QuotientProducerB2nAttestationError::InvalidDeviceSelection { .. }
            ));
        }
        assert!(matches!(
            rejected(|value| value.sm_arch = 89),
            QuotientProducerB2nAttestationError::DeviceSmMismatch { .. }
        ));

        for error in [
            rejected(|value| value.producer.role = QuotientProducerB2nKernelRole::Continuation),
            rejected(|value| value.producer.ordinal = 1),
            rejected(|value| value.producer.start_stage = 2),
            rejected(|value| value.producer.stages = 6),
            rejected(|value| value.producer.launch_threads = 127),
            rejected(|value| value.continuations[0].ordinal = 1),
            rejected(|value| value.continuations[1].start_stage = 15),
            rejected(|value| value.continuations[1].stages = 7),
            rejected(|value| value.continuations[1].launch_threads = 256),
        ] {
            assert!(matches!(
                error,
                QuotientProducerB2nAttestationError::LaunchMetadataMismatch { .. }
            ));
        }
    }

    #[test]
    fn runtime_attestation_rejects_every_loaded_function_resource_mutation() {
        assert!(matches!(
            rejected(|value| value.producer.function.abi_version = 0),
            QuotientProducerB2nAttestationError::FunctionAbiVersion { .. }
        ));
        assert!(matches!(
            rejected(|value| value.producer.function.binary_version = 89),
            QuotientProducerB2nAttestationError::BinaryVersion { .. }
        ));
        assert!(matches!(
            rejected(|value| value.producer.function.ptx_version = 0),
            QuotientProducerB2nAttestationError::MissingPtxVersion { .. }
        ));
        assert!(matches!(
            rejected(|value| value.producer.function.max_threads_per_block = 127),
            QuotientProducerB2nAttestationError::MaxThreadsPerBlock { .. }
        ));
        assert!(matches!(
            rejected(|value| value.producer.function.registers_per_thread = 129),
            QuotientProducerB2nAttestationError::RegistersPerThread { .. }
        ));
        assert!(matches!(
            rejected(|value| value.producer.function.local_bytes = 1),
            QuotientProducerB2nAttestationError::LocalMemory { .. }
        ));
        assert!(matches!(
            rejected(|value| value.producer.function.static_shared_bytes = 2_049),
            QuotientProducerB2nAttestationError::StaticSharedMemory { .. }
        ));

        assert!(matches!(
            rejected(|value| { value.continuations[1].function.max_threads_per_block = 511 }),
            QuotientProducerB2nAttestationError::MaxThreadsPerBlock { .. }
        ));
        assert!(matches!(
            rejected(|value| value.continuations[1].function.registers_per_thread = 129),
            QuotientProducerB2nAttestationError::RegistersPerThread { .. }
        ));
        assert!(matches!(
            rejected(|value| value.continuations[1].function.local_bytes = 1),
            QuotientProducerB2nAttestationError::LocalMemory { .. }
        ));
        assert!(matches!(
            rejected(|value| value.continuations[1].function.static_shared_bytes = 34_817),
            QuotientProducerB2nAttestationError::StaticSharedMemory { .. }
        ));
    }

    #[test]
    fn continuation_attestations_have_distinct_metadata_but_identical_functions() {
        let attestation = valid_attestation();
        assert_ne!(
            attestation.continuations[0].ordinal,
            attestation.continuations[1].ordinal
        );
        assert_ne!(
            attestation.continuations[0].start_stage,
            attestation.continuations[1].start_stage
        );
        assert_eq!(
            attestation.continuations[0].function,
            attestation.continuations[1].function
        );
        assert!(matches!(
            rejected(|value| value.continuations[1].function.ptx_version = 81),
            QuotientProducerB2nAttestationError::ContinuationFunctionsDiffer
        ));
    }

    #[test]
    fn compilation_fails_closed_outside_the_registered_shape() {
        for config in [
            QuotientWorkspaceConfig {
                lifting_log_size: 24,
                log_blowup_factor: 2,
            },
            QuotientWorkspaceConfig {
                lifting_log_size: 25,
                log_blowup_factor: 1,
            },
        ] {
            assert!(matches!(
                QuotientProducerB2nProgram::compile(config, &[23]),
                Err(QuotientProducerB2nError::UnsupportedShape(_))
            ));
        }
        let config = QuotientWorkspaceConfig {
            lifting_log_size: 25,
            log_blowup_factor: 2,
        };
        assert_eq!(
            QuotientProducerB2nProgram::compile(config, &[]),
            Err(QuotientProducerB2nError::EmptySources)
        );
        assert!(matches!(
            QuotientProducerB2nProgram::compile(config, &[24]),
            Err(QuotientProducerB2nError::PartialLogSizeTooLarge { .. })
        ));
    }

    #[test]
    fn scalar_oracle_matches_the_independent_cpu_inverse_transform() {
        for config in [
            QuotientWorkspaceConfig {
                lifting_log_size: 8,
                log_blowup_factor: 1,
            },
            QuotientWorkspaceConfig {
                lifting_log_size: 9,
                log_blowup_factor: 2,
            },
        ] {
            assert_scalar_oracle_matches_cpu(config);
        }
    }

    fn assert_scalar_oracle_matches_cpu(config: QuotientWorkspaceConfig) {
        let constants = [
            QuotientSampleConstants {
                sample_point: SECURE_FIELD_CIRCLE_GEN.mul(3),
                first_linear_term_acc: SecureField::from_u32_unchecked(2, 3, 5, 7),
            },
            QuotientSampleConstants {
                sample_point: SECURE_FIELD_CIRCLE_GEN.mul(11),
                first_linear_term_acc: SecureField::from_u32_unchecked(13, 17, 19, 23),
            },
        ];
        let logs = [7u32, 5];
        let partials = logs
            .iter()
            .enumerate()
            .map(|(source, &log_size)| {
                (0..1usize << log_size)
                    .map(|row| {
                        let value = (source as u32 + 1) * 65_537 + row as u32 * 257;
                        SecureField::from_u32_unchecked(value, value + 1, value + 2, value + 3)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let oracle = quotient_producer_b2n_oracle(config, &constants, &partials).unwrap();

        let eval_domain = CanonicCoset::new(config.lifting_log_size).circle_domain();
        let (domain, _) = eval_domain.split(config.log_blowup_factor);
        let full_twiddles = CpuBackend::precompute_twiddles(eval_domain.half_coset);
        let inverse_twiddles = full_twiddles
            .itwiddles
            .extract_subdomain_twiddles(config.lifting_log_size, domain.log_size());
        let tree = stwo::prover::poly::twiddles::TwiddleTree {
            root_coset: domain.half_coset,
            twiddles: Vec::new(),
            itwiddles: inverse_twiddles,
        };

        let sample_points = constants
            .iter()
            .map(|value| value.sample_point)
            .collect::<Vec<_>>();
        let mut rows: [Vec<BaseField>; 4] = std::array::from_fn(|_| Vec::new());
        for row in 0..domain.size() {
            let point = domain.at(bit_reverse_index(row, domain.log_size()));
            let inverses = denominator_inverses(&sample_points, point);
            let quotient = constants
                .iter()
                .zip(&partials)
                .zip(logs)
                .zip(inverses)
                .fold(
                    SecureField::zero(),
                    |sum, (((constants, partial), log), inverse)| {
                        let ratio = domain.log_size() - log;
                        let lifted = (row >> (ratio + 1) << 1) + (row & 1);
                        sum + (partial[lifted] - constants.first_linear_term_acc * point.y)
                            .mul_cm31(inverse)
                    },
                );
            for (coordinate, value) in quotient.to_m31_array().into_iter().enumerate() {
                rows[coordinate].push(value);
            }
        }
        let scale = BaseField::from_u32_unchecked(domain.size() as u32).inverse();
        for coordinate in 0..4 {
            let expected = CircleEvaluation::<CpuBackend, BaseField, BitReversedOrder>::new(
                domain,
                rows[coordinate].clone(),
            )
            .interpolate_with_twiddles(&tree)
            .coeffs;
            let actual = oracle[coordinate]
                .iter()
                .copied()
                .map(BaseField::from_u32_unchecked)
                .map(|value| value * scale)
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "coordinate {coordinate}");
        }
    }

    #[test]
    fn cuda_layout_oracle_covers_multiple_producer_ctas() {
        let lifting_log_size = 11;
        let subdomain_log_size = 9;
        let rows = 1usize << subdomain_log_size;
        let eval_domain = CanonicCoset::new(lifting_log_size).circle_domain();
        let twiddles = CpuBackend::precompute_twiddles(eval_domain.half_coset)
            .itwiddles
            .extract_subdomain_twiddles(lifting_log_size, subdomain_log_size);
        let input: [Vec<BaseField>; 4] = std::array::from_fn(|coordinate| {
            (0..rows)
                .map(|row| BaseField::from_u32_unchecked((coordinate * rows + row + 1) as u32))
                .collect()
        });

        let mut expected = input.clone();
        let mut layer_size = rows / 2;
        let mut layer_offset = 0usize;
        for stage in 1..=QUOTIENT_PRODUCER_B2N_FIRST_STAGES {
            let stride = 1usize << (stage - 1);
            for gid in 0..rows / 2 {
                let group = gid & (stride - 1);
                let pair = gid >> (stage - 1);
                let left = group + pair * 2 * stride;
                let right = left + stride;
                let twiddle = if stage == 1 {
                    circle_twiddle(&twiddles, pair)
                } else {
                    twiddles[layer_offset + pair]
                };
                for values in &mut expected {
                    let left_value = values[left];
                    let right_value = values[right];
                    values[left] = left_value + right_value;
                    values[right] = (left_value - right_value) * twiddle;
                }
            }
            if stage >= 2 {
                layer_size /= 2;
                layer_offset += layer_size;
            }
        }

        let mut actual = input;
        producer_b2n_first_seven_cuda_layout(&mut actual, &twiddles);
        assert_eq!(actual, expected);
    }
}
