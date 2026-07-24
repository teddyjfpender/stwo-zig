//! Device witness generation for the Cairo memory tables (witness-on-GPU P1).
//!
//! Safe wrappers over the `memory_witness.cu` kernels plus the device-resident
//! logup finalize: the stwo-cairo memory component calls these to generate its
//! base limb columns, feed the rc_9_9 multiplicity counts, and produce its logup
//! interaction columns entirely on device — no host columns, no `lookup_data`.
//!
//! Every formula is a port of the generated SIMD writer (see the spec in the
//! stwo-cairo fork's `gpu_benchmarks/WITNESS_ON_GPU.md`); the authoritative gates
//! are the component differential (`STWO_CUDA_WITNESS_VERIFY`) and the Cairo e2e
//! proof byte-equality, both in stwo-cairo.

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

use crate::backend::{CudaBackend, UploadedDevicePointerVec};
use crate::columns::base_field_vec::BaseFieldVec;
use crate::columns::bindings::{self, CudaSecureField};
use crate::{CudaLaunchContext, CudaRuntimeError};

/// A logup column whose raw inputs already live on the device: numerator
/// coordinate columns plus element-major qm31 denominators. The device-native
/// counterpart of `stwo-constraint-framework`'s `RawLogupColumn`.
pub struct DeviceRawLogupColumn {
    pub numerator: [BaseFieldVec; 4],
    /// `4 * len` words: element-major qm31 denominators.
    pub denominator: BaseFieldVec,
}

/// Splits a device-resident f252 value table (8 u32 words per value, row-major)
/// into 28 9-bit limb columns of `column_length` (zero-padded past `n_values`).
pub fn limb_split_big(
    values: &BaseFieldVec,
    n_values: usize,
    column_length: usize,
) -> Vec<BaseFieldVec> {
    limb_split(values, n_values, column_length, 28, true)
}

/// Small-value variant: 4 words (u128 LE) per value into 8 limb columns.
pub fn limb_split_small(
    values: &BaseFieldVec,
    n_values: usize,
    column_length: usize,
) -> Vec<BaseFieldVec> {
    limb_split(values, n_values, column_length, 8, false)
}

/// Arena-native big-memory writer: the 28 limb columns and multiplicity column
/// are final borrowed BaseTrace destinations. The launch is allocation-free and
/// stream-explicit; `mults` already includes zero padding to `column_length`.
pub fn limb_split_big_into_on(
    values: &BaseFieldVec,
    n_values: usize,
    column_length: usize,
    mults: &[u32],
    trace: &[BaseFieldVec],
    context: CudaLaunchContext,
) -> Result<(), CudaRuntimeError> {
    limb_split_into_on(
        values,
        n_values,
        column_length,
        mults,
        trace,
        28,
        true,
        context,
    )
}

/// Arena-native small-memory counterpart of [`limb_split_big_into_on`].
pub fn limb_split_small_into_on(
    values: &BaseFieldVec,
    n_values: usize,
    column_length: usize,
    mults: &[u32],
    trace: &[BaseFieldVec],
    context: CudaLaunchContext,
) -> Result<(), CudaRuntimeError> {
    limb_split_into_on(
        values,
        n_values,
        column_length,
        mults,
        trace,
        8,
        false,
        context,
    )
}

#[allow(clippy::too_many_arguments)]
fn limb_split_into_on(
    values: &BaseFieldVec,
    n_values: usize,
    column_length: usize,
    mults: &[u32],
    trace: &[BaseFieldVec],
    n_limbs: usize,
    big: bool,
    context: CudaLaunchContext,
) -> Result<(), CudaRuntimeError> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(CudaRuntimeError::Unavailable);
    }
    let required_input_words = n_values.checked_mul(if big { 8 } else { 4 });
    if trace.len() != n_limbs + 1
        || trace.iter().any(|column| column.size != column_length)
        || mults.len() != column_length
        || n_values > column_length
        || required_input_words.is_none_or(|required| required > values.size)
    {
        return Err(CudaRuntimeError::Cuda {
            operation: "memory_limb_split_into_on_geometry",
            code: -1,
        });
    }
    let limb_ptrs: Vec<*mut u32> = trace[..n_limbs]
        .iter()
        .map(|column| column.device_ptr.cast_mut())
        .collect();
    let args = (
        values.device_ptr,
        u32::try_from(n_values).map_err(|_| CudaRuntimeError::SizeOverflow)?,
        u32::try_from(column_length).map_err(|_| CudaRuntimeError::SizeOverflow)?,
        limb_ptrs.as_ptr(),
        mults.as_ptr(),
        trace[n_limbs].device_ptr.cast_mut(),
        context.stream_raw().as_ptr(),
    );
    let code = unsafe {
        if big {
            stwo_backend_cuda_kernels::raw::memory_limb_split_big_into_on(
                args.0, args.1, args.2, args.3, args.4, args.5, args.6,
            )
        } else {
            stwo_backend_cuda_kernels::raw::memory_limb_split_small_into_on(
                args.0, args.1, args.2, args.3, args.4, args.5, args.6,
            )
        }
    };
    if code == 0 {
        Ok(())
    } else {
        Err(CudaRuntimeError::Cuda {
            operation: if big {
                "memory_limb_split_big_into_on"
            } else {
                "memory_limb_split_small_into_on"
            },
            code,
        })
    }
}

fn limb_split(
    values: &BaseFieldVec,
    n_values: usize,
    column_length: usize,
    n_limbs: usize,
    big: bool,
) -> Vec<BaseFieldVec> {
    bindings::ensure_mem_pool_init();
    let cols: Vec<BaseFieldVec> = (0..n_limbs)
        .map(|_| BaseFieldVec::new_uninitialized(column_length))
        .collect();
    let ptrs: Vec<*const u32> = cols.iter().map(|c| c.device_ptr).collect();
    let table = UploadedDevicePointerVec::upload(&ptrs);
    unsafe {
        if big {
            stwo_backend_cuda_kernels::raw::memory_limb_split_big(
                values.device_ptr,
                n_values as u32,
                column_length as u32,
                table.as_ptr(),
            );
        } else {
            stwo_backend_cuda_kernels::raw::memory_limb_split_small(
                values.device_ptr,
                n_values as u32,
                column_length as u32,
                table.as_ptr(),
            );
        }
    }
    cols
}

/// Counts the rc_9_9 inputs fed by `limb_cols` (pairs (2j, 2j+1), relation index
/// j % 8 — padding rows included, matching the host loop) into 8 relation-indexed
/// count tables, and returns them to the host for merging into the rc state's
/// atomic multiplicity columns. `input_to_row_lut` is the dense
/// `(v0 << 9 | v1) -> rc row` map derived from the rc table's preprocessed layout.
pub fn rc99_count(
    limb_cols: &[BaseFieldVec],
    column_length: usize,
    input_to_row_lut: &[u32],
    rc_table_size: usize,
) -> Vec<u32> {
    assert_eq!(input_to_row_lut.len(), 1 << 18);
    assert!(limb_cols.len().is_multiple_of(2));
    let n_pairs = limb_cols.len() / 2;
    let ptrs: Vec<*const u32> = limb_cols.iter().map(|c| c.device_ptr).collect();
    let table = UploadedDevicePointerVec::upload(&ptrs);
    let lut_dev = unsafe {
        bindings::copy_uint32_t_vec_from_host_to_device(
            input_to_row_lut.as_ptr(),
            input_to_row_lut.len() as u32,
        )
    };
    let lut = BaseFieldVec::new(lut_dev, input_to_row_lut.len());
    let counts = BaseFieldVec::new_zeroes(8 * rc_table_size);
    unsafe {
        stwo_backend_cuda_kernels::raw::memory_rc99_count(
            table.as_ptr(),
            n_pairs as u32,
            column_length as u32,
            lut.device_ptr,
            rc_table_size as u32,
            counts.device_ptr.cast_mut(),
        );
    }
    // Synchronous D2H readback (the fence); the caller adds into the host atomics.
    counts.to_vec().into_iter().map(|f| f.0).collect()
}

/// The final memory-relation logup column for one segment:
/// `denom = combine([relation_id, (offset + row) | tag, limbs...])`,
/// numerator `(-mult, 0, 0, 0)`.
#[allow(clippy::too_many_arguments)]
pub fn memory_logup_inputs(
    limb_cols: &[BaseFieldVec],
    mults: &BaseFieldVec,
    relation_id: u32,
    id_offset: u32,
    id_tag: u32,
    column_length: usize,
    alpha_powers: &[SecureField],
    z: SecureField,
) -> DeviceRawLogupColumn {
    assert!(alpha_powers.len() >= limb_cols.len() + 2);
    let ptrs: Vec<*const u32> = limb_cols.iter().map(|c| c.device_ptr).collect();
    let table = UploadedDevicePointerVec::upload(&ptrs);
    let alphas = crate::columns::SecureFieldVec::from_vec(alpha_powers.to_vec());
    let out = new_device_raw_column(column_length);
    unsafe {
        stwo_backend_cuda_kernels::raw::memory_logup_inputs(
            table.as_ptr(),
            limb_cols.len() as u32,
            mults.device_ptr,
            relation_id,
            id_offset,
            id_tag,
            column_length as u32,
            alphas.device_ptr,
            CudaSecureField::from(z).into_raw(),
            out.denominator.device_ptr,
            out.numerator[0].device_ptr,
            out.numerator[1].device_ptr,
            out.numerator[2].device_ptr,
            out.numerator[3].device_ptr,
        );
    }
    out
}

/// One pair-batched rc_9_9 logup column: `num = d0 + d1`, `den = d0 * d1` with
/// `d_i = combine([rel_id_i, limb_a, limb_b])`.
#[allow(clippy::too_many_arguments)]
pub fn memory_rc_pair_logup(
    limbs: [&BaseFieldVec; 4],
    rel_id0: u32,
    rel_id1: u32,
    column_length: usize,
    alpha_powers: &[SecureField],
    z: SecureField,
) -> DeviceRawLogupColumn {
    assert!(alpha_powers.len() >= 3);
    let alphas = crate::columns::SecureFieldVec::from_vec(alpha_powers[..3].to_vec());
    let out = new_device_raw_column(column_length);
    unsafe {
        stwo_backend_cuda_kernels::raw::memory_rc_pair_logup(
            limbs[0].device_ptr,
            limbs[1].device_ptr,
            limbs[2].device_ptr,
            limbs[3].device_ptr,
            rel_id0,
            rel_id1,
            column_length as u32,
            alphas.device_ptr,
            CudaSecureField::from(z).into_raw(),
            out.denominator.device_ptr,
            out.numerator[0].device_ptr,
            out.numerator[1].device_ptr,
            out.numerator[2].device_ptr,
            out.numerator[3].device_ptr,
        );
    }
    out
}

fn new_device_raw_column(column_length: usize) -> DeviceRawLogupColumn {
    bindings::ensure_mem_pool_init();
    DeviceRawLogupColumn {
        numerator: std::array::from_fn(|_| BaseFieldVec::new_uninitialized(column_length)),
        denominator: BaseFieldVec::new_uninitialized(4 * column_length),
    }
}

/// Finalizes device-resident raw logup columns: identical math to
/// [`super::logup::finalize_raw_logup`] (fraction chain, claimed sum, shift,
/// prefix sums) without any host-to-device transfer — the inputs were born here.
pub fn finalize_device_raw_logup(
    log_size: u32,
    columns: Vec<DeviceRawLogupColumn>,
) -> (
    Vec<CircleEvaluation<CudaBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let size = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();

    let mut finalized: Vec<[BaseFieldVec; 4]> = Vec::with_capacity(columns.len());
    for column in columns {
        let prev = finalized.last();
        unsafe {
            stwo_backend_cuda_kernels::raw::logup_fraction_chain_dense(
                column.numerator[0].device_ptr,
                column.numerator[1].device_ptr,
                column.numerator[2].device_ptr,
                column.numerator[3].device_ptr,
                column.denominator.device_ptr,
                prev.map_or(std::ptr::null(), |p| p[0].device_ptr),
                prev.map_or(std::ptr::null(), |p| p[1].device_ptr),
                prev.map_or(std::ptr::null(), |p| p[2].device_ptr),
                prev.map_or(std::ptr::null(), |p| p[3].device_ptr),
                size as u32,
            );
        }
        finalized.push(column.numerator);
    }

    let last = finalized.last().expect("device raw logup trace is empty");
    let claimed_sum: SecureField = unsafe {
        bindings::logup_sum_secure_coords(
            last[0].device_ptr,
            last[1].device_ptr,
            last[2].device_ptr,
            last[3].device_ptr,
            size as u32,
        )
    }
    .into();
    let cumsum_shift = claimed_sum / BaseField::from_u32_unchecked(1 << log_size);
    unsafe {
        bindings::logup_shift_secure_coords(
            last[0].device_ptr,
            last[1].device_ptr,
            last[2].device_ptr,
            last[3].device_ptr,
            cumsum_shift.into(),
            size as u32,
        );
        // P3: the four coordinate scans are independent — they run on the pool
        // streams with event bridges to the legacy stream on both sides.
        stwo_backend_cuda_kernels::raw::inclusive_prefix_sum_x4(
            last[0].device_ptr,
            last[1].device_ptr,
            last[2].device_ptr,
            last[3].device_ptr,
            size as u32,
        );
    }

    let trace = finalized
        .into_iter()
        .flat_map(|coords| coords.map(|col| CircleEvaluation::new(domain, col)))
        .collect();
    (trace, claimed_sum)
}
