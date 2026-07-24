//! Device witness generation for the Cairo Pedersen family (witness-on-GPU W3
//! phase 2 — the partial_ec_mul / pedersen_aggregator cohort).
//!
//! Safe wrappers over the `pedersen_witness.cu` kernels. See that file's scope
//! contract: this module provides the reusable interaction/logup primitives
//! (generalized pair-logup and multi-value final-logup) plus the shared device
//! finalize; the per-component fp256 base-trace gadget kernels land on hardware
//! behind the stwo-cairo `STWO_CUDA_WITNESS_VERIFY` differential (they cannot be
//! validated in a no-GPU session and are not shipped here).
//!
//! The `DeviceRawLogupColumn` layout and the finalize lane are shared with the
//! `memory_witness` / `blake_witness` device lanes — byte-identical finalize by
//! construction (same fraction chain, claimed sum, shift, prefix sums).

use stwo::core::fields::qm31::SecureField;

use crate::backend::memory_witness::DeviceRawLogupColumn;
use crate::backend::UploadedDevicePointerVec;
use crate::columns::bindings::{self, CudaSecureField};
use crate::columns::{BaseFieldVec, SecureFieldVec};

fn new_device_raw_column(column_length: usize) -> DeviceRawLogupColumn {
    bindings::ensure_mem_pool_init();
    DeviceRawLogupColumn {
        numerator: std::array::from_fn(|_| BaseFieldVec::new_uninitialized(column_length)),
        denominator: BaseFieldVec::new_uninitialized(4 * column_length),
    }
}

/// One pair-batched logup column: `num = sign0*(d0*m1) + sign1*(d1*m0)`,
/// `den = d0*d1`, with `d_i = combine([rel_i, vals_i...])` over `n_vals` value
/// columns (both tuples share the family arity). `m0`/`m1` are the multiplicity
/// columns (pass the same handle for both when the writer used a single mult).
///
/// The three generated numerator shapes map via the sign pair:
///   `d0*m1 + d1*m0` → `(1, 1)`; `d0*m1 - d1*m0` → `(1, -1)`;
///   `d1*m0 - d0*m1` → `(-1, 1)`.
#[allow(clippy::too_many_arguments)]
pub fn pair_logup(
    vals0: &[&BaseFieldVec],
    rel0: u32,
    vals1: &[&BaseFieldVec],
    rel1: u32,
    m0: &BaseFieldVec,
    m1: &BaseFieldVec,
    sign0: i32,
    sign1: i32,
    column_length: usize,
    alpha_powers: &[SecureField],
    z: SecureField,
) -> DeviceRawLogupColumn {
    let n_vals = vals0.len();
    assert_eq!(n_vals, vals1.len(), "pair tuple arities must match");
    assert!(alpha_powers.len() > n_vals);
    let p0: Vec<*const u32> = vals0.iter().map(|c| c.device_ptr).collect();
    let p1: Vec<*const u32> = vals1.iter().map(|c| c.device_ptr).collect();
    let t0 = UploadedDevicePointerVec::upload(&p0);
    let t1 = UploadedDevicePointerVec::upload(&p1);
    let alphas = SecureFieldVec::from_vec(alpha_powers[..n_vals + 1].to_vec());
    let out = new_device_raw_column(column_length);
    unsafe {
        stwo_backend_cuda_kernels::raw::pedersen_pair_logup(
            t0.as_ptr(),
            rel0,
            t1.as_ptr(),
            rel1,
            n_vals as u32,
            m0.device_ptr,
            m1.device_ptr,
            sign0,
            sign1,
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

/// The final relation logup column: `den = combine([rel, vals...])` over
/// `vals.len()` value columns (`vals.len() + 1` alpha powers), numerator
/// `((neg ? -mult : mult), 0, 0, 0)`.
#[allow(clippy::too_many_arguments)]
pub fn multi_logup(
    vals: &[&BaseFieldVec],
    rel: u32,
    mult: &BaseFieldVec,
    neg_num: bool,
    column_length: usize,
    alpha_powers: &[SecureField],
    z: SecureField,
) -> DeviceRawLogupColumn {
    let n_vals = vals.len();
    assert!(alpha_powers.len() > n_vals);
    let ptrs: Vec<*const u32> = vals.iter().map(|c| c.device_ptr).collect();
    let table = UploadedDevicePointerVec::upload(&ptrs);
    let alphas = SecureFieldVec::from_vec(alpha_powers[..n_vals + 1].to_vec());
    let out = new_device_raw_column(column_length);
    unsafe {
        stwo_backend_cuda_kernels::raw::pedersen_multi_logup(
            table.as_ptr(),
            n_vals as u32,
            rel,
            mult.device_ptr,
            i32::from(neg_num),
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

pub use crate::backend::memory_witness::finalize_device_raw_logup;
