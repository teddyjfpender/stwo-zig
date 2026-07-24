#![allow(dead_code)] // ported intact from the stwo-cuda prototype
use std::ffi::c_void;

use num_traits::One;
use stwo::core::circle::{CirclePoint, CirclePointIndex, Coset};
use stwo::core::constraints::{coset_vanishing, coset_vanishing_derivative};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::{CanonicCoset, CircleDomain};
use stwo::core::poly::line::LineDomain;
use stwo::core::poly::utils::get_folding_alphas;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::fri::FriOps;
use stwo::prover::poly::circle::{
    CircleCoefficients as CirclePoly, CircleEvaluation, PolyOps, SecureEvaluation,
};
use stwo::prover::poly::twiddles::TwiddleTree;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::secure_column::SecureColumnByCoords;

use crate::backend::{CudaBackend, UploadedDevicePointerVec};
use crate::columns::bindings::CudaSecureField;

/// CUDA caps `grid.y` and `grid.z` at 65535 (`maxGridSize[1]`/`[2]`). The batched NTT
/// launchers (`ntt_n2b_columns`, `ntt_b2n_column`) map the column (batch) axis onto
/// `grid.y`/`grid.z`, so a same-`log_size` column group larger than this overflows the
/// launch configuration (observed as an `invalid argument` failure in `rfft.cu` when
/// proving 14M-step PIEs). Columns transform independently, so a group is split into
/// contiguous chunks of at most this many columns. Mirrors `MAX_NTT_BATCH_COLUMNS` in
/// the CUDA launchers; the CUDA side re-applies the same tiling defensively.
const MAX_NTT_BATCH_COLUMNS: usize = 65535;

/// Partition `num_poly` columns into contiguous `(offset, len)` chunks of at most
/// `max` columns each. Pure launch-geometry arithmetic (no device state); see
/// [`MAX_NTT_BATCH_COLUMNS`]. `num_poly <= max` yields a single `(0, num_poly)` chunk,
/// so the common case is unchanged.
fn ntt_batch_chunks(num_poly: usize, max: usize) -> impl Iterator<Item = (usize, usize)> {
    assert!(max > 0, "chunk size must be positive");
    (0..num_poly)
        .step_by(max)
        .map(move |base| (base, core::cmp::min(max, num_poly - base)))
}

pub trait CudaVariable<T> {
    /// # Safety
    /// do not dereference if the memory is located on the device
    unsafe fn as_ref(&self) -> &T;

    fn as_ptr(&self) -> *const T {
        unsafe { self.as_ref() }
    }

    fn as_c_void_ptr(&self) -> *const c_void {
        self.as_ptr() as *const c_void
    }
}

pub trait CudaVariableMut<T>: CudaVariable<T> {
    /// # Safety
    /// do not dereference if the memory is located on the device
    unsafe fn as_mut(&mut self) -> &mut T;

    fn as_mut_ptr(&mut self) -> *mut T {
        unsafe { self.as_mut() }
    }

    fn as_mut_c_void_ptr(&mut self) -> *mut c_void {
        self.as_mut_ptr() as *mut c_void
    }
}

impl<T> CudaVariable<T> for T {
    unsafe fn as_ref(&self) -> &T {
        self
    }
}

impl<T> CudaVariableMut<T> for T {
    unsafe fn as_mut(&mut self) -> &mut T {
        self
    }
}

use stwo::prover::backend::cpu::CpuCirclePoly;

use crate::columns as interface;
use crate::columns::base_field_vec::BaseFieldVec;
use crate::columns::SecureFieldVec;
pub(crate) type CudaCircleEvaluation<F, EvalOrder> = CircleEvaluation<CudaBackend, F, EvalOrder>;
// fn interpolate_native(
//     eval: CircleEvaluation<CudaBackend, BaseField, BitReversedOrder>,
//     twiddle_tree: &TwiddleTree<CudaBackend>,
// ) -> CirclePoly<CudaBackend> {
//     let values = eval.values;
//     assert!(eval.domain.half_coset.is_doubling_of(twiddle_tree.root_coset));
//     unsafe {
//         interface::bindings::interpolate(
//             eval.domain.half_coset.size() as u32,
//             values.device_ptr,
//             twiddle_tree.itwiddles.device_ptr,
//             twiddle_tree.itwiddles.len() as u32,
//             values.len() as u32,
//         );
//     }

//     CirclePoly::new(values)
// }

// fn interpolate_columns_native(
//     columns: impl IntoIterator<Item = CircleEvaluation<CudaBackend, BaseField,
// BitReversedOrder>>,     twiddles: &TwiddleTree<CudaBackend>,
// ) -> Vec<CirclePoly<CudaBackend>> {
//     let columns = columns.into_iter().collect_vec();
//     let values = columns
//         .iter()
//         .map(|column| column.values.device_ptr)
//         .collect_vec();
//     let number_of_rows = columns[0].len();
//     unsafe {
//         interface::bindings::interpolate_columns(
//             columns[0].domain.half_coset.size() as u32,
//             values.as_ptr(),
//             twiddles.itwiddles.device_ptr,
//             twiddles.itwiddles.len() as u32,
//             columns.len() as u32,
//             number_of_rows as u32,
//         );
//     }

//     columns
//         .into_iter()
//         .map(|column| CirclePoly::new(column.values))
//         .collect_vec()
// }

use stwo::prover::backend::cpu::CpuCircleEvaluation;

/// Evaluate multiple same-size polynomials at the same point using a single batched CUDA call.
/// All polynomials must have the same coeffs_size.
/// Only the array of device pointers is copied to the GPU — the polynomial data stays in place.
/// Returns a Vec<SecureField> with one result per polynomial.
pub fn cuda_batch_eval_at_point(
    polys: &[&CirclePoly<CudaBackend>],
    point: CirclePoint<SecureField>,
) -> Vec<SecureField> {
    let num_polys = polys.len();
    if num_polys == 0 {
        return Vec::new();
    }

    // Collect device pointers from each polynomial (these are already GPU addresses)
    let host_ptrs: Vec<*const u32> = polys.iter().map(|p| p.coeffs.device_ptr).collect();
    let coeffs_size = polys[0].coeffs.len();

    // Upload only the pointer array to device (num_polys * 8 bytes, not the data)
    let device_ptrs = UploadedDevicePointerVec::upload(&host_ptrs);

    // Allocate host result buffer
    let mut results: Vec<CudaSecureField> =
        (0..num_polys).map(|_| CudaSecureField::zero()).collect();

    unsafe {
        interface::bindings::batch_eval_at_points(
            device_ptrs.as_ptr(),
            coeffs_size as i32,
            num_polys as i32,
            CudaSecureField::from(point.x),
            CudaSecureField::from(point.y),
            results.as_mut_ptr(),
        );
    }

    results.into_iter().map(SecureField::from).collect()
}

/// Downloads a device twiddle tree into a CPU-backend tree (small-domain fallbacks).
/// NEVER transmute between `TwiddleTree<CudaBackend>` and `TwiddleTree<CpuBackend>`:
/// their `Twiddles` types have different layouts (device pointer struct vs `Vec`).
fn to_cpu_twiddle_tree(
    twiddles: &stwo::prover::poly::twiddles::TwiddleTree<CudaBackend>,
) -> stwo::prover::poly::twiddles::TwiddleTree<stwo::prover::backend::CpuBackend> {
    stwo::prover::poly::twiddles::TwiddleTree {
        root_coset: twiddles.root_coset,
        twiddles: twiddles.twiddles.to_vec(),
        itwiddles: twiddles.itwiddles.to_vec(),
    }
}

/// Prepare `buffer` as the in-place NTT input for evaluating `poly` on a domain of
/// `buffer.len()` points: the polynomial's coefficients followed by a zero tail.
/// `buffer` may arrive in any state (the mempool hands out uninitialized buffers),
/// so every word is written: one device-to-device copy plus one region memset —
/// no intermediate "extend" allocation and no second full-buffer copy.
fn fill_ntt_buffer(poly: &CirclePoly<CudaBackend>, buffer: &mut BaseFieldVec) {
    let n_coeffs = poly.coeffs.len();
    debug_assert!(buffer.len() >= n_coeffs);
    buffer.copy_from(&poly.coeffs);
    unsafe {
        interface::bindings::cuda_zero_device_region(
            buffer.device_ptr,
            n_coeffs as u64,
            (buffer.len() - n_coeffs) as u64,
        );
    }
}

fn evaluate_into_cuda(
    poly: &CirclePoly<CudaBackend>,
    domain: CircleDomain,
    twiddle_tree: &TwiddleTree<CudaBackend>,
    mut buffer: BaseFieldVec,
) -> CircleEvaluation<CudaBackend, BaseField, BitReversedOrder> {
    let domain_log_size = domain.log_size();

    assert!(domain.half_coset.is_doubling_of(twiddle_tree.root_coset));
    assert_eq!(buffer.len(), domain.size());

    if domain_log_size <= 3 {
        let cpu_poly = CpuCirclePoly::new(poly.coeffs.to_cpu());
        let cpu_circle_eval =
            CpuBackend::evaluate(&cpu_poly, domain, &to_cpu_twiddle_tree(twiddle_tree));
        let uploaded = BaseFieldVec::from_vec(cpu_circle_eval.values.to_vec());
        buffer.copy_from(&uploaded);
        return CudaCircleEvaluation::new(cpu_circle_eval.domain, buffer);
    }

    fill_ntt_buffer(poly, &mut buffer);

    unsafe {
        interface::bindings::ntt_n2b_columns(
            buffer.device_ptr.as_ptr() as *mut *mut u32,
            (buffer.len().ilog2() as usize) as u32,
            1,
            twiddle_tree.twiddles.device_ptr,
            twiddle_tree.twiddles.len() as u32,
            domain.half_coset.size() as u32,
        );
    }

    CircleEvaluation::new(domain, buffer)
}

impl PolyOps for CudaBackend {
    type Twiddles = BaseFieldVec;

    // fn new_canonical_ordered(
    //     coset: CanonicCoset,
    //     values: Col<Self, BaseField>,
    // ) -> CircleEvaluation<Self, BaseField, BitReversedOrder> {
    //     let size = values.len();
    //     let device_ptr = unsafe {
    //         interface::bindings::sort_values_and_permute_with_bit_reverse_order(values.
    // device_ptr, size)     };
    //     let result = BaseFieldVec::new(device_ptr, size);
    //     CircleEvaluation::new(coset.circle_domain(), result)
    // }

    fn interpolate(
        eval: CircleEvaluation<Self, BaseField, BitReversedOrder>,
        twiddle_tree: &TwiddleTree<Self>,
    ) -> CirclePoly<Self> {
        assert!(eval
            .domain
            .half_coset
            .is_doubling_of(twiddle_tree.root_coset));

        if eval.domain.log_size() <= 3 {
            let cpu_eval = CpuCircleEvaluation::new(eval.domain, eval.values.to_cpu());

            let cpu_circle_poly =
                CpuBackend::interpolate(cpu_eval, &to_cpu_twiddle_tree(twiddle_tree));

            let cuda_coeffs = BaseFieldVec::from_vec(cpu_circle_poly.coeffs.to_vec());

            return CirclePoly::<CudaBackend>::new(cuda_coeffs);
        }

        let values = eval.values;
        unsafe {
            interface::bindings::ntt_b2n_column(
                values.device_ptr.as_ptr() as *mut *mut u32,
                (values.len().ilog2() as usize) as u32,
                1_u32,
                twiddle_tree.itwiddles.device_ptr,
                twiddle_tree.itwiddles.len() as u32,
                eval.domain.half_coset.size() as u32,
            );
        }

        CirclePoly::new(values)
    }

    fn interpolate_columns(
        columns: Vec<CircleEvaluation<Self, BaseField, BitReversedOrder>>,
        twiddles: &TwiddleTree<Self>,
    ) -> Vec<CirclePoly<Self>> {
        let columns = columns.into_iter();
        // Collect columns with their original indices, then group by log_size for batch NTT.
        let mut indexed: Vec<(usize, u32, BaseFieldVec, CircleDomain)> = columns
            .enumerate()
            .map(|(i, eval)| {
                let log_size = eval.domain.log_size();
                (i, log_size, eval.values, eval.domain)
            })
            .collect();

        if indexed.is_empty() {
            return Vec::new();
        }

        indexed.sort_by_key(|(_, ls, ..)| *ls);

        let mut results: Vec<(usize, CirclePoly<Self>)> = Vec::with_capacity(indexed.len());
        let mut group_start = 0;

        while group_start < indexed.len() {
            let log_size = indexed[group_start].1;
            let mut group_end = group_start + 1;
            while group_end < indexed.len() && indexed[group_end].1 == log_size {
                group_end += 1;
            }

            let group = &mut indexed[group_start..group_end];

            if log_size <= 3 {
                for item in group.iter_mut() {
                    let values = std::mem::replace(&mut item.2, BaseFieldVec::new_uninitialized(0));
                    let cpu_eval = CpuCircleEvaluation::new(item.3, values.to_cpu());
                    let cpu_poly =
                        CpuBackend::interpolate(cpu_eval, &to_cpu_twiddle_tree(twiddles));
                    let cuda_coeffs = BaseFieldVec::from_vec(cpu_poly.coeffs.to_vec());
                    results.push((item.0, CirclePoly::<Self>::new(cuda_coeffs)));
                }
            } else {
                let eval_domain_size = group[0].3.half_coset.size() as u32;

                let mut ptrs: Vec<*mut u32> = group
                    .iter()
                    .map(|item| item.2.device_ptr as *mut u32)
                    .collect();

                // Tile the batch axis so no launch's grid.y/grid.z exceeds 65535.
                for (base, len) in ntt_batch_chunks(ptrs.len(), MAX_NTT_BATCH_COLUMNS) {
                    unsafe {
                        interface::bindings::ntt_b2n_column(
                            ptrs[base..base + len].as_mut_ptr(),
                            log_size,
                            len as u32,
                            twiddles.itwiddles.device_ptr,
                            twiddles.itwiddles.len() as u32,
                            eval_domain_size,
                        );
                    }
                }

                for item in group.iter_mut() {
                    let values = std::mem::replace(&mut item.2, BaseFieldVec::new_uninitialized(0));
                    results.push((item.0, CirclePoly::new(values)));
                }
            }

            group_start = group_end;
        }

        results.sort_by_key(|(idx, _)| *idx);
        results.into_iter().map(|(_, poly)| poly).collect()
    }

    fn eval_at_point(poly: &CirclePoly<Self>, point: CirclePoint<SecureField>) -> SecureField {
        unsafe {
            interface::bindings::eval_at_point(
                poly.coeffs.device_ptr,
                poly.coeffs.len() as u32,
                CudaSecureField::from(point.x),
                CudaSecureField::from(point.y),
            )
            .into()
        }
    }

    fn barycentric_weights(
        coset: CanonicCoset,
        p: CirclePoint<SecureField>,
    ) -> Col<Self, SecureField> {
        let domain = coset.circle_domain();
        let log_size = domain.log_size();
        let p = p.into_ef::<SecureField>();

        // The per-point work — circle-point generation, the inversion-free
        // `point_vanishing` split (numerator h.y, denominator 1 + h.x), the batched
        // inversion, and the final multiply — all runs ON DEVICE. The previous host
        // pass generated and inverted millions of points on the CPU per unique
        // (log_size, point) pair and uploaded the result; the values are identical
        // (the device point generator is the quotient kernels' conformance-proven
        // routine, and field inverses are unique). Only the O(log n) scale factors
        // stay on the host.
        let point_vanishings = SecureFieldVec::new_uninitialized(domain.size());
        unsafe {
            interface::bindings::barycentric_point_vanishings(
                domain.half_coset.initial_index.0 as u32,
                domain.half_coset.step_size.0 as u32,
                domain.size() as u32,
                log_size,
                CudaSecureField::from(p.x),
                CudaSecureField::from(p.y),
                point_vanishings.device_ptr,
            );
        }

        let p_0 = domain.at(0).into_ef::<SecureField>();
        let si_0 = SecureField::one()
            / ((p_0.y * SecureField::from(-2))
                * coset_vanishing_derivative(
                    Coset::new(CirclePointIndex::generator(), log_size),
                    p_0,
                ));
        let even_scale = si_0 * coset_vanishing(CanonicCoset::new(log_size).coset, p);
        let odd_scale = -even_scale;

        let weights = SecureFieldVec::new_uninitialized(domain.size());
        unsafe {
            interface::bindings::barycentric_weights_from_point_vanishings(
                point_vanishings.device_ptr,
                domain.size() as u32,
                CudaSecureField::from(even_scale),
                CudaSecureField::from(odd_scale),
                weights.device_ptr,
            );
        }

        weights
    }

    fn barycentric_eval_at_point(
        evals: &CircleEvaluation<Self, BaseField, BitReversedOrder>,
        weights: &Col<Self, SecureField>,
    ) -> SecureField {
        assert_eq!(evals.len(), weights.len());

        unsafe {
            interface::bindings::barycentric_eval_base_field(
                evals.values.device_ptr,
                weights.device_ptr,
                evals.len() as u32,
            )
            .into()
        }
    }

    fn barycentric_eval_columns_at_point(
        evals: &[&CircleEvaluation<Self, BaseField, BitReversedOrder>],
        weights: &Col<Self, SecureField>,
    ) -> Vec<SecureField> {
        // One launch pair + one D2H for the whole same-size group, vs a
        // launch+sync round trip per column (the OODS phase issues thousands).
        // Exact field sums — values identical to the per-column path.
        if evals.is_empty() {
            return Vec::new();
        }
        for e in evals {
            assert_eq!(e.len(), weights.len());
        }
        // Kill switch for a clean on/off A/B of the batched kernel vs the
        // per-column path (value-identical either way). Default = batched.
        if std::env::var("STWO_CUDA_BATCHED_OODS").as_deref() == Ok("0") {
            return evals
                .iter()
                .map(|e| Self::barycentric_eval_at_point(e, weights))
                .collect();
        }
        // The batched kernel puts columns on the grid's y-dimension, capped at
        // 65535 by CUDA. Cairo OODS groups are far below this, but chunk so an
        // oversized group can never make the launch fail — each chunk is an
        // independent, exact set of columns, concatenated in order.
        const MAX_COLS_PER_LAUNCH: usize = 32768;
        let mut out = Vec::with_capacity(evals.len());
        for chunk in evals.chunks(MAX_COLS_PER_LAUNCH) {
            let ptrs: Vec<*const u32> = chunk.iter().map(|e| e.values.device_ptr).collect();
            let table = crate::backend::UploadedDevicePointerVec::upload(&ptrs);
            let chunk_out = unsafe {
                interface::bindings::barycentric_eval_base_field_many(
                    table.as_ptr(),
                    chunk.len() as u32,
                    weights.device_ptr,
                    weights.len() as u32,
                )
            };
            drop(table);
            out.extend(chunk_out.into_iter().map(SecureField::from));
        }
        out
    }

    fn eval_at_point_by_folding(
        evals: &CircleEvaluation<Self, BaseField, BitReversedOrder>,
        point: CirclePoint<SecureField>,
        twiddles: &TwiddleTree<Self>,
    ) -> SecureField {
        let log_size = evals.domain.log_size();
        if log_size == 0 {
            return evals.values.at(0).into();
        }

        let mut folding_alphas = get_folding_alphas(point, log_size as usize);
        let first_inner_layer_domain = LineDomain::new(Coset::half_odds(log_size - 1));
        let _ = first_inner_layer_domain;
        let secure_evals = SecureEvaluation::new(
            evals.domain,
            SecureColumnByCoords::from_base_field_col(&evals.values),
        );

        let mut layer_evaluation = CudaBackend::fold_circle_into_line(
            &secure_evals,
            folding_alphas.pop().unwrap(),
            twiddles,
        );

        while layer_evaluation.len() > 1 {
            layer_evaluation = CudaBackend::fold_line(
                &layer_evaluation,
                &[folding_alphas.pop().unwrap()],
                twiddles,
            );
        }

        layer_evaluation.values.at(0) / SecureField::from(2_u32.pow(log_size))
    }

    fn extend(poly: &CirclePoly<Self>, log_size: u32) -> CirclePoly<Self> {
        let new_size = 1 << log_size;
        assert!(
            new_size >= poly.coeffs.len(),
            "New size must be larger than the old size"
        );

        let mut new_coeffs = BaseFieldVec::new_zeroes(new_size);
        new_coeffs.copy_from(&poly.coeffs);
        CirclePoly::new(new_coeffs)
    }

    fn evaluate(
        poly: &CirclePoly<Self>,
        domain: CircleDomain,
        twiddle_tree: &TwiddleTree<Self>,
    ) -> CircleEvaluation<Self, BaseField, BitReversedOrder> {
        evaluate_into_cuda(
            poly,
            domain,
            twiddle_tree,
            BaseFieldVec::new_zeroes(domain.size()),
        )
    }

    fn evaluate_into(
        poly: &CirclePoly<Self>,
        domain: CircleDomain,
        twiddles: &TwiddleTree<Self>,
        buffer: Col<Self, BaseField>,
    ) -> CircleEvaluation<Self, BaseField, BitReversedOrder> {
        evaluate_into_cuda(poly, domain, twiddles, buffer)
    }

    /// Batched override of the per-column default: the trace's polynomials are grouped
    /// by evaluation size and each group runs as ONE multi-column NTT launch (the
    /// mirror of [`Self::interpolate_columns`]). On the Cairo trace this collapses
    /// hundreds of `ntt_n2b_columns(num_poly=1)` launches — each preceded and followed
    /// by wrapper synchronization — into a handful of saturating dispatches.
    fn evaluate_polynomials(
        polynomials: stwo::core::ColumnVec<CirclePoly<Self>>,
        log_blowup_factor: u32,
        twiddles: &TwiddleTree<Self>,
        store_polynomials_coefficients: bool,
        pool: &stwo::prover::mempool::BaseColumnPool<Self>,
    ) -> Vec<stwo::prover::Poly<Self>> {
        // Buffer per polynomial, pooled where possible (uninitialized contents;
        // fill_ntt_buffer writes every word).
        let buffers: Vec<BaseFieldVec> = polynomials
            .iter()
            .map(|poly| pool.take_or_alloc(poly.log_size() + log_blowup_factor))
            .collect();

        // Pair each polynomial with its buffer and original position, group by
        // evaluation log size for the batch NTT.
        let mut indexed: Vec<(usize, u32, CirclePoly<Self>, BaseFieldVec)> = polynomials
            .into_iter()
            .zip(buffers)
            .enumerate()
            .map(|(i, (poly, buffer))| {
                let log_eval_size = poly.log_size() + log_blowup_factor;
                (i, log_eval_size, poly, buffer)
            })
            .collect();
        indexed.sort_by_key(|(_, log_eval_size, ..)| *log_eval_size);

        // Phase 1: stage every group's buffers in place (coefficients + zero tail),
        // then run ONE batch NTT per group. Domains of log size <= 3 are left for the
        // CPU reference path in phase 2 (matching `evaluate_into`'s fallback).
        let mut group_start = 0;
        while group_start < indexed.len() {
            let log_eval_size = indexed[group_start].1;
            let mut group_end = group_start + 1;
            while group_end < indexed.len() && indexed[group_end].1 == log_eval_size {
                group_end += 1;
            }
            if log_eval_size > 3 {
                let group = &mut indexed[group_start..group_end];
                let domain = CanonicCoset::new(log_eval_size).circle_domain();
                for (_, _, poly, buffer) in group.iter_mut() {
                    assert_eq!(buffer.len(), domain.size());
                    fill_ntt_buffer(poly, buffer);
                }
                let mut ptrs: Vec<*mut u32> = group
                    .iter()
                    .map(|(.., buffer)| buffer.device_ptr as *mut u32)
                    .collect();
                // Tile the batch axis so no launch's grid.y/grid.z exceeds 65535.
                for (base, len) in ntt_batch_chunks(ptrs.len(), MAX_NTT_BATCH_COLUMNS) {
                    unsafe {
                        interface::bindings::ntt_n2b_columns(
                            ptrs[base..base + len].as_mut_ptr(),
                            log_eval_size,
                            len as u32,
                            twiddles.twiddles.device_ptr,
                            twiddles.twiddles.len() as u32,
                            domain.half_coset.size() as u32,
                        );
                    }
                }
            }
            group_start = group_end;
        }

        // Phase 2: wrap results in original column order.
        let mut results: Vec<(usize, stwo::prover::Poly<Self>)> = indexed
            .into_iter()
            .map(|(i, log_eval_size, poly, buffer)| {
                let domain = CanonicCoset::new(log_eval_size).circle_domain();
                let evals = if log_eval_size <= 3 {
                    evaluate_into_cuda(&poly, domain, twiddles, buffer)
                } else {
                    CircleEvaluation::new(domain, buffer)
                };
                (
                    i,
                    stwo::prover::Poly::new(store_polynomials_coefficients.then_some(poly), evals),
                )
            })
            .collect();
        results.sort_by_key(|(idx, _)| *idx);
        results.into_iter().map(|(_, poly)| poly).collect()
    }

    fn precompute_twiddles(coset: Coset) -> TwiddleTree<Self> {
        unsafe {
            let twiddles = BaseFieldVec::new(
                interface::bindings::precompute_twiddles(
                    coset.initial.into(),
                    coset.step.into(),
                    coset.size(),
                ),
                coset.size(),
            );
            let itwiddles = BaseFieldVec::new_uninitialized(coset.size());
            interface::bindings::batch_inverse_base_field(
                twiddles.device_ptr,
                itwiddles.device_ptr,
                coset.size(),
            );
            TwiddleTree {
                root_coset: coset,
                twiddles,
                itwiddles,
            }
        }
    }

    fn split_at_mid(poly: CirclePoly<Self>) -> (CirclePoly<Self>, CirclePoly<Self>) {
        let (left, right) = poly.coeffs.split_at_mid();
        (CirclePoly::new(left), CirclePoly::new(right))
    }

    /// Inverse of [`Self::split_at_mid`]: concatenate the halves' coefficients with
    /// two device-to-device copies into a fresh buffer — no host roundtrip. (At
    /// big-trace sizes the previous download/upload moved multiple gigabytes over
    /// PCIe per call.)
    fn join_at_mid(left: CirclePoly<Self>, right: CirclePoly<Self>) -> CirclePoly<Self> {
        let half = left.coeffs.len();
        assert_eq!(
            half,
            right.coeffs.len(),
            "join_at_mid requires equal-length halves"
        );
        let mut coeffs = BaseFieldVec::new_uninitialized(2 * half);
        coeffs.copy_from(&left.coeffs);
        coeffs.copy_from_offset(&right.coeffs, half);
        CirclePoly::new(coeffs)
    }
}
#[cfg(all(test, stwo_cuda_link))]
mod tests {
    // use itertools::Itertools;
    use stwo::core::poly::circle::{CanonicCoset, CircleDomain};
    use stwo::core::{
        circle::{CirclePoint, CirclePointIndex, Coset},
        fields::m31::BaseField,
        // ColumnVec,
    };
    use stwo::prover::backend::{Column, CpuBackend};
    use stwo::prover::poly::circle::{CircleCoefficients as CirclePoly, CircleEvaluation, PolyOps};
    use stwo::prover::poly::twiddles::TwiddleTree;
    use stwo::prover::poly::BitReversedOrder;

    // use crate::backend::poly::evaluate_native;
    use crate::backend::CudaBackend;
    use crate::columns::base_field_vec::BaseFieldVec;

    // use num_traits::start_timer;
    // use num_traits::end_timer;

    // #[test]
    // fn test_new_canonical_ordered() {
    //     let log_size = 4;
    //     let coset = CanonicCoset::new(log_size);
    //     let size: usize = 1 << log_size;
    //     let column_data = (0..size as u32).map(BaseField::from).collect::<Vec<_>>();
    //     let cpu_values = column_data.clone();
    //     let expected_result = CpuBackend::new_canonical_ordered(coset, cpu_values.clone());

    //     let column = BaseFieldVec::from_vec(column_data);
    //     let result = CudaBackend::new_canonical_ordered(coset, column);

    //     assert_eq!(result.values.to_cpu(), expected_result.values);
    //     assert_eq!(
    //         result.domain.iter().collect::<Vec<_>>(),
    //         expected_result.domain.iter().collect::<Vec<_>>()
    //     );
    // }

    #[test]
    fn test_interpolate_evaluate_log24() {
        use stwo::prover::poly::circle::CircleEvaluation as CpuCircleEvaluation;

        let log_size = 24u32;
        let size = 1usize << log_size;

        let cpu_values: Vec<BaseField> = (0..size).map(|i| BaseField::from(i as u32)).collect();
        let gpu_values = BaseFieldVec::from_vec(cpu_values.clone());

        let coset = CanonicCoset::new(log_size);
        let domain = coset.circle_domain();

        let cpu_evaluations =
            CpuCircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, cpu_values);
        let gpu_evaluations =
            CircleEvaluation::<CudaBackend, _, BitReversedOrder>::new(domain, gpu_values);

        let cpu_twiddles = CpuBackend::precompute_twiddles(coset.half_coset());
        let gpu_twiddles = CudaBackend::precompute_twiddles(coset.half_coset());

        let cpu_poly = CpuBackend::interpolate(cpu_evaluations, &cpu_twiddles);
        let gpu_poly = CudaBackend::interpolate(gpu_evaluations, &gpu_twiddles);

        // Compare interpolation results
        assert_eq!(gpu_poly.coeffs.to_cpu(), cpu_poly.coeffs);

        // Test evaluation on a slightly larger domain
        let eval_coset = CanonicCoset::new(log_size + 1);
        let eval_domain = eval_coset.circle_domain();
        let cpu_twiddles2 = CpuBackend::precompute_twiddles(eval_coset.half_coset());
        let gpu_twiddles2 = CudaBackend::precompute_twiddles(eval_coset.half_coset());
        let cpu_eval = CpuBackend::evaluate(&cpu_poly, eval_domain, &cpu_twiddles2);
        let gpu_eval = CudaBackend::evaluate(&gpu_poly, eval_domain, &gpu_twiddles2);

        assert_eq!(gpu_eval.values.to_cpu(), cpu_eval.values);
    }

    #[test]
    fn test_precompute_twiddles() {
        let log_size = 5;

        let half_coset = CanonicCoset::new(log_size).half_coset();
        let expected_result = CpuBackend::precompute_twiddles(half_coset);
        let twiddles = CudaBackend::precompute_twiddles(half_coset);

        assert_eq!(twiddles.twiddles.to_cpu(), expected_result.twiddles);
        assert_eq!(twiddles.itwiddles.to_cpu(), expected_result.itwiddles);
        assert_eq!(
            twiddles.root_coset.iter().collect::<Vec<_>>(),
            expected_result.root_coset.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extend() {
        let log_size = 20;
        let size = 1 << log_size;
        let new_log_size = log_size + 5;
        let cpu_coeffs = (0..size).map(BaseField::from).collect::<Vec<_>>();
        let cuda_coeffs = BaseFieldVec::from_vec(cpu_coeffs.clone());
        let cpu_poly = CirclePoly::<CpuBackend>::new(cpu_coeffs);
        let cuda_poly = CirclePoly::<CudaBackend>::new(cuda_coeffs);
        let result = CudaBackend::extend(&cuda_poly, new_log_size);
        let expected_result = CpuBackend::extend(&cpu_poly, new_log_size);
        assert_eq!(result.coeffs.to_cpu(), expected_result.coeffs);
        assert_eq!(result.log_size(), expected_result.log_size());
    }

    // #[test]
    // fn test_interpolate() {
    //     let log_size = 20;

    //     let size = 1 << log_size;

    //     let cpu_values = (1..(size + 1) as u32)
    //         .map(BaseField::from)
    //         .collect::<Vec<_>>();
    //     let gpu_values = BaseFieldVec::from_vec(cpu_values.clone());

    //     let coset = CanonicCoset::new(log_size);
    //     let cpu_evaluations = CpuBackend::new_canonical_ordered(coset, cpu_values);
    //     let gpu_evaluations = CudaBackend::new_canonical_ordered(coset, gpu_values);

    //     let cpu_twiddles = CpuBackend::precompute_twiddles(coset.half_coset());
    //     let gpu_twiddles = CudaBackend::precompute_twiddles(coset.half_coset());

    //     let timer = start_timer!(|| format!("cpu backend interpolate, log_n:{}", log_size));
    //     let expected_result = CpuBackend::interpolate(cpu_evaluations, &cpu_twiddles);
    //     end_timer!(timer);

    //     let timer = start_timer!(|| format!("gpu backend interpolate, log_n:{}", log_size));
    //     let result = CudaBackend::interpolate(gpu_evaluations, &gpu_twiddles);
    //     end_timer!(timer);

    //     assert_eq!(result.coeffs.to_cpu(), expected_result.coeffs);
    // }

    // #[test]
    // fn test_interpolate_2() {
    //     let log_size = 5;

    //     let cpu_values = vec![
    //         BaseField::from(1),
    //         BaseField::from(443693538),
    //         BaseField::from(793699796),
    //         BaseField::from(1631104375),
    //         BaseField::from(460025527),
    //         BaseField::from(98131605),
    //         BaseField::from(1292025643),
    //         BaseField::from(1056169651),
    //         BaseField::from(29),
    //         BaseField::from(1645907698),
    //         BaseField::from(300234932),
    //         BaseField::from(2113642380),
    //         BaseField::from(2031046861),
    //         BaseField::from(541052612),
    //         BaseField::from(1857203558),
    //         BaseField::from(5),
    //         BaseField::from(2),
    //         BaseField::from(187770177),
    //         BaseField::from(1190378570),
    //         BaseField::from(1107054997),
    //         BaseField::from(1436440899),
    //         BaseField::from(1555024221),
    //         BaseField::from(2002021885),
    //         BaseField::from(866),
    //         BaseField::from(750797),
    //         BaseField::from(1704111751),
    //         BaseField::from(1874758341),
    //         BaseField::from(960394553),
    //         BaseField::from(1365348280),
    //         BaseField::from(376645196),
    //         BaseField::from(2119137245),
    //         BaseField::from(1),
    //     ];
    //     let gpu_values = BaseFieldVec::from_vec(cpu_values.clone());

    //     let coset = CanonicCoset::new(log_size);
    //     let cpu_evaluations = CpuBackend::new_canonical_ordered(coset, cpu_values);
    //     let gpu_evaluations = CudaBackend::new_canonical_ordered(coset, gpu_values);

    //     let cpu_twiddles = CpuBackend::precompute_twiddles(coset.half_coset());
    //     let gpu_twiddles = CudaBackend::precompute_twiddles(coset.half_coset());

    //     let expected_result = CpuBackend::interpolate(cpu_evaluations, &cpu_twiddles);
    //     let result = CudaBackend::interpolate(gpu_evaluations, &gpu_twiddles);

    //     assert_eq!(result.coeffs.to_cpu(), expected_result.coeffs);
    // }

    // #[test]
    // fn test_interpolate_3() {

    //     for log_size in 4..30 {

    //         let size = 1 << log_size;

    //         let cpu_values = (1..(size + 1) as u32)
    //             .map(BaseField::from)
    //             .collect::<Vec<_>>();
    //         let gpu_values = BaseFieldVec::from_vec(cpu_values.clone());

    //         let coset = CanonicCoset::new(log_size);
    //         let cpu_evaluations = CpuBackend::new_canonical_ordered(coset, cpu_values);
    //         let gpu_evaluations = CudaBackend::new_canonical_ordered(coset, gpu_values);

    //         let cpu_twiddles = CpuBackend::precompute_twiddles(coset.half_coset());
    //         let gpu_twiddles = CudaBackend::precompute_twiddles(coset.half_coset());

    //         assert_eq!(cpu_twiddles.twiddles.to_vec(), gpu_twiddles.twiddles.to_vec());

    //         let timer = start_timer!(|| format!("cpu backend interpolate, log_n:{}", log_size));
    //         let cpu_poly = CpuBackend::interpolate(cpu_evaluations, &cpu_twiddles);
    //         end_timer!(timer);

    //         let timer = start_timer!(|| format!("optimize gpu backend interpolate, log_n:{}",
    // log_size));         let gpu_poly = CudaBackend::interpolate(gpu_evaluations,
    // &gpu_twiddles);         end_timer!(timer);

    //         assert_eq!(gpu_poly.coeffs.to_vec(), cpu_poly.coeffs.to_vec());

    //     }

    // }

    // #[test]
    // #[allow(unused_variables)]
    // fn test_evaluate() {
    //     for log_size in 13..26 {

    //         let size = 1 << log_size;

    //         let cpu_values = (1..(size + 1) as u32)
    //             .map(BaseField::from)
    //             .collect::<Vec<_>>();
    //         let gpu_values = BaseFieldVec::from_vec(cpu_values.clone());
    //         let gpu_values_optim = BaseFieldVec::from_vec(cpu_values.clone());

    //         let coset = CanonicCoset::new(log_size);
    //         let cpu_evaluations = CpuBackend::new_canonical_ordered(coset, cpu_values);
    //         let gpu_evaluations = CudaBackend::new_canonical_ordered(coset, gpu_values);
    //         let gpu_evaluations_optim = CudaBackend::new_canonical_ordered(coset,
    // gpu_values_optim);

    //         let cpu_twiddles = CpuBackend::precompute_twiddles(coset.half_coset());
    //         let gpu_twiddles = CudaBackend::precompute_twiddles(coset.half_coset());

    //         assert_eq!(cpu_twiddles.twiddles.to_vec(), gpu_twiddles.twiddles.to_vec());

    //         let cpu_poly = CpuBackend::interpolate(cpu_evaluations, &cpu_twiddles);
    //         let gpu_poly = CudaBackend::interpolate(gpu_evaluations, &gpu_twiddles);
    //         let gpu_poly_optim = CudaBackend::interpolate(gpu_evaluations_optim, &gpu_twiddles);
    //         assert_eq!(gpu_poly_optim.coeffs.to_vec(), cpu_poly.coeffs.to_vec());

    //         let timer = start_timer!(|| format!("cpu backend interpolate, log_n:{}", log_size));
    //         let expected_result = CpuBackend::evaluate(&cpu_poly, coset.circle_domain(),
    // &cpu_twiddles);         end_timer!(timer);

    //         let timer = start_timer!(|| format!("native gpu backend  interpolate, log_n:{}",
    // log_size));         let result = evaluate_native(&gpu_poly, coset.circle_domain(),
    // &gpu_twiddles);         end_timer!(timer);

    //         let timer = start_timer!(|| format!("optimize gpu backend interpolate, log_n:{}",
    // log_size));         let result_optim = CudaBackend::evaluate(&gpu_poly_optim,
    // coset.circle_domain(), &gpu_twiddles);         end_timer!(timer);

    //         assert_eq!(result_optim.values.to_cpu(), expected_result.values);
    //     }

    // }

    // #[test]
    // fn test_eval_at_point() {
    //     let log_size = 20;

    //     let size = 1 << log_size;
    //     let coset = CanonicCoset::new(log_size);
    //     let point = SECURE_FIELD_CIRCLE_GEN;

    //     let cpu_values = (1..(size + 1) as u32)
    //         .map(BaseField::from)
    //         .collect::<Vec<_>>();

    //     let gpu_values = BaseFieldVec::from_vec(cpu_values.clone());
    //     let gpu_evaluations = CudaBackend::new_canonical_ordered(coset, gpu_values);
    //     let gpu_twiddles = CudaBackend::precompute_twiddles(coset.half_coset());
    //     let gpu_poly = CudaBackend::interpolate(gpu_evaluations, &gpu_twiddles);
    //     let result = CudaBackend::eval_at_point(&gpu_poly, point);

    //     let cpu_evaluations = CpuBackend::new_canonical_ordered(coset, cpu_values);
    //     let cpu_twiddles = CpuBackend::precompute_twiddles(coset.half_coset());
    //     let cpu_poly = CpuBackend::interpolate(cpu_evaluations, &cpu_twiddles);

    //     let expected_result = CpuBackend::eval_at_point(&cpu_poly, point.clone());

    //     assert_eq!(result, expected_result);
    // }

    #[test]
    fn test_evaluate_small_poly_on_large_domain() {
        // This tests the exact scenario in accumulator finalize:
        // A polynomial created at log_size=20 evaluated on domain of log_size=24
        use stwo::prover::poly::circle::CircleEvaluation as CpuCircleEvaluation;

        const SMALL_LOG_SIZE: u32 = 20;
        const LARGE_LOG_SIZE: u32 = 24;

        let small_size = 1usize << SMALL_LOG_SIZE;
        let large_size = 1usize << LARGE_LOG_SIZE;

        // Create values at small size
        let cpu_values: Vec<BaseField> =
            (0..small_size).map(|i| BaseField::from(i as u32)).collect();
        let gpu_values = BaseFieldVec::from_vec(cpu_values.clone());

        let small_coset = CanonicCoset::new(SMALL_LOG_SIZE);
        let small_domain = small_coset.circle_domain();
        let large_coset = CanonicCoset::new(LARGE_LOG_SIZE);
        let large_domain = large_coset.circle_domain();

        // Create evaluations
        let cpu_evaluations =
            CpuCircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(small_domain, cpu_values);
        let gpu_evaluations =
            CircleEvaluation::<CudaBackend, _, BitReversedOrder>::new(small_domain, gpu_values);

        // Precompute twiddles for interpolation (small domain)
        let cpu_small_twiddles = CpuBackend::precompute_twiddles(small_coset.half_coset());
        let gpu_small_twiddles = CudaBackend::precompute_twiddles(small_coset.half_coset());

        // Interpolate to get polynomials
        let cpu_poly = CpuBackend::interpolate(cpu_evaluations, &cpu_small_twiddles);
        let gpu_poly = CudaBackend::interpolate(gpu_evaluations, &gpu_small_twiddles);

        // Verify interpolation matches
        assert_eq!(gpu_poly.coeffs.to_cpu(), cpu_poly.coeffs);

        // Precompute twiddles for large domain evaluation
        let cpu_large_twiddles = CpuBackend::precompute_twiddles(large_coset.half_coset());
        let gpu_large_twiddles = CudaBackend::precompute_twiddles(large_coset.half_coset());

        // Evaluate both on the LARGE domain
        let cpu_eval_result = CpuBackend::evaluate(&cpu_poly, large_domain, &cpu_large_twiddles);
        let gpu_eval_result = CudaBackend::evaluate(&gpu_poly, large_domain, &gpu_large_twiddles);

        let cpu_result = cpu_eval_result.values;
        let gpu_result = gpu_eval_result.values.to_cpu();

        assert_eq!(cpu_result.len(), large_size);
        assert_eq!(gpu_result.len(), large_size);

        // Check first 1000 elements
        assert_eq!(
            cpu_result[..1000],
            gpu_result[..1000],
            "First 1000 elements mismatch"
        );
        // Check last 1000 elements
        assert_eq!(
            cpu_result[large_size - 1000..],
            gpu_result[large_size - 1000..],
            "Last 1000 elements mismatch"
        );
        // Check middle elements
        let mid = large_size / 2;
        assert_eq!(
            cpu_result[mid..mid + 1000],
            gpu_result[mid..mid + 1000],
            "Middle 1000 elements mismatch"
        );
    }

    #[test]
    fn test_interpolate_from_fib() {
        let eval = CircleEvaluation::<CudaBackend, BaseField, BitReversedOrder>::new(
            CircleDomain {
                half_coset: Coset {
                    initial_index: CirclePointIndex(33554432),
                    initial: CirclePoint {
                        x: BaseField::from(579625837),
                        y: BaseField::from(1690787918),
                    },
                    step_size: CirclePointIndex(134217728),
                    step: CirclePoint {
                        x: BaseField::from(590768354),
                        y: BaseField::from(978592373),
                    },
                    log_size: 4,
                },
            },
            BaseFieldVec::from_vec(vec![
                BaseField::from(1),
                BaseField::from(443693538),
                BaseField::from(793699796),
                BaseField::from(1631104375),
                BaseField::from(460025527),
                BaseField::from(98131605),
                BaseField::from(1292025643),
                BaseField::from(1056169651),
                BaseField::from(29),
                BaseField::from(1645907698),
                BaseField::from(300234932),
                BaseField::from(2113642380),
                BaseField::from(2031046861),
                BaseField::from(541052612),
                BaseField::from(1857203558),
                BaseField::from(5),
                BaseField::from(2),
                BaseField::from(187770177),
                BaseField::from(1190378570),
                BaseField::from(1107054997),
                BaseField::from(1436440899),
                BaseField::from(1555024221),
                BaseField::from(2002021885),
                BaseField::from(866),
                BaseField::from(750797),
                BaseField::from(1704111751),
                BaseField::from(1874758341),
                BaseField::from(960394553),
                BaseField::from(1365348280),
                BaseField::from(376645196),
                BaseField::from(2119137245),
                BaseField::from(1),
            ]),
        );
        let twiddles = vec![
            BaseField::from(785043271),
            BaseField::from(1260750973),
            BaseField::from(736262640),
            BaseField::from(1553669210),
            BaseField::from(479120236),
            BaseField::from(225856549),
            BaseField::from(197700101),
            BaseField::from(1079800039),
            BaseField::from(1911378744),
            BaseField::from(1577470940),
            BaseField::from(1334497267),
            BaseField::from(2085743640),
            BaseField::from(477953613),
            BaseField::from(125103457),
            BaseField::from(1977033713),
            BaseField::from(2005527287),
            BaseField::from(251924953),
            BaseField::from(636875771),
            BaseField::from(48903418),
            BaseField::from(1896945393),
            BaseField::from(1514613395),
            BaseField::from(870936612),
            BaseField::from(1297878576),
            BaseField::from(583555490),
            BaseField::from(640817200),
            BaseField::from(1702126977),
            BaseField::from(1054411686),
            BaseField::from(648593218),
            BaseField::from(1014093253),
            BaseField::from(2137011181),
            BaseField::from(81378258),
            BaseField::from(789857006),
            BaseField::from(838195206),
            BaseField::from(1774253895),
            BaseField::from(1739004854),
            BaseField::from(262191051),
            BaseField::from(206059115),
            BaseField::from(212443077),
            BaseField::from(1796741361),
            BaseField::from(883753057),
            BaseField::from(2140339328),
            BaseField::from(404685994),
            BaseField::from(9803698),
            BaseField::from(68458636),
            BaseField::from(14530030),
            BaseField::from(228509164),
            BaseField::from(1038945916),
            BaseField::from(134155457),
            BaseField::from(579625837),
            BaseField::from(1690787918),
            BaseField::from(1641940819),
            BaseField::from(2121318970),
            BaseField::from(1952787376),
            BaseField::from(1580223790),
            BaseField::from(1013961365),
            BaseField::from(280947147),
            BaseField::from(1179735656),
            BaseField::from(1241207368),
            BaseField::from(1415090252),
            BaseField::from(2112881577),
            BaseField::from(590768354),
            BaseField::from(978592373),
            BaseField::from(32768),
            BaseField::from(1),
        ];
        let itwiddles = vec![
            BaseField::from(1541158724),
            BaseField::from(16208603),
            BaseField::from(62823040),
            BaseField::from(1642210396),
            BaseField::from(1631996251),
            BaseField::from(1007591000),
            BaseField::from(1874949287),
            BaseField::from(1849862501),
            BaseField::from(781334166),
            BaseField::from(132945364),
            BaseField::from(1278220752),
            BaseField::from(214347122),
            BaseField::from(1165838173),
            BaseField::from(2054194025),
            BaseField::from(1234096940),
            BaseField::from(1721693449),
            BaseField::from(622651690),
            BaseField::from(1373671071),
            BaseField::from(82740187),
            BaseField::from(1683898894),
            BaseField::from(1918467639),
            BaseField::from(1186332607),
            BaseField::from(1296073347),
            BaseField::from(401388709),
            BaseField::from(1383565722),
            BaseField::from(656788371),
            BaseField::from(1787268380),
            BaseField::from(1809670981),
            BaseField::from(99372120),
            BaseField::from(765975505),
            BaseField::from(774809712),
            BaseField::from(348924564),
            BaseField::from(2029303208),
            BaseField::from(959596234),
            BaseField::from(1051468699),
            BaseField::from(721860568),
            BaseField::from(1767118503),
            BaseField::from(218253990),
            BaseField::from(1356867335),
            BaseField::from(1955048591),
            BaseField::from(559361447),
            BaseField::from(1046725194),
            BaseField::from(448375059),
            BaseField::from(1036402186),
            BaseField::from(2138687850),
            BaseField::from(1268642696),
            BaseField::from(1381082522),
            BaseField::from(559888787),
            BaseField::from(248349974),
            BaseField::from(969924856),
            BaseField::from(1461702947),
            BaseField::from(655012266),
            BaseField::from(1385854532),
            BaseField::from(1859156789),
            BaseField::from(349252128),
            BaseField::from(421110815),
            BaseField::from(1160411471),
            BaseField::from(1518526074),
            BaseField::from(490549293),
            BaseField::from(1942501404),
            BaseField::from(991237807),
            BaseField::from(775648038),
            BaseField::from(65536),
            BaseField::from(1),
        ];
        let root_coset = Coset {
            initial_index: CirclePointIndex(8388608),
            initial: CirclePoint {
                x: BaseField::from(785043271),
                y: BaseField::from(1260750973),
            },
            step_size: CirclePointIndex(33554432),
            step: CirclePoint {
                x: BaseField::from(579625837),
                y: BaseField::from(1690787918),
            },
            log_size: 6,
        };
        let twiddle_tree = TwiddleTree::<CudaBackend> {
            root_coset,
            twiddles: BaseFieldVec::from_vec(twiddles),
            itwiddles: BaseFieldVec::from_vec(itwiddles),
        };

        let cpu_evaluation = CircleEvaluation::<CpuBackend, BaseField, BitReversedOrder>::new(
            eval.domain,
            eval.values.to_cpu(),
        );
        let cpu_twiddle_tree = TwiddleTree::<CpuBackend> {
            root_coset: twiddle_tree.root_coset.clone(),
            twiddles: twiddle_tree.twiddles.to_cpu(),
            itwiddles: twiddle_tree.itwiddles.to_cpu(),
        };
        let expected_result = CpuBackend::interpolate(cpu_evaluation, &cpu_twiddle_tree);
        let result = CudaBackend::interpolate(eval, &twiddle_tree);
        assert_eq!(expected_result.coeffs, result.coeffs.to_cpu());
    }

    // #[test_log::test]
    // fn test_interpolate_columns() {
    //     // use crate::backend::poly::interpolate_columns_native;
    //     let log_number_of_columns = 7;

    //     for log_size in 13..17 {
    //         let size = 1 << log_size;
    //         let number_of_columns = 1 << log_number_of_columns;
    //         let cpu_values = (1..(size + 1) as u32).map(BaseField::from).collect_vec();
    //         let gpu_values = BaseFieldVec::from_vec(cpu_values.clone());

    //         let coset = CanonicCoset::new(log_size);
    //         let cpu_evaluations = CpuBackend::new_canonical_ordered(coset, cpu_values);
    //         let gpu_evaluations = CudaBackend::new_canonical_ordered(coset, gpu_values);

    //         let cpu_twiddles = CpuBackend::precompute_twiddles(coset.half_coset());
    //         let gpu_twiddles = CudaBackend::precompute_twiddles(coset.half_coset());

    //         let cpu_columns = (0..number_of_columns)
    //             .map(|_index| cpu_evaluations.clone())
    //             .collect_vec();
    //         let gpu_columns = (0..number_of_columns)
    //             .map(|_index| gpu_evaluations.clone())
    //             .collect_vec();

    //         let timer = start_timer!(|| format!("cpu backend interpolate_columns, column:{}
    // log_n:{}", 1<<log_number_of_columns, log_size));         let expected_result =
    // CpuBackend::interpolate_columns(cpu_columns, &cpu_twiddles);         end_timer!(timer);

    //         // let timer = start_timer!(|| format!("gpu backend native interpolate_columns,
    // column:{} log_n:{}", 1<<log_number_of_columns, log_size));         // let result =
    // interpolate_columns_native(gpu_columns.clone(), &gpu_twiddles);         //
    // end_timer!(timer);

    //         let timer = start_timer!(|| format!("cuda backend optimize interpolate_columns,
    // column:{} log_n:{}", 1<<log_number_of_columns, log_size));         let result_optim =
    // CudaBackend::interpolate_columns(gpu_columns, &gpu_twiddles);         end_timer!(timer);

    //         let expected_coeffs = expected_result
    //             .iter()
    //             .map(|poly| poly.coeffs.clone())
    //             .collect_vec();
    //         let coeffs = result
    //             .iter()
    //             .map(|poly| poly.coeffs.clone().to_cpu())
    //             .collect_vec();
    //         let coeffs_optim = result_optim
    //             .iter()
    //             .map(|poly| poly.coeffs.clone().to_cpu())
    //             .collect_vec();

    //         assert_eq!(expected_coeffs, coeffs_optim);
    //     }
    // }

    // #[allow(unused_variables)]
    // #[test_log::test]
    // fn test_evaluate_columns() {
    //     let log_blowup_factor = 2;
    //     let log_number_of_columns = 7;

    //     for log_size in 13..20-log_blowup_factor {

    //         let size = 1 << log_size;
    //         let number_of_columns = 1 << log_number_of_columns;

    //         let cpu_values = (1..(size + 1) as u32)
    //             .map(BaseField::from)
    //             .collect::<Vec<_>>();
    //         let gpu_values = BaseFieldVec::from_vec(cpu_values.clone());

    //         let trace_coset = CanonicCoset::new(log_size);
    //         let cpu_evaluations = CpuBackend::new_canonical_ordered(trace_coset, cpu_values);
    //         let gpu_evaluations = CudaBackend::new_canonical_ordered(trace_coset,
    // gpu_values.clone());         let gpu_evaluations_ref =
    // CudaBackend::new_canonical_ordered(trace_coset, gpu_values);

    //         let interpolation_coset = CanonicCoset::new(log_size + log_blowup_factor);
    //         let cpu_twiddles = CpuBackend::precompute_twiddles(interpolation_coset.half_coset());
    //         let gpu_twiddles =
    // CudaBackend::precompute_twiddles(interpolation_coset.half_coset());

    //         let cpu_poly = CpuBackend::interpolate(cpu_evaluations, &cpu_twiddles);
    //         let gpu_poly = CudaBackend::interpolate(gpu_evaluations, &gpu_twiddles);

    //         assert_eq!(gpu_poly.coeffs.to_vec(), cpu_poly.coeffs.to_vec());

    //         let mut cpu_columns: Vec<CirclePoly<CpuBackend>> = ColumnVec::from(
    //             (0..number_of_columns)
    //                 .map(|_index| cpu_poly.clone())
    //                 .collect_vec(),
    //         );
    //         let mut gpu_columns = ColumnVec::from(
    //             (0..number_of_columns)
    //                 .map(|_index| gpu_poly.clone())
    //                 .collect_vec(),
    //         );

    //         let timer = start_timer!(|| format!("cpu backend optimize evaluate_polynomials,
    // column:{} log_n:{}", 1<<log_number_of_columns, log_size));         let expected_result =
    // CpuBackend::evaluate_polynomials(&mut cpu_columns, log_blowup_factor, &cpu_twiddles);
    //         end_timer!(timer);

    //         let timer = start_timer!(|| format!("cuda backend evaluate_polynomials, column:{}
    // log_n:{}", 1<<log_number_of_columns, log_size));         let result =
    // CudaBackend::evaluate_polynomials(&mut gpu_columns, log_blowup_factor, &gpu_twiddles);
    //         end_timer!(timer);

    //         let expected_values = expected_result
    //             .iter()
    //             .map(|eval| eval.clone().values)
    //             .collect_vec();
    //         let values = result
    //             .iter()
    //             .map(|eval| eval.clone().values.to_cpu())
    //             .collect_vec();

    //         assert_eq!(values, expected_values);
    //     }
    // }

    #[test]
    fn test_eval_at_point_log24() {
        use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;

        const LOG_SIZE: u32 = 24;
        let size = 1usize << LOG_SIZE;

        // Create a polynomial of log_size=24
        let cpu_values: Vec<BaseField> = (0..size).map(|i| BaseField::from(i as u32)).collect();
        let gpu_values = BaseFieldVec::from_vec(cpu_values.clone());

        let coset = CanonicCoset::new(LOG_SIZE);
        let domain = coset.circle_domain();

        let cpu_evaluations =
            CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, cpu_values);
        let gpu_evaluations =
            CircleEvaluation::<CudaBackend, _, BitReversedOrder>::new(domain, gpu_values);

        let cpu_twiddles = CpuBackend::precompute_twiddles(coset.half_coset());
        let gpu_twiddles = CudaBackend::precompute_twiddles(coset.half_coset());

        let cpu_poly = CpuBackend::interpolate(cpu_evaluations, &cpu_twiddles);
        let gpu_poly = CudaBackend::interpolate(gpu_evaluations, &gpu_twiddles);

        // Verify polynomials match
        assert_eq!(
            gpu_poly.coeffs.to_cpu(),
            cpu_poly.coeffs,
            "Polynomial coeffs mismatch"
        );

        // Test eval_at_point at SECURE_FIELD_CIRCLE_GEN (this is what's used in OODS)
        let point = SECURE_FIELD_CIRCLE_GEN;
        let cpu_result = CpuBackend::eval_at_point(&cpu_poly, point);
        let gpu_result = CudaBackend::eval_at_point(&gpu_poly, point);

        assert_eq!(
            gpu_result, cpu_result,
            "eval_at_point mismatch at SECURE_FIELD_CIRCLE_GEN"
        );

        // Test at another arbitrary point
        let point2 = CirclePoint::get_point(12345678);
        let cpu_result2 = CpuBackend::eval_at_point(&cpu_poly, point2);
        let gpu_result2 = CudaBackend::eval_at_point(&gpu_poly, point2);

        assert_eq!(
            gpu_result2, cpu_result2,
            "eval_at_point mismatch at arbitrary point"
        );
    }

    #[test]
    fn test_batch_eval_at_point_matches_single_and_cpu() {
        use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;

        const N_POLYS: usize = 12;
        for log_size in [5u32, 7, 20] {
            let size = 1usize << log_size;
            let coset = CanonicCoset::new(log_size);
            let domain = coset.circle_domain();

            let cpu_twiddles = CpuBackend::precompute_twiddles(coset.half_coset());
            let gpu_twiddles = CudaBackend::precompute_twiddles(coset.half_coset());

            let cpu_polys: Vec<CirclePoly<CpuBackend>> = (0..N_POLYS)
                .map(|poly_idx| {
                    let cpu_values: Vec<BaseField> = (0..size)
                        .map(|i| {
                            BaseField::from(
                                ((i as u32).wrapping_mul((poly_idx as u32) + 3))
                                    .wrapping_add((poly_idx as u32) * 17),
                            )
                        })
                        .collect();
                    let cpu_evaluations = CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(
                        domain, cpu_values,
                    );
                    CpuBackend::interpolate(cpu_evaluations, &cpu_twiddles)
                })
                .collect();

            let gpu_polys: Vec<CirclePoly<CudaBackend>> = (0..N_POLYS)
                .map(|poly_idx| {
                    let gpu_values: Vec<BaseField> = (0..size)
                        .map(|i| {
                            BaseField::from(
                                ((i as u32).wrapping_mul((poly_idx as u32) + 3))
                                    .wrapping_add((poly_idx as u32) * 17),
                            )
                        })
                        .collect();
                    let gpu_evaluations = CircleEvaluation::<CudaBackend, _, BitReversedOrder>::new(
                        domain,
                        BaseFieldVec::from_vec(gpu_values),
                    );
                    CudaBackend::interpolate(gpu_evaluations, &gpu_twiddles)
                })
                .collect();

            for (gpu_poly, cpu_poly) in gpu_polys.iter().zip(cpu_polys.iter()) {
                assert_eq!(
                    gpu_poly.coeffs.to_cpu(),
                    cpu_poly.coeffs,
                    "coefficient mismatch at log_size {log_size}"
                );
            }

            for point in [SECURE_FIELD_CIRCLE_GEN, CirclePoint::get_point(12_345_678)] {
                let cpu_results: Vec<_> = cpu_polys
                    .iter()
                    .map(|poly| CpuBackend::eval_at_point(poly, point))
                    .collect();
                let gpu_single_results: Vec<_> = gpu_polys
                    .iter()
                    .map(|poly| CudaBackend::eval_at_point(poly, point))
                    .collect();
                let gpu_poly_refs: Vec<_> = gpu_polys.iter().collect();
                let gpu_batch_results = CudaBackend::batch_eval_at_point(&gpu_poly_refs, point);

                assert_eq!(
                    gpu_single_results, cpu_results,
                    "single eval_at_point mismatch at log_size {log_size}, point {:?}",
                    point
                );
                assert_eq!(
                    gpu_batch_results, cpu_results,
                    "batch_eval_at_point mismatch against CPU at log_size {log_size}, point {:?}",
                    point
                );
                assert_eq!(
                    gpu_batch_results, gpu_single_results,
                    "batch_eval_at_point mismatch against CUDA single-path at log_size {log_size}, point {:?}",
                    point
                );
            }
        }
    }
}

impl CudaBackend {
    /// Batched OODS evaluation (not part of the current `PolyOps` surface).
    #[allow(dead_code)]
    pub(crate) fn batch_eval_at_point(
        polys: &[&CirclePoly<CudaBackend>],
        point: CirclePoint<SecureField>,
    ) -> Vec<SecureField> {
        cuda_batch_eval_at_point(polys, point)
    }
}

#[cfg(test)]
mod ntt_batch_chunks_tests {
    use super::{ntt_batch_chunks, MAX_NTT_BATCH_COLUMNS};

    fn collect(num_poly: usize, max: usize) -> Vec<(usize, usize)> {
        ntt_batch_chunks(num_poly, max).collect()
    }

    #[test]
    fn empty_group_produces_no_launches() {
        assert!(collect(0, MAX_NTT_BATCH_COLUMNS).is_empty());
    }

    #[test]
    fn within_limit_is_a_single_unchanged_launch() {
        assert_eq!(collect(1, MAX_NTT_BATCH_COLUMNS), vec![(0, 1)]);
        assert_eq!(collect(230, MAX_NTT_BATCH_COLUMNS), vec![(0, 230)]);
        assert_eq!(
            collect(MAX_NTT_BATCH_COLUMNS, MAX_NTT_BATCH_COLUMNS),
            vec![(0, MAX_NTT_BATCH_COLUMNS)]
        );
    }

    #[test]
    fn one_past_the_grid_cap_splits_in_two() {
        // 65536 columns: grid.y = 65536 > 65535 would fail as one launch.
        assert_eq!(
            collect(MAX_NTT_BATCH_COLUMNS + 1, MAX_NTT_BATCH_COLUMNS),
            vec![(0, MAX_NTT_BATCH_COLUMNS), (MAX_NTT_BATCH_COLUMNS, 1)]
        );
    }

    #[test]
    fn chunks_partition_the_range_and_respect_the_cap() {
        let max = 7;
        for num_poly in 0..60 {
            let chunks = collect(num_poly, max);
            let mut expected_base = 0;
            let mut total = 0;
            for &(base, len) in &chunks {
                assert_eq!(base, expected_base, "chunks must be contiguous");
                assert!(len > 0 && len <= max, "each chunk within the cap");
                expected_base += len;
                total += len;
            }
            assert_eq!(
                total, num_poly,
                "chunks must cover every column exactly once"
            );
            // Only the final chunk may be short.
            for &(_, len) in chunks.iter().take(chunks.len().saturating_sub(1)) {
                assert_eq!(len, max);
            }
        }
    }

    #[test]
    fn row_block_axis_tiling_at_log_26() {
        // Mirrors the CUDA-side MAX_Y_BLOCKS row-block tiling in the legacy
        // batch NTT paths (`evaluate_columns`/`interpolate_columns`): a 2^26-row
        // domain with 1024-thread blocks yields 65536 row-blocks, one past the
        // grid.y cap, and must split into exactly two contiguous chunks.
        let row_blocks = (1usize << 26) / 1024; // 65536
        assert_eq!(
            collect(row_blocks, MAX_NTT_BATCH_COLUMNS),
            vec![(0, MAX_NTT_BATCH_COLUMNS), (MAX_NTT_BATCH_COLUMNS, 1)]
        );
        // One block fewer fits in a single launch.
        assert_eq!(collect(row_blocks - 1, MAX_NTT_BATCH_COLUMNS).len(), 1);
    }

    #[test]
    fn oversized_pie_group_never_exceeds_grid_cap() {
        // Representative of a same-log_size column family in a 14M-step PIE that
        // exceeds the CUDA grid.y/grid.z cap and previously failed at rfft.cu.
        let num_poly = 200_000;
        let chunks = collect(num_poly, MAX_NTT_BATCH_COLUMNS);
        assert_eq!(chunks.len(), num_poly.div_ceil(MAX_NTT_BATCH_COLUMNS));
        assert!(chunks.iter().all(|&(_, len)| len <= MAX_NTT_BATCH_COLUMNS));
        assert_eq!(chunks.iter().map(|&(_, l)| l).sum::<usize>(), num_poly);
    }
}
