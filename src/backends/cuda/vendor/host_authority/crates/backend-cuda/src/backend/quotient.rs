use itertools::Itertools;
use stwo::core::fields::m31::BaseField;
use stwo::core::pcs::quotients::{quotient_constants, ColumnSampleBatch};
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::Column;
use stwo::prover::pcs::quotient_ops::AccumulatedNumerators;
use stwo::prover::poly::circle::{CircleEvaluation, SecureEvaluation};
use stwo::prover::poly::twiddles::{TwiddleBuffer, TwiddleTree};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::secure_column::SecureColumnByCoords;
use stwo::prover::QuotientOps;

use crate::backend::{CudaBackend, UploadedDevicePointerVec};
use crate::columns::bindings::{self, CirclePointSecureField, CudaSecureField};

/// Kill switch for Workstream-E quotient-combine + first-FRI-fold fusion (the "VRAM
/// diet"). Default **OFF** — the fused device path is not yet pod-validated, so until
/// its differential gate (`STWO_CUDA_WITNESS_VERIFY`-style: fused vs. the proven
/// combine→interpolate→evaluate→fold pipeline, column byte-compare) passes on hardware,
/// the switch must default off per the round-9 gating rules.
///
/// `STWO_CUDA_FUSED_QUOTIENT_FOLD=1` (or any non-empty, non-`0` value) opts in; unset /
/// empty / `0` keeps the byte-identical reference path. The integration agent bisects
/// with this switch, so it gates exactly one lane.
pub fn fused_quotient_fold_enabled() -> bool {
    parse_fused_quotient_fold(std::env::var("STWO_CUDA_FUSED_QUOTIENT_FOLD").ok())
}

/// Pure parser for the fusion kill switch, factored out for unit testing.
pub(crate) fn parse_fused_quotient_fold(raw: Option<String>) -> bool {
    matches!(raw.as_deref().map(str::trim), Some(v) if !v.is_empty() && v != "0")
}

impl QuotientOps for CudaBackend {
    fn accumulate_numerators(
        columns: &[&CircleEvaluation<Self, BaseField, BitReversedOrder>],
        sample_batches: &[ColumnSampleBatch],
        accumulated_numerators_vec: &mut Vec<AccumulatedNumerators<Self>>,
        log_blowup_factor: u32,
    ) {
        if columns.is_empty() || sample_batches.is_empty() {
            return;
        }

        // Subdomain semantics: numerators are accumulated on the evaluation subdomain,
        // i.e. the first `len >> log_blowup_factor` bit-reversed entries of each column.
        let size = columns[0].len() >> log_blowup_factor;
        let quotient_constants = quotient_constants(sample_batches);
        let device_column_pointers_vector = columns
            .iter()
            .map(|column| column.values.device_ptr)
            .collect_vec();
        let device_column_pointers =
            UploadedDevicePointerVec::upload(&device_column_pointers_vector);

        for (batch, coeffs) in sample_batches.iter().zip(quotient_constants.line_coeffs) {
            if batch.cols_vals_randpows.is_empty() {
                accumulated_numerators_vec.push(AccumulatedNumerators {
                    sample_point: batch.point,
                    partial_numerators_acc: SecureColumnByCoords::zeros(size),
                    first_linear_term_acc: coeffs.into_iter().map(|(a, ..)| a).sum(),
                });
                continue;
            }

            let sample_column_indexes = batch
                .cols_vals_randpows
                .iter()
                .map(|data| data.column_index as u32)
                .collect_vec();
            let line_coeffs_b = coeffs
                .iter()
                .map(|(_, b, _)| CudaSecureField::from(*b))
                .collect_vec();
            let line_coeffs_c = coeffs
                .iter()
                .map(|(_, _, c)| CudaSecureField::from(*c))
                .collect_vec();
            let first_linear_term_acc = coeffs.iter().map(|(a, ..)| *a).sum();
            let partial_numerators_acc: SecureColumnByCoords<CudaBackend> =
                unsafe { SecureColumnByCoords::uninitialized(size) };

            unsafe {
                bindings::accumulate_partial_quotient_numerators(
                    size as u32,
                    device_column_pointers.as_ptr(),
                    sample_column_indexes.as_ptr(),
                    sample_column_indexes.len() as u32,
                    line_coeffs_b.as_ptr(),
                    line_coeffs_c.as_ptr(),
                    partial_numerators_acc.columns[0].device_ptr,
                    partial_numerators_acc.columns[1].device_ptr,
                    partial_numerators_acc.columns[2].device_ptr,
                    partial_numerators_acc.columns[3].device_ptr,
                );
            }

            accumulated_numerators_vec.push(AccumulatedNumerators {
                sample_point: batch.point,
                partial_numerators_acc,
                first_linear_term_acc,
            });
        }
    }

    fn compute_quotients_and_combine(
        accs: Vec<AccumulatedNumerators<Self>>,
        lifting_log_size: u32,
        log_blowup_factor: u32,
        twiddles: &TwiddleTree<Self>,
    ) -> SecureEvaluation<Self, BitReversedOrder> {
        let eval_domain = CanonicCoset::new(lifting_log_size).circle_domain();
        let (eval_subdomain, _) = eval_domain.split(log_blowup_factor);
        // The combine kernel runs on the evaluation subdomain; the result is then
        // interpolated and re-evaluated on the full domain (mirroring the reference
        // backend's subdomain-accumulate semantics exactly).
        let domain = eval_subdomain;
        let domain_size = domain.size();

        if accs.is_empty() {
            return SecureEvaluation::new(
                eval_domain,
                SecureColumnByCoords::zeros(eval_domain.size()),
            );
        }

        let sample_points = accs
            .iter()
            .map(|acc| CirclePointSecureField::from(acc.sample_point))
            .collect_vec();
        let first_linear_term_accs = accs
            .iter()
            .map(|acc| CudaSecureField::from(acc.first_linear_term_acc))
            .collect_vec();
        let partial_numerator_log_sizes = accs
            .iter()
            .map(|acc| {
                let log_size = acc.partial_numerators_acc.len().ilog2();
                assert!(
                    log_size <= lifting_log_size,
                    "partial numerator log size {log_size} exceeds lifting log size {lifting_log_size}"
                );
                log_size
            })
            .collect_vec();
        let partial_numerator_column_ptrs: [Vec<*const u32>; 4] = std::array::from_fn(|coord| {
            accs.iter()
                .map(|acc| acc.partial_numerators_acc.columns[coord].device_ptr)
                .collect_vec()
        });
        let uploaded_partial_numerator_columns = partial_numerator_column_ptrs
            .each_ref()
            .map(|host_ptrs| UploadedDevicePointerVec::upload(host_ptrs.as_slice()));

        let quotients: SecureColumnByCoords<CudaBackend> =
            unsafe { SecureColumnByCoords::uninitialized(domain_size) };

        unsafe {
            bindings::combine_quotients_from_numerators(
                domain.half_coset.initial_index.0 as u32,
                domain.half_coset.step_size.0 as u32,
                domain_size as u32,
                domain.log_size(),
                sample_points.as_ptr(),
                sample_points.len() as u32,
                first_linear_term_accs.as_ptr(),
                partial_numerator_log_sizes.as_ptr(),
                uploaded_partial_numerator_columns[0].as_ptr(),
                uploaded_partial_numerator_columns[1].as_ptr(),
                uploaded_partial_numerator_columns[2].as_ptr(),
                uploaded_partial_numerator_columns[3].as_ptr(),
                quotients.columns[0].device_ptr,
                quotients.columns[1].device_ptr,
                quotients.columns[2].device_ptr,
                quotients.columns[3].device_ptr,
            );
        }

        // Interpolate on the subdomain and evaluate on the full domain, with itwiddles
        // extracted for the subdomain (same construction as the reference backend).
        // The four QM31 coordinate columns share both domain sizes, so the eight
        // single-column NTTs the per-coordinate path would issue collapse into one
        // batched inverse NTT plus one batched forward NTT.
        let subdomain_twiddles = TwiddleTree {
            root_coset: eval_subdomain.half_coset,
            twiddles: TwiddleBuffer::empty(),
            itwiddles: twiddles
                .itwiddles
                .extract_subdomain_twiddles(eval_domain.log_size(), eval_subdomain.log_size()),
        };
        // Borrow the forward twiddles instead of cloning: `clone` on a device column
        // is a fresh allocation plus a full D2D copy of the entire twiddle buffer.
        // The borrow is safe — `full_twiddles` lives only within this call and
        // `twiddles` (the argument) outlives it; the borrowed column never frees.
        let full_twiddles = TwiddleTree {
            root_coset: eval_domain.half_coset,
            twiddles: crate::columns::base_field_vec::BaseFieldVec::from_borrowed_ptr(
                twiddles.twiddles.device_ptr,
                twiddles.twiddles.size,
            ),
            itwiddles: TwiddleBuffer::empty(),
        };

        if eval_subdomain.log_size() <= 3 {
            // Tiny domains use the reference CPU path inside interpolate/evaluate.
            let evals = SecureColumnByCoords {
                columns: quotients.columns.map(|column| {
                    CircleEvaluation::<Self, BaseField, BitReversedOrder>::new(
                        eval_subdomain,
                        column,
                    )
                    .interpolate_with_twiddles(&subdomain_twiddles)
                    .evaluate_with_twiddles(eval_domain, &full_twiddles)
                    .values
                }),
            };
            return SecureEvaluation::new(eval_domain, evals);
        }

        // Batched interpolate: one inverse NTT over the 4 coordinate columns in place.
        let mut interp_ptrs: Vec<*mut u32> = quotients
            .columns
            .iter()
            .map(|column| column.device_ptr as *mut u32)
            .collect();
        unsafe {
            bindings::ntt_b2n_column(
                interp_ptrs.as_mut_ptr(),
                eval_subdomain.log_size(),
                4,
                subdomain_twiddles.itwiddles.device_ptr,
                subdomain_twiddles.itwiddles.len() as u32,
                eval_subdomain.half_coset.size() as u32,
            );
        }

        // ── Workstream-E fusion seam (STWO_CUDA_FUSED_QUOTIENT_FOLD) ──────────────
        // The lines below materialize the FULL secure-field quotient LDE (`eval_columns`,
        // 4 coordinate columns of `eval_domain.size()`). At `lifting_log_size = 24` that
        // is 4 × 2^24 × 4 B = 1 GiB, and it is the allocation that pushes 14M-step PIEs
        // past 46 GB (RESULTS.md round 8). The fusion goal is to never hold this buffer:
        // emit the forward-NTT output straight into (a) the first-layer Merkle leaf hash
        // and (b) the first `fold_circle_into_line`, streaming per tile.
        //
        // IMPORTANT (discovered while scoping): the first-layer `column` is consumed
        // TWICE downstream — `FriFirstLayerProver::new` commits a Merkle tree over the
        // full LDE (needed for query decommit), AND `fold_circle_into_line` folds it.
        // So the fused kernel must feed the Merkle-leaf hash as well as the fold; it is a
        // quotients.cu + fri.cu + first-layer-commit change, hence pod-gated and OFF by
        // default. Value-identity plan: field add/sub/mul are exact (M31/QM31), the fold
        // butterfly and combine arithmetic are already byte-equal-proven on device; the
        // ONLY reordering is fusing the forward-NTT final stage with the fold read, which
        // is value-identical because the fold reads each NTT output element exactly once
        // in the same (bit-reversed) index order. Gate: differential vs. this reference
        // path (below), then Cairo e2e byte-equality.
        //
        // Until that lands and its pod gate is green, enabling the switch keeps the
        // proven path (below) so nothing regresses; the switch reserves the lane and lets
        // the integration agent bisect once the kernel is wired.
        if fused_quotient_fold_enabled() {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                eprintln!(
                    "[stwo-cuda] STWO_CUDA_FUSED_QUOTIENT_FOLD is set but the fused \
                     quotient+FRI-fold kernel is pod-gated and not yet wired; using the \
                     proven combine→interpolate→evaluate path (no behavior change)."
                );
            });
        }

        // Batched evaluate: extend each coefficient column into a full-domain buffer
        // (coefficients + zero tail), then one forward NTT over the 4 buffers.
        let eval_columns = quotients.columns.map(|coeffs| {
            let mut buffer =
                crate::columns::base_field_vec::BaseFieldVec::new_uninitialized(eval_domain.size());
            buffer.copy_from(&coeffs);
            unsafe {
                bindings::cuda_zero_device_region(
                    buffer.device_ptr,
                    coeffs.len() as u64,
                    (eval_domain.size() - coeffs.len()) as u64,
                );
            }
            buffer
        });
        let mut eval_ptrs: Vec<*mut u32> = eval_columns
            .iter()
            .map(|column| column.device_ptr as *mut u32)
            .collect();
        unsafe {
            bindings::ntt_n2b_columns(
                eval_ptrs.as_mut_ptr(),
                eval_domain.log_size(),
                4,
                full_twiddles.twiddles.device_ptr,
                full_twiddles.twiddles.len() as u32,
                eval_domain.half_coset.size() as u32,
            );
        }

        SecureEvaluation::new(
            eval_domain,
            SecureColumnByCoords {
                columns: eval_columns,
            },
        )
    }
}

#[cfg(any())] // legacy (pre-lifted-merkle) test, superseded by the testkit
mod tests {
    use itertools::Itertools;
    use num_traits::Zero;
    use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;
    use stwo::core::fields::m31::{BaseField, M31};
    use stwo::core::fields::qm31::QM31;
    use stwo::core::pcs::quotients::ColumnSampleBatch;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::prover::backend::simd::column::BaseColumn;
    use stwo::prover::backend::{Column, CpuBackend};
    use stwo::prover::poly::circle::CircleEvaluation;
    use stwo::prover::poly::twiddles::{TwiddleBuffer, TwiddleTree};
    use stwo::prover::poly::BitReversedOrder;
    use stwo::prover::QuotientOps;

    use crate::backend::CudaBackend;
    use crate::columns::base_field_vec::BaseFieldVec;
    #[test]
    fn test_accumulate_quotients_compared_with_cpu() {
        const LOG_SIZE: u32 = 5;
        const LOG_BLOWUP_FACTOR: u32 = 1;
        let small_domain = CanonicCoset::new(LOG_SIZE).circle_domain();
        let domain = CanonicCoset::new(LOG_SIZE + LOG_BLOWUP_FACTOR).circle_domain();
        let e0: BaseColumn = (0..small_domain.size()).map(BaseField::from).collect();
        let e1: BaseColumn = (0..small_domain.size())
            .map(|i| BaseField::from(2 * i))
            .collect();
        let polys = vec![
            CircleEvaluation::<CudaBackend, BaseField, BitReversedOrder>::new(
                small_domain,
                BaseFieldVec::from_vec(e0.to_cpu()),
            )
            .interpolate(),
            CircleEvaluation::<CudaBackend, BaseField, BitReversedOrder>::new(
                small_domain,
                BaseFieldVec::from_vec(e1.to_cpu()),
            )
            .interpolate(),
        ];
        let columns = vec![polys[0].evaluate(domain), polys[1].evaluate(domain)];
        let random_coeff = QM31::from_m31(M31::from(1), M31::from(2), M31::from(3), M31::from(4));
        let a = polys[0].eval_at_point(SECURE_FIELD_CIRCLE_GEN);
        let b = polys[1].eval_at_point(SECURE_FIELD_CIRCLE_GEN);
        let samples = vec![
            ColumnSampleBatch {
                point: SECURE_FIELD_CIRCLE_GEN,
                columns_and_values: vec![(0, a), (1, b)],
            },
            ColumnSampleBatch {
                point: SECURE_FIELD_CIRCLE_GEN,
                columns_and_values: vec![(0, a), (1, b)],
            },
            ColumnSampleBatch {
                point: SECURE_FIELD_CIRCLE_GEN,
                columns_and_values: vec![(0, a), (1, b)],
            },
        ];
        let cpu_columns = columns
            .iter()
            .map(|c| {
                CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(
                    c.domain,
                    c.values.to_cpu(),
                )
            })
            .collect_vec();

        let cpu_result = CpuBackend::accumulate_quotients(
            domain,
            &cpu_columns.iter().collect_vec(),
            random_coeff,
            &samples,
            LOG_BLOWUP_FACTOR,
        )
        .values
        .to_vec();

        let gpu_result = CudaBackend::accumulate_quotients(
            domain,
            &columns.iter().collect_vec(),
            random_coeff,
            &samples,
            LOG_BLOWUP_FACTOR,
        )
        .values
        .to_cpu()
        .to_vec();

        assert_eq!(gpu_result, cpu_result);
    }

    #[test]
    fn test_accumulate_quotients_compared_with_cpu_expend() {
        let log_size: u32 = 6;
        let log_blowup_factor: u32 = 1;
        let num_columns: usize = 4;

        let small_domain = CanonicCoset::new(log_size).circle_domain();
        let domain = CanonicCoset::new(log_size + log_blowup_factor).circle_domain();

        let base_columns: Vec<BaseColumn> = (0..num_columns)
            .map(|i| {
                (0..small_domain.size())
                    .map(|j| BaseField::from((i + 1) * j))
                    .collect()
            })
            .collect();

        let polys: Vec<_> = base_columns
            .iter()
            .map(|col| {
                CircleEvaluation::<CudaBackend, BaseField, BitReversedOrder>::new(
                    small_domain,
                    BaseFieldVec::from_vec(col.to_cpu()),
                )
                .interpolate()
            })
            .collect();

        let columns: Vec<_> = polys.iter().map(|poly| poly.evaluate(domain)).collect();

        let random_coeff = QM31::from_m31(
            M31::from(1208161154),
            M31::from(1460422684),
            M31::from(150901284),
            M31::from(373213585),
        );

        let samples: Vec<ColumnSampleBatch> = (0..num_columns)
            .map(|i| {
                let point = SECURE_FIELD_CIRCLE_GEN;
                let value = polys[i].eval_at_point(point);
                ColumnSampleBatch {
                    point,
                    columns_and_values: vec![(i, value)],
                }
            })
            .collect();

        let cpu_columns: Vec<_> = columns
            .iter()
            .map(|c| {
                CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(
                    c.domain,
                    c.values.to_cpu(),
                )
            })
            .collect();

        let cpu_result = CpuBackend::accumulate_quotients(
            domain,
            &cpu_columns.iter().collect_vec(),
            random_coeff,
            &samples,
            log_blowup_factor,
        )
        .values
        .to_vec();

        let gpu_result = CudaBackend::accumulate_quotients(
            domain,
            &columns.iter().collect_vec(),
            random_coeff,
            &samples,
            log_blowup_factor,
        )
        .values
        .to_cpu()
        .to_vec();

        assert_eq!(gpu_result, cpu_result);

        let log_size: u32 = 4;
        let log_blowup_factor: u32 = 1;
        let num_columns: usize = 325;

        let small_domain = CanonicCoset::new(log_size).circle_domain();
        let domain = CanonicCoset::new(log_size + log_blowup_factor).circle_domain();

        let base_columns: Vec<BaseColumn> = (0..num_columns)
            .map(|i| {
                (0..small_domain.size())
                    .map(|j| {
                        if (317..320).contains(&i) {
                            BaseField::zero()
                        } else if (321..324).contains(&i) {
                            BaseField::zero()
                        } else {
                            BaseField::from((i + 1) * j)
                        }
                    })
                    .collect()
            })
            .collect();

        let polys: Vec<_> = base_columns
            .iter()
            .map(|col| {
                CircleEvaluation::<CudaBackend, BaseField, BitReversedOrder>::new(
                    small_domain,
                    BaseFieldVec::from_vec(col.to_cpu()),
                )
                .interpolate()
            })
            .collect();

        let columns: Vec<_> = polys.iter().map(|poly| poly.evaluate(domain)).collect();

        let random_coeff = QM31::from_m31(
            M31::from(1208161154),
            M31::from(1460422684),
            M31::from(150901284),
            M31::from(373213585),
        );

        let samples: Vec<ColumnSampleBatch> = (0..num_columns)
            .map(|i| {
                let point = SECURE_FIELD_CIRCLE_GEN;
                let value = polys[i].eval_at_point(point);
                ColumnSampleBatch {
                    point,
                    columns_and_values: vec![(i, value)],
                }
            })
            .collect();

        let cpu_columns: Vec<_> = columns
            .iter()
            .map(|c| {
                CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(
                    c.domain,
                    c.values.to_cpu(),
                )
            })
            .collect();

        let cpu_result = CpuBackend::accumulate_quotients(
            domain,
            &cpu_columns.iter().collect_vec(),
            random_coeff,
            &samples,
            log_blowup_factor,
        )
        .values
        .to_vec();

        let gpu_result = CudaBackend::accumulate_quotients(
            domain,
            &columns.iter().collect_vec(),
            random_coeff,
            &samples,
            log_blowup_factor,
        )
        .values
        .to_cpu()
        .to_vec();

        assert_eq!(gpu_result, cpu_result);
    }

    #[test]
    fn test_accumulate_quotients_log24() {
        // Test accumulate_quotients at log_size=24 to check for size-related issues
        const LOG_SIZE: u32 = 24;
        const LOG_BLOWUP_FACTOR: u32 = 1;
        let small_domain = CanonicCoset::new(LOG_SIZE).circle_domain();
        let domain = CanonicCoset::new(LOG_SIZE + LOG_BLOWUP_FACTOR).circle_domain();

        // Create a simple column with pattern values
        let e0: Vec<BaseField> = (0..small_domain.size())
            .map(|i| BaseField::from(i as u32))
            .collect();

        let poly = CircleEvaluation::<CudaBackend, BaseField, BitReversedOrder>::new(
            small_domain,
            BaseFieldVec::from_vec(e0.clone()),
        )
        .interpolate();

        let column = poly.evaluate(domain);
        let columns = vec![column];

        let random_coeff = QM31::from_m31(M31::from(1), M31::from(2), M31::from(3), M31::from(4));
        let sample_value = poly.eval_at_point(SECURE_FIELD_CIRCLE_GEN);
        let samples = vec![ColumnSampleBatch {
            point: SECURE_FIELD_CIRCLE_GEN,
            columns_and_values: vec![(0, sample_value)],
        }];

        // CPU reference
        let cpu_column = CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(
            domain,
            columns[0].values.to_cpu(),
        );
        let cpu_columns = vec![cpu_column];

        let cpu_result = CpuBackend::accumulate_quotients(
            domain,
            &cpu_columns.iter().collect_vec(),
            random_coeff,
            &samples,
            LOG_BLOWUP_FACTOR,
        )
        .values
        .to_vec();

        let gpu_result = CudaBackend::accumulate_quotients(
            domain,
            &columns.iter().collect_vec(),
            random_coeff,
            &samples,
            LOG_BLOWUP_FACTOR,
        )
        .values
        .to_cpu()
        .to_vec();

        // Check first 1000 elements for quick verification
        assert_eq!(
            gpu_result[..1000],
            cpu_result[..1000],
            "First 1000 elements mismatch"
        );
        // Check last 1000 elements
        let len = gpu_result.len();
        assert_eq!(
            gpu_result[len - 1000..],
            cpu_result[len - 1000..],
            "Last 1000 elements mismatch"
        );
        // Full equality check
        assert_eq!(gpu_result, cpu_result);
    }
}

#[cfg(test)]
mod fusion_flag_tests {
    use super::parse_fused_quotient_fold;

    #[test]
    fn kill_switch_defaults_off_and_parses() {
        // Default OFF: unset / empty / "0" / whitespace.
        assert!(!parse_fused_quotient_fold(None));
        assert!(!parse_fused_quotient_fold(Some("".into())));
        assert!(!parse_fused_quotient_fold(Some("0".into())));
        assert!(!parse_fused_quotient_fold(Some("  ".into())));
        assert!(!parse_fused_quotient_fold(Some(" 0 ".into())));
        // Opt in: any non-empty, non-"0" value.
        assert!(parse_fused_quotient_fold(Some("1".into())));
        assert!(parse_fused_quotient_fold(Some(" 1 ".into())));
        assert!(parse_fused_quotient_fold(Some("on".into())));
    }
}
