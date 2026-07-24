use std::array;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use num_traits::Zero;
use stwo::core::circle::Coset;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;

/// The circle->line fold halves the domain (upstream removed the named constant).
const CIRCLE_TO_LINE_FOLD_STEP: u32 = 1;
use stwo::core::poly::circle::{CanonicCoset, CircleDomain};
use stwo::core::poly::line::{LineDomain, LinePoly};
use stwo::core::utils::bit_reverse_index;
use stwo::prover::fri::FriOps;
use stwo::prover::line::LineEvaluation;
use stwo::prover::poly::circle::SecureEvaluation;
use stwo::prover::poly::twiddles::TwiddleTree;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::secure_column::SecureColumnByCoords;
use stwo_backend_metal_sys::metal::U32Buffer;

use super::line::interpolate_line_polynomial;
use super::MetalBackend;
use crate::columns::base_field_vec::BaseFieldVec;
use crate::columns::secure_field_vec::SecureFieldVec;

type DomainFactorCache = Mutex<BTreeMap<(usize, usize, u32), Arc<U32Buffer>>>;

fn line_inverse_x_factor_cache() -> &'static DomainFactorCache {
    static CACHE: OnceLock<DomainFactorCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn circle_inverse_y_factor_cache() -> &'static DomainFactorCache {
    static CACHE: OnceLock<DomainFactorCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn cached_line_inverse_x_factors(domain: LineDomain) -> Arc<U32Buffer> {
    let coset = domain.coset();
    let key = (coset.initial_index.0, coset.step_size.0, coset.log_size());
    if let Some(factors) = line_inverse_x_factor_cache()
        .lock()
        .expect("line inverse-x factor cache mutex should not be poisoned")
        .get(&key)
        .cloned()
    {
        return factors;
    }

    let factors = Arc::new(
        U32Buffer::from_slice(
            &(0..(domain.size() >> 1))
                .map(|i| {
                    domain
                        .at(bit_reverse_index(i << 1, domain.log_size()))
                        .inverse()
                        .0
                })
                .collect::<Vec<_>>(),
        )
        .expect("Metal inverse-x factor upload should initialize"),
    );
    line_inverse_x_factor_cache()
        .lock()
        .expect("line inverse-x factor cache mutex should not be poisoned")
        .insert(key, factors.clone());
    factors
}

fn cached_circle_inverse_y_factors(domain: CircleDomain) -> Arc<U32Buffer> {
    let coset = domain.half_coset;
    let key = (coset.initial_index.0, coset.step_size.0, domain.log_size());
    if let Some(factors) = circle_inverse_y_factor_cache()
        .lock()
        .expect("circle inverse-y factor cache mutex should not be poisoned")
        .get(&key)
        .cloned()
    {
        return factors;
    }

    let factors = Arc::new(
        U32Buffer::from_slice(
            &(0..(domain.size() >> CIRCLE_TO_LINE_FOLD_STEP))
                .map(|i| {
                    domain
                        .at(bit_reverse_index(
                            i << CIRCLE_TO_LINE_FOLD_STEP,
                            domain.log_size(),
                        ))
                        .y
                        .inverse()
                        .0
                })
                .collect::<Vec<_>>(),
        )
        .expect("Metal inverse-y factor upload should initialize"),
    );
    circle_inverse_y_factor_cache()
        .lock()
        .expect("circle inverse-y factor cache mutex should not be poisoned")
        .insert(key, factors.clone());
    factors
}

/// CPU-only computation of all FRI inverse factor vectors for a given
/// lifting_log_size and FRI config.  Returns raw u32 vectors that can be
/// uploaded to the GPU caches later via [`upload_fri_factors`].
///
/// This is safe to call on a background thread since it does no GPU work.
#[allow(dead_code)]
pub fn precompute_fri_factors_cpu(
    lifting_log_size: u32,
    fri_config: &FriConfig,
) -> PrecomputedFriFactors {
    let circle_domain = CanonicCoset::new(lifting_log_size).circle_domain();

    // Circle-to-line inverse-y factors (first layer).
    let n_circle_factors = circle_domain.size() >> CIRCLE_TO_LINE_FOLD_STEP;
    let circle_y_factors: Vec<u32> = (0..n_circle_factors)
        .map(|i| {
            circle_domain
                .at(bit_reverse_index(
                    i << CIRCLE_TO_LINE_FOLD_STEP,
                    circle_domain.log_size(),
                ))
                .y
                .inverse()
                .0
        })
        .collect();

    // Line inverse-x factors for each inner fold layer.
    let line_domain_log_size = lifting_log_size - CIRCLE_TO_LINE_FOLD_STEP;
    let last_layer_log_domain_size = fri_config.last_layer_domain_size().ilog2();
    let mut domain = LineDomain::new(Coset::half_odds(line_domain_log_size));
    let mut line_factors = Vec::new();
    while domain.log_size() > last_layer_log_domain_size {
        let n_factors = domain.size() >> 1;
        let factors: Vec<u32> = (0..n_factors)
            .map(|i| {
                domain
                    .at(bit_reverse_index(i << 1, domain.log_size()))
                    .inverse()
                    .0
            })
            .collect();
        let coset = domain.coset();
        let key = (coset.initial_index.0, coset.step_size.0, coset.log_size());
        line_factors.push((key, factors));
        domain = domain.double();
    }

    PrecomputedFriFactors {
        circle_domain,
        circle_y_factors,
        line_factors,
    }
}

/// Pre-computed FRI factors (CPU-side vectors).
#[allow(dead_code)]
pub struct PrecomputedFriFactors {
    circle_domain: CircleDomain,
    circle_y_factors: Vec<u32>,
    line_factors: Vec<((usize, usize, u32), Vec<u32>)>,
}

/// Upload pre-computed FRI factors to the GPU caches.
#[allow(dead_code)]
pub fn upload_fri_factors(factors: PrecomputedFriFactors) {
    // Upload circle-to-line factors.
    {
        let coset = factors.circle_domain.half_coset;
        let key = (
            coset.initial_index.0,
            coset.step_size.0,
            factors.circle_domain.log_size(),
        );
        let buffer = Arc::new(
            U32Buffer::from_slice(&factors.circle_y_factors)
                .expect("Metal FRI inverse-y factor upload should initialize"),
        );
        circle_inverse_y_factor_cache()
            .lock()
            .expect("circle inverse-y factor cache mutex should not be poisoned")
            .insert(key, buffer);
    }

    // Upload line fold factors.
    {
        let mut cache = line_inverse_x_factor_cache()
            .lock()
            .expect("line inverse-x factor cache mutex should not be poisoned");
        for (key, factor_vec) in factors.line_factors {
            let buffer = Arc::new(
                U32Buffer::from_slice(&factor_vec)
                    .expect("Metal FRI inverse-x factor upload should initialize"),
            );
            cache.insert(key, buffer);
        }
    }
}

#[allow(dead_code)]
pub fn fold_circle_into_line_first_layer(
    src: &SecureFieldVec,
    domain: CircleDomain,
    alpha: SecureField,
) -> SecureFieldVec {
    assert_eq!(
        src.len(),
        domain.size(),
        "FRI first-layer fold requires one secure-field value per domain point"
    );

    let inverse_y_factors = cached_circle_inverse_y_factors(domain);
    src.fold_circle_into_line_first_layer_with_factor_buffer(inverse_y_factors.as_ref(), alpha)
}

#[allow(dead_code)]
pub fn fold_line(
    src: &SecureFieldVec,
    mut domain: LineDomain,
    alpha: SecureField,
    fold_step: u32,
) -> SecureFieldVec {
    assert!(
        fold_step >= 1,
        "FRI line fold requires a positive fold_step"
    );
    assert_eq!(
        src.len(),
        domain.size(),
        "FRI line fold requires one secure-field value per domain point"
    );
    assert!(
        domain.log_size() >= fold_step,
        "FRI line fold cannot remove more layers than the domain contains"
    );

    let mut current = src.clone();
    let mut current_alpha = alpha;
    for _ in 0..fold_step {
        // Use the cached GPU-resident inverse-x factor buffer instead of
        // recomputing on CPU and uploading each fold step. This eliminates
        // an O(n/2) CPU-to-GPU upload per fold layer.
        let cached_factors = cached_line_inverse_x_factors(domain);
        current = current.fold_line_step_with_factor_buffer(cached_factors.as_ref(), current_alpha);
        domain = domain.double();
        current_alpha = current_alpha * current_alpha;
    }

    current
}

fn metal_line_evaluation_from_base_coords(
    domain: LineDomain,
    columns: [BaseFieldVec; 4],
) -> LineEvaluation<MetalBackend> {
    LineEvaluation::new(domain, SecureColumnByCoords { columns })
}

impl MetalBackend {
    /// GPU last-layer line interpolation (not part of `FriOps` at the current stwo rev).
    #[allow(dead_code)]
    pub(crate) fn interpolate_line(evaluation: LineEvaluation<Self>) -> LinePoly {
        interpolate_line_polynomial(&super::line::MetalLineEvaluation::new(
            evaluation.domain(),
            SecureFieldVec::from_base_coords([
                &evaluation.values.columns[0],
                &evaluation.values.columns[1],
                &evaluation.values.columns[2],
                &evaluation.values.columns[3],
            ]),
        ))
    }
}

impl FriOps for MetalBackend {
    fn fold_circle_into_line(
        src: &SecureEvaluation<Self, BitReversedOrder>,
        alpha: SecureField,
        _twiddles: &TwiddleTree<Self>,
    ) -> LineEvaluation<Self> {
        let inverse_y_factors = cached_circle_inverse_y_factors(src.domain);
        let columns =
            SecureFieldVec::fold_circle_into_line_first_layer_base_coords_with_factor_buffer(
                [
                    &src.values.columns[0],
                    &src.values.columns[1],
                    &src.values.columns[2],
                    &src.values.columns[3],
                ],
                inverse_y_factors.as_ref(),
                alpha,
            );
        let domain = LineDomain::new(Coset::half_odds(
            src.domain.log_size() - CIRCLE_TO_LINE_FOLD_STEP,
        ));
        metal_line_evaluation_from_base_coords(domain, columns)
    }

    fn fold_line(
        eval: &LineEvaluation<Self>,
        alphas: &[SecureField],
        _twiddles: &TwiddleTree<Self>,
    ) -> LineEvaluation<Self> {
        assert!(!alphas.is_empty(), "fold_line requires at least one alpha");
        let mut domain = eval.domain();
        // Submit all fold steps async, wait only on the last.
        // Same-queue command buffers execute in order, so each step reads
        // the completed output of the previous step.
        let mut handles = Vec::with_capacity(alphas.len());

        // First fold step references the original eval columns directly.
        let inverse_x_factors = cached_line_inverse_x_factors(domain);
        let (mut current, handle) =
            SecureFieldVec::fold_line_step_base_coords_with_factor_buffer_async(
                [
                    &eval.values.columns[0],
                    &eval.values.columns[1],
                    &eval.values.columns[2],
                    &eval.values.columns[3],
                ],
                inverse_x_factors.as_ref(),
                alphas[0],
            );
        handles.push(handle);
        domain = domain.double();

        for &alpha in &alphas[1..] {
            let inverse_x_factors = cached_line_inverse_x_factors(domain);
            let (next, handle) =
                SecureFieldVec::fold_line_step_base_coords_with_factor_buffer_async(
                    [&current[0], &current[1], &current[2], &current[3]],
                    inverse_x_factors.as_ref(),
                    alpha,
                );
            handles.push(handle);
            current = next;
            domain = domain.double();
        }

        // Wait only on the last handle; all prior are guaranteed complete.
        if let Some(last) = handles.pop() {
            last.wait().expect("Metal FRI fold chain should succeed");
        }
        drop(handles);

        metal_line_evaluation_from_base_coords(domain, current)
    }

    fn decompose(
        eval: &SecureEvaluation<Self, BitReversedOrder>,
    ) -> (SecureEvaluation<Self, BitReversedOrder>, SecureField) {
        Self::decompose_impl(eval)
    }
}

impl MetalBackend {
    /// Accumulating circle->line fold (`dst = dst * alpha^2 + fold(src)`); kept from the
    /// original project for a future multi-polynomial FRI path, unused by `FriOps` at the
    /// current stwo rev.
    #[allow(dead_code)]
    pub(crate) fn fold_circle_into_line_accumulate(
        dst: &mut LineEvaluation<Self>,
        src: &SecureEvaluation<Self, BitReversedOrder>,
        alpha: SecureField,
        _twiddles: &TwiddleTree<Self>,
    ) {
        let inverse_y_factors = cached_circle_inverse_y_factors(src.domain);
        SecureFieldVec::fold_circle_into_line_accumulate_base_coords_with_factor_buffer(
            [
                &src.values.columns[0],
                &src.values.columns[1],
                &src.values.columns[2],
                &src.values.columns[3],
            ],
            &mut dst.values.columns,
            inverse_y_factors.as_ref(),
            alpha,
        );
    }

    fn decompose_impl(
        eval: &SecureEvaluation<Self, BitReversedOrder>,
    ) -> (SecureEvaluation<Self, BitReversedOrder>, SecureField) {
        let domain_size = eval.len();
        let half_domain_size = domain_size / 2;

        // Bulk-access the four coordinate columns via host_slice (zero-copy on
        // Apple Silicon unified memory) instead of per-element at() calls.
        let c0 = eval.values.columns[0].host_slice();
        let c1 = eval.values.columns[1].host_slice();
        let c2 = eval.values.columns[2].host_slice();
        let c3 = eval.values.columns[3].host_slice();

        // Compute a_sum and b_sum from the coordinate slices directly.
        let mut a_sum = SecureField::zero();
        for i in 0..half_domain_size {
            a_sum += SecureField::from_m31_array([c0[i], c1[i], c2[i], c3[i]]);
        }
        let mut b_sum = SecureField::zero();
        for i in half_domain_size..domain_size {
            b_sum += SecureField::from_m31_array([c0[i], c1[i], c2[i], c3[i]]);
        }
        let lambda = (a_sum - b_sum) / BaseField::from_u32_unchecked(domain_size as u32);

        // Build corrected coordinate columns directly, avoiding the intermediate
        // Vec<SecureField> and its per-element scatter into 4 BaseFieldVec uploads.
        let mut out_cols: [Vec<BaseField>; 4] = array::from_fn(|_| Vec::with_capacity(domain_size));
        for i in 0..domain_size {
            let value = SecureField::from_m31_array([c0[i], c1[i], c2[i], c3[i]]);
            let corrected = if i < half_domain_size {
                value - lambda
            } else {
                value + lambda
            };
            let coords = corrected.to_m31_array();
            for (col, &coord) in out_cols.iter_mut().zip(coords.iter()) {
                col.push(coord);
            }
        }

        let columns = out_cols.map(BaseFieldVec::from_vec);
        (
            SecureEvaluation::new(eval.domain, SecureColumnByCoords { columns }),
            lambda,
        )
    }
}
