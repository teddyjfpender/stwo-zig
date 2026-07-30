use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use itertools::Itertools;
use num_traits::Zero;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use stwo::core::circle::{CirclePoint, CirclePointIndex, Coset};
use stwo::core::constraints::{coset_vanishing, coset_vanishing_derivative, point_vanishing};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::{CanonicCoset, CircleDomain};
use stwo::core::poly::utils::{fold, get_folding_alphas};
use stwo::core::utils::bit_reverse_index;
use stwo::prover::backend::cpu::{CpuCircleEvaluation, CpuCirclePoly};
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::fri::FriOps;
use stwo::prover::poly::circle::{CircleCoefficients, CircleEvaluation, PolyOps};
use stwo::prover::poly::twiddles::TwiddleTree;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::secure_column::SecureColumnByCoords;
use stwo_backend_metal_sys::metal::{MetalError, U32Buffer};

use super::MetalBackend;
use crate::columns::base_field_vec::BaseFieldVec;
use crate::columns::secure_field_vec::SecureFieldVec;

#[allow(dead_code)]
pub fn permute_coset_to_circle_domain_bit_reversed(values: &BaseFieldVec) -> BaseFieldVec {
    values.coset_to_circle_domain_bit_reversed()
}

fn to_cpu_twiddle_tree(twiddles: &TwiddleTree<MetalBackend>) -> TwiddleTree<CpuBackend> {
    TwiddleTree {
        root_coset: twiddles.root_coset,
        twiddles: twiddles.twiddles.clone(),
        itwiddles: twiddles.itwiddles.clone(),
    }
}

fn to_cpu_circle_poly(poly: &CircleCoefficients<MetalBackend>) -> CpuCirclePoly {
    CpuCirclePoly::new(poly.coeffs.to_vec())
}

fn to_cpu_circle_eval(
    eval: &CircleEvaluation<MetalBackend, BaseField, BitReversedOrder>,
) -> CpuCircleEvaluation<BaseField, BitReversedOrder> {
    CpuCircleEvaluation::new(eval.domain, eval.values.to_vec())
}

fn into_metal_circle_poly(poly: CpuCirclePoly) -> CircleCoefficients<MetalBackend> {
    CircleCoefficients::new(BaseFieldVec::from_vec(poly.coeffs))
}

fn into_metal_circle_eval(
    eval: CpuCircleEvaluation<BaseField, BitReversedOrder>,
) -> CircleEvaluation<MetalBackend, BaseField, BitReversedOrder> {
    CircleEvaluation::new(eval.domain, BaseFieldVec::from_vec(eval.values))
}

fn point_xy(point: CirclePoint<BaseField>) -> [u32; 2] {
    [point.x.0, point.y.0]
}

fn folding_mappings(point: CirclePoint<SecureField>, log_size: u32) -> Vec<SecureField> {
    let mut mappings = vec![point.y];
    let mut x = point.x;
    for _ in 1..log_size {
        mappings.push(x);
        x = CirclePoint::double_x(x);
    }
    mappings.reverse();
    mappings
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BatchEvalCacheKey {
    coeffs_log_len: u32,
    poly_buffers: Vec<usize>,
}

type BatchEvalCoeffCache = Mutex<BTreeMap<BatchEvalCacheKey, Arc<U32Buffer>>>;

fn batch_eval_coeff_cache() -> &'static BatchEvalCoeffCache {
    static CACHE: OnceLock<BatchEvalCoeffCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

type TwiddleTailCache = Mutex<BTreeMap<(u64, usize), Arc<U32Buffer>>>;

fn twiddle_tail_cache() -> &'static TwiddleTailCache {
    static CACHE: OnceLock<TwiddleTailCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Content fingerprint of a twiddle vector, used as a cache key.
///
/// NEVER key this cache by the vector's address: allocations are reused, and a fresh
/// tree's *forward* twiddles can land on a freed tree's *inverse* twiddle allocation —
/// which silently fed inverse twiddles to the RFFT on every prove after the first.
/// Twiddles are structured, domain-determined data (not attacker-chosen), so a sampled
/// fingerprint over 64 evenly spaced elements plus the ends identifies them; a false
/// hit would require two different twiddle vectors agreeing on every sampled position.
fn twiddle_content_fingerprint(twiddles: &[BaseField]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    twiddles.len().hash(&mut hasher);
    let step = (twiddles.len() / 64).max(1);
    for value in twiddles.iter().step_by(step) {
        value.0.hash(&mut hasher);
    }
    twiddles.first().map(|v| v.0).hash(&mut hasher);
    twiddles.last().map(|v| v.0).hash(&mut hasher);
    hasher.finish()
}

fn coeff_buffer_key(poly: &CircleCoefficients<MetalBackend>) -> usize {
    // Coefficients are immutable throughout the proving hot path, so the buffer's
    // opaque identity (FFI pointer address) is a stable cache key for reusing
    // flattened staging across repeated point queries.  This works for both
    // shared and private buffers (host_ptr returns NULL for private).
    poly.coeffs.buffer.identity()
}

fn cached_flat_coeffs_buffer(
    polys: &[&CircleCoefficients<MetalBackend>],
    coeffs_len: usize,
    coeffs_log_len: u32,
) -> Result<Arc<U32Buffer>, MetalError> {
    let key = BatchEvalCacheKey {
        coeffs_log_len,
        poly_buffers: polys.iter().map(|poly| coeff_buffer_key(poly)).collect(),
    };

    if let Some(buffer) = batch_eval_coeff_cache()
        .lock()
        .expect("Metal batch-eval coefficient cache mutex should not be poisoned")
        .get(&key)
        .cloned()
    {
        return Ok(buffer);
    }

    let mut flat_coeffs_buffer = U32Buffer::uninitialized_private(polys.len() * coeffs_len)?;
    for (index, poly) in polys.iter().enumerate() {
        flat_coeffs_buffer.copy_from_offset(&poly.coeffs.buffer, index * coeffs_len)?;
    }
    let flat_coeffs_buffer = Arc::new(flat_coeffs_buffer);

    let mut cache = batch_eval_coeff_cache()
        .lock()
        .expect("Metal batch-eval coefficient cache mutex should not be poisoned");
    if cache.len() >= 32 {
        cache.clear();
    }
    cache.insert(key, flat_coeffs_buffer.clone());
    Ok(flat_coeffs_buffer)
}

fn batch_eval_same_size_native(
    polys: &[&CircleCoefficients<MetalBackend>],
    point: CirclePoint<SecureField>,
) -> Option<Vec<SecureField>> {
    if polys.is_empty() {
        return Some(Vec::new());
    }

    let coeffs_len = polys[0].coeffs.len();
    let coeffs_log_len = coeffs_len.ilog2();
    if coeffs_log_len <= 9 {
        return None;
    }

    let factor_limbs = folding_mappings(point, coeffs_log_len)
        .into_iter()
        .flat_map(|value| value.to_m31_array().map(|limb| limb.0))
        .collect_vec();
    let factors_buffer = U32Buffer::from_slice_private(&factor_limbs)
        .expect("Metal batched point-evaluation factor upload should initialize");
    let flat_coeffs_buffer = if polys.len() == 1 {
        None
    } else {
        Some(
            cached_flat_coeffs_buffer(polys, coeffs_len, coeffs_log_len)
                .expect("Metal batched point-evaluation staging cache should initialize"),
        )
    };
    let coeffs_buffer = flat_coeffs_buffer
        .as_deref()
        .unwrap_or(&polys[0].coeffs.buffer);
    let result_buffer = coeffs_buffer
        .batch_eval_at_point_base_field(&factors_buffer, coeffs_log_len, polys.len())
        .expect("Metal batched point evaluation should succeed");
    Some(
        result_buffer
            .to_vec()
            .expect("Metal batched point-evaluation readback should succeed")
            .chunks_exact(4)
            .map(|limbs| SecureField::from_u32_unchecked(limbs[0], limbs[1], limbs[2], limbs[3]))
            .collect(),
    )
}

fn precompute_twiddles_native(coset: Coset) -> Result<TwiddleTree<MetalBackend>, MetalError> {
    let mut twiddles = U32Buffer::uninitialized(coset.size())?;
    let mut current_initial = coset.initial;
    let mut current_step = coset.step;
    let mut current_log_size = coset.log_size();
    let mut offset = 0usize;

    while current_log_size > 0 {
        let level_len = 1usize << (current_log_size - 1);
        twiddles.write_twiddle_level(
            offset,
            point_xy(current_initial),
            point_xy(current_step),
            current_log_size,
        )?;
        offset += level_len;
        current_initial = current_initial.double();
        current_step = current_step.double();
        current_log_size -= 1;
    }

    twiddles.set(coset.size() - 1, 1);

    let mut itwiddles = twiddles.clone();
    itwiddles.invert_m31_in_place()?;

    Ok(TwiddleTree {
        root_coset: coset,
        twiddles: twiddles
            .to_vec()?
            .into_iter()
            .map(BaseField::from_u32_unchecked)
            .collect(),
        itwiddles: itwiddles
            .to_vec()?
            .into_iter()
            .map(BaseField::from_u32_unchecked)
            .collect(),
    })
}

fn tail_twiddle_buffer(
    values_len: usize,
    twiddles: &[BaseField],
) -> Result<Arc<U32Buffer>, MetalError> {
    let eval_domain_size = values_len / 2;
    assert!(
        eval_domain_size <= twiddles.len(),
        "twiddle tree tail length {} exceeds available twiddle len {}",
        eval_domain_size,
        twiddles.len()
    );

    let key = (twiddle_content_fingerprint(twiddles), values_len);

    if let Some(cached) = twiddle_tail_cache()
        .lock()
        .expect("Metal twiddle tail cache mutex should not be poisoned")
        .get(&key)
        .cloned()
    {
        return Ok(cached);
    }

    let slice = &twiddles[twiddles.len() - eval_domain_size..];
    let raw: Vec<u32> = slice.iter().map(|value| value.0).collect();
    let buffer = Arc::new(U32Buffer::from_slice(&raw)?);

    let mut cache = twiddle_tail_cache()
        .lock()
        .expect("Metal twiddle tail cache mutex should not be poisoned");
    if cache.len() >= 64 {
        cache.clear();
    }
    cache.insert(key, buffer.clone());
    Ok(buffer)
}

fn evaluate_into_native(
    poly: &CircleCoefficients<MetalBackend>,
    domain: CircleDomain,
    twiddles: &TwiddleTree<MetalBackend>,
    mut buffer: BaseFieldVec,
) -> Result<CircleEvaluation<MetalBackend, BaseField, BitReversedOrder>, MetalError> {
    let domain_log_size = domain.log_size();
    assert!(domain.half_coset.is_doubling_of(twiddles.root_coset));
    assert_eq!(buffer.len(), domain.size());

    if domain_log_size <= 3 {
        let cpu_poly = to_cpu_circle_poly(poly);
        let cpu_twiddles = to_cpu_twiddle_tree(twiddles);
        let cpu_eval = CpuBackend::evaluate_into(
            &cpu_poly,
            domain,
            &cpu_twiddles,
            vec![BaseField::default(); domain.size()],
        );
        let metal_values = BaseFieldVec::from_vec(cpu_eval.values.clone());
        buffer.copy_from(&metal_values);
        return Ok(CircleEvaluation::new(cpu_eval.domain, buffer));
    }

    let extended = MetalBackend::extend(poly, domain_log_size);
    buffer.copy_from(&extended.coeffs);

    let twiddle_tail = tail_twiddle_buffer(buffer.len(), &twiddles.twiddles)?;
    buffer.buffer.rfft_evaluate_in_place(&twiddle_tail)?;
    Ok(CircleEvaluation::new(domain, buffer))
}

fn interpolate_native(
    eval: CircleEvaluation<MetalBackend, BaseField, BitReversedOrder>,
    twiddles: &TwiddleTree<MetalBackend>,
) -> Result<CircleCoefficients<MetalBackend>, MetalError> {
    assert!(eval.domain.half_coset.is_doubling_of(twiddles.root_coset));

    if eval.domain.log_size() <= 3 {
        let cpu_eval = to_cpu_circle_eval(&eval);
        let cpu_twiddles = to_cpu_twiddle_tree(twiddles);
        return Ok(into_metal_circle_poly(CpuBackend::interpolate(
            cpu_eval,
            &cpu_twiddles,
        )));
    }

    let mut values = eval.values.buffer.clone();
    let inverse_twiddle_tail = tail_twiddle_buffer(values.len(), &twiddles.itwiddles)?;
    let scale_factor = BaseField::from_u32_unchecked(
        values
            .len()
            .try_into()
            .expect("IFFT scale length should fit in u32"),
    )
    .inverse()
    .0;
    values.ifft_interpolate_in_place(&inverse_twiddle_tail, scale_factor)?;
    Ok(CircleCoefficients::new(BaseFieldVec::from_buffer(values)))
}

impl PolyOps for MetalBackend {
    type Twiddles = Vec<BaseField>;

    fn interpolate(
        eval: CircleEvaluation<Self, BaseField, BitReversedOrder>,
        twiddles: &TwiddleTree<Self>,
    ) -> CircleCoefficients<Self> {
        interpolate_native(eval, twiddles)
            .expect("Metal interpolate should complete through the native RFFT/IFFT lane")
    }

    fn eval_at_point(
        poly: &CircleCoefficients<Self>,
        point: CirclePoint<SecureField>,
    ) -> SecureField {
        if poly.log_size() == 0 {
            return poly.coeffs.at(0).into();
        }

        if poly.log_size() > 9 {
            return batch_eval_same_size_native(&[poly], point)
                .expect("Metal single point-evaluation batching should return one value")[0];
        }

        let mappings = folding_mappings(point, poly.log_size());
        fold(poly.coeffs.host_slice(), &mappings)
    }

    fn barycentric_weights(
        coset: CanonicCoset,
        p: CirclePoint<SecureField>,
    ) -> Col<Self, SecureField> {
        let domain = coset.circle_domain();

        let (si_i, vi_p): (Vec<_>, Vec<_>) = (0..domain.size())
            .map(|i| {
                let coset_point = domain
                    .at(bit_reverse_index(i, domain.log_size()))
                    .into_ef::<SecureField>();
                let minus_two_coset_point_y = coset_point.y * SecureField::from(-2);
                (
                    minus_two_coset_point_y
                        * coset_vanishing_derivative(
                            Coset::new(CirclePointIndex::generator(), domain.log_size()),
                            coset_point,
                        ),
                    point_vanishing(coset_point, p.into_ef::<SecureField>()),
                )
            })
            .unzip();

        let vn_p: SecureField = coset_vanishing(
            CanonicCoset::new(domain.log_size()).coset,
            p.into_ef::<SecureField>(),
        );

        SecureFieldVec::from_vec(
            (0..domain.size())
                .map(|i| vn_p / (si_i[i] * vi_p[i]))
                .collect_vec(),
        )
    }

    fn barycentric_eval_at_point(
        evals: &CircleEvaluation<Self, BaseField, BitReversedOrder>,
        weights: &Col<Self, SecureField>,
    ) -> SecureField {
        // Materialize both columns once: per-element `at()` crosses the FFI per value
        // (4x per secure felt), which dominates the whole prove at e2e sizes. The
        // weights column is shared across all same-size columns, so its host view is
        // cached across calls.
        let values = evals.values.host_slice();
        let weights = weights.host_values();
        values
            .iter()
            .zip(weights.iter())
            .fold(SecureField::zero(), |acc, (&value, &weight)| {
                acc + weight * value
            })
    }

    fn eval_at_point_by_folding(
        evals: &CircleEvaluation<Self, BaseField, BitReversedOrder>,
        point: CirclePoint<SecureField>,
        twiddles: &TwiddleTree<Self>,
    ) -> SecureField {
        let log_size = evals.domain.log_size();
        let mut folding_alphas = get_folding_alphas(point, log_size as usize);
        let values_len = evals.values.len();
        let secure_field_values = SecureColumnByCoords {
            columns: std::array::from_fn(|coord| {
                if coord == 0 {
                    evals.values.clone()
                } else {
                    BaseFieldVec::new_zeroes(values_len)
                }
            }),
        };

        let mut layer_evaluation = MetalBackend::fold_circle_into_line(
            &stwo::prover::poly::circle::SecureEvaluation::new(evals.domain, secure_field_values),
            folding_alphas.pop().unwrap(),
            twiddles,
        );

        while layer_evaluation.len() > 1 {
            layer_evaluation = MetalBackend::fold_line(
                &layer_evaluation,
                &[folding_alphas.pop().unwrap()],
                twiddles,
            );
        }

        layer_evaluation.values.at(0) / SecureField::from(2_u32.pow(log_size))
    }

    fn extend(poly: &CircleCoefficients<Self>, log_size: u32) -> CircleCoefficients<Self> {
        assert!(
            log_size >= poly.log_size(),
            "Metal extend requires a target log size at least as large as the source"
        );
        let mut coeffs = poly.coeffs.clone();
        coeffs.pad_to_size(1usize << log_size);
        CircleCoefficients::new(coeffs)
    }

    fn evaluate(
        poly: &CircleCoefficients<Self>,
        domain: CircleDomain,
        twiddles: &TwiddleTree<Self>,
    ) -> CircleEvaluation<Self, BaseField, BitReversedOrder> {
        let buffer = BaseFieldVec::new_zeroes(domain.size());
        Self::evaluate_into(poly, domain, twiddles, buffer)
    }

    fn evaluate_into(
        poly: &CircleCoefficients<Self>,
        domain: CircleDomain,
        twiddles: &TwiddleTree<Self>,
        buffer: Col<Self, BaseField>,
    ) -> CircleEvaluation<Self, BaseField, BitReversedOrder> {
        evaluate_into_native(poly, domain, twiddles, buffer)
            .expect("Metal evaluate should complete through the native RFFT/IFFT lane")
    }

    /// Groups polynomials by evaluation domain size and shares a single twiddle
    /// tail buffer per group, avoiding redundant 32 MB allocations (e.g. 57
    /// log-23 polynomials share one buffer instead of 57 copies).
    /// Rayon parallelism provides CPU-GPU pipeline overlap: while the GPU
    /// processes one polynomial's RFFT, CPU threads prepare the next
    /// polynomial's coefficients.
    fn evaluate_polynomials(
        polynomials: stwo::core::ColumnVec<CircleCoefficients<Self>>,
        log_blowup_factor: u32,
        twiddles: &TwiddleTree<Self>,
        store_polynomials_coefficients: bool,
        pool: &stwo::prover::mempool::BaseColumnPool<Self>,
    ) -> Vec<stwo::prover::Poly<Self>>
    where
        Self: stwo::prover::backend::Backend,
    {
        use stwo::prover::Poly;

        // Pre-compute ONE twiddle tail buffer per distinct domain size.
        let mut twiddle_cache: BTreeMap<u32, Arc<U32Buffer>> = BTreeMap::new();
        for poly_coeffs in &polynomials {
            let log_eval_size = poly_coeffs.log_size() + log_blowup_factor;
            if log_eval_size > 3 {
                twiddle_cache.entry(log_eval_size).or_insert_with(|| {
                    let domain_size = 1usize << log_eval_size;
                    tail_twiddle_buffer(domain_size, &twiddles.twiddles)
                        .expect("Metal twiddle tail allocation should succeed")
                });
            }
        }

        // Pre-take all buffers from the pool (sequential, same as default).
        let buffers: Vec<_> = polynomials
            .iter()
            .map(|poly_coeffs| {
                let log_eval_size = poly_coeffs.log_size() + log_blowup_factor;
                pool.take_or_alloc(log_eval_size)
            })
            .collect();

        // Pre-create ONE shared zero-padding buffer per domain size.
        // This avoids per-polynomial allocations in the extend step:
        // instead of clone + pad_to_size (2 temp buffers), we copy coefficients
        // directly to the pool buffer and zero-fill the remainder.
        let mut zero_pad_cache: BTreeMap<u32, U32Buffer> = BTreeMap::new();
        for poly_coeffs in &polynomials {
            let log_eval_size = poly_coeffs.log_size() + log_blowup_factor;
            if log_eval_size > 3 {
                let coeff_size = poly_coeffs.coeffs.len();
                let domain_size = 1usize << log_eval_size;
                let padding = domain_size - coeff_size;
                if padding > 0 {
                    zero_pad_cache.entry(log_eval_size).or_insert_with(|| {
                        U32Buffer::zeroed(padding)
                            .expect("Metal zero padding allocation should succeed")
                    });
                }
            }
        }

        // Phase 1: Copy coefficients and submit RFFTs without blocking.
        // All GPU command buffers are committed and in-flight simultaneously,
        // keeping the GPU fully occupied instead of draining between Rayon waves.
        #[cfg(feature = "parallel")]
        let iter = polynomials.into_par_iter().zip(buffers.into_par_iter());
        #[cfg(not(feature = "parallel"))]
        let iter = polynomials.into_iter().zip(buffers);

        let pending: Vec<_> = iter
            .map(|(poly_coeffs, mut buffer)| {
                let log_eval_size = poly_coeffs.log_size() + log_blowup_factor;
                let domain = CanonicCoset::new(log_eval_size).circle_domain();

                if log_eval_size <= 3 {
                    let cpu_poly = to_cpu_circle_poly(&poly_coeffs);
                    let cpu_twiddles = to_cpu_twiddle_tree(twiddles);
                    let cpu_eval = CpuBackend::evaluate_into(
                        &cpu_poly,
                        domain,
                        &cpu_twiddles,
                        vec![BaseField::default(); domain.size()],
                    );
                    let metal_values = BaseFieldVec::from_vec(cpu_eval.values.clone());
                    buffer.copy_from(&metal_values);
                    (poly_coeffs, buffer, domain, None)
                } else {
                    let coeff_size = poly_coeffs.coeffs.len();
                    let domain_size = domain.size();
                    buffer
                        .buffer
                        .copy_from_offset(&poly_coeffs.coeffs.buffer, 0)
                        .expect("Metal coefficient copy should succeed");
                    let padding = domain_size - coeff_size;
                    if padding > 0 {
                        let zero_pad = zero_pad_cache
                            .get(&log_eval_size)
                            .expect("zero pad cache should have entry for this domain size");
                        buffer
                            .buffer
                            .copy_range_from(zero_pad, 0, padding, coeff_size)
                            .expect("Metal zero padding copy should succeed");
                    }
                    let twiddle_tail = twiddle_cache
                        .get(&log_eval_size)
                        .expect("twiddle cache should have entry for this domain size");
                    // Submit RFFT without blocking — GPU work starts immediately.
                    let handle = buffer
                        .buffer
                        .rfft_evaluate_in_place_async(twiddle_tail.as_ref())
                        .expect("Metal RFFT async submit should succeed");
                    (poly_coeffs, buffer, domain, Some(handle))
                }
            })
            .collect();

        // Phase 2: Wrap results WITHOUT waiting on RFFT handles.
        //
        // Same-queue command buffers execute in submission order. The
        // subsequent Merkle leaf hashing (also on the GPU queue) will
        // naturally follow all RFFTs. Dropping handles without waiting
        // eliminates ~600 CPU-GPU synchronization points, allowing the
        // GPU to transition directly from RFFT to Merkle without a gap.
        //
        // CONTRACT: this ordering argument only covers GPU consumers. Host
        // reads are made safe at the accessor level: `BaseFieldVec::host_slice`,
        // `SecureFieldVec::host_values`, and `Blake2sHashVec::to_vec` fence the
        // queue (`queue_drain()`) before exposing bytes to the host.
        //
        // Coefficient buffers are promoted non-blocking (GPU blit goes
        // to the same queue, ordered after the RFFT).
        pending
            .into_iter()
            .map(|(poly_coeffs, buffer, domain, handle)| {
                // Drop the handle without waiting — queue ordering
                // guarantees the RFFT completes before any later dispatch.
                drop(handle);
                // Skip coefficient promotion: the batch_eval_at_point path
                // uses cached_flat_coeffs_buffer (already private). Skipping
                // promotion eliminates ~600 GPU blit CBs and their overhead.
                // Individual coefficient buffers remain shared, which is fine
                // because OODS evaluation goes through the flat cache.
                let evals = CircleEvaluation::new(domain, buffer);
                Poly::new(store_polynomials_coefficients.then_some(poly_coeffs), evals)
            })
            .collect()
    }

    fn precompute_twiddles(coset: Coset) -> TwiddleTree<Self> {
        precompute_twiddles_native(coset)
            .expect("Metal twiddle precompute should produce native parity-tested twiddles")
    }

    fn split_at_mid(
        poly: CircleCoefficients<Self>,
    ) -> (CircleCoefficients<Self>, CircleCoefficients<Self>) {
        let (left, right) = poly.coeffs.split_at_mid();
        (
            CircleCoefficients::new(left),
            CircleCoefficients::new(right),
        )
    }

    fn join_at_mid(
        left: CircleCoefficients<Self>,
        right: CircleCoefficients<Self>,
    ) -> CircleCoefficients<Self> {
        // The Metal coefficient layout is plain bit-reversed order (no mid-transpose), so
        // joining is a buffer concatenation — the exact inverse of `split_at_mid`.
        assert_eq!(left.coeffs.len(), right.coeffs.len());
        let mut joined = left.coeffs.to_cpu();
        joined.extend(right.coeffs.to_cpu());
        CircleCoefficients::new(BaseFieldVec::from_vec(joined))
    }
}

#[allow(dead_code)]
fn _assert_eval_bridge_type(
    eval: CpuCircleEvaluation<BaseField, BitReversedOrder>,
) -> CircleEvaluation<MetalBackend, BaseField, BitReversedOrder> {
    into_metal_circle_eval(eval)
}

impl MetalBackend {
    /// Fused multi-point/multi-polynomial OODS evaluation (vendor extension; not part of
    /// `PolyOps` at the current stwo rev). Used internally by `eval_at_point`.
    #[allow(dead_code)]
    pub(crate) fn batch_eval_at_point(
        polys: &[&CircleCoefficients<Self>],
        point: CirclePoint<SecureField>,
    ) -> Vec<SecureField> {
        let mut grouped = BTreeMap::<usize, Vec<(usize, &CircleCoefficients<Self>)>>::new();
        for (index, poly) in polys.iter().enumerate() {
            grouped
                .entry(poly.coeffs.len())
                .or_default()
                .push((index, *poly));
        }

        let mut results = vec![SecureField::zero(); polys.len()];

        // Separate GPU-eligible groups (log_size > 9) from CPU-fallback groups.
        type IndexedCoeffs<'a> = Vec<(usize, &'a CircleCoefficients<MetalBackend>)>;
        let mut gpu_groups: Vec<(usize, IndexedCoeffs<'_>)> = Vec::new();
        let mut cpu_groups: Vec<IndexedCoeffs<'_>> = Vec::new();
        for (coeffs_len, group) in grouped {
            let coeffs_log_len = coeffs_len.ilog2();
            if coeffs_log_len > 9 {
                gpu_groups.push((coeffs_len, group));
            } else {
                cpu_groups.push(group);
            }
        }

        // Fuse ALL GPU-eligible groups into a single Metal command buffer.
        if !gpu_groups.is_empty() {
            // Prepare flat coefficient buffers and factor buffers for each group.
            // `flat_coeffs_owned` keeps owned buffers alive; for single-poly
            // groups we reference the polynomial's buffer directly.
            let mut flat_coeffs_owned: Vec<Option<Arc<U32Buffer>>> =
                Vec::with_capacity(gpu_groups.len());
            let mut factors_owned: Vec<U32Buffer> = Vec::with_capacity(gpu_groups.len());
            let mut meta: Vec<(u32, usize)> = Vec::with_capacity(gpu_groups.len()); // (coeffs_log_len, n_polys)

            for (coeffs_len, ref group) in &gpu_groups {
                let coeffs_log_len = coeffs_len.ilog2();
                let group_polys: Vec<&CircleCoefficients<Self>> =
                    group.iter().map(|(_, poly)| *poly).collect();

                let factor_limbs = folding_mappings(point, coeffs_log_len)
                    .into_iter()
                    .flat_map(|value| value.to_m31_array().map(|limb| limb.0))
                    .collect_vec();
                let factors_buffer = U32Buffer::from_slice_private(&factor_limbs)
                    .expect("Metal multi-group eval factor upload should succeed");

                if group_polys.len() == 1 {
                    // Single polynomial -- reference its buffer directly, no copy.
                    flat_coeffs_owned.push(None);
                } else {
                    flat_coeffs_owned.push(Some(
                        cached_flat_coeffs_buffer(&group_polys, *coeffs_len, coeffs_log_len)
                            .expect("Metal multi-group eval coefficient staging should succeed"),
                    ));
                }
                factors_owned.push(factors_buffer);
                meta.push((coeffs_log_len, group_polys.len()));
            }

            // Build the multi-group call arguments, resolving references.
            let group_args: Vec<(&U32Buffer, &U32Buffer, u32, usize)> = gpu_groups
                .iter()
                .enumerate()
                .map(|(i, (_, group))| {
                    let coeffs_ref = match &flat_coeffs_owned[i] {
                        Some(arc) => arc.as_ref(),
                        None => &group[0].1.coeffs.buffer,
                    };
                    (coeffs_ref, &factors_owned[i], meta[i].0, meta[i].1)
                })
                .collect();

            let result_buffers = U32Buffer::batch_eval_at_point_multi_group(&group_args)
                .expect("Metal multi-group batch eval should succeed");

            // Scatter results back to the output vector.
            for ((_, group), result_buffer) in gpu_groups.iter().zip(result_buffers.iter()) {
                let raw_results = result_buffer
                    .to_vec()
                    .expect("Metal multi-group eval readback should succeed");
                for (group_idx, (original_index, _)) in group.iter().enumerate() {
                    let base = group_idx * 4;
                    results[*original_index] = SecureField::from_u32_unchecked(
                        raw_results[base],
                        raw_results[base + 1],
                        raw_results[base + 2],
                        raw_results[base + 3],
                    );
                }
            }
        }

        // Handle CPU-fallback groups (log_size <= 9).
        for group in cpu_groups {
            let group_polys: Vec<&CircleCoefficients<Self>> =
                group.iter().map(|(_, poly)| *poly).collect();

            #[cfg(not(feature = "parallel"))]
            let fallback_values = group_polys
                .iter()
                .map(|poly| Self::eval_at_point(poly, point))
                .collect_vec();
            #[cfg(feature = "parallel")]
            let fallback_values = group_polys
                .par_iter()
                .map(|poly| Self::eval_at_point(poly, point))
                .collect::<Vec<_>>();

            for ((index, _), value) in group.into_iter().zip(fallback_values) {
                results[index] = value;
            }
        }

        results
    }
}
