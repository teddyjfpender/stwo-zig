use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use dashmap::DashMap;
use itertools::Itertools;

use crate::core::air::{Component, Components};
use crate::core::fields::m31::BaseField;
use crate::core::fields::qm31::SecureField;
use crate::core::pcs::TreeVec;
use crate::core::poly::circle::{CanonicCoset, CircleDomain};
use crate::core::ColumnVec;
use crate::prover::air::accumulation::{DomainEvaluationAccumulator, EvaluationMode};
use crate::prover::backend::{Backend, Col};
use crate::prover::poly::circle::{CircleCoefficients, CircleEvaluation, SecureCirclePoly};
use crate::prover::poly::twiddles::TwiddleTree;
use crate::prover::poly::BitReversedOrder;
use crate::prover::CirclePoint;

/// Key for a cached barycentric-weights column: `(log_size, folded_sample_point)`.
pub type WeightsKey = (u32, CirclePoint<SecureField>);

/// Type alias for the weights hash map used in barycentric eval_at_point.
pub type WeightsHashMap<B> = DashMap<WeightsKey, Col<B, SecureField>>;

/// Reads the OODS barycentric-weight cache cap from `STWO_CUDA_OODS_CACHE_CAP` (once).
///
/// Each cached entry is a full eval-domain-sized secure-field column; on GPU backends
/// the cache is device (VRAM) memory and was measured growing to ~18.8 GB on fib
/// (RESULTS.md round 4). This is a *pure* cache keyed by `(log_size, point)` — the
/// weights are a deterministic function of the key (see [`super::super::poly::circle::
/// CircleEvaluation::barycentric_weights`]), so bounding it with recompute-on-miss is
/// **value-identical by construction**: any cache/eviction policy yields the same
/// evaluated OODS values.
///
/// Semantics (kill switch): unset / `0` / unparsable → `None` = **unbounded**, i.e.
/// the pre-existing eager DashMap path with byte- AND performance-identical behavior
/// (default OFF). A positive integer `N` bounds the live entry count to `N` with LRU
/// eviction and lazy recompute-on-miss.
pub fn oods_cache_cap() -> Option<usize> {
    static CAP: OnceLock<Option<usize>> = OnceLock::new();
    *CAP.get_or_init(|| parse_oods_cache_cap(std::env::var("STWO_CUDA_OODS_CACHE_CAP").ok()))
}

/// Pure parser for the cap env var, factored out for unit testing. `None` (unbounded)
/// for missing / empty / `0` / non-numeric input; `Some(n)` for a positive integer.
pub(crate) fn parse_oods_cache_cap(raw: Option<String>) -> Option<usize> {
    match raw?.trim().parse::<usize>() {
        Ok(n) if n >= 1 => Some(n),
        _ => None,
    }
}

/// A capacity-bounded, LRU-evicting map from [`WeightsKey`] to a barycentric-weights
/// column. Recompute-on-miss makes eviction free of correctness cost (the weights are
/// a pure function of the key). Capacity is `>= 1`. Intentionally simple: the live set
/// of distinct `(log_size, point)` keys is tiny (a handful), so linear recency bookkeeping
/// is cheaper than a heap/intrusive list and keeps the eviction order trivially auditable.
pub struct LruWeights<B: Backend> {
    cap: usize,
    map: HashMap<WeightsKey, Col<B, SecureField>>,
    /// Recency order, front (index 0) = least-recently-used, back = most-recently-used.
    order: Vec<WeightsKey>,
}

impl<B: Backend> LruWeights<B> {
    fn new(cap: usize) -> Self {
        assert!(cap >= 1, "OODS weight cache cap must be >= 1");
        Self {
            cap,
            map: HashMap::new(),
            order: Vec::new(),
        }
    }

    fn touch(&mut self, key: &WeightsKey) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            let k = self.order.remove(pos);
            self.order.push(k);
        }
    }

    /// Returns the weights for `key`, computing (and inserting, evicting the LRU entry
    /// if at capacity) on miss. The returned reference is valid until the next mutation.
    fn get_or_insert_with(
        &mut self,
        key: WeightsKey,
        compute: impl FnOnce() -> Col<B, SecureField>,
    ) -> &Col<B, SecureField> {
        if self.map.contains_key(&key) {
            self.touch(&key);
        } else {
            if self.map.len() >= self.cap {
                // Evict the least-recently-used entry, freeing its (device) column.
                let evict = self.order.remove(0);
                self.map.remove(&evict);
            }
            let weights = compute();
            self.map.insert(key, weights);
            self.order.push(key);
        }
        self.map.get(&key).expect("just inserted / present")
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        debug_assert_eq!(self.map.len(), self.order.len());
        self.map.len()
    }
}

/// The barycentric-weight store passed through OODS evaluation. Either the pre-existing
/// unbounded concurrent map (default, eagerly pre-built, byte/perf-identical to before)
/// or a capacity-bounded LRU that computes weights lazily on demand — see
/// [`oods_cache_cap`] for the value-identity argument and kill-switch semantics.
pub enum WeightsCache<B: Backend> {
    Unbounded(WeightsHashMap<B>),
    Bounded(Mutex<LruWeights<B>>),
}

impl<B: Backend> WeightsCache<B> {
    pub fn new_unbounded() -> Self {
        WeightsCache::Unbounded(WeightsHashMap::<B>::new())
    }

    pub fn new_bounded(cap: usize) -> Self {
        WeightsCache::Bounded(Mutex::new(LruWeights::new(cap)))
    }

    /// Fetches (or, in bounded mode, computes-on-miss) the weights for `key` and runs
    /// `use_weights` on them. `compute` reconstructs the weights from the key alone and
    /// is deterministic, so the value handed to `use_weights` is identical regardless
    /// of which variant is used or what has been evicted.
    pub fn with_weights<R>(
        &self,
        key: WeightsKey,
        compute: impl FnOnce() -> Col<B, SecureField>,
        use_weights: impl FnOnce(&Col<B, SecureField>) -> R,
    ) -> R {
        match self {
            // Fast path preserved exactly: the map is eagerly pre-built, so this is a
            // read-lock hit (identical to the original `.get(..).expect(..)`), and the
            // `compute` closure is never invoked in practice.
            WeightsCache::Unbounded(map) => {
                if let Some(weights) = map.get(&key) {
                    use_weights(weights.value())
                } else {
                    let weights = map.entry(key).or_insert_with(compute);
                    use_weights(weights.value())
                }
            }
            WeightsCache::Bounded(lru) => {
                let mut lru = lru.lock().expect("OODS weight cache mutex poisoned");
                let weights = lru.get_or_insert_with(key, compute);
                use_weights(weights)
            }
        }
    }
}

pub trait ComponentProver<B: Backend>: Component {
    /// Evaluates the constraint quotients of the component on the evaluation domain.
    /// Accumulates quotients in `evaluation_accumulator`.
    fn evaluate_constraint_quotients_on_domain(
        &self,
        trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    );
}

/// The set of polynomials that make up the trace.
pub struct Trace<'a, B: Backend> {
    /// Polynomials for each column.
    pub polys: TreeVec<ColumnVec<&'a Poly<B>>>,
}

/// A struct for representing a polynomial corresponding to a trace column.
/// A polynomial is defined by it's evaluations on a circle domain of size at least it's degree,
/// and optionally its coefficients in the FFT basis.
pub struct Poly<B: Backend> {
    pub coeffs: Option<CircleCoefficients<B>>,
    pub evals: CircleEvaluation<B, BaseField, BitReversedOrder>,
}

impl<B: Backend> Poly<B> {
    pub const fn new(
        coeffs: Option<CircleCoefficients<B>>,
        evals: CircleEvaluation<B, BaseField, BitReversedOrder>,
    ) -> Self {
        Self { coeffs, evals }
    }

    pub fn eval_at_point(
        &self,
        point: CirclePoint<SecureField>,
        weights_cache: Option<&WeightsCache<B>>,
    ) -> SecureField {
        if let Some(coeffs) = &self.coeffs {
            coeffs.eval_at_point(point)
        } else {
            let log_size = self.evals.domain.log_size();
            let cache = weights_cache
                .expect("weights cache required when polynomial coefficients are not stored");
            // `point` is already the folded sample point (the caller folds it), matching
            // the key used to pre-build the cache. In bounded mode the `compute` closure
            // recomputes the weights from the key on a miss — the identical formula the
            // eager builder uses, so the result is value-identical.
            cache.with_weights(
                (log_size, point),
                || {
                    CircleEvaluation::<B, BaseField, BitReversedOrder>::barycentric_weights(
                        CanonicCoset::new(log_size),
                        point,
                    )
                },
                |weights| self.evals.barycentric_eval_at_point(weights),
            )
        }
    }

    pub fn get_evaluation_on_domain(
        &self,
        domain: CircleDomain,
        twiddles: &TwiddleTree<B>,
    ) -> CircleEvaluation<B, BaseField, BitReversedOrder> {
        if let Some(coeffs) = &self.coeffs {
            coeffs.evaluate_with_twiddles(domain, twiddles)
        } else {
            panic!("The polynomial's coefficients are not stored");
        }
    }
}

pub struct ComponentProvers<'a, B: Backend> {
    pub components: Vec<&'a dyn ComponentProver<B>>,
    pub n_preprocessed_columns: usize,
}

impl<B: Backend> ComponentProvers<'_, B> {
    pub fn components(&self) -> Components<'_> {
        Components {
            components: self
                .components
                .iter()
                .map(|c| *c as &dyn Component)
                .collect_vec(),
            n_preprocessed_columns: self.n_preprocessed_columns,
        }
    }
    pub fn compute_composition_polynomial(
        &self,
        random_coeff: SecureField,
        trace: &Trace<'_, B>,
        twiddles: &TwiddleTree<B>,
        log_blowup_factor: u32,
    ) -> SecureCirclePoly<B> {
        let total_constraints: usize = self.components.iter().map(|c| c.n_constraints()).sum();
        let components: Vec<&dyn Component> = self
            .components
            .iter()
            .map(|c| *c as &dyn Component)
            .collect();
        // STWO_FORCE_EXTEND_EVAL_MODE=1 forces the per-component evaluate-from-
        // coefficients path even when SubDomain borrowing is available. This is the
        // composition half of the streamed-LDE VRAM diet: with it, composition never
        // touches the trees' committed evaluations, so they can be compacted right
        // after commit instead of after quotients. ExtendToEvalDomain is a
        // long-standing production path (taken whenever component expansions differ),
        // not new machinery; results are value-identical by construction.
        let evaluation_mode = if std::env::var("STWO_FORCE_EXTEND_EVAL_MODE").as_deref() == Ok("1")
        {
            EvaluationMode::ExtendToEvalDomain
        } else {
            EvaluationMode::infer(&components, log_blowup_factor)
        };
        let mut accumulator = DomainEvaluationAccumulator::new(
            random_coeff,
            self.components().composition_log_degree_bound(),
            total_constraints,
            evaluation_mode,
        );
        for component in &self.components {
            component.evaluate_constraint_quotients_on_domain(trace, &mut accumulator)
        }
        accumulator.finalize(twiddles)
    }
}

#[cfg(test)]
mod weights_cache_tests {
    use std::cell::Cell;

    use num_traits::One;

    use super::{parse_oods_cache_cap, Poly, WeightsCache, WeightsKey};
    use crate::core::circle::SECURE_FIELD_CIRCLE_GEN;
    use crate::core::fields::m31::BaseField;
    use crate::core::fields::qm31::SecureField;
    use crate::core::poly::circle::CanonicCoset;
    use crate::prover::backend::CpuBackend;
    use crate::prover::poly::circle::CircleEvaluation;
    use crate::prover::poly::BitReversedOrder;
    use crate::prover::CirclePoint;

    fn key(log_size: u32) -> WeightsKey {
        // Distinct keys via distinct log_size; a single fixed non-trivial point suffices
        // to exercise cache keying/eviction independent of the field arithmetic.
        (log_size, SECURE_FIELD_CIRCLE_GEN)
    }

    /// Deterministic synthetic "weights" derived from the key so any recompute is
    /// bit-identical — mirrors the real invariant (weights are a pure fn of the key).
    fn synth(k: &WeightsKey) -> Vec<SecureField> {
        vec![SecureField::from(BaseField::from(k.0 as usize + 1)); 2]
    }

    #[test]
    fn parse_cap_semantics() {
        assert_eq!(parse_oods_cache_cap(None), None);
        assert_eq!(parse_oods_cache_cap(Some("".into())), None);
        assert_eq!(parse_oods_cache_cap(Some("0".into())), None);
        assert_eq!(parse_oods_cache_cap(Some("garbage".into())), None);
        assert_eq!(parse_oods_cache_cap(Some("-5".into())), None);
        assert_eq!(parse_oods_cache_cap(Some("1".into())), Some(1));
        assert_eq!(parse_oods_cache_cap(Some("  8 ".into())), Some(8));
    }

    #[test]
    fn unbounded_computes_each_key_once() {
        let cache = WeightsCache::<CpuBackend>::new_unbounded();
        let calls = Cell::new(0usize);
        let compute = |k: WeightsKey| {
            calls.set(calls.get() + 1);
            synth(&k)
        };
        for _ in 0..3 {
            for lg in [4u32, 5, 6] {
                let got = cache.with_weights(key(lg), || compute(key(lg)), |w| w.clone());
                assert_eq!(got, synth(&key(lg)));
            }
        }
        // 3 distinct keys, computed once each despite 9 accesses.
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn bounded_is_value_identical_and_respects_cap() {
        let unbounded = WeightsCache::<CpuBackend>::new_unbounded();
        let bounded = WeightsCache::<CpuBackend>::new_bounded(2);

        // Access pattern that forces eviction+recompute under cap=2 (4 distinct keys).
        let pattern = [4u32, 5, 6, 4, 7, 5, 6, 4];
        for lg in pattern {
            let u = unbounded.with_weights(key(lg), || synth(&key(lg)), |w| w.clone());
            let b = bounded.with_weights(key(lg), || synth(&key(lg)), |w| w.clone());
            // Value-identity: bounded eviction/recompute yields exactly the unbounded result.
            assert_eq!(u, b, "log_size {lg}");
            assert_eq!(b, synth(&key(lg)));
        }

        // The bounded cache never exceeds its capacity.
        if let WeightsCache::Bounded(lru) = &bounded {
            assert!(lru.lock().unwrap().len() <= 2);
        } else {
            panic!("expected bounded variant");
        }
    }

    #[test]
    fn bounded_recomputes_after_eviction() {
        let bounded = WeightsCache::<CpuBackend>::new_bounded(1);
        let calls = Cell::new(0usize);
        let hit = |lg: u32| {
            bounded.with_weights(
                key(lg),
                || {
                    calls.set(calls.get() + 1);
                    synth(&key(lg))
                },
                |w| w.clone(),
            )
        };
        hit(4); // miss -> compute (1)
        hit(4); // hit  -> no compute
        hit(5); // miss -> compute (2), evicts 4
        hit(4); // miss again (4 was evicted) -> compute (3)
        assert_eq!(calls.get(), 3);
    }

    /// End-to-end value-identity through the real barycentric machinery: a `Poly`
    /// evaluated with the unbounded cache and with a cap-1 bounded cache (forcing
    /// eviction between the two sampled log_sizes) must return identical field values.
    #[test]
    fn poly_eval_identical_bounded_vs_unbounded() {
        let unbounded = WeightsCache::<CpuBackend>::new_unbounded();
        let bounded = WeightsCache::<CpuBackend>::new_bounded(1);
        let point: CirclePoint<SecureField> = SECURE_FIELD_CIRCLE_GEN;

        let mut polys = Vec::new();
        for log_size in [4u32, 5] {
            let domain = CanonicCoset::new(log_size).circle_domain();
            let values: Vec<BaseField> = (0..(1 << log_size))
                .map(|i| BaseField::from(i as usize) + BaseField::one())
                .collect();
            let evals =
                CircleEvaluation::<CpuBackend, BaseField, BitReversedOrder>::new(domain, values);
            polys.push(Poly::new(None, evals));
        }

        // Interleave the two log_sizes so the cap-1 bounded cache evicts and recomputes.
        for _ in 0..2 {
            for poly in &polys {
                let u = poly.eval_at_point(point, Some(&unbounded));
                let b = poly.eval_at_point(point, Some(&bounded));
                assert_eq!(u, b);
            }
        }
    }
}
