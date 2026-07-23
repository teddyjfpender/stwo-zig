use serde::{Deserialize, Serialize};
use stwo::prover::backend::Backend;
use stwo::prover::{ComponentProver, DomainEvaluationAccumulator, Trace};
use stwo_constraint_framework::{
    evaluate_constraint_quotients_via_cpu, FrameworkBackend, FrameworkComponent, FrameworkEval,
};

/// The Metal GPU proving backend.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct MetalBackend;

impl Backend for MetalBackend {}

impl FrameworkBackend for MetalBackend {
    fn evaluate_constraint_quotients_on_domain<E: FrameworkEval + Sync>(
        component: &FrameworkComponent<E>,
        trace: &Trace<'_, Self>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<Self>,
    ) {
        // Native lane: record the constraint tree once, JIT-compile a fused Metal kernel
        // (cached by semantic hash), evaluate on GPU. Any failure (unsupported feature,
        // runtime error, STWO_METAL_DISABLE_JIT) falls back to the generic CPU driver.
        // Both lanes are byte-equal by construction and gated by the testkit.
        match super::jit::evaluate_constraint_quotients_via_jit(
            component,
            trace,
            evaluation_accumulator,
        ) {
            Ok(()) => {}
            Err(reason) => {
                if std::env::var_os("STWO_METAL_JIT_LOG").is_some() {
                    eprintln!("stwo-metal JIT lane unavailable, using CPU lane: {reason:?}");
                }
                evaluate_constraint_quotients_via_cpu(component, trace, evaluation_accumulator);
            }
        }
    }
}

// `ComponentProver<MetalBackend>` for all `FrameworkComponent`s follows from the blanket impl
// in stwo-constraint-framework.
const _: fn() = || {
    fn assert_component_prover<B>()
    where
        for<'a> FrameworkComponent<DummyEval>: ComponentProver<B>,
        B: Backend,
    {
    }
    #[derive(Clone)]
    struct DummyEval;
    impl FrameworkEval for DummyEval {
        fn log_size(&self) -> u32 {
            4
        }
        fn max_constraint_log_degree_bound(&self) -> u32 {
            5
        }
        fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, eval: E) -> E {
            eval
        }
    }
    assert_component_prover::<MetalBackend>();
};
