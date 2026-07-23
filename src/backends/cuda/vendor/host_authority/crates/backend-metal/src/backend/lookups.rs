use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::prover::lookups::gkr_prover::{
    correct_sum_as_poly_in_first_variable, GkrMultivariatePolyOracle, GkrOps, Layer,
};
use stwo::prover::lookups::mle::{Mle, MleOps};
use stwo::prover::lookups::sumcheck::MultivariatePolyOracle;
use stwo::prover::lookups::utils::UnivariatePoly;

use super::MetalBackend;
use crate::columns::SecureFieldVec;

impl MleOps<BaseField> for MetalBackend {
    fn fix_first_variable(
        mle: Mle<Self, BaseField>,
        assignment: SecureField,
    ) -> Mle<Self, SecureField>
    where
        Self: MleOps<SecureField>,
    {
        Mle::new(mle.into_evals().fix_first_variable(assignment))
    }
}

impl MleOps<SecureField> for MetalBackend {
    fn fix_first_variable(
        mle: Mle<Self, SecureField>,
        assignment: SecureField,
    ) -> Mle<Self, SecureField>
    where
        Self: MleOps<SecureField>,
    {
        Mle::new(mle.into_evals().fix_first_variable(assignment))
    }
}

impl GkrOps for MetalBackend {
    fn gen_eq_evals(y: &[SecureField], v: SecureField) -> Mle<Self, SecureField> {
        Mle::new(SecureFieldVec::gkr_generate_eq_evals(y, v))
    }

    fn next_layer(layer: &Layer<Self>) -> Layer<Self> {
        match layer {
            Layer::GrandProduct(layer) => Layer::GrandProduct(Mle::new(
                layer.clone().into_evals().gkr_next_grand_product_layer(),
            )),
            Layer::LogUpGeneric {
                numerators,
                denominators,
            } => {
                let (next_numerators, next_denominators) =
                    SecureFieldVec::gkr_next_logup_generic_layer(
                        &numerators.clone().into_evals(),
                        &denominators.clone().into_evals(),
                    );
                Layer::LogUpGeneric {
                    numerators: Mle::new(next_numerators),
                    denominators: Mle::new(next_denominators),
                }
            }
            Layer::LogUpMultiplicities {
                numerators,
                denominators,
            } => {
                let (next_numerators, next_denominators) = numerators
                    .clone()
                    .into_evals()
                    .gkr_next_logup_multiplicities_layer(&denominators.clone().into_evals());
                Layer::LogUpGeneric {
                    numerators: Mle::new(next_numerators),
                    denominators: Mle::new(next_denominators),
                }
            }
            Layer::LogUpSingles { denominators } => {
                let (next_numerators, next_denominators) =
                    SecureFieldVec::gkr_next_logup_singles_layer(
                        &denominators.clone().into_evals(),
                    );
                Layer::LogUpGeneric {
                    numerators: Mle::new(next_numerators),
                    denominators: Mle::new(next_denominators),
                }
            }
        }
    }

    fn sum_as_poly_in_first_variable(
        h: &GkrMultivariatePolyOracle<'_, Self>,
        claim: SecureField,
    ) -> UnivariatePoly<SecureField> {
        let n_variables = h.n_variables();
        assert!(
            n_variables > 0,
            "GKR sum polynomial requires at least one variable"
        );
        let eq_evals = h.eq_evals.as_ref();
        let y = eq_evals.y();

        let (mut eval_at_0, mut eval_at_2) = match &h.input_layer {
            Layer::GrandProduct(col) => {
                SecureFieldVec::gkr_sum_grand_product(eq_evals, &col.clone().into_evals())
            }
            Layer::LogUpGeneric {
                numerators,
                denominators,
            } => SecureFieldVec::gkr_sum_logup_generic(
                eq_evals,
                &numerators.clone().into_evals(),
                &denominators.clone().into_evals(),
                h.lambda,
            ),
            Layer::LogUpMultiplicities {
                numerators,
                denominators,
            } => numerators
                .clone()
                .into_evals()
                .gkr_sum_logup_multiplicities(
                    eq_evals,
                    &denominators.clone().into_evals(),
                    h.lambda,
                ),
            Layer::LogUpSingles { denominators } => SecureFieldVec::gkr_sum_logup_singles(
                eq_evals,
                &denominators.clone().into_evals(),
                h.lambda,
            ),
        };

        eval_at_0 *= h.eq_fixed_var_correction;
        eval_at_2 *= h.eq_fixed_var_correction;
        correct_sum_as_poly_in_first_variable(eval_at_0, eval_at_2, claim, y, n_variables)
    }
}
