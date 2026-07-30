use stwo::core::fields::qm31::SecureField;
use stwo::prover::backend::Column;
use stwo::prover::lookups::gkr_prover::{
    correct_sum_as_poly_in_first_variable, EqEvals, GkrMultivariatePolyOracle, GkrOps, Layer,
};
use stwo::prover::lookups::mle::Mle;
use stwo::prover::lookups::sumcheck::MultivariatePolyOracle;
use stwo::prover::lookups::utils::UnivariatePoly;

use crate::backend::{BaseFieldVec, CudaBackend, SecureFieldVec};
use crate::columns::bindings;
use crate::columns::bindings::CudaSecureField;

impl GkrOps for CudaBackend {
    fn gen_eq_evals(y: &[SecureField], v: SecureField) -> Mle<Self, SecureField> {
        let y_size = y.len();
        let result_evals = SecureFieldVec::new_uninitialized(1 << y_size);

        unsafe {
            bindings::gen_eq_evals(
                v.into(),
                y.as_ptr() as *const CudaSecureField,
                y_size as u32,
                result_evals.device_ptr as *const CudaSecureField,
                result_evals.size as u32,
            );
        }

        Mle::new(result_evals)
    }

    fn next_layer(layer: &Layer<Self>) -> Layer<Self> {
        assert!(layer.n_variables() > 0, "output layer has no next layer");

        match layer {
            Layer::GrandProduct(col) => {
                let next_layer_len = next_layer_len(col.len());
                let output = SecureFieldVec::new_uninitialized(next_layer_len);

                unsafe {
                    bindings::gkr_next_grand_product_layer(
                        secure_eval_ptr(col),
                        col.len() as u32,
                        output.device_ptr as *const CudaSecureField,
                    );
                }

                Layer::GrandProduct(Mle::new(output))
            }
            Layer::LogUpGeneric {
                numerators,
                denominators,
            } => {
                let next_layer_len = next_layer_len(denominators.len());
                let next_numerators = SecureFieldVec::new_uninitialized(next_layer_len);
                let next_denominators = SecureFieldVec::new_uninitialized(next_layer_len);

                unsafe {
                    bindings::gkr_next_logup_generic_layer(
                        secure_eval_ptr(numerators),
                        secure_eval_ptr(denominators),
                        denominators.len() as u32,
                        next_numerators.device_ptr as *const CudaSecureField,
                        next_denominators.device_ptr as *const CudaSecureField,
                    );
                }

                Layer::LogUpGeneric {
                    numerators: Mle::new(next_numerators),
                    denominators: Mle::new(next_denominators),
                }
            }
            Layer::LogUpMultiplicities {
                numerators,
                denominators,
            } => {
                let next_layer_len = next_layer_len(denominators.len());
                let next_numerators = SecureFieldVec::new_uninitialized(next_layer_len);
                let next_denominators = SecureFieldVec::new_uninitialized(next_layer_len);

                unsafe {
                    bindings::gkr_next_logup_multiplicities_layer(
                        base_eval_ptr(numerators),
                        secure_eval_ptr(denominators),
                        denominators.len() as u32,
                        next_numerators.device_ptr as *const CudaSecureField,
                        next_denominators.device_ptr as *const CudaSecureField,
                    );
                }

                Layer::LogUpGeneric {
                    numerators: Mle::new(next_numerators),
                    denominators: Mle::new(next_denominators),
                }
            }
            Layer::LogUpSingles { denominators } => {
                let next_layer_len = next_layer_len(denominators.len());
                let next_numerators = SecureFieldVec::new_uninitialized(next_layer_len);
                let next_denominators = SecureFieldVec::new_uninitialized(next_layer_len);

                unsafe {
                    bindings::gkr_next_logup_singles_layer(
                        secure_eval_ptr(denominators),
                        denominators.len() as u32,
                        next_numerators.device_ptr as *const CudaSecureField,
                        next_denominators.device_ptr as *const CudaSecureField,
                    );
                }

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
        let n_terms = gkr_sum_term_count(n_variables);
        let (mut eval_at_0, mut eval_at_2) = sum_oracle_eval_pair(h, n_terms);

        eval_at_0 *= h.eq_fixed_var_correction;
        eval_at_2 *= h.eq_fixed_var_correction;

        correct_sum_as_poly_in_first_variable(
            eval_at_0,
            eval_at_2,
            claim,
            h.eq_evals.y(),
            n_variables,
        )
    }
}

fn next_layer_len(input_len: usize) -> usize {
    assert!(
        input_len >= 2,
        "GKR next_layer requires at least two evaluations"
    );
    assert!(
        input_len.is_power_of_two(),
        "GKR layer length must be a power of two"
    );
    assert!(
        input_len <= u32::MAX as usize,
        "GKR layer length exceeds CUDA ABI bounds"
    );
    input_len >> 1
}

fn secure_eval_ptr(mle: &Mle<CudaBackend, SecureField>) -> *const CudaSecureField {
    let evals: &SecureFieldVec = mle;
    evals.device_ptr as *const CudaSecureField
}

fn base_eval_ptr(mle: &Mle<CudaBackend, stwo::core::fields::m31::BaseField>) -> *const u32 {
    let evals: &BaseFieldVec = mle;
    evals.device_ptr
}

fn eq_eval_ptr(eq_evals: &EqEvals<CudaBackend>) -> *const CudaSecureField {
    let evals: &SecureFieldVec = eq_evals;
    evals.device_ptr as *const CudaSecureField
}

fn gkr_sum_term_count(n_variables: usize) -> usize {
    assert!(
        n_variables > 0,
        "GKR sum projection requires at least one variable"
    );

    let n_terms = 1usize << (n_variables - 1);
    assert!(
        n_terms <= u32::MAX as usize,
        "GKR sum projection exceeds CUDA ABI bounds"
    );
    n_terms
}

fn assert_sum_input_len(input_len: usize, n_terms: usize) {
    assert_eq!(
        input_len,
        n_terms << 2,
        "GKR sum projection expects exactly four evaluations per term"
    );
}

fn sum_oracle_eval_pair(
    h: &GkrMultivariatePolyOracle<'_, CudaBackend>,
    n_terms: usize,
) -> (SecureField, SecureField) {
    let mut eval_at_0 = CudaSecureField::zero();
    let mut eval_at_2 = CudaSecureField::zero();

    unsafe {
        match &h.input_layer {
            Layer::GrandProduct(col) => {
                assert_sum_input_len(col.len(), n_terms);
                bindings::gkr_sum_grand_product(
                    eq_eval_ptr(h.eq_evals.as_ref()),
                    secure_eval_ptr(col),
                    n_terms as u32,
                    &mut eval_at_0,
                    &mut eval_at_2,
                );
            }
            Layer::LogUpGeneric {
                numerators,
                denominators,
            } => {
                assert_sum_input_len(numerators.len(), n_terms);
                assert_sum_input_len(denominators.len(), n_terms);
                bindings::gkr_sum_logup_generic(
                    eq_eval_ptr(h.eq_evals.as_ref()),
                    secure_eval_ptr(numerators),
                    secure_eval_ptr(denominators),
                    n_terms as u32,
                    h.lambda.into(),
                    &mut eval_at_0,
                    &mut eval_at_2,
                );
            }
            Layer::LogUpMultiplicities {
                numerators,
                denominators,
            } => {
                assert_sum_input_len(numerators.len(), n_terms);
                assert_sum_input_len(denominators.len(), n_terms);
                bindings::gkr_sum_logup_multiplicities(
                    eq_eval_ptr(h.eq_evals.as_ref()),
                    base_eval_ptr(numerators),
                    secure_eval_ptr(denominators),
                    n_terms as u32,
                    h.lambda.into(),
                    &mut eval_at_0,
                    &mut eval_at_2,
                );
            }
            Layer::LogUpSingles { denominators } => {
                assert_sum_input_len(denominators.len(), n_terms);
                bindings::gkr_sum_logup_singles(
                    eq_eval_ptr(h.eq_evals.as_ref()),
                    secure_eval_ptr(denominators),
                    n_terms as u32,
                    h.lambda.into(),
                    &mut eval_at_0,
                    &mut eval_at_2,
                );
            }
        }
    }

    (eval_at_0.into(), eval_at_2.into())
}

#[cfg(all(test, stwo_cuda_link))]
mod tests {
    use std::borrow::Cow;

    use num_traits::{One, Zero};
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};
    use stwo::core::fields::m31::BaseField;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::fields::FieldExpOps;
    use stwo::core::Fraction;
    use stwo::prover::backend::{Column, CpuBackend};
    use stwo::prover::lookups::gkr_prover::{EqEvals, GkrMultivariatePolyOracle, GkrOps, Layer};
    use stwo::prover::lookups::mle::Mle;
    use stwo::prover::lookups::utils::{eq, Reciprocal};

    use crate::backend::{BaseFieldVec, CudaBackend, SecureFieldVec};

    #[test]
    fn gen_eq_evals_matches_cpu() {
        use itertools::Itertools;
        use stwo::prover::backend::{Column, CpuBackend};
        use stwo::prover::lookups::gkr_prover::GkrOps;

        use crate::backend::CudaBackend;

        let two = BaseField::from(2).into();

        let from_raw = [7, 3, 5, 6, 1, 1, 9].repeat(4);
        let y = from_raw
            .chunks(4)
            .map(|a| SecureField::from_u32_unchecked(a[0], a[1], a[2], a[3]))
            .collect_vec();

        let cpu_eq_evals = CpuBackend::gen_eq_evals(&y, two);
        let gpu_eq_evals = CudaBackend::gen_eq_evals(&y, two);

        assert_eq!(gpu_eq_evals.to_cpu(), *cpu_eq_evals);
    }

    #[test]
    fn next_grand_product_layer_matches_cpu() {
        let mut rng = SmallRng::seed_from_u64(0);
        let values = (0..(1 << 5))
            .map(|_| rng.gen())
            .collect::<Vec<SecureField>>();
        let cpu_layer = Layer::GrandProduct(Mle::<CpuBackend, SecureField>::new(values.clone()));
        let cuda_layer = into_cuda_layer(cpu_layer.to_cpu());

        let expected = CpuBackend::next_layer(&cpu_layer);
        let actual = CudaBackend::next_layer(&cuda_layer).to_cpu();

        assert_layers_eq(actual, expected);
    }

    #[test]
    fn next_logup_generic_layer_matches_cpu() {
        let mut rng = SmallRng::seed_from_u64(1);
        let numerators = (0..(1 << 5))
            .map(|_| rng.gen())
            .collect::<Vec<SecureField>>();
        let denominators = (0..(1 << 5))
            .map(|_| rng.gen())
            .collect::<Vec<SecureField>>();

        let cpu_layer = Layer::LogUpGeneric {
            numerators: Mle::<CpuBackend, SecureField>::new(numerators),
            denominators: Mle::<CpuBackend, SecureField>::new(denominators),
        };
        let cuda_layer = into_cuda_layer(cpu_layer.to_cpu());

        let expected = CpuBackend::next_layer(&cpu_layer);
        let actual = CudaBackend::next_layer(&cuda_layer).to_cpu();

        assert_layers_eq(actual, expected);
    }

    #[test]
    fn next_logup_multiplicities_layer_matches_cpu() {
        let mut rng = SmallRng::seed_from_u64(2);
        let numerators = (0..(1 << 5)).map(|_| rng.gen()).collect::<Vec<BaseField>>();
        let denominators = (0..(1 << 5))
            .map(|_| rng.gen())
            .collect::<Vec<SecureField>>();

        let cpu_layer = Layer::LogUpMultiplicities {
            numerators: Mle::<CpuBackend, BaseField>::new(numerators),
            denominators: Mle::<CpuBackend, SecureField>::new(denominators),
        };
        let cuda_layer = into_cuda_layer(cpu_layer.to_cpu());

        let expected = CpuBackend::next_layer(&cpu_layer);
        let actual = CudaBackend::next_layer(&cuda_layer).to_cpu();

        assert_layers_eq(actual, expected);
    }

    #[test]
    fn next_logup_singles_layer_matches_cpu() {
        let mut rng = SmallRng::seed_from_u64(3);
        let denominators = (0..(1 << 5))
            .map(|_| rng.gen())
            .collect::<Vec<SecureField>>();

        let cpu_layer = Layer::LogUpSingles {
            denominators: Mle::<CpuBackend, SecureField>::new(denominators),
        };
        let cuda_layer = into_cuda_layer(cpu_layer.to_cpu());

        let expected = CpuBackend::next_layer(&cpu_layer);
        let actual = CudaBackend::next_layer(&cuda_layer).to_cpu();

        assert_layers_eq(actual, expected);
    }

    #[test]
    fn sum_as_poly_in_first_variable_grand_product_matches_cpu() {
        let mut rng = SmallRng::seed_from_u64(4);
        let values = (0..(1 << 5))
            .map(|_| rng.gen())
            .collect::<Vec<SecureField>>();
        let y = draw_secure_field_vec(&mut rng, 4);
        let lambda = rng.gen();
        let cpu_layer = Layer::GrandProduct(Mle::<CpuBackend, SecureField>::new(values));

        assert_sum_polys_match(cpu_layer, y, lambda);
    }

    #[test]
    fn sum_as_poly_in_first_variable_logup_generic_matches_cpu() {
        let mut rng = SmallRng::seed_from_u64(5);
        let y = draw_secure_field_vec(&mut rng, 4);
        let lambda = rng.gen();
        let cpu_layer = Layer::LogUpGeneric {
            numerators: Mle::<CpuBackend, SecureField>::new(draw_secure_field_vec(
                &mut rng,
                1 << 5,
            )),
            denominators: Mle::<CpuBackend, SecureField>::new(draw_secure_field_vec(
                &mut rng,
                1 << 5,
            )),
        };

        assert_sum_polys_match(cpu_layer, y, lambda);
    }

    #[test]
    fn sum_as_poly_in_first_variable_logup_multiplicities_matches_cpu() {
        let mut rng = SmallRng::seed_from_u64(6);
        let y = draw_secure_field_vec(&mut rng, 4);
        let lambda = rng.gen();
        let cpu_layer = Layer::LogUpMultiplicities {
            numerators: Mle::<CpuBackend, BaseField>::new(
                (0..(1 << 5)).map(|_| rng.gen()).collect::<Vec<BaseField>>(),
            ),
            denominators: Mle::<CpuBackend, SecureField>::new(draw_secure_field_vec(
                &mut rng,
                1 << 5,
            )),
        };

        assert_sum_polys_match(cpu_layer, y, lambda);
    }

    #[test]
    fn sum_as_poly_in_first_variable_logup_singles_matches_cpu() {
        let mut rng = SmallRng::seed_from_u64(7);
        let y = draw_secure_field_vec(&mut rng, 4);
        let lambda = rng.gen();
        let cpu_layer = Layer::LogUpSingles {
            denominators: Mle::<CpuBackend, SecureField>::new(draw_secure_field_vec(
                &mut rng,
                1 << 5,
            )),
        };

        assert_sum_polys_match(cpu_layer, y, lambda);
    }

    fn into_cuda_layer(cpu_layer: Layer<CpuBackend>) -> Layer<CudaBackend> {
        match cpu_layer {
            Layer::GrandProduct(mle) => Layer::GrandProduct(Mle::new(
                mle.into_evals().into_iter().collect::<SecureFieldVec>(),
            )),
            Layer::LogUpGeneric {
                numerators,
                denominators,
            } => Layer::LogUpGeneric {
                numerators: Mle::new(
                    numerators
                        .into_evals()
                        .into_iter()
                        .collect::<SecureFieldVec>(),
                ),
                denominators: Mle::new(
                    denominators
                        .into_evals()
                        .into_iter()
                        .collect::<SecureFieldVec>(),
                ),
            },
            Layer::LogUpMultiplicities {
                numerators,
                denominators,
            } => Layer::LogUpMultiplicities {
                numerators: Mle::new(
                    numerators
                        .into_evals()
                        .into_iter()
                        .collect::<BaseFieldVec>(),
                ),
                denominators: Mle::new(
                    denominators
                        .into_evals()
                        .into_iter()
                        .collect::<SecureFieldVec>(),
                ),
            },
            Layer::LogUpSingles { denominators } => Layer::LogUpSingles {
                denominators: Mle::new(
                    denominators
                        .into_evals()
                        .into_iter()
                        .collect::<SecureFieldVec>(),
                ),
            },
        }
    }

    fn assert_layers_eq(actual: Layer<CpuBackend>, expected: Layer<CpuBackend>) {
        match (actual, expected) {
            (Layer::GrandProduct(actual), Layer::GrandProduct(expected)) => {
                assert_eq!(actual.into_evals(), expected.into_evals())
            }
            (
                Layer::LogUpGeneric {
                    numerators: actual_numerators,
                    denominators: actual_denominators,
                },
                Layer::LogUpGeneric {
                    numerators: expected_numerators,
                    denominators: expected_denominators,
                },
            ) => {
                assert_eq!(
                    actual_numerators.into_evals(),
                    expected_numerators.into_evals()
                );
                assert_eq!(
                    actual_denominators.into_evals(),
                    expected_denominators.into_evals()
                );
            }
            (actual, expected) => panic!(
                "layer variants differ: actual={:?}, expected={:?}",
                actual, expected
            ),
        }
    }

    fn into_cuda_oracle(
        cpu_layer: Layer<CpuBackend>,
        y: &[SecureField],
        lambda: SecureField,
    ) -> GkrMultivariatePolyOracle<'static, CudaBackend> {
        GkrMultivariatePolyOracle {
            eq_evals: Cow::Owned(EqEvals::<CudaBackend>::generate(y)),
            input_layer: into_cuda_layer(cpu_layer),
            eq_fixed_var_correction: SecureField::one(),
            lambda,
        }
    }

    fn into_cpu_oracle(
        cpu_layer: Layer<CpuBackend>,
        y: &[SecureField],
        lambda: SecureField,
    ) -> GkrMultivariatePolyOracle<'static, CpuBackend> {
        GkrMultivariatePolyOracle {
            eq_evals: Cow::Owned(EqEvals::<CpuBackend>::generate(y)),
            input_layer: cpu_layer,
            eq_fixed_var_correction: SecureField::one(),
            lambda,
        }
    }

    fn assert_sum_polys_match(
        cpu_layer: Layer<CpuBackend>,
        y: Vec<SecureField>,
        lambda: SecureField,
    ) {
        let cpu_oracle = into_cpu_oracle(cpu_layer.clone(), &y, lambda);
        let cuda_oracle = into_cuda_oracle(cpu_layer, &y, lambda);
        let claim = oracle_claim(&cpu_oracle);

        let expected = CpuBackend::sum_as_poly_in_first_variable(&cpu_oracle, claim);
        let actual = CudaBackend::sum_as_poly_in_first_variable(&cuda_oracle, claim);

        assert_eq!(&*actual, &*expected);
    }

    fn oracle_claim(oracle: &GkrMultivariatePolyOracle<'_, CpuBackend>) -> SecureField {
        let n_variables = oracle.input_layer.n_variables() - 1;
        let n_terms = 1usize << (n_variables - 1);
        let y = oracle.eq_evals.y();
        let prefix_scale = eq(
            &vec![SecureField::zero(); y.len() - n_variables + 1],
            &y[..y.len() - n_variables + 1],
        )
        .inverse();
        let scale_at_0 = prefix_scale * eq(&[SecureField::zero()], &[y[y.len() - n_variables]]);
        let scale_at_1 = prefix_scale * eq(&[SecureField::one()], &[y[y.len() - n_variables]]);

        let (f_at_0, f_at_1) = match &oracle.input_layer {
            Layer::GrandProduct(col) => claim_grand_product(col, oracle, n_terms),
            Layer::LogUpGeneric {
                numerators,
                denominators,
            } => claim_logup_generic(numerators, denominators, oracle, n_terms),
            Layer::LogUpMultiplicities {
                numerators,
                denominators,
            } => claim_logup_multiplicities(numerators, denominators, oracle, n_terms),
            Layer::LogUpSingles { denominators } => {
                claim_logup_singles(denominators, oracle, n_terms)
            }
        };

        oracle.eq_fixed_var_correction * (scale_at_0 * f_at_0 + scale_at_1 * f_at_1)
    }

    fn claim_grand_product(
        col: &Mle<CpuBackend, SecureField>,
        oracle: &GkrMultivariatePolyOracle<'_, CpuBackend>,
        n_terms: usize,
    ) -> (SecureField, SecureField) {
        let mut f_at_0 = SecureField::zero();
        let mut f_at_1 = SecureField::zero();

        for i in 0..n_terms {
            let eq_eval = oracle.eq_evals.at(i);
            f_at_0 += eq_eval * col[i * 2] * col[i * 2 + 1];
            f_at_1 += eq_eval * col[(n_terms + i) * 2] * col[(n_terms + i) * 2 + 1];
        }

        (f_at_0, f_at_1)
    }

    fn claim_logup_generic(
        numerators: &Mle<CpuBackend, SecureField>,
        denominators: &Mle<CpuBackend, SecureField>,
        oracle: &GkrMultivariatePolyOracle<'_, CpuBackend>,
        n_terms: usize,
    ) -> (SecureField, SecureField) {
        let mut f_at_0 = SecureField::zero();
        let mut f_at_1 = SecureField::zero();

        for i in 0..n_terms {
            let eq_eval = oracle.eq_evals.at(i);

            let Fraction {
                numerator: numerator_at_r0,
                denominator: denominator_at_r0,
            } = Fraction::new(numerators[i * 2], denominators[i * 2])
                + Fraction::new(numerators[i * 2 + 1], denominators[i * 2 + 1]);
            let Fraction {
                numerator: numerator_at_r1,
                denominator: denominator_at_r1,
            } = Fraction::new(
                numerators[(n_terms + i) * 2],
                denominators[(n_terms + i) * 2],
            ) + Fraction::new(
                numerators[(n_terms + i) * 2 + 1],
                denominators[(n_terms + i) * 2 + 1],
            );

            f_at_0 += eq_eval * (numerator_at_r0 + oracle.lambda * denominator_at_r0);
            f_at_1 += eq_eval * (numerator_at_r1 + oracle.lambda * denominator_at_r1);
        }

        (f_at_0, f_at_1)
    }

    fn claim_logup_multiplicities(
        numerators: &Mle<CpuBackend, BaseField>,
        denominators: &Mle<CpuBackend, SecureField>,
        oracle: &GkrMultivariatePolyOracle<'_, CpuBackend>,
        n_terms: usize,
    ) -> (SecureField, SecureField) {
        let mut f_at_0 = SecureField::zero();
        let mut f_at_1 = SecureField::zero();

        for i in 0..n_terms {
            let eq_eval = oracle.eq_evals.at(i);

            let Fraction {
                numerator: numerator_at_r0,
                denominator: denominator_at_r0,
            } = Fraction::new(numerators[i * 2], denominators[i * 2])
                + Fraction::new(numerators[i * 2 + 1], denominators[i * 2 + 1]);
            let Fraction {
                numerator: numerator_at_r1,
                denominator: denominator_at_r1,
            } = Fraction::new(
                numerators[(n_terms + i) * 2],
                denominators[(n_terms + i) * 2],
            ) + Fraction::new(
                numerators[(n_terms + i) * 2 + 1],
                denominators[(n_terms + i) * 2 + 1],
            );

            f_at_0 += eq_eval * (numerator_at_r0 + oracle.lambda * denominator_at_r0);
            f_at_1 += eq_eval * (numerator_at_r1 + oracle.lambda * denominator_at_r1);
        }

        (f_at_0, f_at_1)
    }

    fn claim_logup_singles(
        denominators: &Mle<CpuBackend, SecureField>,
        oracle: &GkrMultivariatePolyOracle<'_, CpuBackend>,
        n_terms: usize,
    ) -> (SecureField, SecureField) {
        let mut f_at_0 = SecureField::zero();
        let mut f_at_1 = SecureField::zero();

        for i in 0..n_terms {
            let eq_eval = oracle.eq_evals.at(i);

            let Fraction {
                numerator: numerator_at_r0,
                denominator: denominator_at_r0,
            } = Reciprocal::new(denominators[i * 2]) + Reciprocal::new(denominators[i * 2 + 1]);
            let Fraction {
                numerator: numerator_at_r1,
                denominator: denominator_at_r1,
            } = Reciprocal::new(denominators[(n_terms + i) * 2])
                + Reciprocal::new(denominators[(n_terms + i) * 2 + 1]);

            f_at_0 += eq_eval * (numerator_at_r0 + oracle.lambda * denominator_at_r0);
            f_at_1 += eq_eval * (numerator_at_r1 + oracle.lambda * denominator_at_r1);
        }

        (f_at_0, f_at_1)
    }

    fn draw_secure_field_vec(rng: &mut SmallRng, len: usize) -> Vec<SecureField> {
        (0..len).map(|_| rng.gen()).collect()
    }
}
