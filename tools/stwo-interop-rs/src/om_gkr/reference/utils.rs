// Mechanically lifted from pinned Stwo; see provenance.json.
use std::iter::zip;
use std::ops::{Add, Deref, Mul, Neg, Sub};

use num_traits::Zero;

use crate::om_gkr::SecureField;
use stwo::core::fields::{ExtensionOf, Field};
use stwo::core::Fraction;

/// Univariate polynomial stored as coefficients in the monomial basis.
#[derive(Debug, Clone)]
pub struct UnivariatePoly<F: Field>(pub(crate) Vec<F>);

impl<F: Field> UnivariatePoly<F> {
    pub fn new(coeffs: Vec<F>) -> Self {
        let mut polynomial = Self(coeffs);
        polynomial.truncate_leading_zeros();
        polynomial
    }

    pub fn eval_at_point(&self, x: F) -> F {
        horner_eval(&self.0, x)
    }

    // <https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Polynomial_interpolation>
    pub fn interpolate_lagrange(xs: &[F], ys: &[F]) -> Self {
        assert_eq!(xs.len(), ys.len());

        let mut coeffs = Self::zero();

        for (i, (xi, yi)) in zip(xs, ys).enumerate() {
            let mut prod = *yi;

            for (j, xj) in xs.iter().enumerate() {
                if i != j {
                    prod /= *xi - *xj;
                }
            }

            let mut term = Self::new(vec![prod]);

            for (j, xj) in xs.iter().enumerate() {
                if i != j {
                    term = term * (Self::x() - Self::new(vec![*xj]));
                }
            }

            coeffs = coeffs + term;
        }

        coeffs.truncate_leading_zeros();

        coeffs
    }

    pub fn degree(&self) -> usize {
        let mut coeffs = self.0.iter().rev();
        let _ = (&mut coeffs).take_while(|v| v.is_zero());
        coeffs.len().saturating_sub(1)
    }

    fn x() -> Self {
        Self(vec![F::zero(), F::one()])
    }

    fn truncate_leading_zeros(&mut self) {
        while self.0.last() == Some(&F::zero()) {
            self.0.pop();
        }
    }
}

impl<F: Field> From<F> for UnivariatePoly<F> {
    fn from(value: F) -> Self {
        Self::new(vec![value])
    }
}

impl<F: Field> Mul<F> for UnivariatePoly<F> {
    type Output = Self;

    fn mul(mut self, rhs: F) -> Self {
        self.0.iter_mut().for_each(|coeff| *coeff *= rhs);
        self
    }
}

impl<F: Field> Mul for UnivariatePoly<F> {
    type Output = Self;

    fn mul(mut self, mut rhs: Self) -> Self {
        if self.is_zero() || rhs.is_zero() {
            return Self::zero();
        }

        self.truncate_leading_zeros();
        rhs.truncate_leading_zeros();

        let mut res = vec![F::zero(); self.0.len() + rhs.0.len() - 1];

        for (i, coeff_a) in self.0.into_iter().enumerate() {
            for (j, coeff_b) in rhs.0.iter().enumerate() {
                res[i + j] += coeff_a * *coeff_b;
            }
        }

        Self::new(res)
    }
}

impl<F: Field> Add for UnivariatePoly<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let n = self.0.len().max(rhs.0.len());
        let mut res = Vec::new();

        for i in 0..n {
            res.push(match (self.0.get(i), rhs.0.get(i)) {
                (Some(a), Some(b)) => *a + *b,
                (Some(a), None) | (None, Some(a)) => *a,
                _ => unreachable!(),
            })
        }

        Self(res)
    }
}

impl<F: Field> Sub for UnivariatePoly<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl<F: Field> Neg for UnivariatePoly<F> {
    type Output = Self;

    fn neg(self) -> Self {
        Self(self.0.into_iter().map(|v| -v).collect())
    }
}

impl<F: Field> Zero for UnivariatePoly<F> {
    fn zero() -> Self {
        Self(vec![])
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(F::is_zero)
    }
}

impl<F: Field> Deref for UnivariatePoly<F> {
    type Target = [F];

    fn deref(&self) -> &[F] {
        &self.0
    }
}

/// Evaluates univariate polynomial using [Horner's method].
///
/// [Horner's method]: https://en.wikipedia.org/wiki/Horner%27s_method
pub fn horner_eval<F: Field>(coeffs: &[F], x: F) -> F {
    coeffs
        .iter()
        .rfold(F::zero(), |acc, coeff| acc * x + *coeff)
}

/// Returns `v_0 + alpha * v_1 + ... + alpha^(n-1) * v_{n-1}`.
pub fn random_linear_combination(v: &[SecureField], alpha: SecureField) -> SecureField {
    horner_eval(v, alpha)
}

/// Evaluates the lagrange kernel of the boolean hypercube.
///
/// The lagrange kernel of the boolean hypercube is a multilinear extension of the function that
/// when given `x, y` in `{0, 1}^n` evaluates to 1 if `x = y`, and evaluates to 0 otherwise.
pub fn eq<F: Field>(x: &[F], y: &[F]) -> F {
    assert_eq!(x.len(), y.len());
    zip(x, y)
        .map(|(xi, yi)| *xi * *yi + (F::one() - *xi) * (F::one() - *yi))
        .product()
}

/// Computes `eq(0, assignment) * eval0 + eq(1, assignment) * eval1`.
pub fn fold_mle_evals<F>(assignment: SecureField, eval0: F, eval1: F) -> SecureField
where
    F: Field,
    SecureField: ExtensionOf<F>,
{
    assignment * (eval1 - eval0) + eval0
}

/// Represents the fraction `1 / x`
pub struct Reciprocal<T> {
    x: T,
}

impl<T> Reciprocal<T> {
    pub const fn new(x: T) -> Self {
        Self { x }
    }
}

impl<T: Add<Output = T> + Mul<Output = T> + Clone> Add for Reciprocal<T> {
    type Output = Fraction<T, T>;

    fn add(self, rhs: Self) -> Fraction<T, T> {
        // `1/a + 1/b = (a + b)/(a * b)`
        Fraction {
            numerator: self.x.clone() + rhs.x.clone(),
            denominator: self.x * rhs.x,
        }
    }
}

impl<T: Sub<Output = T> + Mul<Output = T> + Clone> Sub for Reciprocal<T> {
    type Output = Fraction<T, T>;

    fn sub(self, rhs: Self) -> Fraction<T, T> {
        // `1/a - 1/b = (b - a)/(a * b)`
        Fraction {
            numerator: rhs.x.clone() - self.x.clone(),
            denominator: self.x * rhs.x,
        }
    }
}
