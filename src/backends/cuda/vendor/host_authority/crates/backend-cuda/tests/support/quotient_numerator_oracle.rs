use stwo::core::circle::CirclePoint;
use stwo::core::constraints::complex_conjugate_line_coeffs;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::pcs::quotients::PointSample;

pub struct OracleTerm<'a> {
    pub exponent: usize,
    pub source_log: u32,
    pub value: SecureField,
    pub point: CirclePoint<SecureField>,
    pub source: &'a [u32],
}

pub fn expected_group(
    group_point: CirclePoint<SecureField>,
    group_log: u32,
    alpha: SecureField,
    terms: &[OracleTerm<'_>],
) -> (SecureField, [Vec<u32>; 4]) {
    let matching = terms
        .iter()
        .filter(|term| term.point == group_point)
        .collect::<Vec<_>>();
    let coefficients = matching
        .iter()
        .map(|term| {
            complex_conjugate_line_coeffs(
                &PointSample {
                    point: term.point,
                    value: term.value,
                },
                alpha.pow(term.exponent as u128),
            )
        })
        .collect::<Vec<_>>();
    let first = coefficients.iter().map(|(a, ..)| *a).sum();
    let size = 1usize << group_log;
    let mut output: [Vec<u32>; 4] = std::array::from_fn(|_| vec![0; size]);
    for row in 0..size {
        let mut numerator = SecureField::from(0u32);
        for (term, (_, b, c)) in matching.iter().zip(&coefficients) {
            let ratio = group_log
                .checked_sub(term.source_log)
                .expect("quotient oracle source log exceeds group log");
            let source_row = (row >> (ratio + 1) << 1) + (row & 1);
            numerator += BaseField::from_u32_unchecked(term.source[source_row]) * *c - *b;
        }
        for (coordinate, value) in numerator.to_m31_array().into_iter().enumerate() {
            output[coordinate][row] = value.0;
        }
    }
    (first, output)
}
