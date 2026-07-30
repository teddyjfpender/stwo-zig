#[path = "support/quotient_numerator_oracle.rs"]
mod oracle;

use oracle::{expected_group, OracleTerm};
use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;
use stwo::core::constraints::complex_conjugate_line_coeffs;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::PointSample;

#[test]
fn one_term_oracle_accumulates_the_term_exactly_once() {
    let point = SECURE_FIELD_CIRCLE_GEN.mul(3);
    let value = SecureField::from_u32_unchecked(2, 3, 5, 7);
    let alpha = SecureField::from_u32_unchecked(11, 13, 17, 19);
    let source = [23u32, 29, 31, 37];
    let term = OracleTerm {
        exponent: 0,
        source_log: 2,
        value,
        point,
        source: &source,
    };

    let (first, output) = expected_group(point, 2, alpha, &[term]);
    let (a, b, c) =
        complex_conjugate_line_coeffs(&PointSample { point, value }, SecureField::from(1u32));
    assert_eq!(first, a);
    for row in 0..4 {
        let expected = BaseField::from_u32_unchecked(source[row]) * c - b;
        let words = expected.to_m31_array();
        for coordinate in 0..4 {
            assert_eq!(output[coordinate][row], words[coordinate].0);
        }
    }
}

#[test]
#[should_panic(expected = "quotient oracle source log exceeds group log")]
fn oracle_rejects_source_log_larger_than_group() {
    let point = SECURE_FIELD_CIRCLE_GEN.mul(3);
    let term = OracleTerm {
        exponent: 0,
        source_log: 3,
        value: SecureField::from(0u32),
        point,
        source: &[0; 8],
    };

    expected_group(point, 2, SecureField::from(1u32), &[term]);
}
