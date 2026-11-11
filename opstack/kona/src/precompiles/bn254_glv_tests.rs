use super::*;
const LAMBDA: U256 = uint!(0x30644e72e131a029048b6e193fd84104cc37a73fec2bc5e9b8ca0b2d36636f23_U256);

#[test]
fn reciprocal_division_and_signed_split_match_full_width_arithmetic() {
    let mut cases = alloc::vec![
        U256::ZERO,
        U256::from(1),
        ORDER - U256::from(1),
        ORDER / U256::from(2),
        C,
        C - U256::from(1)
    ];
    let mut seed = 0x3714c926ba812d03u64;
    for _ in 0..1024 {
        let mut limbs = [0; 4];
        for x in &mut limbs {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *x = seed;
        }
        cases.push(U256::from_limbs(limbs) % ORDER);
    }
    for k in cases {
        for (c, r) in [(C, RECIP_C), (B, RECIP_B)] {
            let n: U512 = k.widening_mul(c);
            assert_eq!(U512::from(quotient(k, c, r)), n / U512::from(ORDER));
        }
        let (a, b, positive) = split(k);
        assert!(U256::from(a) < C && U256::from(b) < C);
        let b = U256::from(b);
        let signed = if positive || b.is_zero() {
            b
        } else {
            ORDER - b
        };
        assert_eq!(mul_add(LAMBDA, signed, U256::from(a), ORDER), k);
    }
}
