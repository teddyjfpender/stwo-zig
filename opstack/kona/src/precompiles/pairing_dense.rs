//! Opt-in dense BN254 Fq12 products using the EXISTING admitted sparse034
//! service. No new tag, packet, hint, prover equation or whitelist is introduced.
//!
//! For v^3=9+u and w^2=v, write b=S0+v*S1+v^2*S2, with each S a sparse034
//! value. Then a*b=a*S0+v*(a*S1)+v^2*(a*S2). The three service outputs are
//! canonical and the remaining tower rotations/additions execute in the guest.
//! Extra sparse calls are a real prover cost; guest savings must be measured.
use ark_bn254::{Fq, Fq12, Fq2, Fq6};
use ark_ff::{AdditiveGroup, One};

#[inline(always)]
fn times_nonresidue(value: Fq2) -> Fq2 {
    let mut eight = value;
    eight.double_in_place().double_in_place().double_in_place();
    Fq2::new(
        eight.c0 + value.c0 - value.c1,
        eight.c1 + value.c1 + value.c0,
    )
}
#[inline(always)]
fn times_v(value: Fq12) -> Fq12 {
    Fq12::new(
        Fq6::new(times_nonresidue(value.c0.c2), value.c0.c0, value.c0.c1),
        Fq6::new(times_nonresidue(value.c1.c2), value.c1.c0, value.c1.c1),
    )
}
#[inline(always)]
fn times_v_squared(value: Fq12) -> Fq12 {
    Fq12::new(
        Fq6::new(
            times_nonresidue(value.c0.c1),
            times_nonresidue(value.c0.c2),
            value.c0.c0,
        ),
        Fq6::new(
            times_nonresidue(value.c1.c1),
            times_nonresidue(value.c1.c2),
            value.c1.c0,
        ),
    )
}
#[inline(always)]
fn product(a: &Fq12, b: &Fq12) -> Fq12 {
    let one = Fq::one();
    let zero = Fq2::ZERO;
    let mut first = *a;
    let mut second = *a;
    let mut third = *a;
    super::sparse::miller_line(&mut first, &b.c0.c0, &b.c1.c0, &b.c1.c1, &one, &one);
    super::sparse::miller_line(&mut second, &b.c0.c1, &zero, &b.c1.c2, &one, &one);
    super::sparse::miller_line(&mut third, &b.c0.c2, &zero, &zero, &one, &one);
    first + times_v(second) + times_v_squared(third)
}
#[inline(always)]
pub(super) fn square(value: &mut Fq12) {
    let input = *value;
    *value = product(&input, &input);
}
#[inline(always)]
pub(super) fn multiply(value: &mut Fq12, other: &Fq12) {
    *value = product(value, other);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Field, PrimeField};
    fn value(seed: u64) -> Fq12 {
        let mut at = 0u64;
        let mut fq = || {
            at += 1;
            let bytes = [
                seed.wrapping_mul(0x9e3779b97f4a7c15)
                    .wrapping_add(at)
                    .to_le_bytes(),
                (seed ^ at).to_le_bytes(),
                u64::MAX.to_le_bytes(),
                (seed + at).to_le_bytes(),
            ]
            .concat();
            Fq::from_le_bytes_mod_order(&bytes)
        };
        let mut fp2 = || Fq2::new(fq(), fq());
        Fq12::new(Fq6::new(fp2(), fp2(), fp2()), Fq6::new(fp2(), fp2(), fp2()))
    }
    #[test]
    fn sparse_decomposition_matches_independent_dense_arkworks_tower() {
        for seed in 0..64 {
            let a = value(seed);
            let b = value(seed + 97);
            assert_eq!(product(&a, &b), a * b);
            let mut square = a;
            super::square(&mut square);
            assert_eq!(square, a.square());
            let mut inplace = a;
            multiply(&mut inplace, &b);
            assert_eq!(inplace, a * b);
        }
    }
    #[test]
    fn sparse_decomposition_preserves_zero_one_and_high_canonical_values() {
        let high = Fq2::new(-Fq::one(), -Fq::one());
        let full = Fq12::new(Fq6::new(high, high, high), Fq6::new(high, high, high));
        for a in [Fq12::ZERO, Fq12::one(), full] {
            for b in [Fq12::ZERO, Fq12::one(), full, value(17)] {
                assert_eq!(product(&a, &b), a * b);
            }
        }
    }
    #[test]
    fn every_basis_wrap_and_in_place_square_matches_dense_reference() {
        fn basis(index: usize) -> Fq12 {
            let mut c = [Fq::ZERO; 12];
            c[index] = Fq::one();
            Fq12::new(
                Fq6::new(
                    Fq2::new(c[0], c[1]),
                    Fq2::new(c[2], c[3]),
                    Fq2::new(c[4], c[5]),
                ),
                Fq6::new(
                    Fq2::new(c[6], c[7]),
                    Fq2::new(c[8], c[9]),
                    Fq2::new(c[10], c[11]),
                ),
            )
        }
        for i in 0..12 {
            for j in 0..12 {
                let a = basis(i);
                let b = basis(j);
                assert_eq!(product(&a, &b), a * b, "basis {i}/{j}");
            }
        }
        let a = value(71);
        let mut conjugate = a;
        conjugate.conjugate_in_place();
        assert_ne!(
            a * conjugate,
            Fq12::one(),
            "fixture must not assume a unitary/cyclotomic accumulator"
        );
        let mut inplace = a;
        let same_value = inplace;
        multiply(&mut inplace, &same_value);
        assert_eq!(inplace, a.square());
        super::square(&mut inplace);
        assert_eq!(inplace, a.square().square());
    }
}
