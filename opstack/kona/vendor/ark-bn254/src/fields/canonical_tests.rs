//! Differential tests execute canonical storage on native too; they do not
//! silently select the original Montgomery config under cfg(test).
use super::{Fq, Fq2};
#[derive(ark_ff::MontConfig)]
#[modulus = "21888242871839275222246405745257275088696311157297823662689037894645226208583"]
#[generator = "3"]
struct SoftwareConfig;
use ark_ff::{
    AdditiveGroup, BigInt, FftField, Field, Fp, Fp2, Fp2Config, MontBackend, MontFp, PrimeField,
    Zero,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
type Ref = Fp<MontBackend<SoftwareConfig, 4>, 4>;
struct Ref2Config;
impl Fp2Config for Ref2Config {
    type Fp = Ref;
    const NONRESIDUE: Ref = MontFp!("-1");
    const FROBENIUS_COEFF_FP2_C1: &'static [Ref] = &[Ref::ONE, MontFp!("-1")];
}
type Ref2 = Fp2<Ref2Config>;
fn same(a: Fq, b: Ref) {
    assert_eq!(a.0, b.into_bigint());
}
fn same2(a: Fq2, b: Ref2) {
    same(a.c0, b.c0);
    same(a.c1, b.c1);
}
#[test]
fn canonical_constants_conversion_serialization_and_field_operations() {
    const ONE: Fq = MontFp!("1");
    const NEG_ONE: Fq = MontFp!("-1");
    assert_eq!(ONE.0, BigInt([1, 0, 0, 0]));
    assert_ne!(Ref::ONE.0, ONE.0);
    same(NEG_ONE, -Ref::ONE);
    same(Fq::GENERATOR, Ref::GENERATOR);
    same(Fq::TWO_ADIC_ROOT_OF_UNITY, Ref::TWO_ADIC_ROOT_OF_UNITY);
    assert_eq!(Fq::R, ONE.0);
    assert_eq!(Fq::R2, ONE.0);
    assert!(Fq::from_bigint(Fq::MODULUS).is_none());
    assert!(Fq::from_bigint(BigInt([u64::MAX; 4])).is_none());
    assert!(Fq::zero().inverse().is_none());
    let mut seed = 0x93a721d015bc42f7u64;
    for _ in 0..128 {
        let mut limbs = [0; 4];
        for limb in &mut limbs {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *limb = seed;
        }
        let bytes: ark_std::vec::Vec<u8> = limbs.iter().flat_map(|x| x.to_le_bytes()).collect();
        let x = Ref::from_le_bytes_mod_order(&bytes);
        let a = Fq::from_le_bytes_mod_order(&bytes);
        let y = x.square() + Ref::from(17u64);
        let b = Fq::from_bigint(y.into_bigint()).unwrap();
        same(a, x);
        same(a + b, x + y);
        same(a - b, x - y);
        same(-a, -x);
        same(a * b, x * y);
        same(a.square(), x.square());
        same(a.double(), x.double());
        same(a.inverse().unwrap(), x.inverse().unwrap());
        same(Fq::sum_of_products(&[a, b], &[b, -a]), Ref::zero());
        assert!(a.square().sqrt().unwrap().square() == a.square());
        let mut expected = ark_std::vec::Vec::new();
        x.serialize_compressed(&mut expected).unwrap();
        let mut actual = ark_std::vec::Vec::new();
        a.serialize_compressed(&mut actual).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(Fq::deserialize_compressed(actual.as_slice()).unwrap(), a);
        // Const constructor accepts full-width values and must reduce them too.
        same(Fq::new(BigInt(limbs)), Ref::from_le_bytes_mod_order(&bytes));
        let c = Fq2::new(a, b);
        let d = Fq2::new(b, -a);
        let e = Ref2::new(x, y);
        let f = Ref2::new(y, -x);
        same2(c * d, e * f);
        same2(c.square(), e.square());
        same2(c.inverse().unwrap(), e.inverse().unwrap());
        same2(c * Fq2::new(b, Fq::zero()), e * Ref2::new(y, Ref::zero()));
        // Both scalar positions use the specialized two-product path.
        same2(Fq2::new(b, Fq::zero()) * c, Ref2::new(y, Ref::zero()) * e);
        for scalar in [Fq::zero(), Fq::ONE, -Fq::ONE] {
            let reference = Ref::from_bigint(scalar.into_bigint()).unwrap();
            same2(
                c * Fq2::new(scalar, Fq::zero()),
                e * Ref2::new(reference, Ref::zero()),
            );
            same2(
                Fq2::new(scalar, Fq::zero()) * c,
                Ref2::new(reference, Ref::zero()) * e,
            );
        }
    }
}
