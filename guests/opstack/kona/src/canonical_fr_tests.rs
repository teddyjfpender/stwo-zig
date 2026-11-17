//! Independent Montgomery reference checks for the opt-in canonical Fr backend.
#![allow(unexpected_cfgs)]
use ark_bls12_381::{Fr, FrConfig, G1Projective};
use ark_ec::{AdditiveGroup, CurveGroup, PrimeGroup};
use ark_ff::{BigInt, BigInteger, FftField, Field, MontBackend, MontConfig, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(MontConfig)]
#[modulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[generator = "7"]
#[small_subgroup_base = "3"]
#[small_subgroup_power = "1"]
struct ReferenceConfig;
type Reference = ark_ff::Fp<MontBackend<ReferenceConfig, 4>, 4>;
fn reference(v: Fr) -> Reference {
    Reference::from_bigint(v.into_bigint()).unwrap()
}

#[test]
fn roots_configuration_and_packet() {
    assert!(FrConfig::CANONICAL_REPRESENTATION);
    assert_eq!(FrConfig::R, BigInt([1, 0, 0, 0]));
    assert_eq!(FrConfig::R2, FrConfig::R);
    assert_eq!(reference(FrConfig::GENERATOR), ReferenceConfig::GENERATOR);
    assert_eq!(
        reference(FrConfig::TWO_ADIC_ROOT_OF_UNITY),
        ReferenceConfig::TWO_ADIC_ROOT_OF_UNITY
    );
    assert_eq!(
        reference(FrConfig::LARGE_SUBGROUP_ROOT_OF_UNITY.unwrap()),
        ReferenceConfig::LARGE_SUBGROUP_ROOT_OF_UNITY.unwrap()
    );
    assert_eq!(
        Fr::get_root_of_unity(4096).unwrap().into_bigint(),
        Reference::get_root_of_unity(4096).unwrap().into_bigint()
    );
    let request = ark_bls12_381::stwo_canonical_fr_packet([2, 3, 4, 5], [6, 7, 8, 9]);
    assert_eq!(&request[..8], &[2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(&request[8..12], &[0; 4]);
    assert_eq!(&request[12..16], &Fr::MODULUS.0);
    assert_eq!(&request[16..], &[0; 4]);
}
#[test]
fn high_edges_inversion_sqrt_serialization() {
    assert!(Fr::from_bigint(Fr::MODULUS).is_none());
    assert!(Fr::from_bigint(BigInt([u64::MAX; 4])).is_none());
    let mut high = Fr::MODULUS;
    high.sub_with_borrow(&BigInt([1, 0, 0, 0]));
    assert_eq!(
        Fr::new(BigInt([u64::MAX; 4])).into_bigint(),
        Reference::from_be_bytes_mod_order(&[255u8; 32]).into_bigint()
    );
    let values = [
        Fr::ZERO,
        Fr::ONE,
        Fr::from(2u64),
        Fr::from_bigint(high).unwrap(),
        Fr::new(BigInt([u64::MAX; 4])),
    ];
    for a in values {
        for b in values {
            assert_eq!(
                (a * b).into_bigint(),
                (reference(a) * reference(b)).into_bigint()
            );
            assert_eq!(
                (a + b).into_bigint(),
                (reference(a) + reference(b)).into_bigint()
            );
            assert_eq!(
                (a - b).into_bigint(),
                (reference(a) - reference(b)).into_bigint()
            );
        }
        assert_eq!(
            a.inverse().map(|v| v.into_bigint()),
            reference(a).inverse().map(|v| v.into_bigint())
        );
        assert_eq!(a.square().sqrt().unwrap().square(), a.square());
        assert_eq!(a.legendre(), reference(a).legendre());
        let mut raw = alloc::vec::Vec::new();
        a.serialize_compressed(&mut raw).unwrap();
        let mut expected = alloc::vec::Vec::new();
        reference(a).serialize_compressed(&mut expected).unwrap();
        assert_eq!(raw, expected);
        assert_eq!(Fr::deserialize_compressed(raw.as_slice()).unwrap(), a);
    }
}
#[test]
fn deterministic_products_and_group_scalar_semantics() {
    let mut seed = 0x9e3779b97f4a7c15u64;
    for n in 0..128 {
        let mut limbs = [0; 4];
        for limb in &mut limbs {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *limb = seed;
        }
        let a = Fr::new(BigInt(limbs));
        let b = a + Fr::from(17u64);
        assert_eq!(
            (a * b).into_bigint(),
            (reference(a) * reference(b)).into_bigint()
        );
        assert_eq!(
            a.square().into_bigint(),
            reference(a).square().into_bigint()
        );
        if !a.is_zero() {
            assert_eq!(a * a.inverse().unwrap(), Fr::ONE);
        }
        assert_eq!(a.square().sqrt().unwrap().square(), a.square());
        if n < 8 {
            let generator = G1Projective::generator();
            let actual = generator * a;
            let mut expected = G1Projective::ZERO;
            let scalar = a.into_bigint();
            for limb in scalar.0.iter().rev() {
                for bit in (0..64).rev() {
                    expected.double_in_place();
                    if limb & (1 << bit) != 0 {
                        expected += generator;
                    }
                }
            }
            assert_eq!(actual.into_affine(), expected.into_affine());
        }
    }
}
