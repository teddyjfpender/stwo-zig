//! Opt-in canonical Fr255 storage, using admitted arith256_mod (0x00030021).
//! Default BLS12-381 field/curve representations are untouched.
use super::Fr;
use ark_ff::{BigInt, MontConfig, Zero};
#[cfg(not(target_arch = "riscv64"))]
use ark_ff::{MontBackend, PrimeField};

#[derive(MontConfig)]
#[modulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[generator = "7"]
#[small_subgroup_base = "3"]
#[small_subgroup_power = "1"]
pub(super) struct SoftwareConfig;
#[cfg(not(target_arch = "riscv64"))]
type Software = ark_ff::Fp<MontBackend<SoftwareConfig, 4>, 4>;

pub struct FrConfig;
impl MontConfig<4> for FrConfig {
    const CANONICAL_REPRESENTATION: bool = true;
    const MODULUS: BigInt<4> = SoftwareConfig::MODULUS;
    const R: BigInt<4> = BigInt([1, 0, 0, 0]);
    const R2: BigInt<4> = Self::R;
    const GENERATOR: Fr = Fr::new_unchecked(BigInt([7, 0, 0, 0]));
    const TWO_ADIC_ROOT_OF_UNITY: Fr = ark_ff::MontFp!(
        "10238227357739495823651030575849232062558860180284477541189508159991286009131"
    );
    const SMALL_SUBGROUP_BASE: Option<u32> = Some(3);
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = Some(1);
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Fr> = Some(ark_ff::MontFp!(
        "27190014779860110908007675333221278800259766657973320723066279455788162251031"
    ));
    #[inline(always)]
    fn mul_assign(a: &mut Fr, b: &Fr) {
        a.0 = product(a.0, b.0);
    }
    #[inline(always)]
    fn square_in_place(a: &mut Fr) {
        a.0 = product(a.0, a.0);
    }
    fn sum_of_products<const M: usize>(a: &[Fr; M], b: &[Fr; M]) -> Fr {
        let mut result = Fr::zero();
        for (a, b) in a.iter().zip(b) {
            result += Fr::new_unchecked(product(a.0, b.0));
        }
        result
    }
    #[inline(always)]
    fn from_bigint(value: BigInt<4>) -> Option<Fr> {
        (value < Self::MODULUS).then(|| Fr::new_unchecked(value))
    }
    #[inline(always)]
    fn into_bigint(value: Fr) -> BigInt<4> {
        value.0
    }
    // The inherited binary inverse starts at R2=1 and remains canonical. Generic
    // additions, subtraction, negation and sqrt use this field's canonical roots.
}
#[repr(C, align(32))]
pub(super) struct Packet(pub(super) [u64; 20]);
const _: () =
    assert!(core::mem::size_of::<Packet>() == 160 && core::mem::align_of::<Packet>() == 32);
pub(super) fn packet(a: [u64; 4], b: [u64; 4]) -> Packet {
    let p = FrConfig::MODULUS.0;
    Packet([
        a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], 0, 0, 0, 0, p[0], p[1], p[2], p[3], 0, 0,
        0, 0,
    ])
}
#[inline(always)]
fn product(a: BigInt<4>, b: BigInt<4>) -> BigInt<4> {
    if (a.0[0] | a.0[1] | a.0[2] | a.0[3]) == 0 || (b.0[0] | b.0[1] | b.0[2] | b.0[3]) == 0 {
        return BigInt([0; 4]);
    }
    if a.0[0] == 1 && (a.0[1] | a.0[2] | a.0[3]) == 0 {
        return b;
    }
    if b.0[0] == 1 && (b.0[1] | b.0[2] | b.0[3]) == 0 {
        return a;
    }
    product_nontrivial(a, b)
}
#[cfg(target_arch = "riscv64")]
#[allow(unsafe_code)]
#[inline(always)]
fn product_nontrivial(a: BigInt<4>, b: BigInt<4>) -> BigInt<4> {
    let mut request = packet(a.0, b.0);
    // SAFETY: unique initialized160-byte aligned packet; the existing admitted
    // relation reads a,b,c=0,m and writes only output words16..20. Native builds
    // compile the separate software path below and never execute this ECALL.
    unsafe {
        core::arch::asm!("ecall",in("a0")request.0.as_mut_ptr(),in("a7")0x0003_0021usize,options(nostack));
    }
    BigInt([request.0[16], request.0[17], request.0[18], request.0[19]])
}
#[cfg(not(target_arch = "riscv64"))]
fn product_nontrivial(a: BigInt<4>, b: BigInt<4>) -> BigInt<4> {
    (Software::from_bigint(a).unwrap() * Software::from_bigint(b).unwrap()).into_bigint()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
    fn software(v: Fr) -> Software {
        Software::from_bigint(v.into_bigint()).unwrap()
    }
    #[test]
    fn constants_roots_and_packet() {
        assert_eq!(FrConfig::R, BigInt([1, 0, 0, 0]));
        assert_eq!(FrConfig::R2, FrConfig::R);
        assert_eq!(software(FrConfig::GENERATOR), SoftwareConfig::GENERATOR);
        assert_eq!(
            software(FrConfig::TWO_ADIC_ROOT_OF_UNITY),
            SoftwareConfig::TWO_ADIC_ROOT_OF_UNITY
        );
        assert_eq!(
            software(FrConfig::LARGE_SUBGROUP_ROOT_OF_UNITY.unwrap()),
            SoftwareConfig::LARGE_SUBGROUP_ROOT_OF_UNITY.unwrap()
        );
        assert_eq!(FrConfig::TWO_ADIC_ROOT_OF_UNITY.pow([1u64 << 32]), Fr::ONE);
        let request = packet([2, 3, 4, 5], [6, 7, 8, 9]);
        assert_eq!(&request.0[..8], &[2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(&request.0[8..12], &[0; 4]);
        assert_eq!(&request.0[12..16], &FrConfig::MODULUS.0);
        assert_eq!(&request.0[16..], &[0; 4]);
    }
    #[test]
    fn canonical_edges_inverses_and_square_roots() {
        assert!(Fr::from_bigint(FrConfig::MODULUS).is_none());
        assert!(Fr::from_bigint(BigInt([u64::MAX; 4])).is_none());
        let mut high = FrConfig::MODULUS;
        high.sub_with_borrow(&BigInt([1, 0, 0, 0]));
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
                    (software(a) * software(b)).into_bigint()
                );
                assert_eq!(
                    (a + b).into_bigint(),
                    (software(a) + software(b)).into_bigint()
                );
                assert_eq!(
                    (a - b).into_bigint(),
                    (software(a) - software(b)).into_bigint()
                );
            }
            assert_eq!(
                a.inverse().map(|x| x.into_bigint()),
                software(a).inverse().map(|x| x.into_bigint())
            );
            let square = a.square();
            let root = square.sqrt().unwrap();
            assert_eq!(root.square(), square);
        }
        assert_eq!(
            Fr::from(7u64).legendre(),
            software(Fr::from(7u64)).legendre()
        );
    }
    #[test]
    fn deterministic_field_agreement() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        for _ in 0..128 {
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
                (software(a) * software(b)).into_bigint()
            );
            assert_eq!(a.square().into_bigint(), software(a).square().into_bigint());
            if !a.is_zero() {
                assert_eq!(
                    (a * a.inverse().unwrap()).into_bigint(),
                    BigInt([1, 0, 0, 0])
                );
            }
            assert_eq!(a.square().sqrt().unwrap().square(), a.square());
        }
    }
}
