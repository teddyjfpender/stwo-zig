//! Optional canonical BN254 Fq storage, matching admitted arith256/Fp2 packets.
//! No conversion is needed at service boundaries. Default builds retain Ark's
//! original Montgomery representation. Every runtime entry preserves [0, p).
use super::Fq;
use ark_ff::{BigInt, MontConfig, Zero};
#[cfg(not(target_arch = "riscv64"))]
use ark_ff::{MontBackend, PrimeField};

#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088696311157297823662689037894645226208583"]
#[generator = "3"]
pub(super) struct SoftwareConfig;
#[cfg(not(target_arch = "riscv64"))]
type Software = ark_ff::Fp<MontBackend<SoftwareConfig, 4>, 4>;

pub struct FqConfig;
impl MontConfig<4> for FqConfig {
    const CANONICAL_REPRESENTATION: bool = true;
    const MODULUS: BigInt<4> = SoftwareConfig::MODULUS;
    const R: BigInt<4> = BigInt([1, 0, 0, 0]);
    const R2: BigInt<4> = Self::R;
    const GENERATOR: Fq = Fq::new_unchecked(BigInt([3, 0, 0, 0]));
    const TWO_ADIC_ROOT_OF_UNITY: Fq = ark_ff::MontFp!("-1");

    #[inline(always)]
    fn mul_assign(a: &mut Fq, b: &Fq) {
        a.0 = product(a.0, b.0);
    }
    #[inline(always)]
    fn square_in_place(a: &mut Fq) {
        a.0 = product(a.0, a.0);
    }
    fn sum_of_products<const M: usize>(a: &[Fq; M], b: &[Fq; M]) -> Fq {
        let mut result = Fq::zero();
        for (a, b) in a.iter().zip(b) {
            result += Fq::new_unchecked(product(a.0, b.0));
        }
        result
    }
    #[inline(always)]
    fn from_bigint(value: BigInt<4>) -> Option<Fq> {
        (value < Self::MODULUS).then(|| Fq::new_unchecked(value))
    }
    #[inline(always)]
    fn into_bigint(value: Fq) -> BigInt<4> {
        value.0
    }
    // The inherited binary inverse starts its coefficient at R2=1, hence works
    // directly in canonical form. Addition, subtraction and negation already do.
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
    #[repr(C, align(32))]
    struct Packet([u64; 20]);
    let p = FqConfig::MODULUS.0;
    let mut packet = Packet([
        a.0[0], a.0[1], a.0[2], a.0[3], b.0[0], b.0[1], b.0[2], b.0[3], 0, 0, 0, 0, p[0], p[1],
        p[2], p[3], 0, 0, 0, 0,
    ]);
    // SAFETY: initialized, unique, 32-aligned 160-byte inline packet; a,b < p.
    // The admitted service binds every input/output word. No pointers escape.
    unsafe {
        core::arch::asm!("ecall", in("a0") packet.0.as_mut_ptr(), in("a7") 0x0003_0021usize, options(nostack));
    }
    BigInt([packet.0[16], packet.0[17], packet.0[18], packet.0[19]])
}
#[cfg(not(target_arch = "riscv64"))]
fn product_nontrivial(a: BigInt<4>, b: BigInt<4>) -> BigInt<4> {
    (Software::from_bigint(a).unwrap() * Software::from_bigint(b).unwrap()).into_bigint()
}
