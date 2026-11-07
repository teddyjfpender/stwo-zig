//! BN254 Fq Montgomery operations through admitted arith384_mont (0x30121).
//!
//! Ark stores aR with R=2^256. The service returns AB*2^-384 mod p. Feeding
//! A=(aR)<<128 and B=bR therefore returns abR, without converting field form.
//! The shifted operand fits 384 bits because p has 254 bits. Constants and
//! other operations retain Ark's field semantics. No untrusted output is read
//! without an admitted execution/proof bridge; native feature tests use Ark.
use super::Fq;
use ark_ff::{BigInt, MontConfig, Zero};
#[cfg(not(target_arch = "riscv64"))]
use ark_ff::{Fp, MontBackend};

#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088696311157297823662689037894645226208583"]
#[generator = "3"]
struct SoftwareConfig;
#[cfg(not(target_arch = "riscv64"))]
type Software = Fp<MontBackend<SoftwareConfig, 4>, 4>;

pub struct FqConfig;
impl MontConfig<4> for FqConfig {
    const MODULUS: BigInt<4> = SoftwareConfig::MODULUS;
    const GENERATOR: Fq = Fq::new_unchecked(SoftwareConfig::GENERATOR.0);
    const TWO_ADIC_ROOT_OF_UNITY: Fq = Fq::new_unchecked(SoftwareConfig::TWO_ADIC_ROOT_OF_UNITY.0);

    #[inline]
    fn mul_assign(a: &mut Fq, b: &Fq) {
        a.0 = product(a.0, b.0);
    }
    #[inline]
    fn square_in_place(a: &mut Fq) {
        a.0 = product(a.0, a.0);
    }
    fn sum_of_products<const M: usize>(a: &[Fq; M], b: &[Fq; M]) -> Fq {
        let mut result = Fq::zero();
        for (a, b) in a.iter().zip(b) {
            let value = Fq::new_unchecked(product(a.0, b.0));
            result += value;
        }
        result
    }
}

#[cfg(target_arch = "riscv64")]
#[allow(unsafe_code)] // Isolated, documented admitted ECALL ABI.
#[inline(always)]
fn product(a: BigInt<4>, b: BigInt<4>) -> BigInt<4> {
    #[repr(C, align(32))]
    struct Packet([u64; 20]);
    let p = SoftwareConfig::MODULUS.0;
    // Construct the initialized packet directly. Zeroing it first becomes a
    // bulk-memory service per field operation and adds unnecessary RAM work.
    let mut packet = Packet([
        0, 0, a.0[0], a.0[1], a.0[2], a.0[3], b.0[0], b.0[1], b.0[2], b.0[3], 0, 0, p[0], p[1],
        p[2], p[3], 0, 0, 0, 0,
    ]);
    // SAFETY: one unique live 32-aligned inline 160-byte packet. The admitted
    // service reads it and overwrites the leading 384-bit result; no pointers
    // escape. RV64 registers are preserved and memory is a compiler clobber.
    unsafe {
        core::arch::asm!("ecall", in("a0") packet.0.as_mut_ptr(), in("a7") 0x0003_0121usize, options(nostack));
    }
    BigInt([packet.0[0], packet.0[1], packet.0[2], packet.0[3]])
}
#[cfg(not(target_arch = "riscv64"))]
fn product(a: BigInt<4>, b: BigInt<4>) -> BigInt<4> {
    let mut a = Software::new_unchecked(a);
    SoftwareConfig::mul_assign(&mut a, &Software::new_unchecked(b));
    a.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{FftField, Field, PrimeField};

    #[test]
    fn montgomery_adapter_preserves_field_operations_and_constants() {
        for i in 0..64u64 {
            let a = Fq::from(i.wrapping_mul(0x9e3779b97f4a7c15));
            let b = Fq::from(i.wrapping_mul(0xd1b54a32d192ed03));
            let x = Software::new_unchecked(a.0);
            let y = Software::new_unchecked(b.0);
            assert_eq!((a * b).0, (x * y).0);
            assert_eq!(a.square().0, x.square().0);
            assert_eq!(
                Fq::sum_of_products(&[a, -b], &[b, a]).0,
                Software::sum_of_products(&[x, -y], &[y, x]).0
            );
            assert_eq!(a.into_bigint(), x.into_bigint());
            assert_eq!(a.inverse().map(|x| x.0), x.inverse().map(|x| x.0));
        }
        assert_eq!(Fq::GENERATOR.0, Software::GENERATOR.0);
        assert_eq!(
            Fq::TWO_ADIC_ROOT_OF_UNITY.0,
            Software::TWO_ADIC_ROOT_OF_UNITY.0
        );
        assert_eq!(Fq::sum_of_products::<0>(&[], &[]), Fq::zero());
    }
}
