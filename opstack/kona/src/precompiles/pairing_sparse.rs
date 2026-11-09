//! Explicit prototype client for the OP-only sparse034 service. The new
//! execution/profile admission stays separate from the established v3 client.
use ark_bn254::{Fq, Fq2, Fq6, Fq12};
use ark_ff::{BigInt, PrimeField};

pub(super) const TAG: usize = 0x0004_0001;

/// Arrays have a specified contiguous layout; no Ark field object is cast to
/// wire bytes. Each inner row is one canonical, little-endian u256 Fq value.
#[repr(C, align(32))]
struct Packet([[u64; 4]; 18]);

impl Packet {
    #[inline(always)]
    fn prepare(a: &Fq12, c0: &Fq2, c3: &Fq2, c4: &Fq2) -> Self {
        Self([
            a.c0.c0.c0.into_bigint().0,
            a.c0.c0.c1.into_bigint().0,
            a.c0.c1.c0.into_bigint().0,
            a.c0.c1.c1.into_bigint().0,
            a.c0.c2.c0.into_bigint().0,
            a.c0.c2.c1.into_bigint().0,
            a.c1.c0.c0.into_bigint().0,
            a.c1.c0.c1.into_bigint().0,
            a.c1.c1.c0.into_bigint().0,
            a.c1.c1.c1.into_bigint().0,
            a.c1.c2.c0.into_bigint().0,
            a.c1.c2.c1.into_bigint().0,
            c0.c0.into_bigint().0,
            c0.c1.into_bigint().0,
            c3.c0.into_bigint().0,
            c3.c1.into_bigint().0,
            c4.c0.into_bigint().0,
            c4.c1.into_bigint().0,
        ])
    }

    #[inline(always)]
    fn result(&self) -> Option<Fq12> {
        let mut at = 0;
        let mut read = || {
            let value = Fq::from_bigint(BigInt(self.0[at]));
            at += 1;
            value
        };
        Some(Fq12::new(
            Fq6::new(
                Fq2::new(read()?, read()?),
                Fq2::new(read()?, read()?),
                Fq2::new(read()?, read()?),
            ),
            Fq6::new(
                Fq2::new(read()?, read()?),
                Fq2::new(read()?, read()?),
                Fq2::new(read()?, read()?),
            ),
        ))
    }
}

#[inline(always)]
pub(super) fn mul_by_034(a: &mut Fq12, c0: &Fq2, c3: &Fq2, c4: &Fq2) {
    #[cfg(target_arch = "riscv64")]
    {
        use ark_ff::MontConfig;
        const {
            assert!(ark_bn254::FqConfig::CANONICAL_REPRESENTATION);
        }
        let mut packet = Packet::prepare(a, c0, c3, c4);
        // SAFETY: a unique initialized 576-byte, 32-aligned inline packet.
        // OP sparse034 reads all 18 Fq inputs, overwrites only the leading
        // 12 Fq outputs, and constrains those outputs canonical. Its explicit
        // profile must be selected; legacy v3 refuses this new namespace.
        unsafe {
            core::arch::asm!("ecall", in("a0") packet.0.as_mut_ptr(), in("a7") TAG, options(nostack));
        }
        *a = packet.result().expect("noncanonical OP sparse034 output");
    }
    #[cfg(not(target_arch = "riscv64"))]
    a.mul_by_034(c0, c3, c4);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::AdditiveGroup;

    #[test]
    fn packet_is_explicit_canonical_order_and_keeps_line_inputs() {
        assert_eq!(core::mem::size_of::<Packet>(), 576);
        assert_eq!(core::mem::align_of::<Packet>(), 32);
        let q = |x| Fq2::new(Fq::from(x), Fq::from(x + 1));
        let a = Fq12::new(Fq6::new(q(1), q(3), q(5)), Fq6::new(q(7), q(9), q(11)));
        let mut packet = Packet::prepare(&a, &q(13), &q(15), &q(17));
        for (i, word) in packet.0.iter().enumerate() {
            assert_eq!(*word, [i as u64 + 1, 0, 0, 0]);
        }
        assert_eq!(packet.result(), Some(a));
        let line = packet.0[12..].to_vec();
        let mut expected = a;
        expected.mul_by_034(&q(13), &q(15), &q(17));
        let output = Packet::prepare(&expected, &Fq2::ZERO, &Fq2::ZERO, &Fq2::ZERO);
        packet.0[..12].copy_from_slice(&output.0[..12]);
        assert_eq!(packet.result(), Some(expected));
        assert_eq!(packet.0[12..], line);
        packet.0[11] = Fq::MODULUS.0;
        assert!(packet.result().is_none());
    }
}
