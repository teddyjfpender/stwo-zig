//! Explicit prototype client for the OP-only Miller-line service. The new
//! execution/profile admission stays separate from the established v3 client.
use ark_bn254::{Fq, Fq2, Fq6, Fq12};
use ark_ff::{BigInt, PrimeField};
use core::mem::MaybeUninit;

pub(super) const TAG: usize = 0x0004_0001;

/// Arrays have a specified contiguous layout; no Ark field object is cast to
/// wire bytes. Each inner row is one canonical, little-endian u256 Fq value.
#[repr(C, align(32))]
struct Packet([[u64; 4]; 20]);

impl Packet {
    /// Initialize every input coordinate directly in caller-owned storage.
    /// No reference to Packet (or its array) exists until all 80 words are set.
    #[inline(always)]
    fn prepare<'a>(
        storage: &'a mut MaybeUninit<Self>,
        a: &Fq12,
        c0: &Fq2,
        c3: &Fq2,
        c4: &Fq2,
        x: &Fq,
        y: &Fq,
    ) -> &'a mut Self {
        // SAFETY: repr(C) gives the sole array field offset zero and its rows
        // are contiguous. storage owns aligned space for exactly 20 rows.
        // Every row 0..19 is written once; [u64; 4] has no invalid bit patterns.
        // No references or reads of uninitialized storage occur. Only then
        // assume_init_mut exposes the fully initialized Packet to the caller.
        unsafe {
            let rows = storage.as_mut_ptr().cast::<[u64; 4]>();
            rows.add(0).write(a.c0.c0.c0.into_bigint().0);
            rows.add(1).write(a.c0.c0.c1.into_bigint().0);
            rows.add(2).write(a.c0.c1.c0.into_bigint().0);
            rows.add(3).write(a.c0.c1.c1.into_bigint().0);
            rows.add(4).write(a.c0.c2.c0.into_bigint().0);
            rows.add(5).write(a.c0.c2.c1.into_bigint().0);
            rows.add(6).write(a.c1.c0.c0.into_bigint().0);
            rows.add(7).write(a.c1.c0.c1.into_bigint().0);
            rows.add(8).write(a.c1.c1.c0.into_bigint().0);
            rows.add(9).write(a.c1.c1.c1.into_bigint().0);
            rows.add(10).write(a.c1.c2.c0.into_bigint().0);
            rows.add(11).write(a.c1.c2.c1.into_bigint().0);
            rows.add(12).write(c0.c0.into_bigint().0);
            rows.add(13).write(c0.c1.into_bigint().0);
            rows.add(14).write(c3.c0.into_bigint().0);
            rows.add(15).write(c3.c1.into_bigint().0);
            rows.add(16).write(c4.c0.into_bigint().0);
            rows.add(17).write(c4.c1.into_bigint().0);
            rows.add(18).write(x.into_bigint().0);
            rows.add(19).write(y.into_bigint().0);
            storage.assume_init_mut()
        }
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
pub(super) fn miller_line(a: &mut Fq12, c0: &Fq2, c3: &Fq2, c4: &Fq2, x: &Fq, y: &Fq) {
    #[cfg(target_arch = "riscv64")]
    {
        use ark_ff::MontConfig;
        const {
            assert!(ark_bn254::FqConfig::CANONICAL_REPRESENTATION);
        }
        let mut storage = MaybeUninit::uninit();
        let packet = Packet::prepare(&mut storage, a, c0, c3, c4, x, y);
        // SAFETY: a unique initialized 640-byte, 32-aligned inline packet.
        // OP sparse034 reads all 20 Fq inputs, overwrites only the leading
        // 12 Fq outputs, and constrains those outputs canonical. Its explicit
        // profile must be selected; legacy v3 refuses this new namespace.
        unsafe {
            core::arch::asm!("ecall", in("a0") packet.0.as_mut_ptr(), in("a7") TAG, options(nostack));
        }
        *a = packet.result().expect("noncanonical OP sparse034 output");
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        let mut c0 = *c0;
        let mut c3 = *c3;
        c0.mul_assign_by_fp(y);
        c3.mul_assign_by_fp(x);
        a.mul_by_034(&c0, &c3, c4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::AdditiveGroup;

    #[test]
    fn packet_is_explicit_canonical_order_and_keeps_line_inputs() {
        assert_eq!(core::mem::size_of::<Packet>(), 640);
        assert_eq!(core::mem::align_of::<Packet>(), 32);
        let q = |x| Fq2::new(Fq::from(x), Fq::from(x + 1));
        let a = Fq12::new(Fq6::new(q(1), q(3), q(5)), Fq6::new(q(7), q(9), q(11)));
        let mut storage = MaybeUninit::uninit();
        let packet = Packet::prepare(
            &mut storage,
            &a,
            &q(13),
            &q(15),
            &q(17),
            &Fq::from(19),
            &Fq::from(20),
        );
        for (i, word) in packet.0.iter().enumerate() {
            assert_eq!(*word, [i as u64 + 1, 0, 0, 0]);
        }
        assert_eq!(packet.result(), Some(a));
        let line = packet.0[12..].to_vec();
        let mut expected = a;
        let mut c0 = q(13);
        let mut c3 = q(15);
        c0.mul_assign_by_fp(&Fq::from(20));
        c3.mul_assign_by_fp(&Fq::from(19));
        expected.mul_by_034(&c0, &c3, &q(17));
        let mut output_storage = MaybeUninit::uninit();
        let output = Packet::prepare(
            &mut output_storage,
            &expected,
            &Fq2::ZERO,
            &Fq2::ZERO,
            &Fq2::ZERO,
            &Fq::from(19),
            &Fq::from(20),
        );
        packet.0[..12].copy_from_slice(&output.0[..12]);
        assert_eq!(packet.result(), Some(expected));
        assert_eq!(packet.0[12..], line);
        packet.0[11] = Fq::MODULUS.0;
        assert!(packet.result().is_none());
    }
}
