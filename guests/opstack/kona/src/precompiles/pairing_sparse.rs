//! Client for the OP-only Miller-line service. Its explicit execution profile
//! stays separate from the established v3 client.
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

    /// Keep the service-written accumulator prefix in place between groups.
    /// Only the readonly line/point tail changes; all rows already exist.
    #[inline(always)]
    fn replace_line(&mut self, c0: &Fq2, c3: &Fq2, c4: &Fq2, x: &Fq, y: &Fq) {
        self.0[12] = c0.c0.into_bigint().0;
        self.0[13] = c0.c1.into_bigint().0;
        self.0[14] = c3.c0.into_bigint().0;
        self.0[15] = c3.c1.into_bigint().0;
        self.0[16] = c4.c0.into_bigint().0;
        self.0[17] = c4.c1.into_bigint().0;
        self.0[18] = x.into_bigint().0;
        self.0[19] = y.into_bigint().0;
    }

    #[inline(always)]
    // OP profile authority: the service's physical field writer constrains
    // every output < p. As in the admitted canonical Fp2 client, decode those
    // canonical words without duplicating twelve modulus checks in the guest.
    // Admission still requires the full service/RAM/receiver joins; this is
    // never an unchecked host hint or a fallback for legacy v3.
    fn write_result(&self, a: &mut Fq12) {
        #[cfg(target_arch = "riscv64")]
        const {
            assert!(<ark_bn254::FqConfig as ark_ff::MontConfig<4>>::CANONICAL_REPRESENTATION);
        }
        // Host packet tests use ordinary Montgomery Fq; their independent
        // conversion must retain that representation. Host execution uses
        // the ordinary software Miller path rather than issuing this ECALL.
        let field = |index: usize| {
            #[cfg(target_arch = "riscv64")]
            {
                Fq::new_unchecked(BigInt(self.0[index]))
            }
            #[cfg(not(target_arch = "riscv64"))]
            {
                Fq::from_bigint(BigInt(self.0[index])).expect("canonical test packet")
            }
        };
        a.c0.c0.c0 = field(0);
        a.c0.c0.c1 = field(1);
        a.c0.c1.c0 = field(2);
        a.c0.c1.c1 = field(3);
        a.c0.c2.c0 = field(4);
        a.c0.c2.c1 = field(5);
        a.c1.c0.c0 = field(6);
        a.c1.c0.c1 = field(7);
        a.c1.c1.c0 = field(8);
        a.c1.c1.c1 = field(9);
        a.c1.c2.c0 = field(10);
        a.c1.c2.c1 = field(11);
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
        packet.write_result(a);
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

/// A line has one primitive per active group, in the original order. Retain
/// the canonical accumulator words between these crossings and decode once.
#[inline(always)]
#[cfg(feature = "pairing-packet-batching")]
pub(super) fn miller_lines(a: &mut Fq12, groups: &[super::miller::Group], line: usize, skip: u16) {
    #[cfg(target_arch = "riscv64")]
    with_packet(a, groups, line, skip, |packet| {
        // SAFETY: the initialized, unique 640-byte packet is 32-aligned. The
        // service reads all 20 Fq inputs and writes only its canonical prefix.
        unsafe {
            core::arch::asm!("ecall", in("a0") packet.0.as_mut_ptr(), in("a7") TAG, options(nostack));
        }
    });
    #[cfg(not(target_arch = "riscv64"))]
    {
        use ark_ec::AffineRepr;
        for (i, (point, _, prepared)) in groups.iter().enumerate() {
            if point.is_zero() || (skip != 0 && (skip >> i) & 1 != 0) {
                continue;
            }
            let (mut c0, mut c3, c4) = prepared.ell_coeffs[line];
            c0.mul_assign_by_fp(&point.y);
            c3.mul_assign_by_fp(&point.x);
            a.mul_by_034(&c0, &c3, &c4);
        }
    }
}

/// Shared by the real ECALL path and the packet-semantics test executor.
#[cfg(any(target_arch = "riscv64", test))]
#[inline(always)]
fn with_packet(
    a: &mut Fq12,
    groups: &[super::miller::Group],
    line: usize,
    skip: u16,
    mut execute: impl FnMut(&mut Packet),
) {
    use ark_ec::AffineRepr;
    let mut active = groups
        .iter()
        .enumerate()
        .filter(|(i, (point, _, _))| !point.is_zero() && (skip == 0 || (skip >> i) & 1 == 0));
    let Some((_, (point, _, prepared))) = active.next() else {
        return;
    };
    let c = &prepared.ell_coeffs[line];
    let mut storage = MaybeUninit::uninit();
    let packet = Packet::prepare(&mut storage, a, &c.0, &c.1, &c.2, &point.x, &point.y);
    execute(packet);
    for (_, (point, _, prepared)) in active {
        let c = &prepared.ell_coeffs[line];
        packet.replace_line(&c.0, &c.1, &c.2, &point.x, &point.y);
        execute(packet);
    }
    packet.write_result(a);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::AdditiveGroup;

    #[test]
    fn packet_batches_preserve_order_skips_and_every_miller_line() {
        use alloc::{sync::Arc, vec::Vec};
        use ark_bn254::{Fr, G1Affine, G2Affine};
        use ark_ec::{AffineRepr, CurveGroup};
        let groups: Vec<super::super::miller::Group> = (0..16)
            .map(|i| {
                let point = if i == 3 {
                    G1Affine::zero()
                } else {
                    (G1Affine::generator() * Fr::from(i + 1)).into_affine()
                };
                let q = (G2Affine::generator() * Fr::from(i + 2)).into_affine();
                (point, None, Arc::new(super::super::PreparedG2::from(q)))
            })
            .collect();
        let q = |x| Fq2::new(Fq::from(x), Fq::from(x + 1));
        let seed = Fq12::new(Fq6::new(q(1), q(3), q(5)), Fq6::new(q(7), q(9), q(11)));
        for skip in [0u16, 1, 0x8000, 0x5555, 0xffff] {
            for line in 0..groups[0].2.ell_coeffs.len() {
                let mut reference = seed;
                let mut expected_packets = Vec::new();
                for (i, (point, _, prepared)) in groups.iter().enumerate() {
                    if point.is_zero() || (skip != 0 && (skip >> i) & 1 != 0) {
                        continue;
                    }
                    let c = &prepared.ell_coeffs[line];
                    let mut storage = MaybeUninit::uninit();
                    let p = Packet::prepare(
                        &mut storage,
                        &reference,
                        &c.0,
                        &c.1,
                        &c.2,
                        &point.x,
                        &point.y,
                    );
                    expected_packets.push(p.0);
                    let mut c0 = c.0;
                    let mut c3 = c.1;
                    c0.mul_assign_by_fp(&point.y);
                    c3.mul_assign_by_fp(&point.x);
                    reference.mul_by_034(&c0, &c3, &c.2);
                }
                let mut actual = seed;
                let mut calls = 0;
                with_packet(&mut actual, &groups, line, skip, |p| {
                    // Independent software arithmetic implements the packet ABI.
                    // Every call's full input agrees, not merely the final value.
                    assert_eq!(p.0, expected_packets[calls]);
                    calls += 1;
                    let mut a = Fq12::ZERO;
                    p.write_result(&mut a);
                    let f = |i| Fq::from_bigint(BigInt(p.0[i])).unwrap();
                    let mut c0 = Fq2::new(f(12), f(13));
                    let mut c3 = Fq2::new(f(14), f(15));
                    let c4 = Fq2::new(f(16), f(17));
                    c0.mul_assign_by_fp(&f(19));
                    c3.mul_assign_by_fp(&f(18));
                    a.mul_by_034(&c0, &c3, &c4);
                    let mut storage = MaybeUninit::uninit();
                    let output = Packet::prepare(&mut storage, &a, &c0, &c3, &c4, &f(18), &f(19));
                    p.0[..12].copy_from_slice(&output.0[..12]);
                });
                assert_eq!(calls, expected_packets.len());
                assert_eq!(actual, reference);
            }
        }
        let mut value = seed;
        with_packet(&mut value, &[], usize::MAX, 0, |_| {
            panic!("empty batch emitted service")
        });
        assert_eq!(value, seed);
    }

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
        let mut decoded = Fq12::ZERO;
        packet.write_result(&mut decoded);
        assert_eq!(decoded, a);
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
        packet.write_result(&mut decoded);
        assert_eq!(decoded, expected);
        assert_eq!(packet.0[12..], line);
    }
}
