//! One admitted canonical Fp2 product, including squaring, without residue shifts.
#[cfg(target_arch = "riscv64")]
use super::Fq;
use super::Fq2;
#[cfg(target_arch = "riscv64")]
use ark_ff::BigInt;

#[inline(always)]
pub(super) fn product(a: &Fq2, b: &Fq2) -> Fq2 {
    // The generic formulas win for scalar-only operands and preserve cheap zero
    // and unit products through the base-field shortcuts.
    if (a.c1.0 .0[0] | a.c1.0 .0[1] | a.c1.0 .0[2] | a.c1.0 .0[3]) == 0 {
        return Fq2::new(a.c0 * b.c0, a.c0 * b.c1);
    }
    if (b.c1.0 .0[0] | b.c1.0 .0[1] | b.c1.0 .0[2] | b.c1.0 .0[3]) == 0 {
        return Fq2::new(a.c0 * b.c0, a.c1 * b.c0);
    }
    product_full(a, b)
}
#[cfg(target_arch = "riscv64")]
#[allow(unsafe_code)]
#[inline(always)]
fn product_full(a: &Fq2, b: &Fq2) -> Fq2 {
    #[repr(C, align(32))]
    struct Packet([u64; 16]);
    let [a0, a1, a2, a3] = a.c0.0 .0;
    let [a4, a5, a6, a7] = a.c1.0 .0;
    let [b0, b1, b2, b3] = b.c0.0 .0;
    let [b4, b5, b6, b7] = b.c1.0 .0;
    let mut packet = Packet([
        a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7,
    ]);
    // SAFETY: unique initialized 32-aligned inline packet. The admitted native
    // relation reads canonical c0,c1 pairs and overwrites the first pair. Its
    // existing recursive truth bridge binds all words; no new service is used.
    unsafe {
        core::arch::asm!("ecall", in("a0") packet.0.as_mut_ptr(), in("a7") 0x0003_0102usize, options(nostack));
    }
    Fq2::new(
        Fq::new_unchecked(BigInt([packet.0[0], packet.0[1], packet.0[2], packet.0[3]])),
        Fq::new_unchecked(BigInt([packet.0[4], packet.0[5], packet.0[6], packet.0[7]])),
    )
}
#[cfg(not(target_arch = "riscv64"))]
fn product_full(a: &Fq2, b: &Fq2) -> Fq2 {
    Fq2::new(a.c0 * b.c0 - a.c1 * b.c1, a.c0 * b.c1 + a.c1 * b.c0)
}
