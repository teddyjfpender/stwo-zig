//! Optional client of the existing RV64 ethereum_services_v3 arith384_mont
//! relation (tag 0x00030121). Field representations and moduli stay unchanged.
//! No service is used by native builds or by canonical-storage backends.
//!
//! For six limbs the relation returns ab*2^-384 mod m directly. For four
//! limbs pass a'=a*2^128: a'b*2^-384 = ab*2^-256 mod m. The shifted input may
//! exceed m; the admitted relation allows arbitrary 384-bit inputs and proves
//! its output canonical. For four-limb m, the upper two result limbs are zero.

#[repr(C, align(32))]
pub(super) struct Packet(pub(super) [u64; 20]);
const _: () =
    assert!(core::mem::size_of::<Packet>() == 160 && core::mem::align_of::<Packet>() == 32);

#[inline(always)]
pub(super) fn packet<const N: usize>(a: &[u64; N], b: &[u64; N], modulus: &[u64; N]) -> Packet {
    assert!(N == 4 || N == 6);
    if N == 4 {
        Packet([
            0, 0, a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], 0, 0, modulus[0], modulus[1],
            modulus[2], modulus[3], 0, 0, 0, 0,
        ])
    } else {
        Packet([
            a[0], a[1], a[2], a[3], a[4], a[5], b[0], b[1], b[2], b[3], b[4], b[5], modulus[0],
            modulus[1], modulus[2], modulus[3], modulus[4], modulus[5], 0, 0,
        ])
    }
}

#[cfg(target_arch = "riscv64")]
#[allow(unsafe_code)]
#[inline(always)]
pub(super) fn product<const N: usize>(a: &[u64; N], b: &[u64; N], modulus: &[u64; N]) -> [u64; N] {
    let mut packet = packet(a, b, modulus);
    // SAFETY: unique initialized 160-byte inline packet, aligned to 32 bytes.
    // The admitted ABI reads a,b,m and overwrites only the first 48 bytes;
    // other guest registers and stack are preserved. Memory is not nomem.
    unsafe {
        core::arch::asm!("ecall", in("a0") packet.0.as_mut_ptr(), in("a7") 0x0003_0121usize, options(nostack));
    }
    let mut output = [0; N];
    for i in 0..N {
        output[i] = packet.0[i];
    }
    output
}

// Array equality lowers to bytewise memcmp on RV64IM. These constant-length
// reductions preserve the field predicates without a guest-runtime call.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub(super) fn equal<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    let mut difference = 0;
    for i in 0..N {
        difference |= a[i] ^ b[i];
    }
    difference == 0
}
