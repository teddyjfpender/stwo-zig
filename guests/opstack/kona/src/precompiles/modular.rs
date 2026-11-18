//! Arbitrary-modulus 256-bit arithmetic over the existing admitted relation.
use alloc::vec::Vec;
use alloy_primitives::U256;

#[inline]
pub(super) fn mul_add(a: U256, b: U256, c: U256, m: U256) -> U256 {
    #[cfg(target_arch = "riscv64")]
    {
        #[repr(C, align(32))]
        struct Packet([u64; 20]);
        let [a0, a1, a2, a3] = *a.as_limbs();
        let [b0, b1, b2, b3] = *b.as_limbs();
        let [c0, c1, c2, c3] = *c.as_limbs();
        let [m0, m1, m2, m3] = *m.as_limbs();
        let mut packet = Packet([
            a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, m0, m1, m2, m3, 0, 0, 0, 0,
        ]);
        // SAFETY: unique live 32-aligned initialized 160-byte packet. The
        // admitted service reads a,b,c,m and overwrites r; registers preserved.
        unsafe {
            core::arch::asm!("ecall", in("a0") packet.0.as_mut_ptr(), in("a7") 0x0003_0021usize, options(nostack));
        }
        U256::from_limbs([packet.0[16], packet.0[17], packet.0[18], packet.0[19]])
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        a.mul_mod(b, m).add_mod(c, m)
    }
}

pub(super) fn pow(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
    let m = U256::from_be_slice(modulus);
    if m.is_zero() {
        return Vec::new();
    }
    if m == U256::from(1) {
        return alloc::vec![0];
    }
    let base = mul_add(U256::from_be_slice(base), U256::from(1), U256::ZERO, m);
    let mut result = U256::from(1);
    // Skip leading zero bits without changing 0^0 = 1 mod m. Exponents are
    // unbounded byte slices here: no 256-bit truncation is allowed.
    let mut started = false;
    for byte in exponent {
        for bit in (0..8).rev() {
            let one = byte & (1 << bit) != 0;
            if !started {
                if !one {
                    continue;
                }
                result = base;
                started = true;
                continue;
            }
            result = mul_add(result, result, U256::ZERO, m);
            if one {
                result = mul_add(result, base, U256::ZERO, m);
            }
        }
    }
    // Revm owns the requested-width padding. Its crypto provider returns a
    // minimal big-endian integer, with one zero byte for a zero result.
    let bytes = result.to_be_bytes::<32>();
    let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(31);
    bytes[start..].to_vec()
}
