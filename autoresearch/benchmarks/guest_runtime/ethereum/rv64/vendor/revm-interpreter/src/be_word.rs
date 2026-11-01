//! stwo: big-endian 256-bit word transfers for RV64IM (no Zbb).
//!
//! `u64::from_be_bytes` on unaligned bytes lowers to byte loads fused into a
//! little-endian word followed by LLVM's generic byte swap, about 45
//! instructions per limb. Here an 8-aligned word is one load plus a
//! three-stage mask swap (the masks are opaque, so LLVM cannot turn them back
//! into its own byte swap), and an unaligned word assembles its bytes
//! directly in big-endian order (volatile loads keep LLVM from re-fusing
//! them): 14 and 22 instructions per limb.
use core::ptr::{read_volatile, write_volatile};
use primitives::U256;

static M8: u64 = 0x00ff_00ff_00ff_00ff;
static M16: u64 = 0x0000_ffff_0000_ffff;

#[inline(always)]
fn masks() -> (u64, u64) {
    // SAFETY: plain reads of immutable statics; volatile hides the values.
    unsafe { (read_volatile(&M8), read_volatile(&M16)) }
}

#[inline(always)]
fn swap(x: u64, m8: u64, m16: u64) -> u64 {
    let x = ((x & m8) << 8) | ((x >> 8) & m8);
    let x = ((x & m16) << 16) | ((x >> 16) & m16);
    x.rotate_left(32)
}

/// Big-endian u64 from 8 bytes at any alignment.
#[inline(always)]
pub(crate) unsafe fn load_be_bytes(p: *const u8) -> u64 {
    unsafe {
        let b = |i: usize| read_volatile(p.add(i)) as u64;
        (b(0) << 56) | (b(1) << 48) | (b(2) << 40) | (b(3) << 32) | (b(4) << 24) | (b(5) << 16) | (b(6) << 8) | b(7)
    }
}

/// Reads 32 big-endian bytes at `p` as a `U256`.
///
/// # Safety
/// `p..p + 32` must be readable.
#[inline(always)]
pub(crate) unsafe fn load_u256(p: *const u8) -> U256 {
    unsafe {
        if (p as usize) & 7 == 0 {
            let (m8, m16) = masks();
            let w = |k: usize| swap(p.add(8 * k).cast::<u64>().read(), m8, m16);
            U256::from_limbs([w(3), w(2), w(1), w(0)])
        } else {
            let w = |k: usize| load_be_bytes(p.add(8 * k));
            U256::from_limbs([w(3), w(2), w(1), w(0)])
        }
    }
}

/// Writes `v` as 32 big-endian bytes at `p`.
///
/// # Safety
/// `p..p + 32` must be writable.
#[inline(always)]
pub(crate) unsafe fn store_u256(p: *mut u8, v: &U256) {
    let l = v.as_limbs();
    unsafe {
        if (p as usize) & 7 == 0 {
            let (m8, m16) = masks();
            for k in 0..4 {
                p.add(8 * k).cast::<u64>().write(swap(l[3 - k], m8, m16));
            }
        } else {
            for k in 0..4 {
                let x = l[3 - k];
                let q = p.add(8 * k);
                for i in 0..8 {
                    write_volatile(q.add(i), (x >> (56 - 8 * i)) as u8);
                }
            }
        }
    }
}

/// The `U256` of the `N <= 32` big-endian bytes at `p`.
///
/// # Safety
/// `p..p + N` must be readable.
#[inline(always)]
pub(crate) unsafe fn load_u256_n<const N: usize>(p: *const u8) -> U256 {
    let mut limbs = [0u64; 4];
    let mut k = 0;
    while k < 4 {
        // limb k holds bytes [N - 8(k + 1), N - 8k) of the big-endian input
        let hi = N as isize - 8 * k as isize;
        if hi <= 0 {
            break;
        }
        let lo = if hi >= 8 { hi - 8 } else { 0 };
        let mut x = 0u64;
        let mut i = lo;
        while i < hi {
            x = (x << 8) | unsafe { read_volatile(p.offset(i)) } as u64;
            i += 1;
        }
        limbs[k] = x;
        k += 1;
    }
    U256::from_limbs(limbs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference_at_all_offsets() {
        let mut buf = [0u8; 80];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        for off in 0..16 {
            let p = unsafe { buf.as_ptr().add(off) };
            let expected = U256::from_be_slice(&buf[off..off + 32]);
            assert_eq!(unsafe { load_u256(p) }, expected);
            let mut out = [0u8; 80];
            unsafe { store_u256(out.as_mut_ptr().add(off), &expected) };
            assert_eq!(&out[off..off + 32], &buf[off..off + 32]);
            assert!(out[..off].iter().all(|&b| b == 0) && out[off + 32..].iter().all(|&b| b == 0));
            macro_rules! n {
                ($($n:literal),*) => {$(
                    assert_eq!(unsafe { load_u256_n::<$n>(p) }, U256::from_be_slice(&buf[off..off + $n]));
                )*};
            }
            n!(1, 2, 3, 4, 5, 7, 8, 9, 14, 15, 16, 17, 20, 24, 25, 31, 32);
        }
    }
}
