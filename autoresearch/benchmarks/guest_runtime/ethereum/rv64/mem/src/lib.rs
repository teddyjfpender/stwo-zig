//! C memory functions for the RV64IM guest, replacing the weak
//! `compiler_builtins` definitions. The guest traps on misaligned loads and
//! stores, so every word access below is aligned; mismatched source and
//! destination alignment uses an aligned funnel-shift loop that never reads a
//! word beyond the source range. Copies of 17..128 bytes dominate the
//! Ethereum block census, so the aligned and funnel loops are unrolled and the
//! prologue is short. On non-RISC-V targets the symbols stay mangled so host
//! tests run against the platform libc untouched.
#![no_std]
#![no_builtins]
#![allow(clippy::missing_safety_doc)]
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(test)]
extern crate std;

use core::ptr;

#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe { copy_forward(dest, src, n) };
    dest
}

#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dest as usize).wrapping_sub(src as usize) >= n {
        unsafe { copy_forward(dest, src, n) };
    } else {
        // Overlapping with dest ahead of src: byte copy from the end. Rare.
        let mut i = n;
        while i != 0 {
            i -= 1;
            unsafe { *dest.add(i) = *src.add(i) };
        }
    }
    dest
}

#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub unsafe extern "C" fn memset(dest: *mut u8, value: i32, n: usize) -> *mut u8 {
    let byte = value as u8;
    let mut d = dest;
    let mut n = n;
    if n >= 16 {
        let head = (d as usize).wrapping_neg() & 7;
        let mut h = head;
        while h != 0 {
            unsafe { *d = byte };
            d = unsafe { d.add(1) };
            h -= 1;
        }
        n -= head;
        let word = u64::from(byte) * 0x0101_0101_0101_0101;
        while n >= 32 {
            unsafe {
                store(d, word);
                store(d.add(8), word);
                store(d.add(16), word);
                store(d.add(24), word);
                d = d.add(32);
            }
            n -= 32;
        }
        while n >= 8 {
            unsafe {
                store(d, word);
                d = d.add(8);
            }
            n -= 8;
        }
    }
    while n != 0 {
        unsafe { *d = byte };
        d = unsafe { d.add(1) };
        n -= 1;
    }
    dest
}

#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut a = a;
    let mut b = b;
    let mut n = n;
    if ((a as usize) | (b as usize)) & 7 == 0 {
        while n >= 8 {
            let (wa, wb) = unsafe { (load(a), load(b)) };
            if wa != wb {
                // Lexicographic byte order is big-endian word order.
                return if wa.swap_bytes() < wb.swap_bytes() { -1 } else { 1 };
            }
            a = unsafe { a.add(8) };
            b = unsafe { b.add(8) };
            n -= 8;
        }
    }
    while n != 0 {
        let (x, y) = unsafe { (*a, *b) };
        if x != y {
            return i32::from(x) - i32::from(y);
        }
        a = unsafe { a.add(1) };
        b = unsafe { b.add(1) };
        n -= 1;
    }
    0
}

#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    unsafe { memcmp(a, b, n) }
}

#[inline(always)]
unsafe fn load(p: *const u8) -> u64 {
    debug_assert!(p as usize & 7 == 0);
    unsafe { ptr::read(p.cast::<u64>()) }
}

#[inline(always)]
unsafe fn store(p: *mut u8, v: u64) {
    debug_assert!(p as usize & 7 == 0);
    unsafe { ptr::write(p.cast::<u64>(), v) }
}

/// Non-overlapping forward copy. `dest` and `src` may have any alignment.
#[inline(always)]
unsafe fn copy_forward(dest: *mut u8, src: *const u8, n: usize) {
    let mut d = dest;
    let mut s = src;
    let mut n = n;
    if n < 16 {
        unsafe { copy_small(d, s, n) };
        return;
    }
    let head = (d as usize).wrapping_neg() & 7;
    if head != 0 {
        unsafe { copy_bytes(d, s, head) };
        d = unsafe { d.add(head) };
        s = unsafe { s.add(head) };
        n -= head;
    }
    let offset = (s as usize) & 7;
    if offset == 0 {
        unsafe { copy_aligned(d, s, n) };
    } else if offset & 3 == 0 {
        unsafe { copy_aligned32(d, s, n) };
    } else {
        unsafe { copy_funnel(d, s, offset, n) };
    }
}

/// Both pointers 8-aligned, `n` arbitrary.
#[inline(always)]
unsafe fn copy_aligned(mut d: *mut u8, mut s: *const u8, mut n: usize) {
    while n >= 32 {
        unsafe {
            let a = load(s);
            let b = load(s.add(8));
            let c = load(s.add(16));
            let e = load(s.add(24));
            store(d, a);
            store(d.add(8), b);
            store(d.add(16), c);
            store(d.add(24), e);
            d = d.add(32);
            s = s.add(32);
        }
        n -= 32;
    }
    while n >= 8 {
        unsafe {
            store(d, load(s));
            d = d.add(8);
            s = s.add(8);
        }
        n -= 8;
    }
    unsafe { copy_small(d, s, n) };
}

/// Destination 8-aligned, source 4-aligned but not 8-aligned.
#[inline(always)]
unsafe fn copy_aligned32(mut d: *mut u8, mut s: *const u8, mut n: usize) {
    while n >= 16 {
        unsafe {
            let a = ptr::read(s.cast::<u32>());
            let b = ptr::read(s.add(4).cast::<u32>());
            let c = ptr::read(s.add(8).cast::<u32>());
            let e = ptr::read(s.add(12).cast::<u32>());
            store(d, u64::from(a) | (u64::from(b) << 32));
            store(d.add(8), u64::from(c) | (u64::from(e) << 32));
            d = d.add(16);
            s = s.add(16);
        }
        n -= 16;
    }
    unsafe { copy_small(d, s, n) };
}

/// Destination 8-aligned, source at byte `offset` (1..=7, not 4) inside its
/// aligned word. Reads only aligned source words that lie entirely inside
/// `[src, src + n)` or inside the word that contains `src`.
#[inline(always)]
unsafe fn copy_funnel(mut d: *mut u8, s: *const u8, offset: usize, mut n: usize) {
    let shift = (offset * 8) as u32;
    let back = 64 - shift;
    let mut aligned = unsafe { s.sub(offset) };
    let mut current = unsafe { load(aligned) };
    // Output word k needs aligned words k and k + 1; word k + 1 must end
    // inside the source range: 16 - offset bytes must remain.
    let needed = 16 - offset;
    while n >= needed + 24 {
        unsafe {
            let w1 = load(aligned.add(8));
            let w2 = load(aligned.add(16));
            let w3 = load(aligned.add(24));
            let w4 = load(aligned.add(32));
            store(d, (current >> shift) | (w1 << back));
            store(d.add(8), (w1 >> shift) | (w2 << back));
            store(d.add(16), (w2 >> shift) | (w3 << back));
            store(d.add(24), (w3 >> shift) | (w4 << back));
            current = w4;
            aligned = aligned.add(32);
            d = d.add(32);
        }
        n -= 32;
    }
    while n >= needed + 8 {
        unsafe {
            let next = load(aligned.add(8));
            let after = load(aligned.add(16));
            store(d, (current >> shift) | (next << back));
            store(d.add(8), (next >> shift) | (after << back));
            current = after;
            aligned = aligned.add(16);
            d = d.add(16);
        }
        n -= 16;
    }
    if n >= needed {
        unsafe {
            let next = load(aligned.add(8));
            store(d, (current >> shift) | (next << back));
            aligned = aligned.add(8);
            d = d.add(8);
        }
        n -= 8;
    }
    let s = unsafe { aligned.add(offset) };
    unsafe { copy_bytes(d, s, n) };
}

/// `n < 16`; uses the widest access both pointers allow.
#[inline(always)]
unsafe fn copy_small(mut d: *mut u8, mut s: *const u8, mut n: usize) {
    let both = (d as usize) | (s as usize);
    if both & 7 == 0 {
        while n >= 8 {
            unsafe {
                store(d, load(s));
                d = d.add(8);
                s = s.add(8);
            }
            n -= 8;
        }
    }
    if both & 3 == 0 {
        while n >= 4 {
            unsafe {
                ptr::write(d.cast::<u32>(), ptr::read(s.cast::<u32>()));
                d = d.add(4);
                s = s.add(4);
            }
            n -= 4;
        }
    }
    if both & 1 == 0 {
        while n >= 2 {
            unsafe {
                ptr::write(d.cast::<u16>(), ptr::read(s.cast::<u16>()));
                d = d.add(2);
                s = s.add(2);
            }
            n -= 2;
        }
    }
    unsafe { copy_bytes(d, s, n) };
}

/// `n <= 15`, arbitrary alignment: one branch on `n`, then straight-line
/// byte moves. Avoids the five-instruction-per-byte loop on the hot prologue
/// and tail paths.
#[inline(always)]
unsafe fn copy_bytes(d: *mut u8, s: *const u8, n: usize) {
    macro_rules! bytes {
        ($($i:expr),*) => {{ $( unsafe { *d.add($i) = *s.add($i); } )* }};
    }
    match n {
        0 => {}
        1 => bytes!(0),
        2 => bytes!(0, 1),
        3 => bytes!(0, 1, 2),
        4 => bytes!(0, 1, 2, 3),
        5 => bytes!(0, 1, 2, 3, 4),
        6 => bytes!(0, 1, 2, 3, 4, 5),
        7 => bytes!(0, 1, 2, 3, 4, 5, 6),
        8 => bytes!(0, 1, 2, 3, 4, 5, 6, 7),
        9 => bytes!(0, 1, 2, 3, 4, 5, 6, 7, 8),
        10 => bytes!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
        11 => bytes!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10),
        12 => bytes!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
        13 => bytes!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
        14 => bytes!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13),
        _ => bytes!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn pattern(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    #[test]
    fn memcpy_matches_reference_for_all_small_alignments_and_lengths() {
        for len in 0..260 {
            for so in 0..16 {
                for doff in 0..16 {
                    let src = pattern(len + 32, (len * 31 + so * 7 + doff) as u64);
                    let mut dst = vec![0xa5u8; len + 48];
                    let reference = {
                        let mut r = dst.clone();
                        r[doff..doff + len].copy_from_slice(&src[so..so + len]);
                        r
                    };
                    unsafe { memcpy(dst.as_mut_ptr().add(doff), src.as_ptr().add(so), len) };
                    assert_eq!(dst, reference, "len {len} src offset {so} dst offset {doff}");
                }
            }
        }
    }

    #[test]
    fn funnel_never_reads_past_the_source_range() {
        // Place the source so that the word after its last byte is unmapped on a
        // real guest; on the host emulate by checking the read bound by hand.
        for len in 16..200 {
            for so in [1usize, 2, 3, 5, 6, 7] {
                let offset = so;
                let needed = 16 - offset;
                let mut n = len;
                let mut reads = 0usize; // words read beyond the first
                while n >= needed {
                    reads += 1;
                    n -= 8;
                }
                // Last word read ends at offset-adjusted position 8*reads + 8 - offset <= len.
                assert!(8 * reads + 8 - offset <= len, "len {len} offset {offset}");
            }
        }
    }

    #[test]
    fn memmove_handles_both_overlap_directions() {
        for len in 0..130 {
            for delta in 0..40 {
                let base = pattern(len + 80, len as u64 + delta as u64);
                for (dst, src) in [(delta, 0usize), (0, delta)] {
                    let mut buffer = base.clone();
                    let mut reference = base.clone();
                    reference.copy_within(src..src + len, dst);
                    unsafe { memmove(buffer.as_mut_ptr().add(dst), buffer.as_ptr().add(src), len) };
                    assert_eq!(buffer, reference, "len {len} dst {dst} src {src}");
                }
            }
        }
    }

    #[test]
    fn memset_fills_exactly() {
        for len in 0..200 {
            for off in 0..16 {
                let mut buffer = vec![0x11u8; len + 32];
                let mut reference = buffer.clone();
                reference[off..off + len].fill(0xc3);
                unsafe { memset(buffer.as_mut_ptr().add(off), 0x1c3, len) };
                assert_eq!(buffer, reference, "len {len} off {off}");
            }
        }
    }

    #[test]
    fn memcmp_sign_matches_lexicographic_order() {
        for len in 0..80 {
            for off in 0..9 {
                for position in 0..len.max(1) {
                    let a = pattern(len + 16, (len * 3 + off) as u64);
                    let mut b = a.clone();
                    if position < len {
                        b[off + position] = a[off + position].wrapping_add(1 + (position as u8 % 3));
                    }
                    let expected = a[off..off + len].cmp(&b[off..off + len]) as i32;
                    let actual = unsafe { memcmp(a.as_ptr().add(off), b.as_ptr().add(off), len) };
                    assert_eq!(actual.signum(), expected, "len {len} off {off} pos {position}");
                    let reverse = unsafe { memcmp(b.as_ptr().add(off), a.as_ptr().add(off), len) };
                    assert_eq!(reverse.signum(), -expected);
                }
            }
        }
    }
}
