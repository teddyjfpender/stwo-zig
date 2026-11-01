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

/// Execution-only candidate services (profile `ethereum_services_v3_candidate`,
/// autoresearch/guest_efficiency/CONTEXT.md). Off by default: the admitted
/// guest never contains these ECALLs. Calls of at least the threshold length go
/// to the service. The measured optimum is 0 for all three (every call, no
/// length test): a 1..1024-byte sweep on the 15-block basket lowered both
/// instructions/gas and committed bits/gas monotonically as the threshold fell,
/// even at the high end of the estimated service cost
/// (proposals/candidate-service-costs.md, proposals/bulk-memory.md). The
/// thresholds can be overridden at build time for sweeps
/// (`STWO_CANDIDATE_{COPY,SET,CMP}_MIN=<bytes>|off`).
#[cfg(all(feature = "candidate-services", target_arch = "riscv64"))]
mod candidate {
    const fn parse(value: Option<&str>, default: usize) -> usize {
        let Some(text) = value else { return default };
        let bytes = text.as_bytes();
        // "off" disables a family at compile time (no length test emitted).
        if bytes.len() == 3 && bytes[0] == b'o' && bytes[1] == b'f' && bytes[2] == b'f' {
            return usize::MAX;
        }
        let mut i = 0;
        let mut n = 0usize;
        while i < bytes.len() {
            assert!(bytes[i].is_ascii_digit(), "threshold must be decimal");
            n = n * 10 + (bytes[i] - b'0') as usize;
            i += 1;
        }
        n
    }
    pub const COPY_MIN: usize = parse(option_env!("STWO_CANDIDATE_COPY_MIN"), 0);
    pub const SET_MIN: usize = parse(option_env!("STWO_CANDIDATE_SET_MIN"), 0);
    pub const CMP_MIN: usize = parse(option_env!("STWO_CANDIDATE_CMP_MIN"), 0);
    pub const COPY_ON: bool = COPY_MIN != usize::MAX;
    pub const SET_ON: bool = SET_MIN != usize::MAX;
    pub const CMP_ON: bool = CMP_MIN != usize::MAX;
    pub const MEMCPY: usize = 0x0003_0001;
    pub const MEMSET: usize = 0x0003_0002;
    pub const MEMCMP: usize = 0x0003_0003;

    /// `a0` = 8-aligned packet, `a7` = tag; all registers preserved. Default
    /// asm memory effects keep packet stores before and loads after the call.
    #[inline(always)]
    pub unsafe fn call<const N: usize>(packet: &mut [u64; N], tag: usize) {
        unsafe { core::arch::asm!("ecall", in("a0") packet.as_mut_ptr(), in("a7") tag, options(nostack)) };
    }
}

/// ADMITTED bulk-memory services (profile `ethereum_services_v3`,
/// design/riscv-proving-stack/rv64-bulk-memory-service.md). The prover admits
/// packet `dst, src|byte, len` (memcpy/memset) or `a, b, len, result` (memcmp)
/// at an 8-aligned pointer with `dst` (and `a`, `b`) 8-aligned, `len` a
/// nonzero multiple of 8 and at most 1 MiB, a memcpy source of any alignment,
/// and the packet, source and destination WORDS pairwise disjoint. The
/// wrappers below copy the destination's unaligned head and tail inline (and
/// compare a memcmp tail inline), split bodies into 1 MiB chunks and fall back
/// to software for overlap (at word granularity) or unaligned memcmp operands,
/// so the executor never traps on a wrapper call. Host tests compile this
/// module against an emulated service that panics on any call the executor
/// would refuse.
#[cfg(any(test, all(feature = "admitted-bulk", target_arch = "riscv64")))]
mod admitted {
    const fn parse(value: Option<&str>, default: usize) -> usize {
        let Some(text) = value else { return default };
        let bytes = text.as_bytes();
        if bytes.len() == 3 && bytes[0] == b'o' && bytes[1] == b'f' && bytes[2] == b'f' {
            return usize::MAX;
        }
        let mut i = 0;
        let mut n = 0usize;
        while i < bytes.len() {
            assert!(bytes[i].is_ascii_digit(), "threshold must be decimal");
            n = n * 10 + (bytes[i] - b'0') as usize;
            i += 1;
        }
        n
    }
    /// Minimum total length routed to the service (bytes); `off` disables.
    pub const COPY_MIN: usize = parse(option_env!("STWO_ADMITTED_COPY_MIN"), 16);
    /// Mismatched source/destination alignment (unaligned body rows).
    pub const UCOPY_MIN: usize = parse(option_env!("STWO_ADMITTED_UCOPY_MIN"), 16);
    pub const SET_MIN: usize = parse(option_env!("STWO_ADMITTED_SET_MIN"), 16);
    pub const CMP_MIN: usize = parse(option_env!("STWO_ADMITTED_CMP_MIN"), 8);
    pub const MEMCPY: usize = 0x0003_0001;
    pub const MEMSET: usize = 0x0003_0002;
    pub const MEMCMP: usize = 0x0003_0003;
    const MAX: usize = 1 << 20;

    #[cfg(not(test))]
    #[inline(always)]
    unsafe fn call<const N: usize>(packet: &mut [u64; N], tag: usize) {
        unsafe { core::arch::asm!("ecall", in("a0") packet.as_mut_ptr(), in("a7") tag, options(nostack)) };
    }
    /// Host emulation of the executor's admission (ethereum_services/bulk_memory.zig).
    #[cfg(test)]
    unsafe fn call<const N: usize>(packet: &mut [u64; N], tag: usize) {
        let words = if tag == MEMCMP { 4 } else { 3 };
        assert_eq!(N, words);
        let p = packet.as_ptr() as usize;
        let (dst, word1, len) = (packet[0] as usize, packet[1] as usize, packet[2] as usize);
        assert!(p & 7 == 0 && len != 0 && len % 8 == 0 && len <= MAX && dst & 7 == 0);
        let disjoint = |a: usize, an: usize, b: usize, bn: usize| a + an <= b || b + bn <= a;
        assert!(disjoint(p, 8 * words, dst, len));
        match tag {
            MEMCPY => {
                let (s0, sn) = (word1 & !7, len + if word1 & 7 != 0 { 8 } else { 0 });
                assert!(disjoint(p, 24, s0, sn) && disjoint(dst, len, s0, sn), "aliasing words");
                unsafe { core::ptr::copy_nonoverlapping(word1 as *const u8, dst as *mut u8, len) };
            }
            MEMSET => unsafe { core::ptr::write_bytes(dst as *mut u8, word1 as u8, len) },
            MEMCMP => {
                assert!(word1 & 7 == 0 && disjoint(p, 32, word1, len) && disjoint(dst, len, word1, len));
                let (a, b) = unsafe { (core::slice::from_raw_parts(dst as *const u8, len), core::slice::from_raw_parts(word1 as *const u8, len)) };
                packet[3] = a.cmp(b) as i64 as u64;
            }
            _ => panic!("tag"),
        }
    }
    /// `d` 8-aligned, `n` a nonzero multiple of 8, source words disjoint from
    /// the destination.
    #[inline(always)]
    pub unsafe fn copy_words(mut d: *mut u8, mut s: *const u8, mut n: usize) {
        while n > MAX {
            unsafe { call(&mut [d as u64, s as u64, MAX as u64], MEMCPY) };
            d = unsafe { d.add(MAX) };
            s = unsafe { s.add(MAX) };
            n -= MAX;
        }
        unsafe { call(&mut [d as u64, s as u64, n as u64], MEMCPY) };
    }
    /// `d` 8-aligned, `n` a nonzero multiple of 8.
    #[inline(always)]
    pub unsafe fn fill_words(mut d: *mut u8, byte: u8, mut n: usize) {
        while n > MAX {
            unsafe { call(&mut [d as u64, byte as u64, MAX as u64], MEMSET) };
            d = unsafe { d.add(MAX) };
            n -= MAX;
        }
        unsafe { call(&mut [d as u64, byte as u64, n as u64], MEMSET) };
    }
    /// Copies `n` bytes through the service when the destination has at least
    /// one whole word and the touched words are disjoint; returns false
    /// otherwise (the caller copies in software).
    #[inline(always)]
    pub unsafe fn copy(dest: *mut u8, src: *const u8, n: usize) -> bool {
        let (d, s) = (dest as usize, src as usize);
        let min = if (d ^ s) & 7 == 0 { COPY_MIN } else { UCOPY_MIN };
        if n < min {
            return false;
        }
        let head = d.wrapping_neg() & 7;
        if n < head + 8 {
            return false;
        }
        let body = (n - head) & !7;
        // Overlapping moves stay in software. Byte-disjoint ranges never
        // share a service word: the destination body is word-aligned, so the
        // source words holding body bytes end before it or start after it.
        if d < s + n && s < d + n {
            return false;
        }
        unsafe {
            super::copy_bytes(dest, src, head);
            copy_words(dest.add(head), src.add(head), body);
            super::copy_bytes(dest.add(head + body), src.add(head + body), n - head - body);
        }
        true
    }
    #[inline(always)]
    pub unsafe fn set(dest: *mut u8, byte: u8, n: usize) -> bool {
        if n < SET_MIN {
            return false;
        }
        let head = (dest as usize).wrapping_neg() & 7;
        let body = (n - head) & !7;
        if body == 0 {
            return false;
        }
        unsafe {
            for i in 0..head {
                *dest.add(i) = byte;
            }
            fill_words(dest.add(head), byte, body);
            for i in head + body..n {
                *dest.add(i) = byte;
            }
        }
        true
    }
    /// Compares the word body of two 8-aligned disjoint ranges through the
    /// service; `None` when the call does not qualify. A zero body result
    /// leaves the tail (`n % 8` bytes) to the caller.
    #[inline(always)]
    pub unsafe fn compare(a: *const u8, b: *const u8, n: usize) -> Option<i32> {
        let (x, y) = (a as usize, b as usize);
        if n < CMP_MIN || n < 8 || (x | y) & 7 != 0 || (x < y + n && y < x + n) {
            return None;
        }
        let mut body = n & !7;
        let (mut a, mut b) = (a, b);
        while body != 0 {
            let chunk = if body > MAX { MAX } else { body };
            let mut packet = [a as u64, b as u64, chunk as u64, 0];
            unsafe { call(&mut packet, MEMCMP) };
            if packet[3] != 0 {
                return Some(packet[3] as i64 as i32);
            }
            a = unsafe { a.add(chunk) };
            b = unsafe { b.add(chunk) };
            body -= chunk;
        }
        let mut i = 0;
        while i < n & 7 {
            let (p, q) = unsafe { (*a.add(i), *b.add(i)) };
            if p != q {
                return Some(i32::from(p) - i32::from(q));
            }
            i += 1;
        }
        Some(0)
    }
}

#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    #[cfg(all(feature = "admitted-bulk", target_arch = "riscv64"))]
    if (admitted::COPY_MIN != usize::MAX || admitted::UCOPY_MIN != usize::MAX) && unsafe { admitted::copy(dest, src, n) } {
        return dest;
    }
    #[cfg(all(feature = "candidate-services", target_arch = "riscv64"))]
    if candidate::COPY_ON && n >= candidate::COPY_MIN {
        unsafe { candidate::call(&mut [dest as u64, src as u64, n as u64], candidate::MEMCPY) };
        return dest;
    }
    unsafe { copy_forward(dest, src, n) };
    dest
}

#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // The admitted service requires disjoint words; overlapping moves stay in software.
    #[cfg(all(feature = "admitted-bulk", target_arch = "riscv64"))]
    if (admitted::COPY_MIN != usize::MAX || admitted::UCOPY_MIN != usize::MAX) && unsafe { admitted::copy(dest, src, n) } {
        return dest;
    }
    // The candidate service is memmove-safe for any overlap.
    #[cfg(all(feature = "candidate-services", target_arch = "riscv64"))]
    if candidate::COPY_ON && n >= candidate::COPY_MIN {
        unsafe { candidate::call(&mut [dest as u64, src as u64, n as u64], candidate::MEMCPY) };
        return dest;
    }
    if (dest as usize).wrapping_sub(src as usize) >= n {
        unsafe { copy_forward(dest, src, n) };
    } else {
        // Copy backwards, keeping every load/store aligned and loading a
        // whole group before any store (also handles a distance of one word).
        let mut i = n;
        if ((dest as usize) ^ (src as usize)) & 7 == 0 && n >= 16 {
            while (dest as usize + i) & 7 != 0 {
                i -= 1;
                unsafe { *dest.add(i) = *src.add(i) };
            }
            while i >= 32 {
                i -= 32;
                unsafe {
                    let a = load(src.add(i));
                    let b = load(src.add(i + 8));
                    let c = load(src.add(i + 16));
                    let d = load(src.add(i + 24));
                    store(dest.add(i), a);
                    store(dest.add(i + 8), b);
                    store(dest.add(i + 16), c);
                    store(dest.add(i + 24), d);
                }
            }
            while i >= 8 {
                i -= 8;
                unsafe { store(dest.add(i), load(src.add(i))) };
            }
        }
        while i != 0 {
            i -= 1;
            unsafe { *dest.add(i) = *src.add(i) };
        }
    }
    dest
}

#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub unsafe extern "C" fn memset(dest: *mut u8, value: i32, n: usize) -> *mut u8 {
    #[cfg(all(feature = "admitted-bulk", target_arch = "riscv64"))]
    if admitted::SET_MIN != usize::MAX && unsafe { admitted::set(dest, value as u8, n) } {
        return dest;
    }
    #[cfg(all(feature = "candidate-services", target_arch = "riscv64"))]
    if candidate::SET_ON && n >= candidate::SET_MIN {
        unsafe { candidate::call(&mut [dest as u64, value as u8 as u64, n as u64], candidate::MEMSET) };
        return dest;
    }
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
    #[cfg(all(feature = "admitted-bulk", target_arch = "riscv64"))]
    if admitted::CMP_MIN != usize::MAX {
        if let Some(r) = unsafe { admitted::compare(a, b, n) } {
            return r;
        }
    }
    #[cfg(all(feature = "candidate-services", target_arch = "riscv64"))]
    if candidate::CMP_ON && n >= candidate::CMP_MIN {
        let mut packet = [a as u64, b as u64, n as u64, 0];
        unsafe { candidate::call(&mut packet, candidate::MEMCMP) };
        return packet[3] as i64 as i32;
    }
    let mut a = a;
    let mut b = b;
    let mut n = n;
    if ((a as usize) | (b as usize)) & 7 == 0 {
        while n >= 8 {
            let (wa, wb) = unsafe { (load(a), load(b)) };
            if wa != wb {
                // Identify the first differing byte without two expensive
                // RV64IM byte swaps. Propagate each byte's differing bits to
                // its low bit, then isolate the first such byte.
                let mut diff = wa ^ wb;
                diff |= diff >> 4;
                diff |= diff >> 2;
                diff |= diff >> 1;
                let flags = diff & 0x0101_0101_0101_0101;
                let first = flags & flags.wrapping_neg();
                let mask = first.wrapping_mul(255);
                return if wa & mask < wb & mask { -1 } else { 1 };
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
    #[cfg(all(feature = "admitted-bulk", target_arch = "riscv64"))]
    if admitted::CMP_MIN != usize::MAX {
        if let Some(r) = unsafe { admitted::compare(a, b, n) } {
            return r;
        }
    }
    // Equality needs neither a first-difference search nor byte order.
    let (mut a, mut b, mut n) = (a, b, n);
    if ((a as usize) | (b as usize)) & 7 == 0 {
        while n >= 8 {
            if unsafe { load(a) != load(b) } {
                return 1;
            }
            a = unsafe { a.add(8) };
            b = unsafe { b.add(8) };
            n -= 8;
        }
    }
    while n != 0 {
        if unsafe { *a != *b } {
            return 1;
        }
        a = unsafe { a.add(1) };
        b = unsafe { b.add(1) };
        n -= 1;
    }
    0
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
    // Most object copies already have both pointers aligned. Bypass the
    // byte prologue's jump table and the funnel machinery entirely.
    if ((d as usize) | (s as usize)) & 7 == 0 {
        unsafe { copy_aligned(d, s, n) };
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
    if n == 0 {
        return;
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
                    assert_eq!(
                        dst, reference,
                        "len {len} src offset {so} dst offset {doff}"
                    );
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
    fn bcmp_matches_equality_for_independent_alignments() {
        for len in 0..130 {
            for ao in 0..8 {
                for bo in 0..8 {
                    let a = pattern(len + 16, (len * 29 + ao) as u64);
                    let mut b = vec![0u8; len + 16];
                    b[bo..bo + len].copy_from_slice(&a[ao..ao + len]);
                    assert_eq!(unsafe { bcmp(a.as_ptr().add(ao), b.as_ptr().add(bo), len) }, 0);
                    for pos in (0..len).step_by(7) {
                        b[bo + pos] ^= 0x81;
                        assert_ne!(unsafe { bcmp(a.as_ptr().add(ao), b.as_ptr().add(bo), len) }, 0);
                        b[bo + pos] ^= 0x81;
                    }
                }
            }
        }
    }

    #[test]
    fn admitted_copy_routes_every_alignment_without_aliasing_words() {
        let mut routed = 0;
        for len in 0..90 {
            for so in 0..16 {
                for doff in 0..16 {
                    let src = pattern(len + 32, (len * 17 + so * 5 + doff) as u64);
                    let mut dst = vec![0x5au8; len + 48];
                    // 8-aligned backing buffers so offsets are exact alignments.
                    let mut s64 = vec![0u64; (len + 32) / 8 + 2];
                    let mut d64 = vec![0u64; (len + 48) / 8 + 2];
                    let sb = unsafe { core::slice::from_raw_parts_mut(s64.as_mut_ptr() as *mut u8, len + 32) };
                    sb.copy_from_slice(&src);
                    let db = unsafe { core::slice::from_raw_parts_mut(d64.as_mut_ptr() as *mut u8, len + 48) };
                    db.copy_from_slice(&dst);
                    let ok = unsafe { admitted::copy(db.as_mut_ptr().add(doff), sb.as_ptr().add(so), len) };
                    routed += ok as usize;
                    dst[doff..doff + len].copy_from_slice(&src[so..so + len]);
                    if ok {
                        assert_eq!(db, &dst[..], "len {len} so {so} doff {doff}");
                    }
                }
            }
        }
        assert!(routed > 10_000);
    }

    #[test]
    fn admitted_copy_never_aliases_words_inside_one_buffer() {
        // Every byte-disjoint (dst, src, len) inside one buffer: the emulated
        // service asserts word disjointness; the result must equal memmove.
        let base_pattern = pattern(160, 99);
        let mut routed = 0;
        for d in 0..48usize {
            for s in 0..48usize {
                for n in 0..64usize {
                    if d < s + n && s < d + n {
                        continue;
                    }
                    let mut words = [0u64; 20];
                    let buffer = unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr() as *mut u8, 160) };
                    buffer.copy_from_slice(&base_pattern);
                    let mut reference = base_pattern.clone();
                    reference.copy_within(s..s + n, d);
                    let base = buffer.as_mut_ptr();
                    routed += unsafe { admitted::copy(base.add(d), base.add(s), n) } as usize;
                    unsafe { memmove(base.add(d), base.add(s), n) };
                    assert_eq!(buffer, &reference[..], "d {d} s {s} n {n}");
                }
            }
        }
        assert!(routed > 10_000);
    }

    #[test]
    fn admitted_compare_matches_lexicographic_order() {
        for len in 0..80 {
            for position in 0..len.max(1) {
                let mut a64 = vec![0u64; 12];
                let mut b64 = vec![0u64; 12];
                let a = unsafe { core::slice::from_raw_parts_mut(a64.as_mut_ptr() as *mut u8, 96) };
                let b = unsafe { core::slice::from_raw_parts_mut(b64.as_mut_ptr() as *mut u8, 96) };
                a.copy_from_slice(&pattern(96, len as u64 * 7 + 1));
                b.copy_from_slice(a);
                if position < len {
                    b[position] = a[position].wrapping_add(1 + (position as u8 % 3));
                }
                let expected = a[..len].cmp(&b[..len]) as i32;
                match unsafe { admitted::compare(a.as_ptr(), b.as_ptr(), len) } {
                    Some(r) => assert_eq!(r.signum(), expected, "len {len} pos {position}"),
                    None => assert!(len < 8),
                }
            }
        }
        let x = [0u64; 4];
        assert!(unsafe { admitted::compare(x.as_ptr() as *const u8, (x.as_ptr() as *const u8).add(8), 16) }.is_none());
    }

    #[test]
    fn memcmp_sign_matches_lexicographic_order() {
        for len in 0..80 {
            for off in 0..9 {
                for position in 0..len.max(1) {
                    let a = pattern(len + 16, (len * 3 + off) as u64);
                    let mut b = a.clone();
                    if position < len {
                        b[off + position] =
                            a[off + position].wrapping_add(1 + (position as u8 % 3));
                    }
                    let expected = a[off..off + len].cmp(&b[off..off + len]) as i32;
                    let actual = unsafe { memcmp(a.as_ptr().add(off), b.as_ptr().add(off), len) };
                    assert_eq!(
                        actual.signum(),
                        expected,
                        "len {len} off {off} pos {position}"
                    );
                    let reverse = unsafe { memcmp(b.as_ptr().add(off), a.as_ptr().add(off), len) };
                    assert_eq!(reverse.signum(), -expected);
                }
            }
        }
    }
}
