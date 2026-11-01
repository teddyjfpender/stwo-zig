//! stwo: scalar SHA-256 compression for RV64IM (no Zbb rotates).
//!
//! Every 32-bit word lives in the low half of a u64 register; the high half
//! is ignored garbage, which additions, XOR and AND never propagate downward.
//! A 32-bit rotate becomes one 64-bit shift of the doubled word
//! `d = (x << 32) | (x << 32 >> 32)`, so a three-rotate sigma costs eight
//! instructions instead of eleven. `t >> (32 + n)` with `t = x << 32` is the
//! logical shift `x >> n` of the zero-extended word.
use crate::consts::K32;

#[inline(always)]
fn big_sigma0(x: u64) -> u64 {
    let t = x << 32;
    let d = t | (t >> 32);
    (d >> 2) ^ (d >> 13) ^ (d >> 22)
}

#[inline(always)]
fn big_sigma1(x: u64) -> u64 {
    let t = x << 32;
    let d = t | (t >> 32);
    (d >> 6) ^ (d >> 11) ^ (d >> 25)
}

#[inline(always)]
fn small_sigma0(x: u64) -> u64 {
    let t = x << 32;
    let d = t | (t >> 32);
    (d >> 7) ^ (d >> 18) ^ (t >> 35)
}

#[inline(always)]
fn small_sigma1(x: u64) -> u64 {
    let t = x << 32;
    let d = t | (t >> 32);
    (d >> 17) ^ (d >> 19) ^ (t >> 42)
}

macro_rules! round {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $kw:expr) => {
        let t1 = $h
            .wrapping_add(big_sigma1($e))
            .wrapping_add($g ^ ($e & ($f ^ $g)))
            .wrapping_add($kw);
        let t2 = big_sigma0($a).wrapping_add(($a & $b) | ($c & ($a | $b)));
        $d = $d.wrapping_add(t1);
        $h = t1.wrapping_add(t2);
    };
}

/// Runs the 64 rounds over `state` with `kw[t] = K[t] + W[t]` supplied by
/// `kw_at`, then adds the input state back.
#[inline(always)]
fn rounds(state: &mut [u32; 8], kw_at: impl Fn(usize) -> u64) {
    let mut a = state[0] as u64;
    let mut b = state[1] as u64;
    let mut c = state[2] as u64;
    let mut d = state[3] as u64;
    let mut e = state[4] as u64;
    let mut f = state[5] as u64;
    let mut g = state[6] as u64;
    let mut h = state[7] as u64;
    let mut t = 0;
    while t < 64 {
        round!(a, b, c, d, e, f, g, h, kw_at(t));
        round!(h, a, b, c, d, e, f, g, kw_at(t + 1));
        round!(g, h, a, b, c, d, e, f, kw_at(t + 2));
        round!(f, g, h, a, b, c, d, e, kw_at(t + 3));
        round!(e, f, g, h, a, b, c, d, kw_at(t + 4));
        round!(d, e, f, g, h, a, b, c, kw_at(t + 5));
        round!(c, d, e, f, g, h, a, b, kw_at(t + 6));
        round!(b, c, d, e, f, g, h, a, kw_at(t + 7));
        t += 8;
    }
    state[0] = state[0].wrapping_add(a as u32);
    state[1] = state[1].wrapping_add(b as u32);
    state[2] = state[2].wrapping_add(c as u32);
    state[3] = state[3].wrapping_add(d as u32);
    state[4] = state[4].wrapping_add(e as u32);
    state[5] = state[5].wrapping_add(f as u32);
    state[6] = state[6].wrapping_add(g as u32);
    state[7] = state[7].wrapping_add(h as u32);
}

#[inline(always)]
fn be_word(p: &[u8; 64], i: usize) -> u64 {
    // Volatile byte loads stop LLVM from fusing them into a little-endian
    // word followed by a ~20-instruction software byte swap.
    unsafe {
        let b = p.as_ptr().add(4 * i);
        ((core::ptr::read_volatile(b) as u64) << 24)
            | ((core::ptr::read_volatile(b.add(1)) as u64) << 16)
            | ((core::ptr::read_volatile(b.add(2)) as u64) << 8)
            | (core::ptr::read_volatile(b.add(3)) as u64)
    }
}

#[inline(always)]
fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = core::mem::MaybeUninit::<[u64; 64]>::uninit();
    let p = w.as_mut_ptr() as *mut u64;
    unsafe {
        let mut i = 0;
        while i < 16 {
            p.add(i).write(be_word(block, i));
            i += 1;
        }
        while i < 64 {
            let v = small_sigma1(p.add(i - 2).read())
                .wrapping_add(p.add(i - 7).read())
                .wrapping_add(small_sigma0(p.add(i - 15).read()))
                .wrapping_add(p.add(i - 16).read());
            p.add(i).write(v);
            i += 1;
        }
    }
    let w = unsafe { w.assume_init() };
    rounds(state, |t| w[t].wrapping_add(K32[t] as u64));
}

pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block);
    }
}

/// `K[t] + W[t]` of the padding block that follows exactly one 64-byte block
/// (message bit length 512), which every SSZ `hash_nodes` call ends with.
const PAD512_KW: [u32; 64] = {
    let mut w = [0u32; 64];
    w[0] = 0x8000_0000;
    w[15] = 512;
    let mut i = 16;
    while i < 64 {
        let x = w[i - 15];
        let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
        let y = w[i - 2];
        let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
        w[i] = s1.wrapping_add(w[i - 7]).wrapping_add(s0).wrapping_add(w[i - 16]);
        i += 1;
    }
    let mut kw = [0u32; 64];
    let mut t = 0;
    while t < 64 {
        kw[t] = w[t].wrapping_add(K32[t]);
        t += 1;
    }
    kw
};

/// Compresses the constant padding block of a 64-byte message.
pub fn compress_pad512(state: &mut [u32; 8]) {
    rounds(state, |t| PAD512_KW[t] as u64);
}
