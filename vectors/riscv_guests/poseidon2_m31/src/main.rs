//! Poseidon2-over-M31 RISC-V guest for the cross-implementation perf matrix.
//!
//! Faithful port of stwo's own Poseidon2 example permutation (examples/src/
//! poseidon/mod.rs at the pinned Stark-V commit): state width 16, S-box x^5,
//! 8 full rounds (4 + 4) around 14 partial rounds, the circ(2·M4, M4, M4, M4)
//! external matrix, and the 2^(i+1) internal diagonal. Round constants are the
//! same placeholder value stwo's example uses (1234) — the benchmark measures
//! the prover cost of the permutation's arithmetic shape, not the guest hash's
//! cryptographic security, and this keeps the port a byte-faithful mirror.
//!
//! Field arithmetic emits only the RV32IM `MUL` low-word multiply, never
//! MULH/MULHU/MULHSU. M31 multiplication uses 16-bit limbs whose partial
//! products fit in 32 bits, and the internal diagonal uses 31-bit rotations
//! instead of multiplies. This keeps the workload on the portable RV32IM
//! instruction path without relying on a cryptographic precompile.
//!
//! Input : [n: u32 LE][n field elements: u32 LE], each reduced mod p on read.
//! Hash  : rate-1 sponge — absorb one element into state[0], permute, repeat;
//!         one permutation per element, so cost scales linearly with n.
//! Output: 8 field elements (state[0..8]) as 32 raw little-endian bytes.

#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr;

const P: u32 = 0x7FFF_FFFF; // 2^31 - 1
const WIDTH: usize = 16;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 14;
const ROUND_CONST: u32 = 1234;

// I/O region symbols from the vendored linker script.
unsafe extern "C" {
    static __input_start: u8;
    static __halt_flag: u8;
    static __output_len: u8;
    static __output_data: u8;
}

global_asm!(
    r#"
    .section .text._start
    .globl _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __stack_top
    call __zkvm_start
"#
);

#[inline(always)]
fn m31_add(a: u32, b: u32) -> u32 {
    let s = a + b; // a, b < P so s < 2P, no u32 overflow
    if s >= P { s - P } else { s }
}

/// x * y mod (2^31 - 1) from 16-bit-limb `MUL` products only (never MULH*).
///
/// Each limb product is reduced mod p and folded back with rotations, so the
/// four partial products are never recombined into a full 32x32->64 product —
/// which LLVM would otherwise re-fuse into a single MUL+MULHU widening multiply.
/// black_box on each product is the belt-and-braces guard against that re-fusion.
#[inline(always)]
fn m31_mul(a: u32, b: u32) -> u32 {
    let a_lo = a & 0xFFFF;
    let a_hi = a >> 16;
    let b_lo = b & 0xFFFF;
    let b_hi = b >> 16;
    // Each product is <= (2^16-1)^2 < 2^32, so plain 32-bit MUL is exact.
    let ll = core::hint::black_box(a_lo.wrapping_mul(b_lo));
    let lh = core::hint::black_box(a_lo.wrapping_mul(b_hi));
    let hl = core::hint::black_box(a_hi.wrapping_mul(b_lo));
    let hh = core::hint::black_box(a_hi.wrapping_mul(b_hi));
    // result = ll + (lh + hl)*2^16 + hh*2^32   (mod p; 2^32 ≡ 2, 2^16 stays)
    let mid = m31_add(m31_reduce32(lh), m31_reduce32(hl));
    let mut acc = m31_reduce32(ll);
    acc = m31_add(acc, m31_shl(mid, 16));
    acc = m31_add(acc, m31_shl(m31_reduce32(hh), 1));
    acc
}

/// Reduce a u32 (< 2^32) modulo 2^31 - 1 via one fold (shifts + add only).
#[inline(always)]
fn m31_reduce32(x: u32) -> u32 {
    let v = (x & P) + (x >> 31);
    if v >= P { v - P } else { v }
}

/// x * 2^k mod (2^31 - 1) is a k-bit rotation within the 31-bit field.
#[inline(always)]
fn m31_shl(x: u32, k: u32) -> u32 {
    let hi = (x << k) & P;
    let lo = x >> (31 - k);
    m31_add(hi, lo)
}

#[inline(always)]
fn pow5(x: u32) -> u32 {
    let x2 = m31_mul(x, x);
    let x4 = m31_mul(x2, x2);
    m31_mul(x4, x)
}

/// stwo apply_m4: the 4x4 MDS block, additions only.
#[inline(always)]
fn apply_m4(x: [u32; 4]) -> [u32; 4] {
    let t0 = m31_add(x[0], x[1]);
    let t02 = m31_add(t0, t0);
    let t1 = m31_add(x[2], x[3]);
    let t12 = m31_add(t1, t1);
    let t2 = m31_add(m31_add(x[1], x[1]), t1);
    let t3 = m31_add(m31_add(x[3], x[3]), t0);
    let t4 = m31_add(m31_add(t12, t12), t3);
    let t5 = m31_add(m31_add(t02, t02), t2);
    let t6 = m31_add(t3, t5);
    let t7 = m31_add(t2, t4);
    [t6, t5, t7, t4]
}

/// External round matrix: circ(2·M4, M4, M4, M4).
fn apply_external(state: &mut [u32; WIDTH]) {
    let mut i = 0;
    while i < 4 {
        let out = apply_m4([state[4 * i], state[4 * i + 1], state[4 * i + 2], state[4 * i + 3]]);
        state[4 * i] = out[0];
        state[4 * i + 1] = out[1];
        state[4 * i + 2] = out[2];
        state[4 * i + 3] = out[3];
        i += 1;
    }
    let mut j = 0;
    while j < 4 {
        let s = m31_add(m31_add(state[j], state[j + 4]), m31_add(state[j + 8], state[j + 12]));
        let mut i = 0;
        while i < 4 {
            state[4 * i + j] = m31_add(state[4 * i + j], s);
            i += 1;
        }
        j += 1;
    }
}

/// Internal round matrix: mu_i = 2^(i+1); state[i] = state[i]*mu_i + sum.
fn apply_internal(state: &mut [u32; WIDTH]) {
    let mut sum = state[0];
    let mut i = 1;
    while i < WIDTH {
        sum = m31_add(sum, state[i]);
        i += 1;
    }
    let mut i = 0;
    while i < WIDTH {
        state[i] = m31_add(m31_shl(state[i], (i + 1) as u32), sum);
        i += 1;
    }
}

fn permute(state: &mut [u32; WIDTH]) {
    for _ in 0..HALF_FULL_ROUNDS {
        for s in state.iter_mut() {
            *s = m31_add(*s, ROUND_CONST);
        }
        apply_external(state);
        for s in state.iter_mut() {
            *s = pow5(*s);
        }
    }
    for _ in 0..PARTIAL_ROUNDS {
        state[0] = m31_add(state[0], ROUND_CONST);
        apply_internal(state);
        state[0] = pow5(state[0]);
    }
    for _ in 0..HALF_FULL_ROUNDS {
        for s in state.iter_mut() {
            *s = m31_add(*s, ROUND_CONST);
        }
        apply_external(state);
        for s in state.iter_mut() {
            *s = pow5(*s);
        }
    }
}

#[inline(always)]
unsafe fn read_input_word(index: usize) -> u32 {
    let base = ptr::addr_of!(__input_start) as *const u8;
    unsafe { ptr::read_volatile(base.add(index * 4) as *const u32) }
}

#[unsafe(no_mangle)]
pub extern "C" fn __zkvm_start() -> ! {
    let n = unsafe { read_input_word(0) } as usize;

    let mut state = [0u32; WIDTH];
    let mut i = 0;
    while i < n {
        // Reduce via bit folding, never `%` — modulo by a constant compiles to
        // a magic-number MULHU, which is exactly the fail-closed family.
        let element = m31_reduce32(unsafe { read_input_word(1 + i) });
        state[0] = m31_add(state[0], element);
        permute(&mut state);
        i += 1;
    }

    let mut digest = [0u8; 32];
    let mut i = 0;
    while i < 8 {
        digest[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
        i += 1;
    }

    unsafe {
        let data = ptr::addr_of!(__output_data) as *mut u8;
        let mut i = 0;
        while i < digest.len() {
            ptr::write_volatile(data.add(i), digest[i]);
            i += 1;
        }
        ptr::write_volatile(ptr::addr_of!(__output_len) as *mut u32, digest.len() as u32);
        ptr::write_volatile(ptr::addr_of!(__halt_flag) as *mut u32, 1);
    }

    #[allow(clippy::empty_loop)]
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
