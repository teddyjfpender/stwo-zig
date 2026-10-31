//! Keccak-256 sponge over the explicit v1 in-place permutation service.
//! Padding/absorb/squeeze execute as RV64 instructions. The service preserves
//! registers and mutates exactly the aligned 200-byte state at a0.
#[cfg(target_arch = "riscv64")]
use core::arch::asm;
use core::ptr;
const RATE: usize = 136;
#[inline(always)]
#[cfg(target_arch = "riscv64")]
unsafe fn permute(state: *mut u64) {
    unsafe {
        asm!("ecall", in("a0") state, in("a7") 0x00010001u64, options(nostack));
    }
}
#[cfg(all(test, not(target_arch = "riscv64")))]
pub static PERMUTE_CALLS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
#[cfg(all(test, not(target_arch = "riscv64")))]
unsafe fn permute(state: *mut u64) {
    PERMUTE_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        keccak::Keccak::new().with_f1600(|f| f(&mut *state.cast::<[u64; 25]>()));
    }
}
/// XOR `words` little-endian 64-bit words of `input` into the state. For an
/// unaligned input the words are assembled from aligned loads around it; the
/// caller guarantees the last aligned load ends inside the input buffer.
#[inline(always)]
unsafe fn absorb_words(state: *mut u64, input: *const u8, offset: usize, words: usize) {
    if offset == 0 {
        for i in 0..words {
            unsafe {
                let value = u64::from_le(ptr::read(input.add(i * 8).cast::<u64>()));
                ptr::write(state.add(i), ptr::read(state.add(i)) ^ value);
            }
        }
    } else {
        let shift = (offset * 8) as u32;
        let back = 64 - shift;
        let base = unsafe { input.sub(offset) }.cast::<u64>();
        let mut current = u64::from_le(unsafe { ptr::read(base) });
        for i in 0..words {
            unsafe {
                let next = u64::from_le(ptr::read(base.add(i + 1)));
                let value = (current >> shift) | (next << back);
                ptr::write(state.add(i), ptr::read(state.add(i)) ^ value);
                current = next;
            }
        }
    }
}
#[inline(always)]
unsafe fn absorb_bytes(bytes: *mut u8, input: *const u8, count: usize) {
    for i in 0..count {
        unsafe {
            *bytes.add(i) ^= *input.add(i);
        }
    }
}
/// Number of whole words of a `remaining`-byte unaligned chunk that the
/// funnel may assemble: word i reads aligned bytes up to `8 * i + 16 - offset`.
#[inline(always)]
fn funnel_words(offset: usize, remaining: usize) -> usize {
    if offset == 0 {
        remaining / 8
    } else if remaining + offset >= 16 {
        ((remaining + offset - 16) / 8 + 1).min(remaining / 8)
    } else {
        0
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_keccak256(input: *const u8, length: usize, output: *mut u8) {
    assert!(!output.is_null() && (length == 0 || !input.is_null()));
    let mut state = [0u64; 25];
    let state_ptr = state.as_mut_ptr();
    let bytes = state_ptr.cast::<u8>();
    let offset = (input as usize) & 7;
    let mut consumed = 0;
    while length - consumed >= RATE {
        unsafe {
            let block = input.add(consumed);
            // A full block plus whatever follows it; the funnel may need up to
            // 8 - offset bytes of the next block for the final word.
            let words = funnel_words(offset, length - consumed).min(RATE / 8);
            absorb_words(state_ptr, block, offset, words);
            absorb_bytes(bytes.add(words * 8), block.add(words * 8), RATE - words * 8);
            permute(state_ptr);
        }
        consumed += RATE;
    }
    let remaining = length - consumed;
    unsafe {
        let chunk = input.add(consumed);
        let words = funnel_words(offset, remaining);
        absorb_words(state_ptr, chunk, offset, words);
        absorb_bytes(bytes.add(words * 8), chunk.add(words * 8), remaining - words * 8);
        *bytes.add(remaining) ^= 0x01;
        *bytes.add(RATE - 1) ^= 0x80;
        permute(state_ptr);
        ptr::copy_nonoverlapping(bytes, output, 32);
    }
}
