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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_keccak256(input: *const u8, length: usize, output: *mut u8) {
    assert!(!output.is_null() && (length == 0 || !input.is_null()));
    let mut state = [0u64; 25];
    let state_ptr = state.as_mut_ptr();
    let bytes = state_ptr.cast::<u8>();
    let aligned = (input as usize) & 7 == 0;
    let mut consumed = 0;
    while length - consumed >= RATE {
        if aligned {
            for i in 0..RATE / 8 {
                unsafe {
                    let word = ptr::read(state_ptr.add(i));
                    let value = u64::from_le(ptr::read(input.add(consumed + i * 8).cast::<u64>()));
                    ptr::write(state_ptr.add(i), word ^ value);
                }
            }
        } else {
            for i in 0..RATE {
                unsafe {
                    *bytes.add(i) ^= *input.add(consumed + i);
                }
            }
        }
        unsafe {
            permute(state_ptr);
        }
        consumed += RATE;
    }
    let remaining = length - consumed;
    for i in 0..remaining {
        unsafe {
            *bytes.add(i) ^= *input.add(consumed + i);
        }
    }
    unsafe {
        *bytes.add(remaining) ^= 0x01;
        *bytes.add(RATE - 1) ^= 0x80;
        permute(state_ptr);
        ptr::copy_nonoverlapping(bytes, output, 32);
    }
}
