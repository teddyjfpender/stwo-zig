//! LLVM's legacy atomic libcalls for this single-threaded, interrupt-free VM.
//! These are not host synchronization primitives. Compiler fences retain the
//! ordering contract without requiring the RISC-V A extension.
use core::{
    ptr,
    sync::atomic::{Ordering, compiler_fence},
};

#[cfg_attr(target_arch = "riscv32", unsafe(no_mangle))]
pub unsafe extern "C" fn __sync_val_compare_and_swap_4(
    pointer: *mut u32,
    expected: u32,
    replacement: u32,
) -> u32 {
    compiler_fence(Ordering::SeqCst);
    let previous = unsafe { ptr::read_volatile(pointer) };
    if previous == expected {
        unsafe {
            ptr::write_volatile(pointer, replacement);
        }
    }
    compiler_fence(Ordering::SeqCst);
    previous
}

#[cfg_attr(target_arch = "riscv32", unsafe(no_mangle))]
pub unsafe extern "C" fn __sync_val_compare_and_swap_1(
    pointer: *mut u8,
    expected: u8,
    replacement: u8,
) -> u8 {
    compiler_fence(Ordering::SeqCst);
    let previous = unsafe { ptr::read_volatile(pointer) };
    if previous == expected {
        unsafe {
            ptr::write_volatile(pointer, replacement);
        }
    }
    compiler_fence(Ordering::SeqCst);
    previous
}

#[cfg_attr(target_arch = "riscv32", unsafe(no_mangle))]
pub unsafe extern "C" fn __sync_fetch_and_add_4(pointer: *mut u32, value: u32) -> u32 {
    compiler_fence(Ordering::SeqCst);
    let previous = unsafe { ptr::read_volatile(pointer) };
    unsafe {
        ptr::write_volatile(pointer, previous.wrapping_add(value));
    }
    compiler_fence(Ordering::SeqCst);
    previous
}

#[cfg_attr(target_arch = "riscv32", unsafe(no_mangle))]
pub unsafe extern "C" fn __sync_fetch_and_sub_4(pointer: *mut u32, value: u32) -> u32 {
    unsafe { __sync_fetch_and_add_4(pointer, value.wrapping_neg()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_exchange_and_reference_counts_match_atomic_results() {
        let mut word = 1;
        let mut byte = 1;
        unsafe {
            assert_eq!(__sync_val_compare_and_swap_4(&mut word, 0, 2), 1);
            assert_eq!(word, 1);
            assert_eq!(__sync_val_compare_and_swap_4(&mut word, 1, 2), 1);
            assert_eq!(word, 2);
            assert_eq!(__sync_val_compare_and_swap_1(&mut byte, 0, 2), 1);
            assert_eq!(byte, 1);
            assert_eq!(__sync_val_compare_and_swap_1(&mut byte, 1, 2), 1);
            assert_eq!(byte, 2);
            assert_eq!(__sync_fetch_and_add_4(&mut word, u32::MAX), 2);
            assert_eq!(word, 1);
            assert_eq!(__sync_fetch_and_sub_4(&mut word, 2), 1);
            assert_eq!(word, u32::MAX);
        }
    }
}
