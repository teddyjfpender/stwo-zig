//! LLVM legacy atomic libcalls for ONE interrupt-free guest thread only.
//! This supplies compiler ordering and volatile reads/writes, never host/thread
//! synchronization. The target enables forced libcalls without the A extension.
use core::{
    ptr,
    sync::atomic::{Ordering, compiler_fence},
};
macro_rules! width {
    ($ty:ty, $cas:ident, $add:ident, $sub:ident) => {
        #[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
        pub unsafe extern "C" fn $cas(p: *mut $ty, expected: $ty, replacement: $ty) -> $ty {
            compiler_fence(Ordering::SeqCst);
            let old = unsafe { ptr::read_volatile(p) };
            if old == expected {
                unsafe {
                    ptr::write_volatile(p, replacement);
                }
            }
            compiler_fence(Ordering::SeqCst);
            old
        }
        #[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
        pub unsafe extern "C" fn $add(p: *mut $ty, value: $ty) -> $ty {
            compiler_fence(Ordering::SeqCst);
            let old = unsafe { ptr::read_volatile(p) };
            unsafe {
                ptr::write_volatile(p, old.wrapping_add(value));
            }
            compiler_fence(Ordering::SeqCst);
            old
        }
        #[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
        pub unsafe extern "C" fn $sub(p: *mut $ty, value: $ty) -> $ty {
            unsafe { $add(p, value.wrapping_neg()) }
        }
    };
}
width!(
    u8,
    __sync_val_compare_and_swap_1,
    __sync_fetch_and_add_1,
    __sync_fetch_and_sub_1
);
width!(
    u16,
    __sync_val_compare_and_swap_2,
    __sync_fetch_and_add_2,
    __sync_fetch_and_sub_2
);
width!(
    u32,
    __sync_val_compare_and_swap_4,
    __sync_fetch_and_add_4,
    __sync_fetch_and_sub_4
);
width!(
    u64,
    __sync_val_compare_and_swap_8,
    __sync_fetch_and_add_8,
    __sync_fetch_and_sub_8
);
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_width_compare_exchange_and_reference_counts() {
        let mut value = 0x12345678ffffffff_u64;
        unsafe {
            assert_eq!(__sync_val_compare_and_swap_8(&mut value, 0, 4), value);
            assert_eq!(__sync_fetch_and_add_8(&mut value, 1), 0x12345678ffffffff);
            assert_eq!(value, 0x1234567900000000);
            assert_eq!(__sync_fetch_and_sub_8(&mut value, 1), 0x1234567900000000);
            assert_eq!(
                __sync_val_compare_and_swap_8(&mut value, 0x12345678ffffffff, u64::MAX),
                0x12345678ffffffff
            );
            assert_eq!(__sync_fetch_and_add_8(&mut value, 1), u64::MAX);
            assert_eq!(value, 0);
        }
    }
}
