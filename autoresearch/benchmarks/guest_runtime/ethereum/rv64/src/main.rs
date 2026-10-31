//! Software-only RV64IM/LP64 execution of the pinned stateless validator.
//! No zkVM SDK, custom instruction, host crypto call or witness-result hint.
#![no_std]
#![no_main]
extern crate alloc;
use core::{
    arch::{asm, global_asm},
    ptr,
};
#[path = "../../../exact_layout_allocator_v2.rs"]
mod allocator;
mod single_thread_atomics;
#[cfg(feature = "keccak-service")]
mod keccak_service;
#[global_allocator]
static HEAP: allocator::ExactLayoutFreeListHeapV2 = allocator::ExactLayoutFreeListHeapV2::empty();
unsafe extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
    static __input_start: u8;
    static __input_end: u8;
    static __halt_flag: u8;
    static __output_len: u8;
    static __output_data: u8;
}
struct GuestCriticalSection;
critical_section::set_impl!(GuestCriticalSection);
unsafe impl critical_section::Impl for GuestCriticalSection {
    unsafe fn acquire() -> bool {
        false
    }
    unsafe fn release(_: bool) {}
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
    call guest_main
"#
);
#[unsafe(no_mangle)]
extern "C" fn guest_main() -> ! {
    unsafe {
        let begin = ptr::addr_of!(__heap_start) as usize;
        HEAP.initialize(begin as *mut u8, ptr::addr_of!(__heap_end) as usize - begin);
    }
    let input = unsafe {
        let begin = ptr::addr_of!(__input_start);
        let length = ptr::read_volatile(begin.cast::<u32>()) as usize;
        assert!(length <= ptr::addr_of!(__input_end) as usize - begin as usize - 4);
        core::slice::from_raw_parts(begin.add(4), length)
    };
    let output = stateless_validator_reth::guest::run_stateless_guest(input);
    assert!(
        output.len() == 43 && output[32] == 1,
        "block validation failed"
    );
    unsafe {
        ptr::copy_nonoverlapping(
            output.as_ptr(),
            ptr::addr_of!(__output_data).cast_mut(),
            output.len(),
        );
        ptr::write_volatile(
            ptr::addr_of!(__output_len).cast_mut().cast::<u32>(),
            output.len() as u32,
        );
        ptr::write_volatile(ptr::addr_of!(__halt_flag).cast_mut().cast::<u32>(), 1);
        asm!("2: j 2b", options(noreturn));
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe {
        asm!(".word 0", options(noreturn));
    }
}
