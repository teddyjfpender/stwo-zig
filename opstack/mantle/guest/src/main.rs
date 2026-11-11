//! Software Mantle execution guest; shares only the established machine ABI.
#![no_std]
#![no_main]
extern crate alloc;
extern crate stwo_rv64_mem;
#[path = "../../../../guests/exact_layout_allocator_v2.rs"]
mod allocator;
#[path = "../../../../guests/ethereum/rv64/src/single_thread_atomics.rs"]
mod single_thread_atomics;
#[cfg(feature = "crypto-services")]
#[path = "../../../../guests/ethereum/rv64/src/keccak_sponge_service.rs"]
mod sponge_service;
use core::{
    arch::{asm, global_asm},
    ptr,
};
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
        let start = ptr::addr_of!(__input_start);
        let len = ptr::read_volatile(start.cast::<u32>()) as usize;
        assert!(len <= ptr::addr_of!(__input_end) as usize - start as usize - 4);
        let raw = core::slice::from_raw_parts(start.add(4), len);
        let output = stwo_mantle_native::guest_execute(raw).expect("Mantle execution rejected");
        ptr::copy_nonoverlapping(output.as_ptr(), ptr::addr_of!(__output_data).cast_mut(), 43);
        ptr::write_volatile(ptr::addr_of!(__output_len).cast_mut().cast::<u32>(), 43);
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
