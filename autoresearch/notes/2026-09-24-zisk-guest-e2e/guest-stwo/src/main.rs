#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr;
use sha2::{Digest, Sha256};

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
unsafe fn read_input<const N: usize>(offset: usize) -> [u8; N] {
    let source = ptr::addr_of!(__input_start);
    let mut value = [0u8; N];
    let mut index = 0;
    while index < N {
        value[index] = unsafe { ptr::read_volatile(source.add(offset + index)) };
        index += 1;
    }
    value
}

#[unsafe(no_mangle)]
pub extern "C" fn __zkvm_start() -> ! {
    let n = u32::from_le_bytes(unsafe { read_input::<4>(0) });
    assert!(n <= 4096);
    let mut output = [0u8; 32];
    for _ in 0..n { output = Sha256::digest(output).into(); }
    unsafe {
        let output_ptr = ptr::addr_of!(__output_data) as *mut u8;
        let mut index = 0;
        while index < output.len() {
            ptr::write_volatile(output_ptr.add(index), output[index]);
            index += 1;
        }
        ptr::write_volatile(
            ptr::addr_of!(__output_len) as *mut u32,
            output.len() as u32,
        );
        ptr::write_volatile(ptr::addr_of!(__halt_flag) as *mut u32, 1);
    }

    #[allow(clippy::empty_loop)]
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
