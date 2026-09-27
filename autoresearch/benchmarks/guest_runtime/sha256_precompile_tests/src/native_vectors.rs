//! Execute the real RV32 compression instruction through the shared Rust SDK.
#![no_std]
#![no_main]

use core::{arch::{asm, global_asm}, ptr};
use stwo_sha256_precompile_guest_tests::guest;
#[path = "../../ethereum_admission_v1.rs"]
mod admission;

unsafe extern "C" {
    static __halt_flag: u8;
    static __output_len: u8;
    static __output_data: u8;
}
global_asm!(r#"
    .section .text._start
    .globl _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __stack_top
    call guest_main
"#);

#[repr(align(4))]
struct Input([u8; 1032]);

#[unsafe(no_mangle)]
extern "C" fn guest_main() -> ! {
    let mut input = Input([0; 1032]);
    for (i, byte) in input.0.iter_mut().enumerate() {
        *byte = i.wrapping_mul(71).wrapping_add(9) as u8;
    }
    let mut output = [0u8; 44 * 32];
    let mut at = 0;
    for offset in 0..4 {
        for length in [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1024] {
            let digest = guest::hash(&input.0[offset..offset + length]);
            output[at..at + 32].copy_from_slice(&digest);
            at += 32;
        }
    }
    unsafe {
        ptr::copy_nonoverlapping(output.as_ptr(), ptr::addr_of!(__output_data).cast_mut(), output.len());
        ptr::write_volatile(ptr::addr_of!(__output_len).cast_mut().cast::<u32>(), output.len() as u32);
        ptr::write_volatile(ptr::addr_of!(__halt_flag).cast_mut().cast::<u32>(), 1);
        asm!("2: j 2b", options(noreturn));
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { asm!("unimp", options(noreturn)); }
}
