//! OP Stack guest-ABI probe.
//!
//! Reads the length-prefixed input window and writes a 43-byte public output
//! with the OP framing the product statement checks:
//! `digest[32] || status=1 || chain_id u64 LE (10) || "OP"`.
//! `digest[i]` is the XOR of every input byte at index `j` with `j % 32 == i`,
//! followed by the input length mixed into bytes 0..4. The probe uses no
//! services, so its proof needs only the CPU components. It is a test vector,
//! not an OP execution.
#![no_std]
#![no_main]

use core::{
    arch::{asm, global_asm},
    ptr,
};

unsafe extern "C" {
    static __input_start: u8;
    static __input_end: u8;
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
call guest_main
"#
);

const OUTPUT_BYTES: usize = 43;
const CHAIN_ID: u64 = 10;

fn statement(input: &[u8]) -> [u8; OUTPUT_BYTES] {
    let mut out = [0u8; OUTPUT_BYTES];
    for (j, byte) in input.iter().enumerate() {
        out[j % 32] ^= *byte;
    }
    let len = (input.len() as u32).to_le_bytes();
    for i in 0..4 {
        out[i] ^= len[i];
    }
    out[32] = 1;
    out[33..41].copy_from_slice(&CHAIN_ID.to_le_bytes());
    out[41..43].copy_from_slice(b"OP");
    out
}

#[unsafe(no_mangle)]
extern "C" fn guest_main() -> ! {
    let input = unsafe {
        let start = ptr::addr_of!(__input_start);
        let len = ptr::read_volatile(start.cast::<u32>()) as usize;
        if len > ptr::addr_of!(__input_end) as usize - start as usize - 4 {
            asm!(".word 0", options(noreturn));
        }
        core::slice::from_raw_parts(start.add(4), len)
    };
    let output = statement(input);
    unsafe {
        for (i, byte) in output.iter().enumerate() {
            ptr::write_volatile(ptr::addr_of!(__output_data).cast_mut().add(i), *byte);
        }
        ptr::write_volatile(
            ptr::addr_of!(__output_len).cast_mut().cast::<u32>(),
            OUTPUT_BYTES as u32,
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
