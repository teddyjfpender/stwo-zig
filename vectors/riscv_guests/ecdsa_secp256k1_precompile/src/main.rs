//! Successful ECDSA verification via the canonical typed signer-recovery ABI.
//!
//! Same digest[32] || SEC1 key[65] || r[32] || s[32] input as CSP. This
//! program publishes a result only after recovery matches the supplied key.
//! The verifier admits either parity-specific ELF; unsupported/rejected inputs
//! use the ordinary software verifier guest. No host verdict is proof authority.
#![no_std]
#![no_main]
use core::{
    arch::{asm, global_asm},
    panic::PanicInfo,
    ptr,
};

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
    .section .note.stwo.zkvm,"",@note
    .balign 4
    .long 5, 56, 1
    .asciz "STWO"
    .balign 4
    .ascii "STWZKVM\0"
    .short 1, 3
    .quad 6
    .short 1, 0
    .byte 0xfb,0xe8,0x83,0x3d,0xe3,0x5b,0x29,0xab
    .byte 0x15,0x5a,0xfe,0xd5,0x8f,0x59,0x3d,0x44
    .byte 0xd2,0xa7,0x25,0x7a,0xd4,0x49,0x1d,0x95
    .byte 0x37,0x42,0xd3,0x94,0xda,0x66,0xcf,0xc2
"#
);

#[repr(C, align(4))]
struct RecoveryRecord([u8; 168]);

// k256's PrehashVerifier rejects high-S signatures. Keep exactly that policy.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

fn stop() -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn __zkvm_start() -> ! {
    let mut input = [0u8; 161];
    for (i, byte) in input.iter_mut().enumerate() {
        *byte = unsafe { ptr::read_volatile(ptr::addr_of!(__input_start).add(i)) };
    }
    if input[32] != 4 || input[129..161] > HALF_ORDER[..] {
        stop();
    }
    let mut record = RecoveryRecord([0u8; 168]);
    record.0[..32].copy_from_slice(&input[..32]);
    record.0[32..64].copy_from_slice(&input[97..129]);
    record.0[64..96].copy_from_slice(&input[129..161]);
    record.0[96] = u8::from(cfg!(feature = "recovery-odd"));
    unsafe {
        asm!(".word 0x0605000b", in("a0") record.0.as_mut_ptr(), options(nostack));
    }
    if record.0[164..168] != [1, 0, 0, 0] || record.0[100..164] != input[33..97] {
        stop();
    }
    unsafe {
        for (i, byte) in input[..32].iter().enumerate() {
            ptr::write_volatile((ptr::addr_of!(__output_data) as *mut u8).add(i), *byte);
        }
        ptr::write_volatile(ptr::addr_of!(__output_len) as *mut u32, 32);
        ptr::write_volatile(ptr::addr_of!(__halt_flag) as *mut u32, 1);
    }
    stop()
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    stop()
}
