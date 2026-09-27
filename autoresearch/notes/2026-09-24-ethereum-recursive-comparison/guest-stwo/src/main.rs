#![no_std]
#![no_main]
use core::{
    arch::{asm, global_asm},
    panic::PanicInfo,
    ptr,
};
use eth_auth_common::Crypto;
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

struct Native;
#[repr(C, align(8))]
struct State([u8; 200]);
#[repr(C, align(4))]
struct Record([u8; 168]);
impl Crypto for Native {
    fn keccak(data: &[u8]) -> [u8; 32] {
        let mut state = State([0; 200]);
        let mut rest = data;
        while rest.len() >= 136 {
            for i in 0..136 {
                state.0[i] ^= rest[i];
            }
            unsafe {
                asm!(".word 0x0405000b",in("a0") state.0.as_mut_ptr(),options(nostack));
            }
            rest = &rest[136..];
        }
        for i in 0..rest.len() {
            state.0[i] ^= rest[i];
        }
        state.0[rest.len()] ^= 1;
        state.0[135] ^= 128;
        unsafe {
            asm!(".word 0x0405000b",in("a0") state.0.as_mut_ptr(),options(nostack));
        }
        state.0[..32].try_into().unwrap()
    }
    fn recover(d: &[u8; 32], r: &[u8; 32], s: &[u8; 32], p: u8) -> Option<[u8; 64]> {
        let mut x = Record([0; 168]);
        x.0[..32].copy_from_slice(d);
        x.0[32..64].copy_from_slice(r);
        x.0[64..96].copy_from_slice(s);
        x.0[96] = p;
        unsafe {
            asm!(".word 0x0605000b",in("a0") x.0.as_mut_ptr(),options(nostack));
        }
        if x.0[164..] != [1, 0, 0, 0] {
            return None;
        }
        Some(x.0[100..164].try_into().unwrap())
    }
}
#[no_mangle]
pub extern "C" fn __zkvm_start() -> ! {
    let mut input = [0u8; 4096];
    // Outer transport length is authenticated input too; common statement binds payload.
    let mut len = [0; 4];
    for i in 0..4 {
        len[i] = unsafe { ptr::read_volatile(ptr::addr_of!(__input_start).add(i)) };
    }
    let len = u32::from_le_bytes(len) as usize;
    let out = if len <= 4092 {
        for i in 0..len {
            input[i] = unsafe { ptr::read_volatile(ptr::addr_of!(__input_start).add(i + 4)) };
        }
        eth_auth_common::run::<Native>(&input[..len]).unwrap_or([0; 72])
    } else {
        [0; 72]
    };
    unsafe {
        for i in 0..72 {
            ptr::write_volatile((ptr::addr_of!(__output_data) as *mut u8).add(i), out[i]);
        }
        ptr::write_volatile(ptr::addr_of!(__output_len) as *mut u32, 72);
        ptr::write_volatile(ptr::addr_of!(__halt_flag) as *mut u32, 1);
    }
    loop {}
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
