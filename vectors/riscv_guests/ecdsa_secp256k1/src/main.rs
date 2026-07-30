//! Pure-software secp256k1 ECDSA verification guest for the EthProofs CSP row.
//!
//! Input:
//! `[digest: 32 bytes][uncompressed SEC1 key: 65 bytes][r || s: 64 bytes]`.
//! All components are the exact deterministic values returned by the pinned
//! CSP `generate_ecdsa_k256_input` function. A valid signature returns the
//! 32-byte digest; malformed or invalid input returns 32 zero bytes.

#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr;
use k256::{
    EncodedPoint,
    ecdsa::{
        Signature, VerifyingKey,
        signature::hazmat::PrehashVerifier,
    },
};

const DIGEST_LEN: usize = 32;
const KEY_LEN: usize = 65;
const SIGNATURE_LEN: usize = 64;

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

fn verify(digest: &[u8; DIGEST_LEN]) -> bool {
    let key_bytes = unsafe { read_input::<KEY_LEN>(DIGEST_LEN) };
    let signature_bytes =
        unsafe { read_input::<SIGNATURE_LEN>(DIGEST_LEN + KEY_LEN) };

    let encoded = match EncodedPoint::from_bytes(key_bytes) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let key = match VerifyingKey::from_encoded_point(&encoded) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(value) => value,
        Err(_) => return false,
    };
    key.verify_prehash(digest, &signature).is_ok()
}

#[unsafe(no_mangle)]
pub extern "C" fn __zkvm_start() -> ! {
    let digest = unsafe { read_input::<DIGEST_LEN>(0) };
    let output = if verify(&digest) {
        digest
    } else {
        [0u8; DIGEST_LEN]
    };
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
