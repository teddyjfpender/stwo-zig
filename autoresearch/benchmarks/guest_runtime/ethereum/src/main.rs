//! Combined RV32 Ethereum guest over the unmodified pinned validator.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloy_consensus::crypto::{CryptoProvider, RecoveryError, install_default_provider};
use alloy_primitives::Address;
use core::{
    arch::{asm, global_asm},
    ptr,
};
use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};

#[path = "../../exact_layout_allocator_v2.rs"]
mod allocator;
#[path = "../../fast_keccak_sponge_words_v1.rs"]
mod keccak;
mod single_thread_atomics;

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

// The target lowers atomics for a single-thread guest. No interrupts or host
// threads execute in this address space.
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

    .section .note.stwo.zkvm,"",@note
    .balign 4
    .long 5
    .long 56
    .long 1
    .ascii "STWO\0"
    .balign 4
    .ascii "STWZKVM\0"
    .short 1
    .short 3
    .quad 6
    .short 1
    .short 0
    .byte 0xfb,0xe8,0x83,0x3d,0xe3,0x5b,0x29,0xab
    .byte 0x15,0x5a,0xfe,0xd5,0x8f,0x59,0x3d,0x44
    .byte 0xd2,0xa7,0x25,0x7a,0xd4,0x49,0x1d,0x95
    .byte 0x37,0x42,0xd3,0x94,0xda,0x66,0xcf,0xc2
    .balign 4
"#
);

unsafe fn stwo_keccakf(state: *mut u64) {
    unsafe {
        asm!(".word 0x0402800b", in("t0") state, options(nostack));
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn native_keccak256(input: *const u8, length: usize, output: *mut u8) {
    assert!(!output.is_null() && (length == 0 || !input.is_null()));
    unsafe {
        keccak::hash(input, length, output);
    }
}

#[repr(C, align(4))]
struct RecoveryRecord {
    digest: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    recovery_id: u32,
    public_key_xy: [u8; 64],
    status: u32,
}
const _: () = assert!(core::mem::size_of::<RecoveryRecord>() == 168);
const _: () = assert!(core::mem::offset_of!(RecoveryRecord, public_key_xy) == 100);
const _: () = assert!(core::mem::offset_of!(RecoveryRecord, status) == 164);

struct NativeTransactionRecovery;
impl CryptoProvider for NativeTransactionRecovery {
    fn recover_signer_unchecked(
        &self,
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        assert!(sig[64] <= 1, "native recovery requires a parity bit");
        let mut record = RecoveryRecord {
            digest: *msg,
            r: sig[..32].try_into().unwrap(),
            s: sig[32..64].try_into().unwrap(),
            recovery_id: u32::from(sig[64]),
            public_key_xy: [0; 64],
            status: 0,
        };
        unsafe {
            asm!(".word 0x0602800b", in("t0") &mut record, options(nostack));
        }
        assert_eq!(record.status, 1, "native recovery rejection is fatal");
        Ok(Address::from_raw_public_key(&record.public_key_xy))
    }

    fn verify_and_compute_signer_unchecked(
        &self,
        public_key: &[u8; 65],
        sig: &[u8; 64],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        // Successful-only recovery cannot certify invalid-result semantics.
        // Keep this interface on the same software verification as Alloy.
        let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| RecoveryError::new())?;
        let signature = Signature::from_slice(sig).map_err(|_| RecoveryError::new())?;
        let signature = signature.normalize_s().unwrap_or(signature);
        key.verify_prehash(msg, &signature)
            .map_err(|_| RecoveryError::new())?;
        Ok(Address::from_raw_public_key(
            &key.to_encoded_point(false).as_bytes()[1..],
        ))
    }
}

#[unsafe(no_mangle)]
extern "C" fn guest_main() -> ! {
    unsafe {
        let heap_start = ptr::addr_of!(__heap_start) as usize;
        HEAP.initialize(
            heap_start as *mut u8,
            ptr::addr_of!(__heap_end) as usize - heap_start,
        );
    }
    install_default_provider(Arc::new(NativeTransactionRecovery)).unwrap();
    // Revm's Crypto provider stays on its software default.
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
    // An illegal instruction gives the runner a failing retirement, never a
    // successful halt or a software retry of a rejected native operation.
    unsafe {
        asm!("unimp", options(noreturn));
    }
}
