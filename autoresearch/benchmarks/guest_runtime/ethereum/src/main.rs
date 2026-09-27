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
#[path = "../../fast_memory_v1.rs"]
mod fast_memory;
#[cfg(feature = "sha256-precompile")]
#[path = "../../sha256_precompile_v1.rs"]
mod sha256;
mod evm_recovery;
mod evm_hints;

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

#[path = "../../ethereum_admission_v1.rs"]
mod admission;

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

fn proved_recover(sig: &[u8; 64], recid: u8, msg: &[u8; 32]) -> [u8; 64] {
        let mut record = RecoveryRecord {
            digest: *msg,
            r: sig[..32].try_into().unwrap(),
            s: sig[32..64].try_into().unwrap(),
            recovery_id: u32::from(recid),
            public_key_xy: [0; 64],
            status: 0,
        };
        unsafe {
            asm!(".word 0x0602800b", in("t0") &mut record, options(nostack));
        }
        assert_eq!(record.status, 1, "native recovery rejection is fatal");
        record.public_key_xy
}

#[derive(Debug)]
struct NativeEvmCrypto;
impl revm_precompile::interface::Crypto for NativeEvmCrypto {
    #[cfg(feature = "sha256-precompile")]
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        sha256::hash(input)
    }
    fn secp256k1_ecrecover(&self, sig: &[u8; 64], recid: u8, msg: &[u8; 32]) -> Result<[u8; 32], revm_precompile::interface::PrecompileHalt> {
        #[cfg(feature = "collect-evm-hints")]
        {
            use revm_precompile::interface::{Crypto, DefaultCrypto};
            let result = DefaultCrypto.secp256k1_ecrecover(sig, recid, msg);
            evm_hints::observe(result.is_ok() && recid <= 1);
            result
        }
        #[cfg(not(feature = "collect-evm-hints"))]
        evm_recovery::recover(sig, recid, msg, evm_hints::next(), proved_recover)
    }
}

struct NativeTransactionRecovery;
impl CryptoProvider for NativeTransactionRecovery {
    fn recover_signer_unchecked(
        &self,
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        assert!(sig[64] <= 1, "native recovery requires a parity bit");
        Ok(Address::from_raw_public_key(&proved_recover(sig[..64].try_into().unwrap(), sig[64], msg)))
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
    let (input, footer) = unsafe {
        let begin = ptr::addr_of!(__input_start);
        let length = ptr::read_volatile(begin.cast::<u32>()) as usize;
        assert!(length <= ptr::addr_of!(__input_end) as usize - begin as usize - 4);
        let remaining = ptr::addr_of!(__input_end) as usize - begin as usize - 4 - length;
        (core::slice::from_raw_parts(begin.add(4), length), core::slice::from_raw_parts(begin.add(4 + length), remaining))
    };
    evm_hints::initialize(footer);
    assert!(revm_precompile::interface::install_crypto(NativeEvmCrypto));
    let output = stateless_validator_reth::guest::run_stateless_guest(input);
    assert!(
        output.len() == 43 && output[32] == 1,
        "block validation failed"
    );
    let output = evm_hints::finish(output);
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
