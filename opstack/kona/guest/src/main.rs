//! RV64IM OP execution or anchored transition. Panics trap without publishing success.
#![no_std]
#![no_main]
extern crate alloc;
#[cfg(any(
    all(feature = "pairing-packet-probe", any(feature = "blob-eval-probe", feature = "transition-program", feature = "brotli-probe")),
    all(feature = "brotli-probe", any(feature = "transition-program", feature = "blob-eval-probe")),
    all(feature = "blob-eval-probe", feature = "transition-program")
))]
compile_error!("diagnostic and transition guest modes are mutually exclusive");
#[rustfmt::skip]
#[path = "../../../../autoresearch/benchmarks/guest_runtime/exact_layout_allocator_v2.rs"]
mod allocator;
#[rustfmt::skip]
#[path = "../../../../autoresearch/benchmarks/guest_runtime/ethereum/rv64/src/single_thread_atomics.rs"]
mod single_thread_atomics;
extern crate stwo_rv64_mem;
#[cfg(feature = "allocator-check")]
mod allocator_checks;
#[cfg(all(feature = "keccak-service", not(feature = "sponge-service")))]
#[rustfmt::skip]
#[path = "../../../../autoresearch/benchmarks/guest_runtime/ethereum/rv64/src/keccak_service.rs"]
mod keccak_service;
#[cfg(feature = "sponge-service")]
mod sponge_service;
use core::{
    arch::{asm, global_asm},
    ptr,
};
#[cfg(not(any(
    feature = "transition-program",
    feature = "blob-eval-probe",
    feature = "pairing-packet-probe",
    feature = "brotli-probe"
)))]
use stwo_kona_execution::{
    execution::execute,
    witness::{Validation, Witness},
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
    }
    #[cfg(feature = "allocator-check")]
    allocator_checks::check();
    let input = unsafe {
        let start = ptr::addr_of!(__input_start);
        let len = ptr::read_volatile(start.cast::<u32>()) as usize;
        assert!(len <= ptr::addr_of!(__input_end) as usize - start as usize - 4);
        core::slice::from_raw_parts(start.add(4), len)
    };
    #[cfg(not(any(
        feature = "transition-program",
        feature = "blob-eval-probe",
        feature = "pairing-packet-probe",
        feature = "brotli-probe"
    )))]
    let mode = if cfg!(feature = "eager-preimages") {
        Validation::Eager
    } else {
        Validation::Lazy
    };
    #[cfg(all(feature = "precompile-services", not(feature = "pairing-hints")))]
    assert!(stwo_kona_execution::precompiles::install());
    #[cfg(all(feature = "pairing-hints", not(feature = "pairing-packet-probe")))]
    let input = stwo_kona_execution::precompiles::install_hinted(input)
        .expect("invalid pairing hint stream");
    #[cfg(not(any(
        feature = "transition-program",
        feature = "blob-eval-probe",
        feature = "pairing-packet-probe",
        feature = "brotli-probe"
    )))]
    let output = execute(&Witness::parse(input, mode).expect("invalid OP witness"))
        .expect("OP execution rejected")
        .public_output();
    #[cfg(feature = "pairing-packet-probe")]
    let output = {
        assert_eq!(input, b"PKT1");
        stwo_kona_execution::precompiles::pairing_packet_probe()
    };
    #[cfg(feature = "brotli-probe")]
    let output =
        stwo_kona_execution::brotli_probe::execute(input).expect("Brotli diagnostic rejected");
    #[cfg(feature = "blob-eval-probe")]
    let output = stwo_kona_execution::anchored_blobs::evaluation_probe(input)
        .expect("blob evaluation diagnostic rejected");
    #[cfg(feature = "transition-program")]
    let output = stwo_kona_execution::transition_input::TransitionInput::parse(input)
        .expect("invalid OP transition witness")
        .verify()
        .expect("OP anchored transition rejected")
        .statement
        .public_output();
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
