//! Keccak-256 through the existing constrained v3 sponge ABI, no new service.
//! Output is written only after all input has been consumed, permitting aliases.
use core::ptr;
const RATE: usize = 136;
const CHUNK: usize = 7710 * RATE; // Largest whole-block chunk below 2^20.

/// Caller provides valid input/output ranges. Each callback must implement the
/// admitted {state,input,len,flags} service, preserving all other guest memory.
pub unsafe fn hash_with(
    input: *const u8,
    length: usize,
    output: *mut u8,
    mut call: impl FnMut(*mut u64, *const u8, usize, u64),
) {
    assert!(!output.is_null() && (length == 0 || !input.is_null()));
    #[repr(align(32))]
    struct State([u64; 25]);
    let mut state = State([0; 25]);
    let mut remaining = length;
    let mut consumed = 0;
    let mut flags = 2; // Fresh, then continued state for later chunks.
    while remaining > CHUNK {
        call(
            state.0.as_mut_ptr(),
            unsafe { input.add(consumed) },
            CHUNK,
            flags,
        );
        consumed += CHUNK;
        remaining -= CHUNK;
        flags = 0;
    }
    // Do not offset a null pointer, even by zero (empty input is permitted).
    let tail = if consumed == 0 {
        input
    } else {
        unsafe { input.add(consumed) }
    };
    call(state.0.as_mut_ptr(), tail, remaining, flags | 1);
    for i in 0..4 {
        let bytes = state.0[i].to_le_bytes();
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), output.add(i * 8), 8);
        }
    }
}

#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_keccak256(input: *const u8, length: usize, output: *mut u8) {
    unsafe {
        hash_with(input, length, output, |state, input, length, flags| {
            let packet = [state as u64, input as u64, length as u64, flags];
            core::arch::asm!("ecall", in("a0") packet.as_ptr(), in("a7") 0x0003_0130u64, options(nostack));
        });
    }
}
