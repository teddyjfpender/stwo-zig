//! Ordinary-RV32 optimized memcpy candidate.
//!
//! This function deliberately uses only existing RV32IM loads/stores. Linker
//! `--wrap=memcpy` redirects compiler-builtins calls here for the diagnostic
//! guest; no custom opcode or proof-system change is required.

use core::ptr;

#[inline(always)]
unsafe fn copy_byte(destination: *mut u8, source: *const u8) {
    let value = unsafe { ptr::read_volatile(source) };
    unsafe { ptr::write_volatile(destination, value) };
}

#[inline(always)]
unsafe fn copy_word(destination: *mut u32, source: *const u32) {
    let value = unsafe { ptr::read_volatile(source) };
    unsafe { ptr::write_volatile(destination, value) };
}

/// C-compatible memcpy replacement used through the linker's `--wrap` seam.
///
/// # Safety
///
/// Source and destination must be valid for `length` bytes and non-overlapping.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn __wrap_memcpy(
    destination: *mut u8,
    source: *const u8,
    length: usize,
) -> *mut u8 {
    let result = destination;
    let mut destination = destination;
    let mut source = source;
    let mut remaining = length;

    if ((destination as usize) ^ (source as usize)) & 3 == 0 {
        while remaining != 0 && (destination as usize) & 3 != 0 {
            unsafe { copy_byte(destination, source) };
            destination = unsafe { destination.add(1) };
            source = unsafe { source.add(1) };
            remaining -= 1;
        }

        let mut destination_words = destination.cast::<u32>();
        let mut source_words = source.cast::<u32>();
        while remaining >= 32 {
            let values = unsafe {
                [
                    ptr::read_volatile(source_words),
                    ptr::read_volatile(source_words.add(1)),
                    ptr::read_volatile(source_words.add(2)),
                    ptr::read_volatile(source_words.add(3)),
                    ptr::read_volatile(source_words.add(4)),
                    ptr::read_volatile(source_words.add(5)),
                    ptr::read_volatile(source_words.add(6)),
                    ptr::read_volatile(source_words.add(7)),
                ]
            };
            unsafe {
                ptr::write_volatile(destination_words, values[0]);
                ptr::write_volatile(destination_words.add(1), values[1]);
                ptr::write_volatile(destination_words.add(2), values[2]);
                ptr::write_volatile(destination_words.add(3), values[3]);
                ptr::write_volatile(destination_words.add(4), values[4]);
                ptr::write_volatile(destination_words.add(5), values[5]);
                ptr::write_volatile(destination_words.add(6), values[6]);
                ptr::write_volatile(destination_words.add(7), values[7]);
                source_words = source_words.add(8);
                destination_words = destination_words.add(8);
            }
            remaining -= 32;
        }
        while remaining >= 4 {
            unsafe { copy_word(destination_words, source_words) };
            destination_words = unsafe { destination_words.add(1) };
            source_words = unsafe { source_words.add(1) };
            remaining -= 4;
        }
        destination = destination_words.cast::<u8>();
        source = source_words.cast::<u8>();
    }

    while remaining != 0 {
        unsafe { copy_byte(destination, source) };
        destination = unsafe { destination.add(1) };
        source = unsafe { source.add(1) };
        remaining -= 1;
    }
    result
}
