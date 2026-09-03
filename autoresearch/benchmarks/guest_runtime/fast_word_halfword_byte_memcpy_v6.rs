//! Ordinary-RV32 word/halfword/byte-unrolled memcpy candidate v6.
//!
//! This extends the v3 word path with an aligned halfword path for source and
//! destination addresses that agree modulo two but not modulo four. Its final
//! byte path is unrolled eight-way so arbitrary alignments do not pay one
//! branch and two pointer updates per byte. The implementation uses only
//! ordinary RV32IM loads/stores and remains directly compatible with the
//! existing execution proof.

use core::ptr;

#[inline(always)]
unsafe fn copy_byte(destination: *mut u8, source: *const u8) {
    let value = unsafe { ptr::read_volatile(source) };
    unsafe { ptr::write_volatile(destination, value) };
}

#[inline(always)]
unsafe fn copy_halfword(destination: *mut u16, source: *const u16) {
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
    let relative_alignment = ((destination as usize) ^ (source as usize)) & 3;

    if relative_alignment == 0 {
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
    } else if relative_alignment == 2 {
        if remaining != 0 && (destination as usize) & 1 != 0 {
            unsafe { copy_byte(destination, source) };
            destination = unsafe { destination.add(1) };
            source = unsafe { source.add(1) };
            remaining -= 1;
        }
        let mut destination_halves = destination.cast::<u16>();
        let mut source_halves = source.cast::<u16>();
        while remaining >= 16 {
            let values = unsafe {
                [
                    ptr::read_volatile(source_halves),
                    ptr::read_volatile(source_halves.add(1)),
                    ptr::read_volatile(source_halves.add(2)),
                    ptr::read_volatile(source_halves.add(3)),
                    ptr::read_volatile(source_halves.add(4)),
                    ptr::read_volatile(source_halves.add(5)),
                    ptr::read_volatile(source_halves.add(6)),
                    ptr::read_volatile(source_halves.add(7)),
                ]
            };
            unsafe {
                ptr::write_volatile(destination_halves, values[0]);
                ptr::write_volatile(destination_halves.add(1), values[1]);
                ptr::write_volatile(destination_halves.add(2), values[2]);
                ptr::write_volatile(destination_halves.add(3), values[3]);
                ptr::write_volatile(destination_halves.add(4), values[4]);
                ptr::write_volatile(destination_halves.add(5), values[5]);
                ptr::write_volatile(destination_halves.add(6), values[6]);
                ptr::write_volatile(destination_halves.add(7), values[7]);
                source_halves = source_halves.add(8);
                destination_halves = destination_halves.add(8);
            }
            remaining -= 16;
        }
        while remaining >= 2 {
            unsafe { copy_halfword(destination_halves, source_halves) };
            destination_halves = unsafe { destination_halves.add(1) };
            source_halves = unsafe { source_halves.add(1) };
            remaining -= 2;
        }
        destination = destination_halves.cast::<u8>();
        source = source_halves.cast::<u8>();
    }

    while remaining >= 16 {
        let first = unsafe {
            [
                ptr::read_volatile(source),
                ptr::read_volatile(source.add(1)),
                ptr::read_volatile(source.add(2)),
                ptr::read_volatile(source.add(3)),
                ptr::read_volatile(source.add(4)),
                ptr::read_volatile(source.add(5)),
                ptr::read_volatile(source.add(6)),
                ptr::read_volatile(source.add(7)),
            ]
        };
        unsafe {
            ptr::write_volatile(destination, first[0]);
            ptr::write_volatile(destination.add(1), first[1]);
            ptr::write_volatile(destination.add(2), first[2]);
            ptr::write_volatile(destination.add(3), first[3]);
            ptr::write_volatile(destination.add(4), first[4]);
            ptr::write_volatile(destination.add(5), first[5]);
            ptr::write_volatile(destination.add(6), first[6]);
            ptr::write_volatile(destination.add(7), first[7]);
        }
        let second = unsafe {
            [
                ptr::read_volatile(source.add(8)),
                ptr::read_volatile(source.add(9)),
                ptr::read_volatile(source.add(10)),
                ptr::read_volatile(source.add(11)),
                ptr::read_volatile(source.add(12)),
                ptr::read_volatile(source.add(13)),
                ptr::read_volatile(source.add(14)),
                ptr::read_volatile(source.add(15)),
            ]
        };
        unsafe {
            ptr::write_volatile(destination.add(8), second[0]);
            ptr::write_volatile(destination.add(9), second[1]);
            ptr::write_volatile(destination.add(10), second[2]);
            ptr::write_volatile(destination.add(11), second[3]);
            ptr::write_volatile(destination.add(12), second[4]);
            ptr::write_volatile(destination.add(13), second[5]);
            ptr::write_volatile(destination.add(14), second[6]);
            ptr::write_volatile(destination.add(15), second[7]);
            destination = destination.add(16);
            source = source.add(16);
        }
        remaining -= 16;
    }
    while remaining >= 8 {
        let values = unsafe {
            [
                ptr::read_volatile(source),
                ptr::read_volatile(source.add(1)),
                ptr::read_volatile(source.add(2)),
                ptr::read_volatile(source.add(3)),
                ptr::read_volatile(source.add(4)),
                ptr::read_volatile(source.add(5)),
                ptr::read_volatile(source.add(6)),
                ptr::read_volatile(source.add(7)),
            ]
        };
        unsafe {
            ptr::write_volatile(destination, values[0]);
            ptr::write_volatile(destination.add(1), values[1]);
            ptr::write_volatile(destination.add(2), values[2]);
            ptr::write_volatile(destination.add(3), values[3]);
            ptr::write_volatile(destination.add(4), values[4]);
            ptr::write_volatile(destination.add(5), values[5]);
            ptr::write_volatile(destination.add(6), values[6]);
            ptr::write_volatile(destination.add(7), values[7]);
            destination = destination.add(8);
            source = source.add(8);
        }
        remaining -= 8;
    }
    while remaining != 0 {
        unsafe { copy_byte(destination, source) };
        destination = unsafe { destination.add(1) };
        source = unsafe { source.add(1) };
        remaining -= 1;
    }
    result
}
