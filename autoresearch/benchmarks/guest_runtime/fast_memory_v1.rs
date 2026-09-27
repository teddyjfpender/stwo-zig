//! Shared RV32 memcpy using bounded aligned loads/stores and exact byte tails.
//! Ordinary guest instructions: no unproved host memory operation or overread.
use core::ptr;

/// # Safety
/// Both ranges must be valid for `length` bytes and must not overlap, as for memcpy.
#[inline(never)]
pub unsafe fn copy_bytes(destination: *mut u8, source: *const u8, length: usize) -> *mut u8 {
    let mut dst = destination;
    let mut src = source;
    let mut remaining = length;
    unsafe {
        if (dst as usize ^ src as usize) & 3 == 0 {
            while remaining != 0 && dst as usize & 3 != 0 {
                ptr::write_volatile(dst, ptr::read_volatile(src));
                dst = dst.add(1); src = src.add(1); remaining -= 1;
            }
            while remaining >= 16 {
                let a = ptr::read_volatile(src.cast::<u32>());
                let b = ptr::read_volatile(src.add(4).cast::<u32>());
                let c = ptr::read_volatile(src.add(8).cast::<u32>());
                let d = ptr::read_volatile(src.add(12).cast::<u32>());
                ptr::write_volatile(dst.cast::<u32>(), a);
                ptr::write_volatile(dst.add(4).cast::<u32>(), b);
                ptr::write_volatile(dst.add(8).cast::<u32>(), c);
                ptr::write_volatile(dst.add(12).cast::<u32>(), d);
                dst = dst.add(16); src = src.add(16); remaining -= 16;
            }
            while remaining >= 4 {
                ptr::write_volatile(dst.cast::<u32>(), ptr::read_volatile(src.cast::<u32>()));
                dst = dst.add(4); src = src.add(4); remaining -= 4;
            }
        }
        while remaining != 0 {
            ptr::write_volatile(dst, ptr::read_volatile(src));
            dst = dst.add(1); src = src.add(1); remaining -= 1;
        }
    }
    destination
}

// Volatile accesses prevent LLVM from replacing the implementation with a
// recursive memcpy intrinsic. The builtins weak symbol is replaced at link time.
#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(
    dst: *mut core::ffi::c_void,
    src: *const core::ffi::c_void,
    length: usize,
) -> *mut core::ffi::c_void {
    unsafe { copy_bytes(dst.cast(), src.cast(), length).cast() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_alignments_lengths_and_sentinels() {
        let source: [u8; 160] = core::array::from_fn(|i| (i as u8).wrapping_mul(73));
        for from in 0..4 {
            for to in 0..4 {
                for length in 0..=128 {
                    let mut actual = [0xa5; 160];
                    let mut expected = actual;
                    expected[to..to + length].copy_from_slice(&source[from..from + length]);
                    let pointer = unsafe { actual.as_mut_ptr().add(to) };
                    assert_eq!(unsafe { copy_bytes(pointer, source.as_ptr().add(from), length) }, pointer);
                    assert_eq!(actual, expected);
                }
            }
        }
        assert!(unsafe { copy_bytes(ptr::null_mut(), ptr::null(), 0) }.is_null());
    }
}
