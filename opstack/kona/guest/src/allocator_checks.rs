//! Executed through the real Rust allocator ABI (including allocsize attributes)
//! in an explicitly selected regression guest, before normal OP execution.
use alloc::alloc::{alloc, dealloc};
use core::{alloc::Layout, ptr};

pub fn check() {
    for size in [1, 2, 4, 8, 16, 23, 24] {
        for alignment in [1, 2, 4, 8, 16, 32, 64] {
            let logical = Layout::from_size_align(size, alignment).unwrap();
            let physical = Layout::from_size_align(size.max(24), alignment.max(8)).unwrap();
            // SAFETY: nonzero matching layouts. Observe a live byte through a
            // volatile access so LLVM cannot erase the allocation experiment.
            let old_address = unsafe {
                let p = alloc(logical);
                assert!(!p.is_null());
                ptr::write_volatile(p, 0xa5);
                assert_eq!(ptr::read_volatile(p), 0xa5);
                let address = p.addr();
                dealloc(p, logical);
                address
            };
            // Exact normalized classes must recycle the just-published node.
            // No freed pointer is dereferenced by this test.
            unsafe {
                let p = alloc(physical);
                assert_eq!(p.addr(), old_address);
                ptr::write_volatile(p, 0x5a);
                assert_eq!(ptr::read_volatile(p), 0x5a);
                dealloc(p, physical);
            }
        }
    }
}
