//! The admitted evmone JUMPDEST service reused by Revm. Padded code has its
//! own 64-aligned owner with exact-layout destruction; no Vec is constructed
//! from a differently aligned allocation. Original code length remains in
//! Bytecode, while the analyzed buffer has 33 trailing zero bytes for all
//! PUSH32/STOP and DUPN/SWAPN/EXCHANGE immediate reads.
use super::JumpTable;
use core::{alloc::Layout, ptr::NonNull};
use primitives::Bytes;
use std::{
    alloc::{alloc, dealloc, handle_alloc_error},
    vec::Vec,
};

struct Code {
    pointer: NonNull<u8>,
    layout: Layout,
}
// SAFETY: construction is exclusive. After publishing through Bytes this
// owner is immutable, and its exact allocation remains alive until Drop.
unsafe impl Send for Code {}
impl AsRef<[u8]> for Code {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: the entire allocation was initialized before publication.
        unsafe { core::slice::from_raw_parts(self.pointer.as_ptr(), self.layout.size()) }
    }
}
impl Drop for Code {
    fn drop(&mut self) {
        // SAFETY: unique owner; same layout used at allocation, no references
        // remain after Bytes releases its final owner.
        unsafe {
            dealloc(self.pointer.as_ptr(), self.layout);
        }
    }
}

pub(super) fn analyze(input: Bytes) -> (JumpTable, Bytes) {
    assert!((256..=1 << 20).contains(&input.len()));
    let rounded = (input.len() + 7) & !7;
    let layout = Layout::from_size_align(input.len() + 33, 64).unwrap();
    // SAFETY: nonzero bounded layout. Both initialized ranges fit exactly,
    // are disjoint from input, and together cover the full owner allocation.
    let pointer = unsafe {
        let p = NonNull::new(alloc(layout)).unwrap_or_else(|| handle_alloc_error(layout));
        core::ptr::copy_nonoverlapping(input.as_ptr(), p.as_ptr(), input.len());
        core::ptr::write_bytes(p.as_ptr().add(input.len()), 0, 33);
        p
    };
    let code = Code { pointer, layout };
    let mut bitmap = std::vec![0u64;rounded.div_ceil(64)];
    // SAFETY: live disjoint packet/code/bitmap; 64-aligned code, word-aligned
    // output, nonzero word-multiple length <=1MiB. Padding covers rounded.
    unsafe {
        scan(code.pointer.as_ptr(), rounded, bitmap.as_mut_ptr());
    }
    let mut bytes = Vec::with_capacity(bitmap.len() * 8);
    for word in bitmap {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.truncate(input.len().div_ceil(8));
    let jumps = JumpTable::from_vec(bytes, input.len());
    (jumps, Bytes(bytes::Bytes::from_owner(code)))
}

#[cfg(target_arch = "riscv64")]
unsafe fn scan(code: *const u8, len: usize, bitmap: *mut u64) {
    let mut packet = [code as u64, len as u64, bitmap as u64];
    // SAFETY: caller establishes the complete admitted service contract.
    unsafe {
        core::arch::asm!("ecall",in("a0") packet.as_mut_ptr(),in("a7") 0x0003_0040usize,options(nostack));
    }
}
#[cfg(all(test, not(target_arch = "riscv64")))]
unsafe fn scan(code: *const u8, len: usize, bitmap: *mut u64) {
    assert_eq!(code as usize % 64, 0);
    assert_eq!(bitmap as usize % 8, 0);
    assert!(len != 0 && len % 8 == 0 && len <= 1 << 20);
    // Emulate the byte scan only; the production proof uses the existing AIR.
    let input = unsafe { core::slice::from_raw_parts(code, len) };
    let out = unsafe { core::slice::from_raw_parts_mut(bitmap, len.div_ceil(64)) };
    let mut pc = 0;
    while pc < len {
        let op = input[pc];
        if op == 0x5b {
            out[pc / 64] |= 1 << (pc % 64);
        }
        pc += if (0x60..=0x7f).contains(&op) {
            usize::from(op - 0x5f) + 1
        } else {
            1
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admitted_scan_matches_original_revm_with_safe_owned_padding() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        for len in [256, 257, 263, 264, 511, 512, 513, 4096, 24576] {
            let mut code = std::vec![0;len];
            for b in &mut code {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
            for tail in [0, 0x5b, 0x60, 0x7f, 0xe6, 0xe7, 0xe8] {
                code[len - 1] = tail;
                let input = Bytes::from(code.clone());
                let (expected, original) = super::super::analysis::analyze_legacy(input.clone());
                let (actual, padded) = analyze(input);
                assert_eq!(actual, expected);
                assert_eq!(&padded[..len], &code);
                assert!(padded[len..].iter().all(|b| *b == 0));
                assert!(padded.len() >= original.len());
                assert_eq!(padded.as_ptr() as usize % 64, 0);
            }
        }
    }
}
