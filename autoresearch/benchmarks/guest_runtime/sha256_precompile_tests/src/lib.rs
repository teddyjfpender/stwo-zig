#![cfg_attr(target_arch = "riscv32", no_std)]

#[path = "../../sha256_precompile_v1.rs"]
pub mod guest;

/// Native ABI compilation gate, not an executable profile admission.
///
/// # Safety
/// Nonempty input must be readable for `length` bytes; output must be writable
/// for 32 bytes. The executable must admit the SHA compression capability.
#[cfg(all(stwo_sha256_precompile_v1, target_arch = "riscv32"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_sha256_guest_hash(input: *const u8, length: usize, output: *mut u8) {
    let bytes = if length == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(input, length) }
    };
    let digest = guest::hash(bytes);
    unsafe {
        core::ptr::copy_nonoverlapping(digest.as_ptr(), output, digest.len());
    }
}

#[cfg(test)]
mod tests {
    use super::guest;
    use sha2::{Digest, Sha256};

    fn check(input: &[u8]) {
        let mut calls = 0;
        let actual = guest::hash_with(input, |state, block| {
            assert_eq!(state.as_ptr() as usize & 3, 0);
            assert_eq!(block.as_ptr() as usize & 3, 0);
            let state_start = state.as_ptr() as usize;
            let block_start = block.as_ptr() as usize;
            assert!(state_start + 32 <= block_start || block_start + 64 <= state_start);
            if calls < input.len() / 64 && input.as_ptr() as usize & 3 == 0 {
                assert_eq!(block.as_ptr(), input[calls * 64..].as_ptr());
            }
            sha2::compress256(state, &[(*block).into()]);
            calls += 1;
        });
        let expected: [u8; 32] = Sha256::digest(input).into();
        assert_eq!(actual, expected);
        assert_eq!(calls, (input.len() + 9).div_ceil(64));
    }

    #[test]
    fn all_padding_and_alignment_boundaries() {
        let bytes: Vec<u8> = (0..8192 + 8).map(|i| (i * 71 + 9) as u8).collect();
        for offset in 0..8 {
            for length in (0..=130).chain([255, 256, 511, 512, 1023, 2048, 8192]) {
                check(&bytes[offset..offset + length]);
            }
        }
    }

    #[test]
    fn standard_messages_and_large_input() {
        check(b"");
        check(b"abc");
        check(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        check(&vec![b'a'; 1_000_000]);
    }

    #[test]
    fn instruction_is_the_exact_two_register_compression_abi() {
        assert_eq!(guest::COMPRESSION_WORD, 0x0c00_000b | (5 << 15) | (6 << 20));
    }
}
