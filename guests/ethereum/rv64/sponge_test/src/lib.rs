#[cfg(test)]
#[path = "../../src/keccak_service.rs"]
mod service;

#[test]
fn sponge_matches_independent_hash_and_permutation_count_at_boundaries_and_alignments() {
    use core::sync::atomic::Ordering;
    use sha3::{Digest, Keccak256};
    for len in [0, 1, 7, 8, 31, 32, 135, 136, 137, 271, 272, 273, 4096] {
        for offset in 0..8 {
            let bytes: Vec<u8> = (0..len + offset)
                .map(|i| ((i * 37 + 13) & 255) as u8)
                .collect();
            let input = &bytes[offset..];
            let expected = Keccak256::digest(input);
            let mut output = [0; 32];
            service::PERMUTE_CALLS.store(0, Ordering::Relaxed);
            unsafe {
                service::native_keccak256(input.as_ptr(), len, output.as_mut_ptr());
            }
            assert_eq!(
                &output[..],
                expected.as_slice(),
                "len={len} offset={offset}"
            );
            assert_eq!(
                service::PERMUTE_CALLS.load(Ordering::Relaxed),
                len / 136 + 1
            );
        }
    }
    // Empty input may have a null pointer; output can alias a fully consumed input.
    let mut empty = [0; 32];
    unsafe {
        service::native_keccak256(core::ptr::null(), 0, empty.as_mut_ptr());
    }
    assert_eq!(&empty[..], Keccak256::digest([]).as_slice());
    let mut overlapping: Vec<u8> = (0..273).map(|i| i as u8).collect();
    let expected = Keccak256::digest(&overlapping);
    unsafe {
        service::native_keccak256(
            overlapping.as_ptr(),
            overlapping.len(),
            overlapping.as_mut_ptr().add(5),
        );
    }
    assert_eq!(&overlapping[5..37], expected.as_slice());
}
