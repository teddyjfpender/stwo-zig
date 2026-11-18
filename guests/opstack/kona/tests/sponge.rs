#[path = "../guest/src/sponge_service.rs"]
mod service;
use sha3::{Digest, Keccak256};
fn reference_call(state: *mut u64, input: *const u8, length: usize, flags: u64) {
    assert_eq!((state as usize) % 8, 0);
    assert!(length < 1 << 20 && flags & !3 == 0);
    assert!(flags & 1 != 0 || length > 0 && length % 136 == 0);
    let state = unsafe { &mut *state.cast::<[u64; 25]>() };
    if flags & 2 != 0 {
        *state = [0; 25];
    }
    let data = if length == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(input, length) }
    };
    for chunk in data.chunks_exact(136) {
        for (i, byte) in chunk.iter().enumerate() {
            state[i / 8] ^= (*byte as u64) << ((i % 8) * 8);
        }
        keccak::Keccak::new().with_f1600(|f| f(state));
    }
    if flags & 1 != 0 {
        let tail = &data[length / 136 * 136..];
        for (i, byte) in tail.iter().enumerate() {
            state[i / 8] ^= (*byte as u64) << ((i % 8) * 8);
        }
        state[tail.len() / 8] ^= 1u64 << ((tail.len() % 8) * 8);
        state[16] ^= 0x80u64 << 56;
        keccak::Keccak::new().with_f1600(|f| f(state));
    }
}
#[test]
fn sponge_boundaries_alignments_and_long_chunking() {
    for len in [
        0usize,
        1,
        7,
        8,
        32,
        64,
        135,
        136,
        137,
        271,
        272,
        4096,
        7710 * 136,
        7710 * 136 + 1,
        2 * 7710 * 136 + 139,
    ] {
        for offset in 0..8 {
            let bytes: Vec<u8> = (0..len + offset).map(|i| (i * 37 + 13) as u8).collect();
            let input = &bytes[offset..];
            let expected = Keccak256::digest(input);
            let mut output = [0; 32];
            let mut calls = 0;
            unsafe {
                service::hash_with(
                    input.as_ptr(),
                    input.len(),
                    output.as_mut_ptr(),
                    |s, i, n, f| {
                        calls += 1;
                        reference_call(s, i, n, f);
                    },
                );
            }
            assert_eq!(
                output.as_slice(),
                expected.as_slice(),
                "length {len}, offset {offset}"
            );
            assert_eq!(calls, (len.saturating_sub(1) / (7710 * 136)) + 1);
        }
    }
}
#[test]
fn empty_null_input_and_overlapping_output() {
    let mut output = [0; 32];
    unsafe {
        service::hash_with(core::ptr::null(), 0, output.as_mut_ptr(), reference_call);
    }
    assert_eq!(output.as_slice(), Keccak256::digest([]).as_slice());
    let mut bytes: Vec<u8> = (0..273).map(|i| i as u8).collect();
    let expected = Keccak256::digest(&bytes);
    unsafe {
        service::hash_with(
            bytes.as_ptr(),
            bytes.len(),
            bytes.as_mut_ptr().add(5),
            reference_call,
        );
    }
    assert_eq!(&bytes[5..37], expected.as_slice());
}
