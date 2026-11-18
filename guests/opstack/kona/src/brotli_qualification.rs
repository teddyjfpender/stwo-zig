//! Differential policy vectors for the opt-in allocation implementation.
#[test]
fn valid_truncation_and_malformed_policy() {
    use kona_protocol::decompress_brotli;
    let input = alloy_primitives::hex::decode("8b048075ed184249e9bc19675e03").unwrap();
    let output = alloy_primitives::hex::decode("75ed184249e9bc19675e").unwrap();
    for cap in 0..=output.len() + 2 {
        let actual = decompress_brotli(&input, cap);
        assert_eq!(actual.unwrap(), output[..cap.min(output.len())]);
    }
    for len in 0..input.len() {
        let result = decompress_brotli(&input[..len], 1000);
        if let Ok(bytes) = result {
            assert!(output.starts_with(&bytes));
        }
    }
    let valid = alloy_primitives::hex::decode("1b4a0000c4f4a469bd79252d22b452ea830d387068b271c041761e36c6ce1384e836f22a0ce789687a04492faaf731a19b0d48b7f01f483342a59c312697a9c6be67855202").unwrap();
    assert_eq!(
        decompress_brotli(&valid, 1000).unwrap(),
        b"the quick brown fox jumps over the lazy dog twice for redundancy and length"
    );
    for (offset, xor) in [(13, 1), (23, 1), (33, 0x55)] {
        let mut corrupt = valid.clone();
        corrupt[offset] ^= xor;
        assert!(decompress_brotli(&corrupt, 1000).is_err());
    }
}
