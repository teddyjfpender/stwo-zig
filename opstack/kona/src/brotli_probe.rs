//! Bounded diagnostic program; its BP output never asserts OP validity.
use crate::statement_sha2::{Digest, Sha256};
/// Decode BRP1 || u32 max output || Brotli payload into a diagnostic digest.
pub fn execute(input: &[u8]) -> Option<[u8; 43]> {
    if input.len() < 8 || input.len() > 16 * 1024 * 1024 || &input[..4] != b"BRP1" {
        return None;
    }
    let cap = u32::from_le_bytes(input[4..8].try_into().ok()?) as usize;
    if cap > 100_000_000 {
        return None;
    }
    let result = kona_protocol::decompress_brotli(&input[8..], cap);
    let mut output = [0; 43];
    let bytes = match &result {
        Ok(v) => v.as_slice(),
        Err(_) => &[],
    };
    output[..32].copy_from_slice(&Sha256::digest(bytes));
    output[32..36].copy_from_slice(b"BRP1");
    output[36] = u8::from(result.is_ok());
    output[37..41].copy_from_slice(&u32::try_from(bytes.len()).ok()?.to_le_bytes());
    output[41..].copy_from_slice(b"BP");
    Some(output)
}
#[cfg(test)]
mod tests {
    #[test]
    fn bounds_and_framing() {
        assert!(super::execute(b"BRP1").is_none());
        assert!(super::execute(b"BRP1\xff\xff\xff\xff").is_none());
        let mut input = b"BRP1".to_vec();
        input.extend_from_slice(&1000u32.to_le_bytes());
        input.extend_from_slice(
            &alloy_primitives::hex::decode("8b048075ed184249e9bc19675e03").unwrap(),
        );
        let v = super::execute(&input).unwrap();
        assert_eq!(&v[32..37], b"BRP1\x01");
        assert_eq!(u32::from_le_bytes(v[37..41].try_into().unwrap()), 10);
        assert_eq!(&v[41..], b"BP");
    }
}
