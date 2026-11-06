use alloy_primitives::{B256, keccak256};
use stwo_kona_execution::witness::{self, DESCRIPTOR, Error, HEADER, Validation, Witness};
fn fixture() -> (Vec<u8>, B256) {
    let value = vec![1, 2, 3, 4];
    let key = keccak256(&value);
    (witness::encode(b"metadata", &[(key, value)]).unwrap(), key)
}
#[test]
fn borrowed_bytes_and_once_only_validation() {
    let (bytes, key) = fixture();
    let w = Witness::parse(&bytes, Validation::Lazy).unwrap();
    assert_eq!(w.stats().hashes, 0);
    let value = w.get(key).unwrap();
    assert!(value.as_ptr() >= bytes.as_ptr());
    assert!(
        unsafe { value.as_ptr().add(value.len()) } <= unsafe { bytes.as_ptr().add(bytes.len()) }
    );
    assert_eq!(value, [1, 2, 3, 4]);
    assert_eq!(w.get(key).unwrap(), value);
    assert_eq!(w.stats().hashes, 1);
    assert_eq!(w.stats().lookups, 2);
    assert_eq!(w.stats().hashed_bytes, 4);
}
#[test]
fn eager_and_lazy_agree_on_used_bytes() {
    let (bytes, key) = fixture();
    for mode in [Validation::Lazy, Validation::Eager] {
        let w = Witness::parse(&bytes, mode).unwrap();
        assert_eq!(w.get(key).unwrap(), [1, 2, 3, 4]);
        assert_eq!(w.stats().hashes, 1);
    }
}
#[test]
fn corrupted_preimage_is_never_admitted_or_memoized() {
    let (mut bytes, key) = fixture();
    *bytes.last_mut().unwrap() ^= 1;
    assert_eq!(
        Witness::parse(&bytes, Validation::Eager).unwrap_err(),
        Error::Hash
    );
    let w = Witness::parse(&bytes, Validation::Lazy).unwrap();
    for _ in 0..2 {
        assert_eq!(w.get(key), Err(Error::Hash));
    }
    assert_eq!(w.stats().hashes, 0);
}
#[test]
fn every_truncation_rejects() {
    let (bytes, _) = fixture();
    for len in 0..bytes.len() {
        assert!(Witness::parse(&bytes[..len], Validation::Lazy).is_err());
    }
}
#[test]
fn canonical_offsets_and_trailing_bytes_are_enforced() {
    let (bytes, _) = fixture();
    for offset in [0u32, 1, u32::MAX] {
        let mut bad = bytes.clone();
        bad[HEADER + 8 + 32..HEADER + 8 + 36].copy_from_slice(&offset.to_le_bytes());
        if offset == 0 {
            assert!(Witness::parse(&bad, Validation::Lazy).is_ok());
        } else {
            assert_eq!(
                Witness::parse(&bad, Validation::Lazy).unwrap_err(),
                Error::Offset
            );
        }
    }
    let mut bad = bytes;
    bad.push(0);
    let len = bad.len() as u32;
    bad[16..20].copy_from_slice(&len.to_le_bytes());
    assert_eq!(
        Witness::parse(&bad, Validation::Lazy).unwrap_err(),
        Error::Offset
    );
}
#[test]
fn bad_version_reserved_count_and_lengths_reject() {
    let (bytes, _) = fixture();
    for (at, value) in [
        (0, 0),
        (20, 1),
        (12, u32::MAX),
        (8, u32::MAX),
        (16, 0),
        (HEADER + 8 + 36, u32::MAX),
    ] {
        let mut bad = bytes.clone();
        bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
        assert!(Witness::parse(&bad, Validation::Lazy).is_err());
    }
}
#[test]
fn missing_key_fails_and_empty_preimage_is_authenticated() {
    let empty = keccak256([]);
    let bytes = witness::encode(&[], &[(empty, vec![])]).unwrap();
    let w = Witness::parse(&bytes, Validation::Lazy).unwrap();
    assert_eq!(w.get(B256::ZERO), Err(Error::Missing(B256::ZERO)));
    assert!(w.get(empty).unwrap().is_empty());
    assert_eq!(w.stats().hashes, 1);
}
#[test]
fn duplicate_and_unsorted_keys_reject() {
    let a = keccak256([1]);
    let b = keccak256([2]);
    assert_eq!(
        witness::encode(&[], &[(a, vec![1]), (a, vec![1])]),
        Err(Error::Order)
    );
    let mut rows = vec![(a, vec![1]), (b, vec![2])];
    rows.sort_by_key(|r| r.0);
    let mut bytes = witness::encode(&[], &rows).unwrap();
    let original = bytes[HEADER..HEADER + 32].to_vec();
    bytes[HEADER + DESCRIPTOR..HEADER + DESCRIPTOR + 32].copy_from_slice(&original);
    assert_eq!(
        Witness::parse(&bytes, Validation::Lazy).unwrap_err(),
        Error::Order
    );
    rows.reverse();
    assert_eq!(witness::encode(&[], &rows), Err(Error::Order));
}
