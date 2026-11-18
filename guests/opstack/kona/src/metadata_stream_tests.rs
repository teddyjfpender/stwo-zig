use super::*;
use crate::execution::Fixture;

fn range() -> RangeInput {
    let fixture: Fixture = serde_json::from_slice(include_bytes!("../tests/fixture.json")).unwrap();
    RangeInput {
        rollup_config: fixture.rollup_config,
        parent_header: fixture.parent_header,
        payloads: alloc::vec![fixture.executing_payload],
        expected_block_hashes: alloc::vec![fixture.expected_block_hash],
    }
}
#[test]
fn borrowed_stream_has_identical_legacy_bytes_and_digest_for_every_byte_tail() {
    for length in [0, 1, 2, 31, 32, 63, 64, 65, 127, 128, 129, 1024, 4097] {
        let mut input = range();
        let p = &mut input.payloads[0];
        p.transactions = Some(alloc::vec![
            Bytes::from(alloc::vec![0xa5;length]),
            Bytes::from_static(b"second")
        ]);
        p.payload_attributes.withdrawals = Some(serde_json::from_value(serde_json::json!([{
            "index":"0x1", "validatorIndex":"0x2", "address":"0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "amount":"0x123"
        }])).unwrap());
        p.payload_attributes.slot_number = Some(u64::MAX);
        p.payload_attributes.target_gas_limit = Some(45_000_000);
        p.payload_attributes.parent_beacon_block_root = Some([9; 32].into());
        p.min_base_fee = Some(7);
        p.no_tx_pool = Some(true);
        p.eip_1559_params = Some([4; 8].into());
        let legacy = stream::legacy(&input);
        let bytes = postcard::to_allocvec(&legacy).unwrap();
        assert_eq!(encode(&input).unwrap(), bytes);
        assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(), bytes);
        let mut hash = Sha256::new();
        hash.update(b"stwo/opstack/payload-range/v1\0");
        hash.update(Sha256::digest(&legacy.config_json));
        hash.update(alloy_primitives::Sealable::hash_slow(&input.parent_header));
        hash.update((input.payloads.len() as u32).to_le_bytes());
        for p in legacy.payloads {
            let bytes = postcard::to_allocvec(&p).unwrap();
            hash.update((bytes.len() as u32).to_le_bytes());
            hash.update(bytes);
        }
        let expected: [u8; 32] = hash.finalize().into();
        assert_eq!(input_commitment(&input).unwrap(), expected);
    }
}
#[test]
fn canonical_comparison_rejects_long_varint_and_every_truncation() {
    let input = range();
    let bytes = encode(&input).unwrap();
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end]).is_err());
    }
    let mut long = bytes.clone();
    let last = long.iter().position(|x| x & 0x80 == 0).unwrap();
    long[last] |= 0x80;
    long.insert(last + 1, 0);
    assert!(decode(&long).is_err());
    assert!(
        postcard::serialize_with_flavor(
            &stream::RangeView::new(&input).unwrap(),
            stream::Compare(&bytes[..bytes.len() - 1])
        )
        .is_err()
    );
}

#[test]
fn optional_fields_and_multiple_payloads_keep_the_owned_wire_format() {
    let mut input = range();
    input.payloads[0].transactions = None;
    input.payloads[0].payload_attributes.withdrawals = None;
    let second = input.payloads[0].clone();
    input.payloads.push(second);
    input.expected_block_hashes.push([0x5a; 32].into());
    let expected = postcard::to_allocvec(&stream::legacy(&input)).unwrap();
    assert_eq!(encode(&input).unwrap(), expected);
    assert_eq!(encode(&decode(&expected).unwrap()).unwrap(), expected);
}
