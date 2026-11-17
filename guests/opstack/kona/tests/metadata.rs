use stwo_kona_execution::{
    execution::{Fixture, RangeInput},
    metadata,
};
fn range() -> RangeInput {
    let fixture: Fixture = serde_json::from_slice(include_bytes!("fixture.json")).unwrap();
    RangeInput {
        rollup_config: fixture.rollup_config,
        parent_header: fixture.parent_header,
        payloads: vec![fixture.executing_payload],
        expected_block_hashes: vec![fixture.expected_block_hash],
    }
}
#[test]
fn every_payload_field_survives_binary_roundtrip() {
    let mut range = range();
    let a = &mut range.payloads[0];
    a.payload_attributes.slot_number = Some(3);
    a.payload_attributes.target_gas_limit = Some(45_000_000);
    a.min_base_fee = Some(7);
    a.no_tx_pool = Some(true);
    a.payload_attributes.parent_beacon_block_root = Some([9; 32].into());
    a.eip_1559_params = Some([4; 8].into());
    let bytes = metadata::encode(&range).unwrap();
    let decoded = metadata::decode(&bytes).unwrap();
    assert_eq!(decoded.payloads, range.payloads);
    assert_eq!(decoded.rollup_config, range.rollup_config);
    assert_eq!(decoded.parent_header, range.parent_header);
    assert_eq!(metadata::encode(&decoded).unwrap(), bytes);
    assert_eq!(
        metadata::input_commitment(&decoded).unwrap(),
        metadata::input_commitment(&range).unwrap()
    );
}
#[test]
fn binding_excludes_claimed_outputs_but_includes_all_payload_inputs() {
    let mut r = range();
    let expected = metadata::input_commitment(&r).unwrap();
    r.expected_block_hashes[0] = [8; 32].into();
    assert_eq!(metadata::input_commitment(&r).unwrap(), expected);
    r.payloads[0].payload_attributes.timestamp += 1;
    assert_ne!(metadata::input_commitment(&r).unwrap(), expected);
}
#[test]
fn malformed_metadata_rejects() {
    let r = range();
    let bytes = metadata::encode(&r).unwrap();
    for len in [0, 1, 20, bytes.len() - 1] {
        assert!(metadata::decode(&bytes[..len]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(metadata::decode(&trailing).is_err());
    let mut r = r;
    r.expected_block_hashes.clear();
    assert!(metadata::encode(&r).is_err());
    r.payloads.clear();
    assert!(metadata::encode(&r).is_err());
}

#[test]
fn public_output_has_a_distinct_op_schema_and_full_width_chain_id() {
    let result = stwo_kona_execution::execution::ResultSummary {
        digest: [0xa5; 32],
        chain_id: u64::MAX,
        input_commitment: [0; 32],
        block_hashes: vec![],
        gas_used: 0,
        transactions: 0,
        preimages: stwo_kona_execution::witness::Stats::default(),
    };
    let bytes = result.public_output();
    assert_eq!(bytes.len(), 43);
    assert_eq!(&bytes[..32], &[0xa5; 32]);
    assert_eq!(bytes[32], 1);
    assert_eq!(
        u64::from_le_bytes(bytes[33..41].try_into().unwrap()),
        u64::MAX
    );
    assert_eq!(&bytes[41..], b"OP");
}
