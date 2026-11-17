//! Convert pinned historical mainnet replays using the actual chain registry.
use alloy_consensus::Header;
use alloy_primitives::{B256, Bytes};
use alloy_rlp::Decodable;
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use serde::Deserialize;
use std::{error::Error, fs};
use stwo_kona_execution::execution::Fixture;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replay {
    chain_id: u64,
    block_number: u64,
    parent_rlp: String,
    expected_rlp: String,
    expected_block_hash: B256,
    transactions: Vec<Bytes>,
}
fn header(raw: &str) -> Result<Header, Box<dyn Error>> {
    let bytes = alloy_primitives::hex::decode(raw)?;
    let mut remaining = bytes.as_slice();
    let header = Header::decode(&mut remaining)?;
    if !remaining.is_empty() || alloy_rlp::encode(&header) != bytes {
        return Err("noncanonical or trailing header RLP".into());
    }
    Ok(header)
}
pub fn import(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let replay: Replay = serde_json::from_slice(&fs::read(input)?)?;
    if replay.chain_id != 10 {
        return Err("requires OP Mainnet chain 10".into());
    }
    let parent = header(&replay.parent_rlp)?;
    let expected = header(&replay.expected_rlp)?;
    if parent.number.checked_add(1) != Some(replay.block_number)
        || expected.number != replay.block_number
        || expected.parent_hash != parent.hash_slow()
        || expected.hash_slow() != replay.expected_block_hash
    {
        return Err("mainnet header identity or ancestry mismatch".into());
    }
    let config = kona_registry::ROLLUP_CONFIGS
        .get(&10)
        .ok_or("missing chain 10")?
        .clone();
    // This archive predates Holocene: later payload attributes need their own importer.
    if !expected.extra_data.is_empty()
        || expected.requests_hash.is_some()
        || expected.withdrawals_root.is_none()
        || expected.parent_beacon_block_root.is_none()
    {
        return Err("requires historical Ecotone mainnet headers".into());
    }
    let payload: OpPayloadAttributes = serde_json::from_value(serde_json::json!({
        "timestamp": format!("0x{:x}", expected.timestamp),
        "prevRandao": expected.mix_hash,
        "suggestedFeeRecipient": expected.beneficiary,
        "withdrawals": [],
        "parentBeaconBlockRoot": expected.parent_beacon_block_root,
        "transactions": replay.transactions,
        "noTxPool": true,
        "gasLimit": format!("0x{:x}", expected.gas_limit)
    }))?;
    let fixture = Fixture {
        rollup_config: config,
        parent_header: parent,
        executing_payload: payload,
        expected_block_hash: replay.expected_block_hash,
    };
    fs::write(output, serde_json::to_vec_pretty(&fixture)?)?;
    Ok(())
}
