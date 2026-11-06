//! Explicit binary payload attributes; JSON is confined to the small rollup config.
//! Field completeness is pinned to the Optimism revision in Cargo.lock.
use crate::{execution::RangeInput, witness::MAX_BLOCKS};
use alloc::{string::String, vec::Vec};
use alloy_primitives::{B256, Bytes};
use alloy_rlp::{Decodable, Encodable};
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
struct Payload {
    timestamp: u64,
    prev_randao: [u8; 32],
    fee_recipient: [u8; 20],
    withdrawals_rlp: Option<Vec<u8>>,
    beacon_root: Option<[u8; 32]>,
    slot_number: Option<u64>,
    target_gas_limit: Option<u64>,
    transactions: Option<Vec<Vec<u8>>>,
    no_tx_pool: Option<bool>,
    gas_limit: Option<u64>,
    eip1559: Option<[u8; 8]>,
    min_base_fee: Option<u64>,
}
impl Payload {
    fn from_attributes(a: &OpPayloadAttributes) -> Self {
        let p = &a.payload_attributes;
        Self {
            timestamp: p.timestamp,
            prev_randao: p.prev_randao.0,
            fee_recipient: p.suggested_fee_recipient.0.0,
            withdrawals_rlp: p.withdrawals.as_ref().map(alloy_rlp::encode),
            beacon_root: p.parent_beacon_block_root.map(|r| r.0),
            slot_number: p.slot_number,
            target_gas_limit: p.target_gas_limit,
            transactions: a
                .transactions
                .as_ref()
                .map(|txs| txs.iter().map(|t| t.to_vec()).collect()),
            no_tx_pool: a.no_tx_pool,
            gas_limit: a.gas_limit,
            eip1559: a.eip_1559_params.map(|p| p.0),
            min_base_fee: a.min_base_fee,
        }
    }
    fn into_attributes(self) -> Result<OpPayloadAttributes, String> {
        let mut a = OpPayloadAttributes {
            transactions: self
                .transactions
                .map(|txs| txs.into_iter().map(Bytes::from).collect()),
            no_tx_pool: self.no_tx_pool,
            gas_limit: self.gas_limit,
            eip_1559_params: self.eip1559.map(Into::into),
            min_base_fee: self.min_base_fee,
            payload_attributes: Default::default(),
        };
        let p = &mut a.payload_attributes;
        p.timestamp = self.timestamp;
        p.prev_randao = self.prev_randao.into();
        p.suggested_fee_recipient = self.fee_recipient.into();
        p.withdrawals = match self.withdrawals_rlp {
            Some(bytes) => Some(decode_exact(&bytes)?),
            None => None,
        };
        p.parent_beacon_block_root = self.beacon_root.map(Into::into);
        p.slot_number = self.slot_number;
        p.target_gas_limit = self.target_gas_limit;
        Ok(a)
    }
}
#[derive(Serialize, Deserialize)]
struct Range {
    config_json: Vec<u8>,
    parent_rlp: Vec<u8>,
    #[serde(deserialize_with = "bounded_blocks")]
    payloads: Vec<Payload>,
    #[serde(deserialize_with = "bounded_blocks")]
    expected: Vec<[u8; 32]>,
}
fn decode_exact<T: Decodable + Encodable>(bytes: &[u8]) -> Result<T, String> {
    let mut remaining = bytes;
    let value = T::decode(&mut remaining).map_err(|_| "metadata RLP")?;
    if !remaining.is_empty() || alloy_rlp::encode(&value) != bytes {
        return Err("noncanonical metadata RLP".into());
    }
    Ok(value)
}
pub fn encode(input: &RangeInput) -> Result<Vec<u8>, String> {
    if input.payloads.is_empty()
        || input.payloads.len() > MAX_BLOCKS
        || input.payloads.len() != input.expected_block_hashes.len()
    {
        return Err("range size".into());
    }
    let wire = Range {
        config_json: serde_json::to_vec(&input.rollup_config).map_err(|_| "config encode")?,
        parent_rlp: alloy_rlp::encode(&input.parent_header),
        payloads: input
            .payloads
            .iter()
            .map(Payload::from_attributes)
            .collect(),
        expected: input.expected_block_hashes.iter().map(|h| h.0).collect(),
    };
    postcard::to_allocvec(&wire).map_err(|_| "metadata encode".into())
}
pub fn decode(bytes: &[u8]) -> Result<RangeInput, String> {
    let wire: Range = postcard::from_bytes(bytes).map_err(|_| "metadata decode")?;
    if wire.payloads.is_empty()
        || wire.payloads.len() > MAX_BLOCKS
        || wire.expected.len() != wire.payloads.len()
    {
        return Err("range size".into());
    }
    let input = RangeInput {
        rollup_config: serde_json::from_slice(&wire.config_json).map_err(|_| "config decode")?,
        parent_header: decode_exact(&wire.parent_rlp)?,
        payloads: wire
            .payloads
            .into_iter()
            .map(Payload::into_attributes)
            .collect::<Result<_, _>>()?,
        expected_block_hashes: wire.expected.into_iter().map(B256::from).collect(),
    };
    if encode(&input)? != bytes {
        return Err("noncanonical metadata".into());
    }
    Ok(input)
}
/// Derivation must bind this value. Expected execution hashes are excluded so
/// derivation need not execute the EVM to compute the payload commitment.
pub fn input_commitment(input: &RangeInput) -> Result<[u8; 32], String> {
    let mut hash = Sha256::new();
    hash.update(b"stwo/opstack/payload-range/v1\0");
    hash.update(Sha256::digest(
        serde_json::to_vec(&input.rollup_config).map_err(|_| "config encode")?,
    ));
    hash.update(alloy_primitives::Sealable::hash_slow(&input.parent_header));
    hash.update((input.payloads.len() as u32).to_le_bytes());
    for a in &input.payloads {
        let bytes =
            postcard::to_allocvec(&Payload::from_attributes(a)).map_err(|_| "payload encode")?;
        hash.update((bytes.len() as u32).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hash.finalize().into())
}

// Enforce range limits before allocating a producer-controlled sequence.
fn bounded_blocks<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T>(core::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "at most {MAX_BLOCKS} blocks")
        }
        fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<Vec<T>, S::Error> {
            if seq.size_hint().is_some_and(|n| n > MAX_BLOCKS) {
                return Err(serde::de::Error::custom("too many blocks"));
            }
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_BLOCKS));
            while let Some(value) = seq.next_element()? {
                if out.len() == MAX_BLOCKS {
                    return Err(serde::de::Error::custom("too many blocks"));
                }
                out.push(value);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_seq(Visitor(core::marker::PhantomData))
}
