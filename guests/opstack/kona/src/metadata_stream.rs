//! Borrowed, wire-identical postcard serialization. Payload transaction bytes
//! are streamed in slices rather than copied into a second owned range.
#[cfg(test)]
use super::{Payload, Range};
use crate::{
    execution::RangeInput,
    statement_sha2::{Digest, Sha256},
};
use alloc::vec::Vec;
use alloy_primitives::B256;
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use postcard::ser_flavors::Flavor;
use serde::{Serialize, Serializer, ser::SerializeSeq};

struct RawBytes<'a>(&'a [u8]);
impl Serialize for RawBytes<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}
struct OwnedBytes(Vec<u8>);
impl Serialize for OwnedBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}
struct Transactions<'a>(&'a [alloy_primitives::Bytes]);
impl Serialize for Transactions<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for bytes in self.0 {
            seq.serialize_element(&RawBytes(bytes.as_ref()))?;
        }
        seq.end()
    }
}
#[derive(Serialize)]
pub(super) struct PayloadView<'a> {
    timestamp: u64,
    prev_randao: [u8; 32],
    fee_recipient: [u8; 20],
    withdrawals_rlp: Option<OwnedBytes>,
    beacon_root: Option<[u8; 32]>,
    slot_number: Option<u64>,
    target_gas_limit: Option<u64>,
    transactions: Option<Transactions<'a>>,
    no_tx_pool: Option<bool>,
    gas_limit: Option<u64>,
    eip1559: Option<[u8; 8]>,
    min_base_fee: Option<u64>,
}
impl<'a> PayloadView<'a> {
    pub(super) fn new(a: &'a OpPayloadAttributes) -> Self {
        let p = &a.payload_attributes;
        Self {
            timestamp: p.timestamp,
            prev_randao: p.prev_randao.0,
            fee_recipient: p.suggested_fee_recipient.0.0,
            withdrawals_rlp: p
                .withdrawals
                .as_ref()
                .map(|w| OwnedBytes(alloy_rlp::encode(w))),
            beacon_root: p.parent_beacon_block_root.map(|r| r.0),
            slot_number: p.slot_number,
            target_gas_limit: p.target_gas_limit,
            transactions: a.transactions.as_deref().map(Transactions),
            no_tx_pool: a.no_tx_pool,
            gas_limit: a.gas_limit,
            eip1559: a.eip_1559_params.map(|p| p.0),
            min_base_fee: a.min_base_fee,
        }
    }
}
struct Payloads<'a>(&'a [OpPayloadAttributes]);
impl Serialize for Payloads<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for p in self.0 {
            seq.serialize_element(&PayloadView::new(p))?;
        }
        seq.end()
    }
}
struct Hashes<'a>(&'a [B256]);
impl Serialize for Hashes<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for h in self.0 {
            seq.serialize_element(&h.0)?;
        }
        seq.end()
    }
}
#[derive(Serialize)]
pub(super) struct RangeView<'a> {
    config_json: OwnedBytes,
    parent_rlp: OwnedBytes,
    payloads: Payloads<'a>,
    expected: Hashes<'a>,
}
impl<'a> RangeView<'a> {
    pub(super) fn new(input: &'a RangeInput) -> Result<Self, alloc::string::String> {
        Ok(Self {
            config_json: OwnedBytes(
                serde_json::to_vec(&input.rollup_config).map_err(|_| "config encode")?,
            ),
            parent_rlp: OwnedBytes(alloy_rlp::encode(&input.parent_header)),
            payloads: Payloads(&input.payloads),
            expected: Hashes(&input.expected_block_hashes),
        })
    }
}
/// A canonicality comparison is still exact and checks the complete encoding;
/// it simply has no second range-sized output allocation.
pub(super) struct Compare<'a>(pub &'a [u8]);
impl Flavor for Compare<'_> {
    type Output = ();
    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        self.try_extend(&[byte])
    }
    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        if !self.0.starts_with(bytes) {
            return Err(postcard::Error::SerializeBufferFull);
        }
        self.0 = &self.0[bytes.len()..];
        Ok(())
    }
    fn finalize(self) -> postcard::Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(postcard::Error::SerializeBufferFull)
        }
    }
}
/// Buffer scalar/array bytes locally so each serialized byte does not enter
/// SHA's full update path. Transaction bodies still stream directly in slices.
pub(super) struct Hash<'a> {
    hash: &'a mut Sha256,
    buffer: [u8; 64],
    used: usize,
}
impl<'a> Hash<'a> {
    pub(super) fn new(hash: &'a mut Sha256) -> Self {
        Self {
            hash,
            buffer: [0; 64],
            used: 0,
        }
    }
    fn flush(&mut self) {
        if self.used != 0 {
            self.hash.update(&self.buffer[..self.used]);
            self.used = 0;
        }
    }
}
impl Flavor for Hash<'_> {
    type Output = ();
    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        self.buffer[self.used] = byte;
        self.used += 1;
        if self.used == 64 {
            self.flush();
        }
        Ok(())
    }
    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        self.flush();
        self.hash.update(bytes);
        Ok(())
    }
    fn finalize(mut self) -> postcard::Result<()> {
        self.flush();
        Ok(())
    }
}
// Keep the old owned serialization exclusively as an independent byte oracle.
#[cfg(test)]
pub(super) fn legacy(input: &RangeInput) -> Range {
    Range {
        config_json: serde_json::to_vec(&input.rollup_config).unwrap(),
        parent_rlp: alloy_rlp::encode(&input.parent_header),
        payloads: input
            .payloads
            .iter()
            .map(Payload::from_attributes)
            .collect(),
        expected: input.expected_block_hashes.iter().map(|h| h.0).collect(),
    }
}
