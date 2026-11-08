//! One builder per range retains authenticated trie state between adjacent blocks.
use crate::statement_sha2::{Digest, Sha256};
use crate::witness::{Error, MAX_BLOCKS, Stats, Witness};
use alloc::{format, string::String, vec::Vec};
use alloy_consensus::Header;
use alloy_op_evm::{OpEvmFactory, OpTx, block::OpAlloyReceiptBuilder};
use alloy_primitives::{B256, Bytes, Sealable};
use alloy_rlp::Decodable;
use kona_executor::{StatelessL2Builder, TrieDBProvider};
use kona_genesis::RollupConfig;
#[cfg(not(feature = "host"))]
use kona_mpt::NoopTrieHinter;
use kona_mpt::{TrieNode, TrieProvider};
#[cfg(feature = "host")]
#[path = "host/hints.rs"]
mod hints;
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RangeInput {
    pub rollup_config: RollupConfig,
    pub parent_header: Header,
    pub payloads: Vec<OpPayloadAttributes>,
    pub expected_block_hashes: Vec<B256>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Fixture {
    pub rollup_config: RollupConfig,
    pub parent_header: Header,
    pub executing_payload: OpPayloadAttributes,
    pub expected_block_hash: B256,
}
#[derive(Debug)]
pub(crate) struct Provider<'w, 'a>(pub(crate) &'w Witness<'a>);
pub(crate) fn decode_exact<T: Decodable>(bytes: &[u8]) -> Result<T, Error> {
    let mut remaining = bytes;
    let value = T::decode(&mut remaining).map_err(|_| Error::Rlp)?;
    if !remaining.is_empty() {
        return Err(Error::Rlp);
    }
    Ok(value)
}
impl TrieProvider for Provider<'_, '_> {
    type Error = Error;
    fn trie_node_by_hash(&self, key: B256) -> Result<TrieNode, Error> {
        decode_exact(self.0.get(key)?)
    }
}
impl TrieDBProvider for Provider<'_, '_> {
    fn bytecode_by_hash(&self, hash: B256) -> Result<Bytes, Error> {
        Ok(Bytes::copy_from_slice(self.0.get(hash)?))
    }
    fn header_by_hash(&self, hash: B256) -> Result<Header, Error> {
        decode_exact(self.0.get(hash)?)
    }
}
#[derive(Debug)]
pub struct ResultSummary {
    pub digest: [u8; 32],
    pub chain_id: u64,
    pub input_commitment: [u8; 32],
    pub block_hashes: Vec<B256>,
    pub gas_used: u64,
    pub transactions: usize,
    pub preimages: Stats,
}

fn execution_digest(input_commitment: [u8; 32]) -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(b"stwo/opstack/execution-range/v1\0");
    digest.update(input_commitment);
    digest
}

pub(crate) fn single_block_output(
    chain_id: u64,
    input_commitment: [u8; 32],
    block_hash: B256,
) -> [u8; 43] {
    let mut digest = execution_digest(input_commitment);
    digest.update(block_hash);
    public_output(chain_id, digest.finalize().into(), b"OP")
}

pub(crate) fn public_output(chain_id: u64, digest: [u8; 32], schema: &[u8; 2]) -> [u8; 43] {
    let mut bytes = [0; 43];
    bytes[..32].copy_from_slice(&digest);
    bytes[32] = 1;
    bytes[33..41].copy_from_slice(&chain_id.to_le_bytes());
    bytes[41..43].copy_from_slice(schema);
    bytes
}

pub fn execute(witness: &Witness<'_>) -> Result<ResultSummary, String> {
    let input = crate::metadata::decode(witness.metadata())?;
    let count = input.payloads.len();
    if count == 0 || count > MAX_BLOCKS || input.expected_block_hashes.len() != count {
        return Err("range size".into());
    }
    if input
        .parent_header
        .number
        .checked_add(count as u64)
        .is_none()
    {
        return Err("block number overflow".into());
    }
    let chain_id: u64 = input.rollup_config.l2_chain_id.into();
    let input_commitment = crate::metadata::input_commitment(&input)?;
    let mut digest = execution_digest(input_commitment);
    #[cfg(feature = "host")]
    let last_hint = core::cell::Cell::new(None);
    #[cfg(feature = "host")]
    let hinter = hints::Hints(&last_hint);
    #[cfg(not(feature = "host"))]
    let hinter = NoopTrieHinter;
    let mut builder = StatelessL2Builder::new(
        &input.rollup_config,
        OpEvmFactory::<OpTx>::default(),
        OpAlloyReceiptBuilder::default(),
        Provider(witness),
        hinter,
        input.parent_header.seal_slow(),
    );
    let mut hashes = Vec::with_capacity(count);
    let mut gas_used = 0u64;
    let mut transactions = 0usize;
    for (payload, expected) in input.payloads.into_iter().zip(input.expected_block_hashes) {
        transactions += payload.transactions.as_ref().map_or(0, Vec::len);
        let outcome = builder.build_block(payload).map_err(|e| {
            #[cfg(feature = "host")]
            return format!(
                "Kona execution: {e}; last witness hint: {}",
                last_hint
                    .get()
                    .map(|hint| format!("{hint}"))
                    .unwrap_or_default()
            );
            #[cfg(not(feature = "host"))]
            format!("Kona execution: {e}")
        })?;
        if outcome.header.hash() != expected {
            return Err("block hash mismatch".into());
        }
        gas_used = gas_used
            .checked_add(outcome.header.gas_used)
            .ok_or("gas overflow")?;
        digest.update(outcome.header.hash().as_slice());
        hashes.push(outcome.header.hash());
    }
    Ok(ResultSummary {
        digest: digest.finalize().into(),
        chain_id,
        input_commitment,
        block_hashes: hashes,
        gas_used,
        transactions,
        preimages: witness.stats(),
    })
}

impl ResultSummary {
    /// Existing machine transport, new OP-specific schema 0x504f (bytes "OP").
    /// The digest binds execution only, not L1 derivation or data availability.
    pub fn public_output(&self) -> [u8; 43] {
        public_output(self.chain_id, self.digest, b"OP")
    }
}
