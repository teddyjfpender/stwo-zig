//! Bounded Mantle execution core. No derivation or proof admission.
#![no_std]
extern crate alloc;
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use alloy_consensus::Header;
use alloy_op_evm::OpEvmFactory;
use alloy_primitives::{B256, Bytes, Sealable, keccak256};
use alloy_rlp::{Decodable, Encodable};
use kona_executor::{StatelessL2Builder, TrieDBProvider};
use kona_genesis::RollupConfig;
use kona_mpt::{NoopTrieHinter, TrieNode, TrieProvider};
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const MAX_RECORDS: usize = 131_072;
pub const MAX_PREIMAGE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TRANSACTIONS: usize = 16_384;
pub const MAX_TRANSACTION_BYTES: usize = 16 * 1024 * 1024;
pub type Error = String;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub rollup_config: serde_json::Value,
    pub parent_header: Header,
    pub payload: OpPayloadAttributes,
    pub expected_parent_hash: B256,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preimage {
    pub hash: B256,
    pub data: Bytes,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Expected {
    pub config_sha256: B256,
    pub block_hash: B256,
}
#[derive(Debug, Serialize)]
pub struct Receipt {
    pub schema: &'static str,
    pub scope: &'static str,
    pub proof_verified: bool,
    pub derivation_verified: bool,
    pub chain_id: u64,
    pub config_sha256: B256,
    pub parent_hash: B256,
    pub block_hash: B256,
    pub block_number: u64,
    pub state_root: B256,
    pub receipts_root: B256,
    pub transactions_root: B256,
    pub gas_used: u64,
    pub transactions: usize,
    pub preimage_records: usize,
    pub preimage_bytes: usize,
}
/// SHA256 of compact recursively key-sorted JSON, before typed config decoding.
pub fn config_hash(config: &serde_json::Value) -> Result<B256, Error> {
    let mut canonical = config.clone();
    canonical.sort_all_objects();
    let bytes = serde_json::to_vec(&canonical).map_err(|e| e.to_string())?;
    Ok(B256::from_slice(&Sha256::digest(bytes)))
}
#[derive(Debug)]
pub struct VerifiedPreimages(BTreeMap<B256, Bytes>, usize);
pub fn checked_preimages(records: Vec<Preimage>) -> Result<VerifiedPreimages, Error> {
    if records.len() > MAX_RECORDS {
        return Err("preimage record limit".into());
    }
    let mut map = BTreeMap::new();
    let mut bytes = 0usize;
    for record in records {
        bytes = bytes
            .checked_add(record.data.len())
            .ok_or("preimage byte overflow")?;
        if bytes > MAX_PREIMAGE_BYTES {
            return Err("preimage byte limit".into());
        }
        if keccak256(&record.data) != record.hash {
            return Err("preimage hash mismatch".into());
        }
        if map.insert(record.hash, record.data).is_some() {
            return Err("duplicate preimage".into());
        }
    }
    Ok(VerifiedPreimages(map, bytes))
}
fn exact<T: Decodable + Encodable>(bytes: &[u8]) -> Result<T, Error> {
    let mut rest = bytes;
    let value = T::decode(&mut rest).map_err(|e| e.to_string())?;
    if !rest.is_empty() || alloy_rlp::encode(&value) != bytes {
        return Err("noncanonical preimage RLP".into());
    }
    Ok(value)
}
#[derive(Debug, Clone, Copy)]
struct Provider<'a>(&'a BTreeMap<B256, Bytes>);
impl Provider<'_> {
    fn get(&self, hash: B256) -> Result<&[u8], Error> {
        self.0
            .get(&hash)
            .map(|b| b.as_ref())
            .ok_or_else(|| format!("missing preimage {hash}"))
    }
}
impl TrieProvider for Provider<'_> {
    type Error = Error;
    fn trie_node_by_hash(&self, hash: B256) -> Result<TrieNode, Error> {
        exact(self.get(hash)?)
    }
}
impl TrieDBProvider for Provider<'_> {
    fn bytecode_by_hash(&self, hash: B256) -> Result<Bytes, Error> {
        Ok(Bytes::copy_from_slice(self.get(hash)?))
    }
    fn header_by_hash(&self, hash: B256) -> Result<Header, Error> {
        exact(self.get(hash)?)
    }
}
fn validate_source(
    config: &RollupConfig,
    parent: &Header,
    payload: &OpPayloadAttributes,
) -> Result<usize, Error> {
    if config.l2_chain_id.id() != 5000 || config.l1_chain_id != 1 || config.block_time != 2 {
        return Err("Mantle mainnet network mismatch".into());
    }
    let f = &config.mantle_hardforks;
    if f.mantle_skadi_time != Some(1_756_278_000)
        || f.mantle_limb_time != Some(1_768_374_000)
        || f.mantle_arsia_time != Some(1_776_841_200)
    {
        return Err("Mantle mainnet fork schedule mismatch".into());
    }
    let timestamp = payload.payload_attributes.timestamp;
    if parent.timestamp.checked_add(config.block_time) != Some(timestamp)
        || !config.is_mantle_arsia_active(timestamp)
    {
        return Err("requires adjacent post-Arsia Mantle block".into());
    }
    parent
        .number
        .checked_add(1)
        .ok_or("block number overflow")?;
    let transactions = payload
        .transactions
        .as_deref()
        .ok_or("missing explicit transaction list")?;
    if transactions.is_empty() || transactions.len() > MAX_TRANSACTIONS {
        return Err("transaction count limit".into());
    }
    let bytes = transactions.iter().try_fold(0usize, |n, tx| {
        n.checked_add(tx.len()).ok_or("transaction byte overflow")
    })?;
    if bytes > MAX_TRANSACTION_BYTES {
        return Err("transaction byte limit".into());
    }
    Ok(transactions.len())
}
pub fn execute(
    fixture: Fixture,
    expected: Expected,
    preimages: VerifiedPreimages,
) -> Result<Receipt, Error> {
    if config_hash(&fixture.rollup_config)? != expected.config_sha256 {
        return Err("independent config pin mismatch".into());
    }
    let config: RollupConfig =
        serde_json::from_value(fixture.rollup_config).map_err(|e| format!("Mantle config: {e}"))?;
    let transactions = validate_source(&config, &fixture.parent_header, &fixture.payload)?;
    let parent_hash = fixture.parent_header.hash_slow();
    if parent_hash != fixture.expected_parent_hash {
        return Err("parent header hash mismatch".into());
    }
    let VerifiedPreimages(preimages, bytes) = preimages;
    let provider = Provider(&preimages);
    let mut builder = StatelessL2Builder::new(
        &config,
        OpEvmFactory::<alloy_op_evm::OpTx>::default(),
        provider,
        NoopTrieHinter,
        fixture.parent_header.seal_slow(),
    );
    let outcome = builder
        .build_block(fixture.payload)
        .map_err(|e| format!("Mantle execution: {e}"))?;
    let header = &outcome.header;
    if header.hash() != expected.block_hash || header.parent_hash != parent_hash {
        return Err("independent block hash or parent link mismatch".into());
    }
    Ok(Receipt {
        schema: "stwo.mantle.native-execution.v1",
        scope: "native EVM execution only; no L1 derivation, RV64 execution or proof acceptance",
        proof_verified: false,
        derivation_verified: false,
        chain_id: 5000,
        config_sha256: expected.config_sha256,
        parent_hash,
        block_hash: header.hash(),
        block_number: header.number,
        state_root: header.state_root,
        receipts_root: header.receipts_root,
        transactions_root: header.transactions_root,
        gas_used: header.gas_used,
        transactions,
        preimage_records: preimages.len(),
        preimage_bytes: bytes,
    })
}
pub const MAX_GUEST_INPUT: usize = 16 * 1024 * 1024 - 4;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestInput {
    pub schema: u32,
    pub fixture: Fixture,
    pub expected: Expected,
    pub preimages: Vec<Preimage>,
}
pub fn guest_execute(raw: &[u8]) -> Result<[u8; 43], Error> {
    guest_execute_with_receipt(raw).map(|(output, _)| output)
}
/// Host callers receive the execution counters without parsing or executing twice.
pub fn guest_execute_with_receipt(raw: &[u8]) -> Result<([u8; 43], Receipt), Error> {
    if raw.len() > MAX_GUEST_INPUT {
        return Err("guest input limit".into());
    }
    let input: GuestInput = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if input.schema != 1 {
        return Err("guest input schema".into());
    }
    let receipt = execute(
        input.fixture,
        input.expected,
        checked_preimages(input.preimages)?,
    )?;
    let mut digest = Sha256::new();
    digest.update(b"stwo/mantle/execution/v1\0");
    digest.update(Sha256::digest(raw));
    digest.update(receipt.block_hash);
    let mut output = [0u8; 43];
    output[..32].copy_from_slice(&digest.finalize());
    output[32] = 1;
    output[33..41].copy_from_slice(&5000u64.to_le_bytes());
    output[41..].copy_from_slice(b"ME");
    Ok((output, receipt))
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec;
    fn record(data: &'static [u8]) -> Preimage {
        Preimage {
            hash: keccak256(data),
            data: Bytes::from_static(data),
        }
    }
    #[test]
    fn pins_and_preimage_authority() {
        assert!(checked_preimages(vec![record(b"x"), record(b"x")]).is_err());
        let mut invalid = record(b"x");
        invalid.hash = B256::ZERO;
        assert!(checked_preimages(vec![invalid]).is_err());
        assert!(exact::<u64>(&[0x81, 1]).is_err());
    }
    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../tests/fixtures/block-103132217.json")).unwrap()
    }
    fn advice() -> VerifiedPreimages {
        checked_preimages(
            serde_json::from_str(include_str!(
                "../tests/fixtures/block-103132217-preimages.json"
            ))
            .unwrap(),
        )
        .unwrap()
    }
    fn expected() -> Expected {
        Expected {
            config_sha256: alloy_primitives::b256!(
                "b9583f9b493763c945cc961535b9298070c92d538be1af77523b27053f4a23de"
            ),
            block_hash: alloy_primitives::b256!(
                "bac88cdc801196ab975bb07717bd964f87b14b093ac94997f47f768ed7ff1fcc"
            ),
        }
    }
    #[test]
    fn real_mantle_103132217_and_bad_pins() {
        let r = execute(fixture(), expected(), advice()).unwrap();
        assert_eq!((r.preimage_records, r.preimage_bytes), (77, 29248));
        for config in [true, false] {
            let mut wrong = expected();
            if config {
                wrong.config_sha256 = B256::ZERO;
            } else {
                wrong.block_hash = B256::ZERO;
            }
            let error = execute(fixture(), wrong, advice()).unwrap_err();
            assert!(error.contains(if config { "config pin" } else { "block hash" }));
        }
        assert!(execute(fixture(), expected(), checked_preimages(vec![]).unwrap()).is_err());
    }
    #[test]
    fn guest_statement_and_mutations() {
        let records = serde_json::from_str(include_str!(
            "../tests/fixtures/block-103132217-preimages.json"
        ))
        .unwrap();
        let mut input = GuestInput {
            schema: 1,
            fixture: fixture(),
            expected: expected(),
            preimages: records,
        };
        let raw = serde_json::to_vec(&input).unwrap();
        let output = guest_execute(&raw).unwrap();
        let (host_output, receipt) = guest_execute_with_receipt(&raw).unwrap();
        assert_eq!(output, host_output);
        assert_eq!(receipt.block_hash, expected().block_hash);
        assert!(receipt.gas_used > 0 && receipt.transactions > 0);
        let mut digest = Sha256::new();
        digest.update(b"stwo/mantle/execution/v1\0");
        digest.update(Sha256::digest(&raw));
        digest.update(expected().block_hash);
        assert_eq!(&output[..32], &digest.finalize()[..]);
        assert_eq!(&output[32..], &[1, 136, 19, 0, 0, 0, 0, 0, 0, b'M', b'E']);
        input.schema = 2;
        assert!(guest_execute(&serde_json::to_vec(&input).unwrap()).is_err());
        input.schema = 1;
        input.expected.config_sha256 = B256::ZERO;
        assert!(guest_execute(&serde_json::to_vec(&input).unwrap()).is_err());
        input.expected = expected();
        input.preimages.clear();
        assert!(guest_execute(&serde_json::to_vec(&input).unwrap()).is_err());
    }
}
