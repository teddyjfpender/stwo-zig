//! Recover the pinned block's canonical input using the upstream codecs.
//! This converts input; it neither executes the block nor proves validation.

use alloy_consensus::{Block, Transaction, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_genesis::ChainConfig;
use alloy_rlp::Decodable;
use serde::Deserialize;
use serde_with::serde_as;
use sha2::{Digest, Sha256};
use stateless_validator_common::{
    HashTreeRoot, Sha2Hasher,
    guest::input::{ExecutionWitness, ProtocolFork, StatelessInput, new_payload_request::*},
};
use std::{error::Error, fs, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

// These fields match guest_reth::RethInputPublic at the pinned Zisk client
// commit 0887d436. Its BlockRlp adapter serializes the block as a byte vector.
#[serde_as]
#[derive(Deserialize)]
struct PublicInput {
    block: Vec<u8>,
    #[serde_as(as = "alloy_genesis::serde_bincode_compat::ChainConfig<'_>")]
    chain_config: ChainConfig,
    public_keys: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
struct WitnessInput {
    witness: alloy_rpc_types_debug::ExecutionWitness,
}

fn require(ok: bool, message: &str) -> Result<()> {
    if !ok {
        return Err(message.into());
    }
    Ok(())
}

fn checked_hash(bytes: &[u8], expected: &str) -> Result<()> {
    require(
        format!("{:x}", Sha256::digest(bytes)) == expected,
        "artifact hash mismatch",
    )
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, consumed) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
    require(consumed == bytes.len(), "trailing bincode bytes")?;
    Ok(value)
}

fn frame<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
    let start = offset.checked_add(8).ok_or("frame offset overflow")?;
    let length = u64::from_le_bytes(
        bytes
            .get(*offset..start)
            .ok_or("truncated frame header")?
            .try_into()?,
    );
    let end = start
        .checked_add(usize::try_from(length)?)
        .ok_or("frame length overflow")?;
    let padded = end.checked_add(7).ok_or("padding overflow")? & !7;
    let data = bytes.get(start..end).ok_or("truncated frame payload")?;
    require(
        bytes
            .get(end..padded)
            .ok_or("truncated padding")?
            .iter()
            .all(|b| *b == 0),
        "nonzero padding",
    )?;
    *offset = padded;
    Ok(data)
}

/// `general == false` admits only the pinned block 24,628,607 fixture (the
/// historical contract). `general == true` admits any BPO2-era mainnet block
/// without execution requests; callers must pin the source fixture and the
/// canonical output hashes themselves (see autoresearch/guest_efficiency).
fn project(bytes: &[u8], general: bool) -> Result<(Vec<u8>, String)> {
    if !general {
        checked_hash(
            bytes,
            "e1c6d4e06a87649da68e461a91465e4123b990f531e68581ee1750599ff12376",
        )?;
    }
    let mut offset = 0;
    let public: PublicInput = decode(frame(bytes, &mut offset)?)?;
    let WitnessInput { witness } = decode(frame(bytes, &mut offset)?)?;
    require(offset == bytes.len(), "trailing framed input")?;
    let inventory = (
        witness.state.len(),
        witness.codes.len(),
        witness.keys.len(),
        witness.headers.len(),
    );
    require(
        general || inventory == (3854, 120, 835, 1),
        "wrong witness inventory",
    )?;
    let mut block_bytes = public.block.as_slice();
    let block = Block::<TxEnvelope>::decode(&mut block_bytes)?;
    require(block_bytes.is_empty(), "trailing block RLP")?;
    let header = &block.header;
    require(
        general || (header.number == 24628607 && header.timestamp == 1773164303),
        "wrong block",
    )?;
    if general {
        require(header.timestamp >= 1767747671, "pre-BPO2 block")?;
        if let Some(t) = public.chain_config.amsterdam_time {
            require(header.timestamp < t, "Amsterdam-fork block is not supported by the BPO2 guest")?;
        }
        require(
            header.requests_hash
                == Some(alloy_primitives::b256!(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                )),
            "non-empty execution requests are not reconstructible from this fixture",
        )?;
    }
    require(
        public.chain_config.chain_id == 1
            && public.chain_config.bpo1_time == Some(1765290071)
            && public.chain_config.bpo2_time == Some(1767747671),
        "wrong legacy fork schedule",
    )?;
    require(block.body.ommers.is_empty(), "post-merge ommers")?;
    require(
        block.body.transactions.len() == public.public_keys.len()
            && (general || block.body.transactions.len() == 66),
        "wrong transaction/key count",
    )?;
    let mut parent_bytes = witness
        .headers
        .last()
        .ok_or("missing parent header")?
        .as_ref();
    let parent = alloy_consensus::Header::decode(&mut parent_bytes)?;
    require(parent_bytes.is_empty(), "trailing parent header RLP")?;
    require(
        parent.hash_slow() == header.parent_hash && parent.number + 1 == header.number,
        "parent header relation differs",
    )?;
    // Values come from the same decoded header used by the canonical projection.
    // This receipt normalizes statements; it does not execute either guest.
    let normalized = format!(
        concat!(
            "{{\"schema\":\"stwo.ethereum.fixture-normalization-projection.v1\",",
            "\"block\":{{\"chain_id\":{},\"number\":{},\"hash\":\"{:#x}\",",
            "\"parent_hash\":\"{:#x}\",\"state_root\":\"{:#x}\",",
            "\"transactions_root\":\"{:#x}\",\"receipts_root\":\"{:#x}\",",
            "\"withdrawals_root\":\"{:#x}\",\"requests_hash\":\"{:#x}\",",
            "\"transaction_count\":{},\"gas_used\":{},\"gas_limit\":{},\"timestamp\":{}}},",
            "\"parent_state_root\":\"{:#x}\",\"schema_id\":{},",
            "\"guest_execution_reproduced\":false}}\n"
        ),
        public.chain_config.chain_id,
        header.number,
        header.hash_slow(),
        header.parent_hash,
        header.state_root,
        header.transactions_root,
        header.receipts_root,
        header.withdrawals_root.ok_or("missing withdrawals root")?,
        header.requests_hash.ok_or("missing requests hash")?,
        block.body.transactions.len(),
        header.gas_used,
        header.gas_limit,
        header.timestamp,
        parent.state_root,
        ProtocolFork::BPO2.schema_id(),
    );
    let mut public_keys = Vec::new();
    let mut versioned_hashes = Vec::new();
    for (tx, supplied) in block.body.transactions.iter().zip(public.public_keys) {
        let signature = tx.signature();
        let recovered = signature.recover_from_prehash(&tx.signature_hash())?;
        let key: [u8; 65] = recovered.to_encoded_point(false).as_bytes().try_into()?;
        require(
            key.as_slice() == supplied,
            "transaction public key mismatch",
        )?;
        public_keys.push(key);
        if let Some(hashes) = tx.blob_versioned_hashes() {
            versioned_hashes.extend(hashes.iter().map(|hash| hash.0));
        }
    }
    let payload = ExecutionPayloadV3 {
        parent_hash: header.parent_hash.0,
        fee_recipient: header.beneficiary.into_array(),
        state_root: header.state_root.0,
        receipts_root: header.receipts_root.0,
        logs_bloom: header.logs_bloom.0.0,
        prev_randao: header.mix_hash.0,
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: header
            .extra_data
            .to_vec()
            .try_into()
            .map_err(|e| format!("extra data: {e:?}"))?,
        base_fee_per_gas: alloy_primitives::U256::from(
            header.base_fee_per_gas.ok_or("missing base fee")?,
        )
        .to_le_bytes(),
        block_hash: header.hash_slow().0,
        transactions: block
            .body
            .transactions
            .iter()
            .map(|tx| tx.encoded_2718().into())
            .collect::<Vec<_>>()
            .into(),
        withdrawals: block
            .body
            .withdrawals
            .as_ref()
            .ok_or("missing withdrawals")?
            .iter()
            .map(|w| Withdrawal {
                index: w.index,
                validator_index: w.validator_index,
                address: w.address.into_array(),
                amount: w.amount,
            })
            .collect::<Vec<_>>()
            .into(),
        blob_gas_used: header.blob_gas_used.ok_or("missing blob gas")?,
        excess_blob_gas: header.excess_blob_gas.ok_or("missing excess blob gas")?,
    };
    let request = NewPayloadRequest::ElectraFulu(NewPayloadRequestElectraFulu {
        execution_payload: payload,
        versioned_hashes: versioned_hashes.into(),
        parent_beacon_block_root: header
            .parent_beacon_block_root
            .ok_or("missing beacon root")?
            .0,
        // This fixture contains no execution requests; the final canonical hash
        // below rejects any unsupported reconstruction of this field.
        execution_requests: ExecutionRequestsElectraFulu {
            deposits: Default::default(),
            withdrawals: Default::default(),
            consolidations: Default::default(),
        },
    });
    let request_root = request.hash_tree_root(&Sha2Hasher);
    require(
        general
            || request_root
                == alloy_primitives::b256!(
                "e63d2797ca5c6f826a32d20c41ba552d25777533ab295f9d232560b014d09030"
            )
            .0,
        "payload request root mismatch",
    )?;
    let input = StatelessInput {
        new_payload_request: request,
        witness: ExecutionWitness {
            state: witness
                .state
                .into_iter()
                .map(|b| b.to_vec().try_into())
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| format!("witness list: {e:?}"))?
                .into(),
            codes: witness
                .codes
                .into_iter()
                .map(|b| b.to_vec().try_into())
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| format!("witness list: {e:?}"))?
                .into(),
            headers: witness
                .headers
                .into_iter()
                .map(|b| b.to_vec().try_into())
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| format!("witness list: {e:?}"))?
                .try_into()
                .map_err(|e| format!("headers: {e:?}"))?,
        },
        chain_id: 1,
        public_keys: public_keys.into(),
    };
    let canonical = input.to_schema_prefixed_ssz(ProtocolFork::BPO2);
    require(
        StatelessInput::from_schema_prefixed_ssz(&canonical)?.1 == input,
        "SSZ roundtrip mismatch",
    )?;
    if !general {
        checked_hash(
            &canonical,
            "845b7c924728c1fcd3c7dbcd38b71e2744a1a36f2205d6e05ceb32db4278065c",
        )?;
    }
    let normalized = format!(
        "{{\"projection\":{},\"new_payload_request_root\":\"{:#x}\"}}\n",
        normalized.trim(),
        alloy_primitives::B256::from(request_root),
    );
    Ok((canonical, normalized))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    let general = args.len() == 4 && args[1] == "--general";
    require(
        args.len() == 3 || general,
        "usage: stwo-ethereum-input-projection [--general] ZISK_INPUT NEW_OUTPUT_DIRECTORY",
    )?;
    let (input, out) = if general { (&args[2], &args[3]) } else { (&args[1], &args[2]) };
    let size = fs::metadata(input)?.len();
    require(
        if general { size > 0 && size <= 64 * 1024 * 1024 } else { size == 2718960 },
        "wrong fixture size",
    )?;
    let (canonical, normalized) = project(&fs::read(input)?, general)?;
    let mut runner = u32::try_from(canonical.len())?.to_le_bytes().to_vec();
    runner.extend_from_slice(&canonical);
    if !general {
        checked_hash(
            &runner,
            "faaf02583929396faed177914da27b4a493766993001357bd1720340ca1ddabb",
        )?;
    }
    let output = Path::new(out);
    fs::create_dir(output)?;
    fs::write(output.join("canonical-input.ssz"), &canonical)?;
    fs::write(output.join("stwo-runner-input.bin"), &runner)?;
    fs::write(output.join("normalization-v1.json"), normalized)?;
    println!(
        "canonical_bytes={} runner_bytes={} general={} input_projection_verified=true block_execution_verified=false",
        canonical.len(),
        runner.len(),
        general
    );
    Ok(())
}
