//! Offline intake for an anchored OP Mainnet transition witness.
use alloy_eips::{BlockNumHash, eip4844::Blob};
use alloy_primitives::{B256, hex};
use serde::Deserialize;
use std::{collections::BTreeMap, error::Error, fs, io::Write, path::Path};
use stwo_kona_execution::{
    anchored_blobs::BlobSidecar,
    transition::Transition,
    transition_input::{self, TransitionInput},
    witness,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    number: u64,
    hash: B256,
}

impl From<Checkpoint> for BlockNumHash {
    fn from(c: Checkpoint) -> Self {
        Self {
            number: c.number,
            hash: c.hash,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    anchor: Checkpoint,
    previous_number: u64,
    previous_root: B256,
    next_number: u64,
    next_root: B256,
    next_origin: Checkpoint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sidecar {
    blob: String,
    kzg_commitment: String,
    kzg_proof: String,
}

pub fn pack(
    claim: &str,
    records: &str,
    sidecars: &str,
    output: &str,
) -> Result<(), Box<dyn Error>> {
    let claim: Claim = serde_json::from_slice(&fs::read(claim)?)?;
    let claim = Transition {
        anchor: claim.anchor.into(),
        previous_number: claim.previous_number,
        previous_root: claim.previous_root,
        next_number: claim.next_number,
        next_root: claim.next_root,
        next_origin: claim.next_origin.into(),
    };
    let mut map = BTreeMap::new();
    let rows: Vec<(B256, String)> = serde_json::from_slice(&fs::read(records)?)?;
    for (key, value) in rows {
        let value = hex::decode(value)?;
        if map.insert(key, value).is_some() {
            return Err("duplicate transition preimage".into());
        }
    }
    let witness = witness::encode_transition_records(&map.into_iter().collect::<Vec<_>>())?;
    let mut blobs = Vec::new();
    if sidecars != "-" {
        let rows: Vec<Sidecar> = serde_json::from_slice(&fs::read(sidecars)?)?;
        for row in rows {
            let bytes = hex::decode(row.blob)?;
            if bytes.len() != alloy_eips::eip4844::BYTES_PER_BLOB {
                return Err("invalid EIP-4844 blob length".into());
            }
            blobs.push((
                <[u8; 48]>::try_from(hex::decode(row.kzg_commitment)?)
                    .map_err(|_| "invalid KZG commitment length")?,
                <[u8; 48]>::try_from(hex::decode(row.kzg_proof)?)
                    .map_err(|_| "invalid KZG proof length")?,
                bytes,
            ));
        }
    }
    blobs.sort_unstable_by_key(|(commitment, _, _)| *commitment);
    let sidecars: Vec<_> = blobs
        .iter()
        .map(|(commitment, proof, blob)| BlobSidecar {
            blob: <&Blob>::try_from(blob.as_slice()).unwrap(),
            commitment: *commitment,
            proof: *proof,
        })
        .collect();
    let input = transition_input::encode(claim, &witness, &sidecars)?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(output))?
        .write_all(&input)?;
    Ok(())
}

pub fn run(path: &str, trace_path: Option<&str>) -> Result<(), Box<dyn Error>> {
    let input = fs::read(path)?;
    let input = TransitionInput::parse(&input)?;
    let verified = if let Some(trace_path) = trace_path {
        let (verified, trace) = stwo_kona_execution::transition_trace::record(|| input.verify());
        let verified = verified?;
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(trace_path)?;
        out.write_all(&serde_json::to_vec(&trace)?)?;
        out.write_all(b"\n")?;
        verified
    } else {
        input.verify()?
    };
    let statement = verified.statement;
    println!(
        "{}",
        serde_json::json!({
        "schema": "stwo.opstack.anchored-transition.v1",
        "chain_id": statement.chain_id,
        "l1_chain_id": statement.l1_chain_id,
        "anchor_number": statement.claim.anchor.number,
        "anchor_hash": hex::encode(statement.claim.anchor.hash),
        "previous_number": statement.claim.previous_number,
        "previous_root": hex::encode(statement.claim.previous_root),
        "next_number": statement.claim.next_number,
        "next_root": hex::encode(statement.claim.next_root),
        "next_origin_number": verified.block.l1_origin.number,
        "next_origin_hash": hex::encode(verified.block.l1_origin.hash),
        "block_hash": hex::encode(verified.block.hash()),
        "payload_commitment": hex::encode(statement.payload_commitment),
                        })
    );
    Ok(())
}
