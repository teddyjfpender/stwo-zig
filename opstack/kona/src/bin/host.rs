//! Native fixture conversion and execution, separate from the no_std guest.
use alloy_primitives::B256;
use std::{collections::BTreeMap, env, fs, time::Instant};
use stwo_kona_execution::{
    execution::{self, Fixture, RangeInput},
    witness::{self, Validation, Witness},
};
#[path = "../host/mainnet.rs"]
mod mainnet;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("import-mainnet") => {
            if args.len() != 4 {
                return Err("import-mainnet REPLAY_JSON FIXTURE_JSON".into());
            }
            mainnet::import(&args[2], &args[3])?;
        }
        Some("pack") => {
            if args.len() < 4 {
                return Err("pack OUT FIXTURE_DIR...".into());
            }
            let mut records = BTreeMap::<B256, Vec<u8>>::new();
            let mut range: Option<RangeInput> = None;
            let mut previous = None;
            for dir in &args[3..] {
                let fixture: Fixture =
                    serde_json::from_slice(&fs::read(format!("{dir}/fixture.json"))?)?;
                if previous.is_some_and(|h| {
                    alloy_primitives::Sealable::hash_slow(&fixture.parent_header) != h
                }) {
                    return Err("fixtures are not adjacent".into());
                }
                previous = Some(fixture.expected_block_hash);
                let rows: Vec<(B256, String)> =
                    serde_json::from_slice(&fs::read(format!("{dir}/preimages.json"))?)?;
                for (key, hex) in rows {
                    let value = alloy_primitives::hex::decode(hex)?;
                    if let Some(old) = records.insert(key, value.clone()) {
                        if old != value {
                            return Err("conflicting preimage".into());
                        }
                    }
                }
                let input = range.get_or_insert_with(|| RangeInput {
                    rollup_config: fixture.rollup_config.clone(),
                    parent_header: fixture.parent_header.clone(),
                    payloads: Vec::new(),
                    expected_block_hashes: Vec::new(),
                });
                if input.rollup_config != fixture.rollup_config {
                    return Err("rollup config differs".into());
                }
                input.payloads.push(fixture.executing_payload);
                input
                    .expected_block_hashes
                    .push(fixture.expected_block_hash);
            }
            let range = range.ok_or("empty range")?;
            let metadata = stwo_kona_execution::metadata::encode(&range)?;
            let bytes = witness::encode(&metadata, &records.into_iter().collect::<Vec<_>>())
                .map_err(|e| e.to_string())?;
            // Validate the producer conversion eagerly before publishing.
            Witness::parse(&bytes, Validation::Eager).map_err(|e| e.to_string())?;
            fs::write(&args[2], bytes)?;
        }
        Some("run") => {
            if args.len() != 4 {
                return Err("run INPUT eager|lazy".into());
            }
            let bytes = fs::read(&args[2])?;
            let mode = match args[3].as_str() {
                "eager" => Validation::Eager,
                "lazy" => Validation::Lazy,
                _ => return Err("unknown validation mode".into()),
            };
            let start = Instant::now();
            let witness = Witness::parse(&bytes, mode).map_err(|e| e.to_string())?;
            let parse = start.elapsed().as_secs_f64();
            let result = execution::execute(&witness)?;
            println!(
                "{}",
                serde_json::json!({"schema":"stwo.opstack.native-execution.v1", "mode":args[3],
                "input_bytes":bytes.len(), "records":witness.records(), "parse_s":parse, "total_s":start.elapsed().as_secs_f64(),
                "digest":alloy_primitives::hex::encode(result.digest), "output":alloy_primitives::hex::encode(result.public_output()), "input_commitment":alloy_primitives::hex::encode(result.input_commitment),
                "block_hashes":result.block_hashes, "gas_used":result.gas_used, "transactions":result.transactions,
                "preimage_lookups":result.preimages.lookups, "preimage_hashes":result.preimages.hashes,
                "preimage_hashed_bytes":result.preimages.hashed_bytes, "proof_verified":false})
            );
        }
        _ => {
            return Err(
                "usage: stwo-kona-host pack OUT FIXTURE_DIR... | run INPUT eager|lazy".into(),
            );
        }
    }
    Ok(())
}
