use alloy_primitives::B256;
use std::{fs::File, io::Read, path::Path};
use stwo_mantle_native::{Expected, Fixture, Preimage, checked_preimages, execute};
fn read(path: &Path, limit: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    if file.metadata()?.len() > limit {
        return Err("JSON file byte limit".into());
    }
    let mut data = Vec::new();
    file.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err("JSON file changed beyond limit".into());
    }
    Ok(data)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 3 && args[1] == "guest-input" {
        let raw = read(
            Path::new(&args[2]),
            stwo_mantle_native::MAX_GUEST_INPUT as u64,
        )?;
        let (output, receipt) = stwo_mantle_native::guest_execute_with_receipt(&raw)?;
        println!(
            "{}",
            serde_json::json!({
                "output": alloy_primitives::Bytes::copy_from_slice(&output),
                "gas_used": receipt.gas_used, "transactions": receipt.transactions,
                "block_hash": receipt.block_hash, "scope": receipt.scope
            })
        );
        return Ok(());
    }
    if args.len() != 5 {
        return Err("usage: stwo-mantle-native FIXTURE.json PREIMAGES.json EXPECTED_CONFIG_SHA256 EXPECTED_BLOCK_HASH".into());
    }
    let expected = Expected {
        config_sha256: args[3].to_str().ok_or("config pin UTF8")?.parse::<B256>()?,
        block_hash: args[4].to_str().ok_or("block pin UTF8")?.parse::<B256>()?,
    };
    let fixture: Fixture = serde_json::from_slice(&read(Path::new(&args[1]), 4 * 1024 * 1024)?)?;
    let records: Vec<Preimage> =
        serde_json::from_slice(&read(Path::new(&args[2]), 160 * 1024 * 1024)?)?;
    let receipt = execute(fixture, expected, checked_preimages(records)?)?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}
