//! Execute the pinned canonical block input on the host and retain its output.
use sha2::{Digest, Sha256};
use std::{error::Error, fs, io::Write};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("usage: stwo-ethereum-host-validation CANONICAL_INPUT NEW_OUTPUT_FILE".into());
    }
    if fs::metadata(&args[1])?.len() != 2700688 {
        return Err("canonical input size mismatch".into());
    }
    let input = fs::read(&args[1])?;
    if format!("{:x}", Sha256::digest(&input))
        != "845b7c924728c1fcd3c7dbcd38b71e2744a1a36f2205d6e05ceb32db4278065c"
    {
        return Err("canonical input hash mismatch".into());
    }
    let started = std::time::Instant::now();
    let output = stateless_validator_reth::guest::run_stateless_guest(&input);
    if format!("{:x}", Sha256::digest(&output))
        != "730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5"
    {
        return Err("host validation output mismatch".into());
    }
    let elapsed = started.elapsed();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])?;
    file.write_all(&output)?;
    file.sync_all()?;
    println!(
        "host_validation_verified=true output_bytes={} elapsed_ms={} rv32_execution_verified=false",
        output.len(),
        elapsed.as_millis()
    );
    Ok(())
}
