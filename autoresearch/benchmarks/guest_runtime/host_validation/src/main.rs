//! Execute a canonical block input on the host and retain its output.
//!
//! Default mode admits only the pinned block 24,628,607 input and output (the
//! historical contract). `--general` admits any canonical input up to 16 MiB;
//! callers (autoresearch/guest_efficiency) pin the input hash and compare the
//! output against the independently projected request root themselves.
use sha2::{Digest, Sha256};
use std::{error::Error, fs, io::Write};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    let general = args.len() == 4 && args[1] == "--general";
    if args.len() != 3 && !general {
        return Err(
            "usage: stwo-ethereum-host-validation [--general] CANONICAL_INPUT NEW_OUTPUT_FILE".into(),
        );
    }
    let (input_path, output_path) = if general { (&args[2], &args[3]) } else { (&args[1], &args[2]) };
    let size = fs::metadata(input_path)?.len();
    if if general { size == 0 || size > 16 * 1024 * 1024 - 4 } else { size != 2700688 } {
        return Err("canonical input size mismatch".into());
    }
    let input = fs::read(input_path)?;
    if !general
        && format!("{:x}", Sha256::digest(&input))
            != "845b7c924728c1fcd3c7dbcd38b71e2744a1a36f2205d6e05ceb32db4278065c"
    {
        return Err("canonical input hash mismatch".into());
    }
    let started = std::time::Instant::now();
    let output = stateless_validator_reth::guest::run_stateless_guest(&input);
    if !general
        && format!("{:x}", Sha256::digest(&output))
            != "730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5"
    {
        return Err("host validation output mismatch".into());
    }
    let elapsed = started.elapsed();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)?;
    file.write_all(&output)?;
    file.sync_all()?;
    println!(
        "host_validation_verified=true general={} output_bytes={} elapsed_ms={} rv32_execution_verified=false",
        general,
        output.len(),
        elapsed.as_millis()
    );
    Ok(())
}
