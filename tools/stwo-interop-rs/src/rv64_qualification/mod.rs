//! Explicit fixture-scoped independent Rust proof boundary and measured lifecycle.
mod layout;
mod local;
mod memory;
mod model;
mod proof;
mod state;
use anyhow::{ensure, Result};
use std::{fs, io::Read, time::Instant};
pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        args.len() == 4,
        "usage: rv64_qualification EXPECTED.json BUNDLE.json REPEATS"
    );
    let s: model::Statement = serde_json::from_slice(&read_limited(&args[1], 64 * 1024)?)?;
    let bytes = read_limited(&args[2], 8 * 1024 * 1024)?;
    ensure!(bytes.len() <= 8 * 1024 * 1024, "bundle too large");
    let repeats: usize = args[3].parse()?;
    ensure!((1..=100).contains(&repeats), "invalid repeat count");
    let start = Instant::now();
    let artifact: model::Artifact = serde_json::from_slice(&bytes)?;
    let decode_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let setup = proof::Setup::new(&s, &artifact.metadata)?;
    let setup_ns = start.elapsed().as_nanos();
    setup.verify(&s, &artifact.metadata, artifact.proof.decode()?)?;
    let mut decode = vec![];
    let mut verify = vec![];
    for _ in 0..repeats {
        let start = Instant::now();
        let artifact: model::Artifact = serde_json::from_slice(&bytes)?;
        let proof = artifact.proof.decode()?;
        decode.push(start.elapsed().as_nanos());
        let start = Instant::now();
        setup.verify(&s, &artifact.metadata, proof)?;
        verify.push(start.elapsed().as_nanos());
    }
    println!(
        "{}",
        serde_json::json!({"verified":true,"authority":"Native Stwo a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2 PCS/FRI + fixture-scoped four-way RV64 adapter","stock_top_level_verify":false,"witness_available":false,"program_scope":"ADDI/ADDI/SD/LD/ADD qualification fixture","constraint_count":5513,"independent_setup_ns":setup_ns,"initial_json_decode_ns":decode_ns,"decode_ns":decode,"prepared_verify_ns":verify,"warmups":1,"samples":repeats})
    );
    Ok(())
}

fn read_limited(path: &str, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input too large");
    Ok(bytes)
}
