use anyhow::{ensure,Result};
use sha2::{Digest,Sha256};
use std::{path::PathBuf,time::Instant};
use zisk_common::{io::ZiskStdin,HashMode};
use zisk_prover_backend::{BackendProverOpts,GuestProgram,ProverClientBuilder};
fn main()->Result<()> {
    let args:Vec<_>=std::env::args().collect();
    let guest=GuestProgram::from_uri(&args[1])?;
    let n:u32=args[2].parse()?;
    let mut expected=[0u8;32];
    for _ in 0..n { expected=Sha256::digest(expected).into(); }
    let start=Instant::now();
    let options=BackendProverOpts::default().proving_key(PathBuf::from(&args[3])).aggregation(true).verify_proofs();
    let prover=ProverClientBuilder::new().emu().with_prover_options(options).build()?;
    prover.setup(&guest).run()?;
    let setup_seconds=start.elapsed().as_secs_f64();
    let input=ZiskStdin::from_uri(Some(format!("inline://[[{n}]]")))?;
    eprintln!("GUEST_BENCH_SETUP_COMPLETE seconds={setup_seconds}");
    let t=Instant::now();
    let result=prover.prove(&guest,input).run()?;
    let prove_seconds=t.elapsed().as_secs_f64();
    ensure!(!result.get_proof().is_empty(),"complete aggregated proof missing");
    let t=Instant::now();
    let vk=guest.vk_with_mode(HashMode::Blake3)?;
    result.with_program_vk(&vk).verify()?;
    let mut actual=[0u8;32];result.get_public_values_slice(&mut actual);
    ensure!(actual==expected,"public digest mismatch");
    let verify_seconds=t.elapsed().as_secs_f64();
    result.save_proof(&args[4])?;
    let report=serde_json::json!({"iterations":n,"setup_seconds":setup_seconds,"prove_seconds":prove_seconds,"verify_seconds":verify_seconds,"prover_reported_ms":result.get_proving_time(),"steps":result.get_execution_steps(),"output_bytes":actual,"proof_bytes":result.get_proof_bytes()?.len(),"verified":true,"aggregation":true});
    std::fs::write(&args[5],serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    Ok(())
}
