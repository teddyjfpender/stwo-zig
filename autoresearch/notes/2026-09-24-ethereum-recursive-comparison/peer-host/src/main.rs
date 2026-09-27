use anyhow::{ensure, Result};
use std::{path::PathBuf, time::Instant};
use zisk_common::{io::ZiskStdin, HashMode};
use zisk_prover_backend::{BackendProverOpts, GuestProgram, ProverClientBuilder};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 8, "elf input expected key proof report mode");
    let guest = GuestProgram::from_uri(&args[1])?;
    let raw = std::fs::read(&args[2])?;
    let expected = std::fs::read(&args[3])?;
    ensure!(expected.len() == 72);
    let input = ZiskStdin::new();
    input.write_slice(&raw);
    if args[7] == "execute" {
        let client = ProverClientBuilder::new().emu().execute_only().build()?;
        client.setup(&guest)?;
        let result = client.execute(input)?;
        let mut actual = [0; 72];
        result.get_public_values_slice(&mut actual);
        ensure!(actual.as_slice() == expected, "execution output mismatch");
        let report = serde_json::json!({"steps":result.get_execution_steps(),"execution_ms":result.get_execution_time(),"plan":result.get_plan().map(|entries|entries.iter().map(|e|serde_json::json!({"airgroup_id":e.airgroup_id,"air_id":e.air_id,"name":e.name,"count":e.count})).collect::<Vec<_>>()),"output_bytes":actual.as_slice(),"execution_only":true});
        std::fs::write(&args[6], serde_json::to_vec_pretty(&report)?)?;
        println!("{report}");
        return Ok(());
    }
    let start = Instant::now();
    let options = BackendProverOpts::default()
        .verbose(if std::env::var_os("ETH_AUTH_PROFILE").is_some() {
            1
        } else {
            0
        })
        .proving_key(PathBuf::from(&args[4]))
        .aggregation(true)
        .verify_proofs();
    let prover = ProverClientBuilder::new()
        .emu()
        .with_prover_options(options)
        .build()?;
    prover.setup(&guest).run()?;
    let setup_seconds = start.elapsed().as_secs_f64();
    eprintln!("ETH_AUTH_SETUP_COMPLETE seconds={setup_seconds}");
    let t = Instant::now();
    let result = prover.prove(&guest, input).run()?;
    let prove_seconds = t.elapsed().as_secs_f64();
    ensure!(
        !result.get_proof().is_empty(),
        "complete aggregated proof missing"
    );
    let t = Instant::now();
    let vk = guest.vk_with_mode(HashMode::Blake3)?;
    result.with_program_vk(&vk).verify()?;
    let mut actual = [0; 72];
    result.get_public_values_slice(&mut actual);
    ensure!(actual.as_slice() == expected, "public output mismatch");
    let verify_seconds = t.elapsed().as_secs_f64();
    result.save_proof(&args[5])?;
    let report = serde_json::json!({"setup_seconds":setup_seconds,"prove_seconds":prove_seconds,"verify_seconds":verify_seconds,"steps":result.get_execution_steps(),"output_bytes":actual.as_slice(),"proof_bytes":result.get_proof_bytes()?.len(),"verified":true,"aggregation":true,"backend":"cpu-emu-native-precompiles"});
    std::fs::write(&args[6], serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    Ok(())
}
