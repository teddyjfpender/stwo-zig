mod cli;
mod commands;
mod components;
mod model;
mod plonk_logup;
mod poseidon_exact;
mod profile;
mod proving;
mod state_machine;
mod statements;
mod traces;
mod wire;
mod xor;

#[cfg(test)]
mod backend_tests;

use anyhow::{bail, Result};
use cli::parse_cli;
use commands::{run_bench, run_generate, run_verify};
use model::Mode;
use serde_json::json;
use std::env;
use std::panic::{self, AssertUnwindSafe};

const UPSTREAM_COMMIT: &str = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";

fn main() -> Result<()> {
    let cli = parse_cli(env::args().collect())?;
    if cli.stage_profile_out.is_some() && cli.mode != Mode::Generate {
        bail!("--stage-profile-out is only supported for generate mode");
    }
    match cli.mode {
        Mode::Capabilities => run_capabilities(),
        Mode::Generate => run_generate(&cli),
        Mode::Verify => run_verify_guarded(&cli),
        Mode::Bench => run_bench(&cli),
    }
}

fn run_capabilities() -> Result<()> {
    let manifest = json!({
        "schema_version": 1,
        "protocol": "stwo_interop_capabilities_v1",
        "upstream_commit": UPSTREAM_COMMIT,
        "exact_air_protocols": {
            "state_machine": state_machine::PROTOCOL_NAME,
        },
    });
    println!("{}", serde_json::to_string(&manifest)?);
    Ok(())
}

fn run_verify_guarded(cli: &model::Cli) -> Result<()> {
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(|| run_verify(cli)));
    panic::set_hook(original_hook);
    match result {
        Ok(result) => result,
        Err(_) => bail!("malformed proof rejected at verifier safety boundary"),
    }
}
