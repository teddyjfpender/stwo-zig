//! Parity oracle for the circuit recursion lane, pinned to `starkware-libs/proving@5a7c5ed`.
//!
//! Each subcommand runs pinned upstream Rust code and emits one checkpoint that a rung of the Zig
//! parity ladder compares against. See `README.md` for the rung mapping and the digest contracts.

mod adapt_program;
mod checkpoint;
mod compiled_air;
mod components;
mod gadgets;
mod goldens;
mod output;
mod primitives;
mod project_air;
mod prove_cairo;
mod upstream;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

const USAGE: &str = "usage: stwo-circuit-oracle primitives [--output PATH]
       stwo-circuit-oracle gadgets [--output PATH]
       stwo-circuit-oracle components --proving-root DIR [--output PATH]
       stwo-circuit-oracle project-air --proving-root DIR [--output PATH]
       stwo-circuit-oracle adapt-program --proving-root DIR --program PATH [--output PATH]
       stwo-circuit-oracle prove-cairo --prover-input PATH --params PATH [--proving-root DIR]
                                   [--proof-output PATH] [--output PATH]";

fn main() -> Result<()> {
    let mut values = std::env::args().skip(1);
    let subcommand = values.next().with_context(|| USAGE)?;
    let (mut output, mut proving_root) = (None, None);
    let (mut prover_input, mut params, mut proof_output, mut program) = (None, None, None, None);
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .with_context(|| format!("{flag} requires a value"))?;
        let slot = match flag.as_str() {
            "--output" => &mut output,
            "--proving-root" => &mut proving_root,
            "--prover-input" => &mut prover_input,
            "--params" => &mut params,
            "--proof-output" => &mut proof_output,
            "--program" => &mut program,
            _ => bail!("unexpected argument {flag:?}\n{USAGE}"),
        };
        if slot.replace(PathBuf::from(value)).is_some() {
            bail!("{flag} given twice");
        }
    }
    let root = || {
        proving_root
            .as_deref()
            .with_context(|| format!("{subcommand} requires --proving-root"))
    };
    let bytes = match subcommand.as_str() {
        "primitives" | "gadgets" if proving_root.is_some() => {
            bail!("{subcommand} does not read upstream data; drop --proving-root")
        }
        "primitives" => output::json(&primitives::run()?)?,
        "gadgets" => output::json(&gadgets::run()?)?,
        "components" => output::json(&components::run(root()?)?)?,
        "project-air" => project_air::run(root()?)?,
        "adapt-program" => adapt_program::run(
            root()?,
            &program
                .as_deref()
                .context("adapt-program requires --program")?
                .display()
                .to_string(),
        )?,
        "prove-cairo" => {
            let proved = prove_cairo::run(
                prover_input.as_deref().context("prove-cairo requires --prover-input")?,
                params.as_deref().context("prove-cairo requires --params")?,
                proving_root.as_deref(),
            )?;
            if let Some(path) = proof_output.as_deref() {
                output::emit(Some(path), &proved.extended_binary)?;
            }
            proved.checkpoint
        }
        other => bail!("unknown subcommand {other:?}\n{USAGE}"),
    };
    output::emit(output.as_deref(), &bytes)
}
