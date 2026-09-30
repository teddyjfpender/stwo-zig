//! Parity oracle for the circuit recursion lane, pinned to `starkware-libs/proving@5a7c5ed`.
//!
//! Each subcommand runs pinned upstream Rust code and emits one checkpoint that a rung of the Zig
//! parity ladder compares against. See `README.md` for the rung mapping and the digest contracts.

mod adapt_program;
mod air_programs;
mod cairo_statement;
mod checkpoint;
mod columns;
mod compiled_air;
mod components;
mod contexts;
#[path = "../../stwo-eval-program-abi/src/lib.rs"]
mod eval_program_abi;
mod finalize;
mod gadgets;
mod goldens;
mod multiverifier_inputs;
mod output;
mod primitives;
mod project_air;
mod prove_cairo;
mod prove_lifted_example;
mod prove_small;
mod topology;
#[path = "../../stwo-trace-digest/src/lib.rs"]
mod trace_digest;
mod upstream;
mod verifier_stages;
mod verify_circuit;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

const USAGE: &str = "usage: stwo-circuit-oracle primitives [--output PATH]
       stwo-circuit-oracle gadgets [--output PATH]
       stwo-circuit-oracle components --proving-root DIR [--output PATH]
       stwo-circuit-oracle statement-trace --proving-root DIR [--output PATH]
       stwo-circuit-oracle project-air --proving-root DIR [--output PATH]
       stwo-circuit-oracle finalize [--output PATH]
       stwo-circuit-oracle prove-small [--memory-budget BYTES] [--output PATH]
       stwo-circuit-oracle prove-profiles [--memory-budget BYTES] [--output PATH]
       stwo-circuit-oracle multiverifier-inputs --proving-root DIR --inputs-output PATH [--output PATH]
       stwo-circuit-oracle verify-circuit --proof PATH --request PATH [--output PATH]
       stwo-circuit-oracle air-programs [--output PATH]
       stwo-circuit-oracle topology --proving-root DIR [--output PATH]
       stwo-circuit-oracle verifier-stages --proving-root DIR [--output PATH]
       stwo-circuit-oracle cairo-statement --proving-root DIR [--output PATH]
       stwo-circuit-oracle prove-lifted-example [--output PATH]
       stwo-circuit-oracle adapt-program --proving-root DIR --program PATH [--program-input PATH]
                                     [--output PATH]
       stwo-circuit-oracle prove-cairo --prover-input PATH --params PATH [--proving-root DIR]
                                   [--lifting-size-policy POLICY] [--proof-output PATH] [--output PATH]";

fn main() -> Result<()> {
    let mut values = std::env::args().skip(1);
    let subcommand = values.next().with_context(|| USAGE)?;
    let (mut output, mut proving_root, mut memory_budget) = (None, None, None);
    let (mut prover_input, mut params, mut proof_output, mut program) = (None, None, None, None);
    let mut lifting_size_policy = None;
    let (mut inputs_output, mut proof, mut request) = (None, None, None);
    let mut program_input = None;
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .with_context(|| format!("{flag} requires a value"))?;
        if flag == "--memory-budget" {
            let bytes: u64 = value
                .parse()
                .with_context(|| format!("--memory-budget {value:?} is not a byte count"))?;
            if memory_budget.replace(bytes).is_some() {
                bail!("{flag} given twice");
            }
            continue;
        }
        let slot = match flag.as_str() {
            "--output" => &mut output,
            "--proving-root" => &mut proving_root,
            "--prover-input" => &mut prover_input,
            "--params" => &mut params,
            "--proof-output" => &mut proof_output,
            "--program" => &mut program,
            "--program-input" => &mut program_input,
            "--lifting-size-policy" => &mut lifting_size_policy,
            "--inputs-output" => &mut inputs_output,
            "--proof" => &mut proof,
            "--request" => &mut request,
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
    if memory_budget.is_some() && subcommand != "prove-small" && subcommand != "prove-profiles" {
        bail!("--memory-budget applies only to prove-small and prove-profiles");
    }
    let bytes = match subcommand.as_str() {
        "primitives" | "gadgets" | "finalize" | "prove-small" | "prove-profiles"
        | "air-programs" | "verify-circuit"
            if proving_root.is_some() =>
        {
            bail!("{subcommand} does not read upstream data; drop --proving-root")
        }
        "primitives" => output::json(&primitives::run()?)?,
        "gadgets" => output::json(&gadgets::run()?)?,
        "finalize" => output::json(&finalize::run()?)?,
        "prove-small" => output::json(&prove_small::run(
            memory_budget.unwrap_or(prove_small::DEFAULT_MEMORY_BUDGET),
        )?)?,
        "prove-profiles" => output::json(&prove_small::run_profiles(
            memory_budget.unwrap_or(prove_small::DEFAULT_MEMORY_BUDGET),
        )?)?,
        "multiverifier-inputs" => output::json(&multiverifier_inputs::run(
            root()?,
            inputs_output
                .as_deref()
                .context("multiverifier-inputs requires --inputs-output")?,
        )?)?,
        "verify-circuit" => output::json(&verify_circuit::run(
            proof
                .as_deref()
                .context("verify-circuit requires --proof")?,
            request
                .as_deref()
                .context("verify-circuit requires --request")?,
        )?)?,
        "components" => output::json(&components::run(root()?)?)?,
        "statement-trace" => output::json(&components::statement_trace::run(root()?)?)?,
        "project-air" => project_air::run(root()?)?,
        "air-programs" => air_programs::run()?,
        "topology" => output::json(&topology::run(root()?)?)?,
        "verifier-stages" => output::json(&verifier_stages::run(root()?)?)?,
        "cairo-statement" => output::json(&cairo_statement::run(root()?)?)?,
        "prove-lifted-example" => prove_lifted_example::run()?,
        "adapt-program" => adapt_program::run(
            root()?,
            &program
                .as_deref()
                .context("adapt-program requires --program")?
                .display()
                .to_string(),
            program_input.as_deref(),
        )?,
        "prove-cairo" => {
            let proved = prove_cairo::run(
                prover_input.as_deref().context("prove-cairo requires --prover-input")?,
                params.as_deref().context("prove-cairo requires --params")?,
                proving_root.as_deref(),
                lifting_size_policy
                    .as_deref()
                    .map(|policy| policy.to_str().context("policy is not UTF-8"))
                    .transpose()?,
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
