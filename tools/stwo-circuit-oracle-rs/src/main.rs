//! Parity oracle for the circuit recursion lane, pinned to `starkware-libs/proving@5a7c5ed`.
//!
//! Each subcommand runs pinned upstream Rust code and emits one checkpoint that a rung of the Zig
//! parity ladder compares against. See `README.md` for the rung mapping and the digest contracts.

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
mod output;
mod primitives;
mod project_air;
mod prove_small;
mod topology;
mod upstream;
mod verifier_stages;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

const USAGE: &str = "usage: stwo-circuit-oracle primitives [--output PATH]
       stwo-circuit-oracle gadgets [--output PATH]
       stwo-circuit-oracle components --proving-root DIR [--output PATH]
       stwo-circuit-oracle statement-trace --proving-root DIR [--output PATH]
       stwo-circuit-oracle project-air --proving-root DIR [--output PATH]
       stwo-circuit-oracle finalize [--output PATH]
       stwo-circuit-oracle prove-small [--memory-budget BYTES] [--output PATH]
       stwo-circuit-oracle air-programs [--output PATH]
       stwo-circuit-oracle topology --proving-root DIR [--output PATH]
       stwo-circuit-oracle verifier-stages --proving-root DIR [--output PATH]
       stwo-circuit-oracle cairo-statement --proving-root DIR [--output PATH]";

fn main() -> Result<()> {
    let mut values = std::env::args().skip(1);
    let subcommand = values.next().with_context(|| USAGE)?;
    let (mut output, mut proving_root, mut memory_budget) = (None, None, None);
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
    if memory_budget.is_some() && subcommand != "prove-small" {
        bail!("--memory-budget applies only to prove-small");
    }
    let bytes = match subcommand.as_str() {
        "primitives" | "gadgets" | "finalize" | "prove-small" | "air-programs"
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
        "components" => output::json(&components::run(root()?)?)?,
        "statement-trace" => output::json(&components::statement_trace::run(root()?)?)?,
        "project-air" => project_air::run(root()?)?,
        "air-programs" => air_programs::run()?,
        "topology" => output::json(&topology::run(root()?)?)?,
        "verifier-stages" => output::json(&verifier_stages::run(root()?)?)?,
        "cairo-statement" => output::json(&cairo_statement::run(root()?)?)?,
        other => bail!("unknown subcommand {other:?}\n{USAGE}"),
    };
    output::emit(output.as_deref(), &bytes)
}
