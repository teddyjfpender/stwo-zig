//! Parity oracle for the circuit recursion lane, pinned to `starkware-libs/proving@5a7c5ed`.
//!
//! Each subcommand runs pinned upstream Rust code and emits one checkpoint that a rung of the Zig
//! parity ladder compares against. See `README.md` for the rung mapping and the digest contracts.

mod checkpoint;
mod columns;
mod compiled_air;
mod components;
mod contexts;
mod finalize;
mod gadgets;
mod goldens;
mod output;
mod primitives;
mod project_air;
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
       stwo-circuit-oracle topology --proving-root DIR [--output PATH]
       stwo-circuit-oracle verifier-stages --proving-root DIR [--output PATH]";

fn main() -> Result<()> {
    let mut values = std::env::args().skip(1);
    let subcommand = values.next().with_context(|| USAGE)?;
    let (mut output, mut proving_root) = (None, None);
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .with_context(|| format!("{flag} requires a value"))?;
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
    let bytes = match subcommand.as_str() {
        "primitives" | "gadgets" | "finalize" if proving_root.is_some() => {
            bail!("{subcommand} does not read upstream data; drop --proving-root")
        }
        "primitives" => output::json(&primitives::run()?)?,
        "gadgets" => output::json(&gadgets::run()?)?,
        "finalize" => output::json(&finalize::run()?)?,
        "components" => output::json(&components::run(root()?)?)?,
        "statement-trace" => output::json(&components::statement_trace::run(root()?)?)?,
        "project-air" => project_air::run(root()?)?,
        "topology" => output::json(&topology::run(root()?)?)?,
        "verifier-stages" => output::json(&verifier_stages::run(root()?)?)?,
        other => bail!("unknown subcommand {other:?}\n{USAGE}"),
    };
    output::emit(output.as_deref(), &bytes)
}
