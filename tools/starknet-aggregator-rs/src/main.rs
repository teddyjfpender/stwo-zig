//! Run the Starknet aggregator (`core/aggregator/main.cairo`) over contiguous
//! Starknet OS leaf PIEs and write the aggregator's Cairo PIE.
//!
//! The aggregator's input is the leaves' outputs in simple-bootloader format:
//! `[n_tasks, (output_size, os_program_hash, os_output...) ...]`. In production
//! those outputs are vouched for by verifying the leaf proofs; here they are read
//! straight from the leaf PIEs, which is enough to execute and prove the
//! aggregator program itself.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use apollo_starknet_os_program::PROGRAM_HASHES;
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use clap::Parser;
use starknet_os::hint_processor::aggregator_hint_processor::{AggregatorInput, DataAvailability};
use starknet_os::runner::run_aggregator;
use starknet_types_core::felt::Felt;

/// Mainnet STRK fee token, as used by SNOS for the OS chain info.
const STRK_FEE_TOKEN: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

#[derive(Parser)]
struct Args {
    /// Leaf PIE zips, in block order.
    #[arg(long, num_args = 1.., required = true)]
    leaves: Vec<PathBuf>,
    /// Where to write the aggregator PIE zip.
    #[arg(long)]
    output: PathBuf,
    /// Also write the aggregator's program output (JSON array of hex felts).
    #[arg(long)]
    program_output: Option<PathBuf>,
    /// Emit the full state diff (default: compressed, as on L1).
    #[arg(long)]
    full_output: bool,
    #[arg(long, default_value = "SN_MAIN")]
    chain_id: String,
    #[arg(long, default_value = "all_cairo")]
    layout: String,
}

fn os_output(pie_path: &Path) -> Result<Vec<Felt>> {
    let pie = CairoPie::read_zip_file(pie_path).with_context(|| format!("read {}", pie_path.display()))?;
    let seg = pie
        .metadata
        .builtin_segments
        .get(&BuiltinName::output)
        .context("PIE has no output segment")?;
    let mut cells: Vec<(usize, Felt)> = pie
        .memory
        .0
        .iter()
        .filter(|((s, _), _)| *s == seg.index as usize)
        .map(|((_, off), v)| match v {
            MaybeRelocatable::Int(f) => Ok((*off, *f)),
            _ => bail!("relocatable value in output segment"),
        })
        .collect::<Result<_>>()?;
    cells.sort_by_key(|(off, _)| *off);
    if cells.len() != seg.size || cells.iter().enumerate().any(|(i, (off, _))| i != *off) {
        bail!("output segment of {} is not dense ({} cells, size {})", pie_path.display(), cells.len(), seg.size);
    }
    Ok(cells.into_iter().map(|(_, v)| v).collect())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let os_hash = PROGRAM_HASHES.os;
    let mut bootloader_output = vec![Felt::from(args.leaves.len())];
    for leaf in &args.leaves {
        let out = os_output(leaf)?;
        eprintln!("{}: {} output felts, blocks {}..{}", leaf.display(), out.len(), out[2], out[3]);
        bootloader_output.push(Felt::from(out.len() + 2));
        bootloader_output.push(os_hash);
        bootloader_output.extend(out);
    }
    let chain_id = Felt::from_bytes_be_slice(args.chain_id.as_bytes());
    let input = AggregatorInput {
        bootloader_output: Some(bootloader_output),
        full_output: args.full_output,
        da: DataAvailability::CallData,
        debug_mode: false,
        fee_token_address: Felt::from_hex(STRK_FEE_TOKEN)?,
        chain_id,
        public_keys: None,
    };
    let layout = match args.layout.as_str() {
        "all_cairo" => LayoutName::all_cairo,
        "all_cairo_stwo" => LayoutName::all_cairo_stwo,
        other => bail!("unsupported layout {other}"),
    };
    let started = std::time::Instant::now();
    let out = run_aggregator(layout, input).map_err(|e| anyhow::anyhow!("aggregator failed: {e:?}"))?;
    eprintln!(
        "aggregator: {} steps, {} output felts, {:.2}s",
        out.cairo_pie.execution_resources.n_steps,
        out.aggregator_output.len(),
        started.elapsed().as_secs_f64()
    );
    out.cairo_pie.write_zip_file(&args.output, true)?;
    if let Some(path) = args.program_output {
        let hex: Vec<String> = out.aggregator_output.iter().map(|f| format!("{f:#x}")).collect();
        std::fs::write(path, serde_json::to_string(&hex)?)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "leaves": args.leaves.len(),
            "n_steps": out.cairo_pie.execution_resources.n_steps,
            "builtins": out.cairo_pie.execution_resources.builtin_instance_counter,
            "output_felts": out.aggregator_output.len(),
            "os_program_hash": format!("{os_hash:#x}"),
            "aggregator_program_hash": format!("{:#x}", PROGRAM_HASHES.aggregator),
        })
    );
    Ok(())
}
