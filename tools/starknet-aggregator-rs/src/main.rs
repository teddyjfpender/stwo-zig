//! Run the Starknet aggregator (`core/aggregator/main.cairo`) over contiguous
//! Starknet OS leaf PIEs and write the aggregator's Cairo PIE.
//!
//! The aggregator's input is the leaves' outputs in simple-bootloader format:
//! `[n_tasks, (output_size, os_program_hash, os_output...) ...]`. In production
//! those outputs are vouched for by verifying the leaf proofs. For a circuit
//! root, the packed public preimages are sufficient to run this aggregator:
//! the final circuit-applicative Cairo proof checks that it consumed precisely
//! those preimages and that their tree root was verified. ZIPs are optional
//! cross-check inputs, not a requirement to rebuild the aggregator task.

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
    /// Optional leaf PIE zips, in block order, for cross-checking a packed tree.
    #[arg(long, num_args = 1..)]
    leaves: Vec<PathBuf>,
    /// Where to write the aggregator PIE zip.
    #[arg(long)]
    output: PathBuf,
    /// Also write the aggregator's program output (JSON array of hex felts).
    #[arg(long)]
    program_output: Option<PathBuf>,
    /// Recursive circuit root's packed tree. With no ZIPs, its ordered public
    /// preimages supply the aggregator input directly; with ZIPs, they must match.
    #[arg(long)]
    packed_output: Option<PathBuf>,
    /// Ordered, already admitted leaf output preimages. This allows the
    /// aggregator to run while the circuit tree is still being proved.
    #[arg(long, conflicts_with = "packed_output")]
    preimages: Option<PathBuf>,
    /// Emit the full state diff (default: compressed, as on L1).
    #[arg(long)]
    full_output: bool,
    #[arg(long, default_value = "SN_MAIN")]
    chain_id: String,
    #[arg(long, default_value = "all_cairo")]
    layout: String,
}

fn os_output(pie_path: &Path) -> Result<Vec<Felt>> {
    let pie = CairoPie::read_zip_file(pie_path)
        .with_context(|| format!("read {}", pie_path.display()))?;
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
        bail!(
            "output segment of {} is not dense ({} cells, size {})",
            pie_path.display(),
            cells.len(),
            seg.size
        );
    }
    Ok(cells.into_iter().map(|(_, v)| v).collect())
}

fn packed_preimages(path: &Path) -> Result<Vec<Vec<Felt>>> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let root: serde_json::Value = serde_json::from_slice(&bytes)?;
    let mut leaves = Vec::new();
    collect_preimages(&root, &mut leaves, 0)?;
    if leaves.is_empty() {
        bail!("packed tree has no leaves");
    }
    Ok(leaves)
}

fn ordered_preimages(path: &Path) -> Result<Vec<Vec<Felt>>> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let encoded: Vec<Vec<String>> = serde_json::from_slice(&bytes)?;
    if encoded.is_empty() || encoded.len() > 4096 {
        bail!("preimage count must be 1..4096");
    }
    encoded
        .into_iter()
        .map(|preimage| {
            if preimage.is_empty() {
                bail!("empty leaf preimage");
            }
            preimage
                .into_iter()
                .map(|value| {
                    Felt::from_dec_str(&value)
                        .with_context(|| format!("invalid preimage felt {value}"))
                })
                .collect::<Result<Vec<_>>>()
        })
        .collect()
}

fn collect_preimages(
    node: &serde_json::Value,
    leaves: &mut Vec<Vec<Felt>>,
    depth: usize,
) -> Result<()> {
    if depth > 32 {
        bail!("packed tree exceeds maximum depth");
    }
    let composite = node
        .get("Composite")
        .context("expected a packed Composite node")?;
    let children = composite
        .get("subtasks")
        .and_then(serde_json::Value::as_array)
        .context("packed Composite has no subtasks")?;
    if children.len() == 1 && children[0].get("Plain").is_some() {
        let preimage = children[0]["Plain"]["output_preimage"]
            .as_array()
            .context("packed leaf has no output preimage")?;
        if preimage.is_empty() {
            bail!("packed leaf has an empty output preimage");
        }
        let parsed = preimage
            .iter()
            .map(|value| {
                let text = value
                    .as_str()
                    .context("packed preimage felt is not a decimal string")?;
                Felt::from_dec_str(text)
                    .with_context(|| format!("invalid packed preimage felt {text}"))
            })
            .collect::<Result<Vec<_>>>()?;
        leaves.push(parsed);
        return Ok(());
    }
    if children.is_empty() || children.len() > 2 {
        bail!("packed internal node has invalid arity");
    }
    for child in children {
        collect_preimages(child, leaves, depth + 1)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let os_hash = PROGRAM_HASHES.os;
    let packed = args
        .packed_output
        .as_deref()
        .map(packed_preimages)
        .transpose()?;
    let preimages = args
        .preimages
        .as_deref()
        .map(ordered_preimages)
        .transpose()?;
    let revealed = packed.as_ref().or(preimages.as_ref());
    if args.leaves.is_empty() && revealed.is_none() {
        bail!("provide --packed-output or --preimages, with optional --leaves for cross-checking");
    }
    if let Some(preimages) = revealed {
        if !args.leaves.is_empty() && preimages.len() != args.leaves.len() {
            bail!(
                "preimage input contains {} leaves, but {} OS PIEs were supplied",
                preimages.len(),
                args.leaves.len()
            );
        }
    }
    let n_leaves = revealed.map_or(args.leaves.len(), Vec::len);
    if n_leaves > 4096 {
        bail!("aggregator input exceeds the 4096-leaf circuit-applicative bound");
    }
    let mut bootloader_output = vec![Felt::from(n_leaves)];
    for index in 0..n_leaves {
        let out = if let Some(leaf) = args.leaves.get(index) {
            os_output(leaf)?
        } else {
            let preimage = &revealed.expect("preimage source required")[index];
            if preimage.len() < 5 || preimage[0] != os_hash {
                bail!(
                    "packed public preimage {} has an invalid OS program hash or output",
                    index
                );
            }
            preimage[1..].to_vec()
        };
        if out.len() < 4 {
            bail!(
                "OS output for PIE {} is too short for block continuity",
                index
            );
        }
        if let Some(preimages) = revealed {
            if preimages[index].len() != out.len() + 1
                || preimages[index][0] != os_hash
                || &preimages[index][1..] != out.as_slice()
            {
                bail!(
                    "packed public preimage for PIE {} differs from the aggregator input",
                    index
                );
            }
        }
        eprintln!(
            "PIE {}: {} output felts, blocks {}..{}",
            index,
            out.len(),
            out[2],
            out[3]
        );
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
    let out =
        run_aggregator(layout, input).map_err(|e| anyhow::anyhow!("aggregator failed: {e:?}"))?;
    eprintln!(
        "aggregator: {} steps, {} output felts, {:.2}s",
        out.cairo_pie.execution_resources.n_steps,
        out.aggregator_output.len(),
        started.elapsed().as_secs_f64()
    );
    out.cairo_pie.write_zip_file(&args.output, true)?;
    if let Some(path) = args.program_output {
        let hex: Vec<String> = out
            .aggregator_output
            .iter()
            .map(|f| format!("{f:#x}"))
            .collect();
        std::fs::write(path, serde_json::to_string(&hex)?)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "leaves": n_leaves,
            "n_steps": out.cairo_pie.execution_resources.n_steps,
            "builtins": out.cairo_pie.execution_resources.builtin_instance_counter,
            "output_felts": out.aggregator_output.len(),
            "os_program_hash": format!("{os_hash:#x}"),
            "aggregator_program_hash": format!("{:#x}", PROGRAM_HASHES.aggregator),
            "input_source": if args.leaves.is_empty() {
                if args.packed_output.is_some() { "packed_output" } else { "ordered_preimages" }
            } else { "pie_zips" },
            "packed_preimages_matched": if args.leaves.is_empty() { None } else { packed.as_ref().map(Vec::len) },
        })
    );
    Ok(())
}
