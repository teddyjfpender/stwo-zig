//! `adapt-program`: steps 1-2 of `crates/leaf_prover/src/prove_leaf.rs` (`prove_leaf`) at
//! proving@5a7c5ed. Runs a compiled Cairo program in the Cairo VM with the leaf prover's run
//! configuration (layout `all_cairo_stwo`, proof mode, no trace padding, no VM relocation) and
//! adapts the runner into the `ProverInput` that `prove-cairo` and the Zig leaf lane prove. The
//! program is read from the `proving` checkout, and its optional input file (`--program_input` of
//! `leaf-prover`, for example a bootloader's task list) from anywhere; the output is the
//! `ProverInput` serde JSON with `public_memory_addresses` sorted.

use anyhow::{Context, Result};
use cairo_program_runner_lib::cairo_run_program;
use cairo_program_runner_lib::utils::{get_cairo_run_config, get_program_input_from_path};
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use stwo_cairo_adapter::adapter::adapt;

use crate::upstream::ProvingRoot;

pub fn run(
    proving_root: &std::path::Path,
    program: &str,
    program_input: Option<&std::path::Path>,
    compact_output: bool,
    public_output: Option<&std::path::Path>,
) -> Result<Vec<u8>> {
    let mut checkout = ProvingRoot::open(proving_root)?;
    let bytes = checkout.read(program)?;
    let program = Program::from_bytes(&bytes, Some("main")).context("invalid compiled program")?;
    let config = get_cairo_run_config(&None, LayoutName::all_cairo_stwo, true, true, true, false)
        .map_err(|error| anyhow::anyhow!("invalid run configuration: {error:?}"))?;
    // As `prove_leaf_from_files`: the input file is only wrapped here and read by the run.
    let program_input =
        get_program_input_from_path(&program_input.map(std::path::Path::to_path_buf))
            .map_err(|error| anyhow::anyhow!("invalid program input: {error:?}"))?;
    let runner = cairo_run_program(&program, program_input, config, None)
        .map_err(|error| anyhow::anyhow!("Cairo run failed: {error:?}"))?;
    let mut prover_input = adapt(&runner).context("adapter failed")?;
    if let Some(path) = public_output {
        let segment = prover_input
            .builtin_segments
            .output
            .context("adapted Cairo execution lacks an output segment")?;
        let values: Vec<_> = (segment.begin_addr..segment.stop_ptr)
            .map(|address| {
                let words = prover_input.memory.get(address as u32).as_u256();
                let highest = words.iter().rposition(|word| *word != 0).unwrap_or(0);
                let mut value = format!("0x{:x}", words[highest]);
                for word in words[..highest].iter().rev() {
                    use std::fmt::Write;
                    write!(&mut value, "{word:08x}").expect("write into string");
                }
                value
            })
            .collect();
        crate::output::emit(Some(path), &crate::output::json(&values)?)?;
    }
    // The adapter collects the public memory addresses through a hash map, so their order
    // changes from run to run; the proof does not depend on it (prove-cairo emits the same bytes
    // for every order observed). Sorted, the fixture is reproducible.
    prover_input.public_memory_addresses.sort_unstable();
    if compact_output {
        let mut bytes = Vec::new();
        crate::compact::write(&mut bytes, &prover_input)
            .context("failed to encode compact ProverInput")?;
        return Ok(bytes);
    }
    let mut json = serde_json::to_vec(&prover_input).context("failed to encode ProverInput")?;
    json.push(b'\n');
    Ok(json)
}

/// Re-encode an already adapted official JSON input without rerunning Cairo.
/// This is a transport conversion: the Zig frontend re-admits the compact
/// bytes and full proof parity is checked by the pipeline benchmark.
pub fn convert_input(path: &std::path::Path) -> Result<Vec<u8>> {
    const MAX_BYTES: u64 = 2 << 30;
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let size = file.metadata()?.len();
    anyhow::ensure!(
        size > 0 && size <= MAX_BYTES,
        "adapted input size is outside bounds"
    );
    let input: stwo_cairo_adapter::ProverInput =
        serde_json::from_reader(file).context("failed to decode official ProverInput JSON")?;
    let mut bytes = Vec::new();
    crate::compact::write(&mut bytes, &input).context("failed to encode compact ProverInput")?;
    Ok(bytes)
}
