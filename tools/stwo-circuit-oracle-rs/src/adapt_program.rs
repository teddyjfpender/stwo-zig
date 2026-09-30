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
    // The adapter collects the public memory addresses through a hash map, so their order
    // changes from run to run; the proof does not depend on it (prove-cairo emits the same bytes
    // for every order observed). Sorted, the fixture is reproducible.
    prover_input.public_memory_addresses.sort_unstable();
    let mut json = serde_json::to_vec(&prover_input).context("failed to encode ProverInput")?;
    json.push(b'\n');
    Ok(json)
}
