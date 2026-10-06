//! Run the pinned two-output-cell circuit leaf bootloader on a Cairo1 task.

use super::CompletedExecution;
use anyhow::{Context, Result, ensure};
use cairo_program_runner_lib::ProgramInput;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::program::Program;
use stwo_cairo_adapter::PublicSegmentContext;

const BOOTLOADER: &[u8] = include_bytes!(
    "../../../../vectors/circuit/official/programs/leaf_simple_bootloader_compiled.json"
);

pub fn run(
    program_bytes: &[u8],
    argument_bytes: Option<&[u8]>,
    config: CairoRunConfig<'_>,
) -> Result<CompletedExecution> {
    ensure!(program_bytes == BOOTLOADER, "circuit leaf bootloader bytes are not pinned");
    let input = std::str::from_utf8(
        argument_bytes.context("leaf bootloader requires --arguments with its task input")?,
    )
    .context("leaf bootloader input is not UTF-8 JSON")?
    .to_owned();
    let program = Program::from_bytes(BOOTLOADER, Some("main"))
        .context("invalid pinned circuit leaf bootloader")?;
    let context = PublicSegmentContext::new(&program.iter_builtins().cloned().collect::<Vec<_>>());
    let runner = cairo_program_runner_lib::cairo_run_program(
        &program,
        Some(ProgramInput::Json(input)),
        config,
        None,
    )
    .context("pinned circuit leaf bootloader execution failed")?;
    Ok(CompletedExecution {
        runner,
        public_segment_context: Some(context),
    })
}
