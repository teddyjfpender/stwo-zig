//! Modern Cairo `Executable` artifact execution through the official runner.

use anyhow::Context;
use cairo_lang_executable::executable::{EntryPointKind, Executable};
use cairo_lang_execute_utils::program_and_hints_from_executable;
use cairo_lang_runner::{Arg, CairoHintProcessor};
use cairo_lang_utils::bigint::BigUintAsHex;
use cairo_vm::cairo_run::{CairoRunConfig, cairo_run_program};
use stwo_cairo_adapter::PublicSegmentContext;

use super::CompletedExecution;

pub fn run(
    program_bytes: &[u8],
    argument_bytes: Option<&[u8]>,
    config: &CairoRunConfig,
) -> anyhow::Result<CompletedExecution> {
    let executable: Executable = serde_json::from_slice(program_bytes)
        .context("failed to decode modern Cairo executable artifact")?;
    let entrypoint = executable
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.kind == EntryPointKind::Standalone)
        .context("Cairo executable has no standalone entrypoint")?;
    let (program, string_to_hint) = program_and_hints_from_executable(&executable, entrypoint)?;
    let builtins = program.iter_builtins().cloned().collect::<Vec<_>>();
    let serialized_arguments: Vec<BigUintAsHex> = match argument_bytes {
        Some(bytes) => serde_json::from_slice(bytes)
            .context("Cairo executable arguments must be a JSON array of hex felts")?,
        None => Vec::new(),
    };
    let user_arguments = serialized_arguments
        .into_iter()
        .map(|value| Arg::Value(value.value.into()))
        .collect();
    let mut hints = CairoHintProcessor {
        runner: None,
        user_args: vec![vec![Arg::Array(user_arguments)]],
        string_to_hint,
        starknet_state: Default::default(),
        run_resources: Default::default(),
        syscalls_used_resources: Default::default(),
        no_temporary_segments: false,
        markers: Default::default(),
        panic_traceback: Default::default(),
    };
    Ok(CompletedExecution {
        runner: cairo_run_program(&program, config, &mut hints)
            .context("official Cairo VM executable execution failed")?,
        public_segment_context: Some(PublicSegmentContext::new(&builtins)),
    })
}
