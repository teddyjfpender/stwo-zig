//! Cairo-0 compiled JSON execution retained for official Stwo-Cairo fixtures.

use anyhow::{Context, Result};
use cairo_vm::cairo_run::{CairoRunConfig, cairo_run_program_with_initial_scope};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::hint_processor::hint_processor_definition::HintProcessor;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::program::Program;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;

pub fn run(
    program_bytes: &[u8],
    argument_bytes: Option<&[u8]>,
    config: &CairoRunConfig,
) -> Result<CairoRunner> {
    let program = Program::from_bytes(program_bytes, Some("main"))
        .context("failed to decode compiled Cairo JSON program")?;
    let mut scopes = ExecutionScopes::new();
    if let Some(argument_bytes) = argument_bytes {
        let arguments = std::str::from_utf8(argument_bytes)
            .context("legacy Cairo JSON arguments are not valid UTF-8")?
            .to_owned();
        scopes.insert_value("program_input", arguments);
    }
    scopes.insert_value("program_object", program.clone());
    let mut hints = Box::new(BuiltinHintProcessor::new_empty()) as Box<dyn HintProcessor>;
    cairo_run_program_with_initial_scope(&program, config, hints.as_mut(), scopes)
        .context("official Cairo VM JSON execution failed")
}
