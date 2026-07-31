//! Cairo-0 compiled JSON execution retained for official Stwo-Cairo fixtures.

use std::collections::HashMap;
use std::rc::Rc;

use anyhow::{Context, Result};
use cairo_vm::Felt252;
use cairo_vm::cairo_run::{CairoRunConfig, cairo_run_program_with_initial_scope};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::insert_value_from_var_name;
use cairo_vm::hint_processor::hint_processor_definition::HintProcessor;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::program::Program;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;

/// The one non-builtin hint this sidecar accepts, byte-for-byte: the
/// zkvm-benchmarks Cairo-0 corpus (`vectors/cairo/cairo_program_matrix.json`
/// pins each source by SHA-256) reads its single scalar input with exactly
/// this line. The match is on the full hint string, the input must be a JSON
/// object with a non-negative integer `iterations`, and every other unknown
/// hint still fails closed.
const PROGRAM_INPUT_ITERATIONS_HINT: &str = "ids.iterations = program_input['iterations']";

fn program_input_iterations_hint() -> HintFunc {
    HintFunc(Box::new(|vm, scopes, ids_data, ap_tracking, _constants| {
        let raw: String = scopes.get::<String>("program_input")?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|error| {
            HintError::CustomHint(
                format!("program_input is not valid JSON: {error}").into_boxed_str(),
            )
        })?;
        let iterations = parsed
            .get("iterations")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                HintError::CustomHint(
                    "program_input.iterations must be a non-negative integer"
                        .to_string()
                        .into_boxed_str(),
                )
            })?;
        insert_value_from_var_name(
            "iterations",
            Felt252::from(iterations),
            vm,
            ids_data,
            ap_tracking,
        )
    }))
}

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
    let mut extra_hints: HashMap<String, Rc<HintFunc>> = HashMap::new();
    extra_hints.insert(
        PROGRAM_INPUT_ITERATIONS_HINT.to_string(),
        Rc::new(program_input_iterations_hint()),
    );
    let mut hints = Box::new(BuiltinHintProcessor::new(
        extra_hints,
        Default::default(),
    )) as Box<dyn HintProcessor>;
    cairo_run_program_with_initial_scope(&program, config, hints.as_mut(), scopes)
        .context("official Cairo VM JSON execution failed")
}
