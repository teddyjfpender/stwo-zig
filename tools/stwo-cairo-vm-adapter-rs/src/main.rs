use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use cairo_vm::cairo_run::{CairoRunConfig, cairo_run_program_with_initial_scope};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::hint_processor::hint_processor_definition::HintProcessor;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use serde_json::json;
use sha2::{Digest, Sha256};
use stwo_cairo_adapter::adapter::adapt;

const STWO_CAIRO_REVISION: &str = "82f21252a68ec006d73e299f5bf1ce6d4db0ee78";
const STWO_REVISION: &str = "7b211edde786775016ef3eecb837a6240d8fe792";
const CAIRO_VM_VERSION: &str = "3.2.0";
const MAX_PROGRAM_BYTES: u64 = 256 << 20;
const MAX_ARGUMENT_BYTES: u64 = 64 << 20;

enum Command {
    Identity,
    Run {
        program: PathBuf,
        arguments: Option<PathBuf>,
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("stwo-cairo-vm-adapter: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<()> {
    match parse_args(std::env::args_os().skip(1))? {
        Command::Identity => {
            let executable = std::env::current_exe().context("failed to locate executable")?;
            serde_json::to_writer(
                std::io::stdout().lock(),
                &json!({
                    "schema_version": 1,
                    "name": "stwo-cairo-vm-adapter",
                    "program_types": ["json"],
                    "layout": "all_cairo_stwo",
                    "cairo_vm_version": CAIRO_VM_VERSION,
                    "stwo_cairo_revision": STWO_CAIRO_REVISION,
                    "stwo_revision": STWO_REVISION,
                    "executable_sha256": sha256_file(&executable)?,
                }),
            )?;
            println!();
        }
        Command::Run {
            program,
            arguments,
            output,
        } => run_json_program(&program, arguments.as_deref(), &output)?,
    }
    Ok(())
}

fn run_json_program(
    program_path: &Path,
    arguments_path: Option<&Path>,
    output_path: &Path,
) -> Result<()> {
    let program_bytes = read_bounded(program_path, MAX_PROGRAM_BYTES)?;
    let program = Program::from_bytes(&program_bytes, Some("main"))
        .context("failed to decode compiled Cairo JSON program")?;
    let mut scopes = ExecutionScopes::new();
    if let Some(arguments_path) = arguments_path {
        let arguments = read_bounded(arguments_path, MAX_ARGUMENT_BYTES)?;
        let arguments = String::from_utf8(arguments)
            .context("legacy Cairo JSON arguments are not valid UTF-8")?;
        scopes.insert_value("program_input", arguments);
    }
    scopes.insert_value("program_object", program.clone());
    let mut hints = Box::new(BuiltinHintProcessor::new_empty()) as Box<dyn HintProcessor>;
    let config = CairoRunConfig {
        trace_enabled: true,
        relocate_trace: false,
        layout: LayoutName::all_cairo_stwo,
        fill_holes: true,
        proof_mode: true,
        disable_trace_padding: true,
        ..Default::default()
    };
    let runner = cairo_run_program_with_initial_scope(&program, &config, hints.as_mut(), scopes)
        .context("official Cairo VM execution failed")?;
    let mut prover_input = adapt(&runner).context("official Stwo-Cairo adaptation failed")?;
    prover_input.public_memory_addresses.sort_unstable();
    write_json_new(output_path, &prover_input)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = path
        .metadata()
        .with_context(|| format!("failed to stat {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= limit,
        "{} exceeds the {limit}-byte limit",
        path.display()
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(bytes)
}

fn write_json_new(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("refusing to replace {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value).context("failed to serialize ProverInput")?;
    file.sync_all().context("failed to sync ProverInput")
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = read_bounded(path, u64::MAX)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn parse_args<I>(mut args: I) -> Result<Command>
where
    I: Iterator<Item = OsString>,
{
    let command = utf8(args.next(), "missing command")?;
    match command.as_str() {
        "identity" => {
            anyhow::ensure!(args.next().is_none(), "identity accepts no arguments");
            Ok(Command::Identity)
        }
        "run" => parse_run_args(args),
        _ => bail!("unknown command {command:?}; expected identity or run"),
    }
}

fn parse_run_args<I>(mut args: I) -> Result<Command>
where
    I: Iterator<Item = OsString>,
{
    let mut program = None;
    let mut program_type = None;
    let mut arguments = None;
    let mut output = None;
    while let Some(flag) = args.next() {
        let flag = flag
            .into_string()
            .map_err(|_| anyhow::anyhow!("option is not valid UTF-8"))?;
        let value = args
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?;
        match flag.as_str() {
            "--program" if program.is_none() => program = Some(PathBuf::from(value)),
            "--program-type" if program_type.is_none() => {
                program_type = Some(utf8(Some(value), "missing program type")?)
            }
            "--arguments" if arguments.is_none() => arguments = Some(PathBuf::from(value)),
            "--prover-input-out" if output.is_none() => output = Some(PathBuf::from(value)),
            "--program" | "--program-type" | "--arguments" | "--prover-input-out" => {
                bail!("duplicate option {flag}")
            }
            _ => bail!("unknown option {flag}"),
        }
    }
    let program_type = program_type.unwrap_or_else(|| "json".to_owned());
    anyhow::ensure!(
        program_type == "json",
        "unsupported program type {program_type:?}; expected json"
    );
    Ok(Command::Run {
        program: program.ok_or_else(|| anyhow::anyhow!("missing --program"))?,
        arguments,
        output: output.ok_or_else(|| anyhow::anyhow!("missing --prover-input-out"))?,
    })
}

fn utf8(value: Option<OsString>, missing: &str) -> Result<String> {
    value
        .ok_or_else(|| anyhow::anyhow!("{missing}"))?
        .into_string()
        .map_err(|_| anyhow::anyhow!("argument is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_unknown_program_types_and_duplicate_paths() {
        assert!(
            parse_args(
                ["run", "--program", "p.json", "--program-type", "executable"]
                    .into_iter()
                    .map(OsString::from)
            )
            .is_err()
        );
        assert!(
            parse_args(
                [
                    "run",
                    "--program",
                    "a.json",
                    "--program",
                    "b.json",
                    "--prover-input-out",
                    "out.json",
                ]
                .into_iter()
                .map(OsString::from)
            )
            .is_err()
        );
    }
}
