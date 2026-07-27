use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use serde_json::json;
use sha2::{Digest, Sha256};
use stwo_cairo_adapter::adapter::adapt;

mod execution;

const STWO_CAIRO_REVISION: &str = "82f21252a68ec006d73e299f5bf1ce6d4db0ee78";
const STWO_REVISION: &str = "7b211edde786775016ef3eecb837a6240d8fe792";
const CAIRO_VM_VERSION: &str = "3.2.0";
const MAX_PROGRAM_BYTES: u64 = 256 << 20;
const MAX_ARGUMENT_BYTES: u64 = 64 << 20;

enum Command {
    Identity,
    Run {
        program: PathBuf,
        program_type: execution::ProgramType,
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
                    "program_types": execution::PROGRAM_TYPE_NAMES,
                    "layout": "all_cairo_stwo",
                    "cairo_vm_version": CAIRO_VM_VERSION,
                    "cairo_language_version": execution::CAIRO_LANGUAGE_VERSION,
                    "stwo_cairo_revision": STWO_CAIRO_REVISION,
                    "stwo_revision": STWO_REVISION,
                    "executable_sha256": sha256_file(&executable)?,
                }),
            )?;
            println!();
        }
        Command::Run {
            program,
            program_type,
            arguments,
            output,
        } => run_program(program_type, &program, arguments.as_deref(), &output)?,
    }
    Ok(())
}

fn run_program(
    program_type: execution::ProgramType,
    program_path: &Path,
    arguments_path: Option<&Path>,
    output_path: &Path,
) -> Result<()> {
    let program_bytes = read_bounded(program_path, MAX_PROGRAM_BYTES)?;
    let argument_bytes = arguments_path
        .map(|path| read_bounded(path, MAX_ARGUMENT_BYTES))
        .transpose()?;
    let execution = execution::run(program_type, &program_bytes, argument_bytes.as_deref())?;
    let mut prover_input =
        adapt(&execution.runner).context("official Stwo-Cairo adaptation failed")?;
    if let Some(public_segment_context) = execution.public_segment_context {
        prover_input.public_segment_context = public_segment_context;
    }
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
    let program_type = execution::ProgramType::parse(program_type.as_deref().unwrap_or("json"))?;
    Ok(Command::Run {
        program: program.ok_or_else(|| anyhow::anyhow!("missing --program"))?,
        program_type,
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
                ["run", "--program", "p.json", "--program-type", "sierra"]
                    .into_iter()
                    .map(OsString::from)
            )
            .is_err()
        );
        assert!(matches!(
            parse_args(
                [
                    "run",
                    "--program",
                    "p.json",
                    "--program-type",
                    "executable",
                    "--prover-input-out",
                    "out.json",
                ]
                .into_iter()
                .map(OsString::from)
            )
            .unwrap(),
            Command::Run {
                program_type: execution::ProgramType::Executable,
                ..
            }
        ));
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
