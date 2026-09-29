use std::ffi::OsString;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use serde_json::json;
use sha2::{Digest, Sha256};
use stwo_cairo_adapter::adapter::adapt;

mod compact;
mod execution;

#[derive(Clone, Copy)]
enum InputFormat {
    Json,
    Compact,
}

const STWO_CAIRO_REVISION: &str = "82f21252a68ec006d73e299f5bf1ce6d4db0ee78";
const STWO_REVISION: &str = "7b211edde786775016ef3eecb837a6240d8fe792";
const CAIRO_VM_VERSION: &str = "3.2.0";
const EXECUTION_RUNNER_REVISION: &str = "5a7c5ede4299c91a61df19a07cba4f7502c14230";
const PIE_BOOTLOADER_SHA256: &str =
    "f6d235eb6a7f97038105ed9b6e0e083b11def61c664a17fe157135f9615efc76";
const MAX_PROGRAM_BYTES: u64 = 256 << 20;
const MAX_ARGUMENT_BYTES: u64 = 64 << 20;

enum Command {
    Identity,
    Run {
        program: PathBuf,
        program_type: execution::ProgramType,
        arguments: Option<PathBuf>,
        output: PathBuf,
        overwrite: bool,
        input_format: InputFormat,
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
                    "schema_version": 2,
                    "name": "stwo-cairo-vm-adapter",
                    "program_types": execution::PROGRAM_TYPE_NAMES,
                    "input_formats": ["json", "compact-v1"],
                    "execution_runner_revision": EXECUTION_RUNNER_REVISION,
                    "pie_bootloader_sha256": PIE_BOOTLOADER_SHA256,
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
            overwrite,
            input_format,
        } => run_program(
            program_type,
            &program,
            arguments.as_deref(),
            &output,
            overwrite,
            input_format,
        )?,
    }
    Ok(())
}

fn run_program(
    program_type: execution::ProgramType,
    program_path: &Path,
    arguments_path: Option<&Path>,
    output_path: &Path,
    overwrite: bool,
    input_format: InputFormat,
) -> Result<()> {
    let profile = std::env::var_os("STWO_CAIRO_VM_PROFILE").is_some();
    let started = std::time::Instant::now();
    let program_bytes = read_bounded_maybe_gzip(program_path, MAX_PROGRAM_BYTES)?;
    let argument_bytes = arguments_path
        .map(|path| read_bounded(path, MAX_ARGUMENT_BYTES))
        .transpose()?;
    let loaded = std::time::Instant::now();
    let execution = execution::run(program_type, &program_bytes, argument_bytes.as_deref())?;
    let executed = std::time::Instant::now();
    let mut prover_input =
        adapt(&execution.runner).context("official Stwo-Cairo adaptation failed")?;
    if let Some(public_segment_context) = execution.public_segment_context {
        prover_input.public_segment_context = public_segment_context;
    }
    prover_input.public_memory_addresses.sort_unstable();
    let adapted = std::time::Instant::now();
    if overwrite {
        write_input_overwrite(output_path, &prover_input, input_format)?;
    } else {
        write_input_new(output_path, &prover_input, input_format)?;
    }
    if profile {
        eprintln!(
            "cairo_vm_profile load_ms={:.3} execute_ms={:.3} adapt_ms={:.3} publish_ms={:.3}",
            loaded.duration_since(started).as_secs_f64() * 1000.0,
            executed.duration_since(loaded).as_secs_f64() * 1000.0,
            adapted.duration_since(executed).as_secs_f64() * 1000.0,
            adapted.elapsed().as_secs_f64() * 1000.0,
        );
    }
    Ok(())
}

/// Committed fixture programs may be gzip-compressed (`.json.gz`) to respect
/// the repository fixture budget; detection is by the gzip magic, and the
/// DECOMPRESSED size is held to the same bound as a plain program.
fn read_bounded_maybe_gzip(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let bytes = read_bounded(path, limit)?;
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Ok(bytes);
    }
    let mut decoder = flate2::read::GzDecoder::new(bytes.as_slice());
    let mut decompressed = Vec::new();
    decoder
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut decompressed)
        .with_context(|| format!("failed to decompress {}", path.display()))?;
    anyhow::ensure!(
        decompressed.len() as u64 <= limit,
        "{} exceeds the {limit}-byte limit after decompression",
        path.display()
    );
    Ok(decompressed)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let metadata = file
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
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= limit,
        "{} exceeds the {limit}-byte limit",
        path.display()
    );
    Ok(bytes)
}

/// Publish only a complete, synced input document. A unique sibling file
/// avoids collisions between adapters and is removed on serialization failure.
fn write_input_overwrite(
    path: &Path,
    value: &stwo_cairo_adapter::ProverInput,
    format: InputFormat,
) -> Result<()> {
    write_input_file(path, value, format, true)
}

fn write_input_new(
    path: &Path,
    value: &stwo_cairo_adapter::ProverInput,
    format: InputFormat,
) -> Result<()> {
    write_input_file(path, value, format, false)
}

fn write_input_file(
    path: &Path,
    value: &stwo_cairo_adapter::ProverInput,
    format: InputFormat,
    overwrite: bool,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut writer = BufWriter::with_capacity(4 << 20, temporary.as_file_mut());
        write_input(&mut writer, value, format)?;
        writer.flush().context("failed to flush ProverInput")?;
    }
    temporary
        .as_file()
        .sync_all()
        .context("failed to sync ProverInput")?;
    if overwrite {
        temporary
            .persist(path)
            .with_context(|| format!("failed to publish {}", path.display()))?;
    } else {
        temporary
            .persist_noclobber(path)
            .with_context(|| format!("refusing to replace {}", path.display()))?;
    }
    Ok(())
}

fn write_input(
    writer: &mut impl Write,
    input: &stwo_cairo_adapter::ProverInput,
    format: InputFormat,
) -> Result<()> {
    match format {
        InputFormat::Json => {
            serde_json::to_writer(writer, input).context("failed to serialize ProverInput")
        }
        InputFormat::Compact => {
            compact::write(writer, input).context("failed to encode compact ProverInput")
        }
    }
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
    let mut overwrite = false;
    let mut input_format = None;
    while let Some(flag) = args.next() {
        let flag = flag
            .into_string()
            .map_err(|_| anyhow::anyhow!("option is not valid UTF-8"))?;
        if flag == "--overwrite" {
            anyhow::ensure!(!overwrite, "duplicate option --overwrite");
            overwrite = true;
            continue;
        }
        let value = args
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?;
        match flag.as_str() {
            "--input-format" if input_format.is_none() => {
                input_format = Some(match utf8(Some(value), "missing input format")?.as_str() {
                    "json" => InputFormat::Json,
                    "compact" => InputFormat::Compact,
                    other => bail!("unsupported input format {other:?}; expected json or compact"),
                });
            }
            "--program" if program.is_none() => program = Some(PathBuf::from(value)),
            "--program-type" if program_type.is_none() => {
                program_type = Some(utf8(Some(value), "missing program type")?)
            }
            "--arguments" if arguments.is_none() => arguments = Some(PathBuf::from(value)),
            "--prover-input-out" if output.is_none() => output = Some(PathBuf::from(value)),
            "--program" | "--program-type" | "--arguments" | "--prover-input-out"
            | "--input-format" => {
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
        overwrite,
        input_format: input_format.unwrap_or(InputFormat::Json),
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
