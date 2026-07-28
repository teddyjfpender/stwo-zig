mod checkpoint;
mod interaction;

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo_cairo_adapter::ProverInput;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTrace;
use stwo_cairo_prover::witness::cairo::create_cairo_claim_generator;

struct Arguments {
    mode: Mode,
    input: PathBuf,
    output: Option<PathBuf>,
}

enum Mode {
    Base,
    Interaction,
}

fn arguments() -> Result<Arguments> {
    let mut values = std::env::args_os().skip(1);
    let first = values
        .next()
        .map(PathBuf::from)
        .context(
            "usage: stwo-cairo-trace-oracle INPUT.json [OUTPUT.json]\n       stwo-cairo-trace-oracle interaction INPUT.json [OUTPUT.json]",
        )?;
    let (mode, input) = if first == Path::new("interaction") {
        let input = values
            .next()
            .map(PathBuf::from)
            .context("interaction mode requires an input path")?;
        (Mode::Interaction, input)
    } else {
        (Mode::Base, first)
    };
    let output = values.next().map(PathBuf::from);
    if values.next().is_some() {
        bail!("too many arguments");
    }
    Ok(Arguments {
        mode,
        input,
        output,
    })
}

fn serialize(mut writer: impl Write, checkpoint: &impl Serialize) -> Result<()> {
    serde_json::to_writer_pretty(&mut writer, checkpoint).context("failed to write checkpoint")?;
    writer.write_all(b"\n")?;
    writer.flush().context("failed to flush checkpoint")
}

struct PendingFile {
    path: PathBuf,
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn create_pending(output: &Path) -> Result<(PendingFile, File)> {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = output.file_name().context("output path has no file name")?;
    for _ in 0..1_000 {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            id
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((PendingFile { path }, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create checkpoint temporary file"),
        }
    }
    bail!("unable to allocate a unique checkpoint temporary file")
}

fn publish_checkpoint(output: &Path, checkpoint: &impl Serialize) -> Result<()> {
    let (pending, file) = create_pending(output)?;
    {
        let writer = BufWriter::new(&file);
        serialize(writer, checkpoint)?;
    }
    file.sync_all().context("failed to sync checkpoint")?;
    std::fs::hard_link(&pending.path, output)
        .with_context(|| format!("refusing to replace {}", output.display()))?;
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn write_checkpoint(output: Option<&Path>, checkpoint: &impl Serialize) -> Result<()> {
    match output {
        Some(path) => publish_checkpoint(path, checkpoint),
        None => serialize(BufWriter::new(std::io::stdout().lock()), checkpoint),
    }
}

fn main() -> Result<()> {
    let arguments = arguments()?;
    let bytes = std::fs::read(&arguments.input)
        .with_context(|| format!("failed to read {}", arguments.input.display()))?;
    let input_digest: [u8; 32] = Sha256::digest(&bytes).into();
    let prover_input: ProverInput =
        serde_json::from_slice(&bytes).context("failed to decode official ProverInput JSON")?;

    let preprocessed = Arc::new(PreProcessedTrace::canonical());
    let generator = create_cairo_claim_generator(prover_input, preprocessed);
    let (evals, claim, interaction_generator) = generator.write_trace(None);
    match arguments.mode {
        Mode::Base => {
            let checkpoint = checkpoint::build(input_digest, &claim, evals)?;
            write_checkpoint(arguments.output.as_deref(), &checkpoint)
        }
        Mode::Interaction => {
            drop(evals);
            let (lookup_elements, challenge) = interaction::diagnostic_lookup_elements()?;
            let (evals, interaction_claim) =
                interaction_generator.write_interaction_trace(&lookup_elements);
            let checkpoint =
                interaction::build(input_digest, &claim, &interaction_claim, evals, challenge)?;
            write_checkpoint(arguments.output.as_deref(), &checkpoint)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use checkpoint::Authority;

    fn test_checkpoint() -> checkpoint::Checkpoint {
        checkpoint::Checkpoint {
            schema: "stwo-cairo-base-trace-checkpoint-v1",
            input_sha256: "00".repeat(32),
            authority: Authority {
                stwo_cairo_revision: "cairo",
                stwo_revision: "stwo",
            },
            components: Vec::new(),
            final_accumulator_sha256: "00".repeat(32),
        }
    }

    #[test]
    fn atomic_publish_refuses_existing_destination() {
        let directory = std::env::temp_dir().join(format!(
            "stwo-cairo-trace-oracle-test-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("atomic")
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        let output = directory.join("checkpoint.json");
        std::fs::write(&output, b"original").unwrap();

        assert!(publish_checkpoint(&output, &test_checkpoint()).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn interaction_publish_refuses_existing_destination() {
        let directory = std::env::temp_dir().join(format!(
            "stwo-cairo-interaction-oracle-test-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("atomic")
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        let output = directory.join("interaction.json");
        std::fs::write(&output, b"original").unwrap();
        let (_, challenge) = interaction::diagnostic_lookup_elements().unwrap();
        let checkpoint = interaction::Checkpoint {
            schema: "stwo-cairo-interaction-trace-checkpoint-v1",
            input_sha256: "00".repeat(32),
            authority: Authority {
                stwo_cairo_revision: "cairo",
                stwo_revision: "stwo",
            },
            challenge,
            components: Vec::new(),
            final_accumulator_sha256: "00".repeat(32),
        };

        assert!(publish_checkpoint(&output, &checkpoint).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
