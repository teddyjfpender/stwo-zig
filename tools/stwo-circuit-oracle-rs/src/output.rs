//! Checkpoint output: JSON encoding and atomic, non-replacing publication.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

/// `serde_json::to_vec_pretty` followed by a newline.
pub fn json(document: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(document).context("failed to encode checkpoint")?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// A temporary file removed on drop; publishing hard-links it to its final name first.
struct PendingFile {
    path: PathBuf,
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn create_pending(output: &Path) -> Result<(PendingFile, File)> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = output.file_name().context("output path has no file name")?;
    for attempt in 0..1_000u32 {
        let path = parent.join(format!(
            ".{}.{}.{attempt}.tmp",
            name.to_string_lossy(),
            std::process::id()
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((PendingFile { path }, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create checkpoint temporary file"),
        }
    }
    bail!("unable to allocate a unique checkpoint temporary file")
}

/// Writes `bytes` to `output` atomically; an existing `output` is never replaced.
fn publish(output: &Path, bytes: &[u8]) -> Result<()> {
    let (pending, mut file) = create_pending(output)?;
    file.write_all(bytes)
        .context("failed to write checkpoint")?;
    file.sync_all().context("failed to sync checkpoint")?;
    std::fs::hard_link(&pending.path, output)
        .with_context(|| format!("refusing to replace {}", output.display()))?;
    eprintln!("wrote {}", output.display());
    Ok(())
}

/// Publishes `bytes` to `output`, or writes them to standard output.
pub fn emit(output: Option<&Path>, bytes: &[u8]) -> Result<()> {
    match output {
        Some(path) => publish(path, bytes),
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(bytes)?;
            stdout.flush().context("failed to flush checkpoint")
        }
    }
}
