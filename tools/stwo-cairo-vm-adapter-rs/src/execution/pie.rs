//! Proof-mode PIE execution using the upstream simple bootloader.

use super::CompletedExecution;
use anyhow::{Context, Result, ensure};
use cairo_program_runner_lib::types::HashFunc;
use cairo_program_runner_lib::{ProgramInput, SimpleBootloaderInput, Task, TaskSpec};
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::program::Program;
use sha2::{Digest, Sha256};
use std::io::Read;
use stwo_cairo_adapter::PublicSegmentContext;

const BOOTLOADER: &[u8] = include_bytes!("../../resources/simple_bootloader_compiled.json.gz");

const MAX_BOOTLOADER_BYTES: u64 = 32 << 20;

pub fn run(
    bytes: &[u8],
    arguments: Option<&[u8]>,
    config: CairoRunConfig<'_>,
) -> Result<CompletedExecution> {
    let started = std::time::Instant::now();
    ensure!(arguments.is_none(), "PIE inputs do not accept --arguments");
    let pie = super::pie_archive::decode(bytes)?;
    let decoded = std::time::Instant::now();
    let mut bootloader_bytes = Vec::new();
    flate2::read::GzDecoder::new(BOOTLOADER)
        .take(MAX_BOOTLOADER_BYTES + 1)
        .read_to_end(&mut bootloader_bytes)?;
    ensure!(
        bootloader_bytes.len() as u64 <= MAX_BOOTLOADER_BYTES,
        "bootloader exceeds size limit"
    );
    ensure!(
        format!("{:x}", Sha256::digest(&bootloader_bytes)) == crate::PIE_BOOTLOADER_SHA256,
        "bootloader identity mismatch"
    );
    let program = Program::from_bytes(&bootloader_bytes, Some("main"))?;
    let context = PublicSegmentContext::new(&program.iter_builtins().cloned().collect::<Vec<_>>());
    let input = SimpleBootloaderInput {
        fact_topologies_path: None,
        single_page: true,
        tasks: vec![TaskSpec {
            task: Task::Pie(pie).into(),
            program_hash_function: HashFunc::Blake,
        }],
    };
    let prepared = std::time::Instant::now();
    let runner = cairo_program_runner_lib::cairo_run_program(
        &program,
        Some(ProgramInput::Value(Box::new(input))),
        config,
        None,
    )
    .context("upstream bootloader PIE execution failed")?;
    if std::env::var_os("STWO_CAIRO_VM_PROFILE").is_some() {
        eprintln!(
            "cairo_pie_profile decode_ms={:.3} bootloader_prepare_ms={:.3} runner_ms={:.3}",
            decoded.duration_since(started).as_secs_f64() * 1000.0,
            prepared.duration_since(decoded).as_secs_f64() * 1000.0,
            prepared.elapsed().as_secs_f64() * 1000.0,
        );
    }
    Ok(CompletedExecution {
        runner,
        public_segment_context: Some(context),
    })
}
