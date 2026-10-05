//! Parse the Go service's staged applicative input with the exact pinned Rust
//! runner types. This checks task loading and schema compatibility before a
//! compiled circuit-applicative Cairo 0 program is available.

use std::path::Path;

use anyhow::{Context, Result, ensure};
use cairo_program_runner_lib::hints::types::{CircuitApplicativeBootloaderInput, PackedNode, Task};

pub fn run(path: &Path) -> Result<Vec<u8>> {
    let input: CircuitApplicativeBootloaderInput = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )
    .context("parse pinned CircuitApplicativeBootloaderInput")?;
    ensure!(
        matches!(input.aggregator_task.task.as_ref(), Task::Pie(_)),
        "aggregator task is not a Cairo PIE"
    );
    ensure!(
        matches!(input.verifier_task.task.as_ref(), Task::Cairo1Program(_)),
        "verifier task is not a Cairo 1 program"
    );
    ensure!(
        !input.supported_circuit_hashes.is_empty(),
        "no supported circuit hashes"
    );
    let leaves = count_leaves(&input.packed_output)?;
    crate::output::json(&serde_json::json!({
        "schema": "stwo-circuit-oracle.applicative-input.v1",
        "aggregator_task": "CairoPiePath",
        "verifier_task": "Cairo1Executable",
        "packed_leaves": leaves,
        "supported_circuit_hashes": input.supported_circuit_hashes.len(),
    }))
}

fn count_leaves(node: &PackedNode) -> Result<usize> {
    match node {
        PackedNode::Plain { .. } => Ok(1),
        PackedNode::Composite { subtasks, .. } => {
            ensure!(!subtasks.is_empty(), "empty packed composite");
            subtasks
                .iter()
                .try_fold(0usize, |count, child| Ok(count + count_leaves(child)?))
        }
    }
}
