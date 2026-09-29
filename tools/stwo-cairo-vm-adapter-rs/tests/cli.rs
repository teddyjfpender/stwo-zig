use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tempfile::tempdir;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_stwo-cairo-vm-adapter")
}

fn repository_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

#[test]
fn identity_binds_the_official_execution_stack() {
    let output = Command::new(binary()).arg("identity").output().unwrap();
    assert!(output.status.success());
    let identity: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(identity["schema_version"], 2);
    assert_eq!(
        identity["execution_runner_revision"],
        "5a7c5ede4299c91a61df19a07cba4f7502c14230"
    );
    assert_eq!(
        identity["pie_bootloader_sha256"],
        "f6d235eb6a7f97038105ed9b6e0e083b11def61c664a17fe157135f9615efc76"
    );
    assert_eq!(identity["layout"], "all_cairo_stwo");
    assert_eq!(identity["cairo_vm_version"], "3.2.0");
    assert_eq!(identity["cairo_language_version"], "2.20.0");
    assert_eq!(
        identity["program_types"],
        serde_json::json!(["json", "executable", "pie"])
    );
    assert_eq!(
        identity["stwo_cairo_revision"],
        "82f21252a68ec006d73e299f5bf1ce6d4db0ee78"
    );
    assert_eq!(
        identity["stwo_revision"],
        "7b211edde786775016ef3eecb837a6240d8fe792"
    );
}

#[test]
fn executable_program_derives_its_public_builtin_context() {
    let directory = tempdir().unwrap();
    let output = directory.path().join("prover-input.json");
    let status = Command::new(binary())
        .args(["run", "--program"])
        .arg(repository_path(
            "vectors/cairo/programs/executable/add_one.executable.json",
        ))
        .args(["--program-type", "executable", "--arguments"])
        .arg(repository_path(
            "vectors/cairo/programs/executable/add_one.arguments.json",
        ))
        .args(["--prover-input-out"])
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    let input: Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    assert_eq!(
        input["public_segment_context"]["present"],
        serde_json::json!([
            true, false, true, false, false, false, false, false, false, false, false
        ])
    );
}

#[test]
fn all_opcodes_program_reproduces_the_official_prover_input() {
    let directory = tempdir().unwrap();
    let output = directory.path().join("prover-input.json");
    let status = Command::new(binary())
        .args(["run", "--program"])
        .arg(repository_path(
            "vectors/cairo/programs/all_opcodes.compiled.json",
        ))
        .args(["--program-type", "json", "--prover-input-out"])
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    let rendered = std::fs::read(output).unwrap();
    assert!(!rendered.contains(&b'\n'));
    let actual: Value = serde_json::from_slice(&rendered).unwrap();
    let expected: Value = serde_json::from_slice(
        &std::fs::read(repository_path(
            "vectors/cairo/official/all_opcodes.prover_input.json",
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn compact_transport_preserves_official_opcode_geometry() {
    let directory = tempdir().unwrap();
    let output = directory.path().join("input.cpi");
    let status = Command::new(binary())
        .args(["run", "--program"])
        .arg(repository_path(
            "vectors/cairo/programs/all_opcodes.compiled.json",
        ))
        .args(["--input-format", "compact", "--prover-input-out"])
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    let bytes = std::fs::read(output).unwrap();
    assert_eq!(&bytes[..8], b"STWZCPI\0");
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(bytes[40..48].try_into().unwrap()), 778);
    let mut offset = 64;
    let mut rows = 0;
    for _ in 0..20 {
        let count = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
        rows += count;
        offset += 8 + count * 12;
    }
    assert_eq!(rows, 1498);
    assert_eq!(
        bytes,
        std::fs::read(repository_path(
            "vectors/cairo/official/all_opcodes.prover_input.cpi"
        ))
        .unwrap()
    );
}

#[test]
fn pie_is_executed_in_the_upstream_proof_mode_bootloader() {
    let directory = tempdir().unwrap();
    let output = directory.path().join("pie-input.json");
    let status = Command::new(binary())
        .args(["run", "--program"])
        .arg(repository_path(
            "tools/stwo-cairo-vm-adapter-rs/resources/fibonacci_pie.zip",
        ))
        .args(["--program-type", "pie", "--prover-input-out"])
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    let input: Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    assert_eq!(
        input["public_segment_context"]["present"],
        serde_json::to_value([true; 11]).unwrap()
    );
    assert!(
        input["state_transitions"]["casm_states_by_opcode"]["blake_compress_opcode"]
            .as_array()
            .unwrap()
            .len()
            > 0
    );
    assert!(input["public_memory_addresses"].as_array().unwrap().len() > 0);
}

#[test]
fn failed_publication_preserves_an_existing_input() {
    let directory = tempdir().unwrap();
    let output = directory.path().join("existing.json");
    std::fs::write(&output, b"keep this input").unwrap();
    let status = Command::new(binary())
        .args(["run", "--program"])
        .arg(repository_path(
            "vectors/cairo/programs/all_opcodes.compiled.json",
        ))
        .args(["--program-type", "json", "--prover-input-out"])
        .arg(&output)
        .status()
        .unwrap();
    assert!(!status.success());
    assert_eq!(std::fs::read(output).unwrap(), b"keep this input");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
