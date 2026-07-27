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
    assert_eq!(identity["layout"], "all_cairo_stwo");
    assert_eq!(identity["cairo_vm_version"], "3.2.0");
    assert_eq!(identity["cairo_language_version"], "2.20.0");
    assert_eq!(
        identity["program_types"],
        serde_json::json!(["json", "executable"])
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
