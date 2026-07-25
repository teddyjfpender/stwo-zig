use std::process::Command;

use serde_json::Value;
use tempfile::tempdir;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_stwo-cairo-official-verifier")
}

#[test]
fn identity_names_exact_official_sources() {
    let output = Command::new(binary()).arg("identity").output().unwrap();
    assert!(output.status.success());
    let identity: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        identity["stwo_cairo"]["revision"],
        "82f21252a68ec006d73e299f5bf1ce6d4db0ee78"
    );
    assert_eq!(
        identity["stwo"]["revision"],
        "7b211edde786775016ef3eecb837a6240d8fe792"
    );
    assert_eq!(identity["channels"].as_array().unwrap().len(), 3);
    assert_eq!(identity["proof_formats"].as_array().unwrap().len(), 3);
}

#[test]
fn invalid_proof_publishes_a_rejection_without_replacing_results() {
    let directory = tempdir().unwrap();
    let proof = directory.path().join("proof.json");
    let result = directory.path().join("result.json");
    std::fs::write(&proof, b"{}").unwrap();

    let status = Command::new(binary())
        .args(["verify", "--proof"])
        .arg(&proof)
        .args(["--result"])
        .arg(&result)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(3));
    let report: Value = serde_json::from_slice(&std::fs::read(&result).unwrap()).unwrap();
    assert_eq!(report["verified"], false);
    assert_eq!(report["channel"], "blake2s");
    assert!(report["error"].as_str().unwrap().contains("deserialize"));

    let second = Command::new(binary())
        .args(["verify", "--proof"])
        .arg(&proof)
        .args(["--result"])
        .arg(&result)
        .status()
        .unwrap();
    assert_eq!(second.code(), Some(2));
}
