use std::process::Command;
use std::{path::Path, path::PathBuf};

use serde_json::Value;
use tempfile::tempdir;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_stwo-cairo-official-verifier")
}

fn input_vector() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/cairo/official/all_opcodes.prover_input.json")
}

fn proof_vector() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/cairo/official/all_opcodes_blake2s.proof.bz2")
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
    assert_eq!(
        identity["prover_input_schema"],
        "stwo_cairo_adapter::ProverInput@1.2.2"
    );
    assert_eq!(
        identity["claim_summary_schema"],
        "stwo_cairo_official_claim_summary_v1"
    );
}

#[test]
fn inspect_input_publishes_an_immutable_semantic_summary() {
    let directory = tempdir().unwrap();
    let result = directory.path().join("summary.json");
    let status = Command::new(binary())
        .args(["inspect-input", "--prover-input"])
        .arg(input_vector())
        .args(["--result"])
        .arg(&result)
        .status()
        .unwrap();
    assert!(status.success());
    let summary: Value = serde_json::from_slice(&std::fs::read(&result).unwrap()).unwrap();
    assert_eq!(summary["schema"], "stwo_cairo_official_input_summary_v2");
    assert_eq!(summary["pc_count"], 778);
}

#[test]
fn inspect_proof_publishes_the_canonical_claim_geometry() {
    let directory = tempdir().unwrap();
    let result = directory.path().join("claim.json");
    let status = Command::new(binary())
        .args(["inspect-blake2s-proof", "--proof"])
        .arg(proof_vector())
        .args(["--proof-format", "binary", "--result"])
        .arg(&result)
        .status()
        .unwrap();
    assert!(status.success());
    let summary: Value = serde_json::from_slice(&std::fs::read(&result).unwrap()).unwrap();
    assert_eq!(summary["schema"], "stwo_cairo_official_claim_summary_v1");
    assert_eq!(
        summary["flat_claim"]["component_enable_bits"]
            .as_array()
            .unwrap()
            .len(),
        83
    );
}

#[test]
fn cairo_serde_transport_is_pinned_to_the_official_vector() {
    let directory = tempdir().unwrap();
    let result = directory.path().join("proof.cairo-serde.json");
    let status = Command::new(binary())
        .args(["serialize-cairo", "--proof"])
        .arg(proof_vector())
        .args(["--proof-format", "binary", "--result"])
        .arg(&result)
        .status()
        .unwrap();
    assert!(status.success());
    let encoded = std::fs::read(&result).unwrap();
    let values: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(values.as_array().unwrap().len(), 301_739);
    assert_eq!(
        stwo_cairo_official_verifier::proof_sha256(&result).unwrap(),
        "0d05742cceafef88e3b44d933e8e301d2c68f05c1a864026e00f4dae5861f454"
    );
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
