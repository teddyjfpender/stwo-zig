use std::path::{Path, PathBuf};

use stwo_cairo_official_verifier::{Channel, ProofFormat, proof_sha256, verify_proof};

const VECTOR_SHA256: &str = "2d7acaabc6ac00afd1a840aaa1527c4a73a4807a9153dc3fe1d4fdefa86104f1";

fn vector() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/cairo/official/all_opcodes_blake2s.proof.bz2")
}

#[test]
fn official_all_opcodes_vector_is_accepted() {
    let vector = vector();
    assert_eq!(proof_sha256(&vector).unwrap(), VECTOR_SHA256);
    verify_proof(&vector, Channel::Blake2s, ProofFormat::Binary).unwrap();
}

#[test]
fn mutated_official_vector_is_rejected() {
    let vector = vector();
    let mut bytes = std::fs::read(vector).unwrap();
    let index = bytes.len() / 2;
    bytes[index] ^= 1;

    let directory = tempfile::tempdir().unwrap();
    let mutation = directory.path().join("mutated.proof.bz2");
    std::fs::write(&mutation, bytes).unwrap();
    assert!(verify_proof(&mutation, Channel::Blake2s, ProofFormat::Binary).is_err());
}
