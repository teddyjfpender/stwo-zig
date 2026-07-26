use std::path::{Path, PathBuf};

use stwo_cairo_official_verifier::{ProofFormat, inspect_blake2s_proof_claim};

fn vector() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/cairo/official/all_opcodes_blake2s.proof.bz2")
}

#[test]
fn official_claim_has_stable_flat_and_interaction_geometry() {
    let summary =
        serde_json::to_value(inspect_blake2s_proof_claim(&vector(), ProofFormat::Binary).unwrap())
            .unwrap();
    assert_eq!(
        summary["schema"],
        "stwo_cairo_official_claim_summary_v1"
    );
    assert_eq!(summary["preprocessed_trace_variant"], "canonical");
    assert_eq!(
        summary["flat_claim"]["component_enable_bits"]
            .as_array()
            .unwrap()
            .len(),
        83
    );
    assert_eq!(
        summary["flat_claim"]["component_log_sizes"]
            .as_array()
            .unwrap()
            .len(),
        46
    );
    assert_eq!(
        summary["interaction"]["claimed_sums_m31"]
            .as_array()
            .unwrap()
            .len(),
        46
    );
    assert_eq!(summary["interaction"]["pow"], 201_863_670_255_u64);
    assert_eq!(
        summary["flat_claim"]["blake2s_mix_digest"],
        "163ef19a405897b555ff3e9e2d0090466b45c9df9f7c57193858b4f70f2d398c"
    );
}
