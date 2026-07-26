use std::path::{Path, PathBuf};

use serde_json::Value;
use stwo_cairo_official_verifier::input::inspect_input;
use stwo_cairo_official_verifier::{ProofFormat, inspect_blake2s_proof_public_statement};

fn vector() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/cairo/official/all_opcodes.prover_input.json")
}

fn builtin_vector() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/cairo/official/all_builtins.prover_input.json")
}

fn all_opcodes_proof() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/cairo/official/all_opcodes_blake2s.proof.bz2")
}

#[test]
fn official_all_opcodes_input_has_stable_semantics() {
    let summary = serde_json::to_value(inspect_input(&vector()).unwrap()).unwrap();
    assert_eq!(
        summary["input_sha256"],
        "7f94bd5dcf32e7dd69a8a47f42d41830b4fdd3b75846ef9f7694f3164117fcd6"
    );
    assert_eq!(summary["initial_state"], serde_json::json!([1, 1343, 1343]));
    assert_eq!(summary["final_state"], serde_json::json!([5, 2529, 1343]));
    assert_eq!(summary["pc_count"], 778);
    assert_eq!(summary["memory"]["address_to_id"]["count"], 2779);
    assert_eq!(summary["memory"]["f252_values"]["count"], 19);
    assert_eq!(summary["memory"]["small_values"]["count"], 430);
    assert_eq!(summary["public_memory_addresses"]["count"], 1366);
    assert_eq!(
        summary["opcode_states"]["blake_compress_opcode"]["count"],
        2
    );
    assert_eq!(
        summary["execution_resources"]["verify_instruction"],
        Value::from(778)
    );
    assert_eq!(summary["public_statement"]["program_len"], 1340);
    assert_eq!(summary["public_statement"]["output_len"], 2);
}

#[test]
fn official_all_builtins_input_has_complete_segment_resources() {
    let summary = serde_json::to_value(inspect_input(&builtin_vector()).unwrap()).unwrap();
    assert_eq!(
        summary["input_sha256"],
        "d7e902c3b8584a79b466ef0c384208ad95ea75340f0b0590ea0ba765c54acac1"
    );
    assert_eq!(summary["pc_count"], 272);
    for name in [
        "add_mod_builtin",
        "bitwise_builtin",
        "output",
        "mul_mod_builtin",
        "pedersen_builtin",
        "poseidon_builtin",
        "range_check96_builtin",
        "range_check_builtin",
        "ec_op_builtin",
    ] {
        assert!(summary["builtin_segments"][name].is_object(), "{name}");
    }
    for name in [
        "add_mod_builtin",
        "bitwise_builtin",
        "mul_mod_builtin",
        "pedersen_builtin",
        "poseidon_builtin",
        "range_check96_builtin",
        "range_check_builtin",
        "ec_op_builtin",
    ] {
        assert_eq!(
            summary["execution_resources"]["builtin_instance_counter"][name], 64,
            "{name}"
        );
    }
    assert_eq!(
        summary["execution_resources"]["builtin_instance_counter"]["output_builtin"],
        50
    );
}

#[test]
fn input_statement_matches_the_public_data_in_the_official_proof() {
    let input = inspect_input(&vector()).unwrap();
    let proof =
        inspect_blake2s_proof_public_statement(&all_opcodes_proof(), ProofFormat::Binary).unwrap();
    assert_eq!(input.public_statement(), &proof);
}
