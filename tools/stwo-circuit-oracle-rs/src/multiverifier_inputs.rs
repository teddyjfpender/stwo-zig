//! `multiverifier-inputs`: the circuit prover's inputs for `test_data/circuit_multiverifier/proof.bin`.
//!
//! `test_prove_multiverifier_of_two_cairo_subcircuits` (`crates/circuit_multiverifier/src/
//! verify_test.rs`) builds the multiverifier over two copies of the privacy Cairo verifier proof
//! `proof_cairo.bin`, pads it to `TARGET_PADDING_SIZES`, preprocesses it and proves the value
//! table with `prove_circuit_assignment` under `PCS_CONFIG = get_pcs_config(21, 3)`; the
//! serialized `prepare_circuit_proof_for_circuit_verifier` output is `proof.bin`. This subcommand
//! builds the same circuit and writes the prover's two inputs, the finalized circuit's gate lists
//! and its value table, as one `STWZCIRC/1` file, so that a circuit prover can be checked against
//! `proof.bin` byte for byte without building the in-circuit verifier. It proves nothing.
//!
//! ```text
//! "STWZCIRC" || version u32 (1) || n_vars u32 || count u32 × 10 (GATE_KINDS order)
//! || gate records (GATE_KINDS order; a gate is its variable indices, u32 each, in struct field
//!    order; a permutation is len, inputs.., len, outputs..)
//! || n_values u32 || value (4 × canonical u32) × n_values
//! ```
//!
//! All integers are little-endian. The checkpoint pins the file's SHA-256, the gate-list and value
//! digests of `checkpoint.rs`, the preprocessed root (asserted equal to
//! `MULTIVERIFIER_PREPROCESSED_ROOT`) and `proof.bin`'s own digest.

use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use circuit_cairo_verifier::privacy::get_pcs_config;
use circuit_common::finalize::{ComponentSizes, pad_to_targets};
use circuit_common::preprocessed::{PreprocessedCircuit, layout_from_component_sizes};
use circuit_multiverifier::verify::{
    MultiverifierInput, SharedConfig, build_multiverifier_circuit,
};
use circuit_serialize::deserialize::deserialize_proof_with_config;
use circuit_verifier::statement::circuit_verifier_proof_config;
use circuits::circuit::Circuit;
use circuits::utils::le_u32s_from_bytes;
use serde::Serialize;
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::PcsConfig;

use crate::checkpoint::{
    Envelope, GATE_KINDS, Gate, GateSummary, InputRecord, gate_counts, gate_summary, sha256_hex,
    values_sha256, visit_gates,
};
use crate::goldens;
use crate::upstream::ProvingRoot;

const CAIRO_VERIFIER_PROOF: &str = "test_data/circuit_multiverifier/proof_cairo.bin";
const MULTIVERIFIER_PROOF: &str = "test_data/circuit_multiverifier/proof.bin";

/// Aggregate digest of the two files above at `proving@5a7c5ed` (the same pair `verifier-stages`
/// pins).
const PINNED_PROOFS_SHA256: &str = crate::verifier_stages::PINNED_PROOFS_SHA256;

pub const MAGIC: &[u8; 8] = b"STWZCIRC";
pub const VERSION: u32 = 1;

#[derive(Serialize)]
pub struct DumpRecord {
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct MultiverifierInputsBody {
    pub pcs_config: PcsConfig,
    pub target_log_sizes: [u32; 5],
    pub circuit: GateSummary,
    pub values_sha256: String,
    pub n_values: usize,
    pub n_outputs: usize,
    pub first_permutation_row: usize,
    pub trace_log_size: u32,
    pub preprocessed_root: [u32; 8],
    pub inputs_file: DumpRecord,
    /// `test_data/circuit_multiverifier/proof.bin`: the expected CircuitSerialize bytes.
    pub proof: DumpRecord,
}

fn put(bytes: &mut Vec<u8>, value: usize) -> Result<()> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .context("value exceeds u32")?
            .to_le_bytes(),
    );
    Ok(())
}

/// The `STWZCIRC/1` encoding of a finalized circuit and its value table.
pub fn encode(circuit: &Circuit, values: &[QM31]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    put(&mut bytes, circuit.n_vars)?;
    for count in gate_counts(circuit) {
        put(&mut bytes, count)?;
    }
    let mut failure = None;
    visit_gates(circuit, [0; GATE_KINDS.len()], |_, gate| {
        let mut write = |value: usize| {
            if let Err(error) = put(&mut bytes, value) {
                failure.get_or_insert(error);
            }
        };
        match gate {
            Gate::Fields(fields) => fields.iter().for_each(|field| write(*field)),
            Gate::Lists(inputs, outputs) => {
                for list in [inputs, outputs] {
                    write(list.len());
                    list.iter().for_each(|index| write(*index));
                }
            }
        }
    });
    if let Some(error) = failure {
        return Err(error);
    }
    put(&mut bytes, values.len())?;
    for value in values {
        for limb in value.to_m31_array() {
            bytes.extend_from_slice(&limb.0.to_le_bytes());
        }
    }
    Ok(bytes)
}

pub fn run(proving_root: &Path, inputs_output: &Path) -> Result<Envelope<MultiverifierInputsBody>> {
    let mut root = ProvingRoot::open(proving_root)?;
    let proof_bytes = root.read(MULTIVERIFIER_PROOF)?;
    let cairo_bytes = root.read(CAIRO_VERIFIER_PROOF)?;
    let inputs: Vec<InputRecord> = root.finish(PINNED_PROOFS_SHA256)?;

    let target_log_sizes = goldens::PRIVACY_TARGET_LOG_SIZES;
    let [eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate] = target_log_sizes;
    let target = ComponentSizes {
        eq: 1 << eq,
        qm31_ops: 1 << qm31_ops,
        m31_to_u32: 1 << m31_to_u32,
        triple_xor: 1 << triple_xor,
        blake_g_gate: 1 << blake_g_gate,
    };
    let layout = layout_from_component_sizes(&target);
    ensure!(
        layout
            .iter()
            .map(|(id, log)| (id.id.as_str(), *log))
            .eq(goldens::MULTIVERIFIER_PRIVACY_LAYOUT.iter().copied()),
        "privacy layout differs from {}",
        goldens::MULTIVERIFIER_TEST_UTILS
    );
    let pcs_config = get_pcs_config(
        goldens::PRIVACY_CAIRO_VERIFIER_TRACE_LOG_SIZE,
        goldens::MULTIVERIFIER_LOG_BLOWUP_FACTOR,
    );
    let shared_config = SharedConfig {
        pcs_config,
        proof_config: circuit_verifier_proof_config(&layout, &pcs_config),
        preprocessed_column_log_sizes: layout,
    };
    let cairo_proof =
        deserialize_proof_with_config(&mut cairo_bytes.as_slice(), &shared_config.proof_config)
            .map_err(|error| anyhow::anyhow!("{CAIRO_VERIFIER_PROOF}: {error:?}"))?;

    // `test_prove_multiverifier_of_two_cairo_subcircuits`: two copies of the Cairo verifier input.
    let input = || MultiverifierInput {
        proof: cairo_proof.clone(),
        preprocessed_root: goldens::PRIVACY_CAIRO_VERIFIER_PREPROCESSED_ROOT.into(),
        output_digest: goldens::PRIVACY_CAIRO_VERIFIER_OUTPUT_DIGEST.into(),
    };
    // Wall times go to stderr only (design §9.1 builder share); the checkpoint stays deterministic.
    let build_start = std::time::Instant::now();
    let mut context = build_multiverifier_circuit::<QM31>(vec![input(), input()], &shared_config);
    pad_to_targets(&mut context, &target);
    let build_seconds = build_start.elapsed().as_secs_f64();
    context.validate_circuit();
    let preprocess_start = std::time::Instant::now();
    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut context);
    eprintln!(
        "multiverifier: build_multiverifier_circuit + pad_to_targets {build_seconds:.3} s, \
         preprocess_circuit {:.3} s",
        preprocess_start.elapsed().as_secs_f64()
    );
    let preprocessed_root: [u32; 8] = le_u32s_from_bytes(
        preprocessed
            .preprocessed_root(pcs_config.fri_config.log_blowup_factor)
            .0,
    );
    ensure!(
        preprocessed_root == goldens::MULTIVERIFIER_PREPROCESSED_ROOT,
        "the multiverifier's preprocessed root differs from MULTIVERIFIER_PREPROCESSED_ROOT"
    );

    let encoded = encode(context.circuit(), context.values())?;
    crate::output::emit(Some(inputs_output), &encoded)?;
    Ok(Envelope::new(
        "r7",
        "multiverifier-inputs",
        inputs,
        MultiverifierInputsBody {
            pcs_config,
            target_log_sizes,
            circuit: gate_summary(context.circuit()),
            values_sha256: values_sha256(context.values()),
            n_values: context.values().len(),
            n_outputs: preprocessed.n_outputs,
            first_permutation_row: preprocessed.first_permutation_row,
            trace_log_size: preprocessed.trace_log_size(),
            preprocessed_root,
            inputs_file: DumpRecord {
                bytes: encoded.len(),
                sha256: sha256_hex(&encoded),
            },
            proof: DumpRecord {
                bytes: proof_bytes.len(),
                sha256: sha256_hex(&proof_bytes),
            },
        },
    ))
}
