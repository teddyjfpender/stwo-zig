//! Rung R4: the in-circuit STARK verifier, stage by stage, on `test_data/circuit_multiverifier`.
//!
//! The circuit is the one `circuit_multiverifier/src/verify_test.rs`
//! (`test_verify_cairo_proof_and_multiverifier_proof`) builds: a multiverifier over the
//! multiverifier proof `proof.bin` (LOG_BLOWUP 3) and the Cairo verifier proof `proof_cairo.bin`,
//! padded to the privacy target sizes. Upstream exposes `verify` and `build_multiverifier_circuit`
//! only as single calls, so the oracle mirrors both call for call ([`verify_staged`] transcribes
//! `crates/stark_verifier/src/verify.rs`, including its private helpers) and records a
//! [`GateSummary`] of the whole circuit after every stage. Gates are only ever appended, so each
//! summary is the summary of a prefix of the final gate lists.
//!
//! Before emitting, the oracle asserts that:
//!
//! - the mirrored value-mode circuit equals the one upstream `build_multiverifier_circuit` +
//!   `pad_to_targets` build (gate lists and values), and is satisfied;
//! - the topology-mode mirror (empty proofs, `NoValue`) yields identical stage summaries;
//! - the padded circuit's preprocessed root is `MULTIVERIFIER_PREPROCESSED_ROOT`.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use circuit_cairo_verifier::privacy::get_pcs_config;
use circuit_common::N_RESERVED;
use circuit_common::finalize::{ComponentSizes, pad_to_targets};
use circuit_common::preprocessed::{PreprocessedCircuit, layout_from_component_sizes};
use circuit_multiverifier::verify::{MultiverifierInput, SharedConfig, build_multiverifier_circuit};
use circuit_prover::circuit_hash::compute_circuit_hash;
use circuit_serialize::deserialize::deserialize_proof_with_config;
use circuit_verifier::statement::{
    CircuitStatement, all_circuit_components, circuit_component_log_sizes,
    circuit_verifier_proof_config,
};
use circuit_verifier::verify::CircuitConfig;
use circuits::blake::{HashValue, blake2s_u32s};
use circuits::context::{Context, FinalizedContext, U_VAR_IDX, Var};
use circuits::eval;
use circuits::extract_bits::extract_bits;
use circuits::ivalue::{IValue, NoValue};
use circuits::ops::{Guess, eq};
use circuits::simd::Simd;
use circuits::utils::{bytes_from_le_u32s, le_u32s_from_bytes};
use circuits::wrappers::M31Wrapper;
use circuits_stark_verifier::channel::Channel as CircuitChannel;
use circuits_stark_verifier::constraint_eval::compute_composition_polynomial;
use circuits_stark_verifier::fri::{fri_commit, fri_decommit, mix_fri_config};
use circuits_stark_verifier::merkle::decommit_eval_domain_samples;
use circuits_stark_verifier::oods::{
    collect_oods_responses, compute_fri_input, extract_expected_composition_eval,
};
use circuits_stark_verifier::proof::{Proof, ProofConfig, empty_proof};
use circuits_stark_verifier::select_queries::{
    get_query_selection_input_from_channel, select_queries,
};
use circuits_stark_verifier::statement::{EvaluateArgs, OodsSamples, Statement};
use circuits_stark_verifier::verify::{
    LOG_SIZE_BITS, RELATION_USES_NUM_ROWS_SHIFT, validate_logup_sum,
};
use itertools::{Itertools, chain, zip_eq};
use serde::Serialize;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;
use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasher};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo::core::verifier::COMPOSITION_LOG_SPLIT;
use stwo_constraint_framework::{INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX};

use crate::checkpoint::{Envelope, GateSummary, gate_summary};
use crate::contexts::Mode;
use crate::goldens;
use crate::upstream::ProvingRoot;

/// Aggregate digest of `test_data/circuit_multiverifier/{proof,proof_cairo}.bin` at
/// `proving@5a7c5ed`.
pub const PINNED_PROOFS_SHA256: &str =
    "04d1f6c9142c634b2e888b0e20f51a6fcdbea3b185c7b239745f44fa0fea7c99";

const MULTIVERIFIER_PROOF: &str = "test_data/circuit_multiverifier/proof.bin";
const CAIRO_VERIFIER_PROOF: &str = "test_data/circuit_multiverifier/proof_cairo.bin";

#[derive(Serialize)]
pub struct StageRecord {
    pub stage: String,
    pub circuit: GateSummary,
}

#[derive(Serialize)]
pub struct VerifierStagesBody {
    pub pcs_config_trace_log_size: u32,
    pub log_blowup_factor: u32,
    /// The `[circuit_hash (8 words), output_digest (8 words)]` preimage words of each verified
    /// child, left to right, as the multiverifier hashes them.
    pub preimage_words: Vec<u32>,
    pub output_digest: [u32; 8],
    pub stages: Vec<StageRecord>,
    pub values_sha256: String,
    pub preprocessed_root: [u32; 8],
}

/// Records a gate summary after every stage.
struct Stages {
    prefix: String,
    records: Vec<(String, GateSummary)>,
}

impl Stages {
    fn mark<V: IValue>(&mut self, context: &Context<V>, stage: &str) {
        self.records
            .push((format!("{}{stage}", self.prefix), gate_summary(&context.circuit)));
    }
}

/// `circuits_stark_verifier::verify::verify`, transcribed call for call, with stage marks.
fn verify_staged<Value: IValue>(
    context: &mut Context<Value>,
    proof: &Proof<Var>,
    config: &ProofConfig,
    statement: &impl Statement<Value>,
    stages: &mut Stages,
) {
    proof.validate_structure(config);
    assert!(config.log_evaluation_domain_size() <= 30);
    let mut channel = CircuitChannel::new(context);
    channel.mix_qm31s(context, [proof.channel_salt]);
    mix_fri_config(context, &mut channel, &config.fri);
    stages.mark(context, "channel_salt_and_fri_config");

    let preprocessed_root = statement.get_preprocessed_root(context);
    channel.mix_commitment(context, &preprocessed_root);
    stages.mark(context, "preprocessed_root");

    let component_log_sizes = statement.get_component_log_sizes().clone();
    let component_sizes = validate_and_compute_component_sizes(
        context,
        &component_log_sizes,
        config.log_trace_size(),
    );
    let component_sizes_bits =
        extract_bits(context, &component_sizes, config.log_trace_size() as u32 + 1);
    stages.mark(context, "component_sizes");

    for claim_to_mix in statement.claims_to_mix(context) {
        channel.mix_u32s(context, claim_to_mix.into_iter());
    }
    stages.mark(context, "claims_mixed");

    channel.mix_commitment(context, &proof.trace_root);
    channel.pow(context, config.n_interaction_pow_bits, proof.interaction_pow_nonce);
    stages.mark(context, "trace_root_and_interaction_pow");

    let [interaction_z, interaction_alpha] = channel.draw_two_qm31s(context);
    context.debug_info.insert("interaction_z".into(), interaction_z);
    context
        .debug_info
        .insert("interaction_alpha".into(), interaction_alpha);
    stages.mark(context, "interaction_elements");

    let public_logup_sum =
        statement.public_logup_sum(context, [interaction_z, interaction_alpha]);
    validate_logup_sum(context, public_logup_sum, &proof.claimed_sums);
    stages.mark(context, "logup_sum");

    channel.mix_qm31s(context, proof.claimed_sums.iter().cloned());
    channel.mix_commitment(context, &proof.interaction_root);
    let composition_polynomial_coeff = channel.draw_qm31(context);
    context
        .debug_info
        .insert("composition_polynomial_coeff".into(), composition_polynomial_coeff);
    channel.mix_commitment(context, &proof.composition_polynomial_root);
    let oods_point = channel.draw_point(context);
    stages.mark(context, "composition_coeff_and_oods_point");

    let shifted_relation_uses = check_relation_uses(context, statement, &component_sizes_bits);
    stages.mark(context, "check_relation_uses");
    let unpacked_component_sizes = Simd::unpack(context, &component_sizes);
    statement.verify_claim(context, &unpacked_component_sizes, &shifted_relation_uses);
    stages.mark(context, "verify_claim");

    let interaction_at_oods = proof
        .interaction_at_oods
        .iter()
        .flat_map(|interaction| {
            if let Some(interaction_at_prev) = interaction.at_prev {
                vec![interaction_at_prev, interaction.at_oods]
            } else {
                vec![interaction.at_oods]
            }
        })
        .collect_vec();
    channel.mix_qm31s(
        context,
        chain!(
            proof.preprocessed_columns_at_oods.iter().cloned(),
            proof.trace_at_oods.iter().cloned(),
            interaction_at_oods,
            proof.composition_eval_at_oods,
        ),
    );
    stages.mark(context, "oods_values_mixed");

    let composition_eval = compute_composition_polynomial(
        context,
        config,
        statement,
        EvaluateArgs {
            oods_samples: OodsSamples {
                preprocessed_columns: &proof.preprocessed_columns_at_oods,
                trace: &proof.trace_at_oods,
                interaction: &proof.interaction_at_oods,
            },
            pt: oods_point,
            log_domain_size: config.log_trace_size(),
            composition_polynomial_coeff,
            interaction_elements: [interaction_z, interaction_alpha],
            claimed_sums: &proof.claimed_sums,
            component_sizes: &unpacked_component_sizes,
            n_instances_bits: &component_sizes_bits,
        },
    );
    context
        .debug_info
        .insert("composition_eval".into(), composition_eval);
    stages.mark(context, "composition_polynomial");
    let expected_composition_eval = extract_expected_composition_eval(
        context,
        &proof.composition_eval_at_oods,
        oods_point,
        config.log_trace_size() + COMPOSITION_LOG_SPLIT as usize,
    );
    eq(context, composition_eval, expected_composition_eval);
    stages.mark(context, "composition_check");

    let oods_quotient_coef = channel.draw_qm31(context);
    let fri_alphas = fri_commit(context, &mut channel, &proof.fri.commit);
    stages.mark(context, "fri_commit");
    channel.pow(context, config.fri.pow_bits, proof.pow_nonce);
    stages.mark(context, "fri_pow");

    let query_selection_input =
        get_query_selection_input_from_channel(context, &mut channel, config.n_queries());
    let queries =
        select_queries(context, &query_selection_input, config.log_evaluation_domain_size());
    stages.mark(context, "select_queries");

    let bits = queries
        .bits
        .iter()
        .map(|simd| Simd::unpack(context, simd))
        .collect_vec();
    let opt_column_log_sizes_by_trace = get_opt_column_log_sizes_by_trace(
        context,
        config,
        component_log_sizes,
        statement.sorting_required(),
    );
    stages.mark(context, "query_bits");
    decommit_eval_domain_samples(
        context,
        config.n_queries(),
        &opt_column_log_sizes_by_trace,
        &proof.eval_domain_samples,
        &proof.eval_domain_auth_paths,
        &bits,
        &{
            let [trace, interaction, composition] = proof.merkle_roots();
            [&preprocessed_root, trace, interaction, composition]
        },
    );
    stages.mark(context, "merkle_decommit");

    let oods_responses =
        collect_oods_responses(context, config, oods_point, &component_sizes_bits, proof);
    stages.mark(context, "oods_responses");
    let fri_input = compute_fri_input(
        context,
        &oods_responses,
        &queries,
        &proof.eval_domain_samples,
        oods_quotient_coef,
    );
    stages.mark(context, "fri_input");
    fri_decommit(
        context,
        &proof.fri,
        config.log_trace_size,
        &config.fri,
        fri_input,
        &bits,
        queries,
        &fri_alphas,
    );
    stages.mark(context, "fri_decommit");
}

/// `check_relation_uses` of `crates/stark_verifier/src/verify.rs` (private upstream).
fn check_relation_uses<Value: IValue>(
    context: &mut Context<impl IValue>,
    statement: &impl Statement<Value>,
    component_sizes_bits: &[Simd],
) -> HashMap<String, Var> {
    let components = statement.get_components();
    let mut max_shifted_uses_per_relation = HashMap::<&str, u64>::new();
    for component in components.values() {
        for relation_use in component.relation_uses_per_row() {
            let entry = max_shifted_uses_per_relation
                .entry(relation_use.relation_id)
                .or_insert(0);
            *entry = entry
                .checked_add(relation_use.uses * (((P >> RELATION_USES_NUM_ROWS_SHIFT) + 1) as u64))
                .expect("Shifted num rows upper bound computation overflowed");
        }
    }
    assert!(
        max_shifted_uses_per_relation
            .values()
            .all(|count| *count < (P as u64))
    );

    let shifted_component_sizes_p1 = match component_sizes_bits.get(RELATION_USES_NUM_ROWS_SHIFT..)
    {
        Some(high_bits) => {
            let one = Simd::one(context, components.len());
            let shifted_component_sizes = Simd::combine_bits(context, high_bits);
            let res = eval!(context, (shifted_component_sizes) + (one));
            Simd::mark_partly_used(context, &res);
            res
        }
        None => Simd::one(context, components.len()),
    };

    let mut shifted_relation_uses = HashMap::new();
    for (i, component) in components.values().enumerate() {
        let relation_uses = component.relation_uses_per_row();
        if relation_uses.is_empty() {
            continue;
        }
        let shifted_size_p1 = Simd::unpack_idx(context, &shifted_component_sizes_p1, i);
        for relation_use in relation_uses {
            let uses_per_row = context.constant(u32::try_from(relation_use.uses).unwrap().into());
            let shifted_uses_upper_bound = eval!(context, (shifted_size_p1) * (uses_per_row));
            shifted_relation_uses
                .entry(relation_use.relation_id.to_string())
                .and_modify(|entry| {
                    *entry = eval!(context, (*entry) + (shifted_uses_upper_bound));
                })
                .or_insert(shifted_uses_upper_bound);
        }
    }

    let shifted_use_counts = shifted_relation_uses
        .iter()
        .sorted_by_key(|(k, _v)| *k)
        .map(|(_k, v)| M31Wrapper::new_unsafe(*v))
        .collect_vec();
    let shifted_use_counts = Simd::pack(context, &shifted_use_counts);
    extract_bits(
        context,
        &shifted_use_counts,
        31 - RELATION_USES_NUM_ROWS_SHIFT as u32,
    );
    shifted_relation_uses
}

/// `get_opt_column_log_sizes_by_trace` of `crates/stark_verifier/src/verify.rs`.
fn get_opt_column_log_sizes_by_trace(
    context: &mut Context<impl IValue>,
    config: &ProofConfig,
    component_log_sizes: Simd,
    sorting_required: bool,
) -> HashMap<usize, Vec<Var>> {
    if !sorting_required {
        return HashMap::new();
    }
    let mut column_log_sizes = [
        Vec::with_capacity(config.n_trace_columns),
        Vec::with_capacity(config.n_interaction_columns),
    ];
    for (component_shape, log_size) in zip_eq(
        &config.component_shapes,
        Simd::unpack(context, &component_log_sizes),
    ) {
        column_log_sizes[0].extend(vec![log_size; component_shape.trace_columns]);
        column_log_sizes[1].extend(vec![log_size; component_shape.interaction_columns]);
    }
    let [trace, interaction] = column_log_sizes;
    HashMap::from([(ORIGINAL_TRACE_IDX, trace), (INTERACTION_TRACE_IDX, interaction)])
}

/// `validate_and_compute_component_sizes` of `crates/stark_verifier/src/verify.rs`.
fn validate_and_compute_component_sizes(
    context: &mut Context<impl IValue>,
    component_log_sizes: &Simd,
    log_trace_size: usize,
) -> Simd {
    const _: () = assert!(LOG_SIZE_BITS == 5);
    let component_log_size_bits = extract_bits(context, component_log_sizes, LOG_SIZE_BITS);
    let log_trace_size =
        Simd::repeat(context, M31::from(log_trace_size), component_log_sizes.len());
    let diff = eval!(context, (log_trace_size) - (*component_log_sizes));
    extract_bits(context, &diff, LOG_SIZE_BITS);
    Simd::pow2(context, &component_log_size_bits)
}

/// `build_multiverifier_circuit`, transcribed with stage marks, followed by `pad_to_targets`.
fn build_staged<Value: IValue>(
    inputs: Vec<MultiverifierInput<Value>>,
    shared_config: &SharedConfig,
    target: &ComponentSizes,
) -> (FinalizedContext<Value>, Vec<(String, GateSummary)>) {
    let mut stages = Stages {
        prefix: String::new(),
        records: Vec::new(),
    };
    let mut context = Context::new(N_RESERVED);
    let mut preimage = vec![];
    for (index, input) in inputs.into_iter().enumerate() {
        stages.prefix = format!("input_{index}.");
        let MultiverifierInput {
            proof,
            preprocessed_root,
            output_digest,
        } = input;
        let circuit_config = CircuitConfig {
            config: shared_config.pcs_config,
            preprocessed_column_log_sizes: shared_config.preprocessed_column_log_sizes.clone(),
        };
        let output_digest = output_digest.guess(&mut context);
        let preprocessed_root = preprocessed_root.guess(&mut context);
        stages.mark(&context, "guess_output_digest_and_root");
        let statement =
            CircuitStatement::new(&mut context, &circuit_config, preprocessed_root, output_digest);
        stages.mark(&context, "statement");
        let proof_vars = proof.guess(&mut context);
        stages.mark(&context, "guess_proof");
        stages.prefix = format!("input_{index}.verify.");
        verify_staged(
            &mut context,
            &proof_vars,
            &shared_config.proof_config,
            &statement,
            &mut stages,
        );
        preimage.extend(chain!(statement.circuit_hash, statement.output_digest));
    }
    stages.prefix = String::new();
    let n_bytes = 4 * preimage.len();
    let output_hash = blake2s_u32s(&mut context, preimage, n_bytes);
    stages.mark(&context, "preimage_hash");
    context.set_outputs(&output_hash.iter().map(|word| *word.get()).collect_vec());
    stages.mark(&context, "set_outputs");
    let mut context = context.finalize(false);
    stages.records.push((
        "finalize".into(),
        gate_summary(context.circuit()),
    ));
    pad_to_targets(&mut context, target);
    stages.records.push((
        "pad_to_targets".into(),
        gate_summary(context.circuit()),
    ));
    (context, stages.records)
}

/// `leaf_circuit_hash` of `crates/circuit_multiverifier/src/test_utils.rs`.
fn leaf_circuit_hash(preprocessed_root: [u32; 8], shared_config: &SharedConfig) -> [u32; 8] {
    let component_log_sizes = circuit_component_log_sizes(
        &all_circuit_components::<QM31>(),
        &shared_config.preprocessed_column_log_sizes,
    );
    let hash = compute_circuit_hash::<Blake2sMerkleHasher>(
        &component_log_sizes,
        shared_config.pcs_config.fri_config.log_blowup_factor,
        Blake2sHash(bytes_from_le_u32s(preprocessed_root)),
    );
    le_u32s_from_bytes(hash.0)
}

/// `native_blake_u32s` of `crates/circuit_multiverifier/src/test_utils.rs`.
fn native_blake_u32s(words: &[u32]) -> [u32; 8] {
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    le_u32s_from_bytes(Blake2sHasher::hash(&bytes).0)
}

fn inputs(
    proofs: [Proof<QM31>; 2],
    roots: [[u32; 8]; 2],
    digests: [[u32; 8]; 2],
) -> Vec<MultiverifierInput<QM31>> {
    proofs
        .into_iter()
        .zip(roots.into_iter().zip(digests))
        .map(|(proof, (root, digest))| MultiverifierInput {
            proof,
            preprocessed_root: root.into(),
            output_digest: digest.into(),
        })
        .collect()
}

fn topology_inputs(config: &ProofConfig) -> Vec<MultiverifierInput<NoValue>> {
    (0..2)
        .map(|_| MultiverifierInput {
            proof: empty_proof(config),
            preprocessed_root: HashValue::no_value(),
            output_digest: HashValue::no_value(),
        })
        .collect()
}

pub fn run(proving_root: &Path) -> Result<Envelope<VerifierStagesBody>> {
    let mut root = ProvingRoot::open(proving_root)?;
    let multiverifier_bytes = root.read(MULTIVERIFIER_PROOF)?;
    let cairo_bytes = root.read(CAIRO_VERIFIER_PROOF)?;
    let inputs_records = root.finish(PINNED_PROOFS_SHA256)?;

    let [eq_log, qm31_log, triple_xor_log, m31_to_u32_log, blake_log] =
        goldens::PRIVACY_TARGET_LOG_SIZES;
    let target = ComponentSizes {
        eq: 1 << eq_log,
        qm31_ops: 1 << qm31_log,
        m31_to_u32: 1 << m31_to_u32_log,
        triple_xor: 1 << triple_xor_log,
        blake_g_gate: 1 << blake_log,
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
    let multiverifier_proof =
        deserialize_proof_with_config(&mut multiverifier_bytes.as_slice(), &shared_config.proof_config)
            .map_err(|error| anyhow::anyhow!("{MULTIVERIFIER_PROOF}: {error:?}"))?;
    let cairo_proof =
        deserialize_proof_with_config(&mut cairo_bytes.as_slice(), &shared_config.proof_config)
            .map_err(|error| anyhow::anyhow!("{CAIRO_VERIFIER_PROOF}: {error:?}"))?;

    // The children, as `test_verify_cairo_proof_and_multiverifier_proof` builds them: the
    // multiverifier of two Cairo verifier proofs, then one Cairo verifier proof.
    let cairo_preimage: Vec<u32> = leaf_circuit_hash(
        goldens::PRIVACY_CAIRO_VERIFIER_PREPROCESSED_ROOT,
        &shared_config,
    )
    .into_iter()
    .chain(goldens::PRIVACY_CAIRO_VERIFIER_OUTPUT_DIGEST)
    .collect();
    let multiverifier_digest =
        native_blake_u32s(&[cairo_preimage.clone(), cairo_preimage.clone()].concat());
    let roots = [
        goldens::MULTIVERIFIER_PREPROCESSED_ROOT,
        goldens::PRIVACY_CAIRO_VERIFIER_PREPROCESSED_ROOT,
    ];
    let digests = [
        multiverifier_digest,
        goldens::PRIVACY_CAIRO_VERIFIER_OUTPUT_DIGEST,
    ];
    let preimage_words: Vec<u32> = roots
        .iter()
        .zip(&digests)
        .flat_map(|(root, digest)| {
            leaf_circuit_hash(*root, &shared_config)
                .into_iter()
                .chain(*digest)
        })
        .collect();
    let output_digest = native_blake_u32s(&preimage_words);

    let proofs = [multiverifier_proof, cairo_proof];
    let (mut context, stages) =
        build_staged::<QM31>(inputs(proofs.clone(), roots, digests), &shared_config, &target);
    ensure!(
        QM31::is_circuit_valid(&context),
        "the mirrored multiverifier circuit is not satisfied"
    );
    let outputs: Vec<u32> = context
        .circuit()
        .output
        .iter()
        .filter(|gate| gate.in0 != U_VAR_IDX)
        .map(|gate| context.get(Var { idx: gate.in0 }).unpack_u32())
        .collect();
    ensure!(
        outputs == output_digest,
        "multiverifier outputs {outputs:?} differ from the host preimage digest"
    );

    let mut upstream = build_multiverifier_circuit::<QM31>(inputs(proofs, roots, digests), &shared_config);
    pad_to_targets(&mut upstream, &target);
    ensure!(
        gate_summary(upstream.circuit()) == gate_summary(context.circuit())
            && upstream.values() == context.values(),
        "the mirrored multiverifier differs from build_multiverifier_circuit"
    );
    drop(upstream);

    let (_, topology_stages) = build_staged::<NoValue>(
        topology_inputs(&shared_config.proof_config),
        &shared_config,
        &target,
    );
    ensure!(
        topology_stages == stages,
        "value and topology stage summaries differ"
    );

    let values_sha256 = QM31::values_sha256(context.values()).context("value mode")?;
    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut context);
    drop(context);
    let preprocessed_root: [u32; 8] = le_u32s_from_bytes(
        preprocessed
            .preprocessed_root(pcs_config.fri_config.log_blowup_factor)
            .0,
    );
    ensure!(
        preprocessed_root == goldens::MULTIVERIFIER_PREPROCESSED_ROOT,
        "multiverifier preprocessed root differs from {}",
        goldens::MULTIVERIFIER_TEST_UTILS
    );

    Ok(Envelope::new(
        "r4",
        "verifier-stages",
        inputs_records,
        VerifierStagesBody {
            pcs_config_trace_log_size: goldens::PRIVACY_CAIRO_VERIFIER_TRACE_LOG_SIZE,
            log_blowup_factor: goldens::MULTIVERIFIER_LOG_BLOWUP_FACTOR,
            preimage_words,
            output_digest,
            stages: stages
                .into_iter()
                .map(|(stage, circuit)| StageRecord { stage, circuit })
                .collect(),
            values_sha256,
            preprocessed_root,
        },
    ))
}
