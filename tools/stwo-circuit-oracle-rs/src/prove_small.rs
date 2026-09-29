//! Rung R7: circuit proofs of the small `prover_test.rs` circuits, step by step.
//!
//! For every context of [`crate::contexts`] (finalized with `finalize(false)` and preprocessed with
//! `PreprocessedCircuit::preprocess_circuit`, as the upstream tests do) the oracle proves the
//! assignment under `default_circuit_pcs_config` (`FriConfig::default()` lifted to the trace) with
//! the default `Blake2sM31MerkleChannel`. `prove_circuit_with_precompute` has no hooks, so the
//! oracle mirrors `prove_circuit_assignment_with_channel` and `prove_circuit_with_precompute` call
//! for call and records the Fiat-Shamir channel digest after every transcript step:
//!
//! 1. `mix_felts([channel_salt])`;
//! 2. `FriConfig::mix_into`;
//! 3. `commit_tree` of the preprocessed tree;
//! 4. `mix_hash(circuit_hash)`; 5. `CircuitClaim::mix_into`; 6. commit of the base trace;
//! 7. `mix_u64` of the interaction grind nonce (`INTERACTION_POW_BITS`);
//! 8. `CircuitInteractionElements::draw` (the drawn `z` and `alpha` are recorded from a channel
//!    clone); 9. `CircuitInteractionClaim::mix_into`; 10. commit of the interaction trace;
//! 11. `prove_ex`, which has no hook: the steps after it are the proof's own fields (the
//!    composition commitment, the FRI layer commitments and last layer, the FRI grind nonce).
//!
//! Before `prove_ex` consumes the commitment scheme, the committed base and interaction columns
//! are digested per component in `ComponentList` order ([`columns::BASE`],
//! [`columns::INTERACTION`]); the preprocessed columns are digested as one component. The mirrored
//! proof must equal the output of upstream `prove_circuit_assignment`: the serde encoding of the
//! `ExtendedStarkProof`, the claims, the nonce and the circuit hash are compared byte for byte.
//! The preprocessed roots of the four contexts `prover_test.rs` snapshots are asserted, and for
//! circuits with a Blake2s-digest output the `CircuitSerialize` bytes of
//! `prepare_circuit_proof_for_circuit_verifier` are recorded.
//!
//! `--memory-budget` bounds a conservative estimate of the prover's resident memory (every
//! committed column as evaluations, coefficients and a blown-up evaluation, plus the Merkle
//! layers); a context over budget is refused before proving.

use anyhow::{Result, bail, ensure};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_common::{N_RESERVED, Qm31OpsTraceGenerator};
use circuit_prover::circuit_air::circuit_components::CircuitComponents;
use circuit_prover::circuit_hash::compute_circuit_hash;
use circuit_prover::prover::{
    BaseColumnPool, CircuitProof, SimdBackend, prepare_circuit_proof_for_circuit_verifier,
    prove_circuit_assignment_with_channel,
};
use circuit_prover::witness::trace::{TraceGenerator, write_interaction_trace, write_trace};
use circuit_serialize::serialize::CircuitSerialize;
use circuit_verifier::circuit_claim::{
    CircuitInteractionElements, column_log_sizes_per_tree, lookup_sum,
};
use circuit_verifier::statement::{
    INTERACTION_POW_BITS, all_circuit_components, circuit_component_log_sizes,
};
use circuits::ivalue::NoValue;
use circuits::utils::le_u32s_from_bytes;
use num_traits::Zero;
use serde::Serialize;
use stwo::core::channel::{Blake2sChannelGeneric, Channel, MerkleChannel};
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof_of_work::GrindOps;
use stwo::core::utils::MaybeOwned;
use stwo::core::vcs_lifted::blake2_merkle::{
    Blake2sM31MerkleChannel, Blake2sMerkleChannel, Blake2sMerkleHasher,
};
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::Column;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{CommitmentSchemeProver, CommitmentTreeProver, prove_ex};
use stwo_constraint_framework::{
    INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX,
};

use crate::checkpoint::{Envelope, U64Record, hex32, qm31, sha256_hex, values_sha256};
use crate::columns::{self, ColumnDigester, ComponentColumns};
use crate::contexts::{self, TestContext};

/// `COMPOSITION_POLYNOMIAL_LOG_DEGREE_BOUND` of `crates/circuit_prover/src/prover.rs`.
const COMPOSITION_POLYNOMIAL_LOG_DEGREE_BOUND: u32 = 1;

/// The default `--memory-budget`: 4 GiB, half of the per-process cap of this lane's hosts.
pub const DEFAULT_MEMORY_BUDGET: u64 = 4 << 30;

/// `preprocessed_root_from_proof` snapshots of `prover_test.rs`.
const PREPROCESSED_ROOT_SNAPSHOTS: [(TestContext, [u32; 8]); 4] = [
    (
        TestContext::TripleXor,
        [
            3108580124, 1195472639, 406742981, 4043963605, 410011815, 3851714429, 3026550905,
            53533403,
        ],
    ),
    (
        TestContext::Fibonacci,
        [
            3839694203, 1426645878, 544260312, 942396420, 1308763733, 2376548999, 3794595096,
            1471736858,
        ],
    ),
    (
        TestContext::M31ToU32,
        [
            600625078, 2147083019, 3436167066, 2746062012, 2124652205, 863849368, 4013760731,
            1715700551,
        ],
    ),
    (
        TestContext::BlakeGGate,
        [
            2845429778, 2218835085, 1205125096, 2501607039, 240595925, 1726247725, 2770929447,
            238604015,
        ],
    ),
];

#[derive(Serialize)]
pub struct StepRecord {
    pub step: &'static str,
    pub channel_digest: String,
}

#[derive(Serialize)]
pub struct FriRecord {
    pub first_layer_root: String,
    pub inner_layer_roots: Vec<String>,
    pub last_layer_poly: Vec<[u32; 4]>,
}

#[derive(Serialize)]
pub struct ProofRecord {
    pub name: &'static str,
    pub pcs_config: PcsConfig,
    pub trace_log_size: u32,
    pub values_sha256: String,
    pub memory_estimate_bytes: u64,
    pub component_log_sizes: Vec<(&'static str, u32)>,
    pub steps: Vec<StepRecord>,
    pub preprocessed_root: String,
    pub circuit_hash: String,
    pub output_values: Vec<[u32; 4]>,
    pub interaction_pow_nonce: U64Record,
    pub interaction_z: [u32; 4],
    pub interaction_alpha: [u32; 4],
    pub claimed_sums: Vec<(&'static str, [u32; 4])>,
    /// `commitments` of the STARK proof: preprocessed, base, interaction, composition.
    pub commitments: Vec<String>,
    pub fri: FriRecord,
    pub fri_pow_nonce: U64Record,
    pub preprocessed_columns: Vec<ComponentColumns>,
    pub preprocessed_accumulator_sha256: String,
    pub base_columns: Vec<ComponentColumns>,
    pub base_accumulator_sha256: String,
    pub interaction_columns: Vec<ComponentColumns>,
    pub interaction_accumulator_sha256: String,
    /// SHA-256 of `serde_json::to_vec(&StarkProof)` (the aux data is left out: it holds
    /// `HashMap`s, whose serde order is not deterministic).
    pub stark_proof_json_sha256: String,
    /// `CircuitSerialize` of `prepare_circuit_proof_for_circuit_verifier`, for circuits whose
    /// outputs are a Blake2s digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_serialize: Option<SerializedRecord>,
}

#[derive(Serialize)]
pub struct SerializedRecord {
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct ProveSmallBody {
    pub channel: &'static str,
    pub proofs: Vec<ProofRecord>,
}

/// The circuit FRI config every checked-in circuit registry uses
/// (`crates/circuit_params/tests/cairo_consts_test.rs`): 26 PoW bits, blowup 1, 70 queries,
/// fold step 4. `prove-profiles` proves under it so that both grinds (20-bit interaction,
/// 26-bit FRI) run in `SimdBackend` order on both channel profiles.
fn circuit_fri_config() -> FriConfig {
    FriConfig::new(26, 0, 1, 70, 4)
}

/// The contexts `prove-profiles` proves on each channel profile.
const PROFILE_CONTEXTS: [TestContext; 2] = [TestContext::Fibonacci, TestContext::BlakeGGate];

/// An estimate of the prover's peak resident memory from the committed column sizes: every column
/// held as evaluations, coefficients and a blown-up evaluation (4 bytes per M31), the four
/// lifted Merkle trees (two 32-byte layers per leaf), doubled for allocator and scratch headroom.
fn memory_estimate(preprocessed: &PreprocessedCircuit, config: &PcsConfig) -> u64 {
    let blowup = 1u64 << config.fri_config.log_blowup_factor;
    let column_bytes = |log_size: u32| (1u64 << log_size) * 4 * (2 + blowup);
    let preprocessed_bytes: u64 = preprocessed
        .preprocessed_trace
        .log_sizes()
        .values()
        .map(|log_size| column_bytes(*log_size))
        .sum();
    let log_sizes = crate::topology::component_log_sizes_of(preprocessed);
    let trace_bytes: u64 = all_circuit_components::<NoValue>()
        .values()
        .zip(&log_sizes)
        .map(|(component, (_, log_size))| {
            (component.trace_columns() + component.interaction_columns()) as u64
                * column_bytes(*log_size)
        })
        .sum();
    let trace_log_size = preprocessed.trace_log_size();
    let composition_bytes = 8 * column_bytes(trace_log_size);
    let merkle_bytes =
        4 * 2 * 32 * (1u64 << (trace_log_size + config.fri_config.log_blowup_factor));
    2 * (preprocessed_bytes + trace_bytes + composition_bytes + merkle_bytes)
}

struct Mirrored {
    proof: CircuitProof<Blake2sMerkleHasher>,
    steps: Vec<StepRecord>,
    z: QM31,
    alpha: QM31,
    preprocessed: (Vec<ComponentColumns>, String),
    base: (Vec<ComponentColumns>, String),
    interaction: (Vec<ComponentColumns>, String),
}

/// Digests the columns of one committed tree, grouped by component column counts.
fn digest_tree<'a>(
    domains: columns::Domains,
    evaluations: impl Iterator<Item = Vec<stwo::core::fields::m31::BaseField>>,
    groups: impl Iterator<Item = (&'a str, usize)>,
) -> Result<(Vec<ComponentColumns>, String)> {
    let mut evaluations = evaluations;
    let mut digester = ColumnDigester::new(domains);
    for (label, n_columns) in groups {
        let columns = (0..n_columns)
            .map(|_| evaluations.next().map(|values| (None, values)))
            .collect::<Option<Vec<_>>>();
        let Some(columns) = columns else {
            bail!("{label}: tree has fewer columns than the component list");
        };
        digester.component(label, columns)?;
    }
    ensure!(
        evaluations.next().is_none(),
        "tree has more columns than the component list"
    );
    Ok(digester.finish())
}

/// `prove_circuit_assignment_with_channel` + `prove_circuit_with_precompute`, with step marks.
fn prove_mirrored<MC, const M31_OUTPUT: bool>(
    values: &[QM31],
    circuit: &PreprocessedCircuit,
    config: PcsConfig,
) -> Result<Mirrored>
where
    MC: MerkleChannel<C = Blake2sChannelGeneric<M31_OUTPUT>, H = Blake2sMerkleHasher>,
    SimdBackend: BackendForChannel<MC>,
{
    let pool = BaseColumnPool::<SimdBackend>::new();
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(
            circuit.trace_log_size()
                + std::cmp::max(
                    config.fri_config.log_blowup_factor,
                    COMPOSITION_POLYNOMIAL_LOG_DEGREE_BOUND,
                ),
        )
        .circle_domain()
        .half_coset,
    );
    let preprocessed_trace_polys = SimdBackend::interpolate_columns(
        circuit.preprocessed_trace.get_trace::<SimdBackend>(),
        &twiddles,
    );
    let preprocessed_tree = CommitmentTreeProver::<SimdBackend, MC>::new(
        preprocessed_trace_polys,
        config.fri_config.log_blowup_factor,
        &twiddles,
        true,
        config.preprocessed_lifting_log_size,
        &pool,
    );

    let PreprocessedCircuit {
        preprocessed_trace,
        first_permutation_row,
        n_outputs,
    } = circuit;
    let trace_generator = TraceGenerator {
        qm31_ops_trace_generator: Qm31OpsTraceGenerator {
            first_permutation_row: *first_permutation_row,
        },
    };
    let mut steps = Vec::new();
    let mut step = |step: &'static str, channel: &Blake2sChannelGeneric<M31_OUTPUT>| {
        steps.push(StepRecord {
            step,
            channel_digest: hex32(channel.digest().0),
        })
    };

    let channel = &mut Blake2sChannelGeneric::<M31_OUTPUT>::default();
    let channel_salt = 0_u32;
    channel.mix_felts(&[channel_salt.into()]);
    step("mix_channel_salt", channel);
    config.fri_config.mix_into(channel);
    step("mix_fri_config", channel);
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, MC>::with_memory_pool(config, &twiddles, &pool);
    commitment_scheme.set_store_polynomials_coefficients();
    let preprocessed_root = preprocessed_tree.commitment.root();
    commitment_scheme.commit_tree(MaybeOwned::Owned(preprocessed_tree), channel);
    step("commit_preprocessed", channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    let (claim, component_log_sizes, interaction_generator) = write_trace(
        values,
        preprocessed_trace.clone(),
        *n_outputs,
        &mut tree_builder,
        &trace_generator,
        &twiddles,
    );
    let circuit_hash = compute_circuit_hash::<Blake2sMerkleHasher>(
        &component_log_sizes,
        config.fri_config.log_blowup_factor,
        preprocessed_root,
    );
    MC::mix_hash(channel, circuit_hash);
    step("mix_circuit_hash", channel);
    claim.mix_into(channel);
    step("mix_claim", channel);
    tree_builder.commit(channel);
    step("commit_base_trace", channel);

    let interaction_pow_nonce = SimdBackend::grind(channel, INTERACTION_POW_BITS);
    channel.mix_u64(interaction_pow_nonce);
    step("mix_interaction_pow_nonce", channel);
    let [z, alpha]: [QM31; 2] = channel
        .clone()
        .draw_secure_felts(2)
        .try_into()
        .expect("two draws");
    let interaction_elements = CircuitInteractionElements::draw(channel);
    step("draw_interaction_elements", channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    let interaction_claim = write_interaction_trace(
        &component_log_sizes,
        interaction_generator,
        &mut tree_builder,
        &interaction_elements,
        &twiddles,
    );
    ensure!(
        lookup_sum(&claim, &interaction_claim, &interaction_elements) == QM31::zero(),
        "lookup sum is not zero"
    );
    interaction_claim.mix_into(channel);
    step("mix_interaction_claim", channel);
    tree_builder.commit(channel);
    step("commit_interaction_trace", channel);

    // Digest the committed columns before `prove_ex` consumes the commitment scheme.
    let evaluations = commitment_scheme.evaluations();
    let components = all_circuit_components::<NoValue>();
    let ids = preprocessed_trace.ids();
    let preprocessed = {
        let mut digester = ColumnDigester::new(columns::PREPROCESSED);
        digester.component(
            "preprocessed",
            evaluations[PREPROCESSED_TRACE_IDX]
                .iter()
                .zip(&ids)
                .map(|(eval, id)| (Some(id.id.clone()), eval.values.to_cpu())),
        )?;
        digester.finish()
    };
    let base = digest_tree(
        columns::BASE,
        evaluations[ORIGINAL_TRACE_IDX]
            .iter()
            .map(|eval| eval.values.to_cpu()),
        components
            .iter()
            .map(|(name, c)| (*name, c.trace_columns())),
    )?;
    let interaction = digest_tree(
        columns::INTERACTION,
        evaluations[INTERACTION_TRACE_IDX]
            .iter()
            .map(|eval| eval.values.to_cpu()),
        components
            .iter()
            .map(|(name, c)| (*name, c.interaction_columns())),
    )?;
    drop(evaluations);

    let circuit_components = CircuitComponents::new(
        &interaction_elements,
        &interaction_claim,
        &component_log_sizes,
        &preprocessed_trace.ids(),
    );
    let provers = circuit_components.component_provers();
    let stark_proof = prove_ex::<SimdBackend, _>(&provers, channel, commitment_scheme, true)
        .map_err(|error| anyhow::anyhow!("prove_ex: {error:?}"))?;
    step("prove_ex", channel);
    Ok(Mirrored {
        proof: CircuitProof {
            pcs_config: config,
            claim,
            interaction_pow_nonce,
            interaction_claim,
            stark_proof,
            channel_salt,
            circuit_hash,
        },
        steps,
        z,
        alpha,
        preprocessed,
        base,
        interaction,
    })
}

/// The fields in which two proofs differ (empty when equal byte for byte).
fn proof_differences(
    a: &CircuitProof<Blake2sMerkleHasher>,
    b: &CircuitProof<Blake2sMerkleHasher>,
) -> Result<Vec<&'static str>> {
    let json = |value: &dyn erased::Json| value.bytes();
    let checks = [
        (
            "stark_proof.proof",
            json(&a.stark_proof.proof) == json(&b.stark_proof.proof),
        ),
        // The aux Merkle data holds `HashMap`s: compare as JSON values, whose maps are
        // order-insensitive.
        (
            "stark_proof.aux",
            serde_json::to_value(&a.stark_proof.aux)? == serde_json::to_value(&b.stark_proof.aux)?,
        ),
        ("claim", a.claim == b.claim),
        (
            "interaction_claim",
            a.interaction_claim == b.interaction_claim,
        ),
        (
            "interaction_pow_nonce",
            a.interaction_pow_nonce == b.interaction_pow_nonce,
        ),
        ("channel_salt", a.channel_salt == b.channel_salt),
        ("circuit_hash", a.circuit_hash == b.circuit_hash),
        ("pcs_config", json(&a.pcs_config) == json(&b.pcs_config)),
    ];
    Ok(checks
        .into_iter()
        .filter_map(|(field, same)| (!same).then_some(field))
        .collect())
}

mod erased {
    /// Object-safe serde JSON encoding, for comparing heterogeneous proof fields.
    pub trait Json {
        fn bytes(&self) -> Vec<u8>;
    }

    impl<T: serde::Serialize> Json for T {
        fn bytes(&self) -> Vec<u8> {
            serde_json::to_vec(self).expect("proof fields encode as JSON")
        }
    }
}

/// `stwo_verify` of `crates/circuit_prover/src/prover_test.rs`: the native stwo verifier on a
/// circuit proof, with the lookup sum checked to be zero.
fn native_verify<MC>(proof: CircuitProof<MC::H>, preprocessed: &PreprocessedCircuit) -> Result<()>
where
    MC: MerkleChannel,
{
    let CircuitProof {
        claim,
        interaction_claim,
        pcs_config,
        stark_proof: proof,
        interaction_pow_nonce,
        channel_salt,
        circuit_hash: _,
    } = proof;
    let preprocessed_column_log_sizes = preprocessed.preprocessed_trace.log_sizes();
    let log_sizes = circuit_component_log_sizes(
        &all_circuit_components::<NoValue>(),
        &preprocessed_column_log_sizes,
    );
    let channel = &mut MC::C::default();
    channel.mix_felts(&[channel_salt.into()]);
    pcs_config.fri_config.mix_into(channel);
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(pcs_config);
    let [trace_log_sizes, interaction_log_sizes] = column_log_sizes_per_tree(&log_sizes);
    commitment_scheme.commit(
        proof.proof.commitments[0],
        &preprocessed_column_log_sizes.values().copied().collect::<Vec<_>>(),
        channel,
    );
    let circuit_hash = compute_circuit_hash::<MC::H>(
        &log_sizes,
        pcs_config.fri_config.log_blowup_factor,
        proof.proof.commitments[0],
    );
    MC::mix_hash(channel, circuit_hash);
    claim.mix_into(channel);
    commitment_scheme.commit(proof.proof.commitments[1], &trace_log_sizes, channel);
    ensure!(
        channel.verify_pow_nonce(INTERACTION_POW_BITS, interaction_pow_nonce),
        "interaction proof of work"
    );
    channel.mix_u64(interaction_pow_nonce);
    let interaction_elements = CircuitInteractionElements::draw(channel);
    interaction_claim.mix_into(channel);
    commitment_scheme.commit(proof.proof.commitments[2], &interaction_log_sizes, channel);
    let components = CircuitComponents::new(
        &interaction_elements,
        &interaction_claim,
        &log_sizes,
        &preprocessed.preprocessed_trace.ids(),
    );
    stwo::core::verifier::verify_ex(
        &components.components(),
        channel,
        commitment_scheme,
        proof.proof,
        true,
    )
    .map_err(|error| anyhow::anyhow!("verify_ex: {error:?}"))?;
    ensure!(
        lookup_sum(&claim, &interaction_claim, &interaction_elements) == QM31::zero(),
        "lookup sum is not zero"
    );
    Ok(())
}

fn proof_record<MC, const M31_OUTPUT: bool>(
    test: TestContext,
    fri_config: FriConfig,
    memory_budget: u64,
) -> Result<ProofRecord>
where
    MC: MerkleChannel<C = Blake2sChannelGeneric<M31_OUTPUT>, H = Blake2sMerkleHasher>,
    SimdBackend: BackendForChannel<MC>,
{
    proof_record_verified::<MC, M31_OUTPUT>(test, fri_config, memory_budget, false).map(|(r, _)| r)
}

/// [`proof_record`], optionally also verifying upstream's proof with [`native_verify`].
fn proof_record_verified<MC, const M31_OUTPUT: bool>(
    test: TestContext,
    fri_config: FriConfig,
    memory_budget: u64,
    verify: bool,
) -> Result<(ProofRecord, bool)>
where
    MC: MerkleChannel<C = Blake2sChannelGeneric<M31_OUTPUT>, H = Blake2sMerkleHasher>,
    SimdBackend: BackendForChannel<MC>,
{
    let name = test.name();
    let mut context = test.context::<QM31>(true)?.finalize(false);
    context.validate_circuit();
    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut context);
    let config = PcsConfig::from_fri_and_trace_size(fri_config, preprocessed.trace_log_size());
    let memory_estimate_bytes = memory_estimate(&preprocessed, &config);
    ensure!(
        memory_estimate_bytes <= memory_budget,
        "{name}: estimated {memory_estimate_bytes} bytes exceed --memory-budget {memory_budget}"
    );

    let mirrored = prove_mirrored::<MC, M31_OUTPUT>(context.values(), &preprocessed, config)?;
    let upstream = prove_circuit_assignment_with_channel::<MC>(
        context.values(),
        &preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
        config,
    )
    .map_err(|error| anyhow::anyhow!("{name}: prove_circuit_assignment: {error:?}"))?;
    let differences = proof_differences(&mirrored.proof, &upstream)?;
    ensure!(
        differences.is_empty(),
        "{name}: the mirrored proof differs from prove_circuit_assignment in {differences:?}"
    );
    let native_verified = if verify {
        native_verify::<MC>(upstream, &preprocessed)?;
        true
    } else {
        drop(upstream);
        false
    };

    let Mirrored {
        proof,
        steps,
        z,
        alpha,
        preprocessed: (preprocessed_columns, preprocessed_accumulator_sha256),
        base: (base_columns, base_accumulator_sha256),
        interaction: (interaction_columns, interaction_accumulator_sha256),
    } = mirrored;
    let commitments = &proof.stark_proof.proof.0.commitments;
    let preprocessed_root: [u32; 8] = le_u32s_from_bytes(commitments[PREPROCESSED_TRACE_IDX].0);
    if let Some((_, expected)) = PREPROCESSED_ROOT_SNAPSHOTS.iter().find(|(t, _)| *t == test) {
        ensure!(
            preprocessed_root == *expected,
            "{name}: preprocessed root differs from the prover_test.rs snapshot"
        );
    }
    let fri = &proof.stark_proof.proof.0.fri_proof;
    let fri_record = FriRecord {
        first_layer_root: hex32(fri.first_layer.commitment.0),
        inner_layer_roots: fri
            .inner_layers
            .iter()
            .map(|layer| hex32(layer.commitment.0))
            .collect(),
        last_layer_poly: fri.last_layer_poly.iter().map(|c| qm31(*c)).collect(),
    };
    let stark_proof_json_sha256 = sha256_hex(serde_json::to_vec(&proof.stark_proof.proof)?);
    let component_log_sizes = crate::topology::component_log_sizes_of(&preprocessed);
    let record = ProofRecord {
        name,
        pcs_config: config,
        trace_log_size: preprocessed.trace_log_size(),
        values_sha256: values_sha256(context.values()),
        memory_estimate_bytes,
        component_log_sizes,
        steps,
        preprocessed_root: hex32(commitments[PREPROCESSED_TRACE_IDX].0),
        circuit_hash: hex32(proof.circuit_hash.0),
        output_values: proof.claim.output_values.iter().map(|v| qm31(*v)).collect(),
        interaction_pow_nonce: proof.interaction_pow_nonce.into(),
        interaction_z: qm31(z),
        interaction_alpha: qm31(alpha),
        claimed_sums: proof
            .interaction_claim
            .claimed_sums
            .into_named_iter()
            .map(|(component, sum)| (component, qm31(sum)))
            .collect(),
        commitments: commitments.iter().map(|root| hex32(root.0)).collect(),
        fri: fri_record,
        fri_pow_nonce: proof.stark_proof.proof.0.proof_of_work.into(),
        preprocessed_columns,
        preprocessed_accumulator_sha256,
        base_columns,
        base_accumulator_sha256,
        interaction_columns,
        interaction_accumulator_sha256,
        stark_proof_json_sha256,
        circuit_serialize: None,
    };
    // Only circuits whose outputs are a Blake2s digest (plus `u`) feed the circuit verifier.
    let circuit_serialize = (proof.claim.output_values.len() == N_RESERVED).then(|| {
        let (prepared, _) = prepare_circuit_proof_for_circuit_verifier(proof);
        let mut bytes = Vec::new();
        prepared.serialize(&mut bytes);
        SerializedRecord {
            bytes: bytes.len(),
            sha256: sha256_hex(&bytes),
        }
    });
    Ok((
        ProofRecord {
            circuit_serialize,
            ..record
        },
        native_verified,
    ))
}

pub fn run(memory_budget: u64) -> Result<Envelope<ProveSmallBody>> {
    // `default_circuit_pcs_config` of `crates/circuit_prover/src/test_utils.rs`.
    let proofs = contexts::ALL
        .into_iter()
        .map(|test| {
            proof_record::<Blake2sM31MerkleChannel, true>(test, FriConfig::default(), memory_budget)
        })
        .collect::<Result<_>>()?;
    Ok(Envelope::new(
        "r7",
        "prove-small",
        Vec::new(),
        ProveSmallBody {
            channel: "blake2s_m31",
            proofs,
        },
    ))
}

/// A `prove-profiles` record: the `prove-small` record plus the verdict of upstream's native
/// `stwo_verify` (`crates/circuit_prover/src/prover_test.rs`) on the same proof.
#[derive(Serialize)]
pub struct ProfileProofRecord {
    #[serde(flatten)]
    pub record: ProofRecord,
    pub native_verified: bool,
}

#[derive(Serialize)]
pub struct ProfileProofs {
    /// `internal` (`Blake2sM31MerkleChannel`) or `root` (`Blake2sMerkleChannel`).
    pub profile: &'static str,
    pub channel: &'static str,
    pub proofs: Vec<ProfileProofRecord>,
}

#[derive(Serialize)]
pub struct ProveProfilesBody {
    pub profiles: Vec<ProfileProofs>,
}

/// `prove-profiles`: [`PROFILE_CONTEXTS`] under [`circuit_fri_config`], once on each channel
/// profile, with the same records as `prove-small`.
pub fn run_profiles(memory_budget: u64) -> Result<Envelope<ProveProfilesBody>> {
    let record = |(record, native_verified)| ProfileProofRecord {
        record,
        native_verified,
    };
    let internal = PROFILE_CONTEXTS
        .into_iter()
        .map(|test| {
            proof_record_verified::<Blake2sM31MerkleChannel, true>(
                test,
                circuit_fri_config(),
                memory_budget,
                true,
            )
            .map(record)
        })
        .collect::<Result<_>>()?;
    let root = PROFILE_CONTEXTS
        .into_iter()
        .map(|test| {
            proof_record_verified::<Blake2sMerkleChannel, false>(
                test,
                circuit_fri_config(),
                memory_budget,
                true,
            )
            .map(record)
        })
        .collect::<Result<_>>()?;
    Ok(Envelope::new(
        "r7",
        "prove-profiles",
        Vec::new(),
        ProveProfilesBody {
            profiles: vec![
                ProfileProofs {
                    profile: "internal",
                    channel: "blake2s_m31",
                    proofs: internal,
                },
                ProfileProofs {
                    profile: "root",
                    channel: "blake2s",
                    proofs: root,
                },
            ],
        },
    ))
}
