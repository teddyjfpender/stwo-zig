//! Rung R5: finalization and padding, one summary per sub-stage.
//!
//! For every test circuit of [`crate::contexts`] the oracle records, in value mode and in topology
//! mode (asserting both yield identical gate lists), the circuit after:
//!
//! 1. `built`: the builder calls;
//! 2. `finalize_constants`: `circuits::finalize_constants::finalize_constants` alone, on a fresh
//!    build (the constant interning `IndexMap` order and its `swap_remove`/`retain` passes are the
//!    parity hazard this stage pins);
//! 3. `finalized`: `Context::finalize(false)`, i.e. constants then guess finalization;
//! 4. `padded_<kind>`: `circuit_common::finalize::pad_to_targets` raising one component at a time
//!    to its `compute_padded_sizes` target, in the upstream order eq, qm31_ops, triple_xor,
//!    m31_to_u32, blake_g_gate (asserted equal to one `pad_context` call);
//! 5. `zk_blinded`: `add_zk_blinding` on the finalized circuit with the privacy registry's amount
//!    (`n_queries + NON_QUERY_INFO_LEAK`) and a fixed seed (a Blake2s trace root, as the Cairo
//!    verifier seeds it; topology mode uses the zero seed, as `build_cairo_verifier_circuit`
//!    does); then `zk_blinded_padded`, padded to its own power-of-two sizes.
//!
//! `values_sha256` is recorded for the value-mode circuit at every stage after `finalized`, and
//! every value-mode stage from `finalized` on is asserted satisfied.

use anyhow::{Result, ensure};
use circuit_cairo_verifier::verify::NON_QUERY_INFO_LEAK;
use circuit_common::finalize::{
    ComponentSizes, add_zk_blinding, compute_padded_sizes, pad_context, pad_to_targets,
    raw_component_sizes,
};
use circuits::context::{Context, FinalizedContext};
use circuits::finalize_constants::finalize_constants;
use circuits::ivalue::NoValue;
use serde::Serialize;
use stwo::core::fields::qm31::QM31;
use stwo::core::vcs_lifted::Hasher;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;

use crate::checkpoint::{Envelope, GateSummary, gate_summary, hex32};
use crate::contexts::{self, Mode, TestContext};
use crate::goldens;

/// `n_queries` of `circuit_registry_definitions/privacy/**/circuit_fri_config.json`
/// (`fri_config_privacy_large_proofs` in the `primitives` checkpoint).
const PRIVACY_N_QUERIES: usize = 35;

#[derive(Serialize, Clone, Copy)]
pub struct SizesRecord {
    pub eq: usize,
    pub qm31_ops: usize,
    pub m31_to_u32: usize,
    pub triple_xor: usize,
    pub blake_g_gate: usize,
}

impl From<&ComponentSizes> for SizesRecord {
    fn from(sizes: &ComponentSizes) -> Self {
        Self {
            eq: sizes.eq,
            qm31_ops: sizes.qm31_ops,
            m31_to_u32: sizes.m31_to_u32,
            triple_xor: sizes.triple_xor,
            blake_g_gate: sizes.blake_g_gate,
        }
    }
}

#[derive(Serialize)]
pub struct StageRecord {
    pub stage: String,
    pub circuit: GateSummary,
    /// Raw (unpadded) AIR component row counts, for stages after `finalize`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_sizes: Option<SizesRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values_sha256: Option<String>,
}

#[derive(Serialize)]
pub struct ContextRecord {
    pub name: &'static str,
    pub n_reserved: usize,
    pub padded_sizes: SizesRecord,
    pub stages: Vec<StageRecord>,
}

#[derive(Serialize)]
pub struct FinalizeBody {
    pub zk_blinding_amount: usize,
    pub zk_blinding_seed: String,
    pub contexts: Vec<ContextRecord>,
}

/// One sub-stage as seen in one value mode.
struct Stage {
    name: String,
    circuit: GateSummary,
    raw_sizes: Option<SizesRecord>,
    values_sha256: Option<String>,
}

/// The padding order of `pad_to_targets`, as setters raising one component of `sizes`.
const PAD_ORDER: [(&str, fn(&mut ComponentSizes, &ComponentSizes)); 5] = [
    ("eq", |s, t| s.eq = t.eq),
    ("qm31_ops", |s, t| s.qm31_ops = t.qm31_ops),
    ("triple_xor", |s, t| s.triple_xor = t.triple_xor),
    ("m31_to_u32", |s, t| s.m31_to_u32 = t.m31_to_u32),
    ("blake_g_gate", |s, t| s.blake_g_gate = t.blake_g_gate),
];

fn finalized_stage<V: Mode>(name: &str, context: &FinalizedContext<V>) -> Stage {
    Stage {
        name: name.to_owned(),
        circuit: gate_summary(context.circuit()),
        raw_sizes: Some(SizesRecord::from(&raw_component_sizes(context))),
        values_sha256: V::values_sha256(context.values()),
    }
}

fn stages<V: Mode>(test: TestContext, seed: [u8; 32], values: bool) -> Result<Vec<Stage>> {
    let check = |context: &FinalizedContext<V>, stage: &str| -> Result<()> {
        ensure!(
            !values || V::is_circuit_valid(context),
            "{}: circuit is not satisfied after {stage}",
            test.name()
        );
        Ok(())
    };
    let mut stages = Vec::new();

    let context: Context<V> = test.context(values)?;
    stages.push(Stage {
        name: "built".into(),
        circuit: gate_summary(&context.circuit),
        raw_sizes: None,
        values_sha256: None,
    });

    let mut constants_only: Context<V> = test.context(values)?;
    finalize_constants(&mut constants_only);
    stages.push(Stage {
        name: "finalize_constants".into(),
        circuit: gate_summary(&constants_only.circuit),
        raw_sizes: None,
        values_sha256: None,
    });

    let finalized = context.finalize(false);
    check(&finalized, "finalize")?;
    stages.push(finalized_stage("finalized", &finalized));

    // Padding, one component kind at a time.
    let targets = compute_padded_sizes(&finalized);
    let mut padded = test.context::<V>(values)?.finalize(false);
    let mut current = raw_component_sizes(&padded);
    for (kind, raise) in PAD_ORDER {
        raise(&mut current, &targets);
        pad_to_targets(&mut padded, &current);
        check(&padded, kind)?;
        stages.push(finalized_stage(&format!("padded_{kind}"), &padded));
    }
    let mut padded_once = test.context::<V>(values)?.finalize(false);
    pad_context(&mut padded_once);
    ensure!(
        gate_summary(padded_once.circuit()) == gate_summary(padded.circuit()),
        "{}: per-kind padding differs from pad_context",
        test.name()
    );

    // ZK blinding with the privacy amount, then padding.
    let amount = PRIVACY_N_QUERIES + NON_QUERY_INFO_LEAK;
    let mut blinded = test.context::<V>(values)?.finalize(false);
    add_zk_blinding(&mut blinded, seed, amount);
    check(&blinded, "add_zk_blinding")?;
    stages.push(finalized_stage("zk_blinded", &blinded));
    pad_context(&mut blinded);
    check(&blinded, "add_zk_blinding + pad_context")?;
    stages.push(finalized_stage("zk_blinded_padded", &blinded));

    Ok(stages)
}

fn context_record(test: TestContext, seed: [u8; 32]) -> Result<ContextRecord> {
    let value_stages = stages::<QM31>(test, seed, true)?;
    let topology_stages = stages::<NoValue>(test, [0; 32], false)?;
    ensure!(
        value_stages.len() == topology_stages.len(),
        "{}: stage lists differ",
        test.name()
    );
    for (value, topology) in value_stages.iter().zip(&topology_stages) {
        ensure!(
            value.name == topology.name && value.circuit == topology.circuit,
            "{}: value and topology gate lists differ after {}",
            test.name(),
            value.name
        );
    }
    let padded_sizes = compute_padded_sizes(&test.context::<NoValue>(false)?.finalize(false));
    Ok(ContextRecord {
        name: test.name(),
        n_reserved: test.n_reserved(),
        padded_sizes: SizesRecord::from(&padded_sizes),
        stages: value_stages
            .into_iter()
            .map(|stage| StageRecord {
                stage: stage.name,
                circuit: stage.circuit,
                raw_sizes: stage.raw_sizes,
                values_sha256: stage.values_sha256,
            })
            .collect(),
    })
}

pub fn run() -> Result<Envelope<FinalizeBody>> {
    // A realistic trace-root seed, the same as the `blake2s_digest_seed` ChaCha KAT of R0.
    let seed = Blake2sMerkleHasher::hash_u32s(&goldens::HASHER_TEST_WORDS).0;
    let contexts = contexts::ALL
        .into_iter()
        .map(|test| context_record(test, seed))
        .collect::<Result<_>>()?;
    Ok(Envelope::new(
        "r5",
        "finalize",
        Vec::new(),
        FinalizeBody {
            zk_blinding_amount: PRIVACY_N_QUERIES + NON_QUERY_INFO_LEAK,
            zk_blinding_seed: hex32(seed),
            contexts,
        },
    ))
}
