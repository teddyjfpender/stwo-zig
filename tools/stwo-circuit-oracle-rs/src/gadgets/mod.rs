//! Rungs R1 and R2: builder snapshots and gadget circuits.
//!
//! For each case the oracle records the gate-list summary right after the builder calls
//! (`built`) and after `Context::finalize(false)` (`finalized`), the finalized value digest and
//! the values of the case's output variables. Before emitting, it asserts that:
//!
//! - the `NoValue` build yields exactly the same gate lists and output variables at both stages;
//! - the finalized `QM31` circuit is satisfied and every variable is yielded exactly once;
//! - gadget outputs equal a host-side computation where one exists (Blake2s digests, the
//!   `reduce_to_m31` packing, the circuit-hash golden).

mod cases;

use anyhow::{Result, ensure};
use circuits::blake::qm31_from_bytes;
use circuits::context::{Context, Var};
use circuits::ivalue::{IValue, NoValue};
use serde::Serialize;
use stwo::core::fields::qm31::QM31;
use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasher, reduce_to_m31};

use crate::checkpoint::{
    CircuitSummary, Envelope, circuit_summary, debug_text, qm31, values_sha256,
};
use crate::goldens;
use cases::{CASES, Case, REDUCE_HASH_WORDS, m31_message_words, message_bytes};

/// Finalized circuits up to this many gates carry their full `Debug` text in the checkpoint.
const DEBUG_TEXT_MAX_GATES: usize = 800;

#[derive(Serialize)]
pub struct CaseRecord {
    pub name: String,
    pub rung: &'static str,
    pub n_reserved: usize,
    pub built: CircuitSummary,
    pub finalized: CircuitSummary,
    pub finalized_values_sha256: String,
    pub output_vars: Vec<usize>,
    pub output_values: Vec<[u32; 4]>,
    /// `true` when `output_values` were checked against an independent host computation.
    pub outputs_host_checked: bool,
    /// The finalized circuit's `Debug` text, one gate per line, for small circuits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalized_debug_text: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct GadgetsBody {
    pub debug_text_max_gates: usize,
    pub cases: Vec<CaseRecord>,
}

fn digest_words(hash: Blake2sHash) -> Vec<QM31> {
    hash.0
        .chunks_exact(4)
        .map(|chunk| *QM31::pack_u32(u32::from_le_bytes(chunk.try_into().unwrap())).get())
        .collect()
}

fn le_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Host-side expectations for the outputs of cases that compute a known function.
fn expected_outputs(case: Case) -> Option<Vec<QM31>> {
    match case {
        Case::Blake2sU32s(n_bytes) => {
            Some(digest_words(Blake2sHasher::hash(&message_bytes(n_bytes))))
        }
        Case::Blake2sQm31 { n_bytes, reduce } => {
            let bytes = le_bytes(&m31_message_words(n_bytes));
            let hash = Blake2sHasher::hash(&bytes[..n_bytes]);
            Some(if reduce {
                reduced_pair(reduce_to_m31(hash.0))
            } else {
                digest_words(hash)
            })
        }
        Case::ReduceHashValue => Some(reduced_pair(reduce_to_m31(
            le_bytes(&REDUCE_HASH_WORDS).try_into().unwrap(),
        ))),
        Case::CircuitHash => Some(
            goldens::CIRCUIT_HASH_TEST_WORDS
                .into_iter()
                .map(|w| *QM31::pack_u32(w).get())
                .collect(),
        ),
        _ => None,
    }
}

fn reduced_pair(reduced: [u8; 32]) -> Vec<QM31> {
    vec![
        qm31_from_bytes(reduced[0..16].try_into().unwrap()),
        qm31_from_bytes(reduced[16..32].try_into().unwrap()),
    ]
}

fn gate_count(summary: &CircuitSummary) -> usize {
    summary.kinds.iter().map(|kind| kind.count as usize).sum()
}

fn build_topology(case: Case) -> (Vec<Var>, CircuitSummary, CircuitSummary) {
    let mut context = Context::<NoValue>::new(case.n_reserved());
    let outputs = case.build(&mut context);
    let built = circuit_summary(&context.circuit);
    let finalized = context.finalize(false);
    (outputs, built, circuit_summary(finalized.circuit()))
}

fn run_case(case: Case) -> Result<CaseRecord> {
    let name = case.name();
    let mut context = Context::<QM31>::new(case.n_reserved());
    context.enable_assert_eq_on_eval();
    let outputs = case.build(&mut context);
    let output_values: Vec<QM31> = outputs.iter().map(|var| context.get(*var)).collect();
    let built = circuit_summary(&context.circuit);
    let finalized_context = context.finalize(false);
    ensure!(
        finalized_context.is_circuit_valid(),
        "{name}: finalized circuit is not satisfied"
    );
    finalized_context.circuit().check_yields();
    let finalized = circuit_summary(finalized_context.circuit());

    let (topology_outputs, topology_built, topology_finalized) = build_topology(case);
    ensure!(
        topology_outputs == outputs,
        "{name}: NoValue output variables differ"
    );
    ensure!(
        topology_built == built,
        "{name}: NoValue built gate lists differ"
    );
    ensure!(
        topology_finalized == finalized,
        "{name}: NoValue finalized gate lists differ"
    );

    let expected = expected_outputs(case);
    if let Some(expected) = &expected {
        ensure!(
            *expected == output_values,
            "{name}: outputs differ from the host computation"
        );
    }

    let finalized_debug_text = (gate_count(&finalized) <= DEBUG_TEXT_MAX_GATES).then(|| {
        debug_text(finalized_context.circuit())
            .lines()
            .map(str::to_owned)
            .collect()
    });
    Ok(CaseRecord {
        rung: case.rung(),
        n_reserved: case.n_reserved(),
        built,
        finalized,
        finalized_values_sha256: values_sha256(finalized_context.values()),
        output_vars: outputs.iter().map(|var| var.idx).collect(),
        output_values: output_values.into_iter().map(qm31).collect(),
        outputs_host_checked: expected.is_some(),
        finalized_debug_text,
        name,
    })
}

pub fn run() -> Result<Envelope<GadgetsBody>> {
    let cases = CASES.into_iter().map(run_case).collect::<Result<_>>()?;
    Ok(Envelope::new(
        "r1-r2",
        "gadgets",
        Vec::new(),
        GadgetsBody {
            debug_text_max_gates: DEBUG_TEXT_MAX_GATES,
            cases,
        },
    ))
}
