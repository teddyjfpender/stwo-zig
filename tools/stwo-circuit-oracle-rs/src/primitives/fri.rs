//! FRI folding with `fold_step = 4` and `log_last_layer_degree_bound = 0`, the circuit FRI shape
//! of every shipped registry (`circuit_fri_config.json`).
//!
//! The vector replays the prover's layer schedule (`crates/stwo/src/prover/fri.rs`,
//! `FriProver::commit`) with the single-fold functions of `crates/stwo/src/core/fri.rs`:
//!
//! - first layer: `fold_circle_into_line(alpha_0)` on the circle evaluation, then
//!   `fold_step - 1` line folds with `alpha_0^2, alpha_0^4, alpha_0^8`
//!   (`squared_alpha_powers(alpha_0^2, fold_step - 1)`);
//! - every further layer `k`: `fold_step` line folds with `alpha_k, alpha_k^2, alpha_k^4, ...`
//!   (`squared_alpha_powers(alpha_k, fold_step)`), the last one clamped to the remaining size.
//!
//! The input is stored in bit-reversed order over `CanonicCoset::new(LOG_SIZE).circle_domain()`,
//! as the prover stores it; its values need not be of low degree. Each single fold is recorded
//! with the digest [`values_sha256`] of its output and its first values. Before emitting, the
//! oracle asserts that the verifier's per-subset `fold_coset` reproduces every layer.

use serde::Serialize;
use stwo::core::fields::m31::P;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::{fold_circle_into_line, fold_coset, fold_line};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::LineDomain;

use anyhow::{Result, ensure};
use circuits::ivalue::qm31_from_u32s;

use crate::checkpoint::{qm31, values_sha256};

/// Log size of the circle evaluation: 2^8 values fold to one through two fold_step-4 layers.
const LOG_SIZE: u32 = 8;
const FOLD_STEP: u32 = 4;
const LOG_LAST_LAYER_DEGREE_BOUND: u32 = 0;
/// Leading output values recorded per fold.
const HEAD: usize = 4;

/// The fixed layer alphas: one per FRI layer (each the value a channel draw would produce).
const ALPHAS: [[u32; 4]; 2] = [[5, 7, 11, 13], [17, 19, 23, 29]];

#[derive(Serialize)]
pub struct FoldRecord {
    /// `circle_into_line` or `line`.
    pub kind: &'static str,
    pub alpha: [u32; 4],
    /// Log size of the output evaluation.
    pub log_size: u32,
    pub values_sha256: String,
    pub head: Vec<[u32; 4]>,
}

#[derive(Serialize)]
pub struct FriLayerRecord {
    pub layer: usize,
    pub layer_alpha: [u32; 4],
    pub input_log_size: u32,
    pub folds: Vec<FoldRecord>,
}

#[derive(Serialize)]
pub struct FriFoldSection {
    pub log_size: u32,
    pub fold_step: u32,
    pub log_last_layer_degree_bound: u32,
    /// `input[i] = (i + 1, 2i + 3, 3i + 5, 7i + 11)` (each reduced mod `P`), in bit-reversed
    /// storage order over the canonic circle domain.
    pub input_formula: &'static str,
    pub input_sha256: String,
    pub layers: Vec<FriLayerRecord>,
    /// The single value left after the last layer.
    pub last_layer: [u32; 4],
}

fn input() -> Vec<QM31> {
    (0..1u64 << LOG_SIZE)
        .map(|i| {
            let limb = |a: u64, b: u64| ((a * i + b) % u64::from(P)) as u32;
            qm31_from_u32s(limb(1, 1), limb(2, 3), limb(3, 5), limb(7, 11))
        })
        .collect()
}

fn fold_record(kind: &'static str, alpha: QM31, values: &[QM31]) -> FoldRecord {
    FoldRecord {
        kind,
        alpha: qm31(alpha),
        log_size: values.len().ilog2(),
        values_sha256: values_sha256(values),
        head: values.iter().take(HEAD).map(|v| qm31(*v)).collect(),
    }
}

/// The verifier's view of one layer: every `2^n_folds` subset folded by `fold_coset`.
fn fold_subsets(eval: &[QM31], domain: LineDomain, alpha: QM31, n_folds: u32) -> Vec<QM31> {
    eval.chunks(1 << n_folds)
        .enumerate()
        .map(|(subset, values)| {
            let initial = domain.coset().index_at(subset << n_folds);
            let fold_domain = LineDomain::new(stwo::core::circle::Coset::new(initial, n_folds));
            fold_coset(values.to_vec(), fold_domain, alpha)
        })
        .collect()
}

pub fn fri_fold_section() -> Result<FriFoldSection> {
    let alphas = ALPHAS.map(|[a, b, c, d]| qm31_from_u32s(a, b, c, d));
    let input = input();
    let circle_domain = CanonicCoset::new(LOG_SIZE).circle_domain();

    // First layer: circle -> line, then `fold_step - 1` line folds with the squared alpha.
    let alpha = alphas[0];
    let mut folds = Vec::new();
    let mut eval = fold_circle_into_line(&input, circle_domain, alpha);
    let mut domain = LineDomain::new(circle_domain.half_coset);
    folds.push(fold_record("circle_into_line", alpha, &eval));
    let mut fold_alpha = alpha * alpha;
    for _ in 1..FOLD_STEP {
        let (next_domain, next) = fold_line(&eval, domain, fold_alpha);
        folds.push(fold_record("line", fold_alpha, &next));
        (domain, eval) = (next_domain, next);
        fold_alpha = fold_alpha * fold_alpha;
    }
    let mut layers = vec![FriLayerRecord {
        layer: 0,
        layer_alpha: qm31(alpha),
        input_log_size: LOG_SIZE,
        folds,
    }];

    // Inner layers until the last layer's degree bound is reached.
    let mut layer = 1;
    while domain.log_size() > LOG_LAST_LAYER_DEGREE_BOUND {
        let n_folds = FOLD_STEP.min(domain.log_size() - LOG_LAST_LAYER_DEGREE_BOUND);
        let alpha = alphas[layer];
        let (input_domain, input_eval) = (domain, eval.clone());
        let mut folds = Vec::new();
        let mut fold_alpha = alpha;
        for _ in 0..n_folds {
            let (next_domain, next) = fold_line(&eval, domain, fold_alpha);
            folds.push(fold_record("line", fold_alpha, &next));
            (domain, eval) = (next_domain, next);
            fold_alpha = fold_alpha * fold_alpha;
        }
        ensure!(
            fold_subsets(&input_eval, input_domain, alpha, n_folds) == eval,
            "FRI layer {layer}: fold_coset disagrees with the fold_line chain"
        );
        layers.push(FriLayerRecord {
            layer,
            layer_alpha: qm31(alpha),
            input_log_size: input_domain.log_size(),
            folds,
        });
        layer += 1;
    }
    ensure!(
        layer == alphas.len() && eval.len() == 1,
        "FRI schedule must end with one value after {} layers",
        alphas.len()
    );

    Ok(FriFoldSection {
        log_size: LOG_SIZE,
        fold_step: FOLD_STEP,
        log_last_layer_degree_bound: LOG_LAST_LAYER_DEGREE_BOUND,
        input_formula: "input[i] = (i + 1, 2i + 3, 3i + 5, 7i + 11) mod P",
        input_sha256: values_sha256(&input),
        layers,
        last_layer: qm31(eval[0]),
    })
}
