//! Bounded independent numerical oracle. All terminals remain obligations to
//! the physical PCS; expected artifacts/public initial state are diagnostic.
#![allow(dead_code)]
use anyhow::{ensure, Context, Result};
use num_traits::Zero;
use serde::Deserialize;
use std::{fs::File, io::Read};
use stwo::core::fields::m31::P;
pub mod channel;
pub mod field;
pub use field::O as SecureField;
pub trait Channel {
    fn mix_felts(&mut self, v: &[SecureField]);
    fn draw_secure_felt(&mut self) -> SecureField;
}
#[path = "reference/gkr_verifier.rs"]
pub mod gkr_verifier;
#[path = "reference/sumcheck.rs"]
pub mod sumcheck;
#[path = "reference/utils.rs"]
pub mod utils;
type Words = [u32; 8];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    digest: [u8; 32],
    draws: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    point: Vec<Words>,
    claims: Vec<Vec<Words>>,
    variables: Vec<usize>,
    end: State,
}
#[derive(Deserialize)]
enum Gate {
    LogUp,
    GrandProduct,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema: u32,
    scope: String,
    initial: State,
    gates: Vec<Gate>,
    sumchecks: Vec<Vec<Vec<Words>>>,
    masks: Vec<Vec<Vec<[Words; 2]>>>,
    outputs: Vec<Vec<Words>>,
    expected: Expected,
    terminal_inputs: Option<Vec<Vec<Vec<Words>>>>,
    require_local_closure: bool,
}
fn field(w: Words) -> Result<SecureField> {
    ensure!(w.iter().all(|&x| x < P), "noncanonical coordinate");
    Ok(SecureField::from_words(w))
}
fn fields(v: &[Words]) -> Result<Vec<SecureField>> {
    v.iter().copied().map(field).collect()
}
fn verify(input: &Input) -> Result<serde_json::Value> {
    ensure!(input.schema == 1, "unsupported numerical oracle schema");
    let n = input.gates.len();
    ensure!(
        n > 0 && n <= 64 && input.masks.len() == n && input.outputs.len() == n,
        "instance shape"
    );
    let layers = input.masks.iter().map(Vec::len).max().unwrap();
    ensure!(
        layers > 0 && layers <= 30 && input.sumchecks.len() == layers,
        "layer shape"
    );
    let mut sc = Vec::new();
    for (layer, rounds) in input.sumchecks.iter().enumerate() {
        ensure!(rounds.len() == layer, "sumcheck topology");
        let mut polys = Vec::new();
        for coeff in rounds {
            ensure!(coeff.len() <= 4, "sumcheck degree");
            polys.push(utils::UnivariatePoly(fields(coeff)?));
        }
        sc.push(sumcheck::SumcheckProof { round_polys: polys });
    }
    let mut masks = Vec::new();
    let mut outputs = Vec::new();
    let mut gates = Vec::new();
    for i in 0..n {
        let width = match input.gates[i] {
            Gate::LogUp => 2,
            Gate::GrandProduct => 1,
        };
        ensure!(
            !input.masks[i].is_empty()
                && input.masks[i].len() <= 30
                && input.outputs[i].len() == width,
            "instance topology"
        );
        let mut ms = Vec::new();
        for m in &input.masks[i] {
            ensure!(m.len() == width, "mask width");
            let mut cols = Vec::new();
            for p in m {
                cols.push([field(p[0])?, field(p[1])?]);
            }
            ms.push(gkr_verifier::GkrMask::new(cols));
        }
        masks.push(ms);
        let out = fields(&input.outputs[i])?;
        if width == 2 {
            ensure!(!out[1].is_zero(), "LogUp root pole");
        }
        outputs.push(out);
        gates.push(match input.gates[i] {
            Gate::LogUp => gkr_verifier::Gate::LogUp,
            Gate::GrandProduct => gkr_verifier::Gate::GrandProduct,
        });
    }
    if input.require_local_closure {
        let mut s = SecureField::zero();
        for (i, out) in outputs.iter().enumerate() {
            ensure!(
                matches!(input.gates[i], Gate::LogUp),
                "closure requires all LogUp"
            );
            s += out[0] / out[1];
        }
        ensure!(s.is_zero(), "unclosed local outputs");
    }
    let proof = gkr_verifier::GkrBatchProof {
        sumcheck_proofs: sc,
        layer_masks_by_instance: masks,
        output_claims_by_instance: outputs,
    };
    let mut ch = channel::RawMod::seeded(input.initial.digest, input.initial.draws)?;
    let artifact = gkr_verifier::partially_verify_batch(gates, &proof, &mut ch)
        .context("pinned Rust lifted numerical verifier")?;
    ensure!(
        artifact.ood_point == fields(&input.expected.point)?,
        "OOD point mismatch"
    );
    ensure!(
        artifact.n_variables_by_instance == input.expected.variables
            && artifact.claims_to_verify_by_instance.len() == input.expected.claims.len(),
        "terminal shape mismatch"
    );
    for (actual, expected) in artifact
        .claims_to_verify_by_instance
        .iter()
        .zip(&input.expected.claims)
    {
        ensure!(*actual == fields(expected)?, "terminal claim mismatch");
    }
    ensure!(
        ch.digest() == input.expected.end.digest && ch.draws == input.expected.end.draws,
        "channel digest/counter mismatch"
    );
    let bound = if let Some(inputs) = &input.terminal_inputs {
        ensure!(inputs.len() == n, "terminal fixture instances");
        for i in 0..n {
            ensure!(
                inputs[i].len() == artifact.claims_to_verify_by_instance[i].len(),
                "terminal fixture columns"
            );
            let nv = artifact.n_variables_by_instance[i];
            ensure!(nv <= 12, "terminal fixture resource bound");
            let point = &artifact.ood_point[artifact.ood_point.len() - nv..];
            for (col, claim) in inputs[i]
                .iter()
                .zip(&artifact.claims_to_verify_by_instance[i])
            {
                ensure!(col.len() == 1 << nv, "terminal fixture rows");
                let mut v = fields(col)?;
                let mut len = v.len();
                for x in point {
                    let half = len / 2;
                    for j in 0..half {
                        v[j] = v[j] + *x * (v[j + half] - v[j]);
                    }
                    len = half;
                }
                ensure!(v[0] == *claim, "independent terminal MLE mismatch");
            }
        }
        true
    } else {
        false
    };
    Ok(
        serde_json::json!({"schema":"rv64-rust-om-gkr-numerical-oracle-v1","numerical_verified":true,"accepting_execution_receiver":false,"physical_pcs_verified":false,"whole_protocol_128":false,"starting_channel_state_authenticated":false,"scope":input.scope,"instances":n,"layers":layers,"all_eight_coordinates_compared":true,"terminal_fixture_inputs_checked":bound,"production_terminal_binding_pending":true,"end_digest":ch.digest(),"end_draws":ch.draws}),
    )
}
pub fn run() -> Result<()> {
    let mut args = std::env::args();
    args.next();
    let path = args.next().context("expected bounded numerical sidecar")?;
    ensure!(args.next().is_none(), "one sidecar argument required");
    let mut data = Vec::new();
    File::open(path)?
        .take((16 << 20) + 1)
        .read_to_end(&mut data)?;
    ensure!(data.len() <= 16 << 20, "sidecar byte bound");
    let input: Input = serde_json::from_slice(&data)?;
    let report = verify(&input)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;
    use stwo::core::fields::FieldExpOps;
    #[test]
    fn dense_tower_inverse_and_every_high_coordinate() {
        for k in 1..9 {
            let a = SecureField::from_words(std::array::from_fn(|i| {
                ((k * 103 + i * 71) % P as usize) as u32
            }));
            assert_eq!(a * a.inverse(), SecureField::one());
            assert_eq!((a + a) - a, a);
            assert_eq!(a.words()[7], (k * 103 + 7 * 71) as u32);
        }
    }
    #[test]
    fn rare_raw_reduction_boundaries() {
        let raw = [P - 1, P, P + 1, 2 * P - 1, 2 * P, 2 * P + 1, 0, 1];
        assert_eq!(raw.map(|x| x % P), [P - 1, 0, 1, P - 1, 0, 1, 0, 1]);
    }
}
