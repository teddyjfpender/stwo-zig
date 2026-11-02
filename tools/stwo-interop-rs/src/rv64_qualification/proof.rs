//! Four-way composition adapter over the exact Native Stwo pin. No witness replay.
use super::{
    layout::Layout,
    local::{self, Sink},
    model::{self, Metadata, Proof, Statement},
    state::{self, Challenges},
};
use anyhow::{ensure, Result};
use num_traits::Zero;
use stwo::{
    core::{
        air::accumulation::PointEvaluationAccumulator,
        channel::{Blake2sChannel, Channel},
        circle::CirclePoint,
        constraints::coset_vanishing,
        fields::{m31::M31, qm31::SecureField as Q, FieldExpOps},
        pcs::CommitmentSchemeVerifier,
        poly::circle::CanonicCoset,
        utils::{bit_reverse_index, coset_index_to_circle_domain_index},
        vcs::blake2_hash::Blake2sHash,
        vcs_lifted::blake2_merkle::Blake2sMerkleChannel,
    },
    prover::{
        backend::cpu::CpuBackend,
        poly::{
            circle::{CircleEvaluation, PolyOps},
            BitReversedOrder,
        },
        CommitmentSchemeProver,
    },
};
pub struct Setup {
    layout: Layout,
    root: Blake2sHash,
    program_base: u64,
}
impl Setup {
    pub fn new(s: &Statement, meta: &Metadata) -> Result<Self> {
        let layout = Layout::derive(s, meta)?;
        let twiddles =
            CpuBackend::precompute_twiddles(CanonicCoset::new(7).circle_domain().half_coset);
        let mut pcs = CommitmentSchemeProver::<CpuBackend, Blake2sMerkleChannel>::new(
            model::config(),
            &twiddles,
        );
        let columns = layout
            .fixed_sources
            .iter()
            .map(|&source| {
                let mut values = vec![M31(0); 32];
                for i in 0..32 {
                    let index = bit_reverse_index(coset_index_to_circle_domain_index(i, 5), 5);
                    values[index] = M31(layout.rows[i][source]);
                }
                CircleEvaluation::<CpuBackend, M31, BitReversedOrder>::new(
                    CanonicCoset::new(5).circle_domain(),
                    values,
                )
            })
            .collect();
        let mut channel = Blake2sChannel::default();
        let mut builder = pcs.tree_builder();
        builder.extend_evals(columns);
        builder.commit(&mut channel);
        Ok(Self {
            root: pcs.roots()[0],
            layout,
            program_base: s.program_base,
        })
    }
    pub fn verify(&self, s: &Statement, meta: &Metadata, proof: Proof) -> Result<()> {
        // Revalidate request bounds, but reuse independently derived immutable setup.
        ensure!(
            s.program_base == self.program_base,
            "setup identity mismatch"
        );
        super::layout::validate(s, meta)?;
        ensure!(
            proof.0.commitments[0] == self.root,
            "untrusted preprocessing root"
        );
        let mut channel = Blake2sChannel::default();
        state::mix(&mut channel, s, meta);
        let mut pcs = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(model::config());
        pcs.commit(proof.0.commitments[0], &vec![5; 21], &mut channel);
        pcs.commit(proof.0.commitments[1], &vec![5; 643], &mut channel);
        let challenges = Challenges::draw(&mut channel);
        let target = challenges.expected(s, meta)?;
        pcs.commit(proof.0.commitments[2], &vec![5; 36], &mut channel);
        let alpha = channel.draw_secure_felt();
        pcs.commit(proof.0.commitments[3], &vec![5; 16], &mut channel);
        let point = CirclePoint::<Q>::get_random_point(&mut channel);
        let previous = point - CanonicCoset::new(5).step().into_ef();
        let mut masks = vec![
            vec![vec![point]; 21],
            vec![vec![point]; 643],
            (0..36)
                .map(|i| {
                    if i >= 32 {
                        vec![point, previous]
                    } else {
                        vec![point]
                    }
                })
                .collect(),
            vec![vec![point]; 16],
        ];
        let sampled = &proof.0.sampled_values;
        let fp: Vec<Q> = sampled[0].iter().map(|c| c[0]).collect();
        let mp: Vec<Q> = sampled[1].iter().map(|c| c[0]).collect();
        let (f, m) = self.layout.inflate(&fp, &mp);
        let current: Vec<Q> = sampled[2].iter().map(|c| c[0]).collect();
        let previous: Vec<Q> = sampled[2]
            .iter()
            .enumerate()
            .map(|(i, c)| if i >= 32 { c[1] } else { Q::zero() })
            .collect();
        let mut sink = Sink {
            accumulator: PointEvaluationAccumulator::new(alpha),
            inverse: coset_vanishing(CanonicCoset::new(5).coset, point).inverse(),
            count: 0,
        };
        local::evaluate(&f, &m, &mut sink);
        challenges.evaluate(&f, &m, &current, &previous, target, &mut sink);
        ensure!(sink.count == 5513, "constraint schema count mismatch");
        let comp: Vec<Q> = sampled[3].iter().map(|c| c[0]).collect();
        let chunks: Vec<Q> = (0..4).map(|i| state::secure(&comp, 4 * i)).collect();
        let low = point.repeated_double(4).x;
        let high = point.repeated_double(5).x;
        let expected = (chunks[0] + low * chunks[1]) + high * (chunks[2] + low * chunks[3]);
        ensure!(expected == sink.accumulator.finalize(), "OodsNotMatching");
        pcs.verify_values(
            stwo::core::pcs::TreeVec::new(std::mem::take(&mut masks)),
            proof.0,
            &mut channel,
        )
        .map_err(|e| anyhow::anyhow!("pinned Rust PCS/FRI rejected: {e}"))?;
        Ok(())
    }
}
